use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use hickory_resolver::proto::op::{Message, MessageType, ResponseCode};
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::{Level, info, warn};
use tracing_subscriber::FmtSubscriber;

mod db;
mod handler;
mod resolver;

/// Default maximum number of in-flight DNS queries processed concurrently.
///
/// Chosen to bound memory and scheduler pressure under burst traffic while still
/// serving realistic DNS load (a single upstream round-trip is ~10–200 ms, so 256
/// permits supports ~1 280–25 600 QPS before shedding begins at default timeout).
/// Override with the `MAX_CONCURRENT_QUERIES` environment variable.
const DEFAULT_MAX_CONCURRENT_QUERIES: usize = 256;

/// Default per-query timeout covering the full pipeline: upstream DNS lookup,
/// database round-trip, and UDP send_to.  Override with `QUERY_TIMEOUT_SECS`.
const DEFAULT_QUERY_TIMEOUT_SECS: u64 = 5;

/// Log a saturation warning at most once every this many dropped packets to
/// prevent the logger itself from becoming a bottleneck under flood conditions.
const SATURATION_LOG_INTERVAL: u64 = 100;

/// Build a minimal SERVFAIL response for the given raw DNS query bytes.
/// Returns `None` if the query cannot be parsed (malformed packet).
fn servfail(query_bytes: &[u8]) -> Option<Vec<u8>> {
    let request = Message::from_vec(query_bytes).ok()?;
    let mut response = Message::new();
    response.set_id(request.id());
    response.set_message_type(MessageType::Response);
    response.set_op_code(request.op_code());
    response.set_recursion_desired(request.recursion_desired());
    response.set_recursion_available(true);
    for query in request.queries() {
        response.add_query(query.clone());
    }
    response.set_response_code(ResponseCode::ServFail);
    response.to_vec().ok()
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .context("failed to set tracing subscriber")?;

    // Read environment variables
    let database_url =
        std::env::var("DATABASE_URL").context("DATABASE_URL environment variable not set")?;
    let listen_addr = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:53".to_string());

    let max_concurrent: usize = std::env::var("MAX_CONCURRENT_QUERIES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MAX_CONCURRENT_QUERIES);

    let query_timeout = Duration::from_secs(
        std::env::var("QUERY_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_QUERY_TIMEOUT_SECS),
    );

    info!("Connecting to database...");
    let db_pool = db::create_pool(&database_url).await?;

    info!("Creating upstream resolver...");
    let upstream_resolver = resolver::create_resolver().await?;

    info!("Starting DNS server on {listen_addr}");
    let socket_addr: SocketAddr = listen_addr.parse().context("invalid LISTEN_ADDR format")?;

    let handler = Arc::new(handler::DnsHandler::new(
        Arc::new(db_pool),
        Arc::new(upstream_resolver),
    ));

    // Semaphore bounding concurrent in-flight tasks.
    // try_acquire_owned() is intentionally non-blocking: the receive loop must
    // never stall so that the OS UDP buffer keeps draining.
    let semaphore = Arc::new(Semaphore::new(max_concurrent));

    // Counter used to rate-limit saturation log lines.
    let dropped_count = Arc::new(AtomicU64::new(0));

    // Bind UDP socket
    let socket = Arc::new(
        UdpSocket::bind(socket_addr)
            .await
            .context("failed to bind UDP socket")?,
    );

    info!(
        "DNS server listening on {socket_addr} (UDP), \
         max_concurrent={max_concurrent}, query_timeout={}s",
        query_timeout.as_secs()
    );

    // Main receive loop — never blocks on query processing.
    let mut buf = vec![0u8; 4096];
    loop {
        let (len, src) = socket.recv_from(&mut buf).await?;

        // --- Backpressure: acquire a permit before touching heap memory ---
        //
        // try_acquire_owned() fails instantly when saturated.  We respond with
        // SERVFAIL rather than silently dropping so the client knows to retry
        // instead of waiting for a timeout.  This is a deliberate design choice:
        // SERVFAIL under overload is more honest than silence, and the cost
        // (one small parse + send) is negligible compared to what a full query
        // would have done.
        let permit = match semaphore.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                // Rate-limited log: warn once per SATURATION_LOG_INTERVAL drops.
                let n = dropped_count.fetch_add(1, Ordering::Relaxed) + 1;
                if n % SATURATION_LOG_INTERVAL == 1 {
                    warn!(
                        "semaphore saturated (limit={max_concurrent}); \
                         dropped {n} queries so far, returning SERVFAIL (sample log)"
                    );
                }
                if let Some(pkt) = servfail(&buf[..len]) {
                    let _ = socket.send_to(&pkt, src).await;
                }
                continue;
            }
        };

        // Allocate owned copy only after confirming we have capacity.
        let data = buf[..len].to_vec();
        let handler = Arc::clone(&handler);
        let socket = Arc::clone(&socket);

        tokio::spawn(async move {
            // _permit is held for the task lifetime; released on drop.
            let _permit = permit;

            // Timeout covers the full response pipeline: upstream DNS lookup,
            // DB round-trip, and send_to.  send_to on a non-blocking UDP socket
            // is normally instantaneous, but including it avoids an unbounded
            // tail in the pathological case of a stalled socket write buffer.
            match timeout(query_timeout, async {
                match handler.handle_query(&data).await {
                    Ok(response) => {
                        if let Err(e) = socket.send_to(&response, src).await {
                            tracing::error!("failed to send response to {src}: {e}");
                        }
                    }
                    Err(e) => {
                        tracing::error!("failed to handle query from {src}: {e}");
                        if let Some(pkt) = servfail(&data) {
                            let _ = socket.send_to(&pkt, src).await;
                        }
                    }
                }
            })
            .await
            {
                Ok(()) => {}
                Err(_elapsed) => {
                    tracing::warn!(
                        "query from {src} timed out after {}s",
                        query_timeout.as_secs()
                    );
                    // Best-effort SERVFAIL on timeout so the client gets a
                    // signal rather than waiting for its own resolver timeout.
                    if let Some(pkt) = servfail(&data) {
                        let _ = socket.send_to(&pkt, src).await;
                    }
                }
            }
        });
    }
}
