use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::net::UdpSocket;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

mod db;
mod handler;
mod resolver;

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

    info!("Connecting to database...");
    let db_pool = db::create_pool(&database_url).await?;

    info!("Creating upstream resolver...");
    let upstream_resolver = resolver::create_resolver().await?;

    info!("Starting DNS server on {listen_addr}");
    let socket_addr: SocketAddr = listen_addr
        .parse()
        .context("invalid LISTEN_ADDR format")?;

    let handler = Arc::new(handler::DnsHandler::new(
        Arc::new(db_pool),
        Arc::new(upstream_resolver),
    ));

    // Bind UDP socket
    let socket = UdpSocket::bind(socket_addr)
        .await
        .context("failed to bind UDP socket")?;

    info!("DNS server listening on {socket_addr} (UDP)");

    // Main receive loop
    let mut buf = vec![0u8; 4096];
    loop {
        let (len, src) = socket.recv_from(&mut buf).await?;
        let handler = Arc::clone(&handler);
        let data = buf[..len].to_vec();

        // Clone the socket reference for responding
        let socket_ref = &socket;

        match handler.handle_query(&data).await {
            Ok(response) => {
                if let Err(e) = socket_ref.send_to(&response, src).await {
                    tracing::error!("Failed to send response to {src}: {e}");
                }
            }
            Err(e) => {
                tracing::error!("Failed to handle query from {src}: {e}");
            }
        }
    }
}
