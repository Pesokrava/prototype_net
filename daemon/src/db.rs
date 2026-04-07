use std::net::Ipv6Addr;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use tracing::{info, warn};

use crate::maps::BpfMaps;

/// Minimum run duration before a reconnect is considered "successful enough" to reset backoff.
const HEALTHY_RUN_THRESHOLD: Duration = Duration::from_secs(5);
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Create a Postgres connection pool.
pub async fn create_pool(database_url: &str) -> Result<PgPool> {
    PgPoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await
        .context("failed to connect to Postgres")
}

/// Listen for domain_changes notifications and update BPF maps.
///
/// Reconnects automatically on transient errors with exponential backoff.
/// Returns `Err` only on a fatal startup condition (initial pool creation failure),
/// which the caller should treat as a daemon-level failure.
pub async fn listen_for_changes(database_url: &str, maps: BpfMaps) -> Result<()> {
    let mut backoff = INITIAL_BACKOFF;

    loop {
        // Recreate the pool on every reconnect attempt so a stale pool after a
        // DB restart does not cause the row-fetch queries to fail silently.
        let pool = create_pool(database_url)
            .await
            .context("PgListener supervisor: failed to create connection pool")?;

        let started_at = Instant::now();
        match run_listener(database_url, &maps, &pool).await {
            Ok(()) => {
                warn!("PgListener loop exited unexpectedly, reconnecting...");
            }
            Err(e) => {
                warn!(
                    "PgListener error: {e}, reconnecting in {}s",
                    backoff.as_secs()
                );
            }
        }

        // Reset backoff if the last run was healthy long enough; otherwise double it.
        if started_at.elapsed() >= HEALTHY_RUN_THRESHOLD {
            backoff = INITIAL_BACKOFF;
        } else {
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }

        tokio::time::sleep(backoff).await;
    }
}

async fn run_listener(database_url: &str, maps: &BpfMaps, pool: &PgPool) -> Result<()> {
    let mut listener = sqlx::postgres::PgListener::connect(database_url)
        .await
        .context("failed to connect PgListener")?;

    listener
        .listen("domain_changes")
        .await
        .context("failed to LISTEN on domain_changes")?;

    info!("Listening for domain_changes notifications...");

    loop {
        let notification = listener.recv().await.context("PgListener recv error")?;

        let domain_id: i32 = notification
            .payload()
            .parse()
            .context("invalid domain_id in notification payload")?;

        info!("Received domain_changes notification for domain_id={domain_id}");

        // Fetch the full row: (domain_id, domain, origin_ipv6_text, synthetic_ipv6_text)
        let row: Option<(i32, String, String, String)> = sqlx::query_as(
            r#"SELECT domain_id, domain, host(origin_ipv6)::text, host(synthetic_ipv6)::text FROM domains WHERE domain_id = $1"#,
        )
        .bind(domain_id)
        .fetch_optional(pool)
        .await
        .context("failed to fetch domain by domain_id")?;

        match row {
            Some((_id, _domain, origin_ipv6_text, _synthetic)) => {
                let origin: Ipv6Addr = origin_ipv6_text
                    .parse()
                    .context("invalid origin_ipv6 in notification row")?;

                // Insert into NAT_MAP
                if let Err(e) = maps.insert_nat_entry(domain_id as u32, origin) {
                    warn!("Failed to update NAT_MAP for domain_id={domain_id}: {e}");
                } else {
                    info!("Updated NAT_MAP: domain_id={domain_id} → origin={origin_ipv6_text}",);
                }
            }
            None => {
                warn!("Domain with domain_id={domain_id} not found after notification");
            }
        }
    }
}
