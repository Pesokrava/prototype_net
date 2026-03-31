use std::net::Ipv6Addr;

use anyhow::{Context, Result};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use tracing::{info, warn};

use crate::maps::BpfMaps;

/// Create a Postgres connection pool.
pub async fn create_pool(database_url: &str) -> Result<PgPool> {
    PgPoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await
        .context("failed to connect to Postgres")
}

/// Listen for domain_changes notifications and update BPF maps.
pub async fn listen_for_changes(database_url: &str, maps: BpfMaps, client_ipv6: Ipv6Addr) -> Result<()> {
    let mut listener = sqlx::postgres::PgListener::connect(database_url)
        .await
        .context("failed to connect PgListener")?;

    listener
        .listen("domain_changes")
        .await
        .context("failed to LISTEN on domain_changes")?;

    info!("Listening for domain_changes notifications...");

    // We need a pool for querying the row details
    let pool = create_pool(database_url).await?;

    loop {
        let notification = listener
            .recv()
            .await
            .context("PgListener recv error")?;

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
        .fetch_optional(&pool)
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
                    info!(
                        "Updated NAT_MAP: domain_id={domain_id} → origin={origin_ipv6_text}",
                    );
                }

                // Insert into REVERSE_MAP
                if let Err(e) = maps.insert_reverse_entry(origin, domain_id as u32, client_ipv6) {
                    warn!("Failed to update REVERSE_MAP for domain_id={domain_id}: {e}");
                } else {
                    info!(
                        "Updated REVERSE_MAP: origin={origin_ipv6_text} → domain_id={domain_id}",
                    );
                }
            }
            None => {
                warn!("Domain with domain_id={domain_id} not found after notification");
            }
        }
    }
}
