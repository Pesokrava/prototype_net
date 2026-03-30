use std::net::Ipv6Addr;

use anyhow::{Context, Result};
use sqlx::PgPool;
use tracing::{info, warn};

use crate::maps::BpfMaps;

/// Run periodic AAAA re-resolution for all domains in the database.
///
/// Every 60 seconds, re-resolves each domain and updates the database + BPF maps
/// if the origin IPv6 has changed.
pub async fn run_periodic_resolver(pool: PgPool, maps: BpfMaps) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));

    loop {
        interval.tick().await;

        if let Err(e) = resolve_all(&pool, &maps).await {
            warn!("Periodic re-resolution error: {e}");
        }
    }
}

async fn resolve_all(pool: &PgPool, maps: &BpfMaps) -> Result<()> {
    let rows = sqlx::query!(
        r#"SELECT domain_id, domain, host(origin_ipv6)::text as "origin_ipv6!" FROM domains"#
    )
    .fetch_all(pool)
    .await
    .context("failed to fetch domains for re-resolution")?;

    // Use the system resolver for upstream lookups
    use hickory_resolver::config::*;
    let resolver = hickory_resolver::TokioAsyncResolver::tokio(
        ResolverConfig::default(),
        ResolverOpts::default(),
    );

    for row in rows {
        match resolver.ipv6_lookup(&row.domain).await {
            Ok(lookup) => {
                if let Some(new_ip) = lookup.iter().next() {
                    let new_ip_str = new_ip.to_string();
                    if new_ip_str != row.origin_ipv6 {
                        info!(
                            "Origin changed for {}: {} → {}",
                            row.domain, row.origin_ipv6, new_ip_str
                        );

                        // Update database
                        sqlx::query!(
                            r#"UPDATE domains SET origin_ipv6 = $1::inet, last_resolved_at = now() WHERE domain_id = $2"#,
                            new_ip_str,
                            row.domain_id
                        )
                        .execute(pool)
                        .await
                        .context("failed to update origin_ipv6")?;

                        // Update BPF NAT_MAP
                        let new_ipv6: Ipv6Addr = new_ip_str
                            .parse()
                            .context("invalid new origin IPv6")?;
                        maps.insert_nat_entry(row.domain_id as u32, new_ipv6)?;
                    }
                }
            }
            Err(e) => {
                warn!("Re-resolution failed for {}: {e}", row.domain);
            }
        }
    }

    Ok(())
}
