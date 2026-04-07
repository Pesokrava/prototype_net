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
    // (domain_id, domain, origin_ipv6_text)
    let rows: Vec<(i32, String, String)> =
        sqlx::query_as(r#"SELECT domain_id, domain, host(origin_ipv6)::text FROM domains"#)
            .fetch_all(pool)
            .await
            .context("failed to fetch domains for re-resolution")?;

    // Use the system resolver for upstream lookups
    use hickory_resolver::TokioResolver;
    use hickory_resolver::config::*;
    let resolver = TokioResolver::builder_with_config(
        ResolverConfig::default(),
        hickory_resolver::name_server::TokioConnectionProvider::default(),
    )
    .build();

    for (domain_id, domain, origin_ipv6_text) in rows {
        match resolver.ipv6_lookup(&domain).await {
            Ok(lookup) => {
                if let Some(new_ip) = lookup.iter().next().map(|a| **a) {
                    let new_ip_str = new_ip.to_string();
                    if new_ip_str != origin_ipv6_text {
                        info!(
                            "Origin changed for {}: {} → {}",
                            domain, origin_ipv6_text, new_ip_str
                        );

                        // Update database
                        sqlx::query(
                            r#"UPDATE domains SET origin_ipv6 = $1::inet, last_resolved_at = now() WHERE domain_id = $2"#,
                        )
                        .bind(&new_ip_str)
                        .bind(domain_id)
                        .execute(pool)
                        .await
                        .context("failed to update origin_ipv6")?;

                        // Update BPF NAT_MAP
                        maps.insert_nat_entry(domain_id as u32, new_ip)?;
                    }
                }
            }
            Err(e) => {
                warn!("Re-resolution failed for {}: {e}", domain);
            }
        }
    }

    Ok(())
}
