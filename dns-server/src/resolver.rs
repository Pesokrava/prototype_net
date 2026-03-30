use std::net::Ipv6Addr;

use anyhow::{Context, Result};
use hickory_resolver::{config::*, TokioAsyncResolver};

pub struct UpstreamResolver {
    resolver: TokioAsyncResolver,
}

impl UpstreamResolver {
    pub fn new(resolver: TokioAsyncResolver) -> Self {
        Self { resolver }
    }

    /// Resolve the AAAA record for a domain.
    /// Returns `Ok(Some(ip))` if found, `Ok(None)` if no AAAA record, or an error.
    pub async fn lookup_aaaa(&self, domain: &str) -> Result<Option<Ipv6Addr>> {
        match self.resolver.ipv6_lookup(domain).await {
            Ok(lookup) => {
                // Take the first AAAA record
                let ip = lookup.iter().next().copied();
                Ok(ip)
            }
            Err(e) => {
                // If the domain doesn't exist or has no AAAA, return None
                use hickory_resolver::error::ResolveErrorKind;
                match e.kind() {
                    ResolveErrorKind::NoRecordsFound { .. } => Ok(None),
                    _ => Err(e).context(format!("upstream AAAA lookup failed for {domain}")),
                }
            }
        }
    }
}

/// Create an upstream resolver using system DNS configuration.
pub async fn create_resolver() -> Result<UpstreamResolver> {
    let resolver = TokioAsyncResolver::tokio(
        ResolverConfig::default(),
        ResolverOpts::default(),
    );
    Ok(UpstreamResolver::new(resolver))
}
