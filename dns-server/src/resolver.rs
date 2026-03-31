use std::net::Ipv6Addr;

use anyhow::{Context, Result};
use hickory_resolver::config::*;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::{ResolveErrorKind, TokioResolver};

pub struct UpstreamResolver {
    resolver: TokioResolver,
}

impl UpstreamResolver {
    pub fn new(resolver: TokioResolver) -> Self {
        Self { resolver }
    }

    /// Resolve the AAAA record for a domain.
    /// Returns `Ok(Some(ip))` if found, `Ok(None)` if no AAAA record, or an error.
    pub async fn lookup_aaaa(&self, domain: &str) -> Result<Option<Ipv6Addr>> {
        match self.resolver.ipv6_lookup(domain).await {
            Ok(lookup) => {
                // Take the first AAAA record; AAAA derefs to Ipv6Addr
                let ip = lookup.iter().next().map(|a| **a);
                Ok(ip)
            }
            Err(e) => {
                // If the domain doesn't exist or has no AAAA, return None.
                // In hickory-resolver 0.25, NoRecordsFound moved to ProtoErrorKind,
                // but ProtoError exposes is_no_records_found() for convenience.
                let is_no_records = match e.kind() {
                    ResolveErrorKind::Proto(proto_err) => proto_err.is_no_records_found(),
                    _ => false,
                };
                if is_no_records {
                    Ok(None)
                } else {
                    Err(e).context(format!("upstream AAAA lookup failed for {domain}"))
                }
            }
        }
    }
}

/// Create an upstream resolver using the default DNS configuration.
pub async fn create_resolver() -> Result<UpstreamResolver> {
    let resolver = TokioResolver::builder_with_config(
        ResolverConfig::default(),
        TokioConnectionProvider::default(),
    )
    .build();
    Ok(UpstreamResolver::new(resolver))
}
