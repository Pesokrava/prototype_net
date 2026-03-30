use std::net::Ipv6Addr;
use std::sync::Arc;

use anyhow::{Context, Result};
use hickory_resolver::proto::op::{Message, MessageType, ResponseCode};
use hickory_resolver::proto::rr::rdata::AAAA;
use hickory_resolver::proto::rr::{Name, RData, Record, RecordType};
use tracing::{debug, info, warn};

use crate::db::DbPool;
use crate::resolver::UpstreamResolver;

pub struct DnsHandler {
    db: Arc<DbPool>,
    resolver: Arc<UpstreamResolver>,
}

impl DnsHandler {
    pub fn new(db: Arc<DbPool>, resolver: Arc<UpstreamResolver>) -> Self {
        Self { db, resolver }
    }

    /// Handle a raw DNS query packet and return a raw response packet.
    pub async fn handle_query(&self, data: &[u8]) -> Result<Vec<u8>> {
        let request =
            Message::from_vec(data).context("failed to parse DNS query")?;

        let mut response = Message::new();
        response.set_id(request.id());
        response.set_message_type(MessageType::Response);
        response.set_op_code(request.op_code());
        response.set_recursion_desired(request.recursion_desired());
        response.set_recursion_available(true);

        // Copy the query section into the response
        for query in request.queries() {
            response.add_query(query.clone());
        }

        if request.queries().is_empty() {
            response.set_response_code(ResponseCode::FormErr);
            return Ok(response.to_vec()?);
        }

        let query = &request.queries()[0];
        let name = query.name().clone();
        let qtype = query.query_type();

        debug!("DNS query: {} {:?}", name, qtype);

        match qtype {
            RecordType::AAAA => {
                self.handle_aaaa(&name, &mut response).await?;
            }
            RecordType::A => {
                // IPv4-only domains are not supported — return NXDOMAIN for A queries
                response.set_response_code(ResponseCode::NXDomain);
            }
            _ => {
                // All other types → NXDOMAIN
                response.set_response_code(ResponseCode::NXDomain);
            }
        }

        Ok(response.to_vec()?)
    }

    async fn handle_aaaa(&self, name: &Name, response: &mut Message) -> Result<()> {
        let domain_str = name.to_ascii().trim_end_matches('.').to_lowercase();

        // 1. Check database for existing mapping
        if let Some(row) = self.db.find_by_domain(&domain_str).await? {
            info!("Cache hit for {domain_str} → {}", row.synthetic_ipv6);
            let synthetic: Ipv6Addr = row.synthetic_ipv6.parse()
                .context("invalid synthetic IPv6 in DB")?;
            let ttl = row.ttl_seconds.unwrap_or(300) as u32;
            let mut record = Record::from_rdata(name.clone(), ttl, RData::AAAA(AAAA(synthetic)));
            record.set_dns_class(hickory_resolver::proto::rr::DNSClass::IN);
            response.add_answer(record);
            response.set_response_code(ResponseCode::NoError);
            return Ok(());
        }

        // 2. Resolve upstream AAAA
        let upstream_result = self.resolver.lookup_aaaa(&domain_str).await;
        let origin_ipv6 = match upstream_result {
            Ok(Some(ip)) => ip,
            Ok(None) => {
                info!("No AAAA record for {domain_str} — returning NXDOMAIN");
                response.set_response_code(ResponseCode::NXDomain);
                return Ok(());
            }
            Err(e) => {
                warn!("Upstream resolution failed for {domain_str}: {e}");
                response.set_response_code(ResponseCode::ServFail);
                return Ok(());
            }
        };

        // 3. Allocate domain_id and construct synthetic address
        let domain_id = self.db.next_domain_id().await?;
        let synthetic_bytes = common::synthetic_ipv6(domain_id as u32);
        let synthetic_ipv6 = Ipv6Addr::from(synthetic_bytes);

        // 4. Insert into database (triggers NOTIFY)
        let ttl = 300u32; // default TTL
        self.db
            .insert_domain(
                domain_id,
                &domain_str,
                &origin_ipv6.to_string(),
                &synthetic_ipv6.to_string(),
                ttl as i32,
            )
            .await?;

        info!(
            "New mapping: {domain_str} → synthetic={synthetic_ipv6}, origin={origin_ipv6}, domain_id={domain_id}"
        );

        // 5. Return synthetic AAAA record
        let mut record = Record::from_rdata(name.clone(), ttl, RData::AAAA(AAAA(synthetic_ipv6)));
        record.set_dns_class(hickory_resolver::proto::rr::DNSClass::IN);
        response.add_answer(record);
        response.set_response_code(ResponseCode::NoError);
        Ok(())
    }
}
