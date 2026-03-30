use anyhow::{Context, Result};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

pub type DbPool = PgPool;

/// Row returned from the domains table.
pub struct DomainRow {
    pub domain_id: i32,
    pub domain: String,
    pub origin_ipv6: String,
    pub synthetic_ipv6: String,
    pub ttl_seconds: Option<i32>,
}

/// Create a Postgres connection pool.
pub async fn create_pool(database_url: &str) -> Result<PgPool> {
    PgPoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await
        .context("failed to connect to Postgres")
}

/// Find a domain mapping by domain name.
pub trait DbOps {
    async fn find_by_domain(&self, domain: &str) -> Result<Option<DomainRow>>;
    async fn insert_domain(
        &self,
        domain_id: i32,
        domain: &str,
        origin_ipv6: &str,
        synthetic_ipv6: &str,
        ttl_seconds: i32,
    ) -> Result<()>;
    async fn next_domain_id(&self) -> Result<i32>;
}

impl DbOps for PgPool {
    async fn find_by_domain(&self, domain: &str) -> Result<Option<DomainRow>> {
        let row = sqlx::query_as!(
            DomainRow,
            r#"
            SELECT domain_id, domain, host(origin_ipv6)::text as "origin_ipv6!",
                   host(synthetic_ipv6)::text as "synthetic_ipv6!", ttl_seconds
            FROM domains
            WHERE domain = $1
            "#,
            domain
        )
        .fetch_optional(self)
        .await
        .context("failed to query domains table")?;

        Ok(row)
    }

    async fn insert_domain(
        &self,
        domain_id: i32,
        domain: &str,
        origin_ipv6: &str,
        synthetic_ipv6: &str,
        ttl_seconds: i32,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO domains (domain_id, domain, origin_ipv6, synthetic_ipv6, ttl_seconds, last_resolved_at)
            VALUES ($1, $2, $3::inet, $4::inet, $5, now())
            ON CONFLICT (domain) DO UPDATE SET
                origin_ipv6 = EXCLUDED.origin_ipv6,
                last_resolved_at = now(),
                ttl_seconds = EXCLUDED.ttl_seconds
            "#,
            domain_id,
            domain,
            origin_ipv6,
            synthetic_ipv6,
            ttl_seconds
        )
        .execute(self)
        .await
        .context("failed to insert domain")?;

        Ok(())
    }

    async fn next_domain_id(&self) -> Result<i32> {
        let row = sqlx::query_scalar!(
            r#"SELECT nextval('domain_id_seq')::integer as "id!""#
        )
        .fetch_one(self)
        .await
        .context("failed to get next domain_id from sequence")?;

        Ok(row)
    }
}
