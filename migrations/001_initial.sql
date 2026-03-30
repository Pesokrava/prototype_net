-- prototype_net initial schema
-- Applied automatically by Postgres initdb (mounted to /docker-entrypoint-initdb.d/)

-- Domain ID sequence: allocates unique IDs embedded in synthetic IPv6 addresses
CREATE SEQUENCE domain_id_seq START 1;

-- Main domains table
CREATE TABLE domains (
    id               SERIAL PRIMARY KEY,
    domain_id        INTEGER UNIQUE NOT NULL,   -- embedded in synthetic IPv6, allocated via domain_id_seq
    domain           TEXT UNIQUE NOT NULL,       -- e.g. "google.com"
    origin_ipv6      INET NOT NULL,              -- real AAAA record of origin
    synthetic_ipv6   INET NOT NULL,              -- fd00:abcd:XXXX:YYYY::1
    created_at       TIMESTAMPTZ DEFAULT now(),
    last_resolved_at TIMESTAMPTZ,
    ttl_seconds      INTEGER
);

-- Index for fast domain_id lookups (used by daemon map sync)
CREATE INDEX idx_domains_domain_id ON domains(domain_id);

-- Index for reverse lookups by origin IP
CREATE INDEX idx_domains_origin_ipv6 ON domains(origin_ipv6);

-- Notify trigger: fires on INSERT or UPDATE, sends domain_id on 'domain_changes' channel
CREATE OR REPLACE FUNCTION notify_domain_change() RETURNS trigger AS $$
BEGIN
    PERFORM pg_notify('domain_changes', NEW.domain_id::text);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER domain_change_trigger
    AFTER INSERT OR UPDATE ON domains
    FOR EACH ROW
    EXECUTE FUNCTION notify_domain_change();
