# migrations/ -- Postgres Schema Initialization

This directory contains SQL migration files that define the database schema. These are automatically applied by Postgres on container startup (mounted to `/docker-entrypoint-initdb.d/` in the Docker Compose configuration).

## Schema Overview (`001_initial.sql`)

- **`domain_id_seq`** -- Sequence starting at 1 for allocating unique domain IDs. These IDs are embedded into the synthetic IPv6 addresses (bytes 4-7).
- **`domains` table** -- Central mapping table with columns:
  - `id` (serial PK), `domain_id` (unique int from sequence), `domain` (unique text)
  - `origin_ipv6` (inet -- the real AAAA address), `synthetic_ipv6` (inet -- the `fd00:abcd::` address)
  - `created_at`, `last_resolved_at`, `ttl_seconds`
- **Indexes** -- On `domain_id` (for daemon BPF map lookups) and `origin_ipv6` (for reverse lookups).
- **`notify_domain_change()` trigger** -- Fires `pg_notify('domain_changes', NEW.domain_id::text)` on INSERT or UPDATE. This is the pub/sub mechanism that alerts the daemon to update BPF maps in real time.

## Conventions

- Uses Postgres `INET` type for IPv6 address storage.
- The LISTEN/NOTIFY pattern is the bridge between `dns-server` (writer) and `daemon` (subscriber) -- changes to the trigger function affect real-time BPF map synchronization.
- Sequence-based ID allocation prevents collisions across DNS server restarts.
- Migration files are numbered with a `NNN_` prefix for ordering.
