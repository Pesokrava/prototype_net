# dns-server/ -- Synthetic AAAA DNS Responder

This is a custom DNS server that intercepts AAAA queries, resolves the real origin IPv6 address upstream, mints a synthetic `fd00:abcd::/32` address, stores the mapping in Postgres, and returns the synthetic address to the client. This is the entry point for new domain mappings in the system.

## How It Works

1. A client sends an AAAA DNS query (e.g., for `example.com`).
2. The handler checks Postgres for an existing mapping. If found, returns the cached synthetic address.
3. If not cached, the upstream resolver fetches the real AAAA record from public DNS.
4. A new `domain_id` is allocated from the `domain_id_seq` Postgres sequence.
5. A synthetic IPv6 is constructed via `common::synthetic_ipv6(domain_id)`.
6. The mapping is upserted into Postgres via `INSERT ... ON CONFLICT (domain) DO UPDATE ... RETURNING domain_id, synthetic_ipv6`. The `RETURNING` clause yields the **actually stored** row — under concurrent inserts for the same domain, the first writer wins and all callers receive the winner's canonical address. `domain_id` and `synthetic_ipv6` are never updated on conflict; only `origin_ipv6`, `ttl_seconds`, and `last_resolved_at` are refreshed.
7. The synthetic AAAA record from the DB-returned row is sent to the client with a 300-second TTL.

A-record queries and all other record types return NXDOMAIN -- this is an IPv6-only system.

## Key Files

- `src/main.rs` -- Entry point. Binds a UDP socket, runs the receive/respond loop.
- `src/handler.rs` -- `DnsHandler` that parses DNS packets, orchestrates lookup/allocation/response.
- `src/resolver.rs` -- `UpstreamResolver` wrapping `hickory_resolver::TokioAsyncResolver` for AAAA lookups.
- `src/db.rs` -- `DbOps` trait and `PgPool` implementation for domain storage. Uses `INSERT ... ON CONFLICT ... RETURNING` to upsert domains and return the canonically stored `domain_id` and `synthetic_ipv6` (first writer wins). `next_domain_id()` calls `nextval('domain_id_seq')`.

## Configuration

- `DATABASE_URL` -- Postgres connection string.
- `LISTEN_ADDR` -- Address to bind the DNS server to (default `0.0.0.0:53`).

## Conventions

- DNS packet parsing uses `hickory_resolver::proto::op::Message` directly on raw UDP bytes (not hickory-server's `ServerFuture`).
- The `DbOps` trait abstracts database operations for potential testability.
- Domain names are normalized: lowercased and trailing dots stripped.
- Error handling uses `anyhow`; logging via `tracing`.
