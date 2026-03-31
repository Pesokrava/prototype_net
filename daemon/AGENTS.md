# daemon/ -- eBPF Loader and BPF Map Sync Daemon

This is the main userspace daemon that loads the compiled eBPF programs onto the network interface, populates the BPF maps from Postgres, and keeps them synchronized in real time.

## Architecture

The daemon runs as an async Tokio application with three concurrent concerns:

1. **eBPF Loading** (`loader.rs`) -- Loads the pre-compiled eBPF ELF (embedded via `include_bytes!()`), creates a `clsact` qdisc on the tunnel interface, and attaches `tc_ingress` and `tc_egress` as `SchedClassifier` programs. Writes the initial `SERVER_CONFIG` map entry. Pins BPF objects at `/sys/fs/bpf/prototype_net`.

2. **Database Sync** (`db.rs` + `maps.rs`) -- On startup, bulk-loads all domain mappings from Postgres into both `NAT_MAP` and `REVERSE_MAP`. Then subscribes to the `domain_changes` Postgres NOTIFY channel via `PgListener`. When the DNS server inserts or updates a domain, the daemon receives the notification and updates both BPF maps immediately.

3. **Periodic DNS Re-resolution** (`resolver.rs`) -- Every 60 seconds, fetches all domains from the database, re-resolves their AAAA records via `hickory-resolver`, and updates both the database and BPF maps if an origin IPv6 has changed. This acts as a safety net for DNS TTL expiry.

## Key Files

- `src/main.rs` -- Entry point. Reads env vars, orchestrates loading and spawns tasks.
- `src/loader.rs` -- eBPF ELF loading, qdisc setup, program attachment, `SERVER_CONFIG` initialization.
- `src/maps.rs` -- Thread-safe `BpfMaps` wrapper (`Arc<Mutex<>>`) for `NAT_MAP` and `REVERSE_MAP` operations. Contains `bulk_load_from_db()`.
- `src/db.rs` -- Postgres pool creation, `PgListener` subscription, reactive map update on NOTIFY.
- `src/resolver.rs` -- Periodic AAAA re-resolution loop.

## Configuration

All configuration is via environment variables:

- `DATABASE_URL` -- Postgres connection string.
- `INTERFACE_NAME` -- Network interface to attach eBPF programs to (e.g., `xfrm0`).
- `SERVER_IPV6` -- The server's public IPv6 address.
- `CLIENT_IPV6` -- The VPN client's IPv6 address (IKEv2 traffic selector). Used to populate `REVERSE_MAP` so the egress eBPF program can rewrite replies back to the correct client.

## Build Order Dependency

The daemon embeds the eBPF ELF at compile time via `include_bytes!("../target/bpfel-unknown-none/release/ebpf")`. You **must** run `cargo xtask build-ebpf` before building this crate, or compilation will fail.

## Conventions

- Uses `aya` (v0.13) for eBPF loading and map manipulation.
- BPF map access is wrapped in `Arc<Mutex<>>` for safe sharing across Tokio tasks.
- `unsafe BorrowedFd::borrow_raw()` is used to reopen BPF maps from cached file descriptors.
- Error handling uses `anyhow` with `.context()` throughout.
- Logging via `tracing` + `tracing-subscriber`; eBPF log messages forwarded via `aya-log`.
