# daemon/ -- eBPF Loader and BPF Map Sync Daemon

This is the main userspace daemon that loads the compiled eBPF programs onto the network interfaces, populates the BPF maps from Postgres, and keeps them synchronized in real time.

## Architecture

The daemon runs as an async Tokio application with three concurrent concerns:

1. **eBPF Loading** (`loader.rs`) -- Loads the pre-compiled eBPF ELF (embedded via
   `include_bytes_aligned!()`), attaches `tc_ingress` to the tunnel interface (`xfrm0`)
   ingress, `tc_ingress_wan` to WAN ingress (`enp0s3`) as a `SchedClassifier`, and `xdp_wan`
   to WAN ingress as an XDP program. Writes the initial `XFRM_IFINDEX` map entry. Pins BPF objects at
   `/sys/fs/bpf/prototype_net`. Polls for the tunnel interface to appear (up to 5 minutes)
   so the daemon can start before the first IKEv2 SA is established.

2. **Database Sync** (`db.rs` + `maps.rs`) -- On startup, bulk-loads all domain mappings from
   Postgres into `NAT_MAP`. Then subscribes to the `domain_changes` Postgres NOTIFY channel
   via `PgListener`. When the DNS server inserts or updates a domain, the daemon receives the
   notification and updates `NAT_MAP` immediately.

3. **Periodic DNS Re-resolution** (`resolver.rs`) -- Every 60 seconds, fetches all domains
   from the database, re-resolves their AAAA records via `hickory-resolver`, and updates both
   the database and `NAT_MAP` if an origin IPv6 has changed. This acts as a safety net for DNS
   TTL expiry.

## Key Files

- `src/main.rs` -- Entry point. Reads env vars (`DATABASE_URL`, `INTERFACE_NAME`, `WAN_INTERFACE`), orchestrates loading and spawns tasks.
- `src/loader.rs` -- eBPF ELF loading, qdisc setup, program attachment, `XFRM_IFINDEX` initialization. Contains `wait_for_interface()` polling loop.
- `src/maps.rs` -- Thread-safe `BpfMaps` wrapper (`Arc<Mutex<>>`) for `NAT_MAP` operations. Contains `bulk_load_from_db()`.
- `src/db.rs` -- Postgres pool creation, `PgListener` subscription, reactive `NAT_MAP` update on NOTIFY.
- `src/resolver.rs` -- Periodic AAAA re-resolution loop.

## Configuration

All configuration is via environment variables:

- `DATABASE_URL` -- Postgres connection string.
- `INTERFACE_NAME` -- Tunnel interface to attach `tc_ingress` to (e.g., `xfrm0`).
- `WAN_INTERFACE` -- WAN interface to attach `xdp_wan` and `tc_ingress_wan` to (e.g., `enp0s3`).

No server IPv6 address or client IPv6 address is required at runtime. The stateless
proxy-source encoding in the eBPF data plane derives all routing information from the packet
addresses themselves, so the daemon has no address configuration to manage beyond `NAT_MAP`.

## Build Order Dependency

The daemon embeds the eBPF ELF at compile time via `include_bytes_aligned!(concat!(env!("CARGO_MANIFEST_DIR"), "/../target/bpfel-unknown-none/release/ebpf"))`. You **must** run `cargo xtask build-ebpf` before building this crate, or compilation will fail.

## Conventions

- Uses `aya` (v0.13) for eBPF loading and map manipulation.
- BPF map access is wrapped in `Arc<Mutex<>>` for safe sharing across Tokio tasks.
- `unsafe BorrowedFd::borrow_raw()` is used to reopen BPF maps from cached file descriptors.
- Error handling uses `anyhow` with `.context()` throughout.
- Logging via `tracing` + `tracing-subscriber`; eBPF log messages forwarded via `aya-log`.
- Only `NAT_MAP` is managed by the daemon. There is no `REVERSE_MAP`, `NAT_FLOWS`, or
  `SERVER_CONFIG` — those concepts were eliminated by the stateless proxy-source encoding.
