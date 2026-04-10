# daemon/ -- eBPF Loader and BPF Map Sync Daemon

This is the main userspace daemon that loads the compiled eBPF programs onto the network interfaces, populates the BPF maps from Postgres, and keeps them synchronized in real time.

## Architecture

The daemon runs as an async Tokio application with three concurrent concerns:

1. **eBPF Loading** (`loader.rs`) -- Loads the pre-compiled eBPF ELF (embedded via
   `include_bytes_aligned!()`), attaches `tc_ingress` to the tunnel interface (`xfrm0`)
   ingress, `tc_ingress_wan` to WAN ingress (`enp0s3`) as a `SchedClassifier`, and `xdp_wan`
   to WAN ingress as an XDP program. Writes the initial `XFRM_IFINDEX` and `OBFS_KEYS` map
   entries. In dev-mode builds, auto-detects the server's WAN IPv6 from the WAN interface and
   populates the `DEV_WAN_IPV6` BPF map. Pins BPF objects at `/sys/fs/bpf/prototype_net`.
   Polls for the tunnel interface to appear (up to 5 minutes) so the daemon can start before
   the first IKEv2 SA is established.

2. **Database Sync** (`db.rs` + `maps.rs`) -- On startup, bulk-loads all domain mappings from
   Postgres into `NAT_MAP`. Then subscribes to the `domain_changes` Postgres NOTIFY channel
   via `PgListener`. When the DNS server inserts or updates a domain, the daemon receives the
   notification and updates `NAT_MAP` immediately.

3. **Periodic DNS Re-resolution** (`resolver.rs`) -- Every 60 seconds, fetches all domains
   from the database, re-resolves their AAAA records via `hickory-resolver`, and updates both
   the database and `NAT_MAP` if an origin IPv6 has changed. This acts as a safety net for DNS
   TTL expiry.

## Key Files

- `src/main.rs` -- Entry point. Reads env vars, orchestrates loading and spawns tasks.
- `src/loader.rs` -- eBPF ELF loading, qdisc setup, program attachment, `XFRM_IFINDEX` +
  `OBFS_KEYS` initialization (plus `DEV_WAN_IPV6` auto-detection in dev-mode builds). Contains `wait_for_interface()` polling loop.
- `src/maps.rs` -- Thread-safe `BpfMaps` wrapper (`Arc<Mutex<>>`) for `NAT_MAP` operations. Contains `bulk_load_from_db()`.
- `src/db.rs` -- Postgres pool creation, `PgListener` subscription, reactive `NAT_MAP` update on NOTIFY.
- `src/resolver.rs` -- Periodic AAAA re-resolution loop.

## Configuration

All configuration is via environment variables:

| Variable | Required | Description |
|:---------|:---------|:------------|
| `DATABASE_URL` | yes | Postgres connection string |
| `INTERFACE_NAME` | yes | Tunnel interface for `tc_ingress` (e.g. `xfrm0`) |
| `WAN_INTERFACE` | yes | WAN interface for `xdp_wan` + `tc_ingress_wan` (e.g. `enp0s3`) |
| `PROXY_ADDR_KEY_HEX` | yes | 64-hex-char (32-byte) proxy-source obfuscation key |
| `PROXY_ADDR_PREV_KEY_HEX` | no | Previous key for rotation grace window |

`PROXY_ADDR_KEY_HEX` is removed from the process environment immediately after parsing to
limit its exposure window.

### Dev-Mode (Build-Time Feature)

When the daemon is compiled with `--features dev-mode`, it auto-detects the server's WAN IPv6
address from the WAN interface at startup (using `nix::ifaddrs`) and writes it into the
`DEV_WAN_IPV6` BPF map. No environment variables or manual configuration needed.

The daemon logs will show:
```
Dev-mode: set DEV_WAN_IPV6[0] = 2a01:xxxx:xxxx::xxxx (auto-detected from enp0s3)
```

In production builds (without `dev-mode` feature), none of this code is compiled in.

## Build Order Dependency

The daemon embeds the eBPF ELF at compile time via `include_bytes_aligned!(concat!(env!("CARGO_MANIFEST_DIR"), "/../target/bpfel-unknown-none/release/ebpf"))`. You **must** run `cargo xtask build-ebpf` before building this crate, or compilation will fail.

## Conventions

- Uses `aya` (v0.13) for eBPF loading and map manipulation.
- BPF map access is wrapped in `Arc<Mutex<>>` for safe sharing across Tokio tasks.
- `unsafe BorrowedFd::borrow_raw()` is used to reopen BPF maps from cached file descriptors.
- Error handling uses `anyhow` with `.context()` throughout.
- Logging via `tracing` + `tracing-subscriber`; eBPF log messages forwarded via `aya-log`.
- Only `NAT_MAP` is managed post-startup. `XFRM_IFINDEX`, `OBFS_KEYS`, and (in dev-mode)
  `DEV_WAN_IPV6` are written once at startup and never updated again — there is no hot-reload
  path for them.
