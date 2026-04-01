# prototype_net

An eBPF-based IPv6 NAT66 transparent proxy. Uses synthetic DNS addresses, strongSwan IKEv2 tunnels, and a Postgres-backed domain mapping system to transparently route IPv6 traffic through an encrypted tunnel while performing address translation at the kernel level.

## Architecture Overview

```
Client DNS query --> dns-server (synthetic AAAA) --> Postgres (domain mapping)
                                                          |
                                                     pg_notify
                                                          |
Client traffic --> IPSec tunnel --> xfrm0 --> ebpf tc_ingress (NAT66) --> origin
                                                          |
                                              ebpf tc_ingress_wan (WAN ingress)
                                                          |
                                   BPF maps (NAT_MAP, REVERSE_MAP, NAT_FLOWS, XFRM_IFINDEX)
```

The system works in two phases:
1. **DNS phase**: The custom DNS server resolves domains, assigns synthetic `fd00:abcd::/32` addresses, and stores mappings in Postgres (which notifies the daemon).
2. **Data plane**: eBPF programs on TC hooks rewrite IPv6 addresses in-kernel.
   - `tc_ingress` on `xfrm0` ingress: rewrites synthetic dst→origin and src→server_pub for client→origin traffic.
   - `tc_ingress_wan` on `enp0s3` ingress: rewrites origin src→synthetic and dst→client for reply traffic, then redirects to `xfrm0` for IPSec re-encapsulation.

## Toolchain

- **Rust stable** (1.87.0+) for userspace crates (`common`, `daemon`, `dns-server`, `xtask`).
- **Rust nightly** for the eBPF crate (cross-compiled to `bpfel-unknown-none`).
- **Postgres 18** via Docker Compose.
- **Terraform** with libvirt provider for VM provisioning.

## Build Order

1. `cargo xtask build-ebpf` -- Compile eBPF programs (nightly toolchain).
2. `cargo build -p daemon -p dns-server` -- Build userspace binaries (embeds the eBPF ELF).

## Configuration

All runtime configuration is via environment variables. See `.env.example` for the full list. Key variables: `DATABASE_URL`, `INTERFACE_NAME`, `WAN_INTERFACE`, `SERVER_IPV6`, `CLIENT_IPV6`, `LISTEN_ADDR`.

## Subdirectory Documentation

Each top-level subdirectory contains its own `AGENTS.md` with detailed context about that directory's purpose, contents, and conventions:

- [`common/AGENTS.md`](common/AGENTS.md) -- Shared `#[repr(C)]` BPF map types (`no_std` compatible, used by both eBPF and userspace).
- [`ebpf/AGENTS.md`](ebpf/AGENTS.md) -- TC NAT66 eBPF programs (`tc_ingress` on xfrm0, `tc_ingress_wan` on WAN interface) with per-flow `NAT_FLOWS` tracking (nightly Rust, `bpfel-unknown-none` target).
- [`daemon/AGENTS.md`](daemon/AGENTS.md) -- Userspace daemon: eBPF loader, BPF map sync from Postgres, periodic DNS re-resolution.
- [`dns-server/AGENTS.md`](dns-server/AGENTS.md) -- Custom DNS server: mints synthetic AAAA records, stores mappings in Postgres.
- [`xtask/AGENTS.md`](xtask/AGENTS.md) -- Build automation for cross-compiling the eBPF crate.
- [`migrations/AGENTS.md`](migrations/AGENTS.md) -- Postgres schema: `domains` table, `domain_id_seq`, LISTEN/NOTIFY trigger.
- [`certs/AGENTS.md`](certs/AGENTS.md) -- X.509 certificate generation for strongSwan IKEv2 authentication.
- [`strongswan/AGENTS.md`](strongswan/AGENTS.md) -- Server-side IKEv2 swanctl configuration.
- [`client/AGENTS.md`](client/AGENTS.md) -- Docker test client: establishes IPSec tunnel and routes synthetic traffic.
- [`terraform/AGENTS.md`](terraform/AGENTS.md) -- Libvirt VM provisioning with cloud-init for automated server setup.

## Cross-Cutting Conventions

- **Dual toolchain**: Stable for userspace, nightly for eBPF. Separate `rust-toolchain.toml` in `ebpf/`.
- **Aya eBPF framework**: `aya-ebpf` for kernel programs, `aya` for userspace loader.
- **network-types**: `no_std` crate for typed protocol header structs (`EthHdr`, `Ipv6Hdr`, `IpProto`, etc.) used in the eBPF crate. Prefer these over hand-rolled byte-offset constants.
- **Feature-gated code**: `common` crate uses a `userspace` feature for `aya::Pod` implementations.
- **Async Rust**: Tokio runtime in both `daemon` and `dns-server`.
- **Error handling**: `anyhow` with `.context()` throughout userspace code.
- **Logging**: `tracing` + `tracing-subscriber` in userspace; `aya-log-ebpf` in eBPF.
- **Database**: `sqlx` with Postgres. LISTEN/NOTIFY for reactive BPF map updates.
- **Env-var configuration**: No config files; all runtime settings via environment variables.
- **Strict shell scripts**: All bash scripts use `set -euo pipefail`.
- **Secrets**: `.env` gitignored; `certs/output/` gitignored; Terraform vars marked `sensitive`.
