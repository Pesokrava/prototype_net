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
                                              ebpf xdp_wan (WAN ingress filter)
                                                          |
                                              ebpf tc_ingress_wan (WAN ingress)
                                                          |
                                          BPF maps (NAT_MAP, XFRM_IFINDEX)
```

The system works in two phases:
1. **DNS phase**: The custom DNS server resolves domains, assigns synthetic `fd00:abcd::/32` addresses, and stores mappings in Postgres (which notifies the daemon).
2. **Data plane**: eBPF programs on XDP + TC hooks rewrite IPv6 addresses in-kernel using a **stateless proxy-source encoding** — no per-flow tables.
   - `xdp_wan` on `enp0s3` ingress: drops IPv6 packets whose destination is outside `fd00:abcd::/32` and passes everything else (including non-IPv6 and parse failures).
   - `tc_ingress` on `xfrm0` ingress: rewrites synthetic dst→origin and src→`proxy_src_ipv6(client_id, domain_id)` for client→origin traffic. The encoded source address carries all reply-routing information; no flow state is written.
   - `tc_ingress_wan` on `enp0s3` ingress: decodes `client_id` and `domain_id` from the packet's destination address (the proxy-source written by `tc_ingress`), verifies source against `NAT_MAP`, rewrites src→synthetic and dst→client VIP, then redirects to `xfrm0` for IPSec re-encapsulation.

## Toolchain

- **Rust stable** (1.87.0+) for userspace crates (`common`, `daemon`, `dns-server`, `xtask`).
- **Rust nightly** for the eBPF crate (cross-compiled to `bpfel-unknown-none`).
- **Postgres 18** via Docker Compose.
- **Terraform** with libvirt provider for VM provisioning.

## Build Order

1. `cargo xtask verify-contract` -- Verify all config files match `contract.toml` (run automatically by `build-ebpf`).
2. `cargo test -p common` -- Run address encoding round-trip contract tests.
3. `cargo xtask build-ebpf` -- Compile eBPF programs (nightly toolchain); calls `verify-contract` first.
4. `cargo build -p daemon -p dns-server` -- Build userspace binaries (embeds the eBPF ELF).

## Address-Space Contract

All address-space constants (synthetic prefix, VIP pool range, XFRM `if_id`) are defined in a single file: **`contract.toml`** at the workspace root. Do not hardcode these values anywhere else.

- **Rust code** consumes them via `SYNTHETIC_PREFIX`, `VIP_POOL_DISCRIMINATOR`, and `XFRM_IF_ID` constants generated into `common` at compile time by `common/build.rs`.
- **Config files** (`client/swanctl.conf`, `client/entrypoint.sh`, `ansible/roles/prototype_net/templates/swanctl.conf.j2`, `ansible/roles/prototype_net/templates/prototype-xfrm0.service.j2`) are checked against `contract.toml` by `cargo xtask verify-contract`.
- **Systemd unit files and the server-side swanctl config** are rendered from Jinja2 templates in `ansible/roles/prototype_net/templates/` — the `xfrm if_id` value is substituted from `contract.toml` at deploy time.

## Configuration

All runtime configuration is via environment variables. See `.env.example` for the full list. Key variables: `DATABASE_URL`, `INTERFACE_NAME`, `WAN_INTERFACE`, `LISTEN_ADDR`.

## Subdirectory Documentation

Each top-level subdirectory contains its own `AGENTS.md` with detailed context about that directory's purpose, contents, and conventions:

- [`common/AGENTS.md`](common/AGENTS.md) -- Shared `#[repr(C)]` BPF map types and address helpers (`no_std` compatible, used by both eBPF and userspace). Constants generated from `contract.toml` via `build.rs`.
- [`ebpf/AGENTS.md`](ebpf/AGENTS.md) -- XDP + TC NAT66 eBPF programs (`xdp_wan` and `tc_ingress_wan` on WAN, `tc_ingress` on xfrm0) with stateless proxy-source address encoding (nightly Rust, `bpfel-unknown-none` target).
- [`daemon/AGENTS.md`](daemon/AGENTS.md) -- Userspace daemon: eBPF loader, BPF map sync from Postgres, periodic DNS re-resolution.
- [`dns-server/AGENTS.md`](dns-server/AGENTS.md) -- Custom DNS server: mints synthetic AAAA records, stores mappings in Postgres.
- [`xtask/AGENTS.md`](xtask/AGENTS.md) -- Build automation: cross-compiling eBPF and `verify-contract` config drift detection.
- [`migrations/AGENTS.md`](migrations/AGENTS.md) -- Postgres schema: `domains` table, `domain_id_seq`, LISTEN/NOTIFY trigger.
- [`certs/AGENTS.md`](certs/AGENTS.md) -- X.509 certificate generation for strongSwan IKEv2 authentication.
- [`client/AGENTS.md`](client/AGENTS.md) -- Docker test client: establishes IPSec tunnel and routes synthetic traffic.
- [`terraform/AGENTS.md`](terraform/AGENTS.md) -- Libvirt VM provisioning with cloud-init for automated server setup.
- [`ansible/AGENTS.md`](ansible/AGENTS.md) -- Ansible role for server provisioning: packages, sysctl, strongSwan config, systemd unit templates.

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
