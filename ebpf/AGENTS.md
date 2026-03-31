# ebpf/ -- TC Ingress/Egress NAT66 eBPF Programs

This directory contains the Linux kernel-side eBPF programs that perform NAT66 (IPv6-to-IPv6 network address translation) on the TC (Traffic Control) hook points. These programs run inside the kernel and are compiled for the `bpfel-unknown-none` target using the **nightly** Rust toolchain.

## How It Works

Two TC classifier programs perform bidirectional address rewriting:

- **`tc_ingress`** (client-to-origin): Intercepts outbound packets destined for synthetic `fd00:abcd::/32` addresses. Extracts the `domain_id` from the destination, looks up the real origin IPv6 in `NAT_MAP`, rewrites the destination to the origin and the source to the server's public IPv6. Updates L4 (TCP/UDP) checksums incrementally.
- **`tc_egress`** (origin-to-client): Intercepts inbound response packets from origin servers. Looks up the source IPv6 in `REVERSE_MAP` to find the `domain_id` and client address. Rewrites source to the synthetic IPv6 and destination to the client's IPv6. Updates L4 checksums.

## BPF Maps

Three BPF maps are defined here and populated by the userspace `daemon/`:

| Map | Type | Key | Value | Max Entries |
|-----|------|-----|-------|-------------|
| `NAT_MAP` | HashMap | `u32` (domain_id) | `NatEntry` | 65536 |
| `REVERSE_MAP` | HashMap | `[u8; 16]` (origin IPv6) | `ReverseEntry` | 65536 |
| `SERVER_CONFIG` | Array | index 0 | `ServerConfig` | 1 |

## Build Requirements

- **Nightly Rust toolchain** -- this directory has its own `rust-toolchain.toml` overriding the workspace stable channel.
- **Target**: `bpfel-unknown-none` with `build-std = ["core"]`.
- Build via: `cargo xtask build-ebpf` (never `cargo build` directly from workspace root).
- The compiled ELF is output to `target/bpfel-unknown-none/release/ebpf` and is embedded into the `daemon` binary via `include_bytes!()`.

## Dependencies

- `aya-ebpf` / `aya-log-ebpf` -- eBPF framework and logging.
- `network-types` -- `no_std` crate providing typed structs for Ethernet, IPv4/IPv6, TCP,
  UDP, and ICMP headers (`EthHdr`, `Ipv6Hdr`, `IpProto`, etc.). Replaces hand-rolled
  byte-offset constants with verified struct definitions and enums, eliminating the class of
  bug where a wrong offset silently reads the wrong byte. Packet header access uses
  bounds-checked pointer casting (`ptr_at` helper) rather than `ctx.load()`.
- `common` (local) -- shared `NatEntry`, `ReverseEntry`, `ServerConfig` types.

## Conventions

- `#![no_std]` and `#![no_main]` are required -- this is kernel code.
- All BPF map lookups use `unsafe` blocks (required by `aya-ebpf`).
- On parse/lookup failures, programs return `TC_ACT_OK` (pass-through) rather than dropping packets, to avoid disrupting non-matching traffic.
- Protocol header access uses typed `network-types` structs via a `ptr_at` bounds-check
  helper; raw `ctx.load()` is reserved for fields not covered by `network-types`.
- The panic handler is an infinite loop (required for no_std eBPF targets).
- Shared types (`NatEntry`, `ReverseEntry`, `ServerConfig`) come from the `common/` crate (no_std, no `userspace` feature).
