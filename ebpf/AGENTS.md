# ebpf/ -- TC NAT66 eBPF Programs

This directory contains the Linux kernel-side eBPF programs that perform NAT66 (IPv6-to-IPv6 network address translation) on the TC (Traffic Control) hook points. These programs run inside the kernel and are compiled for the `bpfel-unknown-none` target using the **nightly** Rust toolchain.

## How It Works

Two TC classifier programs perform bidirectional address rewriting:

- **`tc_ingress`** (client→origin, attached to `xfrm0` ingress): Intercepts outbound packets
  destined for synthetic `fd00:abcd::/32` addresses. Extracts the `domain_id` from the
  destination, looks up the real origin IPv6 in `NAT_MAP`, rewrites the destination to the
  real origin and the source to the server's public IPv6. Records the server-side source port
  in `NAT_FLOWS` so the reply direction can match the flow.

- **`tc_ingress_wan`** (origin→client, attached to WAN interface `enp0s3` ingress): Intercepts
  reply packets arriving from origin servers. Matches on the destination port (the
  server-side ephemeral port stored in `NAT_FLOWS` by `tc_ingress`) and cross-checks the
  source IPv6 against `REVERSE_MAP` to avoid stealing the server's own connections. Rewrites
  the source to the synthetic IPv6 and the destination to the client's IPv6, then redirects
  the packet to `xfrm0` egress for IPSec encapsulation back to the client.

Both programs auto-detect whether the packet has an Ethernet header or is raw IPv6 (as on
`xfrm0`, an `ARPHRD_NONE` device) via the `ipv6_offset()` helper.

Checksum updates use `bpf_csum_diff(old, 16, new, 16, 0)` for endian-correct 16-byte address
deltas. `tc_ingress_wan` additionally applies `BPF_F_PSEUDO_HDR | BPF_F_MARK_MANGLED_0` after
the address rewrites to transition the skb to `CHECKSUM_PARTIAL`, delegating final
recomputation to the kernel transmit path and avoiding mismatches with NIC hardware checksum
offload (`CHECKSUM_COMPLETE`) on WAN ingress.

## BPF Maps

Five BPF maps are defined here and populated by the userspace `daemon/`:

| Map | Type | Key | Value | Max Entries |
|-----|------|-----|-------|-------------|
| `NAT_MAP` | HashMap | `u32` (domain_id) | `NatEntry` | 65536 |
| `REVERSE_MAP` | HashMap | `[u8; 16]` (origin IPv6) | `ReverseEntry` | 65536 |
| `SERVER_CONFIG` | Array | index 0 | `ServerConfig` | 1 |
| `XFRM_IFINDEX` | Array | index 0 | `u32` (ifindex) | 1 |
| `NAT_FLOWS` | HashMap | `u32` (src port) | `FlowEntry` | 65536 |

`XFRM_IFINDEX` holds the kernel interface index of `xfrm0`, written by the daemon at startup,
used by `tc_ingress_wan` for `bpf_redirect`.

`NAT_FLOWS` is written by `tc_ingress` and read by `tc_ingress_wan`. It maps the server-side
ephemeral source port to the corresponding `domain_id` and `client_ipv6`, enabling 5-tuple
flow matching in the reply direction.

## Build Requirements

- **Nightly Rust toolchain** -- this directory has its own `rust-toolchain.toml` overriding the workspace stable channel.
- **Target**: `bpfel-unknown-none` with `build-std = ["core"]`.
- Build via: `cargo xtask build-ebpf` (never `cargo build` directly from workspace root).
- The compiled ELF is output to `target/bpfel-unknown-none/release/ebpf` and is embedded into the `daemon` binary via `include_bytes_aligned!()`.

## Dependencies

- `aya-ebpf` / `aya-log-ebpf` -- eBPF framework and logging.
- `network-types` -- `no_std` crate providing typed structs for Ethernet, IPv4/IPv6, TCP,
  UDP, and ICMP headers (`EthHdr`, `Ipv6Hdr`, `IpProto`, etc.). Replaces hand-rolled
  byte-offset constants with verified struct definitions and enums, eliminating the class of
  bug where a wrong offset silently reads the wrong byte. Packet header access uses
  bounds-checked pointer casting (`ptr_at` helper) rather than `ctx.load()`.
- `common` (local) -- shared `NatEntry`, `ReverseEntry`, `ServerConfig`, `FlowEntry` types.

## Conventions

- `#![no_std]` and `#![no_main]` are required -- this is kernel code.
- All BPF map lookups use `unsafe` blocks (required by `aya-ebpf`).
- On parse/lookup failures, programs return `TC_ACT_OK` (pass-through) rather than dropping
  packets, to avoid disrupting non-matching traffic.
- Framing is auto-detected via `ipv6_offset()` -- never assume Ethernet on all interfaces.
- Protocol header access uses typed `network-types` structs via a `ptr_at` bounds-check
  helper; raw `ctx.load()` is used only for the single framing-detect byte peek.
- Checksum updates for IPv6 address fields must use `bpf_csum_diff` (not `l4_csum_replace`
  size=2/4), which is endian-correct for 16-byte address replacements.
- The panic handler is an infinite loop (required for no_std eBPF targets).
- Shared types come from the `common/` crate (no_std, no `userspace` feature).
