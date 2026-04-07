# ebpf/ -- XDP + TC NAT66 eBPF Programs

This directory contains the Linux kernel-side eBPF programs that perform NAT66 (IPv6-to-IPv6 network address translation) using one XDP hook and two TC (Traffic Control) hook points. These programs run inside the kernel and are compiled for the `bpfel-unknown-none` target using the **nightly** Rust toolchain.

## How It Works

One XDP program and two TC classifier programs implement stateless filtering + bidirectional address rewriting. No per-flow state is needed — all reply routing information is encoded into the source address written toward the origin server.

- **`xdp_wan`** (WAN ingress XDP): Parses Ethernet + IPv6 and drops only IPv6 packets
  whose destination is outside `fd00:abcd::/32`. Non-IPv6 and parse failures return
  `XDP_PASS` (fail open).

- **`tc_ingress`** (client→origin, attached to `xfrm0` ingress): Intercepts outbound packets
  destined for synthetic `fd00:abcd::/32` addresses. Extracts the `domain_id` from the
  destination and looks up the real origin IPv6 in `NAT_MAP`. Derives `client_id` from the
  last 4 bytes of the client VIP (`fd00:abcd:0:1::<u32>`). Rewrites:
  - `dst` → real origin IPv6 (from `NAT_MAP`)
  - `src` → `proxy_src_ipv6(client_id, domain_id)` where bytes `[4..8]` carry `client_id`
    and bytes `[8..12]` carry `domain_id`

  No flow table is written. The encoded source address carries all necessary return-path information.

- **`tc_ingress_wan`** (origin→client, attached to WAN interface `enp0s3` ingress): Intercepts
  reply packets arriving from origin servers. Packets have already been constrained to
  `fd00:abcd::/32` by `xdp_wan`. Decodes `client_id` and `domain_id` directly from the
  destination address, verifies the source IPv6 matches `NAT_MAP[domain_id].origin_ipv6` as a
  guard against unrelated traffic, then rewrites:
  - `src` → synthetic IPv6 (`fd00:abcd:XXXX:YYYY::1` for the domain)
  - `dst` → client VIP (`fd00:abcd:0:1::<client_id>`)

  Then redirects to `xfrm0` egress for IPSec encapsulation back to the client. Zero per-flow
  map lookups are needed for routing — only 1 `NAT_MAP` lookup for the origin guard.

Both TC programs auto-detect whether the packet has an Ethernet header or is raw IPv6 (as on
`xfrm0`, an `ARPHRD_NONE` device) via the `ipv6_offset()` helper. `xdp_wan` always parses
Ethernet framing because it is attached to the physical WAN NIC ingress.

Checksum updates use `bpf_csum_diff(old, 16, new, 16, 0)` for endian-correct 16-byte address
deltas. `tc_ingress_wan` additionally applies `BPF_F_PSEUDO_HDR | BPF_F_MARK_MANGLED_0` after
the address rewrites to transition the skb to `CHECKSUM_PARTIAL`, delegating final
recomputation to the kernel transmit path and avoiding mismatches with NIC hardware checksum
offload (`CHECKSUM_COMPLETE`) on WAN ingress.

## BPF Maps

Two BPF maps are defined here and populated by the userspace `daemon/`:

| Map | Type | Key | Value | Max Entries |
|-----|------|-----|-------|-------------|
| `NAT_MAP` | HashMap | `u32` (domain_id) | `NatEntry` | 65536 |
| `XFRM_IFINDEX` | Array | index 0 | `u32` (ifindex) | 1 |

`XFRM_IFINDEX` holds the kernel interface index of `xfrm0`, written by the daemon at startup,
used by `tc_ingress_wan` for `bpf_redirect`.

`NAT_MAP` is the only map consulted at packet-processing time. It is used by `tc_ingress` to
resolve the origin IPv6 for a domain, and by `tc_ingress_wan` as an origin-guard to avoid
intercepting unrelated traffic.

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
  bounds-checked pointer casting (`ptr_at` / `ptr_at_xdp` helpers) rather than `ctx.load()`.
- `common` (local) -- shared `NatEntry` type and address helpers (`proxy_src_ipv6`,
  `decode_proxy_src`, `client_vip_from_id`, `synthetic_ipv6`).

## Conventions

- `#![no_std]` and `#![no_main]` are required -- this is kernel code.
- All BPF map lookups use `unsafe` blocks (required by `aya-ebpf`).
- On parse/lookup failures, TC programs return `TC_ACT_OK` and XDP returns `XDP_PASS`
  (fail open) to avoid disrupting non-matching traffic.
- Framing is auto-detected via `ipv6_offset()` -- never assume Ethernet on all interfaces.
- Protocol header access uses typed `network-types` structs via a `ptr_at` bounds-check
  helper; raw `ctx.load()` is used only for the single framing-detect byte peek.
- Checksum updates for IPv6 address fields must use `bpf_csum_diff` (not `l4_csum_replace`
  size=2/4), which is endian-correct for 16-byte address replacements.
- The panic handler is an infinite loop (required for no_std eBPF targets).
- Shared types and helpers come from the `common/` crate (no_std, no `userspace` feature).
- **No per-flow state**: `tc_ingress` must never write to any flow table. All reply-direction
  routing information must be derivable solely from the proxy-source address in the packet.
