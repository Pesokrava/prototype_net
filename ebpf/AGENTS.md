# ebpf/ -- XDP + TC NAT66 eBPF Programs

This directory contains the Linux kernel-side eBPF programs that perform NAT66 (IPv6-to-IPv6 network address translation) using one XDP hook and two TC (Traffic Control) hook points. These programs run inside the kernel and are compiled for the `bpfel-unknown-none` target using the **nightly** Rust toolchain.

## How It Works

One XDP program and two TC classifier programs implement stateless filtering + bidirectional address rewriting. No per-flow state is needed — all reply routing information is encoded into the source address written toward the origin server using obfuscated proxy-source encoding (PRINCE cipher + SipHash-2-4 MAC).

- **`xdp_wan`** (WAN ingress XDP): Parses Ethernet + IPv6 and drops only IPv6 packets
  whose destination is outside `PROXY_SRC_PREFIX` (`2001:db8::/32`), with one exception
  that always passes: ICMPv6 (NS/NA/RA/RS/PMTU/etc.) — so neighbor discovery and WAN
  reachability are never blocked.
  Non-IPv6 and parse failures return `XDP_PASS` (fail open).
  In dev-mode, `xdp_wan` additionally detects reply packets (dst = WAN IPv6) by looking up
  `REPLY_TRACK`. On a hit, it rewrites the destination from WAN IPv6 back to the original
  proxy-source address using raw pointer writes (no checksum update — the downstream
  `tc_ingress_wan` compensates). Returns `XDP_PASS` so the rewritten packet enters the kernel
  stack and is processed normally by `tc_ingress_wan`. Increments `DBG_COUNTERS` slots to trace
  decision paths. In production builds the dev-mode code is not compiled in — zero overhead.

- **`tc_ingress`** (client→origin, attached to `xfrm0` ingress): Intercepts outbound packets
  destined for synthetic `fd00:abcd::/32` addresses. Extracts the `domain_id` from the
  destination and looks up the real origin IPv6 in `NAT_MAP`. Derives `client_id` from the
  last 4 bytes of the client VIP (`fd00:abcd:0:1::<u32>`). Extracts L4 ports and protocol
  to build a `ProxySrcCtx` flow context. Reads the active key from `OBFS_KEYS[0]` and calls
  `encode_proxy_src(client_id, domain_id, &ctx, key)` to produce an obfuscated proxy-source
  address. Rewrites:
  - `dst` → real origin IPv6 (from `NAT_MAP`)
  - `src` → obfuscated proxy-source address in `2001:db8::/32` (PRINCE-encrypted IDs + SipHash TAG32)

  No flow table is written. The encoded source address carries all necessary return-path
  information in an opaque, authenticated form.

- **`tc_ingress_wan`** (origin→client, attached to WAN interface `enp0s3` ingress): Intercepts
  reply packets arriving from origin servers. Checks destination prefix matches
  `PROXY_SRC_PREFIX`. Extracts L4 ports (swapped to match the original outbound perspective)
  and builds `ProxySrcCtx`. Tries `decode_proxy_src` with `OBFS_KEYS[0]` (active key), then
  `OBFS_KEYS[1]` (previous key for rotation grace window) if the first fails. On decode
  failure (TAG32 mismatch, padding error, both keys fail) → `TC_ACT_SHOT` (forged/corrupted
  packet). On success, verifies the source IPv6 matches `NAT_MAP[domain_id].origin_ipv6` as a
  guard against unrelated traffic, then rewrites:
  - `src` → synthetic IPv6 (`fd00:abcd:XXXX:YYYY::1` for the domain)
  - `dst` → client VIP (`fd00:abcd:0:1::<client_id>`)

  Then redirects to `xfrm0` egress for IPSec encapsulation back to the client.

Both TC programs auto-detect whether the packet has an Ethernet header or is raw IPv6 (as on
`xfrm0`, an `ARPHRD_NONE` device) via the `ipv6_offset()` helper. `xdp_wan` always parses
Ethernet framing because it is attached to the physical WAN NIC ingress.

Checksum updates use `bpf_csum_diff(old, 16, new, 16, 0)` for endian-correct 16-byte address
deltas. `tc_ingress_wan` additionally applies `BPF_F_PSEUDO_HDR | BPF_F_MARK_MANGLED_0` after
the address rewrites to transition the skb to `CHECKSUM_PARTIAL`, delegating final
recomputation to the kernel transmit path and avoiding mismatches with NIC hardware checksum
offload (`CHECKSUM_COMPLETE`) on WAN ingress.

## BPF Maps

Three production BPF maps are defined here and populated by the userspace `daemon/`.
In dev-mode builds, three additional maps are compiled in (see below).

| Map | Type | Key | Value | Max Entries | Purpose |
|-----|------|-----|-------|-------------|---------|
| `NAT_MAP` | HashMap | `u32` (domain_id) | `NatEntry` | 65536 | domain_id → origin IPv6 |
| `XFRM_IFINDEX` | Array | index 0 | `u32` (ifindex) | 1 | xfrm0 ifindex for bpf_redirect |
| `OBFS_KEYS` | Array | index 0–1 | `ProxySrcKey` | 2 | proxy-source obfuscation keys |

`XFRM_IFINDEX` holds the kernel interface index of `xfrm0`, written by the daemon at startup,
used by `tc_ingress_wan` for `bpf_redirect`.

`NAT_MAP` is consulted at packet-processing time. It is used by `tc_ingress` to resolve the
origin IPv6 for a domain, and by `tc_ingress_wan` as an origin-guard to avoid intercepting
unrelated traffic.

`OBFS_KEYS` holds the proxy-source obfuscation keys. Slot 0 is the active key (required).
Slot 1 is the previous key for manual rotation grace window (optional; zero if unused).
Written by the daemon at startup from `PROXY_ADDR_KEY_HEX` env var.

### Dev-Mode Maps (compile-time only, `#[cfg(feature = "dev-mode")]`)

| Map | Type | Key | Value | Max Entries | Purpose |
|-----|------|-----|-------|-------------|---------|
| `DEV_WAN_IPV6` | Array | index 0 | `[u8; 16]` | 1 | Server's WAN IPv6 (auto-detected by daemon) |
| `REPLY_TRACK` | HashMap | `ReplyTrackKey` | `ReplyTrackValue` | 65536 | Outbound connection tracking for reply handling |
| `DBG_COUNTERS` | Array | index 0–7 | `u32` | 8 | Debug counters for tracing xdp_wan decision paths |

`DEV_WAN_IPV6` is populated by the daemon at startup via auto-detection from the WAN interface.
`REPLY_TRACK` is written by `tc_ingress` for each outbound connection and read by `xdp_wan` to
identify reply packets. `DBG_COUNTERS` is incremented by `xdp_wan` at various decision points
for debugging. In production builds these maps do not exist — zero overhead.

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
- `common` (local) -- shared `NatEntry`, `ProxySrcKey`, `ProxySrcCtx` types and address
  helpers (`encode_proxy_src`, `decode_proxy_src`, `client_vip_from_id24`, `synthetic_ipv6`).
  Also provides PRINCE cipher and SipHash-2-4 implementations used by the encode/decode
  functions.
- `siphasher` -- `no_std` SipHash-2-4 implementation (transitive via `common`).

## Conventions

- `#![no_std]` and `#![no_main]` are required -- this is kernel code.
- All BPF map lookups use `unsafe` blocks (required by `aya-ebpf`).
- On parse/lookup failures for non-matching traffic, TC programs return `TC_ACT_OK` and XDP
  returns `XDP_PASS` (fail open). For matching traffic with decode failures (TAG32 mismatch,
  padding error, NAT_MAP miss/mismatch), TC programs return `TC_ACT_SHOT` (drop).
- Framing is auto-detected via `ipv6_offset()` -- never assume Ethernet on all interfaces.
- Protocol header access uses typed `network-types` structs via a `ptr_at` bounds-check
  helper; raw `ctx.load()` is used only for the single framing-detect byte peek.
- Checksum updates for IPv6 address fields must use `bpf_csum_diff` (not `l4_csum_replace`
  size=2/4), which is endian-correct for 16-byte address replacements.
- The panic handler is an infinite loop (required for no_std eBPF targets).
- Shared types and helpers come from the `common/` crate (no_std, no `userspace` feature).
- **No per-flow state**: `tc_ingress` must never write to any flow table. All reply-direction
  routing information must be derivable solely from the proxy-source address in the packet.
  (Exception: in dev-mode, `tc_ingress` writes to `REPLY_TRACK` for the double-NAT mechanism,
  but this code is not compiled into production builds.)
