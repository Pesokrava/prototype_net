# common/ -- Shared BPF Map Types and Address Helpers

This crate provides `#[repr(C)]` data structures and pure address-manipulation functions shared between the eBPF kernel programs (`ebpf/`) and userspace Rust binaries (`daemon/`, `dns-server/`). It is `#![no_std]` compatible so it can be compiled for both the `bpfel-unknown-none` eBPF target and standard Linux targets.

## Key Types

- **`NatEntry`** -- Maps a `domain_id` to its real origin IPv6 address. Used in the `NAT_MAP` BPF hash map.

## Key Functions

- **`synthetic_ipv6(domain_id) -> [u8; 16]`** -- Constructs a synthetic `fd00:abcd:XXXX:YYYY::1` address from a `u32` domain ID.
- **`domain_id_from_ipv6(addr) -> u32`** -- Extracts the domain ID from bytes `[4..8]` of a synthetic IPv6 address.
- **`proxy_src_ipv6(client_id, domain_id) -> [u8; 16]`** -- Constructs a proxy-source address that encodes the client identity and domain into the source address used toward origin servers. Layout:

  | Bytes | Value | Meaning |
  |:------|:------|:--------|
  | 0–3   | `fd 00 ab cd` | ULA /32 prefix |
  | 4     | `0xff`        | Proxy-source marker (unambiguous: synthetic addrs have byte 4 < `0x01` in practice; client pool addrs have byte 4 = `0x00`) |
  | 5     | `0x00`        | Reserved |
  | 6–7   | `client_id` (u16 BE) | Last 2 bytes of client VIP (`::0100`–`::ffff`) |
  | 8–11  | `domain_id` (u32 BE) | Domain identifier from `NAT_MAP` |
  | 12–15 | `0x00 00 00 00` | Unused (structural padding to fill 16 bytes) |

- **`is_proxy_src(addr) -> bool`** -- Returns `true` if byte 4 of `addr` is `0xff` (proxy-source marker).
- **`decode_proxy_src(addr) -> (u16, u32)`** -- Extracts `(client_id, domain_id)` from a proxy-source address. Caller must verify `is_proxy_src()` first.
- **`client_vip_from_id(client_id) -> [u8; 16]`** -- Reconstructs the client VIP `fd00:abcd:0:1::<client_id>` from a `client_id`. Mirrors the strongSwan pool range `::0100–::ffff`.

## Conventions

- All structs use `#[repr(C)]` for BPF map compatibility -- this is mandatory and must not be removed.
- The `userspace` Cargo feature gates `unsafe impl aya::Pod` for each struct. eBPF code uses this crate without that feature; userspace crates (`daemon`) enable it.
- The constant `SYNTHETIC_PREFIX: [u8; 4]` defines `fd00:abcd::/32` and is the source of truth for the synthetic address space.
- Changes to struct layout here affect both kernel-side eBPF and userspace programs -- always rebuild both after modifying types.
- Adding a new map value type requires: `#[repr(C)]`, an `unsafe impl aya::Pod` behind `#[cfg(feature = "userspace")]`, and rebuilding with `cargo xtask build-ebpf` before `cargo build -p daemon`.
- The proxy-source helpers (`proxy_src_ipv6`, `is_proxy_src`, `decode_proxy_src`, `client_vip_from_id`) are `no_std` pure functions — they have no side effects and can be called freely from both eBPF and userspace.
