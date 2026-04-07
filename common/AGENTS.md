# common/ -- Shared BPF Map Types and Address Helpers

This crate provides `#[repr(C)]` data structures and pure address-manipulation functions shared between the eBPF kernel programs (`ebpf/`) and userspace Rust binaries (`daemon/`, `dns-server/`). It is `#![no_std]` compatible so it can be compiled for both the `bpfel-unknown-none` eBPF target and standard Linux targets.

## Address-Space Constants

All address-space constants are generated at compile time from **`contract.toml`** at the workspace root by `common/build.rs`. They are emitted into `$OUT_DIR/contract.rs` and pulled in via `include!()` at the top of `lib.rs`. Do not hardcode these values — edit `contract.toml` instead.

| Constant | Type | Value | Meaning |
|:---------|:-----|:------|:--------|
| `SYNTHETIC_PREFIX` | `[u8; 4]` | `[0xfd, 0x00, 0xab, 0xcd]` | ULA /32 prefix for all synthetic, proxy-source, and VIP addresses |
| `VIP_POOL_DISCRIMINATOR` | `[u8; 4]` | `[0x00, 0x00, 0x00, 0x01]` | Bytes 4–7 of every client VIP — the `:0:1` segment that distinguishes VIPs from other address types |
| `XFRM_IF_ID` | `u32` | `1` | XFRM interface `if_id` used in the strongSwan child SA and `ip link add xfrm0 type xfrm if_id <N>` |

## Key Types

- **`NatEntry`** -- Maps a `domain_id` to its real origin IPv6 address. Used in the `NAT_MAP` BPF hash map.

## Key Functions

- **`synthetic_ipv6(domain_id) -> [u8; 16]`** -- Constructs a synthetic `fd00:abcd:XXXX:YYYY::1` address from a `u32` domain ID.
- **`domain_id_from_ipv6(addr) -> u32`** -- Extracts the domain ID from bytes `[4..8]` of a synthetic IPv6 address.
- **`proxy_src_ipv6(client_id, domain_id) -> [u8; 16]`** -- Constructs a proxy-source address that encodes the client identity and domain into the source address used toward origin servers. Layout:

  | Bytes | Value | Meaning |
  |:------|:------|:--------|
  | 0–3   | `SYNTHETIC_PREFIX` | ULA /32 prefix |
  | 4–7   | `client_id` (u32 BE) | Client identifier derived from VIP bytes `[12..16]` |
  | 8–11  | `domain_id` (u32 BE) | Domain identifier from `NAT_MAP` |
  | 12–15 | `0x00 00 00 00` | Reserved/future expansion |

- **`decode_proxy_src(addr) -> (u32, u32)`** -- Extracts `(client_id, domain_id)` from a proxy-source address.
- **`client_vip_from_id(client_id) -> [u8; 16]`** -- Reconstructs the client VIP `fd00:abcd:0:1::<client_id>` from a `client_id`. Uses `VIP_POOL_DISCRIMINATOR` for bytes 4–7. Mirrors the strongSwan pool range `::1:0–::ffff:ffff`.

## Contract Tests

A `#[cfg(test)]` module (`contract_tests`) in `lib.rs` verifies the internal consistency of the generated constants and all address-encoding round-trips. Run with:

```sh
cargo test -p common
```

Tests cover:
- `client_vip_from_id` produces the correct prefix, discriminator, and client_id bytes
- `proxy_src_ipv6` / `decode_proxy_src` round-trip for representative values
- All address types share `SYNTHETIC_PREFIX` in bytes 0–3
- `XFRM_IF_ID` is non-zero

## Conventions

- All structs use `#[repr(C)]` for BPF map compatibility -- this is mandatory and must not be removed.
- The `userspace` Cargo feature gates `unsafe impl aya::Pod` for each struct. eBPF code uses this crate without that feature; userspace crates (`daemon`) enable it.
- **Never hardcode address-space values** — all constants come from `contract.toml` via `build.rs`. Cargo automatically re-runs `build.rs` when `contract.toml` changes.
- Changes to struct layout here affect both kernel-side eBPF and userspace programs -- always rebuild both after modifying types.
- Adding a new map value type requires: `#[repr(C)]`, an `unsafe impl aya::Pod` behind `#[cfg(feature = "userspace")]`, and rebuilding with `cargo xtask build-ebpf` before `cargo build -p daemon`.
- The proxy-source helpers (`proxy_src_ipv6`, `decode_proxy_src`, `client_vip_from_id`) are `no_std` pure functions — they have no side effects and can be called freely from both eBPF and userspace.
