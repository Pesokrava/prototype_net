# common/ -- Shared BPF Map Types, Crypto Primitives, and Address Helpers

This crate provides `#[repr(C)]` data structures, cryptographic primitives (PRINCE cipher, SipHash-2-4), and address-manipulation functions shared between the eBPF kernel programs (`ebpf/`) and userspace Rust binaries (`daemon/`, `xtask/`). It is `#![no_std]` compatible so it can be compiled for both the `bpfel-unknown-none` eBPF target and standard Linux targets.

## Address-Space Constants

All address-space constants are generated at compile time from **`contract.toml`** at the workspace root by `common/build.rs`. They are emitted into `$OUT_DIR/contract.rs` and pulled in via `include!()` at the top of `lib.rs`. Do not hardcode these values — edit `contract.toml` instead.

| Constant | Type | Value | Meaning |
|:---------|:-----|:------|:--------|
| `SYNTHETIC_PREFIX` | `[u8; 4]` | `[0xfd, 0x00, 0xab, 0xcd]` | ULA /32 prefix for synthetic destination and VIP addresses |
| `VIP_POOL_DISCRIMINATOR` | `[u8; 4]` | `[0x00, 0x00, 0x00, 0x01]` | Bytes 4–7 of every client VIP — the `:0:1` segment that distinguishes VIPs from other address types |
| `XFRM_IF_ID` | `u32` | `1` | XFRM interface `if_id` used in the strongSwan child SA and `ip link add xfrm0 type xfrm if_id <N>` |
| `PROXY_SRC_PREFIX` | `[u8; 4]` | `[0x20, 0x01, 0x0d, 0xb8]` | Public /32 prefix for obfuscated proxy-source addresses (distinct from SYNTHETIC_PREFIX) |
| `PROXY_SRC_CLIENT_ID_MAX` | `u32` | `0x00FF_FFFF` | Maximum 24-bit client_id |
| `PROXY_SRC_DOMAIN_ID_MAX` | `u32` | `0x00FF_FFFF` | Maximum 24-bit domain_id |

## Key Types

- **`NatEntry`** -- Maps a `domain_id` to its real origin IPv6 address. Used in the `NAT_MAP` BPF hash map.
- **`ProxySrcCtx`** -- 5-tuple flow context (src_port, dst_port, proto) used as tweak in encode/decode. Ports are host-byte-order u16.
- **`ProxySrcKey`** -- 256-bit key material: bytes 0-15 = PRINCE key, bytes 16-31 = SipHash-2-4 key. Used in the `OBFS_KEYS` BPF array map.

## Key Functions

- **`synthetic_ipv6(domain_id) -> [u8; 16]`** -- Constructs a synthetic `fd00:abcd:XXXX:YYYY::1` address from a `u32` domain ID.
- **`domain_id_from_ipv6(addr) -> u32`** -- Extracts the domain ID from bytes `[4..8]` of a synthetic IPv6 address.
- **`encode_proxy_src(client_id, domain_id, ctx, key) -> Option<[u8; 16]>`** -- Encodes client_id (24-bit) + domain_id (24-bit) into an obfuscated proxy-source IPv6 address using PRINCE encryption with flow-context XOR tweak and SipHash-2-4 TAG32 MAC. Wire format:

  | Bytes | Value | Meaning |
  |:------|:------|:--------|
  | 0–3   | `PROXY_SRC_PREFIX` | Public /32 prefix |
  | 4–11  | ENC64 | PRINCE_k(P64 XOR H(ctx)), where P64 = client24 ‖ domain24 ‖ PAD16 |
  | 12–15 | TAG32 | truncate32(SipHash-2-4_k2(prefix ‖ ENC64 ‖ ctx)) |

  Returns `None` if client_id or domain_id exceed 24-bit range.

- **`decode_proxy_src(addr, ctx, key) -> Option<(u32, u32)>`** -- Validates TAG32, decrypts ENC64 via PRINCE, unmixes flow context, validates 16-bit zero padding. Returns `None` on any validation failure. Returns `Some((client_id, domain_id))` on success.
- **`client_vip_from_id24(client_id) -> [u8; 16]`** -- Reconstructs the client VIP `fd00:abcd:0:1::<client_id>` from a 24-bit `client_id`. Uses `VIP_POOL_DISCRIMINATOR` for bytes 4–7. Mirrors the strongSwan pool range `::1:0–::ffff:ffff`.

## Crypto Module (`crypto.rs`)

All cryptographic primitives are `no_std` compatible and used by both eBPF and userspace:

- **`prince_encrypt(block, key) -> u64`** -- Full 12-round PRINCE cipher (64-bit block, 128-bit key). Passes all 3 paper test vectors.
- **`prince_decrypt(block, key) -> u64`** -- PRINCE decrypt via alpha-reflection property.
- **`siphash_2_4(key, data) -> u64`** -- SipHash-2-4 via the `siphasher` crate. Passes all 16 Appendix A reference vectors.
- **`hash_ctx(ctx) -> u64`** -- Deterministic context mixer using splitmix64 finalizer. Injective: packs 40-bit context into u64, then applies bijective finalizer.

## Tests

Run with `cargo test -p common`. Currently 29 tests covering:

- PRINCE: 3 paper test vectors + round-trip consistency + M' involution
- SipHash: 16 Appendix A reference vectors + empty input
- hash_ctx: 5 frozen test vectors + distinct output verification
- encode/decode: round-trip, various IDs, different contexts produce different ENC64, same context = deterministic, wrong-key returns None, TAG32 tamper returns None, ENC64 tamper returns None, ID overflow returns None
- Size/alignment invariants for ProxySrcCtx (8 bytes) and ProxySrcKey (32 bytes)
- Prefix distinctness: PROXY_SRC_PREFIX != SYNTHETIC_PREFIX

## Conventions

- All structs use `#[repr(C)]` for BPF map compatibility -- this is mandatory and must not be removed.
- The `userspace` Cargo feature gates `unsafe impl aya::Pod` for each struct. eBPF code uses this crate without that feature; userspace crates (`daemon`) enable it.
- **Never hardcode address-space values** — all constants come from `contract.toml` via `build.rs`. Cargo automatically re-runs `build.rs` when `contract.toml` changes.
- Changes to struct layout here affect both kernel-side eBPF and userspace programs -- always rebuild both after modifying types.
- Adding a new map value type requires: `#[repr(C)]`, an `unsafe impl aya::Pod` behind `#[cfg(feature = "userspace")]`, and rebuilding with `cargo xtask build-ebpf` before `cargo build -p daemon`.
- The proxy-source helpers (`encode_proxy_src`, `decode_proxy_src`, `client_vip_from_id24`) are `no_std` pure functions — they have no side effects and can be called freely from both eBPF and userspace.
- The `siphasher` crate is a direct dependency (no_std, pure Rust). It is expected to compile cleanly for the `bpfel-unknown-none` eBPF target.
