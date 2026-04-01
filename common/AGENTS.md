# common/ -- Shared BPF Map Types

This crate provides `#[repr(C)]` data structures shared between the eBPF kernel programs (`ebpf/`) and userspace Rust binaries (`daemon/`, `dns-server/`). It is `#![no_std]` compatible so it can be compiled for both the `bpfel-unknown-none` eBPF target and standard Linux targets.

## Key Types

- **`NatEntry`** -- Maps a `domain_id` to its real origin IPv6 address. Used in the `NAT_MAP` BPF hash map.
- **`ReverseEntry`** -- Maps an origin IPv6 address back to `(domain_id, client_ipv6)`. Used in the `REVERSE_MAP` BPF hash map. Contains an explicit `_pad` field for C-compatible alignment.
- **`ServerConfig`** -- Stores the server's public IPv6 address and synthetic prefix. Stored in a single-entry `SERVER_CONFIG` BPF array map.
- **`FlowEntry`** -- Tracks an active NAT'd TCP/UDP flow by the server-side source port. Fields: `domain_id`, `_pad` (alignment), `client_ipv6`. Stored in the `NAT_FLOWS` BPF hash map, keyed by `u32` (source port widened from `u16`). Written by `tc_ingress` when forwarding a packet; read by `tc_ingress_wan` to match reply packets to the originating client without address-only disambiguation.

## Key Functions

- **`synthetic_ipv6(domain_id) -> [u8; 16]`** -- Constructs a synthetic `fd00:abcd:XXXX:YYYY::1` address from a `u32` domain ID.
- **`domain_id_from_ipv6(addr) -> u32`** -- Extracts the domain ID from bytes `[4..8]` of a synthetic IPv6 address.

## Conventions

- All structs use `#[repr(C)]` for BPF map compatibility -- this is mandatory and must not be removed.
- The `userspace` Cargo feature gates `unsafe impl aya::Pod` for each struct. eBPF code uses this crate without that feature; userspace crates (`daemon`) enable it.
- The constant `SYNTHETIC_PREFIX: [u8; 4]` defines `fd00:abcd::/32` and is the source of truth for the synthetic address space.
- Changes to struct layout here affect both kernel-side eBPF and userspace programs -- always rebuild both after modifying types.
- Adding a new map value type requires: `#[repr(C)]`, an `unsafe impl aya::Pod` behind `#[cfg(feature = "userspace")]`, and rebuilding with `cargo xtask build-ebpf` before `cargo build -p daemon`.
