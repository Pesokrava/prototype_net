# xtask/ -- Build Automation

This crate implements the `cargo xtask` pattern for workspace build automation. It handles
cross-compiling the eBPF programs (which require a different toolchain and target) and
enforcing that all config files stay in sync with `contract.toml`.

## Subcommands

### `cargo xtask build-ebpf`

Calls `verify-contract` first, then runs:

```sh
cargo +nightly build -Z build-std=core --target bpfel-unknown-none --release -p ebpf
```

The compiled eBPF ELF is output to `target/bpfel-unknown-none/release/ebpf` and is embedded
into the `daemon` binary at compile time via `include_bytes!()`.

**`verify-contract` is called automatically** before the eBPF build. A drifted config file
causes the build to fail immediately with a clear error listing every divergence.

### `cargo xtask verify-contract`

Reads `contract.toml` at the workspace root, derives the expected string form of every
address-space constant, and checks that each of the following config files contains the
expected substring:

| File | Pattern checked | Derived from |
|:-----|:----------------|:-------------|
| `client/swanctl.conf` | `local_ts = <synthetic_prefix_cidr>` | `address.synthetic_prefix_cidr` |
| `client/swanctl.conf` | `if_id_in = <if_id>` | `xfrm.if_id` |
| `client/swanctl.conf` | `if_id_out = <if_id>` | `xfrm.if_id` |
| `client/entrypoint.sh` | `if_id <if_id> dev eth0` | `xfrm.if_id` |
| `ansible/roles/prototype_net/templates/swanctl.conf.j2` | `{{ vip_pool_start }}` | literal template placeholder |
| `ansible/roles/prototype_net/templates/swanctl.conf.j2` | `{{ vip_pool_end }}` | literal template placeholder |
| `ansible/roles/prototype_net/templates/swanctl.conf.j2` | `{{ synthetic_prefix_cidr }}` | literal template placeholder |
| `ansible/roles/prototype_net/templates/swanctl.conf.j2` | `{{ xfrm_if_id }}` | literal template placeholder |
| `ansible/roles/prototype_net/templates/prototype-xfrm0.service.j2` | `{{ xfrm_if_id }}` | literal template placeholder |

All failures are collected and printed before exiting so the user sees every divergence in
one run. Use this command for fast feedback when editing config files without doing a full
rebuild:

```sh
cargo xtask verify-contract
```

## Key Files

- `src/main.rs` -- CLI entry point using `clap`. Defines `BuildEbpf` and `VerifyContract`
  subcommands. Reads and deserialises `contract.toml` for the verify step. Locates the
  workspace root dynamically via `cargo locate-project`.

## Single Source of Truth

`contract.toml` at the workspace root is the authoritative definition for all address-space
constants (synthetic prefix, VIP pool range, XFRM `if_id`). `verify-contract` mechanically
enforces consistency between `contract.toml` and all config files at build time.

## Why This Exists

The `ebpf/` crate is excluded from the Cargo workspace because it requires the nightly
toolchain and the `bpfel-unknown-none` target with `build-std=core`. Building it as part of
a normal `cargo build` would fail. The xtask pattern provides a clean way to invoke this
specialised build step while also running pre-build sanity checks.

## Conventions

- Invoked via the `xtask` alias defined in `.cargo/config.toml`: `[alias] xtask = "run --package xtask --"`.
- Uses `clap` with derive macros for CLI parsing.
- Uses `toml` + `serde` (runtime deps) to parse `contract.toml` in `verify_contract()` —
  distinct from `common/build.rs` which uses them as build-dependencies.
- Must be run (via `build-ebpf` or `verify-contract`) before building the `daemon` crate to
  ensure the eBPF ELF is up to date.
