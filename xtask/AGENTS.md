# xtask/ -- Build Automation

This crate implements the `cargo xtask` pattern for workspace build automation. Its primary purpose is cross-compiling the eBPF programs, which require a different toolchain and target than the rest of the workspace.

## Usage

```sh
cargo xtask build-ebpf
```

This runs: `cargo +nightly build -Z build-std=core --target bpfel-unknown-none --release -p ebpf`

The compiled eBPF ELF is output to `target/bpfel-unknown-none/release/ebpf` and is embedded into the `daemon` binary at compile time via `include_bytes!()`.

## Key Files

- `src/main.rs` -- CLI entry point using `clap`. Defines the `BuildEbpf` subcommand. Locates the workspace root dynamically via `cargo locate-project`.

## Why This Exists

The `ebpf/` crate is excluded from the Cargo workspace because it requires the nightly toolchain and the `bpfel-unknown-none` target with `build-std=core`. Building it as part of a normal `cargo build` would fail. The xtask pattern provides a clean way to invoke this specialized build step.

## Conventions

- Invoked via the `xtask` alias defined in `.cargo/config.toml`: `[alias] xtask = "run --package xtask --"`.
- Uses `clap` with derive macros for CLI parsing.
- Must be run before building the `daemon` crate.
