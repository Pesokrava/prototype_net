use std::process::Command;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};

/// Workspace automation tasks, invoked via `cargo xtask`.
#[derive(Parser)]
#[command(name = "cargo xtask", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Build the eBPF program with the nightly toolchain.
    BuildEbpf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::BuildEbpf => build_ebpf(),
    }
}

fn build_ebpf() -> Result<()> {
    let workspace = workspace_root()?;

    let status = Command::new("cargo")
        .args([
            "+nightly",
            "build",
            "-Z",
            "build-std=core",
            "--target",
            "bpfel-unknown-none",
            "--release",
        ])
        .env("CARGO_TARGET_DIR", workspace.join("target"))
        .current_dir(workspace.join("ebpf"))
        .status()
        .context("failed to run cargo +nightly build for eBPF")?;

    if !status.success() {
        bail!("eBPF build failed with status: {status}");
    }

    let elf_path = workspace
        .join("target")
        .join("bpfel-unknown-none")
        .join("release")
        .join("ebpf");
    eprintln!("eBPF object built at: {}", elf_path.display());
    Ok(())
}

fn workspace_root() -> Result<std::path::PathBuf> {
    let output = Command::new("cargo")
        .args(["locate-project", "--workspace", "--message-format=plain"])
        .output()
        .context("failed to run cargo locate-project")?;
    let path = String::from_utf8(output.stdout)?;
    Ok(std::path::Path::new(path.trim())
        .parent()
        .expect("Cargo.toml should have a parent")
        .to_path_buf())
}
