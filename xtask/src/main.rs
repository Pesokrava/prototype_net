use std::process::Command;

use anyhow::{bail, Context, Result};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(|s| s.as_str()) {
        Some("build-ebpf") => build_ebpf(),
        Some(cmd) => bail!("unknown xtask command: {cmd}"),
        None => {
            eprintln!("Usage: cargo xtask <COMMAND>");
            eprintln!();
            eprintln!("Commands:");
            eprintln!("  build-ebpf    Build the eBPF program with nightly toolchain");
            Ok(())
        }
    }
}

fn build_ebpf() -> Result<()> {
    let status = Command::new("cargo")
        .args([
            "+nightly",
            "build",
            "-Z",
            "build-std=core",
            "--target",
            "bpfel-unknown-none",
            "--release",
            "-p",
            "ebpf",
        ])
        .current_dir(workspace_root()?)
        .status()
        .context("failed to run cargo +nightly build for eBPF")?;

    if !status.success() {
        bail!("eBPF build failed with status: {status}");
    }

    let elf_path = workspace_root()?
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
