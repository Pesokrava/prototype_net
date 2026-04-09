use std::{fs, path::PathBuf, process::Command};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use serde::Deserialize;

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
    /// Verify that all config files match the constants in contract.toml.
    VerifyContract,
    /// Decode an obfuscated proxy-source IPv6 address to recover client_id and domain_id.
    DecodeProxySrc {
        /// 256-bit key as 64 hex characters (same as PROXY_ADDR_KEY_HEX).
        #[arg(long)]
        key: String,
        /// The proxy-source IPv6 address to decode (e.g. 2001:0db8:xxxx:...).
        #[arg(long)]
        addr: String,
        /// Source port (client's ephemeral port from the original outbound connection).
        #[arg(long)]
        src_port: u16,
        /// Destination port (server port from the original outbound connection, e.g. 443).
        #[arg(long)]
        dst_port: u16,
        /// IP protocol: "tcp" or "udp".
        #[arg(long)]
        proto: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::BuildEbpf => build_ebpf(),
        Commands::VerifyContract => verify_contract(),
        Commands::DecodeProxySrc {
            key,
            addr,
            src_port,
            dst_port,
            proto,
        } => decode_proxy_src(&key, &addr, src_port, dst_port, &proto),
    }
}

// ---------------------------------------------------------------------------
// contract.toml deserialization (mirrors common/build.rs)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct Contract {
    address: Address,
    xfrm: Xfrm,
}

#[derive(Deserialize)]
struct Address {
    synthetic_prefix_cidr: String,
}

#[derive(Deserialize)]
struct Xfrm {
    if_id: u32,
}

// ---------------------------------------------------------------------------
// verify_contract
// ---------------------------------------------------------------------------

fn verify_contract() -> Result<()> {
    let workspace = workspace_root()?;
    let contract_path = workspace.join("contract.toml");

    let src = fs::read_to_string(&contract_path)
        .with_context(|| format!("cannot read {}", contract_path.display()))?;
    let c: Contract = toml::from_str(&src).context("failed to parse contract.toml")?;

    let local_ts = format!("local_ts = {}", c.address.synthetic_prefix_cidr);
    let if_id_in = format!("if_id_in = {}", c.xfrm.if_id);
    let if_id_out = format!("if_id_out = {}", c.xfrm.if_id);
    let xfrm_if_link = format!("if_id {} dev eth0", c.xfrm.if_id);
    // Jinja2 template placeholder — not derived from a value, just checked
    // for presence so we know the template file still contains the substitution.
    let xfrm_j2_placeholder = "{{ xfrm_if_id }}";

    // (file relative to workspace, expected substring, description)
    let checks: &[(&str, &str, &str)] = &[
        (
            "client/swanctl.conf",
            &local_ts,
            "local_ts synthetic prefix",
        ),
        ("client/swanctl.conf", &if_id_in, "if_id_in"),
        ("client/swanctl.conf", &if_id_out, "if_id_out"),
        (
            "client/entrypoint.sh",
            &xfrm_if_link,
            "xfrm if_id in ip link add",
        ),
        (
            "ansible/roles/prototype_net/templates/swanctl.conf.j2",
            "{{ vip_pool_start }}",
            "Jinja2 {{ vip_pool_start }} placeholder",
        ),
        (
            "ansible/roles/prototype_net/templates/swanctl.conf.j2",
            "{{ vip_pool_end }}",
            "Jinja2 {{ vip_pool_end }} placeholder",
        ),
        (
            "ansible/roles/prototype_net/templates/swanctl.conf.j2",
            "{{ synthetic_prefix_cidr }}",
            "Jinja2 {{ synthetic_prefix_cidr }} placeholder",
        ),
        (
            "ansible/roles/prototype_net/templates/swanctl.conf.j2",
            xfrm_j2_placeholder,
            "Jinja2 {{ xfrm_if_id }} placeholder",
        ),
        (
            "ansible/roles/prototype_net/templates/prototype-xfrm0.service.j2",
            xfrm_j2_placeholder,
            "Jinja2 {{ xfrm_if_id }} placeholder",
        ),
    ];

    let mut failures: Vec<String> = Vec::new();

    for (rel_path, pattern, description) in checks {
        let full_path = workspace.join(rel_path);
        let content = match fs::read_to_string(&full_path) {
            Ok(s) => s,
            Err(e) => {
                failures.push(format!("ERROR: {} — could not read file: {}", rel_path, e));
                continue;
            }
        };

        if !content.contains(pattern.as_ref() as &str) {
            failures.push(format!(
                "ERROR: {} — expected pattern not found ({})\n  {}",
                rel_path, description, pattern
            ));
        }
    }

    if failures.is_empty() {
        eprintln!(
            "verify-contract: all checks passed ({} files).",
            checks.len()
        );
        Ok(())
    } else {
        for f in &failures {
            eprintln!("{}", f);
        }
        bail!(
            "verify-contract: {} check(s) failed — update the config files or contract.toml",
            failures.len()
        )
    }
}

// ---------------------------------------------------------------------------
// decode-proxy-src
// ---------------------------------------------------------------------------

fn decode_proxy_src(
    key_hex: &str,
    addr_str: &str,
    src_port: u16,
    dst_port: u16,
    proto: &str,
) -> Result<()> {
    use common::{ProxySrcCtx, ProxySrcKey};

    // Parse key.
    let key_hex = key_hex.trim();
    if key_hex.len() != 64 {
        bail!(
            "key must be exactly 64 hex characters (32 bytes), got {}",
            key_hex.len()
        );
    }
    let mut key_bytes = [0u8; 32];
    for i in 0..32 {
        key_bytes[i] = u8::from_str_radix(&key_hex[i * 2..i * 2 + 2], 16)
            .with_context(|| format!("invalid hex at position {}", i * 2))?;
    }
    let mut prince_key = [0u8; 16];
    let mut siphash_key = [0u8; 16];
    prince_key.copy_from_slice(&key_bytes[0..16]);
    siphash_key.copy_from_slice(&key_bytes[16..32]);
    let key = ProxySrcKey {
        prince_key,
        siphash_key,
    };

    // Parse IPv6 address into 16 bytes.
    let addr_bytes =
        parse_ipv6(addr_str.trim()).with_context(|| format!("invalid IPv6 address: {addr_str}"))?;

    // Parse protocol.
    let proto_num: u8 = match proto.to_lowercase().as_str() {
        "tcp" => 6,
        "udp" => 17,
        _ => bail!("proto must be 'tcp' or 'udp', got '{proto}'"),
    };

    let ctx = ProxySrcCtx::new(src_port, dst_port, proto_num);

    match common::decode_proxy_src(&addr_bytes, &ctx, &key) {
        Some((client_id, domain_id)) => {
            println!("client_id={client_id}, domain_id={domain_id}");
            // Also print the reconstructed client VIP and synthetic address.
            let vip = common::client_vip_from_id24(client_id);
            let synthetic = common::synthetic_ipv6(domain_id);
            println!("client_vip={}", format_ipv6(&vip));
            println!("synthetic_addr={}", format_ipv6(&synthetic));
        }
        None => {
            eprintln!("DECODE FAILED: tag mismatch, padding error, or wrong key/context");
            std::process::exit(1);
        }
    }

    Ok(())
}

/// Parse a textual IPv6 address (with :: shorthand) into a 16-byte array.
/// Supports both full and compressed forms: `2001:0db8::1`, `::1`, etc.
fn parse_ipv6(s: &str) -> Result<[u8; 16]> {
    // Use std::net for parsing.
    let addr: std::net::Ipv6Addr = s
        .parse()
        .with_context(|| format!("failed to parse IPv6: {s}"))?;
    Ok(addr.octets())
}

/// Format 16 bytes as a canonical IPv6 string.
fn format_ipv6(bytes: &[u8; 16]) -> String {
    let addr = std::net::Ipv6Addr::from(*bytes);
    format!("{addr}")
}

// ---------------------------------------------------------------------------
// build_ebpf
// ---------------------------------------------------------------------------

fn build_ebpf() -> Result<()> {
    // Ensure all config files are consistent with contract.toml before building.
    verify_contract()?;

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

fn workspace_root() -> Result<PathBuf> {
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
