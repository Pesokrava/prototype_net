use std::net::Ipv6Addr;

use anyhow::{Context, Result};
use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::Ebpf;
use common::ServerConfig;
use tracing::info;

/// Path where BPF maps are pinned for persistence.
const BPF_PIN_PATH: &str = "/sys/fs/bpf/prototype_net";

/// Load the eBPF ELF, attach TC ingress/egress, configure server.
pub fn load_and_attach(interface: &str, server_ipv6: Ipv6Addr) -> Result<Ebpf> {
    // The eBPF ELF is embedded at compile time.
    // This path is relative to the workspace root target directory.
    let elf_bytes = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../target/bpfel-unknown-none/release/ebpf"
    ));

    let mut bpf = Ebpf::load(elf_bytes).context("failed to load eBPF object")?;

    // Initialize aya-log for eBPF logging
    if let Err(e) = aya_log::EbpfLogger::init(&mut bpf) {
        tracing::warn!("Failed to initialize eBPF logger: {e}");
    }

    // Create pin directory
    std::fs::create_dir_all(BPF_PIN_PATH).context("failed to create BPF pin directory")?;

    // Add clsact qdisc to the interface (required for TC programs)
    let _ = tc::qdisc_add_clsact(interface);

    // Attach TC ingress
    let ingress: &mut SchedClassifier = bpf
        .program_mut("tc_ingress")
        .context("tc_ingress program not found")?
        .try_into()
        .context("tc_ingress is not a SchedClassifier")?;
    ingress.load().context("failed to load tc_ingress")?;
    ingress
        .attach(interface, TcAttachType::Ingress)
        .context("failed to attach tc_ingress")?;
    info!("Attached tc_ingress to {interface}");

    // Attach TC egress
    let egress: &mut SchedClassifier = bpf
        .program_mut("tc_egress")
        .context("tc_egress program not found")?
        .try_into()
        .context("tc_egress is not a SchedClassifier")?;
    egress.load().context("failed to load tc_egress")?;
    egress
        .attach(interface, TcAttachType::Egress)
        .context("failed to attach tc_egress")?;
    info!("Attached tc_egress to {interface}");

    // Write SERVER_CONFIG[0]
    let mut server_config_map: aya::maps::Array<&mut aya::maps::MapData, ServerConfig> =
        aya::maps::Array::try_from(
            bpf.map_mut("SERVER_CONFIG")
                .context("SERVER_CONFIG map not found")?,
        )
        .context("failed to open SERVER_CONFIG as Array")?;

    let config = ServerConfig {
        server_pub_ipv6: server_ipv6.octets(),
        prefix: [0xfd, 0x00, 0xab, 0xcd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    };
    server_config_map
        .set(0, config, 0)
        .context("failed to write SERVER_CONFIG[0]")?;
    info!("Wrote SERVER_CONFIG[0] with server IPv6: {server_ipv6}");

    Ok(bpf)
}
