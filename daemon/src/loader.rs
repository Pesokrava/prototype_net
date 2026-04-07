use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::{include_bytes_aligned, Ebpf};
use tracing::info;

/// Path where BPF maps are pinned for persistence.
const BPF_PIN_PATH: &str = "/sys/fs/bpf/prototype_net";

/// Maximum number of seconds to wait for the tunnel interface to appear.
const IFACE_WAIT_SECS: u64 = 300;
/// Polling interval while waiting for the interface.
const IFACE_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Block until the network interface `name` appears under /sys/class/net,
/// or return an error if `IFACE_WAIT_SECS` elapses first.
fn wait_for_interface(name: &str) -> Result<()> {
    let sysfs_path = format!("/sys/class/net/{name}");
    let deadline = std::time::Instant::now() + Duration::from_secs(IFACE_WAIT_SECS);
    loop {
        if Path::new(&sysfs_path).exists() {
            info!("Interface {name} is ready");
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!(
                "interface {name} did not appear within {IFACE_WAIT_SECS}s — \
                 is the IPSec tunnel established?"
            );
        }
        info!(
            "Waiting for interface {name} to appear (retrying in {}s)...",
            IFACE_POLL_INTERVAL.as_secs()
        );
        std::thread::sleep(IFACE_POLL_INTERVAL);
    }
}

/// Read the kernel ifindex for a network interface from /sys/class/net.
fn ifindex(name: &str) -> Result<u32> {
    let path = format!("/sys/class/net/{name}/ifindex");
    let s = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read ifindex for {name} from {path}"))?;
    s.trim()
        .parse::<u32>()
        .with_context(|| format!("invalid ifindex for {name}: {s:?}"))
}

/// Load the eBPF ELF, attach TC programs, configure BPF maps.
///
/// - `tunnel_iface`: xfrm0 — client→origin ingress NAT
/// - `wan_iface`: enp0s3 — origin→client reply rewrite + redirect to tunnel
pub fn load_and_attach(tunnel_iface: &str, wan_iface: &str) -> Result<Ebpf> {
    // The eBPF ELF is embedded at compile time.
    // include_bytes_aligned! ensures the data has at least 32-byte alignment,
    // which satisfies the alignment requirements of the `object` crate's ELF
    // parser (Elf64_Ehdr requires 8-byte alignment; 32-byte is a safe superset).
    let elf_bytes = include_bytes_aligned!(concat!(
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

    // Wait for the tunnel interface (e.g. xfrm0) to be created by the kernel.
    // The interface only exists once the IPSec SA is established, so the daemon
    // must poll rather than fail immediately if it starts before the first client
    // connects.
    wait_for_interface(tunnel_iface).context("tunnel interface not available")?;

    // Attach tc_ingress to the tunnel interface (xfrm0) ingress.
    // Handles client→origin direction: rewrites synthetic dst→origin and
    // src→proxy_src_ipv6(client_id, domain_id) for stateless reply routing.
    let _ = tc::qdisc_add_clsact(tunnel_iface);
    let ingress: &mut SchedClassifier = bpf
        .program_mut("tc_ingress")
        .context("tc_ingress program not found")?
        .try_into()
        .context("tc_ingress is not a SchedClassifier")?;
    ingress.load().context("failed to load tc_ingress")?;
    ingress
        .attach(tunnel_iface, TcAttachType::Ingress)
        .context("failed to attach tc_ingress")?;
    info!("Attached tc_ingress to {tunnel_iface}");

    // Attach tc_ingress_wan to the WAN interface (enp0s3) ingress.
    // Handles origin→client direction: decodes proxy-source dst addr to recover
    // client_id + domain_id, rewrites reply src→synthetic, dst→client_VIP,
    // then redirects to xfrm0 egress for IPSec encapsulation back to the client.
    let _ = tc::qdisc_add_clsact(wan_iface);
    let ingress_wan: &mut SchedClassifier = bpf
        .program_mut("tc_ingress_wan")
        .context("tc_ingress_wan program not found")?
        .try_into()
        .context("tc_ingress_wan is not a SchedClassifier")?;
    ingress_wan
        .load()
        .context("failed to load tc_ingress_wan")?;
    ingress_wan
        .attach(wan_iface, TcAttachType::Ingress)
        .context("failed to attach tc_ingress_wan")?;
    info!("Attached tc_ingress_wan to {wan_iface}");

    // Write XFRM_IFINDEX[0] — the tunnel interface's ifindex for bpf_redirect.
    let xfrm_idx = ifindex(tunnel_iface)
        .with_context(|| format!("failed to get ifindex for {tunnel_iface}"))?;
    let mut xfrm_ifindex_map: aya::maps::Array<&mut aya::maps::MapData, u32> =
        aya::maps::Array::try_from(
            bpf.map_mut("XFRM_IFINDEX")
                .context("XFRM_IFINDEX map not found")?,
        )
        .context("failed to open XFRM_IFINDEX as Array")?;
    xfrm_ifindex_map
        .set(0, xfrm_idx, 0)
        .context("failed to write XFRM_IFINDEX[0]")?;
    info!("Wrote XFRM_IFINDEX[0] = {xfrm_idx} ({tunnel_iface})");

    Ok(bpf)
}
