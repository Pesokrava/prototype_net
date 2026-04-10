use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use aya::programs::{SchedClassifier, TcAttachType, Xdp, XdpFlags, tc};
use aya::{Ebpf, include_bytes_aligned};
use common::ProxySrcKey;
use tracing::info;

/// Path where BPF maps are pinned for persistence.
const BPF_PIN_PATH: &str = "/sys/fs/bpf/prototype_net";

/// Polling interval while waiting for the interface.
const IFACE_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Async: wait indefinitely for the network interface `name` to appear under
/// /sys/class/net, polling every `IFACE_POLL_INTERVAL`.
///
/// Returns `Ok(())` once the interface exists, or `Err` if a shutdown signal
/// (SIGINT / SIGTERM) is received before the interface appears.
pub async fn wait_for_interface(name: &str) -> Result<()> {
    use tokio::signal::unix::{SignalKind, signal};

    let sysfs_path = format!("/sys/class/net/{name}");

    // Register SIGTERM handler once, before entering the poll loop.
    let mut sigterm = signal(SignalKind::terminate())
        .context("failed to register SIGTERM handler")?;

    loop {
        if Path::new(&sysfs_path).exists() {
            info!("Interface {name} is ready");
            return Ok(());
        }

        info!(
            "Waiting for interface {name} to appear (retrying in {}s)...",
            IFACE_POLL_INTERVAL.as_secs()
        );

        tokio::select! {
            // Shutdown signals: propagate as an error so main() exits cleanly.
            _ = tokio::signal::ctrl_c() => {
                anyhow::bail!("interrupted while waiting for interface {name}");
            }
            _ = sigterm.recv() => {
                anyhow::bail!("received SIGTERM while waiting for interface {name}");
            }
            // Poll interval elapsed — go around the loop and re-check sysfs.
            _ = tokio::time::sleep(IFACE_POLL_INTERVAL) => {}
        }
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
/// - `active_key`: proxy-source obfuscation key for OBFS_KEYS[0]
/// - `prev_key`: optional previous key for OBFS_KEYS[1] (rotation grace window)
///
/// In dev-mode (build feature), also auto-detects WAN IPv6 and populates DEV_WAN_IPV6 map.
pub fn load_and_attach(
    tunnel_iface: &str,
    wan_iface: &str,
    active_key: &ProxySrcKey,
    prev_key: Option<&ProxySrcKey>,
) -> Result<Ebpf> {
    // The eBPF ELF is embedded at compile time.
    // include_bytes_aligned! ensures the data has at least 32-byte alignment,
    // which satisfies the alignment requirements of the `object` crate's ELF
    // parser (Elf64_Ehdr requires 8-byte alignment; 32-byte is a safe superset).
    let elf_bytes = include_bytes_aligned!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../target/bpfel-unknown-none/release/ebpf"
    ));

    let mut bpf = Ebpf::load(elf_bytes).context("failed to load eBPF object")?;

    // Initialize aya-log for eBPF logging.
    // The returned EbpfLogger must be kept alive for the lifetime of the program —
    // dropping it stops the internal perf-buffer poller and silences all BPF log output.
    // We intentionally leak it so it lives for 'static.
    match aya_log::EbpfLogger::init(&mut bpf) {
        Ok(logger) => {
            info!("eBPF logger initialized");
            // Leak the logger so it is never dropped and keeps polling.
            Box::leak(Box::new(logger));
        }
        Err(e) => {
            tracing::warn!("Failed to initialize eBPF logger: {e}");
        }
    };

    // Create pin directory
    std::fs::create_dir_all(BPF_PIN_PATH).context("failed to create BPF pin directory")?;

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

    // Attach xdp_wan to WAN ingress for early fd00:abcd::/32 destination filtering.
    let xdp_wan: &mut Xdp = bpf
        .program_mut("xdp_wan")
        .context("xdp_wan program not found")?
        .try_into()
        .context("xdp_wan is not an Xdp program")?;
    xdp_wan.load().context("failed to load xdp_wan")?;
    xdp_wan
        .attach(wan_iface, XdpFlags::default())
        .context("failed to attach xdp_wan")?;
    info!("Attached xdp_wan to {wan_iface}");

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

    // Write OBFS_KEYS — proxy-source obfuscation keys for PRINCE + SipHash.
    let mut obfs_keys_map: aya::maps::Array<&mut aya::maps::MapData, ProxySrcKey> =
        aya::maps::Array::try_from(
            bpf.map_mut("OBFS_KEYS")
                .context("OBFS_KEYS map not found")?,
        )
        .context("failed to open OBFS_KEYS as Array")?;

    // Slot 0: active key (required).
    obfs_keys_map
        .set(0, *active_key, 0)
        .context("failed to write OBFS_KEYS[0]")?;
    info!("Wrote OBFS_KEYS[0] (active key)");

    // Slot 1: previous key (optional, for rotation grace window).
    if let Some(prev) = prev_key {
        obfs_keys_map
            .set(1, *prev, 0)
            .context("failed to write OBFS_KEYS[1]")?;
        info!("Wrote OBFS_KEYS[1] (previous key for rotation grace window)");
    }

    // Dev-mode: auto-detect WAN IPv6 and populate DEV_WAN_IPV6 map.
    // This enables double-NAT for dev testing: tc_ingress uses WAN IPv6 as source,
    // and xdp_wan rewrites reply packets back to proxy-source.
    #[cfg(feature = "dev-mode")]
    {
        let wan_ipv6 = get_wan_ipv6(wan_iface)
            .context("failed to auto-detect WAN IPv6 for dev-mode")?;
        
        let mut dev_wan_map: aya::maps::Array<&mut aya::maps::MapData, [u8; 16]> =
            aya::maps::Array::try_from(
                bpf.map_mut("DEV_WAN_IPV6")
                    .context("DEV_WAN_IPV6 map not found")?,
            )
            .context("failed to open DEV_WAN_IPV6 as Array")?;
        dev_wan_map
            .set(0, wan_ipv6.octets(), 0)
            .context("failed to write DEV_WAN_IPV6[0]")?;
        info!("Dev-mode: set DEV_WAN_IPV6[0] = {} (auto-detected from {})", wan_ipv6, wan_iface);

        // WAN_IFINDEX removed: xdp_wan now uses XDP_PASS after rewrite instead of bpf_redirect.
    }

    Ok(bpf)
}

/// Get the global IPv6 address assigned to a network interface.
#[cfg(feature = "dev-mode")]
fn get_wan_ipv6(iface: &str) -> Result<std::net::Ipv6Addr> {
    let addrs = nix::ifaddrs::getifaddrs()
        .context("failed to get interface addresses")?;
    
    for ifaddr in addrs {
        if ifaddr.interface_name == iface {
            if let Some(addr) = ifaddr.address {
                if let Some(sockaddr_in6) = addr.as_sockaddr_in6() {
                    let ip = sockaddr_in6.ip();
                    // Skip link-local addresses (fe80::)
                    if !ip.is_unicast_link_local() {
                        return Ok(ip);
                    }
                }
            }
        }
    }
    
    anyhow::bail!("no global IPv6 address found on interface {}", iface)
}
