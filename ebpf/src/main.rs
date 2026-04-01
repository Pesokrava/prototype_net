#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{
    bindings::TC_ACT_OK,
    bindings::TC_ACT_SHOT,
    helpers::{bpf_csum_diff, bpf_redirect},
    macros::{classifier, map},
    maps::{Array, HashMap},
    programs::TcContext,
};
use aya_log_ebpf::info;
use common::{FlowEntry, NatEntry, ReverseEntry, ServerConfig, SYNTHETIC_PREFIX};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

// ---------------------------------------------------------------------------
// BPF Maps
// ---------------------------------------------------------------------------

/// domain_id (u32) → NatEntry { origin_ipv6 }
#[map]
static NAT_MAP: HashMap<u32, NatEntry> = HashMap::with_max_entries(65536, 0);

/// origin_ipv6 ([u8;16]) → ReverseEntry { domain_id, client_ipv6 }
#[map]
static REVERSE_MAP: HashMap<[u8; 16], ReverseEntry> = HashMap::with_max_entries(65536, 0);

/// Index 0 → ServerConfig { server_pub_ipv6, prefix }
#[map]
static SERVER_CONFIG: Array<ServerConfig> = Array::with_max_entries(1, 0);

/// Index 0 → xfrm0 interface index (for bpf_redirect in tc_ingress_wan)
#[map]
static XFRM_IFINDEX: Array<u32> = Array::with_max_entries(1, 0);

/// server src_port (u16, stored as u32 key) → FlowEntry { domain_id, client_ipv6 }
/// Populated by tc_ingress when forwarding a client packet to origin.
/// Consumed by tc_ingress_wan to match reply packets to the correct client.
#[map]
static NAT_FLOWS: HashMap<u32, FlowEntry> = HashMap::with_max_entries(65536, 0);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Return a raw pointer to type `T` at `offset` bytes into the packet,
/// or `Err(())` if that would exceed the packet's data_end boundary.
#[inline(always)]
unsafe fn ptr_at<T>(ctx: &TcContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    if start + offset + mem::size_of::<T>() > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

/// BPF flag: the updated field is in the pseudo-header (used for IP address updates
/// that affect TCP/UDP checksums, which include the pseudo-header).
/// Corresponds to BPF_F_PSEUDO_HDR = (1 << 4) from include/uapi/linux/bpf.h.
const BPF_F_PSEUDO_HDR: u64 = 1 << 4;

/// BPF flag: if the result of a checksum update is zero, store 0xffff rather than 0.
/// Also signals to the kernel to transition the skb to CHECKSUM_PARTIAL (the kernel will
/// recompute the stored L4 checksum on transmit).  Combined with BPF_F_PSEUDO_HDR this
/// sidesteps CHECKSUM_COMPLETE interactions on NIC-offloaded ingress packets.
/// Corresponds to BPF_F_MARK_MANGLED_0 = (1 << 5) from include/uapi/linux/bpf.h.
const BPF_F_MARK_MANGLED_0: u64 = 1 << 5;

/// Update the L4 checksum for a single address change (one 16-byte IPv6 address).
///
/// Uses `bpf_csum_diff` to compute the exact checksum delta for replacing `old_addr`
/// with `new_addr`, then applies it via `l4_csum_replace` with `BPF_F_PSEUDO_HDR`.
///
/// This avoids endianness ambiguity in the incremental word-by-word approach.
/// Not inlined — keeps the call stack shallow in both TC programs.
#[inline(never)]
fn update_addr_csum(
    ctx: &mut TcContext,
    csum_offset: usize,
    old_addr: &[u8; 16],
    new_addr: &[u8; 16],
) -> Result<(), ()> {
    let diff = unsafe {
        bpf_csum_diff(
            old_addr.as_ptr() as *mut u32,
            16,
            new_addr.as_ptr() as *mut u32,
            16,
            0,
        )
    };
    // diff is a __s64 running checksum delta (not yet folded).
    // Use l4_csum_replace size=0 to fold it into the stored checksum.
    // size=0 case: sum = csum_fold(csum_unfold(*ptr) + csum_partial(&to, sizeof(to), 0))
    // We pass diff as `to`. sizeof(to for u64) = 8, but diff is a csum_diff result.
    // Actually use the standard approach: apply diff via l4_csum_replace with BPF_F_PSEUDO_HDR.
    ctx.l4_csum_replace(csum_offset, 0, diff as u64, BPF_F_PSEUDO_HDR)
        .map_err(|_| ())?;
    Ok(())
}

/// Determine the byte offset to the IPv6 header in the packet.
///
/// `xfrm0` (and other raw-IP interfaces) deliver packets with no Ethernet
/// framing — the packet data begins directly with the IP header.  Regular
/// Ethernet interfaces prepend a 14-byte `EthHdr`.
///
/// We auto-detect by peeking at the first byte:
///   - If the upper nibble is 6, the packet starts with an IPv6 header.
///   - Otherwise we assume an Ethernet header and look for EtherType::Ipv6.
///
/// Returns `Ok(ipv6_offset)` or `Err(())` to pass the packet through.
#[inline(always)]
fn ipv6_offset(ctx: &TcContext) -> Result<usize, ()> {
    // Peek at first byte to decide framing.
    let first_byte: u8 = ctx.load(0).map_err(|_| ())?;
    if (first_byte >> 4) == 6 {
        // Raw IPv6 — no Ethernet header.
        return Ok(0);
    }

    // Ethernet framing — validate EtherType.
    let ethhdr: *const EthHdr = unsafe { ptr_at(ctx, 0)? };
    if unsafe { (*ethhdr).ether_type() } != Ok(EtherType::Ipv6) {
        return Err(());
    }
    Ok(EthHdr::LEN)
}

// ---------------------------------------------------------------------------
// TC Ingress on xfrm0 — client→origin direction
//
// Packets arriving from the IPSec tunnel with dst in fd00:abcd::/32.
// Rewrite dst to the real origin IPv6, rewrite src to server's public IPv6.
// ---------------------------------------------------------------------------

#[classifier]
pub fn tc_ingress(mut ctx: TcContext) -> i32 {
    match try_tc_ingress(&mut ctx) {
        Ok(action) => action,
        Err(_) => TC_ACT_OK, // pass through on error
    }
}

fn try_tc_ingress(ctx: &mut TcContext) -> Result<i32, ()> {
    // Determine where the IPv6 header starts (raw IP vs Ethernet).
    let ip_off = ipv6_offset(ctx).map_err(|_| ())?;

    // Parse IPv6 header.
    let ipv6hdr: *const Ipv6Hdr = unsafe { ptr_at(ctx, ip_off)? };

    // Extension headers: if next_hdr is not directly TCP or UDP, we cannot
    // safely walk the header chain to find and update the L4 checksum.
    // Pass the packet through unmodified to avoid silent corruption.
    let nexthdr = unsafe { (*ipv6hdr).next_hdr };
    match nexthdr {
        IpProto::Tcp | IpProto::Udp => {}
        _ => {
            return Ok(TC_ACT_OK);
        }
    }

    // Bounds-check the L4 header before any packet mutation.
    let l4_base = ip_off + Ipv6Hdr::LEN;
    match nexthdr {
        IpProto::Tcp => {
            let _: *const TcpHdr = unsafe { ptr_at(ctx, l4_base)? };
        }
        _ => {
            let _: *const UdpHdr = unsafe { ptr_at(ctx, l4_base)? };
        }
    }

    // Read destination IPv6 address.
    let dst_ipv6: [u8; 16] = unsafe { (*ipv6hdr).dst_addr };

    // Check prefix: fd00:abcd::/32
    if dst_ipv6[0] != SYNTHETIC_PREFIX[0]
        || dst_ipv6[1] != SYNTHETIC_PREFIX[1]
        || dst_ipv6[2] != SYNTHETIC_PREFIX[2]
        || dst_ipv6[3] != SYNTHETIC_PREFIX[3]
    {
        return Ok(TC_ACT_OK);
    }

    // Extract domain_id from bytes [4..8] of the destination address.
    let domain_id = u32::from_be_bytes([dst_ipv6[4], dst_ipv6[5], dst_ipv6[6], dst_ipv6[7]]);

    // Look up the real origin IPv6 from NAT_MAP.
    let nat_entry = unsafe { NAT_MAP.get(&domain_id) };
    let nat_entry = match nat_entry {
        Some(e) => e,
        None => {
            info!(ctx, "tc_ingress: NAT_MAP miss for domain_id={}", domain_id);
            return Ok(TC_ACT_SHOT);
        }
    };

    // Load server config for src rewrite.
    let server_cfg = SERVER_CONFIG.get(0);
    let server_cfg = match server_cfg {
        Some(c) => c,
        None => return Ok(TC_ACT_SHOT),
    };

    // Save original src for checksum fixup (read before any stores).
    let orig_src: [u8; 16] = unsafe { (*ipv6hdr).src_addr };

    // Byte offsets for src/dst address fields within the packet.
    // IPv6Hdr layout: vcf(4) + payload_len(2) + next_hdr(1) + hop_limit(1) + src(16) + dst(16)
    let ipv6_src_offset = ip_off + 8;
    let ipv6_dst_offset = ip_off + 24;

    // L4 checksum offset.
    let csum_offset = match nexthdr {
        IpProto::Tcp => l4_base + 16,
        _ => l4_base + 6, // UDP
    };

    // Rewrite dst → origin IPv6
    for i in 0..16 {
        ctx.store(ipv6_dst_offset + i, &nat_entry.origin_ipv6[i], 0)
            .map_err(|_| ())?;
    }

    // Rewrite src → server's public IPv6
    for i in 0..16 {
        ctx.store(ipv6_src_offset + i, &server_cfg.server_pub_ipv6[i], 0)
            .map_err(|_| ())?;
    }

    // Incremental L4 checksum updates.
    update_addr_csum(ctx, csum_offset, &orig_src, &server_cfg.server_pub_ipv6)?;
    update_addr_csum(ctx, csum_offset, &dst_ipv6, &nat_entry.origin_ipv6)?;

    // Record this flow in NAT_FLOWS so tc_ingress_wan can match the reply.
    // Key: src_port (after kernel assigned it, this is the port Google sees as dst).
    let src_port = match nexthdr {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = unsafe { ptr_at(ctx, l4_base)? };
            u16::from_be_bytes(unsafe { (*tcphdr).source })
        }
        _ => {
            let udphdr: *const UdpHdr = unsafe { ptr_at(ctx, l4_base)? };
            u16::from_be_bytes(unsafe { (*udphdr).src })
        }
    };
    let flow = FlowEntry {
        domain_id,
        _pad: 0,
        client_ipv6: orig_src,
    };
    // Store keyed by src_port (widened to u32 to satisfy BPF map key size).
    let _ = NAT_FLOWS.insert(&(src_port as u32), &flow, 0);

    info!(ctx, "tc_ingress: rewrote domain_id={}", domain_id);

    Ok(TC_ACT_OK)
}

// ---------------------------------------------------------------------------
// TC Ingress on WAN interface (e.g. enp0s3) — origin→client direction
//
// Reply packets arriving from origin servers on the WAN interface.
// If src matches a known origin in REVERSE_MAP, rewrite:
//   src → synthetic IPv6 (fd00:abcd:XXXX:YYYY::1)
//   dst → client's IPv6
// Then redirect to xfrm0 (which will encrypt via IPSec and deliver to client).
// ---------------------------------------------------------------------------

#[classifier]
pub fn tc_ingress_wan(mut ctx: TcContext) -> i32 {
    match try_tc_ingress_wan(&mut ctx) {
        Ok(action) => action,
        Err(_) => TC_ACT_OK,
    }
}

fn try_tc_ingress_wan(ctx: &mut TcContext) -> Result<i32, ()> {
    // Determine where the IPv6 header starts.
    let ip_off = ipv6_offset(ctx).map_err(|_| ())?;

    // Parse IPv6 header.
    let ipv6hdr: *const Ipv6Hdr = unsafe { ptr_at(ctx, ip_off)? };

    // Extension headers: pass through to avoid corruption.
    let nexthdr = unsafe { (*ipv6hdr).next_hdr };
    match nexthdr {
        IpProto::Tcp | IpProto::Udp => {}
        _ => {
            return Ok(TC_ACT_OK);
        }
    }

    // Bounds-check the L4 header before any packet mutation.
    let l4_base = ip_off + Ipv6Hdr::LEN;
    match nexthdr {
        IpProto::Tcp => {
            let _: *const TcpHdr = unsafe { ptr_at(ctx, l4_base)? };
        }
        _ => {
            let _: *const UdpHdr = unsafe { ptr_at(ctx, l4_base)? };
        }
    }

    // Read destination port — this is the server-side src port of the original
    // outbound flow (stored in NAT_FLOWS by tc_ingress).
    let dst_port = match nexthdr {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = unsafe { ptr_at(ctx, l4_base)? };
            u16::from_be_bytes(unsafe { (*tcphdr).dest })
        }
        _ => {
            let udphdr: *const UdpHdr = unsafe { ptr_at(ctx, l4_base)? };
            u16::from_be_bytes(unsafe { (*udphdr).dst })
        }
    };

    // Look up this reply flow by dst_port in NAT_FLOWS.
    let flow_entry = unsafe { NAT_FLOWS.get(&(dst_port as u32)) };
    let flow_entry = match flow_entry {
        Some(e) => e,
        None => return Ok(TC_ACT_OK), // not a tracked NAT flow, pass through
    };

    // Read source IPv6 address and verify it is known in REVERSE_MAP.
    // This double-check ensures we don't accidentally intercept unrelated traffic
    // that happens to use the same dst_port.
    let src_ipv6: [u8; 16] = unsafe { (*ipv6hdr).src_addr };
    let rev_entry = unsafe { REVERSE_MAP.get(&src_ipv6) };
    if rev_entry.is_none() {
        return Ok(TC_ACT_OK);
    }

    // Save original dst for checksum fixup (read before any stores).
    let orig_dst: [u8; 16] = unsafe { (*ipv6hdr).dst_addr };

    // Build synthetic IPv6 from domain_id.
    let synthetic = common::synthetic_ipv6(flow_entry.domain_id);

    // Byte offsets for src/dst address fields within the packet.
    let ipv6_src_offset = ip_off + 8;
    let ipv6_dst_offset = ip_off + 24;

    // L4 checksum offset.
    let csum_offset = match nexthdr {
        IpProto::Tcp => l4_base + 16,
        _ => l4_base + 6, // UDP
    };

    // Rewrite src → synthetic address
    for i in 0..16 {
        ctx.store(ipv6_src_offset + i, &synthetic[i], 0)
            .map_err(|_| ())?;
    }

    // Rewrite dst → client IPv6
    for i in 0..16 {
        ctx.store(ipv6_dst_offset + i, &flow_entry.client_ipv6[i], 0)
            .map_err(|_| ())?;
    }

    // Incremental L4 checksum updates (bpf_csum_diff-based, endian-safe).
    update_addr_csum(ctx, csum_offset, &src_ipv6, &synthetic)?;
    update_addr_csum(ctx, csum_offset, &orig_dst, &flow_entry.client_ipv6)?;

    // Mark the checksum as CHECKSUM_PARTIAL so the kernel recomputes it on
    // xfrm0 egress.  WAN-ingress packets often arrive with ip_summed =
    // CHECKSUM_COMPLETE (NIC hardware checksum); calling l4_csum_replace with
    // BPF_F_PSEUDO_HDR | BPF_F_MARK_MANGLED_0 and from=0/to=0 is a no-op for
    // the stored value but transitions ip_summed to CHECKSUM_PARTIAL, which
    // causes the kernel transmit path to recompute the checksum from scratch.
    // This sidesteps the subtle CHECKSUM_COMPLETE vs incremental-delta mismatch
    // identified in the debugging session.
    ctx.l4_csum_replace(csum_offset, 0, 0, BPF_F_PSEUDO_HDR | BPF_F_MARK_MANGLED_0)
        .map_err(|_| ())?;

    // Look up xfrm0 ifindex for redirect.
    let xfrm_ifindex = XFRM_IFINDEX.get(0);
    let xfrm_ifindex = match xfrm_ifindex {
        Some(idx) if *idx != 0 => *idx,
        _ => {
            info!(ctx, "tc_ingress_wan: XFRM_IFINDEX not set, dropping");
            return Ok(TC_ACT_SHOT);
        }
    };

    info!(
        ctx,
        "tc_ingress_wan: rewrote domain_id={}, redirecting to xfrm0", flow_entry.domain_id
    );

    // Redirect to xfrm0 egress so it goes through the IPSec tunnel to the client.
    // bpf_redirect returns TC_ACT_REDIRECT (7) on success.
    Ok(unsafe { bpf_redirect(xfrm_ifindex, 0) } as i32)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
