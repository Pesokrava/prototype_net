#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{
    bindings::TC_ACT_OK,
    bindings::TC_ACT_SHOT,
    macros::{classifier, map},
    maps::{Array, HashMap},
    programs::TcContext,
};
use aya_log_ebpf::info;
use common::{NatEntry, ReverseEntry, ServerConfig, SYNTHETIC_PREFIX};
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

// ---------------------------------------------------------------------------
// Packet offset constants (derived from network-types struct sizes)
// ---------------------------------------------------------------------------

// Byte offset of the IPv6 src address field within the packet.
// EthHdr (14 bytes) + vcf(4) + payload_len(2) + next_hdr(1) + hop_limit(1) = offset 22.
const IPV6_SRC_OFFSET: usize = EthHdr::LEN + 8;
// Byte offset of the IPv6 dst address field within the packet.
// src_addr is 16 bytes after IPV6_SRC_OFFSET.
const IPV6_DST_OFFSET: usize = EthHdr::LEN + 24;

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

/// Update the L4 checksum for a single address change (one 16-byte IPv6 address).
/// Processes the address as 4 × u32 words using incremental checksum replacement.
/// Not inlined — keeps the call stack shallow in both TC programs.
#[inline(never)]
fn update_addr_csum(
    ctx: &mut TcContext,
    csum_offset: usize,
    old_addr: &[u8; 16],
    new_addr: &[u8; 16],
) -> Result<(), ()> {
    for i in 0..4 {
        let off = i * 4;
        let old_word = u32::from_be_bytes([
            old_addr[off],
            old_addr[off + 1],
            old_addr[off + 2],
            old_addr[off + 3],
        ]);
        let new_word = u32::from_be_bytes([
            new_addr[off],
            new_addr[off + 1],
            new_addr[off + 2],
            new_addr[off + 3],
        ]);
        if old_word != new_word {
            ctx.l4_csum_replace(csum_offset, old_word as u64, new_word as u64, 4)
                .map_err(|_| ())?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// TC Ingress — client→origin direction
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
    // Parse Ethernet header — ptr_at enforces the bounds check.
    let ethhdr: *const EthHdr = unsafe { ptr_at(ctx, 0)? };
    if unsafe { (*ethhdr).ether_type() } != Ok(EtherType::Ipv6) {
        return Ok(TC_ACT_OK);
    }

    // Parse IPv6 header.
    let ipv6hdr: *const Ipv6Hdr = unsafe { ptr_at(ctx, EthHdr::LEN)? };

    // Extension headers: if next_hdr is not directly TCP or UDP, we cannot
    // safely walk the header chain to find and update the L4 checksum.
    // Pass the packet through unmodified to avoid silent corruption.
    // (Walking the extension header chain is a v2 item.)
    let nexthdr = unsafe { (*ipv6hdr).next_hdr };
    match nexthdr {
        IpProto::Tcp | IpProto::Udp => {}
        _ => {
            // Extension headers (e.g. Fragment=44, Routing=43, Hop-by-Hop=0): we cannot
            // walk the chain to locate the L4 header, so we pass the packet through
            // unmodified to avoid silent corruption. NAT is not applied to these packets.
            // Walking the extension header chain is a v2 item.
            info!(
                ctx,
                "tc_ingress: extension header passthrough, nexthdr={}", nexthdr as u8
            );
            return Ok(TC_ACT_OK);
        }
    }

    // Bounds-check the L4 header before any packet mutation.  This ensures
    // that the checksum field (TCP offset 16, UDP offset 6) is reachable and
    // prevents forwarding a packet whose addresses were rewritten but whose
    // L4 checksum could not be updated (partial-rewrite correctness bug).
    let l4_base = EthHdr::LEN + Ipv6Hdr::LEN;
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

    // L4 checksum offset (nexthdr is guaranteed TCP or UDP here;
    // l4_base is already defined above from the bounds check).
    let csum_offset = match nexthdr {
        IpProto::Tcp => l4_base + 16,
        _ => l4_base + 6, // UDP
    };

    // Rewrite dst → origin IPv6
    for i in 0..16 {
        ctx.store(IPV6_DST_OFFSET + i, &nat_entry.origin_ipv6[i], 0)
            .map_err(|_| ())?;
    }

    // Rewrite src → server's public IPv6
    for i in 0..16 {
        ctx.store(IPV6_SRC_OFFSET + i, &server_cfg.server_pub_ipv6[i], 0)
            .map_err(|_| ())?;
    }

    // Incremental L4 checksum updates.
    update_addr_csum(ctx, csum_offset, &orig_src, &server_cfg.server_pub_ipv6)?;
    update_addr_csum(ctx, csum_offset, &dst_ipv6, &nat_entry.origin_ipv6)?;

    Ok(TC_ACT_OK)
}

// ---------------------------------------------------------------------------
// TC Egress — origin→client direction
//
// Response packets from origin arriving at the server.
// If src matches a known origin in REVERSE_MAP, rewrite:
//   src → synthetic IPv6 (fd00:abcd:XXXX:YYYY::1)
//   dst → client's IPv6
// ---------------------------------------------------------------------------

#[classifier]
pub fn tc_egress(mut ctx: TcContext) -> i32 {
    match try_tc_egress(&mut ctx) {
        Ok(action) => action,
        Err(_) => TC_ACT_OK,
    }
}

fn try_tc_egress(ctx: &mut TcContext) -> Result<i32, ()> {
    // Parse Ethernet header.
    let ethhdr: *const EthHdr = unsafe { ptr_at(ctx, 0)? };
    if unsafe { (*ethhdr).ether_type() } != Ok(EtherType::Ipv6) {
        return Ok(TC_ACT_OK);
    }

    // Parse IPv6 header.
    let ipv6hdr: *const Ipv6Hdr = unsafe { ptr_at(ctx, EthHdr::LEN)? };

    // Read source IPv6 address.
    let src_ipv6: [u8; 16] = unsafe { (*ipv6hdr).src_addr };

    // Look up in REVERSE_MAP by origin src IP.
    let rev_entry = unsafe { REVERSE_MAP.get(&src_ipv6) };
    let rev_entry = match rev_entry {
        Some(e) => e,
        None => return Ok(TC_ACT_OK), // not a tracked origin, pass through
    };

    // Extension headers: pass through to avoid corruption.
    // (Walking the extension header chain is a v2 item.)
    let nexthdr = unsafe { (*ipv6hdr).next_hdr };
    match nexthdr {
        IpProto::Tcp | IpProto::Udp => {}
        _ => {
            // Extension headers: pass through unmodified — NAT is not applied.
            // Walking the extension header chain is a v2 item.
            info!(
                ctx,
                "tc_egress: extension header passthrough, nexthdr={}", nexthdr as u8
            );
            return Ok(TC_ACT_OK);
        }
    }

    // Bounds-check the L4 header before any packet mutation.  This ensures
    // that the checksum field (TCP offset 16, UDP offset 6) is reachable and
    // prevents forwarding a packet whose addresses were rewritten but whose
    // L4 checksum could not be updated (partial-rewrite correctness bug).
    let l4_base = EthHdr::LEN + Ipv6Hdr::LEN;
    match nexthdr {
        IpProto::Tcp => {
            let _: *const TcpHdr = unsafe { ptr_at(ctx, l4_base)? };
        }
        _ => {
            let _: *const UdpHdr = unsafe { ptr_at(ctx, l4_base)? };
        }
    }

    // Save original dst for checksum fixup (read before any stores).
    let orig_dst: [u8; 16] = unsafe { (*ipv6hdr).dst_addr };

    // Build synthetic IPv6 from domain_id.
    let synthetic = common::synthetic_ipv6(rev_entry.domain_id);

    // L4 checksum offset (nexthdr is guaranteed TCP or UDP here;
    // l4_base is already defined above from the bounds check).
    let csum_offset = match nexthdr {
        IpProto::Tcp => l4_base + 16,
        _ => l4_base + 6, // UDP
    };

    // Rewrite src → synthetic address
    for i in 0..16 {
        ctx.store(IPV6_SRC_OFFSET + i, &synthetic[i], 0)
            .map_err(|_| ())?;
    }

    // Rewrite dst → client IPv6
    for i in 0..16 {
        ctx.store(IPV6_DST_OFFSET + i, &rev_entry.client_ipv6[i], 0)
            .map_err(|_| ())?;
    }

    // Incremental L4 checksum updates.
    update_addr_csum(ctx, csum_offset, &src_ipv6, &synthetic)?;
    update_addr_csum(ctx, csum_offset, &orig_dst, &rev_entry.client_ipv6)?;

    Ok(TC_ACT_OK)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
