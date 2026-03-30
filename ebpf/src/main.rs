#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_OK,
    bindings::TC_ACT_SHOT,
    macros::{classifier, map},
    maps::{Array, HashMap},
    programs::TcContext,
};
use aya_log_ebpf::info;
use common::{NatEntry, ReverseEntry, ServerConfig, SYNTHETIC_PREFIX};

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
// Constants
// ---------------------------------------------------------------------------

const ETH_HDR_LEN: usize = 14;
const IPV6_HDR_LEN: usize = 40;
const ETH_P_IPV6: u16 = 0x86DD;

// IPv6 next-header protocol numbers
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

// Offsets within the IPv6 header (after Ethernet header)
const IPV6_SRC_OFFSET: usize = ETH_HDR_LEN + 8; // src addr starts at byte 8 of IPv6 hdr
const IPV6_DST_OFFSET: usize = ETH_HDR_LEN + 24; // dst addr starts at byte 24 of IPv6 hdr
const IPV6_NEXTHDR_OFFSET: usize = ETH_HDR_LEN + 6; // next header field

// ---------------------------------------------------------------------------
// TC Ingress — client→origin direction
//
// Packets arriving from the IPSec tunnel with dst in fd00:abcd::/32.
// Rewrite dst to the real origin IPv6, rewrite src to server's public IPv6.
// ---------------------------------------------------------------------------

#[classifier]
pub fn tc_ingress(ctx: TcContext) -> i32 {
    match try_tc_ingress(&ctx) {
        Ok(action) => action,
        Err(_) => TC_ACT_OK, // pass through on error
    }
}

fn try_tc_ingress(ctx: &TcContext) -> Result<i32, ()> {
    // Bounds-check: need at least Ethernet + IPv6 header
    let data_end = ctx.data_end();
    let data = ctx.data();
    if data + ETH_HDR_LEN + IPV6_HDR_LEN > data_end {
        return Ok(TC_ACT_OK);
    }

    // Check EtherType == IPv6
    let ethertype: u16 = ctx.load::<u16>(12).map_err(|_| ())?;
    if ethertype != ETH_P_IPV6.to_be() && ethertype != ETH_P_IPV6 {
        return Ok(TC_ACT_OK);
    }
    // Read the raw u16 and compare in network byte order
    let ethertype_be = u16::from_be(ethertype);
    if ethertype_be != ETH_P_IPV6 {
        return Ok(TC_ACT_OK);
    }

    // Read destination IPv6 address (16 bytes at offset 24 in IPv6 header)
    let mut dst_ipv6 = [0u8; 16];
    for i in 0..16 {
        dst_ipv6[i] = ctx.load::<u8>(IPV6_DST_OFFSET + i).map_err(|_| ())?;
    }

    // Check prefix: fd00:abcd::/32
    if dst_ipv6[0] != SYNTHETIC_PREFIX[0]
        || dst_ipv6[1] != SYNTHETIC_PREFIX[1]
        || dst_ipv6[2] != SYNTHETIC_PREFIX[2]
        || dst_ipv6[3] != SYNTHETIC_PREFIX[3]
    {
        return Ok(TC_ACT_OK);
    }

    // Extract domain_id from bytes [4..8]
    let domain_id = u32::from_be_bytes([dst_ipv6[4], dst_ipv6[5], dst_ipv6[6], dst_ipv6[7]]);

    // Look up the real origin IPv6 from NAT_MAP
    let nat_entry = unsafe { NAT_MAP.get(&domain_id) };
    let nat_entry = match nat_entry {
        Some(e) => e,
        None => {
            info!(ctx, "tc_ingress: NAT_MAP miss for domain_id={}", domain_id);
            return Ok(TC_ACT_SHOT);
        }
    };

    // Load server config for src rewrite
    let server_cfg = unsafe { SERVER_CONFIG.get(0) };
    let server_cfg = match server_cfg {
        Some(c) => c,
        None => return Ok(TC_ACT_SHOT),
    };

    // Read the next-header field for checksum update
    let nexthdr: u8 = ctx.load::<u8>(IPV6_NEXTHDR_OFFSET).map_err(|_| ())?;

    // Save original src/dst for checksum fixup
    let mut orig_src = [0u8; 16];
    for i in 0..16 {
        orig_src[i] = ctx.load::<u8>(IPV6_SRC_OFFSET + i).map_err(|_| ())?;
    }
    let orig_dst = dst_ipv6;

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

    // Incremental L4 checksum update for TCP/UDP
    if nexthdr == IPPROTO_TCP || nexthdr == IPPROTO_UDP {
        update_l4_csum_ipv6(
            ctx,
            nexthdr,
            &orig_src,
            &server_cfg.server_pub_ipv6,
            &orig_dst,
            &nat_entry.origin_ipv6,
        )?;
    }

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
pub fn tc_egress(ctx: TcContext) -> i32 {
    match try_tc_egress(&ctx) {
        Ok(action) => action,
        Err(_) => TC_ACT_OK,
    }
}

fn try_tc_egress(ctx: &TcContext) -> Result<i32, ()> {
    let data_end = ctx.data_end();
    let data = ctx.data();
    if data + ETH_HDR_LEN + IPV6_HDR_LEN > data_end {
        return Ok(TC_ACT_OK);
    }

    // Check EtherType == IPv6
    let ethertype: u16 = ctx.load::<u16>(12).map_err(|_| ())?;
    let ethertype_be = u16::from_be(ethertype);
    if ethertype_be != ETH_P_IPV6 {
        return Ok(TC_ACT_OK);
    }

    // Read source IPv6 address
    let mut src_ipv6 = [0u8; 16];
    for i in 0..16 {
        src_ipv6[i] = ctx.load::<u8>(IPV6_SRC_OFFSET + i).map_err(|_| ())?;
    }

    // Look up in REVERSE_MAP by origin src IP
    let rev_entry = unsafe { REVERSE_MAP.get(&src_ipv6) };
    let rev_entry = match rev_entry {
        Some(e) => e,
        None => return Ok(TC_ACT_OK), // not a tracked origin, pass through
    };

    // Read nexthdr for checksum update
    let nexthdr: u8 = ctx.load::<u8>(IPV6_NEXTHDR_OFFSET).map_err(|_| ())?;

    // Save original dst
    let mut orig_dst = [0u8; 16];
    for i in 0..16 {
        orig_dst[i] = ctx.load::<u8>(IPV6_DST_OFFSET + i).map_err(|_| ())?;
    }
    let orig_src = src_ipv6;

    // Build synthetic IPv6 from domain_id
    let synthetic = common::synthetic_ipv6(rev_entry.domain_id);

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

    // Incremental L4 checksum update
    if nexthdr == IPPROTO_TCP || nexthdr == IPPROTO_UDP {
        update_l4_csum_ipv6(
            ctx,
            nexthdr,
            &orig_src,
            &synthetic,
            &orig_dst,
            &rev_entry.client_ipv6,
        )?;
    }

    Ok(TC_ACT_OK)
}

// ---------------------------------------------------------------------------
// L4 checksum incremental update
//
// IPv6 pseudo-header includes src + dst addresses (each 16 bytes = 8 u16 words).
// We update the checksum by subtracting old and adding new address words.
// ---------------------------------------------------------------------------

fn update_l4_csum_ipv6(
    ctx: &TcContext,
    nexthdr: u8,
    old_src: &[u8; 16],
    new_src: &[u8; 16],
    old_dst: &[u8; 16],
    new_dst: &[u8; 16],
) -> Result<(), ()> {
    // L4 checksum offset depends on protocol
    let l4_offset = ETH_HDR_LEN + IPV6_HDR_LEN;
    let csum_offset = if nexthdr == IPPROTO_TCP {
        l4_offset + 16 // TCP checksum at offset 16
    } else {
        l4_offset + 6 // UDP checksum at offset 6
    };

    // Use l4_csum_replace for each 4-byte word of the address change
    // Process src address (4 x u32 words)
    for i in 0..4 {
        let off = i * 4;
        let old_word = u32::from_be_bytes([
            old_src[off],
            old_src[off + 1],
            old_src[off + 2],
            old_src[off + 3],
        ]);
        let new_word = u32::from_be_bytes([
            new_src[off],
            new_src[off + 1],
            new_src[off + 2],
            new_src[off + 3],
        ]);
        if old_word != new_word {
            ctx.l4_csum_replace(csum_offset, old_word as u64, new_word as u64, 4)
                .map_err(|_| ())?;
        }
    }

    // Process dst address
    for i in 0..4 {
        let off = i * 4;
        let old_word = u32::from_be_bytes([
            old_dst[off],
            old_dst[off + 1],
            old_dst[off + 2],
            old_dst[off + 3],
        ]);
        let new_word = u32::from_be_bytes([
            new_dst[off],
            new_dst[off + 1],
            new_dst[off + 2],
            new_dst[off + 3],
        ]);
        if old_word != new_word {
            ctx.l4_csum_replace(csum_offset, old_word as u64, new_word as u64, 4)
                .map_err(|_| ())?;
        }
    }

    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
