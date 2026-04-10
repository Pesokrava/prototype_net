#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{
    bindings::{xdp_action::XDP_DROP, xdp_action::XDP_PASS, TC_ACT_OK, TC_ACT_SHOT},
    helpers::{bpf_csum_diff, bpf_redirect},
    macros::{classifier, map, xdp},
    maps::{Array, HashMap},
    programs::{TcContext, XdpContext},
};
use aya_log_ebpf::info;
use common::{NatEntry, ProxySrcCtx, ProxySrcKey, PROXY_SRC_PREFIX, SYNTHETIC_PREFIX};
#[cfg(feature = "dev-mode")]
use common::{ReplyTrackKey, ReplyTrackValue};
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

/// Index 0 → xfrm0 interface index (for bpf_redirect in tc_ingress_wan)
#[map]
static XFRM_IFINDEX: Array<u32> = Array::with_max_entries(1, 0);

/// Slot 0 = active key, slot 1 = previous key (zero if no rotation in progress).
/// Written by daemon at startup.
#[map]
static OBFS_KEYS: Array<ProxySrcKey> = Array::with_max_entries(2, 0);

/// Dev-mode WAN IPv6 address. When set (non-zero), tc_ingress uses this as the
/// source address instead of proxy-source, enabling double-NAT for dev testing.
/// xdp_wan also uses this to detect and rewrite reply packets.
/// In production this is all zeros — normal proxy-source encoding is used.
#[cfg(feature = "dev-mode")]
#[map]
static DEV_WAN_IPV6: Array<[u8; 16]> = Array::with_max_entries(1, 0);

/// Dev-mode reply tracking: maps (origin, origin_port, translated_port, proto) → proxy_source.
/// When tc_ingress rewrites src to WAN-IPv6 (dev mode), it stores the original
/// proxy-source here. xdp_wan looks up replies by the 4-tuple and rewrites
/// dst from WAN-IPv6 back to proxy-source, then redirects for normal processing.
/// LRU eviction handles connection cleanup automatically.
#[cfg(feature = "dev-mode")]
#[map]
static REPLY_TRACK: HashMap<ReplyTrackKey, ReplyTrackValue> = HashMap::with_max_entries(65536, 0);

/// Dev-mode debug counters for tracing xdp_wan decision paths.
/// Index 0: entered try_xdp_wan (IPv6, non-ICMPv6)
/// Index 1: dst matched PROXY_SRC_PREFIX
/// Index 2: dst matched DEV_WAN_IPV6
/// Index 3: REPLY_TRACK lookup hit
/// Index 4: REPLY_TRACK lookup miss
/// Index 5: XDP_DROP (fell through)
/// Index 6: dst_ipv6 != wan (entered dev block but didn't match)
/// Index 7: DEV_WAN_IPV6 not populated / None
#[cfg(feature = "dev-mode")]
#[map]
static DBG_COUNTERS: Array<u64> = Array::with_max_entries(8, 0);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Increment a debug counter atomically.
#[cfg(feature = "dev-mode")]
#[inline(always)]
fn dbg_inc(idx: u32) {
    if let Some(val) = unsafe { DBG_COUNTERS.get_ptr_mut(idx) } {
        unsafe { *val += 1 };
    }
}

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

/// Return a raw pointer to type `T` at `offset` bytes into an XDP packet,
/// or `Err(())` if that would exceed the packet's data_end boundary.
#[inline(always)]
unsafe fn ptr_at_xdp<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
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

/// Extract L4 ports (in host byte order) from a bounds-checked L4 header.
///
/// For both TCP and UDP the first 4 bytes are [src_port_be16, dst_port_be16].
/// Returns `(src_port_host, dst_port_host)`.
#[inline(always)]
fn extract_l4_ports(ctx: &TcContext, l4_base: usize, proto: IpProto) -> Result<(u16, u16), ()> {
    match proto {
        IpProto::Tcp => {
            let tcp: *const TcpHdr = unsafe { ptr_at(ctx, l4_base)? };
            let src = u16::from_be_bytes(unsafe { (*tcp).source });
            let dst = u16::from_be_bytes(unsafe { (*tcp).dest });
            Ok((src, dst))
        }
        IpProto::Udp => {
            // UDP (caller guarantees proto is TCP or UDP)
            let udp: *const UdpHdr = unsafe { ptr_at(ctx, l4_base)? };
            let src = u16::from_be_bytes(unsafe { (*udp).src });
            let dst = u16::from_be_bytes(unsafe { (*udp).dst });
            Ok((src, dst))
        }
        // This is unreachable because callers check for TCP/UDP.
        _ => unsafe { core::hint::unreachable_unchecked() },
    }
}

// ---------------------------------------------------------------------------
// XDP filter on WAN ingress
//
// Drop only IPv6 packets whose destination is outside the two accepted /32
// prefixes (PROXY_SRC_PREFIX and SYNTHETIC_PREFIX), except ICMPv6 control
// traffic which must always pass.
// Pass everything else (non-IPv6 and parse failures included).
// ---------------------------------------------------------------------------

#[xdp]
pub fn xdp_wan(ctx: XdpContext) -> u32 {
    match try_xdp_wan(&ctx) {
        Ok(action) => action,
        Err(_) => XDP_PASS,
    }
}

fn try_xdp_wan(ctx: &XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = unsafe { ptr_at_xdp(ctx, 0)? };
    if unsafe { (*ethhdr).ether_type() } != Ok(EtherType::Ipv6) {
        return Ok(XDP_PASS);
    }

    let ipv6hdr: *const Ipv6Hdr = unsafe { ptr_at_xdp(ctx, EthHdr::LEN)? };

    // Always pass ICMPv6 (NS/NA/RA/RS/PMTU/etc.) so neighbor discovery and
    // control-plane reachability for the WAN interface are never blocked.
    if unsafe { (*ipv6hdr).next_hdr } == IpProto::Ipv6Icmp {
        return Ok(XDP_PASS);
    }

    let dst_ipv6: [u8; 16] = unsafe { (*ipv6hdr).dst_addr };

    // DBG 0: entered try_xdp_wan with IPv6, non-ICMPv6 packet
    #[cfg(feature = "dev-mode")]
    dbg_inc(0);

    info!(
        ctx,
        "xdp_wan: ipv6 pkt dst[0..4]={:x}:{:x}:{:x}:{:x}",
        dst_ipv6[0],
        dst_ipv6[1],
        dst_ipv6[2],
        dst_ipv6[3]
    );
    // Accept ONLY packets destined for PROXY_SRC_PREFIX (return traffic from origins).
    if dst_ipv6[0] == PROXY_SRC_PREFIX[0]
        && dst_ipv6[1] == PROXY_SRC_PREFIX[1]
        && dst_ipv6[2] == PROXY_SRC_PREFIX[2]
        && dst_ipv6[3] == PROXY_SRC_PREFIX[3]
    {
        // DBG 1: dst matched PROXY_SRC_PREFIX
        #[cfg(feature = "dev-mode")]
        dbg_inc(1);
        return Ok(XDP_PASS);
    }

    // Dev-mode reply handling: check if this is a reply to a tracked connection.
    // In dev-mode, replies arrive with dst=server's WAN IPv6 instead of proxy-source.
    // We rewrite dst back to proxy-source and redirect for normal processing.
    #[cfg(feature = "dev-mode")]
    {
        let dev_wan = DEV_WAN_IPV6.get(0);
        if let Some(wan_addr) = dev_wan {
            let wan = *wan_addr;
            // Check if non-zero (dev mode enabled) and dst matches WAN IPv6
            if wan != [0u8; 16] && dst_ipv6 == wan {
                // DBG 2: dst matched DEV_WAN_IPV6
                dbg_inc(2);
                let nexthdr = unsafe { (*ipv6hdr).next_hdr };
                let proto = match nexthdr {
                    IpProto::Tcp => 6u8,
                    IpProto::Udp => 17u8,
                    _ => return Ok(XDP_PASS), // Not TCP/UDP, pass through
                };

                // Extract ports from L4 header
                let l4_base = EthHdr::LEN + Ipv6Hdr::LEN;
                let (src_port, dst_port) = match extract_l4_ports_xdp(ctx, l4_base, nexthdr) {
                    Ok(ports) => ports,
                    Err(_) => return Ok(XDP_PASS),
                };

                info!(
                    ctx,
                    "xdp_wan: dst==WAN, proto={} src_port={} dst_port={}",
                    proto,
                    src_port,
                    dst_port
                );

                // Look up the tracked connection
                let src_ipv6: [u8; 16] = unsafe { (*ipv6hdr).src_addr };
                let track_key = ReplyTrackKey {
                    origin_ipv6: src_ipv6,
                    origin_port: src_port.to_be(), // origin's port (e.g., 443)
                    translated_port: dst_port.to_be(), // our original source port
                    proto,
                    ..Default::default()
                };

                info!(
                    ctx,
                    "xdp_wan: REPLY_TRACK lookup origin_port_be={} xlat_port_be={}",
                    src_port.to_be(),
                    dst_port.to_be()
                );

                if let Some(track_val) = unsafe { REPLY_TRACK.get(&track_key) } {
                    // DBG 3: REPLY_TRACK hit
                    dbg_inc(3);
                    // Found! This is a reply to a tracked connection.
                    info!(ctx, "xdp_wan: REPLY_TRACK HIT, rewriting dst and passing");

                    // Rewrite dst: WAN-IPv6 → proxy-source using raw pointer manipulation.
                    // We do NOT update the L4 checksum here — XDP can't safely invalidate
                    // the NIC's CHECKSUM_COMPLETE metadata. tc_ingress_wan compensates by
                    // adding the missing WAN→proxy_src checksum delta in its dev-mode block.
                    let ipv6hdr_mut = ipv6hdr as *mut Ipv6Hdr;
                    unsafe {
                        (*ipv6hdr_mut).dst_addr = track_val.proxy_src;
                    }

                    return Ok(XDP_PASS);
                }
                // dst == WAN_IPV6 but not in REPLY_TRACK: this is the server's own traffic
                // (not proxied through tc_ingress). Pass it through to the kernel.
                // DBG 4: REPLY_TRACK miss
                dbg_inc(4);
                info!(ctx, "xdp_wan: REPLY_TRACK MISS, passing through");
                return Ok(XDP_PASS);
            } else {
                // DBG 6: entered dev block but dst != wan (or wan is zero)
                dbg_inc(6);
            }
        } else {
            // DBG 7: DEV_WAN_IPV6 not populated / None
            dbg_inc(7);
        }
    }

    // DBG 5: fell through to XDP_DROP
    #[cfg(feature = "dev-mode")]
    dbg_inc(5);

    Ok(XDP_DROP)
}

/// Extract L4 ports from XDP context.
#[cfg(feature = "dev-mode")]
#[inline(always)]
fn extract_l4_ports_xdp(
    ctx: &XdpContext,
    l4_base: usize,
    proto: IpProto,
) -> Result<(u16, u16), ()> {
    match proto {
        IpProto::Tcp => {
            let tcp: *const TcpHdr = unsafe { ptr_at_xdp(ctx, l4_base)? };
            let src = u16::from_be_bytes(unsafe { (*tcp).source });
            let dst = u16::from_be_bytes(unsafe { (*tcp).dest });
            Ok((src, dst))
        }
        IpProto::Udp => {
            let udp: *const UdpHdr = unsafe { ptr_at_xdp(ctx, l4_base)? };
            let src = u16::from_be_bytes(unsafe { (*udp).src });
            let dst = u16::from_be_bytes(unsafe { (*udp).dst });
            Ok((src, dst))
        }
        _ => Err(()),
    }
}

// ---------------------------------------------------------------------------
// TC Ingress on xfrm0 — client→origin direction
//
// Packets arriving from the IPSec tunnel with dst in fd00:abcd::/32 (synthetic).
// Rewrite dst to the real origin IPv6.
// Rewrite src to encode_proxy_src(client_id, domain_id, ctx, key) — an
// obfuscated address carrying all reply routing information so that
// tc_ingress_wan can decode it statelessly.
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

    // Read destination IPv6 address.
    let dst_ipv6: [u8; 16] = unsafe { (*ipv6hdr).dst_addr };

    info!(
        ctx,
        "tc_ingress: pkt dst[0..4]={:x}:{:x}:{:x}:{:x}",
        dst_ipv6[0],
        dst_ipv6[1],
        dst_ipv6[2],
        dst_ipv6[3]
    );
    // Check prefix: fd00:abcd::/32 — only intercept synthetic destination addresses.
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
        None => return Ok(TC_ACT_SHOT),
    };

    // Read original src — needed for checksum fixup and for encoding client_id.
    let orig_src: [u8; 16] = unsafe { (*ipv6hdr).src_addr };

    // Derive client_id from the last 4 bytes of the client VIP.
    // Pool range fd00:abcd:0:1::1:0–::ffff:ffff — bytes [12..16] hold the unique suffix.
    let client_id = u32::from_be_bytes([orig_src[12], orig_src[13], orig_src[14], orig_src[15]]);

    // Extract L4 ports for the flow context.
    let l4_base = ip_off + Ipv6Hdr::LEN;
    let (src_port, dst_port) = extract_l4_ports(ctx, l4_base, nexthdr)?;

    // Read active obfuscation key from OBFS_KEYS[0].
    let key = OBFS_KEYS.get(0);
    let key = match key {
        Some(k) if !k.is_zero() => k,
        _ => return Ok(TC_ACT_SHOT),
    };

    // Build flow context and encode the obfuscated proxy-source address.
    let proto_num = match nexthdr {
        IpProto::Tcp => 6u8,
        _ => 17u8, // UDP
    };
    let flow_ctx = ProxySrcCtx::new(src_port, dst_port, proto_num);
    let proxy_src = match common::encode_proxy_src(client_id, domain_id, &flow_ctx, key) {
        Some(addr) => addr,
        None => return Ok(TC_ACT_SHOT),
    };

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

    // Determine source address based on dev-mode.
    // Production: use obfuscated proxy-source (encodes client_id + domain_id + flow context)
    // Dev-mode: use server's WAN IPv6 for double-NAT, track for reply handling
    #[cfg(feature = "dev-mode")]
    let final_src: [u8; 16] = {
        let dev_wan = DEV_WAN_IPV6.get(0);
        if let Some(wan_addr) = dev_wan {
            let wan = *wan_addr;
            // Check if non-zero (dev mode enabled)
            if wan != [0u8; 16] {
                // Track this connection for reply handling in xdp_wan
                let track_key = ReplyTrackKey {
                    origin_ipv6: nat_entry.origin_ipv6,
                    origin_port: dst_port.to_be(),     // server's port
                    translated_port: src_port.to_be(), // our source port
                    proto: proto_num,
                    ..Default::default()
                };
                let track_val = ReplyTrackValue {
                    proxy_src: proxy_src,
                };
                let _ = REPLY_TRACK.insert(&track_key, &track_val, 0);
                info!(
                    ctx,
                    "tc_ingress: REPLY_TRACK insert dst_port_be={} src_port_be={}",
                    dst_port.to_be(),
                    src_port.to_be()
                );
                // Use WAN IPv6 as source
                wan
            } else {
                proxy_src
            }
        } else {
            proxy_src
        }
    };

    #[cfg(not(feature = "dev-mode"))]
    let final_src: [u8; 16] = proxy_src;

    // Rewrite src → final source address
    for (i, byte) in final_src.iter().enumerate() {
        ctx.store(ipv6_src_offset + i, byte, 0).map_err(|_| ())?;
    }

    // Incremental L4 checksum updates.
    update_addr_csum(ctx, csum_offset, &orig_src, &final_src)?;
    update_addr_csum(ctx, csum_offset, &dst_ipv6, &nat_entry.origin_ipv6)?;

    Ok(TC_ACT_OK)
}

// ---------------------------------------------------------------------------
// TC Ingress on WAN interface (e.g. enp0s3) — origin→client direction
//
// Reply packets arriving from origin servers on the WAN interface.
// Decode client_id and domain_id from the destination proxy-source address
// (obfuscated via PRINCE + SipHash), reconstruct client VIP, verify src
// against NAT_MAP, then rewrite:
//   src → synthetic IPv6 (fd00:abcd:XXXX:YYYY::1)
//   dst → client VIP (fd00:abcd:0:1::<client_id>)
// Then redirect to xfrm0 (which will encrypt via IPSec and deliver to client).
//
// On any decode failure (TAG32 mismatch, padding error, or missing/invalid active key)
// → TC_ACT_SHOT. This is a forged or corrupted packet targeting our prefix.
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

    // Read destination IPv6 address — this is the proxy-source address written
    // by tc_ingress, encoding client_id + domain_id obfuscated with PRINCE + SipHash.
    let dst_ipv6: [u8; 16] = unsafe { (*ipv6hdr).dst_addr };

    // Check prefix: PROXY_SRC_PREFIX — only intercept return traffic destined
    // for our proxy-source address range. Non-matching traffic passes through.
    if dst_ipv6[0] != PROXY_SRC_PREFIX[0]
        || dst_ipv6[1] != PROXY_SRC_PREFIX[1]
        || dst_ipv6[2] != PROXY_SRC_PREFIX[2]
        || dst_ipv6[3] != PROXY_SRC_PREFIX[3]
    {
        return Ok(TC_ACT_OK);
    }

    // Extract L4 ports for the flow context.
    // In the return direction the port roles are swapped relative to tc_ingress:
    // what was dst_port (e.g. 443) on the outbound side is now src_port on the reply,
    // and what was src_port (ephemeral) is now dst_port.
    // The decode ctx must use the ORIGINAL tc_ingress perspective (client src_port, server dst_port),
    // so we swap: ctx.src_port = reply.dst_port, ctx.dst_port = reply.src_port.
    let l4_base = ip_off + Ipv6Hdr::LEN;
    let (reply_src_port, reply_dst_port) = extract_l4_ports(ctx, l4_base, nexthdr)?;

    let proto_num = match nexthdr {
        IpProto::Tcp => 6u8,
        _ => 17u8,
    };
    // Swap ports to reconstruct the original tc_ingress perspective.
    let flow_ctx = ProxySrcCtx::new(reply_dst_port, reply_src_port, proto_num);

    // Decode with active key (slot 0).
    let decoded = try_decode_with_active_key(&dst_ipv6, &flow_ctx);
    let (client_id, domain_id) = match decoded {
        Some(ids) => ids,
        None => {
            // Active key failed (or no key populated). Drop as forged/corrupted.
            return Ok(TC_ACT_SHOT);
        }
    };

    // Reconstruct client VIP: fd00:abcd:0:1::<client_id>
    let client_ipv6 = common::client_vip_from_id24(client_id);

    // Read source IPv6 address and verify it matches the known origin in NAT_MAP.
    // This guards against accidentally intercepting unrelated traffic.
    let src_ipv6: [u8; 16] = unsafe { (*ipv6hdr).src_addr };
    let nat_entry = unsafe { NAT_MAP.get(&domain_id) };
    let nat_entry = match nat_entry {
        Some(e) => e,
        None => return Ok(TC_ACT_SHOT), // unknown domain → drop
    };
    if src_ipv6 != nat_entry.origin_ipv6 {
        return Ok(TC_ACT_SHOT); // src does not match expected origin → drop
    }

    // Build synthetic IPv6 from domain_id for the src rewrite.
    let synthetic = common::synthetic_ipv6(domain_id);

    // Byte offsets for src/dst address fields within the packet.
    let ipv6_src_offset = ip_off + 8;
    let ipv6_dst_offset = ip_off + 24;

    // L4 checksum offset.
    let csum_offset = match nexthdr {
        IpProto::Tcp => l4_base + 16,
        _ => l4_base + 6, // UDP
    };

    // Rewrite src → synthetic address
    for (i, byte) in synthetic.iter().enumerate() {
        ctx.store(ipv6_src_offset + i, byte, 0).map_err(|_| ())?;
    }

    // Rewrite dst → client VIP
    for (i, byte) in client_ipv6.iter().enumerate() {
        ctx.store(ipv6_dst_offset + i, byte, 0).map_err(|_| ())?;
    }

    // Incremental L4 checksum updates (bpf_csum_diff-based, endian-safe).
    update_addr_csum(ctx, csum_offset, &src_ipv6, &synthetic)?;
    update_addr_csum(ctx, csum_offset, &dst_ipv6, &client_ipv6)?;

    // Dev-mode: xdp_wan rewrites dst from WAN_IPv6 → proxy_src without updating the
    // checksum (XDP can't properly handle CHECKSUM_COMPLETE). The stored checksum is
    // still based on WAN_IPv6. The update_addr_csum above only accounts for proxy_src →
    // client_vip, but the actual change is WAN → client_vip. Add the missing WAN →
    // proxy_src delta so the incremental chain is correct:
    //   checksum_in_packet (for WAN) + delta(WAN→proxy_src) + delta(proxy_src→client) = checksum(for client)
    #[cfg(feature = "dev-mode")]
    {
        if let Some(wan_addr) = DEV_WAN_IPV6.get(0) {
            let wan = *wan_addr;
            if wan != [0u8; 16] {
                update_addr_csum(ctx, csum_offset, &wan, &dst_ipv6)?;
            }
        }
    }

    // Mark the checksum as CHECKSUM_PARTIAL so the kernel recomputes it on
    // xfrm0 egress.  WAN-ingress packets often arrive with ip_summed =
    // CHECKSUM_COMPLETE (NIC hardware checksum); calling l4_csum_replace with
    // BPF_F_PSEUDO_HDR | BPF_F_MARK_MANGLED_0 and from=0/to=0 is a no-op for
    // the stored value but transitions ip_summed to CHECKSUM_PARTIAL, which
    // causes the kernel transmit path to recompute the checksum from scratch.
    ctx.l4_csum_replace(csum_offset, 0, 0, BPF_F_PSEUDO_HDR | BPF_F_MARK_MANGLED_0)
        .map_err(|_| ())?;

    // Look up xfrm0 ifindex for redirect.
    let xfrm_ifindex = XFRM_IFINDEX.get(0);
    let xfrm_ifindex = match xfrm_ifindex {
        Some(idx) if *idx != 0 => *idx,
        _ => return Ok(TC_ACT_SHOT),
    };

    // Redirect to xfrm0 egress so it goes through the IPSec tunnel to the client.
    // bpf_redirect returns TC_ACT_REDIRECT (7) on success.
    Ok(unsafe { bpf_redirect(xfrm_ifindex, 0) } as i32)
}

/// Try decoding the proxy-source address with the active key (slot 0).
///
/// Returns `Some((client_id, domain_id))` on success, `None` on failure.
#[inline(never)]
fn try_decode_with_active_key(addr: &[u8; 16], flow_ctx: &ProxySrcCtx) -> Option<(u32, u32)> {
    if let Some(key0) = OBFS_KEYS.get(0) {
        if !key0.is_zero() {
            if let Some(ids) = common::decode_proxy_src(addr, flow_ctx, key0) {
                return Some(ids);
            }
        }
    }

    None
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
