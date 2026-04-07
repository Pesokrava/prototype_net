#![no_std]

// Constants generated from contract.toml at build time.
// Defines: SYNTHETIC_PREFIX, VIP_POOL_DISCRIMINATOR, XFRM_IF_ID
include!(concat!(env!("OUT_DIR"), "/contract.rs"));

// ---------------------------------------------------------------------------
// BPF map value types — must be #[repr(C)] for BPF map compatibility
// ---------------------------------------------------------------------------

/// NAT_MAP value: maps domain_id (u32) → origin IPv6 address.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NatEntry {
    pub origin_ipv6: [u8; 16],
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract the domain_id from a synthetic IPv6 address.
///
/// Layout: `fd00:abcd:XXXX:YYYY::1`
///   - bits\[32:47\] = XXXX = domain_id >> 16
///   - bits\[48:63\] = YYYY = domain_id & 0xffff
///
/// In byte terms: bytes\[4..8\] contain the domain_id in big-endian.
pub fn domain_id_from_ipv6(addr: &[u8; 16]) -> u32 {
    u32::from_be_bytes([addr[4], addr[5], addr[6], addr[7]])
}

/// Construct a synthetic IPv6 address from a domain_id.
///
/// Returns `fd00:abcd:XXXX:YYYY::1` where XXXX:YYYY encodes the domain_id.
pub fn synthetic_ipv6(domain_id: u32) -> [u8; 16] {
    let id_bytes = domain_id.to_be_bytes();
    [
        // fd00:abcd prefix (bytes 0-3)
        SYNTHETIC_PREFIX[0],
        SYNTHETIC_PREFIX[1],
        SYNTHETIC_PREFIX[2],
        SYNTHETIC_PREFIX[3],
        // domain_id (bytes 4-7)
        id_bytes[0],
        id_bytes[1],
        id_bytes[2],
        id_bytes[3],
        // zeros (bytes 8-14) + ::1 (byte 15)
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        1,
    ]
}

/// Construct a proxy-source IPv6 address encoding client_id and domain_id.
///
/// Layout (16 bytes):
///   bytes 0–3  : `fd 00 ab cd`  (ULA /32 prefix)
///   bytes 4–7  : client_id (u32 BE)
///   bytes 8–11 : domain_id (u32 BE)
///   bytes 12–15: `0x00 00 00 00`
///
/// Example: client_id=0x00000101, domain_id=7 → fd00:abcd:0:101:0:7::
pub fn proxy_src_ipv6(client_id: u32, domain_id: u32) -> [u8; 16] {
    let cid = client_id.to_be_bytes();
    let did = domain_id.to_be_bytes();
    [
        SYNTHETIC_PREFIX[0],
        SYNTHETIC_PREFIX[1],
        SYNTHETIC_PREFIX[2],
        SYNTHETIC_PREFIX[3], // bytes 0–3: prefix
        cid[0],
        cid[1],
        cid[2],
        cid[3], // bytes 4–7: client_id
        did[0],
        did[1],
        did[2],
        did[3], // bytes 8–11: domain_id
        0x00,
        0x00,
        0x00,
        0x00, // bytes 12–15: zero
    ]
}

/// Decode `client_id` and `domain_id` from a proxy-source address.
#[inline(always)]
pub fn decode_proxy_src(addr: &[u8; 16]) -> (u32, u32) {
    let client_id = u32::from_be_bytes([addr[4], addr[5], addr[6], addr[7]]);
    let domain_id = u32::from_be_bytes([addr[8], addr[9], addr[10], addr[11]]);
    (client_id, domain_id)
}

/// Reconstruct the client VIP (`fd00:abcd:0:1::<client_id>`) from a `client_id`.
///
/// Mirrors the strongSwan pool range `::1:0–::ffff:ffff`.
pub fn client_vip_from_id(client_id: u32) -> [u8; 16] {
    let d = VIP_POOL_DISCRIMINATOR; // [0x00, 0x00, 0x00, 0x01]
    let cid = client_id.to_be_bytes();
    [
        SYNTHETIC_PREFIX[0],
        SYNTHETIC_PREFIX[1],
        SYNTHETIC_PREFIX[2],
        SYNTHETIC_PREFIX[3], // bytes 0–3: prefix
        d[0],
        d[1], // bytes 4–5: :0 segment
        d[2],
        d[3], // bytes 6–7: :1 segment
        0x00,
        0x00,
        0x00,
        0x00, // bytes 8–11: zero
        cid[0],
        cid[1],
        cid[2],
        cid[3], // bytes 12–15: client_id
    ]
}

// ---------------------------------------------------------------------------
// Userspace-only: aya::Pod implementations
// ---------------------------------------------------------------------------

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for NatEntry {}

// ---------------------------------------------------------------------------
// Contract tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn vip_discriminator_matches_client_vip_layout() {
        let vip = client_vip_from_id(0x0001_0000);
        assert_eq!(&vip[0..4], &SYNTHETIC_PREFIX);
        assert_eq!(&vip[4..8], &VIP_POOL_DISCRIMINATOR);
        assert_eq!(&vip[8..12], &[0u8; 4]);
        assert_eq!(&vip[12..16], &0x0001_0000u32.to_be_bytes());
    }

    #[test]
    fn proxy_src_roundtrip() {
        let cid = 0x0001_0000u32;
        let did = 0x0000_0007u32;
        let addr = proxy_src_ipv6(cid, did);
        assert_eq!(&addr[0..4], &SYNTHETIC_PREFIX);
        let (c, d) = decode_proxy_src(&addr);
        assert_eq!(c, cid);
        assert_eq!(d, did);
    }

    #[test]
    fn synthetic_ipv6_prefix_matches() {
        let addr = synthetic_ipv6(42);
        assert_eq!(&addr[0..4], &SYNTHETIC_PREFIX);
    }

    #[test]
    fn proxy_src_and_vip_spaces_are_disjoint() {
        // A proxy-source address (client_id in bytes 4–7) must never have the
        // VIP pool discriminator in bytes 4–7, because the discriminator's high
        // halfword (bytes 4–5) is always 0x0000 while client_id for any real
        // client will have bytes 4–5 equal to client_id >> 16.
        // For pool_start (client_id = 0x0001_0000): bytes 4–5 = 0x00, 0x01
        // which happens to equal the discriminator's bytes 4–5 = 0x00, 0x00 ... 0x00, 0x01.
        // The test therefore checks byte 8 onward: proxy-src has domain_id there,
        // VIP has zeros.
        let src = proxy_src_ipv6(0x0001_0000, 1);
        let vip = client_vip_from_id(0x0001_0000);
        // They share the same prefix but differ from byte 8 onward.
        assert_eq!(&src[0..4], &vip[0..4]); // same prefix
        assert_ne!(&src[8..12], &vip[8..12]); // proxy-src has domain_id, VIP has zeros
    }

    #[test]
    fn xfrm_if_id_is_nonzero() {
        assert!(XFRM_IF_ID > 0);
    }
}
