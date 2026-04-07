#![no_std]

/// Prefix bytes for synthetic IPv6 addresses: fd00:abcd::/32
pub const SYNTHETIC_PREFIX: [u8; 4] = [0xfd, 0x00, 0xab, 0xcd];

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
        0xfd,
        0x00,
        0xab,
        0xcd,
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
///   byte  4    : `0xff`         (proxy-source marker)
///   byte  5    : `0x00`         (reserved)
///   bytes 6–7  : client_id (u16 BE)
///   bytes 8–11 : domain_id (u32 BE)
///   bytes 12–15: `0x00 00 00 00`
///
/// Example: client_id=0x0101, domain_id=7 → fd00:abcd:ff00:101:0:7::
pub fn proxy_src_ipv6(client_id: u16, domain_id: u32) -> [u8; 16] {
    let cid = client_id.to_be_bytes();
    let did = domain_id.to_be_bytes();
    [
        0xfd, 0x00, 0xab, 0xcd, // bytes 0–3: prefix
        0xff, 0x00, // bytes 4–5: marker + reserved
        cid[0], cid[1], // bytes 6–7: client_id
        did[0], did[1], did[2], did[3], // bytes 8–11: domain_id
        0x00, 0x00, 0x00, 0x00, // bytes 12–15: zero
    ]
}

/// Return true if `addr` is a proxy-source address (byte 4 == 0xff).
#[inline(always)]
pub fn is_proxy_src(addr: &[u8; 16]) -> bool {
    addr[4] == 0xff
}

/// Decode `client_id` and `domain_id` from a proxy-source address.
///
/// Caller must verify `is_proxy_src()` first.
#[inline(always)]
pub fn decode_proxy_src(addr: &[u8; 16]) -> (u16, u32) {
    let client_id = u16::from_be_bytes([addr[6], addr[7]]);
    let domain_id = u32::from_be_bytes([addr[8], addr[9], addr[10], addr[11]]);
    (client_id, domain_id)
}

/// Reconstruct the client VIP (`fd00:abcd:0:1::<client_id>`) from a `client_id`.
///
/// Mirrors the strongSwan pool range `::0100–::ffff`.
pub fn client_vip_from_id(client_id: u16) -> [u8; 16] {
    let cid = client_id.to_be_bytes();
    [
        0xfd, 0x00, 0xab, 0xcd, // bytes 0–3: prefix
        0x00, 0x00, // bytes 4–5: zero
        0x00, 0x01, // bytes 6–7: :0:1 segment
        0x00, 0x00, 0x00, 0x00, // bytes 8–11: zero
        0x00, 0x00, // bytes 12–13: zero
        cid[0], cid[1], // bytes 14–15: client_id
    ]
}

// ---------------------------------------------------------------------------
// Userspace-only: aya::Pod implementations
// ---------------------------------------------------------------------------

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for NatEntry {}
