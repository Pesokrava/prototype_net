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

/// REVERSE_MAP value: maps origin IPv6 → (domain_id, client IPv6).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ReverseEntry {
    pub domain_id: u32,
    pub _pad: u32,
    pub client_ipv6: [u8; 16],
}

/// SERVER_CONFIG array value: server's own public IPv6 + synthetic prefix.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ServerConfig {
    pub server_pub_ipv6: [u8; 16],
    pub prefix: [u8; 16],
}

/// NAT_FLOWS value: tracks an active NAT'd TCP/UDP flow by server-side src port.
///
/// Keyed by `u16` src port (the port the server uses when forwarding to origin).
/// Looked up by `tc_ingress_wan` using the reply packet's dst port.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FlowEntry {
    pub domain_id: u32,
    pub _pad: u32,
    pub client_ipv6: [u8; 16],
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

// ---------------------------------------------------------------------------
// Userspace-only: aya::Pod implementations
// ---------------------------------------------------------------------------

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for NatEntry {}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for ReverseEntry {}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for ServerConfig {}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for FlowEntry {}
