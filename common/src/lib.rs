#![no_std]

// Constants generated from contract.toml at build time.
// Defines: SYNTHETIC_PREFIX, VIP_POOL_DISCRIMINATOR, XFRM_IF_ID,
//          PROXY_SRC_PREFIX, PROXY_SRC_CLIENT_ID_MAX, PROXY_SRC_DOMAIN_ID_MAX
include!(concat!(env!("OUT_DIR"), "/contract.rs"));

pub mod crypto;

// ---------------------------------------------------------------------------
// Proxy-source context and key types
// ---------------------------------------------------------------------------

/// 5-tuple context used as tweak in encode/decode.
///
/// Port values are host-byte-order u16, converted from big-endian wire format
/// at parse time (eBPF: `u16::from_be(raw)`; userspace: decimal integer input).
/// Both eBPF and userspace paths MUST use identical canonicalization to avoid
/// silent decode failures.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProxySrcCtx {
    pub src_port: u16, // host-order, converted from BE wire format
    pub dst_port: u16, // host-order, converted from BE wire format
    pub proto: u8,     // IP protocol number (6=TCP, 17=UDP)
    _pad: [u8; 3],     // always zero, not included in hash_ctx packing
}

impl ProxySrcCtx {
    #[inline(always)]
    pub fn new(src_port: u16, dst_port: u16, proto: u8) -> Self {
        Self {
            src_port,
            dst_port,
            proto,
            _pad: [0; 3],
        }
    }
}

/// 256-bit key material for proxy-source obfuscation.
///
/// Bytes 0-15: PRINCE key (128-bit).
/// Bytes 16-31: SipHash-2-4 key (128-bit).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProxySrcKey {
    pub prince_key: [u8; 16],
    pub siphash_key: [u8; 16],
}

impl ProxySrcKey {
    /// Returns true if the key is all zeros (not populated / invalid).
    pub fn is_zero(&self) -> bool {
        let mut acc: u8 = 0;
        let mut i = 0;
        while i < 16 {
            acc |= self.prince_key[i];
            acc |= self.siphash_key[i];
            i += 1;
        }
        acc == 0
    }
}

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
// Helpers — synthetic addresses
// ---------------------------------------------------------------------------

/// Extract the domain_id from a synthetic IPv6 address.
///
/// Layout: `fd00:abcd:XXXX:YYYY::1`
///   - bytes\[4..8\] contain the domain_id in big-endian.
pub fn domain_id_from_ipv6(addr: &[u8; 16]) -> u32 {
    u32::from_be_bytes([addr[4], addr[5], addr[6], addr[7]])
}

/// Construct a synthetic IPv6 address from a domain_id.
///
/// Returns `fd00:abcd:XXXX:YYYY::1` where XXXX:YYYY encodes the domain_id.
pub fn synthetic_ipv6(domain_id: u32) -> [u8; 16] {
    let id_bytes = domain_id.to_be_bytes();
    [
        SYNTHETIC_PREFIX[0],
        SYNTHETIC_PREFIX[1],
        SYNTHETIC_PREFIX[2],
        SYNTHETIC_PREFIX[3],
        id_bytes[0],
        id_bytes[1],
        id_bytes[2],
        id_bytes[3],
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
// Proxy-source encoding — obfuscated (PRINCE + SipHash)
//
// Wire format (16 bytes):
//   bytes 0–3  : PROXY_SRC_PREFIX  (owned public /32)
//   bytes 4–11 : ENC64 = PRINCE_k(P64)  where P64 = (client24 ‖ domain24 ‖ PAD16) XOR H(ctx)
//   bytes 12–15: TAG32 = truncate32(SipHash-2-4_k2(prefix ‖ ENC64 ‖ ctx))
// ---------------------------------------------------------------------------

/// Encode client_id (24-bit) + domain_id (24-bit) into an obfuscated proxy-source IPv6 address.
///
/// Returns `None` if client_id or domain_id exceed 24-bit range.
#[inline(always)]
pub fn encode_proxy_src(
    client_id: u32,
    domain_id: u32,
    ctx: &ProxySrcCtx,
    key: &ProxySrcKey,
) -> Option<[u8; 16]> {
    if client_id > PROXY_SRC_CLIENT_ID_MAX || domain_id > PROXY_SRC_DOMAIN_ID_MAX {
        return None;
    }

    // Build 64-bit plaintext: client24 (bits 63-40) | domain24 (bits 39-16) | PAD16=0 (bits 15-0)
    let p64: u64 = ((client_id as u64) << 40) | ((domain_id as u64) << 16);

    // Mix in flow context (tweakable encryption).
    let h = crypto::hash_ctx(ctx);
    let p64_tweaked = p64 ^ h;

    // Encrypt with PRINCE.
    let enc64 = crypto::prince_encrypt(p64_tweaked, &key.prince_key);
    let enc64_bytes = enc64.to_be_bytes();

    // Build MAC input: prefix(4) || ENC64(8) || src_port(2) || dst_port(2) || proto(1) = 17 bytes
    let mut mac_input = [0u8; 17];
    mac_input[0] = PROXY_SRC_PREFIX[0];
    mac_input[1] = PROXY_SRC_PREFIX[1];
    mac_input[2] = PROXY_SRC_PREFIX[2];
    mac_input[3] = PROXY_SRC_PREFIX[3];
    mac_input[4] = enc64_bytes[0];
    mac_input[5] = enc64_bytes[1];
    mac_input[6] = enc64_bytes[2];
    mac_input[7] = enc64_bytes[3];
    mac_input[8] = enc64_bytes[4];
    mac_input[9] = enc64_bytes[5];
    mac_input[10] = enc64_bytes[6];
    mac_input[11] = enc64_bytes[7];
    let sp = ctx.src_port.to_be_bytes();
    let dp = ctx.dst_port.to_be_bytes();
    mac_input[12] = sp[0];
    mac_input[13] = sp[1];
    mac_input[14] = dp[0];
    mac_input[15] = dp[1];
    mac_input[16] = ctx.proto;

    // Compute TAG32 (lower 32 bits of SipHash-2-4).
    let tag64 = crypto::siphash_2_4(&key.siphash_key, &mac_input);
    let tag32 = (tag64 as u32).to_be_bytes();

    // Assemble the 16-byte proxy-source address.
    Some([
        PROXY_SRC_PREFIX[0],
        PROXY_SRC_PREFIX[1],
        PROXY_SRC_PREFIX[2],
        PROXY_SRC_PREFIX[3],
        enc64_bytes[0],
        enc64_bytes[1],
        enc64_bytes[2],
        enc64_bytes[3],
        enc64_bytes[4],
        enc64_bytes[5],
        enc64_bytes[6],
        enc64_bytes[7],
        tag32[0],
        tag32[1],
        tag32[2],
        tag32[3],
    ])
}

/// Decode a proxy-source IPv6 address.
///
/// Validates TAG32, decrypts ENC64 via PRINCE, unmixes flow context, and
/// validates 16-bit zero padding. Returns `None` on any validation failure.
#[inline(always)]
pub fn decode_proxy_src(
    addr: &[u8; 16],
    ctx: &ProxySrcCtx,
    key: &ProxySrcKey,
) -> Option<(u32, u32)> {
    // Extract ENC64 (bytes 4-11) and TAG32 (bytes 12-15).
    let enc64 = u64::from_be_bytes([
        addr[4], addr[5], addr[6], addr[7], addr[8], addr[9], addr[10], addr[11],
    ]);
    let enc64_bytes = enc64.to_be_bytes();
    let packet_tag = u32::from_be_bytes([addr[12], addr[13], addr[14], addr[15]]);

    // Rebuild MAC input and verify TAG32.
    let mut mac_input = [0u8; 17];
    mac_input[0] = PROXY_SRC_PREFIX[0];
    mac_input[1] = PROXY_SRC_PREFIX[1];
    mac_input[2] = PROXY_SRC_PREFIX[2];
    mac_input[3] = PROXY_SRC_PREFIX[3];
    mac_input[4] = enc64_bytes[0];
    mac_input[5] = enc64_bytes[1];
    mac_input[6] = enc64_bytes[2];
    mac_input[7] = enc64_bytes[3];
    mac_input[8] = enc64_bytes[4];
    mac_input[9] = enc64_bytes[5];
    mac_input[10] = enc64_bytes[6];
    mac_input[11] = enc64_bytes[7];
    let sp = ctx.src_port.to_be_bytes();
    let dp = ctx.dst_port.to_be_bytes();
    mac_input[12] = sp[0];
    mac_input[13] = sp[1];
    mac_input[14] = dp[0];
    mac_input[15] = dp[1];
    mac_input[16] = ctx.proto;

    let expected_tag = crypto::siphash_2_4(&key.siphash_key, &mac_input) as u32;
    if packet_tag != expected_tag {
        return None;
    }

    // Decrypt ENC64.
    let p64_tweaked = crypto::prince_decrypt(enc64, &key.prince_key);

    // Unmix flow context.
    let h = crypto::hash_ctx(ctx);
    let p64 = p64_tweaked ^ h;

    // Validate PAD16 (lower 16 bits must be zero).
    if (p64 & 0xFFFF) != 0 {
        return None;
    }

    // Extract client_id (bits 63-40) and domain_id (bits 39-16).
    let client_id = ((p64 >> 40) & 0x00FF_FFFF) as u32;
    let domain_id = ((p64 >> 16) & 0x00FF_FFFF) as u32;

    Some((client_id, domain_id))
}

/// Reconstruct the client VIP (`fd00:abcd:0:1::<client_id>`) from a 24-bit `client_id`.
///
/// Mirrors the strongSwan pool range `::1:0–::ffff:ffff`.
pub fn client_vip_from_id24(client_id: u32) -> [u8; 16] {
    let d = VIP_POOL_DISCRIMINATOR; // [0x00, 0x00, 0x00, 0x01]
    let cid = client_id.to_be_bytes();
    [
        SYNTHETIC_PREFIX[0],
        SYNTHETIC_PREFIX[1],
        SYNTHETIC_PREFIX[2],
        SYNTHETIC_PREFIX[3],
        d[0],
        d[1],
        d[2],
        d[3],
        0x00,
        0x00,
        0x00,
        0x00,
        cid[0],
        cid[1],
        cid[2],
        cid[3],
    ]
}

// ---------------------------------------------------------------------------
// Userspace-only: aya::Pod implementations
// ---------------------------------------------------------------------------

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for NatEntry {}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for ProxySrcKey {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Test key for encode/decode tests.
    const TEST_KEY: ProxySrcKey = ProxySrcKey {
        prince_key: [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ],
        siphash_key: [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ],
    };

    fn tcp_ctx(src_port: u16, dst_port: u16) -> ProxySrcCtx {
        ProxySrcCtx::new(src_port, dst_port, 6)
    }

    // -- Existing contract tests (adapted) --

    #[test]
    fn vip_discriminator_matches_client_vip_layout() {
        let vip = client_vip_from_id24(0x0001_0000);
        assert_eq!(&vip[0..4], &SYNTHETIC_PREFIX);
        assert_eq!(&vip[4..8], &VIP_POOL_DISCRIMINATOR);
        assert_eq!(&vip[8..12], &[0u8; 4]);
        assert_eq!(&vip[12..16], &0x0001_0000u32.to_be_bytes());
    }

    #[test]
    fn synthetic_ipv6_prefix_matches() {
        let addr = synthetic_ipv6(42);
        assert_eq!(&addr[0..4], &SYNTHETIC_PREFIX);
    }

    #[test]
    fn xfrm_if_id_is_nonzero() {
        assert!(XFRM_IF_ID > 0);
    }

    // -- Obfuscated encode/decode tests --

    #[test]
    fn encode_decode_roundtrip() {
        let ctx = tcp_ctx(50000, 443);
        let addr = encode_proxy_src(100, 7, &ctx, &TEST_KEY).unwrap();
        assert_eq!(&addr[0..4], &PROXY_SRC_PREFIX);
        let (cid, did) = decode_proxy_src(&addr, &ctx, &TEST_KEY).unwrap();
        assert_eq!(cid, 100);
        assert_eq!(did, 7);
    }

    #[test]
    fn encode_decode_roundtrip_various() {
        let cases: &[(u32, u32, u16, u16)] = &[
            (0, 0, 1024, 80),
            (1, 1, 443, 50000),
            (0x00FF_FFFF, 0x00FF_FFFF, 65535, 65535),
            (0x0001_0000, 7, 50000, 443),
            (42, 999, 8080, 3000),
        ];
        for &(cid, did, sp, dp) in cases {
            let ctx = tcp_ctx(sp, dp);
            let addr = encode_proxy_src(cid, did, &ctx, &TEST_KEY).unwrap();
            let (c, d) = decode_proxy_src(&addr, &ctx, &TEST_KEY).unwrap();
            assert_eq!(
                (c, d),
                (cid, did),
                "roundtrip failed for cid={cid}, did={did}"
            );
        }
    }

    #[test]
    fn different_ctx_different_enc64() {
        let ctx1 = tcp_ctx(50000, 443);
        let ctx2 = tcp_ctx(50001, 443);
        let addr1 = encode_proxy_src(100, 7, &ctx1, &TEST_KEY).unwrap();
        let addr2 = encode_proxy_src(100, 7, &ctx2, &TEST_KEY).unwrap();
        // ENC64 (bytes 4-11) should differ for different flow contexts.
        assert_ne!(&addr1[4..12], &addr2[4..12]);
    }

    #[test]
    fn same_ctx_same_enc64() {
        let ctx = tcp_ctx(50000, 443);
        let addr1 = encode_proxy_src(100, 7, &ctx, &TEST_KEY).unwrap();
        let addr2 = encode_proxy_src(100, 7, &ctx, &TEST_KEY).unwrap();
        assert_eq!(
            addr1, addr2,
            "determinism: same inputs must produce same output"
        );
    }

    #[test]
    fn wrong_key_decode_returns_none() {
        let ctx = tcp_ctx(50000, 443);
        let addr = encode_proxy_src(100, 7, &ctx, &TEST_KEY).unwrap();
        let wrong_key = ProxySrcKey {
            prince_key: [0xFF; 16],
            siphash_key: [0xFF; 16],
        };
        assert!(decode_proxy_src(&addr, &ctx, &wrong_key).is_none());
    }

    #[test]
    fn tag32_tamper_returns_none() {
        let ctx = tcp_ctx(50000, 443);
        let mut addr = encode_proxy_src(100, 7, &ctx, &TEST_KEY).unwrap();
        // Flip a bit in TAG32 (byte 12).
        addr[12] ^= 0x01;
        assert!(decode_proxy_src(&addr, &ctx, &TEST_KEY).is_none());
    }

    #[test]
    fn enc64_tamper_returns_none() {
        let ctx = tcp_ctx(50000, 443);
        let mut addr = encode_proxy_src(100, 7, &ctx, &TEST_KEY).unwrap();
        // Flip a bit in ENC64 (byte 6). TAG32 will mismatch.
        addr[6] ^= 0x01;
        assert!(decode_proxy_src(&addr, &ctx, &TEST_KEY).is_none());
    }

    #[test]
    fn client_id_over_24bit_returns_none() {
        let ctx = tcp_ctx(50000, 443);
        assert!(encode_proxy_src(0x0100_0000, 7, &ctx, &TEST_KEY).is_none());
    }

    #[test]
    fn domain_id_over_24bit_returns_none() {
        let ctx = tcp_ctx(50000, 443);
        assert!(encode_proxy_src(100, 0x0100_0000, &ctx, &TEST_KEY).is_none());
    }

    #[test]
    fn size_alignment_invariants() {
        assert_eq!(core::mem::size_of::<ProxySrcCtx>(), 8);
        assert_eq!(core::mem::size_of::<ProxySrcKey>(), 32);
    }

    #[test]
    fn proxy_src_key_is_zero() {
        let zero = ProxySrcKey {
            prince_key: [0; 16],
            siphash_key: [0; 16],
        };
        assert!(zero.is_zero());
        assert!(!TEST_KEY.is_zero());
    }

    #[test]
    fn proxy_src_prefix_distinct_from_synthetic() {
        // The proxy-source prefix must be different from the synthetic prefix.
        assert_ne!(PROXY_SRC_PREFIX, SYNTHETIC_PREFIX);
    }
}
