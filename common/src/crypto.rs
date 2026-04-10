//! Cryptographic primitives for proxy-source address obfuscation.
//!
//! All code is `no_std` compatible, integer-only, fixed-round, and eBPF-verifier safe.
//! No heap allocations, no branches on secret data.
//!
//! - **PRINCE**: 64-bit block cipher with 128-bit key (Borghoff et al., 2012).
//!   Used for encrypting `(client_id, domain_id, PAD16)` in the proxy-source address.
//!
//! - **SipHash-2-4**: 128-bit key, 64-bit output MAC (Aumasson & Bernstein).
//!   Used for TAG32 integrity tag (truncated to lower 32 bits).
//!
//! - **hash_ctx**: splitmix64-based context mixer for flow-context tweaking.

use crate::ProxySrcCtx;

// ===========================================================================
// PRINCE block cipher (64-bit block, 128-bit key, 12 rounds)
// ===========================================================================

/// PRINCE round constants RC[0..11] from the original paper (Borghoff et al., 2012).
const RC: [u64; 12] = [
    0x0000000000000000,
    0x13198a2e03707344,
    0xa4093822299f31d0,
    0x082efa98ec4e6c89,
    0x452821e638d01377,
    0xbe5466cf34e90c6c,
    0x7ef84f78fd955cb1,
    0x85840851f1ac43aa,
    0xc882d32f25323c54,
    0x64a51195e0e3610d,
    0xd3b5a399ca0c2399,
    0xc0ac29b7c97c50dd,
];

/// PRINCE alpha constant used for key derivation: k0' = k0 XOR alpha.
const ALPHA: u64 = 0xc0ac29b7c97c50dd;

/// 4-bit PRINCE S-box (16 entries).
const SBOX: [u8; 16] = [
    0xB, 0xF, 0x3, 0x2, 0xA, 0xC, 0x9, 0x1, 0x6, 0x7, 0x8, 0x0, 0xE, 0x5, 0xD, 0x4,
];

/// 4-bit PRINCE inverse S-box.
const SBOX_INV: [u8; 16] = [
    0xB, 0x7, 0x3, 0x2, 0xF, 0xD, 0x8, 0x9, 0xA, 0x6, 0x4, 0x0, 0x5, 0xE, 0xC, 0x1,
];

/// Apply the PRINCE S-box to all 16 nibbles of a 64-bit value.
///
/// The nibble ordering is irrelevant for this function — every nibble is
/// independently substituted. We iterate LSB to MSB for simplicity.
#[inline(never)]
fn sbox_layer(x: u64) -> u64 {
    (SBOX[(x & 0xF) as usize] as u64)
        | (SBOX[((x >> 4) & 0xF) as usize] as u64) << 4
        | (SBOX[((x >> 8) & 0xF) as usize] as u64) << 8
        | (SBOX[((x >> 12) & 0xF) as usize] as u64) << 12
        | (SBOX[((x >> 16) & 0xF) as usize] as u64) << 16
        | (SBOX[((x >> 20) & 0xF) as usize] as u64) << 20
        | (SBOX[((x >> 24) & 0xF) as usize] as u64) << 24
        | (SBOX[((x >> 28) & 0xF) as usize] as u64) << 28
        | (SBOX[((x >> 32) & 0xF) as usize] as u64) << 32
        | (SBOX[((x >> 36) & 0xF) as usize] as u64) << 36
        | (SBOX[((x >> 40) & 0xF) as usize] as u64) << 40
        | (SBOX[((x >> 44) & 0xF) as usize] as u64) << 44
        | (SBOX[((x >> 48) & 0xF) as usize] as u64) << 48
        | (SBOX[((x >> 52) & 0xF) as usize] as u64) << 52
        | (SBOX[((x >> 56) & 0xF) as usize] as u64) << 56
        | (SBOX[((x >> 60) & 0xF) as usize] as u64) << 60
}

/// Apply the PRINCE inverse S-box to all 16 nibbles of a 64-bit value.
#[inline(never)]
fn sbox_inv_layer(x: u64) -> u64 {
    (SBOX_INV[(x & 0xF) as usize] as u64)
        | (SBOX_INV[((x >> 4) & 0xF) as usize] as u64) << 4
        | (SBOX_INV[((x >> 8) & 0xF) as usize] as u64) << 8
        | (SBOX_INV[((x >> 12) & 0xF) as usize] as u64) << 12
        | (SBOX_INV[((x >> 16) & 0xF) as usize] as u64) << 16
        | (SBOX_INV[((x >> 20) & 0xF) as usize] as u64) << 20
        | (SBOX_INV[((x >> 24) & 0xF) as usize] as u64) << 24
        | (SBOX_INV[((x >> 28) & 0xF) as usize] as u64) << 28
        | (SBOX_INV[((x >> 32) & 0xF) as usize] as u64) << 32
        | (SBOX_INV[((x >> 36) & 0xF) as usize] as u64) << 36
        | (SBOX_INV[((x >> 40) & 0xF) as usize] as u64) << 40
        | (SBOX_INV[((x >> 44) & 0xF) as usize] as u64) << 44
        | (SBOX_INV[((x >> 48) & 0xF) as usize] as u64) << 48
        | (SBOX_INV[((x >> 52) & 0xF) as usize] as u64) << 52
        | (SBOX_INV[((x >> 56) & 0xF) as usize] as u64) << 56
        | (SBOX_INV[((x >> 60) & 0xF) as usize] as u64) << 60
}

// ---------------------------------------------------------------------------
// M' (M-prime) layer
//
// The 64-bit state is split into four 16-bit chunks:
//   chunk0 = bits 15:0, chunk1 = bits 31:16,
//   chunk2 = bits 47:32, chunk3 = bits 63:48
//
// M'(state) = M_hat_0(chunk0) | M_hat_1(chunk1) << 16
//           | M_hat_1(chunk2) << 32 | M_hat_0(chunk3) << 48
//
// M_hat_0 and M_hat_1 are 16x16 involutory matrices over GF(2),
// represented as column vectors.
// ---------------------------------------------------------------------------

/// M_hat_0 column vectors (16-bit each). Column i is the vector that input bit i maps to.
/// From the PRINCE reference implementation.
const M_HAT_0: [u16; 16] = [
    0x0111, 0x2220, 0x4404, 0x8088, 0x1011, 0x0222, 0x4440, 0x8808, 0x1101, 0x2022, 0x0444, 0x8880,
    0x1110, 0x2202, 0x4044, 0x0888,
];

/// M_hat_1 column vectors. M_hat_1[i] = rotate_left_16(M_hat_0[i], 4).
const M_HAT_1: [u16; 16] = [
    0x1110, 0x2202, 0x4044, 0x0888, 0x0111, 0x2220, 0x4404, 0x8088, 0x1011, 0x0222, 0x4440, 0x8808,
    0x1101, 0x2022, 0x0444, 0x8880,
];

/// GF(2) matrix-vector multiplication: 16x16 matrix (column vectors) * 16-bit value.
#[inline(never)]
fn gf2_mat_mul(val: u16, cols: &[u16; 16]) -> u16 {
    let mut out: u16 = 0;
    out ^= cols[0] & (val & 1).wrapping_neg();
    out ^= cols[1] & ((val >> 1) & 1).wrapping_neg();
    out ^= cols[2] & ((val >> 2) & 1).wrapping_neg();
    out ^= cols[3] & ((val >> 3) & 1).wrapping_neg();
    out ^= cols[4] & ((val >> 4) & 1).wrapping_neg();
    out ^= cols[5] & ((val >> 5) & 1).wrapping_neg();
    out ^= cols[6] & ((val >> 6) & 1).wrapping_neg();
    out ^= cols[7] & ((val >> 7) & 1).wrapping_neg();
    out ^= cols[8] & ((val >> 8) & 1).wrapping_neg();
    out ^= cols[9] & ((val >> 9) & 1).wrapping_neg();
    out ^= cols[10] & ((val >> 10) & 1).wrapping_neg();
    out ^= cols[11] & ((val >> 11) & 1).wrapping_neg();
    out ^= cols[12] & ((val >> 12) & 1).wrapping_neg();
    out ^= cols[13] & ((val >> 13) & 1).wrapping_neg();
    out ^= cols[14] & ((val >> 14) & 1).wrapping_neg();
    out ^= cols[15] & ((val >> 15) & 1).wrapping_neg();
    out
}

/// M' layer: applies M_hat_0/M_hat_1 to the four 16-bit chunks.
/// M' is an involution (self-inverse).
#[inline(never)]
fn m_prime(x: u64) -> u64 {
    let c0 = (x & 0xFFFF) as u16;
    let c1 = ((x >> 16) & 0xFFFF) as u16;
    let c2 = ((x >> 32) & 0xFFFF) as u16;
    let c3 = ((x >> 48) & 0xFFFF) as u16;

    let r0 = gf2_mat_mul(c0, &M_HAT_0) as u64;
    let r1 = gf2_mat_mul(c1, &M_HAT_1) as u64;
    let r2 = gf2_mat_mul(c2, &M_HAT_1) as u64;
    let r3 = gf2_mat_mul(c3, &M_HAT_0) as u64;

    r0 | (r1 << 16) | (r2 << 32) | (r3 << 48)
}

// ---------------------------------------------------------------------------
// ShiftRows
//
// The 64-bit state is viewed as a 4×4 matrix of nibbles. The nibble layout:
//   Row 0: nibbles at positions 3,7,11,15 (mask 0xF000F000F000F000 shifted)
//   Row 1: nibbles at positions 2,6,10,14
//   Row 2: nibbles at positions 1,5,9,13
//   Row 3: nibbles at positions 0,4,8,12
//
// Using the convention where nibble 0 = bits 3:0 (LSB), nibble 15 = bits 63:60 (MSB):
//   Row 0: mask = 0xF000_F000_F000_F000  (nibbles 3,7,11,15)
//   Row 1: mask = 0x0F00_0F00_0F00_0F00  (nibbles 2,6,10,14)
//   Row 2: mask = 0x00F0_00F0_00F0_00F0  (nibbles 1,5,9,13)
//   Row 3: mask = 0x000F_000F_000F_000F  (nibbles 0,4,8,12)
//
// ShiftRows rotates row r by r positions. In terms of the 64-bit word,
// each row occupies bits at 16-bit intervals, so shifting row r by r
// positions corresponds to rotating the row's bits right by r*16.
// ---------------------------------------------------------------------------

const ROW_MASK: [u64; 4] = [
    0xF000_F000_F000_F000,
    0x0F00_0F00_0F00_0F00,
    0x00F0_00F0_00F0_00F0,
    0x000F_000F_000F_000F,
];

/// Forward ShiftRows: row r is shifted by r positions.
/// In the reference C implementation, forward shift uses:
///   shift = 64 - i*16  (right rotate by (64 - i*16) = left rotate by i*16)
#[inline(always)]
fn shift_rows(x: u64) -> u64 {
    let row0 = x & ROW_MASK[0];
    let row1 = x & ROW_MASK[1];
    let row2 = x & ROW_MASK[2];
    let row3 = x & ROW_MASK[3];

    row0 | row1.rotate_left(16) | row2.rotate_right(32) | row3.rotate_right(16)
}

/// Inverse ShiftRows.
#[inline(always)]
fn shift_rows_inv(x: u64) -> u64 {
    let row0 = x & ROW_MASK[0];
    let row1 = x & ROW_MASK[1];
    let row2 = x & ROW_MASK[2];
    let row3 = x & ROW_MASK[3];

    row0 | row1.rotate_right(16) | row2.rotate_left(32) | row3.rotate_left(16)
}

// ---------------------------------------------------------------------------
// Full M-layer: M = SR ∘ M'
// ---------------------------------------------------------------------------

/// Full M-layer for forward rounds: SR ∘ M'.
#[inline(always)]
fn m_layer(x: u64) -> u64 {
    shift_rows(m_prime(x))
}

/// Inverse M-layer for inverse rounds: M' ∘ SR^{-1}.
#[inline(always)]
fn m_layer_inv(x: u64) -> u64 {
    m_prime(shift_rows_inv(x))
}

// ---------------------------------------------------------------------------
// PRINCE core
// ---------------------------------------------------------------------------

/// PRINCE core encryption: the 12-round core with key k1.
///
/// Full PRINCE: ciphertext = k0' XOR prince_core(plaintext XOR k0, k1)
#[inline(never)]
fn prince_core_encrypt(block: u64, k1: u64) -> u64 {
    let mut s = block;

    // Pre-whitening
    s ^= k1 ^ RC[0];

    // Forward rounds 1-5
    s = m_layer(sbox_layer(s)) ^ (RC[1] ^ k1);
    s = m_layer(sbox_layer(s)) ^ (RC[2] ^ k1);
    s = m_layer(sbox_layer(s)) ^ (RC[3] ^ k1);
    s = m_layer(sbox_layer(s)) ^ (RC[4] ^ k1);
    s = m_layer(sbox_layer(s)) ^ (RC[5] ^ k1);

    // Middle layer: S -> M' -> S^{-1}
    s = sbox_layer(s);
    s = m_prime(s);
    s = sbox_inv_layer(s);

    // Inverse rounds 6-10
    s = sbox_inv_layer(m_layer_inv(s ^ (k1 ^ RC[6])));
    s = sbox_inv_layer(m_layer_inv(s ^ (k1 ^ RC[7])));
    s = sbox_inv_layer(m_layer_inv(s ^ (k1 ^ RC[8])));
    s = sbox_inv_layer(m_layer_inv(s ^ (k1 ^ RC[9])));
    s = sbox_inv_layer(m_layer_inv(s ^ (k1 ^ RC[10])));

    // Post-whitening
    s ^= k1 ^ RC[11];

    s
}

/// PRINCE encrypt: 64-bit block, 128-bit key (k0 ‖ k1).
///
/// `key` is 16 bytes: bytes 0-7 = k0 (big-endian u64), bytes 8-15 = k1 (big-endian u64).
///
/// Full PRINCE: ciphertext = k0' XOR prince_core(plaintext XOR k0, k1)
/// where k0' = (k0 >>> 1) XOR (k0 >> 63).
#[inline(never)]
pub fn prince_encrypt(block: u64, key: &[u8; 16]) -> u64 {
    let k0 = u64::from_be_bytes([
        key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],
    ]);
    let k1 = u64::from_be_bytes([
        key[8], key[9], key[10], key[11], key[12], key[13], key[14], key[15],
    ]);

    // k0' = (k0 >>> 1) XOR (k0 >> 63) — the PRINCE key schedule.
    let k0_prime = k0.rotate_right(1) ^ (k0 >> 63);

    let input = block ^ k0;
    let core_out = prince_core_encrypt(input, k1);
    core_out ^ k0_prime
}

/// PRINCE decrypt: uses the alpha-reflection property.
///
/// Decryption is PRINCE encryption with k0 and k0' swapped, and k1' = k1 XOR alpha.
#[inline(never)]
pub fn prince_decrypt(block: u64, key: &[u8; 16]) -> u64 {
    let k0 = u64::from_be_bytes([
        key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],
    ]);
    let k1 = u64::from_be_bytes([
        key[8], key[9], key[10], key[11], key[12], key[13], key[14], key[15],
    ]);

    let k0_prime = k0.rotate_right(1) ^ (k0 >> 63);

    // For decryption: swap k0 and k0', use k1 XOR alpha
    let k1_dec = k1 ^ ALPHA;

    let input = block ^ k0_prime;
    let core_out = prince_core_encrypt(input, k1_dec);
    core_out ^ k0
}

// ===========================================================================
// SipHash-2-4 (128-bit key, 64-bit output) — delegated to `siphasher` crate
// ===========================================================================

#[inline(always)]
fn sip_round(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = v1.rotate_left(13);
    *v1 ^= *v0;
    *v0 = v0.rotate_left(32);

    *v2 = v2.wrapping_add(*v3);
    *v3 = v3.rotate_left(16);
    *v3 ^= *v2;

    *v0 = v0.wrapping_add(*v3);
    *v3 = v3.rotate_left(21);
    *v3 ^= *v0;

    *v2 = v2.wrapping_add(*v1);
    *v1 = v1.rotate_left(17);
    *v1 ^= *v2;
    *v2 = v2.rotate_left(32);
}

/// SipHash-2-4 specialized for a fixed 17-byte input.
///
/// This avoids variable-length loops in the eBPF path, keeping verifier state
/// growth bounded while preserving standard SipHash-2-4 output.
#[inline(never)]
pub fn siphash_2_4_17(key: &[u8; 16], data: &[u8; 17]) -> u64 {
    let k0 = u64::from_le_bytes([
        key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],
    ]);
    let k1 = u64::from_le_bytes([
        key[8], key[9], key[10], key[11], key[12], key[13], key[14], key[15],
    ]);

    let mut v0 = 0x736f6d6570736575 ^ k0;
    let mut v1 = 0x646f72616e646f6d ^ k1;
    let mut v2 = 0x6c7967656e657261 ^ k0;
    let mut v3 = 0x7465646279746573 ^ k1;

    let m0 = u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]);
    let m1 = u64::from_le_bytes([
        data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
    ]);
    let b = ((17u64) << 56) | (data[16] as u64);

    v3 ^= m0;
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= m0;

    v3 ^= m1;
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= m1;

    v3 ^= b;
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= b;

    v2 ^= 0xff;
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);

    v0 ^ v1 ^ v2 ^ v3
}

/// SipHash-2-4 with 128-bit key, producing a 64-bit hash.
///
/// Thin wrapper around the `siphasher` crate (jedisct1, no_std, audited).
/// The caller truncates to 32 bits for TAG32.
#[inline(never)]
pub fn siphash_2_4(key: &[u8; 16], data: &[u8]) -> u64 {
    use siphasher::sip::SipHasher24;
    SipHasher24::new_with_key(key).hash(data)
}

// ===========================================================================
// Context hash (splitmix64 finalizer)
// ===========================================================================

/// Deterministic context mixer: ProxySrcCtx → u64.
///
/// Packs the 5 meaningful context bytes (host-order src_port, dst_port, proto)
/// into a u64, then applies the splitmix64 finalizer for full diffusion.
///
/// This is NOT a cryptographic hash. It is a fast, deterministic, injective
/// mixer used to XOR flow context into the PRINCE plaintext, making the
/// encryption tweakable. PRINCE provides all cryptographic security.
///
/// Injectivity guarantee: packed() is injective on the 40-bit input space,
/// splitmix64 finalizer is a bijection on u64, so the composition is injective.
/// Distinct (src_port, dst_port, proto) tuples CANNOT collide.
///
/// ~5 instructions (2 multiplies, 3 XOR-shifts). eBPF-verifier safe.
/// No lookup tables, no branches, no_std compatible.
pub fn hash_ctx(ctx: &ProxySrcCtx) -> u64 {
    // Pack 5 context bytes into a u64 (host-byte-order values):
    //   bits 48-63: src_port (u16)
    //   bits 32-47: dst_port (u16)
    //   bits 24-31: proto (u8)
    //   bits  0-23: zero (unused, not from _pad)
    let packed: u64 =
        ((ctx.src_port as u64) << 48) | ((ctx.dst_port as u64) << 32) | ((ctx.proto as u64) << 24);

    // splitmix64 finalizer — bijection on u64.
    // Constants and shift amounts are locked. Do not modify.
    let mut h = packed;
    h ^= h >> 30;
    h = h.wrapping_mul(0xbf58476d1ce4e5b9);
    h ^= h >> 27;
    h = h.wrapping_mul(0x94d049bb133111eb);
    h ^= h >> 31;
    h
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
extern crate alloc;

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    // -----------------------------------------------------------------------
    // hash_ctx frozen test vectors (from plan)
    // -----------------------------------------------------------------------

    #[test]
    fn hash_ctx_zero() {
        let ctx = ProxySrcCtx::new(0, 0, 0);
        assert_eq!(hash_ctx(&ctx), 0x0000000000000000);
    }

    #[test]
    fn hash_ctx_443_50000_tcp() {
        let ctx = ProxySrcCtx::new(443, 50000, 6);
        assert_eq!(hash_ctx(&ctx), 0xae510a47a775e0c3);
    }

    #[test]
    fn hash_ctx_50000_443_tcp() {
        let ctx = ProxySrcCtx::new(50000, 443, 6);
        assert_eq!(hash_ctx(&ctx), 0x6999dcb37e570b67);
    }

    #[test]
    fn hash_ctx_443_50000_udp() {
        let ctx = ProxySrcCtx::new(443, 50000, 17);
        assert_eq!(hash_ctx(&ctx), 0x8e7b5430862b54bc);
    }

    #[test]
    fn hash_ctx_1_1_1() {
        let ctx = ProxySrcCtx::new(1, 1, 1);
        assert_eq!(hash_ctx(&ctx), 0xfbf2b99b8d507220);
    }

    #[test]
    fn hash_ctx_distinct_outputs() {
        let values = [
            0x0000000000000000u64,
            0xae510a47a775e0c3,
            0x6999dcb37e570b67,
            0x8e7b5430862b54bc,
            0xfbf2b99b8d507220,
        ];
        for i in 0..values.len() {
            for j in (i + 1)..values.len() {
                assert_ne!(values[i], values[j], "collision at indices {i} and {j}");
            }
        }
    }

    // -----------------------------------------------------------------------
    // M' involution test
    // -----------------------------------------------------------------------

    #[test]
    fn m_prime_is_involution() {
        for x in [
            0u64,
            1,
            0xdeadbeef,
            0x0123456789abcdef,
            0xffffffffffffffff,
            0xcafebabe00000000,
        ] {
            let y = m_prime(x);
            let z = m_prime(y);
            assert_eq!(z, x, "M' is not involutory for x={x:#018x}");
        }
    }

    // -----------------------------------------------------------------------
    // PRINCE test vectors from the original paper (Borghoff et al., 2012)
    // -----------------------------------------------------------------------

    #[test]
    fn prince_test_vector_all_zero() {
        let key = [0u8; 16];
        let ct = prince_encrypt(0x0000000000000000, &key);
        assert_eq!(ct, 0x818665aa0d02dfda, "PRINCE all-zero: got {ct:#018x}");
        let pt = prince_decrypt(ct, &key);
        assert_eq!(pt, 0x0000000000000000);
    }

    #[test]
    fn prince_test_vector_2() {
        let key = [0u8; 16];
        let ct = prince_encrypt(0xffffffffffffffff, &key);
        assert_eq!(ct, 0x604ae6ca03c20ada, "PRINCE TV2: got {ct:#018x}");
        let pt = prince_decrypt(ct, &key);
        assert_eq!(pt, 0xffffffffffffffff);
    }

    #[test]
    fn prince_test_vector_3() {
        let mut key = [0u8; 16];
        key[8] = 0xfe;
        key[9] = 0xdc;
        key[10] = 0xba;
        key[11] = 0x98;
        key[12] = 0x76;
        key[13] = 0x54;
        key[14] = 0x32;
        key[15] = 0x10;
        let ct = prince_encrypt(0x0123456789abcdef, &key);
        assert_eq!(ct, 0xae25ad3ca8fa9ccf, "PRINCE TV3: got {ct:#018x}");
        let pt = prince_decrypt(ct, &key);
        assert_eq!(pt, 0x0123456789abcdef);
    }

    #[test]
    fn prince_roundtrip_various() {
        let key: [u8; 16] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        for pt in [
            0u64,
            1,
            0xdeadbeefcafe0000,
            0xffffffffffffffff,
            0x0123456789abcdef,
        ] {
            let ct = prince_encrypt(pt, &key);
            let dec = prince_decrypt(ct, &key);
            assert_eq!(dec, pt, "round-trip failed for pt={pt:#018x}");
            assert_ne!(ct, pt, "no encryption for pt={pt:#018x}");
        }
    }

    #[test]
    fn prince_encrypt_decrypt_consistency() {
        let key: [u8; 16] = [
            0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08,
        ];
        for pt in 0..100u64 {
            let ct = prince_encrypt(pt, &key);
            let dec = prince_decrypt(ct, &key);
            assert_eq!(dec, pt, "consistency failed for pt={pt}");
        }
    }

    // -----------------------------------------------------------------------
    // SipHash-2-4 test vectors from Appendix A
    // -----------------------------------------------------------------------

    #[test]
    fn siphash_reference_vectors() {
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];

        let expected: [u64; 16] = [
            0x726fdb47dd0e0e31,
            0x74f839c593dc67fd,
            0x0d6c8009d9a94f5a,
            0x85676696d7fb7e2d,
            0xcf2794e0277187b7,
            0x18765564cd99a68d,
            0xcbc9466e58fee3ce,
            0xab0200f58b01d137,
            0x93f5f5799a932462,
            0x9e0082df0ba9e4b0,
            0x7a5dbbc594ddb9f3,
            0xf4b32f46226bada7,
            0x751e8fbc860ee5fb,
            0x14ea5627c0843d90,
            0xf723ca908e7af2ee,
            0xa129ca6149be45e5,
        ];

        for i in 0..16usize {
            let input: Vec<u8> = (0..i as u8).collect();
            let result = siphash_2_4(&key, &input);
            assert_eq!(
                result, expected[i],
                "SipHash vector {i} failed: got={result:#018x}, expected={:#018x}",
                expected[i]
            );
        }
    }

    #[test]
    fn siphash_empty_input() {
        let key = [0u8; 16];
        let h1 = siphash_2_4(&key, &[]);
        let h2 = siphash_2_4(&key, &[]);
        assert_eq!(h1, h2);
    }

    #[test]
    fn siphash_fixed_17_matches_reference() {
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let input: [u8; 17] = [
            0x20, 0x01, 0x0d, 0xb8, 0x13, 0x57, 0x9b, 0xdf, 0x24, 0x68, 0xac, 0xf0, 0x01, 0xbb,
            0xc3, 0x50, 0x06,
        ];

        let expected = siphash_2_4(&key, &input);
        let got = siphash_2_4_17(&key, &input);
        assert_eq!(got, expected);
    }

    #[test]
    fn siphash_fixed_17_matches_reference_many_inputs() {
        let key: [u8; 16] = [
            0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d,
            0x1e, 0x0f,
        ];

        for seed in 0u8..32u8 {
            let mut input = [0u8; 17];
            let mut i = 0usize;
            while i < 17 {
                input[i] = seed
                    .wrapping_mul(17)
                    .wrapping_add((i as u8).wrapping_mul(29));
                i += 1;
            }

            let expected = siphash_2_4(&key, &input);
            let got = siphash_2_4_17(&key, &input);
            assert_eq!(got, expected, "seed={seed}");
        }
    }
}
