//! Refuses ed25519 public keys of small order.
//!
//! A point of small order (one of the eight torsion points of edwards25519) has no secret key,
//! and a cofactorless verifier — `ed25519_dalek::VerifyingKey::verify`, the one `near-crypto`
//! uses — accepts signatures for it that nobody needs a secret to make. A key a contract adds to
//! an account, or a key a TEE registers, must never be one.
//!
//! The test is libsodium's `ge25519_has_small_order`: the encoding, its sign bit ignored, against
//! the seven encodings of the torsion points' y coordinates, the two non-canonical ones (y = p,
//! y = p + 1) included. Every other non-canonical y (p + 2 … 2^255 − 1) is a point of large order
//! or no point. The tests check it against curve25519-dalek on every encoding that can decode to
//! a torsion point.
#![no_std]

const SMALL_ORDER_Y: [[u8; 32]; 7] = [
    // y = 0 (order 4)
    [0; 32],
    // y = 1 (order 1)
    [
        0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0,
    ],
    // order 8
    [
        0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98,
        0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53,
        0xfc, 0x05,
    ],
    // order 8
    [
        0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67,
        0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac,
        0x03, 0x7a,
    ],
    // y = p − 1 (order 2)
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    // y = p, non-canonical 0 (order 4)
    [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    // y = p + 1, non-canonical 1 (order 1)
    [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
];

/// True when the 32-byte ed25519 public key encodes a point of small order (sign bit ignored).
pub fn is_small_order(key: &[u8; 32]) -> bool {
    SMALL_ORDER_Y.iter().any(|y| {
        key[..31] == y[..31] && (key[31] & 0x7f) == y[31]
    })
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::is_small_order;
    use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION};
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use curve25519_dalek::scalar::Scalar;
    use sha2::{Digest, Sha512};

    /// What curve25519-dalek says: the encoding decodes to a point, and that point is of small order.
    fn dalek_small_order(key: &[u8; 32]) -> bool {
        CompressedEdwardsY(*key).decompress().map(|p| p.is_small_order()).unwrap_or(false)
    }

    fn both_signs(mut key: [u8; 32]) -> [[u8; 32]; 2] {
        key[31] &= 0x7f;
        let mut neg = key;
        neg[31] |= 0x80;
        [key, neg]
    }

    #[test]
    fn every_torsion_point_is_refused_with_either_sign_bit() {
        for p in EIGHT_TORSION.iter() {
            for key in both_signs(p.compress().to_bytes()) {
                assert!(is_small_order(&key), "torsion point {:02x?} passed", key);
            }
        }
    }

    #[test]
    fn the_all_zero_key_is_refused() {
        assert!(is_small_order(&[0u8; 32]));
    }

    #[test]
    fn non_canonical_encodings_agree_with_dalek() {
        // y = p + k for k in 0..19: every y at or above p that fits in 255 bits.
        for k in 0u8..19 {
            let mut y = [0xffu8; 32];
            y[0] = 0xed + k; // 0xed..0xff; p = 2^255 - 19 = ed ff … ff 7f (little endian)
            y[31] = 0x7f;
            for key in both_signs(y) {
                assert_eq!(is_small_order(&key), dalek_small_order(&key), "y = p + {k}, {:02x?}", key);
            }
        }
    }

    #[test]
    fn small_order_points_plus_canonical_neighbours_agree_with_dalek() {
        // Each torsion point's y, and y ± 1: nothing next to a refused encoding is refused.
        for p in EIGHT_TORSION.iter() {
            let base = p.compress().to_bytes();
            for delta in [-1i16, 0, 1] {
                let mut y = base;
                let b0 = y[0] as i16 + delta;
                if !(0..=255).contains(&b0) {
                    continue;
                }
                y[0] = b0 as u8;
                for key in both_signs(y) {
                    assert_eq!(is_small_order(&key), dalek_small_order(&key), "{:02x?}", key);
                }
            }
        }
    }

    #[test]
    fn real_keys_pass() {
        // Public keys of 2000 secret scalars: none is refused, and dalek agrees they are large order.
        let mut seed = [0u8; 64];
        for i in 0..2000u32 {
            seed = Sha512::new().chain_update(seed).chain_update(i.to_le_bytes()).finalize().into();
            let s = Scalar::from_bytes_mod_order_wide(&seed);
            let key = (ED25519_BASEPOINT_POINT * s).compress().to_bytes();
            assert!(!is_small_order(&key), "real key {:02x?} refused", key);
            assert!(!dalek_small_order(&key));
        }
    }

    #[test]
    fn a_torsion_point_added_to_a_real_key_passes() {
        // Mixed-order keys (real + torsion) are large order: not this function's business.
        let key = (ED25519_BASEPOINT_POINT * Scalar::from(7u64) + EIGHT_TORSION[1]).compress().to_bytes();
        assert!(!is_small_order(&key));
        assert!(!dalek_small_order(&key));
    }
}
