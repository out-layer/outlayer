//! Sealing an answer to a key the caller supplied — how a run on chain returns
//! something only the caller may read.
//!
//! The output of an on-chain run is written into the transaction's result and
//! is public for ever. The owner's policy names the repositories their agent may
//! touch, so it does not go there in the clear: a caller passes a fresh
//! secp256k1 public key as `reply_pubkey` and gets the policy back sealed to
//! it. The private half never left the caller's browser, so nothing on the
//! chain — and nothing between here and the chain — can open the answer.
//!
//! The construction is the pair near.email runs on: the `ecies` crate here and
//! `eciesjs` in the browser — secp256k1 ECDH → HKDF-SHA256 → AES-256-GCM, in a
//! format the two libraries keep compatible with each other, so nothing about
//! the bytes is ours to get wrong. The keystore's own ECIES (X25519) is the
//! other direction, browser → enclave, and the two never meet.

/// The caller's key, as `status` accepts it: a secp256k1 public key in hex —
/// 33 bytes compressed, as `eciesjs` gives it, or 65 uncompressed. Parsed on
/// the curve before anything is sealed to it, so a refusal can say exactly what
/// was wrong.
pub fn parse_pubkey(hex: &str) -> Result<Vec<u8>, String> {
    let hex = hex.trim();
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    let bytes = decode_hex(hex).ok_or_else(|| {
        format!(
            "`reply_pubkey` must be a secp256k1 public key in hex — 66 characters compressed \
             (as `eciesjs` gives it) or 130 uncompressed; got {} characters{}",
            hex.len(),
            if hex.bytes().all(|b| b.is_ascii_hexdigit()) { "" } else { ", not all of them hex" }
        )
    })?;
    if bytes.len() != 33 && bytes.len() != 65 {
        return Err(format!(
            "`reply_pubkey` must be a secp256k1 public key of 33 or 65 bytes; got {} bytes",
            bytes.len()
        ));
    }
    libsecp256k1::PublicKey::parse_slice(&bytes, None)
        .map_err(|e| format!("`reply_pubkey` is not a point on secp256k1 ({e:?}); generate a fresh keypair"))?;
    Ok(bytes)
}

fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok()).collect()
}

/// Seal `plaintext` so that only the holder of `recipient`'s private half can
/// open it. `recipient` has been through `parse_pubkey`.
pub fn seal(recipient: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    ecies::encrypt(recipient, plaintext).map_err(|e| format!("sealing failed: {e:?}"))
}

/// The receiving side, kept here for the tests only: the connector never opens
/// anything. The dashboard opens with `eciesjs`, and the golden vector below is
/// opened by both.
#[cfg(test)]
pub fn open(secret: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>, String> {
    ecies::decrypt(secret, blob).map_err(|e| format!("the seal did not open: {e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> ([u8; 32], Vec<u8>) {
        let (sk, pk) = ecies::utils::generate_keypair();
        (sk.serialize(), pk.serialize_compressed().to_vec())
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn a_pubkey_is_a_point_on_the_curve_and_the_refusal_says_what_was_wrong() {
        let (_, public) = keypair();
        assert_eq!(parse_pubkey(&hex(&public)).unwrap(), public);
        assert_eq!(parse_pubkey(&format!("0x{}", hex(&public))).unwrap(), public, "a 0x prefix is tolerated");
        assert_eq!(parse_pubkey(&hex(&public).to_uppercase()).unwrap(), public);
        let short = parse_pubkey("abcd").unwrap_err();
        assert!(short.contains("33 or 65 bytes") && short.contains("got 2 bytes"), "{short}");
        let odd = parse_pubkey("abc").unwrap_err();
        assert!(odd.contains("66 characters") && odd.contains("got 3"), "{odd}");
        let bad = parse_pubkey(&"zz".repeat(33)).unwrap_err();
        assert!(bad.contains("not all of them hex"), "{bad}");
        // Right length, wrong bytes: a prefix byte no compressed key has.
        let mut off = public.clone();
        off[0] = 0x05;
        let err = parse_pubkey(&hex(&off)).unwrap_err();
        assert!(err.contains("not a point on secp256k1"), "{err}");
    }

    #[test]
    fn what_is_sealed_to_a_key_opens_with_its_private_half_and_nothing_else() {
        let (secret, public) = keypair();
        let (other, _) = keypair();
        let blob = seal(&public, b"{\"present\":true}").unwrap();
        assert_eq!(open(&secret, &blob).unwrap(), b"{\"present\":true}");
        assert!(open(&other, &blob).is_err(), "another key must not open it");
        let mut tampered = blob.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(open(&secret, &tampered).is_err(), "a changed byte must not open");
        assert_ne!(seal(&public, b"x").unwrap(), seal(&public, b"x").unwrap(), "fresh ephemeral key and nonce every time");
    }

    /// The bytes the dashboard's test opens with `eciesjs`: `test/ecies.test.mjs`
    /// there holds this same blob and secret. Change one side and the other
    /// must move.
    #[test]
    fn the_golden_vector_the_dashboard_also_opens() {
        let secret: [u8; 32] = core::array::from_fn(|i| (i as u8) + 1);
        let blob = decode_hex(GOLDEN_BLOB).expect("the pinned vector is hex");
        assert_eq!(String::from_utf8(open(&secret, &blob).unwrap()).unwrap(), GOLDEN_PLAINTEXT);
    }

    /// `cargo test -- --ignored --nocapture print_a_fresh_golden_vector` when
    /// the format changes; paste the output here and into the dashboard test.
    #[test]
    #[ignore]
    fn print_a_fresh_golden_vector() {
        let secret: [u8; 32] = core::array::from_fn(|i| (i as u8) + 1);
        let sk = libsecp256k1::SecretKey::parse(&secret).unwrap();
        let public = libsecp256k1::PublicKey::from_secret_key(&sk).serialize_compressed();
        let blob = seal(&public, GOLDEN_PLAINTEXT.as_bytes()).unwrap();
        println!("GOLDEN_PUBKEY = {}", hex(&public));
        println!("GOLDEN_BLOB = {}", hex(&blob));
    }

    const GOLDEN_PLAINTEXT: &str =
        r#"{"present":true,"recipient_domains":["example.com"],"max_per_day":20}"#;
    const GOLDEN_BLOB: &str = "0492378401b0aa5cc254daf633fe5d683a037f61ef03c1f2e6d45cc356e0e451183fbce77e9c469abb97bf04e1434caad989d4098ecaeb4da1356d7da0a76c4c5684185c155e8161102168242adebddb0e727580285dee0f6fa2aeb4b16a8fcac03b911e61dd5a6ea0bd193ab78fd168016b419fe090a42f7d0843ae62086d6f7171cd70aab94d8d221e06b608a1a8390e794194f67a4aac6ed14137e8c436962366894fb7ae";
}
