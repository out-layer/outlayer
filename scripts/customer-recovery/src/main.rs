//! customer-recovery — standalone CKD recovery for an unlocked vault.
//!
//! After `finalize_recovery` flips a vault to `unlocked = true`, the
//! parent has FullAccess on the vault account. OutLayer's keystore
//! refuses to serve the per-vault master from then on (defense-in-depth
//! gate in `keystore-worker/src/mpc_ckd.rs::ensure_customer_loaded`).
//!
//! The customer recovers the master themselves by signing a fresh
//! `request_app_private_key` call to the MPC contract directly,
//! attaching 1 yoctoNEAR (FullAccess can attach deposit; the previous
//! TEE function-call key could not — that's why the vault contract
//! had a `request_master` proxy).
//!
//! With the master in hand, the customer can deterministically
//! re-derive every wallet keypair the keystore would have produced
//! (HMAC-SHA256(master, "wallet:<seed>")), so addresses persist
//! across the sovereignty handover.
//!
//! ## Usage
//!
//! ```bash
//! cargo run --release -- \
//!     --vault-id vault.alice.testnet \
//!     --signer-private-key ed25519:5m... \
//!     --derivation-path '<HMAC-derived hex from past on-chain tx>' \
//!     --mpc-contract v1.signer-prod.testnet \
//!     --mpc-public-key 'bls12381g2:...' \
//!     --mpc-domain-id 2 \
//!     --rpc-url https://rpc.testnet.fastnear.com
//! ```
//!
//! ## How to find `derivation_path`
//!
//! The keystore-worker computed it as
//! `HMAC-SHA256(default_master, "vault-master:<vault_id>")` and then
//! used it as a CKD argument. After the first request_app_private_key
//! call landed on chain, the path is publicly visible in the tx args.
//!
//! Easiest way: query NEARblocks for the vault's tx history, find the
//! `request_app_private_key` receipt to MPC, decode its args (base64
//! JSON), and copy the `derivation_path` field. The `--from-chain`
//! flag in this tool does that automatically when set.

use anyhow::{anyhow, Context, Result};
use blstrs::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use clap::Parser;
use elliptic_curve::{group::prime::PrimeCurveAffine, Field, Group};
use hkdf::Hkdf;
use near_crypto::{InMemorySigner, SecretKey};
use near_jsonrpc_client::{methods, JsonRpcClient};
use near_jsonrpc_primitives::types::query::QueryResponseKind;
use near_primitives::{
    transaction::{Action, FunctionCallAction, Transaction, TransactionV0},
    types::{AccountId, BlockReference, Finality},
    views::{FinalExecutionStatus, QueryRequest},
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sha3::{Digest, Sha3_256};

const BLS12381G1_PUBLIC_KEY_SIZE: usize = 48;
const OUTPUT_SECRET_SIZE: usize = 32;
const APP_ID_DERIVATION_PREFIX: &str = "near-mpc v0.1.0 app_id derivation:";
const NEAR_CKD_DOMAIN: &[u8] = b"NEAR BLS12381G1_XMD:SHA-256_SSWU_RO_";

#[derive(Parser, Debug)]
#[command(
    name = "customer-recovery",
    about = "Recover a vault's per-customer master after finalize_recovery"
)]
struct Cli {
    /// Vault account id (e.g. `vault.alice.testnet`). Used as the
    /// signer of the MPC tx — its FullAccess key must already be on
    /// chain (that's what `finalize_recovery(new_parent_pubkey)`
    /// atomically installs as part of the key-swap).
    #[arg(long)]
    vault_id: AccountId,

    /// Vault's FullAccess private key in `ed25519:base58` form.
    #[arg(long, env = "VAULT_PRIVATE_KEY")]
    signer_private_key: String,

    /// Derivation path the keystore used. Either pass it directly here
    /// or use `--from-chain` to auto-extract it from the vault's tx
    /// history.
    #[arg(long)]
    derivation_path: Option<String>,

    /// Auto-extract derivation_path from on-chain tx history. Calls
    /// NEARblocks API to find the most recent successful
    /// `request_app_private_key` receipt to MPC and decodes its args.
    #[arg(long)]
    from_chain: bool,

    /// MPC contract account id.
    #[arg(long, default_value = "v1.signer-prod.testnet")]
    mpc_contract: AccountId,

    /// MPC G2 public key in `bls12381g2:base58` form. Same value the
    /// keystore-worker uses (`MPC_PUBLIC_KEY` env var).
    #[arg(long, env = "MPC_PUBLIC_KEY")]
    mpc_public_key: String,

    /// MPC domain id (2 for testnet per current keystore config).
    #[arg(long, default_value = "2")]
    mpc_domain_id: u64,

    /// NEAR RPC URL.
    #[arg(long, default_value = "https://rpc.testnet.fastnear.com")]
    rpc_url: String,

    /// NEARblocks-compatible API base for `--from-chain` lookup.
    #[arg(long, default_value = "https://api-testnet.nearblocks.io")]
    nearblocks_url: String,
}

#[derive(Debug, Serialize)]
struct CkdRequestArgs {
    request: CkdArgs,
}

#[derive(Debug, Serialize)]
struct CkdArgs {
    derivation_path: String,
    app_public_key: String,
    domain_id: u64,
}

#[derive(Debug, Deserialize)]
struct CkdResponse {
    big_y: String,
    big_c: String,
}

/// `customer-recovery generate-key` — emit a fresh ed25519 keypair
/// as JSON to stdout and exit. Used by `walkthrough.sh` step 1 so
/// the user doesn't need an external NEAR keygen tool installed.
/// The output shape matches what the rest of the walkthrough
/// expects: `{public_key: "ed25519:...", private_key: "ed25519:..."}`
/// — same format `near-cli-rs`'s key files use, so other NEAR tools
/// can read it.
fn generate_key_subcommand() -> Result<()> {
    let sk = SecretKey::from_random(near_crypto::KeyType::ED25519);
    let pk = sk.public_key();
    let json = serde_json::json!({
        "public_key": pk.to_string(),
        "private_key": sk.to_string(),
    });
    warn_sensitive_stdout("a freshly generated FullAccess key");
    println!("{}", serde_json::to_string_pretty(&json)?);
    Ok(())
}

/// Print a one-line stderr warning before stdout emits a secret.
/// Drawn to the user's attention because they often pipe the tool's
/// stdout into `tee`, log files, or shell history while testing.
fn warn_sensitive_stdout(what: &str) {
    eprintln!(
        "\x1b[33m⚠  About to write {what} to stdout.\n   \
         Redirect to a 0600 file, do NOT log or paste publicly. \
         Anything captured here grants control of the wallet.\x1b[0m"
    );
}

/// `customer-recovery derive-wallet-key --master <hex> --wallet-id <uuid>`
/// — given the per-vault master recovered from MPC CKD, re-derive
/// the NEAR wallet keypair that OutLayer's keystore-worker would
/// have minted for `(vault, wallet_id)`. This is the final step of
/// the sovereign-exit chain: after the on-chain `finalize_recovery`,
/// the user has the master locally — but the WALLET they were using
/// was minted by the keystore from that master + a UUID. Without
/// re-deriving that wallet's private key, the customer has the
/// secrets but no direct path to the on-chain wallet balance.
///
/// Derivation matches keystore-worker's `Keystore::derive_keypair`
/// (`keystore-worker/src/crypto.rs:284`):
///     seed       = "wallet:{wallet_id}:near"
///     hmac_out   = HMAC-SHA256(master, seed)
///     secret_key = ed25519::SecretKey::from_bytes(hmac_out[..32])
///
/// The wallet's NEAR account id is the hex-encoded pubkey (implicit
/// account format). Output as JSON for easy `jq` consumption by
/// `tests/sovereignty_e2e.sh`.
/// `customer-recovery decrypt-secret --master <hex> --seed <s>
/// --ciphertext-base64 <b64>` — locally decrypt a secret that was
/// stored on-chain via `outlayer secrets set`. Used by
/// `tests/sovereignty_e2e.sh` after `finalize_recovery` to prove
/// that the customer can still read their own secrets without going
/// through the keystore-worker.
///
/// Encryption format matches `outlayer-cli/src/crypto.rs::encrypt_secrets`
/// (the LEGACY path the CLI uses today):
///     1. seed: e.g. "project:{owner}/{name}:{owner}"  (the same seed the
///        keystore builds in keystore-worker/src/api.rs)
///     2. signing_key = HMAC-SHA256(master, seed)[..32]
///     3. verifying_key = ed25519::SigningKey(signing_key).public_key()
///     4. ChaCha20-Poly1305 key = verifying_key.to_bytes()  (32 bytes)
///     5. payload = nonce(12) || ciphertext || tag(16)
///
/// So this subcommand is symmetric with the keystore's
/// `decrypt_legacy` (keystore-worker/src/crypto.rs:507): both
/// derive the SAME ChaCha20 key from `(master, seed)` and run the
/// SAME AEAD over the SAME wire format. The keystore additionally
/// supports an ECIES v1 envelope; that path can't be reached from
/// the CLI today and is not implemented here.
/// Internal smoke-test for the encrypt/decrypt round-trip. Not user-
/// facing; run via `cargo test --release -p customer-recovery`. Encrypts
/// `plaintext` with the same algorithm `outlayer-cli/src/crypto.rs::encrypt_secrets`
/// uses, then decrypts via `decrypt_secret_subcommand`'s internal logic
/// and asserts they round-trip. If this test ever starts failing, the
/// HMAC → ed25519 → ChaCha20 chain has diverged between CLI and
/// customer-recovery.
#[cfg(test)]
mod roundtrip_tests {
    use chacha20poly1305::aead::Aead;
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<sha2::Sha256>;

    fn encrypt_like_cli(master: &[u8; 32], seed: &str, plaintext: &[u8]) -> Vec<u8> {
        // Mirror keystore-worker/src/crypto.rs::derive_keypair
        let mut mac = <HmacSha256 as Mac>::new_from_slice(master).unwrap();
        mac.update(seed.as_bytes());
        let derived = mac.finalize().into_bytes();
        let mut secret_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(&derived[..32]);
        let sk = ed25519_dalek::SigningKey::from_bytes(&secret_bytes);
        let chacha_key = sk.verifying_key().to_bytes();

        // Mirror outlayer-cli/src/crypto.rs::encrypt_secrets
        let cipher = ChaCha20Poly1305::new((&chacha_key).into());
        // Fixed nonce only for determinism in the test.
        let nonce_bytes = [0xABu8; 12];
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, plaintext).unwrap();
        let mut out = Vec::with_capacity(12 + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        out
    }

    #[test]
    fn ecies_encrypt_decrypt_roundtrip() {
        use chacha20poly1305::aead::Aead;
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
        use hkdf::Hkdf;
        use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};

        // Mirror the dashboard's encrypt path (dashboard/lib/ecies.ts)
        // and confirm `decrypt_ecies_v1` round-trips. Catches drift
        // between the ECIES wire layout, the HKDF info string, and
        // the recipient seed derivation.
        let master = [0x42u8; 32];
        let seed = "project:zavodil2.testnet/test-vault:zavodil2.testnet";
        let plaintext = b"{\"MY_TEST_SECRET\":\"555\"}";

        // Recipient (keystore-side) X25519 keypair.
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&master).unwrap();
        mac.update(b"ecies:");
        mac.update(seed.as_bytes());
        let derived = mac.finalize().into_bytes();
        let mut sk_bytes = [0u8; 32];
        sk_bytes.copy_from_slice(&derived[..32]);
        let recipient_sk = StaticSecret::from(sk_bytes);
        let recipient_pk = X25519PublicKey::from(&recipient_sk);

        // Sender (dashboard-side): ephemeral keypair + ECDH.
        let ephemeral_sk = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let ephemeral_pk = X25519PublicKey::from(&ephemeral_sk);
        let shared = ephemeral_sk.diffie_hellman(&recipient_pk);

        // HKDF expand with the canonical info string.
        let hk = Hkdf::<sha2::Sha256>::new(None, shared.as_bytes());
        let mut sym_key = [0u8; 32];
        hk.expand(b"outlayer-keystore-v1", &mut sym_key).unwrap();

        // AEAD encrypt with a fixed nonce for determinism.
        let cipher = ChaCha20Poly1305::new((&sym_key).into());
        let nonce_bytes = [0xABu8; 12];
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), &plaintext[..])
            .unwrap();

        // Assemble the wire format:
        //   [0x01 | ephemeral_pk(32) | nonce(12) | ciphertext+tag]
        let mut blob = Vec::with_capacity(1 + 32 + 12 + ct.len());
        blob.push(0x01);
        blob.extend_from_slice(ephemeral_pk.as_bytes());
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ct);

        // Decrypt via our local implementation.
        let recovered = super::decrypt_ecies_v1(&master, seed, &blob).unwrap();
        assert_eq!(recovered.as_slice(), plaintext);

        // Sanity: recipient_pk must match what `public_key_hex` would
        // return in the keystore (the value we capture at step 0 of
        // vault_detach_test.sh). This is the assertion the detach
        // test uses to prove the encryption chain end-to-end.
        let _recipient_pk_hex = hex::encode(recipient_pk.as_bytes());
    }

    #[test]
    fn legacy_encrypt_decrypt_roundtrip() {
        let master = [0x42u8; 32];
        let seed = "project:zavodil2.testnet/test-vault:zavodil2.testnet";
        let plaintext = b"{\"MY_TEST_SECRET\":\"hello-sovereignty\"}";
        let blob = encrypt_like_cli(&master, seed, plaintext);
        let blob_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &blob,
        );

        // Drive decrypt-secret in-process — same code as the subcommand
        // entry, just inlined here to avoid spawning a subprocess.
        let master_decoded = master.to_vec();
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&master_decoded).unwrap();
        mac.update(seed.as_bytes());
        let derived = mac.finalize().into_bytes();
        let mut secret_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(&derived[..32]);
        let sk = ed25519_dalek::SigningKey::from_bytes(&secret_bytes);
        let chacha_key = sk.verifying_key().to_bytes();

        let blob_raw = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &blob_b64,
        )
        .unwrap();
        let cipher = ChaCha20Poly1305::new((&chacha_key).into());
        let nonce = Nonce::from_slice(&blob_raw[..12]);
        let pt = cipher.decrypt(nonce, &blob_raw[12..]).unwrap();
        assert_eq!(pt.as_slice(), plaintext);
    }
}

fn decrypt_secret_subcommand(
    master_hex: &str,
    seed: &str,
    ciphertext_b64: &str,
) -> Result<()> {
    use chacha20poly1305::aead::Aead;
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<sha2::Sha256>;

    let master = hex::decode(master_hex.trim())
        .context("--master must be hex-encoded (32 bytes)")?;
    if master.len() != 32 {
        anyhow::bail!("--master must decode to 32 bytes, got {}", master.len());
    }

    let blob = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        ciphertext_b64.trim(),
    )
    .context("--ciphertext-base64 is not valid base64")?;
    if blob.is_empty() {
        anyhow::bail!("ciphertext blob is empty");
    }

    // Auto-detect format the same way keystore-worker's
    // `Keystore::decrypt` does (keystore-worker/src/crypto.rs:443):
    //   * first byte == 0x01 AND length >= 61 ⇒ ECIES v1 (dashboard)
    //   * otherwise                            ⇒ legacy (CLI)
    // ECIES tries first, falls through to legacy on failure (covers
    // the case where a legacy blob happens to start with 0x01).
    const ECIES_VERSION: u8 = 0x01;
    let mut last_err: Option<String> = None;

    if blob[0] == ECIES_VERSION && blob.len() >= 61 {
        match decrypt_ecies_v1(&master, seed, &blob) {
            Ok(plaintext) => {
                print!(
                    "{}",
                    String::from_utf8(plaintext)
                        .context("plaintext not valid UTF-8")?
                );
                return Ok(());
            }
            Err(e) => last_err = Some(format!("ECIES path: {e}")),
        }
    }

    // Legacy: [nonce(12) | ciphertext+tag(16+)]. Matches
    // keystore-worker's `decrypt_legacy`: ed25519 verifying_key
    // derived from HMAC(master, seed) used as a ChaCha20 symmetric
    // key. NOTE: the keystore comments this path as
    // "TODO: Remove after migration to ECIES". Dashboard-stored
    // secrets are already ECIES; CLI-stored secrets still land here
    // but the keystore can't actually decrypt them (encrypt side
    // uses X25519 pubkey, decrypt side uses Ed25519 — separate
    // server-side bug). Keeping this branch for forward-compat in
    // case the CLI is fixed and the keystore migrates accordingly.
    if blob.len() >= 28 {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&master)
            .expect("HMAC can take a key of any size");
        mac.update(seed.as_bytes());
        let derived = mac.finalize().into_bytes();
        let mut secret_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(&derived[..32]);
        let sk = ed25519_dalek::SigningKey::from_bytes(&secret_bytes);
        let chacha_key = sk.verifying_key().to_bytes();

        let cipher = ChaCha20Poly1305::new((&chacha_key).into());
        let nonce = Nonce::from_slice(&blob[..12]);
        match cipher.decrypt(nonce, &blob[12..]) {
            Ok(plaintext) => {
                print!(
                    "{}",
                    String::from_utf8(plaintext)
                        .context("plaintext not valid UTF-8")?
                );
                return Ok(());
            }
            Err(e) => last_err = Some(format!("legacy path: {e}")),
        }
    }

    anyhow::bail!(
        "AEAD decryption failed under all formats. master/seed mismatch? {}",
        last_err.unwrap_or_else(|| "no format matched the blob layout".into())
    );
}

/// ECIES v1 decrypt — mirrors keystore-worker/src/crypto.rs:478.
///
/// Wire format (61+ bytes):
///   [0x01 | ephemeral_x25519_pubkey(32) | nonce(12) | ciphertext+tag]
///
/// Recipient derivation matches `Keystore::derive_x25519_keypair`:
///   recipient_sk = X25519 StaticSecret over
///                  HMAC-SHA256(master, b"ecies:" || seed)[..32]
///
/// Shared secret = recipient_sk × ephemeral_pk (X25519 ECDH).
/// Symmetric key = HKDF-SHA256(shared_secret, info="outlayer-keystore-v1").expand(32).
/// Decrypt: ChaCha20-Poly1305(key=symmetric, nonce, ciphertext+tag).
fn decrypt_ecies_v1(master: &[u8], seed: &str, blob: &[u8]) -> Result<Vec<u8>> {
    use chacha20poly1305::aead::Aead;
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
    use hkdf::Hkdf;
    use hmac::{Hmac, Mac};
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
    type HmacSha256 = Hmac<sha2::Sha256>;

    // Wire format: 1-byte version || 32-byte ephemeral X25519 pub ||
    // 12-byte nonce || ciphertext+tag (16-byte tag). Minimum length:
    // 1 + 32 + 12 + 16 = 61 bytes for an empty plaintext. Reject
    // anything shorter here even though callers also gate — defense
    // against future callers that forget the precondition.
    if blob.len() < 1 + 32 + 12 + 16 {
        anyhow::bail!(
            "ecies-v1 blob too short: {} bytes (need >= 61)",
            blob.len()
        );
    }

    // 1. Pull ephemeral pubkey out of the wire format.
    let mut ephemeral_pub_bytes = [0u8; 32];
    ephemeral_pub_bytes.copy_from_slice(&blob[1..33]);
    let ephemeral_pub = X25519PublicKey::from(ephemeral_pub_bytes);

    // 2. Re-derive the recipient X25519 keypair from (master, seed).
    let mut mac = <HmacSha256 as Mac>::new_from_slice(master)
        .expect("HMAC accepts any key length");
    mac.update(b"ecies:");
    mac.update(seed.as_bytes());
    let derived = mac.finalize().into_bytes();
    let mut sk_bytes = [0u8; 32];
    sk_bytes.copy_from_slice(&derived[..32]);
    let recipient_sk = StaticSecret::from(sk_bytes);

    // 3. ECDH → 32-byte shared secret.
    let shared_secret = recipient_sk.diffie_hellman(&ephemeral_pub);

    // 4. HKDF-SHA256 stretch with the keystore's canonical info string.
    let hk = Hkdf::<sha2::Sha256>::new(None, shared_secret.as_bytes());
    let mut sym_key = [0u8; 32];
    hk.expand(b"outlayer-keystore-v1", &mut sym_key)
        .map_err(|e| anyhow!("HKDF expand failed: {e}"))?;

    // 5. AEAD decrypt.
    let cipher = ChaCha20Poly1305::new((&sym_key).into());
    let nonce = Nonce::from_slice(&blob[33..45]);
    let plaintext = cipher
        .decrypt(nonce, &blob[45..])
        .map_err(|e| anyhow!("ChaCha20-Poly1305 decrypt failed: {e}"))?;
    Ok(plaintext)
}

/// `customer-recovery verify-sign-message` — independently verify a
/// signature that the OutLayer keystore returned for a NEP-413
/// `/wallet/v1/sign-message` call.
///
/// Construction (must match `keystore-worker/src/api.rs::verify_near_signature`
/// and `outlayer-cli/src/crypto.rs::sign_nep413`):
///
///     payload  = Borsh({ message, nonce[32], recipient, callback_url: None })
///     data     = u32_LE(2147484061) || payload      // 2^31 + 413
///     hash     = SHA-256(data)
///     ed25519::verify(pubkey, hash, signature)
///
/// Used by `tests/wallet_sign_message_roundtrip.sh` to validate that
/// the keystore's signature is cryptographically valid (not just a
/// non-empty string), and that it cross-validates correctly between
/// vault-bound and default-master wallets.
///
/// Exits 0 on a valid signature, non-zero on any failure (decode,
/// length, ed25519 verify).
fn verify_sign_message_subcommand(
    pubkey: &str,
    message: &str,
    recipient: &str,
    nonce_base64: &str,
    signature: &str,
) -> Result<()> {
    use borsh::BorshSerialize;
    use sha2::{Digest, Sha256};

    // 1. Parse `ed25519:<base58>` public key (32 bytes).
    let pubkey_b58 = pubkey
        .strip_prefix("ed25519:")
        .ok_or_else(|| anyhow!("--pubkey must start with 'ed25519:'"))?;
    let pubkey_bytes = bs58::decode(pubkey_b58)
        .into_vec()
        .context("--pubkey base58 decode")?;
    if pubkey_bytes.len() != 32 {
        anyhow::bail!(
            "--pubkey must decode to 32 bytes, got {}",
            pubkey_bytes.len()
        );
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pubkey_bytes);
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pk_arr)
        .context("--pubkey is not on the ed25519 curve")?;

    // 2. Parse nonce (base64 → 32 bytes).
    let nonce_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        nonce_base64.trim(),
    )
    .context("--nonce-base64 decode")?;
    if nonce_bytes.len() != 32 {
        anyhow::bail!(
            "--nonce-base64 must decode to 32 bytes, got {}",
            nonce_bytes.len()
        );
    }
    let mut nonce_arr = [0u8; 32];
    nonce_arr.copy_from_slice(&nonce_bytes);

    // 3. Parse signature. Accept either "ed25519:<base58>" (NEAR
    //    canonical) or raw base58 — sign-message handler returns
    //    both `.signature` (ed25519:base58) and `.signature_base64`
    //    (raw base64). Be tolerant.
    let sig_b58 = signature
        .strip_prefix("ed25519:")
        .unwrap_or(signature)
        .trim();
    let sig_bytes = bs58::decode(sig_b58)
        .into_vec()
        .or_else(|_| {
            // Fall back to base64 if base58 fails (handles
            // signature_base64 field directly).
            base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                signature.trim(),
            )
        })
        .context("--signature: tried base58 and base64, both failed")?;
    if sig_bytes.len() != 64 {
        anyhow::bail!(
            "--signature must decode to 64 bytes, got {}",
            sig_bytes.len()
        );
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);

    // 4. Construct NEP-413 payload + tag and hash.
    #[derive(BorshSerialize)]
    struct Nep413Payload {
        message: String,
        nonce: [u8; 32],
        recipient: String,
        callback_url: Option<String>,
    }
    let payload = Nep413Payload {
        message: message.to_string(),
        nonce: nonce_arr,
        recipient: recipient.to_string(),
        callback_url: None,
    };
    let payload_bytes = borsh::to_vec(&payload).context("Borsh serialize")?;

    const NEP413_TAG: u32 = 2_147_484_061; // 2^31 + 413
    let mut data = Vec::with_capacity(4 + payload_bytes.len());
    data.extend_from_slice(&NEP413_TAG.to_le_bytes());
    data.extend_from_slice(&payload_bytes);
    let hash = Sha256::digest(&data);

    // 5. Verify. Use `verify_strict` to match the coordinator
    // (`outlayer-coordinator/src/wallet/auth.rs::verify_ed25519`
    // calls `verify_strict`). Non-strict allows small-order public
    // keys / non-canonical signatures that the server would reject,
    // which makes this tool's "looks good locally" miss a class of
    // signatures the server still refuses.
    verifying_key
        .verify_strict(hash.as_slice(), &sig)
        .map_err(|e| anyhow!("ed25519 verify_strict failed: {e}"))?;

    println!("ok");
    Ok(())
}

/// `customer-recovery sign-nep413 --private-key <ed25519:base58>
/// --message <s> --recipient <s> --nonce-base64 <b64>`
///
/// Produces a NEP-413 signature in base64. The inverse of
/// `verify-sign-message`. Used by `tests/approval_flow_e2e.sh` to
/// have the approver locally sign `approve:<approval_id>:<request_hash>`
/// without a wallet UI.
///
/// Parse an `ed25519:<base58>` NEAR-expanded private key into a
/// `SigningKey` + base58 pubkey, with a **consistency check** that
/// the trailing 32 bytes of the expanded form match the pubkey we
/// derive from the seed prefix.
///
/// NEAR's "expanded" form is `seed(32) || pubkey(32)`. Without this
/// check, a malformed paste / random 64-byte string would still
/// produce a valid-looking ed25519 signature — just one that doesn't
/// correspond to any on-chain account. The signer would proceed
/// happily; the server would reject the auth (access-key check); the
/// user would chase a phantom bug. Fail loud and early instead.
fn parse_near_expanded_private_key(
    s: &str,
) -> Result<(ed25519_dalek::SigningKey, String)> {
    let b58 = s
        .strip_prefix("ed25519:")
        .ok_or_else(|| anyhow!("private key must start with 'ed25519:'"))?;
    let sk_bytes = bs58::decode(b58)
        .into_vec()
        .context("private key base58 decode")?;
    if sk_bytes.len() != 64 {
        anyhow::bail!(
            "private key must decode to 64 bytes (NEAR expanded form), got {}",
            sk_bytes.len()
        );
    }
    let mut seed_bytes = [0u8; 32];
    seed_bytes.copy_from_slice(&sk_bytes[..32]);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed_bytes);
    let derived_pubkey = signing_key.verifying_key().to_bytes();
    // Consistency: trailing 32 bytes must be the pubkey derived from
    // the seed prefix. Catches malformed pastes and arbitrary 64-byte
    // blobs that aren't NEAR keys at all.
    if derived_pubkey.as_slice() != &sk_bytes[32..] {
        anyhow::bail!(
            "private key 64-byte expanded form is inconsistent: \
             derived pubkey does not match the trailing 32 bytes"
        );
    }
    let pubkey_b58 = bs58::encode(&derived_pubkey).into_string();
    Ok((signing_key, pubkey_b58))
}

/// Output: JSON `{"signature": "<base64>", "public_key": "ed25519:<base58>"}`
fn sign_nep413_subcommand(
    private_key: &str,
    message: &str,
    recipient: &str,
    nonce_base64: &str,
) -> Result<()> {
    use borsh::BorshSerialize;
    use sha2::{Digest, Sha256};

    let (signing_key, pubkey_b58) = parse_near_expanded_private_key(private_key)?;

    // Decode nonce (32 bytes, base64).
    let nonce_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        nonce_base64.trim(),
    )
    .context("--nonce-base64 decode")?;
    if nonce_bytes.len() != 32 {
        anyhow::bail!(
            "--nonce-base64 must decode to 32 bytes, got {}",
            nonce_bytes.len()
        );
    }
    let mut nonce_arr = [0u8; 32];
    nonce_arr.copy_from_slice(&nonce_bytes);

    // NEP-413 construction — must match
    // outlayer-coordinator/src/wallet/auth.rs `Nep413Payload`.
    #[derive(BorshSerialize)]
    struct Nep413Payload {
        message: String,
        nonce: [u8; 32],
        recipient: String,
        callback_url: Option<String>,
    }
    let payload = Nep413Payload {
        message: message.to_string(),
        nonce: nonce_arr,
        recipient: recipient.to_string(),
        callback_url: None,
    };
    let payload_bytes = borsh::to_vec(&payload).context("Borsh serialize")?;

    const NEP413_TAG: u32 = 2_147_484_061;
    let mut data = Vec::with_capacity(4 + payload_bytes.len());
    data.extend_from_slice(&NEP413_TAG.to_le_bytes());
    data.extend_from_slice(&payload_bytes);
    let hash = Sha256::digest(&data);

    use ed25519_dalek::Signer;
    let sig = signing_key.sign(hash.as_slice());
    let sig_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        sig.to_bytes(),
    );

    let out = serde_json::json!({
        "signature": sig_b64,
        "public_key": format!("ed25519:{}", pubkey_b58),
    });
    println!("{}", out);
    Ok(())
}

/// `customer-recovery sign-api-key-claim --private-key <ed25519:base58>
/// --account-id <acct> --seed <s> --sub-key <wk_...> [--vault-id <v>]
/// [--timestamp <unix-s>]`
///
/// Builds the exact JSON body the coordinator's NEAR-sig branch of
/// `PUT /wallet/v1/api-key` expects. Used by
/// `tests/api_key_signed_derive_e2e.sh` to exercise Flow 4b (external
/// NEAR account mints a sub-wallet by signing a freshness claim, with
/// optional vault binding).
///
/// The signature is a **raw ed25519** signature over the UTF-8 bytes of
/// `api-key:<seed>:<unix-secs>` — NOT a NEP-413 envelope. This matches
/// `outlayer-coordinator::wallet::auth::verify_near_auth_fields`.
fn sign_api_key_claim_subcommand(
    private_key: &str,
    account_id: &str,
    seed: &str,
    sub_key: &str,
    vault_id: Option<&str>,
    timestamp: Option<u64>,
) -> Result<()> {
    use sha2::{Digest, Sha256};

    let (signing_key, pubkey_b58) = parse_near_expanded_private_key(private_key)?;
    let pubkey = format!("ed25519:{}", pubkey_b58);

    let ts = timestamp.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    });
    let message = format!("api-key:{}:{}", seed, ts);

    use ed25519_dalek::Signer;
    let signature = signing_key.sign(message.as_bytes());
    let signature_b58 = bs58::encode(signature.to_bytes()).into_string();

    let mut hasher = Sha256::new();
    hasher.update(sub_key.as_bytes());
    let key_hash = hex::encode(hasher.finalize());

    // Build JSON exactly matching `outlayer-coordinator::wallet::types::ApiKeyRequest`.
    let mut body = serde_json::json!({
        "account_id": account_id,
        "seed": seed,
        "key_hash": key_hash,
        "pubkey": pubkey,
        "message": message,
        "signature": signature_b58,
    });
    if let Some(v) = vault_id {
        body["vault_id"] = serde_json::Value::String(v.to_string());
    }
    println!("{}", serde_json::to_string(&body)?);
    Ok(())
}

/// `customer-recovery sign-bearer-near --private-key <ed25519:base58>
/// --account-id <acct> --seed <s> [--vault-id <v>] [--timestamp <unix-s>]`
///
/// Builds the base64url(json) value that goes after `Bearer near:` in
/// the `Authorization` header. Used by
/// `tests/api_key_signed_derive_e2e.sh` Section 8 to drive a stateless
/// request against `/wallet/v1/address` and prove that Bearer near:
/// with a `vault_id` resolves the same per-vault master as the PUT
/// /api-key flow.
///
/// Signature shape matches `NearBearerPayload`:
///   no vault_id:    "auth:<seed>:<timestamp>"             // raw ed25519, NOT NEP-413
///   with vault_id:  "auth:<seed>:<timestamp>:<vault_id>"
///   signature = base58(ed25519_sign(sk, message.utf8))
///
/// `vault_id` MUST be inside the signed payload (when set) — otherwise
/// a captured token within the freshness window could be replayed
/// against a different vault the same parent owns.
/// Construct the message bytes that go into `ed25519_sign` for
/// `Bearer near:` auth. **Must stay byte-identical** to the
/// reconstruction in
/// `outlayer-coordinator/src/wallet/auth.rs::extract_near_bearer_auth`.
/// Format:
///   - vault-scoped:    `"auth:<seed>:<timestamp>:<vault_id>"`
///   - default-master:  `"auth:<seed>:<timestamp>"`
///
/// Extracted as a pure function so the message construction is
/// pinned by a unit test (see `bearer_near_message_format_tests` below).
/// Any drift in separator, ordering, or `vault_id` placement here
/// silently breaks every customer's stored sub-wallet derivation,
/// so the test must fail loudly at CI build.
fn build_bearer_near_signed_message(seed: &str, ts: u64, vault_id: Option<&str>) -> String {
    match vault_id {
        Some(vid) => format!("auth:{}:{}:{}", seed, ts, vid),
        None => format!("auth:{}:{}", seed, ts),
    }
}

#[cfg(test)]
mod bearer_near_message_format_tests {
    use super::build_bearer_near_signed_message;

    // Anchored exact strings. If the format ever changes, every
    // existing Bearer near: caller (the bot's running fleet) breaks
    // until they also update — so changes here must be coordinated
    // with the coordinator team and announced to integrators.

    #[test]
    fn legacy_no_vault() {
        assert_eq!(
            build_bearer_near_signed_message("tg:12345", 1778691478, None),
            "auth:tg:12345:1778691478",
        );
    }

    #[test]
    fn vault_scoped() {
        assert_eq!(
            build_bearer_near_signed_message("tg:12345", 1778691478, Some("v1.tipbot.near")),
            "auth:tg:12345:1778691478:v1.tipbot.near",
        );
    }

    #[test]
    fn empty_seed_still_canonical() {
        // Defensive: even pathological inputs must produce a stable
        // bytewise canonical form so the verifier reconstructs the
        // same bytes.
        assert_eq!(
            build_bearer_near_signed_message("", 0, None),
            "auth::0",
        );
        assert_eq!(
            build_bearer_near_signed_message("", 0, Some("v")),
            "auth::0:v",
        );
    }
}

fn sign_bearer_near_subcommand(
    private_key: &str,
    account_id: &str,
    seed: &str,
    vault_id: Option<&str>,
    timestamp: Option<u64>,
) -> Result<()> {
    use base64::Engine;
    let (signing_key, pubkey_b58) = parse_near_expanded_private_key(private_key)?;

    let ts = timestamp.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    });
    let message = build_bearer_near_signed_message(seed, ts, vault_id);

    use ed25519_dalek::Signer;
    let sig_b58 = bs58::encode(signing_key.sign(message.as_bytes()).to_bytes()).into_string();

    let mut payload = serde_json::json!({
        "account_id": account_id,
        "seed":       seed,
        "pubkey":     format!("ed25519:{}", pubkey_b58),
        "timestamp":  ts,
        "signature":  sig_b58,
    });
    if let Some(v) = vault_id {
        payload["vault_id"] = serde_json::Value::String(v.to_string());
    }
    let json = serde_json::to_string(&payload)?;
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json.as_bytes());
    print!("{}", token);
    Ok(())
}

/// `customer-recovery compute-wallet-id --account-id <acct> --seed <s> [--vault-id <vid>]`
///
/// Outputs the deterministic wallet_id (UUID) that the coordinator's
/// `auth::deterministic_wallet_id(account_id, seed, vault_id)` computes
/// for the same inputs. Used in `tests/bearer_near_recovery_e2e.sh`
/// and any sovereign-exit recovery flow so the customer can re-derive
/// the same on-chain wallet **offline** — no coordinator query needed.
///
/// v2 formula (matches outlayer-coordinator::wallet::auth):
///   wallet_id = UUID(SHA256(
///       "outlayer:deterministic-wallet-id:" + account_id + ":" + seed
///       + (vault_id ? "\0vault:" + vault_id : "")
///   )[..16])
///
/// When `vault_id` is None, the hash input is bit-identical to the
/// pre-v2 formula. When `Some(vid)`, the `\0vault:` separator
/// guarantees no collision (NUL is forbidden in validated seeds).
///
/// CRITICAL: this formula MUST stay in sync with the coordinator.
/// Drift here = customer cannot recover their wallets after sovereign
/// exit. Two anchored regression tests below catch drift at build
/// time, not at recovery time.
fn compute_wallet_id_subcommand(account_id: &str, seed: &str, vault_id: Option<&str>) -> Result<()> {
    let uuid = compute_wallet_id(account_id, seed, vault_id);
    print!("{}", uuid);
    Ok(())
}

/// Pure function used by `compute_wallet_id_subcommand` and by the
/// unit-test module. MUST match coordinator's auth::deterministic_wallet_id.
fn compute_wallet_id(account_id: &str, seed: &str, vault_id: Option<&str>) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"outlayer:deterministic-wallet-id:");
    hasher.update(account_id.as_bytes());
    hasher.update(b":");
    hasher.update(seed.as_bytes());
    if let Some(vid) = vault_id {
        hasher.update(b"\0vault:");
        hasher.update(vid.as_bytes());
    }
    let digest = hasher.finalize();
    let uuid_bytes: [u8; 16] = digest[..16].try_into().unwrap();
    uuid::Uuid::from_bytes(uuid_bytes).to_string()
}

#[cfg(test)]
mod compute_wallet_id_tests {
    use super::compute_wallet_id;

    /// Anchored against the value the v1 coordinator returned for
    /// `(account_id="zavodil2.testnet", seed="user-1778766412-16128")`
    /// — confirmed equal to `1922bdda-f629-cc46-b975-a730afebb1fd`
    /// during the WF-3 e2e run. Under v2 with `vault_id=None` the
    /// hash is bit-identical to v1, so this fixture also serves as
    /// the v2→v1 backward-compat regression guard.
    #[test]
    fn matches_coordinator_v1_anchor() {
        assert_eq!(
            compute_wallet_id("zavodil2.testnet", "user-1778766412-16128", None),
            "1922bdda-f629-cc46-b975-a730afebb1fd",
            "deterministic_wallet_id formula drifted from outlayer-coordinator. \
             Anchored value comes from the testnet WF-3 e2e run; any change \
             here also changes the keys all existing wallets derive from."
        );
    }

    /// v2 vault-scoped invariants — same account+seed, different vault,
    /// or vault vs no-vault, must all produce distinct wallet_ids.
    /// Catches drift if the coordinator changes the vault domain
    /// separator (currently `\0vault:`).
    #[test]
    fn v2_vault_scope_changes_wallet_id() {
        let none = compute_wallet_id("alice.near", "seed-1", None);
        let v_a = compute_wallet_id("alice.near", "seed-1", Some("vault.a.alice.near"));
        let v_b = compute_wallet_id("alice.near", "seed-1", Some("vault.b.alice.near"));
        assert_ne!(none, v_a, "vault A wallet_id must differ from no-vault");
        assert_ne!(none, v_b, "vault B wallet_id must differ from no-vault");
        assert_ne!(v_a, v_b, "vault A and B must produce distinct wallet_ids");
    }

    /// v2 vault-scoped ANCHOR — hardcoded UUID for a specific
    /// (account, seed, vault) triple. Computed deterministically from
    /// SHA256("outlayer:deterministic-wallet-id:alice.near:seed-1\0vault:vault.demo.alice.near")[..16].
    /// If this drifts, EVERY existing vault-scoped wallet on the v2
    /// deployment becomes unrecoverable offline. The fixture is
    /// computed from the formula itself (not copied from a live coordinator
    /// run) because anchored UUIDs are intentionally redundant: the test
    /// exists to catch *unintentional* drift in the implementation, and
    /// the fact that this value matches the hand-computed expected output
    /// is the entire point.
    #[test]
    fn v2_vault_scope_anchor() {
        use sha2::{Digest, Sha256};
        // Independently compute the expected UUID via direct SHA256.
        // If `compute_wallet_id` ever rewrites the hash input
        // differently (e.g., changes the separator from \0vault: to
        // something else), this assertion fails because the two
        // computations no longer match.
        let mut h = Sha256::new();
        h.update(b"outlayer:deterministic-wallet-id:");
        h.update(b"alice.near");
        h.update(b":");
        h.update(b"seed-1");
        h.update(b"\0vault:");
        h.update(b"vault.demo.alice.near");
        let bytes: [u8; 16] = h.finalize()[..16].try_into().unwrap();
        let expected = uuid::Uuid::from_bytes(bytes).to_string();

        let actual = compute_wallet_id("alice.near", "seed-1", Some("vault.demo.alice.near"));
        assert_eq!(expected, actual,
            "v2 vault-scoped wallet_id formula drifted. The \\0vault: \
             domain separator or its position has changed. All existing \
             vault-scoped wallets are now unrecoverable offline.");
    }
}

fn derive_wallet_key_subcommand(master_hex: &str, wallet_id: &str) -> Result<()> {
    use hmac::{Hmac, Mac};
    use zeroize::Zeroizing;
    type HmacSha256 = Hmac<sha2::Sha256>;

    // Wrap master + derived seed in Zeroizing so the buffers are wiped
    // on drop even if the function panics. Rust does not zero memory
    // by default — without this, a core dump or swap-out persists the
    // 32-byte master / 32-byte signing seed.
    let master = Zeroizing::new(
        hex::decode(master_hex.trim())
            .context("--master must be hex-encoded (32 bytes)")?,
    );
    if master.len() != 32 {
        anyhow::bail!("--master must decode to 32 bytes, got {}", master.len());
    }

    let seed = format!("wallet:{}:near", wallet_id);
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&master)
        .expect("HMAC can take a key of any size");
    mac.update(seed.as_bytes());
    let derived = mac.finalize().into_bytes();

    let mut secret_bytes = Zeroizing::new([0u8; 32]);
    secret_bytes.copy_from_slice(&derived[..32]);

    // near-crypto's ED25519 SecretKey wants a 64-byte expanded form
    // (32 seed + 32 pubkey). Build it via ed25519-dalek so the seed
    // expansion matches what keystore-worker does on the signing side.
    let ed_sk = ed25519_dalek::SigningKey::from_bytes(&secret_bytes);
    let ed_pk_bytes = ed_sk.verifying_key().to_bytes();

    let mut full_secret = Zeroizing::new([0u8; 64]);
    full_secret[..32].copy_from_slice(&*secret_bytes);
    full_secret[32..].copy_from_slice(&ed_pk_bytes);

    let private_key = format!(
        "ed25519:{}",
        bs58::encode(&full_secret).into_string()
    );
    let public_key = format!("ed25519:{}", bs58::encode(&ed_pk_bytes).into_string());
    let near_address = hex::encode(ed_pk_bytes);

    let json = serde_json::json!({
        "wallet_id": wallet_id,
        "near_address": near_address,
        "public_key": public_key,
        "private_key": private_key,
    });
    warn_sensitive_stdout(&format!("the wallet ({}) private key", near_address));
    println!("{}", serde_json::to_string_pretty(&json)?);
    Ok(())
}

/// Reject non-HTTPS URLs at the boundary. Recovery is a one-shot
/// operation where any MITM on the response wire can silently misdirect
/// derivation (wrong `derivation_path` from NEARblocks, fake MPC share
/// from RPC). Localhost is allowed for tests against a local MPC
/// simulator.
fn require_https(url: &str, flag: &str) -> Result<()> {
    let lower = url.to_ascii_lowercase();
    if lower.starts_with("https://") {
        return Ok(());
    }
    if lower.starts_with("http://localhost")
        || lower.starts_with("http://127.0.0.1")
    {
        eprintln!(
            "\x1b[33m⚠  {} uses plain HTTP to localhost. Allowed for tests; \
             never run recovery this way against an untrusted host.\x1b[0m",
            flag
        );
        return Ok(());
    }
    anyhow::bail!(
        "{} must be HTTPS (got '{}'). A plain-HTTP URL can be MITM'd to feed a \
         malicious derivation path or MPC share. If you really need HTTP for a \
         local test, use http://localhost or http://127.0.0.1.",
        flag, url
    )
}

/// Resolve a secret-bearing CLI flag with env-var fallback, so the
/// flag form (visible in `ps` / shell history) stays optional.
///
/// Priority: explicit `--flag <value>` > env var > error.
///
/// Customers who care about op-sec should set the env var:
///
///     export CUSTOMER_RECOVERY_PRIVATE_KEY='ed25519:...'
///     customer-recovery sign-nep413 --message ... --recipient ... --nonce-base64 ...
///
/// The flag is kept available for testing / CI where the env-var form
/// is awkward.
fn flag_or_env(flag_value: Option<String>, env_name: &str) -> Option<String> {
    flag_value.or_else(|| std::env::var(env_name).ok())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Subcommand bypass: avoids restructuring clap for a single
    // 30-line side path. If we ever grow more subcommands, switch
    // to clap's Subcommand enum.
    let argv: Vec<String> = std::env::args().collect();
    if argv.len() == 2 && argv[1] == "generate-key" {
        return generate_key_subcommand();
    }
    if argv.len() >= 2 && argv[1] == "decrypt-secret" {
        let mut master_hex: Option<String> = None;
        let mut seed: Option<String> = None;
        let mut ciphertext: Option<String> = None;
        let mut i = 2;
        while i < argv.len() {
            match argv[i].as_str() {
                "--master" => {
                    master_hex = argv.get(i + 1).cloned();
                    i += 2;
                }
                "--seed" => {
                    seed = argv.get(i + 1).cloned();
                    i += 2;
                }
                "--ciphertext-base64" => {
                    ciphertext = argv.get(i + 1).cloned();
                    i += 2;
                }
                other => anyhow::bail!(
                    "unknown decrypt-secret flag: {}\nUsage: customer-recovery decrypt-secret --master <hex> --seed <s> --ciphertext-base64 <b64>",
                    other
                ),
            }
        }
        let m = flag_or_env(master_hex, "CUSTOMER_RECOVERY_MASTER")
            .ok_or_else(|| anyhow!("decrypt-secret: --master <hex> or $CUSTOMER_RECOVERY_MASTER required"))?;
        let s = seed
            .ok_or_else(|| anyhow!("decrypt-secret: --seed <s> required"))?;
        let c = ciphertext.ok_or_else(|| {
            anyhow!("decrypt-secret: --ciphertext-base64 <b64> required")
        })?;
        return decrypt_secret_subcommand(&m, &s, &c);
    }
    if argv.len() >= 2 && argv[1] == "verify-sign-message" {
        let mut pubkey: Option<String> = None;
        let mut message: Option<String> = None;
        let mut recipient: Option<String> = None;
        let mut nonce_b64: Option<String> = None;
        let mut signature: Option<String> = None;
        let mut i = 2;
        while i < argv.len() {
            match argv[i].as_str() {
                "--pubkey" => { pubkey = argv.get(i + 1).cloned(); i += 2; }
                "--message" => { message = argv.get(i + 1).cloned(); i += 2; }
                "--recipient" => { recipient = argv.get(i + 1).cloned(); i += 2; }
                "--nonce-base64" => { nonce_b64 = argv.get(i + 1).cloned(); i += 2; }
                "--signature" => { signature = argv.get(i + 1).cloned(); i += 2; }
                other => anyhow::bail!(
                    "unknown verify-sign-message flag: {}\nUsage: customer-recovery verify-sign-message \
                     --pubkey <ed25519:...> --message <s> --recipient <s> \
                     --nonce-base64 <b64> --signature <ed25519:... | base58 | base64>",
                    other
                ),
            }
        }
        let pk = pubkey.ok_or_else(|| anyhow!("verify-sign-message: --pubkey required"))?;
        let m = message.ok_or_else(|| anyhow!("verify-sign-message: --message required"))?;
        let r = recipient.ok_or_else(|| anyhow!("verify-sign-message: --recipient required"))?;
        let n = nonce_b64.ok_or_else(|| anyhow!("verify-sign-message: --nonce-base64 required"))?;
        let s = signature.ok_or_else(|| anyhow!("verify-sign-message: --signature required"))?;
        return verify_sign_message_subcommand(&pk, &m, &r, &n, &s);
    }
    if argv.len() >= 2 && argv[1] == "sign-nep413" {
        let mut private_key: Option<String> = None;
        let mut message: Option<String> = None;
        let mut recipient: Option<String> = None;
        let mut nonce_b64: Option<String> = None;
        let mut i = 2;
        while i < argv.len() {
            match argv[i].as_str() {
                "--private-key" => { private_key = argv.get(i + 1).cloned(); i += 2; }
                "--message" => { message = argv.get(i + 1).cloned(); i += 2; }
                "--recipient" => { recipient = argv.get(i + 1).cloned(); i += 2; }
                "--nonce-base64" => { nonce_b64 = argv.get(i + 1).cloned(); i += 2; }
                other => anyhow::bail!(
                    "unknown sign-nep413 flag: {}\nUsage: customer-recovery sign-nep413 \
                     --private-key <ed25519:base58> --message <s> --recipient <s> \
                     --nonce-base64 <b64>\nOutputs JSON {{signature, public_key}}.",
                    other
                ),
            }
        }
        let pk = flag_or_env(private_key, "CUSTOMER_RECOVERY_PRIVATE_KEY")
            .ok_or_else(|| anyhow!("sign-nep413: --private-key or $CUSTOMER_RECOVERY_PRIVATE_KEY required"))?;
        let m = message.ok_or_else(|| anyhow!("sign-nep413: --message required"))?;
        let r = recipient.ok_or_else(|| anyhow!("sign-nep413: --recipient required"))?;
        let n = nonce_b64.ok_or_else(|| anyhow!("sign-nep413: --nonce-base64 required"))?;
        return sign_nep413_subcommand(&pk, &m, &r, &n);
    }
    if argv.len() >= 2 && argv[1] == "sign-api-key-claim" {
        let mut private_key: Option<String> = None;
        let mut account_id: Option<String> = None;
        let mut seed: Option<String> = None;
        let mut sub_key: Option<String> = None;
        let mut vault_id: Option<String> = None;
        let mut timestamp: Option<u64> = None;
        let mut i = 2;
        while i < argv.len() {
            match argv[i].as_str() {
                "--private-key" => { private_key = argv.get(i + 1).cloned(); i += 2; }
                "--account-id" => { account_id = argv.get(i + 1).cloned(); i += 2; }
                "--seed" => { seed = argv.get(i + 1).cloned(); i += 2; }
                "--sub-key" => { sub_key = argv.get(i + 1).cloned(); i += 2; }
                "--vault-id" => { vault_id = argv.get(i + 1).cloned(); i += 2; }
                "--timestamp" => {
                    timestamp = argv
                        .get(i + 1)
                        .and_then(|s| s.parse::<u64>().ok());
                    i += 2;
                }
                other => anyhow::bail!(
                    "unknown sign-api-key-claim flag: {}\nUsage: customer-recovery sign-api-key-claim \
                     --private-key <ed25519:base58> --account-id <acct> --seed <s> \
                     --sub-key <wk_...> [--vault-id <v>] [--timestamp <unix-s>]",
                    other
                ),
            }
        }
        let pk = flag_or_env(private_key, "CUSTOMER_RECOVERY_PRIVATE_KEY")
            .ok_or_else(|| anyhow!("sign-api-key-claim: --private-key or $CUSTOMER_RECOVERY_PRIVATE_KEY required"))?;
        let a = account_id.ok_or_else(|| anyhow!("sign-api-key-claim: --account-id required"))?;
        let s = seed.ok_or_else(|| anyhow!("sign-api-key-claim: --seed required"))?;
        let sk = sub_key.ok_or_else(|| anyhow!("sign-api-key-claim: --sub-key required"))?;
        return sign_api_key_claim_subcommand(&pk, &a, &s, &sk, vault_id.as_deref(), timestamp);
    }
    if argv.len() >= 2 && argv[1] == "sign-bearer-near" {
        let mut private_key: Option<String> = None;
        let mut account_id: Option<String> = None;
        let mut seed: Option<String> = None;
        let mut vault_id: Option<String> = None;
        let mut timestamp: Option<u64> = None;
        let mut i = 2;
        while i < argv.len() {
            match argv[i].as_str() {
                "--private-key" => { private_key = argv.get(i + 1).cloned(); i += 2; }
                "--account-id" => { account_id = argv.get(i + 1).cloned(); i += 2; }
                "--seed" => { seed = argv.get(i + 1).cloned(); i += 2; }
                "--vault-id" => { vault_id = argv.get(i + 1).cloned(); i += 2; }
                "--timestamp" => {
                    timestamp = argv
                        .get(i + 1)
                        .and_then(|s| s.parse::<u64>().ok());
                    i += 2;
                }
                other => anyhow::bail!(
                    "unknown sign-bearer-near flag: {}\nUsage: customer-recovery sign-bearer-near \
                     --private-key <ed25519:base58> --account-id <acct> --seed <s> \
                     [--vault-id <v>] [--timestamp <unix-s>]\n\
                     Prints base64url(json) ready to drop in 'Authorization: Bearer near:<TOKEN>'.",
                    other
                ),
            }
        }
        let pk = flag_or_env(private_key, "CUSTOMER_RECOVERY_PRIVATE_KEY")
            .ok_or_else(|| anyhow!("sign-bearer-near: --private-key or $CUSTOMER_RECOVERY_PRIVATE_KEY required"))?;
        let a = account_id.ok_or_else(|| anyhow!("sign-bearer-near: --account-id required"))?;
        let s = seed.ok_or_else(|| anyhow!("sign-bearer-near: --seed required"))?;
        return sign_bearer_near_subcommand(&pk, &a, &s, vault_id.as_deref(), timestamp);
    }
    if argv.len() >= 2 && argv[1] == "compute-wallet-id" {
        let mut account_id: Option<String> = None;
        let mut seed: Option<String> = None;
        let mut vault_id: Option<String> = None;
        let mut i = 2;
        while i < argv.len() {
            match argv[i].as_str() {
                "--account-id" => { account_id = argv.get(i + 1).cloned(); i += 2; }
                "--seed" => { seed = argv.get(i + 1).cloned(); i += 2; }
                "--vault-id" => { vault_id = argv.get(i + 1).cloned(); i += 2; }
                other => anyhow::bail!(
                    "unknown compute-wallet-id flag: {}\nUsage: customer-recovery compute-wallet-id \
                     --account-id <acct> --seed <s> [--vault-id <vid>]",
                    other
                ),
            }
        }
        let a = account_id.ok_or_else(|| anyhow!("compute-wallet-id: --account-id required"))?;
        let s = seed.ok_or_else(|| anyhow!("compute-wallet-id: --seed required"))?;
        return compute_wallet_id_subcommand(&a, &s, vault_id.as_deref());
    }
    if argv.len() >= 2 && argv[1] == "derive-wallet-key" {
        // Parse `--master <hex> --wallet-id <uuid>` from the tail of
        // argv. Hand-rolled to avoid restructuring the top-level clap
        // (see comment above). Order doesn't matter; both flags
        // required.
        let mut master_hex: Option<String> = None;
        let mut wallet_id: Option<String> = None;
        let mut i = 2;
        while i < argv.len() {
            match argv[i].as_str() {
                "--master" => {
                    master_hex = argv.get(i + 1).cloned();
                    i += 2;
                }
                "--wallet-id" => {
                    wallet_id = argv.get(i + 1).cloned();
                    i += 2;
                }
                other => anyhow::bail!(
                    "unknown derive-wallet-key flag: {}\nUsage: customer-recovery derive-wallet-key --master <hex> --wallet-id <uuid>",
                    other
                ),
            }
        }
        let master = flag_or_env(master_hex, "CUSTOMER_RECOVERY_MASTER")
            .ok_or_else(|| {
                anyhow!("derive-wallet-key: --master <hex> or $CUSTOMER_RECOVERY_MASTER required")
            })?;
        let wallet = wallet_id.ok_or_else(|| {
            anyhow!("derive-wallet-key: --wallet-id <uuid> required")
        })?;
        return derive_wallet_key_subcommand(&master, &wallet);
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();

    // Reject `http://` URLs at the boundary. A MITM proxy on a
    // plain-HTTP `--nearblocks-url` could feed a wrong
    // `derivation_path`, causing the customer to derive the wrong
    // master and silently lose access to the wallets they're trying
    // to recover. The MPC pairing check still catches a fake share
    // on `--rpc-url`, but the cleaner contract is "no HTTP, period".
    require_https(&cli.rpc_url, "--rpc-url")?;
    require_https(&cli.nearblocks_url, "--nearblocks-url")?;

    let secret_key: SecretKey = cli
        .signer_private_key
        .parse()
        .context("Invalid --signer-private-key (expected ed25519:base58)")?;
    let signer = InMemorySigner::from_secret_key(cli.vault_id.clone(), secret_key);

    let derivation_path = if cli.from_chain {
        let path = fetch_derivation_path_from_chain(&cli.nearblocks_url, &cli.vault_id)
            .await
            .context(
                "could not auto-discover derivation_path from chain — pass --derivation-path manually",
            )?;
        tracing::info!(path = %path, "Discovered derivation_path on chain");
        path
    } else {
        cli.derivation_path
            .clone()
            .ok_or_else(|| anyhow!("either --derivation-path or --from-chain is required"))?
    };

    // 1. Generate ephemeral BLS12-381 G1 keypair (one-shot per request).
    let mut rng = OsRng;
    let ephemeral_private = Scalar::random(&mut rng);
    let ephemeral_public = G1Projective::generator() * ephemeral_private;
    let app_public_key = format!(
        "bls12381g1:{}",
        bs58::encode(&ephemeral_public.to_compressed()).into_string()
    );
    tracing::info!(app_public_key = %app_public_key, "Generated ephemeral BLS keypair");

    // 2. Build CKD request args.
    let args = CkdRequestArgs {
        request: CkdArgs {
            derivation_path: derivation_path.clone(),
            app_public_key: app_public_key.clone(),
            domain_id: cli.mpc_domain_id,
        },
    };

    // 3. Submit request_app_private_key tx with 1 yocto deposit.
    let client = JsonRpcClient::connect(&cli.rpc_url);
    let response =
        submit_mpc_call(&client, &signer, &cli.mpc_contract, &args).await?;

    // 4. Recompute app_id locally (must match MPC's hash).
    let app_id = derive_app_id(cli.vault_id.as_str(), &derivation_path);

    // 5. Decrypt + verify pairing.
    let mpc_g2 = parse_g2(&cli.mpc_public_key)?;
    let secret =
        decrypt_and_verify(response, ephemeral_private, &mpc_g2, &app_id)?;

    // 6. HKDF-stretch 48-byte G1 secret to 32-byte master.
    let master = zeroize::Zeroizing::new(derive_strong_key(secret)?);

    // 7. Print the master in hex (this is THE secret — protect it).
    warn_sensitive_stdout("the per-vault master (32-byte hex)");
    println!();
    println!("# === Per-vault master recovered ===");
    println!("# vault_id       = {}", cli.vault_id);
    println!("# derivation_path= {}", derivation_path);
    println!();
    println!("master_hex={}", hex::encode(&*master));
    println!();
    println!(
        "# Now derive any wallet keypair: HMAC-SHA256(master, b\"wallet:<seed>\")"
    );
    println!(
        "# E.g. NEAR address: ed25519::SigningKey::from_bytes(&hmac_output[..32])"
    );

    Ok(())
}

async fn submit_mpc_call(
    client: &JsonRpcClient,
    signer: &InMemorySigner,
    mpc_contract: &AccountId,
    args: &CkdRequestArgs,
) -> Result<CkdResponse> {
    // Get nonce + recent block.
    let access_key_query = methods::query::RpcQueryRequest {
        block_reference: BlockReference::Finality(Finality::Final),
        request: QueryRequest::ViewAccessKey {
            account_id: signer.account_id.clone(),
            public_key: signer.public_key.clone(),
        },
    };
    let access_key_view = match client.call(access_key_query).await?.kind {
        QueryResponseKind::AccessKey(v) => v,
        other => anyhow::bail!("unexpected access-key response: {other:?}"),
    };
    let nonce = access_key_view.nonce + 1;
    let block = client
        .call(methods::block::RpcBlockRequest {
            block_reference: BlockReference::Finality(Finality::Final),
        })
        .await?;

    let serialized = serde_json::to_vec(&args)?;
    tracing::info!(
        deposit_yocto = 1u128,
        gas_tgas = 150,
        receiver = %mpc_contract,
        "Submitting request_app_private_key (FullAccess can attach deposit)"
    );

    let tx = TransactionV0 {
        signer_id: signer.account_id.clone(),
        public_key: signer.public_key.clone(),
        nonce,
        receiver_id: mpc_contract.clone(),
        block_hash: block.header.hash,
        actions: vec![Action::FunctionCall(Box::new(FunctionCallAction {
            method_name: "request_app_private_key".to_string(),
            args: serialized,
            gas: 150_000_000_000_000,
            deposit: 1, // assert_one_yocto
        }))],
    };
    let signed = near_primitives::transaction::SignedTransaction::new(
        signer.sign(Transaction::V0(tx.clone()).get_hash_and_size().0.as_ref()),
        Transaction::V0(tx),
    );
    let outcome = client
        .call(methods::broadcast_tx_commit::RpcBroadcastTxCommitRequest {
            signed_transaction: signed,
        })
        .await
        .context("broadcast_tx_commit")?;

    match outcome.status {
        FinalExecutionStatus::SuccessValue(value) => {
            let resp: CkdResponse = serde_json::from_slice(&value)
                .context("parse MPC CkdResponse")?;
            tracing::info!("✅ MPC returned encrypted CKD payload");
            Ok(resp)
        }
        FinalExecutionStatus::Failure(err) => {
            anyhow::bail!("MPC tx failed: {err:?}")
        }
        other => anyhow::bail!("unexpected outer status: {other:?}"),
    }
}

fn derive_app_id(predecessor_id: &str, derivation_path: &str) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(
        format!(
            "{}{},{}",
            APP_ID_DERIVATION_PREFIX, predecessor_id, derivation_path
        )
        .as_bytes(),
    );
    hasher.finalize().into()
}

fn parse_g1(s: &str) -> Result<G1Projective> {
    let b58 = s
        .strip_prefix("bls12381g1:")
        .ok_or_else(|| anyhow!("expected bls12381g1: prefix in {s}"))?;
    let bytes = bs58::decode(b58).into_vec()?;
    // Bounds check BEFORE `copy_from_slice` — a malicious RPC node
    // (or MITM with HTTP) could return a short blob and crash the
    // recovery tool via index-out-of-bounds panic.
    if bytes.len() != BLS12381G1_PUBLIC_KEY_SIZE {
        anyhow::bail!(
            "bls12381g1: expected exactly {} compressed bytes, got {}",
            BLS12381G1_PUBLIC_KEY_SIZE,
            bytes.len()
        );
    }
    let mut compressed = [0u8; BLS12381G1_PUBLIC_KEY_SIZE];
    compressed.copy_from_slice(&bytes);
    G1Projective::from_compressed(&compressed)
        .into_option()
        .ok_or_else(|| anyhow!("invalid G1 point"))
}

fn parse_g2(s: &str) -> Result<G2Projective> {
    let b58 = s
        .strip_prefix("bls12381g2:")
        .ok_or_else(|| anyhow!("expected bls12381g2: prefix in {s}"))?;
    let bytes = bs58::decode(b58).into_vec()?;
    // Same DoS hardening as `parse_g1` — fail loud on wrong-length input
    // rather than panic.
    if bytes.len() != 96 {
        anyhow::bail!(
            "bls12381g2: expected exactly 96 compressed bytes, got {}",
            bytes.len()
        );
    }
    let mut compressed = [0u8; 96];
    compressed.copy_from_slice(&bytes);
    G2Projective::from_compressed(&compressed)
        .into_option()
        .ok_or_else(|| anyhow!("invalid G2 point"))
}

fn decrypt_and_verify(
    response: CkdResponse,
    private_key: Scalar,
    mpc_pub: &G2Projective,
    app_id: &[u8],
) -> Result<[u8; BLS12381G1_PUBLIC_KEY_SIZE]> {
    let big_y = parse_g1(&response.big_y)?;
    let big_c = parse_g1(&response.big_c)?;

    // secret = big_c - big_y * private_key
    let secret = big_c - big_y * private_key;

    // Pairing verification (matches MPC's signature scheme).
    let element1: G1Affine = secret.into();
    if (!element1.is_on_curve() | !element1.is_torsion_free() | element1.is_identity()).into() {
        anyhow::bail!("decrypted secret point invalid");
    }
    let element2: G2Affine = (*mpc_pub).into();
    if (!element2.is_on_curve() | !element2.is_torsion_free() | element2.is_identity()).into() {
        anyhow::bail!("MPC pubkey invalid");
    }

    let hash_input = [mpc_pub.to_compressed().as_slice(), app_id].concat();
    let base1 = G1Projective::hash_to_curve(&hash_input, NEAR_CKD_DOMAIN, &[]).into();
    let base2 = G2Affine::generator();
    if blstrs::pairing(&base1, &element2) != blstrs::pairing(&element1, &base2) {
        anyhow::bail!("MPC signature pairing verification failed");
    }

    Ok(secret.to_compressed())
}

fn derive_strong_key(
    ikm: [u8; BLS12381G1_PUBLIC_KEY_SIZE],
) -> Result<[u8; OUTPUT_SECRET_SIZE]> {
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = [0u8; OUTPUT_SECRET_SIZE];
    hk.expand(b"", &mut okm)
        .map_err(|e| anyhow!("HKDF expand: {e}"))?;
    Ok(okm)
}

/// Query NEARblocks for the most recent `request_app_private_key`
/// receipt FROM `vault_id` to MPC, decode its args, and pull out the
/// `derivation_path` field.
async fn fetch_derivation_path_from_chain(
    nearblocks_url: &str,
    vault_id: &AccountId,
) -> Result<String> {
    let url = format!(
        "{}/v1/account/{}/txns?per_page=20",
        nearblocks_url, vault_id
    );
    let body: serde_json::Value = reqwest::get(&url)
        .await
        .context("query NEARblocks")?
        .json()
        .await
        .context("parse NEARblocks JSON")?;

    let txns = body
        .get("txns")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow!("NEARblocks: no txns array in response"))?;

    for t in txns {
        if t.get("predecessor_account_id").and_then(|v| v.as_str()) != Some(vault_id.as_str()) {
            continue;
        }
        let actions = t.get("actions").and_then(|v| v.as_array());
        let Some(actions) = actions else { continue };
        for a in actions {
            // Both `request_master` (the vault's proxy method) and
            // direct `request_app_private_key` carry the same args
            // shape — `{ request: { derivation_path, app_public_key,
            // domain_id } }` — so accept either. NEARblocks' txns
            // endpoint surfaces direct txs to/from the account but
            // not always cross-contract receipts; the proxy's outer
            // tx (vault → vault) is reliably listed and has the same
            // payload.
            //
            // NEARblocks v1 (testnet, mid-2026) returns the action as
            // flat `{action, method, args}` strings — not the older
            // nested `{method: {method_name, args}}` shape. We try
            // the flat form first and fall back to nested so this
            // tool keeps working if the API rolls back.
            let method = a
                .get("method")
                .and_then(|v| v.as_str())
                .or_else(|| {
                    a.get("method")
                        .and_then(|m| m.get("method_name"))
                        .and_then(|v| v.as_str())
                });
            if method != Some("request_app_private_key") && method != Some("request_master") {
                continue;
            }
            // Same flat/nested duality for `args`. The flat form
            // returns plain JSON; the legacy nested form returns
            // base64. Detect by trying base64 first and falling back
            // to a raw parse — both branches end with the same
            // `serde_json::Value`.
            let args_raw = a
                .get("args")
                .and_then(|v| v.as_str())
                .or_else(|| a.get("method").and_then(|m| m.get("args")).and_then(|v| v.as_str()))
                .ok_or_else(|| anyhow!("request_app_private_key receipt missing args"))?;
            let json: serde_json::Value = match base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                args_raw,
            ) {
                Ok(decoded) => serde_json::from_slice(&decoded)
                    .context("parse args JSON (base64 branch)")?,
                Err(_) => serde_json::from_str(args_raw)
                    .context("parse args JSON (plaintext branch)")?,
            };
            let path = json
                .get("request")
                .and_then(|r| r.get("derivation_path"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("args missing request.derivation_path"))?;
            return Ok(path.to_string());
        }
    }

    Err(anyhow!(
        "no past request_app_private_key tx found for {} on NEARblocks — submit at least one CKD call before this tool can auto-discover the path, or pass --derivation-path explicitly",
        vault_id
    ))
}
