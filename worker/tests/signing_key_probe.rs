//! `wasi-examples/signing-key-probe` through the executor, with injected keys.
//!
//! What a guest sees of the `outlayer:signing-keys` host interface: every
//! operation, the pinned public keys and signatures (computed independently —
//! ed25519 with PyNaCl, secp256k1 with `coincurve`), an independent ed25519,
//! secp256k1 and NEP-413 verification, the host's `sign-nep413` byte for byte
//! the guest-built signature, every attack answered as an `err` inside a run
//! that succeeds, every vault mismatch, no seed byte anywhere the guest can
//! look — and a module that declares keys and is handed none refused before it
//! runs.
//!
//! Run with: cargo test --test signing_key_probe
//! The probe must be built first: wasi-examples/signing-key-probe/build.sh

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

use offchainvm_worker::api_client::{ExecutionResult, ResourceLimits, ResponseFormat};
use offchainvm_worker::executor::Executor;
use offchainvm_worker::signing_keys::{SeedHex, SigningKeys};
use serde_json::{json, Value};

/// The seed of `crypto.rs`'s first pinned vector in the keystore, and its
/// public key.
const SEED_A: &str = "b5ca092c9bb7c321f2d6f69c6eb147907d5df9fcc2309552786e7502706a7493";
const PUB_A: &str = "a31824c9aac23c954e90eba38553aee73658cf09c57b5f2a124c26ade2da2e52";
const SEED_B: &str = "87e38fc6d2921ae6a0262969bf3dc73b7da74acdbb2f28faebdacce287739f60";
const PUB_B: &str = "d8be888df7045d710417e2733a1555d96a0b3e1f1684ff53f5f382e9b878e66f";
const SEED_C: &str = "f2011fe88d7a85e9b49c910bb88f8b37e9724f6a1a36a49e7b63ebea2203411a";

/// SEED_A's RFC 8032 signature of `record #1`, from an independent
/// implementation.
const SIG_A_RECORD_1: &str = "8654231a0f339db04286614725f044c9063771ffb08647dcc22f4405d6e1442c6b0ecacb1ba72aa7dc68af102f718e1935a0fb9dd7dbdfd55f5ddcfebdb6b90f";

/// A NEP-413 signature by SEED_A, computed with Python (borsh by hand with
/// `struct`, `hashlib`, PyNaCl) for message "Login to example.com", recipient
/// "example.com", nonce 00 01 … 1f, no callback URL.
const NEP413_HASH: &str = "cd116988f58c30e8e583243b8b61ea5f567ccbc8529dcca6565ae2022d559ed2";
const NEP413_PUBLIC_KEY: &str = "ed25519:ByeoqbFJ3wTXANnK9bSQqdB8uM7iVQFFxMHdJTWkEN3K";
const NEP413_SIGNATURE: &str = "BwSUP+RPUQJ6gV30nIFJsy3ywCs4VvRtd9QV6quPxK5MVrWn/7Y1+ADzS6652AsDVsZJIHLuZRDWNivImQJtDw==";
/// The same, with callback URL "https://example.com/cb".
const NEP413_SIGNATURE_CB: &str = "pYY73u/dA6smLFR3cTEG/Bdi1JkiXVT+KK+oQvJBa4+SvYtvq/k1xHVBp0EDngBSM0/SLhM09adQ3r4HQXMCCg==";

/// The keystore's pinned secp256k1 seeds (`crypto.rs`,
/// `secp256k1_signing_key_pinned_vectors`), their public keys `x ‖ y` and EVM
/// addresses, computed with Python (`coincurve`, `pycryptodome` keccak256).
const SECP_SEED_A: &str = "772890cc14851d53236ca8223391e336f711aedaaca1ee1922e9ad6452661b90";
const SECP_PUB_A: &str = "ed426f3507c4c5d16edaa292cc2a60e3bdb4a92724613c4d242c97f51ff47d677ca9bd17bd777ecddbe30fc984d124f0b189ebac9c40e322da396b5fd217c5e3";
const SECP_EVM_A: &str = "0x20d9ed83e1e77fe943ff7627cb55b87a94675832";
const SECP_SEED_B: &str = "eca5d0f77b791ab4165da888811f52130b61a594f1efba0015c473da48efee50";
const SECP_PUB_B: &str = "ad0a99c4c37c0f69cce104532f8fa3b59534d5c259891c37e1e8e4180e85b458f065d5678b11500966b320b7d1f0ce607c84d6fe0962ce3bcb5dc874bea81783";
const SECP_EVM_B: &str = "0x8914e846ae2737631d8b242daf4f2cd25929de1e";
/// keccak256("record #1"), and SECP_SEED_A's `r ‖ s ‖ v` over it (RFC 6979,
/// libsecp256k1 through `coincurve`).
const KECCAK_RECORD_1: &str = "7e212fe9e9a2b5d41a353b8f7399c8d48fb7e83bee75d2233a856cefad932852";
const SECP_SIG_A_RECORD_1: &str = "b5f5dc30365e5da9c6c2135a088d7974ac3293d9a0ea64955df0ffd117a927cb56bbf86061befe7d1e1e64342360a6ae1d401c70e4d0b0d7c384e05bdd7b8c4601";

fn probe(variant: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join(format!("wasi-examples/signing-key-probe/target/variants/signing-key-probe-{variant}.wasm"));
    if !path.exists() {
        panic!(
            "Test WASM not found at {}! Build it first:\n\
             cd ../wasi-examples/signing-key-probe && ./build.sh",
            path.display()
        );
    }
    std::fs::read(&path).expect("read the probe")
}

/// The keys `wasm` declares, with the given seeds by path — as the keystore's
/// answer would hand them over.
fn keys_for(wasm: &[u8], seeds: &[(&str, &str)]) -> SigningKeys {
    let manifest = offchainvm_worker::connector_manifest::manifest_from_wasm(wasm)
        .expect("the manifest reads")
        .expect("the probe carries a manifest");
    let declared = manifest.signing_keys.expect("the probe declares keys");
    let seeds: BTreeMap<String, SeedHex> =
        serde_json::from_value(json!(seeds.iter().map(|(p, s)| (p.to_string(), s.to_string())).collect::<BTreeMap<_, _>>()))
            .unwrap();
    SigningKeys::from_keystore(&declared, seeds).expect("the keys the manifest declares")
}

fn project_keys(wasm: &[u8]) -> SigningKeys {
    keys_for(wasm, &[("alpha", SEED_A), ("beta", SEED_B)])
}

/// The keys of the `project-secp` build: `evm` (secp256k1), `alpha` (ed25519).
fn secp_keys(wasm: &[u8]) -> SigningKeys {
    keys_for(wasm, &[("evm", SECP_SEED_A), ("alpha", SEED_A)])
}

/// The keys every build declares, by variant, as the keystore would hand them.
fn seeds_of(variant: &str) -> Vec<(&'static str, &'static str)> {
    match variant {
        "project" | "project-v2" => vec![("alpha", SEED_A), ("beta", SEED_B)],
        "project-vault" => vec![("alpha", SEED_A), ("treasury", SEED_B)],
        "wasm" | "wasm-v2" => vec![("code", SEED_C)],
        "project-secp" => vec![("evm", SECP_SEED_A), ("alpha", SEED_A)],
        "wasm-secp" => vec![("code-evm", SECP_SEED_B)],
        other => panic!("no seeds for {other}"),
    }
}

async fn run(wasm: &[u8], keys: Option<SigningKeys>, input: Value) -> ExecutionResult {
    let executor = Executor::new(10_000_000_000, false);
    let limits = ResourceLimits { max_instructions: 10_000_000_000, max_memory_mb: 128, max_execution_seconds: 60 };
    let sha = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(wasm))
    };
    let env: HashMap<String, String> = [
        ("NEAR_USER_ACCOUNT_ID", "bob.near"),
        ("NEAR_SENDER_ID", "bob.near"),
        ("OUTLAYER_EXECUTION_TYPE", "NEAR"),
        ("NEAR_NETWORK_ID", "testnet"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    executor
        .with_keys(offchainvm_worker::executor::RunKeys { signing: keys, encryption: None })
        .execute(
            wasm,
            Some(&sha),
            input.to_string().as_bytes(),
            &limits,
            Some(env),
            Some("wasm32-wasip2"),
            &ResponseFormat::Json,
            None,
            None,
            None,
            None,
        )
        .await
        .expect("the executor answers")
}

/// The probe's answer from a run that must succeed.
async fn answer(wasm: &[u8], keys: SigningKeys, input: Value) -> Value {
    let result = run(wasm, Some(keys), input.clone()).await;
    assert!(result.success, "{input}: the run failed: {:?}", result.error);
    match result.output {
        Some(offchainvm_worker::api_client::ExecutionOutput::Json(v)) => v,
        other => panic!("{input}: expected JSON output, got {other:?}"),
    }
}

fn verify(public_key_hex: &str, message: &[u8], signature: &[u8]) -> bool {
    use ed25519_dalek::Verifier;
    let pk: [u8; 32] = hex::decode(public_key_hex).unwrap().try_into().unwrap();
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk).unwrap();
    let Ok(sig) = ed25519_dalek::Signature::from_slice(signature) else { return false };
    vk.verify(message, &sig).is_ok()
}

/// NEP-413's hash, built here independently of the probe: the tag and the
/// payload spelled out byte by byte.
fn nep413_hash(message: &str, nonce: &[u8; 32], recipient: &str, callback_url: Option<&str>) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(2u32.pow(31) + 413).to_le_bytes());
    bytes.extend_from_slice(&(message.len() as u32).to_le_bytes());
    bytes.extend_from_slice(message.as_bytes());
    bytes.extend_from_slice(nonce);
    bytes.extend_from_slice(&(recipient.len() as u32).to_le_bytes());
    bytes.extend_from_slice(recipient.as_bytes());
    match callback_url {
        None => bytes.push(0),
        Some(url) => {
            bytes.push(1);
            bytes.extend_from_slice(&(url.len() as u32).to_le_bytes());
            bytes.extend_from_slice(url.as_bytes());
        }
    }
    Sha256::digest(&bytes).into()
}

fn nonce() -> [u8; 32] {
    std::array::from_fn(|i| i as u8)
}

#[tokio::test]
async fn every_operation_answers_with_the_pinned_key_and_verifying_signatures() {
    let wasm = probe("project");

    let pk = answer(&wasm, project_keys(&wasm), json!({ "operation": "public_key", "path": "alpha" })).await;
    assert_eq!(pk["status"], "ok", "{pk}");
    assert_eq!(pk["public_key"], PUB_A, "the pinned public key");

    let message = b"record #1";
    let signed = answer(
        &wasm,
        project_keys(&wasm),
        json!({ "operation": "sign", "path": "alpha", "message_hex": hex::encode(message) }),
    )
    .await;
    assert_eq!(signed["status"], "ok", "{signed}");
    assert_eq!(signed["signature"], SIG_A_RECORD_1, "the independent implementation's signature");
    let sig = hex::decode(signed["signature"].as_str().unwrap()).unwrap();
    assert!(verify(PUB_A, message, &sig), "an independent verification");
    assert!(!verify(PUB_A, b"record #2", &sig));
    assert!(!verify(PUB_B, message, &sig), "beta does not verify alpha's signature");

    let checked = answer(
        &wasm,
        project_keys(&wasm),
        json!({ "operation": "sign_and_verify", "path": "beta", "message_hex": hex::encode(b"verified inside") }),
    )
    .await;
    assert_eq!(checked["status"], "ok", "{checked}");
    assert_eq!((checked["verified"].as_bool(), checked["tampered_rejected"].as_bool()), (Some(true), Some(true)));
    assert_eq!(checked["public_key"], PUB_B);
    let sig = hex::decode(checked["signature"].as_str().unwrap()).unwrap();
    assert!(verify(PUB_B, b"verified inside", &sig));

    let all = answer(&wasm, project_keys(&wasm), json!({ "operation": "all_public_keys" })).await;
    assert_eq!(all["status"], "ok", "{all}");
    assert_eq!(all["keys"]["alpha"]["public_key"], PUB_A);
    assert_eq!(all["keys"]["beta"]["public_key"], PUB_B);
    assert_ne!(all["keys"]["alpha"]["public_key"], all["keys"]["beta"]["public_key"], "alpha ≠ beta");
    assert_eq!(all["keys"].as_object().unwrap().len(), 2);
    assert_eq!(all["build"], "signing-key-probe build 1");
}

#[tokio::test]
async fn a_nep413_signature_verifies_as_a_wallets_does() {
    use base64::Engine;
    let wasm = probe("project");
    let b64 = base64::engine::general_purpose::STANDARD;
    let request = |callback: Option<&str>| {
        json!({
            "operation": "sign_nep413", "path": "alpha",
            "message": "Login to example.com", "recipient": "example.com",
            "nonce_hex": hex::encode(nonce()), "callback_url": callback,
        })
    };
    for (callback, pinned) in [(None, NEP413_SIGNATURE), (Some("https://example.com/cb"), NEP413_SIGNATURE_CB)] {
        let signed = answer(&wasm, project_keys(&wasm), request(callback)).await;
        assert_eq!(signed["status"], "ok", "{signed}");
        // The wallet-style fields.
        assert_eq!(signed["accountId"], PUB_A, "the implicit account is the public key in hex");
        let public_key = hex::decode(PUB_A).unwrap();
        assert_eq!(signed["publicKey"], format!("ed25519:{}", bs58::encode(&public_key).into_string()));
        assert_eq!(signed["publicKey"], NEP413_PUBLIC_KEY);
        assert_eq!(signed["signature"], pinned, "Python's signature, byte for byte");

        // Verified against a hash rebuilt here, not by the probe.
        let sig = b64.decode(signed["signature"].as_str().unwrap()).unwrap();
        let hash = nep413_hash("Login to example.com", &nonce(), "example.com", callback);
        if callback.is_none() {
            assert_eq!(hex::encode(hash), NEP413_HASH);
        }
        assert!(verify(PUB_A, &hash, &sig), "the signature verifies over the NEP-413 hash");

        // Anything changed, and it does not.
        let mut other_nonce = nonce();
        other_nonce[0] ^= 1;
        let other_callback = match callback {
            None => Some("https://example.com/cb"),
            Some(_) => None,
        };
        for (label, tampered) in [
            ("message", nep413_hash("Login to example.org", &nonce(), "example.com", callback)),
            ("recipient", nep413_hash("Login to example.com", &nonce(), "example.org", callback)),
            ("nonce", nep413_hash("Login to example.com", &other_nonce, "example.com", callback)),
            ("callback URL", nep413_hash("Login to example.com", &nonce(), "example.com", other_callback)),
        ] {
            assert!(!verify(PUB_A, &tampered, &sig), "a tampered {label} must not verify");
        }
    }
    // A nonce that is not 32 bytes is an answer, not a crash.
    let mut short = request(None);
    short["nonce_hex"] = json!("0011");
    let refused = answer(&wasm, project_keys(&wasm), short).await;
    assert_eq!(refused["status"], "err", "{refused}");
}

#[tokio::test]
async fn the_same_path_is_the_same_key_across_runs() {
    let wasm = probe("project");
    let input = json!({ "operation": "sign", "path": "beta", "message_hex": hex::encode(b"twice") });
    let first = answer(&wasm, project_keys(&wasm), input.clone()).await;
    let second = answer(&wasm, project_keys(&wasm), input).await;
    assert_eq!(first["public_key"], second["public_key"]);
    assert_eq!(first["signature"], second["signature"]);
    // The other build of the same manifest, handed the same seeds, answers the same.
    let v2 = probe("project-v2");
    let third = answer(&v2, project_keys(&v2), json!({ "operation": "public_key", "path": "beta" })).await;
    assert_eq!(third["public_key"], first["public_key"]);
    assert_eq!(third["build"], "signing-key-probe build 2");
}

#[tokio::test]
async fn a_wasm_key_answers_through_the_wasm_build() {
    let wasm = probe("wasm");
    let keys = || keys_for(&wasm, &[("code", SEED_C)]);
    let all = answer(&wasm, keys(), json!({ "operation": "all_public_keys" })).await;
    assert_eq!(all["keys"].as_object().unwrap().keys().collect::<Vec<_>>(), vec!["code"], "{all}");
    let checked = answer(
        &wasm,
        keys(),
        json!({ "operation": "sign_and_verify", "path": "code", "message_hex": hex::encode(b"code-bound") }),
    )
    .await;
    assert_eq!(checked["status"], "ok", "{checked}");
    let pk = checked["public_key"].as_str().unwrap();
    assert!(verify(pk, b"code-bound", &hex::decode(checked["signature"].as_str().unwrap()).unwrap()));
    // alpha is not this build's.
    let refused = answer(&wasm, keys(), json!({ "operation": "public_key", "path": "alpha" })).await;
    assert_eq!(refused["status"], "err", "{refused}");
}

/// Every attack is answered — an `err` with the host's reason, `ok` for the two
/// that must succeed, `n/a` where the build declares no key the attack needs —
/// and the run itself succeeds.
#[tokio::test]
async fn every_attack_is_an_err_and_the_run_succeeds() {
    let paths: &[(&str, &str, &str)] = &[
        ("undeclared_path", "err", "no signing key at path"),
        ("empty_path", "err", "no signing key at path"),
        ("colon_path", "err", "no signing key at path"),
        ("traversal_path", "err", "no signing key at path"),
        ("huge_path", "err", "no signing key at path"),
        ("vault_when_none_declared", "err", "declared without a vault"),
        ("determinism", "ok", "one public key and one signature"),
    ];
    let ed: &[(&str, &str, &str)] = &[
        ("oversized_message", "err", "at most 65536"),
        ("message_at_cap", "ok", "signature verifies"),
        ("nep413_bad_nonce", "err", "nonce is 31 bytes; it must be exactly 32"),
    ];
    let no_ed: &[(&str, &str, &str)] = &[
        ("oversized_message", "n/a", "no ed25519 key"),
        ("message_at_cap", "n/a", "no ed25519 key"),
        ("nep413_bad_nonce", "n/a", "no ed25519 key"),
    ];
    let secp: &[(&str, &str, &str)] = &[
        ("secp_message_not_32", "err", "32-byte prehash only, and the message is 31 bytes"),
        ("nep413_wrong_type", "err", "sign-nep413 signs with an ed25519 key"),
    ];
    let no_secp: &[(&str, &str, &str)] =
        &[("secp_message_not_32", "n/a", "no secp256k1 key"), ("nep413_wrong_type", "n/a", "no secp256k1 key")];
    let no_vault: &[(&str, &str, &str)] = &[
        ("vault_missing_when_declared", "n/a", "no key with a vault"),
        ("vault_wrong_when_declared", "n/a", "no key with a vault"),
    ];
    let vault: &[(&str, &str, &str)] = &[
        ("vault_missing_when_declared", "err", "names none"),
        ("vault_wrong_when_declared", "err", "names vault \"vault.attacker.near\""),
    ];
    for (variant, groups) in [
        ("project", [ed, no_secp, no_vault]),
        ("project-vault", [ed, no_secp, vault]),
        ("project-secp", [ed, secp, no_vault]),
        ("wasm-secp", [no_ed, secp, no_vault]),
    ] {
        let wasm = probe(variant);
        let keys = || keys_for(&wasm, &seeds_of(variant));
        let all = answer(&wasm, keys(), json!({ "operation": "attacks" })).await;
        assert_eq!(all["status"], "ok", "{variant}: {all}");
        let results = all["results"].as_array().expect("results");
        let rows: Vec<(&str, &str, &str)> = paths.iter().chain(groups.into_iter().flatten()).copied().collect();
        assert_eq!(results.len(), rows.len(), "{variant}: {all}");
        for (name, status, says) in rows {
            let r = results.iter().find(|r| r["name"] == name).unwrap_or_else(|| panic!("{variant}: no {name}"));
            assert_eq!(r["status"], status, "{variant} {name}: {r}");
            let message = r["message"].as_str().unwrap();
            assert!(message.contains(says), "{variant} {name}: {message}");
            assert!(message.len() < 400, "{variant} {name}: a reason, not an echo ({} bytes)", message.len());
        }
        // One at a time, too: each its own run, each answered.
        for name in ["huge_path", "oversized_message", "message_at_cap", "secp_message_not_32", "nep413_wrong_type", "nep413_bad_nonce"] {
            let one = answer(&wasm, keys(), json!({ "operation": "attack", "name": name })).await;
            let expected = results.iter().find(|r| r["name"] == name).unwrap();
            assert_eq!(one["status"], expected["status"], "{variant} {name}: {one}");
        }
    }
}

/// A call names the key's declared vault exactly; every other way round is an
/// `err`.
#[tokio::test]
async fn every_vault_mismatch_is_an_err() {
    let wasm = probe("project-vault");
    let keys = || keys_for(&wasm, &[("alpha", SEED_A), ("treasury", SEED_B)]);
    let ask = |path: &str, vault: Option<&str>| {
        json!({ "operation": "sign", "path": path, "vault": vault, "message_hex": hex::encode(b"vaulted") })
    };
    let cases = [
        ("treasury, declared with a vault, called with none", ask("treasury", None), "err", "names none"),
        ("treasury, called with another vault", ask("treasury", Some("vault.mallory.near")), "err", "names vault \"vault.mallory.near\""),
        ("treasury, called with an empty vault", ask("treasury", Some("")), "err", "names vault \"\""),
        ("alpha, declared without a vault, called with one", ask("alpha", Some("vault.alice.near")), "err", "declared without a vault"),
        ("treasury, called with its vault", ask("treasury", Some("vault.alice.near")), "ok", "signed"),
        ("alpha, called with none", ask("alpha", None), "ok", "signed"),
    ];
    for (label, input, status, says) in cases {
        let got = answer(&wasm, keys(), input).await;
        assert_eq!(got["status"], status, "{label}: {got}");
        assert!(got["message"].as_str().unwrap().contains(says), "{label}: {got}");
    }
    // public_key follows the same rule.
    let got = answer(&wasm, keys(), json!({ "operation": "public_key", "path": "treasury" })).await;
    assert_eq!(got["status"], "err", "{got}");
    let got = answer(&wasm, keys(), json!({ "operation": "public_key", "path": "treasury", "vault": "vault.alice.near" })).await;
    assert_eq!(got["public_key"], PUB_B, "{got}");
    // And all_public_keys, which names each key's declared vault, reads both.
    let all = answer(&wasm, keys(), json!({ "operation": "all_public_keys" })).await;
    assert_eq!(all["status"], "ok", "{all}");
    assert_eq!(all["keys"]["treasury"]["vault"], "vault.alice.near");
}

/// Nothing of a seed reaches the guest: not its environment, not its stdin,
/// not its filesystem, and not one byte of its own linear memory — searched
/// after every declared key has been used in the same run.
#[tokio::test]
async fn no_seed_is_visible_to_the_guest() {
    const MASK: u8 = 0x5a;
    let masked = |bytes: &[u8]| hex::encode(bytes.iter().map(|b| b ^ MASK).collect::<Vec<u8>>());
    for variant in ["project", "project-vault", "wasm", "project-secp", "wasm-secp"] {
        let seeds = seeds_of(variant);
        let wasm = probe(variant);
        let mut needles = Vec::new();
        for (_, seed) in &seeds {
            let raw = hex::decode(seed).unwrap();
            needles.push(masked(&raw)); // the 32 bytes
            needles.push(masked(&raw[..8])); // any 8 of them in a row
            needles.push(masked(seed.as_bytes())); // the hex, lowercase
            needles.push(masked(seed.to_uppercase().as_bytes())); // the hex, uppercase
        }
        // A control that IS in memory — the manifest's first key path — so a
        // scan that finds nothing is a scan that works.
        let first_path = seeds[0].0;
        needles.push(masked(format!("\"path\": \"{first_path}\"").as_bytes()));

        let seen = answer(
            &wasm,
            keys_for(&wasm, &seeds),
            json!({ "operation": "what_i_can_see", "scan_masked_hex": needles }),
        )
        .await;
        assert_eq!(seen["status"], "ok", "{variant}: {seen}");
        let exercised = seen["exercised"].as_array().unwrap();
        assert_eq!(exercised.len(), seeds.len(), "{variant}: {seen}");
        for e in exercised {
            assert_eq!((e["public_key"].as_bool(), e["sign"].as_bool()), (Some(true), Some(true)), "{variant}: {e}");
        }
        let scans = seen["memory_scans"].as_array().unwrap();
        let (control, seed_scans) = scans.split_last().unwrap();
        assert!(control["found"].as_u64().unwrap() >= 1, "{variant}: the control needle must be found: {seen}");
        for (i, scan) in seed_scans.iter().enumerate() {
            assert_eq!(scan["found"], 0, "{variant}: seed needle {i} is in the guest's memory");
        }
        assert!(seen["memory_bytes"].as_u64().unwrap() > 0);

        // The environment and stdin as the guest read them: the job's, and no
        // key material in either.
        assert_eq!(seen["env"]["NEAR_USER_ACCOUNT_ID"], "bob.near", "{variant}: reading the environment works");
        let text = seen.to_string();
        for (_, seed) in &seeds {
            use base64::Engine;
            let raw = hex::decode(seed).unwrap();
            for shape in [
                seed.to_string(),
                seed.to_uppercase(),
                base64::engine::general_purpose::STANDARD.encode(&raw),
                bs58::encode(&raw).into_string(),
            ] {
                assert!(!text.contains(&shape), "{variant}: a seed is visible to the guest");
            }
        }
        for (name, value) in seen["env"].as_object().unwrap() {
            let value = value.as_str().unwrap_or_default().to_ascii_lowercase();
            assert!(!name.to_ascii_lowercase().contains("seed") && !name.to_ascii_lowercase().contains("signing"), "{variant}: {name}");
            for (_, seed) in &seeds {
                assert!(!value.contains(&seed[..16]), "{variant}: {name} carries a seed");
            }
        }
    }
}

/// A module that declares keys and is handed none — a keystore that predates
/// signing keys — is refused before it runs; so is one handed keys that are
/// not the ones it declares, or keys it does not declare at all.
#[tokio::test]
async fn a_module_that_declares_keys_and_receives_none_is_refused_before_running() {
    let wasm = probe("project");
    let refused = run(&wasm, None, json!({ "operation": "all_public_keys" })).await;
    assert!(!refused.success, "a module declaring keys ran without them");
    assert!(refused.output.is_none(), "nothing ran, so nothing was output");
    let error = refused.error.unwrap();
    assert!(error.contains("declares signing keys") && error.contains("given none"), "{error}");
    assert!(error.contains("\"alpha\"") && error.contains("\"beta\""), "{error}");
    assert_eq!(refused.instructions, 0, "refused before running: {error}");

    // An empty set is none.
    let refused = run(&wasm, Some(SigningKeys::none()), json!({ "operation": "all_public_keys" })).await;
    assert!(!refused.success && refused.error.unwrap().contains("given none"));

    // Keys for another declaration: the wasm build's `code` handed to the project build.
    let other = probe("wasm");
    let refused = run(&wasm, Some(keys_for(&other, &[("code", SEED_C)])), json!({ "operation": "all_public_keys" })).await;
    assert!(!refused.success);
    assert!(refused.error.unwrap().contains("not the ones its manifest declares"));

    // The same paths with a vault the manifest does not declare.
    let vaulted = probe("project-vault");
    let refused = run(
        &vaulted,
        Some(keys_for(&probe("project"), &[("alpha", SEED_A), ("beta", SEED_B)])),
        json!({ "operation": "all_public_keys" }),
    )
    .await;
    assert!(!refused.success);

    // Keys handed to a module that declares none.
    let minimal = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    let refused = run(&minimal, Some(project_keys(&wasm)), json!({})).await;
    assert!(!refused.success);
    assert!(refused.error.unwrap().contains("declares none"));

    // And with its keys it runs.
    assert!(run(&wasm, Some(project_keys(&wasm)), json!({ "operation": "all_public_keys" })).await.success);
}

/// A secp256k1 key through the executor: the pinned public key, EVM address
/// and signature of an independent implementation; verified, low-s and
/// recovered inside the guest; a message that is not 32 bytes refused; and
/// the ed25519 key of the same build untouched.
#[tokio::test]
async fn a_secp256k1_key_answers_with_the_pinned_key_address_and_signature() {
    let wasm = probe("project-secp");

    let pk = answer(&wasm, secp_keys(&wasm), json!({ "operation": "public_key", "path": "evm" })).await;
    assert_eq!(pk["status"], "ok", "{pk}");
    assert_eq!(pk["public_key"], SECP_PUB_A, "64 bytes x ‖ y");

    let address = answer(&wasm, secp_keys(&wasm), json!({ "operation": "evm_address", "path": "evm" })).await;
    assert_eq!(address["status"], "ok", "{address}");
    assert_eq!(address["evm_address"], SECP_EVM_A);
    let not_evm = answer(&wasm, secp_keys(&wasm), json!({ "operation": "evm_address", "path": "alpha" })).await;
    assert_eq!(not_evm["status"], "err", "an ed25519 key has no EVM address: {not_evm}");

    let signed = answer(&wasm, secp_keys(&wasm), json!({ "operation": "sign", "path": "evm", "message_hex": KECCAK_RECORD_1 })).await;
    assert_eq!(signed["status"], "ok", "{signed}");
    assert_eq!(signed["signature"], SECP_SIG_A_RECORD_1, "coincurve's signature, byte for byte");

    // Verified outside the guest too, with k256's verification and recovery.
    {
        use k256::ecdsa::signature::hazmat::PrehashVerifier;
        let sig = hex::decode(SECP_SIG_A_RECORD_1).unwrap();
        let prehash = hex::decode(KECCAK_RECORD_1).unwrap();
        let mut sec1 = vec![0x04];
        sec1.extend(hex::decode(SECP_PUB_A).unwrap());
        let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).unwrap();
        let signature = k256::ecdsa::Signature::from_slice(&sig[..64]).unwrap();
        assert!(vk.verify_prehash(&prehash, &signature).is_ok());
        assert!(signature.normalize_s().is_none(), "low-s");
        assert_eq!(sig[64], 1);
        let recovered =
            k256::ecdsa::VerifyingKey::recover_from_prehash(&prehash, &signature, k256::ecdsa::RecoveryId::from_byte(sig[64]).unwrap())
                .unwrap();
        assert_eq!(recovered, vk);
    }

    for message_hex in [KECCAK_RECORD_1.to_string(), hex::encode([0x42u8; 32])] {
        let checked =
            answer(&wasm, secp_keys(&wasm), json!({ "operation": "sign_and_verify", "path": "evm", "message_hex": message_hex })).await;
        assert_eq!(checked["status"], "ok", "{checked}");
        for field in ["verified", "recovered", "low_s", "tampered_rejected"] {
            assert_eq!(checked[field], true, "{field}: {checked}");
        }
        assert!(checked["v"] == 0 || checked["v"] == 1, "{checked}");
        assert_eq!(checked["evm_address"], SECP_EVM_A);
        assert_eq!(checked["public_key"], SECP_PUB_A);
    }

    for bad in [hex::encode(b"record #1"), hex::encode([0u8; 31]), hex::encode([0u8; 33]), String::new()] {
        let refused = answer(&wasm, secp_keys(&wasm), json!({ "operation": "sign", "path": "evm", "message_hex": bad })).await;
        assert_eq!(refused["status"], "err", "{refused}");
        assert!(refused["message"].as_str().unwrap().contains("32-byte prehash only"), "{refused}");
    }

    let all = answer(&wasm, secp_keys(&wasm), json!({ "operation": "all_public_keys" })).await;
    assert_eq!(all["status"], "ok", "{all}");
    assert_eq!(all["keys"]["evm"]["public_key"], SECP_PUB_A);
    assert_eq!(all["keys"]["alpha"]["public_key"], PUB_A, "the ed25519 key beside it");
    let ed = answer(&wasm, secp_keys(&wasm), json!({ "operation": "sign", "path": "alpha", "message_hex": hex::encode(b"record #1") })).await;
    assert_eq!(ed["signature"], SIG_A_RECORD_1);

    // The wasm build's secp256k1 key.
    let wasm = probe("wasm-secp");
    let keys = || keys_for(&wasm, &seeds_of("wasm-secp"));
    let address = answer(&wasm, keys(), json!({ "operation": "evm_address", "path": "code-evm" })).await;
    assert_eq!((address["public_key"].as_str(), address["evm_address"].as_str()), (Some(SECP_PUB_B), Some(SECP_EVM_B)), "{address}");
    let checked =
        answer(&wasm, keys(), json!({ "operation": "sign_and_verify", "path": "code-evm", "message_hex": KECCAK_RECORD_1 })).await;
    assert_eq!(checked["status"], "ok", "{checked}");
}

/// The host's `sign-nep413` answers the guest-built signature byte for byte —
/// PyNaCl's — and refuses a secp256k1 key and a nonce that is not 32 bytes.
#[tokio::test]
async fn the_host_nep413_signature_is_the_guest_built_one() {
    use base64::Engine;
    let wasm = probe("project");
    let request = |operation: &str, callback: Option<&str>| {
        json!({
            "operation": operation, "path": "alpha",
            "message": "Login to example.com", "recipient": "example.com",
            "nonce_hex": hex::encode(nonce()), "callback_url": callback,
        })
    };
    for (callback, pinned) in [(None, NEP413_SIGNATURE), (Some("https://example.com/cb"), NEP413_SIGNATURE_CB)] {
        let host = answer(&wasm, project_keys(&wasm), request("host_nep413", callback)).await;
        let guest = answer(&wasm, project_keys(&wasm), request("sign_nep413", callback)).await;
        assert_eq!(host["status"], "ok", "{host}");
        for field in ["accountId", "publicKey", "signature"] {
            assert_eq!(host[field], guest[field], "{field}: host {host} / guest {guest}");
        }
        assert_eq!(host["signature"], pinned, "PyNaCl's signature");
        assert_eq!(host["publicKey"], NEP413_PUBLIC_KEY);
        assert_eq!(host["accountId"], PUB_A);
        let sig = base64::engine::general_purpose::STANDARD.decode(host["signature"].as_str().unwrap()).unwrap();
        assert!(verify(PUB_A, &nep413_hash("Login to example.com", &nonce(), "example.com", callback), &sig));
    }
    for bad_nonce in ["", "00", &hex::encode([0u8; 31]), &hex::encode([0u8; 33])] {
        let mut ask = request("host_nep413", None);
        ask["nonce_hex"] = json!(bad_nonce);
        let refused = answer(&wasm, project_keys(&wasm), ask).await;
        assert_eq!(refused["status"], "err", "{refused}");
        assert!(refused["message"].as_str().unwrap().contains("must be exactly 32"), "{refused}");
    }
    let mut long = request("host_nep413", None);
    long["recipient"] = json!("r".repeat(2049));
    let refused = answer(&wasm, project_keys(&wasm), long).await;
    assert!(refused["message"].as_str().unwrap().contains("recipient is 2049 bytes; at most 2048"), "{refused}");

    // A secp256k1 key: the host refuses, and so does the guest-built op.
    let wasm = probe("project-secp");
    let mut on_evm = request("host_nep413", None);
    on_evm["path"] = json!("evm");
    let refused = answer(&wasm, secp_keys(&wasm), on_evm.clone()).await;
    assert_eq!(refused["status"], "err", "{refused}");
    assert!(refused["message"].as_str().unwrap().contains("\"evm\" is secp256k1"), "{refused}");
    on_evm["operation"] = json!("sign_nep413");
    let refused = answer(&wasm, secp_keys(&wasm), on_evm).await;
    assert_eq!(refused["status"], "err", "{refused}");
    // Its ed25519 key signs as in the project build.
    let host = answer(&wasm, secp_keys(&wasm), request("host_nep413", None)).await;
    assert_eq!(host["signature"], NEP413_SIGNATURE);
}
