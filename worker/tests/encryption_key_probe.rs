//! `wasi-examples/signing-key-probe`'s encryption builds through the executor,
//! with injected keys.
//!
//! What a guest sees of the `outlayer:encryption-keys` host interface: a round
//! trip, a ciphertext sealed by an independent implementation (libsodium)
//! opening inside the guest, the pinned `mac`, every attack answered as an
//! `err` inside a run that succeeds, every vault mismatch, the two families
//! apart at one path, no key byte anywhere the guest can look — and a module
//! that declares encryption keys and is handed none refused before it runs.
//!
//! And raw storage, through the `encryption-storage` build: the guest's
//! `near:storage` calls go through the worker's real storage client to an
//! in-process coordinator and keystore ([`FakeStorage`]) that keep the
//! coordinator's rule — a record keeps its mode, a write in the other mode is
//! a 409 — so the round trips, the mode errors both ways, compare-and-swap,
//! and records sealed with an encryption key and stored raw under a mac are
//! seen as the guest sees them. Those tests run in a release build only
//! (`cargo test --release --test encryption_key_probe`): the storage client is
//! reqwest's blocking one, and in a debug build reqwest asserts that it is not
//! inside a tokio runtime — which a wasmtime run always is.
//!
//! Run with: cargo test --test encryption_key_probe
//! The probe must be built first: wasi-examples/signing-key-probe/build.sh

use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use offchainvm_worker::api_client::{ExecutionResult, ResourceLimits, ResponseFormat};
use offchainvm_worker::encryption_keys::EncryptionKeys;
use offchainvm_worker::executor::{Executor, RunKeys};
use offchainvm_worker::outlayer_storage::StorageConfig;
use offchainvm_worker::signing_keys::{SeedHex, SigningKeys};
use serde_json::{json, Value};

/// The keystore's pinned encryption keys (`crypto.rs`,
/// `encryption_key_pinned_vectors`): the project key of bob at `records`, and
/// two wasm keys.
const KEY_A: &str = "4324b148cb409d9a56e27a37c0cfbc4787481db4dec90cfcd2219a091c4a5d0a";
const KEY_B: &str = "d5c8e2c2561e2102cfc400e8e3a7c3031745e55e7820d9d2a298b8e1a977e65d";
const KEY_C: &str = "070db0b5ad8a6028a1125a3162cec09243edd7b80884f7571b8dcdae9bc5267f";
/// A signing seed, for the signing key the `encryption` build declares at
/// `alpha` beside its encryption key there.
const SEED_A: &str = "b5ca092c9bb7c321f2d6f69c6eb147907d5df9fcc2309552786e7502706a7493";
const PUB_A: &str = "a31824c9aac23c954e90eba38553aee73658cf09c57b5f2a124c26ade2da2e52";

/// `0x01 || nonce 00..17 || XChaCha20-Poly1305(KEY_A, "record #1", aad
/// "storage-key-1")`, sealed with libsodium (PyNaCl).
const SEALED_BY_LIBSODIUM: &str =
    "01000102030405060708090a0b0c0d0e0f10111213141516179fbbdc1be35f2c9c516c5e6d25c709a68fe569a22811382927";
/// `HMAC-SHA256(HMAC-SHA256(KEY_A, "outlayer:encryption-keys:v1:mac"), "alice's inbox")`, Python `hmac`.
const MAC_A_INBOX: &str = "51f41e345c29ef105e29b11df910df64ee85f36bf767d08c71ae9474ee3a7b2b";

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

fn hexes(pairs: &[(&str, &str)]) -> BTreeMap<String, SeedHex> {
    serde_json::from_value(json!(pairs.iter().map(|(p, s)| (p.to_string(), s.to_string())).collect::<BTreeMap<_, _>>()))
        .unwrap()
}

fn manifest(wasm: &[u8]) -> offchainvm_worker::connector_manifest::ProjectManifest {
    offchainvm_worker::connector_manifest::manifest_from_wasm(wasm)
        .expect("the manifest reads")
        .expect("the probe carries a manifest")
}

/// The keys `wasm` declares, both families, as the keystore's answer would
/// hand them over.
fn keys_for(wasm: &[u8], encryption: &[(&str, &str)], signing: &[(&str, &str)]) -> RunKeys {
    let m = manifest(wasm);
    let enc = m.encryption_keys.clone().unwrap_or_default();
    let sig = m.signing_keys.clone().unwrap_or_default();
    RunKeys {
        encryption: (!enc.is_empty())
            .then(|| EncryptionKeys::from_keystore(&enc, hexes(encryption)).expect("the encryption keys the manifest declares")),
        signing: (!sig.is_empty())
            .then(|| SigningKeys::from_keystore(&sig, hexes(signing)).expect("the signing keys the manifest declares")),
    }
}

/// The `encryption` build's keys: signing `alpha`, encryption `alpha` and `beta`.
fn enc_keys(wasm: &[u8]) -> RunKeys {
    keys_for(wasm, &[("alpha", KEY_A), ("beta", KEY_B)], &[("alpha", SEED_A)])
}

fn vault_keys(wasm: &[u8]) -> RunKeys {
    keys_for(wasm, &[("alpha", KEY_A), ("treasury", KEY_B)], &[])
}

async fn run(wasm: &[u8], keys: RunKeys, input: Value) -> ExecutionResult {
    run_with(wasm, keys, input, None).await
}

/// One run, with storage for the project account `bob.near` when `storage`
/// is given — the `encryption-storage` build imports `near:storage` and does
/// not start without it.
async fn run_with(wasm: &[u8], keys: RunKeys, input: Value, storage: Option<&FakeStorage>) -> ExecutionResult {
    let executor = Executor::new(10_000_000_000, false);
    let limits = ResourceLimits { max_instructions: 10_000_000_000, max_memory_mb: 128, max_execution_seconds: 60 };
    let sha = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(wasm))
    };
    let env: HashMap<String, String> = [("NEAR_USER_ACCOUNT_ID", "bob.near"), ("NEAR_NETWORK_ID", "testnet")]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    executor
        .with_keys(keys)
        .execute(
            wasm,
            Some(&sha),
            input.to_string().as_bytes(),
            &limits,
            Some(env),
            Some("wasm32-wasip2"),
            &ResponseFormat::Json,
            storage.map(FakeStorage::config),
            None,
            None,
            None,
        )
        .await
        .expect("the executor answers")
}

async fn answer(wasm: &[u8], keys: RunKeys, input: Value) -> Value {
    answer_with(wasm, keys, input, None).await
}

async fn answer_with(wasm: &[u8], keys: RunKeys, input: Value, storage: Option<&FakeStorage>) -> Value {
    let result = run_with(wasm, keys, input.clone(), storage).await;
    assert!(result.success, "{input}: the run failed: {:?}", result.error);
    match result.output {
        Some(offchainvm_worker::api_client::ExecutionOutput::Json(v)) => v,
        other => panic!("{input}: expected JSON output, got {other:?}"),
    }
}

/// Seal in one run, open in the next: the same key across runs, and what the
/// guest sealed opens under an independent XChaCha20-Poly1305 with the
/// keystore's key; what libsodium sealed opens inside the guest; the mac is
/// the pinned one.
#[tokio::test]
async fn a_round_trip_across_runs_and_independent_implementations() {
    let wasm = probe("encryption");
    let pt = b"record #1";
    let sealed = answer(
        &wasm,
        enc_keys(&wasm),
        json!({ "operation": "encrypt", "path": "alpha", "plaintext_hex": hex::encode(pt), "aad_hex": hex::encode(b"row-1") }),
    )
    .await;
    assert_eq!(sealed["status"], "ok", "{sealed}");
    let ct = hex::decode(sealed["ciphertext"].as_str().unwrap()).unwrap();
    assert_eq!(ct.len(), pt.len() + 41);
    assert_eq!(ct[0], 0x01);
    {
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};
        let cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(&hex::decode(KEY_A).unwrap()).unwrap();
        let opened = cipher
            .decrypt(chacha20poly1305::XNonce::from_slice(&ct[1..25]), Payload { msg: &ct[25..], aad: b"row-1" })
            .expect("an independent AEAD opens what the guest sealed");
        assert_eq!(opened, pt);
    }
    let opened = answer(
        &wasm,
        enc_keys(&wasm),
        json!({ "operation": "decrypt", "path": "alpha", "ciphertext_hex": hex::encode(&ct), "aad_hex": hex::encode(b"row-1") }),
    )
    .await;
    assert_eq!(opened["plaintext"], hex::encode(pt), "{opened}");

    let libsodium = answer(
        &wasm,
        enc_keys(&wasm),
        json!({ "operation": "decrypt", "path": "alpha", "ciphertext_hex": SEALED_BY_LIBSODIUM, "aad_hex": hex::encode(b"storage-key-1") }),
    )
    .await;
    assert_eq!(libsodium["plaintext"], hex::encode(b"record #1"), "{libsodium}");

    let mac = answer(&wasm, enc_keys(&wasm), json!({ "operation": "mac", "path": "alpha", "plaintext_hex": hex::encode(b"alice's inbox") })).await;
    assert_eq!(mac["mac"], MAC_A_INBOX, "{mac}");

    let checks = answer(
        &wasm,
        enc_keys(&wasm),
        json!({ "operation": "encrypt_and_decrypt", "path": "beta", "plaintext_hex": "00ff", "aad_hex": "" }),
    )
    .await;
    assert_eq!(checks["status"], "ok", "{checks}");

    let all = answer(&wasm, enc_keys(&wasm), json!({ "operation": "all_encryption_keys" })).await;
    assert_eq!(all["status"], "ok", "{all}");
    assert_eq!(all["keys"].as_object().unwrap().len(), 2);
}

/// One path in both families: two unrelated keys, each reached only through
/// its own interface.
#[tokio::test]
async fn the_families_are_apart_at_one_path() {
    let wasm = probe("encryption");
    let pk = answer(&wasm, enc_keys(&wasm), json!({ "operation": "public_key", "path": "alpha" })).await;
    assert_eq!(pk["public_key"], PUB_A, "the signing key at alpha is the signing seed's: {pk}");
    let mac = answer(&wasm, enc_keys(&wasm), json!({ "operation": "mac", "path": "alpha", "plaintext_hex": hex::encode(b"alice's inbox") })).await;
    assert_eq!(mac["mac"], MAC_A_INBOX, "the encryption key at alpha is the encryption key's: {mac}");
    let sign_beta = answer(&wasm, enc_keys(&wasm), json!({ "operation": "sign", "path": "beta", "message_hex": "00" })).await;
    assert_eq!(sign_beta["status"], "err", "beta is an encryption path only: {sign_beta}");
    assert!(sign_beta["message"].as_str().unwrap().contains("no signing key at path"), "{sign_beta}");
}

#[tokio::test]
async fn every_attack_is_an_err_and_the_run_succeeds() {
    let common: &[(&str, &str, &str)] = &[
        ("undeclared_path", "err", "no encryption key at path"),
        ("empty_path", "err", "no encryption key at path"),
        ("colon_path", "err", "no encryption key at path"),
        ("wrong_aad", "err", "decryption failed"),
        ("tampered_tag", "err", "decryption failed"),
        ("tampered_body", "err", "decryption failed"),
        ("tampered_nonce", "err", "decryption failed"),
        ("bad_format_marker", "err", "decryption failed"),
        ("truncated", "err", "decryption failed"),
        ("shorter_than_overhead", "err", "decryption failed"),
        ("empty_ciphertext", "err", "decryption failed"),
        ("cross_path", "err", "decryption failed"),
        ("oversized_plaintext", "err", "at most 262144"),
        ("oversized_aad", "err", "aad is"),
        ("oversized_data", "err", "at most 262144"),
        ("oversized_ciphertext", "err", "ciphertext is"),
        ("plaintext_at_cap", "ok", "exactly 262144 bytes"),
        ("vault_when_none_declared", "err", "declared without a vault"),
        ("mac_determinism", "ok", "one name, one tag"),
        ("mac_separation", "ok", "a tag is not a ciphertext"),
    ];
    let variants: Vec<(&str, fn(&[u8]) -> RunKeys, Vec<(&str, &str, &str)>)> = vec![
        (
            "encryption",
            enc_keys,
            vec![
                ("vault_missing_when_declared", "n/a", "no encryption key with a vault"),
                ("vault_wrong_when_declared", "n/a", "no encryption key with a vault"),
                ("encryption_path_is_not_a_signing_path", "err", "no signing key at path \"beta\""),
                ("signing_path_is_not_an_encryption_path", "n/a", "every signing path here is also an encryption path"),
            ],
        ),
        (
            "encryption-vault",
            vault_keys,
            vec![
                ("vault_missing_when_declared", "err", "names none"),
                ("vault_wrong_when_declared", "err", "names vault \"vault.attacker.near\""),
                ("encryption_path_is_not_a_signing_path", "err", "no signing key at path \"alpha\""),
                ("signing_path_is_not_an_encryption_path", "n/a", "every signing path here is also an encryption path"),
            ],
        ),
    ];
    for (variant, keys, extra) in variants {
        let wasm = probe(variant);
        let all = answer(&wasm, keys(&wasm), json!({ "operation": "enc_attacks" })).await;
        assert_eq!(all["status"], "ok", "{variant}: {all}");
        let results = all["results"].as_array().expect("results");
        let rows: Vec<(&str, &str, &str)> = common.iter().copied().chain(extra).collect();
        assert_eq!(results.len(), rows.len(), "{variant}: {all}");
        for (name, status, says) in rows {
            let r = results.iter().find(|r| r["name"] == name).unwrap_or_else(|| panic!("{variant}: no {name}"));
            assert_eq!(r["status"], status, "{variant} {name}: {r}");
            let message = r["message"].as_str().unwrap();
            assert!(message.contains(says), "{variant} {name}: {message}");
            assert!(message.len() < 400, "{variant} {name}: a reason, not an echo ({} bytes)", message.len());
            if says == "decryption failed" {
                assert_eq!(message, "decryption failed", "{variant} {name}: no detail on a failure to open");
            }
        }
    }
    // The wasm build: one key, bound to the build.
    let wasm = probe("encryption-wasm");
    let keys = || keys_for(&wasm, &[("code", KEY_C)], &[]);
    let all = answer(&wasm, keys(), json!({ "operation": "enc_attacks" })).await;
    let cross = all["results"].as_array().unwrap().iter().find(|r| r["name"] == "cross_path").unwrap().clone();
    assert_eq!(cross["status"], "n/a", "{cross}");
    let checks = answer(&wasm, keys(), json!({ "operation": "encrypt_and_decrypt", "path": "code", "plaintext_hex": "61", "aad_hex": "62" })).await;
    assert_eq!(checks["status"], "ok", "{checks}");
}

#[tokio::test]
async fn every_vault_mismatch_is_an_err() {
    let wasm = probe("encryption-vault");
    let ask = |op: &str, path: &str, vault: Option<&str>| {
        json!({ "operation": op, "path": path, "vault": vault, "plaintext_hex": "00", "aad_hex": "" })
    };
    for (label, input, status, says) in [
        ("treasury with none", ask("encrypt", "treasury", None), "err", "names none"),
        ("treasury with another vault", ask("mac", "treasury", Some("vault.mallory.near")), "err", "names vault \"vault.mallory.near\""),
        ("treasury with an empty vault", ask("encrypt", "treasury", Some("")), "err", "names vault \"\""),
        ("alpha with a vault", ask("mac", "alpha", Some("vault.alice.near")), "err", "declared without a vault"),
        ("treasury with its vault", ask("encrypt_and_decrypt", "treasury", Some("vault.alice.near")), "ok", "sealed and opened"),
        ("alpha with none", ask("mac", "alpha", None), "ok", "mac"),
    ] {
        let got = answer(&wasm, vault_keys(&wasm), input).await;
        assert_eq!(got["status"], status, "{label}: {got}");
        assert!(got["message"].as_str().unwrap().contains(says), "{label}: {got}");
    }
}

/// Nothing of a key reaches the guest — not the AEAD key, not the mac
/// subkey — in its environment, stdin, output or linear memory, searched
/// after every declared key has been used in the same run.
#[tokio::test]
async fn no_key_is_visible_to_the_guest() {
    const MASK: u8 = 0x5a;
    let masked = |bytes: &[u8]| hex::encode(bytes.iter().map(|b| b ^ MASK).collect::<Vec<u8>>());
    let mac_subkey = |key: &str| {
        use hmac::{Hmac, Mac};
        let mut mac = <Hmac<sha2::Sha256> as Mac>::new_from_slice(&hex::decode(key).unwrap()).unwrap();
        mac.update(b"outlayer:encryption-keys:v1:mac");
        mac.finalize().into_bytes().to_vec()
    };
    for (variant, keys) in [
        ("encryption", vec![("alpha", KEY_A), ("beta", KEY_B)]),
        ("encryption-vault", vec![("alpha", KEY_A), ("treasury", KEY_B)]),
        ("encryption-wasm", vec![("code", KEY_C)]),
    ] {
        let wasm = probe(variant);
        let signing: &[(&str, &str)] = if variant == "encryption" { &[("alpha", SEED_A)] } else { &[] };
        let mut needles = Vec::new();
        let mut secrets: Vec<Vec<u8>> = Vec::new();
        for (_, key) in &keys {
            let raw = hex::decode(key).unwrap();
            secrets.push(raw.clone());
            secrets.push(mac_subkey(key));
        }
        for raw in &secrets {
            needles.push(masked(raw));
            needles.push(masked(&raw[..8]));
            needles.push(masked(hex::encode(raw).as_bytes()));
        }
        let control = format!("\"path\": \"{}\"", keys[0].0);
        needles.push(masked(control.as_bytes()));

        let seen = answer(
            &wasm,
            keys_for(&wasm, &keys, signing),
            json!({ "operation": "what_i_can_see", "scan_masked_hex": needles }),
        )
        .await;
        assert_eq!(seen["status"], "ok", "{variant}: {seen}");
        let exercised: Vec<&Value> =
            seen["exercised"].as_array().unwrap().iter().filter(|e| e.get("encryption_path").is_some()).collect();
        assert_eq!(exercised.len(), keys.len(), "{variant}: {seen}");
        for e in exercised {
            assert_eq!((e["encrypt"].as_bool(), e["decrypt"].as_bool(), e["mac"].as_bool()), (Some(true), Some(true), Some(true)), "{variant}: {e}");
        }
        let scans = seen["memory_scans"].as_array().unwrap();
        let (control, key_scans) = scans.split_last().unwrap();
        assert!(control["found"].as_u64().unwrap() >= 1, "{variant}: the control needle must be found: {seen}");
        for (i, scan) in key_scans.iter().enumerate() {
            assert_eq!(scan["found"], 0, "{variant}: key needle {i} is in the guest's memory");
        }
        let text = seen.to_string().to_ascii_lowercase();
        for raw in &secrets {
            use base64::Engine;
            assert!(!text.contains(&hex::encode(raw)[..16]), "{variant}: a key is visible to the guest");
            assert!(!seen.to_string().contains(&base64::engine::general_purpose::STANDARD.encode(raw)), "{variant}");
        }
        for name in seen["env"].as_object().unwrap().keys() {
            let n = name.to_ascii_lowercase();
            assert!(!n.contains("encryption") && !n.contains("key"), "{variant}: {name}");
        }
    }
}

/// A module that declares encryption keys and is handed none — a keystore
/// that predates them — is refused before it runs; so is one handed other
/// keys, or encryption keys it does not declare.
#[tokio::test]
async fn a_module_that_declares_encryption_keys_and_receives_none_is_refused_before_running() {
    let wasm = probe("encryption");
    let signing_only = RunKeys { encryption: None, ..enc_keys(&wasm) };
    let refused = run(&wasm, signing_only, json!({ "operation": "all_encryption_keys" })).await;
    assert!(!refused.success, "a module declaring encryption keys ran without them");
    assert!(refused.output.is_none());
    let error = refused.error.unwrap();
    assert!(error.contains("declares encryption keys") && error.contains("given none"), "{error}");
    assert!(error.contains("\"alpha\"") && error.contains("\"beta\""), "{error}");
    assert_eq!(refused.instructions, 0, "refused before running: {error}");

    // An empty set is none.
    let empty = RunKeys { encryption: Some(EncryptionKeys::none()), ..enc_keys(&wasm) };
    let refused = run(&wasm, empty, json!({ "operation": "all_encryption_keys" })).await;
    assert!(!refused.success && refused.error.unwrap().contains("given none"));

    // The vault build's keys handed to this build: not its declaration.
    let other = vault_keys(&probe("encryption-vault"));
    let refused = run(&wasm, RunKeys { encryption: other.encryption, ..enc_keys(&wasm) }, json!({ "operation": "all_encryption_keys" })).await;
    assert!(!refused.success);
    assert!(refused.error.unwrap().contains("not the ones its manifest declares"));

    // Encryption keys handed to a build that declares none.
    let signing_build = probe("project");
    let enc = enc_keys(&wasm).encryption;
    let keys = keys_for(&signing_build, &[], &[("alpha", SEED_A), ("beta", SEED_A)]);
    let refused = run(&signing_build, RunKeys { encryption: enc, ..keys }, json!({ "operation": "all_public_keys" })).await;
    assert!(!refused.success);
    assert!(refused.error.unwrap().contains("handed to a module whose manifest declares none"));
}

// ── raw storage ─────────────────────────────────────────────────────────────

/// One stored record, as the coordinator keeps it.
#[derive(Clone, Debug)]
struct Row {
    key: Vec<u8>,
    value: Vec<u8>,
    encrypted: bool,
}

/// An in-process coordinator (`/storage/*`) and keystore (`/storage/encrypt`,
/// `/storage/decrypt`) on one port, holding one account's records in memory.
/// It keeps the coordinator's rules: a write in the other mode than the
/// stored record's is `409 storage_mode_mismatch` and changes nothing;
/// set-if-absent inserts only where no record is, in either mode;
/// set-if-equals compares the stored bytes and the mode. The keystore's
/// "encryption" is a reversible marker — what matters here is which mode a
/// record is in and that raw records never reach the keystore, which
/// [`FakeStorage::keystore_calls`] counts.
struct FakeStorage {
    url: String,
    rows: Arc<Mutex<BTreeMap<String, Row>>>,
    keystore_calls: Arc<Mutex<usize>>,
}

const SEALED_BY_FAKE_KEYSTORE: &[u8] = b"fake-keystore:";

fn seal_fake(bytes: &[u8]) -> Vec<u8> {
    [SEALED_BY_FAKE_KEYSTORE, bytes].concat()
}

fn open_fake(bytes: &[u8]) -> Option<Vec<u8>> {
    bytes.strip_prefix(SEALED_BY_FAKE_KEYSTORE).map(<[u8]>::to_vec)
}

fn bytes_of(v: &Value) -> Vec<u8> {
    v.as_array().map(|a| a.iter().filter_map(|b| b.as_u64().map(|b| b as u8)).collect()).unwrap_or_default()
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn unb64(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(s).unwrap_or_default()
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

impl FakeStorage {
    fn start() -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let url = format!("http://{}", listener.local_addr().expect("addr"));
        let rows: Arc<Mutex<BTreeMap<String, Row>>> = Arc::default();
        let keystore_calls: Arc<Mutex<usize>> = Arc::default();
        let (r, k) = (Arc::clone(&rows), Arc::clone(&keystore_calls));
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let Some((path, body)) = read_request(&mut stream) else { continue };
                let (code, reply) = Self::answer(&r, &k, &path, &body);
                let response = format!(
                    "HTTP/1.1 {code} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                    reply.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        FakeStorage { url, rows, keystore_calls }
    }

    fn config(&self) -> StorageConfig {
        StorageConfig {
            coordinator_url: self.url.clone(),
            coordinator_token: "coordinator-test-token".to_string(),
            keystore_url: self.url.clone(),
            keystore_token: "keystore-test-token".to_string(),
            project_uuid: "p-test".to_string(),
            wasm_hash: "wasm-test".to_string(),
            account_id: "bob.near".to_string(),
            keystore_tee_session_id: None,
        }
    }

    fn keystore_calls(&self) -> usize {
        *self.keystore_calls.lock().unwrap()
    }

    /// The record stored under the name `key`.
    fn row(&self, key: &str) -> Option<Row> {
        self.rows.lock().unwrap().get(&sha256_hex(key.as_bytes())).cloned()
    }

    fn answer(rows: &Mutex<BTreeMap<String, Row>>, keystore_calls: &Mutex<usize>, path: &str, body: &Value) -> (u16, String) {
        let mut rows = rows.lock().unwrap();
        let hash = body["key_hash"].as_str().unwrap_or_default().to_string();
        let encrypted = body["is_encrypted"].as_bool().unwrap_or(true);
        let mismatch = |stored: bool| (409, json!({ "error": "storage_mode_mismatch", "stored_is_encrypted": stored }).to_string());
        match path.split('?').next().unwrap_or_default() {
            "/storage/encrypt" => {
                *keystore_calls.lock().unwrap() += 1;
                let key = body["key"].as_str().unwrap_or_default();
                let value = unb64(body["value_base64"].as_str().unwrap_or_default());
                (
                    200,
                    json!({
                        "encrypted_key_base64": b64(&seal_fake(key.as_bytes())),
                        "encrypted_value_base64": b64(&seal_fake(&value)),
                        "key_hash": sha256_hex(key.as_bytes()),
                    })
                    .to_string(),
                )
            }
            "/storage/decrypt" => {
                *keystore_calls.lock().unwrap() += 1;
                let key = open_fake(&unb64(body["encrypted_key_base64"].as_str().unwrap_or_default()));
                let value = open_fake(&unb64(body["encrypted_value_base64"].as_str().unwrap_or_default()));
                match (key, value) {
                    (Some(k), Some(v)) => (200, json!({ "key": String::from_utf8_lossy(&k), "value_base64": b64(&v) }).to_string()),
                    _ => (400, json!({ "error": "not sealed by this keystore" }).to_string()),
                }
            }
            "/storage/set" => {
                if let Some(stored) = rows.get(&hash) {
                    if stored.encrypted != encrypted {
                        return mismatch(stored.encrypted);
                    }
                }
                rows.insert(hash, Row { key: bytes_of(&body["encrypted_key"]), value: bytes_of(&body["encrypted_value"]), encrypted });
                (200, String::new())
            }
            "/storage/get" => match rows.get(&hash) {
                Some(r) => (
                    200,
                    json!({ "exists": true, "encrypted_key": r.key, "encrypted_value": r.value, "is_encrypted": r.encrypted }).to_string(),
                ),
                None => (200, json!({ "exists": false }).to_string()),
            },
            "/storage/has" => (200, json!({ "exists": rows.contains_key(&hash) }).to_string()),
            "/storage/delete" => match rows.remove(&hash) {
                Some(_) => (200, String::new()),
                None => (404, String::new()),
            },
            "/storage/list" => {
                let keys: Vec<Value> = rows
                    .iter()
                    .map(|(h, r)| {
                        json!({ "key_hash": h, "encrypted_key": r.key, "encrypted_value": r.value, "wasm_hash": "wasm-test", "is_encrypted": r.encrypted })
                    })
                    .collect();
                (200, json!({ "total": keys.len(), "keys": keys }).to_string())
            }
            "/storage/set-if-absent" => {
                let inserted = !rows.contains_key(&hash);
                if inserted {
                    rows.insert(hash, Row { key: bytes_of(&body["encrypted_key"]), value: bytes_of(&body["encrypted_value"]), encrypted });
                }
                (200, json!({ "inserted": inserted }).to_string())
            }
            "/storage/set-if-equals" => match rows.get_mut(&hash) {
                Some(r) if r.encrypted != encrypted => mismatch(r.encrypted),
                Some(r) if r.value == bytes_of(&body["expected_encrypted_value"]) => {
                    r.key = bytes_of(&body["new_encrypted_key"]);
                    r.value = bytes_of(&body["new_encrypted_value"]);
                    (200, json!({ "updated": true }).to_string())
                }
                Some(r) => (
                    200,
                    json!({ "updated": false, "current_encrypted_value": r.value, "current_encrypted_key": r.key }).to_string(),
                ),
                None => (200, json!({ "updated": false }).to_string()),
            },
            other => (404, json!({ "error": format!("no route {other}") }).to_string()),
        }
    }
}

/// One request: the request line's path and the JSON body sized by
/// `Content-Length`.
fn read_request(stream: &mut std::net::TcpStream) -> Option<(String, Value)> {
    let mut data = Vec::new();
    let mut buf = [0u8; 8192];
    let header_end = loop {
        let n = stream.read(&mut buf).ok()?;
        if n == 0 {
            return None;
        }
        data.extend_from_slice(&buf[..n]);
        if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
    };
    let head = String::from_utf8_lossy(&data[..header_end]).into_owned();
    let path = head.split_whitespace().nth(1)?.to_string();
    let content_length = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim().eq_ignore_ascii_case("content-length").then(|| value.trim().parse::<usize>().ok())?
        })
        .unwrap_or(0);
    while data.len() < header_end + content_length {
        let n = stream.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buf[..n]);
    }
    let body = &data[header_end..(header_end + content_length).min(data.len())];
    Some((path, if body.is_empty() { Value::Null } else { serde_json::from_slice(body).ok()? }))
}

/// Raw records across runs: stored as given, read back in a later run, the
/// conditional writes and has / delete / list on them — and not one keystore
/// call for any of it.
#[tokio::test(flavor = "multi_thread")]
#[cfg_attr(debug_assertions, ignore = "storage runs need a release build: reqwest's blocking client asserts in debug that it is outside a tokio runtime")]
async fn raw_records_round_trip_across_runs_without_the_keystore() {
    let wasm = probe("encryption-storage");
    let storage = FakeStorage::start();
    let ask = |input: Value| {
        let wasm = wasm.clone();
        let storage = &storage;
        async move { answer_with(&wasm, enc_keys(&wasm), input, Some(storage)).await }
    };

    let set = ask(json!({ "operation": "raw_set", "key": "raw/one", "value_hex": "00ff10" })).await;
    assert_eq!(set["status"], "ok", "{set}");
    let row = storage.row("raw/one").expect("the record is stored");
    assert_eq!((row.key.as_slice(), row.value.as_slice(), row.encrypted), (&b"raw/one"[..], &[0x00, 0xff, 0x10][..], false));

    let got = ask(json!({ "operation": "raw_get", "key": "raw/one" })).await;
    assert_eq!((got["found"].as_bool(), got["value_hex"].as_str()), (Some(true), Some("00ff10")), "{got}");
    let missing = ask(json!({ "operation": "raw_get", "key": "raw/none" })).await;
    assert_eq!((missing["status"].as_str(), missing["found"].as_bool()), (Some("ok"), Some(false)), "{missing}");

    let again = ask(json!({ "operation": "raw_set_if_absent", "key": "raw/one", "value_hex": "01" })).await;
    assert_eq!(again["inserted"], false, "{again}");
    let fresh = ask(json!({ "operation": "raw_set_if_absent", "key": "raw/two", "value_hex": "02" })).await;
    assert_eq!(fresh["inserted"], true, "{fresh}");

    let lose = ask(json!({ "operation": "raw_set_if_equals", "key": "raw/one", "expected_hex": "00", "new_hex": "aa" })).await;
    assert_eq!((lose["updated"].as_bool(), lose["current_hex"].as_str()), (Some(false), Some("00ff10")), "{lose}");
    let win = ask(json!({ "operation": "raw_set_if_equals", "key": "raw/one", "expected_hex": "00ff10", "new_hex": "aa" })).await;
    assert_eq!(win["updated"], true, "{win}");
    assert_eq!(storage.row("raw/one").unwrap().value, vec![0xaa]);

    let listed = ask(json!({ "operation": "storage_list", "prefix": "raw/" })).await;
    let mut names: Vec<&str> = listed["keys"].as_array().unwrap().iter().filter_map(Value::as_str).collect();
    names.sort();
    assert_eq!(names, ["raw/one", "raw/two"], "{listed}");

    let has = ask(json!({ "operation": "storage_has", "key": "raw/two" })).await;
    assert_eq!(has["exists"], true, "{has}");
    let deleted = ask(json!({ "operation": "storage_delete", "key": "raw/two" })).await;
    assert_eq!(deleted["deleted"], true, "{deleted}");
    let gone = ask(json!({ "operation": "storage_has", "key": "raw/two" })).await;
    assert_eq!(gone["exists"], false, "{gone}");

    assert_eq!(storage.keystore_calls(), 0, "a raw operation called the keystore");
}

/// The mode errors both ways, as the guest reads them.
#[tokio::test(flavor = "multi_thread")]
#[cfg_attr(debug_assertions, ignore = "storage runs need a release build: reqwest's blocking client asserts in debug that it is outside a tokio runtime")]
async fn a_record_is_read_only_in_its_own_mode() {
    let wasm = probe("encryption-storage");
    let storage = FakeStorage::start();
    let ask = |input: Value| {
        let wasm = wasm.clone();
        let storage = &storage;
        async move { answer_with(&wasm, enc_keys(&wasm), input, Some(storage)).await }
    };
    assert_eq!(ask(json!({ "operation": "enc_set", "key": "e", "value_hex": "01" })).await["status"], "ok");
    assert_eq!(ask(json!({ "operation": "raw_set", "key": "r", "value_hex": "02" })).await["status"], "ok");
    for (input, says) in [
        (json!({ "operation": "raw_get", "key": "e" }), "the record at this key was written encrypted; read it with get"),
        (json!({ "operation": "enc_get", "key": "r" }), "the record at this key was written raw; read it with get-raw"),
        (
            json!({ "operation": "raw_set", "key": "e", "value_hex": "03" }),
            "the record at this key was written encrypted; set-raw does not convert it — write it with set, or delete it first",
        ),
        (
            json!({ "operation": "enc_set", "key": "r", "value_hex": "03" }),
            "the record at this key was written raw; set does not convert it — write it with set-raw, or delete it first",
        ),
        (
            json!({ "operation": "raw_set_if_equals", "key": "e", "expected_hex": "01", "new_hex": "03" }),
            "the record at this key was written encrypted; compare it with set-if-equals",
        ),
    ] {
        let got = ask(input.clone()).await;
        assert_eq!((got["status"].as_str(), got["message"].as_str()), (Some("err"), Some(says)), "{input}: {got}");
    }
    let enc = ask(json!({ "operation": "enc_get", "key": "e" })).await;
    assert_eq!(enc["value_hex"], "01", "the encrypted record is untouched: {enc}");
    let raw = ask(json!({ "operation": "raw_get", "key": "r" })).await;
    assert_eq!(raw["value_hex"], "02", "the raw record is untouched: {raw}");
    // Deleted, a key takes a record in the other mode.
    assert_eq!(ask(json!({ "operation": "storage_delete", "key": "r" })).await["deleted"], true);
    assert_eq!(ask(json!({ "operation": "enc_set", "key": "r", "value_hex": "04" })).await["status"], "ok");
    assert!(storage.row("r").unwrap().encrypted);
}

#[tokio::test(flavor = "multi_thread")]
#[cfg_attr(debug_assertions, ignore = "storage runs need a release build: reqwest's blocking client asserts in debug that it is outside a tokio runtime")]
async fn every_storage_attack_answers_as_documented() {
    let wasm = probe("encryption-storage");
    let storage = FakeStorage::start();
    let all = answer_with(&wasm, enc_keys(&wasm), json!({ "operation": "raw_attacks", "key": "attacks" }), Some(&storage)).await;
    assert_eq!(all["status"], "ok", "{all}");
    let rows: &[(&str, &str, &str)] = &[
        ("get_raw_on_encrypted", "err", "written encrypted; read it with get"),
        ("get_on_raw", "err", "written raw; read it with get-raw"),
        ("set_raw_over_encrypted", "err", "written encrypted; set-raw does not convert it"),
        ("set_over_raw", "err", "written raw; set does not convert it"),
        ("cas_raw_on_encrypted", "err", "written encrypted; compare it with set-if-equals"),
        ("cas_on_raw", "err", "written raw; compare it with set-if-equals-raw"),
        ("increment_on_raw", "err", "written raw"),
        ("set_if_absent_raw_on_encrypted", "err", "not inserted"),
        ("set_if_absent_on_raw", "err", "not inserted"),
        ("set_if_absent_raw_on_raw", "err", "not inserted"),
        ("cas_raw_lose", "err", "not replaced"),
        ("cas_raw_absent", "err", "not replaced: no record"),
        ("cas_raw_win", "ok", "replaced, and the new bytes are stored"),
        ("delete_raw", "ok", "has, then deleted, then gone"),
        ("list_shows_raw_name", "ok", "the raw name is listed as written"),
    ];
    let results = all["results"].as_array().unwrap();
    assert_eq!(results.len(), rows.len(), "{all}");
    for (name, status, says) in rows {
        let r = results.iter().find(|r| r["name"] == *name).unwrap_or_else(|| panic!("no {name}"));
        assert_eq!(r["status"], *status, "{name}: {r}");
        assert!(r["message"].as_str().unwrap().contains(says), "{name}: {r}");
        if let Some(unchanged) = r.get("unchanged") {
            assert_eq!(unchanged, true, "{name}: the stored record changed: {r}");
        }
        if let Some(current) = r.get("current_is_stored") {
            assert_eq!(current, true, "{name}: a lost swap hands back the stored bytes: {r}");
        }
    }
    assert!(storage.rows.lock().unwrap().is_empty(), "every attack deletes its records");
}

/// `sealed_put` / `sealed_get`: sealed with the encryption key, bound to the
/// record's name as aad, stored raw under the hex of the name's mac. What is
/// stored is `0x01 ‖ nonce ‖ ciphertext ‖ tag` — opened here with the key and
/// that aad — and neither the name nor the value appears in the row.
#[tokio::test(flavor = "multi_thread")]
#[cfg_attr(debug_assertions, ignore = "storage runs need a release build: reqwest's blocking client asserts in debug that it is outside a tokio runtime")]
async fn a_sealed_record_is_ciphertext_under_a_mac_name() {
    let wasm = probe("encryption-storage");
    let storage = FakeStorage::start();
    let value = "the value of alice's inbox";
    let put = answer_with(
        &wasm,
        enc_keys(&wasm),
        json!({ "operation": "sealed_put", "path": "alpha", "key": "alice's inbox", "value": value }),
        Some(&storage),
    )
    .await;
    assert_eq!(put["status"], "ok", "{put}");
    assert_eq!(put["storage_key"], MAC_A_INBOX, "the storage key is the pinned mac of the name");
    let row = storage.row(MAC_A_INBOX).expect("stored under the mac");
    assert!(!row.encrypted);
    assert_eq!(row.key, MAC_A_INBOX.as_bytes());
    assert_eq!(row.value[0], 0x01);
    assert_eq!(row.value.len(), value.len() + 41);
    for needle in [value.as_bytes(), b"alice's inbox"] {
        assert!(!row.value.windows(needle.len()).any(|w| w == needle) && !row.key.windows(needle.len()).any(|w| w == needle));
    }
    {
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};
        let cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(&hex::decode(KEY_A).unwrap()).unwrap();
        let opened = cipher
            .decrypt(
                chacha20poly1305::XNonce::from_slice(&row.value[1..25]),
                Payload { msg: &row.value[25..], aad: MAC_A_INBOX.as_bytes() },
            )
            .expect("sealed under alpha, bound to the storage key");
        assert_eq!(opened, value.as_bytes());
    }
    let got = answer_with(&wasm, enc_keys(&wasm), json!({ "operation": "sealed_get", "path": "alpha", "key": "alice's inbox" }), Some(&storage)).await;
    assert_eq!((got["found"].as_bool(), got["value"].as_str()), (Some(true), Some(value)), "{got}");
    // Under another key the name maps elsewhere: nothing is there.
    let other = answer_with(&wasm, enc_keys(&wasm), json!({ "operation": "sealed_get", "path": "beta", "key": "alice's inbox" }), Some(&storage)).await;
    assert_eq!(other["found"], false, "{other}");
    // The ciphertext copied under another name does not open there.
    let raw = answer_with(&wasm, enc_keys(&wasm), json!({ "operation": "raw_get", "key": MAC_A_INBOX }), Some(&storage)).await;
    let moved = answer_with(
        &wasm,
        enc_keys(&wasm),
        json!({ "operation": "decrypt", "path": "alpha", "ciphertext_hex": raw["value_hex"], "aad_hex": hex::encode(b"another name") }),
        Some(&storage),
    )
    .await;
    assert_eq!(moved["message"], "decryption failed", "{moved}");
    assert_eq!(storage.keystore_calls(), 0, "sealed records never reach the keystore's storage encryption");
}

/// The predecessor build runs with its key; the typed build's manifest does
/// not read — `type` is an unknown field on an encryption key — so a run of it
/// is refused before anything is served.
#[tokio::test]
async fn the_predecessor_build_runs_and_the_typed_build_does_not_read() {
    let pred = probe("encryption-pred");
    let m = manifest(&pred);
    let declared = serde_json::to_value(m.encryption_keys.clone().unwrap()).unwrap();
    assert_eq!(declared[0]["caller"], "predecessor", "{declared}");
    let all = answer(&pred, keys_for(&pred, &[("alpha", KEY_A)], &[]), json!({ "operation": "all_encryption_keys" })).await;
    assert_eq!(all["status"], "ok", "{all}");

    let typed = probe("encryption-typed");
    let e = offchainvm_worker::connector_manifest::manifest_from_wasm(&typed).unwrap_err();
    assert!(e.contains("unknown field `type`"), "{e}");
}

/// The storage build without storage — what a direct run of its wasm URL is —
/// is refused before it runs; that is why no build meant for a direct run
/// imports `near:storage`.
#[tokio::test]
async fn the_storage_build_does_not_start_without_storage() {
    let wasm = probe("encryption-storage");
    let refused = run(&wasm, enc_keys(&wasm), json!({ "operation": "raw_get", "key": "k" })).await;
    assert!(!refused.success, "a module importing near:storage ran without storage");
    assert!(refused.error.unwrap().contains("near:storage/api"));
}
