//! A WASI module whose only job is exercising the `outlayer:signing-keys` and
//! `outlayer:encryption-keys` host functions, and raw storage.
//!
//! It imports those interfaces and WASI, nothing else; only the encryption
//! builds import `outlayer:encryption-keys`, and only the `encryption-storage`
//! builds import `near:storage` (the raw-storage operations and `sealed_put` /
//! `sealed_get`, encryption over raw records). It is separate from
//! `wallet-probe` because a module importing `outlayer:wallet` cannot run
//! without a wallet id (see `wasi-examples/wallet-probe/README.md`), while a
//! signing key needs no wallet at all.
//!
//! Thirteen builds, one per manifest (`manifests/`), chosen by feature:
//!
//! | feature | keys | runs as |
//! |---|---|---|
//! | `project` (default) | `alpha`, `beta` — `bind: "project"` | a project version |
//! | `project-pred` | `alpha` — `caller: "predecessor"` | a project version |
//! | `wasm` | `code` — `bind: "wasm"` | a direct run of its wasm URL |
//! | `project-vault` | `alpha`, and `treasury` with a vault | a project version whose owner has that vault |
//! | `project-secp` | `evm` (secp256k1), `alpha` (ed25519) — `bind: "project"` | a project version |
//! | `wasm-secp` | `code-evm` (secp256k1) — `bind: "wasm"` | a direct run of its wasm URL |
//! | `encryption` | signing `alpha`; encryption `alpha`, `beta` | a project version |
//! | `encryption-storage` | the `encryption` keys, and storage | a project version |
//! | `encryption-storage-pred` | the same, storage in the predecessor's cell (`storage_account: "predecessor"`) | a project version |
//! | `encryption-wasm` | encryption `code` — `bind: "wasm"` | a direct run of its wasm URL |
//! | `encryption-vault` | encryption `alpha`, and `treasury` with a vault | a project version whose owner has that vault |
//! | `encryption-pred` | encryption `alpha` — `caller: "predecessor"` | a project version |
//! | `encryption-typed` | encryption `alpha` with a `type` — refused before it runs | anything |
//!
//! `v2` changes one constant, so the same manifest gets a second sha256.
//!
//! Every answer is one JSON object with `status` (`ok`, `err`, `n/a` for an
//! attack that does not apply to this build, or `setup_failed` for a storage
//! attack whose record could not be written) and `message`. A refusal from the
//! host is an answer, never a crash: the run itself always succeeds.

use serde::Deserialize;
use serde_json::{json, Map, Value};

#[cfg(not(any(
    feature = "project",
    feature = "project-pred",
    feature = "wasm",
    feature = "project-vault",
    feature = "project-secp",
    feature = "wasm-secp",
    feature = "encryption",
    feature = "encryption-storage",
    feature = "encryption-storage-pred",
    feature = "encryption-wasm",
    feature = "encryption-vault",
    feature = "encryption-pred",
    feature = "encryption-typed"
)))]
compile_error!(
    "choose the manifest: --features project | project-pred | wasm | project-vault | project-secp | wasm-secp | encryption | \
     encryption-storage | encryption-storage-pred | encryption-wasm | encryption-vault | encryption-pred | encryption-typed"
);

/// How many manifest features this build names: exactly one is allowed.
const MANIFEST_FEATURES: usize = cfg!(feature = "project") as usize
    + cfg!(feature = "project-pred") as usize
    + cfg!(feature = "wasm") as usize
    + cfg!(feature = "project-vault") as usize
    + cfg!(feature = "project-secp") as usize
    + cfg!(feature = "wasm-secp") as usize
    + cfg!(feature = "encryption") as usize
    + cfg!(feature = "encryption-storage") as usize
    + cfg!(feature = "encryption-storage-pred") as usize
    + cfg!(feature = "encryption-wasm") as usize
    + cfg!(feature = "encryption-vault") as usize
    + cfg!(feature = "encryption-pred") as usize
    + cfg!(feature = "encryption-typed") as usize;
const _: () = assert!(MANIFEST_FEATURES == 1, "exactly one manifest feature: pass --no-default-features with one");

/// Embeds `$file` as the `outlayer.manifest` custom section — covered by the
/// wasm's sha256 — and keeps a readable copy for `all_public_keys` and the
/// attacks, which need the declared paths and vaults. The section itself is
/// not in linear memory, so it cannot be read back at runtime.
///
/// The section only on wasm: `link_section` takes a platform-specific name and
/// the host build (`cargo test`) rejects this one.
macro_rules! manifest {
    ($file:literal) => {
        #[cfg(target_arch = "wasm32")]
        #[used]
        #[link_section = "outlayer.manifest"]
        static OUTLAYER_MANIFEST: [u8; include_bytes!($file).len()] = *include_bytes!($file);

        const MANIFEST: &[u8] = include_bytes!($file);
    };
}

#[cfg(feature = "project")]
manifest!("../manifests/project.json");
#[cfg(feature = "project-pred")]
manifest!("../manifests/project-pred.json");
#[cfg(feature = "wasm")]
manifest!("../manifests/wasm.json");
#[cfg(feature = "project-vault")]
manifest!("../manifests/project-vault.json");
#[cfg(feature = "project-secp")]
manifest!("../manifests/project-secp.json");
#[cfg(feature = "wasm-secp")]
manifest!("../manifests/wasm-secp.json");
#[cfg(feature = "encryption")]
manifest!("../manifests/encryption.json");
#[cfg(feature = "encryption-storage")]
manifest!("../manifests/encryption-storage.json");
#[cfg(feature = "encryption-storage-pred")]
manifest!("../manifests/encryption-storage-pred.json");
#[cfg(feature = "encryption-wasm")]
manifest!("../manifests/encryption-wasm.json");
#[cfg(feature = "encryption-vault")]
manifest!("../manifests/encryption-vault.json");
#[cfg(feature = "encryption-pred")]
manifest!("../manifests/encryption-pred.json");
#[cfg(feature = "encryption-typed")]
manifest!("../manifests/encryption-typed.json");

/// Which build this is. Part of every answer, so the constant is in the binary
/// and `v2` really is another sha256.
const BUILD: &str = if cfg!(feature = "v2") { "signing-key-probe build 2" } else { "signing-key-probe build 1" };

/// The host's limit on one message an ed25519 key signs (`wit/signing-keys.wit`).
const MAX_MESSAGE: usize = 65536;

/// The one message length a secp256k1 key signs: a 32-byte prehash.
const SECP256K1_PREHASH: usize = 32;

/// Bindings for `outlayer:signing-keys`, generated from `wit/signing-keys.wit`
/// — a copy of the worker's `worker/wit/deps/signing-keys.wit`, which
/// `build.sh` diffs against.
mod signing_keys_host {
    wit_bindgen::generate!({
        world: "signing-keys-host",
        path: "wit",
    });
}
use signing_keys_host::outlayer::signing_keys::api as signing_keys;

/// Bindings for `outlayer:encryption-keys`, generated from
/// `wit-encryption/encryption-keys.wit` — a copy of the worker's
/// `worker/wit/deps/encryption-keys.wit`, which `build.sh` diffs against. Only
/// the encryption builds import it.
#[cfg(feature = "enc-api")]
mod encryption_keys_host {
    wit_bindgen::generate!({
        world: "encryption-keys-host",
        path: "wit-encryption",
    });
}
#[cfg(feature = "enc-api")]
use encryption_keys_host::outlayer::encryption_keys::api as encryption_keys;

#[cfg(feature = "enc-api")]
mod encryption;

/// Bindings for `near:storage`, generated from `wit-storage/storage.wit` — a
/// copy of the worker's `worker/wit/deps/storage.wit`, which `build.sh` diffs
/// against. Only the `encryption-storage` builds import it.
#[cfg(feature = "storage-api")]
mod storage_host {
    wit_bindgen::generate!({
        world: "storage-host",
        path: "wit-storage",
    });
}
#[cfg(feature = "storage-api")]
use storage_host::near::storage::api as storage;

#[cfg(feature = "storage-api")]
mod raw_storage;

#[derive(Debug, Deserialize, Default)]
struct Input {
    #[serde(default)]
    operation: String,
    /// The key's path, for `public_key`, `sign`, `sign_and_verify`,
    /// `sign_nep413`, `host_nep413`, `evm_address`.
    #[serde(default)]
    path: Option<String>,
    /// The vault the call names — the key's declared one, or none.
    #[serde(default)]
    vault: Option<String>,
    /// `sign`, `sign_and_verify`: the message, hex — for a secp256k1 key, the
    /// 32-byte prehash.
    #[serde(default)]
    message_hex: Option<String>,
    /// `sign_nep413`, `host_nep413`: the NEP-413 fields.
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    recipient: Option<String>,
    #[serde(default)]
    nonce_hex: Option<String>,
    #[serde(default)]
    callback_url: Option<String>,
    /// `attack`: which one.
    #[serde(default)]
    name: Option<String>,
    /// `what_i_can_see`: byte strings to look for in this module's own linear
    /// memory, each hex of the bytes XOR [`SCAN_MASK`] — so the needle itself
    /// is never in memory to be found.
    #[serde(default)]
    scan_masked_hex: Vec<String>,
    /// `encrypt`: the plaintext, hex. `mac`: the data, hex.
    #[serde(default)]
    #[cfg_attr(not(feature = "enc-api"), allow(dead_code))]
    plaintext_hex: Option<String>,
    /// `decrypt`: the ciphertext, hex.
    #[serde(default)]
    #[cfg_attr(not(feature = "enc-api"), allow(dead_code))]
    ciphertext_hex: Option<String>,
    /// `encrypt`, `decrypt`, `encrypt_and_decrypt`: the associated data, hex.
    #[serde(default)]
    #[cfg_attr(not(feature = "enc-api"), allow(dead_code))]
    aad_hex: Option<String>,
    /// The storage operations: the record's name — for `sealed_put` and
    /// `sealed_get`, the name the record is stored under the mac of; for
    /// `raw_attacks`, the prefix its records are written under.
    #[serde(default)]
    #[cfg_attr(not(feature = "storage-api"), allow(dead_code))]
    key: Option<String>,
    /// `sealed_put`: the value, as text.
    #[serde(default)]
    #[cfg_attr(not(feature = "storage-api"), allow(dead_code))]
    value: Option<String>,
    /// `raw_set`, `raw_set_if_absent`, `enc_set`: the value, hex.
    #[serde(default)]
    #[cfg_attr(not(feature = "storage-api"), allow(dead_code))]
    value_hex: Option<String>,
    /// `raw_set_if_equals`: the bytes expected, hex.
    #[serde(default)]
    #[cfg_attr(not(feature = "storage-api"), allow(dead_code))]
    expected_hex: Option<String>,
    /// `raw_set_if_equals`: the bytes to write, hex.
    #[serde(default)]
    #[cfg_attr(not(feature = "storage-api"), allow(dead_code))]
    new_hex: Option<String>,
    /// `storage_list`: the key prefix.
    #[serde(default)]
    #[cfg_attr(not(feature = "storage-api"), allow(dead_code))]
    prefix: Option<String>,
}

fn main() {
    let raw = read_stdin();
    let answer = match serde_json::from_str::<Input>(if raw.trim().is_empty() { "{}" } else { &raw }) {
        Ok(input) => run(&input, &raw),
        Err(e) => err(format!("input is not a JSON object this probe reads: {e}")),
    };
    emit(answer);
}

fn run(input: &Input, raw: &str) -> Value {
    let mut out = match input.operation.as_str() {
        "public_key" => with_path(input, |path, vault| public_key(path, vault)),
        "sign" => with_path(input, |path, vault| sign(path, vault, input.message_hex.as_deref())),
        "sign_and_verify" => with_path(input, |path, vault| sign_and_verify(path, vault, input.message_hex.as_deref())),
        "sign_nep413" => with_path(input, |path, vault| nep413_answer(input, path, vault)),
        "host_nep413" => with_path(input, |path, vault| host_nep413(input, path, vault)),
        "evm_address" => with_path(input, |path, vault| evm_address_answer(path, vault)),
        "all_public_keys" => all_public_keys(),
        "what_i_can_see" => what_i_can_see(raw, &input.scan_masked_hex),
        "attack" => match input.name.as_deref() {
            Some(name) => attack(name),
            None => err("attack needs a `name`; `attacks` runs them all".to_string()),
        },
        "attacks" => attacks(),
        #[cfg(feature = "enc-api")]
        "encrypt" | "decrypt" | "mac" | "encrypt_and_decrypt" | "all_encryption_keys" | "enc_attack" | "enc_attacks" => {
            encryption::run(input)
        }
        #[cfg(feature = "storage-api")]
        "raw_set" | "raw_get" | "raw_set_if_absent" | "raw_set_if_equals" | "enc_set" | "enc_get" | "storage_has"
        | "storage_delete" | "storage_list" | "sealed_put" | "sealed_get" | "raw_attack" | "raw_attacks" => raw_storage::run(input),
        other => err(format!(
            "unknown operation {other:?}; one of public_key, sign, sign_and_verify, sign_nep413, host_nep413, \
             evm_address, all_public_keys, what_i_can_see, attack, attacks"
        )),
    };
    if let Value::Object(map) = &mut out {
        map.insert("operation".into(), json!(input.operation));
        map.insert("build".into(), json!(BUILD));
    }
    out
}

fn with_path(input: &Input, f: impl FnOnce(&str, Option<&str>) -> Value) -> Value {
    match input.path.as_deref() {
        Some(path) => f(path, input.vault.as_deref()),
        None => err("this operation needs a `path`".to_string()),
    }
}

fn ok(message: impl Into<String>, fields: Value) -> Value {
    let mut map = Map::new();
    map.insert("status".into(), json!("ok"));
    map.insert("message".into(), json!(message.into()));
    if let Value::Object(extra) = fields {
        map.extend(extra);
    }
    Value::Object(map)
}

fn err(message: String) -> Value {
    json!({ "status": "err", "message": message })
}

// ── the operations ──────────────────────────────────────────────────────────

fn public_key(path: &str, vault: Option<&str>) -> Value {
    match signing_keys::public_key(path, vault) {
        Ok(pk) => ok("the host answered with the public key", json!({ "path": path, "vault": vault, "public_key": hex::encode(pk) })),
        Err(e) => err(e),
    }
}

fn sign(path: &str, vault: Option<&str>, message_hex: Option<&str>) -> Value {
    let message = match decode_message(message_hex) {
        Ok(m) => m,
        Err(e) => return err(e),
    };
    match (signing_keys::sign(path, vault, &message), signing_keys::public_key(path, vault)) {
        (Ok(sig), Ok(pk)) => ok(
            format!("signed {} bytes", message.len()),
            json!({ "path": path, "vault": vault, "signature": hex::encode(sig), "public_key": hex::encode(pk) }),
        ),
        (Err(e), _) | (_, Err(e)) => err(e),
    }
}

/// Sign, then verify the signature here, inside the guest, against the public
/// key the host gives — and check that a message one bit off does not verify.
/// A secp256k1 key (a 64-byte public key) is verified with k256, and its
/// signature must also be low-s and recover to the key.
fn sign_and_verify(path: &str, vault: Option<&str>, message_hex: Option<&str>) -> Value {
    let message = match decode_message(message_hex) {
        Ok(m) => m,
        Err(e) => return err(e),
    };
    let (sig, pk) = match (signing_keys::sign(path, vault, &message), signing_keys::public_key(path, vault)) {
        (Ok(sig), Ok(pk)) => (sig, pk),
        (Err(e), _) | (_, Err(e)) => return err(e),
    };
    if pk.len() == 64 {
        return secp_sign_and_verify(path, vault, &message, &sig, &pk);
    }
    let verified = verify(&pk, &message, &sig);
    let mut tampered = message.clone();
    match tampered.first_mut() {
        Some(b) => *b ^= 1,
        None => tampered.push(0),
    }
    let tampered_rejected = !verify(&pk, &tampered, &sig);
    let fields = json!({
        "path": path, "vault": vault,
        "signature": hex::encode(&sig), "public_key": hex::encode(&pk),
        "verified": verified, "tampered_rejected": tampered_rejected,
    });
    if verified && tampered_rejected {
        ok("the signature verifies inside the guest, and a changed message does not", fields)
    } else {
        let mut out = err(format!("in-guest verification: verified={verified} tampered_rejected={tampered_rejected}"));
        if let (Value::Object(map), Value::Object(extra)) = (&mut out, fields) {
            map.extend(extra);
        }
        out
    }
}

/// [`sign_and_verify`] for a secp256k1 key: the signature verifies over the
/// prehash, is low-s, recovers to the key with its `v`, and does not verify a
/// prehash one bit off.
fn secp_sign_and_verify(path: &str, vault: Option<&str>, prehash: &[u8], sig: &[u8], pk: &[u8]) -> Value {
    let checked = secp_check(pk, prehash, sig);
    let mut tampered = prehash.to_vec();
    tampered[0] ^= 1;
    let tampered_rejected = !secp_check(pk, &tampered, sig).verified;
    let fields = json!({
        "path": path, "vault": vault,
        "signature": hex::encode(sig), "public_key": hex::encode(pk),
        "evm_address": evm_address(pk),
        "verified": checked.verified, "recovered": checked.recovered, "low_s": checked.low_s, "v": checked.v,
        "tampered_rejected": tampered_rejected,
    });
    if checked.verified && checked.recovered && checked.low_s && tampered_rejected {
        ok("the secp256k1 signature verifies inside the guest, is low-s and recovers to the key; a changed prehash does not verify", fields)
    } else {
        let mut out = err(format!(
            "in-guest secp256k1 check: verified={} recovered={} low_s={} tampered_rejected={tampered_rejected}",
            checked.verified, checked.recovered, checked.low_s
        ));
        if let (Value::Object(map), Value::Object(extra)) = (&mut out, fields) {
            map.extend(extra);
        }
        out
    }
}

/// What the guest establishes about one secp256k1 signature `r ‖ s ‖ v`.
struct SecpCheck {
    verified: bool,
    recovered: bool,
    low_s: bool,
    v: Option<u8>,
}

/// Check `sig` (65 bytes) over `prehash` against `pk` (64 bytes `x ‖ y`).
fn secp_check(pk: &[u8], prehash: &[u8], sig: &[u8]) -> SecpCheck {
    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    let none = SecpCheck { verified: false, recovered: false, low_s: false, v: None };
    let mut sec1 = vec![0x04];
    sec1.extend_from_slice(pk);
    let (Ok(vk), Some((rs, v))) = (VerifyingKey::from_sec1_bytes(&sec1), sig.split_at_checked(64)) else { return none };
    let (Ok(signature), [v]) = (Signature::from_slice(rs), v) else { return none };
    let recovered = RecoveryId::from_byte(*v)
        .and_then(|id| VerifyingKey::recover_from_prehash(prehash, &signature, id).ok())
        .is_some_and(|k| k == vk);
    SecpCheck {
        verified: vk.verify_prehash(prehash, &signature).is_ok(),
        recovered,
        low_s: signature.normalize_s().is_none(),
        v: Some(*v),
    }
}

/// The EVM address of a secp256k1 public key `x ‖ y`: `0x` and the last 20
/// bytes of keccak256 of the 64 bytes, lowercase hex. `None` for any other
/// length.
fn evm_address(public_key: &[u8]) -> Option<String> {
    use sha3::{Digest, Keccak256};
    (public_key.len() == 64).then(|| format!("0x{}", hex::encode(&Keccak256::digest(public_key)[12..])))
}

fn evm_address_answer(path: &str, vault: Option<&str>) -> Value {
    match signing_keys::public_key(path, vault) {
        Ok(pk) => match evm_address(&pk) {
            Some(address) => ok(
                "keccak256 of the 64-byte public key, its last 20 bytes",
                json!({ "path": path, "vault": vault, "public_key": hex::encode(&pk), "evm_address": address }),
            ),
            None => err(format!("the key at {path:?} has a {}-byte public key; an EVM address needs a secp256k1 key", pk.len())),
        },
        Err(e) => err(e),
    }
}

fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    use ed25519_dalek::Verifier;
    let Ok(pk) = <[u8; 32]>::try_from(public_key) else { return false };
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&pk) else { return false };
    let Ok(sig) = ed25519_dalek::Signature::from_slice(signature) else { return false };
    vk.verify(message, &sig).is_ok()
}

fn decode_message(message_hex: Option<&str>) -> Result<Vec<u8>, String> {
    hex::decode(message_hex.unwrap_or_default()).map_err(|e| format!("message_hex is not hex: {e}"))
}

/// The signing keys this build declares, as its manifest says: `(path, vault)`.
fn declared() -> Vec<(String, Option<String>)> {
    declared_in("signing_keys")
}

/// The signing keys this build declares with their type: `(path, vault, type)`.
fn declared_typed() -> Vec<(String, Option<String>, String)> {
    let manifest: Value = serde_json::from_slice(MANIFEST).unwrap_or(Value::Null);
    manifest["signing_keys"]
        .as_array()
        .map(|keys| {
            keys.iter()
                .filter_map(|k| {
                    Some((k["path"].as_str()?.to_string(), k["vault"].as_str().map(str::to_string), k["type"].as_str()?.to_string()))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// A message every declared key signs: 32 bytes, the one length a secp256k1
/// key takes, and a fine ed25519 message.
fn sample_prehash(label: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(label.as_bytes()).into()
}

/// The keys of one family this build declares: `(path, vault)`.
fn declared_in(member: &str) -> Vec<(String, Option<String>)> {
    let manifest: Value = serde_json::from_slice(MANIFEST).unwrap_or(Value::Null);
    manifest[member]
        .as_array()
        .map(|keys| {
            keys.iter()
                .filter_map(|k| {
                    let path = k["path"].as_str()?.to_string();
                    Some((path, k["vault"].as_str().map(str::to_string)))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn all_public_keys() -> Value {
    let mut keys = Map::new();
    let mut failures = Vec::new();
    for (path, vault) in declared() {
        match signing_keys::public_key(&path, vault.as_deref()) {
            Ok(pk) => {
                keys.insert(path, json!({ "vault": vault, "public_key": hex::encode(pk) }));
            }
            Err(e) => failures.push(format!("{path}: {e}")),
        }
    }
    if failures.is_empty() {
        ok(format!("{} declared keys, each answered", keys.len()), json!({ "keys": keys }))
    } else {
        let mut out = err(failures.join("; "));
        out["keys"] = Value::Object(keys);
        out
    }
}

// ── NEP-413 (NEAR `signMessage`) ────────────────────────────────────────────
//
// The copyable part: a NEP-413 signature made with a signing key, in the shape
// a NEAR wallet's `signMessage` answers. Anything that verifies a wallet's
// NEP-413 signature verifies this one, against `publicKey`.

/// NEP-413's prefix: `2^31 + 413`, borsh-serialized as a little-endian `u32`
/// in front of the payload, so the signed bytes can never be a valid NEAR
/// transaction.
const NEP413_TAG: u32 = (1 << 31) + 413;

/// The NEP-413 payload, in the specification's field order — borsh encodes
/// fields in declaration order, so the order is part of the format.
#[derive(borsh::BorshSerialize)]
struct Nep413Payload {
    message: String,
    nonce: [u8; 32],
    recipient: String,
    callback_url: Option<String>,
}

/// What a wallet's `signMessage` answers.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct Nep413Signed {
    /// The NEAR implicit account of the key: its 32-byte public key, lowercase hex.
    account_id: String,
    /// `ed25519:` + base58 of the public key.
    public_key: String,
    /// The 64-byte ed25519 signature, base64.
    signature: String,
}

/// The 32 bytes NEP-413 signs: `sha256(borsh(NEP413_TAG) ++ borsh(payload))`.
fn nep413_hash(payload: &Nep413Payload) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut bytes = borsh::to_vec(&NEP413_TAG).expect("a u32 serializes");
    bytes.extend(borsh::to_vec(payload).expect("the payload serializes"));
    Sha256::digest(&bytes).into()
}

/// Sign a NEP-413 message with the declared key at `path`.
fn sign_nep413(path: &str, vault: Option<&str>, payload: &Nep413Payload) -> Result<Nep413Signed, String> {
    use base64::Engine;
    let public_key = signing_keys::public_key(path, vault)?;
    if public_key.len() != 32 {
        return Err(format!("NEP-413 is signed with an ed25519 key; the key at {path:?} is not one"));
    }
    let signature = signing_keys::sign(path, vault, &nep413_hash(payload))?;
    Ok(Nep413Signed {
        account_id: hex::encode(&public_key),
        public_key: format!("ed25519:{}", bs58::encode(&public_key).into_string()),
        signature: base64::engine::general_purpose::STANDARD.encode(signature),
    })
}

fn nep413_answer(input: &Input, path: &str, vault: Option<&str>) -> Value {
    let (Some(message), Some(recipient), Some(nonce_hex)) = (&input.message, &input.recipient, &input.nonce_hex) else {
        return err("sign_nep413 needs `message`, `recipient` and `nonce_hex` (32 bytes)".to_string());
    };
    let nonce: [u8; 32] = match hex::decode(nonce_hex).ok().and_then(|n| n.try_into().ok()) {
        Some(n) => n,
        None => return err("nonce_hex must be exactly 32 bytes of hex".to_string()),
    };
    let payload = Nep413Payload {
        message: message.clone(),
        nonce,
        recipient: recipient.clone(),
        callback_url: input.callback_url.clone(),
    };
    match sign_nep413(path, vault, &payload) {
        Ok(signed) => ok("signed a NEP-413 message", serde_json::to_value(signed).unwrap_or(Value::Null)),
        Err(e) => err(e),
    }
}

/// The same signature from the host's `sign-nep413`, which builds the NEP-413
/// bytes itself: the guest passes the fields and never assembles the payload.
/// The nonce goes to the host as given, whatever its length — the host says
/// whether it is 32 bytes.
fn host_nep413(input: &Input, path: &str, vault: Option<&str>) -> Value {
    let (Some(message), Some(recipient), Some(nonce_hex)) = (&input.message, &input.recipient, &input.nonce_hex) else {
        return err("host_nep413 needs `message`, `recipient` and `nonce_hex`".to_string());
    };
    let Ok(nonce) = hex::decode(nonce_hex) else {
        return err("nonce_hex is not hex".to_string());
    };
    match signing_keys::sign_nep413(path, vault, message, recipient, &nonce, input.callback_url.as_deref()) {
        Ok(signed) => ok(
            "the host signed a NEP-413 message",
            json!({ "accountId": signed.account_id, "publicKey": signed.public_key, "signature": signed.signature }),
        ),
        Err(e) => err(e),
    }
}

// ── what the guest can see ──────────────────────────────────────────────────

/// The mask `scan_masked_hex` needles are XORed with.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
const SCAN_MASK: u8 = 0x5a;

/// Everything this module can read about its run: every environment variable
/// with its value, its arguments, its stdin as it arrived, its working
/// directory and what the filesystem shows — and, for each masked needle, how
/// many times it occurs anywhere in this module's own linear memory.
///
/// Every declared key is used first — its public key read, a message signed —
/// so the memory scan runs after the host functions have had every chance to
/// leave something behind.
fn what_i_can_see(raw_stdin: &str, scan_masked_hex: &[String]) -> Value {
    let mut exercised = Vec::new();
    for (path, vault) in declared() {
        let public_key = signing_keys::public_key(&path, vault.as_deref()).map(hex::encode);
        let signature = signing_keys::sign(&path, vault.as_deref(), &sample_prehash("what_i_can_see")).map(hex::encode);
        exercised.push(json!({ "path": path, "public_key": public_key.is_ok(), "sign": signature.is_ok() }));
    }
    #[cfg(feature = "enc-api")]
    exercised.extend(encryption::exercise_all());
    let env: Map<String, Value> = std::env::vars_os()
        .map(|(k, v)| (k.to_string_lossy().into_owned(), json!(v.to_string_lossy())))
        .collect();
    let args: Vec<String> = std::env::args_os().map(|a| a.to_string_lossy().into_owned()).collect();
    let cwd = std::env::current_dir().map(|p| p.display().to_string()).map_err(|e| e.to_string());
    let mut dirs = Map::new();
    for dir in ["/", "."] {
        let listing = std::fs::read_dir(dir)
            .map(|entries| entries.filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().into_owned()).collect::<Vec<_>>())
            .map_err(|e| e.to_string());
        dirs.insert(dir.into(), json!(listing));
    }
    let mut scans = Vec::new();
    for masked_hex in scan_masked_hex {
        match hex::decode(masked_hex) {
            Ok(masked) if !masked.is_empty() => scans.push(json!({ "needle_len": masked.len(), "found": scan_memory(&masked) })),
            _ => scans.push(json!({ "error": "not a non-empty hex string" })),
        }
    }
    ok(
        "everything this module can read about its run",
        json!({
            "env": env,
            "args": args,
            "stdin": raw_stdin,
            "stdin_len": raw_stdin.len(),
            "cwd": match cwd { Ok(c) => json!(c), Err(e) => json!({ "error": e }) },
            "dirs": dirs,
            "memory_bytes": memory_bytes(),
            "memory_scans": scans,
            "exercised": exercised,
        }),
    )
}

#[cfg(target_arch = "wasm32")]
fn memory_bytes() -> usize {
    core::arch::wasm32::memory_size(0) * 65536
}

#[cfg(not(target_arch = "wasm32"))]
fn memory_bytes() -> usize {
    0
}

/// How many times the unmasked `masked` occurs in linear memory, read byte by
/// byte from address 1 to the end. Each memory byte is masked before it is
/// compared, so the unmasked needle is never assembled anywhere this scan
/// could find it.
#[cfg(target_arch = "wasm32")]
fn scan_memory(masked: &[u8]) -> usize {
    let end = memory_bytes();
    let read = |at: usize| unsafe { core::ptr::read_volatile(at as *const u8) };
    let mut found = 0;
    let mut at = 1;
    while at + masked.len() <= end {
        if read(at) ^ SCAN_MASK == masked[0] && (1..masked.len()).all(|j| read(at + j) ^ SCAN_MASK == masked[j]) {
            found += 1;
        }
        at += 1;
    }
    found
}

#[cfg(not(target_arch = "wasm32"))]
fn scan_memory(_masked: &[u8]) -> usize {
    0
}

// ── attacks ─────────────────────────────────────────────────────────────────

const ATTACKS: &[&str] = &[
    "undeclared_path",
    "empty_path",
    "colon_path",
    "traversal_path",
    "huge_path",
    "oversized_message",
    "message_at_cap",
    "vault_when_none_declared",
    "vault_missing_when_declared",
    "vault_wrong_when_declared",
    "determinism",
    "secp_message_not_32",
    "nep413_wrong_type",
    "nep413_bad_nonce",
];

fn attacks() -> Value {
    let results: Vec<Value> = ATTACKS
        .iter()
        .map(|name| {
            let mut one = attack(name);
            one["name"] = json!(name);
            one
        })
        .collect();
    ok(format!("{} attacks, each answered", results.len()), json!({ "results": results }))
}

/// One attack: `status` is what the host answered (`err` for a refusal, `ok`
/// for an answer), `n/a` when this build declares no key the attack needs.
fn attack(name: &str) -> Value {
    let keys = declared();
    let typed = declared_typed();
    let first = keys.first().cloned();
    let unvaulted = keys.iter().find(|(_, v)| v.is_none()).cloned();
    let vaulted = keys.iter().find(|(_, v)| v.is_some()).cloned();
    let of_type = |t: &str| typed.iter().find(|(_, _, ty)| ty == t).map(|(p, v, _)| (p.clone(), v.clone()));
    let first_ed = of_type("ed25519");
    let first_secp = of_type("secp256k1");
    let answered = |r: Result<Vec<u8>, String>, what: &str| match r {
        Err(e) => json!({ "status": "err", "message": e }),
        Ok(bytes) => json!({ "status": "ok", "message": format!("the host answered {what} ({} bytes)", bytes.len()) }),
    };
    let na = |why: &str| json!({ "status": "n/a", "message": why });
    match name {
        "undeclared_path" => answered(signing_keys::public_key("undeclared", None), "for an undeclared path"),
        "empty_path" => answered(signing_keys::sign("", None, b"x"), "for an empty path"),
        "colon_path" => match &first {
            Some((path, vault)) => answered(signing_keys::sign(&format!("{path}:x"), vault.as_deref(), b"x"), "for a path with ':'"),
            None => na("this build declares no key"),
        },
        "traversal_path" => match &first {
            Some((path, vault)) => answered(signing_keys::sign(&format!("../{path}"), vault.as_deref(), b"x"), "for a path with '../'"),
            None => na("this build declares no key"),
        },
        "huge_path" => answered(signing_keys::sign(&"a".repeat(1 << 20), None, b"x"), "for a 1 MiB path"),
        "oversized_message" => match &first_ed {
            Some((path, vault)) => answered(signing_keys::sign(path, vault.as_deref(), &vec![0u8; MAX_MESSAGE + 1]), "for a message over the cap"),
            None => na("this build declares no ed25519 key"),
        },
        "message_at_cap" => match &first_ed {
            Some((path, vault)) => {
                let message = vec![0x61u8; MAX_MESSAGE];
                match (signing_keys::sign(path, vault.as_deref(), &message), signing_keys::public_key(path, vault.as_deref())) {
                    (Ok(sig), Ok(pk)) if verify(&pk, &message, &sig) => {
                        json!({ "status": "ok", "message": format!("signed exactly {MAX_MESSAGE} bytes, and the signature verifies") })
                    }
                    (Ok(_), Ok(_)) => json!({ "status": "err", "message": "signed at the cap, and the signature does NOT verify" }),
                    (Err(e), _) | (_, Err(e)) => json!({ "status": "err", "message": e }),
                }
            }
            None => na("this build declares no ed25519 key"),
        },
        "vault_when_none_declared" => match &unvaulted {
            Some((path, _)) => answered(signing_keys::sign(path, Some("vault.attacker.near"), b"x"), "with a vault the key does not declare"),
            None => na("this build declares no key without a vault"),
        },
        "vault_missing_when_declared" => match &vaulted {
            Some((path, _)) => answered(signing_keys::sign(path, None, b"x"), "without the key's declared vault"),
            None => na("this build declares no key with a vault"),
        },
        "vault_wrong_when_declared" => match &vaulted {
            Some((path, _)) => answered(signing_keys::sign(path, Some("vault.attacker.near"), b"x"), "with another vault than the declared one"),
            None => na("this build declares no key with a vault"),
        },
        "determinism" => match &first {
            Some((path, vault)) => {
                let v = vault.as_deref();
                let message = sample_prehash("determinism");
                let calls = (
                    signing_keys::public_key(path, v),
                    signing_keys::public_key(path, v),
                    signing_keys::sign(path, v, &message),
                    signing_keys::sign(path, v, &message),
                );
                match calls {
                    (Ok(pk1), Ok(pk2), Ok(s1), Ok(s2)) if pk1 == pk2 && s1 == s2 => {
                        json!({ "status": "ok", "message": "two calls gave one public key and one signature" })
                    }
                    (Ok(_), Ok(_), Ok(_), Ok(_)) => json!({ "status": "err", "message": "two calls gave different answers" }),
                    (Err(e), ..) | (_, Err(e), ..) | (_, _, Err(e), _) | (.., Err(e)) => json!({ "status": "err", "message": e }),
                }
            }
            None => na("this build declares no key"),
        },
        // A secp256k1 key signs a 32-byte prehash only: 31 and 33 bytes are
        // both refused, and the answer is the refusal of the first.
        "secp_message_not_32" => match &first_secp {
            Some((path, vault)) => {
                let v = vault.as_deref();
                match (
                    signing_keys::sign(path, v, &[0x61; SECP256K1_PREHASH - 1]),
                    signing_keys::sign(path, v, &[0x61; SECP256K1_PREHASH + 1]),
                    signing_keys::sign(path, v, b"not a prehash"),
                ) {
                    (Err(e), Err(_), Err(_)) => json!({ "status": "err", "message": e }),
                    _ => json!({ "status": "ok", "message": "the host signed a secp256k1 message that is not 32 bytes" }),
                }
            }
            None => na("this build declares no secp256k1 key"),
        },
        "nep413_wrong_type" => match &first_secp {
            Some((path, vault)) => match signing_keys::sign_nep413(path, vault.as_deref(), "m", "r", &[0; 32], None) {
                Err(e) => json!({ "status": "err", "message": e }),
                Ok(_) => json!({ "status": "ok", "message": "the host signed a NEP-413 message with a secp256k1 key" }),
            },
            None => na("this build declares no secp256k1 key"),
        },
        "nep413_bad_nonce" => match &first_ed {
            Some((path, vault)) => {
                let v = vault.as_deref();
                match (
                    signing_keys::sign_nep413(path, v, "m", "r", &[0; 31], None),
                    signing_keys::sign_nep413(path, v, "m", "r", &[0; 33], None),
                    signing_keys::sign_nep413(path, v, "m", "r", &[], None),
                ) {
                    (Err(e), Err(_), Err(_)) => json!({ "status": "err", "message": e }),
                    _ => json!({ "status": "ok", "message": "the host signed a NEP-413 message with a nonce that is not 32 bytes" }),
                }
            }
            None => na("this build declares no ed25519 key"),
        },
        other => json!({ "status": "err", "message": format!("unknown attack {other:?}; one of {}", ATTACKS.join(", ")) }),
    }
}

// ── io ──────────────────────────────────────────────────────────────────────

fn read_stdin() -> String {
    use std::io::Read;
    let mut buf = String::new();
    let _ = std::io::stdin().read_to_string(&mut buf);
    buf
}

fn emit(answer: Value) {
    use std::io::Write;
    let mut stdout = std::io::stdout();
    let _ = stdout.write_all(answer.to_string().as_bytes());
    let _ = stdout.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nonce() -> [u8; 32] {
        let mut n = [0u8; 32];
        for (i, b) in n.iter_mut().enumerate() {
            *b = i as u8;
        }
        n
    }

    /// The payload hash against a vector computed independently (Python:
    /// `struct` for borsh, `hashlib` for sha256) — see the README.
    #[test]
    fn the_nep413_hash_is_the_specifications() {
        let without = Nep413Payload {
            message: "Login to example.com".into(),
            nonce: nonce(),
            recipient: "example.com".into(),
            callback_url: None,
        };
        assert_eq!(hex::encode(nep413_hash(&without)), "cd116988f58c30e8e583243b8b61ea5f567ccbc8529dcca6565ae2022d559ed2");
        let with = Nep413Payload { callback_url: Some("https://example.com/cb".into()), ..without };
        assert_eq!(hex::encode(nep413_hash(&with)), "b54001a0afc35cf781a640b30fa20aa202a2a64a1e6de3fc0889421b8d1cf028");
    }

    /// borsh's bytes, spelled out: the tag, then each field in order.
    #[test]
    fn the_borsh_encoding_is_the_one_spelled_out() {
        let payload = Nep413Payload { message: "hi".into(), nonce: [7; 32], recipient: "r".into(), callback_url: None };
        let mut expected = Vec::new();
        expected.extend_from_slice(&2_147_484_061u32.to_le_bytes());
        expected.extend_from_slice(&2u32.to_le_bytes());
        expected.extend_from_slice(b"hi");
        expected.extend_from_slice(&[7; 32]);
        expected.extend_from_slice(&1u32.to_le_bytes());
        expected.extend_from_slice(b"r");
        expected.push(0);
        let mut actual = borsh::to_vec(&NEP413_TAG).unwrap();
        actual.extend(borsh::to_vec(&payload).unwrap());
        assert_eq!(actual, expected);
    }

    #[test]
    fn this_build_declares_its_keys() {
        let signing = declared();
        let encryption = declared_in("encryption_keys");
        assert!(!signing.is_empty() || !encryption.is_empty());
        assert!(signing.len() <= 3 && encryption.len() <= 3, "{signing:?} {encryption:?}");
        assert_eq!(!encryption.is_empty(), cfg!(feature = "enc-api"), "only the encryption builds declare encryption keys");
        // An encryption key has no type — the worker refuses one that names
        // it — and a signing key always names its own.
        // `encryption-typed` exists to be refused for naming one.
        let manifest: Value = serde_json::from_slice(MANIFEST).unwrap();
        for k in manifest["encryption_keys"].as_array().into_iter().flatten() {
            assert_eq!(k.get("type").is_some(), cfg!(feature = "encryption-typed"), "an encryption key has no type: {k}");
        }
        // One predecessor key per family, each in the one build that exists for it.
        let predecessor = manifest["encryption_keys"].as_array().into_iter().flatten().any(|k| k["caller"] == "predecessor");
        assert_eq!(predecessor, cfg!(feature = "encryption-pred"));
        let signing_predecessor = manifest["signing_keys"].as_array().into_iter().flatten().any(|k| k["caller"] == "predecessor");
        assert_eq!(signing_predecessor, cfg!(feature = "project-pred"));
        let secp_build = cfg!(any(feature = "project-secp", feature = "wasm-secp"));
        for k in manifest["signing_keys"].as_array().into_iter().flatten() {
            assert!(k["type"] == "ed25519" || (secp_build && k["type"] == "secp256k1"), "{k}");
        }
        assert_eq!(declared_typed().iter().any(|(_, _, t)| t == "secp256k1"), secp_build, "only the secp builds declare one");
        assert_eq!(declared_typed().len(), signing.len());
    }

    /// The EVM address of the keystore's pinned secp256k1 key, against
    /// Python (`coincurve` for the point, `pycryptodome` for keccak256).
    #[test]
    fn the_evm_address_is_keccak_of_x_and_y() {
        let pk = hex::decode(
            "ed426f3507c4c5d16edaa292cc2a60e3bdb4a92724613c4d242c97f51ff47d677ca9bd17bd777ecddbe30fc984d124f0b189ebac9c40e322da396b5fd217c5e3",
        )
        .unwrap();
        assert_eq!(evm_address(&pk).unwrap(), "0x20d9ed83e1e77fe943ff7627cb55b87a94675832");
        assert!(evm_address(&pk[..32]).is_none());
        assert!(evm_address(&[]).is_none());
    }

    /// The in-guest secp256k1 check against Python's signature of
    /// keccak256("record #1") by that key: verified, recovered, low-s, v = 1;
    /// its high-s twin is refused; another prehash does not verify.
    #[test]
    fn the_guest_secp256k1_check_accepts_the_independent_signature() {
        let pk = hex::decode(
            "ed426f3507c4c5d16edaa292cc2a60e3bdb4a92724613c4d242c97f51ff47d677ca9bd17bd777ecddbe30fc984d124f0b189ebac9c40e322da396b5fd217c5e3",
        )
        .unwrap();
        let prehash = hex::decode("7e212fe9e9a2b5d41a353b8f7399c8d48fb7e83bee75d2233a856cefad932852").unwrap();
        let sig = hex::decode(
            "b5f5dc30365e5da9c6c2135a088d7974ac3293d9a0ea64955df0ffd117a927cb56bbf86061befe7d1e1e64342360a6ae1d401c70e4d0b0d7c384e05bdd7b8c4601",
        )
        .unwrap();
        let c = secp_check(&pk, &prehash, &sig);
        assert!(c.verified && c.recovered && c.low_s && c.v == Some(1));
        let mut wrong_v = sig.clone();
        wrong_v[64] = 0;
        assert!(!secp_check(&pk, &prehash, &wrong_v).recovered);
        let mut other = prehash.clone();
        other[0] ^= 1;
        assert!(!secp_check(&pk, &other, &sig).verified);
        let high = {
            let s = k256::ecdsa::Signature::from_slice(&sig[..64]).unwrap();
            let (r, s_low) = s.split_scalars();
            let high = k256::ecdsa::Signature::from_scalars(r, -*s_low).unwrap();
            let mut out = high.to_bytes().to_vec();
            out.push(0);
            out
        };
        let c = secp_check(&pk, &prehash, &high);
        assert!(!c.low_s && !c.verified, "k256 refuses a high-s signature");
        assert!(!secp_check(&pk, &prehash, &sig[..64]).verified, "64 bytes: no v");
    }
}
