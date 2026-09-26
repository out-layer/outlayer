//! Encryption keys a component declares in its manifest.
//!
//! The manifest inside the wasm names the keys (`"encryption_keys": [{"path":
//! "records"}]`, at most [`MAX_ENCRYPTION_KEYS`]);
//! the worker names them in the run's one `/decrypt` request beside the signing
//! keys and the secret row, with the same run facts ([`RunSource`], the job's
//! accounts, the measured build), never anything the guest says; and the guest
//! seals, opens and authenticates data through the `outlayer:encryption-keys`
//! host interface ([`host_functions`], `wit/deps/encryption-keys.wit`) by path,
//! without ever seeing a key.
//!
//! **The rules are the signing keys', key for key** (`crate::signing_keys`):
//! `bind: "project"` only on a run through a project, `bind: "wasm"` only on a
//! direct run of a wasm URL, nothing for code built from GitHub, `caller`
//! `signer` or `predecessor` (a predecessor key needs a predecessor), a vault
//! only on a project key. One key that breaks a rule refuses the whole run
//! before any secret is decrypted, and again in the keystore
//! (`keystore-worker/src/encryption_keys.rs`). The two families are separate
//! namespaces: an encryption key and a signing key at the same path are two
//! unrelated secrets, derived under two roots.
//!
//! **What a key does.** A key has no type: the declaration names no algorithm,
//! and a `type` member is refused as an unknown field. Each key is 32 bytes
//! from the keystore, and the algorithm is this host's choice, named by the
//! first byte of every ciphertext ([`CIPHERTEXT_FORMAT`]). Format `0x01` uses
//! the 32 bytes as they are only as the XChaCha20-Poly1305 key: `encrypt`
//! seals under a fresh random 24-byte nonce from the host CSPRNG and answers
//! `0x01 || nonce || ciphertext || tag`. Another format would get another
//! marker over the same key, and `decrypt` would read each by its marker.
//! `decrypt` answers every failure to open — format marker, length, tag, key,
//! `aad` — with the one error [`DECRYPTION_FAILED`], so a guest learns nothing
//! from which it was. `mac` is HMAC-SHA256 under a subkey derived from the key
//! with a fixed label ([`MAC_SUBKEY_LABEL`]), never under the AEAD key itself.
//! Inputs are capped at [`MAX_CRYPT_INPUT_BYTES`].
//!
//! **The keys live in the job's memory only.** They arrive in one response,
//! are read straight into buffers wiped when dropped, travel into the one
//! execution by value and are dropped with it. They are never cached across
//! jobs, never put in the guest's environment or stdin, and never logged: key
//! paths at debug level at most.

pub mod host_functions;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::digest::generic_array::GenericArray;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::signing_keys::{shown, CallerKind, Declared, Family, KeyBinding, RunSource, SeedHex};

pub use host_functions::{add_encryption_keys_to_linker, EncryptionKeysHostState};

/// How many encryption keys one manifest may declare. The keystore's own
/// limit, counted apart from the signing keys.
pub const MAX_ENCRYPTION_KEYS: usize = 3;

/// The encryption keys' family, as refusals name it.
pub const ENCRYPTION: Family = Family { noun: "encryption key", field: "encryption_keys", most: MAX_ENCRYPTION_KEYS };

/// Largest plaintext `encrypt` seals, data `mac` authenticates, and `aad`
/// either AEAD call binds to: 256 KiB. A ciphertext may be longer by
/// [`CIPHERTEXT_OVERHEAD`], so everything `encrypt` returns opens again.
pub const MAX_CRYPT_INPUT_BYTES: usize = 256 * 1024;

/// The first byte of every ciphertext: its format marker — XChaCha20-Poly1305
/// with a 24-byte random nonce, `0x01 || nonce || ciphertext || tag`. It names
/// the ciphertext's format, not the key's: a later format would get another
/// marker and use the same key.
pub const CIPHERTEXT_FORMAT: u8 = 0x01;

/// XChaCha20-Poly1305's nonce.
pub const NONCE_LEN: usize = 24;

/// Poly1305's tag.
pub const TAG_LEN: usize = 16;

/// Format marker, nonce and tag: what a ciphertext adds to its plaintext.
pub const CIPHERTEXT_OVERHEAD: usize = 1 + NONCE_LEN + TAG_LEN;

/// The one error every failure to open a ciphertext answers with.
pub const DECRYPTION_FAILED: &str = "decryption failed";

/// The label the `mac` subkey is derived under: `HMAC-SHA256(key, label)`. A
/// fixed constant of this format; changing it changes every tag ever made.
pub const MAC_SUBKEY_LABEL: &[u8] = b"outlayer:encryption-keys:v1:mac";

/// One encryption key as the manifest declares it — and, unchanged, as the
/// keystore is asked for it. Unknown fields and values are refused, as for a
/// signing key; `type` is one of them — an encryption key has none.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptionManifestKey {
    /// An input of the derivation: the same path is the same key, a renamed
    /// path another key — and everything the old key sealed stays sealed.
    pub path: String,
    #[serde(default)]
    pub bind: KeyBinding,
    #[serde(default)]
    pub caller: CallerKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault: Option<String>,
}

impl Declared for EncryptionManifestKey {
    fn path(&self) -> &str {
        &self.path
    }
    fn bind(&self) -> KeyBinding {
        self.bind
    }
    fn caller(&self) -> CallerKind {
        self.caller
    }
    fn vault(&self) -> Option<&str> {
        self.vault.as_deref()
    }
}

/// Read the manifest's `encryption_keys`, refusing a declaration that breaks
/// the declaration rules.
pub fn deserialize_declared<'de, D>(deserializer: D) -> Result<Option<Vec<EncryptionManifestKey>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let keys = Option::<Vec<EncryptionManifestKey>>::deserialize(deserializer)?;
    if let Some(keys) = keys.as_deref() {
        crate::signing_keys::check_family_declarations(ENCRYPTION, keys).map_err(serde::de::Error::custom)?;
    }
    Ok(keys)
}

/// The encryption keys the running artefact declares, checked against how
/// the run was started — the signing keys' rules — before any secret is
/// decrypted or any keystore round trip is made. Empty when the manifest
/// declares none.
pub fn declared_encryption_keys(
    manifest: Option<&crate::connector_manifest::ProjectManifest>,
    run: &RunSource<'_>,
) -> Result<Vec<EncryptionManifestKey>, String> {
    let Some(keys) = manifest.and_then(|m| m.encryption_keys.as_ref()).filter(|k| !k.is_empty()) else {
        return Ok(Vec::new());
    };
    crate::signing_keys::check_family_against_run(ENCRYPTION, keys, run)?;
    Ok(keys.clone())
}

/// One usable key, with its declaration.
struct Key {
    declared: EncryptionManifestKey,
    /// The key exactly as the keystore derived it: format `0x01`'s
    /// XChaCha20-Poly1305 key.
    aead: Zeroizing<[u8; 32]>,
    /// `HMAC-SHA256(aead, MAC_SUBKEY_LABEL)`: the only key `mac` uses.
    mac: Zeroizing<[u8; 32]>,
}

/// The encryption keys of one run, by path. Not `Clone`: there is one copy,
/// and it goes into the run by value.
pub struct EncryptionKeys {
    keys: BTreeMap<String, Key>,
}

/// HMAC-SHA256 (RFC 2104) under a 32-byte key, built on SHA-256 here so that
/// every copy of key-equivalent material is one this function owns and wipes:
/// the padded key blocks live in wiped buffers, the hasher's state after
/// absorbing a padded key is reset in place by each `finalize_into_reset` and
/// the hasher is overwritten with zeros before it goes out of scope.
fn hmac_sha256(key: &[u8; 32], data: &[u8]) -> Zeroizing<[u8; 32]> {
    const BLOCK: usize = 64;
    const IPAD: u8 = 0x36;
    const OPAD: u8 = 0x5c;
    let mut pad = Zeroizing::new([0u8; BLOCK]);
    pad[..key.len()].copy_from_slice(key);
    pad.iter_mut().for_each(|b| *b ^= IPAD);
    let mut hasher = Sha256::new();
    hasher.update(pad.as_ref());
    hasher.update(data);
    let mut inner = Zeroizing::new([0u8; 32]);
    hasher.finalize_into_reset(GenericArray::from_mut_slice(inner.as_mut()));
    pad.iter_mut().for_each(|b| *b ^= IPAD ^ OPAD);
    hasher.update(pad.as_ref());
    hasher.update(inner.as_ref());
    let mut out = Zeroizing::new([0u8; 32]);
    hasher.finalize_into_reset(GenericArray::from_mut_slice(out.as_mut()));
    // SAFETY: `Sha256` (sha2 0.10) is flat: `[u32; 8]` state, a `u64` block
    // count, a `[u8; 64]` buffer and a `u8` position, with no pointers and no
    // `Drop` impl, and all zeros is a valid value of every field. It is not
    // used again.
    unsafe { zeroize::zeroize_flat_type(&mut hasher as *mut Sha256) };
    out
}

impl EncryptionKeys {
    /// No keys: what a guest that imports the interface without declaring any
    /// key sees — every path is unknown.
    pub fn none() -> Self {
        Self { keys: BTreeMap::new() }
    }

    /// The declared keys, from the keystore's answer. Exactly the declared
    /// paths must come back, each 32 bytes of hex; anything else is refused,
    /// not patched.
    pub fn from_keystore(declared: &[EncryptionManifestKey], mut keys: BTreeMap<String, SeedHex>) -> Result<Self, String> {
        let mut out = BTreeMap::new();
        for d in declared {
            let hex_key = keys.remove(&d.path).ok_or_else(|| {
                format!("the keystore's answer carries no encryption key {:?}, which the manifest declares", d.path)
            })?;
            let aead = hex_key
                .decode32()
                .ok_or_else(|| format!("the keystore's encryption key {:?} is not 32 bytes of hex", d.path))?;
            let mac = hmac_sha256(&aead, MAC_SUBKEY_LABEL);
            out.insert(d.path.clone(), Key { declared: d.clone(), aead, mac });
        }
        if let Some(extra) = keys.keys().next() {
            return Err(format!(
                "the keystore's answer carries an encryption key {:?} that the manifest does not declare",
                shown(extra)
            ));
        }
        Ok(Self { keys: out })
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// The declared paths, in order.
    pub fn paths(&self) -> impl Iterator<Item = &str> {
        self.keys.keys().map(String::as_str)
    }

    /// Are these exactly the keys `declared` names — the same paths, each with
    /// the declared binding, caller and vault?
    pub fn serve_exactly(&self, declared: &[EncryptionManifestKey]) -> bool {
        declared.len() == self.keys.len()
            && declared.iter().all(|d| self.keys.get(&d.path).is_some_and(|k| &k.declared == d))
    }

    /// The key at `path`, when `vault` is the one it is declared with.
    fn get(&self, path: &str, vault: Option<&str>) -> Result<&Key, String> {
        let key = self.keys.get(path).ok_or_else(|| {
            format!(
                "no encryption key at path {:?}: the component's manifest declares {}",
                shown(path),
                if self.keys.is_empty() {
                    "none".to_string()
                } else {
                    self.keys.keys().map(|k| format!("{k:?}")).collect::<Vec<_>>().join(", ")
                }
            )
        })?;
        match (key.declared.vault.as_deref(), vault) {
            (None, None) => Ok(key),
            (Some(declared), Some(asked)) if declared == asked => Ok(key),
            (None, Some(asked)) => Err(format!(
                "encryption key {:?} is declared without a vault, and the call names vault {:?}; call it with none",
                key.declared.path,
                shown(asked)
            )),
            (Some(declared), None) => Err(format!(
                "encryption key {:?} is declared with vault {declared:?}, and the call names none; name that vault",
                key.declared.path
            )),
            (Some(declared), Some(asked)) => Err(format!(
                "encryption key {:?} is declared with vault {declared:?}, and the call names vault {:?}",
                key.declared.path,
                shown(asked)
            )),
        }
    }

    fn within_cap(what: &str, len: usize, most: usize) -> Result<(), String> {
        if len > most {
            return Err(format!("{what} is {len} bytes; at most {most} are accepted"));
        }
        Ok(())
    }

    /// Seal `plaintext` under the key at `path`, bound to `aad`, in format
    /// [`CIPHERTEXT_FORMAT`]: `0x01 || nonce (24) || ciphertext || tag (16)`,
    /// XChaCha20-Poly1305 with the nonce fresh from the host CSPRNG. When the
    /// CSPRNG cannot answer, the call is an error and nothing is sealed.
    pub fn encrypt(&self, path: &str, vault: Option<&str>, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};
        use rand::RngCore;
        let key = self.get(path, vault)?;
        Self::within_cap("plaintext", plaintext.len(), MAX_CRYPT_INPUT_BYTES)?;
        Self::within_cap("aad", aad.len(), MAX_CRYPT_INPUT_BYTES)?;
        let mut nonce = [0u8; NONCE_LEN];
        rand::rngs::OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| "encryption failed: the host has no randomness for a nonce".to_string())?;
        // The cipher's copy of the key, and each message's ChaCha20 state and
        // Poly1305 key, are wiped when dropped; the HChaCha20 subkey chacha20
        // derives on its own stack is not.
        let cipher = chacha20poly1305::XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key.aead.as_ref()));
        let sealed = cipher
            .encrypt(chacha20poly1305::XNonce::from_slice(&nonce), Payload { msg: plaintext, aad })
            .map_err(|_| "encryption failed".to_string())?;
        let mut out = Vec::with_capacity(1 + NONCE_LEN + sealed.len());
        out.push(CIPHERTEXT_FORMAT);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    /// Open what [`Self::encrypt`] sealed under the same key and `aad`. The
    /// first byte names the format; [`CIPHERTEXT_FORMAT`] is the one there is.
    /// Every failure to open is [`DECRYPTION_FAILED`] and nothing more.
    pub fn decrypt(&self, path: &str, vault: Option<&str>, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};
        let key = self.get(path, vault)?;
        Self::within_cap("ciphertext", ciphertext.len(), MAX_CRYPT_INPUT_BYTES + CIPHERTEXT_OVERHEAD)?;
        Self::within_cap("aad", aad.len(), MAX_CRYPT_INPUT_BYTES)?;
        if ciphertext.len() < CIPHERTEXT_OVERHEAD || ciphertext[0] != CIPHERTEXT_FORMAT {
            return Err(DECRYPTION_FAILED.to_string());
        }
        let (nonce, sealed) = ciphertext[1..].split_at(NONCE_LEN);
        let cipher = chacha20poly1305::XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key.aead.as_ref()));
        cipher
            .decrypt(chacha20poly1305::XNonce::from_slice(nonce), Payload { msg: sealed, aad })
            .map_err(|_| DECRYPTION_FAILED.to_string())
    }

    /// HMAC-SHA256 of `data` under the key's `mac` subkey: 32 bytes,
    /// deterministic.
    pub fn mac(&self, path: &str, vault: Option<&str>, data: &[u8]) -> Result<Vec<u8>, String> {
        let key = self.get(path, vault)?;
        Self::within_cap("data", data.len(), MAX_CRYPT_INPUT_BYTES)?;
        Ok(hmac_sha256(&key.mac, data).to_vec())
    }
}

/// Paths and declarations only.
impl std::fmt::Debug for EncryptionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut m = f.debug_map();
        for (path, key) in &self.keys {
            m.entry(path, &key.declared);
        }
        m.finish()
    }
}

/// Does the component in `wasm` get exactly the encryption keys it declares?
///
/// Checked by the executor on the bytes it is about to run, before anything is
/// instantiated: a component declaring encryption keys that were not handed
/// over is refused rather than started with every call failing; keys handed to
/// a module that declares none, or to a module that is not a component and so
/// cannot import the host interface, are refused too.
pub fn check_run_keys(wasm: &[u8], keys: Option<&EncryptionKeys>) -> Result<(), String> {
    let handed = keys.filter(|k| !k.is_empty());
    let declared = match crate::connector_manifest::manifest_from_wasm(wasm) {
        Ok(manifest) => manifest.and_then(|m| m.encryption_keys).unwrap_or_default(),
        Err(reason) if handed.is_some() => {
            return Err(format!(
                "the component's manifest cannot be read ({reason}), and encryption keys were handed to it"
            ))
        }
        Err(_) => Vec::new(),
    };
    match (declared.is_empty(), handed) {
        (true, None) => Ok(()),
        (true, Some(_)) => Err("encryption keys were handed to a module whose manifest declares none".to_string()),
        (false, None) => Err(format!(
            "the component declares encryption keys ({}) and this run was given none — the keystore predates \
             encryption keys, or they were not requested. Refused before running.",
            declared.iter().map(|k| format!("{:?}", k.path)).collect::<Vec<_>>().join(", ")
        )),
        (false, Some(keys)) if !keys.serve_exactly(&declared) => Err(
            "the encryption keys handed to this run are not the ones its manifest declares. Refused before running."
                .to_string(),
        ),
        (false, Some(_)) if !wasmparser::Parser::is_component(wasm) => Err(
            "the module declares encryption keys, which are reached only through the outlayer:encryption-keys \
             host interface, and a WASI P1 module cannot import one. Build it for wasm32-wasip2."
                .to_string(),
        ),
        (false, Some(_)) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api_client::CodeSource;
    use crate::connector_manifest::ProjectManifest;

    /// The keystore's pinned `encryption-key:v1:project:p0000000000000001:signer:bob.near:records`.
    const KEY_A: &str = "4324b148cb409d9a56e27a37c0cfbc4787481db4dec90cfcd2219a091c4a5d0a";
    /// The keystore's pinned `encryption-key:v1:wasm:{"11" × 32}:signer:bob.near:records`.
    const KEY_B: &str = "d5c8e2c2561e2102cfc400e8e3a7c3031745e55e7820d9d2a298b8e1a977e65d";

    const APP: Option<&str> = Some("alice.near/app");

    fn wasm_url() -> CodeSource {
        CodeSource::WasmUrl { url: "https://x/y.wasm".into(), hash: "ab".repeat(32), build_target: "wasm32-wasip2".into() }
    }

    fn github() -> CodeSource {
        CodeSource::GitHub { repo: "https://github.com/a/b".into(), commit: "c0ffee".into(), build_target: "wasm32-wasip2".into() }
    }

    fn project_run() -> RunSource<'static> {
        RunSource::of_job(APP, &wasm_url(), None)
    }

    fn direct_run() -> RunSource<'static> {
        RunSource::of_job(None, &wasm_url(), None)
    }

    fn manifest(keys: serde_json::Value) -> Result<ProjectManifest, String> {
        serde_json::from_value(serde_json::json!({ "encryption_keys": keys })).map_err(|e| e.to_string())
    }

    fn declared(keys: serde_json::Value, run: RunSource<'_>) -> Result<Vec<EncryptionManifestKey>, String> {
        declared_encryption_keys(Some(&manifest(keys)?), &run)
    }

    fn hexes(pairs: &[(&str, &str)]) -> BTreeMap<String, SeedHex> {
        serde_json::from_value(serde_json::Value::Object(
            pairs.iter().map(|(p, h)| (p.to_string(), serde_json::Value::String(h.to_string()))).collect(),
        ))
        .unwrap()
    }

    fn two_keys() -> EncryptionKeys {
        let d = declared(
            serde_json::json!([
                { "path": "records" },
                { "path": "vaulted", "vault": "vault.alice.near" }
            ]),
            project_run(),
        )
        .unwrap();
        EncryptionKeys::from_keystore(&d, hexes(&[("records", KEY_A), ("vaulted", KEY_B)])).unwrap()
    }

    #[test]
    fn declarations_are_checked_when_the_manifest_is_read() {
        for keys in [
            serde_json::json!([{ "path": "" }]),
            serde_json::json!([{ "path": "a:b" }]),
            serde_json::json!([{ "path": "A" }]),
            serde_json::json!([{ "path": "a".repeat(33) }]),
            serde_json::json!([{ "path": "k" }, { "path": "k" }]),
            serde_json::json!([{ "path": "k", "bind": "wasm", "vault": "vault.a.near" }]),
            serde_json::json!([{ "path": "k", "vault": "" }]),
            serde_json::json!([{}]),
            serde_json::json!([{ "path": "k", "bind": "hash" }]),
            serde_json::json!([{ "path": "k", "caller": "sender" }]),
            serde_json::json!([{ "path": "k", "valut": "vault.a.near" }]),
            serde_json::json!([{ "name": "k" }]),
        ] {
            assert!(manifest(keys.clone()).is_err(), "{keys}");
        }
        let four: Vec<_> = (0..4).map(|i| serde_json::json!({ "path": format!("k{i}") })).collect();
        let e = manifest(serde_json::Value::Array(four)).unwrap_err();
        assert!(e.contains("declares 4 encryption keys; at most 3"), "{e}");
        let three: Vec<_> = (0..3).map(|i| serde_json::json!({ "path": format!("k{i}") })).collect();
        assert_eq!(declared(serde_json::Value::Array(three), project_run()).unwrap().len(), 3);
    }

    /// An encryption key has no type: a `type` member — whatever its value, a
    /// signing type included — is an unknown field, and the manifest does not
    /// parse. The refusal names the field and the ones there are.
    #[test]
    fn a_type_on_an_encryption_key_is_an_unknown_field() {
        for ty in [
            serde_json::json!("xchacha20poly1305"),
            serde_json::json!("ed25519"),
            serde_json::json!("aes-256-gcm"),
            serde_json::Value::Null,
        ] {
            let e = manifest(serde_json::json!([{ "path": "k", "type": ty }])).unwrap_err();
            assert!(
                e.contains("unknown field `type`") && e.contains("expected one of `path`, `bind`, `caller`, `vault`"),
                "{ty}: {e}"
            );
        }
        // Through the reader a run uses, too.
        let e = ProjectManifest::read(br#"{"encryption_keys":[{"path":"k","type":"xchacha20poly1305"}]}"#).unwrap_err();
        assert!(e.contains("unknown field `type`"), "{e}");
        // The signing keys keep theirs.
        assert!(manifest(serde_json::json!([{ "path": "k" }])).is_ok());
        let sig: Result<ProjectManifest, _> = serde_json::from_value(serde_json::json!({ "signing_keys": [{ "path": "k" }] }));
        assert!(sig.is_err(), "a signing key still names its type");
    }

    /// The two families are separate namespaces with separate limits: the
    /// same path in both lists is fine, and three of each parse.
    #[test]
    fn the_families_are_separate_namespaces() {
        let sig: Vec<_> = (0..3).map(|i| serde_json::json!({ "path": format!("k{i}"), "type": "ed25519" })).collect();
        let enc: Vec<_> = (0..3).map(|i| serde_json::json!({ "path": format!("k{i}") })).collect();
        let m: ProjectManifest = serde_json::from_value(serde_json::json!({ "signing_keys": sig, "encryption_keys": enc })).unwrap();
        assert_eq!(m.signing_keys.as_ref().unwrap().len(), 3);
        assert_eq!(declared_encryption_keys(Some(&m), &project_run()).unwrap().len(), 3);
        assert_eq!(crate::signing_keys::declared_signing_keys(Some(&m), &project_run()).unwrap().len(), 3);
        // A manifest without the member declares none, on any run.
        let none: ProjectManifest = serde_json::from_str(r#"{"signing_keys":[{"path":"k","type":"ed25519"}]}"#).unwrap();
        assert!(declared_encryption_keys(Some(&none), &RunSource::of_job(None, &github(), None)).unwrap().is_empty());
    }

    #[test]
    fn every_bind_source_and_caller_mismatch_is_refused_before_any_secret() {
        let p = serde_json::json!([{ "path": "k" }]);
        let w = serde_json::json!([{ "path": "k", "bind": "wasm" }]);
        let pred = serde_json::json!([{ "path": "k", "caller": "predecessor" }]);
        assert!(declared(p.clone(), project_run()).is_ok());
        assert!(declared(w.clone(), direct_run()).is_ok());
        assert!(declared(pred.clone(), RunSource::of_job(APP, &wasm_url(), Some("dao.near"))).is_ok());
        for (label, keys, run, says) in [
            ("wasm key on a project run", w.clone(), project_run(), "the encryption key \"k\" is bound to the build"),
            ("project key on a direct run", p.clone(), direct_run(), "direct run with no project"),
            ("GitHub direct", w, RunSource::of_job(None, &github(), None), "gets no encryption keys"),
            ("GitHub project version", p, RunSource::of_job(APP, &github(), None), "project version is built from a GitHub repository"),
            ("predecessor key without one", pred, project_run(), "carries no predecessor"),
        ] {
            let e = declared(keys, run).unwrap_err();
            assert!(e.contains(says), "{label}: {e}");
        }
    }

    #[test]
    fn exactly_the_declared_keys_must_come_back() {
        let d = declared(serde_json::json!([{ "path": "records" }]), project_run()).unwrap();
        assert!(EncryptionKeys::from_keystore(&d, hexes(&[])).is_err(), "missing");
        assert!(EncryptionKeys::from_keystore(&d, hexes(&[("records", KEY_A), ("other", KEY_B)])).is_err(), "extra");
        assert!(EncryptionKeys::from_keystore(&d, hexes(&[("records", "abcd")])).is_err(), "short");
        assert!(EncryptionKeys::from_keystore(&d, hexes(&[("records", &"zz".repeat(32))])).is_err(), "not hex");
        let keys = EncryptionKeys::from_keystore(&d, hexes(&[("records", KEY_A)])).unwrap();
        assert!(keys.serve_exactly(&d));
        let mut vaulted = d.clone();
        vaulted[0].vault = Some("vault.alice.near".into());
        assert!(!keys.serve_exactly(&vaulted));
        assert!(!keys.serve_exactly(&[]));
    }

    #[test]
    fn a_round_trip_opens_and_the_format_is_pinned() {
        let keys = two_keys();
        let ct = keys.encrypt("records", None, b"record #1", b"storage-key-1").unwrap();
        assert_eq!(ct.len(), b"record #1".len() + CIPHERTEXT_OVERHEAD);
        assert_eq!(ct[0], CIPHERTEXT_FORMAT);
        assert_eq!(CIPHERTEXT_FORMAT, 0x01);
        assert_eq!(keys.decrypt("records", None, &ct, b"storage-key-1").unwrap(), b"record #1");
        // The same layout an independent XChaCha20-Poly1305 opens: the key is
        // the keystore's bytes as they are.
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};
        let key = hex::decode(KEY_A).unwrap();
        let cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(&key).unwrap();
        let opened = cipher
            .decrypt(chacha20poly1305::XNonce::from_slice(&ct[1..25]), Payload { msg: &ct[25..], aad: b"storage-key-1" })
            .unwrap();
        assert_eq!(opened, b"record #1");
        // Empty plaintext and empty aad are fine.
        let empty = keys.encrypt("records", None, b"", b"").unwrap();
        assert_eq!(keys.decrypt("records", None, &empty, b"").unwrap(), b"");
    }

    /// Independent vectors, computed with libsodium (PyNaCl) and PyCryptodome:
    /// the XChaCha20-Poly1305 draft's A.3.1 vector, a ciphertext in this
    /// format sealed by libsodium under the keystore's pinned key and a fixed
    /// nonce — which `decrypt` must open — and the pinned `mac` of that key.
    /// A failure means the format changed, and nothing sealed before opens.
    #[test]
    fn the_format_opens_what_an_independent_implementation_sealed() {
        let keys = two_keys();
        let sealed = hex::decode(
            "01000102030405060708090a0b0c0d0e0f10111213141516179fbbdc1be35f2c9c516c5e6d25c709a68fe569a22811382927",
        )
        .unwrap();
        assert_eq!(keys.decrypt("records", None, &sealed, b"storage-key-1").unwrap(), b"record #1");
        assert_eq!(keys.decrypt("records", None, &sealed, b"storage-key-2").unwrap_err(), DECRYPTION_FAILED);
        assert_eq!(
            hex::encode(keys.mac("records", None, b"alice's inbox").unwrap()),
            "51f41e345c29ef105e29b11df910df64ee85f36bf767d08c71ae9474ee3a7b2b"
        );
    }

    #[test]
    fn the_aead_is_xchacha20_poly1305() {
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};
        let key = hex::decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
        let nonce = hex::decode("404142434445464748494a4b4c4d4e4f5051525354555657").unwrap();
        let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(&key).unwrap();
        let ct = cipher.encrypt(chacha20poly1305::XNonce::from_slice(&nonce), Payload { msg: pt, aad: &aad }).unwrap();
        assert_eq!(hex::encode(&ct[ct.len() - 16..]), "c0875924c1c7987947deafd8780acf49");
        assert_eq!(&hex::encode(&ct[..16]), "bd6d179d3e83d43b9576579493c0e939");
    }

    #[test]
    fn every_nonce_is_fresh() {
        let keys = two_keys();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            let ct = keys.encrypt("records", None, b"same", b"same").unwrap();
            assert!(seen.insert(ct[1..25].to_vec()), "a nonce repeated");
        }
    }

    #[test]
    fn every_failure_to_open_is_one_error() {
        let keys = two_keys();
        let ct = keys.encrypt("records", None, b"record #1", b"row-1").unwrap();
        let mut tampered = ct.clone();
        *tampered.last_mut().unwrap() ^= 1;
        let mut body = ct.clone();
        body[30] ^= 1;
        let mut nonce = ct.clone();
        nonce[5] ^= 1;
        let mut format = ct.clone();
        format[0] = 0x02;
        let cases: Vec<(&str, &str, Option<&str>, Vec<u8>, &[u8])> = vec![
            ("wrong aad", "records", None, ct.clone(), b"row-2"),
            ("tampered tag", "records", None, tampered, b"row-1"),
            ("tampered body", "records", None, body, b"row-1"),
            ("tampered nonce", "records", None, nonce, b"row-1"),
            ("unknown format marker", "records", None, format, b"row-1"),
            ("truncated", "records", None, ct[..ct.len() - 1].to_vec(), b"row-1"),
            ("shorter than the overhead", "records", None, ct[..CIPHERTEXT_OVERHEAD - 1].to_vec(), b"row-1"),
            ("empty", "records", None, vec![], b"row-1"),
            ("another path's key", "vaulted", Some("vault.alice.near"), ct.clone(), b"row-1"),
        ];
        for (label, path, vault, input, aad) in cases {
            assert_eq!(keys.decrypt(path, vault, &input, aad).unwrap_err(), DECRYPTION_FAILED, "{label}");
        }
    }

    #[test]
    fn the_mac_is_deterministic_and_never_under_the_aead_key() {
        let keys = two_keys();
        let a = keys.mac("records", None, b"alice's inbox").unwrap();
        assert_eq!(a.len(), 32);
        assert_eq!(a, keys.mac("records", None, b"alice's inbox").unwrap());
        assert_ne!(a, keys.mac("records", None, b"bob's inbox").unwrap());
        assert_ne!(a, keys.mac("vaulted", Some("vault.alice.near"), b"alice's inbox").unwrap());
        let key: [u8; 32] = hex::decode(KEY_A).unwrap().try_into().unwrap();
        // Not HMAC under the AEAD key itself …
        assert_ne!(a, hmac_sha256(&key, b"alice's inbox").to_vec());
        // … but under the labelled subkey, as pinned here.
        let sub = hmac_sha256(&key, MAC_SUBKEY_LABEL);
        assert_eq!(a, hmac_sha256(&sub, b"alice's inbox").to_vec());
        assert_eq!(MAC_SUBKEY_LABEL, b"outlayer:encryption-keys:v1:mac");
    }

    /// The HMAC here is RFC 2104's: the `hmac` crate gives the same tag for
    /// every data length around SHA-256's block and padding boundaries.
    #[test]
    fn the_hmac_is_the_hmac_crates() {
        use hmac::{Hmac, Mac};
        for key in [KEY_A, KEY_B] {
            let key: [u8; 32] = hex::decode(key).unwrap().try_into().unwrap();
            for len in [0usize, 1, 31, 32, 55, 56, 63, 64, 65, 119, 120, 128, 1000] {
                let data: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
                let mut reference = <Hmac<Sha256> as Mac>::new_from_slice(&key).unwrap();
                reference.update(&data);
                assert_eq!(hmac_sha256(&key, &data).as_ref(), reference.finalize().into_bytes().as_slice(), "len {len}");
            }
        }
    }

    #[test]
    fn the_vault_must_be_the_declared_one_and_paths_must_be_declared() {
        let keys = two_keys();
        assert!(keys.encrypt("records", Some("vault.alice.near"), b"m", b"").unwrap_err().contains("declared without a vault"));
        assert!(keys.mac("vaulted", None, b"m").unwrap_err().contains("names none"));
        assert!(keys.decrypt("vaulted", Some("vault.mallory.near"), b"x", b"").unwrap_err().contains("names vault \"vault.mallory.near\""));
        assert!(keys.encrypt("vaulted", Some("vault.alice.near"), b"m", b"").is_ok());
        for path in ["", "Records", "nope", "records:x", &"a".repeat(100_000)] {
            let e = keys.encrypt(path, None, b"m", b"").unwrap_err();
            assert!(e.contains("no encryption key at path") && e.len() < 400, "{}", shown(path));
            assert!(keys.mac(path, None, b"m").is_err());
        }
        assert!(EncryptionKeys::none().mac("records", None, b"m").unwrap_err().contains("declares none"));
    }

    #[test]
    fn inputs_over_the_cap_are_errors() {
        let keys = two_keys();
        let most = vec![0u8; MAX_CRYPT_INPUT_BYTES];
        let over = vec![0u8; MAX_CRYPT_INPUT_BYTES + 1];
        let ct = keys.encrypt("records", None, &most, b"").unwrap();
        assert_eq!(keys.decrypt("records", None, &ct, b"").unwrap().len(), MAX_CRYPT_INPUT_BYTES);
        assert!(keys.encrypt("records", None, &over, b"").unwrap_err().contains("at most 262144"));
        assert!(keys.encrypt("records", None, b"", &over).unwrap_err().contains("aad"));
        assert!(keys.mac("records", None, &over).unwrap_err().contains("at most 262144"));
        let long = vec![0u8; MAX_CRYPT_INPUT_BYTES + CIPHERTEXT_OVERHEAD + 1];
        assert!(keys.decrypt("records", None, &long, b"").unwrap_err().contains("ciphertext is"));
        assert!(keys.mac("records", None, &most).is_ok());
    }

    #[test]
    fn nothing_key_shaped_prints() {
        let keys = two_keys();
        let shown = format!("{keys:?}");
        assert!(shown.contains("records") && shown.contains("vault.alice.near"), "{shown}");
        for key in [KEY_A, KEY_B] {
            assert!(!shown.contains(&key[..16]), "{shown}");
        }
    }
}
