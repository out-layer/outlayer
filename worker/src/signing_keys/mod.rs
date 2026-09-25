//! Signing keys a component declares in its manifest.
//!
//! The manifest inside the wasm names the keys (`"signing_keys": [{"path":
//! "records", "type": "ed25519"}]`, at most [`MAX_SIGNING_KEYS`]); the worker
//! names them in the run's one `/decrypt` request — beside its secret row when
//! it has one, alone when it has none — with the job's project, its signer and
//! predecessor, and the measured build ([`RunSource`], read off the job the
//! coordinator gave this worker), never anything the guest says; and the guest
//! signs through the `outlayer:signing-keys` host interface ([`host_functions`])
//! by path, without ever seeing a key.
//!
//! A key is issued strictly by how the code is run: `bind: "project"` (the
//! default) only to a run through a project, `bind: "wasm"` only to a direct
//! run of a wasm URL, and nothing to a run built from a GitHub repository —
//! directly or as a project's version. `caller: "signer"` (the default) binds
//! the key to the job's `user_account_id`, `caller: "predecessor"` to its
//! `predecessor_id`, and a `predecessor` key on a run with no predecessor is
//! refused. One key that does not match refuses the whole run, here before any
//! secret is decrypted, and again in the keystore; see
//! `keystore-worker/src/signing_keys.rs` and `wit/deps/signing-keys.wit`.
//!
//! **Who checks what.** The keystore takes the job's `user_account_id`,
//! `predecessor_id`, `executed_wasm_sha256` and `project_id` from this worker
//! on the trust of its TEE attestation, exactly as it does for secrets, and
//! verifies on chain only what the chain can answer: the project's version and
//! owner, the vault's ownership. The request has no field saying how the run
//! was started: a `project_id` makes it a project run, none a direct run. A
//! run built from GitHub is therefore refused in two places. Through a
//! project, the keystore sees it — the contract's version for the build's hash
//! has a GitHub source, or there is none. Directly, only this worker can: it
//! holds the resolved `code_source`, while the keystore holds nothing but the
//! hash of the bytes, which does not say whether they came from a wasm URL or
//! a repository build. So [`declared_signing_keys`] refuses a direct GitHub
//! build before any request is made, and nothing downstream is asked to.
//!
//! **The keys live in the job's memory only.** They arrive in one response,
//! become ed25519 signing keys that wipe themselves when dropped, travel into
//! the one execution by value and are dropped with it. They are never cached
//! across jobs, never put in the guest's environment or stdin, and never
//! logged: key paths and public keys at debug level at most.

pub mod host_functions;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::api_client::CodeSource;

pub use host_functions::{add_signing_keys_to_linker, SigningKeysHostState};

/// How many keys one manifest may declare. The keystore's own limit.
pub const MAX_SIGNING_KEYS: usize = 3;

/// Longest key path: `[a-z0-9][a-z0-9_-]{0,31}`.
pub const MAX_KEY_PATH_LEN: usize = 32;

/// Largest message `sign` accepts. A guest that needs to cover more signs a
/// digest of it.
pub const MAX_SIGN_MESSAGE_BYTES: usize = 64 * 1024;

/// The algorithm a key is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SigningKeyType {
    Ed25519,
}

/// What a key belongs to besides the caller — and so how the code must be run
/// to get it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyBinding {
    /// The project: every version of its code signs with the same key. Issued
    /// only to a run through the project.
    #[default]
    Project,
    /// The exact build: a new build signs with a new key. Issued only to a
    /// direct run of a wasm URL.
    Wasm,
}

/// Which account of the job a key belongs to. A segment of the keystore's
/// derivation string, so the two never derive one key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CallerKind {
    /// The job's `user_account_id`: the transaction signer on chain, the
    /// payment-key owner over HTTPS.
    #[default]
    Signer,
    /// The job's `predecessor_id`: the account that called the contract on
    /// chain — a DAO, a wallet contract — and the signer itself over HTTPS.
    /// Refused on a run that carries no predecessor.
    Predecessor,
}

/// How this run was started, as the job the coordinator gave the worker says.
///
/// Read from the job and nothing else: its `project_id` — which the contract
/// puts on an execution request exactly when its source names a project, and
/// which an HTTPS call always carries — the variant of its resolved
/// `code_source`, and the predecessor the job's context names. Never from the
/// guest, never from the manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunSource<'a> {
    /// The job's project: present for a run through a project, absent for a
    /// direct run of a wasm URL. What the keystore reads the kind of run off.
    pub project_id: Option<&'a str>,
    /// The running code was built from a GitHub repository — directly, or as
    /// the project version this run resolved to.
    pub built_from_github: bool,
    /// The account that called the contract, when the run has one — what a
    /// `caller: "predecessor"` key is bound to.
    pub predecessor_id: Option<&'a str>,
}

impl<'a> RunSource<'a> {
    /// The run's source, from the job's `project_id`, resolved `code_source`
    /// and predecessor.
    pub fn of_job(project_id: Option<&'a str>, code_source: &CodeSource, predecessor_id: Option<&'a str>) -> Self {
        let built_from_github = matches!(code_source, CodeSource::GitHub { .. });
        Self { project_id, built_from_github, predecessor_id }
    }
}

/// One key as the manifest declares it — and, unchanged, as the keystore is
/// asked for it. Unknown fields and values are refused: a misspelled `vault`
/// read as absent would ask for the default master's key, a misspelled `bind`
/// would silently bind to the project, a misspelled `caller` to the signer.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestKey {
    /// An input of the derivation: the same path is the same key, a renamed
    /// path another key.
    pub path: String,
    #[serde(rename = "type")]
    pub key_type: SigningKeyType,
    #[serde(default)]
    pub bind: KeyBinding,
    #[serde(default)]
    pub caller: CallerKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault: Option<String>,
}

/// `[a-z0-9][a-z0-9_-]{0,31}` — the keystore refuses anything else.
pub fn validate_key_path(path: &str) -> Result<(), String> {
    let bytes = path.as_bytes();
    let lower_alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    let ok = !bytes.is_empty()
        && bytes.len() <= MAX_KEY_PATH_LEN
        && lower_alnum(bytes[0])
        && bytes.iter().all(|&b| lower_alnum(b) || b == b'_' || b == b'-');
    if ok {
        Ok(())
    } else {
        Err(format!("key path {:?} must match [a-z0-9][a-z0-9_-]{{0,31}}", shown(path)))
    }
}

/// Everything a declaration says on its own, whatever run it is in: at most
/// [`MAX_SIGNING_KEYS`], every path of the one shape and declared once, a
/// vault only on a `project` key and only an account id. Applied when the
/// manifest is read ([`deserialize_declared`]), so a manifest that breaks one
/// of these does not parse.
pub fn check_declarations(keys: &[ManifestKey]) -> Result<(), String> {
    if keys.len() > MAX_SIGNING_KEYS {
        return Err(format!(
            "the manifest declares {} signing keys; at most {MAX_SIGNING_KEYS} are allowed",
            keys.len()
        ));
    }
    for (i, key) in keys.iter().enumerate() {
        validate_key_path(&key.path).map_err(|e| format!("signing_keys[{i}]: {e}"))?;
        if keys[..i].iter().any(|k| k.path == key.path) {
            return Err(format!("the manifest declares the signing key path {:?} twice", key.path));
        }
        match (key.bind, key.vault.as_deref()) {
            (_, None) => {}
            (KeyBinding::Wasm, Some(_)) => {
                return Err(format!(
                    "the signing key {:?} is bound to the build (bind \"wasm\") and names a vault; a build \
                     has no owner to own a vault",
                    key.path
                ))
            }
            (KeyBinding::Project, Some(v)) => {
                v.parse::<near_primitives::types::AccountId>().map_err(|e| {
                    format!(
                        "the signing key {:?} names vault {:?}, which is not an account id ({e})",
                        key.path,
                        shown(v)
                    )
                })?;
            }
        }
    }
    Ok(())
}

/// Read the manifest's `signing_keys`, refusing a declaration that breaks
/// [`check_declarations`].
pub fn deserialize_declared<'de, D>(deserializer: D) -> Result<Option<Vec<ManifestKey>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let keys = Option::<Vec<ManifestKey>>::deserialize(deserializer)?;
    if let Some(keys) = keys.as_deref() {
        check_declarations(keys).map_err(serde::de::Error::custom)?;
    }
    Ok(keys)
}

/// The keys the running artefact declares, checked against how the run was
/// started — the rules the keystore applies, plus the one only this worker
/// can apply — so a declaration that cannot be served is refused with its
/// reason before any secret is decrypted or any keystore round trip is made.
///
/// Empty when the manifest declares none. Refused: any key on a run whose code
/// was built from a GitHub repository (the keystore cannot see a direct GitHub
/// build — it is refused here and nowhere else); a `project` key on a direct
/// run; a `wasm` key on a project run; a `predecessor` key on a run with no
/// predecessor.
pub fn declared_signing_keys(
    manifest: Option<&crate::connector_manifest::ProjectManifest>,
    run: &RunSource<'_>,
) -> Result<Vec<ManifestKey>, String> {
    let Some(keys) = manifest.and_then(|m| m.signing_keys.as_ref()).filter(|k| !k.is_empty()) else {
        return Ok(Vec::new());
    };
    check_declarations(keys)?;
    if run.built_from_github {
        return Err(match run.project_id {
            Some(_) => "this project version is built from a GitHub repository, and code built \
                        from a repository gets no signing keys; publish the build as a WasmUrl \
                        version of the project"
                .to_string(),
            None => "this run builds its code from a GitHub repository, \
                     and code built from a repository gets no signing keys; run a wasm URL \
                     directly for bind \"wasm\" keys, or publish it as a project version for \
                     bind \"project\" keys"
                .to_string(),
        });
    }
    for key in keys {
        match (key.bind, run.project_id) {
            (KeyBinding::Project, Some(_)) | (KeyBinding::Wasm, None) => {}
            (KeyBinding::Wasm, Some(_)) => {
                return Err(format!(
                    "the signing key {:?} is bound to the build (bind \"wasm\"), and this run goes through a \
                     project; a wasm key is issued only to a direct run of the wasm URL — run it directly, or \
                     declare the key with bind \"project\"",
                    key.path
                ))
            }
            (KeyBinding::Project, None) => {
                return Err(format!(
                    "the signing key {:?} is bound to the project (bind \"project\"), and this run is a direct \
                     run with no project; run it through its project, or declare the key with bind \"wasm\"",
                    key.path
                ))
            }
        }
        if key.caller == CallerKind::Predecessor && run.predecessor_id.is_none() {
            return Err(format!(
                "the signing key {:?} belongs to the predecessor (caller \"predecessor\"), and this run carries \
                 no predecessor to bind it to; a predecessor key is issued only to a run some account called \
                 the contract for",
                key.path
            ));
        }
    }
    Ok(keys.clone())
}

/// A seed as the keystore's response carries it: hex, read straight into a
/// buffer that is wiped when dropped. Its `Debug` prints nothing of it.
pub struct SeedHex(Zeroizing<String>);

impl<'de> Deserialize<'de> for SeedHex {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(|s| SeedHex(Zeroizing::new(s)))
    }
}

impl std::fmt::Debug for SeedHex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SeedHex(..)")
    }
}

/// One usable key, with its declaration.
struct Key {
    declared: ManifestKey,
    /// Wipes its secret half when dropped.
    signing: ed25519_dalek::SigningKey,
}

/// The keys of one run, by path. Not `Clone`: there is one copy, and it goes
/// into the run by value.
pub struct SigningKeys {
    keys: BTreeMap<String, Key>,
}

impl SigningKeys {
    /// No keys: what a guest that imports the interface without declaring any
    /// key sees — every path is unknown.
    pub fn none() -> Self {
        Self { keys: BTreeMap::new() }
    }

    /// The declared keys, from the keystore's answer. Exactly the declared
    /// paths must come back, each a 32-byte seed; anything else is refused, not
    /// patched: a key the manifest declares and the run does not have would
    /// fail at the guest's first call instead of here.
    pub fn from_keystore(declared: &[ManifestKey], mut seeds: BTreeMap<String, SeedHex>) -> Result<Self, String> {
        let mut keys = BTreeMap::new();
        for d in declared {
            let seed_hex = seeds.remove(&d.path).ok_or_else(|| {
                format!("the keystore's answer carries no signing key {:?}, which the manifest declares", d.path)
            })?;
            let mut seed = Zeroizing::new([0u8; 32]);
            hex::decode_to_slice(seed_hex.0.as_bytes(), seed.as_mut())
                .map_err(|_| format!("the keystore's seed for signing key {:?} is not 32 bytes of hex", d.path))?;
            let signing = match d.key_type {
                SigningKeyType::Ed25519 => ed25519_dalek::SigningKey::from_bytes(&seed),
            };
            keys.insert(d.path.clone(), Key { declared: d.clone(), signing });
        }
        if let Some(extra) = seeds.keys().next() {
            return Err(format!(
                "the keystore's answer carries a signing key {:?} that the manifest does not declare",
                shown(extra)
            ));
        }
        Ok(Self { keys })
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// The declared paths, in order.
    pub fn paths(&self) -> impl Iterator<Item = &str> {
        self.keys.keys().map(String::as_str)
    }

    /// Are these exactly the keys `declared` names — the same paths, each with
    /// the declared type, binding and vault?
    pub fn serve_exactly(&self, declared: &[ManifestKey]) -> bool {
        declared.len() == self.keys.len()
            && declared.iter().all(|d| self.keys.get(&d.path).is_some_and(|k| &k.declared == d))
    }

    /// The key at `path`, when `vault` is the one it is declared with.
    fn get(&self, path: &str, vault: Option<&str>) -> Result<&Key, String> {
        let key = self.keys.get(path).ok_or_else(|| {
            format!(
                "no signing key at path {:?}: the component's manifest declares {}",
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
                "signing key {:?} is declared without a vault, and the call names vault {:?}; call it with none",
                key.declared.path,
                shown(asked)
            )),
            (Some(declared), None) => Err(format!(
                "signing key {:?} is declared with vault {declared:?}, and the call names none; name that vault",
                key.declared.path
            )),
            (Some(declared), Some(asked)) => Err(format!(
                "signing key {:?} is declared with vault {declared:?}, and the call names vault {:?}",
                key.declared.path,
                shown(asked)
            )),
        }
    }

    /// The public key at `path`: 32 bytes for ed25519.
    pub fn public_key(&self, path: &str, vault: Option<&str>) -> Result<Vec<u8>, String> {
        let key = self.get(path, vault)?;
        match key.declared.key_type {
            SigningKeyType::Ed25519 => Ok(key.signing.verifying_key().to_bytes().to_vec()),
        }
    }

    /// Sign `message` with the key at `path`. ed25519: RFC 8032 over the raw
    /// bytes, 64 bytes out. Over [`MAX_SIGN_MESSAGE_BYTES`] is refused.
    pub fn sign(&self, path: &str, vault: Option<&str>, message: &[u8]) -> Result<Vec<u8>, String> {
        let key = self.get(path, vault)?;
        if message.len() > MAX_SIGN_MESSAGE_BYTES {
            return Err(format!(
                "message is {} bytes; sign accepts at most {MAX_SIGN_MESSAGE_BYTES} — sign a digest of it",
                message.len()
            ));
        }
        match key.declared.key_type {
            SigningKeyType::Ed25519 => {
                use ed25519_dalek::Signer;
                Ok(key.signing.sign(message).to_bytes().to_vec())
            }
        }
    }
}

/// Paths and public keys only.
impl std::fmt::Debug for SigningKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut m = f.debug_map();
        for (path, key) in &self.keys {
            m.entry(
                path,
                &format!("{:?}:{}", key.declared.key_type, hex::encode(key.signing.verifying_key().as_bytes())),
            );
        }
        m.finish()
    }
}

/// Does the component in `wasm` get exactly the keys it declares?
///
/// Checked by the executor on the bytes it is about to run, before anything is
/// instantiated, so a run the job path let through by mistake still cannot
/// start short of its keys: a component declaring keys that were not handed
/// over — a keystore that predates signing keys, a request that did not ask —
/// is refused rather than started with every `sign` failing; keys handed to a
/// module that declares none, or to a module that is not a component and so
/// cannot import the host interface, are refused too.
pub fn check_run_keys(wasm: &[u8], keys: Option<&SigningKeys>) -> Result<(), String> {
    let handed = keys.filter(|k| !k.is_empty());
    let declared = match crate::connector_manifest::manifest_from_wasm(wasm) {
        Ok(manifest) => manifest.and_then(|m| m.signing_keys).unwrap_or_default(),
        // An unreadable manifest is the job path's refusal to make; here it
        // only matters when keys were handed over, which it never allows.
        Err(reason) if handed.is_some() => {
            return Err(format!("the component's manifest cannot be read ({reason}), and signing keys were handed to it"))
        }
        Err(_) => Vec::new(),
    };
    match (declared.is_empty(), handed) {
        (true, None) => Ok(()),
        (true, Some(_)) => Err("signing keys were handed to a module whose manifest declares none".to_string()),
        (false, None) => Err(format!(
            "the component declares signing keys ({}) and this run was given none — the keystore predates \
             signing keys, or they were not requested. Refused before running.",
            declared.iter().map(|k| format!("{:?}", k.path)).collect::<Vec<_>>().join(", ")
        )),
        (false, Some(keys)) if !keys.serve_exactly(&declared) => Err(
            "the signing keys handed to this run are not the ones its manifest declares. Refused before running."
                .to_string(),
        ),
        (false, Some(_)) if !wasmparser::Parser::is_component(wasm) => Err(
            "the module declares signing keys, which are reached only through the outlayer:signing-keys host \
             interface, and a WASI P1 module cannot import one. Build it for wasm32-wasip2."
                .to_string(),
        ),
        (false, Some(_)) => Ok(()),
    }
}

/// A guest- or manifest-written value, as an error may quote it: cut short.
pub(crate) fn shown(raw: &str) -> String {
    const MOST: usize = 64;
    match raw.char_indices().nth(MOST) {
        Some((cut, _)) => format!("{}…", &raw[..cut]),
        None => raw.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connector_manifest::ProjectManifest;

    const SEED_A: &str = "b5ca092c9bb7c321f2d6f69c6eb147907d5df9fcc2309552786e7502706a7493";
    const PUB_A: &str = "a31824c9aac23c954e90eba38553aee73658cf09c57b5f2a124c26ade2da2e52";
    const SEED_B: &str = "87e38fc6d2921ae6a0262969bf3dc73b7da74acdbb2f28faebdacce287739f60";

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

    /// A project run some account called the contract for.
    fn called_run() -> RunSource<'static> {
        RunSource::of_job(APP, &wasm_url(), Some("dao.near"))
    }

    fn manifest(keys: serde_json::Value) -> Result<ProjectManifest, String> {
        serde_json::from_value(serde_json::json!({ "signing_keys": keys })).map_err(|e| e.to_string())
    }

    fn declared(keys: serde_json::Value, run: RunSource<'_>) -> Result<Vec<ManifestKey>, String> {
        declared_signing_keys(Some(&manifest(keys)?), &run)
    }

    fn seeds(pairs: &[(&str, &str)]) -> BTreeMap<String, SeedHex> {
        pairs.iter().map(|(n, s)| (n.to_string(), SeedHex(Zeroizing::new(s.to_string())))).collect()
    }

    fn two_keys() -> SigningKeys {
        let d = declared(
            serde_json::json!([{ "path": "records", "type": "ed25519" }, { "path": "payouts", "type": "ed25519", "vault": "vault.alice.near" }]),
            project_run(),
        )
        .unwrap();
        SigningKeys::from_keystore(&d, seeds(&[("records", SEED_A), ("payouts", SEED_B)])).unwrap()
    }

    #[test]
    fn the_run_source_is_read_off_the_job() {
        assert_eq!(
            RunSource::of_job(APP, &wasm_url(), None),
            RunSource { project_id: APP, built_from_github: false, predecessor_id: None }
        );
        assert_eq!(
            RunSource::of_job(APP, &github(), Some("dao.near")),
            RunSource { project_id: APP, built_from_github: true, predecessor_id: Some("dao.near") }
        );
        assert_eq!(
            RunSource::of_job(None, &wasm_url(), Some("bob.near")),
            RunSource { project_id: None, built_from_github: false, predecessor_id: Some("bob.near") }
        );
        assert_eq!(
            RunSource::of_job(None, &github(), None),
            RunSource { project_id: None, built_from_github: true, predecessor_id: None }
        );
    }

    /// `caller` has two spellings, defaults to the signer, and travels to the
    /// keystore exactly as declared.
    #[test]
    fn the_caller_kind_is_parsed_and_forwarded_as_declared() {
        let keys = declared(
            serde_json::json!([
                { "path": "mine", "type": "ed25519" },
                { "path": "theirs", "type": "ed25519", "caller": "predecessor" },
                { "path": "explicit", "type": "ed25519", "caller": "signer" }
            ]),
            called_run(),
        )
        .unwrap();
        assert_eq!(keys[0].caller, CallerKind::Signer);
        assert_eq!(keys[1].caller, CallerKind::Predecessor);
        assert_eq!(keys[2].caller, CallerKind::Signer);
        assert_eq!(
            serde_json::to_value(&keys[1]).unwrap(),
            serde_json::json!({ "path": "theirs", "type": "ed25519", "bind": "project", "caller": "predecessor" })
        );
        for bad in ["sender", "Signer", "PREDECESSOR", "", "both", "user"] {
            assert!(manifest(serde_json::json!([{ "path": "k", "type": "ed25519", "caller": bad }])).is_err(), "caller {bad:?}");
        }
    }

    /// A predecessor key needs a run some account called the contract for.
    #[test]
    fn a_predecessor_key_on_a_run_without_a_predecessor_is_refused() {
        let theirs = serde_json::json!([{ "path": "k", "type": "ed25519", "caller": "predecessor" }]);
        assert!(declared(theirs.clone(), called_run()).is_ok());
        let e = declared(theirs.clone(), project_run()).unwrap_err();
        assert!(e.contains("carries no predecessor"), "{e}");
        // A wasm key of the predecessor, on a direct run with and without one.
        let wasm_theirs = serde_json::json!([{ "path": "k", "type": "ed25519", "bind": "wasm", "caller": "predecessor" }]);
        assert!(declared(wasm_theirs.clone(), RunSource::of_job(None, &wasm_url(), Some("bob.near"))).is_ok());
        assert!(declared(wasm_theirs, direct_run()).unwrap_err().contains("carries no predecessor"));
        // One such key among signer keys refuses the whole manifest.
        let mixed = serde_json::json!([{ "path": "a", "type": "ed25519" }, { "path": "b", "type": "ed25519", "caller": "predecessor" }]);
        assert!(declared(mixed, project_run()).is_err());
        // A signer key does not need one.
        assert!(declared(serde_json::json!([{ "path": "k", "type": "ed25519" }]), project_run()).is_ok());
    }

    #[test]
    fn a_manifest_without_keys_declares_none() {
        assert!(declared_signing_keys(None, &project_run()).unwrap().is_empty());
        let m: ProjectManifest = serde_json::from_str(r#"{"connector_id":"x"}"#).unwrap();
        assert!(declared_signing_keys(Some(&m), &project_run()).unwrap().is_empty());
        // Even a GitHub run: no declaration, nothing to refuse.
        assert!(declared_signing_keys(Some(&m), &RunSource::of_job(None, &github(), None)).unwrap().is_empty());
        assert!(declared(serde_json::json!([]), RunSource::of_job(None, &github(), None)).unwrap().is_empty());
    }

    /// Three keys are accepted; a fourth refuses the manifest when it is read.
    #[test]
    fn three_keys_are_accepted_and_four_refused() {
        let key = |i: usize| serde_json::json!({ "path": format!("k{i}"), "type": "ed25519" });
        let three: Vec<_> = (0..3).map(key).collect();
        assert_eq!(declared(serde_json::Value::Array(three), project_run()).unwrap().len(), 3);
        let four: Vec<_> = (0..4).map(key).collect();
        let e = manifest(serde_json::Value::Array(four.clone())).unwrap_err();
        assert!(e.contains("declares 4 signing keys; at most 3"), "{e}");
        // Read out of a wasm, a manifest with four keys is a manifest that does not parse.
        let bytes = serde_json::to_vec(&serde_json::json!({ "signing_keys": four })).unwrap();
        let e = ProjectManifest::read(&bytes).unwrap_err();
        assert!(e.contains("at most 3"), "{e}");
    }

    #[test]
    fn declarations_are_checked_when_the_manifest_is_read() {
        for keys in [
            serde_json::json!([{ "path": "", "type": "ed25519" }]),
            serde_json::json!([{ "path": "a:b", "type": "ed25519" }]),
            serde_json::json!([{ "path": "../a", "type": "ed25519" }]),
            serde_json::json!([{ "path": "A", "type": "ed25519" }]),
            serde_json::json!([{ "path": "a".repeat(33), "type": "ed25519" }]),
            serde_json::json!([{ "path": "k", "type": "ed25519" }, { "path": "k", "type": "ed25519", "vault": "vault.a.near" }]),
            serde_json::json!([{ "path": "k", "type": "ed25519", "bind": "wasm", "vault": "vault.a.near" }]),
            serde_json::json!([{ "path": "k", "type": "ed25519", "vault": "" }]),
            serde_json::json!([{ "path": "k", "type": "ed25519", "vault": "Vault:x" }]),
            // The field is `path`; `name` is not a field.
            serde_json::json!([{ "name": "k", "type": "ed25519" }]),
            serde_json::json!([{ "path": "k", "type": "secp256k1" }]),
            serde_json::json!([{ "path": "k", "type": "Ed25519" }]),
            serde_json::json!([{ "path": "k" }]),
            serde_json::json!([{ "path": "k", "type": "ed25519", "bind": "hash" }]),
            serde_json::json!([{ "path": "k", "type": "ed25519", "bind": "repo" }]),
            serde_json::json!([{ "path": "k", "type": "ed25519", "valut": "vault.a.near" }]),
        ] {
            assert!(manifest(keys.clone()).is_err(), "{keys}");
        }
        let ok = declared(
            serde_json::json!([
                { "path": "records", "type": "ed25519" },
                { "path": "pay-outs_1", "type": "ed25519", "vault": "vault.alice.near" }
            ]),
            project_run(),
        )
        .unwrap();
        assert_eq!(ok[0].bind, KeyBinding::Project);
        assert_eq!(ok[1].vault.as_deref(), Some("vault.alice.near"));
        // A member of another name is not `signing_keys`: it declares nothing.
        let m: ProjectManifest =
            serde_json::from_value(serde_json::json!({ "keys": [{ "name": "k", "type": "ed25519" }] })).unwrap();
        assert!(m.signing_keys.is_none());
    }

    /// A key is issued strictly by how the code is run.
    #[test]
    fn every_bind_and_source_mismatch_is_refused_before_any_secret() {
        let p = serde_json::json!([{ "path": "k", "type": "ed25519" }]);
        let w = serde_json::json!([{ "path": "k", "type": "ed25519", "bind": "wasm" }]);
        let mixed_project = serde_json::json!([{ "path": "a", "type": "ed25519" }, { "path": "b", "type": "ed25519" }, { "path": "c", "type": "ed25519", "bind": "wasm" }]);
        let mixed_direct = serde_json::json!([{ "path": "a", "type": "ed25519", "bind": "wasm" }, { "path": "c", "type": "ed25519" }]);
        // Matching: served.
        assert!(declared(p.clone(), project_run()).is_ok());
        assert!(declared(w.clone(), direct_run()).is_ok());
        // Mismatched, or built from GitHub: refused, whole. The GitHub refusal
        // is this worker's alone — a direct GitHub build reaches the keystore
        // as nothing but a hash.
        let refused = [
            ("a wasm key on a project run", w.clone(), project_run(), "only to a direct run"),
            ("a project key on a direct run", p.clone(), direct_run(), "direct run with no project"),
            ("a project key on a GitHub run", p.clone(), RunSource::of_job(None, &github(), None), "GitHub repository"),
            ("a wasm key on a GitHub run", w.clone(), RunSource::of_job(None, &github(), None), "GitHub repository"),
            ("a project key on a GitHub project version", p.clone(), RunSource::of_job(APP, &github(), None), "project version is built from a GitHub repository"),
            ("a wasm key on a GitHub project version", w, RunSource::of_job(APP, &github(), Some("dao.near")), "GitHub repository"),
            ("mixed on a project run", mixed_project, project_run(), "\"c\""),
            ("mixed on a direct run", mixed_direct, direct_run(), "\"c\""),
        ];
        for (label, keys, run, says) in refused {
            let e = declared(keys, run).unwrap_err();
            assert!(e.contains(says), "{label}: {e}");
        }
    }

    #[test]
    fn exactly_the_declared_keys_must_come_back() {
        let d = declared(serde_json::json!([{ "path": "records", "type": "ed25519" }]), project_run()).unwrap();
        assert!(SigningKeys::from_keystore(&d, seeds(&[])).is_err(), "missing");
        assert!(SigningKeys::from_keystore(&d, seeds(&[("records", SEED_A), ("other", SEED_B)])).is_err(), "extra");
        assert!(SigningKeys::from_keystore(&d, seeds(&[("records", "abcd")])).is_err(), "short");
        assert!(SigningKeys::from_keystore(&d, seeds(&[("records", &"zz".repeat(32))])).is_err(), "not hex");
        let keys = SigningKeys::from_keystore(&d, seeds(&[("records", SEED_A)])).unwrap();
        assert!(keys.serve_exactly(&d));
        let mut vaulted = d.clone();
        vaulted[0].vault = Some("vault.alice.near".into());
        assert!(!keys.serve_exactly(&vaulted), "another declaration is not served by these keys");
        assert!(!keys.serve_exactly(&[]));
    }

    #[test]
    fn the_public_key_is_the_seeds() {
        let keys = two_keys();
        assert_eq!(hex::encode(keys.public_key("records", None).unwrap()), PUB_A);
        assert_eq!(keys.paths().collect::<Vec<_>>(), vec!["payouts", "records"]);
    }

    #[test]
    fn sign_then_verify() {
        use ed25519_dalek::Verifier;
        let keys = two_keys();
        let sig = keys.sign("records", None, b"record #1").unwrap();
        // The same bytes an independent ed25519 implementation produces.
        assert_eq!(
            hex::encode(&sig),
            "8654231a0f339db04286614725f044c9063771ffb08647dcc22f4405d6e1442c6b0ecacb1ba72aa7dc68af102f718e1935a0fb9dd7dbdfd55f5ddcfebdb6b90f"
        );
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&keys.public_key("records", None).unwrap().try_into().unwrap()).unwrap();
        let sig = ed25519_dalek::Signature::from_slice(&sig).unwrap();
        assert!(vk.verify(b"record #1", &sig).is_ok());
        assert!(vk.verify(b"record #2", &sig).is_err());
        // Another key's signature does not verify under this one.
        let other = keys.sign("payouts", Some("vault.alice.near"), b"record #1").unwrap();
        assert!(vk.verify(b"record #1", &ed25519_dalek::Signature::from_slice(&other).unwrap()).is_err());
    }

    #[test]
    fn an_undeclared_path_is_an_error_not_another_key() {
        let keys = two_keys();
        for path in ["", "Records", "record", "records ", "nope", "../records", "records:x", &"a".repeat(100_000)] {
            let e = keys.sign(path, None, b"m").unwrap_err();
            assert!(e.contains("no signing key at path"), "{}: {e}", shown(path));
            assert!(e.len() < 400, "a huge path is not echoed whole: {} bytes", e.len());
            assert!(keys.public_key(path, None).is_err(), "{}", shown(path));
        }
        let none = SigningKeys::none();
        assert!(none.sign("records", None, b"m").unwrap_err().contains("declares none"));
    }

    /// The vault a call names must be the declared one, every other way round
    /// is an error.
    #[test]
    fn the_vault_must_be_the_declared_one() {
        let keys = two_keys();
        // Declared none, passed some.
        let e = keys.sign("records", Some("vault.alice.near"), b"m").unwrap_err();
        assert!(e.contains("declared without a vault"), "{e}");
        assert!(keys.public_key("records", Some("")).unwrap_err().contains("declared without a vault"));
        // Declared X, passed none.
        let e = keys.sign("payouts", None, b"m").unwrap_err();
        assert!(e.contains("declared with vault \"vault.alice.near\"") && e.contains("names none"), "{e}");
        // Declared X, passed Y.
        let e = keys.public_key("payouts", Some("vault.mallory.near")).unwrap_err();
        assert!(e.contains("names vault \"vault.mallory.near\""), "{e}");
        // Declared X, passed X; declared none, passed none.
        assert_eq!(keys.sign("payouts", Some("vault.alice.near"), b"m").unwrap().len(), 64);
        assert_eq!(keys.sign("records", None, b"m").unwrap().len(), 64);
    }

    #[test]
    fn a_message_over_the_limit_is_an_error() {
        let keys = two_keys();
        assert!(keys.sign("records", None, &vec![0u8; MAX_SIGN_MESSAGE_BYTES]).is_ok());
        let e = keys.sign("records", None, &vec![0u8; MAX_SIGN_MESSAGE_BYTES + 1]).unwrap_err();
        assert!(e.contains("at most 65536"), "{e}");
    }

    #[test]
    fn nothing_seed_shaped_prints() {
        let keys = two_keys();
        let shown = format!("{keys:?}");
        assert!(shown.contains(PUB_A), "the public key is what identifies a key: {shown}");
        for seed in [SEED_A, SEED_B] {
            assert!(!shown.contains(&seed[..16]), "{shown}");
        }
        let hex = SeedHex(Zeroizing::new(SEED_A.to_string()));
        assert_eq!(format!("{hex:?}"), "SeedHex(..)");
    }
}
