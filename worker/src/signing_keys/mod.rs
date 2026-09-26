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
//! **Two types.** `type: "ed25519"` reads the keystore's 32 bytes as an RFC
//! 8032 seed; `type: "secp256k1"` reads them as the secret scalar, and a scalar
//! that is zero or not below the group order fails the run. The keystore
//! derives both the same way, the type a segment of the derivation string.
//!
//! **The keys live in the job's memory only.** They arrive in one response,
//! become ed25519 or secp256k1 signing keys that wipe their secret when
//! dropped, travel into the one execution by value and are dropped with it. They are never cached
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

/// Largest message `sign` accepts from an ed25519 key. A guest that needs to
/// cover more signs a digest of it.
pub const MAX_SIGN_MESSAGE_BYTES: usize = 64 * 1024;

/// The one message length a secp256k1 key signs: a 32-byte prehash.
pub const SECP256K1_PREHASH_BYTES: usize = 32;

/// Largest NEP-413 `message` `sign-nep413` accepts.
pub const MAX_NEP413_MESSAGE_BYTES: usize = 64 * 1024;

/// Largest NEP-413 `recipient` `sign-nep413` accepts.
pub const MAX_NEP413_RECIPIENT_BYTES: usize = 2 * 1024;

/// Largest NEP-413 callback URL `sign-nep413` accepts.
pub const MAX_NEP413_CALLBACK_URL_BYTES: usize = 2 * 1024;

/// NEP-413's tag, `2^31 + 413`, borsh-serialized (a little-endian `u32`) in
/// front of the payload, so the signed bytes can never be a NEAR transaction.
pub const NEP413_TAG: u32 = (1 << 31) + 413;

/// The algorithm a key is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SigningKeyType {
    /// The 32 bytes are an RFC 8032 seed. `public-key`: 32 bytes. `sign`:
    /// 64 bytes over the raw message.
    Ed25519,
    /// The 32 bytes are the secret scalar, big-endian. `public-key`: 64 bytes
    /// `x ‖ y`. `sign`: a 32-byte prehash only, 65 bytes `r ‖ s ‖ v` out.
    Secp256k1,
}

impl SigningKeyType {
    /// The name the manifest spells.
    pub fn label(self) -> &'static str {
        match self {
            SigningKeyType::Ed25519 => "ed25519",
            SigningKeyType::Secp256k1 => "secp256k1",
        }
    }
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

impl Declared for ManifestKey {
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

/// What the declaration rules read off one declared key, in either family —
/// the signing keys here, the encryption keys in `crate::encryption_keys`,
/// which follow the same rules key for key.
pub trait Declared {
    fn path(&self) -> &str;
    fn bind(&self) -> KeyBinding;
    fn caller(&self) -> CallerKind;
    fn vault(&self) -> Option<&str>;
}

/// How a family's declarations are named in a refusal, and its limit.
#[derive(Debug, Clone, Copy)]
pub struct Family {
    /// One key: `"signing key"`.
    pub noun: &'static str,
    /// The manifest member: `"signing_keys"`.
    pub field: &'static str,
    /// The most keys the manifest may declare.
    pub most: usize,
}

/// The signing keys' family.
pub const SIGNING: Family = Family { noun: "signing key", field: "signing_keys", most: MAX_SIGNING_KEYS };

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
    check_family_declarations(SIGNING, keys)
}

/// [`check_declarations`] for any family: the same rules, the family's own
/// name and limit. Paths are checked within the family only — each family is
/// a namespace of its own.
pub fn check_family_declarations<K: Declared>(family: Family, keys: &[K]) -> Result<(), String> {
    let Family { noun, field, most } = family;
    if keys.len() > most {
        return Err(format!("the manifest declares {} {noun}s; at most {most} are allowed", keys.len()));
    }
    for (i, key) in keys.iter().enumerate() {
        let path = key.path();
        validate_key_path(path).map_err(|e| format!("{field}[{i}]: {e}"))?;
        if keys[..i].iter().any(|k| k.path() == path) {
            return Err(format!("the manifest declares the {noun} path {path:?} twice"));
        }
        match (key.bind(), key.vault()) {
            (_, None) => {}
            (KeyBinding::Wasm, Some(_)) => {
                return Err(format!(
                    "the {noun} {path:?} is bound to the build (bind \"wasm\") and names a vault; a build \
                     has no owner to own a vault"
                ))
            }
            (KeyBinding::Project, Some(v)) => {
                v.parse::<near_primitives::types::AccountId>().map_err(|e| {
                    format!("the {noun} {path:?} names vault {:?}, which is not an account id ({e})", shown(v))
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
    check_family_against_run(SIGNING, keys, run)?;
    Ok(keys.clone())
}

/// The run rules of [`declared_signing_keys`] for any family's non-empty
/// declaration: its own declaration rules, no key for code built from GitHub,
/// every `bind` matching how the run was started, and a predecessor for every
/// `predecessor` key.
pub fn check_family_against_run<K: Declared>(family: Family, keys: &[K], run: &RunSource<'_>) -> Result<(), String> {
    let noun = family.noun;
    check_family_declarations(family, keys)?;
    if run.built_from_github {
        return Err(match run.project_id {
            Some(_) => format!(
                "this project version is built from a GitHub repository, and code built \
                 from a repository gets no {noun}s; publish the build as a WasmUrl \
                 version of the project"
            ),
            None => format!(
                "this run builds its code from a GitHub repository, \
                 and code built from a repository gets no {noun}s; run a wasm URL \
                 directly for bind \"wasm\" keys, or publish it as a project version for \
                 bind \"project\" keys"
            ),
        });
    }
    for key in keys {
        let path = key.path();
        match (key.bind(), run.project_id) {
            (KeyBinding::Project, Some(_)) | (KeyBinding::Wasm, None) => {}
            (KeyBinding::Wasm, Some(_)) => {
                return Err(format!(
                    "the {noun} {path:?} is bound to the build (bind \"wasm\"), and this run goes through a \
                     project; a wasm key is issued only to a direct run of the wasm URL — run it directly, or \
                     declare the key with bind \"project\""
                ))
            }
            (KeyBinding::Project, None) => {
                return Err(format!(
                    "the {noun} {path:?} is bound to the project (bind \"project\"), and this run is a direct \
                     run with no project; run it through its project, or declare the key with bind \"wasm\""
                ))
            }
        }
        if key.caller() == CallerKind::Predecessor && run.predecessor_id.is_none() {
            return Err(format!(
                "the {noun} {path:?} belongs to the predecessor (caller \"predecessor\"), and this run carries \
                 no predecessor to bind it to; a predecessor key is issued only to a run some account called \
                 the contract for"
            ));
        }
    }
    Ok(())
}

/// A seed as the keystore's response carries it: hex, read straight into a
/// buffer that is wiped when dropped. Its `Debug` prints nothing of it.
pub struct SeedHex(Zeroizing<String>);

impl SeedHex {
    /// The 32 bytes the hex spells, into a buffer wiped when dropped; `None`
    /// for anything that is not exactly 32 bytes of hex.
    pub(crate) fn decode32(&self) -> Option<Zeroizing<[u8; 32]>> {
        let mut out = Zeroizing::new([0u8; 32]);
        hex::decode_to_slice(self.0.as_bytes(), out.as_mut()).ok()?;
        Some(out)
    }
}

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
    secret: Secret,
}

/// A key's secret half, of the declared type. Both wipe the secret when
/// dropped: `ed25519_dalek::SigningKey` and `k256::ecdsa::SigningKey` are
/// `ZeroizeOnDrop`.
enum Secret {
    Ed25519(ed25519_dalek::SigningKey),
    Secp256k1(k256::ecdsa::SigningKey),
}

impl Secret {
    /// The public key: ed25519, the 32-byte key; secp256k1, the 64 bytes
    /// `x ‖ y` — the uncompressed SEC1 point without its `0x04` prefix, NEAR's
    /// `secp256k1:` public-key bytes.
    fn public_key(&self) -> Vec<u8> {
        match self {
            Secret::Ed25519(k) => k.verifying_key().to_bytes().to_vec(),
            Secret::Secp256k1(k) => k.verifying_key().to_encoded_point(false).as_bytes()[1..].to_vec(),
        }
    }
}

/// A NEP-413 signature in the shape a NEAR wallet's `signMessage` answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nep413Signed {
    /// The key's NEAR implicit account: its 32-byte public key, lowercase hex.
    pub account_id: String,
    /// `ed25519:` + base58 of the public key.
    pub public_key: String,
    /// The 64-byte ed25519 signature, standard base64 with padding.
    pub signature: String,
}

/// The 32 bytes NEP-413 signs: `sha256(borsh(NEP413_TAG) ‖ borsh(payload))`,
/// the payload `{message: String, nonce: [u8; 32], recipient: String,
/// callback_url: Option<String>}` in that order — borsh writes fields in
/// order, so the order is part of the format.
pub fn nep413_hash(message: &str, nonce: &[u8; 32], recipient: &str, callback_url: Option<&str>) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let bytes = borsh::to_vec(&(NEP413_TAG, message, nonce, recipient, callback_url))
        .expect("borsh writes a u32, strings under 4 GiB, an array and an option");
    Sha256::digest(&bytes).into()
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
            let secret = match d.key_type {
                SigningKeyType::Ed25519 => Secret::Ed25519(ed25519_dalek::SigningKey::from_bytes(&seed)),
                SigningKeyType::Secp256k1 => {
                    let scalar = k256::SecretKey::from_slice(seed.as_ref()).map_err(|_| {
                        format!(
                            "the derived bytes of signing key {:?} are not a valid secp256k1 scalar (astronomically \
                             unlikely)",
                            d.path
                        )
                    })?;
                    Secret::Secp256k1(k256::ecdsa::SigningKey::from(scalar))
                }
            };
            keys.insert(d.path.clone(), Key { declared: d.clone(), secret });
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

    /// The public key at `path`: 32 bytes for ed25519; 64 bytes `x ‖ y` for
    /// secp256k1.
    pub fn public_key(&self, path: &str, vault: Option<&str>) -> Result<Vec<u8>, String> {
        Ok(self.get(path, vault)?.secret.public_key())
    }

    /// Sign `message` with the key at `path`.
    ///
    /// ed25519: RFC 8032 over the raw bytes, 64 bytes out; over
    /// [`MAX_SIGN_MESSAGE_BYTES`] is refused.
    ///
    /// secp256k1: `message` is a 32-byte prehash, signed as it is — no further
    /// hashing — with an RFC 6979 nonce; anything but 32 bytes is refused. 65
    /// bytes out, `r ‖ s ‖ v`: `s` in the low half of the group order, `v` the
    /// recovery id, 0 or 1 (NEAR's secp256k1 signature and `ecrecover`; EVM
    /// adds 27).
    pub fn sign(&self, path: &str, vault: Option<&str>, message: &[u8]) -> Result<Vec<u8>, String> {
        let key = self.get(path, vault)?;
        match &key.secret {
            Secret::Ed25519(signing) => {
                if message.len() > MAX_SIGN_MESSAGE_BYTES {
                    return Err(format!(
                        "message is {} bytes; sign accepts at most {MAX_SIGN_MESSAGE_BYTES} — sign a digest of it",
                        message.len()
                    ));
                }
                use ed25519_dalek::Signer;
                Ok(signing.sign(message).to_bytes().to_vec())
            }
            Secret::Secp256k1(signing) => {
                if message.len() != SECP256K1_PREHASH_BYTES {
                    return Err(format!(
                        "signing key {:?} is secp256k1, which signs a {SECP256K1_PREHASH_BYTES}-byte prehash only, \
                         and the message is {} bytes; hash it first (keccak256 for EVM)",
                        key.declared.path,
                        message.len()
                    ));
                }
                // Low-s: k256 normalises `s` and flips the recovery id to match.
                let (signature, recovery) = signing
                    .sign_prehash_recoverable(message)
                    .map_err(|_| format!("signing key {:?}: secp256k1 signing failed", key.declared.path))?;
                // The x-reduced bit is set only when k·G's x is not below the
                // group order — about 2^-128, fixed per (key, prehash) by RFC
                // 6979. `v` would then be 2 or 3, which no `ecrecover` takes.
                if recovery.is_x_reduced() {
                    return Err(format!(
                        "signing key {:?}: this prehash yields a secp256k1 recovery id with a reduced \
                         x-coordinate, which has no v in {{0, 1}} (astronomically unlikely); sign another prehash",
                        key.declared.path
                    ));
                }
                let mut out = signature.to_bytes().to_vec();
                out.push(recovery.to_byte());
                Ok(out)
            }
        }
    }

    /// A NEP-413 signature (NEAR `signMessage`) by the ed25519 key at `path`.
    ///
    /// The bytes are built here, never taken from the guest:
    /// `sha256(borsh(2^31 + 413) ‖ borsh({message, nonce, recipient,
    /// callback_url}))`, signed with ed25519. Refused: a key of another type,
    /// a `nonce` that is not 32 bytes, a `message` over
    /// [`MAX_NEP413_MESSAGE_BYTES`], a `recipient` over
    /// [`MAX_NEP413_RECIPIENT_BYTES`], a callback URL over
    /// [`MAX_NEP413_CALLBACK_URL_BYTES`].
    pub fn sign_nep413(
        &self,
        path: &str,
        vault: Option<&str>,
        message: &str,
        recipient: &str,
        nonce: &[u8],
        callback_url: Option<&str>,
    ) -> Result<Nep413Signed, String> {
        let key = self.get(path, vault)?;
        let Secret::Ed25519(signing) = &key.secret else {
            return Err(format!(
                "sign-nep413 signs with an ed25519 key, and signing key {:?} is {}",
                key.declared.path,
                key.declared.key_type.label()
            ));
        };
        let nonce: &[u8; 32] = nonce
            .try_into()
            .map_err(|_| format!("the NEP-413 nonce is {} bytes; it must be exactly 32", nonce.len()))?;
        for (field, len, most) in [
            ("message", message.len(), MAX_NEP413_MESSAGE_BYTES),
            ("recipient", recipient.len(), MAX_NEP413_RECIPIENT_BYTES),
            ("callback URL", callback_url.map_or(0, str::len), MAX_NEP413_CALLBACK_URL_BYTES),
        ] {
            if len > most {
                return Err(format!("the NEP-413 {field} is {len} bytes; at most {most} are accepted"));
            }
        }
        use base64::Engine;
        use ed25519_dalek::Signer;
        let signature = signing.sign(&nep413_hash(message, nonce, recipient, callback_url));
        let public_key = signing.verifying_key().to_bytes();
        Ok(Nep413Signed {
            account_id: hex::encode(public_key),
            public_key: format!("ed25519:{}", bs58::encode(public_key).into_string()),
            signature: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
        })
    }
}

/// Paths and public keys only.
impl std::fmt::Debug for SigningKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut m = f.debug_map();
        for (path, key) in &self.keys {
            m.entry(path, &format!("{:?}:{}", key.declared.key_type, hex::encode(key.secret.public_key())));
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
            serde_json::json!([{ "path": "k", "type": "Secp256k1" }]),
            serde_json::json!([{ "path": "k", "type": "secp256r1" }]),
            serde_json::json!([{ "path": "k", "type": "Ed25519" }]),
            // One path is one key, whatever the type.
            serde_json::json!([{ "path": "k", "type": "ed25519" }, { "path": "k", "type": "secp256k1" }]),
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
        // A member of another name is not `signing_keys`: the manifest does not parse.
        let e = ProjectManifest::read(br#"{"keys":[{"name":"k","type":"ed25519"}]}"#).unwrap_err();
        assert!(e.contains("unknown field `keys`"), "{e}");
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
        let secp = secp_keys();
        let shown = format!("{secp:?}");
        assert!(shown.contains(SECP_PUB_A) && shown.contains("Secp256k1"), "{shown}");
        for seed in [SECP_SEED_A, SECP_SEED_B, SEED_A] {
            assert!(!shown.contains(&seed[..16]), "{shown}");
        }
        let hex = SeedHex(Zeroizing::new(SEED_A.to_string()));
        assert_eq!(format!("{hex:?}"), "SeedHex(..)");
    }

    // ── secp256k1 ──────────────────────────────────────────────────────────

    /// The keystore's pinned secp256k1 seeds (`keystore-worker/src/crypto.rs`,
    /// `secp256k1_signing_key_pinned_vectors`), and what an independent
    /// implementation makes of them: public keys and signatures computed with
    /// Python `coincurve` (libsecp256k1, RFC 6979), public keys checked with
    /// `cryptography`, every signature verified and recovered there.
    const SECP_SEED_A: &str = "772890cc14851d53236ca8223391e336f711aedaaca1ee1922e9ad6452661b90";
    const SECP_PUB_A: &str = "ed426f3507c4c5d16edaa292cc2a60e3bdb4a92724613c4d242c97f51ff47d677ca9bd17bd777ecddbe30fc984d124f0b189ebac9c40e322da396b5fd217c5e3";
    const SECP_SEED_B: &str = "eca5d0f77b791ab4165da888811f52130b61a594f1efba0015c473da48efee50";
    const SECP_PUB_B: &str = "ad0a99c4c37c0f69cce104532f8fa3b59534d5c259891c37e1e8e4180e85b458f065d5678b11500966b320b7d1f0ce607c84d6fe0962ce3bcb5dc874bea81783";
    /// keccak256("record #1").
    const KECCAK_RECORD_1: &str = "7e212fe9e9a2b5d41a353b8f7399c8d48fb7e83bee75d2233a856cefad932852";
    /// `r ‖ s ‖ v` over KECCAK_RECORD_1: A's `v` is 1, B's 0.
    const SECP_SIG_A_RECORD_1: &str = "b5f5dc30365e5da9c6c2135a088d7974ac3293d9a0ea64955df0ffd117a927cb56bbf86061befe7d1e1e64342360a6ae1d401c70e4d0b0d7c384e05bdd7b8c4601";
    const SECP_SIG_B_RECORD_1: &str = "65b01cfcdbd9213f8144def0bfaa2e6c412dfe12219a280e8db53361d1a9d7567187a6de987511e07792d1c1d1a858a29068d99671c88569a64439cd50f2fb4200";
    /// A's signatures over sha256([i]) for i in 0..6.
    const SECP_SIGS_A_SHA256_I: [(&str, &str); 6] = [
        ("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d", "4dfe5dfca3954e7d21cfb8865287c74aa3079ed584e8b6873602e6ecdd511aa609c4aaafe1712078bfc08514b0c7a83dbbf5115b9a03a2f95cd29a7b1c7cd76800"),
        ("4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a", "15e5ce6b264b14d8370943faa5f173c9fccf4388397ccc957bb5f64e14a7caa15b84602e8f11bd6156190f125874ec518d3b9dd340f2813402d398184a77a59700"),
        ("dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986", "ad1a22a5995fc5db83c0690784490da0213bdda6f69e324affc04f4d4f91c53b25cfcbb064112b5ba0158748203e36ccda70ae7c3ccf5e3698a64c45b86e311501"),
        ("084fed08b978af4d7d196a7446a86b58009e636b611db16211b65a9aadff29c5", "59e6a3c639658f51c4d8abc9ffa3823327e2a1ceadd35bac6c64e5604540d17f1cb94d4cc8ec24c2645e9a319f866d6eb2269069df2d9c113b87b28e0181308c01"),
        ("e52d9c508c502347344d8c07ad91cbd6068afc75ff6292f062a09ca381c89e71", "6552db0373145172f37daff56f3eed3bd7365f8d51dc645d7a90f024b1645e8172d81c3cfd99dd7ca09ff5699aed74039809b32d968809c7eed0c47cac03c74801"),
        ("e77b9a9ae9e30b0dbdb6f510a264ef9de781501d7b6b92ae89eb059c5ab743db", "e4147d9bb2b308a13eb55ac1afb60f1199f5a046a1b8450d720c5780d26075bf0fef85c41198909b31c08d8aa20c8289043c073397f24cec677e344a346a075001"),
    ];
    /// The secp256k1 group order, big-endian.
    const SECP256K1_ORDER: &str = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";

    /// `evm` (secp256k1), `alpha` (ed25519) and `evm-vault` (secp256k1, with
    /// a vault), on a project run.
    fn secp_keys() -> SigningKeys {
        let d = declared(
            serde_json::json!([
                { "path": "evm", "type": "secp256k1" },
                { "path": "alpha", "type": "ed25519" },
                { "path": "evm-vault", "type": "secp256k1", "vault": "vault.alice.near" }
            ]),
            project_run(),
        )
        .unwrap();
        SigningKeys::from_keystore(&d, seeds(&[("evm", SECP_SEED_A), ("alpha", SEED_A), ("evm-vault", SECP_SEED_B)])).unwrap()
    }

    fn secp_verifying_key(public_key: &[u8]) -> k256::ecdsa::VerifyingKey {
        let mut sec1 = vec![0x04];
        sec1.extend_from_slice(public_key);
        k256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).unwrap()
    }

    fn hash32(hex_str: &str) -> [u8; 32] {
        hex::decode(hex_str).unwrap().try_into().unwrap()
    }

    /// The type is declared, read, and forwarded to the keystore as spelled.
    #[test]
    fn a_secp256k1_key_is_declared_and_forwarded_as_declared() {
        let keys = declared(
            serde_json::json!([{ "path": "evm", "type": "secp256k1" }, { "path": "code", "type": "secp256k1", "bind": "wasm" }]),
            project_run(),
        );
        assert!(keys.unwrap_err().contains("bound to the build"), "the run rules apply to every type");
        let keys = declared(serde_json::json!([{ "path": "evm", "type": "secp256k1", "caller": "predecessor" }]), called_run()).unwrap();
        assert_eq!(keys[0].key_type, SigningKeyType::Secp256k1);
        assert_eq!(
            serde_json::to_value(&keys[0]).unwrap(),
            serde_json::json!({ "path": "evm", "type": "secp256k1", "bind": "project", "caller": "predecessor" })
        );
        assert!(declared(serde_json::json!([{ "path": "evm", "type": "secp256k1" }]), RunSource::of_job(None, &github(), None)).is_err());
        assert!(declared(serde_json::json!([{ "path": "evm", "type": "secp256k1", "bind": "wasm", "vault": "vault.a.near" }]), direct_run()).is_err());
        assert_eq!(SigningKeyType::Secp256k1.label(), "secp256k1");
        assert_eq!(SigningKeyType::Ed25519.label(), "ed25519");
    }

    /// `x ‖ y`, the SEC1 point without its prefix: the vectors of an
    /// independent implementation.
    #[test]
    fn the_secp256k1_public_key_is_x_and_y() {
        let keys = secp_keys();
        let a = keys.public_key("evm", None).unwrap();
        assert_eq!(a.len(), 64);
        assert_eq!(hex::encode(&a), SECP_PUB_A);
        assert_eq!(hex::encode(keys.public_key("evm-vault", Some("vault.alice.near")).unwrap()), SECP_PUB_B);
        // The same point k256 parses back from its SEC1 form.
        assert_eq!(hex::encode(&secp_verifying_key(&a).to_encoded_point(false).as_bytes()[1..]), SECP_PUB_A);
        // The ed25519 key beside it is untouched.
        assert_eq!(hex::encode(keys.public_key("alpha", None).unwrap()), PUB_A);
        assert_eq!(keys.paths().collect::<Vec<_>>(), vec!["alpha", "evm", "evm-vault"]);
    }

    /// Byte for byte the signatures of an independent RFC 6979 implementation.
    #[test]
    fn a_secp256k1_signature_is_the_independent_implementations() {
        let keys = secp_keys();
        assert_eq!(hex::encode(keys.sign("evm", None, &hash32(KECCAK_RECORD_1)).unwrap()), SECP_SIG_A_RECORD_1);
        assert_eq!(
            hex::encode(keys.sign("evm-vault", Some("vault.alice.near"), &hash32(KECCAK_RECORD_1)).unwrap()),
            SECP_SIG_B_RECORD_1
        );
        for (i, (prehash, signature)) in SECP_SIGS_A_SHA256_I.iter().enumerate() {
            use sha2::Digest;
            assert_eq!(hex::encode(sha2::Sha256::digest([i as u8])), *prehash);
            assert_eq!(hex::encode(keys.sign("evm", None, &hash32(prehash)).unwrap()), *signature, "sha256([{i}])");
        }
        // Deterministic: one key and one prehash, one signature.
        assert_eq!(keys.sign("evm", None, &[9; 32]).unwrap(), keys.sign("evm", None, &[9; 32]).unwrap());
    }

    /// Every signature is low-s with `v` in {0, 1}, verifies under the public
    /// key, and recovers to it — through k256's verification and recovery,
    /// code paths apart from its signing. Over 64 prehashes, a signer that did
    /// not normalise would have left a high `s` with probability 1 - 2^-64.
    #[test]
    fn every_secp256k1_signature_is_low_s_recoverable_and_v_is_0_or_1() {
        use k256::ecdsa::signature::hazmat::PrehashVerifier;
        let keys = secp_keys();
        let public_key = keys.public_key("evm", None).unwrap();
        let vk = secp_verifying_key(&public_key);
        let half_order = {
            let mut n = hex::decode(SECP256K1_ORDER).unwrap();
            // n >> 1, big-endian
            let mut carry = 0u8;
            for b in n.iter_mut() {
                let next = *b & 1;
                *b = (*b >> 1) | (carry << 7);
                carry = next;
            }
            n
        };
        let mut seen_v = [false; 2];
        for i in 0..64u8 {
            use sha2::Digest;
            let prehash: [u8; 32] = sha2::Sha256::digest([b'p', i]).into();
            let sig = keys.sign("evm", None, &prehash).unwrap();
            assert_eq!(sig.len(), 65);
            let (rs, v) = sig.split_at(64);
            assert!(v[0] <= 1, "v = {}", v[0]);
            seen_v[v[0] as usize] = true;
            assert!(rs[32..].to_vec() <= half_order, "high s for prehash {i}");
            let signature = k256::ecdsa::Signature::from_slice(rs).unwrap();
            assert!(signature.normalize_s().is_none(), "k256 calls s high for prehash {i}");
            assert!(vk.verify_prehash(&prehash, &signature).is_ok());
            let recovered = k256::ecdsa::VerifyingKey::recover_from_prehash(
                &prehash,
                &signature,
                k256::ecdsa::RecoveryId::from_byte(v[0]).unwrap(),
            )
            .unwrap();
            assert_eq!(recovered, vk, "ecrecover of prehash {i} is the key");
            // The other recovery id recovers another key.
            let other = k256::ecdsa::VerifyingKey::recover_from_prehash(
                &prehash,
                &signature,
                k256::ecdsa::RecoveryId::from_byte(v[0] ^ 1).unwrap(),
            );
            assert!(other.map_or(true, |k| k != vk));
            // Another prehash does not verify.
            let mut other_prehash = prehash;
            other_prehash[0] ^= 1;
            assert!(vk.verify_prehash(&other_prehash, &signature).is_err());
        }
        assert!(seen_v[0] && seen_v[1], "both recovery ids occur over 64 prehashes");
    }

    /// A secp256k1 key signs a 32-byte prehash and nothing else.
    #[test]
    fn a_secp256k1_key_signs_exactly_32_bytes() {
        let keys = secp_keys();
        for len in [0usize, 1, 20, 31, 33, 64, 65, MAX_SIGN_MESSAGE_BYTES, MAX_SIGN_MESSAGE_BYTES + 1] {
            let e = keys.sign("evm", None, &vec![7u8; len]).unwrap_err();
            assert!(e.contains("32-byte prehash only") && e.contains(&format!("is {len} bytes")), "{len}: {e}");
            assert!(e.contains("\"evm\""), "{e}");
        }
        assert_eq!(keys.sign("evm", None, &[7u8; 32]).unwrap().len(), 65);
        // Path and vault are checked first, whatever the message.
        assert!(keys.sign("nope", None, &[7u8; 3]).unwrap_err().contains("no signing key at path"));
        assert!(keys.sign("evm-vault", None, &[7u8; 3]).unwrap_err().contains("names none"));
        assert!(keys.sign("evm", Some("vault.alice.near"), &[7u8; 3]).unwrap_err().contains("declared without a vault"));
        // The ed25519 key beside it still signs any length up to the cap.
        assert_eq!(keys.sign("alpha", None, b"record #1").unwrap().len(), 64);
    }

    /// A seed that is not a secp256k1 scalar — zero, the group order or above
    /// — fails the run; one below the order is a key.
    #[test]
    fn a_seed_that_is_not_a_secp256k1_scalar_fails_the_run() {
        let d = declared(serde_json::json!([{ "path": "evm", "type": "secp256k1" }]), project_run()).unwrap();
        let order_plus_one = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142";
        for bad in ["00".repeat(32).as_str(), SECP256K1_ORDER, order_plus_one, "ff".repeat(32).as_str()] {
            let e = SigningKeys::from_keystore(&d, seeds(&[("evm", bad)])).unwrap_err();
            assert!(e.contains("not a valid secp256k1 scalar (astronomically unlikely)") && e.contains("\"evm\""), "{e}");
            assert!(!e.contains(&bad[..16]), "the refusal does not quote the seed: {e}");
        }
        let order_minus_one = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140";
        for good in [order_minus_one, "0000000000000000000000000000000000000000000000000000000000000001"] {
            let keys = SigningKeys::from_keystore(&d, seeds(&[("evm", good)])).unwrap();
            assert_eq!(keys.sign("evm", None, &[1; 32]).unwrap().len(), 65);
        }
        // The same bytes are a fine ed25519 seed: the type decides.
        let ed = declared(serde_json::json!([{ "path": "evm", "type": "ed25519" }]), project_run()).unwrap();
        assert!(SigningKeys::from_keystore(&ed, seeds(&[("evm", &"00".repeat(32))])).is_ok());
    }

    // ── NEP-413 ────────────────────────────────────────────────────────────

    /// The probe's NEP-413 vector (`wasi-examples/signing-key-probe`), computed
    /// with Python — borsh by hand with `struct`, `hashlib`, PyNaCl — for
    /// message "Login to example.com", recipient "example.com", nonce 00 01 …
    /// 1f, by SEED_A: the host builds the identical signature.
    const NEP413_HASH: &str = "cd116988f58c30e8e583243b8b61ea5f567ccbc8529dcca6565ae2022d559ed2";
    const NEP413_HASH_CB: &str = "b54001a0afc35cf781a640b30fa20aa202a2a64a1e6de3fc0889421b8d1cf028";
    const NEP413_PUBLIC_KEY: &str = "ed25519:ByeoqbFJ3wTXANnK9bSQqdB8uM7iVQFFxMHdJTWkEN3K";
    const NEP413_SIGNATURE: &str = "BwSUP+RPUQJ6gV30nIFJsy3ywCs4VvRtd9QV6quPxK5MVrWn/7Y1+ADzS6652AsDVsZJIHLuZRDWNivImQJtDw==";
    const NEP413_SIGNATURE_CB: &str = "pYY73u/dA6smLFR3cTEG/Bdi1JkiXVT+KK+oQvJBa4+SvYtvq/k1xHVBp0EDngBSM0/SLhM09adQ3r4HQXMCCg==";

    fn nonce() -> [u8; 32] {
        std::array::from_fn(|i| i as u8)
    }

    #[test]
    fn the_nep413_bytes_are_the_specifications() {
        assert_eq!(NEP413_TAG, 2_147_484_061);
        assert_eq!(hex::encode(nep413_hash("Login to example.com", &nonce(), "example.com", None)), NEP413_HASH);
        assert_eq!(
            hex::encode(nep413_hash("Login to example.com", &nonce(), "example.com", Some("https://example.com/cb"))),
            NEP413_HASH_CB
        );
        // borsh's bytes, spelled out: the tag, then each field in order.
        let mut expected = Vec::new();
        expected.extend_from_slice(&2_147_484_061u32.to_le_bytes());
        expected.extend_from_slice(&2u32.to_le_bytes());
        expected.extend_from_slice(b"hi");
        expected.extend_from_slice(&[7; 32]);
        expected.extend_from_slice(&1u32.to_le_bytes());
        expected.extend_from_slice(b"r");
        expected.push(1);
        expected.extend_from_slice(&1u32.to_le_bytes());
        expected.extend_from_slice(b"c");
        use sha2::Digest;
        assert_eq!(nep413_hash("hi", &[7; 32], "r", Some("c")), <[u8; 32]>::from(sha2::Sha256::digest(&expected)));
    }

    #[test]
    fn the_host_nep413_signature_is_the_guest_built_one() {
        use ed25519_dalek::Verifier;
        let keys = secp_keys();
        for (callback, hash, pinned) in [(None, NEP413_HASH, NEP413_SIGNATURE), (Some("https://example.com/cb"), NEP413_HASH_CB, NEP413_SIGNATURE_CB)] {
            let signed = keys.sign_nep413("alpha", None, "Login to example.com", "example.com", &nonce(), callback).unwrap();
            assert_eq!(signed.account_id, PUB_A, "the implicit account is the public key in hex");
            assert_eq!(signed.public_key, NEP413_PUBLIC_KEY);
            assert_eq!(signed.signature, pinned, "PyNaCl's signature, byte for byte");
            // The same as the key's own `sign` over the hash.
            use base64::Engine;
            let raw = base64::engine::general_purpose::STANDARD.decode(&signed.signature).unwrap();
            assert_eq!(raw, keys.sign("alpha", None, &hash32(hash)).unwrap());
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&hash32(PUB_A)).unwrap();
            assert!(vk.verify(&hash32(hash), &ed25519_dalek::Signature::from_slice(&raw).unwrap()).is_ok());
        }
        // A vaulted ed25519 key follows the vault rule.
        let keys = two_keys();
        assert!(keys.sign_nep413("payouts", None, "m", "r", &nonce(), None).unwrap_err().contains("names none"));
        let signed = keys.sign_nep413("payouts", Some("vault.alice.near"), "m", "r", &nonce(), None).unwrap();
        assert_eq!(hex::decode(&signed.account_id).unwrap(), keys.public_key("payouts", Some("vault.alice.near")).unwrap());
    }

    #[test]
    fn sign_nep413_refuses_another_type_a_bad_nonce_and_oversized_fields() {
        let keys = secp_keys();
        let e = keys.sign_nep413("evm", None, "m", "r", &nonce(), None).unwrap_err();
        assert!(e.contains("ed25519 key") && e.contains("\"evm\" is secp256k1"), "{e}");
        for len in [0usize, 16, 31, 33, 64] {
            let e = keys.sign_nep413("alpha", None, "m", "r", &vec![0; len], None).unwrap_err();
            assert!(e.contains(&format!("nonce is {len} bytes")) && e.contains("exactly 32"), "{e}");
        }
        let at = |n: usize| "a".repeat(n);
        assert!(keys.sign_nep413("alpha", None, &at(MAX_NEP413_MESSAGE_BYTES), "r", &nonce(), None).is_ok());
        let e = keys.sign_nep413("alpha", None, &at(MAX_NEP413_MESSAGE_BYTES + 1), "r", &nonce(), None).unwrap_err();
        assert!(e.contains("message is 65537 bytes; at most 65536"), "{e}");
        assert!(keys.sign_nep413("alpha", None, "m", &at(MAX_NEP413_RECIPIENT_BYTES), &nonce(), None).is_ok());
        let e = keys.sign_nep413("alpha", None, "m", &at(MAX_NEP413_RECIPIENT_BYTES + 1), &nonce(), None).unwrap_err();
        assert!(e.contains("recipient is 2049 bytes; at most 2048"), "{e}");
        assert!(keys.sign_nep413("alpha", None, "m", "r", &nonce(), Some(&at(MAX_NEP413_CALLBACK_URL_BYTES))).is_ok());
        let e = keys.sign_nep413("alpha", None, "m", "r", &nonce(), Some(&at(MAX_NEP413_CALLBACK_URL_BYTES + 1))).unwrap_err();
        assert!(e.contains("callback URL is 2049 bytes; at most 2048"), "{e}");
        // An undeclared path and a wrong vault are refused before anything else.
        assert!(keys.sign_nep413("nope", None, "m", "r", &[], None).unwrap_err().contains("no signing key at path"));
        assert!(keys.sign_nep413("alpha", Some("vault.alice.near"), "m", "r", &[], None).unwrap_err().contains("declared without a vault"));
        // Every refusal is a reason, not an echo.
        let e = keys.sign_nep413("alpha", None, &at(1 << 20), "r", &nonce(), None).unwrap_err();
        assert!(e.len() < 200, "{e}");
    }
}
