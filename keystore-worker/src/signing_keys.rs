//! Signing keys: keys a WebAssembly artefact declares in its manifest, derived
//! here from a master and handed to the worker for the one job that asked.
//!
//! An artefact declares the keys it needs (`"signing_keys": [{"path":
//! "records", "type": "ed25519"}]`); the worker sends those declarations in the
//! run's `/decrypt` request (`KeyedDecryptRequest`, `api_support.rs`) together
//! with the job's project, caller and measured build, and this keystore derives
//! each key under one of two bindings — no other binding exists:
//!
//! ```text
//! bind "project": HMAC-SHA256(master, "signing-key:v1:{type}:project:{project_uuid}:{caller}:{account_id}:{path}")
//! bind "wasm":    HMAC-SHA256(master, "signing-key:v1:{type}:wasm:{wasm_sha256}:{caller}:{account_id}:{path}")
//! ```
//!
//! `caller` is which account of the job the key belongs to, chosen per key in
//! the manifest (`"caller": "signer" | "predecessor"`, default `signer`), and
//! `account_id` is that account:
//!
//! * `signer` — the job's `user_account_id`: the transaction signer on chain,
//!   the payment-key owner over HTTPS.
//! * `predecessor` — the job's `predecessor_id`: the receipt predecessor on
//!   chain (a DAO, a wallet contract), equal to the signer over HTTPS. A
//!   `predecessor` key on a request that carries no `predecessor_id` is
//!   refused.
//!
//! The choice is a segment of the string with a fixed label, so a signer key
//! and a predecessor key for one account are two keys.
//!
//! A key is issued strictly by how the code is run. A request that names a
//! `project_id` is a project run; one that names none is a direct run of a wasm
//! URL. Every declared key's binding must match, or the whole request is
//! refused:
//!
//! * `project` — only for a project run whose executed build is a version of
//!   that project published as a WasmUrl (checked on the contract). The key
//!   belongs to the project and the caller: every version of the project
//!   derives the same key, so it survives a code upgrade. The string carries
//!   the project's `uuid` (`p{16 hex}`, minted once by the contract at
//!   `create_project` and read back through `get_project`), never its
//!   `owner/name` id: a project deleted and created again under the same name
//!   is another project with another uuid, and so another key.
//! * `wasm` — only for a direct run: no project. The key belongs to the exact
//!   build and the caller; a new build is a new key. Because the key belongs to
//!   the code, the code must not decide what to sign from its secrets,
//!   environment or configuration: whoever runs the binary controls those.
//! * A run built from a GitHub repository gets no key at all. Through a
//!   project, this keystore sees it: the version found by the build's hash has
//!   a GitHub source, or no version is found, and the request is refused.
//!   Directly, only the worker sees it — it holds the resolved code source,
//!   while this keystore holds nothing but the hash of what runs, which does
//!   not say how the bytes were obtained — so the worker refuses a direct
//!   GitHub build before any request is made (`worker/src/signing_keys`).
//!
//! `path` is an input of the derivation, not a label on a key: the same path
//! derives the same key forever, a different path derives a different key, and
//! renaming a path in a manifest therefore loses the key it named.
//!
//! **What is trusted, and what is checked.** `user_account_id` and
//! `predecessor_id` (the job's accounts), `executed_wasm_sha256` (the hash the
//! worker measured on the bytes it runs) and `project_id` (the job's project)
//! come from the worker, and are
//! taken on the trust of its TEE attestation — the same trust every secret's
//! access condition is judged on. A worker that is not what it attests to be
//! can name any caller, any build and any project, and receive their keys;
//! nothing here limits it to the jobs it was given. What this keystore verifies
//! is what the chain can answer: that the build is a WasmUrl version of the
//! named project, that the project exists and is owned by the account its id
//! names, and that each vault a key names belongs to that owner.
//!
//! `master` is the default master, or — for a `project` key that names a
//! `vault` — that vault's master, which must belong to the project's owner. A
//! vault that is not available is a refusal, never the default master in its
//! place. A `wasm` key cannot name a vault: it has no project owner to own one.
//!
//! **The string is built here, from validated fields only.** No field may hold
//! a `:` — each is checked against a shape that cannot contain one — so after
//! the fixed `signing-key:v1:{type}:{bind}` the segments parse back uniquely,
//! and two different tuples never spell one string. The root `signing-key:v1:`
//! is the start of no other seed this keystore derives (pinned in `api_tests`),
//! so no other family's string equals a signing key's, and no signing key's
//! equals another family's.
//!
//! `v1` names the scheme. A different scheme would be added beside it under its
//! own label; this one never changes, because changing it changes every key and
//! every signature made with one.

use near_primitives::types::AccountId;
use serde::{Deserialize, Serialize};

/// The root of every signing-key derivation string.
pub const SIGNING_KEY_LABEL: &str = "signing-key:v1:";

/// How many keys one request may name — the manifest's own limit. The bound
/// keeps one request from making the keystore derive without limit.
pub const MAX_SIGNING_KEYS: usize = 3;

/// Longest key path: `[a-z0-9][a-z0-9_-]{0,31}`.
pub const MAX_KEY_PATH_LEN: usize = 32;

/// Longest project name, the part after `/` — the contract's own limit.
const MAX_PROJECT_NAME_LEN: usize = 64;

/// Caller strings the worker writes where it has no caller: a key bound to one
/// of these would be the key of everyone who ever ran without a sender. Refused
/// by name, before the account-id check, which would accept `anonymous` as a
/// perfectly valid NEAR account id.
///
/// The worker writes `"anonymous"` as the storage account of a run without a
/// sender (`worker/src/main.rs`, `storage_account_id`).
pub const PLACEHOLDER_CALLERS: &[&str] = &["anonymous"];

/// The algorithm a key is for. It is an input of the derivation, so one secret
/// never serves two algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SigningKeyType {
    /// The 32-byte seed is the ed25519 signing-key seed (RFC 8032).
    Ed25519,
}

impl SigningKeyType {
    /// The segment this type contributes to the derivation string.
    pub fn label(self) -> &'static str {
        match self {
            SigningKeyType::Ed25519 => "ed25519",
        }
    }
}

/// What a key belongs to besides the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyBinding {
    /// The project: every version of its code derives the same key.
    #[default]
    Project,
    /// The exact build: any job running these bytes derives the same key.
    Wasm,
}

impl KeyBinding {
    /// The tag this binding contributes to the derivation string.
    pub fn label(self) -> &'static str {
        match self {
            KeyBinding::Project => "project",
            KeyBinding::Wasm => "wasm",
        }
    }
}

/// Which account of the job a key belongs to. A segment of the derivation
/// string, so the two choices never derive one key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CallerKind {
    /// The job's `user_account_id`: the transaction signer on chain, the
    /// payment-key owner over HTTPS.
    #[default]
    Signer,
    /// The job's `predecessor_id`: the receipt predecessor on chain — the DAO
    /// or wallet contract that called the contract — and the signer itself over
    /// HTTPS. Refused when the request carries no `predecessor_id`.
    Predecessor,
}

impl CallerKind {
    /// The segment this choice contributes to the derivation string.
    pub fn label(self) -> &'static str {
        match self {
            CallerKind::Signer => "signer",
            CallerKind::Predecessor => "predecessor",
        }
    }
}

/// One key as the worker asks for it, copied from the running artefact's
/// manifest. Unknown fields are refused: a misspelled `vault` would otherwise
/// be read as "no vault" and derive from the default master, a misspelled
/// `bind` as "project", a misspelled `caller` as "signer".
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SigningKeyRequest {
    /// An input of the derivation: the same path is the same key forever, a
    /// renamed path is a different key.
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

/// A key path that passed [`KeyPath::parse`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyPath(String);

impl KeyPath {
    /// `[a-z0-9][a-z0-9_-]{0,31}`: non-empty, lowercase, no `:`.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let bytes = raw.as_bytes();
        let Some(&first) = bytes.first() else {
            return Err("a key path must not be empty".to_string());
        };
        if bytes.len() > MAX_KEY_PATH_LEN {
            return Err(format!(
                "key path {:?} is {} bytes; at most {} are allowed",
                truncate_for_message(raw),
                bytes.len(),
                MAX_KEY_PATH_LEN
            ));
        }
        let lower_alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
        if !lower_alnum(first) || !bytes.iter().all(|&b| lower_alnum(b) || b == b'_' || b == b'-') {
            return Err(format!(
                "key path {:?} must match [a-z0-9][a-z0-9_-]{{0,31}}",
                truncate_for_message(raw)
            ));
        }
        Ok(Self(raw.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A project id that passed [`ProjectId::parse`]: `{owner}/{name}`. It names
/// the project on the contract (`get_version`, `get_project`) and says who
/// must own it; it is not part of any derivation string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectId {
    id: String,
    owner: AccountId,
}

impl ProjectId {
    /// `{owner}/{name}` — `owner` a valid NEAR account id, `name` 1 to 64 of
    /// `[A-Za-z0-9_-]`. Neither half can hold a `:` or a second `/`.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let Some((owner, name)) = raw.split_once('/') else {
            return Err(format!(
                "project_id {:?} is not of the form <owner>/<name>",
                truncate_for_message(raw)
            ));
        };
        let owner: AccountId = owner.parse().map_err(|e| {
            format!(
                "project_id {:?}: the owner is not a valid NEAR account id ({e})",
                truncate_for_message(raw)
            )
        })?;
        let name_ok = !name.is_empty()
            && name.len() <= MAX_PROJECT_NAME_LEN
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !name_ok {
            return Err(format!(
                "project_id {:?}: the name must be 1 to {MAX_PROJECT_NAME_LEN} of [A-Za-z0-9_-]",
                truncate_for_message(raw)
            ));
        }
        Ok(Self { id: raw.to_string(), owner })
    }

    pub fn as_str(&self) -> &str {
        &self.id
    }

    /// The account the id names as its owner.
    pub fn owner(&self) -> &AccountId {
        &self.owner
    }
}

/// A project's uuid as the contract mints it (`contract/src/projects.rs`,
/// `create_project`): `p` and 16 lowercase hex digits. What a `project` key is
/// bound to. Read from the contract's `get_project` answer, never from the
/// request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectUuid(String);

impl ProjectUuid {
    /// `^p[0-9a-f]{16}$`.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let ok = raw.len() == 17
            && raw.starts_with('p')
            && raw[1..].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !ok {
            return Err(format!(
                "project uuid {:?} is not 'p' followed by 16 lowercase hex digits",
                truncate_for_message(raw)
            ));
        }
        Ok(Self(raw.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The SHA-256 of the running build, as the worker measured it: exactly 64
/// lowercase hex characters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmSha256(String);

impl WasmSha256 {
    pub fn parse(raw: &str) -> Result<Self, String> {
        let ok = raw.len() == 64 && raw.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !ok {
            return Err(format!(
                "executed_wasm_sha256 {:?} is not 64 lowercase hex characters",
                truncate_for_message(raw)
            ));
        }
        Ok(Self(raw.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What one key's string is bound to, validated.
#[derive(Debug, Clone, Copy)]
pub enum Binding<'a> {
    Project(&'a ProjectUuid),
    Wasm(&'a WasmSha256),
}

/// The derivation string of one key. Built only by [`DerivationInput::new`]
/// from validated parts, so nothing else can hand the keystore a string to
/// derive under this root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivationInput(String);

impl DerivationInput {
    /// `signing-key:v1:{type}:project:{project_uuid}:{caller}:{account_id}:{path}`,
    /// or `signing-key:v1:{type}:wasm:{wasm_sha256}:{caller}:{account_id}:{path}`.
    ///
    /// Every part is already a validated type that cannot hold a `:`; the check
    /// here is the invariant the whole scheme rests on, stated once more where
    /// the string is made.
    pub fn new(
        key_type: SigningKeyType,
        binding: Binding<'_>,
        caller: CallerKind,
        account: &AccountId,
        path: &KeyPath,
    ) -> Result<Self, String> {
        let (tag, bound_to) = match binding {
            Binding::Project(uuid) => (KeyBinding::Project.label(), uuid.as_str()),
            Binding::Wasm(wasm) => (KeyBinding::Wasm.label(), wasm.as_str()),
        };
        let parts = [key_type.label(), tag, bound_to, caller.label(), account.as_str(), path.as_str()];
        if let Some(bad) = parts.iter().find(|p| p.is_empty() || p.contains(':')) {
            return Err(format!(
                "a signing-key field is empty or holds ':' ({:?})",
                truncate_for_message(bad)
            ));
        }
        Ok(Self(format!("{SIGNING_KEY_LABEL}{}", parts.join(":"))))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    #[cfg(test)]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One requested key, validated on its fields: its path, its type, its
/// binding, which of the job's accounts it belongs to and that account, and
/// the vault whose master it derives from (`None` for the default master). Its
/// derivation string is built by [`ValidatedKeys::bind`], once the project's
/// uuid is known.
#[derive(Debug, Clone)]
pub struct ValidatedKey {
    pub path: KeyPath,
    pub key_type: SigningKeyType,
    pub bind: KeyBinding,
    pub caller: CallerKind,
    /// The job's signer or predecessor, as `caller` says.
    pub account: AccountId,
    pub vault: Option<AccountId>,
}

/// A whole request's keys, validated against the job's project, accounts and
/// build — everything that can be checked before a chain read.
#[derive(Debug, Clone)]
pub struct ValidatedKeys {
    /// The job's project: present exactly for a project run.
    pub project: Option<ProjectId>,
    /// The job's `user_account_id`.
    pub signer: AccountId,
    /// The job's `predecessor_id`, when the request carries one.
    pub predecessor: Option<AccountId>,
    pub wasm_sha256: WasmSha256,
    pub keys: Vec<ValidatedKey>,
}

impl ValidatedKeys {
    /// The distinct vaults the keys name, in first-seen order.
    pub fn vaults(&self) -> Vec<AccountId> {
        let mut out: Vec<AccountId> = Vec::new();
        for v in self.keys.iter().filter_map(|k| k.vault.as_ref()) {
            if !out.contains(v) {
                out.push(v.clone());
            }
        }
        out
    }

    /// Build every key's derivation string. `project_uuid` is the contract's
    /// uuid of the run's project, required exactly when the run has one: a
    /// project run without its uuid, or a direct run handed one, is refused.
    pub fn bind(self, project_uuid: Option<ProjectUuid>) -> Result<BoundKeys, String> {
        let project = match (self.project, project_uuid) {
            (Some(id), Some(uuid)) => Some(BoundProject { id, uuid }),
            (None, None) => None,
            (Some(id), None) => {
                return Err(format!("project {} has no uuid to bind its keys to", id.as_str()));
            }
            (None, Some(uuid)) => {
                return Err(format!("a direct run has no project, and uuid {} was given for one", uuid.as_str()));
            }
        };
        let mut keys = Vec::with_capacity(self.keys.len());
        for key in self.keys {
            let binding = match (key.bind, project.as_ref()) {
                (KeyBinding::Project, Some(p)) => Binding::Project(&p.uuid),
                (KeyBinding::Wasm, None) => Binding::Wasm(&self.wasm_sha256),
                // `validate_request` refuses these pairings before anything is bound.
                (KeyBinding::Project, None) | (KeyBinding::Wasm, Some(_)) => {
                    return Err(format!(
                        "key {:?} is bound to {} and the run does not match",
                        key.path.as_str(),
                        key.bind.label()
                    ));
                }
            };
            let input = DerivationInput::new(key.key_type, binding, key.caller, &key.account, &key.path)?;
            keys.push(BoundKey {
                path: key.path,
                key_type: key.key_type,
                bind: key.bind,
                caller: key.caller,
                account: key.account,
                vault: key.vault,
                input,
            });
        }
        Ok(BoundKeys { project, signer: self.signer, predecessor: self.predecessor, wasm_sha256: self.wasm_sha256, keys })
    }
}

/// The run's project as the contract knows it: the id the request named, and
/// the uuid the contract holds under it.
#[derive(Debug, Clone)]
pub struct BoundProject {
    pub id: ProjectId,
    pub uuid: ProjectUuid,
}

/// One key with its derivation string.
#[derive(Debug, Clone)]
pub struct BoundKey {
    pub path: KeyPath,
    pub key_type: SigningKeyType,
    pub bind: KeyBinding,
    pub caller: CallerKind,
    /// The account the key belongs to: the job's signer or predecessor.
    pub account: AccountId,
    pub vault: Option<AccountId>,
    pub input: DerivationInput,
}

/// A whole request's keys, each with its derivation string: what
/// `derive_signing_key_seed` is given.
#[derive(Debug, Clone)]
pub struct BoundKeys {
    pub project: Option<BoundProject>,
    pub signer: AccountId,
    pub predecessor: Option<AccountId>,
    pub wasm_sha256: WasmSha256,
    pub keys: Vec<BoundKey>,
}

/// Validate everything the request says about keys, before any chain read.
///
/// `project_id`, `account_id` (the signer), `predecessor_id` and
/// `executed_wasm_sha256` are the job's (sent by the worker, never by the
/// guest). A `project_id` makes the run a project run; none makes it a direct
/// run. Refused, and the whole request with it:
/// * no keys, or more than [`MAX_SIGNING_KEYS`];
/// * a malformed project id;
/// * a signer or predecessor that is a placeholder ([`PLACEHOLDER_CALLERS`])
///   or not a NEAR account id, a build hash that is missing or not 64 lowercase
///   hex;
/// * a path of the wrong shape, or a path asked for twice;
/// * a key whose binding does not match the run: a `wasm` key on a project run,
///   a `project` key on a direct run;
/// * a `predecessor` key on a request that names no `predecessor_id`;
/// * a vault that is empty or not an account id, or a vault on a `wasm` key.
pub fn validate_request(
    project_id: Option<&str>,
    account_id: &str,
    predecessor_id: Option<&str>,
    executed_wasm_sha256: Option<&str>,
    keys: &[SigningKeyRequest],
) -> Result<ValidatedKeys, String> {
    if keys.is_empty() {
        return Err("no signing keys were requested".to_string());
    }
    if keys.len() > MAX_SIGNING_KEYS {
        return Err(format!(
            "{} signing keys were requested; at most {MAX_SIGNING_KEYS} are allowed",
            keys.len()
        ));
    }
    let project = project_id.map(ProjectId::parse).transpose()?;
    let signer = real_account("caller", account_id)?;
    let predecessor = predecessor_id.map(|p| real_account("predecessor", p)).transpose()?;
    let Some(executed_wasm_sha256) = executed_wasm_sha256 else {
        return Err("signing keys need the running build's executed_wasm_sha256, and the request names none".to_string());
    };
    let wasm_sha256 = WasmSha256::parse(executed_wasm_sha256)?;

    let mut out: Vec<ValidatedKey> = Vec::with_capacity(keys.len());
    for request in keys {
        let path = KeyPath::parse(&request.path)?;
        if out.iter().any(|k| k.path == path) {
            return Err(format!("key path {:?} is requested twice", path.as_str()));
        }
        match (request.bind, project.as_ref()) {
            (KeyBinding::Project, Some(_)) | (KeyBinding::Wasm, None) => {}
            (KeyBinding::Project, None) => {
                return Err(format!(
                    "key {:?} is bound to the project (bind \"project\"), and this is a direct wasm run \
                     with no project; a project key is issued only to a run through its project",
                    path.as_str()
                ))
            }
            (KeyBinding::Wasm, Some(p)) => {
                return Err(format!(
                    "key {:?} is bound to the build (bind \"wasm\"), and this run goes through project {}; \
                     a wasm key is issued only to a direct run of the wasm URL, and a project run holds \
                     only bind \"project\" keys",
                    path.as_str(),
                    p.as_str()
                ))
            }
        }
        let account = match request.caller {
            CallerKind::Signer => signer.clone(),
            CallerKind::Predecessor => predecessor.clone().ok_or_else(|| {
                format!(
                    "key {:?} belongs to the predecessor (caller \"predecessor\"), and this run carries no \
                     predecessor_id to bind it to",
                    path.as_str()
                )
            })?,
        };
        let vault = match (request.vault.as_deref(), request.bind) {
            (None, _) => None,
            (Some(_), KeyBinding::Wasm) => {
                return Err(format!(
                    "key {:?}: a key bound to the build (bind \"wasm\") cannot name a vault — it has no \
                     project owner to own one",
                    path.as_str()
                ))
            }
            (Some(raw), KeyBinding::Project) => Some(raw.parse::<AccountId>().map_err(|e| {
                format!(
                    "key {:?}: vault {:?} is not a valid NEAR account id ({e})",
                    path.as_str(),
                    truncate_for_message(raw)
                )
            })?),
        };
        out.push(ValidatedKey { path, key_type: request.key_type, bind: request.bind, caller: request.caller, account, vault });
    }
    Ok(ValidatedKeys { project, signer, predecessor, wasm_sha256, keys: out })
}

/// `raw` as an account a key may belong to: not a placeholder the worker
/// writes for a missing account, and a valid NEAR account id. `role` names the
/// field in the refusal.
fn real_account(role: &str, raw: &str) -> Result<AccountId, String> {
    if PLACEHOLDER_CALLERS.contains(&raw) {
        return Err(format!(
            "the {role} {raw:?} is the worker's placeholder for a run without one, not an account; a signing \
             key needs a real caller to be bound to, so a run without one gets no key"
        ));
    }
    raw.parse().map_err(|e| {
        format!(
            "the {role} {:?} is not a valid NEAR account id ({e}); a signing key is bound to one",
            truncate_for_message(raw)
        )
    })
}

/// Is `vault` named under `owner` — a DIRECT sub-account of it? On NEAR only
/// `owner` can create `x.owner`. Decided on the two names alone, so a vault
/// that is not the owner's is refused without a single read of it.
pub fn vault_is_named_under(owner: &AccountId, vault: &AccountId) -> Result<(), String> {
    if !vault.is_sub_account_of(owner) {
        return Err(format!(
            "vault {vault} does not belong to {owner}, the project's owner: it is not a direct \
             sub-account of {owner}"
        ));
    }
    Ok(())
}

/// Does `vault` belong to `owner`?
///
/// Two independent facts, both required:
/// * the vault account is a DIRECT sub-account of `owner`
///   ([`vault_is_named_under`]);
/// * the vault's own `get_state().parent` is `owner` — the vault contract sets
///   it once, at `new`, and refuses to be deployed on an account that is not a
///   direct sub-account of it.
///
/// `state` is the vault's `get_state` answer. A missing or non-string `parent`
/// is a refusal, not a pass.
pub fn vault_belongs_to(
    owner: &AccountId,
    vault: &AccountId,
    state: &serde_json::Value,
) -> Result<(), String> {
    vault_is_named_under(owner, vault)?;
    let parent = state
        .get("parent")
        .and_then(|p| p.as_str())
        .ok_or_else(|| format!("vault {vault}: get_state names no parent, so its owner cannot be established"))?;
    if parent != owner.as_str() {
        return Err(format!(
            "vault {vault} does not belong to {owner}, the project's owner: its parent is {parent}"
        ));
    }
    Ok(())
}

/// A derived seed in hex, as the `/decrypt` response carries it to the worker.
/// Wiped when dropped; its `Debug` prints nothing of it.
pub struct SeedHex(zeroize::Zeroizing<String>);

impl SeedHex {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(zeroize::Zeroizing::new(hex::encode(seed)))
    }
}

impl Serialize for SeedHex {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl std::fmt::Debug for SeedHex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SeedHex(..)")
    }
}

/// Most characters of another party's text that a message repeats: an RPC or
/// contract error quoted in a refusal or a log line.
pub(crate) const MOST_QUOTED_ERROR: usize = 200;

/// `text`, cut to at most `most` characters, with a mark where it was cut.
pub(crate) fn bounded(text: &str, most: usize) -> String {
    match text.char_indices().nth(most) {
        Some((cut, _)) => format!("{}…", &text[..cut]),
        None => text.to_string(),
    }
}

/// A caller-written value, as a refusal may quote it: cut short so a huge field
/// cannot fill a response or a log line.
pub(crate) fn truncate_for_message(raw: &str) -> String {
    bounded(raw, 80)
}

#[cfg(test)]
mod tests {
    use super::*;

    const H1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const H2: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const P1: &str = "p0000000000000001";
    const P2: &str = "p0000000000000002";

    fn acct(s: &str) -> AccountId {
        s.parse().unwrap()
    }

    fn uuid(s: &str) -> ProjectUuid {
        ProjectUuid::parse(s).unwrap()
    }

    fn req(path: &str) -> SigningKeyRequest {
        SigningKeyRequest {
            path: path.to_string(),
            key_type: SigningKeyType::Ed25519,
            bind: KeyBinding::Project,
            caller: CallerKind::Signer,
            vault: None,
        }
    }

    fn wasm_req(path: &str) -> SigningKeyRequest {
        SigningKeyRequest { bind: KeyBinding::Wasm, ..req(path) }
    }

    fn pred_req(path: &str) -> SigningKeyRequest {
        SigningKeyRequest { caller: CallerKind::Predecessor, ..req(path) }
    }

    /// A run through project `alice.near/app` as `bob.near`, on build H1.
    fn validate(keys: &[SigningKeyRequest]) -> Result<ValidatedKeys, String> {
        validate_request(Some("alice.near/app"), "bob.near", None, Some(H1), keys)
    }

    /// The same run, its project's uuid P1 read, keys bound.
    fn bound(keys: &[SigningKeyRequest]) -> Result<BoundKeys, String> {
        validate(keys)?.bind(Some(uuid(P1)))
    }

    /// A direct run of build H1 as `bob.near`.
    fn validate_direct(keys: &[SigningKeyRequest]) -> Result<ValidatedKeys, String> {
        validate_request(None, "bob.near", None, Some(H1), keys)
    }

    fn bound_direct(keys: &[SigningKeyRequest]) -> Result<BoundKeys, String> {
        validate_direct(keys)?.bind(None)
    }

    #[test]
    fn the_derivation_strings_have_the_pinned_shapes() {
        let v = bound(&[req("records")]).unwrap();
        assert_eq!(v.keys[0].input.as_str(), "signing-key:v1:ed25519:project:p0000000000000001:signer:bob.near:records");
        let project = v.project.as_ref().unwrap();
        assert_eq!(project.id.as_str(), "alice.near/app");
        assert_eq!(project.id.owner().as_str(), "alice.near");
        assert_eq!(project.uuid.as_str(), P1);
        assert_eq!(v.signer.as_str(), "bob.near");
        assert_eq!(v.keys[0].account.as_str(), "bob.near");
        assert!(v.predecessor.is_none());
        let w = bound_direct(&[wasm_req("session")]).unwrap();
        assert_eq!(w.keys[0].input.as_str(), format!("signing-key:v1:ed25519:wasm:{H1}:signer:bob.near:session"));
        assert!(w.project.is_none());
        // A predecessor key, on a run whose predecessor is a DAO.
        let d = validate_request(Some("alice.near/app"), "bob.near", Some("dao.near"), Some(H1), &[pred_req("votes")])
            .unwrap()
            .bind(Some(uuid(P1)))
            .unwrap();
        assert_eq!(d.keys[0].input.as_str(), "signing-key:v1:ed25519:project:p0000000000000001:predecessor:dao.near:votes");
        assert_eq!(d.keys[0].account.as_str(), "dao.near");
        assert_eq!(d.predecessor.as_ref().unwrap().as_str(), "dao.near");
    }

    /// `caller` chooses which of the job's accounts the key belongs to, and is
    /// itself a segment: a signer key and a predecessor key never coincide,
    /// even for one account.
    #[test]
    fn the_caller_kind_is_a_segment_and_picks_the_account() {
        let run = |keys: &[SigningKeyRequest], predecessor: Option<&str>| {
            validate_request(Some("alice.near/app"), "bob.near", predecessor, Some(H1), keys)
                .unwrap()
                .bind(Some(uuid(P1)))
                .unwrap()
                .keys[0]
                .input
                .clone()
        };
        // Same account both ways (as over HTTPS): still two keys.
        assert_ne!(run(&[req("k")], Some("bob.near")), run(&[pred_req("k")], Some("bob.near")));
        // The predecessor key is the predecessor's, whoever signed.
        assert_eq!(
            run(&[pred_req("k")], Some("dao.near")),
            validate_request(Some("alice.near/app"), "carol.near", Some("dao.near"), Some(H1), &[pred_req("k")])
                .unwrap()
                .bind(Some(uuid(P1)))
                .unwrap()
                .keys[0]
                .input
        );
        // The signer key does not change with the predecessor.
        assert_eq!(run(&[req("k")], Some("dao.near")), run(&[req("k")], None));
        // The two labels are fixed and are the only two.
        assert_eq!(CallerKind::Signer.label(), "signer");
        assert_eq!(CallerKind::Predecessor.label(), "predecessor");
        let r: SigningKeyRequest = serde_json::from_str(r#"{"path":"k","type":"ed25519"}"#).unwrap();
        assert_eq!(r.caller, CallerKind::Signer);
        let r: SigningKeyRequest = serde_json::from_str(r#"{"path":"k","type":"ed25519","caller":"predecessor"}"#).unwrap();
        assert_eq!(r.caller, CallerKind::Predecessor);
        for bad in ["Signer", "PREDECESSOR", "", "user", "sender", "signer:x", "both"] {
            let body = format!(r#"{{"path":"k","type":"ed25519","caller":"{bad}"}}"#);
            assert!(serde_json::from_str::<SigningKeyRequest>(&body).is_err(), "caller {bad:?}");
        }
    }

    /// A predecessor key needs the run's predecessor; without one it is
    /// refused, and the whole request with it.
    #[test]
    fn a_predecessor_key_without_a_predecessor_is_refused() {
        let e = validate_request(Some("alice.near/app"), "bob.near", None, Some(H1), &[pred_req("k")]).unwrap_err();
        assert!(e.contains("carries no predecessor_id"), "{e}");
        let e = validate_request(None, "bob.near", None, Some(H1), &[SigningKeyRequest { bind: KeyBinding::Wasm, ..pred_req("k") }])
            .unwrap_err();
        assert!(e.contains("carries no predecessor_id"), "{e}");
        // One predecessor key among signer keys: the whole request.
        assert!(validate_request(Some("alice.near/app"), "bob.near", None, Some(H1), &[req("a"), pred_req("b")]).is_err());
        // The predecessor is checked like the signer: a real account id, not a placeholder.
        for bad in ["anonymous", "", "DAO", "dao..near", "dao.near:x"] {
            let e = validate_request(Some("alice.near/app"), "bob.near", Some(bad), Some(H1), &[pred_req("k")]).unwrap_err();
            assert!(e.contains("predecessor"), "{bad:?}: {e}");
            // Even a request whose keys are all signer keys refuses a bad predecessor.
            assert!(validate_request(Some("alice.near/app"), "bob.near", Some(bad), Some(H1), &[req("k")]).is_err(), "{bad:?}");
        }
    }

    /// A project key is bound to the project's uuid, never to its name: two
    /// projects that spell one `owner/name` — one deleted, one created again —
    /// are two keys, and the string never carries the id's `/`.
    #[test]
    fn a_project_key_follows_the_uuid_and_not_the_name() {
        let under = |u: &str| validate(&[req("k")]).unwrap().bind(Some(uuid(u))).unwrap().keys[0].input.clone();
        assert_eq!(under(P1), under(P1));
        assert_ne!(under(P1), under(P2));
        // Two ids, one uuid: one key. The id is not in the string.
        let other_name = validate_request(Some("alice.near/app2"), "bob.near", None, Some(H1), &[req("k")])
            .unwrap()
            .bind(Some(uuid(P1)))
            .unwrap();
        assert_eq!(other_name.keys[0].input, under(P1));
        for input in [under(P1), other_name.keys[0].input.clone()] {
            assert!(!input.as_str().contains('/'), "{}", input.as_str());
            assert!(!input.as_str().contains("alice.near"), "{}", input.as_str());
        }
    }

    #[test]
    fn a_project_uuid_has_exactly_one_shape() {
        for ok in [P1, P2, "pffffffffffffffff", "p0123456789abcdef"] {
            assert!(ProjectUuid::parse(ok).is_ok(), "{ok:?}");
        }
        for bad in [
            "",
            "p",
            "p1",
            "0000000000000001",
            "P0000000000000001",
            "p000000000000000",
            "p00000000000000001",
            "p000000000000000G",
            "p00000000000000:1",
            "q0000000000000001",
            "p0000000000000001 ",
        ] {
            assert!(ProjectUuid::parse(bad).is_err(), "{bad:?}");
        }
    }

    /// Binding needs the uuid exactly when the run has a project.
    #[test]
    fn binding_needs_the_uuid_exactly_for_a_project_run() {
        let e = validate(&[req("k")]).unwrap().bind(None).unwrap_err();
        assert!(e.contains("has no uuid"), "{e}");
        let e = validate_direct(&[wasm_req("k")]).unwrap().bind(Some(uuid(P1))).unwrap_err();
        assert!(e.contains("direct run has no project"), "{e}");
    }

    /// A key is issued strictly by how the code is run.
    #[test]
    fn a_key_is_issued_only_to_the_run_its_binding_names() {
        // A project run holds project keys, a direct run wasm keys.
        assert!(validate(&[req("k")]).is_ok());
        assert!(validate_direct(&[wasm_req("k")]).is_ok());
        // A project run declaring a wasm key: refused.
        let e = validate(&[wasm_req("k")]).unwrap_err();
        assert!(e.contains("bound to the build") && e.contains("only to a direct run"), "{e}");
        // A direct run declaring a project key: refused.
        let e = validate_direct(&[req("k")]).unwrap_err();
        assert!(e.contains("bound to the project") && e.contains("direct wasm run"), "{e}");
    }

    /// One key that does not match the run refuses the whole request, whichever
    /// position it holds.
    #[test]
    fn one_mismatched_key_refuses_the_whole_request() {
        assert!(validate(&[req("a"), req("b"), wasm_req("c")]).is_err());
        assert!(validate(&[wasm_req("c"), req("a")]).is_err());
        assert!(validate_direct(&[wasm_req("a"), wasm_req("b"), req("c")]).is_err());
        assert!(validate_direct(&[req("c"), wasm_req("a")]).is_err());
    }

    /// The worker's placeholder for a missing sender is not a caller.
    #[test]
    fn a_placeholder_caller_is_refused_by_name() {
        for placeholder in PLACEHOLDER_CALLERS {
            assert!(placeholder.parse::<AccountId>().is_ok(), "{placeholder:?} would pass as an account id");
            let e = validate_request(Some("alice.near/app"), placeholder, None, Some(H1), &[req("k")]).unwrap_err();
            assert!(e.contains("needs a real caller"), "{e}");
            let e = validate_request(None, placeholder, None, Some(H1), &[wasm_req("k")]).unwrap_err();
            assert!(e.contains("needs a real caller"), "{e}");
            let e = validate_request(None, "bob.near", Some(placeholder), Some(H1), &[wasm_req("k")]).unwrap_err();
            assert!(e.contains("needs a real caller") && e.contains("predecessor"), "{e}");
        }
        assert!(PLACEHOLDER_CALLERS.contains(&"anonymous"));
        // A real account whose name merely contains the word is not a placeholder.
        assert!(validate_request(None, "anonymous.near", None, Some(H1), &[wasm_req("k")]).is_ok());
    }

    #[test]
    fn bind_defaults_to_project_and_an_unknown_bind_is_refused() {
        let r: SigningKeyRequest = serde_json::from_str(r#"{"path":"k","type":"ed25519"}"#).unwrap();
        assert_eq!(r.bind, KeyBinding::Project);
        let r: SigningKeyRequest = serde_json::from_str(r#"{"path":"k","type":"ed25519","bind":"wasm"}"#).unwrap();
        assert_eq!(r.bind, KeyBinding::Wasm);
        for b in ["hash", "Wasm", "PROJECT", "", "project:x", "account", "code"] {
            let body = format!(r#"{{"path":"k","type":"ed25519","bind":"{b}"}}"#);
            assert!(serde_json::from_str::<SigningKeyRequest>(&body).is_err(), "bind {b:?}");
        }
        // `name` is not a field: a request spelling it is refused, not read as a path.
        assert!(serde_json::from_str::<SigningKeyRequest>(r#"{"name":"k","type":"ed25519"}"#).is_err());
    }

    #[test]
    fn one_tuple_under_the_two_bindings_is_two_strings() {
        let v = bound(&[req("k")]).unwrap();
        let w = bound_direct(&[wasm_req("k")]).unwrap();
        assert_ne!(v.keys[0].input, w.keys[0].input);
    }

    /// The path is an input of the derivation: the same path is the same
    /// string every time, a renamed path a different string.
    #[test]
    fn the_path_is_an_input_of_the_derivation() {
        let input = |p: &str| bound(&[req(p)]).unwrap().keys[0].input.clone();
        assert_eq!(input("records"), input("records"));
        assert_ne!(input("records"), input("records2"));
        assert_ne!(input("records"), input("record"));
        let direct = |p: &str| bound_direct(&[wasm_req(p)]).unwrap().keys[0].input.clone();
        assert_eq!(direct("session"), direct("session"));
        assert_ne!(direct("session"), direct("sessions"));
    }

    #[test]
    fn a_wasm_key_follows_the_build_and_a_project_key_does_not() {
        let direct = |h: &str| {
            validate_request(None, "bob.near", None, Some(h), &[wasm_req("k")]).unwrap().bind(None).unwrap().keys[0].input.clone()
        };
        assert_eq!(direct(H1), direct(H1));
        assert_ne!(direct(H1), direct(H2));
        let project = |h: &str| {
            validate_request(Some("alice.near/app"), "bob.near", None, Some(h), &[req("k")])
                .unwrap()
                .bind(Some(uuid(P1)))
                .unwrap()
                .keys[0]
                .input
                .clone()
        };
        assert_eq!(project(H1), project(H2));
    }

    #[test]
    fn a_wasm_key_cannot_name_a_vault() {
        let mut r = wasm_req("k");
        r.vault = Some("vault.alice.near".into());
        let e = validate_direct(&[r.clone()]).unwrap_err();
        assert!(e.contains("cannot name a vault"), "{e}");
        // On a project run it is refused already for its binding.
        assert!(validate(&[r]).is_err());
        let mut p = req("k");
        p.vault = Some("vault.alice.near".into());
        assert!(validate(&[p]).is_ok());
    }

    #[test]
    fn the_build_hash_is_required_and_has_one_shape() {
        assert!(validate_request(Some("alice.near/app"), "bob.near", None, None, &[req("k")]).is_err());
        assert!(validate_request(None, "bob.near", None, None, &[wasm_req("k")]).is_err());
        for bad in ["", "abc", &"AB".repeat(32), &"g".repeat(64), &format!("{H1}0"), &H1[1..], &format!("{}:", &H1[1..])] {
            assert!(
                validate_request(Some("alice.near/app"), "bob.near", None, Some(bad), &[req("k")]).is_err(),
                "hash {bad:?}"
            );
        }
    }

    #[test]
    fn a_path_has_exactly_one_shape() {
        for ok in ["a", "0", "records", "pay-outs", "pay_outs", "a1", &"a".repeat(32)] {
            assert!(KeyPath::parse(ok).is_ok(), "{ok:?} must be accepted");
        }
        for bad in [
            "",
            "-a",
            "_a",
            "A",
            "Records",
            "rec:ords",
            ":",
            "rec ords",
            "rec.ords",
            "rec/ords",
            "../records",
            "..",
            "ключ",
            &"a".repeat(33),
        ] {
            assert!(KeyPath::parse(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn empty_and_over_long_paths_are_refused() {
        let e = validate(&[req("")]).unwrap_err();
        assert!(e.contains("empty"), "{e}");
        let e = validate(&[req(&"a".repeat(33))]).unwrap_err();
        assert!(e.contains("at most 32"), "{e}");
    }

    #[test]
    fn a_colon_in_any_field_is_refused() {
        // path
        assert!(validate(&[req("a:b")]).is_err());
        assert!(validate_direct(&[wasm_req("a:b")]).is_err());
        // project id: in the owner half, in the name half, and as the whole id
        for p in ["alice.near:x/app", "alice.near/app:x", "alice.near/a:pp", ":/app", "alice.near:app"] {
            assert!(validate_request(Some(p), "bob.near", None, Some(H1), &[req("k")]).is_err(), "project {p:?}");
        }
        // account id
        for a in ["bob.near:x", "bob:near", ":"] {
            assert!(validate_request(Some("alice.near/app"), a, None, Some(H1), &[req("k")]).is_err(), "account {a:?}");
            assert!(validate_request(None, a, None, Some(H1), &[wasm_req("k")]).is_err(), "account {a:?}");
        }
        // predecessor
        for a in ["dao.near:x", ":"] {
            assert!(validate_request(Some("alice.near/app"), "bob.near", Some(a), Some(H1), &[pred_req("k")]).is_err(), "predecessor {a:?}");
        }
        // build hash
        let colon_hash = format!("{}:", &H1[..63]);
        assert!(validate_request(None, "bob.near", None, Some(&colon_hash), &[wasm_req("k")]).is_err());
        // vault
        let mut r = req("k");
        r.vault = Some("vault.alice.near:x".to_string());
        assert!(validate(&[r]).is_err());
        // uuid
        assert!(ProjectUuid::parse("p00000000000000:1").is_err());
        // type and bind: fixed enums, so a value holding ':' cannot even be named
        assert!(serde_json::from_str::<SigningKeyRequest>(r#"{"path":"k","type":"ed25519:x"}"#).is_err());
        assert!(serde_json::from_str::<SigningKeyRequest>(r#"{"path":"k","type":"ed25519","bind":"wasm:x"}"#).is_err());
    }

    #[test]
    fn the_input_constructor_refuses_a_colon_whatever_the_types_allow() {
        // The types already exclude ':'; the constructor's own check is what
        // this pins, independently of how the types are built.
        let bob = acct("bob.near");
        let k = KeyPath("k".into());
        let make = |b: Binding<'_>, p: &KeyPath| DerivationInput::new(SigningKeyType::Ed25519, b, CallerKind::Signer, &bob, p);
        let good_uuid = ProjectUuid(P1.into());
        let colon_uuid = ProjectUuid("p00000000000000:1".into());
        let empty_uuid = ProjectUuid(String::new());
        assert!(make(Binding::Project(&colon_uuid), &k).is_err());
        assert!(make(Binding::Project(&empty_uuid), &k).is_err());
        assert!(make(Binding::Project(&good_uuid), &KeyPath("k:x".into())).is_err());
        assert!(make(Binding::Project(&good_uuid), &KeyPath(String::new())).is_err());
        assert!(make(Binding::Wasm(&WasmSha256("ab:cd".into())), &k).is_err());
        assert!(make(Binding::Wasm(&WasmSha256(String::new())), &k).is_err());
        assert!(make(Binding::Project(&good_uuid), &k).is_ok());
    }

    #[test]
    fn an_unknown_type_is_refused() {
        for t in ["secp256k1", "Ed25519", "ED25519", "", "x25519"] {
            let body = format!(r#"{{"path":"k","type":"{t}"}}"#);
            assert!(serde_json::from_str::<SigningKeyRequest>(&body).is_err(), "type {t:?}");
        }
        assert!(serde_json::from_str::<SigningKeyRequest>(r#"{"path":"k"}"#).is_err(), "no type");
        let ok: SigningKeyRequest = serde_json::from_str(r#"{"path":"k","type":"ed25519"}"#).unwrap();
        assert_eq!(ok.key_type, SigningKeyType::Ed25519);
    }

    #[test]
    fn a_misspelled_field_is_refused_rather_than_ignored() {
        for body in [
            r#"{"path":"k","type":"ed25519","valut":"vault.alice.near"}"#,
            r#"{"path":"k","type":"ed25519","bnid":"wasm"}"#,
            r#"{"paht":"k","type":"ed25519"}"#,
        ] {
            assert!(serde_json::from_str::<SigningKeyRequest>(body).is_err(), "{body}");
        }
    }

    #[test]
    fn a_vault_must_be_a_real_account_id_and_never_blank() {
        for bad in ["", " ", "VAULT", "vault..alice.near"] {
            let mut r = req("k");
            r.vault = Some(bad.to_string());
            assert!(validate(&[r]).is_err(), "vault {bad:?}");
        }
    }

    /// Three keys are served; a fourth refuses the whole request.
    #[test]
    fn three_keys_are_accepted_and_four_refused() {
        assert_eq!(MAX_SIGNING_KEYS, 3);
        let three: Vec<_> = (0..3).map(|i| req(&format!("k{i}"))).collect();
        assert_eq!(bound(&three).unwrap().keys.len(), 3);
        let four: Vec<_> = (0..4).map(|i| req(&format!("k{i}"))).collect();
        let e = validate(&four).unwrap_err();
        assert!(e.contains("4 signing keys") && e.contains("at most 3"), "{e}");
        let three_direct: Vec<_> = (0..3).map(|i| wasm_req(&format!("k{i}"))).collect();
        assert!(bound_direct(&three_direct).is_ok());
        let four_direct: Vec<_> = (0..4).map(|i| wasm_req(&format!("k{i}"))).collect();
        assert!(validate_direct(&four_direct).is_err());
    }

    #[test]
    fn counts_duplicates_and_malformed_projects_are_refused() {
        assert!(validate(&[]).is_err());
        assert!(validate(&[req("k"), req("k")]).is_err());
        let mut vaulted = req("k");
        vaulted.vault = Some("vault.alice.near".into());
        assert!(validate(&[req("k"), vaulted]).is_err(), "one path, two masters: still one path");
        for p in ["", "alice.near", "/app", "alice.near/", "alice.near/app/x", "alice.near/ap p", "Alice.near/app"] {
            assert!(validate_request(Some(p), "bob.near", None, Some(H1), &[req("k")]).is_err(), "project {p:?}");
        }
        assert!(validate_request(Some("alice.near/app"), "", None, Some(H1), &[req("k")]).is_err());
    }

    #[test]
    fn the_segments_parse_back_uniquely() {
        // No field holds ':', so after `signing-key:v1:{type}:{bind}` splitting
        // on ':' recovers the tuple exactly, and two different tuples can never
        // spell one string.
        let account = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let project = validate_request(Some("a-b_c.near/My_App-2"), account, Some("signer.near"), Some(H2), &[req("x"), pred_req("y")])
            .unwrap()
            .bind(Some(uuid("pfedcba9876543210")))
            .unwrap();
        let direct = validate_request(None, account, None, Some(H2), &[wasm_req("pay-outs_1")]).unwrap().bind(None).unwrap();
        for v in [&project, &direct] {
            for k in &v.keys {
                let parts: Vec<&str> = k.input.as_str().split(':').collect();
                assert_eq!(parts.len(), 8, "{}", k.input.as_str());
                assert_eq!(&parts[..3], &["signing-key", "v1", "ed25519"], "{}", k.input.as_str());
                assert_eq!(parts[3], k.bind.label());
                let bound_to = match k.bind {
                    KeyBinding::Project => v.project.as_ref().unwrap().uuid.as_str(),
                    KeyBinding::Wasm => v.wasm_sha256.as_str(),
                };
                assert_eq!(&parts[4..], &[bound_to, k.caller.label(), k.account.as_str(), k.path.as_str()]);
            }
        }
    }

    #[test]
    fn a_vault_belongs_to_the_owner_only_by_both_facts() {
        let owner = acct("alice.near");
        let vault = acct("vault.alice.near");
        let state = |parent: &str| serde_json::json!({ "parent": parent, "unlocked": false });

        assert!(vault_belongs_to(&owner, &vault, &state("alice.near")).is_ok());
        assert!(vault_is_named_under(&owner, &vault).is_ok());
        // Someone else's vault, even if its state names our owner — and the
        // name alone already refuses it, before any state is read.
        assert!(vault_belongs_to(&owner, &acct("vault.mallory.near"), &state("alice.near")).is_err());
        assert!(vault_is_named_under(&owner, &acct("vault.mallory.near")).is_err());
        // Not a DIRECT sub-account.
        assert!(vault_belongs_to(&owner, &acct("x.vault.alice.near"), &state("alice.near")).is_err());
        assert!(vault_is_named_under(&owner, &acct("x.vault.alice.near")).is_err());
        // The owner's own account is not its vault.
        assert!(vault_belongs_to(&owner, &owner, &state("alice.near")).is_err());
        assert!(vault_is_named_under(&owner, &owner).is_err());
        // A sub-account whose vault names another parent.
        assert!(vault_belongs_to(&owner, &vault, &state("mallory.near")).is_err());
        // No parent at all.
        assert!(vault_belongs_to(&owner, &vault, &serde_json::json!({ "unlocked": false })).is_err());
        assert!(vault_belongs_to(&owner, &vault, &serde_json::json!({ "parent": 7 })).is_err());
    }

    #[test]
    fn the_distinct_vaults_are_listed_once() {
        let mut a = req("a");
        a.vault = Some("vault.alice.near".into());
        let mut b = req("b");
        b.vault = Some("vault.alice.near".into());
        let c = req("c");
        let v = validate(&[a, b, c]).unwrap();
        assert_eq!(v.vaults(), vec![acct("vault.alice.near")]);
    }

    #[test]
    fn quoted_text_is_cut_short() {
        assert_eq!(bounded("abc", 3), "abc");
        assert_eq!(bounded("abcd", 3), "abc…");
        assert_eq!(truncate_for_message(&"x".repeat(80)).len(), 80);
        assert!(truncate_for_message(&"x".repeat(81)).ends_with('…'));
        let long = bounded(&"e".repeat(1000), MOST_QUOTED_ERROR);
        assert_eq!(long.chars().count(), MOST_QUOTED_ERROR + 1);
    }

    #[test]
    fn a_seed_never_prints() {
        let s = SeedHex::from_seed(&[0xab; 32]);
        assert_eq!(format!("{s:?}"), "SeedHex(..)");
        assert_eq!(serde_json::to_string(&s).unwrap(), format!("\"{}\"", "ab".repeat(32)));
    }
}
