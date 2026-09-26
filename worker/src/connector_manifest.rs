//! Project manifest and the outbound-domain allowlist (§C3).
//!
//! A connector runs our code inside a keys-bearing TEE and talks to the
//! internet. What it may talk to is declared in a manifest carried in the
//! wasm's own `outlayer.manifest` custom section.
//!
//! **The artefact is the source, not a database and not a repository.** The
//! manifest is read out of the very bytes that are about to run, never handed
//! to this worker by the coordinator: an allowlist the coordinator supplies is
//! an allowlist an operator can widen silently, and the product's claim is
//! precisely that they cannot.
//!
//! **The custom section is the ONLY source**, and a file at a git ref may not
//! become a second one. A ref like `main` moves when somebody pushes, so a
//! policy read from there would change while nothing on chain did. The section
//! is covered by the on-chain wasm hash, which is what "anchored" has to mean.
//!
//! **Enforced from day one, and only where it can be.** For a connector the
//! allowlist is mandatory and fail-closed: no manifest, no network. For every
//! other project it is opt-in, because retrofitting a deny-by-default rule onto
//! projects that already exist would break them — which is the same argument
//! §C3 makes for introducing it on day one for connectors.
//!
//! Manifest shape (subset we read; see the connector manifest spec):
//!
//! ```jsonc
//! {
//!   "connector_id": "near-email",
//!   "capabilities": { "network": ["api.near.email"] }
//! }
//! ```

use serde::Deserialize;

/// Maximum manifest we will read. A manifest is a few hundred bytes; anything
/// larger is either a mistake or an attempt to make us buffer a repository.
const MAX_MANIFEST_BYTES: usize = 64 * 1024;

/// The manifest: the members this worker acts on, and those it accepts for
/// other readers. A member outside this list refuses the run, naming the
/// member and the ones that exist — a misspelling must not quietly become the
/// default it was written to override.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectManifest {
    /// Stable connector identity. Never contains a version — the version is a
    /// property of the code, not of who the connector is.
    #[serde(default)]
    pub connector_id: Option<String>,
    #[serde(default)]
    pub capabilities: Option<ManifestCapabilities>,
    /// Accepted as an alias for `capabilities.network` so a manifest that
    /// declares nothing else does not need the nesting.
    #[serde(default)]
    pub network: Option<Vec<String>>,
    /// Rate limits this connector declares about itself.
    ///
    /// DECLARATION, not enforcement. Enforcement is the coordinator's
    /// `operation_limits` table, because a limit has to be counted across calls
    /// and a guest sees only its own. What this buys is auditability: the
    /// manifest lives in a custom section of the wasm, so the numbers are
    /// covered by the on-chain hash and a reviewer can read what the connector
    /// claims without trusting our database.
    ///
    /// If the two ever disagree, the enforced number is the coordinator's. That
    /// is a gap, and it is named here rather than papered over: closing it needs
    /// the coordinator to read the manifest out of the artefact it dispatches,
    /// which it does not do today.
    #[serde(default)]
    pub limits: Option<Vec<ManifestLimit>>,
    /// The author's own credential, named by the artefact instead of by the
    /// call. `{ "owner": "author.near", "profile": "prod" }` — the secrets
    /// stored by `owner` under the accessor `Project(<this project id>)` and
    /// that profile are decrypted into the guest's environment on EVERY run,
    /// alongside whatever the call itself names (an agent's own secrets, over
    /// `X-Use-Owner-Secret`). `owner` defaults to the account the project is
    /// published under. Nothing here grants anything: the secret exists only
    /// because `owner` stored it for this project, and its access condition
    /// is still evaluated against the caller.
    #[serde(default)]
    pub author_secrets: Option<AuthorSecrets>,
    /// Signing keys the artefact signs with, by path, at most three — see
    /// [`crate::signing_keys`] and `wit/deps/signing-keys.wit`. The keystore
    /// derives each for the run from how the code is run, the job's project or
    /// build and its caller; the guest reaches them only through the
    /// `outlayer:signing-keys` host functions. A declaration that breaks the
    /// rules of [`crate::signing_keys::check_declarations`] does not parse, and
    /// one the run cannot be served refuses the run.
    #[serde(default, deserialize_with = "crate::signing_keys::deserialize_declared")]
    pub signing_keys: Option<Vec<crate::signing_keys::ManifestKey>>,
    /// Encryption keys the artefact seals data with, by path, at most three —
    /// see [`crate::encryption_keys`] and `wit/deps/encryption-keys.wit`.
    /// Issued under the signing keys' rules, in a namespace of their own: a
    /// path may name a signing key and an encryption key at once, and they
    /// are two unrelated secrets. The guest reaches them only through the
    /// `outlayer:encryption-keys` host functions. A declaration that breaks
    /// the rules does not parse, and one the run cannot be served refuses the
    /// run.
    #[serde(default, deserialize_with = "crate::encryption_keys::deserialize_declared")]
    pub encryption_keys: Option<Vec<crate::encryption_keys::EncryptionManifestKey>>,
    /// Whose per-account storage cell the run reads and writes — see
    /// [`StorageAccount`]. Absent means `signer`. A value other than the two
    /// spellings does not parse, and a manifest that does not parse refuses
    /// the run.
    #[serde(default)]
    pub storage_account: StorageAccount,
    /// The operation names, for the dashboard and the price-list check.
    #[serde(default, rename = "operations")]
    _operations: Option<serde::de::IgnoredAny>,
    /// Name and author, for the dashboard.
    #[serde(default, rename = "display")]
    _display: Option<serde::de::IgnoredAny>,
    /// What each operation does and takes, served by the coordinator.
    #[serde(default, rename = "describe")]
    _describe: Option<serde::de::IgnoredAny>,
}

/// `storage_account` in the manifest: which account of the job owns the
/// run's per-account storage cell (`near:storage`'s `set`/`get`, the `-raw`
/// functions and everything else outside the `@worker` cell). Chosen by the
/// artefact, resolved against the job by
/// [`crate::outlayer_storage::cell_account`]; the guest never names an
/// account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StorageAccount {
    /// The job's `user_account_id`: the transaction signer on chain, the
    /// payment-key owner over HTTPS; `anonymous` on a run that carries
    /// neither.
    #[default]
    Signer,
    /// The job's `predecessor_id`, the account the secrets and the
    /// `caller: "predecessor"` keys are judged for: the account that called
    /// the contract on chain — a DAO, a wallet contract, a relaying contract —
    /// and the payment-key owner over HTTPS. A run that carries no
    /// predecessor is refused before it executes.
    Predecessor,
}

/// `author_secrets` in the manifest — see [`ProjectManifest::author_secrets`].
#[derive(Debug, Clone, Deserialize)]
pub struct AuthorSecrets {
    #[serde(default)]
    pub owner: Option<String>,
    /// Optional at the parse so that a block missing it does not make the
    /// WHOLE manifest unparseable — which would run the connector with an
    /// empty allowlist and no credential instead of refusing it with a
    /// reason. `author_secrets_ref` refuses a blank or absent profile.
    #[serde(default)]
    pub profile: Option<String>,
}

/// Where a manifest's author secrets are stored: the resolved `(owner, profile)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorSecretsRef {
    pub owner: String,
    pub profile: String,
}

/// The author secrets a manifest asks for, resolved against the project the
/// artefact is published under; `None` when the manifest names none.
///
/// A blank profile, or a project id with no owner half to default to, is a
/// refusal rather than a guess: a defaulted profile would decrypt SOMEBODY's
/// secrets into a guest that never asked for them.
pub fn author_secrets_ref(
    project_id: &str,
    manifest: Option<&ProjectManifest>,
) -> Result<Option<AuthorSecretsRef>, String> {
    let Some(declared) = manifest.and_then(|m| m.author_secrets.as_ref()) else {
        return Ok(None);
    };
    let profile = declared.profile.as_deref().map(str::trim).unwrap_or_default();
    if profile.is_empty() {
        return Err("the manifest's author_secrets.profile must be a non-empty string".to_string());
    }
    let owner = match declared.owner.as_deref().map(str::trim).filter(|o| !o.is_empty()) {
        Some(o) => o.to_string(),
        None => match project_id.split_once('/') {
            Some((owner, _)) if !owner.is_empty() => owner.to_string(),
            _ => {
                return Err(format!(
                    "the manifest's author_secrets names no owner and the project id '{}' has none to default to",
                    project_id
                ))
            }
        },
    };
    Ok(Some(AuthorSecretsRef { owner, profile: profile.to_string() }))
}

/// The author's secrets and the caller's, as one environment.
///
/// A name in both is refused, never resolved: whichever side won, the other's
/// value would be silently missing from a run that then does something with
/// the wrong credential.
pub fn merge_secret_maps(
    author: std::collections::HashMap<String, String>,
    agent: std::collections::HashMap<String, String>,
) -> Result<std::collections::HashMap<String, String>, String> {
    let mut clashes: Vec<&String> = agent.keys().filter(|k| author.contains_key(*k)).collect();
    if !clashes.is_empty() {
        clashes.sort();
        return Err(format!(
            "the author's secrets and the caller's both define {}; rename one side",
            clashes.iter().map(|k| format!("`{k}`")).collect::<Vec<_>>().join(", ")
        ));
    }
    let mut merged = author;
    merged.extend(agent);
    Ok(merged)
}

impl ProjectManifest {
    /// The declared limits, as one line for the log.
    ///
    /// Logged when a connector's manifest is read, so what the artefact CLAIMS
    /// is visible next to what the coordinator enforces. That comparison is a
    /// human one today — the coordinator does not read the manifest of the
    /// artefact it dispatches — and a declaration nobody can see would be no
    /// declaration at all.
    pub fn declared_limits_summary(&self) -> Option<String> {
        let limits = self.limits.as_ref()?;
        if limits.is_empty() {
            return None;
        }
        Some(
            limits
                .iter()
                .map(|l| {
                    format!(
                        "{} <= {}/{} ({})",
                        l.operation, l.max_count, l.window, l.applies
                    )
                })
                .collect::<Vec<_>>()
                .join(", "),
        )
    }
}

/// One declared limit. Mirrors `operation_limits` in the coordinator.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ManifestLimit {
    /// Operation this bounds, e.g. `send`. Bare — the connector id is implied.
    pub operation: String,
    /// `day` | `week` | `month`.
    pub window: String,
    pub max_count: u32,
    /// `everyone` | `unpaid` | `covered`.
    ///
    /// A value the coordinator does not know is read at its STRICTEST
    /// (`everyone`), not dropped — so a manifest still saying `pro_only` binds
    /// every caller rather than none. Strict cannot widen anything: a
    /// declaration is unioned with the configured rules and every applicable
    /// one must pass. Validate the words at build time; see
    /// `wasi-examples/CONNECTOR_MANIFEST.md`.
    #[serde(default = "default_applies")]
    pub applies: String,
}

fn default_applies() -> String {
    // The strictest reading of an under-specified declaration.
    "everyone".to_string()
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ManifestCapabilities {
    #[serde(default)]
    pub network: Option<Vec<String>>,
}

impl ProjectManifest {
    /// Whether this manifest claims to be a connector.
    ///
    /// Declaring `connector_id` only ever RESTRICTS the project — it opts it
    /// into a fail-closed allowlist. It grants nothing: free execution comes
    /// from the coordinator's connector registry and the key's own scope, never
    /// from something the code says about itself. So a project claiming to be a
    /// connector when it is not costs it, not us.
    pub fn declares_connector(&self) -> bool {
        self.connector_id
            .as_deref()
            .is_some_and(|id| !id.trim().is_empty())
    }

    /// The declared allowlist, if the manifest declares one at all.
    ///
    /// `None` and `Some(vec![])` are DIFFERENT and must stay so: "declared
    /// nothing" is a manifest that says nothing about the network, while
    /// "declared an empty list" is a manifest that says this project talks to
    /// nobody. Collapsing them turns an explicit no into a silent yes.
    pub fn allowlist(&self) -> Option<&[String]> {
        self.capabilities
            .as_ref()
            .and_then(|c| c.network.as_deref())
            .or(self.network.as_deref())
    }

    /// Read a manifest, or say why it is not one. The reason is kept: a
    /// manifest is public, author-written text, and "unknown variant
    /// `secp256k1`" is what its author needs.
    pub fn read(bytes: &[u8]) -> Result<Self, String> {
        serde_json::from_slice::<Self>(bytes).map_err(|e| e.to_string())
    }

    #[cfg(test)]
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        Self::read(bytes).ok()
    }
}

/// What the runtime will let a guest reach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkPolicy {
    /// No allowlist applies. Outbound requests are still subject to the SSRF
    /// filter — this is "no ADDITIONAL restriction", never "no restriction".
    Unrestricted,
    /// Only these hosts. An empty list means no outbound network at all, which
    /// is what a connector without a usable manifest gets.
    Allowlist(Vec<String>),
}

impl NetworkPolicy {
    /// Whether `host` may be reached.
    ///
    /// Matching is exact and case-insensitive, with a trailing root dot
    /// normalised away (`example.com.` is the same host as `example.com` to
    /// every resolver, and a policy that disagrees is trivially bypassed).
    /// There is no implicit subdomain wildcard: `example.com` does NOT permit
    /// `evil.example.com`. A project that needs a subdomain lists it.
    pub fn allows(&self, host: &str) -> bool {
        match self {
            NetworkPolicy::Unrestricted => true,
            NetworkPolicy::Allowlist(hosts) => {
                let host = normalize_host(host);
                hosts.iter().any(|h| normalize_host(h) == host)
            }
        }
    }

    pub fn is_enforced(&self) -> bool {
        matches!(self, NetworkPolicy::Allowlist(_))
    }
}

fn normalize_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// The one field a connector request must carry, at the top level, as a
/// non-empty string.
///
/// **Universal, not per-connector.** The contract reads the operation out of
/// these very bytes to price the call, and it cannot be taught one request
/// shape per connector. One value, read the same way by the contract, the
/// coordinator, this worker and the guest.
///
/// Must stay identical to `payment::OPERATION_FIELD` in the contract and
/// `connectors::OPERATION_FIELD` in the coordinator. Three copies rather than
/// one shared function: the contract cannot depend on the crate the other two
/// share, and it is the one that decides the money — a shared function would
/// have covered two of three and missed the one that matters. The list of edge
/// cases below is the same in all three.
pub const OPERATION_FIELD: &str = "operation";

/// Why a connector request could not be read.
#[derive(Debug, PartialEq, Eq)]
pub enum OperationError {
    /// Not JSON at all. A connector takes a JSON object; that is part of the
    /// format.
    NotJson,
    /// No `operation`, or one that is not a non-empty string.
    Missing,
}

impl OperationError {
    pub fn message(&self) -> String {
        match self {
            OperationError::NotJson => format!(
                "its input is not a JSON object naming \"{}\".",
                OPERATION_FIELD
            ),
            OperationError::Missing => format!(
                "its input does not name \"{}\" as a non-empty string at the top level.",
                OPERATION_FIELD
            ),
        }
    }
}

/// Read the operation out of a connector request body.
///
/// Fail-closed at every step. None of these may default to an operation: a
/// defaulted operation upstream is a defaulted PRICE, and the cheapest is the
/// one an attacker would pick — so by the time a body reaches here without one,
/// the safe answer is that nothing runs.
///
/// No size cap here, unlike the contract's copy: that cap exists because
/// parsing on chain is paid for in the caller's gas. Here the bytes are already
/// in memory and about to be handed to a guest anyway.
pub fn operation_from_input(input_data: &str) -> Result<String, OperationError> {
    let parsed: serde_json::Value =
        serde_json::from_str(input_data).map_err(|_| OperationError::NotJson)?;

    parsed
        .get(OPERATION_FIELD)
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or(OperationError::Missing)
}

/// May this job run at all?
///
/// The verdict, returned rather than acted on, so the rule can be exercised
/// without a whole job fixture — the call site in `handle_execute_job` is then
/// one line that cannot silently do something else.
///
/// A connector call must name its operation. This is the last of three checks
/// on the same field and the only one inside the TEE: the contract priced the
/// call by reading `operation` out of these very bytes, and the coordinator
/// billed it the same way. If a connector is about to execute a body that names
/// none, something upstream priced nothing, and the safe answer is to run
/// nothing.
///
/// Everything else runs as before. An ordinary project has no operation, no
/// price and nothing to check.
pub fn may_run(is_connector: bool, input_data: &str) -> Result<(), OperationError> {
    if !is_connector {
        return Ok(());
    }
    operation_from_input(input_data).map(|_| ())
}

/// True if `project_id` belongs to the curated connector namespace.
///
/// Membership is a prefix comparison against the namespace account, which makes
/// it structural rather than declarative: a project cannot claim to be a
/// connector, it either lives under that account on chain or it does not.
pub fn is_connector_project(project_id: &str, namespace: &str) -> bool {
    match project_id.split_once('/') {
        Some((owner, name)) => owner == namespace && !name.is_empty(),
        None => false,
    }
}

/// The connector whose sub-keys this execution may name, or `None`.
///
/// Two conditions, both read from what the worker verified itself: the project
/// is published under the connectors namespace, and the manifest inside the
/// wasm names `connector_id` equal to the project's own name. A manifest is
/// self-declared — any artefact can embed one — so the id alone would let a
/// project outside the namespace, or a namespace project with somebody
/// else's id, sign with that connector's sub-keys of the caller's wallet. The
/// wallet's own policy would still govern, but the promise "a connector
/// reaches only its own sub-keys" has to hold against a hostile artefact too,
/// and tying the id to the curated name is what makes it hold.
pub fn sub_key_connector_id(
    in_connector_namespace: bool,
    project_id: Option<&str>,
    manifest: Option<&ProjectManifest>,
) -> Option<String> {
    if !in_connector_namespace {
        return None;
    }
    let name = project_id?.split_once('/')?.1;
    let declared = manifest?.connector_id.as_deref()?.trim();
    (!declared.is_empty() && declared == name).then(|| declared.to_string())
}

/// Decide the network policy for one execution.
///
/// A project is treated as a connector if EITHER is true:
///
///   * it lives under the curated connector namespace on chain, or
///   * its manifest declares a `connector_id`.
///
/// Two routes on purpose, because each covers what the other misses. The
/// namespace catches a curated connector that shipped without a manifest — it
/// gets no network, loudly, instead of silently keeping the run of the
/// internet. The self-declaration catches a curated connector that lives
/// outside the namespace, which is the normal case: connectors are published
/// wherever their author already had a project, and re-publishing every one of
/// them under a single account is not something we are going to do.
///
/// * A connector always gets an allowlist. A missing, unparseable, or silent
///   manifest yields an EMPTY allowlist — no network — rather than an
///   unrestricted one. Fail-closed is the only safe direction here: the failure
///   mode of the other choice is a connector with a broken manifest quietly
///   gaining the run of the internet from inside a keys-bearing TEE.
/// * Any other project gets an allowlist only if its manifest declares one.
///   Retrofitting deny-by-default onto existing projects would break every one
///   of them that makes an HTTP call, which is precisely why §C3 insists the
///   rule be introduced with the connectors rather than after them.
pub fn resolve_network_policy(
    in_connector_namespace: bool,
    manifest: Option<&ProjectManifest>,
) -> NetworkPolicy {
    let is_connector =
        in_connector_namespace || manifest.is_some_and(ProjectManifest::declares_connector);
    match manifest.and_then(|m| m.allowlist()) {
        Some(hosts) => NetworkPolicy::Allowlist(hosts.to_vec()),
        None if is_connector => NetworkPolicy::Allowlist(Vec::new()),
        None => NetworkPolicy::Unrestricted,
    }
}

/// One outbound request, as observed inside the TEE.
///
/// Recorded for allowed and refused requests alike: a log that only shows
/// refusals cannot answer "where did this connector actually go", which is the
/// question an audit is for.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EgressRecord {
    /// Destination host. The path and query are deliberately NOT recorded —
    /// they routinely carry tokens and recipient addresses, and an audit trail
    /// is not a place to accumulate other people's secrets.
    pub host: String,
    /// Request body size in bytes, when the guest declared one.
    pub bytes: Option<u64>,
    pub allowed: bool,
    /// Why it was refused. `None` when allowed.
    pub reason: Option<String>,
}

/// Custom section carrying the manifest inside the wasm itself.
///
/// This is the PRIMARY source, and it is a better anchor than a file in a
/// repository: the wasm's hash is recorded on chain and checked before
/// execution, so the section is covered by that hash. A `manifest.json` at a
/// git ref is not — a force-push moves what the ref points at while the ref
/// stays the same, and a project whose source is a `WasmUrl` has no repository
/// to read at all.
///
/// Rust guests embed it with a `#[link_section]` static; see
/// `wasi-examples/CONNECTOR_MANIFEST.md`.
pub const MANIFEST_SECTION: &str = "outlayer.manifest";

/// Read the manifest out of a wasm binary's custom section.
///
/// Works for a core module and for a component alike: `parse_all` descends into
/// the core modules a component embeds, so a manifest placed by the guest's
/// source survives `wasm-tools component new`.
///
/// `Ok(None)` when there is no such section, `Ok(Some)` when it parses, and
/// `Err(reason)` when a section IS there and cannot be read — over the size
/// cap, not JSON, not a manifest. The caller refuses the run on `Err`: a
/// declaration nobody can read must not become "no declaration", because with
/// the author's secret would go the author's admission gate, and an app opened
/// to a circle would run for everyone.
pub fn manifest_from_wasm(wasm: &[u8]) -> Result<Option<ProjectManifest>, String> {
    for payload in wasmparser::Parser::new(0).parse_all(wasm) {
        // A malformed tail must not lose a section already found, and must not
        // panic: these bytes come from a project we did not write.
        let Ok(payload) = payload else { break };
        if let wasmparser::Payload::CustomSection(reader) = payload {
            if reader.name() != MANIFEST_SECTION {
                continue;
            }
            if reader.data().len() > MAX_MANIFEST_BYTES {
                return Err(format!(
                    "the {MANIFEST_SECTION} section is {} bytes, over the {MAX_MANIFEST_BYTES}-byte limit",
                    reader.data().len()
                ));
            }
            return match ProjectManifest::read(reader.data()) {
                Ok(m) => Ok(Some(m)),
                Err(e) => Err(format!("the {MANIFEST_SECTION} section does not parse as a manifest: {e}")),
            };
        }
    }
    Ok(None)
}

/// Decide one outbound request and record it.
///
/// Returns `None` to allow, `Some(reason)` to refuse. Every call appends
/// exactly one record either way — the log is the audit, so a branch that
/// forgets to write is a branch that erases evidence.
///
/// Kept separate from the wasmtime plumbing that calls it so the decision and
/// its audit side-effect can be tested without standing up a runtime.
pub fn decide_egress(
    policy: &NetworkPolicy,
    host: Option<&str>,
    bytes: Option<u64>,
    log: &std::sync::Mutex<Vec<EgressRecord>>,
) -> Option<String> {
    let reason = match host {
        None | Some("") => Some("request has no host".to_string()),
        Some(h) if !policy.allows(h) => Some(format!(
            "host {:?} is not in the project's manifest network allowlist",
            h
        )),
        Some(_) => None,
    };

    // A poisoned log must not take the decision with it: refusing is still
    // refusing even if we cannot write the line, and allowing is still allowing.
    if let Ok(mut log) = log.lock() {
        log.push(EgressRecord {
            host: host.unwrap_or_default().to_string(),
            bytes,
            allowed: reason.is_none(),
            reason: reason.clone(),
        });
    }

    reason
}

/// **There is no fallback to a manifest fetched over the network**, and its
/// absence is the point.
///
/// The allowlist has to be anchored to the exact bytes that run, and a file at
/// a git ref is not: `validate_git_ref` accepts `main` and `release/2024-01`,
/// so the ref moves when somebody pushes and the policy moves with it while
/// nothing on chain changes. Anything fetched at execution time has the same
/// problem — whoever serves it decides what a published version may reach.
///
/// Embedding is not a burden either: `connectors/connector-probe/build.sh`
/// fails the build when the custom section is missing, which is the right place
/// to catch it — at the author's desk rather than in a TEE holding somebody's
/// keys.
///
/// So a project that wants an allowlist puts it in the binary. A connector
/// without one gets no network at all, loudly.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn author_secrets_are_resolved_against_the_publishing_account() {
        let m: ProjectManifest =
            serde_json::from_str(r#"{"connector_id":"pm","author_secrets":{"profile":"prod"}}"#).unwrap();
        assert_eq!(
            author_secrets_ref("connectors.outlayer.near/pm", Some(&m)).unwrap(),
            Some(AuthorSecretsRef { owner: "connectors.outlayer.near".into(), profile: "prod".into() })
        );
        let explicit: ProjectManifest = serde_json::from_str(
            r#"{"connector_id":"pm","author_secrets":{"owner":" author.near ","profile":" prod "}}"#,
        )
        .unwrap();
        assert_eq!(
            author_secrets_ref("connectors.outlayer.near/pm", Some(&explicit)).unwrap(),
            Some(AuthorSecretsRef { owner: "author.near".into(), profile: "prod".into() })
        );
        // None declared: nothing to decrypt, not an error.
        let plain = manifest_with_id("pm");
        assert_eq!(author_secrets_ref("connectors.outlayer.near/pm", Some(&plain)).unwrap(), None);
        assert_eq!(author_secrets_ref("x/y", None).unwrap(), None);
        // A blank profile and an owner-less project id are refusals, not guesses.
        let blank: ProjectManifest =
            serde_json::from_str(r#"{"author_secrets":{"profile":"  "}}"#).unwrap();
        assert!(author_secrets_ref("a/b", Some(&blank)).is_err());
        // A block with no profile at all still PARSES — the rest of the
        // manifest (allowlist, connector id) stays in force — and is refused
        // here with a reason, not run with an empty allowlist.
        let absent: ProjectManifest = serde_json::from_str(
            r#"{"connector_id":"pm","capabilities":{"network":["api.example"]},"author_secrets":{"owner":"a.near"}}"#,
        )
        .unwrap();
        assert_eq!(absent.connector_id.as_deref(), Some("pm"));
        assert!(author_secrets_ref("a/b", Some(&absent)).unwrap_err().contains("profile"));
        assert!(author_secrets_ref("no-slash", Some(&m)).is_err());
    }

    #[test]
    fn a_name_defined_on_both_sides_is_refused_not_resolved() {
        let author = std::collections::HashMap::from([("BUILDER_KEY".to_string(), "a".to_string())]);
        let agent = std::collections::HashMap::from([("MERCURY_TOKEN".to_string(), "b".to_string())]);
        let merged = merge_secret_maps(author.clone(), agent).unwrap();
        assert_eq!(merged.len(), 2);
        assert_eq!(merged["BUILDER_KEY"], "a");
        let clash = std::collections::HashMap::from([
            ("BUILDER_KEY".to_string(), "x".to_string()),
            ("API_URL".to_string(), "y".to_string()),
        ]);
        let mut both = author.clone();
        both.insert("API_URL".into(), "z".into());
        let err = merge_secret_maps(both, clash).unwrap_err();
        assert!(err.contains("`API_URL`, `BUILDER_KEY`"), "{err}");
    }

    fn manifest_with_id(id: &str) -> ProjectManifest {
        serde_json::from_str(&format!(r#"{{"connector_id":"{id}"}}"#)).expect("manifest")
    }

    #[test]
    fn sub_keys_belong_to_a_curated_connector_under_its_own_name_only() {
        let ns = true;
        let m = manifest_with_id("mercury");
        assert_eq!(
            sub_key_connector_id(ns, Some("connectors.outlayer.near/mercury"), Some(&m)).as_deref(),
            Some("mercury")
        );
        // Outside the namespace: a manifest may say what it likes.
        assert_eq!(sub_key_connector_id(false, Some("alice.near/mercury"), Some(&m)), None);
        // Inside it, under another project's name: refused.
        assert_eq!(sub_key_connector_id(ns, Some("connectors.outlayer.near/near-email"), Some(&m)), None);
        // No manifest, no id, no project: nothing.
        assert_eq!(sub_key_connector_id(ns, Some("connectors.outlayer.near/mercury"), None), None);
        assert_eq!(sub_key_connector_id(ns, None, Some(&m)), None);
        let blank = manifest_with_id("");
        assert_eq!(sub_key_connector_id(ns, Some("connectors.outlayer.near/"), Some(&blank)), None);
    }

    /// The allowlist comes from the BYTES THAT RUN, and from nowhere else.
    ///
    /// A second source is the tempting convenience here — reading
    /// `manifest.json` from the project's repository when the wasm carries no
    /// section. It would make the claim the whole design rests on untrue:
    /// `validate_git_ref` accepts `main` and `release/2024-01`, so the ref moves
    /// when somebody pushes and the network policy would move with it while
    /// nothing on chain changed.
    ///
    /// The test is here so that convenience cannot arrive by accident. If a
    /// project's manifest ever needs a second source, that is a decision to take
    /// deliberately — and the first thing to answer is what anchors it.
    /// The operation format, pinned — the SAME vectors the contract and the
    /// coordinator run against their own copies of this rule.
    ///
    /// Three trivial parsers rather than one shared function, because the
    /// contract cannot depend on the crate the coordinator and keystore share,
    /// and the contract is the one that decides the money. What keeps them
    /// honest is this list. Change a case here and change it in both others.
    #[test]
    fn the_operation_format_is_one_field_and_fails_closed() {
        assert_eq!(
            operation_from_input(r#"{"operation":"send"}"#).unwrap(),
            "send"
        );
        assert_eq!(
            operation_from_input(r#"{"operation":" send ","to":"a@b"}"#).unwrap(),
            "send",
            "surrounding whitespace is trimmed, so a padded name is the same name"
        );

        for (body, expected) in [
            (r#"{"to":"a@b"}"#, OperationError::Missing),
            (r#"{"operation":""}"#, OperationError::Missing),
            (r#"{"operation":"   "}"#, OperationError::Missing),
            (r#"{"operation":42}"#, OperationError::Missing),
            (r#"{"operation":null}"#, OperationError::Missing),
            (r#"{"operation":["send"]}"#, OperationError::Missing),
            // Nested does NOT count. One place, top level, or the format is a
            // convention again.
            (r#"{"input":{"operation":"send"}}"#, OperationError::Missing),
            // The old near-email spelling is not the standard, and the contract
            // accepts only one name. Honouring it here would let a body price
            // as nothing on chain and still run.
            (r#"{"op":"send"}"#, OperationError::Missing),
            ("not json at all", OperationError::NotJson),
            ("", OperationError::NotJson),
        ] {
            assert_eq!(
                operation_from_input(body),
                Err(expected),
                "body {body:?} must be refused"
            );
        }
    }

    /// A connector without an operation does not run; anything else is
    /// untouched.
    ///
    /// Refused BEFORE execution, deliberately. Running and then charging would
    /// mean the side effect — the email — has already happened, and no amount
    /// of money kept afterwards undoes it. The timing is the protection; the
    /// money is not.
    #[test]
    fn a_connector_call_without_an_operation_does_not_run() {
        assert!(may_run(true, r#"{"operation":"send"}"#).is_ok());

        for body in [
            r#"{"to":"a@b"}"#,
            r#"{"operation":""}"#,
            // The old spelling prices as nothing on chain, so it must not run
            // here either.
            r#"{"op":"send"}"#,
            "not json",
            "",
        ] {
            assert!(
                may_run(true, body).is_err(),
                "a connector call with body {body:?} must not run"
            );
        }

        // An ordinary project has no operation and never had one. Requiring it
        // here would break every project that already exists.
        for body in [r#"{"to":"a@b"}"#, "not json", "", r#"{"operation":"x"}"#] {
            assert!(may_run(false, body).is_ok(), "an ordinary project runs: {body:?}");
        }
    }

    #[test]
    fn the_allowlist_has_exactly_one_source() {
        // No section: a connector gets no network, whatever its repository says.
        assert_eq!(
            resolve_network_policy(true, manifest_from_wasm(b"not a wasm at all").unwrap().as_ref()),
            NetworkPolicy::Allowlist(Vec::new()),
            "a connector without an embedded manifest reaches nothing"
        );

        // And the module offers no way to look elsewhere. `manifest_from_wasm`
        // takes bytes and returns immediately; nothing here is async, and
        // nothing here takes an HTTP client.
        assert!(matches!(manifest_from_wasm(&[]), Ok(None)));
    }

    // ============ parsing ============

    #[test]
    fn both_manifest_shapes_are_read() {
        let nested = ProjectManifest::parse(
            br#"{"connector_id":"near-email","capabilities":{"network":["api.near.email"]}}"#,
        )
        .unwrap();
        assert_eq!(nested.connector_id.as_deref(), Some("near-email"));
        assert_eq!(nested.allowlist(), Some(&["api.near.email".to_string()][..]));

        let flat = ProjectManifest::parse(br#"{"network":["api.near.email"]}"#).unwrap();
        assert_eq!(flat.allowlist(), Some(&["api.near.email".to_string()][..]));
    }

    #[test]
    fn an_unknown_member_refuses_the_run_naming_it_and_the_known_ones() {
        // Read with the member dropped, a misspelled `storage_account` would
        // quietly mean the signer's cell.
        let wasm = core_module(&[custom_section(MANIFEST_SECTION, br#"{"storage_acount":"predecessor"}"#)]);
        let err = manifest_from_wasm(&wasm).expect_err("an unknown member refuses the run");
        assert!(err.contains("`storage_acount`"), "{err}");
        for known in ["storage_account", "capabilities", "describe"] {
            assert!(err.contains(&format!("`{known}`")), "{err}");
        }
        // The members only other readers use are accepted, whatever they hold.
        let other = ProjectManifest::parse(
            br#"{"operations":["a"],"display":{"name":"A"},"describe":{"summary":"s","operations":{}}}"#,
        )
        .unwrap();
        assert_eq!(other.allowlist(), None);
    }

    /// Every manifest this repository builds into a wasm still parses. The
    /// private connector submodules are read when they are checked out.
    #[test]
    fn every_manifest_in_the_tree_parses() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let mut files = Vec::new();
        for dir in ["connectors", "connectors/rejected", "wasi-examples"] {
            for project in std::fs::read_dir(root.join(dir)).into_iter().flatten().flatten() {
                files.push(project.path().join("manifest.json"));
                let variants = std::fs::read_dir(project.path().join("manifests")).into_iter().flatten().flatten();
                files.extend(variants.map(|v| v.path()));
            }
        }
        files.retain(|f| f.is_file());
        assert!(files.len() >= 15, "found only {files:?}");
        for file in files {
            let bytes = std::fs::read(&file).expect("read");
            match ProjectManifest::read(&bytes) {
                Ok(_) => {}
                // The probe's deliberately refused variant: a `type` on an
                // encryption key.
                Err(e) if file.ends_with("encryption-typed.json") => assert!(e.contains("`type`"), "{e}"),
                Err(e) => panic!("{}: {e}", file.display()),
            }
        }
    }

    #[test]
    fn declaring_an_empty_list_is_not_the_same_as_declaring_nothing() {
        // "talks to nobody" vs "says nothing". Collapsing the two turns an
        // explicit no into a silent yes for non-connectors.
        let explicit = ProjectManifest::parse(br#"{"capabilities":{"network":[]}}"#).unwrap();
        assert_eq!(explicit.allowlist(), Some(&[][..]));
        assert_eq!(
            resolve_network_policy(false, Some(&explicit)),
            NetworkPolicy::Allowlist(vec![])
        );

        let silent = ProjectManifest::parse(br#"{"capabilities":{}}"#).unwrap();
        assert_eq!(silent.allowlist(), None);
        assert_eq!(
            resolve_network_policy(false, Some(&silent)),
            NetworkPolicy::Unrestricted
        );
    }

    #[test]
    fn garbage_is_not_a_manifest() {
        assert!(ProjectManifest::parse(b"not json").is_none());
        assert!(ProjectManifest::parse(b"").is_none());
    }

    // ============ matching ============

    #[test]
    fn matching_is_exact_and_case_insensitive() {
        let policy = NetworkPolicy::Allowlist(vec!["API.Near.Email".to_string()]);
        assert!(policy.allows("api.near.email"));
        assert!(policy.allows("API.NEAR.EMAIL"));
        // A trailing root dot is the same host to every resolver; a policy that
        // disagreed would be bypassed by typing one extra character.
        assert!(policy.allows("api.near.email."));
        assert!(!policy.allows("api.near.email.evil.com"));
    }

    #[test]
    fn there_is_no_implicit_subdomain_wildcard() {
        // Listing a domain must not hand over everything under it: an attacker
        // who can register or control a subdomain would otherwise be inside the
        // allowlist. A project that needs a subdomain lists the subdomain.
        let policy = NetworkPolicy::Allowlist(vec!["example.com".to_string()]);
        assert!(policy.allows("example.com"));
        assert!(!policy.allows("evil.example.com"));
        assert!(!policy.allows("example.com.evil.net"));
        // ...and a prefix of a listed host is not the host.
        assert!(!policy.allows("ample.com"));
    }

    #[test]
    fn an_empty_allowlist_permits_nothing() {
        let policy = NetworkPolicy::Allowlist(vec![]);
        assert!(!policy.allows("example.com"));
        assert!(!policy.allows(""));
        assert!(policy.is_enforced());
    }

    #[test]
    fn unrestricted_permits_everything_it_is_asked_about() {
        // Note this is only the ALLOWLIST layer. The SSRF filter still runs
        // underneath and blocks private, loopback, and metadata addresses.
        let policy = NetworkPolicy::Unrestricted;
        assert!(policy.allows("example.com"));
        assert!(!policy.is_enforced());
    }

    // ============ policy resolution ============

    #[test]
    fn a_connector_without_a_usable_manifest_gets_no_network() {
        // Fail-closed. The alternative — treating a broken manifest as "no
        // restriction" — hands a connector the run of the internet from inside
        // a keys-bearing TEE, and does it silently.
        assert_eq!(
            resolve_network_policy(true, None),
            NetworkPolicy::Allowlist(vec![])
        );
        let silent = ProjectManifest::default();
        assert_eq!(
            resolve_network_policy(true, Some(&silent)),
            NetworkPolicy::Allowlist(vec![])
        );
    }

    #[test]
    fn an_ordinary_project_without_a_manifest_is_unchanged() {
        // The backwards-compatibility case: every project that exists today
        // has no manifest and must keep reaching the internet exactly as it
        // did. Deny-by-default here would break all of them at once.
        assert_eq!(
            resolve_network_policy(false, None),
            NetworkPolicy::Unrestricted
        );
    }

    #[test]
    fn a_declared_allowlist_is_enforced_for_anyone() {
        let m = ProjectManifest::parse(br#"{"capabilities":{"network":["a.example"]}}"#).unwrap();
        let expected = NetworkPolicy::Allowlist(vec!["a.example".to_string()]);
        assert_eq!(resolve_network_policy(true, Some(&m)), expected);
        assert_eq!(resolve_network_policy(false, Some(&m)), expected);
    }

    // ============ the manifest embedded in the wasm ============
    //
    // The section is covered by the wasm hash the contract records, which is
    // what makes it a stronger anchor than a file at a git ref. These tests
    // build real wasm binaries byte by byte rather than mocking the parser —
    // the thing that can break here is the encoding, and a mock would not see
    // it.

    fn leb128(mut n: u32) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (n & 0x7f) as u8;
            n >>= 7;
            if n == 0 {
                out.push(byte);
                return out;
            }
            out.push(byte | 0x80);
        }
    }

    /// A custom section: id 0, size, then a name-prefixed payload.
    fn custom_section(name: &str, payload: &[u8]) -> Vec<u8> {
        let mut body = leb128(name.len() as u32);
        body.extend_from_slice(name.as_bytes());
        body.extend_from_slice(payload);

        let mut section = vec![0u8];
        section.extend_from_slice(&leb128(body.len() as u32));
        section.extend_from_slice(&body);
        section
    }

    /// A core module carrying `sections`.
    fn core_module(sections: &[Vec<u8>]) -> Vec<u8> {
        let mut wasm = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        for s in sections {
            wasm.extend_from_slice(s);
        }
        wasm
    }

    /// A component embedding `module` — the shape `cargo build` for
    /// wasm32-wasip2 actually produces, where the guest's section ends up
    /// nested one level down.
    fn component_wrapping(module: &[u8]) -> Vec<u8> {
        let mut wasm = vec![0x00, 0x61, 0x73, 0x6d, 0x0d, 0x00, 0x01, 0x00];
        // Component section id 1 = core module.
        wasm.push(0x01);
        wasm.extend_from_slice(&leb128(module.len() as u32));
        wasm.extend_from_slice(module);
        wasm
    }

    const MANIFEST_JSON: &[u8] =
        br#"{"connector_id":"near-email","capabilities":{"network":["mail.near.email"]}}"#;

    #[test]
    fn the_manifest_is_read_from_a_core_module() {
        let wasm = core_module(&[custom_section(MANIFEST_SECTION, MANIFEST_JSON)]);
        let manifest = manifest_from_wasm(&wasm).unwrap().expect("section must be found");
        assert_eq!(manifest.connector_id.as_deref(), Some("near-email"));
        assert_eq!(manifest.allowlist(), Some(&["mail.near.email".to_string()][..]));
    }

    #[test]
    fn the_manifest_survives_being_wrapped_in_a_component() {
        // wasm32-wasip2 artefacts are components with the guest's core module
        // inside. If the reader did not descend, every P2 connector would look
        // like it had no manifest — and get no network, which would at least be
        // loud. The reverse mistake would be worse, so this is pinned.
        let wasm = component_wrapping(&core_module(&[custom_section(
            MANIFEST_SECTION,
            MANIFEST_JSON,
        )]));
        let manifest = manifest_from_wasm(&wasm).unwrap().expect("nested section must be found");
        assert_eq!(manifest.connector_id.as_deref(), Some("near-email"));
    }

    #[test]
    fn other_custom_sections_are_ignored() {
        // Real binaries carry several: `producers`, `.debug_*`, `name`. Reading
        // the wrong one would either fail to parse or, worse, parse something
        // that happened to be JSON.
        let wasm = core_module(&[
            custom_section("producers", b"processed-by"),
            custom_section("name", b"\x00\x03abc"),
            custom_section(MANIFEST_SECTION, MANIFEST_JSON),
            custom_section(".debug_info", b"\xde\xad\xbe\xef"),
        ]);
        assert!(matches!(manifest_from_wasm(&wasm), Ok(Some(_))));

        // ...and a binary with no manifest section reports none, rather than
        // picking up whichever custom section came first.
        let without = core_module(&[custom_section("producers", b"processed-by")]);
        assert!(matches!(manifest_from_wasm(&without), Ok(None)));
    }

    #[test]
    fn a_wasm_that_is_not_a_wasm_yields_nothing_and_does_not_panic() {
        // These bytes come from a project we did not write. Whatever they are,
        // reading them must produce an answer, not a crashed worker.
        assert!(matches!(manifest_from_wasm(b""), Ok(None)));
        assert!(matches!(manifest_from_wasm(b"not wasm at all"), Ok(None)));
        // Right magic, truncated body.
        assert!(matches!(manifest_from_wasm(&[0x00, 0x61, 0x73, 0x6d, 0x01]), Ok(None)));
        // A section header claiming more bytes than exist.
        let mut truncated = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x00];
        truncated.extend_from_slice(&leb128(9_999));
        assert!(matches!(manifest_from_wasm(&truncated), Ok(None)));
    }

    #[test]
    fn a_section_that_is_not_json_refuses_the_run() {
        // A section that is not JSON is refused with a message, never ignored
        // — ignored would drop the author's secret and, with it, the author's
        // admission gate.
        let wasm = core_module(&[custom_section(MANIFEST_SECTION, b"not json")]);
        let err = manifest_from_wasm(&wasm).expect_err("an unreadable section is an error, not None");
        assert!(err.contains("does not parse as a manifest"), "{err}");
    }

    #[test]
    fn a_manifest_with_a_numeric_profile_refuses_the_run() {
        // Valid JSON, not a manifest: `profile` must be a string.
        let wasm = core_module(&[custom_section(MANIFEST_SECTION, br#"{"author_secrets":{"profile":5}}"#)]);
        assert!(manifest_from_wasm(&wasm).is_err());
    }

    #[test]
    fn an_oversized_section_is_refused() {
        // A custom section is an arbitrary blob the author controls. Reading it
        // into memory unbounded is a way to make the worker buffer whatever
        // they like.
        //
        // The payload has to be VALID JSON and oversized, or the size check is
        // not what rejects it — a blob of filler is turned away by the parser
        // and the test passes whether or not the limit exists at all.
        let padding = "h".repeat(MAX_MANIFEST_BYTES);
        let huge = format!(
            r#"{{"connector_id":"near-email","capabilities":{{"network":["{}"]}}}}"#,
            padding
        );
        assert!(huge.len() > MAX_MANIFEST_BYTES);
        assert!(
            ProjectManifest::parse(huge.as_bytes()).is_some(),
            "the oversized payload must be parseable, or the size limit is not \
             what this test is exercising"
        );

        let wasm = core_module(&[custom_section(MANIFEST_SECTION, huge.as_bytes())]);
        let err = manifest_from_wasm(&wasm).expect_err("over the cap is an error, not None");
        assert!(err.contains("over the"), "{err}");

        // Just under the limit still goes through, so the check is a bound and
        // not a blanket refusal.
        let small = r#"{"connector_id":"near-email"}"#;
        let ok = core_module(&[custom_section(MANIFEST_SECTION, small.as_bytes())]);
        assert!(matches!(manifest_from_wasm(&ok), Ok(Some(_))));
    }

    #[test]
    fn a_connector_outside_the_namespace_is_still_enforced() {
        // The case that made this necessary: near.email is published as
        // zavodil.near/near-email, not under the connector namespace. Without
        // the self-declaration route it would be treated as an ordinary project
        // and reach anything it liked from inside the TEE.
        let manifest = ProjectManifest::parse(MANIFEST_JSON).unwrap();
        assert!(manifest.declares_connector());
        assert_eq!(
            resolve_network_policy(false, Some(&manifest)),
            NetworkPolicy::Allowlist(vec!["mail.near.email".to_string()])
        );

        // Declaring a connector_id but no network is still fail-closed, wherever
        // the project lives.
        let silent = ProjectManifest::parse(br#"{"connector_id":"x"}"#).unwrap();
        assert_eq!(
            resolve_network_policy(false, Some(&silent)),
            NetworkPolicy::Allowlist(vec![])
        );

        // An ordinary project that says nothing is still unaffected.
        let plain = ProjectManifest::parse(br#"{"display":{"name":"My App"}}"#).unwrap();
        assert!(!plain.declares_connector());
        assert_eq!(
            resolve_network_policy(false, Some(&plain)),
            NetworkPolicy::Unrestricted
        );
        // ...including a blank connector_id, which is not an identity.
        let blank = ProjectManifest::parse(br#"{"connector_id":"  "}"#).unwrap();
        assert!(!blank.declares_connector());
        assert_eq!(
            resolve_network_policy(false, Some(&blank)),
            NetworkPolicy::Unrestricted
        );
    }

    // ============ the runtime decision + its audit record ============

    fn log() -> std::sync::Mutex<Vec<EgressRecord>> {
        std::sync::Mutex::new(Vec::new())
    }

    #[test]
    fn a_host_outside_the_allowlist_is_refused_and_recorded() {
        let policy = NetworkPolicy::Allowlist(vec!["api.near.email".to_string()]);
        let log = log();

        let reason = decide_egress(&policy, Some("evil.example.com"), Some(42), &log);
        assert!(reason.is_some(), "an unlisted host must be refused");

        // Refused AND recorded. The audit line is the deliverable of §C3 —
        // "попытка выйти за аллоулист даёт отказ И запись в аудит" — so a
        // refusal that leaves no trace fails half the requirement.
        let records = log.lock().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].host, "evil.example.com");
        assert_eq!(records[0].bytes, Some(42));
        assert!(!records[0].allowed);
        assert!(records[0].reason.as_deref().unwrap().contains("allowlist"));
    }

    #[test]
    fn an_allowed_host_is_also_recorded() {
        // Recording only refusals would leave the audit unable to answer
        // "where did this connector actually go".
        let policy = NetworkPolicy::Allowlist(vec!["api.near.email".to_string()]);
        let log = log();

        assert!(decide_egress(&policy, Some("api.near.email"), None, &log).is_none());

        let records = log.lock().unwrap();
        assert_eq!(records.len(), 1);
        assert!(records[0].allowed);
        assert!(records[0].reason.is_none());
        assert_eq!(records[0].bytes, None);
    }

    #[test]
    fn a_request_without_a_host_is_refused_under_every_policy() {
        // Including Unrestricted: a request with no host cannot be checked
        // against anything, and "cannot be checked" must never mean "allowed".
        for policy in [
            NetworkPolicy::Unrestricted,
            NetworkPolicy::Allowlist(vec!["a.example".to_string()]),
        ] {
            let log = log();
            assert!(decide_egress(&policy, None, None, &log).is_some());
            assert!(decide_egress(&policy, Some(""), None, &log).is_some());
            let records = log.lock().unwrap();
            assert_eq!(records.len(), 2);
            assert!(records.iter().all(|r| !r.allowed));
        }
    }

    #[test]
    fn a_connector_with_no_manifest_reaches_nothing() {
        // End to end for the fail-closed case: no manifest -> empty allowlist
        // -> every host refused, each with an audit line.
        let policy = resolve_network_policy(true, None);
        let log = log();
        for host in ["api.near.email", "github.com", "example.com"] {
            assert!(
                decide_egress(&policy, Some(host), None, &log).is_some(),
                "{} must be refused for a connector with no manifest",
                host
            );
        }
        assert_eq!(log.lock().unwrap().len(), 3);
    }

    #[test]
    fn an_ordinary_project_is_unaffected_and_still_audited() {
        // Backwards compatibility on the live path: a project with no manifest
        // reaches what it always reached...
        let policy = resolve_network_policy(false, None);
        let log = log();
        assert!(decide_egress(&policy, Some("anything.example"), Some(7), &log).is_none());
        // ...and is still recorded, so the audit covers everything, not just
        // the projects that opted into an allowlist.
        let records = log.lock().unwrap();
        assert_eq!(records.len(), 1);
        assert!(records[0].allowed);
    }

    // ============ namespace membership ============

    #[test]
    fn connector_membership_is_the_owner_account_exactly() {
        let ns = "connectors.outlayer.near";
        assert!(is_connector_project("connectors.outlayer.near/near-email", ns));
        // A look-alike owner is not the namespace. Without the exact
        // comparison, registering `connectors.outlayer.near.evil.near` would
        // buy connector treatment.
        assert!(!is_connector_project("connectors.outlayer.near.evil.near/x", ns));
        assert!(!is_connector_project("evil.connectors.outlayer.near/x", ns));
        assert!(!is_connector_project("zavodil.near/near-email", ns));
        // Malformed ids are not connectors.
        assert!(!is_connector_project("connectors.outlayer.near", ns));
        assert!(!is_connector_project("connectors.outlayer.near/", ns));
        assert!(!is_connector_project("", ns));
        // The testnet namespace is a different namespace.
        assert!(!is_connector_project(
            "connectors.outlayer.near/near-email",
            "connectors.outlayer.testnet"
        ));
    }
}
