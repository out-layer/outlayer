//! HTTP API server for keystore worker
//!
//! ## Route Access Levels
//!
//! ### Public endpoints (no auth required):
//! - GET /health - Health check
//! - POST /pubkey - Get public key for encryption (used by dashboard)
//! - GET /vrf/pubkey - Get VRF public key for verification
//!
//! ### Worker-only endpoints (ALLOWED_WORKER_TOKEN_HASHES):
//! - POST /decrypt - Decrypt secrets from contract, and derive declared signing keys
//! - POST /encrypt - Encrypt data (for TopUp flow)
//! - POST /decrypt-raw - Decrypt raw data with seed
//! - POST /storage/encrypt - Encrypt persistent storage data
//! - POST /storage/decrypt - Decrypt persistent storage data
//! - POST /vrf/generate - Generate VRF output (verifiable random)
//!
//! ### Coordinator-only endpoints (ALLOWED_COORDINATOR_TOKEN_HASHES):
//! - POST /add_generated_secret - Add generated PROTECTED_ secrets
//! - POST /update_user_secrets - Update user secrets with NEP-413 signature
//!
//! ### TEE registration endpoints (coordinator OR worker token):
//! - POST /tee-challenge - Get challenge for TEE session registration
//! - POST /register-tee - Complete challenge-response and create TEE session
//!
//! ## Security Model
//!
//! Workers (running in TEE) get access to decrypt/encrypt endpoints.
//! Coordinator (NOT in TEE) only gets access to secret management endpoints
//! that require additional NEP-413 signature verification.

use axum::{
    extract::State,
    http::StatusCode,
    middleware,
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use shared_tee_helpers::{is_evm_chain, is_solana_chain};
use tower_http::trace::TraceLayer;

#[path = "api_support.rs"]
mod support;
use support::*;

/// How many approval (or rejection) votes one signing request may carry.
///
/// Verifying a vote costs a NEP-413 signature check, so an uncapped ballot is CPU an
/// unauthenticated-to-us caller can spend on our behalf. Thresholds are single digits in
/// practice; this is well above any real multisig and is a size check, not a policy rule — the
/// on-chain contract has no such limit and is not being changed.
const MAX_APPROVAL_VOTES: usize = 16;

/// How many secrets one `/add_generated_secret` call may generate.
///
/// Generation itself is free and entirely off-chain — random bytes plus one encryption of the
/// resulting map, no transaction, no gas. What the cap bounds is the work and the log volume of
/// a request nobody pays for: the coordinator's `/secrets/add_generated_secret` proxy takes no
/// user credential (IP rate limit only) and forwards under the coordinator's own token, so the
/// body is effectively caller-chosen. The one on-chain cost anywhere near this path is the
/// first-touch vault CKD derivation, which is why the check runs before `ensure_customer_loaded`.
///
/// Matched to [`MAX_APPROVAL_VOTES`] and to the dashboard's own limit in
/// `dashboard/app/secrets/components/GenerateSecretsForm.tsx`. Callers needing more split across
/// calls; the refusal says so.
const MAX_GENERATED_SECRETS: usize = 16;

/// Secret key names the worker owns, refused on the way IN.
///
/// This is the first of the two locks on the guest's environment. The second
/// is in the worker: `merge_env_vars` strips every one of these from the
/// secrets before writing a single system value, so a name that slips past
/// here is still not forgeable. They fail differently, though — this one tells
/// the owner at store time, in an error they can act on, while the worker's
/// silently drops a secret the owner thought they had set. Both are wanted.
///
/// **Must cover every name the worker injects.** The list mirrors
/// `worker::SYSTEM_ENV_VARS`, and
/// `reserved_keys_tests::every_worker_system_variable_is_a_reserved_secret_key`
/// reads the worker's source to prove it: add a variable there and this test
/// fails until it is added here.
const RESERVED_SECRET_KEYS: &[&str] = &[
    "NEAR_SENDER_ID",
    "NEAR_CONTRACT_ID",
    "NEAR_BLOCK_HEIGHT",
    "NEAR_BLOCK_TIMESTAMP",
    "NEAR_RECEIPT_ID",
    "NEAR_PREDECESSOR_ID",
    "NEAR_SIGNER_PUBLIC_KEY",
    "NEAR_GAS_BURNT",
    "NEAR_USER_ACCOUNT_ID",
    "NEAR_PAYMENT_YOCTO",
    "NEAR_TRANSACTION_HASH",
    "NEAR_MAX_INSTRUCTIONS",
    "NEAR_MAX_MEMORY_MB",
    "NEAR_MAX_EXECUTION_SECONDS",
    "NEAR_REQUEST_ID",
    "NEAR_NETWORK_ID",
    "OUTLAYER_PROJECT_ID",
    "OUTLAYER_PROJECT_UUID",
    // Added once the worker's own list was written down and compared: each of
    // these was injected into the guest while remaining a legal secret key.
    // `OUTLAYER_PROJECT_OWNER` and `OUTLAYER_PROJECT_NAME` were the reachable
    // pair — the worker writes them only when a project id exists AND contains
    // a slash, so the overwrite lock did not cover them either.
    "OUTLAYER_EXECUTION_TYPE",
    "OUTLAYER_CALL_ID",
    "OUTLAYER_PROJECT_NAME",
    "OUTLAYER_PROJECT_OWNER",
    "ATTACHED_USD",
    "USD_PAYMENT",
    "WALLET_ID",
    "NEAR_RPC_PROXY_AVAILABLE",
];

/// Refuse a write that names one of [`RESERVED_SECRET_KEYS`].
///
/// One function rather than the same filter written at each door: the list
/// itself used to exist twice, the two copies drifted, and the names that had
/// only ever been added to one of them were exactly the ones a caller could
/// forge. A single list closed that; a single check keeps the doors from
/// drifting the same way.
///
/// Every name is reported, not just the first — an owner fixing a JSON blob
/// wants one round trip, not one per offending key.
fn reject_reserved_secret_keys<'a>(
    keys: impl Iterator<Item = &'a str>,
) -> Result<(), ApiError> {
    let reserved: Vec<&str> = keys.filter(|k| RESERVED_SECRET_KEYS.contains(k)).collect();
    if reserved.is_empty() {
        return Ok(());
    }
    tracing::warn!(reserved_keys = ?reserved, "Rejected secrets with reserved keywords");
    Err(ApiError::BadRequest(format!(
        "Cannot use reserved system keywords as secret keys: {}. \
         These environment variables are automatically set by OutLayer worker. \
         Please use different key names.",
        reserved.join(", ")
    )))
}

/// In-memory TEE challenge entry (for challenge-response protocol)
struct TeeChallenge {
    created_at: std::time::Instant,
}

/// In-memory TEE session entry
#[derive(Clone)]
struct TeeSession {
    worker_public_key: String,
    #[allow(dead_code)]
    created_at: std::time::Instant,
}

/// Bundled context populated together by `set_mpc_context` after TEE
/// registration. See [`AppState::mpc_context`] for the rationale.
///
/// **Nonce-lock invariant:** the keystore-worker holds ONE access key
/// on the keystore-dao contract that's authorised for both
/// `request_key` (CKD via [`crate::mpc_ckd`]) and
/// `mark_vault_verified` / `ban_vault` (via
/// [`crate::near::NearClient::submit_function_call`]). Any tx submitted
/// with this signer must serialize through `signer_nonce_lock` —
/// otherwise concurrent callers race to read the same nonce, build
/// txs with the same `nonce + 1`, and only one wins; the loser
/// surfaces an opaque `InvalidNonce` 500.
///
/// CKD calls FROM a vault account (Layer 2 of the per-vault master derivation) use a DIFFERENT
/// signer (the vault's TEE function-call key) and don't share this lock.
pub struct MpcContext {
    /// MPC CKD config (incl. `keystore_dao_id` and `mpc_contract_id`,
    /// both pre-parsed `AccountId`s). We require
    /// separate `keystore_dao_id` on this struct — read it from
    /// `mpc_ckd_config.keystore_dao_id` to keep one source of truth.
    pub mpc_ckd_config: crate::mpc_ckd::MpcCkdConfig,
    pub keystore_dao_signer: near_crypto::InMemorySigner,
    pub signer_nonce_lock: tokio::sync::Mutex<()>,
}

/// Application state shared across all handlers
#[derive(Clone)]
pub struct AppState {
    pub keystore: std::sync::Arc<tokio::sync::RwLock<crate::crypto::Keystore>>,
    pub config: crate::config::Config,
    pub near_client: Option<std::sync::Arc<crate::near::NearClient>>,
    pub is_ready: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// MPC CKD context — config + dao id + worker's keystore-dao
    /// signer with an integrated nonce-lock — populated only after a
    /// successful TEE registration. Empty for non-TEE / mock modes,
    /// which means the lazy per-vault-master path AND
    /// `/sign-vault-verification` are unavailable; any request that
    /// names a customer or asks to mark a vault fails fast with an
    /// explanatory error rather than silently falling back.
    ///
    /// **Why one struct, not three OnceLocks (atomicity invariant):**
    /// the three values are set together by exactly one path
    /// (`perform_tee_registration` → `set_mpc_context`). Bundling
    /// them under a single `OnceLock<MpcContext>` makes the set
    /// atomic — no observer can ever see a half-populated state
    /// where, say, `keystore_dao_signer` is set but `mpc_ckd_config`
    /// isn't.
    ///
    /// **Set-once interior mutability** is required because
    /// `AppState` is `Clone`d into handler tasks before TEE
    /// registration completes; the registration task runs async and
    /// populates this AFTER cloning.
    pub mpc_context: std::sync::Arc<std::sync::OnceLock<MpcContext>>,
    /// In-memory TEE challenge store: challenge_hex -> TeeChallenge
    tee_challenges: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, TeeChallenge>>>,
    /// In-memory TEE session store: session_id -> TeeSession
    tee_sessions: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<uuid::Uuid, TeeSession>>>,
}

impl AppState {
    pub fn new(
        keystore: crate::crypto::Keystore,
        config: crate::config::Config,
        near_client: Option<crate::near::NearClient>,
    ) -> Self {
        // Check if we're in TEE registration mode
        let is_tee_registration = std::env::var("USE_TEE_REGISTRATION")
            .unwrap_or_else(|_| "false".to_string())
            .parse::<bool>()
            .unwrap_or(false);

        // If not in TEE mode or already initialized, we're ready
        // If in TEE mode, we're ready only after getting master key from MPC
        let is_ready = !is_tee_registration;

        Self {
            keystore: std::sync::Arc::new(tokio::sync::RwLock::new(keystore)),
            config: config.clone(),
            near_client: near_client.map(std::sync::Arc::new),
            is_ready: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(is_ready)),
            mpc_context: std::sync::Arc::new(std::sync::OnceLock::new()),
            tee_challenges: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            tee_sessions: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        }
    }

    pub fn mark_ready(&self) {
        self.is_ready.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn is_ready(&self) -> bool {
        self.is_ready.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub async fn replace_keystore(&self, new_keystore: crate::crypto::Keystore) {
        let mut keystore = self.keystore.write().await;
        *keystore = new_keystore;
    }

    /// Populate the MPC CKD context after a successful TEE-mode boot.
    /// Called from `main.rs` once we know which keystore-dao + MPC
    /// contracts the worker is bound to. Set-once.
    ///
    /// **Re-call safety**: on the second call, the OnceLock will refuse
    /// the new value. If the inputs are identical to the first set
    /// (same dao_id, same MPC config) we treat it as benign idempotency.
    /// If they differ, we WARN — it almost certainly means a bug
    /// (worker re-registered against a different DAO mid-flight, or a
    /// configuration race). We do NOT panic because that would crash a
    /// running keystore over what is most likely an operator-fixable
    /// situation, but the warning is loud so on-call notices.
    ///
    /// Takes `&self` because `AppState` is shared across handler tasks
    /// via `Clone`. The fields use `OnceLock` for set-once interior
    /// mutability.
    pub fn set_mpc_context(
        &self,
        config: crate::mpc_ckd::MpcCkdConfig,
        keystore_dao_signer: near_crypto::InMemorySigner,
    ) {
        let new_ctx = MpcContext {
            mpc_ckd_config: config,
            keystore_dao_signer,
            signer_nonce_lock: tokio::sync::Mutex::new(()),
        };
        if let Err(rejected) = self.mpc_context.set(new_ctx) {
            let prev = self
                .mpc_context
                .get()
                .expect("OnceLock returned Err so it must already be set");
            // Re-call protection. The only legitimate caller is the
            // post-TEE-registration path, which runs once per process
            // — any second call is a bug. Warn loudly even on
            // identical config so the caller is held accountable
            // (intentional escalation from `debug!` so identical
            // re-set still surfaces as a state-bug signal).
            let drift = prev.mpc_ckd_config.mpc_contract_id != rejected.mpc_ckd_config.mpc_contract_id
                || prev.mpc_ckd_config.mpc_domain_id != rejected.mpc_ckd_config.mpc_domain_id
                || prev.mpc_ckd_config.mpc_public_key != rejected.mpc_ckd_config.mpc_public_key
                || prev.mpc_ckd_config.keystore_dao_id != rejected.mpc_ckd_config.keystore_dao_id
                || prev.keystore_dao_signer.public_key != rejected.keystore_dao_signer.public_key;
            if drift {
                tracing::warn!(
                    prev_dao = %prev.mpc_ckd_config.keystore_dao_id,
                    new_dao = %rejected.mpc_ckd_config.keystore_dao_id,
                    prev_mpc = %prev.mpc_ckd_config.mpc_contract_id,
                    new_mpc = %rejected.mpc_ckd_config.mpc_contract_id,
                    "set_mpc_context called twice with DIFFERENT context — keeping first, second ignored. \
                     This indicates a bug or misconfiguration."
                );
            } else {
                tracing::warn!(
                    "set_mpc_context called twice with identical context — second call ignored. \
                     This indicates a coding bug (only one TEE registration runs per process)."
                );
            }
        }
    }

    /// Lazy-load gate wrapper used by per-customer handlers. Snapshots
    /// the keystore (cheap — internal state is `Arc`-shared, so any
    /// inserts done by `add_customer` become visible to all clones) and
    /// delegates to [`crate::mpc_ckd::ensure_customer_loaded`].
    ///
    /// Returns an error when:
    ///   * `customer = Some(_)` but the worker was booted without MPC
    ///     context (non-TEE / mock — feature unsupported in that mode).
    ///   * the vault is not verified on keystore-dao (or banned).
    ///   * the vault is `unlocked == true` on chain (recovery
    ///     completed) — covered by the cold-path gate.
    ///   * the MPC CKD round-trip fails.
    ///
    /// `customer = None` always returns `Ok(())` immediately (legacy
    /// default-master path).
    ///
    /// **No cache short-circuit at this layer.** Every signing op
    /// delegates straight into [`crate::mpc_ckd::ensure_customer_loaded`],
    /// which calls `assert_serving_allowed` (the
    /// `is_vault_verified` + `get_state().unlocked == false` view-call
    /// pair) BEFORE checking the in-memory cache. That preserves the
    /// "sovereign after recovery" property even if the indexer-driven
    /// `/admin/evict-customer` is delayed: a vault under parent
    /// FullAccess control will trip the unlocked check and have its
    /// cached master evicted on the next request. Cost: two view-calls
    /// per signing op, issued concurrently once the vault is loaded, so
    /// ~100-300 ms rather than ~200-600 ms on the hot path; acceptable
    /// on the wallet path.
    pub async fn ensure_customer_loaded(
        &self,
        customer: Option<&near_primitives::types::AccountId>,
    ) -> anyhow::Result<()> {
        let Some(vault_id) = customer else {
            return Ok(());
        };

        // Snapshot the keystore. Cloning is cheap (Arc-shared internal
        // state) and avoids holding the outer RwLock across the await.
        // Inserts into the snapshot's `masters` propagate to the
        // canonical keystore via the shared Arc.
        let keystore_snapshot = self.keystore.read().await.clone();

        let ctx = self.mpc_context.get().ok_or_else(|| {
            anyhow::anyhow!(
                "per-customer master requested for {} but worker is running \
                 without MPC CKD context (non-TEE mode)",
                vault_id
            )
        })?;
        let near_client = self.near_client.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "per-customer master requested for {} but near_client \
                 is not configured",
                vault_id
            )
        })?;

        crate::mpc_ckd::ensure_customer_loaded(
            &ctx.mpc_ckd_config,
            near_client.as_ref(),
            &ctx.mpc_ckd_config.keystore_dao_id,
            &keystore_snapshot,
            Some(vault_id),
        )
        .await
    }
}

/// The door's verdict on one stored condition for one caller.
///
/// The condition's patterns are compiled first, once: one the engine will
/// not compile ([`crate::types::UnreadablePattern`]) refuses everyone with a
/// 401 naming the pattern, before anything is evaluated — the OWNER fixes
/// the row. Then the verdict: a denial carries the condition's own sentence
/// (`denial_message_in`, which names the caller's own lapsed time limit);
/// an error from evaluation (a chain read that failed, no client, a `WasmHash`
/// leaf on a request that reports no build, a `Predecessor` leaf on one that
/// reports no calling account) is this service's failure, a 500. Nothing is
/// ever admitted on an error.
///
/// `facts` is what the worker reported about the run: the build it will run,
/// as measured; the account that called the contract, as the receipt names it.
pub(crate) async fn judge_access(
    condition: &crate::types::AccessCondition,
    caller: &str,
    near_client: Option<&crate::near::NearClient>,
    facts: crate::types::RunFacts<'_>,
) -> Result<(), ApiError> {
    // Bounds first: a condition the keystore will not judge in full is refused
    // whole, before a single pattern is compiled — nothing else bounds how
    // many patterns a row holds, and each costs memory to compile.
    let shape = serde_json::to_value(condition)
        .map_err(|e| ApiError::InternalError(format!("Access condition could not be serialised: {e}")))?;
    if let Err(why) = shared_tee_helpers::access_limits::condition_bounds(&shape) {
        return Err(ApiError::Unauthorized(format!("Access denied by access condition: {why}")));
    }
    let patterns = match condition.compile_patterns() {
        Ok(patterns) => patterns,
        Err(unreadable) => return Err(ApiError::Unauthorized(unreadable.to_string())),
    };
    // A deadline on the whole evaluation, not on the number of leaves.
    // `NearBalance`, `FtBalance`, `NftOwned` and `DaoMember` are answered by a
    // view call against a contract the ROW'S OWNER chose, one after another,
    // on a client that waits 30s per call. Five of those is well under a
    // second against a healthy chain and up to two and a half minutes against
    // a slow or hostile one — and the caller's worker gives up after 30s,
    // which marks THIS keystore instance down for a minute for every other
    // job on that worker. Answering promptly with an error keeps the instance
    // in the pool (a stall does not), so a condition nobody can evaluate in
    // time costs its own row and nothing else.
    //
    // A branch that cannot be evaluated no longer stops the walk (see
    // `AccessCondition::evaluate`), so a tree whose first chain read fails now
    // performs the rest rather than returning at once: up to `MAX_CHAIN_READ_LEAVES`
    // calls where it used to make one. The wall-clock ceiling is unchanged —
    // this deadline covers the whole evaluation either way.
    let verdict = within_deadline(
        ACCESS_EVALUATION_DEADLINE,
        condition.evaluate(caller, near_client, &patterns, facts),
    )
    .await?;
    match verdict {
        Ok(true) => Ok(()),
        Ok(false) => Err(ApiError::Unauthorized(condition.denial_message_in(caller, &patterns, facts))),
        Err(e) => Err(ApiError::InternalError(format!("Access validation failed: {e}"))),
    }
}

/// How long the whole of one condition may take to evaluate.
///
/// Sized against the consumer, not against the chain: the worker waits 30s for
/// a decrypt in all (`worker/src/keystore_client.rs`), and a decrypt is more
/// than this step. Five chain reads against a healthy RPC are under a second,
/// so this leaves better than tenfold headroom for the honest case while
/// keeping a slow one from spending the worker's whole window. Fifteen seconds
/// is half of that window: enough that a merely sluggish RPC still answers,
/// short enough that the worker is not left waiting on this step alone.
const ACCESS_EVALUATION_DEADLINE: std::time::Duration = std::time::Duration::from_secs(15);

/// The deadline, applied. Separated so the three properties that matter can be
/// tested: that it fires, that firing is a REFUSAL, and that it never turns
/// into an admission.
async fn within_deadline<T>(
    deadline: std::time::Duration,
    fut: impl std::future::Future<Output = T>,
) -> Result<T, ApiError> {
    tokio::time::timeout(deadline, fut).await.map_err(|_| {
        ApiError::InternalError(format!(
            "Access condition could not be evaluated within {}s: it asks the chain for answers that did not arrive. \
             This is not a verdict about the caller — the condition's balance, NFT or DAO checks name contracts that are not answering.",
            deadline.as_secs()
        ))
    })
}

/// A caller-written seed, as a log line may carry it.
///
/// The seed arrives in the request body, whose only bound is the body limit, so
/// it is cut to a readable prefix BEFORE it reaches the log rather than filling
/// it. The length is kept because it is the part worth seeing when a seed is
/// not the shape it should be.
fn seed_for_log(seed: &str) -> String {
    const MOST: usize = 64;
    match seed.char_indices().nth(MOST) {
        Some((cut, _)) => format!("{}… ({} bytes in all)", &seed[..cut], seed.len()),
        None => seed.to_string(),
    }
}

/// The roots of the two families derived only for the keys a job's manifest
/// declares (`crate::signing_keys`, `crate::encryption_keys`), version
/// included in neither so a later scheme is covered too.
pub(crate) const DECLARED_KEY_ROOTS: [&str; 2] = ["signing-key:", "encryption-key:"];

/// Refuse a seed a caller spells when it starts at a declared-key root.
///
/// `/pubkey`, `/encrypt` and `/add_generated_secret` derive from the seed they
/// are sent — a secret's seed, `repo:owner[:branch]` and its siblings, none of
/// which starts at either root. One that did would spell a declared key's
/// derivation string.
fn refuse_declared_key_seed(seed: &str) -> Result<(), ApiError> {
    match DECLARED_KEY_ROOTS.iter().find(|root| seed.starts_with(**root)) {
        Some(root) => Err(ApiError::BadRequest(format!(
            "a seed cannot start with `{root}`: that root is reserved for the keys a job's manifest declares"
        ))),
        None => Ok(()),
    }
}

/// The first segment of a `Repo` accessor's seed: its normalized repo.
///
/// The seed is `{repo}:{owner}[:{branch}]` with the repo as the caller wrote it
/// less its scheme and `.git`, so a repo whose `{repo}:` starts at a
/// declared-key root (`signing-key`, or `encryption-key:v1:project`), with owner
/// and branch to match, would spell a declared key's derivation string. A
/// repository URL never does; such a repo is refused, every other one is
/// returned as `normalize_repo_url` gives it.
fn repo_seed_root(repo: &str) -> Result<String, ApiError> {
    let normalized = crate::utils::normalize_repo_url(repo);
    let seed_start = format!("{normalized}:");
    match DECLARED_KEY_ROOTS.iter().find(|root| seed_start.starts_with(**root)) {
        Some(root) => Err(ApiError::BadRequest(format!(
            "`{}` is not a repository URL: a repo cannot start with `{root}`, a root reserved for \
             the keys a job's manifest declares",
            seed_for_log(&normalized)
        ))),
        None => Ok(normalized),
    }
}

/// API error types
#[derive(Debug)]
pub enum ApiError {
    BadRequest(String),
    Unauthorized(String),
    Forbidden(String),
    /// The customer vault is underfunded and cannot pay for on-chain key
    /// derivation. HTTP 402 — the client must top up the vault. Distinct from
    /// BadRequest so the coordinator can forward an actionable message.
    PaymentRequired(String),
    /// The chain ANSWERED about the account, and the answer was not a value.
    ///
    /// `query_access_key` on an account the network cannot see returns "does
    /// not exist while viewing" — the chain telling us something, not failing
    /// to tell us anything. HTTP 422, which the coordinator forwards as
    /// `chain_refused`: terminal, and no `Retry-After`, because no interval
    /// makes an absent account present.
    ///
    /// Its own variant because the alternative was `InternalError` — a 500 the
    /// coordinator forwards as a transient `503`, telling the caller our
    /// service is down about a condition that will never clear on its own.
    /// This is the first thing a new wallet does, so it was also the first
    /// thing a new user saw.
    ///
    /// It deliberately does NOT claim the account is underfunded. The RPC
    /// returns a byte-identical string whether the account has never been used
    /// or exists with a different key on it (verified against testnet), so
    /// "send NEAR and it will work" would be a remedy we cannot know applies.
    ChainRefused(String),
    InternalError(String),
    /// This instance cannot serve the request at this moment, and the same
    /// request can succeed when made again: HTTP 503. A condition of the
    /// keystore's own memory, never a verdict on the request — no refusal
    /// code, nothing for the author or caller to change.
    Unavailable(String),
    /// The secret row a `/decrypt` request names is not on the contract. On the
    /// wire it is a 400 with the message, byte for byte what `BadRequest`
    /// answers — the answer the worker has always run on without secrets. Its
    /// own variant so that a keyed request reports this outcome beside the keys
    /// by type, and no other 400 is mistaken for it.
    SecretsNotFound(String),
    /// The declared keys a `/decrypt` request names — signing keys, encryption
    /// keys, or both — cannot be served: a field, the project or build, or a
    /// vault. Answered with its status and the code `signing_keys_refused`,
    /// so the worker can tell it from a secret's refusal and from a keystore
    /// that could not answer.
    ///
    /// One code for both families, on purpose: a keyed request is judged
    /// whole — the project and vault checks are shared by every key it names —
    /// so a refusal belongs to the request, not to a family, and the message
    /// says which keys it concerns. The code is the one workers already read.
    SigningKeysRefused(StatusCode, String),
}

/// The `code` of a refused keyed request, whichever family the refused keys
/// belong to.
pub(crate) const SIGNING_KEYS_REFUSED: &str = "signing_keys_refused";

impl ApiError {
    /// The message, whatever the variant.
    pub fn message(&self) -> &str {
        match self {
            ApiError::BadRequest(m)
            | ApiError::Unauthorized(m)
            | ApiError::Forbidden(m)
            | ApiError::PaymentRequired(m)
            | ApiError::ChainRefused(m)
            | ApiError::InternalError(m)
            | ApiError::Unavailable(m)
            | ApiError::SecretsNotFound(m)
            | ApiError::SigningKeysRefused(_, m) => m,
        }
    }

    /// Map an `ensure_customer_loaded` / CKD failure to an API error.
    ///
    /// An underfunded vault (the vault can't pay the MPC gas prepayment) is a
    /// user-actionable condition, not a server fault — surface it as a 402 with
    /// the exact top-up amount. Everything else surfaces the full anyhow source
    /// chain as a 400 (the chain carries the real `InvalidTxError` variant; it
    /// contains no secrets — see `mpc_ckd` logging audit).
    pub fn from_customer_load(e: anyhow::Error) -> Self {
        if let Some(b) = e.downcast_ref::<crate::mpc_ckd::InsufficientVaultBalance>() {
            ApiError::PaymentRequired(b.to_string())
        } else {
            ApiError::BadRequest(format!("{:#}", e))
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::BadRequest(msg) | ApiError::SecretsNotFound(msg) => (StatusCode::BAD_REQUEST, msg),
            ApiError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg),
            ApiError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg),
            ApiError::PaymentRequired(msg) => (StatusCode::PAYMENT_REQUIRED, msg),
            // 422 and not 402: the status IS the meaning, so nothing has to
            // read the sentence to classify it, and the vault's 402 keeps its
            // own remedy.
            ApiError::ChainRefused(msg) => (StatusCode::UNPROCESSABLE_ENTITY, msg),
            ApiError::InternalError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            ApiError::Unavailable(msg) => (StatusCode::SERVICE_UNAVAILABLE, msg),
            ApiError::SigningKeysRefused(status, msg) => {
                return (status, Json(serde_json::json!({"error": msg, "code": SIGNING_KEYS_REFUSED})))
                    .into_response()
            }
        };

        (status, Json(serde_json::json!({"error": message}))).into_response()
    }
}

/// Create the API router with all endpoints
///
/// Route access levels:
/// - Public (no auth): /health, /pubkey
/// - Worker-only (ALLOWED_WORKER_TOKEN_HASHES): /decrypt, /encrypt, /decrypt-raw, /storage/*
/// - Coordinator-only (ALLOWED_COORDINATOR_TOKEN_HASHES): /add_generated_secret, /update_user_secrets, /wallet/*
pub fn create_router(state: AppState) -> Router {
    // Worker-only routes (for TEE workers)
    // These endpoints require valid worker token - coordinator CANNOT access them
    // TEE session middleware runs AFTER auth (inner layer runs first in axum)
    let worker_routes = Router::new()
        .route("/decrypt", post(decrypt_handler))
        .route("/encrypt", post(encrypt_handler)) // For TopUp flow - re-encrypt with new balance
        .route("/decrypt-raw", post(decrypt_raw_handler)) // For TopUp flow - decrypt raw data with seed
        .route("/storage/encrypt", post(storage_encrypt_handler))
        .route("/storage/decrypt", post(storage_decrypt_handler))
        .route("/vrf/generate", post(vrf_generate_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            tee_session_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            worker_auth_middleware,
        ));

    // Coordinator-only routes (for dashboard proxy)
    // These endpoints require valid coordinator token - workers CANNOT access them
    let coordinator_routes = Router::new()
        .route("/add_generated_secret", post(add_generated_secret_handler))
        .route("/update_user_secrets", post(update_user_secrets_handler)) // + NEP-413 signature
        // Wallet endpoints (coordinator-only)
        .route("/wallet/derive-address", post(wallet_derive_address_handler))
        .route("/wallet/sign", post(wallet_sign_handler))
        .route("/wallet/evm/sign-typed-data", post(wallet_evm_sign_typed_data_handler))
        .route("/wallet/evm/sign-message", post(wallet_evm_sign_message_handler))
        .route("/wallet/evm/sign-transaction", post(wallet_evm_sign_transaction_handler))
        .route("/wallet/solana/sign-message", post(wallet_solana_sign_message_handler))
        .route("/wallet/solana/sign-transaction", post(wallet_solana_sign_transaction_handler))
        .route("/wallet/sign-policy", post(wallet_sign_policy_handler))
        .route("/wallet/sign-secret-store", post(wallet_sign_secret_store_handler))
        .route("/wallet/sign-secret-delete", post(wallet_sign_secret_delete_handler))
        .route("/wallet/check-policy", post(wallet_check_policy_handler))
        .route("/wallet/encrypt-policy", post(wallet_encrypt_policy_handler))
        .route("/wallet/decrypt-policy", post(wallet_decrypt_policy_handler))
        // Ephemeral keys — separate module, returns private keys (see ephemeral_keys.rs)
        .merge(crate::ephemeral_keys::ephemeral_key_routes())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            coordinator_auth_middleware,
        ));

    // Admin routes — internal-only side-channel for the monitoring
    // service to forcibly drop a per-customer master from cache when a
    // vault is banned. Auth piggybacks on the worker token so anything
    // that already speaks to /decrypt can also evict — see the route's
    // doc-comment on `/admin/evict-customer` for the threat model.
    // Read-only admin: worker OR coordinator token (see `admin_read_auth_middleware`).
    let admin_read_routes = Router::new()
        .route("/admin/loaded-vaults", get(admin_loaded_vaults_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            admin_read_auth_middleware,
        ));

    let admin_routes = Router::new()
        .route("/admin/evict-customer", post(admin_evict_customer_handler))
        // Race-attack monitor calls this. Worker-token-only —
        // unlike vault_routes, this MUTATES on-chain state by submitting
        // a `ban_vault` tx, so the auth boundary is intentionally
        // tight. Operator's monitoring service must hold a worker token.
        .route("/admin/ban-vault", post(admin_ban_vault_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            worker_auth_middleware,
        ));

    // Vault provisioning routes — accept EITHER coordinator OR worker
    // token. `/sign-vault-verification` is called by the public
    // `outlayer.near/vault-checker` WASI agent (worker token, since the
    // agent runs inside OutLayer's TEE workers) AND by the coordinator
    // proxy `/customer/sign-verification` driven by `outlayer vault init`
    // (coordinator token, since the CLI customer doesn't have a worker
    // token). `/derive-vault-tee-key` has the same caller mix. Both
    // endpoints' security guarantee is in-process re-verification or
    // public-only return, NOT the auth boundary; widening the auth lane
    // keeps the deploy story simple (one keystore token in coordinator
    // env, one in worker env, no double-allowlisting required) without
    // weakening the trust model.
    // /sign-vault-verification submits `mark_vault_verified` on chain
    // using the worker's keystore-DAO access key — every legitimate
    // call burns a small amount of that key's gas budget. To shrink
    // the blast radius of a leaked TEE-worker token, we restrict this
    // endpoint to coordinator auth only. Workers don't need to call
    // it (the verification flow is coordinator-driven); they keep
    // their wider auth on /decrypt, /derive, /wallet/*, etc.
    let vault_sign_routes = Router::new()
        .route("/sign-vault-verification", post(sign_vault_verification_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            coordinator_auth_middleware,
        ));

    // /derive-vault-tee-key returns a deterministic pubkey, no on-chain
    // tx, no allowance burn — safe on the wider TEE-registration lane.
    let vault_derive_routes = Router::new()
        .route("/derive-vault-tee-key", post(derive_vault_tee_key_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            tee_registration_auth_middleware,
        ));

    // TEE session routes (coordinator OR worker auth)
    // Workers can register directly or via coordinator proxy.
    // Security: challenge-response + NEAR RPC key check provide the actual verification.
    let tee_routes = Router::new()
        .route("/tee-challenge", post(tee_challenge_handler))
        .route("/register-tee", post(register_tee_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            tee_registration_auth_middleware,
        ));

    // Public routes (no auth required)
    Router::new()
        .route("/health", get(health_handler))
        .route("/pubkey", post(pubkey_handler)) // Public for dashboard encryption
        .route("/vrf/pubkey", get(vrf_pubkey_handler)) // Public VRF public key
        .merge(worker_routes)
        .merge(coordinator_routes)
        .merge(admin_read_routes)
        .merge(admin_routes)
        .merge(vault_sign_routes)
        .merge(vault_derive_routes)
        .merge(tee_routes)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Health check endpoint (no auth required)
/// Public and unauthenticated by design — it must stay a bare liveness signal. Anything that
/// reports fleet state (session counts, loaded vaults) belongs on `/admin/loaded-vaults`, where
/// a token is checked by auth middleware that also LOGS rejections: an unauthenticated,
/// unrate-limited, silent endpoint would otherwise let anyone test a candidate token by whether
/// the extra field appears.
async fn health_handler(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        tee_mode: format!("{}", state.config.tee_mode),
    })
}

/// Returns true iff the request's `Authorization: Bearer <token>` header
/// carries either a coordinator or worker token. Used for the
/// vault-scoped path on otherwise-public routes (`/pubkey`).
///
/// **Why this gate exists:** without it, the body-based
/// `vault_id` on `/pubkey` would let an unauthenticated caller force
/// the worker to perform an MPC CKD round-trip for ANY verified vault,
/// charging gas to the victim vault account on every cache miss
/// (~30 mNEAR/call). Public reads of pubkeys are still allowed for
/// `vault_id = None`, which preserves the dashboard's
/// pre-store-secrets pubkey-fetch flow on the legacy default master.
///
/// The cost is bounded and intended: a derivation is paid ONCE per vault per instance
/// lifetime. The master then stays in memory (`Keystore::masters`), so every later request for
/// that vault is served from RAM. A restart or a version upgrade empties the map and the first
/// request per vault pays again — that is how a new keystore version recovers vault keys, not a
/// leak. `/admin/loaded-vaults` reports what is currently loaded.
///
/// NOTE (2026-08-03 audit): the coordinator's `/secrets/pubkey` proxy is itself unauthenticated
/// and forwards a caller-supplied `X-Customer-Vault` under its own coordinator token, so an
/// anonymous caller CAN reach this path and make a vault pay for its own derivation. Accepted
/// (Vadim, 2026-08-03): the cost is one derivation per vault per instance lifetime, and the
/// vault set is not secret to whoever already knows a vault id. What must NOT leak to such a
/// caller is the keystore's address — the coordinator therefore strips the URL from the errors
/// it returns on that path. The loaded-vault list is worker-token-only
/// (`/admin/loaded-vaults`); enumeration by a holder of that token was considered and accepted
/// (Vadim, 2026-08-03): the same list is derivable from a chain indexer anyway.
fn has_authenticated_caller(state: &AppState, headers: &axum::http::HeaderMap) -> bool {
    let Some(auth) = headers.get("Authorization").and_then(|h| h.to_str().ok()) else {
        return false;
    };
    let Some(token) = auth.strip_prefix("Bearer ") else {
        return false;
    };
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let token_hash = hex::encode(hasher.finalize());
    token_hash_allowed_ct(&state.config.allowed_coordinator_token_hashes, &token_hash)
        | token_hash_allowed_ct(&state.config.allowed_worker_token_hashes, &token_hash)
}

/// Constant-time membership check of a bearer-token SHA-256 hash against an allowlist.
///
/// A plain `Vec::contains` / `==` short-circuits at the first differing byte, so the response
/// time leaks how many leading bytes matched — the classic timing side-channel for secret
/// comparison. Here the practical risk is LOW: we compare the SHA-256 *hash* of the token, not
/// the token, and SHA-256 is preimage-resistant, so an attacker who can only submit a token
/// (never the hash) cannot recover the hash byte-by-byte from timings. We still compare in
/// constant time as defense-in-depth (and so any future *raw*-secret compare can reuse this).
/// We OR over the whole list with no early-out, so neither the match position nor the
/// byte-match count leaks.
fn token_hash_allowed_ct(allowlist: &[String], token_hash: &str) -> bool {
    let mut allowed = false;
    for h in allowlist {
        // constant_time_eq is constant-time for equal-length inputs; SHA-256 hex is always 64 chars.
        allowed |= constant_time_eq::constant_time_eq(h.as_bytes(), token_hash.as_bytes());
    }
    allowed
}

/// Get public key for encryption AND validate secrets before encryption
async fn pubkey_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<PubkeyRequest>,
) -> Result<Json<PubkeyResponse>, ApiError> {
    // Check if keystore is ready (has master key from MPC)
    if !state.is_ready() {
        tracing::warn!("Pubkey request rejected - keystore not ready (waiting for DAO approval and MPC key)");
        return Err(ApiError::Unauthorized(
            "Keystore not ready. Waiting for DAO approval and master key from MPC.".to_string()
        ));
    }

    // 1. Validate secrets JSON first (check for reserved keywords)
    let secrets_map: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&req.secrets_json)
        .map_err(|e| ApiError::BadRequest(format!("Invalid JSON format: {}", e)))?;

    reject_reserved_secret_keys(secrets_map.keys().map(String::as_str))?;

    // Check for PROTECTED_ prefix in manual secrets (reserved for generated secrets)
    let protected_manual_keys: Vec<&str> = secrets_map.keys()
        .filter(|k| k.starts_with("PROTECTED_"))
        .map(|k| k.as_str())
        .collect();

    if !protected_manual_keys.is_empty() {
        tracing::warn!(
            protected_keys = ?protected_manual_keys,
            "Rejected manual secrets with PROTECTED_ prefix"
        );
        return Err(ApiError::BadRequest(format!(
            "Manual secrets cannot use 'PROTECTED_' prefix (reserved for auto-generated secrets): {}. \
            This prefix proves that a secret was generated in TEE and never seen by anyone.",
            protected_manual_keys.join(", ")
        )));
    }

    refuse_declared_key_seed(&req.seed)?;

    // 2. Generate public key for encryption
    // Route through per-vault master if vault_id is set in
    // the request body. We use body-based extraction here (not the
    // X-Customer-Vault header) because the vault scope is an attribute
    // of *which secret* this pubkey will encrypt — not of the caller's
    // session. Same fail-loud-on-malformed semantics.
    let customer = parse_optional_vault_id(req.vault_id.as_deref())?;

    // SECURITY: /pubkey is a public route. The
    // legacy `vault_id = None` flow stays public for the dashboard's
    // pre-store-secrets pubkey fetch. The vault-scoped flow can trigger
    // an MPC CKD round-trip via `ensure_customer_loaded` — that's gas
    // charged to the customer's vault account. We therefore require
    // coordinator/worker auth before allowing vault_id != None, so an
    // unauthenticated attacker cannot enumerate verified vaults and
    // burn their gas.
    if customer.is_some() && !has_authenticated_caller(&state, &headers) {
        tracing::warn!(
            vault_id = ?customer,
            "Rejected /pubkey vault-scoped request without coordinator/worker token"
        );
        return Err(ApiError::Unauthorized(
            "vault-scoped /pubkey requires coordinator or worker token".to_string(),
        ));
    }

    state
        .ensure_customer_loaded(customer.as_ref())
        .await
        .map_err(ApiError::from_customer_load)?;

    let keystore = state.keystore.read().await;
    let pubkey_hex = keystore
        .public_key_hex(customer.as_ref(), &req.seed)
        .map_err(|e| ApiError::InternalError(format!("Failed to derive public key: {}", e)))?;

    tracing::info!(
        seed = %seed_for_log(&req.seed),
        num_secrets = secrets_map.len(),
        vault_id = ?customer,
        "Validated secrets and generated pubkey"
    );

    Ok(Json(PubkeyResponse { pubkey: pubkey_hex }))
}

/// Convert keystore-worker's internally-tagged `SecretAccessor` to the
/// externally-tagged JSON shape that contract view methods expect.
///
/// keystore-worker uses `#[serde(tag = "type")]` on `SecretAccessor` so
/// it can deserialize requests where the accessor variant is announced
/// inline; the contract uses NEAR's default external tagging
/// (`{"Variant": {...}}`). This is the small adapter that bridges them.
/// `Repo.repo` is normalised the same way `near.rs::get_secrets` does
/// — this keeps key derivation consistent between the legacy lookup
/// path and the new combined `get_secret_with_vault` path.
fn accessor_to_contract_json(a: &SecretAccessor) -> serde_json::Value {
    match a {
        SecretAccessor::Repo { repo, branch } => serde_json::json!({
            "Repo": {
                "repo": crate::utils::normalize_repo_url(repo),
                "branch": branch,
            }
        }),
        SecretAccessor::WasmHash { hash } => serde_json::json!({
            "WasmHash": { "hash": hash }
        }),
        SecretAccessor::Project { project_id } => serde_json::json!({
            "Project": { "project_id": project_id }
        }),
        SecretAccessor::System { secret_type } => {
            serde_json::json!({ "System": secret_type.as_contract_str() })
        }
    }
}

/// A secret named after an agent may be read only by that agent, and may only
/// have been left there by that agent.
///
/// A connector credential belongs to a person, not to us, so both halves matter:
///
/// * **who reads it.** The author leaves it under the ACCOUNT of the agent it is
///   meant for, and comparing that name with the account actually asking is what
///   makes the name binding rather than decorative. No access condition has to be
///   written and none can be forgotten — naming the secret IS the grant;
/// * **who left it.** The owner must be the agent too. Anyone may call
///   `store_secrets`, and an agent's account is public, so without this half a
///   stranger could plant a credential of their own under that name and the
///   connector would run on THEIR mailbox, THEIR token. Only the agent's own
///   wallet can produce a secret it owns, and only `wk_` can make that wallet
///   sign.
///
/// It fires on the SHAPE of the name, because that is the one thing a thief
/// cannot avoid: the secret they are after is named after an agent, so asking
/// for it means asking under an account-shaped profile. A flag on the request
/// would instead be left off by whoever builds the request.
///
/// **An earlier version compared the owner against the wallet policy** read from
/// chain. That was weaker and dearer: weaker because the policy's owner is
/// whoever set it FIRST, and any holder of `wk_` can, so the credential's safety
/// rested on a race; dearer because it meant a view call on every read, one that
/// could not be cached. Making the agent own the secret settles both — the three
/// values become one, and the encryption seed (`project:{id}:{owner}`) lines up
/// with the name instead of quietly diverging from it.
///
/// **What this check is, and is not.** It separates one agent from another: a
/// secret named after agent A is not handed to agent B. That is a narrower and
/// much cheaper claim than authenticating either of them, and it is the claim
/// this function makes.
///
/// `caller` arrives from the coordinator. What that means for the trust model
/// is a question about the platform rather than about this function, and it is
/// answered where the platform is described, not in a comment here.
/// Whether an RPC failure is the chain telling us about the ACCOUNT rather
/// than failing to tell us anything.
///
/// Mirrors the coordinator's `ACCOUNT_FACT_ERRORS` on purpose: the same
/// distinction, in the component that is holding the error. One of these is
/// terminal and fixable by the caller; everything else is a node that did not
/// answer, which is transient and ours.
///
/// Matched on the FULL anyhow chain (`{:#}`), because the typed error's own
/// Display is the context string and says nothing.
fn rpc_error_is_about_the_signer(cause: &str) -> bool {
    // Wordings that can only be about an account or a key. The first is what
    // this RPC actually returns, captured from testnet; the other two are the
    // typed variants.
    const UNAMBIGUOUS: [&str; 3] = [
        "does not exist while viewing",
        "UNKNOWN_ACCOUNT",
        "UNKNOWN_ACCESS_KEY",
    ];
    if UNAMBIGUOUS.iter().any(|marker| cause.contains(marker)) {
        return true;
    }

    // A BARE "does not exist" is not enough, and this is the direction that
    // matters. A node that has garbage-collected a block answers "block does
    // not exist"; an unknown method answers that it does not exist either.
    // Read as a fact about the account, both would tell somebody whose wallet
    // is perfectly fine that their account is not on the network — a node's
    // condition reported as the caller's. So the sentence has to be ABOUT an
    // account or a key to count as one.
    let lower = cause.to_ascii_lowercase();
    let absent = lower.contains("does not exist") || lower.contains("doesn't exist");
    absent && (lower.contains("account") || lower.contains("access key"))
}

fn enforce_agent_secret(caller: &str, owner: &str, profile: &str) -> Result<(), ApiError> {
    if !shared_tee_helpers::is_implicit_account(profile) {
        return Ok(());
    }

    if profile != caller {
        return Err(ApiError::Unauthorized(
            "This secret is addressed to a different agent. A secret named after \
             an agent can only be read by that agent."
                .to_string(),
        ));
    }

    if profile != owner {
        return Err(ApiError::Unauthorized(
            "This secret was not left by the agent itself. A secret an agent may \
             read has to be stored by its own wallet — anyone else naming the \
             agent is a stranger planting a credential."
                .to_string(),
        ));
    }

    Ok(())
}


/// Decrypt secrets from contract for authorized TEE worker — and, for a request
/// that names them, derive the job's signing and encryption keys in the same
/// answer.
///
/// Which of the two a request is, is decided on its body before either shape is
/// parsed: a body with a `signing_keys` or `encryption_keys` member other than
/// `null` or `[]` is a [`KeyedDecryptRequest`]; every other body is a
/// [`DecryptRequest`], read by the same extractor as always, so its answer —
/// status, body, and every rejection — is the answer it always got.
async fn decrypt_handler(
    State(state): State<AppState>,
    worker: Option<axum::Extension<WorkerIdentity>>,
    request: axum::extract::Request,
) -> Response {
    use axum::extract::FromRequest;

    // A body that is not JSON-typed is never read here: the extractor refuses
    // it first, as it always did.
    if !json_content_type(request.headers()) {
        return match Json::<DecryptRequest>::from_request(request, &state).await {
            Ok(Json(req)) => decrypt_secrets_only(state, worker, req).await.into_response(),
            Err(rejection) => rejection.into_response(),
        };
    }
    let bytes = match axum::body::Bytes::from_request(request, &state).await {
        Ok(bytes) => bytes,
        Err(rejection) => return rejection.into_response(),
    };
    match body_shape(&bytes) {
        BodyShape::Keyed => match Json::<KeyedDecryptRequest>::from_bytes(&bytes) {
            Ok(Json(req)) => decrypt_with_keys(state, worker, req).await.into_response(),
            Err(rejection) => rejection.into_response(),
        },
        BodyShape::SecretsOnly => match Json::<DecryptRequest>::from_bytes(&bytes) {
            Ok(Json(req)) => decrypt_secrets_only(state, worker, req).await.into_response(),
            Err(rejection) => rejection.into_response(),
        },
        BodyShape::Ambiguous(reason) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({
                "error": format!(
                    "the request body cannot be read as either a secrets request or a keyed request: \
                     {reason}. A body names each of `signing_keys` and `encryption_keys` at most once."
                )
            })),
        )
            .into_response(),
    }
}

/// The content-type test the JSON extractor applies, so a body it would refuse
/// for its type is handed to it untouched and refused exactly as before.
fn json_content_type(headers: &axum::http::HeaderMap) -> bool {
    let Some(content_type) = headers.get(axum::http::header::CONTENT_TYPE) else {
        return false;
    };
    let Ok(content_type) = content_type.to_str() else {
        return false;
    };
    let Ok(mime) = content_type.parse::<mime::Mime>() else {
        return false;
    };
    mime.type_() == "application"
        && (mime.subtype() == "json" || mime.suffix().is_some_and(|name| name == "json"))
}

/// Which request a `/decrypt` body is.
enum BodyShape {
    /// A `signing_keys` or `encryption_keys` member other than `null` or an
    /// empty array.
    Keyed,
    /// No such member — or not a JSON object at all, or not JSON: the
    /// secrets-only extractor answers it as it always has.
    SecretsOnly,
    /// A JSON object the probe could not read as data — `signing_keys` or
    /// `encryption_keys` named twice. Neither parser is trusted with it: a duplicate member is read
    /// differently by different readers, so which shape the body "is" would
    /// depend on which reader looked. Refused with the reason.
    Ambiguous(String),
}

fn body_shape(body: &[u8]) -> BodyShape {
    #[derive(Deserialize)]
    struct Probe {
        #[serde(default)]
        signing_keys: Option<serde_json::Value>,
        #[serde(default)]
        encryption_keys: Option<serde_json::Value>,
    }
    /// Absent, `null` or `[]`: names no key.
    fn names_keys(member: &Option<serde_json::Value>) -> bool {
        match member {
            None | Some(serde_json::Value::Null) => false,
            Some(serde_json::Value::Array(a)) => !a.is_empty(),
            Some(_) => true,
        }
    }
    match serde_json::from_slice::<Probe>(body) {
        Ok(probe) if names_keys(&probe.signing_keys) || names_keys(&probe.encryption_keys) => BodyShape::Keyed,
        Ok(_) => BodyShape::SecretsOnly,
        // A data error on a well-formed object is one of the probe's fields
        // named more than once; a data error on anything else (an array, a
        // string) is the extractor's to refuse, as it always did.
        Err(e) if e.classify() == serde_json::error::Category::Data && is_json_object(body) => {
            BodyShape::Ambiguous(e.to_string())
        }
        Err(_) => BodyShape::SecretsOnly,
    }
}

/// Is `body` one JSON object (whatever its members, repeated or not)?
fn is_json_object(body: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(body).is_ok()
}

fn not_ready() -> ApiError {
    tracing::warn!("Decrypt request rejected - keystore not ready (waiting for DAO approval and MPC key)");
    ApiError::Unauthorized("Keystore not ready. Waiting for DAO approval and master key from MPC.".to_string())
}

/// Which worker instance asked. Absent only in dev mode (`TeeMode::None`),
/// where sessions are not enforced at all.
fn worker_key(worker: &Option<axum::Extension<WorkerIdentity>>) -> String {
    worker
        .as_ref()
        .map(|w| w.0 .0.clone())
        .unwrap_or_else(|| "no-session".to_string())
}

/// A request that names a secret row and no keys: the row, decrypted.
async fn decrypt_secrets_only(
    state: AppState,
    worker: Option<axum::Extension<WorkerIdentity>>,
    req: DecryptRequest,
) -> Result<Json<DecryptResponse>, ApiError> {
    // Check if keystore is ready (has master key from MPC)
    if !state.is_ready() {
        return Err(not_ready());
    }
    let worker_key = worker_key(&worker);
    let plaintext_secrets = decrypt_secret_row(
        &state,
        &worker_key,
        SecretRow {
            accessor: &req.accessor,
            profile: &req.profile,
            owner: &req.owner,
            user_account_id: &req.user_account_id,
            task_id: req.task_id.as_deref(),
            executed_wasm_sha256: req.executed_wasm_sha256.as_deref(),
            predecessor_id: req.predecessor_id.as_deref(),
        },
    )
    .await?;
    Ok(Json(DecryptResponse { plaintext_secrets }))
}

/// A request that names declared keys — signing, encryption, or both — and
/// the job's secret row if it has one.
///
/// The two are judged independently, and neither decides for the other: the
/// keys by [`authorize_keys`] (every key's binding against how the job was
/// started, the job's project and build on the contract, the vaults' owner),
/// the row by its own access condition, exactly as for a secrets-only request.
/// The keys are judged first and in full, both families together; a refusal
/// answers the whole request with the `signing_keys_refused` code before the
/// row is read, so no secret leaves beside a refused key. Then the row: an
/// outcome that would let the run continue without secrets is reported in
/// `secrets` and the keys still come back; any other failure of the row fails
/// the request with the same status and message a secrets-only request gets.
/// Only then are the keys derived.
async fn decrypt_with_keys(
    state: AppState,
    worker: Option<axum::Extension<WorkerIdentity>>,
    req: KeyedDecryptRequest,
) -> Result<Json<KeyedDecryptResponse>, ApiError> {
    if !state.is_ready() {
        return Err(not_ready());
    }
    let worker_key = worker_key(&worker);
    let task_id_str = req.task_id.as_deref().unwrap_or("unknown");

    let row = match (&req.accessor, &req.profile, &req.owner) {
        (Some(accessor), Some(profile), Some(owner)) => Some(SecretRow {
            accessor,
            profile,
            owner,
            user_account_id: &req.user_account_id,
            task_id: req.task_id.as_deref(),
            executed_wasm_sha256: req.executed_wasm_sha256.as_deref(),
            predecessor_id: req.predecessor_id.as_deref(),
        }),
        (None, None, None) => None,
        _ => {
            return Err(ApiError::BadRequest(
                "accessor, profile and owner name one secret row together: send all three, or none \
                 for a request that only derives keys"
                    .to_string(),
            ))
        }
    };

    let authorized = authorize_keys(&state, &req).await.inspect_err(|e| {
        tracing::warn!(
            task_id = %task_id_str,
            worker = %worker_key,
            project_id = ?req.project_id.as_deref().map(seed_for_log),
            caller = %seed_for_log(&req.user_account_id),
            predecessor = ?req.predecessor_id.as_deref().map(seed_for_log),
            "Declared keys refused: {}",
            crate::signing_keys::bounded(e.message(), crate::signing_keys::MOST_QUOTED_ERROR)
        );
    })?;

    let secrets = match row {
        None => None,
        Some(row) => Some(match decrypt_secret_row(&state, &worker_key, row).await {
            Ok(plaintext_secrets) => SecretsOutcome::Decrypted { plaintext_secrets },
            // The one refusal the worker runs on past, reported beside the keys.
            Err(ApiError::SecretsNotFound(error)) => {
                tracing::info!(task_id = %task_id_str, "Secret row reported as not found beside the declared keys");
                SecretsOutcome::NotFound { error }
            }
            Err(e) => return Err(e),
        }),
    };

    let signing_keys = match &authorized.signing {
        Some(bound) => Some(derive_keys(&state, bound, &authorized.what).await?),
        None => None,
    };
    let encryption_keys = match &authorized.encryption {
        Some(bound) => Some(derive_keys(&state, bound, &authorized.what).await?),
        None => None,
    };
    let described = |bound: &Option<crate::signing_keys::BoundKeys>| {
        bound
            .iter()
            .flat_map(|b| b.keys.iter())
            .map(|k| {
                format!(
                    "{}({}, bind={}, caller={}={}, vault={})",
                    k.path.as_str(),
                    k.kind.label(),
                    k.bind.label(),
                    k.caller.label(),
                    k.account,
                    k.vault.as_ref().map(|v| v.as_str()).unwrap_or("default")
                )
            })
            .collect::<Vec<_>>()
    };
    let run = authorized.run();
    tracing::info!(
        task_id = %task_id_str,
        worker = %worker_key,
        project_id = ?run.project.as_ref().map(|p| p.id.as_str()),
        project_uuid = ?run.project.as_ref().map(|p| p.uuid.as_str()),
        executed_wasm_sha256 = %run.wasm_sha256.as_str(),
        signer = %run.signer,
        predecessor = ?run.predecessor.as_ref().map(|p| p.as_str()),
        signing_keys = ?described(&authorized.signing),
        encryption_keys = ?described(&authorized.encryption),
        "Declared keys derived"
    );
    Ok(Json(KeyedDecryptResponse { secrets, signing_keys, encryption_keys }))
}

/// One secret row, as a `/decrypt` request names it, with the facts of the run
/// its access condition is judged against.
struct SecretRow<'a> {
    accessor: &'a SecretAccessor,
    profile: &'a str,
    owner: &'a str,
    user_account_id: &'a str,
    task_id: Option<&'a str>,
    executed_wasm_sha256: Option<&'a str>,
    predecessor_id: Option<&'a str>,
}

/// Read one secret row from the contract, judge its access condition against
/// the job's caller, and decrypt it. Returns the plaintext, base64.
async fn decrypt_secret_row(
    state: &AppState,
    worker_key: &str,
    row: SecretRow<'_>,
) -> Result<String, ApiError> {
    let task_id_str = row.task_id.unwrap_or("unknown");

    // Log request based on accessor type
    match row.accessor {
        SecretAccessor::Repo { repo, branch } => {
            tracing::info!(
                task_id = %task_id_str,
                worker = %worker_key,
                repo = %repo,
                branch = ?branch,
                profile = %row.profile,
                owner = %row.owner,
                "Received decrypt request (Repo)"
            );
        }
        SecretAccessor::WasmHash { hash } => {
            tracing::info!(
                task_id = %task_id_str,
                worker = %worker_key,
                wasm_hash = %hash,
                profile = %row.profile,
                owner = %row.owner,
                "Received decrypt request (WasmHash)"
            );
        }
        SecretAccessor::Project { project_id } => {
            tracing::info!(
                task_id = %task_id_str,
                worker = %worker_key,
                project_id = %project_id,
                profile = %row.profile,
                owner = %row.owner,
                "Received decrypt request (Project)"
            );
        }
        SecretAccessor::System { secret_type } => {
            tracing::info!(
                task_id = %task_id_str,
                worker = %worker_key,
                secret_type = ?secret_type,
                profile = %row.profile,
                owner = %row.owner,
                "Received decrypt request (System)"
            );
        }
    }

    // 1. Read secrets + vault binding from NEAR contract.
    //
    // Mechanism: on-chain side-table. A single combined
    // view call returns BOTH the encrypted secret profile AND the
    // per-secret vault binding. The vault binding tells us which master
    // to use for decryption; we don't accept a customer header here
    // because the customer must equal whatever was on-chain at write
    // time, and the chain is the only authoritative source.
    let near_client = state.near_client.as_ref()
        .ok_or_else(|| ApiError::InternalError("NEAR client not configured".to_string()))?;

    let accessor_json = accessor_to_contract_json(row.accessor);
    let combined = near_client
        .get_secret_with_vault(accessor_json, row.profile, row.owner)
        .await
        .map_err(|e| {
            tracing::error!(task_id = %task_id_str, error = %e, "Failed to read secrets from contract");
            ApiError::InternalError(format!("Failed to read secrets from contract: {}", e))
        })?;
    let vault_id_str = combined.vault_id;

    let secret_profile = combined.profile.ok_or_else(|| {
        // Per-variant log fields for grep-friendliness — operators
        // search by repo/wasm_hash/project_id/secret_type, so we don't
        // dump the whole accessor as Debug.
        match row.accessor {
            SecretAccessor::Repo { repo, branch } => tracing::warn!(
                task_id = %task_id_str,
                repo = %repo,
                branch = ?branch,
                profile = %row.profile,
                owner = %row.owner,
                "Secrets not found in contract"
            ),
            SecretAccessor::WasmHash { hash } => tracing::warn!(
                task_id = %task_id_str,
                wasm_hash = %hash,
                profile = %row.profile,
                owner = %row.owner,
                "Secrets not found in contract"
            ),
            SecretAccessor::Project { project_id } => tracing::warn!(
                task_id = %task_id_str,
                project_id = %project_id,
                profile = %row.profile,
                owner = %row.owner,
                "Secrets not found in contract"
            ),
            SecretAccessor::System { secret_type } => tracing::warn!(
                task_id = %task_id_str,
                secret_type = ?secret_type,
                profile = %row.profile,
                owner = %row.owner,
                "Secrets not found in contract"
            ),
        }
        ApiError::SecretsNotFound("Secrets not found in contract".to_string())
    })?;

    // Parse the on-chain vault binding into an AccountId, then ensure
    // the per-vault master is loaded BEFORE we touch the keystore.
    // Bridge between the contract's vault-binding side-table and the
    // lazy-load gate. Malformed vault_id on chain is a hard error
    // (chain shouldn't store malformed AccountIds — it would be a bug
    // in the contract or the binding writer).
    let customer = parse_optional_vault_id(vault_id_str.as_deref())?;

    tracing::debug!(
        task_id = %task_id_str,
        vault_id = ?customer,
        "Successfully read secrets from contract"
    );

    // 2. A secret named by an agent belongs to that agent alone.
    enforce_agent_secret(row.user_account_id, row.owner, row.profile).inspect_err(|_| {
        tracing::warn!(
            task_id = %task_id_str,
            caller = %row.user_account_id,
            owner = %row.owner,
            profile = %row.profile,
            "Access denied - secret is not this agent's"
        );
    })?;

    // 3. Validate access conditions
    let access_condition: crate::types::AccessCondition = serde_json::from_value(secret_profile["access"].clone())
        .map_err(|e| {
            tracing::error!(task_id = %task_id_str, error = %e, "Failed to parse access condition");
            ApiError::InternalError(format!("Failed to parse access condition: {}", e))
        })?;

    // Use user_account_id (who requested execution) as caller for access control
    let caller = row.user_account_id;

    if let Err(refusal) = judge_access(
        &access_condition,
        caller,
        state.near_client.as_ref().map(|c| c.as_ref()),
        crate::types::RunFacts {
            executed_wasm_sha256: row.executed_wasm_sha256,
            predecessor_id: row.predecessor_id,
        },
    )
    .await
    {
        match &refusal {
            // The message quotes an owner-written pattern: escaped, so a
            // newline or an escape sequence in it cannot forge a log line.
            ApiError::Unauthorized(message) => tracing::warn!(task_id = %task_id_str, caller = %caller, "{}", message.escape_debug()),
            other => tracing::error!(task_id = %task_id_str, caller = %caller, "{other:?}"),
        }
        return Err(refusal);
    }

    // The per-vault master is loaded only once the condition has ADMITTED. A
    // first touch derives the key through MPC CKD and is paid for out of the
    // vault's own balance, so loading it before the verdict would let anyone
    // spend a stranger's vault by asking for a row they may not read — and a
    // caller refused by the condition would be told about the vault's funding
    // instead of about the condition.
    state
        .ensure_customer_loaded(customer.as_ref())
        .await
        // Underfunded vault → 402 with a top-up message; anything else → 400
        // with the full chain. (Was InternalError/500, which hid the cause.)
        .map_err(ApiError::from_customer_load)?;

    tracing::info!(task_id = %task_id_str, caller = %caller, "Access granted");

    // 4. Build seed based on accessor type
    // SECURITY NOTE:
    // - For Repo: use branch from SECRET PROFILE (not request) to construct seed
    // - This is correct because seed must match the one used during encryption
    // - Access control already validated above via the secret's AccessCondition
    //   (caller = user_account_id, i.e. the request's signer — NOT necessarily the owner)
    // - Contract already returned the correct secrets based on request parameters
    //
    // The `seed` values logged below are NOT secrets — they are the
    // public input to `HMAC(master, seed)`. The actual secret half
    // is the master, which lives only in TEE enclave memory and is
    // never logged. Logging the seed at debug level helps support
    // hunt seed-mismatch bugs (caller computed seed != keystore's
    // computed seed) without exposing any cryptographic material.
    let seed = match row.accessor {
        SecretAccessor::Repo { repo, branch: request_branch } => {
            let normalized_repo = repo_seed_root(repo)?;
            // The contract's `SecretProfileView`
            // does NOT have a top-level `branch` field — branch is
            // nested inside `accessor.Repo.branch`. Reading
            // `secret_profile["branch"]` always returned Null, which
            // silently disabled the wildcard-fallback seed logic and
            // broke decryption for any secret stored with an explicit
            // branch. Fixed: read the actual nested location, falling
            // back to None if the contract returned a non-Repo accessor.
            let secret_branch = secret_profile
                .get("accessor")
                .and_then(|a| a.get("Repo"))
                .and_then(|r| r.get("branch"))
                .and_then(|b| b.as_str());

            // Log branch matching for debugging
            match (request_branch.as_deref(), secret_branch) {
                (Some(req_b), Some(sec_b)) if req_b == sec_b => {
                    tracing::debug!("Branch match: {} (exact)", req_b);
                }
                (Some(req_b), None) => {
                    tracing::debug!("Branch fallback: requested '{}', using wildcard secrets (branch=null)", req_b);
                }
                (None, None) => {
                    tracing::debug!("Branch match: both null (wildcard)");
                }
                (None, Some(sec_b)) => {
                    tracing::debug!("Branch match: secret has '{}', request wildcard", sec_b);
                }
                (Some(req_b), Some(sec_b)) => {
                    tracing::warn!(
                        task_id = %task_id_str,
                        request_branch = %req_b,
                        secret_branch = %sec_b,
                        "Branch mismatch - contract returned different branch than requested"
                    );
                }
            }

            // Build seed using branch from secret profile (critical for correct decryption)
            let seed = if let Some(b) = secret_branch {
                format!("{}:{}:{}", normalized_repo, row.owner, b)
            } else {
                format!("{}:{}", normalized_repo, row.owner)
            };

            tracing::debug!(
                task_id = %task_id_str,
                repo_normalized = %normalized_repo,
                owner = %row.owner,
                secret_branch = ?secret_branch,
                seed = %seed,
                "🔓 DECRYPTION SEED (Repo)"
            );

            seed
        }
        SecretAccessor::WasmHash { hash } => {
            let seed = format!("wasm_hash:{}:{}", hash, row.owner);

            tracing::debug!(
                task_id = %task_id_str,
                wasm_hash = %hash,
                owner = %row.owner,
                seed = %seed,
                "🔓 DECRYPTION SEED (WasmHash)"
            );

            seed
        }
        SecretAccessor::Project { project_id } => {
            let seed = format!("project:{}:{}", project_id, row.owner);

            tracing::debug!(
                task_id = %task_id_str,
                project_id = %project_id,
                owner = %row.owner,
                seed = %seed,
                "🔓 DECRYPTION SEED (Project)"
            );

            seed
        }
        SecretAccessor::System { secret_type } => {
            // Seed format: system:{type}:{owner}:{nonce}
            // nonce is stored in profile field
            let seed = format!("system:{}:{}:{}", secret_type.as_seed_str(), row.owner, row.profile);

            tracing::debug!(
                task_id = %task_id_str,
                secret_type = ?secret_type,
                owner = %row.owner,
                nonce = %row.profile,
                seed = %seed,
                "🔓 DECRYPTION SEED (System)"
            );

            seed
        }
    };

    // 5. Decrypt using derived keypair
    let encrypted_secrets_base64 = secret_profile["encrypted_secrets"]
        .as_str()
        .ok_or_else(|| ApiError::InternalError("Missing encrypted_secrets field".to_string()))?;

    let encrypted_bytes = base64::decode(encrypted_secrets_base64)
        .map_err(|e| ApiError::InternalError(format!("Invalid base64 in encrypted_secrets: {}", e)))?;

    let keystore = state.keystore.read().await;
    let plaintext_bytes = keystore.decrypt(customer.as_ref(), &seed, &encrypted_bytes).map_err(|e| {
        tracing::error!(task_id = %task_id_str, seed = %seed, error = %e, "Decryption failed");
        ApiError::InternalError(format!("Decryption failed: {}", e))
    })?;

    // 6. Encode plaintext as base64 for safe JSON transport
    let plaintext_b64 = base64::encode(&plaintext_bytes);

    tracing::info!(
        task_id = %task_id_str,
        plaintext_size = plaintext_bytes.len(),
        "Successfully decrypted secrets"
    );

    Ok(plaintext_b64)
}

/// The keys of one family that passed [`authorize_keys`], by path: seeds of
/// signing keys, or encryption keys. Never cached here; they leave in the
/// response and nowhere else.
async fn derive_keys(
    state: &AppState,
    bound: &crate::signing_keys::BoundKeys,
    what: &str,
) -> Result<std::collections::BTreeMap<String, crate::signing_keys::SeedHex>, ApiError> {
    use crate::signing_keys::KeyFamily;
    let keystore = state.keystore.read().await;
    let mut out = std::collections::BTreeMap::new();
    for key in &bound.keys {
        // A vault evicted since it was checked fails here — never the default
        // master in its place. That is a race with the eviction, not a verdict
        // on the request: [`authorize_keys`] passed this vault moments ago, and
        // the same request loads it again. So a 503 the run can retry, and no
        // refusal code.
        let derived = match bound.family {
            KeyFamily::Signing => keystore.derive_signing_key_seed(key.vault.as_ref(), &key.input),
            KeyFamily::Encryption => keystore.derive_encryption_key(key.vault.as_ref(), &key.input),
        };
        let secret = derived.map_err(|e| {
            if let Some(crate::crypto::VaultMasterNotLoaded(vault)) = e.downcast_ref() {
                tracing::warn!(vault = %vault, path = %key.path.as_str(), "{what}: vault master unloaded between the checks and the derivation");
                return ApiError::Unavailable(format!(
                    "{what}: the master of vault {vault} was unloaded while the request was served; \
                     the same request loads it again"
                ));
            }
            ApiError::SigningKeysRefused(
                StatusCode::BAD_REQUEST,
                format!("{what} refused: {} {:?} could not be derived: {e}", bound.family.noun(), key.path.as_str()),
            )
        })?;
        out.insert(key.path.as_str().to_string(), crate::signing_keys::SeedHex::from_seed(&secret));
    }
    Ok(out)
}

/// The keys of a keyed request that passed [`authorize_keys`], by family:
/// each present exactly when the request named keys of that family.
struct AuthorizedKeys {
    signing: Option<crate::signing_keys::BoundKeys>,
    encryption: Option<crate::signing_keys::BoundKeys>,
    /// How refusals and log lines name the keys of this request: "Signing
    /// keys", "Encryption keys", or both.
    what: String,
}

impl AuthorizedKeys {
    /// The run's facts, which every family's keys carry alike.
    fn run(&self) -> &crate::signing_keys::BoundKeys {
        self.signing
            .as_ref()
            .or(self.encryption.as_ref())
            .expect("authorize_keys refuses a request that names no keys")
    }
}

/// How a refusal names the keys a request carries.
fn keys_named(req: &KeyedDecryptRequest) -> &'static str {
    match (req.signing_keys.is_empty(), req.encryption_keys.is_empty()) {
        (false, true) => "Signing keys",
        (true, false) => "Encryption keys",
        (false, false) => "Signing and encryption keys",
        (true, true) => "Keys",
    }
}

/// Every check a keyed request must pass before anything is derived — for the
/// signing keys and the encryption keys it names, together.
///
/// 1. The fields, each family on its own:
///    [`crate::signing_keys::validate_request`] — every key's binding against
///    the run (`project` keys only with a `project_id`, `wasm` keys only
///    without one), the shapes that keep `:` out of every segment, the count
///    (per family), the build hash, the signer and predecessor, no vault on a
///    `wasm` key. A request naming no key of either family is refused. A
///    direct run ends here: its `wasm` keys are bound to the hash the worker
///    reports, the same trust a `WasmHash` access condition on a secret gives
///    it (`types.rs`, `RunFacts::executed_wasm_sha256`).
/// 2. The project, for a project run — two reads of the contract, made
///    together since both are needed, made once for both families, and made
///    at ONE final block ([`project_at_one_block`]) so both describe the same
///    project:
///    * `get_version(project_id, executed_wasm_sha256)`: the build the worker
///      measured on the bytes it is about to run must be a version of the
///      project whose source is a `WasmUrl` with that hash. A job cannot name
///      a project its code is not published under. A GitHub-sourced version is
///      keyed by `repo@commit` on chain, has no hash to check, and is refused;
///      so is any version whose source is not a `WasmUrl`.
///    * `get_project(project_id)`: the project exists, is owned by the account
///      its id names ([`project_owner`]), and has a well-formed `uuid`
///      ([`project_uuid`]) — what every `project` key is bound to. Read on
///      every project run and never cached: a project deleted and created
///      again under the same name is another project with another uuid, and a
///      cache would hand the new project the old one's keys for as long as the
///      entry lived.
/// 3. Each vault a key of either family names: it is a direct sub-account of
///    the project's owner ([`crate::signing_keys::vault_is_named_under`]) —
///    decided on the names alone, BEFORE the vault is read, so a vault that is
///    not the owner's costs no RPC — then its own `get_state` names that owner
///    as its parent ([`crate::signing_keys::vault_belongs_to`]), checked
///    BEFORE the vault's master is loaded — a first load is paid for by the
///    vault — and then it is loaded through the same gate as every per-vault
///    operation (verified on the DAO, not unlocked). What the chain SAYS
///    about the vault refuses the request with the refusal code: another
///    parent, not verified on the DAO or banned, unlocked — 403, each a
///    standing answer the author or the vault's owner changes, told apart by
///    type ([`crate::mpc_ckd::VaultNotServable`]), never by message; too poor
///    to pay for its first load — 402. A chain that could not be asked, or a
///    master that could not be loaded for any other reason, is
///    `InternalError` — the keystore's own outage, as for `get_version` and
///    `get_project` — since nothing the author or caller does clears it.
///    Either way the default master is never used for a key that names a
///    vault; a vault whose master leaves memory after these checks fails the
///    derivation in [`derive_keys`] with a 503, not a refusal.
///
/// Text from the RPC or the contract never reaches a message or a log line
/// whole: it is cut to [`crate::signing_keys::MOST_QUOTED_ERROR`] characters.
async fn authorize_keys(state: &AppState, req: &KeyedDecryptRequest) -> Result<AuthorizedKeys, ApiError> {
    use crate::signing_keys::{bounded, MOST_QUOTED_ERROR};

    let what = keys_named(req);
    let refused = |status: StatusCode, m: String| ApiError::SigningKeysRefused(status, format!("{what} refused: {m}"));

    let validate = |family: &str, result: Result<crate::signing_keys::ValidatedKeys, String>| {
        result.map_err(|m| ApiError::SigningKeysRefused(StatusCode::BAD_REQUEST, format!("{family} refused: {m}")))
    };
    let signing = if req.signing_keys.is_empty() {
        None
    } else {
        Some(validate(
            "Signing keys",
            crate::signing_keys::validate_request(
                req.project_id.as_deref(),
                &req.user_account_id,
                req.predecessor_id.as_deref(),
                req.executed_wasm_sha256.as_deref(),
                &req.signing_keys,
            ),
        )?)
    };
    let encryption = if req.encryption_keys.is_empty() {
        None
    } else {
        Some(validate(
            "Encryption keys",
            crate::signing_keys::validate_request(
                req.project_id.as_deref(),
                &req.user_account_id,
                req.predecessor_id.as_deref(),
                req.executed_wasm_sha256.as_deref(),
                &req.encryption_keys,
            ),
        )?)
    };
    let Some(first) = signing.as_ref().or(encryption.as_ref()) else {
        return Err(refused(
            StatusCode::BAD_REQUEST,
            "the request names neither signing_keys nor encryption_keys".to_string(),
        ));
    };
    let bind_all = |uuid: Option<crate::signing_keys::ProjectUuid>| -> Result<AuthorizedKeys, ApiError> {
        let bind = |v: Option<crate::signing_keys::ValidatedKeys>| {
            v.map(|v| v.bind(uuid.clone())).transpose().map_err(|m| refused(StatusCode::BAD_REQUEST, m))
        };
        Ok(AuthorizedKeys { signing: bind(signing.clone())?, encryption: bind(encryption.clone())?, what: what.to_string() })
    };

    let Some(project) = first.project.clone() else {
        return bind_all(None);
    };
    let near_client = state
        .near_client
        .as_ref()
        .ok_or_else(|| ApiError::InternalError("NEAR client not configured".to_string()))?;
    let project_id = project.as_str();
    let wasm = first.wasm_sha256.as_str();

    let (version, project_view) = project_at_one_block(near_client, project_id, wasm).await;
    let version = version.map_err(|e| {
        let said = bounded(&format!("{e:#}"), MOST_QUOTED_ERROR);
        tracing::warn!(project_id = %project_id, "{what}: the project version could not be read: {said}");
        ApiError::InternalError(format!("{what}: the project version could not be read: {said}"))
    })?;
    if !project_version_matches(&version, wasm) {
        return Err(refused(StatusCode::FORBIDDEN, format!(
            "the running build (sha256 {wasm}) is not a WasmUrl version of \
             project {project_id} on the contract. A project run gets keys only when its code is \
             published under the project as a WasmUrl version whose hash is this build's; a version \
             built from a GitHub repository gets none."
        )));
    }
    let project_view = project_view.map_err(|e| {
        let said = bounded(&format!("{e:#}"), MOST_QUOTED_ERROR);
        tracing::warn!(project_id = %project_id, "{what}: the project could not be read: {said}");
        ApiError::InternalError(format!("{what}: the project could not be read: {said}"))
    })?;
    let owner = project_owner(&project_view, &project).map_err(|m| refused(StatusCode::FORBIDDEN, m))?;
    let uuid = project_uuid(&project_view, &project).map_err(|m| refused(StatusCode::FORBIDDEN, m))?;

    // The distinct vaults both families name, in first-seen order.
    let mut vaults: Vec<near_primitives::types::AccountId> = Vec::new();
    for vault in signing.iter().chain(encryption.iter()).flat_map(|v| v.vaults()) {
        if !vaults.contains(&vault) {
            vaults.push(vault);
        }
    }
    // Every vault's name against the owner's, before any vault is read.
    for vault in &vaults {
        crate::signing_keys::vault_is_named_under(&owner, vault).map_err(|m| refused(StatusCode::FORBIDDEN, m))?;
    }
    for vault in &vaults {
        let vault_state = near_client
            .view_call_json(vault, "get_state", serde_json::json!({}))
            .await
            .map_err(|e| {
                let said = bounded(&format!("{e:#}"), MOST_QUOTED_ERROR);
                tracing::warn!(vault = %vault, "{what}: vault could not be read: {said}");
                ApiError::InternalError(format!(
                    "{what}: vault {vault} could not be read, so its owner cannot be established: {said}"
                ))
            })?;
        crate::signing_keys::vault_belongs_to(&owner, vault, &vault_state)
            .map_err(|m| refused(StatusCode::FORBIDDEN, m))?;
    }
    for vault in &vaults {
        state
            .ensure_customer_loaded(Some(vault))
            .await
            .map_err(|e| {
                if let Some(not_servable) = e.downcast_ref::<crate::mpc_ckd::VaultNotServable>() {
                    return refused(StatusCode::FORBIDDEN, not_servable.to_string());
                }
                match ApiError::from_customer_load(e) {
                    ApiError::PaymentRequired(m) => refused(StatusCode::PAYMENT_REQUIRED, m),
                    other => {
                        let said = bounded(other.message(), MOST_QUOTED_ERROR);
                        tracing::warn!(vault = %vault, "{what}: vault could not be loaded: {said}");
                        ApiError::InternalError(format!("{what}: vault {vault} is not available: {said}"))
                    }
                }
            })?;
    }
    bind_all(Some(uuid))
}

/// `get_version(project_id, wasm)` and `get_project(project_id)`, both as of
/// ONE final block, so the build check and the owner and uuid it binds keys to
/// describe one project: never a version of a project deleted in between and
/// the uuid of the one created again under its name.
///
/// Both are asked at `final` together, so the common case costs one
/// round-trip. Two answers from different blocks — the final head moved
/// between them, or the RPC's nodes stand at different heads — are reconciled
/// at the OLDER of the two blocks: the answer read at the newer one is read
/// again at the older one's hash. The older block is the one every node that
/// answered either read already holds. Either read failing is returned as its
/// own error, and no second read is made.
async fn project_at_one_block(
    near_client: &crate::near::NearClient,
    project_id: &str,
    wasm: &str,
) -> (anyhow::Result<serde_json::Value>, anyhow::Result<serde_json::Value>) {
    use near_primitives::types::{BlockId, BlockReference, Finality};
    let contract = near_client.contract_id();
    let version_args = serde_json::json!({ "project_id": project_id, "version_key": wasm });
    let project_args = serde_json::json!({ "project_id": project_id });
    let final_block = || BlockReference::Finality(Finality::Final);

    let (version, project) = tokio::join!(
        near_client.view_call_json_at(contract, "get_version", version_args.clone(), final_block()),
        near_client.view_call_json_at(contract, "get_project", project_args.clone(), final_block()),
    );
    let (version, project) = match (version, project) {
        (Ok(version), Ok(project)) => (version, project),
        (version, project) => return (version.map(|v| v.value), project.map(|p| p.value)),
    };
    if version.block_hash == project.block_hash {
        return (Ok(version.value), Ok(project.value));
    }
    let at = |hash| BlockReference::BlockId(BlockId::Hash(hash));
    if version.block_height <= project.block_height {
        let project = near_client
            .view_call_json_at(contract, "get_project", project_args, at(version.block_hash))
            .await
            .map(|p| p.value);
        (Ok(version.value), project)
    } else {
        let version = near_client
            .view_call_json_at(contract, "get_version", version_args, at(project.block_hash))
            .await
            .map(|v| v.value);
        (version, Ok(project.value))
    }
}

/// Is `version` (the contract's `get_version` answer) a WasmUrl version whose
/// hash is `wasm`? Both the key it was found by and its source must say so:
/// `null` — no such project or no such version — is not, and neither is a
/// version whose source is a GitHub repository, whatever it is keyed by.
fn project_version_matches(version: &serde_json::Value, wasm: &str) -> bool {
    let keyed_by_this_build = version.get("wasm_hash").and_then(|h| h.as_str()) == Some(wasm);
    let published_as_this_wasm = version
        .get("source")
        .and_then(|s| s.get("WasmUrl"))
        .and_then(|w| w.get("hash"))
        .and_then(|h| h.as_str())
        == Some(wasm);
    keyed_by_this_build && published_as_this_wasm
}

/// The project's owner from the contract's `get_project` answer, which must be
/// the owner its id names: a project is created as `{caller}/{name}` and a
/// transfer renames it, so the two disagree only on an answer this keystore
/// does not understand — refused rather than guessed at.
fn project_owner(
    project: &serde_json::Value,
    id: &crate::signing_keys::ProjectId,
) -> Result<near_primitives::types::AccountId, String> {
    if project.is_null() {
        return Err(format!("project {} does not exist on the contract", id.as_str()));
    }
    let owner = project
        .get("owner")
        .and_then(|o| o.as_str())
        .ok_or_else(|| format!("project {}: the contract names no owner", id.as_str()))?;
    let owner: near_primitives::types::AccountId = owner
        .parse()
        .map_err(|e| format!("project {}: the contract's owner is not an account id ({e})", id.as_str()))?;
    if &owner != id.owner() {
        return Err(format!(
            "project {}: the contract names {owner} as its owner, not {}",
            id.as_str(),
            id.owner()
        ));
    }
    Ok(owner)
}

/// The project's uuid from the contract's `get_project` answer: `p{16 hex}`,
/// minted once at `create_project`. What a `project` key is bound to. An
/// answer without one, or with one of another shape, is refused — never
/// derived from the id in its place.
fn project_uuid(
    project: &serde_json::Value,
    id: &crate::signing_keys::ProjectId,
) -> Result<crate::signing_keys::ProjectUuid, String> {
    let uuid = project
        .get("uuid")
        .and_then(|u| u.as_str())
        .ok_or_else(|| format!("project {}: the contract names no uuid", id.as_str()))?;
    crate::signing_keys::ProjectUuid::parse(uuid).map_err(|m| format!("project {}: {m}", id.as_str()))
}

/// Encrypt plaintext data
///
/// Used by workers to re-encrypt secrets after TopUp:
/// 1. Worker decrypts current Payment Key data via /decrypt-raw
/// 2. Worker parses JSON, updates initial_balance
/// 3. Worker calls /encrypt to get new encrypted data
/// 4. Worker calls promise_yield_resume with new encrypted data
async fn encrypt_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<EncryptRequest>,
) -> Result<Json<EncryptResponse>, ApiError> {
    // Check if keystore is ready
    if !state.is_ready() {
        tracing::warn!("Encrypt request rejected - keystore not ready");
        return Err(ApiError::Unauthorized(
            "Keystore not ready. Waiting for DAO approval and master key from MPC.".to_string()
        ));
    }

    tracing::info!(
        seed = %seed_for_log(&req.seed),
        "Received encrypt request"
    );

    refuse_declared_key_seed(&req.seed)?;

    // Decode plaintext from base64
    let plaintext_bytes = base64::decode(&req.plaintext_base64)
        .map_err(|e| ApiError::BadRequest(format!("Invalid base64 in plaintext: {}", e)))?;

    // Which master. A blob re-encrypted under the wrong one cannot be read
    // back by the party that stored it, so the scope has to travel with every
    // step of a re-encryption, not just the first.
    let customer = extract_customer_from_header(&headers)?;

    // Encrypt with derived key
    let keystore = state.keystore.read().await;
    let encrypted_bytes = keystore
        .encrypt(customer.as_ref(), &req.seed, &plaintext_bytes)
        .map_err(|e| ApiError::InternalError(format!("Failed to encrypt data: {}", e)))?;

    let encrypted_base64 = base64::encode(&encrypted_bytes);

    tracing::info!(
        seed = %seed_for_log(&req.seed),
        plaintext_len = plaintext_bytes.len(),
        encrypted_len = encrypted_bytes.len(),
        "Successfully encrypted data"
    );

    Ok(Json(EncryptResponse { encrypted_base64 }))
}

/// Decrypt raw encrypted data directly
///
/// Used by workers for TopUp flow:
/// 1. Worker receives encrypted_data from SystemEvent::TopUpPaymentKey
/// 2. Worker calls /decrypt-raw with seed and encrypted_data
/// 3. Worker receives plaintext Payment Key JSON
/// 4. Worker updates balance and calls /encrypt
async fn decrypt_raw_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<DecryptRawRequest>,
) -> Result<Json<DecryptRawResponse>, ApiError> {
    // Check if keystore is ready
    if !state.is_ready() {
        tracing::warn!("Decrypt-raw request rejected - keystore not ready");
        return Err(ApiError::Unauthorized(
            "Keystore not ready. Waiting for DAO approval and master key from MPC.".to_string()
        ));
    }

    tracing::info!(
        seed = %seed_for_log(&req.seed),
        "Received decrypt-raw request"
    );

    // Who reaches this handler: a worker approved on the register contract,
    // carrying a worker credential (`worker_auth_middleware`) and an attested
    // TEE session (`tee_session_middleware`). The plaintext it returns travels
    // enclave to enclave and is never visible to the host, to the coordinator
    // or to an operator — the same path `/decrypt` uses for a run's secrets.
    //
    // What this handler serves is the top-up flow: a payment key's own blob is
    // decrypted, its balance bumped, and the result re-encrypted.
    //
    // The prefix refuses every `Repo`, `WasmHash` and `Project` seed, which is
    // every row this flow has no business reading. What it does NOT do is scope
    // a worker to the rows of the job it is running: a `system:payment_key:`
    // seed names a row its owner stored with a condition of their own, and this
    // handler does not consult that condition. Inside the trust boundary that
    // is a scoping gap, not an exposure — closing it needs either a per-task
    // capability the keystore can check, or the top-up moving inside the
    // enclave the way `update_user_secrets_handler` already works for a user's
    // own secrets.
    if !req.seed.starts_with("system:payment_key:") {
        tracing::warn!(seed = %seed_for_log(&req.seed), "decrypt-raw refused: not a payment-key seed");
        return Err(ApiError::BadRequest(
            "decrypt-raw serves the top-up flow's `system:payment_key:` blobs only. A stored \
             secret is read through /decrypt, where its access condition is judged against the \
             caller."
                .to_string(),
        ));
    }

    // Decode encrypted data from base64
    let encrypted_bytes = base64::decode(&req.encrypted_base64)
        .map_err(|e| ApiError::BadRequest(format!("Invalid base64 in encrypted_data: {}", e)))?;

    // Which master the blob was written under. Asking the default for a blob
    // stored under a vault fails to decrypt — loudly, which is the right
    // direction, but it means the scope has to be supplied.
    let customer = extract_customer_from_header(&headers)?;

    // Decrypt with derived key
    let keystore = state.keystore.read().await;
    let plaintext_bytes = keystore
        .decrypt(customer.as_ref(), &req.seed, &encrypted_bytes)
        .map_err(|e| ApiError::InternalError(format!("Failed to decrypt data: {}", e)))?;

    let plaintext_base64 = base64::encode(&plaintext_bytes);

    tracing::info!(
        seed = %seed_for_log(&req.seed),
        encrypted_len = encrypted_bytes.len(),
        plaintext_len = plaintext_bytes.len(),
        "Successfully decrypted raw data"
    );

    Ok(Json(DecryptRawResponse { plaintext_base64 }))
}

/// Add generated secrets to existing encrypted secrets
///
/// Flow:
/// 1. Decrypt existing secrets (if provided)
/// 2. Generate new secrets
/// 3. Check for collisions (key already exists?)
/// 4. Merge old + new secrets
/// 5. Re-encrypt and return
async fn add_generated_secret_handler(
    State(state): State<AppState>,
    Json(req): Json<AddGeneratedSecretRequest>,
) -> Result<Json<AddGeneratedSecretResponse>, ApiError> {
    // Check if keystore is ready (has master key from MPC)
    if !state.is_ready() {
        tracing::warn!("Add generated secret request rejected - keystore not ready (waiting for DAO approval and MPC key)");
        return Err(ApiError::Unauthorized(
            "Keystore not ready. Waiting for DAO approval and master key from MPC.".to_string()
        ));
    }

    // Size check FIRST — before the vault is loaded. Loading a cold vault runs an on-chain MPC
    // CKD derivation paid out of that vault's balance, so an oversized request must be refused
    // without ever getting that far.
    if req.new_secrets.len() > MAX_GENERATED_SECRETS {
        return Err(ApiError::BadRequest(format!(
            "too many generated secrets in one request: {} (limit {}). \
             Split them across several calls.",
            req.new_secrets.len(),
            MAX_GENERATED_SECRETS
        )));
    }
    refuse_declared_key_seed(&req.seed)?;

    // Vault scope from request body. The decrypt+re-encrypt
    // round-trip MUST use the same scope (default OR vault) as the
    // original encryption — mismatched scope would either fail to
    // decrypt or silently re-encrypt under the wrong key.
    let customer = parse_optional_vault_id(req.vault_id.as_deref())?;
    state
        .ensure_customer_loaded(customer.as_ref())
        .await
        .map_err(ApiError::from_customer_load)?;

    tracing::info!(
        seed = %seed_for_log(&req.seed),
        num_new_secrets = req.new_secrets.len(),
        has_existing = req.encrypted_secrets_base64.is_some(),
        vault_id = ?customer,
        "Received add_generated_secret request"
    );

    // 1. Decrypt existing secrets (if any)
    let mut secrets_map: serde_json::Map<String, serde_json::Value> = if let Some(ref encrypted_b64) = req.encrypted_secrets_base64 {
        // Decode base64
        let encrypted_bytes = base64::decode(encrypted_b64)
            .map_err(|e| ApiError::BadRequest(format!("Invalid base64 in encrypted_secrets: {}", e)))?;

        // Decrypt
        let keystore = state.keystore.read().await;
        let plaintext_bytes = keystore
            .decrypt(customer.as_ref(), &req.seed, &encrypted_bytes)
            .map_err(|e| ApiError::InternalError(format!("Failed to decrypt existing secrets: {}", e)))?;
        drop(keystore); // Release read lock early

        // Parse JSON
        let plaintext_str = String::from_utf8(plaintext_bytes)
            .map_err(|e| ApiError::InternalError(format!("Decrypted data is not valid UTF-8: {}", e)))?;

        serde_json::from_str(&plaintext_str)
            .map_err(|e| ApiError::InternalError(format!("Decrypted data is not valid JSON: {}", e)))?
    } else {
        // Start with empty secrets
        serde_json::Map::new()
    };

    tracing::debug!(
        existing_keys = secrets_map.len(),
        "Decrypted existing secrets"
    );

    // Validate that manual secrets don't use PROTECTED_ prefix
    let protected_manual_keys: Vec<&String> = secrets_map.keys()
        .filter(|k| k.starts_with("PROTECTED_"))
        .collect();

    if !protected_manual_keys.is_empty() {
        return Err(ApiError::BadRequest(format!(
            "Manual secrets cannot use 'PROTECTED_' prefix (reserved for auto-generated secrets): {}",
            protected_manual_keys.iter().map(|k| k.as_str()).collect::<Vec<_>>().join(", ")
        )));
    }

    // Validate generated secret names MUST start with PROTECTED_
    let missing_prefix: Vec<&String> = req.new_secrets.iter()
        .map(|s| &s.name)
        .filter(|name| !name.starts_with("PROTECTED_"))
        .collect();

    if !missing_prefix.is_empty() {
        return Err(ApiError::BadRequest(format!(
            "Generated secrets must start with 'PROTECTED_' prefix: {}. \
            This prefix proves that secrets were generated in TEE and never seen by anyone.",
            missing_prefix.iter().map(|k| k.as_str()).collect::<Vec<_>>().join(", ")
        )));
    }

    // 2. Check for collisions BEFORE generating
    let mut collisions: Vec<String> = Vec::new();
    for spec in &req.new_secrets {
        if secrets_map.contains_key(&spec.name) {
            collisions.push(spec.name.clone());
        }
    }

    if !collisions.is_empty() {
        return Err(ApiError::BadRequest(format!(
            "Cannot generate secrets: keys already exist: {}. Please use different names or remove existing keys first.",
            collisions.join(", ")
        )));
    }

    // 3. Generate new secrets
    let mut generated_keys: Vec<String> = Vec::new();
    for spec in &req.new_secrets {
        // Build generation directive
        let directive = format!("generate_outlayer_secret:{}", spec.generation_type);

        // Generate
        let generated_value = crate::secret_generation::generate_secret(&directive)
            .map_err(|e| ApiError::BadRequest(format!(
                "Failed to generate secret '{}' with type '{}': {}",
                spec.name, spec.generation_type, e
            )))?;

        // Add to secrets map
        secrets_map.insert(spec.name.clone(), serde_json::Value::String(generated_value));
        generated_keys.push(spec.name.clone());
    }

    // One line for the batch, not one per secret. This used to log inside the loop, which turned
    // a single request into as many log lines as it carried secrets — cheap for the sender,
    // expensive for our disk and for anyone reading the log afterwards. `MAX_GENERATED_SECRETS`
    // now bounds it too, but the aggregate line is the right shape regardless.
    tracing::info!(
        count = generated_keys.len(),
        keys = ?generated_keys,
        "Generated secrets"
    );

    // 4. Validate no reserved keywords (final check)
    reject_reserved_secret_keys(secrets_map.keys().map(String::as_str))?;

    // 5. Re-encrypt merged secrets
    let final_secrets_json = serde_json::to_string(&secrets_map)
        .map_err(|e| ApiError::InternalError(format!("Failed to serialize secrets: {}", e)))?;

    let keystore = state.keystore.read().await;
    let encrypted_bytes = keystore
        .encrypt(customer.as_ref(), &req.seed, final_secrets_json.as_bytes())
        .map_err(|e| ApiError::InternalError(format!("Failed to encrypt secrets: {}", e)))?;

    let encrypted_base64 = base64::encode(&encrypted_bytes);

    // Get all secret keys for verification
    let all_secret_keys: Vec<String> = secrets_map.keys().cloned().collect();

    tracing::info!(
        seed = %seed_for_log(&req.seed),
        total_secrets = secrets_map.len(),
        newly_generated_count = generated_keys.len(),
        encrypted_size = encrypted_bytes.len(),
        all_keys = ?all_secret_keys,
        "Successfully added generated secrets"
    );

    Ok(Json(AddGeneratedSecretResponse {
        encrypted_data_base64: encrypted_base64,
        all_keys: all_secret_keys,
    }))
}

/// Update user secrets with NEAR signature authentication
async fn update_user_secrets_handler(
    State(state): State<AppState>,
    Json(req): Json<UpdateUserSecretsRequest>,
) -> Result<Json<UpdateUserSecretsResponse>, ApiError> {
    // Check if keystore is ready
    if !state.is_ready() {
        tracing::warn!("Update secrets request rejected - keystore not ready");
        return Err(ApiError::Unauthorized(
            "Keystore not ready. Waiting for DAO approval and master key from MPC.".to_string()
        ));
    }

    // What this request is ASKING to store, checked before anything is loaded
    // or decrypted: `ensure_customer_loaded` below can run an on-chain MPC
    // derivation paid out of the vault's balance, and a request that cannot be
    // stored should not cost that.
    //
    // The incoming keys only, never the merged result. In `Append` mode the
    // merge carries whatever the owner already has, and a name that predates
    // this list would then block every future update — including the one that
    // would remove it. Refusing what is being written is the whole rule; what
    // is already written is the worker's second lock to neutralize.
    reject_reserved_secret_keys(req.secrets.keys().map(String::as_str))?;

    // Vault scope from request body. The Append-mode decrypt
    // and the final encrypt MUST run under the same scope, otherwise
    // the round-trip would corrupt the user's data.
    let customer = parse_optional_vault_id(req.vault_id.as_deref())?;
    state
        .ensure_customer_loaded(customer.as_ref())
        .await
        .map_err(ApiError::from_customer_load)?;

    tracing::info!(
        owner = %req.owner,
        profile = %req.profile,
        mode = ?req.mode,
        vault_id = ?customer,
        "Received update_user_secrets request"
    );

    // 1. Verify message format
    // New format includes secrets payload for verification:
    // "Update Outlayer secrets for {owner}:{profile}\nkeys:{key1,key2}\nprotected:{PROTECTED_A,PROTECTED_B}"
    let mut expected_message = format!("Update Outlayer secrets for {}:{}", req.owner, req.profile);

    // Add sorted secret keys to message (must match dashboard serialization)
    let mut secret_keys: Vec<&String> = req.secrets.keys().collect();
    secret_keys.sort();
    if !secret_keys.is_empty() {
        expected_message.push_str("\nkeys:");
        expected_message.push_str(&secret_keys.iter().map(|k| k.as_str()).collect::<Vec<_>>().join(","));
    }

    // Add sorted PROTECTED_ names to message
    if let Some(ref generate) = req.generate_protected {
        let mut protected_names: Vec<&str> = generate.iter().map(|g| g.name.as_str()).collect();
        protected_names.sort();
        if !protected_names.is_empty() {
            expected_message.push_str("\nprotected:");
            expected_message.push_str(&protected_names.join(","));
        }
    }

    if req.signed_message != expected_message {
        tracing::warn!(
            expected = %expected_message,
            received = %req.signed_message,
            "Message format mismatch"
        );
        return Err(ApiError::BadRequest(format!(
            "Invalid message format. Expected payload to match request data. Expected: '{}', Got: '{}'",
            expected_message, req.signed_message
        )));
    }

    // 2. Verify NEAR signature (NEP-413)
    tracing::info!(
        message = %req.signed_message,
        public_key = %crate::near::key_for_display(&req.public_key),
        nonce = %req.nonce,
        recipient = %req.recipient,
        signature_len = req.signature.len(),
        "Verifying NEP-413 signature"
    );

    match verify_near_signature(&req.signed_message, &req.signature, &req.public_key, &req.nonce, &req.recipient) {
        Ok(()) => {
            tracing::info!(
                owner = %req.owner,
                public_key = %crate::near::key_for_display(&req.public_key),
                "✅ NEP-413 signature verified successfully"
            );
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                message = %req.signed_message,
                public_key = %crate::near::key_for_display(&req.public_key),
                nonce = %req.nonce,
                recipient = %req.recipient,
                "❌ NEP-413 signature verification failed"
            );
            return Err(ApiError::Unauthorized(format!("Invalid signature: {}", e)));
        }
    }

    // 3. Verify public key belongs to owner via NEAR RPC
    let near_client = state.near_client.as_ref();
    if let Some(client) = near_client {
        match client.verify_access_key_owner(&req.owner, &req.public_key).await {
            Ok(()) => {
                tracing::info!(
                    owner = %req.owner,
                    public_key = %crate::near::key_for_display(&req.public_key),
                    "✅ Access key ownership verified via NEAR RPC"
                );
            }
            Err(e) => {
                tracing::warn!(
                    owner = %req.owner,
                    public_key = %crate::near::key_for_display(&req.public_key),
                    error = %e,
                    "❌ Access key ownership verification failed"
                );
                return Err(ApiError::Unauthorized(e.to_string()));
            }
        }
    } else {
        // A signature proves somebody holds a key; only the chain says whose
        // account that key is on. Without the lookup any keypair could sign
        // "for" any owner, so an unconfigured keystore refuses instead.
        tracing::error!("update_user_secrets refused: no NEAR client to check key ownership with");
        return Err(ApiError::InternalError(
            "This keystore cannot check that the signing key belongs to the owner's account \
             (NEAR_RPC_URL / NEAR_CONTRACT_ID are not set), so it will not update secrets."
                .to_string(),
        ));
    }

    // 4. Validate user secrets don't contain PROTECTED_ prefix
    let protected_in_user_secrets: Vec<&String> = req.secrets.keys()
        .filter(|k| k.starts_with("PROTECTED_"))
        .collect();

    if !protected_in_user_secrets.is_empty() {
        return Err(ApiError::BadRequest(format!(
            "User secrets cannot use 'PROTECTED_' prefix: {}",
            protected_in_user_secrets.iter().map(|k| k.as_str()).collect::<Vec<_>>().join(", ")
        )));
    }

    // 5. Determine if this is a migration (accessor change)
    let is_migration = req.new_accessor.is_some();
    if is_migration {
        tracing::info!(
            owner = %req.owner,
            profile = %req.profile,
            "Migration mode: will decrypt with old accessor, encrypt with new accessor"
        );
    }

    // 6. Get current encrypted secrets + on-chain vault binding using
    //    OLD accessor (new_accessor is only for encryption target).
    //
    // CRITICAL: we MUST decrypt existing data under the
    // scope it was originally written with — that's the on-chain
    // `vault_id` binding, NOT the body-supplied vault_id (which
    // applies only to the new write).
    //
    // Migration paths supported:
    //   * default→vault: existing secret has vault_id=None on chain;
    //     body sends vault_id=Some(v). We decrypt under None, encrypt
    //     under v.
    //   * vault→vault (rotation): existing has vault_id=Some(a),
    //     body sends Some(b). Decrypt under a, encrypt under b.
    //   * no migration: existing has vault_id=Some(a), body sends
    //     Some(a). Decrypt and encrypt under a.
    let near_client = state.near_client.as_ref()
        .ok_or_else(|| ApiError::InternalError("NEAR client not configured".to_string()))?;

    let accessor_json_for_lookup = accessor_to_contract_json(&req.accessor);
    let combined = near_client
        .get_secret_with_vault(accessor_json_for_lookup, &req.profile, &req.owner)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "Failed to fetch secrets from contract");
            ApiError::InternalError(format!("Failed to fetch secrets: {}", e))
        })?;
    let secret_profile = combined.profile;
    let on_chain_vault_id_str = combined.vault_id;

    let existing_customer = parse_optional_vault_id(on_chain_vault_id_str.as_deref())?;
    // Make sure the master that was used at write time is loaded
    // before we try to decrypt. For default-master path
    // (existing_customer = None) this is a no-op.
    state
        .ensure_customer_loaded(existing_customer.as_ref())
        .await
        .map_err(|e| ApiError::InternalError(format!(
            "lazy-load gate failed for existing vault {}: {}",
            existing_customer.as_ref().map(|v| v.as_str()).unwrap_or("<none>"),
            e
        )))?;

    // 7. Decrypt existing secrets (if any) using OLD accessor seed
    let mut current_secrets: serde_json::Map<String, serde_json::Value> = if let Some(profile) = secret_profile {
        tracing::info!(
            profile_data = ?profile,
            "Found existing secrets in contract, attempting to decrypt"
        );

        // Extract encrypted_secrets field from JSON
        let encrypted_secrets_str = profile
            .get("encrypted_secrets")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                tracing::error!("Missing encrypted_secrets field in profile data");
                ApiError::InternalError("Missing encrypted_secrets field".to_string())
            })?;

        // Decode from base64
        let encrypted_bytes = base64::decode(encrypted_secrets_str)
            .map_err(|e| {
                tracing::error!(error = %e, "Invalid base64 in stored secrets");
                ApiError::BadRequest(format!("Invalid base64 in stored secrets: {}", e))
            })?;

        // Generate seed for decryption (must match format used during encryption)
        // Format: normalized_repo:owner[:branch] - same as /pubkey endpoint
        let seed = match &req.accessor {
            SecretAccessor::Repo { repo, branch } => {
                let normalized_repo = repo_seed_root(repo)?;
                if let Some(b) = branch.as_deref().filter(|s| !s.is_empty()) {
                    format!("{}:{}:{}", normalized_repo, req.owner, b)
                } else {
                    format!("{}:{}", normalized_repo, req.owner)
                }
            }
            SecretAccessor::WasmHash { hash } => {
                format!("wasm_hash:{}:{}", hash, req.owner)
            }
            SecretAccessor::Project { project_id } => {
                format!("project:{}:{}", project_id, req.owner)
            }
            // Both halves in the seed, so a secret pinned to one version of one
            // project is cryptographically a DIFFERENT secret from the same
            // project's other versions and from a clone running the same bytes.
            SecretAccessor::System { secret_type } => {
                format!("system:{}:{}:{}", secret_type.as_seed_str(), req.owner, req.profile)
            }
        };

        tracing::debug!(
            seed = %seed,
            encrypted_len = encrypted_bytes.len(),
            "Attempting to decrypt existing secrets"
        );

        // Decrypt under the EXISTING (on-chain) scope — see comment at
        // step 6 above. Body's `customer` is for the new encrypt only.
        let keystore = state.keystore.read().await;
        let plaintext_bytes = keystore
            .decrypt(existing_customer.as_ref(), &seed, &encrypted_bytes)
            .map_err(|e| {
                tracing::error!(
                    error = %e,
                    seed = %seed,
                    "Failed to decrypt existing secrets - possibly encrypted with different key or corrupted"
                );
                ApiError::InternalError(format!("Failed to decrypt existing secrets: {}", e))
            })?;
        drop(keystore);

        // Parse JSON
        let plaintext_str = String::from_utf8(plaintext_bytes)
            .map_err(|e| {
                tracing::error!(error = %e, "Decrypted data is not valid UTF-8");
                ApiError::InternalError(format!("Decrypted data is not valid UTF-8: {}", e))
            })?;

        let secrets: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&plaintext_str)
            .map_err(|e| {
                tracing::error!(error = %e, "Decrypted data is not valid JSON");
                ApiError::InternalError(format!("Decrypted data is not valid JSON: {}", e))
            })?;

        tracing::info!(
            num_existing_secrets = secrets.len(),
            "Successfully decrypted existing secrets"
        );

        secrets
    } else {
        // No existing secrets
        tracing::info!("No existing secrets found in contract, starting fresh");
        serde_json::Map::new()
    };

    // Track changes for summary
    let mut protected_keys_preserved: Vec<String> = Vec::new();
    let mut updated_keys: Vec<String> = Vec::new();
    let mut removed_keys: Vec<String> = Vec::new();

    // 7. Apply update mode
    match req.mode {
        UpdateMode::Reset => {
            // Remove all non-PROTECTED keys
            let keys_to_remove: Vec<String> = current_secrets.keys()
                .filter(|k| !k.starts_with("PROTECTED_"))
                .cloned()
                .collect();

            for key in &keys_to_remove {
                current_secrets.remove(key);
                removed_keys.push(key.clone());
            }

            // Preserve PROTECTED_ keys
            for key in current_secrets.keys() {
                if key.starts_with("PROTECTED_") {
                    protected_keys_preserved.push(key.clone());
                }
            }
        }
        UpdateMode::Append => {
            // Just preserve existing PROTECTED_ keys
            for key in current_secrets.keys() {
                if key.starts_with("PROTECTED_") {
                    protected_keys_preserved.push(key.clone());
                }
            }
        }
    }

    // 8. Add/update user secrets (values are already serde_json::Value)
    for (key, value) in req.secrets {
        current_secrets.insert(key.clone(), value);
        updated_keys.push(key);
    }

    // 9. Generate new PROTECTED_ secrets if requested
    if let Some(generate_specs) = req.generate_protected {
        for spec in generate_specs {
            // Validate name starts with PROTECTED_
            if !spec.name.starts_with("PROTECTED_") {
                return Err(ApiError::BadRequest(format!(
                    "Generated secret '{}' must start with 'PROTECTED_' prefix",
                    spec.name
                )));
            }

            // Check it doesn't already exist (PROTECTED_ are immutable)
            if current_secrets.contains_key(&spec.name) {
                return Err(ApiError::BadRequest(format!(
                    "Cannot regenerate existing PROTECTED_ secret: {}. These secrets are immutable once created.",
                    spec.name
                )));
            }

            // Generate secret
            let directive = format!("generate_outlayer_secret:{}", spec.generation_type);
            let generated_value = crate::secret_generation::generate_secret(&directive)
                .map_err(|e| ApiError::BadRequest(format!(
                    "Failed to generate secret '{}' with type '{}': {}",
                    spec.name, spec.generation_type, e
                )))?;

            tracing::info!(
                key = %spec.name,
                gen_type = %spec.generation_type,
                "Generated PROTECTED_ secret"
            );

            current_secrets.insert(spec.name.clone(), serde_json::Value::String(generated_value));
            updated_keys.push(spec.name);
        }
    }

    // 10. Re-encrypt updated secrets with NEW accessor seed (if migrating)
    let final_secrets_json = serde_json::to_string(&current_secrets)
        .map_err(|e| ApiError::InternalError(format!("Failed to serialize secrets: {}", e)))?;

    // Generate seed for encryption - use new_accessor if provided (migration), otherwise use original accessor
    // Format: normalized_repo:owner[:branch] - same as /pubkey endpoint
    let final_accessor = req.new_accessor.as_ref().unwrap_or(&req.accessor);
    let encryption_seed = match final_accessor {
        SecretAccessor::Repo { repo, branch } => {
            let normalized_repo = repo_seed_root(repo)?;
            if let Some(b) = branch.as_deref().filter(|s| !s.is_empty()) {
                format!("{}:{}:{}", normalized_repo, req.owner, b)
            } else {
                format!("{}:{}", normalized_repo, req.owner)
            }
        }
        SecretAccessor::WasmHash { hash } => {
            format!("wasm_hash:{}:{}", hash, req.owner)
        }
        SecretAccessor::Project { project_id } => {
            format!("project:{}:{}", project_id, req.owner)
        }
        SecretAccessor::System { secret_type } => {
            format!("system:{}:{}:{}", secret_type.as_seed_str(), req.owner, req.profile)
        }
    };

    if is_migration {
        tracing::info!(
            encryption_seed = %encryption_seed,
            "Migration: encrypting with NEW accessor seed"
        );
    }

    let keystore = state.keystore.read().await;
    let encrypted_bytes = keystore
        .encrypt(customer.as_ref(), &encryption_seed, final_secrets_json.as_bytes())
        .map_err(|e| ApiError::InternalError(format!("Failed to encrypt secrets: {}", e)))?;
    drop(keystore);

    let encrypted_base64 = base64::encode(&encrypted_bytes);

    // Prepare summary
    let summary = UpdateSummary {
        protected_keys_preserved,
        updated_keys,
        removed_keys,
        total_keys: current_secrets.len(),
    };

    tracing::info!(
        owner = %req.owner,
        profile = %req.profile,
        total_keys = summary.total_keys,
        protected_preserved = summary.protected_keys_preserved.len(),
        updated = summary.updated_keys.len(),
        removed = summary.removed_keys.len(),
        "Successfully updated user secrets"
    );

    Ok(Json(UpdateUserSecretsResponse {
        encrypted_secrets_base64: encrypted_base64,
        summary,
    }))
}

/// NEP-413 payload structure for Borsh serialization
/// See: https://github.com/near/NEPs/blob/master/neps/nep-0413.md
#[derive(borsh::BorshSerialize)]
struct Nep413Payload {
    /// The message that was requested to be signed
    message: String,
    /// 32-byte nonce
    nonce: [u8; 32],
    /// The recipient to whom the signature is intended for
    recipient: String,
    /// Optional callback URL (always None for our use case)
    callback_url: Option<String>,
}

/// NEP-413 tag: 2^31 + 413
const NEP413_TAG: u32 = 2147484061;

/// The digest NEP-413 has a wallet sign, and the bytes it is a digest of:
/// `SHA256(NEP413_TAG || Borsh(Nep413Payload))`.
fn nep413_digest(message: &str, nonce: &str, recipient: &str) -> Result<([u8; 32], Vec<u8>), anyhow::Error> {
    use sha2::{Digest, Sha256};

    let nonce_bytes = base64::decode(nonce)
        .map_err(|e| anyhow::anyhow!("Failed to decode nonce: {}", e))?;
    let nonce_len = nonce_bytes.len();
    let nonce_array: [u8; 32] = nonce_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid nonce length: {} (expected 32)", nonce_len))?;

    let payload = Nep413Payload {
        message: message.to_string(),
        nonce: nonce_array,
        recipient: recipient.to_string(),
        callback_url: None,
    };
    let payload_bytes = borsh::to_vec(&payload)
        .map_err(|e| anyhow::anyhow!("Failed to serialize NEP-413 payload: {}", e))?;

    let mut tagged = Vec::with_capacity(4 + payload_bytes.len());
    tagged.extend_from_slice(&NEP413_TAG.to_le_bytes());
    tagged.extend_from_slice(&payload_bytes);
    Ok((Sha256::digest(&tagged).into(), tagged))
}

/// Verify a wallet's NEP-413 signature: ed25519, or ml-dsa-65 (FIPS-204).
///
/// The scheme is the public key's own prefix, and only these two are accepted —
/// they are the schemes a NEAR account's access key can be that a wallet signs
/// messages with. Whether the key belongs to the account is a separate question,
/// asked of the chain by the caller; the key string is compared there as it is
/// here, so nothing about ownership depends on the scheme.
///
/// The signature arrives as wallets give it, base64 of the raw bytes, or in
/// NEAR's canonical `<scheme>:<base58>`.
///
/// What is signed is NEP-413's digest. For ml-dsa-65 the tagged payload itself
/// is accepted too: the scheme hashes its input internally, and a signer that
/// therefore skips the outer SHA-256 has bound itself to exactly the same
/// message, nonce and recipient.
fn verify_near_signature(
    message: &str,
    signature: &str,
    public_key: &str,
    nonce: &str,
    recipient: &str,
) -> Result<(), anyhow::Error> {
    use near_crypto::{KeyType, PublicKey, Signature};
    use std::str::FromStr;

    let pk = PublicKey::from_str(public_key).map_err(|e| {
        anyhow::anyhow!("Invalid public key, expected 'ed25519:<base58>' or 'ml-dsa-65:<base58>': {}", e)
    })?;
    let key_type = pk.key_type();
    if !matches!(key_type, KeyType::ED25519 | KeyType::MLDSA65) {
        anyhow::bail!("Public key scheme {} is not accepted here; sign with an ed25519 or ml-dsa-65 key", key_type);
    }

    let sig = if signature.contains(':') {
        Signature::from_str(signature).map_err(|e| anyhow::anyhow!("Failed to parse signature: {}", e))?
    } else {
        let bytes = base64::decode(signature).map_err(|e| anyhow::anyhow!("Failed to decode signature: {}", e))?;
        Signature::from_parts(key_type, &bytes)
            .map_err(|e| anyhow::anyhow!("Invalid {} signature of {} bytes: {}", key_type, bytes.len(), e))?
    };
    let same_scheme = matches!(
        (sig.key_type(), key_type),
        (KeyType::ED25519, KeyType::ED25519) | (KeyType::MLDSA65, KeyType::MLDSA65)
    );
    if !same_scheme {
        anyhow::bail!("The signature is {} and the public key is {}", sig.key_type(), key_type);
    }

    let (digest, tagged) = nep413_digest(message, nonce, recipient)?;

    tracing::debug!(
        message = %message,
        recipient = %recipient,
        key_type = %key_type,
        hash_hex = %hex::encode(digest),
        "NEP-413 signature verification"
    );

    if sig.verify(&digest, &pk) || (matches!(key_type, KeyType::MLDSA65) && sig.verify(&tagged, &pk)) {
        Ok(())
    } else {
        anyhow::bail!("Signature verification failed")
    }
}

/// Validate X-TEE-Session header against in-memory sessions.
/// Returns Ok(()) if session is valid or TEE sessions not required.
/// Returns Err(ApiError::Forbidden) if required but missing/invalid.
/// Extract a per-customer vault id from the `X-Customer-Vault` header.
///
/// **Use case:** every wallet operation
/// names a customer through this header. The coordinator sets the header
/// based on the API key → customer mapping before forwarding the
/// request to keystore-worker. Absent header ⇒ legacy default-master
/// path (existing OutLayer customers without a vault remain on the
/// shared master).
///
/// Returns `Ok(None)` if the header is absent (legacy path) or
/// `Err(ApiError::BadRequest(_))` if the header is present but
/// malformed — we deliberately do NOT silently fall back to default
/// master on a malformed header, otherwise a typo could route a
/// customer's request to the wrong key-space.
pub(crate) fn extract_customer_from_header(
    headers: &axum::http::HeaderMap,
) -> Result<Option<near_primitives::types::AccountId>, ApiError> {
    let Some(raw) = headers.get("X-Customer-Vault") else {
        return Ok(None);
    };
    let s = raw
        .to_str()
        .map_err(|_| ApiError::BadRequest("X-Customer-Vault header is not valid UTF-8".to_string()))?
        .trim();
    if s.is_empty() {
        // Empty header is treated the same as no header (legacy path).
        return Ok(None);
    }
    let vault_id: near_primitives::types::AccountId = s.parse().map_err(|e| {
        ApiError::BadRequest(format!(
            "X-Customer-Vault is not a valid NEAR AccountId ({}): {}",
            s, e
        ))
    })?;
    Ok(Some(vault_id))
}

/// Parse an optional vault id from a string source.
///
/// **Sources** (any caller may use this):
/// 1. JSON request body field `vault_id: Option<String>` —
///    `/pubkey`, `/add_generated_secret`, `/update_user_secrets`
///    carry vault scope inline because it's an attribute of the
///    operation (which secret to encrypt against), not of the
///    caller's session.
/// 2. On-chain side-table value returned by `get_secret_with_vault`
///    — `/decrypt` and `/update_user_secrets` derive the existing
///    secret's scope from chain rather than trusting the caller.
///
/// Same fail-loud-on-malformed semantics as
/// [`extract_customer_from_header`]: empty / whitespace / missing
/// → `Ok(None)` (legacy default-master path); a present-but-malformed
/// value returns `Err(ApiError::BadRequest)` rather than silently
/// downgrading to None — that prevents a typo from routing into
/// the wrong key-space.
fn parse_optional_vault_id(
    raw: Option<&str>,
) -> Result<Option<near_primitives::types::AccountId>, ApiError> {
    let Some(s) = raw.map(|s| s.trim()).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let vault_id: near_primitives::types::AccountId = s.parse().map_err(|e| {
        ApiError::BadRequest(format!(
            "vault_id is not a valid NEAR AccountId ({}): {}",
            s, e
        ))
    })?;
    Ok(Some(vault_id))
}

/// Validate the session and return the worker public key it was registered with.
///
/// The key is what makes a decrypt attributable to a specific worker instance. Before the
/// vestigial `attestation` field was removed the log line carried `tee_type` — a self-reported
/// constant that identified nothing — so this is the first time the record names the caller.
fn validate_tee_session(
    state: &AppState,
    headers: &axum::http::HeaderMap,
) -> Result<Option<String>, ApiError> {
    if state.config.tee_mode == crate::config::TeeMode::None {
        return Ok(None);
    }

    let session_header = headers
        .get("X-TEE-Session")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            ApiError::Forbidden("TEE session required. Register via /tee-challenge + /register-tee".to_string())
        })?;

    let session_id = uuid::Uuid::parse_str(session_header)
        .map_err(|_| ApiError::Forbidden("Invalid TEE session ID format".to_string()))?;

    let sessions = state.tee_sessions.lock().unwrap();
    match sessions.get(&session_id) {
        Some(session) => Ok(Some(session.worker_public_key.clone())),
        None => Err(ApiError::Forbidden(
            "TEE session not found or expired".to_string(),
        )),
    }
}

/// TEE session middleware
///
/// Checks X-TEE-Session header against in-memory sessions.
/// Only enforced when TEE_MODE=outlayer_tee (skipped in none mode).
/// Runs after worker_auth_middleware (inner layer) on worker-only routes.
async fn tee_session_middleware(
    State(state): State<AppState>,
    mut req: axum::http::Request<axum::body::Body>,
    next: middleware::Next,
) -> Result<Response, ApiError> {
    // Hand the validated worker identity to the handlers so a decrypt can be attributed to the
    // instance that asked for it — the only worker identifier the keystore can trust.
    if let Some(worker_public_key) = validate_tee_session(&state, req.headers())? {
        req.extensions_mut().insert(WorkerIdentity(worker_public_key));
    }
    Ok(next.run(req).await)
}

/// Worker public key taken from a validated TEE session, injected by
/// [`tee_session_middleware`] for logging.
#[derive(Clone)]
pub struct WorkerIdentity(pub String);

/// Worker authentication middleware
///
/// For TEE worker-only endpoints: /decrypt, /encrypt, /decrypt-raw, /storage/*
/// Checks Bearer token against ALLOWED_WORKER_TOKEN_HASHES.
async fn worker_auth_middleware(
    State(state): State<AppState>,
    req: axum::http::Request<axum::body::Body>,
    next: middleware::Next,
) -> Result<Response, ApiError> {
    // Get Authorization header
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            tracing::warn!("Missing Authorization header in worker request");
            ApiError::Unauthorized("Missing Authorization header".to_string())
        })?;

    // Extract Bearer token
    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| {
            tracing::warn!("Invalid Authorization format (expected 'Bearer <token>')");
            ApiError::Unauthorized("Invalid Authorization format".to_string())
        })?;

    // Hash token with SHA256
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let token_hash = hex::encode(hasher.finalize());

    // Check if hash is in allowed WORKER list (constant-time — see token_hash_allowed_ct)
    if !token_hash_allowed_ct(&state.config.allowed_worker_token_hashes, &token_hash) {
        tracing::warn!(
            token_hash = %token_hash,
            "Unauthorized: token hash not in worker allowed list"
        );
        return Err(ApiError::Unauthorized("Invalid worker token".to_string()));
    }

    // Find which worker this token belongs to (for logging)
    let worker_index = state.config.allowed_worker_token_hashes
        .iter()
        .position(|h| h == &token_hash)
        .unwrap_or(0);

    tracing::debug!(
        token_hash = %token_hash,
        worker_index = worker_index,
        "✅ Worker authenticated successfully"
    );

    Ok(next.run(req).await)
}

/// Coordinator authentication middleware
///
/// For coordinator-only endpoints: /add_generated_secret, /update_user_secrets
/// Checks Bearer token against ALLOWED_COORDINATOR_TOKEN_HASHES.
async fn coordinator_auth_middleware(
    State(state): State<AppState>,
    req: axum::http::Request<axum::body::Body>,
    next: middleware::Next,
) -> Result<Response, ApiError> {
    // Get Authorization header
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            tracing::warn!("Missing Authorization header in coordinator request");
            ApiError::Unauthorized("Missing Authorization header".to_string())
        })?;

    // Extract Bearer token
    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| {
            tracing::warn!("Invalid Authorization format (expected 'Bearer <token>')");
            ApiError::Unauthorized("Invalid Authorization format".to_string())
        })?;

    // Hash token with SHA256
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let token_hash = hex::encode(hasher.finalize());

    // Check if hash is in allowed COORDINATOR list
    if !state.config.allowed_coordinator_token_hashes.contains(&token_hash) {
        tracing::warn!(
            token_hash = %token_hash,
            "Unauthorized: token hash not in coordinator allowed list"
        );
        return Err(ApiError::Unauthorized("Invalid coordinator token".to_string()));
    }

    tracing::debug!(
        token_hash = %token_hash,
        "✅ Coordinator authenticated successfully"
    );

    Ok(next.run(req).await)
}

/// Auth for READ-ONLY admin endpoints: accepts a worker OR a coordinator token.
///
/// Deliberately separate from `worker_auth_middleware`, which guards the MUTATING admin routes
/// (`/admin/evict-customer` drops a vault master and makes that vault pay for a fresh CKD
/// derivation). Those stay worker-only.
///
/// The coordinator is admitted here so it can surface fleet state in its own `/health/detailed`,
/// which the monitoring collector already relays. The alternative — giving the collector a worker
/// token and the keystore's URL — would put a mutation-capable credential in the monitoring stack
/// and undo the deliberate choice in `keystore_probe.rs` to keep the keystore's address out of it.
/// Reading which vaults are loaded tells the coordinator nothing it does not already know: it is
/// the party sending the traffic that loads them.
async fn admin_read_auth_middleware(
    State(state): State<AppState>,
    req: axum::http::Request<axum::body::Body>,
    next: middleware::Next,
) -> Result<Response, ApiError> {
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            tracing::warn!("Missing Authorization header in admin read request");
            ApiError::Unauthorized("Missing Authorization header".to_string())
        })?;

    let token = auth_header.strip_prefix("Bearer ").ok_or_else(|| {
        tracing::warn!("Invalid Authorization format (expected 'Bearer <token>')");
        ApiError::Unauthorized("Invalid Authorization format".to_string())
    })?;

    use sha2::{Digest, Sha256};
    let token_hash = hex::encode(Sha256::digest(token.as_bytes()));

    // Constant-time membership, same as the worker path — an admin endpoint is no place to leak
    // a token prefix through timing.
    let worker_ok = token_hash_allowed_ct(&state.config.allowed_worker_token_hashes, &token_hash);
    let coordinator_ok =
        token_hash_allowed_ct(&state.config.allowed_coordinator_token_hashes, &token_hash);
    if !worker_ok && !coordinator_ok {
        tracing::warn!(token_hash = %token_hash, "Unauthorized: token in neither allowed list");
        return Err(ApiError::Unauthorized("Invalid token".to_string()));
    }

    Ok(next.run(req).await)
}

/// TEE registration authentication middleware
///
/// For TEE session endpoints: /tee-challenge, /register-tee
/// Accepts EITHER coordinator OR worker token (so workers can register directly).
async fn tee_registration_auth_middleware(
    State(state): State<AppState>,
    req: axum::http::Request<axum::body::Body>,
    next: middleware::Next,
) -> Result<Response, ApiError> {
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            tracing::warn!("Missing Authorization header in TEE registration request");
            ApiError::Unauthorized("Missing Authorization header".to_string())
        })?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| {
            tracing::warn!("Invalid Authorization format (expected 'Bearer <token>')");
            ApiError::Unauthorized("Invalid Authorization format".to_string())
        })?;

    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let token_hash = hex::encode(hasher.finalize());

    let is_coordinator = state.config.allowed_coordinator_token_hashes.contains(&token_hash);
    let is_worker = state.config.allowed_worker_token_hashes.contains(&token_hash);

    if !is_coordinator && !is_worker {
        tracing::warn!(
            token_hash = %token_hash,
            "Unauthorized: token hash not in coordinator or worker allowed list"
        );
        return Err(ApiError::Unauthorized("Invalid token".to_string()));
    }

    let source = if is_coordinator { "coordinator" } else { "worker" };
    tracing::debug!(
        token_hash = %token_hash,
        source = source,
        "✅ TEE registration authenticated ({})", source
    );

    Ok(next.run(req).await)
}

// Base64 encoding/decoding helpers
mod base64 {
    use ::base64::Engine;
    use ::base64::engine::general_purpose::STANDARD;

    pub fn encode<T: AsRef<[u8]>>(input: T) -> String {
        STANDARD.encode(input)
    }

    pub fn decode<T: AsRef<[u8]>>(input: T) -> Result<Vec<u8>, ::base64::DecodeError> {
        STANDARD.decode(input)
    }
}

// ==================== Wallet Handlers ====================

// `is_evm_chain` is the single source of truth in `shared_tee_helpers` (shared
// with the coordinator so the two can't drift); imported at the top of this file.

/// Build the keystore derivation seed for `(wallet_id, chain)`.
///
/// **All EVM chains share ONE secp256k1 key** — a single `0x` address
/// across every EVM network, the standard EVM model — so every EVM
/// chain maps to one canonical `:evm` seed suffix regardless of which
/// network was requested. Non-EVM chains keep their own per-chain
/// suffix (`:near`, `:solana`, …). Changing this suffix rotates every
/// derived EVM address — see the domain-separation note on
/// `Keystore::derive_secp256k1_keypair`.
pub(crate) fn wallet_seed(wallet_id: &str, chain: &str) -> String {
    wallet_seed_impl(wallet_id, chain)
}

fn wallet_seed_impl(wallet_id: &str, chain: &str) -> String {
    if is_evm_chain(chain) {
        format!("wallet:{}:evm", wallet_id)
    } else if is_solana_chain(chain) {
        // Canonicalize the `sol` alias — both spellings must derive the ONE
        // Solana key (`wallet:{id}:sol` would silently be a different key).
        format!("wallet:{}:solana", wallet_id)
    } else {
        format!("wallet:{}:{}", wallet_id, chain)
    }
}

/// A wallet id may not contain `:`.
///
/// Every seed is `root:{wallet_id}:…` with `:` as the segment separator, so a
/// wallet id carrying one would shift every segment after it: wallet `a:evm`'s
/// NEAR key (`wallet:a:evm:near`) would be the string the ephemeral exporter
/// builds for `(a, evm, near)`. The coordinator only ever sends UUIDs; this is
/// the keystore's own refusal, so the invariant does not rest on a caller.
/// Applied at the top of every handler that takes a `wallet_id`, signing and
/// exporting alike, so no seed of any family is ever built from an id that
/// could shift it.
pub(crate) fn validate_wallet_id(wallet_id: &str) -> Result<(), ApiError> {
    if wallet_id.is_empty() || wallet_id.contains(':') {
        return Err(ApiError::BadRequest(
            "wallet_id must be non-empty and must not contain ':'".to_string(),
        ));
    }
    Ok(())
}

/// Seed of a wallet's EVM **sub-key**: `subkey:{id}:evm:{sub_path}`.
///
/// A sub-key is a distinct secp256k1 key, and so a distinct address, under the
/// same wallet's ONE authority: the wallet's policy governs every sub-key, and
/// whoever holds the wallet's authority can sign for any path. What a path
/// buys is separation of balances — a connector's trading key and its bridge
/// key are different addresses, and neither is the wallet's own
/// (`wallet:{id}:evm`). Which path an integration may use is decided by
/// whoever forwards it (an API-key holder for their own wallet; for a
/// connector, the worker, from the connector's verified manifest); the
/// keystore guarantees only that different paths are different keys.
///
/// Its own root, `subkey:`, rather than a level under `wallet:`, is the whole
/// security argument. Every seed this keystore will hand a PRIVATE key for
/// (`/wallet/derive-ephemeral-key`, payment checks) has the shape
/// `wallet:{id}:{chain}:{sub_path}` built from request strings; a sub-key seed
/// under `wallet:` would be one of the strings that endpoint can spell, and
/// with `derive_keypair` and `derive_secp256k1_keypair` feeding the same HMAC
/// input, the bytes it returned WOULD BE the sub-key's scalar. A different root
/// makes that impossible by construction instead of by a check — see
/// `README.md` § "Adding a key family".
pub(crate) fn subkey_seed(wallet_id: &str, sub_path: &str) -> String {
    format!("subkey:{}:evm:{}", wallet_id, sub_path)
}

/// The one shape a `sub_path` may have — `shared_tee_helpers::is_valid_sub_path`,
/// shared with the coordinator so the two cannot drift.
///
/// Absent or empty means "the wallet's own key" and comes back as `None`.
/// Anything else is refused rather than normalised: a path is part of a key's
/// identity, and two spellings that derived the same key — or a spelling that
/// derived a different one than the caller wrote — would both be silent.
pub(crate) fn validate_sub_path(raw: Option<&str>) -> Result<Option<&str>, ApiError> {
    let Some(p) = raw.filter(|p| !p.is_empty()) else {
        return Ok(None);
    };
    if !shared_tee_helpers::is_valid_sub_path(p) {
        return Err(ApiError::BadRequest(
            "sub_path must match [a-z0-9][a-z0-9._-]{0,63}".to_string(),
        ));
    }
    Ok(Some(p))
}

/// Derive a wallet address for a specific chain
///
/// Seed format: see [`wallet_seed`] — EVM chains collapse to one
/// `wallet:{wallet_id}:evm` key; non-EVM use `wallet:{wallet_id}:{chain}`.
/// - near/solana: Ed25519 keypair → implicit account (hex-encoded public key)
/// - EVM: secp256k1 keypair → keccak256 → address (0x-prefixed), same across all EVM chains
async fn wallet_derive_address_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<WalletDeriveAddressRequest>,
) -> Result<Json<WalletDeriveAddressResponse>, ApiError> {
    if !state.is_ready() {
        return Err(ApiError::Unauthorized(
            "Keystore not ready. Waiting for DAO approval and master key from MPC.".to_string(),
        ));
    }

    // Route to per-customer master if X-Customer-Vault is set.
    let customer = extract_customer_from_header(&headers)?;
    state
        .ensure_customer_loaded(customer.as_ref())
        .await
        // Underfunded vault → 402 with an actionable top-up message; anything
        // else → 400 carrying the full anyhow chain (real `InvalidTxError`).
        .map_err(ApiError::from_customer_load)?;

    validate_wallet_id(&req.wallet_id)?;
    let chain = req.chain.to_lowercase();
    let sub_path = validate_sub_path(req.sub_path.as_deref())?;
    if sub_path.is_some() && !is_evm_chain(&chain) {
        return Err(ApiError::BadRequest(
            "sub_path is supported for EVM chains only".to_string(),
        ));
    }
    let seed = match sub_path {
        Some(p) => subkey_seed(&req.wallet_id, p),
        None => wallet_seed_impl(&req.wallet_id, &chain),
    };

    let keystore = state.keystore.read().await;

    match chain.as_str() {
        "near" => {
            let (_, verifying_key) = keystore.derive_keypair(customer.as_ref(), &seed).map_err(|e| {
                ApiError::InternalError(format!("Key derivation failed: {}", e))
            })?;
            // Both fields use HEX-encoded ed25519 pubkey. This is
            // intentional, NOT a bug. The OutLayer contract
            // `wallet_policies` map keys are `ed25519:<hex>` (see
            // contract/src/wallet.rs::parse_wallet_pubkey, which calls
            // `hex::decode` and panics on anything else). Returning
            // base58 here would diverge from `/wallet/sign-policy` (also
            // hex) and break the round-trip into `store_wallet_policy`.
            //
            // For NEAR-canonical `ed25519:<base58>` (signatures, AddKey,
            // SDK consumers), use `/wallet/sign-nep413` or
            // `/derive-vault-tee-key` — those emit base58 because they
            // feed NEAR-protocol-level parsers.
            let pubkey_hex = hex::encode(verifying_key.as_bytes());
            Ok(Json(WalletDeriveAddressResponse {
                address: pubkey_hex.clone(),
                public_key: format!("ed25519:{}", pubkey_hex),
            }))
        }
        _ if is_solana_chain(&chain) => {
            let (_, verifying_key) = keystore.derive_keypair(customer.as_ref(), &seed).map_err(|e| {
                ApiError::InternalError(format!("Key derivation failed: {}", e))
            })?;
            let pubkey_bytes = verifying_key.as_bytes();
            let address = bs58::encode(pubkey_bytes).into_string();
            Ok(Json(WalletDeriveAddressResponse {
                address: address.clone(),
                public_key: address,
            }))
        }
        // EVM chains — secp256k1. All EVM networks share ONE address
        // (one secp256k1 key via the canonical `:evm` seed). See
        // `wallet_seed` / docs/MULTI_CHAIN.md.
        _ if is_evm_chain(&chain) => {
            let (address, pubkey_hex) = keystore.derive_eth_address(customer.as_ref(), &seed).map_err(|e| {
                ApiError::InternalError(format!("Key derivation failed: {}", e))
            })?;
            Ok(Json(WalletDeriveAddressResponse {
                address,
                public_key: format!("secp256k1:{}", pubkey_hex),
            }))
        }
        _ => Err(ApiError::BadRequest(format!(
            "Unsupported chain: {}. Supported: near, solana, and EVM (ethereum, polygon, base, arbitrum, optimism, bsc, avalanche, hyperevm, hood)",
            chain
        ))),
    }
}

/// Shared EVM-signing path: validate the chain, gate on the `evm_sign`
/// capability, then sign an **already-computed 32-byte keccak digest** with the
/// wallet's canonical EVM key — or, given a `sub_path`, with that sub-key of
/// it (see [`subkey_seed`]). The policy decision is the wallet's and does
/// not depend on the path: a sub-key is the same wallet's authority over a
/// separate balance, not a separate authority. `want_raw_tx` is `false` for
/// typed-data and personal_sign, which ride the base `evm_sign` capability;
/// raw-transaction signing passes `true` (gated by `evm_sign.raw_tx`).
async fn evm_sign_digest(
    state: &AppState,
    customer: Option<&near_primitives::types::AccountId>,
    wallet_id: &str,
    chain: &str,
    sub_path: Option<&str>,
    digest: &[u8; 32],
    want_raw_tx: bool,
) -> Result<String, ApiError> {
    use shared_tee_helpers::wallet_policy::{evm_sign_decision, Decision};

    validate_wallet_id(wallet_id)?;
    if !is_evm_chain(chain) {
        return Err(ApiError::BadRequest(format!(
            "'{}' is not an EVM chain (supported: ethereum, polygon, base, arbitrum, optimism, bsc, avalanche, hyperevm, hood)",
            chain
        )));
    }

    let policy = load_wallet_policy(state, wallet_id, customer).await?;
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    match evm_sign_decision(policy.as_ref(), want_raw_tx, now_unix) {
        Decision::Allow => {}
        Decision::Frozen => return Err(ApiError::Forbidden("Wallet is frozen".to_string())),
        Decision::Deny { reason } => return Err(ApiError::Forbidden(reason)),
        Decision::RequiresApproval { .. } => {
            return Err(ApiError::Forbidden(
                "EVM signing does not support per-op approval".to_string(),
            ))
        }
    }

    let seed = match sub_path {
        Some(p) => subkey_seed(wallet_id, p),
        None => wallet_seed_impl(wallet_id, chain),
    };
    let keystore = state.keystore.read().await;
    let sig = keystore
        .sign_secp256k1_prehash(customer, &seed, digest)
        .map_err(|e| ApiError::InternalError(format!("EVM signing failed: {}", e)))?;
    Ok(format!("0x{}", hex::encode(sig)))
}

/// `POST /wallet/evm/sign-typed-data` — EIP-712 v4 typed-data signature.
///
/// The digest is computed server-side from the full typed-data object (we do
/// NOT trust a client-supplied hash). `ecrecover` over it returns the address
/// from `/wallet/derive-address` for the same `(wallet_id, evm, sub_path)`.
async fn wallet_evm_sign_typed_data_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<WalletEvmSignTypedDataRequest>,
) -> Result<Json<WalletEvmSignResponse>, ApiError> {
    if !state.is_ready() {
        return Err(ApiError::Unauthorized("Keystore not ready.".to_string()));
    }
    let customer = extract_customer_from_header(&headers)?;
    state
        .ensure_customer_loaded(customer.as_ref())
        .await
        .map_err(ApiError::from_customer_load)?;

    let sub_path = validate_sub_path(req.sub_path.as_deref())?;
    let digest = crate::eip712::eip712_digest(&req.typed_data)
        .map_err(|e| ApiError::BadRequest(format!("Invalid EIP-712 typed data: {:#}", e)))?;

    let signature = evm_sign_digest(
        &state,
        customer.as_ref(),
        &req.wallet_id,
        &req.chain.to_lowercase(),
        sub_path,
        &digest,
        false,
    )
    .await?;
    Ok(Json(WalletEvmSignResponse { signature }))
}

/// `POST /wallet/evm/sign-message` — EIP-191 `personal_sign` signature.
async fn wallet_evm_sign_message_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<WalletEvmSignMessageRequest>,
) -> Result<Json<WalletEvmSignResponse>, ApiError> {
    if !state.is_ready() {
        return Err(ApiError::Unauthorized("Keystore not ready.".to_string()));
    }
    let customer = extract_customer_from_header(&headers)?;
    state
        .ensure_customer_loaded(customer.as_ref())
        .await
        .map_err(ApiError::from_customer_load)?;

    // Explicit encoding — no content sniffing. "utf8" (default) signs the
    // UTF-8 bytes; "hex" treats `message` as hex and signs the decoded bytes.
    let hex = match req.encoding.as_deref() {
        None | Some("utf8") => false,
        Some("hex") => true,
        Some(other) => {
            return Err(ApiError::BadRequest(format!(
                "invalid encoding '{}' (use 'utf8' or 'hex')",
                other
            )))
        }
    };
    let sub_path = validate_sub_path(req.sub_path.as_deref())?;
    let digest = crate::eip712::eip191_digest_for(&req.message, hex)
        .map_err(|e| ApiError::BadRequest(format!("Invalid message: {:#}", e)))?;

    let signature = evm_sign_digest(
        &state,
        customer.as_ref(),
        &req.wallet_id,
        &req.chain.to_lowercase(),
        sub_path,
        &digest,
        false,
    )
    .await?;
    Ok(Json(WalletEvmSignResponse { signature }))
}

/// `POST /wallet/evm/sign-transaction` — sign a raw EVM transaction.
///
/// Gated by the `evm_sign.raw_tx` sub-capability (default-OFF). The caller sends
/// the serialized unsigned transaction; we keccak256 it and return the
/// recoverable signature. For an EIP-1559 (type-2) tx the `yParity` the caller
/// needs to assemble the final tx is `v - 27`. The caller assembles the signed
/// tx and broadcasts — the keystore neither builds the tx nor broadcasts.
async fn wallet_evm_sign_transaction_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<WalletEvmSignTransactionRequest>,
) -> Result<Json<WalletEvmSignResponse>, ApiError> {
    if !state.is_ready() {
        return Err(ApiError::Unauthorized("Keystore not ready.".to_string()));
    }
    let customer = extract_customer_from_header(&headers)?;
    state
        .ensure_customer_loaded(customer.as_ref())
        .await
        .map_err(ApiError::from_customer_load)?;

    // Decode the serialized unsigned tx and compute its keccak256 signing hash.
    // We do NOT parse or assemble the transaction — only hash the supplied bytes.
    let hex_body = req
        .unsigned_tx
        .strip_prefix("0x")
        .or_else(|| req.unsigned_tx.strip_prefix("0X"))
        .unwrap_or(&req.unsigned_tx);
    let tx_bytes = hex::decode(hex_body)
        .map_err(|e| ApiError::BadRequest(format!("Invalid unsigned_tx hex: {}", e)))?;
    if tx_bytes.is_empty() {
        return Err(ApiError::BadRequest("unsigned_tx is empty".to_string()));
    }
    let digest: [u8; 32] = {
        use sha3::{Digest as _, Keccak256};
        let mut d = [0u8; 32];
        d.copy_from_slice(&Keccak256::digest(&tx_bytes));
        d
    };

    let sub_path = validate_sub_path(req.sub_path.as_deref())?;
    let signature = evm_sign_digest(
        &state,
        customer.as_ref(),
        &req.wallet_id,
        &req.chain.to_lowercase(),
        sub_path,
        &digest,
        true,
    )
    .await?;
    Ok(Json(WalletEvmSignResponse { signature }))
}

/// Shared Solana-signing path: validate the chain, gate on the `solana_sign`
/// capability, then ed25519-sign the supplied bytes with the wallet's Solana
/// key. Solana has no digest step — the signature covers the raw message
/// bytes — so "sign the supplied bytes" is the correct primitive (unlike EVM,
/// where we keccak-hash first). `want_raw_tx` distinguishes transaction
/// signing (gated by `solana_sign.raw_tx`, default-OFF) from message signing
/// (base capability).
///
/// The message/transaction guard is enforced HERE, not in the handlers: any
/// `want_raw_tx == false` call refuses bytes that parse as a valid Solana
/// transaction message, so no future caller can accidentally open a
/// `raw_tx`-bypass through a message-signing path.
async fn solana_sign_bytes(
    state: &AppState,
    customer: Option<&near_primitives::types::AccountId>,
    wallet_id: &str,
    chain: &str,
    bytes: &[u8],
    want_raw_tx: bool,
) -> Result<String, ApiError> {
    use shared_tee_helpers::wallet_policy::{solana_sign_decision, Decision};

    validate_wallet_id(wallet_id)?;
    if !is_solana_chain(chain) {
        return Err(ApiError::BadRequest(format!(
            "'{}' is not a Solana chain (supported: solana)",
            chain
        )));
    }

    // Message signing must not be usable as transaction signing: Solana has no
    // EIP-191-style prefix separating the two, so a "message" that IS a valid
    // tx message would bypass the `solana_sign.raw_tx` sub-flag. Cheap (no
    // RPC), so it runs before the policy load.
    if !want_raw_tx && crate::solana::parses_as_transaction_message(bytes) {
        return Err(ApiError::BadRequest(
            "message parses as a Solana transaction message — use \
             /wallet/solana/sign-transaction (requires the solana_sign.raw_tx capability)"
                .to_string(),
        ));
    }

    let policy = load_wallet_policy(state, wallet_id, customer).await?;
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    match solana_sign_decision(policy.as_ref(), want_raw_tx, now_unix) {
        Decision::Allow => {}
        Decision::Frozen => return Err(ApiError::Forbidden("Wallet is frozen".to_string())),
        Decision::Deny { reason } => return Err(ApiError::Forbidden(reason)),
        Decision::RequiresApproval { .. } => {
            return Err(ApiError::Forbidden(
                "Solana signing does not support per-op approval".to_string(),
            ))
        }
    }

    let seed = wallet_seed(wallet_id, chain);
    let keystore = state.keystore.read().await;
    let sig = keystore
        .sign(customer, &seed, bytes)
        .map_err(|e| ApiError::InternalError(format!("Solana signing failed: {}", e)))?;
    Ok(bs58::encode(sig.to_bytes()).into_string())
}

/// `POST /wallet/solana/sign-message` — ed25519 signature over raw message bytes.
///
/// Signs exactly the decoded bytes (verifiable with standard tooling, e.g.
/// `nacl.sign.detached.verify` — Sign-in-with-Solana flows work unchanged).
/// Bytes that parse as a valid Solana **transaction message** are rejected:
/// Solana has no EIP-191-style prefix separating the two, so without this
/// guard a "message" could be a broadcastable transaction and bypass the
/// `solana_sign.raw_tx` sub-flag (same protection Phantom/Solflare apply).
async fn wallet_solana_sign_message_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<WalletSolanaSignMessageRequest>,
) -> Result<Json<WalletSolanaSignResponse>, ApiError> {
    if !state.is_ready() {
        return Err(ApiError::Unauthorized("Keystore not ready.".to_string()));
    }
    let customer = extract_customer_from_header(&headers)?;
    state
        .ensure_customer_loaded(customer.as_ref())
        .await
        .map_err(ApiError::from_customer_load)?;

    // Explicit encoding — no content sniffing (same rule as EVM sign-message).
    let bytes = match req.encoding.as_deref() {
        None | Some("utf8") => req.message.as_bytes().to_vec(),
        Some("hex") => {
            let body = req
                .message
                .strip_prefix("0x")
                .or_else(|| req.message.strip_prefix("0X"))
                .unwrap_or(&req.message);
            if body.len() % 2 == 1 {
                return Err(ApiError::BadRequest("odd-length hex message".to_string()));
            }
            hex::decode(body)
                .map_err(|e| ApiError::BadRequest(format!("Invalid hex message: {}", e)))?
        }
        Some("base64") => base64::decode(&req.message)
            .map_err(|e| ApiError::BadRequest(format!("Invalid base64 message: {}", e)))?,
        Some(other) => {
            return Err(ApiError::BadRequest(format!(
                "invalid encoding '{}' (use 'utf8', 'hex' or 'base64')",
                other
            )))
        }
    };
    if bytes.is_empty() {
        return Err(ApiError::BadRequest("message is empty".to_string()));
    }
    if bytes.len() > crate::solana::MAX_MESSAGE_LEN {
        return Err(ApiError::BadRequest(format!(
            "message exceeds {} bytes",
            crate::solana::MAX_MESSAGE_LEN
        )));
    }
    // The message-vs-transaction guard is enforced inside `solana_sign_bytes`
    // (want_raw_tx = false), not here — see its doc comment.

    let signature = solana_sign_bytes(
        &state,
        customer.as_ref(),
        &req.wallet_id,
        &req.chain.to_lowercase(),
        &bytes,
        false,
    )
    .await?;
    Ok(Json(WalletSolanaSignResponse { signature }))
}

/// `POST /wallet/solana/sign-transaction` — sign a Solana transaction message.
///
/// Gated by the `solana_sign.raw_tx` sub-capability (default-OFF). The caller
/// sends the serialized unsigned transaction **message** (base64 — what the
/// signature covers: web3.js `tx.serializeMessage()`); we ed25519-sign the
/// bytes as-is and return the base58 signature. The caller assembles the
/// signed transaction (`compact-u16 sig count ‖ signatures ‖ message`) and
/// broadcasts — the keystore neither builds the tx nor broadcasts.
async fn wallet_solana_sign_transaction_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<WalletSolanaSignTransactionRequest>,
) -> Result<Json<WalletSolanaSignResponse>, ApiError> {
    if !state.is_ready() {
        return Err(ApiError::Unauthorized("Keystore not ready.".to_string()));
    }
    let customer = extract_customer_from_header(&headers)?;
    state
        .ensure_customer_loaded(customer.as_ref())
        .await
        .map_err(ApiError::from_customer_load)?;

    let tx_bytes = base64::decode(&req.unsigned_tx)
        .map_err(|e| ApiError::BadRequest(format!("Invalid unsigned_tx base64: {}", e)))?;
    if tx_bytes.is_empty() {
        return Err(ApiError::BadRequest("unsigned_tx is empty".to_string()));
    }
    // Anything larger than a network packet can never be broadcast.
    if tx_bytes.len() > crate::solana::MAX_TX_MESSAGE_LEN {
        return Err(ApiError::BadRequest(format!(
            "unsigned_tx exceeds {} bytes (Solana packet limit)",
            crate::solana::MAX_TX_MESSAGE_LEN
        )));
    }

    let signature = solana_sign_bytes(
        &state,
        customer.as_ref(),
        &req.wallet_id,
        &req.chain.to_lowercase(),
        &tx_bytes,
        true,
    )
    .await?;
    Ok(Json(WalletSolanaSignResponse { signature }))
}

/// What an agent's secret is stored against: a project, or one exact WASM.
///
/// Two facts hang off this choice and they must agree, which is why it is one
/// type rather than two parameters passed around separately:
///
/// * the SEED the secret is sealed to, which the read path rebuilds when the
///   worker asks for a decryption. Those strings are not invented here — they
///   are the ones `/decrypt` and `/get-or-create-secrets` already use, and
///   `the_agent_seeds_match_the_read_path` pins them against those call sites.
/// * the ACCESSOR BINDING inside the signed message, which the contract
///   rebuilds from its own `SecretAccessor`. `wasm:` there is the contract's
///   spelling and is deliberately NOT the seed's `wasm_hash:` — two different
///   strings for two different jobs, each pinned to the side that reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentSecretTarget {
    Project(String),
    WasmHash(String),
}

impl AgentSecretTarget {
    /// Exactly one of the two, or an error saying which.
    ///
    /// Neither is not a default: a secret sealed to the wrong scope is
    /// unreadable by the code meant to read it, and picking one silently is how
    /// that happens.
    pub fn from_fields(
        project_id: Option<&str>,
        wasm_hash: Option<&str>,
    ) -> Result<Self, ApiError> {
        let project = project_id.map(str::trim).filter(|s| !s.is_empty());
        let hash = wasm_hash.map(str::trim).filter(|s| !s.is_empty());

        match (project, hash) {
            (Some(_), Some(_)) => Err(ApiError::BadRequest(
                "Give either project_id or wasm_hash, not both — a secret is sealed to \
                 one scope and the two seal it differently."
                    .to_string(),
            )),
            (Some(p), None) => Ok(Self::Project(p.to_string())),
            // LOWER CASE, because hex has two spellings and the contract stores
            // exactly one: `canonical_accessor` lowercases it before the
            // accessor becomes a storage key. Sealing to the shouted spelling
            // would produce a secret whose seed nothing rebuilds — the worker
            // reads the accessor back FROM THE CHAIN, so it asks in lower case.
            (None, Some(h)) => Ok(Self::WasmHash(h.to_lowercase())),
            (None, None) => Err(ApiError::BadRequest(
                "project_id or wasm_hash is required: a secret is stored against the \
                 connector's project or against one exact WASM hash."
                    .to_string(),
            )),
        }
    }

    /// The seed the secret is sealed to, for this agent.
    ///
    /// The agent's account plays all three roles — owner, name and seed
    /// material — so there is no second value here to get wrong.
    pub fn seed(&self, agent_account: &str) -> String {
        match self {
            Self::Project(project_id) => format!("project:{}:{}", project_id, agent_account),
            Self::WasmHash(hash) => format!("wasm_hash:{}:{}", hash, agent_account),
        }
    }

    /// The accessor as it appears INSIDE the signed message, matching the
    /// contract's `accessor_binding`.
    pub fn binding(&self) -> String {
        match self {
            Self::Project(project_id) => project_id.clone(),
            Self::WasmHash(hash) => format!("wasm:{}", hash),
        }
    }

    /// For a log line: what this secret is stored against.
    pub fn describe(&self) -> String {
        match self {
            Self::Project(project_id) => format!("project {}", project_id),
            Self::WasmHash(hash) => format!("wasm {}", hash),
        }
    }
}

/// The exact string the contract rebuilds and verifies in `store_agent_secret`.
///
/// **The leading domain is what makes this unforgeable as a transaction.** The
/// wallet's NEAR key signs `sha256(borsh(tx))`, and borsh starts a transaction
/// with the u32 length of `signer_id` — so a preimage beginning with these ASCII
/// bytes reads as a length of about 1.9 billion against a 64-byte maximum. No
/// transaction can look like this, which is why assembling the message HERE,
/// from typed fields, is a structural guarantee and not a probabilistic one.
///
/// Byte-for-byte identical to the contract's `format!` — the signature is
/// verified against a string rebuilt there, so a change on one side alone
/// produces signatures nothing will accept.
fn secret_store_message(
    wallet_pubkey: &str,
    accessor_binding: &str,
    profile: &str,
    encrypted_secrets_base64: &str,
    payer: &str,
    vault_id: &str,
    access_json: &str,
) -> String {
    // The accessor is LENGTH-PREFIXED, and `AgentSecretTarget::binding` is what
    // this endpoint renders one from — the contract writes the same, from
    // `accessor_binding(…)`: a project id verbatim, a WASM hash behind `wasm:`.
    //
    // The length is what lets the field hold colons: its end is pinned by
    // arithmetic rather than by the next delimiter, so two different accessors
    // can no longer produce one string. The domain stays `v1`: the prefix
    // arrived before anyone was signing with this endpoint, so there is no
    // older format to tell apart. What it does mean is that this signer and the
    // contract must ship TOGETHER — the signature is checked against a string
    // the CONTRACT rebuilds, so a version of one that predates the prefix
    // produces signatures the other rejects outright.
    format!(
        "store_secrets_for:v1:{}:{}:{}:{}:{}:{}:{}:{}",
        wallet_pubkey,
        accessor_binding.len(),
        accessor_binding,
        profile,
        encrypted_secrets_base64,
        payer,
        vault_id,
        access_json
    )
}

/// The exact string the contract rebuilds and verifies in `store_wallet_policy`.
///
/// Byte-for-byte the contract's `policy_store_message`. The blob is
/// length-prefixed so it may hold anything, and the caller is last so a
/// signature authorises one account to file this policy and nobody else.
///
/// Both parts are load-bearing. Without the DOMAIN, any signature this wallet
/// has ever produced — and they are public, in the arguments of every
/// `store_agent_secret` transaction — could be filed here as a policy blob,
/// making a stranger the controller of somebody else's policy slot. Without the
/// CALLER, a genuine policy signature could be lifted and replayed by whoever
/// saw it first.
fn policy_store_message(wallet_pubkey: &str, encrypted_data: &str, caller: &str) -> String {
    format!(
        "store_wallet_policy:v1:{}:{}:{}:{}",
        wallet_pubkey,
        encrypted_data.len(),
        encrypted_data,
        caller
    )
}

/// The exact string the contract rebuilds and verifies in `delete_agent_secret`.
///
/// A DIFFERENT domain from the store, and that is the whole point: a signature
/// obtained to store a secret must not also destroy one. The contract pins the
/// same distinction, and `a_store_signature_cannot_delete` here fails if either
/// side loses it.
///
/// Shorter than the store by everything that describes CONTENT — there is no
/// ciphertext, no access condition and no vault, because a delete names a
/// secret rather than describing one. What remains is exactly the tuple the
/// contract looks the secret up by, plus the payer.
///
/// The payer is in here for a sharper reason than in the store: the pair
/// `(args, signature)` sits on chain forever once submitted, and a replayed
/// DELETE is not a rollback — it is a deletion that happens whenever somebody
/// else chooses. Binding the submitter is what stops everyone but them.
fn secret_delete_message(
    wallet_pubkey: &str,
    accessor_binding: &str,
    profile: &str,
    payer: &str,
) -> String {
    format!(
        "delete_agent_secret:v1:{}:{}:{}:{}:{}",
        wallet_pubkey,
        accessor_binding.len(),
        accessor_binding,
        profile,
        payer
    )
}

/// The access condition as the CONTRACT will render it when it rebuilds this
/// message.
///
/// Serialised from the typed value, not echoed from whatever text arrived, so
/// the two sides agree by doing the same thing rather than by the caller
/// sending the same bytes twice. If the two type definitions ever drift, the
/// pinned tests here and in the contract print different strings — which is the
/// point of pinning both.
fn access_binding(access: &crate::types::AccessCondition) -> Result<String, ApiError> {
    serde_json::to_string(access).map_err(|e| {
        ApiError::BadRequest(format!("access condition could not be serialised: {}", e))
    })
}

/// Sign a secret store so the contract can record it as the WALLET's, while
/// somebody else pays for the storage.
///
/// This is what lets an agent hold a credential without ever holding NEAR:
/// `store_secrets` makes the caller the owner, so without a signature the wallet
/// itself would have to send the transaction and stake the deposit.
///
/// SECURITY: the signing key here (`wallet:{id}:near`) is ALSO the wallet's NEAR
/// tx key, and a NEAR tx signature is `sign(sha256(borsh(tx)))`. So no
/// caller-supplied hash is ever signed. Two things keep this safe, and neither
/// may be weakened:
///
///   1. the signed preimage is BUILT HERE and begins with a fixed domain
///      string, so a caller cannot steer it towards a serialised transaction;
///   2. the ciphertext is DECRYPT-VALIDATED first. The AEAD tag can only verify
///      for something genuinely sealed to this exact seed, so arbitrary attacker
///      bytes are refused before any signing happens — the same gate
///      `/wallet/sign-policy` relies on.
///
/// Rebuilding the seed here has a second effect worth keeping: it proves the
/// secret was sealed to the seed the keystore will later rebuild when it
/// decrypts. Sealing to the wrong one used to fail silently, at read time, long
/// after the author had gone.
async fn wallet_sign_secret_store_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<SignSecretStoreRequest>,
) -> Result<Json<SignSecretStoreResponse>, ApiError> {
    if !state.is_ready() {
        return Err(ApiError::Unauthorized("Keystore not ready.".to_string()));
    }

    validate_wallet_id(&req.wallet_id)?;
    let customer = extract_customer_from_header(&headers)?;
    state
        .ensure_customer_loaded(customer.as_ref())
        .await
        .map_err(ApiError::from_customer_load)?;

    if req.encrypted_secrets_base64.is_empty() {
        return Err(ApiError::BadRequest(
            "encrypted_secrets_base64 is required".to_string(),
        ));
    }
    let target = AgentSecretTarget::from_fields(
        req.project_id.as_deref(),
        req.wasm_hash.as_deref(),
    )?;
    if req.payer.trim().is_empty() {
        return Err(ApiError::BadRequest("payer is required".to_string()));
    }

    // No colon check on the accessor, deliberately. It is
    // length-prefixed in the message below, so its content cannot move a
    // boundary however it is spelled — a ban here would refuse what the
    // contract now accepts. The only field still required to be colon-free is
    // `profile`, and this endpoint does not take one: it derives it from the
    // wallet's own key, as 64 hex characters.

    let keystore = state.keystore.read().await;
    let wallet_seed = wallet_seed(&req.wallet_id, "near");
    let verifying_key = keystore
        .get_public_key_for_seed(customer.as_ref(), &wallet_seed)
        .map_err(|e| ApiError::InternalError(format!("Failed to derive public key: {}", e)))?;
    let agent_account = hex::encode(verifying_key.as_bytes());
    let wallet_pubkey = format!("ed25519:{}", agent_account);

    // 1. Decrypt-validate against the seed WE rebuild. Fails for attacker bytes
    //    and equally for a secret sealed to the wrong seed.
    let secret_seed = target.seed(&agent_account);
    let encrypted_bytes = base64::decode(&req.encrypted_secrets_base64).map_err(|e| {
        ApiError::BadRequest(format!(
            "encrypted_secrets_base64 is not valid base64: {}",
            e
        ))
    })?;
    keystore
        .decrypt(customer.as_ref(), &secret_seed, &encrypted_bytes)
        .map_err(|_| {
            ApiError::Forbidden(
                "The secret did not decrypt under this agent's seed — refusing to sign. \
                 Encrypt it with the key from the agent-secret pubkey endpoint for this \
                 exact project."
                    .to_string(),
            )
        })?;

    // A condition the keystore would refuse to judge is not signed into a row.
    // NOT `unwrap_or(Null)`: an unserialisable condition would then count as
    // zero of everything and pass a bound whose whole job is to refuse.
    let access_shape = serde_json::to_value(&req.access).map_err(|e| {
        ApiError::InternalError(format!("Access condition could not be serialised: {e}"))
    })?;
    if let Err(why) = shared_tee_helpers::access_limits::condition_bounds(&access_shape) {
        return Err(ApiError::BadRequest(format!("access condition refused: {why}")));
    }

    // 2. Only now build the message the contract will rebuild, and sign it.
    // The message covers the ACCESSOR as well. The signature authorises one
    // stored secret, and what it belongs to is part of what was authorised:
    // without it the payer could send the same signed blob under a different
    // accessor. Nothing leaks either way — the ciphertext is sealed to that
    // scope's seed and would not decrypt elsewhere — but an authorisation that
    // does not cover what it authorises is a hole waiting for the day one of
    // those facts changes.
    let message = secret_store_message(
        &wallet_pubkey,
        &target.binding(),
        &agent_account,
        &req.encrypted_secrets_base64,
        req.payer.trim(),
        req.vault_id.as_deref().unwrap_or(""),
        &access_binding(&req.access)?,
    );
    let message_hash = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(message.as_bytes());
        hasher.finalize()
    };

    let signature = keystore
        .sign(customer.as_ref(), &wallet_seed, &message_hash)
        .map_err(|e| ApiError::InternalError(format!("Signing failed: {}", e)))?;

    tracing::info!(
        wallet_id = %req.wallet_id,
        target = %target.describe(),
        payer = %req.payer,
        "Signed a secret store for an agent"
    );

    Ok(Json(SignSecretStoreResponse {
        signature_hex: hex::encode(signature.to_bytes()),
        wallet_pubkey,
        agent_account,
    }))
}

/// Sign a `delete_agent_secret` call: destroy ONE named secret, on behalf of
/// ONE named submitter.
///
/// The store's safety argument runs through the ciphertext — it is
/// decrypt-validated, so a caller cannot get an arbitrary preimage signed. A
/// delete carries no ciphertext, so that argument is unavailable and the
/// structure has to hold on its own:
///
///   1. the message is BUILT here from typed fields, never taken from the
///      caller, and it opens with an ASCII domain. Read as borsh, that domain
///      claims a `signer_id` of about 1.9 billion against a 64-byte maximum, so
///      no transaction can wear this preimage — the same property that makes
///      the store endpoint safe to expose, and it does not depend on the
///      ciphertext at all;
///   2. the domain is `delete_agent_secret:v1:`, DIFFERENT from the store's, so
///      neither signature can be presented as the other;
///   3. every field the contract looks the secret up by is inside the
///      signature, and so is the payer. What comes back destroys one tuple when
///      sent by one account.
///
/// The deposit returns to the submitter, which is the payer named here. That is
/// the contract's rule, not this endpoint's, and it is why the author who
/// staked the storage is the sensible account to name.
async fn wallet_sign_secret_delete_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<SignSecretDeleteRequest>,
) -> Result<Json<SignSecretDeleteResponse>, ApiError> {
    if !state.is_ready() {
        return Err(ApiError::Unauthorized("Keystore not ready.".to_string()));
    }

    validate_wallet_id(&req.wallet_id)?;
    let customer = extract_customer_from_header(&headers)?;
    state
        .ensure_customer_loaded(customer.as_ref())
        .await
        .map_err(ApiError::from_customer_load)?;

    let target = AgentSecretTarget::from_fields(
        req.project_id.as_deref(),
        req.wasm_hash.as_deref(),
    )?;
    if req.payer.trim().is_empty() {
        return Err(ApiError::BadRequest(
            "payer is required: the signature is bound to the account that will send the \
             transaction, and the storage deposit comes back to it."
                .to_string(),
        ));
    }

    let keystore = state.keystore.read().await;
    let wallet_seed = wallet_seed(&req.wallet_id, "near");
    let verifying_key = keystore
        .get_public_key_for_seed(customer.as_ref(), &wallet_seed)
        .map_err(|e| ApiError::InternalError(format!("Failed to derive public key: {}", e)))?;
    let agent_account = hex::encode(verifying_key.as_bytes());
    let wallet_pubkey = format!("ed25519:{}", agent_account);

    let message = secret_delete_message(
        &wallet_pubkey,
        &target.binding(),
        &agent_account,
        req.payer.trim(),
    );
    let message_hash = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(message.as_bytes());
        hasher.finalize()
    };

    let signature = keystore
        .sign(customer.as_ref(), &wallet_seed, &message_hash)
        .map_err(|e| ApiError::InternalError(format!("Signing failed: {}", e)))?;

    tracing::info!(
        wallet_id = %req.wallet_id,
        target = %target.describe(),
        payer = %req.payer,
        "Signed a secret delete for an agent"
    );

    Ok(Json(SignSecretDeleteResponse {
        signature_hex: hex::encode(signature.to_bytes()),
        wallet_pubkey,
        agent_account,
    }))
}

/// Sign encrypted policy data so the NEAR contract can verify wallet ownership.
///
/// The contract's `store_wallet_policy` requires a signature over
/// [`policy_store_message`] — domain, wallet key, the blob, and the account
/// that will send the call. This endpoint produces it with the wallet's derived
/// key.
async fn wallet_sign_policy_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<WalletSignPolicyRequest>,
) -> Result<Json<WalletSignPolicyResponse>, ApiError> {
    if !state.is_ready() {
        return Err(ApiError::Unauthorized("Keystore not ready.".to_string()));
    }

    validate_wallet_id(&req.wallet_id)?;
    let customer = extract_customer_from_header(&headers)?;
    state
        .ensure_customer_loaded(customer.as_ref())
        .await
        .map_err(ApiError::from_customer_load)?;

    // SECURITY: the signing key here (`wallet:{id}:near`) is ALSO the wallet's NEAR tx key,
    // and a NEAR tx signature is `sign(sha256(borsh(tx)))`. So we must NEVER sign a
    // caller-supplied 32-byte hash — that is a universal tx-forging oracle (feed it a tx_hash,
    // get a valid transaction signature → drain). We take the encrypted policy BLOB (never a
    // pre-computed hash) and first DECRYPT-VALIDATE it: the ChaCha20-Poly1305 AEAD auth tag
    // can only verify for a real ciphertext produced under this wallet's policy key, so
    // arbitrary attacker bytes (e.g. `borsh(tx)`) FAIL decryption and are rejected here. ONLY
    // after a successful decrypt (to a parseable Policy) do we sign the message the contract
    // rebuilds. The decrypt is the gate; do not weaken, reorder, or skip it — the domain in
    // that message is a second, independent reason no transaction can wear this preimage, not
    // a replacement for this one.
    if req.encrypted_data.is_empty() {
        return Err(ApiError::BadRequest("encrypted_data is required".to_string()));
    }
    if req.caller.trim().is_empty() {
        // Refused rather than signed as an empty string: the contract rebuilds
        // this message with its own predecessor, so a signature naming nobody
        // matches nothing and would fail on chain with "Invalid Ed25519 wallet
        // signature" — a message about cryptography for what is a missing
        // field.
        return Err(ApiError::BadRequest(
            "caller is required: the signature names the NEAR account that will send \
             store_wallet_policy, and is good for that account only."
                .to_string(),
        ));
    }

    let keystore = state.keystore.read().await;

    // 1. Decrypt-validate: prove `encrypted_data` is a real ciphertext under this wallet's
    //    policy key (same seed as `load_wallet_policy` / `wallet_decrypt_policy_handler`).
    let policy_seed = format!("wallet-policy:{}", req.wallet_id);
    let encrypted_bytes = base64::decode(&req.encrypted_data).map_err(|e| {
        ApiError::BadRequest(format!("encrypted_data is not valid base64: {}", e))
    })?;
    let decrypted = keystore
        .decrypt(customer.as_ref(), &policy_seed, &encrypted_bytes)
        .map_err(|_| {
            // AEAD auth-tag failure ⇒ not a genuine policy ciphertext (could be a forged
            // tx-hash preimage). Refuse — this is the check that closes the oracle.
            ApiError::Forbidden(
                "encrypted_data did not decrypt as this wallet's policy — refusing to sign \
                 (only a genuine policy ciphertext may be attested)".to_string(),
            )
        })?;
    // Defence-in-depth: the plaintext must be a well-formed policy.
    serde_json::from_slice::<shared_tee_helpers::wallet_policy::Policy>(&decrypted).map_err(|e| {
        ApiError::Forbidden(format!(
            "decrypted policy did not parse as a Policy — refusing to sign: {}",
            e
        ))
    })?;

    // 2. Sign the message the CONTRACT rebuilds — domain first, caller last.
    //
    //    It used to be the bare `sha256(encrypted_data)`, which the decrypt
    //    above made safe to produce but did not make safe to HOLD: every wallet
    //    signature in this system has that shape, and the strings are public,
    //    so any signature from any verb could be filed here as a policy. The
    //    domain stops that; the caller stops the resulting signature being
    //    usable by anyone but the account it was made for.
    let seed = wallet_seed(&req.wallet_id, "near");
    let policy_pubkey = {
        let vk = keystore
            .get_public_key_for_seed(customer.as_ref(), &seed)
            .map_err(|e| ApiError::InternalError(format!("Failed to derive public key: {}", e)))?;
        format!("ed25519:{}", hex::encode(vk.as_bytes()))
    };
    let message = policy_store_message(&policy_pubkey, &req.encrypted_data, req.caller.trim());
    let message_hash = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(message.as_bytes());
        hasher.finalize()
    };

    let signature = keystore.sign(customer.as_ref(), &seed, &message_hash).map_err(|e| {
        ApiError::InternalError(format!("Signing failed: {}", e))
    })?;

    // The Ed25519 pubkey (not the X25519 one) — the key the contract's
    // `ed25519_verify` uses, and the same value the message above names. Taken
    // from `policy_pubkey` rather than derived a second time, so the answer and
    // what was signed cannot describe different keys.
    let public_key_hex = policy_pubkey
        .strip_prefix("ed25519:")
        .unwrap_or(&policy_pubkey)
        .to_string();

    Ok(Json(WalletSignPolicyResponse {
        signature_hex: hex::encode(signature.to_bytes()),
        public_key_hex,
    }))
}

/// Independently verify approver signatures for an operation that the on-chain
/// policy requires approval for.
///
/// The trust anchor is the on-chain policy (read + decrypted by `load_wallet_policy`)
/// and the approvers' real NEP-413 signatures over `approve:{approval_id}:{wallet_pubkey}:{request_hash}`,
/// where `request_hash` is derived HERE from the canonical `op` — never supplied by the
/// coordinator. So a genuine approval bundle cannot be replayed to authorize a different
/// op (the binding is automatic), and the coordinator transports the signatures but
/// cannot forge them.
/// The exact NEP-413 message an approver/rejecter signs. Binds the vote to (a) the approval
/// id, (b) THIS wallet's on-chain pubkey — so a signature collected for wallet A can never be
/// replayed onto wallet B — and (c) the canonical request hash. Pure + unit-tested.
fn approval_vote_message(vote: &str, approval_id: &str, wallet_pubkey: &str, request_hash: &str) -> String {
    format!("{}:{}:{}:{}", vote, approval_id, wallet_pubkey, request_hash)
}

/// Trusted-artifact NEP-413 recipients (intents verifiers only). `intents.near` for the
/// public shard (swap/cross_chain_withdraw/payment_check transfers) and `intents.far` for
/// the confidential shard's generate-intent. NEAR Intents is mainnet-only (no testnet
/// solvers), so the keystore only ever signs intents against the mainnet verifiers. The
/// coordinator still controls the actual recipient; this allowlist is the keystore's
/// independent backstop. Pure + unit-tested.
fn is_trusted_recipient(recipient: &str) -> bool {
    matches!(recipient, "intents.near" | "intents.far")
}

async fn verify_approvals(
    state: &AppState,
    policy: &shared_tee_helpers::wallet_policy::Policy,
    wallet_pubkey: &str,
    request_hash: &str,
    approval_info: Option<&ApprovalInfo>,
    threshold: usize,
) -> Result<(), ApiError> {
    let near_client = state.near_client.as_ref().ok_or_else(|| {
        ApiError::InternalError("NEAR client not configured".to_string())
    })?;

    // The configured approver set from the on-chain policy: (account id, optional PINNED
    // ed25519 pubkey). When a pubkey is pinned, the signing key MUST match it (a compromised
    // coordinator can't substitute another key the account also owns); otherwise we fall back
    // to on-chain key-ownership verification.
    let approvers: Vec<(&str, Option<&str>)> = policy
        .approval
        .as_ref()
        .and_then(|a| a.approvers.as_ref())
        .map(|v| {
            v.iter()
                .filter_map(|ap| ap.id.as_deref().map(|id| (id, ap.pubkey.as_deref())))
                .collect()
        })
        .unwrap_or_default();
    if approvers.is_empty() {
        return Err(ApiError::Forbidden(format!(
            "Policy requires {} approvals but no approvers are configured.",
            threshold
        )));
    }
    // Pinned-pubkey lookup: a vote from approver `id` whose policy entry pins a pubkey is
    // only valid if signed by THAT pubkey. Returns Ok(()) when allowed, Err otherwise.
    let pinned_ok = |id: &str, pubkey: &str| -> bool {
        match approvers.iter().find(|(aid, _)| *aid == id) {
            Some((_, Some(pinned))) => *pinned == pubkey,
            Some((_, None)) => true, // no pin → ownership check below is the gate
            None => false,           // not a policy approver
        }
    };

    // Multisig is required → approvals MUST be present and valid (no skipping).
    let info = approval_info.ok_or_else(|| {
        ApiError::Forbidden(
            "This wallet requires multisig approval, but none were provided.".to_string(),
        )
    })?;

    // Cap the ballot before verifying anything in it. Each vote past the (cheap) approver-set
    // filter costs a NEP-413 signature verification, and nothing else bounds the array — only
    // axum's implicit 2 MB body limit, i.e. thousands of votes on one request.
    //
    // Repeating a single known approver id is enough to reach that cost: the duplicate check in
    // the approval loop skips an id only once it has been SUCCESSFULLY verified, so invalid
    // repeats sail past it. No on-chain setup and no gas is needed to try this.
    //
    // The cap is on votes in this request, not on approvers in the policy, and it is far above
    // any real threshold — a multisig with more than 16 approvers is not a thing we support.
    // Deliberately checked before `recipient` so an oversized body is rejected on its size
    // alone, without touching its contents.
    if info.approvals.len() > MAX_APPROVAL_VOTES || info.rejections.len() > MAX_APPROVAL_VOTES {
        return Err(ApiError::BadRequest(format!(
            "too many approval votes: {} approvals / {} rejections (limit {} each). \
             Send only the votes that count toward the threshold.",
            info.approvals.len(),
            info.rejections.len(),
            MAX_APPROVAL_VOTES
        )));
    }

    // recipient = THIS keystore's contract (the on-chain trust anchor). Assert the
    // coordinator agrees, so a config mismatch fails loudly instead of looking like a
    // bad signature on every approval.
    let recipient = near_client.contract_id().to_string();
    if info.recipient != recipient {
        return Err(ApiError::Forbidden(format!(
            "approval recipient '{}' != this keystore's contract '{}'",
            info.recipient, recipient
        )));
    }

    // Each approval must be a valid NEP-413 signature over
    // `approve:{id}:{wallet_pubkey}:{request_hash}`, signed against THIS keystore's contract,
    // by a key that belongs to a policy approver's account. The `wallet_pubkey` binds the
    // vote to THIS wallet — a signature collected for wallet A cannot be replayed onto
    // wallet B (shared approvers + shared whitelisted destination). Count distinct approvers.
    let message = approval_vote_message("approve", &info.approval_id, wallet_pubkey, request_hash);
    let mut approved_by: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for ap in &info.approvals {
        if approved_by.contains(ap.approver_id.as_str()) {
            continue;
        }
        if !pinned_ok(&ap.approver_id, &ap.public_key) {
            continue; // not a policy approver, or signed by a non-pinned key
        }
        if verify_near_signature(&message, &ap.signature, &ap.public_key, &ap.nonce, &recipient)
            .is_err()
        {
            continue; // invalid signature
        }
        // Propagate RPC errors instead of silently dropping a valid approver below
        // threshold on a transient blip — fail-closed and retryable.
        near_client
            .verify_access_key_owner(&ap.approver_id, &ap.public_key)
            .await
            .map_err(|e| {
                ApiError::InternalError(format!(
                    "could not verify approver {} key ownership: {}",
                    ap.approver_id, e
                ))
            })?;
        approved_by.insert(ap.approver_id.as_str());
    }

    // Veto: a NO vote from ANY real policy approver (valid sig over
    // `reject:{id}:{wallet_pubkey}:{request_hash}` + on-chain key ownership + in the approver set)
    // refuses the operation, regardless of how many approvals were collected.
    // Non-approver rejections are ignored — filtered exactly like non-approver approvals.
    let reject_message = approval_vote_message("reject", &info.approval_id, wallet_pubkey, request_hash);
    for rj in &info.rejections {
        if !pinned_ok(&rj.approver_id, &rj.public_key) {
            continue; // not a policy approver, or signed by a non-pinned key
        }
        if verify_near_signature(&reject_message, &rj.signature, &rj.public_key, &rj.nonce, &recipient)
            .is_err()
        {
            continue; // invalid signature
        }
        near_client
            .verify_access_key_owner(&rj.approver_id, &rj.public_key)
            .await
            .map_err(|e| {
                ApiError::InternalError(format!(
                    "could not verify rejecter {} key ownership: {}",
                    rj.approver_id, e
                ))
            })?;
        return Err(ApiError::Forbidden(format!(
            "Operation vetoed by approver {}",
            rj.approver_id
        )));
    }

    if approved_by.len() < threshold {
        return Err(ApiError::Forbidden(format!(
            "Insufficient valid approvals: {} of {} required",
            approved_by.len(),
            threshold
        )));
    }

    Ok(())
}

/// Read + decrypt the wallet's on-chain policy, returning the parsed `Policy`.
///
/// The policy is keyed on-chain by the wallet's ed25519 pubkey, derived the same way
/// `/check-policy` does (from `wallet:{wallet_id}:near`) — NOT the raw `wallet_id`,
/// which would miss the policy entirely. `None` means no policy on-chain → single-sig
/// wallet, nothing for the keystore to enforce.
/// Derive the wallet's on-chain ed25519 pubkey ("ed25519:<hex>") from `wallet:{id}:near`.
/// The single source of truth for the policy key AND the approval-message wallet binding —
/// both MUST use the identical string, so they share this helper.
async fn derive_wallet_ed25519_pubkey(
    state: &AppState,
    customer: Option<&near_primitives::types::AccountId>,
    wallet_id: &str,
) -> Result<String, ApiError> {
    let near_seed = wallet_seed(&wallet_id, "near");
    let keystore = state.keystore.read().await;
    let ed25519_vk = keystore
        .get_public_key_for_seed(customer, &near_seed)
        .map_err(|e| ApiError::InternalError(format!("Failed to derive wallet pubkey: {}", e)))?;
    Ok(format!("ed25519:{}", hex::encode(ed25519_vk.as_bytes())))
}

async fn load_wallet_policy(
    state: &AppState,
    wallet_id: &str,
    customer: Option<&near_primitives::types::AccountId>,
) -> Result<Option<shared_tee_helpers::wallet_policy::Policy>, ApiError> {
    let near_client = state.near_client.as_ref().ok_or_else(|| {
        ApiError::InternalError("NEAR client not configured".to_string())
    })?;

    let wallet_pubkey = derive_wallet_ed25519_pubkey(state, customer, wallet_id).await?;

    let policy_view = near_client
        .get_wallet_policy(&wallet_pubkey)
        .await
        .map_err(|e| ApiError::InternalError(format!("Failed to fetch wallet policy: {}", e)))?;
    let policy_view = match policy_view {
        Some(pv) => pv,
        None => return Ok(None),
    };

    // The frozen flag is visible without decryption.
    //
    // A freeze is the controller's hard stop, so it is the ONE flag that must
    // not default. `unwrap_or(false)` read a field we could not parse as "not
    // frozen" — unreachable today, because the contract types it as `bool` and
    // always serializes it, and precisely the reason nobody would notice the
    // day that stopped being true. A freeze we cannot read is not an absence
    // of one, and it is refused rather than answered `Frozen`: the owner's
    // wallet may not be frozen at all, and telling them it is would send them
    // to unfreeze something nobody froze.
    let frozen = match policy_view.get("frozen") {
        Some(v) => v.as_bool().ok_or_else(|| {
            ApiError::BadRequest(
                "this wallet's freeze state could not be read from the policy on chain, so \
                 nothing will be signed. This is a schema mismatch between the contract and \
                 this build, not a setting — it needs an operator, not a re-save"
                    .to_string(),
            )
        })?,
        // Absent is not the same as unreadable: a policy that predates the
        // field was never frozen.
        None => false,
    };
    if frozen {
        return Ok(Some(shared_tee_helpers::wallet_policy::Policy {
            frozen: true,
            ..Default::default()
        }));
    }

    let encrypted_data_b64 = policy_view
        .get("encrypted_data")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::InternalError("Missing encrypted_data in policy".to_string()))?;
    let seed = format!("wallet-policy:{}", wallet_id);
    let decrypted = {
        let keystore = state.keystore.read().await;
        let encrypted_bytes = base64::decode(encrypted_data_b64)
            .map_err(|e| ApiError::InternalError(format!("Invalid base64: {}", e)))?;
        keystore
            .decrypt(customer, &seed, &encrypted_bytes)
            .map_err(|e| ApiError::InternalError(format!("Policy decryption failed: {}", e)))?
    };
    let mut policy: shared_tee_helpers::wallet_policy::Policy = serde_json::from_slice(&decrypted)
        .map_err(|e| ApiError::InternalError(format!("Policy parse failed: {}", e)))?;
    policy.frozen = policy.frozen || frozen;
    Ok(Some(policy))
}

/// The wallet's implicit NEAR account id (hex of the derived ed25519 pubkey).
async fn wallet_implicit_account(
    state: &AppState,
    customer: Option<&near_primitives::types::AccountId>,
    wallet_id: &str,
) -> Result<String, ApiError> {
    let seed = wallet_seed(&wallet_id, "near");
    let keystore = state.keystore.read().await;
    let vk = keystore
        .get_public_key_for_seed(customer, &seed)
        .map_err(|e| ApiError::InternalError(format!("Failed to derive wallet pubkey: {}", e)))?;
    Ok(hex::encode(vk.as_bytes()))
}

/// Format a Unix timestamp (seconds) as an ISO-8601 UTC string
/// (`YYYY-MM-DDThh:mm:ss.000Z`) — the deadline format the Intents contract expects.
/// Civil-date conversion via Howard Hinnant's algorithm (no chrono dependency).
fn unix_to_iso8601(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (hh, mm, ss) = (rem / 3_600, (rem % 3_600) / 60, rem % 60);

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as i64; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.000Z",
        year, month, d, hh, mm, ss
    )
}

/// Build the NEP-413 intent message for an Intents withdrawal OUT (to a NEAR account)
/// FROM canonical op fields. Native NEAR → `native_withdraw`; NEP-141 token →
/// `ft_withdraw` (the WITHDRAW-OUT intent; `token` is the UNPREFIXED contract id).
/// NOT `transfer` — that is an internal move between intents accounts, not a withdrawal.
/// (Verified against the defuse `Intent` enum in `near/intents`.)
fn build_withdraw_intent_message(
    signer_id: &str,
    to: &str,
    amount: &str,
    token: &str,
    deadline: &str,
) -> String {
    let t = token.trim().to_lowercase();
    if t == "near" || t == "native" || t.is_empty() {
        serde_json::json!({
            "signer_id": signer_id,
            "deadline": deadline,
            "intents": [{ "intent": "native_withdraw", "receiver_id": to, "amount": amount }]
        })
        .to_string()
    } else {
        // ft_withdraw's `token` is the bare NEP-141 contract id (no nep141:/nep245: prefix).
        let token_contract = token
            .strip_prefix("nep141:")
            .or_else(|| token.strip_prefix("nep245:"))
            .unwrap_or(token);
        serde_json::json!({
            "signer_id": signer_id,
            "deadline": deadline,
            "intents": [{
                "intent": "ft_withdraw",
                "token": token_contract,
                "receiver_id": to,
                "amount": amount
            }]
        })
        .to_string()
    }
}

/// Build the NEP-413 intent message for an INTERNAL Intents transfer (move a token
/// balance to ANOTHER intents account) FROM canonical op fields. This is the defuse
/// `transfer` intent — NOT a withdrawal: funds stay inside `intents.near`, credited to
/// `receiver_id`'s mt balance. The `tokens` map is keyed by the PREFIXED Defuse asset id
/// (`nep141:`/`nep245:`), unlike `ft_withdraw` which uses the bare contract id. Kept
/// byte-compatible with the coordinator's `intents_helpers::build_transfer_intent_message`
/// (same intent/receiver_id/tokens shape). (Verified against the defuse `Intent` enum in
/// `near/intents`.)
fn build_transfer_intent_message(
    signer_id: &str,
    to: &str,
    amount: &str,
    token: &str,
    deadline: &str,
) -> String {
    let t = token.trim();
    let token_id = if t.starts_with("nep141:") || t.starts_with("nep245:") {
        t.to_string()
    } else {
        format!("nep141:{}", t)
    };
    let mut tokens = serde_json::Map::new();
    tokens.insert(token_id, serde_json::Value::String(amount.to_string()));
    serde_json::json!({
        "signer_id": signer_id,
        "deadline": deadline,
        "intents": [{
            "intent": "transfer",
            "receiver_id": to,
            "tokens": tokens
        }]
    })
    .to_string()
}

/// Default-DENY allowlist for `sign_message` recipients. Under a policy, the recipient
/// must appear in `capabilities.sign_message.allowed_recipients`; anything else is
/// refused so an auth signature can never target a fund-moving verifier (named or
/// future). `None` policy = single-sig wallet → unrestricted.
///
/// Feed this the STATED policy — the `Option` as `load_wallet_policy` returned it —
/// and never the stand-in `policy_to_judge_by` builds for a wallet that has none.
/// The chain below short-circuits on the first absent link, so a policy whose
/// `sign_message` is unnamed denies EVERY recipient. That is correct for a policy
/// the owner wrote and wrong for a wallet that has none: passing the stand-in here
/// would close auth signing on every freshly registered wallet.
fn sign_message_recipient_allowed(
    policy: Option<&shared_tee_helpers::wallet_policy::Policy>,
    recipient: &str,
) -> bool {
    match policy {
        None => true,
        Some(policy) => policy
            .capabilities
            .as_ref()
            .and_then(|c| c.sign_message.as_ref())
            .and_then(|sm| sm.allowed_recipients.as_ref())
            .map(|list| list.iter().any(|r| r == recipient))
            .unwrap_or(false),
    }
}

/// Sign a NEP-413 payload constructed from `(message, nonce, recipient)` with the
/// wallet's derived ed25519 key. Returns `(signature_base58, public_key)` in
/// `ed25519:...` form. The recipient is part of the signed payload, so it binds the
/// signature to a domain.
async fn sign_nep413(
    state: &AppState,
    customer: Option<&near_primitives::types::AccountId>,
    wallet_id: &str,
    // Connector scope from the signed canonical op, when there is one (§D1).
    // A connector-scoped signature comes from the connector's OWN key, so the
    // returned public key is the connector sub-key's, not the wallet's — which
    // is what keeps one connector's identity from standing in for another's.
    message: &str,
    nonce: [u8; 32],
    recipient: &str,
) -> Result<(String, String), ApiError> {
    use ed25519_dalek::Signer;
    use sha2::{Digest, Sha256};

    let seed = wallet_seed(wallet_id, "near");
    let keystore = state.keystore.read().await;
    let (signing_key, verifying_key) = keystore
        .derive_keypair(customer, &seed)
        .map_err(|e| ApiError::InternalError(format!("Key derivation failed: {}", e)))?;

    let payload = Nep413Payload {
        message: message.to_string(),
        nonce,
        recipient: recipient.to_string(),
        callback_url: None,
    };
    let payload_bytes = borsh::to_vec(&payload)
        .map_err(|e| ApiError::InternalError(format!("Failed to serialize NEP-413 payload: {}", e)))?;
    let mut to_hash = Vec::with_capacity(4 + payload_bytes.len());
    to_hash.extend_from_slice(&NEP413_TAG.to_le_bytes());
    to_hash.extend_from_slice(&payload_bytes);
    let hash = Sha256::digest(&to_hash);
    let signature = signing_key.sign(&hash);

    Ok((
        format!("ed25519:{}", bs58::encode(signature.to_bytes()).into_string()),
        format!("ed25519:{}", bs58::encode(verifying_key.to_bytes()).into_string()),
    ))
}

/// Derive the wallet key, query the access-key nonce + block hash, build a NEAR
/// `Transaction::V0` from the actions produced by `make_tx`, sign it, and return the
/// signed transaction. The signer is the wallet's implicit account.
async fn sign_near_transaction<F>(
    state: &AppState,
    customer: Option<&near_primitives::types::AccountId>,
    wallet_id: &str,
    request_hash: String,
    make_tx: F,
) -> Result<WalletSignResponse, ApiError>
where
    F: FnOnce(
        &near_primitives::types::AccountId,
    ) -> Result<
        (
            near_primitives::types::AccountId,
            Vec<near_primitives::transaction::Action>,
        ),
        ApiError,
    >,
{
    use ed25519_dalek::Signer;
    use near_primitives::transaction::{SignedTransaction, Transaction, TransactionV0};
    use near_primitives::types::AccountId;
    use std::str::FromStr;

    let near_client = state.near_client.as_ref().ok_or_else(|| {
        ApiError::InternalError("NEAR client not configured".to_string())
    })?;

    let seed = wallet_seed(wallet_id, "near");
    let (signing_key, verifying_key) = {
        let keystore = state.keystore.read().await;
        keystore
            .derive_keypair(customer, &seed)
            .map_err(|e| ApiError::InternalError(format!("Key derivation failed: {}", e)))?
    };

    let pubkey_bytes = verifying_key.to_bytes();
    let signer_id_str = hex::encode(pubkey_bytes);
    let signer_id = AccountId::from_str(&signer_id_str)
        .map_err(|e| ApiError::InternalError(format!("Invalid implicit account ID: {}", e)))?;
    let public_key_str = format!("ed25519:{}", bs58::encode(&pubkey_bytes).into_string());
    let public_key: near_crypto::PublicKey = public_key_str
        .parse()
        .map_err(|e| ApiError::InternalError(format!("Invalid public key: {}", e)))?;

    let (receiver_id, actions) = make_tx(&signer_id)?;

    let (rpc_nonce, block_hash) = near_client
        .query_access_key(&signer_id_str, &public_key)
        .await
        .map_err(|e| {
            // `{:#}` and not `{}`. On an `anyhow::Error` the plain form prints
            // only the outermost context — here the string "Failed to query
            // access key" that `near.rs` attached — so the message came back as
            // that sentence twice and named nothing at all: not the account,
            // not that it does not exist, not what to do about it. The cause
            // was in the source chain the whole time.
            let cause = format!("{e:#}");
            if rpc_error_is_about_the_signer(&cause) {
                // Says what the chain said, and stops there. It answers
                // identically for an account that has never been used and for
                // one that exists carrying a different key (checked against
                // testnet: the same bytes, both times), so naming a remedy
                // would be naming one we cannot know applies.
                ApiError::ChainRefused(format!(
                    "the account {signer_id_str} is not visible on the network, so there is no \
                     key to sign with. Most often that means it has never taken part in a \
                     transaction. Retrying will not change it — the chain answered, and this \
                     is its answer."
                ))
            } else {
                ApiError::InternalError(format!("Failed to query access key: {cause}"))
            }
        })?;
    // Always rpc_nonce + 1 — the keystore keeps no idempotency state, and a caller-chosen
    // nonce would let one approved op be signed at many nonces.
    let tx_nonce = rpc_nonce + 1;

    let transaction = Transaction::V0(TransactionV0 {
        signer_id: signer_id.clone(),
        public_key: public_key.clone(),
        nonce: tx_nonce,
        receiver_id,
        block_hash,
        actions,
    });

    let (tx_hash, _) = transaction.get_hash_and_size();
    let sig = signing_key.sign(tx_hash.as_ref());
    let sig_str = format!("ed25519:{}", bs58::encode(sig.to_bytes()).into_string());
    let signature: near_crypto::Signature = sig_str
        .parse()
        .map_err(|e| ApiError::InternalError(format!("Failed to construct signature: {}", e)))?;
    let signed_tx = SignedTransaction::new(signature, transaction);
    let signed_tx_bytes = borsh::to_vec(&signed_tx)
        .map_err(|e| ApiError::InternalError(format!("Failed to serialize signed transaction: {}", e)))?;

    let mut resp = WalletSignResponse::new(request_hash);
    resp.signed_tx_base64 = Some(base64::encode(&signed_tx_bytes));
    resp.tx_hash = Some(bs58::encode(tx_hash.as_ref()).into_string());
    resp.signer_id = Some(signer_id_str);
    resp.public_key = Some(public_key.to_string());
    resp.nonce = Some(tx_nonce);
    Ok(resp)
}

/// Unified wallet signing endpoint. Evaluates the on-chain policy, verifies approver
/// signatures when required, and produces the artifact per the op's bind mode:
/// `Built` constructs the artifact from the op, `HashPinned` signs supplied bytes
/// pinned by hash, `Trusted` signs an externally-generated artifact.
async fn wallet_sign_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<WalletSignRequest>,
) -> Result<Json<WalletSignResponse>, ApiError> {
    use shared_tee_helpers::wallet_policy::{self, BindMode, Decision};

    if !state.is_ready() {
        return Err(ApiError::Unauthorized("Keystore not ready.".to_string()));
    }
    validate_wallet_id(&req.wallet_id)?;
    let customer = extract_customer_from_header(&headers)?;
    state
        .ensure_customer_loaded(customer.as_ref())
        .await
        .map_err(ApiError::from_customer_load)?;

    // The canonical hash the keystore signs under — derived from the op, never trusted
    // from the coordinator. Approver signatures must cover exactly this.
    let request_hash = wallet_policy::request_hash(&req.op);

    // K8: the nested request of `w_execute_extension` is parsed by a decoder
    // chosen in THIS image. If the account moved to a schema this build has no
    // decoder for, the parse would still succeed and mean something else — so
    // the policy below would be enforced against effects that are not the
    // request's. Refuse before that can happen, and before the key is touched.
    if let shared_tee_helpers::wallet_policy::Op::Call { method, .. } = &req.op {
        if let Err(reason) = shared_tee_helpers::binding::signing_version_gate(
            method,
            req.binding_kind.as_deref(),
            req.decoder_version,
        ) {
            return Err(ApiError::Forbidden(reason));
        }
    }

    // 1. Evaluate the on-chain policy. The keystore enforces the STATELESS subset
    //    (usage = None); the coordinator enforces stateful velocity. No policy on-chain
    //    → single-sig wallet → the owner's rules are empty.
    //
    //    Evaluated even then, because a few of the engine's rules are not the
    //    owner's to relax. `w_execute_extension` is the one that matters: it
    //    denies account-CONTROL operations (`add_extension` hands a stranger
    //    the whole lane) and anything whose effects cannot be stated. Those
    //    hold for every wallet — and a wallet with no policy is the state every
    //    wallet is in right after registration, so gating them behind "has a
    //    policy" would leave the default open.
    //
    //    What it is evaluated AGAINST is `policy_to_judge_by`, not an empty
    //    policy: rules, the approval block and `frozen` are all inert when
    //    unset, but capabilities are not — five of them default to DENY.
    let policy = load_wallet_policy(&state, &req.wallet_id, customer.as_ref()).await?;
    {
        let effective = policy_to_judge_by(policy.as_ref());
        let effective = effective.as_ref();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // Sole evaluator: full enforcement with coordinator-supplied usage (stateful)
        // when present; stateless-only otherwise.
        let usage = req
            .usage
            .as_ref()
            .map(wallet_policy::Usage::from_current_usage);
        match wallet_policy::evaluate(effective, &req.op, usage.as_ref(), now) {
            Decision::Frozen => return Err(ApiError::Forbidden("Wallet is frozen".to_string())),
            Decision::Deny { reason } => return Err(ApiError::Forbidden(reason)),
            Decision::RequiresApproval { threshold } => {
                // Owner-control multisig — for Built/HashPinned AND Trusted kinds. Verify real
                // approver signatures over exactly this op's request_hash before signing. For
                // Built/HashPinned the signed artifact is bound to the op by construction/hash.
                // For Trusted (swap/confidential/cross_chain_withdraw/payment_check) the approval
                // gates WHETHER the op runs and binds its policy-checked token+amount; the
                // coordinator supplies the off-chain artifact (e.g. the 1Click deposit address)
                // at execution and that destination is coordinator-trusted — a documented
                // tradeoff (we do not defend against a compromised coordinator; it is the access
                // path). See plan "Trusted ops under multisig".
                let wallet_pubkey =
                    derive_wallet_ed25519_pubkey(&state, customer.as_ref(), &req.wallet_id).await?;
                // `effective` IS the on-chain policy here: the stand-in for an
                // absent one names no `requires_approval` and carries no
                // approval block, and those are the only two things that can
                // produce this decision.
                verify_approvals(
                    &state,
                    effective,
                    &wallet_pubkey,
                    &request_hash,
                    req.approval_info.as_ref(),
                    threshold.max(1) as usize,
                )
                .await?;
            }
            Decision::Allow => {}
        }
    }

    // 3. Produce the artifact per bind mode.
    match wallet_policy::bind_mode(&req.op) {
        BindMode::Built => sign_built(&state, customer.as_ref(), &req, request_hash).await,
        BindMode::HashPinned => {
            sign_hash_pinned(&state, customer.as_ref(), &req, policy.as_ref(), request_hash).await
        }
        BindMode::Trusted => sign_trusted(&state, customer.as_ref(), &req, request_hash).await,
    }
}


/// Built kinds: the keystore CONSTRUCTS the artifact from the op fields, so what it
/// signs always equals what was approved.
/// Confidential-intents JWT auth challenge deadline horizon: now + 7 days (matches the
/// live confidential auth flow). The challenge carries an EMPTY `intents` array, so a
/// long horizon is harmless — it authenticates, it never authorizes a fund move.
const AUTH_DEADLINE_HORIZON_MS: u64 = 7 * 86_400 * 1_000;

async fn sign_built(
    state: &AppState,
    customer: Option<&near_primitives::types::AccountId>,
    req: &WalletSignRequest,
    request_hash: String,
) -> Result<Json<WalletSignResponse>, ApiError> {
    use near_primitives::transaction::{
        Action, DeleteAccountAction, FunctionCallAction, TransferAction,
    };
    use near_primitives::types::{AccountId, Balance, Gas};
    use shared_tee_helpers::wallet_policy::Op;
    use std::str::FromStr;

    match &req.op {
        Op::Transfer { to, amount } => {
            let to = to.clone();
            let deposit: u128 = amount
                .parse()
                .map_err(|e| ApiError::BadRequest(format!("Invalid amount: {}", e)))?;
            let resp = sign_near_transaction(
                state,
                customer,
                &req.wallet_id,
                        request_hash,
                move |_signer| {
                    let receiver = AccountId::from_str(&to)
                        .map_err(|e| ApiError::BadRequest(format!("Invalid 'to': {}", e)))?;
                    Ok((receiver, vec![Action::Transfer(TransferAction { deposit: Balance::from_yoctonear(deposit) })]))
                },
            )
            .await?;
            Ok(Json(resp))
        }
        Op::Call {
            to,
            method,
            args_base64,
            gas,
            deposit,
            } => {
            let to = to.clone();
            let method = method.clone();
            let args = base64::decode(args_base64)
                .map_err(|e| ApiError::BadRequest(format!("Invalid args_base64: {}", e)))?;
            let gas: u64 = gas
                .parse()
                .map_err(|e| ApiError::BadRequest(format!("Invalid gas: {}", e)))?;
            let deposit: u128 = deposit
                .parse()
                .map_err(|e| ApiError::BadRequest(format!("Invalid deposit: {}", e)))?;
            let resp = sign_near_transaction(
                state,
                customer,
                &req.wallet_id,
                        request_hash,
                move |_signer| {
                    let receiver = AccountId::from_str(&to)
                        .map_err(|e| ApiError::BadRequest(format!("Invalid 'to': {}", e)))?;
                    Ok((
                        receiver,
                        vec![Action::FunctionCall(Box::new(FunctionCallAction {
                            method_name: method,
                            args,
                            gas: Gas::from_gas(gas),
                            deposit: Balance::from_yoctonear(deposit),
                        }))],
                    ))
                },
            )
            .await?;
            Ok(Json(resp))
        }
        Op::Delete { beneficiary } => {
            let beneficiary = beneficiary.clone();
            let resp = sign_near_transaction(
                state,
                customer,
                &req.wallet_id,
                request_hash,
                move |signer| {
                    let beneficiary_id = AccountId::from_str(&beneficiary)
                        .map_err(|e| ApiError::BadRequest(format!("Invalid beneficiary: {}", e)))?;
                    // Deleting own account: receiver == signer.
                    Ok((
                        signer.clone(),
                        vec![Action::DeleteAccount(DeleteAccountAction { beneficiary_id })],
                    ))
                },
            )
            .await?;
            Ok(Json(resp))
        }
        Op::Withdraw { to, amount, token, .. } => {
            // Construct the NEP-413 intent message FROM the op (fresh deadline + nonce).
            let signer_id = wallet_implicit_account(state, customer, &req.wallet_id).await?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let deadline = unix_to_iso8601(now + 300);
            let message = build_withdraw_intent_message(&signer_id, to, amount, token, &deadline);
            let mut nonce = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
            // NEAR Intents is mainnet-only (no testnet solvers), so the verifier is always
            // mainnet `intents.near`. The NEP-413 recipient is bound into the signature, so it
            // must match the verifier the withdraw intent will actually execute against.
            let recipient = "intents.near".to_string();
            let (signature_base58, public_key) =
                sign_nep413(state, customer, &req.wallet_id, &message, nonce, &recipient).await?;
            let mut resp = WalletSignResponse::new(request_hash);
            resp.signature_base58 = Some(signature_base58);
            resp.public_key = Some(public_key);
            resp.message = Some(message);
            resp.nonce_base64 = Some(base64::encode(nonce));
            resp.recipient = Some(recipient);
            Ok(Json(resp))
        }
        Op::IntentsTransfer { to, amount, token, .. } => {
            // Construct the NEP-413 `transfer` intent message FROM the op (fresh deadline +
            // nonce). Internal move INSIDE intents.near (defuse `transfer`): funds stay in the
            // intents pool, credited to `to`'s mt balance — NOT a withdrawal out. Built → the
            // keystore (not the coordinator) fixes the recipient, so it cannot be substituted.
            let signer_id = wallet_implicit_account(state, customer, &req.wallet_id).await?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let deadline = unix_to_iso8601(now + 300);
            let message = build_transfer_intent_message(&signer_id, to, amount, token, &deadline);
            let mut nonce = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
            // Same verifier as withdraw: intents.near (mainnet-only). The NEP-413 recipient is
            // bound into the signature and must match the verifier the intent executes against.
            let recipient = "intents.near".to_string();
            let (signature_base58, public_key) =
                sign_nep413(state, customer, &req.wallet_id, &message, nonce, &recipient).await?;
            let mut resp = WalletSignResponse::new(request_hash);
            resp.signature_base58 = Some(signature_base58);
            resp.public_key = Some(public_key);
            resp.message = Some(message);
            resp.nonce_base64 = Some(base64::encode(nonce));
            resp.recipient = Some(recipient);
            Ok(Json(resp))
        }
        Op::Auth { purpose, seed, vault_id } if purpose == "jwt" => {
            // Confidential-intents JWT auth challenge. Unlike the raw schemes below, this
            // is a NEP-413 signature over `intents.near` — but the keystore BUILDS the
            // challenge itself with an EMPTY `intents` array (provably non-fund-moving),
            // so it can never be a fund-moving intent and never goes through
            // `sign_message`'s recipient allowlist (which would otherwise have to list the
            // fund-moving `intents.near`). `seed` is unused (the signer is derived);
            // `vault_id` is not carried.
            let _ = seed;
            if vault_id.is_some() {
                return Err(ApiError::BadRequest(
                    "auth purpose 'jwt' does not carry vault_id".to_string(),
                ));
            }
            let near_client = state.near_client.as_ref().ok_or_else(|| {
                ApiError::InternalError("NEAR client not configured".to_string())
            })?;
            // signer_id = the wallet's own 64-hex implicit account — derived here, never
            // trusted from the caller (binds the challenge to this wallet's key).
            let signer_id = wallet_implicit_account(state, customer, &req.wallet_id).await?;
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            let deadline_ms = now_ms + AUTH_DEADLINE_HORIZON_MS;
            let issued_ns = now_ms.saturating_mul(1_000_000);
            let deadline_ns = deadline_ms.saturating_mul(1_000_000);

            // Fresh 4-byte salt from intents.near.current_salt() (JSON-quoted hex string).
            let intents_id = AccountId::from_str("intents.near")
                .map_err(|e| ApiError::InternalError(format!("Invalid intents account: {}", e)))?;
            let salt_val = near_client
                .view_call_json(&intents_id, "current_salt", serde_json::json!({}))
                .await
                .map_err(|e| {
                    ApiError::InternalError(format!("current_salt fetch failed: {}", e))
                })?;
            let salt_hex = salt_val.as_str().ok_or_else(|| {
                ApiError::InternalError("current_salt did not return a string".to_string())
            })?;
            let salt_bytes = hex::decode(salt_hex)
                .map_err(|e| ApiError::InternalError(format!("current_salt not hex: {}", e)))?;
            let salt: [u8; 4] = salt_bytes.as_slice().try_into().map_err(|_| {
                ApiError::InternalError(format!(
                    "current_salt expected 4 bytes, got {}",
                    salt_bytes.len()
                ))
            })?;

            let mut random = [0u8; 7];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut random);
            let nonce = shared_tee_helpers::wallet_policy::build_jwt_versioned_nonce(
                salt, deadline_ns, issued_ns, random,
            );
            let deadline_iso = unix_to_iso8601(deadline_ms / 1000);
            let message =
                shared_tee_helpers::wallet_policy::build_jwt_auth_message(&deadline_iso, &signer_id);
            let recipient = "intents.near".to_string();
            let (signature_base58, public_key) =
                sign_nep413(state, customer, &req.wallet_id, &message, nonce, &recipient).await?;
            let mut resp = WalletSignResponse::new(request_hash);
            resp.signature_base58 = Some(signature_base58);
            resp.public_key = Some(public_key);
            resp.message = Some(message);
            resp.nonce_base64 = Some(base64::encode(nonce));
            resp.recipient = Some(recipient);
            Ok(Json(resp))
        }
        Op::Auth { purpose, seed, vault_id } => {
            // Construct the exact coordinator auth string (fresh timestamp) and sign it
            // RAW ed25519 — NOT NEP-413. The `auth:`/`register:`/`api-key:` prefix is
            // domain-separated from a 32-byte tx hash, so this can never forge a tx and
            // needs no raw_sign capability. Non-fund → evaluate() already allowed it.
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let message = shared_tee_helpers::wallet_policy::build_auth_message(
                purpose,
                seed,
                now,
                vault_id.as_deref(),
            )
            .map_err(ApiError::BadRequest)?;

            use ed25519_dalek::Signer;
            let seed_path = wallet_seed(&req.wallet_id, "near");
            let keystore = state.keystore.read().await;
            let (signing_key, verifying_key) = keystore
                .derive_keypair(customer, &seed_path)
                .map_err(|e| ApiError::InternalError(format!("Key derivation failed: {}", e)))?;
            let sig = signing_key.sign(message.as_bytes());

            let mut resp = WalletSignResponse::new(request_hash);
            resp.auth_message = Some(message);
            resp.auth_timestamp = Some(now);
            resp.auth_signature_base58 = Some(bs58::encode(sig.to_bytes()).into_string());
            resp.public_key = Some(format!(
                "ed25519:{}",
                bs58::encode(verifying_key.to_bytes()).into_string()
            ));
            Ok(Json(resp))
        }
        _ => Err(ApiError::InternalError(
            "sign_built invoked for a non-Built op".to_string(),
        )),
    }
}

/// Hash-pinned kinds: `raw` signs supplied bytes iff `sha256(bytes) == op.payload_hash`;
/// `sign_message` signs a NEP-413 auth payload built from the supplied message (pinned
/// by `op.message_hash`) and `op.recipient`. The recipient must be in the policy's
/// `sign_message.allowed_recipients` allowlist (default-deny under a policy); a wallet
/// with no on-chain policy is single-sig and unrestricted.
/// `policy` is the STATED policy (`None` = the owner has written none). It is NOT
/// the stand-in from `policy_to_judge_by`: `sign_message_recipient_allowed` below
/// reads it directly and treats "no policy" as unrestricted, which the stand-in
/// would not reproduce.
async fn sign_hash_pinned(
    state: &AppState,
    customer: Option<&near_primitives::types::AccountId>,
    req: &WalletSignRequest,
    policy: Option<&shared_tee_helpers::wallet_policy::Policy>,
    request_hash: String,
) -> Result<Json<WalletSignResponse>, ApiError> {
    use sha2::{Digest, Sha256};
    use shared_tee_helpers::wallet_policy::Op;

    let artifact = req.artifact.as_ref();
    match &req.op {
        Op::Raw {
            chain,
            payload_hash,
                ..
        } => {
            let bytes_b64 = artifact
                .and_then(|a| a.bytes_base64.as_ref())
                .ok_or_else(|| {
                    ApiError::BadRequest("raw op requires artifact.bytes_base64".to_string())
                })?;
            let bytes = base64::decode(bytes_b64)
                .map_err(|e| ApiError::BadRequest(format!("Invalid bytes_base64: {}", e)))?;
            let computed = hex::encode(Sha256::digest(&bytes));
            if !computed.eq_ignore_ascii_case(payload_hash) {
                return Err(ApiError::Forbidden(
                    "supplied bytes do not match op.payload_hash".to_string(),
                ));
            }
            let chain_l = chain.to_lowercase();
            // EVM signing lives on the dedicated /wallet/evm/* endpoints: they
            // use the canonical `wallet:{id}:evm` key (one address across all EVM
            // chains), produce a RECOVERABLE keccak signature (r‖s‖v), and are
            // gated by the `evm_sign` capability. The legacy Op::Raw secp256k1
            // path used a per-chain seed (`wallet:{id}:ethereum`) that no longer
            // matches the derived address AND a non-recoverable SHA-256 signature
            // — so it could only return a signature that fails to ecrecover to the
            // wallet's EVM address. Refuse it and point callers at the real path.
            if is_evm_chain(&chain_l) {
                return Err(ApiError::BadRequest(format!(
                    "Raw signing is not supported for EVM chain '{}'. Use POST /wallet/v1/evm/sign-typed-data, /sign-message, or /sign-transaction.",
                    chain_l
                )));
            }
            // Only the two ed25519 chains this keystore holds keys for. The
            // chain is a seed segment, so an arbitrary string here would name
            // an arbitrary seed — `evm` spells the secp256k1 key, `near:check:0`
            // spells an exported payment-check key.
            if chain_l != "near" && !is_solana_chain(&chain_l) {
                return Err(ApiError::BadRequest(format!(
                    "Raw signing supports chains near and solana, not '{}'",
                    chain_l
                )));
            }
            let seed = wallet_seed(&req.wallet_id, &chain_l);
            let keystore = state.keystore.read().await;
            let sig = keystore
                .sign(customer, &seed, &bytes)
                .map_err(|e| ApiError::InternalError(format!("Signing failed: {}", e)))?;
            let mut resp = WalletSignResponse::new(request_hash);
            resp.signature_base64 = Some(base64::encode(sig.to_bytes()));
            Ok(Json(resp))
        }
        Op::SignMessage {
            message_hash,
            recipient,
                ..
        } => {
            // Hard exclusion of the intents verifiers, ABOVE the owner allowlist: an owner
            // mis-listing `intents.near`/`intents.far` in allowed_recipients
            // would re-open the fund path (a "login" signature replayable as a fund-moving
            // NEP-413 intent). sign_message can NEVER target an intents verifier — those go
            // through the gated Trusted ops only.
            if is_trusted_recipient(recipient) {
                return Err(ApiError::Forbidden(format!(
                    "sign_message recipient '{}' is a fund-moving intents verifier and is never \
                     allowed here (even if listed in allowed_recipients)",
                    recipient
                )));
            }
            // Domain separation lives here: a default-DENY allowlist of auth recipients
            // (see `sign_message_recipient_allowed`).
            if !sign_message_recipient_allowed(policy, recipient) {
                return Err(ApiError::Forbidden(format!(
                    "sign_message recipient '{}' is not in the policy's allowed_recipients (default-deny)",
                    recipient
                )));
            }
            let artifact = artifact.ok_or_else(|| {
                ApiError::BadRequest(
                    "sign_message requires artifact.message + nonce_base64".to_string(),
                )
            })?;
            let message = artifact.message.as_ref().ok_or_else(|| {
                ApiError::BadRequest("sign_message requires artifact.message".to_string())
            })?;
            let nonce_b64 = artifact.nonce_base64.as_ref().ok_or_else(|| {
                ApiError::BadRequest("sign_message requires artifact.nonce_base64".to_string())
            })?;
            // Hash-pin the message to the canonical op.
            let computed = hex::encode(Sha256::digest(message.as_bytes()));
            if !computed.eq_ignore_ascii_case(message_hash) {
                return Err(ApiError::Forbidden(
                    "supplied message does not match op.message_hash".to_string(),
                ));
            }
            let nonce_bytes = base64::decode(nonce_b64)
                .map_err(|e| ApiError::BadRequest(format!("Invalid nonce_base64: {}", e)))?;
            if nonce_bytes.len() != 32 {
                return Err(ApiError::BadRequest(format!(
                    "Invalid nonce length: {} (expected 32)",
                    nonce_bytes.len()
                )));
            }
            let nonce: [u8; 32] = nonce_bytes.try_into().unwrap();
            // recipient is taken from the canonical op, so it is bound into the payload.
            // So is `connector_id`: a sign_message made on behalf of a connector is
            // signed by that connector's own key, and a third party verifying it sees
            // the connector's public key rather than the wallet's.
            let (signature_base58, public_key) = sign_nep413(
                state,
                customer,
                &req.wallet_id,
                        message,
                nonce,
                recipient,
            )
            .await?;
            let mut resp = WalletSignResponse::new(request_hash);
            resp.signature_base58 = Some(signature_base58);
            resp.public_key = Some(public_key);
            resp.message = Some(message.clone());
            resp.nonce_base64 = Some(nonce_b64.clone());
            resp.recipient = Some(recipient.clone());
            Ok(Json(resp))
        }
        _ => Err(ApiError::InternalError(
            "sign_hash_pinned invoked for a non-HashPinned op".to_string(),
        )),
    }
}

/// Trusted kinds (`swap`/`confidential`): the artifact is generated externally (a
/// 1Click quote / generate-intent) AFTER approval, so it can't be reconstructed from
/// the op. Capability + policy + multisig were already enforced on the op; the keystore
/// signs the supplied NEP-413 artifact, trusting the generator.
async fn sign_trusted(
    state: &AppState,
    customer: Option<&near_primitives::types::AccountId>,
    req: &WalletSignRequest,
    request_hash: String,
) -> Result<Json<WalletSignResponse>, ApiError> {
    let artifact = req.artifact.as_ref().ok_or_else(|| {
        ApiError::BadRequest(
            "trusted op requires artifact.message + nonce_base64 + recipient".to_string(),
        )
    })?;
    let message = artifact
        .message
        .as_ref()
        .ok_or_else(|| ApiError::BadRequest("trusted op requires artifact.message".to_string()))?;
    let nonce_b64 = artifact
        .nonce_base64
        .as_ref()
        .ok_or_else(|| ApiError::BadRequest("trusted op requires artifact.nonce_base64".to_string()))?;
    let recipient = artifact
        .recipient
        .as_ref()
        .ok_or_else(|| ApiError::BadRequest("trusted op requires artifact.recipient".to_string()))?;
    // Pin the NEP-413 recipient to the intents verifiers. Trusted ops are intents-only — every
    // kind routes through intents.near (the public shard: swap/cross_chain_withdraw/limit_order/
    // payment_check transfer intents) or intents.far (the confidential shard's generate-intent).
    // NEAR Intents is mainnet-only (no testnet solvers), so there is no testnet verifier here.
    // Without this, a Trusted op could emit a NEP-413 signature bound to ANY verifier (the very
    // class sign_message's allowlist closes). VERIFIED: no Trusted flow uses another recipient.
    if !is_trusted_recipient(recipient) {
        return Err(ApiError::Forbidden(format!(
            "trusted op recipient '{}' is not an intents verifier (intents.near/intents.far)",
            recipient
        )));
    }
    let nonce_bytes = base64::decode(nonce_b64)
        .map_err(|e| ApiError::BadRequest(format!("Invalid nonce_base64: {}", e)))?;
    if nonce_bytes.len() != 32 {
        return Err(ApiError::BadRequest(format!(
            "Invalid nonce length: {} (expected 32)",
            nonce_bytes.len()
        )));
    }
    let nonce: [u8; 32] = nonce_bytes.try_into().unwrap();
    let (signature_base58, public_key) =
        sign_nep413(state, customer, &req.wallet_id, message, nonce, recipient).await?;
    let mut resp = WalletSignResponse::new(request_hash);
    resp.signature_base58 = Some(signature_base58);
    resp.public_key = Some(public_key);
    resp.message = Some(message.clone());
    resp.nonce_base64 = Some(nonce_b64.clone());
    resp.recipient = Some(recipient.clone());
    Ok(Json(resp))
}

/// The policy to judge a request by, given what the owner has STATED.
///
/// `None` — no policy on chain — is not the same statement as an empty policy,
/// and standing one in for the other is what broke custody: `check_capabilities`
/// falls back to each op's DEFAULT when no capability is named, and six of them
/// (`raw_sign`, `confidential`, `payment_check`, `swap`, `cross_chain_withdraw`,
/// `limit_order`) default to DENY. Those defaults exist so a STATED policy cannot be walked
/// around — a claimable link routes funds past a `to` whitelist, raw signing
/// past the transaction-type gate. A wallet with no policy has no whitelist and
/// no type gate to walk around, so there is nothing for them to protect: a fresh
/// wallet may do anything, and the owner funds it and then states what it may
/// not do.
///
/// An absent policy is still EVALUATED rather than short-circuited to `Allow`,
/// because one rule is not the owner's to relax: `w_execute_extension` denies
/// account-control operations and effects that cannot be stated, on every
/// wallet. The capabilities named below do not touch it.
///
/// Both doors go through here so the substitution is made once and can be
/// tested once.
fn policy_to_judge_by(
    stated: Option<&shared_tee_helpers::wallet_policy::Policy>,
) -> std::borrow::Cow<'_, shared_tee_helpers::wallet_policy::Policy> {
    use std::borrow::Cow;
    let Some(stated) = stated else {
        let open = || {
            Some(shared_tee_helpers::wallet_policy::Capability {
                allowed: Some(true),
                ..Default::default()
            })
        };
        return Cow::Owned(shared_tee_helpers::wallet_policy::Policy {
            // Exactly the capabilities `check_capabilities` would otherwise
            // default to DENY. `sign_message`, `evm_sign` and `solana_sign` are
            // NOT named: their engines read the STATED policy directly (see
            // `sign_message_recipient_allowed` and `chain_sign_decision`, both
            // of which treat `None` as unrestricted), so naming them here would
            // be dead code that also answers wrongly if it were ever reached —
            // `chain_sign_decision` denies a raw transaction unless `raw_tx`
            // is explicitly true.
            capabilities: Some(shared_tee_helpers::wallet_policy::Capabilities {
                raw_sign: open(),
                confidential: open(),
                payment_check: open(),
                swap: open(),
                cross_chain_withdraw: open(),
                limit_order: open(),
                sign_message: None,
                evm_sign: None,
                solana_sign: None,
            }),
            ..Default::default()
        });
    };
    Cow::Borrowed(stated)
}


/// Pre-flight policy check for a canonical `op` — the SAME engine `/wallet/sign` uses.
///
/// Decrypts the on-chain policy (which NEVER leaves the keystore) and runs
/// `wallet_policy::evaluate(policy, op, usage, now)`. Returns only the decision plus the
/// canonical `request_hash` the dashboard signs.
async fn wallet_check_policy_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<WalletCheckPolicyRequest>,
) -> Result<Json<WalletCheckPolicyResponse>, ApiError> {
    use shared_tee_helpers::wallet_policy::{self, Decision};

    if !state.is_ready() {
        return Err(ApiError::Unauthorized("Keystore not ready.".to_string()));
    }
    validate_wallet_id(&req.wallet_id)?;
    let customer = extract_customer_from_header(&headers)?;
    state
        .ensure_customer_loaded(customer.as_ref())
        .await
        .map_err(ApiError::from_customer_load)?;

    let request_hash = wallet_policy::request_hash(&req.op);

    // Decrypt the policy: inline override (TEST-ONLY) or fetch+decrypt from chain.
    //
    // The inline path lets the CALLER supply the policy for this pre-flight decision — a
    // coordinator-fabricated "allowed" could mislead a UI. It is safe for fund movement
    // (`/wallet/sign` ALWAYS reads + decrypts the on-chain policy via `load_wallet_policy`
    // and NEVER accepts an inline policy, so a fabricated check-policy can't authorize a
    // sign), but to keep this advisory endpoint honest in production it is gated behind an
    // explicit test flag. Default (prod): inline is rejected, on-chain only.
    if req.encrypted_policy_data.is_some()
        && std::env::var("KEYSTORE_ALLOW_INLINE_POLICY").map(|v| v == "1" || v == "true").unwrap_or(false) == false
    {
        return Err(ApiError::Forbidden(
            "inline encrypted_policy_data is disabled (set KEYSTORE_ALLOW_INLINE_POLICY=1 for \
             local testing); check-policy reads the on-chain policy in production".to_string(),
        ));
    }
    let policy: Option<wallet_policy::Policy> = if let Some(ref inline_data) = req.encrypted_policy_data {
        let seed = format!("wallet-policy:{}", req.wallet_id);
        let encrypted_bytes = base64::decode(inline_data)
            .map_err(|e| ApiError::InternalError(format!("Invalid base64 in encrypted_data: {}", e)))?;
        let keystore = state.keystore.read().await;
        let decrypted = keystore
            .decrypt(customer.as_ref(), &seed, &encrypted_bytes)
            .map_err(|e| ApiError::InternalError(format!("Policy decryption failed: {}", e)))?;
        let p: wallet_policy::Policy = serde_json::from_slice(&decrypted)
            .map_err(|e| ApiError::InternalError(format!("Policy JSON parse failed: {}", e)))?;
        Some(p)
    } else {
        load_wallet_policy(&state, &req.wallet_id, customer.as_ref()).await?
    };

    // No policy on-chain → judged by the stand-in (`policy_to_judge_by`), not a
    // short-circuit to "allowed": `w_execute_extension` is denied for
    // account-control operations and for effects that cannot be stated,
    // whatever the owner did or did not configure. Returning early here would
    // also let the pre-flight answer "allowed" for a request the signing path
    // then refuses, which is exactly the split this endpoint exists to avoid.
    //
    // The pre-flight and the signing path MUST make this substitution the same
    // way, which is why both call the one function.
    let policy = policy_to_judge_by(policy.as_ref()).into_owned();

    // Narrow carve-out surfaced to the coordinator (the rest of the policy stays here).
    let webhook_url = policy.webhook_url.clone();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // K8, same gate as the signing path — a pre-flight that answered
    // differently would tell a caller "allowed" and then refuse the signature.
    if let shared_tee_helpers::wallet_policy::Op::Call { method, .. } = &req.op {
        if let Err(reason) = shared_tee_helpers::binding::signing_version_gate(
            method,
            req.binding_kind.as_deref(),
            req.decoder_version,
        ) {
            return Ok(Json(WalletCheckPolicyResponse {
                allowed: false,
                frozen: false,
                requires_approval: None,
                required_approvals: None,
                reason: Some(reason),
                request_hash: Some(request_hash),
                webhook_url: None,
            }));
        }
    }

    let usage = req.usage.as_ref().map(wallet_policy::Usage::from_current_usage);
    let decision = wallet_policy::evaluate(&policy, &req.op, usage.as_ref(), now);

    let response = match decision {
        Decision::Allow => WalletCheckPolicyResponse {
            allowed: true,
            frozen: false,
            requires_approval: None,
            required_approvals: None,
            reason: None,
            request_hash: Some(request_hash),
            webhook_url,
        },
        Decision::Frozen => WalletCheckPolicyResponse {
            allowed: false,
            frozen: true,
            requires_approval: None,
            required_approvals: None,
            reason: Some("Wallet is frozen".to_string()),
            request_hash: Some(request_hash),
            webhook_url,
        },
        Decision::Deny { reason } => WalletCheckPolicyResponse {
            allowed: false,
            frozen: false,
            requires_approval: None,
            required_approvals: None,
            reason: Some(reason),
            request_hash: Some(request_hash),
            webhook_url,
        },
        Decision::RequiresApproval { threshold } => {
            // Owner-control multisig applies to Built/HashPinned AND Trusted kinds. The
            // coordinator creates a pending approval; a Trusted op is signed against the
            // coordinator-supplied artifact AFTER approval (off-chain destination stays
            // coordinator-trusted — documented tradeoff). See plan "Trusted ops under multisig".
            WalletCheckPolicyResponse {
                allowed: true,
                frozen: false,
                requires_approval: Some(true),
                required_approvals: Some(threshold as i32),
                reason: None,
                request_hash: Some(request_hash),
                webhook_url,
            }
        }
    };
    Ok(Json(response))
}

/// Encrypt a wallet policy for on-chain storage
async fn wallet_encrypt_policy_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<WalletEncryptPolicyRequest>,
) -> Result<Json<WalletEncryptPolicyResponse>, ApiError> {
    if !state.is_ready() {
        return Err(ApiError::Unauthorized(
            "Keystore not ready.".to_string(),
        ));
    }

    validate_wallet_id(&req.wallet_id)?;
    let customer = extract_customer_from_header(&headers)?;
    state
        .ensure_customer_loaded(customer.as_ref())
        .await
        .map_err(ApiError::from_customer_load)?;

    let seed = format!("wallet-policy:{}", req.wallet_id);
    let keystore = state.keystore.read().await;

    let encrypted = keystore
        .encrypt(customer.as_ref(), &seed, req.policy_json.as_bytes())
        .map_err(|e| ApiError::InternalError(format!("Encryption failed: {}", e)))?;

    Ok(Json(WalletEncryptPolicyResponse {
        encrypted_base64: base64::encode(&encrypted),
    }))
}

/// Decrypt a wallet policy for owner-view / config sync. This is NOT the signing
/// decision path (`/check-policy` and `/wallet/sign` decide WITHOUT returning the
/// policy). The coordinator caches the result in `wallet_accounts.policy_json` and uses
/// it for owner display + `authorized_key_hashes` — pre-existing behavior.
async fn wallet_decrypt_policy_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<WalletDecryptPolicyRequest>,
) -> Result<Json<WalletDecryptPolicyResponse>, ApiError> {
    if !state.is_ready() {
        return Err(ApiError::Unauthorized("Keystore not ready.".to_string()));
    }

    validate_wallet_id(&req.wallet_id)?;
    let customer = extract_customer_from_header(&headers)?;
    state
        .ensure_customer_loaded(customer.as_ref())
        .await
        .map_err(ApiError::from_customer_load)?;

    let seed = format!("wallet-policy:{}", req.wallet_id);
    let encrypted_bytes = base64::decode(&req.encrypted_policy_data)
        .map_err(|e| ApiError::BadRequest(format!("Invalid base64 in encrypted_policy_data: {}", e)))?;
    let decrypted = {
        let keystore = state.keystore.read().await;
        keystore
            .decrypt(customer.as_ref(), &seed, &encrypted_bytes)
            .map_err(|e| ApiError::InternalError(format!("Policy decryption failed: {}", e)))?
    };
    let policy: serde_json::Value = serde_json::from_slice(&decrypted)
        .map_err(|e| ApiError::InternalError(format!("Policy JSON parse failed: {}", e)))?;

    Ok(Json(WalletDecryptPolicyResponse { policy }))
}

#[cfg(test)]
#[path = "api_tests.rs"]
mod api_tests;
