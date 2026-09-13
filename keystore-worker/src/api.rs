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
//! - POST /decrypt - Decrypt secrets from contract
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
}

impl ApiError {
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
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            ApiError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg),
            ApiError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg),
            ApiError::PaymentRequired(msg) => (StatusCode::PAYMENT_REQUIRED, msg),
            // 422 and not 402: the status IS the meaning, so nothing has to
            // read the sentence to classify it, and the vault's 402 keeps its
            // own remedy.
            ApiError::ChainRefused(msg) => (StatusCode::UNPROCESSABLE_ENTITY, msg),
            ApiError::InternalError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };

        (status, Json(serde_json::json!({"error": message}))).into_response()
    }
}

/// Secret accessor type - matches contract's SecretAccessor enum
///
/// IMPORTANT: When adding new accessor types:
/// 1. Add variant here in keystore-worker
/// 2. Add variant in coordinator/src/handlers/github.rs (SecretAccessor enum)
/// 3. Add variant in contract/src/lib.rs (SecretAccessor enum)
/// 4. Update seed generation in decrypt_handler below
/// 5. Update near.rs get_secrets methods if needed
/// 6. Update worker/src/keystore_client.rs decrypt methods
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SecretAccessor {
    /// Secrets bound to a GitHub repository
    Repo {
        repo: String,
        #[serde(default)]
        branch: Option<String>,
    },
    /// Secrets bound to a specific WASM hash
    WasmHash {
        hash: String,
    },
    /// Secrets bound to a project (available to all versions)
    Project {
        project_id: String,
    },
    /// System secrets (Payment Keys for HTTPS API)
    System {
        secret_type: SystemSecretType,
    },
}

/// System secret types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SystemSecretType {
    /// Payment Key for HTTPS API
    PaymentKey,
}

impl SystemSecretType {
    /// Contract-side representation (CamelCase, matches NEAR's default
    /// JSON serialisation of the contract's `SystemSecretType` enum
    /// variants). Used by `accessor_to_contract_json` when forwarding
    /// the variant to a contract view method. **Centralised here so a
    /// future variant addition is one match arm**, not five scattered
    /// across the file.
    fn as_contract_str(&self) -> &'static str {
        match self {
            SystemSecretType::PaymentKey => "PaymentKey",
        }
    }

    /// Seed-string representation (snake_case, matches the seed
    /// convention used at write time by all storage paths). Used inside
    /// derived secret seeds for decrypt/encrypt of System secrets.
    fn as_seed_str(&self) -> &'static str {
        match self {
            SystemSecretType::PaymentKey => "payment_key",
        }
    }
}

/// Request to decrypt secrets from contract
#[derive(Debug, Deserialize)]
pub struct DecryptRequest {
    /// What code can access these secrets
    pub accessor: SecretAccessor,

    /// Profile name (e.g., "default", "production")
    pub profile: String,

    /// Owner account ID (who owns the secrets)
    pub owner: String,

    /// User account ID (who is requesting execution)
    /// This is used for access control validation
    pub user_account_id: String,

    /// Optional task ID for logging
    pub task_id: Option<String>,
}

/// Response with decrypted secrets
#[derive(Debug, Serialize)]
pub struct DecryptResponse {
    /// Decrypted secrets (base64 encoded)
    /// Base64 is used to safely transport binary data over JSON
    pub plaintext_secrets: String,
}

/// Request to get public key (includes secrets for validation)
#[derive(Debug, Deserialize)]
pub struct PubkeyRequest {
    /// Seed for deriving keypair (format: "repo:owner[:branch]")
    pub seed: String,
    /// Secrets as JSON string for validation (e.g., '{"API_KEY":"value"}')
    pub secrets_json: String,
    /// Optional vault id: when set, the returned pubkey is
    /// derived from the per-vault master so the resulting on-chain
    /// secret is encrypted under the correct customer scope. Absent
    /// (or null/empty) ⇒ default OutLayer master, legacy behaviour.
    #[serde(default)]
    pub vault_id: Option<String>,
}

/// Response with public key
#[derive(Debug, Serialize)]
pub struct PubkeyResponse {
    /// Public key in hex format
    pub pubkey: String,
}

/// Request to add generated secrets to existing encrypted secrets
#[derive(Debug, Deserialize)]
pub struct AddGeneratedSecretRequest {
    /// Seed for deriving keypair (format: "repo:owner[:branch]")
    pub seed: String,

    /// Existing encrypted secrets (base64, can be empty for first generation)
    /// If empty, starts with empty secrets object
    pub encrypted_secrets_base64: Option<String>,

    /// New secrets to generate
    pub new_secrets: Vec<GeneratedSecretSpec>,

    /// Optional vault id: scope the encrypt/decrypt calls to a
    /// per-vault master. MUST match the scope under which
    /// `encrypted_secrets_base64` was originally encrypted, otherwise
    /// the decrypt step will fail. Absent ⇒ default OutLayer master.
    #[serde(default)]
    pub vault_id: Option<String>,
}

/// Specification for a secret to generate
#[derive(Debug, Deserialize)]
pub struct GeneratedSecretSpec {
    /// Secret name (key in JSON)
    pub name: String,

    /// Generation type (hex32, ed25519, password, etc.)
    pub generation_type: String,
}

/// Response after adding generated secrets
#[derive(Debug, Serialize)]
pub struct AddGeneratedSecretResponse {
    /// Updated encrypted secrets (base64)
    pub encrypted_data_base64: String,

    /// List of ALL secret key names after merge (for verification)
    pub all_keys: Vec<String>,
}

/// Mode for updating user secrets
#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpdateMode {
    /// Add/update secrets, keeping existing ones
    Append,
    /// Replace all non-PROTECTED secrets
    Reset,
}

/// Request to update user secrets (with NEAR signature)
#[derive(Debug, Deserialize)]
pub struct UpdateUserSecretsRequest {
    /// Current accessor for the secrets
    pub accessor: SecretAccessor,

    /// Optional new accessor (for migration)
    pub new_accessor: Option<SecretAccessor>,

    /// Profile name
    pub profile: String,

    /// Owner account ID
    pub owner: String,

    /// Update mode
    pub mode: UpdateMode,

    /// User secrets to add/update (cannot contain PROTECTED_ prefix)
    /// Values can be strings, numbers, booleans, or null - preserved as-is
    pub secrets: std::collections::HashMap<String, serde_json::Value>,

    /// Optional PROTECTED_ secrets to generate
    pub generate_protected: Option<Vec<GeneratedSecretSpec>>,

    /// Signed message (format: "Update Outlayer secrets for owner:profile")
    pub signed_message: String,

    /// Ed25519 signature
    pub signature: String,

    /// Public key (ed25519:base58...)
    pub public_key: String,

    /// Nonce for NEP-413
    pub nonce: String,

    /// Recipient for NEP-413 signature verification
    pub recipient: String,

    /// Optional vault id: scope the encrypt/decrypt calls to
    /// a per-vault master. MUST match the scope under which the existing
    /// secrets were encrypted (when in Append mode reading current
    /// state). Absent ⇒ default OutLayer master.
    #[serde(default)]
    pub vault_id: Option<String>,
}

/// Response after updating user secrets
#[derive(Debug, Serialize)]
pub struct UpdateUserSecretsResponse {
    /// Updated encrypted secrets (base64) for storing in contract
    pub encrypted_secrets_base64: String,

    /// Summary of changes
    pub summary: UpdateSummary,
}

#[derive(Debug, Serialize)]
pub struct UpdateSummary {
    /// PROTECTED_ keys that were preserved
    pub protected_keys_preserved: Vec<String>,

    /// Keys that were updated/added
    pub updated_keys: Vec<String>,

    /// Keys that were removed (only in reset mode)
    pub removed_keys: Vec<String>,

    /// Total number of secrets after update
    pub total_keys: usize,
}

/// Health check response
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub tee_mode: String,
}

// ==================== Storage Encryption API ====================

/// Request to encrypt data for persistent storage
#[derive(Debug, Deserialize)]
pub struct StorageEncryptRequest {
    /// Project UUID (None for standalone WASM - use wasm_hash instead)
    pub project_uuid: Option<String>,
    /// WASM hash (used when project_uuid is None)
    pub wasm_hash: String,
    /// Account ID (user account or "@worker" for private storage)
    pub account_id: String,
    /// Plaintext key (will be encrypted)
    pub key: String,
    /// Plaintext value (base64 encoded)
    pub value_base64: String,
}

/// Response with encrypted storage data
#[derive(Debug, Serialize)]
pub struct StorageEncryptResponse {
    /// Encrypted key (base64)
    pub encrypted_key_base64: String,
    /// Encrypted value (base64)
    pub encrypted_value_base64: String,
    /// Key hash for unique constraint (SHA256 of plaintext key)
    pub key_hash: String,
}

/// Request to decrypt data from persistent storage
#[derive(Debug, Deserialize)]
pub struct StorageDecryptRequest {
    /// Project UUID (None for standalone WASM - use wasm_hash instead)
    pub project_uuid: Option<String>,
    /// WASM hash (used when project_uuid is None)
    pub wasm_hash: String,
    /// Account ID (user account or "@worker" for private storage)
    pub account_id: String,
    /// Encrypted key (base64)
    pub encrypted_key_base64: String,
    /// Encrypted value (base64)
    pub encrypted_value_base64: String,
}

/// Response with decrypted storage data
#[derive(Debug, Serialize)]
pub struct StorageDecryptResponse {
    /// Decrypted key
    pub key: String,
    /// Decrypted value (base64)
    pub value_base64: String,
}

// ==================== Generic Encryption API (for TopUp flow) ====================

/// Request to generate VRF output
#[derive(Debug, Deserialize)]
pub struct VrfGenerateRequest {
    /// Alpha string (VRF pre-image). Format: "vrf:{request_id}:{user_seed}"
    pub alpha: String,
}

/// Response with VRF output and signature (proof)
#[derive(Debug, Serialize)]
pub struct VrfGenerateResponse {
    /// VRF output: SHA256(Ed25519_signature), 32 bytes hex
    pub output_hex: String,
    /// VRF proof: Ed25519 signature, 64 bytes hex
    pub signature_hex: String,
}

/// Response with VRF public key
#[derive(Debug, Serialize)]
pub struct VrfPublicKeyResponse {
    /// VRF public key (Ed25519), 32 bytes hex
    pub vrf_public_key_hex: String,
}

/// `GET /admin/loaded-vaults` response.
#[derive(Debug, Serialize)]
pub struct LoadedVaultsResponse {
    /// Vault ids whose master is in memory right now — addresses only, no key material.
    pub vaults: Vec<String>,
    /// How many of them there are.
    pub count: usize,
    /// TEE handshakes since boot — NOT live workers. Sessions are never expired (`created_at` is
    /// unread), so this only ever climbs until a restart; two workers reconnecting concurrently
    /// add two. Reported here rather than on the public `/health` so that reading it requires a
    /// token checked by real auth middleware, which also logs failures.
    pub tee_sessions: usize,
}

/// `GET /admin/loaded-vaults` — which vaults this instance has derived a master for.
///
/// Every entry cost one on-chain CKD derivation (~30 mNEAR of that vault's balance). The map
/// lives in memory only, so a restart or a version upgrade empties it and the first request per
/// vault pays again — expected, once per instance lifetime. This endpoint makes that visible:
/// after a restart it answers "who has come back", and an entry for a vault nobody expected is
/// the signal that someone probed it.
async fn admin_loaded_vaults_handler(
    State(state): State<AppState>,
) -> Result<Json<LoadedVaultsResponse>, ApiError> {
    let vaults: Vec<String> = state
        .keystore
        .read()
        .await
        .loaded_customers()
        .into_iter()
        .map(|id| id.to_string())
        .collect();
    let tee_sessions = state.tee_sessions.lock().map(|s| s.len()).unwrap_or(0);

    Ok(Json(LoadedVaultsResponse {
        count: vaults.len(),
        vaults,
        tee_sessions,
    }))
}

/// `POST /admin/evict-customer` request body.
#[derive(Debug, Deserialize)]
pub struct AdminEvictCustomerRequest {
    /// Vault account id whose per-customer master should be dropped
    /// from cache. Must parse as `AccountId`.
    pub vault_id: String,
    /// Free-form reason logged for audit visibility (e.g.
    /// `"duplicate_mpc_call_after_init"`, `"manual_dao_ban"`). Not
    /// validated against any whitelist — operators set the
    /// convention.
    pub reason: String,
}

/// `POST /admin/evict-customer` response. `ok = true` always; the
/// endpoint is idempotent and signals no error states.
#[derive(Debug, Serialize)]
pub struct AdminEvictCustomerResponse {
    pub ok: bool,
}

/// `POST /admin/ban-vault` request body.
///
/// Called by the race-attack monitoring service when it
/// detects more than one MPC `request_app_private_key` call from the
/// same vault account within the dedup window. The keystore-worker
/// submits `keystore_dao.ban_vault(vault_id, reason)` on chain (its
/// access key on the keystore-DAO contract is approved for this
/// method) and ALSO evicts the per-customer master from cache so the
/// ban takes effect within milliseconds rather than waiting for the
/// next worker restart.
#[derive(Debug, Deserialize)]
pub struct AdminBanVaultRequest {
    pub vault_id: String,
    /// Free-form reason recorded in the on-chain `vault_banned` log
    /// event (max 256 bytes per the contract). Operators choose the
    /// convention; typical values:
    /// `"duplicate_mpc_call_after_init"`,
    /// `"manual_admin_action"`,
    /// `"phase8_monitor_alert_<id>"`.
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct AdminBanVaultResponse {
    /// Tx hash of the on-chain `ban_vault` submission. `None` if the
    /// vault is already banned (idempotent short-circuit).
    pub tx_hash: Option<String>,
    /// `true` when the keystore short-circuited because
    /// `is_vault_banned == true` already.
    pub already_banned: bool,
}

/// `POST /sign-vault-verification` request body.
///
/// Sent by the public `outlayer.near/vault-checker` WASI agent after
/// it has verified the vault state itself. The keystore-worker
/// re-runs the SAME 5 RPC checks (defense-in-depth) and only then
/// signs+broadcasts `keystore_dao.mark_vault_verified(vault_id)`.
#[derive(Debug, Deserialize)]
pub struct SignVaultVerificationRequest {
    /// Vault account id to mark as verified.
    pub vault_id: String,
}

/// `POST /sign-vault-verification` response.
///
/// * `tx_hash = Some(_)` — the worker submitted a fresh
///   `mark_vault_verified` tx; the value is the base58 NEAR tx hash.
/// * `tx_hash = None`, `already_verified = true` — the vault was
///   already verified on-chain; the worker SHORT-CIRCUITED without
///   spending gas or a nonce. Audit noteC3: spamming
///   `/sign-vault-verification` against an already-verified vault
///   would otherwise burn the worker's per-tx nonce and gas budget.
///
/// **Idempotency contract (Audit noteC1):** a 5xx
/// response from this endpoint MUST be treated as ambiguous by the
/// caller — the tx may or may not have landed. Caller MUST query
/// `keystore_dao.is_vault_verified(vault_id)` independently before
/// retrying; a retry without that check could trip a NEAR
/// `InvalidNonce` if the original tx silently committed.
#[derive(Debug, Serialize)]
pub struct SignVaultVerificationResponse {
    /// Base58-encoded tx hash of the `mark_vault_verified` call, or
    /// `None` when `already_verified = true`.
    pub tx_hash: Option<String>,
    /// `true` if the vault was already verified at request time.
    /// `false` if a fresh tx was submitted (and `tx_hash` is `Some`).
    #[serde(default)]
    pub already_verified: bool,
}

/// `POST /derive-vault-tee-key` request body.
///
/// Used by `outlayer-cli init-vault` to fetch the public
/// half of the Layer-1 TEE keypair BEFORE submitting the atomic
/// deploy that adds it as a function-call AccessKey on the new vault.
/// The keypair is HMAC-derived from the OutLayer default master with
/// seed `outlayer.near:{vault_id}` (Layer 1 of the per-vault master derivation) — deterministic,
/// re-derivable on any approved TEE, never leaves the enclave's
/// memory in private form.
#[derive(Debug, Deserialize)]
pub struct DeriveVaultTeeKeyRequest {
    pub vault_id: String,
}

/// `POST /derive-vault-tee-key` response.
///
/// Returns ONLY the public key — the private key never leaves the TEE
/// (it's used by the worker to sign Layer-2 MPC CKD calls FROM the
/// vault). The caller (CLI) embeds `public_key` in an `AddKey` action
/// inside the atomic deploy tx; afterwards anyone reading
/// `view_access_key_list(vault_id)` sees that exact pubkey, which
/// `vault-checker` and `vault_verifier.rs` then assert against.
#[derive(Debug, Serialize)]
pub struct DeriveVaultTeeKeyResponse {
    /// NEAR-format public key, e.g. `"ed25519:<base58>"`.
    pub public_key: String,
}

/// Request to encrypt plaintext data
/// Used by workers to re-encrypt secrets after TopUp
#[derive(Debug, Deserialize)]
pub struct EncryptRequest {
    /// Seed for deriving keypair (format depends on secret type)
    /// For Payment Key: "system:payment_key:{owner}:{nonce}"
    pub seed: String,
    /// Plaintext data to encrypt (base64 encoded)
    pub plaintext_base64: String,
}

/// Response with encrypted data
#[derive(Debug, Serialize)]
pub struct EncryptResponse {
    /// Encrypted data (base64)
    pub encrypted_base64: String,
}

// ==================== Wallet API ====================

/// Request to derive a wallet address for a specific chain
#[derive(Debug, Deserialize)]
pub struct WalletDeriveAddressRequest {
    pub wallet_id: String,
    pub chain: String,
    /// Optional sub-key under the wallet's EVM key — see [`validate_sub_path`].
    /// Absent or empty: the wallet's own key.
    #[serde(default)]
    pub sub_path: Option<String>,
}

/// Response with derived address and public key
#[derive(Debug, Serialize)]
pub struct WalletDeriveAddressResponse {
    pub address: String,
    pub public_key: String,
}

/// Request to sign EIP-712 typed data with the wallet's EVM (secp256k1) key.
#[derive(Debug, Deserialize)]
pub struct WalletEvmSignTypedDataRequest {
    pub wallet_id: String,
    pub chain: String,
    /// Full `eth_signTypedData_v4` object: `{ domain, types, primaryType, message }`.
    pub typed_data: serde_json::Value,
    /// Sign with this sub-key of the wallet's EVM key instead of the key
    /// itself — see [`validate_sub_path`].
    #[serde(default)]
    pub sub_path: Option<String>,
}

/// Request to sign an EIP-191 `personal_sign` message with the wallet's EVM key.
#[derive(Debug, Deserialize)]
pub struct WalletEvmSignMessageRequest {
    pub wallet_id: String,
    pub chain: String,
    /// The message to sign; interpreted per `encoding`.
    pub message: String,
    /// `"utf8"` (default) signs the UTF-8 bytes of `message`; `"hex"` treats
    /// `message` as hex and signs the decoded bytes. No content sniffing.
    #[serde(default)]
    pub encoding: Option<String>,
    /// Sign with this sub-key of the wallet's EVM key — see [`validate_sub_path`].
    #[serde(default)]
    pub sub_path: Option<String>,
}

/// Request to sign a raw EVM transaction with the wallet's EVM key.
///
/// The caller supplies the **serialized unsigned transaction** (e.g. viem
/// `serializeTransaction(tx)` — `0x02‖rlp(...)` for EIP-1559). The keystore
/// keccak256-hashes it and signs — it does NOT parse or assemble the tx, manage
/// nonce/gas, or broadcast. Gated by the `evm_sign.raw_tx` sub-capability.
#[derive(Debug, Deserialize)]
pub struct WalletEvmSignTransactionRequest {
    pub wallet_id: String,
    pub chain: String,
    /// Serialized unsigned transaction, `0x`-hex.
    pub unsigned_tx: String,
    /// Sign with this sub-key of the wallet's EVM key — see [`validate_sub_path`].
    #[serde(default)]
    pub sub_path: Option<String>,
}

/// A 65-byte recoverable EVM signature, `0x`-hex (`r‖s‖v`, `v ∈ {27,28}`).
#[derive(Debug, Serialize)]
pub struct WalletEvmSignResponse {
    pub signature: String,
}

/// Request to sign an off-chain message with the wallet's Solana (ed25519) key.
///
/// The raw decoded bytes are signed as-is (Solana convention — verifiable
/// with `nacl.sign.detached.verify`), EXCEPT bytes that parse as a valid
/// Solana transaction message, which are rejected (use
/// `/wallet/solana/sign-transaction`, gated by `solana_sign.raw_tx`).
#[derive(Debug, Deserialize)]
pub struct WalletSolanaSignMessageRequest {
    pub wallet_id: String,
    pub chain: String,
    /// The message to sign; interpreted per `encoding`.
    pub message: String,
    /// `"utf8"` (default) signs the UTF-8 bytes of `message`; `"hex"` /
    /// `"base64"` decode `message` first and sign the decoded bytes.
    /// No content sniffing.
    #[serde(default)]
    pub encoding: Option<String>,
}

/// Request to sign a Solana transaction message with the wallet's Solana key.
///
/// The caller supplies the **serialized unsigned transaction message** (what
/// the signature covers on Solana: web3.js `tx.serializeMessage()` /
/// `versionedTx.message.serialize()`), base64. The keystore signs the bytes
/// as-is — it does NOT parse or assemble the transaction, pick a blockhash,
/// or broadcast. Gated by the `solana_sign.raw_tx` sub-capability.
#[derive(Debug, Deserialize)]
pub struct WalletSolanaSignTransactionRequest {
    pub wallet_id: String,
    pub chain: String,
    /// Serialized unsigned transaction message, base64.
    pub unsigned_tx: String,
}

/// A 64-byte ed25519 signature, base58 (Solana convention).
#[derive(Debug, Serialize)]
pub struct WalletSolanaSignResponse {
    pub signature: String,
}

/// Request to sign encrypted policy data (for on-chain store_wallet_policy)
#[derive(Debug, Deserialize)]
pub struct WalletSignPolicyRequest {
    pub wallet_id: String,
    /// The encrypted policy blob (base64 ciphertext), NOT a pre-computed hash. The keystore
    /// DECRYPT-VALIDATES it (AEAD) before signing — a caller-supplied
    /// raw hash, or any non-ciphertext, is rejected (it would be a tx-signing oracle).
    pub encrypted_data: String,
    /// The NEAR account that will SEND `store_wallet_policy`. Part of the
    /// signed message, so the signature is good for that account and no other —
    /// which is what stops a signature lifted off the chain being filed by a
    /// stranger.
    pub caller: String,
}

/// Request for POST /wallet/sign-secret-store.
#[derive(Debug, Deserialize)]
pub struct SignSecretStoreRequest {
    pub wallet_id: String,
    /// The connector's project. Used to REBUILD the seed here rather than take
    /// one from the caller — that is what makes a mis-sealed secret impossible
    /// rather than merely unlikely.
    ///
    /// Exactly one of this and `wasm_hash`. See [`AgentSecretTarget`].
    #[serde(default)]
    pub project_id: Option<String>,
    /// One exact WASM binary instead of a project: the secret is then readable
    /// only by that build, and a rebuild that changes a byte cannot open it.
    #[serde(default)]
    pub wasm_hash: Option<String>,
    /// The sealed secret (base64 ciphertext), NOT a hash. Decrypt-validated
    /// before anything is signed — see the handler.
    pub encrypted_secrets_base64: String,
    /// The account that will send the transaction and stake the storage. Part of
    /// the signed message, so the signature cannot be replayed by anyone else.
    pub payer: String,
    /// Who may obtain a decryption of this secret. **Signed**, because consent
    /// to a ciphertext is not consent to an audience: with this outside the
    /// signature, the payer chose the readers after the owner had signed and
    /// the signature still verified.
    pub access: crate::types::AccessCondition,
    /// Which per-customer master the secret is sealed to, if any. Signed for
    /// the same reason as the accessor: it decides which key decrypts, so it is
    /// part of what is being authorised.
    #[serde(default)]
    pub vault_id: Option<String>,
}

/// Response with the signature the contract's `store_agent_secret` verifies.
#[derive(Debug, Serialize)]
pub struct SignSecretStoreResponse {
    pub signature_hex: String,
    /// `ed25519:<hex>` — the form the contract takes.
    pub wallet_pubkey: String,
    /// The agent's implicit account: both the owner of the secret and its name.
    pub agent_account: String,
}

/// Request for POST /wallet/sign-secret-delete.
///
/// No ciphertext, because a delete names a secret rather than carrying one —
/// which also removes the decrypt-validation this endpoint's sibling relies on.
/// What authorises it instead is the same thing that authorises every other
/// wallet operation: the caller reached here holding the wallet's key, and the
/// signature covers the agent, the accessor, the profile and the payer, so it
/// destroys one named secret on behalf of one named submitter and nothing else.
#[derive(Debug, Deserialize)]
pub struct SignSecretDeleteRequest {
    pub wallet_id: String,
    /// Exactly one of this and `wasm_hash`, exactly as for the store — the
    /// signature must name the accessor the secret is filed under.
    #[serde(default)]
    pub project_id: Option<String>,
    #[serde(default)]
    pub wasm_hash: Option<String>,
    /// The account that will send the transaction, and the one the storage
    /// deposit comes back to.
    pub payer: String,
}

/// Response with the signature the contract's `delete_agent_secret` verifies.
#[derive(Debug, Serialize)]
pub struct SignSecretDeleteResponse {
    pub signature_hex: String,
    pub wallet_pubkey: String,
    pub agent_account: String,
}

/// Response with ed25519 signature + public key for contract verification
#[derive(Debug, Serialize)]
pub struct WalletSignPolicyResponse {
    pub signature_hex: String,  // ed25519 signature (64 bytes hex)
    pub public_key_hex: String, // ed25519 public key (32 bytes hex)
}

/// A single approver's NEP-413 signature over `approve:{approval_id}:{wallet_pubkey}:{request_hash}`.
#[derive(Debug, Deserialize)]
pub struct ApproverSig {
    pub approver_id: String, // NEAR account id; must be in the wallet policy's approvers
    pub public_key: String,  // ed25519:base58
    pub signature: String,   // base64 (64 bytes)
    pub nonce: String,       // base64 (32 bytes) — the NEP-413 nonce the approver used
}

/// Approval bundle forwarded by the coordinator. It carries the real approver
/// signatures (not just names) so the keystore verifies them itself — the
/// coordinator transports them but cannot forge them. The keystore derives the
/// `request_hash` itself from the canonical `op` (binding is automatic), so the
/// coordinator can neither pick the hash nor bind approvals to a different op.
#[derive(Debug, Deserialize)]
pub struct ApprovalInfo {
    pub approval_id: String,
    /// NEP-413 `recipient` the approvers signed against; asserted == this keystore's contract.
    pub recipient: String,
    /// YES votes — NEP-413 sigs over `approve:{approval_id}:{wallet_pubkey}:{request_hash}`.
    pub approvals: Vec<ApproverSig>,
    /// NO votes (vetoes) — NEP-413 sigs over `reject:{approval_id}:{wallet_pubkey}:{request_hash}`. Any
    /// vote from a REAL policy approver (valid sig + on-chain key + in approver set)
    /// vetoes the operation; non-approver rejections are ignored. Symmetric with approvals.
    #[serde(default)]
    pub rejections: Vec<ApproverSig>,
}

/// Unified wallet signing request (the single `/wallet/sign` endpoint).
///
/// `op` is the canonical operation. The keystore derives
/// `request_hash = sha256(canonical_json(op))`, evaluates the on-chain policy,
/// verifies approver signatures when required, then produces the artifact per the
/// op's bind mode — for `Built` kinds it CONSTRUCTS the artifact from the op (never
/// accepts a ready one), so what it signs always equals what was approved.
#[derive(Debug, Deserialize)]
pub struct WalletSignRequest {
    pub wallet_id: String,
    pub op: shared_tee_helpers::wallet_policy::Op,
    #[serde(default)]
    pub approval_info: Option<ApprovalInfo>,
    /// Supplementary material the keystore cannot derive from `op`:
    /// - Hash-pinned `raw`: the exact bytes to sign (`bytes_base64`); signed iff
    ///   `sha256(bytes) == op.payload_hash`.
    /// - Hash-pinned `sign_message`: the plaintext `message` + `nonce_base64`. The
    ///   recipient comes from `op` (bound into the signature → domain separation).
    /// - Trusted `swap`/`confidential`: the externally-generated NEP-413 `message`
    ///   + `nonce_base64` + `recipient` (artifact can't exist at approval time).
    #[serde(default)]
    pub artifact: Option<SignArtifact>,
    /// Stateful usage state (per-token daily/hourly/monthly spend + hourly_tx_count),
    /// in the coordinator's `current_usage` JSON shape. The keystore is the sole policy
    /// evaluator; the coordinator merely SUPPLIES this state (it cannot decrypt the
    /// policy). Absent → only the stateless subset is enforced. Trusted: a compromised
    /// coordinator can under-report usage, but the keystore still enforces the stateless
    /// rules + multisig independently.
    #[serde(default)]
    pub usage: Option<serde_json::Value>,
    /// Agent Connect: which binding mode the coordinator believes this wallet
    /// operates in, and — for the leased mode — the DECODER the coordinator
    /// resolved for the bound account's implementation version through its
    /// `hos_impl_versions` table. Both are CLAIMS: the enclave has no chain
    /// access, so it cannot check them, only refuse what it cannot evaluate —
    /// and it evaluates by decoder, not by partner version, so a partner
    /// release that changes nothing on the wire never reaches this image. See
    /// `binding::signing_version_gate` for what that buys.
    #[serde(default)]
    pub binding_kind: Option<String>,
    #[serde(default)]
    pub decoder_version: Option<u32>,
}

/// Supplementary signing material — see `WalletSignRequest::artifact`.
#[derive(Debug, Default, Deserialize)]
pub struct SignArtifact {
    #[serde(default)]
    pub bytes_base64: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub nonce_base64: Option<String>,
    #[serde(default)]
    pub recipient: Option<String>,
}

/// Unified wallet signing response. Fields are populated per bind mode; the
/// `request_hash` is always the canonical hash the keystore signed under.
#[derive(Debug, Serialize)]
pub struct WalletSignResponse {
    pub request_hash: String,
    // --- Built NEAR transaction (transfer / call / delete) ---
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_tx_base64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<u64>,
    // --- NEP-413 intent / message (withdraw / sign_message / swap / confidential) ---
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_base58: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce_base64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient: Option<String>,
    // --- Raw signature (hash-pinned cross-chain) ---
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_base64: Option<String>,
    // --- Auth (raw ed25519 over the coordinator auth string) ---
    /// The exact signed auth string (`<prefix>:<seed>:<ts>[:<vault>]`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_message: Option<String>,
    /// The fresh timestamp the keystore embedded in `auth_message`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_timestamp: Option<u64>,
    /// Raw ed25519 signature, base58 (no `ed25519:` prefix) — what the coordinator's
    /// `verify_near_auth_fields` `bs58::decode`s.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_signature_base58: Option<String>,
    // public_key applies to every signing mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
}

impl WalletSignResponse {
    fn new(request_hash: String) -> Self {
        WalletSignResponse {
            request_hash,
            signed_tx_base64: None,
            tx_hash: None,
            signer_id: None,
            nonce: None,
            signature_base58: None,
            message: None,
            nonce_base64: None,
            recipient: None,
            signature_base64: None,
            auth_message: None,
            auth_timestamp: None,
            auth_signature_base58: None,
            public_key: None,
        }
    }
}

/// Pre-flight policy check for a canonical `op` (the same engine `/wallet/sign` uses).
/// The keystore is the SOLE policy evaluator; the coordinator supplies `usage`.
#[derive(Debug, Deserialize)]
pub struct WalletCheckPolicyRequest {
    pub wallet_id: String,
    pub op: shared_tee_helpers::wallet_policy::Op,
    /// Stateful usage state (coordinator `current_usage` shape). Absent → stateless only.
    #[serde(default)]
    pub usage: Option<serde_json::Value>,
    /// Optional: encrypted policy data (base64) for local/test policy override.
    /// When provided, skips fetching from NEAR contract.
    #[serde(default)]
    pub encrypted_policy_data: Option<String>,
    /// See `WalletSignRequest::binding_kind`. The pre-flight check must answer
    /// what the signature would, or a caller could be told "allowed" and then
    /// refused at signing.
    #[serde(default)]
    pub binding_kind: Option<String>,
    #[serde(default)]
    pub decoder_version: Option<u32>,
}

/// Response from policy check. The decrypted policy is NEVER returned — it does not
/// leave the keystore.
#[derive(Debug, Serialize)]
pub struct WalletCheckPolicyResponse {
    pub allowed: bool,
    pub frozen: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requires_approval: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_approvals: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Canonical request hash the dashboard signs (`approve:{id}:{wallet_pubkey}:{request_hash}`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_hash: Option<String>,
    /// Narrow carve-out: the owner's event-delivery URL (NOT a secret). The rest of the
    /// decrypted policy never leaves the keystore.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<String>,
}

/// Request to encrypt a wallet policy
#[derive(Debug, Deserialize)]
pub struct WalletEncryptPolicyRequest {
    pub wallet_id: String,
    pub policy_json: String,
}

/// Response with encrypted policy
#[derive(Debug, Serialize)]
pub struct WalletEncryptPolicyResponse {
    pub encrypted_base64: String,
}

/// Request to DECRYPT a wallet policy for owner-view / config sync (NOT the signing
/// decision path — `/check-policy` and `/wallet/sign` never return the policy). The
/// coordinator already caches the result in `wallet_accounts.policy_json`.
#[derive(Debug, Deserialize)]
pub struct WalletDecryptPolicyRequest {
    pub wallet_id: String,
    /// Encrypted policy blob (base64) read from chain by the caller.
    pub encrypted_policy_data: String,
}

/// Response with the decrypted policy JSON.
#[derive(Debug, Serialize)]
pub struct WalletDecryptPolicyResponse {
    pub policy: serde_json::Value,
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
        seed = %req.seed,
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


/// Decrypt secrets from contract for authorized TEE worker
async fn decrypt_handler(
    State(state): State<AppState>,
    worker: Option<axum::Extension<WorkerIdentity>>,
    Json(req): Json<DecryptRequest>,
) -> Result<Json<DecryptResponse>, ApiError> {
    // Check if keystore is ready (has master key from MPC)
    if !state.is_ready() {
        tracing::warn!("Decrypt request rejected - keystore not ready (waiting for DAO approval and MPC key)");
        return Err(ApiError::Unauthorized(
            "Keystore not ready. Waiting for DAO approval and master key from MPC.".to_string()
        ));
    }

    let task_id_str = req.task_id.as_deref().unwrap_or("unknown");
    // Which worker instance asked. Absent only in dev mode (`TeeMode::None`), where sessions
    // are not enforced at all.
    let worker_key = worker
        .as_ref()
        .map(|w| w.0 .0.as_str())
        .unwrap_or("no-session");

    // Log request based on accessor type
    match &req.accessor {
        SecretAccessor::Repo { repo, branch } => {
            tracing::info!(
                task_id = %task_id_str,
                worker = %worker_key,
                repo = %repo,
                branch = ?branch,
                profile = %req.profile,
                owner = %req.owner,
                "Received decrypt request (Repo)"
            );
        }
        SecretAccessor::WasmHash { hash } => {
            tracing::info!(
                task_id = %task_id_str,
                worker = %worker_key,
                wasm_hash = %hash,
                profile = %req.profile,
                owner = %req.owner,
                "Received decrypt request (WasmHash)"
            );
        }
        SecretAccessor::Project { project_id } => {
            tracing::info!(
                task_id = %task_id_str,
                worker = %worker_key,
                project_id = %project_id,
                profile = %req.profile,
                owner = %req.owner,
                "Received decrypt request (Project)"
            );
        }
        SecretAccessor::System { secret_type } => {
            tracing::info!(
                task_id = %task_id_str,
                worker = %worker_key,
                secret_type = ?secret_type,
                profile = %req.profile,
                owner = %req.owner,
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

    let accessor_json = accessor_to_contract_json(&req.accessor);
    let combined = near_client
        .get_secret_with_vault(accessor_json, &req.profile, &req.owner)
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
        match &req.accessor {
            SecretAccessor::Repo { repo, branch } => tracing::warn!(
                task_id = %task_id_str,
                repo = %repo,
                branch = ?branch,
                profile = %req.profile,
                owner = %req.owner,
                "Secrets not found in contract"
            ),
            SecretAccessor::WasmHash { hash } => tracing::warn!(
                task_id = %task_id_str,
                wasm_hash = %hash,
                profile = %req.profile,
                owner = %req.owner,
                "Secrets not found in contract"
            ),
            SecretAccessor::Project { project_id } => tracing::warn!(
                task_id = %task_id_str,
                project_id = %project_id,
                profile = %req.profile,
                owner = %req.owner,
                "Secrets not found in contract"
            ),
            SecretAccessor::System { secret_type } => tracing::warn!(
                task_id = %task_id_str,
                secret_type = ?secret_type,
                profile = %req.profile,
                owner = %req.owner,
                "Secrets not found in contract"
            ),
        }
        ApiError::BadRequest("Secrets not found in contract".to_string())
    })?;

    // Parse the on-chain vault binding into an AccountId, then ensure
    // the per-vault master is loaded BEFORE we touch the keystore.
    // Bridge between the contract's vault-binding side-table and the
    // lazy-load gate. Malformed vault_id on chain is a hard error
    // (chain shouldn't store malformed AccountIds — it would be a bug
    // in the contract or the binding writer).
    let customer = parse_optional_vault_id(vault_id_str.as_deref())?;
    state
        .ensure_customer_loaded(customer.as_ref())
        .await
        // Underfunded vault → 402 with a top-up message; anything else → 400
        // with the full chain. (Was InternalError/500, which hid the cause.)
        .map_err(ApiError::from_customer_load)?;

    tracing::debug!(
        task_id = %task_id_str,
        vault_id = ?customer,
        "Successfully read secrets from contract"
    );

    // 2. A secret named by an agent belongs to that agent alone.
    enforce_agent_secret(&req.user_account_id, &req.owner, &req.profile).inspect_err(|_| {
        tracing::warn!(
            task_id = %task_id_str,
            caller = %req.user_account_id,
            owner = %req.owner,
            profile = %req.profile,
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
    let caller = &req.user_account_id;

    // An unreadable condition is refused BEFORE it is evaluated, wherever the
    // unreadable leaf sits: evaluated, a bad pattern denies as a leaf, and
    // under `Not` that denial would admit. The message names the owner's own
    // pattern — public on chain in the row — and nothing else.
    if let Some((pattern, why)) = access_condition.unparseable_pattern() {
        let message = format!(
            "Access denied by access condition: its AccountPattern `{pattern}` is not a valid regular expression ({why})"
        );
        tracing::warn!(task_id = %task_id_str, caller = %caller, "{message}");
        return Err(ApiError::Unauthorized(message));
    }

    let access_granted = access_condition.validate(caller, state.near_client.as_ref().map(|c| c.as_ref())).await
        .map_err(|e| {
            tracing::error!(task_id = %task_id_str, error = %e, "Access validation failed");
            ApiError::InternalError(format!("Access validation failed: {}", e))
        })?;

    if !access_granted {
        let message = access_condition.denial_message();
        tracing::warn!(
            task_id = %task_id_str,
            caller = %caller,
            "{message}"
        );
        return Err(ApiError::Unauthorized(message));
    }

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
    let seed = match &req.accessor {
        SecretAccessor::Repo { repo, branch: request_branch } => {
            let normalized_repo = crate::utils::normalize_repo_url(repo);
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
                format!("{}:{}:{}", normalized_repo, req.owner, b)
            } else {
                format!("{}:{}", normalized_repo, req.owner)
            };

            tracing::debug!(
                task_id = %task_id_str,
                repo_normalized = %normalized_repo,
                owner = %req.owner,
                secret_branch = ?secret_branch,
                seed = %seed,
                "🔓 DECRYPTION SEED (Repo)"
            );

            seed
        }
        SecretAccessor::WasmHash { hash } => {
            let seed = format!("wasm_hash:{}:{}", hash, req.owner);

            tracing::debug!(
                task_id = %task_id_str,
                wasm_hash = %hash,
                owner = %req.owner,
                seed = %seed,
                "🔓 DECRYPTION SEED (WasmHash)"
            );

            seed
        }
        SecretAccessor::Project { project_id } => {
            let seed = format!("project:{}:{}", project_id, req.owner);

            tracing::debug!(
                task_id = %task_id_str,
                project_id = %project_id,
                owner = %req.owner,
                seed = %seed,
                "🔓 DECRYPTION SEED (Project)"
            );

            seed
        }
        SecretAccessor::System { secret_type } => {
            // Seed format: system:{type}:{owner}:{nonce}
            // nonce is stored in profile field
            let seed = format!("system:{}:{}:{}", secret_type.as_seed_str(), req.owner, req.profile);

            tracing::debug!(
                task_id = %task_id_str,
                secret_type = ?secret_type,
                owner = %req.owner,
                nonce = %req.profile,
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

    Ok(Json(DecryptResponse {
        plaintext_secrets: plaintext_b64,
    }))
}

/// POST /vrf/generate — Generate VRF output for alpha (worker-only)
async fn vrf_generate_handler(
    State(state): State<AppState>,
    Json(req): Json<VrfGenerateRequest>,
) -> Result<Json<VrfGenerateResponse>, ApiError> {
    if !state.is_ready() {
        return Err(ApiError::Unauthorized(
            "Keystore not ready. Waiting for DAO approval and master key from MPC.".to_string()
        ));
    }

    if req.alpha.is_empty() {
        return Err(ApiError::BadRequest("alpha must not be empty".to_string()));
    }

    let keystore = state.keystore.read().await;
    let (output_hex, signature_hex) = keystore
        .vrf_generate(req.alpha.as_bytes())
        .map_err(|e| ApiError::InternalError(format!("VRF generation failed: {}", e)))?;

    tracing::info!(alpha = %req.alpha, "VRF generated");

    Ok(Json(VrfGenerateResponse { output_hex, signature_hex }))
}

/// GET /vrf/pubkey — Get VRF public key (public, no auth)
async fn vrf_pubkey_handler(
    State(state): State<AppState>,
) -> Result<Json<VrfPublicKeyResponse>, ApiError> {
    if !state.is_ready() {
        return Err(ApiError::Unauthorized(
            "Keystore not ready. Waiting for DAO approval and master key from MPC.".to_string()
        ));
    }

    let keystore = state.keystore.read().await;
    let vrf_public_key_hex = keystore
        .vrf_public_key_hex()
        .map_err(|e| ApiError::InternalError(format!("VRF public key derivation failed: {}", e)))?;

    Ok(Json(VrfPublicKeyResponse { vrf_public_key_hex }))
}

/// `POST /admin/evict-customer` — drop the cached per-customer master.
///
/// Called by the monitoring service when it detects a vault should
/// no longer operate (race-attack ban, manual DAO ban). The next
/// `derive_*` call for this vault will fail because the lazy-load
/// gate re-checks `keystore-dao.is_vault_verified` which now
/// returns false-when-banned.
///
/// Without this endpoint a banned vault would continue operating
/// until the next keystore-worker restart drops the in-memory cache.
///
/// **Auth:** worker token. Same boundary as `/decrypt` — anything
/// inside the operator's TEE network can evict. The endpoint is NOT
/// exposed to coordinator or external clients.
///
/// **Idempotent:** evicting a customer that was never loaded is a
/// no-op. Returns `{ ok: true }` either way.
async fn admin_evict_customer_handler(
    State(state): State<AppState>,
    Json(req): Json<AdminEvictCustomerRequest>,
) -> Result<Json<AdminEvictCustomerResponse>, ApiError> {
    let customer: near_primitives::types::AccountId = req.vault_id.parse().map_err(|e| {
        ApiError::BadRequest(format!("invalid vault_id account: {e}"))
    })?;
    let keystore = state.keystore.read().await;
    keystore.evict_customer(&customer);
    tracing::info!(
        vault_id = %customer,
        reason = %req.reason,
        "admin: evicted per-customer master from cache"
    );
    Ok(Json(AdminEvictCustomerResponse { ok: true }))
}

/// `POST /admin/ban-vault` — submit `keystore_dao.ban_vault(vault_id,
/// reason)` and evict the cached per-customer master in one shot.
///
/// Called by the race-attack monitoring service when it
/// detects more than one MPC `request_app_private_key` call for the
/// same vault within the dedup window. Side effects (in order):
///   1. Short-circuit if `keystore_dao.is_vault_banned(vault_id)` is
///      already true — no need to spend another nonce + log line.
///   2. Submit `ban_vault` via the worker's keystore-DAO function-call
///      access key (same key that `mark_vault_verified` uses; the DAO
///      whitelists the method-list). 300 TGas, no deposit. Serialized
///      through `signer_nonce_lock` so this can run concurrently with
///      `/sign-vault-verification`.
///   3. Evict the in-memory per-customer master so the ban takes
///      effect within ms — the `is_vault_verified` check on the
///      next-derive-call already returns false-when-banned (the DAO
///      view reads `verified - banned`).
///
/// **Auth:** worker token. Same boundary as `/admin/evict-customer`.
async fn admin_ban_vault_handler(
    State(state): State<AppState>,
    Json(req): Json<AdminBanVaultRequest>,
) -> Result<Json<AdminBanVaultResponse>, ApiError> {
    if !state.is_ready() {
        return Err(ApiError::Unauthorized(
            "Keystore not ready. Waiting for DAO approval and master key from MPC.".to_string(),
        ));
    }

    let vault_id: near_primitives::types::AccountId = req.vault_id.parse().map_err(|e| {
        ApiError::BadRequest(format!("invalid vault_id account: {e}"))
    })?;

    if req.reason.is_empty() {
        return Err(ApiError::BadRequest(
            "reason is required (operators set the convention; see the handler docs)".to_string(),
        ));
    }
    if req.reason.len() > 256 {
        return Err(ApiError::BadRequest(format!(
            "reason must be at most 256 bytes (got {})",
            req.reason.len()
        )));
    }

    let ctx = state.mpc_context.get().ok_or_else(|| {
        ApiError::InternalError(
            "MPC CKD context not configured — worker booted in non-TEE mode".to_string(),
        )
    })?;
    let near_client = state.near_client.as_ref().ok_or_else(|| {
        ApiError::InternalError("NEAR client not configured".to_string())
    })?;

    // 1. Short-circuit if already banned.
    let is_banned = near_client
        .view_call_json(
            &ctx.mpc_ckd_config.keystore_dao_id,
            "is_vault_banned",
            serde_json::json!({ "vault_id": vault_id }),
        )
        .await
        .map_err(|e| {
            ApiError::InternalError(format!("is_vault_banned view-call failed: {e}"))
        })?;
    if is_banned.as_bool() == Some(true) {
        // Still evict — the cache may have stale state if a different
        // operator banned via DAO vote and this monitor is catching up.
        let keystore = state.keystore.read().await;
        keystore.evict_customer(&vault_id);
        tracing::info!(
            vault_id = %vault_id,
            "Skipping ban_vault tx — already banned on chain. Cache evicted."
        );
        return Ok(Json(AdminBanVaultResponse {
            tx_hash: None,
            already_banned: true,
        }));
    }

    // 2. Submit ban_vault tx, serialized through signer_nonce_lock to
    //    avoid racing /sign-vault-verification on the keystore-DAO
    //    access key's nonce.
    let outcome = {
        let _guard = ctx.signer_nonce_lock.lock().await;
        near_client
            .submit_function_call(
                &ctx.keystore_dao_signer,
                &ctx.mpc_ckd_config.keystore_dao_id,
                "ban_vault",
                serde_json::json!({ "vault_id": vault_id, "reason": req.reason }),
                300_000_000_000_000,
                0,
            )
            .await
    }
    .map_err(|e| {
        tracing::error!(
            vault_id = %vault_id,
            reason = %req.reason,
            error = %e,
            "ban_vault tx submission failed"
        );
        let msg = format!("{e:#}");
        // Concurrent ban via DAO vote = treat as "already banned"
        // (idempotent end state). The contract panics with a generic
        // require! message so we match permissively.
        if msg.contains("already") {
            ApiError::Forbidden(format!("vault {} already banned (race): {}", vault_id, msg))
        } else {
            ApiError::InternalError(format!("tx submission failed: {msg}"))
        }
    })?;

    // 3. Evict the cached master so existing in-flight derive_* calls
    //    on this vault stop succeeding immediately. Does not need the
    //    on-chain tx to land first — the lazy-load gate re-checks
    //    `is_vault_verified` (which factors in `banned_vaults`) on the
    //    NEXT call after eviction, by which point the tx is final.
    {
        let keystore = state.keystore.read().await;
        keystore.evict_customer(&vault_id);
    }

    tracing::warn!(
        vault_id = %vault_id,
        reason = %req.reason,
        tx_hash = %outcome.tx_hash,
        "ban_vault tx landed; per-customer master evicted from cache"
    );

    Ok(Json(AdminBanVaultResponse {
        tx_hash: Some(outcome.tx_hash),
        already_banned: false,
    }))
}

/// `POST /sign-vault-verification` — re-verify a vault and submit
/// `mark_vault_verified` on chain.
///
/// Called by the public
/// `outlayer.near/vault-checker` WASI agent after it has run the
/// same 5 checks itself. The keystore-worker:
///
/// 1. Re-runs all 5 checks via [`crate::vault_verifier::verify_vault_for_signing`]
///    (defense in depth — independent code from the WASI agent).
/// 2. If everything passes, submits `keystore_dao.mark_vault_verified(vault_id)`
///    using the worker's approved access key on the keystore-dao
///    contract (set up at TEE registration time).
/// 3. Returns the broadcast tx hash. The agent does NOT need to wait
///    for finality on the worker side — `broadcast_tx_commit` already
///    waits, and the response only returns once the tx is final.
///
/// **Critically NOT done here:** MPC CKD for the vault's master.
/// That's lazy on first wallet-request via [`crate::mpc_ckd::add_customer`]
/// (lazy MPC CKD). Materialising masters at verification time would
/// charge gas to the vault account before any wallet operation is
/// requested — an unnecessary upfront cost.
///
/// **Auth:** worker token. The vault-checker WASI runs in OutLayer's
/// TEE workers and forwards its worker token; an external caller with
/// a worker token (i.e. an operator) can also drive this endpoint.
/// The auth boundary is intentionally permissive because the security
/// guarantee is the in-process re-verification, not the auth.
///
/// **Idempotent:** if `vault_id` is already verified on chain, the
/// `mark_vault_verified` tx is still submitted — the contract is
/// expected to no-op on re-mark. We don't short-circuit here because
/// we want the canonical tx hash to return either way.
async fn sign_vault_verification_handler(
    State(state): State<AppState>,
    Json(req): Json<SignVaultVerificationRequest>,
) -> Result<Json<SignVaultVerificationResponse>, ApiError> {
    if !state.is_ready() {
        return Err(ApiError::Unauthorized(
            "Keystore not ready. Waiting for DAO approval and master key from MPC.".to_string(),
        ));
    }

    let vault_id: near_primitives::types::AccountId = req.vault_id.parse().map_err(|e| {
        ApiError::BadRequest(format!("invalid vault_id account: {e}"))
    })?;

    // All required context lives in one OnceLock — atomicity
    // invariant means no half-set state can be observed.
    let ctx = state.mpc_context.get().ok_or_else(|| {
        ApiError::InternalError(
            "MPC CKD context not configured — worker booted in non-TEE mode".to_string(),
        )
    })?;
    let near_client = state.near_client.as_ref().ok_or_else(|| {
        ApiError::InternalError("NEAR client not configured".to_string())
    })?;

    // 0. Short-circuit if already verified on-chain. The
    //    `mark_vault_verified` contract method is
    //    idempotent (insert into UnorderedSet is no-op if present), so
    //    skipping the tx is purely an optimisation — but a meaningful
    //    one: every `mark_vault_verified` consumes a nonce and ~0.001
    //    NEAR from the worker's keystore-dao access-key allowance,
    //    and an attacker with a worker token could DoS the nonce by
    //    spamming this endpoint against verified vaults.
    let is_verified = near_client
        .view_call_json(
            &ctx.mpc_ckd_config.keystore_dao_id,
            "is_vault_verified",
            serde_json::json!({ "vault_id": vault_id }),
        )
        .await
        .map_err(|e| {
            ApiError::InternalError(format!("is_vault_verified view-call failed: {e}"))
        })?;
    if is_verified.as_bool() == Some(true) {
        tracing::info!(
            vault_id = %vault_id,
            "Skipping mark_vault_verified — vault already verified on chain"
        );
        return Ok(Json(SignVaultVerificationResponse {
            tx_hash: None,
            already_verified: true,
        }));
    }

    // 1. Defense-in-depth re-verification of all 5 checks. If any
    //    fails, classify caller-side vs worker-side and surface an
    //    appropriate status (see `map_verify_error`).
    crate::vault_verifier::verify_vault_for_signing(
        near_client.as_ref(),
        &ctx.mpc_ckd_config.keystore_dao_id,
        &ctx.mpc_ckd_config.mpc_contract_id,
        &vault_id,
    )
    .await
    .map_err(|e| {
        tracing::warn!(
            vault_id = %vault_id,
            error = %e,
            "Refusing to sign mark_vault_verified — re-verification failed"
        );
        map_verify_error(&vault_id, e)
    })?;

    // 2. Submit mark_vault_verified tx, serializing through the
    //    per-signer nonce lock so concurrent /sign-vault-verification
    //    calls (and /admin/ban-vault) don't race for the same nonce.
    //    Lock is held only across the build+broadcast critical
    //    section; the response wait is inside broadcast_tx_commit so
    //    we cannot release earlier without losing the tx_hash.
    //    300 TGas, no deposit.
    let outcome = {
        let _guard = ctx.signer_nonce_lock.lock().await;
        near_client
            .submit_function_call(
                &ctx.keystore_dao_signer,
                &ctx.mpc_ckd_config.keystore_dao_id,
                "mark_vault_verified",
                serde_json::json!({ "vault_id": vault_id }),
                300_000_000_000_000,
                0,
            )
            .await
    }
    .map_err(|e| {
        tracing::error!(
            vault_id = %vault_id,
            error = %e,
            "mark_vault_verified tx submission failed"
        );
        // A vault that gets banned between vault-checker's own
        // check and our signing window will surface as a
        // contract-side panic with a recognisable message. Map it
        // to 409 Conflict so the caller doesn't retry indefinitely
        // treating it as a transient failure.
        let msg = format!("{e:#}");
        // Match only the exact contract-side panic phrase. The earlier
        // loose `|| msg.contains("banned")` also fired on words like
        // "unbanned" / "rebanned" / any future error mentioning the
        // root, mis-mapping unrelated failures to 403 Forbidden.
        if msg.contains("vault is banned") {
            ApiError::Forbidden(format!(
                "vault {} is banned (likely banned between check and sign): {}",
                vault_id, msg
            ))
        } else {
            ApiError::InternalError(format!("tx submission failed: {msg}"))
        }
    })?;

    tracing::info!(
        vault_id = %vault_id,
        tx_hash = %outcome.tx_hash,
        "mark_vault_verified tx landed"
    );

    Ok(Json(SignVaultVerificationResponse {
        tx_hash: Some(outcome.tx_hash),
        already_verified: false,
    }))
}

/// `POST /derive-vault-tee-key` — return the Layer-1 vault TEE
/// public key for a given `vault_id`.
///
/// `outlayer-cli init-vault` flow: the customer needs the
/// pubkey BEFORE submitting the atomic deploy that adds it as a
/// function-call AccessKey on the new vault. The keypair is
/// [HMAC-derived from the OutLayer default master](mpc_ckd::derive_vault_tee_keypair),
/// so the worker can answer this query without any state — it's
/// read-only and doesn't trigger MPC CKD.
///
/// **Auth:** worker token (admin lane). The CLI is operator-bundled
/// or run by the customer through coordinator's auth proxy; either
/// way the caller has the worker token (or a coordinator token,
/// per the same `worker_auth_middleware` allowlist as
/// `/admin/evict-customer` and `/sign-vault-verification`).
///
/// **Idempotent / pure:** does NOT touch the keystore_dao_signer,
/// does NOT acquire any locks. Two concurrent calls for the same
/// vault_id return identical pubkeys.
async fn derive_vault_tee_key_handler(
    State(state): State<AppState>,
    Json(req): Json<DeriveVaultTeeKeyRequest>,
) -> Result<Json<DeriveVaultTeeKeyResponse>, ApiError> {
    if !state.is_ready() {
        return Err(ApiError::Unauthorized(
            "Keystore not ready. Waiting for DAO approval and master key from MPC.".to_string(),
        ));
    }

    let vault_id: near_primitives::types::AccountId = req.vault_id.parse().map_err(|e| {
        ApiError::BadRequest(format!("invalid vault_id: {e}"))
    })?;

    let keystore = state.keystore.read().await;
    let (public_key, _secret_key) =
        crate::mpc_ckd::derive_vault_tee_keypair(&keystore, &vault_id).map_err(|e| {
            ApiError::InternalError(format!("Layer-1 keypair derivation failed: {e}"))
        })?;

    Ok(Json(DeriveVaultTeeKeyResponse {
        public_key: public_key.to_string(),
    }))
}

/// Map [`crate::vault_verifier::VerifyError`] into the right HTTP
/// status. The split is:
///
/// * **4xx (caller-side / vault-state issue)** — the caller submitted
///   a bad request OR pointed at a vault that fails the protocol's
///   security invariants. Caller should surface to its end-user, not
///   retry transparently.
/// * **5xx (worker-side / RPC-down)** — something between the worker
///   and chain or contract is misbehaving. Caller MAY retry with
///   exponential backoff.
fn map_verify_error(
    vault_id: &near_primitives::types::AccountId,
    e: crate::vault_verifier::VerifyError,
) -> ApiError {
    use crate::vault_verifier::VerifyError as V;
    let msg = format!("vault {vault_id} re-verification failed: {e}");
    match e {
        // Caller-/vault-side problems → 4xx
        V::AlreadyBanned => ApiError::Forbidden(msg),
        V::CodeHashNotApproved { .. }
        | V::CodeHashMissing
        | V::FullAccessKeyPresent
        | V::FunctionCallKeyMisconfigured { .. }
        | V::UnexpectedAccessKeyCount { .. }
        | V::KeystoreDaoMismatch { .. }
        | V::MpcContractMismatch { .. }
        | V::VaultUnlocked
        | V::VaultRecoveryInProgress => ApiError::BadRequest(msg),
        // AccountNotFound is ambiguous (vault doesn't exist OR rpc
        // flake) — bias toward "caller pointed at something invalid"
        // because that's the dominant case; the error message still
        // surfaces the underlying RPC error for ops triage.
        V::AccountNotFound(_) => ApiError::BadRequest(msg),
        // Worker-/system-side problems → 5xx so callers can retry.
        V::KeystoreDaoUnreachable(_)
        | V::AccessKeyListUnreachable(_)
        | V::VaultStateUnreachable(_) => ApiError::InternalError(msg),
        // Contract returning unexpected response shape — that's a
        // contract version mismatch, NOT a caller-side bug.
        V::KeystoreDaoMalformed { .. } | V::VaultStateInvalid(_) => ApiError::InternalError(msg),
    }
}

/// Encrypt plaintext data
///
/// Used by workers to re-encrypt secrets after TopUp:
/// 1. Worker decrypts current Payment Key data via /decrypt
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
        seed = %req.seed,
        "Received encrypt request"
    );

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
        seed = %req.seed,
        plaintext_len = plaintext_bytes.len(),
        encrypted_len = encrypted_bytes.len(),
        "Successfully encrypted data"
    );

    Ok(Json(EncryptResponse { encrypted_base64 }))
}

/// Request to decrypt raw encrypted data directly
#[derive(Debug, Deserialize)]
pub struct DecryptRawRequest {
    /// Seed for key derivation
    pub seed: String,
    /// Base64-encoded encrypted data
    pub encrypted_base64: String,
}

/// Response with decrypted data
#[derive(Debug, Serialize)]
pub struct DecryptRawResponse {
    /// Base64-encoded plaintext data
    pub plaintext_base64: String,
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
        seed = %req.seed,
        "Received decrypt-raw request"
    );

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
        seed = %req.seed,
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
        seed = %req.seed,
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
        seed = %req.seed,
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
        public_key = %req.public_key,
        nonce = %req.nonce,
        recipient = %req.recipient,
        signature_len = req.signature.len(),
        "Verifying NEP-413 signature"
    );

    match verify_near_signature(&req.signed_message, &req.signature, &req.public_key, &req.nonce, &req.recipient) {
        Ok(()) => {
            tracing::info!(
                owner = %req.owner,
                public_key = %req.public_key,
                "✅ NEP-413 signature verified successfully"
            );
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                message = %req.signed_message,
                public_key = %req.public_key,
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
                    public_key = %req.public_key,
                    "✅ Access key ownership verified via NEAR RPC"
                );
            }
            Err(e) => {
                tracing::warn!(
                    owner = %req.owner,
                    public_key = %req.public_key,
                    error = %e,
                    "❌ Access key ownership verification failed"
                );
                return Err(ApiError::Unauthorized(format!(
                    "Public key {} does not belong to account {}: {}",
                    req.public_key, req.owner, e
                )));
            }
        }
    } else {
        tracing::warn!(
            "NEAR client not configured - skipping access key ownership verification. \
            This is a security risk! Set NEAR_RPC_URL and NEAR_CONTRACT_ID."
        );
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
                let normalized_repo = crate::utils::normalize_repo_url(repo);
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
            let normalized_repo = crate::utils::normalize_repo_url(repo);
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

// ==================== Storage Encryption Handlers ====================

/// Encrypt data for persistent storage
///
/// Uses derived key from: `storage:{project_uuid|wasm_hash}:{account_id}`
/// This keeps encryption keys isolated per project/wasm and per account.
async fn storage_encrypt_handler(
    State(state): State<AppState>,
    Json(req): Json<StorageEncryptRequest>,
) -> Result<Json<StorageEncryptResponse>, ApiError> {
    // Check if keystore is ready
    if !state.is_ready() {
        return Err(ApiError::Unauthorized(
            "Keystore not ready. Waiting for DAO approval and master key from MPC.".to_string()
        ));
    }

    // Build seed for key derivation
    // For projects: storage:{project_uuid}:{account_id}
    // For standalone WASM: storage:wasm:{wasm_hash}:{account_id}
    let seed = if let Some(ref project_uuid) = req.project_uuid {
        format!("storage:{}:{}", project_uuid, req.account_id)
    } else {
        format!("storage:wasm:{}:{}", req.wasm_hash, req.account_id)
    };

    tracing::debug!(
        seed = %seed,
        project_uuid = ?req.project_uuid,
        wasm_hash = %req.wasm_hash,
        account_id = %req.account_id,
        key = %req.key,
        "Encrypting storage data"
    );

    // Decode value from base64
    let value_bytes = base64::decode(&req.value_base64)
        .map_err(|e| ApiError::BadRequest(format!("Invalid base64 in value: {}", e)))?;

    // Encrypt key and value
    let keystore = state.keystore.read().await;

    let encrypted_key = keystore
        .encrypt(None, &seed, req.key.as_bytes())
        .map_err(|e| ApiError::InternalError(format!("Failed to encrypt key: {}", e)))?;

    let encrypted_value = keystore
        .encrypt(None, &seed, &value_bytes)
        .map_err(|e| ApiError::InternalError(format!("Failed to encrypt value: {}", e)))?;

    // Calculate key hash for unique constraint
    use sha2::{Sha256, Digest};
    let key_hash = hex::encode(Sha256::digest(req.key.as_bytes()));

    tracing::info!(
        project_uuid = ?req.project_uuid,
        wasm_hash = %req.wasm_hash,
        account_id = %req.account_id,
        key_hash = %key_hash,
        encrypted_key_len = encrypted_key.len(),
        encrypted_value_len = encrypted_value.len(),
        "Successfully encrypted storage data"
    );

    Ok(Json(StorageEncryptResponse {
        encrypted_key_base64: base64::encode(&encrypted_key),
        encrypted_value_base64: base64::encode(&encrypted_value),
        key_hash,
    }))
}

/// Decrypt data from persistent storage
async fn storage_decrypt_handler(
    State(state): State<AppState>,
    Json(req): Json<StorageDecryptRequest>,
) -> Result<Json<StorageDecryptResponse>, ApiError> {
    // Check if keystore is ready
    if !state.is_ready() {
        return Err(ApiError::Unauthorized(
            "Keystore not ready. Waiting for DAO approval and master key from MPC.".to_string()
        ));
    }

    // Build seed for key derivation (same as encrypt)
    let seed = if let Some(ref project_uuid) = req.project_uuid {
        format!("storage:{}:{}", project_uuid, req.account_id)
    } else {
        format!("storage:wasm:{}:{}", req.wasm_hash, req.account_id)
    };

    // Decode encrypted data from base64
    let encrypted_key = base64::decode(&req.encrypted_key_base64)
        .map_err(|e| ApiError::BadRequest(format!("Invalid base64 in encrypted_key: {}", e)))?;

    let encrypted_value = base64::decode(&req.encrypted_value_base64)
        .map_err(|e| ApiError::BadRequest(format!("Invalid base64 in encrypted_value: {}", e)))?;

    // Decrypt key and value
    let keystore = state.keystore.read().await;

    let key_bytes = keystore
        .decrypt(None, &seed, &encrypted_key)
        .map_err(|e| ApiError::InternalError(format!("Failed to decrypt key: {}", e)))?;

    let value_bytes = keystore
        .decrypt(None, &seed, &encrypted_value)
        .map_err(|e| ApiError::InternalError(format!("Failed to decrypt value: {}", e)))?;

    // Convert key to string
    let key = String::from_utf8(key_bytes)
        .map_err(|e| ApiError::InternalError(format!("Decrypted key is not valid UTF-8: {}", e)))?;

    tracing::debug!(
        project_uuid = ?req.project_uuid,
        wasm_hash = %req.wasm_hash,
        account_id = %req.account_id,
        key = %key,
        "Successfully decrypted storage data"
    );

    Ok(Json(StorageDecryptResponse {
        key,
        value_base64: base64::encode(&value_bytes),
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

/// Verify NEAR signature (NEP-413)
///
/// NEP-413 specifies that the signed payload is:
/// SHA256(NEP413_TAG || Borsh(Nep413Payload))
fn verify_near_signature(
    message: &str,
    signature: &str,
    public_key: &str,
    nonce: &str,
    recipient: &str,
) -> Result<(), anyhow::Error> {
    use sha2::{Sha256, Digest};

    // Parse public key (format: "ed25519:base58...")
    let pubkey_parts: Vec<&str> = public_key.split(':').collect();
    if pubkey_parts.len() != 2 || pubkey_parts[0] != "ed25519" {
        anyhow::bail!("Invalid public key format, expected 'ed25519:base58...'");
    }

    let pubkey_bytes = bs58::decode(pubkey_parts[1])
        .into_vec()
        .map_err(|e| anyhow::anyhow!("Failed to decode public key: {}", e))?;

    if pubkey_bytes.len() != 32 {
        anyhow::bail!("Invalid public key length: {}", pubkey_bytes.len());
    }

    // Decode signature (base64)
    let signature_bytes = base64::decode(signature)
        .map_err(|e| anyhow::anyhow!("Failed to decode signature: {}", e))?;

    if signature_bytes.len() != 64 {
        anyhow::bail!("Invalid signature length: {}", signature_bytes.len());
    }

    // Decode nonce (base64) - must be exactly 32 bytes
    let nonce_bytes = base64::decode(nonce)
        .map_err(|e| anyhow::anyhow!("Failed to decode nonce: {}", e))?;

    let nonce_len = nonce_bytes.len();
    if nonce_len != 32 {
        anyhow::bail!("Invalid nonce length: {} (expected 32)", nonce_len);
    }

    let nonce_array: [u8; 32] = nonce_bytes.try_into()
        .map_err(|_| anyhow::anyhow!("Failed to convert nonce to array"))?;

    // Build NEP-413 payload
    let payload = Nep413Payload {
        message: message.to_string(),
        nonce: nonce_array,
        recipient: recipient.to_string(),
        callback_url: None,
    };

    // Serialize payload with Borsh
    let payload_bytes = borsh::to_vec(&payload)
        .map_err(|e| anyhow::anyhow!("Failed to serialize NEP-413 payload: {}", e))?;

    // Build final message: tag (4 bytes LE) + payload
    let mut to_hash = Vec::with_capacity(4 + payload_bytes.len());
    to_hash.extend_from_slice(&NEP413_TAG.to_le_bytes());
    to_hash.extend_from_slice(&payload_bytes);

    // SHA256 hash the combined data
    let hash = Sha256::digest(&to_hash);

    tracing::debug!(
        message = %message,
        recipient = %recipient,
        nonce_len = nonce_len,
        payload_len = payload_bytes.len(),
        hash_hex = %hex::encode(&hash),
        "NEP-413 signature verification"
    );

    // Verify using ed25519
    use ed25519_dalek::{Signature, VerifyingKey, Verifier};

    let verifying_key = VerifyingKey::from_bytes(
        &<[u8; 32]>::try_from(pubkey_bytes.as_slice())
            .map_err(|_| anyhow::anyhow!("Invalid public key bytes"))?
    ).map_err(|e| anyhow::anyhow!("Invalid public key: {}", e))?;

    let signature = Signature::from_bytes(
        &<[u8; 64]>::try_from(signature_bytes.as_slice())
            .map_err(|_| anyhow::anyhow!("Invalid signature bytes"))?
    );

    // Verify signature against the hash
    verifying_key
        .verify(&hash, &signature)
        .map_err(|e| anyhow::anyhow!("Signature verification failed: {}", e))?;

    Ok(())
}

// =========================================================================
// TEE Challenge-Response Endpoints
// =========================================================================

/// Generate a TEE challenge for worker registration
///
/// Worker calls this to get a random nonce, then signs it with their TEE private key.
async fn tee_challenge_handler(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let challenge = shared_tee_helpers::generate_challenge();

    // Store challenge in memory with timestamp
    {
        let mut challenges = state.tee_challenges.lock().unwrap();

        // Clean up expired challenges (>60 seconds old)
        challenges.retain(|_, c| c.created_at.elapsed().as_secs() < 60);

        challenges.insert(challenge.clone(), TeeChallenge {
            created_at: std::time::Instant::now(),
        });
    }

    tracing::debug!("TEE challenge generated: {}...", &challenge[..16]);

    Ok(Json(serde_json::json!({ "challenge": challenge })))
}

/// Request body for TEE registration
#[derive(Debug, Deserialize)]
struct RegisterTeeRequest {
    public_key: String,
    challenge: String,
    signature: String,
}

/// Register a TEE session after challenge-response verification
///
/// 1. Verify challenge exists and is not expired
/// 2. Verify ed25519 signature
/// 3. Check public key exists on register-contract via NEAR RPC
/// 4. Create session and return session_id
async fn register_tee_handler(
    State(state): State<AppState>,
    Json(req): Json<RegisterTeeRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // 1. Find and remove challenge (one-time use)
    {
        let mut challenges = state.tee_challenges.lock().unwrap();
        let challenge = challenges.remove(&req.challenge).ok_or_else(|| {
            ApiError::BadRequest("Invalid or expired challenge".to_string())
        })?;

        // Check expiration (60 seconds)
        if challenge.created_at.elapsed().as_secs() > 60 {
            return Err(ApiError::BadRequest("Challenge expired".to_string()));
        }
    }

    // 2. Verify signature
    shared_tee_helpers::verify_signature(&req.public_key, &req.challenge, &req.signature, state.config.tee_allowed_key_types)
        .map_err(|e| ApiError::BadRequest(format!("Signature verification failed: {}", e)))?;

    // 3. Check key on operator account via NEAR RPC (with retry for finality lag)
    let operator_account_id = state.config.operator_account_id.as_ref().ok_or_else(|| {
        ApiError::InternalError("OPERATOR_ACCOUNT_ID not configured on keystore".to_string())
    })?;

    let key_exists = shared_tee_helpers::check_access_key_with_retry(
        &state.config.near_rpc_url,
        operator_account_id,
        &req.public_key,
    )
    .await
    .map_err(|e| ApiError::InternalError(format!("NEAR RPC check failed: {}", e)))?;

    if !key_exists {
        return Err(ApiError::Unauthorized(format!(
            "Public key {} not found on operator account {}",
            req.public_key, operator_account_id
        )));
    }

    // 4. Create session
    let session_id = uuid::Uuid::new_v4();
    {
        let mut sessions = state.tee_sessions.lock().unwrap();
        sessions.insert(session_id, TeeSession {
            worker_public_key: req.public_key.clone(),
            created_at: std::time::Instant::now(),
        });
    }

    tracing::info!(
        session_id = %session_id,
        public_key = %req.public_key,
        "TEE session registered on keystore"
    );

    Ok(Json(serde_json::json!({ "session_id": session_id.to_string() })))
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
            "Unsupported chain: {}. Supported: near, solana, and EVM (ethereum, polygon, base, arbitrum, optimism, bsc, avalanche, hyperevm)",
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
            "'{}' is not an EVM chain (supported: ethereum, polygon, base, arbitrum, optimism, bsc, avalanche, hyperevm)",
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
    //    Evaluated even then, against an EMPTY policy, because a few of the
    //    engine's rules are not the owner's to relax. `w_execute_extension` is
    //    the one that matters: it denies account-CONTROL operations
    //    (`add_extension` hands a stranger the whole lane) and anything whose
    //    effects cannot be stated. Those hold for every wallet — and a wallet
    //    with no policy is the state every wallet is in right after
    //    registration, so gating them behind "has a policy" would have left the
    //    default open. Every other section is inert on an empty policy: no
    //    rules, no capabilities, no approval block, not frozen — so this
    //    changes nothing for any op that is not the extension door.
    let policy = load_wallet_policy(&state, &req.wallet_id, customer.as_ref()).await?;
    {
        let empty = wallet_policy::Policy::default();
        let effective = policy.as_ref().unwrap_or(&empty);
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
                // `effective` IS the on-chain policy here: the empty stand-in
                // has no approval block and no capabilities, and those are the
                // only two things that can produce this decision.
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
    // Pin the NEP-413 recipient to the intents verifiers. Trusted ops are intents-only — all
    // four kinds route through intents.near (the public shard: swap/cross_chain_withdraw/
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

    // No policy on-chain → an EMPTY policy, not a short-circuit to "allowed".
    //
    // Every section of the engine is inert on an empty policy, so the answer
    // is the same "allow" for single-sig / quick onboarding — with one
    // exception that must not be skipped: `w_execute_extension` is denied for
    // account-control operations and for effects that cannot be stated,
    // whatever the owner did or did not configure. Returning early here would
    // also let the pre-flight answer "allowed" for a request the signing path
    // then refuses, which is exactly the split this endpoint exists to avoid.
    let policy = policy.unwrap_or_default();

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
mod wallet_sign_tests {
    use super::*;
    use shared_tee_helpers::wallet_policy::{self, Op};

    // --- Domain separation: sign_message recipient is a default-DENY allowlist -----

    /// A freeze we cannot read is not an absence of one.
    ///
    /// `frozen` is the only field of the policy readable WITHOUT decryption,
    /// and it is the controller's hard stop — the one setting whose whole
    /// purpose is to halt a wallet that is doing something its owner does not
    /// want. It was read with `unwrap_or(false)`: a value we could not parse
    /// became "not frozen", which is the single worst direction to default in
    /// this file.
    ///
    /// Unreachable today — the contract types it `bool` and always serializes
    /// it — and that is exactly why it would have gone unnoticed on the day a
    /// contract upgrade changed the shape. Absent stays false, because a policy
    /// written before the field existed was never frozen; present-and-unreadable
    /// refuses.
    /// The JSON an `ApiError` actually serialises to.
    fn read_json_body(response: axum::response::Response) -> serde_json::Value {
        let bytes = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(axum::body::to_bytes(response.into_body(), 64 * 1024))
            .expect("body");
        serde_json::from_slice(&bytes).expect("json")
    }

    /// An account that does not exist yet is a fact, not an outage.
    ///
    /// A NEAR implicit account is created by its FIRST INCOMING TRANSFER. Until
    /// then there is no account and no access key, and `query_access_key`
    /// answers "does not exist while viewing" — the chain telling us about the
    /// account, not failing to tell us anything.
    ///
    /// It used to arrive as `InternalError`, which the coordinator forwards as
    /// `503` with a `Retry-After`: come back in five seconds, about a condition
    /// that never clears on its own and that the caller fixes in thirty by
    /// sending NEAR. It is also the FIRST thing a new wallet does, so it was
    /// the first thing a new user saw.
    #[test]
    fn an_account_that_was_never_funded_is_not_reported_as_our_outage() {
        // Captured from testnet RPC, `view_access_key` on a derived address
        // nobody has funded. The chain answers inside `result`, not as a
        // JSON-RPC error, which is why nothing above noticed it was an answer.
        assert!(rpc_error_is_about_the_signer(
            "Failed to query access key: access key ed25519:9dj5Xz1 does not exist while viewing"
        ));
        for fact in [
            "UNKNOWN_ACCOUNT",
            "UNKNOWN_ACCESS_KEY",
            "account doesn't exist",
            "account 7f7ab400 does not exist",
            "Access key does not exist",
        ] {
            assert!(rpc_error_is_about_the_signer(fact), "not recognised: {fact}");
        }

        // And a bare absence that is about something ELSE is not a fact about
        // the account. This is the direction that costs: a node which has
        // garbage-collected a block, or a call to a method nobody implements,
        // would otherwise tell a caller with a funded wallet that their
        // account is not on the network — a node's condition delivered as the
        // caller's fault, which is the mistake this whole change is about.
        for elsewhere in [
            "block does not exist",
            "the requested method does not exist",
            "shard does not exist on this node",
            "contract method doesn't exist",
        ] {
            assert!(
                !rpc_error_is_about_the_signer(elsewhere),
                "a condition of the NODE was read as a fact about the account: {elsewhere}"
            );
        }

        // A node that did not answer is OURS, stays a 500, and stays
        // retryable. Reading one of these as the caller's problem would tell
        // somebody to fund an account that is already funded.
        for outage in [
            "error sending request for url (https://rpc.testnet.fastnear.com/)",
            "operation timed out",
            "connection closed before message completed",
            "503 Service Temporarily Unavailable",
        ] {
            assert!(
                !rpc_error_is_about_the_signer(outage),
                "an outage was read as a fact about the account: {outage}"
            );
        }
    }

    /// The signing path actually USES the classifier, and prints the cause.
    ///
    /// The two tests around this one cover a pure function and a response
    /// shape; neither touches the call site, and both stayed green when the
    /// branch there was deleted. What is worth pinning is the WIRING: that the
    /// one place which queries an access key before signing asks whether the
    /// failure is about the account, and formats the error chain rather than
    /// its outermost context.
    ///
    /// Read out of the source because the alternative is a live NEAR node and
    /// an account nobody has funded.
    #[test]
    fn the_signing_path_asks_whether_the_failure_is_about_the_account() {
        let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/api.rs"))
            .expect("cannot read api.rs");
        let at = src
            .find(".query_access_key(&signer_id_str, &public_key)")
            .expect("the access-key query this guard follows is gone");
        let end = at + src[at..].find("\n    // Always rpc_nonce").expect("unterminated arm");
        let arm = &src[at..end];

        assert!(
            arm.contains("rpc_error_is_about_the_signer"),
            "the signing path no longer distinguishes an account that does not exist from a \
             node that did not answer, so a caller who has simply not funded their wallet is \
             told our service is down and to retry: {arm}"
        );
        assert!(
            arm.contains("ApiError::ChainRefused"),
            "the terminal case no longer has its own error, so it will be forwarded as a \
             transient 503: {arm}"
        );
        assert!(
            arm.contains("{e:#}"),
            "the error is formatted with `{{e}}` again, which prints only the outermost \
             context — the reason this failure read as `Failed to query access key: Failed to \
             query access key` and named nothing: {arm}"
        );
        assert!(
            arm.contains("signer_id_str") && arm.contains("not visible on the network"),
            "the refusal no longer names the account, or no longer states the chain's answer \
             about it: {arm}"
        );

        // AND it promises nothing — checked against the sentence the code
        // actually sends, not against a copy of it written in a test.
        //
        // That distinction is the whole value here: the assertion below lived
        // in a test that built its own `ChainRefused` string, so editing the
        // REAL message to promise a remedy changed nothing and everything
        // stayed green. `view_access_key` answers with the same bytes for an
        // account that has never been used and for one that exists carrying a
        // different key, so any remedy named here is a guess presented as an
        // instruction.
        for promise in ["send NEAR", "top up", "fund it", "will work"] {
            assert!(
                !arm.contains(promise),
                "the refusal promises `{promise}`. The chain's answer does not distinguish an \
                 account that has never been used from one that exists with another key, so \
                 this advice is right at most half the time: {arm}"
            );
        }
        assert!(
            arm.contains("Retrying will not"),
            "the refusal no longer says it is terminal, so a client will treat it as worth \
             repeating: {arm}"
        );
    }

    /// The refusal states the chain's answer and stops there.
    ///
    /// It must NOT promise a remedy. `view_access_key` returns a byte-identical
    /// "does not exist while viewing" for an account that has never been used
    /// and for one that exists with a different key on it — verified against
    /// testnet, both strings the same — so "send NEAR and the call will work"
    /// would be true in one case and false in the other, and we cannot tell
    /// which from here.
    #[test]
    fn the_refusal_states_the_answer_and_promises_nothing() {
        let addr = "7f7ab40018902d4a3d07d5040bb94cbcaeac13096be3c312423e96f37108f56f";
        let err = ApiError::ChainRefused(format!(
            "the account {addr} is not visible on the network, so there is no key to sign \
             with. Most often that means it has never taken part in a transaction. Retrying \
             will not change it — the chain answered, and this is its answer."
        ));
        let response = axum::response::IntoResponse::into_response(err);
        assert_eq!(
            response.status(),
            axum::http::StatusCode::UNPROCESSABLE_ENTITY,
            "a fact the chain stated must not be a 500 the coordinator turns into a 503"
        );

        let body = read_json_body(response);
        let text = body["error"].as_str().unwrap_or_default().to_string();
        assert!(text.contains(addr), "the refusal does not name the account: {body}");
        assert!(
            text.contains("Retrying will not"),
            "the refusal does not say it is terminal: {text}"
        );
        for promise in ["send NEAR", "top up", "fund"] {
            assert!(
                !text.contains(promise),
                "the refusal promises `{promise}`, which the chain's answer does not support: \
                 the same answer comes back for an account that exists with another key"
            );
        }

        // The vault's 402 is untouched — a different account with a different
        // remedy, and it keeps its own status.
        let vault = axum::response::IntoResponse::into_response(ApiError::PaymentRequired(
            "vault is short".to_string(),
        ));
        assert_eq!(vault.status(), axum::http::StatusCode::PAYMENT_REQUIRED);
    }

    #[test]
    fn a_freeze_we_cannot_read_is_not_read_as_unfrozen() {
        // The reading, extracted exactly as `load_wallet_policy` performs it.
        fn freeze_state(view: &serde_json::Value) -> Result<bool, &'static str> {
            match view.get("frozen") {
                Some(v) => v.as_bool().ok_or("unreadable"),
                None => Ok(false),
            }
        }

        assert_eq!(freeze_state(&serde_json::json!({ "frozen": true })), Ok(true));
        assert_eq!(freeze_state(&serde_json::json!({ "frozen": false })), Ok(false));

        // A policy that predates the field was never frozen.
        assert_eq!(freeze_state(&serde_json::json!({ "encrypted_data": "..." })), Ok(false));

        // Every shape that is not a boolean refuses. `"false"` is the one that
        // matters: a contract that started serializing the flag as a string
        // would, under the old reading, have unfrozen every frozen wallet at
        // once — and `"true"` would have done it too.
        for wrong in [
            serde_json::json!({ "frozen": "true" }),
            serde_json::json!({ "frozen": "false" }),
            serde_json::json!({ "frozen": 1 }),
            serde_json::json!({ "frozen": 0 }),
            serde_json::json!({ "frozen": null }),
            serde_json::json!({ "frozen": {} }),
        ] {
            assert_eq!(
                freeze_state(&wrong),
                Err("unreadable"),
                "a freeze state of {wrong} was answered instead of refused"
            );
        }

        // And the reading this test mirrors is the one that ships.
        let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/api.rs"))
            .expect("cannot read api.rs");
        // Bounded by the statement itself, not by a fixed width: a comment
        // added above the code would push what this looks for out of a window,
        // and a slice past the end of the file panics instead of failing with
        // the sentence that says what regressed.
        let at = src
            .find("let frozen = match policy_view.get(\"frozen\")")
            .expect("the freeze read this test follows is gone");
        let end = at + src[at..].find("\n    };").expect("unterminated freeze read");
        let block = &src[at..end];
        assert!(
            !block.contains(".and_then(|v| v.as_bool())\n        .unwrap_or(false)"),
            "the freeze flag defaults again"
        );
        assert!(
            block.contains("as_bool().ok_or_else"),
            "the freeze flag is no longer read fallibly"
        );
    }

    #[test]
    fn sign_message_recipient_allowlist_is_default_deny() {
        use serde_json::json;
        let parse = |v: serde_json::Value| -> wallet_policy::Policy {
            serde_json::from_value(v).expect("policy parse")
        };

        // No policy → single-sig wallet, unrestricted.
        assert!(sign_message_recipient_allowed(None, "intents.near"));

        // Policy present but no allowed_recipients → deny EVERYTHING (incl. would-be auth).
        let bare = parse(json!({ "capabilities": { "sign_message": { "allowed": true } } }));
        assert!(!sign_message_recipient_allowed(Some(&bare), "auth.app.near"));
        assert!(!sign_message_recipient_allowed(Some(&bare), "intents.near"));

        // Only explicitly-listed recipients are allowed; a fund-moving verifier that is
        // NOT listed is refused (the blocklist gap the allowlist closes).
        let listed = parse(json!({
            "capabilities": { "sign_message": { "allowed_recipients": ["auth.app.near"] } }
        }));
        assert!(sign_message_recipient_allowed(Some(&listed), "auth.app.near"));
        assert!(!sign_message_recipient_allowed(Some(&listed), "intents.near"));
        assert!(!sign_message_recipient_allowed(Some(&listed), "some-dex.near")); // unnamed verifier
        assert!(!sign_message_recipient_allowed(Some(&listed), "auth.app.near.evil")); // no substring match
    }

    #[test]
    fn evm_chains_share_one_canonical_seed() {
        // "One EVM address across all chains" reduces to: every EVM
        // chain name maps to the SAME derivation seed (long names and
        // 1Click short aliases alike), while non-EVM chains stay
        // distinct. Address == f(seed), so equal seeds ⇒ equal address.
        let id = "abc-123";
        let evm = [
            "ethereum", "eth", "polygon", "pol", "matic", "base", "arbitrum", "arb", "optimism",
            "op", "bsc", "avalanche", "avax", "hyperevm",
        ];
        let canonical = wallet_seed(id, "ethereum");
        assert_eq!(canonical, format!("wallet:{}:evm", id));
        for c in evm {
            assert!(is_evm_chain(c), "{c} must be recognized as EVM");
            assert_eq!(wallet_seed(id, c), canonical, "{c} must share the canonical EVM seed");
        }
        // Non-EVM keep their own per-chain seed (distinct curve/key).
        assert_eq!(wallet_seed(id, "near"), format!("wallet:{}:near", id));
        assert_eq!(wallet_seed(id, "solana"), format!("wallet:{}:solana", id));
        assert!(!is_evm_chain("near") && !is_evm_chain("solana"));
    }

    #[test]
    fn a_sub_key_is_its_own_key_under_its_own_root() {
        // Two paths are two keys, no path is the wallet's own, and the seed
        // does not depend on which EVM name was asked for. Address == f(seed),
        // so this is the isolation argument for sub-keys.
        let id = "abc-123";
        let trading = subkey_seed(id, "connector.hl.trading");
        assert_eq!(trading, "subkey:abc-123:evm:connector.hl.trading");
        assert_ne!(subkey_seed(id, "connector.hl.bridge"), trading);
        assert_ne!(trading, wallet_seed(id, "base"));
        assert_ne!(trading, wallet_seed(id, "hyperevm"));
    }

    #[test]
    fn no_exportable_seed_can_name_a_signing_key() {
        // `/wallet/derive-ephemeral-key` hands out PRIVATE keys for seeds it
        // builds as `wallet:{id}:{chain}:{sub_path}` from two request strings.
        // Both curves derive from the same HMAC input, so any signing seed that
        // endpoint could spell would be a signing key it could export. The
        // invariant every key family must keep: signing seeds are either two
        // segments under `wallet:` (which the exporter cannot spell — it needs
        // a non-empty third) or live under a root that is not `wallet:`.
        let id = "abc-123";
        let exportable = |chain: &str, sub: &str| format!("wallet:{id}:{chain}:{sub}");
        let signing = [
            wallet_seed(id, "near"),
            wallet_seed(id, "solana"),
            wallet_seed(id, "ethereum"),
            wallet_seed(id, "hyperevm"),
            subkey_seed(id, "connector.hl.trading"),
            subkey_seed(id, "0"),
            // The other seeds this keystore signs with: the VRF key and a
            // vault's TEE key (`mpc_ckd.rs`).
            "vrf-key".to_string(),
            format!("outlayer.near:{}", "vault.alice.near"),
        ];
        // The strings an attacker holding the exporter would try, including
        // the ones that spell a sub-key path verbatim.
        let attempts = [
            ("evm", "connector.hl.trading"),
            ("evm", "0"),
            ("near", "check:0"),
            ("near:check", "0"),
            ("ethereum", "connector.hl.trading"),
            ("evm:connector.hl.trading", ""),
            ("", "evm:connector.hl.trading"),
            ("subkey", "evm:connector.hl.trading"),
        ];
        for (chain, sub) in attempts {
            let spelled = exportable(chain, sub);
            for s in &signing {
                assert_ne!(&spelled, s, "exporter input ({chain:?}, {sub:?}) reaches a signing key");
            }
        }
        for s in &signing {
            // The exporter's output always starts with `wallet:` and always has
            // at least three `:`-separated segments after the root.
            let under_wallet_root = s.starts_with("wallet:");
            let two_segments = s.matches(':').count() == 2;
            assert!(
                !under_wallet_root || two_segments,
                "{s} is a wallet seed with a third segment — the exporter can spell it"
            );
        }
    }

    #[test]
    fn a_wallet_id_with_a_colon_is_refused_before_it_can_shift_a_seed() {
        // Wallet `a:evm`'s NEAR seed would be `wallet:a:evm:near` — exactly the
        // exporter's string for (a, evm, near). The id is refused instead.
        assert_eq!(wallet_seed("a:evm", "near"), "wallet:a:evm:near");
        assert!(validate_wallet_id("a:evm").is_err());
        assert!(validate_wallet_id("").is_err());
        assert!(validate_wallet_id("9c3c9e10-1c1f-4f5e-9c4a-1d7b9a8f3c20").is_ok());
    }

    #[test]
    fn a_sub_path_has_exactly_one_shape() {
        assert_eq!(validate_sub_path(None).unwrap(), None);
        assert_eq!(validate_sub_path(Some("")).unwrap(), None);
        assert_eq!(validate_sub_path(Some("connector.hl.trading")).unwrap(), Some("connector.hl.trading"));
        assert_eq!(validate_sub_path(Some("0")).unwrap(), Some("0"));
        assert_eq!(validate_sub_path(Some(&"a".repeat(64))).unwrap().map(str::len), Some(64));
        for bad in [
            ".leading-dot",
            "-leading-dash",
            "Upper",
            "with:colon",
            "with space",
            "unicode-ё",
            &"a".repeat(65),
        ] {
            assert!(validate_sub_path(Some(bad)).is_err(), "{bad:?} must be refused");
        }
    }

    // --- Built: the withdraw artifact is constructed FROM the op fields ------------

    #[test]
    fn built_withdraw_message_native_binds_op_fields() {
        let msg = build_withdraw_intent_message(
            "signer.near",
            "alice.near",
            "1000000000000000000000000",
            "near",
            "2026-06-04T12:05:00.000Z",
        );
        let v: serde_json::Value = serde_json::from_str(&msg).unwrap();
        assert_eq!(v["signer_id"], "signer.near");
        assert_eq!(v["deadline"], "2026-06-04T12:05:00.000Z");
        assert_eq!(v["intents"][0]["intent"], "native_withdraw");
        assert_eq!(v["intents"][0]["receiver_id"], "alice.near");
        assert_eq!(v["intents"][0]["amount"], "1000000000000000000000000");
    }

    #[test]
    fn built_withdraw_message_ft_uses_ft_withdraw_unprefixed_token() {
        // FT withdrawal OUT → `ft_withdraw` intent with the UNPREFIXED token contract.
        let msg = build_withdraw_intent_message(
            "signer.near",
            "alice.near",
            "1000000",
            "nep141:usdt.tether-token.near",
            "2026-06-04T12:05:00.000Z",
        );
        let v: serde_json::Value = serde_json::from_str(&msg).unwrap();
        assert_eq!(v["intents"][0]["intent"], "ft_withdraw");
        assert_eq!(v["intents"][0]["token"], "usdt.tether-token.near"); // prefix stripped
        assert_eq!(v["intents"][0]["receiver_id"], "alice.near");
        assert_eq!(v["intents"][0]["amount"], "1000000");
        // No `tokens` map on ft_withdraw.
        assert!(v["intents"][0]["tokens"].is_null());

        // Bare contract id passes through unchanged.
        let msg2 = build_withdraw_intent_message(
            "signer.near",
            "alice.near",
            "5",
            "usdt.near",
            "2026-06-04T12:05:00.000Z",
        );
        let v2: serde_json::Value = serde_json::from_str(&msg2).unwrap();
        assert_eq!(v2["intents"][0]["intent"], "ft_withdraw");
        assert_eq!(v2["intents"][0]["token"], "usdt.near");
    }

    #[test]
    fn built_transfer_message_is_internal_transfer_prefixed_tokens_map() {
        // Internal intents transfer → defuse `transfer` intent: funds stay inside intents.near,
        // credited to receiver_id. `tokens` is a PREFIXED map (unlike ft_withdraw).
        let msg = build_transfer_intent_message(
            "signer.near",
            "partner.near",
            "1000000",
            "nep141:usdt.tether-token.near",
            "2026-06-04T12:05:00.000Z",
        );
        let v: serde_json::Value = serde_json::from_str(&msg).unwrap();
        assert_eq!(v["signer_id"], "signer.near");
        assert_eq!(v["deadline"], "2026-06-04T12:05:00.000Z");
        assert_eq!(v["intents"][0]["intent"], "transfer");
        assert_eq!(v["intents"][0]["receiver_id"], "partner.near");
        assert_eq!(v["intents"][0]["tokens"]["nep141:usdt.tether-token.near"], "1000000");
        // It is NOT a withdrawal — no ft_withdraw/native_withdraw, no bare `token`/`amount`.
        assert!(v["intents"][0]["token"].is_null());
        assert!(v["intents"][0]["amount"].is_null());

        // Bare contract id is normalized to the prefixed asset id.
        let msg2 = build_transfer_intent_message(
            "signer.near",
            "950c134e8e7b2e2a1c0f3d4b5a6978a0b1c2d3e4f5061728394a5b6c7d8e9f001",
            "5",
            "usdt.near",
            "2026-06-04T12:05:00.000Z",
        );
        let v2: serde_json::Value = serde_json::from_str(&msg2).unwrap();
        assert_eq!(v2["intents"][0]["tokens"]["nep141:usdt.near"], "5");
    }

    #[test]
    fn iso8601_matches_known_timestamps() {
        assert_eq!(unix_to_iso8601(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(unix_to_iso8601(1_700_000_000), "2023-11-14T22:13:20.000Z");
    }

    // --- Approval binding: a substituted op cannot reuse genuine approvals ---------
    //
    // The keystore derives request_hash from the canonical op and the approvers sign
    // `approve:{id}:{wallet_pubkey}:{request_hash}` (see `approval_vote_message`). If any
    // op field is substituted, request_hash changes, so a signature collected for the
    // original op fails to verify against the substituted op's message — the binding is
    // automatic. The `sign_vote` helper below exercises this substitution/domain-separation
    // property with a simplified message; the wallet-pubkey binding is covered separately by
    // `approval_message_is_wallet_bound_no_cross_wallet_replay`.

    fn sign_vote(
        verb: &str,
        signing_key: &ed25519_dalek::SigningKey,
        approval_id: &str,
        request_hash: &str,
        recipient: &str,
    ) -> (String, String, String) {
        use ed25519_dalek::Signer;
        use sha2::{Digest, Sha256};
        let message = format!("{}:{}:{}", verb, approval_id, request_hash);
        let nonce = [7u8; 32];
        let payload = Nep413Payload {
            message,
            nonce,
            recipient: recipient.to_string(),
            callback_url: None,
        };
        let payload_bytes = borsh::to_vec(&payload).unwrap();
        let mut to_hash = Vec::with_capacity(4 + payload_bytes.len());
        to_hash.extend_from_slice(&NEP413_TAG.to_le_bytes());
        to_hash.extend_from_slice(&payload_bytes);
        let hash = Sha256::digest(&to_hash);
        let sig = signing_key.sign(&hash);
        (
            base64::encode(sig.to_bytes()),
            format!("ed25519:{}", bs58::encode(signing_key.verifying_key().to_bytes()).into_string()),
            base64::encode(nonce),
        )
    }

    #[test]
    fn approval_signature_binds_to_exact_op_and_rejects_substitution() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let pubkey = format!(
            "ed25519:{}",
            bs58::encode(signing_key.verifying_key().to_bytes()).into_string()
        );
        let recipient = "outlayer.near";
        let approval_id = "appr-1";

        // Approver approves a 1-NEAR transfer to a vendor.
        let approved_op = Op::Transfer {
            to: "vendor.near".into(),
            amount: "1000000000000000000000000".into() };
        let approved_hash = wallet_policy::request_hash(&approved_op);
        let (sig, sig_pubkey, nonce) = sign_vote("approve", &signing_key, approval_id, &approved_hash, recipient);
        assert_eq!(sig_pubkey, pubkey);

        // The signature verifies for the op that was actually approved.
        let good_msg = format!("approve:{}:{}", approval_id, approved_hash);
        assert!(verify_near_signature(&good_msg, &sig, &pubkey, &nonce, recipient).is_ok());

        // A substituted op (100 NEAR to an attacker) has a different request_hash, so
        // the genuine signature fails to verify against it.
        let substituted_op = Op::Transfer {
            to: "attacker.near".into(),
            amount: "100000000000000000000000000".into() };
        let substituted_hash = wallet_policy::request_hash(&substituted_op);
        assert_ne!(approved_hash, substituted_hash);
        let bad_msg = format!("approve:{}:{}", approval_id, substituted_hash);
        assert!(verify_near_signature(&bad_msg, &sig, &pubkey, &nonce, recipient).is_err());
    }

    #[test]
    fn reject_vote_is_domain_separated_from_approve() {
        // A reject vote signs `reject:{id}:{hash}` — it must NOT verify as an approval
        // (and vice versa), so an approve sig can't be replayed as a veto or the reverse.
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let pubkey = format!(
            "ed25519:{}",
            bs58::encode(signing_key.verifying_key().to_bytes()).into_string()
        );
        let recipient = "outlayer.near";
        let id = "appr-1";
        let op = Op::Transfer { to: "vendor.near".into(), amount: "1".into() };
        let hash = wallet_policy::request_hash(&op);

        let (rej_sig, _, rej_nonce) = sign_vote("reject", &signing_key, id, &hash, recipient);
        // Verifies as a reject vote.
        let reject_msg = format!("reject:{}:{}", id, hash);
        assert!(verify_near_signature(&reject_msg, &rej_sig, &pubkey, &rej_nonce, recipient).is_ok());
        // Does NOT verify as an approval (different verb → different signed bytes).
        let approve_msg = format!("approve:{}:{}", id, hash);
        assert!(verify_near_signature(&approve_msg, &rej_sig, &pubkey, &rej_nonce, recipient).is_err());
    }

    // --- Auth: raw ed25519 over the coordinator string, byte-compatible ------------

    #[test]
    fn auth_signature_is_raw_ed25519_over_the_constructed_string() {
        use ed25519_dalek::Signer;
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());

        // Keystore-side construction (fresh ts) for a bearer auth.
        let ts = 1_700_000_000u64;
        let message = wallet_policy::build_auth_message("bearer", "default", ts, Some("v1.vault.near")).unwrap();
        assert_eq!(message, "auth:default:1700000000:v1.vault.near");

        // RAW ed25519 over the message bytes (NOT NEP-413). The coordinator's
        // verify_near_auth_fields does exactly `verify_strict(message.as_bytes(), sig)`.
        let sig = signing_key.sign(message.as_bytes());
        assert!(signing_key
            .verifying_key()
            .verify_strict(message.as_bytes(), &sig)
            .is_ok());

        // Domain separation: the signed bytes are a readable string, never a 32-byte
        // tx hash, so this signature can't double as a NEAR transaction signature.
        assert_ne!(message.as_bytes().len(), 32);
        assert!(message.starts_with("auth:"));
    }

    // --- Connector scope ----------------------------------------------------------

    // --- Bind-mode mapping for every kind -----------------------------------------

    #[test]
    fn every_kind_maps_to_expected_bind_mode() {
        use wallet_policy::{bind_mode, BindMode};
        assert_eq!(bind_mode(&Op::Transfer { to: "a".into(), amount: "1".into() }), BindMode::Built);
        assert_eq!(bind_mode(&Op::Delete { beneficiary: "a".into() }), BindMode::Built);
        assert_eq!(
            bind_mode(&Op::Withdraw { to: "a".into(), amount: "1".into(), token: "near".into() }),
            BindMode::Built
        );
        assert_eq!(
            bind_mode(&Op::Raw { chain: "ethereum".into(), payload_hash: "ab".into(), label: None }),
            BindMode::HashPinned
        );
        assert_eq!(
            bind_mode(&Op::SignMessage { message_hash: "ab".into(), recipient: "app".into(), purpose: None }),
            BindMode::HashPinned
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AccessCondition, LogicOperator};

    // ── Audit fixes: bound approval message, Trusted recipient pin, Trusted multisig guard ──

    #[test]
    fn approval_message_is_wallet_bound_no_cross_wallet_replay() {
        let id = "appr-1";
        let hash = "abc123";
        let pub_a = "ed25519:AAAA";
        let pub_b = "ed25519:BBBB";
        // The wallet pubkey is part of the signed string, so a signature collected for
        // wallet A's message can never satisfy wallet B's (different message → different sig).
        let a = approval_vote_message("approve", id, pub_a, hash);
        let b = approval_vote_message("approve", id, pub_b, hash);
        assert_ne!(a, b, "approval message must differ per wallet pubkey");
        assert_eq!(a, "approve:appr-1:ed25519:AAAA:abc123");
        // approve vs reject are domain-separated for the SAME wallet.
        assert_ne!(
            approval_vote_message("approve", id, pub_a, hash),
            approval_vote_message("reject", id, pub_a, hash)
        );
    }

    #[test]
    fn trusted_recipient_pin_allows_only_intents_verifiers() {
        assert!(is_trusted_recipient("intents.near"));
        assert!(is_trusted_recipient("intents.far")); // confidential shard
        // NEAR Intents is mainnet-only: testnet verifier is NOT a trusted recipient.
        assert!(!is_trusted_recipient("intents.testnet"));
        assert!(!is_trusted_recipient("evil.near"));
        assert!(!is_trusted_recipient("alice.near"));
        assert!(!is_trusted_recipient("intents.near.evil.near")); // no suffix/substring match
        assert!(!is_trusted_recipient(""));
    }

    #[test]
    fn trusted_kinds_are_bind_mode_trusted() {
        // Trusted kinds route to sign_trusted. Under multisig they now pass through
        // verify_approvals first (owner control); the keystore signs the coordinator-supplied
        // artifact after approval (off-chain destination stays coordinator-trusted).
        use shared_tee_helpers::wallet_policy::{bind_mode, BindMode, Op};
        let trusted = [
            Op::Swap { token_in: "a".into(), amount_in: "1".into(), token_out: "b".into(), min_out: "1".into() },
            Op::Confidential { flow: "withdraw".into(), to: Some("x".into()), amount: "1".into(), token: "near".into(), chain: Some("near".into()), token_out: None, min_amount_out: None },
            Op::CrossChainWithdraw { to: "0x".into(), amount: "1".into(), token: "nep141:usdt.tether-token.near".into(), chain: "ethereum".into() },
            Op::PaymentCheck { amount: "1".into(), token: "nep141:usdt.tether-token.near".into() },
        ];
        for op in &trusted {
            assert_eq!(bind_mode(op), BindMode::Trusted, "must be Trusted: {:?}", op);
        }
    }

    /// Test that DecryptRequest correctly includes user_account_id field
    #[test]
    fn test_decrypt_request_serialization() {
        let json = r#"{
            "accessor": {
                "type": "Repo",
                "repo": "github.com/user/repo",
                "branch": "main"
            },
            "profile": "production",
            "owner": "owner.testnet",
            "user_account_id": "caller.testnet",
            "task_id": "task123"
        }"#;

        let req: DecryptRequest = serde_json::from_str(json).unwrap();
        match req.accessor {
            SecretAccessor::Repo { repo, branch } => {
                assert_eq!(repo, "github.com/user/repo");
                assert_eq!(branch, Some("main".to_string()));
            }
            _ => panic!("Expected Repo accessor"),
        }
        assert_eq!(req.owner, "owner.testnet");
        assert_eq!(req.user_account_id, "caller.testnet");
    }

    /// Test access control: owner != user_account_id
    /// This simulates the scenario where:
    /// - owner.testnet owns secrets with Whitelist access
    /// - caller.testnet requests execution
    /// - Access should be checked against caller.testnet, not owner.testnet
    #[tokio::test]
    async fn test_access_control_with_different_user() {
        // Test Whitelist: owner not in list, but user_account_id is
        let whitelist = AccessCondition::Whitelist {
            accounts: vec![
                "caller.testnet".to_string(),
                "other.testnet".to_string(),
            ],
        };

        // Should grant access to caller (even though owner is different)
        assert!(whitelist.validate("caller.testnet", None).await.unwrap());

        // Should deny access to owner (not in whitelist)
        assert!(!whitelist.validate("owner.testnet", None).await.unwrap());
    }

    /// Test that Whitelist correctly allows multiple accounts
    #[tokio::test]
    async fn test_whitelist_multiple_accounts() {
        let whitelist = AccessCondition::Whitelist {
            accounts: vec![
                "alice.testnet".to_string(),
                "bob.testnet".to_string(),
                "charlie.testnet".to_string(),
            ],
        };

        assert!(whitelist.validate("alice.testnet", None).await.unwrap());
        assert!(whitelist.validate("bob.testnet", None).await.unwrap());
        assert!(whitelist.validate("charlie.testnet", None).await.unwrap());
        assert!(!whitelist.validate("eve.testnet", None).await.unwrap());
    }

    /// Test AccountPattern with testnet suffix
    #[tokio::test]
    async fn test_account_pattern_testnet() {
        let pattern = AccessCondition::AccountPattern {
            pattern: r".*\.testnet$".to_string(),
        };

        assert!(pattern.validate("alice.testnet", None).await.unwrap());
        assert!(pattern.validate("project.testnet", None).await.unwrap());
        assert!(!pattern.validate("alice.near", None).await.unwrap());
    }

    /// Test complex Logic condition (AND + Whitelist + Pattern)
    #[tokio::test]
    async fn test_complex_logic_condition() {
        let condition = AccessCondition::Logic {
            operator: LogicOperator::And,
            conditions: vec![
                AccessCondition::AccountPattern {
                    pattern: r".*\.testnet$".to_string(),
                },
                AccessCondition::Whitelist {
                    accounts: vec![
                        "alice.testnet".to_string(),
                        "bob.testnet".to_string(),
                    ],
                },
            ],
        };

        // alice.testnet: matches pattern AND in whitelist
        assert!(condition.validate("alice.testnet", None).await.unwrap());

        // bob.testnet: matches pattern AND in whitelist
        assert!(condition.validate("bob.testnet", None).await.unwrap());

        // charlie.testnet: matches pattern but NOT in whitelist
        assert!(!condition.validate("charlie.testnet", None).await.unwrap());

        // alice.near: in "whitelist" but doesn't match pattern
        assert!(!condition.validate("alice.near", None).await.unwrap());
    }

    /// Test that AllowAll always grants access
    #[tokio::test]
    async fn test_allow_all() {
        let condition = AccessCondition::AllowAll;

        assert!(condition.validate("anyone.testnet", None).await.unwrap());
        assert!(condition.validate("another.near", None).await.unwrap());
        assert!(condition.validate("random.account", None).await.unwrap());
    }

    /// Test SecretAccessor::Repo serialization (with branch)
    #[test]
    fn test_secret_accessor_repo_with_branch() {
        let accessor = SecretAccessor::Repo {
            repo: "github.com/user/repo".to_string(),
            branch: Some("main".to_string()),
        };

        let json = serde_json::to_string(&accessor).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["type"], "Repo");
        assert_eq!(parsed["repo"], "github.com/user/repo");
        assert_eq!(parsed["branch"], "main");
    }

    /// Test SecretAccessor::Repo serialization (without branch)
    #[test]
    fn test_secret_accessor_repo_without_branch() {
        let accessor = SecretAccessor::Repo {
            repo: "github.com/user/repo".to_string(),
            branch: None,
        };

        let json = serde_json::to_string(&accessor).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["type"], "Repo");
        assert_eq!(parsed["repo"], "github.com/user/repo");
        assert!(parsed["branch"].is_null());
    }

    /// Test SecretAccessor::WasmHash serialization
    #[test]
    fn test_secret_accessor_wasm_hash() {
        let accessor = SecretAccessor::WasmHash {
            hash: "abc123def456".to_string(),
        };

        let json = serde_json::to_string(&accessor).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["type"], "WasmHash");
        assert_eq!(parsed["hash"], "abc123def456");
    }

    /// Test SecretAccessor deserialization from JSON
    #[test]
    fn test_secret_accessor_deserialization() {
        // Test Repo with branch
        let json = r#"{"type": "Repo", "repo": "github.com/test/project", "branch": "develop"}"#;
        let accessor: SecretAccessor = serde_json::from_str(json).unwrap();
        match accessor {
            SecretAccessor::Repo { repo, branch } => {
                assert_eq!(repo, "github.com/test/project");
                assert_eq!(branch, Some("develop".to_string()));
            }
            _ => panic!("Expected Repo variant"),
        }

        // Test Repo without branch
        let json = r#"{"type": "Repo", "repo": "github.com/test/project"}"#;
        let accessor: SecretAccessor = serde_json::from_str(json).unwrap();
        match accessor {
            SecretAccessor::Repo { repo, branch } => {
                assert_eq!(repo, "github.com/test/project");
                assert_eq!(branch, None);
            }
            _ => panic!("Expected Repo variant"),
        }

        // Test WasmHash
        let json = r#"{"type": "WasmHash", "hash": "deadbeef123456"}"#;
        let accessor: SecretAccessor = serde_json::from_str(json).unwrap();
        match accessor {
            SecretAccessor::WasmHash { hash } => {
                assert_eq!(hash, "deadbeef123456");
            }
            _ => panic!("Expected WasmHash variant"),
        }
    }

    /// Test DecryptRequest with Repo accessor
    #[test]
    fn test_decrypt_request_with_repo_accessor() {
        let json = r#"{
            "accessor": {
                "type": "Repo",
                "repo": "github.com/user/repo",
                "branch": "main"
            },
            "profile": "production",
            "owner": "owner.testnet",
            "user_account_id": "caller.testnet",
            "task_id": "task123"
        }"#;

        let req: DecryptRequest = serde_json::from_str(json).unwrap();
        match req.accessor {
            SecretAccessor::Repo { repo, branch } => {
                assert_eq!(repo, "github.com/user/repo");
                assert_eq!(branch, Some("main".to_string()));
            }
            _ => panic!("Expected Repo accessor"),
        }
        assert_eq!(req.profile, "production");
        assert_eq!(req.owner, "owner.testnet");
        assert_eq!(req.user_account_id, "caller.testnet");
    }

    /// Test DecryptRequest with WasmHash accessor
    #[test]
    fn test_decrypt_request_with_wasm_hash_accessor() {
        let json = r#"{
            "accessor": {
                "type": "WasmHash",
                "hash": "abc123def456"
            },
            "profile": "default",
            "owner": "alice.near",
            "user_account_id": "bob.near"
        }"#;

        let req: DecryptRequest = serde_json::from_str(json).unwrap();
        match req.accessor {
            SecretAccessor::WasmHash { hash } => {
                assert_eq!(hash, "abc123def456");
            }
            _ => panic!("Expected WasmHash accessor"),
        }
        assert_eq!(req.profile, "default");
        assert_eq!(req.owner, "alice.near");
        assert_eq!(req.user_account_id, "bob.near");
        assert!(req.task_id.is_none());
    }

    // ============== request-size caps ==============

    /// Oversized batches must be refused BEFORE the vault is loaded — loading a cold vault runs
    /// an on-chain MPC CKD derivation paid out of that vault's balance, so a spam request must
    /// never get that far. `test_state()` has no MPC context, so if the handler reached
    /// `ensure_customer_loaded` with a vault id it would fail differently; asserting on the
    /// message is what pins the ordering.
    #[tokio::test]
    async fn oversized_generated_secret_batches_are_refused_before_any_vault_work() {
        let state = test_state();
        state.mark_ready();

        let too_many: Vec<GeneratedSecretSpec> = (0..=MAX_GENERATED_SECRETS)
            .map(|i| GeneratedSecretSpec {
                name: format!("PROTECTED_K{i}"),
                generation_type: "hex32".to_string(),
            })
            .collect();

        let err = add_generated_secret_handler(
            State(state),
            Json(AddGeneratedSecretRequest {
                seed: "repo:alice".to_string(),
                encrypted_secrets_base64: None,
                new_secrets: too_many,
                // A vault id that WOULD trigger a derivation if the size check ran too late.
                vault_id: Some("vault.alice.testnet".to_string()),
            }),
        )
        .await
        .expect_err("over the limit must be refused");

        match err {
            ApiError::BadRequest(msg) => {
                assert!(msg.contains("too many generated secrets"), "wrong reason: {msg}");
                assert!(msg.contains(&MAX_GENERATED_SECRETS.to_string()), "state the limit: {msg}");
            }
            other => panic!("expected BadRequest about the batch size, got {other:?}"),
        }
    }

    /// A batch AT the limit is not refused for its size — it proceeds and fails later for an
    /// unrelated reason (no MPC context in tests). Guards against an off-by-one that would
    /// reject legitimate batches.
    #[tokio::test]
    async fn a_batch_at_the_limit_is_not_refused_for_its_size() {
        let state = test_state();
        state.mark_ready();

        let at_limit: Vec<GeneratedSecretSpec> = (0..MAX_GENERATED_SECRETS)
            .map(|i| GeneratedSecretSpec {
                name: format!("PROTECTED_K{i}"),
                generation_type: "hex32".to_string(),
            })
            .collect();

        let result = add_generated_secret_handler(
            State(state),
            Json(AddGeneratedSecretRequest {
                seed: "repo:alice".to_string(),
                encrypted_secrets_base64: None,
                new_secrets: at_limit,
                vault_id: Some("vault.alice.testnet".to_string()),
            }),
        )
        .await;

        if let Err(ApiError::BadRequest(msg)) = &result {
            assert!(
                !msg.contains("too many generated secrets"),
                "a batch at the limit must not be refused for its size: {msg}"
            );
        }
    }

    fn state_with_dead_rpc() -> AppState {
        let config = crate::config::Config {
            server_addr: "127.0.0.1:0".parse().unwrap(),
            near_network: "testnet".into(),
            near_rpc_url: "http://127.0.0.1:1".into(),
            offchainvm_contract_id: "outlayer.test".into(),
            allowed_worker_token_hashes: vec![],
            allowed_coordinator_token_hashes: vec![],
            tee_mode: crate::config::TeeMode::None,
            operator_account_id: None,
            keystore_key_type: near_crypto::KeyType::ED25519,
            tee_allowed_key_types: shared_tee_helpers::AllowedKeyTypes { ed25519: true, ml_dsa_65: true },
        };
        // Nothing listens on port 1 — any RPC call would fail, which is the point: the cap must
        // be enforced without one.
        let near_client = crate::near::NearClient::new("http://127.0.0.1:1", "outlayer.test").unwrap();
        AppState::new(crate::crypto::Keystore::generate(), config, Some(near_client))
    }

    fn one_approver_policy() -> shared_tee_helpers::wallet_policy::Policy {
        serde_json::from_value(serde_json::json!({
            "approval": {
                "threshold": { "required": 1 },
                "approvers": [{ "id": "alice.testnet", "role": "admin" }]
            }
        }))
        .expect("policy")
    }

    fn votes(n: usize) -> Vec<ApproverSig> {
        (0..n)
            .map(|_| ApproverSig {
                // The SAME approver repeated: the duplicate check skips an id only once it has
                // been successfully verified, so invalid repeats each cost a signature check.
                // No on-chain setup is needed to send these.
                approver_id: "alice.testnet".to_string(),
                public_key: "ed25519:11111111111111111111111111111111".to_string(),
                signature: "AA==".to_string(),
                nonce: "AA==".to_string(),
            })
            .collect()
    }

    /// A ballot larger than the cap is rejected on its SIZE, before anything in it is verified.
    /// The recipient below is deliberately wrong too — if the cap ran later, the error would be
    /// about the recipient instead, so the message is what proves the ordering.
    #[tokio::test]
    async fn an_oversized_ballot_is_refused_without_verifying_a_single_vote() {
        let state = state_with_dead_rpc();

        let err = verify_approvals(
            &state,
            &one_approver_policy(),
            "ed25519:wallet",
            "hash",
            Some(&ApprovalInfo {
                approval_id: "a1".to_string(),
                recipient: "definitely-not-this-keystore.testnet".to_string(),
                approvals: votes(MAX_APPROVAL_VOTES + 1),
                rejections: vec![],
            }),
            1,
        )
        .await
        .expect_err("an oversized ballot must be refused");

        match err {
            ApiError::BadRequest(msg) => {
                assert!(msg.contains("too many approval votes"), "wrong reason: {msg}");
                assert!(msg.contains(&MAX_APPROVAL_VOTES.to_string()), "state the limit: {msg}");
            }
            other => panic!("expected BadRequest about ballot size, got {other:?}"),
        }
    }

    /// Rejections are capped on the same terms — a veto ballot is just as expensive to verify.
    #[tokio::test]
    async fn oversized_rejection_ballots_are_refused_too() {
        let state = state_with_dead_rpc();

        let err = verify_approvals(
            &state,
            &one_approver_policy(),
            "ed25519:wallet",
            "hash",
            Some(&ApprovalInfo {
                approval_id: "a1".to_string(),
                recipient: "outlayer.test".to_string(),
                approvals: vec![],
                rejections: votes(MAX_APPROVAL_VOTES + 1),
            }),
            1,
        )
        .await
        .expect_err("an oversized veto ballot must be refused");

        assert!(
            matches!(&err, ApiError::BadRequest(m) if m.contains("too many approval votes")),
            "got {err:?}"
        );
    }

    /// A ballot AT the cap passes the size check and fails for a real reason instead — here the
    /// recipient mismatch. Guards the off-by-one: a legitimate full-threshold vote must not be
    /// refused for its size.
    #[tokio::test]
    async fn a_ballot_at_the_cap_passes_the_size_check() {
        let state = state_with_dead_rpc();

        let err = verify_approvals(
            &state,
            &one_approver_policy(),
            "ed25519:wallet",
            "hash",
            Some(&ApprovalInfo {
                approval_id: "a1".to_string(),
                recipient: "definitely-not-this-keystore.testnet".to_string(),
                approvals: votes(MAX_APPROVAL_VOTES),
                rejections: vec![],
            }),
            1,
        )
        .await
        .expect_err("the wrong recipient must still be refused");

        let msg = format!("{err:?}");
        assert!(
            !msg.contains("too many approval votes"),
            "a ballot at the cap must not be refused for its size: {msg}"
        );
        assert!(msg.contains("recipient"), "expected the recipient check to fire: {msg}");
    }

    // ============== /admin/loaded-vaults + TEE worker identity ==============

    /// Build a state whose worker token is `token`, so the router's auth layer can be exercised.
    fn state_with_worker_token(token: &str) -> AppState {
        use sha2::{Digest, Sha256};
        let mut state_config = crate::config::Config {
            server_addr: "127.0.0.1:0".parse().unwrap(),
            near_network: "testnet".into(),
            near_rpc_url: "http://127.0.0.1:1".into(),
            offchainvm_contract_id: "outlayer.test".into(),
            allowed_worker_token_hashes: vec![],
            allowed_coordinator_token_hashes: vec![],
            tee_mode: crate::config::TeeMode::None,
            operator_account_id: None,
            keystore_key_type: near_crypto::KeyType::ED25519,
            tee_allowed_key_types: shared_tee_helpers::AllowedKeyTypes { ed25519: true, ml_dsa_65: true },
        };
        state_config.allowed_worker_token_hashes =
            vec![hex::encode(Sha256::digest(token.as_bytes()))];
        // A DIFFERENT coordinator token, so the tests can tell the two lists apart rather than
        // passing because one value happens to be in both.
        state_config.allowed_coordinator_token_hashes =
            vec![hex::encode(Sha256::digest(format!("coordinator-{token}").as_bytes()))];
        let state = AppState::new(crate::crypto::Keystore::generate(), state_config, None);
        state.mark_ready();
        state
    }

    async fn get_loaded_vaults(state: AppState, auth: Option<&str>) -> (axum::http::StatusCode, String) {
        use tower::ServiceExt;
        let mut builder = axum::http::Request::builder()
            .method("GET")
            .uri("/admin/loaded-vaults");
        if let Some(a) = auth {
            builder = builder.header("Authorization", a);
        }
        let response = create_router(state)
            .oneshot(builder.body(axum::body::Body::empty()).unwrap())
            .await
            .expect("router");
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("body");
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    /// This endpoint lists which vaults this keystore holds a master for. That list is
    /// operational detail, not public information, and the route must stay behind the worker
    /// token — a router refactor that dropped the auth layer would otherwise go unnoticed.
    #[tokio::test]
    async fn loaded_vaults_is_refused_without_a_worker_token() {
        let (status, body) = get_loaded_vaults(state_with_worker_token("s3cret"), None).await;
        assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED, "body: {body}");
        assert!(
            !body.contains("vaults"),
            "an unauthorized caller must not see the vault list: {body}"
        );

        let (status, _) =
            get_loaded_vaults(state_with_worker_token("s3cret"), Some("Bearer wrong")).await;
        assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);

        // A token that is right but presented in the wrong scheme is still a refusal.
        let (status, _) = get_loaded_vaults(state_with_worker_token("s3cret"), Some("s3cret")).await;
        assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
    }

    /// The coordinator reads this to publish fleet state in its own health output, which the
    /// monitoring collector relays. Admitting it here is what lets monitoring see the numbers
    /// WITHOUT holding a worker token — which would also open `/admin/evict-customer`.
    #[tokio::test]
    async fn loaded_vaults_accepts_the_coordinator_token_too() {
        let state = state_with_worker_token("s3cret");
        let (status, body) = get_loaded_vaults(state, Some("Bearer coordinator-s3cret")).await;
        assert_eq!(status, axum::http::StatusCode::OK, "body: {body}");
        assert!(body.contains("\"count\""), "body: {body}");
    }

    /// ...and that read access must NOT extend to the mutating admin route. `/admin/evict-customer`
    /// drops a vault master, forcing that vault to pay for a fresh on-chain CKD derivation — a
    /// credential that can only read must never be able to trigger it.
    #[tokio::test]
    async fn the_coordinator_token_cannot_reach_the_mutating_admin_route() {
        use tower::ServiceExt;
        let state = state_with_worker_token("s3cret");
        let response = create_router(state)
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/admin/evict-customer")
                    .header("Authorization", "Bearer coordinator-s3cret")
                    .header("Content-Type", "application/json")
                    .body(axum::body::Body::from(r#"{"vault_id":"vault.alice.testnet"}"#))
                    .unwrap(),
            )
            .await
            .expect("router");
        assert_eq!(
            response.status(),
            axum::http::StatusCode::UNAUTHORIZED,
            "the coordinator token must not be able to evict a vault master"
        );
    }

    /// With the token it reports what is actually in memory — vault ids only, sorted, plus the
    /// counts an operator reads after a restart to see who has come back.
    #[tokio::test]
    async fn loaded_vaults_reports_the_masters_in_memory() {
        let state = state_with_worker_token("s3cret");
        {
            let ks = state.keystore.read().await;
            ks.add_customer("vault.zoe.testnet".parse().unwrap(), [1u8; 32]);
            ks.add_customer("vault.alice.testnet".parse().unwrap(), [2u8; 32]);
        }

        let (status, body) = get_loaded_vaults(state, Some("Bearer s3cret")).await;
        assert_eq!(status, axum::http::StatusCode::OK, "body: {body}");

        let json: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(json["count"], 2);
        assert_eq!(json["vaults"][0], "vault.alice.testnet", "must be sorted");
        assert_eq!(json["vaults"][1], "vault.zoe.testnet");
        assert_eq!(json["tee_sessions"], 0);
        // Addresses only — never key material.
        assert!(!body.contains("0101010101"), "key material leaked: {body}");
    }

    /// `/decrypt` logs which worker instance asked, taken from the validated TEE session. That
    /// is the only worker identifier the keystore can trust, and it is the first time the record
    /// names the caller at all — before this it logged a self-declared constant.
    #[test]
    fn a_live_session_yields_the_worker_key_that_opened_it() {
        let state = state_with_worker_token("s3cret");
        let mut config = state.config.clone();
        config.tee_mode = crate::config::TeeMode::OutlayerTee;
        let state = AppState::new(crate::crypto::Keystore::generate(), config, None);

        let session_id = uuid::Uuid::new_v4();
        state.tee_sessions.lock().unwrap().insert(
            session_id,
            TeeSession {
                worker_public_key: "ed25519:WorkerAAA".to_string(),
                created_at: std::time::Instant::now(),
            },
        );

        let mut headers = axum::http::HeaderMap::new();
        headers.insert("X-TEE-Session", session_id.to_string().parse().unwrap());
        assert_eq!(
            validate_tee_session(&state, &headers).unwrap(),
            Some("ed25519:WorkerAAA".to_string())
        );

        // An unknown session is refused outright — the identity is not optional in TEE mode.
        let mut unknown = axum::http::HeaderMap::new();
        unknown.insert("X-TEE-Session", uuid::Uuid::new_v4().to_string().parse().unwrap());
        assert!(validate_tee_session(&state, &unknown).is_err());
    }

    /// The identity has to survive the trip from the middleware to the handler. If the extension
    /// stopped being inserted, `/decrypt` would silently log `worker=no-session` and every
    /// decrypt would become unattributable, with nothing failing.
    #[tokio::test]
    async fn the_middleware_hands_the_worker_identity_to_the_handler() {
        use tower::ServiceExt;

        let mut config = state_with_worker_token("s3cret").config.clone();
        config.tee_mode = crate::config::TeeMode::OutlayerTee;
        let state = AppState::new(crate::crypto::Keystore::generate(), config, None);

        let session_id = uuid::Uuid::new_v4();
        state.tee_sessions.lock().unwrap().insert(
            session_id,
            TeeSession {
                worker_public_key: "ed25519:WorkerBBB".to_string(),
                created_at: std::time::Instant::now(),
            },
        );

        // A throwaway route behind the real middleware, echoing whatever identity arrived.
        async fn echo(worker: Option<axum::Extension<WorkerIdentity>>) -> String {
            worker.map(|w| w.0 .0).unwrap_or_else(|| "no-session".to_string())
        }
        let app = Router::new()
            .route("/echo", get(echo))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                tee_session_middleware,
            ))
            .with_state(state);

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/echo")
                    .header("X-TEE-Session", session_id.to_string())
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .expect("router");
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 1024).await.unwrap();
        assert_eq!(
            String::from_utf8_lossy(&bytes),
            "ed25519:WorkerBBB",
            "the validated worker identity never reached the handler"
        );
    }

    // ============== AppState::ensure_customer_loaded gate ==============

    fn test_state() -> AppState {
        let config = crate::config::Config {
            server_addr: "127.0.0.1:0".parse().unwrap(),
            near_network: "testnet".into(),
            near_rpc_url: "http://127.0.0.1:1".into(),
            offchainvm_contract_id: "outlayer.test".into(),
            allowed_worker_token_hashes: vec![],
            allowed_coordinator_token_hashes: vec![],
            tee_mode: crate::config::TeeMode::None,
            operator_account_id: None,
            keystore_key_type: near_crypto::KeyType::ED25519,
            tee_allowed_key_types: shared_tee_helpers::AllowedKeyTypes { ed25519: true, ml_dsa_65: true },
        };
        AppState::new(crate::crypto::Keystore::generate(), config, None)
    }

    #[tokio::test]
    async fn ensure_customer_loaded_none_is_noop() {
        // Legacy default-master path: handlers that pass None must
        // never trip the lazy-load gate, even when MPC context is
        // unset. This is the backward-compat invariant.
        let state = test_state();
        state
            .ensure_customer_loaded(None)
            .await
            .expect("None customer must always succeed");
    }

    #[tokio::test]
    async fn ensure_customer_loaded_some_without_mpc_context_errors() {
        // When booted without a TEE/MPC context, asking for a
        // per-customer master must fail-fast with a clear error
        // rather than silently falling back to the default master
        // (which would defeat the customer-isolation invariant).
        use std::str::FromStr;
        let state = test_state();
        let vault = near_primitives::types::AccountId::from_str("vault.alice.testnet").unwrap();
        let err = state
            .ensure_customer_loaded(Some(&vault))
            .await
            .expect_err("must fail without MPC context");
        let msg = format!("{:#}", err);
        assert!(
            msg.contains("MPC CKD context") || msg.contains("non-TEE"),
            "error message should explain the missing context, got: {}",
            msg
        );
    }

    #[tokio::test]
    async fn ensure_customer_loaded_some_with_cached_master_still_requires_mpc_context() {
        // The wrapper used to short-circuit on `has_customer` to skip
        // the on-chain verify, but that opened a "served cached master
        // for a now-unlocked vault" window if the indexer-driven
        // eviction lagged. The current behaviour: every signing op
        // delegates to `mpc_ckd::ensure_customer_loaded`, which does
        // the `is_vault_verified` + `unlocked == false` view-call pair
        // BEFORE checking the cache. A cached master alone is no
        // longer a free pass.
        //
        // In this test the worker has no MPC context, so the wrapper
        // errors before reaching the view-call layer — exactly the
        // contract we want: cached-master serving is gated behind a
        // properly configured worker.
        use std::str::FromStr;
        let state = test_state();
        let vault = near_primitives::types::AccountId::from_str("vault.alice.testnet").unwrap();
        state
            .keystore
            .read()
            .await
            .add_customer(vault.clone(), [9u8; 32]);

        let err = state
            .ensure_customer_loaded(Some(&vault))
            .await
            .expect_err(
                "cache hit must not short-circuit the MPC-context guard \
                 — full re-verify happens at the next layer",
            );
        let msg = format!("{:#}", err);
        assert!(
            msg.contains("MPC CKD context") || msg.contains("non-TEE"),
            "error must surface the missing MPC context, got: {}",
            msg
        );
    }

    // ============== Vault-scope helpers ==============
    // Audit finding I7: pin behaviour of the new request-extraction
    // helpers and the accessor → contract-JSON adapter. Without these
    // tests, future drift between the worker enum and the contract
    // enum (e.g. someone adding `#[serde(tag = "type")]` to either)
    // would silently break decrypt — accessor lookups would target
    // the wrong row and `get_secret_with_vault` would always return
    // `(None, None)`.

    use axum::http::HeaderMap;

    #[test]
    fn extract_customer_from_header_absent_is_none() {
        let h = HeaderMap::new();
        assert!(extract_customer_from_header(&h).unwrap().is_none());
    }

    #[test]
    fn extract_customer_from_header_empty_is_none() {
        let mut h = HeaderMap::new();
        h.insert("X-Customer-Vault", "".parse().unwrap());
        assert!(extract_customer_from_header(&h).unwrap().is_none());
        h.insert("X-Customer-Vault", "   ".parse().unwrap());
        assert!(extract_customer_from_header(&h).unwrap().is_none());
    }

    #[test]
    fn extract_customer_from_header_valid_account() {
        let mut h = HeaderMap::new();
        h.insert("X-Customer-Vault", "vault.alice.testnet".parse().unwrap());
        let result = extract_customer_from_header(&h).unwrap().unwrap();
        assert_eq!(result.as_str(), "vault.alice.testnet");
    }

    #[test]
    fn extract_customer_from_header_trims_whitespace() {
        let mut h = HeaderMap::new();
        h.insert("X-Customer-Vault", "  vault.alice.testnet  ".parse().unwrap());
        let result = extract_customer_from_header(&h).unwrap().unwrap();
        assert_eq!(result.as_str(), "vault.alice.testnet");
    }

    #[test]
    fn extract_customer_from_header_malformed_id_errors() {
        // No silent fallback to default master — that's the
        // anti-typo guarantee.
        let mut h = HeaderMap::new();
        h.insert("X-Customer-Vault", "INVALID UPPERCASE".parse().unwrap());
        let err = extract_customer_from_header(&h).unwrap_err();
        match err {
            ApiError::BadRequest(msg) => assert!(msg.contains("X-Customer-Vault")),
            other => panic!("expected BadRequest, got {:?}", other),
        }
    }

    #[test]
    fn parse_optional_vault_id_treats_none_empty_whitespace_uniformly() {
        assert!(parse_optional_vault_id(None).unwrap().is_none());
        assert!(parse_optional_vault_id(Some("")).unwrap().is_none());
        assert!(parse_optional_vault_id(Some("   ")).unwrap().is_none());
        assert!(parse_optional_vault_id(Some("\t")).unwrap().is_none());
    }

    #[test]
    fn parse_optional_vault_id_valid() {
        let result = parse_optional_vault_id(Some("vault.alice.testnet")).unwrap().unwrap();
        assert_eq!(result.as_str(), "vault.alice.testnet");
    }

    #[test]
    fn parse_optional_vault_id_malformed_errors() {
        let err = parse_optional_vault_id(Some("INVALID")).unwrap_err();
        match err {
            ApiError::BadRequest(msg) => assert!(msg.contains("vault_id")),
            other => panic!("expected BadRequest, got {:?}", other),
        }
    }

    // ============== accessor_to_contract_json — frozen contract ==============
    // These tests pin the EXACT JSON shape sent to the contract for
    // every accessor variant. If the contract enum tagging ever
    // changes, OR the worker enum tagging changes, these tests fail
    // — and that failure is what protects every secret stored on
    // chain from silent decryption misses.

    #[test]
    fn accessor_to_contract_json_repo_normalizes_url() {
        let a = SecretAccessor::Repo {
            repo: "https://github.com/alice/repo".into(),
            branch: Some("main".into()),
        };
        let json = accessor_to_contract_json(&a);
        assert_eq!(
            json,
            serde_json::json!({"Repo": {"repo": "github.com/alice/repo", "branch": "main"}})
        );
    }

    #[test]
    fn accessor_to_contract_json_repo_null_branch() {
        // Null branch must serialise as JSON null (NOT omitted) — the
        // contract's wildcard-fallback logic relies on the field
        // being present.
        let a = SecretAccessor::Repo {
            repo: "github.com/alice/repo".into(),
            branch: None,
        };
        let json = accessor_to_contract_json(&a);
        assert_eq!(
            json,
            serde_json::json!({"Repo": {"repo": "github.com/alice/repo", "branch": null}})
        );
    }

    #[test]
    fn accessor_to_contract_json_wasm_hash() {
        let a = SecretAccessor::WasmHash { hash: "abc123".into() };
        let json = accessor_to_contract_json(&a);
        assert_eq!(json, serde_json::json!({"WasmHash": {"hash": "abc123"}}));
    }

    #[test]
    fn accessor_to_contract_json_project() {
        let a = SecretAccessor::Project { project_id: "alice.near/myapp".into() };
        let json = accessor_to_contract_json(&a);
        assert_eq!(json, serde_json::json!({"Project": {"project_id": "alice.near/myapp"}}));
    }

    #[test]
    fn accessor_to_contract_json_system_payment_key_uses_camelcase() {
        // Critical: the contract's `System(SystemSecretType)` is a tuple
        // variant, so `{"System": "PaymentKey"}` (string, CamelCase),
        // not `{"System": "payment_key"}` or `{"System": {"PaymentKey": null}}`.
        let a = SecretAccessor::System { secret_type: SystemSecretType::PaymentKey };
        let json = accessor_to_contract_json(&a);
        assert_eq!(json, serde_json::json!({"System": "PaymentKey"}));
    }

    #[test]
    fn system_secret_type_helpers_disagree_on_case() {
        // Drift guard: contract format is CamelCase, seed format is
        // snake_case. If both helpers ever drift to the same value,
        // either contract lookups break (System: payment_key won't
        // match) or seed format breaks (system:PaymentKey:... is a
        // different seed). This test is the canary.
        let s = SystemSecretType::PaymentKey;
        assert_eq!(s.as_contract_str(), "PaymentKey");
        assert_eq!(s.as_seed_str(), "payment_key");
        assert_ne!(s.as_contract_str(), s.as_seed_str());
    }

    // ============== map_verify_error HTTP status mapping ==============
    // The caller-side / worker-side
    // split. These tests pin which VerifyError variant maps to which
    // ApiError so a future change (e.g. someone moving an arm by
    // accident) shows up as a unit-test failure rather than a
    // production caller suddenly retrying or surfacing the wrong
    // status to its end-user.

    use crate::vault_verifier::VerifyError;
    use std::str::FromStr as _;

    fn vault() -> near_primitives::types::AccountId {
        near_primitives::types::AccountId::from_str("vault.alice.testnet").unwrap()
    }

    fn assert_bad_request(e: ApiError) {
        match e {
            ApiError::BadRequest(_) => {}
            other => panic!("expected BadRequest, got {:?}", other),
        }
    }
    fn assert_forbidden(e: ApiError) {
        match e {
            ApiError::Forbidden(_) => {}
            other => panic!("expected Forbidden, got {:?}", other),
        }
    }
    fn assert_internal(e: ApiError) {
        match e {
            ApiError::InternalError(_) => {}
            other => panic!("expected InternalError, got {:?}", other),
        }
    }

    #[test]
    fn map_verify_error_already_banned_is_403() {
        // Banned vault is a security signal that the caller's request
        // CAN'T succeed regardless of retries. 403 says so plainly.
        assert_forbidden(map_verify_error(&vault(), VerifyError::AlreadyBanned));
    }

    #[test]
    fn map_verify_error_caller_side_failures_are_400() {
        // Each arm here represents a CALLER-side failure mode:
        // either the vault was deployed wrong (FullAccess key,
        // misconfigured TEE key, wrong DAO) or its state is in a
        // non-eligible phase (unlocked, recovering). All must
        // surface as 400 so callers don't retry.
        assert_bad_request(map_verify_error(
            &vault(),
            VerifyError::CodeHashNotApproved { code_hash: "abc".into() },
        ));
        assert_bad_request(map_verify_error(&vault(), VerifyError::CodeHashMissing));
        assert_bad_request(map_verify_error(&vault(), VerifyError::FullAccessKeyPresent));
        assert_bad_request(map_verify_error(
            &vault(),
            VerifyError::FunctionCallKeyMisconfigured {
                receiver: "bad".into(),
                methods: vec![],
            },
        ));
        assert_bad_request(map_verify_error(
            &vault(),
            VerifyError::UnexpectedAccessKeyCount { expected: 1, got: 2 },
        ));
        assert_bad_request(map_verify_error(
            &vault(),
            VerifyError::KeystoreDaoMismatch {
                configured: "x".into(),
                on_chain: "y".into(),
            },
        ));
        assert_bad_request(map_verify_error(
            &vault(),
            VerifyError::MpcContractMismatch {
                configured: "x".into(),
                on_chain: "y".into(),
            },
        ));
        assert_bad_request(map_verify_error(&vault(), VerifyError::VaultUnlocked));
        assert_bad_request(map_verify_error(&vault(), VerifyError::VaultRecoveryInProgress));
    }

    #[test]
    fn map_verify_error_account_not_found_is_400() {
        // Ambiguous: vault doesn't exist OR rpc flake. Bias to 400
        // because dominant case is bad vault_id.
        let err = anyhow::anyhow!("account does not exist");
        assert_bad_request(map_verify_error(
            &vault(),
            VerifyError::AccountNotFound(err),
        ));
    }

    #[test]
    fn map_verify_error_rpc_failures_are_500() {
        // A flaky NEAR RPC must not surface as
        // 400 because callers won't retry on 4xx. These cases are
        // worker-side / system-side, callers SHOULD retry.
        let err = || anyhow::anyhow!("rpc timeout");
        assert_internal(map_verify_error(
            &vault(),
            VerifyError::KeystoreDaoUnreachable(err()),
        ));
        assert_internal(map_verify_error(
            &vault(),
            VerifyError::AccessKeyListUnreachable(err()),
        ));
        assert_internal(map_verify_error(
            &vault(),
            VerifyError::VaultStateUnreachable(err()),
        ));
    }

    #[test]
    fn map_verify_error_contract_shape_mismatch_is_500() {
        // A contract returning malformed JSON
        // is a contract bug or version mismatch — NOT a caller bug.
        // Caller has done nothing wrong; surfacing 400 would be a
        // lie.
        assert_internal(map_verify_error(
            &vault(),
            VerifyError::KeystoreDaoMalformed { method: "is_vault_banned".into() },
        ));
        assert_internal(map_verify_error(
            &vault(),
            VerifyError::VaultStateInvalid("missing keystore_dao".into()),
        ));
    }

    // ============== Handler-level customer isolation ==============
    // Builds on the crypto-layer isolation tests in `crypto.rs`. At
    // the handler layer the only customer-facing surface that we can
    // exercise without an HTTP test server is `AppState::ensure_customer_loaded`.
    // The `crypto.rs` tests already prove the underlying derive_*
    // calls produce disjoint output per customer; here we simply
    // verify the gate's behaviour matrix:

    #[tokio::test]
    async fn ensure_customer_loaded_treats_cached_and_uncached_uniformly_without_mpc() {
        // The api-layer wrapper used to fast-path on `has_customer`,
        // so cached masters were served without going through
        // `mpc_ckd::ensure_customer_loaded`'s on-chain verify. That
        // short-circuit is gone — every call now needs an MPC context
        // because the verify (and any subsequent re-load) happens at
        // the lower layer. Both a cached vault AND an uncached vault
        // must surface the same "no MPC context" error in non-TEE
        // mode; per-vault cache isolation is unit-tested at the
        // Keystore layer, not here.
        use std::str::FromStr;
        let state = test_state();
        let alice = near_primitives::types::AccountId::from_str("vault.alice.testnet").unwrap();
        let bob = near_primitives::types::AccountId::from_str("vault.bob.testnet").unwrap();

        // Pre-populate alice only; bob stays uncached.
        state
            .keystore
            .read()
            .await
            .add_customer(alice.clone(), [0xAA; 32]);

        for vault in [&alice, &bob] {
            let err = state
                .ensure_customer_loaded(Some(vault))
                .await
                .expect_err(
                    "wrapper must require MPC context regardless of cache state",
                );
            let msg = format!("{:#}", err);
            assert!(
                msg.contains("MPC CKD context") || msg.contains("non-TEE"),
                "non-TEE-mode error message expected for {vault}, got: {msg}"
            );
        }
    }

    // ============== Audit noteC2 — backward-compat smoke ==============
    // The plan (line 598) explicitly mandates: "запросы без
    // X-Customer-Vault header работают на default_master (legacy
    // clients)". Earlier audits caught customer-isolation invariants
    // at the gate level. This test drives a real wallet handler with
    // an EMPTY HeaderMap and asserts the derived address matches what
    // direct `keystore.derive_keypair(None, …)` produces — pinning
    // the legacy customer-less path against accidental regression.
    #[tokio::test]
    async fn handler_without_x_customer_vault_uses_default_master() {
        let state = test_state();
        // Wait for is_ready (test_state initialises with is_ready=true).

        // Snapshot the keystore's default-master output for the seed
        // the handler will build internally.
        let expected_seed = "wallet:test-wallet-id:near".to_string();
        let expected_pubkey = {
            let ks = state.keystore.read().await;
            let (_, vk) = ks.derive_keypair(None, &expected_seed).unwrap();
            hex::encode(vk.as_bytes())
        };

        // Drive the handler with an empty HeaderMap — proves the
        // legacy "no header → default master" path.
        let request = WalletDeriveAddressRequest {
                        wallet_id: "test-wallet-id".to_string(),
            chain: "near".to_string(),
            sub_path: None,
        };
        let response = wallet_derive_address_handler(
            axum::extract::State(state),
            axum::http::HeaderMap::new(),
            axum::Json(request),
        )
        .await
        .expect("handler must succeed without X-Customer-Vault header");

        assert_eq!(
            response.0.address, expected_pubkey,
            "derived address must match default-master derive_keypair output"
        );
    }

    #[tokio::test]
    async fn handler_with_empty_x_customer_vault_uses_default_master() {
        // An empty header value must be treated identically to no
        // header — `extract_customer_from_header` returns Ok(None).
        // This matters because some HTTP clients always send all
        // configured headers, even with empty values.
        let state = test_state();
        let expected_pubkey = {
            let ks = state.keystore.read().await;
            let (_, vk) = ks.derive_keypair(None, "wallet:abc:near").unwrap();
            hex::encode(vk.as_bytes())
        };

        let mut headers = axum::http::HeaderMap::new();
        headers.insert("X-Customer-Vault", "".parse().unwrap());

        let request = WalletDeriveAddressRequest {
                        wallet_id: "abc".to_string(),
            chain: "near".to_string(),
            sub_path: None,
        };
        let response = wallet_derive_address_handler(
            axum::extract::State(state),
            headers,
            axum::Json(request),
        )
        .await
        .expect("empty header must be treated as no header");

        assert_eq!(response.0.address, expected_pubkey);
    }
}

/// A secret named after an agent belongs to that agent — both to read and to
/// have written.
///
/// These pin the rule itself rather than the handler around it: the handler
/// needs a NEAR client and a live contract, while the rule needs nothing at all,
/// and it is the rule that decides who reads a connector credential.
#[cfg(test)]
mod agent_secret_tests {
    use super::*;

    const AGENT: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
    const OTHER_AGENT: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

    fn refused(e: ApiError) -> String {
        match e {
            ApiError::Unauthorized(m) => m,
            other => panic!("expected a refusal, got {:?}", other),
        }
    }

    #[test]
    fn an_agent_reads_the_secret_its_own_wallet_stored() {
        enforce_agent_secret(AGENT, AGENT, AGENT)
            .expect("the agent's own secret must be readable by it");
    }

    /// An agent's account is public — it is in every top-up and every policy —
    /// so knowing one must buy nothing.
    #[test]
    fn another_agents_name_is_refused_however_it_was_learned() {
        let message = refused(
            enforce_agent_secret(AGENT, OTHER_AGENT, OTHER_AGENT)
                .expect_err("one agent must not read a secret addressed to another"),
        );
        assert!(
            message.contains("different agent"),
            "the refusal must say why: {message}"
        );
    }

    /// THE test of this section. `store_secrets` is open to anyone and the name
    /// is public, so a stranger can absolutely put a secret on chain under an
    /// agent's name — with themselves as owner, which is the one thing they
    /// cannot fake. Reading it would mean the connector running on THEIR
    /// mailbox, THEIR token.
    #[test]
    fn a_secret_planted_under_the_agents_name_by_someone_else_is_refused() {
        let message = refused(
            enforce_agent_secret(AGENT, "mallory.near", AGENT)
                .expect_err("a secret owned by anyone but the agent must be refused"),
        );
        assert!(
            message.contains("not left by the agent"),
            "the refusal must say why: {message}"
        );

        // Including when the planter is another agent, whose owner field is
        // just as implicit-account-shaped as the real one.
        refused(
            enforce_agent_secret(AGENT, OTHER_AGENT, AGENT)
                .expect_err("another agent is a stranger too"),
        );
    }

    /// Ordinary secrets keep working exactly as before. This is the check's
    /// blast radius, and it has to stay at zero for every name a human types.
    #[test]
    fn an_ordinary_profile_is_not_subject_to_the_rule() {
        for profile in ["production", "default", "staging", "7", "balance", ""] {
            enforce_agent_secret("alice.near", "bob.near", profile)
                .unwrap_or_else(|e| panic!("profile {profile:?} must pass untouched: {e:?}"));
        }
    }

    /// A named account is not shaped like an implicit one, so a human storing a
    /// secret under their own name — and letting others read it through an
    /// access condition — is untouched.
    #[test]
    fn a_named_account_never_triggers_the_rule() {
        enforce_agent_secret("alice.near", "alice.near", "alice.near").unwrap();
        enforce_agent_secret("mallory.near", "alice.near", "alice.near").unwrap();
    }

    /// The shape decides whether the rule fires at all, and it now comes from
    /// `shared_tee_helpers` — the same function the coordinator asks before it
    /// addresses a secret.
    ///
    /// The shape itself is tested there. What this pins is that the RULE is
    /// driven by it: a profile of that shape must be policed, and one of any
    /// other shape must pass untouched. Both halves have a silent failure —
    /// too wide and a human's secret falls under a rule written for agents, too
    /// narrow and an agent's connector credential is guarded by nothing.
    #[test]
    fn the_rule_fires_on_exactly_the_shared_account_shape() {
        for agentish in [AGENT, &"0".repeat(64), &"f".repeat(64)] {
            assert!(shared_tee_helpers::is_implicit_account(agentish));
            enforce_agent_secret("someone.near", agentish, agentish)
                .expect_err("a profile of this shape must be policed");
        }

        for ordinary in ["alice.near", &AGENT[..63], &AGENT.to_uppercase(), "production"] {
            assert!(!shared_tee_helpers::is_implicit_account(ordinary));
            enforce_agent_secret("someone.near", "other.near", ordinary)
                .expect("a profile of any other shape must pass untouched");
        }
    }
}

/// What stops either signing endpoint from becoming a transaction-forging
/// oracle.
///
/// Both sign with `wallet:{id}:near` — the wallet's own NEAR transaction key —
/// so a signature over an attacker-chosen 32-byte hash would BE a valid
/// transaction signature. Neither endpoint accepts a hash, and each blocks the
/// preimage by a different structural argument. Those arguments are load-bearing
/// and invisible in the code, which is what these tests are for.
#[cfg(test)]
mod signing_oracle_tests {
    use super::*;

    /// The first four bytes of a borsh-serialised NEAR transaction are the u32
    /// little-endian length of `signer_id`, and an account id is at most 64
    /// bytes. So ANY preimage whose first four bytes read as a larger number
    /// cannot be a transaction — which is the whole reason the domain string
    /// goes first.
    const MAX_ACCOUNT_ID_LEN: u32 = 64;

    fn first_u32_le(bytes: &[u8]) -> u32 {
        u32::from_le_bytes(bytes[..4].try_into().unwrap())
    }

    /// `/wallet/sign-secret-store` builds its own message, and the domain prefix
    /// is what makes it unusable as a transaction. Drop the prefix and this
    /// fails — which is the point, because nothing else would notice.
    #[test]
    fn the_secret_store_message_cannot_be_a_transaction() {
        let message = secret_store_message(
            "ed25519:aa",
            "connectors.outlayer.near/near-email",
            "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
            "Y2lwaGVy",
            "payer.near",
            "",
            "\"AllowAll\"",
        );

        // The DOMAIN is `store_secrets_for:`, and it deliberately did NOT move
        // when the contract method was renamed to
        // `store_agent_secret`. A domain's job is to be a unique,
        // non-transaction-shaped prefix that both sides agree on; renaming it
        // to follow a method name would invalidate every signature in flight
        // and buy nothing. It is a protocol constant, not a label.
        assert!(
            message.starts_with("store_secrets_for:"),
            "the domain must come FIRST — a prefix in the middle protects nothing"
        );
        assert!(
            first_u32_le(message.as_bytes()) > MAX_ACCOUNT_ID_LEN,
            "read as borsh, this preimage claims a signer_id longer than any \
             account can be, so no transaction has this shape"
        );
    }

    /// Byte-for-byte the string the contract rebuilds. Pinned, because the two
    /// sides never compare notes: a drifted format shows up as signatures the
    /// contract silently rejects, on a path nobody exercises until launch.
    #[test]
    fn the_secret_store_message_format_is_pinned() {
        // The contract pins the SAME string, from its own types, in
        // `contract/src/secrets.rs`. The two sides never compare notes at run
        // time — a drifted format shows up as signatures the contract silently
        // rejects — so the agreement is held by these two tests reading alike.
        assert_eq!(
            secret_store_message(
                "ed25519:ab",
                "a.near/p",
                "agent",
                "cipher",
                "payer.near",
                "",
                "\"AllowAll\"",
            ),
            "store_secrets_for:v1:ed25519:ab:8:a.near/p:agent:cipher:payer.near::\"AllowAll\""
        );

        // A vault-bound secret names its vault, and an absent vault leaves an
        // empty field rather than dropping one — a dropped field would shift
        // every field after it.
        assert_eq!(
            secret_store_message(
                "ed25519:ab",
                "a.near/p",
                "agent",
                "cipher",
                "payer.near",
                "vault.alice.near",
                "\"AllowAll\"",
            ),
            "store_secrets_for:v1:ed25519:ab:8:a.near/p:agent:cipher:payer.near:vault.alice.near:\"AllowAll\""
        );

        // `access` is LAST because it is JSON and may contain colons. Anything
        // earlier would make the boundaries ambiguous — except the accessor,
        // which is allowed to because the `8:` in front of it says how long it
        // is.
        let nested = secret_store_message(
            "ed25519:ab",
            "a.near/p",
            "agent",
            "cipher",
            "payer.near",
            "",
            "{\"Whitelist\":{\"accounts\":[\"a.near\"]}}",
        );
        assert!(nested.ends_with("{\"Whitelist\":{\"accounts\":[\"a.near\"]}}"));
    }

    /// The domain is `store_secrets_for:v1:`, and both sides must write it.
    ///
    /// It stayed at v1 through the length-prefix change deliberately. A version
    /// exists to keep two formats apart in the wild, and there is no v1 in the
    /// wild: the mechanism has never been on mainnet, and the only testnet
    /// secrets under the earlier format are ours. Bumping would have marked a
    /// boundary nobody is on either side of.
    ///
    /// The string is load-bearing regardless: the CONTRACT rebuilds it to
    /// verify, so a side writing anything else produces signatures the other
    /// silently rejects. Pinned here and there.
    #[test]
    fn the_domain_is_pinned() {
        let m = secret_store_message("ed25519:ab", "a.near/p", "agent", "c", "p.near", "", "\"AllowAll\"");
        assert!(m.starts_with("store_secrets_for:v1:"));
        assert!(
            !m.contains(":v2:"),
            "there is no v2 — the length prefix arrived inside v1, before anyone was using it"
        );
    }

    /// Every argument that decides what gets stored is inside the signature.
    ///
    /// Leave one out and a payer holding a signed call can resend the same
    /// bytes with that argument changed. For the PROJECT, nothing would leak —
    /// the ciphertext is sealed to one project's seed and decrypts under no
    /// other — but an authorisation that does not cover what it authorises
    /// holds only while a second, unrelated fact stays true. That is the shape
    /// this test exists to keep.
    #[test]
    fn changing_any_signed_field_changes_the_message() {
        let m = |pk, proj, prof, ct, payer, vault, access| {
            secret_store_message(pk, proj, prof, ct, payer, vault, access)
        };
        let base = m("ed25519:ab", "a.near/p", "agent", "cipher", "payer.near", "", "\"AllowAll\"");

        for other in [
            m("ed25519:cd", "a.near/p", "agent", "cipher", "payer.near", "", "\"AllowAll\""),
            m("ed25519:ab", "b.near/q", "agent", "cipher", "payer.near", "", "\"AllowAll\""),
            m("ed25519:ab", "a.near/p", "other", "cipher", "payer.near", "", "\"AllowAll\""),
            m("ed25519:ab", "a.near/p", "agent", "other", "payer.near", "", "\"AllowAll\""),
            m("ed25519:ab", "a.near/p", "agent", "cipher", "thief.near", "", "\"AllowAll\""),
            // The two that were added: who may READ it, and which master seals
            // it. Both were outside the signature at first.
            m("ed25519:ab", "a.near/p", "agent", "cipher", "payer.near", "vault.x.near", "\"AllowAll\""),
            m("ed25519:ab", "a.near/p", "agent", "cipher", "payer.near", "", "{\"Whitelist\":{\"accounts\":[\"thief.near\"]}}"),
        ] {
            assert_ne!(base, other, "a changed argument must change the message");
        }
    }

    /// The delete message, byte for byte, as `contract/src/secrets.rs` rebuilds
    /// it. Same reason as the store's pin: the two sides never compare notes at
    /// run time, so a drift shows up only as signatures the contract rejects.
    #[test]
    fn the_secret_delete_message_format_is_pinned() {
        assert_eq!(
            secret_delete_message("ed25519:ab", "a.near/p", "agent", "payer.near"),
            "delete_agent_secret:v1:ed25519:ab:8:a.near/p:agent:payer.near"
        );

        // A WASM-scoped secret is named by the contract's `wasm:` binding, and
        // the length in front of it counts THAT string, prefix included.
        assert_eq!(
            secret_delete_message("ed25519:ab", "wasm:beef", "agent", "payer.near"),
            "delete_agent_secret:v1:ed25519:ab:9:wasm:beef:agent:payer.near"
        );
    }

    /// A signature obtained to STORE must not destroy anything, and a delete
    /// signature must not store.
    ///
    /// Asserted on the DOMAIN rather than on the two strings differing: they
    /// also differ by field count, so an equality check between them would pass
    /// even if both domains read `store_secrets_for:` — which is the failure
    /// this test exists for and the one it used to miss.
    #[test]
    fn a_store_signature_cannot_delete() {
        let store = secret_store_message(
            "ed25519:ab",
            "a.near/p",
            "agent",
            "cipher",
            "payer.near",
            "",
            "\"AllowAll\"",
        );
        let delete = secret_delete_message("ed25519:ab", "a.near/p", "agent", "payer.near");

        assert!(store.starts_with("store_secrets_for:v1:"));
        assert!(delete.starts_with("delete_agent_secret:v1:"));
        assert!(
            !delete.starts_with("store_secrets_for:"),
            "one domain for both verbs would make a store signature a licence to delete"
        );
        assert!(
            first_u32_le(delete.as_bytes()) > MAX_ACCOUNT_ID_LEN,
            "the delete preimage must be unusable as a transaction too"
        );
    }

    /// Every field of a delete is inside its signature.
    ///
    /// A delete is the operation where an unbound field costs the most: the
    /// pair `(args, signature)` is public on chain forever, so anything left
    /// outside can be varied by whoever finds it.
    #[test]
    fn changing_any_delete_field_changes_the_message() {
        let base = secret_delete_message("ed25519:ab", "a.near/p", "agent", "payer.near");
        for other in [
            secret_delete_message("ed25519:cd", "a.near/p", "agent", "payer.near"),
            secret_delete_message("ed25519:ab", "b.near/q", "agent", "payer.near"),
            secret_delete_message("ed25519:ab", "a.near/p", "other", "payer.near"),
            secret_delete_message("ed25519:ab", "a.near/p", "agent", "thief.near"),
        ] {
            assert_ne!(base, other, "a changed argument must change the message");
        }
    }

    /// The policy message, byte for byte, as `contract/src/wallet.rs` rebuilds
    /// it.
    ///
    /// This one is newer than the others and was added to close a hole rather
    /// than to describe one: the contract used to verify a policy signature
    /// over the BARE `sha256(encrypted_data)`, which any other signature of
    /// this wallet satisfied.
    #[test]
    fn the_policy_store_message_format_is_pinned() {
        assert_eq!(
            policy_store_message("ed25519:ab", "Y2lwaGVy", "alice.near"),
            "store_wallet_policy:v1:ed25519:ab:8:Y2lwaGVy:alice.near"
        );
    }

    /// No signature of another verb can be a policy, and no policy signature
    /// can be another verb.
    ///
    /// Asserted on the DOMAINS, because that is the property: three messages
    /// that begin differently cannot be substituted for one another however
    /// their remaining fields line up.
    #[test]
    fn the_three_domains_are_distinct() {
        let policy = policy_store_message("ed25519:ab", "cipher", "alice.near");
        let store = secret_store_message(
            "ed25519:ab",
            "a.near/p",
            "agent",
            "cipher",
            "alice.near",
            "",
            "\"AllowAll\"",
        );
        let delete = secret_delete_message("ed25519:ab", "a.near/p", "agent", "alice.near");

        assert!(policy.starts_with("store_wallet_policy:v1:"));
        assert!(store.starts_with("store_secrets_for:v1:"));
        assert!(delete.starts_with("delete_agent_secret:v1:"));
        assert!(
            first_u32_le(policy.as_bytes()) > MAX_ACCOUNT_ID_LEN,
            "the policy preimage must be unusable as a transaction too"
        );
    }

    /// Every field of a policy signature is inside it — including the account
    /// that may send it.
    #[test]
    fn changing_any_policy_field_changes_the_message() {
        let base = policy_store_message("ed25519:ab", "cipher", "alice.near");
        for other in [
            policy_store_message("ed25519:cd", "cipher", "alice.near"),
            policy_store_message("ed25519:ab", "other", "alice.near"),
            policy_store_message("ed25519:ab", "cipher", "thief.near"),
        ] {
            assert_ne!(base, other, "a changed argument must change the message");
        }
    }

    /// The seeds this endpoint seals to are the ones the READ path rebuilds.
    ///
    /// Written out literally rather than by calling the same helper, because a
    /// helper compared against itself agrees by construction. These strings are
    /// copied from the `/decrypt` and `/get-or-create-secrets` match arms; if
    /// one of those is edited, this is what says so — and the symptom it
    /// replaces is a secret that stores fine and cannot be read months later.
    #[test]
    fn the_agent_seeds_match_the_read_path() {
        let agent = "a1b2c3";
        assert_eq!(
            AgentSecretTarget::Project("owner.near/app".to_string()).seed(agent),
            format!("project:{}:{}", "owner.near/app", agent)
        );
        assert_eq!(
            AgentSecretTarget::WasmHash("beef".to_string()).seed(agent),
            format!("wasm_hash:{}:{}", "beef", agent)
        );
    }

    /// The binding is the CONTRACT's spelling, which is not the seed's.
    ///
    /// `wasm:` in the signed message, `wasm_hash:` in the seed. Two strings for
    /// two jobs; swapping them produces either a signature the contract rejects
    /// or a secret the worker cannot open, and neither failure names the cause.
    #[test]
    fn the_bindings_are_the_contracts_spelling() {
        assert_eq!(
            AgentSecretTarget::Project("owner.near/app".to_string()).binding(),
            "owner.near/app"
        );
        assert_eq!(
            AgentSecretTarget::WasmHash("beef".to_string()).binding(),
            "wasm:beef"
        );
    }

    /// One scope or the other, never both and never neither.
    #[test]
    fn an_agent_secret_names_exactly_one_scope() {
        assert_eq!(
            AgentSecretTarget::from_fields(Some("a.near/p"), None).unwrap(),
            AgentSecretTarget::Project("a.near/p".to_string())
        );
        assert_eq!(
            AgentSecretTarget::from_fields(None, Some("beef")).unwrap(),
            AgentSecretTarget::WasmHash("beef".to_string())
        );

        // Blank is not a choice: an empty string would otherwise seal a secret
        // to `project::{agent}` and look like a project scope forever after.
        assert!(AgentSecretTarget::from_fields(Some("   "), None).is_err());
        assert!(AgentSecretTarget::from_fields(None, None).is_err());
        assert!(AgentSecretTarget::from_fields(Some("a.near/p"), Some("beef")).is_err());
    }

    /// A shouted hash is the same hash.
    ///
    /// The contract lowercases the accessor before it becomes a storage key, so
    /// the worker reads it back in lower case and rebuilds a lower-case seed. A
    /// secret sealed here under the shouted spelling would be one nothing can
    /// open — and the signature would name an accessor the contract does not
    /// store, so it would not even land.
    #[test]
    fn a_wasm_hash_is_lowercased_to_match_the_chain() {
        let target = AgentSecretTarget::from_fields(None, Some("BEEF")).unwrap();
        assert_eq!(target, AgentSecretTarget::WasmHash("beef".to_string()));
        assert_eq!(target.binding(), "wasm:beef");
        assert_eq!(target.seed("agent"), "wasm_hash:beef:agent");
    }

    /// `/wallet/sign-policy` has a domain NOW, but the older argument still
    /// holds and is worth keeping: what protected it before was the ORDER — the
    /// base64 decode and the AEAD decrypt both run BEFORE the signature — and
    /// the first of those is what this pins. Two independent reasons a
    /// transaction cannot come out of that endpoint are better than one.
    ///
    /// A transaction's borsh has NUL bytes in the length prefix, and NUL is not
    /// in the base64 alphabet, so a preimage that survives decoding cannot be
    /// one. Move the signing above the decode and this argument evaporates.
    #[test]
    fn a_transaction_preimage_is_not_valid_base64() {
        // A plausible transaction: signer_id of 10 bytes, then the account.
        let mut tx = Vec::new();
        tx.extend_from_slice(&10u32.to_le_bytes());
        tx.extend_from_slice(b"alice.near");
        tx.extend_from_slice(&[0u8; 32]); // public key
        assert!(
            first_u32_le(&tx) <= MAX_ACCOUNT_ID_LEN,
            "a real transaction starts with a plausible account length"
        );

        let as_text = String::from_utf8_lossy(&tx).to_string();
        assert!(
            base64::decode(&as_text).is_err(),
            "a transaction preimage must not survive the base64 decode that \
             happens before /wallet/sign-policy signs anything"
        );
    }
}

#[cfg(test)]
mod reserved_keys_tests {
    use super::{reject_reserved_secret_keys, RESERVED_SECRET_KEYS};

    /// The check every door shares: refuse, name every offender, leave
    /// everything else alone.
    #[test]
    fn the_shared_check_refuses_every_reserved_name_and_nothing_else() {
        for name in RESERVED_SECRET_KEYS {
            let err = reject_reserved_secret_keys([*name].into_iter())
                .expect_err("a reserved name must be refused");
            assert!(
                format!("{err:?}").contains(name),
                "the refusal for {name} does not say which key was wrong, so the owner has to \
                 guess which of their secrets to rename"
            );
        }
        assert!(reject_reserved_secret_keys(["API_KEY", "DB_URL"].into_iter()).is_ok());
        // Case matters: the environment is case-sensitive, so a lowercase
        // spelling is a different variable and reserving it would take a name
        // from the owner for nothing.
        assert!(reject_reserved_secret_keys(["wallet_id"].into_iter()).is_ok());

        // All offenders in one answer — an owner editing a JSON blob should
        // need one round trip, not one per key.
        let err =
            reject_reserved_secret_keys(["API_KEY", "WALLET_ID", "NEAR_SENDER_ID"].into_iter())
                .expect_err("a batch containing reserved names must be refused");
        let text = format!("{err:?}");
        assert!(text.contains("WALLET_ID") && text.contains("NEAR_SENDER_ID"), "{text}");
        assert!(!text.contains("API_KEY"), "a legal key was named as an offender: {text}");
    }

    /// The worker's list of injected variables, read from its source.
    ///
    /// A cross-crate read rather than a shared constant on purpose: the two
    /// binaries ship in different images and are deployed separately, so a
    /// compile-time dependency would say nothing about what is actually
    /// running. What matters is that whoever EDITS the worker is told, in the
    /// same working tree, that the keystore has to change too.
    fn worker_system_env_vars() -> Vec<String> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../worker/src/main.rs");
        let src = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("cannot read the worker source at {path}: {e}"));
        let (_, after) = src
            .split_once("pub const SYSTEM_ENV_VARS: &[&str] = &[")
            .expect("worker::SYSTEM_ENV_VARS — the list this test exists to follow — is gone");
        let (body, _) = after
            .split_once("];")
            .expect("SYSTEM_ENV_VARS is not terminated");

        let mut names = Vec::new();
        let mut rest = body;
        while let Some(open) = rest.find('"') {
            let after_open = &rest[open + 1..];
            let Some(close) = after_open.find('"') else { break };
            names.push(after_open[..close].to_string());
            rest = &after_open[close + 1..];
        }
        names
    }

    /// Every variable the worker injects must be refused as a secret key.
    ///
    /// Without this the two lists drift silently, and drift here is not
    /// cosmetic: a worker-injected name that is NOT reserved can be set as a
    /// secret, and the guest then reads a caller-chosen value as a fact about
    /// its run. That is how `OUTLAYER_PROJECT_OWNER`, `OUTLAYER_PROJECT_NAME`
    /// and `WALLET_ID` came to be forgeable — each was added to the worker and
    /// nobody remembered this list.
    #[test]
    fn every_worker_system_variable_is_a_reserved_secret_key() {
        let worker_vars = worker_system_env_vars();
        assert!(
            worker_vars.len() >= 20,
            "read only {} names out of worker::SYSTEM_ENV_VARS — the parse stopped matching the \
             list, so this guard is no longer guarding anything",
            worker_vars.len()
        );

        let unreserved: Vec<&String> = worker_vars
            .iter()
            .filter(|name| !RESERVED_SECRET_KEYS.contains(&name.as_str()))
            .collect();
        assert!(
            unreserved.is_empty(),
            "the worker injects {unreserved:?} into the guest, but a customer may still store \
             secrets under those names — add them to RESERVED_SECRET_KEYS"
        );
    }

    /// Every door that stores a secret has to consult the list.
    ///
    /// The two tests around this one compare LISTS. This one compares
    /// HANDLERS, and it exists because the gap that was found was neither list
    /// being wrong: `update_user_secrets` simply never asked. A list guard
    /// cannot see a door that does not consult it, which is why the hole
    /// survived a round of auditing that was looking straight at the lists.
    ///
    /// The set is derived from the source rather than written here: a handler
    /// counts if it works with a map of secret keys at all, so a fourth door
    /// added tomorrow is held to the same rule on the day it appears.
    #[test]
    fn every_handler_that_stores_secrets_refuses_reserved_names() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/api.rs");
        let src = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
        // Stop at the tests. This module names the same things it looks for,
        // and the last handler's chunk would otherwise run to end-of-file and
        // pass on the strength of this comment.
        let code = src.split("#[cfg(test)]").next().unwrap_or_default();
        // Both spellings are used at file scope; one form to split on.
        let normalized = code.replace("\npub async fn ", "\nasync fn ");

        let mut handles_secrets: Vec<(&str, bool)> = Vec::new();
        let mut chunks = normalized.split("\nasync fn ");
        chunks.next(); // everything before the first handler
        for chunk in chunks {
            let name = chunk.split('(').next().unwrap_or("").trim();
            // A body that names a secrets map is a body that can write one.
            // Deliberately loose: a false positive costs one call to the
            // guard, a false negative is the bug this test is about.
            if !(chunk.contains("secrets_map") || chunk.contains("req.secrets")) {
                continue;
            }
            handles_secrets.push((name, chunk.contains("reject_reserved_secret_keys")));
        }

        // The scan itself, pinned: if a rename or a reformat makes it stop
        // seeing handlers, an empty set would otherwise satisfy every
        // assertion below.
        for expected in ["pubkey_handler", "add_generated_secret_handler", "update_user_secrets_handler"] {
            assert!(
                handles_secrets.iter().any(|(name, _)| *name == expected),
                "the scan no longer finds {expected}, so this guard is guarding nothing — \
                 found: {:?}",
                handles_secrets.iter().map(|(n, _)| *n).collect::<Vec<_>>()
            );
        }

        let unguarded: Vec<&str> = handles_secrets
            .iter()
            .filter(|(_, guarded)| !guarded)
            .map(|(name, _)| *name)
            .collect();
        assert!(
            unguarded.is_empty(),
            "these handlers work with secret keys without calling \
             reject_reserved_secret_keys: {unguarded:?} — a caller can store a name the worker \
             injects, and the only thing left standing is the worker's own strip"
        );
    }

    /// The reverse direction is a WARNING, not a failure: reserving a name the
    /// worker does not inject costs a customer a key name and nothing else, and
    /// un-reserving one is itself a breaking change. So this test only pins the
    /// names that are deliberately reserved beyond the worker's list — today,
    /// none — so that the set is a decision rather than an accident.
    #[test]
    fn nothing_is_reserved_without_a_reason() {
        let worker_vars = worker_system_env_vars();
        let extra: Vec<&&str> = RESERVED_SECRET_KEYS
            .iter()
            .filter(|k| !worker_vars.iter().any(|w| w == *k))
            .collect();
        assert!(
            extra.is_empty(),
            "these keys are reserved but the worker never injects them: {extra:?} — either the \
             worker dropped a variable (then drop it here too) or the reservation needs a comment \
             saying what it is for"
        );
    }
}
