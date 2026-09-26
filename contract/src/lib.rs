use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::collections::{LookupMap, UnorderedMap, UnorderedSet};
use near_sdk::json_types::U128;
use near_sdk::serde::Serialize;
use near_sdk::serde_json;
use near_sdk::{
    env, log, near, near_bindgen, AccountId, BorshStorageKey, Gas, GasWeight, NearToken,
    PanicOnDefault, PromiseError,
};
use std::convert::TryInto;

mod admin;
mod events;
mod execution;
mod migration;
mod payment;
mod projects;
mod secrets;
mod types;
mod views;
mod wallet;

pub type Balance = u128;
pub type CryptoHash = [u8; 32];

// Gas constants
pub const MIN_RESPONSE_GAS: Gas = Gas::from_tgas(50);
pub const DATA_ID_REGISTER: u64 = 37;

// Timeout for stale execution cancellation (10 minutes)
pub const EXECUTION_TIMEOUT: u64 = 600 * 1_000_000_000;

// Maximum resource limits (hard caps)
pub const MAX_INSTRUCTIONS: u64 = 500_000_000_000; // 500 billion instructions
pub const MAX_EXECUTION_SECONDS: u64 = 180; // 180 seconds
pub const MAX_COMPILATION_SECONDS: u64 = 300; // 5 minutes max compilation time

// Large payload handling: threshold for including input_data in event log
// Payloads >= this size are stored in state only, worker fetches via get_request()
// NEAR has 16KB limit per log message, so we use 10KB to leave room for other fields
pub const INPUT_DATA_EVENT_THRESHOLD: usize = 10_000; // 10KB

#[derive(BorshSerialize, BorshStorageKey)]
#[borsh(crate = "near_sdk::borsh")]
enum StorageKey {
    PendingRequests,
    SecretsStorage,
    UserSecretsIndex,
    UserSecretsList { account_id: AccountId },
    // Project storage
    Projects,
    ProjectVersions { project_uuid: String },
    UserProjects,
    UserProjectsList { account_id: AccountId },
    // Developer earnings (stablecoin)
    DeveloperEarnings,
    // User stablecoin balances for developer payments
    UserStablecoinBalances,
    // Wallet policies (wallet_pubkey -> WalletPolicyEntry)
    WalletPolicies,
    // Wallet owner index (owner -> set of wallet_pubkeys)
    WalletOwnerIndex,
    WalletOwnerList { account_id: AccountId },
    // Per-secret vault binding (side-table for sovereign-vault opt-in)
    SecretVaultBindings,
    // What curated projects charge (project_id -> ProjectPricing)
    ProjectPricing,
}

/// Execution source - GitHub repo, pre-compiled WASM URL, or project reference
#[derive(Clone, Debug)]
#[near(serializers = [borsh, json])]
pub enum ExecutionSource {
    /// GitHub repository with source code to compile
    GitHub {
        repo: String,
        commit: String,
        build_target: Option<String>, // e.g., "wasm32-wasip1"
    },
    /// Pre-compiled WASM file accessible via URL
    /// Worker downloads from URL, verifies SHA256 hash, then executes without compilation
    WasmUrl {
        url: String,           // URL for downloading (https://, ipfs://, ar://)
        hash: String,          // SHA256 hash for verification (hex encoded)
        build_target: Option<String>, // e.g., "wasm32-wasip1", "wasm32-wasip2"
    },
    /// Project reference - uses registered project's code
    /// If version_key is None, uses active version
    Project {
        project_id: String,              // "alice.near/my-app"
        version_key: Option<String>,     // None = active version, Some = specific version
    },
}

/// Resolved code source for worker (GitHub or WasmUrl only, no Project)
/// This is what gets sent to worker after resolving Project references
#[derive(Clone, Debug)]
#[near(serializers = [borsh, json])]
pub enum CodeSource {
    GitHub {
        repo: String,
        commit: String,
        build_target: Option<String>,
    },
    WasmUrl {
        url: String,
        hash: String,
        build_target: Option<String>,
    },
}

/// Optional request parameters for additional options
#[derive(Clone, Debug, Default)]
#[near(serializers = [borsh, json])]
pub struct RequestParams {
    /// Force recompilation even if WASM exists in cache
    #[serde(default)]
    pub force_rebuild: bool,

    /// Store compiled WASM to FastFS after compilation
    /// Path will be: /{checksum}.wasm
    #[serde(default)]
    pub store_on_fastfs: bool,

    /// Compile only flag. Also set = true if resource_limits is none
    #[serde(default)]
    pub compile_only: bool,

    /// Project UUID for project-based execution: the storage namespace the
    /// worker runs the code in. The contract sets it from a Project source and
    /// clears it for any other; a value the caller supplies is ignored.
    #[serde(default)]
    pub project_uuid: Option<String>,

    /// Payment to project owner in stablecoin (minimal units, e.g., 1_000_000 = $1 USD)
    /// Only valid for ExecutionSource::Project
    /// Deducted from user's stablecoin balance in contract
    #[serde(default)]
    pub attached_usd: Option<U128>,

    /// Agent Connect: run the guest under the caller's BOUND account name, so
    /// `NEAR_SENDER_ID` inside the WASI module is the bound account instead of
    /// the caller's own.
    ///
    /// The same field the HTTPS path takes, so one agent's module behaves the
    /// same whichever way it was started. Opt-in on both: a binding is a
    /// capability the caller gains, not a silent change to who they are.
    ///
    /// The contract neither knows nor checks what this means — it only carries
    /// the request. The claim is settled off-chain against the chain itself:
    /// the caller must be a live extension of the account it wants to be seen
    /// as, verified inside the worker's TEE before the guest is given a name.
    ///
    /// Not stored in `ExecutionRequest`, only carried in the emitted request
    /// data — exactly like `force_rebuild` and `store_on_fastfs`. That is what
    /// keeps this a pure code change with no state migration.
    #[serde(default)]
    pub use_bound_identity: bool,
}

/// Response format for execution output
#[derive(Clone, Debug, PartialEq, Eq)]
#[near(serializers = [borsh, json])]
pub enum ResponseFormat {
    /// Raw bytes - no parsing
    Bytes,
    /// UTF-8 text string (default)
    Text,
    /// Parse stdout as JSON
    Json,
}

impl Default for ResponseFormat {
    fn default() -> Self {
        Self::Text
    }
}

/// Resource limits for execution
#[derive(Clone, Debug)]
#[near(serializers = [borsh, json])]
pub struct ResourceLimits {
    pub max_instructions: Option<u64>,
    pub max_memory_mb: Option<u32>,
    pub max_execution_seconds: Option<u64>,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_instructions: Some(1_000_000_000), // 1B instructions
            max_memory_mb: Some(128),              // 128 MB
            max_execution_seconds: Some(60),       // 60 seconds
        }
    }
}

/// Execution request stored in contract
#[derive(Clone, Debug)]
#[near(serializers = [borsh, json])]
pub struct ExecutionRequest {
    pub request_id: u64,
    pub data_id: CryptoHash,
    pub sender_id: AccountId,
    pub execution_source: ExecutionSource,  // Original source (may be Project)
    pub resolved_source: CodeSource,         // Resolved source for worker (GitHub/WasmUrl only)
    pub resource_limits: ResourceLimits,
    pub payment: Balance,
    pub timestamp: u64,
    pub secrets_ref: Option<SecretsReference>, // Reference to repo-based secrets
    pub response_format: ResponseFormat,
    pub input_data: Option<String>, // Optional input data for execution
    pub payer_account_id: AccountId, // Account to receive refunds (explicit or defaults to sender)
    pub attached_usd: u128, // Payment to project developer (stablecoin minimal units)

    // Large output handling (2-call flow)
    pub pending_output: Option<StoredOutput>, // Temporary storage for large output data
    pub output_submitted: bool, // Flag indicating output data has been submitted
}

/// Execution output - can be bytes, text, or parsed JSON
#[derive(Clone, Debug)]
#[near(serializers = [json])]
pub enum ExecutionOutput {
    Bytes(Vec<u8>),
    Text(String),
    Json(serde_json::Value),
}

/// Internal storage format for ExecutionOutput (Borsh-compatible)
/// Stores all data as Vec<u8> for efficient serialization
#[derive(Clone, Debug)]
#[near(serializers = [borsh, json])]
pub enum StoredOutput {
    Bytes(Vec<u8>),
    Text(Vec<u8>),      // UTF-8 bytes
    Json(Vec<u8>),      // JSON string as UTF-8 bytes
}

impl From<ExecutionOutput> for StoredOutput {
    fn from(output: ExecutionOutput) -> Self {
        match output {
            ExecutionOutput::Bytes(bytes) => StoredOutput::Bytes(bytes),
            ExecutionOutput::Text(text) => StoredOutput::Text(text.into_bytes()),
            ExecutionOutput::Json(value) => {
                let json_str = serde_json::to_string(&value).unwrap_or_default();
                StoredOutput::Json(json_str.into_bytes())
            }
        }
    }
}

impl From<StoredOutput> for ExecutionOutput {
    fn from(stored: StoredOutput) -> Self {
        match stored {
            StoredOutput::Bytes(bytes) => ExecutionOutput::Bytes(bytes),
            StoredOutput::Text(bytes) => ExecutionOutput::Text(
                String::from_utf8(bytes).unwrap_or_else(|_| String::from("[invalid UTF-8]"))
            ),
            StoredOutput::Json(bytes) => {
                let json_str = String::from_utf8(bytes).unwrap_or_default();
                ExecutionOutput::Json(
                    serde_json::from_str(&json_str).unwrap_or(serde_json::Value::Null)
                )
            }
        }
    }
}

/// Execution response from worker
#[derive(Clone, Debug)]
#[near(serializers = [json])]
pub struct ExecutionResponse {
    pub success: bool,
    pub output: Option<ExecutionOutput>,
    pub error: Option<String>,
    pub resources_used: ResourceMetrics,
    pub compilation_note: Option<String>, // e.g., "Cached WASM from 2025-01-10 14:30 UTC"
    /// Refund amount to return to user from attached_usd (stablecoin minimal units)
    /// Set by WASM via refund_usd() host function
    #[serde(default)]
    pub refund_usd: Option<u64>,
}

/// Resource usage metrics
#[derive(Clone, Debug)]
#[near(serializers = [json])]
pub struct ResourceMetrics {
    pub instructions: u64,        // Instructions used during WASM execution
    pub time_ms: u64,              // Execution time in milliseconds
    pub compile_time_ms: Option<u64>, // Compilation time in milliseconds (if compiled)
}

/// Reference to secrets stored in contract (new approach)
#[derive(Clone, Debug)]
#[near(serializers = [borsh, json])]
pub struct SecretsReference {
    pub profile: String,      // Profile name (e.g., "default", "premium")
    pub account_id: AccountId, // Account that owns the secrets
}

/// Secret profile stored in contract (internal storage)
#[derive(Clone, Debug)]
#[near(serializers = [borsh])]
pub struct SecretProfile {
    pub encrypted_secrets: String,      // base64-encoded encrypted secrets
    pub access: types::AccessCondition, // Access control rules
    pub created_at: u64,                // Timestamp when created
    pub updated_at: u64,                // Timestamp when last updated
    pub storage_deposit: Balance,       // Storage staking amount (u128 for cheaper storage)
}

/// Secret profile for JSON view (returned from view methods)
#[derive(Clone, Debug)]
#[near(serializers = [json])]
pub struct SecretProfileView {
    pub encrypted_secrets: String,      // base64-encoded encrypted secrets
    pub access: types::AccessCondition, // Access control rules
    pub created_at: u64,                // Timestamp when created
    pub updated_at: u64,                // Timestamp when last updated
    pub storage_deposit: U128,          // Storage staking amount (U128 for JSON)
    pub accessor: SecretAccessor,       // What code can access this secret (Repo or WasmHash)
}


/// System secret types (Payment Keys, etc.)
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[near(serializers = [borsh, json])]
pub enum SystemSecretType {
    /// Payment Key for HTTPS API
    PaymentKey,
}

/// Secret accessor - defines what code can access/decrypt the secret
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[near(serializers = [borsh, json])]
pub enum SecretAccessor {
    /// Secrets bound to a GitHub repository and optional branch
    Repo {
        repo: String,           // Normalized repo path: "github.com/owner/repo"
        branch: Option<String>, // Branch name or None for all branches
    },
    /// Secrets bound to a specific WASM hash (for WasmUrl sources)
    WasmHash {
        hash: String,           // SHA256 hash of the WASM binary
    },
    /// Secrets bound to a project (available to all versions)
    Project {
        project_id: String,     // "alice.near/my-app"
    },
    /// System secrets (Payment Keys for HTTPS API)
    ///
    /// Anything added to this enum goes at the END. It is borsh-encoded as part
    /// of `SecretKey`, which is a storage KEY: borsh writes the variant's
    /// ORDINAL, so inserting one before `System` moves `System` from 3 to 4 and
    /// every payment key ever stored is looked up under a key that holds
    /// nothing — every HTTPS call failing with "payment key not found", and the
    /// secrets unreachable rather than lost.
    System(SystemSecretType),
}

/// Composite key for secrets storage
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[near(serializers = [borsh])]
pub struct SecretKey {
    pub accessor: SecretAccessor, // What code can access this secret (Repo, WasmHash, or Project)
    pub profile: String,          // Profile name: "default", "premium", etc.
    pub owner: AccountId,         // Account that created these secrets
}

// ============================================================================
// Project System - Persistent Storage for WASM Applications
// ============================================================================

/// Project stored in contract
#[derive(Clone, Debug)]
#[near(serializers = [borsh, json])]
pub struct Project {
    pub uuid: String,              // Internal UUID: "proj_a1b2c3d4"
    pub owner: AccountId,          // alice.near
    pub name: String,              // "my-app"
    pub active_version: String,    // wasm_hash of active version
    pub created_at: u64,
    pub storage_deposit: Balance,  // Storage staking for contract data
}

/// Version info stored per project
#[derive(Clone, Debug)]
#[near(serializers = [borsh, json])]
pub struct VersionInfo {
    pub source: CodeSource,
    pub added_at: u64,
    pub storage_deposit: Balance,  // Storage staking for this version entry
    //
    // NOTE: this struct is borsh-encoded as the VALUE of `project_versions`,
    // and borsh has no schema evolution: appending a field — even an `Option`
    // — leaves every entry written by an earlier contract one byte short, and
    // reading one then fails outright rather than defaulting. Anything new
    // about a version belongs in a side map, never here.
}

/// Pending version request (for yield/resume flow)
#[derive(Clone, Debug)]
#[near(serializers = [borsh])]
pub struct PendingVersion {
    pub project_uuid: String,
    pub project_id: String,        // "alice.near/my-app" for metadata verification
    pub source: CodeSource,
    pub set_active: bool,
    pub requested_at: u64,
    pub data_id: CryptoHash,
}

/// Project view for JSON responses
#[derive(Clone, Debug)]
#[near(serializers = [json])]
pub struct ProjectView {
    pub uuid: String,
    pub owner: AccountId,
    pub name: String,
    pub project_id: String,        // "alice.near/my-app"
    pub active_version: String,
    pub created_at: u64,
    pub storage_deposit: U128,
}

/// Version view for JSON responses
#[derive(Clone, Debug)]
#[near(serializers = [json])]
pub struct VersionView {
    pub wasm_hash: String,
    pub source: CodeSource,
    pub added_at: u64,
    pub is_active: bool,
}

/// Pricing view for JSON responses (includes both NEAR and USD pricing)
#[derive(Clone, Debug)]
#[near(serializers = [json])]
pub struct PricingView {
    // NEAR pricing (for blockchain transactions)
    pub base_fee: U128,
    pub per_million_instructions_fee: U128,
    pub per_ms_fee: U128,
    pub per_compile_ms_fee: U128,
    // USD pricing (for HTTPS API, in minimal token units)
    pub base_fee_usd: U128,
    pub per_million_instructions_fee_usd: U128,
    pub per_sec_fee_usd: U128,
    pub per_compile_ms_fee_usd: U128,
}

#[derive(BorshDeserialize, BorshSerialize, PanicOnDefault)]
#[borsh(crate = "near_sdk::borsh")]
#[near_bindgen]
pub struct Contract {
    // Contract configuration
    owner_id: AccountId,
    operator_id: AccountId,
    paused: bool,

    // Event metadata (for NEP-297 events)
    event_standard: String,
    event_version: String,

    // Pricing (NEAR) - for blockchain transactions
    base_fee: Balance,
    per_million_instructions_fee: Balance,
    per_ms_fee: Balance,                 // Execution time cost
    per_compile_ms_fee: Balance,         // Compilation time cost

    // Pricing (USD) - for HTTPS API (in minimal token units, e.g., 1 = 0.000001 USDT)
    base_fee_usd: u128,                      // e.g., 10000 = $0.01
    per_million_instructions_fee_usd: u128,  // e.g., 1 = $0.000001 per 1M instructions
    per_sec_fee_usd: u128,                    // e.g., 1 = $0.000001 per sec execution
    per_compile_ms_fee_usd: u128,            // e.g., 10 = $0.00001 per ms compilation

    // Payment token for HTTPS API (e.g., "usdt.tether-token.near")
    payment_token_contract: Option<AccountId>,

    // Request tracking
    next_request_id: u64,
    pending_requests: LookupMap<u64, ExecutionRequest>,

    // Statistics
    total_executions: u64,
    total_fees_collected: Balance,

    // Repo-based secrets storage
    secrets_storage: LookupMap<SecretKey, SecretProfile>,

    // User secrets index: account_id -> set of SecretKey
    user_secrets_index: LookupMap<AccountId, UnorderedSet<SecretKey>>,

    // Project storage: project_id ("alice.near/my-app") -> Project
    projects: LookupMap<String, Project>,

    // Project versions: project_uuid -> (wasm_hash -> VersionInfo)
    project_versions: LookupMap<String, UnorderedMap<String, VersionInfo>>,

    // User projects index: account_id -> set of project_id
    user_projects_index: LookupMap<AccountId, UnorderedSet<String>>,

    // Next project UUID counter
    next_project_id: u64,

    // Developer earnings: project_owner -> accumulated balance (stablecoin minimal units)
    developer_earnings: LookupMap<AccountId, u128>,

    // User stablecoin balances: user_account -> balance (stablecoin minimal units)
    // Used for attached_usd payments to project developers
    user_stablecoin_balances: LookupMap<AccountId, u128>,

    // Wallet policies: wallet_pubkey ("ed25519:<hex>" / "secp256k1:<hex>") -> WalletPolicyEntry
    wallet_policies: LookupMap<String, wallet::WalletPolicyEntry>,

    // Wallet owner index: owner -> set of wallet_pubkeys (for get_wallet_policies_by_owner)
    wallet_owner_index: LookupMap<AccountId, UnorderedSet<String>>,

    // Per-secret vault binding side-table.
    // SecretKey -> vault account whose master encrypted this secret.
    // None / absent entry means "use the default OutLayer master".
    // Kept separate from SecretProfile so existing borsh-serialised
    // entries deserialise unchanged after a contract upgrade that
    // adds this map.
    secret_vault_bindings: LookupMap<SecretKey, AccountId>,

    // What a subscription costs: the price list, and the only copy of it.
    // The coordinator syncs from here the way it syncs execution pricing.
    //
    // A plain Vec rather than a collection: it is a handful of rows, every
    // purchase needs all of them to resolve an index, and a view has to return
    // the whole list anyway.
    subscription_plans: Vec<payment::SubscriptionPlan>,

    // What curated projects charge per operation, and whom to credit for them.
    //
    // An UnorderedMap, not a LookupMap, and the difference is the point: a
    // LookupMap cannot be ENUMERATED. The coordinator mirrors these prices, and
    // with a LookupMap it could only ask about project ids it already knew — it
    // took its list from its own connector registry, so a project priced here
    // but absent there would be charged on chain and free over HTTPS, for ever
    // and with nothing to notice it.
    //
    // Not a Vec in root state either: unlike the subscription plans, an entry
    // is read only when the project it belongs to is called, so a caller of any
    // other project never pays to deserialise it. `UnorderedMap` keeps that
    // property and adds the key list.
    project_pricing: UnorderedMap<String, payment::ProjectPricing>,
}

#[near_bindgen]
impl Contract {
    #[init]
    pub fn new(owner_id: AccountId, operator_id: Option<AccountId>, event_standard: Option<String>,
        event_version: Option<String>) -> Self {
        Self {
            owner_id: owner_id.clone(),
            operator_id: operator_id.unwrap_or(owner_id),
            paused: false,
            event_standard: event_standard.unwrap_or("near-outlayer".to_string()),
            event_version: event_version.unwrap_or("1.0.0".to_string()),
            // NEAR pricing
            base_fee: 1_000_000_000_000_000_000_000, // 0.001 NEAR
            per_million_instructions_fee: 100_000_000_000_000, // 0.0000001 NEAR per million instructions
            per_ms_fee: 100_000_000_000_000_000, // 0.0001 NEAR per second (execution)
            per_compile_ms_fee: 100_000_000_000_000_000, // 0.0001 NEAR per second (compilation)
            // USD pricing (for HTTPS API, using USDT with 6 decimals)
            base_fee_usd: 1_000,             // $0.001 base fee
            per_million_instructions_fee_usd: 1, // $0.000001 per million instructions
            per_sec_fee_usd: 1,               // $0.000001 per sec execution
            per_compile_ms_fee_usd: 10,       // $0.00001 per ms compilation
            // Payment token (set via admin method)
            payment_token_contract: None,
            next_request_id: 0,
            pending_requests: LookupMap::new(StorageKey::PendingRequests),
            total_executions: 0,
            total_fees_collected: 0,
            secrets_storage: LookupMap::new(StorageKey::SecretsStorage),
            user_secrets_index: LookupMap::new(StorageKey::UserSecretsIndex),
            // Project system
            projects: LookupMap::new(StorageKey::Projects),
            project_versions: LookupMap::new(b"pv".to_vec()),
            user_projects_index: LookupMap::new(StorageKey::UserProjects),
            next_project_id: 0,
            // Developer earnings (stablecoin)
            developer_earnings: LookupMap::new(StorageKey::DeveloperEarnings),
            // User stablecoin balances
            user_stablecoin_balances: LookupMap::new(StorageKey::UserStablecoinBalances),
            // Wallet policies
            wallet_policies: LookupMap::new(StorageKey::WalletPolicies),
            wallet_owner_index: LookupMap::new(StorageKey::WalletOwnerIndex),
            // Per-vault master phase 2
            secret_vault_bindings: LookupMap::new(StorageKey::SecretVaultBindings),
            // Empty sells nothing: a deployment that has not set its price list
            // refuses purchases and returns the money, rather than giving a
            // subscription away at a price nobody set.
            subscription_plans: Vec::new(),
            project_pricing: UnorderedMap::new(StorageKey::ProjectPricing),
        }
    }

    /// Withdraw accumulated developer earnings (stablecoin)
    ///
    /// Only the project owner themselves can withdraw their earnings.
    /// Withdraws entire balance to caller via ft_transfer.
    /// Uses callback pattern to rollback on transfer failure.
    ///
    /// # Returns
    /// Promise to transfer stablecoin to the caller
    #[payable]
    pub fn withdraw_developer_earnings(&mut self) -> near_sdk::Promise {
        assert!(
            env::attached_deposit().as_yoctonear() >= 1,
            "Requires attached deposit of at least 1 yoctoNEAR"
        );

        let caller = env::predecessor_account_id();
        let balance = self.developer_earnings.get(&caller).unwrap_or(0);

        assert!(balance > 0, "No earnings to withdraw");

        // Get payment token contract
        let token_contract = self.payment_token_contract.as_ref()
            .expect("Payment token contract not configured");

        // Remove entry (balance becomes 0) - will be restored in callback if transfer fails
        self.developer_earnings.remove(&caller);

        log!(
            "Developer {} initiating withdrawal of {} stablecoin",
            caller,
            balance
        );

        // Transfer stablecoin to caller via ft_transfer with callback
        // ft_transfer requires 1 yoctoNEAR attached deposit
        near_sdk::Promise::new(token_contract.clone())
            .function_call(
                "ft_transfer".to_string(),
                serde_json::json!({
                    "receiver_id": caller,
                    "amount": U128(balance),
                    "memo": Some("Developer earnings withdrawal")
                }).to_string().into_bytes(),
                NearToken::from_yoctonear(1),
                Gas::from_tgas(10),
            )
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(Gas::from_tgas(5))
                    .on_withdraw_developer_earnings(caller, U128(balance))
            )
    }

    /// Callback for withdraw_developer_earnings
    /// Restores balance if ft_transfer failed
    #[private]
    pub fn on_withdraw_developer_earnings(
        &mut self,
        developer: AccountId,
        amount: U128,
        #[callback_result] transfer_result: Result<(), PromiseError>,
    ) {
        match transfer_result {
            Ok(()) => {
                log!(
                    "Developer {} successfully withdrew {} stablecoin",
                    developer,
                    amount.0
                );
            }
            Err(_) => {
                // Transfer failed - restore balance
                let current = self.developer_earnings.get(&developer).unwrap_or(0);
                self.developer_earnings.insert(&developer, &(current + amount.0));
                log!(
                    "ft_transfer failed, restored {} stablecoin to developer {}",
                    amount.0,
                    developer
                );
            }
        }
    }
}

impl Contract {
    fn assert_not_paused(&self) {
        assert!(!self.paused, "Contract is paused");
    }

    fn assert_operator(&self) {
        assert_eq!(
            env::predecessor_account_id(),
            self.operator_id,
            "Only operator can call this"
        );
    }

    fn calculate_cost(&self, metrics: &ResourceMetrics) -> Balance {
        let instruction_cost =
            (metrics.instructions / 1_000_000) as u128 * self.per_million_instructions_fee;
        let time_cost = metrics.time_ms as u128 * self.per_ms_fee;

        // Add compilation cost if compilation occurred (uses separate, higher rate)
        let compile_cost = metrics.compile_time_ms
            .map(|ms| ms as u128 * self.per_compile_ms_fee)
            .unwrap_or(0);

        self.base_fee + instruction_cost + time_cost + compile_cost
    }

    /// Estimate cost based on resource limits
    fn estimate_cost(&self, limits: &ResourceLimits) -> Balance {
        // Use requested limits or defaults
        let max_instructions = limits.max_instructions.unwrap_or(1_000_000_000);
        let max_execution_seconds = limits.max_execution_seconds.unwrap_or(60);
        let max_time_ms = max_execution_seconds * 1000;

        // Calculate worst-case cost
        let instruction_cost = (max_instructions / 1_000_000) as u128 * self.per_million_instructions_fee;
        let time_cost = max_time_ms as u128 * self.per_ms_fee;

        self.base_fee + instruction_cost + time_cost
    }
}

#[cfg(test)]
mod tests;
