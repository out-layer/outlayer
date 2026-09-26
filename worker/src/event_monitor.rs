use anyhow::{Context, Result};
use near_jsonrpc_client::{methods, JsonRpcClient};
use near_primitives::types::{AccountId, BlockId, BlockReference, Finality};
use near_primitives::views::QueryRequest;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{error, info, warn};

use crate::api_client::{ApiClient, CreateTaskParams, ResourceLimits as ApiResourceLimits};

/// Error indicating block is not yet indexed by neardata
/// This should be handled differently from other errors - we should wait, not skip
#[derive(Debug)]
pub struct BlockNotIndexedError {
    pub block_id: u64,
}

impl std::fmt::Display for BlockNotIndexedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Block {} not yet indexed by neardata", self.block_id)
    }
}

impl std::error::Error for BlockNotIndexedError {}

/// Enum for different event types from contract
#[derive(Debug, Clone)]
pub enum ContractEvent {
    ExecutionRequested(ExecutionRequestedEvent),
    ProjectStorageCleanup(ProjectStorageCleanupEvent),
    ProjectTransferred(ProjectTransferredEvent),
    TopUpPaymentKey(TopUpPaymentKeyEvent),
    DeletePaymentKey(DeletePaymentKeyEvent),
    WalletPolicyUpdated(WalletPolicyUpdatedEvent),
    WalletPolicyDeleted(WalletPolicyDeletedEvent),
    WalletFrozenChanged(WalletFrozenChangedEvent),
    SubscriptionPurchased(SubscriptionPurchasedEvent),
}

/// TopUpPaymentKey event data from SystemEvent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopUpPaymentKeyEvent {
    pub data_id: Vec<u8>,          // CryptoHash for yield/resume
    pub owner: String,              // Payment Key owner
    pub nonce: u32,                 // Payment Key nonce (profile)
    pub amount: String,             // Amount in minimal token units (U128 as string)
    pub encrypted_data: String,     // Current encrypted secret (base64)
}

/// DeletePaymentKey event data from SystemEvent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletePaymentKeyEvent {
    pub data_id: Vec<u8>,          // CryptoHash for yield/resume
    pub owner: String,              // Payment Key owner
    pub nonce: u32,                 // Payment Key nonce (profile)
}

/// WalletPolicyUpdated event data from SystemEvent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletPolicyUpdatedEvent {
    pub wallet_pubkey: String,      // "ed25519:<hex>" or "secp256k1:<hex>"
    pub owner: String,              // Controller NEAR account
    pub encrypted_data: String,     // Encrypted policy (keystore decrypts to extract key hashes)
    pub frozen: bool,
}

/// WalletPolicyDeleted event data from SystemEvent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletPolicyDeletedEvent {
    pub wallet_pubkey: String,
    pub owner: String,
}

/// WalletFrozenChanged event data from SystemEvent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletFrozenChangedEvent {
    pub wallet_pubkey: String,
    pub owner: String,
    pub frozen: bool,
}

/// SubscriptionPurchased event data from SystemEvent.
///
/// Carries what was PAID — the plan and the money — and nothing about what it
/// is worth: the contract does not know, and the worker must not assert it.
/// The coordinator reads the terms from its own table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionPurchasedEvent {
    pub owner: String,
    pub nonce: u32,
    pub plan: u8,
    pub paid_usd: String,
    pub payer: String,
    /// The receipt that carried the payment, filled in from the block rather
    /// than the log. It is what stops a redelivery granting a second
    /// allowance, so an event without one is not relayed at all.
    #[serde(default)]
    pub receipt_id: Option<String>,
}

/// ExecutionRequested event data from contract (matches contract's event structure)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionRequestedEvent {
    pub request_data: String,  // JSON string containing RequestData
    pub data_id: Vec<u8>,
    pub timestamp: u64,
    #[serde(skip)]
    pub block_height: u64,  // Added locally, not from contract event
    #[serde(skip)]
    pub transaction_hash: Option<String>,  // Original transaction hash from neardata
    #[serde(skip)]
    pub receipt_id: Option<String>,  // Receipt ID from neardata
    #[serde(skip)]
    pub predecessor_id: Option<String>,  // Predecessor from neardata
    #[serde(skip)]
    pub signer_id: Option<String>,  // Signer from neardata
    #[serde(skip)]
    pub signer_public_key: Option<String>,  // Signer public key from neardata
    #[serde(skip)]
    pub gas_burnt: Option<u64>,  // Gas burnt from neardata
}

/// ProjectStorageCleanup event data from contract (emitted when project is deleted)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectStorageCleanupEvent {
    pub project_id: String,
    pub project_uuid: String,
    pub timestamp: u64,
    /// The block the event was written in, from the block rather than the
    /// log: the coordinator confirms the deletion on the contract there.
    #[serde(skip)]
    pub block_height: u64,
}

/// ProjectTransferred event data from SystemEvent (emitted by
/// `transfer_project`). The uuid is unchanged; the project now answers to
/// `new_project_id`, and `old_project_id` is free for a new project.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectTransferredEvent {
    pub old_project_id: String,
    pub new_project_id: String,
    pub project_uuid: String,
    pub old_owner: String,
    pub new_owner: String,
}

/// Parsed request data from the JSON string
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestData {
    pub request_id: u64,
    pub sender_id: String,
    pub code_source: CodeSource,
    pub resource_limits: ResourceLimits,
    pub input_data: String,
    /// If true, input_data is stored in contract state (too large for event log)
    /// Worker should fetch via get_request() view call
    #[serde(default)]
    pub input_data_in_state: bool,
    #[serde(default)]
    pub secrets_ref: Option<crate::api_client::SecretsReference>,
    /// The account that called the contract, as the contract itself saw it
    /// (`env::predecessor_account_id()`): the relaying contract, or the signer
    /// on a direct call. What a `Predecessor` access condition is judged
    /// against.
    #[serde(default)]
    pub predecessor_id: Option<String>,
    pub payment: String,
    /// Payment to project developer (stablecoin, minimal token units)
    #[serde(default)]
    pub attached_usd: Option<String>,
    pub timestamp: u64,
    #[serde(default)]
    pub response_format: crate::api_client::ResponseFormat,
    #[serde(default)]
    pub compile_only: bool,
    #[serde(default)]
    pub force_rebuild: bool,
    #[serde(default)]
    pub store_on_fastfs: bool,
    /// Agent Connect: the caller asked to run under its bound account's name.
    /// Carried through untouched — the claim is settled against the chain in
    /// the TEE, not here.
    #[serde(default)]
    pub use_bound_identity: bool,
    /// Project UUID for persistent storage (passed from request_execution_project)
    #[serde(default)]
    pub project_uuid: Option<String>,
    /// Project ID for project-based secrets (e.g., "alice.near/my-app")
    #[serde(default)]
    pub project_id: Option<String>,
}

/// Code source - either GitHub repo or pre-compiled WASM URL
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CodeSource {
    GitHub {
        #[serde(rename = "GitHub")]
        github: GitHubSource,
    },
    WasmUrl {
        #[serde(rename = "WasmUrl")]
        wasm_url: WasmUrlSource,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubSource {
    pub repo: String,
    pub commit: String,
    pub build_target: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmUrlSource {
    pub url: String,
    pub hash: String,
    pub build_target: Option<String>,
}

impl CodeSource {
    /// Get repo URL (for GitHub sources)
    #[allow(dead_code)]
    pub fn repo(&self) -> Option<&str> {
        match self {
            CodeSource::GitHub { github } => Some(&github.repo),
            CodeSource::WasmUrl { .. } => None,
        }
    }

    /// Get commit (for GitHub sources)
    #[allow(dead_code)]
    pub fn commit(&self) -> Option<&str> {
        match self {
            CodeSource::GitHub { github } => Some(&github.commit),
            CodeSource::WasmUrl { .. } => None,
        }
    }

    /// Get build target
    pub fn build_target(&self) -> Option<&str> {
        match self {
            CodeSource::GitHub { github } => github.build_target.as_deref(),
            CodeSource::WasmUrl { wasm_url } => wasm_url.build_target.as_deref(),
        }
    }

    /// Set build target
    pub fn set_build_target(&mut self, target: String) {
        match self {
            CodeSource::GitHub { github } => github.build_target = Some(target),
            CodeSource::WasmUrl { wasm_url } => wasm_url.build_target = Some(target),
        }
    }

    /// Get display string for logging
    pub fn display(&self) -> String {
        match self {
            CodeSource::GitHub { github } => format!("{}@{}", github.repo, github.commit),
            CodeSource::WasmUrl { wasm_url } => format!("url:{} hash:{}", wasm_url.url, wasm_url.hash),
        }
    }

    /// Convert to api_client::CodeSource
    pub fn to_api_code_source(&self) -> crate::api_client::CodeSource {
        match self {
            CodeSource::GitHub { github } => crate::api_client::CodeSource::GitHub {
                repo: github.repo.clone(),
                commit: github.commit.clone(),
                build_target: github.build_target.clone().unwrap_or_else(|| "wasm32-wasi".to_string()),
            },
            CodeSource::WasmUrl { wasm_url } => crate::api_client::CodeSource::WasmUrl {
                url: wasm_url.url.clone(),
                hash: wasm_url.hash.clone(),
                build_target: wasm_url.build_target.clone().unwrap_or_else(|| "wasm32-wasi".to_string()),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub max_instructions: u64,
    pub max_memory_mb: u32,
    pub max_execution_seconds: u64,
}

/// Block data from neardata.xyz API
#[derive(Debug, Deserialize)]
struct BlockData {
    shards: Option<Vec<ShardData>>,
}

#[derive(Debug, Deserialize)]
struct ShardData {
    receipt_execution_outcomes: Option<Vec<ReceiptExecutionOutcome>>,
}

#[derive(Debug, Deserialize)]
struct ReceiptExecutionOutcome {
    receipt: Option<Receipt>,
    execution_outcome: Option<ExecutionOutcome>,
    tx_hash: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Receipt {
    receiver_id: Option<String>,
    receipt_id: Option<String>,
    predecessor_id: Option<String>,
    receipt: Option<ReceiptAction>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "Action")]
struct ReceiptAction {
    #[serde(rename = "Action")]
    action: Option<ActionDetails>,
}

#[derive(Debug, Deserialize)]
struct ActionDetails {
    signer_id: Option<String>,
    signer_public_key: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ExecutionOutcome {
    outcome: Option<Outcome>,
    #[allow(dead_code)]
    id: Option<String>,  // receipt_id
}

#[derive(Debug, Deserialize)]
struct Outcome {
    logs: Option<Vec<String>>,
    #[allow(dead_code)]
    receipt_ids: Option<Vec<String>>,
    gas_burnt: Option<u64>,
    /// nearcore's `ExecutionStatusView`, read by [`ExecutionOutcome::committed`].
    /// Kept as JSON so that one receipt with a shape this worker does not know
    /// is refused on its own, without failing the whole block.
    status: Option<Value>,
}

/// How a receipt's execution ended, as neardata carries nearcore's
/// `ExecutionStatusView`. A receipt keeps its logs whatever its status; only a
/// receipt that succeeded keeps its state. The events in a failed receipt's
/// logs announce work the chain rolled back — a purchase whose payment was
/// refunded, a request that was never stored, a deletion that was undone — so
/// such a log is not an event.
#[derive(Debug, Deserialize)]
enum ExecutionStatus {
    /// The receipt ran to the end and returned a value (possibly empty).
    SuccessValue(#[allow(dead_code)] String),
    /// The receipt ran to the end and returned a promise, resolved by the
    /// receipt named here; `request_execution` ends this way (yield).
    SuccessReceiptId(#[allow(dead_code)] String),
    /// The receipt failed; every state change it made was rolled back.
    Failure(Value),
    /// The outcome is not final. neardata serves final blocks, so this is not
    /// expected; it is not a success.
    Unknown,
}

impl ExecutionOutcome {
    /// `Ok` when this receipt's state changes are on chain, so its logs may be
    /// read as events; `Err(reason)` otherwise: a failure, a missing status, or
    /// a status this worker does not recognise. An unknown shape is refused,
    /// not guessed — a variant nearcore adds later is a reason to look, not an
    /// event.
    fn committed(&self) -> Result<(), String> {
        let status = self
            .outcome
            .as_ref()
            .and_then(|o| o.status.as_ref())
            .ok_or_else(|| "no execution status".to_string())?;
        match serde_json::from_value::<ExecutionStatus>(status.clone()) {
            Ok(ExecutionStatus::SuccessValue(_)) | Ok(ExecutionStatus::SuccessReceiptId(_)) => Ok(()),
            Ok(ExecutionStatus::Failure(error)) => {
                Err(format!("failed: {}", crate::near_client::head(&error.to_string(), 200)))
            }
            Ok(ExecutionStatus::Unknown) => Err("status Unknown".to_string()),
            Err(_) => Err(format!(
                "unrecognised status {}",
                crate::near_client::head(&status.to_string(), 200)
            )),
        }
    }
}

/// `Ok` when the receipt's logs may be read as events — see
/// [`ExecutionOutcome::committed`]; a receipt without an execution outcome
/// has nothing on chain either.
fn receipt_committed(outcome: &ReceiptExecutionOutcome) -> Result<(), String> {
    outcome
        .execution_outcome
        .as_ref()
        .ok_or_else(|| "no execution outcome".to_string())?
        .committed()
}

/// NEAR RPC block response (simplified, only what we need)
#[derive(Debug, Deserialize)]
struct NearRpcBlockResponse {
    result: Option<NearRpcBlockResult>,
}

#[derive(Debug, Deserialize)]
struct NearRpcBlockResult {
    header: NearRpcBlockHeader,
}

#[derive(Debug, Deserialize)]
struct NearRpcBlockHeader {
    height: u64,
}

/// The prefix NEP-297 puts at the start of every event log.
pub const EVENT_JSON_PREFIX: &str = "EVENT_JSON:";

/// The JSON of a NEP-297 event log, or `None` when `log` is not one.
///
/// NEP-297 defines an event as a log that STARTS with `EVENT_JSON:`, the rest
/// of the log being the event. The contract also writes logs that carry
/// caller-supplied text — a version key, a WASM's output, an error — and that
/// text may itself read `EVENT_JSON:{…}`; a match anywhere but at the start
/// would take it for an event of the contract. `log` is one entry of a
/// receipt's `logs` and is never split into lines. The contract's own event
/// JSON is one line, so a log holding a line break is not an event: a consumer
/// that does split on lines must not find a second event inside it.
pub fn event_json_payload(log: &str) -> Option<&str> {
    let json = log.strip_prefix(EVENT_JSON_PREFIX)?;
    if json.contains(['\n', '\r']) {
        return None;
    }
    Some(json)
}

/// NEAR event monitor that watches neardata.xyz for execution_requested and version_requested events
pub struct EventMonitor {
    api_client: ApiClient,
    neardata_api_url: String,
    contract_id: AccountId,
    current_block: u64,
    scan_interval_ms: u64,
    http_client: reqwest::Client,
    rpc_client: JsonRpcClient,
    blocks_scanned: u64,
    events_found: u64,
    system_events_found: u64,
    // Event filters
    event_filter_standard_name: String,
    #[allow(dead_code)]
    event_filter_function_name: String, // Kept for compatibility but we now handle multiple events
    event_filter_min_version: Option<(u64, u64, u64)>, // Parsed semver (major, minor, patch)
    /// Shared block height for heartbeat reporting to coordinator
    shared_block_height: Arc<AtomicU64>,
}

impl EventMonitor {
    /// Parse semver string like "1.2.3" into (major, minor, patch)
    fn parse_semver(version: &str) -> Option<(u64, u64, u64)> {
        let parts: Vec<&str> = version.split('.').collect();
        if parts.len() >= 3 {
            let major = parts[0].parse().ok()?;
            let minor = parts[1].parse().ok()?;
            let patch = parts[2].parse().ok()?;
            Some((major, minor, patch))
        } else if parts.len() == 2 {
            let major = parts[0].parse().ok()?;
            let minor = parts[1].parse().ok()?;
            Some((major, minor, 0))
        } else if parts.len() == 1 {
            let major = parts[0].parse().ok()?;
            Some((major, 0, 0))
        } else {
            None
        }
    }

    /// Compare two semver tuples: returns true if actual >= required
    fn semver_gte(actual: (u64, u64, u64), required: (u64, u64, u64)) -> bool {
        actual >= required
    }

    pub async fn new(
        api_client: ApiClient,
        neardata_api_url: String,
        near_rpc_url: String,
        contract_id: AccountId,
        start_block: u64,
        scan_interval_ms: u64,
        event_filter_standard_name: String,
        event_filter_function_name: String,
        event_filter_min_version: Option<String>,
        shared_block_height: Arc<AtomicU64>,
    ) -> Result<Self> {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .context("Failed to create HTTP client")?;

        // Create RPC client for view calls (e.g., fetching large input_data)
        let rpc_client = JsonRpcClient::connect(&near_rpc_url);

        // Determine starting block:
        // 1. Try saved cursor from coordinator (persisted across restarts)
        // 2. Fall back to START_BLOCK_HEIGHT env var
        // 3. If 0, fetch latest block from NEAR RPC
        // Max blocks behind before we skip to latest (100 blocks ≈ 2 minutes)
        const MAX_CATCHUP_BLOCKS: u64 = 1000;

        let current_block = match api_client.get_block_cursor().await {
            Ok(Some(saved_block)) if saved_block > 0 => {
                // Check if cursor is too far behind — skip to latest instead of slow catch-up
                let latest = Self::fetch_latest_block(&http_client, &near_rpc_url).await
                    .unwrap_or(saved_block);
                if latest > saved_block + MAX_CATCHUP_BLOCKS {
                    info!(
                        "⏩ Saved cursor {} is {} blocks behind latest {}. Skipping to latest.",
                        saved_block, latest - saved_block, latest
                    );
                    latest
                } else {
                    info!(
                        "📌 Resuming from saved block cursor: {} ({} blocks behind latest)",
                        saved_block, latest.saturating_sub(saved_block)
                    );
                    saved_block
                }
            }
            Ok(_) => {
                if start_block == 0 {
                    info!("START_BLOCK_HEIGHT=0, fetching latest block from NEAR RPC...");
                    Self::fetch_latest_block(&http_client, &near_rpc_url).await?
                } else {
                    info!("No saved block cursor, using START_BLOCK_HEIGHT={}", start_block);
                    start_block
                }
            }
            Err(e) => {
                warn!("Failed to load block cursor (falling back to START_BLOCK_HEIGHT): {}", e);
                if start_block == 0 {
                    Self::fetch_latest_block(&http_client, &near_rpc_url).await?
                } else {
                    start_block
                }
            }
        };

        // Parse min version if provided
        let parsed_min_version = event_filter_min_version
            .as_ref()
            .and_then(|v| Self::parse_semver(v));

        info!(
            "Event filter: standard={}, function={}, min_version={:?}",
            event_filter_standard_name, event_filter_function_name, event_filter_min_version
        );

        // Set initial shared block height
        shared_block_height.store(current_block, Ordering::Relaxed);

        Ok(Self {
            api_client,
            neardata_api_url,
            contract_id,
            current_block,
            scan_interval_ms,
            http_client,
            rpc_client,
            blocks_scanned: 0,
            events_found: 0,
            system_events_found: 0,
            event_filter_standard_name,
            event_filter_function_name,
            event_filter_min_version: parsed_min_version,
            shared_block_height,
        })
    }

    /// Fetch latest finalized block height from NEAR RPC
    async fn fetch_latest_block(
        http_client: &reqwest::Client,
        near_rpc_url: &str,
    ) -> Result<u64> {
        let request_body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "dontcare",
            "method": "block",
            "params": {
                "finality": "final"
            }
        });

        let response = http_client
            .post(near_rpc_url)
            .json(&request_body)
            .send()
            .await
            .context("Failed to fetch block from NEAR RPC")?;

        if !response.status().is_success() {
            anyhow::bail!("NEAR RPC returned status: {}", response.status());
        }

        let block_response: NearRpcBlockResponse = response
            .json()
            .await
            .context("Failed to parse NEAR RPC response")?;

        let height = block_response
            .result
            .ok_or_else(|| anyhow::anyhow!("NEAR RPC returned no result"))?
            .header
            .height;

        Ok(height)
    }

    /// Start continuous monitoring of new blocks
    pub async fn start_monitoring(&mut self) -> Result<()> {
        info!(
            "Starting event monitoring from block {} for contract {}",
            self.current_block, self.contract_id
        );

        let start_block = self.current_block;
        let mut retry_count = 0;
        let mut wait_for_block_count = 0u32; // Counter for "waiting for block" logging
        const MAX_RETRIES: u32 = 3;
        // How many times a block has been held because a MONEY event could not
        // be relayed. Bounded so one event the coordinator will never accept
        // cannot stop the monitor from ever scanning again.
        let mut relay_retry_count = 0u32;
        const MAX_RELAY_RETRIES: u32 = 12;

        loop {
            // Set when an event that MOVES MONEY could not be relayed for a
            // reason that may pass. See the hold below.
            let mut hold_for_relay = false;

            match self.scan_single_block(self.current_block).await {
                Ok(events) => {
                    self.blocks_scanned += 1;
                    retry_count = 0; // Reset retry counter on success
                    wait_for_block_count = 0; // Reset wait counter on success

                    if !events.is_empty() {
                        self.events_found += events.len() as u64;
                        let system_count = events.iter().filter(|e| !matches!(e, ContractEvent::ExecutionRequested(_))).count();
                        if system_count > 0 {
                            self.system_events_found += system_count as u64;
                        }
                        info!(
                            "📦 Block {}: Found {} events ({} execution, {} system) — total: {} events in {} blocks",
                            self.current_block,
                            events.len(),
                            events.len() - system_count,
                            system_count,
                            self.events_found,
                            self.blocks_scanned
                        );
                    }

                    // Process found events
                    for event in events {
                        match event {
                            ContractEvent::ExecutionRequested(exec_event) => {
                                if let Err(e) = self.handle_execution_requested(exec_event).await {
                                    error!("Failed to handle execution_requested event: {}", e);
                                }
                            }
                            ContractEvent::ProjectStorageCleanup(cleanup_event) => {
                                if let Err(e) = self.handle_project_storage_cleanup(cleanup_event).await {
                                    error!("Failed to handle project_storage_cleanup event: {}", e);
                                }
                            }
                            ContractEvent::ProjectTransferred(transfer_event) => {
                                if let Err(e) = self.handle_project_transferred(transfer_event).await {
                                    error!("Failed to handle project_transferred event: {}", e);
                                }
                            }
                            ContractEvent::TopUpPaymentKey(topup_event) => {
                                if let Err(e) = self.handle_topup_payment_key(topup_event).await {
                                    error!("Failed to handle topup_payment_key event: {}", e);
                                }
                            }
                            ContractEvent::DeletePaymentKey(delete_event) => {
                                if let Err(e) = self.handle_delete_payment_key(delete_event).await {
                                    error!("Failed to handle delete_payment_key event: {}", e);
                                }
                            }
                            ContractEvent::WalletPolicyUpdated(event) => {
                                if let Err(e) = self.handle_wallet_policy_updated(event).await {
                                    error!("Failed to handle wallet_policy_updated event: {}", e);
                                }
                            }
                            ContractEvent::WalletPolicyDeleted(event) => {
                                if let Err(e) = self.handle_wallet_policy_deleted(event).await {
                                    error!("Failed to handle wallet_policy_deleted event: {}", e);
                                }
                            }
                            ContractEvent::WalletFrozenChanged(event) => {
                                if let Err(e) = self.handle_wallet_frozen_changed(event).await {
                                    error!("Failed to handle wallet_frozen_changed event: {}", e);
                                }
                            }
                            ContractEvent::SubscriptionPurchased(event) => {
                                // The one event where dropping the relay costs a
                                // customer money. Their transaction has already
                                // succeeded and the contract has already kept the
                                // payment: there is no yield left to time out, so
                                // if this does not reach the coordinator the
                                // allowance is simply never granted, and nobody
                                // finds out but the customer.
                                if let Err(e) = self.handle_subscription_purchased(event).await {
                                    if crate::api_client::TerminalRelay::is_terminal(&e) {
                                        error!(
                                            "Subscription purchase REFUSED by the coordinator, \
                                             giving up on it: {:#}",
                                            e
                                        );
                                    } else {
                                        error!(
                                            "Subscription purchase could not be relayed, \
                                             holding block {}: {:#}",
                                            self.current_block, e
                                        );
                                        hold_for_relay = true;
                                    }
                                }
                            }
                        }
                    }

                    // Hold the block when a money event could not be relayed.
                    //
                    // Re-processing a block is safe: a task is keyed by
                    // `request_id`, a top-up by `data_id`, a purchase by its
                    // receipt — every relay in here is idempotent, which is why
                    // the runbook already prescribes a re-scan as the recovery.
                    // So the cheap move is to stay put until the coordinator is
                    // back, rather than walk past a payment that has already
                    // been taken.
                    //
                    // Bounded, because a transient failure that is not transient
                    // must not stop the monitor forever: after enough attempts
                    // the block moves on and the loss is at least a loud line
                    // with the receipt in it.
                    if hold_for_relay {
                        relay_retry_count += 1;
                        if relay_retry_count < MAX_RELAY_RETRIES {
                            // The same pause the loop already takes for a block
                            // it could not scan — this is the same situation:
                            // something downstream is briefly unavailable.
                            sleep(Duration::from_secs(5)).await;
                            continue;
                        }
                        error!(
                            "Giving up on block {} after {} failed relay attempts. A \
                             subscription purchase in it has NOT been granted — replay its \
                             receipt to /internal/subscription-purchased.",
                            self.current_block, relay_retry_count
                        );
                    }
                    relay_retry_count = 0;

                    // Move to next block
                    self.current_block += 1;
                    self.shared_block_height.store(self.current_block, Ordering::Relaxed);

                    // Log progress every 100 blocks
                    if self.blocks_scanned % 100 == 0 {
                        info!(
                            "📊 Progress: Scanned blocks {}-{} ({} blocks, {} events: {} execution, {} system)",
                            start_block,
                            self.current_block - 1,
                            self.blocks_scanned,
                            self.events_found,
                            self.events_found - self.system_events_found,
                            self.system_events_found
                        );
                    }

                    // Brief pause between blocks (if configured)
                    if self.scan_interval_ms > 0 {
                        sleep(Duration::from_millis(self.scan_interval_ms)).await;
                    }
                }
                Err(e) => {
                    // Check if this is a "block not indexed" error - should wait, not skip
                    if e.downcast_ref::<BlockNotIndexedError>().is_some() {
                        // Block not indexed by neardata yet - wait and retry
                        // DO NOT increment current_block here - that was the bug!
                        wait_for_block_count += 1;
                        if wait_for_block_count == 1 || wait_for_block_count % 50 == 0 {
                            info!(
                                "⏳ Waiting for block {} (not indexed by neardata yet)",
                                self.current_block
                            );
                        }
                        // Wait 200ms before retry
                        sleep(Duration::from_millis(200)).await;
                        continue;
                    }

                    // Regular error - use retry logic
                    retry_count += 1;
                    error!(
                        "❌ Error scanning block {} (attempt {}/{}): {}",
                        self.current_block, retry_count, MAX_RETRIES, e
                    );

                    if retry_count >= MAX_RETRIES {
                        warn!(
                            "⚠️  Skipping block {} after {} failed attempts",
                            self.current_block, MAX_RETRIES
                        );
                        // Skip to next block
                        self.current_block += 1;
                        retry_count = 0;
                        sleep(Duration::from_secs(1)).await;
                    } else {
                        // Wait before retrying same block
                        sleep(Duration::from_secs(5)).await;
                    }
                }
            }
        }
    }

    /// Scan a single block for contract events
    async fn scan_single_block(&self, block_id: u64) -> Result<Vec<ContractEvent>> {
        let block_data = self.load_block(block_id).await?;

        if block_data.shards.is_none() {
            return Ok(vec![]);
        }

        let events = self.process_shards(&block_data.shards.unwrap(), block_id)?;

        if !events.is_empty() {
            info!(
                "Block {}: found {} contract events",
                block_id,
                events.len()
            );
        }

        Ok(events)
    }

    /// Load block data from neardata.xyz API
    async fn load_block(&self, block_id: u64) -> Result<BlockData> {
        let url = self.neardata_api_url.replace("{block_id}", &block_id.to_string());

        let response = self
            .http_client
            .get(&url)
            .send()
            .await
            .context("Failed to fetch block")?;

        match response.status() {
            reqwest::StatusCode::OK => {
                // First, get the response body as a raw string.
                // This helps in debugging if JSON parsing fails later.
                let response_text = response
                    .text()
                    .await
                    .context("Failed to read response body as text")?;

                // Handle null response - block doesn't exist in NEAR (was skipped)
                // Per neardata docs: "If the block doesn't exist it returns null"
                // neardata waits for blocks close to finalized, so null = truly doesn't exist
                if response_text.trim() == "null" {
                    info!("⏭️  Block {} doesn't exist (skipped in NEAR consensus)", block_id);
                    return Ok(BlockData { shards: None });
                }

                // Now, try to parse the string. If it fails, the error
                // message can include the raw text that caused the issue.
                let block_data: BlockData = serde_json::from_str(&response_text)
                    .with_context(|| format!("Failed to parse block data from JSON. Raw text (truncated): '{}'",
                        crate::near_client::head(&response_text, 200)))?;

                // The rest of your logic remains unchanged.
                let shard_count = block_data.shards.as_ref().map(|s| s.len()).unwrap_or(0);
                if self.blocks_scanned % 10 == 0 {
                    // Assuming `block_id` is available in this scope.
                    info!("📥 Block {}: Fetched from neardata ({} shards)", block_id, shard_count);
                }

                Ok(block_data)
            }
            reqwest::StatusCode::NOT_FOUND => {
                // Block not indexed yet - return special error so main loop waits
                // No logging here to avoid spam when waiting for new blocks
                return Err(BlockNotIndexedError { block_id }.into());
            }
            status => {
                anyhow::bail!("HTTP {} for block {}", status, block_id);
            }
        }
    }

    /// Process shards from block data
    fn process_shards(
        &self,
        shards: &[ShardData],
        block_height: u64,
    ) -> Result<Vec<ContractEvent>> {
        let mut events = Vec::new();
        let mut receipts_checked = 0;
        let mut contract_receipts = 0;

        // Process receipt execution outcomes
        for shard in shards {
            if let Some(receipt_outcomes) = &shard.receipt_execution_outcomes {
                for outcome in receipt_outcomes {
                    receipts_checked += 1;

                    // Extract neardata fields
                    let receipt_id = outcome.receipt.as_ref()
                        .and_then(|r| r.receipt_id.clone());
                    let predecessor_id = outcome.receipt.as_ref()
                        .and_then(|r| r.predecessor_id.clone());
                    let action_details = outcome.receipt.as_ref()
                        .and_then(|r| r.receipt.as_ref())
                        .and_then(|action| action.action.as_ref());
                    let signer_id = action_details.and_then(|details| details.signer_id.clone());
                    let signer_public_key = action_details.and_then(|details| details.signer_public_key.clone());
                    let gas_burnt = outcome.execution_outcome.as_ref()
                        .and_then(|exec| exec.outcome.as_ref())
                        .and_then(|o| o.gas_burnt);
                    let transaction_hash = outcome.tx_hash.clone();

                    // Check receiver_id matches our contract
                    let is_our_contract = if let Some(receipt) = &outcome.receipt {
                        if let Some(receiver_id) = &receipt.receiver_id {
                            if receiver_id == self.contract_id.as_str() {
                                contract_receipts += 1;
                                true
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    } else {
                        false
                    };

                    if !is_our_contract {
                        continue;
                    }

                    // Only a committed receipt's logs are events: a failed one
                    // keeps its logs while the chain rolled back everything
                    // they announce.
                    if let Err(reason) = receipt_committed(outcome) {
                        let event_logs = outcome
                            .execution_outcome
                            .as_ref()
                            .and_then(|exec| exec.outcome.as_ref())
                            .and_then(|o| o.logs.as_ref())
                            .map(|logs| logs.iter().filter(|l| event_json_payload(l).is_some()).count())
                            .unwrap_or(0);
                        if event_logs > 0 {
                            warn!(
                                "⛔ Block {}: receipt {:?} of {} did not commit ({}); {} EVENT_JSON log(s) ignored",
                                block_height, receipt_id, self.contract_id, reason, event_logs
                            );
                        }
                        continue;
                    }

                    // Process logs from our contract
                    if let Some(execution) = &outcome.execution_outcome {
                        if let Some(outcome_data) = &execution.outcome {
                            if let Some(logs) = &outcome_data.logs {
                                if !logs.is_empty() {
                                    let event_logs: Vec<_> = logs.iter()
                                        .filter(|l| event_json_payload(l).is_some())
                                        .collect();
                                    if !event_logs.is_empty() {
                                        info!(
                                            "📋 Block {}: contract receipt has {} EVENT_JSON logs",
                                            block_height, event_logs.len()
                                        );
                                    }
                                }
                                for log in logs {
                                    if let Some(mut event) =
                                        self.process_log(log, block_height)
                                    {
                                        // Add transaction metadata only for ExecutionRequested events
                                        if let ContractEvent::ExecutionRequested(ref mut exec_event) = event {
                                            exec_event.transaction_hash = transaction_hash.clone();
                                            exec_event.receipt_id = receipt_id.clone();
                                            exec_event.predecessor_id = predecessor_id.clone();
                                            exec_event.signer_id = signer_id.clone();
                                            exec_event.signer_public_key = signer_public_key.clone();
                                            exec_event.gas_burnt = gas_burnt;
                                        }
                                        // A purchase is granted at most once, and the receipt is
                                        // what decides. It is not in the log — it belongs to the
                                        // receipt that produced it — so it is attached here.
                                        if let ContractEvent::SubscriptionPurchased(ref mut buy) = event {
                                            buy.receipt_id = receipt_id.clone();
                                        }
                                        events.push(event);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Log detailed stats every 10 blocks if we found receipts for our contract
        if contract_receipts > 0 || (self.blocks_scanned % 50 == 0 && receipts_checked > 0) {
            info!(
                "🔍 Block {}: Checked {} receipts, {} for contract {}, {} events",
                block_height,
                receipts_checked,
                contract_receipts,
                self.contract_id,
                events.len()
            );
        }

        Ok(events)
    }

    /// Process individual log entry - handles multiple event types
    fn process_log(&self, log: &str, block_height: u64) -> Option<ContractEvent> {
        let event_json_str = event_json_payload(log)?;

        // Parse JSON
        let event: Value = serde_json::from_str(event_json_str).ok()?;

        // Check standard name
        let standard = event.get("standard")?.as_str()?;
        if standard != self.event_filter_standard_name {
            return None;
        }

        // Check min version (>= comparison)
        if let Some(required_version) = self.event_filter_min_version {
            let event_version_str = event.get("version").and_then(|v| v.as_str());
            match event_version_str.and_then(|v| Self::parse_semver(v)) {
                Some(actual_version) if Self::semver_gte(actual_version, required_version) => {}
                _ => return None,
            }
        }

        let event_name = event.get("event")?.as_str()?;
        let data_array = event.get("data")?.as_array()?;
        if data_array.is_empty() {
            return None;
        }

        // Handle different event types
        match event_name {
            "execution_requested" => {
                // Only process if matches the configured filter (for backwards compatibility)
                if event_name != self.event_filter_function_name {
                    return None;
                }

                let mut event_data: ExecutionRequestedEvent =
                    serde_json::from_value(data_array[0].clone()).ok()?;
                event_data.block_height = block_height;

                // Parse and validate request_data
                let mut request_data: RequestData = match serde_json::from_str(&event_data.request_data) {
                    Ok(data) => data,
                    Err(e) => {
                        error!(
                            "Failed to parse request_data JSON at block {}: {}. Raw: {}",
                            block_height, e, event_data.request_data
                        );
                        return None;
                    }
                };

                info!("request_data secrets_ref: {:?}", request_data.secrets_ref);

                if request_data.code_source.build_target().is_none() {
                    request_data.code_source.set_build_target("wasm32-wasi".to_string());
                    info!("⚠️  No build_target specified, defaulting to wasm32-wasi");
                } else {
                    info!("📦 build_target specified: {}", request_data.code_source.build_target().unwrap());
                }

                info!(
                    "✅ Found execution_requested event at block {}: request_id={} source={}",
                    block_height, request_data.request_id, request_data.code_source.display()
                );

                Some(ContractEvent::ExecutionRequested(event_data))
            }
            "system_event" => {
                // SystemEvent is wrapped: {"TopUpPaymentKey": {...}}, {"DeletePaymentKey": {...}}, or {"ProjectStorageCleanup": {...}}
                let system_event = &data_array[0];

                if let Some(topup_data) = system_event.get("TopUpPaymentKey") {
                    let event_data: TopUpPaymentKeyEvent =
                        serde_json::from_value(topup_data.clone()).ok()?;

                    info!(
                        "✅ Found system_event TopUpPaymentKey at block {}: owner={} nonce={} amount={}",
                        block_height, event_data.owner, event_data.nonce, event_data.amount
                    );

                    Some(ContractEvent::TopUpPaymentKey(event_data))
                } else if let Some(delete_data) = system_event.get("DeletePaymentKey") {
                    let event_data: DeletePaymentKeyEvent =
                        serde_json::from_value(delete_data.clone()).ok()?;

                    info!(
                        "✅ Found system_event DeletePaymentKey at block {}: owner={} nonce={}",
                        block_height, event_data.owner, event_data.nonce
                    );

                    Some(ContractEvent::DeletePaymentKey(event_data))
                } else if let Some(cleanup_data) = system_event.get("ProjectStorageCleanup") {
                    let mut event_data: ProjectStorageCleanupEvent =
                        serde_json::from_value(cleanup_data.clone()).ok()?;
                    event_data.block_height = block_height;

                    info!(
                        "✅ Found system_event ProjectStorageCleanup at block {}: project_id={} uuid={}",
                        block_height, event_data.project_id, event_data.project_uuid
                    );

                    Some(ContractEvent::ProjectStorageCleanup(event_data))
                } else if let Some(data) = system_event.get("ProjectTransferred") {
                    match serde_json::from_value::<ProjectTransferredEvent>(data.clone()) {
                        Ok(event_data) => {
                            info!(
                                "✅ Found system_event ProjectTransferred at block {}: {} -> {} uuid={}",
                                block_height,
                                event_data.old_project_id,
                                event_data.new_project_id,
                                event_data.project_uuid
                            );
                            Some(ContractEvent::ProjectTransferred(event_data))
                        }
                        Err(e) => {
                            error!(
                                "❌ Failed to parse ProjectTransferred at block {}: {}. Raw: {:?}",
                                block_height, e, data
                            );
                            None
                        }
                    }
                } else if let Some(data) = system_event.get("SubscriptionPurchased") {
                    match serde_json::from_value::<SubscriptionPurchasedEvent>(data.clone()) {
                        Ok(event_data) => {
                            info!(
                                "✅ Found system_event SubscriptionPurchased at block {}: owner={} nonce={} plan={} paid={}",
                                block_height,
                                event_data.owner,
                                event_data.nonce,
                                event_data.plan,
                                event_data.paid_usd
                            );
                            Some(ContractEvent::SubscriptionPurchased(event_data))
                        }
                        Err(e) => {
                            error!(
                                "❌ Failed to parse SubscriptionPurchased at block {}: {}. Raw: {:?}",
                                block_height, e, data
                            );
                            None
                        }
                    }
                } else if let Some(data) = system_event.get("WalletPolicyUpdated") {
                    match serde_json::from_value::<WalletPolicyUpdatedEvent>(data.clone()) {
                        Ok(event_data) => {
                            info!(
                                "✅ Found system_event WalletPolicyUpdated at block {}: wallet={} owner={}",
                                block_height, event_data.wallet_pubkey, event_data.owner
                            );
                            Some(ContractEvent::WalletPolicyUpdated(event_data))
                        }
                        Err(e) => {
                            error!(
                                "❌ Failed to parse WalletPolicyUpdated at block {}: {}. Raw: {:?}",
                                block_height, e, data
                            );
                            None
                        }
                    }
                } else if let Some(data) = system_event.get("WalletPolicyDeleted") {
                    match serde_json::from_value::<WalletPolicyDeletedEvent>(data.clone()) {
                        Ok(event_data) => {
                            info!(
                                "✅ Found system_event WalletPolicyDeleted at block {}: wallet={} owner={}",
                                block_height, event_data.wallet_pubkey, event_data.owner
                            );
                            Some(ContractEvent::WalletPolicyDeleted(event_data))
                        }
                        Err(e) => {
                            error!(
                                "❌ Failed to parse WalletPolicyDeleted at block {}: {}. Raw: {:?}",
                                block_height, e, data
                            );
                            None
                        }
                    }
                } else if let Some(data) = system_event.get("WalletFrozenChanged") {
                    match serde_json::from_value::<WalletFrozenChangedEvent>(data.clone()) {
                        Ok(event_data) => {
                            info!(
                                "✅ Found system_event WalletFrozenChanged at block {}: wallet={} frozen={}",
                                block_height, event_data.wallet_pubkey, event_data.frozen
                            );
                            Some(ContractEvent::WalletFrozenChanged(event_data))
                        }
                        Err(e) => {
                            error!(
                                "❌ Failed to parse WalletFrozenChanged at block {}: {}. Raw: {:?}",
                                block_height, e, data
                            );
                            None
                        }
                    }
                } else {
                    warn!("Unknown system_event type at block {}: {:?}", block_height, system_event);
                    None
                }
            }
            other => {
                info!(
                    "📨 Block {}: skipping unrecognized event type '{}'",
                    block_height, other
                );
                None
            }
        }
    }

    /// Handle execution_requested event by creating task in coordinator
    async fn handle_execution_requested(&self, event: ExecutionRequestedEvent) -> Result<()> {
        // Log raw event data for debugging
        tracing::debug!("📋 Raw request_data JSON: {}", event.request_data);

        // Parse the nested request_data JSON
        let request_data: RequestData = serde_json::from_str(&event.request_data)
            .context("Failed to parse request_data JSON")?;
        let raw_request: Value = serde_json::from_str(&event.request_data)
            .context("Failed to parse request_data JSON")?;

        // The event is run only as the chain holds it: the receipt that wrote
        // it was signed and sent by the accounts it names, and the pending
        // request under its id is this one, in the project it names.
        if let Some(why) = receipt_mismatch(&request_data, &event) {
            anyhow::bail!(
                "Refusing execution_requested for request_id={}: {}",
                request_data.request_id, why
            );
        }
        let (pending, viewed_at) = self
            .fetch_pending_request(request_data.request_id, event.block_height)
            .await?;
        let project_uuid_on_chain = match pending_project_id(&pending) {
            Some(project_id) => Some(
                self.fetch_project_uuid_at(project_id, viewed_at)
                    .await?
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "Refusing execution_requested for request_id={}: project {} does not exist at {}",
                            request_data.request_id, project_id, viewed_at
                        )
                    })?,
            ),
            None => None,
        };
        if let Some(why) = pending_request_mismatch(
            &raw_request,
            &event.data_id,
            &pending,
            project_uuid_on_chain.as_deref(),
        ) {
            anyhow::bail!(
                "Refusing execution_requested for request_id={}: {}",
                request_data.request_id, why
            );
        }

        info!(
            "Creating task for execution request: request_id={} source={} sender={} response_format={:?} project_uuid={:?} project_id={:?}",
            request_data.request_id,
            request_data.code_source.display(),
            request_data.sender_id,
            request_data.response_format,
            request_data.project_uuid,
            request_data.project_id
        );

        // Convert data_id Vec<u8> to hex string
        let data_id_hex = hex::encode(&event.data_id);

        // Build execution context
        let context = crate::api_client::ExecutionContext {
            sender_id: Some(request_data.sender_id.clone()),
            block_height: Some(event.block_height),
            block_timestamp: Some(event.timestamp),
            contract_id: Some(self.contract_id.to_string()),
            transaction_hash: event.transaction_hash.clone(),
            receipt_id: event.receipt_id.clone(),
            // The contract's own word on who called it, from the event it
            // wrote; the receipt's predecessor is the same account, read off
            // the feed, and stands in for an event that carries none.
            predecessor_id: request_data.predecessor_id.clone().or_else(|| event.predecessor_id.clone()),
            signer_public_key: event.signer_public_key.clone(),
            gas_burnt: event.gas_burnt,
        };

        // Convert code_source to api_client format
        let api_code_source = request_data.code_source.to_api_code_source();

        // Input too large for the event log is read from the pending request
        let input_data = if request_data.input_data_in_state {
            pending
                .get("input_data")
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "input_data field missing in ExecutionRequest for request_id={}",
                        request_data.request_id
                    )
                })?
        } else {
            request_data.input_data.clone()
        };

        // Create task in coordinator API
        let params = CreateTaskParams {
            request_id: request_data.request_id,
            data_id: data_id_hex.clone(),
            code_source: api_code_source,
            resource_limits: ApiResourceLimits {
                max_instructions: request_data.resource_limits.max_instructions,
                max_memory_mb: request_data.resource_limits.max_memory_mb,
                max_execution_seconds: request_data.resource_limits.max_execution_seconds,
            },
            input_data,
            secrets_ref: request_data.secrets_ref.clone(),
            response_format: request_data.response_format.clone(),
            context,
            user_account_id: Some(request_data.sender_id.clone()),
            near_payment_yocto: Some(request_data.payment.clone()),
            attached_usd: request_data.attached_usd.clone(),
            compile_only: request_data.compile_only,
            force_rebuild: request_data.force_rebuild,
            store_on_fastfs: request_data.store_on_fastfs,
            use_bound_identity: request_data.use_bound_identity,
            project_uuid: request_data.project_uuid.clone(),
            project_id: request_data.project_id.clone(),
        };

        info!("📤 Sending task to coordinator: project_uuid={:?} project_id={:?}",
            request_data.project_uuid, request_data.project_id);

        match self.api_client.create_task(params).await
        {
            Ok(Some(request_id)) => {
                info!("✅ Task created in coordinator: request_id={} data_id={}",
                    request_id, data_id_hex);
            }
            Ok(None) => {
                info!("ℹ️  Task already exists (duplicate): data_id={}", data_id_hex);
            }
            Err(e) => {
                error!(
                    "❌ Failed to create task: {}. data_id={} source={}",
                    e, data_id_hex, request_data.code_source.display()
                );
                return Err(e);
            }
        }

        Ok(())
    }

    /// Handle ProjectStorageCleanup event by creating task in coordinator
    ///
    /// The worker with execution capability will pick up this task and:
    /// 1. Call clear_project_storage on coordinator
    ///
    /// The relay is retried on a transport error or a 5xx — a 503 is a
    /// coordinator that cannot read the contract at the event's block yet. A
    /// 4xx is its decision, a 409 among them: the contract still holds the
    /// project, and nothing is deleted.
    async fn handle_project_storage_cleanup(&self, event: ProjectStorageCleanupEvent) -> Result<()> {
        info!(
            "🧹 Creating cleanup task for deleted project: project_id={} uuid={} block={}",
            event.project_id, event.project_uuid, event.block_height
        );

        match crate::api_client::retry_relay(
            "ProjectStorageCleanup relay",
            &crate::api_client::RELAY_RETRY_DELAYS,
            || {
                self.api_client.create_project_storage_cleanup_task(
                    &event.project_id,
                    &event.project_uuid,
                    event.block_height,
                )
            },
        )
        .await
        {
            Ok(Some(task_id)) => {
                info!(
                    "✅ Created ProjectStorageCleanup task: task_id={} uuid={}",
                    task_id, event.project_uuid
                );
                Ok(())
            }
            Ok(None) => {
                info!(
                    "⏭️ ProjectStorageCleanup task already exists for uuid={}",
                    event.project_uuid
                );
                Ok(())
            }
            Err(e) => {
                let refused = crate::api_client::TerminalRelay::is_terminal(&e);
                error!(
                    "❌ {} cleanup task for project uuid={} at block {}: {:#}",
                    if refused { "Coordinator refused the" } else { "Failed to create the" },
                    event.project_uuid, event.block_height, e
                );
                Err(e)
            }
        }
    }

    /// Handle ProjectTransferred event: the coordinator drops its cached
    /// name → uuid entries for both names, so the old name no longer resolves
    /// to the transferred project and the new one resolves from the contract.
    /// Retried on a transport error or a 5xx; a 4xx is final.
    async fn handle_project_transferred(&self, event: ProjectTransferredEvent) -> Result<()> {
        info!(
            "🔀 Project transferred: {} -> {} uuid={} ({} -> {})",
            event.old_project_id,
            event.new_project_id,
            event.project_uuid,
            event.old_owner,
            event.new_owner
        );

        let project_ids = [event.old_project_id.clone(), event.new_project_id.clone()];
        crate::api_client::retry_relay(
            "Project uuid cache invalidation",
            &crate::api_client::RELAY_RETRY_DELAYS,
            || self.api_client.invalidate_project_uuid_cache(&project_ids),
        )
        .await
        .with_context(|| {
            format!(
                "Failed to invalidate project uuid cache for {} and {}",
                event.old_project_id, event.new_project_id
            )
        })
    }

    /// Handle TopUpPaymentKey event by creating task in coordinator
    ///
    /// The worker will pick up this task and:
    /// 1. Decrypt current Payment Key data via keystore
    /// 2. Update balance (add topup amount)
    /// 3. Re-encrypt via keystore
    /// 4. Call promise_yield_resume on contract
    ///
    /// Special case: amount=0 means PaymentKey was just created (store_secrets).
    /// Worker will detect this and only initialize key in coordinator (no resume).
    async fn handle_topup_payment_key(&self, event: TopUpPaymentKeyEvent) -> Result<()> {
        info!(
            "💰 Processing TopUp event: owner={} nonce={} amount={}",
            event.owner, event.nonce, event.amount
        );

        // For amount=0 (PaymentKey creation), contract sends dummy data_id=[0;32]
        // Generate unique data_id from owner+nonce to avoid duplicate detection
        let data_id_hex = if event.amount == "0" {
            use sha2::{Sha256, Digest};
            let unique_key = format!("init:{}:{}", event.owner, event.nonce);
            hex::encode(Sha256::digest(unique_key.as_bytes()))
        } else {
            hex::encode(&event.data_id)
        };

        let params = crate::api_client::TopUpTaskData {
            data_id: data_id_hex.clone(),
            owner: event.owner.clone(),
            nonce: event.nonce,
            amount: event.amount.clone(),
            encrypted_data: event.encrypted_data,
        };

        match self.api_client.create_topup_task(params).await {
            Ok(Some(task_id)) => {
                info!(
                    "✅ TopUp task created: task_id={} data_id={} owner={} amount={}",
                    task_id, data_id_hex, event.owner, event.amount
                );
            }
            Ok(None) => {
                info!(
                    "ℹ️  TopUp task already exists (duplicate): data_id={}",
                    data_id_hex
                );
            }
            Err(e) => {
                error!(
                    "❌ Failed to create TopUp task: {}. data_id={} owner={}",
                    e, data_id_hex, event.owner
                );
                return Err(e);
            }
        }

        Ok(())
    }

    /// Handle DeletePaymentKey event by creating task in coordinator
    ///
    /// The worker will pick up this task and:
    /// 1. Delete payment key from coordinator PostgreSQL
    /// 2. Call resume_delete_payment_key on contract
    async fn handle_delete_payment_key(&self, event: DeletePaymentKeyEvent) -> Result<()> {
        info!(
            "🗑️ Processing DeletePaymentKey event: owner={} nonce={}",
            event.owner, event.nonce
        );

        // Convert data_id to hex string
        let data_id_hex = hex::encode(&event.data_id);

        let params = crate::api_client::DeletePaymentKeyTaskData {
            data_id: data_id_hex.clone(),
            owner: event.owner.clone(),
            nonce: event.nonce,
        };

        match self.api_client.create_delete_payment_key_task(params).await {
            Ok(Some(task_id)) => {
                info!(
                    "✅ DeletePaymentKey task created: task_id={} data_id={} owner={}",
                    task_id, data_id_hex, event.owner
                );
            }
            Ok(None) => {
                info!(
                    "ℹ️  DeletePaymentKey task already exists (duplicate): data_id={}",
                    data_id_hex
                );
            }
            Err(e) => {
                error!(
                    "❌ Failed to create DeletePaymentKey task: {}. data_id={} owner={}",
                    e, data_id_hex, event.owner
                );
                return Err(e);
            }
        }

        Ok(())
    }

    /// Handle SubscriptionPurchased — tell the coordinator to grant the allowance.
    ///
    /// The worker carries the fact and none of the meaning: what the plan is
    /// worth is the coordinator's, read from its own table. Relayed rather than
    /// applied here because the allowance lives in its database, not on chain.
    ///
    /// An event with no receipt id is NOT relayed. The receipt is what makes
    /// the grant idempotent, and a relay without one would grant again on every
    /// redelivery.
    async fn handle_subscription_purchased(&self, event: SubscriptionPurchasedEvent) -> Result<()> {
        let Some(receipt_id) = event.receipt_id.clone() else {
            anyhow::bail!(
                "SubscriptionPurchased without a receipt id (owner={} nonce={}): not relaying, \
                 because the receipt is what stops the allowance being granted twice",
                event.owner,
                event.nonce
            );
        };

        info!(
            "💳 Processing SubscriptionPurchased: owner={} nonce={} plan={} paid={} receipt={}",
            event.owner, event.nonce, event.plan, event.paid_usd, receipt_id
        );

        self.api_client
            .notify_subscription_purchased(
                &receipt_id,
                &event.owner,
                event.nonce,
                event.plan,
                &event.paid_usd,
                &event.payer,
            )
            .await
    }

    /// Handle WalletPolicyUpdated event — notify coordinator to sync authorized key hashes
    async fn handle_wallet_policy_updated(&self, event: WalletPolicyUpdatedEvent) -> Result<()> {
        info!(
            "🔑 Processing WalletPolicyUpdated: wallet={} owner={} frozen={}",
            event.wallet_pubkey, event.owner, event.frozen
        );

        self.api_client
            .notify_wallet_policy_updated(
                &event.wallet_pubkey,
                &event.owner,
                &event.encrypted_data,
                event.frozen,
            )
            .await
    }

    /// Handle WalletPolicyDeleted event — notify coordinator to remove wallet keys
    async fn handle_wallet_policy_deleted(&self, event: WalletPolicyDeletedEvent) -> Result<()> {
        info!(
            "🗑️ Processing WalletPolicyDeleted: wallet={} owner={}",
            event.wallet_pubkey, event.owner
        );

        self.api_client
            .notify_wallet_policy_deleted(&event.wallet_pubkey, &event.owner)
            .await
    }

    /// Handle WalletFrozenChanged event — notify coordinator to update freeze status
    async fn handle_wallet_frozen_changed(&self, event: WalletFrozenChangedEvent) -> Result<()> {
        info!(
            "🧊 Processing WalletFrozenChanged: wallet={} frozen={}",
            event.wallet_pubkey, event.frozen
        );

        self.api_client
            .notify_wallet_frozen_changed(&event.wallet_pubkey, &event.owner, event.frozen)
            .await
    }

    /// One view call of the contract at `at`: the parsed JSON answer and the
    /// height of the block the node answered at.
    async fn view_once(&self, method: &str, args: &Value, at: &BlockReference) -> Result<(Value, u64), ViewFailure> {
        let request = methods::query::RpcQueryRequest {
            block_reference: at.clone(),
            request: QueryRequest::CallFunction {
                account_id: self.contract_id.clone(),
                method_name: method.to_string(),
                args: args.to_string().into_bytes().into(),
            },
        };

        let response = self.rpc_client.call(request).await.map_err(classify_view_error)?;

        let result_bytes = match response.kind {
            near_jsonrpc_primitives::types::query::QueryResponseKind::CallResult(call_result) => {
                call_result.result
            }
            _ => return Err(ViewFailure::Final(format!("unexpected response kind for {}", method))),
        };

        let value = serde_json::from_slice(&result_bytes)
            .map_err(|e| ViewFailure::Final(format!("the {} answer does not parse: {}", method, e)))?;
        Ok((value, response.block_height))
    }

    /// [`Self::view_once`], asked again after each [`VIEW_RETRY_DELAYS`] pause
    /// while the failure is one a later attempt can get past.
    async fn view_retrying(&self, method: &str, args: &Value, at: &BlockReference) -> Result<(Value, u64), ViewFailure> {
        let mut delays = VIEW_RETRY_DELAYS.iter();
        loop {
            match self.view_once(method, args, at).await {
                Err(failure) if failure.is_retried() => match delays.next() {
                    Some(delay) => {
                        warn!("RPC view {} failed ({}), retrying in {:?}", method, failure, delay);
                        sleep(*delay).await;
                    }
                    None => return Err(failure),
                },
                answered => return answered,
            }
        }
    }

    /// A view of the contract as it stood at the end of `block_height`: the
    /// block the event was written in, so the answer is the state that block
    /// left, not one a later block changed.
    ///
    /// A node that does not serve that block — one still behind it after every
    /// retry, or one that has garbage-collected it — is asked at `final`
    /// instead, and the answer says so. A final block below `block_height` is
    /// a node that is behind, and no answer at all.
    async fn view_at(&self, method: &str, args: Value, block_height: u64) -> Result<(Value, ViewedAt)> {
        let at_block = BlockReference::BlockId(BlockId::Height(block_height));
        let why = match self.view_retrying(method, &args, &at_block).await {
            Ok((value, _)) => return Ok((value, ViewedAt::Block(block_height))),
            Err(ViewFailure::UnknownBlock(why) | ViewFailure::GarbageCollected(why)) => why,
            Err(failure) => anyhow::bail!("RPC view {} at block {} failed: {}", method, block_height, failure),
        };
        warn!(
            "RPC view {} at block {} is not served ({}); reading it at the final block",
            method, block_height, why
        );
        let (value, final_height) = self
            .view_final(method, &args)
            .await
            .with_context(|| format!("RPC view {} at block {} is not served ({})", method, block_height, why))?;
        if final_height < block_height {
            anyhow::bail!(
                "RPC view {} at block {} is not served ({}), and the node's final block {} is behind it",
                method, block_height, why, final_height
            );
        }
        Ok((value, ViewedAt::Final))
    }

    /// A view of the contract at the node's final block, and that block's height.
    async fn view_final(&self, method: &str, args: &Value) -> Result<(Value, u64)> {
        self.view_retrying(method, args, &BlockReference::Finality(Finality::Final))
            .await
            .map_err(|failure| anyhow::anyhow!("RPC view {} at the final block failed: {}", method, failure))
    }

    /// `get_request(request_id)` at the event's block. The contract stores the
    /// request in the same receipt that writes the event, so a genuine event
    /// always finds it there. Read at the final block instead (see
    /// [`Self::view_at`]), a request still pending is checked the same way,
    /// and one no longer there was resolved or timed out since the event.
    async fn fetch_pending_request(&self, request_id: u64, block_height: u64) -> Result<(Value, ViewedAt)> {
        let (request, at) = self
            .view_at("get_request", serde_json::json!({ "request_id": request_id }), block_height)
            .await?;
        if request.is_null() {
            match at {
                ViewedAt::Block(_) => anyhow::bail!(
                    "Refusing execution_requested for request_id={}: the contract holds no such pending request at block {}",
                    request_id, block_height
                ),
                ViewedAt::Final => anyhow::bail!(
                    "Dropping execution_requested for request_id={}: block {} is no longer served, and at the final block the request is no longer pending — it was resolved or timed out since",
                    request_id, block_height
                ),
            }
        }
        Ok((request, at))
    }

    /// The uuid of `project_id` where the pending request was read, `None`
    /// when no such project.
    async fn fetch_project_uuid_at(&self, project_id: &str, at: ViewedAt) -> Result<Option<String>> {
        let args = serde_json::json!({ "project_id": project_id });
        let project = match at {
            ViewedAt::Block(block_height) => self.view_at("get_project", args, block_height).await?.0,
            ViewedAt::Final => self.view_final("get_project", &args).await?.0,
        };
        Ok(project.get("uuid").and_then(|u| u.as_str()).map(str::to_string))
    }
}

/// The pauses between the attempts of one view of the contract: five attempts
/// within about thirty seconds — long enough for a node a block behind
/// neardata to catch up, or a rate limit to lift.
const VIEW_RETRY_DELAYS: [Duration; 4] = [
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
    Duration::from_secs(16),
];

/// Where a view of the contract was read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ViewedAt {
    /// At the event's own block.
    Block(u64),
    /// At the node's final block, the event's block being no longer served.
    Final,
}

impl std::fmt::Display for ViewedAt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ViewedAt::Block(height) => write!(f, "block {}", height),
            ViewedAt::Final => write!(f, "the final block"),
        }
    }
}

/// Why a view of the contract got no answer. Every message is free of the
/// RPC URL, which can carry an API key.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ViewFailure {
    /// The node could not answer now: unreachable, rate-limited, overloaded,
    /// timed out, or not yet synced. Asked again.
    Unavailable(String),
    /// The node has not seen the block: it is behind the block, or has
    /// dropped it. Asked again; still unknown, read at the final block.
    UnknownBlock(String),
    /// The node has garbage-collected the block. Read at the final block.
    GarbageCollected(String),
    /// Any other answer, which asking again does not change.
    Final(String),
}

impl ViewFailure {
    fn is_retried(&self) -> bool {
        matches!(self, ViewFailure::Unavailable(_) | ViewFailure::UnknownBlock(_))
    }
}

impl std::fmt::Display for ViewFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ViewFailure::Unavailable(why)
            | ViewFailure::UnknownBlock(why)
            | ViewFailure::GarbageCollected(why)
            | ViewFailure::Final(why) => f.write_str(why),
        }
    }
}

/// What a failed query call means for the view. Takes the error by value so
/// a transport error's URL can be stripped before it is formatted.
fn classify_view_error(
    err: near_jsonrpc_client::errors::JsonRpcError<near_jsonrpc_primitives::types::query::RpcQueryError>,
) -> ViewFailure {
    use near_jsonrpc_client::errors::{
        JsonRpcError, JsonRpcServerError, JsonRpcServerResponseStatusError as Status,
        JsonRpcTransportRecvError as Recv, JsonRpcTransportSendError as Send, RpcTransportError,
    };
    use near_jsonrpc_primitives::types::query::RpcQueryError as Query;

    match err {
        JsonRpcError::TransportError(RpcTransportError::SendError(Send::PayloadSendError(e))) => {
            ViewFailure::Unavailable(format!("sending the request failed: {}", e.without_url()))
        }
        JsonRpcError::TransportError(RpcTransportError::SendError(e @ Send::PayloadSerializeError(_))) => {
            ViewFailure::Final(e.to_string())
        }
        JsonRpcError::TransportError(RpcTransportError::RecvError(Recv::PayloadRecvError(e))) => {
            ViewFailure::Unavailable(format!("reading the response failed: {}", e.without_url()))
        }
        // A body that is not a JSON-RPC response: a proxy's error page, a
        // truncated answer.
        JsonRpcError::TransportError(RpcTransportError::RecvError(e)) => ViewFailure::Unavailable(e.to_string()),
        JsonRpcError::ServerError(JsonRpcServerError::ResponseStatusError(status)) => match status {
            Status::TooManyRequests | Status::ServiceUnavailable | Status::TimeoutError => {
                ViewFailure::Unavailable(status.to_string())
            }
            Status::Unexpected { status: code } if code.is_server_error() => {
                ViewFailure::Unavailable(format!("the node answered HTTP {}", code))
            }
            Status::Unauthorized | Status::BadRequest | Status::Unexpected { .. } => {
                ViewFailure::Final(status.to_string())
            }
        },
        JsonRpcError::ServerError(e @ JsonRpcServerError::InternalError { .. }) => {
            ViewFailure::Unavailable(e.to_string())
        }
        JsonRpcError::ServerError(e @ JsonRpcServerError::NonContextualError(_)) => {
            ViewFailure::Unavailable(e.to_string())
        }
        JsonRpcError::ServerError(e @ JsonRpcServerError::RequestValidationError(_)) => {
            ViewFailure::Final(e.to_string())
        }
        JsonRpcError::ServerError(JsonRpcServerError::HandlerError(query)) => match query {
            Query::UnknownBlock { .. } => ViewFailure::UnknownBlock(query.to_string()),
            Query::GarbageCollectedBlock { .. } => ViewFailure::GarbageCollected(query.to_string()),
            Query::NoSyncedBlocks | Query::UnavailableShard { .. } | Query::InternalError { .. } => {
                ViewFailure::Unavailable(query.to_string())
            }
            Query::InvalidAccount { .. }
            | Query::UnknownAccount { .. }
            | Query::NoContractCode { .. }
            | Query::TooLargeContractState { .. }
            | Query::UnknownAccessKey { .. }
            | Query::UnknownGasKey { .. }
            | Query::ContractExecutionError { .. }
            | Query::NoGlobalContractCode { .. } => ViewFailure::Final(query.to_string()),
        },
    }
}

/// Why the receipt that wrote an `execution_requested` event cannot have been
/// the contract's `request_execution` for the accounts the event names, or
/// `None`. The receipt's signer and predecessor come from the block, not the
/// log: `request_execution` writes `env::signer_account_id()` as `sender_id`
/// and `env::predecessor_account_id()` as `predecessor_id`, and those are the
/// receipt's own.
fn receipt_mismatch(request: &RequestData, event: &ExecutionRequestedEvent) -> Option<String> {
    match event.signer_id.as_deref() {
        None => return Some("the receipt that wrote the event carries no signer".to_string()),
        Some(signer) if signer != request.sender_id => {
            return Some(format!(
                "the event names sender {} but the receipt was signed by {}",
                request.sender_id, signer
            ))
        }
        Some(_) => {}
    }
    if let Some(named) = request.predecessor_id.as_deref() {
        match event.predecessor_id.as_deref() {
            Some(actual) if actual == named => {}
            actual => {
                return Some(format!(
                    "the event names predecessor {} but the receipt came from {:?}",
                    named, actual
                ))
            }
        }
    }
    None
}

/// The project a pending request runs, from its `execution_source`.
fn pending_project_id(pending: &Value) -> Option<&str> {
    pending
        .get("execution_source")?
        .get("Project")?
        .get("project_id")?
        .as_str()
}

/// Why an `execution_requested` event is not the pending request the contract
/// holds under its id, or `None`. `raw` is the event's `request_data`,
/// `pending` is `get_request(request_id)` at the event's block, and
/// `project_uuid_on_chain` the uuid of the project `pending` runs (`None` when
/// it runs code given inline). Every field the run is decided by and the
/// contract keeps is compared; the uuid, which the contract does not keep on
/// the request, is compared with the project's.
fn pending_request_mismatch(
    raw: &Value,
    data_id: &[u8],
    pending: &Value,
    project_uuid_on_chain: Option<&str>,
) -> Option<String> {
    let null = Value::Null;
    let field = |v: &Value, k: &str| -> Value { v.get(k).cloned().unwrap_or(Value::Null) };

    let pending_data_id: Option<Vec<u8>> = serde_json::from_value(field(pending, "data_id")).ok();
    if pending_data_id.as_deref() != Some(data_id) {
        return Some("its data_id is not the pending request's".to_string());
    }
    if field(raw, "request_id") != field(pending, "request_id") {
        return Some("its request_id is not the pending request's".to_string());
    }
    // The contract keeps the predecessor as the request's `sender_id`.
    if let Some(p) = raw.get("predecessor_id").filter(|p| !p.is_null()) {
        if Some(p) != pending.get("sender_id") {
            return Some("its predecessor is not the pending request's".to_string());
        }
    }
    for (event_key, pending_key) in [
        ("code_source", "resolved_source"),
        ("secrets_ref", "secrets_ref"),
        ("response_format", "response_format"),
        ("resource_limits", "resource_limits"),
    ] {
        if field(raw, event_key) != field(pending, pending_key) {
            return Some(format!("its {} is not the pending request's", event_key));
        }
    }
    if !raw.get("input_data_in_state").and_then(|v| v.as_bool()).unwrap_or(false) {
        let pending_input = pending.get("input_data").unwrap_or(&null).as_str().unwrap_or("");
        if raw.get("input_data").and_then(|v| v.as_str()).unwrap_or("") != pending_input {
            return Some("its input_data is not the pending request's".to_string());
        }
    }
    // `attached_usd` is a U128 string in the event and a number on the request.
    let event_usd = raw.get("attached_usd").and_then(|v| v.as_str()).unwrap_or("0");
    let pending_usd = pending.get("attached_usd").and_then(|v| v.as_u64()).map(|v| v.to_string());
    if pending_usd.as_deref() != Some(event_usd) {
        return Some("its attached_usd is not the pending request's".to_string());
    }
    let event_project = raw.get("project_id").and_then(|v| v.as_str());
    if event_project != pending_project_id(pending) {
        return Some("its project_id is not the pending request's".to_string());
    }
    let event_uuid = raw.get("project_uuid").and_then(|v| v.as_str());
    if event_uuid != project_uuid_on_chain {
        return Some(format!(
            "it names project_uuid {:?} but the request runs in {:?}",
            event_uuid, project_uuid_on_chain
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLEANUP_EVENT: &str = r#"EVENT_JSON:{"standard":"near-outlayer","version":"1.0.0","event":"system_event","data":[{"ProjectStorageCleanup":{"project_id":"victim.near/app","project_uuid":"p0000000000000001","timestamp":1}}]}"#;

    #[test]
    fn a_log_starting_with_the_prefix_is_an_event() {
        assert_eq!(
            event_json_payload(CLEANUP_EVENT),
            Some(&CLEANUP_EVENT[EVENT_JSON_PREFIX.len()..])
        );
    }

    /// The contract logs caller-chosen text after its own words, e.g.
    /// `Project created: …, version={hash}`; a hash that reads `EVENT_JSON:{…}`
    /// must not become an event.
    #[test]
    fn text_before_the_prefix_is_not_an_event() {
        let forged = format!(
            "Project created: id=eve.near/x, uuid=p0000000000000009, owner=eve.near, version={}",
            CLEANUP_EVENT
        );
        assert!(event_json_payload(&forged).is_none());
        assert!(event_json_payload(&format!(" {}", CLEANUP_EVENT)).is_none());
        assert!(event_json_payload(&format!("x{}", CLEANUP_EVENT)).is_none());
    }

    /// A line break cannot start a second event inside one log, whether it
    /// comes before the prefix or after a genuine-looking one.
    #[test]
    fn a_line_break_cannot_smuggle_an_event() {
        let before = format!("Active version changed: project=eve.near/x, version=a\n{}", CLEANUP_EVENT);
        assert!(event_json_payload(&before).is_none());
        let crlf = format!("Execution failed: boom\r\n{}", CLEANUP_EVENT);
        assert!(event_json_payload(&crlf).is_none());
        let after = format!("{}\n{}", CLEANUP_EVENT, CLEANUP_EVENT);
        assert!(event_json_payload(&after).is_none());
    }

    #[test]
    fn the_prefix_is_case_sensitive_and_exact() {
        assert!(event_json_payload(&CLEANUP_EVENT.replacen("EVENT_JSON:", "event_json:", 1)).is_none());
        assert!(event_json_payload(&CLEANUP_EVENT.replacen("EVENT_JSON:", "EVENT_JSON :", 1)).is_none());
    }

    /// The whole path, as a block's log reaches it: the contract's own event
    /// is taken, the same event behind a version key is not.
    #[test]
    fn process_log_takes_the_contracts_event_and_ignores_a_forged_one() {
        let m = parsing_monitor();
        match m.process_log(CLEANUP_EVENT, 7) {
            Some(ContractEvent::ProjectStorageCleanup(e)) => {
                assert_eq!(e.project_uuid, "p0000000000000001");
                // The block comes from the block, for the coordinator to check the deletion at.
                assert_eq!(e.block_height, 7);
            }
            other => panic!("expected ProjectStorageCleanup, got {other:?}"),
        }
        for forged in [
            format!("Project created: id=eve.near/x, uuid=p0000000000000009, owner=eve.near, version={CLEANUP_EVENT}"),
            format!("Active version changed: project=eve.near/x, version={CLEANUP_EVENT}"),
            format!("Version added: project=eve.near/x, version=a\n{CLEANUP_EVENT}"),
        ] {
            assert!(m.process_log(&forged, 7).is_none(), "{forged}");
        }
    }

    /// The status shapes a live neardata block carries (mainnet 217337399).
    #[test]
    fn execution_status_parses_the_shapes_neardata_serves() {
        let parse = |v: Value| serde_json::from_value::<ExecutionStatus>(v).unwrap();
        assert!(matches!(parse(serde_json::json!({"SuccessValue": ""})), ExecutionStatus::SuccessValue(v) if v.is_empty()));
        assert!(matches!(
            parse(serde_json::json!({"SuccessReceiptId": "5RnPtNhLEjY7T8WzLckfgCfnXugejztMvaKsWw15N6Zq"})),
            ExecutionStatus::SuccessReceiptId(_)
        ));
        assert!(matches!(
            parse(serde_json::json!({"Failure": {"ActionError": {"index": 0, "kind": {"FunctionCallError": {"ExecutionError": "Smart contract panicked: boom"}}}}})),
            ExecutionStatus::Failure(_)
        ));
        assert!(matches!(parse(serde_json::json!("Unknown")), ExecutionStatus::Unknown));
        assert!(serde_json::from_value::<ExecutionStatus>(serde_json::json!({"Whatever": 1})).is_err());
    }

    /// One receipt as neardata lists it in `receipt_execution_outcomes`.
    /// `status` `None` leaves the field out altogether.
    fn receipt_json(receiver: &str, id: &str, logs: &[&str], status: Option<Value>) -> Value {
        let mut outcome = serde_json::json!({
            "logs": logs,
            "receipt_ids": [],
            "gas_burnt": 2_000_000_000_000u64,
            "tokens_burnt": "200000000000000000000",
            "executor_id": receiver,
        });
        if let Some(status) = status {
            outcome["status"] = status;
        }
        serde_json::json!({
            "receipt": {
                "predecessor_id": "alice.testnet",
                "receiver_id": receiver,
                "receipt_id": id,
                "receipt": {"Action": {
                    "signer_id": "alice.testnet",
                    "signer_public_key": "ed25519:11111111111111111111111111111111",
                    "gas_price": "100000000",
                    "output_data_receivers": [],
                    "input_data_ids": [],
                    "actions": []
                }}
            },
            "execution_outcome": {"id": id, "outcome": outcome, "block_hash": "11111111111111111111111111111111", "proof": []},
            "tx_hash": "11111111111111111111111111111111"
        })
    }

    fn cleanup_event(uuid: &str) -> String {
        CLEANUP_EVENT.replace("p0000000000000001", uuid)
    }

    fn cleaned_uuids(events: &[ContractEvent]) -> Vec<String> {
        events
            .iter()
            .map(|e| match e {
                ContractEvent::ProjectStorageCleanup(c) => c.project_uuid.clone(),
                other => panic!("unexpected event {other:?}"),
            })
            .collect()
    }

    /// A block holding the contract's receipts in every status neardata can
    /// report: only the two that committed yield events. The failed receipt
    /// carries the very same event log — the case of a purchase whose
    /// `ft_on_transfer` ran out of gas after its emit and was refunded.
    #[test]
    fn only_a_committed_receipts_logs_are_events() {
        let contract = "outlayer.testnet";
        let failure = serde_json::json!({"Failure": {"ActionError": {"index": 0, "kind": {"FunctionCallError": {"ExecutionError": "Exceeded the prepaid gas."}}}}});
        let block: BlockData = serde_json::from_value(serde_json::json!({
            "shards": [
                {"receipt_execution_outcomes": [
                    receipt_json(contract, "r1", &[&cleanup_event("p0000000000000001")], Some(serde_json::json!({"SuccessValue": ""}))),
                    receipt_json(contract, "r2", &[&cleanup_event("p0000000000000002")], Some(serde_json::json!({"SuccessReceiptId": "5RnPtNhLEjY7T8WzLckfgCfnXugejztMvaKsWw15N6Zq"}))),
                    receipt_json(contract, "r3", &["Purchasing a subscription", &cleanup_event("p0000000000000003")], Some(failure)),
                    receipt_json(contract, "r4", &[&cleanup_event("p0000000000000004")], Some(serde_json::json!("Unknown"))),
                    receipt_json(contract, "r5", &[&cleanup_event("p0000000000000005")], None),
                    receipt_json(contract, "r6", &[&cleanup_event("p0000000000000006")], Some(serde_json::json!({"Whatever": 1}))),
                ]},
                {"receipt_execution_outcomes": [
                    // Another contract's committed receipt with the same log: not ours.
                    receipt_json("other.testnet", "r7", &[&cleanup_event("p0000000000000007")], Some(serde_json::json!({"SuccessValue": ""}))),
                    receipt_json(contract, "r8", &[&cleanup_event("p0000000000000008")], Some(serde_json::json!({"SuccessValue": "dHJ1ZQ=="}))),
                ]},
            ]
        }))
        .unwrap();
        let events = parsing_monitor().process_shards(block.shards.as_deref().unwrap(), 7).unwrap();
        assert_eq!(
            cleaned_uuids(&events),
            ["p0000000000000001", "p0000000000000002", "p0000000000000008"]
        );
    }

    /// A receipt whose execution outcome is missing has nothing on chain.
    #[test]
    fn a_receipt_without_an_outcome_is_not_committed() {
        let mut receipt = receipt_json("outlayer.testnet", "r1", &[], Some(serde_json::json!({"SuccessValue": ""})));
        receipt.as_object_mut().unwrap().remove("execution_outcome");
        let parsed: ReceiptExecutionOutcome = serde_json::from_value(receipt).unwrap();
        assert_eq!(receipt_committed(&parsed), Err("no execution outcome".to_string()));
    }

    const DATA_ID: [u8; 32] = [7; 32];

    /// A request as `request_execution` writes it: the event's `request_data`
    /// and the pending request `get_request` returns for it.
    fn genuine() -> (Value, Value) {
        let raw = serde_json::json!({
            "request_id": 5,
            "sender_id": "alice.near",
            "predecessor_id": "alice.near",
            "code_source": {"GitHub": {"repo": "github.com/alice/app", "commit": "main", "build_target": null}},
            "resource_limits": {"max_instructions": 1000, "max_memory_mb": 128, "max_execution_seconds": 10},
            "input_data": "{\"x\":1}",
            "input_data_in_state": false,
            "secrets_ref": {"profile": "default", "account_id": "alice.near"},
            "response_format": "Text",
            "payment": "100",
            "attached_usd": "250000",
            "timestamp": 1,
            "compile_only": false,
            "force_rebuild": false,
            "store_on_fastfs": false,
            "use_bound_identity": false,
            "project_uuid": "p0000000000000003",
            "project_id": "alice.near/app"
        });
        let pending = serde_json::json!({
            "request_id": 5,
            "data_id": DATA_ID.to_vec(),
            "sender_id": "alice.near",
            "execution_source": {"Project": {"project_id": "alice.near/app", "version_key": null}},
            "resolved_source": {"GitHub": {"repo": "github.com/alice/app", "commit": "main", "build_target": null}},
            "resource_limits": {"max_instructions": 1000, "max_memory_mb": 128, "max_execution_seconds": 10},
            "payment": 100,
            "timestamp": 1,
            "secrets_ref": {"profile": "default", "account_id": "alice.near"},
            "response_format": "Text",
            "input_data": "{\"x\":1}",
            "payer_account_id": "alice.near",
            "attached_usd": 250000,
            "pending_output": null,
            "output_submitted": false
        });
        (raw, pending)
    }

    fn event_for(raw: &Value, signer: Option<&str>, predecessor: Option<&str>) -> ExecutionRequestedEvent {
        ExecutionRequestedEvent {
            request_data: raw.to_string(),
            data_id: DATA_ID.to_vec(),
            timestamp: 1,
            block_height: 9,
            transaction_hash: None,
            receipt_id: None,
            predecessor_id: predecessor.map(str::to_string),
            signer_id: signer.map(str::to_string),
            signer_public_key: None,
            gas_burnt: None,
        }
    }

    #[test]
    fn a_genuine_request_matches_its_receipt_and_its_pending_request() {
        let (raw, pending) = genuine();
        let request: RequestData = serde_json::from_value(raw.clone()).unwrap();
        let event = event_for(&raw, Some("alice.near"), Some("alice.near"));
        assert_eq!(receipt_mismatch(&request, &event), None);
        assert_eq!(pending_project_id(&pending), Some("alice.near/app"));
        assert_eq!(pending_request_mismatch(&raw, &DATA_ID, &pending, Some("p0000000000000003")), None);
    }

    /// An event written in a receipt the named sender did not sign.
    #[test]
    fn an_event_in_someone_elses_receipt_is_refused() {
        let (raw, _) = genuine();
        let request: RequestData = serde_json::from_value(raw.clone()).unwrap();
        assert!(receipt_mismatch(&request, &event_for(&raw, Some("eve.near"), Some("alice.near"))).is_some());
        assert!(receipt_mismatch(&request, &event_for(&raw, Some("alice.near"), Some("eve.near"))).is_some());
        assert!(receipt_mismatch(&request, &event_for(&raw, None, Some("alice.near"))).is_some());
    }

    /// Every field the run is decided by must be the pending request's.
    #[test]
    fn an_event_that_differs_from_the_pending_request_is_refused() {
        let (raw, pending) = genuine();
        let uuid = Some("p0000000000000003");
        assert!(pending_request_mismatch(&raw, &[8; 32], &pending, uuid).is_some());
        for (key, value) in [
            ("request_id", serde_json::json!(6)),
            ("predecessor_id", serde_json::json!("eve.near")),
            ("code_source", serde_json::json!({"GitHub": {"repo": "github.com/eve/x", "commit": "main", "build_target": null}})),
            ("secrets_ref", serde_json::json!({"profile": "default", "account_id": "bob.near"})),
            ("secrets_ref", Value::Null),
            ("response_format", serde_json::json!("Json")),
            ("resource_limits", serde_json::json!({"max_instructions": 1, "max_memory_mb": 128, "max_execution_seconds": 10})),
            ("input_data", serde_json::json!("{\"x\":2}")),
            ("attached_usd", serde_json::json!("1")),
            ("project_id", serde_json::json!("bob.near/app")),
            ("project_id", Value::Null),
            ("project_uuid", serde_json::json!("p0000000000000001")),
            ("project_uuid", Value::Null),
        ] {
            let mut forged = raw.clone();
            forged[key] = value.clone();
            assert!(
                pending_request_mismatch(&forged, &DATA_ID, &pending, uuid).is_some(),
                "accepted {key}={value}"
            );
        }
    }

    /// Code given inline runs in no project: an event naming a uuid for it is
    /// refused, whatever the caller put in `params`.
    #[test]
    fn an_inline_request_naming_a_project_uuid_is_refused() {
        let (mut raw, mut pending) = genuine();
        raw["project_id"] = Value::Null;
        pending["execution_source"] = serde_json::json!({"GitHub": {"repo": "github.com/alice/app", "commit": "main", "build_target": null}});
        assert!(pending_request_mismatch(&raw, &DATA_ID, &pending, None).is_some());
        raw["project_uuid"] = Value::Null;
        assert_eq!(pending_request_mismatch(&raw, &DATA_ID, &pending, None), None);
    }

    /// Input kept in state is not in the event and is not compared there.
    #[test]
    fn input_kept_in_state_is_not_compared_with_the_event() {
        let (mut raw, pending) = genuine();
        raw["input_data"] = serde_json::json!("");
        raw["input_data_in_state"] = serde_json::json!(true);
        assert_eq!(pending_request_mismatch(&raw, &DATA_ID, &pending, Some("p0000000000000003")), None);
    }

    /// A monitor that is only asked to parse logs: nothing in it is contacted.
    fn parsing_monitor() -> EventMonitor {
        EventMonitor {
            api_client: ApiClient::new("http://127.0.0.1:9".to_string(), "t".to_string()).unwrap(),
            neardata_api_url: "http://127.0.0.1:9".to_string(),
            contract_id: "outlayer.testnet".parse().unwrap(),
            current_block: 0,
            scan_interval_ms: 0,
            http_client: reqwest::Client::new(),
            rpc_client: JsonRpcClient::connect("http://127.0.0.1:9"),
            blocks_scanned: 0,
            events_found: 0,
            system_events_found: 0,
            event_filter_standard_name: "near-outlayer".to_string(),
            event_filter_function_name: "execution_requested".to_string(),
            event_filter_min_version: EventMonitor::parse_semver("1.0.0"),
            shared_block_height: Arc::new(AtomicU64::new(0)),
        }
    }

    /// A log line of the shape `transfer_project` writes for
    /// `SystemEvent::ProjectTransferred`.
    const TRANSFER_LOG: &str = r#"EVENT_JSON:{"data":[{"ProjectTransferred":{"new_owner":"bob.testnet","new_project_id":"bob.testnet/app","old_owner":"alice.testnet","old_project_id":"alice.testnet/app","project_uuid":"p000000000000002a"}}],"event":"system_event","standard":"near-outlayer","version":"1.0.0"}"#;

    #[test]
    fn project_transferred_is_parsed_with_both_names() {
        match parsing_monitor().process_log(TRANSFER_LOG, 7) {
            Some(ContractEvent::ProjectTransferred(e)) => {
                assert_eq!(e.old_project_id, "alice.testnet/app");
                assert_eq!(e.new_project_id, "bob.testnet/app");
                assert_eq!(e.project_uuid, "p000000000000002a");
                assert_eq!(e.old_owner, "alice.testnet");
                assert_eq!(e.new_owner, "bob.testnet");
            }
            other => panic!("expected ProjectTransferred, got {other:?}"),
        }
    }

    #[test]
    fn project_transferred_missing_a_field_is_dropped() {
        let log = TRANSFER_LOG.replace(r#""new_owner":"bob.testnet","#, "");
        assert!(parsing_monitor().process_log(&log, 7).is_none());
    }

    #[test]
    fn project_transferred_under_another_standard_is_ignored() {
        let log = TRANSFER_LOG.replace("near-outlayer", "someone-else");
        assert!(parsing_monitor().process_log(&log, 7).is_none());
    }

    /// A system event this worker does not know is skipped, not an error: a
    /// contract may announce more than a given worker handles.
    #[test]
    fn an_unknown_system_event_is_skipped() {
        let log = TRANSFER_LOG.replace("ProjectTransferred", "SomethingNew");
        assert!(parsing_monitor().process_log(&log, 7).is_none());
    }

    #[tokio::test]
    async fn test_fetch_latest_block_mainnet() {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();

        let result = EventMonitor::fetch_latest_block(
            &http_client,
            "https://rpc.mainnet.fastnear.com",
        )
        .await;

        assert!(result.is_ok(), "Failed to fetch block: {:?}", result.err());
        let height = result.unwrap();
        assert!(height > 0, "Block height should be > 0, got {}", height);
        println!("Mainnet block height: {}", height);
    }

    #[tokio::test]
    async fn test_fetch_latest_block_testnet() {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();

        let result = EventMonitor::fetch_latest_block(
            &http_client,
            "https://rpc.testnet.fastnear.com",
        )
        .await;

        assert!(result.is_ok(), "Failed to fetch block: {:?}", result.err());
        let height = result.unwrap();
        assert!(height > 0, "Block height should be > 0, got {}", height);
        println!("Testnet block height: {}", height);
    }

    // ---- classification of a failed view of the contract ----

    use near_jsonrpc_client::errors::{
        JsonRpcError, JsonRpcServerError, JsonRpcServerResponseStatusError, JsonRpcTransportHandlerResponseError,
        JsonRpcTransportRecvError, RpcTransportError,
    };
    use near_jsonrpc_primitives::types::query::RpcQueryError;

    type QueryCallError = JsonRpcError<RpcQueryError>;

    fn handler(e: RpcQueryError) -> QueryCallError {
        JsonRpcError::ServerError(JsonRpcServerError::HandlerError(e))
    }

    fn status(e: JsonRpcServerResponseStatusError) -> QueryCallError {
        JsonRpcError::ServerError(JsonRpcServerError::ResponseStatusError(e))
    }

    fn contract() -> near_primitives::types::AccountId {
        "outlayer.testnet".parse().unwrap()
    }

    #[test]
    fn a_node_behind_the_block_is_asked_again_then_read_at_final() {
        let f = classify_view_error(handler(RpcQueryError::UnknownBlock {
            block_reference: BlockReference::BlockId(BlockId::Height(123)),
        }));
        assert!(matches!(f, ViewFailure::UnknownBlock(_)), "{f:?}");
        assert!(f.is_retried());
    }

    #[test]
    fn a_garbage_collected_block_is_read_at_final_without_retrying() {
        let f = classify_view_error(handler(RpcQueryError::GarbageCollectedBlock {
            block_height: 123,
            block_hash: Default::default(),
        }));
        assert!(matches!(f, ViewFailure::GarbageCollected(_)), "{f:?}");
        assert!(!f.is_retried());
    }

    #[test]
    fn an_outage_or_a_rate_limit_is_asked_again() {
        for (label, e) in [
            ("429", status(JsonRpcServerResponseStatusError::TooManyRequests)),
            ("503", status(JsonRpcServerResponseStatusError::ServiceUnavailable)),
            ("408", status(JsonRpcServerResponseStatusError::TimeoutError)),
            ("502", status(JsonRpcServerResponseStatusError::Unexpected { status: 502u16.try_into().unwrap() })),
            ("504", status(JsonRpcServerResponseStatusError::Unexpected { status: 504u16.try_into().unwrap() })),
            ("500", JsonRpcError::ServerError(JsonRpcServerError::InternalError { info: Some("x".into()) })),
            ("no synced blocks", handler(RpcQueryError::NoSyncedBlocks)),
            ("node overloaded", handler(RpcQueryError::InternalError { error_message: "busy".into() })),
            (
                "a body that is not JSON-RPC",
                JsonRpcError::TransportError(RpcTransportError::RecvError(JsonRpcTransportRecvError::PayloadParseError(
                    near_jsonrpc_primitives::message::Broken::SyntaxError("<html>".into()),
                ))),
            ),
            (
                "a result that does not parse",
                JsonRpcError::TransportError(RpcTransportError::RecvError(JsonRpcTransportRecvError::ResponseParseError(
                    JsonRpcTransportHandlerResponseError::ResultParseError(serde_json::from_str::<u8>("x").unwrap_err()),
                ))),
            ),
        ] {
            let f = classify_view_error(e);
            assert!(matches!(f, ViewFailure::Unavailable(_)), "{label}: {f:?}");
            assert!(f.is_retried(), "{label}");
        }
    }

    #[test]
    fn an_answer_about_the_contract_is_final() {
        for (label, e) in [
            ("401", status(JsonRpcServerResponseStatusError::Unauthorized)),
            ("400", status(JsonRpcServerResponseStatusError::BadRequest)),
            ("403", status(JsonRpcServerResponseStatusError::Unexpected { status: 403u16.try_into().unwrap() })),
            (
                "no such account",
                handler(RpcQueryError::UnknownAccount {
                    requested_account_id: contract(),
                    block_height: 1,
                    block_hash: Default::default(),
                }),
            ),
            (
                "no contract",
                handler(RpcQueryError::NoContractCode {
                    contract_account_id: contract(),
                    block_height: 1,
                    block_hash: Default::default(),
                }),
            ),
            (
                "the view panicked",
                handler(RpcQueryError::ContractExecutionError {
                    vm_error: "panicked".into(),
                    error: near_primitives::errors::FunctionCallError::ExecutionError("panicked".into()),
                    block_height: 1,
                    block_hash: Default::default(),
                }),
            ),
        ] {
            let f = classify_view_error(e);
            assert!(matches!(f, ViewFailure::Final(_)), "{label}: {f:?}");
            assert!(!f.is_retried(), "{label}");
        }
    }

    /// An RPC endpoint on the loopback that answers one request with `status`
    /// and `body`.
    fn rpc_answering(status: u16, body: &'static str) -> String {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        std::thread::spawn(move || {
            if let Some(Ok(mut stream)) = listener.incoming().next() {
                let mut buf = [0u8; 8192];
                let _ = stream.read(&mut buf);
                let response = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        format!("http://{}/?apiKey=SECRET-KEY-VALUE", addr)
    }

    async fn view_through(url: &str) -> ViewFailure {
        let request = methods::query::RpcQueryRequest {
            block_reference: BlockReference::BlockId(BlockId::Height(123)),
            request: QueryRequest::CallFunction {
                account_id: contract(),
                method_name: "get_request".to_string(),
                args: b"{}".to_vec().into(),
            },
        };
        let err = JsonRpcClient::connect(url).call(request).await.expect_err("the call must fail");
        classify_view_error(err)
    }

    /// The node's own error bodies, as near-jsonrpc-client parses them.
    #[tokio::test]
    async fn the_nodes_error_answers_classify_as_they_should() {
        let unknown = r#"{"jsonrpc":"2.0","id":"dontcare","error":{"name":"HANDLER_ERROR","cause":{"name":"UNKNOWN_BLOCK","info":{"block_reference":{"block_id":123}}},"code":-32000,"message":"Server error","data":"DB Not Found Error: BLOCK HEIGHT: 123"}}"#;
        let gone = r#"{"jsonrpc":"2.0","id":"dontcare","error":{"name":"HANDLER_ERROR","cause":{"name":"GARBAGE_COLLECTED_BLOCK","info":{"block_height":123,"block_hash":"11111111111111111111111111111111"}},"code":-32000,"message":"Server error","data":"gc"}}"#;
        let f = view_through(&rpc_answering(200, unknown)).await;
        assert!(matches!(f, ViewFailure::UnknownBlock(_)), "{f:?}");
        let f = view_through(&rpc_answering(200, gone)).await;
        assert!(matches!(f, ViewFailure::GarbageCollected(_)), "{f:?}");
        let f = view_through(&rpc_answering(429, "{}")).await;
        assert!(matches!(f, ViewFailure::Unavailable(_)), "{f:?}");
        let f = view_through(&rpc_answering(502, "{}")).await;
        assert!(matches!(f, ViewFailure::Unavailable(_)), "{f:?}");
        let f = view_through(&rpc_answering(401, "{}")).await;
        assert!(matches!(f, ViewFailure::Final(_)), "{f:?}");
    }

    /// A node that cannot be reached is asked again, and what is logged about
    /// it does not carry the URL, which can carry the RPC's API key.
    #[tokio::test]
    async fn an_unreachable_node_is_asked_again_and_its_url_is_never_shown() {
        let f = view_through("http://127.0.0.1:1/?apiKey=SECRET-KEY-VALUE").await;
        assert!(matches!(f, ViewFailure::Unavailable(_)), "{f:?}");
        let shown = format!("{f} {f:?}");
        assert!(!shown.contains("SECRET-KEY-VALUE") && !shown.contains("127.0.0.1"), "{shown}");
    }

    #[test]
    fn the_view_retries_are_bounded_to_about_thirty_seconds() {
        let total: Duration = VIEW_RETRY_DELAYS.iter().sum();
        assert_eq!(VIEW_RETRY_DELAYS.len() + 1, 5);
        assert_eq!(total, Duration::from_secs(30));
    }
}
