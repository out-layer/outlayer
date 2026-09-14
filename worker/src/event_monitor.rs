use anyhow::{Context, Result};
use near_jsonrpc_client::{methods, JsonRpcClient};
use near_primitives::types::{AccountId, BlockReference, Finality};
use near_primitives::views::QueryRequest;
use regex::Regex;
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

/// NEAR event monitor that watches neardata.xyz for execution_requested and version_requested events
pub struct EventMonitor {
    api_client: ApiClient,
    neardata_api_url: String,
    contract_id: AccountId,
    current_block: u64,
    scan_interval_ms: u64,
    http_client: reqwest::Client,
    rpc_client: JsonRpcClient,
    event_json_regex: Regex,
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
            event_json_regex: Regex::new(r"EVENT_JSON:(.*?)$")
                .context("Failed to compile regex")?,
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
                    let signer_public_key = outcome.receipt.as_ref()
                        .and_then(|r| r.receipt.as_ref())
                        .and_then(|action| action.action.as_ref())
                        .and_then(|details| details.signer_public_key.clone());
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

                    // Process logs from our contract
                    if let Some(execution) = &outcome.execution_outcome {
                        if let Some(outcome_data) = &execution.outcome {
                            if let Some(logs) = &outcome_data.logs {
                                if !logs.is_empty() {
                                    let event_logs: Vec<_> = logs.iter()
                                        .filter(|l| l.contains("EVENT_JSON:"))
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
        // Extract EVENT_JSON from log
        let captures = self.event_json_regex.captures(log)?;
        let event_json_str = captures.get(1)?.as_str();

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
                    let event_data: ProjectStorageCleanupEvent =
                        serde_json::from_value(cleanup_data.clone()).ok()?;

                    info!(
                        "✅ Found system_event ProjectStorageCleanup at block {}: project_id={} uuid={}",
                        block_height, event_data.project_id, event_data.project_uuid
                    );

                    Some(ContractEvent::ProjectStorageCleanup(event_data))
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
            predecessor_id: event.predecessor_id.clone(),
            signer_public_key: event.signer_public_key.clone(),
            gas_burnt: event.gas_burnt,
        };

        // Convert code_source to api_client format
        let api_code_source = request_data.code_source.to_api_code_source();

        // Fetch input_data from contract if it was too large for event log
        let input_data = if request_data.input_data_in_state {
            self.fetch_input_data_from_contract(request_data.request_id)
                .await
                .context("Failed to fetch large input_data from contract")?
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
    async fn handle_project_storage_cleanup(&self, event: ProjectStorageCleanupEvent) -> Result<()> {
        info!(
            "🧹 Creating cleanup task for deleted project: project_id={} uuid={}",
            event.project_id, event.project_uuid
        );

        match self
            .api_client
            .create_project_storage_cleanup_task(&event.project_id, &event.project_uuid)
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
                error!(
                    "❌ Failed to create cleanup task for project uuid={}: {}",
                    event.project_uuid, e
                );
                Err(e)
            }
        }
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

    /// Fetch input_data from contract state via RPC view call
    ///
    /// Used when input_data is too large for event log (>10KB).
    /// Contract stores it in pending_requests, we fetch via get_request() view.
    async fn fetch_input_data_from_contract(&self, request_id: u64) -> Result<String> {
        info!(
            "📥 Fetching large input_data from contract for request_id={}",
            request_id
        );

        // Build RPC query request
        let request = methods::query::RpcQueryRequest {
            block_reference: BlockReference::Finality(Finality::Final),
            request: QueryRequest::CallFunction {
                account_id: self.contract_id.clone(),
                method_name: "get_request".to_string(),
                args: serde_json::json!({ "request_id": request_id })
                    .to_string()
                    .into_bytes()
                    .into(),
            },
        };

        let response = self
            .rpc_client
            .call(request)
            .await
            .with_context(|| format!("RPC call failed for request_id={}", request_id))?;

        // Extract result bytes from CallResult
        let result_bytes = match response.kind {
            near_jsonrpc_primitives::types::query::QueryResponseKind::CallResult(call_result) => {
                call_result.result
            }
            _ => anyhow::bail!("Unexpected response kind for get_request call"),
        };

        // get_request returns Option<ExecutionRequest> - handle None case
        let execution_request: Option<serde_json::Value> =
            serde_json::from_slice(&result_bytes).with_context(|| {
                format!(
                    "Failed to parse get_request response for request_id={}",
                    request_id
                )
            })?;

        // If None, the request doesn't exist (already completed, cancelled, or timed out)
        let execution_request = execution_request.ok_or_else(|| {
            anyhow::anyhow!(
                "Request {} not found in contract state (may have completed or timed out)",
                request_id
            )
        })?;

        // Extract input_data from ExecutionRequest
        let input_data = execution_request
            .get("input_data")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "input_data field missing in ExecutionRequest for request_id={}",
                    request_id
                )
            })?;

        info!(
            "✅ Fetched input_data from contract: request_id={} size={} bytes",
            request_id,
            input_data.len()
        );

        Ok(input_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
