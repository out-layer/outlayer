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

/// An event of the contract, as the monitor read it from a block.
///
/// Every variant is classified in [`relay_decision`], and the match there is
/// exhaustive on purpose. A block can reach the monitor LATE — older than the
/// contract's 200-block yield window: a slow head, a restart's catch-up — and
/// OUT OF ORDER — a deferred block read after newer ones. What is safe then
/// differs per event. Before adding a variant, answer:
///
/// 1. Does the contract hold a **yield** for it? A late resume finds the yield
///    gone and the timeout callback already settled (refunded, kept). The
///    contract's `resume_*` must refuse a missing yield, and the worker must
///    check that the chain TOOK the resume (`NearClient::require_taken`)
///    before telling the coordinator anything. If the worker acts on the
///    coordinator BEFORE the resume, a late event must be dropped.
/// 2. Does the coordinator apply the event's **value**, or create or revive a
///    row from it? Then an older event delivered after a newer one rewinds
///    state: out of order, relay the chain's CURRENT state, or check the chain
///    first — never the event's value as is.
/// 3. Is the relay idempotent and order-free — keyed by receipt, request_id or
///    data_id, or a re-read of the chain? Only then is it relayed as is from
///    every delivery.
///
/// A top-up resumed after its yield was refunded, and credited anyway, is what
/// skipping (1) costs.
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
    /// The account that relayed this call as a NEP-366 meta-transaction —
    /// signed the outer transaction and paid its gas — read off the block
    /// that carried the `Delegate` action; `None` when the call was not one.
    #[serde(skip)]
    pub relayer_id: Option<String>,
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
    /// nearcore's `ActionView`s, kept as JSON: only a `Delegate` is read.
    #[serde(default)]
    actions: Vec<Value>,
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

/// Blocks a delegated receipt is remembered for after the `Delegate` that
/// created it. The receipt normally executes one block later; the rest is
/// room for congestion.
const DELEGATED_TTL_BLOCKS: u64 = 3_000;

/// Blocks before its first block the monitor reads for `Delegate` actions
/// alone, so a meta-transaction whose delegate ran just before a restart is
/// still told from a contract call.
const DELEGATED_BACKFILL_BLOCKS: u64 = 100;

/// A receipt a NEP-366 `Delegate` action created for this contract.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Delegated {
    /// The account that signed the delegate action: the inner receipt's
    /// predecessor.
    sender_id: String,
    /// The account that signed the transaction carrying it: the inner
    /// receipt's signer.
    relayer_id: String,
    /// The key the sender signed the delegate action with.
    public_key: Option<String>,
    block: u64,
}

/// What the block that carried a meta-transaction says about it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MetaTransaction {
    relayer_id: String,
    /// The sender's key, which stands for the signer's key of the call: the
    /// receipt's own `signer_public_key` is the relayer's.
    sender_public_key: Option<String>,
}

/// Which receipts that reach this contract were made by a `Delegate` action.
///
/// The receipt that calls the contract carries no trace of the delegate: its
/// predecessor is the user, its signer the relayer, its actions the inner
/// function call — the same shape as a call a contract makes on a user's
/// behalf. The `Delegate` action is on its parent, executed on the user's
/// account at least one block earlier, and the parent's outcome lists the
/// child's id. The monitor reads every block, so it remembers the children of
/// every committed `Delegate` whose `receiver_id` is this contract and
/// recognises the child when it arrives. No RPC is made.
#[derive(Debug, Default)]
struct DelegatedCalls {
    by_receipt: std::collections::HashMap<String, Delegated>,
}

impl DelegatedCalls {
    /// Remember the receipts the `Delegate` actions in `outcome` created for
    /// `contract_id`.
    fn record(&mut self, outcome: &ReceiptExecutionOutcome, contract_id: &str, block: u64) {
        let Some(receipt) = outcome.receipt.as_ref() else { return };
        let Some(action) = receipt.receipt.as_ref().and_then(|r| r.action.as_ref()) else { return };
        let Some(relayer_id) = action.signer_id.as_deref() else { return };
        if receipt_committed(outcome).is_err() {
            return;
        }
        let children = outcome
            .execution_outcome
            .as_ref()
            .and_then(|e| e.outcome.as_ref())
            .and_then(|o| o.receipt_ids.as_ref());
        let Some(children) = children else { return };
        for delegate in action.actions.iter().filter_map(|a| a.get("Delegate")?.get("delegate_action")) {
            if delegate.get("receiver_id").and_then(Value::as_str) != Some(contract_id) {
                continue;
            }
            let Some(sender_id) = delegate.get("sender_id").and_then(Value::as_str) else { continue };
            let public_key = delegate.get("public_key").and_then(Value::as_str).map(str::to_string);
            for child in children {
                self.by_receipt.insert(
                    child.clone(),
                    Delegated {
                        sender_id: sender_id.to_string(),
                        relayer_id: relayer_id.to_string(),
                        public_key: public_key.clone(),
                        block,
                    },
                );
            }
        }
    }

    /// The meta-transaction behind the receipt `receipt_id`, when a
    /// `Delegate` signed by `predecessor` and relayed by `signer` created it.
    /// A delegate its own sender relayed is a direct call. The entry stays
    /// until it expires: a block the monitor scans again must read the same.
    fn meta_transaction(&self, receipt_id: &str, predecessor: Option<&str>, signer: Option<&str>) -> Option<MetaTransaction> {
        let d = self.by_receipt.get(receipt_id)?;
        (Some(d.sender_id.as_str()) == predecessor
            && Some(d.relayer_id.as_str()) == signer
            && d.sender_id != d.relayer_id)
            .then(|| MetaTransaction { relayer_id: d.relayer_id.clone(), sender_public_key: d.public_key.clone() })
    }

    fn prune(&mut self, block: u64) {
        self.by_receipt.retain(|_, d| d.block + DELEGATED_TTL_BLOCKS >= block);
    }
}

/// The longest the head spends on one block, every attempt included, before
/// the block is deferred and the head moves on.
const HEAD_BLOCK_BUDGET: Duration = Duration::from_secs(15);

/// One read of a block: the HTTP client's own timeout.
const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// The pause between two reads of the same block inside its budget.
const READ_RETRY_PAUSE: Duration = Duration::from_secs(2);

/// How far past an unreadable head block the monitor looks to tell one bad
/// block from neardata being down: any of these read means the head block is
/// the problem, none means neardata is.
const PROBE_AHEAD_BLOCKS: u64 = 3;

/// How long the head waits on neardata being down before it defers its block
/// anyway. A range neardata has lost must not hold the head for ever; a short
/// outage is waited out, so the blocks keep their order.
const HEAD_OUTAGE_MAX: Duration = Duration::from_secs(300);

/// The pauses between two tries of the head block while neardata is down.
const OUTAGE_PAUSES: [Duration; 4] = [
    Duration::from_secs(5),
    Duration::from_secs(10),
    Duration::from_secs(20),
    Duration::from_secs(30),
];

/// The pauses between two tries of one deferred block.
const DEFERRED_PAUSES: [Duration; 5] = [
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
    Duration::from_secs(16),
    Duration::from_secs(30),
];

/// How many blocks behind the head a deferred block is kept before it is
/// given up — about an hour.
const DEFERRED_MAX_AGE_BLOCKS: u64 = 3_000;

/// The most blocks the queue holds; past it the oldest is given up.
const DEFERRED_MAX_LEN: usize = 500;

/// How many due deferred blocks one turn of the loop tries, and for how long
/// at most, so the head keeps moving while the queue drains.
const DEFERRED_PER_TURN: usize = 3;
const DEFERRED_TURN_BUDGET: Duration = Duration::from_secs(5);

/// One read of a deferred block: once, and shorter than the head's.
const DEFERRED_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// How far past an unreadable head the monitor looks for a block that reads,
/// once neardata has not served the head for [`HEAD_OUTAGE_MAX`].
const FAR_PROBE_STEPS: [u64; 6] = [8, 16, 32, 64, 128, 256];

/// A delegated receipt normally runs one block after its `Delegate`. While a
/// block this close before a block is unread, a call in it that may be a
/// meta-transaction cannot be told from a contract call, and the block waits.
const DELEGATE_LOOKBACK_BLOCKS: u64 = 10;

/// An event older than this many blocks behind the chain tip is LATE: the
/// contract's yield window is 200 blocks, and the work that answers a yield
/// needs the rest of it.
const LATE_AFTER_BLOCKS: u64 = 100;

/// How long a read of the chain tip is reused.
const TIP_REUSE: Duration = Duration::from_secs(10);

/// How a block reached the monitor. The head reads blocks in order — a
/// restart's catch-up too. A deferred block is read after newer ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Delivery {
    InOrder,
    OutOfOrder,
}

/// How far a block is behind the chain tip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Age {
    Blocks(u64),
    /// The tip could not be read.
    Unknown,
}

impl Age {
    fn is_late(self) -> Option<bool> {
        match self {
            Age::Blocks(blocks) => Some(blocks > LATE_AFTER_BLOCKS),
            Age::Unknown => None,
        }
    }
}

/// What the monitor does with one event.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Relay {
    /// Relayed as the event says.
    AsIs,
    /// Relayed only while the contract still holds the request at the final
    /// block: a request that timed out has been refunded.
    IfPendingAtFinal,
    /// Relayed only while the payment key exists at the final block: a key
    /// created and then deleted must not be created again.
    IfKeyExistsAtFinal,
    /// The wallet's policy and freeze AT THE FINAL BLOCK are relayed instead
    /// of the event's, which a newer event may have replaced.
    WalletStateAtFinal,
    /// Not decided now: delivered again later, for the reason given.
    Later(&'static str),
    /// Not relayed, for the reason given.
    Drop(&'static str),
}

/// The one place each event's late and out-of-order handling is decided. No
/// wildcard arm: a new [`ContractEvent`] does not compile until it is
/// classified here (see the questions on [`ContractEvent`]).
fn relay_decision(event: &ContractEvent, delivery: Delivery, age: Age) -> Relay {
    match event {
        // A yield. The contract refuses a late resolve and the worker reports
        // nothing for it, so a late request is safe — but a request already
        // refunded is not run.
        ContractEvent::ExecutionRequested(_) => match (delivery, age.is_late()) {
            (Delivery::InOrder, Some(false)) => Relay::AsIs,
            _ => Relay::IfPendingAtFinal,
        },
        // A yield. A late resume is refused and not credited
        // (`NearClient::require_taken`), so the chain decides; additive by
        // `data_id`, so order is free.
        ContractEvent::TopUpPaymentKey(e) if e.amount != "0" => Relay::AsIs,
        // A key's creation, no yield. The coordinator creates the row, and
        // revives a deleted one.
        ContractEvent::TopUpPaymentKey(_) => match delivery {
            Delivery::InOrder => Relay::AsIs,
            Delivery::OutOfOrder => Relay::IfKeyExistsAtFinal,
        },
        // A yield, and the coordinator deletes the key BEFORE the resume: a
        // delete whose yield is gone would leave the key deleted here and kept
        // on chain. Kept on both sides instead; the owner deletes again.
        ContractEvent::DeletePaymentKey(_) => match age.is_late() {
            Some(false) => Relay::AsIs,
            Some(true) => Relay::Drop("older than the yield window allows; the contract keeps the key — delete it again"),
            None => Relay::Later("the chain tip could not be read to tell whether its yield is still open"),
        },
        // Values the coordinator applies as they come.
        ContractEvent::WalletPolicyUpdated(_)
        | ContractEvent::WalletPolicyDeleted(_)
        | ContractEvent::WalletFrozenChanged(_) => match delivery {
            Delivery::InOrder => Relay::AsIs,
            Delivery::OutOfOrder => Relay::WalletStateAtFinal,
        },
        // Keyed by receipt; the allowance adds and the expiry extends.
        ContractEvent::SubscriptionPurchased(_) => Relay::AsIs,
        // The coordinator confirms the deletion on the contract; a uuid is
        // never reused.
        ContractEvent::ProjectStorageCleanup(_) => Relay::AsIs,
        // Drops a cache.
        ContractEvent::ProjectTransferred(_) => Relay::AsIs,
    }
}

/// An execution request whose receipt has the shape of a meta-transaction —
/// signed by one account on another's behalf — with no `Delegate` found for
/// it: a contract call, or a meta-transaction whose delegate is unread.
fn may_be_unattributed_meta_tx(event: &ContractEvent) -> bool {
    match event {
        ContractEvent::ExecutionRequested(e) => {
            e.relayer_id.is_none()
                && matches!((&e.signer_id, &e.predecessor_id), (Some(s), Some(p)) if s != p)
        }
        _ => false,
    }
}

/// One block in the queue: unread, or read with events still to deliver.
#[derive(Debug, Clone)]
struct Deferred {
    tries: usize,
    next_try: tokio::time::Instant,
    /// `None`: the block is unread. `Some`: it was read, and these of its
    /// events are still to be delivered — the rest were.
    events: Option<Vec<ContractEvent>>,
}

/// The blocks the head moved past with something undone: unread, or read
/// with events still to deliver. Each is tried again on its own backoff and
/// delivered OUT OF ORDER. A block is here or behind the head, never both,
/// and an event is delivered from one place only.
#[derive(Debug, Default)]
struct DeferredBlocks {
    blocks: std::collections::BTreeMap<u64, Deferred>,
}

/// A block the queue gave up, and its events still undelivered if it was read.
type GivenUp = (u64, Option<Vec<ContractEvent>>);

impl DeferredBlocks {
    /// Add `height` unread, due after the first pause. Returns the block given
    /// up to make room, if the queue was full.
    fn defer(&mut self, height: u64, now: tokio::time::Instant) -> Option<GivenUp> {
        self.insert(height, None, now)
    }

    /// Add `height` read, with `events` still to deliver.
    fn keep(&mut self, height: u64, events: Vec<ContractEvent>, now: tokio::time::Instant) -> Option<GivenUp> {
        self.insert(height, Some(events), now)
    }

    fn insert(&mut self, height: u64, events: Option<Vec<ContractEvent>>, now: tokio::time::Instant) -> Option<GivenUp> {
        self.blocks.insert(height, Deferred { tries: 0, next_try: now + DEFERRED_PAUSES[0], events });
        if self.blocks.len() > DEFERRED_MAX_LEN {
            return self.blocks.pop_first().map(|(h, d)| (h, d.events));
        }
        None
    }

    /// The oldest blocks due by `now`, at most `limit`.
    fn due(&self, now: tokio::time::Instant, limit: usize) -> Vec<u64> {
        self.blocks.iter().filter(|(_, d)| d.next_try <= now).map(|(h, _)| *h).take(limit).collect()
    }

    /// The events still to deliver from `height`, `None` while it is unread.
    fn events(&self, height: u64) -> Option<Vec<ContractEvent>> {
        self.blocks.get(&height).and_then(|d| d.events.clone())
    }

    /// `height` is not done: due after the next pause, with `events` still to
    /// deliver if it has been read.
    fn retry_later(&mut self, height: u64, events: Option<Vec<ContractEvent>>, now: tokio::time::Instant) {
        if let Some(d) = self.blocks.get_mut(&height) {
            d.tries += 1;
            d.next_try = now + DEFERRED_PAUSES[d.tries.min(DEFERRED_PAUSES.len() - 1)];
            if events.is_some() {
                d.events = events;
            }
        }
    }

    fn remove(&mut self, height: u64) {
        self.blocks.remove(&height);
    }

    /// Give up the unread blocks more than [`DEFERRED_MAX_AGE_BLOCKS`] behind
    /// `head`, and the read ones twice as far. The blocks that waited for an
    /// unread one given up are tried at once.
    fn expire(&mut self, head: u64, now: tokio::time::Instant) -> Vec<GivenUp> {
        let unread_cutoff = head.saturating_sub(DEFERRED_MAX_AGE_BLOCKS);
        let read_cutoff = head.saturating_sub(2 * DEFERRED_MAX_AGE_BLOCKS);
        let gone: Vec<u64> = self
            .blocks
            .iter()
            .filter(|(h, d)| match d.events {
                None => **h < unread_cutoff,
                Some(_) => **h < read_cutoff,
            })
            .map(|(h, _)| *h)
            .collect();
        let mut given_up = Vec::new();
        for height in gone {
            if let Some(d) = self.blocks.remove(&height) {
                if d.events.is_none() {
                    for (_, waiting) in self.blocks.range_mut(height + 1..=height + DELEGATE_LOOKBACK_BLOCKS) {
                        waiting.next_try = now;
                    }
                }
                given_up.push((height, d.events));
            }
        }
        given_up
    }

    /// Whether an UNREAD block lies in `[height − DELEGATE_LOOKBACK_BLOCKS, height)`.
    fn unread_just_before(&self, height: u64) -> bool {
        self.blocks
            .range(height.saturating_sub(DELEGATE_LOOKBACK_BLOCKS)..height)
            .any(|(_, d)| d.events.is_none())
    }

    fn len(&self) -> usize {
        self.blocks.len()
    }

    fn heights(&self) -> Vec<u64> {
        self.blocks.keys().copied().collect()
    }
}

/// What one read of a block found.
enum Scan {
    Events(Vec<ContractEvent>),
    /// neardata has not indexed it yet (404): wait for it.
    NotIndexed,
    /// It could not be read now. The text names what failed and never quotes
    /// the URL, which can carry an API key.
    Unreadable(String),
}

/// What is left of a block after delivering it.
struct Leftover {
    /// The events not delivered yet. Every other event of the block was
    /// relayed, refused or dropped for good, and is not delivered again.
    events: Vec<ContractEvent>,
    why: String,
    /// Some of them wait for an older block still unread: holding the block
    /// in place cannot help.
    waits: bool,
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
    /// Receipts to this contract made by a `Delegate` action.
    delegated: std::sync::Mutex<DelegatedCalls>,
    /// Blocks the head moved past unread.
    deferred: DeferredBlocks,
    /// The last chain tip read, and when.
    tip: std::sync::Mutex<Option<(u64, tokio::time::Instant)>>,
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
            delegated: std::sync::Mutex::new(DelegatedCalls::default()),
            deferred: DeferredBlocks::default(),
            tip: std::sync::Mutex::new(None),
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

    /// Start continuous monitoring of new blocks.
    ///
    /// The head reads blocks in order and never waits on one block for more
    /// than [`HEAD_BLOCK_BUDGET`]: a block it cannot read is deferred and read
    /// again on its own backoff, delivered out of order (see
    /// [`relay_decision`]). When the blocks after it cannot be read either,
    /// neardata is down rather than the block: the head waits, so the blocks
    /// keep their order, for up to [`HEAD_OUTAGE_MAX`].
    pub async fn start_monitoring(&mut self) -> Result<()> {
        info!(
            "Starting event monitoring from block {} for contract {}",
            self.current_block, self.contract_id
        );

        let start_block = self.current_block;
        self.backfill_delegated(start_block).await;
        let mut wait_for_block_count = 0u32; // Counter for "waiting for block" logging
        // How many times the head holds a block whose events could not all be
        // relayed for a reason that may pass, before it defers what is left.
        const MAX_RELAY_RETRIES: u32 = 12;
        // Since when neardata has been down, and how many pauses the head has
        // taken in it.
        let mut outage: Option<(tokio::time::Instant, usize)> = None;

        loop {
            self.serve_deferred().await;

            let head = self.current_block;
            match self.scan_within(head, HEAD_BLOCK_BUDGET).await {
                Scan::NotIndexed => {
                    wait_for_block_count += 1;
                    if wait_for_block_count == 1 || wait_for_block_count % 50 == 0 {
                        info!("⏳ Waiting for block {} (not indexed by neardata yet)", head);
                    }
                    sleep(Duration::from_millis(200)).await;
                }
                Scan::Events(events) => {
                    wait_for_block_count = 0;
                    outage = None;
                    self.blocks_scanned += 1;
                    self.count_events(head, &events);

                    // Hold the block while what is left of it may still go
                    // through in order — only the events not relayed yet are
                    // delivered again. Bounded: after that they are deferred
                    // and delivered out of order.
                    let mut left = self.deliver(head, events, Delivery::InOrder).await;
                    let mut holds = 0;
                    while let Some(l) = left.take() {
                        if l.waits || holds + 1 >= MAX_RELAY_RETRIES {
                            warn!("Block {}: {} event(s) deferred: {}", head, l.events.len(), l.why);
                            self.keep(head, l.events);
                            break;
                        }
                        holds += 1;
                        warn!("Holding block {} ({}); delivering what is left again", head, l.why);
                        sleep(Duration::from_secs(5)).await;
                        left = self.deliver(head, l.events, Delivery::InOrder).await;
                    }
                    self.advance();

                    // Brief pause between blocks (if configured)
                    if self.scan_interval_ms > 0 {
                        sleep(Duration::from_millis(self.scan_interval_ms)).await;
                    }
                }
                Scan::Unreadable(why) => {
                    wait_for_block_count = 0;
                    warn!("❌ Block {} not read within {:?}: {}", head, HEAD_BLOCK_BUDGET, why);
                    if let Some(readable) = self.probe_ahead(head).await {
                        // The blocks after it read: the problem is this block.
                        outage = None;
                        for height in head..readable {
                            self.defer(height);
                        }
                        self.set_head(readable);
                        continue;
                    }
                    let now = tokio::time::Instant::now();
                    let since = outage.get_or_insert((now, 0)).0;
                    if now.duration_since(since) >= HEAD_OUTAGE_MAX {
                        if let Some(tip) = self.chain_tip().await.filter(|tip| head < *tip) {
                            // A range neardata has lost, or a long outage: look
                            // further for a block that reads, below the tip.
                            let next = self.probe_far(head, tip).await.unwrap_or(head + 1);
                            error!(
                                "Blocks {}..{} unreadable for {:?}; deferring them and moving the head to {}",
                                head, next, HEAD_OUTAGE_MAX, next
                            );
                            for height in head..next {
                                self.defer(height);
                            }
                            self.set_head(next);
                            outage = Some((now, 0));
                            continue;
                        }
                    }
                    let (since, pauses) = outage.get_or_insert((now, 0));
                    let pause = OUTAGE_PAUSES[(*pauses).min(OUTAGE_PAUSES.len() - 1)];
                    *pauses += 1;
                    warn!(
                        "neardata does not serve block {} or the {} after it; waiting {:?} (down for {:?})",
                        head, PROBE_AHEAD_BLOCKS, pause, now.duration_since(*since)
                    );
                    sleep(pause).await;
                }
            }
        }
    }

    fn count_events(&mut self, height: u64, events: &[ContractEvent]) {
        if events.is_empty() {
            return;
        }
        self.events_found += events.len() as u64;
        let system_count = events.iter().filter(|e| !matches!(e, ContractEvent::ExecutionRequested(_))).count();
        self.system_events_found += system_count as u64;
        info!(
            "📦 Block {}: Found {} events ({} execution, {} system) — total: {} events in {} blocks",
            height,
            events.len(),
            events.len() - system_count,
            system_count,
            self.events_found,
            self.blocks_scanned
        );
    }

    /// Move the head to the next block.
    fn advance(&mut self) {
        self.set_head(self.current_block + 1);

        // Log progress every 100 blocks
        if self.blocks_scanned % 100 == 0 {
            info!(
                "📊 Progress: head {} ({} blocks scanned, {} events: {} execution, {} system)",
                self.current_block,
                self.blocks_scanned,
                self.events_found,
                self.events_found - self.system_events_found,
                self.system_events_found
            );
            if self.deferred.len() > 0 {
                warn!("📊 Deferred blocks not done yet: {:?}", self.deferred.heights());
            }
        }
    }

    fn set_head(&mut self, height: u64) {
        self.current_block = height;
        self.shared_block_height.store(height, Ordering::Relaxed);
    }

    /// Queue `height` unread.
    fn defer(&mut self, height: u64) {
        warn!("⏸️  Deferring block {} unread (queue: {})", height, self.deferred.len() + 1);
        let given_up = self.deferred.defer(height, tokio::time::Instant::now());
        Self::log_given_up(given_up, "the queue is full");
    }

    /// Queue `height`, read, with `events` still to deliver.
    fn keep(&mut self, height: u64, events: Vec<ContractEvent>) {
        let given_up = self.deferred.keep(height, events, tokio::time::Instant::now());
        Self::log_given_up(given_up, "the queue is full");
    }

    fn log_given_up(given_up: Option<GivenUp>, why: &str) {
        match given_up {
            None => {}
            Some((height, None)) => error!(
                "⚠️  Giving up deferred block {} ({}): never read — its events are NOT delivered",
                height, why
            ),
            Some((height, Some(events))) => error!(
                "⚠️  Giving up deferred block {} ({}): these events are NOT delivered: {:?}",
                height, why, events
            ),
        }
    }

    /// Try the due deferred blocks, oldest first, for at most
    /// [`DEFERRED_TURN_BUDGET`], and deliver them out of order.
    async fn serve_deferred(&mut self) {
        let started = tokio::time::Instant::now();
        for given_up in self.deferred.expire(self.current_block, started) {
            Self::log_given_up(Some(given_up), "too far behind the head");
        }
        for height in self.deferred.due(started, DEFERRED_PER_TURN) {
            if started.elapsed() >= DEFERRED_TURN_BUDGET {
                break;
            }
            let events = match self.deferred.events(height) {
                Some(events) => Ok(events),
                None => match self.scan_once(height, DEFERRED_READ_TIMEOUT).await {
                    Scan::Events(events) => {
                        self.blocks_scanned += 1;
                        self.count_events(height, &events);
                        Ok(events)
                    }
                    Scan::NotIndexed => Err("not indexed by neardata".to_string()),
                    Scan::Unreadable(why) => Err(why),
                },
            };
            let now = tokio::time::Instant::now();
            match events {
                Err(why) => {
                    self.deferred.retry_later(height, None, now);
                    warn!("Deferred block {} still unread: {}", height, why);
                }
                Ok(events) => match self.deliver(height, events, Delivery::OutOfOrder).await {
                    None => {
                        self.deferred.remove(height);
                        info!("✅ Deferred block {} delivered (queue: {})", height, self.deferred.len());
                    }
                    Some(left) => {
                        warn!("Deferred block {}: {} event(s) not delivered yet: {}", height, left.events.len(), left.why);
                        self.deferred.retry_later(height, Some(left.events), now);
                    }
                },
            }
        }
    }

    /// The first of the blocks after `head` that reads, if one does before a
    /// block not indexed yet.
    async fn probe_ahead(&self, head: u64) -> Option<u64> {
        for height in head + 1..=head + PROBE_AHEAD_BLOCKS {
            match self.read_once(height, READ_TIMEOUT).await {
                Ok(_) => return Some(height),
                Err(e) if e.downcast_ref::<BlockNotIndexedError>().is_some() => return None,
                Err(_) => {}
            }
        }
        None
    }

    /// A block below `tip`, further than [`probe_ahead`](Self::probe_ahead)
    /// looks, that reads.
    async fn probe_far(&self, head: u64, tip: u64) -> Option<u64> {
        for step in FAR_PROBE_STEPS {
            let height = head + step;
            if height >= tip {
                return None;
            }
            if self.read_once(height, READ_TIMEOUT).await.is_ok() {
                return Some(height);
            }
        }
        None
    }

    /// The final block's height, read at most every [`TIP_REUSE`].
    async fn chain_tip(&self) -> Option<u64> {
        let now = tokio::time::Instant::now();
        if let Some((tip, at)) = *self.tip.lock().unwrap_or_else(|e| e.into_inner()) {
            if now.duration_since(at) < TIP_REUSE {
                return Some(tip);
            }
        }
        let request = methods::block::RpcBlockRequest {
            block_reference: BlockReference::Finality(Finality::Final),
        };
        match tokio::time::timeout(READ_TIMEOUT, self.rpc_client.call(request)).await {
            Ok(Ok(block)) => {
                let tip = block.header.height;
                *self.tip.lock().unwrap_or_else(|e| e.into_inner()) = Some((tip, now));
                Some(tip)
            }
            _ => {
                warn!("The chain tip could not be read from the RPC");
                None
            }
        }
    }

    async fn age_of(&self, height: u64) -> Age {
        match self.chain_tip().await {
            Some(tip) => Age::Blocks(tip.saturating_sub(height)),
            None => Age::Unknown,
        }
    }

    /// Read and scan `height` once, within `timeout`.
    async fn scan_once(&self, height: u64, timeout: Duration) -> Scan {
        match self.read_once(height, timeout).await {
            Ok(block) => match block.shards {
                None => Scan::Events(vec![]),
                Some(shards) => match self.process_shards(&shards, height) {
                    Ok(events) => Scan::Events(events),
                    Err(e) => Scan::Unreadable(e.to_string()),
                },
            },
            Err(e) if e.downcast_ref::<BlockNotIndexedError>().is_some() => Scan::NotIndexed,
            // `{}`, not `{:#}`: the cause of a transport error quotes the
            // URL, which can carry an API key.
            Err(e) => Scan::Unreadable(e.to_string()),
        }
    }

    /// Read and scan `height`, trying again within `budget` wall-clock.
    async fn scan_within(&self, height: u64, budget: Duration) -> Scan {
        let deadline = tokio::time::Instant::now() + budget;
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            let scan = self.scan_once(height, READ_TIMEOUT.min(left)).await;
            let Scan::Unreadable(why) = scan else { return scan };
            if deadline.saturating_duration_since(tokio::time::Instant::now()) <= READ_RETRY_PAUSE {
                return Scan::Unreadable(why);
            }
            sleep(READ_RETRY_PAUSE).await;
        }
    }

    /// Relay the events of block `height` as [`relay_decision`] says, and
    /// return what is left: the events a later delivery may still get
    /// through. Everything else is done and is never delivered again.
    async fn deliver(&self, height: u64, events: Vec<ContractEvent>, delivery: Delivery) -> Option<Leftover> {
        if events.is_empty() {
            return None;
        }
        // A meta-transaction is told from a contract call by the `Delegate`
        // in an earlier block. With such a block unread, a call of that shape
        // would be judged by the wrong door and run as the relayer: it waits.
        let (waiting, events): (Vec<ContractEvent>, Vec<ContractEvent>) = if self.deferred.unread_just_before(height) {
            events.into_iter().partition(may_be_unattributed_meta_tx)
        } else {
            (Vec::new(), events)
        };
        let mut again = Vec::new();
        let mut why = None;
        if !events.is_empty() {
            let age = self.age_of(height).await;
            for event in events {
                let decision = relay_decision(&event, delivery, age);
                if let Err(e) = self.relay(event.clone(), decision, height, age).await {
                    why = Some(e);
                    again.push(event);
                }
            }
        }
        if waiting.is_empty() && again.is_empty() {
            return None;
        }
        let waits = !waiting.is_empty();
        let why = match (waits, why) {
            (true, None) => format!(
                "{} call(s) that may be meta-transactions wait for an unread block of the {} before it",
                waiting.len(),
                DELEGATE_LOOKBACK_BLOCKS
            ),
            (true, Some(why)) => format!(
                "{} call(s) wait for an unread block before it; {}",
                waiting.len(),
                why
            ),
            (false, why) => why.unwrap_or_default(),
        };
        again.extend(waiting);
        Some(Leftover { events: again, why, waits })
    }

    /// Carry out one decision. `Err` is a failure a later delivery of the
    /// event can get past.
    async fn relay(&self, event: ContractEvent, decision: Relay, height: u64, age: Age) -> std::result::Result<(), String> {
        match decision {
            Relay::AsIs => self.relay_as_is(event, height).await,
            Relay::Later(why) => Err(why.to_string()),
            Relay::Drop(why) => {
                error!("⛔ Block {} ({:?} behind the tip): not relaying {:?}: {}", height, age, event, why);
                Ok(())
            }
            Relay::IfPendingAtFinal => {
                let ContractEvent::ExecutionRequested(exec_event) = event else {
                    return Err(format!("IfPendingAtFinal is not a decision for {:?}", event));
                };
                let request_id = serde_json::from_str::<RequestData>(&exec_event.request_data)
                    .map_err(|e| format!("execution_requested at block {}: request_data does not parse: {}", height, e))?
                    .request_id;
                let (request, final_height) = self
                    .view_final("get_request", &serde_json::json!({ "request_id": request_id }))
                    .await
                    .map_err(|e| format!("request {} not read at the final block: {}", request_id, e))?;
                if final_height < height {
                    return Err(format!("the RPC's final block {} is behind block {}", final_height, height));
                }
                if request.is_null() {
                    warn!(
                        "Dropping execution_requested for request_id={}: block {} is late or read out of order, and at final block {} the request is no longer pending — it was resolved or timed out and refunded",
                        request_id, height, final_height
                    );
                    return Ok(());
                }
                if let Err(e) = self.handle_execution_requested(exec_event).await {
                    error!("Failed to handle execution_requested event: {}", e);
                }
                Ok(())
            }
            Relay::IfKeyExistsAtFinal => {
                let ContractEvent::TopUpPaymentKey(topup) = event else {
                    return Err(format!("IfKeyExistsAtFinal is not a decision for {:?}", event));
                };
                let (exists, final_height) = self
                    .payment_key_exists_at_final(&topup.owner, topup.nonce)
                    .await
                    .map_err(|e| format!("payment key {}:{} not read at the final block: {}", topup.owner, topup.nonce, e))?;
                if final_height < height {
                    return Err(format!("the RPC's final block {} is behind block {}", final_height, height));
                }
                if !exists {
                    warn!(
                        "Block {}: payment key {}:{} was created and is gone at final block {}; its creation is not relayed",
                        height, topup.owner, topup.nonce, final_height
                    );
                    return Ok(());
                }
                if let Err(e) = self.handle_topup_payment_key(topup).await {
                    error!("Failed to handle topup_payment_key event: {}", e);
                }
                Ok(())
            }
            Relay::WalletStateAtFinal => {
                let (wallet_pubkey, owner) = match &event {
                    ContractEvent::WalletPolicyUpdated(e) => (e.wallet_pubkey.clone(), e.owner.clone()),
                    ContractEvent::WalletPolicyDeleted(e) => (e.wallet_pubkey.clone(), e.owner.clone()),
                    ContractEvent::WalletFrozenChanged(e) => (e.wallet_pubkey.clone(), e.owner.clone()),
                    other => return Err(format!("WalletStateAtFinal is not a decision for {:?}", other)),
                };
                // The head has relayed every block below it in order; the
                // state relayed now must be no older than those.
                let not_before = height.max(self.current_block.saturating_sub(1));
                self.relay_wallet_state_at_final(&wallet_pubkey, &owner, not_before)
                    .await
                    .map_err(|e| format!("wallet {} not synced from the final block: {}", wallet_pubkey, e))
            }
        }
    }

    /// Relay an event as it says. `Err` only for a failure the event is
    /// delivered again for; every other failure is logged, as delivering it
    /// again cannot help.
    async fn relay_as_is(&self, event: ContractEvent, height: u64) -> std::result::Result<(), String> {
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
                            "Subscription purchase in block {} could not be relayed: {:#}",
                            height, e
                        );
                        return Err("a subscription purchase could not be relayed".to_string());
                    }
                }
            }
        }
        Ok(())
    }

    /// Relay the wallet's policy and freeze as the final block holds them,
    /// instead of an event a newer one may have replaced: the coordinator
    /// applies what it is sent. No policy on chain is a deletion. A final
    /// block below `not_before` may predate what was already relayed, and is
    /// no answer.
    async fn relay_wallet_state_at_final(&self, wallet_pubkey: &str, event_owner: &str, not_before: u64) -> Result<()> {
        let (policy, at) = self
            .view_final("get_wallet_policy", &serde_json::json!({ "wallet_pubkey": wallet_pubkey }))
            .await?;
        if at < not_before {
            anyhow::bail!("the RPC's final block {} is behind block {}", at, not_before);
        }
        if policy.is_null() {
            info!("🔁 Wallet {}: no policy at final block {}; relaying the deletion", wallet_pubkey, at);
            return self.api_client.notify_wallet_policy_deleted(wallet_pubkey, event_owner).await;
        }
        let owner = policy.get("owner").and_then(Value::as_str).context("get_wallet_policy: no owner")?;
        let encrypted_data = policy
            .get("encrypted_data")
            .and_then(Value::as_str)
            .context("get_wallet_policy: no encrypted_data")?;
        let frozen = policy.get("frozen").and_then(Value::as_bool).context("get_wallet_policy: no frozen")?;
        info!("🔁 Wallet {}: relaying the policy at final block {} (frozen={})", wallet_pubkey, at, frozen);
        self.api_client
            .notify_wallet_policy_updated(wallet_pubkey, owner, encrypted_data, frozen)
            .await
    }

    /// Whether the payment key `owner`:`nonce` exists at the final block, and
    /// that block's height.
    async fn payment_key_exists_at_final(&self, owner: &str, nonce: u32) -> Result<(bool, u64)> {
        let args = serde_json::json!({
            "accessor": { "System": "PaymentKey" },
            "profile": nonce.to_string(),
            "owner": owner,
        });
        let (exists, at) = self.view_final("secrets_exist", &args).await?;
        Ok((exists.as_bool().context("secrets_exist answered something other than a bool")?, at))
    }

    /// Read the blocks just before `start_block` for `Delegate` actions only.
    /// A block that cannot be read is skipped: at worst a meta-transaction
    /// whose delegate ran in it is read as a contract call.
    async fn backfill_delegated(&self, start_block: u64) {
        for block_id in start_block.saturating_sub(DELEGATED_BACKFILL_BLOCKS)..start_block {
            match self.read_once(block_id, READ_TIMEOUT).await {
                Ok(block) => {
                    let mut delegated = self.delegated.lock().unwrap_or_else(|e| e.into_inner());
                    for shard in block.shards.iter().flatten() {
                        for outcome in shard.receipt_execution_outcomes.iter().flatten() {
                            delegated.record(outcome, self.contract_id.as_str(), block_id);
                        }
                    }
                }
                Err(e) => warn!("Delegate backfill: block {} not read: {}", block_id, e),
            }
        }
    }

    /// Load block data from neardata.xyz API, the whole read — body
    /// included — within `timeout`.
    async fn read_once(&self, block_id: u64, timeout: Duration) -> Result<BlockData> {
        let url = self.neardata_api_url.replace("{block_id}", &block_id.to_string());

        let response = self
            .http_client
            .get(&url)
            .timeout(timeout)
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
        let mut delegated = self.delegated.lock().unwrap_or_else(|e| e.into_inner());
        delegated.prune(block_height);
        for shard in shards {
            for outcome in shard.receipt_execution_outcomes.iter().flatten() {
                delegated.record(outcome, self.contract_id.as_str(), block_height);
            }
        }

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
                                            let meta = receipt_id.as_deref().and_then(|id| {
                                                delegated.meta_transaction(id, predecessor_id.as_deref(), signer_id.as_deref())
                                            });
                                            if let Some(meta) = meta {
                                                exec_event.relayer_id = Some(meta.relayer_id);
                                                exec_event.signer_public_key = meta.sender_public_key;
                                            }
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

        // Who the run is for. A meta-transaction's signer is its relayer, who
        // only paid the gas; the call is the account that signed the delegate
        // action, which is the receipt's predecessor.
        let user_account_id = match event.relayer_id.as_deref() {
            Some(relayer) => {
                let user = request_data.predecessor_id.clone().or_else(|| event.predecessor_id.clone()).ok_or_else(|| {
                    anyhow::anyhow!(
                        "Refusing execution_requested for request_id={}: a meta-transaction relayed by {} names no predecessor",
                        request_data.request_id, relayer
                    )
                })?;
                info!("🔁 request_id={}: meta-transaction signed by {} and relayed by {}", request_data.request_id, user, relayer);
                user
            }
            None => request_data.sender_id.clone(),
        };

        // Build execution context
        let context = crate::api_client::ExecutionContext {
            sender_id: Some(user_account_id.clone()),
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
            relayer_id: event.relayer_id.clone(),
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
            user_account_id: Some(user_account_id),
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

    // ============ meta-transactions ============
    //
    // Fixtures: mainnet blocks 217910341 (the `Delegate` receipt on
    // jars-oracle.sweat, relayed by sweat-relayer.near) and 217910342 (the
    // receipt it made, reaching v2.jars.sweat), trimmed.

    const DELEGATE_TARGET: &str = "v2.jars.sweat";
    const DELEGATE_SENDER: &str = "jars-oracle.sweat";
    const DELEGATE_RELAYER: &str = "sweat-relayer.near";
    const DELEGATED_CHILD: &str = "EXwNf6hCfyqvN3YwwK1v4fcVJayNafT8YoxY6883FtYo";

    fn delegate_parent() -> Value {
        serde_json::from_str(include_str!("testdata/neardata_delegate_parent.json")).unwrap()
    }

    fn outcome(v: Value) -> ReceiptExecutionOutcome {
        serde_json::from_value(v).unwrap()
    }

    fn recorded(parent: Value, contract: &str) -> DelegatedCalls {
        let mut calls = DelegatedCalls::default();
        calls.record(&outcome(parent), contract, 217910341);
        calls
    }

    #[test]
    fn a_delegated_receipt_is_known_by_its_parent() {
        let calls = recorded(delegate_parent(), DELEGATE_TARGET);
        let meta = MetaTransaction {
            relayer_id: DELEGATE_RELAYER.to_string(),
            sender_public_key: Some("ed25519:j1ahz6PGEhwSR8Prscow95PnykimghhdLsfjgCP4ktr".to_string()),
        };
        assert_eq!(calls.meta_transaction(DELEGATED_CHILD, Some(DELEGATE_SENDER), Some(DELEGATE_RELAYER)), Some(meta.clone()));
        // Asked again, as a block scanned twice asks: the same answer.
        assert_eq!(calls.meta_transaction(DELEGATED_CHILD, Some(DELEGATE_SENDER), Some(DELEGATE_RELAYER)), Some(meta));
    }

    #[test]
    fn the_delegated_receipt_itself_carries_no_trace_of_the_delegate() {
        let child: Value = serde_json::from_str(include_str!("testdata/neardata_delegate_child.json")).unwrap();
        assert_eq!(child["receipt"]["predecessor_id"], DELEGATE_SENDER);
        assert_eq!(child["receipt"]["receipt"]["Action"]["signer_id"], DELEGATE_RELAYER);
        let mut calls = DelegatedCalls::default();
        calls.record(&outcome(child), DELEGATE_TARGET, 217910342);
        assert!(calls.by_receipt.is_empty(), "only the parent names the delegate");
    }

    #[test]
    fn only_delegates_to_this_contract_are_remembered() {
        assert!(recorded(delegate_parent(), "outlayer.near").by_receipt.is_empty());
    }

    #[test]
    fn a_delegated_receipt_must_match_its_delegate() {
        let calls = recorded(delegate_parent(), DELEGATE_TARGET);
        assert!(calls.meta_transaction(DELEGATED_CHILD, Some("someone.near"), Some(DELEGATE_RELAYER)).is_none());
        assert!(calls.meta_transaction(DELEGATED_CHILD, Some(DELEGATE_SENDER), Some("someone.near")).is_none());
        assert!(calls.meta_transaction(DELEGATED_CHILD, None, Some(DELEGATE_RELAYER)).is_none());
        assert!(calls.meta_transaction("other", Some(DELEGATE_SENDER), Some(DELEGATE_RELAYER)).is_none());
    }

    #[test]
    fn a_delegate_its_sender_relayed_is_a_direct_call() {
        let mut parent = delegate_parent();
        parent["receipt"]["receipt"]["Action"]["signer_id"] = DELEGATE_SENDER.into();
        let calls = recorded(parent, DELEGATE_TARGET);
        assert!(calls.meta_transaction(DELEGATED_CHILD, Some(DELEGATE_SENDER), Some(DELEGATE_SENDER)).is_none());
    }

    #[test]
    fn a_failed_delegate_made_nothing() {
        let mut parent = delegate_parent();
        parent["execution_outcome"]["outcome"]["status"] = serde_json::json!({"Failure": {"ActionError": {}}});
        assert!(recorded(parent, DELEGATE_TARGET).by_receipt.is_empty());
    }

    /// The whole path on a monitor: the block with the `Delegate`, then the
    /// block where the delegated `request_execution` writes its event.
    #[test]
    fn a_meta_transaction_event_names_its_relayer() {
        let monitor = parsing_monitor();
        let contract = "outlayer.testnet";
        let (sender, relayer) = ("alice.near", "relay.near");

        let mut parent = delegate_parent();
        let delegate = &mut parent["receipt"]["receipt"]["Action"]["actions"][0]["Delegate"]["delegate_action"];
        delegate["receiver_id"] = contract.into();
        delegate["sender_id"] = sender.into();
        parent["receipt"]["receiver_id"] = sender.into();
        parent["receipt"]["receipt"]["Action"]["signer_id"] = relayer.into();

        let (raw, _) = genuine();
        let log = format!(
            "EVENT_JSON:{}",
            serde_json::json!({"standard": "near-outlayer", "version": "1.0.0", "event": "execution_requested",
                "data": [{"request_data": raw.to_string(), "data_id": DATA_ID.to_vec(), "timestamp": 1}]})
        );
        let child_for = |receipt_id: &str| {
            let mut child: Value = serde_json::from_str(include_str!("testdata/neardata_delegate_child.json")).unwrap();
            child["receipt"]["receipt_id"] = receipt_id.into();
            child["receipt"]["receiver_id"] = contract.into();
            child["receipt"]["predecessor_id"] = sender.into();
            child["receipt"]["receipt"]["Action"]["signer_id"] = relayer.into();
            child["execution_outcome"]["outcome"]["logs"] = serde_json::json!([log]);
            child
        };
        let shards = |outcomes: Vec<Value>| -> Vec<ShardData> {
            serde_json::from_value(serde_json::json!([{"receipt_execution_outcomes": outcomes}])).unwrap()
        };

        assert!(monitor.process_shards(&shards(vec![parent]), 100).unwrap().is_empty());
        let events = monitor
            .process_shards(&shards(vec![child_for(DELEGATED_CHILD), child_for("NotDelegated")]), 101)
            .unwrap();
        let seen: Vec<(Option<String>, Option<String>)> = events
            .iter()
            .map(|e| match e {
                ContractEvent::ExecutionRequested(e) => (e.relayer_id.clone(), e.signer_public_key.clone()),
                other => panic!("{other:?}"),
            })
            .collect();
        let relayer_key = "ed25519:AddAbvFQifGdE5yDjR3HKGN2BUDDWKA5HxNLp4E5fiYZ".to_string();
        let sender_key = "ed25519:j1ahz6PGEhwSR8Prscow95PnykimghhdLsfjgCP4ktr".to_string();
        assert_eq!(
            seen,
            vec![(Some(relayer.to_string()), Some(sender_key)), (None, Some(relayer_key))],
            "a meta-transaction carries the sender's key, anything else the receipt's"
        );
    }

    #[test]
    fn a_remembered_delegate_expires() {
        let mut calls = recorded(delegate_parent(), DELEGATE_TARGET);
        calls.prune(217910341 + DELEGATED_TTL_BLOCKS);
        assert_eq!(calls.by_receipt.len(), 2);
        calls.prune(217910341 + DELEGATED_TTL_BLOCKS + 1);
        assert!(calls.by_receipt.is_empty());
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
            relayer_id: None,
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
    pub(super) fn parsing_monitor() -> EventMonitor {
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
            delegated: std::sync::Mutex::new(DelegatedCalls::default()),
            deferred: DeferredBlocks::default(),
            tip: std::sync::Mutex::new(None),
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

#[cfg(test)]
mod late_and_out_of_order {
    //! A block can reach the monitor late (older than the yield window) or
    //! out of order (a deferred block read after newer ones). What each event
    //! may do then is decided in one place, and the queue that holds the
    //! unread blocks keeps each block once and gives up only what it says.
    use super::*;
    use tokio::time::Instant;

    const OWNER: &str = "alice.testnet";
    const ON_TIME: Age = Age::Blocks(LATE_AFTER_BLOCKS);
    const LATE: Age = Age::Blocks(LATE_AFTER_BLOCKS + 1);

    fn execution(signer: Option<&str>, predecessor: Option<&str>, relayer: Option<&str>) -> ContractEvent {
        ContractEvent::ExecutionRequested(ExecutionRequestedEvent {
            request_data: "{}".to_string(),
            data_id: vec![0; 32],
            timestamp: 1,
            block_height: 9,
            transaction_hash: None,
            receipt_id: None,
            predecessor_id: predecessor.map(str::to_string),
            signer_id: signer.map(str::to_string),
            signer_public_key: None,
            gas_burnt: None,
            relayer_id: relayer.map(str::to_string),
        })
    }

    fn topup(amount: &str) -> ContractEvent {
        ContractEvent::TopUpPaymentKey(TopUpPaymentKeyEvent {
            data_id: vec![1; 32],
            owner: OWNER.to_string(),
            nonce: 3,
            amount: amount.to_string(),
            encrypted_data: "blob".to_string(),
        })
    }

    fn delete() -> ContractEvent {
        ContractEvent::DeletePaymentKey(DeletePaymentKeyEvent { data_id: vec![2; 32], owner: OWNER.to_string(), nonce: 3 })
    }

    fn wallet_events() -> Vec<ContractEvent> {
        vec![
            ContractEvent::WalletPolicyUpdated(WalletPolicyUpdatedEvent {
                wallet_pubkey: "ed25519:ab".to_string(),
                owner: OWNER.to_string(),
                encrypted_data: "blob".to_string(),
                frozen: false,
            }),
            ContractEvent::WalletPolicyDeleted(WalletPolicyDeletedEvent {
                wallet_pubkey: "ed25519:ab".to_string(),
                owner: OWNER.to_string(),
            }),
            ContractEvent::WalletFrozenChanged(WalletFrozenChangedEvent {
                wallet_pubkey: "ed25519:ab".to_string(),
                owner: OWNER.to_string(),
                frozen: false,
            }),
        ]
    }

    fn order_free() -> Vec<ContractEvent> {
        vec![
            ContractEvent::SubscriptionPurchased(SubscriptionPurchasedEvent {
                owner: OWNER.to_string(),
                nonce: 3,
                plan: 1,
                paid_usd: "1".to_string(),
                payer: OWNER.to_string(),
                receipt_id: Some("r".to_string()),
            }),
            ContractEvent::ProjectStorageCleanup(ProjectStorageCleanupEvent {
                project_id: "alice/p".to_string(),
                project_uuid: "u".to_string(),
                timestamp: 1,
                block_height: 9,
            }),
            ContractEvent::ProjectTransferred(ProjectTransferredEvent {
                old_project_id: "alice/p".to_string(),
                new_project_id: "bob/p".to_string(),
                project_uuid: "u".to_string(),
                old_owner: OWNER.to_string(),
                new_owner: "bob.testnet".to_string(),
            }),
        ]
    }

    #[test]
    fn an_execution_in_order_and_on_time_is_relayed_and_any_other_is_checked_at_final() {
        let e = execution(Some(OWNER), Some(OWNER), None);
        assert_eq!(relay_decision(&e, Delivery::InOrder, ON_TIME), Relay::AsIs);
        assert_eq!(relay_decision(&e, Delivery::InOrder, LATE), Relay::IfPendingAtFinal);
        assert_eq!(relay_decision(&e, Delivery::InOrder, Age::Unknown), Relay::IfPendingAtFinal);
        assert_eq!(relay_decision(&e, Delivery::OutOfOrder, ON_TIME), Relay::IfPendingAtFinal);
    }

    /// The chain decides a late top-up: a refused resume is not credited.
    #[test]
    fn a_top_up_is_relayed_late_and_out_of_order() {
        for delivery in [Delivery::InOrder, Delivery::OutOfOrder] {
            for age in [ON_TIME, LATE, Age::Unknown] {
                assert_eq!(relay_decision(&topup("5"), delivery, age), Relay::AsIs);
            }
        }
    }

    /// A creation read after the key's deletion must not bring the key back.
    #[test]
    fn a_key_creation_out_of_order_is_relayed_only_if_the_key_still_exists() {
        assert_eq!(relay_decision(&topup("0"), Delivery::InOrder, LATE), Relay::AsIs);
        assert_eq!(relay_decision(&topup("0"), Delivery::OutOfOrder, ON_TIME), Relay::IfKeyExistsAtFinal);
    }

    /// The coordinator deletes before the resume: a late delete would leave
    /// the key deleted here and kept on chain. An unknown age is asked again.
    #[test]
    fn a_delete_is_relayed_only_while_its_yield_is_surely_open() {
        for delivery in [Delivery::InOrder, Delivery::OutOfOrder] {
            assert_eq!(relay_decision(&delete(), delivery, ON_TIME), Relay::AsIs);
            assert!(matches!(relay_decision(&delete(), delivery, LATE), Relay::Drop(_)));
            assert!(matches!(relay_decision(&delete(), delivery, Age::Unknown), Relay::Later(_)));
        }
    }

    /// An older policy or freeze applied after a newer one would restore a
    /// revoked key or unfreeze a wallet.
    #[test]
    fn a_wallet_event_out_of_order_relays_the_state_at_final() {
        for e in wallet_events() {
            assert_eq!(relay_decision(&e, Delivery::InOrder, LATE), Relay::AsIs);
            assert_eq!(relay_decision(&e, Delivery::OutOfOrder, ON_TIME), Relay::WalletStateAtFinal);
        }
    }

    #[test]
    fn order_free_events_are_relayed_from_every_delivery() {
        for e in order_free() {
            for delivery in [Delivery::InOrder, Delivery::OutOfOrder] {
                for age in [ON_TIME, LATE, Age::Unknown] {
                    assert_eq!(relay_decision(&e, delivery, age), Relay::AsIs);
                }
            }
        }
    }

    #[test]
    fn a_call_signed_for_another_account_with_no_delegate_found_may_be_a_meta_transaction() {
        assert!(may_be_unattributed_meta_tx(&execution(Some("relayer.testnet"), Some(OWNER), None)));
        assert!(!may_be_unattributed_meta_tx(&execution(Some("relayer.testnet"), Some(OWNER), Some("relayer.testnet"))));
        assert!(!may_be_unattributed_meta_tx(&execution(Some(OWNER), Some(OWNER), None)));
        assert!(!may_be_unattributed_meta_tx(&topup("5")));
    }

    #[test]
    fn a_deferred_block_is_due_after_its_pause_and_backs_off() {
        let now = Instant::now();
        let mut q = DeferredBlocks::default();
        assert!(q.defer(100, now).is_none());
        assert!(q.due(now, 3).is_empty());
        assert_eq!(q.due(now + DEFERRED_PAUSES[0], 3), vec![100]);
        q.retry_later(100, None, now);
        assert!(q.due(now + DEFERRED_PAUSES[0], 3).is_empty());
        assert_eq!(q.due(now + DEFERRED_PAUSES[1], 3), vec![100]);
        for _ in 0..20 {
            q.retry_later(100, None, now);
        }
        assert_eq!(q.due(now + *DEFERRED_PAUSES.last().unwrap(), 3), vec![100]);
        q.remove(100);
        assert_eq!(q.len(), 0);
    }

    #[test]
    fn the_oldest_due_blocks_come_first_and_at_most_the_limit() {
        let now = Instant::now();
        let mut q = DeferredBlocks::default();
        for h in [105, 101, 103, 102] {
            q.defer(h, now);
        }
        assert_eq!(q.due(now + DEFERRED_PAUSES[0], 3), vec![101, 102, 103]);
    }

    #[test]
    fn a_block_too_far_behind_the_head_is_given_up() {
        let now = Instant::now();
        let mut q = DeferredBlocks::default();
        q.defer(1_000, now);
        q.defer(1_001, now);
        assert!(q.expire(1_000 + DEFERRED_MAX_AGE_BLOCKS, now).is_empty());
        let given_up: Vec<u64> = q.expire(1_001 + DEFERRED_MAX_AGE_BLOCKS, now).into_iter().map(|(h, _)| h).collect();
        assert_eq!(given_up, vec![1_000]);
        assert_eq!(q.heights(), vec![1_001]);
    }

    #[test]
    fn a_full_queue_gives_up_its_oldest_block() {
        let now = Instant::now();
        let mut q = DeferredBlocks::default();
        for h in 0..DEFERRED_MAX_LEN as u64 {
            assert!(q.defer(10_000 + h, now).is_none());
        }
        assert_eq!(q.defer(20_000, now).map(|(h, _)| h), Some(10_000));
        assert_eq!(q.len(), DEFERRED_MAX_LEN);
    }

    /// A call that may be a meta-transaction, with its delegate's block
    /// unread, is not relayed under a guessed door: the block waits, before
    /// anything in it is relayed.
    #[tokio::test]
    async fn a_block_with_a_possible_meta_transaction_waits_for_an_unread_block_before_it() {
        let mut monitor = super::tests::parsing_monitor();
        monitor.deferred.defer(100, Instant::now());
        let call = execution(Some("relayer.testnet"), Some(OWNER), None);
        for delivery in [Delivery::InOrder, Delivery::OutOfOrder] {
            let left = monitor.deliver(101, vec![call.clone()], delivery).await.expect("the call waits");
            assert!(left.waits);
            assert_eq!(left.events.len(), 1);
        }
    }

    #[tokio::test]
    async fn a_block_without_events_is_delivered_at_once() {
        let monitor = super::tests::parsing_monitor();
        assert!(monitor.deliver(101, vec![], Delivery::OutOfOrder).await.is_none());
    }

    /// A block read and kept only for events still to deliver has had its
    /// delegates recorded: it makes nothing wait, so waits do not chain.
    #[test]
    fn a_read_block_in_the_queue_makes_nothing_wait() {
        let now = Instant::now();
        let mut q = DeferredBlocks::default();
        q.keep(100, vec![topup("5")], now);
        assert!(!q.unread_just_before(101));
        assert_eq!(q.events(100).map(|e| e.len()), Some(1));
        assert!(q.events(99).is_none());
    }

    /// When an unread block is given up, the blocks that waited for it are
    /// tried at once rather than aging out behind it.
    #[test]
    fn giving_up_an_unread_block_releases_the_blocks_that_waited_for_it() {
        let now = Instant::now();
        let mut q = DeferredBlocks::default();
        q.defer(1_000, now);
        q.keep(1_001, vec![execution(Some("relayer.testnet"), Some(OWNER), None)], now);
        q.retry_later(1_001, None, now);
        let later = now + Duration::from_secs(1);
        let given_up = q.expire(1_001 + DEFERRED_MAX_AGE_BLOCKS, later);
        assert_eq!(given_up.len(), 1);
        assert_eq!(q.due(later, 3), vec![1_001]);
        assert!(!q.unread_just_before(1_001));
    }

    /// A read block is kept twice as long as an unread one before it is
    /// given up.
    #[test]
    fn a_read_block_outlives_an_unread_one() {
        let now = Instant::now();
        let mut q = DeferredBlocks::default();
        q.keep(1_000, vec![topup("5")], now);
        assert!(q.expire(1_001 + DEFERRED_MAX_AGE_BLOCKS, now).is_empty());
        assert_eq!(q.expire(1_001 + 2 * DEFERRED_MAX_AGE_BLOCKS, now).len(), 1);
    }

    #[test]
    fn an_unread_block_just_before_is_seen_and_one_further_back_is_not() {
        let now = Instant::now();
        let mut q = DeferredBlocks::default();
        q.defer(100, now);
        assert!(q.unread_just_before(101));
        assert!(q.unread_just_before(100 + DELEGATE_LOOKBACK_BLOCKS));
        assert!(!q.unread_just_before(101 + DELEGATE_LOOKBACK_BLOCKS));
        assert!(!q.unread_just_before(100));
    }
}

#[cfg(test)]
mod head_never_waits_on_one_block {
    //! The monitor's loop against a fake neardata: one block that will not
    //! read is deferred and read later while the head moves on; neardata down
    //! as a whole holds the head, so nothing is read out of order.
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    type Script = Arc<dyn Fn(u64, usize) -> u16 + Send + Sync>;

    /// A neardata answering `GET /block/{n}` with the status `script(n, nth
    /// request for n)` gives — 200 an empty block, 404 not indexed, anything
    /// else an error — and the order the blocks were asked for.
    async fn fake_neardata(script: Script) -> (String, Arc<Mutex<Vec<u64>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/block/{{block_id}}", listener.local_addr().unwrap());
        let asked = Arc::new(Mutex::new(Vec::new()));
        let counts = Arc::new(Mutex::new(HashMap::<u64, usize>::new()));
        let log = asked.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else { return };
                let (script, log, counts) = (script.clone(), log.clone(), counts.clone());
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = socket.read(&mut buf).await.unwrap_or(0);
                    let request = String::from_utf8_lossy(&buf[..n]);
                    let height: u64 = request
                        .split_whitespace()
                        .nth(1)
                        .and_then(|path| path.rsplit('/').next())
                        .and_then(|h| h.parse().ok())
                        .unwrap_or(0);
                    log.lock().unwrap().push(height);
                    let nth = {
                        let mut counts = counts.lock().unwrap();
                        let c = counts.entry(height).or_insert(0);
                        *c += 1;
                        *c
                    };
                    let status = script(height, nth);
                    let body = if status == 200 { r#"{"shards":[]}"# } else { "" };
                    let response = format!(
                        "HTTP/1.1 {} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        status,
                        body.len(),
                        body
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
        });
        (url, asked)
    }

    fn monitor_at(url: String, head: u64) -> (EventMonitor, Arc<AtomicU64>) {
        let mut monitor = super::tests::parsing_monitor();
        monitor.neardata_api_url = url;
        monitor.current_block = head;
        let shared = Arc::new(AtomicU64::new(head));
        monitor.shared_block_height = shared.clone();
        (monitor, shared)
    }

    #[tokio::test]
    async fn one_unreadable_block_is_deferred_and_read_after_the_head_moved_on() {
        // Block 1001 fails until the head has gone past it; 1010 is the tip.
        let script: Script = Arc::new(|h, nth| match h {
            1001 if nth <= 8 => 500,
            1010.. => 404,
            _ => 200,
        });
        let (url, asked) = fake_neardata(script).await;
        let (mut monitor, head) = monitor_at(url, 1000);
        let run = tokio::spawn(async move { monitor.start_monitoring().await });

        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        loop {
            let asked = asked.lock().unwrap().clone();
            let read_after_moving_on = asked
                .iter()
                .position(|h| *h == 1002)
                .is_some_and(|first_1002| asked[first_1002..].contains(&1001));
            if head.load(Ordering::Relaxed) == 1010 && read_after_moving_on {
                break;
            }
            assert!(tokio::time::Instant::now() < deadline, "head {:?}, asked {:?}", head, asked);
            sleep(Duration::from_millis(200)).await;
        }
        run.abort();
    }

    #[tokio::test]
    async fn neardata_down_holds_the_head_and_nothing_is_read_out_of_order() {
        // Everything from 1001 on fails for the first 25 s, then reads.
        let down_until = std::time::Instant::now() + Duration::from_secs(25);
        let script: Script = Arc::new(move |h, _| match h {
            1010.. => 404,
            1001.. if std::time::Instant::now() < down_until => 503,
            _ => 200,
        });
        let (url, asked) = fake_neardata(script).await;
        let (mut monitor, head) = monitor_at(url, 1000);
        let run = tokio::spawn(async move { monitor.start_monitoring().await });

        let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
        while head.load(Ordering::Relaxed) < 1010 {
            assert!(tokio::time::Instant::now() < deadline, "head stuck at {:?}", head);
            sleep(Duration::from_millis(200)).await;
        }
        run.abort();
        // Once the head first READ past 1001, no block below the head was
        // asked for again: nothing was deferred.
        let asked = asked.lock().unwrap().clone();
        let mut highest_read = 0;
        for h in asked.iter().copied().filter(|h| *h >= 1001 && *h < 1010) {
            assert!(h + PROBE_AHEAD_BLOCKS >= highest_read, "block {} asked for after {}: {:?}", h, highest_read, asked);
            highest_read = highest_read.max(h);
        }
    }
}
