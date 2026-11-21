//! Receipt event sources.
//!
//! Production: a HTTP-based adapter (`LakeSource`) that polls
//! FastNEAR's `neardata.xyz` finalized-block feed (no AWS
//! credentials, no S3 — same JSON shape as the deprecated Pagoda
//! lake). See `LakeSource` below.
//!
//! Tests: an in-memory [`MockSource`] that yields a fixed sequence of
//! receipts. Used to drive the end-to-end pipeline test.

use std::collections::VecDeque;
use std::sync::Mutex;

use anyhow::{Context, Result};
use async_trait::async_trait;

use crate::types::{McpReceipt, StreamEvent, VaultEventReceipt};

#[async_trait]
pub trait ReceiptSource: Send + Sync {
    /// Block until the next event is available; return `None` when
    /// the source is permanently closed (test fixtures, manual
    /// shutdown). Production lake adapter never returns `None`.
    ///
    /// The single-trait shape replaces what would otherwise be two
    /// parallel sources (one for MPC receipts, one for vault
    /// contract logs): both are extracted from the same neardata
    /// block walk, so a single iterator + sum-typed event keeps
    /// the source-side code path identical for both event classes.
    async fn next(&self) -> Result<Option<StreamEvent>>;
}

// ─── Mock source for unit + integration tests ─────────────────────────────

pub struct MockSource {
    queue: Mutex<VecDeque<StreamEvent>>,
}

impl MockSource {
    /// Convenience: wrap a Vec<McpReceipt> so existing tests don't
    /// have to map to StreamEvent::Mcp manually.
    pub fn new(receipts: Vec<McpReceipt>) -> Self {
        Self {
            queue: Mutex::new(receipts.into_iter().map(StreamEvent::Mcp).collect()),
        }
    }
    /// New-style mock: yields a fixed sequence of typed events.
    pub fn from_events(events: Vec<StreamEvent>) -> Self {
        Self {
            queue: Mutex::new(VecDeque::from(events)),
        }
    }
}

#[async_trait]
impl ReceiptSource for MockSource {
    async fn next(&self) -> Result<Option<StreamEvent>> {
        let mut q = self.queue.lock().expect("mutex poison");
        Ok(q.pop_front())
    }
}

// ─── FastNEAR neardata.xyz adapter ────────────────────────────────────────
//
// Polls the public HTTPS feed at `https://{network}.neardata.xyz`:
//   * `GET /v0/last_block/final` → current finality height
//   * `GET /v0/block/{height}`   → full block in the same JSON shape
//                                  near-lake-framework consumers used
//
// Filter shape on each block:
//   shards[*].receipt_execution_outcomes[*].receipt.receipt.Action.actions[]
//   where:
//     * receipt.receiver_id == mpc_contract_id
//     * action == FunctionCall { method_name: "request_app_private_key", args: <b64> }
//   args is base64-encoded JSON; we decode it to extract `derivation_path`.
//   `predecessor_id` from `receipt` is the vault, `tx_hash` from the outcome
//   wrapper.
//
// Why this shape and not the alternatives:
//   * Pagoda's S3 `near-lake-framework` is no longer maintained; AWS
//     creds + S3 bucket access are unnecessary friction for a feature
//     where this project already uses FastNEAR (see project memory:
//     `rpc.mainnet.fastnear.com`).
//   * Self-hosted neard with indexer is the heavyweight alternative;
//     deferred until the monitor's volume justifies it.
//   * Polling is fine for our scale: a single MPC `request_app_private_key`
//     call per customer per first-derive (and ~per worker restart);
//     operationally a handful of relevant receipts per hour.
//
// Persistence:
//   The source persists its `last_processed_block` to a JSON
//   checkpoint file every block. On restart it reads the checkpoint
//   and resumes — no re-processing of already-handled receipts (the
//   keystore-worker's `/admin/ban-vault` is idempotent anyway, but
//   spam-replay across restarts wastes RPC).
use std::path::PathBuf;
use std::sync::Mutex as StdMutex;
use std::time::Duration;

use base64::Engine as _;

#[derive(Clone)]
pub struct LakeSourceConfig {
    /// Filter MPC receipts for this contract id. Mainnet:
    /// `v1.signer`. Testnet: `v1.signer-prod.testnet`.
    pub mpc_contract_id: String,
    /// keystore-DAO account id — source of `vault_banned` /
    /// `vault_unbanned` / `vault_verified` log events that the
    /// monitor forwards to the coordinator. Mainnet:
    /// `dao.outlayer.near`. Testnet: `dao.outlayer.testnet`. Set
    /// to empty string to disable vault-event forwarding entirely
    /// (race-attack monitor still works).
    pub keystore_dao_id: String,
    /// First block height to fetch on a fresh deploy. Ignored if a
    /// checkpoint file exists (resume wins). Operator should set this
    /// to a recent finality height when starting from scratch.
    pub start_block_height: u64,
    /// "mainnet" or "testnet" — selects the neardata subdomain.
    /// Cross-check RPC URL lives on the forwarder, not the source,
    /// because the source itself never makes view-calls.
    pub network: String,
    /// Path to the JSON checkpoint file. `None` disables persistence
    /// (in-memory state only — the audit-flagged case where restarts
    /// lose the dedup window). Set in production.
    pub checkpoint_path: Option<PathBuf>,
}

pub struct LakeSource {
    pub config: LakeSourceConfig,
    client: reqwest::Client,
    base_url: String,
    /// Buffered receipts already extracted from a block; consumed by
    /// successive `next()` calls before the next block fetch.
    state: tokio::sync::Mutex<StreamState>,
    /// Sync mutex around the checkpoint file path — write-side only,
    /// not held across awaits.
    checkpoint_lock: StdMutex<()>,
}

struct StreamState {
    /// Next block height to fetch. Initialised from checkpoint or
    /// `start_block_height`.
    next_height: u64,
    /// Events pulled from the most-recent block, awaiting delivery.
    buffer: std::collections::VecDeque<StreamEvent>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct CheckpointFile {
    /// Bumped on incompatible format changes.
    version: u32,
    last_processed_block: u64,
}

impl LakeSource {
    pub fn new(config: LakeSourceConfig) -> Self {
        let base_url = format!("https://{}.neardata.xyz", config.network);
        let next_height = match &config.checkpoint_path {
            Some(p) if p.exists() => match Self::read_checkpoint(p) {
                Ok(cp) => {
                    tracing::info!(
                        path = %p.display(),
                        last_processed_block = cp.last_processed_block,
                        "resuming from checkpoint"
                    );
                    cp.last_processed_block + 1
                }
                Err(e) => {
                    tracing::warn!(
                        path = %p.display(),
                        error = %e,
                        start_block_height = config.start_block_height,
                        "checkpoint unreadable; falling back to --start-block"
                    );
                    config.start_block_height
                }
            },
            _ => config.start_block_height,
        };
        Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("reqwest client"),
            base_url,
            state: tokio::sync::Mutex::new(StreamState {
                next_height,
                buffer: Default::default(),
            }),
            checkpoint_lock: StdMutex::new(()),
            config,
        }
    }

    fn read_checkpoint(path: &std::path::Path) -> Result<CheckpointFile> {
        let bytes = std::fs::read(path)?;
        let cp: CheckpointFile = serde_json::from_slice(&bytes)?;
        if cp.version != 1 {
            anyhow::bail!("checkpoint version {} not supported", cp.version);
        }
        Ok(cp)
    }

    /// Atomic write: tmp + rename. Holding the sync lock guarantees
    /// concurrent `next()` calls don't interleave checkpoint writes.
    fn write_checkpoint(&self, last_processed_block: u64) -> Result<()> {
        let Some(ref path) = self.config.checkpoint_path else {
            return Ok(());
        };
        let _g = self.checkpoint_lock.lock().expect("checkpoint mutex");
        let tmp = path.with_extension("checkpoint.tmp");
        let cp = CheckpointFile {
            version: 1,
            last_processed_block,
        };
        let bytes = serde_json::to_vec(&cp)?;
        std::fs::write(&tmp, &bytes)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Fetch one block's worth of relevant receipts. Returns `Ok(0)`
    /// when caught up to finality (caller should sleep and retry).
    /// Returns `Ok(n)` where n is how many receipts were appended to
    /// the buffer.
    async fn fetch_one_block(&self, state: &mut StreamState) -> Result<usize> {
        // Ensure we're not running ahead of finality.
        let last_final: u64 = self
            .client
            .get(format!("{}/v0/last_block/final", self.base_url))
            .send()
            .await
            .context("fetch /v0/last_block/final")?
            .error_for_status()?
            .json::<serde_json::Value>()
            .await
            .context("parse /v0/last_block/final")?
            .pointer("/block/header/height")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| anyhow::anyhow!("missing block.header.height in last_block response"))?;

        if state.next_height > last_final {
            return Ok(0);
        }

        let h = state.next_height;
        let block_url = format!("{}/v0/block/{}", self.base_url, h);
        let resp = self.client.get(&block_url).send().await
            .with_context(|| format!("fetch {block_url}"))?;
        // 404 = block was skipped (NEAR has missing-block heights);
        // advance and continue.
        if resp.status().as_u16() == 404 {
            state.next_height += 1;
            self.write_checkpoint(h)?;
            return Ok(0);
        }
        let block: serde_json::Value = resp
            .error_for_status()
            .with_context(|| format!("status from {block_url}"))?
            .json()
            .await
            .with_context(|| format!("parse {block_url}"))?;

        let count_before = state.buffer.len();
        self.extract_receipts(&block, h, &mut state.buffer);
        let count = state.buffer.len() - count_before;

        state.next_height = h + 1;
        // Checkpoint AFTER extraction: if extraction crashes mid-block
        // we replay the same block on restart — buffered receipts are
        // not yet persisted, but the detector's eviction-on-write
        // makes a single double-process harmless (vault gets the same
        // verdict either way). Persisting before extraction would
        // risk dropping receipts on crash.
        if let Err(e) = self.write_checkpoint(h) {
            tracing::warn!(
                block_height = h,
                error = %e,
                "checkpoint write failed; will retry on next block"
            );
        }
        Ok(count)
    }

    /// Walk the block JSON and append matching events to `out`.
    /// Two filter passes share the same outcome iteration:
    ///
    /// 1. **MPC receipts** — `receiver_id == mpc_contract_id` AND
    ///    `FunctionCall.method_name == "request_app_private_key"`.
    ///    Race-attack detector input.
    /// 2. **Vault contract logs** — outcome.logs contain a known
    ///    vault-event prefix (e.g. `recovery_initiated_unilateral`,
    ///    `vault_banned`) AND the executor_id is either a known
    ///    keystore-DAO account or any account that emitted such a
    ///    log (vault accounts emit their own recovery_* lines).
    ///    Webhook forwarder input.
    ///
    /// We look at `receipt_execution_outcomes` (not `chunk.receipts`)
    /// because filter applies to EXECUTED receipts — a tx that
    /// emitted the log but ran out of gas before execution doesn't
    /// produce a real on-chain effect.
    fn extract_receipts(
        &self,
        block: &serde_json::Value,
        block_height: u64,
        out: &mut std::collections::VecDeque<StreamEvent>,
    ) {
        let Some(shards) = block.get("shards").and_then(|s| s.as_array()) else {
            return;
        };
        for shard in shards {
            let Some(outcomes) = shard
                .get("receipt_execution_outcomes")
                .and_then(|o| o.as_array())
            else {
                continue;
            };
            for outcome in outcomes {
                let Some(receipt_wrapper) = outcome.get("receipt") else {
                    continue;
                };
                let receiver_id = receipt_wrapper
                    .get("receiver_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let predecessor = receipt_wrapper
                    .get("predecessor_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let receipt_id = receipt_wrapper
                    .get("receipt_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let tx_hash = outcome
                    .get("tx_hash")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                // ── Filter 1: MPC receipts (race-attack detection) ──
                if receiver_id == self.config.mpc_contract_id && !predecessor.is_empty() {
                    if let Some(actions) = receipt_wrapper
                        .pointer("/receipt/Action/actions")
                        .and_then(|a| a.as_array())
                    {
                        for action in actions {
                            let Some(fc) = action.get("FunctionCall") else {
                                continue;
                            };
                            let method_name =
                                fc.get("method_name").and_then(|v| v.as_str()).unwrap_or("");
                            if method_name != "request_app_private_key" {
                                continue;
                            }
                            let derivation_path = fc
                                .get("args")
                                .and_then(|v| v.as_str())
                                .and_then(|s| {
                                    base64::engine::general_purpose::STANDARD
                                        .decode(s)
                                        .ok()
                                        .and_then(|bytes| {
                                            serde_json::from_slice::<serde_json::Value>(&bytes).ok()
                                        })
                                })
                                .and_then(|args_json| {
                                    args_json
                                        .get("derivation_path")
                                        .and_then(|v| v.as_str())
                                        .map(|s| s.to_string())
                                })
                                .unwrap_or_default();
                            if derivation_path.is_empty() {
                                continue;
                            }
                            out.push_back(StreamEvent::Mcp(McpReceipt {
                                vault_id: predecessor.to_string(),
                                derivation_path,
                                block_height,
                                tx_hash: tx_hash.clone(),
                                receipt_id: receipt_id.clone(),
                            }));
                        }
                    }
                }

                // ── Filter 2: vault contract event logs ─────────────
                // Disabled if operator left keystore_dao_id empty.
                if self.config.keystore_dao_id.is_empty() {
                    continue;
                }
                let Some(logs) = outcome
                    .pointer("/execution_outcome/outcome/logs")
                    .and_then(|l| l.as_array())
                else {
                    continue;
                };
                let executor_id = outcome
                    .pointer("/execution_outcome/outcome/executor_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                for log in logs {
                    let Some(log_str) = log.as_str() else { continue };
                    let Some((event_type, vault_id)) =
                        parse_vault_log(log_str, &executor_id, &self.config.keystore_dao_id)
                    else {
                        continue;
                    };
                    out.push_back(StreamEvent::Vault(VaultEventReceipt {
                        emitting_account: executor_id.clone(),
                        vault_id,
                        event_type,
                        // Cap raw_log so a malicious-but-DAO-emitted
                        // log can't bloat the webhook payload past
                        // the keystore-DAO 256-byte limit.
                        raw_log: log_str.chars().take(256).collect(),
                        block_height,
                        tx_hash: tx_hash.clone(),
                        receipt_id: receipt_id.clone(),
                    }));
                }
            }
        }
    }
}

/// Parse a vault contract / keystore-DAO log line into a typed
/// `(event_type, vault_id)` pair. Returns `None` if the log doesn't
/// match any known vault-event prefix.
///
/// Two log shapes:
///   * **Vault-emitted** (executor_id == vault account): bare event
///     type, e.g. `recovery_initiated_unilateral`. The vault id is
///     `executor_id` itself.
///   * **DAO-emitted** (executor_id == keystore_dao_id): event
///     followed by the vault id, e.g. `vault_banned vault.alice.near`
///     or `vault_verified vault.alice.near`.
///
/// Whitelist matching: only events listed in the coordinator's
/// `ALLOWED_VAULT_EVENT_TYPES` (handlers.rs) are returned. Any
/// other log shape (gibberish, unrelated logs from the same account,
/// new event types we don't know about) is dropped silently — the
/// forwarder is permissive on input but strict on output.
pub(crate) fn parse_vault_log(
    log: &str,
    executor_id: &str,
    keystore_dao_id: &str,
) -> Option<(String, String)> {
    let trimmed = log.trim();

    // Vault-emitted events (executor_id is the vault itself).
    const VAULT_EVENTS: &[&str] = &[
        "recovery_initiated_cessation",
        "recovery_initiated_unilateral",
        "recovery_finalized_cessation",
        "recovery_finalized_unilateral",
        "recovery_finalize_swap_failed",
        "recovery_finalize_failed_dao_call",
        "recovery_window_expired",
        "recovery_cancelled_dao_revoked",
        "vault_tee_key_added",
        // `exit_window_set_to_<n>_secs`,
        // `exit_window_lowering_to_<n>_secs_effective_at_<ns>` and
        // `vault_tee_keys_cleared count=<n>` — dynamic suffixes,
        // special-cased below.
    ];
    for ev in VAULT_EVENTS {
        if trimmed == *ev {
            return Some((ev.to_string(), executor_id.to_string()));
        }
    }
    if trimmed.starts_with("exit_window_set_to_") && trimmed.ends_with("_secs") {
        return Some(("exit_window_set".to_string(), executor_id.to_string()));
    }
    if trimmed.starts_with("exit_window_lowering_to_") && trimmed.contains("_secs_effective_at_") {
        return Some(("exit_window_lowering".to_string(), executor_id.to_string()));
    }
    if trimmed.starts_with("vault_tee_keys_cleared") {
        return Some(("vault_tee_keys_cleared".to_string(), executor_id.to_string()));
    }

    // DAO-emitted events (executor_id == keystore_dao). Format:
    // `<event> <vault_id> [reason="..."]`.
    if executor_id != keystore_dao_id {
        return None;
    }
    const DAO_EVENTS: &[&str] = &["vault_banned", "vault_unbanned", "vault_verified"];
    for ev in DAO_EVENTS {
        if let Some(rest) = trimmed.strip_prefix(&format!("{ev} ")) {
            // Take the first whitespace-delimited token as vault_id;
            // anything after (e.g. `reason="..."`) is dropped, the
            // event_type is the canonical name without args.
            let vault_id = rest.split_whitespace().next().unwrap_or("").to_string();
            if vault_id.is_empty() {
                return None;
            }
            return Some((ev.to_string(), vault_id));
        }
    }
    None
}

#[async_trait]
impl ReceiptSource for LakeSource {
    async fn next(&self) -> Result<Option<StreamEvent>> {
        loop {
            let mut s = self.state.lock().await;
            if let Some(r) = s.buffer.pop_front() {
                return Ok(Some(r));
            }
            // Buffer empty → fetch next block. Drop the lock between
            // fetches if we're caught up so a parallel call can also
            // make progress (single-task in practice, but
            // defensive).
            match self.fetch_one_block(&mut s).await {
                Ok(0) => {
                    // Caught up. Drop the lock and back off.
                    drop(s);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                Ok(_) => {
                    // Fall through to re-check buffer on next iteration.
                }
                Err(e) => {
                    drop(s);
                    tracing::warn!(error = %e, "neardata fetch failed; retrying after backoff");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod parse_vault_log_tests {
    use super::parse_vault_log;

    const DAO: &str = "dao.outlayer.testnet";
    const VAULT: &str = "vault.alice.testnet";

    #[test]
    fn vault_emitted_recovery_initiated_unilateral() {
        assert_eq!(
            parse_vault_log("recovery_initiated_unilateral", VAULT, DAO),
            Some(("recovery_initiated_unilateral".into(), VAULT.into()))
        );
    }

    #[test]
    fn vault_emitted_recovery_finalized_cessation() {
        assert_eq!(
            parse_vault_log("recovery_finalized_cessation", VAULT, DAO),
            Some(("recovery_finalized_cessation".into(), VAULT.into()))
        );
    }

    #[test]
    fn vault_emitted_exit_window_lowering() {
        assert_eq!(
            parse_vault_log(
                "exit_window_lowering_to_86400_secs_effective_at_1700000000000000000",
                VAULT,
                DAO
            ),
            Some(("exit_window_lowering".into(), VAULT.into()))
        );
        // Not the line of a window that applies at once.
        assert_eq!(
            parse_vault_log("exit_window_set_to_86400_secs", VAULT, DAO),
            Some(("exit_window_set".into(), VAULT.into()))
        );
    }

    #[test]
    fn vault_emitted_exit_window_set_dynamic_suffix() {
        assert_eq!(
            parse_vault_log("exit_window_set_to_86400_secs", VAULT, DAO),
            Some(("exit_window_set".into(), VAULT.into()))
        );
        assert_eq!(
            parse_vault_log("exit_window_set_to_604800_secs", VAULT, DAO),
            Some(("exit_window_set".into(), VAULT.into()))
        );
    }

    #[test]
    fn vault_emitted_finalize_swap_failed() {
        // Contract emits this when the post-swap callback observes a
        // failed atomic-swap promise. Operator-visible signal that
        // the vault is still locked despite a finalize attempt.
        assert_eq!(
            parse_vault_log("recovery_finalize_swap_failed", VAULT, DAO),
            Some(("recovery_finalize_swap_failed".into(), VAULT.into()))
        );
    }

    #[test]
    fn vault_emitted_finalize_failed_dao_call() {
        assert_eq!(
            parse_vault_log("recovery_finalize_failed_dao_call", VAULT, DAO),
            Some(("recovery_finalize_failed_dao_call".into(), VAULT.into()))
        );
    }

    #[test]
    fn vault_emitted_tee_keys_cleared_dynamic_count() {
        // Has a dynamic `count=<n>` suffix — collapse to the stable
        // base event name so the webhook contract stays small.
        assert_eq!(
            parse_vault_log("vault_tee_keys_cleared count=3", VAULT, DAO),
            Some(("vault_tee_keys_cleared".into(), VAULT.into()))
        );
        assert_eq!(
            parse_vault_log("vault_tee_keys_cleared count=0", VAULT, DAO),
            Some(("vault_tee_keys_cleared".into(), VAULT.into()))
        );
    }

    #[test]
    fn dao_emitted_vault_banned_with_reason() {
        assert_eq!(
            parse_vault_log("vault_banned vault.alice.testnet reason=\"duplicate\"", DAO, DAO),
            Some(("vault_banned".into(), "vault.alice.testnet".into()))
        );
    }

    #[test]
    fn dao_emitted_vault_unbanned() {
        assert_eq!(
            parse_vault_log("vault_unbanned vault.alice.testnet", DAO, DAO),
            Some(("vault_unbanned".into(), "vault.alice.testnet".into()))
        );
    }

    #[test]
    fn dao_emitted_vault_verified() {
        assert_eq!(
            parse_vault_log("vault_verified vault.alice.testnet", DAO, DAO),
            Some(("vault_verified".into(), "vault.alice.testnet".into()))
        );
    }

    #[test]
    fn dao_event_from_non_dao_account_is_dropped() {
        // A non-DAO account emitting a `vault_banned ...` log is
        // either spam or a malicious imitation; drop it.
        assert_eq!(
            parse_vault_log("vault_banned vault.alice.testnet", "imposter.testnet", DAO),
            None
        );
    }

    #[test]
    fn unknown_log_lines_are_dropped() {
        assert_eq!(parse_vault_log("hello world", VAULT, DAO), None);
        assert_eq!(parse_vault_log("", VAULT, DAO), None);
        assert_eq!(parse_vault_log("recovery_initiated", VAULT, DAO), None);
    }

    #[test]
    fn dao_event_without_vault_id_is_dropped() {
        assert_eq!(parse_vault_log("vault_banned ", DAO, DAO), None);
        assert_eq!(parse_vault_log("vault_banned", DAO, DAO), None);
    }
}
