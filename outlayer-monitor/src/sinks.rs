//! Action sinks driven by [`Verdict::RaceDetected`].
//!
//! Two effects fire in sequence on every detected race:
//!   1. `POST /admin/ban-vault {vault_id, reason}` — submits the ban
//!      tx on chain. Idempotent on the keystore-worker side.
//!   2. `POST /admin/evict-customer {vault_id, reason}` — drops the
//!      cached per-customer master so any in-flight derive_* requests
//!      stop succeeding within ms.
//!
//! Step 2 is technically redundant with step 1's own eviction (the
//! ban handler does it), but we re-issue here so that if the ban
//! handler is added piecewise across deploys (e.g. monitor talks to
//! an older keystore that does ban-only, no evict) we still get the
//! cache flush.
//!
//! Alerting (Slack/email) is a separate trait so operators can plug
//! in their own webhook without touching the action path. The default
//! `StdoutAlerter` writes structured JSON to stdout; operators wire
//! the output into their existing pipeline (Slack and Telegram
//! adapters are also bundled).

use anyhow::{Context, Result};
use async_trait::async_trait;
use reqwest::Client;
use serde::Serialize;

use crate::types::{ban_reason, McpReceipt, VaultEventReceipt, Verdict};

/// Submits ban/evict to the keystore-worker.
#[async_trait]
pub trait ActionSink: Send + Sync {
    async fn ban_and_evict(&self, previous: &McpReceipt, current: &McpReceipt) -> Result<()>;

    /// Drop the keystore-worker's cached per-vault master after a
    /// successful `finalize_recovery`. The contract has already
    /// deleted the TEE access keys on chain so the keystore physically
    /// can't re-derive — this call just clears the in-memory cache so
    /// signing requests fail within seconds rather than waiting for
    /// the next cold-path re-verify. Best-effort: failures are
    /// logged, not propagated (the on-chain key-swap is the
    /// authoritative cutoff). `trigger` distinguishes the source
    /// event for ops triage.
    async fn evict_on_recovery_finalize(&self, vault_id: &str, trigger: &str) -> Result<()>;
}

/// Notifies an out-of-band alerting channel. Default impl
/// ([`StdoutAlerter`]) just writes structured JSON to stdout; operators
/// running their own pipeline can replace this with a Slack webhook,
/// PagerDuty, etc.
#[async_trait]
pub trait Alerter: Send + Sync {
    async fn alert(&self, previous: &McpReceipt, current: &McpReceipt) -> Result<()>;
}

/// Forwards observed vault contract events to the coordinator's
/// `/internal/vault-event` proxy.
///
/// **Defense vs neardata compromise:** the implementation
/// [`CoordinatorVaultEventForwarder`] performs an independent NEAR
/// RPC view-call BEFORE forwarding, to verify the event reflects
/// real chain state. Without this cross-check, a compromised CDN
/// (or MITM) could push fake `vault_unlocked` / `vault_banned`
/// events that fan out to customer webhooks. The cross-check costs
/// ~1 RPC per forwarded event — acceptable given the rarity of
/// vault state transitions (< 1/hour even at scale).
#[async_trait]
pub trait VaultEventForwarder: Send + Sync {
    async fn forward(&self, event: &VaultEventReceipt) -> Result<()>;
}

// ─── HTTP-backed action sink ──────────────────────────────────────────────

#[derive(Clone)]
pub struct KeystoreActionSink {
    client: Client,
    keystore_base_url: String,
    worker_token: String,
    /// Launch posture: alert-only by default, no ban/evict actions
    /// taken. Flip via config once real-world data confirms the
    /// detector's false-positive rate is acceptable.
    pub auto_ban_enabled: bool,
}

impl KeystoreActionSink {
    pub fn new(keystore_base_url: String, worker_token: String, auto_ban_enabled: bool) -> Self {
        Self {
            client: Client::builder()
                // 90s timeout (was 30s, too tight). The keystore's
                // `/admin/ban-vault` chains:
                //   * is_vault_banned view-call (~1-3s)
                //   * access-key visibility retries (up to 5×3s)
                //   * broadcast_tx_commit (~10-20s under testnet load)
                // 30s is too tight; under bursty conditions the sink
                // would spuriously time out while the tx actually
                // lands, and the operator sees a misleading "vault
                // NOT banned" log line.
                .timeout(std::time::Duration::from_secs(90))
                .build()
                .expect("reqwest client"),
            keystore_base_url,
            worker_token,
            auto_ban_enabled,
        }
    }
}

#[derive(Serialize)]
struct BanRequest<'a> {
    vault_id: &'a str,
    reason: &'a str,
}

#[derive(Serialize)]
struct EvictRequest<'a> {
    vault_id: &'a str,
    reason: &'a str,
}

#[async_trait]
impl ActionSink for KeystoreActionSink {
    async fn ban_and_evict(&self, previous: &McpReceipt, current: &McpReceipt) -> Result<()> {
        let reason = ban_reason(previous, current);
        if !self.auto_ban_enabled {
            tracing::warn!(
                vault_id = %current.vault_id,
                reason = %reason,
                "auto-ban DISABLED — alert-only mode. Manually ban via keystore /admin/ban-vault if appropriate."
            );
            return Ok(());
        }

        // Step 1: ban on chain.
        let ban_body = BanRequest {
            vault_id: &current.vault_id,
            reason: &reason,
        };
        let resp = self
            .client
            .post(format!("{}/admin/ban-vault", self.keystore_base_url))
            .bearer_auth(&self.worker_token)
            .json(&ban_body)
            .send()
            .await
            .context("ban-vault POST failed")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            // 5xx is ambiguous — the keystore may have already
            // submitted the ban tx and timed out waiting for
            // commit. The handler is idempotent (short-circuits on
            // `is_vault_banned`), so the operator's recovery is
            // simply to re-call this endpoint. We log at warn (not
            // error) for 5xx to avoid alert-fatigue; 4xx surfaces
            // as a real error since it indicates a request-side
            // bug (bad payload, missing token).
            if status.is_server_error() {
                tracing::warn!(
                    vault_id = %current.vault_id,
                    status = %status,
                    body = %body,
                    "ban-vault returned 5xx — tx may have landed; sink will not retry. \
                     Verify on chain via is_vault_banned, re-call if needed."
                );
                // Do NOT bail — proceed to evict cache so the
                // worker stops serving the (possibly-) banned vault.
            } else {
                anyhow::bail!("/admin/ban-vault returned {status}: {body}");
            }
        } else {
            tracing::warn!(
                vault_id = %current.vault_id,
                "ban_vault tx submitted via keystore-worker"
            );
        }

        // Step 2: evict cache. Defensive duplication of the ban
        // handler's own evict — idempotent and cheap.
        let evict_body = EvictRequest {
            vault_id: &current.vault_id,
            reason: &reason,
        };
        let resp = self
            .client
            .post(format!("{}/admin/evict-customer", self.keystore_base_url))
            .bearer_auth(&self.worker_token)
            .json(&evict_body)
            .send()
            .await
            .context("evict-customer POST failed")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            // Eviction failure is logged, NOT propagated — the ban
            // tx already landed; the cache will refresh on next
            // worker restart, and the next derive call already
            // re-checks `is_vault_verified` (which factors in
            // banned_vaults).
            tracing::error!(
                vault_id = %current.vault_id,
                status = %status,
                body = %body,
                "/admin/evict-customer failed; ban already on chain so safety boundary holds"
            );
        }
        Ok(())
    }

    async fn evict_on_recovery_finalize(&self, vault_id: &str, trigger: &str) -> Result<()> {
        // The reason field is descriptive only — keystore uses it
        // for audit logging, not for any policy decision. Surface
        // the trigger so ops know which recovery path fired.
        let reason = format!("recovery_finalize:{trigger}");
        let body = EvictRequest { vault_id, reason: &reason };
        let resp = self
            .client
            .post(format!("{}/admin/evict-customer", self.keystore_base_url))
            .bearer_auth(&self.worker_token)
            .json(&body)
            .send()
            .await
            .context("evict-customer POST failed (recovery-finalize)")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            // Best-effort: contract has already deleted the on-chain
            // TEE key, so the keystore physically cannot re-derive
            // the master anyway. Cache eviction just shortens the
            // window during which a still-cached master could
            // service signing requests. Log at warn; do NOT bail.
            tracing::warn!(
                vault_id = %vault_id,
                trigger = %trigger,
                status = %status,
                body = %body,
                "/admin/evict-customer failed on recovery_finalize — \
                 cached master may keep serving until next cold-path \
                 re-verify, but on-chain key-swap already cut the \
                 MPC re-derivation path"
            );
        } else {
            tracing::info!(
                vault_id = %vault_id,
                trigger = %trigger,
                "evicted cached per-vault master after recovery_finalize"
            );
        }
        Ok(())
    }
}

// ─── Slack webhook alerter ────────────────────────────────────────────────

/// POSTs the race-attack alert to a Slack incoming-webhook URL.
///
/// Operators set the webhook URL via `--slack-webhook-url` /
/// `OUTLAYER_MONITOR_SLACK_WEBHOOK` when starting the monitor
/// binary; if the flag is absent the monitor falls back to
/// [`StdoutAlerter`].
///
/// The webhook payload is the same JSON object as the stdout sink
/// produces, plus a `text` field with a human-readable summary so
/// Slack renders something useful even without a custom unfurl.
pub struct SlackAlerter {
    client: Client,
    webhook_url: String,
}

impl SlackAlerter {
    pub fn new(webhook_url: String) -> Self {
        Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .expect("reqwest client"),
            webhook_url,
        }
    }
}

#[async_trait]
impl Alerter for SlackAlerter {
    async fn alert(&self, previous: &McpReceipt, current: &McpReceipt) -> Result<()> {
        let summary = format!(
            "🚨 RACE ATTACK on vault `{}` — duplicate `request_app_private_key` calls (dpath `{}`) at blocks {} and {}. txs: {} / {}.",
            current.vault_id,
            current.derivation_path,
            previous.block_height,
            current.block_height,
            previous.tx_hash,
            current.tx_hash,
        );
        let payload = serde_json::json!({
            "text": summary,
            "event": "race_attack_detected",
            "vault_id": current.vault_id,
            "derivation_path": current.derivation_path,
            "previous": {
                "block_height": previous.block_height,
                "tx_hash": previous.tx_hash,
                "receipt_id": previous.receipt_id,
            },
            "current": {
                "block_height": current.block_height,
                "tx_hash": current.tx_hash,
                "receipt_id": current.receipt_id,
            },
        });
        let resp = self
            .client
            .post(&self.webhook_url)
            .json(&payload)
            .send()
            .await
            .context("Slack webhook POST failed")?;
        // Slack returns 200 + "ok" on success. Anything else logs
        // but does NOT propagate — alerter failures must not block
        // the action sink (the action sink is the load-bearing
        // path; alerts are advisory).
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            tracing::error!(
                vault_id = %current.vault_id,
                status = %status,
                body = %body,
                "Slack webhook returned non-2xx; alert may have been dropped"
            );
        } else {
            tracing::info!(
                vault_id = %current.vault_id,
                "Slack alert delivered"
            );
        }
        // Always Ok — see comment above; alerter errors don't block
        // the action sink.
        Ok(())
    }
}

// ─── Vault event forwarder (coordinator + RPC cross-check) ───────────────

#[derive(Clone)]
pub struct CoordinatorVaultEventForwarder {
    client: Client,
    coordinator_base_url: String,
    /// Worker token authorised on coordinator's `/internal/vault-event`.
    /// Same token that the keystore-worker presents (`x-internal-wallet-auth`
    /// header per coordinator's `verify_internal_auth`).
    worker_token: String,
    /// Independent NEAR RPC URL (NOT the neardata feed) used to
    /// cross-check the event against on-chain state. Defaults to
    /// FastNEAR's public RPC.
    near_rpc_url: String,
    /// keystore-DAO account id — used by some cross-check view-calls
    /// (`is_vault_banned`, `is_vault_verified`).
    keystore_dao_id: String,
}

impl CoordinatorVaultEventForwarder {
    pub fn new(
        coordinator_base_url: String,
        worker_token: String,
        near_rpc_url: String,
        keystore_dao_id: String,
    ) -> Self {
        Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("reqwest client"),
            coordinator_base_url,
            worker_token,
            near_rpc_url,
            keystore_dao_id,
        }
    }

    /// Cross-check the event by view-calling the canonical source
    /// of truth on chain. Returns `Ok(true)` if the event is
    /// consistent with chain state; `Ok(false)` if the event looks
    /// like a stale or fake notification (drop silently); `Err(_)`
    /// only on transport failure (will be retried by caller).
    async fn cross_check(&self, event: &VaultEventReceipt) -> Result<bool> {
        // Each event type maps to a specific RPC view-call that
        // confirms the on-chain state transition is real. We pick
        // the simplest single view-call that should be true at the
        // time the monitor sees the log:
        //
        //   * vault_banned       → keystore_dao.is_vault_banned == true
        //   * vault_unbanned     → keystore_dao.is_vault_banned == false
        //   * vault_verified     → keystore_dao.is_vault_verified == true
        //   * recovery_initiated → vault.get_recovery_state().is_some()
        //   * recovery_finalized → either vault.unlocked == true (unilateral)
        //                          OR get_recovery_state().is_none() AND unlocked
        //                          (cessation may take callback)
        //   * exit_window_set    → vault.get_state().exit_window_secs matches log
        //                          (parsing the suffix is fragile, so we just
        //                          confirm the vault still exists and the
        //                          recovery_state observably matches a recent
        //                          window — for v1 we just confirm vault exists)
        //   * recovery_window_expired / recovery_cancelled_dao_revoked
        //                        → vault.get_recovery_state().is_none()
        //
        // The cross-check is a SOFT signal (returns false → drop event,
        // not an alarm). Genuine block-finality lag could cause a
        // consistent log to mismatch a slightly later view-call; in
        // that case we'd lose ONE event. The customer's webhook is
        // best-effort by design (the webhook system has its own
        // retry semantics for transport, but a view-call mismatch
        // means we don't even try).
        let res: Option<serde_json::Value> = match event.event_type.as_str() {
            "vault_banned" => Some(self.view_dao(
                "is_vault_banned",
                serde_json::json!({ "vault_id": event.vault_id }),
            )
            .await?),
            "vault_unbanned" => {
                let v = self
                    .view_dao(
                        "is_vault_banned",
                        serde_json::json!({ "vault_id": event.vault_id }),
                    )
                    .await?;
                // Inverted: banned == false matches the unbanned event.
                return Ok(v.as_bool() == Some(false));
            }
            "vault_verified" => Some(self.view_dao(
                "is_vault_verified",
                serde_json::json!({ "vault_id": event.vault_id }),
            )
            .await?),
            "recovery_initiated_cessation"
            | "recovery_initiated_unilateral" => {
                let state = self.view_vault(&event.vault_id, "get_recovery_state", serde_json::json!({})).await?;
                return Ok(!state.is_null());
            }
            "recovery_finalized_cessation" | "recovery_finalized_unilateral" => {
                let state = self.view_vault(&event.vault_id, "get_state", serde_json::json!({})).await?;
                let unlocked = state.get("unlocked").and_then(|v| v.as_bool()) == Some(true);
                return Ok(unlocked);
            }
            "recovery_window_expired" | "recovery_cancelled_dao_revoked" => {
                let state = self.view_vault(&event.vault_id, "get_recovery_state", serde_json::json!({})).await?;
                return Ok(state.is_null());
            }
            "exit_window_set" => {
                // Confirm vault exists + has approved exit window
                // value. Looser than per-suffix matching to avoid
                // tx-finality races. v1: just confirm vault is live.
                let state = self.view_vault(&event.vault_id, "get_exit_window", serde_json::json!({})).await?;
                return Ok(state.is_u64());
            }
            "exit_window_lowering" => {
                // A lowering leaves a pending value until it comes into
                // force; by then a later change may have replaced it, so
                // the cross-check is that the vault answers its state.
                let state = self.view_vault(&event.vault_id, "get_state", serde_json::json!({})).await?;
                return Ok(state.get("unilateral_exit_window_secs").map(|v| v.is_u64()).unwrap_or(false));
            }
            "vault_tee_key_added" => {
                // Confirm vault has at least one registered TEE key.
                // We don't know which key was just added (the log
                // doesn't include it — customer queries
                // `get_registered_keys` after the webhook lands),
                // so the cross-check is "vault is alive and has
                // tee keys". A vault with zero keys + this event
                // is impossible in legitimate flow.
                let keys = self.view_vault(&event.vault_id, "get_registered_keys", serde_json::json!({})).await?;
                return Ok(keys.as_array().map(|a| !a.is_empty()).unwrap_or(false));
            }
            // Allow-listed event types we don't yet cross-check —
            // forward without verification. None today; placeholder
            // for future event types.
            _ => None,
        };
        Ok(res.map(|v| v.as_bool() == Some(true)).unwrap_or(false))
    }

    async fn view_dao(&self, method: &str, args: serde_json::Value) -> Result<serde_json::Value> {
        self.view_call(&self.keystore_dao_id, method, args).await
    }

    async fn view_vault(
        &self,
        vault_id: &str,
        method: &str,
        args: serde_json::Value,
    ) -> Result<serde_json::Value> {
        self.view_call(vault_id, method, args).await
    }

    async fn view_call(
        &self,
        contract: &str,
        method: &str,
        args: serde_json::Value,
    ) -> Result<serde_json::Value> {
        use base64::Engine as _;
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "cross-check",
            "method": "query",
            "params": {
                "request_type": "call_function",
                "finality": "final",
                "account_id": contract,
                "method_name": method,
                "args_base64": base64::engine::general_purpose::STANDARD
                    .encode(args.to_string().as_bytes()),
            }
        });
        let resp = self
            .client
            .post(&self.near_rpc_url)
            .json(&body)
            .send()
            .await
            .context("rpc cross-check POST")?;
        let json: serde_json::Value = resp.json().await.context("rpc cross-check body")?;
        // NEAR's call_function returns bytes under
        // `.result.result` — JSON-decode them. A contract panic
        // surfaces as `.result.error` (treated as "vault doesn't
        // exist / view failed", drop event silently).
        if json.pointer("/result/error").is_some() {
            return Ok(serde_json::Value::Null);
        }
        let bytes_arr = json
            .pointer("/result/result")
            .and_then(|v| v.as_array())
            .ok_or_else(|| anyhow::anyhow!("missing result.result in RPC response: {json}"))?;
        let bytes: Vec<u8> = bytes_arr
            .iter()
            .filter_map(|v| v.as_u64().map(|n| n as u8))
            .collect();
        if bytes.is_empty() {
            return Ok(serde_json::Value::Null);
        }
        Ok(serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null))
    }
}

#[async_trait]
impl VaultEventForwarder for CoordinatorVaultEventForwarder {
    async fn forward(&self, event: &VaultEventReceipt) -> Result<()> {
        // 1. Cross-check via independent RPC. Compromised neardata
        //    or MITM cannot fabricate state on the actual NEAR
        //    chain, so an RPC view-call provides ground truth.
        match self.cross_check(event).await {
            Ok(true) => {} // verified, proceed
            Ok(false) => {
                tracing::info!(
                    vault_id = %event.vault_id,
                    event_type = %event.event_type,
                    "RPC cross-check disagreed with neardata log; dropping event"
                );
                return Ok(());
            }
            Err(e) => {
                tracing::warn!(
                    vault_id = %event.vault_id,
                    event_type = %event.event_type,
                    error = %e,
                    "RPC cross-check failed (transport); dropping event"
                );
                return Ok(());
            }
        }

        // 2. Forward to coordinator.
        let url = format!("{}/internal/vault-event", self.coordinator_base_url);
        let payload = serde_json::json!({
            "vault_account_id": event.vault_id,
            "event_type": event.event_type,
            "payload": {
                "block_height": event.block_height,
                "tx_hash": event.tx_hash,
                "receipt_id": event.receipt_id,
                "raw_log": event.raw_log,
                "emitting_account": event.emitting_account,
            },
        });
        let resp = self
            .client
            .post(&url)
            .header("x-internal-wallet-auth", &self.worker_token)
            .json(&payload)
            .send()
            .await
            .context("/internal/vault-event POST")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            tracing::warn!(
                vault_id = %event.vault_id,
                event_type = %event.event_type,
                status = %status,
                body = %body,
                "/internal/vault-event returned non-2xx; event dropped"
            );
        } else {
            tracing::debug!(
                vault_id = %event.vault_id,
                event_type = %event.event_type,
                "vault event forwarded"
            );
        }
        Ok(())
    }
}

// ─── Telegram alerter ─────────────────────────────────────────────────────

/// POSTs the race-attack alert to a Telegram bot.
///
/// Plays the same role as [`SlackAlerter`] for ops who run their
/// alerting through a Telegram channel/group. Bot API: token +
/// chat_id, simple `sendMessage` call. Same "alerter failures
/// don't block the action sink" semantics.
///
/// The text is plain (no Markdown) to avoid escaping issues — the
/// log already contains the verbatim vault id and tx hashes which
/// would otherwise need escaping for MarkdownV2.
pub struct TelegramAlerter {
    client: Client,
    bot_token: String,
    chat_id: String,
}

impl TelegramAlerter {
    pub fn new(bot_token: String, chat_id: String) -> Self {
        Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .expect("reqwest client"),
            bot_token,
            chat_id,
        }
    }
}

#[async_trait]
impl Alerter for TelegramAlerter {
    async fn alert(&self, previous: &McpReceipt, current: &McpReceipt) -> Result<()> {
        let text = format!(
            "🚨 RACE ATTACK\n\nVault: {}\nDerivation path: {}\nBlocks: {} → {}\nTxs: {}\n     {}\nReceipts: {}\n          {}",
            current.vault_id,
            current.derivation_path,
            previous.block_height,
            current.block_height,
            previous.tx_hash,
            current.tx_hash,
            previous.receipt_id,
            current.receipt_id,
        );
        let url = format!(
            "https://api.telegram.org/bot{}/sendMessage",
            self.bot_token
        );
        let resp = self
            .client
            .post(&url)
            .json(&serde_json::json!({
                "chat_id": self.chat_id,
                "text": text,
                "disable_web_page_preview": true,
            }))
            .send()
            .await
            .context("Telegram sendMessage")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            tracing::error!(
                vault_id = %current.vault_id,
                status = %status,
                body = %body,
                "Telegram sendMessage returned non-2xx"
            );
        } else {
            tracing::info!(vault_id = %current.vault_id, "Telegram alert delivered");
        }
        Ok(())
    }
}

// ─── Stdout alerter ───────────────────────────────────────────────────────

pub struct StdoutAlerter;

#[async_trait]
impl Alerter for StdoutAlerter {
    async fn alert(&self, previous: &McpReceipt, current: &McpReceipt) -> Result<()> {
        // Single-line JSON for grep-friendliness in operator log
        // pipelines. Keep field names stable; downstream alerting
        // tools may key on them.
        let payload = serde_json::json!({
            "event": "race_attack_detected",
            "vault_id": current.vault_id,
            "derivation_path": current.derivation_path,
            "previous": {
                "block_height": previous.block_height,
                "tx_hash": previous.tx_hash,
                "receipt_id": previous.receipt_id,
            },
            "current": {
                "block_height": current.block_height,
                "tx_hash": current.tx_hash,
                "receipt_id": current.receipt_id,
            },
        });
        // tracing has structured fields, but for downstream tooling
        // (jq pipelines, log aggregators) a plain stdout JSON line is
        // the lowest-friction format. Stdout is BLOCK-buffered when
        // piped (which is the operator-deploy case), so flush
        // explicitly — otherwise an alert can sit in the buffer for
        // seconds and a process crash between alert and ban tx loses
        // it entirely. The "alert FIRST" invariant relies on this.
        use std::io::Write;
        println!("{}", payload);
        let _ = std::io::stdout().flush();
        tracing::warn!(
            vault_id = %current.vault_id,
            previous_tx = %previous.tx_hash,
            current_tx = %current.tx_hash,
            "RACE ATTACK DETECTED"
        );
        Ok(())
    }
}

// ─── Composed handler ─────────────────────────────────────────────────────

/// Runs the full action pipeline for a single verdict. Pure side-effect
/// composition; the [`crate::detector::Detector`] decides WHEN to call
/// this, the sinks decide WHAT happens.
pub async fn handle_verdict(
    verdict: Verdict,
    actions: &dyn ActionSink,
    alerter: &dyn Alerter,
) -> Result<()> {
    match verdict {
        Verdict::FirstSeen => Ok(()),
        Verdict::RaceDetected { previous, current } => {
            // Alert FIRST so even if the ban call fails we have a
            // permanent record of the detection. Errors from either
            // sink are logged but not propagated — a monitor that
            // bails on the first failure is worse than one that keeps
            // running.
            if let Err(e) = alerter.alert(&previous, &current).await {
                tracing::error!(error = %e, "alert sink failed; race detection still recorded above");
            }
            if let Err(e) = actions.ban_and_evict(&previous, &current).await {
                tracing::error!(
                    vault_id = %current.vault_id,
                    error = %e,
                    "action sink failed; vault NOT banned. Manual intervention required."
                );
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct CountingSink {
        bans: Arc<AtomicUsize>,
    }
    #[async_trait]
    impl ActionSink for CountingSink {
        async fn ban_and_evict(&self, _: &McpReceipt, _: &McpReceipt) -> Result<()> {
            self.bans.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        async fn evict_on_recovery_finalize(&self, _: &str, _: &str) -> Result<()> {
            Ok(())
        }
    }

    struct CountingAlerter {
        alerts: Arc<AtomicUsize>,
    }
    #[async_trait]
    impl Alerter for CountingAlerter {
        async fn alert(&self, _: &McpReceipt, _: &McpReceipt) -> Result<()> {
            self.alerts.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    fn rcpt(vault: &str, dpath: &str, h: u64, t: &str) -> McpReceipt {
        McpReceipt {
            vault_id: vault.into(),
            derivation_path: dpath.into(),
            block_height: h,
            tx_hash: t.into(),
            receipt_id: format!("r-{t}"),
        }
    }

    #[tokio::test]
    async fn first_seen_skips_action_and_alert() {
        let bans = Arc::new(AtomicUsize::new(0));
        let alerts = Arc::new(AtomicUsize::new(0));
        let sink = CountingSink { bans: bans.clone() };
        let alerter = CountingAlerter { alerts: alerts.clone() };
        handle_verdict(Verdict::FirstSeen, &sink, &alerter).await.unwrap();
        assert_eq!(bans.load(Ordering::SeqCst), 0);
        assert_eq!(alerts.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn race_fires_both_sinks() {
        let bans = Arc::new(AtomicUsize::new(0));
        let alerts = Arc::new(AtomicUsize::new(0));
        let sink = CountingSink { bans: bans.clone() };
        let alerter = CountingAlerter { alerts: alerts.clone() };
        let v = Verdict::RaceDetected {
            previous: rcpt("v.alice.near", "near", 1, "t1"),
            current: rcpt("v.alice.near", "near", 5, "t2"),
        };
        handle_verdict(v, &sink, &alerter).await.unwrap();
        assert_eq!(bans.load(Ordering::SeqCst), 1);
        assert_eq!(alerts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn alert_only_mode_skips_ban() {
        let sink = KeystoreActionSink::new(
            "http://unused".into(),
            "wt-test".into(),
            false, // auto_ban disabled
        );
        // ban_and_evict on the real sink with auto_ban=false must NOT
        // attempt any HTTP — the fake URL would otherwise time out.
        let r = sink
            .ban_and_evict(
                &rcpt("v.alice.near", "near", 1, "t1"),
                &rcpt("v.alice.near", "near", 5, "t2"),
            )
            .await;
        assert!(r.is_ok());
    }
}
