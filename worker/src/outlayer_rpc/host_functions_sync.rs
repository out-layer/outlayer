//! NEAR RPC Proxy for wasi-test-runner
//!
//! Provides RPC host functions for WASM components that import `near:rpc/api@0.1.0`.
//!
//! ## Versioning
//!
//! Host functions are versioned to maintain backward compatibility:
//! - `near:rpc@0.1.0` - Current API (view, call, transfer, etc.)
//! - Future versions (0.2.0+) can coexist with old versions
//!
//! WASM compiled with different API versions can run on the same worker.

use anyhow::{Context, Result};
use base64::Engine;
use log::{debug, info};
use near_crypto::{InMemorySigner, SecretKey};
use near_primitives::action::{Action, FunctionCallAction, TransferAction};
use near_primitives::hash::CryptoHash;
use near_primitives::transaction::{Transaction, TransactionV0, SignedTransaction};
use near_primitives::types::{AccountId, Balance, BlockHeight, Gas, Nonce};
use serde_json::{json, Value};
use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use wasmtime::component::Linker;

// Generate bindings from WIT - sync mode for simpler implementation
// A published interface version never changes a type: a changed signature is
// a new package version, registered next to the old one (wit/README.md).
wasmtime::component::bindgen!({
    path: "wit",
    world: "rpc-host",
});

/// RPC Proxy client with rate limiting (using blocking HTTP)
pub struct RpcProxy {
    /// HTTP client for RPC requests (blocking)
    client: reqwest::blocking::Client,
    /// RPC URL
    rpc_url: String,
    /// Maximum calls per execution
    max_calls: u32,
    /// Allow transaction methods
    allow_transactions: bool,
    /// Call counter for rate limiting
    call_count: Arc<AtomicU32>,
    /// Optional signer for transactions (account_id, private_key)
    signer: Option<(String, String)>,
}

impl RpcProxy {
    /// Create a new RPC proxy
    pub fn new(
        rpc_url: &str,
        max_calls: u32,
        allow_transactions: bool,
        signer: Option<(String, String)>,
    ) -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .build()
            .context("Failed to create HTTP client")?;

        Ok(Self {
            client,
            rpc_url: rpc_url.to_string(),
            max_calls,
            allow_transactions,
            call_count: Arc::new(AtomicU32::new(0)),
            signer,
        })
    }

    /// Reset call counter
    #[allow(dead_code)]
    pub fn reset_call_count(&self) {
        self.call_count.store(0, Ordering::SeqCst);
    }


    /// Get current call count
    pub fn get_call_count(&self) -> u32 {
        self.call_count.load(Ordering::SeqCst)
    }
    /// Check rate limit and increment counter
    fn check_rate_limit(&self) -> Result<()> {
        let count = self.call_count.fetch_add(1, Ordering::SeqCst);
        if count >= self.max_calls {
            anyhow::bail!(
                "RPC rate limit exceeded: {} calls (max: {})",
                count + 1,
                self.max_calls
            );
        }
        Ok(())
    }

    /// Safe display of URL - hides API keys and query parameters
    fn safe_url_display(url: &str) -> String {
        if let Some(question_mark_pos) = url.find('?') {
            let base = &url[..question_mark_pos];
            format!("{}... (length: {})", base, url.len())
        } else {
            url.to_string()
        }
    }

    /// Send JSON-RPC request (blocking)
    pub fn call_method(&self, method: &str, params: Value) -> Result<Value> {
        let is_tx_method = matches!(
            method,
            "send_tx" | "broadcast_tx_async" | "broadcast_tx_commit"
        );

        if is_tx_method && !self.allow_transactions {
            anyhow::bail!("Transaction method '{}' is disabled", method);
        }

        self.check_rate_limit()?;

        let request = json!({
            "jsonrpc": "2.0",
            "id": "proxy",
            "method": method,
            "params": params
        });

        info!("[RPC] Sending {} request to {}", method, Self::safe_url_display(&self.rpc_url));

        let response = self
            .client
            .post(&self.rpc_url)
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .context("Failed to send RPC request")?;

        let status = response.status();
        if !status.is_success() {
            let error_text = response.text().unwrap_or_default();
            anyhow::bail!("RPC returned status {}: {}", status, error_text);
        }

        let body: Value = response
            .json()
            .context("Failed to parse RPC response")?;
        Ok(body)
    }

    #[allow(dead_code)]
    pub fn view_account(&self, account_id: &str) -> Result<Value> {
        let params = json!({
            "request_type": "view_account",
            "account_id": account_id,
            "finality": "final"
        });
        self.call_method("query", params)
    }

    #[allow(dead_code)]
    pub fn call_function(&self, account_id: &str, method_name: &str, args_base64: &str) -> Result<Value> {
        let params = json!({
            "request_type": "call_function",
            "account_id": account_id,
            "method_name": method_name,
            "args_base64": args_base64,
            "finality": "final"
        });
        self.call_method("query", params)
    }

    pub fn view_access_key(&self, account_id: &str, public_key: &str) -> Result<Value> {
        let params = json!({
            "request_type": "view_access_key",
            "account_id": account_id,
            "public_key": public_key,
            "finality": "final"
        });
        self.call_method("query", params)
    }

    #[allow(dead_code)]
    pub fn block(&self, finality: Option<&str>, block_id: Option<Value>) -> Result<Value> {
        let params = if let Some(fin) = finality {
            json!({ "finality": fin })
        } else if let Some(id) = block_id {
            json!({ "block_id": id })
        } else {
            json!({ "finality": "final" })
        };
        self.call_method("block", params)
    }

    #[allow(dead_code)]
    pub fn gas_price(&self) -> Result<Value> {
        self.call_method("gas_price", json!([null]))
    }

    pub fn send_tx(&self, signed_tx_base64: &str, wait_until: Option<&str>) -> Result<Value> {
        let mut params = json!({
            "signed_tx_base64": signed_tx_base64
        });
        if let Some(wait) = wait_until {
            params["wait_until"] = json!(wait);
        }
        self.call_method("send_tx", params)
    }

    /// Get access key info for nonce
    fn get_access_key_nonce(&self, account_id: &str, public_key: &str) -> Result<(Nonce, CryptoHash, BlockHeight)> {
        let result = self.view_access_key(account_id, public_key)?;

        let nonce = result
            .get("result")
            .and_then(|r| r.get("nonce"))
            .and_then(|n| n.as_u64())
            .ok_or_else(|| anyhow::anyhow!("Failed to get nonce"))?;

        let block_hash_str = result
            .get("result")
            .and_then(|r| r.get("block_hash"))
            .and_then(|h| h.as_str())
            .ok_or_else(|| anyhow::anyhow!("Failed to get block_hash"))?;

        let block_height = result
            .get("result")
            .and_then(|r| r.get("block_height"))
            .and_then(|h| h.as_u64())
            .ok_or_else(|| anyhow::anyhow!("Failed to get block_height"))?;

        let block_hash = CryptoHash::from_str(block_hash_str)
            .map_err(|e| anyhow::anyhow!("Invalid block hash: {}", e))?;

        Ok((nonce, block_hash, block_height))
    }

    /// Sign and send a transaction with actions (using configured signer)
    #[allow(dead_code)]
    pub fn sign_and_send_tx(&self, receiver_id: &str, actions: Vec<Action>) -> Result<String> {
        let (signer_account, secret_key_str) = self
            .signer
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No signer configured. Use --rpc-signer-account and --rpc-signer-key"))?;

        self.sign_and_send_tx_as(signer_account, secret_key_str, receiver_id, actions)
    }

    /// Sign and send a transaction with explicit signer
    pub fn sign_and_send_tx_as(
        &self,
        signer_account: &str,
        secret_key_str: &str,
        receiver_id: &str,
        actions: Vec<Action>,
    ) -> Result<String> {
        debug!("[RPC_PROXY] sign_and_send_tx_as called: signer={}, receiver={}", signer_account, receiver_id);

        let secret_key = SecretKey::from_str(secret_key_str)
            .map_err(|e| {
                debug!("[RPC_PROXY] Failed to parse secret key: {}", e);
                anyhow::anyhow!("Invalid secret key: {}", e)
            })?;

        let signer_id = AccountId::from_str(signer_account)
            .map_err(|e| {
                debug!("[RPC_PROXY] Failed to parse signer account: {}", e);
                anyhow::anyhow!("Invalid signer account: {}", e)
            })?;

        let receiver = AccountId::from_str(receiver_id)
            .map_err(|e| {
                debug!("[RPC_PROXY] Failed to parse receiver account: {}", e);
                anyhow::anyhow!("Invalid receiver account: {}", e)
            })?;

        let signer = InMemorySigner {
            account_id: signer_id.clone(),
            public_key: secret_key.public_key(),
            secret_key,
        };
        let public_key = signer.public_key();

        debug!("[RPC_PROXY] About to get access key nonce for {}, pubkey: {}", signer_account, public_key);

        // Get nonce and block hash
        let (nonce, block_hash, _) = self.get_access_key_nonce(signer_account, &public_key.to_string())
            .map_err(|e| {
                debug!("[RPC_PROXY] Failed to get access key nonce: {}", e);
                e
            })?;

        debug!("[RPC_PROXY] Got nonce={}, block_hash={}", nonce, block_hash);

        let tx = Transaction::V0(TransactionV0 {
            signer_id,
            public_key,
            nonce: nonce + 1,
            receiver_id: receiver,
            block_hash,
            actions,
        });

        // Get transaction hash before signing (this is what will be the final tx hash)
        let tx_hash = tx.get_hash_and_size().0;
        let tx_hash_base58 = bs58::encode(tx_hash.as_ref()).into_string();

        debug!("[RPC_PROXY] Transaction hash: {}", tx_hash_base58);

        // Sign transaction
        let signature = signer.sign(tx_hash.as_ref());
        let signed_tx = SignedTransaction::new(signature, tx);

        // Serialize and encode
        let signed_tx_bytes = borsh::to_vec(&signed_tx)
            .map_err(|e| {
                debug!("[RPC_PROXY] Failed to serialize tx: {}", e);
                anyhow::anyhow!("Failed to serialize tx: {}", e)
            })?;
        let signed_tx_base64 = base64::engine::general_purpose::STANDARD.encode(&signed_tx_bytes);

        info!("[RPC_PROXY] Sending transaction to RPC...");

        // Send transaction and wait for finalization
        let result = self.send_tx(&signed_tx_base64, Some("FINAL"))
            .map_err(|e| {
                eprintln!("[RPC_PROXY] Failed to send tx: {}", e);
                e
            })?;

        debug!("[RPC_PROXY] Transaction sent, checking status...");

        // Print full result for debugging (only in debug mode)
        debug!("[RPC_PROXY] Full RPC result: {}", serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)));

        // Check for RPC-level error first (e.g., invalid transaction, not enough balance)
        if let Some(error) = result.get("error") {
            let error_msg = if let Some(msg) = error.get("message").and_then(|m| m.as_str()) {
                msg.to_string()
            } else {
                format!("{:?}", error)
            };
            eprintln!("[RPC_PROXY] RPC error: {}", error_msg);
            return Err(anyhow::anyhow!("RPC error: {}", error_msg));
        }

        // Check if transaction was successful - check both top-level and nested status
        if let Some(status) = result.get("result").and_then(|r| r.get("status")) {
            // Check for Failure variant
            if let Some(failure) = status.get("Failure") {
                debug!("[RPC_PROXY] Transaction failed: {:?}", failure);
                return Err(anyhow::anyhow!("Transaction failed: {:?}", failure));
            }
        } else if let Some(status) = result.get("status") {
            // Check top-level status (some RPC responses have it here)
            if let Some(failure) = status.get("Failure") {
                debug!("[RPC_PROXY] Transaction failed (top-level): {:?}", failure);
                return Err(anyhow::anyhow!("Transaction failed: {:?}", failure));
            }
        }

        info!("[RPC_PROXY] Transaction completed successfully: {}", tx_hash_base58);

        // Return the transaction hash we computed (not from RPC response)
        Ok(tx_hash_base58)
    }
}

/// Host state for RPC host functions
pub struct RpcHostState {
    pub proxy: RpcProxy,
}

impl RpcHostState {
    pub fn new(proxy: RpcProxy) -> Self {
        Self { proxy }
    }
}

/// Helper to parse finality-or-block parameter
fn parse_finality_or_block(s: &str) -> (Option<&str>, Option<Value>) {
    if s.is_empty() || s == "final" {
        (Some("final"), None)
    } else if s == "optimistic" {
        (Some("optimistic"), None)
    } else if let Ok(height) = s.parse::<u64>() {
        (None, Some(json!(height)))
    } else {
        // Assume it's a block hash
        (None, Some(json!(s)))
    }
}

/// Implement the generated Host trait for RpcHostState
impl near::rpc::api::Host for RpcHostState {
    // ==================== Query Methods ====================

    fn view(&mut self, contract_id: String, method_name: String, args_json: String, finality_or_block: String) -> (String, String) {
        let args_base64 = base64::engine::general_purpose::STANDARD.encode(args_json.as_bytes());
        let (finality, block_id) = parse_finality_or_block(&finality_or_block);

        let mut params = json!({
            "request_type": "call_function",
            "account_id": contract_id,
            "method_name": method_name,
            "args_base64": args_base64,
        });
        if let Some(fin) = finality {
            params["finality"] = json!(fin);
        } else if let Some(bid) = block_id {
            params["block_id"] = bid;
        }

        match self.proxy.call_method("query", params) {
            Ok(result) => {
                if let Some(result_array) = result.get("result").and_then(|r| r.get("result")) {
                    if let Some(arr) = result_array.as_array() {
                        let bytes: Vec<u8> = arr
                            .iter()
                            .filter_map(|v| v.as_u64().map(|n| n as u8))
                            .collect();
                        return (String::from_utf8_lossy(&bytes).to_string(), String::new());
                    }
                }
                (serde_json::to_string(&result).unwrap_or_default(), String::new())
            }
            Err(e) => (String::new(), e.to_string()),
        }
    }

    fn view_account(&mut self, account_id: String, finality_or_block: String) -> (String, String) {
        let (finality, block_id) = parse_finality_or_block(&finality_or_block);

        let mut params = json!({
            "request_type": "view_account",
            "account_id": account_id,
        });
        if let Some(fin) = finality {
            params["finality"] = json!(fin);
        } else if let Some(bid) = block_id {
            params["block_id"] = bid;
        }

        match self.proxy.call_method("query", params) {
            Ok(result) => (serde_json::to_string(&result).unwrap_or_default(), String::new()),
            Err(e) => (String::new(), e.to_string()),
        }
    }

    fn view_access_key(&mut self, account_id: String, public_key: String, finality_or_block: String) -> (String, String) {
        let (finality, block_id) = parse_finality_or_block(&finality_or_block);

        let mut params = json!({
            "request_type": "view_access_key",
            "account_id": account_id,
            "public_key": public_key,
        });
        if let Some(fin) = finality {
            params["finality"] = json!(fin);
        } else if let Some(bid) = block_id {
            params["block_id"] = bid;
        }

        match self.proxy.call_method("query", params) {
            Ok(result) => (serde_json::to_string(&result).unwrap_or_default(), String::new()),
            Err(e) => (String::new(), e.to_string()),
        }
    }

    fn view_access_key_list(&mut self, account_id: String, finality_or_block: String) -> (String, String) {
        let (finality, block_id) = parse_finality_or_block(&finality_or_block);

        let mut params = json!({
            "request_type": "view_access_key_list",
            "account_id": account_id,
        });
        if let Some(fin) = finality {
            params["finality"] = json!(fin);
        } else if let Some(bid) = block_id {
            params["block_id"] = bid;
        }

        match self.proxy.call_method("query", params) {
            Ok(result) => (serde_json::to_string(&result).unwrap_or_default(), String::new()),
            Err(e) => (String::new(), e.to_string()),
        }
    }

    fn view_code(&mut self, account_id: String, finality_or_block: String) -> (String, String) {
        let (finality, block_id) = parse_finality_or_block(&finality_or_block);

        let mut params = json!({
            "request_type": "view_code",
            "account_id": account_id,
        });
        if let Some(fin) = finality {
            params["finality"] = json!(fin);
        } else if let Some(bid) = block_id {
            params["block_id"] = bid;
        }

        match self.proxy.call_method("query", params) {
            Ok(result) => (serde_json::to_string(&result).unwrap_or_default(), String::new()),
            Err(e) => (String::new(), e.to_string()),
        }
    }

    fn view_state(&mut self, account_id: String, prefix_base64: String, finality_or_block: String) -> (String, String) {
        let (finality, block_id) = parse_finality_or_block(&finality_or_block);

        let mut params = json!({
            "request_type": "view_state",
            "account_id": account_id,
            "prefix_base64": prefix_base64,
        });
        if let Some(fin) = finality {
            params["finality"] = json!(fin);
        } else if let Some(bid) = block_id {
            params["block_id"] = bid;
        }

        match self.proxy.call_method("query", params) {
            Ok(result) => (serde_json::to_string(&result).unwrap_or_default(), String::new()),
            Err(e) => (String::new(), e.to_string()),
        }
    }

    // ==================== Block Methods ====================

    fn block(&mut self, finality_or_block: String) -> (String, String) {
        let (finality, block_id) = parse_finality_or_block(&finality_or_block);

        let params = if let Some(fin) = finality {
            json!({ "finality": fin })
        } else if let Some(bid) = block_id {
            json!({ "block_id": bid })
        } else {
            json!({ "finality": "final" })
        };

        match self.proxy.call_method("block", params) {
            Ok(result) => (serde_json::to_string(&result).unwrap_or_default(), String::new()),
            Err(e) => (String::new(), e.to_string()),
        }
    }

    fn chunk(&mut self, chunk_id_or_block_shard: String) -> (String, String) {
        // Parse: either "chunk_id" or "block_id,shard_id"
        let params = if chunk_id_or_block_shard.contains(',') {
            let parts: Vec<&str> = chunk_id_or_block_shard.split(',').collect();
            if parts.len() != 2 {
                return (String::new(), "Invalid format. Use 'block_id,shard_id' or 'chunk_id'".to_string());
            }
            let block_id = parts[0].parse::<u64>().unwrap_or(0);
            let shard_id = parts[1].parse::<u64>().unwrap_or(0);
            json!({
                "block_id": block_id,
                "shard_id": shard_id
            })
        } else {
            json!({ "chunk_id": chunk_id_or_block_shard })
        };

        match self.proxy.call_method("chunk", params) {
            Ok(result) => (serde_json::to_string(&result).unwrap_or_default(), String::new()),
            Err(e) => (String::new(), e.to_string()),
        }
    }

    fn changes(&mut self, finality_or_block: String) -> (String, String) {
        let (finality, block_id) = parse_finality_or_block(&finality_or_block);

        let params = if let Some(fin) = finality {
            json!({ "finality": fin })
        } else if let Some(bid) = block_id {
            json!({ "block_id": bid })
        } else {
            json!({ "finality": "final" })
        };

        match self.proxy.call_method("EXPERIMENTAL_changes", params) {
            Ok(result) => (serde_json::to_string(&result).unwrap_or_default(), String::new()),
            Err(e) => (String::new(), e.to_string()),
        }
    }

    // ==================== Transaction Methods ====================

    fn send_tx(&mut self, signed_tx_base64: String, wait_until: String) -> (String, String) {
        let wait = if wait_until.is_empty() {
            Some("EXECUTED_OPTIMISTIC")
        } else {
            Some(wait_until.as_str())
        };

        match self.proxy.send_tx(&signed_tx_base64, wait) {
            Ok(result) => (serde_json::to_string(&result).unwrap_or_default(), String::new()),
            Err(e) => (String::new(), e.to_string()),
        }
    }

    fn tx_status(&mut self, tx_hash: String, sender_account_id: String, wait_until: String) -> (String, String) {
        let mut params = json!({
            "tx_hash": tx_hash,
            "sender_account_id": sender_account_id
        });

        if !wait_until.is_empty() {
            params["wait_until"] = json!(wait_until);
        }

        match self.proxy.call_method("EXPERIMENTAL_tx_status", params) {
            Ok(result) => (serde_json::to_string(&result).unwrap_or_default(), String::new()),
            Err(e) => (String::new(), e.to_string()),
        }
    }

    fn receipt(&mut self, receipt_id: String) -> (String, String) {
        let params = json!({ "receipt_id": receipt_id });

        match self.proxy.call_method("EXPERIMENTAL_receipt", params) {
            Ok(result) => (serde_json::to_string(&result).unwrap_or_default(), String::new()),
            Err(e) => (String::new(), e.to_string()),
        }
    }

    /// CRITICAL: Worker NEVER signs with its own key!
    /// This function receives signer_id and signer_key FROM WASM (via secrets).
    /// Worker only proxies the transaction - does NOT use its own credentials.
    fn call(
        &mut self,
        signer_id: String,        // From WASM (user-provided)
        signer_key: String,       // From WASM (user-provided via secrets)
        receiver_id: String,
        method_name: String,
        args_json: String,
        deposit_yocto: String,
        gas: String,
        wait_until: String,       // NEW: wait until finality
    ) -> (String, String) {
        debug!("[HOST] call() invoked: signer={}, receiver={}, method={}, deposit={}, gas={}, wait={}",
            signer_id, receiver_id, method_name, deposit_yocto, gas,
            if wait_until.is_empty() { "FINAL" } else { &wait_until });

        let deposit: u128 = match deposit_yocto.parse() {
            Ok(d) => d,
            Err(e) => {
                debug!("[HOST] Invalid deposit: {}", e);
                return (String::new(), format!("Invalid deposit: {}", e));
            }
        };

        let gas_amount: u64 = match gas.parse() {
            Ok(g) => g,
            Err(e) => {
                debug!("[HOST] Invalid gas: {}", e);
                return (String::new(), format!("Invalid gas: {}", e));
            }
        };

        debug!("[HOST] Creating FunctionCall action...");

        let action = Action::FunctionCall(Box::new(FunctionCallAction {
            method_name: method_name.clone(),
            args: args_json.clone().into_bytes(),
            gas: Gas::from_gas(gas_amount),
            deposit: Balance::from_yoctonear(deposit),
        }));

        debug!("[HOST] Calling sign_and_send_tx_as...");

        // Note: wait_until is ignored for now - sign_and_send_tx_as always waits for FINAL
        // TODO: Add wait_until parameter to sign_and_send_tx_as
        match self.proxy.sign_and_send_tx_as(&signer_id, &signer_key, &receiver_id, vec![action]) {
            Ok(tx_hash) => {
                info!("[HOST] Transaction successful: {}", tx_hash);
                (tx_hash, String::new())
            }
            Err(e) => {
                eprintln!("[HOST] Transaction failed: {}", e);
                (String::new(), e.to_string())
            }
        }
    }

    /// CRITICAL: Worker NEVER signs with its own key!
    /// This function receives signer_id and signer_key FROM WASM (via secrets).
    /// Worker only proxies the transaction - does NOT use its own credentials.
    fn transfer(
        &mut self,
        signer_id: String,        // From WASM (user-provided)
        signer_key: String,       // From WASM (user-provided via secrets)
        receiver_id: String,
        amount_yocto: String,
        wait_until: String,       // NEW: wait until finality
    ) -> (String, String) {
        debug!("[HOST] transfer() invoked: signer={}, receiver={}, amount={}, wait={}",
            signer_id, receiver_id, amount_yocto,
            if wait_until.is_empty() { "FINAL" } else { &wait_until });

        let amount: u128 = match amount_yocto.parse() {
            Ok(a) => a,
            Err(e) => return (String::new(), format!("Invalid amount: {}", e)),
        };

        let action = Action::Transfer(TransferAction { deposit: Balance::from_yoctonear(amount) });

        // Note: wait_until is ignored for now - sign_and_send_tx_as always waits for FINAL
        // TODO: Add wait_until parameter to sign_and_send_tx_as
        match self.proxy.sign_and_send_tx_as(&signer_id, &signer_key, &receiver_id, vec![action]) {
            Ok(tx_hash) => (tx_hash, String::new()),
            Err(e) => (String::new(), e.to_string()),
        }
    }

    // ==================== Network Methods ====================

    fn gas_price(&mut self, block_id: String) -> (String, String) {
        let params = if block_id.is_empty() {
            json!([null])
        } else if let Ok(height) = block_id.parse::<u64>() {
            json!([height])
        } else {
            json!([block_id])
        };

        match self.proxy.call_method("gas_price", params) {
            Ok(result) => {
                if let Some(price) = result.get("result").and_then(|r| r.get("gas_price")) {
                    return (price.to_string(), String::new());
                }
                (serde_json::to_string(&result).unwrap_or_default(), String::new())
            }
            Err(e) => (String::new(), e.to_string()),
        }
    }

    fn status(&mut self) -> (String, String) {
        match self.proxy.call_method("status", json!([])) {
            Ok(result) => (serde_json::to_string(&result).unwrap_or_default(), String::new()),
            Err(e) => (String::new(), e.to_string()),
        }
    }

    fn network_info(&mut self) -> (String, String) {
        match self.proxy.call_method("network_info", json!([])) {
            Ok(result) => (serde_json::to_string(&result).unwrap_or_default(), String::new()),
            Err(e) => (String::new(), e.to_string()),
        }
    }

    fn validators(&mut self, epoch_id: String) -> (String, String) {
        let params = if epoch_id.is_empty() {
            json!([null])
        } else {
            json!([epoch_id])
        };

        match self.proxy.call_method("validators", params) {
            Ok(result) => (serde_json::to_string(&result).unwrap_or_default(), String::new()),
            Err(e) => (String::new(), e.to_string()),
        }
    }

    // ==================== Low-level API ====================

    fn raw(&mut self, method: String, params_json: String) -> (String, String) {
        let params: Value = serde_json::from_str(&params_json).unwrap_or(json!([]));

        match self.proxy.call_method(&method, params) {
            Ok(result) => (serde_json::to_string(&result).unwrap_or_default(), String::new()),
            Err(e) => (String::new(), e.to_string()),
        }
    }
}

/// Add NEAR RPC host functions to a wasmtime component linker
pub fn add_rpc_to_linker<T: Send + 'static>(
    linker: &mut Linker<T>,
    get_state: impl Fn(&mut T) -> &mut RpcHostState + Send + Sync + Copy + 'static,
) -> anyhow::Result<()> {
    near::rpc::api::add_to_linker(linker, get_state)
}
