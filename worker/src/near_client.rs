use anyhow::{Context, Result};
use near_crypto::InMemorySigner;
use near_jsonrpc_client::{methods, JsonRpcClient};
use near_primitives::transaction::{Action, FunctionCallAction, Transaction, TransactionV0};
use near_primitives::types::{AccountId, Balance, BlockReference, Finality, Gas};
use near_primitives::views::FinalExecutionOutcomeView;
use serde_json::{json, Value};
use tracing::{debug, info, warn};

use crate::api_client::{ExecutionOutput, ExecutionResult};

/// NEAR blockchain client for worker operations
#[derive(Clone)]
pub struct NearClient {
    client: JsonRpcClient,
    signer: InMemorySigner,
    contract_id: AccountId,
    /// Kept for the one read the typed client cannot express: NEP-591
    /// `global_contract_hash` in view_account (see [`Self::fetch_code_hash`]).
    rpc_url: String,
    /// For that same read. Built once, with its own timeouts, so a stalled RPC
    /// cannot hold a job open — and so the read does not pay for a fresh TLS
    /// setup every time.
    http: reqwest::Client,
}

impl NearClient {
    /// Create a new NEAR client
    ///
    /// # Arguments
    /// * `rpc_url` - NEAR RPC endpoint URL
    /// * `signer` - Signer for transactions
    /// * `contract_id` - OffchainVM contract account ID
    pub fn new(rpc_url: String, signer: InMemorySigner, contract_id: AccountId) -> Result<Self> {
        let client = JsonRpcClient::connect(&rpc_url);
        let http = reqwest::Client::builder()
            .timeout(Self::RPC_TIMEOUT)
            .connect_timeout(std::time::Duration::from_secs(5))
            .build()
            .context("Failed to build the view_account HTTP client")?;

        Ok(Self {
            client,
            signer,
            contract_id,
            rpc_url,
            http,
        })
    }

    /// RPC call timeout to prevent hanging on unresponsive RPC nodes
    const RPC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

    /// Broadcast tx with timeout (longer timeout since tx confirmation can take time)
    const TX_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

    /// Extract cost from transaction logs (parses [[yNEAR charged: "..."]] or estimated_cost)
    /// Parses the "Resolving execution" log from contract which contains estimated_cost
    /// Returns 0 if not found (will show as 0 NEAR in dashboard)
    #[allow(dead_code)]
    pub fn extract_payment_from_logs(outcome: &FinalExecutionOutcomeView) -> u128 {
        // Collect all logs from transaction and receipt outcomes
        let mut all_logs = Vec::new();

        info!("📋 Extracting estimated_cost from transaction logs...");

        // Logs from transaction itself
        info!("   Transaction outcome logs: {}", outcome.transaction_outcome.outcome.logs.len());
        all_logs.extend(outcome.transaction_outcome.outcome.logs.clone());

        // Logs from all receipts
        info!("   Receipt outcomes: {}", outcome.receipts_outcome.len());
        for (i, receipt_outcome) in outcome.receipts_outcome.iter().enumerate() {
            info!("   Receipt #{} executor: {}, logs: {}",
                i,
                receipt_outcome.outcome.executor_id,
                receipt_outcome.outcome.logs.len()
            );
            for (j, log) in receipt_outcome.outcome.logs.iter().enumerate() {
                let preview = if log.len() > 300 {
                    format!("{}...", head(log, 300))
                } else {
                    log.clone()
                };
                info!("      Receipt #{} Log #{}: {}", i, j, preview);
            }
            all_logs.extend(receipt_outcome.outcome.logs.clone());
        }

        info!("   Total logs to parse: {}", all_logs.len());

        // Try to find "[[yNEAR charged: \"...\"]]" log (most reliable, set after refund calculation)
        for (i, log) in all_logs.iter().enumerate() {
            info!("   Log #{}: {}", i, head(log, 200));

            // Parse log format: [[yNEAR charged: "123456789"]] (exact final cost after refunds)
            if let Some(start) = log.find("[[yNEAR charged: \"") {
                info!("   ✓ Found '[[yNEAR charged]]' log");

                let after_prefix = &log[start + "[[yNEAR charged: \"".len()..];
                // Find closing quote
                if let Some(quote_end) = after_prefix.find('"') {
                    let cost_str = &after_prefix[..quote_end];

                    match cost_str.parse::<u128>() {
                        Ok(cost) => {
                            info!("💰 Successfully extracted yNEAR charged: {} yoctoNEAR ({:.6} NEAR)",
                                cost, cost as f64 / 1e24);
                            return cost;
                        }
                        Err(e) => {
                            warn!("   ❌ Failed to parse yNEAR charged '{}' as u128: {}", cost_str, e);
                        }
                    }
                }
            }

            // Fallback: Parse "estimated_cost" from resolve_execution log (before callback)
            if log.contains("Resolving execution") && log.contains("estimated_cost:") {
                info!("   ✓ Found 'Resolving execution' log with estimated_cost");

                // Extract the cost value using string parsing
                // Format: "estimated_cost: 12345678 yoctoNEAR"
                if let Some(cost_start) = log.find("estimated_cost: ") {
                    let after_prefix = &log[cost_start + "estimated_cost: ".len()..];
                    if let Some(space_pos) = after_prefix.find(' ') {
                        let cost_str = &after_prefix[..space_pos];
                        match cost_str.parse::<u128>() {
                            Ok(cost) => {
                                info!("💰 Successfully extracted estimated_cost: {} yoctoNEAR ({:.6} NEAR)",
                                    cost, cost as f64 / 1e24);
                                return cost;
                            }
                            Err(e) => {
                                warn!("   ❌ Failed to parse estimated_cost '{}' as u128: {}", cost_str, e);
                            }
                        }
                    }
                }
            }

            // Fallback: Also try EVENT_JSON for backwards compatibility
            if let Some(event_json) = log.strip_prefix("EVENT_JSON:") {
                info!("   ✓ Found EVENT_JSON, parsing...");

                match serde_json::from_str::<Value>(event_json) {
                    Ok(event) => {
                        if let Some(event_type) = event.get("event").and_then(|e| e.as_str()) {
                            if event_type == "execution_completed" {
                                info!("   ✓ Found execution_completed event!");

                                if let Some(data) = event.get("data").and_then(|d| d.as_array()) {
                                    if let Some(first_data) = data.first() {
                                        if let Some(payment_str) = first_data.get("payment_charged").and_then(|p| p.as_str()) {
                                            info!("   ✓ Found payment_charged: {}", payment_str);

                                            match payment_str.parse::<u128>() {
                                                Ok(payment) => {
                                                    info!("💰 Successfully extracted payment_charged from event: {} yoctoNEAR ({:.6} NEAR)",
                                                        payment, payment as f64 / 1e24);
                                                    return payment;
                                                }
                                                Err(e) => {
                                                    warn!("   ❌ Failed to parse payment_charged: {}", e);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        warn!("   ❌ Failed to parse EVENT_JSON: {}", e);
                    }
                }
            }
        }

        warn!("⚠️  Contract did not provide estimated_cost in logs - will record as 0 NEAR");
        0
    }

    /// Submit execution result using optimized 1-transaction flow
    ///
    /// This method handles large outputs efficiently by calling the combined
    /// submit_execution_output_and_resolve method which:
    /// 1. Stores large output in contract storage
    /// 2. Creates internal promise to resolve_execution
    ///
    /// This saves ~1-2 seconds compared to two separate transactions.
    ///
    /// # Arguments
    /// * `request_id` - Request ID from the contract
    /// * `result` - Execution result with large output
    async fn submit_result_two_call_flow(
        &self,
        request_id: u64,
        result: &ExecutionResult,
    ) -> Result<(String, FinalExecutionOutcomeView)> {
        let output = result.output.as_ref().unwrap();

        // Prepare arguments for submit_execution_output_and_resolve
        let args = json!({
            "request_id": request_id,
            "output": output,
            "success": result.success,
            "error": result.error,
            "resources_used": {
                "instructions": result.instructions,
                "time_ms": result.execution_time_ms,
                "compile_time_ms": result.compile_time_ms,
            },
            "compilation_note": result.compilation_note,
            "refund_usd": result.refund_usd,
        });

        let args_json = serde_json::to_string(&args)
            .context("Failed to serialize submit_execution_output_and_resolve args")?;

        info!(
            "📤 Submitting large output + resolve in ONE transaction (size: {} bytes)",
            args_json.len()
        );

        // Call the combined method (400 TGas: 100 for submit + 300 for internal resolve)
        let outcome = self
            .call_contract_method(
                "submit_execution_output_and_resolve",
                args_json.into_bytes(),
                300_000_000_000_000, // 300 TGas total
                0,
            )
            .await
            .context("Failed to call submit_execution_output_and_resolve")?;

        info!("✅ Combined transaction complete: {:?}", outcome.status);
        info!("   Transaction ID: {}", outcome.transaction_outcome.id);
        info!("   Receipt outcomes: {}", outcome.receipts_outcome.len());

        // No need to fetch nested receipts - submit_execution_output_and_resolve
        // is synchronous (no Promise), all logs are in the initial outcome

        // Return transaction hash and outcome
        let tx_hash = format!("{}", outcome.transaction_outcome.id);
        Ok((tx_hash, outcome))
    }

    /// Submit large execution output separately (legacy 2-call flow)
    ///
    /// This is kept as a fallback option. The recommended approach is to use
    /// submit_execution_output_and_resolve for better performance.
    ///
    /// # Arguments
    /// * `request_id` - Request ID from the contract
    /// * `output` - Execution output (bytes, text, or JSON)
    ///
    /// # Returns
    /// * `Ok(tx_hash)` - Transaction hash as hex string
    #[allow(dead_code)]
    async fn submit_execution_output(
        &self,
        request_id: u64,
        output: &ExecutionOutput,
    ) -> Result<String> {
        info!(
            "📤 Submitting large execution output separately: request_id={}",
            request_id
        );

        // Prepare method arguments matching contract signature:
        // submit_execution_output(request_id: u64, output: ExecutionOutput)
        let args = json!({
            "request_id": request_id,
            "output": output,
        });

        let args_json = serde_json::to_string(&args).context("Failed to serialize args")?;
        info!("📤 Full args for submit_execution_output (size: {} bytes)", args_json.len());

        // Send transaction (no deposit needed)
        let outcome = self
            .call_contract_method(
                "submit_execution_output",
                args_json.into_bytes(),
                100_000_000_000_000, // 100 TGas
                0, // No deposit
            )
            .await
            .context("Failed to call submit_execution_output")?;

        info!("✅ submit_execution_output transaction outcome status: {:?}", outcome.status);
        info!("   Transaction ID: {}", outcome.transaction_outcome.id);

        // Return transaction hash as hex string
        let tx_hash = format!("{}", outcome.transaction_outcome.id);
        Ok(tx_hash)
    }

    /// Submit execution result back to the NEAR contract
    ///
    /// Automatically decides between 1-call or 2-call flow based on payload size:
    /// - If payload < 1024 bytes: calls `resolve_execution` directly (1-call)
    /// - If payload >= 1024 bytes: calls `submit_execution_output_and_resolve` (optimized 1-transaction flow)
    ///
    /// # Arguments
    /// * `request_id` - Request ID from the contract
    /// * `result` - Execution result from WASM executor
    ///
    /// # Returns
    /// * `Ok((tx_hash, outcome))` - Transaction hash and full execution outcome
    pub async fn submit_execution_result(
        &self,
        request_id: u64,
        result: &ExecutionResult,
    ) -> Result<(String, FinalExecutionOutcomeView)> {
        info!(
            "📡 Submitting execution result: request_id={}, success={}",
            request_id, result.success
        );

        // Check payload size to decide between 1-call or 2-call flow
        // Build full ExecutionResponse to estimate payload size
        let full_response = json!({
            "success": result.success,
            "output": result.output,
            "error": result.error,
            "resources_used": {
                "instructions": result.instructions,
                "time_ms": result.execution_time_ms,
                "compile_time_ms": result.compile_time_ms,
            },
            "compilation_note": result.compilation_note,
            "refund_usd": result.refund_usd,
        });

        let response_json = serde_json::to_string(&full_response)
            .context("Failed to serialize response")?;

        const PAYLOAD_LIMIT: usize = 1024;
        let payload_size = response_json.len();

        info!("📊 Response payload size: {} bytes (limit: {} bytes)", payload_size, PAYLOAD_LIMIT);
        info!("   result.success={}, result.output.is_some()={}, result.error.is_some()={}",
            result.success, result.output.is_some(), result.error.is_some());

        // Check if payload exceeds limit
        if payload_size >= PAYLOAD_LIMIT {
            // Payload too large - need to use 2-call flow
            if result.success && result.output.is_some() {
                // Success case: use optimized 2-call flow (submit_execution_output_and_resolve)
                info!("⚠️  Payload exceeds limit ({} >= {}), using 2-call flow (submit_execution_output_and_resolve)",
                    payload_size, PAYLOAD_LIMIT);
                return self.submit_result_two_call_flow(request_id, result).await;
            } else {
                // Error case: truncate error message to fit in 1024 byte limit
                // This prevents transaction failure due to large error messages
                info!("⚠️  Payload exceeds limit ({} >= {}) but execution failed - truncating error message",
                    payload_size, PAYLOAD_LIMIT);

                let truncated_result = if let Some(ref error_msg) = result.error {
                    if error_msg.len() > MAX_ERROR_SIZE {
                        info!("   Truncated error from {} to {} bytes", error_msg.len(), MAX_ERROR_SIZE);
                        let mut new_result = result.clone();
                        new_result.error = Some(truncate_error_for_chain(error_msg));
                        new_result
                    } else {
                        result.clone()
                    }
                } else {
                    result.clone()
                };

                // Continue with 1-call flow using truncated result
                return self.submit_small_result(request_id, &truncated_result).await;
            }
        } else {
            info!("✅ Payload size OK, using 1-call flow (resolve_execution only)");
        }

        // Use standard 1-call flow
        self.submit_small_result(request_id, result).await
    }

    /// Submit small execution result using 1-call flow (resolve_execution only)
    ///
    /// This method is used when the payload fits within the 1024 byte limit.
    async fn submit_small_result(
        &self,
        request_id: u64,
        result: &ExecutionResult,
    ) -> Result<(String, FinalExecutionOutcomeView)> {
        // 1-call flow: Prepare method arguments for resolve_execution with output
        let args = json!({
            "request_id": request_id,
            "response": {
                "success": result.success,
                "output": result.output,
                "error": result.error,
                "resources_used": {
                    "instructions": result.instructions,
                    "time_ms": result.execution_time_ms,
                    "compile_time_ms": result.compile_time_ms,
                },
                "compilation_note": result.compilation_note,
                "refund_usd": result.refund_usd,
            }
        });

        let args_json = serde_json::to_string(&args).context("Failed to serialize args")?;
        info!("📤 resolve_execution args (1-call flow, with output): size={} bytes", args_json.len());

        info!("   Args preview (first 500 bytes): {}", head(&args_json, 500));

        // Send transaction
        info!("🔗 Sending resolve_execution transaction:");
        info!("   Contract: {}", self.contract_id);
        info!("   Signer: {}", self.signer.account_id);
        info!("   Method: resolve_execution");
        info!("   Gas: 300 TGas");

        let outcome = self
            .call_contract_method(
                "resolve_execution",
                args_json.into_bytes(),
                300_000_000_000_000, // 300 TGas (increased for yield resume)
                0,                    // No attached deposit
            )
            .await
            .context("Failed to call resolve_execution")?;

        info!("✅ Transaction outcome status: {:?}", outcome.status);
        info!("   Transaction ID: {}", outcome.transaction_outcome.id);
        info!("   Receipt outcomes: {}", outcome.receipts_outcome.len());

        // Log receipt details for debugging
        for (i, receipt) in outcome.receipts_outcome.iter().enumerate() {
            info!("   Receipt #{}: executor={}, logs={}",
                i, receipt.outcome.executor_id, receipt.outcome.logs.len());
            for (j, log) in receipt.outcome.logs.iter().enumerate() {
                info!("      Log #{}: {}", j, log);
            }
        }

        // Return transaction hash and outcome with receipt logs
        // Note: The estimated_cost is in the resolve_execution receipt logs
        let tx_hash = format!("{}", outcome.transaction_outcome.id);
        Ok((tx_hash, outcome))
    }

    /// Call a contract method with explicit nonce
    #[allow(dead_code)]
    async fn call_contract_method_with_nonce(
        &self,
        method_name: &str,
        args: Vec<u8>,
        gas: u64,
        deposit: u128,
        nonce: u64,
        block_hash: near_primitives::hash::CryptoHash,
    ) -> Result<FinalExecutionOutcomeView> {
        // Create transaction using V0 format (no priority_fee)
        let transaction_v0 = TransactionV0 {
            signer_id: self.signer.account_id.clone(),
            public_key: self.signer.public_key(),
            nonce,
            receiver_id: self.contract_id.clone(),
            block_hash,
            actions: vec![Action::FunctionCall(Box::new(FunctionCallAction {
                method_name: method_name.to_string(),
                args,
                gas: Gas::from_gas(gas),
                deposit: Balance::from_yoctonear(deposit),
            }))],
        };

        let transaction = Transaction::V0(transaction_v0);

        // Sign transaction
        let signature = self.signer.sign(transaction.get_hash_and_size().0.as_ref());
        let signed_transaction = near_primitives::transaction::SignedTransaction::new(
            signature,
            transaction,
        );
        let hash = signed_transaction.get_hash();

        // Broadcast transaction with commit (wait for finality)
        let tx_request = methods::broadcast_tx_commit::RpcBroadcastTxCommitRequest {
            signed_transaction,
        };

        debug!("Broadcasting transaction with commit: {:?}", hash);

        let outcome = tokio::time::timeout(Self::TX_TIMEOUT, self.client.call(tx_request))
            .await
            .context("NEAR RPC broadcast timed out")?
            .context("Failed to broadcast transaction and wait for commit")?;

        debug!("Transaction committed: {:?}", hash);

        Ok(outcome)
    }

    /// Call a contract method (public API for registration and other use cases)
    ///
    /// # Arguments
    /// * `contract_id` - Target contract account ID
    /// * `method_name` - Contract method name
    /// * `args` - Serialized JSON arguments
    /// * `gas` - Gas limit in yoctoGas
    /// * `deposit` - Attached NEAR deposit in yoctoNEAR
    ///
    /// # Returns
    /// * Transaction outcome with logs and receipts
    pub async fn call_contract(
        &self,
        contract_id: &AccountId,
        method_name: &str,
        args: Vec<u8>,
        gas: u64,
        deposit: u128,
    ) -> Result<FinalExecutionOutcomeView> {
        self.call_contract_method_internal(contract_id, method_name, args, gas, deposit).await
    }

    /// Call a contract method (internal - uses default contract_id)
    async fn call_contract_method(
        &self,
        method_name: &str,
        args: Vec<u8>,
        gas: u64,
        deposit: u128,
    ) -> Result<FinalExecutionOutcomeView> {
        self.call_contract_method_internal(&self.contract_id, method_name, args, gas, deposit).await
    }

    /// Call a contract method (internal implementation)
    async fn call_contract_method_internal(
        &self,
        contract_id: &AccountId,
        method_name: &str,
        args: Vec<u8>,
        gas: u64,
        deposit: u128,
    ) -> Result<FinalExecutionOutcomeView> {
        // Get account access key for nonce
        let access_key_query = methods::query::RpcQueryRequest {
            block_reference: BlockReference::Finality(Finality::Final),
            request: near_primitives::views::QueryRequest::ViewAccessKey {
                account_id: self.signer.account_id.clone(),
                public_key: self.signer.public_key(),
            },
        };

        let access_key_response = tokio::time::timeout(Self::RPC_TIMEOUT, self.client.call(access_key_query))
            .await
            .context("NEAR RPC access key query timed out")?
            .context("Failed to query access key")?;

        let current_nonce = match access_key_response.kind {
            near_jsonrpc_primitives::types::query::QueryResponseKind::AccessKey(access_key) => {
                access_key.nonce
            }
            _ => anyhow::bail!("Unexpected query response"),
        };

        // Get latest block hash
        let block_query = methods::block::RpcBlockRequest {
            block_reference: BlockReference::Finality(Finality::Final),
        };

        let block = tokio::time::timeout(Self::RPC_TIMEOUT, self.client.call(block_query))
            .await
            .context("NEAR RPC block query timed out")?
            .context("Failed to query block")?;

        let block_hash = block.header.hash;

        // Create transaction using V0 format (no priority_fee)
        let transaction_v0 = TransactionV0 {
            signer_id: self.signer.account_id.clone(),
            public_key: self.signer.public_key(),
            nonce: current_nonce + 1,
            receiver_id: contract_id.clone(),
            block_hash,
            actions: vec![Action::FunctionCall(Box::new(FunctionCallAction {
                method_name: method_name.to_string(),
                args,
                gas: Gas::from_gas(gas),
                deposit: Balance::from_yoctonear(deposit),
            }))],
        };

        let transaction = Transaction::V0(transaction_v0);

        // Sign transaction
        let signature = self.signer.sign(transaction.get_hash_and_size().0.as_ref());
        let signed_transaction = near_primitives::transaction::SignedTransaction::new(
            signature,
            transaction,
        );
        let hash = signed_transaction.get_hash();

        // Broadcast transaction with commit (wait for finality)
        let tx_request = methods::broadcast_tx_commit::RpcBroadcastTxCommitRequest {
            signed_transaction,
        };

        debug!("Broadcasting transaction with commit: {:?}", hash);

        let outcome = tokio::time::timeout(Self::TX_TIMEOUT, self.client.call(tx_request))
            .await
            .context("NEAR RPC broadcast timed out")?
            .context("Failed to broadcast transaction and wait for commit")?;

        debug!("Transaction committed: {:?}", hash);

        Ok(outcome)
    }

    /// Resume a TopUp yield promise
    ///
    /// # Arguments
    /// * `data_id` - CryptoHash from the yield promise (hex encoded)
    /// * `new_encrypted_data` - New encrypted secret with updated balance (base64)
    ///
    /// # Returns
    /// * `Ok(tx_hash)` - Transaction hash
    pub async fn resume_topup(
        &self,
        data_id: &str,
        new_encrypted_data: &str,
    ) -> Result<String> {
        info!("📤 Resuming TopUp: data_id={}", data_id);

        // Build TopUpResult::Success
        let args = json!({
            "data_id": data_id,
            "result": {
                "Success": {
                    "new_encrypted_data": new_encrypted_data
                }
            }
        });

        let args_json = serde_json::to_string(&args)
            .context("Failed to serialize resume_topup args")?;

        let outcome = self
            .call_contract_method(
                "resume_topup",
                args_json.into_bytes(),
                100_000_000_000_000, // 100 TGas
                0,                    // No deposit
            )
            .await
            .context("Failed to call resume_topup")?;

        let tx_hash = format!("{}", outcome.transaction_outcome.id);
        info!("✅ TopUp resumed: data_id={} tx={}", data_id, tx_hash);

        Ok(tx_hash)
    }

    /// Resume a TopUp yield promise with error
    ///
    /// # Arguments
    /// * `data_id` - CryptoHash from the yield promise (hex encoded)
    /// * `error_message` - Error message
    ///
    /// # Returns
    /// * `Ok(tx_hash)` - Transaction hash
    pub async fn resume_topup_error(
        &self,
        data_id: &str,
        error_message: &str,
    ) -> Result<String> {
        info!("📤 Resuming TopUp with error: data_id={} error={}", data_id, error_message);

        // Build TopUpResult::Error
        let args = json!({
            "data_id": data_id,
            "result": {
                "Error": {
                    "message": error_message
                }
            }
        });

        let args_json = serde_json::to_string(&args)
            .context("Failed to serialize resume_topup args")?;

        let outcome = self
            .call_contract_method(
                "resume_topup",
                args_json.into_bytes(),
                100_000_000_000_000, // 100 TGas
                0,                    // No deposit
            )
            .await
            .context("Failed to call resume_topup")?;

        let tx_hash = format!("{}", outcome.transaction_outcome.id);
        info!("✅ TopUp error resumed: data_id={} tx={}", data_id, tx_hash);

        Ok(tx_hash)
    }

    /// Resume a DeletePaymentKey yield promise with success
    ///
    /// Called after successfully deleting the payment key from coordinator PostgreSQL.
    ///
    /// # Arguments
    /// * `data_id` - CryptoHash from the yield promise (hex encoded)
    ///
    /// # Returns
    /// * `Ok(tx_hash)` - Transaction hash
    pub async fn resume_delete_payment_key(&self, data_id: &str) -> Result<String> {
        info!("📤 Resuming DeletePaymentKey: data_id={}", data_id);

        // Build DeletePaymentKeyResult::Success
        let args = json!({
            "data_id": data_id,
            "result": "Success"
        });

        let args_json = serde_json::to_string(&args)
            .context("Failed to serialize resume_delete_payment_key args")?;

        let outcome = self
            .call_contract_method(
                "resume_delete_payment_key",
                args_json.into_bytes(),
                100_000_000_000_000, // 100 TGas
                0,                    // No deposit
            )
            .await
            .context("Failed to call resume_delete_payment_key")?;

        let tx_hash = format!("{}", outcome.transaction_outcome.id);
        info!("✅ DeletePaymentKey resumed: data_id={} tx={}", data_id, tx_hash);

        Ok(tx_hash)
    }

    /// Resume a DeletePaymentKey yield promise with error
    ///
    /// # Arguments
    /// * `data_id` - CryptoHash from the yield promise (hex encoded)
    /// * `error_message` - Error message
    ///
    /// # Returns
    /// * `Ok(tx_hash)` - Transaction hash
    pub async fn resume_delete_payment_key_error(
        &self,
        data_id: &str,
        error_message: &str,
    ) -> Result<String> {
        info!(
            "📤 Resuming DeletePaymentKey with error: data_id={} error={}",
            data_id, error_message
        );

        // Build DeletePaymentKeyResult::Error
        let args = json!({
            "data_id": data_id,
            "result": {
                "Error": {
                    "message": error_message
                }
            }
        });

        let args_json = serde_json::to_string(&args)
            .context("Failed to serialize resume_delete_payment_key args")?;

        let outcome = self
            .call_contract_method(
                "resume_delete_payment_key",
                args_json.into_bytes(),
                100_000_000_000_000, // 100 TGas
                0,                    // No deposit
            )
            .await
            .context("Failed to call resume_delete_payment_key")?;

        let tx_hash = format!("{}", outcome.transaction_outcome.id);
        info!(
            "✅ DeletePaymentKey error resumed: data_id={} tx={}",
            data_id, tx_hash
        );

        Ok(tx_hash)
    }

    /// Fetch project info from contract by project_id
    ///
    /// Returns project with active version info (repo, commit, build_target)
    /// Used for HTTPS API calls where coordinator passes project_id instead of code_source
    pub async fn fetch_project(&self, project_id: &str) -> Result<Option<ProjectInfo>> {
        info!("📦 Fetching project from contract: {}", project_id);

        let request = methods::query::RpcQueryRequest {
            block_reference: BlockReference::Finality(Finality::Final),
            request: near_primitives::views::QueryRequest::CallFunction {
                account_id: self.contract_id.clone(),
                method_name: "get_project".to_string(),
                args: json!({ "project_id": project_id }).to_string().into_bytes().into(),
            },
        };

        let response = tokio::time::timeout(Self::RPC_TIMEOUT, self.client.call(request))
            .await
            .context("NEAR RPC get_project timed out")?
            .context("Failed to call get_project")?;

        if let near_jsonrpc_primitives::types::query::QueryResponseKind::CallResult(result) = response.kind {
            if result.result.is_empty() {
                debug!("Project not found: {}", project_id);
                return Ok(None);
            }

            let project: ProjectInfo = serde_json::from_slice(&result.result)
                .context("Failed to parse project info")?;

            info!("✅ Project found: {} (active_version: {})", project.project_id, project.active_version);
            Ok(Some(project))
        } else {
            anyhow::bail!("Unexpected response kind from get_project");
        }
    }

    /// Which per-customer vault a payment key's secret is bound to, if any.
    ///
    /// Read from the CHAIN rather than taken from the task, because it decides
    /// which master decrypts the blob: a value supplied by whoever is asking
    /// would let the asker choose the key-space, and choosing wrong is the
    /// difference between reading a customer's balance and not.
    ///
    /// `None` means the default master — every key created by a wallet without
    /// a vault, which is most of them.
    pub async fn fetch_payment_key_vault(
        &self,
        owner: &str,
        nonce: u32,
    ) -> Result<Option<String>> {
        let request = methods::query::RpcQueryRequest {
            block_reference: BlockReference::Finality(Finality::Final),
            request: near_primitives::views::QueryRequest::CallFunction {
                account_id: self.contract_id.clone(),
                method_name: "get_secret_vault".to_string(),
                args: json!({
                    "accessor": { "System": "PaymentKey" },
                    "profile": nonce.to_string(),
                    "owner": owner,
                })
                .to_string()
                .into_bytes()
                .into(),
            },
        };

        let response = tokio::time::timeout(Self::RPC_TIMEOUT, self.client.call(request))
            .await
            .context("NEAR RPC get_secret_vault timed out")?
            .context("Failed to call get_secret_vault")?;

        if let near_jsonrpc_primitives::types::query::QueryResponseKind::CallResult(result) =
            response.kind
        {
            if result.result.is_empty() {
                return Ok(None);
            }
            let vault: Option<String> = serde_json::from_slice(&result.result)
                .context("Failed to parse get_secret_vault response")?;
            Ok(vault)
        } else {
            anyhow::bail!("Unexpected response kind from get_secret_vault");
        }
    }

    /// `hos_agent_status(extension)` on an Agent Connect asset account.
    ///
    /// Read from the CHAIN rather than taken from the task, for the same
    /// reason as [`Self::fetch_payment_key_vault`]: the value decides an
    /// identity — whether this job may run under the asset account's name —
    /// and a value supplied by whoever queued the job would let the asker
    /// pick it. The verdict on the answer is
    /// `shared_tee_helpers::hos::assess_binding`, shared with the
    /// coordinator so the two cannot read the same response differently.
    pub async fn fetch_hos_agent_status(
        &self,
        asset_account_id: &str,
        executor_account_id: &str,
    ) -> Result<shared_tee_helpers::hos::AgentStatusView> {
        let asset: AccountId = asset_account_id
            .parse()
            .with_context(|| format!("Invalid asset account id: {}", asset_account_id))?;

        let request = methods::query::RpcQueryRequest {
            block_reference: BlockReference::Finality(Finality::Final),
            request: near_primitives::views::QueryRequest::CallFunction {
                account_id: asset,
                method_name: "hos_agent_status".to_string(),
                args: json!({ "extension": executor_account_id })
                    .to_string()
                    .into_bytes()
                    .into(),
            },
        };

        let response = tokio::time::timeout(Self::RPC_TIMEOUT, self.client.call(request))
            .await
            .context("NEAR RPC hos_agent_status timed out")?
            .context("Failed to call hos_agent_status")?;

        if let near_jsonrpc_primitives::types::query::QueryResponseKind::CallResult(result) =
            response.kind
        {
            serde_json::from_slice(&result.result)
                .context("Failed to parse hos_agent_status response")
        } else {
            anyhow::bail!("Unexpected response kind from hos_agent_status");
        }
    }

    /// `w_is_extension_enabled(executor)` on a personal_account-bound account —
    /// the membership half of that mode's evidence; the other half is
    /// [`Self::fetch_code_hash`]. Same chain-not-task rationale as
    /// [`Self::fetch_hos_agent_status`].
    pub async fn fetch_extension_enabled(
        &self,
        account_id: &str,
        executor_account_id: &str,
    ) -> Result<bool> {
        let account: AccountId = account_id
            .parse()
            .with_context(|| format!("Invalid account id: {}", account_id))?;

        let request = methods::query::RpcQueryRequest {
            block_reference: BlockReference::Finality(Finality::Final),
            request: near_primitives::views::QueryRequest::CallFunction {
                account_id: account,
                method_name: "w_is_extension_enabled".to_string(),
                args: json!({ "account_id": executor_account_id })
                    .to_string()
                    .into_bytes()
                    .into(),
            },
        };

        let response = tokio::time::timeout(Self::RPC_TIMEOUT, self.client.call(request))
            .await
            .context("NEAR RPC w_is_extension_enabled timed out")?
            .context("Failed to call w_is_extension_enabled")?;

        if let near_jsonrpc_primitives::types::query::QueryResponseKind::CallResult(result) =
            response.kind
        {
            serde_json::from_slice(&result.result)
                .context("Failed to parse w_is_extension_enabled response")
        } else {
            anyhow::bail!("Unexpected response kind from w_is_extension_enabled");
        }
    }

    /// The hash of the code the account RUNS, raw 32 bytes: `code_hash` for
    /// an inline deploy, `global_contract_hash` for a NEP-591 global
    /// reference (the recommended install path, where `code_hash` stays at
    /// the zero sentinel). Raw JSON-RPC on purpose: the typed `AccountView`
    /// of this near-primitives has no NEP-591 field and would silently drop
    /// it — refusing every properly installed wallet. An account that does
    /// not exist is an error; an account with NO code answers all-zeros —
    /// both directions end in refusal at the caller.
    pub async fn fetch_code_hash(&self, account_id: &str) -> Result<[u8; 32]> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": "view_account",
            "method": "query",
            "params": {
                "request_type": "view_account",
                "finality": "final",
                "account_id": account_id,
            },
        });
        // The timeout covers the BODY too. Wrapping `send()` alone bounds the
        // headers and leaves the read after them unbounded, so an RPC that
        // answers and then stalls holds the job forever — the one failure a
        // timeout is there to prevent.
        let resp: serde_json::Value = tokio::time::timeout(Self::RPC_TIMEOUT, async {
            self.http
                .post(&self.rpc_url)
                .json(&body)
                .send()
                .await
                .with_context(|| format!("Failed to view account {}", account_id))?
                .json::<serde_json::Value>()
                .await
                .context("view_account response is not JSON")
        })
        .await
        .context("NEAR RPC view_account timed out")??;

        if let Some(err) = resp.get("error") {
            anyhow::bail!("view_account({}) RPC error: {}", account_id, err);
        }
        let code_hash = resp["result"]["code_hash"].as_str();
        let global = resp["result"]["global_contract_hash"].as_str();
        if code_hash.is_none() && global.is_none() {
            anyhow::bail!("Missing code_hash in view_account for {}", account_id);
        }
        let effective =
            shared_tee_helpers::binding::effective_code_hash_b58(code_hash, global)
                .unwrap_or_else(|| {
                    shared_tee_helpers::binding::NO_CODE_HASH_B58.to_string()
                });
        shared_tee_helpers::binding::parse_code_hash_base58(&effective)
            .with_context(|| format!("Unparseable code hash '{}' for {}", effective, account_id))
    }

    /// Fetch project version (code source) from contract
    pub async fn fetch_project_version(&self, project_id: &str, version_key: &str) -> Result<Option<VersionView>> {
        info!("📦 Fetching project version: {} @ {}", project_id, version_key);

        let request = methods::query::RpcQueryRequest {
            block_reference: BlockReference::Finality(Finality::Final),
            request: near_primitives::views::QueryRequest::CallFunction {
                account_id: self.contract_id.clone(),
                method_name: "get_version".to_string(),
                args: json!({
                    "project_id": project_id,
                    "version_key": version_key
                }).to_string().into_bytes().into(),
            },
        };

        let response = tokio::time::timeout(Self::RPC_TIMEOUT, self.client.call(request))
            .await
            .context("NEAR RPC get_version timed out")?
            .context("Failed to call get_version")?;

        if let near_jsonrpc_primitives::types::query::QueryResponseKind::CallResult(result) = response.kind {
            if result.result.is_empty() {
                debug!("Project version not found: {} @ {}", project_id, version_key);
                return Ok(None);
            }

            let version_view: VersionView = serde_json::from_slice(&result.result)
                .context("Failed to parse version view")?;

            info!("✅ Project version found: source={:?}", version_view.source);
            Ok(Some(version_view))
        } else {
            anyhow::bail!("Unexpected response kind from get_version");
        }
    }
}

/// Project info from contract
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProjectInfo {
    pub uuid: String,
    pub owner: String,
    pub name: String,
    pub project_id: String,
    pub active_version: String,
}

/// Version view from contract (matches contract's VersionView)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VersionView {
    pub wasm_hash: String,
    pub source: ContractCodeSource,
    pub added_at: u64,
    pub is_active: bool,
}

/// Code source from contract (matches contract's CodeSource enum)
/// Uses serde default (externally tagged) to match NEAR SDK serialization:
/// {"GitHub": {"repo": "...", "commit": "...", "build_target": "..."}}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ContractCodeSource {
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

/// The most of an error message that fits the 1-call flow's 1024-byte
/// payload beside its JSON envelope.
const MAX_ERROR_SIZE: usize = 512;

/// An error message cut to fit the chain, saying it was cut. Cut on a
/// character boundary: the text is whatever a guest or a refusal wrote,
/// multi-byte letters included, and a byte index inside one of them is a
/// panic — in the worker's own loop, which ends the process.
fn truncate_error_for_chain(error_msg: &str) -> String {
    format!(
        "{}... (truncated, original size: {} bytes)",
        head(error_msg, MAX_ERROR_SIZE),
        error_msg.len()
    )
}

/// The first `max` bytes of `s`, never cutting a character: every preview of
/// text this worker did not write — a guest's output, a contract's log, an
/// RPC body — goes through here rather than through `&s[..n]`.
pub(crate) fn head(s: &str, max: usize) -> &str {
    &s[..s.floor_char_boundary(max)]
}

#[cfg(test)]
mod text_this_worker_did_not_write_is_cut_on_a_character_boundary {
    use super::{head, truncate_error_for_chain, MAX_ERROR_SIZE};

    #[test]
    fn a_multibyte_error_straddling_the_limit_does_not_panic() {
        // 600 two-byte letters: byte 512 falls inside the 257th.
        let msg = "ж".repeat(600);
        let cut = truncate_error_for_chain(&msg);
        assert!(cut.ends_with("(truncated, original size: 1200 bytes)"), "{cut}");
        assert!(cut.starts_with(&"ж".repeat(256)) && !cut.starts_with(&"ж".repeat(257)));
        let payload = cut.len() - "... (truncated, original size: 1200 bytes)".len();
        assert!(payload <= MAX_ERROR_SIZE);
    }

    #[test]
    fn head_never_splits_a_character() {
        assert_eq!(head("abc", 10), "abc");
        assert_eq!(head("abcdef", 3), "abc");
        assert_eq!(head("жж", 1), "");
        assert_eq!(head("жж", 2), "ж");
        assert_eq!(head("жж", 3), "ж");
        assert_eq!(head("", 5), "");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_crypto::SecretKey;

    #[test]
    fn test_near_client_creation() {
        let secret_key = "ed25519:3D4YudUahN1nawWvHfEKBGpmJLfbCTbvdXDJKqfLhQ98XewyWK4tEDWvmAYPZqcgz7qfkCEHyWD15m8JVVWJ3LXD"
            .parse::<SecretKey>()
            .unwrap();
        let signer = InMemorySigner {
            account_id: "worker.testnet".parse().unwrap(),
            public_key: secret_key.public_key(),
            secret_key,
        };

        let client = NearClient::new(
            "https://rpc.testnet.near.org".to_string(),
            signer,
            "outlayer.testnet".parse().unwrap(),
        );

        assert!(client.is_ok());
    }
}
