//! NEAR RPC method implementations
//!
//! All methods follow the official NEAR RPC API specification.
//! Reference: https://docs.near.org/api/rpc/introduction
//!
//! ## Method Categories
//!
//! - **Query**: view_account, view_code, view_state, call_function, view_access_key, view_access_key_list
//! - **Block/Chunk**: block, chunk, changes_in_block
//! - **Gas**: gas_price
//! - **Network**: status, network_info, validators
//! - **Protocol**: EXPERIMENTAL_genesis_config, EXPERIMENTAL_protocol_config
//! - **Transactions**: send_tx, tx, broadcast_tx_async, broadcast_tx_commit, EXPERIMENTAL_tx_status

use anyhow::Result;
use serde_json::{json, Value};

use super::RpcProxy;

#[allow(dead_code)]
impl RpcProxy {
    // =========================================================================
    // Query Methods (view calls)
    // =========================================================================

    /// View account information
    ///
    /// # Arguments
    /// * `account_id` - Account to query
    /// * `finality` - "final" or "optimistic", or None to use block_id
    /// * `block_id` - Block height or hash (optional, used if finality is None)
    pub async fn view_account(
        &self,
        account_id: &str,
        finality: Option<&str>,
        block_id: Option<Value>,
    ) -> Result<Value> {
        let mut params = json!({
            "request_type": "view_account",
            "account_id": account_id
        });

        Self::add_block_reference(&mut params, finality, block_id);
        self.call_method("query", params).await
    }

    /// View contract code (returns base64)
    #[allow(dead_code)]
    pub async fn view_code(
        &self,
        account_id: &str,
        finality: Option<&str>,
        block_id: Option<Value>,
    ) -> Result<Value> {
        let mut params = json!({
            "request_type": "view_code",
            "account_id": account_id
        });

        Self::add_block_reference(&mut params, finality, block_id);
        self.call_method("query", params).await
    }

    /// View contract state (key-value pairs)
    #[allow(dead_code)]
    pub async fn view_state(
        &self,
        account_id: &str,
        prefix_base64: &str,
        finality: Option<&str>,
        block_id: Option<Value>,
    ) -> Result<Value> {
        let mut params = json!({
            "request_type": "view_state",
            "account_id": account_id,
            "prefix_base64": prefix_base64
        });

        Self::add_block_reference(&mut params, finality, block_id);
        self.call_method("query", params).await
    }

    /// Call a view function on a contract
    ///
    /// # Arguments
    /// * `account_id` - Contract account ID
    /// * `method_name` - Method to call
    /// * `args_base64` - Arguments encoded in base64
    pub async fn call_function(
        &self,
        account_id: &str,
        method_name: &str,
        args_base64: &str,
        finality: Option<&str>,
        block_id: Option<Value>,
    ) -> Result<Value> {
        let mut params = json!({
            "request_type": "call_function",
            "account_id": account_id,
            "method_name": method_name,
            "args_base64": args_base64
        });

        Self::add_block_reference(&mut params, finality, block_id);
        self.call_method("query", params).await
    }

    /// View a single access key
    pub async fn view_access_key(
        &self,
        account_id: &str,
        public_key: &str,
        finality: Option<&str>,
        block_id: Option<Value>,
    ) -> Result<Value> {
        let mut params = json!({
            "request_type": "view_access_key",
            "account_id": account_id,
            "public_key": public_key
        });

        Self::add_block_reference(&mut params, finality, block_id);
        self.call_method("query", params).await
    }

    /// View all access keys for an account
    #[allow(dead_code)]
    pub async fn view_access_key_list(
        &self,
        account_id: &str,
        finality: Option<&str>,
        block_id: Option<Value>,
    ) -> Result<Value> {
        let mut params = json!({
            "request_type": "view_access_key_list",
            "account_id": account_id
        });

        Self::add_block_reference(&mut params, finality, block_id);
        self.call_method("query", params).await
    }

    // =========================================================================
    // Block/Chunk Methods
    // =========================================================================

    /// Get block details
    ///
    /// # Arguments
    /// * `finality` - "final" or "optimistic"
    /// * `block_id` - Block height (number) or hash (string)
    pub async fn block(&self, finality: Option<&str>, block_id: Option<Value>) -> Result<Value> {
        let params = if let Some(fin) = finality {
            json!({ "finality": fin })
        } else if let Some(id) = block_id {
            json!({ "block_id": id })
        } else {
            json!({ "finality": "final" })
        };

        self.call_method("block", params).await
    }

    /// Get chunk details
    ///
    /// # Arguments
    /// * `chunk_id` - Chunk hash
    /// OR
    /// * `block_id` - Block height/hash
    /// * `shard_id` - Shard ID
    #[allow(dead_code)]
    pub async fn chunk(
        &self,
        chunk_id: Option<&str>,
        block_id: Option<Value>,
        shard_id: Option<u64>,
    ) -> Result<Value> {
        let params = if let Some(id) = chunk_id {
            json!({ "chunk_id": id })
        } else if let (Some(bid), Some(sid)) = (block_id, shard_id) {
            json!({ "block_id": bid, "shard_id": sid })
        } else {
            anyhow::bail!("chunk requires either chunk_id or (block_id + shard_id)");
        };

        self.call_method("chunk", params).await
    }

    /// Get changes in a block
    #[allow(dead_code)]
    pub async fn changes_in_block(
        &self,
        finality: Option<&str>,
        block_id: Option<Value>,
    ) -> Result<Value> {
        let params = if let Some(fin) = finality {
            json!({ "finality": fin })
        } else if let Some(id) = block_id {
            json!({ "block_id": id })
        } else {
            json!({ "finality": "final" })
        };

        self.call_method("EXPERIMENTAL_changes_in_block", params).await
    }

    /// Get changes by type (account, access key, data, code)
    #[allow(dead_code)]
    pub async fn changes(
        &self,
        changes_type: &str,
        account_ids: Vec<&str>,
        key_prefix_base64: Option<&str>,
        finality: Option<&str>,
        block_id: Option<Value>,
    ) -> Result<Value> {
        let mut params = json!({
            "changes_type": changes_type,
            "account_ids": account_ids
        });

        if let Some(prefix) = key_prefix_base64 {
            params["key_prefix_base64"] = json!(prefix);
        }

        Self::add_block_reference(&mut params, finality, block_id);
        self.call_method("EXPERIMENTAL_changes", params).await
    }

    // =========================================================================
    // Gas Methods
    // =========================================================================

    /// Get gas price
    ///
    /// # Arguments
    /// * `block_id` - Block height, hash, or null for latest
    pub async fn gas_price(&self, block_id: Option<Value>) -> Result<Value> {
        let params = vec![block_id.unwrap_or(Value::Null)];
        self.call_method("gas_price", json!(params)).await
    }

    // =========================================================================
    // Network Methods
    // =========================================================================

    /// Get node status
    #[allow(dead_code)]
    pub async fn status(&self) -> Result<Value> {
        self.call_method("status", json!([])).await
    }

    /// Get network info (peers, etc)
    #[allow(dead_code)]
    pub async fn network_info(&self) -> Result<Value> {
        self.call_method("network_info", json!([])).await
    }

    /// Get validators
    ///
    /// # Arguments
    /// * `epoch_id` - Epoch ID or null for current epoch
    #[allow(dead_code)]
    pub async fn validators(&self, epoch_id: Option<&str>) -> Result<Value> {
        let params = vec![epoch_id.map(|s| json!(s)).unwrap_or(Value::Null)];
        self.call_method("validators", json!(params)).await
    }

    // =========================================================================
    // Protocol Methods
    // =========================================================================

    /// Get genesis config
    #[allow(dead_code)]
    pub async fn genesis_config(&self) -> Result<Value> {
        self.call_method("EXPERIMENTAL_genesis_config", json!([])).await
    }

    /// Get protocol config
    #[allow(dead_code)]
    pub async fn protocol_config(
        &self,
        finality: Option<&str>,
        block_id: Option<Value>,
    ) -> Result<Value> {
        let params = if let Some(fin) = finality {
            json!({ "finality": fin })
        } else if let Some(id) = block_id {
            json!({ "block_id": id })
        } else {
            json!({ "finality": "final" })
        };

        self.call_method("EXPERIMENTAL_protocol_config", params).await
    }

    // =========================================================================
    // Transaction Methods
    // =========================================================================

    /// Send a signed transaction (new API)
    ///
    /// # Arguments
    /// * `signed_tx_base64` - Signed transaction encoded in base64
    /// * `wait_until` - Wait level: "NONE", "INCLUDED", "EXECUTED_OPTIMISTIC", etc.
    pub async fn send_tx(
        &self,
        signed_tx_base64: &str,
        wait_until: Option<&str>,
    ) -> Result<Value> {
        let mut params = json!({
            "signed_tx_base64": signed_tx_base64
        });

        if let Some(wait) = wait_until {
            params["wait_until"] = json!(wait);
        }

        self.call_method("send_tx", params).await
    }

    /// Broadcast transaction async (returns immediately with tx hash)
    ///
    /// DEPRECATED: Use send_tx with wait_until="NONE" instead
    #[allow(dead_code)]
    pub async fn broadcast_tx_async(&self, signed_tx_base64: &str) -> Result<Value> {
        let params = vec![json!(signed_tx_base64)];
        self.call_method("broadcast_tx_async", json!(params)).await
    }

    /// Broadcast transaction and wait for commit
    ///
    /// DEPRECATED: Use send_tx with wait_until="EXECUTED_OPTIMISTIC" instead
    #[allow(dead_code)]
    pub async fn broadcast_tx_commit(&self, signed_tx_base64: &str) -> Result<Value> {
        let params = vec![json!(signed_tx_base64)];
        self.call_method("broadcast_tx_commit", json!(params)).await
    }

    /// Get transaction status
    ///
    /// # Arguments
    /// * `tx_hash` - Transaction hash
    /// * `sender_account_id` - Sender's account ID
    /// * `wait_until` - Wait level (optional)
    #[allow(dead_code)]
    pub async fn tx_status(
        &self,
        tx_hash: &str,
        sender_account_id: &str,
        wait_until: Option<&str>,
    ) -> Result<Value> {
        let mut params = json!({
            "tx_hash": tx_hash,
            "sender_account_id": sender_account_id
        });

        if let Some(wait) = wait_until {
            params["wait_until"] = json!(wait);
        }

        self.call_method("tx", params).await
    }

    /// Get detailed transaction status with all receipts
    #[allow(dead_code)]
    pub async fn tx_status_experimental(
        &self,
        tx_hash: &str,
        sender_account_id: &str,
        wait_until: Option<&str>,
    ) -> Result<Value> {
        let mut params = json!({
            "tx_hash": tx_hash,
            "sender_account_id": sender_account_id
        });

        if let Some(wait) = wait_until {
            params["wait_until"] = json!(wait);
        }

        self.call_method("EXPERIMENTAL_tx_status", params).await
    }

    /// Get receipt by ID
    #[allow(dead_code)]
    pub async fn receipt(&self, receipt_id: &str) -> Result<Value> {
        let params = json!({ "receipt_id": receipt_id });
        self.call_method("EXPERIMENTAL_receipt", params).await
    }

    // =========================================================================
    // Transaction Creation Methods (WASM provides signing key)
    // =========================================================================

    /// Call a contract method with transaction (WASM provides signing key)
    ///
    /// CRITICAL: Worker NEVER signs with its own key. WASM MUST provide signer credentials.
    ///
    /// # Arguments
    /// * `signer_id` - Account ID that will sign the transaction (from WASM)
    /// * `signer_key` - Private key in NEAR format (ed25519:base58...) (from WASM)
    /// * `receiver_id` - Contract to call
    /// * `method_name` - Method to call
    /// * `args_json` - Arguments as JSON string
    /// * `deposit_yocto` - Attached deposit in yoctoNEAR (as string)
    /// * `gas` - Gas limit (as string)
    ///
    /// # Returns
    /// * Transaction hash on success
    pub async fn call_contract_method(
        &self,
        signer_id: &str,
        signer_key: &str,
        receiver_id: &str,
        method_name: &str,
        args_json: &str,
        deposit_yocto: &str,
        gas: &str,
    ) -> Result<String> {
        use near_crypto::{InMemorySigner, SecretKey};
        use near_primitives::transaction::{Action, FunctionCallAction, Transaction, TransactionV0};
        use near_primitives::types::{AccountId, Balance, Gas};
        use base64::Engine;

        // Parse signer credentials
        let signer_account_id: AccountId = signer_id.parse()
            .map_err(|e| anyhow::anyhow!("Invalid signer account ID '{}': {}", signer_id, e))?;

        let secret_key: SecretKey = signer_key.parse()
            .map_err(|e| anyhow::anyhow!("Invalid signer private key: {}", e))?;

        let signer = InMemorySigner {
            account_id: signer_account_id.clone(),
            public_key: secret_key.public_key(),
            secret_key,
        };

        // Parse receiver
        let receiver_account_id: AccountId = receiver_id.parse()
            .map_err(|e| anyhow::anyhow!("Invalid receiver account ID '{}': {}", receiver_id, e))?;

        // Parse deposit and gas
        let deposit: u128 = deposit_yocto.parse()
            .map_err(|e| anyhow::anyhow!("Invalid deposit '{}': {}", deposit_yocto, e))?;

        let gas_amount: u64 = gas.parse()
            .map_err(|e| anyhow::anyhow!("Invalid gas '{}': {}", gas, e))?;

        // Convert args_json to bytes
        let args_bytes = args_json.as_bytes().to_vec();

        // 1. Get access key for nonce. Read at OPTIMISTIC finality: a guest
        // that sends two transactions in one run would, at Final, read the
        // nonce before its first transaction's increment is final and sign the
        // same number twice — the chain refuses the second for its nonce. The
        // block hash the transaction is signed against stays a final block's
        // (step 2), one every node behind a load-balanced RPC knows.
        let access_key_params = json!({
            "request_type": "view_access_key",
            "finality": "optimistic",
            "account_id": signer_id,
            "public_key": signer.public_key().to_string()
        });

        let access_key_response = self.call_method("query", access_key_params).await
            .map_err(|e| anyhow::anyhow!("Failed to query access key for {}: {}", signer_id, e))?;

        let current_nonce = access_key_response
            .get("result")
            .and_then(|r| r.get("nonce"))
            .and_then(|n| n.as_u64())
            .ok_or_else(|| anyhow::anyhow!("Failed to extract nonce from access key response"))?;

        // 2. Get latest block hash
        let block_response = self.block(Some("final"), None).await
            .map_err(|e| anyhow::anyhow!("Failed to query block: {}", e))?;

        let block_hash_str = block_response
            .get("result")
            .and_then(|r| r.get("header"))
            .and_then(|h| h.get("hash"))
            .and_then(|h| h.as_str())
            .ok_or_else(|| anyhow::anyhow!("Failed to extract block hash from response"))?;

        let block_hash: near_primitives::hash::CryptoHash = block_hash_str.parse()
            .map_err(|e| anyhow::anyhow!("Failed to parse block hash: {}", e))?;

        // 3. Create transaction
        let transaction_v0 = TransactionV0 {
            signer_id: signer_account_id,
            public_key: signer.public_key(),
            nonce: current_nonce + 1,
            receiver_id: receiver_account_id,
            block_hash,
            actions: vec![Action::FunctionCall(Box::new(FunctionCallAction {
                method_name: method_name.to_string(),
                args: args_bytes,
                gas: Gas::from_gas(gas_amount),
                deposit: Balance::from_yoctonear(deposit),
            }))],
        };

        let transaction = Transaction::V0(transaction_v0);

        // 4. Sign transaction with WASM-provided key
        let signature = signer.sign(transaction.get_hash_and_size().0.as_ref());
        let signed_transaction = near_primitives::transaction::SignedTransaction::new(
            signature,
            transaction,
        );

        let tx_hash = signed_transaction.get_hash();

        // 5. Serialize to borsh and encode base64
        let signed_tx_bytes = borsh::to_vec(&signed_transaction)
            .map_err(|e| anyhow::anyhow!("Failed to serialize transaction: {}", e))?;

        let signed_tx_base64 = base64::engine::general_purpose::STANDARD.encode(&signed_tx_bytes);

        // 6. Broadcast transaction via send_tx
        self.send_tx(&signed_tx_base64, Some("NONE")).await?;

        // Return transaction hash
        Ok(format!("{}", tx_hash))
    }

    /// Transfer NEAR tokens (WASM provides signing key)
    ///
    /// CRITICAL: Worker NEVER signs with its own key. WASM MUST provide signer credentials.
    ///
    /// # Arguments
    /// * `signer_id` - Account ID that will sign the transaction (from WASM)
    /// * `signer_key` - Private key in NEAR format (ed25519:base58...) (from WASM)
    /// * `receiver_id` - Recipient account
    /// * `amount_yocto` - Amount in yoctoNEAR (as string)
    ///
    /// # Returns
    /// * Transaction hash on success
    pub async fn transfer(
        &self,
        signer_id: &str,
        signer_key: &str,
        receiver_id: &str,
        amount_yocto: &str,
    ) -> Result<String> {
        use near_crypto::{InMemorySigner, SecretKey};
        use near_primitives::transaction::{Action, Transaction, TransactionV0, TransferAction};
        use near_primitives::types::{AccountId, Balance};
        use base64::Engine;

        // Parse signer credentials
        let signer_account_id: AccountId = signer_id.parse()
            .map_err(|e| anyhow::anyhow!("Invalid signer account ID '{}': {}", signer_id, e))?;

        let secret_key: SecretKey = signer_key.parse()
            .map_err(|e| anyhow::anyhow!("Invalid signer private key: {}", e))?;

        let signer = InMemorySigner {
            account_id: signer_account_id.clone(),
            public_key: secret_key.public_key(),
            secret_key,
        };

        // Parse receiver
        let receiver_account_id: AccountId = receiver_id.parse()
            .map_err(|e| anyhow::anyhow!("Invalid receiver account ID '{}': {}", receiver_id, e))?;

        // Parse amount
        let amount: u128 = amount_yocto.parse()
            .map_err(|e| anyhow::anyhow!("Invalid amount '{}': {}", amount_yocto, e))?;

        // 1. Get access key for nonce. Read at OPTIMISTIC finality: a guest
        // that sends two transactions in one run would, at Final, read the
        // nonce before its first transaction's increment is final and sign the
        // same number twice — the chain refuses the second for its nonce. The
        // block hash the transaction is signed against stays a final block's
        // (step 2), one every node behind a load-balanced RPC knows.
        let access_key_params = json!({
            "request_type": "view_access_key",
            "finality": "optimistic",
            "account_id": signer_id,
            "public_key": signer.public_key().to_string()
        });

        let access_key_response = self.call_method("query", access_key_params).await
            .map_err(|e| anyhow::anyhow!("Failed to query access key for {}: {}", signer_id, e))?;

        let current_nonce = access_key_response
            .get("result")
            .and_then(|r| r.get("nonce"))
            .and_then(|n| n.as_u64())
            .ok_or_else(|| anyhow::anyhow!("Failed to extract nonce from access key response"))?;

        // 2. Get latest block hash
        let block_response = self.block(Some("final"), None).await
            .map_err(|e| anyhow::anyhow!("Failed to query block: {}", e))?;

        let block_hash_str = block_response
            .get("result")
            .and_then(|r| r.get("header"))
            .and_then(|h| h.get("hash"))
            .and_then(|h| h.as_str())
            .ok_or_else(|| anyhow::anyhow!("Failed to extract block hash from response"))?;

        let block_hash: near_primitives::hash::CryptoHash = block_hash_str.parse()
            .map_err(|e| anyhow::anyhow!("Failed to parse block hash: {}", e))?;

        // 3. Create transfer transaction
        let transaction_v0 = TransactionV0 {
            signer_id: signer_account_id,
            public_key: signer.public_key(),
            nonce: current_nonce + 1,
            receiver_id: receiver_account_id,
            block_hash,
            actions: vec![Action::Transfer(TransferAction { deposit: Balance::from_yoctonear(amount) })],
        };

        let transaction = Transaction::V0(transaction_v0);

        // 4. Sign transaction with WASM-provided key
        let signature = signer.sign(transaction.get_hash_and_size().0.as_ref());
        let signed_transaction = near_primitives::transaction::SignedTransaction::new(
            signature,
            transaction,
        );

        let tx_hash = signed_transaction.get_hash();

        // 5. Serialize to borsh and encode base64
        let signed_tx_bytes = borsh::to_vec(&signed_transaction)
            .map_err(|e| anyhow::anyhow!("Failed to serialize transaction: {}", e))?;

        let signed_tx_base64 = base64::engine::general_purpose::STANDARD.encode(&signed_tx_bytes);

        // 6. Broadcast transaction via send_tx
        self.send_tx(&signed_tx_base64, Some("NONE")).await?;

        // Return transaction hash
        Ok(format!("{}", tx_hash))
    }

    // =========================================================================
    // Helper Methods
    // =========================================================================

    /// Add block reference (finality or block_id) to params
    fn add_block_reference(params: &mut Value, finality: Option<&str>, block_id: Option<Value>) {
        if let Some(fin) = finality {
            params["finality"] = json!(fin);
        } else if let Some(id) = block_id {
            params["block_id"] = id;
        } else {
            // Default to final
            params["finality"] = json!("final");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RpcProxyConfig;

    fn create_test_proxy() -> RpcProxy {
        let config = RpcProxyConfig {
            enabled: true,
            rpc_url: None,
            max_calls_per_execution: 100,
            allow_transactions: true,
        };
        RpcProxy::new(config, "https://rpc.testnet.near.org").unwrap()
    }

    #[tokio::test]
    async fn test_view_account_params() {
        let proxy = create_test_proxy();

        // Test with finality - just verify the call doesn't panic
        // Result depends on network availability (may succeed or fail)
        let _result = proxy.view_account("test.near", Some("final"), None).await;

        // Reset for next test
        proxy.reset_call_count();
    }

    #[tokio::test]
    async fn test_gas_price_params() {
        let proxy = create_test_proxy();

        // Test with null (latest) - just verify the call doesn't panic
        // Result depends on network availability (may succeed or fail)
        let _result = proxy.gas_price(None).await;
    }

    #[test]
    fn test_add_block_reference() {
        let mut params = json!({});

        // With finality
        RpcProxy::add_block_reference(&mut params, Some("final"), None);
        assert_eq!(params["finality"], "final");

        // With block_id number
        let mut params2 = json!({});
        RpcProxy::add_block_reference(&mut params2, None, Some(json!(12345)));
        assert_eq!(params2["block_id"], 12345);

        // Default to final
        let mut params3 = json!({});
        RpcProxy::add_block_reference(&mut params3, None, None);
        assert_eq!(params3["finality"], "final");
    }
}
