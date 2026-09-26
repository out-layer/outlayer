//! TEE Registration Module
//!
//! Handles keystore registration with DAO contract:
//! 1. Generate or load NEAR keypair
//! 2. Generate TEE attestation
//! 3. Submit registration to DAO
//! 4. Wait for DAO approval

use anyhow::{Context, Result};
use near_crypto::{InMemorySigner, KeyType, PublicKey, SecretKey};
use near_jsonrpc_client::{methods, JsonRpcClient};
use near_jsonrpc_primitives::types::query::QueryResponseKind;
use near_primitives::transaction::{Action, FunctionCallAction, Transaction, TransactionV0};
use near_primitives::types::{AccountId, Balance, BlockReference, Finality, Gas};
use near_primitives::views::{QueryRequest, CallResult};
use serde_json::json;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{info, warn, error};

/// Keystore registration client
pub struct RegistrationClient {
    /// NEAR RPC client
    rpc_client: crate::near::RpcClient,

    /// DAO contract ID
    dao_contract_id: AccountId,

    /// Init account for gas payment
    init_signer: InMemorySigner,
    /// Signature scheme for the generated keystore registration key
    key_type: KeyType,

    /// Path to store keypair
    keypair_path: PathBuf,
}

/// Compute the 32-byte value embedded into the TDX quote's `report_data` that binds the
/// TEE to its on-chain keystore key.
///
/// - `ed25519`: the raw 32-byte public key (unchanged — backward compatible with already
///   approved keystores).
/// - `ml-dsa-65`: SHA-256 of the 1952-byte public key. The full ML-DSA key does not fit into
///   `report_data`'s 32 bytes, so we bind to its hash. keystore-dao-contract recomputes the
///   same hash from the submitted public key and compares.
pub fn report_data_binding(public_key: &PublicKey) -> Result<[u8; 32]> {
    match public_key {
        PublicKey::ED25519(key) => Ok(key.0),
        PublicKey::MLDSA65(key) => {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(&key.0[..]); // 1952 bytes of ML-DSA-65 public key
            Ok(hasher.finalize().into())
        }
        _ => anyhow::bail!(
            "Unsupported keystore key type for report_data binding (use ed25519 or ml-dsa-65)"
        ),
    }
}

impl RegistrationClient {
    /// Create new registration client
    pub fn new(
        near_rpc_url: String,
        dao_contract_id: AccountId,
        init_account_id: AccountId,
        init_secret_key: SecretKey,
        key_type: KeyType,
    ) -> Result<Self> {
        let rpc_client = crate::near::RpcClient::new(JsonRpcClient::connect(&near_rpc_url));

        let init_signer = InMemorySigner {
            account_id: init_account_id,
            public_key: init_secret_key.public_key(),
            secret_key: init_secret_key,
        };

        let keypair_path = Self::get_keypair_path();

        Ok(Self {
            rpc_client,
            dao_contract_id,
            init_signer,
            keypair_path,
            key_type,
        })
    }

    /// Get standard path for keypair storage
    fn get_keypair_path() -> PathBuf {
        let mut path = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        path.push(".near-credentials");
        path.push("keystore-keypair.json");
        path
    }

    /// Load or generate keystore keypair
    ///
    /// In TEE mode: Always generates new keypair in memory (never saves to disk)
    /// In non-TEE mode: Loads from disk if exists, otherwise generates and saves
    pub fn load_or_generate_keypair(&self, is_tee_mode: bool) -> Result<(PublicKey, SecretKey)> {
        if is_tee_mode {
            // TEE MODE: Always generate in memory, NEVER save to disk
            info!("🔐 TEE Mode: Generating ephemeral keypair in memory (not saved to disk)");
            let (public_key, secret_key) = self.generate_keypair()?;
            info!("✅ TEE keypair generated: {} (exists only in memory)", public_key);
            Ok((public_key, secret_key))
        } else {
            // Non-TEE mode: Can use persistent storage
            if self.keypair_path.exists() {
                info!("📂 Loading existing keystore keypair from: {}", self.keypair_path.display());
                let (public_key, secret_key) = self.load_keypair()?;

                // KeyType has no PartialEq; compare discriminants of this fieldless enum.
                if public_key.key_type() as u8 == self.key_type as u8 {
                    return Ok((public_key, secret_key));
                }

                // KEYSTORE_KEY_TYPE changed — reusing the stored key would silently ignore the
                // flag, so generate a fresh keypair and overwrite the file.
                info!(
                    "♻️  Stored keystore key is {} but KEYSTORE_KEY_TYPE={} — generating a new keypair",
                    public_key.key_type(),
                    self.key_type
                );
            }

            info!("🔑 Generating new keystore keypair...");
            let (public_key, secret_key) = self.generate_keypair()?;
            self.save_keypair(&public_key, &secret_key)?;
            Ok((public_key, secret_key))
        }
    }

    /// Generate a new keystore registration keypair using the configured signature scheme.
    ///
    /// Supports `ed25519` (default) and `ml-dsa-65` (FIPS-204 post-quantum). Both are
    /// generated randomly from the OS CSPRNG inside the TEE via near-crypto.
    fn generate_keypair(&self) -> Result<(PublicKey, SecretKey)> {
        match self.key_type {
            KeyType::ED25519 | KeyType::MLDSA65 => {}
            other => anyhow::bail!(
                "Unsupported keystore key type {} (use 'ed25519' or 'ml-dsa-65')",
                other
            ),
        }

        let secret_key = SecretKey::from_random(self.key_type);
        let public_key = secret_key.public_key();

        info!("✅ Generated new {} keystore keypair: {}", self.key_type, public_key);

        Ok((public_key, secret_key))
    }

    /// Save keypair to file
    fn save_keypair(&self, public_key: &PublicKey, secret_key: &SecretKey) -> Result<()> {
        // Create directory if it doesn't exist
        if let Some(parent) = self.keypair_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Save as JSON
        let keypair_json = json!({
            "public_key": public_key.to_string(),
            "private_key": secret_key.to_string(),
        });

        fs::write(&self.keypair_path, serde_json::to_string_pretty(&keypair_json)?)
            .context("Failed to save keypair")?;

        info!("💾 Saved keypair to: {}", self.keypair_path.display());
        Ok(())
    }

    /// Load keypair from file
    fn load_keypair(&self) -> Result<(PublicKey, SecretKey)> {
        let content = fs::read_to_string(&self.keypair_path)
            .context("Failed to read keypair file")?;

        let keypair_json: serde_json::Value = serde_json::from_str(&content)
            .context("Failed to parse keypair JSON")?;

        let public_key_str = keypair_json["public_key"]
            .as_str()
            .context("Missing public_key in keypair file")?;

        let private_key_str = keypair_json["private_key"]
            .as_str()
            .context("Missing private_key in keypair file")?;

        let public_key = public_key_str.parse()
            .context("Invalid public key format")?;

        let secret_key = private_key_str.parse()
            .context("Invalid private key format")?;

        Ok((public_key, secret_key))
    }


    /// Submit registration to DAO contract
    pub async fn submit_registration(
        &self,
        public_key: PublicKey,
        tdx_quote_hex: String,
        app_id: Option<String>,
    ) -> Result<u64> {
        info!("📤 Submitting keystore registration to DAO contract");

        // Prepare function call
        let args = json!({
            "public_key": public_key.to_string(),
            "tdx_quote_hex": tdx_quote_hex,
            "app_id": app_id,
        });

        // Convert to JSON string first, then to bytes (NEAR expects JSON text, not MessagePack)
        let args_json = serde_json::to_string(&args)
            .context("Failed to serialize args to JSON")?;

        // Debug logging if LOG_MASTER_KEY_HASH is set
        if std::env::var("LOG_MASTER_KEY_HASH").unwrap_or_default() == "true" {
            info!("🔍 DEBUG: Registration transaction details:");
            info!("   Contract ID: {}", self.dao_contract_id);
            info!("   Method name: submit_keystore_registration");
            info!("   Signer account: {}", self.init_signer.account_id);
            info!("   Signer public key: {}", self.init_signer.public_key);
            info!("   Args size: {} bytes", args_json.len());
            info!("   Args JSON (first 500 chars): {}",
                if args_json.len() > 500 { &args_json[..500] } else { &args_json });
            info!("   Public key in args: {}", public_key.to_string());
            info!("   TDX quote hex length: {} chars", tdx_quote_hex.len());
        }

        // Get current nonce
        let access_key_query = methods::query::RpcQueryRequest {
            block_reference: BlockReference::Finality(Finality::Final),
            request: QueryRequest::ViewAccessKey {
                account_id: self.init_signer.account_id.clone(),
                public_key: self.init_signer.public_key.clone(),
            },
        };

        // Debug logging for access key query
        if std::env::var("LOG_MASTER_KEY_HASH").unwrap_or_default() == "true" {
            info!("🔍 DEBUG: Querying access key for transaction nonce");
            info!("   Account: {}", self.init_signer.account_id);
            info!("   Public key: {}", self.init_signer.public_key);
        }

        let access_key_response = match self.rpc_client.call(access_key_query).await {
            Ok(response) => response,
            Err(e) => {
                if std::env::var("LOG_MASTER_KEY_HASH").unwrap_or_default() == "true" {
                    warn!("🔍 DEBUG: Failed to query access key!");
                    warn!("   Error: {:?}", e);
                    warn!("   This might mean:");
                    warn!("   1. Account {} doesn't exist", self.init_signer.account_id);
                    warn!("   2. Public key {} is not added to the account", self.init_signer.public_key);
                    warn!("   3. The private key doesn't match the public key");

                    // Check if this is the actual MethodNotFound error
                    let error_str = format!("{:?}", e);
                    if error_str.contains("MethodNotFound") {
                        warn!("   ⚠️ MethodNotFound during ACCESS KEY query (not contract call!)");
                        warn!("   This is very unusual - RPC issue?");
                    }
                }
                return Err(anyhow::anyhow!("Failed to query access key: {:?}", e));
            }
        };

        let nonce = if let QueryResponseKind::AccessKey(key) = access_key_response.kind {
            if std::env::var("LOG_MASTER_KEY_HASH").unwrap_or_default() == "true" {
                info!("🔍 DEBUG: Access key found, nonce: {}", key.nonce);
            }
            key.nonce + 1
        } else {
            if std::env::var("LOG_MASTER_KEY_HASH").unwrap_or_default() == "true" {
                warn!("🔍 DEBUG: Unexpected response type for access key query");
            }
            1
        };

        // Get latest block hash
        let block = self.rpc_client
            .call(methods::block::RpcBlockRequest {
                block_reference: BlockReference::Finality(Finality::Final),
            })
            .await?;

        // Create transaction using V0 format
        let transaction_v0 = TransactionV0 {
            signer_id: self.init_signer.account_id.clone(),
            public_key: self.init_signer.public_key.clone(),
            nonce,
            receiver_id: self.dao_contract_id.clone(),
            block_hash: block.header.hash,
            actions: vec![Action::FunctionCall(Box::new(FunctionCallAction {
                method_name: "submit_keystore_registration".to_string(),
                args: args_json.into_bytes(),  // Use JSON string as bytes, not MessagePack
                gas: Gas::from_gas(300_000_000_000_000), // 300 TGas (matching worker registration)
                deposit: Balance::from_yoctonear(0),
            }))],
        };

        let transaction = Transaction::V0(transaction_v0);

        // Get transaction hash before moving transaction
        let tx_hash = transaction.get_hash_and_size().0;

        // Sign and send
        let signature = self.init_signer.sign(tx_hash.as_ref());
        let signed_tx = near_primitives::transaction::SignedTransaction::new(
            signature,
            transaction,
        );
        let request = methods::broadcast_tx_commit::RpcBroadcastTxCommitRequest {
            signed_transaction: signed_tx,
        };

        // Debug logging before sending transaction
        if std::env::var("LOG_MASTER_KEY_HASH").unwrap_or_default() == "true" {
            info!("🔍 DEBUG: About to send transaction to NEAR RPC");
            info!("   Transaction hash: {}", tx_hash);
            info!("   Nonce: {}", nonce);
            info!("   Block hash: {}", block.header.hash);
        }

        let outcome = match self.rpc_client.call(request).await {
            Ok(outcome) => outcome,
            Err(e) => {
                // Enhanced error logging
                if std::env::var("LOG_MASTER_KEY_HASH").unwrap_or_default() == "true" {
                    warn!("🔍 DEBUG: Transaction failed with error: {:?}", e);
                    warn!("   Error type: {}", std::any::type_name_of_val(&e));
                    warn!("   Contract tried: {}", self.dao_contract_id);
                    warn!("   Method tried: submit_keystore_registration");
                    warn!("   Signer: {}", self.init_signer.account_id);

                    // Try to extract more details from the error
                    let error_str = format!("{:?}", e);
                    if error_str.contains("MethodNotFound") {
                        warn!("   ⚠️  MethodNotFound: The contract doesn't have 'submit_keystore_registration' method");
                        warn!("   ⚠️  Possible causes:");
                        warn!("      1. Wrong contract deployed at {}", self.dao_contract_id);
                        warn!("      2. Method name typo (should be 'submit_keystore_registration')");
                        warn!("      3. Arguments format issue (expecting JSON string as bytes)");
                    }
                }
                return Err(anyhow::anyhow!("Transaction failed: {:?}", e));
            }
        };

        // Log transaction outcome details (similar to worker)
        info!("📋 Transaction outcome status: {:?}", outcome.status);
        info!("   Transaction ID: {:?}", outcome.transaction.hash);
        info!("   Transaction logs: {}", outcome.transaction_outcome.outcome.logs.len());
        for (i, log) in outcome.transaction_outcome.outcome.logs.iter().enumerate() {
            info!("      Log #{}: {}", i, log);
        }
        for (i, receipt) in outcome.receipts_outcome.iter().enumerate() {
            info!("   Receipt #{}: executor={}, logs={}",
                i, receipt.outcome.executor_id, receipt.outcome.logs.len());
            for (j, log) in receipt.outcome.logs.iter().enumerate() {
                info!("      Receipt #{} Log #{}: {}", i, j, log);
            }
        }

        // Check transaction status
        use near_primitives::views::FinalExecutionStatus;
        match &outcome.status {
            FinalExecutionStatus::SuccessValue(value) => {
                // Extract proposal ID from return value
                let proposal_id: u64 = serde_json::from_slice(value)
                    .context("Failed to parse proposal ID from transaction result")?;
                info!("✅ Registration submitted successfully! Proposal ID: {}", proposal_id);
                info!("   Transaction: {:?}", outcome.transaction.hash);
                Ok(proposal_id)
            }
            FinalExecutionStatus::Failure(err) => {
                // Parse the error to provide better feedback
                let err_str = format!("{:?}", err);

                if err_str.contains("Smart contract panicked") {
                    error!("❌ Smart contract panicked!");

                    if err_str.contains("TDX quote verification failed") {
                        error!("   ⚠️  TDX quote verification failed in contract");
                        error!("   ⚠️  This happens when using MOCK mode with a contract expecting real TDX quotes");
                        error!("   ⚠️  Solutions:");
                        error!("      1. Add measurements to pre-approved list: near call {} add_approved_measurements", self.dao_contract_id);
                        error!("      2. Or switch to real TDX mode: TEE_MODE=tdx");

                        if err_str.contains("Unsupported quote version") {
                            error!("   ⚠️  The MOCK quote format is not recognized by the contract");
                            error!("   ⚠️  The contract expects a real Intel TDX quote, but received 'MOCK' (0x4d4f434b)");
                        }
                    } else if err_str.contains("must be 96 hex chars") {
                        error!("   ⚠️  Measurement format error - must be exactly 96 hex characters");
                    } else if err_str.contains("Keystore already approved") {
                        error!("   ⚠️  This keystore public key is already approved");
                    }

                    error!("   Full error: {}", err_str);
                }

                Err(anyhow::anyhow!("Transaction failed with status: {:?}", err))
            }
            other => {
                warn!("⚠️ Unexpected transaction status: {:?}", other);
                Err(anyhow::anyhow!("Unexpected transaction status: {:?}", other))
            }
        }
    }


    /// Wait for DAO approval and execute proposal when approved
    pub async fn wait_for_approval(&self, proposal_id: u64, public_key: &PublicKey) -> Result<()> {
        info!("⏳ Waiting for DAO approval of proposal #{}...", proposal_id);
        info!("   DAO members need to vote to approve the keystore");

        let mut attempts = 0;
        const MAX_ATTEMPTS: u32 = 360; // 30 minutes with 5 second intervals

        loop {
            // Check if keystore is already approved (proposal executed)
            if self.check_approval_status(public_key).await? {
                info!("✅ Keystore approved by DAO!");
                return Ok(());
            }

            // Check proposal status
            let proposal_status = self.get_proposal_status(proposal_id).await?;
            match proposal_status.as_str() {
                "Approved" => {
                    info!("✅ Proposal approved! Will auto-execute when quorum reached");
                }
                "Executed" => {
                    // Proposal already executed, wait for keystore to be approved
                    info!("✅ Proposal already executed, waiting for keystore approval...");
                }
                "Rejected" => {
                    anyhow::bail!("❌ Proposal rejected by DAO");
                }
                "Pending" => {
                    if attempts % 12 == 0 { // Log every minute
                        info!("   Still waiting for votes... ({}/{})",
                            attempts * 5, MAX_ATTEMPTS * 5);
                    }
                }
                _ => {}
            }

            attempts += 1;
            if attempts >= MAX_ATTEMPTS {
                anyhow::bail!("Timeout waiting for DAO approval");
            }

            sleep(Duration::from_secs(5)).await;
        }
    }

    /* REMOVE
    /// Execute approved proposal
    async fn execute_proposal(&self, proposal_id: u64) -> Result<()> {
        info!("📤 Executing proposal #{}", proposal_id);

        // Get access key information
        let access_key_query = methods::query::RpcQueryRequest {
            block_reference: BlockReference::Finality(Finality::Final),
            request: QueryRequest::ViewAccessKey {
                account_id: self.init_signer.account_id.clone(),
                public_key: self.init_signer.public_key.clone(),
            },
        };

        let access_key_response = self.rpc_client.call(access_key_query).await
            .context("Failed to query access key")?;

        let nonce = if let QueryResponseKind::AccessKey(access_key_view) = access_key_response.kind {
            access_key_view.nonce + 1
        } else {
            anyhow::bail!("Failed to get access key nonce");
        };

        // Get current block hash
        let block = self.rpc_client
            .call(methods::block::RpcBlockRequest {
                block_reference: BlockReference::Finality(Finality::Final),
            })
            .await
            .context("Failed to get latest block")?;

        // Create transaction to execute proposal
        let args = json!({
            "proposal_id": proposal_id,
        });

        let args_json = serde_json::to_string(&args)?;

        let transaction_v0 = TransactionV0 {
            signer_id: self.init_signer.account_id.clone(),
            public_key: self.init_signer.public_key.clone(),
            nonce,
            receiver_id: self.dao_contract_id.clone(),
            block_hash: block.header.hash,
            actions: vec![Action::FunctionCall(Box::new(FunctionCallAction {
                method_name: "execute_proposal".to_string(),
                args: args_json.into_bytes(),
                gas: 100_000_000_000_000, // 100 TGas
                deposit: 0,
            }))],
        };

        let transaction = Transaction::V0(transaction_v0);

        // Sign and send transaction
        let signature = self.init_signer.sign(transaction.get_hash_and_size().0.as_ref());
        let request = methods::broadcast_tx_commit::RpcBroadcastTxCommitRequest {
            signed_transaction: near_primitives::transaction::SignedTransaction::new(
                signature,
                transaction,
            ),
        };

        let outcome = self.rpc_client.call(request).await
            .context("Failed to execute proposal")?;

        // Check transaction status
        match &outcome.status {
            FinalExecutionStatus::SuccessValue(_) => {
                info!("✅ Proposal executed successfully");
                Ok(())
            }
            FinalExecutionStatus::Failure(err) => {
                Err(anyhow::anyhow!("Transaction failed: {:?}", err))
            }
            other => {
                Err(anyhow::anyhow!("Unexpected transaction status: {:?}", other))
            }
        }
    }
    */

    /// Check if keystore is approved
    async fn check_approval_status(&self, public_key: &PublicKey) -> Result<bool> {
        let args = json!({
            "public_key": public_key.to_string(),
        });

        let request = methods::query::RpcQueryRequest {
            block_reference: BlockReference::Finality(Finality::Final),
            request: QueryRequest::CallFunction {
                account_id: self.dao_contract_id.clone(),
                method_name: "is_keystore_approved".to_string(),
                args: serde_json::to_vec(&args)?.into(),
            },
        };

        let response = self.rpc_client.call(request).await?;

        if let QueryResponseKind::CallResult(CallResult { result, .. }) = response.kind {
            let approved: bool = serde_json::from_slice(&result)?;
            Ok(approved)
        } else {
            Ok(false)
        }
    }

    /// Get proposal status
    async fn get_proposal_status(&self, proposal_id: u64) -> Result<String> {
        let args = json!({
            "proposal_id": proposal_id,
        });

        let request = methods::query::RpcQueryRequest {
            block_reference: BlockReference::Finality(Finality::Final),
            request: QueryRequest::CallFunction {
                account_id: self.dao_contract_id.clone(),
                method_name: "get_proposal".to_string(),
                args: serde_json::to_vec(&args)?.into(),
            },
        };

        let response = self.rpc_client.call(request).await?;

        if let QueryResponseKind::CallResult(CallResult { result, .. }) = response.kind {
            let proposal: serde_json::Value = serde_json::from_slice(&result)?;
            Ok(proposal["status"].as_str().unwrap_or("Unknown").to_string())
        } else {
            Ok("Unknown".to_string())
        }
    }
}
#[cfg(test)]
mod binding_tests {
    use super::*;
    use sha2::{Digest, Sha256};

    /// ed25519 keeps the legacy binding: report_data[..32] is the raw public key.
    /// This is what makes already-approved ed25519 keystores survive the upgrade.
    #[test]
    fn ed25519_binding_is_raw_public_key() {
        let sk = SecretKey::from_random(KeyType::ED25519);
        let pk = sk.public_key();

        let binding = report_data_binding(&pk).expect("ed25519 binding");

        match &pk {
            PublicKey::ED25519(k) => assert_eq!(binding, k.0),
            _ => panic!("expected ed25519"),
        }
    }

    /// ml-dsa-65 public keys are 1952 bytes and cannot fit in report_data's 32 bytes,
    /// so the binding is their SHA-256. keystore-dao-contract recomputes exactly this
    /// (env::sha256_array over the key bytes minus the curve tag) — keep them in sync.
    #[test]
    fn mldsa_binding_is_sha256_of_public_key() {
        let sk = SecretKey::from_random(KeyType::MLDSA65);
        let pk = sk.public_key();

        let raw = match &pk {
            PublicKey::MLDSA65(k) => k.0.to_vec(),
            _ => panic!("expected ml-dsa-65"),
        };
        assert_eq!(raw.len(), 1952, "ML-DSA-65 public key must be 1952 bytes");

        let binding = report_data_binding(&pk).expect("ml-dsa binding");
        assert_eq!(binding, <[u8; 32]>::from(Sha256::digest(&raw)));

        // The contract strips the leading curve tag before hashing; same bytes must result.
        let mut tagged = vec![2u8];
        tagged.extend_from_slice(&raw);
        assert_eq!(binding, <[u8; 32]>::from(Sha256::digest(&tagged[1..])));
    }

    /// The keystore must be able to actually sign with an ml-dsa key and round-trip it
    /// through the `ml-dsa-65:<base58>` textual form used by the keypair file.
    #[test]
    fn mldsa_signs_and_round_trips_through_string() {
        let sk = SecretKey::from_random(KeyType::MLDSA65);
        let pk = sk.public_key();

        let msg = b"keystore dao registration";
        let sig = sk.sign(msg);
        assert!(sig.verify(msg, &pk), "ml-dsa signature must verify");
        assert!(!sig.verify(b"tampered", &pk), "must reject a wrong message");

        let sk_str = sk.to_string();
        assert!(sk_str.starts_with("ml-dsa-65:"), "got {sk_str}");
        let parsed: SecretKey = sk_str.parse().expect("parse ml-dsa-65 secret key");
        assert_eq!(parsed.public_key(), pk);
    }
}
