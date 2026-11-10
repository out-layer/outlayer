//! FastFS integration for publishing compiled WASM files
//!
//! FastFS is a decentralized file storage on NEAR Protocol.
//! This module handles uploading compiled WASM files to FastFS.

use anyhow::{Context, Result};
use borsh::{BorshSerialize, BorshDeserialize};
use near_crypto::InMemorySigner;
use near_jsonrpc_client::{methods, JsonRpcClient};
use near_primitives::transaction::{Action, FunctionCallAction, Transaction, TransactionV0};
use near_primitives::types::{AccountId, Balance, BlockReference, Finality, Gas};
use tracing::{debug, info, warn};

/// MIME type for WASM files
const WASM_MIME_TYPE: &str = "application/wasm";

/// Method name for FastFS upload
const FASTFS_METHOD: &str = "__fastdata_fastfs";

/// FastFS file content structure
#[derive(BorshSerialize, BorshDeserialize)]
struct FastfsFileContent {
    mime_type: String,
    content: Vec<u8>,
}

/// SimpleFastfs structure for Borsh serialization
#[derive(BorshSerialize, BorshDeserialize)]
struct SimpleFastfs {
    relative_path: String,
    content: Option<FastfsFileContent>,
}

/// FastfsData enum wrapper
#[derive(BorshSerialize, BorshDeserialize)]
enum FastfsData {
    Simple(SimpleFastfs),
}

/// FastFS client for uploading WASM files
pub struct FastFsClient {
    client: JsonRpcClient,
    signer: InMemorySigner,
    receiver: String,
}

impl FastFsClient {
    /// Create a new FastFS client
    pub fn new(rpc_url: &str, signer: InMemorySigner, receiver: &str) -> Self {
        let client = JsonRpcClient::connect(rpc_url);
        Self {
            client,
            signer,
            receiver: receiver.to_string(),
        }
    }

    /// Upload WASM file to FastFS
    ///
    /// # Arguments
    /// * `wasm_bytes` - The compiled WASM binary
    /// * `checksum` - SHA256 checksum (hex) used as filename
    ///
    /// # Returns
    /// * `Ok(url)` - FastFS URL where the file is accessible
    pub async fn upload_wasm(&self, wasm_bytes: &[u8], checksum: &str) -> Result<String> {
        let relative_path = format!("{}.wasm", checksum);

        info!(
            "📦 Uploading WASM to FastFS: {} ({} bytes)",
            relative_path,
            wasm_bytes.len()
        );

        // Create FastFS data structure
        let fastfs_data = FastfsData::Simple(SimpleFastfs {
            relative_path: relative_path.clone(),
            content: Some(FastfsFileContent {
                mime_type: WASM_MIME_TYPE.to_string(),
                content: wasm_bytes.to_vec(),
            }),
        });

        // Serialize with Borsh
        let args = borsh::to_vec(&fastfs_data)
            .context("Failed to serialize FastFS data with Borsh")?;

        info!("   Serialized Borsh payload: {} bytes", args.len());

        // Get account access key for nonce
        let access_key_query = methods::query::RpcQueryRequest {
            block_reference: BlockReference::Finality(Finality::Final),
            request: near_primitives::views::QueryRequest::ViewAccessKey {
                account_id: self.signer.account_id.clone(),
                public_key: self.signer.public_key(),
            },
        };

        let access_key_response = self
            .client
            .call(access_key_query)
            .await
            .context("Failed to query access key for FastFS")?;

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

        let block = self
            .client
            .call(block_query)
            .await
            .context("Failed to query block for FastFS")?;

        let block_hash = block.header.hash;

        // Parse receiver account ID
        let receiver_id: AccountId = self.receiver
            .parse()
            .context("Failed to parse FastFS receiver account ID")?;

        // Create transaction (no deposit needed for FastFS)

        let transaction_v0 = TransactionV0 {
            signer_id: self.signer.account_id.clone(),
            public_key: self.signer.public_key(),
            nonce: current_nonce + 1,
            receiver_id: receiver_id.clone(),
            block_hash,
            actions: vec![Action::FunctionCall(Box::new(FunctionCallAction {
                method_name: FASTFS_METHOD.to_string(),
                args,
                gas: Gas::from_gas(300_000_000_000_000), // 300 TGas
                deposit: Balance::from_yoctonear(0),
            }))],
        };

        let transaction = Transaction::V0(transaction_v0);

        // Sign transaction
        let signature = self.signer.sign(transaction.get_hash_and_size().0.as_ref());
        let signed_transaction = near_primitives::transaction::SignedTransaction::new(
            signature,
            transaction,
        );

        // Broadcast transaction
        let tx_request = methods::broadcast_tx_commit::RpcBroadcastTxCommitRequest {
            signed_transaction,
        };

        let outcome = self
            .client
            .call(tx_request)
            .await
            .context("Failed to broadcast FastFS transaction")?;

        // The file travels in the transaction's arguments and the indexer
        // reads it from the chain, so a transaction the chain EXECUTED is a
        // publish whatever its status: there is no contract at the receiver,
        // and the call "fails" every time. Only a transaction the chain did
        // not take — refused before inclusion (`InvalidNonce`, `Expired`, a
        // signer short of balance) or never answered — is a failed publish,
        // and `?` above returns it as one: the file is not on FastFS then, and
        // no URL may be reported.
        let url = format!(
            "https://{}.fastfs.io/{}/{}",
            self.signer.account_id,
            receiver_id,
            relative_path
        );
        match &outcome.status {
            near_primitives::views::FinalExecutionStatus::SuccessValue(_) => {
                info!("✅ FastFS upload successful!");
            }
            near_primitives::views::FinalExecutionStatus::Failure(err) => {
                info!("📁 FastFS transaction executed with a failed status, as expected (no contract at the receiver); the indexer picks the file up");
                debug!("   Transaction status: {:?}", err);
            }
            status => {
                warn!("⚠️ FastFS upload unexpected status: {:?}", status);
                anyhow::bail!("FastFS transaction has unexpected status: {:?}", status)
            }
        }
        info!("   Transaction: {}", outcome.transaction_outcome.id);
        info!("   URL: {}", url);
        Ok(url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fastfs_data_serialization() {
        let data = FastfsData::Simple(SimpleFastfs {
            relative_path: "test.wasm".to_string(),
            content: Some(FastfsFileContent {
                mime_type: "application/wasm".to_string(),
                content: vec![0, 1, 2, 3],
            }),
        });

        let serialized = borsh::to_vec(&data).unwrap();
        assert!(!serialized.is_empty());

        // First byte should be 0 for Simple variant
        assert_eq!(serialized[0], 0);
    }
}
