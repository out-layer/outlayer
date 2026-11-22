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

        // The block hash is a FINAL block's: every node behind a load-balanced
        // RPC knows it.
        let block_query = methods::block::RpcBlockRequest {
            block_reference: BlockReference::Finality(Finality::Final),
        };

        let block = self
            .client
            .call(block_query)
            .await
            .map_err(crate::near_client::rpc_call_error)
            .context("Failed to query block for FastFS")?;

        let block_hash = block.header.hash;

        // Parse receiver account ID
        let receiver_id: AccountId = self.receiver
            .parse()
            .context("Failed to parse FastFS receiver account ID")?;

        // `broadcast_tx_commit` answers once a transaction has executed, two or
        // three blocks before its block is final, so a read at final can miss
        // the nonce the previous upload of this sender took. The nonce is read
        // at optimistic finality, and one `InvalidNonce` is answered by one
        // re-read and one more broadcast: the refused transaction never ran.
        let mut nonce_refusals = 0u32;
        let outcome = loop {
            let current_nonce = self.access_key_nonce().await?;

            // Create transaction (no deposit needed for FastFS)
            let transaction_v0 = TransactionV0 {
                signer_id: self.signer.account_id.clone(),
                public_key: self.signer.public_key(),
                nonce: current_nonce + 1,
                receiver_id: receiver_id.clone(),
                block_hash,
                actions: vec![Action::FunctionCall(Box::new(FunctionCallAction {
                    method_name: FASTFS_METHOD.to_string(),
                    args: args.clone(),
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

            match self.client.call(tx_request).await {
                Ok(outcome) => break outcome,
                Err(e) if is_invalid_nonce(&e) && nonce_refusals < 1 => {
                    nonce_refusals += 1;
                    warn!(
                        "FastFS upload refused for its nonce {}; re-reading the nonce and broadcasting once more",
                        current_nonce + 1
                    );
                }
                Err(e) => {
                    return Err(crate::near_client::rpc_call_error(e))
                        .context("Failed to broadcast FastFS transaction")
                }
            }
        };

        // The file travels in the transaction's arguments and the indexer
        // reads it from the chain, so a transaction the chain EXECUTED is a
        // publish whatever its status: there is no contract at the receiver,
        // and the call "fails" every time. Only a transaction the chain did
        // not take — refused before inclusion (`InvalidNonce`, `Expired`, a
        // signer short of balance) or never answered — is a failed publish,
        // and the broadcast above returns it as one: the file is not on FastFS then, and
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

    /// The nonce of the sender's access key, at optimistic finality: the head
    /// carries every transaction that has executed.
    async fn access_key_nonce(&self) -> Result<u64> {
        let access_key_query = methods::query::RpcQueryRequest {
            block_reference: BlockReference::Finality(Finality::None),
            request: near_primitives::views::QueryRequest::ViewAccessKey {
                account_id: self.signer.account_id.clone(),
                public_key: self.signer.public_key(),
            },
        };

        let access_key_response = self
            .client
            .call(access_key_query)
            .await
            .map_err(crate::near_client::rpc_call_error)
            .context("Failed to query access key for FastFS")?;

        match access_key_response.kind {
            near_jsonrpc_primitives::types::query::QueryResponseKind::AccessKey(access_key) => {
                Ok(access_key.nonce)
            }
            _ => anyhow::bail!("Unexpected query response"),
        }
    }
}

/// Whether the chain refused a transaction for its nonce: the one refusal that
/// goes away with a fresh read of the nonce.
fn is_invalid_nonce(
    e: &near_jsonrpc_client::errors::JsonRpcError<
        near_jsonrpc_primitives::types::transactions::RpcTransactionError,
    >,
) -> bool {
    use near_jsonrpc_primitives::types::transactions::RpcTransactionError;
    use near_primitives::errors::InvalidTxError;
    matches!(
        e.handler_error(),
        Some(RpcTransactionError::InvalidTransaction {
            context: InvalidTxError::InvalidNonce { .. },
        })
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A transaction that executed, as `broadcast_tx_commit` answers it.
    const EXECUTED: &str = include_str!("testdata/tx_executed.json");
    /// A final block of testnet, as the `block` method answers it.
    const BLOCK: &str = include_str!("testdata/block_final.json");

    /// What the fake node saw: the finality of every access-key read, and the
    /// nonce of every transaction broadcast, in order.
    #[derive(Default)]
    struct Seen {
        key_reads: Vec<String>,
        broadcast_nonces: Vec<u64>,
    }

    /// A node whose sender has an access key at nonce `head` at the optimistic
    /// head and `head - 1` at final: the previous upload has executed and its
    /// block is not final yet. The first `lagging_reads` optimistic reads come
    /// from a node one block behind and answer `head - 1` too. A transaction
    /// with a nonce at or below `head` is refused `InvalidNonce`.
    fn node(head: u64, lagging_reads: usize) -> (String, std::sync::Arc<std::sync::Mutex<Seen>>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let url = format!("http://{}", listener.local_addr().expect("addr"));
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Seen::default()));
        let record = seen.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut buf = vec![0u8; 65536];
                let mut got = 0;
                loop {
                    let n = stream.read(&mut buf[got..]).unwrap_or(0);
                    if n == 0 { break; }
                    got += n;
                    let text = String::from_utf8_lossy(&buf[..got]);
                    if let Some(h) = text.find("\r\n\r\n") {
                        let len = text[..h].lines()
                            .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap_or(0)))
                            .unwrap_or(0);
                        if got >= h + 4 + len { break; }
                    }
                }
                let text = String::from_utf8_lossy(&buf[..got]).into_owned();
                let body = text.split("\r\n\r\n").nth(1).unwrap_or("");
                let request = serde_json::from_str::<serde_json::Value>(body).unwrap_or_default();
                let answer = {
                    let mut seen = record.lock().unwrap();
                    match request["method"].as_str().unwrap_or_default() {
                        "query" => {
                            let finality = request["params"]["finality"].as_str().unwrap_or_default().to_string();
                            let optimistic_reads = seen.key_reads.iter().filter(|f| *f == "optimistic").count();
                            let nonce = if finality == "optimistic" && optimistic_reads >= lagging_reads { head } else { head - 1 };
                            seen.key_reads.push(finality);
                            format!(r#"{{"jsonrpc":"2.0","id":"dontcare","result":{{"nonce":{nonce},"permission":"FullAccess","block_height":1,"block_hash":"11111111111111111111111111111111"}}}}"#)
                        }
                        "block" => BLOCK.to_string(),
                        "broadcast_tx_commit" => {
                            use base64::Engine;
                            let b64 = request["params"][0].as_str().expect("signed transaction");
                            let bytes = base64::engine::general_purpose::STANDARD.decode(b64).expect("base64");
                            let signed: near_primitives::transaction::SignedTransaction = borsh::from_slice(&bytes).expect("borsh");
                            let nonce = signed.transaction.nonce().nonce();
                            seen.broadcast_nonces.push(nonce);
                            if nonce <= head {
                                let info = format!(r#"{{"InvalidNonce":{{"tx_nonce":{nonce},"ak_nonce":{head}}}}}"#);
                                format!(r#"{{"jsonrpc":"2.0","id":"dontcare","error":{{"name":"HANDLER_ERROR","cause":{{"name":"INVALID_TRANSACTION","info":{info}}},"code":-32000,"message":"Server error","data":{{"TxExecutionError":{{"InvalidTxError":{info}}}}}}}}}"#)
                            } else {
                                EXECUTED.to_string()
                            }
                        }
                        other => panic!("unexpected RPC method {other:?}"),
                    }
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    answer.len(),
                    answer
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        (url, seen)
    }

    fn client(url: &str) -> FastFsClient {
        let secret_key = near_crypto::SecretKey::from_random(near_crypto::KeyType::ED25519);
        let signer = InMemorySigner {
            account_id: "compiler.testnet".parse().unwrap(),
            public_key: secret_key.public_key(),
            secret_key,
        };
        FastFsClient::new(url, signer, "outlayer.testnet")
    }

    /// An upload right after another one by the same sender takes the nonce
    /// after the one the first upload took, while that upload's block is not
    /// final yet.
    #[tokio::test]
    async fn a_second_upload_takes_the_nonce_after_the_first_one() {
        let (url, seen) = node(6, 0);
        let published = client(&url).upload_wasm(&[0, 97, 115, 109], "ab12").await.expect("published");
        assert!(published.ends_with("/outlayer.testnet/ab12.wasm"), "{published}");
        let seen = seen.lock().unwrap();
        assert_eq!(seen.key_reads, vec!["optimistic"]);
        assert_eq!(seen.broadcast_nonces, vec![7]);
    }

    /// A node that is a block behind hands out a nonce already taken: the
    /// refusal is answered by one re-read and one more broadcast.
    #[tokio::test]
    async fn an_upload_refused_for_its_nonce_is_sent_once_more_with_a_fresh_one() {
        let (url, seen) = node(6, 1);
        client(&url).upload_wasm(&[0, 97, 115, 109], "ab12").await.expect("published on the second broadcast");
        let seen = seen.lock().unwrap();
        assert_eq!(seen.key_reads, vec!["optimistic", "optimistic"]);
        assert_eq!(seen.broadcast_nonces, vec![6, 7]);
    }

    /// A second refusal is the error: the upload is not retried in a loop.
    #[tokio::test]
    async fn an_upload_refused_twice_for_its_nonce_fails() {
        let (url, seen) = node(6, 2);
        let e = client(&url).upload_wasm(&[0, 97, 115, 109], "ab12").await.expect_err("refused twice");
        assert!(format!("{e:#}").contains("InvalidNonce"), "{e:#}");
        assert_eq!(seen.lock().unwrap().broadcast_nonces, vec![6, 6]);
    }

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
