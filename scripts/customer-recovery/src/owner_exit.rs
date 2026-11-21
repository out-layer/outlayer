//! `customer-recovery owner-exit …` — leave OutLayer with the keys of an owner's wallets,
//! through the keystore DAO contract and NEAR MPC, with no OutLayer service.
//!
//! An owner registered in the keystore DAO has a master per GENERATION. The keystore stored
//! an ESCROW of it in the DAO contract: the master sealed under the key MPC derives for the
//! owner path `owner:{account}:{generation}` with the DAO as predecessor. `claim` asks the
//! DAO for that key after the exit window, opens the escrow and prints the master.
//!
//! The crypto is the keystore's, byte for byte (`keystore-worker/src/crypto.rs`,
//! `seal_owner_escrow`); the test at the bottom holds this file to the keystore's vector.

use anyhow::{anyhow, bail, Context, Result};
use blstrs::{G1Projective, Scalar};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use clap::{Parser, Subcommand};
use elliptic_curve::{Field, Group};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use near_crypto::{InMemorySigner, SecretKey};
use near_jsonrpc_client::{
    errors::{JsonRpcError, JsonRpcServerError, JsonRpcServerResponseStatusError},
    methods, JsonRpcClient,
};
use near_jsonrpc_primitives::types::query::QueryResponseKind;
use near_jsonrpc_primitives::types::transactions::{RpcTransactionError, TransactionInfo};
use near_primitives::{
    hash::CryptoHash,
    transaction::{Action, FunctionCallAction, SignedTransaction, Transaction, TransactionV0},
    types::{AccountId, BlockReference, Finality, FunctionArgs},
    views::{FinalExecutionStatus, QueryRequest, TxExecutionStatus},
};
use rand::rngs::OsRng;
use sha2::Sha256;
use std::str::FromStr;
use zeroize::Zeroizing;

use super::{decrypt_and_verify, derive_app_id, derive_strong_key, parse_g2, require_https, CkdResponse};

const OWNER_ESCROW_SALT: &[u8] = b"outlayer/owner-escrow/v1";
const OWNER_ESCROW_CHECK_LABEL: &[u8] = b"owner-escrow-check/v1";

/// Gas for a call that asks MPC for a key: the DAO gives MPC 100 TGas and keeps 30 for its
/// callback; the rest is refunded.
const CLAIM_GAS: u64 = 300_000_000_000_000;
const PLAIN_GAS: u64 = 30_000_000_000_000;

/// The most `initiate` attaches as the exit fee: a hundred times the fee the contract
/// charges (0.01 NEAR), so a raised fee still goes through and a lying RPC cannot name the
/// owner's balance.
const MAX_EXIT_FEE_YOCTO: u128 = 1_000_000_000_000_000_000_000_000;

/// How many numbered seeds in a row may be unused before `wallets` stops looking.
const UNUSED_RUN: u32 = 5;

#[derive(Parser, Debug)]
#[command(name = "customer-recovery owner-exit", about = "Leave with an owner's wallet keys through the keystore DAO")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Args, Debug, Clone)]
struct Chain {
    /// The owner's NEAR account.
    #[arg(long)]
    owner: AccountId,
    /// The keystore DAO contract: `dao.outlayer.near` on mainnet.
    #[arg(long, default_value = "dao.outlayer.testnet")]
    dao: AccountId,
    #[arg(long, env = "RPC_URL", hide_env_values = true, default_value = "https://rpc.testnet.fastnear.com")]
    rpc_url: String,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// The owner's record in the DAO: generation, exit window, approvers, a pending exit.
    Status {
        #[command(flatten)]
        chain: Chain,
    },
    /// Start an exit from the current generation. Attaches the DAO's exit fee.
    Initiate {
        #[command(flatten)]
        chain: Chain,
        /// The owner's full-access private key, `ed25519:<base58>`.
        #[arg(long, env = "OWNER_PRIVATE_KEY", hide_env_values = true)]
        signer_private_key: String,
    },
    /// Drop the pending exit, or the pending change of approvers.
    Cancel {
        #[command(flatten)]
        chain: Chain,
        #[arg(long, env = "OWNER_PRIVATE_KEY", hide_env_values = true)]
        signer_private_key: String,
    },
    /// Claim the escrow key after the exit window, open the escrow, print the master.
    Claim {
        #[command(flatten)]
        chain: Chain,
        #[arg(long, env = "OWNER_PRIVATE_KEY", hide_env_values = true)]
        signer_private_key: String,
        /// MPC's `bls12381g2:<base58>` key for CKD domain 2.
        #[arg(long, env = "MPC_PUBLIC_KEY")]
        mpc_public_key: String,
        /// Where the one-time key and the transaction hash of this claim are kept (mode
        /// 0600). A new file, written BEFORE the transaction is sent: with it, MPC's answer
        /// can be opened later — from any RPC for the first days, from an archival one after.
        /// An existing file is never overwritten.
        #[arg(long)]
        claim_file: std::path::PathBuf,
    },
    /// Open the escrow from a claim file: reads the claim's result from the chain by its
    /// transaction hash. Works after a claim whose own run was cut short.
    Open {
        #[arg(long)]
        claim_file: std::path::PathBuf,
        #[arg(long, env = "MPC_PUBLIC_KEY")]
        mpc_public_key: String,
        #[arg(long, env = "RPC_URL", hide_env_values = true, default_value = "https://rpc.testnet.fastnear.com")]
        rpc_url: String,
    },
    /// The wallets of a generation: numbered seeds from 0, their wallet ids and NEAR accounts,
    /// until a run of accounts that do not exist on chain.
    Wallets {
        #[command(flatten)]
        chain: Chain,
        #[arg(long)]
        generation: u64,
        /// The generation's master, 32 bytes hex.
        #[arg(long, env = "CUSTOMER_RECOVERY_MASTER", hide_env_values = true)]
        master: String,
        /// Stop after this many seeds whatever is found.
        #[arg(long, default_value = "1000")]
        max: u32,
    },
}

/// What `claim` keeps on disk, written before its transaction is sent: the one-time key
/// MPC's answer is encrypted to, and the transaction whose result is that answer. The two
/// open the escrow later, whatever happened to the process that sent it — for as long as
/// the RPC asked still serves the transaction's result.
#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq, Eq)]
struct ClaimFile {
    owner: String,
    dao: String,
    generation: u64,
    /// The one-time BLS12-381 scalar MPC's answer is encrypted to, little-endian hex.
    one_time_key_hex: String,
    /// The claim transaction, base58.
    tx_hash: String,
}

/// How long the result of a claim is waited for: MPC answers within its own yield
/// timeout, a few hundred blocks.
const CLAIM_RESULT_WAIT: std::time::Duration = std::time::Duration::from_secs(360);

pub(super) fn owner_path(account: &str, generation: u64) -> String {
    format!("owner:{account}:{generation}")
}

fn escrow_cipher(escrow_key: &[u8; 32], path: &str) -> ChaCha20Poly1305 {
    let hkdf = Hkdf::<Sha256>::new(Some(OWNER_ESCROW_SALT), escrow_key);
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf.expand(path.as_bytes(), key.as_mut()).expect("32 bytes is a valid HKDF-SHA256 output length");
    ChaCha20Poly1305::new_from_slice(key.as_ref()).expect("a 32-byte key is a ChaCha20-Poly1305 key")
}

/// Open an escrow with the key MPC's answer for `path` gives.
pub(super) fn open_escrow(escrow_key: &[u8; 32], ct: &[u8], path: &str) -> Result<Zeroizing<[u8; 32]>> {
    let plain = Zeroizing::new(
        escrow_cipher(escrow_key, path)
            .decrypt(&Nonce::from([0u8; 12]), Payload { msg: ct, aad: path.as_bytes() })
            .map_err(|_| anyhow!("the escrow does not open with this key for {path}"))?,
    );
    let master: [u8; 32] = plain
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("the escrow holds {} bytes, not a 32-byte master", plain.len()))?;
    Ok(Zeroizing::new(master))
}

/// `HMAC-SHA256(master, label || 0x00 || path || 0x00 || ct)`.
pub(super) fn escrow_check(master: &[u8; 32], path: &str, ct: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(master).expect("HMAC can take a key of any size");
    mac.update(OWNER_ESCROW_CHECK_LABEL);
    mac.update(&[0]);
    mac.update(path.as_bytes());
    mac.update(&[0]);
    mac.update(ct);
    mac.finalize().into_bytes().into()
}

/// How long one request to the RPC may take. Without a bound a node that accepts the
/// connection and never answers holds the tool for good.
const RPC_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

fn rpc_client(rpc_url: &str) -> Result<JsonRpcClient> {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(reqwest::header::CONTENT_TYPE, reqwest::header::HeaderValue::from_static("application/json"));
    let http = reqwest::Client::builder()
        .default_headers(headers)
        .timeout(RPC_REQUEST_TIMEOUT)
        .build()
        .map_err(|_| anyhow!("the HTTP client could not be built"))?;
    Ok(JsonRpcClient::with(http).connect(rpc_url))
}

/// Why an RPC call failed, safe to print. What the node answered is the node's words. A
/// transport failure is said as a fact and not quoted: the HTTP error names the endpoint,
/// and an RPC URL can carry an API key.
pub(super) fn rpc_why<E: std::fmt::Display>(e: &JsonRpcError<E>) -> String {
    match e {
        JsonRpcError::ServerError(answer) => answer.to_string(),
        JsonRpcError::TransportError(_) => {
            "the RPC could not be reached, timed out, or answered something that is not JSON-RPC".to_string()
        }
    }
}

async fn view(client: &JsonRpcClient, contract: &AccountId, method: &str, args: serde_json::Value) -> Result<serde_json::Value> {
    let response = client
        .call(methods::query::RpcQueryRequest {
            block_reference: BlockReference::Finality(Finality::Final),
            request: QueryRequest::CallFunction {
                account_id: contract.clone(),
                method_name: method.to_string(),
                args: FunctionArgs::from(serde_json::to_vec(&args)?),
            },
        })
        .await
        .map_err(|e| anyhow!("{method} on {contract}: {}", rpc_why(&e)))?;
    match response.kind {
        QueryResponseKind::CallResult(result) => {
            serde_json::from_slice(&result.result).with_context(|| format!("{method} on {contract} answered something that is not JSON"))
        }
        other => bail!("unexpected answer to {method}: {other:?}"),
    }
}

fn signer_of(owner: &AccountId, private_key: &str) -> Result<InMemorySigner> {
    let secret_key = SecretKey::from_str(private_key).context("the private key must be ed25519:<base58>")?;
    Ok(InMemorySigner::from_secret_key(owner.clone(), secret_key))
}

/// One function call from the owner, signed and not sent.
async fn sign_call(
    client: &JsonRpcClient,
    signer: &InMemorySigner,
    contract: &AccountId,
    method: &str,
    args: serde_json::Value,
    gas: u64,
    deposit: u128,
) -> Result<SignedTransaction> {
    let access_key = match client
        .call(methods::query::RpcQueryRequest {
            block_reference: BlockReference::Finality(Finality::Final),
            request: QueryRequest::ViewAccessKey {
                account_id: signer.account_id.clone(),
                public_key: signer.public_key.clone(),
            },
        })
        .await
        .map_err(|e| anyhow!("the owner's access key could not be read: {}", rpc_why(&e)))?
        .kind
    {
        QueryResponseKind::AccessKey(v) => v,
        other => bail!("unexpected access-key answer: {other:?}"),
    };
    let block = client
        .call(methods::block::RpcBlockRequest { block_reference: BlockReference::Finality(Finality::Final) })
        .await
        .map_err(|e| anyhow!("the latest final block could not be read: {}", rpc_why(&e)))?;
    let tx = TransactionV0 {
        signer_id: signer.account_id.clone(),
        public_key: signer.public_key.clone(),
        nonce: access_key.nonce + 1,
        receiver_id: contract.clone(),
        block_hash: block.header.hash,
        actions: vec![Action::FunctionCall(Box::new(FunctionCallAction {
            method_name: method.to_string(),
            args: serde_json::to_vec(&args)?,
            gas,
            deposit,
        }))],
    };
    Ok(SignedTransaction::new(
        signer.sign(Transaction::V0(tx.clone()).get_hash_and_size().0.as_ref()),
        Transaction::V0(tx),
    ))
}

/// Where a transaction stands on chain.
enum TxResult {
    /// Executed; what it returned.
    Returned(Vec<u8>),
    /// Executed and failed: nothing it did holds.
    Failed(String),
    /// The chain does not know it (yet), or it has not finished.
    NotThere,
}

async fn tx_result(client: &JsonRpcClient, tx_hash: CryptoHash, sender: &AccountId) -> Result<TxResult> {
    let answer = client
        .call(methods::tx::RpcTransactionStatusRequest {
            transaction_info: TransactionInfo::TransactionId { tx_hash, sender_account_id: sender.clone() },
            wait_until: TxExecutionStatus::Final,
        })
        .await;
    let outcome = match answer {
        Ok(response) => response.final_execution_outcome,
        Err(e) => {
            return match e.handler_error() {
                Some(RpcTransactionError::UnknownTransaction { .. }) | Some(RpcTransactionError::TimeoutError) => Ok(TxResult::NotThere),
                // A node that waited for the transaction and gave up answers 408.
                _ if matches!(
                    &e,
                    JsonRpcError::ServerError(JsonRpcServerError::ResponseStatusError(
                        JsonRpcServerResponseStatusError::Unexpected { status }
                    )) if *status == reqwest::StatusCode::REQUEST_TIMEOUT
                ) =>
                {
                    Ok(TxResult::NotThere)
                }
                _ => Err(anyhow!("the transaction {tx_hash} could not be read: {}", rpc_why(&e))),
            }
        }
    };
    Ok(match outcome.map(|o| o.into_outcome().status) {
        Some(FinalExecutionStatus::SuccessValue(value)) => TxResult::Returned(value),
        Some(FinalExecutionStatus::Failure(err)) => TxResult::Failed(format!("{err:?}")),
        _ => TxResult::NotThere,
    })
}

/// The result of a transaction, read until it has one or `wait` has passed. `NotThere`
/// only when the node SAID it has no such result; a read that failed is the error it
/// failed with, never "not there".
async fn wait_for_tx(client: &JsonRpcClient, tx_hash: CryptoHash, sender: &AccountId, wait: std::time::Duration) -> Result<TxResult> {
    let started = std::time::Instant::now();
    loop {
        let read = tx_result(client, tx_hash, sender).await;
        if let Ok(TxResult::Returned(_) | TxResult::Failed(_)) = read {
            return read;
        }
        if started.elapsed() >= wait {
            return read;
        }
        // The transaction is on its way whatever this read came to: read again.
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

/// Send one function call from the owner and return what the transaction returned.
async fn call(
    client: &JsonRpcClient,
    signer: &InMemorySigner,
    contract: &AccountId,
    method: &str,
    args: serde_json::Value,
    gas: u64,
    deposit: u128,
) -> Result<Vec<u8>> {
    let signed = sign_call(client, signer, contract, method, args, gas, deposit).await?;
    let outcome = client
        .call(methods::broadcast_tx_commit::RpcBroadcastTxCommitRequest { signed_transaction: signed })
        .await
        .map_err(|e| match &e {
            // The answer was lost, not the transaction: it may be on chain.
            JsonRpcError::TransportError(_) => anyhow!(
                "no answer to {method} on {contract}: {}. The transaction may have gone through — run \
                 `owner-exit status` before sending it again",
                rpc_why(&e)
            ),
            // The node's own refusal of the transaction: it is not on chain.
            _ if e.handler_error().is_some() => anyhow!("{method} on {contract} was not accepted: {}", rpc_why(&e)),
            // A status with no answer in it — a timeout, an overloaded node — says nothing
            // of the transaction either way.
            _ => anyhow!(
                "no usable answer to {method} on {contract}: {}. The transaction may have gone through — run \
                 `owner-exit status` before sending it again",
                rpc_why(&e)
            ),
        })?;
    match outcome.status {
        FinalExecutionStatus::SuccessValue(value) => Ok(value),
        FinalExecutionStatus::Failure(err) => bail!("{method} on {contract} failed: {err:?}"),
        other => bail!("{method} on {contract} ended as {other:?}"),
    }
}

/// Write a claim file that does not exist yet, readable by its owner only. A file already
/// at the path is never touched: it may hold the only key that opens an earlier claim.
fn write_claim_file(path: &std::path::Path, file: &ClaimFile) -> Result<()> {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut f = options.open(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::AlreadyExists => anyhow!(
            "{} exists. It may hold the key of an earlier claim: open it with `owner-exit open --claim-file {}`, \
             and give a new claim a new path",
            path.display(),
            path.display()
        ),
        _ => anyhow!("{} could not be written: {e}", path.display()),
    })?;
    f.write_all(serde_json::to_string_pretty(file)?.as_bytes())?;
    f.sync_all()?;
    Ok(())
}

fn read_claim_file(path: &std::path::Path) -> Result<ClaimFile> {
    serde_json::from_slice(&std::fs::read(path).with_context(|| format!("{} could not be read", path.display()))?)
        .with_context(|| format!("{} is not a claim file", path.display()))
}

/// Open the escrow a claim file names: read its transaction's result from the chain, decrypt
/// MPC's answer with the file's one-time key, open the escrow, print the master.
async fn open_claim(client: &JsonRpcClient, mpc_public_key: &str, path: &std::path::Path, wait: std::time::Duration) -> Result<()> {
    let file = read_claim_file(path)?;
    let key_bytes: [u8; 32] = hex::decode(&file.one_time_key_hex)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow!("the claim file's one-time key is not 32 bytes of hex"))?;
    let one_time_key = Option::<Scalar>::from(Scalar::from_bytes_le(&key_bytes))
        .ok_or_else(|| anyhow!("the claim file's one-time key is not a scalar"))?;
    let owner: AccountId = file.owner.parse().context("the claim file's owner")?;
    let dao: AccountId = file.dao.parse().context("the claim file's dao")?;
    let tx_hash = CryptoHash::from_str(&file.tx_hash).map_err(|_| anyhow!("the claim file's tx_hash is not a transaction hash"))?;

    let result = wait_for_tx(client, tx_hash, &owner, wait).await?;
    // The owner's record, read AFTER the transaction: it says whether the generation the
    // file names has been left, and a DAO this RPC does not know is the wrong network.
    let record = view(client, &dao, "get_exit_owner", serde_json::json!({ "account": file.owner }))
        .await
        .with_context(|| format!("{dao} could not be read: --rpc-url (or RPC_URL) must be an RPC of the network {dao} is on"))?;
    let generation_now = record
        .get("generation")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow!("{} is not registered as an owner on {dao}", file.owner))?;

    let value = match result {
        TxResult::Returned(value) => value,
        TxResult::Failed(why) => bail!(
            "the claim {tx_hash} failed: {why}\nA failed claim changes nothing in the DAO. {} is in generation {} now: if that is \
             still {} and `owner-exit status` shows the exit pending, this claim file opens nothing — claim again with a new \
             --claim-file",
            file.owner,
            generation_now,
            file.generation
        ),
        // The node has no result for this transaction. The owner's record says which of
        // two different things that is.
        TxResult::NotThere if generation_now > file.generation => bail!(
            "{} has left generation {}, and this RPC holds no result for {tx_hash}. If this is the claim that \
             did it, an ordinary node no longer keeps its result: run `owner-exit open --claim-file {}` with an \
             ARCHIVAL RPC of this network, and the file opens it. If another claim was made for this generation, \
             its own claim file is the one that holds the key",
            file.owner,
            file.generation,
            path.display()
        ),
        TxResult::NotThere => bail!(
            "this RPC holds no result for the claim {tx_hash}, and {} is still in generation {}: the transaction is \
             not final yet, or it never reached the chain. Keep {} and run `owner-exit open --claim-file {}` again in \
             a minute. If `owner-exit status` then still shows the exit pending and the generation unchanged, the \
             transaction was lost: claim again with a new --claim-file",
            file.owner,
            file.generation,
            path.display(),
            path.display()
        ),
    };
    let answer: CkdResponse = match serde_json::from_slice(&value) {
        Ok(answer) => answer,
        // The DAO passes MPC's answer on as the claim's result; with none, the generation
        // says which of the two cases this is.
        Err(_) if generation_now > file.generation => bail!(
            "{} is past generation {}, and the claim {tx_hash} returned no key. If this is the claim that moved it, \
             MPC's answer is in MPC's own receipt of that transaction, encrypted to the one-time key in {}: keep that \
             file. If another claim moved it, that claim's file is the one that holds the key",
            file.owner,
            file.generation,
            path.display()
        ),
        Err(_) => bail!(
            "the claim {tx_hash} went through but MPC did not answer: {} is still in generation {} and nothing changed. \
             Claim again inside the claim window with a new --claim-file",
            file.owner,
            file.generation
        ),
    };
    let master = master_from_answer(client, mpc_public_key, &file.owner, &dao, file.generation, one_time_key, answer).await?;
    print_master(&file.owner, file.generation, &master);
    Ok(())
}

/// From MPC's answer and the one-time key to the master, checked against the escrow on chain.
async fn master_from_answer(
    client: &JsonRpcClient,
    mpc_public_key: &str,
    owner: &str,
    dao: &AccountId,
    generation: u64,
    one_time_key: Scalar,
    answer: CkdResponse,
) -> Result<Zeroizing<[u8; 32]>> {
    let path = owner_path(owner, generation);
    let app_id = derive_app_id(dao.as_str(), &path);
    let secret = decrypt_and_verify(answer, one_time_key, &parse_g2(mpc_public_key)?, &app_id)
        .context("MPC's answer is not the escrow key of this owner and generation")?;
    let escrow_key = Zeroizing::new(derive_strong_key(secret)?);

    let escrow = view(client, dao, "get_escrow", serde_json::json!({ "account": owner, "generation": generation })).await?;
    let b64 = |field: &str| -> Result<Vec<u8>> {
        let text = escrow.get(field).and_then(|v| v.as_str()).ok_or_else(|| anyhow!("get_escrow: no {field}"))?;
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, text).with_context(|| format!("get_escrow: {field} is not base64"))
    };
    let ct = b64("ct")?;
    let check = b64("check")?;
    let master = open_escrow(&escrow_key, &ct, &path)?;
    if escrow_check(&master, &path, &ct).as_slice() != check.as_slice() {
        bail!("the escrow opened, but its check does not match the master inside it");
    }
    Ok(master)
}

fn print_master(owner: &str, generation: u64, master: &[u8; 32]) {
    super::warn_sensitive_stdout("the owner's master (32-byte hex)");
    println!();
    println!("# === Owner master recovered ===");
    println!("# owner      = {owner}");
    println!("# generation = {generation}");
    println!("# scope      = {}", owner_path(owner, generation));
    println!();
    println!("master_hex={}", hex::encode(master));
    println!();
    println!("# A wallet's id: customer-recovery compute-wallet-id --account-id {owner} --seed <seed> --vault-id {}", owner_path(owner, generation));
    println!("# Its key:       customer-recovery derive-wallet-key --master <master_hex> --wallet-id <id>");
}

pub(super) async fn run(args: &[String]) -> Result<()> {
    let cli = Cli::parse_from(std::iter::once("owner-exit".to_string()).chain(args.iter().cloned()));
    match cli.command {
        Command::Status { chain } => {
            require_https(&chain.rpc_url, "--rpc-url")?;
            let client = rpc_client(&chain.rpc_url)?;
            let record = view(&client, &chain.dao, "get_exit_owner", serde_json::json!({ "account": chain.owner })).await?;
            if record.is_null() {
                bail!("{} is not registered as an owner on {}", chain.owner, chain.dao);
            }
            println!("{}", serde_json::to_string_pretty(&record)?);
        }
        Command::Initiate { chain, signer_private_key } => {
            require_https(&chain.rpc_url, "--rpc-url")?;
            let client = rpc_client(&chain.rpc_url)?;
            let config = view(&client, &chain.dao, "get_config", serde_json::json!({})).await?;
            let fee: u128 = config
                .pointer("/exit/exit_fee")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| anyhow!("{} names no exit fee", chain.dao))?;
            // The fee is read from the RPC and the DAO keeps whatever is attached: an RPC
            // that lies about it must not be able to send the owner's balance to the DAO.
            if fee > MAX_EXIT_FEE_YOCTO {
                bail!(
                    "{} names an exit fee of {} yoctoNEAR, more than this tool attaches ({} yoctoNEAR). \
                     Nothing was sent: check the DAO's get_config through another RPC",
                    chain.dao,
                    fee,
                    MAX_EXIT_FEE_YOCTO
                );
            }
            eprintln!("# attaching the exit fee of {fee} yoctoNEAR, which {} keeps", chain.dao);
            let signer = signer_of(&chain.owner, &signer_private_key)?;
            call(&client, &signer, &chain.dao, "initiate_exit", serde_json::json!({}), PLAIN_GAS, fee).await?;
            let record = view(&client, &chain.dao, "get_exit_owner", serde_json::json!({ "account": chain.owner })).await?;
            println!("{}", serde_json::to_string_pretty(&record["pending"])?);
        }
        Command::Cancel { chain, signer_private_key } => {
            require_https(&chain.rpc_url, "--rpc-url")?;
            let client = rpc_client(&chain.rpc_url)?;
            let signer = signer_of(&chain.owner, &signer_private_key)?;
            call(&client, &signer, &chain.dao, "cancel_exit", serde_json::json!({}), PLAIN_GAS, 1).await?;
            println!("cancelled");
        }
        Command::Claim { chain, signer_private_key, mpc_public_key, claim_file } => {
            require_https(&chain.rpc_url, "--rpc-url")?;
            parse_g2(&mpc_public_key)?;
            let client = rpc_client(&chain.rpc_url)?;
            let record = view(&client, &chain.dao, "get_exit_owner", serde_json::json!({ "account": chain.owner })).await?;
            let generation = record
                .get("generation")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| anyhow!("{} is not registered as an owner on {}", chain.owner, chain.dao))?;

            let one_time_key = Scalar::random(&mut OsRng);
            let app_public_key = format!(
                "bls12381g1:{}",
                bs58::encode((G1Projective::generator() * one_time_key).to_compressed()).into_string()
            );
            let signer = signer_of(&chain.owner, &signer_private_key)?;
            let signed = sign_call(
                &client,
                &signer,
                &chain.dao,
                "claim_escrow_key",
                serde_json::json!({ "app_public_key": app_public_key }),
                CLAIM_GAS,
                1,
            )
            .await?;
            // On disk before the transaction leaves: MPC answers once, to this key, and the
            // answer is the result of this transaction.
            write_claim_file(
                &claim_file,
                &ClaimFile {
                    owner: chain.owner.to_string(),
                    dao: chain.dao.to_string(),
                    generation,
                    one_time_key_hex: hex::encode(one_time_key.to_bytes_le()),
                    tx_hash: signed.get_hash().to_string(),
                },
            )?;
            // Sent without waiting on this connection: the result is read by hash, so a
            // lost answer to the send loses nothing.
            if let Err(e) = client.call(methods::broadcast_tx_async::RpcBroadcastTxAsyncRequest { signed_transaction: signed }).await {
                eprintln!("# the send was not confirmed ({}); reading the chain for the transaction", rpc_why(&e));
            }
            open_claim(&client, &mpc_public_key, &claim_file, CLAIM_RESULT_WAIT).await?;
        }
        Command::Open { claim_file, mpc_public_key, rpc_url } => {
            require_https(&rpc_url, "--rpc-url")?;
            let client = rpc_client(&rpc_url)?;
            open_claim(&client, &mpc_public_key, &claim_file, std::time::Duration::ZERO).await?;
        }
        Command::Wallets { chain, generation, master, max } => {
            require_https(&chain.rpc_url, "--rpc-url")?;
            let master = Zeroizing::new(hex::decode(master.trim()).context("--master must be hex")?);
            if master.len() != 32 {
                bail!("--master must decode to 32 bytes, got {}", master.len());
            }
            let client = rpc_client(&chain.rpc_url)?;
            let scope = owner_path(chain.owner.as_str(), generation);
            let mut unused = 0;
            for n in 0..max {
                let seed = n.to_string();
                let wallet_id = super::compute_wallet_id(chain.owner.as_str(), &seed, Some(&scope));
                let account = near_account_of(&master, &wallet_id);
                let exists = account_exists(&client, &account).await?;
                println!("seed={seed} wallet_id={wallet_id} near_account={account} on_chain={exists}");
                unused = if exists { 0 } else { unused + 1 };
                if unused >= UNUSED_RUN {
                    break;
                }
            }
            if unused >= UNUSED_RUN {
                println!("# stopped after {UNUSED_RUN} seeds in a row with no account on chain; a wallet made with a named seed is found with compute-wallet-id");
            } else {
                println!("# stopped at --max {max}: there may be wallets at later seeds; raise --max to look further");
            }
        }
    }
    Ok(())
}

/// The implicit NEAR account of a wallet: the hex of the key the keystore derives for it.
fn near_account_of(master: &[u8], wallet_id: &str) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(master).expect("HMAC can take a key of any size");
    mac.update(format!("wallet:{wallet_id}:near").as_bytes());
    let derived = mac.finalize().into_bytes();
    let mut secret = Zeroizing::new([0u8; 32]);
    secret.copy_from_slice(&derived[..32]);
    hex::encode(ed25519_dalek::SigningKey::from_bytes(&secret).verifying_key().to_bytes())
}

async fn account_exists(client: &JsonRpcClient, account: &str) -> Result<bool> {
    let account_id: AccountId = account.parse()?;
    match client
        .call(methods::query::RpcQueryRequest {
            block_reference: BlockReference::Finality(Finality::Final),
            request: QueryRequest::ViewAccount { account_id },
        })
        .await
    {
        Ok(_) => Ok(true),
        Err(e) => {
            // Matched on the node's own answer; a transport failure is never read as "no account".
            let answered = e.handler_error().map(|h| format!("{h:?}")).unwrap_or_default();
            if answered.contains("UnknownAccount") || answered.contains("does not exist") {
                Ok(false)
            } else {
                Err(anyhow!("the account {account} could not be read: {}", rpc_why(&e)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The keystore's vector (`keystore-worker/src/crypto.rs`, `the_escrow_format_is_pinned`):
    /// default master `11…11`, escrow key `55…55`, owner `alice.near`, generation 1.
    const MASTER: &str = "f87a0234f26f41714588b8e9892402dd4384c6492282f17f573af5bff0d86ebf";
    const CT: &str = "166f4b556d5496ed4dfc7744fc1a05a560994b4abf650115fb576d370d19ec159cf9524a8c579f286ef683df604d5ca9";
    const CHECK: &str = "9f3b66c79132b41d9ac781a7c1f94ed511bac41c3b56597d003059f21d134581";

    #[test]
    fn the_keystores_escrow_opens_here() {
        let path = owner_path("alice.near", 1);
        assert_eq!(path, "owner:alice.near:1");
        let ct = hex::decode(CT).unwrap();
        let master = open_escrow(&[0x55; 32], &ct, &path).unwrap();
        assert_eq!(hex::encode(*master), MASTER);
        assert_eq!(hex::encode(escrow_check(&master, &path, &ct)), CHECK);
    }

    #[test]
    fn an_escrow_opens_for_its_own_key_and_path_only() {
        let ct = hex::decode(CT).unwrap();
        assert!(open_escrow(&[0x56; 32], &ct, "owner:alice.near:1").is_err());
        assert!(open_escrow(&[0x55; 32], &ct, "owner:alice.near:2").is_err());
        assert!(open_escrow(&[0x55; 32], &ct, "owner:bob.near:1").is_err());
        let mut tampered = ct.clone();
        tampered[0] ^= 1;
        assert!(open_escrow(&[0x55; 32], &tampered, "owner:alice.near:1").is_err());
    }

    fn claim_file() -> ClaimFile {
        ClaimFile {
            owner: "alice.near".into(),
            dao: "dao.outlayer.near".into(),
            generation: 1,
            one_time_key_hex: "07".repeat(32),
            tx_hash: CryptoHash::default().to_string(),
        }
    }

    #[test]
    fn a_claim_file_is_never_written_over_another() {
        let dir = std::env::temp_dir().join(format!("owner-exit-test-{}-{}", std::process::id(), rand::random::<u64>()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("claim.json");
        let first = claim_file();
        write_claim_file(&path, &first).unwrap();
        // A second claim on the same path: refused, and the first key is still there.
        let second = ClaimFile { one_time_key_hex: "09".repeat(32), ..claim_file() };
        let refused = write_claim_file(&path, &second).unwrap_err().to_string();
        assert!(refused.contains("exists") && refused.contains("owner-exit open"), "{refused}");
        assert_eq!(read_claim_file(&path).unwrap(), first);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(&dir).unwrap();
    }

    #[test]
    fn a_transport_failure_is_said_without_the_endpoint() {
        use near_jsonrpc_client::errors::{JsonRpcTransportSendError, RpcTransportError};
        // The serialization failure stands in for any transport error: whatever it holds
        // is not quoted.
        let secret = "https://rpc.example/?apiKey=SECRET-KEY";
        let inner = serde_json::from_str::<serde_json::Value>(secret).unwrap_err();
        let transport: JsonRpcError<String> =
            JsonRpcError::TransportError(RpcTransportError::SendError(JsonRpcTransportSendError::PayloadSerializeError(inner.into())));
        let said = rpc_why(&transport);
        assert!(!said.contains("SECRET") && !said.contains("http"), "{said}");
        // What the node answered is passed on.
        let answered: JsonRpcError<String> = JsonRpcError::ServerError(JsonRpcServerError::HandlerError("the node's words".into()));
        assert!(rpc_why(&answered).contains("the node's words"));
    }

    #[test]
    fn a_claim_file_names_its_transaction() {
        // A file with a key and no transaction opens nothing and is not taken for one.
        let without: serde_json::Value = serde_json::json!({
            "owner": "alice.near", "dao": "dao.outlayer.near", "generation": 1, "one_time_key_hex": "07".repeat(32)
        });
        assert!(serde_json::from_value::<ClaimFile>(without).is_err());
        let json = serde_json::to_value(claim_file()).unwrap();
        assert_eq!(serde_json::from_value::<ClaimFile>(json).unwrap(), claim_file());
    }

    #[test]
    fn a_wallet_of_an_owner_is_named_by_account_seed_and_scope() {
        let g1 = super::super::compute_wallet_id("alice.near", "0", Some("owner:alice.near:1"));
        let g2 = super::super::compute_wallet_id("alice.near", "0", Some("owner:alice.near:2"));
        let default = super::super::compute_wallet_id("alice.near", "0", None);
        assert!(g1 != g2 && g1 != default && g2 != default);
    }
}
