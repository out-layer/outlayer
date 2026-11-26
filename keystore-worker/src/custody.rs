//! Agent On-chain custody: the TEE's side of a wallet contract.
//!
//! A wallet with an owner may have a wallet contract: an account that runs
//! the two-key standard, whose pair of keys is the agent's and this wallet's
//! TEE key. Nothing moves out of it without a signature of each. This file is
//! the four things the keystore does for it:
//!
//! * `key`: says what the TEE's public key of a wallet is, for the setup;
//! * `prepare`: judges an operation the agent asked for by the owner's policy,
//!   builds the wallet contract's request for it and signs the TEE's half;
//! * `relay`: signs, with the wallet's own NEAR key, the transaction that
//!   carries a request with both halves to the wallet contract;
//! * `identity`: tells a worker whether a caller's wallet is the one an
//!   account is the wallet contract of, before a program runs as that account.
//!
//! The byte formats and the pure rules are `custody_core`'s; which move an
//! operation is, `shared_tee_helpers::custody_op`'s. The TEE's key is derived
//! in [`tee_key`] and is used in `prepare` alone, for a message built there.

use axum::{extract::State, http::HeaderMap, routing::post, Json, Router};
use near_primitives::types::AccountId;
use serde::{Deserialize, Serialize};
use shared_tee_helpers::{
    custody_core::{
        admit::{admit, Admitted, Fault, Observed},
        agent_request::{NotSigned, SignedAgentRequest, OPERATION_METHOD, OPERATION_PATH},
        halves::{sign_half, Role},
        refusal,
        keys::tee_key_seed,
        message::RequestMessage,
        moves::{build, Context, Move},
        TIMEOUT_SECS,
    },
    custody_op::move_for,
    wallet_policy::{self, Decision, Op},
};

use crate::{
    api::{
        derive_wallet_ed25519_pubkey, extract_customer_from_header, load_wallet_policy_with_owner,
        sign_near_transaction, validate_wallet_id, verify_approvals, wallet_seed, ApiError, AppState,
        ApprovalInfo, WalletSignResponse,
    },
    crypto::Customer,
};

/// The Intents contract a move inside NEAR Intents is sent to. NEAR Intents
/// is on mainnet only.
const INTENTS_CONTRACT: &str = "intents.near";

/// The gas of the relaying transaction: all a transaction can carry. The
/// request names the exact gas of its own call; the rest is the wallet
/// contract's execution, and what is unused returns to the relaying account.
const RELAY_GAS: u64 = 300_000_000_000_000;

/// How far before the keystore's clock a request is dated, in nanoseconds:
/// the contract refuses a request from its future, and a block's time lags.
const CREATED_AT_LAG_NS: u64 = 60_000_000_000;

/// The route a worker asks, merged into the worker-token group.
pub fn custody_worker_routes() -> Router<AppState> {
    Router::new().route("/wallet/contract/identity", post(identity_handler))
}

/// The routes the coordinator asks, merged into the coordinator-token group.
pub fn custody_routes() -> Router<AppState> {
    Router::new()
        .route("/wallet/contract/key", post(key_handler))
        .route("/wallet/contract/prepare", post(prepare_handler))
        .route("/wallet/contract/relay", post(relay_handler))
}

/// The owner scope a wallet contract's wallet is in, loaded: the scope, and
/// the owner's account.
///
/// A wallet contract is for a wallet with an owner. The owner's master is the
/// one the owner can leave with, and the TEE's key under it is the key the
/// owner then holds.
async fn owner_scope(
    state: &AppState,
    headers: &HeaderMap,
    wallet_id: &str,
) -> Result<(Customer, AccountId), ApiError> {
    if !state.is_ready() {
        return Err(ApiError::Unauthorized("Keystore not ready.".to_string()));
    }
    validate_wallet_id(wallet_id)?;
    let Some(customer @ Customer::Owner { .. }) = extract_customer_from_header(headers)? else {
        return Err(ApiError::BadRequest(
            "On-chain custody is for a wallet with an owner: register the owner's exit first"
                .to_string(),
        ));
    };
    let owner = state
        .ensure_customer_loaded(Some(&customer))
        .await
        .map_err(ApiError::from_customer_load)?
        .ok_or_else(|| ApiError::InternalError("an owner scope has no owner".to_string()))?;
    Ok((customer, owner))
}

/// The TEE's key of the wallet contract of `wallet_id`, in the owner scope
/// `customer` that [`owner_scope`] loaded.
async fn tee_key(
    state: &AppState,
    customer: &Customer,
    wallet_id: &str,
) -> Result<ed25519_dalek::SigningKey, ApiError> {
    let (key, _) = state
        .keystore
        .read()
        .await
        .derive_keypair(Some(customer), &tee_key_seed(wallet_id))
        .map_err(|e| ApiError::InternalError(format!("Failed to derive the TEE key: {e}")))?;
    Ok(key)
}

/// The public half of [`tee_key`]: the second key of the wallet contract's
/// pair.
async fn tee_public_key(
    state: &AppState,
    customer: &Customer,
    wallet_id: &str,
) -> Result<ed25519_dalek::VerifyingKey, ApiError> {
    state
        .keystore
        .read()
        .await
        .get_public_key_for_seed(Some(customer), &tee_key_seed(wallet_id))
        .map_err(|e| ApiError::InternalError(format!("Failed to derive the TEE key: {e}")))
}

/// `mainnet` or `testnet`, by the contract this keystore serves.
fn chain_id(state: &AppState) -> Result<&'static str, ApiError> {
    let contract = near_client(state)?.contract_id().as_str();
    if contract.ends_with(".near") {
        Ok("mainnet")
    } else if contract.ends_with(".testnet") {
        Ok("testnet")
    } else {
        Err(ApiError::InternalError(format!(
            "the chain of `{contract}` is not known, so no request can be built for it"
        )))
    }
}

fn near_client(state: &AppState) -> Result<&crate::near::NearClient, ApiError> {
    state
        .near_client
        .as_deref()
        .ok_or_else(|| ApiError::InternalError("NEAR client not configured".to_string()))
}

/// Read `account` from the chain and admit it as the wallet contract whose
/// TEE key is `tee`. Every request about a wallet contract passes here first.
///
/// The account's code and the three views of it are read at one final
/// block, so what is admitted is one state of the account: the pair, the
/// extensions and the signature switch are answers of the code whose hash
/// was checked.
async fn load_admitted(
    state: &AppState,
    account: &str,
    tee: &ed25519_dalek::VerifyingKey,
) -> Result<(AccountId, Admitted), ApiError> {
    use near_primitives::types::{BlockId, BlockReference};

    let account: AccountId = account
        .parse()
        .map_err(|_| ApiError::BadRequest(format!("`{account}` is not a NEAR account id")))?;
    let near = near_client(state)?;
    let unread =
        |e: anyhow::Error| ApiError::InternalError(format!("Failed to read the wallet contract: {e:#}"));

    let (code_hash, block) = near.view_account_code_hash_at_final(&account).await.map_err(unread)?;
    let code_hash = code_hash
        .and_then(|b58| shared_tee_helpers::code_hash::parse_code_hash_base58(&b58))
        .ok_or_else(|| not_admitted(format!("`{account}` runs no contract, so it is not a wallet contract")))?;
    // An account that runs anything but an approved build is refused before
    // any of its methods is called.
    if !approved_builds(state, near).await?.contains(&code_hash) {
        return Err(not_admitted(format!("`{account}`: {}", Fault::CodeHash)));
    }

    let at = BlockReference::BlockId(BlockId::Hash(block));
    let view = |method: &'static str| near.view_call_json_at(&account, method, serde_json::json!({}), at.clone());
    fn shaped<T: serde::de::DeserializeOwned>(method: &str, answer: crate::near::ViewAt) -> Result<T, ApiError> {
        serde_json::from_value(answer.value).map_err(|_| {
            ApiError::InternalError(format!("the wallet contract's `{method}` answered in another shape"))
        })
    }
    let observed = Observed {
        code_hash,
        public_key: shaped("w_public_key", view("w_public_key").await.map_err(unread)?)?,
        extensions: shaped("w_extensions", view("w_extensions").await.map_err(unread)?)?,
        signature_allowed: shaped(
            "w_is_signature_allowed",
            view("w_is_signature_allowed").await.map_err(unread)?,
        )?,
    };

    let admitted = admit(&code_hash, tee.as_bytes(), &observed)
        .map_err(|fault| not_admitted(format!("`{account}`: {fault}")))?;
    Ok((account, admitted))
}

/// The account is not served as this wallet's wallet contract.
fn not_admitted(message: String) -> ApiError {
    ApiError::Refused { code: refusal::WALLET_CONTRACT_REFUSED, message }
}

/// The builds this keystore signs for: the keystore DAO's list, read on
/// every request, so a build the DAO took off it is refused from the next
/// one.
async fn approved_builds(state: &AppState, near: &crate::near::NearClient) -> Result<Vec<[u8; 32]>, ApiError> {
    let dao = &state
        .mpc_context
        .get()
        .ok_or_else(|| ApiError::InternalError("MPC CKD context not configured".to_string()))?
        .mpc_ckd_config
        .keystore_dao_id;
    let listed: Vec<String> = serde_json::from_value(
        near.view_call_json(dao, "get_approved_wallet_contracts", serde_json::json!({})).await.map_err(|e| {
            ApiError::Unavailable(format!("the approved wallet contracts could not be read from {dao}: {e:#}"))
        })?,
    )
    .map_err(|_| {
        ApiError::InternalError(format!("`get_approved_wallet_contracts` on {dao} answered in another shape"))
    })?;
    Ok(listed.iter().filter_map(|b58| shared_tee_helpers::code_hash::parse_code_hash_base58(b58)).collect())
}

// ---------------------------------------------------------------------------
// key
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyRequest {
    wallet_id: String,
}

#[derive(Debug, Serialize)]
struct KeyResponse {
    /// The TEE's public key of this wallet's wallet contract, in hex: the
    /// second half of the pair the contract is initialised with.
    tee_public_key: String,
}

async fn key_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<KeyRequest>,
) -> Result<Json<KeyResponse>, ApiError> {
    let (customer, _) = owner_scope(&state, &headers, &req.wallet_id).await?;
    let public_key = tee_public_key(&state, &customer, &req.wallet_id).await?;
    Ok(Json(KeyResponse { tee_public_key: hex::encode(public_key.as_bytes()) }))
}

// ---------------------------------------------------------------------------
// prepare
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrepareRequest {
    wallet_id: String,
    /// The account of the wallet contract.
    wallet_contract: String,
    /// The agent's request, as it arrived.
    agent_request: SignedAgentRequest,
    /// The nonce of the wallet contract's request: the coordinator's counter
    /// for this wallet contract.
    nonce: u32,
    /// The 1Click deposit address of the quote made for a swap or a
    /// cross-chain withdrawal.
    #[serde(default)]
    deposit_address: Option<String>,
    /// What the wallet has spent, in the coordinator's `current_usage` shape.
    #[serde(default)]
    usage: Option<serde_json::Value>,
    #[serde(default)]
    approval_info: Option<ApprovalInfo>,
}

/// The body of the agent's request for an operation.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationBody {
    /// The agent's own id of the operation; the coordinator's to use.
    #[allow(dead_code)]
    id: String,
    op: Op,
}

#[derive(Debug, Serialize)]
struct PrepareResponse {
    /// The hash of the operation that was judged.
    request_hash: String,
    /// The wallet contract's request for it.
    message: RequestMessage,
    /// The request's canonical hash, in hex: what the two halves are over.
    message_hash: String,
    /// The TEE's half, in hex.
    tee_half: String,
}

/// One linear path: the wallet contract is admitted, the request is the
/// agent's, the operation is read from the signed bytes, the owner's policy
/// allows it, and only then a request is built and the TEE's half made.
async fn prepare_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<PrepareRequest>,
) -> Result<Json<PrepareResponse>, ApiError> {
    let (customer, owner) = owner_scope(&state, &headers, &req.wallet_id).await?;
    let tee = tee_key(&state, &customer, &req.wallet_id).await?;
    let (wallet_contract, admitted) =
        load_admitted(&state, &req.wallet_contract, &tee.verifying_key()).await?;
    let now_ns = crate::types::now_ns()
        .map_err(|e| ApiError::InternalError(format!("the clock cannot be read: {e}")))?;

    // The request is the agent's: signed by the key in the contract's pair,
    // for this wallet contract, to the operation route, now.
    let signed = &req.agent_request;
    if signed.method != OPERATION_METHOD || signed.path != OPERATION_PATH {
        return Err(ApiError::BadRequest(format!(
            "an operation is asked for by {OPERATION_METHOD} {OPERATION_PATH}"
        )));
    }
    let agent_request = signed
        .verified(wallet_contract.as_str(), &admitted.pair.agent, now_ns / 1_000_000_000)
        .map_err(|why| match why {
            NotSigned::Field(_) => ApiError::BadRequest(why.to_string()),
            NotSigned::Signature => ApiError::Refused { code: refusal::INVALID_SIGNATURE, message: why.to_string() },
        })?;

    // The operation judged is the one in the bytes the agent signed.
    let OperationBody { op, .. } = serde_json::from_slice(agent_request.body)
        .map_err(|e| ApiError::BadRequest(format!("the request's body is not an operation: {e}")))?;
    let request_hash = wallet_policy::request_hash(&op);

    // The owner's policy, stored by the owner's account. No policy, no signature.
    let Some((policy, stored_by)) =
        load_wallet_policy_with_owner(&state, &req.wallet_id, Some(&customer)).await?
    else {
        return Err(ApiError::Forbidden(
            "This wallet has no policy on chain. A wallet contract's operations are signed only \
             under a policy its owner stored"
                .to_string(),
        ));
    };
    if stored_by.as_deref() != Some(owner.as_str()) {
        return Err(ApiError::Forbidden(format!(
            "This wallet's policy was not stored by its owner `{owner}`, so nothing is signed under it"
        )));
    }
    let usage = req.usage.as_ref().map(wallet_policy::Usage::from_current_usage);
    match wallet_policy::evaluate(&policy, &op, usage.as_ref(), now_ns / 1_000_000_000) {
        Decision::Frozen => {
            return Err(ApiError::Refused { code: refusal::WALLET_FROZEN, message: "Wallet is frozen".to_string() })
        }
        Decision::Deny { reason } => return Err(ApiError::Forbidden(reason)),
        Decision::RequiresApproval { threshold } => {
            let wallet_pubkey =
                derive_wallet_ed25519_pubkey(&state, Some(&customer), &req.wallet_id).await?;
            verify_approvals(
                &state,
                &policy,
                &wallet_pubkey,
                &request_hash,
                req.approval_info.as_ref(),
                threshold.max(1) as usize,
            )
            .await?;
        }
        Decision::Allow => {}
    }

    // The policy passed: the move, the request for it, the TEE's half.
    let mv = move_for(&op, req.deposit_address.as_deref())
        .map_err(|refusal| ApiError::BadRequest(refusal.to_string()))?;
    // The contract that holds the policies takes its caller for the account
    // that acts: a wallet contract installed on the owner's own account would
    // store, replace or delete a policy as the owner.
    if matches!(&mv, Move::Call { to, .. } if to == near_client(&state)?.contract_id().as_str()) {
        return Err(ApiError::BadRequest(
            "A wallet contract does not make this call: it is to the OutLayer contract, which takes \
             its caller for the owner"
                .to_string(),
        ));
    }
    let chain_id = chain_id(&state)?;
    if chain_id != "mainnet" && matches!(mv, Move::IntentsTransfer { .. } | Move::IntentsWithdraw { .. }) {
        return Err(ApiError::BadRequest("NEAR Intents is on mainnet only".to_string()));
    }
    let message = build(
        &mv,
        &Context {
            chain_id: chain_id.to_string(),
            wallet_contract: wallet_contract.to_string(),
            intents_contract: INTENTS_CONTRACT.to_string(),
            nonce: req.nonce,
            created_at_ns: now_ns.saturating_sub(CREATED_AT_LAG_NS),
        },
    )
    .map_err(|refusal| ApiError::BadRequest(refusal.to_string()))?;
    let tee_half = sign_half(Role::Tee, &tee, &message);

    Ok(Json(PrepareResponse {
        request_hash,
        message_hash: hex::encode(message.hash()),
        tee_half: hex::encode(tee_half),
        message,
    }))
}

// ---------------------------------------------------------------------------
// relay
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayRequest {
    wallet_id: String,
    wallet_contract: String,
    /// The request `prepare` returned.
    message: RequestMessage,
    /// `agent ‖ tee`, 256 characters of lowercase hex.
    proof: String,
}

/// What the relaying transaction does: one call of `w_execute_signed` with
/// the request and both halves, and no deposit.
fn relay_actions(message: &RequestMessage, proof: &str) -> Vec<near_primitives::transaction::Action> {
    use near_primitives::transaction::{Action, FunctionCallAction};
    use near_primitives::types::{Balance, Gas};

    vec![Action::FunctionCall(Box::new(FunctionCallAction {
        method_name: "w_execute_signed".to_string(),
        args: message.execute_signed_args(proof),
        gas: Gas::from_gas(RELAY_GAS),
        deposit: Balance::from_yoctonear(0),
    }))]
}

/// The wallet's own NEAR account pays the gas of a request that the wallet
/// contract will accept: one call of `w_execute_signed` on the admitted
/// account, with both halves valid for the message. The transaction comes
/// back signed; the coordinator sends it.
async fn relay_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RelayRequest>,
) -> Result<Json<WalletSignResponse>, ApiError> {
    let (customer, _) = owner_scope(&state, &headers, &req.wallet_id).await?;
    let tee = tee_public_key(&state, &customer, &req.wallet_id).await?;
    let (wallet_contract, admitted) = load_admitted(&state, &req.wallet_contract, &tee).await?;

    if req.message.signer_id != wallet_contract.as_str() || req.message.chain_id != chain_id(&state)? {
        return Err(ApiError::BadRequest(
            "the request is for another wallet contract or another chain".to_string(),
        ));
    }
    // A request past the wallet contract's timeout is refused there: the
    // working account pays for no transaction that can only fail.
    let now_ns = crate::types::now_ns()
        .map_err(|e| ApiError::InternalError(format!("the clock cannot be read: {e}")))?;
    let expires_ns = req.message.created_at_ns.saturating_add(u64::from(TIMEOUT_SECS) * 1_000_000_000);
    if now_ns >= expires_ns {
        return Err(ApiError::BadRequest(
            "the request is past the time the wallet contract accepts it for".to_string(),
        ));
    }
    if !admitted.pair.verify(&req.message, &req.proof) {
        return Err(ApiError::Refused {
            code: refusal::INVALID_SIGNATURE,
            message: "The proof is not the agent's and the TEE's signatures over this request".to_string(),
        });
    }

    let actions = relay_actions(&req.message, &req.proof);
    let response = sign_near_transaction(
        &state,
        Some(&customer),
        &req.wallet_id,
        hex::encode(req.message.hash()),
        move |_| Ok((wallet_contract, actions)),
    )
    .await?;
    Ok(Json(response))
}

// ---------------------------------------------------------------------------
// identity
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityRequest {
    wallet_id: String,
    /// The account a program is asked to run as.
    wallet_contract: String,
    /// The NEAR account that called: the wallet's own.
    caller: String,
}

#[derive(Debug, Serialize)]
struct IdentityResponse {
    /// The account the program may run as.
    account_id: String,
}

/// A program runs as an account only when its caller is the wallet that
/// account is the wallet contract of: the caller is the NEAR account of
/// `wallet_id`, and the account is admitted with that wallet's TEE key in its
/// pair. The wallet's id and its scope are the coordinator's word; a wrong
/// one derives another account or another key, and is refused here.
async fn identity_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<IdentityRequest>,
) -> Result<Json<IdentityResponse>, ApiError> {
    let (customer, _) = owner_scope(&state, &headers, &req.wallet_id).await?;
    let near_key = state
        .keystore
        .read()
        .await
        .get_public_key_for_seed(Some(&customer), &wallet_seed(&req.wallet_id, "near"))
        .map_err(|e| ApiError::InternalError(format!("Failed to derive the wallet's key: {e}")))?;
    if hex::encode(near_key.as_bytes()) != req.caller {
        return Err(ApiError::Forbidden(format!(
            "`{}` is not the account of the wallet it is said to be",
            req.caller
        )));
    }
    let tee = tee_public_key(&state, &customer, &req.wallet_id).await?;
    let (wallet_contract, _) = load_admitted(&state, &req.wallet_contract, &tee).await?;
    Ok(Json(IdentityResponse { account_id: wallet_contract.to_string() }))
}

#[cfg(test)]
#[path = "custody_tests.rs"]
mod tests;
