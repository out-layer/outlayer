use axum::{extract::State, http::HeaderMap, Json};
use shared_tee_helpers::custody_core::keys::{tee_key as tee_key_of_master, tee_key_seed};

use super::*;
use crate::crypto::Keystore;

const WALLET: &str = "7c9e6679-7425-40de-944b-e07fc1f90ae7";

fn state() -> AppState {
    let config = crate::config::Config {
        server_addr: "127.0.0.1:0".parse().unwrap(),
        near_network: "testnet".into(),
        near_rpc_url: "http://127.0.0.1:1".into(),
        allowed_worker_token_hashes: vec![],
        allowed_coordinator_token_hashes: vec![],
        tee_mode: crate::config::TeeMode::None,
        operator_account_id: None,
        near_contract_id: None,
        keystore_key_type: near_crypto::KeyType::ED25519,
        tee_allowed_key_types: shared_tee_helpers::AllowedKeyTypes { ed25519: true, ml_dsa_65: true },
        wallet_contract_code_hash: None,
    };
    AppState::new(Keystore::from_master_secret(&[0x11; 32]).unwrap(), config, None)
}

fn scope(value: Option<&str>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let Some(value) = value {
        headers.insert("X-Customer-Vault", value.parse().unwrap());
    }
    headers
}

/// The key the enclave signs with is the key an owner who has left derives
/// from their master with `custody_core`: the same function of the owner
/// master and the wallet's id.
#[test]
fn the_tee_key_is_the_one_the_owner_derives_after_an_exit() {
    let keystore = Keystore::from_master_secret(&[0x11; 32]).unwrap();
    let account: AccountId = "alice.near".parse().unwrap();
    let generation = 2;
    keystore.load_owner(&account, generation, [0; 32]);
    let owner = Customer::Owner { account: account.clone(), generation };

    let (in_enclave, _) = keystore.derive_keypair(Some(&owner), &tee_key_seed(WALLET)).unwrap();
    let after_exit = tee_key_of_master(&keystore.owner_master(&account, generation), WALLET);
    assert_eq!(in_enclave.to_bytes(), after_exit.to_bytes());

    // another generation of the same owner is another key
    keystore.load_owner(&account, generation + 1, [0; 32]);
    let next = Customer::Owner { account, generation: generation + 1 };
    let (rotated, _) = keystore.derive_keypair(Some(&next), &tee_key_seed(WALLET)).unwrap();
    assert_ne!(rotated.to_bytes(), in_enclave.to_bytes());
}

/// A wallet under the default master or under a vault's has no wallet
/// contract: each route refuses before anything is derived or read.
#[tokio::test]
async fn only_a_wallet_with_an_owner_is_served() {
    for value in [None, Some("vault.alice.near")] {
        let refused = key_handler(
            State(state()),
            scope(value),
            Json(KeyRequest { wallet_id: WALLET.to_string() }),
        )
        .await;
        assert!(
            matches!(&refused, Err(ApiError::BadRequest(reason)) if reason.contains("with an owner")),
            "{value:?}: {refused:?}"
        );
        assert!(matches!(owner_scope(&state(), &scope(value), WALLET).await, Err(ApiError::BadRequest(_))));
    }
}

/// An owner scope is loaded from the chain before it is served: with no way
/// to read the owner's record, nothing is derived.
#[tokio::test]
async fn an_owner_scope_that_cannot_be_loaded_is_refused() {
    let refused = owner_scope(&state(), &scope(Some("owner:alice.near:1")), WALLET).await;
    assert!(refused.is_err(), "{refused:?}");
}

fn source() -> &'static str {
    let source = include_str!("custody.rs");
    &source[..source.find("#[cfg(test)]").expect("the tests' mount")]
}

fn body_of<'a>(source: &'a str, signature: &str) -> &'a str {
    let start = source.find(signature).unwrap_or_else(|| panic!("no `{signature}`"));
    let body = &source[start..];
    &body[..body.find("\n}\n").expect("the function's end")]
}

/// The TEE's private key is derived in one function, which `prepare` alone
/// calls, and the one thing made with it is a half over the message built
/// there.
#[test]
fn the_tee_key_signs_in_prepare_only() {
    let source = source();
    assert_eq!(source.matches("tee_key(&state").count(), 1);
    assert_eq!(source.matches("sign_half(").count(), 1);
    assert_eq!(source.matches(".derive_keypair(").count(), 1);

    let prepare = body_of(source, "async fn prepare_handler(");
    assert!(prepare.contains("tee_key(&state") && prepare.contains("sign_half(Role::Tee, &tee, &message)"));
    assert!(body_of(source, "async fn tee_key(").contains(".derive_keypair(Some(customer), &tee_key_seed(wallet_id))"));
}

/// `prepare` is one path in one order: nothing is built or signed before the
/// wallet contract is admitted, the request is verified as the agent's, the
/// owner's policy has passed and the approvals are verified.
#[test]
fn prepare_judges_before_it_builds() {
    let prepare = body_of(source(), "async fn prepare_handler(");
    let steps = [
        "owner_scope(&state",
        "load_admitted(&state",
        "agent_request.verify(&admitted.pair.agent",
        "serde_json::from_slice(agent_request.body)",
        "load_wallet_policy_with_owner(&state",
        "stored_by.as_deref() != Some(owner.as_str())",
        "wallet_policy::evaluate(&policy, &op",
        "verify_approvals(",
        "move_for(&op",
        "build(",
        "sign_half(",
    ];
    let mut at = 0;
    for step in steps {
        let found = prepare[at..].find(step).unwrap_or_else(|| panic!("`{step}` is missing or out of order"));
        at += found + step.len();
    }
    // the stand-in for a wallet with no policy is not for a wallet contract
    assert!(!prepare.contains("policy_to_judge_by"));
    // the operation has one source: the signed body
    assert_eq!(prepare.matches("op:").count(), 0);
}

/// `relay` serves an admitted wallet contract, signs for a request both
/// halves are valid over, and puts one call in the transaction.
#[test]
fn relay_signs_one_call_for_a_proven_request() {
    let relay = body_of(source(), "async fn relay_handler(");
    let steps = [
        "owner_scope(&state",
        "load_admitted(&state",
        "req.message.signer_id != wallet_contract.as_str()",
        "admitted.pair.verify(&req.message, &req.proof)",
        "sign_near_transaction(",
    ];
    let mut at = 0;
    for step in steps {
        let found = relay[at..].find(step).unwrap_or_else(|| panic!("`{step}` is missing or out of order"));
        at += found + step.len();
    }
    assert_eq!(relay.matches("Action::").count(), 1);
    assert!(relay.contains(r#"method_name: "w_execute_signed".to_string()"#));
    assert!(relay.contains("deposit: Balance::from_yoctonear(0)"));
}

#[test]
fn the_chain_is_read_from_the_contract_served() {
    let with = |contract: &str| {
        let mut state = state();
        state.near_client = Some(std::sync::Arc::new(
            crate::near::NearClient::new("http://127.0.0.1:1", contract).unwrap(),
        ));
        chain_id(&state).ok()
    };
    assert_eq!(with("outlayer.near"), Some("mainnet"));
    assert_eq!(with("outlayer.testnet"), Some("testnet"));
    assert_eq!(with("outlayer.test"), None);
}

#[test]
fn the_request_bodies_take_no_field_they_do_not_name() {
    let op = r#"{"kind":"transfer","to":"bob.near","amount":"1"}"#;
    assert!(serde_json::from_str::<OperationBody>(&format!(r#"{{"id":"1","op":{op}}}"#)).is_ok());
    assert!(serde_json::from_str::<OperationBody>(&format!(r#"{{"id":"1","op":{op},"deposit_address":"x"}}"#)).is_err());
    assert!(serde_json::from_str::<OperationBody>(&format!(r#"{{"op":{op}}}"#)).is_err());
    assert!(serde_json::from_str::<KeyRequest>(r#"{"wallet_id":"w","seed":"x"}"#).is_err());
}
