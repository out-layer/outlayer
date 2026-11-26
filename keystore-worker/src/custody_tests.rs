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

/// A program is let to run as an account after the caller is shown to be the
/// wallet's own account and the account is admitted for that wallet.
#[test]
fn identity_checks_the_caller_then_admits_the_account() {
    let identity = body_of(source(), "async fn identity_handler(");
    let steps = [
        "owner_scope(&state",
        r#"wallet_seed(&req.wallet_id, "near")"#,
        "hex::encode(near_key.as_bytes()) != req.caller",
        "load_admitted(&state, &req.wallet_contract, &tee)",
    ];
    let mut at = 0;
    for step in steps {
        let found = identity[at..].find(step).unwrap_or_else(|| panic!("`{step}` is missing or out of order"));
        at += found + step.len();
    }
    assert!(!identity.contains("derive_keypair"));
}

/// The handlers against a chain that answers what a scenario says: the
/// owner's record in the DAO, the wallet contract's account and views, and
/// the wallet's policy.
mod at_the_door {
    use std::sync::{Arc, Mutex};

    use ed25519_dalek::SigningKey;
    use serde_json::json;
    use shared_tee_helpers::custody_core::{
        agent_request::AgentRequest,
        halves::{proof, sign_half, verify_half, PublicKeyPair, Role},
        message::{Action, Promise},
    };

    use super::*;

    const OWNER: &str = "alice.testnet";
    const SCOPE: &str = "owner:alice.testnet:1";
    const CONTRACT: &str = "trader.alice.testnet";
    const CODE_HASH: [u8; 32] = [0xc0; 32];
    const ESCROW_CHECK: [u8; 32] = [0xe5; 32];

    /// What the chain says. Each test changes one thing.
    #[derive(Clone)]
    struct Chain {
        code_hash: [u8; 32],
        public_key: String,
        extensions: Vec<String>,
        signature_allowed: bool,
        /// `(stored by, frozen, the policy)`; `None` is no policy on chain.
        policy: Option<(String, bool, serde_json::Value)>,
    }

    struct Stand {
        state: AppState,
        chain: Arc<Mutex<Chain>>,
        agent: SigningKey,
        tee: ed25519_dalek::VerifyingKey,
    }

    fn agent_key() -> SigningKey {
        SigningKey::from_bytes(&[0xa1; 32])
    }

    async fn stand() -> Stand {
        let keystore = Keystore::from_master_secret(&[0x11; 32]).unwrap();
        let owner: AccountId = OWNER.parse().unwrap();
        keystore.load_owner(&owner, 1, ESCROW_CHECK);
        let customer = Customer::Owner { account: owner, generation: 1 };
        let tee = keystore.get_public_key_for_seed(Some(&customer), &tee_key_seed(WALLET)).unwrap();
        let pair = PublicKeyPair { agent: agent_key().verifying_key().to_bytes(), tee: tee.to_bytes() };
        let chain = Arc::new(Mutex::new(Chain {
            code_hash: CODE_HASH,
            public_key: pair.to_string(),
            extensions: Vec::new(),
            signature_allowed: true,
            policy: Some((OWNER.to_string(), false, json!({}))),
        }));

        let encrypt = {
            let keystore = keystore.clone();
            move |policy: &serde_json::Value| {
                let sealed = keystore
                    .encrypt(Some(&customer), &format!("wallet-policy:{WALLET}"), policy.to_string().as_bytes())
                    .unwrap();
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sealed)
            }
        };
        let answers = chain.clone();
        let app = Router::new().route(
            "/",
            post(move |Json(body): Json<serde_json::Value>| {
                let chain = answers.lock().unwrap().clone();
                let encrypt = encrypt.clone();
                async move {
                    let (id, params) = (body["id"].clone(), body["params"].clone());
                    if params["request_type"] == "view_account" {
                        return Json(json!({"jsonrpc": "2.0", "id": id, "result": {
                            "code_hash": "11111111111111111111111111111111",
                            "global_contract_hash": bs58::encode(chain.code_hash).into_string()}}));
                    }
                    let view = match params["method_name"].as_str().unwrap_or_default() {
                        "get_exit_owner" => json!({
                            "generation": 1, "claim_in_flight": false,
                            "escrow_check": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, ESCROW_CHECK)}),
                        "w_public_key" => json!(chain.public_key),
                        "w_extensions" => json!(chain.extensions),
                        "w_is_signature_allowed" => json!(chain.signature_allowed),
                        "get_wallet_policy" => match &chain.policy {
                            None => serde_json::Value::Null,
                            Some((owner, frozen, policy)) => {
                                json!({ "owner": owner, "frozen": frozen, "encrypted_data": encrypt(policy) })
                            }
                        },
                        other => panic!("the chain is not asked for {other}: {params}"),
                    };
                    Json(json!({"jsonrpc": "2.0", "id": id, "result": {
                        "block_hash": "11111111111111111111111111111111", "block_height": 9, "logs": [],
                        "result": view.to_string().into_bytes()}}))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let config = crate::config::Config {
            near_rpc_url: url.clone().into(),
            wallet_contract_code_hash: Some(CODE_HASH),
            ..state().config
        };
        let near_client = crate::near::NearClient::new(&url, "outlayer.testnet").unwrap();
        let state = AppState::new(keystore, config, Some(near_client));
        let secret_key = near_crypto::SecretKey::from_random(near_crypto::KeyType::ED25519);
        state.set_mpc_context(
            crate::mpc_ckd::MpcCkdConfig {
                mpc_contract_id: "v1.signer.test".parse().unwrap(),
                mpc_domain_id: 2,
                mpc_public_key: "unused".into(),
                near_rpc_url: url,
                keystore_dao_id: "dao.test".parse().unwrap(),
            },
            near_crypto::InMemorySigner { account_id: "dao.test".parse().unwrap(), public_key: secret_key.public_key(), secret_key },
        );
        Stand { state, chain, agent: agent_key(), tee }
    }

    fn now() -> u64 {
        crate::types::now_ns().unwrap() / 1_000_000_000
    }

    const TRANSFER: &str = r#"{"id":"pay-1","op":{"kind":"transfer","to":"bob.testnet","amount":"5"}}"#;

    /// The coordinator's `prepare` request for `body`, signed by `key` at `timestamp`.
    fn prepare_request(key: &SigningKey, body: &str, timestamp: u64) -> PrepareRequest {
        let nonce = [7; 16];
        let signature = AgentRequest {
            wallet_contract: CONTRACT,
            method: OPERATION_METHOD,
            path: OPERATION_PATH,
            body: body.as_bytes(),
            timestamp,
            nonce,
        }
        .sign(key);
        serde_json::from_value(json!({
            "wallet_id": WALLET,
            "wallet_contract": CONTRACT,
            "agent_request": {
                "method": OPERATION_METHOD, "path": OPERATION_PATH, "body": body,
                "timestamp": timestamp, "nonce": hex::encode(nonce), "signature": hex::encode(signature),
            },
            "nonce": 3,
        }))
        .unwrap()
    }

    async fn prepare(stand: &Stand, req: PrepareRequest) -> Result<PrepareResponse, ApiError> {
        prepare_handler(State(stand.state.clone()), scope(Some(SCOPE)), Json(req)).await.map(|Json(r)| r)
    }

    fn refusal(result: Result<PrepareResponse, ApiError>) -> String {
        match result {
            Err(ApiError::Forbidden(reason)) | Err(ApiError::BadRequest(reason)) => reason,
            Err(other) => panic!("refused for another class of reason: {other:?}"),
            Ok(_) => panic!("a request was built and the TEE's half made"),
        }
    }

    #[tokio::test]
    async fn an_allowed_operation_comes_back_as_its_request_with_the_tees_half() {
        let stand = stand().await;
        let prepared = prepare(&stand, prepare_request(&stand.agent, TRANSFER, now())).await.unwrap();

        let msg = &prepared.message;
        assert_eq!((msg.chain_id.as_str(), msg.signer_id.as_str(), msg.nonce), ("testnet", CONTRACT, 3));
        assert_eq!(
            msg.promise,
            Promise { receiver_id: "bob.testnet".to_string(), action: Action::Transfer { amount: 5 } }
        );
        assert_eq!(prepared.message_hash, hex::encode(msg.hash()));
        let created_s = msg.created_at_ns / 1_000_000_000;
        assert!((now() - 62..=now() - 59).contains(&created_s), "dated a minute back: {created_s}");

        let tee_half: [u8; 64] = hex::decode(&prepared.tee_half).unwrap().try_into().unwrap();
        assert!(verify_half(Role::Tee, stand.tee.as_bytes(), msg, &tee_half));
        // with the agent's half the wallet contract accepts it
        let pair = PublicKeyPair { agent: stand.agent.verifying_key().to_bytes(), tee: stand.tee.to_bytes() };
        assert!(pair.verify(msg, &proof(&sign_half(Role::Agent, &stand.agent, msg), &tee_half)));
    }

    #[tokio::test]
    async fn the_request_has_to_be_the_agents_for_this_route_and_now() {
        let stand = stand().await;

        let other = SigningKey::from_bytes(&[0xb2; 32]);
        assert!(refusal(prepare(&stand, prepare_request(&other, TRANSFER, now())).await).contains("not signed by the agent"));

        for timestamp in [now() - 600, now() + 600] {
            let stale = prepare_request(&stand.agent, TRANSFER, timestamp);
            assert!(refusal(prepare(&stand, stale).await).contains("not signed by the agent"));
        }

        // the body changed after it was signed: another amount is another request
        let mut tampered = prepare_request(&stand.agent, TRANSFER, now());
        tampered.agent_request.body = TRANSFER.replace(r#""amount":"5""#, r#""amount":"500""#);
        assert!(refusal(prepare(&stand, tampered).await).contains("not signed by the agent"));

        // a request signed for another route is not an operation
        let mut elsewhere = prepare_request(&stand.agent, TRANSFER, now());
        elsewhere.agent_request.path = format!("{OPERATION_PATH}/pay-1/relay");
        assert!(refusal(prepare(&stand, elsewhere).await).contains("an operation is asked for by"));
    }

    #[tokio::test]
    async fn nothing_is_signed_without_the_owners_policy_passing() {
        let stand = stand().await;
        let ask = || async { refusal(prepare(&stand, prepare_request(&stand.agent, TRANSFER, now())).await) };
        let set = |policy| stand.chain.lock().unwrap().policy = policy;

        set(None);
        assert!(ask().await.contains("no policy on chain"));

        set(Some(("mallory.testnet".to_string(), false, json!({}))));
        assert!(ask().await.contains("not stored by its owner"));

        set(Some((OWNER.to_string(), true, json!({}))));
        assert!(ask().await.contains("frozen"));

        let approvers = json!({
            "approval": { "threshold": { "required": 1 }, "approvers": [{ "id": "a.testnet", "role": "admin" }] }
        });
        set(Some((OWNER.to_string(), false, approvers)));
        assert!(ask().await.to_lowercase().contains("approval"));
    }

    #[tokio::test]
    async fn only_an_admitted_wallet_contract_is_served() {
        let stand = stand().await;
        let honest = stand.chain.lock().unwrap().clone();
        let cases = [
            (Chain { code_hash: [0; 32], ..honest.clone() }, "published build"),
            (Chain { extensions: vec![OWNER.to_string()], ..honest.clone() }, "extension"),
            (Chain { signature_allowed: false, ..honest.clone() }, "does not accept signatures"),
            (Chain { public_key: "not a pair".to_string(), ..honest.clone() }, "not a pair of keys"),
            (
                Chain {
                    public_key: PublicKeyPair {
                        agent: stand.agent.verifying_key().to_bytes(),
                        tee: SigningKey::from_bytes(&[0xee; 32]).verifying_key().to_bytes(),
                    }
                    .to_string(),
                    ..honest.clone()
                },
                "another wallet's",
            ),
        ];
        for (chain, why) in cases {
            *stand.chain.lock().unwrap() = chain;
            let reason = refusal(prepare(&stand, prepare_request(&stand.agent, TRANSFER, now())).await);
            assert!(reason.contains(why), "{why}: {reason}");

            let identity = identity_handler(
                State(stand.state.clone()),
                scope(Some(SCOPE)),
                Json(IdentityRequest {
                    wallet_id: WALLET.to_string(),
                    wallet_contract: CONTRACT.to_string(),
                    caller: wallet_account(&stand).await,
                }),
            )
            .await;
            assert!(matches!(identity, Err(ApiError::Forbidden(_))), "{why}");
        }
    }

    #[tokio::test]
    async fn an_operation_a_wallet_contract_does_not_do_is_refused_after_the_policy() {
        let stand = stand().await;
        for (body, why) in [
            (r#"{"id":"x","op":{"kind":"delete","beneficiary":"bob.testnet"}}"#, "does not do `delete`"),
            (
                r#"{"id":"x","op":{"kind":"intents_transfer","to":"bob.testnet","amount":"1","token":"nep141:wrap.near"}}"#,
                "mainnet only",
            ),
            (r#"{"id":"x","op":{"kind":"transfer","to":"trader.alice.testnet","amount":"1"}}"#, "to itself"),
            (r#"{"id":"x","op":{"kind":"transfer","to":"bob.testnet","amount":"1"},"extra":1}"#, "not an operation"),
        ] {
            let reason = refusal(prepare(&stand, prepare_request(&stand.agent, body, now())).await);
            assert!(reason.contains(why), "{why}: {reason}");
        }
    }

    async fn wallet_account(stand: &Stand) -> String {
        let customer = Customer::Owner { account: OWNER.parse().unwrap(), generation: 1 };
        let key = stand.state.keystore.read().await.get_public_key_for_seed(Some(&customer), &wallet_seed(WALLET, "near")).unwrap();
        hex::encode(key.as_bytes())
    }

    #[tokio::test]
    async fn a_program_runs_as_the_account_for_its_own_wallet_only() {
        let stand = stand().await;
        let ask = |caller: String| {
            identity_handler(
                State(stand.state.clone()),
                scope(Some(SCOPE)),
                Json(IdentityRequest { wallet_id: WALLET.to_string(), wallet_contract: CONTRACT.to_string(), caller }),
            )
        };
        let Json(served) = ask(wallet_account(&stand).await).await.unwrap();
        assert_eq!(served.account_id, CONTRACT);

        assert!(matches!(ask("f".repeat(64)).await, Err(ApiError::Forbidden(_))));
        assert!(matches!(ask(OWNER.to_string()).await, Err(ApiError::Forbidden(_))));
    }

    #[tokio::test]
    async fn relay_signs_nothing_for_a_request_that_is_not_proven() {
        let stand = stand().await;
        let prepared = prepare(&stand, prepare_request(&stand.agent, TRANSFER, now())).await.unwrap();
        let msg = prepared.message;
        let tee_half: [u8; 64] = hex::decode(&prepared.tee_half).unwrap().try_into().unwrap();
        let agent_half = sign_half(Role::Agent, &stand.agent, &msg);
        let relay = |message: RequestMessage, proof: String| {
            relay_handler(
                State(stand.state.clone()),
                scope(Some(SCOPE)),
                Json(RelayRequest {
                    wallet_id: WALLET.to_string(),
                    wallet_contract: CONTRACT.to_string(),
                    message,
                    proof,
                }),
            )
        };

        for unproven in [hex::encode(tee_half), hex::encode(agent_half), proof(&tee_half, &agent_half), proof(&tee_half, &tee_half)] {
            assert!(matches!(relay(msg.clone(), unproven).await, Err(ApiError::Forbidden(_))));
        }

        // the proof of one request does not relay another
        let mut another = msg.clone();
        another.promise.action = Action::Transfer { amount: 500 };
        assert!(matches!(relay(another, proof(&agent_half, &tee_half)).await, Err(ApiError::Forbidden(_))));

        let mut elsewhere = msg.clone();
        elsewhere.signer_id = "other.alice.testnet".to_string();
        assert!(matches!(relay(elsewhere, proof(&agent_half, &tee_half)).await, Err(ApiError::BadRequest(_))));
    }
}
