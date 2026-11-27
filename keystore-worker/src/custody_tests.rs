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
    assert_eq!(source.matches(" tee_key(&state").count(), 1);
    assert_eq!(source.matches("sign_half(").count(), 1);
    assert_eq!(source.matches(".derive_keypair(").count(), 1);

    let prepare = body_of(source, "async fn prepare_handler(");
    assert!(prepare.contains("tee_key(&state") && prepare.contains("sign_half(Role::Tee, &tee, &message)"));
    assert!(body_of(source, "async fn tee_key(").contains(".derive_keypair(Some(customer), &tee_key_seed(wallet_id))"));
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

/// The handlers against a chain that answers what a scenario says: the
/// owner's record in the DAO, the wallet contract's account and views, and
/// the wallet's policy.
mod at_the_door {
    use std::sync::{Arc, Mutex};

    use ed25519_dalek::SigningKey;
    use serde_json::json;
    use shared_tee_helpers::custody_core::{
        agent_request::{AgentRequest, SignedAgentRequest},
        halves::{proof, sign_half, verify_half, PublicKeyPair, Role},
        refusal,
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
        /// The builds the keystore DAO approved, as it lists them.
        approved: Vec<String>,
        /// The DAO's list cannot be read: the node answers that view with an error.
        approved_unreadable: bool,
        public_key: String,
        extensions: Vec<String>,
        signature_allowed: bool,
        /// `(stored by, frozen, the policy)`; `None` is no policy on chain.
        policy: Option<(String, bool, serde_json::Value)>,
        /// The wallet contract's views that were asked for, each with the
        /// block it was asked at.
        views_asked: Vec<(String, serde_json::Value)>,
    }

    /// The final block the chain answers `view_account` from.
    const BLOCK: [u8; 32] = [0xb1; 32];

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
            approved: vec![bs58::encode(CODE_HASH).into_string()],
            approved_unreadable: false,
            public_key: pair.to_string(),
            extensions: Vec::new(),
            signature_allowed: true,
            policy: Some((OWNER.to_string(), false, json!({}))),
            views_asked: Vec::new(),
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
                let answers = answers.clone();
                let encrypt = encrypt.clone();
                async move {
                    let (id, params) = (body["id"].clone(), body["params"].clone());
                    if body["method"] == "block" {
                        // a final block of testnet, without its chunks
                        let block: serde_json::Value = serde_json::from_str(include_str!("fixtures/final_block.json")).unwrap();
                        return Json(json!({"jsonrpc": "2.0", "id": id, "result": block}));
                    }
                    if params["request_type"] == "view_account" {
                        return Json(json!({"jsonrpc": "2.0", "id": id, "result": {
                            "code_hash": "11111111111111111111111111111111",
                            "global_contract_hash": bs58::encode(chain.code_hash).into_string(),
                            "block_hash": bs58::encode(BLOCK).into_string(), "block_height": 9}}));
                    }
                    if params["request_type"] == "view_access_key" {
                        // the working account's key, for the relaying transaction
                        return Json(json!({"jsonrpc": "2.0", "id": id, "result": {
                            "nonce": 41, "permission": "FullAccess",
                            "block_hash": bs58::encode(BLOCK).into_string(), "block_height": 9}}));
                    }
                    let method = params["method_name"].as_str().unwrap_or_default();
                    if method.starts_with("w_") {
                        answers.lock().unwrap().views_asked.push((method.to_string(), params["block_id"].clone()));
                    }
                    if method == "get_approved_wallet_contracts" && chain.approved_unreadable {
                        return Json(json!({"jsonrpc": "2.0", "id": id, "error": {
                            "name": "HANDLER_ERROR", "cause": {"name": "UNKNOWN_ACCOUNT"},
                            "code": -32000, "message": "Server error", "data": "the account does not exist"}}));
                    }
                    let view = match method {
                        "get_exit_owner" => json!({
                            "generation": 1, "claim_in_flight": false,
                            "escrow_check": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, ESCROW_CHECK)}),
                        "get_approved_wallet_contracts" => json!(chain.approved),
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
            Err(ApiError::Refused { message, .. }) => message,
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
            // the DAO took the build off its list, or never approved one
            (Chain { approved: Vec::new(), ..honest.clone() }, "published build"),
            (Chain { approved: vec![bs58::encode([7u8; 32]).into_string()], ..honest.clone() }, "published build"),
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
            assert!(
                matches!(identity, Err(ApiError::Refused { code: refusal::WALLET_CONTRACT_REFUSED, .. })),
                "{why}"
            );
        }
    }

    /// The DAO's list that cannot be read is not an empty list: nothing is refused
    /// as unapproved and nothing is signed; the caller is told to come again.
    #[tokio::test]
    async fn an_unreadable_list_of_builds_is_unavailable_not_a_refusal() {
        let stand = stand().await;
        stand.chain.lock().unwrap().approved_unreadable = true;
        match prepare(&stand, prepare_request(&stand.agent, TRANSFER, now())).await {
            Err(ApiError::Unavailable(why)) => assert!(why.contains("approved wallet contracts"), "{why}"),
            Err(other) => panic!("answered as {other:?}"),
            Ok(_) => panic!("a request was prepared with the list unread"),
        }
    }

    /// An account stays on the build it was installed with, so the DAO lists a
    /// later build beside it and both are served.
    #[tokio::test]
    async fn a_build_is_served_while_it_is_one_of_the_approved() {
        let stand = stand().await;
        stand.chain.lock().unwrap().approved =
            vec![bs58::encode([7u8; 32]).into_string(), bs58::encode(CODE_HASH).into_string()];
        prepare(&stand, prepare_request(&stand.agent, TRANSFER, now())).await.expect("one of the approved builds");
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
            (
                r#"{"id":"x","op":{"kind":"call","to":"outlayer.testnet","method":"store_wallet_policy","args_base64":"e30=","gas":"30000000000000","deposit":"0"}}"#,
                "to the OutLayer contract",
            ),
            (
                r#"{"id":"x","op":{"kind":"call","to":"outlayer.testnet","method":"delete_wallet_policy","args_base64":"e30=","gas":"30000000000000","deposit":"0"}}"#,
                "to the OutLayer contract",
            ),
            (r#"{"id":"x","op":{"kind":"transfer","to":"bob.testnet","amount":"1"},"extra":1}"#, "not an operation"),
            // the wallet contract's own operations: an extension, the signature mode
            (r#"{"id":"x","op":{"kind":"add_extension","account_id":"bob.testnet"}}"#, "not an operation"),
            (r#"{"id":"x","op":{"kind":"remove_extension","account_id":"bob.testnet"}}"#, "not an operation"),
            (r#"{"id":"x","op":{"kind":"set_signature_mode","enable":false}}"#, "not an operation"),
            (r#"{"id":"x","op":{"internal":[{"op":"add_extension","account_id":"bob.testnet"}]}}"#, "not an operation"),
        ] {
            let reason = refusal(prepare(&stand, prepare_request(&stand.agent, body, now())).await);
            assert!(reason.contains(why), "{why}: {reason}");
        }
    }

    /// `prepare` takes an operation, never a request to sign: a body that
    /// carries a request, a proof or a half of its own is not a `prepare`
    /// request at all.
    #[test]
    fn prepare_takes_no_request_from_its_caller() {
        let stand_free = |extra: serde_json::Value| {
            let mut req = json!({
                "wallet_id": WALLET, "wallet_contract": CONTRACT, "nonce": 3,
                "agent_request": { "method": OPERATION_METHOD, "path": OPERATION_PATH, "body": TRANSFER,
                    "timestamp": 1, "nonce": hex::encode([7u8; 16]), "signature": hex::encode([0u8; 64]) },
            });
            req.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
            serde_json::from_value::<PrepareRequest>(req)
        };
        assert!(stand_free(json!({})).is_ok());
        for extra in [
            json!({ "message": { "chain_id": "testnet" } }),
            json!({ "message_hash": "00" }),
            json!({ "proof": "00" }),
            json!({ "tee_half": "00" }),
        ] {
            assert!(stand_free(extra.clone()).is_err(), "{extra}");
        }
    }

    /// What is admitted is one state of the account: the three views are
    /// asked at the block the account's code was read at.
    #[tokio::test]
    async fn the_wallet_contract_is_read_at_one_block() {
        let stand = stand().await;
        prepare(&stand, prepare_request(&stand.agent, TRANSFER, now())).await.unwrap();

        let asked = stand.chain.lock().unwrap().views_asked.clone();
        let block = json!(bs58::encode(BLOCK).into_string());
        assert_eq!(
            asked,
            [
                ("w_public_key".to_string(), block.clone()),
                ("w_extensions".to_string(), block.clone()),
                ("w_is_signature_allowed".to_string(), block),
            ]
        );
    }

    /// An account that runs another build is refused before any of its
    /// methods is called.
    #[tokio::test]
    async fn no_method_of_an_unapproved_build_is_called() {
        let stand = stand().await;
        stand.chain.lock().unwrap().code_hash = [0; 32];
        refusal(prepare(&stand, prepare_request(&stand.agent, TRANSFER, now())).await);
        assert!(stand.chain.lock().unwrap().views_asked.is_empty());
    }

    /// `prepare` is one path in one order: with two things wrong, the earlier
    /// gate is the one that refuses. The wallet contract is admitted, then the
    /// request is shown to be the agent's, then the owner's policy is read
    /// and judged, and only then is the operation turned into a move.
    #[tokio::test]
    async fn the_earlier_gate_refuses() {
        let stand = stand().await;
        let honest = stand.chain.lock().unwrap().clone();
        let other = SigningKey::from_bytes(&[0xb2; 32]);
        let to_itself = r#"{"id":"x","op":{"kind":"transfer","to":"trader.alice.testnet","amount":"1"}}"#;

        // not admitted, and not the agent's
        *stand.chain.lock().unwrap() = Chain { extensions: vec![OWNER.to_string()], ..honest.clone() };
        let reason = refusal(prepare(&stand, prepare_request(&other, TRANSFER, now())).await);
        assert!(reason.contains("extension"), "{reason}");

        // not the agent's, and no policy
        *stand.chain.lock().unwrap() = Chain { policy: None, ..honest.clone() };
        let reason = refusal(prepare(&stand, prepare_request(&other, TRANSFER, now())).await);
        assert!(reason.contains("not signed by the agent"), "{reason}");

        // not the agent's, and a body that is no operation: nothing is read
        // from bytes the agent did not sign
        let reason = refusal(prepare(&stand, prepare_request(&other, r#"{"nonsense":1}"#, now())).await);
        assert!(reason.contains("not signed by the agent"), "{reason}");

        // no policy, and an operation a wallet contract does not do
        let reason = refusal(prepare(&stand, prepare_request(&stand.agent, to_itself, now())).await);
        assert!(reason.contains("no policy on chain"), "{reason}");

        // a frozen wallet, and an operation a wallet contract does not do
        *stand.chain.lock().unwrap() = Chain { policy: Some((OWNER.to_string(), true, json!({}))), ..honest };
        let reason = refusal(prepare(&stand, prepare_request(&stand.agent, to_itself, now())).await);
        assert!(reason.contains("frozen"), "{reason}");
    }

    /// The handed-on request is read strictly: bytes in another spelling are
    /// refused as malformed before any signature is checked.
    #[tokio::test]
    async fn the_signed_request_has_one_spelling() {
        let stand = stand().await;
        let honest = prepare_request(&stand.agent, TRANSFER, now());
        for (nonce, signature) in [
            (honest.agent_request.nonce.replace('7', "A"), honest.agent_request.signature.clone()),
            (honest.agent_request.nonce.clone(), honest.agent_request.signature.to_uppercase()),
            (honest.agent_request.nonce.clone(), format!("0x{}", &honest.agent_request.signature[2..])),
        ] {
            let mut req = prepare_request(&stand.agent, TRANSFER, now());
            req.agent_request = SignedAgentRequest { nonce, signature, ..req.agent_request };
            let refused = prepare(&stand, req).await;
            assert!(
                matches!(&refused, Err(ApiError::BadRequest(reason)) if reason.contains("lowercase hex")),
                "{refused:?}"
            );
        }
    }

    /// The relaying transaction is one call of `w_execute_signed` with the
    /// request and its proof, and it carries no deposit.
    #[tokio::test]
    async fn the_relaying_transaction_is_one_call_with_no_deposit() {
        use near_primitives::transaction::Action;

        let stand = stand().await;
        let prepared = prepare(&stand, prepare_request(&stand.agent, TRANSFER, now())).await.unwrap();
        let tee_half: [u8; 64] = hex::decode(&prepared.tee_half).unwrap().try_into().unwrap();
        let proof = proof(&sign_half(Role::Agent, &stand.agent, &prepared.message), &tee_half);

        let actions = relay_actions(&prepared.message, &proof);
        let [Action::FunctionCall(call)] = actions.as_slice() else {
            panic!("not one call: {actions:?}");
        };
        assert_eq!(call.method_name, "w_execute_signed");
        assert_eq!(call.deposit, near_primitives::types::Balance::from_yoctonear(0));
        assert_eq!(call.gas, near_primitives::types::Gas::from_gas(RELAY_GAS));
        assert_eq!(call.args, prepared.message.execute_signed_args(&proof));
    }

    /// A refusal that is not the policy's says which it is, so the API in
    /// front answers a freeze as a freeze and a bad signature as one; a
    /// denial by the policy carries no code.
    #[tokio::test]
    async fn a_refusal_that_is_not_the_policys_names_itself() {
        let stand = stand().await;
        let honest = stand.chain.lock().unwrap().clone();
        let code = |result: Result<PrepareResponse, ApiError>| match result {
            Err(ApiError::Refused { code, .. }) => Some(code),
            Err(ApiError::Forbidden(_)) => None,
            other => panic!("not a refusal: {:?}", other.map(|r| r.request_hash)),
        };

        let other = SigningKey::from_bytes(&[0xb2; 32]);
        assert_eq!(code(prepare(&stand, prepare_request(&other, TRANSFER, now())).await), Some(refusal::INVALID_SIGNATURE));

        *stand.chain.lock().unwrap() = Chain { policy: Some((OWNER.to_string(), true, json!({}))), ..honest.clone() };
        assert_eq!(code(prepare(&stand, prepare_request(&stand.agent, TRANSFER, now())).await), Some(refusal::WALLET_FROZEN));

        *stand.chain.lock().unwrap() = Chain { extensions: vec![OWNER.to_string()], ..honest.clone() };
        assert_eq!(
            code(prepare(&stand, prepare_request(&stand.agent, TRANSFER, now())).await),
            Some(refusal::WALLET_CONTRACT_REFUSED)
        );

        *stand.chain.lock().unwrap() = Chain { policy: None, ..honest };
        assert_eq!(code(prepare(&stand, prepare_request(&stand.agent, TRANSFER, now())).await), None);
    }

    /// In an owner's scope a policy is the owner's to store. One that another
    /// account stored earlier stays that account's to change, and nobody
    /// else's: the contract takes a change from the account that stored it.
    #[tokio::test]
    async fn a_policy_is_the_owners_to_store_and_its_first_authors_to_change() {
        let stand = stand().await;
        let customer = Customer::Owner { account: OWNER.parse().unwrap(), generation: 1 };
        let may = |caller: &'static str| {
            let state = stand.state.clone();
            let customer = customer.clone();
            async move { crate::api::policy_is_the_callers_to_store(&state, Some(&customer), WALLET, caller).await }
        };

        // stored by the owner, or not stored yet: the owner alone
        assert!(may(OWNER).await.is_ok());
        assert!(matches!(may("mallory.testnet").await, Err(ApiError::Forbidden(reason)) if reason.contains(OWNER)));
        stand.chain.lock().unwrap().policy = None;
        assert!(may(OWNER).await.is_ok());
        assert!(matches!(may("mallory.testnet").await, Err(ApiError::Forbidden(_))));

        // stored by another account earlier: that account still changes it, and no third one
        stand.chain.lock().unwrap().policy = Some(("carol.testnet".to_string(), false, json!({})));
        assert!(may("carol.testnet").await.is_ok());
        assert!(may(OWNER).await.is_ok());
        assert!(matches!(may("mallory.testnet").await, Err(ApiError::Forbidden(_))));

        // a wallet outside an owner's scope: the rule is the contract's alone
        assert!(crate::api::policy_is_the_callers_to_store(&stand.state, None, WALLET, "anyone.testnet").await.is_ok());
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

        // a caller that is not the wallet is refused before the account is read
        stand.chain.lock().unwrap().views_asked.clear();
        stand.chain.lock().unwrap().code_hash = [0; 32];
        let refused = ask("f".repeat(64)).await;
        assert!(
            matches!(&refused, Err(ApiError::Forbidden(reason)) if reason.contains("not the account of the wallet")),
            "{refused:?}"
        );
    }

    /// A proven request is relayed as the working account's transaction to the
    /// wallet contract: the one call, the next nonce, and nothing else in it.
    #[tokio::test]
    async fn a_proven_request_is_signed_as_one_call_to_the_wallet_contract() {
        use near_primitives::transaction::{Action as TxAction, SignedTransaction};

        let stand = stand().await;
        let prepared = prepare(&stand, prepare_request(&stand.agent, TRANSFER, now())).await.unwrap();
        let tee_half: [u8; 64] = hex::decode(&prepared.tee_half).unwrap().try_into().unwrap();
        let whole = proof(&sign_half(Role::Agent, &stand.agent, &prepared.message), &tee_half);
        let Json(signed) = relay_handler(
            State(stand.state.clone()),
            scope(Some(SCOPE)),
            Json(RelayRequest {
                wallet_id: WALLET.to_string(),
                wallet_contract: CONTRACT.to_string(),
                message: prepared.message.clone(),
                proof: whole.clone(),
            }),
        )
        .await
        .expect("a proven request");

        let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, signed.signed_tx_base64.as_deref().expect("a signed transaction")).unwrap();
        let tx: SignedTransaction = borsh::from_slice(&bytes).unwrap();
        assert_eq!(tx.transaction.receiver_id().as_str(), CONTRACT);
        assert_eq!(tx.transaction.signer_id().as_str(), wallet_account(&stand).await);
        assert_eq!(
            tx.transaction.nonce(),
            near_primitives::transaction::TransactionNonce::Nonce { nonce: 42 },
            "the key's nonce and one"
        );
        let block: serde_json::Value = serde_json::from_str(include_str!("fixtures/final_block.json")).unwrap();
        assert_eq!(tx.transaction.block_hash().to_string(), block["header"]["hash"].as_str().unwrap());
        let [TxAction::FunctionCall(call)] = tx.transaction.actions() else {
            panic!("not one call: {:?}", tx.transaction.actions());
        };
        assert_eq!(call.method_name, "w_execute_signed");
        assert_eq!(call.args, prepared.message.execute_signed_args(&whole));
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
            assert!(matches!(
                relay(msg.clone(), unproven).await,
                Err(ApiError::Refused { code: refusal::INVALID_SIGNATURE, .. })
            ));
        }

        // the proof of one request does not relay another
        let mut another = msg.clone();
        another.promise.action = Action::Transfer { amount: 500 };
        assert!(matches!(
            relay(another, proof(&agent_half, &tee_half)).await,
            Err(ApiError::Refused { code: refusal::INVALID_SIGNATURE, .. })
        ));

        // past its time, a whole proof relays nothing
        let mut old = msg.clone();
        old.created_at_ns -= u64::from(TIMEOUT_SECS) * 1_000_000_000;
        let old_proof = proof(&sign_half(Role::Agent, &stand.agent, &old), &{
            let customer = Customer::Owner { account: OWNER.parse().unwrap(), generation: 1 };
            let (tee, _) = stand.state.keystore.read().await.derive_keypair(Some(&customer), &tee_key_seed(WALLET)).unwrap();
            sign_half(Role::Tee, &tee, &old)
        });
        assert!(matches!(relay(old, old_proof).await, Err(ApiError::BadRequest(reason)) if reason.contains("past the time")));

        let mut elsewhere = msg.clone();
        elsewhere.signer_id = "other.alice.testnet".to_string();
        assert!(matches!(relay(elsewhere, proof(&agent_half, &tee_half)).await, Err(ApiError::BadRequest(_))));
    }
}
