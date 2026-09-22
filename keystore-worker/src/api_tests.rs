use super::*;

#[cfg(test)]
mod wallet_sign_tests {
    use super::*;
    use shared_tee_helpers::wallet_policy::{self, Op};

    // --- Domain separation: sign_message recipient is a default-DENY allowlist -----

    /// A freeze we cannot read is not an absence of one.
    ///
    /// `frozen` is the only field of the policy readable WITHOUT decryption,
    /// and it is the controller's hard stop — the one setting whose whole
    /// purpose is to halt a wallet that is doing something its owner does not
    /// want. It was read with `unwrap_or(false)`: a value we could not parse
    /// became "not frozen", which is the single worst direction to default in
    /// this file.
    ///
    /// Unreachable today — the contract types it `bool` and always serializes
    /// it — and that is exactly why it would have gone unnoticed on the day a
    /// contract upgrade changed the shape. Absent stays false, because a policy
    /// written before the field existed was never frozen; present-and-unreadable
    /// refuses.
    /// The JSON an `ApiError` actually serialises to.
    fn read_json_body(response: axum::response::Response) -> serde_json::Value {
        let bytes = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(axum::body::to_bytes(response.into_body(), 64 * 1024))
            .expect("body");
        serde_json::from_slice(&bytes).expect("json")
    }

    /// An account that does not exist yet is a fact, not an outage.
    ///
    /// A NEAR implicit account is created by its FIRST INCOMING TRANSFER. Until
    /// then there is no account and no access key, and `query_access_key`
    /// answers "does not exist while viewing" — the chain telling us about the
    /// account, not failing to tell us anything.
    ///
    /// It used to arrive as `InternalError`, which the coordinator forwards as
    /// `503` with a `Retry-After`: come back in five seconds, about a condition
    /// that never clears on its own and that the caller fixes in thirty by
    /// sending NEAR. It is also the FIRST thing a new wallet does, so it was
    /// the first thing a new user saw.
    #[test]
    fn an_account_that_was_never_funded_is_not_reported_as_our_outage() {
        // Captured from testnet RPC, `view_access_key` on a derived address
        // nobody has funded. The chain answers inside `result`, not as a
        // JSON-RPC error, which is why nothing above noticed it was an answer.
        assert!(rpc_error_is_about_the_signer(
            "Failed to query access key: access key ed25519:9dj5Xz1 does not exist while viewing"
        ));
        for fact in [
            "UNKNOWN_ACCOUNT",
            "UNKNOWN_ACCESS_KEY",
            "account doesn't exist",
            "account 7f7ab400 does not exist",
            "Access key does not exist",
        ] {
            assert!(rpc_error_is_about_the_signer(fact), "not recognised: {fact}");
        }

        // And a bare absence that is about something ELSE is not a fact about
        // the account. This is the direction that costs: a node which has
        // garbage-collected a block, or a call to a method nobody implements,
        // would otherwise tell a caller with a funded wallet that their
        // account is not on the network — a node's condition delivered as the
        // caller's fault, which is the mistake this whole change is about.
        for elsewhere in [
            "block does not exist",
            "the requested method does not exist",
            "shard does not exist on this node",
            "contract method doesn't exist",
        ] {
            assert!(
                !rpc_error_is_about_the_signer(elsewhere),
                "a condition of the NODE was read as a fact about the account: {elsewhere}"
            );
        }

        // A node that did not answer is OURS, stays a 500, and stays
        // retryable. Reading one of these as the caller's problem would tell
        // somebody to fund an account that is already funded.
        for outage in [
            "error sending request for url (https://rpc.testnet.fastnear.com/)",
            "operation timed out",
            "connection closed before message completed",
            "503 Service Temporarily Unavailable",
        ] {
            assert!(
                !rpc_error_is_about_the_signer(outage),
                "an outage was read as a fact about the account: {outage}"
            );
        }
    }

    /// The signing path actually USES the classifier, and prints the cause.
    ///
    /// The two tests around this one cover a pure function and a response
    /// shape; neither touches the call site, and both stayed green when the
    /// branch there was deleted. What is worth pinning is the WIRING: that the
    /// one place which queries an access key before signing asks whether the
    /// failure is about the account, and formats the error chain rather than
    /// its outermost context.
    ///
    /// Read out of the source because the alternative is a live NEAR node and
    /// an account nobody has funded.
    #[test]
    fn the_signing_path_asks_whether_the_failure_is_about_the_account() {
        let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/api.rs"))
            .expect("cannot read api.rs");
        let at = src
            .find(".query_access_key(&signer_id_str, &public_key)")
            .expect("the access-key query this guard follows is gone");
        let end = at + src[at..].find("\n    // Always rpc_nonce").expect("unterminated arm");
        let arm = &src[at..end];

        assert!(
            arm.contains("rpc_error_is_about_the_signer"),
            "the signing path no longer distinguishes an account that does not exist from a \
             node that did not answer, so a caller who has simply not funded their wallet is \
             told our service is down and to retry: {arm}"
        );
        assert!(
            arm.contains("ApiError::ChainRefused"),
            "the terminal case no longer has its own error, so it will be forwarded as a \
             transient 503: {arm}"
        );
        assert!(
            arm.contains("{e:#}"),
            "the error is formatted with `{{e}}` again, which prints only the outermost \
             context — the reason this failure read as `Failed to query access key: Failed to \
             query access key` and named nothing: {arm}"
        );
        assert!(
            arm.contains("signer_id_str") && arm.contains("not visible on the network"),
            "the refusal no longer names the account, or no longer states the chain's answer \
             about it: {arm}"
        );

        // AND it promises nothing — checked against the sentence the code
        // actually sends, not against a copy of it written in a test.
        //
        // That distinction is the whole value here: the assertion below lived
        // in a test that built its own `ChainRefused` string, so editing the
        // REAL message to promise a remedy changed nothing and everything
        // stayed green. `view_access_key` answers with the same bytes for an
        // account that has never been used and for one that exists carrying a
        // different key, so any remedy named here is a guess presented as an
        // instruction.
        for promise in ["send NEAR", "top up", "fund it", "will work"] {
            assert!(
                !arm.contains(promise),
                "the refusal promises `{promise}`. The chain's answer does not distinguish an \
                 account that has never been used from one that exists with another key, so \
                 this advice is right at most half the time: {arm}"
            );
        }
        assert!(
            arm.contains("Retrying will not"),
            "the refusal no longer says it is terminal, so a client will treat it as worth \
             repeating: {arm}"
        );
    }

    /// The refusal states the chain's answer and stops there.
    ///
    /// It must NOT promise a remedy. `view_access_key` returns a byte-identical
    /// "does not exist while viewing" for an account that has never been used
    /// and for one that exists with a different key on it — verified against
    /// testnet, both strings the same — so "send NEAR and the call will work"
    /// would be true in one case and false in the other, and we cannot tell
    /// which from here.
    #[test]
    fn the_refusal_states_the_answer_and_promises_nothing() {
        let addr = "7f7ab40018902d4a3d07d5040bb94cbcaeac13096be3c312423e96f37108f56f";
        let err = ApiError::ChainRefused(format!(
            "the account {addr} is not visible on the network, so there is no key to sign \
             with. Most often that means it has never taken part in a transaction. Retrying \
             will not change it — the chain answered, and this is its answer."
        ));
        let response = axum::response::IntoResponse::into_response(err);
        assert_eq!(
            response.status(),
            axum::http::StatusCode::UNPROCESSABLE_ENTITY,
            "a fact the chain stated must not be a 500 the coordinator turns into a 503"
        );

        let body = read_json_body(response);
        let text = body["error"].as_str().unwrap_or_default().to_string();
        assert!(text.contains(addr), "the refusal does not name the account: {body}");
        assert!(
            text.contains("Retrying will not"),
            "the refusal does not say it is terminal: {text}"
        );
        for promise in ["send NEAR", "top up", "fund"] {
            assert!(
                !text.contains(promise),
                "the refusal promises `{promise}`, which the chain's answer does not support: \
                 the same answer comes back for an account that exists with another key"
            );
        }

        // The vault's 402 is untouched — a different account with a different
        // remedy, and it keeps its own status.
        let vault = axum::response::IntoResponse::into_response(ApiError::PaymentRequired(
            "vault is short".to_string(),
        ));
        assert_eq!(vault.status(), axum::http::StatusCode::PAYMENT_REQUIRED);
    }

    #[test]
    fn a_freeze_we_cannot_read_is_not_read_as_unfrozen() {
        // The reading, extracted exactly as `load_wallet_policy` performs it.
        fn freeze_state(view: &serde_json::Value) -> Result<bool, &'static str> {
            match view.get("frozen") {
                Some(v) => v.as_bool().ok_or("unreadable"),
                None => Ok(false),
            }
        }

        assert_eq!(freeze_state(&serde_json::json!({ "frozen": true })), Ok(true));
        assert_eq!(freeze_state(&serde_json::json!({ "frozen": false })), Ok(false));

        // A policy that predates the field was never frozen.
        assert_eq!(freeze_state(&serde_json::json!({ "encrypted_data": "..." })), Ok(false));

        // Every shape that is not a boolean refuses. `"false"` is the one that
        // matters: a contract that started serializing the flag as a string
        // would, under the old reading, have unfrozen every frozen wallet at
        // once — and `"true"` would have done it too.
        for wrong in [
            serde_json::json!({ "frozen": "true" }),
            serde_json::json!({ "frozen": "false" }),
            serde_json::json!({ "frozen": 1 }),
            serde_json::json!({ "frozen": 0 }),
            serde_json::json!({ "frozen": null }),
            serde_json::json!({ "frozen": {} }),
        ] {
            assert_eq!(
                freeze_state(&wrong),
                Err("unreadable"),
                "a freeze state of {wrong} was answered instead of refused"
            );
        }

        // And the reading this test mirrors is the one that ships.
        let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/api.rs"))
            .expect("cannot read api.rs");
        // Bounded by the statement itself, not by a fixed width: a comment
        // added above the code would push what this looks for out of a window,
        // and a slice past the end of the file panics instead of failing with
        // the sentence that says what regressed.
        let at = src
            .find("let frozen = match policy_view.get(\"frozen\")")
            .expect("the freeze read this test follows is gone");
        let end = at + src[at..].find("\n    };").expect("unterminated freeze read");
        let block = &src[at..end];
        assert!(
            !block.contains(".and_then(|v| v.as_bool())\n        .unwrap_or(false)"),
            "the freeze flag defaults again"
        );
        assert!(
            block.contains("as_bool().ok_or_else"),
            "the freeze flag is no longer read fallibly"
        );
    }

    #[test]
    fn sign_message_recipient_allowlist_is_default_deny() {
        use serde_json::json;
        let parse = |v: serde_json::Value| -> wallet_policy::Policy {
            serde_json::from_value(v).expect("policy parse")
        };

        // No policy → single-sig wallet, unrestricted.
        assert!(sign_message_recipient_allowed(None, "intents.near"));

        // Policy present but no allowed_recipients → deny EVERYTHING (incl. would-be auth).
        let bare = parse(json!({ "capabilities": { "sign_message": { "allowed": true } } }));
        assert!(!sign_message_recipient_allowed(Some(&bare), "auth.app.near"));
        assert!(!sign_message_recipient_allowed(Some(&bare), "intents.near"));

        // Only explicitly-listed recipients are allowed; a fund-moving verifier that is
        // NOT listed is refused (the blocklist gap the allowlist closes).
        let listed = parse(json!({
            "capabilities": { "sign_message": { "allowed_recipients": ["auth.app.near"] } }
        }));
        assert!(sign_message_recipient_allowed(Some(&listed), "auth.app.near"));
        assert!(!sign_message_recipient_allowed(Some(&listed), "intents.near"));
        assert!(!sign_message_recipient_allowed(Some(&listed), "some-dex.near")); // unnamed verifier
        assert!(!sign_message_recipient_allowed(Some(&listed), "auth.app.near.evil")); // no substring match
    }

    #[test]
    fn evm_chains_share_one_canonical_seed() {
        // "One EVM address across all chains" reduces to: every EVM
        // chain name maps to the SAME derivation seed (long names and
        // 1Click short aliases alike), while non-EVM chains stay
        // distinct. Address == f(seed), so equal seeds ⇒ equal address.
        let id = "abc-123";
        let evm = [
            "ethereum", "eth", "polygon", "pol", "matic", "base", "arbitrum", "arb", "optimism",
            "op", "bsc", "avalanche", "avax", "hyperevm", "hood",
        ];
        let canonical = wallet_seed(id, "ethereum");
        assert_eq!(canonical, format!("wallet:{}:evm", id));
        for c in evm {
            assert!(is_evm_chain(c), "{c} must be recognized as EVM");
            assert_eq!(wallet_seed(id, c), canonical, "{c} must share the canonical EVM seed");
        }
        // Non-EVM keep their own per-chain seed (distinct curve/key).
        assert_eq!(wallet_seed(id, "near"), format!("wallet:{}:near", id));
        assert_eq!(wallet_seed(id, "solana"), format!("wallet:{}:solana", id));
        assert!(!is_evm_chain("near") && !is_evm_chain("solana"));
    }

    #[test]
    fn a_sub_key_is_its_own_key_under_its_own_root() {
        // Two paths are two keys, no path is the wallet's own, and the seed
        // does not depend on which EVM name was asked for. Address == f(seed),
        // so this is the isolation argument for sub-keys.
        let id = "abc-123";
        let trading = subkey_seed(id, "connector.hl.trading");
        assert_eq!(trading, "subkey:abc-123:evm:connector.hl.trading");
        assert_ne!(subkey_seed(id, "connector.hl.bridge"), trading);
        assert_ne!(trading, wallet_seed(id, "base"));
        assert_ne!(trading, wallet_seed(id, "hyperevm"));
    }

    #[test]
    fn no_exportable_seed_can_name_a_signing_key() {
        // `/wallet/derive-ephemeral-key` hands out PRIVATE keys for seeds it
        // builds as `wallet:{id}:{chain}:{sub_path}` from two request strings.
        // Both curves derive from the same HMAC input, so any signing seed that
        // endpoint could spell would be a signing key it could export. The
        // invariant every key family must keep: signing seeds are either two
        // segments under `wallet:` (which the exporter cannot spell — it needs
        // a non-empty third) or live under a root that is not `wallet:`.
        let id = "abc-123";
        let exportable = |chain: &str, sub: &str| format!("wallet:{id}:{chain}:{sub}");
        let signing = [
            wallet_seed(id, "near"),
            wallet_seed(id, "solana"),
            wallet_seed(id, "ethereum"),
            wallet_seed(id, "hyperevm"),
            subkey_seed(id, "connector.hl.trading"),
            subkey_seed(id, "0"),
            // The other seeds this keystore signs with: the VRF key and a
            // vault's TEE key (`mpc_ckd.rs`).
            "vrf-key".to_string(),
            format!("outlayer.near:{}", "vault.alice.near"),
        ];
        // The strings an attacker holding the exporter would try, including
        // the ones that spell a sub-key path verbatim.
        let attempts = [
            ("evm", "connector.hl.trading"),
            ("evm", "0"),
            ("near", "check:0"),
            ("near:check", "0"),
            ("ethereum", "connector.hl.trading"),
            ("evm:connector.hl.trading", ""),
            ("", "evm:connector.hl.trading"),
            ("subkey", "evm:connector.hl.trading"),
        ];
        for (chain, sub) in attempts {
            let spelled = exportable(chain, sub);
            for s in &signing {
                assert_ne!(&spelled, s, "exporter input ({chain:?}, {sub:?}) reaches a signing key");
            }
        }
        for s in &signing {
            // The exporter's output always starts with `wallet:` and always has
            // at least three `:`-separated segments after the root.
            let under_wallet_root = s.starts_with("wallet:");
            let two_segments = s.matches(':').count() == 2;
            assert!(
                !under_wallet_root || two_segments,
                "{s} is a wallet seed with a third segment — the exporter can spell it"
            );
        }
    }

    #[test]
    fn a_wallet_id_with_a_colon_is_refused_before_it_can_shift_a_seed() {
        // Wallet `a:evm`'s NEAR seed would be `wallet:a:evm:near` — exactly the
        // exporter's string for (a, evm, near). The id is refused instead.
        assert_eq!(wallet_seed("a:evm", "near"), "wallet:a:evm:near");
        assert!(validate_wallet_id("a:evm").is_err());
        assert!(validate_wallet_id("").is_err());
        assert!(validate_wallet_id("9c3c9e10-1c1f-4f5e-9c4a-1d7b9a8f3c20").is_ok());
    }

    #[test]
    fn a_sub_path_has_exactly_one_shape() {
        assert_eq!(validate_sub_path(None).unwrap(), None);
        assert_eq!(validate_sub_path(Some("")).unwrap(), None);
        assert_eq!(validate_sub_path(Some("connector.hl.trading")).unwrap(), Some("connector.hl.trading"));
        assert_eq!(validate_sub_path(Some("0")).unwrap(), Some("0"));
        assert_eq!(validate_sub_path(Some(&"a".repeat(64))).unwrap().map(str::len), Some(64));
        for bad in [
            ".leading-dot",
            "-leading-dash",
            "Upper",
            "with:colon",
            "with space",
            "unicode-ё",
            &"a".repeat(65),
        ] {
            assert!(validate_sub_path(Some(bad)).is_err(), "{bad:?} must be refused");
        }
    }

    // --- Built: the withdraw artifact is constructed FROM the op fields ------------

    #[test]
    fn built_withdraw_message_native_binds_op_fields() {
        let msg = build_withdraw_intent_message(
            "signer.near",
            "alice.near",
            "1000000000000000000000000",
            "near",
            "2026-06-04T12:05:00.000Z",
        );
        let v: serde_json::Value = serde_json::from_str(&msg).unwrap();
        assert_eq!(v["signer_id"], "signer.near");
        assert_eq!(v["deadline"], "2026-06-04T12:05:00.000Z");
        assert_eq!(v["intents"][0]["intent"], "native_withdraw");
        assert_eq!(v["intents"][0]["receiver_id"], "alice.near");
        assert_eq!(v["intents"][0]["amount"], "1000000000000000000000000");
    }

    #[test]
    fn built_withdraw_message_ft_uses_ft_withdraw_unprefixed_token() {
        // FT withdrawal OUT → `ft_withdraw` intent with the UNPREFIXED token contract.
        let msg = build_withdraw_intent_message(
            "signer.near",
            "alice.near",
            "1000000",
            "nep141:usdt.tether-token.near",
            "2026-06-04T12:05:00.000Z",
        );
        let v: serde_json::Value = serde_json::from_str(&msg).unwrap();
        assert_eq!(v["intents"][0]["intent"], "ft_withdraw");
        assert_eq!(v["intents"][0]["token"], "usdt.tether-token.near"); // prefix stripped
        assert_eq!(v["intents"][0]["receiver_id"], "alice.near");
        assert_eq!(v["intents"][0]["amount"], "1000000");
        // No `tokens` map on ft_withdraw.
        assert!(v["intents"][0]["tokens"].is_null());

        // Bare contract id passes through unchanged.
        let msg2 = build_withdraw_intent_message(
            "signer.near",
            "alice.near",
            "5",
            "usdt.near",
            "2026-06-04T12:05:00.000Z",
        );
        let v2: serde_json::Value = serde_json::from_str(&msg2).unwrap();
        assert_eq!(v2["intents"][0]["intent"], "ft_withdraw");
        assert_eq!(v2["intents"][0]["token"], "usdt.near");
    }

    #[test]
    fn built_transfer_message_is_internal_transfer_prefixed_tokens_map() {
        // Internal intents transfer → defuse `transfer` intent: funds stay inside intents.near,
        // credited to receiver_id. `tokens` is a PREFIXED map (unlike ft_withdraw).
        let msg = build_transfer_intent_message(
            "signer.near",
            "partner.near",
            "1000000",
            "nep141:usdt.tether-token.near",
            "2026-06-04T12:05:00.000Z",
        );
        let v: serde_json::Value = serde_json::from_str(&msg).unwrap();
        assert_eq!(v["signer_id"], "signer.near");
        assert_eq!(v["deadline"], "2026-06-04T12:05:00.000Z");
        assert_eq!(v["intents"][0]["intent"], "transfer");
        assert_eq!(v["intents"][0]["receiver_id"], "partner.near");
        assert_eq!(v["intents"][0]["tokens"]["nep141:usdt.tether-token.near"], "1000000");
        // It is NOT a withdrawal — no ft_withdraw/native_withdraw, no bare `token`/`amount`.
        assert!(v["intents"][0]["token"].is_null());
        assert!(v["intents"][0]["amount"].is_null());

        // Bare contract id is normalized to the prefixed asset id.
        let msg2 = build_transfer_intent_message(
            "signer.near",
            "950c134e8e7b2e2a1c0f3d4b5a6978a0b1c2d3e4f5061728394a5b6c7d8e9f001",
            "5",
            "usdt.near",
            "2026-06-04T12:05:00.000Z",
        );
        let v2: serde_json::Value = serde_json::from_str(&msg2).unwrap();
        assert_eq!(v2["intents"][0]["tokens"]["nep141:usdt.near"], "5");
    }

    #[test]
    fn iso8601_matches_known_timestamps() {
        assert_eq!(unix_to_iso8601(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(unix_to_iso8601(1_700_000_000), "2023-11-14T22:13:20.000Z");
    }

    // --- Approval binding: a substituted op cannot reuse genuine approvals ---------
    //
    // The keystore derives request_hash from the canonical op and the approvers sign
    // `approve:{id}:{wallet_pubkey}:{request_hash}` (see `approval_vote_message`). If any
    // op field is substituted, request_hash changes, so a signature collected for the
    // original op fails to verify against the substituted op's message — the binding is
    // automatic. The `sign_vote` helper below exercises this substitution/domain-separation
    // property with a simplified message; the wallet-pubkey binding is covered separately by
    // `approval_message_is_wallet_bound_no_cross_wallet_replay`.

    fn sign_vote(
        verb: &str,
        signing_key: &ed25519_dalek::SigningKey,
        approval_id: &str,
        request_hash: &str,
        recipient: &str,
    ) -> (String, String, String) {
        use ed25519_dalek::Signer;
        use sha2::{Digest, Sha256};
        let message = format!("{}:{}:{}", verb, approval_id, request_hash);
        let nonce = [7u8; 32];
        let payload = Nep413Payload {
            message,
            nonce,
            recipient: recipient.to_string(),
            callback_url: None,
        };
        let payload_bytes = borsh::to_vec(&payload).unwrap();
        let mut to_hash = Vec::with_capacity(4 + payload_bytes.len());
        to_hash.extend_from_slice(&NEP413_TAG.to_le_bytes());
        to_hash.extend_from_slice(&payload_bytes);
        let hash = Sha256::digest(&to_hash);
        let sig = signing_key.sign(&hash);
        (
            base64::encode(sig.to_bytes()),
            format!("ed25519:{}", bs58::encode(signing_key.verifying_key().to_bytes()).into_string()),
            base64::encode(nonce),
        )
    }

    /// A wallet whose access key is ml-dsa-65 signs NEP-413 like any other, and
    /// the message, nonce and recipient bind its signature the same way.
    #[test]
    fn an_ml_dsa_wallet_signature_is_verified_and_bound_like_an_ed25519_one() {
        use near_crypto::{KeyType, SecretKey, Signature};
        let sk = SecretKey::from_random(KeyType::MLDSA65);
        let pubkey = sk.public_key().to_string();
        assert!(pubkey.starts_with("ml-dsa-65:"), "{}", &pubkey[..12]);
        let nonce = base64::encode([7u8; 32]);
        let (msg, recipient) = ("Update Outlayer secrets for a.near:gmail\nkeys:GMAIL_POLICY", "keystore.outlayer.near");
        let (digest, tagged) = nep413_digest(msg, &nonce, recipient).unwrap();

        let raw = |sig: &Signature| match sig {
            Signature::MLDSA65(s) => base64::encode(s.as_ref()),
            _ => unreachable!(),
        };
        let over_digest = sk.sign(&digest);
        // As a wallet gives it (base64 of the raw bytes), and in canonical form.
        assert!(verify_near_signature(msg, &raw(&over_digest), &pubkey, &nonce, recipient).is_ok());
        assert!(verify_near_signature(msg, &over_digest.to_string(), &pubkey, &nonce, recipient).is_ok());
        // A signer that leaves the hashing to ml-dsa signed the same payload.
        assert!(verify_near_signature(msg, &raw(&sk.sign(&tagged)), &pubkey, &nonce, recipient).is_ok());

        // Another message, nonce or recipient is another payload.
        assert!(verify_near_signature("Update Outlayer secrets for a.near:gmail\nkeys:OTHER", &raw(&over_digest), &pubkey, &nonce, recipient).is_err());
        assert!(verify_near_signature(msg, &raw(&over_digest), &pubkey, &base64::encode([8u8; 32]), recipient).is_err());
        assert!(verify_near_signature(msg, &raw(&over_digest), &pubkey, &nonce, "elsewhere.near").is_err());
        // Another key does not verify it.
        let other = SecretKey::from_random(KeyType::MLDSA65).public_key().to_string();
        assert!(verify_near_signature(msg, &raw(&over_digest), &other, &nonce, recipient).is_err());
    }

    /// What an attacker can put in the three fields they control. None of it
    /// verifies, and none of it panics: every case is a refusal.
    #[test]
    fn nothing_an_attacker_can_type_into_key_or_signature_verifies() {
        use near_crypto::{KeyType, SecretKey, Signature};
        let nonce = base64::encode([3u8; 32]);
        let (msg, recipient) = ("Update Outlayer secrets for victim.near:gmail\nkeys:GMAIL_POLICY", "keystore.outlayer.near");
        let (digest, _) = nep413_digest(msg, &nonce, recipient).unwrap();
        let pq = SecretKey::from_random(KeyType::MLDSA65);
        let pq_pub = pq.public_key().to_string();
        let good = match pq.sign(&digest) { Signature::MLDSA65(s) => s.as_ref().to_vec(), _ => unreachable!() };
        let ed = SecretKey::from_random(KeyType::ED25519);
        let ed_pub = ed.public_key().to_string();

        let refused = |sig: &str, key: &str, nonce: &str| verify_near_signature(msg, sig, key, nonce, recipient).is_err();

        // Empty and malformed keys.
        for key in ["", " ", ":", "ml-dsa-65:", "ed25519:", "ml-dsa-65", "ml-dsa-65:0OIl", "ed25519:1111", "unknown:abcd"] {
            assert!(refused(&base64::encode(&good), key, &nonce), "key {key:?}");
        }
        // Empty, truncated, over-long and all-zero signatures, under either scheme.
        for sig in [String::new(), " ".into(), "!!!".into(), base64::encode(&good[..good.len() - 1]),
                    base64::encode([good.clone(), vec![0]].concat()), base64::encode(vec![0u8; good.len()]),
                    "ml-dsa-65:".into(), "ed25519:".into()] {
            assert!(refused(&sig, &pq_pub, &nonce), "ml-dsa sig {:?}", &sig[..sig.len().min(12)]);
        }
        for sig in [String::new(), base64::encode([0u8; 64]), base64::encode([0u8; 63]), base64::encode([0u8; 65])] {
            assert!(refused(&sig, &ed_pub, &nonce), "ed25519 sig len {}", sig.len());
        }
        // A good signature with one bit changed.
        let mut flipped = good.clone();
        flipped[100] ^= 1;
        assert!(refused(&base64::encode(&flipped), &pq_pub, &nonce));
        // A nonce that is not 32 bytes, or not base64.
        for bad in ["", "AAAA", "not base64!", &base64::encode([3u8; 31]), &base64::encode([3u8; 33])] {
            assert!(refused(&base64::encode(&good), &pq_pub, bad), "nonce {bad:?}");
        }
        // The control: untouched, it verifies.
        assert!(!refused(&base64::encode(&good), &pq_pub, &nonce));
    }

    /// ed25519 must not get the unhashed fallback, a scheme outside the two is
    /// refused by name, and a signature of one scheme never passes under a key
    /// of the other.
    #[test]
    fn only_the_two_wallet_schemes_are_accepted_and_they_do_not_mix() {
        use near_crypto::{KeyType, SecretKey, Signature};
        let nonce = base64::encode([1u8; 32]);
        let (msg, recipient) = ("m", "r.near");
        let (digest, tagged) = nep413_digest(msg, &nonce, recipient).unwrap();

        let ed = SecretKey::from_random(KeyType::ED25519);
        let ed_raw = |s: Signature| match s { Signature::ED25519(s) => base64::encode(s.to_bytes()), _ => unreachable!() };
        assert!(verify_near_signature(msg, &ed_raw(ed.sign(&digest)), &ed.public_key().to_string(), &nonce, recipient).is_ok());
        assert!(verify_near_signature(msg, &ed_raw(ed.sign(&tagged)), &ed.public_key().to_string(), &nonce, recipient).is_err());

        let secp = SecretKey::from_random(KeyType::SECP256K1);
        let err = verify_near_signature(msg, &secp.sign(&digest).to_string(), &secp.public_key().to_string(), &nonce, recipient).unwrap_err();
        assert!(err.to_string().contains("not accepted"), "{err}");

        let pq = SecretKey::from_random(KeyType::MLDSA65);
        let err = verify_near_signature(msg, &ed.sign(&digest).to_string(), &pq.public_key().to_string(), &nonce, recipient).unwrap_err();
        assert!(err.to_string().contains("signature is"), "{err}");
        // A bare key with no scheme is refused with the two that are expected.
        let err = verify_near_signature(msg, "AAAA", "nokey", &nonce, recipient).unwrap_err();
        assert!(err.to_string().contains("ml-dsa-65"), "{err}");
    }

    #[test]
    fn approval_signature_binds_to_exact_op_and_rejects_substitution() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let pubkey = format!(
            "ed25519:{}",
            bs58::encode(signing_key.verifying_key().to_bytes()).into_string()
        );
        let recipient = "outlayer.near";
        let approval_id = "appr-1";

        // Approver approves a 1-NEAR transfer to a vendor.
        let approved_op = Op::Transfer {
            to: "vendor.near".into(),
            amount: "1000000000000000000000000".into() };
        let approved_hash = wallet_policy::request_hash(&approved_op);
        let (sig, sig_pubkey, nonce) = sign_vote("approve", &signing_key, approval_id, &approved_hash, recipient);
        assert_eq!(sig_pubkey, pubkey);

        // The signature verifies for the op that was actually approved.
        let good_msg = format!("approve:{}:{}", approval_id, approved_hash);
        assert!(verify_near_signature(&good_msg, &sig, &pubkey, &nonce, recipient).is_ok());

        // A substituted op (100 NEAR to an attacker) has a different request_hash, so
        // the genuine signature fails to verify against it.
        let substituted_op = Op::Transfer {
            to: "attacker.near".into(),
            amount: "100000000000000000000000000".into() };
        let substituted_hash = wallet_policy::request_hash(&substituted_op);
        assert_ne!(approved_hash, substituted_hash);
        let bad_msg = format!("approve:{}:{}", approval_id, substituted_hash);
        assert!(verify_near_signature(&bad_msg, &sig, &pubkey, &nonce, recipient).is_err());
    }

    #[test]
    fn reject_vote_is_domain_separated_from_approve() {
        // A reject vote signs `reject:{id}:{hash}` — it must NOT verify as an approval
        // (and vice versa), so an approve sig can't be replayed as a veto or the reverse.
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let pubkey = format!(
            "ed25519:{}",
            bs58::encode(signing_key.verifying_key().to_bytes()).into_string()
        );
        let recipient = "outlayer.near";
        let id = "appr-1";
        let op = Op::Transfer { to: "vendor.near".into(), amount: "1".into() };
        let hash = wallet_policy::request_hash(&op);

        let (rej_sig, _, rej_nonce) = sign_vote("reject", &signing_key, id, &hash, recipient);
        // Verifies as a reject vote.
        let reject_msg = format!("reject:{}:{}", id, hash);
        assert!(verify_near_signature(&reject_msg, &rej_sig, &pubkey, &rej_nonce, recipient).is_ok());
        // Does NOT verify as an approval (different verb → different signed bytes).
        let approve_msg = format!("approve:{}:{}", id, hash);
        assert!(verify_near_signature(&approve_msg, &rej_sig, &pubkey, &rej_nonce, recipient).is_err());
    }

    // --- Auth: raw ed25519 over the coordinator string, byte-compatible ------------

    #[test]
    fn auth_signature_is_raw_ed25519_over_the_constructed_string() {
        use ed25519_dalek::Signer;
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());

        // Keystore-side construction (fresh ts) for a bearer auth.
        let ts = 1_700_000_000u64;
        let message = wallet_policy::build_auth_message("bearer", "default", ts, Some("v1.vault.near")).unwrap();
        assert_eq!(message, "auth:default:1700000000:v1.vault.near");

        // RAW ed25519 over the message bytes (NOT NEP-413). The coordinator's
        // verify_near_auth_fields does exactly `verify_strict(message.as_bytes(), sig)`.
        let sig = signing_key.sign(message.as_bytes());
        assert!(signing_key
            .verifying_key()
            .verify_strict(message.as_bytes(), &sig)
            .is_ok());

        // Domain separation: the signed bytes are a readable string, never a 32-byte
        // tx hash, so this signature can't double as a NEAR transaction signature.
        assert_ne!(message.as_bytes().len(), 32);
        assert!(message.starts_with("auth:"));
    }

    // --- Connector scope ----------------------------------------------------------

    // --- Bind-mode mapping for every kind -----------------------------------------

    #[test]
    fn every_kind_maps_to_expected_bind_mode() {
        use wallet_policy::{bind_mode, BindMode};
        assert_eq!(bind_mode(&Op::Transfer { to: "a".into(), amount: "1".into() }), BindMode::Built);
        assert_eq!(bind_mode(&Op::Delete { beneficiary: "a".into() }), BindMode::Built);
        assert_eq!(
            bind_mode(&Op::Withdraw { to: "a".into(), amount: "1".into(), token: "near".into() }),
            BindMode::Built
        );
        assert_eq!(
            bind_mode(&Op::Raw { chain: "ethereum".into(), payload_hash: "ab".into(), label: None }),
            BindMode::HashPinned
        );
        assert_eq!(
            bind_mode(&Op::SignMessage { message_hash: "ab".into(), recipient: "app".into(), purpose: None }),
            BindMode::HashPinned
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AccessCondition, LogicOperator};

    // ── Audit fixes: bound approval message, Trusted recipient pin, Trusted multisig guard ──

    #[test]
    fn approval_message_is_wallet_bound_no_cross_wallet_replay() {
        let id = "appr-1";
        let hash = "abc123";
        let pub_a = "ed25519:AAAA";
        let pub_b = "ed25519:BBBB";
        // The wallet pubkey is part of the signed string, so a signature collected for
        // wallet A's message can never satisfy wallet B's (different message → different sig).
        let a = approval_vote_message("approve", id, pub_a, hash);
        let b = approval_vote_message("approve", id, pub_b, hash);
        assert_ne!(a, b, "approval message must differ per wallet pubkey");
        assert_eq!(a, "approve:appr-1:ed25519:AAAA:abc123");
        // approve vs reject are domain-separated for the SAME wallet.
        assert_ne!(
            approval_vote_message("approve", id, pub_a, hash),
            approval_vote_message("reject", id, pub_a, hash)
        );
    }

    #[test]
    fn trusted_recipient_pin_allows_only_intents_verifiers() {
        assert!(is_trusted_recipient("intents.near"));
        assert!(is_trusted_recipient("intents.far")); // confidential shard
        // NEAR Intents is mainnet-only: testnet verifier is NOT a trusted recipient.
        assert!(!is_trusted_recipient("intents.testnet"));
        assert!(!is_trusted_recipient("evil.near"));
        assert!(!is_trusted_recipient("alice.near"));
        assert!(!is_trusted_recipient("intents.near.evil.near")); // no suffix/substring match
        assert!(!is_trusted_recipient(""));
    }

    #[test]
    fn trusted_kinds_are_bind_mode_trusted() {
        // Trusted kinds route to sign_trusted. Under multisig they now pass through
        // verify_approvals first (owner control); the keystore signs the coordinator-supplied
        // artifact after approval (off-chain destination stays coordinator-trusted).
        use shared_tee_helpers::wallet_policy::{bind_mode, BindMode, Op};
        let trusted = [
            Op::Swap { token_in: "a".into(), amount_in: "1".into(), token_out: "b".into(), min_out: "1".into() },
            Op::Confidential { flow: "withdraw".into(), to: Some("x".into()), amount: "1".into(), token: "near".into(), chain: Some("near".into()), token_out: None, min_amount_out: None },
            Op::CrossChainWithdraw { to: "0x".into(), amount: "1".into(), token: "nep141:usdt.tether-token.near".into(), chain: "ethereum".into() },
            Op::PaymentCheck { amount: "1".into(), token: "nep141:usdt.tether-token.near".into() },
            Op::LimitOrder { to: "x".into(), to_type: shared_tee_helpers::wallet_policy::RecipientType::Intents, amount: "1".into(), token: "nep141:wrap.near".into(), token_out: "nep141:usdc.near".into(), min_amount_out: "1".into() },
        ];
        for op in &trusted {
            assert_eq!(bind_mode(op), BindMode::Trusted, "must be Trusted: {:?}", op);
        }
    }

    /// Test that DecryptRequest correctly includes user_account_id field
    #[test]
    fn test_decrypt_request_serialization() {
        let json = r#"{
            "accessor": {
                "type": "Repo",
                "repo": "github.com/user/repo",
                "branch": "main"
            },
            "profile": "production",
            "owner": "owner.testnet",
            "user_account_id": "caller.testnet",
            "task_id": "task123"
        }"#;

        let req: DecryptRequest = serde_json::from_str(json).unwrap();
        match req.accessor {
            SecretAccessor::Repo { repo, branch } => {
                assert_eq!(repo, "github.com/user/repo");
                assert_eq!(branch, Some("main".to_string()));
            }
            _ => panic!("Expected Repo accessor"),
        }
        assert_eq!(req.owner, "owner.testnet");
        assert_eq!(req.user_account_id, "caller.testnet");
    }

    /// Test access control: owner != user_account_id
    /// This simulates the scenario where:
    /// - owner.testnet owns secrets with Whitelist access
    /// - caller.testnet requests execution
    /// - Access should be checked against caller.testnet, not owner.testnet
    #[tokio::test]
    async fn test_access_control_with_different_user() {
        // Test Whitelist: owner not in list, but user_account_id is
        let whitelist = AccessCondition::Whitelist {
            accounts: vec![
                "caller.testnet".to_string(),
                "other.testnet".to_string(),
            ],
        };

        // Should grant access to caller (even though owner is different)
        assert!(whitelist.validate("caller.testnet", None).await.unwrap());

        // Should deny access to owner (not in whitelist)
        assert!(!whitelist.validate("owner.testnet", None).await.unwrap());
    }

    /// Test that Whitelist correctly allows multiple accounts
    #[tokio::test]
    async fn test_whitelist_multiple_accounts() {
        let whitelist = AccessCondition::Whitelist {
            accounts: vec![
                "alice.testnet".to_string(),
                "bob.testnet".to_string(),
                "charlie.testnet".to_string(),
            ],
        };

        assert!(whitelist.validate("alice.testnet", None).await.unwrap());
        assert!(whitelist.validate("bob.testnet", None).await.unwrap());
        assert!(whitelist.validate("charlie.testnet", None).await.unwrap());
        assert!(!whitelist.validate("eve.testnet", None).await.unwrap());
    }

    /// Test AccountPattern with testnet suffix
    #[tokio::test]
    async fn test_account_pattern_testnet() {
        let pattern = AccessCondition::AccountPattern {
            pattern: r".*\.testnet$".to_string(),
        };

        assert!(pattern.validate("alice.testnet", None).await.unwrap());
        assert!(pattern.validate("project.testnet", None).await.unwrap());
        assert!(!pattern.validate("alice.near", None).await.unwrap());
    }

    /// Test complex Logic condition (AND + Whitelist + Pattern)
    #[tokio::test]
    async fn test_complex_logic_condition() {
        let condition = AccessCondition::Logic {
            operator: LogicOperator::And,
            conditions: vec![
                AccessCondition::AccountPattern {
                    pattern: r".*\.testnet$".to_string(),
                },
                AccessCondition::Whitelist {
                    accounts: vec![
                        "alice.testnet".to_string(),
                        "bob.testnet".to_string(),
                    ],
                },
            ],
        };

        // alice.testnet: matches pattern AND in whitelist
        assert!(condition.validate("alice.testnet", None).await.unwrap());

        // bob.testnet: matches pattern AND in whitelist
        assert!(condition.validate("bob.testnet", None).await.unwrap());

        // charlie.testnet: matches pattern but NOT in whitelist
        assert!(!condition.validate("charlie.testnet", None).await.unwrap());

        // alice.near: in "whitelist" but doesn't match pattern
        assert!(!condition.validate("alice.near", None).await.unwrap());
    }

    /// Test that AllowAll always grants access
    #[tokio::test]
    async fn test_allow_all() {
        let condition = AccessCondition::AllowAll;

        assert!(condition.validate("anyone.testnet", None).await.unwrap());
        assert!(condition.validate("another.near", None).await.unwrap());
        assert!(condition.validate("random.account", None).await.unwrap());
    }

    /// Test SecretAccessor::Repo serialization (with branch)
    #[test]
    fn test_secret_accessor_repo_with_branch() {
        let accessor = SecretAccessor::Repo {
            repo: "github.com/user/repo".to_string(),
            branch: Some("main".to_string()),
        };

        let json = serde_json::to_string(&accessor).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["type"], "Repo");
        assert_eq!(parsed["repo"], "github.com/user/repo");
        assert_eq!(parsed["branch"], "main");
    }

    /// Test SecretAccessor::Repo serialization (without branch)
    #[test]
    fn test_secret_accessor_repo_without_branch() {
        let accessor = SecretAccessor::Repo {
            repo: "github.com/user/repo".to_string(),
            branch: None,
        };

        let json = serde_json::to_string(&accessor).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["type"], "Repo");
        assert_eq!(parsed["repo"], "github.com/user/repo");
        assert!(parsed["branch"].is_null());
    }

    /// Test SecretAccessor::WasmHash serialization
    #[test]
    fn test_secret_accessor_wasm_hash() {
        let accessor = SecretAccessor::WasmHash {
            hash: "abc123def456".to_string(),
        };

        let json = serde_json::to_string(&accessor).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["type"], "WasmHash");
        assert_eq!(parsed["hash"], "abc123def456");
    }

    /// Test SecretAccessor deserialization from JSON
    #[test]
    fn test_secret_accessor_deserialization() {
        // Test Repo with branch
        let json = r#"{"type": "Repo", "repo": "github.com/test/project", "branch": "develop"}"#;
        let accessor: SecretAccessor = serde_json::from_str(json).unwrap();
        match accessor {
            SecretAccessor::Repo { repo, branch } => {
                assert_eq!(repo, "github.com/test/project");
                assert_eq!(branch, Some("develop".to_string()));
            }
            _ => panic!("Expected Repo variant"),
        }

        // Test Repo without branch
        let json = r#"{"type": "Repo", "repo": "github.com/test/project"}"#;
        let accessor: SecretAccessor = serde_json::from_str(json).unwrap();
        match accessor {
            SecretAccessor::Repo { repo, branch } => {
                assert_eq!(repo, "github.com/test/project");
                assert_eq!(branch, None);
            }
            _ => panic!("Expected Repo variant"),
        }

        // Test WasmHash
        let json = r#"{"type": "WasmHash", "hash": "deadbeef123456"}"#;
        let accessor: SecretAccessor = serde_json::from_str(json).unwrap();
        match accessor {
            SecretAccessor::WasmHash { hash } => {
                assert_eq!(hash, "deadbeef123456");
            }
            _ => panic!("Expected WasmHash variant"),
        }
    }

    /// Test DecryptRequest with Repo accessor
    #[test]
    fn test_decrypt_request_with_repo_accessor() {
        let json = r#"{
            "accessor": {
                "type": "Repo",
                "repo": "github.com/user/repo",
                "branch": "main"
            },
            "profile": "production",
            "owner": "owner.testnet",
            "user_account_id": "caller.testnet",
            "task_id": "task123"
        }"#;

        let req: DecryptRequest = serde_json::from_str(json).unwrap();
        match req.accessor {
            SecretAccessor::Repo { repo, branch } => {
                assert_eq!(repo, "github.com/user/repo");
                assert_eq!(branch, Some("main".to_string()));
            }
            _ => panic!("Expected Repo accessor"),
        }
        assert_eq!(req.profile, "production");
        assert_eq!(req.owner, "owner.testnet");
        assert_eq!(req.user_account_id, "caller.testnet");
    }

    /// Test DecryptRequest with WasmHash accessor
    #[test]
    fn test_decrypt_request_with_wasm_hash_accessor() {
        let json = r#"{
            "accessor": {
                "type": "WasmHash",
                "hash": "abc123def456"
            },
            "profile": "default",
            "owner": "alice.near",
            "user_account_id": "bob.near"
        }"#;

        let req: DecryptRequest = serde_json::from_str(json).unwrap();
        match req.accessor {
            SecretAccessor::WasmHash { hash } => {
                assert_eq!(hash, "abc123def456");
            }
            _ => panic!("Expected WasmHash accessor"),
        }
        assert_eq!(req.profile, "default");
        assert_eq!(req.owner, "alice.near");
        assert_eq!(req.user_account_id, "bob.near");
        assert!(req.task_id.is_none());
    }

    // ============== request-size caps ==============

    /// Oversized batches must be refused BEFORE the vault is loaded — loading a cold vault runs
    /// an on-chain MPC CKD derivation paid out of that vault's balance, so a spam request must
    /// never get that far. `test_state()` has no MPC context, so if the handler reached
    /// `ensure_customer_loaded` with a vault id it would fail differently; asserting on the
    /// message is what pins the ordering.
    #[tokio::test]
    async fn oversized_generated_secret_batches_are_refused_before_any_vault_work() {
        let state = test_state();
        state.mark_ready();

        let too_many: Vec<GeneratedSecretSpec> = (0..=MAX_GENERATED_SECRETS)
            .map(|i| GeneratedSecretSpec {
                name: format!("PROTECTED_K{i}"),
                generation_type: "hex32".to_string(),
            })
            .collect();

        let err = add_generated_secret_handler(
            State(state),
            Json(AddGeneratedSecretRequest {
                seed: "repo:alice".to_string(),
                encrypted_secrets_base64: None,
                new_secrets: too_many,
                // A vault id that WOULD trigger a derivation if the size check ran too late.
                vault_id: Some("vault.alice.testnet".to_string()),
            }),
        )
        .await
        .expect_err("over the limit must be refused");

        match err {
            ApiError::BadRequest(msg) => {
                assert!(msg.contains("too many generated secrets"), "wrong reason: {msg}");
                assert!(msg.contains(&MAX_GENERATED_SECRETS.to_string()), "state the limit: {msg}");
            }
            other => panic!("expected BadRequest about the batch size, got {other:?}"),
        }
    }

    /// A batch AT the limit is not refused for its size — it proceeds and fails later for an
    /// unrelated reason (no MPC context in tests). Guards against an off-by-one that would
    /// reject legitimate batches.
    #[tokio::test]
    async fn a_batch_at_the_limit_is_not_refused_for_its_size() {
        let state = test_state();
        state.mark_ready();

        let at_limit: Vec<GeneratedSecretSpec> = (0..MAX_GENERATED_SECRETS)
            .map(|i| GeneratedSecretSpec {
                name: format!("PROTECTED_K{i}"),
                generation_type: "hex32".to_string(),
            })
            .collect();

        let result = add_generated_secret_handler(
            State(state),
            Json(AddGeneratedSecretRequest {
                seed: "repo:alice".to_string(),
                encrypted_secrets_base64: None,
                new_secrets: at_limit,
                vault_id: Some("vault.alice.testnet".to_string()),
            }),
        )
        .await;

        if let Err(ApiError::BadRequest(msg)) = &result {
            assert!(
                !msg.contains("too many generated secrets"),
                "a batch at the limit must not be refused for its size: {msg}"
            );
        }
    }

    fn state_with_dead_rpc() -> AppState {
        let config = crate::config::Config {
            server_addr: "127.0.0.1:0".parse().unwrap(),
            near_network: "testnet".into(),
            near_rpc_url: "http://127.0.0.1:1".into(),
            offchainvm_contract_id: "outlayer.test".into(),
            allowed_worker_token_hashes: vec![],
            allowed_coordinator_token_hashes: vec![],
            tee_mode: crate::config::TeeMode::None,
            operator_account_id: None,
            keystore_key_type: near_crypto::KeyType::ED25519,
            tee_allowed_key_types: shared_tee_helpers::AllowedKeyTypes { ed25519: true, ml_dsa_65: true },
        };
        // Nothing listens on port 1 — any RPC call would fail, which is the point: the cap must
        // be enforced without one.
        let near_client = crate::near::NearClient::new("http://127.0.0.1:1", "outlayer.test").unwrap();
        AppState::new(crate::crypto::Keystore::generate(), config, Some(near_client))
    }

    fn one_approver_policy() -> shared_tee_helpers::wallet_policy::Policy {
        serde_json::from_value(serde_json::json!({
            "approval": {
                "threshold": { "required": 1 },
                "approvers": [{ "id": "alice.testnet", "role": "admin" }]
            }
        }))
        .expect("policy")
    }

    fn votes(n: usize) -> Vec<ApproverSig> {
        (0..n)
            .map(|_| ApproverSig {
                // The SAME approver repeated: the duplicate check skips an id only once it has
                // been successfully verified, so invalid repeats each cost a signature check.
                // No on-chain setup is needed to send these.
                approver_id: "alice.testnet".to_string(),
                public_key: "ed25519:11111111111111111111111111111111".to_string(),
                signature: "AA==".to_string(),
                nonce: "AA==".to_string(),
            })
            .collect()
    }

    /// A ballot larger than the cap is rejected on its SIZE, before anything in it is verified.
    /// The recipient below is deliberately wrong too — if the cap ran later, the error would be
    /// about the recipient instead, so the message is what proves the ordering.
    #[tokio::test]
    async fn an_oversized_ballot_is_refused_without_verifying_a_single_vote() {
        let state = state_with_dead_rpc();

        let err = verify_approvals(
            &state,
            &one_approver_policy(),
            "ed25519:wallet",
            "hash",
            Some(&ApprovalInfo {
                approval_id: "a1".to_string(),
                recipient: "definitely-not-this-keystore.testnet".to_string(),
                approvals: votes(MAX_APPROVAL_VOTES + 1),
                rejections: vec![],
            }),
            1,
        )
        .await
        .expect_err("an oversized ballot must be refused");

        match err {
            ApiError::BadRequest(msg) => {
                assert!(msg.contains("too many approval votes"), "wrong reason: {msg}");
                assert!(msg.contains(&MAX_APPROVAL_VOTES.to_string()), "state the limit: {msg}");
            }
            other => panic!("expected BadRequest about ballot size, got {other:?}"),
        }
    }

    /// Rejections are capped on the same terms — a veto ballot is just as expensive to verify.
    #[tokio::test]
    async fn oversized_rejection_ballots_are_refused_too() {
        let state = state_with_dead_rpc();

        let err = verify_approvals(
            &state,
            &one_approver_policy(),
            "ed25519:wallet",
            "hash",
            Some(&ApprovalInfo {
                approval_id: "a1".to_string(),
                recipient: "outlayer.test".to_string(),
                approvals: vec![],
                rejections: votes(MAX_APPROVAL_VOTES + 1),
            }),
            1,
        )
        .await
        .expect_err("an oversized veto ballot must be refused");

        assert!(
            matches!(&err, ApiError::BadRequest(m) if m.contains("too many approval votes")),
            "got {err:?}"
        );
    }

    /// A ballot AT the cap passes the size check and fails for a real reason instead — here the
    /// recipient mismatch. Guards the off-by-one: a legitimate full-threshold vote must not be
    /// refused for its size.
    #[tokio::test]
    async fn a_ballot_at_the_cap_passes_the_size_check() {
        let state = state_with_dead_rpc();

        let err = verify_approvals(
            &state,
            &one_approver_policy(),
            "ed25519:wallet",
            "hash",
            Some(&ApprovalInfo {
                approval_id: "a1".to_string(),
                recipient: "definitely-not-this-keystore.testnet".to_string(),
                approvals: votes(MAX_APPROVAL_VOTES),
                rejections: vec![],
            }),
            1,
        )
        .await
        .expect_err("the wrong recipient must still be refused");

        let msg = format!("{err:?}");
        assert!(
            !msg.contains("too many approval votes"),
            "a ballot at the cap must not be refused for its size: {msg}"
        );
        assert!(msg.contains("recipient"), "expected the recipient check to fire: {msg}");
    }

    // ============== /admin/loaded-vaults + TEE worker identity ==============

    /// Build a state whose worker token is `token`, so the router's auth layer can be exercised.
    fn state_with_worker_token(token: &str) -> AppState {
        use sha2::{Digest, Sha256};
        let mut state_config = crate::config::Config {
            server_addr: "127.0.0.1:0".parse().unwrap(),
            near_network: "testnet".into(),
            near_rpc_url: "http://127.0.0.1:1".into(),
            offchainvm_contract_id: "outlayer.test".into(),
            allowed_worker_token_hashes: vec![],
            allowed_coordinator_token_hashes: vec![],
            tee_mode: crate::config::TeeMode::None,
            operator_account_id: None,
            keystore_key_type: near_crypto::KeyType::ED25519,
            tee_allowed_key_types: shared_tee_helpers::AllowedKeyTypes { ed25519: true, ml_dsa_65: true },
        };
        state_config.allowed_worker_token_hashes =
            vec![hex::encode(Sha256::digest(token.as_bytes()))];
        // A DIFFERENT coordinator token, so the tests can tell the two lists apart rather than
        // passing because one value happens to be in both.
        state_config.allowed_coordinator_token_hashes =
            vec![hex::encode(Sha256::digest(format!("coordinator-{token}").as_bytes()))];
        let state = AppState::new(crate::crypto::Keystore::generate(), state_config, None);
        state.mark_ready();
        state
    }

    async fn get_loaded_vaults(state: AppState, auth: Option<&str>) -> (axum::http::StatusCode, String) {
        use tower::ServiceExt;
        let mut builder = axum::http::Request::builder()
            .method("GET")
            .uri("/admin/loaded-vaults");
        if let Some(a) = auth {
            builder = builder.header("Authorization", a);
        }
        let response = create_router(state)
            .oneshot(builder.body(axum::body::Body::empty()).unwrap())
            .await
            .expect("router");
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("body");
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    /// This endpoint lists which vaults this keystore holds a master for. That list is
    /// operational detail, not public information, and the route must stay behind the worker
    /// token — a router refactor that dropped the auth layer would otherwise go unnoticed.
    #[tokio::test]
    async fn loaded_vaults_is_refused_without_a_worker_token() {
        let (status, body) = get_loaded_vaults(state_with_worker_token("s3cret"), None).await;
        assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED, "body: {body}");
        assert!(
            !body.contains("vaults"),
            "an unauthorized caller must not see the vault list: {body}"
        );

        let (status, _) =
            get_loaded_vaults(state_with_worker_token("s3cret"), Some("Bearer wrong")).await;
        assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);

        // A token that is right but presented in the wrong scheme is still a refusal.
        let (status, _) = get_loaded_vaults(state_with_worker_token("s3cret"), Some("s3cret")).await;
        assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
    }

    /// The coordinator reads this to publish fleet state in its own health output, which the
    /// monitoring collector relays. Admitting it here is what lets monitoring see the numbers
    /// WITHOUT holding a worker token — which would also open `/admin/evict-customer`.
    #[tokio::test]
    async fn loaded_vaults_accepts_the_coordinator_token_too() {
        let state = state_with_worker_token("s3cret");
        let (status, body) = get_loaded_vaults(state, Some("Bearer coordinator-s3cret")).await;
        assert_eq!(status, axum::http::StatusCode::OK, "body: {body}");
        assert!(body.contains("\"count\""), "body: {body}");
    }

    /// ...and that read access must NOT extend to the mutating admin route. `/admin/evict-customer`
    /// drops a vault master, forcing that vault to pay for a fresh on-chain CKD derivation — a
    /// credential that can only read must never be able to trigger it.
    #[tokio::test]
    async fn the_coordinator_token_cannot_reach_the_mutating_admin_route() {
        use tower::ServiceExt;
        let state = state_with_worker_token("s3cret");
        let response = create_router(state)
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/admin/evict-customer")
                    .header("Authorization", "Bearer coordinator-s3cret")
                    .header("Content-Type", "application/json")
                    .body(axum::body::Body::from(r#"{"vault_id":"vault.alice.testnet"}"#))
                    .unwrap(),
            )
            .await
            .expect("router");
        assert_eq!(
            response.status(),
            axum::http::StatusCode::UNAUTHORIZED,
            "the coordinator token must not be able to evict a vault master"
        );
    }

    /// With the token it reports what is actually in memory — vault ids only, sorted, plus the
    /// counts an operator reads after a restart to see who has come back.
    #[tokio::test]
    async fn loaded_vaults_reports_the_masters_in_memory() {
        let state = state_with_worker_token("s3cret");
        {
            let ks = state.keystore.read().await;
            ks.add_customer("vault.zoe.testnet".parse().unwrap(), [1u8; 32]);
            ks.add_customer("vault.alice.testnet".parse().unwrap(), [2u8; 32]);
        }

        let (status, body) = get_loaded_vaults(state, Some("Bearer s3cret")).await;
        assert_eq!(status, axum::http::StatusCode::OK, "body: {body}");

        let json: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(json["count"], 2);
        assert_eq!(json["vaults"][0], "vault.alice.testnet", "must be sorted");
        assert_eq!(json["vaults"][1], "vault.zoe.testnet");
        assert_eq!(json["tee_sessions"], 0);
        // Addresses only — never key material.
        assert!(!body.contains("0101010101"), "key material leaked: {body}");
    }

    /// `/decrypt` logs which worker instance asked, taken from the validated TEE session. That
    /// is the only worker identifier the keystore can trust, and it is the first time the record
    /// names the caller at all — before this it logged a self-declared constant.
    #[test]
    fn a_live_session_yields_the_worker_key_that_opened_it() {
        let state = state_with_worker_token("s3cret");
        let mut config = state.config.clone();
        config.tee_mode = crate::config::TeeMode::OutlayerTee;
        let state = AppState::new(crate::crypto::Keystore::generate(), config, None);

        let session_id = uuid::Uuid::new_v4();
        state.tee_sessions.lock().unwrap().insert(
            session_id,
            TeeSession {
                worker_public_key: "ed25519:WorkerAAA".to_string(),
                created_at: std::time::Instant::now(),
            },
        );

        let mut headers = axum::http::HeaderMap::new();
        headers.insert("X-TEE-Session", session_id.to_string().parse().unwrap());
        assert_eq!(
            validate_tee_session(&state, &headers).unwrap(),
            Some("ed25519:WorkerAAA".to_string())
        );

        // An unknown session is refused outright — the identity is not optional in TEE mode.
        let mut unknown = axum::http::HeaderMap::new();
        unknown.insert("X-TEE-Session", uuid::Uuid::new_v4().to_string().parse().unwrap());
        assert!(validate_tee_session(&state, &unknown).is_err());
    }

    /// The identity has to survive the trip from the middleware to the handler. If the extension
    /// stopped being inserted, `/decrypt` would silently log `worker=no-session` and every
    /// decrypt would become unattributable, with nothing failing.
    #[tokio::test]
    async fn the_middleware_hands_the_worker_identity_to_the_handler() {
        use tower::ServiceExt;

        let mut config = state_with_worker_token("s3cret").config.clone();
        config.tee_mode = crate::config::TeeMode::OutlayerTee;
        let state = AppState::new(crate::crypto::Keystore::generate(), config, None);

        let session_id = uuid::Uuid::new_v4();
        state.tee_sessions.lock().unwrap().insert(
            session_id,
            TeeSession {
                worker_public_key: "ed25519:WorkerBBB".to_string(),
                created_at: std::time::Instant::now(),
            },
        );

        // A throwaway route behind the real middleware, echoing whatever identity arrived.
        async fn echo(worker: Option<axum::Extension<WorkerIdentity>>) -> String {
            worker.map(|w| w.0 .0).unwrap_or_else(|| "no-session".to_string())
        }
        let app = Router::new()
            .route("/echo", get(echo))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                tee_session_middleware,
            ))
            .with_state(state);

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/echo")
                    .header("X-TEE-Session", session_id.to_string())
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .expect("router");
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 1024).await.unwrap();
        assert_eq!(
            String::from_utf8_lossy(&bytes),
            "ed25519:WorkerBBB",
            "the validated worker identity never reached the handler"
        );
    }

    // ============== AppState::ensure_customer_loaded gate ==============

    pub(super) fn test_state() -> AppState {
        let config = crate::config::Config {
            server_addr: "127.0.0.1:0".parse().unwrap(),
            near_network: "testnet".into(),
            near_rpc_url: "http://127.0.0.1:1".into(),
            offchainvm_contract_id: "outlayer.test".into(),
            allowed_worker_token_hashes: vec![],
            allowed_coordinator_token_hashes: vec![],
            tee_mode: crate::config::TeeMode::None,
            operator_account_id: None,
            keystore_key_type: near_crypto::KeyType::ED25519,
            tee_allowed_key_types: shared_tee_helpers::AllowedKeyTypes { ed25519: true, ml_dsa_65: true },
        };
        AppState::new(crate::crypto::Keystore::generate(), config, None)
    }

    #[tokio::test]
    async fn ensure_customer_loaded_none_is_noop() {
        // Legacy default-master path: handlers that pass None must
        // never trip the lazy-load gate, even when MPC context is
        // unset. This is the backward-compat invariant.
        let state = test_state();
        state
            .ensure_customer_loaded(None)
            .await
            .expect("None customer must always succeed");
    }

    #[tokio::test]
    async fn ensure_customer_loaded_some_without_mpc_context_errors() {
        // When booted without a TEE/MPC context, asking for a
        // per-customer master must fail-fast with a clear error
        // rather than silently falling back to the default master
        // (which would defeat the customer-isolation invariant).
        use std::str::FromStr;
        let state = test_state();
        let vault = near_primitives::types::AccountId::from_str("vault.alice.testnet").unwrap();
        let err = state
            .ensure_customer_loaded(Some(&vault))
            .await
            .expect_err("must fail without MPC context");
        let msg = format!("{:#}", err);
        assert!(
            msg.contains("MPC CKD context") || msg.contains("non-TEE"),
            "error message should explain the missing context, got: {}",
            msg
        );
    }

    #[tokio::test]
    async fn ensure_customer_loaded_some_with_cached_master_still_requires_mpc_context() {
        // The wrapper used to short-circuit on `has_customer` to skip
        // the on-chain verify, but that opened a "served cached master
        // for a now-unlocked vault" window if the indexer-driven
        // eviction lagged. The current behaviour: every signing op
        // delegates to `mpc_ckd::ensure_customer_loaded`, which does
        // the `is_vault_verified` + `unlocked == false` view-call pair
        // BEFORE checking the cache. A cached master alone is no
        // longer a free pass.
        //
        // In this test the worker has no MPC context, so the wrapper
        // errors before reaching the view-call layer — exactly the
        // contract we want: cached-master serving is gated behind a
        // properly configured worker.
        use std::str::FromStr;
        let state = test_state();
        let vault = near_primitives::types::AccountId::from_str("vault.alice.testnet").unwrap();
        state
            .keystore
            .read()
            .await
            .add_customer(vault.clone(), [9u8; 32]);

        let err = state
            .ensure_customer_loaded(Some(&vault))
            .await
            .expect_err(
                "cache hit must not short-circuit the MPC-context guard \
                 — full re-verify happens at the next layer",
            );
        let msg = format!("{:#}", err);
        assert!(
            msg.contains("MPC CKD context") || msg.contains("non-TEE"),
            "error must surface the missing MPC context, got: {}",
            msg
        );
    }

    // ============== Vault-scope helpers ==============
    // Audit finding I7: pin behaviour of the new request-extraction
    // helpers and the accessor → contract-JSON adapter. Without these
    // tests, future drift between the worker enum and the contract
    // enum (e.g. someone adding `#[serde(tag = "type")]` to either)
    // would silently break decrypt — accessor lookups would target
    // the wrong row and `get_secret_with_vault` would always return
    // `(None, None)`.

    use axum::http::HeaderMap;

    #[test]
    fn extract_customer_from_header_absent_is_none() {
        let h = HeaderMap::new();
        assert!(extract_customer_from_header(&h).unwrap().is_none());
    }

    #[test]
    fn extract_customer_from_header_empty_is_none() {
        let mut h = HeaderMap::new();
        h.insert("X-Customer-Vault", "".parse().unwrap());
        assert!(extract_customer_from_header(&h).unwrap().is_none());
        h.insert("X-Customer-Vault", "   ".parse().unwrap());
        assert!(extract_customer_from_header(&h).unwrap().is_none());
    }

    #[test]
    fn extract_customer_from_header_valid_account() {
        let mut h = HeaderMap::new();
        h.insert("X-Customer-Vault", "vault.alice.testnet".parse().unwrap());
        let result = extract_customer_from_header(&h).unwrap().unwrap();
        assert_eq!(result.as_str(), "vault.alice.testnet");
    }

    #[test]
    fn extract_customer_from_header_trims_whitespace() {
        let mut h = HeaderMap::new();
        h.insert("X-Customer-Vault", "  vault.alice.testnet  ".parse().unwrap());
        let result = extract_customer_from_header(&h).unwrap().unwrap();
        assert_eq!(result.as_str(), "vault.alice.testnet");
    }

    #[test]
    fn extract_customer_from_header_malformed_id_errors() {
        // No silent fallback to default master — that's the
        // anti-typo guarantee.
        let mut h = HeaderMap::new();
        h.insert("X-Customer-Vault", "INVALID UPPERCASE".parse().unwrap());
        let err = extract_customer_from_header(&h).unwrap_err();
        match err {
            ApiError::BadRequest(msg) => assert!(msg.contains("X-Customer-Vault")),
            other => panic!("expected BadRequest, got {:?}", other),
        }
    }

    #[test]
    fn parse_optional_vault_id_treats_none_empty_whitespace_uniformly() {
        assert!(parse_optional_vault_id(None).unwrap().is_none());
        assert!(parse_optional_vault_id(Some("")).unwrap().is_none());
        assert!(parse_optional_vault_id(Some("   ")).unwrap().is_none());
        assert!(parse_optional_vault_id(Some("\t")).unwrap().is_none());
    }

    #[test]
    fn parse_optional_vault_id_valid() {
        let result = parse_optional_vault_id(Some("vault.alice.testnet")).unwrap().unwrap();
        assert_eq!(result.as_str(), "vault.alice.testnet");
    }

    #[test]
    fn parse_optional_vault_id_malformed_errors() {
        let err = parse_optional_vault_id(Some("INVALID")).unwrap_err();
        match err {
            ApiError::BadRequest(msg) => assert!(msg.contains("vault_id")),
            other => panic!("expected BadRequest, got {:?}", other),
        }
    }

    // ============== accessor_to_contract_json — frozen contract ==============
    // These tests pin the EXACT JSON shape sent to the contract for
    // every accessor variant. If the contract enum tagging ever
    // changes, OR the worker enum tagging changes, these tests fail
    // — and that failure is what protects every secret stored on
    // chain from silent decryption misses.

    #[test]
    fn accessor_to_contract_json_repo_normalizes_url() {
        let a = SecretAccessor::Repo {
            repo: "https://github.com/alice/repo".into(),
            branch: Some("main".into()),
        };
        let json = accessor_to_contract_json(&a);
        assert_eq!(
            json,
            serde_json::json!({"Repo": {"repo": "github.com/alice/repo", "branch": "main"}})
        );
    }

    #[test]
    fn accessor_to_contract_json_repo_null_branch() {
        // Null branch must serialise as JSON null (NOT omitted) — the
        // contract's wildcard-fallback logic relies on the field
        // being present.
        let a = SecretAccessor::Repo {
            repo: "github.com/alice/repo".into(),
            branch: None,
        };
        let json = accessor_to_contract_json(&a);
        assert_eq!(
            json,
            serde_json::json!({"Repo": {"repo": "github.com/alice/repo", "branch": null}})
        );
    }

    #[test]
    fn accessor_to_contract_json_wasm_hash() {
        let a = SecretAccessor::WasmHash { hash: "abc123".into() };
        let json = accessor_to_contract_json(&a);
        assert_eq!(json, serde_json::json!({"WasmHash": {"hash": "abc123"}}));
    }

    #[test]
    fn accessor_to_contract_json_project() {
        let a = SecretAccessor::Project { project_id: "alice.near/myapp".into() };
        let json = accessor_to_contract_json(&a);
        assert_eq!(json, serde_json::json!({"Project": {"project_id": "alice.near/myapp"}}));
    }

    #[test]
    fn accessor_to_contract_json_system_payment_key_uses_camelcase() {
        // Critical: the contract's `System(SystemSecretType)` is a tuple
        // variant, so `{"System": "PaymentKey"}` (string, CamelCase),
        // not `{"System": "payment_key"}` or `{"System": {"PaymentKey": null}}`.
        let a = SecretAccessor::System { secret_type: SystemSecretType::PaymentKey };
        let json = accessor_to_contract_json(&a);
        assert_eq!(json, serde_json::json!({"System": "PaymentKey"}));
    }

    #[test]
    fn system_secret_type_helpers_disagree_on_case() {
        // Drift guard: contract format is CamelCase, seed format is
        // snake_case. If both helpers ever drift to the same value,
        // either contract lookups break (System: payment_key won't
        // match) or seed format breaks (system:PaymentKey:... is a
        // different seed). This test is the canary.
        let s = SystemSecretType::PaymentKey;
        assert_eq!(s.as_contract_str(), "PaymentKey");
        assert_eq!(s.as_seed_str(), "payment_key");
        assert_ne!(s.as_contract_str(), s.as_seed_str());
    }

    // ============== map_verify_error HTTP status mapping ==============
    // The caller-side / worker-side
    // split. These tests pin which VerifyError variant maps to which
    // ApiError so a future change (e.g. someone moving an arm by
    // accident) shows up as a unit-test failure rather than a
    // production caller suddenly retrying or surfacing the wrong
    // status to its end-user.

    use crate::vault_verifier::VerifyError;
    use std::str::FromStr as _;

    fn vault() -> near_primitives::types::AccountId {
        near_primitives::types::AccountId::from_str("vault.alice.testnet").unwrap()
    }

    fn assert_bad_request(e: ApiError) {
        match e {
            ApiError::BadRequest(_) => {}
            other => panic!("expected BadRequest, got {:?}", other),
        }
    }
    fn assert_forbidden(e: ApiError) {
        match e {
            ApiError::Forbidden(_) => {}
            other => panic!("expected Forbidden, got {:?}", other),
        }
    }
    fn assert_internal(e: ApiError) {
        match e {
            ApiError::InternalError(_) => {}
            other => panic!("expected InternalError, got {:?}", other),
        }
    }

    #[test]
    fn map_verify_error_already_banned_is_403() {
        // Banned vault is a security signal that the caller's request
        // CAN'T succeed regardless of retries. 403 says so plainly.
        assert_forbidden(map_verify_error(&vault(), VerifyError::AlreadyBanned));
    }

    #[test]
    fn map_verify_error_caller_side_failures_are_400() {
        // Each arm here represents a CALLER-side failure mode:
        // either the vault was deployed wrong (FullAccess key,
        // misconfigured TEE key, wrong DAO) or its state is in a
        // non-eligible phase (unlocked, recovering). All must
        // surface as 400 so callers don't retry.
        assert_bad_request(map_verify_error(
            &vault(),
            VerifyError::CodeHashNotApproved { code_hash: "abc".into() },
        ));
        assert_bad_request(map_verify_error(&vault(), VerifyError::CodeHashMissing));
        assert_bad_request(map_verify_error(&vault(), VerifyError::FullAccessKeyPresent));
        assert_bad_request(map_verify_error(
            &vault(),
            VerifyError::FunctionCallKeyMisconfigured {
                receiver: "bad".into(),
                methods: vec![],
            },
        ));
        assert_bad_request(map_verify_error(
            &vault(),
            VerifyError::UnexpectedAccessKeyCount { expected: 1, got: 2 },
        ));
        assert_bad_request(map_verify_error(
            &vault(),
            VerifyError::KeystoreDaoMismatch {
                configured: "x".into(),
                on_chain: "y".into(),
            },
        ));
        assert_bad_request(map_verify_error(
            &vault(),
            VerifyError::MpcContractMismatch {
                configured: "x".into(),
                on_chain: "y".into(),
            },
        ));
        assert_bad_request(map_verify_error(&vault(), VerifyError::VaultUnlocked));
        assert_bad_request(map_verify_error(&vault(), VerifyError::VaultRecoveryInProgress));
    }

    #[test]
    fn map_verify_error_account_not_found_is_400() {
        // Ambiguous: vault doesn't exist OR rpc flake. Bias to 400
        // because dominant case is bad vault_id.
        let err = anyhow::anyhow!("account does not exist");
        assert_bad_request(map_verify_error(
            &vault(),
            VerifyError::AccountNotFound(err),
        ));
    }

    #[test]
    fn map_verify_error_rpc_failures_are_500() {
        // A flaky NEAR RPC must not surface as
        // 400 because callers won't retry on 4xx. These cases are
        // worker-side / system-side, callers SHOULD retry.
        let err = || anyhow::anyhow!("rpc timeout");
        assert_internal(map_verify_error(
            &vault(),
            VerifyError::KeystoreDaoUnreachable(err()),
        ));
        assert_internal(map_verify_error(
            &vault(),
            VerifyError::AccessKeyListUnreachable(err()),
        ));
        assert_internal(map_verify_error(
            &vault(),
            VerifyError::VaultStateUnreachable(err()),
        ));
    }

    #[test]
    fn map_verify_error_contract_shape_mismatch_is_500() {
        // A contract returning malformed JSON
        // is a contract bug or version mismatch — NOT a caller bug.
        // Caller has done nothing wrong; surfacing 400 would be a
        // lie.
        assert_internal(map_verify_error(
            &vault(),
            VerifyError::KeystoreDaoMalformed { method: "is_vault_banned".into() },
        ));
        assert_internal(map_verify_error(
            &vault(),
            VerifyError::VaultStateInvalid("missing keystore_dao".into()),
        ));
    }

    // ============== Handler-level customer isolation ==============
    // Builds on the crypto-layer isolation tests in `crypto.rs`. At
    // the handler layer the only customer-facing surface that we can
    // exercise without an HTTP test server is `AppState::ensure_customer_loaded`.
    // The `crypto.rs` tests already prove the underlying derive_*
    // calls produce disjoint output per customer; here we simply
    // verify the gate's behaviour matrix:

    #[tokio::test]
    async fn ensure_customer_loaded_treats_cached_and_uncached_uniformly_without_mpc() {
        // The api-layer wrapper used to fast-path on `has_customer`,
        // so cached masters were served without going through
        // `mpc_ckd::ensure_customer_loaded`'s on-chain verify. That
        // short-circuit is gone — every call now needs an MPC context
        // because the verify (and any subsequent re-load) happens at
        // the lower layer. Both a cached vault AND an uncached vault
        // must surface the same "no MPC context" error in non-TEE
        // mode; per-vault cache isolation is unit-tested at the
        // Keystore layer, not here.
        use std::str::FromStr;
        let state = test_state();
        let alice = near_primitives::types::AccountId::from_str("vault.alice.testnet").unwrap();
        let bob = near_primitives::types::AccountId::from_str("vault.bob.testnet").unwrap();

        // Pre-populate alice only; bob stays uncached.
        state
            .keystore
            .read()
            .await
            .add_customer(alice.clone(), [0xAA; 32]);

        for vault in [&alice, &bob] {
            let err = state
                .ensure_customer_loaded(Some(vault))
                .await
                .expect_err(
                    "wrapper must require MPC context regardless of cache state",
                );
            let msg = format!("{:#}", err);
            assert!(
                msg.contains("MPC CKD context") || msg.contains("non-TEE"),
                "non-TEE-mode error message expected for {vault}, got: {msg}"
            );
        }
    }

    // ============== Audit noteC2 — backward-compat smoke ==============
    // The plan (line 598) explicitly mandates: "запросы без
    // X-Customer-Vault header работают на default_master (legacy
    // clients)". Earlier audits caught customer-isolation invariants
    // at the gate level. This test drives a real wallet handler with
    // an EMPTY HeaderMap and asserts the derived address matches what
    // direct `keystore.derive_keypair(None, …)` produces — pinning
    // the legacy customer-less path against accidental regression.
    #[tokio::test]
    async fn handler_without_x_customer_vault_uses_default_master() {
        let state = test_state();
        // Wait for is_ready (test_state initialises with is_ready=true).

        // Snapshot the keystore's default-master output for the seed
        // the handler will build internally.
        let expected_seed = "wallet:test-wallet-id:near".to_string();
        let expected_pubkey = {
            let ks = state.keystore.read().await;
            let (_, vk) = ks.derive_keypair(None, &expected_seed).unwrap();
            hex::encode(vk.as_bytes())
        };

        // Drive the handler with an empty HeaderMap — proves the
        // legacy "no header → default master" path.
        let request = WalletDeriveAddressRequest {
                        wallet_id: "test-wallet-id".to_string(),
            chain: "near".to_string(),
            sub_path: None,
        };
        let response = wallet_derive_address_handler(
            axum::extract::State(state),
            axum::http::HeaderMap::new(),
            axum::Json(request),
        )
        .await
        .expect("handler must succeed without X-Customer-Vault header");

        assert_eq!(
            response.0.address, expected_pubkey,
            "derived address must match default-master derive_keypair output"
        );
    }

    #[tokio::test]
    async fn handler_with_empty_x_customer_vault_uses_default_master() {
        // An empty header value must be treated identically to no
        // header — `extract_customer_from_header` returns Ok(None).
        // This matters because some HTTP clients always send all
        // configured headers, even with empty values.
        let state = test_state();
        let expected_pubkey = {
            let ks = state.keystore.read().await;
            let (_, vk) = ks.derive_keypair(None, "wallet:abc:near").unwrap();
            hex::encode(vk.as_bytes())
        };

        let mut headers = axum::http::HeaderMap::new();
        headers.insert("X-Customer-Vault", "".parse().unwrap());

        let request = WalletDeriveAddressRequest {
                        wallet_id: "abc".to_string(),
            chain: "near".to_string(),
            sub_path: None,
        };
        let response = wallet_derive_address_handler(
            axum::extract::State(state),
            headers,
            axum::Json(request),
        )
        .await
        .expect("empty header must be treated as no header");

        assert_eq!(response.0.address, expected_pubkey);
    }
}

/// A secret named after an agent belongs to that agent — both to read and to
/// have written.
///
/// These pin the rule itself rather than the handler around it: the handler
/// needs a NEAR client and a live contract, while the rule needs nothing at all,
/// and it is the rule that decides who reads a connector credential.
#[cfg(test)]
mod agent_secret_tests {
    use super::*;

    const AGENT: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
    const OTHER_AGENT: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

    fn refused(e: ApiError) -> String {
        match e {
            ApiError::Unauthorized(m) => m,
            other => panic!("expected a refusal, got {:?}", other),
        }
    }

    #[test]
    fn an_agent_reads_the_secret_its_own_wallet_stored() {
        enforce_agent_secret(AGENT, AGENT, AGENT)
            .expect("the agent's own secret must be readable by it");
    }

    /// An agent's account is public — it is in every top-up and every policy —
    /// so knowing one must buy nothing.
    #[test]
    fn another_agents_name_is_refused_however_it_was_learned() {
        let message = refused(
            enforce_agent_secret(AGENT, OTHER_AGENT, OTHER_AGENT)
                .expect_err("one agent must not read a secret addressed to another"),
        );
        assert!(
            message.contains("different agent"),
            "the refusal must say why: {message}"
        );
    }

    /// THE test of this section. `store_secrets` is open to anyone and the name
    /// is public, so a stranger can absolutely put a secret on chain under an
    /// agent's name — with themselves as owner, which is the one thing they
    /// cannot fake. Reading it would mean the connector running on THEIR
    /// mailbox, THEIR token.
    #[test]
    fn a_secret_planted_under_the_agents_name_by_someone_else_is_refused() {
        let message = refused(
            enforce_agent_secret(AGENT, "mallory.near", AGENT)
                .expect_err("a secret owned by anyone but the agent must be refused"),
        );
        assert!(
            message.contains("not left by the agent"),
            "the refusal must say why: {message}"
        );

        // Including when the planter is another agent, whose owner field is
        // just as implicit-account-shaped as the real one.
        refused(
            enforce_agent_secret(AGENT, OTHER_AGENT, AGENT)
                .expect_err("another agent is a stranger too"),
        );
    }

    /// Ordinary secrets keep working exactly as before. This is the check's
    /// blast radius, and it has to stay at zero for every name a human types.
    #[test]
    fn an_ordinary_profile_is_not_subject_to_the_rule() {
        for profile in ["production", "default", "staging", "7", "balance", ""] {
            enforce_agent_secret("alice.near", "bob.near", profile)
                .unwrap_or_else(|e| panic!("profile {profile:?} must pass untouched: {e:?}"));
        }
    }

    /// A named account is not shaped like an implicit one, so a human storing a
    /// secret under their own name — and letting others read it through an
    /// access condition — is untouched.
    #[test]
    fn a_named_account_never_triggers_the_rule() {
        enforce_agent_secret("alice.near", "alice.near", "alice.near").unwrap();
        enforce_agent_secret("mallory.near", "alice.near", "alice.near").unwrap();
    }

    /// The shape decides whether the rule fires at all, and it now comes from
    /// `shared_tee_helpers` — the same function the coordinator asks before it
    /// addresses a secret.
    ///
    /// The shape itself is tested there. What this pins is that the RULE is
    /// driven by it: a profile of that shape must be policed, and one of any
    /// other shape must pass untouched. Both halves have a silent failure —
    /// too wide and a human's secret falls under a rule written for agents, too
    /// narrow and an agent's connector credential is guarded by nothing.
    #[test]
    fn the_rule_fires_on_exactly_the_shared_account_shape() {
        for agentish in [AGENT, &"0".repeat(64), &"f".repeat(64)] {
            assert!(shared_tee_helpers::is_implicit_account(agentish));
            enforce_agent_secret("someone.near", agentish, agentish)
                .expect_err("a profile of this shape must be policed");
        }

        for ordinary in ["alice.near", &AGENT[..63], &AGENT.to_uppercase(), "production"] {
            assert!(!shared_tee_helpers::is_implicit_account(ordinary));
            enforce_agent_secret("someone.near", "other.near", ordinary)
                .expect("a profile of any other shape must pass untouched");
        }
    }
}

/// What stops either signing endpoint from becoming a transaction-forging
/// oracle.
///
/// Both sign with `wallet:{id}:near` — the wallet's own NEAR transaction key —
/// so a signature over an attacker-chosen 32-byte hash would BE a valid
/// transaction signature. Neither endpoint accepts a hash, and each blocks the
/// preimage by a different structural argument. Those arguments are load-bearing
/// and invisible in the code, which is what these tests are for.
#[cfg(test)]
mod signing_oracle_tests {
    use super::*;

    /// The first four bytes of a borsh-serialised NEAR transaction are the u32
    /// little-endian length of `signer_id`, and an account id is at most 64
    /// bytes. So ANY preimage whose first four bytes read as a larger number
    /// cannot be a transaction — which is the whole reason the domain string
    /// goes first.
    const MAX_ACCOUNT_ID_LEN: u32 = 64;

    fn first_u32_le(bytes: &[u8]) -> u32 {
        u32::from_le_bytes(bytes[..4].try_into().unwrap())
    }

    /// `/wallet/sign-secret-store` builds its own message, and the domain prefix
    /// is what makes it unusable as a transaction. Drop the prefix and this
    /// fails — which is the point, because nothing else would notice.
    #[test]
    fn the_secret_store_message_cannot_be_a_transaction() {
        let message = secret_store_message(
            "ed25519:aa",
            "connectors.outlayer.near/near-email",
            "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
            "Y2lwaGVy",
            "payer.near",
            "",
            "\"AllowAll\"",
        );

        // The DOMAIN is `store_secrets_for:`, and it deliberately did NOT move
        // when the contract method was renamed to
        // `store_agent_secret`. A domain's job is to be a unique,
        // non-transaction-shaped prefix that both sides agree on; renaming it
        // to follow a method name would invalidate every signature in flight
        // and buy nothing. It is a protocol constant, not a label.
        assert!(
            message.starts_with("store_secrets_for:"),
            "the domain must come FIRST — a prefix in the middle protects nothing"
        );
        assert!(
            first_u32_le(message.as_bytes()) > MAX_ACCOUNT_ID_LEN,
            "read as borsh, this preimage claims a signer_id longer than any \
             account can be, so no transaction has this shape"
        );
    }

    /// Byte-for-byte the string the contract rebuilds. Pinned, because the two
    /// sides never compare notes: a drifted format shows up as signatures the
    /// contract silently rejects, on a path nobody exercises until launch.
    #[test]
    fn the_secret_store_message_format_is_pinned() {
        // The contract pins the SAME string, from its own types, in
        // `contract/src/secrets.rs`. The two sides never compare notes at run
        // time — a drifted format shows up as signatures the contract silently
        // rejects — so the agreement is held by these two tests reading alike.
        assert_eq!(
            secret_store_message(
                "ed25519:ab",
                "a.near/p",
                "agent",
                "cipher",
                "payer.near",
                "",
                "\"AllowAll\"",
            ),
            "store_secrets_for:v1:ed25519:ab:8:a.near/p:agent:cipher:payer.near::\"AllowAll\""
        );

        // A vault-bound secret names its vault, and an absent vault leaves an
        // empty field rather than dropping one — a dropped field would shift
        // every field after it.
        assert_eq!(
            secret_store_message(
                "ed25519:ab",
                "a.near/p",
                "agent",
                "cipher",
                "payer.near",
                "vault.alice.near",
                "\"AllowAll\"",
            ),
            "store_secrets_for:v1:ed25519:ab:8:a.near/p:agent:cipher:payer.near:vault.alice.near:\"AllowAll\""
        );

        // `access` is LAST because it is JSON and may contain colons. Anything
        // earlier would make the boundaries ambiguous — except the accessor,
        // which is allowed to because the `8:` in front of it says how long it
        // is.
        let nested = secret_store_message(
            "ed25519:ab",
            "a.near/p",
            "agent",
            "cipher",
            "payer.near",
            "",
            "{\"Whitelist\":{\"accounts\":[\"a.near\"]}}",
        );
        assert!(nested.ends_with("{\"Whitelist\":{\"accounts\":[\"a.near\"]}}"));
    }

    /// The domain is `store_secrets_for:v1:`, and both sides must write it.
    ///
    /// It stayed at v1 through the length-prefix change deliberately. A version
    /// exists to keep two formats apart in the wild, and there is no v1 in the
    /// wild: the mechanism has never been on mainnet, and the only testnet
    /// secrets under the earlier format are ours. Bumping would have marked a
    /// boundary nobody is on either side of.
    ///
    /// The string is load-bearing regardless: the CONTRACT rebuilds it to
    /// verify, so a side writing anything else produces signatures the other
    /// silently rejects. Pinned here and there.
    #[test]
    fn the_domain_is_pinned() {
        let m = secret_store_message("ed25519:ab", "a.near/p", "agent", "c", "p.near", "", "\"AllowAll\"");
        assert!(m.starts_with("store_secrets_for:v1:"));
        assert!(
            !m.contains(":v2:"),
            "there is no v2 — the length prefix arrived inside v1, before anyone was using it"
        );
    }

    /// Every argument that decides what gets stored is inside the signature.
    ///
    /// Leave one out and a payer holding a signed call can resend the same
    /// bytes with that argument changed. For the PROJECT, nothing would leak —
    /// the ciphertext is sealed to one project's seed and decrypts under no
    /// other — but an authorisation that does not cover what it authorises
    /// holds only while a second, unrelated fact stays true. That is the shape
    /// this test exists to keep.
    #[test]
    fn changing_any_signed_field_changes_the_message() {
        let m = |pk, proj, prof, ct, payer, vault, access| {
            secret_store_message(pk, proj, prof, ct, payer, vault, access)
        };
        let base = m("ed25519:ab", "a.near/p", "agent", "cipher", "payer.near", "", "\"AllowAll\"");

        for other in [
            m("ed25519:cd", "a.near/p", "agent", "cipher", "payer.near", "", "\"AllowAll\""),
            m("ed25519:ab", "b.near/q", "agent", "cipher", "payer.near", "", "\"AllowAll\""),
            m("ed25519:ab", "a.near/p", "other", "cipher", "payer.near", "", "\"AllowAll\""),
            m("ed25519:ab", "a.near/p", "agent", "other", "payer.near", "", "\"AllowAll\""),
            m("ed25519:ab", "a.near/p", "agent", "cipher", "thief.near", "", "\"AllowAll\""),
            // The two that were added: who may READ it, and which master seals
            // it. Both were outside the signature at first.
            m("ed25519:ab", "a.near/p", "agent", "cipher", "payer.near", "vault.x.near", "\"AllowAll\""),
            m("ed25519:ab", "a.near/p", "agent", "cipher", "payer.near", "", "{\"Whitelist\":{\"accounts\":[\"thief.near\"]}}"),
        ] {
            assert_ne!(base, other, "a changed argument must change the message");
        }
    }

    /// The delete message, byte for byte, as `contract/src/secrets.rs` rebuilds
    /// it. Same reason as the store's pin: the two sides never compare notes at
    /// run time, so a drift shows up only as signatures the contract rejects.
    #[test]
    fn the_secret_delete_message_format_is_pinned() {
        assert_eq!(
            secret_delete_message("ed25519:ab", "a.near/p", "agent", "payer.near"),
            "delete_agent_secret:v1:ed25519:ab:8:a.near/p:agent:payer.near"
        );

        // A WASM-scoped secret is named by the contract's `wasm:` binding, and
        // the length in front of it counts THAT string, prefix included.
        assert_eq!(
            secret_delete_message("ed25519:ab", "wasm:beef", "agent", "payer.near"),
            "delete_agent_secret:v1:ed25519:ab:9:wasm:beef:agent:payer.near"
        );
    }

    /// A signature obtained to STORE must not destroy anything, and a delete
    /// signature must not store.
    ///
    /// Asserted on the DOMAIN rather than on the two strings differing: they
    /// also differ by field count, so an equality check between them would pass
    /// even if both domains read `store_secrets_for:` — which is the failure
    /// this test exists for and the one it used to miss.
    #[test]
    fn a_store_signature_cannot_delete() {
        let store = secret_store_message(
            "ed25519:ab",
            "a.near/p",
            "agent",
            "cipher",
            "payer.near",
            "",
            "\"AllowAll\"",
        );
        let delete = secret_delete_message("ed25519:ab", "a.near/p", "agent", "payer.near");

        assert!(store.starts_with("store_secrets_for:v1:"));
        assert!(delete.starts_with("delete_agent_secret:v1:"));
        assert!(
            !delete.starts_with("store_secrets_for:"),
            "one domain for both verbs would make a store signature a licence to delete"
        );
        assert!(
            first_u32_le(delete.as_bytes()) > MAX_ACCOUNT_ID_LEN,
            "the delete preimage must be unusable as a transaction too"
        );
    }

    /// Every field of a delete is inside its signature.
    ///
    /// A delete is the operation where an unbound field costs the most: the
    /// pair `(args, signature)` is public on chain forever, so anything left
    /// outside can be varied by whoever finds it.
    #[test]
    fn changing_any_delete_field_changes_the_message() {
        let base = secret_delete_message("ed25519:ab", "a.near/p", "agent", "payer.near");
        for other in [
            secret_delete_message("ed25519:cd", "a.near/p", "agent", "payer.near"),
            secret_delete_message("ed25519:ab", "b.near/q", "agent", "payer.near"),
            secret_delete_message("ed25519:ab", "a.near/p", "other", "payer.near"),
            secret_delete_message("ed25519:ab", "a.near/p", "agent", "thief.near"),
        ] {
            assert_ne!(base, other, "a changed argument must change the message");
        }
    }

    /// The policy message, byte for byte, as `contract/src/wallet.rs` rebuilds
    /// it.
    ///
    /// This one is newer than the others and was added to close a hole rather
    /// than to describe one: the contract used to verify a policy signature
    /// over the BARE `sha256(encrypted_data)`, which any other signature of
    /// this wallet satisfied.
    #[test]
    fn the_policy_store_message_format_is_pinned() {
        assert_eq!(
            policy_store_message("ed25519:ab", "Y2lwaGVy", "alice.near"),
            "store_wallet_policy:v1:ed25519:ab:8:Y2lwaGVy:alice.near"
        );
    }

    /// No signature of another verb can be a policy, and no policy signature
    /// can be another verb.
    ///
    /// Asserted on the DOMAINS, because that is the property: three messages
    /// that begin differently cannot be substituted for one another however
    /// their remaining fields line up.
    #[test]
    fn the_three_domains_are_distinct() {
        let policy = policy_store_message("ed25519:ab", "cipher", "alice.near");
        let store = secret_store_message(
            "ed25519:ab",
            "a.near/p",
            "agent",
            "cipher",
            "alice.near",
            "",
            "\"AllowAll\"",
        );
        let delete = secret_delete_message("ed25519:ab", "a.near/p", "agent", "alice.near");

        assert!(policy.starts_with("store_wallet_policy:v1:"));
        assert!(store.starts_with("store_secrets_for:v1:"));
        assert!(delete.starts_with("delete_agent_secret:v1:"));
        assert!(
            first_u32_le(policy.as_bytes()) > MAX_ACCOUNT_ID_LEN,
            "the policy preimage must be unusable as a transaction too"
        );
    }

    /// Every field of a policy signature is inside it — including the account
    /// that may send it.
    #[test]
    fn changing_any_policy_field_changes_the_message() {
        let base = policy_store_message("ed25519:ab", "cipher", "alice.near");
        for other in [
            policy_store_message("ed25519:cd", "cipher", "alice.near"),
            policy_store_message("ed25519:ab", "other", "alice.near"),
            policy_store_message("ed25519:ab", "cipher", "thief.near"),
        ] {
            assert_ne!(base, other, "a changed argument must change the message");
        }
    }

    /// The seeds this endpoint seals to are the ones the READ path rebuilds.
    ///
    /// Written out literally rather than by calling the same helper, because a
    /// helper compared against itself agrees by construction. These strings are
    /// copied from the `/decrypt` and `/get-or-create-secrets` match arms; if
    /// one of those is edited, this is what says so — and the symptom it
    /// replaces is a secret that stores fine and cannot be read months later.
    #[test]
    fn the_agent_seeds_match_the_read_path() {
        let agent = "a1b2c3";
        assert_eq!(
            AgentSecretTarget::Project("owner.near/app".to_string()).seed(agent),
            format!("project:{}:{}", "owner.near/app", agent)
        );
        assert_eq!(
            AgentSecretTarget::WasmHash("beef".to_string()).seed(agent),
            format!("wasm_hash:{}:{}", "beef", agent)
        );
    }

    /// The binding is the CONTRACT's spelling, which is not the seed's.
    ///
    /// `wasm:` in the signed message, `wasm_hash:` in the seed. Two strings for
    /// two jobs; swapping them produces either a signature the contract rejects
    /// or a secret the worker cannot open, and neither failure names the cause.
    #[test]
    fn the_bindings_are_the_contracts_spelling() {
        assert_eq!(
            AgentSecretTarget::Project("owner.near/app".to_string()).binding(),
            "owner.near/app"
        );
        assert_eq!(
            AgentSecretTarget::WasmHash("beef".to_string()).binding(),
            "wasm:beef"
        );
    }

    /// One scope or the other, never both and never neither.
    #[test]
    fn an_agent_secret_names_exactly_one_scope() {
        assert_eq!(
            AgentSecretTarget::from_fields(Some("a.near/p"), None).unwrap(),
            AgentSecretTarget::Project("a.near/p".to_string())
        );
        assert_eq!(
            AgentSecretTarget::from_fields(None, Some("beef")).unwrap(),
            AgentSecretTarget::WasmHash("beef".to_string())
        );

        // Blank is not a choice: an empty string would otherwise seal a secret
        // to `project::{agent}` and look like a project scope forever after.
        assert!(AgentSecretTarget::from_fields(Some("   "), None).is_err());
        assert!(AgentSecretTarget::from_fields(None, None).is_err());
        assert!(AgentSecretTarget::from_fields(Some("a.near/p"), Some("beef")).is_err());
    }

    /// A shouted hash is the same hash.
    ///
    /// The contract lowercases the accessor before it becomes a storage key, so
    /// the worker reads it back in lower case and rebuilds a lower-case seed. A
    /// secret sealed here under the shouted spelling would be one nothing can
    /// open — and the signature would name an accessor the contract does not
    /// store, so it would not even land.
    #[test]
    fn a_wasm_hash_is_lowercased_to_match_the_chain() {
        let target = AgentSecretTarget::from_fields(None, Some("BEEF")).unwrap();
        assert_eq!(target, AgentSecretTarget::WasmHash("beef".to_string()));
        assert_eq!(target.binding(), "wasm:beef");
        assert_eq!(target.seed("agent"), "wasm_hash:beef:agent");
    }

    /// `/wallet/sign-policy` has a domain NOW, but the older argument still
    /// holds and is worth keeping: what protected it before was the ORDER — the
    /// base64 decode and the AEAD decrypt both run BEFORE the signature — and
    /// the first of those is what this pins. Two independent reasons a
    /// transaction cannot come out of that endpoint are better than one.
    ///
    /// A transaction's borsh has NUL bytes in the length prefix, and NUL is not
    /// in the base64 alphabet, so a preimage that survives decoding cannot be
    /// one. Move the signing above the decode and this argument evaporates.
    #[test]
    fn a_transaction_preimage_is_not_valid_base64() {
        // A plausible transaction: signer_id of 10 bytes, then the account.
        let mut tx = Vec::new();
        tx.extend_from_slice(&10u32.to_le_bytes());
        tx.extend_from_slice(b"alice.near");
        tx.extend_from_slice(&[0u8; 32]); // public key
        assert!(
            first_u32_le(&tx) <= MAX_ACCOUNT_ID_LEN,
            "a real transaction starts with a plausible account length"
        );

        let as_text = String::from_utf8_lossy(&tx).to_string();
        assert!(
            base64::decode(&as_text).is_err(),
            "a transaction preimage must not survive the base64 decode that \
             happens before /wallet/sign-policy signs anything"
        );
    }
}

#[cfg(test)]
mod reserved_keys_tests {
    use super::{reject_reserved_secret_keys, RESERVED_SECRET_KEYS};

    /// The check every door shares: refuse, name every offender, leave
    /// everything else alone.
    #[test]
    fn the_shared_check_refuses_every_reserved_name_and_nothing_else() {
        for name in RESERVED_SECRET_KEYS {
            let err = reject_reserved_secret_keys([*name].into_iter())
                .expect_err("a reserved name must be refused");
            assert!(
                format!("{err:?}").contains(name),
                "the refusal for {name} does not say which key was wrong, so the owner has to \
                 guess which of their secrets to rename"
            );
        }
        assert!(reject_reserved_secret_keys(["API_KEY", "DB_URL"].into_iter()).is_ok());
        // Case matters: the environment is case-sensitive, so a lowercase
        // spelling is a different variable and reserving it would take a name
        // from the owner for nothing.
        assert!(reject_reserved_secret_keys(["wallet_id"].into_iter()).is_ok());

        // All offenders in one answer — an owner editing a JSON blob should
        // need one round trip, not one per key.
        let err =
            reject_reserved_secret_keys(["API_KEY", "WALLET_ID", "NEAR_SENDER_ID"].into_iter())
                .expect_err("a batch containing reserved names must be refused");
        let text = format!("{err:?}");
        assert!(text.contains("WALLET_ID") && text.contains("NEAR_SENDER_ID"), "{text}");
        assert!(!text.contains("API_KEY"), "a legal key was named as an offender: {text}");
    }

    /// The worker's list of injected variables, read from its source.
    ///
    /// A cross-crate read rather than a shared constant on purpose: the two
    /// binaries ship in different images and are deployed separately, so a
    /// compile-time dependency would say nothing about what is actually
    /// running. What matters is that whoever EDITS the worker is told, in the
    /// same working tree, that the keystore has to change too.
    fn worker_system_env_vars() -> Vec<String> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../worker/src/main.rs");
        let src = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("cannot read the worker source at {path}: {e}"));
        let (_, after) = src
            .split_once("pub const SYSTEM_ENV_VARS: &[&str] = &[")
            .expect("worker::SYSTEM_ENV_VARS — the list this test exists to follow — is gone");
        let (body, _) = after
            .split_once("];")
            .expect("SYSTEM_ENV_VARS is not terminated");

        let mut names = Vec::new();
        let mut rest = body;
        while let Some(open) = rest.find('"') {
            let after_open = &rest[open + 1..];
            let Some(close) = after_open.find('"') else { break };
            names.push(after_open[..close].to_string());
            rest = &after_open[close + 1..];
        }
        names
    }

    /// Every variable the worker injects must be refused as a secret key.
    ///
    /// Without this the two lists drift silently, and drift here is not
    /// cosmetic: a worker-injected name that is NOT reserved can be set as a
    /// secret, and the guest then reads a caller-chosen value as a fact about
    /// its run. That is how `OUTLAYER_PROJECT_OWNER`, `OUTLAYER_PROJECT_NAME`
    /// and `WALLET_ID` came to be forgeable — each was added to the worker and
    /// nobody remembered this list.
    #[test]
    fn every_worker_system_variable_is_a_reserved_secret_key() {
        let worker_vars = worker_system_env_vars();
        assert!(
            worker_vars.len() >= 20,
            "read only {} names out of worker::SYSTEM_ENV_VARS — the parse stopped matching the \
             list, so this guard is no longer guarding anything",
            worker_vars.len()
        );

        let unreserved: Vec<&String> = worker_vars
            .iter()
            .filter(|name| !RESERVED_SECRET_KEYS.contains(&name.as_str()))
            .collect();
        assert!(
            unreserved.is_empty(),
            "the worker injects {unreserved:?} into the guest, but a customer may still store \
             secrets under those names — add them to RESERVED_SECRET_KEYS"
        );
    }

    /// Every door that stores a secret has to consult the list.
    ///
    /// The two tests around this one compare LISTS. This one compares
    /// HANDLERS, and it exists because the gap that was found was neither list
    /// being wrong: `update_user_secrets` simply never asked. A list guard
    /// cannot see a door that does not consult it, which is why the hole
    /// survived a round of auditing that was looking straight at the lists.
    ///
    /// The set is derived from the source rather than written here: a handler
    /// counts if it works with a map of secret keys at all, so a fourth door
    /// added tomorrow is held to the same rule on the day it appears.
    #[test]
    fn every_handler_that_stores_secrets_refuses_reserved_names() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/api.rs");
        let src = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
        // Stop at the tests. This module names the same things it looks for,
        // and the last handler's chunk would otherwise run to end-of-file and
        // pass on the strength of this comment.
        let code = src.split("#[cfg(test)]").next().unwrap_or_default();
        // Both spellings are used at file scope; one form to split on.
        let normalized = code.replace("\npub async fn ", "\nasync fn ");

        let mut handles_secrets: Vec<(&str, bool)> = Vec::new();
        let mut chunks = normalized.split("\nasync fn ");
        chunks.next(); // everything before the first handler
        for chunk in chunks {
            let name = chunk.split('(').next().unwrap_or("").trim();
            // A body that names a secrets map is a body that can write one.
            // Deliberately loose: a false positive costs one call to the
            // guard, a false negative is the bug this test is about.
            if !(chunk.contains("secrets_map") || chunk.contains("req.secrets")) {
                continue;
            }
            handles_secrets.push((name, chunk.contains("reject_reserved_secret_keys")));
        }

        // The scan itself, pinned: if a rename or a reformat makes it stop
        // seeing handlers, an empty set would otherwise satisfy every
        // assertion below.
        for expected in ["pubkey_handler", "add_generated_secret_handler", "update_user_secrets_handler"] {
            assert!(
                handles_secrets.iter().any(|(name, _)| *name == expected),
                "the scan no longer finds {expected}, so this guard is guarding nothing — \
                 found: {:?}",
                handles_secrets.iter().map(|(n, _)| *n).collect::<Vec<_>>()
            );
        }

        let unguarded: Vec<&str> = handles_secrets
            .iter()
            .filter(|(_, guarded)| !guarded)
            .map(|(name, _)| *name)
            .collect();
        assert!(
            unguarded.is_empty(),
            "these handlers work with secret keys without calling \
             reject_reserved_secret_keys: {unguarded:?} — a caller can store a name the worker \
             injects, and the only thing left standing is the worker's own strip"
        );
    }

    /// The reverse direction is a WARNING, not a failure: reserving a name the
    /// worker does not inject costs a customer a key name and nothing else, and
    /// un-reserving one is itself a breaking change. So this test only pins the
    /// names that are deliberately reserved beyond the worker's list — today,
    /// none — so that the set is a decision rather than an accident.
    #[test]
    fn nothing_is_reserved_without_a_reason() {
        let worker_vars = worker_system_env_vars();
        let extra: Vec<&&str> = RESERVED_SECRET_KEYS
            .iter()
            .filter(|k| !worker_vars.iter().any(|w| w == *k))
            .collect();
        assert!(
            extra.is_empty(),
            "these keys are reserved but the worker never injects them: {extra:?} — either the \
             worker dropped a variable (then drop it here too) or the reservation needs a comment \
             saying what it is for"
        );
    }
}

#[cfg(test)]
mod the_door_judges_one_condition_for_one_caller {
    //! `judge_access` is the one place a stored condition becomes a verdict
    //! for a decrypt; the handler calls nothing else. An unreadable pattern is
    //! a 401 that names it — wherever it sits — and nothing is admitted on an
    //! error.
    use super::*;
    use crate::types::{AccessCondition, ComparisonOperator, LogicOperator, RunFacts};

    fn bad() -> AccessCondition {
        AccessCondition::AccountPattern { pattern: "(".to_string() }
    }

    #[tokio::test]
    async fn a_bad_pattern_under_not_is_a_401_naming_the_pattern() {
        let not_bad = AccessCondition::Not { condition: Box::new(bad()) };
        match judge_access(&not_bad, "anyone.near", None, RunFacts::default()).await {
            Err(ApiError::Unauthorized(m)) => {
                assert!(m.contains("AccountPattern `(`") && m.contains("cannot be compiled"), "{m}");
            }
            other => panic!("Not over an unreadable leaf must refuse with the pattern named, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_bad_leaf_under_or_and_and_is_the_same_401() {
        let or = AccessCondition::Logic {
            operator: LogicOperator::Or,
            conditions: vec![AccessCondition::Whitelist { accounts: vec!["bob.near".into()] }, bad()],
        };
        let and = AccessCondition::Logic { operator: LogicOperator::And, conditions: vec![AccessCondition::AllowAll, bad()] };
        for c in [or, and] {
            assert!(matches!(judge_access(&c, "alice.near", None, RunFacts::default()).await, Err(ApiError::Unauthorized(m)) if m.contains("cannot be compiled")));
        }
    }

    #[tokio::test]
    async fn a_denial_carries_the_conditions_own_sentence() {
        let wl = AccessCondition::Whitelist { accounts: vec!["bob.near".into()] };
        match judge_access(&wl, "alice.near", None, RunFacts::default()).await {
            Err(ApiError::Unauthorized(m)) => assert!(m.starts_with("Access denied by access condition"), "{m}"),
            other => panic!("{other:?}"),
        }
        assert!(judge_access(&wl, "bob.near", None, RunFacts::default()).await.is_ok());
        assert!(judge_access(&AccessCondition::AllowAll, "anyone.near", None, RunFacts::default()).await.is_ok());
    }

    #[tokio::test]
    async fn a_lapsed_grant_is_named_to_the_caller_it_bound_and_to_nobody_else() {
        let dated = |a: &str| AccessCondition::Logic {
            operator: LogicOperator::And,
            conditions: vec![
                AccessCondition::Whitelist { accounts: vec![a.into()] },
                AccessCondition::ValidUntil { until_ns: "1".into() },
            ],
        };
        let grants = AccessCondition::Logic {
            operator: LogicOperator::Or,
            conditions: vec![AccessCondition::Whitelist { accounts: vec!["owner.near".into()] }, dated("agent.near")],
        };
        match judge_access(&grants, "agent.near", None, RunFacts::default()).await {
            Err(ApiError::Unauthorized(m)) => assert!(m.ends_with("its time limit passed at 1970-01-01T00:00:00Z"), "{m}"),
            other => panic!("{other:?}"),
        }
        match judge_access(&grants, "stranger.near", None, RunFacts::default()).await {
            Err(ApiError::Unauthorized(m)) => assert_eq!(m, "Access denied by access condition", "not named, so no date"),
            other => panic!("{other:?}"),
        }
        assert!(judge_access(&grants, "owner.near", None, RunFacts::default()).await.is_ok());
    }

    #[tokio::test]
    async fn a_condition_past_the_pattern_bounds_is_refused_whole_before_any_compile() {
        let leaf = |i: usize| AccessCondition::AccountPattern { pattern: format!("a{i}\\.near") };
        let mut seventeen: Vec<_> = (0..17).map(leaf).collect();
        seventeen.push(AccessCondition::AllowAll);
        let tree = AccessCondition::Logic { operator: LogicOperator::Or, conditions: seventeen };
        match judge_access(&tree, "anyone.near", None, RunFacts::default()).await {
            Err(ApiError::Unauthorized(m)) => assert!(m.contains("17 AccountPattern leaves"), "{m}"),
            other => panic!("AllowAll beside 17 patterns must still refuse: {other:?}"),
        }
        let sixteen = AccessCondition::Logic { operator: LogicOperator::Or, conditions: (0..16).map(leaf).chain([AccessCondition::AllowAll]).collect() };
        assert!(judge_access(&sixteen, "anyone.near", None, RunFacts::default()).await.is_ok());
    }

    /// The deadline: it fires, firing is a REFUSAL, and a verdict that arrives
    /// in time is passed through untouched. On a paused clock, so the test
    /// costs no wall time and cannot flake.
    #[tokio::test]
    async fn the_evaluation_deadline_refuses_and_never_admits() {
        let tiny = std::time::Duration::from_millis(5);
        // Fires: a future that outlasts it yields an error, not a verdict —
        // and the verdict it would have produced is an ADMISSION, so this is
        // the case that must not leak through.
        let slow = async {
            tokio::time::sleep(tiny * 20).await;
            Ok::<bool, anyhow::Error>(true)
        };
        match within_deadline(tiny, slow).await {
            Err(ApiError::InternalError(m)) => {
                assert!(m.contains("could not be evaluated within"), "{m}");
                // Not a verdict about the caller: a 401 here would read as
                // "denied by the condition", and an Ok would admit.
            }
            other => panic!("a deadline that fires must refuse: {other:?}"),
        }

        // Does not fire: a verdict inside the deadline arrives as it was.
        let quick = async { Ok::<bool, anyhow::Error>(true) };
        let inner = within_deadline(ACCESS_EVALUATION_DEADLINE, quick).await.expect("inside the deadline");
        assert!(inner.expect("no error"), "a verdict must pass through untouched");

        let refused = async { Ok::<bool, anyhow::Error>(false) };
        assert!(!within_deadline(ACCESS_EVALUATION_DEADLINE, refused).await.unwrap().unwrap());
    }

    /// The chain-read bound is refused at the door, before the chain is asked
    /// once — and the ORDER is the point: five leaves get past the bound and
    /// fail on the missing client, six never reach it.
    #[tokio::test]
    async fn a_condition_past_the_chain_read_bound_never_asks_the_chain() {
        let read = || AccessCondition::NearBalance {
            operator: crate::types::ComparisonOperator::Gte,
            value: "1".to_string(),
        };
        let tree = |n: usize| AccessCondition::Logic {
            operator: LogicOperator::Or,
            conditions: (0..n).map(|_| read()).collect(),
        };

        match judge_access(&tree(6), "anyone.near", None, RunFacts::default()).await {
            Err(ApiError::Unauthorized(m)) => {
                assert!(m.contains("asks the chain 6 times"), "{m}");
            }
            other => panic!("six chain reads must be refused by the bound: {other:?}"),
        }

        // Five are within the bound, so the refusal that follows is the
        // missing client — the bound did not answer for it.
        match judge_access(&tree(5), "anyone.near", None, RunFacts::default()).await {
            Err(ApiError::InternalError(m)) => {
                assert!(!m.contains("asks the chain"), "the bound answered for five: {m}");
                assert!(m.contains("no NEAR client"), "{m}");
            }
            other => panic!("five chain reads must reach evaluation: {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_chain_read_that_cannot_run_is_this_services_failure_not_an_admission() {
        let balance = AccessCondition::NearBalance { operator: ComparisonOperator::Gte, value: "1".into() };
        assert!(matches!(judge_access(&balance, "anyone.near", None, RunFacts::default()).await, Err(ApiError::InternalError(_))));
        let negated = AccessCondition::Not { condition: Box::new(balance) };
        assert!(matches!(judge_access(&negated, "anyone.near", None, RunFacts::default()).await, Err(ApiError::InternalError(_))));
    }
}

/// What `/decrypt-raw` will serve.
///
/// The handler derives a key from the seed the CALLER names and hands back the
/// plaintext without consulting any access condition, so the set of seeds it
/// answers for IS its access control. Every blob below is encrypted under the
/// very seed the request carries, so it WOULD decrypt: a refusal here is the
/// prefix refusing, not base64 or the AEAD, which is the only way this test
/// says anything.
#[cfg(test)]
mod decrypt_raw_serves_the_top_up_flow_only {
    use super::tests::test_state;
    use super::*;

    const PLAINTEXT: &[u8] = br#"{"owner":"alice.testnet","initial_balance":"1000000"}"#;

    async fn decryptable_under(state: &AppState, seed: &str) -> DecryptRawRequest {
        let blob = state
            .keystore
            .read()
            .await
            .encrypt(None, seed, PLAINTEXT)
            .expect("the test's own blob must encrypt");
        DecryptRawRequest {
            seed: seed.to_string(),
            encrypted_base64: base64::encode(&blob),
        }
    }

    #[tokio::test]
    async fn the_top_up_seed_is_served_and_every_other_shape_is_refused() {
        let state = test_state();
        // A keystore that is not ready refuses everything with a different
        // error, which would make every assertion below pass for nothing.
        assert!(state.is_ready(), "the fixture must be past the readiness gate");

        // The seed the top-up flow builds — `worker/src/main.rs`, and the
        // `System` arm of `decrypt_handler`: system:payment_key:{owner}:{nonce}.
        let req = decryptable_under(&state, "system:payment_key:alice.testnet:7").await;
        let served = decrypt_raw_handler(State(state.clone()), axum::http::HeaderMap::new(), Json(req))
            .await
            .expect("the flow this handler exists for must still work");
        assert_eq!(
            base64::decode(&served.0.plaintext_base64).expect("base64"),
            PLAINTEXT,
            "the served plaintext must be the blob's own"
        );

        // Every other seed this keystore derives keys for, in the shape the
        // code writes it. Each names a row whose reader is decided by an access
        // condition that THIS handler never reads.
        for seed in [
            "project:alice.testnet/app:alice.testnet",
            "github.com/alice/app:alice.testnet",
            "wasm_hash:d39dfee85c0085604e516d37f83032ed98abba4a43322ed4b5c455b33c13c8f7:alice.testnet",
            "wallet-policy:0123456789abcdef",
            // The narrowing: `system:` alone is not the pass. A system type
            // added later is refused here until someone decides otherwise,
            // rather than becoming readable the day it is introduced.
            "system:something_later:alice.testnet:1",
            "",
        ] {
            let req = decryptable_under(&state, seed).await;
            match decrypt_raw_handler(State(state.clone()), axum::http::HeaderMap::new(), Json(req)).await {
                Err(ApiError::BadRequest(message)) => assert!(
                    message.contains("system:payment_key:") && message.contains("/decrypt"),
                    "the refusal must name the one seed this door serves and where a stored secret is read instead: {message}"
                ),
                Err(other) => panic!("{seed:?} was refused, but not by the prefix: {other:?}"),
                Ok(_) => panic!("{seed:?} was SERVED: this handler reads it with no condition judged"),
            }
        }
    }

    /// The prefix is a prefix of the whole seed, not a substring of it: a seed
    /// that merely CONTAINS the marker is not the top-up flow's.
    #[tokio::test]
    async fn the_marker_has_to_start_the_seed() {
        let state = test_state();
        for seed in [
            "project:alice.testnet/system:payment_key:x:alice.testnet",
            " system:payment_key:alice.testnet:7",
            "SYSTEM:PAYMENT_KEY:alice.testnet:7",
        ] {
            let req = decryptable_under(&state, seed).await;
            assert!(
                matches!(
                    decrypt_raw_handler(State(state.clone()), axum::http::HeaderMap::new(), Json(req)).await,
                    Err(ApiError::BadRequest(_))
                ),
                "{seed:?} must not pass as a payment-key seed"
            );
        }
    }
}

/// The decrypt door, where a build lock decides whether a run sees a secret.
///
/// `judge_access` is the only door; the tests above cover the other leaves.
/// These three are about the build: that a wrong one refuses with the owner's
/// sentence, that a request which names no build FAILS rather than passes, and
/// that a worker too old to name one still reads every row without a lock.
#[cfg(test)]
mod the_door_judges_a_build_lock {
    use super::*;
    use crate::types::{AccessCondition, LogicOperator, RunFacts};

    const RUNNING: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const OTHER: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    /// A request that names the running build and no calling account.
    fn running() -> RunFacts<'static> {
        RunFacts { executed_wasm_sha256: Some(RUNNING), ..Default::default() }
    }

    fn locked_to(hash: &str) -> AccessCondition {
        AccessCondition::Logic {
            operator: LogicOperator::And,
            conditions: vec![
                AccessCondition::Whitelist { accounts: vec!["alice.near".into()] },
                AccessCondition::WasmHash { hash: hash.to_string() },
            ],
        }
    }

    #[tokio::test]
    async fn the_running_build_passes_and_another_is_a_401_naming_both() {
        assert!(judge_access(&locked_to(RUNNING), "alice.near", None, running()).await.is_ok());
        match judge_access(&locked_to(OTHER), "alice.near", None, running()).await {
            Err(ApiError::Unauthorized(m)) => {
                assert!(m.contains(OTHER) && m.contains(RUNNING), "both builds are named: {m}");
            }
            other => panic!("a wrong build must be a 401, got {other:?}"),
        }
    }

    /// A worker that reports no build cannot be judged against one. This must
    /// be the service's failure (500) and never an admission: a 401 would read
    /// as "the caller is not allowed", and an `Ok` would hand a locked secret
    /// to any build at all.
    #[tokio::test]
    async fn a_request_without_a_build_is_a_500_not_an_admission() {
        match judge_access(&locked_to(RUNNING), "alice.near", None, RunFacts::default()).await {
            Err(ApiError::InternalError(m)) => assert!(m.contains("no executing wasm hash"), "{m}"),
            other => panic!("a locked row and no build must fail closed, got {other:?}"),
        }
    }

    /// The compatibility that makes the deploy order survivable: a row with no
    /// build leaf is decided exactly as before, whether or not the worker
    /// names a build.
    #[tokio::test]
    async fn a_row_with_no_lock_is_unaffected_by_the_new_field() {
        let wl = AccessCondition::Whitelist { accounts: vec!["alice.near".into()] };
        assert!(judge_access(&wl, "alice.near", None, RunFacts::default()).await.is_ok());
        assert!(judge_access(&wl, "alice.near", None, running()).await.is_ok());
        assert!(judge_access(&wl, "bob.near", None, running()).await.is_err());
    }

    /// An older worker sends no such field, and its requests must still parse.
    #[test]
    fn the_request_parses_with_and_without_the_build() {
        let old: DecryptRequest = serde_json::from_str(
            r#"{"accessor":{"type":"Project","project_id":"a.near/p"},"profile":"default",
                "owner":"a.near","user_account_id":"a.near"}"#,
        )
        .expect("a request from a worker that predates the field");
        assert_eq!(old.executed_wasm_sha256, None);

        let new: DecryptRequest = serde_json::from_str(&format!(
            r#"{{"accessor":{{"type":"Project","project_id":"a.near/p"}},"profile":"default",
                 "owner":"a.near","user_account_id":"a.near","executed_wasm_sha256":"{RUNNING}"}}"#
        ))
        .expect("a request that names the build");
        assert_eq!(new.executed_wasm_sha256.as_deref(), Some(RUNNING));
        assert_eq!(new.predecessor_id, None, "a worker that names the build but not the caller's contract");

        let full: DecryptRequest = serde_json::from_str(&format!(
            r#"{{"accessor":{{"type":"Project","project_id":"a.near/p"}},"profile":"default",
                 "owner":"a.near","user_account_id":"a.near","executed_wasm_sha256":"{RUNNING}",
                 "predecessor_id":"dao.near"}}"#
        ))
        .expect("a request that names the calling account");
        assert_eq!(full.predecessor_id.as_deref(), Some("dao.near"));
    }
}

/// A wallet with no stored policy is unrestricted, except where the engine
/// denies on everyone's behalf.
///
/// "No policy" and "an empty policy" are different statements: five capabilities
/// fall back to DENY when none is named, so judging an absent policy by an empty
/// one silently closes payment checks, raw signing, confidential ops, swaps and
/// cross-chain withdrawals — the state every wallet is in right after
/// registration. `policy_to_judge_by` is the one place that substitution is
/// made, and these tests are on that function rather than on its output, so a
/// call site that stops using it fails here.
#[cfg(test)]
mod a_wallet_with_no_policy_is_unrestricted {
    use super::policy_to_judge_by;
    use shared_tee_helpers::wallet_policy::{evaluate, Capabilities, Decision, Op, Policy};

    const NOW: u64 = 1_800_000_000;

    fn allows(stated: Option<&Policy>, op: &Op) -> bool {
        matches!(evaluate(&policy_to_judge_by(stated), op, None, NOW), Decision::Allow)
    }

    fn opt_in_ops() -> Vec<Op> {
        vec![
            Op::PaymentCheck { amount: "1".into(), token: "near".into() },
            Op::Raw { chain: "near".into(), payload_hash: "00".into(), label: None },
            Op::Confidential {
                flow: "transfer".into(),
                to: None,
                amount: "1".into(),
                token: "near".into(),
                chain: None,
                token_out: None,
                min_amount_out: None,
            },
            Op::Swap {
                token_in: "near".into(),
                amount_in: "1".into(),
                token_out: "usdc".into(),
                min_out: "1".into(),
            },
            Op::CrossChainWithdraw {
                to: "0xabc".into(),
                amount: "1".into(),
                token: "near".into(),
                chain: "eth".into(),
            },
            Op::LimitOrder {
                to: "0xabc".into(),
                to_type: shared_tee_helpers::wallet_policy::RecipientType::DestinationChain,
                amount: "1".into(),
                token: "near".into(),
                token_out: "usdc".into(),
                min_amount_out: "1".into(),
            },
        ]
    }

    #[test]
    fn every_opt_in_capability_is_open_when_the_owner_has_stated_nothing() {
        for op in opt_in_ops() {
            assert!(
                allows(None, &op),
                "a wallet with no policy was refused {:?} — the state every wallet is in right after registration",
                op.primary_type()
            );
        }
    }

    /// The owner HAS spoken: an empty policy names no capability, and the
    /// engine's defaults then apply. This is the line the stand-in must not
    /// cross — and the reason the stand-in has to exist at all.
    #[test]
    fn a_stored_policy_that_names_nothing_still_denies_them() {
        let stated = Policy::default();
        for op in opt_in_ops() {
            assert!(
                !allows(Some(&stated), &op),
                "a STATED policy admitted {:?}; the stand-in is leaking into the stated path",
                op.primary_type()
            );
        }
    }

    /// A stated policy is passed through untouched — the substitution must not
    /// add capabilities to what the owner wrote.
    #[test]
    fn a_stated_policy_is_returned_as_written() {
        let stated = Policy {
            capabilities: Some(Capabilities { payment_check: None, ..Default::default() }),
            ..Default::default()
        };
        // `Policy` carries no `PartialEq`; compare the serialised form, which is
        // what the engine reads anyway.
        let judged = policy_to_judge_by(Some(&stated));
        assert_eq!(
            serde_json::to_value(&*judged).unwrap(),
            serde_json::to_value(&stated).unwrap()
        );
    }

    /// The one rule an absent policy does NOT relax, which is why the request is
    /// evaluated instead of short-circuited to Allow. The envelope is real: an
    /// unparseable one is refused before any rule is consulted, so a test built
    /// on empty args would pass with the account-control rule deleted.
    #[test]
    fn the_extension_door_stays_shut() {
        use base64::Engine;
        let request = r#"{"request":{
            "internal":[{"op":"add_extension","payload":{"account_id":"evil.near"}}],
            "external":[{"receiver_id":"good.near",
                         "actions":[{"action":"transfer","payload":{"amount":"1"}}]}]}}"#;
        let op = Op::Call {
            to: "agent.tla".into(),
            method: "w_execute_extension".into(),
            args_base64: base64::engine::general_purpose::STANDARD.encode(request),
            gas: "100000000000000".into(),
            deposit: "1".into(),
        };
        match evaluate(&policy_to_judge_by(None), &op, None, NOW) {
            Decision::Deny { reason } => {
                assert!(reason.contains("add_extension"), "{reason}");
                assert!(reason.contains("account-control"), "{reason}");
            }
            other => panic!("a wallet with no policy handed its lane to a stranger: {other:?}"),
        }
    }
}

/// Both doors make the absent-policy substitution the same way.
///
/// The fix for the mainnet custody outage was to stop standing an EMPTY policy
/// in for an absent one. Extracting that into `policy_to_judge_by` removed the
/// duplication; this keeps it removed. A call site that goes back to
/// `Policy::default()` — or to any hand-rolled stand-in — evaluates a wallet
/// with no policy as one that allows nothing, and no unit test on the helper
/// would notice.
#[cfg(test)]
mod the_substitution_is_made_in_one_place {
    #[test]
    fn both_policy_doors_go_through_the_one_function() {
        let src = include_str!("api.rs");
        // api.rs holds production code only — the tests live in api_tests.rs —
        // so the assertions below cannot count the very strings they quote.
        let product = src;
        // The signing path and the /wallet/check-policy pre-flight.
        assert_eq!(
            product.matches("policy_to_judge_by(policy.as_ref())").count(),
            2,
            "a policy door stopped using policy_to_judge_by"
        );
        // An empty policy is never a stand-in.
        assert_eq!(
            product.matches("Policy::default()").count(),
            0,
            "an empty policy is being used as a stand-in again"
        );
    }
}
