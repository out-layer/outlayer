//! A stand-in for the partner's leased-account contract — the views our
//! pre-flight reads, and nothing else. Deployed twice per run: once as the
//! leased ACCOUNT (`hos_agent_status`, `nft_item_info`) and once as the
//! COLLECTION that account says it belongs to (`nft_token`), so that the
//! pairing of the two can be made to agree or disagree at will.
//!
//! Why this exists (test plan §10): every `hos_lease` rule we implement — the
//! grant ladder, the call-form rules, the reserve floor, the lifecycle faults,
//! the version gate — is decided by what `hos_agent_status` answers. Until the
//! partner leases us a real account we cannot make that view say "the grant
//! expired" or "the lease ran out" on a live chain, so the whole mode would be
//! provable only in unit vectors. This contract makes the view say anything a
//! test needs it to, on testnet, through the real coordinator.
//!
//! What it deliberately does NOT do: enforce anything. It is a mirror, not a
//! second implementation. Proving that the partner's contract PANICS where our
//! pre-flight refuses is their account's job, and no stub can stand in for it —
//! see the boundary §10 asks us to state plainly.
//!
//! The stored answer is raw JSON, returned verbatim. A typed struct would
//! quietly normalise exactly the malformed and truncated shapes the fail-closed
//! cases are about (a missing `state`, a `lease_until_ns` that is not a number,
//! a grant with an unknown field), and those cases are half the point.

use near_sdk::{env, near, AccountId, PanicOnDefault};

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Stub {
    owner: AccountId,
    /// Raw JSON returned by `hos_agent_status`, as a string.
    status_json: String,
    /// Raw JSON returned by `nft_item_info` (the own-collection rule reads it).
    item_info_json: String,
    /// Raw JSON returned by `nft_token`, whatever `token_id` is asked —
    /// `null` when unset, which is NEP-171 for "no such token". Lives in
    /// the instance playing the collection.
    nft_token_json: String,
    /// When set, `hos_agent_status` panics instead of answering — the
    /// "the view is unreachable / the account is not what we think" case.
    panic_message: Option<String>,
}

#[near]
impl Stub {
    #[init]
    pub fn new() -> Self {
        Self {
            owner: env::predecessor_account_id(),
            status_json: "{}".to_string(),
            item_info_json: "{}".to_string(),
            nft_token_json: "null".to_string(),
            panic_message: None,
        }
    }

    /// The view the coordinator and the keystore both read. `extension` is
    /// accepted and ignored: a stub answers for whoever asks, and a test that
    /// needs "this executor is not enabled" says so in the stored answer.
    pub fn hos_agent_status(&self, extension: Option<AccountId>) -> serde_json::Value {
        let _ = extension;
        if let Some(msg) = &self.panic_message {
            env::panic_str(msg);
        }
        serde_json::from_str(&self.status_json).unwrap_or(serde_json::Value::Null)
    }

    pub fn nft_item_info(&self) -> serde_json::Value {
        serde_json::from_str(&self.item_info_json).unwrap_or(serde_json::Value::Null)
    }

    /// Owner-only, because a stub anyone could reconfigure would make two
    /// concurrent test runs read each other's fixtures.
    pub fn set_status(&mut self, status_json: String) {
        self.assert_owner();
        self.status_json = status_json;
        self.panic_message = None;
    }

    pub fn set_item_info(&mut self, item_info_json: String) {
        self.assert_owner();
        self.item_info_json = item_info_json;
    }

    /// NEP-171 `nft_token`, as the collection answers it. The argument is
    /// accepted and ignored — a mirror answers what it was told to; a case
    /// that needs "asked about X, answered about Y" stores a Y.
    pub fn nft_token(&self, token_id: String) -> serde_json::Value {
        let _ = token_id;
        serde_json::from_str(&self.nft_token_json).unwrap_or(serde_json::Value::Null)
    }

    pub fn set_nft_token(&mut self, nft_token_json: String) {
        self.assert_owner();
        self.nft_token_json = nft_token_json;
    }

    pub fn set_panic(&mut self, message: Option<String>) {
        self.assert_owner();
        self.panic_message = message;
    }

    pub fn get_status(&self) -> String {
        self.status_json.clone()
    }

    fn assert_owner(&self) {
        assert_eq!(
            env::predecessor_account_id(),
            self.owner,
            "only the stub's owner may reconfigure it"
        );
    }
}
