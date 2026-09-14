//! A relay contract for the on-chain door's identity row (X1 in
//! `tests/secrets_security_e2e.sh`).
//!
//! The door judges the transaction's SIGNER: `request_execution` puts
//! `signer_id` into the event as `sender_id`, and that is the account the
//! keystore evaluates a secret's `AccessCondition` against. When a contract
//! relays `request_execution`, it is the predecessor and the payer while the
//! account that signed the outer transaction is still the signer. This
//! contract is that relay: its owner signs ONE transaction to `relay`, and it
//! forwards `request_execution` naming a row the owner holds and a source of
//! the caller's choosing. `success == true` in the completion event is the
//! keystore's admission of the owner's secret to a run this contract asked
//! for — the boundary the row observes. The guest's bytes are downstream of
//! it: the yield's value is this transaction's own return value.
//!
//! Guarded so that it cannot be turned on anyone else: only the `owner` named
//! at initialisation may call `relay` (the owner signs, the owner relays); it
//! initialises only from a transaction the deputy account signs itself (the
//! deploy), and only on a `.testnet` account. It forwards its arguments
//! verbatim and enforces nothing else.

use near_sdk::json_types::U128;
use near_sdk::{env, near, AccountId, Gas, NearToken, PanicOnDefault, Promise};
use serde_json::json;

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Deputy {
    owner: AccountId,
}

#[near]
impl Deputy {
    /// `owner` is the one account `relay` accepts calls from — named
    /// explicitly, because the deploy-and-init transaction is signed by the
    /// deputy account's own key, so the predecessor here is the deputy
    /// itself. Re-initialisable: a redeploy of the artefact over an existing
    /// account takes the new owner without a migration — a fixture, not a
    /// product.
    #[init(ignore_state)]
    pub fn new(owner: AccountId) -> Self {
        assert!(
            env::current_account_id().as_str().ends_with(".testnet"),
            "the deputy stub is a test fixture and initialises only on a .testnet account"
        );
        // Re-initialisable means anyone could otherwise call this and become
        // the owner: only a transaction the deputy account signs itself may.
        assert_eq!(
            env::predecessor_account_id(),
            env::current_account_id(),
            "the deputy initialises only from its own deploy transaction"
        );
        Self { owner }
    }

    /// Forward `request_execution` to `outlayer`, naming a `source` the caller
    /// chose and a `secrets_ref` for a row the owner holds. The attached
    /// deposit is THIS contract's balance — the point of the row is that the
    /// payer is the deputy while the signer is whoever signed the transaction
    /// that reached this method. `resource_limits` are the shape `run_as`
    /// sends, so the run is a real execute, not a compile-only.
    #[payable]
    pub fn relay(
        &mut self,
        outlayer: AccountId,
        source: serde_json::Value,
        secrets_ref: serde_json::Value,
        deposit: U128,
    ) -> Promise {
        assert_eq!(
            env::predecessor_account_id(),
            self.owner,
            "only the deputy's owner may relay through it"
        );
        let args = json!({
            "source": source,
            "secrets_ref": secrets_ref,
            "input_data": "{\"message\":\"relayed-by-a-deputy\"}",
            "resource_limits": {
                "max_instructions": 1_000_000_000u64,
                "max_memory_mb": 128u32,
                "max_execution_seconds": 30u32
            }
        });
        Promise::new(outlayer).function_call(
            "request_execution".to_string(),
            serde_json::to_vec(&args).unwrap(),
            NearToken::from_yoctonear(deposit.0),
            Gas::from_tgas(120),
        )
    }

    /// The one account `relay` accepts calls from.
    pub fn owner(&self) -> AccountId {
        self.owner.clone()
    }

    /// The deputy's own balance, so a row can confirm it is funded before the
    /// relay attaches a deposit from it.
    pub fn balance(&self) -> U128 {
        U128(env::account_balance().as_yoctonear())
    }
}
