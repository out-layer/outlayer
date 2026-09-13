//! A confused-deputy stand-in for the on-chain door (test plan: "conditions
//! judge the payer", stated twice — "Holes considered" bullet 4 and "Attack
//! surface" bullet 7).
//!
//! What it exists to test. The plan says a secret's `AccessCondition` is judged
//! against the account that PAYS for the run. On the on-chain door that account
//! is the predecessor; the value actually fed to the keystore is the SIGNER
//! (`contract/src/execution.rs`: the event's `sender_id` is `signer_id`, not
//! `predecessor_id`). This contract is the wedge between the two: a victim signs
//! ONE transaction to `relay`, and this contract — the predecessor, the payer —
//! forwards `request_execution` naming a secret the victim owns and a project
//! the CALLER chose. If the keystore judged the payer, `request_execution` would
//! be judged against THIS contract, which no victim whitelists, and the run
//! would be refused. If it judges the signer, the victim's own whitelist admits
//! their own signature and the secret decrypts into a run this contract
//! launched.
//!
//! What it deliberately does NOT do: read the secret back. The completion event
//! carries `success`/`error_message` but not the guest's output, and
//! `get_request` drops a finished request — so the leaked bytes are not
//! chain-visible (the same wall the D2/B3 rows hit). What IS visible is the
//! ADMISSION: a denied `secrets_ref` refuses the whole run, so `success == true`
//! in the completion event is proof the keystore admitted the victim's secret to
//! a run this contract, not the victim, asked for. That admission is the
//! security boundary; the bytes are downstream of it.
//!
//! A mirror, not a second implementation: it forwards arguments verbatim and
//! enforces nothing.

use near_sdk::{env, near, AccountId, Gas, NearToken, Promise, PanicOnDefault};
use near_sdk::json_types::U128;
use serde_json::json;

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Deputy {}

#[near]
impl Deputy {
    #[init]
    pub fn new() -> Self {
        Self {}
    }

    /// Forward `request_execution` to `outlayer`, naming a `source` the caller
    /// chose and a `secrets_ref` for a row the caller does not own. The attached
    /// deposit is THIS contract's balance — the point of the test is that the
    /// payer is the deputy while the signer is whoever signed the transaction
    /// that reached this method. `resource_limits` are the same shape `run_as`
    /// sends, so the run is a real execute, not a compile-only.
    #[payable]
    pub fn relay(
        &mut self,
        outlayer: AccountId,
        source: serde_json::Value,
        secrets_ref: serde_json::Value,
        deposit: U128,
    ) -> Promise {
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

    /// The deputy's own balance, so a test can confirm it is funded before the
    /// relay attaches a deposit from it.
    pub fn balance(&self) -> U128 {
        U128(env::account_balance().as_yoctonear())
    }
}
