//! A TEST FIXTURE for testnet: a contract that calls OutLayer's
//! `request_execution` on its caller's behalf.
//!
//! A run reached through it has two accounts: the receipt's predecessor is
//! this contract, and the transaction's signer is whoever signed the call to
//! `relay`. That is the shape the platform's `caller: "predecessor"` keys and
//! `storage_account: "predecessor"` cells exist for, and a suite can only
//! observe them through a contract that forwards a source and an input of the
//! caller's choosing — which is all this one does.
//!
//! It holds nothing of anyone's:
//!
//! * the attached deposit goes on to `request_execution` whole, naming the
//!   caller as `payer_account_id`, so OutLayer returns the unused part to the
//!   caller directly;
//! * when `request_execution` itself fails, the deposit comes back to this
//!   contract, and the callback sends it on to the caller;
//! * there is no owner, and nothing to administer: the one piece of state is
//!   the OutLayer account, fixed at initialisation.
//!
//! The run's answer is the transaction's return value: the callback returns
//! the bytes `request_execution` returned (the guest's output in the requested
//! `response_format`, or `null` for a failed run), unchanged.
//!
//! It initialises only on a `.testnet` account and relays only to a `.testnet`
//! OutLayer.

use near_sdk::json_types::U128;
use near_sdk::serde_json::{self, json, Value};
use near_sdk::{env, near, require, AccountId, Gas, GasWeight, NearToken, PanicOnDefault, Promise, PromiseResult};

/// Gas kept for `on_relayed`: it returns bytes and, at most, sends one
/// transfer. Everything else the transaction has left goes to
/// `request_execution`, whose own yield reserves the gas OutLayer's response
/// callback needs.
const CALLBACK_GAS: Gas = Gas::from_tgas(20);

/// The least `request_execution` is given; the unused gas of the transaction is
/// added to it by weight.
const EXECUTION_GAS: Gas = Gas::from_tgas(100);

/// The `request_execution` arguments: the caller's fields as given, an absent
/// one left out, and the caller as `payer_account_id`.
fn request_args(
    caller: &AccountId,
    source: Value,
    input_data: Option<String>,
    resource_limits: Option<Value>,
    secrets_ref: Option<Value>,
    response_format: Option<Value>,
) -> Value {
    let mut args = json!({ "source": source, "payer_account_id": caller });
    let optional = [
        ("input_data", input_data.map(Value::String)),
        ("resource_limits", resource_limits),
        ("secrets_ref", secrets_ref),
        ("response_format", response_format),
    ];
    for (name, value) in optional {
        if let Some(value) = value {
            args[name] = value;
        }
    }
    args
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Relay {
    outlayer: AccountId,
}

#[near]
impl Relay {
    /// `outlayer` is the OutLayer contract every call is relayed to, e.g.
    /// `outlayer.testnet`. Initialise in the deploy transaction itself, so no
    /// one else can initialise the account first.
    #[init]
    pub fn new(outlayer: AccountId) -> Self {
        require!(
            env::current_account_id().as_str().ends_with(".testnet"),
            "the relay is a test fixture and initialises only on a .testnet account"
        );
        require!(
            outlayer.as_str().ends_with(".testnet"),
            "the relay relays only to an OutLayer contract on testnet"
        );
        Self { outlayer }
    }

    /// Call `request_execution` on OutLayer from this contract with the
    /// caller's `source`, `input_data`, `resource_limits`, `secrets_ref` and
    /// `response_format` (each forwarded as given; an absent one is absent
    /// there too), the whole attached deposit, and the caller as
    /// `payer_account_id`. The transaction's return value is the run's answer.
    ///
    /// Attach 300 Tgas: the run's response callback is paid out of it.
    #[payable]
    pub fn relay(
        &mut self,
        source: Value,
        input_data: Option<String>,
        resource_limits: Option<Value>,
        secrets_ref: Option<Value>,
        response_format: Option<Value>,
    ) -> Promise {
        let caller = env::predecessor_account_id();
        let deposit = env::attached_deposit();
        let args = request_args(&caller, source, input_data, resource_limits, secrets_ref, response_format);

        Promise::new(self.outlayer.clone())
            .function_call_weight(
                "request_execution".to_string(),
                serde_json::to_vec(&args).unwrap_or_else(|e| env::panic_str(&e.to_string())),
                deposit,
                EXECUTION_GAS,
                GasWeight(1),
            )
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(CALLBACK_GAS)
                    .with_unused_gas_weight(0)
                    .on_relayed(caller, U128(deposit.as_yoctonear())),
            )
    }

    /// Returns what `request_execution` returned, byte for byte. When it
    /// failed, the deposit it was sent came back here; it goes on to `caller`,
    /// and the transaction returns nothing.
    #[private]
    pub fn on_relayed(&self, caller: AccountId, deposit: U128) {
        match env::promise_result(0) {
            PromiseResult::Successful(value) => env::value_return(&value),
            PromiseResult::Failed => {
                env::log_str(&format!(
                    "relay: request_execution failed with an error (its receipt carries the reason); returning {} yoctoNEAR to {}",
                    deposit.0, caller
                ));
                if deposit.0 > 0 {
                    // The refund of the failed call is a receipt of its own and
                    // may land after this one: pay from what is free now.
                    let storage = env::storage_byte_cost().saturating_mul(u128::from(env::storage_usage()));
                    let free = env::account_balance().saturating_sub(storage);
                    if free >= NearToken::from_yoctonear(deposit.0) {
                        Promise::new(caller).transfer(NearToken::from_yoctonear(deposit.0));
                    } else {
                        env::log_str(&format!(
                            "relay: only {} yoctoNEAR free, the deposit is not returned; top the relay up",
                            free.as_yoctonear()
                        ));
                    }
                }
            }
        }
    }

    /// The OutLayer contract this relay calls.
    pub fn outlayer(&self) -> AccountId {
        self.outlayer.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;

    fn on(account: &str) {
        let mut b = VMContextBuilder::new();
        b.current_account_id(account.parse().unwrap());
        testing_env!(b.build());
    }

    #[test]
    fn initialises_on_testnet() {
        on("relay.alice.testnet");
        assert_eq!(Relay::new("outlayer.testnet".parse().unwrap()).outlayer().as_str(), "outlayer.testnet");
    }

    #[test]
    #[should_panic(expected = "initialises only on a .testnet account")]
    fn refuses_a_mainnet_account() {
        on("relay.alice.near");
        Relay::new("outlayer.testnet".parse().unwrap());
    }

    #[test]
    #[should_panic(expected = "relays only to an OutLayer contract on testnet")]
    fn refuses_a_mainnet_outlayer() {
        on("relay.alice.testnet");
        Relay::new("outlayer.near".parse().unwrap());
    }

    #[test]
    fn forwards_the_callers_fields_and_names_the_caller_payer() {
        let caller: AccountId = "alice.testnet".parse().unwrap();
        let source = json!({"Project": {"project_id": "alice.testnet/probe", "version_key": "abc"}});
        let limits = json!({"max_instructions": 10_000_000_000u64, "max_memory_mb": 128, "max_execution_seconds": 60});
        let args = request_args(
            &caller,
            source.clone(),
            Some("{\"operation\":\"raw_get\"}".to_string()),
            Some(limits.clone()),
            None,
            Some(json!("Json")),
        );
        assert_eq!(
            args,
            json!({
                "source": source,
                "payer_account_id": "alice.testnet",
                "input_data": "{\"operation\":\"raw_get\"}",
                "resource_limits": limits,
                "response_format": "Json"
            })
        );
    }

    #[test]
    fn leaves_absent_fields_absent() {
        let caller: AccountId = "alice.testnet".parse().unwrap();
        let args = request_args(&caller, json!({"WasmUrl": {}}), None, None, None, None);
        assert_eq!(args, json!({"source": {"WasmUrl": {}}, "payer_account_id": "alice.testnet"}));
    }
}
