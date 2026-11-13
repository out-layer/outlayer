//! Governance and the owner's money.
//!
//! Three roles:
//! - **Governance** (`governance_id`, the DAO `dao.outlayer.<net>`): upgrades this contract,
//!   replaces the owner, the operator, the payment token and itself, and moves any balance in
//!   a rescue (`gov_transfer`). Every call it makes ran through a DAO vote and its delay.
//! - **Owner** (`owner_id`, ops): pricing, pause, cancelling requests, event metadata, and
//!   the platform's money — NEAR fees up to what the contract collected, stablecoin without a
//!   bound.
//! - The operator (`operator_id`): resolves executions and answers payment-key yields.
//!
//! Upgrade ABI: an earlier version calls these on a later one, so every version keeps them
//! with the same name and arguments — `upgrade()` and `upgrade_and_migrate()` (governance
//! only, the wasm as the raw input), `migrate()` without arguments once deployed through
//! governance, `gov_health()`.

use crate::*;
use near_sdk::{assert_one_yocto, require, Promise};

const MIGRATE_GAS: Gas = Gas::from_tgas(60);
const HEALTH_GAS: Gas = Gas::from_tgas(20);
const WITHDRAW_CALLBACK_GAS: Gas = Gas::from_tgas(10);
const RESCUE_FT_GAS: Gas = Gas::from_tgas(30);

impl Contract {
    fn governed_upgrade(&self, migrate: bool) -> Promise {
        self.assert_governance();
        let code = env::input().unwrap_or_default();
        require!(!code.is_empty(), "upgrade takes the wasm as the raw input of the call");
        log!(
            "upgrade size={} migrate={}",
            code.len(),
            migrate
        );
        let mut p = Promise::new(env::current_account_id()).deploy_contract(code);
        if migrate {
            p = p.function_call(
                "migrate".to_string(),
                b"{}".to_vec(),
                NearToken::from_yoctonear(0),
                MIGRATE_GAS,
            );
        }
        p.function_call(
            "gov_health".to_string(),
            b"{}".to_vec(),
            NearToken::from_yoctonear(0),
            HEALTH_GAS,
        )
    }

    pub(crate) fn assert_governance(&self) {
        require!(
            env::predecessor_account_id() == self.governance_id,
            format!("Only governance ({}) can call this method", self.governance_id)
        );
    }

    /// NEAR the owner may still take: fees the contract collected minus what was withdrawn.
    fn platform_near_available(&self) -> Balance {
        self.total_fees_collected.saturating_sub(self.platform_near_withdrawn)
    }
}

#[near_bindgen]
impl Contract {
    // ===== Governance =====

    /// Governance: deploy the wasm given as the raw input of the call (not JSON) on this
    /// account. `upgrade_and_migrate` also calls the new code's `migrate()`. One atomic batch:
    /// a failing `migrate`, or a state the new code cannot read (`gov_health`), leaves the old
    /// code in place.
    pub fn upgrade(&mut self) -> Promise {
        self.governed_upgrade(false)
    }

    pub fn upgrade_and_migrate(&mut self) -> Promise {
        self.governed_upgrade(true)
    }

    /// Reads the state; the last step of the upgrade batch.
    pub fn gov_health(&self) -> u64 {
        self.next_request_id
    }

    /// Governance: hand governance to another account.
    pub fn set_governance(&mut self, governance_id: AccountId) {
        self.assert_governance();
        log!("Governance changed from {} to {}", self.governance_id, governance_id);
        self.governance_id = governance_id;
    }

    pub fn get_governance(&self) -> AccountId {
        self.governance_id.clone()
    }

    /// Governance: move any balance of this contract — NEAR (`token: None`) or a fungible
    /// token. The rescue for money stuck by a bug; it runs only after a DAO vote and its delay.
    #[payable]
    pub fn gov_transfer(
        &mut self,
        token: Option<AccountId>,
        amount: U128,
        receiver_id: AccountId,
    ) -> Promise {
        self.assert_governance();
        require!(amount.0 > 0, "amount must be positive");
        log!(
            "gov_transfer token={} amount={} receiver={}",
            token.as_ref().map(|t| t.as_str()).unwrap_or("NEAR"),
            amount.0,
            receiver_id
        );
        match token {
            None => {
                // NEAR leaving through governance counts against the platform's fees first, so
                // the owner's bounded withdrawal never draws on what is no longer there.
                // Not clamped to what was collected: an owner withdrawal in flight may be
                // credited back on failure, and a clamp would erase this transfer from the
                // count. `platform_near_available` saturates at zero.
                self.platform_near_withdrawn =
                    self.platform_near_withdrawn.saturating_add(amount.0);
                Promise::new(receiver_id).transfer(NearToken::from_yoctonear(amount.0))
            }
            Some(token) => Promise::new(token).function_call(
                "ft_transfer".to_string(),
                serde_json::json!({
                    "receiver_id": receiver_id,
                    "amount": amount,
                    "memo": "OutLayer governance transfer",
                })
                .to_string()
                .into_bytes(),
                NearToken::from_yoctonear(1),
                RESCUE_FT_GAS,
            ),
        }
    }

    // ===== The owner's money =====

    /// Owner: take NEAR fees the contract collected. Bounded by `total_fees_collected` minus
    /// what was already withdrawn, so it never reaches a deposit, a pending payment or a
    /// storage refund. The counter moves first; a failed transfer puts it back.
    #[payable]
    pub fn withdraw_platform_near(&mut self, amount: U128, receiver_id: AccountId) -> Promise {
        assert_one_yocto();
        self.assert_owner();
        let available = self.platform_near_available();
        require!(amount.0 > 0, "amount must be positive");
        require!(
            amount.0 <= available,
            format!(
                "Requested {} yoctoNEAR; the platform's fees available are {}",
                amount.0, available
            )
        );
        self.platform_near_withdrawn += amount.0;
        log!("Platform NEAR withdrawal: {} yoctoNEAR to {}", amount.0, receiver_id);
        Promise::new(receiver_id.clone())
            .transfer(NearToken::from_yoctonear(amount.0))
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(WITHDRAW_CALLBACK_GAS)
                    .on_platform_near_withdrawn(U128(amount.0), receiver_id),
            )
    }

    /// The transfer's outcome, read as success or failure only.
    #[private]
    pub fn on_platform_near_withdrawn(
        &mut self,
        #[callback_result] transfer: Result<(), near_sdk::PromiseError>,
        amount: U128,
        receiver_id: AccountId,
    ) {
        if transfer.is_err() {
            self.platform_near_withdrawn = self.platform_near_withdrawn.saturating_sub(amount.0);
            log!(
                "Platform NEAR withdrawal to {} failed; {} yoctoNEAR is available again",
                receiver_id,
                amount.0
            );
        }
    }

    /// Owner: take stablecoin from this contract's balance. No bound: the contract holds
    /// the platform's stablecoin together with what users and developers deposited, and it
    /// cannot tell the platform's share apart — payment keys are spent off chain.
    #[payable]
    pub fn withdraw_platform_token(&mut self, amount: U128, receiver_id: AccountId) -> Promise {
        assert_one_yocto();
        self.assert_owner();
        require!(amount.0 > 0, "amount must be positive");
        log!("Platform stablecoin withdrawal: {} to {}", amount.0, receiver_id);
        self.stablecoin_transfer(&receiver_id, amount.0, "OutLayer platform withdrawal")
    }

    /// `(collected, withdrawn, available)` NEAR fees, in yoctoNEAR.
    pub fn get_platform_near(&self) -> (U128, U128, U128) {
        (
            U128(self.total_fees_collected),
            U128(self.platform_near_withdrawn),
            U128(self.platform_near_available()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::{testing_env, PromiseResult, RuntimeFeesConfig};

    fn a(s: &str) -> AccountId {
        s.parse().unwrap()
    }
    fn with_input(predecessor: &str, input: &[u8]) {
        let mut b = VMContextBuilder::new();
        b.current_account_id(a("outlayer.testnet")).predecessor_account_id(a(predecessor));
        b.context.input = input.to_vec();
        testing_env!(b.build());
    }
    fn at(predecessor: &str, deposit: u128) {
        let mut b = VMContextBuilder::new();
        b.current_account_id(a("outlayer.testnet"))
            .predecessor_account_id(a(predecessor))
            .attached_deposit(NearToken::from_yoctonear(deposit));
        testing_env!(b.build());
    }
    fn contract() -> Contract {
        at("owner.testnet", 0);
        let mut c = Contract::new(a("owner.testnet"), Some(a("worker.testnet")), None, None);
        // A fresh deploy is governed by its owner until it hands governance to the DAO.
        assert_eq!(c.get_governance(), a("owner.testnet"));
        c.set_governance(a("dao.testnet"));
        c
    }

    #[test]
    fn governance_replaces_owner_operator_token_and_itself() {
        let mut c = contract();
        at("dao.testnet", 0);
        c.set_owner(a("ops2.testnet"));
        c.set_operator(a("worker2.testnet"));
        c.set_payment_token_contract(Some(a("usdc.testnet")));
        assert_eq!(c.get_config(), (a("ops2.testnet"), a("worker2.testnet")));
        c.set_governance(a("dao2.testnet"));
        assert_eq!(c.get_governance(), a("dao2.testnet"));
    }

    #[test]
    #[should_panic(expected = "Only governance")]
    fn the_owner_cannot_replace_the_operator() {
        let mut c = contract();
        at("owner.testnet", 0);
        c.set_operator(a("evil.testnet"));
    }

    #[test]
    #[should_panic(expected = "Only governance")]
    fn the_owner_cannot_replace_itself() {
        let mut c = contract();
        at("owner.testnet", 0);
        c.set_owner(a("evil.testnet"));
    }

    #[test]
    #[should_panic(expected = "Only governance")]
    fn the_owner_cannot_change_the_payment_token() {
        let mut c = contract();
        at("owner.testnet", 0);
        c.set_payment_token_contract(Some(a("fake-usdc.testnet")));
    }

    #[test]
    #[should_panic(expected = "Only governance")]
    fn the_owner_cannot_upgrade() {
        let mut c = contract();
        with_input("owner.testnet", b"\0asm-new-code");
        let _ = c.upgrade();
    }

    #[test]
    #[should_panic(expected = "raw input")]
    fn an_upgrade_without_code_is_refused() {
        let mut c = contract();
        with_input("dao.testnet", b"");
        let _ = c.upgrade_and_migrate();
    }

    #[test]
    fn governance_upgrades_and_rescues() {
        let mut c = contract();
        with_input("dao.testnet", b"\0asm-new-code");
        let _ = c.upgrade();
        let _ = c.upgrade_and_migrate();
        at("dao.testnet", 0);
        let _ = c.gov_transfer(None, U128(5), a("treasury.testnet"));
        let _ = c.gov_transfer(Some(a("usdc.testnet")), U128(5), a("treasury.testnet"));
    }

    #[test]
    fn a_governance_near_transfer_counts_against_the_fees() {
        let mut c = contract();
        c.total_fees_collected = 1_000;
        at("dao.testnet", 0);
        let _ = c.gov_transfer(None, U128(600), a("treasury.testnet"));
        assert_eq!(c.get_platform_near().2, U128(400));
        let _ = c.gov_transfer(None, U128(5_000), a("treasury.testnet"));
        assert_eq!(c.get_platform_near(), (U128(1_000), U128(5_600), U128(0)));
    }

    /// A governance transfer made while an owner withdrawal is in flight stays
    /// counted when that withdrawal fails and is credited back.
    #[test]
    fn a_governance_transfer_survives_a_failed_owner_withdrawal() {
        let mut c = contract();
        c.total_fees_collected = 1_000;
        at("owner.testnet", 1);
        let _ = c.withdraw_platform_near(U128(1_000), a("missing.testnet"));
        at("dao.testnet", 0);
        let _ = c.gov_transfer(None, U128(100), a("treasury.testnet"));
        at("outlayer.testnet", 0);
        c.on_platform_near_withdrawn(
            Err(near_sdk::PromiseError::Failed),
            U128(1_000),
            a("missing.testnet"),
        );
        assert_eq!(c.get_platform_near(), (U128(1_000), U128(100), U128(900)));
    }

    #[test]
    #[should_panic(expected = "event standard and version must be at most 64 bytes")]
    fn a_long_event_standard_is_refused() {
        let mut c = contract();
        at("owner.testnet", 0);
        c.set_event_metadata(Some("s".repeat(65)), None);
    }

    #[test]
    #[should_panic(expected = "a plan name must be at most 64 bytes")]
    fn a_long_plan_name_is_refused() {
        let mut c = contract();
        at("owner.testnet", 0);
        c.set_subscription_plans(vec![crate::payment::SubscriptionPlan {
            index: 0,
            name: "p".repeat(65),
            price_usd: U128(1),
            active: true,
        }]);
    }

    #[test]
    #[should_panic(expected = "Only governance")]
    fn the_owner_cannot_rescue() {
        let mut c = contract();
        at("owner.testnet", 0);
        let _ = c.gov_transfer(None, U128(5), a("owner.testnet"));
    }

    #[test]
    fn the_owner_takes_near_fees_up_to_what_was_collected() {
        let mut c = contract();
        c.total_fees_collected = 1_000;
        at("owner.testnet", 1);
        let _ = c.withdraw_platform_near(U128(600), a("treasury.testnet"));
        assert_eq!(c.get_platform_near().2, U128(400));
        let _ = c.withdraw_platform_near(U128(400), a("treasury.testnet"));
        assert_eq!(c.get_platform_near(), (U128(1_000), U128(1_000), U128(0)));
    }

    #[test]
    #[should_panic(expected = "the platform's fees available are 1000")]
    fn near_above_the_fees_is_refused() {
        let mut c = contract();
        c.total_fees_collected = 1_000;
        at("owner.testnet", 1);
        let _ = c.withdraw_platform_near(U128(1_001), a("treasury.testnet"));
    }

    #[test]
    #[should_panic(expected = "Only owner")]
    fn a_stranger_cannot_take_fees() {
        let mut c = contract();
        c.total_fees_collected = 1_000;
        at("stranger.testnet", 1);
        let _ = c.withdraw_platform_near(U128(1), a("stranger.testnet"));
    }

    #[test]
    #[should_panic(expected = "Requires attached deposit of exactly 1 yoctoNEAR")]
    fn fee_withdrawal_needs_one_yocto() {
        let mut c = contract();
        c.total_fees_collected = 1_000;
        at("owner.testnet", 0);
        let _ = c.withdraw_platform_near(U128(1), a("treasury.testnet"));
    }

    #[test]
    fn a_failed_near_transfer_makes_the_fees_available_again() {
        let mut c = contract();
        c.total_fees_collected = 1_000;
        at("owner.testnet", 1);
        let _ = c.withdraw_platform_near(U128(700), a("missing.testnet"));
        assert_eq!(c.get_platform_near().2, U128(300));

        let mut b = VMContextBuilder::new();
        b.current_account_id(a("outlayer.testnet"))
            .predecessor_account_id(a("outlayer.testnet"));
        testing_env!(
            b.build(),
            near_sdk::test_vm_config(),
            RuntimeFeesConfig::test(),
            Default::default(),
            vec![PromiseResult::Failed],
        );
        c.on_platform_near_withdrawn(
            Err(near_sdk::PromiseError::Failed),
            U128(700),
            a("missing.testnet"),
        );
        assert_eq!(c.get_platform_near().2, U128(1_000));
    }

    #[test]
    fn the_owner_takes_stablecoin() {
        let mut c = contract();
        at("dao.testnet", 0);
        c.set_payment_token_contract(Some(a("usdc.testnet")));
        at("owner.testnet", 1);
        let _ = c.withdraw_platform_token(U128(5_000_000), a("treasury.testnet"));
    }
}
