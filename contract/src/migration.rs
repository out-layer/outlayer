//! Contract migration module
//!
//! Migration history (each `migrate()` is single-use; once run, the
//! state shape advances and prior migrate paths cannot be re-applied):
//!
//! * v4 → v5: rename `per_ms_fee_usd` → `per_sec_fee_usd`. (Run.)
//! * v5 → v6: add `wallet_policies`, `wallet_owner_index`. (Run.)
//! * v6 → v7: add `secret_vault_bindings` (Phase 2 of per-vault master
//!   plan). (Run.)
//! * v7 → v8: add `subscription_plans` and `project_pricing`. (Run.)
//! * v8 → v9: add `payment_key_nonce_floors`. (Run.)
//! * v9 → v10: add `storage_refund_to`. (Run.)
//! * v10 → v11: add `project_transfer_acceptances` — who agreed to take
//!   which project from whom. (Run.)
//! * v11 → v12: add `policy_meta` — a wallet policy's version and lock.
//!   (Run.)
//! * v12 → v13: add `payment_key_refund_ledger`, `withdrawing`,
//!   `closing_counts` and `payment_key_flight`. (Run.)
//! * **v13 → v14 (current): add `governance_id` — the DAO that upgrades this
//!   contract and replaces its owner, operator and payment token — and
//!   `platform_near_withdrawn`, the NEAR fees counted as taken (every fee
//!   collected before the release).**
//!
//! **`ContractV13` mirrors what is DEPLOYED, not this working tree minus
//! the new fields.** Check it against `git show HEAD:` before touching
//! it. The two are the same only when the previous migration is already
//! committed, and it is the DEPLOYED shape that `state_read` will be
//! handed.
//!
//! Versions ≤ v13 are historical. Production deployments must be on v13
//! before calling this migration.
//!
//! This migration takes `governance_id` and runs with the full-access key
//! that deploys v14 — the last deploy that key makes. Every version deployed
//! through governance after it has a `migrate()` without arguments: the
//! upgrade batch calls it that way (see `governance`).
//!
//! Deploy and `migrate` go in ONE transaction (a `DeployContract` action
//! followed by a `FunctionCall` of `migrate`): between the two, every call
//! would fail to read the state.

use crate::*;
use near_sdk::borsh::BorshDeserialize;
use near_sdk::collections::{LookupMap, LookupSet, UnorderedMap, UnorderedSet};

/// Contract state as DEPLOYED at v13 — the last shape any chain has held.
///
/// Mirrors `Contract` as it was before governance; every field carries over
/// verbatim. Check it against `git show HEAD:contract/src/lib.rs`,
/// not against the struct in this working tree: the two differ by exactly the
/// fields this migration adds.
///
/// A new field means a new state SHAPE, and borsh reads by position — so a
/// deploy without this migration would read the old bytes into the new struct
/// and run off the end. That is the whole reason this file exists.
#[derive(BorshDeserialize)]
#[cfg_attr(test, derive(near_sdk::borsh::BorshSerialize))]
#[borsh(crate = "near_sdk::borsh")]
#[allow(dead_code)] // fields needed for borsh deserialisation only
pub struct ContractV13 {
    owner_id: AccountId,
    operator_id: AccountId,
    paused: bool,
    event_standard: String,
    event_version: String,

    // NEAR pricing
    base_fee: Balance,
    per_million_instructions_fee: Balance,
    per_ms_fee: Balance,
    per_compile_ms_fee: Balance,

    // USD pricing
    base_fee_usd: u128,
    per_million_instructions_fee_usd: u128,
    per_sec_fee_usd: u128,
    per_compile_ms_fee_usd: u128,

    payment_token_contract: Option<AccountId>,

    next_request_id: u64,
    pending_requests: LookupMap<u64, ExecutionRequest>,

    total_executions: u64,
    total_fees_collected: Balance,

    secrets_storage: LookupMap<SecretKey, SecretProfile>,
    user_secrets_index: LookupMap<AccountId, UnorderedSet<SecretKey>>,

    projects: LookupMap<String, Project>,
    project_versions: LookupMap<String, UnorderedMap<String, VersionInfo>>,
    user_projects_index: LookupMap<AccountId, UnorderedSet<String>>,
    next_project_id: u64,

    developer_earnings: LookupMap<AccountId, u128>,
    user_stablecoin_balances: LookupMap<AccountId, u128>,

    wallet_policies: LookupMap<String, wallet::WalletPolicyEntry>,
    wallet_owner_index: LookupMap<AccountId, UnorderedSet<String>>,

    secret_vault_bindings: LookupMap<SecretKey, AccountId>,

    subscription_plans: Vec<payment::SubscriptionPlan>,
    project_pricing: UnorderedMap<String, payment::ProjectPricing>,

    payment_key_nonce_floors: LookupMap<AccountId, u32>,

    storage_refund_to: LookupMap<wallet::StorageItem, AccountId>,

    project_transfer_acceptances: LookupMap<TransferAcceptance, Balance>,

    policy_meta: LookupMap<String, wallet::PolicyMeta>,

    payment_key_refund_ledger: LookupMap<refunds::PaymentKeyId, refunds::RefundLedger>,
    withdrawing: LookupSet<AccountId>,
    closing_counts: LookupMap<AccountId, u32>,
    payment_key_flight: LookupMap<refunds::PaymentKeyId, refunds::KeyFlight>,
}

#[near_bindgen]
impl Contract {
    /// Migrate from v13 to v14: add `governance_id` and `platform_near_withdrawn`, set to every
    /// fee collected so far. The owner's bounded withdrawal covers only fees collected from
    /// here on; whether earlier fees already left the account cannot be read from the state,
    /// and anything of them still here moves only through governance (`gov_transfer`).
    #[private]
    #[init(ignore_state)]
    pub fn migrate(governance_id: AccountId) -> Self {
        let v13: ContractV13 = env::state_read().expect("failed to read v13 state");

        log!(
            "Migrating contract v13 -> v14 (governance_id={}, platform_near_withdrawn): owner={}, total_executions={}",
            governance_id,
            v13.owner_id,
            v13.total_executions
        );

        Self {
            owner_id: v13.owner_id,
            operator_id: v13.operator_id,
            paused: v13.paused,
            event_standard: v13.event_standard,
            event_version: v13.event_version,
            base_fee: v13.base_fee,
            per_million_instructions_fee: v13.per_million_instructions_fee,
            per_ms_fee: v13.per_ms_fee,
            per_compile_ms_fee: v13.per_compile_ms_fee,
            base_fee_usd: v13.base_fee_usd,
            per_million_instructions_fee_usd: v13.per_million_instructions_fee_usd,
            per_sec_fee_usd: v13.per_sec_fee_usd,
            per_compile_ms_fee_usd: v13.per_compile_ms_fee_usd,
            payment_token_contract: v13.payment_token_contract,
            next_request_id: v13.next_request_id,
            pending_requests: v13.pending_requests,
            total_executions: v13.total_executions,
            total_fees_collected: v13.total_fees_collected,
            secrets_storage: v13.secrets_storage,
            user_secrets_index: v13.user_secrets_index,
            projects: v13.projects,
            project_versions: v13.project_versions,
            user_projects_index: v13.user_projects_index,
            next_project_id: v13.next_project_id,
            developer_earnings: v13.developer_earnings,
            user_stablecoin_balances: v13.user_stablecoin_balances,
            wallet_policies: v13.wallet_policies,
            wallet_owner_index: v13.wallet_owner_index,
            secret_vault_bindings: v13.secret_vault_bindings,
            subscription_plans: v13.subscription_plans,
            project_pricing: v13.project_pricing,
            payment_key_nonce_floors: v13.payment_key_nonce_floors,
            storage_refund_to: v13.storage_refund_to,
            project_transfer_acceptances: v13.project_transfer_acceptances,
            policy_meta: v13.policy_meta,
            payment_key_refund_ledger: v13.payment_key_refund_ledger,
            withdrawing: v13.withdrawing,
            closing_counts: v13.closing_counts,
            payment_key_flight: v13.payment_key_flight,
            // ----- v14 -----
            governance_id,
            platform_near_withdrawn: v13.total_fees_collected,
        }
    }

    /// Returns the contract's storage-schema version. Bumped each time
    /// `migrate()` advances the layout. Off-chain tooling reads this to
    /// decide whether a deploy needs a migration call.
    pub fn get_storage_version(&self) -> String {
        "14".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SecretAccessor as Acc;
    use near_sdk::test_utils::{accounts, VMContextBuilder};
    use near_sdk::{testing_env, NearToken};

    fn ctx(predecessor: AccountId) -> VMContextBuilder {
        let mut b = VMContextBuilder::new();
        b.current_account_id(accounts(0))
            .signer_account_id(predecessor.clone())
            .predecessor_account_id(predecessor)
            .block_timestamp(1_000_000_000);
        b
    }

    fn dao() -> AccountId {
        "dao.outlayer.testnet".parse().unwrap()
    }

    /// A v13 chain: payment keys with a refund ledger, a balance withdrawal in
    /// flight, a wallet policy, a project, a stablecoin balance and fees.
    fn v13_state() -> VMContextBuilder {
        let mut b = ctx(accounts(1));
        testing_env!(b.build());
        let mut c = Contract::new(accounts(0), Some(accounts(3)), None, None);
        for n in [1u32, 2] {
            testing_env!(b.attached_deposit(NearToken::from_near(1)).build());
            c.store_secrets(
                Acc::System(SystemSecretType::PaymentKey),
                n.to_string(),
                "encrypted".to_string(),
                types::AccessCondition::AllowAll,
                None,
            );
        }
        c.user_stablecoin_balances.insert(&accounts(1), &250_000);
        c.withdrawing.insert(&accounts(2));
        c.total_fees_collected = 3_580;
        testing_env!(b.attached_deposit(NearToken::from_near(1)).build());
        c.create_project(
            "app".to_string(),
            CodeSource::WasmUrl {
                url: "https://example.invalid/app.wasm".to_string(),
                hash: "ab".repeat(32),
                build_target: None,
            },
        );
        let v13 = ContractV13 {
            owner_id: c.owner_id,
            operator_id: c.operator_id,
            paused: c.paused,
            event_standard: c.event_standard,
            event_version: c.event_version,
            base_fee: c.base_fee,
            per_million_instructions_fee: c.per_million_instructions_fee,
            per_ms_fee: c.per_ms_fee,
            per_compile_ms_fee: c.per_compile_ms_fee,
            base_fee_usd: c.base_fee_usd,
            per_million_instructions_fee_usd: c.per_million_instructions_fee_usd,
            per_sec_fee_usd: c.per_sec_fee_usd,
            per_compile_ms_fee_usd: c.per_compile_ms_fee_usd,
            payment_token_contract: c.payment_token_contract,
            next_request_id: c.next_request_id,
            pending_requests: c.pending_requests,
            total_executions: c.total_executions,
            total_fees_collected: c.total_fees_collected,
            secrets_storage: c.secrets_storage,
            user_secrets_index: c.user_secrets_index,
            projects: c.projects,
            project_versions: c.project_versions,
            user_projects_index: c.user_projects_index,
            next_project_id: c.next_project_id,
            developer_earnings: c.developer_earnings,
            user_stablecoin_balances: c.user_stablecoin_balances,
            wallet_policies: c.wallet_policies,
            wallet_owner_index: c.wallet_owner_index,
            secret_vault_bindings: c.secret_vault_bindings,
            subscription_plans: c.subscription_plans,
            project_pricing: c.project_pricing,
            payment_key_nonce_floors: c.payment_key_nonce_floors,
            storage_refund_to: c.storage_refund_to,
            project_transfer_acceptances: c.project_transfer_acceptances,
            policy_meta: c.policy_meta,
            payment_key_refund_ledger: c.payment_key_refund_ledger,
            withdrawing: c.withdrawing,
            closing_counts: c.closing_counts,
            payment_key_flight: c.payment_key_flight,
        };
        env::state_write(&v13);
        b
    }

    #[test]
    fn a_v13_state_migrates_under_governance() {
        let _b = v13_state();
        testing_env!(ctx(accounts(0)).build());
        let mut c = Contract::migrate(dao());

        assert_eq!(c.get_storage_version(), "14");
        assert_eq!(c.get_config(), (accounts(0), accounts(3)));
        assert_eq!(c.get_governance(), dao());
        assert_eq!(
            c.get_platform_near(),
            (U128(3_580), U128(3_580), U128(0)),
            "fees collected before the release are not the owner's to withdraw"
        );
        for n in 1..=2 {
            assert!(
                c.get_secrets(Acc::System(SystemSecretType::PaymentKey), n.to_string(), accounts(1))
                    .is_some(),
                "key {n} survives the migration"
            );
            assert!(c.get_payment_key_refund_ledger(accounts(1), n).is_some(), "its ledger too");
        }
        assert!(c.is_withdrawing(accounts(2)), "an in-flight withdrawal carries over");
        assert_eq!(c.get_user_stablecoin_balance(accounts(1)).0, 250_000);
        assert!(c.get_project(format!("{}/app", accounts(1))).is_some());

        // The DAO governs; the owner no longer replaces the operator.
        testing_env!(ctx(dao()).build());
        c.set_operator(accounts(4));
        assert_eq!(c.get_config(), (accounts(0), accounts(4)));
    }

    #[test]
    #[should_panic(expected = "Only governance")]
    fn after_migration_the_owner_cannot_replace_the_operator() {
        let _b = v13_state();
        testing_env!(ctx(accounts(0)).build());
        let mut c = Contract::migrate(dao());
        c.set_operator(accounts(4));
    }

    /// `ContractV13` is HEAD's `Contract`, field for field: a drift here is
    /// a migration that reads the deployed bytes into the wrong shape.
    #[test]
    fn contract_v13_mirrors_the_deployed_shape() {
        let _b = v13_state();
        let bytes = env::storage_read(b"STATE").expect("state written");
        assert!(
            Contract::try_from_slice(&bytes).is_err(),
            "a v13 STATE must not read as the v14 shape"
        );
        let v13 = ContractV13::try_from_slice(&bytes).expect("the v13 STATE reads as ContractV13");
        assert_eq!(v13.owner_id, accounts(0));
    }

    /// The deployed state itself, read through `ContractV13`. Runs when
    /// `V13_STATE_FILE` names a file holding the raw `STATE` value of a live
    /// contract (a `view_state` with prefix `STATE`); skipped otherwise.
    #[test]
    fn a_deployed_state_reads_as_v13_and_migrates() {
        let Ok(path) = std::env::var("V13_STATE_FILE") else { return };
        let bytes = std::fs::read(&path).expect("read V13_STATE_FILE");
        testing_env!(ctx(accounts(0)).build());
        assert!(
            Contract::try_from_slice(&bytes).is_err(),
            "the deployed STATE already reads as the v14 shape — this migration is not for it"
        );
        let v13 = ContractV13::try_from_slice(&bytes).expect("the deployed STATE is not the v13 shape");
        let owner = v13.owner_id.clone();
        let fees = v13.total_fees_collected;
        env::state_write(&v13);
        let c = Contract::migrate(dao());
        assert_eq!(c.owner_id, owner);
        assert_eq!(c.get_storage_version(), "14");
        assert_eq!(c.get_platform_near().0, U128(fees));
        println!("v13 state of {} bytes, owner {owner}, fees {fees}, migrated", bytes.len());
    }
}
