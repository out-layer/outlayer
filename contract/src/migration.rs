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
//! * **v9 → v10 (current): add `storage_refund_to` — who a refundable
//!   storage deposit goes back to, by what it is held for.**
//!
//! **`ContractV9` mirrors what is DEPLOYED, not this working tree minus
//! the new field.** Check it against `git show HEAD:` before touching
//! it. The two are the same only when the previous migration is already
//! committed, and it is the DEPLOYED shape that `state_read` will be
//! handed.
//!
//! Versions ≤ v9 are historical. Production deployments must be on v9
//! before calling this migration; an earlier-version deployment must
//! first run the prior migrations from an earlier code revision.
//!
//! Deploy and `migrate` go in ONE transaction (a `DeployContract` action
//! followed by a `FunctionCall` of `migrate`): between the two, every call
//! would fail to read the state.

use crate::*;
use near_sdk::borsh::BorshDeserialize;
use near_sdk::collections::{LookupMap, UnorderedMap, UnorderedSet};

/// Contract state as DEPLOYED at v9 — the last shape any chain has held.
///
/// Mirrors `Contract` as it was before `storage_refund_to` existed; every
/// field carries over verbatim. Check it against
/// `git show HEAD:contract/src/lib.rs`, not against the struct in this working
/// tree: the two differ by exactly the field this migration adds.
///
/// A new field means a new state SHAPE, and borsh reads by position — so a
/// deploy without this migration would read the old bytes into the new struct
/// and run off the end. That is the whole reason this file exists.
#[derive(BorshDeserialize)]
#[cfg_attr(test, derive(near_sdk::borsh::BorshSerialize))]
#[borsh(crate = "near_sdk::borsh")]
#[allow(dead_code)] // fields needed for borsh deserialisation only
pub struct ContractV9 {
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
}

#[near_bindgen]
impl Contract {
    /// Migrate from v9 to v10: add the storage refund beneficiaries.
    ///
    /// The map starts EMPTY: every existing policy refunds its caller, as
    /// before, until a beneficiary is set on it with `set_storage_refund_to`.
    #[private]
    #[init(ignore_state)]
    pub fn migrate() -> Self {
        let v9: ContractV9 = env::state_read().expect("failed to read v9 state");

        log!(
            "Migrating contract v9 -> v10 (storage_refund_to): owner={}, total_executions={}",
            v9.owner_id,
            v9.total_executions
        );

        Self {
            owner_id: v9.owner_id,
            operator_id: v9.operator_id,
            paused: v9.paused,
            event_standard: v9.event_standard,
            event_version: v9.event_version,
            base_fee: v9.base_fee,
            per_million_instructions_fee: v9.per_million_instructions_fee,
            per_ms_fee: v9.per_ms_fee,
            per_compile_ms_fee: v9.per_compile_ms_fee,
            base_fee_usd: v9.base_fee_usd,
            per_million_instructions_fee_usd: v9.per_million_instructions_fee_usd,
            per_sec_fee_usd: v9.per_sec_fee_usd,
            per_compile_ms_fee_usd: v9.per_compile_ms_fee_usd,
            payment_token_contract: v9.payment_token_contract,
            next_request_id: v9.next_request_id,
            pending_requests: v9.pending_requests,
            total_executions: v9.total_executions,
            total_fees_collected: v9.total_fees_collected,
            secrets_storage: v9.secrets_storage,
            user_secrets_index: v9.user_secrets_index,
            projects: v9.projects,
            project_versions: v9.project_versions,
            user_projects_index: v9.user_projects_index,
            next_project_id: v9.next_project_id,
            developer_earnings: v9.developer_earnings,
            user_stablecoin_balances: v9.user_stablecoin_balances,
            wallet_policies: v9.wallet_policies,
            wallet_owner_index: v9.wallet_owner_index,
            secret_vault_bindings: v9.secret_vault_bindings,
            subscription_plans: v9.subscription_plans,
            project_pricing: v9.project_pricing,
            payment_key_nonce_floors: v9.payment_key_nonce_floors,
            // ----- v10 -----
            storage_refund_to: LookupMap::new(StorageKey::StorageRefundTo),
        }
    }

    /// Returns the contract's storage-schema version. Bumped each time
    /// `migrate()` advances the layout. Off-chain tooling reads this to
    /// decide whether a deploy needs a migration call.
    pub fn get_storage_version(&self) -> String {
        "10".to_string()
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

    fn store_key(c: &mut Contract, b: &mut VMContextBuilder, nonce: u32) {
        testing_env!(b.attached_deposit(NearToken::from_near(1)).build());
        c.store_secrets(
            Acc::System(SystemSecretType::PaymentKey),
            nonce.to_string(),
            "encrypted".to_string(),
            types::AccessCondition::AllowAll,
            None,
        );
    }

    /// A v9 chain: the contract as it stands, a wallet policy and payment keys
    /// in storage, no beneficiary map.
    fn v9_state(nonces: &[u32], policy_key: &str) -> VMContextBuilder {
        let mut b = ctx(accounts(1));
        testing_env!(b.build());
        let mut c = Contract::new(accounts(0), Some(accounts(0)), None, None);
        for &n in nonces {
            store_key(&mut c, &mut b, n);
        }
        c.wallet_policies.insert(
            &policy_key.to_string(),
            &wallet::WalletPolicyEntry {
                owner: accounts(1),
                encrypted_data: "enc".to_string(),
                frozen: false,
                updated_at: 0,
                storage_deposit: 7,
            },
        );
        let v9 = ContractV9 {
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
        };
        env::state_write(&v9);
        b
    }

    /// Everything a v9 chain held reads on as before, and no policy has a
    /// beneficiary until one is set.
    #[test]
    fn a_v9_state_migrates_with_no_beneficiaries() {
        let key = format!("ed25519:{}", "ab".repeat(32));
        let _b = v9_state(&[1, 2, 3], &key);
        testing_env!(ctx(accounts(0)).build());
        let c = Contract::migrate();

        assert_eq!(c.get_storage_version(), "10");
        assert_eq!(c.owner_id, accounts(0));
        for n in 1..=3 {
            assert!(
                c.get_secrets(Acc::System(SystemSecretType::PaymentKey), n.to_string(), accounts(1))
                    .is_some(),
                "key {n} survives the migration"
            );
        }
        assert_eq!(c.get_payment_key_nonce_floor(accounts(1)), 3, "the v9 floors carry over");
        let view = c.get_wallet_policy(key).expect("the policy survives");
        assert_eq!(view.owner, accounts(1));
        assert_eq!(view.storage_deposit.0, 7);
        assert_eq!(view.storage_refund_to, None);
    }

    /// The deployed state itself, read through `ContractV9`. Runs when
    /// `V9_STATE_FILE` names a file holding the raw `STATE` value of a live
    /// contract (a `view_state` with prefix `STATE`); skipped otherwise.
    #[test]
    fn a_deployed_state_reads_as_v9_and_migrates() {
        let Ok(path) = std::env::var("V9_STATE_FILE") else { return };
        let bytes = std::fs::read(&path).expect("read V9_STATE_FILE");
        testing_env!(ctx(accounts(0)).build());
        assert!(
            Contract::try_from_slice(&bytes).is_err(),
            "the deployed STATE already reads as the v10 shape — this migration is not for it"
        );
        let v9 = ContractV9::try_from_slice(&bytes).expect("the deployed STATE is not the v9 shape");
        let owner = v9.owner_id.clone();
        env::state_write(&v9);
        let c = Contract::migrate();
        assert_eq!(c.owner_id, owner);
        assert_eq!(c.get_storage_version(), "10");
        println!("v9 state of {} bytes, owner {owner}, migrated", bytes.len());
    }
}
