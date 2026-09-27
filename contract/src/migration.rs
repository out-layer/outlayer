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
//! * **v8 → v9 (current): add `payment_key_nonce_floors` — the highest
//!   payment-key nonce the contract has seen each owner create or delete.**
//!
//! **`ContractV8` mirrors what is DEPLOYED, not this working tree minus
//! the new field.** Check it against `git show HEAD:` before touching
//! it. The two are the same only when the previous migration is already
//! committed, and it is the DEPLOYED shape that `state_read` will be
//! handed.
//!
//! Versions ≤ v8 are historical. Production deployments must be on v8
//! before calling this migration; an earlier-version deployment must
//! first run the prior migrations from an earlier code revision.
//!
//! Deploy and `migrate` go in ONE transaction (a `DeployContract` action
//! followed by a `FunctionCall` of `migrate`): between the two, every call
//! would fail to read the state.

use crate::*;
use near_sdk::borsh::BorshDeserialize;
use near_sdk::collections::{LookupMap, UnorderedMap, UnorderedSet};

/// Contract state as DEPLOYED at v8 — the last shape any chain has held.
///
/// Mirrors `Contract` as it was before `payment_key_nonce_floors` existed;
/// every field carries over verbatim. Check it against
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
pub struct ContractV8 {
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
}

#[near_bindgen]
impl Contract {
    /// Migrate from v8 to v9: add the payment-key nonce floors.
    ///
    /// The map starts EMPTY. Every owner's floor is then 0, so each keeps the
    /// nonce `get_next_payment_key_nonce` answered before — the highest live
    /// key + 1 — and the floor fills itself from the next key created or
    /// deleted. Keys deleted before this migration are not in it.
    #[private]
    #[init(ignore_state)]
    pub fn migrate() -> Self {
        let v8: ContractV8 = env::state_read().expect("failed to read v8 state");

        log!(
            "Migrating contract v8 -> v9 (payment_key_nonce_floors): owner={}, total_executions={}",
            v8.owner_id,
            v8.total_executions
        );

        Self {
            owner_id: v8.owner_id,
            operator_id: v8.operator_id,
            paused: v8.paused,
            event_standard: v8.event_standard,
            event_version: v8.event_version,
            base_fee: v8.base_fee,
            per_million_instructions_fee: v8.per_million_instructions_fee,
            per_ms_fee: v8.per_ms_fee,
            per_compile_ms_fee: v8.per_compile_ms_fee,
            base_fee_usd: v8.base_fee_usd,
            per_million_instructions_fee_usd: v8.per_million_instructions_fee_usd,
            per_sec_fee_usd: v8.per_sec_fee_usd,
            per_compile_ms_fee_usd: v8.per_compile_ms_fee_usd,
            payment_token_contract: v8.payment_token_contract,
            next_request_id: v8.next_request_id,
            pending_requests: v8.pending_requests,
            total_executions: v8.total_executions,
            total_fees_collected: v8.total_fees_collected,
            secrets_storage: v8.secrets_storage,
            user_secrets_index: v8.user_secrets_index,
            projects: v8.projects,
            project_versions: v8.project_versions,
            user_projects_index: v8.user_projects_index,
            next_project_id: v8.next_project_id,
            developer_earnings: v8.developer_earnings,
            user_stablecoin_balances: v8.user_stablecoin_balances,
            wallet_policies: v8.wallet_policies,
            wallet_owner_index: v8.wallet_owner_index,
            secret_vault_bindings: v8.secret_vault_bindings,
            subscription_plans: v8.subscription_plans,
            project_pricing: v8.project_pricing,
            // ----- v9 -----
            payment_key_nonce_floors: LookupMap::new(StorageKey::PaymentKeyNonceFloor),
        }
    }

    /// Returns the contract's storage-schema version. Bumped each time
    /// `migrate()` advances the layout. Off-chain tooling reads this to
    /// decide whether a deploy needs a migration call.
    pub fn get_storage_version(&self) -> String {
        "9".to_string()
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

    /// A v8 chain: the contract as it stood, its keys in storage, no floor.
    fn v8_state_with_keys(nonces: &[u32]) -> VMContextBuilder {
        let mut b = ctx(accounts(1));
        testing_env!(b.build());
        let mut c = Contract::new(accounts(0), Some(accounts(0)), None, None);
        for &n in nonces {
            store_key(&mut c, &mut b, n);
        }
        // v8 had no floor: drop what the stores above recorded.
        c.payment_key_nonce_floors.remove(&accounts(1));
        let v8 = ContractV8 {
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
        };
        env::state_write(&v8);
        b
    }

    /// The owner of five v8 keys keeps them, gets 6 next, and from then on
    /// the floor holds every nonce created or deleted.
    #[test]
    fn a_v8_state_migrates_and_its_keys_continue_from_their_highest_nonce() {
        let mut b = v8_state_with_keys(&[1, 2, 3, 4, 5]);
        testing_env!(ctx(accounts(0)).build());
        let mut c = Contract::migrate();

        assert_eq!(c.get_storage_version(), "9");
        assert_eq!(c.owner_id, accounts(0));
        for n in 1..=5 {
            assert!(
                c.get_secrets(Acc::System(SystemSecretType::PaymentKey), n.to_string(), accounts(1))
                    .is_some(),
                "key {n} survives the migration"
            );
        }
        assert_eq!(c.get_payment_key_nonce_floor(accounts(1)), 0);
        assert_eq!(c.get_next_payment_key_nonce(accounts(1)), 6);

        store_key(&mut c, &mut b, 6);
        assert_eq!(c.get_payment_key_nonce_floor(accounts(1)), 6);
        assert_eq!(c.get_next_payment_key_nonce(accounts(1)), 7);
    }

    /// The deployed state itself, read through `ContractV8`. Runs when
    /// `V8_STATE_FILE` names a file holding the raw `STATE` value of a live
    /// contract (a `view_state` with prefix `STATE`); skipped otherwise.
    #[test]
    fn a_deployed_state_reads_as_v8_and_migrates() {
        let Ok(path) = std::env::var("V8_STATE_FILE") else { return };
        let bytes = std::fs::read(&path).expect("read V8_STATE_FILE");
        testing_env!(ctx(accounts(0)).build());
        assert!(
            Contract::try_from_slice(&bytes).is_err(),
            "the deployed STATE already reads as the v9 shape — this migration is not for it"
        );
        let v8 = ContractV8::try_from_slice(&bytes).expect("the deployed STATE is not the v8 shape");
        let owner = v8.owner_id.clone();
        env::state_write(&v8);
        let c = Contract::migrate();
        assert_eq!(c.owner_id, owner);
        assert_eq!(c.get_storage_version(), "9");
        println!("v8 state of {} bytes, owner {owner}, migrated", bytes.len());
    }
}
