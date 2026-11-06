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
//! * **v11 → v12 (current): add `policy_meta` — a wallet policy's version
//!   and lock (`approval.locked`), beside the entry.**
//!
//! **`ContractV11` mirrors what is DEPLOYED, not this working tree minus
//! the new field.** Check it against `git show HEAD:` before touching
//! it. The two are the same only when the previous migration is already
//! committed, and it is the DEPLOYED shape that `state_read` will be
//! handed.
//!
//! Versions ≤ v11 are historical. Production deployments must be on v11
//! before calling this migration; an earlier-version deployment must
//! first run the prior migrations from an earlier code revision.
//!
//! Deploy and `migrate` go in ONE transaction (a `DeployContract` action
//! followed by a `FunctionCall` of `migrate`): between the two, every call
//! would fail to read the state.

use crate::*;
use near_sdk::borsh::BorshDeserialize;
use near_sdk::collections::{LookupMap, UnorderedMap, UnorderedSet};

/// Contract state as DEPLOYED at v11 — the last shape any chain has held.
///
/// Mirrors `Contract` as it was before `policy_meta` existed; every field carries over verbatim. Check it against
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
pub struct ContractV11 {
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
}

#[near_bindgen]
impl Contract {
    /// Migrate from v11 to v12: add the policy version-and-lock map.
    ///
    /// The map starts EMPTY: every existing policy reads as version 0 and
    /// unlocked, so its next write carries version 1 and needs no quorum.
    #[private]
    #[init(ignore_state)]
    pub fn migrate() -> Self {
        let v11: ContractV11 = env::state_read().expect("failed to read v11 state");

        log!(
            "Migrating contract v11 -> v12 (policy_meta): owner={}, total_executions={}",
            v11.owner_id,
            v11.total_executions
        );

        Self {
            owner_id: v11.owner_id,
            operator_id: v11.operator_id,
            paused: v11.paused,
            event_standard: v11.event_standard,
            event_version: v11.event_version,
            base_fee: v11.base_fee,
            per_million_instructions_fee: v11.per_million_instructions_fee,
            per_ms_fee: v11.per_ms_fee,
            per_compile_ms_fee: v11.per_compile_ms_fee,
            base_fee_usd: v11.base_fee_usd,
            per_million_instructions_fee_usd: v11.per_million_instructions_fee_usd,
            per_sec_fee_usd: v11.per_sec_fee_usd,
            per_compile_ms_fee_usd: v11.per_compile_ms_fee_usd,
            payment_token_contract: v11.payment_token_contract,
            next_request_id: v11.next_request_id,
            pending_requests: v11.pending_requests,
            total_executions: v11.total_executions,
            total_fees_collected: v11.total_fees_collected,
            secrets_storage: v11.secrets_storage,
            user_secrets_index: v11.user_secrets_index,
            projects: v11.projects,
            project_versions: v11.project_versions,
            user_projects_index: v11.user_projects_index,
            next_project_id: v11.next_project_id,
            developer_earnings: v11.developer_earnings,
            user_stablecoin_balances: v11.user_stablecoin_balances,
            wallet_policies: v11.wallet_policies,
            wallet_owner_index: v11.wallet_owner_index,
            secret_vault_bindings: v11.secret_vault_bindings,
            subscription_plans: v11.subscription_plans,
            project_pricing: v11.project_pricing,
            payment_key_nonce_floors: v11.payment_key_nonce_floors,
            storage_refund_to: v11.storage_refund_to,
            project_transfer_acceptances: v11.project_transfer_acceptances,
            // ----- v12 -----
            policy_meta: LookupMap::new(StorageKey::PolicyMeta),
        }
    }

    /// Returns the contract's storage-schema version. Bumped each time
    /// `migrate()` advances the layout. Off-chain tooling reads this to
    /// decide whether a deploy needs a migration call.
    pub fn get_storage_version(&self) -> String {
        "12".to_string()
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

    /// A v11 chain: the contract as it stands, payment keys, a wallet policy
    /// with a beneficiary and a project in storage, no acceptance map.
    fn v11_state(nonces: &[u32], policy_key: &str) -> VMContextBuilder {
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
        c.storage_refund_to.insert(
            &wallet::StorageItem::WalletPolicy { wallet_pubkey: policy_key.to_string() },
            &accounts(2),
        );
        testing_env!(b.attached_deposit(NearToken::from_near(1)).build());
        c.create_project(
            "app".to_string(),
            CodeSource::WasmUrl {
                url: "https://example.invalid/app.wasm".to_string(),
                hash: "ab".repeat(32),
                build_target: None,
            },
        );
        let v11 = ContractV11 {
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
        };
        env::state_write(&v11);
        b
    }

    /// Everything a v11 chain held reads on as before, and a project moves
    /// only once somebody has accepted it.
    #[test]
    fn a_v11_state_migrates_with_no_policy_meta() {
        let key = format!("ed25519:{}", "ab".repeat(32));
        let _b = v11_state(&[1, 2, 3], &key);
        testing_env!(ctx(accounts(0)).build());
        let mut c = Contract::migrate();

        assert_eq!(c.get_storage_version(), "12");
        assert_eq!(c.owner_id, accounts(0));
        for n in 1..=3 {
            assert!(
                c.get_secrets(Acc::System(SystemSecretType::PaymentKey), n.to_string(), accounts(1))
                    .is_some(),
                "key {n} survives the migration"
            );
        }
        assert_eq!(c.get_payment_key_nonce_floor(accounts(1)), 3, "the v11 floors carry over");
        let view = c.get_wallet_policy(key.clone()).expect("the policy survives");
        assert_eq!(view.owner, accounts(1));
        assert_eq!(view.storage_deposit.0, 7);
        assert_eq!(view.storage_refund_to, Some(accounts(2)), "the v11 beneficiaries carry over");
        // A policy from before versions existed: version 0, unlocked — its
        // controller can still delete it, and its next write is version 1.
        assert_eq!((view.version, view.locked), (0, false));
        testing_env!(ctx(accounts(1)).build());
        c.delete_wallet_policy(key.clone());
        assert!(c.get_wallet_policy(key).is_none(), "an unlocked pre-v12 policy deletes as before");
        let project_id = format!("{}/app", accounts(1));
        assert!(c.get_project(project_id.clone()).is_some(), "the project survives");

        // Nothing has been accepted yet, so nothing moves.
        testing_env!(ctx(accounts(1)).build());
        let moved = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            c.transfer_project("app".to_string(), accounts(2));
        }));
        assert!(moved.is_err(), "a transfer with no acceptance is refused after the migration");

        // The new map works on the migrated state: accept, then the v11
        // project moves.
        testing_env!(ctx(accounts(2)).attached_deposit(NearToken::from_near(1)).build());
        c.accept_project_transfer(accounts(1), "app".to_string());
        testing_env!(ctx(accounts(1)).build());
        c.transfer_project("app".to_string(), accounts(2));
        assert!(c.get_project(format!("{}/app", accounts(2))).is_some(), "the v11 project moved onto the acceptance");
        assert!(c.get_project(project_id).is_none());
    }

    /// The deployed state itself, read through `ContractV11`. Runs when
    /// `V11_STATE_FILE` names a file holding the raw `STATE` value of a live
    /// contract (a `view_state` with prefix `STATE`); skipped otherwise.
    #[test]
    fn a_deployed_state_reads_as_v11_and_migrates() {
        let Ok(path) = std::env::var("V11_STATE_FILE") else { return };
        let bytes = std::fs::read(&path).expect("read V11_STATE_FILE");
        testing_env!(ctx(accounts(0)).build());
        assert!(
            Contract::try_from_slice(&bytes).is_err(),
            "the deployed STATE already reads as the v12 shape — this migration is not for it"
        );
        let v11 = ContractV11::try_from_slice(&bytes).expect("the deployed STATE is not the v11 shape");
        let owner = v11.owner_id.clone();
        env::state_write(&v11);
        let c = Contract::migrate();
        assert_eq!(c.owner_id, owner);
        assert_eq!(c.get_storage_version(), "12");
        println!("v11 state of {} bytes, owner {owner}, migrated", bytes.len());
    }
}
