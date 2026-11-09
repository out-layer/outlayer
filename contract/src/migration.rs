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
//! * **v12 → v13 (current): add `payment_key_refund_ledger`, `withdrawing`,
//!   `closing_counts` and `payment_key_flight` — what each payment key's
//!   owner deposited on chain and had back, the accounts with a balance
//!   withdrawal in flight, how many keys each owner has closing, and what is
//!   in flight on each key.**
//!
//! **`ContractV12` mirrors what is DEPLOYED, not this working tree minus
//! the new fields.** Check it against `git show HEAD:` before touching
//! it. The two are the same only when the previous migration is already
//! committed, and it is the DEPLOYED shape that `state_read` will be
//! handed.
//!
//! Versions ≤ v12 are historical. Production deployments must be on v12
//! before calling this migration; an earlier-version deployment must
//! first run the prior migrations from an earlier code revision.
//!
//! Deploy and `migrate` go in ONE transaction (a `DeployContract` action
//! followed by a `FunctionCall` of `migrate`): between the two, every call
//! would fail to read the state.

use crate::*;
use near_sdk::borsh::BorshDeserialize;
use near_sdk::collections::{LookupMap, LookupSet, UnorderedMap, UnorderedSet};

/// Contract state as DEPLOYED at v12 — the last shape any chain has held.
///
/// Mirrors `Contract` as it was before the refund ledger existed; every field
/// carries over verbatim. Check it against `git show HEAD:contract/src/lib.rs`,
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
pub struct ContractV12 {
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
}

#[near_bindgen]
impl Contract {
    /// Migrate from v12 to v13: add the payment-key refund ledger, the
    /// withdrawal in-flight set, the per-owner closing count and the per-key
    /// in-flight record.
    ///
    /// All four start EMPTY, and that is the rule, not a shortcut: a key
    /// that existed before the ledger has `user_funded = 0`, so only deposits
    /// made after this release are refundable (no backfill).
    #[private]
    #[init(ignore_state)]
    pub fn migrate() -> Self {
        let v12: ContractV12 = env::state_read().expect("failed to read v12 state");

        log!(
            "Migrating contract v12 -> v13 (payment_key_refund_ledger, withdrawing, closing_counts, payment_key_flight): owner={}, total_executions={}",
            v12.owner_id,
            v12.total_executions
        );

        Self {
            owner_id: v12.owner_id,
            operator_id: v12.operator_id,
            paused: v12.paused,
            event_standard: v12.event_standard,
            event_version: v12.event_version,
            base_fee: v12.base_fee,
            per_million_instructions_fee: v12.per_million_instructions_fee,
            per_ms_fee: v12.per_ms_fee,
            per_compile_ms_fee: v12.per_compile_ms_fee,
            base_fee_usd: v12.base_fee_usd,
            per_million_instructions_fee_usd: v12.per_million_instructions_fee_usd,
            per_sec_fee_usd: v12.per_sec_fee_usd,
            per_compile_ms_fee_usd: v12.per_compile_ms_fee_usd,
            payment_token_contract: v12.payment_token_contract,
            next_request_id: v12.next_request_id,
            pending_requests: v12.pending_requests,
            total_executions: v12.total_executions,
            total_fees_collected: v12.total_fees_collected,
            secrets_storage: v12.secrets_storage,
            user_secrets_index: v12.user_secrets_index,
            projects: v12.projects,
            project_versions: v12.project_versions,
            user_projects_index: v12.user_projects_index,
            next_project_id: v12.next_project_id,
            developer_earnings: v12.developer_earnings,
            user_stablecoin_balances: v12.user_stablecoin_balances,
            wallet_policies: v12.wallet_policies,
            wallet_owner_index: v12.wallet_owner_index,
            secret_vault_bindings: v12.secret_vault_bindings,
            subscription_plans: v12.subscription_plans,
            project_pricing: v12.project_pricing,
            payment_key_nonce_floors: v12.payment_key_nonce_floors,
            storage_refund_to: v12.storage_refund_to,
            project_transfer_acceptances: v12.project_transfer_acceptances,
            policy_meta: v12.policy_meta,
            // ----- v13 -----
            payment_key_refund_ledger: LookupMap::new(StorageKey::PaymentKeyRefundLedger),
            withdrawing: LookupSet::new(StorageKey::Withdrawing),
            closing_counts: LookupMap::new(StorageKey::ClosingCounts),
            payment_key_flight: LookupMap::new(StorageKey::PaymentKeyFlight),
        }
    }

    /// Returns the contract's storage-schema version. Bumped each time
    /// `migrate()` advances the layout. Off-chain tooling reads this to
    /// decide whether a deploy needs a migration call.
    pub fn get_storage_version(&self) -> String {
        "13".to_string()
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

    /// A v12 chain: the contract as it stands, payment keys, a wallet policy
    /// with a beneficiary, a project and a stablecoin balance in storage, no
    /// refund ledger.
    fn v12_state(nonces: &[u32], policy_key: &str) -> VMContextBuilder {
        let mut b = ctx(accounts(1));
        testing_env!(b.build());
        let mut c = Contract::new(accounts(0), Some(accounts(0)), None, None);
        for &n in nonces {
            store_key(&mut c, &mut b, n);
            // A v12 key has no ledger entry: the map did not exist.
            c.payment_key_refund_ledger
                .remove(&refunds::PaymentKeyId { owner: accounts(1), nonce: n });
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
        c.user_stablecoin_balances.insert(&accounts(1), &250_000);
        testing_env!(b.attached_deposit(NearToken::from_near(1)).build());
        c.create_project(
            "app".to_string(),
            CodeSource::WasmUrl {
                url: "https://example.invalid/app.wasm".to_string(),
                hash: "ab".repeat(32),
                build_target: None,
            },
        );
        let v12 = ContractV12 {
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
        };
        env::state_write(&v12);
        b
    }

    /// Everything a v12 chain held reads on as before; a pre-ledger key has
    /// nothing refundable, and a pre-ledger balance can be withdrawn.
    #[test]
    fn a_v12_state_migrates_with_an_empty_refund_ledger() {
        let key = format!("ed25519:{}", "ab".repeat(32));
        let _b = v12_state(&[1, 2, 3], &key);
        testing_env!(ctx(accounts(0)).build());
        let mut c = Contract::migrate();

        assert_eq!(c.get_storage_version(), "13");
        assert_eq!(c.owner_id, accounts(0));
        for n in 1..=3 {
            assert!(
                c.get_secrets(Acc::System(SystemSecretType::PaymentKey), n.to_string(), accounts(1))
                    .is_some(),
                "key {n} survives the migration"
            );
            assert!(
                c.get_payment_key_refund_ledger(accounts(1), n).is_none(),
                "a pre-ledger key has no ledger entry: nothing of it is refundable"
            );
        }
        assert_eq!(c.get_payment_key_nonce_floor(accounts(1)), 3, "the v12 floors carry over");
        assert_eq!(c.get_closing_payment_key_count(accounts(1)), 0);
        assert!(!c.is_withdrawing(accounts(1)));
        let view = c.get_wallet_policy(key.clone()).expect("the policy survives");
        assert_eq!(view.owner, accounts(1));
        assert_eq!(view.storage_deposit.0, 7);
        assert_eq!(view.storage_refund_to, Some(accounts(2)), "the v12 beneficiaries carry over");
        assert_eq!((view.version, view.locked), (0, false));
        let project_id = format!("{}/app", accounts(1));
        assert!(c.get_project(project_id).is_some(), "the project survives");
        assert_eq!(
            c.get_user_stablecoin_balance(accounts(1)).0,
            250_000,
            "the v12 stablecoin balance carries over"
        );

        // The new maps work on the migrated state: a pre-ledger key can be
        // closed (its ledger entry appears at zero), and the balance can be
        // withdrawn once a token is configured.
        testing_env!(ctx(accounts(0)).build());
        c.on_close_payment_key_response(accounts(1), 2, Ok(payment::DeletePaymentKeyResult::Success));
        let ledger = c.get_payment_key_refund_ledger(accounts(1), 2).expect("closing creates the entry");
        assert_eq!((ledger.user_funded.0, ledger.refunded.0, ledger.refundable_cap.0), (0, 0, 0));
        assert!(ledger.closing_since.is_some());
        assert_eq!(c.get_closing_payment_key_count(accounts(1)), 1);

        testing_env!(ctx(accounts(0)).build());
        c.set_payment_token_contract(Some("usdc.test".parse().unwrap()));
        testing_env!(ctx(accounts(1)).attached_deposit(NearToken::from_yoctonear(1)).build());
        c.withdraw_balance(U128(100_000));
        assert_eq!(c.get_user_stablecoin_balance(accounts(1)).0, 150_000);
        assert!(c.is_withdrawing(accounts(1)));
    }

    /// `ContractV12` is HEAD's `Contract`, field for field: a drift here is
    /// a migration that reads the deployed bytes into the wrong shape.
    #[test]
    fn contract_v12_mirrors_the_deployed_shape() {
        let _b = v12_state(&[1], &format!("ed25519:{}", "cd".repeat(32)));
        let bytes = env::storage_read(b"STATE").expect("state written");
        assert!(
            Contract::try_from_slice(&bytes).is_err(),
            "a v12 STATE must not read as the v13 shape"
        );
        let v12 = ContractV12::try_from_slice(&bytes).expect("the v12 STATE reads as ContractV12");
        assert_eq!(v12.owner_id, accounts(0));
    }

    /// The deployed state itself, read through `ContractV12`. Runs when
    /// `V12_STATE_FILE` names a file holding the raw `STATE` value of a live
    /// contract (a `view_state` with prefix `STATE`); skipped otherwise.
    #[test]
    fn a_deployed_state_reads_as_v12_and_migrates() {
        let Ok(path) = std::env::var("V12_STATE_FILE") else { return };
        let bytes = std::fs::read(&path).expect("read V12_STATE_FILE");
        testing_env!(ctx(accounts(0)).build());
        assert!(
            Contract::try_from_slice(&bytes).is_err(),
            "the deployed STATE already reads as the v13 shape — this migration is not for it"
        );
        let v12 = ContractV12::try_from_slice(&bytes).expect("the deployed STATE is not the v12 shape");
        let owner = v12.owner_id.clone();
        env::state_write(&v12);
        let c = Contract::migrate();
        assert_eq!(c.owner_id, owner);
        assert_eq!(c.get_storage_version(), "13");
        println!("v12 state of {} bytes, owner {owner}, migrated", bytes.len());
    }
}
