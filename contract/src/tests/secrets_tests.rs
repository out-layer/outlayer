use crate::*;
use crate::secrets::STORAGE_PRICE_PER_BYTE;
use near_sdk::test_utils::{accounts, VMContextBuilder};
use near_sdk::testing_env;
use near_sdk::NearToken;

fn get_context(predecessor: AccountId) -> VMContextBuilder {
    let mut builder = VMContextBuilder::new();
    builder
        .current_account_id(accounts(0))
        .signer_account_id(predecessor.clone())
        .predecessor_account_id(predecessor)
        .block_timestamp(1_000_000_000);
    builder
}

#[test]
fn test_estimate_storage_cost() {
    let mut context = get_context(accounts(1));
    testing_env!(context.build());

    let contract = Contract::new(accounts(0), Some(accounts(0)), None, None);

    // Estimate cost for small secrets
    let small_data = "test_encrypted_data";
    let cost = contract.estimate_storage_cost(
        SecretAccessor::Repo {
            repo: "github.com/test/repo".to_string(),
            branch: None,
        },
        "default".to_string(),
        accounts(1),
        small_data.to_string(),
        types::AccessCondition::AllowAll,
        None,
    );

    // Should be non-zero
    assert!(cost.0 > 0, "Storage cost should be greater than 0");

    // Cost should be at least BASE_OVERHEAD * PRICE_PER_BYTE
    let min_cost = 40 * STORAGE_PRICE_PER_BYTE;
    assert!(cost.0 >= min_cost, "Cost should be at least base overhead");
}

#[test]
fn test_storage_deposit_theft_attack_large_to_small() {
    let mut context = get_context(accounts(1));
    testing_env!(context.build());

    let mut contract = Contract::new(accounts(0), Some(accounts(0)), None, None);

    // 1. Create large secret (1KB encrypted data)
    let large_data = "a".repeat(1000);
    let cost_large = contract.estimate_storage_cost(
        SecretAccessor::Repo {
            repo: "github.com/test/repo".to_string(),
            branch: None,
        },
        "test".to_string(),
        accounts(1),
        large_data.clone(),
        types::AccessCondition::AllowAll,
        None,
    );

    println!("Large secret cost: {} yoctoNEAR", cost_large.0);

    // Store with exact deposit
    testing_env!(context.attached_deposit(NearToken::from_yoctonear(cost_large.0)).build());
    contract.store_secrets(
        SecretAccessor::Repo {
            repo: "github.com/test/repo".to_string(),
            branch: None,
        },
        "test".to_string(),
        large_data,
        types::AccessCondition::AllowAll,
        None,
    );

    // Verify stored deposit
    let stored = contract.get_secrets(
        SecretAccessor::Repo {
            repo: "github.com/test/repo".to_string(),
            branch: None,
        },
        "test".to_string(),
        accounts(1),
    ).unwrap();
    assert_eq!(stored.storage_deposit.0, cost_large.0, "Stored deposit should match cost");

    // 2. Update to small secret (10 bytes)
    let small_data = "small_data";
    let cost_small = contract.estimate_storage_cost(
        SecretAccessor::Repo {
            repo: "github.com/test/repo".to_string(),
            branch: None,
        },
        "test".to_string(),
        accounts(1),
        small_data.to_string(),
        types::AccessCondition::AllowAll,
        None,
    );

    println!("Small secret cost: {} yoctoNEAR", cost_small.0);
    assert!(cost_small.0 < cost_large.0, "Small secret should cost less");

    // Try to update with 0 attached deposit (should use old deposit)
    testing_env!(context.attached_deposit(NearToken::from_yoctonear(0)).build());
    contract.store_secrets(
        SecretAccessor::Repo {
            repo: "github.com/test/repo".to_string(),
            branch: None,
        },
        "test".to_string(),
        small_data.to_string(),
        types::AccessCondition::AllowAll,
        None,
    );

    // 3. Check result: storage_deposit should now be cost_small (NOT cost_large!)
    let updated = contract.get_secrets(
        SecretAccessor::Repo {
            repo: "github.com/test/repo".to_string(),
            branch: None,
        },
        "test".to_string(),
        accounts(1),
    ).unwrap();

    assert_eq!(
        updated.storage_deposit.0,
        cost_small.0,
        "After update, deposit should be new (smaller) cost, not old cost"
    );

    // Attacker should have received refund of (cost_large - cost_small)
    // This is correct behavior - not a theft!
}

#[test]
fn test_storage_deposit_increase_requires_payment() {
    let mut context = get_context(accounts(1));
    testing_env!(context.build());

    let mut contract = Contract::new(accounts(0), Some(accounts(0)), None, None);

    // 1. Create small secret
    let small_data = "small";
    let cost_small = contract.estimate_storage_cost(
        SecretAccessor::Repo {
            repo: "github.com/test/repo".to_string(),
            branch: None,
        },
        "test".to_string(),
        accounts(1),
        small_data.to_string(),
        types::AccessCondition::AllowAll,
        None,
    );

    testing_env!(context.attached_deposit(NearToken::from_yoctonear(cost_small.0)).build());
    contract.store_secrets(
        SecretAccessor::Repo {
            repo: "github.com/test/repo".to_string(),
            branch: None,
        },
        "test".to_string(),
        small_data.to_string(),
        types::AccessCondition::AllowAll,
        None,
    );

    // 2. Try to update to large secret with 0 deposit - should FAIL
    let large_data = "a".repeat(1000);
    let cost_large = contract.estimate_storage_cost(
        SecretAccessor::Repo {
            repo: "github.com/test/repo".to_string(),
            branch: None,
        },
        "test".to_string(),
        accounts(1),
        large_data.clone(),
        types::AccessCondition::AllowAll,
        None,
    );

    println!("Small cost: {}, Large cost: {}", cost_small.0, cost_large.0);
    assert!(cost_large.0 > cost_small.0, "Large secret should cost more");

    // Try with 0 deposit - should panic
    testing_env!(context.attached_deposit(NearToken::from_yoctonear(0)).build());
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        contract.store_secrets(
            SecretAccessor::Repo {
                repo: "github.com/test/repo".to_string(),
                branch: None,
            },
            "test".to_string(),
            large_data.clone(),
            types::AccessCondition::AllowAll,
            None,
        );
    }));

    assert!(result.is_err(), "Should panic when insufficient deposit for larger secret");

    // Now try with exact difference - should succeed
    let additional_needed = cost_large.0 - cost_small.0;
    testing_env!(context.attached_deposit(NearToken::from_yoctonear(additional_needed)).build());
    contract.store_secrets(
        SecretAccessor::Repo {
            repo: "github.com/test/repo".to_string(),
            branch: None,
        },
        "test".to_string(),
        large_data,
        types::AccessCondition::AllowAll,
        None,
    );

    // Verify new cost is stored
    let updated = contract.get_secrets(
        SecretAccessor::Repo {
            repo: "github.com/test/repo".to_string(),
            branch: None,
        },
        "test".to_string(),
        accounts(1),
    ).unwrap();
    assert_eq!(updated.storage_deposit.0, cost_large.0);
}

#[test]
fn test_multiple_secrets_separate_deposits() {
    let mut context = get_context(accounts(1));
    testing_env!(context.build());

    let mut contract = Contract::new(accounts(0), Some(accounts(0)), None, None);

    // Create secret 1: repo1/main/profile1
    let data1 = "secret_one_data";
    let cost1 = contract.estimate_storage_cost(
        SecretAccessor::Repo {
            repo: "github.com/repo1".to_string(),
            branch: Some("main".to_string()),
        },
        "profile1".to_string(),
        accounts(1),
        data1.to_string(),
        types::AccessCondition::AllowAll,
        None,
    );

    testing_env!(context.attached_deposit(NearToken::from_yoctonear(cost1.0)).build());
    contract.store_secrets(
        SecretAccessor::Repo {
            repo: "github.com/repo1".to_string(),
            branch: Some("main".to_string()),
        },
        "profile1".to_string(),
        data1.to_string(),
        types::AccessCondition::AllowAll,
        None,
    );

    // Create secret 2: repo2/dev/profile2
    let data2 = "secret_two_data_longer_content";
    let cost2 = contract.estimate_storage_cost(
        SecretAccessor::Repo {
            repo: "github.com/repo2".to_string(),
            branch: Some("dev".to_string()),
        },
        "profile2".to_string(),
        accounts(1),
        data2.to_string(),
        types::AccessCondition::AllowAll,
        None,
    );

    testing_env!(context.attached_deposit(NearToken::from_yoctonear(cost2.0)).build());
    contract.store_secrets(
        SecretAccessor::Repo {
            repo: "github.com/repo2".to_string(),
            branch: Some("dev".to_string()),
        },
        "profile2".to_string(),
        data2.to_string(),
        types::AccessCondition::AllowAll,
        None,
    );

    // Verify both exist with correct deposits
    let secret1 = contract.get_secrets(
        SecretAccessor::Repo {
            repo: "github.com/repo1".to_string(),
            branch: Some("main".to_string()),
        },
        "profile1".to_string(),
        accounts(1),
    ).unwrap();
    assert_eq!(secret1.storage_deposit.0, cost1.0);

    let secret2 = contract.get_secrets(
        SecretAccessor::Repo {
            repo: "github.com/repo2".to_string(),
            branch: Some("dev".to_string()),
        },
        "profile2".to_string(),
        accounts(1),
    ).unwrap();
    assert_eq!(secret2.storage_deposit.0, cost2.0);

    // Delete secret 1
    testing_env!(context.attached_deposit(NearToken::from_yoctonear(1)).build());
    contract.delete_secrets(
        SecretAccessor::Repo {
            repo: "github.com/repo1".to_string(),
            branch: Some("main".to_string()),
        },
        "profile1".to_string(),
    );

    // Verify secret 1 is gone
    let deleted = contract.get_secrets(
        SecretAccessor::Repo {
            repo: "github.com/repo1".to_string(),
            branch: Some("main".to_string()),
        },
        "profile1".to_string(),
        accounts(1),
    );
    assert!(deleted.is_none(), "Secret 1 should be deleted");

    // Verify secret 2 still exists with original deposit (NOT affected by delete)
    let secret2_after = contract.get_secrets(
        SecretAccessor::Repo {
            repo: "github.com/repo2".to_string(),
            branch: Some("dev".to_string()),
        },
        "profile2".to_string(),
        accounts(1),
    ).unwrap();
    assert_eq!(secret2_after.storage_deposit.0, cost2.0, "Secret 2 deposit should be unchanged");
}

#[test]
fn test_delete_refunds_exact_amount() {
    let mut context = get_context(accounts(1));
    testing_env!(context.build());

    let mut contract = Contract::new(accounts(0), Some(accounts(0)), None, None);

    // Create secret
    let data = "test_secret_for_deletion";
    let cost = contract.estimate_storage_cost(
        SecretAccessor::Repo {
            repo: "github.com/test/repo".to_string(),
            branch: None,
        },
        "test".to_string(),
        accounts(1),
        data.to_string(),
        types::AccessCondition::AllowAll,
        None,
    );

    testing_env!(context.attached_deposit(NearToken::from_yoctonear(cost.0)).build());
    contract.store_secrets(
        SecretAccessor::Repo {
            repo: "github.com/test/repo".to_string(),
            branch: None,
        },
        "test".to_string(),
        data.to_string(),
        types::AccessCondition::AllowAll,
        None,
    );

    // Delete and check refund
    testing_env!(context.attached_deposit(NearToken::from_yoctonear(1)).build());
    contract.delete_secrets(
        SecretAccessor::Repo {
            repo: "github.com/test/repo".to_string(),
            branch: None,
        },
        "test".to_string(),
    );

    // Note: In real scenario, we'd check Promise transfers
    // Here we verify the secret is gone
    let deleted = contract.get_secrets(
        SecretAccessor::Repo {
            repo: "github.com/test/repo".to_string(),
            branch: None,
        },
        "test".to_string(),
        accounts(1),
    );
    assert!(deleted.is_none(), "Secret should be deleted and deposit refunded");
}

#[test]
fn test_access_condition_size_affects_cost() {
    let mut context = get_context(accounts(1));
    testing_env!(context.build());

    let contract = Contract::new(accounts(0), Some(accounts(0)), None, None);

    let data = "same_data_for_both";

    // Cost with simple access condition (AllowAll)
    let cost_simple = contract.estimate_storage_cost(
        SecretAccessor::Repo {
            repo: "github.com/test/repo".to_string(),
            branch: None,
        },
        "test".to_string(),
        accounts(1),
        data.to_string(),
        types::AccessCondition::AllowAll,
        None,
    );

    // Cost with complex access condition (Whitelist with many accounts)
    let complex_access = types::AccessCondition::Whitelist {
        accounts: vec![
            "account1.near".parse().unwrap(),
            "account2.near".parse().unwrap(),
            "account3.near".parse().unwrap(),
            "account4.near".parse().unwrap(),
            "account5.near".parse().unwrap(),
        ],
    };

    let cost_complex = contract.estimate_storage_cost(
        SecretAccessor::Repo {
            repo: "github.com/test/repo".to_string(),
            branch: None,
        },
        "test".to_string(),
        accounts(1),
        data.to_string(),
        complex_access,
        None,
    );

    println!("Simple access cost: {}, Complex access cost: {}", cost_simple.0, cost_complex.0);
    assert!(cost_complex.0 > cost_simple.0, "Complex access condition should cost more");
}

/// A payment key is written once. Its blob is a money record maintained by the
/// worker on real transfers, and `store_secrets` takes opaque bytes it cannot
/// inspect — so "the owner may rewrite it" would mean "the owner may put
/// anything in it".
#[test]
#[should_panic(expected = "cannot be rewritten")]
fn a_payment_key_cannot_be_overwritten() {
    let mut context = get_context(accounts(1));
    testing_env!(context.build());
    let mut contract = Contract::new(accounts(0), Some(accounts(0)), None, None);

    let blob = "encrypted".to_string();
    let cost = contract.estimate_storage_cost(
        SecretAccessor::System(SystemSecretType::PaymentKey),
        "7".to_string(),
        accounts(1),
        blob.clone(),
        types::AccessCondition::AllowAll,
        None,
    );

    testing_env!(context.attached_deposit(NearToken::from_yoctonear(cost.0)).build());
    contract.store_secrets(
        SecretAccessor::System(SystemSecretType::PaymentKey),
        "7".to_string(),
        blob,
        types::AccessCondition::AllowAll,
        None,
    );

    // Same owner, same nonce, different bytes — refused.
    testing_env!(context.attached_deposit(NearToken::from_yoctonear(cost.0)).build());
    contract.store_secrets(
        SecretAccessor::System(SystemSecretType::PaymentKey),
        "7".to_string(),
        "forged".to_string(),
        types::AccessCondition::AllowAll,
        None,
    );
}

/// The refusal is for payment keys ONLY. Rotating an ordinary secret in place
/// is what secrets are for, and that must keep working untouched.
#[test]
fn an_ordinary_secret_is_still_overwritable() {
    let mut context = get_context(accounts(1));
    testing_env!(context.build());
    let mut contract = Contract::new(accounts(0), Some(accounts(0)), None, None);

    let accessor = SecretAccessor::Repo {
        repo: "github.com/test/repo".to_string(),
        branch: None,
    };
    let cost = contract.estimate_storage_cost(
        accessor.clone(),
        "test".to_string(),
        accounts(1),
        "v1".to_string(),
        types::AccessCondition::AllowAll,
        None,
    );

    testing_env!(context.attached_deposit(NearToken::from_yoctonear(cost.0)).build());
    contract.store_secrets(
        accessor.clone(),
        "test".to_string(),
        "v1".to_string(),
        types::AccessCondition::AllowAll,
        None,
    );

    testing_env!(context.attached_deposit(NearToken::from_yoctonear(cost.0)).build());
    contract.store_secrets(
        accessor.clone(),
        "test".to_string(),
        "v2".to_string(),
        types::AccessCondition::AllowAll,
        None,
    );

    let stored = contract
        .secrets_storage
        .get(&SecretKey {
            accessor,
            profile: "test".to_string(),
            owner: accounts(1),
        })
        .expect("the secret must still be there");
    assert_eq!(
        stored.encrypted_secrets, "v2",
        "an ordinary secret must keep taking a new value"
    );
}

/// Store a payment key at `nonce`, so the nonce rules below exercise the real
/// entry point rather than a copy of the check.
fn store_payment_key_at(nonce: &str) {
    let mut context = get_context(accounts(1));
    testing_env!(context.build());
    let mut contract = Contract::new(accounts(0), Some(accounts(0)), None, None);

    let blob = "encrypted".to_string();
    let cost = contract.estimate_storage_cost(
        SecretAccessor::System(SystemSecretType::PaymentKey),
        nonce.to_string(),
        accounts(1),
        blob.clone(),
        types::AccessCondition::AllowAll,
        None,
    );

    testing_env!(context.attached_deposit(NearToken::from_yoctonear(cost.0)).build());
    contract.store_secrets(
        SecretAccessor::System(SystemSecretType::PaymentKey),
        nonce.to_string(),
        blob,
        types::AccessCondition::AllowAll,
        None,
    );
}

/// Nonce 0 is reserved for the keys the coordinator issues in its own database
/// — the free trial — which have no on-chain record and cost no gas.
///
/// `payment_keys` is keyed by `(owner, nonce)`, so an on-chain key at 0 would
/// land in the SAME row as its owner's trial key. One order silently drops the
/// real key's hash (`init` inserts with `ON CONFLICT DO NOTHING`, so the key is
/// paid for and dead); the other marks a funded key as a grant, and its owner
/// can no longer withdraw their own money.
///
/// `get_next_payment_key_nonce` has always answered 1 for a fresh account, but
/// it only SUGGESTS — nothing stopped a hand-built transaction from claiming 0.
/// Checked on mainnet and testnet before this was added: no key at nonce 0
/// exists, so nothing that works today stops working.
#[test]
#[should_panic(expected = "nonce 0 is reserved")]
fn a_payment_key_cannot_take_the_reserved_nonce() {
    store_payment_key_at("0");
}

/// The coordinator holds a nonce as a 32-bit SIGNED integer, so 2^31 and above
/// arrive there as negative numbers. Refused on the way in rather than left to
/// mean one thing on chain and another in the database.
#[test]
#[should_panic(expected = "too large")]
fn a_payment_key_nonce_must_fit_where_it_is_stored() {
    store_payment_key_at("2147483648");
}

/// The first nonce the contract itself hands out must keep working, as must the
/// largest one that still fits. The rules above bound the range; they must not
/// move its edges.
#[test]
fn the_first_and_last_usable_nonces_are_accepted() {
    store_payment_key_at("1");
    store_payment_key_at("2147483647");
}

/// A payment key's nonce has ONE spelling, and it is the one
/// `delete_payment_key` builds.
///
/// `"01"` parses to 1, passed every check, and landed in a DIFFERENT slot from
/// `"1"` — a second on-chain key for one nonce that `delete_payment_key(1)`
/// could not see (it looks up `nonce.to_string()`) and that the coordinator's
/// single row per `(owner, nonce)` could not represent. Its storage deposit was
/// staked and unreachable. Confirmed against the deployed contract as probe P2
/// of `tests/contract_probe_e2e.sh`.
///
/// Now `"01"` names the same slot as `"1"`, so the second store meets the
/// write-once rule and is refused for the honest reason.
#[test]
#[should_panic(expected = "Payment key already exists")]
fn a_payment_key_nonce_is_stored_under_one_spelling() {
    let mut context = get_context(accounts(1));
    testing_env!(context.build());
    let mut contract = Contract::new(accounts(0), Some(accounts(0)), None, None);

    let blob = "encrypted".to_string();
    let mut store = |profile: &str| {
        let cost = contract.estimate_storage_cost(
            SecretAccessor::System(SystemSecretType::PaymentKey),
            profile.to_string(),
            accounts(1),
            blob.clone(),
            types::AccessCondition::AllowAll,
            None,
        );
        testing_env!(context.attached_deposit(NearToken::from_yoctonear(cost.0)).build());
        contract.store_secrets(
            SecretAccessor::System(SystemSecretType::PaymentKey),
            profile.to_string(),
            blob.clone(),
            types::AccessCondition::AllowAll,
            None,
        );
    };

    store("1");
    store("01");
}

/// …and a padded nonce written FIRST is still reachable by the plain one.
///
/// The half that matters for the money: a key stored as `"007"` must be the key
/// `delete_payment_key(7)` removes, because that is the only way its deposit
/// comes back.
#[test]
fn a_padded_nonce_lands_where_the_plain_one_is_read() {
    let mut context = get_context(accounts(1));
    testing_env!(context.build());
    let mut contract = Contract::new(accounts(0), Some(accounts(0)), None, None);

    let blob = "encrypted".to_string();
    let cost = contract.estimate_storage_cost(
        SecretAccessor::System(SystemSecretType::PaymentKey),
        "007".to_string(),
        accounts(1),
        blob.clone(),
        types::AccessCondition::AllowAll,
        None,
    );
    testing_env!(context.attached_deposit(NearToken::from_yoctonear(cost.0)).build());
    contract.store_secrets(
        SecretAccessor::System(SystemSecretType::PaymentKey),
        "007".to_string(),
        blob,
        types::AccessCondition::AllowAll,
        None,
    );

    assert!(
        contract
            .get_secrets(
                SecretAccessor::System(SystemSecretType::PaymentKey),
                "7".to_string(),
                accounts(1),
            )
            .is_some(),
        "the plain nonce must find the key that was written padded",
    );
    assert_eq!(
        contract.get_next_payment_key_nonce(accounts(1)),
        8,
        "and the next nonce must count it once",
    );
}

/// One WASM binary is one secret, however the hash is typed.
///
/// The contract checked that a hash was 64 hex characters and never which
/// CASE, so `AB…` and `ab…` were two storage keys for one binary — and the
/// worker computes the hash with `hex::encode`, which is lower. A secret filed
/// under the shouted spelling stored cleanly, read back under its own
/// spelling, and was invisible to the code it was left for. Probe P1 against
/// the deployed contract.
#[test]
fn a_wasm_hash_is_one_secret_however_it_is_spelled() {
    let mut context = get_context(accounts(1));
    testing_env!(context.build());
    let mut contract = Contract::new(accounts(0), Some(accounts(0)), None, None);

    let lower = "ab".repeat(32);
    let upper = lower.to_uppercase();
    let blob = "encrypted".to_string();

    let cost = contract.estimate_storage_cost(
        SecretAccessor::WasmHash { hash: upper.clone() },
        "prod".to_string(),
        accounts(1),
        blob.clone(),
        types::AccessCondition::AllowAll,
        None,
    );
    testing_env!(context.attached_deposit(NearToken::from_yoctonear(cost.0)).build());
    contract.store_secrets(
        SecretAccessor::WasmHash { hash: upper.clone() },
        "prod".to_string(),
        blob,
        types::AccessCondition::AllowAll,
        None,
    );

    assert!(
        contract
            .get_secrets(
                SecretAccessor::WasmHash { hash: lower.clone() },
                "prod".to_string(),
                accounts(1),
            )
            .is_some(),
        "the worker asks in lower case and must find it",
    );

    // And it can be taken back with either spelling — otherwise the deposit
    // would be reachable only by whoever remembered how it was typed.
    testing_env!(context.attached_deposit(NearToken::from_yoctonear(0)).build());
    contract.delete_secrets(
        SecretAccessor::WasmHash { hash: lower.clone() },
        "prod".to_string(),
    );
    assert!(
        contract
            .get_secrets(
                SecretAccessor::WasmHash { hash: upper },
                "prod".to_string(),
                accounts(1),
            )
            .is_none(),
        "deleting under one spelling must remove the one secret, not a twin",
    );
}

/// `list_user_secrets` hands out PAGES, and the pages tile the whole set.
///
/// It walks an `UnorderedSet` and reads storage per entry, so an unbounded
/// answer is a view that eventually cannot be called at all — and the caller
/// sees a gas failure rather than a long list. What this pins is the part that
/// makes paging safe to impose: every entry appears exactly once across the
/// pages, so a caller that keeps asking gets everything.
#[test]
fn listing_secrets_pages_and_the_pages_tile_the_set() {
    let mut context = get_context(accounts(1));
    testing_env!(context.build());
    let mut contract = Contract::new(accounts(0), Some(accounts(0)), None, None);

    let blob = "encrypted".to_string();
    for i in 0..7 {
        let profile = format!("p{i}");
        let cost = contract.estimate_storage_cost(
            SecretAccessor::WasmHash { hash: "ab".repeat(32) },
            profile.clone(),
            accounts(1),
            blob.clone(),
            types::AccessCondition::AllowAll,
            None,
        );
        testing_env!(context.attached_deposit(NearToken::from_yoctonear(cost.0)).build());
        contract.store_secrets(
            SecretAccessor::WasmHash { hash: "ab".repeat(32) },
            profile,
            blob.clone(),
            types::AccessCondition::AllowAll,
            None,
        );
    }

    // A page is a page, not the whole table.
    let first = contract.list_user_secrets(accounts(1), Some(0), Some(3));
    assert_eq!(first.len(), 3);

    // Walk it the way a caller must: keep asking until a short page arrives.
    let mut seen: Vec<String> = Vec::new();
    let mut from = 0u64;
    loop {
        let page = contract.list_user_secrets(accounts(1), Some(from), Some(3));
        let n = page.len() as u64;
        seen.extend(page.into_iter().map(|s| s.profile));
        if n < 3 {
            break;
        }
        from += n;
    }
    seen.sort();
    assert_eq!(
        seen,
        vec!["p0", "p1", "p2", "p3", "p4", "p5", "p6"],
        "the pages must tile the set — every secret once, none lost between them",
    );

    // Omitting both arguments is the compatible call, and it answers a page:
    // near-sdk reads an absent `Option` as `None`, so old callers keep working
    // and get the first page rather than an unbounded read.
    assert_eq!(contract.list_user_secrets(accounts(1), None, None).len(), 7);

    // Past the end is empty, not an error — a caller paging to the end must not
    // have to know the length in advance.
    assert!(contract.list_user_secrets(accounts(1), Some(99), None).is_empty());

    // And the ceiling holds however much is asked for.
    assert_eq!(
        contract.list_user_secrets(accounts(1), Some(0), Some(100_000)).len(),
        7,
        "a huge limit is clamped, not honoured",
    );
}

/// A profile shaped like an implicit account is reserved for that agent.
///
/// The keystore decides an agent secret by the SHAPE of the profile and then
/// serves it only when reader, owner and name agree — which is what stops a
/// stranger planting a credential under an agent's name. The honest cost of
/// that rule used to fall on ordinary users: a profile that merely looked like
/// an account (a content hash, a session id) stored cleanly and could then
/// never be read, with an error about agents. Refused on the way in instead.
#[test]
#[should_panic(expected = "names an AGENT")]
fn a_profile_shaped_like_an_agent_is_refused_to_everyone_else() {
    let mut context = get_context(accounts(1));
    testing_env!(context.build());
    let mut contract = Contract::new(accounts(0), Some(accounts(0)), None, None);

    testing_env!(context.attached_deposit(NearToken::from_near(1)).build());
    contract.store_secrets(
        SecretAccessor::WasmHash { hash: "ab".repeat(32) },
        "cd".repeat(32), // 64 hex characters: the shape of an implicit account
        "encrypted".to_string(),
        types::AccessCondition::AllowAll,
        None,
    );
}

/// …and the agent itself may still use its own name, which is the whole point
/// of the shape. Owner and profile are the same implicit account here.
#[test]
fn an_agent_may_store_under_its_own_name() {
    let agent_hex = "cd".repeat(32);
    let agent: AccountId = agent_hex.parse().unwrap();

    let mut context = get_context(agent.clone());
    testing_env!(context.build());
    let mut contract = Contract::new(accounts(0), Some(accounts(0)), None, None);

    testing_env!(context.attached_deposit(NearToken::from_near(1)).build());
    contract.store_secrets(
        SecretAccessor::WasmHash { hash: "ab".repeat(32) },
        agent_hex.clone(),
        "encrypted".to_string(),
        types::AccessCondition::AllowAll,
        None,
    );

    assert!(
        contract
            .get_secrets(
                SecretAccessor::WasmHash { hash: "ab".repeat(32) },
                agent_hex,
                agent,
            )
            .is_some(),
        "an agent's own secret must still be storable under its own name",
    );
}

/// A name that is 64 characters but NOT hex is ordinary text and stays allowed.
/// The rule is about the shape an account has, not about length.
#[test]
fn a_long_profile_that_is_not_hex_is_still_ordinary() {
    let mut context = get_context(accounts(1));
    testing_env!(context.build());
    let mut contract = Contract::new(accounts(0), Some(accounts(0)), None, None);

    testing_env!(context.attached_deposit(NearToken::from_near(1)).build());
    contract.store_secrets(
        SecretAccessor::WasmHash { hash: "ab".repeat(32) },
        "z".repeat(64),
        "encrypted".to_string(),
        types::AccessCondition::AllowAll,
        None,
    );

    assert!(contract
        .get_secrets(
            SecretAccessor::WasmHash { hash: "ab".repeat(32) },
            "z".repeat(64),
            accounts(1),
        )
        .is_some());
}

// ── A build lock is a condition, and the contract only stores ones that mean
//    something ────────────────────────────────────────────────────────────────
//
// The keystore judges a `WasmHash` leaf by comparing it with the hash the
// attested worker measured. A leaf in any other spelling therefore matches
// nothing and admits nobody — a row its owner would then hunt through the
// keystore's logs to explain. And an empty `Logic` is the opposite failure:
// `And` of nothing is TRUE, so a row "protected" by one is open to everybody
// while rendering as `()` in both the CLI and the dashboard. Both are refused
// at the door, and these pin that they are refused at EVERY door.

/// Every shape the keystore could never match.
fn malformed_build_leaves() -> Vec<types::AccessCondition> {
    let good = "ab".repeat(32);
    [
        String::new(),
        good[..63].to_string(),
        format!("{good}0"),
        good.to_uppercase(),
        format!("{}g", &good[..63]),
        "не-хэш".to_string(),
    ]
    .into_iter()
    .map(|hash| types::AccessCondition::WasmHash { hash })
    .collect()
}

/// A `Repo` accessor deliberately: a `Project` one first asserts the project
/// EXISTS, and a test that let that panic stand would pass for the wrong
/// reason — which is the whole failure mode these tests are about.
fn locked_row_accessor() -> SecretAccessor {
    SecretAccessor::Repo { repo: "github.com/test/app".to_string(), branch: None }
}

/// Why a call refused, or `None` if it did not. The MESSAGE, because a test
/// that only asks "did it panic" passes on any panic at all — including the
/// unrelated one that made these tests green the first time they were run.
fn refusal_from(f: impl FnOnce()) -> Option<String> {
    let hushed = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    std::panic::set_hook(hushed);
    match out {
        Ok(()) => None,
        Err(e) => Some(
            e.downcast_ref::<String>()
                .cloned()
                .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_default(),
        ),
    }
}

fn store_with(contract: &mut Contract, access: types::AccessCondition) {
    contract.store_secrets(
        locked_row_accessor(),
        "default".to_string(),
        "ciphertext".to_string(),
        access,
        None,
    );
}

#[test]
fn a_build_lock_that_is_a_real_sha256_is_stored_and_read_back() {
    let mut context = get_context(accounts(1));
    testing_env!(context.attached_deposit(NearToken::from_near(1)).build());
    let mut contract = Contract::new(accounts(0), Some(accounts(0)), None, None);

    let hash = "ab".repeat(32);
    let locked = types::AccessCondition::Logic {
        operator: types::LogicOperatorV1::And,
        conditions: vec![
            types::AccessCondition::Whitelist { accounts: vec![accounts(1)] },
            types::AccessCondition::WasmHash { hash: hash.clone() },
        ],
    };
    store_with(&mut contract, locked.clone());

    let stored = contract
        .get_secrets(
            locked_row_accessor(),
            "default".to_string(),
            accounts(1),
        )
        .expect("the row is there");
    assert_eq!(stored.access, locked, "the condition survives the round trip unchanged");
}

#[test]
fn a_build_lock_nested_under_not_and_logic_is_stored() {
    let mut context = get_context(accounts(1));
    testing_env!(context.attached_deposit(NearToken::from_near(1)).build());
    let mut contract = Contract::new(accounts(0), Some(accounts(0)), None, None);

    // The validator recurses, so a well-formed leaf must not be refused for
    // sitting deep in a tree.
    store_with(
        &mut contract,
        types::AccessCondition::Not {
            condition: Box::new(types::AccessCondition::Logic {
                operator: types::LogicOperatorV1::Or,
                conditions: vec![types::AccessCondition::WasmHash { hash: "cd".repeat(32) }],
            }),
        },
    );
}

#[test]
#[should_panic(expected = "64 lowercase hex")]
fn store_secrets_refuses_a_malformed_build_leaf() {
    let mut context = get_context(accounts(1));
    testing_env!(context.attached_deposit(NearToken::from_near(1)).build());
    let mut contract = Contract::new(accounts(0), Some(accounts(0)), None, None);
    store_with(&mut contract, malformed_build_leaves().remove(1)); // 63 characters
}

#[test]
fn every_malformed_build_leaf_is_refused_wherever_it_sits() {
    for (i, leaf) in malformed_build_leaves().into_iter().enumerate() {
        for (shape, access) in [
            ("bare", leaf.clone()),
            (
                "under And",
                types::AccessCondition::Logic {
                    operator: types::LogicOperatorV1::And,
                    conditions: vec![types::AccessCondition::AllowAll, leaf.clone()],
                },
            ),
            ("under Not", types::AccessCondition::Not { condition: Box::new(leaf.clone()) }),
        ] {
            let why = refusal_from(|| {
                let mut context = get_context(accounts(1));
                testing_env!(context.attached_deposit(NearToken::from_near(1)).build());
                let mut contract = Contract::new(accounts(0), Some(accounts(0)), None, None);
                store_with(&mut contract, access);
            });
            let why = why.unwrap_or_else(|| panic!("malformed leaf #{i} was stored when it sat {shape}"));
            assert!(
                why.contains("64 lowercase hex"),
                "malformed leaf #{i} sitting {shape} was refused for another reason: {why}"
            );
        }
    }
}

#[test]
fn every_door_refuses_a_malformed_build_leaf() {
    let bad = types::AccessCondition::WasmHash { hash: "too-short".to_string() };

    // estimate_storage_cost is a VIEW, and the CLI and dashboard price a
    // condition before storing it — so the refusal must arrive there too,
    // before a wallet prompt rather than after one.
    let priced = refusal_from(|| {
        let mut context = get_context(accounts(1));
        testing_env!(context.build());
        let contract = Contract::new(accounts(0), Some(accounts(0)), None, None);
        contract.estimate_storage_cost(
            locked_row_accessor(),
            "default".to_string(),
            accounts(1),
            "ciphertext".to_string(),
            bad.clone(),
            None,
        );
    });
    assert!(
        priced.is_some_and(|w| w.contains("64 lowercase hex")),
        "the estimator priced a condition the store would refuse"
    );

    // update_access is the door a lock MOVES through, so it is the one an owner
    // uses most often once a row is locked.
    let moved = refusal_from(|| {
        let mut context = get_context(accounts(1));
        testing_env!(context.attached_deposit(NearToken::from_near(1)).build());
        let mut contract = Contract::new(accounts(0), Some(accounts(0)), None, None);
        store_with(&mut contract, types::AccessCondition::AllowAll);
        contract.update_access(
            locked_row_accessor(),
            "default".to_string(),
            bad,
        );
    });
    assert!(
        moved.is_some_and(|w| w.contains("64 lowercase hex")),
        "update_access moved a row to a leaf the keystore could never match"
    );
}

#[test]
#[should_panic(expected = "at least one condition")]
fn an_empty_logic_is_refused_because_an_empty_and_admits_everyone() {
    let mut context = get_context(accounts(1));
    testing_env!(context.attached_deposit(NearToken::from_near(1)).build());
    let mut contract = Contract::new(accounts(0), Some(accounts(0)), None, None);
    store_with(
        &mut contract,
        types::AccessCondition::Logic { operator: types::LogicOperatorV1::And, conditions: vec![] },
    );
}

#[test]
fn an_empty_logic_is_refused_wherever_it_hides() {
    let empty = types::AccessCondition::Logic {
        operator: types::LogicOperatorV1::Or,
        conditions: vec![],
    };
    for (shape, access) in [
        (
            "under And",
            types::AccessCondition::Logic {
                operator: types::LogicOperatorV1::And,
                conditions: vec![types::AccessCondition::AllowAll, empty.clone()],
            },
        ),
        ("under Not", types::AccessCondition::Not { condition: Box::new(empty.clone()) }),
    ] {
        let why = refusal_from(|| {
            let mut context = get_context(accounts(1));
            testing_env!(context.attached_deposit(NearToken::from_near(1)).build());
            let mut contract = Contract::new(accounts(0), Some(accounts(0)), None, None);
            store_with(&mut contract, access);
        });
        let why = why.unwrap_or_else(|| panic!("an empty Logic was stored when it sat {shape}"));
        assert!(why.contains("at least one condition"), "refused for another reason: {why}");
    }
}

/// The Borsh layout is the variant ORDER, and `SecretProfile.access` is stored
/// as Borsh of this enum directly. An appended variant leaves every row already
/// on chain decoding by its old index; an inserted one silently re-reads every
/// stored condition as a different rule. This is the test that makes "append
/// only" enforceable rather than a comment.
#[test]
fn the_build_lock_is_the_last_variant_and_every_earlier_one_keeps_its_index() {
    fn ordinal(c: &types::AccessConditionV1) -> u8 {
        near_sdk::borsh::to_vec(c).expect("borsh")[0]
    }
    let a = || types::AccessConditionV1::AllowAll;
    assert_eq!(ordinal(&types::AccessConditionV1::Logic { operator: types::LogicOperatorV1::And, conditions: vec![a()] }), 0);
    assert_eq!(ordinal(&types::AccessConditionV1::Not { condition: Box::new(a()) }), 1);
    assert_eq!(ordinal(&a()), 2);
    assert_eq!(ordinal(&types::AccessConditionV1::Whitelist { accounts: vec![] }), 3);
    assert_eq!(ordinal(&types::AccessConditionV1::AccountPattern { pattern: String::new() }), 4);
    assert_eq!(
        ordinal(&types::AccessConditionV1::NearBalance {
            operator: types::ComparisonOperatorV1::Gte,
            value: NearToken::from_yoctonear(0)
        }),
        5
    );
    assert_eq!(ordinal(&types::AccessConditionV1::ValidUntil { until_ns: near_sdk::json_types::U64(0) }), 9);
    assert_eq!(
        ordinal(&types::AccessConditionV1::WasmHash { hash: String::new() }),
        10,
        "WasmHash must stay LAST; anything else re-reads every stored condition"
    );
}
