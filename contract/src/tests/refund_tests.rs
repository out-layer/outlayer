//! Money back to its owner: the refund cap, the close → claim flow, and
//! `withdraw_balance`.
//!
//! The one rule under test everywhere: nothing leaves the contract that the
//! owner did not deposit on chain. A worker's report sets the ceiling the
//! owner asks for; the ledger sets the ceiling the contract pays.

use crate::payment::{DeletePaymentKeyResult, TopUpResult, MIN_TOP_UP_AMOUNT};
use crate::refunds::{claimable, refund_payout, CLAIM_COOLDOWN_NS, FLIGHT_STALE_BLOCKS, REFUND_SETTLE_DELAY_NS};
use crate::*;
use near_sdk::test_utils::{accounts, VMContextBuilder};
use near_sdk::{testing_env, NearToken, PromiseOrValue};

const T0: u64 = 1_000_000_000_000;

fn ctx(predecessor: AccountId) -> VMContextBuilder {
    let mut b = VMContextBuilder::new();
    b.current_account_id(accounts(0))
        .signer_account_id(predecessor.clone())
        .predecessor_account_id(predecessor)
        .block_timestamp(T0);
    b
}

fn token() -> AccountId {
    "usdc.test".parse().unwrap()
}

/// A contract with a payment token, owner accounts(0) (also the operator and
/// the account the private callbacks run as), and a user accounts(1).
fn fresh() -> Contract {
    testing_env!(ctx(accounts(0)).build());
    let mut c = Contract::new(accounts(0), Some(accounts(0)), None, None);
    c.set_payment_token_contract(Some(token()));
    c
}

/// accounts(1) stores a payment key at `nonce`, paying exactly the quote.
fn store_key(c: &mut Contract, nonce: u32) {
    testing_env!(ctx(accounts(1)).build());
    let cost = c.estimate_storage_cost(
        SecretAccessor::System(SystemSecretType::PaymentKey),
        nonce.to_string(),
        accounts(1),
        "encrypted".to_string(),
        types::AccessCondition::AllowAll,
        None,
    );
    testing_env!(ctx(accounts(1)).attached_deposit(NearToken::from_yoctonear(cost.0)).build());
    c.store_secrets(
        SecretAccessor::System(SystemSecretType::PaymentKey),
        nonce.to_string(),
        "encrypted".to_string(),
        types::AccessCondition::AllowAll,
        None,
    );
}

fn has_key(c: &Contract, nonce: u32) -> bool {
    c.get_secrets(
        SecretAccessor::System(SystemSecretType::PaymentKey),
        nonce.to_string(),
        accounts(1),
    )
    .is_some()
}

/// The worker re-encrypted the key with `amount` more: the top-up's callback.
/// Returns what the callback sends back to the payer.
fn credit(c: &mut Contract, nonce: u32, amount: u128) -> u128 {
    testing_env!(ctx(accounts(0)).build());
    c.on_top_up_response(
        accounts(1),
        nonce,
        U128(amount),
        Ok(TopUpResult::Success { new_encrypted_data: format!("blob+{amount}") }),
    )
    .0
}

/// accounts(1) tops up its key at `nonce`: the admission half (a yield opens).
fn admit_top_up(c: &mut Contract, nonce: u32, amount: u128) {
    ft_on_transfer(c, accounts(1), amount, &format!(r#"{{"action":"top_up_payment_key","nonce":{nonce}}}"#));
}

fn top_ups_in_flight(c: &Contract, nonce: u32) -> u32 {
    c.get_payment_key_flight(accounts(1), nonce).map(|f| f.top_ups_in_flight).unwrap_or(0)
}

/// The worker confirmed the coordinator soft-deleted the key: the close's
/// callback, at block time `at`.
fn confirm_close(c: &mut Contract, nonce: u32, at: u64) {
    testing_env!(ctx(accounts(0)).block_timestamp(at).build());
    c.on_close_payment_key_response(accounts(1), nonce, Ok(DeletePaymentKeyResult::Success));
}

/// The worker relayed the coordinator's quote: the claim's callback.
fn quote(c: &mut Contract, nonce: u32, amount: u128) -> PromiseOrValue<U128> {
    testing_env!(ctx(accounts(0)).block_timestamp(T0 + REFUND_SETTLE_DELAY_NS + 1).build());
    c.on_payment_key_refund_response(
        accounts(1),
        nonce,
        Ok(DeletePaymentKeyResult::Refund { amount: U128(amount) }),
    )
}

fn transfer_done(c: &mut Contract, nonce: u32, amount: u128, since: u64, ok: bool) -> u128 {
    testing_env!(ctx(accounts(0)).build());
    let r = if ok { Ok(()) } else { Err(near_sdk::PromiseError::Failed) };
    c.on_payment_key_refund_transfer(accounts(1), nonce, U128(amount), since, r).0
}

fn is_promise(v: &PromiseOrValue<U128>) -> bool {
    matches!(v, PromiseOrValue::Promise(_))
}

fn value_of(v: &PromiseOrValue<U128>) -> Option<u128> {
    match v {
        PromiseOrValue::Value(x) => Some(x.0),
        PromiseOrValue::Promise(_) => None,
    }
}

/// The stablecoin arrives through `ft_on_transfer` from the configured token.
fn ft_on_transfer(c: &mut Contract, sender: AccountId, amount: u128, msg: &str) {
    testing_env!(ctx(token()).build());
    c.ft_on_transfer(sender, U128(amount), msg.to_string());
}

fn one_yocto(predecessor: AccountId) -> VMContextBuilder {
    let mut b = ctx(predecessor);
    b.attached_deposit(NearToken::from_yoctonear(1));
    b
}

// ── the rule itself ─────────────────────────────────────────────────────────

#[test]
fn the_payout_is_the_report_or_the_cap_whichever_is_less() {
    assert_eq!(refund_payout(30_000, 50_000), (30_000, false), "under the cap: the report");
    assert_eq!(refund_payout(50_000, 50_000), (50_000, false), "at the cap: the report");
    assert_eq!(refund_payout(80_000, 50_000), (50_000, true), "over the cap: the cap, flagged");
    assert_eq!(refund_payout(5_000_000, 0), (0, true), "a grant-only key: nothing, flagged");
    assert_eq!(refund_payout(0, 50_000), (0, false), "a spent key: nothing");
    assert_eq!(refund_payout(9_999, 50_000), (0, false), "dust under $0.01: nothing, no transfer");
    assert_eq!(refund_payout(10_000, 50_000), (10_000, false), "$0.01 exactly is paid");
    assert_eq!(refund_payout(80_000, 9_999), (0, true), "a dust cap: nothing, flagged");
}

#[test]
fn a_claim_waits_a_day_from_the_close() {
    assert_eq!(claimable(T0, T0), Err(T0 + REFUND_SETTLE_DELAY_NS));
    assert_eq!(claimable(T0, T0 + REFUND_SETTLE_DELAY_NS - 1), Err(T0 + REFUND_SETTLE_DELAY_NS));
    assert_eq!(claimable(T0, T0 + REFUND_SETTLE_DELAY_NS), Ok(()));
    let _ = claimable(u64::MAX, u64::MAX); // saturates, never overflows
}

// ── the ledger ──────────────────────────────────────────────────────────────

/// A new key starts with a ledger at zero; the ledger's bytes are in its
/// deposit (the quote is what `store_key` attaches).
#[test]
fn a_new_key_has_a_zero_ledger() {
    let mut c = fresh();
    store_key(&mut c, 1);
    let v = c.get_payment_key_refund_ledger(accounts(1), 1).expect("created with the key");
    assert_eq!((v.user_funded.0, v.refunded.0, v.refundable_cap.0), (0, 0, 0));
    assert_eq!((v.closing_since, v.claimable_at), (None, None));
    assert_eq!(c.get_closing_payment_key_count(accounts(1)), 0);
    assert!(c.get_payment_key_refund_ledger(accounts(1), 2).is_none(), "no key, no ledger");
}

/// Only a top-up the chain ACCEPTED counts: the callback's success path, once
/// the blob holds the money. Two top-ups add up.
#[test]
fn a_top_up_the_chain_accepted_is_counted_as_user_funded() {
    let mut c = fresh();
    store_key(&mut c, 1);
    assert_eq!(credit(&mut c, 1, 50_000), 0, "accepted: nothing goes back");
    assert_eq!(credit(&mut c, 1, 25_000), 0);
    let v = c.get_payment_key_refund_ledger(accounts(1), 1).unwrap();
    assert_eq!((v.user_funded.0, v.refundable_cap.0), (75_000, 75_000));

    // A top-up on a key that is gone is returned, and counted nowhere.
    assert_eq!(credit(&mut c, 9, 50_000), 50_000, "no such key: the whole amount goes back");
    assert!(c.get_payment_key_refund_ledger(accounts(1), 9).is_none());

    // A worker error returns the money and counts nothing.
    testing_env!(ctx(accounts(0)).build());
    let back = c.on_top_up_response(
        accounts(1),
        1,
        U128(10_000),
        Ok(TopUpResult::Error { message: "keystore down".into() }),
    );
    assert_eq!(back.0, 10_000);
    assert_eq!(c.get_payment_key_refund_ledger(accounts(1), 1).unwrap().user_funded.0, 75_000);
}

/// A key from before the ledger existed has no entry; its first top-up after
/// the release creates one, counting only that top-up.
#[test]
fn a_pre_ledger_key_counts_only_what_comes_after() {
    let mut c = fresh();
    store_key(&mut c, 1);
    c.payment_key_refund_ledger
        .remove(&refunds::PaymentKeyId { owner: accounts(1), nonce: 1 });
    assert!(c.get_payment_key_refund_ledger(accounts(1), 1).is_none());
    credit(&mut c, 1, 40_000);
    assert_eq!(c.get_payment_key_refund_ledger(accounts(1), 1).unwrap().refundable_cap.0, 40_000);
}

// ── close ───────────────────────────────────────────────────────────────────

/// Closing takes a yocto, an existing key, a key not already closing, and a
/// closing count under the bound; the callback marks the key closing and
/// keeps its nonce used.
#[test]
fn a_close_marks_the_key_closing_and_keeps_its_nonce() {
    let mut c = fresh();
    store_key(&mut c, 1);
    testing_env!(one_yocto(accounts(1)).build());
    c.close_payment_key(1);
    // Nothing changed yet: the worker has not answered.
    assert!(c.get_payment_key_refund_ledger(accounts(1), 1).unwrap().closing_since.is_none());

    confirm_close(&mut c, 1, T0 + 5);
    let v = c.get_payment_key_refund_ledger(accounts(1), 1).unwrap();
    assert_eq!(v.closing_since, Some(T0 + 5));
    assert_eq!(v.claimable_at, Some(T0 + 5 + REFUND_SETTLE_DELAY_NS));
    assert!(has_key(&c, 1), "the secret stays until the refund is claimed");
    assert_eq!(c.get_closing_payment_key_count(accounts(1)), 1);
    assert_eq!(c.get_payment_key_nonce_floor(accounts(1)), 1);
    assert_eq!(c.get_next_payment_key_nonce(accounts(1)), 2);

    // A second confirmation (a replayed task) changes nothing.
    confirm_close(&mut c, 1, T0 + 99);
    assert_eq!(c.get_payment_key_refund_ledger(accounts(1), 1).unwrap().closing_since, Some(T0 + 5));
    assert_eq!(c.get_closing_payment_key_count(accounts(1)), 1);
}

#[test]
#[should_panic(expected = "Requires attached deposit of exactly 1 yoctoNEAR")]
fn a_close_needs_a_yocto() {
    let mut c = fresh();
    store_key(&mut c, 1);
    testing_env!(ctx(accounts(1)).build());
    c.close_payment_key(1);
}

#[test]
#[should_panic(expected = "Payment key not found")]
fn a_close_of_a_missing_key_is_refused() {
    let mut c = fresh();
    testing_env!(one_yocto(accounts(1)).build());
    c.close_payment_key(7);
}

#[test]
#[should_panic(expected = "is already closing")]
fn a_second_close_is_refused() {
    let mut c = fresh();
    store_key(&mut c, 1);
    confirm_close(&mut c, 1, T0);
    testing_env!(one_yocto(accounts(1)).build());
    c.close_payment_key(1);
}

/// An error or a timeout from the worker leaves the key live and unmarked.
#[test]
fn a_failed_close_leaves_the_key_live() {
    let mut c = fresh();
    store_key(&mut c, 1);
    testing_env!(ctx(accounts(0)).build());
    c.on_close_payment_key_response(
        accounts(1),
        1,
        Ok(DeletePaymentKeyResult::Error { message: "db down".into() }),
    );
    c.on_close_payment_key_response(accounts(1), 1, Err(near_sdk::PromiseError::Failed));
    c.on_close_payment_key_response(
        accounts(1),
        1,
        Ok(DeletePaymentKeyResult::Refund { amount: U128(5) }),
    );
    assert!(c.get_payment_key_refund_ledger(accounts(1), 1).unwrap().closing_since.is_none());
    assert_eq!(c.get_closing_payment_key_count(accounts(1)), 0);
    assert!(has_key(&c, 1));
    // And a top-up still lands on it.
    assert_eq!(credit(&mut c, 1, 10_000), 0);
}

/// One owner may have at most `MAX_CLOSING_KEYS_PER_OWNER` keys closing.
#[test]
fn the_closing_count_is_bounded() {
    let mut c = fresh();
    let max = refunds::MAX_CLOSING_KEYS_PER_OWNER;
    for n in 1..=max + 1 {
        store_key(&mut c, n);
    }
    for n in 1..=max {
        confirm_close(&mut c, n, T0);
    }
    assert_eq!(c.get_closing_payment_key_count(accounts(1)), max);
    testing_env!(one_yocto(accounts(1)).build());
    let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        c.close_payment_key(max + 1);
    }));
    assert!(refused.is_err(), "the {}th close is refused", max + 1);

    // A refund of one of them frees a place.
    let v = quote(&mut c, 1, 0);
    assert_eq!(value_of(&v), Some(0));
    assert_eq!(c.get_closing_payment_key_count(accounts(1)), max - 1);
    testing_env!(one_yocto(accounts(1)).build());
    c.close_payment_key(max + 1);
}

// ── nothing in flight when a key closes or goes ─────────────────────────────

/// A top-up admitted and not yet answered holds the key open: neither close
/// nor delete is accepted until its callback has run — whatever it answered.
#[test]
fn a_key_with_a_top_up_in_flight_is_neither_closed_nor_deleted() {
    let mut c = fresh();
    store_key(&mut c, 1);
    admit_top_up(&mut c, 1, 30_000);
    admit_top_up(&mut c, 1, 20_000);
    assert_eq!(top_ups_in_flight(&c, 1), 2);

    testing_env!(one_yocto(accounts(1)).build());
    let closed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| c.close_payment_key(1)));
    assert!(closed.is_err(), "close is refused while top-ups are in flight");
    testing_env!(one_yocto(accounts(1)).build());
    let deleted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| c.delete_payment_key(1)));
    assert!(deleted.is_err(), "delete is refused while top-ups are in flight");

    // One answered (credited), one still open: still refused.
    assert_eq!(credit(&mut c, 1, 30_000), 0);
    assert_eq!(top_ups_in_flight(&c, 1), 1);
    testing_env!(one_yocto(accounts(1)).build());
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| c.close_payment_key(1))).is_err());

    // The other times out: answered too, the key closes.
    testing_env!(ctx(accounts(0)).build());
    assert_eq!(
        c.on_top_up_response(accounts(1), 1, U128(20_000), Err(near_sdk::PromiseError::Failed)).0,
        20_000
    );
    assert_eq!(top_ups_in_flight(&c, 1), 0);
    assert!(c.get_payment_key_flight(accounts(1), 1).is_none(), "an empty record is dropped");
    testing_env!(one_yocto(accounts(1)).build());
    c.close_payment_key(1);
    assert_eq!(c.get_payment_key_refund_ledger(accounts(1), 1).unwrap().user_funded.0, 30_000);
}

/// Every branch of the top-up callback settles the count, and it never goes
/// below zero.
#[test]
fn every_top_up_answer_settles_the_count() {
    let mut c = fresh();
    store_key(&mut c, 1);
    for answer in [
        Ok(TopUpResult::Success { new_encrypted_data: "b".into() }),
        Ok(TopUpResult::Error { message: "e".into() }),
        Err(near_sdk::PromiseError::Failed),
    ] {
        admit_top_up(&mut c, 1, 10_000);
        assert_eq!(top_ups_in_flight(&c, 1), 1);
        testing_env!(ctx(accounts(0)).build());
        c.on_top_up_response(accounts(1), 1, U128(10_000), answer);
        assert_eq!(top_ups_in_flight(&c, 1), 0);
    }
    // A callback for a yield from before the count existed: no underflow.
    testing_env!(ctx(accounts(0)).build());
    c.on_top_up_response(accounts(1), 1, U128(10_000), Ok(TopUpResult::Error { message: "e".into() }));
    assert_eq!(top_ups_in_flight(&c, 1), 0);
    testing_env!(one_yocto(accounts(1)).build());
    c.close_payment_key(1);
}

/// The other half of the exclusion: while a close or a delete waits for its
/// answer, no top-up is admitted — whichever order the workers answer in, a
/// top-up can never be returned by the chain and credited by the coordinator.
#[test]
fn a_key_with_a_close_pending_takes_no_top_up() {
    let mut c = fresh();
    store_key(&mut c, 1);
    testing_env!(one_yocto(accounts(1)).build());
    c.close_payment_key(1);
    assert!(c.get_payment_key_flight(accounts(1), 1).unwrap().close_pending);
    let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| admit_top_up(&mut c, 1, 10_000)));
    assert!(refused.is_err(), "a top-up is refused while the close waits");

    // The close FAILED (RPC, timeout): the key is live again and takes top-ups.
    testing_env!(ctx(accounts(0)).build());
    c.on_close_payment_key_response(accounts(1), 1, Err(near_sdk::PromiseError::Failed));
    assert!(c.get_payment_key_flight(accounts(1), 1).is_none(), "nothing pending, record dropped");
    admit_top_up(&mut c, 1, 10_000);
    assert_eq!(credit(&mut c, 1, 10_000), 0);

    // The close SUCCEEDED: the flag clears, and the ledger refuses from here.
    testing_env!(one_yocto(accounts(1)).build());
    c.close_payment_key(1);
    confirm_close(&mut c, 1, T0);
    assert!(!c.get_payment_key_flight(accounts(1), 1).map(|f| f.close_pending).unwrap_or(false));
    let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| admit_top_up(&mut c, 1, 10_000)));
    assert!(refused.is_err(), "a closing key takes no top-up");

    // A delete pending refuses top-ups the same way; an Error answer frees it.
    store_key(&mut c, 2);
    testing_env!(one_yocto(accounts(1)).build());
    c.delete_payment_key(2);
    let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| admit_top_up(&mut c, 2, 10_000)));
    assert!(refused.is_err(), "a top-up is refused while the delete waits");
    testing_env!(ctx(accounts(0)).build());
    c.on_delete_payment_key_response(accounts(1), 2, Ok(DeletePaymentKeyResult::Error { message: "db".into() }));
    admit_top_up(&mut c, 2, 10_000);

    // A stale flag (the callback never ran within the window) does not brick
    // top-ups either.
    store_key(&mut c, 3);
    testing_env!(one_yocto(accounts(1)).build());
    c.close_payment_key(3);
    let mut late = ctx(token());
    late.block_height(FLIGHT_STALE_BLOCKS + 1);
    testing_env!(late.build());
    c.ft_on_transfer(accounts(1), U128(10_000), r#"{"action":"top_up_payment_key","nonce":3}"#.to_string());
}

/// One close or delete at a time: a second one while the first waits would
/// share the flag, and the first answer would clear it under the second.
#[test]
fn a_second_close_or_delete_while_one_waits_is_refused() {
    let mut c = fresh();
    store_key(&mut c, 1);
    testing_env!(one_yocto(accounts(1)).build());
    c.close_payment_key(1);
    for again in ["close", "delete"] {
        testing_env!(one_yocto(accounts(1)).build());
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if again == "close" { c.close_payment_key(1) } else { c.delete_payment_key(1) }
        }));
        assert!(r.is_err(), "a second {again} while the first close waits is refused");
    }
    // The first is answered (failed): the flag clears, and a delete goes through.
    testing_env!(ctx(accounts(0)).build());
    c.on_close_payment_key_response(accounts(1), 1, Err(near_sdk::PromiseError::Failed));
    testing_env!(one_yocto(accounts(1)).build());
    c.delete_payment_key(1);
    testing_env!(one_yocto(accounts(1)).build());
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| c.close_payment_key(1)));
    assert!(r.is_err(), "a close while the delete waits is refused");
}

#[test]
#[should_panic(expected = "Requires attached deposit of exactly 1 yoctoNEAR")]
fn a_delete_needs_exactly_a_yocto() {
    let mut c = fresh();
    store_key(&mut c, 1);
    testing_env!(ctx(accounts(1)).attached_deposit(NearToken::from_yoctonear(2)).build());
    c.delete_payment_key(1);
}

/// A count that outlived the yield window is a defect, not a lock: close
/// ignores it.
#[test]
fn a_stale_in_flight_count_does_not_brick_the_key() {
    let mut c = fresh();
    store_key(&mut c, 1);
    admit_top_up(&mut c, 1, 10_000);
    let mut late = one_yocto(accounts(1));
    late.block_height(FLIGHT_STALE_BLOCKS + 1);
    testing_env!(late.build());
    c.close_payment_key(1);
    assert_eq!(top_ups_in_flight(&c, 1), 0, "the stale count was dropped");
}

// ── one claim at a time, an hour apart ──────────────────────────────────────

#[test]
fn one_claim_is_in_flight_at_a_time_and_an_hour_apart() {
    let mut c = fresh();
    store_key(&mut c, 1);
    credit(&mut c, 1, 40_000);
    confirm_close(&mut c, 1, T0);
    let open = T0 + REFUND_SETTLE_DELAY_NS;
    testing_env!(one_yocto(accounts(1)).block_timestamp(open).block_height(10).build());
    c.claim_payment_key_refund(1);
    let f = c.get_payment_key_flight(accounts(1), 1).expect("a claim is open");
    assert!(f.claim_open);
    assert_eq!(f.next_claim_at, Some(open + CLAIM_COOLDOWN_NS));

    // A second claim while the first is open: refused.
    testing_env!(one_yocto(accounts(1)).block_timestamp(open + 1).block_height(11).build());
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| c.claim_payment_key_refund(1)));
    assert!(r.is_err(), "a claim in flight refuses another");

    // Answered with a refusal (money in flight on the coordinator): closing
    // still, but the next claim waits for the cooldown (a day).
    testing_env!(ctx(accounts(0)).block_timestamp(open + 2).build());
    c.on_payment_key_refund_response(accounts(1), 1, Ok(DeletePaymentKeyResult::Error { message: "in_flight".into() }));
    assert!(!c.get_payment_key_flight(accounts(1), 1).unwrap().claim_open);
    testing_env!(one_yocto(accounts(1)).block_timestamp(open + CLAIM_COOLDOWN_NS - 1).block_height(12).build());
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| c.claim_payment_key_refund(1)));
    assert!(r.is_err(), "inside the cooldown");
    testing_env!(one_yocto(accounts(1)).block_timestamp(open + CLAIM_COOLDOWN_NS).block_height(13).build());
    c.claim_payment_key_refund(1);

    // A claim whose callback never ran (stale by height) does not lock the key.
    testing_env!(one_yocto(accounts(1)).block_timestamp(open + 2 * CLAIM_COOLDOWN_NS).block_height(13 + FLIGHT_STALE_BLOCKS + 1).build());
    c.claim_payment_key_refund(1);
}

/// A refund that pays drops the flight record with the ledger.
#[test]
fn a_paid_refund_drops_the_flight_record() {
    let mut c = fresh();
    store_key(&mut c, 1);
    credit(&mut c, 1, 40_000);
    confirm_close(&mut c, 1, T0);
    testing_env!(one_yocto(accounts(1)).block_timestamp(T0 + REFUND_SETTLE_DELAY_NS).build());
    c.claim_payment_key_refund(1);
    assert!(is_promise(&quote(&mut c, 1, 40_000)));
    transfer_done(&mut c, 1, 40_000, T0, true);
    assert!(c.get_payment_key_flight(accounts(1), 1).is_none());
}

// ── a top-up that cannot land goes back to its sender, whoever that is ──────

/// One return rule: NEP-141 gives a refused transfer back to its SENDER. A
/// NEAR top-up is delivered by the swap account, so on a closing key the
/// stablecoin goes back there — the owner is told not to close a key with a
/// top-up in progress. No case analysis on the sender, nothing credited
/// anywhere.
#[test]
fn a_refused_top_up_goes_back_to_its_sender_whoever_that_is() {
    let swap: AccountId = "swap.test".parse().unwrap();
    let mut c = fresh();
    store_key(&mut c, 1);
    admit_top_up(&mut c, 1, 30_000);
    confirm_close(&mut c, 1, T0);
    assert_eq!(credit(&mut c, 1, 30_000), 30_000, "the whole amount goes back");
    assert_eq!(c.get_user_stablecoin_balance(accounts(1)).0, 0, "nothing lands on a balance");
    assert_eq!(c.get_payment_key_refund_ledger(accounts(1), 1).unwrap().user_funded.0, 0);

    // At admission the refusal is a panic, and NEP-141 returns the transfer
    // to the sender — the swap account here.
    let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        ft_on_transfer(&mut c, swap, 20_000, &format!(r#"{{"action":"top_up_payment_key","nonce":1,"owner":"{}"}}"#, accounts(1)));
    }));
    assert!(refused.is_err());
    assert_eq!(c.get_user_stablecoin_balance(accounts(1)).0, 0);
}

#[test]
#[should_panic(expected = "Payment key not found")]
fn a_top_up_of_a_missing_key_is_returned() {
    let mut c = fresh();
    admit_top_up(&mut c, 9, 20_000);
}

// ── the other doors ─────────────────────────────────────────────────────────

#[test]
#[should_panic(expected = "A payment key is not deleted here")]
fn delete_secrets_refuses_a_payment_key() {
    let mut c = fresh();
    store_key(&mut c, 1);
    testing_env!(ctx(accounts(1)).build());
    c.delete_secrets(SecretAccessor::System(SystemSecretType::PaymentKey), "1".to_string());
}

/// A delete answered after a claim already retired the secret does not panic.
#[test]
fn a_delete_answered_after_the_refund_retired_the_key_is_harmless() {
    let mut c = fresh();
    store_key(&mut c, 1);
    confirm_close(&mut c, 1, T0);
    assert_eq!(value_of(&quote(&mut c, 1, 0)), Some(0));
    assert!(!has_key(&c, 1));
    testing_env!(ctx(accounts(0)).build());
    c.on_delete_payment_key_response(accounts(1), 1, Ok(DeletePaymentKeyResult::Success));
    assert!(c.get_payment_key_refund_ledger(accounts(1), 1).is_none());
}

// ── a closing key takes no money ────────────────────────────────────────────

#[test]
#[should_panic(expected = "is closing since")]
fn a_closing_key_refuses_a_top_up_at_admission() {
    let mut c = fresh();
    store_key(&mut c, 1);
    confirm_close(&mut c, 1, T0);
    ft_on_transfer(
        &mut c,
        accounts(1),
        50_000,
        r#"{"action":"top_up_payment_key","nonce":1}"#,
    );
}

/// A top-up admitted before the close and answered after it is returned to
/// the payer, and counted nowhere.
#[test]
fn a_top_up_answered_after_the_close_goes_back() {
    let mut c = fresh();
    store_key(&mut c, 1);
    credit(&mut c, 1, 30_000);
    confirm_close(&mut c, 1, T0);
    assert_eq!(credit(&mut c, 1, 20_000), 20_000, "returned");
    let v = c.get_payment_key_refund_ledger(accounts(1), 1).unwrap();
    assert_eq!(v.user_funded.0, 30_000, "the late top-up is not counted");
}

#[test]
#[should_panic(expected = "is closing since")]
fn a_closing_key_refuses_a_near_top_up() {
    let mut c = fresh();
    store_key(&mut c, 1);
    confirm_close(&mut c, 1, T0);
    testing_env!(ctx(accounts(1)).attached_deposit(NearToken::from_near(1)).build());
    c.top_up_payment_key_with_near(1, "swap.test".parse().unwrap());
}

// ── claim ───────────────────────────────────────────────────────────────────

#[test]
#[should_panic(expected = "is not closing")]
fn a_claim_on_a_live_key_is_refused() {
    let mut c = fresh();
    store_key(&mut c, 1);
    testing_env!(one_yocto(accounts(1)).build());
    c.claim_payment_key_refund(1);
}

#[test]
#[should_panic(expected = "can be claimed from")]
fn a_claim_before_the_delay_is_refused() {
    let mut c = fresh();
    store_key(&mut c, 1);
    confirm_close(&mut c, 1, T0);
    testing_env!(one_yocto(accounts(1)).block_timestamp(T0 + REFUND_SETTLE_DELAY_NS - 1).build());
    c.claim_payment_key_refund(1);
}

/// After the delay the claim yields (nothing changes until the worker
/// answers).
#[test]
fn a_claim_after_the_delay_is_accepted() {
    let mut c = fresh();
    store_key(&mut c, 1);
    confirm_close(&mut c, 1, T0);
    testing_env!(one_yocto(accounts(1)).block_timestamp(T0 + REFUND_SETTLE_DELAY_NS).build());
    c.claim_payment_key_refund(1);
    assert!(has_key(&c, 1));
    assert_eq!(c.get_payment_key_refund_ledger(accounts(1), 1).unwrap().closing_since, Some(T0));
}

/// A grant-only key — nothing deposited on chain — is quoted a balance by
/// the coordinator and gets nothing: the key is retired, the deposit back,
/// the ledger gone.
#[test]
fn a_grant_only_key_refunds_nothing() {
    let mut c = fresh();
    store_key(&mut c, 1);
    confirm_close(&mut c, 1, T0);
    let v = quote(&mut c, 1, 5_000_000);
    assert_eq!(value_of(&v), Some(0), "paid nothing, no transfer");
    assert!(!has_key(&c, 1), "the key is retired");
    assert!(c.get_payment_key_refund_ledger(accounts(1), 1).is_none(), "the ledger is dropped");
    assert_eq!(c.get_closing_payment_key_count(accounts(1)), 0);
    assert_eq!(c.get_payment_key_nonce_floor(accounts(1)), 1);
}

/// A report above what the owner deposited pays the deposit, not the report.
#[test]
fn a_refund_is_capped_at_what_the_owner_deposited() {
    let mut c = fresh();
    store_key(&mut c, 1);
    credit(&mut c, 1, 50_000);
    confirm_close(&mut c, 1, T0);
    let v = quote(&mut c, 1, 80_000);
    assert!(is_promise(&v), "a transfer is made");
    let l = c.get_payment_key_refund_ledger(accounts(1), 1).unwrap();
    assert_eq!(l.refunded.0, 50_000, "the cap, not the report");
    assert_eq!(l.refundable_cap.0, 0);
    assert_eq!(l.closing_since, None, "no longer closing while the transfer runs");
    assert_eq!(c.get_closing_payment_key_count(accounts(1)), 0, "and the count follows");
    assert!(!has_key(&c, 1));

    // A claim during the transfer is refused: the key is not closing.
    testing_env!(one_yocto(accounts(1)).block_timestamp(T0 + REFUND_SETTLE_DELAY_NS + 2).build());
    let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| c.claim_payment_key_refund(1)));
    assert!(refused.is_err(), "no second claim while the transfer runs");

    assert_eq!(transfer_done(&mut c, 1, 50_000, T0, true), 50_000);
    assert!(c.get_payment_key_refund_ledger(accounts(1), 1).is_none());
    assert_eq!(c.get_closing_payment_key_count(accounts(1)), 0);
}

/// A key partly spent refunds what the coordinator says is left, when that is
/// within the cap.
#[test]
fn a_partial_spend_refunds_the_remainder() {
    let mut c = fresh();
    store_key(&mut c, 1);
    credit(&mut c, 1, 100_000);
    confirm_close(&mut c, 1, T0);
    let v = quote(&mut c, 1, 30_000);
    assert!(is_promise(&v));
    assert_eq!(c.get_payment_key_refund_ledger(accounts(1), 1).unwrap().refunded.0, 30_000);
    assert_eq!(transfer_done(&mut c, 1, 30_000, T0, true), 30_000);
}

/// Mixed money: a user's $0.01 dust under a grant. The coordinator's quote
/// is what matters for the amount; the chain caps it to the dust.
#[test]
fn a_mixed_key_refunds_at_most_the_user_part() {
    let mut c = fresh();
    store_key(&mut c, 1);
    credit(&mut c, 1, 10_000);
    confirm_close(&mut c, 1, T0);
    // The coordinator, grant-first, quotes the dust; a forged or confused one
    // quoting the whole balance would be capped to the same number.
    let v = quote(&mut c, 1, 3_000_000);
    assert!(is_promise(&v));
    assert_eq!(c.get_payment_key_refund_ledger(accounts(1), 1).unwrap().refunded.0, 10_000);
}

/// A failed transfer un-counts the payout and puts the key back to closing
/// from its ORIGINAL close, so the owner claims again at once.
#[test]
fn a_failed_transfer_reopens_the_claim() {
    let mut c = fresh();
    store_key(&mut c, 1);
    credit(&mut c, 1, 40_000);
    confirm_close(&mut c, 1, T0);
    let v = quote(&mut c, 1, 40_000);
    assert!(is_promise(&v));
    assert_eq!(transfer_done(&mut c, 1, 40_000, T0, false), 0, "nothing was paid");

    let l = c.get_payment_key_refund_ledger(accounts(1), 1).unwrap();
    assert_eq!((l.refunded.0, l.refundable_cap.0), (0, 40_000), "the payout is un-counted");
    assert_eq!(l.closing_since, Some(T0), "closing again, from the original close");
    assert_eq!(c.get_closing_payment_key_count(accounts(1)), 1, "still one key closing");
    assert!(!has_key(&c, 1), "the secret stays gone");

    // Claim again: accepted at once (the delay ran from T0), paid in full.
    testing_env!(one_yocto(accounts(1)).block_timestamp(T0 + REFUND_SETTLE_DELAY_NS + 2).build());
    c.claim_payment_key_refund(1);
    let v = quote(&mut c, 1, 40_000);
    assert!(is_promise(&v));
    assert_eq!(c.get_payment_key_refund_ledger(accounts(1), 1).unwrap().refunded.0, 40_000);
    assert_eq!(transfer_done(&mut c, 1, 40_000, T0, true), 40_000);
    assert!(c.get_payment_key_refund_ledger(accounts(1), 1).is_none());
    assert_eq!(c.get_closing_payment_key_count(accounts(1)), 0);
}

/// Two quotes in a row — a replayed task — pay once: the second finds the key
/// no longer closing.
#[test]
fn a_replayed_quote_pays_once() {
    let mut c = fresh();
    store_key(&mut c, 1);
    credit(&mut c, 1, 40_000);
    confirm_close(&mut c, 1, T0);
    assert!(is_promise(&quote(&mut c, 1, 40_000)));
    assert_eq!(value_of(&quote(&mut c, 1, 40_000)), Some(0), "not closing: nothing paid");
    assert_eq!(c.get_payment_key_refund_ledger(accounts(1), 1).unwrap().refunded.0, 40_000);
    assert_eq!(transfer_done(&mut c, 1, 40_000, T0, true), 40_000);
    assert_eq!(value_of(&quote(&mut c, 1, 40_000)), Some(0), "no ledger: nothing paid");
}

/// A coordinator with calls still in flight answers an error; a delete-shaped
/// answer or a timeout is no quote either. The key stays closing, intact.
#[test]
fn a_refused_quote_keeps_the_key_closing() {
    let mut c = fresh();
    store_key(&mut c, 1);
    credit(&mut c, 1, 40_000);
    confirm_close(&mut c, 1, T0);
    testing_env!(ctx(accounts(0)).build());
    for answer in [
        Ok(DeletePaymentKeyResult::Error { message: "in_flight: 1 call pending".into() }),
        Ok(DeletePaymentKeyResult::Success),
        Err(near_sdk::PromiseError::Failed),
    ] {
        let v = c.on_payment_key_refund_response(accounts(1), 1, answer);
        assert_eq!(value_of(&v), Some(0));
    }
    let l = c.get_payment_key_refund_ledger(accounts(1), 1).unwrap();
    assert_eq!((l.refunded.0, l.closing_since), (0, Some(T0)));
    assert!(has_key(&c, 1), "the secret is kept");
    assert_eq!(c.get_closing_payment_key_count(accounts(1)), 1);
}

/// `delete_payment_key` on a closing key is the "I do not want the money"
/// path: the key goes, the ledger with it, and the closing place is freed.
#[test]
fn a_delete_forfeits_and_drops_the_ledger() {
    let mut c = fresh();
    store_key(&mut c, 1);
    credit(&mut c, 1, 40_000);
    confirm_close(&mut c, 1, T0);
    testing_env!(ctx(accounts(0)).build());
    c.on_delete_payment_key_response(accounts(1), 1, Ok(DeletePaymentKeyResult::Success));
    assert!(!has_key(&c, 1));
    assert!(c.get_payment_key_refund_ledger(accounts(1), 1).is_none());
    assert_eq!(c.get_closing_payment_key_count(accounts(1)), 0);
    // A quote arriving after that pays nothing.
    assert_eq!(value_of(&quote(&mut c, 1, 40_000)), Some(0));
}

// ── withdraw_balance ────────────────────────────────────────────────────────

fn deposit(c: &mut Contract, amount: u128) {
    ft_on_transfer(c, accounts(1), amount, r#"{"action":"deposit_balance"}"#);
}

#[test]
fn a_withdrawal_debits_first_and_restores_on_failure() {
    let mut c = fresh();
    deposit(&mut c, 250_000);
    assert_eq!(c.get_user_stablecoin_balance(accounts(1)).0, 250_000);

    testing_env!(one_yocto(accounts(1)).build());
    c.withdraw_balance(U128(100_000));
    assert_eq!(c.get_user_stablecoin_balance(accounts(1)).0, 150_000, "debited before the transfer");
    assert!(c.is_withdrawing(accounts(1)));

    testing_env!(ctx(accounts(0)).build());
    c.on_withdraw_balance(accounts(1), U128(100_000), Err(near_sdk::PromiseError::Failed));
    assert_eq!(c.get_user_stablecoin_balance(accounts(1)).0, 250_000, "restored");
    assert!(!c.is_withdrawing(accounts(1)));

    testing_env!(one_yocto(accounts(1)).build());
    c.withdraw_balance(U128(250_000));
    assert_eq!(c.get_user_stablecoin_balance(accounts(1)).0, 0);
    testing_env!(ctx(accounts(0)).build());
    c.on_withdraw_balance(accounts(1), U128(250_000), Ok(()));
    assert_eq!(c.get_user_stablecoin_balance(accounts(1)).0, 0);
    assert!(!c.is_withdrawing(accounts(1)));
}

#[test]
#[should_panic(expected = "already in flight")]
fn a_second_withdrawal_while_one_is_in_flight_is_refused() {
    let mut c = fresh();
    deposit(&mut c, 250_000);
    testing_env!(one_yocto(accounts(1)).build());
    c.withdraw_balance(U128(100_000));
    testing_env!(one_yocto(accounts(1)).build());
    c.withdraw_balance(U128(100_000));
}

#[test]
#[should_panic(expected = "Minimum withdrawal is $0.01")]
fn a_withdrawal_below_the_minimum_is_refused() {
    let mut c = fresh();
    deposit(&mut c, 250_000);
    testing_env!(one_yocto(accounts(1)).build());
    c.withdraw_balance(U128(MIN_TOP_UP_AMOUNT - 1));
}

#[test]
#[should_panic(expected = "Insufficient stablecoin balance")]
fn a_withdrawal_over_the_balance_is_refused() {
    let mut c = fresh();
    deposit(&mut c, 250_000);
    testing_env!(one_yocto(accounts(1)).build());
    c.withdraw_balance(U128(250_001));
}

#[test]
#[should_panic(expected = "Requires attached deposit of exactly 1 yoctoNEAR")]
fn a_withdrawal_needs_a_yocto() {
    let mut c = fresh();
    deposit(&mut c, 250_000);
    testing_env!(ctx(accounts(1)).build());
    c.withdraw_balance(U128(100_000));
}

#[test]
#[should_panic(expected = "Payment token contract not configured")]
fn a_withdrawal_without_a_token_moves_nothing() {
    testing_env!(ctx(accounts(0)).build());
    let mut c = Contract::new(accounts(0), Some(accounts(0)), None, None);
    c.user_stablecoin_balances.insert(&accounts(1), &250_000);
    testing_env!(one_yocto(accounts(1)).build());
    c.withdraw_balance(U128(100_000));
}

/// The deposit floor: below $0.01 the whole transfer is refused (NEP-141
/// returns it), so no entry is created at the contract's storage cost.
#[test]
#[should_panic(expected = "Minimum deposit is $0.01")]
fn a_deposit_below_the_minimum_is_refused() {
    let mut c = fresh();
    deposit(&mut c, MIN_TOP_UP_AMOUNT - 1);
}

#[test]
fn a_deposit_at_the_minimum_is_credited() {
    let mut c = fresh();
    deposit(&mut c, MIN_TOP_UP_AMOUNT);
    assert_eq!(c.get_user_stablecoin_balance(accounts(1)).0, MIN_TOP_UP_AMOUNT);
}
