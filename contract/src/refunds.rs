//! Money back to its owner: a payment key's unspent balance, and the
//! stablecoin balance deposited for `attached_usd`.
//!
//! **The cap is the whole safety argument.** The contract sees every top-up a
//! user makes on chain — `TopUpPaymentKey` in `ft_on_transfer` — and never
//! sees a grant, a sponsor code or a trial: those are coordinator rows. So it
//! keeps, per key, what the user deposited and what was paid back, and pays a
//! refund of at most the difference. Whatever a worker or the coordinator
//! reports as the key's remaining balance — honest, inflated, or forged —
//! nothing leaves this contract that was not deposited on chain onto that
//! owner's key (by the owner, or by anybody paying for them: it is the key's
//! money, refundable to its owner alone).
//!
//! The ledger starts at zero for every key that existed before it did: only
//! deposits made after this release are refundable.
//!
//! A payment-key refund takes two transactions, because the amount is known
//! only after every call in flight on the key has settled, and that can take
//! longer than a yield lives:
//!
//!   1. `close_payment_key(nonce)` — the key stops taking calls (the
//!      coordinator soft-deletes it through the ordinary `DeletePaymentKey`
//!      task) and is marked closing on chain. Nothing else changes.
//!   2. `claim_payment_key_refund(nonce)` — after `REFUND_SETTLE_DELAY`, the
//!      worker asks the coordinator what is left; the contract pays
//!      `min(reported, cap)`, deletes the key and refunds its storage.
//!
//! `withdraw_balance(amount)` is one transaction: the balance is already net of
//! everything in flight (`request_execution` debits at admission), so it is
//! debit, transfer, credit back on failure — the `withdraw_developer_earnings`
//! pattern.

use crate::payment::{DeletePaymentKeyResult, SystemEvent, MIN_TOP_UP_AMOUNT};
use crate::*;
use near_sdk::serde_json::json;
use near_sdk::{env, log, near_bindgen, AccountId, Gas, GasWeight, NearToken, Promise, PromiseError, PromiseOrValue};

/// How long a closed key waits before its refund can be claimed: a day. Every
/// call the key had in flight settles well inside it; the decisive rule is
/// still the coordinator's — a quote is refused while anything is reserved on
/// the key — this delay only keeps the first claim from being that refusal.
pub const REFUND_SETTLE_DELAY_NS: u64 = 24 * 60 * 60 * 1_000_000_000;

/// How many keys one owner may have closing at once. Each closing key is a
/// delete task and, later, a refund task on the worker queue; a storage
/// deposit per key already prices the loop, this bounds its width.
pub const MAX_CLOSING_KEYS_PER_OWNER: u32 = 20;

/// Blocks after which an in-flight record is stale: the chain's yield window
/// (200 blocks) and the same again as margin. A yield's callback always runs,
/// resumed or timed out, so a count that outlives this is a defect — and it
/// must not brick the key: close, delete and claim ignore a stale record.
pub const FLIGHT_STALE_BLOCKS: u64 = 400;

/// Between two claims of one key: a day, the same as the settlement delay.
/// A claim is a yield, a worker task, a coordinator quote and a worker
/// transaction at the operator's gas; the owner pays about as much gas as the
/// operator, so a claim loop is bounded by the owner's own money — but a claim
/// refused because a call of the key is still running (a long generation can
/// run for hours) is not worth repeating sooner than that, and a claim is a
/// money path: slow and simple over quick. One claim is in flight at a time
/// as well.
pub const CLAIM_COOLDOWN_NS: u64 = 24 * 60 * 60 * 1_000_000_000;

/// Gas for the close yield's callback: a ledger write and a floor raise.
pub const CLOSE_CALLBACK_GAS: Gas = Gas::from_tgas(30);

/// Gas for the refund yield's callback: it removes the secret, writes the
/// ledger and creates the transfer with its own callback. The weight share of
/// the claim's unused gas comes on top.
pub const REFUND_CALLBACK_GAS: Gas = Gas::from_tgas(50);

/// Gas for the stablecoin `ft_transfer` a refund or a withdrawal makes.
pub const REFUND_TRANSFER_GAS: Gas = Gas::from_tgas(10);

/// Gas for the callback that settles a transfer's outcome.
pub const REFUND_TRANSFER_CALLBACK_GAS: Gas = Gas::from_tgas(10);

/// Which payment key a ledger entry is about: the key of
/// `payment_key_refund_ledger`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[near(serializers = [borsh, json])]
pub struct PaymentKeyId {
    pub owner: AccountId,
    pub nonce: u32,
}

/// What the chain itself knows about one payment key's money.
///
/// Borsh-encoded as the VALUE of `payment_key_refund_ledger`, and borsh has no
/// schema evolution: anything new about a key's refund belongs in a side map,
/// never appended here.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[near(serializers = [borsh])]
pub struct RefundLedger {
    /// Σ of the stablecoin top-ups the contract accepted on this key since the
    /// ledger exists. Never a grant, a sponsor's gift or a trial: none of
    /// those pass through `ft_on_transfer`.
    pub user_funded: u128,
    /// Σ of the refunds paid out of this key.
    pub refunded: u128,
    /// The block timestamp the key was closed at, while it is closing.
    pub closing_since: Option<u64>,
}

impl RefundLedger {
    /// The most a refund of this key may pay: what its owner deposited and has
    /// not had back.
    pub fn cap(&self) -> u128 {
        self.user_funded.saturating_sub(self.refunded)
    }
}

/// What is in flight on a payment key, beside the ledger (borsh has no schema
/// evolution, so a new fact about a key is a new map).
///
/// A top-up is admitted in one receipt and answered in another, blocks later,
/// in the PAYER's receipt chain. A close or a delete that lands between the
/// two changes what the answer does with the money, and the worker, which
/// credits the coordinator on its own resume, never sees that answer. So a
/// key is closed or deleted only while `top_ups == 0`: counted up at
/// admission, down as the first thing every branch of the top-up callback
/// does, the timeout's included.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[near(serializers = [borsh])]
pub struct KeyFlight {
    /// Top-up yields admitted and not yet answered.
    pub top_ups: u32,
    /// The block the last top-up was admitted in: a count older than
    /// `FLIGHT_STALE_BLOCKS` is ignored.
    pub last_top_up_height: u64,
    /// A refund claim yielded and not yet answered.
    pub claim_open: bool,
    /// The block the last claim was made in, for the same staleness rule.
    pub last_claim_height: u64,
    /// When the last claim was made (block timestamp, ns): the cooldown.
    pub last_claim_at: u64,
    /// A close or a delete yielded and not yet answered. While it is set no
    /// top-up is admitted: the other half of the exclusion — a top-up in
    /// flight refuses a close, a close in flight refuses a top-up — so the
    /// two can never be answered in an order that returns money the
    /// coordinator then credits, whatever the workers do.
    pub close_pending: bool,
    /// The block the close or delete was made in, for the staleness rule.
    pub close_pending_height: u64,
}

/// The ledger as a view answers it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[near(serializers = [json])]
pub struct PaymentKeyRefundView {
    pub owner: AccountId,
    pub nonce: u32,
    /// Stablecoin deposited on chain on this key since the ledger exists.
    pub user_funded: U128,
    /// Stablecoin already refunded from it.
    pub refunded: U128,
    /// `user_funded − refunded`: the most a claim can pay.
    pub refundable_cap: U128,
    /// Block timestamp (ns) of the close, while the key is closing.
    pub closing_since: Option<u64>,
    /// Block timestamp (ns) from which `claim_payment_key_refund` is accepted.
    pub claimable_at: Option<u64>,
}

/// `KeyFlight` as a view answers it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[near(serializers = [json])]
pub struct PaymentKeyFlightView {
    pub top_ups_in_flight: u32,
    pub last_top_up_height: u64,
    pub close_pending: bool,
    pub claim_open: bool,
    pub last_claim_at: u64,
    pub next_claim_at: Option<u64>,
}

/// Bytes one ledger entry occupies: the record overhead, the map prefix, the
/// borsh-encoded `PaymentKeyId` and the `RefundLedger`. Part of a payment
/// key's storage deposit (`calculate_secret_storage_size`), refunded with it.
pub(crate) fn refund_ledger_entry_bytes(owner: &AccountId) -> u64 {
    40 + 1 + (4 + owner.as_str().len() as u64 + 4) + (16 + 16 + 9)
}

/// What `min(reported, cap)` pays, and whether the cap bit. Below
/// `MIN_TOP_UP_AMOUNT` nothing is paid: a transfer of dust costs more gas
/// than it moves, and the key is retired either way. Pure, so the one rule
/// every refund goes through is pinned by tests rather than by reading the
/// callback.
pub(crate) fn refund_payout(reported: u128, cap: u128) -> (u128, bool) {
    let within_cap = reported.min(cap);
    let pay = if within_cap < MIN_TOP_UP_AMOUNT { 0 } else { within_cap };
    (pay, within_cap < reported)
}

/// Whether a key closed at `closing_since` may claim at `now`, and if not,
/// when it may.
pub(crate) fn claimable(closing_since: u64, now: u64) -> Result<(), u64> {
    let at = closing_since.saturating_add(REFUND_SETTLE_DELAY_NS);
    if now >= at {
        Ok(())
    } else {
        Err(at)
    }
}

fn payment_key_secret(owner: &AccountId, nonce: u32) -> SecretKey {
    SecretKey {
        accessor: SecretAccessor::System(SystemSecretType::PaymentKey),
        profile: nonce.to_string(),
        owner: owner.clone(),
    }
}

fn yield_data_id() -> CryptoHash {
    env::read_register(DATA_ID_REGISTER)
        .expect("Failed to read data_id")
        .try_into()
        .expect("Invalid data_id")
}

// Internals. Outside `#[near_bindgen]` on purpose: these take an owner as an
// argument, and exported they would let anyone name whoever they liked.
impl Contract {
    /// The ledger of `(owner, nonce)`, or a fresh one. A key from before the
    /// ledger existed has no entry until its first top-up or close creates
    /// one — at zero, which is the rule: earlier deposits are not refundable.
    pub(crate) fn refund_ledger(&self, id: &PaymentKeyId) -> RefundLedger {
        self.payment_key_refund_ledger.get(id).unwrap_or_default()
    }

    /// A key that is closing takes no top-up: the money would land on a row
    /// the coordinator has already stopped reading, and would be counted by a
    /// quote the chain is about to cap it out of.
    pub(crate) fn assert_payment_key_not_closing(&self, owner: &AccountId, nonce: u32) {
        let id = PaymentKeyId { owner: owner.clone(), nonce };
        if let Some(since) = self.refund_ledger(&id).closing_since {
            env::panic_str(&format!(
                "Payment key {owner}:{nonce} is closing since {since}: it takes no top-up. \
                 Claim its refund with claim_payment_key_refund, or create a new key."
            ));
        }
    }

    /// Whether `(owner, nonce)` is closing.
    pub(crate) fn payment_key_is_closing(&self, owner: &AccountId, nonce: u32) -> bool {
        let id = PaymentKeyId { owner: owner.clone(), nonce };
        self.refund_ledger(&id).closing_since.is_some()
    }

    /// Record a top-up the chain accepted on `(owner, nonce)`: the only way
    /// `user_funded` grows. Called from the top-up callback once the key's
    /// blob holds the new balance, never at admission — a top-up refunded by
    /// the callback was never deposited.
    pub(crate) fn record_user_funded(&mut self, owner: &AccountId, nonce: u32, amount: u128) {
        if amount == 0 {
            return;
        }
        let id = PaymentKeyId { owner: owner.clone(), nonce };
        let mut ledger = self.refund_ledger(&id);
        ledger.user_funded = ledger.user_funded.saturating_add(amount);
        self.payment_key_refund_ledger.insert(&id, &ledger);
    }

    /// A new payment key's ledger entry, at zero. Its bytes are in the key's
    /// storage deposit.
    pub(crate) fn create_refund_ledger(&mut self, owner: &AccountId, nonce: u32) {
        let id = PaymentKeyId { owner: owner.clone(), nonce };
        if !self.payment_key_refund_ledger.contains_key(&id) {
            self.payment_key_refund_ledger.insert(&id, &RefundLedger::default());
        }
    }

    fn flight(&self, id: &PaymentKeyId) -> KeyFlight {
        self.payment_key_flight.get(id).unwrap_or_default()
    }

    fn set_flight(&mut self, id: &PaymentKeyId, flight: KeyFlight) {
        if flight == KeyFlight::default() {
            self.payment_key_flight.remove(id);
        } else {
            self.payment_key_flight.insert(id, &flight);
        }
    }

    /// A top-up yield was created on `(owner, nonce)`.
    pub(crate) fn note_top_up_admitted(&mut self, owner: &AccountId, nonce: u32) {
        let id = PaymentKeyId { owner: owner.clone(), nonce };
        let mut f = self.flight(&id);
        f.top_ups = f.top_ups.saturating_add(1);
        f.last_top_up_height = env::block_height();
        self.set_flight(&id, f);
    }

    /// A top-up yield was answered — resumed or timed out, whatever the answer.
    pub(crate) fn note_top_up_settled(&mut self, owner: &AccountId, nonce: u32) {
        let id = PaymentKeyId { owner: owner.clone(), nonce };
        let mut f = self.flight(&id);
        f.top_ups = f.top_ups.saturating_sub(1);
        self.set_flight(&id, f);
    }

    /// Top-up yields open on `(owner, nonce)`, a stale count read as none (and
    /// dropped, so the record cannot outlive its yields).
    pub(crate) fn top_ups_in_flight(&mut self, owner: &AccountId, nonce: u32) -> u32 {
        let id = PaymentKeyId { owner: owner.clone(), nonce };
        let mut f = self.flight(&id);
        if f.top_ups > 0 && env::block_height() > f.last_top_up_height.saturating_add(FLIGHT_STALE_BLOCKS) {
            log!(
                "{} top-up(s) of payment key {}:{} recorded in flight since block {} are stale; ignored",
                f.top_ups,
                owner,
                nonce,
                f.last_top_up_height
            );
            f.top_ups = 0;
            self.set_flight(&id, f);
            return 0;
        }
        f.top_ups
    }

    /// A close or a delete yielded on `(owner, nonce)`: no top-up until it is
    /// answered.
    pub(crate) fn note_close_pending(&mut self, owner: &AccountId, nonce: u32) {
        let id = PaymentKeyId { owner: owner.clone(), nonce };
        let mut f = self.flight(&id);
        f.close_pending = true;
        f.close_pending_height = env::block_height();
        self.set_flight(&id, f);
    }

    /// The close or delete was answered, whatever the answer.
    pub(crate) fn note_close_settled(&mut self, owner: &AccountId, nonce: u32) {
        let id = PaymentKeyId { owner: owner.clone(), nonce };
        let mut f = self.flight(&id);
        f.close_pending = false;
        self.set_flight(&id, f);
    }

    /// The block a close or delete of the key is waiting for its answer
    /// since, if one is; a flag older than `FLIGHT_STALE_BLOCKS` is a defect
    /// and is ignored (and dropped).
    fn close_pending_since(&mut self, owner: &AccountId, nonce: u32) -> Option<u64> {
        let id = PaymentKeyId { owner: owner.clone(), nonce };
        let mut f = self.flight(&id);
        if !f.close_pending {
            return None;
        }
        if env::block_height() > f.close_pending_height.saturating_add(FLIGHT_STALE_BLOCKS) {
            log!(
                "a close of payment key {}:{} recorded pending since block {} is stale; ignored",
                owner,
                nonce,
                f.close_pending_height
            );
            f.close_pending = false;
            self.set_flight(&id, f);
            return None;
        }
        Some(f.close_pending_height)
    }

    /// A top-up is not admitted while a close or a delete of the key waits
    /// for its answer.
    pub(crate) fn assert_no_close_pending(&mut self, owner: &AccountId, nonce: u32) {
        if let Some(since) = self.close_pending_since(owner, nonce) {
            env::panic_str(&format!(
                "A close or delete of payment key {owner}:{nonce} is waiting for its answer (block {since}); \
                 it takes no top-up until then — retry in a few blocks."
            ));
        }
    }

    /// One close or delete of a key at a time: a second one would share the
    /// flag, and the first answer would clear it while the second still
    /// waits — reopening the top-up window the flag exists to shut.
    pub(crate) fn assert_no_other_close_pending(&mut self, owner: &AccountId, nonce: u32) {
        if let Some(since) = self.close_pending_since(owner, nonce) {
            env::panic_str(&format!(
                "A close or delete of payment key {owner}:{nonce} is already waiting for its answer (block {since}); \
                 retry once it has settled (a few blocks)."
            ));
        }
    }

    /// A key whose refund claim waits for its answer is not deleted: the two
    /// answers would race over the secret and the ledger, and a failed refund
    /// transfer would then find no ledger to reopen.
    pub(crate) fn assert_no_claim_open(&mut self, owner: &AccountId, nonce: u32) {
        let id = PaymentKeyId { owner: owner.clone(), nonce };
        let f = self.flight(&id);
        if f.claim_open && env::block_height() <= f.last_claim_height.saturating_add(FLIGHT_STALE_BLOCKS) {
            env::panic_str(&format!(
                "A refund claim of payment key {owner}:{nonce} is waiting for its answer (block {}); \
                 retry once it has settled (a few blocks).",
                f.last_claim_height
            ));
        }
    }

    /// A key with a top-up not yet answered is neither closed nor deleted:
    /// the answer would then return the money to the payer while the
    /// coordinator, told only of the resume, credits it.
    pub(crate) fn assert_no_top_up_in_flight(&mut self, owner: &AccountId, nonce: u32) {
        let n = self.top_ups_in_flight(owner, nonce);
        assert!(
            n == 0,
            "{} top-up(s) of payment key {}:{} are in flight; retry once they have settled (a few blocks)",
            n,
            owner,
            nonce
        );
    }

    /// Drop the ledger of a key that is gone for good, and release its place
    /// in the owner's closing count if it was closing.
    ///
    /// The count is exactly the number of the owner's ledgers with
    /// `closing_since` set: raised when a close is confirmed, lowered here,
    /// when a refund's transfer starts (the key stops being closing) and
    /// raised again if that transfer fails.
    pub(crate) fn remove_refund_ledger(&mut self, owner: &AccountId, nonce: u32) {
        let id = PaymentKeyId { owner: owner.clone(), nonce };
        if let Some(ledger) = self.payment_key_refund_ledger.remove(&id) {
            if ledger.closing_since.is_some() {
                self.dec_closing_count(owner);
            }
        }
        self.payment_key_flight.remove(&id);
    }

    fn inc_closing_count(&mut self, owner: &AccountId) {
        let n = self.closing_counts.get(owner).unwrap_or(0).saturating_add(1);
        self.closing_counts.insert(owner, &n);
    }

    fn dec_closing_count(&mut self, owner: &AccountId) {
        match self.closing_counts.get(owner).unwrap_or(0) {
            0 | 1 => {
                self.closing_counts.remove(owner);
            }
            n => {
                self.closing_counts.insert(owner, &(n - 1));
            }
        }
    }

    /// Remove the key's secret if it is still there (refunding its storage
    /// deposit to the owner) and keep its nonce used.
    fn retire_payment_key(&mut self, owner: &AccountId, nonce: u32) {
        let secret_key = payment_key_secret(owner, nonce);
        if self.secrets_storage.get(&secret_key).is_some() {
            self.delete_secrets_internal(secret_key, owner, owner);
        }
        self.raise_payment_key_nonce_floor(owner, nonce);
    }

    fn stablecoin_transfer(&self, to: &AccountId, amount: u128, memo: &str) -> Promise {
        let token_contract = self
            .payment_token_contract
            .as_ref()
            .expect("Payment token contract not configured");
        Promise::new(token_contract.clone()).function_call(
            "ft_transfer".to_string(),
            json!({
                "receiver_id": to,
                "amount": U128(amount),
                "memo": memo,
            })
            .to_string()
            .into_bytes(),
            NearToken::from_yoctonear(1),
            REFUND_TRANSFER_GAS,
        )
    }
}

#[near_bindgen]
impl Contract {
    // =========================================================================
    // Payment key: close, wait, claim
    // =========================================================================

    /// Stop a payment key and start its refund clock.
    ///
    /// Yields until the worker has soft-deleted the key in the coordinator —
    /// the ordinary `DeletePaymentKey` task, so from here the key is refused
    /// every new call while the calls it has in flight settle — then marks the
    /// key closing on chain. The secret stays until the refund is claimed.
    ///
    /// Refused for a key already closing, and once an owner has
    /// `MAX_CLOSING_KEYS_PER_OWNER` keys closing. On a worker error or a
    /// timeout nothing changes: the key stays live.
    #[payable]
    pub fn close_payment_key(&mut self, nonce: u32) {
        near_sdk::assert_one_yocto();
        let owner = env::predecessor_account_id();

        assert!(
            self.secrets_storage.get(&payment_key_secret(&owner, nonce)).is_some(),
            "Payment key not found: owner={}, nonce={}",
            owner,
            nonce
        );
        self.assert_no_top_up_in_flight(&owner, nonce);
        self.assert_no_other_close_pending(&owner, nonce);
        let id = PaymentKeyId { owner: owner.clone(), nonce };
        if let Some(since) = self.refund_ledger(&id).closing_since {
            env::panic_str(&format!(
                "Payment key {owner}:{nonce} is already closing since {since}; claim its refund \
                 with claim_payment_key_refund once {} has passed.",
                since.saturating_add(REFUND_SETTLE_DELAY_NS)
            ));
        }
        let closing = self.closing_counts.get(&owner).unwrap_or(0);
        assert!(
            closing < MAX_CLOSING_KEYS_PER_OWNER,
            "{} payment keys of {} are already closing (the most is {}); claim their refunds first",
            closing,
            owner,
            MAX_CLOSING_KEYS_PER_OWNER
        );

        let callback_data = json!({ "owner": owner, "nonce": nonce });
        let promise_idx = env::promise_yield_create(
            "on_close_payment_key_response",
            &callback_data.to_string().into_bytes(),
            CLOSE_CALLBACK_GAS,
            GasWeight(1),
            DATA_ID_REGISTER,
        );
        let data_id = yield_data_id();
        // No top-up lands until this is answered.
        self.note_close_pending(&owner, nonce);

        // The same event a delete emits: the worker soft-deletes the key in
        // the coordinator and resumes, exactly as for `delete_payment_key`.
        // What differs is the callback the yield was created with.
        self.emit_system_event(SystemEvent::DeletePaymentKey {
            data_id,
            owner: owner.clone(),
            nonce,
        });
        log!("ClosePaymentKey requested: owner={}, nonce={}", owner, nonce);
        env::promise_return(promise_idx);
    }

    /// The worker's answer to a close: on success the key is marked closing.
    #[private]
    pub fn on_close_payment_key_response(
        &mut self,
        owner: AccountId,
        nonce: u32,
        #[callback_result] result: Result<DeletePaymentKeyResult, PromiseError>,
    ) {
        // First, in every branch: the close is answered, top-ups are admitted
        // again (and refused for a closing key by the ledger from here).
        self.note_close_settled(&owner, nonce);
        match result {
            Ok(DeletePaymentKeyResult::Success) => {
                let id = PaymentKeyId { owner: owner.clone(), nonce };
                let mut ledger = self.refund_ledger(&id);
                if ledger.closing_since.is_some() {
                    log!("Payment key already closing: owner={}, nonce={}", owner, nonce);
                    return;
                }
                let since = env::block_timestamp();
                ledger.closing_since = Some(since);
                self.payment_key_refund_ledger.insert(&id, &ledger);
                self.inc_closing_count(&owner);
                // Its nonce is used from here: the coordinator's row is dead.
                self.raise_payment_key_nonce_floor(&owner, nonce);
                log!(
                    "Payment key closing: owner={}, nonce={}, since={}, claimable_at={}, cap={}",
                    owner,
                    nonce,
                    since,
                    since.saturating_add(REFUND_SETTLE_DELAY_NS),
                    ledger.cap()
                );
            }
            Ok(DeletePaymentKeyResult::Error { message }) => {
                log!(
                    "ClosePaymentKey failed: owner={}, nonce={}, error={:?}; the key stays live",
                    owner,
                    nonce,
                    message
                );
            }
            Ok(DeletePaymentKeyResult::Refund { amount }) => {
                log!(
                    "ClosePaymentKey answered with a refund amount ({}): not a close answer; the key stays live: owner={}, nonce={}",
                    amount.0,
                    owner,
                    nonce
                );
            }
            Err(_) => {
                log!(
                    "ClosePaymentKey callback timeout: owner={}, nonce={}; the key stays live",
                    owner,
                    nonce
                );
            }
        }
    }

    /// Claim what a closed key has left.
    ///
    /// Accepted `REFUND_SETTLE_DELAY_NS` after the close. Yields until the
    /// worker has asked the coordinator for the key's remaining balance
    /// (`RefundPaymentKey` event); the callback pays `min(reported, cap)`,
    /// deletes the key and refunds its storage deposit. A coordinator that
    /// still has calls in flight on the key answers with an error, and the key
    /// stays closing: claim again later. Returns what was paid, in stablecoin
    /// minimal units; 0 when the claim was refused or nothing was due.
    #[payable]
    pub fn claim_payment_key_refund(&mut self, nonce: u32) {
        near_sdk::assert_one_yocto();
        let owner = env::predecessor_account_id();
        let id = PaymentKeyId { owner: owner.clone(), nonce };
        let Some(since) = self.refund_ledger(&id).closing_since else {
            env::panic_str(&format!(
                "Payment key {owner}:{nonce} is not closing. Close it first with close_payment_key."
            ));
        };
        let now = env::block_timestamp();
        if let Err(at) = claimable(since, now) {
            env::panic_str(&format!(
                "Payment key {owner}:{nonce} closed at {since}; its refund can be claimed from {at} \
                 (now {}), {} seconds from now.",
                now,
                at.saturating_sub(now) / 1_000_000_000
            ));
        }
        // Not while a close or delete of the key waits for its answer, one
        // claim at a time, and a day between two.
        self.assert_no_other_close_pending(&owner, nonce);
        let mut flight = self.flight(&id);
        let height = env::block_height();
        if flight.claim_open && height <= flight.last_claim_height.saturating_add(FLIGHT_STALE_BLOCKS) {
            env::panic_str(&format!(
                "A refund claim of payment key {owner}:{nonce} is already in flight (block {}); its answer settles within a few minutes.",
                flight.last_claim_height
            ));
        }
        if flight.last_claim_at > 0 && now < flight.last_claim_at.saturating_add(CLAIM_COOLDOWN_NS) {
            env::panic_str(&format!(
                "Payment key {owner}:{nonce} was claimed at {}; the next claim is accepted from {}, {} seconds from now.",
                flight.last_claim_at,
                flight.last_claim_at.saturating_add(CLAIM_COOLDOWN_NS),
                flight.last_claim_at.saturating_add(CLAIM_COOLDOWN_NS).saturating_sub(now) / 1_000_000_000
            ));
        }
        flight.claim_open = true;
        flight.last_claim_height = height;
        flight.last_claim_at = now;
        self.set_flight(&id, flight);

        let callback_data = json!({ "owner": owner, "nonce": nonce });
        let promise_idx = env::promise_yield_create(
            "on_payment_key_refund_response",
            &callback_data.to_string().into_bytes(),
            REFUND_CALLBACK_GAS,
            GasWeight(1),
            DATA_ID_REGISTER,
        );
        let data_id = yield_data_id();
        self.emit_system_event(SystemEvent::RefundPaymentKey {
            data_id,
            owner: owner.clone(),
            nonce,
        });
        log!("PaymentKeyRefund requested: owner={}, nonce={}", owner, nonce);
        env::promise_return(promise_idx);
    }

    /// The worker's answer to a claim: the key's remaining balance as the
    /// coordinator quoted it, or an error.
    ///
    /// On a quote the key is retired whatever the amount: the secret removed
    /// (storage deposit back), the nonce kept used. The payout is
    /// `min(reported, cap)`; a report above the cap is logged — it means a
    /// coordinator-side figure disagrees with the chain and is worth a look.
    /// On an error or a timeout nothing changes and the key stays closing.
    #[private]
    pub fn on_payment_key_refund_response(
        &mut self,
        owner: AccountId,
        nonce: u32,
        #[callback_result] result: Result<DeletePaymentKeyResult, PromiseError>,
    ) -> PromiseOrValue<U128> {
        // The claim is answered, whatever the answer: another may be made
        // after the cooldown.
        {
            let id = PaymentKeyId { owner: owner.clone(), nonce };
            let mut flight = self.flight(&id);
            flight.claim_open = false;
            self.set_flight(&id, flight);
        }
        let reported = match result {
            Ok(DeletePaymentKeyResult::Refund { amount }) => amount.0,
            Ok(DeletePaymentKeyResult::Success) => {
                log!(
                    "PaymentKeyRefund answered as a delete, with no amount; the key stays closing: owner={}, nonce={}",
                    owner,
                    nonce
                );
                return PromiseOrValue::Value(U128(0));
            }
            Ok(DeletePaymentKeyResult::Error { message }) => {
                log!(
                    "PaymentKeyRefund refused: owner={}, nonce={}, error={:?}; the key stays closing",
                    owner,
                    nonce,
                    message
                );
                return PromiseOrValue::Value(U128(0));
            }
            Err(_) => {
                log!(
                    "PaymentKeyRefund callback timeout: owner={}, nonce={}; the key stays closing",
                    owner,
                    nonce
                );
                return PromiseOrValue::Value(U128(0));
            }
        };

        let id = PaymentKeyId { owner: owner.clone(), nonce };
        let Some(mut ledger) = self.payment_key_refund_ledger.get(&id) else {
            // Deleted outright (`delete_payment_key`) between claim and answer.
            log!("PaymentKeyRefund: no ledger for owner={}, nonce={}; nothing paid", owner, nonce);
            return PromiseOrValue::Value(U128(0));
        };
        let Some(since) = ledger.closing_since else {
            log!("PaymentKeyRefund: owner={}, nonce={} is not closing; nothing paid", owner, nonce);
            return PromiseOrValue::Value(U128(0));
        };

        let (pay, capped) = refund_payout(reported, ledger.cap());
        if capped {
            log!(
                "refund capped: owner={}, nonce={}, reported {}, cap {} (user_funded {}, refunded {})",
                owner,
                nonce,
                reported,
                ledger.cap(),
                ledger.user_funded,
                ledger.refunded
            );
        }

        // The key is gone from here, whatever the transfer does: the
        // coordinator has zeroed the row behind this quote.
        self.retire_payment_key(&owner, nonce);

        if pay == 0 {
            self.remove_refund_ledger(&owner, nonce);
            log!(
                "Payment key refunded: owner={}, nonce={}, paid 0 (reported {})",
                owner,
                nonce,
                reported
            );
            return PromiseOrValue::Value(U128(0));
        }

        ledger.refunded = ledger.refunded.saturating_add(pay);
        // Not closing while the transfer runs: a second claim is refused, and
        // the count follows.
        ledger.closing_since = None;
        self.payment_key_refund_ledger.insert(&id, &ledger);
        self.dec_closing_count(&owner);
        log!(
            "Payment key refund: owner={}, nonce={}, paying {} (reported {})",
            owner,
            nonce,
            pay,
            reported
        );

        PromiseOrValue::Promise(
            self.stablecoin_transfer(&owner, pay, "Payment key refund").then(
                Self::ext(env::current_account_id())
                    .with_static_gas(REFUND_TRANSFER_CALLBACK_GAS)
                    .on_payment_key_refund_transfer(owner, nonce, U128(pay), since),
            ),
        )
    }

    /// The refund transfer's outcome. Paid: the ledger is dropped. Failed
    /// (the owner is not registered on the token, say): the payout is
    /// un-counted and the key is closing again from its original close, so
    /// the owner can claim once more after registering.
    #[private]
    pub fn on_payment_key_refund_transfer(
        &mut self,
        owner: AccountId,
        nonce: u32,
        amount: U128,
        closing_since: u64,
        #[callback_result] transfer_result: Result<(), PromiseError>,
    ) -> U128 {
        match transfer_result {
            Ok(()) => {
                self.remove_refund_ledger(&owner, nonce);
                log!(
                    "Payment key refunded: owner={}, nonce={}, paid {}",
                    owner,
                    nonce,
                    amount.0
                );
                amount
            }
            Err(_) => {
                let id = PaymentKeyId { owner: owner.clone(), nonce };
                let Some(mut ledger) = self.payment_key_refund_ledger.get(&id) else {
                    log!(
                        "Payment key refund transfer of {} to {} failed (nonce {}) and the key's ledger is gone; nothing to reopen",
                        amount.0,
                        owner,
                        nonce
                    );
                    return U128(0);
                };
                ledger.refunded = ledger.refunded.saturating_sub(amount.0);
                ledger.closing_since = Some(closing_since);
                self.payment_key_refund_ledger.insert(&id, &ledger);
                self.inc_closing_count(&owner);
                log!(
                    "Payment key refund transfer of {} to {} failed (nonce {}); the key is closing again — \
                     register on the token (storage_deposit) and claim_payment_key_refund once more",
                    amount.0,
                    owner,
                    nonce
                );
                U128(0)
            }
        }
    }

    // =========================================================================
    // Stablecoin balance: withdraw
    // =========================================================================

    /// Take `amount` of the caller's stablecoin balance (the one
    /// `deposit_balance` fills and `attached_usd` spends) back to the caller.
    ///
    /// At least `MIN_TOP_UP_AMOUNT`, at most the balance, one transfer in
    /// flight per account. The balance is debited first and credited back if
    /// the transfer fails; nothing in flight can spend it in between, because
    /// `request_execution` already took what it will use at admission.
    #[payable]
    pub fn withdraw_balance(&mut self, amount: U128) -> Promise {
        near_sdk::assert_one_yocto();
        let caller = env::predecessor_account_id();
        let amount = amount.0;
        assert!(
            amount >= MIN_TOP_UP_AMOUNT,
            "Minimum withdrawal is $0.01 ({} minimal units)",
            MIN_TOP_UP_AMOUNT
        );
        let balance = self.user_stablecoin_balances.get(&caller).unwrap_or(0);
        assert!(
            amount <= balance,
            "Insufficient stablecoin balance. Requested: {}, available: {}",
            amount,
            balance
        );
        assert!(
            !self.withdrawing.contains(&caller),
            "A withdrawal by {} is already in flight; wait for it to settle",
            caller
        );
        // Configured, or nothing moves: checked before the debit.
        assert!(
            self.payment_token_contract.is_some(),
            "Payment token contract not configured"
        );

        let left = balance - amount;
        if left == 0 {
            self.user_stablecoin_balances.remove(&caller);
        } else {
            self.user_stablecoin_balances.insert(&caller, &left);
        }
        self.withdrawing.insert(&caller);
        log!(
            "Balance withdrawal: {} taking {} stablecoin (remaining {})",
            caller,
            amount,
            left
        );

        self.stablecoin_transfer(&caller, amount, "Balance withdrawal").then(
            Self::ext(env::current_account_id())
                .with_static_gas(REFUND_TRANSFER_CALLBACK_GAS)
                .on_withdraw_balance(caller, U128(amount)),
        )
    }

    /// The withdrawal transfer's outcome: the in-flight mark is cleared, and
    /// a failed transfer's amount goes back on the balance.
    #[private]
    pub fn on_withdraw_balance(
        &mut self,
        account: AccountId,
        amount: U128,
        #[callback_result] transfer_result: Result<(), PromiseError>,
    ) {
        self.withdrawing.remove(&account);
        match transfer_result {
            Ok(()) => {
                log!("Balance withdrawn: {} received {} stablecoin", account, amount.0);
            }
            Err(_) => {
                let current = self.user_stablecoin_balances.get(&account).unwrap_or(0);
                self.user_stablecoin_balances
                    .insert(&account, &(current.saturating_add(amount.0)));
                log!(
                    "ft_transfer failed, restored {} stablecoin to {}'s balance",
                    amount.0,
                    account
                );
            }
        }
    }

    // =========================================================================
    // Views
    // =========================================================================

    /// What the chain knows about one payment key's refund: deposits, payouts,
    /// the cap, and the close clock. `null` for a key with no ledger entry —
    /// one created before the ledger and not topped up or closed since.
    pub fn get_payment_key_refund_ledger(&self, owner: AccountId, nonce: u32) -> Option<PaymentKeyRefundView> {
        let id = PaymentKeyId { owner: owner.clone(), nonce };
        self.payment_key_refund_ledger.get(&id).map(|ledger| PaymentKeyRefundView {
            owner,
            nonce,
            user_funded: U128(ledger.user_funded),
            refunded: U128(ledger.refunded),
            refundable_cap: U128(ledger.cap()),
            closing_since: ledger.closing_since,
            claimable_at: ledger.closing_since.map(|s| s.saturating_add(REFUND_SETTLE_DELAY_NS)),
        })
    }

    /// How many of `owner`'s payment keys are closing.
    pub fn get_closing_payment_key_count(&self, owner: AccountId) -> u32 {
        self.closing_counts.get(&owner).unwrap_or(0)
    }

    /// What is in flight on a payment key: top-up yields not yet answered
    /// (the key is closed or deleted only at zero), whether a refund claim is
    /// open, and when the last claim was made. `null` when nothing is.
    pub fn get_payment_key_flight(&self, owner: AccountId, nonce: u32) -> Option<PaymentKeyFlightView> {
        let id = PaymentKeyId { owner, nonce };
        self.payment_key_flight.get(&id).map(|f| PaymentKeyFlightView {
            top_ups_in_flight: f.top_ups,
            last_top_up_height: f.last_top_up_height,
            close_pending: f.close_pending,
            claim_open: f.claim_open,
            last_claim_at: f.last_claim_at,
            next_claim_at: if f.last_claim_at > 0 { Some(f.last_claim_at.saturating_add(CLAIM_COOLDOWN_NS)) } else { None },
        })
    }

    /// Whether `account` has a `withdraw_balance` transfer in flight.
    pub fn is_withdrawing(&self, account: AccountId) -> bool {
        self.withdrawing.contains(&account)
    }
}
