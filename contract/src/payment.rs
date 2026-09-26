//! Payment Key Top-Up via NEP-141 ft_transfer_call
//!
//! This module handles topping up Payment Keys with stablecoins (stablecoins).
//! Uses yield/resume mechanism similar to request_execution.
//!
//! Also supports top-up with NEAR or other tokens via swap to USDC.

use crate::*;
use near_sdk::serde_json::json;
use near_sdk::{env, log, near_bindgen, AccountId, Gas, GasWeight, NearToken, Promise};

/// Minimum top-up amount: $0.01 (10_000 for USDT with 6 decimals)
pub const MIN_TOP_UP_AMOUNT: u128 = 10_000;

/// Minimum NEAR deposit: 0.01 NEAR
pub const MIN_NEAR_DEPOSIT: u128 = 10_000_000_000_000_000_000_000; // 0.01 NEAR

/// wNEAR contract on mainnet
pub const WNEAR_CONTRACT: &str = "wrap.near";

/// Cost for OutLayer execution (covers base_fee + 1 yoctoNEAR for ft_transfer)
/// Must be >= base_fee + 1. Currently set to 0.01 NEAR to have margin.
pub const EXECUTION_COST: u128 = 10_000_000_000_000_000_000_000; // 0.01 NEAR

/// Gas for wrap.near calls
pub const WRAP_GAS: Gas = Gas::from_tgas(10);

/// Gas for ft_transfer calls
pub const FT_TRANSFER_GAS: Gas = Gas::from_tgas(30);

/// Gas for on_top_up_response callback
pub const TOP_UP_CALLBACK_GAS: Gas = Gas::from_tgas(30);

/// What one operation of a priced project costs.
///
/// The pair is `(project, operation)` rather than the project alone because a
/// connector charges per action: near-email sells `send` and gives `list` and
/// `read` away, and a single per-project price would either make the free ones
/// cost money or make the paid one free.
///
/// `operation` is the same string the caller puts in the request's `operation`
/// field and the guest dispatches on. One value, read from the same bytes by
/// the contract, the coordinator, the worker and the guest — see
/// [`OPERATION_FIELD`].
#[derive(Clone, Debug, PartialEq)]
#[near(serializers = [borsh, json])]
pub struct OperationPrice {
    /// The guest's `op` value, verbatim.
    pub operation: String,
    /// Stablecoin minimal units, the unit of `attached_usd` and of every
    /// balance here: `10_000` = $0.01. Zero is a real price — it is how an
    /// operation is published as free, which is not the same as unlisted.
    pub price_usd: U128,
    /// The author's cut of THIS operation's price, in basis points of 10_000.
    ///
    /// Per operation, not per project, and that is not an accident of shape:
    /// the economics of sending an email and of moving money are not the same
    /// number, so a single share for a whole connector would have to be wrong
    /// for at least one of its operations.
    ///
    /// Quoted with the price it splits. Read from one row and split by another
    /// is how a call gets charged one operation's fee and divided by another's
    /// percentage.
    pub developer_share_bp: u16,
}

/// What a curated project charges, and who gets paid for it.
///
/// **The contract is the only home of a connector's prices.** A guest that also
/// knew its price would be a second copy that wins on money whenever the two
/// disagree; the earlier `Connector::price()` hook was removed for exactly that
/// reason, and nothing here restores it.
///
/// Set by us when we curate a project into the subscription, never by the
/// project's owner: the price is what a subscription's allowance may be spent
/// against, so a party who could set it could invoice against credit we sold
/// wholesale.
#[derive(Clone, Debug, PartialEq)]
#[near(serializers = [borsh, json])]
pub struct ProjectPricing {
    /// Who is credited when a call succeeds.
    ///
    /// Held explicitly instead of being derived from the project's owner,
    /// because for connectors the owner is US: they all live under
    /// `connectors.outlayer.near`, the money arrives as ours, and crediting the
    /// author is our obligation rather than a transfer the caller made.
    ///
    /// Per project, not per operation: two operations paid to two different
    /// people are two projects.
    pub author_account_id: AccountId,
    /// Every operation this project sells. An operation absent from this list
    /// has no price, which is not the same as being free — see
    /// [`price_for_operation`].
    pub operations: Vec<OperationPrice>,
}

/// The most this project can charge for one call.
///
/// NOT what admission uses — admission prices the exact operation, read from
/// the request under [`OPERATION_FIELD`]. This is published so a caller can
/// budget: it is the most one call to this project can cost.
///
/// It WAS the admission rule, back when the contract did not read the request.
/// The universal operation field is what made the exact price reachable on
/// chain, and with it the question of who returns the difference disappeared
/// rather than being answered.
///
/// Derived on read rather than stored next to the list. The list is already in
/// hand by then — it arrives in the same deserialisation — so caching the
/// maximum would save no storage read and add a second number to keep in step
/// with the first.
pub(crate) fn max_price(pricing: &ProjectPricing) -> u128 {
    pricing.operations.iter().map(|o| o.price_usd.0).max().unwrap_or(0)
}

/// The field a priced project's request MUST carry, at the top level, as a
/// non-empty string.
///
/// **One universal format, not a per-connector convention.** This is what makes
/// the operation knowable to everyone who needs it — the contract that prices
/// it, the coordinator that bills it, the worker that runs it and the guest
/// that dispatches on it — from the same bytes, with no translation step.
///
/// The alternative was a per-connector rule for reading the operation, which
/// meant the contract would have had to learn every connector's request shape.
/// The one after that was a separate `operation` argument alongside the body,
/// which is the §4.3 trap: two values in two roles, one named by the caller and
/// one executed by the guest, to be bound together forever. A single field is
/// neither.
pub const OPERATION_FIELD: &str = "operation";

/// The largest request a priced project may be called with, on chain.
///
/// Parsing is linear in the body, and the caller's gas pays for it, so an
/// unbounded body is an unbounded and unpredictable cost. Bounded at the size
/// at which this contract already treats a payload as large — the threshold
/// that pushes `input_data` out of the event and into state — rather than at a
/// new number nobody would be able to relate to anything.
///
/// A connector that needs to move more than this takes a reference to it, not
/// the bytes: an on-chain transaction is a poor place for a payload either way.
pub const MAX_PRICED_INPUT_BYTES: usize = crate::INPUT_DATA_EVENT_THRESHOLD;

/// Why a priced project's request could not be priced.
#[derive(Debug, PartialEq, Eq)]
pub enum OperationError {
    /// Too big to parse for the gas it would cost.
    TooLarge { len: usize },
    /// Not JSON at all. A priced project takes a JSON object; that is part of
    /// the format, and guessing at anything else is how a body gets priced as
    /// one operation and executed as another.
    NotJson,
    /// No `operation`, or one that is not a non-empty string.
    Missing,
}

impl OperationError {
    pub fn message(&self) -> String {
        match self {
            OperationError::TooLarge { len } => format!(
                "input_data is {} bytes; a priced project accepts at most {}. \
                 Pass a reference rather than the payload.",
                len, MAX_PRICED_INPUT_BYTES
            ),
            OperationError::NotJson => format!(
                "input_data must be a JSON object naming \"{}\".",
                OPERATION_FIELD
            ),
            OperationError::Missing => format!(
                "input_data must name \"{}\" as a non-empty string at the top level.",
                OPERATION_FIELD
            ),
        }
    }
}

/// Read the operation out of a request body.
///
/// Fail-closed at every step: absent, blank, the wrong type, unparseable or
/// oversized all refuse. None of them defaults to an operation, because a
/// defaulted operation is a defaulted PRICE, and the cheapest one is the one an
/// attacker would pick.
///
/// Pure, so the format can be pinned by tests rather than by reading the caller
/// — and so the same vectors can be run against the coordinator's and the
/// worker's copies of this rule.
pub(crate) fn operation_from_input(input_data: Option<&str>) -> Result<String, OperationError> {
    let body = input_data.unwrap_or_default();
    if body.len() > MAX_PRICED_INPUT_BYTES {
        return Err(OperationError::TooLarge { len: body.len() });
    }

    let parsed: serde_json::Value =
        serde_json::from_str(body).map_err(|_| OperationError::NotJson)?;

    parsed
        .get(OPERATION_FIELD)
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or(OperationError::Missing)
}

/// How a paid call's money is divided.
#[derive(Debug, PartialEq, Eq)]
pub struct Split {
    /// The connector author's cut.
    pub author_usd: u128,
    /// What is left for the project's owner — us, for a connector.
    pub owner_usd: u128,
}

/// Divide what the caller paid between the connector's author and the project's
/// owner.
///
/// Pure, and returns BOTH halves, so the two cannot be computed from different
/// numbers and cannot silently fail to add up: `author_usd + owner_usd` is
/// always exactly `paid_usd`.
///
/// Rounding goes to the OWNER — us. The author's cut is floored, so a split can
/// never pay out more than came in, and the fraction of a minimal unit that
/// nobody can transfer stays where it can be accounted for.
pub(crate) fn split_payment(paid_usd: u128, developer_share_bp: u16) -> Split {
    let bp = developer_share_bp.min(10_000) as u128;
    let author_usd = paid_usd * bp / 10_000;
    Split {
        author_usd,
        owner_usd: paid_usd - author_usd,
    }
}

/// How a settled call divides what was attached: what goes back, and what is
/// left to split between the developers.
///
/// Two refunds meet here and they are not the same thing. The CHANGE is
/// whatever the caller attached over the price — theirs, always, and not the
/// guest's to give away or keep. The guest's own `refund_usd` is a decision
/// about the work it did, so it can only reach into the PRICE.
///
/// Clamping the guest to the price is the whole reason this is one function:
/// clamped to `attached` instead, a guest could hand back money it was never
/// paid — the caller's change — and the developer's side would come out short
/// by exactly that much.
pub(crate) fn settle_attached(
    attached_usd: u128,
    price_usd: u128,
    guest_refund_usd: u128,
) -> (u128, u128) {
    let overpaid = attached_usd.saturating_sub(price_usd);
    let chargeable = attached_usd - overpaid;
    let guest_refund = guest_refund_usd.min(chargeable);
    (overpaid + guest_refund, chargeable - guest_refund)
}

/// What this operation costs, or `None` if the project does not sell it.
///
/// `None` and `Some(0)` are different answers on purpose: a published free
/// operation costs nothing, while an unlisted one is not part of the offer at
/// all, and an unlisted one must be REFUSED rather than run for free.
pub(crate) fn price_for_operation(pricing: &ProjectPricing, operation: &str) -> Option<u128> {
    pricing
        .operations
        .iter()
        .find(|o| o.operation == operation)
        .map(|o| o.price_usd.0)
}

/// One subscription offer, as the contract knows it.
///
/// **The contract is the source of truth for what a subscription COSTS.** The
/// coordinator syncs this list the same way it syncs the execution prices, and
/// a purchase is refused on chain when the money does not cover the plan — so
/// nobody pays for something they will not get, and the refusal does not depend
/// on an off-chain component being honest or even reachable.
///
/// What a plan GIVES — how much allowance, for how many days — is deliberately
/// NOT here. It is metering, it changes with our costs rather than with a
/// price, and putting it on chain would mean a transaction to adjust it. Each
/// field therefore has exactly one home, and there is nothing to keep in step.
#[derive(Clone, Debug, PartialEq)]
#[near(serializers = [borsh, json])]
pub struct SubscriptionPlan {
    /// Stable identifier, and what a payment names. Never reused: a withdrawn
    /// plan keeps its index so an old payment cannot silently buy a new offer.
    pub index: u8,
    /// Human label, for the purchase page and for support.
    pub name: String,
    /// What it costs, in stablecoin minimal units.
    pub price_usd: U128,
    /// Withdrawn plans stay in the list and stop being purchasable. Removing
    /// the row instead would free the index for reuse.
    pub active: bool,
}

/// Action for ft_on_transfer msg field
#[derive(Clone, Debug)]
#[near(serializers = [json])]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum FtTransferAction {
    /// Top up a Payment Key balance
    /// `owner` - optional, defaults to sender_id. Required when called via
    /// NEAR Intents ft_withdraw (sender_id = intents.near, not the actual user).
    TopUpPaymentKey {
        nonce: u32,
        owner: Option<AccountId>,
    },
    /// Deposit stablecoin to user's balance (for attached_usd payments)
    DepositBalance,
    /// Buy a subscription for a payment key.
    ///
    /// NOT a top-up, and the difference is the point: the money does not become
    /// the key's balance. It is revenue the moment it arrives, so it can never
    /// be withdrawn back out, and no blob is rewritten — which is why this path
    /// needs no yield, no worker task and no keystore round trip. The allowance
    /// it buys is granted by the coordinator against the event below.
    ///
    /// `owner` defaults to the sender, so one transaction from anybody's wallet
    /// can put a subscription on somebody else's agent.
    BuySubscription {
        nonce: u32,
        owner: Option<AccountId>,
        /// Which plan, by [`SubscriptionPlan::index`].
        plan: u8,
    },
}

/// Result of top-up operation (sent via yield/resume)
#[derive(Clone, Debug)]
#[near(serializers = [borsh, json])]
pub enum TopUpResult {
    /// Success - contains new encrypted secret data
    Success { new_encrypted_data: String },
    /// Error - contains error message
    Error { message: String },
}

/// Result of delete operation (sent via yield/resume)
#[derive(Clone, Debug)]
#[near(serializers = [borsh, json])]
pub enum DeletePaymentKeyResult {
    /// Success - key deleted from coordinator PostgreSQL
    Success,
    /// Error - contains error message
    Error { message: String },
}

/// Gas for on_delete_payment_key_response callback
pub const DELETE_CALLBACK_GAS: Gas = Gas::from_tgas(30);

/// System event for workers to process
#[derive(Clone, Debug)]
#[near(serializers = [json])]
pub enum SystemEvent {
    /// Payment Key top-up request
    TopUpPaymentKey {
        data_id: CryptoHash,
        owner: AccountId,
        nonce: u32,
        amount: U128,
        encrypted_data: String, // current encrypted secret (base64)
    },
    /// Payment Key delete request
    DeletePaymentKey {
        data_id: CryptoHash,
        owner: AccountId,
        nonce: u32,
    },
    /// A subscription was bought and paid for on chain.
    ///
    /// Carries what was PAID, not what it buys: the coordinator holds the
    /// allowance and the validity, and reads them from its own row for this
    /// plan index. `paid_usd` is what the contract kept, so the two ledgers can
    /// be reconciled against each other later.
    SubscriptionPurchased {
        owner: AccountId,
        nonce: u32,
        plan: u8,
        paid_usd: U128,
        payer: AccountId,
    },
    /// Wallet policy created/updated — worker should sync authorized key hashes
    WalletPolicyUpdated {
        wallet_pubkey: String,
        owner: AccountId,
        encrypted_data: String,
        frozen: bool,
    },
    /// Wallet policy deleted — worker should remove authorized keys
    WalletPolicyDeleted {
        wallet_pubkey: String,
        owner: AccountId,
    },
    /// Wallet frozen/unfrozen — worker should update freeze status
    WalletFrozenChanged {
        wallet_pubkey: String,
        owner: AccountId,
        frozen: bool,
    },
    /// A project moved to a new owner and so to a new name; its uuid, versions
    /// and storage stay. Anything that maps a project name to a uuid drops both
    /// names: the old one is free for a new project, the new one may have been
    /// looked up while it named nothing.
    ProjectTransferred {
        old_project_id: String,
        new_project_id: String,
        project_uuid: String,
        old_owner: AccountId,
        new_owner: AccountId,
    },
}

/// Which plan a payment buys, or `None` if it buys nothing.
///
/// Pure, and separate from the handler, because it is the whole commercial
/// decision: which offer, at what price, and whether the money covers it.
///
/// A payment SHORT of the named plan buys nothing here — unlike the
/// coordinator's own purchase endpoint, which sells the best plan the money
/// covers. The difference is deliberate: an API caller can be told what is
/// available and try again for nothing, while a transfer that has already
/// landed can only be answered with a product or with the money back, and
/// giving them a cheaper plan than the one they named would be choosing for
/// them.
pub(crate) fn plan_for_sale(
    plans: &[SubscriptionPlan],
    plan_index: u8,
    amount_usd: u128,
) -> Option<&SubscriptionPlan> {
    plans
        .iter()
        .find(|p| p.index == plan_index && p.active)
        .filter(|p| amount_usd >= p.price_usd.0)
}

/// Keep the whole payment.
///
/// NEP-141 reads the return value of `ft_on_transfer` as "how much to give
/// back", so zero is "nothing goes back". Said explicitly rather than left to
/// the default: a branch that credits something and answers with nothing at all
/// leaves the most important number in the transfer to be inferred, and the
/// next person to add a branch here has no example to copy.
fn keep_everything() {
    value_return_u128(0)
}

/// Set the `ft_on_transfer` return value by hand.
///
/// `ft_on_transfer` is declared as returning `()` because the top-up branch
/// answers through a yield promise instead. This branch has no promise to
/// return, so it writes the value directly.
fn value_return_u128(amount: u128) {
    env::value_return(
        &serde_json::to_vec(&U128(amount)).expect("U128 always serialises"),
    );
}

#[near_bindgen]
impl Contract {
    /// NEP-141 callback for receiving fungible tokens
    ///
    /// msg format: {"action": "top_up_payment_key", "nonce": 0}
    ///
    /// Uses yield/resume: waits for worker to update the encrypted secret
    /// with new balance, then returns 0 (accept) or amount (refund)
    pub fn ft_on_transfer(
        &mut self,
        sender_id: AccountId,
        amount: U128,
        msg: String,
    ) {
        let token_contract = env::predecessor_account_id();

        // Check that payment token is configured
        let configured_token = self.payment_token_contract.as_ref()
            .expect("Payment token contract not configured");

        // Check that token matches configured contract
        assert!(
            &token_contract == configured_token,
            "Invalid token contract. Expected: {}, got: {}",
            configured_token,
            token_contract
        );

        // Parse action from msg
        let action: FtTransferAction = serde_json::from_str(&msg)
            .expect("Invalid msg format. Expected: {\"action\": \"top_up_payment_key\", \"nonce\": 0}");

        match action {
            FtTransferAction::TopUpPaymentKey { nonce, owner } => {
                let effective_owner = owner.unwrap_or(sender_id);
                self.handle_top_up(effective_owner, amount, nonce)
            }
            FtTransferAction::DepositBalance => {
                self.handle_deposit_balance(sender_id, amount)
            }
            FtTransferAction::BuySubscription { nonce, owner, plan } => {
                let effective_owner = owner.unwrap_or(sender_id.clone());
                self.handle_buy_subscription(effective_owner, sender_id, amount, nonce, plan)
            }
        }
    }

    /// Callback after worker processes top-up via yield/resume
    /// Returns U128 - amount to refund (0 = accept all, amount = refund all)
    #[private]
    pub fn on_top_up_response(
        &mut self,
        owner: AccountId,
        nonce: u32,
        amount: U128, // amount to refund on error
        #[callback_result] result: Result<TopUpResult, PromiseError>,
    ) -> U128 {
        match result {
            Ok(TopUpResult::Success { new_encrypted_data }) => {
                // Build secret key
                let secret_key = SecretKey {
                    accessor: SecretAccessor::System(SystemSecretType::PaymentKey),
                    profile: nonce.to_string(),
                    owner: owner.clone(),
                };

                // Get existing profile to preserve metadata
                if let Some(mut profile) = self.secrets_storage.get(&secret_key) {
                    log!(
                        "Updating Payment Key secret: owner={}, nonce={}, old_len={}, new_len={}",
                        owner,
                        nonce,
                        profile.encrypted_secrets.len(),
                        new_encrypted_data.len()
                    );

                    // Update encrypted data with new balance
                    profile.encrypted_secrets = new_encrypted_data;
                    profile.updated_at = env::block_timestamp();

                    // Save updated profile
                    self.secrets_storage.insert(&secret_key, &profile);

                    log!(
                        "Payment key topped up: owner={}, nonce={}, amount={}",
                        owner,
                        nonce,
                        amount.0
                    );

                    U128(0) // Accept all tokens
                } else {
                    log!("Payment key not found during callback: owner={}, nonce={}", owner, nonce);
                    amount // Refund all tokens
                }
            }
            Ok(TopUpResult::Error { message }) => {
                log!(
                    "TopUp failed: owner={}, nonce={}, error={:?}",
                    owner,
                    nonce,
                    message
                );
                amount // Refund all tokens
            }
            Err(_) => {
                log!(
                    "TopUp callback timeout: owner={}, nonce={}",
                    owner,
                    nonce
                );
                amount // Refund all tokens
            }
        }
    }

    /// Resume a TopUp yield promise with the result
    ///
    /// Called by the worker (operator) after processing the TopUp:
    /// 1. Worker decrypts current Payment Key data
    /// 2. Worker adds topup amount to balance
    /// 3. Worker re-encrypts data
    /// 4. Worker calls this method to resume the yield
    ///
    /// # Arguments
    /// * `data_id` - CryptoHash from the yield promise (hex encoded)
    /// * `result` - TopUpResult with new encrypted data or error
    pub fn resume_topup(&mut self, data_id: String, result: TopUpResult) {
        // Only operator can resume
        assert!(
            env::predecessor_account_id() == self.operator_id,
            "Only operator can resume topup"
        );

        // Decode data_id from hex
        let data_id_bytes = hex::decode(&data_id)
            .expect("Invalid data_id hex");
        let data_id_hash: CryptoHash = data_id_bytes
            .try_into()
            .expect("Invalid data_id length");

        // Serialize result for yield resume (callback_result expects JSON)
        let result_bytes = serde_json::to_vec(&result)
            .expect("Failed to serialize TopUpResult");

        // Resume the yield promise
        let success = env::promise_yield_resume(&data_id_hash, &result_bytes);

        if success {
            log!("TopUp yield resumed: data_id={}", data_id);
        } else {
            log!("TopUp yield resume failed (timeout?): data_id={}", data_id);
        }
    }

    // =========================================================================
    // Delete Payment Key (with yield/resume)
    // =========================================================================

    /// Delete a Payment Key using yield/resume mechanism
    ///
    /// Flow:
    /// 1. User calls delete_payment_key(nonce)
    /// 2. Contract emits DeletePaymentKey event
    /// 3. Worker receives event, deletes key from coordinator PostgreSQL
    /// 4. Worker calls resume_delete_payment_key with Success
    /// 5. Contract callback deletes secret from storage and refunds deposit
    ///
    /// # Arguments
    /// * `nonce` - Payment Key nonce to delete
    #[payable]
    pub fn delete_payment_key(&mut self, nonce: u32) {
        let caller = env::predecessor_account_id();

        // Require 1 yoctoNEAR for security (prevent accidental calls)
        assert!(
            env::attached_deposit().as_yoctonear() >= 1,
            "Requires attached deposit of at least 1 yoctoNEAR"
        );

        // Build secret key for Payment Key
        let secret_key = SecretKey {
            accessor: SecretAccessor::System(SystemSecretType::PaymentKey),
            profile: nonce.to_string(),
            owner: caller.clone(),
        };

        // Verify Payment Key exists
        assert!(
            self.secrets_storage.get(&secret_key).is_some(),
            "Payment key not found: owner={}, nonce={}",
            caller,
            nonce
        );

        // Create callback data
        let callback_data = json!({
            "owner": caller,
            "nonce": nonce,
        });

        // Create yield - wait for worker to delete from coordinator
        let promise_idx = env::promise_yield_create(
            "on_delete_payment_key_response",
            &callback_data.to_string().into_bytes(),
            DELETE_CALLBACK_GAS,
            GasWeight(1),
            DATA_ID_REGISTER,
        );

        // Get data_id for resume
        let data_id: CryptoHash = env::read_register(DATA_ID_REGISTER)
            .expect("Failed to read data_id")
            .try_into()
            .expect("Invalid data_id");

        // Emit event for worker to process
        self.emit_system_event(SystemEvent::DeletePaymentKey {
            data_id,
            owner: caller.clone(),
            nonce,
        });

        log!(
            "DeletePaymentKey requested: owner={}, nonce={}",
            caller,
            nonce
        );

        // Return the yield promise (will be resumed by worker)
        env::promise_return(promise_idx);
    }

    /// Callback after worker processes delete via yield/resume
    #[private]
    pub fn on_delete_payment_key_response(
        &mut self,
        owner: AccountId,
        nonce: u32,
        #[callback_result] result: Result<DeletePaymentKeyResult, PromiseError>,
    ) {
        match result {
            Ok(DeletePaymentKeyResult::Success) => {
                // Build secret key
                let secret_key = SecretKey {
                    accessor: SecretAccessor::System(SystemSecretType::PaymentKey),
                    profile: nonce.to_string(),
                    owner: owner.clone(),
                };

                log!(
                    "Deleting Payment Key secret from storage: owner={}, nonce={}",
                    owner,
                    nonce
                );

                // Delete secret from contract storage (refunds storage deposit)
                // A payment key is owned by the account that created it, and the
                // storage deposit goes back to that same account.
                self.delete_secrets_internal(secret_key, &owner, &owner);

                log!(
                    "Payment key deleted: owner={}, nonce={}",
                    owner,
                    nonce
                );
            }
            Ok(DeletePaymentKeyResult::Error { message }) => {
                log!(
                    "DeletePaymentKey failed: owner={}, nonce={}, error={:?}",
                    owner,
                    nonce,
                    message
                );
                // Don't delete on error - key remains valid
            }
            Err(_) => {
                log!(
                    "DeletePaymentKey callback timeout: owner={}, nonce={}",
                    owner,
                    nonce
                );
                // Don't delete on timeout - key remains valid
            }
        }
    }

    /// Resume a DeletePaymentKey yield promise with the result
    ///
    /// Called by the worker (operator) after deleting the key from coordinator:
    /// 1. Worker receives DeletePaymentKey event
    /// 2. Worker calls POST /payment-keys/delete on coordinator
    /// 3. Worker calls this method to resume the yield
    ///
    /// # Arguments
    /// * `data_id` - CryptoHash from the yield promise (hex encoded)
    /// * `result` - DeletePaymentKeyResult (Success or Error)
    pub fn resume_delete_payment_key(&mut self, data_id: String, result: DeletePaymentKeyResult) {
        // Only operator can resume
        assert!(
            env::predecessor_account_id() == self.operator_id,
            "Only operator can resume delete_payment_key"
        );

        // Decode data_id from hex
        let data_id_bytes = hex::decode(&data_id)
            .expect("Invalid data_id hex");
        let data_id_hash: CryptoHash = data_id_bytes
            .try_into()
            .expect("Invalid data_id length");

        // Serialize result for yield resume (callback_result expects JSON)
        let result_bytes = serde_json::to_vec(&result)
            .expect("Failed to serialize DeletePaymentKeyResult");

        // Resume the yield promise
        let success = env::promise_yield_resume(&data_id_hash, &result_bytes);

        if success {
            log!("DeletePaymentKey yield resumed: data_id={}", data_id);
        } else {
            log!("DeletePaymentKey yield resume failed (timeout?): data_id={}", data_id);
        }
    }

    // =========================================================================
    // Top-up Payment Key with NEAR (swapped to USDC via Intents)
    // =========================================================================
    //
    // MAINNET ONLY: NEAR Intents protocol is only available on mainnet.
    // These methods will fail on testnet because:
    // - wrap.near doesn't exist on testnet (use wrap.testnet)
    // - v1.publishintent.near doesn't exist on testnet
    // - Intents API (api.defuse.org) only supports mainnet
    //
    // UI should hide "Top Up with NEAR" button on testnet.
    // =========================================================================

    /// Top up a Payment Key with NEAR (MAINNET ONLY)
    ///
    /// This is a convenience wrapper that:
    /// 1. Wraps NEAR to wNEAR
    /// 2. Transfers wNEAR to swap_contract_id
    /// 3. Calls WASI to swap wNEAR -> USDC via Intents
    ///
    /// The token will be swapped to USDC via NEAR Intents protocol.
    /// Minimum deposit: 0.1 NEAR (after subtracting execution cost).
    ///
    /// # Arguments
    /// * `nonce` - Payment Key nonce to top up (must already exist)
    /// * `swap_contract_id` - Account that will execute the swap (e.g., "v1.publishintent.near")
    ///
    /// # Panics
    /// * Payment key not found
    /// * Deposit below minimum (0.1 NEAR + execution cost)
    ///
    /// # Note
    /// This method only works on mainnet. NEAR Intents are not available on testnet.
    #[payable]
    pub fn top_up_payment_key_with_near(
        &mut self,
        nonce: u32,
        swap_contract_id: AccountId,
    ) -> Promise {
        self.assert_not_paused();

        let caller = env::predecessor_account_id();
        let deposit = env::attached_deposit();

        // Reserve NEAR for execution cost
        let wrap_amount = deposit
            .as_yoctonear()
            .saturating_sub(EXECUTION_COST);

        // Check minimum deposit (after subtracting execution cost)
        assert!(
            wrap_amount >= MIN_NEAR_DEPOSIT,
            "Minimum deposit is {} yoctoNEAR (0.01 NEAR) + {} yoctoNEAR (execution cost), got {} yoctoNEAR",
            MIN_NEAR_DEPOSIT,
            EXECUTION_COST,
            deposit.as_yoctonear()
        );

        // Verify payment key exists
        let secret_key = SecretKey {
            accessor: SecretAccessor::System(SystemSecretType::PaymentKey),
            profile: nonce.to_string(),
            owner: caller.clone(),
        };

        assert!(
            self.secrets_storage.get(&secret_key).is_some(),
            "Payment key not found. Create it first with store_secrets()"
        );

        // Verify we have enough reserved for ft_transfer (1 yocto) + base_fee
        let ft_transfer_deposit: u128 = 1;
        assert!(
            EXECUTION_COST >= self.base_fee + ft_transfer_deposit,
            "EXECUTION_COST ({}) must cover base_fee ({}) + ft_transfer deposit (1)",
            EXECUTION_COST,
            self.base_fee
        );

        log!(
            "TopUpWithNear: owner={}, nonce={}, wrap_amount={}, swap_contract={}",
            caller,
            nonce,
            wrap_amount,
            swap_contract_id
        );

        let wnear_contract: AccountId = WNEAR_CONTRACT.parse().unwrap();

        // Step 1: Wrap NEAR to wNEAR (wrap_amount, keep EXECUTION_COST for later)
        // Step 2: Transfer wNEAR to swap_contract_id
        // Step 3: Call request_execution for payment-keys-with-intents WASI
        Promise::new(wnear_contract.clone())
            .function_call(
                "near_deposit".to_string(),
                vec![],
                NearToken::from_yoctonear(wrap_amount),
                WRAP_GAS,
            )
            .then(
                Promise::new(wnear_contract)
                    .function_call(
                        "ft_transfer".to_string(),
                        json!({
                            "receiver_id": swap_contract_id,
                            "amount": wrap_amount.to_string(),
                        })
                        .to_string()
                        .into_bytes(),
                        NearToken::from_yoctonear(1), // 1 yoctoNEAR for ft_transfer
                        FT_TRANSFER_GAS,
                    ),
            )
            .then(self.internal_request_token_swap(
                caller,
                nonce,
                WNEAR_CONTRACT.to_string(),
                wrap_amount.to_string(),
                swap_contract_id.to_string(),
            ))
    }

    /// Top up a Payment Key with any whitelisted token — **DISABLED (naive implementation)**.
    ///
    /// This method panics and does nothing. It was never wired into any client: the dashboard
    /// tops up payment keys with the configured stablecoin via `ft_on_transfer`, and with NEAR
    /// via `top_up_payment_key_with_near`.
    ///
    /// # Why it is disabled — front-runnable by design
    /// The intended flow assumed the caller had already transferred `amount` of `token_id` to
    /// `swap_contract_id`, then asked the `payment-keys-with-intents` WASI to swap it to USDC and
    /// credit the caller's key. The WASI *does* reject fake amounts (its `ft_transfer_call` of the
    /// claimed `amount` OUT of `swap_contract_id` fails if the tokens aren't there), but it does NOT
    /// bind the depositor to the credited owner, and `swap_contract_id` is a single shared account
    /// (it holds the one `SWAP_CONTRACT_PRIVATE_KEY`). So an attacker can watch a victim's deposit
    /// sitting in that shared pool, call this method first (own `nonce`, victim's `amount`), and have
    /// the WASI move the victim's tokens and credit the attacker — the victim's own top-up then fails
    /// for lack of funds.
    ///
    /// # The correct implementation (if this feature is ever needed)
    /// Do NOT use a pre-deposit method: NEP-141 is push-only, so a contract cannot atomically pull the
    /// caller's FT, and on-chain attribution would need a deposit ledger. Instead fold token top-up
    /// into `ft_on_transfer` (which already powers the safe USDC path): when a whitelisted non-USDC
    /// token arrives, the NEP-141 transfer binds `sender_id` + the REAL `amount` atomically — forward
    /// it to `swap_contract_id` and call `internal_request_token_swap(sender_id, nonce, token, amount,
    /// swap)`. Then the swapped amount is provably the sender's own deposit and there is no front-run
    /// window. (`top_up_payment_key_with_near` is already safe this way — it wraps and swaps only the
    /// caller's attached NEAR.)
    pub fn top_up_payment_key_with_token(
        &mut self,
        nonce: u32,
        token_id: AccountId,
        amount: U128,
        swap_contract_id: AccountId,
    ) -> Promise {
        // Disabled: the naive pre-deposit design is front-runnable on the shared swap account.
        // See the doc-comment above for the correct `ft_on_transfer`-based implementation.
        let _ = (nonce, token_id, amount, swap_contract_id);
        env::panic_str(
            "top_up_payment_key_with_token is disabled (naive, front-runnable design). \
             Top up with the stablecoin via ft_on_transfer, or with NEAR via \
             top_up_payment_key_with_near. See this method's doc-comment for the correct fix.",
        )

        // self.assert_not_paused();

        // let caller = env::predecessor_account_id();

        // // Verify payment key exists
        // let secret_key = SecretKey {
        //     accessor: SecretAccessor::System(SystemSecretType::PaymentKey),
        //     profile: nonce.to_string(),
        //     owner: caller.clone(),
        // };

        // assert!(
        //     self.secrets_storage.get(&secret_key).is_some(),
        //     "Payment key not found. Create it first with store_secrets()"
        // );

        // log!(
        //     "TopUpWithToken: owner={}, nonce={}, token={}, amount={}, swap_contract={}",
        //     caller,
        //     nonce,
        //     token_id,
        //     amount.0,
        //     swap_contract_id
        // );

        // // Token should already be at the swap contract
        // // Call request_execution for payment-keys-with-intents WASI
        // self.internal_request_token_swap(
        //     caller,
        //     nonce,
        //     token_id.to_string(),
        //     amount.0.to_string(),
        //     swap_contract_id.to_string(),
        // )
    }

}


// Internals. Deliberately OUTSIDE `#[near_bindgen]`: the macro exports a
// contract method for every `pub fn` in a block it annotates, so a helper that
// lives there is one visibility keyword away from becoming a public entry
// point. These take an already-authenticated caller as an argument — exposed,
// they would let anyone name whoever they liked.
impl Contract {
    /// Sell a subscription, or hand the money straight back.
    ///
    /// Everything is decided here, on chain, before anything is kept:
    ///
    ///   * an unknown or withdrawn plan returns the WHOLE payment;
    ///   * a payment short of the price returns the whole payment — the payer
    ///     asked for a specific plan and getting a lesser one is not what they
    ///     paid for;
    ///   * a payment for a key that does not exist returns the whole payment,
    ///     because the allowance would have nowhere to land;
    ///   * anything ABOVE the price is kept, and buys proportionally more. The
    ///     event carries what was actually paid, and the coordinator scales the
    ///     plan's terms by it — $60 on a $10 plan is six times the allowance and
    ///     six times the days, not a $50 gift to us.
    ///
    /// Nothing is ever returned as change, and that is deliberate. A partial
    /// refund would be a second money path through a worker, and a bug there
    /// sends the wrong sum to a real account. Refusing outright returns
    /// everything through NEP-141, which needs no arithmetic of ours at all.
    ///
    /// Nothing is written to a key here. What was sold is an EVENT, and the
    /// allowance behind it is granted by the coordinator, which is where the
    /// metering lives. That is also why this needs no yield: the encrypted blob
    /// is not touched, so there is nothing for a worker to re-encrypt.
    fn handle_buy_subscription(
        &mut self,
        owner: AccountId,
        payer: AccountId,
        amount: U128,
        nonce: u32,
        plan_index: u8,
    ) {
        // Refusals PANIC, and that is the whole refund mechanism: NEP-141
        // refunds the full amount when `ft_on_transfer` fails, and the payer
        // reads the reason in their own transaction outcome. Returning the
        // money by arithmetic instead would be more code doing the same thing,
        // less visibly — and the branch that got it wrong would keep somebody's
        // money.
        let plan = plan_for_sale(&self.subscription_plans, plan_index, amount.0)
            .unwrap_or_else(|| {
                env::panic_str(&format!(
                    "No plan {} on sale that {} covers. Check get_subscription_plans().",
                    plan_index, amount.0
                ))
            })
            .clone();

        // The key has to exist, exactly as a top-up requires: a subscription on
        // a key that was never created would be an allowance with nowhere to
        // land.
        let secret_key = SecretKey {
            accessor: SecretAccessor::System(SystemSecretType::PaymentKey),
            profile: nonce.to_string(),
            owner: owner.clone(),
        };
        assert!(
            self.secrets_storage.get(&secret_key).is_some(),
            "No payment key {}:{}. Create it before buying a subscription for it.",
            owner,
            nonce
        );

        self.emit_system_event(SystemEvent::SubscriptionPurchased {
            owner: owner.clone(),
            nonce,
            plan: plan.index,
            // What was actually TRANSFERRED, not the plan's price. The two
            // differ whenever somebody overpays, and the coordinator scales the
            // terms by this number — so a figure of `plan.price_usd` here would
            // silently keep the difference.
            paid_usd: amount,
            payer: payer.clone(),
        });

        log!(
            "Subscription sold: owner={}, nonce={}, plan={} ({}), paid={}, payer={}",
            owner,
            nonce,
            plan.index,
            plan.name,
            plan.price_usd.0,
            payer
        );

        // Sold: keep everything. An overpayment is not kept FROM the payer — the
        // event carries the full amount and the coordinator grants in
        // proportion — it is simply not handed back here, because handing money
        // back by arithmetic is the one thing this path must not do.
        keep_everything();
    }

    /// Handle stablecoin deposit to user's balance
    /// Used for attached_usd payments to project developers
    fn handle_deposit_balance(&mut self, sender_id: AccountId, amount: U128) {
        // Add to user's stablecoin balance
        let current = self.user_stablecoin_balances.get(&sender_id).unwrap_or(0);
        self.user_stablecoin_balances.insert(&sender_id, &(current + amount.0));

        log!(
            "Deposited {} stablecoin to {} (new balance: {})",
            amount.0,
            sender_id,
            current + amount.0
        );

        // The credit is real spendable value — `request_execution` pays
        // developers out of it — so the transfer answer is stated rather than
        // left implicit.
        keep_everything();
    }

    /// Handle Payment Key top-up with yield/resume
    fn handle_top_up(
        &mut self,
        sender_id: AccountId,
        amount: U128,
        nonce: u32,
    ) {
        // Check minimum amount
        assert!(
            amount.0 >= MIN_TOP_UP_AMOUNT,
            "Minimum top-up is $0.01 ({} minimal units)",
            MIN_TOP_UP_AMOUNT
        );

        // Build secret key for Payment Key
        let secret_key = SecretKey {
            accessor: SecretAccessor::System(SystemSecretType::PaymentKey),
            profile: nonce.to_string(),
            owner: sender_id.clone(),
        };

        // Get existing secret
        let secret_profile = self.secrets_storage.get(&secret_key)
            .expect("Payment key not found. Create it first with store_secrets()");

        // Create callback data
        let callback_data = json!({
            "owner": sender_id,
            "nonce": nonce,
            "amount": amount,
        });

        // Create yield - wait for worker to re-encrypt secret with new balance
        let promise_idx = env::promise_yield_create(
            "on_top_up_response",
            &callback_data.to_string().into_bytes(),
            TOP_UP_CALLBACK_GAS,
            GasWeight(1),
            DATA_ID_REGISTER,
        );

        // Get data_id for resume
        let data_id: CryptoHash = env::read_register(DATA_ID_REGISTER)
            .expect("Failed to read data_id")
            .try_into()
            .expect("Invalid data_id");

        // Emit event for worker to process
        self.emit_system_event(SystemEvent::TopUpPaymentKey {
            data_id,
            owner: sender_id.clone(),
            nonce,
            amount,
            encrypted_data: secret_profile.encrypted_secrets,
        });

        log!(
            "TopUp requested: owner={}, nonce={}, amount={}",
            sender_id,
            nonce,
            amount.0
        );

        // Return the yield promise (will be resumed by worker)
        env::promise_return(promise_idx);
    }

    /// Emit system event for workers
    /// pub(crate) to allow calling from secrets.rs for PaymentKey creation
    pub(crate) fn emit_system_event(&self, event: SystemEvent) {
        let event_json = json!({
            "standard": self.event_standard,
            "version": self.event_version,
            "event": "system_event",
            "data": [event]
        });

        log!("EVENT_JSON:{}", event_json.to_string());
    }

    /// Internal: Request execution of payment-keys-with-intents WASI
    fn internal_request_token_swap(
        &self,
        owner: AccountId,
        nonce: u32,
        token_id: String,
        amount: String,
        swap_contract_id: String,
    ) -> Promise {
        // Build input for the WASI
        let input_data = json!({
            "owner": owner,
            "nonce": nonce,
            "token_id": token_id,
            "amount": amount,
            "swap_contract_id": swap_contract_id,
        })
        .to_string();

        // Build execution source - project reference
        let source = json!({
            "Project": {
                "project_id": "publishintent.near/payment-keys-with-intents",
                "version_key": null
            }
        });

        // Call request_execution on ourselves
        // Note: This is an internal call, so we use env::current_account_id()
        // Use function_call_weight to give ALL remaining gas to this call
        Promise::new(env::current_account_id()).function_call_weight(
            "request_execution".to_string(),
            json!({
                "source": source,
                "resource_limits": {
                    "max_instructions": 10_000_000_000_u64, // 10B instructions
                    "max_memory_mb": 256_u32,
                    "max_execution_seconds": 120_u64, // 2 minutes for swap
                },
                "input_data": input_data,
                // Secrets owner for swap contract private key (SWAP_CONTRACT_PRIVATE_KEY)
                // This account must have stored secrets with profile "intents-swap"
                "secrets_ref": {
                    "profile": "intents-swap",
                    "account_id": "publishintent.near", // Hardcoded: secrets owner for intents swap
                },
                "response_format": "Json",
                "payer_account_id": null,
                "params": null,
            })
            .to_string()
            .into_bytes(),
            NearToken::from_yoctonear(15000000000000000000000), // Pay base fee for execution
            Gas::from_tgas(0), // minimum gas (will get all remaining)
            GasWeight(1),      // weight = 1, gets all remaining gas
        )
    }
}