//! Owner exit: a NEAR account that owns agent wallets leaves with its master through this
//! contract, with no keystore alive.
//!
//! The keystore derives an owner's master inside the TEE from the default master and the
//! OWNER PATH `owner:{account}:{generation}`, and stores here an ESCROW of it: the master
//! encrypted under the MPC CKD key for that same path, with this contract as the predecessor.
//! Only this contract can ask MPC for that key, and it does so for exactly two callers: an
//! approved keystore, once, to write the escrow; and the owner, after the exit window, to open
//! it. The owner then holds the master and the generation moves on — the keystore stops
//! serving the generation that left.
//!
//! The path is built here, from `predecessor_account_id()` or from the stored record. No
//! method takes a path. An account id cannot contain `:`, so no two `(account, generation)`
//! pairs give the same path and none gives the empty path of the default master.
//!
//! Records live under their own storage prefixes, outside the root struct.
//!
//! An owner may name approvers: accounts whose quorum the exit then needs. A wallet policy
//! that is locked under its approvers' quorum is signed by the keystore only when the same
//! accounts and threshold stand here, so that an exit is never easier than the policy change
//! it would bypass. A vote is a transaction from the approver's account.

use near_sdk::json_types::{Base64VecU8, U128};
use near_sdk::serde_json::json;
use near_sdk::{assert_one_yocto, PromiseError};

use crate::*;

/// The CKD domain every key of this contract is derived in.
pub const CKD_DOMAIN_ID: u64 = 2;

/// What registering costs the caller. Kept: it pays for what the registration makes the
/// contract hold and do — the owner's record at its largest (3378 bytes with a full set of
/// approvers, a pending change to another and every vote cast: 0.034 NEAR of storage), the
/// first generation's escrow (214 bytes, 0.002 NEAR), and the gas of the two transactions
/// the keystore sends from this account to write that escrow — rounded up. The test
/// `the_fees_cover_the_storage_they_pay_for` holds it to the measured sizes.
pub const EXIT_REGISTRATION_FEE: NearToken = NearToken::from_millinear(50);

/// What starting an exit costs the caller. Kept, whether the exit is claimed, cancelled,
/// rejected or lapses: it pays for the next generation's escrow (214 bytes, 0.002 NEAR) and
/// the gas of the keystore's two transactions that write it — rounded up.
pub const EXIT_FEE: NearToken = NearToken::from_millinear(10);

/// The gas of the two transactions an approved keystore sends from this account for one
/// escrow (`request_escrow_key`, `store_escrow`), as the fees allow for it: 50 TGas burnt
/// at the protocol's minimum gas price.
pub const ESCROW_GAS_ALLOWANCE: NearToken = NearToken::from_millinear(5);

/// The most accounts an approver set holds.
pub const MAX_EXIT_APPROVERS: usize = 16;

/// How long a claim counts as in flight. Far above the time MPC takes to answer or to time
/// out; a claim whose callback never ran stops blocking the owner after it.
pub const CLAIM_MARK_LAPSE_NS: u64 = 3_600 * SECOND_NS;

const SECOND_NS: u64 = 1_000_000_000;
const HOUR_SECS: u64 = 3_600;
const DAY_SECS: u64 = 24 * HOUR_SECS;

const GAS_CLAIM_MPC: Gas = Gas::from_tgas(100);
const GAS_CLAIM_CALLBACK: Gas = Gas::from_tgas(30);
const GAS_ESCROW_MPC: Gas = Gas::from_tgas(100);

/// The longest ciphertext an escrow holds: a 32-byte master and an AEAD tag, with room.
const ESCROW_CT_MAX_BYTES: usize = 128;
const ESCROW_CHECK_BYTES: usize = 32;

/// The longest CKD answer the claim's callback passes on to the caller. A real one is two
/// G1 points in a small JSON object. A longer one still counts as MPC's success — the key
/// is out — and is read from MPC's own receipt instead.
const CKD_ANSWER_MAX_BYTES: usize = 4096;

/// The exit window's bounds and the claim window, by the account this contract runs on: the
/// real values on a `.near` account, short ones elsewhere so that a test network can walk an
/// exit through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExitTiming {
    pub min_window_secs: u64,
    pub max_window_secs: u64,
    pub default_window_secs: u64,
    pub finalize_window_secs: u64,
}

impl ExitTiming {
    pub fn of_this_account() -> Self {
        if env::current_account_id().as_str().ends_with(".near") {
            Self {
                min_window_secs: DAY_SECS,
                max_window_secs: 2 * DAY_SECS,
                default_window_secs: DAY_SECS,
                finalize_window_secs: 7 * DAY_SECS,
            }
        } else {
            Self { min_window_secs: 60, max_window_secs: HOUR_SECS, default_window_secs: 60, finalize_window_secs: 600 }
        }
    }
}

/// A lowering of the exit window that is not in force yet.
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq)]
#[borsh(crate = "near_sdk::borsh")]
#[serde(crate = "near_sdk::serde")]
pub struct PendingExitWindow {
    pub secs: u64,
    /// Block timestamp (ns) from which it is in force.
    pub effective_at: u64,
}

/// What a pending action does once it may proceed.
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[borsh(crate = "near_sdk::borsh")]
#[serde(crate = "near_sdk::serde")]
pub enum ExitActionKind {
    /// The owner's exit from the current generation. The key is claimed inside
    /// `[finalize_after, finalize_before]`, block timestamps in ns.
    Exit { finalize_after: u64, finalize_before: u64 },
    /// A change of the approver set, in force once the set it replaces has approved it.
    SetApprovers {
        #[schemars(with = "Vec<String>")]
        approvers: Vec<AccountId>,
        threshold: u32,
    },
}

/// The one action an owner may have pending.
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[borsh(crate = "near_sdk::borsh")]
#[serde(crate = "near_sdk::serde")]
pub struct PendingExitAction {
    /// What a vote names. Never reused by this owner.
    pub nonce: u64,
    pub kind: ExitActionKind,
    /// The approvers that voted for it, each once.
    #[schemars(with = "Vec<String>")]
    pub approvals: Vec<AccountId>,
}

#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, PartialEq, Eq)]
#[borsh(crate = "near_sdk::borsh")]
pub struct ExitOwner {
    pub generation: u64,
    /// Read through [`ExitOwner::window_at`]: a matured `pending_window` supersedes it.
    pub window_secs: u64,
    pub pending_window: Option<PendingExitWindow>,
    pub approvers: Vec<AccountId>,
    pub threshold: u32,
    pub next_nonce: u64,
    pub pending: Option<PendingExitAction>,
    /// Block timestamp (ns) of a claim whose callback has not run. Read through
    /// [`ExitOwner::claim_in_flight`].
    pub claim_mark: Option<u64>,
}

/// Stored versioned: a released variant is never changed, a later version adds the next one
/// and keeps reading the old.
#[derive(BorshDeserialize, BorshSerialize)]
#[borsh(crate = "near_sdk::borsh")]
pub enum VersionedExitOwner {
    V1(ExitOwner),
}

impl From<VersionedExitOwner> for ExitOwner {
    fn from(v: VersionedExitOwner) -> Self {
        match v {
            VersionedExitOwner::V1(o) => o,
        }
    }
}

#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, PartialEq, Eq)]
#[borsh(crate = "near_sdk::borsh")]
pub struct Escrow {
    pub ct: Vec<u8>,
    pub check: Vec<u8>,
    pub domain_id: u64,
}

#[derive(BorshDeserialize, BorshSerialize)]
#[borsh(crate = "near_sdk::borsh")]
pub enum VersionedEscrow {
    V1(Escrow),
}

impl From<VersionedEscrow> for Escrow {
    fn from(v: VersionedEscrow) -> Self {
        match v {
            VersionedEscrow::V1(e) => e,
        }
    }
}

/// An owner's record as the keystore's gate and the owner read it.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "near_sdk::serde")]
pub struct ExitOwnerView {
    pub generation: u64,
    /// The exit window in force at the block the view ran at.
    pub exit_window_secs: u64,
    /// A lowering not in force yet.
    pub pending_exit_window: Option<PendingExitWindow>,
    #[schemars(with = "Vec<String>")]
    pub approvers: Vec<AccountId>,
    pub threshold: u32,
    /// The pending action; an exit past its `finalize_before` is not shown.
    pub pending: Option<PendingExitAction>,
    /// A claim was sent to MPC and its outcome is not recorded yet: the keystore serves
    /// nothing of this owner while it is set.
    pub claim_in_flight: bool,
    /// The current generation's escrow `check`; absent until the keystore stored the escrow.
    #[schemars(with = "Option<String>")]
    pub escrow_check: Option<Base64VecU8>,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "near_sdk::serde")]
pub struct EscrowView {
    #[schemars(with = "String")]
    pub ct: Base64VecU8,
    #[schemars(with = "String")]
    pub check: Base64VecU8,
    pub domain_id: u64,
}

impl ExitOwner {
    /// The exit window in force at `now`.
    pub fn window_at(&self, now: u64) -> u64 {
        match self.pending_window {
            Some(p) if now >= p.effective_at => p.secs,
            _ => self.window_secs,
        }
    }

    fn settle_window(&mut self, now: u64) {
        if let Some(p) = self.pending_window {
            if now >= p.effective_at {
                self.window_secs = p.secs;
                self.pending_window = None;
            }
        }
    }

    pub fn claim_in_flight(&self, now: u64) -> bool {
        self.claim_mark.is_some_and(|mark| now < mark.saturating_add(CLAIM_MARK_LAPSE_NS))
    }

    /// The pending action that still stands at `now`: an exit past `finalize_before` does not.
    pub fn live_pending(&self, now: u64) -> Option<&PendingExitAction> {
        self.pending.as_ref().filter(|p| match p.kind {
            ExitActionKind::Exit { finalize_before, .. } => now <= finalize_before,
            ExitActionKind::SetApprovers { .. } => true,
        })
    }

    fn take_nonce(&mut self) -> u64 {
        let nonce = self.next_nonce;
        self.next_nonce += 1;
        nonce
    }
}

/// The path that names `account`'s `generation`: the CKD path of its escrow key and the key
/// its escrow is stored under.
pub fn owner_path(account: &AccountId, generation: u64) -> String {
    format!("owner:{}:{}", account, generation)
}

#[near_bindgen]
impl KeystoreDao {
    // ===== The owner =====

    /// Register the caller as an owner whose wallets can leave through this contract.
    /// `exit_window_sec`: how long an exit waits; the default when absent.
    #[payable]
    pub fn register_exit_owner(&mut self, exit_window_sec: Option<u64>) {
        let account = env::predecessor_account_id();
        require!(
            env::attached_deposit() >= EXIT_REGISTRATION_FEE,
            format!("registration takes {} attached", EXIT_REGISTRATION_FEE)
        );
        require!(Self::exit_owner(&account).is_none(), "this account is already registered");
        let timing = ExitTiming::of_this_account();
        let window_secs = exit_window_sec.unwrap_or(timing.default_window_secs);
        Self::assert_exit_window_in_range(window_secs, &timing);
        Self::put_exit_owner(
            &account,
            &ExitOwner {
                generation: 1,
                window_secs,
                pending_window: None,
                approvers: Vec::new(),
                threshold: 0,
                next_nonce: 1,
                pending: None,
                claim_mark: None,
            },
        );
        env::log_str(&format!("exit_owner_registered {} window_secs={}", account, window_secs));
    }

    /// Change the caller's exit window. A window at least as long as the one in force applies
    /// at once and drops a pending lowering; a shorter one applies after the window in force
    /// has elapsed and replaces a pending lowering.
    #[payable]
    pub fn set_exit_window(&mut self, exit_window_sec: u64) {
        assert_one_yocto();
        let (account, mut owner, now) = Self::exit_owner_for_write();
        Self::assert_exit_window_in_range(exit_window_sec, &ExitTiming::of_this_account());
        owner.settle_window(now);
        if exit_window_sec >= owner.window_secs {
            owner.window_secs = exit_window_sec;
            owner.pending_window = None;
            env::log_str(&format!("exit_window_set {} secs={}", account, exit_window_sec));
        } else {
            let effective_at = now + owner.window_secs * SECOND_NS;
            owner.pending_window = Some(PendingExitWindow { secs: exit_window_sec, effective_at });
            env::log_str(&format!(
                "exit_window_lowering {} secs={} effective_at={}",
                account, exit_window_sec, effective_at
            ));
        }
        Self::put_exit_owner(&account, &owner);
    }

    /// Name the accounts whose quorum the caller's exit needs. With no set in force it takes
    /// effect at once. With one in force it becomes the pending action, in force once that
    /// set's quorum has approved it. An empty list with threshold 0 removes the set.
    #[payable]
    pub fn set_exit_approvers(&mut self, approvers: Vec<AccountId>, threshold: u32) {
        assert_one_yocto();
        let (account, mut owner, now) = Self::exit_owner_for_write();
        require!(
            approvers.len() <= MAX_EXIT_APPROVERS,
            format!("at most {} approvers", MAX_EXIT_APPROVERS)
        );
        for (i, a) in approvers.iter().enumerate() {
            require!(!approvers[..i].contains(a), format!("{} is listed twice", a));
        }
        if approvers.is_empty() {
            require!(threshold == 0, "an empty set takes threshold 0");
        } else {
            require!(
                threshold >= 1 && threshold as usize <= approvers.len(),
                "threshold must be between 1 and the number of approvers"
            );
        }
        if owner.approvers.is_empty() {
            owner.approvers = approvers;
            owner.threshold = threshold;
            env::log_str(&format!("exit_approvers_set {} count={} threshold={}", account, owner.approvers.len(), threshold));
        } else {
            require!(
                owner.live_pending(now).is_none(),
                "an action is already pending: cancel_exit first"
            );
            let nonce = owner.take_nonce();
            owner.pending = Some(PendingExitAction {
                nonce,
                kind: ExitActionKind::SetApprovers { approvers, threshold },
                approvals: Vec::new(),
            });
            env::log_str(&format!("exit_approvers_change_pending {} nonce={}", account, nonce));
        }
        Self::put_exit_owner(&account, &owner);
    }

    /// Start the caller's exit from its current generation. The key can be claimed once the
    /// exit window in force now has elapsed.
    #[payable]
    pub fn initiate_exit(&mut self) {
        require!(env::attached_deposit() >= EXIT_FEE, format!("an exit takes {} attached", EXIT_FEE));
        let (account, mut owner, now) = Self::exit_owner_for_write();
        require!(owner.live_pending(now).is_none(), "an action is already pending: cancel_exit first");
        require!(
            Self::escrows().contains_key(&owner_path(&account, owner.generation)),
            "no escrow for this generation yet: it is written when the first wallet is used"
        );
        owner.settle_window(now);
        let finalize_after = now + owner.window_secs * SECOND_NS;
        let finalize_before = finalize_after + ExitTiming::of_this_account().finalize_window_secs * SECOND_NS;
        let nonce = owner.take_nonce();
        owner.pending = Some(PendingExitAction {
            nonce,
            kind: ExitActionKind::Exit { finalize_after, finalize_before },
            approvals: Vec::new(),
        });
        Self::put_exit_owner(&account, &owner);
        env::log_str(&format!(
            "exit_initiated {} generation={} nonce={} finalize_after={} finalize_before={}",
            account, owner.generation, nonce, finalize_after, finalize_before
        ));
    }

    /// Drop the caller's pending action.
    #[payable]
    pub fn cancel_exit(&mut self) {
        assert_one_yocto();
        let (account, mut owner, _) = Self::exit_owner_for_write();
        let pending = owner.pending.take().unwrap_or_else(|| env::panic_str("nothing is pending"));
        Self::put_exit_owner(&account, &owner);
        env::log_str(&format!("exit_cancelled {} nonce={}", account, pending.nonce));
    }

    /// Hand the caller the key that opens the escrow of the generation it is leaving: MPC's
    /// CKD answer, encrypted to `app_public_key`. Inside the claim window, with the approvers'
    /// quorum when a set is in force. On MPC's success the generation moves on.
    #[payable]
    pub fn claim_escrow_key(&mut self, app_public_key: dtos::Bls12381G1PublicKey) -> Promise {
        assert_one_yocto();
        let (account, mut owner, now) = Self::exit_owner_for_write();
        let (finalize_after, approvals) = match owner.live_pending(now) {
            Some(PendingExitAction { kind: ExitActionKind::Exit { finalize_after, .. }, approvals, .. }) => {
                (*finalize_after, approvals.iter().filter(|a| owner.approvers.contains(a)).count())
            }
            _ => env::panic_str("no exit is pending"),
        };
        require!(now >= finalize_after, "the exit window has not elapsed");
        require!(
            owner.approvers.is_empty() || approvals >= owner.threshold as usize,
            format!("{} of {} approvals", approvals, owner.threshold)
        );
        // MPC's answer is in MPC's own receipt whether or not the callback below runs: from
        // here the generation counts as leaving.
        owner.claim_mark = Some(now);
        Self::put_exit_owner(&account, &owner);

        ext_mpc::ext(self.mpc_contract_id.clone())
            .with_static_gas(GAS_CLAIM_MPC)
            .with_attached_deposit(NearToken::from_yoctonear(1))
            .request_app_private_key(CKDRequestArgs {
                derivation_path: owner_path(&account, owner.generation),
                app_public_key,
                domain_id: DomainId(CKD_DOMAIN_ID),
            })
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_CLAIM_CALLBACK)
                    .with_unused_gas_weight(0)
                    .on_escrow_key_claimed(account),
            )
    }

    /// Records the outcome of a claim. Reads only whether MPC answered: it never parses the
    /// answer and checks nothing else, so it cannot fail and leave the claim in flight. On
    /// success it returns MPC's bytes as they came.
    #[private]
    pub fn on_escrow_key_claimed(&mut self, owner: AccountId) {
        let answer = env::promise_result_checked(0, CKD_ANSWER_MAX_BYTES);
        let Some(mut record) = Self::exit_owner(&owner) else {
            return;
        };
        record.claim_mark = None;
        if matches!(answer, Err(PromiseError::Failed)) {
            Self::put_exit_owner(&owner, &record);
            env::log_str(&format!("exit_claim_failed {}", owner));
            return;
        }
        let left = record.generation;
        record.pending = None;
        record.generation += 1;
        Self::put_exit_owner(&owner, &record);
        env::log_str(&format!("exit_claimed {} generation={}", owner, left));
        if let Ok(bytes) = answer {
            env::value_return(&bytes);
        }
    }

    // ===== An approver =====

    /// Approve `owner`'s pending action `nonce`. A change of the approver set takes effect
    /// with the vote that completes the quorum.
    #[payable]
    pub fn approve_exit(&mut self, owner: AccountId, nonce: u64) {
        assert_one_yocto();
        let (approver, mut record, mut pending) = Self::exit_vote_context(&owner, nonce);
        pending.approvals.push(approver.clone());
        env::log_str(&format!("exit_vote {} nonce={} by={} approve", owner, nonce, approver));
        let quorum = pending.approvals.len() >= record.threshold as usize;
        match (&pending.kind, quorum) {
            (ExitActionKind::SetApprovers { approvers, threshold }, true) => {
                record.approvers = approvers.clone();
                record.threshold = *threshold;
                record.pending = None;
                env::log_str(&format!(
                    "exit_approvers_set {} count={} threshold={}",
                    owner,
                    record.approvers.len(),
                    record.threshold
                ));
            }
            _ => record.pending = Some(pending),
        }
        Self::put_exit_owner(&owner, &record);
    }

    /// End `owner`'s pending action `nonce`. One reject is final for that action.
    #[payable]
    pub fn reject_exit(&mut self, owner: AccountId, nonce: u64) {
        assert_one_yocto();
        let (approver, mut record, _) = Self::exit_vote_context(&owner, nonce);
        record.pending = None;
        Self::put_exit_owner(&owner, &record);
        env::log_str(&format!("exit_vote {} nonce={} by={} reject", owner, nonce, approver));
        env::log_str(&format!("exit_cancelled {} nonce={}", owner, nonce));
    }

    // ===== The keystore =====

    /// MPC's CKD answer for `owner`'s current generation, for the keystore to write the
    /// escrow with. Refused once that escrow is stored: after it, this key goes to the owner
    /// alone, through an exit.
    pub fn request_escrow_key(&self, owner: AccountId, app_public_key: dtos::Bls12381G1PublicKey) -> Promise {
        self.assert_approved_keystore_signer();
        let record = Self::exit_owner(&owner).unwrap_or_else(|| env::panic_str("not a registered owner"));
        let path = owner_path(&owner, record.generation);
        require!(!Self::escrows().contains_key(&path), "this generation's escrow is already stored");
        ext_mpc::ext(self.mpc_contract_id.clone())
            .with_static_gas(GAS_ESCROW_MPC)
            .with_attached_deposit(NearToken::from_yoctonear(1))
            .request_app_private_key(CKDRequestArgs {
                derivation_path: path,
                app_public_key,
                domain_id: DomainId(CKD_DOMAIN_ID),
            })
    }

    /// Store the escrow of `owner`'s current generation. The first write stands: a later one
    /// changes nothing and answers `false`.
    pub fn store_escrow(&mut self, owner: AccountId, generation: u64, ct: Base64VecU8, check: Base64VecU8) -> bool {
        self.assert_approved_keystore_signer();
        let record = Self::exit_owner(&owner).unwrap_or_else(|| env::panic_str("not a registered owner"));
        require!(generation == record.generation, "not the owner's current generation");
        require!(!ct.0.is_empty() && ct.0.len() <= ESCROW_CT_MAX_BYTES, "ct has the wrong length");
        require!(check.0.len() == ESCROW_CHECK_BYTES, "check has the wrong length");
        let path = owner_path(&owner, generation);
        let mut escrows = Self::escrows();
        if escrows.contains_key(&path) {
            return false;
        }
        escrows.insert(
            &path,
            &VersionedEscrow::V1(Escrow { ct: ct.0, check: check.0, domain_id: CKD_DOMAIN_ID }),
        );
        env::log_str(&format!("exit_escrow_stored {} generation={}", owner, generation));
        true
    }

    // ===== Views =====

    pub fn get_exit_owner(&self, account: AccountId) -> Option<ExitOwnerView> {
        let owner = Self::exit_owner(&account)?;
        let now = env::block_timestamp();
        let escrow_check = Self::escrows()
            .get(&owner_path(&account, owner.generation))
            .map(|e| Base64VecU8(Escrow::from(e).check));
        Some(ExitOwnerView {
            generation: owner.generation,
            exit_window_secs: owner.window_at(now),
            pending_exit_window: owner.pending_window.filter(|p| now < p.effective_at),
            pending: owner.live_pending(now).cloned(),
            claim_in_flight: owner.claim_in_flight(now),
            approvers: owner.approvers,
            threshold: owner.threshold,
            escrow_check,
        })
    }

    pub fn get_escrow(&self, account: AccountId, generation: u64) -> Option<EscrowView> {
        let e = Escrow::from(Self::escrows().get(&owner_path(&account, generation))?);
        Some(EscrowView { ct: Base64VecU8(e.ct), check: Base64VecU8(e.check), domain_id: e.domain_id })
    }
}

impl KeystoreDao {
    fn exit_owners() -> LookupMap<AccountId, VersionedExitOwner> {
        LookupMap::new(StorageKey::ExitOwners)
    }

    fn escrows() -> LookupMap<String, VersionedEscrow> {
        LookupMap::new(StorageKey::ExitEscrows)
    }

    pub(crate) fn exit_owner(account: &AccountId) -> Option<ExitOwner> {
        Self::exit_owners().get(account).map(Into::into)
    }

    pub(crate) fn put_exit_owner(account: &AccountId, owner: &ExitOwner) {
        Self::exit_owners().insert(account, &VersionedExitOwner::V1(owner.clone()));
    }

    /// The caller's record for a method that writes it: refused for an account that is not
    /// registered and while a claim is in flight.
    fn exit_owner_for_write() -> (AccountId, ExitOwner, u64) {
        let account = env::predecessor_account_id();
        let owner = Self::exit_owner(&account).unwrap_or_else(|| env::panic_str("not a registered owner"));
        let now = env::block_timestamp();
        require!(!owner.claim_in_flight(now), "a claim is in flight");
        (account, owner, now)
    }

    /// The voter, the owner's record and its pending action `nonce`, for a vote that counts:
    /// from an account of the set in force that has not voted on this action.
    fn exit_vote_context(owner: &AccountId, nonce: u64) -> (AccountId, ExitOwner, PendingExitAction) {
        let approver = env::predecessor_account_id();
        let record = Self::exit_owner(owner).unwrap_or_else(|| env::panic_str("not a registered owner"));
        let now = env::block_timestamp();
        require!(!record.claim_in_flight(now), "a claim is in flight");
        require!(record.approvers.contains(&approver), "not an approver of this owner");
        let pending = record
            .live_pending(now)
            .filter(|p| p.nonce == nonce)
            .cloned()
            .unwrap_or_else(|| env::panic_str("no pending action with this nonce"));
        require!(!pending.approvals.contains(&approver), "this account has voted on this action");
        (approver, record, pending)
    }

    fn assert_exit_window_in_range(secs: u64, timing: &ExitTiming) {
        require!(
            secs >= timing.min_window_secs && secs <= timing.max_window_secs,
            format!(
                "the exit window must be between {}s and {}s",
                timing.min_window_secs, timing.max_window_secs
            )
        );
    }

    /// The exit's fees and timing on this account, for `get_config`.
    pub(crate) fn exit_config() -> serde_json::Value {
        let t = ExitTiming::of_this_account();
        json!({
            "registration_fee": U128(EXIT_REGISTRATION_FEE.as_yoctonear()),
            "exit_fee": U128(EXIT_FEE.as_yoctonear()),
            "min_window_secs": t.min_window_secs,
            "max_window_secs": t.max_window_secs,
            "default_window_secs": t.default_window_secs,
            "finalize_window_secs": t.finalize_window_secs,
            "max_approvers": MAX_EXIT_APPROVERS,
            "ckd_domain_id": CKD_DOMAIN_ID,
        })
    }
}
