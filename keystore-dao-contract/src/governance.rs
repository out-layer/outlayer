//! Governance: every change that can reach the master secret, the members or the code of a
//! contract is a proposal that DAO members vote on, and runs only after a delay. Every method
//! here is for DAO members only; the owner can cancel a proposal and nothing else.
//!
//! A proposal fixes its electorate and threshold when it is created. A vote counts only from
//! an account in that electorate that is still a member. Quorum makes it `Approved`; a member
//! calls `execute` once `gov_delay_ns` has passed.
//!
//! No callbacks. `execute` marks the proposal `Executed` and then dispatches its promise. An
//! upgrade batch is atomic — deploy [+ `migrate()`] + `gov_health()` — so a failing step
//! leaves the old code; the proposal stays `Executed`, and members propose again.
//!
//! Proposals are stored versioned (`VersionedGovProposal`): a released variant is never changed
//! or removed, a later version adds the next one and keeps reading the old. So any version reads
//! every proposal any earlier version wrote, open or closed, and the DAO upgrades itself whatever
//! is open.
//!
//! A proposal does not live for ever: `Pending` for `PROPOSAL_TTL`, `Approved` for
//! `EXECUTION_WINDOW` after its delay. Past that, a member closes it with `expire`, so an
//! approved proposal cannot be executed long after the moment it was voted for.
//!
//! A proposal is stored at its proposer's cost (`propose` is payable).
//!
//! Code reaches a vote as a blob: a member stores the wasm with `store_blob` (raw input,
//! storage deposit) and the proposal names its sha256 — the code hash NEAR reports for the
//! account after the deploy, and the hash a reproducible build gives. Executing the upgrade
//! drops the blob and returns the deposit to whoever stored it.
//!
//! Upgrade ABI — called by an earlier version on a later one, so every version keeps them:
//! `migrate()` (`#[private]`, `#[init(ignore_state)]`, no arguments) and `gov_health()`; on a
//! governed contract `upgrade()` / `upgrade_and_migrate()`, the wasm as raw input.

use crate::*;
use near_sdk::json_types::{Base64VecU8, U128};
use near_sdk::PromiseOrValue;

/// Longest delay governance may set. A delay without a bound could be voted so long that
/// nothing, including a vote to shorten it, would ever execute again.
pub const MAX_GOV_DELAY_SEC: u64 = 30 * 24 * 60 * 60;

/// Delay a contract starts with when none is given: 72 h on a `.near` account (mainnet),
/// none elsewhere (testnet, sandbox).
pub const MAINNET_GOV_DELAY_SEC: u64 = 72 * 60 * 60;

/// Most gas a `Call` proposal may attach.
pub const MAX_CALL_GAS_TGAS: u64 = 250;

/// Largest `Call.args`. The methods governance calls take a few hundred bytes.
pub const MAX_CALL_ARGS_BYTES: usize = 8 * 1024;

/// How long a proposal may wait for its votes.
pub const PROPOSAL_TTL_NS: u64 = 14 * 24 * 60 * 60 * 1_000_000_000;

/// How long an approved proposal may wait to be executed once its delay has passed.
pub const EXECUTION_WINDOW_NS: u64 = 7 * 24 * 60 * 60 * 1_000_000_000;

const MIGRATE_GAS: Gas = Gas::from_tgas(60);
const HEALTH_GAS: Gas = Gas::from_tgas(20);
/// The least gas a governed contract's `upgrade` / `upgrade_and_migrate` gets: deploying the
/// wasm on itself, then its `migrate` (60) and `gov_health` (20). The call also takes all the
/// gas `execute` leaves unused (weight 1), so a larger wasm needs only more gas on `execute`,
/// never a new DAO release.
const REMOTE_UPGRADE_GAS: Gas = Gas::from_tgas(180);

/// Raw storage key of a stored blob's bytes. Outside the `StorageKey` prefix table (one borsh
/// variant byte each), so it cannot collide with a collection.
fn blob_key(hash: &Base58CryptoHash) -> Vec<u8> {
    let bytes: [u8; 32] = (*hash).into();
    [b"blob:".as_slice(), bytes.as_slice()].concat()
}

/// A stored wasm: who stored it and what it holds of their deposit. Frozen once released, like
/// `VersionedGovProposal::V1`: a changed shape would leave stored blobs unremovable.
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(::near_sdk::schemars::JsonSchema)
)]
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[borsh(crate = "near_sdk::borsh")]
#[serde(crate = "near_sdk::serde")]
pub struct BlobInfo {
    pub storer: AccountId,
    pub deposit: U128,
    pub size: u64,
}

#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(::near_sdk::schemars::JsonSchema)
)]
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[borsh(crate = "near_sdk::borsh")]
#[serde(crate = "near_sdk::serde")]
pub enum GovAction {
    /// Deploy the stored blob `code_hash` on `target`, calling its `migrate()` when `migrate`
    /// is true. `target` is this contract or a contract whose `governance_id` is this contract.
    Upgrade {
        target: AccountId,
        code_hash: Base58CryptoHash,
        migrate: bool,
    },
    /// A function call on another contract governed by this one (its owner or governance
    /// methods). Never this contract — everything this contract governs on itself is a
    /// typed action below — and never the MPC contract.
    Call {
        target: AccountId,
        method: String,
        args: Base64VecU8,
        deposit: U128,
        gas_tgas: u64,
    },
    /// Whitelist a keystore build. Revoking one is also open to the owner (fast path).
    ApproveMeasurements { measurements: ApprovedMeasurements },
    RevokeMeasurements { measurements: ApprovedMeasurements },
    AddMember { member: AccountId },
    RemoveMember { member: AccountId },
    SetDelay { seconds: u64 },
    SetOwner { owner: AccountId },
}

impl GovAction {
    fn kind(&self) -> &'static str {
        match self {
            GovAction::Upgrade { .. } => "upgrade",
            GovAction::Call { .. } => "call",
            GovAction::ApproveMeasurements { .. } => "approve_measurements",
            GovAction::RevokeMeasurements { .. } => "revoke_measurements",
            GovAction::AddMember { .. } => "add_member",
            GovAction::RemoveMember { .. } => "remove_member",
            GovAction::SetDelay { .. } => "set_delay",
            GovAction::SetOwner { .. } => "set_owner",
        }
    }
}

#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(::near_sdk::schemars::JsonSchema)
)]
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[borsh(crate = "near_sdk::borsh")]
#[serde(crate = "near_sdk::serde")]
pub enum GovStatus {
    Pending,
    /// Quorum reached; executable from `executable_after`.
    Approved,
    Rejected,
    Executed,
    Cancelled,
    /// Past `PROPOSAL_TTL` while pending, or past `EXECUTION_WINDOW` while approved.
    Expired,
}

#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(::near_sdk::schemars::JsonSchema)
)]
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug)]
#[borsh(crate = "near_sdk::borsh")]
#[serde(crate = "near_sdk::serde")]
pub struct GovProposal {
    pub id: u64,
    pub action: GovAction,
    pub proposer: AccountId,
    pub created_at: u64,
    /// Members when the proposal was created. Only they can vote on it.
    pub electorate: Vec<AccountId>,
    /// Votes needed, fixed when the proposal was created.
    pub threshold: u32,
    pub votes_for: Vec<AccountId>,
    pub votes_against: Vec<AccountId>,
    pub status: GovStatus,
    /// Block timestamp (ns) of the vote that reached quorum.
    pub approved_at: Option<u64>,
    /// Block timestamp (ns) from which `execute` runs it.
    pub executable_after: Option<u64>,
}

/// How a proposal is stored. A released variant is never changed or removed: a later version of
/// this contract adds `V2` and keeps reading `V1`, so whatever an earlier version wrote stays
/// readable. `V1`'s shape is frozen once released — `GovProposal`, `GovAction`, `GovStatus`
/// and every type inside them, `ApprovedMeasurements` included.
#[derive(BorshSerialize, BorshDeserialize)]
#[borsh(crate = "near_sdk::borsh")]
pub enum VersionedGovProposal {
    V1(GovProposal),
}

impl From<VersionedGovProposal> for GovProposal {
    fn from(v: VersionedGovProposal) -> Self {
        match v {
            VersionedGovProposal::V1(p) => p,
        }
    }
}

/// Methods of a governed contract that replace one of its roles: its owner, its governance, its
/// operator. A `Call` to one of them is a role change (`role_of`).
const GOVERNED_ROLE_METHODS: [&str; 3] = ["set_owner", "set_governance", "set_operator"];

/// A role a governance proposal changes.
enum Role<'a> {
    /// This contract's owner (`SetOwner`).
    Owner,
    /// A governed contract's owner, governance or operator (a `Call` to that method).
    Governed { method: &'a str, target: &'a AccountId },
    /// One account's membership (`AddMember` / `RemoveMember`).
    Member(&'a AccountId),
}

impl KeystoreDao {
    pub(crate) fn gov_get(&self, proposal_id: u64) -> Option<GovProposal> {
        self.gov_proposals.get(&proposal_id).map(GovProposal::from)
    }

    fn gov_put(&mut self, p: &GovProposal) {
        self.gov_proposals.insert(&p.id, &VersionedGovProposal::V1(p.clone()));
    }

    /// The role a proposal changes, if any. The one list of roles: `execute` orders proposals
    /// by it (`role_key`) and `cancel` keeps the owner from stopping its own replacement by it.
    fn role_of(action: &GovAction) -> Option<Role<'_>> {
        match action {
            GovAction::SetOwner { .. } => Some(Role::Owner),
            GovAction::Call { target, method, .. } if GOVERNED_ROLE_METHODS.contains(&method.as_str()) => {
                Some(Role::Governed { method: method.as_str(), target })
            }
            GovAction::AddMember { member } | GovAction::RemoveMember { member } => Some(Role::Member(member)),
            _ => None,
        }
    }

    /// Of two approved proposals for one role, the newer decision wins: once a proposal has
    /// changed a role, an older proposal for the same role no longer executes. Otherwise a
    /// duplicate approved earlier could be executed by a single member after the majority
    /// decided otherwise.
    fn role_key(action: &GovAction) -> Option<String> {
        Self::role_of(action).map(|role| match role {
            Role::Owner => format!("set_owner:{}", env::current_account_id()),
            Role::Governed { method, target } => format!("{}:{}", method, target),
            Role::Member(member) => format!("member:{}", member),
        })
    }

    fn role_changes() -> LookupMap<String, u64> {
        LookupMap::new(StorageKey::RoleChanges)
    }

    /// Delay for a fresh or migrated contract when none is given (see `MAINNET_GOV_DELAY_SEC`).
    pub(crate) fn default_gov_delay_ns() -> u64 {
        let delay_sec = if env::current_account_id().as_str().ends_with(".near") {
            MAINNET_GOV_DELAY_SEC
        } else {
            0
        };
        delay_sec * 1_000_000_000
    }

    fn validate_gov_action(&self, action: &GovAction) {
        match action {
            GovAction::Upgrade { target, code_hash, .. } => {
                require!(
                    *target != self.mpc_contract_id,
                    "An Upgrade proposal cannot target the MPC contract"
                );
                require!(
                    self.blobs.get(code_hash).is_some(),
                    format!("No blob {} stored; store_blob the wasm first", String::from(code_hash))
                );
            }
            GovAction::Call { target, method, args, gas_tgas, .. } => {
                require!(
                    *target != env::current_account_id(),
                    "A Call proposal cannot target this contract; use the typed action instead"
                );
                // The MPC contract derives the master for THIS account: a call to it from here
                // is the master itself. That only ever happens from a keystore's request_key.
                require!(
                    *target != self.mpc_contract_id,
                    "A Call proposal cannot target the MPC contract"
                );
                require!(!method.is_empty(), "method must not be empty");
                // Code changes only as an `Upgrade`: a stored blob, reviewed by its hash.
                require!(
                    method != "upgrade" && method != "upgrade_and_migrate",
                    "Upgrade a contract with an Upgrade proposal, not a Call"
                );
                require!(
                    args.0.len() <= MAX_CALL_ARGS_BYTES,
                    format!("args must be at most {} bytes", MAX_CALL_ARGS_BYTES)
                );
                require!(
                    *gas_tgas > 0 && *gas_tgas <= MAX_CALL_GAS_TGAS,
                    format!("gas_tgas must be in 1..={}", MAX_CALL_GAS_TGAS)
                );
            }
            GovAction::ApproveMeasurements { measurements }
            | GovAction::RevokeMeasurements { measurements } => {
                Self::validate_measurements(measurements);
            }
            GovAction::AddMember { member } => {
                require!(!self.dao_members.contains(member), "Already a DAO member");
            }
            GovAction::RemoveMember { member } => {
                require!(self.dao_members.contains(member), "Not a DAO member");
                require!(self.dao_members.len() > 1, "Cannot remove the last DAO member");
            }
            GovAction::SetDelay { seconds } => {
                require!(
                    *seconds <= MAX_GOV_DELAY_SEC,
                    format!("Delay must be at most {} seconds", MAX_GOV_DELAY_SEC)
                );
            }
            GovAction::SetOwner { owner } => {
                require!(*owner != self.owner_id, "Already the owner");
                // This contract cannot sign as its own owner: the brake would be gone until
                // another SetOwner.
                require!(
                    *owner != env::current_account_id(),
                    "The owner cannot be this contract itself"
                );
            }
        }
    }

    pub(crate) fn internal_gov_vote(&mut self, proposal_id: u64, approve: bool) {
        let voter = env::predecessor_account_id();
        let mut p = self.gov_get(proposal_id)
            .unwrap_or_else(|| env::panic_str("Governance proposal not found"));
        require!(p.status == GovStatus::Pending, "Proposal is not pending");
        // Past its time a proposal takes no votes: otherwise old votes plus one new one could
        // approve it months later, with a fresh execution window.
        require!(
            !Self::is_expired(&p, env::block_timestamp()),
            "Proposal expired: it takes no more votes; close it with expire and propose again"
        );
        require!(
            p.electorate.contains(&voter),
            "Not in this proposal's electorate (members when it was created)"
        );
        require!(
            !p.votes_for.contains(&voter) && !p.votes_against.contains(&voter),
            "Already voted on this proposal"
        );
        if approve {
            p.votes_for.push(voter);
        } else {
            p.votes_against.push(voter);
        }

        // Only votes of accounts that are still members count; the threshold stays the one
        // fixed at creation.
        let live_for = p.votes_for.iter().filter(|v| self.dao_members.contains(v)).count() as u32;
        let live_against =
            p.votes_against.iter().filter(|v| self.dao_members.contains(v)).count() as u32;
        let electorate = p.electorate.len() as u32;

        if live_for >= p.threshold {
            let now = env::block_timestamp();
            p.status = GovStatus::Approved;
            p.approved_at = Some(now);
            p.executable_after = Some(now.saturating_add(self.gov_delay_ns));
            env::log_str(&format!(
                "gov_approved id={} kind={} executable_after={}",
                p.id,
                p.action.kind(),
                p.executable_after.unwrap_or_default()
            ));
        } else if live_against > electorate.saturating_sub(p.threshold) {
            p.status = GovStatus::Rejected;
            env::log_str(&format!("gov_rejected id={} kind={}", p.id, p.action.kind()));
        } else {
            env::log_str(&format!("gov_vote id={} votes={}/{}", p.id, live_for, p.threshold));
        }
        self.gov_put(&p);
    }

    /// Take a blob out of storage and return its deposit; the bytes go to the deploy.
    fn take_blob(&mut self, hash: &Base58CryptoHash) -> Vec<u8> {
        let info = self
            .blobs
            .get(hash)
            .unwrap_or_else(|| env::panic_str("The blob this proposal names is no longer stored"));
        let code = env::storage_read(&blob_key(hash))
            .unwrap_or_else(|| env::panic_str("Blob bytes missing"));
        self.remove_blob_and_refund(hash, &info);
        code
    }

    fn remove_blob_and_refund(&mut self, hash: &Base58CryptoHash, info: &BlobInfo) {
        env::storage_remove(&blob_key(hash));
        self.blobs.remove(hash);
        env::log_str(&format!("blob_removed {} refund={}", String::from(hash), info.deposit.0));
        if info.deposit.0 > 0 {
            Promise::new(info.storer.clone())
                .transfer(NearToken::from_yoctonear(info.deposit.0))
                .detach();
        }
    }

    /// The batch that deploys `code` on THIS account: atomic, so a failing `migrate` or a
    /// state the new code cannot read (`gov_health`) leaves the old code in place.
    pub(crate) fn self_upgrade_batch(code: Vec<u8>, migrate: bool) -> Promise {
        let mut p = Promise::new(env::current_account_id()).deploy_contract(code);
        if migrate {
            p = p.function_call(
                "migrate".to_string(),
                b"{}".to_vec(),
                NearToken::from_yoctonear(0),
                MIGRATE_GAS,
            );
        }
        p.function_call(
            "gov_health".to_string(),
            b"{}".to_vec(),
            NearToken::from_yoctonear(0),
            HEALTH_GAS,
        )
    }

    /// Past its time: `Pending` beyond `PROPOSAL_TTL`, `Approved` beyond `EXECUTION_WINDOW`.
    fn is_expired(p: &GovProposal, now: u64) -> bool {
        match p.status {
            GovStatus::Pending => now > p.created_at.saturating_add(PROPOSAL_TTL_NS),
            GovStatus::Approved => {
                now > p.executable_after.unwrap_or(u64::MAX).saturating_add(EXECUTION_WINDOW_NS)
            }
            _ => false,
        }
    }

    fn apply_member_change(&mut self) {
        self.approval_threshold = (self.dao_members.len() as u32 / 2) + 1;
    }
}

#[near_bindgen]
impl KeystoreDao {
    /// DAO member: propose a governance action. The proposer's vote is recorded with it, so
    /// a one-member DAO reaches quorum here. Returns the proposal id (shared with keystore
    /// registration and key-revocation proposals; members vote on all of them with `vote`).
    ///
    /// Payable: attach the storage the proposal takes (its action, the electorate and the votes
    /// to come are kept for good, as the record); the excess comes back.
    #[payable]
    pub fn propose(&mut self, action: GovAction) -> u64 {
        self.assert_dao_member();
        self.validate_gov_action(&action);
        let before = env::storage_usage();

        let id = self.next_proposal_id;
        self.next_proposal_id += 1;
        let p = GovProposal {
            id,
            action,
            proposer: env::predecessor_account_id(),
            created_at: env::block_timestamp(),
            electorate: self.dao_members.to_vec(),
            threshold: self.approval_threshold,
            votes_for: Vec::new(),
            votes_against: Vec::new(),
            status: GovStatus::Pending,
            approved_at: None,
            executable_after: None,
        };
        env::log_str(&format!(
            "gov_proposed id={} kind={} threshold={}/{}",
            id,
            p.action.kind(),
            p.threshold,
            p.electorate.len()
        ));
        self.gov_put(&p);
        self.internal_gov_vote(id, true);

        // Room for every member's vote: the votes are written later, by members who pay nothing.
        let votes_reserve = (self.dao_members.len() as u64) * 96;
        let cost = (env::storage_usage() - before + votes_reserve) as u128
            * env::storage_byte_cost().as_yoctonear();
        let attached = env::attached_deposit().as_yoctonear();
        require!(
            attached >= cost,
            format!("Attach {} yoctoNEAR for the proposal's storage (attached {})", cost, attached)
        );
        if attached > cost {
            Promise::new(env::predecessor_account_id())
                .transfer(NearToken::from_yoctonear(attached - cost))
                .detach();
        }
        id
    }

    /// DAO member: run an approved proposal once its delay has passed. The proposal is
    /// `Executed` from here on; an upgrade or a call is then dispatched, and if it fails on the
    /// other side (an upgrade reverts as a whole) members propose it again.
    pub fn execute(&mut self, proposal_id: u64) -> PromiseOrValue<bool> {
        self.assert_dao_member();
        let mut p = self.gov_get(proposal_id)
            .unwrap_or_else(|| env::panic_str("Governance proposal not found"));
        require!(p.status == GovStatus::Approved, "Proposal is not approved");
        let after = p.executable_after.unwrap_or(u64::MAX);
        require!(
            env::block_timestamp() >= after,
            format!("Proposal executes from block timestamp {}", after)
        );
        require!(
            !Self::is_expired(&p, env::block_timestamp()),
            "Proposal expired: its execution window has passed; close it with expire and propose again"
        );
        // The same checks as at proposal time, against the state now.
        self.validate_gov_action(&p.action);
        if let Some(role) = Self::role_key(&p.action) {
            let mut changes = Self::role_changes();
            if let Some(last) = changes.get(&role) {
                require!(
                    p.id > last,
                    format!(
                        "Proposal {} for {} is older than proposal {}, which already changed it",
                        p.id, role, last
                    )
                );
            }
            changes.insert(&role, &p.id);
        }

        p.status = GovStatus::Executed;
        self.gov_put(&p);
        env::log_str(&format!("gov_executed id={} kind={}", p.id, p.action.kind()));

        match p.action {
            GovAction::Upgrade { target, code_hash, migrate } => {
                let code = self.take_blob(&code_hash);
                if target == env::current_account_id() {
                    PromiseOrValue::Promise(Self::self_upgrade_batch(code, migrate))
                } else {
                    let method = if migrate { "upgrade_and_migrate" } else { "upgrade" };
                    PromiseOrValue::Promise(Promise::new(target).function_call_weight(
                        method.to_string(),
                        code,
                        NearToken::from_yoctonear(0),
                        REMOTE_UPGRADE_GAS,
                        near_sdk::GasWeight(1),
                    ))
                }
            }
            GovAction::Call { target, method, args, deposit, gas_tgas } => {
                PromiseOrValue::Promise(Promise::new(target).function_call(
                    method,
                    args.0,
                    NearToken::from_yoctonear(deposit.0),
                    Gas::from_tgas(gas_tgas),
                ))
            }
            GovAction::ApproveMeasurements { measurements } => {
                let measurements = measurements.lowercase();
                if !self.approved_measurements.contains(&measurements) {
                    self.approved_measurements.push(measurements.clone());
                }
                env::log_str(&format!(
                    "measurements_approved mrtd={} rtmr3={} total={}",
                    measurements.mrtd,
                    measurements.rtmr3,
                    self.approved_measurements.len()
                ));
                PromiseOrValue::Value(true)
            }
            GovAction::RevokeMeasurements { measurements } => {
                let measurements = measurements.lowercase();
                self.approved_measurements.retain(|m| m != &measurements);
                env::log_str(&format!(
                    "measurements_revoked mrtd={} rtmr3={} total={}",
                    measurements.mrtd,
                    measurements.rtmr3,
                    self.approved_measurements.len()
                ));
                PromiseOrValue::Value(true)
            }
            GovAction::AddMember { member } => {
                self.dao_members.insert(&member);
                self.apply_member_change();
                env::log_str(&format!(
                    "member_added {} threshold={}/{}",
                    member,
                    self.approval_threshold,
                    self.dao_members.len()
                ));
                PromiseOrValue::Value(true)
            }
            GovAction::RemoveMember { member } => {
                self.dao_members.remove(&member);
                self.apply_member_change();
                env::log_str(&format!(
                    "member_removed {} threshold={}/{}",
                    member,
                    self.approval_threshold,
                    self.dao_members.len()
                ));
                PromiseOrValue::Value(true)
            }
            GovAction::SetDelay { seconds } => {
                self.gov_delay_ns = seconds * 1_000_000_000;
                env::log_str(&format!("gov_delay_set seconds={}", seconds));
                PromiseOrValue::Value(true)
            }
            GovAction::SetOwner { owner } => {
                env::log_str(&format!("owner_set {} -> {}", self.owner_id, owner));
                self.owner_id = owner;
                PromiseOrValue::Value(true)
            }
        }
    }

    /// Owner: stop a pending or approved proposal before it executes. A proposal that
    /// replaces a role — `SetOwner` here, a `Call` to `set_owner`, `set_governance` or
    /// `set_operator` on a governed contract — cannot be cancelled by the owner: otherwise a lost
    /// or stolen owner key could keep itself, or a compromised operator, in place. Members vote
    /// such a proposal down, or let it expire.
    pub fn cancel(&mut self, proposal_id: u64) {
        self.assert_owner();
        let mut p = self.gov_get(proposal_id)
            .unwrap_or_else(|| env::panic_str("Governance proposal not found"));
        require!(
            matches!(p.status, GovStatus::Pending | GovStatus::Approved),
            "Only a pending or approved proposal can be cancelled"
        );
        // Membership is the members' own business; the owner is kept from stopping only the
        // replacement of an owner, a governance or an operator.
        let replaces_a_role = matches!(Self::role_of(&p.action), Some(Role::Owner | Role::Governed { .. }));
        require!(
            !replaces_a_role,
            "A proposal that replaces the owner cannot be cancelled by the owner; members can vote it down"
        );
        p.status = GovStatus::Cancelled;
        self.gov_put(&p);
        env::log_str(&format!("gov_cancelled id={} kind={}", p.id, p.action.kind()));
    }

    /// DAO member: close a proposal past its time (`Pending` beyond 14 days, `Approved` beyond
    /// 7 days after its delay). Any kind, an owner replacement included.
    pub fn expire(&mut self, proposal_id: u64) {
        self.assert_dao_member();
        let mut p = self.gov_get(proposal_id)
            .unwrap_or_else(|| env::panic_str("Governance proposal not found"));
        require!(Self::is_expired(&p, env::block_timestamp()), "Proposal has not expired");
        p.status = GovStatus::Expired;
        self.gov_put(&p);
        env::log_str(&format!("gov_expired id={} kind={}", p.id, p.action.kind()));
    }

    /// DAO member: store a wasm for an upgrade proposal. The wasm is the raw input of the call
    /// (not JSON); attach the storage deposit for its bytes, the excess comes back. Returns its
    /// sha256 — the `code_hash` a proposal names. The deposit returns when the upgrade that
    /// uses the blob executes, or when the storer removes the blob.
    #[payable]
    pub fn store_blob(&mut self) -> Base58CryptoHash {
        self.assert_dao_member();
        let code = env::input().unwrap_or_default();
        require!(!code.is_empty(), "store_blob takes the wasm as the raw input of the call");
        let hash = Base58CryptoHash::from(env::sha256_array(&code));
        require!(self.blobs.get(&hash).is_none(), "This blob is already stored");

        let storer = env::predecessor_account_id();
        let before = env::storage_usage();
        env::storage_write(&blob_key(&hash), &code);
        let mut info = BlobInfo { storer: storer.clone(), deposit: U128(0), size: code.len() as u64 };
        self.blobs.insert(&hash, &info);
        let cost =
            (env::storage_usage() - before) as u128 * env::storage_byte_cost().as_yoctonear();
        let attached = env::attached_deposit().as_yoctonear();
        require!(
            attached >= cost,
            format!("Attach {} yoctoNEAR for the blob's storage (attached {})", cost, attached)
        );
        info.deposit = U128(cost);
        self.blobs.insert(&hash, &info);
        if attached > cost {
            Promise::new(storer).transfer(NearToken::from_yoctonear(attached - cost)).detach();
        }
        env::log_str(&format!(
            "blob_stored {} size={} deposit={}",
            String::from(&hash),
            code.len(),
            cost
        ));
        hash
    }

    /// The member who stored a blob: remove it and take the deposit back.
    pub fn remove_blob(&mut self, hash: Base58CryptoHash) {
        let info = self.blobs.get(&hash).unwrap_or_else(|| env::panic_str("No such blob"));
        require!(
            env::predecessor_account_id() == info.storer,
            "Only the member who stored the blob can remove it"
        );
        self.remove_blob_and_refund(&hash, &info);
    }

    /// Reads the state. Part of the upgrade batch: a version that cannot read the state it
    /// is switched onto fails here, and the whole batch — the code switch included — reverts.
    pub fn gov_health(&self) -> u64 {
        self.next_proposal_id
    }

    pub fn get_gov_proposal(&self, proposal_id: u64) -> Option<GovProposal> {
        self.gov_get(proposal_id)
    }

    /// Governance proposals with ids in `from_index .. from_index + limit` (ids are shared
    /// with keystore registration and revocation proposals, so some ids hold none).
    pub fn get_gov_proposals(&self, from_index: u64, limit: u64) -> Vec<GovProposal> {
        (from_index..from_index.saturating_add(limit).min(self.next_proposal_id))
            .filter_map(|i| self.gov_get(i))
            .collect()
    }

    /// Id of the last executed proposal that changed `role` (`role_key`).
    pub fn get_last_role_change(&self, role: String) -> Option<u64> {
        Self::role_changes().get(&role)
    }

    pub fn get_gov_delay_sec(&self) -> u64 {
        self.gov_delay_ns / 1_000_000_000
    }

    pub fn get_blob(&self, hash: Base58CryptoHash) -> Option<BlobInfo> {
        self.blobs.get(&hash)
    }
}
