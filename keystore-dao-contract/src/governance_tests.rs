use crate::migration::KeystoreDaoV4;
use crate::*;
use near_sdk::json_types::{Base64VecU8, U128};
use near_sdk::test_utils::VMContextBuilder;
use near_sdk::mock::MockAction;
use near_sdk::test_utils::get_created_receipts;
use near_sdk::{testing_env, PromiseOrValue};

const HOUR_NS: u64 = 3_600 * 1_000_000_000;
const DAY_NS: u64 = 24 * HOUR_NS;

fn a(s: &str) -> AccountId {
    s.parse().unwrap()
}
fn dao_id() -> AccountId {
    a("dao.testnet")
}
fn owner() -> AccountId {
    a("owner.testnet")
}

fn ctx(predecessor: AccountId) -> VMContextBuilder {
    let mut b = VMContextBuilder::new();
    b.current_account_id(dao_id()).predecessor_account_id(predecessor);
    b
}
/// A call at `now_ns` with 1 NEAR attached: `propose` takes its storage from it (a direct call in
/// a unit test skips the payable check, so the other methods are unaffected).
fn at(predecessor: AccountId, now_ns: u64) {
    testing_env!(ctx(predecessor)
        .block_timestamp(now_ns)
        .attached_deposit(NearToken::from_near(1))
        .build());
}

fn dao(members: &[&str], delay_sec: u64) -> KeystoreDao {
    at(owner(), 0);
    KeystoreDao::new(
        owner(),
        a("init.testnet"),
        members.iter().map(|m| a(m)).collect(),
        a("v1.signer-prod.testnet"),
        Some(delay_sec),
    )
}

fn measurements(byte: char) -> ApprovedMeasurements {
    let f = byte.to_string().repeat(96);
    ApprovedMeasurements { mrtd: f.clone(), rtmr0: f.clone(), rtmr1: f.clone(), rtmr2: f.clone(), rtmr3: f }
}

fn status(d: &KeystoreDao, id: u64) -> GovStatus {
    d.get_gov_proposal(id).unwrap().status
}

/// Store a wasm blob as `who` (the call's raw input). Leaves the context at `who`, time 0.
fn store_as(d: &mut KeystoreDao, who: &str, code: &[u8]) -> Base58CryptoHash {
    let mut b = ctx(a(who));
    b.attached_deposit(NearToken::from_near(5));
    b.context.input = std::rc::Rc::from(code.to_vec().into_boxed_slice());
    testing_env!(b.build());
    let h = d.store_blob();
    at(a(who), 0);
    h
}
fn blob(d: &mut KeystoreDao, byte: u8) -> Base58CryptoHash {
    store_as(d, "m1.testnet", &vec![byte; 64])
}

fn key(byte: u8) -> PublicKey {
    PublicKey::from_parts(CurveType::ED25519, vec![byte; 32]).unwrap()
}

// ===== proposing and voting =====

#[test]
#[should_panic(expected = "only DAO members")]
fn propose_rejects_non_member() {
    let mut d = dao(&["m1.testnet"], 0);
    at(owner(), 0);
    d.propose(GovAction::SetDelay { seconds: 1 });
}

#[test]
fn one_member_reaches_quorum_on_propose_and_waits_for_the_delay() {
    let mut d = dao(&["m1.testnet"], 3_600);
    at(a("m1.testnet"), 10);
    let id = d.propose(GovAction::ApproveCompose { compose_hash: "ab".repeat(32) });
    let p = d.get_gov_proposal(id).unwrap();
    assert_eq!(p.status, GovStatus::Approved);
    assert_eq!(p.executable_after, Some(10 + HOUR_NS));

    at(a("m1.testnet"), 10 + HOUR_NS);
    assert!(matches!(d.execute(id), PromiseOrValue::Value(true)));
    assert_eq!(status(&d, id), GovStatus::Executed);
    assert_eq!(d.get_approved_composes(), vec!["ab".repeat(32)]);
}

#[test]
#[should_panic(expected = "Proposal executes from block timestamp")]
fn execute_before_the_delay_panics() {
    let mut d = dao(&["m1.testnet"], 3_600);
    at(a("m1.testnet"), 10);
    let id = d.propose(GovAction::ApproveCompose { compose_hash: "ab".repeat(32) });
    at(a("m1.testnet"), 10 + HOUR_NS - 1);
    let _ = d.execute(id);
}

#[test]
#[should_panic(expected = "only DAO members")]
fn only_a_member_executes() {
    let mut d = dao(&["m1.testnet"], 0);
    at(a("m1.testnet"), 0);
    let id = d.propose(GovAction::SetDelay { seconds: 5 });
    at(a("stranger.testnet"), 0);
    let _ = d.execute(id);
}

#[test]
#[should_panic(expected = "Proposal is not approved")]
fn pending_proposal_does_not_execute() {
    let mut d = dao(&["m1.testnet", "m2.testnet", "m3.testnet"], 0);
    at(a("m1.testnet"), 0);
    let id = d.propose(GovAction::SetDelay { seconds: 5 });
    let _ = d.execute(id);
}

#[test]
#[should_panic(expected = "Proposal is not approved")]
fn an_executed_proposal_does_not_execute_again() {
    let mut d = dao(&["m1.testnet"], 0);
    at(a("m1.testnet"), 0);
    let id = d.propose(GovAction::SetDelay { seconds: 5 });
    let _ = d.execute(id);
    let _ = d.execute(id);
}

#[test]
fn threshold_and_electorate_are_fixed_when_the_proposal_is_created() {
    let mut d = dao(&["m1.testnet", "m2.testnet", "m3.testnet"], 0);
    assert_eq!(d.approval_threshold, 2);
    at(a("m1.testnet"), 0);
    let id = d.propose(GovAction::SetDelay { seconds: 5 });

    // Members change while the ballot is open (as an executed AddMember would).
    d.dao_members.insert(&a("m4.testnet"));
    d.dao_members.insert(&a("m5.testnet"));
    d.approval_threshold = (d.dao_members.len() as u32 / 2) + 1;
    assert_eq!(d.approval_threshold, 3);

    at(a("m2.testnet"), 0);
    d.vote(id, true, None);
    // 2 of the snapshot threshold 2, not 2 of the current 3.
    assert_eq!(status(&d, id), GovStatus::Approved);
}

#[test]
#[should_panic(expected = "Not in this proposal's electorate")]
fn a_member_added_after_the_proposal_cannot_vote_on_it() {
    let mut d = dao(&["m1.testnet", "m2.testnet", "m3.testnet"], 0);
    at(a("m1.testnet"), 0);
    let id = d.propose(GovAction::SetDelay { seconds: 5 });
    d.dao_members.insert(&a("m4.testnet"));
    at(a("m4.testnet"), 0);
    d.vote(id, true, None);
}

#[test]
fn a_removed_members_vote_stops_counting() {
    let mut d = dao(&["m1.testnet", "m2.testnet", "m3.testnet"], 0);
    at(a("m1.testnet"), 0);
    let id = d.propose(GovAction::SetDelay { seconds: 5 });
    d.dao_members.remove(&a("m1.testnet"));
    d.approval_threshold = (d.dao_members.len() as u32 / 2) + 1;

    at(a("m2.testnet"), 0);
    d.vote(id, true, None);
    assert_eq!(status(&d, id), GovStatus::Pending, "m1's vote no longer counts");
    at(a("m3.testnet"), 0);
    d.vote(id, true, None);
    assert_eq!(status(&d, id), GovStatus::Approved);
}

#[test]
#[should_panic(expected = "Only DAO members can vote")]
fn a_removed_member_cannot_vote() {
    let mut d = dao(&["m1.testnet", "m2.testnet", "m3.testnet"], 0);
    at(a("m1.testnet"), 0);
    let id = d.propose(GovAction::SetDelay { seconds: 5 });
    d.dao_members.remove(&a("m2.testnet"));
    at(a("m2.testnet"), 0);
    d.vote(id, true, None);
}

#[test]
fn a_majority_against_rejects() {
    let mut d = dao(&["m1.testnet", "m2.testnet", "m3.testnet"], 0);
    at(a("m1.testnet"), 0);
    let id = d.propose(GovAction::SetDelay { seconds: 5 });
    at(a("m2.testnet"), 0);
    d.vote(id, false, None);
    assert_eq!(status(&d, id), GovStatus::Pending);
    at(a("m3.testnet"), 0);
    d.vote(id, false, None);
    assert_eq!(status(&d, id), GovStatus::Rejected);
}

#[test]
#[should_panic(expected = "Already voted")]
fn double_vote_panics() {
    let mut d = dao(&["m1.testnet", "m2.testnet", "m3.testnet"], 0);
    at(a("m1.testnet"), 0);
    let id = d.propose(GovAction::SetDelay { seconds: 5 });
    d.vote(id, true, None);
}

// ===== action validation =====

#[test]
#[should_panic(expected = "cannot target this contract")]
fn call_cannot_target_the_dao_itself() {
    let mut d = dao(&["m1.testnet"], 0);
    at(a("m1.testnet"), 0);
    d.propose(GovAction::Call {
        target: dao_id(),
        method: "request_key".into(),
        args: Base64VecU8(b"{}".to_vec()),
        deposit: U128(0),
        gas_tgas: 50,
    });
}

#[test]
#[should_panic(expected = "cannot target the MPC contract")]
fn call_cannot_target_the_mpc_contract() {
    let mut d = dao(&["m1.testnet"], 0);
    at(a("m1.testnet"), 0);
    d.propose(GovAction::Call {
        target: a("v1.signer-prod.testnet"),
        method: "request_app_private_key".into(),
        args: Base64VecU8(b"{}".to_vec()),
        deposit: U128(1),
        gas_tgas: 50,
    });
}

#[test]
#[should_panic(expected = "gas_tgas must be in")]
fn call_gas_is_bounded() {
    let mut d = dao(&["m1.testnet"], 0);
    at(a("m1.testnet"), 0);
    d.propose(GovAction::Call {
        target: a("outlayer.testnet"),
        method: "set_operator".into(),
        args: Base64VecU8(b"{}".to_vec()),
        deposit: U128(0),
        gas_tgas: 251,
    });
}

#[test]
#[should_panic(expected = "Delay must be at most")]
fn delay_is_bounded() {
    let mut d = dao(&["m1.testnet"], 0);
    at(a("m1.testnet"), 0);
    d.propose(GovAction::SetDelay { seconds: governance::MAX_GOV_DELAY_SEC + 1 });
}

#[test]
#[should_panic(expected = "Cannot remove the last DAO member")]
fn the_last_member_cannot_be_removed() {
    let mut d = dao(&["m1.testnet"], 0);
    at(a("m1.testnet"), 0);
    d.propose(GovAction::RemoveMember { member: a("m1.testnet") });
}

#[test]
fn members_change_only_by_vote_and_the_threshold_follows() {
    let mut d = dao(&["m1.testnet"], 0);
    at(a("m1.testnet"), 0);
    for m in ["m2.testnet", "m3.testnet"] {
        let id = d.propose(GovAction::AddMember { member: a(m) });
        if status(&d, id) == GovStatus::Pending {
            at(a("m2.testnet"), 0);
            d.vote(id, true, None);
            at(a("m1.testnet"), 0);
        }
        let _ = d.execute(id);
    }
    assert_eq!(d.get_dao_members().len(), 3);
    assert_eq!(d.approval_threshold, 2);

    let id = d.propose(GovAction::RemoveMember { member: a("m3.testnet") });
    at(a("m2.testnet"), 0);
    d.vote(id, true, None);
    let _ = d.execute(id);
    assert_eq!(d.get_dao_members().len(), 2);
    assert_eq!(d.approval_threshold, 2);
}

#[test]
fn set_owner_and_set_delay_apply_on_execute() {
    let mut d = dao(&["m1.testnet"], 0);
    at(a("m1.testnet"), 0);
    let id = d.propose(GovAction::SetOwner { owner: a("new-owner.testnet") });
    let _ = d.execute(id);
    assert_eq!(d.get_owner(), a("new-owner.testnet"));
    let id = d.propose(GovAction::SetDelay { seconds: 7_200 });
    let _ = d.execute(id);
    assert_eq!(d.get_gov_delay_sec(), 7_200);
}

#[test]
fn measurements_are_no_longer_proposed() {
    let mut d = dao(&["m1.testnet"], 0);
    at(a("m1.testnet"), 0);
    for action in [
        GovAction::ApproveMeasurements { measurements: measurements('a') },
        GovAction::RevokeMeasurements { measurements: measurements('a') },
    ] {
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| d.propose(action)));
        assert!(r.is_err(), "a measurements proposal is refused");
    }
}

/// One made before they were retired still reads, and no longer executes: it expires.
#[test]
#[should_panic(expected = "propose ApproveOsImage and ApproveCompose")]
fn a_stored_measurements_proposal_no_longer_executes() {
    let mut d = dao(&["m1.testnet"], 0);
    at(a("m1.testnet"), 0);
    let id = d.propose(GovAction::SetDelay { seconds: 0 });
    let mut p = d.get_gov_proposal(id).unwrap();
    p.action = GovAction::ApproveMeasurements { measurements: measurements('a') };
    d.gov_proposals.insert(&id, &governance::VersionedGovProposal::V1(p));
    assert!(d.get_gov_proposal(id).is_some(), "it reads");
    let _ = d.execute(id);
}

// ===== the owner: a brake, never an accelerator =====

#[test]
fn owner_cancels_a_pending_and_an_approved_proposal() {
    let mut d = dao(&["m1.testnet", "m2.testnet", "m3.testnet"], 3_600);
    at(a("m1.testnet"), 0);
    let pending = d.propose(GovAction::SetDelay { seconds: 1 });
    let approved = d.propose(GovAction::SetDelay { seconds: 2 });
    at(a("m2.testnet"), 0);
    d.vote(approved, true, None);
    assert_eq!(status(&d, approved), GovStatus::Approved);

    at(owner(), 0);
    d.cancel(pending);
    d.cancel(approved);
    assert_eq!(status(&d, pending), GovStatus::Cancelled);
    assert_eq!(status(&d, approved), GovStatus::Cancelled);
}

#[test]
#[should_panic(expected = "Only owner")]
fn a_member_cannot_cancel() {
    let mut d = dao(&["m1.testnet", "m2.testnet", "m3.testnet"], 0);
    at(a("m1.testnet"), 0);
    let id = d.propose(GovAction::SetDelay { seconds: 1 });
    d.cancel(id);
}

#[test]
#[should_panic(expected = "cannot be cancelled by the owner")]
fn the_owner_cannot_cancel_its_own_replacement() {
    let mut d = dao(&["m1.testnet", "m2.testnet", "m3.testnet"], 0);
    at(a("m1.testnet"), 0);
    let id = d.propose(GovAction::SetOwner { owner: a("new-owner.testnet") });
    at(owner(), 0);
    d.cancel(id);
}

fn cancel_call_as_owner(method: &str) {
    let mut d = dao(&["m1.testnet", "m2.testnet", "m3.testnet"], 0);
    at(a("m1.testnet"), 0);
    let id = d.propose(GovAction::Call {
        target: a("outlayer.testnet"),
        method: method.into(),
        args: Base64VecU8(br#"{"new_owner_id":"new-owner.testnet"}"#.to_vec()),
        deposit: U128(0),
        gas_tgas: 30,
    });
    at(owner(), 0);
    d.cancel(id);
}

#[test]
#[should_panic(expected = "cannot be cancelled by the owner")]
fn the_owner_cannot_cancel_a_call_to_set_owner() {
    cancel_call_as_owner("set_owner");
}

#[test]
#[should_panic(expected = "cannot be cancelled by the owner")]
fn the_owner_cannot_cancel_a_call_to_set_governance() {
    cancel_call_as_owner("set_governance");
}

#[test]
#[should_panic(expected = "revocation of a worker build or key cannot be cancelled by the owner")]
fn the_owner_cannot_cancel_a_call_to_remove_approved_measurements() {
    cancel_call_as_owner("remove_approved_measurements");
}

#[test]
#[should_panic(expected = "revocation of a worker build or key cannot be cancelled by the owner")]
fn the_owner_cannot_cancel_a_call_to_clear_all_approved_measurements() {
    cancel_call_as_owner("clear_all_approved_measurements");
}

#[test]
#[should_panic(expected = "revocation of a worker build or key cannot be cancelled by the owner")]
fn the_owner_cannot_cancel_a_call_to_remove_worker_keys() {
    cancel_call_as_owner("remove_worker_keys");
}

#[test]
fn the_owner_still_cancels_an_ordinary_call() {
    let mut d = dao(&["m1.testnet", "m2.testnet", "m3.testnet"], 0);
    at(a("m1.testnet"), 0);
    let id = d.propose(GovAction::Call {
        target: a("outlayer.testnet"),
        method: "set_payment_token_contract".into(),
        args: Base64VecU8(b"{}".to_vec()),
        deposit: U128(0),
        gas_tgas: 30,
    });
    at(owner(), 0);
    d.cancel(id);
    assert_eq!(status(&d, id), GovStatus::Cancelled);
}

#[test]
#[should_panic(expected = "Only a pending or approved proposal")]
fn an_executed_proposal_cannot_be_cancelled() {
    let mut d = dao(&["m1.testnet"], 0);
    at(a("m1.testnet"), 0);
    let id = d.propose(GovAction::SetDelay { seconds: 1 });
    let _ = d.execute(id);
    at(owner(), 0);
    d.cancel(id);
}

// ===== upgrades and blobs =====

#[test]
fn an_upgrade_is_executed_at_once_and_its_blob_is_dropped() {
    let mut d = dao(&["m1.testnet"], 0);
    let h = blob(&mut d, 6);
    let id = d.propose(GovAction::Upgrade { target: a("outlayer.testnet"), code_hash: h, migrate: true });
    assert!(matches!(d.execute(id), PromiseOrValue::Promise(_)));
    assert_eq!(status(&d, id), GovStatus::Executed, "no in-flight state: Executed as dispatched");
    assert!(d.get_blob(h).is_none());
    assert!(env::storage_read(&[b"blob:".as_slice(), &<[u8; 32]>::from(h)].concat()).is_none());
}

#[test]
fn another_contract_upgrades_while_other_proposals_are_open() {
    let mut d = dao(&["m1.testnet"], 0);
    let h = blob(&mut d, 8);
    d.propose(GovAction::SetDelay { seconds: 1 }); // approved, not executed: still open
    let up = d.propose(GovAction::Upgrade { target: a("worker.testnet"), code_hash: h, migrate: false });
    assert!(matches!(d.execute(up), PromiseOrValue::Promise(_)));
}

#[test]
fn a_blob_is_stored_under_its_sha256_and_pays_its_storage() {
    let mut d = dao(&["m1.testnet"], 0);
    let code = vec![9u8; 1_000];
    let h = store_as(&mut d, "m1.testnet", &code);
    assert_eq!(h, Base58CryptoHash::from(env::sha256_array(&code)));
    let info = d.get_blob(h).unwrap();
    assert_eq!(info.storer, a("m1.testnet"));
    assert_eq!(info.size, 1_000);
    assert!(info.deposit.0 >= 1_000 * 10u128.pow(19), "at least the bytes' storage");
}

#[test]
#[should_panic(expected = "only DAO members")]
fn only_a_member_stores_a_blob() {
    let mut d = dao(&["m1.testnet"], 0);
    store_as(&mut d, "stranger.testnet", &[1u8; 64]);
}

#[test]
#[should_panic(expected = "already stored")]
fn the_same_blob_is_stored_once() {
    let mut d = dao(&["m1.testnet"], 0);
    blob(&mut d, 1);
    blob(&mut d, 1);
}

#[test]
#[should_panic(expected = "Attach")]
fn a_blob_without_its_deposit_is_refused() {
    let mut d = dao(&["m1.testnet"], 0);
    let mut b = ctx(a("m1.testnet"));
    b.context.input = std::rc::Rc::from(vec![1u8; 64].into_boxed_slice());
    testing_env!(b.build());
    d.store_blob();
}

#[test]
#[should_panic(expected = "No blob")]
fn an_upgrade_names_a_stored_blob() {
    let mut d = dao(&["m1.testnet"], 0);
    at(a("m1.testnet"), 0);
    d.propose(GovAction::Upgrade {
        target: dao_id(),
        code_hash: Base58CryptoHash::from([1u8; 32]),
        migrate: false,
    });
}

#[test]
fn the_storer_removes_a_blob() {
    let mut d = dao(&["m1.testnet"], 0);
    let h = blob(&mut d, 4);
    d.remove_blob(h);
    assert!(d.get_blob(h).is_none());
}

#[test]
#[should_panic(expected = "Only the member who stored the blob")]
fn only_the_storer_removes_a_blob() {
    let mut d = dao(&["m1.testnet", "m2.testnet"], 0);
    let h = blob(&mut d, 4);
    at(a("m2.testnet"), 0);
    d.remove_blob(h);
}

#[test]
#[should_panic(expected = "No blob")]
fn a_removed_blob_cannot_be_executed() {
    let mut d = dao(&["m1.testnet"], 0);
    let h = blob(&mut d, 5);
    let id = d.propose(GovAction::Upgrade { target: a("outlayer.testnet"), code_hash: h, migrate: false });
    d.remove_blob(h);
    let _ = d.execute(id);
}

// ===== keystore keys: only DAO-installed keys reach the master =====

#[test]
#[should_panic(expected = "signer key is not an approved keystore key")]
fn request_key_refuses_a_key_outside_approved_keystores() {
    let d = dao(&["m1.testnet"], 0);
    // e.g. a full-access key on the DAO account: predecessor is the DAO, the signer is not
    // a keystore key.
    testing_env!(ctx(dao_id()).signer_account_pk(key(9)).build());
    let _ = d.request_key(CKDRequestArgs {
        derivation_path: String::new(),
        app_public_key: dtos::Bls12381G1PublicKey("k".into()),
        domain_id: DomainId(2),
    });
}

#[test]
fn request_key_accepts_an_approved_keystore_key() {
    let mut d = dao(&["m1.testnet"], 0);
    d.approved_keystores.insert(&key(9));
    testing_env!(ctx(dao_id()).signer_account_pk(key(9)).build());
    assert!(matches!(
        d.request_key(CKDRequestArgs {
            derivation_path: String::new(),
            app_public_key: dtos::Bls12381G1PublicKey("k".into()),
            domain_id: DomainId(2),
        }),
        PromiseOrValue::Promise(_)
    ));
}

#[test]
#[should_panic(expected = "only an approved keystore")]
fn ban_vault_refuses_a_self_call_with_an_unapproved_key() {
    let mut d = dao(&["m1.testnet"], 0);
    testing_env!(ctx(dao_id()).signer_account_pk(key(9)).build());
    d.ban_vault(a("vault.alice.testnet"), "x".into());
}

#[test]
#[should_panic(expected = "signer key is not an approved keystore key")]
fn mark_vault_verified_refuses_an_unapproved_key() {
    let mut d = dao(&["m1.testnet"], 0);
    testing_env!(ctx(dao_id()).signer_account_pk(key(9)).build());
    d.mark_vault_verified(a("vault.alice.testnet"));
}

// ===== stale registration proposals =====

fn pending_registration(d: &mut KeystoreDao, id: u64, created_at: u64) {
    d.proposals.insert(
        &id,
        &KeystoreProposal {
            id,
            public_key: key(id as u8),
            measurements: measurements('e'),
            submitter: a("init.testnet"),
            created_at,
            votes_for: 0,
            votes_against: 0,
            status: ProposalStatus::Pending,
        },
    );
}

#[test]
fn the_owner_deletes_registrations_pending_for_more_than_two_days() {
    let mut d = dao(&["m1.testnet"], 0);
    pending_registration(&mut d, 1, 0);
    pending_registration(&mut d, 2, 20 * HOUR_NS);
    let mut done = d.proposals.get(&1).unwrap();
    done.id = 3;
    done.status = ProposalStatus::Executed;
    d.proposals.insert(&3, &done);

    at(owner(), 49 * HOUR_NS);
    assert_eq!(d.remove_stale_proposals(vec![1, 2, 3, 99]), 1);
    assert!(d.get_proposal(1).is_none(), "pending for 49 h: deleted");
    assert!(d.get_proposal(2).is_some(), "pending for 29 h: kept, within the margin");
    assert!(d.get_proposal(3).is_some(), "not pending: kept");
}

#[test]
#[should_panic(expected = "Only owner")]
fn only_the_owner_deletes_stale_registrations() {
    let mut d = dao(&["m1.testnet"], 0);
    at(a("m1.testnet"), 0);
    d.remove_stale_proposals(vec![1]);
}

/// A registration stored before registrations carried their event log states no build: a quorum
/// on it installs nothing.
#[test]
fn a_registration_that_states_no_build_gets_no_key_at_quorum() {
    let mut d = dao(&["m1.testnet", "m2.testnet", "m3.testnet"], 0);
    KeystoreDao::set_os_images(&vec![OsImage::of(&measurements('e'))]);
    pending_registration(&mut d, 1, 0);
    at(a("m1.testnet"), 0);
    d.vote(1, true, Some(key(1)));
    at(a("m2.testnet"), 0);
    d.vote(1, true, Some(key(1)));
    assert_eq!(d.get_proposal(1).unwrap().status, ProposalStatus::Rejected);
    assert!(!d.is_keystore_approved(String::from(&key(1))));
    assert!(get_created_receipts().is_empty(), "no key is added");
}

#[test]
fn the_owner_rejects_a_pending_registration_and_no_vote_installs_it() {
    let mut d = dao(&["m1.testnet", "m2.testnet", "m3.testnet"], 0);
    pending_registration(&mut d, 1, 0);
    at(owner(), 0);
    d.reject_registration(1);
    assert_eq!(d.get_proposal(1).unwrap().status, ProposalStatus::Rejected);
    at(a("m1.testnet"), 0);
    let voted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| d.vote(1, true, Some(key(1)))));
    assert!(voted.is_err(), "a rejected registration takes no votes");
    assert!(!d.is_keystore_approved(String::from(&key(1))));
}

#[test]
#[should_panic(expected = "Only owner")]
fn only_the_owner_rejects_a_registration() {
    let mut d = dao(&["m1.testnet"], 0);
    pending_registration(&mut d, 1, 0);
    at(a("m1.testnet"), 0);
    d.reject_registration(1);
}

#[test]
#[should_panic(expected = "Only a pending registration can be rejected")]
fn an_executed_registration_cannot_be_rejected() {
    let mut d = dao(&["m1.testnet"], 0);
    pending_registration(&mut d, 1, 0);
    let mut p = d.proposals.get(&1).unwrap();
    p.status = ProposalStatus::Executed;
    d.proposals.insert(&1, &p);
    at(owner(), 0);
    d.reject_registration(1);
}

#[test]
#[should_panic(expected = "Registration proposal not found")]
fn reject_registration_does_not_reach_a_governance_proposal() {
    let mut d = dao(&["m1.testnet"], 0);
    at(a("m1.testnet"), 0);
    let id = d.propose(GovAction::SetDelay { seconds: 5 });
    at(owner(), 0);
    d.reject_registration(id);
}

// ===== collateral =====

#[test]
fn collateral_up_to_the_bound_is_stored() {
    let mut d = dao(&["m1.testnet"], 0);
    at(owner(), 0);
    d.update_collateral("c".repeat(128 * 1024), 0);
    assert_eq!(d.get_collaterals()[0].len(), 128 * 1024);
}

#[test]
#[should_panic(expected = "collateral must be at most")]
fn collateral_above_the_bound_is_refused() {
    let mut d = dao(&["m1.testnet"], 0);
    at(owner(), 0);
    d.update_collateral("c".repeat(128 * 1024 + 1), 0);
}

// ===== roles: the newer decision wins =====

#[test]
#[should_panic(expected = "which already changed it")]
fn an_older_delay_change_does_not_undo_a_newer_one() {
    let mut d = dao(&["m1.testnet"], 0);
    at(a("m1.testnet"), 0);
    let older = d.propose(GovAction::SetDelay { seconds: 0 });
    let newer = d.propose(GovAction::SetDelay { seconds: 259_200 });
    let _ = d.execute(newer);
    assert_eq!(d.get_gov_delay_sec(), 259_200);
    let _ = d.execute(older);
}

#[test]
#[should_panic(expected = "raises the delay cannot be cancelled by the owner")]
fn the_owner_cannot_cancel_a_raise_of_the_delay() {
    let mut d = dao(&["m1.testnet", "m2.testnet"], 600);
    at(a("m1.testnet"), 0);
    let p = d.propose(GovAction::SetDelay { seconds: 259_200 });
    at(a("owner.testnet"), 0);
    d.cancel(p);
}

#[test]
fn the_owner_cancels_a_delay_that_does_not_rise() {
    let mut d = dao(&["m1.testnet", "m2.testnet"], 600);
    at(a("m1.testnet"), 0);
    let lower = d.propose(GovAction::SetDelay { seconds: 0 });
    let same = d.propose(GovAction::SetDelay { seconds: 600 });
    at(a("owner.testnet"), 0);
    d.cancel(lower);
    d.cancel(same);
}

#[test]
fn an_older_approved_owner_change_does_not_execute_after_a_newer_one() {
    let mut d = dao(&["m1.testnet"], 0);
    at(a("m1.testnet"), 0);
    let first = d.propose(GovAction::SetOwner { owner: a("y.testnet") });
    let duplicate = d.propose(GovAction::SetOwner { owner: a("y.testnet") });
    let _ = d.execute(first);
    assert_eq!(d.get_owner(), a("y.testnet"));
    let later = d.propose(GovAction::SetOwner { owner: a("z.testnet") });
    let _ = d.execute(later);
    assert_eq!(d.get_owner(), a("z.testnet"));

    let stale = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| d.execute(duplicate)));
    assert!(stale.is_err(), "the duplicate is older than the change that executed");
    assert_eq!(d.get_owner(), a("z.testnet"));
    assert_eq!(d.get_last_role_change("set_owner:dao.testnet".into()), Some(later));
}

#[test]
fn of_two_open_owner_changes_the_newer_one_still_executes_after_the_older() {
    let mut d = dao(&["m1.testnet"], 0);
    at(a("m1.testnet"), 0);
    let older = d.propose(GovAction::SetOwner { owner: a("y.testnet") });
    let newer = d.propose(GovAction::SetOwner { owner: a("z.testnet") });
    let _ = d.execute(older);
    let _ = d.execute(newer);
    assert_eq!(d.get_owner(), a("z.testnet"));
}

#[test]
#[should_panic(expected = "which already changed it")]
fn an_older_owner_change_does_not_undo_a_newer_one() {
    let mut d = dao(&["m1.testnet"], 0);
    at(a("m1.testnet"), 0);
    let older = d.propose(GovAction::SetOwner { owner: a("y.testnet") });
    let newer = d.propose(GovAction::SetOwner { owner: a("z.testnet") });
    let _ = d.execute(newer);
    let _ = d.execute(older);
}

#[test]
#[should_panic(expected = "which already changed it")]
fn an_older_call_to_set_owner_on_a_governed_contract_does_not_execute_after_a_newer_one() {
    let mut d = dao(&["m1.testnet"], 0);
    at(a("m1.testnet"), 0);
    let call = |owner: &str| GovAction::Call {
        target: a("outlayer.testnet"),
        method: "set_owner".into(),
        args: Base64VecU8(format!("{{\"owner_id\":\"{}\"}}", owner).into_bytes()),
        deposit: U128(0),
        gas_tgas: 50,
    };
    let older = d.propose(call("y.testnet"));
    let newer = d.propose(call("z.testnet"));
    let _ = d.execute(newer);
    let _ = d.execute(older);
}

#[test]
fn owner_changes_on_different_contracts_do_not_block_each_other() {
    let mut d = dao(&["m1.testnet"], 0);
    at(a("m1.testnet"), 0);
    let call = |target: &str| GovAction::Call {
        target: a(target),
        method: "set_owner".into(),
        args: Base64VecU8(b"{\"owner_id\":\"z.testnet\"}".to_vec()),
        deposit: U128(0),
        gas_tgas: 50,
    };
    let own = d.propose(GovAction::SetOwner { owner: a("z.testnet") });
    let main = d.propose(call("outlayer.testnet"));
    let register = d.propose(call("worker.outlayer.testnet"));
    // An incident replaces the owner of all three; they execute in any order.
    let _ = d.execute(register);
    let _ = d.execute(own);
    let _ = d.execute(main);
    assert_eq!(d.get_owner(), a("z.testnet"));
}

#[test]
#[should_panic(expected = "which already changed it")]
fn an_older_approved_add_member_does_not_bring_back_a_removed_member() {
    let mut d = dao(&["m1.testnet"], 0);
    at(a("m1.testnet"), 0);
    let add = d.propose(GovAction::AddMember { member: a("x.testnet") });
    let add_again = d.propose(GovAction::AddMember { member: a("x.testnet") });
    let _ = d.execute(add);
    let remove = d.propose(GovAction::RemoveMember { member: a("x.testnet") });
    at(a("x.testnet"), 0);
    d.vote(remove, true, None);
    at(a("m1.testnet"), 0);
    let _ = d.execute(remove);
    assert!(!d.get_dao_members().contains(&a("x.testnet")));
    let _ = d.execute(add_again);
}

#[test]
#[should_panic(expected = "The owner cannot be this contract itself")]
fn the_owner_cannot_be_the_dao_itself() {
    let mut d = dao(&["m1.testnet"], 0);
    at(a("m1.testnet"), 0);
    d.propose(GovAction::SetOwner { owner: dao_id() });
}

#[test]
#[should_panic(expected = "An Upgrade proposal cannot target the MPC contract")]
fn an_upgrade_cannot_target_the_mpc_contract() {
    let mut d = dao(&["m1.testnet"], 0);
    let h = blob(&mut d, 7);
    at(a("m1.testnet"), 0);
    d.propose(GovAction::Upgrade { target: a("v1.signer-prod.testnet"), code_hash: h, migrate: false });
}

#[test]
fn a_remote_upgrade_takes_the_gas_execute_leaves() {
    let mut d = dao(&["m1.testnet"], 0);
    let h = blob(&mut d, 7);
    at(a("m1.testnet"), 0);
    let id = d.propose(GovAction::Upgrade { target: a("outlayer.testnet"), code_hash: h, migrate: true });
    let _ = d.execute(id);
    let receipts = get_created_receipts();
    let weight = receipts.iter().flat_map(|r| r.actions.iter()).find_map(|act| match act {
        MockAction::FunctionCallWeight { method_name, gas_weight, .. }
            if method_name == b"upgrade_and_migrate" => Some(gas_weight.0),
        _ => None,
    });
    assert_eq!(weight, Some(1));
}

// ===== migration =====

fn v4_state() -> KeystoreDaoV4 {
    let mut members = near_sdk::collections::UnorderedSet::new(StorageKey::DaoMembers);
    members.insert(&a("zavodil.near"));
    let mut keystores = near_sdk::collections::UnorderedSet::new(StorageKey::ApprovedKeystores);
    keystores.insert(&key(5));
    KeystoreDaoV4 {
        dao_members: members,
        approval_threshold: 1,
        owner_id: a("owner.outlayer.near"),
        init_account_id: a("init-keystore.outlayer.near"),
        mpc_contract_id: a("v1.signer"),
        proposals: near_sdk::collections::LookupMap::new(StorageKey::Proposals),
        next_proposal_id: 50,
        votes: near_sdk::collections::LookupMap::new(StorageKey::Votes { proposal_id: 0 }),
        approved_keystores: keystores,
        approved_measurements: vec![measurements('e')],
        collaterals: vec!["c0".into(), "c1".into()],
        ceased_operations: false,
        approved_vault_code_hashes: near_sdk::collections::UnorderedSet::new(
            StorageKey::ApprovedVaultCodeHashes,
        ),
        vault_versions: near_sdk::collections::LookupMap::new(StorageKey::VaultVersions),
        verified_vaults: near_sdk::collections::UnorderedSet::new(StorageKey::VerifiedVaults),
        banned_vaults: near_sdk::collections::UnorderedSet::new(StorageKey::BannedVaults),
        vault_version_votes: near_sdk::collections::LookupMap::new(StorageKey::VaultVersionVotes),
        vault_version_approval_args: near_sdk::collections::LookupMap::new(
            StorageKey::VaultVersionApprovalArgs,
        ),
        revoke_proposals: near_sdk::collections::LookupMap::new(StorageKey::RevokeProposals),
    }
}

#[test]
fn v4_state_migrates_to_v5_with_every_field_kept() {
    let mut b = VMContextBuilder::new();
    b.current_account_id(a("dao.outlayer.near")).predecessor_account_id(a("dao.outlayer.near"));
    testing_env!(b.build());
    env::state_write(&v4_state());

    let d = KeystoreDao::migrate(None);
    assert_eq!(d.get_dao_members(), vec![a("zavodil.near")]);
    assert_eq!(d.get_owner(), a("owner.outlayer.near"));
    assert_eq!(d.next_proposal_id, 50);
    assert!(d.approved_keystores.contains(&key(5)));
    assert!(d.approved_measurements.is_empty(), "a tuple approved one CVM; builds are OS + compose now");
    assert_eq!(d.get_collaterals(), vec!["c0".to_string(), "c1".to_string()]);
    assert_eq!(d.get_gov_delay_sec(), governance::MAINNET_GOV_DELAY_SEC, ".near starts at 72 h");
}

/// The deploy sets a shorter delay to start with; `SetDelay` raises it later. A delay above the
/// bound is refused, as at `new`.
#[test]
fn migrate_takes_the_delay_it_is_given() {
    let mut b = VMContextBuilder::new();
    b.current_account_id(a("dao.outlayer.near")).predecessor_account_id(a("dao.outlayer.near"));
    testing_env!(b.build());
    env::state_write(&v4_state());
    assert_eq!(KeystoreDao::migrate(Some(600)).get_gov_delay_sec(), 600);
    env::state_write(&v4_state());
    assert_eq!(KeystoreDao::migrate(Some(0)).get_gov_delay_sec(), 0);
}

#[test]
#[should_panic(expected = "gov_delay_sec must be at most")]
fn migrate_refuses_a_delay_above_the_bound() {
    let mut b = VMContextBuilder::new();
    b.current_account_id(a("dao.outlayer.near")).predecessor_account_id(a("dao.outlayer.near"));
    testing_env!(b.build());
    env::state_write(&v4_state());
    KeystoreDao::migrate(Some(governance::MAX_GOV_DELAY_SEC + 1));
}

#[test]
fn a_testnet_account_starts_without_a_delay() {
    testing_env!(ctx(dao_id()).build());
    assert_eq!(KeystoreDao::default_gov_delay_ns(), 0);
}

// ===== run-2: proposals do not live for ever, the deploy re-checks, storage is paid =====

#[test]
#[should_panic(expected = "Attach")]
fn a_proposal_pays_its_storage() {
    let mut d = dao(&["m1.testnet"], 0);
    testing_env!(ctx(a("m1.testnet")).build());
    d.propose(GovAction::SetDelay { seconds: 1 });
}

#[test]
#[should_panic(expected = "args must be at most")]
fn call_args_are_bounded() {
    let mut d = dao(&["m1.testnet"], 0);
    at(a("m1.testnet"), 0);
    d.propose(GovAction::Call {
        target: a("outlayer.testnet"),
        method: "set_operator".into(),
        args: Base64VecU8(vec![b'x'; governance::MAX_CALL_ARGS_BYTES + 1]),
        deposit: U128(0),
        gas_tgas: 30,
    });
}

#[test]
#[should_panic(expected = "Proposal has not expired")]
fn a_pending_proposal_does_not_expire_early() {
    let mut d = dao(&["m1.testnet", "m2.testnet", "m3.testnet"], 0);
    at(a("m1.testnet"), 0);
    let id = d.propose(GovAction::SetDelay { seconds: 1 });
    at(a("m2.testnet"), 14 * DAY_NS);
    d.expire(id);
}

/// The audit's R2-A: an owner replacement nobody is left to vote on, and the owner may not
/// cancel, expires; and the DAO upgrades itself whatever is open.
#[test]
fn an_owner_replacement_nobody_can_vote_on_expires() {
    let mut d = dao(&["m1.testnet", "m2.testnet", "m3.testnet"], 0);
    at(a("m1.testnet"), 0);
    let stuck = d.propose(GovAction::SetOwner { owner: a("new-owner.testnet") });
    // The electorate rotates away (as executed RemoveMember / AddMember would).
    for m in ["m1.testnet", "m2.testnet", "m3.testnet"] {
        d.dao_members.remove(&a(m));
    }
    d.dao_members.insert(&a("m4.testnet"));
    d.approval_threshold = 1;

    let h0 = store_as(&mut d, "m4.testnet", &[2u8; 64]);
    let up0 = d.propose(GovAction::Upgrade { target: dao_id(), code_hash: h0, migrate: false });
    assert!(matches!(d.execute(up0), PromiseOrValue::Promise(_)), "not blocked by the stuck one");

    at(a("m4.testnet"), 14 * DAY_NS + 1);
    d.expire(stuck);
    assert_eq!(status(&d, stuck), GovStatus::Expired);

    let h = store_as(&mut d, "m4.testnet", &[3u8; 64]);
    at(a("m4.testnet"), 14 * DAY_NS + 2);
    let up = d.propose(GovAction::Upgrade { target: dao_id(), code_hash: h, migrate: false });
    assert!(matches!(d.execute(up), PromiseOrValue::Promise(_)));
}

/// The audit's R2-C: an approved proposal cannot be executed long after it was voted for.
#[test]
#[should_panic(expected = "Proposal expired")]
fn an_approved_proposal_cannot_be_executed_after_its_window() {
    let mut d = dao(&["m1.testnet"], 3_600);
    at(a("m1.testnet"), 0);
    let id = d.propose(GovAction::SetOwner { owner: a("y.testnet") });
    at(a("m1.testnet"), HOUR_NS + 7 * DAY_NS + 1);
    let _ = d.execute(id);
}

#[test]
fn an_approved_proposal_past_its_window_expires() {
    let mut d = dao(&["m1.testnet"], 3_600);
    at(a("m1.testnet"), 0);
    let id = d.propose(GovAction::SetOwner { owner: a("y.testnet") });
    at(a("m1.testnet"), HOUR_NS + 7 * DAY_NS + 1);
    d.expire(id);
    assert_eq!(status(&d, id), GovStatus::Expired);
}

/// The self-upgrade batch: deploy, `migrate`, `gov_health` — one receipt, atomic.
#[test]
fn the_self_upgrade_batch_is_deploy_migrate_health() {
    let mut d = dao(&["m1.testnet"], 0);
    let h = blob(&mut d, 9);
    let up = d.propose(GovAction::Upgrade { target: dao_id(), code_hash: h, migrate: true });
    let _ = d.execute(up);
    let methods: Vec<String> = get_created_receipts()
        .iter()
        .filter(|r| r.receiver_id == dao_id())
        .flat_map(|r| r.actions.iter())
        .filter_map(|a| match a {
            MockAction::FunctionCallWeight { method_name, .. } => {
                Some(String::from_utf8(method_name.clone()).unwrap())
            }
            _ => None,
        })
        .collect();
    assert_eq!(methods, vec!["migrate", "gov_health"]);
}


// ===== run-2 follow-up: versioned proposals, no Call upgrades, operator replacement =====

#[test]
fn a_proposal_is_stored_as_v1_and_reads_back() {
    let mut d = dao(&["m1.testnet"], 0);
    at(a("m1.testnet"), 0);
    let id = d.propose(GovAction::SetDelay { seconds: 9 });
    match d.gov_proposals.get(&id).unwrap() {
        governance::VersionedGovProposal::V1(p) => assert_eq!(p.id, id),
    }
    assert_eq!(d.get_gov_proposal(id).unwrap().action, GovAction::SetDelay { seconds: 9 });
}

#[test]
fn the_dao_upgrades_itself_while_other_proposals_are_open() {
    let mut d = dao(&["m1.testnet", "m2.testnet", "m3.testnet"], 0);
    let h = blob(&mut d, 7);
    let up = d.propose(GovAction::Upgrade { target: dao_id(), code_hash: h, migrate: false });
    let _other = d.propose(GovAction::SetDelay { seconds: 1 });
    at(a("m2.testnet"), 0);
    d.vote(up, true, None);
    assert!(matches!(d.execute(up), PromiseOrValue::Promise(_)));
    assert_eq!(status(&d, up), GovStatus::Executed);
}

fn propose_call(method: &str) -> (KeystoreDao, u64) {
    let mut d = dao(&["m1.testnet", "m2.testnet", "m3.testnet"], 0);
    at(a("m1.testnet"), 0);
    let id = d.propose(GovAction::Call {
        target: a("outlayer.testnet"),
        method: method.into(),
        args: Base64VecU8(b"{}".to_vec()),
        deposit: U128(0),
        gas_tgas: 30,
    });
    (d, id)
}

#[test]
#[should_panic(expected = "Upgrade a contract with an Upgrade proposal")]
fn a_call_cannot_upgrade() {
    propose_call("upgrade");
}

#[test]
#[should_panic(expected = "Upgrade a contract with an Upgrade proposal")]
fn a_call_cannot_upgrade_and_migrate() {
    propose_call("upgrade_and_migrate");
}

#[test]
#[should_panic(expected = "cannot be cancelled by the owner")]
fn the_owner_cannot_cancel_an_operator_replacement() {
    let (mut d, id) = propose_call("set_operator");
    at(owner(), 0);
    d.cancel(id);
}

/// The audit's R3-A: a pending proposal past its time takes no votes, so old votes plus one
/// stolen key cannot approve it months later.
#[test]
#[should_panic(expected = "Proposal expired: it takes no more votes")]
fn an_expired_pending_proposal_takes_no_votes() {
    let mut d = dao(&["m1.testnet", "m2.testnet", "m3.testnet"], 0);
    at(a("m1.testnet"), 0);
    let id = d.propose(GovAction::SetOwner { owner: a("attacker.testnet") });
    at(a("m2.testnet"), 60 * DAY_NS);
    d.vote(id, true, None);
}

#[test]
fn a_pending_proposal_takes_votes_until_its_ttl() {
    let mut d = dao(&["m1.testnet", "m2.testnet", "m3.testnet"], 0);
    at(a("m1.testnet"), 0);
    let id = d.propose(GovAction::SetDelay { seconds: 1 });
    at(a("m2.testnet"), 14 * DAY_NS);
    d.vote(id, true, None);
    assert_eq!(status(&d, id), GovStatus::Approved);
}

// ===== registrations with a boot event log, and votes that name the key =====

const COMPOSE: &str = "cfcba6acbf261f883b9f380c49c1401917f5f4e8c46007cf2cb027d1ddb010be";

fn boot_log(instance: char) -> Vec<event_log::EventLogEntry> {
    event_log::tests::boot_log(COMPOSE, &instance.to_string().repeat(40))
}

/// The measurements of the TD whose RTMR3 events are `log`, under guest OS `os`.
fn measured_on(os: char, log: &[event_log::EventLogEntry]) -> ApprovedMeasurements {
    let mut m = measurements(os);
    m.rtmr3 = event_log::replay(log).unwrap().0;
    m
}
fn measured(log: &[event_log::EventLogEntry]) -> ApprovedMeasurements {
    measured_on('a', log)
}

/// A DAO where governance has approved guest OS 'a' and the compose `COMPOSE`.
fn dao_with_build(members: &[&str]) -> KeystoreDao {
    let d = dao(members, 0);
    KeystoreDao::set_os_images(&vec![OsImage::of(&measurements('a'))]);
    KeystoreDao::set_composes(&vec![COMPOSE.to_string()]);
    d
}

/// Register key `byte` from the init account, its quote verified: `report_data` binds the key.
fn register(d: &mut KeystoreDao, byte: u8, m: ApprovedMeasurements, log: Vec<event_log::EventLogEntry>) -> u64 {
    at(a("init.testnet"), 0);
    d.internal_register(key(byte), m, [byte; 32], log)
}

fn refused(f: impl FnOnce()) -> bool {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).is_err()
}

#[test]
fn a_registration_with_its_event_log_states_its_compose_and_instance() {
    let mut d = dao_with_build(&["m1.testnet", "m2.testnet", "m3.testnet"]);
    let log = boot_log('1');
    let id = register(&mut d, 7, measured(&log), log);

    assert_eq!(d.get_proposal(id).unwrap().status, ProposalStatus::Pending);
    let facts = d.get_registration_facts(id).unwrap();
    assert_eq!(facts.compose_hash, COMPOSE);
    assert_eq!(facts.instance_id, "1".repeat(40));
}

#[test]
fn the_quorum_installs_the_key_and_approves_no_measurements() {
    let mut d = dao_with_build(&["m1.testnet", "m2.testnet", "m3.testnet"]);
    let log = boot_log('1');
    let m = measured(&log);
    let id = register(&mut d, 7, m.clone(), log);

    at(a("m1.testnet"), 0);
    d.vote(id, true, Some(key(7)));
    assert!(!d.is_keystore_approved(String::from(&key(7))), "one vote of two installs nothing");
    at(a("m2.testnet"), 0);
    d.vote(id, true, Some(key(7)));

    assert_eq!(d.get_proposal(id).unwrap().status, ProposalStatus::Executed);
    assert!(d.is_keystore_approved(String::from(&key(7))));
    // The instance's RTMR3 is not a build and is recorded as nothing.
    assert!(d.approved_measurements.is_empty());
    let _ = m;
}

#[test]
#[should_panic(expected = "Guest OS not approved")]
fn an_event_log_under_a_guest_os_governance_did_not_approve_is_refused() {
    // RTMR3 is written by the guest: under an unknown OS anyone can extend it with a real
    // keystore's public event log and "state" its compose and instance.
    let mut d = dao_with_build(&["m1.testnet"]);
    let log = boot_log('1');
    register(&mut d, 7, measured_on('b', &log), log);
}

#[test]
#[should_panic(expected = "Compose not approved")]
fn a_compose_governance_did_not_approve_is_refused() {
    let mut d = dao_with_build(&["m1.testnet"]);
    let other = event_log::tests::boot_log(&"ee".repeat(32), &"1".repeat(40));
    register(&mut d, 7, measured(&other), other);
}

#[test]
fn the_build_is_approved_and_revoked_by_governance_and_removed_by_the_owner() {
    let mut d = dao(&["m1.testnet"], 0);
    let os = OsImage::of(&measurements('a'));
    let log = boot_log('1');
    assert!(refused(|| { register(&mut d, 7, measured(&log), log.clone()); }));

    at(a("m1.testnet"), 0);
    let p = d.propose(GovAction::ApproveOsImage { image: os.clone() });
    let _ = d.execute(p);
    let p = d.propose(GovAction::ApproveCompose { compose_hash: COMPOSE.to_uppercase() });
    let _ = d.execute(p);
    assert_eq!(d.get_approved_os_images(), vec![os.clone()]);
    assert_eq!(d.get_approved_composes(), vec![COMPOSE.to_string()], "stored lowercase");
    assert!(d.is_build_approved(measured(&log), COMPOSE.to_string()));
    let id = register(&mut d, 7, measured(&log), log.clone());
    assert_eq!(d.get_proposal(id).unwrap().status, ProposalStatus::Pending);

    at(owner(), 0);
    d.remove_approved_compose(COMPOSE.to_string());
    assert!(!d.is_build_approved(measured(&log), COMPOSE.to_string()));
    assert!(refused(|| { register(&mut d, 8, measured(&log), log.clone()); }));

    at(a("m1.testnet"), 0);
    let p = d.propose(GovAction::ApproveCompose { compose_hash: COMPOSE.to_string() });
    let _ = d.execute(p);
    let p = d.propose(GovAction::RevokeOsImage { image: os });
    let _ = d.execute(p);
    assert!(d.get_approved_os_images().is_empty());
    assert!(refused(|| { register(&mut d, 8, measured(&log), log); }));
}

fn wallet_code(byte: u8) -> Base58CryptoHash {
    Base58CryptoHash::from([byte; 32])
}

#[test]
fn a_wallet_contract_build_is_approved_and_revoked_by_governance_and_removed_by_the_owner() {
    let mut d = dao(&["m1.testnet"], 0);
    assert!(d.get_approved_wallet_contracts().is_empty());

    at(a("m1.testnet"), 0);
    for byte in [1, 2, 1] {
        let p = d.propose(GovAction::ApproveWalletContract { code_hash: wallet_code(byte) });
        let _ = d.execute(p);
    }
    // a later build stands beside the earlier one, each once, as NEAR spells a code hash
    assert_eq!(
        d.get_approved_wallet_contracts(),
        vec![String::from(&wallet_code(1)), String::from(&wallet_code(2))]
    );
    assert_eq!(String::from(&wallet_code(1)), "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi");

    let p = d.propose(GovAction::RevokeWalletContract { code_hash: wallet_code(1) });
    let _ = d.execute(p);
    assert_eq!(d.get_approved_wallet_contracts(), vec![String::from(&wallet_code(2))]);

    at(owner(), 0);
    d.remove_approved_wallet_contract(wallet_code(2));
    assert!(d.get_approved_wallet_contracts().is_empty());
}

#[test]
fn a_wallet_contract_build_waits_out_the_delay() {
    let mut d = dao(&["m1.testnet"], 3_600);
    at(a("m1.testnet"), 10);
    let id = d.propose(GovAction::ApproveWalletContract { code_hash: wallet_code(1) });
    assert!(refused(|| { let _ = d.execute(id); }));
    assert!(d.get_approved_wallet_contracts().is_empty());
}

#[test]
#[should_panic(expected = "Only owner")]
fn only_the_owner_removes_an_approved_wallet_contract() {
    let mut d = dao(&["m1.testnet"], 0);
    at(a("m1.testnet"), 0);
    d.remove_approved_wallet_contract(wallet_code(1));
}

#[test]
#[should_panic(expected = "Only owner")]
fn only_the_owner_removes_an_approved_compose() {
    let mut d = dao_with_build(&["m1.testnet"]);
    at(a("m1.testnet"), 0);
    d.remove_approved_compose(COMPOSE.to_string());
}

#[test]
#[should_panic(expected = "compose_hash must be 64 hex characters")]
fn a_compose_proposal_takes_a_sha256() {
    let mut d = dao(&["m1.testnet"], 0);
    at(a("m1.testnet"), 0);
    d.propose(GovAction::ApproveCompose { compose_hash: "abc".to_string() });
}

/// One vote in, then the owner takes the build off the list, then the vote that makes quorum.
fn quorum_after_the_owner_removed(remove: impl FnOnce(&mut KeystoreDao)) {
    let mut d = dao_with_build(&["m1.testnet", "m2.testnet", "m3.testnet"]);
    let log = boot_log('1');
    let id = register(&mut d, 7, measured(&log), log);
    at(a("m1.testnet"), 0);
    d.vote(id, true, Some(key(7)));
    at(owner(), 0);
    remove(&mut d);
    at(a("m2.testnet"), 0);
    d.vote(id, true, Some(key(7)));
    assert_eq!(d.get_proposal(id).unwrap().status, ProposalStatus::Rejected);
    assert!(!d.is_keystore_approved(String::from(&key(7))));
    assert!(get_created_receipts().is_empty(), "no key is added");
}

#[test]
fn a_guest_os_removed_while_the_registration_waited_gets_no_key_at_quorum() {
    quorum_after_the_owner_removed(|d| d.remove_approved_os_image(OsImage::of(&measurements('a'))));
}

#[test]
fn a_compose_removed_while_the_registration_waited_gets_no_key_at_quorum() {
    quorum_after_the_owner_removed(|d| d.remove_approved_compose(COMPOSE.to_string()));
}

#[test]
#[should_panic(expected = "Event log does not replay to the quote's RTMR3")]
fn an_event_log_of_another_td_is_refused() {
    let mut d = dao_with_build(&["m1.testnet"]);
    let quoted = measured(&boot_log('1'));
    register(&mut d, 7, quoted, boot_log('2'));
}

#[test]
#[should_panic(expected = "does not replay to the quote's RTMR3")]
fn an_event_log_with_a_forged_field_is_refused() {
    let mut d = dao_with_build(&["m1.testnet"]);
    let mut log = boot_log('1');
    let m = measured(&log);
    log[3].event_payload = "ee".repeat(32);
    register(&mut d, 7, m, log);
}

#[test]
#[should_panic(expected = "Public key mismatch")]
fn a_key_the_quote_does_not_bind_is_refused() {
    let mut d = dao_with_build(&["m1.testnet"]);
    let log = boot_log('1');
    at(a("init.testnet"), 0);
    d.internal_register(key(7), measured(&log), [8u8; 32], log);
}

#[test]
#[should_panic(expected = "names its key")]
fn a_vote_for_a_registration_without_its_key_is_refused() {
    let mut d = dao_with_build(&["m1.testnet", "m2.testnet"]);
    let log = boot_log('1');
    let id = register(&mut d, 7, measured(&log), log);
    at(a("m1.testnet"), 0);
    d.vote(id, true, None);
}

/// A clone: the same approved OS and compose, even the same instance id, another key — started
/// by whoever holds a TDX host and the init key. Its registration is taken. The members' votes
/// name the key the operator read from their own CVM, and land nowhere else, whichever
/// registration came first.
#[test]
fn a_clone_with_another_key_collects_no_vote_meant_for_ours() {
    let mut d = dao_with_build(&["m1.testnet", "m2.testnet", "m3.testnet"]);
    let log = boot_log('1');
    let clone = register(&mut d, 9, measured(&log), log.clone());
    let mine = register(&mut d, 7, measured(&log), log);
    assert_eq!(d.get_registration_facts(clone), d.get_registration_facts(mine), "indistinguishable by facts");

    for m in ["m1.testnet", "m2.testnet"] {
        at(a(m), 0);
        assert!(refused(|| d.vote(clone, true, Some(key(7)))), "the vote for key 7 is refused on the registration of key 9");
        d.vote(mine, true, Some(key(7)));
    }
    assert!(d.is_keystore_approved(String::from(&key(7))));
    assert!(!d.is_keystore_approved(String::from(&key(9))));
    assert_eq!(d.get_proposal(clone).unwrap().status, ProposalStatus::Pending);
    assert_eq!(d.get_proposal(clone).unwrap().votes_for, 0);
}

#[test]
fn a_key_submitted_again_while_pending_is_the_same_registration() {
    let mut d = dao_with_build(&["m1.testnet", "m2.testnet"]);
    let log = boot_log('1');
    let first = register(&mut d, 7, measured(&log), log.clone());
    let again = register(&mut d, 7, measured(&log), log.clone());
    assert_eq!(first, again, "a copy sent ahead of the keystore does not block it, nor add a registration");
    assert_eq!(d.next_proposal_id, first + 1);

    // Once it is no longer pending, the key registers anew.
    at(owner(), 0);
    d.reject_registration(first);
    let anew = register(&mut d, 7, measured(&log), log);
    assert_ne!(anew, first);
}

#[test]
fn a_vote_against_a_registration_needs_no_key_and_the_owner_still_rejects_it() {
    let mut d = dao_with_build(&["m1.testnet", "m2.testnet", "m3.testnet"]);
    let log = boot_log('1');
    let id = register(&mut d, 7, measured(&log), log);
    at(a("m1.testnet"), 0);
    d.vote(id, false, None);
    assert_eq!(d.get_proposal(id).unwrap().votes_against, 1);

    at(owner(), 0);
    d.reject_registration(id);
    at(a("m2.testnet"), 0);
    assert!(refused(|| d.vote(id, true, Some(key(7)))), "a rejected registration takes no votes");
}

#[test]
#[should_panic(expected = "public_key goes only with a vote on a keystore registration")]
fn a_key_on_a_governance_vote_is_refused() {
    let mut d = dao(&["m1.testnet", "m2.testnet"], 0);
    at(a("m1.testnet"), 0);
    let id = d.propose(GovAction::SetDelay { seconds: 1 });
    at(a("m2.testnet"), 0);
    d.vote(id, true, Some(key(7)));
}

#[test]
fn a_restart_of_the_same_instance_registers_its_new_key_by_a_new_vote() {
    let mut d = dao_with_build(&["m1.testnet"]);
    let log = boot_log('1');
    let m = measured(&log);
    let first = register(&mut d, 7, m.clone(), log.clone());
    at(a("m1.testnet"), 0);
    d.vote(first, true, Some(key(7)));

    // Same CVM, same measurements, a new key: nothing is installed until members vote for it.
    let second = register(&mut d, 8, m, log);
    assert_eq!(d.get_proposal(second).unwrap().status, ProposalStatus::Pending);
    assert!(!d.is_keystore_approved(String::from(&key(8))));
}

#[test]
fn a_stale_registration_is_deleted_with_what_it_stated() {
    let mut d = dao_with_build(&["m1.testnet"]);
    let log = boot_log('1');
    let id = register(&mut d, 7, measured(&log), log.clone());
    at(owner(), 49 * HOUR_NS);
    assert_eq!(d.remove_stale_proposals(vec![id]), 1);
    assert!(d.get_proposal(id).is_none());
    assert!(d.get_registration_facts(id).is_none());
    let anew = register(&mut d, 7, measured(&log), log);
    assert_ne!(anew, id, "the key registers anew");
}

#[test]
fn the_owner_cannot_cancel_a_revocation_of_a_keystore_build() {
    let mut d = dao(&["m1.testnet", "m2.testnet"], 3_600);
    at(a("m1.testnet"), 0);
    let os = d.propose(GovAction::RevokeOsImage { image: OsImage::of(&measurements('a')) });
    let compose = d.propose(GovAction::RevokeCompose { compose_hash: "ab".repeat(32) });
    at(owner(), 0);
    for id in [os, compose] {
        assert!(refused(|| d.cancel(id)), "the owner keeps no build the members take away");
        assert_eq!(status(&d, id), GovStatus::Pending);
    }
    // An approval it may still stop.
    at(a("m1.testnet"), 0);
    let approve = d.propose(GovAction::ApproveCompose { compose_hash: "ab".repeat(32) });
    at(owner(), 0);
    d.cancel(approve);
    assert_eq!(status(&d, approve), GovStatus::Cancelled);
}

#[test]
fn a_build_approved_in_uppercase_is_stored_and_checked_in_lowercase() {
    let mut d = dao(&["m1.testnet"], 0);
    let upper = OsImage {
        mrtd: "A".repeat(96),
        rtmr0: "B".repeat(96),
        rtmr1: "C".repeat(96),
        rtmr2: "D".repeat(96),
    };
    at(a("m1.testnet"), 0);
    let p = d.propose(GovAction::ApproveOsImage { image: upper.clone() });
    let _ = d.execute(p);
    let p = d.propose(GovAction::ApproveCompose { compose_hash: COMPOSE.to_uppercase() });
    let _ = d.execute(p);
    assert_eq!(d.get_approved_os_images(), vec![upper.lowercase()]);
    let mut m = measurements('a');
    m.mrtd = "a".repeat(96);
    m.rtmr0 = "b".repeat(96);
    m.rtmr1 = "c".repeat(96);
    m.rtmr2 = "d".repeat(96);
    assert!(d.is_build_approved(m.clone(), COMPOSE.to_uppercase()));
    // Revoked in uppercase too.
    let p = d.propose(GovAction::RevokeOsImage { image: upper });
    let _ = d.execute(p);
    assert!(!d.is_build_approved(m, COMPOSE.to_string()));
}

/// A registration that states its build (made with an event log by the code before the OS and
/// compose lists existed) is checked against both at quorum like any other.
#[test]
fn a_stored_registration_with_facts_is_checked_against_the_lists_at_quorum() {
    let mut d = dao(&["m1.testnet", "m2.testnet", "m3.testnet"], 0);
    let log = boot_log('1');
    let m = measured(&log);
    d.proposals.insert(&1, &KeystoreProposal {
        id: 1,
        public_key: key(1),
        measurements: m.clone(),
        submitter: a("init.testnet"),
        created_at: 0,
        votes_for: 0,
        votes_against: 0,
        status: ProposalStatus::Pending,
    });
    KeystoreDao::registration_facts_for_tests().insert(&1, &event_log::replay(&log).unwrap().1);
    KeystoreDao::set_composes(&vec![COMPOSE.to_string()]); // the compose, not the OS
    at(a("m1.testnet"), 0);
    d.vote(1, true, Some(key(1)));
    at(a("m2.testnet"), 0);
    d.vote(1, true, Some(key(1)));
    assert_eq!(d.get_proposal(1).unwrap().status, ProposalStatus::Rejected);
    assert!(!d.is_keystore_approved(String::from(&key(1))));
}
