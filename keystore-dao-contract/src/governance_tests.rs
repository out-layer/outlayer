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
    let id = d.propose(GovAction::ApproveMeasurements { measurements: measurements('a') });
    let p = d.get_gov_proposal(id).unwrap();
    assert_eq!(p.status, GovStatus::Approved);
    assert_eq!(p.executable_after, Some(10 + HOUR_NS));

    at(a("m1.testnet"), 10 + HOUR_NS);
    assert!(matches!(d.execute(id), PromiseOrValue::Value(true)));
    assert_eq!(status(&d, id), GovStatus::Executed);
    assert!(d.is_measurements_approved(measurements('a')));
}

#[test]
#[should_panic(expected = "Proposal executes from block timestamp")]
fn execute_before_the_delay_panics() {
    let mut d = dao(&["m1.testnet"], 3_600);
    at(a("m1.testnet"), 10);
    let id = d.propose(GovAction::ApproveMeasurements { measurements: measurements('a') });
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
    d.vote(id, true);
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
    d.vote(id, true);
}

#[test]
fn a_removed_members_vote_stops_counting() {
    let mut d = dao(&["m1.testnet", "m2.testnet", "m3.testnet"], 0);
    at(a("m1.testnet"), 0);
    let id = d.propose(GovAction::SetDelay { seconds: 5 });
    d.dao_members.remove(&a("m1.testnet"));
    d.approval_threshold = (d.dao_members.len() as u32 / 2) + 1;

    at(a("m2.testnet"), 0);
    d.vote(id, true);
    assert_eq!(status(&d, id), GovStatus::Pending, "m1's vote no longer counts");
    at(a("m3.testnet"), 0);
    d.vote(id, true);
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
    d.vote(id, true);
}

#[test]
fn a_majority_against_rejects() {
    let mut d = dao(&["m1.testnet", "m2.testnet", "m3.testnet"], 0);
    at(a("m1.testnet"), 0);
    let id = d.propose(GovAction::SetDelay { seconds: 5 });
    at(a("m2.testnet"), 0);
    d.vote(id, false);
    assert_eq!(status(&d, id), GovStatus::Pending);
    at(a("m3.testnet"), 0);
    d.vote(id, false);
    assert_eq!(status(&d, id), GovStatus::Rejected);
}

#[test]
#[should_panic(expected = "Already voted")]
fn double_vote_panics() {
    let mut d = dao(&["m1.testnet", "m2.testnet", "m3.testnet"], 0);
    at(a("m1.testnet"), 0);
    let id = d.propose(GovAction::SetDelay { seconds: 5 });
    d.vote(id, true);
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
            d.vote(id, true);
            at(a("m1.testnet"), 0);
        }
        let _ = d.execute(id);
    }
    assert_eq!(d.get_dao_members().len(), 3);
    assert_eq!(d.approval_threshold, 2);

    let id = d.propose(GovAction::RemoveMember { member: a("m3.testnet") });
    at(a("m2.testnet"), 0);
    d.vote(id, true);
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
fn revoke_measurements_by_vote() {
    let mut d = dao(&["m1.testnet"], 0);
    d.approved_measurements.push(measurements('b'));
    at(a("m1.testnet"), 0);
    let id = d.propose(GovAction::RevokeMeasurements { measurements: measurements('b') });
    let _ = d.execute(id);
    assert!(!d.is_measurements_approved(measurements('b')));
}

// ===== the owner: a brake, never an accelerator =====

#[test]
fn owner_cancels_a_pending_and_an_approved_proposal() {
    let mut d = dao(&["m1.testnet", "m2.testnet", "m3.testnet"], 3_600);
    at(a("m1.testnet"), 0);
    let pending = d.propose(GovAction::SetDelay { seconds: 1 });
    let approved = d.propose(GovAction::SetDelay { seconds: 2 });
    at(a("m2.testnet"), 0);
    d.vote(approved, true);
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

#[test]
fn owner_still_revokes_measurements_without_a_vote() {
    let mut d = dao(&["m1.testnet"], 0);
    d.approved_measurements.push(measurements('c'));
    d.approved_measurements.push(measurements('d'));
    at(owner(), 0);
    d.remove_approved_measurements(measurements('c'));
    assert_eq!(d.get_approved_measurements(), vec![measurements('d')]);
    d.clear_all_approved_measurements();
    assert!(d.get_approved_measurements().is_empty());
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

#[test]
fn a_registration_of_a_build_revoked_while_it_waited_is_rejected_at_quorum() {
    let mut d = dao(&["m1.testnet", "m2.testnet", "m3.testnet"], 0);
    d.approved_measurements.push(measurements('e'));
    pending_registration(&mut d, 1, 0);
    at(owner(), 0);
    d.remove_approved_measurements(measurements('e'));

    at(a("m1.testnet"), 0);
    d.vote(1, true);
    at(a("m2.testnet"), 0);
    d.vote(1, true);
    assert_eq!(d.get_proposal(1).unwrap().status, ProposalStatus::Rejected);
    assert!(!d.is_keystore_approved(String::from(&key(1))));
    assert!(get_created_receipts().is_empty(), "no key is added");
}

#[test]
fn a_registration_of_a_build_still_approved_installs_its_key_at_quorum() {
    let mut d = dao(&["m1.testnet", "m2.testnet", "m3.testnet"], 0);
    d.approved_measurements.push(measurements('e'));
    pending_registration(&mut d, 1, 0);
    at(a("m1.testnet"), 0);
    d.vote(1, true);
    at(a("m2.testnet"), 0);
    d.vote(1, true);
    assert_eq!(d.get_proposal(1).unwrap().status, ProposalStatus::Executed);
    assert!(d.is_keystore_approved(String::from(&key(1))));
}

#[test]
fn the_owner_rejects_a_pending_registration_and_no_vote_installs_it() {
    let mut d = dao(&["m1.testnet", "m2.testnet", "m3.testnet"], 0);
    d.approved_measurements.push(measurements('e'));
    pending_registration(&mut d, 1, 0);
    at(owner(), 0);
    d.reject_registration(1);
    assert_eq!(d.get_proposal(1).unwrap().status, ProposalStatus::Rejected);
    at(a("m1.testnet"), 0);
    let voted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| d.vote(1, true)));
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

#[test]
fn a_build_approved_in_uppercase_is_stored_in_lowercase() {
    let mut d = dao(&["m1.testnet"], 0);
    at(a("m1.testnet"), 0);
    let id = d.propose(GovAction::ApproveMeasurements { measurements: measurements('E') });
    let _ = d.execute(id);
    assert_eq!(d.get_approved_measurements(), vec![measurements('e')]);
    assert!(d.is_measurements_approved(measurements('E')));
}

#[test]
fn a_revoke_in_another_case_removes_the_build_and_its_pending_registration_dies() {
    let mut d = dao(&["m1.testnet", "m2.testnet", "m3.testnet"], 0);
    d.approved_measurements.push(measurements('e'));
    pending_registration(&mut d, 1, 0);
    at(owner(), 0);
    d.remove_approved_measurements(measurements('E'));
    assert!(d.get_approved_measurements().is_empty(), "the uppercase revoke matched");

    at(a("m1.testnet"), 0);
    d.vote(1, true);
    at(a("m2.testnet"), 0);
    d.vote(1, true);
    assert_eq!(d.get_proposal(1).unwrap().status, ProposalStatus::Rejected);
}

#[test]
fn a_governance_revoke_in_another_case_removes_the_build() {
    let mut d = dao(&["m1.testnet"], 0);
    d.approved_measurements.push(measurements('b'));
    at(a("m1.testnet"), 0);
    let id = d.propose(GovAction::RevokeMeasurements { measurements: measurements('B') });
    let _ = d.execute(id);
    assert!(d.get_approved_measurements().is_empty());
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
    d.vote(remove, true);
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

#[test]
fn v4_state_migrates_to_v5_with_every_field_kept() {
    let mut b = VMContextBuilder::new();
    b.current_account_id(a("dao.outlayer.near")).predecessor_account_id(a("dao.outlayer.near"));
    testing_env!(b.build());

    let mut members = near_sdk::collections::UnorderedSet::new(StorageKey::DaoMembers);
    members.insert(&a("zavodil.near"));
    let mut keystores = near_sdk::collections::UnorderedSet::new(StorageKey::ApprovedKeystores);
    keystores.insert(&key(5));
    let v4 = KeystoreDaoV4 {
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
    };
    env::state_write(&v4);

    let d = KeystoreDao::migrate();
    assert_eq!(d.get_dao_members(), vec![a("zavodil.near")]);
    assert_eq!(d.get_owner(), a("owner.outlayer.near"));
    assert_eq!(d.next_proposal_id, 50);
    assert!(d.approved_keystores.contains(&key(5)));
    assert_eq!(d.get_approved_measurements(), vec![measurements('e')]);
    assert_eq!(d.get_collaterals(), vec!["c0".to_string(), "c1".to_string()]);
    assert_eq!(d.get_gov_delay_sec(), governance::MAINNET_GOV_DELAY_SEC, ".near starts at 72 h");
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
    d.vote(up, true);
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
    d.vote(id, true);
}

#[test]
fn a_pending_proposal_takes_votes_until_its_ttl() {
    let mut d = dao(&["m1.testnet", "m2.testnet", "m3.testnet"], 0);
    at(a("m1.testnet"), 0);
    let id = d.propose(GovAction::SetDelay { seconds: 1 });
    at(a("m2.testnet"), 14 * DAY_NS);
    d.vote(id, true);
    assert_eq!(status(&d, id), GovStatus::Approved);
}
