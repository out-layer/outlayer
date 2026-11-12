use crate::migration::RegisterContractV3;
use crate::*;
use near_sdk::test_utils::VMContextBuilder;
use near_sdk::testing_env;


fn a(s: &str) -> AccountId {
    s.parse().unwrap()
}
fn with_input(predecessor: &str, input: &[u8]) {
    let mut b = VMContextBuilder::new();
    b.current_account_id(a("worker.testnet")).predecessor_account_id(a(predecessor));
    b.context.input = std::rc::Rc::from(input.to_vec().into_boxed_slice());
    testing_env!(b.build());
}
fn at(predecessor: &str, now_ns: u64) {
    let mut b = VMContextBuilder::new();
    b.current_account_id(a("worker.testnet"))
        .predecessor_account_id(a(predecessor))
        .block_timestamp(now_ns);
    testing_env!(b.build());
}
fn contract() -> RegisterContract {
    at("owner.testnet", 0);
    RegisterContract::new(a("owner.testnet"), a("init.testnet"), a("outlayer.testnet"), a("dao.testnet"))
}
fn m(c: char) -> ApprovedMeasurements {
    let f = c.to_string().repeat(96);
    ApprovedMeasurements { mrtd: f.clone(), rtmr0: f.clone(), rtmr1: f.clone(), rtmr2: f.clone(), rtmr3: f }
}
#[test]
fn governance_approves_a_build_and_the_owner_revokes_it() {
    let mut c = contract();
    at("dao.testnet", 0);
    c.add_approved_measurements(m('a'), None);
    assert!(c.is_measurements_approved(m('a')));
    at("owner.testnet", 0);
    c.remove_approved_measurements(m('a'));
    assert!(!c.is_measurements_approved(m('a')));
}

#[test]
#[should_panic(expected = "Only governance")]
fn the_owner_cannot_approve_a_build() {
    let mut c = contract();
    at("owner.testnet", 0);
    c.add_approved_measurements(m('a'), None);
}

#[test]
#[should_panic(expected = "Only the owner or governance")]
fn a_stranger_cannot_revoke() {
    let mut c = contract();
    at("stranger.testnet", 0);
    c.clear_all_approved_measurements();
}

#[test]
fn governance_replaces_the_owner_and_itself() {
    let mut c = contract();
    at("dao.testnet", 0);
    c.set_owner(a("ops2.testnet"));
    assert_eq!(c.get_owner(), a("ops2.testnet"));
    c.set_governance(a("dao2.testnet"));
    assert_eq!(c.get_governance(), a("dao2.testnet"));
}

#[test]
#[should_panic(expected = "Only governance")]
fn the_owner_cannot_replace_itself() {
    let mut c = contract();
    at("owner.testnet", 0);
    c.set_owner(a("ops2.testnet"));
}

#[test]
fn governance_upgrades_with_the_wasm_as_raw_input() {
    let mut c = contract();
    with_input("dao.testnet", b"\0asm-new-code");
    let _ = c.upgrade();
    let _ = c.upgrade_and_migrate();
}

#[test]
#[should_panic(expected = "raw input")]
fn an_upgrade_without_code_is_refused() {
    let mut c = contract();
    with_input("dao.testnet", b"");
    let _ = c.upgrade();
}

#[test]
#[should_panic(expected = "Only governance")]
fn the_owner_cannot_upgrade() {
    let mut c = contract();
    with_input("owner.testnet", b"\0asm-new-code");
    let _ = c.upgrade();
}

#[test]
fn v3_state_migrates_to_v4() {
    let mut b = VMContextBuilder::new();
    b.current_account_id(a("worker.testnet")).predecessor_account_id(a("worker.testnet"));
    testing_env!(b.build());
    env::state_write(&RegisterContractV3 {
        owner_id: a("owner.testnet"),
        init_worker_account: a("init.testnet"),
        approved_measurements: vec![m('b')],
        collaterals: vec!["c0".into(), "c1".into()],
        outlayer_contract_id: a("outlayer.testnet"),
    });
    let c = RegisterContract::migrate(a("dao.testnet"));
    assert_eq!(c.get_owner(), a("owner.testnet"));
    assert_eq!(c.get_governance(), a("dao.testnet"));
    assert_eq!(c.get_approved_measurements(), vec![m('b')]);
    assert_eq!(c.get_collaterals(), vec!["c0".to_string(), "c1".to_string()]);
    assert_eq!(c.get_init_worker_account(), a("init.testnet"));
}
