use crate::exit::*;
use crate::*;
use near_sdk::json_types::Base64VecU8;
use near_sdk::test_utils::{get_created_receipts, VMContextBuilder};
use near_sdk::{testing_env, PromiseResult, RuntimeFeesConfig};

const T0: u64 = 1_700_000_000_000_000_000;
const S: u64 = 1_000_000_000;

fn a(s: &str) -> AccountId {
    s.parse().unwrap()
}
fn alice() -> AccountId {
    a("alice.testnet")
}
fn bob() -> AccountId {
    a("bob.testnet")
}
fn carol() -> AccountId {
    a("carol.testnet")
}
fn key(byte: u8) -> PublicKey {
    PublicKey::from_parts(CurveType::ED25519, vec![byte; 32]).unwrap()
}
fn g1() -> dtos::Bls12381G1PublicKey {
    dtos::Bls12381G1PublicKey("bls12381g1:owner-one-time-key".into())
}

/// The contract on `dao_id`: the account decides the exit timing.
fn dao_on(dao_id: &str) -> KeystoreDao {
    testing_env!(VMContextBuilder::new().current_account_id(a(dao_id)).predecessor_account_id(a("owner.testnet")).build());
    KeystoreDao::new(
        a("owner.testnet"),
        a("init.testnet"),
        vec![a("m1.testnet")],
        a("v1.signer-prod.testnet"),
        Some(0),
    )
}

struct World {
    dao: KeystoreDao,
    dao_id: AccountId,
}

impl World {
    fn new() -> Self {
        Self::on("dao.testnet")
    }
    fn on(dao_id: &str) -> Self {
        Self { dao: dao_on(dao_id), dao_id: a(dao_id) }
    }
    /// A call by `who` at `now` with `deposit` attached.
    fn call(&self, who: AccountId, now: u64, deposit: NearToken) {
        testing_env!(VMContextBuilder::new()
            .current_account_id(self.dao_id.clone())
            .predecessor_account_id(who.clone())
            .signer_account_id(who)
            .block_timestamp(now)
            .attached_deposit(deposit)
            .build());
    }
    fn yocto(&self, who: AccountId, now: u64) {
        self.call(who, now, NearToken::from_yoctonear(1));
    }
    /// A call signed with an approved keystore's key on the DAO account.
    fn as_keystore(&mut self, now: u64) {
        self.dao.approved_keystores.insert(&key(9));
        testing_env!(VMContextBuilder::new()
            .current_account_id(self.dao_id.clone())
            .predecessor_account_id(self.dao_id.clone())
            .signer_account_pk(key(9))
            .block_timestamp(now)
            .build());
    }
    fn register(&mut self, who: AccountId, window: Option<u64>) {
        self.call(who, T0, EXIT_REGISTRATION_FEE);
        self.dao.register_exit_owner(window);
    }
    fn store_escrow(&mut self, who: AccountId, generation: u64) -> bool {
        self.as_keystore(T0);
        self.dao.store_escrow(who, generation, Base64VecU8(vec![7; 48]), Base64VecU8(vec![8; 32]))
    }
    /// A registered owner with an escrow, window `window` seconds.
    fn owner_with_escrow(&mut self, who: AccountId, window: u64) {
        self.register(who.clone(), Some(window));
        assert!(self.store_escrow(who, 1));
    }
    fn initiate(&mut self, who: AccountId, now: u64) -> u64 {
        self.call(who.clone(), now, EXIT_FEE);
        self.dao.initiate_exit();
        self.view(who, now).pending.unwrap().nonce
    }
    fn view(&self, who: AccountId, now: u64) -> ExitOwnerView {
        self.call(a("anyone.testnet"), now, NearToken::from_yoctonear(0));
        self.dao.get_exit_owner(who).unwrap()
    }
    /// The claim's callback with MPC's promise result.
    fn callback(&mut self, who: AccountId, now: u64, result: PromiseResult) {
        testing_env!(
            VMContextBuilder::new()
                .current_account_id(self.dao_id.clone())
                .predecessor_account_id(self.dao_id.clone())
                .block_timestamp(now)
                .build(),
            near_sdk::test_vm_config(),
            RuntimeFeesConfig::test(),
            Default::default(),
            vec![result],
        );
        self.dao.on_escrow_key_claimed(who);
    }
    fn claim(&mut self, who: AccountId, now: u64) {
        self.yocto(who, now);
        let _ = self.dao.claim_escrow_key(g1());
    }
}

/// The longest account id NEAR allows is an owner like any other: its path, its record and
/// its escrow are stored and read back, and the path MPC is asked for names it whole.
#[test]
fn an_account_at_the_length_limit_is_an_owner_like_any_other() {
    let longest = a(&format!("{}.testnet", "a".repeat(56)));
    assert_eq!(longest.as_str().len(), 64);
    let mut w = World::new();
    w.owner_with_escrow(longest.clone(), 60);
    assert_eq!(owner_path(&longest, 1), format!("owner:{longest}:1"));
    let nonce = w.initiate(longest.clone(), T0);
    assert_eq!(w.view(longest.clone(), T0).pending.unwrap().nonce, nonce);
    w.claim(longest.clone(), T0 + 61 * S);
    assert_eq!(ckd_path_requested(), format!("owner:{longest}:1"));
    w.callback(longest.clone(), T0 + 62 * S, PromiseResult::Successful(br#"{"big_y":"y","big_c":"c"}"#.to_vec()));
    let after = w.view(longest.clone(), T0 + 63 * S);
    assert_eq!((after.generation, after.pending, after.claim_in_flight), (2, None, false));
    w.call(a("anyone.testnet"), T0 + 63 * S, NearToken::from_yoctonear(0));
    assert!(w.dao.get_escrow(longest.clone(), 1).is_some(), "the escrow of the generation left is still read");
    assert!(w.dao.get_escrow(longest, 2).is_none());
}

/// What a call that must be refused panicked with; `None` when it went through. A test
/// names the words it expects, so that a refusal for another reason does not pass for it.
fn why_refused(f: &mut dyn FnMut()) -> Option<String> {
    // The panic hook is the process's, shared by every test thread: it is left alone, and
    // an expected refusal prints its panic line among the test output.
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    outcome.err().map(|payload| {
        payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default()
    })
}

/// The call is refused, and for the reason named.
fn assert_refused(f: &mut dyn FnMut(), words: &str) {
    match why_refused(f) {
        Some(why) => assert!(why.contains(words), "refused, but with {why:?} and not {words:?}"),
        None => panic!("the call went through; expected a refusal with {words:?}"),
    }
}

/// What an owner costs the contract in storage, at its largest: the longest account id, the
/// largest approver set of the longest ids, a pending change to another such set with every
/// vote cast, a pending lowering of the window, and the escrow. The registration fee pays
/// for the record and the first escrow; an exit fee pays for the next generation's escrow;
/// both pay for the gas of the keystore's two transactions that write an escrow. A change
/// of the record's layout that outgrows a fee fails here and not on chain.
#[test]
fn the_fees_cover_the_storage_they_pay_for() {
    const YOCTO_PER_BYTE: u128 = 10_000_000_000_000_000_000;
    let long = |n: usize| a(&format!("{}{:02}.testnet", "a".repeat(54), n));
    let owner = long(0);
    let approvers: Vec<AccountId> = (1..=MAX_EXIT_APPROVERS).map(long).collect();
    let others: Vec<AccountId> = (21..=20 + MAX_EXIT_APPROVERS).map(long).collect();
    assert!(approvers.iter().chain(&others).all(|a| a.as_str().len() == 64));

    let mut w = World::on("dao.outlayer.near");
    w.register(owner.clone(), Some(48 * 3_600));
    w.yocto(owner.clone(), T0);
    w.dao.set_exit_approvers(approvers.clone(), MAX_EXIT_APPROVERS as u32);
    w.yocto(owner.clone(), T0);
    w.dao.set_exit_window(24 * 3_600);
    w.yocto(owner.clone(), T0);
    w.dao.set_exit_approvers(others, MAX_EXIT_APPROVERS as u32);
    let nonce = w.view(owner.clone(), T0).pending.unwrap().nonce;
    for approver in &approvers[..approvers.len() - 1] {
        w.yocto(approver.clone(), T0);
        w.dao.approve_exit(owner.clone(), nonce);
    }
    w.as_keystore(T0);
    assert!(w.dao.store_escrow(owner.clone(), 1, Base64VecU8(vec![7; 48]), Base64VecU8(vec![8; 32])));

    // What the chain charges for an entry: its key, its value and 40 bytes of bookkeeping.
    const PER_ENTRY: u64 = 40;
    let stored = near_sdk::mock::with_mocked_blockchain(|chain| chain.take_storage());
    let holds = |bytes: &[u8], what: &[u8]| bytes.windows(what.len()).any(|w| w == what);
    let path = owner_path(&owner, 1);
    let size_of = |is: &dyn Fn(&[u8]) -> bool| -> u64 {
        let found: Vec<u64> =
            stored.iter().filter(|(k, _)| is(k)).map(|(k, v)| (k.len() + v.len()) as u64 + PER_ENTRY).collect();
        assert_eq!(found.len(), 1, "one entry was expected, {} found", found.len());
        found[0]
    };
    let escrow = size_of(&|key| holds(key, path.as_bytes()));
    let record = size_of(&|key| holds(key, owner.as_bytes()) && !holds(key, path.as_bytes()));

    let cost = |bytes: u64| bytes as u128 * YOCTO_PER_BYTE;
    println!(
        "storage: record {record} bytes = {} yocto, escrow {escrow} bytes = {} yocto",
        cost(record),
        cost(escrow)
    );
    let gas = ESCROW_GAS_ALLOWANCE.as_yoctonear();
    assert!(
        EXIT_REGISTRATION_FEE.as_yoctonear() >= cost(record + escrow) + gas,
        "the registration fee no longer covers the record, its first escrow ({} bytes) and the keystore's gas",
        record + escrow
    );
    assert!(
        EXIT_FEE.as_yoctonear() >= cost(escrow) + gas,
        "the exit fee no longer covers the next generation's escrow ({escrow} bytes) and the keystore's gas"
    );
    // The sizes the fees were set from: a layout that changes them is a reason to look again.
    assert_eq!((record, escrow), (3378, 214));
}

/// The derivation path of the one CKD call the last transaction made.
fn ckd_path_requested() -> String {
    let receipts = get_created_receipts();
    let call = receipts
        .iter()
        .flat_map(|r| r.actions.iter())
        .find_map(|a| match a {
            near_sdk::mock::MockAction::FunctionCallWeight { method_name, args, .. }
                if method_name == b"request_app_private_key" =>
            {
                Some(args.clone())
            }
            _ => None,
        })
        .expect("a call to MPC");
    let v: serde_json::Value = serde_json::from_slice(&call).unwrap();
    assert_eq!(v["request"]["domain_id"], CKD_DOMAIN_ID);
    v["request"]["derivation_path"].as_str().unwrap().to_string()
}

// ===== paths =====

#[test]
fn an_owner_path_names_one_account_and_generation() {
    assert_eq!(owner_path(&alice(), 1), "owner:alice.testnet:1");
    assert_ne!(owner_path(&a("ab"), 11), owner_path(&a("ab1"), 1));
    assert!(!owner_path(&a("aa"), 1).is_empty());
}

#[test]
fn a_claim_asks_mpc_for_the_callers_own_path() {
    let mut w = World::new();
    w.owner_with_escrow(alice(), 60);
    w.owner_with_escrow(bob(), 60);
    w.initiate(alice(), T0);
    w.claim(alice(), T0 + 60 * S);
    assert_eq!(ckd_path_requested(), "owner:alice.testnet:1");
}

#[test]
fn the_keystore_is_given_the_owners_current_path() {
    let mut w = World::new();
    w.register(alice(), None);
    w.as_keystore(T0);
    let _ = w.dao.request_escrow_key(alice(), g1());
    assert_eq!(ckd_path_requested(), "owner:alice.testnet:1");
}

// ===== request_key =====

#[test]
#[should_panic(expected = "request_key takes the empty derivation path only")]
fn request_key_refuses_an_owner_path() {
    let mut w = World::new();
    w.as_keystore(T0);
    let _ = w.dao.request_key(CKDRequestArgs {
        derivation_path: "owner:alice.testnet:1".into(),
        app_public_key: g1(),
        domain_id: DomainId(CKD_DOMAIN_ID),
    });
}

#[test]
#[should_panic(expected = "request_key takes domain id")]
fn request_key_refuses_another_domain() {
    let mut w = World::new();
    w.as_keystore(T0);
    let _ = w.dao.request_key(CKDRequestArgs {
        derivation_path: String::new(),
        app_public_key: g1(),
        domain_id: DomainId(CKD_DOMAIN_ID + 1),
    });
}

// ===== registration and window =====

#[test]
fn registration_starts_at_generation_one_with_the_default_window() {
    let mut w = World::new();
    w.register(alice(), None);
    let v = w.view(alice(), T0);
    assert_eq!(v.generation, 1);
    assert_eq!(v.exit_window_secs, 60);
    assert!(v.approvers.is_empty() && v.pending.is_none() && !v.claim_in_flight && v.escrow_check.is_none());
}

#[test]
#[should_panic(expected = "registration takes")]
fn registration_needs_the_fee() {
    let mut w = World::new();
    w.call(alice(), T0, NearToken::from_millinear(1));
    w.dao.register_exit_owner(None);
}

#[test]
#[should_panic(expected = "already registered")]
fn registration_is_once() {
    let mut w = World::new();
    w.register(alice(), None);
    w.register(alice(), None);
}

#[test]
#[should_panic(expected = "the exit window must be between")]
fn registration_refuses_a_window_out_of_range() {
    let mut w = World::new();
    w.register(alice(), Some(59));
}

#[test]
fn timing_follows_the_account() {
    let w = World::on("dao.outlayer.near");
    w.call(alice(), T0, NearToken::from_yoctonear(0));
    let t = ExitTiming::of_this_account();
    assert_eq!((t.min_window_secs, t.max_window_secs, t.finalize_window_secs), (86_400, 172_800, 604_800));
    let w = World::on("dao.outlayer.testnet");
    w.call(alice(), T0, NearToken::from_yoctonear(0));
    let t = ExitTiming::of_this_account();
    assert_eq!((t.min_window_secs, t.max_window_secs, t.finalize_window_secs), (60, 3_600, 600));
}

#[test]
fn raising_the_window_applies_at_once_and_lowering_waits() {
    let mut w = World::new();
    w.register(alice(), Some(600));
    w.yocto(alice(), T0);
    w.dao.set_exit_window(1_200);
    assert_eq!(w.view(alice(), T0).exit_window_secs, 1_200);

    w.yocto(alice(), T0);
    w.dao.set_exit_window(60);
    let v = w.view(alice(), T0);
    assert_eq!(v.exit_window_secs, 1_200);
    assert_eq!(v.pending_exit_window, Some(PendingExitWindow { secs: 60, effective_at: T0 + 1_200 * S }));

    let v = w.view(alice(), T0 + 1_200 * S);
    assert_eq!(v.exit_window_secs, 60);
    assert_eq!(v.pending_exit_window, None);
}

#[test]
fn an_exit_started_right_after_a_lowering_waits_the_old_window() {
    let mut w = World::new();
    w.owner_with_escrow(alice(), 1_200);
    w.yocto(alice(), T0);
    w.dao.set_exit_window(60);
    w.initiate(alice(), T0);
    match w.view(alice(), T0).pending.unwrap().kind {
        ExitActionKind::Exit { finalize_after, .. } => assert_eq!(finalize_after, T0 + 1_200 * S),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_matured_lowering_is_used_by_an_exit_with_no_other_call() {
    let mut w = World::new();
    w.owner_with_escrow(alice(), 1_200);
    w.yocto(alice(), T0);
    w.dao.set_exit_window(60);
    let later = T0 + 1_200 * S;
    w.initiate(alice(), later);
    match w.view(alice(), later).pending.unwrap().kind {
        ExitActionKind::Exit { finalize_after, .. } => assert_eq!(finalize_after, later + 60 * S),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_raise_drops_a_pending_lowering_and_a_second_lowering_replaces_the_first() {
    let mut w = World::new();
    w.register(alice(), Some(1_200));
    w.yocto(alice(), T0);
    w.dao.set_exit_window(600);
    w.yocto(alice(), T0 + 100 * S);
    w.dao.set_exit_window(300);
    assert_eq!(
        w.view(alice(), T0 + 100 * S).pending_exit_window,
        Some(PendingExitWindow { secs: 300, effective_at: T0 + 1_300 * S })
    );
    w.yocto(alice(), T0 + 200 * S);
    w.dao.set_exit_window(1_200);
    assert_eq!(w.view(alice(), T0 + 5_000 * S).exit_window_secs, 1_200);
}

#[test]
fn an_owner_method_takes_a_deposit() {
    let mut w = World::new();
    w.owner_with_escrow(alice(), 60);
    let none = NearToken::from_yoctonear(0);
    let one_yocto = "Requires attached deposit of exactly 1 yoctoNEAR";
    w.call(alice(), T0, none);
    assert_refused(&mut || w.dao.set_exit_window(120), one_yocto);
    w.call(alice(), T0, none);
    assert_refused(&mut || w.dao.set_exit_approvers(vec![bob()], 1), one_yocto);
    w.call(alice(), T0, none);
    assert_refused(&mut || w.dao.cancel_exit(), one_yocto);
    w.call(alice(), T0, none);
    assert_refused(
        &mut || {
            let _ = w.dao.claim_escrow_key(g1());
        },
        one_yocto,
    );
    w.call(bob(), T0, none);
    assert_refused(&mut || w.dao.approve_exit(alice(), 1), one_yocto);
    w.call(bob(), T0, none);
    assert_refused(&mut || w.dao.reject_exit(alice(), 1), one_yocto);
    // The two that take a fee say so.
    w.call(alice(), T0, none);
    assert_refused(&mut || w.dao.initiate_exit(), "an exit takes");
    w.call(bob(), T0, none);
    assert_refused(&mut || w.dao.register_exit_owner(None), "registration takes");
}

// ===== escrow =====

#[test]
#[should_panic(expected = "must be called via an approved-keystore access key")]
fn an_ordinary_account_cannot_store_an_escrow() {
    let mut w = World::new();
    w.register(alice(), None);
    w.call(alice(), T0, NearToken::from_yoctonear(0));
    w.dao.store_escrow(alice(), 1, Base64VecU8(vec![7; 48]), Base64VecU8(vec![8; 32]));
}

#[test]
#[should_panic(expected = "must be called via an approved-keystore access key")]
fn an_ordinary_account_cannot_ask_for_an_escrow_key() {
    let mut w = World::new();
    w.register(alice(), None);
    w.call(alice(), T0, NearToken::from_yoctonear(0));
    let _ = w.dao.request_escrow_key(alice(), g1());
}

#[test]
#[should_panic(expected = "not a registered owner")]
fn no_escrow_key_for_an_unregistered_account() {
    let mut w = World::new();
    w.as_keystore(T0);
    let _ = w.dao.request_escrow_key(alice(), g1());
}

#[test]
fn the_first_escrow_stands() {
    let mut w = World::new();
    w.register(alice(), None);
    assert!(w.store_escrow(alice(), 1));
    w.as_keystore(T0);
    assert!(!w.dao.store_escrow(alice(), 1, Base64VecU8(vec![1; 48]), Base64VecU8(vec![2; 32])));
    let e = w.dao.get_escrow(alice(), 1).unwrap();
    assert_eq!((e.ct.0, e.check.0, e.domain_id), (vec![7; 48], vec![8; 32], CKD_DOMAIN_ID));
    assert_eq!(w.view(alice(), T0).escrow_check, Some(Base64VecU8(vec![8; 32])));
}

#[test]
#[should_panic(expected = "not the owner's current generation")]
fn an_escrow_is_for_the_current_generation_only() {
    let mut w = World::new();
    w.register(alice(), None);
    w.store_escrow(alice(), 2);
}

#[test]
#[should_panic(expected = "this generation's escrow is already stored")]
fn the_keystore_gets_the_escrow_key_once() {
    let mut w = World::new();
    w.owner_with_escrow(alice(), 60);
    w.as_keystore(T0);
    let _ = w.dao.request_escrow_key(alice(), g1());
}

// ===== exit =====

#[test]
#[should_panic(expected = "no escrow for this generation yet")]
fn no_exit_without_an_escrow() {
    let mut w = World::new();
    w.register(alice(), None);
    w.call(alice(), T0, EXIT_FEE);
    w.dao.initiate_exit();
}

#[test]
#[should_panic(expected = "an exit takes")]
fn an_exit_needs_the_fee() {
    let mut w = World::new();
    w.owner_with_escrow(alice(), 60);
    w.yocto(alice(), T0);
    w.dao.initiate_exit();
}

#[test]
#[should_panic(expected = "an action is already pending")]
fn one_exit_at_a_time() {
    let mut w = World::new();
    w.owner_with_escrow(alice(), 60);
    w.initiate(alice(), T0);
    w.initiate(alice(), T0 + S);
}

#[test]
#[should_panic(expected = "the exit window has not elapsed")]
fn no_claim_before_the_window() {
    let mut w = World::new();
    w.owner_with_escrow(alice(), 60);
    w.initiate(alice(), T0);
    w.claim(alice(), T0 + 59 * S);
}

#[test]
#[should_panic(expected = "no exit is pending")]
fn no_claim_past_the_claim_window() {
    let mut w = World::new();
    w.owner_with_escrow(alice(), 60);
    w.initiate(alice(), T0);
    w.claim(alice(), T0 + (60 + 600) * S + 1);
}

#[test]
fn an_exit_past_its_claim_window_is_replaced_by_the_next() {
    let mut w = World::new();
    w.owner_with_escrow(alice(), 60);
    let first = w.initiate(alice(), T0);
    let later = T0 + (60 + 600) * S + 1;
    assert!(w.view(alice(), later).pending.is_none());
    let second = w.initiate(alice(), later);
    assert_ne!(first, second);
}

#[test]
#[should_panic(expected = "not a registered owner")]
fn another_account_cannot_claim() {
    let mut w = World::new();
    w.owner_with_escrow(alice(), 60);
    w.initiate(alice(), T0);
    w.claim(bob(), T0 + 60 * S);
}

#[test]
#[should_panic(expected = "no exit is pending")]
fn a_cancelled_exit_cannot_be_claimed() {
    let mut w = World::new();
    w.owner_with_escrow(alice(), 60);
    w.initiate(alice(), T0);
    w.yocto(alice(), T0 + S);
    w.dao.cancel_exit();
    w.claim(alice(), T0 + 60 * S);
}

#[test]
fn a_successful_claim_moves_the_generation_on() {
    let mut w = World::new();
    w.owner_with_escrow(alice(), 60);
    w.initiate(alice(), T0);
    let at = T0 + 60 * S;
    w.claim(alice(), at);
    assert!(w.view(alice(), at).claim_in_flight);

    w.callback(alice(), at + S, PromiseResult::Successful(br#"{"big_y":"y","big_c":"c"}"#.to_vec()));
    let v = w.view(alice(), at + S);
    assert_eq!(v.generation, 2);
    assert!(v.pending.is_none() && !v.claim_in_flight);
    // The escrow of the generation left stays; the new one has none yet.
    assert!(w.dao.get_escrow(alice(), 1).is_some());
    assert_eq!(v.escrow_check, None);
}

#[test]
fn a_failed_claim_changes_nothing_and_can_be_repeated() {
    let mut w = World::new();
    w.owner_with_escrow(alice(), 60);
    let nonce = w.initiate(alice(), T0);
    let at = T0 + 60 * S;
    w.claim(alice(), at);
    w.callback(alice(), at + S, PromiseResult::Failed);
    let v = w.view(alice(), at + S);
    assert_eq!(v.generation, 1);
    assert!(!v.claim_in_flight);
    assert_eq!(v.pending.unwrap().nonce, nonce);

    w.claim(alice(), at + 2 * S);
    w.callback(alice(), at + 3 * S, PromiseResult::Successful(b"x".to_vec()));
    assert_eq!(w.view(alice(), at + 3 * S).generation, 2);
}

#[test]
fn the_callback_does_not_read_what_mpc_answered() {
    let mut w = World::new();
    w.owner_with_escrow(alice(), 60);
    w.initiate(alice(), T0);
    let at = T0 + 60 * S;
    w.claim(alice(), at);
    // Not a CKD answer, and longer than the callback passes on.
    w.callback(alice(), at + S, PromiseResult::Successful(vec![0xff; 10_000]));
    assert_eq!(w.view(alice(), at + S).generation, 2);
}

#[test]
fn the_callback_for_an_unknown_account_does_nothing() {
    let mut w = World::new();
    w.callback(alice(), T0, PromiseResult::Successful(b"x".to_vec()));
    w.call(alice(), T0, NearToken::from_yoctonear(0));
    assert!(w.dao.get_exit_owner(alice()).is_none());
}

#[test]
#[should_panic(expected = "no exit is pending")]
fn a_generation_is_claimed_once() {
    let mut w = World::new();
    w.owner_with_escrow(alice(), 60);
    w.initiate(alice(), T0);
    let at = T0 + 60 * S;
    w.claim(alice(), at);
    w.callback(alice(), at + S, PromiseResult::Successful(b"x".to_vec()));
    w.claim(alice(), at + 2 * S);
}

#[test]
fn a_claim_in_flight_refuses_every_write_and_lapses_after_an_hour() {
    let mut w = World::new();
    w.owner_with_escrow(alice(), 60);
    w.yocto(alice(), T0);
    w.dao.set_exit_approvers(vec![bob(), carol()], 1);
    let nonce = w.initiate(alice(), T0);
    w.yocto(bob(), T0 + S);
    w.dao.approve_exit(alice(), nonce);
    let at = T0 + 60 * S;
    w.claim(alice(), at);

    // Each is refused BECAUSE a claim is in flight: with the right nonce, the right
    // deposit and, for carol, a vote not cast yet, nothing else stands in the way.
    let in_flight = "a claim is in flight";
    let now = at + S;
    w.yocto(alice(), now);
    assert_refused(&mut || w.dao.cancel_exit(), in_flight);
    w.yocto(alice(), now);
    assert_refused(&mut || w.dao.set_exit_window(120), in_flight);
    w.yocto(alice(), now);
    assert_refused(&mut || w.dao.set_exit_approvers(vec![], 0), in_flight);
    w.call(alice(), now, EXIT_FEE);
    assert_refused(&mut || w.dao.initiate_exit(), in_flight);
    w.yocto(alice(), now);
    assert_refused(
        &mut || {
            let _ = w.dao.claim_escrow_key(g1());
        },
        in_flight,
    );
    w.yocto(bob(), now);
    assert_refused(&mut || w.dao.reject_exit(alice(), nonce), in_flight);
    w.yocto(carol(), now);
    assert_refused(&mut || w.dao.approve_exit(alice(), nonce), in_flight);
    w.yocto(carol(), now);
    assert_refused(&mut || w.dao.reject_exit(alice(), nonce), in_flight);

    assert!(w.view(alice(), at + 3_600 * S - 1).claim_in_flight);
    assert!(!w.view(alice(), at + 3_600 * S).claim_in_flight);
}

/// A vote is on an exit that still stands: past its claim window there is nothing to vote on.
#[test]
fn no_vote_on_an_exit_past_its_claim_window() {
    let mut w = World::new();
    w.owner_with_escrow(alice(), 60);
    w.yocto(alice(), T0);
    w.dao.set_exit_approvers(vec![bob()], 1);
    let nonce = w.initiate(alice(), T0);
    let past = T0 + 60 * S + ExitTiming::of_this_account().finalize_window_secs * S + S;
    w.yocto(bob(), past);
    assert_refused(&mut || w.dao.approve_exit(alice(), nonce), "no pending action with this nonce");
    w.yocto(bob(), past);
    assert_refused(&mut || w.dao.reject_exit(alice(), nonce), "no pending action with this nonce");
}

// ===== approvers =====

#[test]
fn the_first_set_takes_effect_at_once() {
    let mut w = World::new();
    w.register(alice(), None);
    w.yocto(alice(), T0);
    w.dao.set_exit_approvers(vec![bob(), carol()], 2);
    let v = w.view(alice(), T0);
    assert_eq!((v.approvers, v.threshold), (vec![bob(), carol()], 2));
    assert!(v.pending.is_none());
}

#[test]
fn a_set_must_be_well_formed() {
    let mut w = World::new();
    w.register(alice(), None);
    let mut refused = |approvers: Vec<AccountId>, threshold: u32, words: &str| {
        w.yocto(alice(), T0);
        assert_refused(&mut || w.dao.set_exit_approvers(approvers.clone(), threshold), words);
    };
    refused((0..17).map(|i| a(&format!("a{i}.testnet"))).collect(), 1, "at most 16 approvers");
    refused(vec![bob(), bob()], 1, "is listed twice");
    refused(vec![bob()], 0, "threshold must be between 1 and the number of approvers");
    refused(vec![bob()], 2, "threshold must be between 1 and the number of approvers");
    refused(vec![], 1, "an empty set takes threshold 0");
}

#[test]
#[should_panic(expected = "0 of 2 approvals")]
fn a_claim_needs_the_quorum() {
    let mut w = World::new();
    w.owner_with_escrow(alice(), 60);
    w.yocto(alice(), T0);
    w.dao.set_exit_approvers(vec![bob(), carol()], 2);
    w.initiate(alice(), T0);
    w.claim(alice(), T0 + 60 * S);
}

#[test]
fn a_claim_passes_with_the_quorum() {
    let mut w = World::new();
    w.owner_with_escrow(alice(), 60);
    w.yocto(alice(), T0);
    w.dao.set_exit_approvers(vec![bob(), carol()], 2);
    let nonce = w.initiate(alice(), T0);
    for who in [bob(), carol()] {
        w.yocto(who, T0 + S);
        w.dao.approve_exit(alice(), nonce);
    }
    w.claim(alice(), T0 + 60 * S);
    assert_eq!(ckd_path_requested(), "owner:alice.testnet:1");
}

#[test]
#[should_panic(expected = "0 of 1 approvals")]
fn a_set_named_after_the_exit_started_still_has_to_approve_it() {
    let mut w = World::new();
    w.owner_with_escrow(alice(), 60);
    w.initiate(alice(), T0);
    w.yocto(alice(), T0 + S);
    w.dao.set_exit_approvers(vec![bob()], 1);
    w.claim(alice(), T0 + 60 * S);
}

#[test]
fn votes_that_do_not_count() {
    let mut w = World::new();
    w.owner_with_escrow(alice(), 60);
    w.yocto(alice(), T0);
    w.dao.set_exit_approvers(vec![bob(), carol()], 2);
    let nonce = w.initiate(alice(), T0);
    let mut vote = |who: AccountId, nonce: u64, approve: bool| {
        w.yocto(who, T0 + S);
        why_refused(&mut || {
            if approve {
                w.dao.approve_exit(alice(), nonce)
            } else {
                w.dao.reject_exit(alice(), nonce)
            }
        })
    };
    let refused_with = |why: Option<String>, words: &str| {
        assert!(why.as_deref().is_some_and(|w| w.contains(words)), "{why:?} is not a refusal with {words:?}");
    };
    refused_with(vote(a("stranger.testnet"), nonce, true), "not an approver of this owner");
    refused_with(vote(bob(), nonce + 1, true), "no pending action with this nonce");
    assert_eq!(vote(bob(), nonce, true), None);
    refused_with(vote(bob(), nonce, true), "this account has voted on this action");
    refused_with(vote(bob(), nonce, false), "this account has voted on this action");
}

#[test]
#[should_panic(expected = "no exit is pending")]
fn one_reject_ends_the_exit() {
    let mut w = World::new();
    w.owner_with_escrow(alice(), 60);
    w.yocto(alice(), T0);
    w.dao.set_exit_approvers(vec![bob(), carol()], 1);
    let nonce = w.initiate(alice(), T0);
    w.yocto(bob(), T0 + S);
    w.dao.approve_exit(alice(), nonce);
    w.yocto(carol(), T0 + 2 * S);
    w.dao.reject_exit(alice(), nonce);
    w.claim(alice(), T0 + 60 * S);
}

#[test]
fn a_change_of_the_set_waits_for_the_old_sets_quorum() {
    let mut w = World::new();
    w.register(alice(), None);
    w.yocto(alice(), T0);
    w.dao.set_exit_approvers(vec![bob()], 1);
    w.yocto(alice(), T0);
    w.dao.set_exit_approvers(vec![carol()], 1);
    let v = w.view(alice(), T0);
    assert_eq!(v.approvers, vec![bob()]);
    let nonce = v.pending.unwrap().nonce;

    w.yocto(bob(), T0 + S);
    w.dao.approve_exit(alice(), nonce);
    let v = w.view(alice(), T0 + S);
    assert_eq!((v.approvers, v.threshold), (vec![carol()], 1));
    assert!(v.pending.is_none());
}

#[test]
fn removing_the_set_goes_through_the_quorum_and_a_reject_drops_it() {
    let mut w = World::new();
    w.register(alice(), None);
    w.yocto(alice(), T0);
    w.dao.set_exit_approvers(vec![bob()], 1);
    w.yocto(alice(), T0);
    w.dao.set_exit_approvers(vec![], 0);
    let nonce = w.view(alice(), T0).pending.unwrap().nonce;
    w.yocto(bob(), T0 + S);
    w.dao.reject_exit(alice(), nonce);
    let v = w.view(alice(), T0 + S);
    assert_eq!(v.approvers, vec![bob()]);
    assert!(v.pending.is_none());
}

#[test]
fn an_exit_and_a_change_of_the_set_exclude_each_other() {
    let mut w = World::new();
    w.owner_with_escrow(alice(), 60);
    w.yocto(alice(), T0);
    w.dao.set_exit_approvers(vec![bob()], 1);

    w.initiate(alice(), T0);
    w.yocto(alice(), T0 + S);
    assert_refused(&mut || w.dao.set_exit_approvers(vec![carol()], 1), "an action is already pending");

    w.yocto(alice(), T0 + S);
    w.dao.cancel_exit();
    w.yocto(alice(), T0 + S);
    w.dao.set_exit_approvers(vec![carol()], 1);
    w.call(alice(), T0 + 2 * S, EXIT_FEE);
    assert_refused(&mut || w.dao.initiate_exit(), "an action is already pending");
}

// ===== config =====

#[test]
fn the_config_shows_fees_and_timing() {
    let w = World::on("dao.outlayer.near");
    w.call(alice(), T0, NearToken::from_yoctonear(0));
    let c = w.dao.get_config();
    assert_eq!(c["exit"]["min_window_secs"], 86_400);
    assert_eq!(c["exit"]["max_window_secs"], 172_800);
    assert_eq!(c["exit"]["finalize_window_secs"], 604_800);
    assert_eq!(c["exit"]["registration_fee"], EXIT_REGISTRATION_FEE.as_yoctonear().to_string());
    assert_eq!(c["exit"]["exit_fee"], EXIT_FEE.as_yoctonear().to_string());
}
