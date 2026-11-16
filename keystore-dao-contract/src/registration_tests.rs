//! `submit_keystore_registration` end to end, on real data, against what a hostile submitter can
//! send.
//!
//! The fixtures are public data from testnet (`tests/fixtures/`):
//!   * `keystore_dal.json` — a real keystore's registration on `dao.outlayer.testnet` (#175): its
//!     public key, its TDX quote, and the RTMR3 events of its CVM, which replay to the quote's
//!     RTMR3;
//!   * `keystore_ams_quote.json` — another real keystore's quote (#177), of the same release and
//!     guest OS, whose CVM was redeployed since: no event log of it exists any more;
//!   * `keystore_ams_events.json` — the RTMR3 events of the CVM that replaced it: a genuine log of
//!     a third TD, same release, another instance;
//!   * `collaterals.json` — Intel's collateral as the DAO cached it, one slot per platform.
//!
//! Every test runs the whole method: the init-account check, the collateral by FMSPC, the dcap
//! verification of the quote, the event-log replay, the build lists, the key binding.

use crate::event_log::EventLogEntry;
use crate::*;
use near_sdk::mock::MockAction;
use near_sdk::serde_json::{self, Value};
use near_sdk::test_utils::{get_created_receipts, VMContextBuilder};
use near_sdk::testing_env;

const DAL: &str = include_str!("../tests/fixtures/keystore_dal.json");
const AMS_QUOTE: &str = include_str!("../tests/fixtures/keystore_ams_quote.json");
const AMS_EVENTS: &str = include_str!("../tests/fixtures/keystore_ams_events.json");
const COLLATERALS: &str = include_str!("../tests/fixtures/collaterals.json");
const V025: &str = include_str!("../tests/fixtures/keystore_v025.json");

fn a(s: &str) -> AccountId {
    s.parse().unwrap()
}
fn owner() -> AccountId {
    a("owner.testnet")
}
fn init() -> AccountId {
    a("init-keystore.testnet")
}
const MEMBERS: [&str; 3] = ["m1.testnet", "m2.testnet", "m3.testnet"];

struct Fixture {
    key: PublicKey,
    quote: String,
    events: Vec<EventLogEntry>,
    measurements: ApprovedMeasurements,
    compose_hash: String,
    instance_id: String,
    app_id: String,
    at_ns: u64,
}

fn json(s: &str) -> Value {
    serde_json::from_str(s).unwrap()
}

fn measurements_of(v: &Value) -> ApprovedMeasurements {
    serde_json::from_value(v["measurements"].clone()).unwrap()
}

fn events_of(v: &Value) -> Vec<EventLogEntry> {
    serde_json::from_value(v["rtmr3_events"].clone()).unwrap()
}

fn dal() -> Fixture {
    let v = json(DAL);
    Fixture {
        key: v["public_key"].as_str().unwrap().parse().unwrap(),
        quote: v["tdx_quote_hex"].as_str().unwrap().to_string(),
        events: events_of(&v),
        measurements: measurements_of(&v),
        compose_hash: v["compose_hash"].as_str().unwrap().to_string(),
        instance_id: v["instance_id"].as_str().unwrap().to_string(),
        app_id: v["app_id"].as_str().unwrap().to_string(),
        at_ns: v["registered_at_ns"].as_u64().unwrap(),
    }
}

/// A call from `who` at the moment the dal keystore registered (the collateral was valid then).
fn at(who: AccountId) {
    at_time(who, dal().at_ns);
}
fn at_time(who: AccountId, ns: u64) {
    let mut b = VMContextBuilder::new();
    b.current_account_id(a("dao.testnet"))
        .predecessor_account_id(who)
        .block_timestamp(ns)
        .attached_deposit(NearToken::from_near(1))
        .prepaid_gas(Gas::from_tgas(300));
    testing_env!(b.build());
}

/// A DAO with the cached collateral of both platforms and three members; nothing approved.
fn bare_dao() -> KeystoreDao {
    at(owner());
    let mut d = KeystoreDao::new(
        owner(),
        init(),
        MEMBERS.iter().map(|m| a(m)).collect(),
        a("v1.signer-prod.testnet"),
        Some(0),
    );
    for (i, c) in json(COLLATERALS)["collaterals"].as_array().unwrap().iter().enumerate() {
        d.update_collateral(c.as_str().unwrap().to_string(), i as u32);
    }
    d
}

/// The same, with the dal keystore's guest OS and release approved by governance.
fn dao() -> KeystoreDao {
    let mut d = bare_dao();
    let f = dal();
    at(a(MEMBERS[0]));
    for action in [
        GovAction::ApproveOsImage { image: OsImage::of(&f.measurements) },
        GovAction::ApproveCompose { compose_hash: f.compose_hash.clone() },
    ] {
        let id = d.propose(action);
        at(a(MEMBERS[1]));
        d.vote(id, true, None);
        let _ = d.execute(id);
        at(a(MEMBERS[0]));
    }
    d
}

fn submit(d: &mut KeystoreDao, key: &PublicKey, quote: &str, log: Vec<EventLogEntry>) -> u64 {
    at(init());
    d.submit_keystore_registration(key.clone(), quote.to_string(), None, log)
}

/// The panic message of `f`, or None when it returned.
fn refusal(f: impl FnOnce()) -> Option<String> {
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    r.err().map(|e| {
        e.downcast_ref::<String>()
            .cloned()
            .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default()
    })
}

fn assert_refused(f: impl FnOnce(), want: &str) {
    match refusal(f) {
        None => panic!("expected a refusal containing {want:?}, the call succeeded"),
        Some(msg) => assert!(msg.contains(want), "refused, but with {msg:?}, not {want:?}"),
    }
}

/// The quote with byte `i` changed.
fn flipped(quote: &str, i: usize) -> String {
    let mut b = hex::decode(quote).unwrap();
    b[i] ^= 0x01;
    hex::encode(b)
}

fn key_installed(key: &PublicKey) -> bool {
    get_created_receipts().iter().any(|r| {
        r.actions.iter().any(|act| matches!(act, MockAction::AddKeyWithFunctionCall { public_key, .. } if public_key.to_string() == String::from(key)))
    })
}

// ===== the genuine registration =====

#[test]
fn the_real_keystore_registers_and_states_its_release_and_instance() {
    let mut d = dao();
    let f = dal();
    let id = submit(&mut d, &f.key, &f.quote, f.events.clone());

    let p = d.get_proposal(id).unwrap();
    assert_eq!(p.status, ProposalStatus::Pending);
    assert_eq!(p.public_key, f.key);
    assert_eq!(p.measurements, f.measurements, "the measurements are the quote's");
    let facts = d.get_registration_facts(id).unwrap();
    assert_eq!(facts.compose_hash, f.compose_hash);
    assert_eq!(facts.instance_id, f.instance_id);
    assert_eq!(facts.app_id, f.app_id);
    assert!(facts.key_provider.len() > 2);
    assert!(d.approved_measurements.is_empty(), "registering records no measurements");
}

#[test]
fn two_members_voting_for_its_key_install_it_and_nothing_else_does() {
    let mut d = dao();
    let f = dal();
    let id = submit(&mut d, &f.key, &f.quote, f.events.clone());
    let other: PublicKey = json(AMS_QUOTE)["public_key"].as_str().unwrap().parse().unwrap();

    at(a(MEMBERS[0]));
    assert_refused(|| d.vote(id, true, Some(other.clone())), "is for another key");
    assert_refused(|| d.vote(id, true, None), "names its key");
    d.vote(id, true, Some(f.key.clone()));
    assert!(!d.is_keystore_approved(String::from(&f.key)));
    assert_refused(|| d.vote(id, true, Some(f.key.clone())), "Already voted");

    at(a("stranger.testnet"));
    assert_refused(|| d.vote(id, true, Some(f.key.clone())), "Only DAO members");

    at(a(MEMBERS[1]));
    d.vote(id, true, Some(f.key.clone()));
    assert_eq!(d.get_proposal(id).unwrap().status, ProposalStatus::Executed);
    assert!(d.is_keystore_approved(String::from(&f.key)));
    assert!(key_installed(&f.key), "the access key is added to the DAO account");
}

/// The registration exactly as keystore v0.2.5 sends it: the event log of dstack's quote API, whose
/// RTMR3 entries carry no digest.
#[test]
fn the_registration_as_the_keystore_sends_it_is_taken() {
    let v = json(V025);
    let events = events_of(&v);
    assert!(events.iter().all(|e| e.digest.is_empty()), "the fixture is the quote API's log");
    let key: PublicKey = v["public_key"].as_str().unwrap().parse().unwrap();
    let compose = v["compose_hash"].as_str().unwrap().to_string();

    let mut d = bare_dao();
    // The same guest OS as the dal fixture; the release is v0.2.5's.
    KeystoreDao::set_os_images(&vec![OsImage::of(&dal().measurements)]);
    KeystoreDao::set_composes(&vec![compose.clone()]);
    at_time(init(), v["registered_at_ns"].as_u64().unwrap());
    let id = d.submit_keystore_registration(key.clone(), v["tdx_quote_hex"].as_str().unwrap().to_string(), None, events);

    let facts = d.get_registration_facts(id).unwrap();
    assert_eq!(facts.compose_hash, compose);
    assert_eq!(facts.instance_id, v["instance_id"].as_str().unwrap());
    assert_eq!(facts.app_id, v["app_id"].as_str().unwrap());
    assert_eq!(d.get_proposal(id).unwrap().public_key, key);
}

// ===== who may submit, and with what collateral =====

#[test]
fn only_the_init_account_submits() {
    let mut d = dao();
    let f = dal();
    for who in [owner(), a(MEMBERS[0]), a("stranger.testnet")] {
        at(who.clone());
        assert_refused(
            || {
                d.submit_keystore_registration(f.key.clone(), f.quote.clone(), None, f.events.clone());
            },
            "Only init-keystore.testnet can submit",
        );
    }
}

#[test]
fn without_a_collateral_for_the_quotes_platform_nothing_is_verified() {
    let f = dal();
    let mut d = KeystoreDao::new(owner(), init(), vec![a(MEMBERS[0])], a("v1.signer-prod.testnet"), Some(0));
    assert_refused(|| { submit(&mut d, &f.key, &f.quote, f.events.clone()); }, "No quote collateral cached");

    // Only the other platform's slot.
    let cols = json(COLLATERALS);
    let fmspc = |c: &str| KeystoreDao::collateral_fmspc(c).unwrap_or_default();
    let quote_fmspc = hex::encode(
        dcap_qvl::quote::Quote::parse(&hex::decode(&f.quote).unwrap()).unwrap().fmspc().unwrap(),
    );
    let other = cols["collaterals"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_string())
        .find(|c| !fmspc(c).eq_ignore_ascii_case(&quote_fmspc))
        .expect("the fixture has a second platform");
    at(owner());
    d.update_collateral(other, 0);
    assert_refused(|| { submit(&mut d, &f.key, &f.quote, f.events.clone()); }, "No cached collateral for quote FMSPC");
}

#[test]
fn a_quote_checked_after_its_collateral_expired_is_refused() {
    let mut d = dao();
    let f = dal();
    let two_years = 2 * 365 * 24 * 3600 * 1_000_000_000u64;
    at_time(init(), f.at_ns + two_years);
    assert_refused(
        || {
            d.submit_keystore_registration(f.key.clone(), f.quote.clone(), None, f.events.clone());
        },
        "TDX quote verification failed",
    );
}

// ===== the quote =====

/// Where the quote's structure ends: the 48-byte header, the 584-byte TD report, the 4-byte
/// signature-data length, the signature data. dstack hands the quote in a larger buffer; the
/// bytes after this are zero padding that no parser reads.
fn quote_end(quote: &str) -> usize {
    let b = hex::decode(quote).unwrap();
    636 + u32::from_le_bytes(b[632..636].try_into().unwrap()) as usize
}

/// Where the n-th PEM certificate of the quote's chain starts (0: the PCK, 1: the intermediate
/// CA, 2: the copy of Intel's root).
fn cert_start(quote: &str, n: usize) -> usize {
    let b = hex::decode(quote).unwrap();
    let tag = b"-----BEGIN CERTIFICATE-----";
    (0..b.len() - tag.len()).filter(|&i| &b[i..i + tag.len()] == tag).nth(n).unwrap()
}

#[test]
fn any_changed_byte_of_the_quote_is_refused() {
    let mut d = dao();
    let f = dal();
    // The header, the TD report (MRTD at 48+136, RTMR3 at 48+472, report_data at 48+520), the
    // signature-data length (its second byte: 256 more), the ECDSA signature, the attestation key, the QE
    // report, the PCK certificate and the intermediate CA.
    let pck = cert_start(&f.quote, 0);
    let intermediate = cert_start(&f.quote, 1);
    for i in [0, 2, 20, 48 + 136, 48 + 472, 48 + 520, 48 + 520 + 31, 633, 640, 700, 1200, pck + 100, pck + 600, intermediate + 100, intermediate + 600] {
        let q = flipped(&f.quote, i);
        let msg = refusal(|| { submit(&mut d, &f.key, &q, f.events.clone()); });
        assert!(msg.is_some(), "a quote with byte {i} changed was taken");
    }
    assert!(d.get_proposals(0, 100).is_empty(), "nothing was registered");
}

/// The padding after the quote's structure is not attested. Changing a byte of it, or growing the
/// signature-data length by one so that the certificate chain takes in one zero byte of it, is
/// another encoding of the same quote: it registers, and states exactly what the quote does. So is a
/// change inside the copy of Intel's root certificate at the end of the chain.
#[test]
fn another_encoding_of_the_same_quote_states_nothing_else() {
    let f = dal();
    let end = quote_end(&f.quote);
    let len = hex::decode(&f.quote).unwrap().len();
    assert!(end < len, "the fixture carries padding");
    let mut d = dao();
    // The padding; the length grown into it; the copy of Intel's root the chain ends with, which
    // the verifier does not use (it checks the chain against its own copy, TRUSTED_ROOT_CA_DER).
    let root = cert_start(&f.quote, 2);
    for q in [flipped(&f.quote, len - 1), flipped(&f.quote, 632), flipped(&f.quote, root + 200)] {
        let id = submit(&mut d, &f.key, &q, f.events.clone());
        let p = d.get_proposal(id).unwrap();
        assert_eq!(p.public_key, f.key);
        assert_eq!(p.measurements, f.measurements);
        assert_eq!(d.get_registration_facts(id).unwrap().instance_id, f.instance_id);
        at(owner());
        d.reject_registration(id);
    }
}

#[test]
fn a_quote_that_is_not_one_is_refused() {
    let mut d = dao();
    let f = dal();
    for q in ["", "zz", "00", &f.quote[..f.quote.len() / 2], &"00".repeat(5006)] {
        let q = q.to_string();
        assert!(refusal(|| { submit(&mut d, &f.key, &q, f.events.clone()); }).is_some(), "quote {:?}… was taken", &q[..q.len().min(16)]);
    }
}

#[test]
fn a_key_the_quote_does_not_carry_is_refused() {
    let mut d = dao();
    let f = dal();
    let theirs: PublicKey = json(AMS_QUOTE)["public_key"].as_str().unwrap().parse().unwrap();
    assert_refused(|| { submit(&mut d, &theirs, &f.quote, f.events.clone()); }, "Public key mismatch");
    let made_up = PublicKey::from_parts(CurveType::ED25519, vec![7u8; 32]).unwrap();
    assert_refused(|| { submit(&mut d, &made_up, &f.quote, f.events.clone()); }, "Public key mismatch");
}

// ===== the event log =====

#[test]
fn the_log_of_another_td_is_refused_both_ways() {
    let mut d = dao();
    let f = dal();
    // A genuine log of a third CVM of the same release with this quote.
    let ams_events = events_of(&json(AMS_EVENTS));
    assert_refused(|| { submit(&mut d, &f.key, &f.quote, ams_events); }, "does not replay to the quote's RTMR3");
    // This CVM's log with another CVM's genuine quote.
    let ams = json(AMS_QUOTE);
    let ams_key: PublicKey = ams["public_key"].as_str().unwrap().parse().unwrap();
    assert_refused(
        || { submit(&mut d, &ams_key, ams["tdx_quote_hex"].as_str().unwrap(), f.events.clone()); },
        "does not replay to the quote's RTMR3",
    );
}

#[test]
fn a_changed_fact_is_refused_whether_or_not_its_digest_is_recomputed() {
    let mut d = dao();
    let f = dal();
    let ams = json(AMS_EVENTS);
    for (event, replacement) in [
        ("compose-hash", "ee".repeat(32)),
        ("instance-id", ams["instance_id"].as_str().unwrap().to_string()),
        ("app-id", "ee".repeat(20)),
        ("key-provider", hex::encode(br#"{"name":"none","id":""}"#)),
    ] {
        // Only the payload changed (the digest sent along is not used): the register changes.
        let mut log = f.events.clone();
        let i = log.iter().position(|e| e.event == event).unwrap();
        log[i].event_payload = replacement.clone();
        assert_refused(|| { submit(&mut d, &f.key, &f.quote, log); }, "does not replay to the quote's RTMR3");

        // The digest recomputed for the new payload: the register no longer matches the quote.
        let mut log = f.events.clone();
        log[i] = crate::event_log::tests::ev(3, event, &replacement);
        log[i].event_type = f.events[i].event_type;
        let mut h = sha2::Sha384::new();
        use sha2::Digest;
        h.update(log[i].event_type.to_le_bytes());
        h.update(b":");
        h.update(event.as_bytes());
        h.update(b":");
        h.update(hex::decode(&replacement).unwrap());
        log[i].digest = hex::encode(h.finalize());
        assert_refused(|| { submit(&mut d, &f.key, &f.quote, log); }, "does not replay to the quote's RTMR3");
    }
}

#[test]
fn a_reordered_shortened_or_extended_log_is_refused() {
    let mut d = dao();
    let f = dal();
    let mut swapped = f.events.clone();
    swapped.swap(1, 2);
    let mut dropped = f.events.clone();
    dropped.remove(4);
    let mut extended = f.events.clone();
    extended.push(crate::event_log::tests::ev(3, "app-event", "00"));
    for log in [swapped, dropped, extended] {
        assert!(refusal(|| { submit(&mut d, &f.key, &f.quote, log); }).is_some());
    }
}

#[test]
fn a_log_too_long_or_with_names_dstack_does_not_write_is_refused_before_any_work() {
    let mut d = dao();
    let f = dal();
    let mut long = f.events.clone();
    long.extend((0..64).map(|_| crate::event_log::tests::ev(3, "x", "")));
    assert_refused(|| { submit(&mut d, &f.key, &f.quote, long); }, "at most");

    let mut big = f.events.clone();
    big[0].event_payload = "00".repeat(600);
    assert_refused(|| { submit(&mut d, &f.key, &f.quote, big); }, "payload too long");

    let mut colon = f.events.clone();
    colon[0].event = "system-preparing:x".to_string();
    assert_refused(|| { submit(&mut d, &f.key, &f.quote, colon); }, "not one dstack writes");
}

// ===== the build =====

#[test]
fn nothing_registers_with_its_log_until_governance_approved_the_os_and_the_release() {
    let f = dal();
    let mut d = bare_dao();
    assert_refused(|| { submit(&mut d, &f.key, &f.quote, f.events.clone()); }, "Guest OS not approved");

    KeystoreDao::set_os_images(&vec![OsImage::of(&f.measurements)]);
    assert_refused(|| { submit(&mut d, &f.key, &f.quote, f.events.clone()); }, "Compose not approved");

    KeystoreDao::set_composes(&vec![f.compose_hash.clone()]);
    KeystoreDao::set_os_images(&vec![]);
    assert_refused(|| { submit(&mut d, &f.key, &f.quote, f.events.clone()); }, "Guest OS not approved");
}

#[test]
fn the_owner_removing_the_release_stops_a_registration_that_waits_for_its_votes() {
    let mut d = dao();
    let f = dal();
    let id = submit(&mut d, &f.key, &f.quote, f.events.clone());
    at(a(MEMBERS[0]));
    d.vote(id, true, Some(f.key.clone()));
    at(owner());
    d.remove_approved_compose(f.compose_hash.clone());
    at(a(MEMBERS[1]));
    d.vote(id, true, Some(f.key.clone()));
    assert_eq!(d.get_proposal(id).unwrap().status, ProposalStatus::Rejected);
    assert!(!key_installed(&f.key));
}

#[test]
fn without_its_log_nothing_registers_even_under_an_approved_build() {
    // The event log is the only evidence of which code runs: a registration without one is not
    // a thing the contract takes (the argument is required).
    let mut d = dao();
    let f = dal();
    assert_refused(|| { submit(&mut d, &f.key, &f.quote, vec![]); }, "Event log refused");
}

// ===== submitted again =====

#[test]
fn the_same_registration_sent_again_is_the_same_id_and_takes_no_other_key() {
    let mut d = dao();
    let f = dal();
    let id = submit(&mut d, &f.key, &f.quote, f.events.clone());
    assert_eq!(submit(&mut d, &f.key, &f.quote, f.events.clone()), id);
    // Garbage under the same key while the registration waits: the same id, and nothing about
    // the registration changes.
    assert_eq!(submit(&mut d, &f.key, "00", vec![]), id);
    assert_eq!(d.get_proposal(id).unwrap().measurements, f.measurements);
    assert_eq!(d.get_registration_facts(id).unwrap().instance_id, f.instance_id);
    assert_eq!(d.get_proposals(0, 100).len(), 1);
}
