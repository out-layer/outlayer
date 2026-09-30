//! `wasi-examples/caller-gate-probe`: the `callers` block read out of the
//! bytes that run, and judged against every door.
//!
//! The matrix here is the one `tests/caller_gate_e2e.sh` runs live, decided on
//! the artefacts it publishes: which build admits a direct call, a call
//! through `relay.outlayer-alice.testnet`, a call through another contract, a
//! meta-transaction and an HTTPS call.
//!
//! Run with: cargo test --test caller_gate_probe
//! The probe must be built first: wasi-examples/caller-gate-probe/build.sh

use std::path::PathBuf;

use offchainvm_worker::callers::{admit, RunCaller};
use offchainvm_worker::connector_manifest::manifest_from_wasm;

fn probe(variant: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join(format!("wasi-examples/caller-gate-probe/target/variants/caller-gate-probe-{variant}.wasm"));
    if !path.exists() {
        panic!(
            "Test WASM not found at {}! Build it first:\n\
             cd ../wasi-examples/caller-gate-probe && ./build.sh",
            path.display()
        );
    }
    std::fs::read(&path).expect("read the probe")
}

const ALICE: &str = "outlayer-alice.testnet";
const RELAY: &str = "relay.outlayer-alice.testnet";
const DEPUTY: &str = "deputy.outlayer-alice.testnet";
const BOB: &str = "outlayer-bob.testnet";

/// The doors, in the order of the matrix's columns.
fn doors() -> [(&'static str, RunCaller<'static>); 5] {
    [
        ("direct", RunCaller { is_https_call: false, user_account_id: Some(ALICE), predecessor_id: Some(ALICE), relayer_id: None }),
        ("relay", RunCaller { is_https_call: false, user_account_id: Some(ALICE), predecessor_id: Some(RELAY), relayer_id: None }),
        ("deputy", RunCaller { is_https_call: false, user_account_id: Some(ALICE), predecessor_id: Some(DEPUTY), relayer_id: None }),
        ("meta_tx", RunCaller { is_https_call: false, user_account_id: Some(ALICE), predecessor_id: Some(ALICE), relayer_id: Some(BOB) }),
        ("https", RunCaller { is_https_call: true, user_account_id: Some(ALICE), predecessor_id: Some(ALICE), relayer_id: None }),
    ]
}

#[test]
fn every_build_admits_exactly_its_doors() {
    //            variant           direct relay  deputy meta_tx https
    let matrix: [(&str, [bool; 5]); 8] = [
        ("open", [true, true, true, true, true]),
        ("open-v2", [true, true, true, true, true]),
        ("direct-only", [true, false, false, false, false]),
        ("contract-any", [false, true, true, false, false]),
        ("contract-relay", [false, true, false, false, false]),
        ("contract-deputy", [false, false, true, false, false]),
        ("https-only", [false, false, false, false, true]),
        ("meta-tx", [true, false, false, true, true]),
    ];
    for (variant, admitted) in matrix {
        let manifest = manifest_from_wasm(&probe(variant))
            .unwrap_or_else(|e| panic!("{variant}: {e}"))
            .unwrap_or_else(|| panic!("{variant} carries a manifest"));
        assert_eq!(manifest.callers.is_none(), variant.starts_with("open"), "{variant}");
        for ((door, run), want) in doors().iter().zip(admitted) {
            let verdict = admit(manifest.callers.as_ref(), run);
            assert_eq!(verdict.is_ok(), want, "{variant} through {door}: {verdict:?}");
            if let Err(sentence) = verdict {
                assert!(sentence.starts_with("This project's manifest"), "{sentence}");
                assert!(sentence.ends_with("Nothing was executed."), "{sentence}");
                if variant == "contract-relay" {
                    assert!(!sentence.contains(RELAY), "the allowlist is never listed: {sentence}");
                }
            }
        }
    }
}

#[test]
fn tasks_with_the_direct_door_shut_do_not_parse() {
    let err = manifest_from_wasm(&probe("tasks-direct-deny")).unwrap_err();
    assert!(err.contains("declares tasks") && err.contains("does not admit direct calls"), "{err}");
}
