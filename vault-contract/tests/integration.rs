#![allow(unused_must_use, dead_code)]

//! Integration tests for vault-contract running on near-sandbox.
//!
//! Each test spins up a fresh sandbox, deploys the vault contract and a
//! mock keystore-dao that exposes the cross-contract surface vault talks
//! to (`is_keystore_approved`, `is_ceased`). The mock has additional
//! test-only setters (`set_ceased`, `approve_keystore`, ...) so each
//! scenario can flip the gates between calls.
//!
//! WASMs are built once at test startup (via `near_workspaces::compile_project`)
//! and shared across sub-tests through a `tokio::sync::OnceCell`.

use anyhow::{anyhow, Result};
use near_workspaces::network::Sandbox;
use near_workspaces::result::ExecutionFinalResult;
use near_workspaces::types::{KeyType, NearToken, PublicKey, SecretKey};
use near_workspaces::{Account, Contract, Worker};
use serde_json::{json, Value};
use tokio::sync::OnceCell;

// Timing values are imported directly from the contract crate so they
// always match what the freshly-compiled sandbox WASM has baked in.
// When `vault-contract/src/lib.rs` is set to mainnet pacing (7-day
// cessation etc.), this suite cannot run — sandbox `fast_forward` won't
// cover 7 days in a reasonable test budget. Temporarily lower the
// constants in `lib.rs` for sandbox QA, then restore mainnet values.
const ONE_SECOND_NS: u64 = 1_000_000_000;
const DAY_SECS: u64 = 24 * 60 * 60;
use vault_contract::{
    CESSATION_DELAY_NS, FINALIZE_WINDOW_NS,
    MAX_UNILATERAL_EXIT_WINDOW_SECS, MIN_UNILATERAL_EXIT_WINDOW_SECS,
};
// Tests use the helper below to advance the sandbox by a target
// number of *real timestamp seconds* — robust to per-block-timestamp
// variance across sandbox versions.

/// Advance `worker` until `block_timestamp` is at least
/// `target_advance_secs` ahead of the timestamp at this call. Loops
/// `fast_forward` in 100-block chunks and re-reads the timestamp;
/// guarantees the wall-clock check inside the contract sees the right
/// time regardless of the sandbox's per-block delta.
async fn fast_forward_secs(worker: &Worker<Sandbox>, target_advance_secs: u64) -> Result<()> {
    let start = worker.view_block().await?.timestamp();
    let target = start + target_advance_secs * ONE_SECOND_NS;
    let mut total_blocks: u64 = 0;
    loop {
        worker.fast_forward(100).await?;
        total_blocks += 100;
        let now = worker.view_block().await?.timestamp();
        if now >= target {
            return Ok(());
        }
        // Safety valve: 50 000 blocks is far beyond what any test
        // legitimately needs, even at extreme low per-block deltas.
        if total_blocks > 50_000 {
            return Err(anyhow!(
                "fast_forward_secs gave up after {} blocks (advanced {} ns of {} ns target)",
                total_blocks,
                now.saturating_sub(start),
                target_advance_secs * ONE_SECOND_NS
            ));
        }
    }
}

/// Comfortably in the contract's `[MIN, MAX]_UNILATERAL_EXIT_WINDOW_SECS`
/// range so tests can pick a window without bumping into the bounds.
/// Picks 2× MIN if there's room, else just MIN.
const TEST_UNILATERAL_WINDOW_SECS: u64 = {
    let doubled = MIN_UNILATERAL_EXIT_WINDOW_SECS * 2;
    if doubled <= MAX_UNILATERAL_EXIT_WINDOW_SECS {
        doubled
    } else {
        MIN_UNILATERAL_EXIT_WINDOW_SECS
    }
};

/// Stand-in pubkey for `finalize_recovery(new_parent_pubkey)` calls
/// in tests that don't otherwise care about the key-swap mechanics —
/// they assert state transitions, not the on-chain access-key list.
/// Generated once at compile time from a fixed secret so the value is
/// stable across runs.
fn test_recovery_pubkey() -> PublicKey {
    SecretKey::from_seed(KeyType::ED25519, "test-recovery-pubkey").public_key()
}

// ============================================================
// Fixture compilation (cached across all tests in this binary)
// ============================================================

static VAULT_WASM: OnceCell<Vec<u8>> = OnceCell::const_new();
static MOCK_DAO_WASM: OnceCell<Vec<u8>> = OnceCell::const_new();

/// Build the vault contract with `--features test-timing` so the recovery
/// delays collapse to 30 s. Uses `cargo near build non-reproducible-wasm`
/// — the same toolchain production uses — because plain
/// `cargo build --target wasm32-unknown-unknown` produces a WASM whose
/// preamble NEAR's contract runtime rejects (`PrepareError(Deserialization)`).
fn build_with_features(manifest_dir: &str, features: &[&str]) -> Vec<u8> {
    use std::process::Command;

    let mut args: Vec<String> = vec![
        "near".into(),
        "build".into(),
        "non-reproducible-wasm".into(),
        "--no-abi".into(),
        // cargo-near 0.20.x refuses to build WASM with rustc >= 1.87
        // ("compiled with 1.87.0 or newer rust toolchain is currently
        // not compatible with nearcore VM"). The integration suite is
        // invoked with `cargo +1.88.0 test` so dev-deps compile cleanly
        // (time-macros requires 1.88), but the contract WASM itself
        // must still come out of 1.85.0 to satisfy nearcore — so we
        // shell out with an explicit override that wins over the
        // `RUSTUP_TOOLCHAIN=1.88.0` env var the parent cargo sets.
        "--override-toolchain".into(),
        "1.85.0".into(),
        "--manifest-path".into(),
        format!("{}/Cargo.toml", manifest_dir),
    ];
    if !features.is_empty() {
        args.push("--features".into());
        args.push(features.join(","));
    }

    let output = Command::new("cargo")
        .args(&args)
        .output()
        .expect("invoke cargo near build");
    assert!(
        output.status.success(),
        "cargo near build failed for {} (features={:?})\nstdout:\n{}\nstderr:\n{}",
        manifest_dir,
        features,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Extract crate name from the directory's Cargo.toml so this helper
    // works for both vault-contract and mock-keystore-dao.
    let cargo_toml = std::fs::read_to_string(format!("{}/Cargo.toml", manifest_dir))
        .expect("read Cargo.toml");
    let crate_name = cargo_toml
        .lines()
        .find_map(|l| {
            l.trim()
                .strip_prefix("name")
                .and_then(|rest| rest.trim().strip_prefix("="))
                .map(|v| v.trim().trim_matches('"').to_string())
        })
        .expect("find name in Cargo.toml");
    let wasm_name = crate_name.replace('-', "_");

    let wasm_path = format!("{}/target/near/{}.wasm", manifest_dir, wasm_name);
    std::fs::read(&wasm_path).unwrap_or_else(|e| panic!("read {}: {}", wasm_path, e))
}

async fn vault_wasm() -> &'static [u8] {
    VAULT_WASM
        .get_or_init(|| async { build_with_features(".", &["test-timing"]) })
        .await
}

async fn mock_dao_wasm() -> &'static [u8] {
    MOCK_DAO_WASM
        .get_or_init(|| async { build_with_features("./tests/mock-keystore-dao", &[]) })
        .await
}

// ============================================================
// Test harness
// ============================================================

/// Live handles to the deployed contracts in a fresh sandbox.
struct Setup {
    worker: Worker<Sandbox>,
    /// Customer's "alice.<root>" parent account.
    parent: Account,
    /// Vault deployed at "vault.alice.<root>" by `parent`.
    vault: Contract,
    /// Mock keystore-dao deployed at "dao.<root>".
    dao: Contract,
    /// Stand-in for the MPC contract — just a plain account so we can
    /// reference it as receiver of the TEE function-call key. Vault never
    /// actually calls into it during these tests.
    mpc: Account,
}

impl Setup {
    /// `initial_exit_window` of `None` selects the contract's default
    /// (24h) so the vault is callable for unilateral recovery without
    /// needing a `set_exit_window` call first.
    async fn new(initial_exit_window: Option<u64>) -> Result<Self> {
        let worker = near_workspaces::sandbox().await?;
        let root = worker.root_account()?;

        // Mock keystore-dao at "dao.<root>"
        let dao = root
            .create_subaccount("dao")
            .initial_balance(NearToken::from_near(20))
            .transact()
            .await?
            .into_result()?
            .deploy(mock_dao_wasm().await)
            .await?
            .into_result()?;
        dao.call("new").max_gas().transact().await?.into_result()?;

        // Plain account standing in for the MPC contract.
        let mpc = root
            .create_subaccount("mpc")
            .initial_balance(NearToken::from_near(5))
            .transact()
            .await?
            .into_result()?;

        // Customer's parent account.
        let parent = root
            .create_subaccount("alice")
            .initial_balance(NearToken::from_near(50))
            .transact()
            .await?
            .into_result()?;

        // Customer creates `vault.alice.<root>` as a sub-account of their
        // parent account, and deploys the vault contract.
        let vault_account = parent
            .create_subaccount("vault")
            .initial_balance(NearToken::from_near(20))
            .transact()
            .await?
            .into_result()?;
        let vault = vault_account.deploy(vault_wasm().await).await?.into_result()?;

        let mut init_args = json!({
            "parent": parent.id(),
            "keystore_dao": dao.id(),
            "mpc_contract": mpc.id(),
        });
        if let Some(secs) = initial_exit_window {
            init_args["initial_exit_window"] = json!(secs);
        }
        vault
            .call("new")
            .args_json(init_args)
            .max_gas()
            .transact()
            .await?
            .into_result()?;

        Ok(Self {
            worker,
            parent,
            vault,
            dao,
            mpc,
        })
    }

    async fn dao_set_ceased(&self, ceased: bool) -> Result<()> {
        self.dao
            .call("set_ceased")
            .args_json(json!({ "value": ceased }))
            .max_gas()
            .transact()
            .await?
            .into_result()?;
        Ok(())
    }

    async fn dao_approve_keystore(&self, public_key: &PublicKey) -> Result<()> {
        self.dao
            .call("approve_keystore")
            .args_json(json!({ "public_key": public_key.to_string() }))
            .max_gas()
            .transact()
            .await?
            .into_result()?;
        Ok(())
    }

    async fn vault_state(&self) -> Result<Value> {
        let v: Value = self.vault.view("get_state").await?.json()?;
        Ok(v)
    }

    async fn vault_has_access_key(&self, pk: &PublicKey) -> Result<bool> {
        Ok(self.vault.as_account().view_access_key(pk).await.is_ok())
    }
}

/// Generate a deterministic ed25519 keypair for repeatable test fixtures.
fn seeded_key(seed: &str) -> (SecretKey, PublicKey) {
    let sk = SecretKey::from_seed(KeyType::ED25519, seed);
    let pk = sk.public_key();
    (sk, pk)
}

/// Convenience — a successful execution that did not panic but may have
/// returned `false` from a callback. We only assert that no receipt
/// failed; payload assertions live in each test.
fn expect_success(outcome: ExecutionFinalResult) -> Result<ExecutionFinalResult> {
    if outcome.is_failure() {
        return Err(anyhow!(
            "tx failed:\n  failures: {:#?}\n  logs: {:#?}",
            outcome.failures(),
            outcome.logs()
        ));
    }
    Ok(outcome)
}

// ============================================================
// Sandbox timing probe (diagnostic)
// ============================================================

/// Probes the actual `block_timestamp` delta per `fast_forward(N)` call.
/// Diagnostic-only — `#[ignore]`'d so it does not run on every CI cycle.
/// Run with `cargo test --test integration -- --ignored --nocapture
/// probe_block_timestamp_delta` if a timing test misbehaves.
#[ignore = "diagnostic — use to inspect sandbox per-block timestamp delta"]
#[tokio::test]
async fn probe_block_timestamp_delta() -> Result<()> {
    let s = Setup::new(None).await?;

    let t0 = s.worker.view_block().await?.timestamp();
    s.worker.fast_forward(100).await?;
    let t1 = s.worker.view_block().await?.timestamp();
    s.worker.fast_forward(1000).await?;
    let t2 = s.worker.view_block().await?.timestamp();

    let d100 = t1.saturating_sub(t0);
    let d1000 = t2.saturating_sub(t1);
    eprintln!(
        "PROBE: fast_forward(100) advanced {} ns ({:.2}s); fast_forward(1000) advanced {} ns ({:.2}s)",
        d100,
        d100 as f64 / 1e9,
        d1000,
        d1000 as f64 / 1e9,
    );
    eprintln!(
        "PROBE: per-block delta ≈ {:.3}s (avg over 1000-block fast_forward)",
        (d1000 as f64 / 1e9) / 1000.0
    );
    Ok(())
}

// ============================================================
// propose_tee_key
// ============================================================

#[tokio::test]
async fn propose_tee_key_happy_path_adds_function_call_key() -> Result<()> {
    let s = Setup::new(None).await?;
    let (_sk, pk) = seeded_key("tee_v1");
    s.dao_approve_keystore(&pk).await?;

    let outcome = s
        .vault
        .call("propose_tee_key")
        .args_json(json!({ "public_key": pk.to_string() }))
        .max_gas()
        .transact()
        .await?;
    expect_success(outcome)?;

    // Recorded in vault state...
    let state = s.vault_state().await?;
    let registered = state["registered_tee_keys"]
        .as_array()
        .expect("registered_tee_keys is array");
    assert_eq!(registered.len(), 1);
    assert_eq!(registered[0].as_str().unwrap(), pk.to_string());

    // ...and actually present in the on-chain access-key list.
    assert!(
        s.vault_has_access_key(&pk).await?,
        "TEE function-call key was not added to the vault account"
    );
    Ok(())
}

#[tokio::test]
async fn propose_tee_key_rejected_when_not_dao_approved() -> Result<()> {
    let s = Setup::new(None).await?;
    let (_sk, pk) = seeded_key("not_approved_v1");
    // Note: DAO does NOT approve this pubkey.

    let outcome = s
        .vault
        .call("propose_tee_key")
        .args_json(json!({ "public_key": pk.to_string() }))
        .max_gas()
        .transact()
        .await?;
    assert!(
        outcome.is_failure(),
        "expected propose_tee_key to fail when key not approved"
    );

    let state = s.vault_state().await?;
    assert!(state["registered_tee_keys"].as_array().unwrap().is_empty());
    assert!(!s.vault_has_access_key(&pk).await?);
    Ok(())
}

#[tokio::test]
async fn propose_tee_key_rejects_duplicate_after_first_success() -> Result<()> {
    let s = Setup::new(None).await?;
    let (_sk, pk) = seeded_key("tee_dup");
    s.dao_approve_keystore(&pk).await?;

    expect_success(
        s.vault
            .call("propose_tee_key")
            .args_json(json!({ "public_key": pk.to_string() }))
            .max_gas()
            .transact()
            .await?,
    )?;

    let outcome = s
        .vault
        .call("propose_tee_key")
        .args_json(json!({ "public_key": pk.to_string() }))
        .max_gas()
        .transact()
        .await?;
    assert!(outcome.is_failure(), "duplicate should be rejected");
    Ok(())
}

#[tokio::test]
async fn propose_tee_key_after_dao_revokes_old_key_rejects_new_unapproved_attempt() -> Result<()> {
    // Scenario: DAO approves pk_a, vault registers it, then DAO revokes
    // pk_a. A subsequent propose for an unrelated unapproved pk_b must
    // fail at the cross-contract callback. This is the tightest test of
    // the callback-side `require!(approved, ...)` branch we can write
    // without inducing an in-block race that near-sandbox cannot
    // reproduce. The synchronous "never approved" path is covered by
    // `propose_tee_key_rejected_when_not_dao_approved`; the *unit* test
    // `callback_add_tee_key_panics_when_dao_returns_false` in lib.rs
    // exercises the callback branch directly.
    let s = Setup::new(None).await?;
    let (_sk, pk_a) = seeded_key("approved_then_revoked");
    s.dao_approve_keystore(&pk_a).await?;

    expect_success(
        s.vault
            .call("propose_tee_key")
            .args_json(json!({ "public_key": pk_a.to_string() }))
            .max_gas()
            .transact()
            .await?,
    )?;
    assert!(s.vault_has_access_key(&pk_a).await?);

    s.dao
        .call("revoke_keystore")
        .args_json(json!({ "public_key": pk_a.to_string() }))
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    let (_sk, pk_b) = seeded_key("attacker_after_revoke");
    let outcome = s
        .vault
        .call("propose_tee_key")
        .args_json(json!({ "public_key": pk_b.to_string() }))
        .max_gas()
        .transact()
        .await?;
    assert!(
        outcome.is_failure(),
        "propose for unapproved key after a revoke must fail"
    );
    assert!(!s.vault_has_access_key(&pk_b).await?);
    Ok(())
}

#[tokio::test]
async fn propose_tee_key_enforces_max_registered_cap() -> Result<()> {
    // I-8 coverage: vault refuses TEE-key registration past
    // MAX_REGISTERED_TEE_KEYS (32). We exercise the cap by stubbing the
    // vault state directly via `near_workspaces::patch_state` would be
    // invasive, so we drive the cap via a smaller fixture: deploy with
    // MAX-1 keys already registered (impossible in current API) — instead
    // we just verify that the synchronous require! check fires by
    // submitting 33 distinct approved keys and inspecting the last
    // outcome. Costs ~30 sandbox tx but proves the cap.
    //
    // Performance note: this test does ~32 cross-contract round-trips,
    // so it's slower than the rest. The cap value (32) is small enough
    // to do this in real time.
    let s = Setup::new(None).await?;

    for i in 0..32u32 {
        let (_sk, pk) = seeded_key(&format!("cap_test_{}", i));
        s.dao_approve_keystore(&pk).await?;
        expect_success(
            s.vault
                .call("propose_tee_key")
                .args_json(json!({ "public_key": pk.to_string() }))
                .max_gas()
                .transact()
                .await?,
        )?;
    }

    // 33rd key: approve, propose, expect failure with cap message.
    let (_sk, pk_33) = seeded_key("cap_test_33");
    s.dao_approve_keystore(&pk_33).await?;
    let outcome = s
        .vault
        .call("propose_tee_key")
        .args_json(json!({ "public_key": pk_33.to_string() }))
        .max_gas()
        .transact()
        .await?;
    assert!(outcome.is_failure(), "33rd propose_tee_key must fail at cap");
    let stderr = format!("{:?}", outcome.failures());
    assert!(
        stderr.contains("TEE key limit reached") || stderr.contains("max 32"),
        "expected cap error message, got: {}",
        stderr
    );
    Ok(())
}

// ============================================================
// Cessation-triggered recovery
// ============================================================

#[tokio::test]
async fn cessation_initiate_rejected_when_dao_not_ceased() -> Result<()> {
    let s = Setup::new(None).await?;
    // dao.is_ceased == false by default

    let outcome = s
        .vault
        .call("initiate_recovery")
        .max_gas()
        .transact()
        .await?;
    assert!(outcome.is_failure(), "initiate must fail when DAO not ceased");
    let state = s.vault_state().await?;
    assert!(state["recovery"].is_null());
    Ok(())
}

#[tokio::test]
async fn cessation_initiate_succeeds_when_dao_ceased() -> Result<()> {
    let s = Setup::new(None).await?;
    s.dao_set_ceased(true).await?;

    expect_success(
        s.vault
            .call("initiate_recovery")
            .max_gas()
            .transact()
            .await?,
    )?;

    let state = s.vault_state().await?;
    let recovery = &state["recovery"];
    assert!(recovery.is_object(), "recovery state should be set");
    assert_eq!(recovery["trigger"], "Cessation");

    let initiated_at = recovery["initiated_at"].as_u64().unwrap();
    let finalize_after = recovery["finalize_after"].as_u64().unwrap();
    let finalize_before = recovery["finalize_before"].as_u64().unwrap();
    assert_eq!(finalize_after - initiated_at, CESSATION_DELAY_NS);
    assert_eq!(finalize_before - finalize_after, FINALIZE_WINDOW_NS);
    Ok(())
}

#[tokio::test]
async fn cessation_full_happy_path_unlocks_after_7d() -> Result<()> {
    let s = Setup::new(None).await?;
    s.dao_set_ceased(true).await?;

    expect_success(
        s.vault
            .call("initiate_recovery")
            .max_gas()
            .transact()
            .await?,
    )?;

    fast_forward_secs(&s.worker, (CESSATION_DELAY_NS / ONE_SECOND_NS).max(TEST_UNILATERAL_WINDOW_SECS) + 30).await?;

    let outcome = expect_success(
        s.parent
            .call(s.vault.id(), "finalize_recovery")
            .args_json(json!({"new_parent_pubkey": test_recovery_pubkey().to_string()}))
            .max_gas()
            .transact()
            .await?,
    )?;
    // finalize_recovery now returns PromiseOrValue::Promise on the
    // success path (the key-swap actions have no return value), so
    // we assert correctness via the post-finalize vault state below.
    let _ = outcome;

    let state = s.vault_state().await?;
    assert!(state["unlocked"].as_bool().unwrap_or(false));
    assert!(state["recovery"].is_null());
    Ok(())
}

#[tokio::test]
async fn cessation_recovery_cancelled_if_dao_revokes() -> Result<()> {
    let s = Setup::new(None).await?;
    s.dao_set_ceased(true).await?;
    expect_success(
        s.vault
            .call("initiate_recovery")
            .max_gas()
            .transact()
            .await?,
    )?;

    // DAO changes its mind during the 7-day window.
    s.dao_set_ceased(false).await?;
    fast_forward_secs(&s.worker, (CESSATION_DELAY_NS / ONE_SECOND_NS).max(TEST_UNILATERAL_WINDOW_SECS) + 30).await?;

    let outcome = expect_success(
        s.parent
            .call(s.vault.id(), "finalize_recovery")
            .args_json(json!({"new_parent_pubkey": test_recovery_pubkey().to_string()}))
            .max_gas()
            .transact()
            .await?,
    )?;
    let returned: bool = outcome.json()?;
    assert!(!returned, "finalize must report cancellation");

    let state = s.vault_state().await?;
    assert!(!state["unlocked"].as_bool().unwrap_or(false));
    assert!(state["recovery"].is_null(), "state should be cleared");
    Ok(())
}

#[tokio::test]
async fn cessation_finalize_after_14d_clears_state() -> Result<()> {
    let s = Setup::new(None).await?;
    s.dao_set_ceased(true).await?;
    expect_success(
        s.vault
            .call("initiate_recovery")
            .max_gas()
            .transact()
            .await?,
    )?;

    // Past finalize_before (CESSATION_DELAY + FINALIZE_WINDOW + buffer).
    fast_forward_secs(
        &s.worker,
        ((CESSATION_DELAY_NS + FINALIZE_WINDOW_NS) / ONE_SECOND_NS) + 30,
    )
    .await?;

    let outcome = expect_success(
        s.parent
            .call(s.vault.id(), "finalize_recovery")
            .args_json(json!({"new_parent_pubkey": test_recovery_pubkey().to_string()}))
            .max_gas()
            .transact()
            .await?,
    )?;
    let returned: bool = outcome.json()?;
    assert!(!returned, "expired window must report false");

    let state = s.vault_state().await?;
    assert!(!state["unlocked"].as_bool().unwrap_or(false));
    assert!(state["recovery"].is_null());
    Ok(())
}

// ============================================================
// Unilateral-triggered recovery
// ============================================================

#[tokio::test]
async fn unilateral_initiate_rejects_non_parent() -> Result<()> {
    let s = Setup::new(None).await?;
    let stranger = s
        .worker
        .root_account()?
        .create_subaccount("eve")
        .initial_balance(NearToken::from_near(10))
        .transact()
        .await?
        .into_result()?;

    let outcome = stranger
        .call(s.vault.id(), "unilateral_initiate_recovery")
        .max_gas()
        .transact()
        .await?;
    assert!(outcome.is_failure(), "non-parent must be rejected");

    let state = s.vault_state().await?;
    assert!(state["recovery"].is_null());
    Ok(())
}

#[tokio::test]
async fn unilateral_finalize_rejects_non_parent_after_window() -> Result<()> {
    // Sandbox-level coverage of the front-running fix: even AFTER the
    // unilateral exit window has elapsed (when finalize is otherwise
    // ready to run), a non-parent caller must be bounced. Without
    // this gate, any chain-watcher could substitute their own pubkey
    // during the atomic key-swap and hijack the vault.
    let s = Setup::new(Some(TEST_UNILATERAL_WINDOW_SECS)).await?;
    expect_success(
        s.parent
            .call(s.vault.id(), "unilateral_initiate_recovery")
            .max_gas()
            .transact()
            .await?,
    )?;
    fast_forward_secs(
        &s.worker,
        (CESSATION_DELAY_NS / ONE_SECOND_NS).max(TEST_UNILATERAL_WINDOW_SECS) + 30,
    )
    .await?;

    let stranger = s
        .worker
        .root_account()?
        .create_subaccount("eve")
        .initial_balance(NearToken::from_near(10))
        .transact()
        .await?
        .into_result()?;

    let outcome = stranger
        .call(s.vault.id(), "finalize_recovery")
        .args_json(json!({"new_parent_pubkey": test_recovery_pubkey().to_string()}))
        .max_gas()
        .transact()
        .await?;
    assert!(outcome.is_failure(), "non-parent finalize must be rejected");

    // Vault MUST remain locked with recovery state intact — the
    // parent should be able to drive the same finalize themselves
    // without re-initiating.
    let state_after_reject = s.vault_state().await?;
    assert_eq!(
        state_after_reject["unlocked"].as_bool().unwrap(),
        false,
        "vault must remain locked after a rejected non-parent finalize"
    );
    assert_eq!(
        state_after_reject["recovery"]["trigger"], "Unilateral",
        "recovery state must survive a rejected non-parent finalize"
    );

    // Now the parent can complete the same recovery in-window.
    expect_success(
        s.parent
            .call(s.vault.id(), "finalize_recovery")
            .args_json(json!({"new_parent_pubkey": test_recovery_pubkey().to_string()}))
            .max_gas()
            .transact()
            .await?,
    )?;
    let state_after_parent = s.vault_state().await?;
    assert!(state_after_parent["unlocked"].as_bool().unwrap());
    assert!(state_after_parent["recovery"].is_null());
    Ok(())
}

#[tokio::test]
async fn unilateral_full_happy_path_24h_window() -> Result<()> {
    let s = Setup::new(Some(TEST_UNILATERAL_WINDOW_SECS)).await?; // 24h
    expect_success(
        s.parent
            .call(s.vault.id(), "unilateral_initiate_recovery")
            .max_gas()
            .transact()
            .await?,
    )?;

    let state_before = s.vault_state().await?;
    assert_eq!(state_before["recovery"]["trigger"], "Unilateral");

    // 24h + safety margin.
    fast_forward_secs(&s.worker, (CESSATION_DELAY_NS / ONE_SECOND_NS).max(TEST_UNILATERAL_WINDOW_SECS) + 30).await?;

    let outcome = expect_success(
        s.parent
            .call(s.vault.id(), "finalize_recovery")
            .args_json(json!({"new_parent_pubkey": test_recovery_pubkey().to_string()}))
            .max_gas()
            .transact()
            .await?,
    )?;
    // Success path returns PromiseOrValue::Promise (key-swap actions
    // have no FunctionCall return), so we check state instead.
    let _ = outcome;

    let state_after = s.vault_state().await?;
    assert!(state_after["unlocked"].as_bool().unwrap());
    assert!(state_after["recovery"].is_null());
    Ok(())
}

#[tokio::test]
async fn unilateral_finalize_works_without_dao_check() -> Result<()> {
    // DAO is fully alive (not ceased) — finalize should still succeed
    // because Unilateral path skips the cross-contract check.
    let s = Setup::new(Some(TEST_UNILATERAL_WINDOW_SECS)).await?;

    expect_success(
        s.parent
            .call(s.vault.id(), "unilateral_initiate_recovery")
            .max_gas()
            .transact()
            .await?,
    )?;

    // Confirm DAO is NOT ceased.
    let is_ceased: bool = s.dao.view("is_ceased").await?.json()?;
    assert!(!is_ceased);

    fast_forward_secs(&s.worker, (CESSATION_DELAY_NS / ONE_SECOND_NS).max(TEST_UNILATERAL_WINDOW_SECS) + 30).await?;

    let outcome = expect_success(
        s.parent
            .call(s.vault.id(), "finalize_recovery")
            .args_json(json!({"new_parent_pubkey": test_recovery_pubkey().to_string()}))
            .max_gas()
            .transact()
            .await?,
    )?;
    // Success path returns PromiseOrValue::Promise.
    let _ = outcome;

    let state = s.vault_state().await?;
    assert!(state["unlocked"].as_bool().unwrap());
    Ok(())
}

#[tokio::test]
async fn set_exit_window_then_initiate_uses_new_window() -> Result<()> {
    // Verifies that `set_exit_window` shapes subsequent
    // `unilateral_initiate_recovery` delays. Under `test-timing` the
    // contract's MIN..=MAX window is 10..=600 s and FINALIZE_WINDOW is
    // 30 s. If the new window did NOT take effect the delay would still
    // be the 30 s starting value and our "before delay" finalize attempt
    // below would unexpectedly succeed.
    let s = Setup::new(Some(TEST_UNILATERAL_WINDOW_SECS)).await?;

    // Extend to 100 s. Combined with the 30 s finalize window this gives
    // the test a 100..=130 s "valid finalize" timestamp range.
    let extended_window_secs: u64 = 100;
    expect_success(
        s.parent
            .call(s.vault.id(), "set_exit_window")
            .args_json(json!({ "new_window_secs": extended_window_secs }))
            .max_gas()
            .transact()
            .await?,
    )?;

    expect_success(
        s.parent
            .call(s.vault.id(), "unilateral_initiate_recovery")
            .max_gas()
            .transact()
            .await?,
    )?;

    // Try finalize at +50 s timestamp — well below the 100 s delay.
    // Confirms the delay extension actually applied (the original 30 s
    // window would have permitted finalize at this point).
    fast_forward_secs(&s.worker, 50).await?;
    let outcome = s
        .parent
        .call(s.vault.id(), "finalize_recovery")
        .args_json(json!({"new_parent_pubkey": test_recovery_pubkey().to_string()}))
        .max_gas()
        .transact()
        .await?;
    assert!(
        outcome.is_failure(),
        "finalize before extended delay must fail (window did not take effect?)"
    );

    // Advance to +130 s total — past the 100 s delay, before the 400 s
    // expiry (delay 100 s + window 300 s).
    // Total +130 s from initiate (50 s already advanced above).
    fast_forward_secs(&s.worker, 80).await?;
    let outcome = expect_success(
        s.parent
            .call(s.vault.id(), "finalize_recovery")
            .args_json(json!({"new_parent_pubkey": test_recovery_pubkey().to_string()}))
            .max_gas()
            .transact()
            .await?,
    )?;
    // Success path returns PromiseOrValue::Promise (key-swap actions
    // have no FunctionCall return), so we check state instead.
    let _ = outcome;

    let state = s.vault_state().await?;
    assert!(state["unlocked"].as_bool().unwrap());
    Ok(())
}

#[tokio::test]
async fn lowering_the_exit_window_does_not_shorten_a_recovery_started_at_once() -> Result<()> {
    // The vault starts on a 300 s window. The parent lowers it to the minimum
    // and starts a recovery in the next transaction — what a holder of a
    // stolen parent key would do. The recovery must wait the 300 s that were
    // in force, not the minimum.
    let long_window_secs: u64 = 300;
    let s = Setup::new(Some(long_window_secs)).await?;

    expect_success(
        s.parent
            .call(s.vault.id(), "set_exit_window")
            .args_json(json!({ "new_window_secs": MIN_UNILATERAL_EXIT_WINDOW_SECS }))
            .max_gas()
            .transact()
            .await?,
    )?;

    let in_force: u64 = s.vault.view("get_exit_window").await?.json()?;
    assert_eq!(in_force, long_window_secs, "a lowering is not in force at once");
    let state = s.vault_state().await?;
    assert_eq!(
        state["pending_exit_window"]["secs"].as_u64(),
        Some(MIN_UNILATERAL_EXIT_WINDOW_SECS),
        "the lowering is recorded as pending"
    );

    expect_success(
        s.parent
            .call(s.vault.id(), "unilateral_initiate_recovery")
            .max_gas()
            .transact()
            .await?,
    )?;

    // Past the minimum, well short of the window in force.
    fast_forward_secs(&s.worker, MIN_UNILATERAL_EXIT_WINDOW_SECS + 60).await?;
    let outcome = s
        .parent
        .call(s.vault.id(), "finalize_recovery")
        .args_json(json!({"new_parent_pubkey": test_recovery_pubkey().to_string()}))
        .max_gas()
        .transact()
        .await?;
    assert!(
        outcome.is_failure(),
        "a recovery started right after a lowering must wait the window that was in force"
    );

    // Past the 300 s that were in force.
    fast_forward_secs(&s.worker, long_window_secs - MIN_UNILATERAL_EXIT_WINDOW_SECS).await?;
    expect_success(
        s.parent
            .call(s.vault.id(), "finalize_recovery")
            .args_json(json!({"new_parent_pubkey": test_recovery_pubkey().to_string()}))
            .max_gas()
            .transact()
            .await?,
    )?;
    let state = s.vault_state().await?;
    assert!(state["unlocked"].as_bool().unwrap());
    Ok(())
}

#[tokio::test]
async fn a_lowering_is_in_force_after_the_old_window() -> Result<()> {
    let long_window_secs: u64 = 300;
    let s = Setup::new(Some(long_window_secs)).await?;

    expect_success(
        s.parent
            .call(s.vault.id(), "set_exit_window")
            .args_json(json!({ "new_window_secs": MIN_UNILATERAL_EXIT_WINDOW_SECS }))
            .max_gas()
            .transact()
            .await?,
    )?;

    fast_forward_secs(&s.worker, long_window_secs + 10).await?;
    let in_force: u64 = s.vault.view("get_exit_window").await?.json()?;
    assert_eq!(in_force, MIN_UNILATERAL_EXIT_WINDOW_SECS);

    expect_success(
        s.parent
            .call(s.vault.id(), "unilateral_initiate_recovery")
            .max_gas()
            .transact()
            .await?,
    )?;
    fast_forward_secs(&s.worker, MIN_UNILATERAL_EXIT_WINDOW_SECS + 30).await?;
    expect_success(
        s.parent
            .call(s.vault.id(), "finalize_recovery")
            .args_json(json!({"new_parent_pubkey": test_recovery_pubkey().to_string()}))
            .max_gas()
            .transact()
            .await?,
    )?;
    let state = s.vault_state().await?;
    assert!(state["unlocked"].as_bool().unwrap());
    Ok(())
}

#[tokio::test]
async fn set_exit_window_validates_range() -> Result<()> {
    // Bounds come from the imported MIN/MAX constants — values just
    // scale with the contract build.
    let s = Setup::new(None).await?;

    // Below MIN — too short
    let too_short = s
        .parent
        .call(s.vault.id(), "set_exit_window")
        .args_json(json!({ "new_window_secs": MIN_UNILATERAL_EXIT_WINDOW_SECS - 1 }))
        .max_gas()
        .transact()
        .await?;
    assert!(too_short.is_failure());

    // Above MAX — too long
    let too_long = s
        .parent
        .call(s.vault.id(), "set_exit_window")
        .args_json(json!({ "new_window_secs": MAX_UNILATERAL_EXIT_WINDOW_SECS + 1 }))
        .max_gas()
        .transact()
        .await?;
    assert!(too_long.is_failure());

    // At MAX — allowed.
    expect_success(
        s.parent
            .call(s.vault.id(), "set_exit_window")
            .args_json(json!({ "new_window_secs": MAX_UNILATERAL_EXIT_WINDOW_SECS }))
            .max_gas()
            .transact()
            .await?,
    )?;

    let exit_window: u64 = s.vault.view("get_exit_window").await?.json()?;
    assert_eq!(exit_window, MAX_UNILATERAL_EXIT_WINDOW_SECS);
    Ok(())
}

#[tokio::test]
async fn set_exit_window_rejects_non_parent() -> Result<()> {
    let s = Setup::new(None).await?;
    let stranger = s
        .worker
        .root_account()?
        .create_subaccount("mallory")
        .initial_balance(NearToken::from_near(10))
        .transact()
        .await?
        .into_result()?;

    let outcome = stranger
        .call(s.vault.id(), "set_exit_window")
        .args_json(json!({ "new_window_secs": 60u64 }))
        .max_gas()
        .transact()
        .await?;
    assert!(outcome.is_failure());
    Ok(())
}

#[tokio::test]
async fn only_one_recovery_at_a_time_across_triggers() -> Result<()> {
    let s = Setup::new(None).await?;
    s.dao_set_ceased(true).await?;

    // Cessation initiated first.
    expect_success(
        s.vault
            .call("initiate_recovery")
            .max_gas()
            .transact()
            .await?,
    )?;

    // Parent attempts a unilateral initiate while cessation is in flight.
    let outcome = s
        .parent
        .call(s.vault.id(), "unilateral_initiate_recovery")
        .max_gas()
        .transact()
        .await?;
    assert!(
        outcome.is_failure(),
        "second recovery (any trigger) must be rejected"
    );

    // Recovery state must still reflect the original Cessation entry.
    let state = s.vault_state().await?;
    assert_eq!(state["recovery"]["trigger"], "Cessation");
    Ok(())
}

#[tokio::test]
async fn only_one_recovery_at_a_time_unilateral_first() -> Result<()> {
    // I-4 reverse direction: Unilateral in flight → Cessation rejected.
    let s = Setup::new(Some(TEST_UNILATERAL_WINDOW_SECS)).await?;

    expect_success(
        s.parent
            .call(s.vault.id(), "unilateral_initiate_recovery")
            .max_gas()
            .transact()
            .await?,
    )?;
    let state = s.vault_state().await?;
    assert_eq!(state["recovery"]["trigger"], "Unilateral");

    // DAO declares cessation while a unilateral recovery is in flight.
    s.dao_set_ceased(true).await?;
    let outcome = s
        .vault
        .call("initiate_recovery")
        .max_gas()
        .transact()
        .await?;
    assert!(
        outcome.is_failure(),
        "Cessation initiate must be rejected while a Unilateral recovery is in flight"
    );

    // Unilateral entry must be untouched.
    let state = s.vault_state().await?;
    assert_eq!(state["recovery"]["trigger"], "Unilateral");
    Ok(())
}

// ============================================================
// unlocked_add_key
// ============================================================

#[tokio::test]
async fn unlocked_add_key_actually_adds_full_access_key_after_recovery() -> Result<()> {
    let s = Setup::new(Some(TEST_UNILATERAL_WINDOW_SECS)).await?;

    // Run unilateral recovery to unlock.
    expect_success(
        s.parent
            .call(s.vault.id(), "unilateral_initiate_recovery")
            .max_gas()
            .transact()
            .await?,
    )?;
    fast_forward_secs(&s.worker, (CESSATION_DELAY_NS / ONE_SECOND_NS).max(TEST_UNILATERAL_WINDOW_SECS) + 30).await?;
    expect_success(
        s.parent
            .call(s.vault.id(), "finalize_recovery")
            .args_json(json!({"new_parent_pubkey": test_recovery_pubkey().to_string()}))
            .max_gas()
            .transact()
            .await?,
    )?;
    assert!(s.vault_state().await?["unlocked"].as_bool().unwrap());

    let (_sk, parent_pk) = seeded_key("parent_full_access");
    expect_success(
        s.parent
            .call(s.vault.id(), "unlocked_add_key")
            .args_json(json!({
                "public_key": parent_pk.to_string(),
                "full_access": true,
                "allowance": null,
            }))
            .max_gas()
            .transact()
            .await?,
    )?;

    assert!(
        s.vault_has_access_key(&parent_pk).await?,
        "parent's new full-access key should be on the vault"
    );
    Ok(())
}

#[tokio::test]
async fn unlocked_add_key_default_allowance_is_one_near_for_function_call_keys() -> Result<()> {
    // Verifies the I-14 default: function-call keys with `allowance: None`
    // get `Allowance::limited(1 NEAR)`, not `Unlimited`.
    let s = Setup::new(Some(TEST_UNILATERAL_WINDOW_SECS)).await?;
    expect_success(
        s.parent
            .call(s.vault.id(), "unilateral_initiate_recovery")
            .max_gas()
            .transact()
            .await?,
    )?;
    fast_forward_secs(&s.worker, (CESSATION_DELAY_NS / ONE_SECOND_NS).max(TEST_UNILATERAL_WINDOW_SECS) + 30).await?;
    expect_success(
        s.parent
            .call(s.vault.id(), "finalize_recovery")
            .args_json(json!({"new_parent_pubkey": test_recovery_pubkey().to_string()}))
            .max_gas()
            .transact()
            .await?,
    )?;

    let (_sk, fcak_pk) = seeded_key("fcak_default");
    expect_success(
        s.parent
            .call(s.vault.id(), "unlocked_add_key")
            .args_json(json!({
                "public_key": fcak_pk.to_string(),
                "full_access": false,
                "allowance": null,
            }))
            .max_gas()
            .transact()
            .await?,
    )?;

    use near_workspaces::types::AccessKeyPermission;
    let view = s.vault.as_account().view_access_key(&fcak_pk).await?;
    match view.permission {
        AccessKeyPermission::FunctionCall(fc) => {
            let allowance = fc
                .allowance
                .expect("default allowance must be Some(1 NEAR), not Unlimited");
            assert_eq!(
                allowance,
                NearToken::from_near(1),
                "default function-call allowance should be 1 NEAR"
            );
        }
        other => panic!("expected FunctionCall permission, got {:?}", other),
    }
    Ok(())
}

#[tokio::test]
async fn unlocked_add_key_rejects_non_parent_after_unlock() -> Result<()> {
    let s = Setup::new(Some(TEST_UNILATERAL_WINDOW_SECS)).await?;
    expect_success(
        s.parent
            .call(s.vault.id(), "unilateral_initiate_recovery")
            .max_gas()
            .transact()
            .await?,
    )?;
    fast_forward_secs(&s.worker, (CESSATION_DELAY_NS / ONE_SECOND_NS).max(TEST_UNILATERAL_WINDOW_SECS) + 30).await?;
    expect_success(
        s.parent
            .call(s.vault.id(), "finalize_recovery")
            .args_json(json!({"new_parent_pubkey": test_recovery_pubkey().to_string()}))
            .max_gas()
            .transact()
            .await?,
    )?;

    let stranger = s
        .worker
        .root_account()?
        .create_subaccount("mallory")
        .initial_balance(NearToken::from_near(10))
        .transact()
        .await?
        .into_result()?;
    let (_sk, pk) = seeded_key("stranger_grab");
    let outcome = stranger
        .call(s.vault.id(), "unlocked_add_key")
        .args_json(json!({
            "public_key": pk.to_string(),
            "full_access": true,
            "allowance": null,
        }))
        .max_gas()
        .transact()
        .await?;
    assert!(
        outcome.is_failure(),
        "non-parent must not be able to add keys even after unlock"
    );
    assert!(!s.vault_has_access_key(&pk).await?);
    Ok(())
}

#[tokio::test]
async fn unlocked_add_key_rejected_before_unlock() -> Result<()> {
    let s = Setup::new(None).await?;
    let (_sk, pk) = seeded_key("premature");
    let outcome = s
        .parent
        .call(s.vault.id(), "unlocked_add_key")
        .args_json(json!({
            "public_key": pk.to_string(),
            "full_access": false,
            "allowance": null,
        }))
        .max_gas()
        .transact()
        .await?;
    assert!(outcome.is_failure(), "vault is locked — must reject");
    assert!(!s.vault_has_access_key(&pk).await?);
    Ok(())
}
