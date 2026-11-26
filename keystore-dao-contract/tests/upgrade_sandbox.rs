//! A DAO release rehearsed on near-sandbox before it is proposed on chain.
//!
//! The DAO starts on the code that runs on `dao.outlayer.<net>` today, and that code builds its
//! own state through its own methods: three members, the cached collaterals, a keystore build
//! approved by governance, a keystore registered from a real quote and installed by vote,
//! approved vault versions, an owner registered for the exit, and open proposals of every kind
//! (a pending governance proposal, an approved one not yet executed, a pending revocation of a
//! keystore key). Then the release goes in as a real one does: the wasm stored as a blob, an
//! `Upgrade` proposal for this account, the votes, the delay, `execute`.
//!
//! What the release is held to:
//! * an `Upgrade` with `migrate: true` on a release that keeps the layout fails as a whole and
//!   leaves the old code serving;
//! * the upgrade without `migrate` deploys the new code, and its `gov_health` reads the state;
//! * every view of the state reads the same before and after, and the raw state differs only by
//!   the two upgrade proposals and the proposal counter;
//! * `ApproveWalletContract` / `RevokeWalletContract` pass through governance, and the owner's
//!   `remove_approved_wallet_contract` takes a build off at once, for the owner only;
//! * the proposals the old code left open run under the new one.
//!
//! The registration verifies the fixture's quote against `fixtures/collaterals.json` at the
//! sandbox's clock, which is the wall clock: it passes while the collateral of the quote's
//! platform is current (until 2026-12-08 for the cached one), and the fixture is refreshed
//! from `get_collaterals` of a live DAO after that.
//!
//! Run by `tests/upgrade_sandbox.sh`, which starts the sandbox (`nearprotocol/sandbox`), reads
//! the deployed code and sets the variables below. A plain `cargo test` skips it.
//!
//!   DAO_SANDBOX_RPC   the sandbox's RPC address
//!   DAO_SANDBOX_HOME  the sandbox's home directory (its `validator_key.json`)
//!   DAO_OLD_WASM      the code the DAO runs today
//!   DAO_NEW_WASM      the release (`cargo near build reproducible-wasm`)

use anyhow::{anyhow, bail, ensure, Context, Result};
use near_sdk::json_types::Base58CryptoHash;
use near_workspaces::network::{Sandbox, ValidatorKey};
use near_workspaces::result::ExecutionFinalResult;
use near_workspaces::types::{Gas, NearToken};
use near_workspaces::{Account, AccountId, ContractState, Worker};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

const DAL: &str = include_str!("fixtures/keystore_dal.json");
const COLLATERALS: &str = include_str!("fixtures/collaterals.json");

/// The wallet contract build the rehearsal approves.
const WALLET_CODE_HASH: &str = "651XC7DH8J4Xczf8JKXH9pyveBY8ZuNCfy5HZ3SvuSiL";
/// The delay `dao.outlayer.testnet` runs with.
const GOV_DELAY_SEC: u64 = 60;
/// Composes `dao.outlayer.testnet` has approved.
const COMPOSE_EXECUTED: &str = "705dfe6469e3bfb3f255af69f2e6b052ff9f35d9b6c8555075153e120e2f3a3a";
const COMPOSE_LEFT_APPROVED: &str = "345b93c9d133219912c17eb9f06bc6f18f71023d08ffbc3bd803f9234746bec5";
/// Vault versions `dao.outlayer.testnet` has approved.
const VAULT_VERSIONS: [(&str, &str); 2] = [
    ("CoVgEt8C13sTyojn7yodWnscQoSvSm1uEr4kLzU5gMhG", "v0.1-testnet"),
    ("9dPDGS3RCj4c5HLtd5m2Xk9dsfZCKB6j3eaPzH3trvtQ", "v0.2-testnet"),
];
/// `StorageKey::GovProposals`: its borsh tag is the prefix of every governance proposal entry.
const GOV_PROPOSALS_PREFIX: u8 = 12;

const ONE_SECOND_NS: u64 = 1_000_000_000;

type RawState = HashMap<Vec<u8>, Vec<u8>>;

fn env_var(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("{name} is not set; run tests/upgrade_sandbox.sh"))
}

fn code_hash(wasm: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(wasm).into();
    String::from(&Base58CryptoHash::from(digest))
}

fn failure_text(r: &ExecutionFinalResult) -> String {
    format!("{:?}", r.failures())
}

fn ok(r: ExecutionFinalResult, what: &str) -> Result<ExecutionFinalResult> {
    ensure!(r.is_success(), "{what} failed: {}", failure_text(&r));
    Ok(r)
}

fn done(r: ExecutionFinalResult, what: &str) -> Result<()> {
    ok(r, what).map(drop)
}

fn refused(r: ExecutionFinalResult, what: &str, needle: &str) -> Result<()> {
    ensure!(r.is_failure(), "{what} succeeded; it must be refused with {needle:?}");
    let text = failure_text(&r);
    ensure!(text.contains(needle), "{what} was refused, but not with {needle:?}: {text}");
    Ok(())
}

async fn call(from: &Account, dao: &AccountId, method: &str, args: Value, deposit: NearToken) -> Result<ExecutionFinalResult> {
    Ok(from
        .call(dao, method)
        .args_json(args)
        .deposit(deposit)
        .gas(Gas::from_tgas(300))
        .transact()
        .await?)
}

async fn view(worker: &Worker<Sandbox>, dao: &AccountId, method: &str, args: Value) -> Result<Value> {
    let r = worker.view(dao, method).args_json(args).await.with_context(|| format!("view {method}"))?;
    Ok(r.json()?)
}

async fn account_code_hash(worker: &Worker<Sandbox>, id: &AccountId) -> Result<String> {
    match worker.view_account(id).await?.contract_state {
        ContractState::LocalHash(hash) => Ok(hash.to_string()),
        other => bail!("{id} runs no code of its own: {other:?}"),
    }
}

/// Advance the sandbox until its block timestamp is `secs` past the current one.
async fn fast_forward_secs(worker: &Worker<Sandbox>, secs: u64) -> Result<()> {
    let target = worker.view_block().await?.timestamp() + secs * ONE_SECOND_NS;
    for _ in 0..500 {
        worker.fast_forward(100).await?;
        if worker.view_block().await?.timestamp() >= target {
            return Ok(());
        }
    }
    bail!("the sandbox did not advance {secs} s")
}

struct Dao<'a> {
    worker: &'a Worker<Sandbox>,
    id: AccountId,
    m1: &'a Account,
    m2: &'a Account,
}

impl Dao<'_> {
    async fn propose(&self, action: Value) -> Result<u64> {
        let r = call(self.m1, &self.id, "propose", json!({ "action": action }), NearToken::from_near(1)).await?;
        Ok(ok(r, "propose")?.json()?)
    }

    async fn vote(&self, member: &Account, id: u64) -> Result<()> {
        let r = call(member, &self.id, "vote", json!({ "proposal_id": id, "approve": true }), NearToken::from_near(0)).await?;
        done(r, "vote")?;
        Ok(())
    }

    async fn execute(&self, id: u64) -> Result<ExecutionFinalResult> {
        call(self.m1, &self.id, "execute", json!({ "proposal_id": id }), NearToken::from_near(0)).await
    }

    async fn status(&self, id: u64) -> Result<String> {
        let p = view(self.worker, &self.id, "get_gov_proposal", json!({ "proposal_id": id })).await?;
        p["status"].as_str().map(str::to_string).ok_or_else(|| anyhow!("no governance proposal {id}"))
    }

    /// Propose, vote to the threshold (two of three), wait out the delay, execute.
    async fn pass(&self, action: Value) -> Result<(u64, ExecutionFinalResult)> {
        let id = self.propose(action).await?;
        self.vote(self.m2, id).await?;
        ensure!(self.status(id).await? == "Approved", "proposal {id} is not approved after two votes of three");
        fast_forward_secs(self.worker, GOV_DELAY_SEC + 1).await?;
        Ok((id, self.execute(id).await?))
    }

    async fn store_blob(&self, wasm: &[u8]) -> Result<String> {
        let r = self
            .m1
            .call(&self.id, "store_blob")
            .args(wasm.to_vec())
            .deposit(NearToken::from_near(10))
            .gas(Gas::from_tgas(300))
            .transact()
            .await?;
        Ok(ok(r, "store_blob")?.json()?)
    }

    async fn wallet_contracts(&self) -> Result<Vec<String>> {
        Ok(serde_json::from_value(view(self.worker, &self.id, "get_approved_wallet_contracts", json!({})).await?)?)
    }

    async fn next_proposal_id(&self) -> Result<u64> {
        view(self.worker, &self.id, "gov_health", json!({}))
            .await?
            .as_u64()
            .ok_or_else(|| anyhow!("gov_health is not a number"))
    }
}

/// Everything the views say about the state, the proposal counter apart (an upgrade proposal
/// moves it). Proposals are read up to `ids`: those that existed before the upgrade.
async fn snapshot(d: &Dao<'_>, ids: u64, exit_owner: &AccountId, registration: u64, revocation: u64) -> Result<Value> {
    let (w, id) = (d.worker, &d.id);
    let mut members: Vec<String> = serde_json::from_value(view(w, id, "get_dao_members", json!({})).await?)?;
    members.sort();
    let mut config = view(w, id, "get_config", json!({})).await?;
    config.as_object_mut().ok_or_else(|| anyhow!("get_config is not an object"))?.remove("next_proposal_id");
    Ok(json!({
        "members": members,
        "owner": view(w, id, "get_owner", json!({})).await?,
        "config": config,
        "collaterals": view(w, id, "get_collaterals", json!({})).await?,
        "os_images": view(w, id, "get_approved_os_images", json!({})).await?,
        "composes": view(w, id, "get_approved_composes", json!({})).await?,
        "keystores": view(w, id, "get_approved_keystores", json!({ "from_index": 0, "limit": 100 })).await?,
        "vault_versions": view(w, id, "list_approved_vault_versions", json!({})).await?,
        "registrations": view(w, id, "get_proposals", json!({ "from_index": 0, "limit": ids })).await?,
        "registration_facts": view(w, id, "get_registration_facts", json!({ "proposal_id": registration })).await?,
        "revocation": view(w, id, "get_revoke_proposal", json!({ "proposal_id": revocation })).await?,
        "gov_proposals": view(w, id, "get_gov_proposals", json!({ "from_index": 0, "limit": ids })).await?,
        "gov_delay_sec": view(w, id, "get_gov_delay_sec", json!({})).await?,
        "ceased": view(w, id, "is_ceased", json!({})).await?,
        "exit_owner": view(w, id, "get_exit_owner", json!({ "account": exit_owner })).await?,
    }))
}

/// The raw state after the upgrade is the state before it, plus the upgrade proposals
/// (`new_ids`), with the proposal counter in the root struct moved past them. Nothing else is
/// added, changed or removed; the blobs are gone again.
fn compare_raw(before: &RawState, after: &RawState, counter_before: u64, new_ids: &[u64]) -> Result<()> {
    let state = b"STATE".as_slice();
    let expected_new: Vec<Vec<u8>> = new_ids
        .iter()
        .map(|id| [[GOV_PROPOSALS_PREFIX].as_slice(), id.to_le_bytes().as_slice()].concat())
        .collect();
    for (k, v) in before {
        if k.as_slice() != state {
            ensure!(after.get(k) == Some(v), "raw state key {} changed or is gone", hex::encode(k));
        }
    }
    for k in after.keys() {
        if k.as_slice() != state && !before.contains_key(k) {
            ensure!(expected_new.contains(k), "raw state key {} is new and is no upgrade proposal", hex::encode(k));
        }
    }
    for k in &expected_new {
        ensure!(after.contains_key(k), "upgrade proposal entry {} is missing", hex::encode(k));
    }

    let (s0, s1) = (
        before.get(state).ok_or_else(|| anyhow!("no STATE before"))?,
        after.get(state).ok_or_else(|| anyhow!("no STATE after"))?,
    );
    ensure!(s0.len() == s1.len(), "the root struct changed size: {} -> {}", s0.len(), s1.len());
    let diff: Vec<usize> = (0..s0.len()).filter(|&i| s0[i] != s1[i]).collect();
    let (first, last) = match (diff.first(), diff.last()) {
        (Some(&f), Some(&l)) => (f, l),
        _ => bail!("the root struct did not change; the proposal counter should have"),
    };
    let (old, new) = (counter_before.to_le_bytes(), (counter_before + new_ids.len() as u64).to_le_bytes());
    let counter_only = (last.saturating_sub(7)..=first)
        .any(|p| p + 8 <= s0.len() && s0[p..p + 8] == old && s1[p..p + 8] == new);
    ensure!(counter_only, "the root struct changed at bytes {first}..={last}, beyond the proposal counter");
    Ok(())
}

#[tokio::test]
#[ignore = "needs a running sandbox and both wasm files: tests/upgrade_sandbox.sh"]
async fn release_upgrades_the_deployed_dao_and_keeps_its_state() -> Result<()> {
    let rpc = env_var("DAO_SANDBOX_RPC")?;
    let home = env_var("DAO_SANDBOX_HOME")?;
    let old_wasm = std::fs::read(env_var("DAO_OLD_WASM")?)?;
    let new_wasm = std::fs::read(env_var("DAO_NEW_WASM")?)?;
    let (old_hash, new_hash) = (code_hash(&old_wasm), code_hash(&new_wasm));
    ensure!(old_hash != new_hash, "the release is the code already deployed ({old_hash})");
    println!("deployed code {old_hash}\nrelease       {new_hash}");

    let worker = near_workspaces::sandbox()
        .rpc_addr(&rpc)
        .validator_key(ValidatorKey::HomeDir(home.into()))
        .await?;

    // ===== The DAO on the deployed code =====
    let dao_account = worker.dev_create_account().await?;
    let owner = worker.dev_create_account().await?;
    let init = worker.dev_create_account().await?;
    let m1 = worker.dev_create_account().await?;
    let m2 = worker.dev_create_account().await?;
    let m3 = worker.dev_create_account().await?;
    let exiter = worker.dev_create_account().await?;
    let newcomer = worker.dev_create_account().await?;
    let dao_id = dao_account.id().clone();
    let zero = NearToken::from_near(0);

    let deployed = dao_account.deploy(&old_wasm).await?;
    ensure!(deployed.is_success(), "deploying the current code failed: {:?}", deployed.details.failures());
    ensure!(account_code_hash(&worker, &dao_id).await? == old_hash, "the account does not run the current code");
    done(
        call(
            &dao_account,
            &dao_id,
            "new",
            json!({
                "owner_id": owner.id(),
                "init_account_id": init.id(),
                "dao_members": [m1.id(), m2.id(), m3.id()],
                "mpc_contract_id": "v1.signer-prod.testnet",
                "gov_delay_sec": GOV_DELAY_SEC,
            }),
            zero,
        )
        .await?,
        "new",
    )?;
    let d = Dao { worker: &worker, id: dao_id.clone(), m1: &m1, m2: &m2 };

    // The collateral of both platforms, as the owner caches it.
    let collaterals: Value = serde_json::from_str(COLLATERALS)?;
    for (i, c) in collaterals["collaterals"].as_array().ok_or_else(|| anyhow!("no collaterals"))?.iter().enumerate() {
        done(call(&owner, &dao_id, "update_collateral", json!({ "collateral": c, "index": i }), zero).await?, "update_collateral")?;
    }

    // A keystore build approved by governance: the dal keystore's guest OS and compose, and
    // another compose.
    let dal: Value = serde_json::from_str(DAL)?;
    let m = &dal["measurements"];
    let image = json!({ "mrtd": m["mrtd"], "rtmr0": m["rtmr0"], "rtmr1": m["rtmr1"], "rtmr2": m["rtmr2"] });
    let mut approvals = Vec::new();
    for action in [
        json!({ "ApproveOsImage": { "image": image } }),
        json!({ "ApproveCompose": { "compose_hash": dal["compose_hash"] } }),
        json!({ "ApproveCompose": { "compose_hash": COMPOSE_EXECUTED } }),
    ] {
        let id = d.propose(action).await?;
        d.vote(&m2, id).await?;
        approvals.push(id);
    }
    fast_forward_secs(&worker, GOV_DELAY_SEC + 1).await?;
    for id in approvals {
        done(d.execute(id).await?, "execute an approval")?;
    }

    // Vault versions, approved by two members each.
    for (hash, label) in VAULT_VERSIONS {
        for member in [&m1, &m2] {
            let args = json!({ "hash": hash, "label": label, "audit_url": null });
            done(call(member, &dao_id, "approve_vault_version", args, zero).await?, "approve_vault_version")?;
        }
    }

    // A keystore registered from its real quote and boot event log, installed by two votes.
    let key = dal["public_key"].as_str().ok_or_else(|| anyhow!("no public_key in the fixture"))?;
    let args = json!({
        "public_key": key,
        "tdx_quote_hex": dal["tdx_quote_hex"],
        "app_id": null,
        "event_log": dal["rtmr3_events"],
    });
    let registration: u64 =
        ok(call(&init, &dao_id, "submit_keystore_registration", args, zero).await?, "submit_keystore_registration")?.json()?;
    for member in [&m1, &m2] {
        let args = json!({ "proposal_id": registration, "approve": true, "public_key": key });
        done(call(member, &dao_id, "vote", args, zero).await?, "vote on the registration")?;
    }
    ensure!(
        view(&worker, &dao_id, "is_keystore_approved", json!({ "public_key": key })).await? == json!(true),
        "the registered keystore is not approved"
    );

    // An owner registered for the exit.
    let fee = NearToken::from_millinear(50);
    done(call(&exiter, &dao_id, "register_exit_owner", json!({ "exit_window_sec": null }), fee).await?, "register_exit_owner")?;

    // Open proposals: a revocation of the keystore's key (one vote of two), a governance
    // proposal pending (one of two), an approved one not executed.
    let revocation: u64 = ok(
        call(&m1, &dao_id, "propose_revoke_keystore_keys", json!({ "public_keys": [key] }), zero).await?,
        "propose_revoke_keystore_keys",
    )?
    .json()?;
    let pending = d.propose(json!({ "AddMember": { "member": newcomer.id() } })).await?;
    let left_approved = d.propose(json!({ "ApproveCompose": { "compose_hash": COMPOSE_LEFT_APPROVED } })).await?;
    d.vote(&m2, left_approved).await?;
    ensure!(d.status(pending).await? == "Pending" && d.status(left_approved).await? == "Approved");

    // The deployed code has no list of wallet contracts.
    ensure!(
        worker.view(&dao_id, "get_approved_wallet_contracts").args_json(json!({})).await.is_err(),
        "the deployed code already answers get_approved_wallet_contracts"
    );

    let counter = d.next_proposal_id().await?;
    let before = snapshot(&d, counter, exiter.id(), registration, revocation).await?;
    let raw_before: RawState = worker.view_state(&dao_id).await?;
    println!("state before: {} entries, proposals 0..{counter}", raw_before.len());

    // ===== The wrong way: `migrate` on a release that keeps the layout =====
    // The release's `migrate()` reads the layout of an earlier version: the batch fails at it
    // and the deploy before it reverts.
    ensure!(d.store_blob(&new_wasm).await? == new_hash, "store_blob returned another hash");
    let upgrade = json!({ "Upgrade": { "target": dao_id, "code_hash": new_hash, "migrate": true } });
    let (with_migrate, r) = d.pass(upgrade).await?;
    ensure!(r.is_failure(), "an upgrade with migrate succeeded on a release that keeps the layout");
    ensure!(account_code_hash(&worker, &dao_id).await? == old_hash, "a failed upgrade left the new code");
    ensure!(d.next_proposal_id().await? == counter + 1, "the old code does not read its state after the failed upgrade");
    ensure!(d.status(with_migrate).await? == "Executed");
    ensure!(view(&worker, &dao_id, "get_blob", json!({ "hash": new_hash })).await?.is_null(), "the blob outlived its upgrade");
    ensure!(
        failure_text(&r).contains("Cannot deserialize the contract state"),
        "the upgrade with migrate failed, but not at migrate's read of the state: {}",
        failure_text(&r)
    );
    println!("upgrade with migrate: fails at migrate's read of the state, old code serving");

    // ===== The release: an upgrade without migrate =====
    d.store_blob(&new_wasm).await?;
    let upgrade = json!({ "Upgrade": { "target": dao_id, "code_hash": new_hash, "migrate": false } });
    let release = d.propose(upgrade).await?;
    d.vote(&m2, release).await?;
    refused(d.execute(release).await?, "execute before the delay", "Proposal executes from block timestamp")?;
    fast_forward_secs(&worker, GOV_DELAY_SEC + 1).await?;
    done(d.execute(release).await?, "execute the upgrade")?;
    ensure!(account_code_hash(&worker, &dao_id).await? == new_hash, "the account does not run the release");
    ensure!(d.next_proposal_id().await? == counter + 2, "gov_health of the release");
    ensure!(view(&worker, &dao_id, "get_blob", json!({ "hash": new_hash })).await?.is_null(), "the blob outlived its upgrade");
    println!("upgrade without migrate: executed, code {new_hash}");

    // ===== The state reads the same =====
    let after = snapshot(&d, counter, exiter.id(), registration, revocation).await?;
    if before != after {
        bail!(
            "the views differ after the upgrade\nbefore: {}\nafter:  {}",
            serde_json::to_string(&before)?,
            serde_json::to_string(&after)?
        );
    }
    let raw_after: RawState = worker.view_state(&dao_id).await?;
    compare_raw(&raw_before, &raw_after, counter, &[with_migrate, release])?;
    println!("state after: the same views; raw state differs by the two upgrade proposals and the counter only");

    // ===== The wallet contract builds =====
    ensure!(d.wallet_contracts().await?.is_empty(), "the list does not start empty");
    let (_, r) = d.pass(json!({ "ApproveWalletContract": { "code_hash": WALLET_CODE_HASH } })).await?;
    done(r, "execute ApproveWalletContract")?;
    ensure!(d.wallet_contracts().await? == vec![WALLET_CODE_HASH.to_string()], "ApproveWalletContract did not list the build");
    let (_, r) = d.pass(json!({ "RevokeWalletContract": { "code_hash": WALLET_CODE_HASH } })).await?;
    done(r, "execute RevokeWalletContract")?;
    ensure!(d.wallet_contracts().await?.is_empty(), "RevokeWalletContract left the build listed");
    let (_, r) = d.pass(json!({ "ApproveWalletContract": { "code_hash": WALLET_CODE_HASH } })).await?;
    done(r, "execute ApproveWalletContract again")?;
    ensure!(d.wallet_contracts().await? == vec![WALLET_CODE_HASH.to_string()]);
    let remove = json!({ "code_hash": WALLET_CODE_HASH });
    refused(
        call(&m1, &dao_id, "remove_approved_wallet_contract", remove.clone(), zero).await?,
        "a member removing a wallet contract build",
        "Only owner can call this method",
    )?;
    done(call(&owner, &dao_id, "remove_approved_wallet_contract", remove, zero).await?, "remove_approved_wallet_contract")?;
    ensure!(d.wallet_contracts().await?.is_empty(), "the owner's removal left the build listed");
    println!("wallet contracts: approved, revoked, approved, removed by the owner");

    // ===== What the old code left open runs under the new one =====
    done(d.execute(left_approved).await?, "execute the approval left from before the upgrade")?;
    let composes = view(&worker, &dao_id, "get_approved_composes", json!({})).await?;
    ensure!(composes.as_array().is_some_and(|c| c.contains(&json!(COMPOSE_LEFT_APPROVED))));

    done(call(&m2, &dao_id, "vote", json!({ "proposal_id": revocation, "approve": true }), zero).await?, "vote on the revocation")?;
    ensure!(
        view(&worker, &dao_id, "is_keystore_approved", json!({ "public_key": key })).await? == json!(false),
        "the revocation left the key approved"
    );

    d.vote(&m2, pending).await?;
    fast_forward_secs(&worker, GOV_DELAY_SEC + 1).await?;
    done(d.execute(pending).await?, "execute the AddMember left pending")?;
    let members = view(&worker, &dao_id, "get_dao_members", json!({})).await?;
    ensure!(members.as_array().is_some_and(|m| m.len() == 4 && m.contains(&json!(newcomer.id()))));
    println!("open proposals from before the upgrade: approved compose executed, revocation executed, member added");

    ensure!(d.next_proposal_id().await? > counter + 2, "gov_health at the end");
    Ok(())
}
