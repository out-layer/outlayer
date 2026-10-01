//! Tasks between an agent and its owner: the host's side.
//!
//! A run of a project that declares tasks (`"tasks": true` in its manifest)
//! and was admitted to an owner's secret row may leave that owner a task; on
//! the owner's signed approval the platform starts a run of the same
//! preparer, on the same payment key, and that run carries the task out —
//! through the `outlayer:tasks` host interface ([`host_functions`],
//! `wit/deps/tasks.wit`) and through nothing else. The component never sees
//! a key and never names an account: whose task it is, who made it, whose
//! consent it carries and which project it belongs to are this worker's
//! facts, from the job and the keystore.
//!
//! **Keys.** The keystore derives one key per project and owner
//! (`task-key:v1:{project_uuid}:{owner}`) in the run's one `/decrypt`
//! request, beside the row, and says whether the row admitted the caller by
//! name ([`TaskGrant`]). Everything else is derived here, per task
//! ([`crypto`]): the key its sealed copy is under, and the key pair the
//! owner's answer is encrypted to.
//!
//! **Two copies.** What a task shows is stored twice by the coordinator,
//! which opens neither: sealed under the task's key, and under a content key
//! wrapped to the public key of each device the owner has signed in. A
//! device's statement is checked here against the chain before anything is
//! encrypted to it ([`statement`]): the signature, and that the key that
//! signed is an access key of the owner's account.
//!
//! **What the run leaves.** The tasks a run answered and what it reported on
//! them, and the approved tasks it was refused before it took them, are read
//! back by the job path after the guest exits ([`RunReport`]), whatever way
//! it exited, and sent to the store: a task reported on by a run that
//! succeeded is `done`, any other it answered is `failed`, and one it was
//! refused is `failed` with the reason.

pub mod client;
pub mod crypto;
pub mod envelope;
pub mod host_functions;
pub mod statement;

use std::sync::{Arc, Mutex};

use zeroize::Zeroizing;

pub use host_functions::{add_tasks_to_linker, TasksHostState};

/// The longest a task waits, in seconds.
pub const MAX_LIFE_SECS: u32 = 24 * 60 * 60;
/// Most bytes of the component's `state`.
pub const MAX_STATE_BYTES: usize = 256 * 1024;
/// Most files a task carries.
pub const MAX_FILES: usize = 10;
/// Most bytes of a task's files together: what one call carries, with room
/// for the rest of it.
pub const MAX_FILES_BYTES: usize = 6 * 1024 * 1024;
/// Most bytes of a policy handed in for its hash.
pub const MAX_POLICY_BYTES: usize = 64 * 1024;
/// Most bytes of an envelope.
pub const MAX_ENVELOPE_BYTES: usize = 256 * 1024;
/// Most bytes of what the owner supplies, sealed.
pub const MAX_SUPPLIED_BYTES: usize = 8 * 1024;
/// Most bytes of the note the owner writes beside an approval, sealed; the
/// note opened is held to the same number and to the characters of a long
/// text.
pub const MAX_NOTE_BYTES: usize = 8 * 1024;
/// Most bytes of the reason of a rejection, sealed; the reason opened is
/// held to the same number.
pub const MAX_REJECTION_BYTES: usize = 8 * 1024;
/// Most bytes of a result left for the preparer.
pub const MAX_RESULT_BYTES: usize = 16 * 1024;
/// Tasks one run may open.
pub const MAX_OPENS_PER_RUN: u32 = 5;
/// Calls of the interface one run may make.
pub const MAX_CALLS_PER_RUN: u32 = 100;

/// The task key of one run, and how its row admitted the caller. Wiped when
/// dropped; its `Debug` prints nothing of the key.
pub struct TaskGrant {
    key: Zeroizing<[u8; 32]>,
    pub admitted_by_name: bool,
    /// The vault the owner's row is bound to, whose master the key is under;
    /// none for the default master. Recorded beside every task the run makes.
    pub vault: Option<String>,
}

impl TaskGrant {
    pub fn new(key: Zeroizing<[u8; 32]>, admitted_by_name: bool) -> Self {
        Self { key, admitted_by_name, vault: None }
    }

    pub fn under(mut self, vault: Option<String>) -> Self {
        self.vault = vault;
        self
    }

    pub(crate) fn key(&self) -> &[u8; 32] {
        &self.key
    }
}

impl std::fmt::Debug for TaskGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TaskGrant").field("admitted_by_name", &self.admitted_by_name).finish_non_exhaustive()
    }
}

/// Where the task store is.
#[derive(Clone)]
pub struct StoreConfig {
    pub coordinator_url: String,
    pub coordinator_token: String,
}

/// Prints where the store is and nothing of the token that opens it.
impl std::fmt::Debug for StoreConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreConfig").field("coordinator_url", &self.coordinator_url).finish_non_exhaustive()
    }
}

/// Where the chain is asked whose a key is, and the recipient the owner's
/// statements are signed for: the OutLayer contract.
#[derive(Clone)]
pub struct ChainConfig {
    pub rpc_url: String,
    pub recipient: String,
}

/// The URL may carry a key: nothing of it is printed.
impl std::fmt::Debug for ChainConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainConfig").field("recipient", &self.recipient).finish_non_exhaustive()
    }
}

/// One task a run answered, and what it left for the preparer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answered {
    pub id: String,
    /// The result, sealed under the task's key; `None` until reported.
    pub outcome: Option<Vec<u8>>,
}

/// An approved task this run was refused before it took it: the host's
/// reason, as the store names it in `run_refused:<reason>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    pub id: String,
    pub reason: String,
}

#[derive(Debug, Default)]
struct Report {
    answered: Vec<Answered>,
    refused: Vec<Refused>,
}

/// What a run did that the store must hear of once the guest has exited.
/// Shared between the host state, which writes it, and the job path, which
/// reads it after the run — so it survives a guest that trapped.
#[derive(Debug, Clone, Default)]
pub struct RunReport(Arc<Mutex<Report>>);

impl RunReport {
    fn lock(&self) -> std::sync::MutexGuard<'_, Report> {
        self.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn answered(&self, id: &str) {
        let mut report = self.lock();
        if !report.answered.iter().any(|t| t.id == id) {
            report.answered.push(Answered { id: id.to_string(), outcome: None });
        }
    }

    /// The store refused the answer after it was recorded: it is not one.
    pub(crate) fn forget(&self, id: &str) {
        self.lock().answered.retain(|t| t.id != id);
    }

    /// The host refused this run an approved task before anything moved: the
    /// task is failed with the reason when the run ends. Recorded once per
    /// task, by the first reason.
    pub(crate) fn refused(&self, id: &str, reason: &str) {
        let mut report = self.lock();
        if !report.refused.iter().any(|t| t.id == id) {
            report.refused.push(Refused { id: id.to_string(), reason: reason.to_string() });
        }
    }

    /// Record the outcome of a task this run answered; `false` when it
    /// answered no such task.
    pub(crate) fn reported(&self, id: &str, outcome: Vec<u8>) -> bool {
        let mut report = self.lock();
        match report.answered.iter_mut().find(|t| t.id == id) {
            Some(task) => {
                task.outcome = Some(outcome);
                true
            }
            None => false,
        }
    }

    /// Everything the run answered, in order.
    pub fn tasks(&self) -> Vec<Answered> {
        self.lock().answered.clone()
    }

    /// Every approved task the run was refused, in order.
    pub fn refusals(&self) -> Vec<Refused> {
        self.lock().refused.clone()
    }
}

/// Everything the host needs of one run to serve `outlayer:tasks`, as the
/// job path established it. Moved into the run with its keys and dropped with
/// it.
#[derive(Debug, Default)]
pub struct TasksRun {
    /// The manifest says `"tasks": true`.
    pub declared: bool,
    /// The task key; present when the run named a row of its own project and
    /// the row opened.
    pub grant: Option<TaskGrant>,
    /// This run: the call's id over HTTPS, `req-{request id}` on chain.
    pub run: String,
    pub project_id: Option<String>,
    pub project_uuid: Option<String>,
    /// SHA-256 of the build that runs, hex: the measured bytes. A task names
    /// the build that made it, and is answered by that build only.
    pub build: Option<String>,
    /// The owner and the profile of the secret row the run named.
    pub owner: Option<String>,
    pub profile: Option<String>,
    /// The operation the call names in its input, read by the host from the
    /// same bytes the contract priced; none when the input names none. A
    /// task is answered in the operation it names, and this is the host's
    /// word for which one is running.
    pub operation: Option<String>,
    /// The account that made the run: the signer on chain — for a
    /// meta-transaction, the sender of the delegate action, not the relayer
    /// that signed the transaction — and the sender over HTTPS.
    pub caller: Option<String>,
    /// The account that called OutLayer: the receipt's predecessor on chain,
    /// the sender over HTTPS. A run uses tasks only when this is the caller:
    /// a contract the caller signed a transaction to can relay a request in
    /// the caller's name, and such a run is nobody's own act.
    pub predecessor: Option<String>,
    /// The nonce of the payment key that pays for this run; none on chain.
    /// With the caller, the wallet, the identity and the compute limit below
    /// it is the consent a task this run opens carries, and what a run that
    /// carries a task out is held to.
    pub payment_key_nonce: Option<u32>,
    /// The custody wallet the run's host functions act on, when the call
    /// named one.
    pub wallet_id: Option<String>,
    /// Whether the run goes under the name of the wallet's bound account.
    pub bound_identity: bool,
    /// What the call authorised for compute, in minimal USD units as the job
    /// spells it; none on chain.
    pub compute_limit_usd: Option<String>,
    pub store: Option<StoreConfig>,
    pub chain: Option<ChainConfig>,
    pub report: RunReport,
}

/// The id of a run, as tasks name it. Lowercase letters, digits and `-`.
pub fn run_id(call_id: Option<&str>, request_id: u64) -> String {
    match call_id {
        Some(call) if is_id(call) => call.to_string(),
        _ => format!("req-{request_id}"),
    }
}

/// Is `raw` the id of a task or of a run: 1 to 80 of `a-z`, `0-9` and `-`?
pub fn is_id(raw: &str) -> bool {
    !raw.is_empty() && raw.len() <= 80 && raw.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Does the component in `wasm` declare tasks?
pub fn declared_in(manifest: Option<&crate::connector_manifest::ProjectManifest>) -> bool {
    manifest.is_some_and(|m| m.tasks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_run_is_named_by_its_call_or_by_its_request() {
        assert_eq!(run_id(Some("0b9c1a52-7c1e-4a53-9c58-2f0c8f6f3b11"), 7), "0b9c1a52-7c1e-4a53-9c58-2f0c8f6f3b11");
        assert_eq!(run_id(None, 7), "req-7");
        assert_eq!(run_id(Some("Not/An Id"), 7), "req-7");
    }

    #[test]
    fn an_id_is_lowercase_letters_digits_and_dashes() {
        for good in ["a", "req-7", "0b9c1a52-7c1e-4a53-9c58-2f0c8f6f3b11-3"] {
            assert!(is_id(good), "{good}");
        }
        let long = "a".repeat(81);
        for bad in ["", "A", "a/b", "..", "a:b", "a b", "é", long.as_str()] {
            assert!(!is_id(bad), "{bad}");
        }
    }

    #[test]
    fn a_grant_prints_nothing_of_its_key() {
        let grant = TaskGrant::new(Zeroizing::new([7u8; 32]), true);
        let printed = format!("{grant:?}");
        assert!(printed.contains("admitted_by_name: true") && !printed.contains('7'), "{printed}");
    }

    #[test]
    fn a_run_and_where_its_store_is_print_nothing_of_a_token_or_a_key() {
        let store = StoreConfig {
            coordinator_url: "http://coordinator.internal:8080".to_string(),
            coordinator_token: "MARKER-BEARER-0123456789".to_string(),
        };
        let chain = ChainConfig {
            rpc_url: "https://rpc.example/?apiKey=MARKER-RPC-KEY".to_string(),
            recipient: "outlayer.testnet".to_string(),
        };
        let printed = format!("{store:?}");
        assert!(printed.contains("http://coordinator.internal:8080"), "{printed}");
        assert!(!printed.contains("MARKER") && !printed.contains("coordinator_token"), "{printed}");
        let printed = format!("{chain:?}");
        assert!(printed.contains("outlayer.testnet") && !printed.contains("MARKER") && !printed.contains("rpc."), "{printed}");

        let run = TasksRun {
            declared: true,
            grant: Some(TaskGrant::new(Zeroizing::new([7u8; 32]), true)),
            run: "run-a".to_string(),
            project_id: Some("a.testnet/app".to_string()),
            project_uuid: Some("p0000000000000001".to_string()),
            build: Some("00".repeat(32)),
            operation: None,
            owner: Some("owner.testnet".to_string()),
            profile: Some("probe".to_string()),
            caller: Some("agent.testnet".to_string()),
            predecessor: Some("agent.testnet".to_string()),
            payment_key_nonce: Some(1),
            wallet_id: None,
            bound_identity: false,
            compute_limit_usd: Some("10000".to_string()),
            store: Some(store),
            chain: Some(chain),
            report: RunReport::default(),
        };
        for printed in [format!("{run:?}"), format!("{run:#?}")] {
            assert!(printed.contains("run-a") && printed.contains("owner.testnet"), "{printed}");
            for secret in ["MARKER", "0123456789", "apiKey", "rpc.example", "7, 7", "0707"] {
                assert!(!printed.contains(secret), "{secret} is printed: {printed}");
            }
        }
    }

    #[test]
    fn a_report_holds_what_was_answered_and_takes_a_result_only_for_that() {
        let report = RunReport::default();
        assert!(!report.reported("t-0", b"x".to_vec()));
        report.answered("t-0");
        report.answered("t-0");
        report.answered("t-1");
        assert!(report.reported("t-1", b"sealed".to_vec()));
        assert_eq!(
            report.tasks(),
            vec![
                Answered { id: "t-0".into(), outcome: None },
                Answered { id: "t-1".into(), outcome: Some(b"sealed".to_vec()) }
            ]
        );
        assert!(report.refusals().is_empty());
    }

    #[test]
    fn a_report_holds_the_approved_tasks_the_run_was_refused_by_their_first_reason() {
        let report = RunReport::default();
        report.refused("t-0", "hash-mismatch");
        report.refused("t-0", "closed");
        report.refused("t-1", "approval-invalid");
        assert_eq!(
            report.refusals(),
            vec![
                Refused { id: "t-0".into(), reason: "hash-mismatch".into() },
                Refused { id: "t-1".into(), reason: "approval-invalid".into() }
            ]
        );
        assert!(report.tasks().is_empty(), "a refusal is not an answer");
    }
}
