//! The host interface against a store and a chain that stand in for the
//! coordinator and the RPC: the store holds what it is given and moves
//! states as the coordinator does, and lets a test change what it holds —
//! which is what whoever holds the database can do.
//!
//! The owner's part is the inbox's: their wallet signs an approval, and the
//! store marks the task approved for the run the platform starts. The run
//! that carries a task out is the agent's, with the agent's consent.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use super::wit::Host;
use super::*;
use crate::tasks::client::{Copy, NewTask, Prepared, State, Stored};
use crate::tasks::statement::tests::{approved, device_key, near_key, signed, wallet, FakeChain, Saying, NOW, RECIPIENT};
use crate::tasks::statement::DeviceStatement;

const OWNER: &str = "owner.testnet";
const AGENT: &str = "agent.testnet";
const PROJECT: &str = "p0000000000000001";
/// The build the world's runs are of, and one more of the same project.
const BUILD: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const OTHER_BUILD: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const POLICY: &[u8] = br#"{"confirm":["send"]}"#;

#[derive(Clone)]
struct Row {
    scope: Scope,
    task: NewTask,
    state: State,
    run: Option<String>,
    outcome: Option<Vec<u8>>,
    rejection: Option<Vec<u8>>,
    failure_reason: Option<String>,
    sealed: Option<Vec<u8>>,
    content: Option<Vec<u8>>,
    files: Vec<Vec<u8>>,
    copies: BTreeMap<String, Vec<u8>>,
}

#[derive(Default)]
struct Mem {
    rows: Mutex<BTreeMap<String, Row>>,
    devices: Mutex<Vec<DeviceStatement>>,
    muted: Mutex<Vec<String>>,
    down: AtomicBool,
    most_open: Mutex<Option<usize>>,
    /// The most open tasks of the owner's from one preparer.
    most_of_preparer: Mutex<Option<usize>>,
    most_stored: Mutex<Option<usize>>,
    /// The most copies one request writes: a device that left since the
    /// devices were read gets none.
    most_copies: Mutex<Option<usize>>,
    /// Every request is refused as one the store could not read.
    reads_nothing: AtomicBool,
    /// What becomes of the next `answer`, when not what the store does.
    answer_fault: Mutex<Option<AnswerFault>>,
}

/// An `answer` that does not go as the store's own.
#[derive(Debug, Clone, Copy)]
enum AnswerFault {
    /// The store moves the task to the run, and its reply is lost.
    ReplyLost,
    /// The store refuses by name and moves nothing: another run took the
    /// task between its reading and its answer.
    Refused,
}

impl Mem {
    fn up(&self) -> Result<(), StoreError> {
        if self.reads_nothing.load(Ordering::SeqCst) {
            return Err(StoreError::Refused(Refusal::InvalidRequest, None));
        }
        match self.down.load(Ordering::SeqCst) {
            true => Err(StoreError::Unavailable("the task store did not answer".to_string())),
            false => Ok(()),
        }
    }

    /// The copies of one request that are written.
    fn written<'a>(&self, copies: &'a [Copy], before: usize) -> &'a [Copy] {
        let most = self.most_copies.lock().unwrap().unwrap_or(usize::MAX);
        &copies[..copies.len().min(most.saturating_sub(before))]
    }

    fn row(&self, id: &str) -> Row {
        self.rows.lock().unwrap().get(id).cloned().expect("the row")
    }

    fn change(&self, id: &str, change: impl FnOnce(&mut Row)) {
        change(self.rows.lock().unwrap().get_mut(id).expect("the row"));
    }

    /// Close a task as the coordinator does: the state, and what it showed.
    fn close(row: &mut Row, to: State) {
        row.state = to;
        row.sealed = None;
        row.content = None;
        row.files.clear();
        row.copies.clear();
    }

    /// The inbox's part of an approval: the owner's signature held, the task
    /// `approved` for the run the platform starts. What the task shows stays
    /// until the run takes it.
    fn approve(&self, id: &str, run: &str) {
        self.change(id, |row| {
            assert_eq!(row.state, State::Open, "only an open task is approved");
            row.state = State::Approved;
            row.run = Some(run.to_string());
        });
    }

    /// The run ended, as the store hears of it: what it answered is `done` or
    /// `failed`; an approved task it was refused is `failed` with the reason.
    fn finish(&self, run: &str, success: bool, answered: &[crate::tasks::Answered], refused: &[crate::tasks::Refused]) {
        for row in self.rows.lock().unwrap().values_mut() {
            if row.run.as_deref() != Some(run) {
                continue;
            }
            match row.state {
                State::Answering => match answered.iter().find(|a| a.id == row.task.id).and_then(|a| a.outcome.clone()) {
                    Some(outcome) if success => {
                        row.state = State::Done;
                        row.outcome = Some(outcome);
                    }
                    _ => row.state = State::Failed,
                },
                State::Approved => {
                    if let Some(refusal) = refused.iter().find(|r| r.id == row.task.id) {
                        Mem::close(row, State::Failed);
                        row.failure_reason = Some(format!("run_refused:{}", refusal.reason));
                    }
                }
                _ => {}
            }
        }
    }
}

struct Shared(Arc<Mem>);

impl Store for Shared {
    fn devices(&self, owner: &str) -> Result<Vec<DeviceStatement>, StoreError> {
        self.0.up()?;
        Ok(self.0.devices.lock().unwrap().iter().filter(|d| d.account_id == owner).cloned().collect())
    }

    fn open(&self, scope: &Scope, task: &NewTask) -> Result<u64, StoreError> {
        self.0.up()?;
        if self.0.muted.lock().unwrap().contains(&task.preparer) {
            return Err(StoreError::Refused(Refusal::Muted, None));
        }
        let mut rows = self.0.rows.lock().unwrap();
        let open = rows.values().filter(|r| r.scope.owner == scope.owner && r.state == State::Open).count();
        if self.0.most_open.lock().unwrap().is_some_and(|most| open >= most) {
            return Err(StoreError::Refused(Refusal::InboxFull, None));
        }
        let of_preparer = rows
            .values()
            .filter(|r| r.scope.owner == scope.owner && r.state == State::Open && r.task.preparer == task.preparer)
            .count();
        if self.0.most_of_preparer.lock().unwrap().is_some_and(|most| of_preparer >= most) {
            return Err(StoreError::Refused(Refusal::PreparerFull, None));
        }
        let held: usize = rows
            .values()
            .filter(|r| r.scope.owner == scope.owner && r.state == State::Open)
            .map(|r| r.files.iter().map(Vec::len).sum::<usize>())
            .sum();
        let asked: usize = task.files.iter().map(Vec::len).sum();
        if self.0.most_stored.lock().unwrap().is_some_and(|most| held + asked > most) {
            return Err(StoreError::Refused(Refusal::StorageFull, None));
        }
        if rows.contains_key(&task.id) {
            return Err(StoreError::Refused(Refusal::Exists, None));
        }
        let written = self.0.written(&task.copies, 0);
        rows.insert(
            task.id.clone(),
            Row {
                scope: scope.clone(),
                task: task.clone(),
                state: State::Open,
                run: None,
                outcome: None,
                rejection: None,
                failure_reason: None,
                sealed: Some(task.sealed.clone()),
                content: Some(task.content.clone()),
                files: task.files.clone(),
                copies: written.iter().map(|c| (c.device_id.clone(), c.wrapped_key.clone())).collect(),
            },
        );
        Ok(written.len() as u64)
    }

    fn mine(&self, scope: &Scope, preparer: &str, id: Option<&str>) -> Result<Vec<Prepared>, StoreError> {
        self.0.up()?;
        let rows = self.0.rows.lock().unwrap();
        let found: Vec<Prepared> = rows
            .values()
            .filter(|r| &r.scope == scope && r.task.preparer == preparer && id.is_none_or(|id| id == r.task.id))
            .map(|r| Prepared {
                id: r.task.id.clone(),
                kind: r.task.kind,
                state: r.state,
                created_at: NOW,
                expires_at: r.task.expires_at as i64,
                run: r.run.clone(),
                outcome: r.outcome.clone(),
                rejection: r.rejection.clone(),
                failure_reason: r.failure_reason.clone(),
            })
            .collect();
        match (found.is_empty(), id) {
            (true, Some(_)) => Err(StoreError::Refused(Refusal::NotFound, None)),
            _ => Ok(found),
        }
    }

    fn get(&self, scope: &Scope, id: &str) -> Result<Stored, StoreError> {
        self.0.up()?;
        let rows = self.0.rows.lock().unwrap();
        rows.get(id)
            .filter(|r| &r.scope == scope)
            .map(|r| Stored {
                id: r.task.id.clone(),
                preparer: r.task.preparer.clone(),
                kind: r.task.kind,
                state: r.state,
                expires_at: r.task.expires_at as i64,
                sealed: r.sealed.clone(),
                files: r.files.clone(),
            })
            .ok_or(StoreError::Refused(Refusal::NotFound, None))
    }

    fn waiting(&self, scope: &Scope) -> Result<Vec<Stored>, StoreError> {
        self.0.up()?;
        let ids: Vec<String> = self
            .0
            .rows
            .lock()
            .unwrap()
            .values()
            .filter(|r| &r.scope == scope && matches!(r.state, State::Open | State::Approved))
            .map(|r| r.task.id.clone())
            .collect();
        ids.iter().map(|id| self.get(scope, id)).collect()
    }

    fn copies(&self, scope: &Scope, tasks: &[(String, Vec<Copy>)]) -> Result<client::Written, StoreError> {
        self.0.up()?;
        let mut rows = self.0.rows.lock().unwrap();
        let mut written = client::Written::default();
        for (id, copies) in tasks {
            if let Some(row) = rows.get_mut(id).filter(|r| &r.scope == scope && matches!(r.state, State::Open | State::Approved)) {
                let copies = self.0.written(copies, written.copies as usize);
                row.copies.extend(copies.iter().map(|c| (c.device_id.clone(), c.wrapped_key.clone())));
                written.copies += copies.len() as u64;
                if !copies.is_empty() {
                    written.tasks += 1;
                }
            }
        }
        Ok(written)
    }

    /// `approved → answering`, for the run the approval started and no other:
    /// the coordinator's compare-and-set on the state and the run.
    fn answer(&self, scope: &Scope, id: &str, run: &str) -> Result<(), StoreError> {
        self.0.up()?;
        let fault = self.0.answer_fault.lock().unwrap().take();
        if let Some(AnswerFault::Refused) = fault {
            return Err(StoreError::Refused(Refusal::Closed, Some(State::Answering)));
        }
        let mut rows = self.0.rows.lock().unwrap();
        let row = rows.get_mut(id).filter(|r| &r.scope == scope).ok_or(StoreError::Refused(Refusal::NotFound, None))?;
        if row.state != State::Approved || row.run.as_deref() != Some(run) {
            return Err(StoreError::Refused(Refusal::Closed, Some(row.state)));
        }
        Mem::close(row, State::Answering);
        match fault {
            Some(AnswerFault::ReplyLost) => Err(StoreError::Unavailable("the task store did not answer".to_string())),
            Some(AnswerFault::Refused) | None => Ok(()),
        }
    }

    fn void(&self, scope: &Scope, id: &str) -> Result<(), StoreError> {
        self.0.up()?;
        let mut rows = self.0.rows.lock().unwrap();
        let row = rows.get_mut(id).filter(|r| &r.scope == scope).ok_or(StoreError::Refused(Refusal::NotFound, None))?;
        Mem::close(row, State::Void);
        Ok(())
    }

    fn cancel(&self, scope: &Scope, preparer: &str, id: &str) -> Result<(), StoreError> {
        self.0.up()?;
        let mut rows = self.0.rows.lock().unwrap();
        let row = rows
            .get_mut(id)
            .filter(|r| &r.scope == scope && r.task.preparer == preparer)
            .ok_or(StoreError::Refused(Refusal::NotFound, None))?;
        if row.state != State::Open {
            return Err(StoreError::Refused(Refusal::Closed, Some(row.state)));
        }
        Mem::close(row, State::Cancelled);
        Ok(())
    }

    fn delete(&self, scope: &Scope, preparer: &str, id: &str) -> Result<(), StoreError> {
        self.0.up()?;
        let mut rows = self.0.rows.lock().unwrap();
        match rows.get(id).is_some_and(|r| &r.scope == scope && r.task.preparer == preparer) {
            true => {
                rows.remove(id);
                Ok(())
            }
            false => Err(StoreError::Refused(Refusal::NotFound, None)),
        }
    }
}

struct SharedChain(Arc<FakeChain>);

impl Chain for SharedChain {
    fn access_key(
        &self,
        account: &str,
        public_key: &str,
    ) -> Result<crate::tasks::statement::OnChain, crate::tasks::statement::ChainUnavailable> {
        self.0.access_key(account, public_key)
    }
}

/// One owner, their wallet and one signed-in device; a store and a chain.
struct World {
    store: Arc<Mem>,
    chain: Arc<FakeChain>,
    clock: Arc<AtomicI64>,
    device: p256::SecretKey,
    project_key: [u8; 32],
}

/// The consent of the agent's runs: one payment key, no wallet, so much
/// compute. The run that carries a task out must be this again.
fn agent_consent() -> Consent {
    Consent { payment_key_nonce: 1, wallet: None, bound_identity: false, compute_limit_usd: "10000".to_string() }
}

/// The owner's own runs, over HTTPS with a key of their own.
fn owner_consent() -> Consent {
    Consent { payment_key_nonce: 7, ..agent_consent() }
}

/// How a run came about.
struct Run<'a> {
    caller: &'a str,
    owner: &'a str,
    project_uuid: &'a str,
    by_name: bool,
    id: &'a str,
    build: &'a str,
    /// The vault the owner's row is bound to, as the keystore said.
    vault: Option<&'a str>,
    /// The operation the call names, as the host read it.
    operation: Option<&'a str>,
    /// The payment key, wallet, identity and compute limit the run has; none
    /// on chain.
    consent: Option<Consent>,
}

impl World {
    fn new() -> Self {
        logged();
        let device = device_key();
        let store = Arc::new(Mem::default());
        store.devices.lock().unwrap().push(signed("d1", OWNER, &device.public_key(), NOW + 86_400 * 7, &wallet(1), RECIPIENT));
        Self {
            store,
            chain: Arc::new(FakeChain::holding(&[(OWNER, &near_key(&wallet(1)))])),
            clock: Arc::new(AtomicI64::new(NOW)),
            device,
            project_key: [7u8; 32],
        }
    }

    fn host(&self, run: Run<'_>) -> (TasksHostState, RunReport) {
        let report = RunReport::default();
        // Another project's runs hold another key.
        let key = match run.project_uuid == PROJECT {
            true => self.project_key,
            false => [8u8; 32],
        };
        let clock = self.clock.clone();
        let ready = Ready {
            grant: TaskGrant::new(zeroize::Zeroizing::new(key), run.by_name).under(run.vault.map(str::to_string)),
            run: run.id.to_string(),
            project_id: "connectors.outlayer.testnet/probe".to_string(),
            build: run.build.to_string(),
            operation: run.operation.map(str::to_string),
            scope: Scope { project_uuid: run.project_uuid.to_string(), owner: run.owner.to_string() },
            profile: "probe".to_string(),
            caller: run.caller.to_string(),
            consent: run.consent,
            recipient: RECIPIENT.to_string(),
            store: Box::new(Shared(self.store.clone())),
            chain: Box::new(SharedChain(self.chain.clone())),
            report: report.clone(),
            now: Box::new(move || clock.load(Ordering::SeqCst)),
        };
        let state = TasksHostState { access: Access::Ready(Box::new(ready)), ..TasksHostState::new(None) };
        (state, report)
    }

    fn agent_run(&self) -> Run<'static> {
        Run { caller: AGENT, owner: OWNER, project_uuid: PROJECT, by_name: true, id: "", build: BUILD, vault: None, operation: None, consent: Some(agent_consent()) }
    }

    /// A run of the agent's: the one that prepares, and the one the platform
    /// starts to carry a task out, which is the same account on the same key.
    fn agent(&self, id: &str) -> TasksHostState {
        self.agent_with(id).0
    }

    fn agent_with(&self, id: &str) -> (TasksHostState, RunReport) {
        self.host(Run { id, ..self.agent_run() })
    }

    /// The agent's run with another consent than the preparing run's.
    fn agent_as(&self, id: &str, consent: Option<Consent>) -> (TasksHostState, RunReport) {
        self.host(Run { id, consent, ..self.agent_run() })
    }

    /// The agent's run of another build of the same project.
    fn agent_of_another_build(&self, id: &str) -> (TasksHostState, RunReport) {
        self.host(Run { id, build: OTHER_BUILD, ..self.agent_run() })
    }

    /// The owner's own run, with a key of their own.
    fn owner(&self, id: &str) -> (TasksHostState, RunReport) {
        self.host(Run { caller: OWNER, by_name: false, id, consent: Some(owner_consent()), ..self.agent_run() })
    }

    /// What the owner's page does with a task of the inbox: open the content
    /// key with the device's key, the content with that, and hash it.
    fn page_reads(&self, id: &str) -> (Envelope, String) {
        let row = self.store.row(id);
        let wrapped = row.copies.get("d1").expect("a copy for the device");
        let key = crypto::open_from(&self.device, Purpose::DeviceCopy, id, wrapped).expect("the device opens its copy");
        let key: [u8; 32] = key.as_slice().try_into().unwrap();
        let document = crypto::decrypt_content(&key, id, row.content.as_deref().expect("content")).expect("content opens");
        (Envelope::from_bytes(&document).unwrap(), envelope::hash(&document))
    }

    /// What the owner's page sends with an answer, a note or a rejection.
    fn page_writes(&self, id: &str, purpose: Purpose, text: &[u8]) -> Vec<u8> {
        let (envelope, _) = self.page_reads(id);
        crypto::seal_to(&crypto::read_pubkey(&envelope.reply_pubkey).unwrap(), purpose, id, text).unwrap()
    }

    /// The owner's wallet signs the approval of the task `id` showing `hash`,
    /// with `supplied` and `note` as the page sends them, at the clock's
    /// minute. The signature alone: the store is told nothing.
    fn signed(&self, id: &str, hash: &str, supplied: Option<&[u8]>, note: Option<&[u8]>) -> wit::Approval {
        let at = self.clock.load(Ordering::SeqCst);
        let approval = approved(OWNER, id, hash, supplied, note, at, &wallet(1), RECIPIENT);
        wit::Approval { at: approval.at, public_key: approval.public_key, signature: approval.signature, nonce: approval.nonce }
    }

    /// The inbox's part: the owner signed, and the platform started `run` for
    /// the task. The approval the run's input carries.
    fn approve(&self, task: &wit::Opened, run: &str) -> wit::Approval {
        self.approve_with(task, run, None, None)
    }

    fn approve_with(&self, task: &wit::Opened, run: &str, supplied: Option<&[u8]>, note: Option<&[u8]>) -> wit::Approval {
        self.store.approve(&task.id, run);
        self.signed(&task.id, &task.hash, supplied, note)
    }
}

fn email() -> wit::Request {
    wit::Request {
        kind: wit::TaskKind::Confirm,
        display: wit::Display {
            title: "Send an email".to_string(),
            fields: vec![
                wit::Field {
                    label: "To".to_string(),
                    kind: wit::FieldKind::Address,
                    values: vec!["bob@example.com".to_string()],
                    written_by: wit::WrittenBy::Agent,
                },
                wit::Field {
                    label: "Body".to_string(),
                    kind: wit::FieldKind::LongText,
                    values: vec!["Hello Bob,\nthe report is attached.".to_string()],
                    written_by: wit::WrittenBy::Agent,
                },
            ],
        },
        answer_by: wit::AnswerBy { operation: "confirm".to_string(), supplies: wit::Supplies::Nothing },
        files: vec![],
        state: b"the prepared message".to_vec(),
        policy: POLICY.to_vec(),
        life_seconds: 3600,
    }
}

fn photo() -> wit::Request {
    wit::Request {
        kind: wit::TaskKind::Input,
        display: wit::Display { title: "Give me your photo".to_string(), fields: vec![] },
        answer_by: wit::AnswerBy { operation: "upload_photo".to_string(), supplies: wit::Supplies::File },
        files: vec![],
        state: b"video job 7".to_vec(),
        policy: POLICY.to_vec(),
        life_seconds: 0,
    }
}

fn reason<T: std::fmt::Debug>(result: Result<T, wit::TaskError>) -> wit::Reason {
    result.expect_err("refused").reason
}

/// An approval of nothing: what a call that is refused before the approval
/// is read may carry.
fn no_approval() -> wit::Approval {
    wit::Approval { at: 0, public_key: String::new(), signature: String::new(), nonce: String::new() }
}

/// The agent's run `run` carries out the confirm task `task` with `approval`.
fn confirm(run: &mut TasksHostState, task: &wit::Opened, approval: &wit::Approval) -> Result<wit::Answer, wit::TaskError> {
    run.answered(task.id.clone(), task.hash.clone(), "confirm".to_string(), POLICY.to_vec(), approval.clone(), None, None)
}

/// The owner approves the task `id` showing `hash`, and a fresh run of the
/// agent's, `run-o`, carries it out naming that hash.
fn answer(world: &World, id: &str, hash: &str) -> Result<wit::Answer, wit::TaskError> {
    if world.store.row(id).state == State::Open {
        world.store.approve(id, "run-o");
    }
    let approval = world.signed(id, hash, None, None);
    world.agent("run-o").answered(id.to_string(), hash.to_string(), "confirm".to_string(), POLICY.to_vec(), approval, None, None)
}

// ── the flow ────────────────────────────────────────────────────────────────

#[test]
fn the_agent_prepares_the_owner_reads_with_no_run_approves_with_one_signature_and_the_agents_run_acts() {
    let world = World::new();
    let mut agent = world.agent("run-a");
    let opened = agent.open(email()).unwrap();
    assert_eq!((opened.id.as_str(), opened.thread.as_str(), opened.devices), ("run-a-0", "run-a-0", 1));
    assert_eq!(opened.expires_at, NOW as u64 + 3600);

    // The owner's page: no run, the device's key and the store's bytes.
    let (shown, hash) = world.page_reads(&opened.id);
    assert_eq!(hash, opened.hash, "what the page hashes is what the run said it made");
    assert_eq!(shown.display.title, "Send an email");
    assert_eq!(shown.display.fields[0].values, vec!["bob@example.com"]);
    assert_eq!((shown.owner.as_str(), shown.preparer.as_str()), (OWNER, AGENT));
    assert_eq!(shown.state_hash, envelope::hash(b"the prepared message"));

    assert_eq!(agent.status(opened.id.clone()).unwrap().state, wit::TaskState::Open);

    // The owner signs; the platform starts the agent's run `run-c` with the
    // approval in its input. While the run has not taken the task the agent
    // reads `approved` and the run.
    let approval = world.approve(&opened, "run-c");
    let waiting = world.agent("run-b").status(opened.id.clone()).unwrap();
    assert_eq!((waiting.state, waiting.run.as_deref()), (wit::TaskState::Approved, Some("run-c")));

    let (mut carrier, report) = world.agent_with("run-c");
    let answer = confirm(&mut carrier, &opened, &approval).unwrap();
    assert_eq!(answer.state, b"the prepared message");
    assert_eq!((answer.operation.as_str(), answer.preparer.as_str()), ("confirm", AGENT));
    assert!(answer.supplied.is_none() && answer.note.is_none());

    // What the task showed is gone from the store with the answer.
    let row = world.store.row(&opened.id);
    assert!(row.sealed.is_none() && row.content.is_none() && row.copies.is_empty() && row.files.is_empty());

    // While the run acts the agent is told so, never `done`.
    let during = world.agent("run-b").status(opened.id.clone()).unwrap();
    assert_eq!((during.state, during.run.as_deref()), (wit::TaskState::Answering, Some("run-c")));

    carrier.report(opened.id.clone(), br#"{"message_id":"m1"}"#.to_vec()).unwrap();
    world.store.finish("run-c", true, &report.tasks(), &report.refusals());

    let after = world.agent("run-d").status(opened.id.clone()).unwrap();
    assert_eq!(after.state, wit::TaskState::Done);
    assert_eq!(after.result.as_deref(), Some(&br#"{"message_id":"m1"}"#[..]));
    assert_eq!(after.run.as_deref(), Some("run-c"));
    assert!(after.failure_reason.is_none());
}

#[test]
fn nothing_of_a_task_is_in_the_store_in_the_clear() {
    let world = World::new();
    let opened = world.agent("run-a").open(email()).unwrap();
    let row = world.store.row(&opened.id);
    let stored = [row.sealed.unwrap(), row.content.unwrap(), row.copies["d1"].clone()].concat();
    let text = String::from_utf8_lossy(&stored);
    for word in ["bob@example.com", "Hello Bob", "Send an email", "the prepared message", "confirm", "10000"] {
        assert!(!text.contains(word), "{word}");
    }
    // The outcome and the reason are ciphertext as well.
    let approval = world.approve(&opened, "run-o");
    let (mut carrier, report) = world.agent_with("run-o");
    confirm(&mut carrier, &opened, &approval).unwrap();
    carrier.report(opened.id.clone(), b"message m1 was sent".to_vec()).unwrap();
    let sealed = report.tasks()[0].outcome.clone().unwrap();
    assert!(!String::from_utf8_lossy(&sealed).contains("m1"));
}

#[test]
fn a_run_that_acted_and_failed_leaves_the_task_failed_and_it_does_not_reopen() {
    let world = World::new();
    let opened = world.agent("run-a").open(email()).unwrap();
    let approval = world.approve(&opened, "run-o");
    let (mut carrier, report) = world.agent_with("run-o");
    confirm(&mut carrier, &opened, &approval).unwrap();
    carrier.report(opened.id.clone(), b"sent".to_vec()).unwrap();
    // The run trapped after it reported: a report of a run that failed is nothing.
    world.store.finish("run-o", false, &report.tasks(), &report.refusals());

    let after = world.agent("run-b").status(opened.id.clone()).unwrap();
    assert_eq!((after.state, after.run.as_deref()), (wit::TaskState::Failed, Some("run-o")));
    assert!(after.result.is_none());
    assert_eq!(reason(confirm(&mut world.agent("run-p"), &opened, &approval)), wit::Reason::Closed);
}

#[test]
fn a_task_answered_and_not_reported_on_is_failed() {
    let world = World::new();
    let opened = world.agent("run-a").open(email()).unwrap();
    let approval = world.approve(&opened, "run-o");
    let (mut carrier, report) = world.agent_with("run-o");
    confirm(&mut carrier, &opened, &approval).unwrap();
    world.store.finish("run-o", true, &report.tasks(), &report.refusals());
    assert_eq!(world.agent("run-b").status(opened.id).unwrap().state, wit::TaskState::Failed);
}

#[test]
fn the_owner_supplies_what_was_asked_and_the_run_that_acts_opens_the_next_task_of_the_conversation() {
    let world = World::new();
    let first = world.agent("run-a").open(photo()).unwrap();
    assert_eq!(first.expires_at, NOW as u64 + u64::from(crate::tasks::MAX_LIFE_SECS), "0 is the longest life");
    let supplied = world.page_writes(&first.id, Purpose::Answer, b"ipfs://photo#sha256=abc");
    let approval = world.approve_with(&first, "run-o", Some(&supplied), None);

    let (mut carrier, _) = world.agent_with("run-o");
    let answer = carrier
        .answered(first.id.clone(), first.hash.clone(), "upload_photo".to_string(), POLICY.to_vec(), approval, Some(supplied), None)
        .unwrap();
    assert_eq!(answer.supplied.as_deref(), Some(&b"ipfs://photo#sha256=abc"[..]));
    assert_eq!(answer.state, b"video job 7");

    let next = carrier.open(photo()).unwrap();
    assert_eq!(next.id, "run-o-0");
    assert_eq!(next.thread, first.id, "both are one conversation");
    let (shown, _) = world.page_reads(&next.id);
    assert_eq!(shown.thread, first.id);
    // The turn is the agent's: its run opened it. Sealed so, recorded so,
    // listed among the agent's tasks.
    assert_eq!((shown.owner.as_str(), shown.preparer.as_str()), (OWNER, AGENT));
    assert_eq!(world.store.row(&next.id).task.preparer, AGENT);
    let (mut agent, mut own) = (world.agent("run-b"), world.owner("run-p").0);
    assert_eq!(agent.status(next.id.clone()).unwrap().state, wit::TaskState::Open);
    assert!(agent.mine().unwrap().iter().any(|task| task.id == next.id));
    assert!(own.mine().unwrap().is_empty(), "the owner prepared nothing");

    // The turn is carried out as any task of the agent's is, and the run that
    // carries it out continues the same conversation.
    let supplied = world.page_writes(&next.id, Purpose::Answer, b"ipfs://photo2");
    let approval = world.approve_with(&next, "run-q", Some(&supplied), None);
    let (mut again, _) = world.agent_with("run-q");
    let answer = again
        .answered(next.id.clone(), next.hash.clone(), "upload_photo".to_string(), POLICY.to_vec(), approval, Some(supplied), None)
        .unwrap();
    assert_eq!((answer.thread.as_str(), answer.preparer.as_str()), (first.id.as_str(), AGENT));
    let third = again.open(photo()).unwrap();
    assert_eq!(third.thread, first.id);
    assert_eq!(world.page_reads(&third.id).0.preparer, AGENT);
}

#[test]
fn a_run_that_answered_nothing_opens_a_conversation_of_its_own() {
    let world = World::new();
    let first = world.agent("run-a").open(email()).unwrap();
    let approval = world.approve(&first, "run-o");

    // The run whose answer was refused holds no conversation.
    let (mut refused, _) = world.agent_with("run-o");
    let wrong = world.signed(&first.id, &"0".repeat(64), None, None);
    assert_eq!(
        reason(refused.answered(first.id.clone(), "0".repeat(64), "confirm".to_string(), POLICY.to_vec(), wrong, None, None)),
        wit::Reason::HashMismatch
    );
    let own = refused.open(email()).unwrap();
    assert_eq!(own.thread, own.id);
    assert_eq!(world.page_reads(&own.id).0.preparer, AGENT);

    // Nor does the run that answered after it opened: the task it opened
    // stays a conversation of its own, and the next one is the turn.
    world.store.change(&first.id, |row| row.run = Some("run-l".to_string()));
    let (mut late, _) = world.agent_with("run-l");
    let before = late.open(email()).unwrap();
    confirm(&mut late, &first, &approval).unwrap();
    let after = late.open(email()).unwrap();
    assert_eq!(world.page_reads(&before.id).0.thread, before.id);
    assert_eq!(after.thread, first.id);
}

/// What a run that was refused an approved task does next.
type Refused = fn(&World, &wit::Opened, &wit::Approval) -> (TasksHostState, RunReport, Result<wit::Answer, wit::TaskError>);

/// What the task is once the refused run ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ends {
    /// The refusal was this run's, before anything moved: recorded, and the
    /// task fails with it.
    FailedWithTheReason,
    /// The void closed the task itself.
    Void,
    /// The store did not move the task to this run: it waits as it was.
    StillApproved,
    /// The store moved it and lost its reply: the run reported on it, and it
    /// failed as a task answered and not reported.
    FailedAsAnswered,
}

/// A refusal before the store moves the task is this run's, recorded so the
/// task fails when the run ends; one at or after the move is the store's
/// record to settle.
#[test]
fn an_answer_that_was_refused_starts_no_conversation_and_a_refusal_before_the_move_fails_the_task() {
    use Ends::*;
    let cases: Vec<(&str, wit::Reason, Ends, Refused)> = vec![
        ("a policy that changed", wit::Reason::Void, Void, |world, task, approval| {
            let (mut run, report) = world.agent_with("run-o");
            let changed = br#"{"confirm":[]}"#.to_vec();
            let answered = run.answered(task.id.clone(), task.hash.clone(), "confirm".to_string(), changed, approval.clone(), None, None);
            (run, report, answered)
        }),
        ("another build", wit::Reason::Void, Void, |world, task, approval| {
            let (mut run, report) = world.agent_of_another_build("run-o");
            let answered = confirm(&mut run, task, approval);
            (run, report, answered)
        }),
        ("a task past its life", wit::Reason::Expired, FailedWithTheReason, |world, task, approval| {
            world.clock.store(NOW + 3601, Ordering::SeqCst);
            let (mut run, report) = world.agent_with("run-o");
            let answered = confirm(&mut run, task, approval);
            (run, report, answered)
        }),
        ("the owner's own run", wit::Reason::NotThePreparer, FailedWithTheReason, |world, task, approval| {
            let (mut run, report) = world.owner("run-o");
            let answered = confirm(&mut run, task, approval);
            (run, report, answered)
        }),
        ("an approval another key signed", wit::Reason::ApprovalInvalid, FailedWithTheReason, |world, task, _| {
            let forged = approved(OWNER, &task.id, &task.hash, None, None, NOW, &wallet(9), RECIPIENT);
            let forged = wit::Approval { at: forged.at, public_key: forged.public_key, signature: forged.signature, nonce: forged.nonce };
            let (mut run, report) = world.agent_with("run-o");
            let answered = confirm(&mut run, task, &forged);
            (run, report, answered)
        }),
        ("a chain that gives no answer about the key", wit::Reason::Unavailable, FailedWithTheReason, |world, task, approval| {
            let (mut run, report) = world.agent_with("run-o");
            let mut down = FakeChain::holding(&[]);
            down.down = true;
            match &mut run.access {
                Access::Ready(ready) => ready.chain = Box::new(down),
                Access::Refused(..) => panic!("a run that may use tasks"),
            }
            let answered = confirm(&mut run, task, approval);
            (run, report, answered)
        }),
        ("another project", wit::Reason::NotFound, StillApproved, |world, task, approval| {
            let other = "p0000000000000002";
            let (mut run, report) = world.host(Run { project_uuid: other, id: "run-o", ..world.agent_run() });
            let answered = confirm(&mut run, task, approval);
            (run, report, answered)
        }),
        ("a store that refused the answer", wit::Reason::Closed, StillApproved, |world, task, approval| {
            *world.store.answer_fault.lock().unwrap() = Some(AnswerFault::Refused);
            let (mut run, report) = world.agent_with("run-o");
            let answered = confirm(&mut run, task, approval);
            (run, report, answered)
        }),
        ("a store whose reply was lost", wit::Reason::Unavailable, FailedAsAnswered, |world, task, approval| {
            *world.store.answer_fault.lock().unwrap() = Some(AnswerFault::ReplyLost);
            let (mut run, report) = world.agent_with("run-o");
            let answered = confirm(&mut run, task, approval);
            (run, report, answered)
        }),
    ];
    for (case, expected, ends, refused) in cases {
        let world = World::new();
        let task = world.agent("run-a").open(email()).unwrap();
        let approval = world.approve(&task, "run-o");
        let (mut run, report, answered) = refused(&world, &task, &approval);
        assert_eq!(reason(answered), expected, "{case}");
        let refusals = report.refusals();
        match ends {
            FailedWithTheReason | Void => {
                assert_eq!(refusals, vec![crate::tasks::Refused { id: task.id.clone(), reason: reason_name(expected).to_string() }], "{case}")
            }
            StillApproved | FailedAsAnswered => assert!(refusals.is_empty(), "{case}: the store's record settles it"),
        }
        // A run whose chain is down opens nothing either; every other opens
        // a conversation of its own.
        if !case.starts_with("a chain") {
            let own = run.open(email()).unwrap_or_else(|e| panic!("{case}: {e:?}"));
            assert_eq!(own.thread, own.id, "{case}: a conversation of its own");
        }
        // The run ends: a refusal recorded fails the task with its reason.
        world.store.finish("run-o", true, &report.tasks(), &report.refusals());
        let after = world.store.row(&task.id);
        let seen = world.agent("run-z").status(task.id.clone()).unwrap();
        match ends {
            FailedWithTheReason => {
                let why = format!("run_refused:{}", reason_name(expected));
                assert_eq!((after.state, after.failure_reason.as_deref()), (State::Failed, Some(why.as_str())), "{case}");
                assert!(after.sealed.is_none() && after.content.is_none(), "{case}: what it showed is gone");
                assert_eq!((seen.state, seen.failure_reason.as_deref()), (wit::TaskState::Failed, Some(why.as_str())), "{case}");
            }
            Void => assert_eq!((after.state, after.failure_reason), (State::Void, None), "{case}"),
            StillApproved => assert_eq!((after.state, after.failure_reason), (State::Approved, None), "{case}"),
            FailedAsAnswered => assert_eq!((after.state, after.failure_reason), (State::Failed, None), "{case}"),
        }
    }
}

#[test]
fn a_task_the_owner_has_not_approved_takes_no_answer_and_no_refusal_is_recorded() {
    let world = World::new();
    let opened = world.agent("run-a").open(email()).unwrap();
    let approval = world.signed(&opened.id, &opened.hash, None, None);
    let (mut carrier, report) = world.agent_with("run-o");
    let refused = confirm(&mut carrier, &opened, &approval).unwrap_err();
    assert_eq!(refused.reason, wit::Reason::ApprovalInvalid);
    assert!(refused.message.contains("has not approved"), "{}", refused.message);
    assert!(report.refusals().is_empty(), "the task is not approved: nothing of it fails with this run");
    assert_eq!(world.store.row(&opened.id).state, State::Open);
}

#[test]
fn a_task_approved_for_another_run_is_closed_to_this_one() {
    let world = World::new();
    let opened = world.agent("run-a").open(email()).unwrap();
    let approval = world.approve(&opened, "run-x");
    let (mut carrier, report) = world.agent_with("run-o");
    assert_eq!(reason(confirm(&mut carrier, &opened, &approval)), wit::Reason::Closed);
    assert!(report.refusals().is_empty() && report.tasks().is_empty());
    assert_eq!(world.store.row(&opened.id).state, State::Approved, "it waits for the run it was approved for");
    assert!(confirm(&mut world.agent("run-x"), &opened, &approval).is_ok());
}

#[test]
fn a_run_that_answered_two_conversations_opens_no_turn() {
    let world = World::new();
    let first = world.agent("run-a").open(email()).unwrap();
    let second = world.agent("run-b").open(email()).unwrap();
    let (first_ok, second_ok) = (world.approve(&first, "run-o"), world.approve(&second, "run-o"));
    let (mut carrier, _) = world.agent_with("run-o");
    confirm(&mut carrier, &first, &first_ok).unwrap();
    assert_eq!(carrier.open(email()).unwrap().thread, first.id, "one conversation answered: its turn");
    confirm(&mut carrier, &second, &second_ok).unwrap();
    let made = world.store.rows.lock().unwrap().len();
    let refused = carrier.open(email()).expect_err("refused");
    assert_eq!(refused.reason, wit::Reason::Internal);
    assert_eq!(refused.message, "this run answered tasks of more than one conversation, so a task it opens belongs to none");
    assert_eq!(world.store.rows.lock().unwrap().len(), made, "no task is made");

    // Two tasks of one conversation are one conversation.
    let start = world.agent("run-c").open(email()).unwrap();
    let ok = world.approve(&start, "run-p");
    let (mut middle, _) = world.agent_with("run-p");
    confirm(&mut middle, &start, &ok).unwrap();
    let (one, two) = (middle.open(email()).unwrap(), middle.open(email()).unwrap());
    let (one_ok, two_ok) = (world.approve(&one, "run-q"), world.approve(&two, "run-q"));
    let (mut last, _) = world.agent_with("run-q");
    confirm(&mut last, &one, &one_ok).unwrap();
    confirm(&mut last, &two, &two_ok).unwrap();
    let next = last.open(email()).unwrap();
    assert_eq!((next.thread.as_str(), world.page_reads(&next.id).0.preparer.as_str()), (start.id.as_str(), AGENT));
}

#[test]
fn a_turn_is_the_agents_to_read_withdraw_and_delete_from_any_run_of_the_agents() {
    let world = World::new();
    let first = world.agent("run-a").open(email()).unwrap();
    let approval = world.approve(&first, "run-o");
    let (mut carrier, _) = world.agent_with("run-o");
    confirm(&mut carrier, &first, &approval).unwrap();
    let turn = carrier.open(email()).unwrap();
    assert_eq!(world.store.row(&turn.id).task.preparer, AGENT);
    assert_eq!(carrier.status(turn.id.clone()).unwrap().state, wit::TaskState::Open);
    // Another run of the agent's reaches it: the task is the account's, not
    // the run's.
    let mut another = world.agent("run-b");
    assert_eq!(another.status(turn.id.clone()).unwrap().state, wit::TaskState::Open);
    another.cancel(turn.id.clone()).unwrap();
    assert_eq!(carrier.status(turn.id.clone()).unwrap().state, wit::TaskState::Cancelled);

    let other = carrier.open(email()).unwrap();
    world.agent("run-c").delete(other.id.clone()).unwrap();
    assert_eq!(reason(carrier.status(other.id)), wit::Reason::NotFound);

    // The owner's run prepared none of them.
    assert_eq!(reason(world.owner("run-p").0.status(turn.id)), wit::Reason::NotFound);
}

#[test]
fn a_turn_counts_in_the_agents_share_and_under_the_agents_mute() {
    let world = World::new();
    *world.store.most_of_preparer.lock().unwrap() = Some(2);
    let first = world.agent("run-a").open(photo()).unwrap();
    world.agent("run-b").open(email()).unwrap();
    let full = world.agent("run-c").open(email()).expect_err("the agent's share is full");
    assert_eq!(full.reason, wit::Reason::InboxFull);
    assert!(full.message.contains("this agent holds as many tasks waiting on this owner"), "{}", full.message);
    let supplied = world.page_writes(&first.id, Purpose::Answer, b"ipfs://photo");
    let approval = world.approve_with(&first, "run-o", Some(&supplied), None);

    // The answer takes the first task out of the open ones: one of the
    // agent's is open, and the turn is the second.
    let (mut carrier, _) = world.agent_with("run-o");
    carrier
        .answered(first.id.clone(), first.hash.clone(), "upload_photo".to_string(), POLICY.to_vec(), approval, Some(supplied), None)
        .unwrap();
    carrier.open(photo()).unwrap();
    assert_eq!(reason(carrier.open(photo())), wit::Reason::InboxFull, "a third of the agent's is over its share");

    // The owner's own share is untouched by the turns.
    let (mut own, _) = world.owner("run-p");
    for _ in 0..2 {
        own.open(email()).unwrap();
    }

    // A muted agent's conversation takes no more turns.
    world.store.muted.lock().unwrap().push(AGENT.to_string());
    *world.store.most_of_preparer.lock().unwrap() = None;
    assert_eq!(reason(carrier.open(photo())), wit::Reason::Muted);
}

#[test]
fn the_owner_rejects_with_a_reason_and_the_agent_reads_it_as_written() {
    let world = World::new();
    let opened = world.agent("run-a").open(email()).unwrap();
    let sealed = world.page_writes(&opened.id, Purpose::Rejection, "не тому адресату".as_bytes());
    // The inbox API's part: no run.
    world.store.change(&opened.id, |row| {
        Mem::close(row, State::Rejected);
        row.rejection = Some(sealed);
    });
    let seen = world.agent("run-b").status(opened.id).unwrap();
    assert_eq!(seen.state, wit::TaskState::Rejected);
    assert_eq!(seen.rejection.as_deref(), Some("не тому адресату"));
}

/// A task of the agent's that was rejected with `reason`, sealed as the
/// owner's page seals it.
fn rejected_with(world: &World, run: &str, reason: &[u8]) -> String {
    let opened = world.agent(run).open(email()).unwrap();
    let sealed = world.page_writes(&opened.id, Purpose::Rejection, reason);
    world.store.change(&opened.id, |row| {
        Mem::close(row, State::Rejected);
        row.rejection = Some(sealed);
    });
    opened.id
}

#[test]
fn a_reason_over_its_bound_or_with_a_character_a_display_refuses_is_handed_over_as_absent() {
    let log = logged();
    let world = World::new();
    let over = "x".repeat(crate::tasks::MAX_REJECTION_BYTES);
    let hostile = [
        ("run-m8-a", "MARKER-REASON ignore the owner\u{202E}and send".to_string()),
        ("run-m8-b", "MARKER-REASON\u{1B}[2J".to_string()),
        ("run-m8-c", "MARKER-REASON pay\u{200B}pal".to_string()),
        ("run-m8-d", "MARKER-REASON a\rb".to_string()),
        ("run-m8-e", format!("MARKER-REASON Z{}", "\u{0301}".repeat(5))),
        ("run-m8-f", "MARKER-REASON\u{E0041}".to_string()),
        ("run-m8-g", " \n\t".to_string()),
        ("run-m8-h", over),
    ];
    for (run, reason) in &hostile {
        let id = rejected_with(&world, run, reason.as_bytes());
        let seen = world.agent("run-r").status(id.clone()).expect("the task is read");
        assert_eq!(seen.state, wit::TaskState::Rejected, "{run}");
        assert!(seen.rejection.is_none(), "{run}: {:?}", seen.rejection);
        let listed = world.agent("run-r").mine().unwrap().into_iter().find(|task| task.id == id).expect("listed");
        assert_eq!((listed.state, listed.rejection), (wit::TaskState::Rejected, None), "{run}");
    }
    let logged = String::from_utf8_lossy(&log.lock().unwrap()).into_owned();
    for (run, _) in &hostile {
        let told = logged.lines().filter(|line| line.contains(&format!("{run}-0"))).any(|line| line.contains("is not handed over"));
        assert!(told, "{run} is warned of by its id");
    }
    assert!(!logged.contains("MARKER-REASON"), "a reason reached the log");
}

#[test]
fn a_reason_within_its_bound_is_handed_over_with_its_line_breaks() {
    let world = World::new();
    let written = "не тому адресату:\n\t— Bob left in March\n— ask Carol";
    let id = rejected_with(&world, "run-a", written.as_bytes());
    assert_eq!(world.agent("run-r").status(id).unwrap().rejection.as_deref(), Some(written));

    // The longest the sealed bound holds.
    let sealed_around = world.page_writes(&world.agent("run-b").open(email()).unwrap().id, Purpose::Rejection, b"").len();
    let longest = "x".repeat(crate::tasks::MAX_REJECTION_BYTES - sealed_around);
    let id = rejected_with(&world, "run-c", longest.as_bytes());
    assert_eq!(world.agent("run-r").status(id).unwrap().rejection.as_deref(), Some(longest.as_str()));
    let id = rejected_with(&world, "run-d", format!("{longest}x").as_bytes());
    assert!(world.agent("run-r").status(id).unwrap().rejection.is_none());
}

#[test]
fn nothing_is_a_list_of_nothing_and_a_store_that_is_down_is_an_error() {
    let world = World::new();
    assert!(world.agent("run-a").mine().unwrap().is_empty());
    world.store.down.store(true, Ordering::SeqCst);
    assert_eq!(reason(world.agent("run-a").mine()), wit::Reason::Unavailable);
    assert_eq!(reason(world.agent("run-a").status("run-a-0".to_string())), wit::Reason::Unavailable);
    assert_eq!(reason(world.agent("run-a").open(email())), wit::Reason::Unavailable);
    assert_eq!(reason(world.owner("run-o").0.unlock()), wit::Reason::Unavailable);
}

#[test]
fn a_task_never_made_deleted_or_anothers_is_not_found() {
    let world = World::new();
    let mut agent = world.agent("run-a");
    let opened = agent.open(email()).unwrap();
    assert_eq!(reason(agent.status("run-z-0".to_string())), wit::Reason::NotFound);
    let mut second = world.host(Run { caller: "second.testnet", id: "run-s", ..world.agent_run() }).0;
    assert_eq!(reason(second.status(opened.id.clone())), wit::Reason::NotFound);
    assert!(second.mine().unwrap().is_empty());
    assert_eq!(reason(second.cancel(opened.id.clone())), wit::Reason::NotFound);
    assert_eq!(reason(second.delete(opened.id.clone())), wit::Reason::NotFound);
    agent.delete(opened.id.clone()).unwrap();
    assert_eq!(reason(agent.status(opened.id)), wit::Reason::NotFound);
}

#[test]
fn the_agent_cancels_its_task_and_it_takes_no_approval() {
    let world = World::new();
    let mut agent = world.agent("run-a");
    let opened = agent.open(email()).unwrap();
    agent.cancel(opened.id.clone()).unwrap();
    assert_eq!(agent.status(opened.id.clone()).unwrap().state, wit::TaskState::Cancelled);
    assert_eq!(reason(agent.cancel(opened.id.clone())), wit::Reason::Closed);
    let approval = world.signed(&opened.id, &opened.hash, None, None);
    assert_eq!(reason(confirm(&mut world.agent("run-o"), &opened, &approval)), wit::Reason::Closed);
}

// ── who may ─────────────────────────────────────────────────────────────────

#[test]
fn a_run_admitted_by_a_rule_that_names_nobody_opens_no_task() {
    let world = World::new();
    let mut open_row = world.host(Run { by_name: false, id: "run-a", ..world.agent_run() }).0;
    assert_eq!(reason(open_row.open(email())), wit::Reason::NotGrantedByName);
    assert!(world.store.rows.lock().unwrap().is_empty());
    // The owner's own run opens one, however their row admits.
    world.owner("run-o").0.open(email()).unwrap();
}

/// The consent to carry a task out is a payment key: a run with none — one
/// on chain — opens no task, whoever made it.
#[test]
fn a_run_with_no_payment_key_opens_no_task() {
    let world = World::new();
    for (who, by_name) in [(AGENT, true), (OWNER, false)] {
        let mut keyless = world.host(Run { caller: who, by_name, id: "run-k", consent: None, ..world.agent_run() }).0;
        let refused = keyless.open(email()).expect_err("refused");
        assert_eq!(refused.reason, wit::Reason::NoPaymentKey, "{who}");
        assert!(refused.message.contains("payment key") && refused.message.contains("HTTPS"), "{}", refused.message);
        // Everything else of the interface is open to it.
        assert!(keyless.mine().unwrap().is_empty());
    }
    assert!(world.store.rows.lock().unwrap().is_empty());
}

/// The task is carried out by the preparer's run the consent names, and by
/// no other: not the owner's, not the agent's on another key, wallet or
/// identity, not with more compute than the preparing run allowed.
#[test]
fn only_the_preparers_run_on_the_consented_key_wallet_identity_and_compute_carries_a_task_out() {
    let world = World::new();
    let opened = world.agent("run-a").open(email()).unwrap();
    let approval = world.approve(&opened, "run-o");
    let refused_as = |consent: Consent| {
        let (mut run, report) = world.agent_as("run-o", Some(consent));
        let refused = confirm(&mut run, &opened, &approval).expect_err("refused");
        assert_eq!(refused.reason, wit::Reason::NotThePreparer);
        assert_eq!(report.refusals().len(), 1, "recorded: the owner said yes to a run that did not act");
        assert_eq!(world.store.row(&opened.id).state, State::Approved, "nothing moved");
        refused.message
    };
    assert!(refused_as(Consent { payment_key_nonce: 2, ..agent_consent() }).contains("another payment key"));
    assert!(refused_as(Consent { wallet: Some("w-1".into()), ..agent_consent() }).contains("another wallet"));
    assert!(refused_as(Consent { bound_identity: true, ..agent_consent() }).contains("another identity"));
    assert!(refused_as(Consent { compute_limit_usd: "10001".into(), ..agent_consent() }).contains("more compute"));

    // The agent's run with no payment key at all.
    let (mut keyless, _) = world.agent_as("run-o", None);
    assert!(confirm(&mut keyless, &opened, &approval).unwrap_err().message.contains("no payment key"));

    // The owner's own run: another account's.
    let (mut owner, _) = world.owner("run-o");
    let refused = confirm(&mut owner, &opened, &approval).unwrap_err();
    assert_eq!(refused.reason, wit::Reason::NotThePreparer);
    assert!(refused.message.contains("another account"), "{}", refused.message);
    assert_eq!(reason(owner.report(opened.id.clone(), b"x".to_vec())), wit::Reason::NotFound, "it answered no task");

    // Less compute than the preparing run allowed is within the consent.
    let (mut thrifty, _) = world.agent_as("run-o", Some(Consent { compute_limit_usd: "9999".into(), ..agent_consent() }));
    assert!(confirm(&mut thrifty, &opened, &approval).is_ok());

    // `unlock` stays the owner's.
    assert_eq!(reason(world.agent("run-u").unlock()), wit::Reason::NotTheOwner);
}

#[test]
fn a_run_with_its_own_row_reaches_nothing_of_the_owner_who_granted_it() {
    let world = World::new();
    let opened = world.agent("run-a").open(email()).unwrap();
    let approval = world.approve(&opened, "run-b");
    // The same agent, run with its own row: the owner of THAT run is the agent.
    let mut own = world.host(Run { owner: AGENT, by_name: false, id: "run-b", ..world.agent_run() }).0;
    assert_eq!(reason(own.status(opened.id.clone())), wit::Reason::NotFound);
    assert_eq!(reason(confirm(&mut own, &opened, &approval)), wit::Reason::NotFound);
    // And what it opens there is addressed to itself.
    let mine = own.open(email()).unwrap();
    assert_eq!(world.store.row(&mine.id).scope.owner, AGENT);
}

#[test]
fn another_project_reaches_nothing_of_this_projects_tasks() {
    let world = World::new();
    let opened = world.agent("run-a").open(email()).unwrap();
    let approval = world.approve(&opened, "run-o");
    let other = "p0000000000000002";
    let mut agent = world.host(Run { project_uuid: other, id: "run-b", ..world.agent_run() }).0;
    assert_eq!(reason(agent.status(opened.id.clone())), wit::Reason::NotFound);
    let mut carrier = world.host(Run { project_uuid: other, id: "run-o", ..world.agent_run() }).0;
    assert_eq!(reason(confirm(&mut carrier, &opened, &approval)), wit::Reason::NotFound);
    let mut owner = world.host(Run { caller: OWNER, by_name: false, project_uuid: other, id: "run-p", consent: Some(owner_consent()), ..world.agent_run() }).0;
    assert_eq!(owner.unlock().unwrap(), 0);

    // Even with the row moved to it in the store, it holds another key.
    world.store.change(&opened.id, |row| row.scope.project_uuid = other.to_string());
    assert_eq!(reason(confirm(&mut carrier, &opened, &approval)), wit::Reason::Unreadable);
}

#[test]
fn a_muted_agent_and_a_full_inbox_are_refused_by_name() {
    let world = World::new();
    world.store.muted.lock().unwrap().push(AGENT.to_string());
    assert_eq!(reason(world.agent("run-a").open(email())), wit::Reason::Muted);
    world.store.muted.lock().unwrap().clear();
    *world.store.most_open.lock().unwrap() = Some(1);
    world.agent("run-b").open(email()).unwrap();
    assert_eq!(reason(world.agent("run-c").open(email())), wit::Reason::InboxFull);
}

#[test]
fn one_run_opens_so_many_tasks_and_no_more() {
    let world = World::new();
    let mut agent = world.agent("run-a");
    for n in 0..crate::tasks::MAX_OPENS_PER_RUN {
        assert_eq!(agent.open(email()).unwrap().id, format!("run-a-{n}"));
    }
    assert_eq!(reason(agent.open(email())), wit::Reason::RunLimit);
}

#[test]
fn a_run_that_may_not_use_tasks_is_told_why_by_every_call() {
    let run = |declared, with_row: bool| TasksRun {
        declared,
        grant: with_row.then(|| TaskGrant::new(zeroize::Zeroizing::new([7u8; 32]), true)),
        run: "run-a".to_string(),
        project_id: Some("a.testnet/app".to_string()),
        project_uuid: Some(PROJECT.to_string()),
        build: Some(BUILD.to_string()),
        operation: None,
        owner: with_row.then(|| OWNER.to_string()),
        profile: with_row.then(|| "probe".to_string()),
        caller: Some(AGENT.to_string()),
        predecessor: Some(AGENT.to_string()),
        payment_key_nonce: Some(1),
        wallet_id: None,
        bound_identity: false,
        compute_limit_usd: Some("10000".to_string()),
        store: None,
        chain: None,
        report: RunReport::default(),
    };
    assert_eq!(reason(TasksHostState::new(None).mine()), wit::Reason::NotDeclared);
    assert_eq!(reason(TasksHostState::new(Some(run(false, true))).open(email())), wit::Reason::NotDeclared);
    assert_eq!(reason(TasksHostState::new(Some(run(true, false))).open(email())), wit::Reason::NoOwner);
    assert_eq!(reason(TasksHostState::new(Some(run(true, false))).mine()), wit::Reason::NoOwner);
    let direct = TasksRun { project_id: None, project_uuid: None, ..run(true, true) };
    assert_eq!(reason(TasksHostState::new(Some(direct)).unlock()), wit::Reason::NoOwner);
    assert_eq!(reason(TasksHostState::new(Some(run(true, true))).mine()), wit::Reason::Unavailable);
}

/// The owner signs a transaction to a contract, and the contract calls
/// OutLayer naming the owner's row and a task to answer. The signer is the
/// owner; the run is not the owner's act, and uses no tasks.
#[test]
fn a_run_a_contract_relayed_uses_no_tasks_whoever_signed_it() {
    let relayed = |signer: &str, called: Option<&str>| TasksRun {
        declared: true,
        grant: Some(TaskGrant::new(zeroize::Zeroizing::new([7u8; 32]), true)),
        run: "run-r".to_string(),
        project_id: Some("a.testnet/app".to_string()),
        project_uuid: Some(PROJECT.to_string()),
        build: Some(BUILD.to_string()),
        operation: None,
        owner: Some(OWNER.to_string()),
        profile: Some("probe".to_string()),
        caller: Some(signer.to_string()),
        predecessor: called.map(str::to_string),
        payment_key_nonce: None,
        wallet_id: None,
        bound_identity: false,
        compute_limit_usd: None,
        store: None,
        chain: None,
        report: RunReport::default(),
    };
    for signer in [OWNER, AGENT] {
        for called in [Some("relay.testnet"), None] {
            let mut host = TasksHostState::new(Some(relayed(signer, called)));
            assert_eq!(reason(host.open(email())), wit::Reason::Relayed, "{signer} {called:?}");
            assert_eq!(reason(host.mine()), wit::Reason::Relayed);
            assert_eq!(reason(host.status("run-a-0".to_string())), wit::Reason::Relayed);
            assert_eq!(
                reason(host.answered("run-a-0".to_string(), "00".repeat(32), "confirm".to_string(), vec![], no_approval(), None, None)),
                wit::Reason::Relayed
            );
            assert_eq!(reason(host.cancel("run-a-0".to_string())), wit::Reason::Relayed);
            assert_eq!(reason(host.unlock()), wit::Reason::Relayed);
        }
    }
    // Called by the account that signed: the run gets as far as its store.
    let own = relayed(OWNER, Some(OWNER));
    assert_eq!(reason(TasksHostState::new(Some(own)).mine()), wit::Reason::Unavailable);
}

#[test]
fn a_run_makes_so_many_calls_and_no_more() {
    let world = World::new();
    let mut agent = world.agent("run-a");
    for _ in 0..crate::tasks::MAX_CALLS_PER_RUN {
        agent.mine().unwrap();
    }
    assert_eq!(reason(agent.mine()), wit::Reason::RunLimit);
}

// ── devices ─────────────────────────────────────────────────────────────────

#[test]
fn a_device_written_into_the_store_by_anyone_but_the_owners_wallet_gets_no_copy() {
    let world = World::new();
    let forged = device_key();
    // Signed, correctly, by a key that is not the owner's.
    world.store.devices.lock().unwrap().push(signed("forged", OWNER, &forged.public_key(), NOW + 3600, &wallet(9), RECIPIENT));
    // The owner's statement, with the device's key replaced.
    let mut replaced = signed("replaced", OWNER, &device_key().public_key(), NOW + 3600, &wallet(1), RECIPIENT);
    replaced.device_pubkey = crypto::write_pubkey(&forged.public_key());
    world.store.devices.lock().unwrap().push(replaced);
    // Another account's device, presented as the owner's.
    let mut anothers = signed("anothers", "other.testnet", &forged.public_key(), NOW + 3600, &wallet(1), RECIPIENT);
    anothers.account_id = OWNER.to_string();
    world.store.devices.lock().unwrap().push(anothers);

    let opened = world.agent("run-a").open(email()).unwrap();
    assert_eq!(opened.devices, 1);
    assert_eq!(world.store.row(&opened.id).copies.keys().collect::<Vec<_>>(), vec!["d1"]);
}

#[test]
fn a_key_removed_from_the_account_names_no_device_from_the_next_task_on() {
    let world = World::new();
    assert_eq!(world.agent("run-a").open(email()).unwrap().devices, 1);
    let removed = World { chain: Arc::new(FakeChain::holding(&[])), ..World::new() };
    let opened = removed.agent("run-b").open(email()).unwrap();
    assert_eq!(opened.devices, 0);
    assert!(removed.store.row(&opened.id).copies.is_empty());
}

#[test]
fn no_task_is_opened_while_the_chain_cannot_say_whose_the_keys_are() {
    let mut chain = FakeChain::holding(&[(OWNER, &near_key(&wallet(1)))]);
    chain.down = true;
    let world = World { chain: Arc::new(chain), ..World::new() };
    assert_eq!(reason(world.agent("run-a").open(email())), wit::Reason::Unavailable);
    assert!(world.store.rows.lock().unwrap().is_empty(), "none made as if the owner had no device");
    assert_eq!(reason(world.owner("run-o").0.unlock()), wit::Reason::Unavailable);
}

#[test]
fn a_task_made_before_the_owner_signed_in_opens_after_one_run() {
    let world = World::new();
    world.store.devices.lock().unwrap().clear();
    let opened = world.agent("run-a").open(email()).unwrap();
    assert_eq!(opened.devices, 0);
    assert!(world.store.row(&opened.id).copies.is_empty(), "locked, not absent");

    // The owner signs in, and runs the project once.
    world.store.devices.lock().unwrap().push(signed("d1", OWNER, &world.device.public_key(), NOW + 3600, &wallet(1), RECIPIENT));
    assert_eq!(world.owner("run-o").0.unlock().unwrap(), 1);

    // Free from then on.
    let (shown, hash) = world.page_reads(&opened.id);
    assert_eq!((shown.display.title.as_str(), hash), ("Send an email", opened.hash));
}

#[test]
fn the_devices_are_read_once_in_a_run() {
    let world = World::new();
    let mut agent = world.agent("run-a");
    agent.open(email()).unwrap();
    agent.open(email()).unwrap();
    assert_eq!(world.chain.asked.load(Ordering::SeqCst), 1);
}

#[test]
fn a_run_whose_task_the_store_refused_asks_the_chain_of_the_devices_once() {
    let world = World::new();
    world.store.muted.lock().unwrap().push(AGENT.to_string());
    let mut agent = world.agent("run-a");
    for _ in 0..3 {
        assert_eq!(reason(agent.open(email())), wit::Reason::Muted);
    }
    assert_eq!(world.chain.asked.load(Ordering::SeqCst), 1);

    // The list read by a call that was refused is the run's list.
    world.store.muted.lock().unwrap().clear();
    world.store.devices.lock().unwrap().clear();
    assert_eq!(agent.open(email()).unwrap().devices, 1);
    assert_eq!(world.chain.asked.load(Ordering::SeqCst), 1);
}

#[test]
fn the_owners_run_that_opens_and_unlocks_reads_the_devices_once() {
    let world = World::new();
    let (mut owner, _) = world.owner("run-o");
    *world.store.most_open.lock().unwrap() = Some(0);
    assert_eq!(reason(owner.open(email())), wit::Reason::InboxFull);
    *world.store.most_open.lock().unwrap() = None;
    owner.open(email()).unwrap();
    owner.unlock().unwrap();
    owner.unlock().unwrap();
    assert_eq!(world.chain.asked.load(Ordering::SeqCst), 1);
}

/// A chain that answers, or does not, as the test says at the time.
struct Flaky {
    chain: Arc<FakeChain>,
    down: Arc<AtomicBool>,
}

impl Chain for Flaky {
    fn access_key(
        &self,
        account: &str,
        public_key: &str,
    ) -> Result<crate::tasks::statement::OnChain, crate::tasks::statement::ChainUnavailable> {
        match self.down.load(Ordering::SeqCst) {
            true => Err(crate::tasks::statement::ChainUnavailable("the chain did not answer".to_string())),
            false => self.chain.access_key(account, public_key),
        }
    }
}

#[test]
fn devices_that_could_not_be_read_are_no_list_and_are_read_again() {
    let world = World::new();
    let down = Arc::new(AtomicBool::new(true));
    let mut agent = world.agent("run-a");
    match &mut agent.access {
        Access::Ready(ready) => ready.chain = Box::new(Flaky { chain: world.chain.clone(), down: down.clone() }),
        Access::Refused(..) => panic!("a run that may use tasks"),
    }
    // The chain gave no answer: not an owner without devices, and not kept as one.
    assert_eq!(reason(agent.open(email())), wit::Reason::Unavailable);
    down.store(false, Ordering::SeqCst);
    // Nor did the store.
    world.store.down.store(true, Ordering::SeqCst);
    assert_eq!(reason(agent.open(email())), wit::Reason::Unavailable);
    world.store.down.store(false, Ordering::SeqCst);

    let opened = agent.open(email()).unwrap();
    assert_eq!(opened.devices, 1);
    assert_eq!(world.store.row(&opened.id).copies.keys().collect::<Vec<_>>(), vec!["d1"]);
    assert_eq!(world.chain.asked.load(Ordering::SeqCst), 1);
}

#[test]
fn the_guest_is_told_of_the_copies_the_store_wrote_not_of_the_devices_that_were_read() {
    let world = World::new();
    let second = device_key();
    world.store.devices.lock().unwrap().push(signed("d2", OWNER, &second.public_key(), NOW + 3600, &wallet(1), RECIPIENT));
    assert_eq!(world.agent("run-a").open(email()).unwrap().devices, 2);

    // A device left between the read of the devices and the task's making.
    *world.store.most_copies.lock().unwrap() = Some(1);
    let opened = world.agent("run-b").open(email()).unwrap();
    assert_eq!(opened.devices, 1);
    assert_eq!(world.store.row(&opened.id).copies.len(), 1);

    *world.store.most_copies.lock().unwrap() = Some(0);
    let opened = world.agent("run-c").open(email()).unwrap();
    assert_eq!(opened.devices, 0, "made, and locked until the owner runs the project");
    assert_eq!(world.store.row(&opened.id).state, State::Open);
}

#[test]
fn unlocking_answers_the_tasks_the_store_wrote_a_copy_of() {
    let world = World::new();
    world.store.devices.lock().unwrap().clear();
    let first = world.agent("run-a").open(email()).unwrap();
    let second = world.agent("run-b").open(photo()).unwrap();
    assert_eq!((first.devices, second.devices), (0, 0));

    let other = device_key();
    for (id, device) in [("d1", &world.device), ("d2", &other)] {
        world.store.devices.lock().unwrap().push(signed(id, OWNER, &device.public_key(), NOW + 3600, &wallet(1), RECIPIENT));
    }
    // Two tasks for two devices are four copies; the store wrote three, of
    // both tasks: the answer counts tasks, not copies.
    *world.store.most_copies.lock().unwrap() = Some(3);
    assert_eq!(world.owner("run-o").0.unlock().unwrap(), 2);
    let held = |id: &str| world.store.row(id).copies.len();
    assert_eq!(held(&first.id) + held(&second.id), 3);

    *world.store.most_copies.lock().unwrap() = None;
    assert_eq!(world.owner("run-p").0.unlock().unwrap(), 2, "two tasks, whatever the number of devices");
    // A task that closed since is written no copy, and is not counted.
    world.agent("run-c").cancel(first.id).unwrap();
    assert_eq!(world.owner("run-q").0.unlock().unwrap(), 1);
}

/// The host knows the operation the call runs; a component that names
/// another in `answered` is refused, and so is a task made for another row
/// of the same owner.
#[test]
fn an_answer_names_the_operation_the_call_runs_and_the_row_the_task_was_made_for() {
    let world = World::new();
    let opened = world.agent("run-a").open(email()).unwrap();
    let approval = world.approve(&opened, "run-o");
    let mut runs_send = world.host(Run { id: "run-o", operation: Some("send"), ..world.agent_run() }).0;
    let refused = confirm(&mut runs_send, &opened, &approval).unwrap_err();
    assert_eq!(refused.reason, wit::Reason::AnswerInvalid);
    assert!(refused.message.contains("not the one this call runs"), "{}", refused.message);
    assert_eq!(world.store.row(&opened.id).state, State::Approved);

    let mut runs_confirm = world.host(Run { id: "run-o", operation: Some("confirm"), ..world.agent_run() }).0;
    assert!(confirm(&mut runs_confirm, &opened, &approval).is_ok());

    // Another row of the same owner and project: not this task's.
    let other = world.agent("run-b").open(email()).unwrap();
    let approval = world.approve(&other, "run-q");
    let mut of_another_row = world.agent("run-q");
    match &mut of_another_row.access {
        Access::Ready(ready) => ready.profile = "personal".to_string(),
        Access::Refused(..) => panic!("a run that may use tasks"),
    }
    let refused = confirm(&mut of_another_row, &other, &approval).unwrap_err();
    assert_eq!(refused.reason, wit::Reason::NotFound);
    assert!(refused.message.contains("another secret row"), "{}", refused.message);
    assert_eq!(world.store.row(&other.id).state, State::Approved);
}

/// An answer the store took is reported on even when its reply was lost, so
/// the run's end closes it; one the store refused by name is not.
#[test]
fn an_answer_is_reported_when_the_store_took_it_even_with_its_reply_lost_and_not_when_it_refused() {
    let world = World::new();

    // The store refuses by name and moves nothing: the task is not among
    // the run's answers, and the next answer takes it.
    let refused = world.agent("run-a").open(email()).unwrap();
    let approval = world.approve(&refused, "run-o");
    let (mut carrier, report) = world.agent_with("run-o");
    *world.store.answer_fault.lock().unwrap() = Some(AnswerFault::Refused);
    assert_eq!(reason(confirm(&mut carrier, &refused, &approval)), wit::Reason::Closed);
    assert_eq!(report.tasks().len(), 0);
    assert_eq!(world.store.row(&refused.id).state, State::Approved);
    assert!(confirm(&mut carrier, &refused, &approval).is_ok());
    assert_eq!(report.tasks().len(), 1);

    // The store moves the task to the run and its reply is lost: the run is
    // told the store did not answer, and reports on the task all the same.
    let lost = world.agent("run-b").open(email()).unwrap();
    let approval = world.approve(&lost, "run-p");
    let (mut carrier, report) = world.agent_with("run-p");
    *world.store.answer_fault.lock().unwrap() = Some(AnswerFault::ReplyLost);
    assert_eq!(reason(confirm(&mut carrier, &lost, &approval)), wit::Reason::Unavailable);
    assert_eq!(report.tasks().len(), 1);
    let row = world.store.row(&lost.id);
    assert_eq!((row.state, row.run.as_deref()), (State::Answering, Some("run-p")));
    // The run's end closes it, rather than the sweep half an hour later.
    world.store.finish("run-p", true, &report.tasks(), &report.refusals());
    assert_eq!(world.agent("run-c").status(lost.id).unwrap().state, wit::TaskState::Failed);
}

/// A run whose chain is a node that says `answer` of every key.
fn on_a_chain_saying(mut host: TasksHostState, answer: serde_json::Value) -> TasksHostState {
    match &mut host.access {
        Access::Ready(ready) => ready.chain = Box::new(Saying(answer)),
        Access::Refused(..) => panic!("a run that may use tasks"),
    }
    host
}

#[test]
fn a_key_of_a_permission_this_build_does_not_know_names_no_device_and_the_task_is_made() {
    use serde_json::json;
    let world = World::new();
    for (at, permission) in [json!("SomethingNew"), json!({"SomethingNew": {"of": 1}})].into_iter().enumerate() {
        let said = json!({"result": {"nonce": 5, "permission": permission, "block_height": 1}});
        let run = format!("run-a{at}");
        let opened = on_a_chain_saying(world.agent(&run), said.clone()).open(email()).expect("made");
        assert_eq!(opened.devices, 0);
        let row = world.store.row(&opened.id);
        assert!(row.copies.is_empty() && row.sealed.is_some(), "locked, not absent");
        // The owner's own run is not failed by it either.
        let run = format!("run-o{at}");
        assert_eq!(on_a_chain_saying(world.owner(&run).0, said.clone()).unlock().unwrap(), 0);
        on_a_chain_saying(world.owner(&run).0, said).open(email()).expect("made");
    }
    // What the node says of a key that cannot be read is no answer.
    let said = json!({"result": {"nonce": 5, "permission": 7, "block_height": 1}});
    assert_eq!(reason(on_a_chain_saying(world.agent("run-b"), said).open(email())), wit::Reason::Unavailable);
}

/// An approval signed by a key that may only call functions does not hold:
/// such a key is held by an application, not by the owner's wallet.
#[test]
fn an_approval_signed_by_a_key_that_may_only_call_functions_does_not_hold() {
    use serde_json::json;
    let world = World::new();
    let opened = world.agent("run-a").open(email()).unwrap();
    let approval = world.approve(&opened, "run-o");
    let limited = json!({"result": {"nonce": 5, "block_height": 1, "permission": {"FunctionCall": {
        "allowance": null, "receiver_id": "app.near", "method_names": []}}}});
    let mut carrier = on_a_chain_saying(world.agent("run-o"), limited);
    let refused = confirm(&mut carrier, &opened, &approval).unwrap_err();
    assert_eq!(refused.reason, wit::Reason::ApprovalInvalid);
    assert!(refused.message.contains("not a full-access key"), "{}", refused.message);
    assert_eq!(world.store.row(&opened.id).state, State::Approved);
}

#[test]
fn a_request_the_store_could_not_read_is_this_hosts_fault_and_not_one_to_repeat() {
    let world = World::new();
    let opened = world.agent("run-a").open(email()).unwrap();
    world.store.reads_nothing.store(true, Ordering::SeqCst);
    assert_eq!(reason(world.agent("run-b").open(email())), wit::Reason::Internal);
    assert_eq!(reason(world.agent("run-b").mine()), wit::Reason::Internal);
    assert_eq!(reason(world.agent("run-b").status(opened.id.clone())), wit::Reason::Internal);
    assert_eq!(reason(world.agent("run-b").cancel(opened.id.clone())), wit::Reason::Internal);
    assert_eq!(reason(world.owner("run-o").0.unlock()), wit::Reason::Internal);
    let approval = world.signed(&opened.id, &opened.hash, None, None);
    let refused = confirm(&mut world.agent("run-o"), &opened, &approval).expect_err("refused");
    assert_eq!(refused.reason, wit::Reason::Internal);
    assert_eq!(refused.message, "the task store refused the request as malformed");
}

// ── broken and hostile data ─────────────────────────────────────────────────

#[test]
fn an_answer_names_the_hash_of_what_was_shown_or_is_refused() {
    let world = World::new();
    let a = world.agent("run-a").open(email()).unwrap();
    let b = world.agent("run-b").open(photo()).unwrap();
    for wrong in [String::new(), "0".repeat(64), b.hash.clone(), format!("{}0", a.hash), a.hash[..63].to_string()] {
        assert_eq!(reason(answer(&world, &a.id, &wrong)), wit::Reason::HashMismatch, "{wrong}");
    }
    assert_eq!(world.store.row(&a.id).state, State::Approved);
    // The hash is read without its case; the approval is over the hash as
    // the page computed it.
    let approval = world.signed(&a.id, &a.hash, None, None);
    world.agent("run-o").answered(a.id.clone(), a.hash.to_uppercase(), "confirm".to_string(), POLICY.to_vec(), approval, None, None).unwrap();
}

#[test]
fn a_display_changed_in_the_store_is_not_what_is_acted_on() {
    let world = World::new();
    let opened = world.agent("run-a").open(email()).unwrap();
    // Whoever holds the store cannot rewrite the content without its key;
    // they can replace it with another task's.
    let other = world.agent("run-b").open(photo()).unwrap();
    let theirs = world.store.row(&other.id);
    world.store.change(&opened.id, |row| {
        row.content = theirs.content.clone();
        row.copies = theirs.copies.clone();
    });
    let row = world.store.row(&opened.id);
    assert!(
        crypto::open_from(&world.device, Purpose::DeviceCopy, &opened.id, &row.copies["d1"]).is_err(),
        "a copy made for another task opens as nothing under this one"
    );
    // And the hash of the other task answers nothing here.
    assert_eq!(reason(answer(&world, &opened.id, &other.hash)), wit::Reason::HashMismatch);
}

#[test]
fn a_sealed_copy_changed_cut_or_swapped_is_unreadable() {
    let world = World::new();
    let a = world.agent("run-a").open(email()).unwrap();
    let b = world.agent("run-b").open(email()).unwrap();
    let (sealed_a, sealed_b) = (world.store.row(&a.id).sealed.unwrap(), world.store.row(&b.id).sealed.unwrap());

    let with = |sealed: Option<Vec<u8>>| {
        world.store.change(&a.id, |row| row.sealed = sealed);
        answer(&world, &a.id, &a.hash)
    };
    let mut changed = sealed_a.clone();
    changed[40] ^= 1;
    for broken in [Some(changed), Some(sealed_a[..sealed_a.len() - 1].to_vec()), Some(vec![]), Some(b"junk".to_vec()), None, Some(sealed_b)] {
        let refused = with(broken).expect_err("refused");
        assert_eq!(refused.reason, wit::Reason::Unreadable);
        assert_eq!(refused.message, "decryption failed");
    }
    assert_eq!(world.store.row(&a.id).state, State::Approved, "nothing was handed over and nothing moved");
    with(Some(sealed_a)).unwrap();
}

/// A sealed copy of the format before consents — without one — does not
/// open: a task with no consent is carried out by nobody.
#[test]
fn a_sealed_copy_without_a_consent_is_unreadable() {
    let world = World::new();
    let a = world.agent("run-a").open(email()).unwrap();
    let keys = TaskKeys::derive(&world.project_key, &a.id);
    let plain = keys.open(Sealed::Task, &a.id, &world.store.row(&a.id).sealed.unwrap()).unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&plain).unwrap();
    value.as_object_mut().unwrap().remove("consent");
    let resealed = keys.seal(Sealed::Task, &a.id, &serde_json::to_vec(&value).unwrap()).unwrap();
    world.store.change(&a.id, |row| row.sealed = Some(resealed));
    assert_eq!(reason(answer(&world, &a.id, &a.hash)), wit::Reason::Unreadable);
}

#[test]
fn the_columns_in_the_clear_decide_nothing() {
    let world = World::new();
    let opened = world.agent("run-a").open(email()).unwrap();
    world.store.approve(&opened.id, "run-m");

    // A task moved to another owner is not theirs to carry out.
    world.store.change(&opened.id, |row| row.scope.owner = "mallory.testnet".to_string());
    let mut mallory = world.host(Run { caller: "mallory.testnet", owner: "mallory.testnet", by_name: false, id: "run-m", ..world.agent_run() }).0;
    let forged = approved("mallory.testnet", &opened.id, &opened.hash, None, None, NOW, &wallet(1), RECIPIENT);
    let forged = wit::Approval { at: forged.at, public_key: forged.public_key, signature: forged.signature, nonce: forged.nonce };
    assert_eq!(reason(confirm(&mut mallory, &opened, &forged)), wit::Reason::Unreadable);
    world.store.change(&opened.id, |row| row.scope.owner = OWNER.to_string());

    // An expiry pushed out in the row revives nothing: the life is the sealed one.
    world.clock.store(NOW + 3601, Ordering::SeqCst);
    world.store.change(&opened.id, |row| {
        row.task.expires_at = NOW as u64 + 999_999;
        row.run = Some("run-o".to_string());
    });
    assert_eq!(reason(answer(&world, &opened.id, &opened.hash)), wit::Reason::Expired);
    assert_eq!(world.store.row(&opened.id).state, State::Approved);
}

#[test]
fn an_answered_task_put_back_takes_no_second_answer_from_the_store_that_moved_it() {
    let world = World::new();
    let opened = world.agent("run-a").open(email()).unwrap();
    let before = world.store.row(&opened.id);
    answer(&world, &opened.id, &opened.hash).unwrap();
    // The sealed copy put back, the state as the store holds it.
    world.store.change(&opened.id, |row| row.sealed = before.sealed.clone());
    assert_eq!(reason(answer(&world, &opened.id, &opened.hash)), wit::Reason::Closed);
}

#[test]
fn a_policy_that_changed_voids_the_task_for_every_reader() {
    let world = World::new();
    let opened = world.agent("run-a").open(email()).unwrap();
    let approval = world.approve(&opened, "run-o");
    let mut carrier = world.agent("run-o");
    let changed = br#"{"confirm":[]}"#.to_vec();
    assert_eq!(
        reason(carrier.answered(opened.id.clone(), opened.hash.clone(), "confirm".to_string(), changed, approval, None, None)),
        wit::Reason::Void
    );
    assert_eq!(world.agent("run-b").status(opened.id.clone()).unwrap().state, wit::TaskState::Void);
    // The old policy back does not bring it back.
    assert_eq!(reason(answer(&world, &opened.id, &opened.hash)), wit::Reason::Void);
}

/// The owner proved the build that made the task; that build answers it, and
/// a later version of the project, published after, does not.
#[test]
fn a_task_is_answered_by_the_build_that_made_it_and_another_build_voids_it() {
    let world = World::new();
    let opened = world.agent("run-a").open(email()).unwrap();
    let (envelope, _) = world.page_reads(&opened.id);
    assert_eq!(envelope.build, BUILD, "the envelope names the build that made the task");
    let approval = world.approve(&opened, "run-o");
    let (mut later, _) = world.agent_of_another_build("run-o");
    let refused = confirm(&mut later, &opened, &approval).unwrap_err();
    assert_eq!(refused.reason, wit::Reason::Void);
    assert!(refused.message.contains("another build"), "{}", refused.message);
    assert_eq!(world.agent("run-b").status(opened.id.clone()).unwrap().state, wit::TaskState::Void);
    // The right build, too late: the task is void for every reader.
    assert_eq!(reason(answer(&world, &opened.id, &opened.hash)), wit::Reason::Void);

    // The build that made it answers it.
    let again = world.agent("run-c").open(email()).unwrap();
    assert!(answer(&world, &again.id, &again.hash).is_ok());
}

#[test]
fn a_task_past_its_life_takes_no_answer() {
    let world = World::new();
    let opened = world.agent("run-a").open(email()).unwrap();
    world.clock.store(NOW + 3599, Ordering::SeqCst);
    let approval = world.approve(&opened, "run-o");
    world.clock.store(NOW + 3600, Ordering::SeqCst);
    assert_eq!(reason(confirm(&mut world.agent("run-o"), &opened, &approval)), wit::Reason::Expired);
}

/// The approval names the digest of what the owner supplied and wrote, as the
/// page sent it: the signature holds for those bytes and no others, and what
/// does not match the task or does not open is refused.
#[test]
fn what_the_answer_supplies_is_what_the_task_asked_for_sealed_for_this_task_and_under_the_signature() {
    let world = World::new();
    let nothing = world.agent("run-a").open(email()).unwrap();
    let file = world.agent("run-b").open(photo()).unwrap();
    let other = world.agent("run-c").open(photo()).unwrap();
    for task in [&nothing, &file, &other] {
        world.store.approve(&task.id, "run-o");
    }
    // Signed over what is passed, so the supplies rules are what refuse.
    let supply_by = |operation: &str, task: &wit::Opened, supplied: Option<Vec<u8>>| {
        let approval = world.signed(&task.id, &task.hash, supplied.as_deref(), None);
        world.agent("run-o").answered(task.id.clone(), task.hash.clone(), operation.to_string(), POLICY.to_vec(), approval, supplied, None)
    };
    let supply = |task: &wit::Opened, supplied: Option<Vec<u8>>| supply_by("upload_photo", task, supplied);
    let good = world.page_writes(&file.id, Purpose::Answer, b"ipfs://photo");

    assert_eq!(reason(supply_by("confirm", &nothing, Some(good.clone()))), wit::Reason::AnswerInvalid);
    assert_eq!(reason(supply(&file, None)), wit::Reason::AnswerInvalid);
    for broken in [
        b"ipfs://photo in the clear".to_vec(),
        good[..good.len() - 1].to_vec(),
        world.page_writes(&other.id, Purpose::Answer, b"made for another task"),
        world.page_writes(&file.id, Purpose::Rejection, b"made as a reason"),
        world.page_writes(&file.id, Purpose::Note, b"made as a note"),
        vec![0u8; crate::tasks::MAX_SUPPLIED_BYTES + 1],
        vec![],
    ] {
        assert_eq!(reason(supply(&file, Some(broken))), wit::Reason::AnswerInvalid);
    }
    assert_eq!(world.store.row(&file.id).state, State::Approved, "the operation was handed nothing");

    // Signed over one supply, handed another: the signature does not hold.
    let signed_over_good = world.signed(&file.id, &file.hash, Some(&good), None);
    let other_supply = world.page_writes(&file.id, Purpose::Answer, b"ipfs://another");
    let refused = world
        .agent("run-o")
        .answered(file.id.clone(), file.hash.clone(), "upload_photo".to_string(), POLICY.to_vec(), signed_over_good.clone(), Some(other_supply), None)
        .unwrap_err();
    assert_eq!(refused.reason, wit::Reason::ApprovalInvalid);
    assert!(refused.message.contains("does not verify"), "{}", refused.message);
    // Signed with no note, handed one: the same.
    let note = world.page_writes(&file.id, Purpose::Note, b"a note");
    assert_eq!(
        reason(world.agent("run-o").answered(file.id.clone(), file.hash.clone(), "upload_photo".to_string(), POLICY.to_vec(), signed_over_good, Some(good.clone()), Some(note))),
        wit::Reason::ApprovalInvalid
    );

    assert_eq!(supply(&file, Some(good)).unwrap().supplied.as_deref(), Some(&b"ipfs://photo"[..]));
}

/// The note beside an approval is opened under its own purpose and held to
/// what a long text may hold; one outside that refuses the answer.
#[test]
fn the_owners_note_is_handed_over_as_text_and_one_outside_a_long_texts_bounds_is_refused() {
    let world = World::new();
    let opened = world.agent("run-a").open(email()).unwrap();
    world.store.approve(&opened.id, "run-o");
    let with_note = |note: Vec<u8>| {
        let approval = world.signed(&opened.id, &opened.hash, None, Some(&note));
        world.agent("run-o").answered(opened.id.clone(), opened.hash.clone(), "confirm".to_string(), POLICY.to_vec(), approval, None, Some(note))
    };
    for (hostile, said) in [
        (world.page_writes(&opened.id, Purpose::Note, "send it\u{202E}".as_bytes()), "U+202E"),
        (world.page_writes(&opened.id, Purpose::Note, b" \n\t"), "blank"),
        (world.page_writes(&opened.id, Purpose::Note, &[0xff, 0xfe]), "not text"),
        (world.page_writes(&opened.id, Purpose::Answer, b"sealed as a supply"), "does not open"),
        (b"in the clear".to_vec(), "does not open"),
        (vec![0u8; crate::tasks::MAX_NOTE_BYTES + 1], "over its bound"),
    ] {
        let refused = with_note(hostile).expect_err(said);
        assert_eq!(refused.reason, wit::Reason::AnswerInvalid, "{said}");
        assert!(refused.message.contains(said), "{said}: {}", refused.message);
    }
    assert_eq!(world.store.row(&opened.id).state, State::Approved);

    let written = "ok, but cc Carol:\n\t— she asked";
    let answer = with_note(world.page_writes(&opened.id, Purpose::Note, written.as_bytes())).unwrap();
    assert_eq!(answer.note.as_deref(), Some(written.as_bytes()));
}

#[test]
fn a_task_is_answered_through_the_operation_it_names_and_through_no_other() {
    let world = World::new();
    let opened = world.agent("run-a").open(email()).unwrap();
    let approval = world.approve(&opened, "run-o");
    let through = |operation: &str| {
        world.agent("run-o").answered(opened.id.clone(), opened.hash.clone(), operation.to_string(), POLICY.to_vec(), approval.clone(), None, None)
    };
    for other in ["send", "upload_photo", "", "Confirm", "confirm "] {
        assert_eq!(reason(through(other)), wit::Reason::AnswerInvalid, "{other:?}");
    }
    assert_eq!(world.store.row(&opened.id).state, State::Approved, "it waits for the operation it names");
    assert_eq!(through("confirm").unwrap().operation, "confirm");
}

#[test]
fn ids_that_are_not_ids_make_no_lookup() {
    let world = World::new();
    world.store.down.store(true, Ordering::SeqCst);
    let long = "a".repeat(81);
    for id in ["", "../x", "a/b", "a:b", "A", "é", "a b", long.as_str()] {
        assert_eq!(reason(world.agent("run-a").status(id.to_string())), wit::Reason::NotFound, "{id:?}");
        assert_eq!(reason(world.agent("run-a").cancel(id.to_string())), wit::Reason::NotFound);
        assert_eq!(reason(world.agent("run-a").delete(id.to_string())), wit::Reason::NotFound);
        assert_eq!(
            reason(world.agent("run-o").answered(id.to_string(), String::new(), "confirm".to_string(), vec![], no_approval(), None, None)),
            wit::Reason::NotFound
        );
    }
}

#[test]
fn a_task_outside_the_bounds_is_refused_by_name_and_none_is_made() {
    let world = World::new();
    let refused = |change: fn(&mut wit::Request)| {
        let mut request = email();
        change(&mut request);
        world.agent("run-a").open(request).expect_err("refused")
    };
    let display = refused(|r| r.display.title = "x".repeat(81));
    assert_eq!(display.reason, wit::Reason::DisplayInvalid);
    assert!(display.message.contains("the title is 81 characters"), "{}", display.message);
    assert_eq!(refused(|r| r.display.fields[0].values.push("two".into())).reason, wit::Reason::DisplayInvalid);
    assert_eq!(refused(|r| r.display.fields[0].values[0] = "evil\u{202E}moc.elpmaxe".into()).reason, wit::Reason::DisplayInvalid);
    assert_eq!(refused(|r| r.answer_by.operation = "send {\"to\":\"x\"}".into()).reason, wit::Reason::DisplayInvalid);
    assert_eq!(refused(|r| r.state = vec![0; crate::tasks::MAX_STATE_BYTES + 1]).reason, wit::Reason::TooLarge);
    assert_eq!(refused(|r| r.policy = vec![0; crate::tasks::MAX_POLICY_BYTES + 1]).reason, wit::Reason::TooLarge);
    let life = refused(|r| r.life_seconds = crate::tasks::MAX_LIFE_SECS + 1);
    assert_eq!(life.reason, wit::Reason::LifeTooLong);
    assert!(world.store.rows.lock().unwrap().is_empty());
    // At the bounds it is made.
    let mut most = email();
    most.state = vec![0; crate::tasks::MAX_STATE_BYTES];
    most.life_seconds = crate::tasks::MAX_LIFE_SECS;
    world.agent("run-a").open(most).unwrap();
}

#[test]
fn markup_is_kept_as_the_text_it_is() {
    let world = World::new();
    let mut request = email();
    let hostile = r#"<img src=x onerror=alert(1)> <a href="https://evil.example">click</a> ![](https://t.example/p.png)"#;
    request.display.fields[1].values[0] = hostile.to_string();
    let opened = world.agent("run-a").open(request).unwrap();
    assert_eq!(world.page_reads(&opened.id).0.display.fields[1].values[0], hostile);
}

#[test]
fn a_result_is_left_only_for_a_task_this_run_answered_and_within_its_bound() {
    let world = World::new();
    let opened = world.agent("run-a").open(email()).unwrap();
    let approval = world.approve(&opened, "run-o");
    let (mut carrier, _) = world.agent_with("run-o");
    assert_eq!(reason(carrier.report(opened.id.clone(), b"x".to_vec())), wit::Reason::NotFound);
    confirm(&mut carrier, &opened, &approval).unwrap();
    assert_eq!(
        reason(carrier.report(opened.id.clone(), vec![0; crate::tasks::MAX_RESULT_BYTES + 1])),
        wit::Reason::TooLarge
    );
    carrier.report(opened.id, vec![0; crate::tasks::MAX_RESULT_BYTES]).unwrap();
}

#[test]
fn an_outcome_changed_in_the_store_is_unreadable_not_a_result() {
    let world = World::new();
    let opened = world.agent("run-a").open(email()).unwrap();
    let approval = world.approve(&opened, "run-o");
    let (mut carrier, report) = world.agent_with("run-o");
    confirm(&mut carrier, &opened, &approval).unwrap();
    carrier.report(opened.id.clone(), b"sent".to_vec()).unwrap();
    world.store.finish("run-o", true, &report.tasks(), &report.refusals());
    world.store.change(&opened.id, |row| row.outcome.as_mut().unwrap()[30] ^= 1);
    assert_eq!(reason(world.agent("run-b").status(opened.id.clone())), wit::Reason::Unreadable);
    world.store.change(&opened.id, |row| row.rejection = Some(b"a reason that is not ciphertext".to_vec()));
    assert_eq!(reason(world.agent("run-b").status(opened.id)), wit::Reason::Unreadable);
}

#[test]
fn a_task_whose_outcome_does_not_open_is_listed_without_it_and_the_others_are_read() {
    let world = World::new();
    let mut agent = world.agent("run-a");
    let (done, changed, rejected) = (agent.open(email()).unwrap(), agent.open(email()).unwrap(), agent.open(email()).unwrap());
    for (run, task) in [("run-o", &done), ("run-p", &changed)] {
        let approval = world.approve(task, run);
        let (mut carrier, report) = world.agent_with(run);
        confirm(&mut carrier, task, &approval).unwrap();
        carrier.report(task.id.clone(), b"sent".to_vec()).unwrap();
        world.store.finish(run, true, &report.tasks(), &report.refusals());
    }
    world.store.change(&changed.id, |row| row.outcome.as_mut().unwrap()[30] ^= 1);
    world.store.change(&rejected.id, |row| {
        Mem::close(row, State::Rejected);
        row.rejection = Some(b"a reason that is not ciphertext".to_vec());
    });

    let mine = world.agent("run-b").mine().expect("the list is read");
    assert_eq!(mine.len(), 3, "no task is dropped");
    let of = |id: &str| mine.iter().find(|task| task.id == id).expect("listed").clone();
    assert_eq!(of(&done.id).result.as_deref(), Some(&b"sent"[..]));
    let unopened = of(&changed.id);
    assert_eq!((unopened.state, unopened.run.as_deref()), (wit::TaskState::Done, Some("run-p")));
    assert_eq!((unopened.created_at, unopened.expires_at), (NOW as u64, changed.expires_at));
    assert!(unopened.result.is_none() && unopened.rejection.is_none());
    let unopened = of(&rejected.id);
    assert_eq!(unopened.state, wit::TaskState::Rejected);
    assert!(unopened.result.is_none() && unopened.rejection.is_none());

    // Asked for by its id, each is what it is.
    assert_eq!(reason(world.agent("run-c").status(changed.id)), wit::Reason::Unreadable);
    assert_eq!(reason(world.agent("run-c").status(rejected.id)), wit::Reason::Unreadable);
    assert_eq!(world.agent("run-c").status(done.id).unwrap().result.as_deref(), Some(&b"sent"[..]));
}

/// Everything this process logs while these tests run. `tracing` remembers,
/// process-wide, whether anybody listens at a call site, so a subscriber of
/// one test's own would miss the call sites another test reached first; one
/// subscriber for the process misses none.
fn logged() -> &'static Mutex<Vec<u8>> {
    use std::io::Write;
    static LOG: std::sync::OnceLock<Mutex<Vec<u8>>> = std::sync::OnceLock::new();
    struct Sink;
    impl Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            logged().lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    static INSTALL: std::sync::Once = std::sync::Once::new();
    let log = LOG.get_or_init(Default::default);
    INSTALL.call_once(|| {
        let subscriber =
            tracing_subscriber::fmt().with_max_level(tracing::Level::TRACE).with_ansi(false).with_writer(|| Sink).finish();
        tracing::subscriber::set_global_default(subscriber).expect("no other subscriber for the process");
    });
    log
}

#[test]
fn nothing_of_a_task_is_logged() {
    let log = logged();
    let world = World::new();
    world.store.devices.lock().unwrap().push(signed("forged", OWNER, &device_key().public_key(), NOW + 60, &wallet(9), RECIPIENT));
    let mut request = photo();
    request.display.title = "MARKER-TITLE give me your photo".to_string();
    request.state = b"MARKER-STATE video job".to_vec();
    request.answer_by.operation = "marker_operation".to_string();
    let opened = world.agent("run-logged").open(request).unwrap();
    let supplied = world.page_writes(&opened.id, Purpose::Answer, b"MARKER-SUPPLIED ipfs://photo");
    let note = world.page_writes(&opened.id, Purpose::Note, b"MARKER-NOTE take the second one");
    let approval = world.approve_with(&opened, "run-logged-o", Some(&supplied), Some(&note));
    let (mut carrier, _) = world.agent_with("run-logged-o");
    carrier
        .answered(opened.id.clone(), opened.hash.clone(), "marker_operation".to_string(), POLICY.to_vec(), approval.clone(), Some(supplied), Some(note))
        .unwrap();
    carrier.report(opened.id.clone(), b"MARKER-RESULT ipfs://video".to_vec()).unwrap();
    // A refusal is logged by its reason, and nothing of the approval.
    let again = world.agent("run-logged-x").open(email()).unwrap();
    let forged = world.approve(&again, "run-logged-y");
    let (mut refused, _) = world.owner("run-logged-y");
    assert_eq!(reason(confirm(&mut refused, &again, &forged)), wit::Reason::NotThePreparer);
    world.owner("run-logged-u").0.unlock().unwrap();

    let logged = String::from_utf8_lossy(&log.lock().unwrap()).into_owned();
    let mine: Vec<&str> = logged.lines().filter(|line| line.contains("run-logged")).collect();
    assert!(mine.iter().any(|line| line.contains("task opened")), "{mine:?}");
    assert!(mine.iter().any(|line| line.contains("task answered")), "{mine:?}");
    assert!(mine.iter().any(|line| line.contains("not-the-preparer")), "{mine:?}");
    for secret in ["MARKER-", "marker_operation", &opened.hash, "p256:", "ed25519:", &"07".repeat(8), &approval.signature[..12], &approval.nonce[..12]] {
        assert!(!logged.contains(secret), "{secret} reached the log");
    }
}

// ── files ───────────────────────────────────────────────────────────────────

fn pdf() -> wit::File {
    wit::File { name: "report.pdf".to_string(), content_type: "application/pdf".to_string(), data: b"%PDF-1.7 the report".to_vec() }
}

fn with_files(files: Vec<wit::File>) -> wit::Request {
    wit::Request { files, ..email() }
}

impl World {
    /// What the owner's page does with a file of a task: opens it with the
    /// task's content key and holds it to what the envelope says of it.
    fn page_opens_file(&self, id: &str, at: usize) -> Vec<u8> {
        let row = self.store.row(id);
        let key = crypto::open_from(&self.device, Purpose::DeviceCopy, id, &row.copies["d1"]).unwrap();
        let key: [u8; 32] = key.as_slice().try_into().unwrap();
        let data = crypto::decrypt_file(&key, id, at, &row.files[at]).expect("the file opens");
        let note = &self.page_reads(id).0.files[at];
        assert_eq!((envelope::hash(&data), data.len() as u64), (note.sha256.clone(), note.size));
        data
    }
}

#[test]
fn a_file_is_listed_in_what_is_shown_opened_by_the_owner_and_handed_back_on_the_answer() {
    let world = World::new();
    let second = wit::File { name: "data.csv".to_string(), content_type: "text/csv".to_string(), data: b"a,b\n1,2\n".to_vec() };
    let opened = world.agent("run-a").open(with_files(vec![pdf(), second.clone()])).unwrap();

    let (shown, hash) = world.page_reads(&opened.id);
    assert_eq!(hash, opened.hash, "the files are part of what the hash is of");
    let listed: Vec<(&str, &str, u64)> =
        shown.files.iter().map(|f| (f.name.as_str(), f.content_type.as_str(), f.size)).collect();
    assert_eq!(listed, vec![("report.pdf", "application/pdf", 19), ("data.csv", "text/csv", 8)]);
    assert_eq!(world.page_opens_file(&opened.id, 0), b"%PDF-1.7 the report");
    assert_eq!(world.page_opens_file(&opened.id, 1), second.data);

    // The store holds them as ciphertext.
    let held = world.store.row(&opened.id).files.concat();
    assert!(!String::from_utf8_lossy(&held).contains("PDF"));

    let answer = answer(&world, &opened.id, &opened.hash).unwrap();
    assert_eq!(answer.files.len(), 2);
    assert_eq!((answer.files[0].name.as_str(), answer.files[0].data.as_slice()), ("report.pdf", &b"%PDF-1.7 the report"[..]));
    assert_eq!(answer.files[1].data, second.data);
    assert!(world.store.row(&opened.id).files.is_empty(), "gone from the store with the answer");
}

#[test]
fn another_file_is_another_hash() {
    let world = World::new();
    let one = world.agent("run-a").open(with_files(vec![pdf()])).unwrap();
    let mut changed = pdf();
    changed.data[0] ^= 1;
    let other = world.agent("run-b").open(with_files(vec![changed])).unwrap();
    assert_ne!(world.page_reads(&one.id).0.files[0].sha256, world.page_reads(&other.id).0.files[0].sha256);
}

#[test]
fn a_file_changed_missing_swapped_or_added_in_the_store_hands_nothing_over() {
    let world = World::new();
    // The same bytes under two names.
    let copy = wit::File { name: "copy.pdf".to_string(), ..pdf() };
    let opened = world.agent("run-a").open(with_files(vec![pdf(), copy])).unwrap();
    let other = world.agent("run-b").open(with_files(vec![pdf()])).unwrap();
    let (good, theirs) = (world.store.row(&opened.id).files, world.store.row(&other.id).files);

    let mut changed = good.clone();
    changed[0][20] ^= 1;
    let swapped = vec![good[1].clone(), good[0].clone()];
    for broken in [
        changed,
        vec![good[0].clone()],
        vec![],
        [good.clone(), vec![good[0].clone()]].concat(),
        // The same bytes, sealed as a file of another task.
        vec![theirs[0].clone(), good[1].clone()],
        // The same file, at another place among the files.
        swapped,
    ] {
        world.store.change(&opened.id, |row| row.files = broken);
        assert_eq!(reason(answer(&world, &opened.id, &opened.hash)), wit::Reason::Unreadable);
    }
    assert_eq!(world.store.row(&opened.id).state, State::Approved);
    world.store.change(&opened.id, |row| row.files = good);
    answer(&world, &opened.id, &opened.hash).unwrap();
}

#[test]
fn files_outside_the_bounds_are_refused_by_name_and_none_is_made() {
    let world = World::new();
    let many = (0..=crate::tasks::MAX_FILES).map(|_| pdf()).collect();
    assert_eq!(reason(world.agent("run-a").open(with_files(many))), wit::Reason::TooLarge);
    let heavy = wit::File { data: vec![0; crate::tasks::MAX_FILES_BYTES + 1], ..pdf() };
    assert_eq!(reason(world.agent("run-a").open(with_files(vec![heavy]))), wit::Reason::TooLarge);
    for (name, kind) in [("../../etc/passwd", "text/plain"), ("invoice\u{202E}fdp.exe", "application/pdf"), ("a.html", "text/html\r\nX: 1"), ("", "a/b")] {
        let file = wit::File { name: name.to_string(), content_type: kind.to_string(), data: vec![1] };
        assert_eq!(reason(world.agent("run-a").open(with_files(vec![file]))), wit::Reason::DisplayInvalid, "{name:?}");
    }
    for (name, kind) in [("report.pdf.", "application/pdf"), ("report.pdf ", "application/pdf"), (".env", "text/plain"), ("a.pdf", "pdf"), ("a\u{200D}b.pdf", "application/pdf")] {
        let file = wit::File { name: name.to_string(), content_type: kind.to_string(), data: vec![1] };
        assert_eq!(reason(world.agent("run-a").open(with_files(vec![file]))), wit::Reason::DisplayInvalid, "{name:?}");
    }
    let twice = world.agent("run-a").open(with_files(vec![pdf(), wit::File { name: "Report.PDF".to_string(), ..pdf() }]));
    let twice = twice.expect_err("two files of one name");
    assert_eq!((twice.reason, twice.message.as_str()), (wit::Reason::DisplayInvalid, "file 2 has the name of file 1"));
    assert!(world.store.rows.lock().unwrap().is_empty());
    let most = wit::File { data: vec![7; crate::tasks::MAX_FILES_BYTES], ..pdf() };
    world.agent("run-a").open(with_files(vec![most])).unwrap();
}

#[test]
fn an_owner_whose_waiting_tasks_hold_all_they_may_is_full_until_one_is_answered() {
    let world = World::new();
    *world.store.most_stored.lock().unwrap() = Some(100);
    let sixty = || with_files(vec![wit::File { data: vec![0; 60 - 29], ..pdf() }]);
    let first = world.agent("run-a").open(sixty()).unwrap();
    assert_eq!(reason(world.agent("run-b").open(sixty())), wit::Reason::InboxFull);
    answer(&world, &first.id, &first.hash).unwrap();
    world.agent("run-c").open(sixty()).unwrap();
}

#[test]
fn a_long_message_is_shown_whole() {
    let world = World::new();
    let mut request = email();
    request.display.fields[1].values[0] = "й".repeat(envelope::MAX_LONG_TEXT_CHARS);
    let opened = world.agent("run-a").open(request).unwrap();
    assert_eq!(world.page_reads(&opened.id).0.display.fields[1].values[0].chars().count(), envelope::MAX_LONG_TEXT_CHARS);
}

/// A task whose making was not heard of may have been made: the next task of
/// the run is another task, under another id, and the store is told nothing
/// twice.
#[test]
fn a_task_the_store_did_not_answer_about_takes_its_number_with_it() {
    let world = World::new();
    let mut agent = world.agent("run-a");
    assert_eq!(agent.open(email()).unwrap().id, "run-a-0");
    world.store.down.store(true, Ordering::SeqCst);
    assert_eq!(reason(agent.open(email())), wit::Reason::Unavailable);
    world.store.down.store(false, Ordering::SeqCst);
    assert_eq!(agent.open(email()).unwrap().id, "run-a-2");
}

/// What can never succeed is not told as something to repeat.
#[test]
fn a_refusal_that_is_final_is_not_told_as_one_to_repeat() {
    let world = World::new();
    let mut first = world.agent("run-a");
    assert_eq!(first.open(email()).unwrap().id, "run-a-0");
    // The same call, run again: its ids are taken.
    let mut again = world.agent("run-a");
    assert_eq!(reason(again.open(email())), wit::Reason::Internal);
}

/// A task of a row bound to a vault is recorded under that vault: the store
/// is told the vault the keystore named with the key, and nothing else names
/// it.
#[test]
fn a_task_of_a_row_bound_to_a_vault_is_recorded_under_the_vault() {
    let world = World::new();
    let mut of_the_vault = world.host(Run { id: "run-v", vault: Some("v1.vault.testnet"), ..world.agent_run() }).0;
    let opened = of_the_vault.open(email()).unwrap();
    assert_eq!(world.store.row(&opened.id).task.vault.as_deref(), Some("v1.vault.testnet"));
    let plain = world.agent("run-a").open(email()).unwrap();
    assert_eq!(world.store.row(&plain.id).task.vault, None);
}

/// The store is told the consent in the clear as the voucher: which key to
/// charge and how to start the run. The sealed copy carries the same.
#[test]
fn the_voucher_the_store_is_told_is_the_consent_that_is_sealed() {
    let world = World::new();
    let (mut run, _) = world.agent_as(
        "run-a",
        Some(Consent { payment_key_nonce: 5, wallet: Some("w-9".into()), bound_identity: true, compute_limit_usd: "2500".into() }),
    );
    let opened = run.open(email()).unwrap();
    let row = world.store.row(&opened.id);
    assert_eq!(
        row.task.voucher,
        client::Voucher {
            payment_key_nonce: 5,
            wallet_id: Some("w-9".into()),
            bound_identity: true,
            compute_limit_usd: "2500".into(),
            operation: "confirm".into(),
            build: BUILD.into(),
        }
    );
    let keys = TaskKeys::derive(&world.project_key, &opened.id);
    let plain = keys.open(Sealed::Task, &opened.id, row.sealed.as_deref().unwrap()).unwrap();
    let sealed: SealedTask = serde_json::from_slice(&plain).unwrap();
    assert_eq!(
        sealed.consent,
        Consent { payment_key_nonce: 5, wallet: Some("w-9".into()), bound_identity: true, compute_limit_usd: "2500".into() }
    );
    // The envelope the owner reads carries no consent: nothing of the key.
    let (shown, _) = world.page_reads(&opened.id);
    let document = serde_json::to_string(&shown).unwrap();
    assert!(!document.contains("w-9") && !document.contains("2500") && !document.contains("nonce"));
}
