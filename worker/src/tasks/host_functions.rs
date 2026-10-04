//! The `outlayer:tasks` host interface.
//!
//! Every function answers `result<_, task-error>` and none traps. Who the
//! caller is, whose the task is and which project it belongs to are this
//! run's facts ([`super::TasksRun`]); nothing the component passes is an
//! account, a project or a key.
//!
//! What a task IS is not taken on the store's word. A task is read from its
//! sealed copy, which opens only under the key of that task of this project
//! and owner; the owner, the project, the preparer, the preparer's consent,
//! the expiry, the operation and the hashes are the ones sealed inside it. A
//! row that was moved, swapped or extended opens as nothing, or disagrees
//! with what is sealed, and is `unreadable`.
//!
//! Whether the OWNER said yes is the owner's word: their wallet's signature
//! over a sentence naming the task, the hash of what they saw and the digest
//! of what they wrote, verified here under a full-access key of their account
//! on chain. Whose run carries the task out is the consent's word: the run
//! must be the preparer's, on the payment key, wallet and identity of the
//! preparing run, within its compute limit.
//!
//! Where a task STANDS is the store's word: its state, the run that acted,
//! and whose tasks a preparer is listed. The enclave keeps nothing between
//! runs, so it cannot know by itself that a task was answered; the store is
//! the coordinator's, which the platform trusts to keep its own records. A
//! row put back to `approved` with its sealed copy is a task that takes the
//! same approval again within its ten minutes, and a reason for a rejection
//! is whatever was sealed to the task's reply key: it is handed over only
//! within the bound and the characters of what an owner writes.
//!
//! Nothing of what a task shows, no key and no statement is logged: ids,
//! kinds, counts and reasons only.

use base64::Engine;
use wasmtime::component::Linker;

use super::client::{self, HttpStore, NewTask, Refusal, Scope, Store, StoreError, Voucher};
use super::crypto::{self, Purpose, Sealed, TaskKeys, DECRYPTION_FAILED};
use super::envelope::{self, Consent, Envelope, SealedTask};
use super::statement::{self, Approval, ApprovalRefused, Chain, Device, RpcChain};
use super::{RunReport, TaskGrant, TasksRun};

wasmtime::component::bindgen!({
    path: "wit",
    world: "outlayer:tasks/tasks-host",
});

use outlayer::tasks::api as wit;

fn refused(reason: wit::Reason, message: impl Into<String>) -> wit::TaskError {
    wit::TaskError { reason, message: message.into() }
}

fn unreadable() -> wit::TaskError {
    refused(wit::Reason::Unreadable, DECRYPTION_FAILED)
}

/// Everything a run that may use tasks holds.
struct Ready {
    grant: TaskGrant,
    run: String,
    project_id: String,
    /// The build that runs, as the envelope names it.
    build: String,
    /// The operation the call names, when it names one.
    operation: Option<String>,
    scope: Scope,
    profile: String,
    caller: String,
    /// The run's consent to the run that carries a task it opens out: its
    /// payment key, wallet, identity and compute limit. None in a run with no
    /// payment key, which opens no task and carries none out.
    consent: Option<Consent>,
    recipient: String,
    store: Box<dyn Store + Send>,
    chain: Box<dyn Chain + Send>,
    report: RunReport,
    now: Box<dyn Fn() -> i64 + Send>,
}

enum Access {
    Ready(Box<Ready>),
    Refused(wit::Reason, String),
}

fn system_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| i64::try_from(since.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// The host's state for one run.
pub struct TasksHostState {
    access: Access,
    calls: u32,
    opened: u32,
    /// The owner's devices in force, read and checked once per run: held
    /// from the read that answered, by whatever call made it.
    devices: Option<Vec<Device>>,
    /// The conversation a task opened in this run continues, as the tasks
    /// this run answered say.
    conversation: Conversation,
}

/// What the tasks a run answered make of a task it opens.
#[derive(Debug, Clone, Default)]
enum Conversation {
    /// The run answered no task: a task it opens starts a conversation of
    /// its own.
    #[default]
    Unanswered,
    /// Every task the run answered is of this conversation, by the id of its
    /// first task: a task the run opens is the next turn of it.
    One(String),
    /// The run answered tasks of more than one conversation: a task it opens
    /// belongs to none, and is refused.
    Several,
}

impl Conversation {
    /// The run answered a task of the conversation `thread`.
    fn answered(&mut self, thread: String) {
        *self = match std::mem::take(self) {
            Conversation::Unanswered => Conversation::One(thread),
            Conversation::One(held) if held == thread => Conversation::One(held),
            Conversation::One(_) | Conversation::Several => Conversation::Several,
        };
    }
}

impl TasksHostState {
    /// The state of a run, from what the job path established. A run with no
    /// context is one whose manifest declares no tasks.
    pub fn new(run: Option<TasksRun>) -> Self {
        let access = match run {
            Some(run) if run.declared => Self::access_of(run),
            _ => Access::Refused(
                wit::Reason::NotDeclared,
                "this component's manifest does not declare tasks: add \"tasks\": true".to_string(),
            ),
        };
        Self {
            access,
            calls: 0,
            opened: 0,
            devices: None,
            conversation: Conversation::Unanswered,
        }
    }

    fn access_of(run: TasksRun) -> Access {
        let no_owner = |why: &str| Access::Refused(wit::Reason::NoOwner, why.to_string());
        let (Some(project_id), Some(project_uuid)) = (run.project_id, run.project_uuid) else {
            return no_owner("this run does not go through a project, and a task belongs to one");
        };
        let Some(build) = run.build.filter(|hash| hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit())) else {
            return Access::Refused(
                wit::Reason::Internal,
                "this run does not name the build it is of, and a task names the build that made it".to_string(),
            );
        };
        let (Some(owner), Some(profile)) = (run.owner, run.profile) else {
            return no_owner("this run names no secret row, so it has no owner to address a task to");
        };
        let Some(grant) = run.grant else {
            return no_owner("the secret row this run names was not opened, so it has no owner to address a task to");
        };
        let Some(caller) = run.caller else {
            return no_owner("this run has no caller, and a task is made and answered by an account");
        };
        // The consent a task this run opens carries, and what this run is
        // held to when it carries one out: the payment key that pays for it,
        // and the wallet, the identity and the compute limit it runs with. A
        // run on chain has no payment key and so no consent.
        let consent = match (run.payment_key_nonce, run.compute_limit_usd) {
            (Some(payment_key_nonce), Some(compute_limit_usd)) => Some(Consent {
                payment_key_nonce,
                wallet: run.wallet_id,
                bound_identity: run.bound_identity,
                compute_limit_usd,
            }),
            _ => None,
        };
        // Judged before anything is read: a relayed run opens, reads and
        // answers nothing, whoever signed it.
        match run.predecessor.as_deref() {
            Some(called) if called == caller => {}
            Some(called) => {
                return Access::Refused(
                    wit::Reason::Relayed,
                    format!(
                        "this run was signed by {caller} and called by {called}: tasks are used by the account \
                         that calls OutLayer itself — directly or through a meta-transaction it signed — not \
                         through a contract"
                    ),
                )
            }
            None => {
                return Access::Refused(
                    wit::Reason::Relayed,
                    "this run does not say which account called OutLayer, so it cannot be told from a relayed one"
                        .to_string(),
                )
            }
        }
        let (Some(store), Some(chain)) = (run.store, run.chain) else {
            return Access::Refused(wit::Reason::Unavailable, "this worker has no task store configured".to_string());
        };
        let store = match HttpStore::new(store) {
            Ok(store) => store,
            Err(_) => return Access::Refused(wit::Reason::Unavailable, "the task store cannot be reached".to_string()),
        };
        let rpc = match RpcChain::new(chain.rpc_url) {
            Ok(rpc) => rpc,
            Err(_) => return Access::Refused(wit::Reason::Unavailable, "the chain cannot be reached".to_string()),
        };
        Access::Ready(Box::new(Ready {
            grant,
            run: run.run,
            project_id,
            build,
            operation: run.operation,
            scope: Scope { project_uuid, owner },
            profile,
            caller,
            consent,
            recipient: chain.recipient,
            store: Box::new(store),
            chain: Box::new(rpc),
            report: run.report,
            now: Box::new(system_now),
        }))
    }

    /// One call of the interface, counted.
    fn count(&mut self) -> Result<(), wit::TaskError> {
        self.calls = self.calls.saturating_add(1);
        match self.calls > super::MAX_CALLS_PER_RUN {
            true => Err(refused(
                wit::Reason::RunLimit,
                format!("this run made more than {} calls of the task interface", super::MAX_CALLS_PER_RUN),
            )),
            false => Ok(()),
        }
    }

    /// One call of the interface, counted; and the run's facts, when it may
    /// use tasks.
    fn enter(&mut self) -> Result<&Ready, wit::TaskError> {
        self.count()?;
        self.access.ready()
    }

    /// `report` and `report-failure`: the result sealed under the task's key,
    /// kept with the word whether the task was carried out.
    fn leave(&mut self, id: String, result: Vec<u8>, failed: bool) -> Result<(), wit::TaskError> {
        let ready = self.enter()?;
        an_id(&id)?;
        if result.len() > super::MAX_RESULT_BYTES {
            return Err(refused(
                wit::Reason::TooLarge,
                format!("the result is {} bytes; at most {} are kept", result.len(), super::MAX_RESULT_BYTES),
            ));
        }
        let sealed = ready
            .keys(&id)
            .seal(Sealed::Outcome, &id, &result)
            .map_err(|why| refused(wit::Reason::Unavailable, why))?;
        match ready.report.reported(&id, sealed, failed) {
            true => Ok(()),
            false => Err(refused(wit::Reason::NotFound, "this run answered no such task")),
        }
    }
}

impl Access {
    /// The run's facts, when it may use tasks.
    fn ready(&self) -> Result<&Ready, wit::TaskError> {
        match self {
            Access::Ready(ready) => Ok(ready),
            Access::Refused(reason, message) => Err(refused(*reason, message.clone())),
        }
    }
}

/// The owner's devices in force for this run: the list the run holds, or the
/// one read and checked now, which the run holds from then on whatever
/// becomes of the call that read it. A store or a chain that gave no answer
/// gave no list, and nothing is held.
fn devices_of_the_run(held: &mut Option<Vec<Device>>, ready: &Ready) -> Result<Vec<Device>, wit::TaskError> {
    match held {
        Some(devices) => Ok(devices.clone()),
        None => Ok(held.insert(ready.devices()?).clone()),
    }
}

impl Ready {
    fn is_the_owners(&self) -> bool {
        self.caller == self.scope.owner
    }

    fn the_owners(&self, what: &str) -> Result<(), wit::TaskError> {
        match self.is_the_owners() {
            true => Ok(()),
            false => Err(refused(
                wit::Reason::NotTheOwner,
                format!("{what} is the owner's: this run was made by another account"),
            )),
        }
    }

    fn keys(&self, task: &str) -> TaskKeys {
        TaskKeys::derive(self.grant.key(), task)
    }

    fn devices(&self) -> Result<Vec<Device>, wit::TaskError> {
        let statements = self.store.devices(&self.scope.owner).map_err(|e| store_failed(&e))?;
        statement::devices_in_force(&statements, &self.scope.owner, (self.now)(), &self.recipient, self.chain.as_ref())
            .map_err(|unavailable| refused(wit::Reason::Unavailable, unavailable.0))
    }

    /// A task as it is sealed: the envelope, its document and the
    /// component's state. `id` is the task asked for; what is sealed must be
    /// that task of this project and owner.
    fn unseal(&self, id: &str, sealed: &[u8]) -> Result<Unsealed, wit::TaskError> {
        let plain = self.keys(id).open(Sealed::Task, id, sealed).map_err(|_| unreadable())?;
        let task: SealedTask = serde_json::from_slice(&plain).map_err(|_| unreadable())?;
        let envelope = Envelope::from_bytes(task.envelope.as_bytes()).map_err(|_| unreadable())?;
        let state =
            base64::engine::general_purpose::STANDARD.decode(task.state.as_bytes()).map_err(|_| unreadable())?;
        let content_key: [u8; 32] =
            hex::decode(task.content_key.as_bytes()).ok().and_then(|k| k.try_into().ok()).ok_or_else(unreadable)?;
        let its_own = envelope.id == id
            && envelope.owner == self.scope.owner
            && envelope.project_uuid == self.scope.project_uuid
            && envelope.v == envelope::VERSION
            && envelope::hash(&state) == envelope.state_hash
            && envelope.kind.takes_an_answer() == task.consent.is_some();
        if !its_own {
            return Err(unreadable());
        }
        Ok(Unsealed {
            hash: envelope::hash(task.envelope.as_bytes()),
            envelope,
            state,
            content_key: zeroize::Zeroizing::new(content_key),
            consent: task.consent,
        })
    }

    fn copies_for(&self, id: &str, content_key: &[u8; 32], devices: &[Device]) -> Result<Vec<client::Copy>, wit::TaskError> {
        devices
            .iter()
            .map(|device| {
                crypto::seal_to(&device.key, Purpose::DeviceCopy, id, content_key)
                    .map(|wrapped_key| client::Copy { device_id: device.id.clone(), wrapped_key })
                    .map_err(|why| refused(wit::Reason::Unavailable, why))
            })
            .collect()
    }

    /// What is sealed beside a task's outcome, opened: the result the project
    /// reported and the reason the owner gave.
    fn opened_outcome(&self, task: &client::Prepared) -> Result<(Option<Vec<u8>>, Option<String>), wit::TaskError> {
        let keys = self.keys(&task.id);
        let result = task
            .outcome
            .as_deref()
            .map(|sealed| keys.open(Sealed::Outcome, &task.id, sealed).map(|r| r.to_vec()).map_err(|_| unreadable()))
            .transpose()?;
        let rejection = match task.rejection.as_deref() {
            Some(sealed) => self.reason_given(&task.id, sealed)?,
            None => None,
        };
        Ok((result, rejection))
    }

    /// The reason of a rejection, as the preparer is handed it. It is
    /// whatever was sealed to the task's reply key, so it is held to what an
    /// owner's page writes: [`super::MAX_REJECTION_BYTES`], sealed and
    /// opened, and the characters a `long_text` of a display holds. A reason
    /// outside them is handed over as no reason; one that does not open is
    /// `unreadable`.
    fn reason_given(&self, id: &str, sealed: &[u8]) -> Result<Option<String>, wit::TaskError> {
        let withheld = || {
            tracing::warn!(task = %id, "the reason of a rejection is outside its bounds and is not handed over");
            Ok(None)
        };
        if sealed.len() > super::MAX_REJECTION_BYTES {
            return withheld();
        }
        let opened = self.keys(id).open_reply(Purpose::Rejection, id, sealed).map_err(|_| unreadable())?;
        let reason = String::from_utf8(opened.to_vec()).map_err(|_| unreadable())?;
        match reason.len() <= super::MAX_REJECTION_BYTES && envelope::check_long_text("the reason", &reason).is_ok() {
            true => Ok(Some(reason)),
            false => withheld(),
        }
    }

    /// A task as its preparer reads it. One whose outcome does not open is
    /// `unreadable` to the caller that asked for that task; in the list of
    /// the caller's tasks it stands with its state and times, and with no
    /// result and no reason.
    fn outcome(&self, task: client::Prepared, asked: Asked) -> Result<wit::Outcome, wit::TaskError> {
        let (result, rejection) = match (self.opened_outcome(&task), asked) {
            (Ok(opened), Asked::ThisTask | Asked::TheList) => opened,
            (Err(refusal), Asked::ThisTask) => return Err(refusal),
            (Err(_), Asked::TheList) => {
                tracing::warn!(task = %task.id, "a task's outcome does not open; the task is listed without it");
                (None, None)
            }
        };
        Ok(wit::Outcome {
            id: task.id,
            kind: kind_out(task.kind),
            state: state_out(task.state),
            created_at: u64::try_from(task.created_at).unwrap_or(0),
            expires_at: u64::try_from(task.expires_at).unwrap_or(0),
            run: task.run,
            result,
            rejection,
            failure_reason: task.failure_reason,
        })
    }
}

/// Why an approved task was not taken by this run.
enum Untaken {
    /// The host refused the run before anything moved: recorded, and the
    /// task fails when the run ends.
    Refused(wit::TaskError),
    /// The store did not move the task to this run — another run took it,
    /// or the store gave no answer — which the store's own record settles.
    NotMoved(wit::TaskError),
}

impl Ready {
    /// Take the approved task `id` for this run: E4 to E11 of the flow, in
    /// order, each refusing before anything moves.
    #[allow(clippy::too_many_arguments)]
    fn take_approved(
        &self,
        id: &str,
        hash: &str,
        operation: &str,
        policy: &[u8],
        approval: &Approval,
        supplied: Option<Vec<u8>>,
        note: Option<Vec<u8>>,
        stored: &client::Stored,
    ) -> Result<wit::Answer, Untaken> {
        let before = Untaken::Refused;
        let task = self.unseal(id, stored.sealed.as_deref().ok_or_else(unreadable).map_err(before)?).map_err(before)?;
        // The life that was sealed, whatever the row says.
        let now = (self.now)();
        if task.envelope.expires_at <= u64::try_from(now).unwrap_or(u64::MAX) {
            return Err(before(not_open(client::State::Expired)));
        }
        if !hash.eq_ignore_ascii_case(&task.hash) {
            return Err(before(refused(
                wit::Reason::HashMismatch,
                "the hash named is not this task's: what was shown is not what is stored",
            )));
        }
        // The operation running is the host's word where the call names one;
        // the component's word must agree with it, and the task's with both.
        if self.operation.as_deref().is_some_and(|running| running != operation) {
            return Err(before(refused(wit::Reason::AnswerInvalid, "the operation named is not the one this call runs")));
        }
        let Some(answer_by) = task.envelope.answer_by.clone() else {
            return Err(before(notice_takes_no_answer()));
        };
        if operation != answer_by.operation {
            return Err(before(refused(
                wit::Reason::AnswerInvalid,
                "the task is answered by another operation of this project than the one running",
            )));
        }
        // The task is acted on with the row it was made for: another row of
        // the same owner and project is not the task's, whatever it holds.
        if task.envelope.profile != self.profile {
            return Err(before(refused(
                wit::Reason::NotFound,
                "the task was made for another secret row of this owner than the one this call names",
            )));
        }
        // The run that carries the task out is the preparer's run the consent
        // names: the same account, on the same payment key, wallet and
        // identity, within the compute the preparing run allowed. Nobody
        // else's run — the owner's included — acts on it.
        let not_the_preparer = |which: &str| {
            before(refused(
                wit::Reason::NotThePreparer,
                format!("the task is carried out by the run of the agent that prepared it, and this run is {which}"),
            ))
        };
        if self.caller != task.envelope.preparer {
            return Err(not_the_preparer("another account's"));
        }
        let Some(consent) = self.consent.as_ref() else {
            return Err(not_the_preparer("made with no payment key"));
        };
        let Some(consented) = task.consent.as_ref() else {
            return Err(before(notice_takes_no_answer()));
        };
        if let Some(differs) = consented.refuses(consent) {
            return Err(not_the_preparer(&format!("on {differs}")));
        }
        // The task is answered under the policy and by the build it was made
        // with, or by nothing: what the owner was shown and proved is what
        // acts. Either changed closes the task for every reader. A store
        // that cannot be told now is told by the run's end, which fails the
        // task with this reason.
        let unchanged = envelope::hash(policy) == task.envelope.policy_hash;
        let same_build = task.envelope.build == self.build;
        if !unchanged || !same_build {
            if let Err(e) = self.store.void(&self.scope, id) {
                tracing::warn!(task = %id, "a void task could not be closed in the store: {e:?}");
            }
            let why = match (unchanged, same_build) {
                (false, _) => "the policy changed since the task was made",
                (true, false) => "the task was made by another build of this project than the one running",
                (true, true) => unreachable!("a task unchanged in both is not void"),
            };
            tracing::info!(task = %id, "a task is void: {why}");
            return Err(before(refused(wit::Reason::Void, format!("the task takes no answer: {why}"))));
        }
        // The owner's approval: over the sealed bytes as the page sent them,
        // verified before they are opened. A chain that gives no answer is a
        // refusal like any other here: the run did not act, the task fails,
        // the agent prepares again.
        if let Err(why) = statement::approval_holds(
            approval,
            &task.envelope.owner,
            id,
            &task.hash,
            supplied.as_deref(),
            note.as_deref(),
            now,
            task.envelope.expires_at,
            &self.recipient,
            self.chain.as_ref(),
        ) {
            return Err(before(match why {
                ApprovalRefused::Invalid(why) => refused(wit::Reason::ApprovalInvalid, why),
                ApprovalRefused::Unavailable(why) => refused(wit::Reason::Unavailable, why),
            }));
        }
        let supplied = match (answer_by.supplies, supplied) {
            (envelope::Supplies::Nothing, None) => None,
            (envelope::Supplies::Nothing, Some(_)) => {
                return Err(before(refused(wit::Reason::AnswerInvalid, "the task asks for nothing, and the answer supplies something")));
            }
            (envelope::Supplies::Text | envelope::Supplies::File, None) => {
                return Err(before(refused(wit::Reason::AnswerInvalid, "the task asks for something, and the answer supplies nothing")));
            }
            (envelope::Supplies::Text | envelope::Supplies::File, Some(sealed)) => {
                if sealed.len() > super::MAX_SUPPLIED_BYTES {
                    return Err(before(refused(wit::Reason::AnswerInvalid, "what the answer supplies is over its bound")));
                }
                let opened = self.keys(id).open_reply(Purpose::Answer, id, &sealed).map_err(|_| {
                    before(refused(wit::Reason::AnswerInvalid, "what the answer supplies does not open for this task"))
                })?;
                Some(opened.to_vec())
            }
        };
        // The note the owner wrote beside their approval: text, within the
        // bound and the characters of a long text, or the answer is refused.
        let note = match note {
            None => None,
            Some(sealed) => {
                if sealed.len() > super::MAX_NOTE_BYTES {
                    return Err(before(refused(wit::Reason::AnswerInvalid, "the note is over its bound")));
                }
                let opened = self.keys(id).open_reply(Purpose::Note, id, &sealed).map_err(|_| {
                    before(refused(wit::Reason::AnswerInvalid, "the note does not open for this task"))
                })?;
                let text = String::from_utf8(opened.to_vec())
                    .map_err(|_| before(refused(wit::Reason::AnswerInvalid, "the note is not text")))?;
                envelope::check_long_text("the note", &text)
                    .map_err(|why| before(refused(wit::Reason::AnswerInvalid, why)))?;
                Some(text.into_bytes())
            }
        };
        // The files the task was made with, opened before anything moves: a
        // file that is missing, changed or another task's hands nothing over.
        if stored.files.len() != task.envelope.files.len() {
            return Err(before(unreadable()));
        }
        let files = task
            .envelope
            .files
            .iter()
            .zip(&stored.files)
            .enumerate()
            .map(|(at, (note, blob))| {
                let data = crypto::decrypt_file(&task.content_key, id, at, blob).map_err(|_| unreadable())?;
                match envelope::hash(&data) == note.sha256 && data.len() as u64 == note.size {
                    true => Ok(wit::File { name: note.name.clone(), content_type: note.content_type.clone(), data }),
                    false => Err(unreadable()),
                }
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(before)?;
        // Recorded before the store is asked, and forgotten only when the
        // store refuses by name, which moves nothing. An answer whose reply
        // did not come may have been taken, and is reported on when the run
        // ends; the store's report of a task it did not move to this run
        // changes nothing. Neither is a refusal of this run's: the store's
        // record settles what became of the task.
        self.report.answered(id);
        if let Err(e) = self.store.answer(&self.scope, id, &self.run) {
            match &e {
                StoreError::Refused(..) => self.report.forget(id),
                StoreError::Unavailable(_) => {
                    tracing::warn!(task = %id, run = %self.run, "the store did not reply to an answer; the run reports on the task in case it was taken")
                }
            }
            return Err(Untaken::NotMoved(store_failed(&e)));
        }
        tracing::info!(task = %id, run = %self.run, "task answered");

        Ok(wit::Answer {
            id: id.to_string(),
            thread: task.envelope.thread,
            preparer: task.envelope.preparer,
            kind: kind_of(task.envelope.kind),
            operation: answer_by.operation,
            state: task.state,
            files,
            supplied,
            note,
        })
    }
}

/// What a preparer asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Asked {
    /// Every task of theirs: `mine`.
    TheList,
    /// One task, by its id: `status`.
    ThisTask,
}

struct Unsealed {
    envelope: Envelope,
    /// SHA-256 of the envelope's document, as it was written.
    hash: String,
    state: Vec<u8>,
    content_key: zeroize::Zeroizing<[u8; 32]>,
    /// The preparer's consent, as sealed with the task; none for a notice.
    consent: Option<Consent>,
}

fn kind_out(kind: client::Kind) -> wit::TaskKind {
    match kind {
        client::Kind::Confirm => wit::TaskKind::Confirm,
        client::Kind::Input => wit::TaskKind::Input,
        client::Kind::Notice => wit::TaskKind::Notice,
    }
}

fn kind_of(kind: envelope::Kind) -> wit::TaskKind {
    match kind {
        envelope::Kind::Confirm => wit::TaskKind::Confirm,
        envelope::Kind::Input => wit::TaskKind::Input,
        envelope::Kind::Notice => wit::TaskKind::Notice,
    }
}

fn notice_takes_no_answer() -> wit::TaskError {
    refused(wit::Reason::AnswerInvalid, "the task is a notice: it takes no answer, and the owner closes it with Got it")
}

fn state_out(state: client::State) -> wit::TaskState {
    match state {
        client::State::Open => wit::TaskState::Open,
        client::State::Approved => wit::TaskState::Approved,
        client::State::Answering => wit::TaskState::Answering,
        client::State::Done => wit::TaskState::Done,
        client::State::Failed => wit::TaskState::Failed,
        client::State::Rejected => wit::TaskState::Rejected,
        client::State::Cancelled => wit::TaskState::Cancelled,
        client::State::Expired => wit::TaskState::Expired,
        client::State::Void => wit::TaskState::Void,
    }
}

/// Why a task that is not `approved` for this run takes no answer.
fn not_open(state: client::State) -> wit::TaskError {
    match state {
        client::State::Open => refused(
            wit::Reason::ApprovalInvalid,
            "the task is open and the owner has not approved it; a run carries a task out on the owner's approval only",
        ),
        client::State::Approved => refused(
            wit::Reason::Closed,
            "the task is approved: the owner said yes, and the run the platform started for it is the one that acts",
        ),
        client::State::Expired => refused(wit::Reason::Expired, "the task is past its life"),
        client::State::Void => refused(wit::Reason::Void, "the policy changed since the task was made"),
        other => refused(wit::Reason::Closed, format!("the task is {} and takes no answer", state_name(other))),
    }
}

fn state_name(state: client::State) -> &'static str {
    match state {
        client::State::Open => "open",
        client::State::Approved => "approved",
        client::State::Answering => "answering",
        client::State::Done => "done",
        client::State::Failed => "failed",
        client::State::Rejected => "rejected",
        client::State::Cancelled => "cancelled",
        client::State::Expired => "expired",
        client::State::Void => "void",
    }
}

/// A reason as the store names it in `run_refused:<reason>`: the WIT's own
/// spelling.
fn reason_name(reason: wit::Reason) -> &'static str {
    match reason {
        wit::Reason::NotDeclared => "not-declared",
        wit::Reason::NoOwner => "no-owner",
        wit::Reason::Relayed => "relayed",
        wit::Reason::NotGrantedByName => "not-granted-by-name",
        wit::Reason::Muted => "muted",
        wit::Reason::InboxFull => "inbox-full",
        wit::Reason::RunLimit => "run-limit",
        wit::Reason::DisplayInvalid => "display-invalid",
        wit::Reason::TooLarge => "too-large",
        wit::Reason::LifeTooLong => "life-too-long",
        wit::Reason::NotFound => "not-found",
        wit::Reason::NotTheOwner => "not-the-owner",
        wit::Reason::NotThePreparer => "not-the-preparer",
        wit::Reason::ApprovalInvalid => "approval-invalid",
        wit::Reason::NoPaymentKey => "no-payment-key",
        wit::Reason::HashMismatch => "hash-mismatch",
        wit::Reason::AnswerInvalid => "answer-invalid",
        wit::Reason::Closed => "closed",
        wit::Reason::Expired => "expired",
        wit::Reason::Void => "void",
        wit::Reason::Unreadable => "unreadable",
        wit::Reason::Unavailable => "unavailable",
        wit::Reason::Internal => "internal",
    }
}

/// The store's failure, as the component is told it.
fn store_failed(error: &StoreError) -> wit::TaskError {
    match error {
        StoreError::Unavailable(why) => refused(wit::Reason::Unavailable, why.clone()),
        StoreError::Refused(Refusal::NotFound, _) => refused(wit::Reason::NotFound, "no such task"),
        StoreError::Refused(Refusal::Muted, _) => {
            refused(wit::Reason::Muted, "the owner muted this agent or this project")
        }
        StoreError::Refused(Refusal::InboxFull, _) => {
            refused(wit::Reason::InboxFull, "the owner has as many open tasks as an inbox holds")
        }
        StoreError::Refused(Refusal::PreparerFull, _) => refused(
            wit::Reason::InboxFull,
            "this agent holds as many tasks waiting on this owner as one agent may; one must close before another opens",
        ),
        StoreError::Refused(Refusal::StorageFull, _) => refused(
            wit::Reason::InboxFull,
            "the owner's waiting tasks hold as much as an inbox stores; it has room when the owner answers some",
        ),
        StoreError::Refused(Refusal::LifeTooLong, _) => {
            refused(wit::Reason::LifeTooLong, "the task's life is longer than a task may wait")
        }
        StoreError::Refused(Refusal::Closed | Refusal::Expired, Some(state)) => not_open(*state),
        StoreError::Refused(Refusal::Expired, None) => not_open(client::State::Expired),
        StoreError::Refused(Refusal::Closed, None) => refused(wit::Reason::Closed, "the task takes no answer"),
        StoreError::Refused(Refusal::Exists, _) => refused(
            wit::Reason::Internal,
            "a task of this id exists already: an earlier run of this call made it, and it is among the caller's tasks",
        ),
        StoreError::Refused(Refusal::InvalidRequest, _) => {
            refused(wit::Reason::Internal, "the task store refused the request as malformed")
        }
    }
}

fn an_id(id: &str) -> Result<(), wit::TaskError> {
    match super::is_id(id) {
        true => Ok(()),
        false => Err(refused(wit::Reason::NotFound, "no such task")),
    }
}

fn display_in(display: wit::Display) -> envelope::Display {
    envelope::Display {
        title: display.title,
        fields: display
            .fields
            .into_iter()
            .map(|field| envelope::Field {
                label: field.label,
                values: field.values,
                kind: match field.kind {
                    wit::FieldKind::Money => envelope::FieldKind::Money,
                    wit::FieldKind::Account => envelope::FieldKind::Account,
                    wit::FieldKind::Address => envelope::FieldKind::Address,
                    wit::FieldKind::Text => envelope::FieldKind::Text,
                    wit::FieldKind::LongText => envelope::FieldKind::LongText,
                    wit::FieldKind::List => envelope::FieldKind::List,
                },
                written_by: match field.written_by {
                    wit::WrittenBy::Project => envelope::WrittenBy::Project,
                    wit::WrittenBy::Agent => envelope::WrittenBy::Agent,
                },
            })
            .collect(),
    }
}

impl wit::Host for TasksHostState {
    fn open(&mut self, request: wit::Request) -> Result<wit::Opened, wit::TaskError> {
        let (opened, conversation) = (self.opened, self.conversation.clone());
        self.count()?;
        let ready = self.access.ready()?;
        if !ready.is_the_owners() && !ready.grant.admitted_by_name {
            return Err(refused(
                wit::Reason::NotGrantedByName,
                "the owner's secret row admitted this run by a rule that names no account; a task is left only by \
                 an account the owner granted by name",
            ));
        }
        if opened >= super::MAX_OPENS_PER_RUN {
            return Err(refused(
                wit::Reason::RunLimit,
                format!("this run opened {opened} tasks, as many as one run may"),
            ));
        }
        // What the task takes back, and the consent it carries: the run that
        // carries an answer out is paid by this run's payment key, with this
        // run's wallet, identity and compute limit. A run with no payment key
        // has nothing to consent with, and opens no task that takes an
        // answer. A notice takes none, and carries no consent.
        let (kind, answer_by) = match (request.kind, request.answer_by) {
            (wit::TaskKind::Notice, None) => ((envelope::Kind::Notice, client::Kind::Notice), None),
            (wit::TaskKind::Notice, Some(_)) => {
                return Err(refused(wit::Reason::DisplayInvalid, "a notice takes no answer, and names no operation to answer by"));
            }
            (wit::TaskKind::Confirm | wit::TaskKind::Input, None) => {
                return Err(refused(wit::Reason::DisplayInvalid, "a task that takes an answer names the operation that carries it out"));
            }
            // A confirm takes a yes and nothing more; an input takes text or a
            // file. The other pairings open a task no answer can carry out —
            // the owner's page sends what the kind asks for, and the answer is
            // then refused against what the task asks for — so they are
            // refused here, before the owner spends an approval on it.
            (wit::TaskKind::Confirm, Some(by)) if !matches!(by.supplies, wit::Supplies::Nothing) => {
                return Err(refused(wit::Reason::DisplayInvalid, "a confirm task takes a yes, and supplies nothing: ask for text or a file with an input task"));
            }
            (wit::TaskKind::Input, Some(by)) if matches!(by.supplies, wit::Supplies::Nothing) => {
                return Err(refused(wit::Reason::DisplayInvalid, "an input task asks for text or a file: a task that takes only a yes is a confirm task"));
            }
            (wit::TaskKind::Confirm, Some(by)) => ((envelope::Kind::Confirm, client::Kind::Confirm), Some(by)),
            (wit::TaskKind::Input, Some(by)) => ((envelope::Kind::Input, client::Kind::Input), Some(by)),
        };
        let consent = match (kind.0.takes_an_answer(), ready.consent.clone()) {
            (false, _) => None,
            (true, Some(consent)) => Some(consent),
            (true, None) => {
                return Err(refused(
                    wit::Reason::NoPaymentKey,
                    "the consent to carry out the owner's answer is a payment key — the run that carries it out is paid \
                     by that key — so a task that takes an answer is opened over HTTPS with one",
                ));
            }
        };
        let id = format!("{}-{opened}", ready.run);
        // A task opened in a run that answered one is the next turn of that
        // task's conversation; its preparer is this run's caller, as every
        // task's is. What that means in the owner's inbox is in
        // `docs/TASKS.md`, "Whose task, and who may do what".
        let preparer = ready.caller.clone();
        let thread = match conversation {
            Conversation::Unanswered => id.clone(),
            Conversation::One(thread) => thread,
            Conversation::Several => {
                return Err(refused(
                    wit::Reason::Internal,
                    "this run answered tasks of more than one conversation, so a task it opens belongs to none",
                ))
            }
        };
        if request.state.len() > super::MAX_STATE_BYTES {
            return Err(refused(
                wit::Reason::TooLarge,
                format!("state is {} bytes; at most {} are sealed", request.state.len(), super::MAX_STATE_BYTES),
            ));
        }
        if request.policy.len() > super::MAX_POLICY_BYTES {
            return Err(refused(
                wit::Reason::TooLarge,
                format!("policy is {} bytes; at most {} are hashed", request.policy.len(), super::MAX_POLICY_BYTES),
            ));
        }
        let life = match request.life_seconds {
            0 => super::MAX_LIFE_SECS,
            life if life > super::MAX_LIFE_SECS => {
                return Err(refused(
                    wit::Reason::LifeTooLong,
                    format!("a life of {life} seconds was asked; a task waits {} at most", super::MAX_LIFE_SECS),
                ));
            }
            life if life < super::MIN_ANSWER_LIFE_SECS && kind.0.takes_an_answer() => {
                return Err(refused(
                    wit::Reason::DisplayInvalid,
                    format!(
                        "a life of {life} seconds was asked; a task that takes an answer waits {} at least, so its owner has time to answer",
                        super::MIN_ANSWER_LIFE_SECS
                    ),
                ));
            }
            life => life,
        };
        if request.files.len() > super::MAX_FILES {
            return Err(refused(
                wit::Reason::TooLarge,
                format!("{} files; a task carries at most {}", request.files.len(), super::MAX_FILES),
            ));
        }
        let files_bytes: usize = request.files.iter().map(|f| f.data.len()).sum();
        if files_bytes > super::MAX_FILES_BYTES {
            return Err(refused(
                wit::Reason::TooLarge,
                format!("the files are {files_bytes} bytes together; a task carries at most {}", super::MAX_FILES_BYTES),
            ));
        }
        envelope::check_files(request.files.iter().map(|file| (file.name.as_str(), file.content_type.as_str())))
            .map_err(|why| refused(wit::Reason::DisplayInvalid, why))?;
        if let Some(by) = &answer_by {
            envelope::check_operation(&by.operation).map_err(|why| refused(wit::Reason::DisplayInvalid, why))?;
        }
        let display = display_in(request.display);
        envelope::check_display(&display).map_err(|why| refused(wit::Reason::DisplayInvalid, why))?;

        let devices = devices_of_the_run(&mut self.devices, ready)?;

        let keys = ready.keys(&id);
        let now = u64::try_from((ready.now)()).unwrap_or(0);
        let task = Envelope {
            build: ready.build.clone(),
            answer_by: answer_by.map(|by| envelope::AnswerBy {
                operation: by.operation,
                supplies: match by.supplies {
                    wit::Supplies::Nothing => envelope::Supplies::Nothing,
                    wit::Supplies::Text => envelope::Supplies::Text,
                    wit::Supplies::File => envelope::Supplies::File,
                },
            }),
            created_at: now,
            display,
            expires_at: now + u64::from(life),
            files: request
                .files
                .iter()
                .map(|file| envelope::FileNote {
                    content_type: file.content_type.clone(),
                    name: file.name.clone(),
                    sha256: envelope::hash(&file.data),
                    size: file.data.len() as u64,
                })
                .collect(),
            id: id.clone(),
            kind: kind.0,
            owner: ready.scope.owner.clone(),
            policy_hash: envelope::hash(&request.policy),
            preparer: preparer.clone(),
            profile: ready.profile.clone(),
            project: ready.project_id.clone(),
            project_uuid: ready.scope.project_uuid.clone(),
            reply_pubkey: kind.0.takes_an_answer().then(|| keys.reply_pubkey()),
            state_hash: envelope::hash(&request.state),
            thread,
            v: envelope::VERSION,
        };
        let document = task.to_bytes().map_err(|why| refused(wit::Reason::Unavailable, why))?;
        if document.len() > super::MAX_ENVELOPE_BYTES {
            return Err(refused(
                wit::Reason::TooLarge,
                format!("the task is {} bytes; at most {} are stored", document.len(), super::MAX_ENVELOPE_BYTES),
            ));
        }
        let unavailable = |why: String| refused(wit::Reason::Unavailable, why);
        let hash = envelope::hash(&document);
        let content_key = crypto::content_key().map_err(unavailable)?;
        let content = crypto::encrypt_content(&content_key, &id, &document).map_err(unavailable)?;
        let files = request
            .files
            .iter()
            .enumerate()
            .map(|(at, file)| crypto::encrypt_file(&content_key, &id, at, &file.data))
            .collect::<Result<Vec<_>, _>>()
            .map_err(unavailable)?;
        let copies = ready.copies_for(&id, &content_key, &devices)?;
        let voucher = match (&consent, &task.answer_by) {
            (Some(consent), Some(by)) => Some(Voucher {
                payment_key_nonce: consent.payment_key_nonce,
                wallet_id: consent.wallet.clone(),
                bound_identity: consent.bound_identity,
                compute_limit_usd: consent.compute_limit_usd.clone(),
                operation: by.operation.clone(),
                build: task.build.clone(),
            }),
            _ => None,
        };
        let sealed_task = SealedTask {
            content_key: hex::encode(content_key.as_ref()),
            envelope: String::from_utf8(document).map_err(|_| unavailable("the task is not text".to_string()))?,
            state: base64::engine::general_purpose::STANDARD.encode(&request.state),
            consent,
        };
        let plain = zeroize::Zeroizing::new(
            serde_json::to_vec(&sealed_task).map_err(|_| unavailable("the task could not be written".to_string()))?,
        );
        let sealed = keys.seal(Sealed::Task, &id, &plain).map_err(unavailable)?;

        let new = NewTask {
            id: id.clone(),
            project_id: ready.project_id.clone(),
            preparer,
            voucher,
            profile: ready.profile.clone(),
            vault: ready.grant.vault.clone(),
            kind: kind.1,
            expires_at: task.expires_at,
            reply_pubkey: task.reply_pubkey.clone(),
            sealed,
            content,
            files,
            copies,
        };
        let stored = ready.store.open(&ready.scope, &new).map_err(|e| store_failed(&e));
        let files = new.files.len();
        // The number is taken whether the store answered or not: a task whose
        // making was not heard of may have been made, and the next task of
        // this run is another task under another id.
        self.opened = self.opened.saturating_add(1);
        // The devices that read the task with no run are those whose copy the
        // store wrote, which is not more than were in force when it was asked.
        let written = stored?;
        tracing::info!(task = %id, devices = devices.len(), copies = written, files, "task opened");

        let answer = wit::Opened {
            id,
            hash,
            thread: task.thread,
            expires_at: task.expires_at,
            devices: u32::try_from(written).unwrap_or(u32::MAX),
        };
        Ok(answer)
    }

    fn mine(&mut self) -> Result<Vec<wit::Outcome>, wit::TaskError> {
        let ready = self.enter()?;
        let tasks = ready.store.mine(&ready.scope, &ready.caller, None).map_err(|e| store_failed(&e))?;
        tasks.into_iter().map(|task| ready.outcome(task, Asked::TheList)).collect()
    }

    fn status(&mut self, id: String) -> Result<wit::Outcome, wit::TaskError> {
        let ready = self.enter()?;
        an_id(&id)?;
        let mut tasks = ready.store.mine(&ready.scope, &ready.caller, Some(&id)).map_err(|e| store_failed(&e))?;
        match (tasks.pop(), tasks.is_empty()) {
            (Some(task), true) if task.id == id => ready.outcome(task, Asked::ThisTask),
            (None, _) => Err(refused(wit::Reason::NotFound, "no such task")),
            _ => Err(refused(wit::Reason::Internal, "the task store answered with other tasks than the one asked")),
        }
    }

    fn answered(
        &mut self,
        id: String,
        hash: String,
        operation: String,
        policy: Vec<u8>,
        approval: wit::Approval,
        supplied: Option<Vec<u8>>,
        note: Option<Vec<u8>>,
    ) -> Result<wit::Answer, wit::TaskError> {
        let ready = self.enter()?;
        an_id(&id)?;
        if policy.len() > super::MAX_POLICY_BYTES {
            return Err(refused(wit::Reason::TooLarge, "policy is over its bound"));
        }
        let stored = ready.store.get(&ready.scope, &id).map_err(|e| store_failed(&e))?;
        if stored.id != id {
            return Err(unreadable());
        }
        if stored.kind == client::Kind::Notice {
            return Err(notice_takes_no_answer());
        }
        if stored.state != client::State::Approved {
            return Err(not_open(stored.state));
        }
        // The task is approved and this run was started for it. A refusal
        // from here to the store's move is this run's, and fails the task
        // when the run ends: the owner said yes to a run that did not act,
        // and the agent prepares again.
        let approval = Approval {
            at: approval.at,
            public_key: approval.public_key,
            signature: approval.signature,
            nonce: approval.nonce,
        };
        match ready.take_approved(&id, &hash, &operation, &policy, &approval, supplied, note, &stored) {
            Ok(answer) => {
                self.conversation.answered(answer.thread.clone());
                Ok(answer)
            }
            Err(Untaken::Refused(refusal)) => {
                tracing::info!(task = %id, run = %ready.run, reason = reason_name(refusal.reason), "an approved task was refused this run");
                ready.report.refused(&id, reason_name(refusal.reason));
                Err(refusal)
            }
            Err(Untaken::NotMoved(refusal)) => Err(refusal),
        }
    }

    fn report(&mut self, id: String, result: Vec<u8>) -> Result<(), wit::TaskError> {
        self.leave(id, result, false)
    }

    fn report_failure(&mut self, id: String, result: Vec<u8>) -> Result<(), wit::TaskError> {
        self.leave(id, result, true)
    }

    fn cancel(&mut self, id: String) -> Result<(), wit::TaskError> {
        let ready = self.enter()?;
        an_id(&id)?;
        ready.store.cancel(&ready.scope, &ready.caller, &id).map_err(|e| store_failed(&e))
    }

    fn delete(&mut self, id: String) -> Result<(), wit::TaskError> {
        let ready = self.enter()?;
        an_id(&id)?;
        ready.store.delete(&ready.scope, &ready.caller, &id).map_err(|e| store_failed(&e))
    }

    fn unlock(&mut self) -> Result<u32, wit::TaskError> {
        self.count()?;
        let ready = self.access.ready()?;
        ready.the_owners("opening tasks for a device")?;
        let devices = devices_of_the_run(&mut self.devices, ready)?;
        let stored = ready.store.waiting(&ready.scope).map_err(|e| store_failed(&e))?;
        let mut copies = Vec::new();
        for row in stored {
            // A row that does not open is passed over: it is no task of the
            // owner's, and the others are.
            let Some(task) = row.sealed.as_deref().and_then(|sealed| ready.unseal(&row.id, sealed).ok()) else {
                tracing::warn!(task = %row.id, "a waiting task does not open and is passed over");
                continue;
            };
            if task.envelope.expires_at <= u64::try_from((ready.now)()).unwrap_or(u64::MAX) {
                continue;
            }
            copies.push((row.id.clone(), ready.copies_for(&row.id, &task.content_key, &devices)?));
        }
        // What was opened is what the store wrote: a task that closed, or a
        // device that left, since they were read is not among them. The
        // answer is in tasks, whatever the number of devices.
        let written = match devices.is_empty() || copies.is_empty() {
            true => client::Written::default(),
            false => ready.store.copies(&ready.scope, &copies).map_err(|e| store_failed(&e))?,
        };
        let opened = u32::try_from(written.tasks).unwrap_or(u32::MAX);
        tracing::info!(waiting = copies.len(), tasks = opened, copies = written.copies, devices = devices.len(), "tasks opened for the owner's devices");
        Ok(opened)
    }
}

/// Add the task host functions to a wasmtime component linker.
pub fn add_tasks_to_linker<T: Send + 'static>(
    linker: &mut Linker<T>,
    get_state: impl Fn(&mut T) -> &mut TasksHostState + Send + Sync + Copy + 'static,
) -> anyhow::Result<()> {
    wit::add_to_linker(linker, get_state)
}

#[cfg(test)]
#[path = "host_tests.rs"]
mod tests;
