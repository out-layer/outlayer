//! Tasks between an agent and its owner
//!
//! An agent's run prepares; the owner reads the task in their inbox and
//! approves it with one signature of their wallet; the platform then starts
//! a run of the same agent — on the agent's own payment key, wallet and
//! identity, within the compute limit of the preparing run — in the
//! operation the task names, and that run carries the task out. A run
//! admitted to an owner's secret row leaves that owner a task — "confirm
//! this email", "give me your photo" — and nothing waits inside a run: a
//! task is a record the platform keeps sealed. The owner makes no call and
//! pays nothing; a task is opened over HTTPS with a payment key, which is
//! the consent to the run that carries it out.
//!
//! Requires the `tasks` feature, and `"tasks": true` in the component's
//! `outlayer.manifest`.
//!
//! # Preparing
//!
//! ```rust,ignore
//! use outlayer::tasks::{self, Display, FieldKind, WrittenBy};
//!
//! let opened = tasks::confirm(
//!     Display::new("Send an email")
//!         .field("To", FieldKind::Address, &to, WrittenBy::Agent)
//!         .field("Body", FieldKind::LongText, &body, WrittenBy::Agent),
//!     "confirm",          // the operation the owner's approval runs
//!     &message_bytes,     // handed back to that operation, never shown
//!     policy_json.as_bytes(),
//! )
//! .open()?;
//! // Answer the agent: it did its part.
//! return Ok(tasks::awaiting_owner(&opened));
//! ```
//!
//! # Acting
//!
//! The operation named in the task is started by the platform, as a run of
//! the agent that prepared it, with `task_id`, `task_hash`, `approval` (the
//! owner's signature), and `supplied` and `note` when the owner wrote them:
//!
//! ```rust,ignore
//! let answer = tasks::answered_for("confirm", &input, policy_json.as_bytes())?;
//! let sent = send(&answer.state)?;          // today's limits, in this run's own cell; the policy is the one the task was made under
//! tasks::report(&answer.id, sent.to_string().as_bytes())?;
//! ```
//!
//! The host hands `state` over only once the run is the preparer's on the
//! same payment key, wallet and identity ([`Reason::NotThePreparer`]) and the
//! owner's approval holds for this task, its hash and what the owner wrote
//! ([`Reason::ApprovalInvalid`]). A refusal there fails the task with
//! `run_refused:<reason>`, which the agent reads in `task_status`, and the
//! agent prepares again.
//!
//! # Telling the owner something
//!
//! A notice asks nothing: the owner reads it and presses Got it. No
//! operation answers it and no run follows it, so a run with no payment key
//! — one made on chain — may open one.
//!
//! ```rust,ignore
//! let opened = tasks::notice(
//!     Display::new("The email was sent").field("To", FieldKind::Address, &to, WrittenBy::Project),
//!     policy_json.as_bytes(),
//! )
//! .open()?;
//! return Ok(tasks::notified(&opened));
//! ```
//!
//! The agent reads it `open` in `task_status` until the owner saw it, then
//! `done`.
//!
//! # The operations every project gets
//!
//! [`dispatch`] answers `task_status`, `task_cancel`, `task_delete`, `tasks`
//! and `tasks_unlock`, so a project writes only what is its own.
//!
//! # Errors
//!
//! Every refusal is a [`TaskError`]: a [`Reason`] to branch on and a sentence
//! for a person. "Nothing" is never an error — [`mine`] with no tasks is an
//! empty list — and a store or a chain that did not answer is never an empty
//! list: it is [`Reason::Unavailable`].

use crate::raw::tasks as raw;

pub use raw::{
    Answer, Approval, FieldKind, File, Opened, Outcome, Reason, Supplies, TaskKind, TaskState, WrittenBy,
};

/// The longest a task waits, in seconds.
pub const MAX_LIFE_SECS: u32 = 24 * 60 * 60;

/// A refusal of the task interface.
#[derive(Debug, Clone)]
pub struct TaskError {
    pub reason: Reason,
    pub message: String,
}

impl TaskError {
    /// The code a project's refusal opens with.
    pub fn code(&self) -> &'static str {
        match self.reason {
            Reason::NotDeclared => "tasks_not_declared",
            Reason::NoOwner => "no_owner",
            Reason::Relayed => "relayed",
            Reason::NotGrantedByName => "not_granted_by_name",
            Reason::Muted => "muted",
            Reason::InboxFull => "inbox_full",
            Reason::RunLimit => "task_run_limit",
            Reason::DisplayInvalid => "display_invalid",
            Reason::TooLarge => "task_too_large",
            Reason::LifeTooLong => "task_life_too_long",
            Reason::NotFound => "task_not_found",
            Reason::NotTheOwner => "not_the_owner",
            Reason::NotThePreparer => "not_the_preparer",
            Reason::ApprovalInvalid => "task_approval_invalid",
            Reason::NoPaymentKey => "task_no_payment_key",
            Reason::HashMismatch => "task_hash_mismatch",
            Reason::AnswerInvalid => "task_answer_invalid",
            Reason::Closed => "task_closed",
            Reason::Expired => "task_expired",
            Reason::Void => "task_void",
            Reason::Unreadable => "task_unreadable",
            Reason::Unavailable => "task_store_unavailable",
            Reason::Internal => "task_internal_error",
        }
    }

    /// Whether the same call may succeed later.
    pub fn is_transient(&self) -> bool {
        matches!(self.reason, Reason::Unavailable)
    }

    /// The refusal as a project answers it: `code: sentence`.
    pub fn refusal(&self) -> String {
        format!("{}: {}", self.code(), self.message)
    }
}

impl From<raw::TaskError> for TaskError {
    fn from(e: raw::TaskError) -> Self {
        Self { reason: e.reason, message: e.message }
    }
}

impl std::fmt::Display for TaskError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.refusal())
    }
}

impl std::error::Error for TaskError {}

/// Result type for task operations
pub type Result<T> = std::result::Result<T, TaskError>;

/// What the owner is shown: a title and fields, drawn as plain text.
///
/// A title is at most 80 characters and there are at most 12 fields; a label
/// is at most 40 characters; a value at most 50000 in a [`FieldKind::LongText`],
/// 500 in a [`FieldKind::Text`], 200 anywhere else. The host checks it when
/// the task is opened.
#[derive(Debug, Clone)]
pub struct Display {
    title: String,
    fields: Vec<raw::Field>,
}

impl Display {
    pub fn new(title: &str) -> Self {
        Self { title: title.to_string(), fields: Vec::new() }
    }

    /// A field of one value. `written_by` says whose words they are: the
    /// project's (an amount it computed, a name the service gave) or the
    /// agent's (a body, a memo).
    pub fn field(mut self, label: &str, kind: FieldKind, value: &str, written_by: WrittenBy) -> Self {
        self.fields.push(raw::Field { label: label.to_string(), kind, values: vec![value.to_string()], written_by });
        self
    }

    /// A [`FieldKind::List`] of 1 to 20 values.
    pub fn list<S: AsRef<str>>(mut self, label: &str, values: &[S], written_by: WrittenBy) -> Self {
        self.fields.push(raw::Field {
            label: label.to_string(),
            kind: FieldKind::List,
            values: values.iter().map(|v| v.as_ref().to_string()).collect(),
            written_by,
        });
        self
    }
}

/// A task to open.
#[derive(Debug, Clone)]
pub struct Task {
    request: raw::Request,
}

impl Task {
    fn new(kind: TaskKind, display: Display, answer_by: Option<raw::AnswerBy>, state: &[u8], policy: &[u8]) -> Self {
        Self {
            request: raw::Request {
                kind,
                display: raw::Display { title: display.title, fields: display.fields },
                answer_by,
                files: Vec::new(),
                state: state.to_vec(),
                policy: policy.to_vec(),
                life_seconds: 0,
            },
        }
    }

    /// How long the task waits, at most [`MAX_LIFE_SECS`]. Without it, that
    /// long. A task whose action depends on a price takes a short life — a
    /// confirm or input task 900 seconds at least, so its owner has time to
    /// answer; less is refused `display-invalid`.
    pub fn life_seconds(mut self, seconds: u32) -> Self {
        self.request.life_seconds = seconds;
        self
    }

    /// A file the owner is given to open beside the fields: an attachment, a
    /// document. The owner's page lists it by name, type and size and hands
    /// it over as a download; the operation that answers the task gets it
    /// back in [`Answer::files`]. At most 10 files, 6 MiB together.
    pub fn file(mut self, name: &str, content_type: &str, data: &[u8]) -> Self {
        self.request.files.push(File {
            name: name.to_string(),
            content_type: content_type.to_string(),
            data: data.to_vec(),
        });
        self
    }

    /// Open it for the owner of the secret row this run was admitted to, with
    /// this run's consent to the run that will carry it out: the same
    /// payment key, wallet and identity, within this run's compute limit. A
    /// run with no payment key is refused [`Reason::NoPaymentKey`], except
    /// for a notice, which no run follows.
    pub fn open(self) -> Result<Opened> {
        raw::open(&self.request).map_err(TaskError::from)
    }
}

/// A task the owner answers yes or no. `operation` is the operation of this
/// project the platform runs, as the agent, on the owner's approval; `state`
/// is handed back to it and never shown; `policy` is the policy the task is
/// made under, as the project reads it.
pub fn confirm(display: Display, operation: &str, state: &[u8], policy: &[u8]) -> Task {
    Task::new(TaskKind::Confirm, display, Some(raw::AnswerBy { operation: operation.to_string(), supplies: Supplies::Nothing }), state, policy)
}

/// A task the owner answers by supplying something: [`Supplies::Text`], or
/// [`Supplies::File`] — a reference to a file and its hash.
pub fn input(display: Display, operation: &str, supplies: Supplies, state: &[u8], policy: &[u8]) -> Task {
    Task::new(TaskKind::Input, display, Some(raw::AnswerBy { operation: operation.to_string(), supplies }), state, policy)
}

/// A notice: it tells the owner something and asks nothing. No operation
/// answers it, nothing is handed back, no run follows; the owner closes it
/// with Got it, and the agent reads it `done`. Files may go with it.
pub fn notice(display: Display, policy: &[u8]) -> Task {
    Task::new(TaskKind::Notice, display, None, &[], policy)
}

/// The tasks whose preparer is this caller in this project for this owner.
pub fn mine() -> Result<Vec<Outcome>> {
    raw::mine().map_err(TaskError::from)
}

/// One of them.
pub fn status(id: &str) -> Result<Outcome> {
    raw::status(id).map_err(TaskError::from)
}

/// Take the task the owner approved, in `operation` — the operation now
/// running; a task that names another to answer by is refused and stays as
/// it is. `policy` is the policy as the project reads it now; `approval` the
/// owner's signature as the run's input carries it; `supplied` and `note`
/// what the owner's page sent, sealed, as the input carries them.
///
/// On `Ok` the task is `answering` under this run. Act, then [`report`].
pub fn answered(
    id: &str,
    hash: &str,
    operation: &str,
    policy: &[u8],
    approval: &Approval,
    supplied: Option<&[u8]>,
    note: Option<&[u8]>,
) -> Result<Answer> {
    raw::answered(id, hash, operation, policy, approval, supplied, note).map_err(TaskError::from)
}

/// Leave `result` for the preparer of a task this run answered, and with it
/// the word that the task was carried out: it is `done` when the run ends as
/// a success, and `failed` as `run_trapped`, with `result`, when the run
/// fails after. A task answered and reported nothing of is `failed` as
/// `run_unreported` — the preparer cannot tell whether it acted, so a run
/// that acted reports. For a task NOT carried out, [`failed`].
pub fn report(id: &str, result: &[u8]) -> Result<()> {
    raw::report(id, result).map_err(TaskError::from)
}

/// Most bytes [`failure`] writes: what a result holds (16384), with room to spare.
const MOST_FAILURE_BYTES: usize = 15 * 1024;

/// What [`failed`] reports: `{"error": refusal}`, at most
/// [`MOST_FAILURE_BYTES`] as written — the refusal cut at a character until
/// its JSON, escapes included, fits. `task_status` hands it to the agent as
/// the failed task's `result`.
pub fn failure(refusal: &str) -> Vec<u8> {
    let written = |text: &str| serde_json::json!({ "error": text }).to_string().into_bytes();
    let whole = written(refusal);
    if whole.len() <= MOST_FAILURE_BYTES {
        return whole;
    }
    // Escapes can make the JSON up to six times the text: halve until it
    // fits, then the cut is at a character.
    let mut keep = refusal.len().min(MOST_FAILURE_BYTES);
    loop {
        while !refusal.is_char_boundary(keep) {
            keep -= 1;
        }
        let cut = written(&refusal[..keep]);
        if cut.len() <= MOST_FAILURE_BYTES || keep == 0 {
            return cut;
        }
        keep /= 2;
    }
}

/// Tell the preparer that a task this run answered was NOT carried out, and
/// why: the refusal after the answer, sealed for the preparer like any
/// result. The task ends `failed` as `run_failed` with `{"error": …}` as the
/// `result` the agent reads in `task_status`, however the run ends.
pub fn failed(id: &str, refusal: &str) -> Result<()> {
    raw::report_failure(id, &failure(refusal)).map_err(TaskError::from)
}

/// The title of the notice [`failed_and_told`] leaves the owner.
pub const NOT_CARRIED_OUT: &str = "Not carried out";

/// What [`failed_and_told`] did.
#[derive(Debug)]
pub struct Told {
    /// The notice, as [`notified`] spells it; `None` when it could not be
    /// opened. The run's answer names it — see [`Refused`].
    pub notice: Option<serde_json::Value>,
    /// The failure report, as [`failed`] answers it.
    pub reported: Result<()>,
}

/// [`failed`], and the owner told why at once: a notice in the answered
/// task's conversation, under it in the inbox, showing the refusal. `policy`
/// is the policy as the project reads it, as for [`answered`]. A notice that
/// cannot be opened does not keep the task from failing: the refusal the
/// agent reads then says the owner was not told, and why.
///
/// The run's answer must name the notice ([`Refused::output`]): the owner's
/// page holds what a notice shows to the attested answer of the run that
/// opened it, and a notice no answer names does not hold.
pub fn failed_and_told(id: &str, refusal: &str, policy: &[u8]) -> Told {
    let display = Display::new(NOT_CARRIED_OUT).field("Why", FieldKind::LongText, shown(refusal), WrittenBy::Project);
    match notice(display, policy).open() {
        Ok(opened) => Told { notice: Some(notified(&opened)), reported: failed(id, refusal) },
        Err(e) => Told {
            notice: None,
            reported: failed(id, &format!("{refusal} (the owner was not told: {})", e.refusal())),
        },
    }
}

/// The refusal of a run that answered a task, with the notice that told the
/// owner why, when one was opened.
#[derive(Debug, Clone, PartialEq)]
pub struct Refused {
    pub refusal: String,
    pub notice: Option<serde_json::Value>,
}

impl From<String> for Refused {
    fn from(refusal: String) -> Self {
        Self { refusal, notice: None }
    }
}

impl Refused {
    /// The `output` the run answers beside its `error`: `{"notice": …}`, so
    /// the attested answer names the notice by its id and hash. `None` when
    /// no notice was opened.
    pub fn output(&self) -> Option<serde_json::Value> {
        self.notice.as_ref().map(|notice| serde_json::json!({ "notice": notice }))
    }
}

/// The refusal as a notice shows it: at most [`MOST_FAILURE_BYTES`], cut at a
/// character.
fn shown(refusal: &str) -> &str {
    let mut keep = refusal.len().min(MOST_FAILURE_BYTES);
    while !refusal.is_char_boundary(keep) {
        keep -= 1;
    }
    &refusal[..keep]
}

/// Withdraw an open task whose preparer is this caller. An approved task is
/// the owner's yes, and is not withdrawn.
pub fn cancel(id: &str) -> Result<()> {
    raw::cancel(id).map_err(TaskError::from)
}

/// Delete a task whose preparer is this caller and that nothing was carried
/// out on; one the owner's yes acted on, or may have, is refused
/// [`Reason::Closed`] — it is the owner's record too.
pub fn delete(id: &str) -> Result<()> {
    raw::delete(id).map_err(TaskError::from)
}

/// Write the copies of this project's open tasks for the owner's devices in
/// force. Answers how many tasks wait.
pub fn unlock() -> Result<u32> {
    raw::unlock().map_err(TaskError::from)
}

/// Standard base64 of what the owner's page sends as `supplied`.
fn from_base64(text: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let text = text.trim_end_matches('=');
    if text.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let (mut bits, mut held) = (0u32, 0u32);
    for byte in text.bytes() {
        let value = ALPHABET.iter().position(|a| *a == byte)? as u32;
        bits = (bits << 6) | value;
        held += 6;
        if held >= 8 {
            held -= 8;
            out.push((bits >> held) as u8);
            bits &= (1 << held) - 1;
        }
    }
    Some(out)
}

fn to_base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().fold(0u32, |n, b| (n << 8) | u32::from(*b)) << (8 * (3 - chunk.len()));
        for at in 0..4 {
            match at <= chunk.len() {
                true => out.push(ALPHABET[((n >> (18 - 6 * at)) & 63) as usize] as char),
                false => out.push('='),
            }
        }
    }
    out
}

fn invalid(what: &str) -> TaskError {
    TaskError { reason: Reason::AnswerInvalid, message: what.to_string() }
}

fn text_of<'a>(input: &'a serde_json::Value, member: &str) -> Result<&'a str> {
    input
        .get(member)
        .and_then(|v| v.as_str())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| invalid(&format!("the call names no `{member}`")))
}

/// Sealed bytes as the input carries them: base64, or absent.
fn sealed_of(input: &serde_json::Value, member: &str) -> Result<Option<Vec<u8>>> {
    match input.get(member) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(text)) => {
            Ok(Some(from_base64(text).ok_or_else(|| invalid(&format!("`{member}` is not base64")))?))
        }
        Some(_) => Err(invalid(&format!("`{member}` is not a string"))),
    }
}

/// The owner's approval as the run's input carries it: `approval` with `at`,
/// `public_key`, `signature` and `nonce`.
pub fn approval_of(input: &serde_json::Value) -> Result<Approval> {
    let approval = input.get("approval").ok_or_else(|| invalid("the call carries no `approval`"))?;
    let at = approval
        .get("at")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| invalid("`approval.at` is not a time"))?;
    let member = |name: &str| {
        approval
            .get(name)
            .and_then(|v| v.as_str())
            .filter(|v| !v.is_empty())
            .map(str::to_string)
            .ok_or_else(|| invalid(&format!("`approval.{name}` is missing")))
    };
    Ok(Approval { at, public_key: member("public_key")?, signature: member("signature")?, nonce: member("nonce")? })
}

/// Take the approved task as the platform starts this run for it: `task_id`
/// and `task_hash`, the owner's `approval`, and `supplied` and `note`
/// (base64) when the owner wrote them. `operation` is the operation now
/// running.
pub fn answered_for(operation: &str, input: &serde_json::Value, policy: &[u8]) -> Result<Answer> {
    let id = text_of(input, "task_id")?;
    let hash = text_of(input, "task_hash")?;
    let approval = approval_of(input)?;
    let supplied = sealed_of(input, "supplied")?;
    let note = sealed_of(input, "note")?;
    answered(id, hash, operation, policy, &approval, supplied.as_deref(), note.as_deref())
}

fn kind_name(kind: TaskKind) -> &'static str {
    match kind {
        TaskKind::Confirm => "confirm",
        TaskKind::Input => "input",
        TaskKind::Notice => "notice",
    }
}

/// A state as a project's answer spells it.
pub fn state_name(state: TaskState) -> &'static str {
    match state {
        TaskState::Open => "open",
        TaskState::Approved => "approved",
        TaskState::Answering => "answering",
        TaskState::Done => "done",
        TaskState::Failed => "failed",
        TaskState::Rejected => "rejected",
        TaskState::Cancelled => "cancelled",
        TaskState::Expired => "expired",
        TaskState::Void => "void",
    }
}

/// What a project answers when it opened a task instead of acting. It is a
/// success: the agent did its part, hands the owner the link and asks for the
/// outcome later with `task_status`. The owner's approval starts a run of
/// this agent, paid by this run's payment key, which must still be able to
/// pay then.
pub fn awaiting_owner(opened: &Opened) -> serde_json::Value {
    serde_json::json!({
        "status": "awaiting_owner",
        "task_id": opened.id,
        "task_hash": opened.hash,
        "thread": opened.thread,
        "expires_at": opened.expires_at,
        "link": format!("https://app.outlayer.ai/inbox/{}", opened.id),
    })
}

/// What a project answers when it told the owner something. Nothing waits
/// on the owner: `task_status` reads `open` until they saw it, then `done`.
/// `task_hash` lets the owner's page prove that this answer named this
/// notice.
pub fn notified(opened: &Opened) -> serde_json::Value {
    serde_json::json!({
        "status": "notified",
        "task_id": opened.id,
        "task_hash": opened.hash,
        "thread": opened.thread,
        "expires_at": opened.expires_at,
        "link": format!("https://app.outlayer.ai/inbox/{}", opened.id),
    })
}

/// A task as `task_status` and `tasks` answer it. A result that is JSON is
/// answered as JSON; any other, as text or as base64.
pub fn outcome_json(outcome: &Outcome) -> serde_json::Value {
    let mut out = serde_json::json!({
        "task_id": outcome.id,
        "kind": kind_name(outcome.kind),
        "state": state_name(outcome.state),
        "created_at": outcome.created_at,
        "expires_at": outcome.expires_at,
    });
    if let Some(run) = &outcome.run {
        out["run"] = serde_json::json!(run);
    }
    if let Some(result) = &outcome.result {
        out["result"] = match (serde_json::from_slice::<serde_json::Value>(result), std::str::from_utf8(result)) {
            (Ok(json), _) => json,
            (Err(_), Ok(text)) => serde_json::json!(text),
            (Err(_), Err(_)) => serde_json::json!({ "base64": to_base64(result) }),
        };
    }
    if let Some(reason) = &outcome.rejection {
        out["reason"] = serde_json::json!(reason);
    }
    if let Some(why) = &outcome.failure_reason {
        out["failure_reason"] = serde_json::json!(why);
    }
    out
}

/// The operations every project that uses tasks answers alike.
pub const OPERATIONS: &[&str] = &["task_status", "task_cancel", "task_delete", "tasks", "tasks_unlock"];

/// Answer `operation` when it is one of [`OPERATIONS`]: `Some` with the
/// output, or with the refusal as `code: sentence`. `None` for any other
/// operation — the project's own.
///
/// | Operation | Input | Output |
/// |---|---|---|
/// | `task_status` | `task_id` | the task: `state`, and `result`, `reason`, `run`, `failure_reason` when it has them |
/// | `task_cancel` | `task_id` | `{"task_id", "state": "cancelled"}` |
/// | `task_delete` | `task_id` | `{"task_id", "deleted": true}` |
/// | `tasks` | — | `{"tasks": [ … ]}`, empty when there are none |
/// | `tasks_unlock` | — | `{"waiting": n}`: the owner's devices read them now |
pub fn dispatch(operation: &str, input: &serde_json::Value) -> Option<std::result::Result<serde_json::Value, String>> {
    let answer = match operation {
        "task_status" => text_of(input, "task_id").and_then(status).map(|outcome| outcome_json(&outcome)),
        "task_cancel" => text_of(input, "task_id")
            .and_then(|id| cancel(id).map(|_| serde_json::json!({ "task_id": id, "state": "cancelled" }))),
        "task_delete" => text_of(input, "task_id")
            .and_then(|id| delete(id).map(|_| serde_json::json!({ "task_id": id, "deleted": true }))),
        "tasks" => mine().map(|tasks| serde_json::json!({ "tasks": tasks.iter().map(outcome_json).collect::<Vec<_>>() })),
        "tasks_unlock" => unlock().map(|waiting| serde_json::json!({ "waiting": waiting })),
        _ => return None,
    };
    Some(answer.map_err(|e| e.refusal()))
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_failure_is_the_refusal_under_error_whole_or_cut_at_a_character() {
        let v: serde_json::Value = serde_json::from_slice(&failure("policy_denied: over the budget. The task is closed")).unwrap();
        assert_eq!(v, serde_json::json!({"error": "policy_denied: over the budget. The task is closed"}));
        let long = "é".repeat(20_000);
        let bytes = failure(&long);
        assert!(bytes.len() <= MOST_FAILURE_BYTES, "{} bytes", bytes.len());
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(v["error"].as_str().unwrap().chars().all(|c| c == 'é'), "cut at a character, never inside one");
        // Quotes and control bytes grow when written: the bound is on the JSON.
        for grows in ["\"".repeat(15_000), "\u{1}".repeat(15_000)] {
            let bytes = failure(&grows);
            assert!(bytes.len() <= MOST_FAILURE_BYTES, "{} bytes", bytes.len());
            assert!(serde_json::from_slice::<serde_json::Value>(&bytes).is_ok());
        }
    }

    use super::*;

    #[test]
    fn the_owner_is_shown_the_refusal_whole_or_cut_at_a_character() {
        assert_eq!(shown("bank_refused: no approver"), "bank_refused: no approver");
        let long = "é".repeat(20_000);
        let cut = shown(&long);
        assert!(cut.len() <= MOST_FAILURE_BYTES && cut.len() > MOST_FAILURE_BYTES - 2, "{} bytes", cut.len());
        assert!(cut.chars().all(|c| c == 'é'), "cut at a character, never inside one");
    }

    #[test]
    fn a_refused_run_names_its_notice_beside_the_error() {
        let notice = serde_json::json!({"status": "notified", "task_id": "run-1", "task_hash": "ab"});
        let told = Refused { refusal: "bank_refused".into(), notice: Some(notice.clone()) };
        assert_eq!(told.output(), Some(serde_json::json!({"notice": notice})));
        assert_eq!(Refused::from("policy_denied".to_string()).output(), None);
    }

    #[test]
    fn base64_reads_what_it_writes_and_refuses_what_is_not() {
        for bytes in [&b""[..], b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar", &[0, 255, 254, 1]] {
            assert_eq!(from_base64(&to_base64(bytes)).unwrap(), bytes);
        }
        assert_eq!(to_base64(b"foob"), "Zm9vYg==");
        assert_eq!(from_base64("Zm9vYg").unwrap(), b"foob");
        assert!(from_base64("Zm9v*g==").is_none());
        assert!(from_base64("Z").is_none());
    }

    #[test]
    fn a_refusal_opens_with_its_code() {
        let e = TaskError { reason: Reason::NotFound, message: "no such task".into() };
        assert_eq!(e.refusal(), "task_not_found: no such task");
        assert!(!e.is_transient());
        let e = TaskError { reason: Reason::Unavailable, message: "the task store did not answer".into() };
        assert_eq!(e.code(), "task_store_unavailable");
        assert!(e.is_transient());
    }

    fn outcome(state: TaskState) -> Outcome {
        Outcome {
            id: "run-0".into(),
            kind: TaskKind::Confirm,
            state,
            created_at: 1,
            expires_at: 2,
            run: None,
            result: None,
            rejection: None,
            failure_reason: None,
        }
    }

    #[test]
    fn an_outcome_says_its_state_and_only_what_it_has() {
        let open = outcome_json(&outcome(TaskState::Open));
        assert_eq!(open["state"], "open");
        assert!(open.get("result").is_none() && open.get("reason").is_none() && open.get("run").is_none());

        let done = Outcome {
            run: Some("run-9".into()),
            result: Some(br#"{"message_id":"m1"}"#.to_vec()),
            ..outcome(TaskState::Done)
        };
        let done = outcome_json(&done);
        assert_eq!((done["state"].as_str(), done["run"].as_str()), (Some("done"), Some("run-9")));
        assert_eq!(done["result"]["message_id"], "m1");

        let text = Outcome { result: Some(b"sent".to_vec()), ..outcome(TaskState::Done) };
        assert_eq!(outcome_json(&text)["result"], "sent");
        let bytes = Outcome { result: Some(vec![0xff, 0xfe]), ..outcome(TaskState::Done) };
        assert_eq!(outcome_json(&bytes)["result"]["base64"], "//4=");

        let rejected = Outcome { rejection: Some("wrong recipient".into()), ..outcome(TaskState::Rejected) };
        assert_eq!(outcome_json(&rejected)["reason"], "wrong recipient");

        let failed = Outcome { run: Some("run-9".into()), failure_reason: Some("run_refused:hash-mismatch".into()), ..outcome(TaskState::Failed) };
        let failed = outcome_json(&failed);
        assert_eq!((failed["state"].as_str(), failed["failure_reason"].as_str()), (Some("failed"), Some("run_refused:hash-mismatch")));
        assert_eq!(state_name(TaskState::Approved), "approved");
    }

    #[test]
    fn the_approval_is_read_off_the_input_as_the_platform_writes_it() {
        let input = serde_json::json!({
            "operation": "confirm", "task_id": "run-a-0", "task_hash": "ab",
            "approval": { "at": 1_790_000_000u64, "public_key": "ed25519:k", "signature": "s", "nonce": "n" },
            "supplied": "YWJj", "note": null,
        });
        let approval = approval_of(&input).unwrap();
        assert_eq!((approval.at, approval.public_key.as_str(), approval.signature.as_str(), approval.nonce.as_str()), (1_790_000_000, "ed25519:k", "s", "n"));
        assert_eq!(sealed_of(&input, "supplied").unwrap().as_deref(), Some(&b"abc"[..]));
        assert_eq!(sealed_of(&input, "note").unwrap(), None);
        for broken in [
            serde_json::json!({}),
            serde_json::json!({ "approval": { "at": "soon", "public_key": "k", "signature": "s", "nonce": "n" } }),
            serde_json::json!({ "approval": { "at": 1, "public_key": "", "signature": "s", "nonce": "n" } }),
            serde_json::json!({ "approval": { "at": 1, "public_key": "k", "signature": "s" } }),
        ] {
            let e = approval_of(&broken).unwrap_err();
            assert_eq!(e.code(), "task_answer_invalid", "{broken}");
        }
        assert_eq!(sealed_of(&serde_json::json!({ "supplied": 5 }), "supplied").unwrap_err().code(), "task_answer_invalid");
        assert_eq!(sealed_of(&serde_json::json!({ "supplied": "***" }), "supplied").unwrap_err().code(), "task_answer_invalid");
    }

    #[test]
    fn every_reason_has_a_code_and_the_new_ones_are_named() {
        let e = |reason: Reason| TaskError { reason, message: String::new() }.code().to_string();
        assert_eq!(e(Reason::NotThePreparer), "not_the_preparer");
        assert_eq!(e(Reason::ApprovalInvalid), "task_approval_invalid");
        assert_eq!(e(Reason::NoPaymentKey), "task_no_payment_key");
        assert_eq!(e(Reason::NotTheOwner), "not_the_owner");
    }

    #[test]
    fn a_task_opened_instead_of_acting_is_answered_as_awaiting_the_owner() {
        let opened = Opened { id: "run-0".into(), hash: "ab".repeat(32), thread: "run-0".into(), expires_at: 9, devices: 1 };
        let answer = awaiting_owner(&opened);
        assert_eq!(answer["status"], "awaiting_owner");
        assert_eq!(answer["task_id"], "run-0");
        assert_eq!(answer["link"], "https://app.outlayer.ai/inbox/run-0");
    }

    #[test]
    fn a_notice_names_no_operation_and_is_answered_as_notified() {
        let task = notice(Display::new("Sent"), b"{}").file("a.txt", "text/plain", b"a");
        assert_eq!(task.request.kind, TaskKind::Notice);
        assert!(task.request.answer_by.is_none() && task.request.state.is_empty());
        assert_eq!(task.request.files.len(), 1);
        let asked = confirm(Display::new("Send"), "confirm", b"s", b"{}");
        assert_eq!(asked.request.answer_by.as_ref().map(|by| by.operation.as_str()), Some("confirm"));
        let opened = Opened { id: "run-0".into(), hash: "cd".repeat(32), thread: "run-0".into(), expires_at: 9, devices: 1 };
        let told = notified(&opened);
        assert_eq!((told["status"].as_str(), told["task_id"].as_str()), (Some("notified"), Some("run-0")));
        assert_eq!(told["task_hash"], "cd".repeat(32));
        assert_eq!(kind_name(TaskKind::Notice), "notice");
        assert_eq!(outcome_json(&Outcome { kind: TaskKind::Notice, ..outcome(TaskState::Done) })["kind"], "notice");
    }

    #[test]
    fn an_operation_of_the_projects_own_is_not_dispatched() {
        assert!(dispatch("send", &serde_json::json!({})).is_none());
        assert!(OPERATIONS.iter().all(|op| *op != "send"));
    }
}
