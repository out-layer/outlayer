//! Tasks between an agent and its owner
//!
//! An agent's run prepares; the owner reads and acts with a call of their
//! own. A run admitted to an owner's secret row leaves that owner a task —
//! "confirm this email", "give me your photo" — and the owner answers it by
//! calling an operation of the same project. Nothing waits inside a run: a
//! task is a record the platform keeps sealed.
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
//!     "confirm",          // the operation the owner calls
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
//! The operation named in the task is called by the owner's page with the
//! task's `task_id` and `task_hash`, and `supplied` when the task asked for
//! something:
//!
//! ```rust,ignore
//! let answer = tasks::answered_for("confirm", &input, policy_json.as_bytes())?;
//! let sent = send(&answer.state)?;          // today's limits; the policy is the one the task was made under
//! tasks::report(&answer.id, sent.to_string().as_bytes())?;
//! ```
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
    Answer, FieldKind, File, Opened, Outcome, Reason, Supplies, TaskKind, TaskState, WrittenBy,
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
    fn new(kind: TaskKind, display: Display, operation: &str, supplies: Supplies, state: &[u8], policy: &[u8]) -> Self {
        Self {
            request: raw::Request {
                kind,
                display: raw::Display { title: display.title, fields: display.fields },
                answer_by: raw::AnswerBy { operation: operation.to_string(), supplies },
                files: Vec::new(),
                state: state.to_vec(),
                policy: policy.to_vec(),
                life_seconds: 0,
            },
        }
    }

    /// How long the task waits, at most [`MAX_LIFE_SECS`]. Without it, that
    /// long. A task whose action depends on a price takes a short life.
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

    /// Open it for the owner of the secret row this run was admitted to.
    pub fn open(self) -> Result<Opened> {
        raw::open(&self.request).map_err(TaskError::from)
    }
}

/// A task the owner answers yes or no. `operation` is the operation of this
/// project the owner calls to say yes; `state` is handed back to it and never
/// shown; `policy` is the policy the task is made under, as the project reads
/// it.
pub fn confirm(display: Display, operation: &str, state: &[u8], policy: &[u8]) -> Task {
    Task::new(TaskKind::Confirm, display, operation, Supplies::Nothing, state, policy)
}

/// A task the owner answers by supplying something: [`Supplies::Text`], or
/// [`Supplies::File`] — a reference to a file and its hash.
pub fn input(display: Display, operation: &str, supplies: Supplies, state: &[u8], policy: &[u8]) -> Task {
    Task::new(TaskKind::Input, display, operation, supplies, state, policy)
}

/// The tasks this caller made in this project for this owner.
pub fn mine() -> Result<Vec<Outcome>> {
    raw::mine().map_err(TaskError::from)
}

/// One of them.
pub fn status(id: &str) -> Result<Outcome> {
    raw::status(id).map_err(TaskError::from)
}

/// Take the owner's answer to a task, in `operation` — the operation now
/// running; a task that names another to answer by is refused and stays
/// open. `policy` is the policy as the project reads it now; `supplied` what
/// the owner's page sent.
///
/// On `Ok` the task is `answering` under this run. Act, then [`report`].
pub fn answered(id: &str, hash: &str, operation: &str, policy: &[u8], supplied: Option<&[u8]>) -> Result<Answer> {
    raw::answered(id, hash, operation, policy, supplied).map_err(TaskError::from)
}

/// Leave `result` for the preparer of a task this run answered. The task is
/// `done` when the run ends as a success; a task answered and not reported on
/// is `failed`.
pub fn report(id: &str, result: &[u8]) -> Result<()> {
    raw::report(id, result).map_err(TaskError::from)
}

/// Withdraw an open task this caller made.
pub fn cancel(id: &str) -> Result<()> {
    raw::cancel(id).map_err(TaskError::from)
}

/// Delete a task this caller made, in any state.
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

/// Take the owner's answer as the owner's page sends it: `task_id` and
/// `task_hash`, and `supplied` (base64) when the task asked for something.
/// `operation` is the operation now running.
pub fn answered_for(operation: &str, input: &serde_json::Value, policy: &[u8]) -> Result<Answer> {
    let id = text_of(input, "task_id")?;
    let hash = text_of(input, "task_hash")?;
    let supplied = match input.get("supplied") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(text)) => {
            Some(from_base64(text).ok_or_else(|| invalid("`supplied` is not base64"))?)
        }
        Some(_) => return Err(invalid("`supplied` is not a string")),
    };
    answered(id, hash, operation, policy, supplied.as_deref())
}

fn kind_name(kind: TaskKind) -> &'static str {
    match kind {
        TaskKind::Confirm => "confirm",
        TaskKind::Input => "input",
    }
}

/// A state as a project's answer spells it.
pub fn state_name(state: TaskState) -> &'static str {
    match state {
        TaskState::Open => "open",
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
/// outcome later with `task_status`.
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
/// | `task_status` | `task_id` | the task: `state`, and `result`, `reason`, `run` when it has them |
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
    use super::*;

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
    fn an_operation_of_the_projects_own_is_not_dispatched() {
        assert!(dispatch("send", &serde_json::json!({})).is_none());
        assert!(OPERATIONS.iter().all(|op| *op != "send"));
    }
}
