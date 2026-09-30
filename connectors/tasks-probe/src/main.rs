//! A project that does nothing useful with tasks, so that everything AROUND a
//! task can be tested: who may open one, what the owner's page reads, what an
//! answer hands back, what the preparer learns.
//!
//! It acts on nothing outside the platform. What a real connector would send
//! or pay, this one echoes: the `state` it sealed when it made the task comes
//! back in the result, so a test sees that what was prepared is what was
//! acted on.
//!
//! | `operation` | Who | What it does |
//! |---|---|---|
//! | `prepare` | agent | opens a task from `title`, `body`, `kind` (`confirm`, `text`, `file`), `life_seconds`, and `files` (`[{name, content_type, text}]`); answers `awaiting_owner`. `answer_by` names the operation that answers a `confirm` task: `confirm` when it is not named, `confirm_slow`, `confirm_silent` or `confirm_trap` |
//! | `prepare_many` | agent | opens `count` tasks (1 to 10) in one run, each as `prepare` makes it, and stops at the first that is refused; answers the tasks opened and the refusal |
//! | `prepare_raw` | agent | opens a task whose display is `display` as given — for a display outside the bounds |
//! | `confirm` | owner | answers a `confirm` task and reports what was prepared |
//! | `supply` | owner | answers a `text` or `file` task and reports what was supplied; with `"again": true` in the prepared body, opens the next task of the conversation |
//! | `confirm_slow` | owner | answers a task that names it, waits `seconds` (1 to 170), then reports what was prepared |
//! | `confirm_silent` | owner | answers a task that names it, and reports nothing: the task ends `failed` |
//! | `confirm_trap` | owner | answers a task that names it, reports, and traps: the task ends `failed` |
//! | `task_status`, `task_cancel`, `task_delete`, `tasks`, `tasks_unlock` | | the SDK's own |
//!
//! The policy is the `TASKS_PROBE_POLICY` secret of the owner's row, as it is
//! at the moment of the run: a test changes it between a task and its answer
//! to see the task void.

use outlayer::tasks::{self, Display, FieldKind, Reason, Supplies, WrittenBy};
use std::time::{Duration, Instant};
use serde_json::{json, Value};

#[used]
#[link_section = "outlayer.manifest"]
static OUTLAYER_MANIFEST: [u8; include_bytes!("../manifest.json").len()] = *include_bytes!("../manifest.json");

const POLICY_ENV: &str = "TASKS_PROBE_POLICY";

const OPERATIONS: &[&str] = &[
    "prepare",
    "prepare_many",
    "prepare_raw",
    "confirm",
    "confirm_slow",
    "supply",
    "confirm_silent",
    "confirm_trap",
    "task_status",
    "task_cancel",
    "task_delete",
    "tasks",
    "tasks_unlock",
];

/// The operations of this project that answer a `confirm` task.
const ANSWER_BY: &[&str] = &["confirm", "confirm_slow", "confirm_silent", "confirm_trap"];

/// The most tasks one call of `prepare_many` asks for: over what one run may
/// open, so the refusal of the run's limit is within reach.
const MAX_COUNT: u64 = 10;

/// The longest `confirm_slow` waits: under the longest run the platform gives.
const MAX_SLOW_SECONDS: u64 = 170;

fn policy() -> Vec<u8> {
    std::env::var(POLICY_ENV).unwrap_or_default().into_bytes()
}

fn text<'a>(input: &'a Value, member: &str, otherwise: &'a str) -> &'a str {
    input.get(member).and_then(|v| v.as_str()).unwrap_or(otherwise)
}

fn life(input: &Value) -> u32 {
    input.get("life_seconds").and_then(|v| v.as_u64()).and_then(|v| u32::try_from(v).ok()).unwrap_or(0)
}

fn open(task: tasks::Task, input: &Value) -> Result<Value, String> {
    let opened = task.life_seconds(life(input)).open().map_err(|e| e.refusal())?;
    let mut answer = tasks::awaiting_owner(&opened);
    answer["devices"] = json!(opened.devices);
    Ok(answer)
}

/// The task `prepare` makes of a call. `number` is the task's place among the
/// tasks of a call that makes several: shown to the owner, and sealed.
fn task_of(input: &Value, number: Option<(u64, u64)>) -> Result<tasks::Task, String> {
    let body = text(input, "body", "a prepared body");
    let mut display = Display::new(text(input, "title", "Tasks probe"))
        .field("Body", FieldKind::LongText, body, WrittenBy::Agent)
        .field("Prepared by", FieldKind::Text, "tasks-probe", WrittenBy::Project);
    let mut state = json!({ "body": body, "again": input.get("again").and_then(|v| v.as_bool()).unwrap_or(false) });
    if let Some((number, of)) = number {
        display = display.field("Number", FieldKind::Text, &format!("{number} of {of}"), WrittenBy::Project);
        state["number"] = json!(number);
    }
    let state = state.to_string();
    let kind = text(input, "kind", "confirm");
    let answer_by = match input.get("answer_by") {
        None | Some(Value::Null) => "confirm",
        Some(named) => match named.as_str().filter(|name| ANSWER_BY.contains(name)) {
            Some(name) if kind == "confirm" => name,
            Some(_) => return Err("invalid_request: `answer_by` is named for a `confirm` task; a `text` or `file` task is answered by `supply`".to_string()),
            None => return Err(format!("invalid_request: `answer_by` is one of {}, not `{named}`", ANSWER_BY.join(", "))),
        },
    };
    let mut task = match kind {
        "confirm" => tasks::confirm(display, answer_by, state.as_bytes(), &policy()),
        "text" => tasks::input(display, "supply", Supplies::Text, state.as_bytes(), &policy()),
        "file" => tasks::input(display, "supply", Supplies::File, state.as_bytes(), &policy()),
        other => return Err(format!("invalid_request: `kind` is `confirm`, `text` or `file`, not `{other}`")),
    };
    for file in input.get("files").and_then(|f| f.as_array()).into_iter().flatten() {
        // `repeat` makes a file of a size a test asks for without sending it.
        let repeat = file.get("repeat").and_then(|r| r.as_u64()).unwrap_or(1) as usize;
        let data = text(file, "text", "").repeat(repeat);
        task = task.file(text(file, "name", ""), text(file, "content_type", "text/plain"), data.as_bytes());
    }
    Ok(task)
}

fn prepare(input: &Value) -> Result<Value, String> {
    open(task_of(input, None)?, input)
}

/// `count` tasks in one run. A refusal ends the call where it met it and is
/// answered beside the tasks opened before it, as a success: the refusal is
/// what a test of a limit reads.
fn prepare_many(input: &Value) -> Result<Value, String> {
    let count = input
        .get("count")
        .and_then(|v| v.as_u64())
        .filter(|count| (1..=MAX_COUNT).contains(count))
        .ok_or_else(|| format!("invalid_request: `count` is a whole number from 1 to {MAX_COUNT}"))?;
    let mut opened = Vec::new();
    let mut refused = Value::Null;
    for number in 1..=count {
        match open(task_of(input, Some((number, count)))?, input) {
            Ok(task) => opened.push(task),
            Err(refusal) => {
                let code = refusal.split(':').next().unwrap_or_default().to_string();
                refused = json!({ "number": number, "code": code, "error": refusal });
                break;
            }
        }
    }
    let status = if opened.is_empty() { "refused" } else { "awaiting_owner" };
    Ok(json!({ "status": status, "asked": count, "opened": opened.len(), "tasks": opened, "refused": refused }))
}

fn field_kind(name: &str) -> Option<FieldKind> {
    Some(match name {
        "money" => FieldKind::Money,
        "account" => FieldKind::Account,
        "address" => FieldKind::Address,
        "text" => FieldKind::Text,
        "long_text" => FieldKind::LongText,
        "list" => FieldKind::List,
        _ => return None,
    })
}

/// A display as the call spells it, handed to the host as it is: the bounds
/// are the host's to refuse, not this project's.
fn prepare_raw(input: &Value) -> Result<Value, String> {
    let shown = input.get("display").ok_or("invalid_request: the call names no `display`")?;
    let mut display = Display::new(text(shown, "title", ""));
    for field in shown.get("fields").and_then(|f| f.as_array()).into_iter().flatten() {
        let label = text(field, "label", "");
        let kind = field_kind(text(field, "kind", "text"))
            .ok_or_else(|| format!("display_invalid: `{}` is no kind of field", text(field, "kind", "")))?;
        let values: Vec<&str> = match field.get("values").and_then(|v| v.as_array()) {
            Some(values) => values.iter().filter_map(|v| v.as_str()).collect(),
            None => field.get("value").and_then(|v| v.as_str()).into_iter().collect(),
        };
        display = match (kind, values.as_slice()) {
            (FieldKind::List, values) => display.list(label, values, WrittenBy::Agent),
            (kind, [one]) => display.field(label, kind, one, WrittenBy::Agent),
            // More than one value in a field of one, or none: handed over as
            // a list of that many, which the host refuses by its own rule.
            (_, values) => display.list(label, values, WrittenBy::Agent),
        };
    }
    let state = input.get("state").and_then(|v| v.as_str()).unwrap_or("").as_bytes().to_vec();
    open(tasks::confirm(display, text(input, "answer_by", "confirm"), &state, &policy()), input)
}

fn prepared(answer: &tasks::Answer) -> Value {
    serde_json::from_slice(&answer.state).unwrap_or_else(|_| json!(String::from_utf8_lossy(&answer.state)))
}

fn confirm(input: &Value) -> Result<Value, String> {
    let answer = tasks::answered_for("confirm", input, &policy()).map_err(|e| e.refusal())?;
    let files: Vec<Value> = answer
        .files
        .iter()
        .map(|f| json!({ "name": f.name, "content_type": f.content_type, "bytes": f.data.len(), "starts": String::from_utf8_lossy(&f.data[..f.data.len().min(16)]) }))
        .collect();
    let result = json!({ "acted_on": prepared(&answer), "prepared_by": answer.preparer, "files": files });
    tasks::report(&answer.id, result.to_string().as_bytes()).map_err(|e| e.refusal())?;
    Ok(json!({ "status": "done", "task_id": answer.id, "thread": answer.thread, "result": result }))
}

fn supply(input: &Value) -> Result<Value, String> {
    let answer = tasks::answered_for("supply", input, &policy()).map_err(|e| e.refusal())?;
    let supplied = answer.supplied.as_deref().map(|s| String::from_utf8_lossy(s).into_owned());
    let prepared = prepared(&answer);
    let result = json!({ "acted_on": prepared, "supplied": supplied, "prepared_by": answer.preparer });
    tasks::report(&answer.id, result.to_string().as_bytes()).map_err(|e| e.refusal())?;
    let mut out = json!({ "status": "done", "task_id": answer.id, "thread": answer.thread, "result": result });
    if prepared.get("again").and_then(|v| v.as_bool()) == Some(true) {
        let display = Display::new("Tasks probe: one more")
            .field("Received", FieldKind::Text, supplied.as_deref().unwrap_or(""), WrittenBy::Project);
        let next = tasks::input(display, "supply", Supplies::Text, br#"{"body":"the next turn","again":false}"#, &policy());
        out["next"] = open(next, input)?;
    }
    Ok(out)
}

/// Waits on the platform's clock: a wait is a host call, which spends the
/// run's seconds and none of its instructions. Asked in slices, and counted
/// by the clock rather than by the slices.
fn wait(seconds: u64) -> Duration {
    let (started, whole) = (Instant::now(), Duration::from_secs(seconds));
    loop {
        match whole.checked_sub(started.elapsed()) {
            Some(left) if !left.is_zero() => std::thread::sleep(left.min(Duration::from_millis(250))),
            _ => return started.elapsed(),
        }
    }
}

fn confirm_slow(input: &Value) -> Result<Value, String> {
    // Read before the answer is taken: a call that names no time leaves the
    // task open.
    let seconds = input
        .get("seconds")
        .and_then(|v| v.as_u64())
        .filter(|seconds| (1..=MAX_SLOW_SECONDS).contains(seconds))
        .ok_or_else(|| format!("invalid_request: `seconds` is a whole number from 1 to {MAX_SLOW_SECONDS}"))?;
    let answer = tasks::answered_for("confirm_slow", input, &policy()).map_err(|e| e.refusal())?;
    let worked = wait(seconds);
    let result = json!({ "acted_on": prepared(&answer), "prepared_by": answer.preparer, "worked_ms": worked.as_millis() as u64 });
    tasks::report(&answer.id, result.to_string().as_bytes()).map_err(|e| e.refusal())?;
    Ok(json!({ "status": "done", "task_id": answer.id, "thread": answer.thread, "result": result }))
}

/// The owner's answer to a task that names `own`: the host holds the answer
/// to the operation the call runs, so a task made for `confirm` is answered
/// by `confirm` and by no other.
fn answered_as(own: &str, input: &Value) -> Result<tasks::Answer, String> {
    tasks::answered_for(own, input, &policy()).map_err(|e| e.refusal())
}

fn confirm_silent(input: &Value) -> Result<Value, String> {
    let answer = answered_as("confirm_silent", input)?;
    Ok(json!({ "status": "answered_and_not_reported", "task_id": answer.id }))
}

fn confirm_trap(input: &Value) -> Result<Value, String> {
    let answer = answered_as("confirm_trap", input)?;
    tasks::report(&answer.id, b"reported before the trap").map_err(|e| e.refusal())?;
    panic!("tasks-probe: a trap after the task was answered");
}

fn run(operation: &str, input: &Value) -> Result<Value, String> {
    if let Some(answer) = tasks::dispatch(operation, input) {
        return answer;
    }
    match operation {
        "prepare" => prepare(input),
        "prepare_many" => prepare_many(input),
        "prepare_raw" => prepare_raw(input),
        "confirm" => confirm(input),
        "confirm_slow" => confirm_slow(input),
        "supply" => supply(input),
        "confirm_silent" => confirm_silent(input),
        "confirm_trap" => confirm_trap(input),
        other => Err(format!("unknown_operation: `{other}` is not one of {}", OPERATIONS.join(", "))),
    }
}

fn main() {
    let input: Value = outlayer::env::input_json::<Value>().ok().flatten().unwrap_or_else(|| json!({}));
    let operation = text(&input, "operation", "").to_string();
    let answer = match run(&operation, &input) {
        Ok(output) => json!({ "success": true, "output": output, "logs": [], "error": null }),
        Err(refusal) => json!({ "success": false, "output": null, "logs": [], "error": refusal }),
    };
    // An error is reported by answering, never by a non-zero exit.
    let _ = outlayer::env::output_json(&answer);
}
