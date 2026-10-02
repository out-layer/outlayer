//! The task store, as the host reaches it: the coordinator's
//! `/owner-tasks/*` routes, behind the worker's token.
//!
//! The store holds ciphertext and moves states; it is trusted to be there,
//! not to be right. What it returns of a task is checked by the host against
//! what is sealed inside it.
//!
//! A refusal the store gives by name is [`StoreError::Refused`]; everything
//! else — no answer, another status, a body that cannot be read, a reason
//! this host does not know — is [`StoreError::Unavailable`], never an absence.

use base64::Engine;
use serde::{Deserialize, Serialize};

use super::statement::DeviceStatement;
use super::StoreConfig;

/// A state as the store names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Open,
    Approved,
    Answering,
    Done,
    Failed,
    Rejected,
    Cancelled,
    Expired,
    Void,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Confirm,
    Input,
    Notice,
}

/// Why the store refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Refusal {
    NotFound,
    Muted,
    /// The owner's limit of open tasks.
    InboxFull,
    /// This preparer's share of it.
    PreparerFull,
    /// The owner's waiting tasks hold as much as they may together.
    StorageFull,
    Exists,
    Closed,
    Expired,
    LifeTooLong,
    InvalidRequest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// The store's own refusal, with the state it found the task in when
    /// that is why.
    Refused(Refusal, Option<State>),
    /// No usable answer.
    Unavailable(String),
}

/// The project and the owner a run was admitted for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    pub project_uuid: String,
    pub owner: String,
}

/// A task's content key wrapped to one device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Copy {
    pub device_id: String,
    pub wrapped_key: Vec<u8>,
}

/// The preparer's consent as the store keeps it in the clear: which payment
/// key to charge for the run that carries the task out, and how to start it.
/// Nothing in it is a secret; the enclave holds the same facts sealed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Voucher {
    pub payment_key_nonce: u32,
    pub wallet_id: Option<String>,
    pub bound_identity: bool,
    pub compute_limit_usd: String,
    /// `answer_by.operation`: the operation the run is started in.
    pub operation: String,
    /// The build that made the task: the version pinned where the platform
    /// pins one.
    pub build: String,
}

/// A task to store.
#[derive(Debug, Clone)]
pub struct NewTask {
    pub id: String,
    pub project_id: String,
    pub preparer: String,
    /// Absent for a notice, which no run follows.
    pub voucher: Option<Voucher>,
    /// The profile of the owner's secret row the run named.
    pub profile: String,
    /// The vault that row is bound to, whose master seals the task.
    pub vault: Option<String>,
    pub kind: Kind,
    /// Unix seconds.
    pub expires_at: u64,
    /// Absent for a notice, which takes nothing back.
    pub reply_pubkey: Option<String>,
    pub sealed: Vec<u8>,
    pub content: Vec<u8>,
    /// The task's files under its content key, in order.
    pub files: Vec<Vec<u8>>,
    pub copies: Vec<Copy>,
}

/// A task as its preparer's run reads it.
#[derive(Debug, Clone, Deserialize)]
pub struct Prepared {
    pub id: String,
    pub kind: Kind,
    pub state: State,
    pub created_at: i64,
    pub expires_at: i64,
    #[serde(default)]
    pub run: Option<String>,
    #[serde(default, deserialize_with = "b64_opt")]
    pub outcome: Option<Vec<u8>>,
    #[serde(default, deserialize_with = "b64_opt")]
    pub rejection: Option<Vec<u8>>,
    #[serde(default)]
    pub failure_reason: Option<String>,
}

/// A task as the run that carries it out reads it.
#[derive(Debug, Clone, Deserialize)]
pub struct Stored {
    pub id: String,
    pub preparer: String,
    pub kind: Kind,
    pub state: State,
    pub expires_at: i64,
    #[serde(default, deserialize_with = "b64_opt")]
    pub sealed: Option<Vec<u8>>,
    /// The task's files as they are stored, in order; with one task read for
    /// its answer, and empty in a list of tasks.
    #[serde(default, deserialize_with = "b64_list")]
    pub files: Vec<Vec<u8>>,
}

fn b64_list<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Vec<Vec<u8>>, D::Error> {
    Vec::<String>::deserialize(deserializer)?
        .into_iter()
        .map(|text| base64::engine::general_purpose::STANDARD.decode(text.as_bytes()).map_err(serde::de::Error::custom))
        .collect()
}

fn b64_opt<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error> {
    match Option::<String>::deserialize(deserializer)? {
        Some(text) => base64::engine::general_purpose::STANDARD
            .decode(text.as_bytes())
            .map(Some)
            .map_err(serde::de::Error::custom),
        None => Ok(None),
    }
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// The store.
pub trait Store {
    fn devices(&self, owner: &str) -> Result<Vec<DeviceStatement>, StoreError>;
    /// Open a task; answers how many of its copies were written. A copy for
    /// a device that left since the devices were read is not written.
    fn open(&self, scope: &Scope, task: &NewTask) -> Result<u64, StoreError>;
    /// The preparer's tasks; with `id`, that one or `NotFound`.
    fn mine(&self, scope: &Scope, preparer: &str, id: Option<&str>) -> Result<Vec<Prepared>, StoreError>;
    fn get(&self, scope: &Scope, id: &str) -> Result<Stored, StoreError>;
    fn waiting(&self, scope: &Scope) -> Result<Vec<Stored>, StoreError>;
    /// Write copies of waiting tasks; answers how many were written, and of
    /// how many tasks.
    fn copies(&self, scope: &Scope, tasks: &[(String, Vec<Copy>)]) -> Result<Written, StoreError>;
    fn answer(&self, scope: &Scope, id: &str, run: &str) -> Result<(), StoreError>;
    fn void(&self, scope: &Scope, id: &str) -> Result<(), StoreError>;
    fn cancel(&self, scope: &Scope, preparer: &str, id: &str) -> Result<(), StoreError>;
    fn delete(&self, scope: &Scope, preparer: &str, id: &str) -> Result<(), StoreError>;
}

/// The store over HTTP.
pub struct HttpStore {
    client: reqwest::blocking::Client,
    config: StoreConfig,
    /// Most bytes of an answer that are read: [`MAX_ANSWER_BYTES`].
    most_answer: usize,
}

#[derive(Deserialize)]
struct RefusalBody {
    reason: Refusal,
    #[serde(default)]
    state: Option<State>,
    /// What the store says was wrong with the request. For this worker's
    /// log: it names a field of the request, nothing of a task.
    #[serde(default)]
    message: Option<String>,
}

/// Most bytes of one answer of the store that are read. The largest answers
/// the store gives within its own limits, as base64 (4 bytes for 3) in JSON,
/// with 512 bytes a task for what is around the base64 — ids, states, times,
/// the punctuation of JSON:
///
/// * the owner's waiting tasks: 20 open tasks of one owner, the sealed copy
///   of each 1 MiB at most — 20 × (1 398 104 + 512) = 27 972 320 bytes;
/// * a preparer's tasks: a list of 200, each an outcome of 32 KiB and a
///   reason of 8 KiB at most — 200 × (43 692 + 10 924 + 512) = 11 025 600
///   bytes;
/// * one task read for its answer: a sealed copy of 1 MiB and ten files of
///   6 MiB and 1 KiB together, each padded on its own —
///   1 398 104 + 8 390 016 + 512 = 9 788 632 bytes.
///
/// The largest is 27 972 320 bytes; 32 MiB, 33 554 432, is above it.
pub const MAX_ANSWER_BYTES: usize = 32 * 1024 * 1024;

fn over_the_bound(most: usize) -> StoreError {
    StoreError::Unavailable(format!("the task store's answer is over {most} bytes"))
}

fn cut_short() -> StoreError {
    StoreError::Unavailable("the task store's answer was cut short".to_string())
}

/// The body of an answer, read to its end and no further than `most` bytes.
fn body_within(response: reqwest::blocking::Response, most: usize) -> Result<Vec<u8>, StoreError> {
    use std::io::Read;
    if response.content_length().is_some_and(|length| length > most as u64) {
        return Err(over_the_bound(most));
    }
    let mut body = Vec::new();
    // One byte past the bound tells an answer at the bound from one over it.
    response.take(most as u64 + 1).read_to_end(&mut body).map_err(|_| cut_short())?;
    match body.len() > most {
        true => Err(over_the_bound(most)),
        false => Ok(body),
    }
}

/// [`body_within`], for the job path's client.
async fn body_within_async(mut response: reqwest::Response, most: usize) -> Result<Vec<u8>, StoreError> {
    if response.content_length().is_some_and(|length| length > most as u64) {
        return Err(over_the_bound(most));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| cut_short())? {
        if body.len() + chunk.len() > most {
            return Err(over_the_bound(most));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Read a status and a body as the store's answer.
fn read<T: serde::de::DeserializeOwned>(status: u16, body: &[u8]) -> Result<T, StoreError> {
    match status {
        200 => serde_json::from_slice(body)
            .map_err(|_| StoreError::Unavailable("the task store's answer could not be read".to_string())),
        400 | 404 | 409 => match serde_json::from_slice::<RefusalBody>(body) {
            Ok(refusal) => {
                if let Some(said) = refusal.message.as_deref() {
                    tracing::warn!(status, "the task store refused a request: {}", said.chars().take(200).collect::<String>());
                }
                Err(StoreError::Refused(refusal.reason, refusal.state))
            }
            Err(_) => Err(StoreError::Unavailable(format!("the task store answered {status} without a reason"))),
        },
        // A request the store could not read at all (413, 415, 422) is this
        // host's fault and will not read better the next time.
        413 | 415 | 422 => {
            tracing::error!(status, "the task store could not read a request of this host");
            Err(StoreError::Refused(Refusal::InvalidRequest, None))
        }
        other => Err(StoreError::Unavailable(format!("the task store answered {other}"))),
    }
}

impl HttpStore {
    pub fn new(config: StoreConfig) -> Result<Self, StoreError> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .connect_timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(|_| StoreError::Unavailable("no client for the task store could be made".to_string()))?;
        Ok(Self { client, config, most_answer: MAX_ANSWER_BYTES })
    }

    fn post<T: serde::de::DeserializeOwned>(&self, path: &str, body: serde_json::Value) -> Result<T, StoreError> {
        let response = self
            .client
            .post(format!("{}{path}", self.config.coordinator_url))
            .header("Authorization", format!("Bearer {}", self.config.coordinator_token))
            .json(&body)
            .send()
            .map_err(|_| StoreError::Unavailable("the task store did not answer".to_string()))?;
        let status = response.status().as_u16();
        read(status, &body_within(response, self.most_answer)?)
    }
}

fn copies_json(copies: &[Copy]) -> Vec<serde_json::Value> {
    copies
        .iter()
        .map(|c| serde_json::json!({ "device_id": c.device_id, "wrapped_key": b64(&c.wrapped_key) }))
        .collect()
}

#[derive(Deserialize)]
struct Devices {
    devices: Vec<DeviceStatement>,
}

#[derive(Deserialize)]
struct PreparedTasks {
    tasks: Vec<Prepared>,
}

#[derive(Deserialize)]
struct StoredTasks {
    tasks: Vec<Stored>,
}

/// An answer whose members this host does not need.
#[derive(Deserialize)]
struct Acknowledged {}

#[derive(Deserialize)]
struct OpenedTask {
    copies: u64,
}

/// What the store wrote of the copies asked for.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
pub struct Written {
    /// Copies written.
    #[serde(rename = "written")]
    pub copies: u64,
    /// Tasks that got at least one.
    pub tasks: u64,
}

impl Store for HttpStore {
    fn devices(&self, owner: &str) -> Result<Vec<DeviceStatement>, StoreError> {
        self.post::<Devices>("/owner-tasks/devices", serde_json::json!({ "owner": owner })).map(|d| d.devices)
    }

    fn open(&self, scope: &Scope, task: &NewTask) -> Result<u64, StoreError> {
        self.post::<OpenedTask>(
            "/owner-tasks/open",
            serde_json::json!({
                "project_uuid": scope.project_uuid,
                "owner": scope.owner,
                "id": task.id,
                "project_id": task.project_id,
                "preparer": task.preparer,
                "voucher": task.voucher,
                "profile": task.profile,
                "vault": task.vault,
                "kind": task.kind,
                "expires_at": task.expires_at,
                "reply_pubkey": task.reply_pubkey,
                "sealed": b64(&task.sealed),
                "content": b64(&task.content),
                "files": task.files.iter().map(|f| b64(f)).collect::<Vec<_>>(),
                "copies": copies_json(&task.copies),
            }),
        )
        .map(|opened| opened.copies)
    }

    fn mine(&self, scope: &Scope, preparer: &str, id: Option<&str>) -> Result<Vec<Prepared>, StoreError> {
        self.post::<PreparedTasks>(
            "/owner-tasks/mine",
            serde_json::json!({
                "project_uuid": scope.project_uuid, "owner": scope.owner, "preparer": preparer, "id": id,
            }),
        )
        .map(|t| t.tasks)
    }

    fn get(&self, scope: &Scope, id: &str) -> Result<Stored, StoreError> {
        self.post(
            "/owner-tasks/get",
            serde_json::json!({ "project_uuid": scope.project_uuid, "owner": scope.owner, "id": id }),
        )
    }

    fn waiting(&self, scope: &Scope) -> Result<Vec<Stored>, StoreError> {
        self.post::<StoredTasks>(
            "/owner-tasks/waiting",
            serde_json::json!({ "project_uuid": scope.project_uuid, "owner": scope.owner }),
        )
        .map(|t| t.tasks)
    }

    fn copies(&self, scope: &Scope, tasks: &[(String, Vec<Copy>)]) -> Result<Written, StoreError> {
        let tasks: Vec<_> = tasks
            .iter()
            .map(|(id, copies)| serde_json::json!({ "id": id, "copies": copies_json(copies) }))
            .collect();
        self.post::<Written>(
            "/owner-tasks/copies",
            serde_json::json!({ "project_uuid": scope.project_uuid, "owner": scope.owner, "tasks": tasks }),
        )

    }

    fn answer(&self, scope: &Scope, id: &str, run: &str) -> Result<(), StoreError> {
        self.post::<Acknowledged>(
            "/owner-tasks/answer",
            serde_json::json!({ "project_uuid": scope.project_uuid, "owner": scope.owner, "id": id, "run": run }),
        )
        .map(|_| ())
    }

    fn void(&self, scope: &Scope, id: &str) -> Result<(), StoreError> {
        self.post::<Acknowledged>(
            "/owner-tasks/void",
            serde_json::json!({ "project_uuid": scope.project_uuid, "owner": scope.owner, "id": id }),
        )
        .map(|_| ())
    }

    fn cancel(&self, scope: &Scope, preparer: &str, id: &str) -> Result<(), StoreError> {
        self.post::<Acknowledged>(
            "/owner-tasks/cancel",
            serde_json::json!({
                "project_uuid": scope.project_uuid, "owner": scope.owner, "preparer": preparer, "id": id,
            }),
        )
        .map(|_| ())
    }

    fn delete(&self, scope: &Scope, preparer: &str, id: &str) -> Result<(), StoreError> {
        self.post::<Acknowledged>(
            "/owner-tasks/delete",
            serde_json::json!({
                "project_uuid": scope.project_uuid, "owner": scope.owner, "preparer": preparer, "id": id,
            }),
        )
        .map(|_| ())
    }
}

/// What became of the tasks a run answered, as the store counted them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct Finished {
    pub done: u64,
    pub failed: u64,
}

/// Tell the store the run that acted has ended: a task it reported on, in a
/// run that succeeded, is `done`; every other task it answered is `failed`;
/// an approved task it was refused is `failed` with the reason. Called by
/// the job path after the guest exits, however it exited.
pub async fn finish(
    config: &StoreConfig,
    scope: &Scope,
    run: &str,
    success: bool,
    answered: &[super::Answered],
    refused: &[super::Refused],
) -> Result<Finished, StoreError> {
    let reported: Vec<_> = answered
        .iter()
        .filter_map(|task| task.outcome.as_ref().map(|outcome| serde_json::json!({ "id": task.id, "outcome": b64(outcome) })))
        .collect();
    let refused: Vec<_> =
        refused.iter().map(|task| serde_json::json!({ "id": task.id, "reason": task.reason })).collect();
    let body = serde_json::json!({
        "project_uuid": scope.project_uuid,
        "owner": scope.owner,
        "run": run,
        "success": success,
        "reported": reported,
        "refused": refused,
    });
    finish_within(config, body, run, MAX_ANSWER_BYTES).await
}

async fn finish_within(
    config: &StoreConfig,
    body: serde_json::Value,
    run: &str,
    most_answer: usize,
) -> Result<Finished, StoreError> {
    let client = reqwest::Client::new();
    // The report is what makes an action that happened read as `done`: a
    // store that did not answer is asked again, at once, before the call is
    // said to be over. The report is the same each time, and a second one
    // after a first that arrived changes nothing.
    let mut last = StoreError::Unavailable("the task store was not asked".to_string());
    for attempt in 1..=FINISH_ATTEMPTS {
        match finish_once(&client, config, &body, most_answer).await {
            Err(StoreError::Unavailable(why)) => {
                tracing::warn!(run = %run, attempt, "the run's report did not reach the task store: {why}");
                last = StoreError::Unavailable(why);
            }
            answered => return answered,
        }
    }
    Err(last)
}

/// How many times a run's report is sent before it is given up.
pub const FINISH_ATTEMPTS: u32 = 3;

async fn finish_once(
    client: &reqwest::Client,
    config: &StoreConfig,
    body: &serde_json::Value,
    most_answer: usize,
) -> Result<Finished, StoreError> {
    let response = client
        .post(format!("{}/owner-tasks/finish", config.coordinator_url))
        .header("Authorization", format!("Bearer {}", config.coordinator_token))
        .timeout(std::time::Duration::from_secs(10))
        .json(body)
        .send()
        .await
        .map_err(|_| StoreError::Unavailable("the task store did not answer".to_string()))?;
    let status = response.status().as_u16();
    read(status, &body_within_async(response, most_answer).await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_answer_is_a_body_a_refusal_by_name_or_no_answer() {
        let tasks: PreparedTasks = read(200, br#"{"tasks":[]}"#).unwrap();
        assert!(tasks.tasks.is_empty(), "nothing is a list of nothing");

        let refused = |status, body: &[u8]| read::<PreparedTasks>(status, body).err().unwrap();
        assert_eq!(refused(404, br#"{"reason":"not_found"}"#), StoreError::Refused(Refusal::NotFound, None));
        assert_eq!(
            refused(409, br#"{"reason":"closed","state":"rejected"}"#),
            StoreError::Refused(Refusal::Closed, Some(State::Rejected))
        );
        assert_eq!(refused(409, br#"{"reason":"inbox_full"}"#), StoreError::Refused(Refusal::InboxFull, None));
        assert_eq!(refused(400, br#"{"reason":"life_too_long"}"#), StoreError::Refused(Refusal::LifeTooLong, None));

        // None of these is "no tasks".
        for (status, body) in [
            (503u16, &b"the database is temporarily unavailable; try again shortly"[..]),
            (500, b"internal error"),
            (401, b""),
            (200, b"not json"),
            (200, br#"{"tasks":[{"id":"t","kind":"confirm","state":"paused","created_at":1,"expires_at":2}]}"#),
            (409, br#"{"reason":"a reason from the future"}"#),
            (404, b""),
        ] {
            assert!(matches!(refused(status, body), StoreError::Unavailable(_)), "{status}");
        }
    }

    #[test]
    fn a_request_the_store_could_not_read_is_a_refusal_that_will_not_read_better() {
        for status in [413u16, 415, 422] {
            for body in [&b""[..], b"Payload Too Large", br#"{"reason":"not_found"}"#] {
                assert_eq!(
                    read::<PreparedTasks>(status, body).err().unwrap(),
                    StoreError::Refused(Refusal::InvalidRequest, None),
                    "{status}"
                );
            }
        }
    }

    #[test]
    fn a_refusal_is_read_with_what_the_store_says_was_wrong() {
        let refused = |status, body: &[u8]| read::<PreparedTasks>(status, body).err().unwrap();
        assert_eq!(
            refused(400, br#"{"reason":"invalid_request","message":"expires_at is not a number"}"#),
            StoreError::Refused(Refusal::InvalidRequest, None)
        );
        assert_eq!(
            refused(409, br#"{"reason":"closed","state":"done","message":"the task is done"}"#),
            StoreError::Refused(Refusal::Closed, Some(State::Done))
        );
        // Longer than is logged, and not only ASCII: read all the same.
        let long = serde_json::json!({ "reason": "storage_full", "message": "й".repeat(5000) }).to_string();
        assert_eq!(refused(409, long.as_bytes()), StoreError::Refused(Refusal::StorageFull, None));
        assert_eq!(
            refused(400, br#"{"reason":"invalid_request","message":null}"#),
            StoreError::Refused(Refusal::InvalidRequest, None)
        );
    }

    /// What the store was sent, one request after another.
    type Seen = std::sync::Arc<std::sync::Mutex<Vec<(String, String, serde_json::Value)>>>;

    /// A store on 127.0.0.1 that answers the requests it gets with `answers`,
    /// in turn, and keeps the path, the `Authorization` header and the body
    /// of each.
    fn store_answering(answers: Vec<(u16, &'static str)>) -> (StoreConfig, Seen) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let config = StoreConfig {
            coordinator_url: format!("http://{}", listener.local_addr().expect("addr")),
            coordinator_token: "the-workers-token".to_string(),
        };
        let seen = Seen::default();
        let kept = seen.clone();
        std::thread::spawn(move || {
            let mut answers = answers.into_iter();
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let (mut data, mut buf) = (Vec::new(), [0u8; 8192]);
                let head_end = loop {
                    match stream.read(&mut buf) {
                        Ok(n) if n > 0 => data.extend_from_slice(&buf[..n]),
                        _ => break None,
                    }
                    if let Some(at) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                        break Some(at + 4);
                    }
                };
                let Some(head_end) = head_end else { continue };
                let head = String::from_utf8_lossy(&data[..head_end]).into_owned();
                let header = |name: &str| {
                    head.lines().find_map(|line| {
                        let (key, value) = line.split_once(':')?;
                        key.trim().eq_ignore_ascii_case(name).then(|| value.trim().to_string())
                    })
                };
                let length = header("content-length").and_then(|l| l.parse::<usize>().ok()).unwrap_or(0);
                while data.len() < head_end + length {
                    match stream.read(&mut buf) {
                        Ok(n) if n > 0 => data.extend_from_slice(&buf[..n]),
                        _ => break,
                    }
                }
                let path = head.split_whitespace().nth(1).unwrap_or_default().to_string();
                let body = serde_json::from_slice(&data[head_end..]).unwrap_or(serde_json::Value::Null);
                kept.lock().unwrap().push((path, header("authorization").unwrap_or_default(), body));
                // A request past the last answer written for it is answered
                // as one the test did not expect.
                let (status, reply) = answers.next().unwrap_or((500, "one request too many"));
                let response = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                    reply.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        (config, seen)
    }

    fn scope() -> Scope {
        Scope { project_uuid: "p0000000000000001".to_string(), owner: "owner.testnet".to_string() }
    }

    fn answered() -> Vec<crate::tasks::Answered> {
        vec![
            crate::tasks::Answered { id: "run-a-0".to_string(), outcome: Some(b"sealed".to_vec()) },
            crate::tasks::Answered { id: "run-b-0".to_string(), outcome: None },
        ]
    }

    fn refused() -> Vec<crate::tasks::Refused> {
        vec![crate::tasks::Refused { id: "run-c-0".to_string(), reason: "hash-mismatch".to_string() }]
    }

    const DOWN: (u16, &str) = (503, "the database is temporarily unavailable; try again shortly");

    #[tokio::test]
    async fn a_report_the_store_took_at_the_third_asking_is_a_report_made() {
        let (config, seen) = store_answering(vec![DOWN, DOWN, (200, r#"{"done":1,"failed":1}"#)]);
        let finished = finish(&config, &scope(), "run-o", true, &answered(), &refused()).await;
        assert_eq!(finished, Ok(Finished { done: 1, failed: 1 }));

        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 3);
        for (path, authorization, body) in seen.iter() {
            assert_eq!(path, "/owner-tasks/finish");
            assert_eq!(authorization, "Bearer the-workers-token");
            // The same report each time: what the run reported on, and
            // nothing of a task it answered and left without a result.
            assert_eq!(
                body,
                &serde_json::json!({
                    "project_uuid": "p0000000000000001",
                    "owner": "owner.testnet",
                    "run": "run-o",
                    "success": true,
                    "reported": [{ "id": "run-a-0", "outcome": "c2VhbGVk" }],
                    "refused": [{ "id": "run-c-0", "reason": "hash-mismatch" }],
                })
            );
        }
    }

    #[tokio::test]
    async fn a_report_the_store_did_not_take_in_three_askings_is_given_up() {
        let (config, seen) = store_answering(vec![DOWN, DOWN, DOWN, (200, r#"{"done":1,"failed":0}"#)]);
        let finished = finish(&config, &scope(), "run-o", true, &answered(), &refused()).await;
        assert_eq!(finished, Err(StoreError::Unavailable("the task store answered 503".to_string())));
        assert_eq!(seen.lock().unwrap().len(), FINISH_ATTEMPTS as usize);
        assert_eq!(FINISH_ATTEMPTS, 3);
    }

    #[tokio::test]
    async fn a_report_the_store_refused_by_name_is_not_sent_again() {
        let (config, seen) =
            store_answering(vec![(400, r#"{"reason":"invalid_request","message":"reported holds a task twice"}"#)]);
        let finished = finish(&config, &scope(), "run-o", false, &answered(), &refused()).await;
        assert_eq!(finished, Err(StoreError::Refused(Refusal::InvalidRequest, None)));
        assert_eq!(seen.lock().unwrap().len(), 1);

        // A request the store could not read at all will not read better
        // the next time either.
        let (config, seen) = store_answering(vec![(413, "Payload Too Large")]);
        let finished = finish(&config, &scope(), "run-o", true, &answered(), &refused()).await;
        assert_eq!(finished, Err(StoreError::Refused(Refusal::InvalidRequest, None)));
        assert_eq!(seen.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_store_that_is_not_there_is_no_answer_and_nothing_of_where_it_is_is_told() {
        // An address nothing listens at: bound, read, and let go.
        let gone = std::net::TcpListener::bind("127.0.0.1:0").expect("bind").local_addr().expect("addr");
        let config =
            StoreConfig { coordinator_url: format!("http://{gone}"), coordinator_token: "the-workers-token".to_string() };
        let Err(StoreError::Unavailable(why)) = finish(&config, &scope(), "run-o", true, &answered(), &refused()).await else {
            panic!("a store that is not there took a report");
        };
        assert_eq!(why, "the task store did not answer");
    }

    /// A preparer's list whose answer is `bytes` long, to the byte.
    fn a_list_of(bytes: usize) -> &'static str {
        let around = r#"{"tasks":[],"pad":""}"#.len();
        Box::leak(format!(r#"{{"tasks":[],"pad":"{}"}}"#, "x".repeat(bytes - around)).into_boxed_str())
    }

    fn store_reading(config: StoreConfig, most_answer: usize) -> HttpStore {
        HttpStore { most_answer, ..HttpStore::new(config).expect("a client") }
    }

    #[test]
    fn an_answer_over_the_bound_is_no_answer_and_one_at_the_bound_is_read() {
        let (at, over) = (a_list_of(4096), a_list_of(4097));
        let (config, seen) = store_answering(vec![(200, at), (200, over), (409, over)]);
        // The store's calls block: made from a thread of their own, as the host makes them.
        let answers = std::thread::spawn(move || {
            let store = store_reading(config, 4096);
            [0; 3].map(|_| store.mine(&scope(), "agent.testnet", None))
        })
        .join()
        .expect("the calls return");
        assert_eq!(answers[0].as_ref().map(Vec::len), Ok(0));
        let over = StoreError::Unavailable("the task store's answer is over 4096 bytes".to_string());
        assert_eq!(answers[1].as_ref().err(), Some(&over));
        assert_eq!(answers[2].as_ref().err(), Some(&over), "a refusal is bounded as an answer is");
        assert_eq!(seen.lock().unwrap().len(), 3);
    }

    #[test]
    fn an_answer_that_does_not_say_how_long_it_is_is_read_to_the_bound_and_no_further() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let config = StoreConfig {
            coordinator_url: format!("http://{}", listener.local_addr().expect("addr")),
            coordinator_token: "the-workers-token".to_string(),
        };
        let sent = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = sent.clone();
        std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else { return };
            let (mut data, mut buf) = (Vec::new(), [0u8; 8192]);
            while !data.windows(4).any(|w| w == b"\r\n\r\n") {
                match stream.read(&mut buf) {
                    Ok(n) if n > 0 => data.extend_from_slice(&buf[..n]),
                    _ => return,
                }
            }
            // No length: the body ends when the store closes, which it does
            // only after 64 MiB or when nobody reads.
            if stream.write_all(b"HTTP/1.1 200 X\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n").is_err() {
                return;
            }
            let block = [b' '; 65536];
            for _ in 0..1024 {
                if stream.write_all(&block).is_err() {
                    return;
                }
                counted.fetch_add(block.len(), std::sync::atomic::Ordering::SeqCst);
            }
        });
        let answer = std::thread::spawn(move || store_reading(config, 1024 * 1024).mine(&scope(), "agent.testnet", None))
            .join()
            .expect("the call returns");
        assert!(matches!(answer, Err(StoreError::Unavailable(why)) if why.contains("is over")));
        assert!(sent.load(std::sync::atomic::Ordering::SeqCst) < 32 * 1024 * 1024, "the answer was not read whole");
    }

    #[tokio::test]
    async fn a_report_answered_over_the_bound_is_no_answer() {
        let body = serde_json::json!({ "run": "run-o" });
        let (config, _) = store_answering(vec![(200, r#"{"done":1,"failed":0}"#)]);
        assert_eq!(finish_within(&config, body.clone(), "run-o", 21).await, Ok(Finished { done: 1, failed: 0 }));

        let (config, seen) = store_answering(vec![(200, r#"{"done":1,"failed":0}"#); 4]);
        let Err(StoreError::Unavailable(why)) = finish_within(&config, body, "run-o", 20).await else {
            panic!("an answer over the bound was read");
        };
        assert!(why.contains("is over"), "{why}");
        assert_eq!(seen.lock().unwrap().len(), FINISH_ATTEMPTS as usize, "no answer, so asked again");
    }

    #[test]
    fn the_bound_is_above_the_largest_answer_the_store_gives() {
        let base64 = |bytes: usize| bytes.div_ceil(3) * 4;
        let around = 512;
        let waiting = 20 * (base64(1024 * 1024) + around);
        let mine = 200 * (base64(32 * 1024) + base64(8 * 1024) + around);
        // Ten files: each is padded on its own.
        let one = base64(1024 * 1024) + base64(crate::tasks::MAX_FILES_BYTES + 1024) + 10 * 4 + around;
        assert_eq!((waiting, mine, one), (27_972_320, 11_025_600, 9_788_632));
        assert!(MAX_ANSWER_BYTES > waiting.max(mine).max(one));
    }

    #[test]
    fn a_task_is_read_with_its_bytes() {
        let tasks: PreparedTasks = read(
            200,
            br#"{"tasks":[{"id":"run-0","kind":"input","state":"done","created_at":1,"expires_at":2,"run":"run-9","outcome":"c2VhbGVk"}]}"#,
        )
        .unwrap();
        assert_eq!(tasks.tasks[0].outcome.as_deref(), Some(&b"sealed"[..]));
        assert_eq!(tasks.tasks[0].run.as_deref(), Some("run-9"));
        assert!(tasks.tasks[0].rejection.is_none());
        assert!(read::<PreparedTasks>(
            200,
            br#"{"tasks":[{"id":"t","kind":"input","state":"done","created_at":1,"expires_at":2,"outcome":"***"}]}"#
        )
        .is_err());
    }
}
