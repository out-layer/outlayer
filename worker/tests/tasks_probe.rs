//! `connectors/tasks-probe` through the executor: what a guest sees of the
//! `outlayer:tasks` host interface, and what reaches the store.
//!
//! The guest's calls go through the worker's real host functions, its real
//! store client and its real chain client, to an in-process coordinator and
//! RPC node that keep the coordinator's rules for a task's state. The owner's
//! page is played here with the device's private key: it opens what the store
//! holds, and nothing else does; the owner's wallet signs the approvals, and
//! the coordinator's part of an approval — `open` → `approved` for the run it
//! starts — is played on the fake store. The run that carries a task out is
//! the agent's, with the agent's consent.
//!
//! These run in a release build only (`cargo test --release --test
//! tasks_probe`): the store client is reqwest's blocking one, and in a debug
//! build reqwest asserts that it is not inside a tokio runtime — which a
//! wasmtime run always is.
//!
//! The probe must be built first: connectors/tasks-probe/build.sh

use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use base64::Engine;
use offchainvm_worker::api_client::{ExecutionResult, ResourceLimits, ResponseFormat};
use offchainvm_worker::executor::{Executor, RunKeys};
use offchainvm_worker::tasks::crypto::{self, Purpose};
use offchainvm_worker::tasks::statement::{approval_sentence, supply_digest};
use offchainvm_worker::tasks::{ChainConfig, RunReport, StoreConfig, TaskGrant, TasksRun};
use serde_json::{json, Value};

const OWNER: &str = "owner.testnet";
const AGENT: &str = "agent.testnet";
const PROJECT_UUID: &str = "p0000000000000001";
const RECIPIENT: &str = "outlayer.testnet";

fn probe() -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("connectors/tasks-probe/target/wasm32-wasip2/release/tasks-probe.wasm");
    if !path.exists() {
        panic!("Test WASM not found at {}! Build it first:\ncd ../connectors/tasks-probe && ./build.sh", path.display());
    }
    std::fs::read(&path).expect("read the probe")
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn un_b64(text: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(text).expect("base64")
}

/// One request: the path and the JSON body.
fn read_request(stream: &mut std::net::TcpStream) -> Option<(String, Value)> {
    let mut data = Vec::new();
    let mut buf = [0u8; 8192];
    let header_end = loop {
        let n = stream.read(&mut buf).ok()?;
        if n == 0 {
            return None;
        }
        data.extend_from_slice(&buf[..n]);
        if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
    };
    let head = String::from_utf8_lossy(&data[..header_end]).into_owned();
    let path = head.split_whitespace().nth(1)?.to_string();
    let length = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim().eq_ignore_ascii_case("content-length").then(|| value.trim().parse::<usize>().ok())?
        })
        .unwrap_or(0);
    while data.len() < header_end + length {
        let n = stream.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buf[..n]);
    }
    let body = &data[header_end..(header_end + length).min(data.len())];
    Some((path, if body.is_empty() { Value::Null } else { serde_json::from_slice(body).ok()? }))
}

fn serve(respond: impl Fn(&str, &Value) -> (u16, Value) + Send + 'static) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("addr"));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let Some((path, body)) = read_request(&mut stream) else { continue };
            let (code, reply) = respond(&path, &body);
            let reply = reply.to_string();
            let response = format!(
                "HTTP/1.1 {code} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                reply.len()
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    url
}

/// A task as the coordinator's row holds it.
#[derive(Clone, Debug)]
struct Row {
    request: Value,
    state: String,
    run: Option<String>,
    outcome: Option<String>,
    failure_reason: Option<String>,
    sealed: Option<String>,
    content: Option<String>,
    files: Vec<Value>,
    copies: BTreeMap<String, String>,
}

#[derive(Default)]
struct Coordinator {
    rows: Mutex<BTreeMap<String, Row>>,
    devices: Mutex<Vec<Value>>,
    seen: Mutex<Vec<String>>,
}

impl Coordinator {
    fn answer(&self, path: &str, body: &Value) -> (u16, Value) {
        self.seen.lock().unwrap().push(path.to_string());
        let mut rows = self.rows.lock().unwrap();
        let text = |member: &str| body[member].as_str().unwrap_or_default().to_string();
        let in_scope = |row: &Row| row.request["project_uuid"] == body["project_uuid"] && row.request["owner"] == body["owner"];
        let not_found = (404, json!({ "reason": "not_found" }));
        let stored = |row: &Row| {
            json!({
                "id": row.request["id"], "preparer": row.request["preparer"], "kind": row.request["kind"],
                "state": row.state, "expires_at": row.request["expires_at"], "sealed": row.sealed,
                "files": row.files,
            })
        };
        match path {
            "/owner-tasks/devices" => {
                let devices: Vec<Value> =
                    self.devices.lock().unwrap().iter().filter(|d| d["account_id"] == body["owner"]).cloned().collect();
                (200, json!({ "devices": devices }))
            }
            "/owner-tasks/open" => {
                let copies = body["copies"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|c| (c["device_id"].as_str().unwrap().to_string(), c["wrapped_key"].as_str().unwrap().to_string()))
                    .collect();
                rows.insert(
                    text("id"),
                    Row {
                        request: body.clone(),
                        state: "open".into(),
                        run: None,
                        outcome: None,
                        failure_reason: None,
                        sealed: Some(text("sealed")),
                        content: Some(text("content")),
                        files: body["files"].as_array().cloned().unwrap_or_default(),
                        copies,
                    },
                );
                let written = body["copies"].as_array().map_or(0, Vec::len);
                (200, json!({ "created": true, "copies": written }))
            }
            "/owner-tasks/get" => match rows.get(&text("id")).filter(|r| in_scope(r)) {
                Some(row) => (200, stored(row)),
                None => not_found,
            },
            "/owner-tasks/waiting" => {
                let tasks: Vec<Value> =
                    rows.values().filter(|r| in_scope(r) && (r.state == "open" || r.state == "approved")).map(stored).collect();
                (200, json!({ "tasks": tasks }))
            }
            "/owner-tasks/copies" => {
                let (mut written, mut tasks) = (0, 0);
                for task in body["tasks"].as_array().into_iter().flatten() {
                    if let Some(row) = rows.get_mut(task["id"].as_str().unwrap()).filter(|r| r.state == "open" || r.state == "approved") {
                        let mut of_this_task = 0;
                        for copy in task["copies"].as_array().into_iter().flatten() {
                            row.copies.insert(
                                copy["device_id"].as_str().unwrap().to_string(),
                                copy["wrapped_key"].as_str().unwrap().to_string(),
                            );
                            of_this_task += 1;
                        }
                        written += of_this_task;
                        if of_this_task > 0 {
                            tasks += 1;
                        }
                    }
                }
                (200, json!({ "written": written, "tasks": tasks }))
            }
            // `approved → answering`, for the run the approval started and no
            // other: the coordinator's CAS keyed on `run`.
            "/owner-tasks/answer" => match rows.get_mut(&text("id")).filter(|r| in_scope(r)) {
                Some(row) if row.state == "approved" && row.run.as_deref() == Some(text("run").as_str()) => {
                    row.state = "answering".into();
                    row.sealed = None;
                    row.content = None;
                    row.files.clear();
                    row.copies.clear();
                    (200, json!({ "state": "answering" }))
                }
                Some(row) => (409, json!({ "reason": "closed", "state": row.state })),
                None => not_found,
            },
            "/owner-tasks/mine" => {
                let tasks: Vec<Value> = rows
                    .values()
                    .filter(|r| in_scope(r) && r.request["preparer"] == body["preparer"])
                    .filter(|r| body["id"].is_null() || r.request["id"] == body["id"])
                    .map(|r| {
                        json!({
                            "id": r.request["id"], "kind": r.request["kind"], "state": r.state, "created_at": 1,
                            "expires_at": r.request["expires_at"], "run": r.run, "outcome": r.outcome,
                            "failure_reason": r.failure_reason,
                        })
                    })
                    .collect();
                match (tasks.is_empty(), body["id"].is_null()) {
                    (true, false) => not_found,
                    _ => (200, json!({ "tasks": tasks })),
                }
            }
            "/owner-tasks/cancel" => match rows.get_mut(&text("id")).filter(|r| in_scope(r) && r.request["preparer"] == body["preparer"]) {
                Some(row) if row.state == "open" => {
                    row.state = "cancelled".into();
                    (200, json!({ "state": "cancelled" }))
                }
                Some(row) => (409, json!({ "reason": "closed", "state": row.state })),
                None => not_found,
            },
            other => (500, json!({ "error": format!("the fake coordinator has no {other}") })),
        }
    }

    /// What the job path does after the guest exits, and the coordinator with
    /// it: what the run answered ends `done` or `failed`; an approved task the
    /// run was refused ends `failed` with the reason.
    fn finish(&self, run: &str, success: bool, report: &RunReport) {
        let mut rows = self.rows.lock().unwrap();
        for task in report.tasks() {
            let row = rows.get_mut(&task.id).expect("the task the run answered");
            assert_eq!((row.state.as_str(), row.run.as_deref()), ("answering", Some(run)));
            match (success, task.outcome) {
                (true, Some(outcome)) => {
                    row.state = "done".into();
                    row.outcome = Some(b64(&outcome));
                }
                _ => row.state = "failed".into(),
            }
        }
        for refused in report.refusals() {
            if let Some(row) = rows.get_mut(&refused.id).filter(|r| r.state == "approved" && r.run.as_deref() == Some(run)) {
                row.state = "failed".into();
                row.failure_reason = Some(format!("run_refused:{}", refused.reason));
                row.sealed = None;
                row.content = None;
                row.files.clear();
                row.copies.clear();
            }
        }
    }

    /// The inbox's part of an approval: `open` → `approved` for `run`.
    fn approve(&self, id: &str, run: &str) {
        let mut rows = self.rows.lock().unwrap();
        let row = rows.get_mut(id).expect("the row");
        assert_eq!(row.state, "open", "only an open task is approved");
        row.state = "approved".into();
        row.run = Some(run.to_string());
    }

    fn row(&self, id: &str) -> Row {
        self.rows.lock().unwrap().get(id).cloned().expect("the row")
    }
}

/// The platform around the probe: a store, a chain that holds the owner's
/// key, and the owner's signed-in device.
struct World {
    wasm: Vec<u8>,
    coordinator: Arc<Coordinator>,
    store_url: String,
    rpc_url: String,
    device: p256::SecretKey,
    wallet: ed25519_dalek::SigningKey,
}

/// The payment key nonce a caller's runs are made with: the agent's key, or
/// the owner's own.
fn nonce_of(caller: &str) -> u32 {
    match caller {
        OWNER => 7,
        _ => 1,
    }
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|since| since.as_secs() as i64).unwrap()
}

#[derive(borsh::BorshSerialize)]
struct Nep413 {
    message: String,
    nonce: [u8; 32],
    recipient: String,
    callback_url: Option<String>,
}

fn nep413_sign(wallet: &ed25519_dalek::SigningKey, message: &str, nonce: [u8; 32]) -> String {
    use ed25519_dalek::Signer;
    use sha2::{Digest, Sha256};
    let payload = Nep413 { message: message.to_string(), nonce, recipient: RECIPIENT.to_string(), callback_url: None };
    let signed = Sha256::digest([&2_147_484_061u32.to_le_bytes()[..], &borsh::to_vec(&payload).unwrap()].concat());
    b64(&wallet.sign(&signed).to_bytes())
}

fn statement(device: &p256::PublicKey, wallet: &ed25519_dalek::SigningKey) -> Value {
    // A day from now: within what a session lasts.
    let valid_until = now() + 24 * 60 * 60;
    let device_pubkey = crypto::write_pubkey(device);
    let message = offchainvm_worker::tasks::statement::sentence(OWNER, &device_pubkey, valid_until).unwrap();
    json!({
        "id": "0b9c1a52-7c1e-4a53-9c58-2f0c8f6f3b11",
        "account_id": OWNER,
        "device_pubkey": device_pubkey,
        "signer_pubkey": format!("ed25519:{}", bs58::encode(wallet.verifying_key().as_bytes()).into_string()),
        "signature": nep413_sign(wallet, &message, [5u8; 32]),
        "nonce": b64(&[5u8; 32]),
        "valid_until": valid_until,
    })
}

impl World {
    fn start() -> Self {
        let coordinator = Arc::new(Coordinator::default());
        let wallet = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
        let device = p256::SecretKey::random(&mut rand::rngs::OsRng);
        coordinator.devices.lock().unwrap().push(statement(&device.public_key(), &wallet));
        let store = coordinator.clone();
        let store_url = serve(move |path, body| store.answer(path, body));
        let owners_key = format!("ed25519:{}", bs58::encode(wallet.verifying_key().as_bytes()).into_string());
        let rpc_url = serve(move |_, body| {
            let params = &body["params"];
            let its_key = params["request_type"] == "view_access_key"
                && params["finality"] == "final"
                && params["account_id"] == OWNER
                && params["public_key"] == owners_key.as_str();
            match its_key {
                true => (200, json!({ "jsonrpc": "2.0", "id": "tasks", "result": { "nonce": 7, "permission": "FullAccess", "block_height": 1, "block_hash": "x" } })),
                false => (200, json!({ "jsonrpc": "2.0", "id": "tasks", "error": { "name": "HANDLER_ERROR", "cause": { "name": "UNKNOWN_ACCESS_KEY", "info": {} } } })),
            }
        });
        Self { wasm: probe(), coordinator, store_url, rpc_url, device, wallet }
    }

    /// The owner's wallet signs the approval of the task `id` showing `hash`,
    /// with `supplied` and `note` as the page sends them; the approval as the
    /// run's input carries it.
    fn signed(&self, id: &str, hash: &str, supplied: Option<&[u8]>, note: Option<&[u8]>) -> Value {
        let at = now();
        let message = approval_sentence(OWNER, id, hash, &supply_digest(supplied, note), at).unwrap();
        let mut nonce = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
        json!({
            "at": at,
            "public_key": format!("ed25519:{}", bs58::encode(self.wallet.verifying_key().as_bytes()).into_string()),
            "signature": nep413_sign(&self.wallet, &message, nonce),
            "nonce": b64(&nonce),
        })
    }

    /// The owner approves the task `id` (the inbox's part, on the fake store)
    /// for the run `run`, and the input the platform starts that run with:
    /// the operation, the task, the approval, and what the owner wrote.
    fn approved(&self, id: &str, hash: &str, run: &str, operation: &str, supplied: Option<&[u8]>, note: Option<&[u8]>) -> Value {
        self.coordinator.approve(id, run);
        let mut input = json!({ "operation": operation, "task_id": id, "task_hash": hash, "approval": self.signed(id, hash, supplied, note) });
        if let Some(supplied) = supplied {
            input["supplied"] = json!(b64(supplied));
        }
        if let Some(note) = note {
            input["note"] = json!(b64(note));
        }
        input
    }

    async fn run(&self, caller: &str, by_name: bool, run: &str, input: Value) -> (ExecutionResult, RunReport) {
        self.run_with(caller, Some(by_name), true, run, input).await
    }

    /// One run of the probe: `grant` is how the owner's row admitted the
    /// caller, `None` for a run that named no row.
    async fn run_with(
        &self,
        caller: &str,
        grant: Option<bool>,
        declared: bool,
        run: &str,
        input: Value,
    ) -> (ExecutionResult, RunReport) {
        let report = RunReport::default();
        let sha = {
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::digest(&self.wasm))
        };
        // `"nonce": null` in the input stands for a run with no payment key:
        // one made on chain.
        let keyless = input.get("nonce").is_some_and(Value::is_null);
        let tasks = TasksRun {
            declared,
            grant: grant.map(|by_name| TaskGrant::new(zeroize::Zeroizing::new([7u8; 32]), by_name)),
            run: run.to_string(),
            project_id: Some("probes.testnet/tasks-probe".to_string()),
            project_uuid: Some(PROJECT_UUID.to_string()),
            build: Some(sha.clone()),
            operation: input.get("operation").and_then(|o| o.as_str()).map(str::to_string),
            owner: grant.map(|_| OWNER.to_string()),
            profile: grant.map(|_| "probe".to_string()),
            caller: Some(caller.to_string()),
            predecessor: Some(caller.to_string()),
            payment_key_nonce: (!keyless).then(|| nonce_of(caller)),
            wallet_id: None,
            bound_identity: false,
            compute_limit_usd: (!keyless).then(|| "10000".to_string()),
            store: Some(StoreConfig { coordinator_url: self.store_url.clone(), coordinator_token: "t".to_string() }),
            chain: Some(ChainConfig { rpc_url: self.rpc_url.clone(), recipient: RECIPIENT.to_string() }),
            report: report.clone(),
        };
        let executor = Executor::new(10_000_000_000, false);
        let limits = ResourceLimits { max_instructions: 10_000_000_000, max_memory_mb: 128, max_execution_seconds: 60 };
        let env: HashMap<String, String> =
            [("NEAR_USER_ACCOUNT_ID", caller), ("NEAR_NETWORK_ID", "testnet"), ("TASKS_PROBE_POLICY", r#"{"confirm":["send"]}"#)]
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
        let result = executor
            .with_keys(RunKeys { signing: None, encryption: None, tasks: Some(tasks) })
            .execute(
                &self.wasm,
                Some(&sha),
                input.to_string().as_bytes(),
                &limits,
                Some(env),
                Some("wasm32-wasip2"),
                &ResponseFormat::Json,
                None,
                None,
                None,
                None,
            )
            .await
            .expect("the executor answers");
        (result, report)
    }

    /// What the owner's page reads of a task in the inbox, with no run.
    fn page_reads(&self, id: &str) -> (Value, String) {
        use aes_gcm::aead::{Aead, KeyInit, Payload};
        use sha2::{Digest, Sha256};
        let row = self.coordinator.row(id);
        let wrapped = un_b64(row.copies.values().next().expect("a copy for the device"));
        let key = crypto::open_from(&self.device, Purpose::DeviceCopy, id, &wrapped).expect("the device opens its copy");
        let content = un_b64(row.content.as_deref().expect("content"));
        assert_eq!(content[0], 0x01);
        let cipher = aes_gcm::Aes256Gcm::new(aes_gcm::Key::<aes_gcm::Aes256Gcm>::from_slice(&key));
        let document = cipher
            .decrypt(aes_gcm::Nonce::from_slice(&content[1..13]), Payload { msg: &content[13..], aad: id.as_bytes() })
            .expect("the content opens under its key");
        (serde_json::from_slice(&document).unwrap(), hex::encode(Sha256::digest(&document)))
    }
}

/// The input of an approved run, with the hash the owner did not sign.
fn wrong_hash_input(input: &Value) -> Value {
    let mut wrong = input.clone();
    wrong["task_hash"] = json!("0".repeat(64));
    wrong
}

/// The probe's answer: the connectors' `{"success","output","logs","error"}`.
fn answer(result: &ExecutionResult) -> Value {
    assert!(result.success, "the run itself succeeds: {:?}", result.error);
    match result.output.as_ref().expect("an answer") {
        offchainvm_worker::api_client::ExecutionOutput::Json(value) => value.clone(),
        other => panic!("the probe answers JSON, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
#[cfg_attr(debug_assertions, ignore = "task runs need a release build: reqwest's blocking client asserts in debug that it is outside a tokio runtime")]
async fn the_agent_prepares_the_owner_reads_and_answers_and_the_agent_learns() {
    let world = World::start();
    let (prepared, report) = world
        .run(AGENT, true, "run-a", json!({ "operation": "prepare", "title": "Send an email", "body": "Hello Bob", "life_seconds": 600 }))
        .await;
    let prepared = answer(&prepared);
    assert_eq!(prepared["success"], true, "{prepared}");
    let out = &prepared["output"];
    assert_eq!((out["status"].as_str(), out["task_id"].as_str(), out["devices"].as_u64()), (Some("awaiting_owner"), Some("run-a-0"), Some(1)), "{prepared}");
    assert!(report.tasks().is_empty(), "preparing answers nothing");

    // The store holds ciphertext.
    let row = world.coordinator.row("run-a-0");
    let held = [un_b64(row.sealed.as_deref().unwrap()), un_b64(row.content.as_deref().unwrap())].concat();
    assert!(!String::from_utf8_lossy(&held).contains("Hello Bob"));

    // The owner's page: no run.
    let (shown, hash) = world.page_reads("run-a-0");
    assert_eq!(hash, out["task_hash"].as_str().unwrap(), "what the page hashes is what the run said it made");
    assert_eq!(shown["display"]["title"], "Send an email");
    assert_eq!(shown["display"]["fields"][0]["values"][0], "Hello Bob");
    assert_eq!((shown["owner"].as_str(), shown["preparer"].as_str()), (Some(OWNER), Some(AGENT)));
    assert_eq!(shown["answer_by"], json!({ "operation": "confirm", "supplies": "nothing" }));

    let (status, _) = world.run(AGENT, true, "run-b", json!({ "operation": "task_status", "task_id": "run-a-0" })).await;
    assert_eq!(answer(&status)["output"]["state"], "open");

    // The owner approves with one signature and a note, sealed to the task's
    // reply key as the page seals it; the platform starts the agent's run
    // with the approval in its input.
    let reply = crypto::read_pubkey(shown["reply_pubkey"].as_str().unwrap()).unwrap();
    let note = crypto::seal_to(&reply, Purpose::Note, "run-a-0", b"go ahead").unwrap();
    let input = world.approved("run-a-0", &hash, "run-o", "confirm", None, Some(&note));
    let (status, _) = world.run(AGENT, true, "run-b", json!({ "operation": "task_status", "task_id": "run-a-0" })).await;
    assert_eq!((answer(&status)["output"]["state"].as_str(), answer(&status)["output"]["run"].as_str()), (Some("approved"), Some("run-o")));
    let (confirmed, report) = world.run(AGENT, true, "run-o", input).await;
    let confirmed_answer = answer(&confirmed);
    assert_eq!(confirmed_answer["output"]["status"], "done", "{confirmed_answer}");
    assert_eq!(confirmed_answer["output"]["result"]["acted_on"]["body"], "Hello Bob");
    assert_eq!(confirmed_answer["output"]["result"]["note"], "go ahead", "the owner's note reaches the agent's run");
    let row = world.coordinator.row("run-a-0");
    assert!(row.sealed.is_none() && row.content.is_none() && row.copies.is_empty(), "what it showed is gone");
    assert_eq!(report.tasks().len(), 1);
    world.coordinator.finish("run-o", confirmed.success, &report);

    let (status, _) = world.run(AGENT, true, "run-c", json!({ "operation": "task_status", "task_id": "run-a-0" })).await;
    let status = answer(&status);
    assert_eq!((status["output"]["state"].as_str(), status["output"]["run"].as_str()), (Some("done"), Some("run-o")), "{status}");
    assert_eq!(status["output"]["result"]["acted_on"]["body"], "Hello Bob");
    assert_eq!(status["output"]["result"]["prepared_by"], AGENT);
}

#[tokio::test(flavor = "multi_thread")]
#[cfg_attr(debug_assertions, ignore = "task runs need a release build: reqwest's blocking client asserts in debug that it is outside a tokio runtime")]
async fn refusals_reach_the_guest_as_answers_that_open_with_their_code() {
    let world = World::start();
    let refused = |result: (ExecutionResult, RunReport)| {
        let answer = answer(&result.0);
        assert_eq!((answer["success"].as_bool(), answer["output"].is_null()), (Some(false), true), "{answer}");
        answer["error"].as_str().expect("a sentence").to_string()
    };
    let prepare = json!({ "operation": "prepare" });

    // A row open to everyone admits the run and refuses the task.
    assert!(refused(world.run(AGENT, false, "run-a", prepare.clone()).await).starts_with("not_granted_by_name: "));
    // A run that names no row has no owner.
    assert!(refused(world.run_with(AGENT, None, true, "run-a", prepare.clone()).await).starts_with("no_owner: "));
    // A component whose manifest the worker read as declaring no tasks.
    assert!(refused(world.run_with(AGENT, Some(true), false, "run-a", prepare.clone()).await).starts_with("tasks_not_declared: "));
    assert!(world.coordinator.rows.lock().unwrap().is_empty());

    let life = json!({ "operation": "prepare", "life_seconds": 86_401 });
    assert!(refused(world.run(AGENT, true, "run-a", life).await).starts_with("task_life_too_long: "));
    let display = json!({ "operation": "prepare_raw", "display": { "title": "x".repeat(81), "fields": [] } });
    let said = refused(world.run(AGENT, true, "run-a", display).await);
    assert!(said.starts_with("display_invalid: ") && said.contains("81 characters"), "{said}");
    let reordered = json!({ "operation": "prepare_raw", "display": { "title": "Pay", "fields": [
        { "label": "To", "kind": "address", "value": "evil\u{202E}moc.knab" } ] } });
    assert!(refused(world.run(AGENT, true, "run-a", reordered).await).starts_with("display_invalid: "));
    assert!(world.coordinator.rows.lock().unwrap().is_empty(), "no task was made");

    // A run with no payment key — one on chain — opens no task.
    assert!(refused(world.run_with(AGENT, Some(true), true, "run-k", json!({ "operation": "prepare", "nonce": null })).await).starts_with("task_no_payment_key: "));
    assert!(world.coordinator.rows.lock().unwrap().is_empty());

    // Before the owner approves, the agent's own call of `confirm` takes
    // nothing: no approval, and the task is not approved.
    let (prepared, _) = world.run(AGENT, true, "run-p", prepare).await;
    let hash = answer(&prepared)["output"]["task_hash"].as_str().unwrap().to_string();
    let unsigned = json!({ "operation": "confirm", "task_id": "run-p-0", "task_hash": hash });
    assert!(refused(world.run(AGENT, true, "run-x", unsigned).await).starts_with("task_answer_invalid: "), "no approval in the call");
    let forged = json!({ "operation": "confirm", "task_id": "run-p-0", "task_hash": hash, "approval": world.signed("run-p-0", &hash, None, None) });
    let (not_approved, report) = world.run(AGENT, true, "run-x", forged.clone()).await;
    assert!(refused((not_approved, report.clone())).starts_with("task_approval_invalid: "), "the owner has not approved");
    assert!(report.refusals().is_empty(), "a task that is not approved is not failed by a run");
    assert_eq!(world.coordinator.row("run-p-0").state, "open");

    // Approved: the owner's own run is not the preparer's; a wrong hash and
    // another operation are refused; each refusal is recorded against the
    // run the approval started, and fails the task when that run ends.
    let input = world.approved("run-p-0", &hash, "run-o", "confirm", None, None);
    let (by_owner, report) = world.run(OWNER, false, "run-o", input.clone()).await;
    assert!(refused((by_owner, report.clone())).starts_with("not_the_preparer: "));
    assert_eq!(report.refusals().len(), 1);
    let mut wrong = input.clone();
    wrong["task_hash"] = json!("0".repeat(64));
    assert!(refused(world.run(AGENT, true, "run-o", wrong).await).starts_with("task_hash_mismatch: "));
    let mut through_another = input.clone();
    through_another["operation"] = json!("supply");
    assert!(refused(world.run(AGENT, true, "run-o", through_another).await).starts_with("task_answer_invalid: "));
    let unknown = json!({ "operation": "task_status", "task_id": "run-z-0" });
    assert!(refused(world.run(AGENT, true, "run-x", unknown).await).starts_with("task_not_found: "));
    assert_eq!(world.coordinator.row("run-p-0").state, "approved", "nothing moved");
    // The run the owner's approval started was refused: the task fails with
    // the reason, and the agent reads it.
    let (_, report) = world.run(AGENT, true, "run-o", wrong_hash_input(&input)).await;
    world.coordinator.finish("run-o", true, &report);
    let (status, _) = world.run(AGENT, true, "run-x", json!({ "operation": "task_status", "task_id": "run-p-0" })).await;
    let status = answer(&status);
    assert_eq!((status["output"]["state"].as_str(), status["output"]["failure_reason"].as_str()), (Some("failed"), Some("run_refused:hash-mismatch")), "{status}");

    // Nothing is a list of nothing.
    let (none, _) = world.run("second.testnet", true, "run-s", json!({ "operation": "tasks" })).await;
    assert_eq!(answer(&none), json!({ "success": true, "output": { "tasks": [] }, "logs": [], "error": null }));
}

#[tokio::test(flavor = "multi_thread")]
#[cfg_attr(debug_assertions, ignore = "task runs need a release build: reqwest's blocking client asserts in debug that it is outside a tokio runtime")]
async fn a_run_that_traps_after_answering_leaves_its_report_for_the_job_path() {
    let world = World::start();
    let (prepared, _) = world.run(AGENT, true, "run-a", json!({ "operation": "prepare", "answer_by": "confirm_trap" })).await;
    let hash = answer(&prepared)["output"]["task_hash"].as_str().unwrap().to_string();
    let input = world.approved("run-a-0", &hash, "run-o", "confirm_trap", None, None);
    let (trapped, report) = world.run(AGENT, true, "run-o", input).await;
    assert!(!trapped.success, "the run trapped");
    // The report outlives the guest: the job path tells the store.
    assert_eq!(report.tasks().len(), 1);
    world.coordinator.finish("run-o", trapped.success, &report);
    let (status, _) = world.run(AGENT, true, "run-b", json!({ "operation": "task_status", "task_id": "run-a-0" })).await;
    let status = answer(&status);
    assert_eq!((status["output"]["state"].as_str(), status["output"]["run"].as_str()), (Some("failed"), Some("run-o")), "{status}");
    assert!(status["output"].get("result").is_none(), "{status}");
}

#[tokio::test(flavor = "multi_thread")]
#[cfg_attr(debug_assertions, ignore = "task runs need a release build: reqwest's blocking client asserts in debug that it is outside a tokio runtime")]
async fn the_owner_supplies_what_was_asked_and_the_turn_opens_the_next_task() {
    let world = World::start();
    let (prepared, _) = world
        .run(AGENT, true, "run-a", json!({ "operation": "prepare", "kind": "file", "title": "Give me your photo", "again": true }))
        .await;
    assert_eq!(answer(&prepared)["output"]["status"], "awaiting_owner");
    let (shown, hash) = world.page_reads("run-a-0");
    let reply = crypto::read_pubkey(shown["reply_pubkey"].as_str().unwrap()).unwrap();
    let supplied = crypto::seal_to(&reply, Purpose::Answer, "run-a-0", b"ipfs://photo#sha256=abc").unwrap();

    // The owner's signature is over the sealed supply: the same supply
    // handed with another signature, or another supply with this one, is
    // refused.
    let input = world.approved("run-a-0", &hash, "run-o", "supply", Some(&supplied), None);
    let mut swapped = input.clone();
    swapped["supplied"] = json!(b64(&crypto::seal_to(&reply, Purpose::Answer, "run-a-0", b"ipfs://other").unwrap()));
    let (refused_swap, report) = world.run(AGENT, true, "run-o", swapped).await;
    let said = answer(&refused_swap)["error"].as_str().unwrap_or_default().to_string();
    assert!(said.starts_with("task_approval_invalid: "), "{said}");
    assert_eq!(report.refusals().len(), 1);
    assert_eq!(world.coordinator.row("run-a-0").state, "approved");

    let (turn, report) = world.run(AGENT, true, "run-o", input).await;
    let turn_answer = answer(&turn);
    assert_eq!(turn_answer["output"]["result"]["supplied"], "ipfs://photo#sha256=abc", "{turn_answer}");
    let next = &turn_answer["output"]["next"];
    assert_eq!((next["status"].as_str(), next["task_id"].as_str(), next["thread"].as_str()), (Some("awaiting_owner"), Some("run-o-0"), Some("run-a-0")), "{turn_answer}");
    world.coordinator.finish("run-o", turn.success, &report);
    let (next_shown, _) = world.page_reads("run-o-0");
    assert_eq!(next_shown["thread"], "run-a-0");
    assert_eq!(next_shown["preparer"], AGENT, "the turn is the agent's: its run opened it");
    assert_eq!(world.coordinator.row("run-o-0").request["preparer"], AGENT);
    assert_eq!(world.coordinator.row("run-a-0").state, "done");
}

#[tokio::test(flavor = "multi_thread")]
#[cfg_attr(debug_assertions, ignore = "task runs need a release build: reqwest's blocking client asserts in debug that it is outside a tokio runtime")]
async fn a_task_made_before_the_owner_signed_in_opens_after_one_run() {
    let world = World::start();
    let signed_in = std::mem::take(&mut *world.coordinator.devices.lock().unwrap());
    let (prepared, _) = world.run(AGENT, true, "run-a", json!({ "operation": "prepare" })).await;
    assert_eq!(answer(&prepared)["output"]["devices"], 0);
    assert!(world.coordinator.row("run-a-0").copies.is_empty());

    *world.coordinator.devices.lock().unwrap() = signed_in;
    // The agent's run opens nothing for the owner's devices.
    let (not_the_owners, _) = world.run(AGENT, true, "run-x", json!({ "operation": "tasks_unlock" })).await;
    assert!(answer(&not_the_owners)["error"].as_str().unwrap().starts_with("not_the_owner: "));
    let (unlocked, _) = world.run(OWNER, false, "run-o", json!({ "operation": "tasks_unlock" })).await;
    assert_eq!(answer(&unlocked)["output"], json!({ "waiting": 1 }));
    assert_eq!(world.page_reads("run-a-0").1, answer(&prepared)["output"]["task_hash"].as_str().unwrap());
}

#[tokio::test(flavor = "multi_thread")]
#[cfg_attr(debug_assertions, ignore = "task runs need a release build: reqwest's blocking client asserts in debug that it is outside a tokio runtime")]
async fn a_file_reaches_the_owners_page_and_comes_back_to_the_operation_that_acts() {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use sha2::{Digest, Sha256};
    let world = World::start();
    // A megabyte: far over what a field holds, and well within what a task carries.
    let files = json!([{ "name": "report.pdf", "content_type": "application/pdf", "text": "%PDF-1.7 0123456", "repeat": 65536 }]);
    let (prepared, _) = world.run(AGENT, true, "run-a", json!({ "operation": "prepare", "files": files })).await;
    let prepared = answer(&prepared);
    assert_eq!(prepared["output"]["status"], "awaiting_owner", "{prepared}");

    let (shown, hash) = world.page_reads("run-a-0");
    let note = &shown["files"][0];
    assert_eq!((note["name"].as_str(), note["content_type"].as_str(), note["size"].as_u64()), (Some("report.pdf"), Some("application/pdf"), Some(1_048_576)));

    // The page: the file's ciphertext from the inbox, opened with the task's
    // content key and held to the hash the envelope names.
    let row = world.coordinator.row("run-a-0");
    let wrapped = un_b64(row.copies.values().next().unwrap());
    let key = crypto::open_from(&world.device, Purpose::DeviceCopy, "run-a-0", &wrapped).unwrap();
    let blob = un_b64(row.files[0].as_str().unwrap());
    assert!(!blob.windows(8).any(|w| w == b"%PDF-1.7"), "the store holds ciphertext");
    let cipher = aes_gcm::Aes256Gcm::new(aes_gcm::Key::<aes_gcm::Aes256Gcm>::from_slice(&key));
    let opened = cipher
        .decrypt(aes_gcm::Nonce::from_slice(&blob[1..13]), Payload { msg: &blob[13..], aad: b"run-a-0:file:0" })
        .expect("the file opens under the content key, as that file of that task");
    assert_eq!(hex::encode(Sha256::digest(&opened)), note["sha256"].as_str().unwrap());
    assert!(opened.starts_with(b"%PDF-1.7 0123456%PDF"));

    let input = world.approved("run-a-0", &hash, "run-o", "confirm", None, None);
    let (confirmed, report) = world.run(AGENT, true, "run-o", input).await;
    let confirmed_answer = answer(&confirmed);
    let got = &confirmed_answer["output"]["result"]["files"][0];
    assert_eq!((got["name"].as_str(), got["bytes"].as_u64(), got["starts"].as_str()), (Some("report.pdf"), Some(1_048_576), Some("%PDF-1.7 0123456")), "{confirmed_answer}");
    assert!(world.coordinator.row("run-a-0").files.is_empty());
    world.coordinator.finish("run-o", confirmed.success, &report);

    // Over what a task carries: refused by name, and nothing is stored.
    let heavy = json!([{ "name": "big.bin", "content_type": "application/octet-stream", "text": "0123456789abcdef", "repeat": 400_000 }]);
    let (refused, _) = world.run(AGENT, true, "run-h", json!({ "operation": "prepare", "files": heavy })).await;
    let refused = answer(&refused);
    assert!(refused["error"].as_str().unwrap().starts_with("task_too_large: "), "{refused}");
    assert!(world.coordinator.rows.lock().unwrap().get("run-h-0").is_none());
}

#[tokio::test(flavor = "multi_thread")]
#[cfg_attr(debug_assertions, ignore = "task runs need a release build: reqwest's blocking client asserts in debug that it is outside a tokio runtime")]
async fn one_run_opens_five_tasks_and_is_refused_the_sixth() {
    let world = World::start();
    let (many, report) = world
        .run(AGENT, true, "run-a", json!({ "operation": "prepare_many", "count": 6, "title": "One of many", "body": "Hello Bob" }))
        .await;
    let many = answer(&many);
    assert_eq!(many["success"], true, "{many}");
    let out = &many["output"];
    assert_eq!((out["status"].as_str(), out["asked"].as_u64(), out["opened"].as_u64()), (Some("awaiting_owner"), Some(6), Some(5)), "{many}");
    assert_eq!((out["refused"]["number"].as_u64(), out["refused"]["code"].as_str()), (Some(6), Some("task_run_limit")), "{many}");
    assert!(out["refused"]["error"].as_str().unwrap().starts_with("task_run_limit: "), "{many}");
    assert!(report.tasks().is_empty(), "preparing answers nothing");

    let tasks = out["tasks"].as_array().expect("the tasks opened");
    assert_eq!(tasks.len(), 5);
    for (at, task) in tasks.iter().enumerate() {
        let id = format!("run-a-{at}");
        assert_eq!((task["status"].as_str(), task["task_id"].as_str()), (Some("awaiting_owner"), Some(id.as_str())), "{many}");
        let (shown, hash) = world.page_reads(&id);
        assert_eq!(hash, task["task_hash"].as_str().unwrap(), "the hash answered is the hash of what the page opens");
        assert_eq!(shown["display"]["title"], "One of many");
        assert_eq!(shown["display"]["fields"][2]["values"][0], format!("{} of 6", at + 1));
    }
    assert_eq!(world.coordinator.rows.lock().unwrap().len(), 5, "the sixth was not stored");

    // A count outside its bounds opens nothing.
    for count in [json!(0), json!(11), json!("6"), Value::Null] {
        let (refused, _) = world.run(AGENT, true, "run-b", json!({ "operation": "prepare_many", "count": count })).await;
        let refused = answer(&refused);
        assert!(refused["error"].as_str().unwrap().starts_with("invalid_request: "), "{refused}");
    }
    assert_eq!(world.coordinator.rows.lock().unwrap().len(), 5);
}

#[tokio::test(flavor = "multi_thread")]
#[cfg_attr(debug_assertions, ignore = "task runs need a release build: reqwest's blocking client asserts in debug that it is outside a tokio runtime")]
async fn a_task_prepared_for_the_slow_answer_is_answered_by_it_and_by_no_other() {
    let world = World::start();
    let (prepared, _) = world
        .run(AGENT, true, "run-a", json!({ "operation": "prepare", "body": "Slowly", "answer_by": "confirm_slow", "seconds": 1 }))
        .await;
    let prepared = answer(&prepared);
    assert_eq!(prepared["output"]["status"], "awaiting_owner", "{prepared}");
    let (shown, hash) = world.page_reads("run-a-0");
    assert_eq!(shown["answer_by"], json!({ "operation": "confirm_slow", "supplies": "nothing" }));

    let refusal = |result: (ExecutionResult, RunReport)| {
        let answer = answer(&result.0);
        assert_eq!(answer["success"], false, "{answer}");
        assert!(result.1.tasks().is_empty(), "a refused answer took no task");
        answer["error"].as_str().expect("a sentence").to_string()
    };
    let input = world.approved("run-a-0", &hash, "run-o", "confirm_slow", None, None);
    // Through `confirm`, and through the operations that answer for `confirm`.
    for operation in ["confirm", "confirm_silent", "confirm_trap"] {
        let mut through = input.clone();
        through["operation"] = json!(operation);
        assert!(refusal(world.run(AGENT, true, "run-o", through).await).starts_with("task_answer_invalid: "), "{operation}");
    }
    // A time outside its bounds is refused before the answer is taken.
    for seconds in [json!(0), json!(171), Value::Null] {
        let mut timed = input.clone();
        timed["seconds"] = seconds;
        assert!(refusal(world.run(AGENT, true, "run-o", timed).await).starts_with("invalid_request: "));
    }
    assert_eq!(world.coordinator.row("run-a-0").state, "approved");

    let began = std::time::Instant::now();
    let mut timed = input.clone();
    timed["seconds"] = json!(1);
    let (slow, report) = world.run(AGENT, true, "run-o", timed).await;
    let took = began.elapsed();
    let slow_answer = answer(&slow);
    assert_eq!(slow_answer["output"]["status"], "done", "{slow_answer}");
    assert_eq!(slow_answer["output"]["result"]["acted_on"]["body"], "Slowly");
    // The second passed on the host's clock and on the guest's, and was
    // waited, not computed: the run's instructions are those of any answer.
    assert!(took >= std::time::Duration::from_secs(1), "the run took {took:?}");
    assert!(slow_answer["output"]["result"]["worked_ms"].as_u64().unwrap() >= 1000, "{slow_answer}");
    assert!(slow.instructions < 100_000_000, "the wait cost {} instructions", slow.instructions);
    assert_eq!(world.coordinator.row("run-a-0").state, "answering");
    world.coordinator.finish("run-o", slow.success, &report);

    let (status, _) = world.run(AGENT, true, "run-b", json!({ "operation": "task_status", "task_id": "run-a-0" })).await;
    let status = answer(&status);
    assert_eq!((status["output"]["state"].as_str(), status["output"]["run"].as_str()), (Some("done"), Some("run-o")), "{status}");
    assert_eq!(status["output"]["result"]["acted_on"]["body"], "Slowly");
}

#[tokio::test(flavor = "multi_thread")]
#[cfg_attr(debug_assertions, ignore = "task runs need a release build: reqwest's blocking client asserts in debug that it is outside a tokio runtime")]
async fn a_task_names_the_operation_that_answers_it_among_the_probes_own() {
    let world = World::start();
    // A task that names `confirm_silent` is answered by it and ends failed.
    let (prepared, _) = world.run(AGENT, true, "run-a", json!({ "operation": "prepare", "answer_by": "confirm_silent" })).await;
    let hash = answer(&prepared)["output"]["task_hash"].as_str().unwrap().to_string();
    let input = world.approved("run-a-0", &hash, "run-o", "confirm_silent", None, None);
    let (silent, report) = world.run(AGENT, true, "run-o", input).await;
    assert_eq!(answer(&silent)["output"]["status"], "answered_and_not_reported");
    world.coordinator.finish("run-o", silent.success, &report);
    assert_eq!(world.coordinator.row("run-a-0").state, "failed");

    // A task that names no operation is `confirm`'s, and `confirm_silent`
    // cannot answer it: the host holds the answer to the operation running.
    let (prepared, _) = world.run(AGENT, true, "run-b", json!({ "operation": "prepare" })).await;
    let hash = answer(&prepared)["output"]["task_hash"].as_str().unwrap().to_string();
    let input = world.approved("run-b-0", &hash, "run-p", "confirm_silent", None, None);
    let (silent, report) = world.run(AGENT, true, "run-p", input).await;
    let said = answer(&silent)["error"].as_str().unwrap_or_default().to_string();
    assert!(said.starts_with("task_answer_invalid: "), "{said}");
    assert!(report.tasks().is_empty());
    assert_eq!(world.coordinator.row("run-b-0").state, "approved");

    // A name that is none of the probe's, or a name on a task that is
    // answered by `supply`, opens nothing.
    for input in [json!({ "answer_by": "send" }), json!({ "answer_by": 7 }), json!({ "kind": "text", "answer_by": "confirm_slow" })] {
        let mut input = input;
        input["operation"] = json!("prepare");
        let (refused, _) = world.run(AGENT, true, "run-c", input).await;
        let refused = answer(&refused);
        assert!(refused["error"].as_str().unwrap().starts_with("invalid_request: "), "{refused}");
    }
    assert_eq!(world.coordinator.rows.lock().unwrap().len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
#[cfg_attr(debug_assertions, ignore = "task runs need a release build: reqwest's blocking client asserts in debug that it is outside a tokio runtime")]
async fn the_probes_notice_reaches_the_owner_needs_no_key_and_takes_no_answer() {
    let world = World::start();
    // A run with no payment key — one on chain — notifies.
    let (told, report) = world
        .run(AGENT, true, "run-n", json!({ "operation": "notify", "title": "The email was sent", "body": "To Bob", "nonce": null }))
        .await;
    let told = answer(&told);
    let out = &told["output"];
    assert_eq!((out["status"].as_str(), out["task_id"].as_str(), out["devices"].as_u64()), (Some("notified"), Some("run-n-0"), Some(1)), "{told}");
    assert!(report.tasks().is_empty());
    // The store was told no voucher and no reply key.
    let row = world.coordinator.row("run-n-0");
    assert_eq!((row.request["kind"].as_str(), &row.request["voucher"], &row.request["reply_pubkey"]), (Some("notice"), &Value::Null, &Value::Null));
    // The owner's page reads it, and it names no answer.
    let (shown, hash) = world.page_reads("run-n-0");
    assert_eq!(hash, out["task_hash"].as_str().unwrap());
    assert_eq!((shown["kind"].as_str(), shown["display"]["title"].as_str()), (Some("notice"), Some("The email was sent")));
    assert!(shown.get("answer_by").is_none() && shown.get("reply_pubkey").is_none(), "{shown}");
    let (status, _) = world.run(AGENT, true, "run-b", json!({ "operation": "task_status", "task_id": "run-n-0" })).await;
    let status = answer(&status);
    assert_eq!((status["output"]["state"].as_str(), status["output"]["kind"].as_str()), (Some("open"), Some("notice")), "{status}");
    // An operation that takes an answer is refused it, and nothing moves.
    let input = json!({ "operation": "confirm", "task_id": "run-n-0", "task_hash": hash, "approval": world.signed("run-n-0", &hash, None, None) });
    let (refused, report) = world.run(AGENT, true, "run-o", input).await;
    let refused = answer(&refused);
    assert_eq!(refused["success"], false);
    assert!(refused["error"].as_str().unwrap().starts_with("task_answer_invalid"), "{refused}");
    assert!(report.refusals().is_empty() && report.tasks().is_empty());
    assert_eq!(world.coordinator.row("run-n-0").state, "open");
    // `prepare` of a notice that names an operation is refused before anything is made.
    let (named, _) = world.run(AGENT, true, "run-x", json!({ "operation": "prepare", "kind": "notice", "answer_by": "confirm" })).await;
    assert_eq!(answer(&named)["success"], false);
}
