//! An in-process HTTP server standing in for the coordinator or the keystore
//! in the storage tests: it answers each request from a closure and records
//! the path and JSON body of everything it was sent.

use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use super::client::StorageConfig;

/// One request the server received.
#[derive(Clone, Debug)]
pub struct Seen {
    /// Path with its query string.
    pub path: String,
    /// JSON body, `Null` when the request had none.
    pub body: serde_json::Value,
}

/// A running fake server.
pub struct FakeServer {
    pub url: String,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl FakeServer {
    /// Everything the server was sent so far, in order.
    pub fn seen(&self) -> Vec<Seen> {
        self.seen.lock().expect("seen lock").clone()
    }
}

/// Start a server answering every request with `respond(path, body)` as
/// `(status, JSON body)`. It lives until the test process exits.
pub fn serve<F>(respond: F) -> FakeServer
where
    F: Fn(&str, &serde_json::Value) -> (u16, String) + Send + 'static,
{
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("addr"));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&seen);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let Some((path, body)) = read_request(&mut stream) else { continue };
            recorded.lock().expect("seen lock").push(Seen { path: path.clone(), body: body.clone() });
            let (code, reply) = respond(&path, &body);
            let response = format!(
                "HTTP/1.1 {code} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                reply.len()
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    FakeServer { url, seen }
}

/// Read one request: the request line's path and the JSON body sized by
/// `Content-Length`.
fn read_request(stream: &mut std::net::TcpStream) -> Option<(String, serde_json::Value)> {
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
    let content_length = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim().eq_ignore_ascii_case("content-length").then(|| value.trim().parse::<usize>().ok())?
        })
        .unwrap_or(0);
    while data.len() < header_end + content_length {
        let n = stream.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buf[..n]);
    }
    let body_bytes = &data[header_end..(header_end + content_length).min(data.len())];
    let body = if body_bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(body_bytes).ok()?
    };
    Some((path, body))
}

/// A storage config for account `agent.near` in project `p-test`, talking to
/// the given coordinator and keystore.
pub fn config(coordinator: &FakeServer, keystore: &FakeServer) -> StorageConfig {
    StorageConfig {
        coordinator_url: coordinator.url.clone(),
        coordinator_token: "coordinator-test-token".to_string(),
        keystore_url: keystore.url.clone(),
        keystore_token: "keystore-test-token".to_string(),
        project_uuid: "p-test".to_string(),
        wasm_hash: "wasm-test".to_string(),
        account_id: "agent.near".to_string(),
        keystore_tee_session_id: None,
    }
}

/// A keystore that must not be called: it answers 500 and records the call.
pub fn untouched_keystore() -> FakeServer {
    serve(|_, _| (500, r#"{"error":"the keystore is not part of this path"}"#.to_string()))
}

/// SHA-256 of `key`, hex — the key hash both modes store under.
pub fn key_hash(key: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(key.as_bytes()))
}

/// The JSON byte array serde writes for `bytes`.
pub fn bytes_json(bytes: &[u8]) -> serde_json::Value {
    serde_json::Value::from(bytes.iter().map(|b| serde_json::Value::from(*b)).collect::<Vec<_>>())
}

/// The coordinator's 409 answer for a write in the other mode.
pub fn mode_mismatch(stored_is_encrypted: bool) -> (u16, String) {
    (
        409,
        serde_json::json!({ "error": "storage_mode_mismatch", "stored_is_encrypted": stored_is_encrypted }).to_string(),
    )
}
