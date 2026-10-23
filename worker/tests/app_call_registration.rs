/// A run's call token: minted here, registered with the coordinator and the
/// keystore by hash, revoked from both. The two services are stand-ins that record
/// what they were sent.
use std::{
    io::{Read, Write},
    sync::{Arc, Mutex},
};

use offchainvm_worker::{
    api_client::ApiClient,
    app_call::{envelope, AppCall, Scope},
    keystore_client::KeystoreClient,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn read_request(stream: &mut std::net::TcpStream) -> Option<(String, String, Value)> {
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
    let auth = head
        .lines()
        .find_map(|l| l.split_once(':').filter(|(n, _)| n.eq_ignore_ascii_case("authorization")).map(|(_, v)| v.trim().to_string()))
        .unwrap_or_default();
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
    Some((path, auth, if body.is_empty() { Value::Null } else { serde_json::from_slice(body).ok()? }))
}

/// One recorded request: path, Authorization header, body.
type Seen = Arc<Mutex<Vec<(String, String, Value)>>>;

/// A service answering `status` to everything, recording what it saw.
fn service(status: u16) -> (String, Seen) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("addr"));
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let Some(req) = read_request(&mut stream) else { continue };
            log.lock().unwrap().push(req);
            let body = "{}";
            let response = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    (url, seen)
}

fn scope() -> Scope {
    Scope {
        project_uuid: Some("p-uuid".into()),
        project_id: Some("alice.testnet/app".into()),
        wasm_hash: "abc123".into(),
        account_id: "bob.testnet".into(),
        wallet_id: Some("w1".into()),
        connector_id: None,
        call_id: Some("call-1".into()),
        request_id: Some(7),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_token_is_registered_with_both_services_and_revoked_from_both() {
    let (coord_url, coord) = service(201);
    let (ks_url, ks) = service(200);
    let api = ApiClient::new(coord_url, "coord-token".into()).expect("api client");
    let keystore = KeystoreClient::new(vec![ks_url], "ks-token".into()).expect("keystore client");

    let call = AppCall::begin(&api, Some(&keystore), scope(), 180).await.expect("begin").expect("a token");
    let token = call.token().to_string();
    assert!(token.starts_with("act_") && token.len() == 4 + 43, "{token}");
    let hash = hex::encode(Sha256::digest(token.as_bytes()));

    {
        let c = coord.lock().unwrap();
        assert_eq!(c.len(), 1);
        let (path, auth, body) = &c[0];
        assert_eq!(path, "/app-calls/register");
        assert_eq!(auth, "Bearer coord-token", "registered over the worker's own token");
        assert_eq!(body["token_hash"], hash, "the hash, never the token");
        assert_eq!(body["ttl_seconds"], 240, "the run's limit plus the margin");
        assert_eq!(body["scope"]["project_uuid"], "p-uuid");
        assert_eq!(body["scope"]["project_id"], "alice.testnet/app");
        assert_eq!(body["scope"]["wasm_hash"], "abc123");
        assert_eq!(body["scope"]["account_id"], "bob.testnet");
        assert_eq!(body["scope"]["wallet_id"], "w1");
        assert_eq!(body["scope"]["call_id"], "call-1");
        assert_eq!(body["scope"]["request_id"], 7);
        assert!(body.to_string().find(&token).is_none(), "the token itself never reaches the coordinator");
    }
    {
        let k = ks.lock().unwrap();
        assert_eq!(k.len(), 1);
        let (path, auth, body) = &k[0];
        assert_eq!(path, "/app-calls/register");
        assert_eq!(auth, "Bearer ks-token");
        assert_eq!(body["token_hash"], hash);
        assert_eq!(body["ttl_seconds"], 240);
        assert_eq!(body["scope"], serde_json::json!({
            "project_uuid": "p-uuid", "wasm_hash": "abc123", "account_id": "bob.testnet", "call_id": "call-1"
        }), "the keystore gets the storage cell only");
    }

    call.end(&api, Some(&keystore)).await;
    let c = coord.lock().unwrap();
    let k = ks.lock().unwrap();
    assert_eq!(c[1].0, "/app-calls/revoke");
    assert_eq!(c[1].2["token_hash"], hash);
    assert_eq!(k[1].0, "/app-calls/revoke");
    assert_eq!(k[1].2["token_hash"], hash);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_keystore_refusal_fails_the_run_and_revokes_the_coordinator_half() {
    let (coord_url, coord) = service(201);
    let (ks_url, _ks) = service(500);
    let api = ApiClient::new(coord_url, "t".into()).expect("api client");
    let keystore = KeystoreClient::new(vec![ks_url], "t".into()).expect("keystore client");

    let err = AppCall::begin(&api, Some(&keystore), scope(), 10).await.err().expect("the keystore refused");
    assert!(format!("{err:#}").contains("keystore"), "{err:#}");
    let c = coord.lock().unwrap();
    assert_eq!(c.iter().map(|(p, _, _)| p.as_str()).collect::<Vec<_>>(), ["/app-calls/register", "/app-calls/revoke"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_coordinator_refusal_fails_the_run_before_the_keystore_is_asked() {
    let (coord_url, _coord) = service(409);
    let (ks_url, ks) = service(200);
    let api = ApiClient::new(coord_url, "t".into()).expect("api client");
    let keystore = KeystoreClient::new(vec![ks_url], "t".into()).expect("keystore client");

    assert!(AppCall::begin(&api, Some(&keystore), scope(), 10).await.is_err(), "the coordinator refused");
    assert!(ks.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn no_caller_identity_means_no_token_and_no_requests() {
    let (coord_url, coord) = service(201);
    let api = ApiClient::new(coord_url, "t".into()).expect("api client");
    let no_account = Scope { account_id: String::new(), ..scope() };
    assert!(AppCall::begin(&api, None, no_account, 10).await.expect("begin").is_none());
    assert!(coord.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn without_a_keystore_only_the_coordinator_is_told() {
    let (coord_url, coord) = service(201);
    let api = ApiClient::new(coord_url, "t".into()).expect("api client");
    let call = AppCall::begin(&api, None, scope(), 10).await.expect("begin").expect("a token");
    let meta = std::collections::HashMap::from([("NEAR_SENDER_ID".to_string(), "bob.testnet".to_string())]);
    let env = envelope(&meta, "https://api.example", Some(call.token()), b"{}");
    let v: Value = serde_json::from_slice(&env).unwrap();
    assert_eq!(v["meta"]["OUTLAYER_CALL_TOKEN"], call.token());
    call.end(&api, None).await;
    assert_eq!(coord.lock().unwrap().len(), 2);
}
