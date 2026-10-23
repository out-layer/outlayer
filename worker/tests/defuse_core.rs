/// The Defuse Outlayer core running inside the worker's dependency tree.
/// Run with: cargo test --test defuse_core
use std::{path::PathBuf, sync::Arc};

use bytes::Bytes;
use defuse_outlayer_executor::{
    CancelToken, Context, Executor, ExecutorConfig, Host, HostContext, Outcome,
};
use defuse_outlayer_signer::InMemorySigner;

const FUEL: u64 = 1_000_000_000;

fn probe() -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("wasi-examples/defuse-core-probe/target/wasm32-wasip2/release/defuse-core-probe.wasm");
    if !path.exists() {
        panic!("Test WASM not found at {}! Build it first:\ncd ../wasi-examples/defuse-core-probe && ./build.sh", path.display());
    }
    std::fs::read(&path).expect("read the probe")
}

async fn run(executor: &Executor, input: &'static [u8]) -> Outcome {
    let component = executor.compiler().compile(probe()).expect("compile");
    let host = Host::new(
        HostContext { app_id: "near:test.near".parse().expect("app id") },
        Arc::new(InMemorySigner::from_seed(b"seed")),
    );
    let ctx = Context { input: Bytes::from_static(input), host, cancel: CancelToken::never() };
    executor.execute(ctx, &component, FUEL).await.expect("execute")
}

#[tokio::test(flavor = "multi_thread")]
async fn echo() {
    let executor = ExecutorConfig::default().build().expect("executor");
    let outcome = run(&executor, b"echo hello").await;
    assert!(outcome.execution.details.fuel_consumed > 0);
    assert_eq!(outcome.into_result().expect("result"), Bytes::from_static(b"hello"));
}

#[tokio::test(flavor = "multi_thread")]
async fn environment_is_empty() {
    let executor = ExecutorConfig::default().build().expect("executor");
    let outcome = run(&executor, b"env").await;
    assert_eq!(outcome.into_result().expect("result"), Bytes::from_static(b"0"));
}

#[tokio::test(flavor = "multi_thread")]
async fn monotonic_clock_traps() {
    let executor = ExecutorConfig::default().build().expect("executor");
    let outcome = run(&executor, b"clock").await;
    let error = outcome.into_result().expect_err("the clock must trap");
    assert!(error.contains("monotonic-clock is disabled"), "{error}");
}

mod keystore_signer {
    use std::io::{Read, Write};

    use defuse_outlayer_kdf_app::AppDerivation;
    use defuse_outlayer_signer::{
        kdf::{
            crypto::{
                ed25519::{ed25519_dalek, Ed25519},
                secp256k1::{k256, Secp256k1},
                Curve as _, RecoverableCurve as _,
            },
            DeriveSigner, RecoverableDeriveSigner, Schema,
        },
        MasterSchema,
    };
    use offchainvm_worker::{app_crypto::KeystoreSigner, keystore_client::KeystoreClient};
    use serde_json::{json, Value};

    use super::*;

    const APP_ID: &str = "near:app.test.near";
    const PATH: &str = "agent-key";

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

    /// The keystore's two routes, over the same signer the keystore builds.
    fn keystore(seed: &'static [u8]) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let url = format!("http://{}", listener.local_addr().expect("addr"));
        std::thread::spawn(move || {
            let signer = InMemorySigner::from_seed(seed);
            let rt = tokio::runtime::Builder::new_current_thread().build().expect("rt");
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let Some((path, body)) = read_request(&mut stream) else { continue };
                let reply = match path.as_str() {
                    "/crypto/root-public-keys" => json!({
                        "ed25519": hex::encode(signer.ed25519_master_public_key().as_bytes()),
                        "secp256k1": hex::encode(signer.secp256k1_master_public_key().to_sec1_bytes()),
                    }),
                    "/crypto/sign" => {
                        let path: [u8; 32] = hex::decode(body["path"].as_str().unwrap()).unwrap().try_into().unwrap();
                        let msg = hex::decode(body["message"].as_str().unwrap()).unwrap();
                        match body["curve"].as_str().unwrap() {
                            "ed25519" => {
                                let sig = rt.block_on(DeriveSigner::<Ed25519, _>::derive_sign(&signer, path, &msg)).unwrap();
                                json!({ "signature": hex::encode(sig.to_bytes()) })
                            }
                            _ => {
                                let (sig, v) = rt
                                    .block_on(RecoverableDeriveSigner::<Secp256k1, _>::derive_sign_recoverable(&signer, path, &msg))
                                    .unwrap();
                                json!({ "signature": hex::encode(sig.to_bytes()), "recovery_id": v.to_byte() })
                            }
                        }
                    }
                    _ => json!({ "error": "not found" }),
                };
                let reply = reply.to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                    reply.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        url
    }

    async fn run_with(signer: Arc<dyn defuse_outlayer_signer::Signer>, input: String) -> String {
        let executor = ExecutorConfig::default().build().expect("executor");
        let component = executor.compiler().compile(probe()).expect("compile");
        let host = Host::new(HostContext { app_id: APP_ID.parse().expect("app id") }, signer);
        let ctx = Context { input: Bytes::from(input), host, cancel: CancelToken::never() };
        let outcome = executor.execute(ctx, &component, FUEL).await.expect("execute");
        String::from_utf8(outcome.into_result().expect("result").to_vec()).expect("utf8")
    }

    async fn keystore_signer(seed: &'static [u8]) -> Arc<dyn defuse_outlayer_signer::Signer> {
        let client = KeystoreClient::new(vec![keystore(seed)], "token".to_string()).expect("client");
        Arc::new(KeystoreSigner::connect(Arc::new(client)).await.expect("connect"))
    }

    fn scoped() -> [u8; 32] {
        AppDerivation::new(APP_ID.parse().expect("app id")).derive(PATH)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn ed25519_offline_host_and_signature_agree() {
        let signer = keystore_signer(b"seed").await;
        let pk = run_with(signer.clone(), format!("ed25519-pk {PATH}")).await;

        let root = InMemorySigner::from_seed(b"seed").ed25519_master_public_key();
        let offline = MasterSchema::<Ed25519>::new(root).derive(scoped());
        assert_eq!(pk, hex::encode(offline.as_bytes()), "host and offline derivation differ");

        let in_memory = run_with(Arc::new(InMemorySigner::from_seed(b"seed")), format!("ed25519-pk {PATH}")).await;
        assert_eq!(pk, in_memory, "keystore-backed and in-memory signers differ");

        let msg = b"hello";
        let sig = run_with(signer, format!("ed25519-sign {PATH} {}", hex::encode(msg))).await;
        let sig = ed25519_dalek::Signature::from_slice(&hex::decode(sig).unwrap()).unwrap();
        assert!(Ed25519::verify(&offline, msg, &sig), "signature does not verify under the offline key");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn secp256k1_offline_host_and_signature_agree() {
        let signer = keystore_signer(b"seed").await;
        let pk = run_with(signer.clone(), format!("secp256k1-pk {PATH}")).await;

        let root = InMemorySigner::from_seed(b"seed").secp256k1_master_public_key();
        let offline = MasterSchema::<Secp256k1>::new(root).derive(scoped());
        assert_eq!(pk, hex::encode(offline.to_sec1_bytes()), "host and offline derivation differ");

        let prehash = [0x42u8; 32];
        let sig = hex::decode(run_with(signer, format!("secp256k1-sign {PATH} {}", hex::encode(prehash))).await).unwrap();
        let signature = k256::ecdsa::Signature::from_slice(&sig[..64]).unwrap();
        let v = k256::ecdsa::RecoveryId::from_byte(sig[64]).unwrap();
        assert!(Secp256k1::verify(&offline, &prehash, &signature), "signature does not verify under the offline key");
        assert_eq!(Secp256k1::recover(&prehash, &signature, v), Some(offline), "recovered key differs");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn another_app_gets_another_key() {
        let root = InMemorySigner::from_seed(b"seed").ed25519_master_public_key();
        let other = AppDerivation::new("near:other.test.near".parse().expect("app id")).derive(PATH);
        assert_ne!(
            MasterSchema::<Ed25519>::new(root).derive(scoped()),
            MasterSchema::<Ed25519>::new(root).derive(other)
        );
    }
}
