/// Jobs on the Defuse Outlayer worker beside ours.
///
/// The sidecar is private code: the tests that need it run only when
/// `DEFUSE_WORKER_BIN` names its binary (built from their repository at the pinned
/// tag). Without it they are skipped, loudly. The import refusal needs no sidecar.
///
/// Run with: DEFUSE_WORKER_BIN=/path/to/outlayer-worker cargo test --test defuse_worker
use std::{path::PathBuf, process::Stdio, time::Duration};

use offchainvm_worker::{
    api_client::{ExecutionOutput, ExecutionResult, ResourceLimits, ResponseFormat},
    executor::{defuse_worker::{imports_outlayer_crypto, DefuseWorker}, Executor},
};

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

/// A component that imports nothing of ours and nothing of `outlayer:crypto`.
fn plain_probe() -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("wasi-examples/defuse-core-probe/target/wasm32-wasip2/release/defuse-plain-probe.wasm");
    if !path.exists() {
        panic!("Test WASM not found at {}! Build it first:\ncd ../wasi-examples/defuse-core-probe && ./build.sh", path.display());
    }
    std::fs::read(&path).expect("read the probe")
}

#[test]
fn the_probe_imports_outlayer_crypto_and_echo_does_not() {
    assert!(imports_outlayer_crypto(&probe()));
    assert!(!imports_outlayer_crypto(&plain_probe()));
    assert!(!imports_outlayer_crypto(b"not wasm"));
}

/// The sidecar process for one test, on a free port, in test mode.
struct Sidecar {
    child: std::process::Child,
    url: String,
}

impl Sidecar {
    fn start() -> Option<Self> {
        let Ok(bin) = std::env::var("DEFUSE_WORKER_BIN") else {
            eprintln!("SKIPPED: set DEFUSE_WORKER_BIN to the Defuse Outlayer worker binary");
            return None;
        };
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let child = std::process::Command::new(bin)
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("OUTLAYER__LOG", "warn")
            .env("OUTLAYER__SEED", "00".repeat(32))
            .env("OUTLAYER__GRPC_SERVER__ADDR", format!("127.0.0.1:{port}"))
            .env("OUTLAYER__GRPC__MAX_REQUEST_BYTES", (64 * 1024 * 1024).to_string())
            .env("OUTLAYER__GRPC__REQUEST_HANDLING_TIMEOUT_SECONDS", "30")
            .env("OUTLAYER__SERVICE__ALLOW_UNDEPLOYED_CODE", "true")
            .env("OUTLAYER__SERVICE__EXECUTOR__IO_LIMITS__STDIN_BYTES", (1024 * 1024).to_string())
            .env("OUTLAYER__TELEMETRY__ENABLED", "false")
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn the Defuse worker");
        let url = format!("http://127.0.0.1:{port}");
        // Ready when the port accepts a connection.
        for _ in 0..100 {
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return Some(Self { child, url });
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("the Defuse worker did not listen on {port} within 10 s");
    }
}

impl Drop for Sidecar {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn limits(max_instructions: u64, max_execution_seconds: u64) -> ResourceLimits {
    ResourceLimits { max_instructions, max_memory_mb: 64, max_execution_seconds }
}

async fn run(sidecar: &Sidecar, wasm: &[u8], input: &[u8], limits: &ResourceLimits) -> ExecutionResult {
    let worker = DefuseWorker::connect(&sidecar.url, 10 * 1024 * 1024, false).await.expect("client");
    Executor::new(FUEL, false)
        .with_defuse_worker(worker)
        .execute(wasm, None, input, limits, None, None, &ResponseFormat::Text, None, None, None, None)
        .await
        .expect("execute")
}

#[tokio::test(flavor = "multi_thread")]
async fn a_job_runs_on_the_sidecar() {
    let Some(sidecar) = Sidecar::start() else { return };
    let result = run(&sidecar, &plain_probe(), b"echo hello", &limits(FUEL, 10)).await;
    assert!(result.success, "{:?}", result.error);
    assert!(result.instructions > 0, "fuel is reported");
    assert!(matches!(result.output, Some(ExecutionOutput::Text(ref t)) if t == "hello"), "{:?}", result.output);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_component_importing_outlayer_crypto_is_refused_before_the_call() {
    let Some(sidecar) = Sidecar::start() else { return };
    let result = run(&sidecar, &probe(), b"echo hi", &limits(FUEL, 10)).await;
    assert!(!result.success);
    assert!(result.error.as_deref().unwrap_or_default().contains("outlayer:crypto is not available"), "{:?}", result.error);
}

#[tokio::test(flavor = "multi_thread")]
async fn time_runs_out_on_the_sidecar() {
    let Some(sidecar) = Sidecar::start() else { return };
    let result = run(&sidecar, &plain_probe(), b"spin", &limits(1_000_000_000_000, 1)).await;
    assert!(!result.success);
    assert_eq!(result.error.as_deref(), Some("Execution exceeded 5 seconds"), "the floor is five seconds, as on our runtime");
    assert_eq!(result.instructions, 1_000_000_000_000, "a timeout spends the whole limit");
}

#[tokio::test(flavor = "multi_thread")]
async fn fuel_runs_out_on_the_sidecar() {
    let Some(sidecar) = Sidecar::start() else { return };
    // Enough fuel to instantiate, not enough to spin for long. (A budget too small to
    // instantiate comes back as the sidecar's `InvalidArgument: instantiate` instead.)
    let result = run(&sidecar, &plain_probe(), b"spin", &limits(10_000_000, 10)).await;
    assert!(!result.success);
    assert!(result.error.as_deref().unwrap_or_default().to_lowercase().contains("fuel"), "{:?}", result.error);
}

/// The OutLayer SDK built for the Defuse engine reads the envelope the worker sends.
mod sdk_on_the_sidecar {
    use std::collections::HashMap;

    use offchainvm_worker::app_call::envelope;

    use super::*;

    fn storage_probe() -> Vec<u8> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("wasi-examples/defuse-storage-probe/target/wasm32-wasip2/release/defuse-storage-probe.wasm");
        if !path.exists() {
            panic!("Test WASM not found at {}! Build it first:\ncd ../wasi-examples/defuse-storage-probe && ./build.sh", path.display());
        }
        std::fs::read(&path).expect("read the probe")
    }

    fn meta() -> HashMap<String, String> {
        [("NEAR_SENDER_ID", "bob.testnet"), ("OUTLAYER_PROJECT_ID", "alice.testnet/app")]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    async fn text(result: ExecutionResult) -> String {
        assert!(result.success, "{:?}", result.error);
        match result.output {
            Some(ExecutionOutput::Text(t)) => t,
            other => panic!("not text: {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_guest_sees_meta_and_the_caller_input() {
        let Some(sidecar) = Sidecar::start() else { return };
        let wasm = storage_probe();
        let run = |input: &str| {
            let bytes = envelope(&meta(), "https://api.example", Some("act_test"), input.as_bytes());
            let sidecar = &sidecar;
            let wasm = wasm.clone();
            async move { text(super::run(sidecar, &wasm, &bytes, &limits(FUEL, 10)).await).await }
        };
        assert_eq!(run("echo hello world").await, "hello world");
        assert_eq!(run("var NEAR_SENDER_ID").await, "bob.testnet");
        assert_eq!(run("sender").await, "bob.testnet");
        assert_eq!(run("var OUTLAYER_CALL_TOKEN").await, "act_test");
        assert_eq!(run("var NOPE").await, "<unset>");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn storage_without_a_registered_cell_says_why() {
        let Some(sidecar) = Sidecar::start() else { return };
        let bytes = envelope(&meta(), "https://api.example", None, b"get k");
        let out = text(run(&sidecar, &storage_probe(), &bytes, &limits(FUEL, 10)).await).await;
        assert!(out.starts_with("error: ") && out.contains("is not set"), "{out}");
    }
}


/// A stand-in sidecar speaking their protocol, for the answers the real one gives
/// rarely: a guest trap with fuel spent, a refusal, a dropped stream, a run that
/// never ends. What the worker reports and charges for each is the point.
mod fake_sidecar {
    use std::time::Duration;

    use defuse_outlayer_proto::{
        outlayer_service_server::{OutlayerService, OutlayerServiceServer},
        response, ExecuteResponse, ExecutionDetails, ExecutionOutcome, Request as PbRequest, Response as PbResponse,
    };

    use super::*;

    #[derive(Clone)]
    enum Answer {
        GuestTrap { fuel: u64, logs: &'static str, error: &'static str },
        Status(tonic::Code, &'static str),
        Hang,
    }

    struct Fake(Answer);

    #[tonic::async_trait]
    impl OutlayerService for Fake {
        async fn call(&self, _req: tonic::Request<PbRequest>) -> Result<tonic::Response<PbResponse>, tonic::Status> {
            match self.0.clone() {
                Answer::GuestTrap { fuel, logs, error } => Ok(tonic::Response::new(PbResponse {
                    kind: Some(response::Kind::Execute(ExecuteResponse {
                        output: Vec::new(),
                        logs: logs.as_bytes().to_vec(),
                        execution: Some(ExecutionOutcome {
                            details: Some(ExecutionDetails { fuel_consumed: fuel }),
                            error: Some(error.to_string()),
                        }),
                    })),
                })),
                Answer::Status(code, message) => Err(tonic::Status::new(code, message)),
                Answer::Hang => {
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                    unreachable!()
                }
            }
        }
    }

    async fn serve(answer: Answer) -> String {
        let addr = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        tokio::spawn(tonic::transport::Server::builder().add_service(OutlayerServiceServer::new(Fake(answer))).serve(addr));
        format!("http://{addr}")
    }

    async fn run(answer: Answer, limits: &ResourceLimits) -> ExecutionResult {
        let url = serve(answer).await;
        let worker = DefuseWorker::connect(&url, 1024 * 1024, false).await.expect("client");
        Executor::new(FUEL, false)
            .with_defuse_worker(worker)
            .execute(&plain_probe(), None, b"echo x", limits, None, None, &ResponseFormat::Text, None, None, None, None)
            .await
            .expect("execute")
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_guest_trap_is_charged_what_it_spent_and_shows_its_stderr() {
        let result = run(Answer::GuestTrap { fuel: 1234, logs: "panicked at main.rs:7\n", error: "wasm trap: unreachable" }, &limits(FUEL, 10)).await;
        assert!(!result.success);
        assert_eq!(result.instructions, 1234, "the fuel the sidecar counted");
        let error = result.error.unwrap();
        assert!(error.starts_with("panicked at main.rs:7\nTrap: wasm trap: unreachable"), "{error}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_sidecar_that_did_not_run_the_job_charges_nothing() {
        for (code, message) in [
            (tonic::Code::Unavailable, "shutting down"),
            (tonic::Code::ResourceExhausted, "service overloaded"),
            (tonic::Code::Cancelled, "stream reset"),
        ] {
            let result = run(Answer::Status(code, message), &limits(FUEL, 10)).await;
            assert!(!result.success);
            assert_eq!(result.instructions, 0, "{code:?}");
            assert!(result.error.as_deref().unwrap().contains("did not run the job"), "{:?}", result.error);
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_run_that_never_ends_is_a_timeout_with_the_full_penalty() {
        let result = run(Answer::Hang, &limits(FUEL, 1)).await;
        assert!(!result.success);
        assert_eq!(result.error.as_deref(), Some("Execution exceeded 5 seconds"), "the floor is five seconds, as on our runtime");
        assert_eq!(result.instructions, FUEL, "a timeout spends the whole limit");
    }
}
