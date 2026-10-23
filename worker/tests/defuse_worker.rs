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
    let worker = DefuseWorker::connect(&sidecar.url, false).expect("client");
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
    let result = run(&sidecar, &plain_probe(), b"spin", &limits(u64::MAX, 1)).await;
    assert!(!result.success);
    assert!(result.error.as_deref().unwrap_or_default().contains("exceeded 1 seconds"), "{:?}", result.error);
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
