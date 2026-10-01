//! A component that imports `outlayer:wallet/api` on a run that named no
//! wallet starts, and every wallet call answers `no_wallet`.
//!
//! `wasi-examples/wallet-probe` must be built first (its `build.sh`); without
//! the artefact the test says so and checks nothing.

use offchainvm_worker::api_client::{ResourceLimits, ResponseFormat};
use offchainvm_worker::executor::Executor;

fn probe() -> Option<Vec<u8>> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../wasi-examples/wallet-probe/target/wasm32-wasip2/release/wallet-probe.wasm");
    match std::fs::read(&path) {
        Ok(bytes) => Some(bytes),
        Err(_) => {
            eprintln!("SKIPPED: build wasi-examples/wallet-probe first ({})", path.display());
            None
        }
    }
}

#[tokio::test]
async fn a_component_importing_the_wallet_starts_without_one_and_its_wallet_calls_answer_no_wallet() {
    let Some(wasm) = probe() else { return };
    let executor = Executor::new(10_000_000_000, false);
    let limits = ResourceLimits { max_instructions: 10_000_000_000, max_memory_mb: 128, max_execution_seconds: 60 };
    let env = [("NEAR_NETWORK_ID", "testnet")].into_iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    let result = executor
        .execute(
            &wasm,
            None,
            br#"{"operation":"whoami"}"#,
            &limits,
            Some(env),
            Some("wasm32-wasip2"),
            &ResponseFormat::Json,
            None,
            None,
            // No wallet: the run was not made with the wallet's own key and X-Wallet-Id.
            None,
            None,
        )
        .await
        .expect("the executor answers");
    // The guest ran: the refusal is its own answer, not a failure to start.
    let output = format!("{:?}", result.output);
    assert!(
        result.error.as_deref().map_or(true, |e| !e.contains("wallet is not available")),
        "refused before main: {:?}",
        result.error
    );
    assert!(output.contains("no_wallet"), "the wallet call answered something else: {output} / {:?}", result.error);
}
