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
