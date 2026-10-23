//! The Defuse Outlayer core as the execution engine.
//!
//! Their runtime, their WASI allowlist and egress policy, `outlayer:crypto`
//! through [`KeystoreSigner`](crate::app_crypto::KeystoreSigner). The App ID is
//! the one their core gives inline code, so it is bound to the wasm bytes: a
//! new build is a new App ID and new keys. The environment is empty and none of
//! our host packages is linked; a component importing one fails to instantiate.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result};
use bytes::Bytes;
use defuse_outlayer_executor::{
    CancelToken, Context, Executor, ExecutorConfig, Host, HostContext, IoLimits,
};
use defuse_outlayer_service::AppCodeUrl;
use defuse_outlayer_signer::Signer;
use tracing::info;

use crate::api_client::ResourceLimits;

pub struct DefuseCore {
    executor: Executor,
    signer: Arc<dyn Signer>,
    print_wasm_stderr: bool,
}

impl DefuseCore {
    pub fn new(
        signer: Arc<dyn Signer>,
        memory_limit_mb: u32,
        max_io_bytes: usize,
        print_wasm_stderr: bool,
    ) -> Result<Self> {
        let config = ExecutorConfig {
            wasm_memory_limit_bytes: usize::try_from(memory_limit_mb)?.saturating_mul(1024 * 1024),
            io_limits: IoLimits {
                stdin_bytes: max_io_bytes,
                stdout_bytes: max_io_bytes,
                ..IoLimits::default()
            },
            ..ExecutorConfig::default()
        };
        Ok(Self {
            executor: config.build().context("Defuse core executor")?,
            signer,
            print_wasm_stderr,
        })
    }

    /// Output and fuel consumed.
    pub async fn execute(&self, wasm: &[u8], input: &[u8], limits: &ResourceLimits) -> Result<(Vec<u8>, u64)> {
        let component = self.executor.compiler().compile(wasm)?;
        let app_id = AppCodeUrl::from_code(wasm).immutable_app_id();
        info!("Defuse core: app {}", app_id);
        let host = Host::new(HostContext { app_id }, self.signer.clone());
        let (cancel, guard) = CancelToken::new();
        let ctx = Context { input: Bytes::copy_from_slice(input), host, cancel };

        // A guest busy in wasm never yields, so a timeout around the future would not
        // fire; the core's epoch check notices the guard instead, from another task.
        let seconds = limits.max_execution_seconds.max(1);
        let deadline = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(seconds)).await;
            drop(guard);
        });
        let outcome = self.executor.execute(ctx, &component, limits.max_instructions).await;
        let timed_out = deadline.is_finished();
        deadline.abort();
        let succeeded = matches!(&outcome, Ok(o) if o.execution.error.is_none());
        if timed_out && !succeeded {
            anyhow::bail!("Execution exceeded {} seconds", seconds);
        }
        let outcome = outcome?;

        if self.print_wasm_stderr && !outcome.logs.is_empty() {
            info!("WASM stderr: {}", String::from_utf8_lossy(&outcome.logs));
        }
        let fuel = outcome.execution.details.fuel_consumed;
        let output = outcome.into_result().map_err(anyhow::Error::msg)?;
        Ok((output.to_vec(), fuel))
    }
}
