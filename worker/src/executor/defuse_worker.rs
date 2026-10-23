//! The Defuse Outlayer worker beside ours, reached over gRPC inside the CVM.
//!
//! A job goes to its `OutlayerService/Call` with the wasm inline, so its runtime,
//! WASI allowlist, limits and egress policy apply, and the App ID is the one it
//! gives inline code, a function of the wasm bytes. The environment is empty and
//! none of our host packages is linked there.
//!
//! `outlayer:crypto` is refused before the call: the sidecar signs from a seed that
//! is not bound to the TEE, so nothing may hold value under those keys.

use std::time::Duration;

use anyhow::{Context as _, Result};
use defuse_outlayer_proto::{
    code, outlayer_service_client::OutlayerServiceClient, request, response, Code, ExecuteRequest,
    Request,
};
use tonic::transport::{Channel, Endpoint};
use tracing::info;

use crate::api_client::ResourceLimits;

/// Added to the job's deadline so the sidecar's own `DEADLINE_EXCEEDED`, which stops
/// the guest, arrives before ours would.
const DEADLINE_GRACE: Duration = Duration::from_secs(2);

pub struct DefuseWorker {
    client: OutlayerServiceClient<Channel>,
    print_wasm_stderr: bool,
}

impl DefuseWorker {
    /// Connects lazily: the sidecar may still be starting when this worker does.
    pub fn connect(url: &str, print_wasm_stderr: bool) -> Result<Self> {
        let channel = Endpoint::from_shared(url.to_string())
            .with_context(|| format!("DEFUSE_WORKER_URL is not a URL: {url}"))?
            .connect_lazy();
        let client = OutlayerServiceClient::new(channel)
            .max_encoding_message_size(usize::MAX)
            .max_decoding_message_size(usize::MAX);
        Ok(Self { client, print_wasm_stderr })
    }

    /// Output and fuel consumed. A guest failure is an error, as with our runtime.
    pub async fn execute(&self, wasm: &[u8], input: &[u8], limits: &ResourceLimits) -> Result<(Vec<u8>, u64)> {
        if imports_outlayer_crypto(wasm) {
            anyhow::bail!(
                "outlayer:crypto is not available on OutLayer yet: the component imports it and cannot run here"
            );
        }

        let seconds = limits.max_execution_seconds.max(1);
        let mut request = tonic::Request::new(Request {
            kind: Some(request::Kind::Execute(ExecuteRequest {
                app: Some(Code { variant: Some(code::Variant::InlineCode(wasm.to_vec())) }),
                input: input.to_vec(),
                fuel: Some(limits.max_instructions),
            })),
        });
        request.set_timeout(Duration::from_secs(seconds) + DEADLINE_GRACE);

        let response = match self.client.clone().call(request).await {
            Ok(response) => response.into_inner(),
            // The sidecar's own deadline, or tonic's client-side timer (`Cancelled`,
            // "Timeout expired") — whichever fires first.
            Err(status) if matches!(status.code(), tonic::Code::DeadlineExceeded | tonic::Code::Cancelled) => {
                anyhow::bail!("Execution exceeded {} seconds", seconds)
            }
            Err(status) => anyhow::bail!("Defuse worker refused the call ({:?}): {}", status.code(), status.message()),
        };

        let Some(response::Kind::Execute(executed)) = response.kind else {
            anyhow::bail!("Defuse worker answered without an execution");
        };
        if self.print_wasm_stderr && !executed.logs.is_empty() {
            info!("WASM stderr: {}", String::from_utf8_lossy(&executed.logs));
        }
        let outcome = executed.execution.context("Defuse worker answered without an outcome")?;
        let fuel = outcome.details.map(|d| d.fuel_consumed).unwrap_or_default();
        if let Some(error) = outcome.error {
            anyhow::bail!("{error}");
        }
        Ok((executed.output, fuel))
    }
}

/// Whether a component imports any `outlayer:crypto/*` interface. Read from the
/// bytes, before anything is compiled or sent.
pub fn imports_outlayer_crypto(wasm: &[u8]) -> bool {
    wasmparser::Parser::new(0).parse_all(wasm).any(|payload| match payload {
        Ok(wasmparser::Payload::ComponentImportSection(reader)) => reader
            .into_iter()
            .flatten()
            .any(|import| import.name.0.starts_with("outlayer:crypto/")),
        _ => false,
    })
}
