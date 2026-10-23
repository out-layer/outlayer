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
use tracing::{info, warn};

use crate::api_client::ResourceLimits;
use crate::executor::sandbox::RunFailed;

/// Added to the job's deadline so the sidecar's own `DEADLINE_EXCEEDED`, which stops
/// the guest, arrives before ours would.
const DEADLINE_GRACE: Duration = Duration::from_secs(2);

/// A run is given at least this long, as on our own runtime.
const MIN_EXECUTION_SECONDS: u64 = 5;

/// What tonic's client-side timer says when it fires.
const CLIENT_TIMEOUT_MESSAGE: &str = "Timeout expired";

/// Headroom over the output cap for the reply's logs and framing.
const REPLY_OVERHEAD_BYTES: usize = 2 * 1024 * 1024;

/// How long the sidecar is given to come up next to this worker.
const STARTUP_ATTEMPTS: u32 = 60;

pub struct DefuseWorker {
    client: OutlayerServiceClient<Channel>,
    print_wasm_stderr: bool,
}

impl DefuseWorker {
    /// Connects, waiting for a sidecar that is still starting: a worker that
    /// advertised the engine before the engine answers would take jobs it fails.
    pub async fn connect(url: &str, max_output_bytes: usize, print_wasm_stderr: bool) -> Result<Self> {
        let endpoint = Endpoint::from_shared(url.to_string())
            .with_context(|| format!("DEFUSE_WORKER_URL is not a URL: {url}"))?
            .connect_timeout(Duration::from_secs(5));
        let mut last = None;
        for attempt in 1..=STARTUP_ATTEMPTS {
            match endpoint.connect().await {
                Ok(channel) => {
                    if attempt > 1 {
                        info!("Defuse worker answered at {url} after {attempt} attempts");
                    }
                    let client = OutlayerServiceClient::new(channel)
                        .max_encoding_message_size(usize::MAX)
                        .max_decoding_message_size(max_output_bytes.saturating_add(REPLY_OVERHEAD_BYTES));
                    return Ok(Self { client, print_wasm_stderr });
                }
                Err(e) => {
                    warn!("Defuse worker not reachable at {url} (attempt {attempt}/{STARTUP_ATTEMPTS}): {e}");
                    last = Some(e);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
        Err(anyhow::anyhow!("Defuse worker not reachable at {url}: {}", last.map(|e| e.to_string()).unwrap_or_default()))
    }

    /// Output and fuel consumed. A guest failure is a [`RunFailed`] with what it
    /// consumed, as on our own runtime; a timeout is a penalty; a sidecar that could
    /// not take the call is a plain error, charged to nobody.
    pub async fn execute(&self, wasm: &[u8], input: &[u8], limits: &ResourceLimits) -> Result<(Vec<u8>, u64)> {
        if imports_outlayer_crypto(wasm) {
            anyhow::bail!(
                "outlayer:crypto is not available on OutLayer yet: the component imports it and cannot run here"
            );
        }

        let seconds = limits.max_execution_seconds.max(MIN_EXECUTION_SECONDS);
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
            Err(status) if is_timeout(&status) => {
                return Err(RunFailed {
                    message: format!("Execution exceeded {} seconds", seconds),
                    instructions: limits.max_instructions,
                    penalty: true,
                }
                .into())
            }
            Err(status) => anyhow::bail!("Defuse worker did not run the job ({:?}): {}", status.code(), status.message()),
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
            // The guest's own stderr first, then the trap, as our runtime reports it.
            let stderr = String::from_utf8_lossy(&executed.logs);
            let message = if stderr.trim().is_empty() {
                format!("Trap: {error}")
            } else {
                format!("{}\nTrap: {error}", stderr.trim_end())
            };
            return Err(RunFailed { message, instructions: fuel, penalty: false }.into());
        }
        Ok((executed.output, fuel))
    }
}

/// The sidecar's own deadline, or tonic's client-side timer. Any other `Cancelled`
/// — a dropped connection, a sidecar restart — is not the guest's doing.
fn is_timeout(status: &tonic::Status) -> bool {
    match status.code() {
        tonic::Code::DeadlineExceeded => true,
        tonic::Code::Cancelled => status.message().contains(CLIENT_TIMEOUT_MESSAGE),
        _ => false,
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

/// A service the guest reaches from the sidecar must pass its egress policy:
/// `https`, port 443 only, a public multi-label name, no IP literal. Checked at
/// startup, where a wrong URL is a configuration error and not a guest's failure.
pub fn reachable_from_the_sidecar(url: &str) -> Result<()> {
    let parsed = url::Url::parse(url).with_context(|| format!("{url} is not a URL"))?;
    if parsed.scheme() != "https" {
        anyhow::bail!("{url}: the sidecar's egress policy allows https only");
    }
    if parsed.port().is_some_and(|p| p != 443) {
        anyhow::bail!("{url}: the sidecar's egress policy allows port 443 only");
    }
    match parsed.host() {
        Some(url::Host::Domain(d)) if d.contains('.') && !d.ends_with(".local") && !d.ends_with(".internal") => Ok(()),
        Some(url::Host::Domain(d)) => anyhow::bail!("{url}: the sidecar's egress policy refuses the name {d}"),
        _ => anyhow::bail!("{url}: the sidecar's egress policy refuses IP literals"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_deadline_or_the_client_timer_is_a_timeout() {
        assert!(is_timeout(&tonic::Status::deadline_exceeded("x")));
        assert!(is_timeout(&tonic::Status::cancelled("Timeout expired")));
        assert!(!is_timeout(&tonic::Status::cancelled("stream reset")));
        assert!(!is_timeout(&tonic::Status::unavailable("x")));
        assert!(!is_timeout(&tonic::Status::resource_exhausted("service overloaded")));
    }

    #[test]
    fn a_service_url_passes_the_sidecar_policy_or_is_refused_at_startup() {
        assert!(reachable_from_the_sidecar("https://api.outlayer.ai").is_ok());
        assert!(reachable_from_the_sidecar("https://abc-8081.dstack.example.com/").is_ok());
        assert!(reachable_from_the_sidecar("https://api.outlayer.ai:443").is_ok());
        for bad in [
            "http://api.outlayer.ai",
            "https://keystore:8081",
            "https://keystore",
            "https://10.0.0.5",
            "https://api.outlayer.ai:8443",
            "https://keystore.internal",
            "not a url",
        ] {
            assert!(reachable_from_the_sidecar(bad).is_err(), "{bad}");
        }
    }
}
