//! WASM executor with support for multiple WASI versions
//!
//! This module provides execution for different WASM formats:
//! - WASI Preview 2 (P2): Modern component model with HTTP support
//! - WASI Preview 1 (P1): Standard WASI modules
//!
//! ## Adding New Build Targets
//!
//! To add support for a new build target (e.g., wasm32-unknown-unknown):
//!
//! 1. Create a new module file: `src/executor/wasi_unknown.rs`
//! 2. Implement the executor function with signature:
//!    ```rust,ignore
//!    pub async fn execute(
//!        wasm_bytes: &[u8],
//!        input_data: &[u8],
//!        limits: &ResourceLimits,
//!        env_vars: Option<HashMap<String, String>>,
//!        ctx: Option<&ExecutionContext>,
//!    ) -> Result<(Vec<u8>, u64)>
//!    ```
//! 3. Add module declaration: `mod wasi_unknown;`
//! 4. Add detection logic in `execute_async()` to try loading the new format
//! 5. Add unit tests in `tests/` directory
//!
//! ## Architecture
//!
//! The executor tries formats in order of priority:
//! 1. WASI P2 component (most modern, has HTTP)
//! 2. WASI P1 module (standard, widely compatible)
//! 3. Return error if no format matches

use anyhow::Result;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tracing::{info, warn};

use crate::api_client::{ExecutionOutput, ExecutionResult, ResourceLimits, ResponseFormat};
use crate::compiled_cache::CompiledCache;
use crate::outlayer_rpc::RpcProxy;
use crate::outlayer_storage::client::StorageConfig;

mod wasi_p1;
mod wasi_p2;

/// VRF configuration for host functions
#[derive(Clone)]
pub struct VrfConfig {
    pub keystore_url: String,
    pub keystore_auth_token: String,
    pub tee_session_id: Option<String>,
    pub request_id: u64,
    /// Signer account ID (included in alpha for per-user VRF binding)
    pub sender_id: String,
}

/// Outbound-network configuration for one execution (§C3).
///
/// Only WASI P2 can make outbound HTTP at all — P1 has no `wasi-http` and no
/// host function that reaches the network — so this is consumed by the P2
/// executor alone. A P1 module needs no allowlist because it has nothing to
/// allow.
#[derive(Clone)]
pub struct NetworkConfig {
    /// Domains the guest may reach, derived from the project's manifest at the
    /// pinned ref. Layered on top of the SSRF filter, never instead of it.
    pub policy: crate::connector_manifest::NetworkPolicy,
    /// Where the runtime records what the guest actually attempted. The caller
    /// owns the handle so it can read the log back after the guest exits and
    /// submit it to the audit — including for a run that trapped.
    pub egress_log: Arc<Mutex<Vec<crate::connector_manifest::EgressRecord>>>,
}

/// Wallet configuration for host functions
#[derive(Clone)]
pub struct WalletConfig {
    /// Wallet ID (e.g. "ed25519:abc..." from X-Wallet-Id header)
    pub wallet_id: String,
    /// Coordinator base URL for wallet API calls
    pub coordinator_url: String,
    /// Internal auth token for coordinator wallet API
    pub wallet_auth_token: String,
    /// `connector_id` from the running artefact's verified manifest; `None`
    /// for an ordinary project. Decides whether the guest may name sub-keys,
    /// and of which connector.
    pub connector_id: Option<String>,
}

/// Execution context with optional dependencies for WASM execution
///
/// This struct holds external services that WASM code can use through host functions.
/// Currently supports:
/// - RPC Proxy: Allows WASM to make NEAR RPC calls without exposing API keys
/// - Storage: Persistent storage for projects and standalone WASM
/// - Compiled Cache: Pre-compiled WASM components for ~10x faster startup
/// - VRF: Verifiable random function via keystore
#[derive(Clone)]
pub struct ExecutionContext {
    /// RPC proxy for NEAR blockchain access (only used in WASI P2)
    pub outlayer_rpc: Option<Arc<RpcProxy>>,
    /// Storage configuration for persistent storage (only used in WASI P2)
    pub storage_config: Option<StorageConfig>,
    /// Tokio runtime handle for async operations in host functions
    pub runtime_handle: tokio::runtime::Handle,
    /// Compiled component cache for fast WASM startup
    pub compiled_cache: Option<Arc<Mutex<CompiledCache>>>,
    /// VRF configuration (only used in WASI P2, requires keystore + request_id)
    pub vrf_config: Option<VrfConfig>,
    /// Wallet configuration (only used in WASI P2, requires wallet_id in execution request)
    pub wallet_config: Option<WalletConfig>,
    /// Outbound-domain allowlist and egress audit sink (only used in WASI P2)
    pub network_config: Option<NetworkConfig>,
}

impl ExecutionContext {
    /// Create a new execution context
    #[allow(dead_code)]
    pub fn new(runtime_handle: tokio::runtime::Handle) -> Self {
        Self {
            outlayer_rpc: None,
            storage_config: None,
            runtime_handle,
            compiled_cache: None,
            vrf_config: None,
            wallet_config: None,
            network_config: None,
        }
    }

    /// Create context with RPC proxy
    #[allow(dead_code)]
    pub fn with_outlayer_rpc(mut self, proxy: RpcProxy) -> Self {
        self.outlayer_rpc = Some(Arc::new(proxy));
        self
    }

    /// Create context with storage config
    #[allow(dead_code)]
    pub fn with_storage(mut self, config: StorageConfig) -> Self {
        self.storage_config = Some(config);
        self
    }

    /// Create context with compiled cache
    #[allow(dead_code)]
    pub fn with_compiled_cache(mut self, cache: Arc<Mutex<CompiledCache>>) -> Self {
        self.compiled_cache = Some(cache);
        self
    }

    /// Check if RPC proxy is available
    #[allow(dead_code)]
    pub fn has_outlayer_rpc(&self) -> bool {
        self.outlayer_rpc.is_some()
    }

    /// Check if storage is available
    #[allow(dead_code)]
    pub fn has_storage(&self) -> bool {
        self.storage_config.is_some()
    }
}

/// One execution carrying its signing keys — see [`Executor::with_signing_keys`].
pub struct RunWithKeys<'a> {
    executor: &'a Executor,
    signing_keys: Option<crate::signing_keys::SigningKeys>,
}

impl RunWithKeys<'_> {
    /// As [`Executor::execute`], with this run's signing keys.
    pub async fn execute(
        self,
        wasm_bytes: &[u8],
        wasm_content_sha256: Option<&str>,
        input_data: &[u8],
        limits: &ResourceLimits,
        env_vars: Option<HashMap<String, String>>,
        build_target: Option<&str>,
        response_format: &ResponseFormat,
        storage_config: Option<StorageConfig>,
        vrf_config: Option<VrfConfig>,
        wallet_config: Option<WalletConfig>,
        network_config: Option<NetworkConfig>,
    ) -> Result<ExecutionResult> {
        self.executor
            .execute_run(
                wasm_bytes,
                wasm_content_sha256,
                input_data,
                limits,
                env_vars,
                build_target,
                response_format,
                storage_config,
                vrf_config,
                wallet_config,
                network_config,
                self.signing_keys,
            )
            .await
    }
}

/// WASM executor supporting multiple WASI versions
pub struct Executor {
    /// Maximum instructions allowed per execution (default)
    _default_max_instructions: u64,
    /// Print WASM stderr to worker logs
    print_wasm_stderr: bool,
    /// Execution context with optional RPC proxy and other services
    context: Option<ExecutionContext>,
}

impl Executor {
    /// Create a new executor
    pub fn new(default_max_instructions: u64, print_wasm_stderr: bool) -> Self {
        Self {
            _default_max_instructions: default_max_instructions,
            print_wasm_stderr,
            context: None,
        }
    }

    /// Create executor with execution context
    #[allow(dead_code)]
    pub fn with_context(mut self, context: ExecutionContext) -> Self {
        self.context = Some(context);
        self
    }

    /// Execute WASM with input data
    ///
    /// Returns ExecutionResult with success/failure and optional output
    ///
    /// # Arguments
    /// * `wasm_bytes` - WASM binary to execute
    /// * `wasm_content_sha256` - SHA256 OF THE WASM BYTES, the compiled cache's key.
    ///   Never a coordinates-derived checksum: see `wasi_p2::execute`.
    /// * `input_data` - Input data passed to WASM via stdin
    /// * `limits` - Resource limits for execution
    /// * `env_vars` - Environment variables (from secrets)
    /// * `build_target` - Build target (wasm32-wasip1, wasm32-wasip2)
    /// * `response_format` - Output format (Bytes, Text, Json)
    /// * `storage_config` - Optional per-execution storage config (overrides context)
    /// * `vrf_config` - Optional per-execution VRF config (overrides context)
    /// * `wallet_config` - Optional per-execution wallet config (overrides context)
    /// * `network_config` - Per-execution outbound allowlist + egress audit sink
    ///
    /// A run with signing keys goes through [`Executor::with_signing_keys`],
    /// which is how the job path calls it; this is the entry for everything
    /// else (tests, tools).
    #[allow(dead_code)]
    pub async fn execute(
        &self,
        wasm_bytes: &[u8],
        wasm_content_sha256: Option<&str>,
        input_data: &[u8],
        limits: &ResourceLimits,
        env_vars: Option<HashMap<String, String>>,
        build_target: Option<&str>,
        response_format: &ResponseFormat,
        storage_config: Option<StorageConfig>,
        vrf_config: Option<VrfConfig>,
        wallet_config: Option<WalletConfig>,
        network_config: Option<NetworkConfig>,
    ) -> Result<ExecutionResult> {
        self.execute_run(
            wasm_bytes,
            wasm_content_sha256,
            input_data,
            limits,
            env_vars,
            build_target,
            response_format,
            storage_config,
            vrf_config,
            wallet_config,
            network_config,
            None,
        )
        .await
    }

    /// One run with this run's signing keys: they are moved in, reachable only
    /// through the `outlayer:signing-keys` host functions, and dropped with the
    /// run — never part of the long-lived execution context.
    pub fn with_signing_keys(&self, signing_keys: Option<crate::signing_keys::SigningKeys>) -> RunWithKeys<'_> {
        RunWithKeys { executor: self, signing_keys }
    }

    async fn execute_run(
        &self,
        wasm_bytes: &[u8],
        wasm_content_sha256: Option<&str>,
        input_data: &[u8],
        limits: &ResourceLimits,
        env_vars: Option<HashMap<String, String>>,
        build_target: Option<&str>,
        response_format: &ResponseFormat,
        storage_config: Option<StorageConfig>,
        vrf_config: Option<VrfConfig>,
        wallet_config: Option<WalletConfig>,
        network_config: Option<NetworkConfig>,
        signing_keys: Option<crate::signing_keys::SigningKeys>,
    ) -> Result<ExecutionResult> {
        info!(
            "Starting WASM execution: {} instructions, {} MB memory, {} seconds, target: {:?}, format: {:?}",
            limits.max_instructions, limits.max_memory_mb, limits.max_execution_seconds, build_target, response_format
        );

        let start = Instant::now();

        // Try to execute with different WASI versions
        let result = self.execute_async(wasm_bytes, wasm_content_sha256, input_data, limits, env_vars, build_target, storage_config, vrf_config, wallet_config, network_config, signing_keys).await;

        let execution_time_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok((output_bytes, instructions, refund_usd)) => {
                info!(
                    "WASM execution succeeded in {} ms, consumed {} instructions",
                    execution_time_ms, instructions
                );
                info!("📦 Raw output size: {} bytes", output_bytes.len());
                if let Some(refund) = refund_usd {
                    info!("💰 WASM requested refund of {} USD", refund);
                }

                if output_bytes.is_empty() {
                    warn!("⚠️ WASM produced empty output (stdout was empty)");
                }

                // Convert output based on requested format
                let output = match response_format {
                    ResponseFormat::Bytes => {
                        Some(ExecutionOutput::Bytes(output_bytes))
                    }
                    ResponseFormat::Text => {
                        let text = String::from_utf8(output_bytes)
                            .unwrap_or_else(|e| format!("Invalid UTF-8 output: {}", e));
                        Some(ExecutionOutput::Text(text))
                    }
                    ResponseFormat::Json => {
                        // Parse output as JSON
                        match serde_json::from_slice::<serde_json::Value>(&output_bytes) {
                            Ok(json_value) => {
                                Some(ExecutionOutput::Json(json_value))
                            }
                            Err(e) => {
                                // If JSON parsing fails, return error
                                return Ok(ExecutionResult {
                                    success: false,
                                    output: None,
                                    error: Some(format!(
                                        "Failed to parse output as JSON: {}. Output was: {}",
                                        e,
                                        String::from_utf8_lossy(&output_bytes)
                                    )),
                                    execution_time_ms,
                                    instructions,
                                    compile_time_ms: None, // Compilation not tracked in executor
                                    compilation_note: None,
                                    refund_usd: None,
                                });
                            }
                        }
                    }
                };

                Ok(ExecutionResult {
                    success: true,
                    output,
                    error: None,
                    execution_time_ms,
                    instructions,
                    compile_time_ms: None, // Compilation not tracked in executor
                    compilation_note: None,
                    refund_usd,
                })
            }
            Err(e) => {
                let error_str = e.to_string();
                info!("WASM execution failed: {}", error_str);

                let is_penalty = error_str.contains("(penalty)");

                // Penalty (timeout/HTTP abuse): charge max_instructions so full compute_limit is spent.
                // Normal errors: parse actual instructions from error message.
                let instructions = if is_penalty {
                    limits.max_instructions
                } else {
                    error_str
                        .split("consumed ")
                        .nth(1)
                        .and_then(|s| s.split(' ').next())
                        .and_then(|s| s.parse::<u64>().ok())
                        .unwrap_or(0)
                };

                Ok(ExecutionResult {
                    success: false,
                    output: None,
                    error: Some(error_str),
                    execution_time_ms,
                    instructions,
                    compile_time_ms: None, // Compilation not tracked in executor
                    compilation_note: None,
                    refund_usd: None, // No refund on failure
                })
            }
        }
    }

    /// Try to execute WASM with different formats
    ///
    /// If build_target is known, try that format first for performance.
    /// Otherwise, try all formats in priority order.
    ///
    /// Priority order:
    /// 1. WASI Preview 2 component (HTTP, modern features, RPC proxy)
    /// 2. WASI Preview 1 module (standard WASI)
    /// 3. Error if no format matches
    ///
    /// Returns: (output_bytes, instructions, refund_usd)
    async fn execute_async(
        &self,
        wasm_bytes: &[u8],
        wasm_content_sha256: Option<&str>,
        input_data: &[u8],
        limits: &ResourceLimits,
        env_vars: Option<HashMap<String, String>>,
        build_target: Option<&str>,
        storage_config: Option<StorageConfig>,
        vrf_config: Option<VrfConfig>,
        wallet_config: Option<WalletConfig>,
        network_config: Option<NetworkConfig>,
        signing_keys: Option<crate::signing_keys::SigningKeys>,
    ) -> Result<(Vec<u8>, u64, Option<u64>)> {
        // A module runs with exactly the signing keys it declares, or not at
        // all — checked on these bytes before anything is instantiated.
        crate::signing_keys::check_run_keys(wasm_bytes, signing_keys.as_ref()).map_err(anyhow::Error::msg)?;

        // Create effective execution context with per-execution overrides
        let has_overrides = storage_config.is_some()
            || vrf_config.is_some()
            || wallet_config.is_some()
            || network_config.is_some();
        let effective_ctx: Option<ExecutionContext> = if has_overrides {
            if let Some(ref base_ctx) = self.context {
                Some(ExecutionContext {
                    outlayer_rpc: base_ctx.outlayer_rpc.clone(),
                    storage_config: storage_config.or_else(|| base_ctx.storage_config.clone()),
                    runtime_handle: base_ctx.runtime_handle.clone(),
                    compiled_cache: base_ctx.compiled_cache.clone(),
                    vrf_config: vrf_config.or_else(|| base_ctx.vrf_config.clone()),
                    wallet_config: wallet_config.or_else(|| base_ctx.wallet_config.clone()),
                    network_config: network_config.or_else(|| base_ctx.network_config.clone()),
                })
            } else {
                // No base context, create minimal one with overrides
                Some(ExecutionContext {
                    outlayer_rpc: None,
                    storage_config,
                    runtime_handle: tokio::runtime::Handle::current(),
                    compiled_cache: None,
                    vrf_config,
                    wallet_config,
                    network_config,
                })
            }
        } else {
            // No overrides, use existing context as-is
            self.context.clone()
        };

        // Get compiled cache from context
        let compiled_cache = effective_ctx.as_ref().and_then(|ctx| ctx.compiled_cache.clone());

        // Optimize: if we know build_target, try appropriate executor first
        if let Some(target) = build_target {
            tracing::debug!("🎯 Build target specified: {:?}", target);
            match target {
                "wasm32-wasip2" => {
                    tracing::debug!("🔹 Trying WASI P2 executor (target: wasm32-wasip2)");
                    // When target is known, return error directly (don't fallback to other formats)
                    // Pass execution context (RPC proxy + storage) and compiled cache to P2 executor
                    return wasi_p2::execute(
                        wasm_bytes,
                        wasm_content_sha256,
                        compiled_cache.as_ref(),
                        input_data,
                        limits,
                        env_vars,
                        self.print_wasm_stderr,
                        effective_ctx.as_ref(),
                        signing_keys,
                    ).await;
                }
                "wasm32-wasip1" | "wasm32-wasi" => {
                    tracing::debug!("🔹 Trying WASI P1 executor (target: {})", target);
                    // When target is known, return error directly (don't fallback to other formats)
                    // P1 does not support RPC proxy, storage, signing keys, or compiled cache
                    // (no component model); a P1 run that declares keys is refused before here.
                    return wasi_p1::execute(wasm_bytes, input_data, limits, env_vars, self.print_wasm_stderr).await;
                }
                _ => {
                    tracing::debug!("⚠️ Unknown target '{}', fallback to auto-detection", target);
                    // Unknown target, fallback to auto-detection below
                }
            }
        } else {
            tracing::debug!("🔍 No build target specified, auto-detecting format");
        }

        // Fallback: auto-detect format (for unknown targets or if specific executor failed)
        // Try WASI P2 component first (with RPC proxy, storage, and compiled cache support)
        if let Ok(result) = wasi_p2::execute(
            wasm_bytes,
            wasm_content_sha256,
            compiled_cache.as_ref(),
            input_data,
            limits,
            env_vars.clone(),
            self.print_wasm_stderr,
            effective_ctx.as_ref(),
            signing_keys,
        ).await
        {
            return Ok(result);
        }

        // Try WASI P1 module (no RPC proxy, storage, or compiled cache)
        if let Ok(result) = wasi_p1::execute(wasm_bytes, input_data, limits, env_vars.clone(), self.print_wasm_stderr).await
        {
            return Ok(result);
        }

        // If nothing worked, return error
        anyhow::bail!(
            "Failed to load WASM binary: not a valid WASI P2 component or WASI P1 module.\n\
             Build target: {:?}\n\
             Supported formats:\n\
             - WASI Preview 2 components (wasm32-wasip2)\n\
             - WASI Preview 1 modules (wasm32-wasip1, wasm32-wasi)\n\
             \n\
             If you need to add support for a new target, see module documentation.",
            build_target
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_executor_creation() {
        let executor = Executor::new(10_000_000_000, false);
        assert_eq!(executor._default_max_instructions, 10_000_000_000);
        assert_eq!(executor.print_wasm_stderr, false);
    }
}
