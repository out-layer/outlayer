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

pub mod sandbox;
mod wasi_p1;
mod wasi_p2;
mod pinned_http;

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
    /// The worker's TEE session with the coordinator, required next to the token
    pub tee_session_id: Option<String>,
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

/// The declared keys of one run: its signing keys and its encryption keys,
/// each present when the manifest declares keys of that family, and what the
/// run holds for tasks when the manifest declares them. Moved into the run
/// and dropped with it; its `Debug` prints paths and public parts only.
#[derive(Debug, Default)]
pub struct RunKeys {
    pub signing: Option<crate::signing_keys::SigningKeys>,
    pub encryption: Option<crate::encryption_keys::EncryptionKeys>,
    pub tasks: Option<crate::tasks::TasksRun>,
}

/// One execution carrying its declared keys — see [`Executor::with_keys`].
pub struct RunWithKeys<'a> {
    executor: &'a Executor,
    keys: RunKeys,
}

impl RunWithKeys<'_> {
    /// As [`Executor::execute`], with this run's declared keys.
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
                self.keys,
            )
            .await
    }
}

/// The least memory a run is given, whatever it asked for: a guest that
/// declared the contract's default of 128 MB and used more kept running while
/// the limit was not enforced, and keeps running under it.
pub const DEFAULT_MEMORY_FLOOR_MB: u32 = 1024;
/// The most memory a run can be given: wasm32's own bound.
pub const DEFAULT_MEMORY_CEILING_MB: u32 = 4096;
/// The stdout capacity: a write past it fails. Set at what the coordinator
/// accepts of a worker's answer (10 MiB).
pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 10 * 1024 * 1024;

/// WASM executor supporting multiple WASI versions
pub struct Executor {
    /// Maximum instructions allowed per execution (default)
    _default_max_instructions: u64,
    /// Print WASM stderr to worker logs
    print_wasm_stderr: bool,
    /// Execution context with optional RPC proxy and other services
    context: Option<ExecutionContext>,
    /// The bounds every run's `max_memory_mb` is held between, and the stdout
    /// capacity (`with_run_limits`).
    memory_floor_mb: u32,
    memory_ceiling_mb: u32,
    max_output_bytes: usize,
}

impl Executor {
    /// Create a new executor
    pub fn new(default_max_instructions: u64, print_wasm_stderr: bool) -> Self {
        Self {
            _default_max_instructions: default_max_instructions,
            print_wasm_stderr,
            context: None,
            memory_floor_mb: DEFAULT_MEMORY_FLOOR_MB,
            memory_ceiling_mb: DEFAULT_MEMORY_CEILING_MB,
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
        }
    }

    /// The bounds a run's memory is held between and its stdout capacity
    /// (`WASM_MEMORY_FLOOR_MB`, `WASM_MEMORY_CEILING_MB`, `MAX_OUTPUT_BYTES` in
    /// the worker's config, which refuses a ceiling below the floor).
    pub fn with_run_limits(mut self, memory_floor_mb: u32, memory_ceiling_mb: u32, max_output_bytes: usize) -> Self {
        self.memory_floor_mb = memory_floor_mb;
        self.memory_ceiling_mb = memory_ceiling_mb;
        self.max_output_bytes = max_output_bytes;
        self
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
    /// A run with declared keys goes through [`Executor::with_keys`],
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
            RunKeys::default(),
        )
        .await
    }

    /// One run with this run's declared keys: they are moved in, reachable
    /// only through the `outlayer:signing-keys` and `outlayer:encryption-keys`
    /// host functions, and dropped with the run — never part of the long-lived
    /// execution context.
    pub fn with_keys(&self, keys: RunKeys) -> RunWithKeys<'_> {
        RunWithKeys { executor: self, keys }
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
        keys: RunKeys,
    ) -> Result<ExecutionResult> {
        // The memory the run is actually given: what it asked, held between
        // the worker's floor and ceiling. The floor exists because the limit
        // was not enforced before: a guest that declared the contract's
        // default of 128 MB and used more kept running, and keeps running.
        // The ceiling is wasm32's own bound.
        let effective = ResourceLimits {
            max_memory_mb: limits.max_memory_mb.clamp(self.memory_floor_mb, self.memory_ceiling_mb),
            ..limits.clone()
        };
        let limits = &effective;

        info!(
            "Starting WASM execution: {} instructions, {} MB memory, {} seconds, target: {:?}, format: {:?}",
            limits.max_instructions, limits.max_memory_mb, limits.max_execution_seconds, build_target, response_format
        );

        let start = Instant::now();

        // Try to execute with different WASI versions
        let result = self.execute_async(wasm_bytes, wasm_content_sha256, input_data, limits, env_vars, build_target, storage_config, vrf_config, wallet_config, network_config, keys).await;

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
                info!("WASM execution failed ({} bytes of error)", error_str.len());

                // What the run consumed, as the executor counted it — never a
                // number read out of the message, which carries the guest's
                // stderr. A penalty (timeout, HTTP abuse) spends the whole
                // compute limit. A failure before the guest ran (it did not
                // load or link) consumed nothing.
                let instructions = match e.downcast_ref::<sandbox::RunFailed>() {
                    Some(run) if run.penalty => limits.max_instructions,
                    Some(run) => run.instructions,
                    None => 0,
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
        keys: RunKeys,
    ) -> Result<(Vec<u8>, u64, Option<u64>)> {
        // A module runs with exactly the signing and encryption keys it
        // declares, or not at all — checked on these bytes before anything is
        // instantiated.
        crate::signing_keys::check_run_keys(wasm_bytes, keys.signing.as_ref()).map_err(anyhow::Error::msg)?;
        crate::encryption_keys::check_run_keys(wasm_bytes, keys.encryption.as_ref()).map_err(anyhow::Error::msg)?;

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
                        keys,
                        self.max_output_bytes,
                    ).await;
                }
                "wasm32-wasip1" | "wasm32-wasi" => {
                    tracing::debug!("🔹 Trying WASI P1 executor (target: {})", target);
                    // When target is known, return error directly (don't fallback to other formats)
                    // P1 does not support RPC proxy, storage, declared keys, or compiled cache
                    // (no component model); a P1 run that declares keys is refused before here.
                    return wasi_p1::execute(wasm_bytes, input_data, limits, env_vars, self.print_wasm_stderr, self.max_output_bytes).await;
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
        // Try WASI P2 component first (with RPC proxy, storage, and compiled cache support).
        // A binary that loaded and RAN is that format whatever became of the
        // run: its failure (`sandbox::RunFailed`, with what it consumed) is the
        // answer, not a reason to try the next format and lose it. Only a
        // binary that is not this format falls through.
        match wasi_p2::execute(
            wasm_bytes,
            wasm_content_sha256,
            compiled_cache.as_ref(),
            input_data,
            limits,
            env_vars.clone(),
            self.print_wasm_stderr,
            effective_ctx.as_ref(),
            keys,
            self.max_output_bytes,
        ).await
        {
            Ok(result) => return Ok(result),
            Err(e) if e.downcast_ref::<sandbox::RunFailed>().is_some() => return Err(e),
            Err(_) => {}
        }

        // Try WASI P1 module (no RPC proxy, storage, or compiled cache)
        match wasi_p1::execute(wasm_bytes, input_data, limits, env_vars.clone(), self.print_wasm_stderr, self.max_output_bytes).await {
            Ok(result) => return Ok(result),
            Err(e) if e.downcast_ref::<sandbox::RunFailed>().is_some() => return Err(e),
            Err(_) => {}
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

    /// `(module (func (export "_start") unreachable))`: a P1 module whose
    /// run traps at once.
    const TRAPPING_P1: &[u8] = &[
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // magic, version
        0x01, 0x04, 0x01, 0x60, 0x00, 0x00, // type: () -> ()
        0x03, 0x02, 0x01, 0x00, // one function of that type
        0x07, 0x0a, 0x01, 0x06, b'_', b's', b't', b'a', b'r', b't', 0x00, 0x00, // export "_start"
        0x0a, 0x05, 0x01, 0x03, 0x00, 0x00, 0x0b, // body: unreachable, end
    ];

    /// With no build target, a module that loaded and ran is answered with
    /// its own failure — not with "not a valid binary", which would charge
    /// nothing and name the wrong cause.
    #[tokio::test]
    async fn an_auto_detected_run_that_fails_keeps_its_failure() {
        let executor = Executor::new(10_000_000, false);
        let limits = ResourceLimits { max_instructions: 10_000_000, max_memory_mb: 16, max_execution_seconds: 5 };
        let result = executor
            .execute(TRAPPING_P1, None, b"{}", &limits, None, None, &ResponseFormat::Json, None, None, None, None)
            .await;
        let failure = match result {
            Ok(r) => {
                assert!(!r.success, "a trap is a failure");
                r.error.unwrap_or_default()
            }
            Err(e) => format!("{e:#}"),
        };
        assert!(!failure.contains("Failed to load WASM binary"), "{failure}");
        assert!(failure.contains("unreachable") || failure.contains("WASM execution failed"), "{failure}");
    }

    #[tokio::test]
    async fn test_executor_creation() {
        let executor = Executor::new(10_000_000_000, false);
        assert_eq!(executor._default_max_instructions, 10_000_000_000);
        assert_eq!(executor.print_wasm_stderr, false);
    }

    /// A P1 guest that burns about sixteen million instructions, grows its
    /// memory from nothing 1 MiB at a time until the host refuses, then writes
    /// its memory size in MiB as one byte to stdout and returns — so the bound
    /// it met is read off its output, not inferred from words.
    const GROWS_UNTIL_REFUSED: &str = r#"(module
        (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))
        (memory (export "memory") 0)
        (func (export "_start")
            (local $i i32)
            (loop $burn
                (local.set $i (i32.add (local.get $i) (i32.const 1)))
                (br_if $burn (i32.lt_u (local.get $i) (i32.const 2000000))))
            (loop $again
                (br_if $again (i32.ne (memory.grow (i32.const 16)) (i32.const -1))))
            ;; iovec at 0: buf = 8, len = 1; the byte at 8 is the size in MiB
            (i32.store (i32.const 0) (i32.const 8))
            (i32.store (i32.const 4) (i32.const 1))
            (i32.store8 (i32.const 8) (i32.shr_u (memory.size) (i32.const 4)))
            (drop (call $fd_write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 12)))))"#;

    /// A P1 guest that writes 64 KiB to stdout over and over, stops at the
    /// first write that fails, and returns — so what it managed to write is
    /// its output.
    const WRITES_UNTIL_REFUSED: &str = r#"(module
        (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))
        (memory (export "memory") 2)
        (func (export "_start")
            ;; iovec at 0: buf = 16, len = 65536
            (i32.store (i32.const 0) (i32.const 16))
            (i32.store (i32.const 4) (i32.const 65536))
            (block $done
                (loop $again
                    (br_if $done (i32.ne (call $fd_write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8)) (i32.const 0)))
                    (br $again)))))"#;

    async fn run_p1(wat: &str, executor: &Executor, memory_mb: u32) -> ExecutionResult {
        let bytes = wat::parse_str(wat).expect("the test module assembles");
        let limits = ResourceLimits { max_instructions: 1_000_000_000, max_memory_mb: memory_mb, max_execution_seconds: 10 };
        executor
            .execute(&bytes, None, b"", &limits, None, Some("wasm32-wasip1"), &ResponseFormat::Bytes, None, None, None, None)
            .await
            .expect("the run answers with a result, not a transport error")
    }

    /// `max_memory_mb` bounds the guest's linear memory: growth stops at
    /// exactly the bound, the refusal is the guest's to handle, and the run
    /// reports every instruction it burned on the way.
    #[tokio::test]
    async fn a_guest_is_refused_memory_at_its_limit_and_billed_for_its_work() {
        let executor = Executor::new(1_000_000_000, false).with_run_limits(16, 64, 1024 * 1024);
        let result = run_p1(GROWS_UNTIL_REFUSED, &executor, 16).await;
        assert!(result.success, "{:?}", result.error);
        match result.output {
            Some(ExecutionOutput::Bytes(bytes)) => assert_eq!(bytes, vec![16], "growth stopped at 16 MiB"),
            other => panic!("expected one byte of output, got {other:?}"),
        }
        assert!(result.instructions > 8_000_000, "the burn is billed: {}", result.instructions);
    }

    /// Below the floor the request's figure is not what is enforced: a guest
    /// that asked for 16 MB and grows to about 40 MiB (one page, then forty 1 MiB
    /// grows) keeps running under a 64 MB floor.
    #[tokio::test]
    async fn the_floor_is_the_least_a_run_is_given() {
        let grows_40 = r#"(module
            (memory (export "memory") 1)
            (func (export "_start")
                (local $i i32)
                (loop $again
                    (if (i32.eq (memory.grow (i32.const 16)) (i32.const -1)) (then unreachable))
                    (local.set $i (i32.add (local.get $i) (i32.const 1)))
                    (br_if $again (i32.lt_u (local.get $i) (i32.const 40))))))"#;
        let executor = Executor::new(1_000_000_000, false).with_run_limits(64, 4096, 1024 * 1024);
        let result = run_p1(grows_40, &executor, 16).await;
        assert!(result.success, "{:?}", result.error);
    }

    /// stdout holds exactly `max_output_bytes`, whatever memory the run has:
    /// the guest gets four 64 KiB writes into 256 KiB and the fifth fails.
    /// Under a capacity tied to `max_memory_mb` (16 MiB here) it would write
    /// far past 256 KiB.
    #[tokio::test]
    async fn stdout_holds_exactly_the_output_capacity() {
        let executor = Executor::new(1_000_000_000, false).with_run_limits(16, 64, 256 * 1024);
        let result = run_p1(WRITES_UNTIL_REFUSED, &executor, 16).await;
        assert!(result.success, "{:?}", result.error);
        match result.output {
            Some(ExecutionOutput::Bytes(bytes)) => assert_eq!(bytes.len(), 256 * 1024),
            other => panic!("expected the bytes written, got {other:?}"),
        }
    }
}

