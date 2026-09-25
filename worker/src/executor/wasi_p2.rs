//! WASI Preview 2 (Component Model) executor
//!
//! Executes WASM components compiled with wasm32-wasip2 target.
//!
//! ## Features
//! - Component model with typed interfaces
//! - HTTP/HTTPS requests via wasi-http
//! - NEAR RPC proxy via host functions `near:rpc/api@0.1.0` (when ExecutionContext is provided)
//! - Advanced filesystem operations
//! - Async execution
//!
//! ## Requirements
//! - wasmtime 28+
//! - WASM component format (not core module)
//! - wasi:cli/run interface

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use tracing::debug;
use wasmtime::component::{Component, Linker};
use wasmtime::*;

/// Global WASM engine for WASI P2 components (component model)
///
/// IMPORTANT: This engine is ONLY for P2 components. P1 modules have their own engine.
///
/// Configuration:
/// - wasm_component_model = true (required for P2)
/// - async_support = true (required for wasi-http)
/// - consume_fuel = true (instruction metering)
///
/// Creating Engine is expensive (~50-100ms). By reusing a single instance,
/// we avoid this overhead on every execution.
///
/// Note: CompiledCache entries are tied to this Engine configuration.
/// If config changes, cached entries will fail to deserialize and be recompiled.
static WASM_ENGINE_P2: OnceLock<Engine> = OnceLock::new();

/// Get or initialize the global P2 engine
///
/// This engine has component_model=true and is NOT compatible with P1 modules.
fn get_p2_engine() -> &'static Engine {
    WASM_ENGINE_P2.get_or_init(|| {
        let mut config = Config::new();
        config.wasm_component_model(true); // P2 ONLY: component model
        config.async_support(true);        // Required for wasi-http
        config.consume_fuel(true);         // Instruction metering
        config.epoch_interruption(true);   // Allow interrupting host calls (wasi-http)
        tracing::info!("⚡ Initialized global WASM engine for P2 (component model)");
        Engine::new(&config).expect("Failed to create P2 WASM engine")
    })
}
use wasmtime_wasi::{DirPerms, FilePerms, ResourceTable, WasiCtx, WasiCtxBuilder, WasiView};
use wasmtime_wasi::bindings::Command;
use wasmtime_wasi_http::{WasiHttpCtx, WasiHttpView};
use wasmtime_wasi_http::body::HyperOutgoingBody;
use wasmtime_wasi_http::types::{
    default_send_request_handler, HostFutureIncomingResponse, OutgoingRequestConfig,
};

use crate::api_client::ResourceLimits;
use crate::compiled_cache::CompiledCache;
use crate::connector_manifest::{EgressRecord, NetworkPolicy};
use crate::outlayer_rpc::RpcHostState;
use crate::outlayer_storage::{StorageClient, StorageHostState, add_storage_to_linker};
use crate::outlayer_payment::{PaymentHostState, add_payment_to_linker};
use crate::outlayer_vrf::{VrfHostState, add_vrf_to_linker};
use crate::outlayer_wallet::{WalletHostState, add_wallet_to_linker};
use crate::signing_keys::{SigningKeys, SigningKeysHostState, add_signing_keys_to_linker};

use super::ExecutionContext;

/// Max time for a single outbound HTTP request from WASI (seconds)
const HTTP_REQUEST_TIMEOUT_SECS: u64 = 30;
/// After this many timed-out HTTP requests, WASI execution is aborted
const HTTP_TIMEOUT_ABORT_THRESHOLD: u32 = 2;

/// Host state for WASI P2 execution
///
/// Contains WASI context, HTTP context, and optionally RPC proxy, storage, payment, VRF, and wallet state.
struct HostState {
    wasi_ctx: WasiCtx,
    wasi_http_ctx: WasiHttpCtx,
    table: ResourceTable,
    /// RPC proxy state (only present if ExecutionContext has outlayer_rpc)
    rpc_state: Option<RpcHostState>,
    /// Storage state (only present if ExecutionContext has storage_config)
    storage_state: Option<StorageHostState>,
    /// Payment state (only present if attached_usd > 0)
    payment_state: Option<PaymentHostState>,
    /// VRF state (only present if keystore configured + request_id available)
    vrf_state: Option<VrfHostState>,
    /// Wallet state (only present if wallet_id in execution request)
    wallet_state: Option<WalletHostState>,
    /// This run's signing keys (only present if the component imports
    /// `outlayer:signing-keys/api`). Dropped with the store, at the end of the run.
    signing_keys_state: Option<SigningKeysHostState>,
    /// Counter for timed-out HTTP requests (shared with spawned tasks)
    http_timeout_count: Arc<std::sync::atomic::AtomicU32>,
    /// Engine handle to force epoch interrupt when aborting due to HTTP abuse (Engine::clone is Arc)
    engine_handle: &'static Engine,
    /// Outbound-domain allowlist for this execution (§C3). Layered ON TOP of
    /// the SSRF filter, never instead of it.
    network_policy: NetworkPolicy,
    /// Every outbound request this run attempted, allowed or refused. Shared
    /// with the spawned per-request tasks; read back by the caller after the
    /// guest finishes and submitted to the audit.
    egress_log: Arc<Mutex<Vec<EgressRecord>>>,
}

impl WasiView for HostState {
    fn ctx(&mut self) -> &mut WasiCtx {
        &mut self.wasi_ctx
    }

    fn table(&mut self) -> &mut ResourceTable {
        &mut self.table
    }
}

/// True for addresses a sandboxed guest must not reach: loopback, RFC1918
/// private, link-local (incl. cloud metadata 169.254.169.254), CGNAT, ULA, etc.
fn is_blocked_ip(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xc0) == 0x40) // 100.64.0.0/10 CGNAT
                || (o[0] == 198 && (o[1] & 0xfe) == 18) // 198.18.0.0/15 benchmark
                || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24 IETF
                || (o[0] == 192 && o[1] == 88 && o[2] == 99) // 192.88.99.0/24 6to4 relay
                || (o[0] & 0xf0) == 0xe0 // 224.0.0.0/4 multicast
                || o[0] >= 240 // 240.0.0.0/4 reserved
        }
        IpAddr::V6(v6) => {
            // Unwrap BOTH IPv4-mapped (::ffff:a.b.c.d) AND the deprecated
            // IPv4-compatible (::a.b.c.d) forms: to_ipv4() covers both, whereas
            // to_ipv4_mapped() misses ::a.b.c.d and would let `::169.254.169.254`
            // (cloud metadata) through. Genuine global v6 returns None.
            if let Some(v4) = v6.to_ipv4() {
                return is_blocked_ip(IpAddr::V4(v4));
            }
            let s = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || (s[0] & 0xfe00) == 0xfc00 // fc00::/7 ULA
                || (s[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
                || (s[0] & 0xff00) == 0xff00 // ff00::/8 multicast
                || (s[0] == 0x0064 && s[1] == 0xff9b) // 64:ff9b::/96 NAT64
                || (s[0] == 0x2001 && s[1] == 0x0db8) // 2001:db8::/32 documentation
        }
    }
}

impl WasiHttpView for HostState {
    fn ctx(&mut self) -> &mut WasiHttpCtx {
        &mut self.wasi_http_ctx
    }

    fn table(&mut self) -> &mut ResourceTable {
        &mut self.table
    }

    /// Increase the max chunk size for outgoing HTTP request bodies
    /// Default is too small for large attachments (wasi-http-client sends entire body in one write)
    fn outgoing_body_buffer_chunks(&mut self) -> usize {
        tracing::trace!("outgoing_body_buffer_chunks: 16");
        16 // Allow more buffered chunks (default is 1)
    }

    fn outgoing_body_chunk_size(&mut self) -> usize {
        tracing::trace!("outgoing_body_chunk_size: 16MB");
        16 * 1024 * 1024 // 16MB max per write (default might be too small)
    }

    fn send_request(
        &mut self,
        request: hyper::Request<HyperOutgoingBody>,
        config: OutgoingRequestConfig,
    ) -> wasmtime_wasi_http::HttpResult<HostFutureIncomingResponse> {
        let timeout_count = self.http_timeout_count.clone();
        let engine = self.engine_handle; // &'static Engine

        // Check if already exceeded threshold before sending
        let current = timeout_count.load(std::sync::atomic::Ordering::Relaxed);
        if current >= HTTP_TIMEOUT_ABORT_THRESHOLD {
            tracing::warn!("WASI HTTP aborted: {} requests timed out, refusing new requests", current);
            return Ok(HostFutureIncomingResponse::ready(Ok(Err(
                wasmtime_wasi_http::bindings::http::types::ErrorCode::InternalError(
                    Some(format!("Execution aborted: {} HTTP requests exceeded {}s timeout", current, HTTP_REQUEST_TIMEOUT_SECS))
                )
            ))));
        }

        let url = request.uri().to_string();
        let host = request.uri().host().map(|h| h.to_string());
        let port = request
            .uri()
            .port_u16()
            .unwrap_or(if request.uri().scheme_str() == Some("http") { 80 } else { 443 });
        let timeout_duration = std::time::Duration::from_secs(HTTP_REQUEST_TIMEOUT_SECS);

        // Body size as the guest declared it. Only used for the audit line, so
        // an absent Content-Length is recorded as unknown rather than guessed.
        let declared_bytes = request
            .headers()
            .get(hyper::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        // Domain allowlist (§C3), enforced BEFORE the request leaves and
        // before DNS resolution — a refused host must not even be looked up,
        // since a DNS query is itself an exfiltration channel.
        //
        // This layer is additional to the SSRF filter below, not a replacement
        // for it: the allowlist answers "may this project talk to that party",
        // the SSRF filter answers "is that party inside our infrastructure".
        // Both must pass.
        if let Some(reason) = crate::connector_manifest::decide_egress(
            &self.network_policy,
            host.as_deref(),
            declared_bytes,
            &self.egress_log,
        ) {
            tracing::warn!(
                host = %host.as_deref().unwrap_or(""),
                "WASI HTTP blocked (not in manifest allowlist)"
            );
            return Ok(HostFutureIncomingResponse::ready(Ok(Err(
                wasmtime_wasi_http::bindings::http::types::ErrorCode::InternalError(Some(reason)),
            ))));
        }

        let handle = wasmtime_wasi::runtime::spawn(async move {
            // SSRF guard: a guest component must not reach internal / private /
            // link-local / cloud-metadata addresses from inside the keys-bearing
            // TEE. Resolve the destination and reject blocked ranges before
            // connecting. Public destinations are unaffected (guest HTTP to the
            // internet still works). NOTE: this resolves then hands off to the
            // default handler which resolves again — a DNS-rebinding window
            // remains; pin the resolved IP into the connection to fully close it.
            match host.as_deref() {
                Some(h) => match tokio::net::lookup_host((h, port)).await {
                    Ok(addrs) => {
                        let addrs: Vec<std::net::SocketAddr> = addrs.collect();
                        if addrs.is_empty() || addrs.iter().any(|a| is_blocked_ip(a.ip())) {
                            tracing::warn!("WASI HTTP blocked (internal/private destination): {:?}", url);
                            return Ok(Err(
                                wasmtime_wasi_http::bindings::http::types::ErrorCode::InternalError(
                                    Some("destination blocked: internal/private/link-local address".to_string()),
                                ),
                            ));
                        }
                    }
                    Err(e) => {
                        return Ok(Err(
                            wasmtime_wasi_http::bindings::http::types::ErrorCode::InternalError(
                                Some(format!("dns resolution failed: {e}")),
                            ),
                        ));
                    }
                },
                None => {
                    return Ok(Err(
                        wasmtime_wasi_http::bindings::http::types::ErrorCode::InternalError(
                            Some("request has no host".to_string()),
                        ),
                    ));
                }
            }

            match tokio::time::timeout(
                timeout_duration,
                default_send_request_handler(request, config),
            )
            .await
            {
                Ok(result) => Ok(result),
                Err(_) => {
                    let count = timeout_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                    tracing::warn!(
                        "WASI HTTP request timed out after {}s: {} (timeout count: {}/{})",
                        HTTP_REQUEST_TIMEOUT_SECS, url, count, HTTP_TIMEOUT_ABORT_THRESHOLD
                    );
                    if count >= HTTP_TIMEOUT_ABORT_THRESHOLD {
                        tracing::error!("HTTP abuse detected: forcing WASI termination via epoch interrupt");
                        // Advance epoch well past any possible deadline to trigger trap.
                        // max_execution_seconds is at most ~180, +100 for safety margin.
                        for _ in 0..300 {
                            engine.increment_epoch();
                        }
                    }
                    Ok(Err(wasmtime_wasi_http::bindings::http::types::ErrorCode::ConnectionTimeout))
                }
            }
        });

        Ok(HostFutureIncomingResponse::pending(handle))
    }
}

impl HostState {
    /// Get RPC host state (for host function callbacks)
    fn rpc_state_mut(&mut self) -> &mut RpcHostState {
        self.rpc_state.as_mut().expect("RPC state not initialized")
    }

    /// Get storage host state (for host function callbacks)
    fn storage_state_mut(&mut self) -> &mut StorageHostState {
        self.storage_state.as_mut().expect("Storage state not initialized")
    }

    /// Get payment host state (for host function callbacks)
    fn payment_state_mut(&mut self) -> &mut PaymentHostState {
        self.payment_state.as_mut().expect("Payment state not initialized")
    }

    /// Get VRF host state (for host function callbacks)
    fn vrf_state_mut(&mut self) -> &mut VrfHostState {
        self.vrf_state.as_mut().expect("VRF state not initialized")
    }

    /// Get wallet host state (for host function callbacks)
    fn wallet_state_mut(&mut self) -> &mut WalletHostState {
        self.wallet_state.as_mut().expect("Wallet state not initialized")
    }

    /// Get signing-keys host state (for host function callbacks)
    fn signing_keys_state_mut(&mut self) -> &mut SigningKeysHostState {
        self.signing_keys_state.as_mut().expect("Signing keys state not initialized")
    }
}

/// Execute WASI Preview 2 component
///
/// # Arguments
/// * `wasm_bytes` - WASM component binary
/// * `wasm_content_sha256` - SHA256 **of the wasm bytes themselves**, the
///   compiled cache's key. It must be the content hash and nothing else: a key
///   that names coordinates (a repo and a commit) is shared by every build made
///   from them, and the entry filed under it would then be served for bytes it
///   was not compiled from. Content-keyed, a hit means byte-identical source by
///   definition, so no separate check is needed and none can be forgotten.
/// * `compiled_cache` - Optional compiled component cache for ~10x speedup
/// * `input_data` - JSON input via stdin
/// * `limits` - Resource limits (memory, instructions, time)
/// * `env_vars` - Environment variables (from encrypted secrets, includes ATTACHED_USD)
/// * `print_stderr` - Print WASM stderr to worker logs
/// * `exec_ctx` - Execution context with optional RPC proxy
/// * `signing_keys` - This run's declared signing keys, if it declares any
///
/// # Returns
/// * `Ok((output, fuel_consumed, refund_usd))` - Execution succeeded
///   - `refund_usd` is Some if WASM called refund_usd() host function
/// * `Err(_)` - Not a valid P2 component or execution failed
pub async fn execute(
    wasm_bytes: &[u8],
    wasm_content_sha256: Option<&str>,
    compiled_cache: Option<&Arc<Mutex<CompiledCache>>>,
    input_data: &[u8],
    limits: &ResourceLimits,
    env_vars: Option<HashMap<String, String>>,
    print_stderr: bool,
    exec_ctx: Option<&ExecutionContext>,
    signing_keys: Option<SigningKeys>,
) -> Result<(Vec<u8>, u64, Option<u64>)> {
    // Use global P2 engine (avoids ~50-100ms overhead per execution)
    let engine = get_p2_engine();

    // Try to load from compiled cache first (if checksum provided)
    let component = if let (Some(checksum), Some(cache)) = (wasm_content_sha256, compiled_cache) {
        // Try cache hit
        let cached = cache.lock().ok().and_then(|mut c| c.get(checksum, &engine));

        if let Some(cached_component) = cached {
            debug!("⚡ Using compiled cache for {}", checksum);
            cached_component
        } else {
            // Cache miss - compile from bytes
            debug!("🔨 Compiling component (cache miss): {}", checksum);
            let component = Component::from_binary(&engine, wasm_bytes)
                .context("Not a valid WASI Preview 2 component")?;

            // Store in cache for next time
            if let Ok(mut c) = cache.lock() {
                if let Err(e) = c.put(checksum, &component) {
                    tracing::warn!("Failed to cache compiled component: {}", e);
                }
            }

            component
        }
    } else {
        // No cache available - compile directly
        Component::from_binary(&engine, wasm_bytes)
            .context("Not a valid WASI Preview 2 component")?
    };

    debug!("Loaded as WASI Preview 2 component");

    // Check which OutLayer SDK interfaces the WASM imports
    let has_storage_import = component.component_type().imports(&engine)
        .any(|(name, _)| name.contains("near:storage/api"));

    let storage_config = exec_ctx.and_then(|ctx| ctx.storage_config.as_ref());

    // If WASM imports storage but we don't have storage config, fail early with helpful message
    if has_storage_import && storage_config.is_none() {
        anyhow::bail!(
            "WASM imports `near:storage/api` but storage is not configured.\n\
            \n\
            This WASM was built with the `outlayer` crate and expects persistent storage.\n\
            \n\
            Possible causes:\n\
            1. WASM is running standalone (not as part of a project)\n\
            2. Keystore is not configured (KEYSTORE_BASE_URLS/KEYSTORE_AUTH_TOKEN)\n\
            3. Project UUID is missing from execution request\n\
            \n\
            To fix:\n\
            1. Run this WASM through a project (request_execution_version with project_id)\n\
            2. Ensure keystore is properly configured in worker environment\n\
            3. Or rebuild WASM without `outlayer` crate if you don't need storage"
        );
    }

    // Create linker with WASI and HTTP support
    let mut linker: Linker<HostState> = Linker::new(&engine);
    wasmtime_wasi::add_to_linker_async(&mut linker)?;
    wasmtime_wasi_http::add_only_http_to_linker_async(&mut linker)?;

    // Add NEAR RPC host functions if context has RPC proxy
    let rpc_state = if let Some(ctx) = exec_ctx {
        if let Some(outlayer_rpc) = &ctx.outlayer_rpc {
            debug!("Adding NEAR RPC host functions to linker");

            // Create sync RPC proxy for host functions
            let rpc_url = outlayer_rpc.get_rpc_url();
            let sync_proxy = crate::outlayer_rpc::host_functions_sync::RpcProxy::new(
                rpc_url,
                100, // max_calls
                true, // allow_transactions
                None, // No default signer - WASM provides signing keys
            )?;

            // Add RPC host functions to linker
            crate::outlayer_rpc::add_rpc_to_linker(&mut linker, |state: &mut HostState| {
                state.rpc_state_mut()
            })?;

            Some(RpcHostState::new(sync_proxy))
        } else {
            debug!("No RPC proxy in execution context");
            None
        }
    } else {
        debug!("No execution context provided");
        None
    };

    // Add storage host functions if context has storage config
    let storage_state = if let Some(ctx) = exec_ctx {
        if let Some(storage_config) = &ctx.storage_config {
            debug!("Adding storage host functions to linker");

            // Create storage client
            let storage_client = StorageClient::new(storage_config.clone())
                .context("Failed to create storage client")?;

            // Add storage host functions to linker
            add_storage_to_linker(&mut linker, |state: &mut HostState| {
                state.storage_state_mut()
            })?;

            Some(StorageHostState::from_client(storage_client))
        } else {
            debug!("No storage config in execution context");
            None
        }
    } else {
        None
    };

    // Extract attached_usd from env_vars for payment state
    // Must be done before env_vars is consumed by wasi_builder
    let attached_usd: u64 = env_vars
        .as_ref()
        .and_then(|env| env.get("ATTACHED_USD"))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    // Check if component imports payment interface
    let has_payment_import = component.component_type().imports(&engine)
        .any(|(name, _)| name.contains("near:payment/api"));

    // Add payment host functions if WASM imports payment interface
    // Even if attached_usd=0, we add the linker so WASM doesn't crash when calling refund_usd
    // Instead, it will get an error message "Refund amount X exceeds attached USD 0"
    let payment_state = if has_payment_import {
        debug!("Adding payment host functions to linker, attached_usd={}", attached_usd);

        // Add payment host functions to linker
        add_payment_to_linker(&mut linker, |state: &mut HostState| {
            state.payment_state_mut()
        })?;

        Some(PaymentHostState::new(attached_usd))
    } else if attached_usd > 0 {
        // WASM has attached_usd but doesn't import payment interface - log warning
        debug!("WASM has attached_usd={} but doesn't import near:payment/api interface, refund not possible", attached_usd);
        None
    } else {
        None
    };

    // Check if component imports VRF interface
    let has_vrf_import = component.component_type().imports(&engine)
        .any(|(name, _)| name.contains("near:vrf/api"));

    let vrf_state = if has_vrf_import {
        if let Some(ref vrf_cfg) = exec_ctx.and_then(|ctx| ctx.vrf_config.as_ref()) {
            debug!("Adding VRF host functions to linker, request_id={}", vrf_cfg.request_id);

            add_vrf_to_linker(&mut linker, |state: &mut HostState| {
                state.vrf_state_mut()
            })?;

            Some(VrfHostState::new(
                vrf_cfg.request_id,
                &vrf_cfg.sender_id,
                &vrf_cfg.keystore_url,
                &vrf_cfg.keystore_auth_token,
                vrf_cfg.tee_session_id.clone(),
            ))
        } else {
            anyhow::bail!(
                "WASM imports near:vrf/api but VRF is not available.\n\
                VRF requires: keystore configured + blockchain execution with request_id."
            );
        }
    } else {
        None
    };

    // Check if component imports wallet interface
    let has_wallet_import = component.component_type().imports(&engine)
        .any(|(name, _)| name.contains("outlayer:wallet/api"));

    let wallet_state = if has_wallet_import {
        if let Some(ref wallet_cfg) = exec_ctx.and_then(|ctx| ctx.wallet_config.as_ref()) {
            debug!("Adding wallet host functions to linker, wallet_id={}", wallet_cfg.wallet_id);

            add_wallet_to_linker(&mut linker, |state: &mut HostState| {
                state.wallet_state_mut()
            })?;

            Some(WalletHostState::new(
                &wallet_cfg.wallet_id,
                &wallet_cfg.coordinator_url,
                &wallet_cfg.wallet_auth_token,
                wallet_cfg.connector_id.as_deref(),
            ))
        } else {
            anyhow::bail!(
                "WASM imports outlayer:wallet/api but wallet is not available.\n\
                Wallet requires: X-Wallet-Id header in the execution request."
            );
        }
    } else {
        None
    };

    // Signing keys: reachable only through the host functions, never through
    // the environment or stdin. A component that imports the interface without
    // declaring a key gets an empty set, so every path answers "not declared".
    let has_signing_keys_import = component.component_type().imports(&engine)
        .any(|(name, _)| name.contains("outlayer:signing-keys/api"));

    let signing_keys_state = if has_signing_keys_import {
        let keys = signing_keys.unwrap_or_else(SigningKeys::none);
        debug!("Adding signing-key host functions to linker, paths={:?}", keys.paths().collect::<Vec<_>>());
        add_signing_keys_to_linker(&mut linker, |state: &mut HostState| state.signing_keys_state_mut())?;
        Some(SigningKeysHostState::new(keys))
    } else {
        if signing_keys.as_ref().is_some_and(|k| !k.is_empty()) {
            debug!("Component declares signing keys but does not import outlayer:signing-keys/api; they go unused");
        }
        drop(signing_keys);
        None
    };

    // Prepare stdin/stdout/stderr pipes
    let stdin_pipe = wasmtime_wasi::pipe::MemoryInputPipe::new(input_data.to_vec());
    let stdout_pipe =
        wasmtime_wasi::pipe::MemoryOutputPipe::new((limits.max_memory_mb as usize) * 1024 * 1024);
    let stderr_pipe = wasmtime_wasi::pipe::MemoryOutputPipe::new(1024 * 1024);

    // Build WASI context
    let mut wasi_builder = WasiCtxBuilder::new();
    wasi_builder.stdin(stdin_pipe);
    wasi_builder.stdout(stdout_pipe.clone());
    wasi_builder.stderr(stderr_pipe.clone());

    // No raw sockets, ever. The guest's only way to the network is
    // `wasi:http`, which runs through the outbound allowlist and the egress
    // audit below; a TCP or UDP socket, or a name lookup, would be a second
    // door around both. The linker still provides `wasi:sockets` so a
    // component that merely imports it instantiates — every call on it is
    // refused.
    wasi_builder.allow_tcp(false);
    wasi_builder.allow_udp(false);
    wasi_builder.allow_ip_name_lookup(false);
    wasi_builder.socket_addr_check(|_, _| Box::pin(async { false }));

    // Add preopened directory (required for WASI P2 filesystem interface)
    wasi_builder.preopened_dir(
        "/tmp",      // host_path
        ".",         // guest_path
        DirPerms::all(),
        FilePerms::all(),
    )?;

    // Add environment variables (from encrypted secrets)
    if let Some(env_map) = env_vars {
        for (key, value) in env_map {
            wasi_builder.env(&key, &value);
            debug!("Added env var: {}", key);
        }
    }

    // Add indicator that RPC proxy is available
    if rpc_state.is_some() {
        wasi_builder.env("NEAR_RPC_PROXY_AVAILABLE", "1");
        debug!("Added env var: NEAR_RPC_PROXY_AVAILABLE=1");
    }

    // Outbound-domain allowlist (§C3). An execution that arrives without a
    // network config is unrestricted at THIS layer — the SSRF filter below
    // still applies. Callers that must enforce a list always supply one; a
    // connector's is resolved fail-closed before we get here.
    let (network_policy, egress_log) = match exec_ctx.and_then(|c| c.network_config.as_ref()) {
        Some(cfg) => (cfg.policy.clone(), cfg.egress_log.clone()),
        None => (NetworkPolicy::Unrestricted, Arc::new(Mutex::new(Vec::new()))),
    };
    if network_policy.is_enforced() {
        debug!("🔒 Outbound allowlist active: {:?}", network_policy);
    }

    let host_state = HostState {
        wasi_ctx: wasi_builder.build(),
        wasi_http_ctx: WasiHttpCtx::new(),
        table: ResourceTable::new(),
        rpc_state,
        storage_state,
        payment_state,
        vrf_state,
        wallet_state,
        signing_keys_state,
        http_timeout_count: Arc::new(std::sync::atomic::AtomicU32::new(0)),
        engine_handle: engine,
        network_policy,
        egress_log,
    };

    // Create store with fuel limit + epoch deadline
    let mut store = Store::new(&engine, host_state);
    store.set_fuel(limits.max_instructions)?;
    let timeout_secs = limits.max_execution_seconds.max(5);
    // Epoch interruption: engine ticks every second, deadline = timeout_secs ticks.
    // This interrupts even during host calls (wasi-http) unlike tokio::time::timeout.
    store.set_epoch_deadline(timeout_secs);
    store.epoch_deadline_trap();
    // Note: Engine::clone() is Arc clone — epoch counter is shared across all executions.
    // This is fine because main loop executes tasks sequentially (one at a time).
    let epoch_engine = engine.clone();
    let epoch_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
        for _ in 0..timeout_secs + 5 {
            interval.tick().await;
            epoch_engine.increment_epoch();
        }
    });

    // Instantiate and execute component
    debug!("Instantiating component");
    let command = Command::instantiate_async(&mut store, &component, &linker)
        .await
        .map_err(|e| {
            tracing::error!("Failed to instantiate component: {}", e);
            tracing::error!("Error details: {:?}", e);
            e
        })
        .context("Failed to instantiate component")?;

    debug!("Running wasi:cli/run");
    // Wall-clock bound on the run itself. The epoch deadline above traps only
    // when wasm code executes: a guest suspended in a host await — a
    // `subscribe-duration` sleep, a body read on a slow server — never returns
    // to wasm, and the epoch alone cannot end it. Dropping the future cancels
    // the run (wasmtime unwinds the fiber; the store is read afterwards as
    // after any trap). Two seconds past the epoch deadline, so this fires only
    // where the epoch could not, and reports the same timeout.
    let execution_result = match tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs + 2),
        command.wasi_cli_run().call_run(&mut store),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(anyhow::anyhow!(
            "interrupt: wall-clock limit of {}s reached while the guest waited in a host call",
            timeout_secs
        )),
    };
    // Stop epoch ticker
    epoch_handle.abort();

    // Get fuel consumed before checking result
    let fuel_consumed = limits.max_instructions - store.get_fuel().unwrap_or(0);
    debug!("Component consumed {} instructions", fuel_consumed);

    // Log RPC call count if available
    if let Some(ref rpc_state) = store.data().rpc_state {
        let call_count = rpc_state.proxy.get_call_count();
        if call_count > 0 {
            debug!("Component made {} RPC calls", call_count);
        }
    }

    // Get refund_usd from payment state (if WASM called refund_usd())
    let refund_usd = store.data().payment_state.as_ref().map(|ps| {
        let refund = ps.get_refund_usd();
        if refund > 0 {
            debug!("Component requested refund of {} USD", refund);
        }
        refund
    }).filter(|&r| r > 0);

    // Check execution result
    // Read stderr for debugging (if flag is enabled)
    let stderr_contents = stderr_pipe.contents();
    if print_stderr && !stderr_contents.is_empty() {
        let stderr_str = String::from_utf8_lossy(&stderr_contents);
        tracing::info!("📝 WASM stderr output:\n{}", stderr_str);
    }

    // Check if execution was killed due to HTTP abuse (before checking result)
    let http_timeouts = store.data().http_timeout_count.load(std::sync::atomic::Ordering::Relaxed);
    if http_timeouts >= HTTP_TIMEOUT_ABORT_THRESHOLD {
        anyhow::bail!(
            "Execution terminated: {} HTTP requests exceeded {}s timeout limit (penalty). \
            Full execution cost is charged with no refund (consumed {} instructions)",
            http_timeouts,
            HTTP_REQUEST_TIMEOUT_SECS,
            fuel_consumed
        );
    }

    match execution_result {
        Ok(Ok(())) => {
            debug!("Component execution completed successfully");
            let output = stdout_pipe.contents().to_vec();
            Ok((output, fuel_consumed, refund_usd))
        }
        Ok(Err(_)) | Err(_) => {
            // Check if this was an epoch interruption (timeout)
            let err_ref = match &execution_result {
                Err(e) => Some(e),
                _ => None,
            };
            let is_epoch_timeout = err_ref
                .map(|e| e.to_string().contains("interrupt"))
                .unwrap_or(false);

            if is_epoch_timeout {
                anyhow::bail!(
                    "WASM execution timed out after {} seconds (penalty). \
                    Full execution cost is charged with no refund (consumed {} instructions)",
                    timeout_secs,
                    fuel_consumed
                );
            }

            // Component exited with error or trapped
            let trap_msg = match &execution_result {
                Err(e) => Some(e.to_string()),
                _ => None,
            };
            let error_msg = if !stderr_contents.is_empty() {
                let stderr_str = String::from_utf8_lossy(&stderr_contents).to_string();
                if let Some(trap) = &trap_msg {
                    format!("{}\nTrap: {}", stderr_str, trap)
                } else {
                    stderr_str
                }
            } else if let Some(trap) = trap_msg {
                format!("Component execution failed: {}", trap)
            } else {
                "Component exited with error (no details in stderr)".to_string()
            };

            debug!("Component execution failed: {}", error_msg);
            Err(anyhow::anyhow!("{}", error_msg))
        }
    }
}

#[cfg(test)]
mod ssrf_tests {
    use super::is_blocked_ip;
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("valid ip literal")
    }

    #[test]
    fn blocks_internal_and_metadata_addresses() {
        for s in [
            "127.0.0.1",
            "0.0.0.0",
            "10.0.0.5",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254", // cloud metadata
            "169.254.0.1",     // link-local
            "100.64.0.1",      // CGNAT 100.64/10
            "198.18.0.1",      // benchmarking 198.18/15
            "240.0.0.1",       // reserved
            "::1",
            "fe80::1",
            "fc00::1",
            "fd12:3456::1",
            "::ffff:127.0.0.1", // IPv4-mapped IPv6
            "::ffff:10.0.0.1",
            "::169.254.169.254", // IPv4-COMPATIBLE IPv6 (the to_ipv4 gap) → metadata
            "::127.0.0.1",        // IPv4-compatible loopback
            "224.0.0.1",          // IPv4 multicast
            "192.0.0.1",          // 192.0.0.0/24
            "192.88.99.1",        // 6to4 relay
            "ff02::1",            // IPv6 multicast
            "64:ff9b::a9fe:a9fe", // NAT64 → 169.254.169.254
            "2001:db8::1",        // IPv6 documentation
        ] {
            assert!(is_blocked_ip(ip(s)), "should block {s}");
        }
    }

    #[test]
    fn allows_public_addresses() {
        for s in [
            "8.8.8.8",
            "1.1.1.1",
            "9.9.9.9",
            "208.67.222.222",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
        ] {
            assert!(!is_blocked_ip(ip(s)), "should allow {s}");
        }
    }
}
