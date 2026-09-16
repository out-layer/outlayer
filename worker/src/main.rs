mod api_client;
mod collateral_fetcher;
mod compiled_cache;
mod compiler;
mod config;
mod event_monitor;
mod executor;
mod fastfs;
mod keystore_client;
mod near_client;
mod registration;
mod connector_manifest;
mod outlayer_rpc;
mod outlayer_storage;
mod outlayer_payment;
mod outlayer_vrf;
mod outlayer_wallet;
mod tdx_attestation;
mod wasm_cache;

use anyhow::{Context, Result};
use std::sync::{Arc, Mutex};
use tracing::{debug, error, info, warn};

use api_client::{ApiClient, CodeSource, ExecutionResult, JobInfo, JobStatus, JobType};
use compiled_cache::CompiledCache;
use wasm_cache::WasmCache;
use collateral_fetcher::fetch_collateral_from_phala;
use compiler::Compiler;
use config::Config;
use event_monitor::EventMonitor;
use executor::{Executor, ExecutionContext};
use keystore_client::KeystoreClient;
use near_client::NearClient;
use outlayer_storage::StorageConfig;
use tdx_attestation::{TdxClient, get_phala_app_info};

/// Generate a dummy TDX quote and fetch collateral from Phala Cloud API
///
/// This is used when registration fails with "Quote collateral required" error.
/// We generate a fresh quote (with dummy data) just to get the collateral JSON.
async fn generate_dummy_quote_and_fetch_collateral(tdx_client: &TdxClient) -> Result<String> {
    info!("Generating dummy TDX quote for collateral fetching...");

    // Generate quote with dummy 32-byte data
    let dummy_data = [0u8; 32];
    let tdx_quote_hex = tdx_client
        .generate_registration_quote(&dummy_data)
        .await
        .context("Failed to generate dummy TDX quote")?;

    info!("   Quote generated: {} bytes", tdx_quote_hex.len() / 2);

    // Fetch collateral from Phala API
    let collateral_json = fetch_collateral_from_phala(&tdx_quote_hex)
        .await
        .context("Failed to fetch collateral from Phala API")?;

    Ok(collateral_json)
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "offchainvm_worker=info".into()),
        )
        .init();

    info!("OffchainVM Worker starting...");

    // Load configuration
    let mut config = Config::from_env().context("Failed to load configuration")?;
    config.validate().context("Invalid configuration")?;

    // Auto-generate worker_id if not explicitly set via WORKER_ID env var
    if !Config::is_worker_id_from_env() {
        info!("🔍 WORKER_ID not set, auto-generating from network + type + Phala app_id...");

        // Try to get Phala app info (only works in TEE environment)
        // Use timeout to avoid hanging if dstack socket exists but is unresponsive
        let phala_app_id = if config.tee_mode == "outlayer_tee" {
            match tokio::time::timeout(
                std::time::Duration::from_secs(5),
                get_phala_app_info()
            ).await {
                Ok(Some(info)) => {
                    info!("📱 Detected Phala TEE: app_id={}", info.app_id);
                    Some(info.app_id)
                }
                Ok(None) => {
                    warn!("⚠️  Could not get Phala app info, using random UUID");
                    None
                }
                Err(_) => {
                    warn!("⚠️  Timeout getting Phala app info (5s), using random UUID");
                    None
                }
            }
        } else {
            debug!("Not in TEE mode, using random UUID for worker_id");
            None
        };

        let generated_id = config.generate_worker_id(phala_app_id.as_deref());
        info!("🏷️  Generated worker_id: {}", generated_id);
        config.set_worker_id(generated_id);
    }

    info!("Worker ID: {}", config.worker_id);
    info!("Coordinator API: {}", config.api_base_url);
    // The host and whether a key is on it — never the URL itself, which carries
    // the key in its query string.
    info!("NEAR RPC: {}", crate::outlayer_rpc::rpc_url_public(&config.near_rpc_url));
    info!("Contract ID: {}", config.offchainvm_contract_id);
    info!("Event monitor enabled: {}", config.enable_event_monitor);
    info!("Worker capabilities: {:?}", config.capabilities.to_array());
    if !config.execute_excludes.is_empty() {
        info!(
            "🚫 This node will NOT run: {:?} (EXECUTE_EXCLUDES) — the coordinator hands those tasks to another worker",
            config.execute_excludes
        );
    }

    // Initialize API client
    let api_client = ApiClient::new(config.api_base_url.clone(), config.api_auth_token.clone())
        .context("Failed to create API client")?;

    // Initialize WASM cache (if enabled)
    let wasm_cache = if config.wasm_cache_max_size_mb > 0 {
        // Determine cache directory - try configured dir first, fall back to /tmp if not writable
        let cache_dir = {
            let configured_dir = std::path::PathBuf::from(&config.wasm_cache_dir);

            // Try to create and write to configured directory
            let configured_ok = std::fs::create_dir_all(&configured_dir).is_ok() && {
                let test_file = configured_dir.join(".write_test");
                let write_ok = std::fs::write(&test_file, b"test").is_ok();
                let _ = std::fs::remove_file(&test_file);
                write_ok
            };

            if configured_ok {
                info!("📦 WASM cache directory: {} (writable)", configured_dir.display());
                configured_dir
            } else {
                // Fall back to /tmp subdirectory (TEE environment like Phala)
                // Security note: WASI P2 has access to /tmp, but cache has checksum verification
                // so tampering would be detected. In TEE only /tmp is writable.
                let fallback_dir = std::path::PathBuf::from("/tmp/outlayer-wasm-cache");
                warn!(
                    "⚠️  Configured cache directory '{}' is not writable, falling back to '{}'",
                    configured_dir.display(),
                    fallback_dir.display()
                );
                warn!("   Note: /tmp fallback is less secure - WASI has access to /tmp");
                warn!("   Cache integrity is protected by checksum verification.");
                fallback_dir
            }
        };

        info!("📦 WASM cache enabled: max_size={}MB, dir={}", config.wasm_cache_max_size_mb, cache_dir.display());
        let cache = WasmCache::new(
            cache_dir,
            config.wasm_cache_max_size_mb,
        ).context("Failed to initialize WASM cache")?;
        Some(Arc::new(Mutex::new(cache)))
    } else {
        info!("📦 WASM cache disabled (WASM_CACHE_MAX_SIZE_MB=0)");
        None
    };

    // Initialize compiler (only if compilation capability enabled)
    let compiler = if config.capabilities.can_compile() {
        info!("✅ Compilation capability enabled - initializing compiler");
        Some(Compiler::new(api_client.clone(), config.clone())
            .context("Failed to create compiler")?)
    } else {
        info!("⚠️  Compilation capability disabled - will only handle Execute jobs");
        None
    };

    // Initialize RPC proxy if enabled
    let rpc_proxy = if config.rpc_proxy.enabled {
        info!("🔧 Initializing NEAR RPC proxy...");
        let proxy = outlayer_rpc::RpcProxy::new(
            config.rpc_proxy.clone(),
            &config.near_rpc_url,
        )?;
        info!("✅ RPC proxy initialized: {}", proxy.get_rpc_url_masked());
        Some(proxy)
    } else {
        info!("⚠️  RPC proxy disabled - WASM modules cannot make NEAR RPC calls");
        None
    };

    // NOTE: Executor creation moved to after registration (needs secret key for compiled cache)

    // Initialize keystore client (optional)
    let mut keystore_client = if let (Some(keystore_urls), Some(keystore_token)) = (
        &config.keystore_base_urls,
        &config.keystore_auth_token,
    ) {
        info!("Keystore instances (in preference order): {}", keystore_urls.join(", "));
        info!("TEE mode: {}", config.tee_mode);
        Some(KeystoreClient::new(
            keystore_urls.clone(),
            keystore_token.clone(),
        )?)
    } else {
        info!("Keystore not configured - encrypted secrets will not be supported");
        None
    };

    // Initialize TDX client for task attestations
    let tdx_client = tdx_attestation::TdxClient::new(config.tee_mode.clone());

    // IMPORTANT: Worker registration MUST happen BEFORE creating NearClient
    // because NearClient requires operator_signer which is generated during registration
    // Make config mutable so we can set operator_signer after registration
    let mut config = config;

    // Check registration mode: TEE or legacy
    if config.use_tee_registration {
        info!("🔐 TEE registration mode enabled (USE_TEE_REGISTRATION=true)");

        // Register worker key on operator account (register-contract is deployed there)
        // This MUST happen before creating NearClient
        info!("🔑 Worker registration enabled - registering on {}...", config.operator_account_id);

        // Use init account for gas payment
        let (init_account_id, init_secret_key) = if let (Some(init_id), Some(init_signer)) =
            (&config.init_account_id, &config.init_account_signer) {
            info!("   Using init account for gas payment: {}", init_id);
            (init_id.clone(), init_signer.secret_key.clone())
        } else {
            error!("❌ Init account credentials missing for worker registration");
            error!("   When using TEE registration, you must provide:");
            error!("   - INIT_ACCOUNT_ID");
            error!("   - INIT_ACCOUNT_PRIVATE_KEY");
            return Err(anyhow::anyhow!("Init account credentials required for worker registration"));
        };

        // Attempt registration (only once - fail fast if it fails)
        let (_public_key, secret_key, tdx_quote_hex) = match registration::register_worker_on_startup(
            config.near_rpc_url.clone(),
            config.operator_account_id.clone(),
            init_account_id.clone(),
            init_secret_key.clone(),
            config.worker_key_type,
            &tdx_client,
        ).await {
            Ok(result) => {
                info!("✅ Worker keypair ready: {}", result.0);
                info!("   Key registered and ready for signing execution results");
                result
            }
            Err(e) => {
                error!("❌ Worker registration flow failed: {:?}", e);
                error!("   Worker CANNOT start without registered key");
                error!("   Error chain:");
                for (i, cause) in e.chain().enumerate() {
                    error!("      {}: {}", i, cause);
                }

                // Auto-fetch collateral from Phala Cloud for ANY registration error
                // This helps diagnose all issues (missing collateral, wrong RTMR3, etc.)
                error!("");
                error!("🔍 Fetching collateral from Phala Cloud API for diagnostics...");
                error!("");

                match generate_dummy_quote_and_fetch_collateral(&tdx_client).await {
                    Ok(collateral_json) => {
                        error!("✅ Successfully fetched collateral from Phala Cloud!");
                        error!("");
                        error!("📋 COLLATERAL JSON (copy this for update_collateral call):");
                        error!("");
                        error!("{}", collateral_json);
                        error!("");
                        error!("📝 To cache this collateral in the register contract, run:");
                        error!("");
                        error!("   COLLATERAL=$(cat <<'EOF'");
                        error!("{}", collateral_json);
                        error!("EOF");
                        error!("   )");
                        error!("");
                        error!("   near call {} update_collateral \\", config.operator_account_id);
                        error!("     \"{{\\\"collateral\\\":$COLLATERAL}}\" \\");
                        error!("     --accountId outlayer.testnet \\");
                        error!("     --gas 300000000000000");
                        error!("");
                    }
                    Err(fetch_err) => {
                        error!("⚠️  Failed to auto-fetch collateral: {:?}", fetch_err);
                        error!("   (This is OK if you already have collateral cached)");
                        error!("");
                    }
                }

                error!("📝 Common issues:");
                error!("   - Missing collateral: Cache collateral JSON above via update_collateral");
                error!("   - RTMR3 not approved: Check contract logs for RTMR3 and add via add_approved_rtmr3");
                error!("   - Init account balance: Verify init-worker.outlayer.testnet has funds");
                error!("");
                error!("⏹️  Worker stopped - fix the issue and restart");

                return Err(anyhow::anyhow!("Worker registration failed: {:?}", e));
            }
        };

        // Clone the worker secret key for the TEE session challenge-response BEFORE it is moved
        // into the operator signer. near-crypto signs/verifies ed25519 and ml-dsa-65 uniformly,
        // so this works regardless of WORKER_KEY_TYPE.
        let tee_secret_key = secret_key.clone();

        // Set operator signer with generated keypair (moves secret_key)
        let operator_signer = near_crypto::InMemorySigner {
            account_id: config.operator_account_id.clone(),
            public_key: secret_key.public_key(),
            secret_key,
        };
        config.set_operator_signer(operator_signer);
        info!("✅ Operator signer configured for account: {}", config.operator_account_id);

        // Send startup attestation to coordinator (using TDX quote from registration)
        info!("📤 Sending startup attestation to coordinator...");
        if let Err(e) = send_startup_attestation_with_quote(&api_client, &tdx_quote_hex, &config).await {
            error!("❌ Failed to send startup attestation to coordinator: {}", e);
            error!("   This is required for coordinator to track worker RTMR3");
            error!("   Common causes:");
            error!("   - Coordinator not accessible (check API_BASE_URL)");
            error!("   - Worker auth token invalid (check API_AUTH_TOKEN)");
            error!("   - Database migration not applied (check coordinator logs)");
            error!("");
            error!("⏹️  Worker stopped - fix the issue and restart");
            return Err(anyhow::anyhow!("Startup attestation failed: {:?}", e));
        }
        info!("✅ Startup attestation sent successfully - worker registered with coordinator");

        // Register TEE sessions with coordinator and keystore (challenge-response)
        // This proves to the coordinator/keystore that we hold the TEE private key
        // registered on the operator account
        {
            const MAX_TEE_RETRIES: u32 = 5;
            const TEE_RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(2);

            // Register TEE session with coordinator
            let mut coordinator_session_ok = false;
            for attempt in 1..=MAX_TEE_RETRIES {
                info!("🔐 Registering TEE session with coordinator (attempt {}/{})", attempt, MAX_TEE_RETRIES);
                match api_client.register_tee_session(&tee_secret_key).await {
                    Ok(session_id) => {
                        info!("✅ TEE session registered with coordinator: {}", session_id);
                        coordinator_session_ok = true;
                        break;
                    }
                    Err(e) => {
                        warn!("⚠️ Attempt {}/{} failed: {}", attempt, MAX_TEE_RETRIES, e);
                        if attempt < MAX_TEE_RETRIES {
                            tokio::time::sleep(TEE_RETRY_DELAY).await;
                        }
                    }
                }
            }
            if !coordinator_session_ok {
                error!("❌ Failed to register TEE session with coordinator after {} attempts", MAX_TEE_RETRIES);
                return Err(anyhow::anyhow!("TEE session registration with coordinator failed after {} attempts", MAX_TEE_RETRIES));
            }

            // Register TEE session directly with keystore (bypasses coordinator proxy)
            if let Some(ref mut kc) = keystore_client {
                // Store signing info for auto-reconnect on session expiry
                kc.set_tee_signing_info(tee_secret_key.clone());

                let mut keystore_session_ok = false;
                for attempt in 1..=MAX_TEE_RETRIES {
                    info!("🔐 Registering TEE session with keystore directly (attempt {}/{})", attempt, MAX_TEE_RETRIES);
                    match kc.register_tee_session(&tee_secret_key).await {
                        Ok(session_id) => {
                            info!("✅ TEE session registered with keystore: {}", session_id);
                            keystore_session_ok = true;
                            break;
                        }
                        Err(e) => {
                            warn!("⚠️ Attempt {}/{} failed: {}", attempt, MAX_TEE_RETRIES, e);
                            if attempt < MAX_TEE_RETRIES {
                                tokio::time::sleep(TEE_RETRY_DELAY).await;
                            }
                        }
                    }
                }
                if !keystore_session_ok {
                    error!("❌ Failed to register TEE session with keystore after {} attempts", MAX_TEE_RETRIES);
                    return Err(anyhow::anyhow!("TEE session registration with keystore failed after {} attempts", MAX_TEE_RETRIES));
                }
            }
        }
    } else {
        info!("🔓 Legacy mode enabled (USE_TEE_REGISTRATION=false)");
        info!("   Using OPERATOR_PRIVATE_KEY from .env for all transactions");
        info!("   ⚠️  This mode is for testnet only - use TEE registration for production!");
    }

    // Initialize compiled cache (requires secret key from registration/config)
    // This caches pre-compiled wasmtime components for ~10x faster WASM startup
    let compiled_cache: Option<Arc<Mutex<CompiledCache>>> = if config.wasm_cache_max_size_mb > 0 {
        // Get secret key bytes from operator signer
        let secret_key = &config.get_operator_signer().secret_key;
        let secret_key_bytes: [u8; 32] = match secret_key {
            near_crypto::SecretKey::ED25519(ed_key) => {
                // ED25519 secret key is 64 bytes (seed + public), we need first 32 (seed)
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&ed_key.0[..32]);
                bytes
            }
            _ => {
                warn!("⚠️ Compiled cache requires ED25519 key, skipping");
                [0u8; 32] // Won't be used
            }
        };

        // Only create cache if we have a valid key
        if secret_key_bytes != [0u8; 32] {
            let compiled_cache_dir = std::path::PathBuf::from(&config.wasm_cache_dir).join("compiled");
            match CompiledCache::new(compiled_cache_dir.clone(), config.wasm_cache_max_size_mb, &secret_key_bytes) {
                Ok(cache) => {
                    info!("⚡ Compiled cache enabled: dir={}, max_size={}MB",
                        compiled_cache_dir.display(), config.wasm_cache_max_size_mb);
                    Some(Arc::new(Mutex::new(cache)))
                }
                Err(e) => {
                    warn!("⚠️ Failed to initialize compiled cache: {}", e);
                    None
                }
            }
        } else {
            None
        }
    } else {
        info!("⚡ Compiled cache disabled (WASM_CACHE_MAX_SIZE_MB=0)");
        None
    };

    // Initialize executor with RPC proxy and compiled cache
    let executor = {
        let runtime_handle = tokio::runtime::Handle::current();
        let mut exec_context = ExecutionContext::new(runtime_handle);

        if let Some(proxy) = rpc_proxy {
            exec_context = exec_context.with_outlayer_rpc(proxy);
        }

        if let Some(ref cache) = compiled_cache {
            exec_context = exec_context.with_compiled_cache(cache.clone());
        }

        Executor::new(config.default_max_instructions, config.print_wasm_stderr)
            .with_context(exec_context)
    };

    // Create NearClient with operator signer from registration
    let near_client = NearClient::new(
        config.near_rpc_url.clone(),
        config.get_operator_signer().clone(),
        config.offchainvm_contract_id.clone(),
    )
    .context("Failed to create NEAR client")?;
    info!("NEAR client initialized");

    // Shared event monitor block height for heartbeat reporting
    let shared_block_height = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));

    // Shared timestamp of last successful poll (epoch seconds)
    let shared_last_poll_at = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));

    // Start heartbeat task
    let heartbeat_api_client = api_client.clone();
    let heartbeat_worker_id = config.worker_id.clone();
    // Worker name = worker_id (already descriptive: mainnet-executor-75ab6ac2)
    let heartbeat_worker_name = config.worker_id.clone();
    let heartbeat_block_height = shared_block_height.clone();
    let heartbeat_last_poll_at = shared_last_poll_at.clone();
    let stale_threshold_secs = config.poll_timeout_seconds + config.max_execution_seconds_cap + config.iteration_overhead_seconds;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            let block = heartbeat_block_height.load(std::sync::atomic::Ordering::Relaxed);
            let event_monitor_block_height = if block > 0 { Some(block) } else { None };
            let last_poll = heartbeat_last_poll_at.load(std::sync::atomic::Ordering::Relaxed);
            let last_poll_at = if last_poll > 0 { Some(last_poll) } else { None };
            // If last_poll_at hasn't updated within iteration_timeout, main loop is likely stuck
            let now_epoch = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let status = if last_poll > 0 && now_epoch.saturating_sub(last_poll) > stale_threshold_secs {
                "stale"
            } else {
                "online"
            };
            if let Err(e) = heartbeat_api_client
                .send_heartbeat(
                    heartbeat_worker_id.clone(),
                    heartbeat_worker_name.clone(),
                    status,
                    None,
                    event_monitor_block_height,
                    last_poll_at,
                )
                .await
            {
                warn!("Failed to send heartbeat: {}", e);
            }
        }
    });
    info!("Heartbeat task started (every 30 seconds)");

    // Start event monitor if enabled
    if config.enable_event_monitor {
        let event_api_client = api_client.clone();
        let neardata_url = config.neardata_api_url.clone();
        let near_rpc_url = config.near_rpc_url.clone();
        let contract_id = config.offchainvm_contract_id.clone();
        let start_block = config.start_block_height;
        let scan_interval_ms = config.scan_interval_ms;
        let event_filter_standard_name = config.event_filter_standard_name.clone();
        let event_filter_function_name = config.event_filter_function_name.clone();
        let event_filter_min_version = config.event_filter_min_version.clone();
        let monitor_block_height = shared_block_height.clone();

        tokio::spawn(async move {
            info!("Starting event monitor...");
            match EventMonitor::new(
                event_api_client,
                neardata_url,
                near_rpc_url,
                contract_id,
                start_block,
                scan_interval_ms,
                event_filter_standard_name,
                event_filter_function_name,
                event_filter_min_version,
                monitor_block_height,
            )
            .await
            {
                Ok(mut monitor) => {
                    if let Err(e) = monitor.start_monitoring().await {
                        error!("Event monitor failed: {}", e);
                    }
                }
                Err(e) => {
                    error!("Failed to create event monitor: {}", e);
                }
            }
        });
    }

    // Start Contract System Callbacks Handler
    // This handles contract business logic that requires yield/resume (TopUp, Delete, etc.)
    // Separated from main worker loop to avoid blocking WASM execution tasks
    // Only workers with "execution" capability should poll system callbacks
    if config.capabilities.to_array().contains(&"execution".to_string()) {
        let callbacks_api_client = api_client.clone();
        let callbacks_keystore_client = keystore_client.clone();
        let callbacks_near_client = near_client.clone();
        let callbacks_capabilities = config.capabilities.to_array();

        tokio::spawn(async move {
            run_contract_system_callbacks_handler(
                callbacks_api_client,
                callbacks_keystore_client,
                callbacks_near_client,
                callbacks_capabilities,
            )
            .await;
        });
        info!("📋 Contract System Callbacks Handler started");
    } else {
        info!("📋 Contract System Callbacks Handler skipped (no 'execution' capability)");
    }

    // Main worker loop
    info!("Starting worker loop...");
    // Hard timeout: poll_timeout + max_execution_cap + overhead for RPC/download/upload
    let iteration_timeout = tokio::time::Duration::from_secs(
        config.poll_timeout_seconds + config.max_execution_seconds_cap + config.iteration_overhead_seconds,
    );
    info!("⏱️ Iteration timeout: {}s (poll={}s + cap={}s + overhead={}s)",
        iteration_timeout.as_secs(), config.poll_timeout_seconds, config.max_execution_seconds_cap, config.iteration_overhead_seconds);
    loop {
        match tokio::time::timeout(
            iteration_timeout,
            worker_iteration(
                &api_client,
                compiler.as_ref(),
                &executor,
                &near_client,
                keystore_client.as_ref(),
                &tdx_client,
                &config,
                wasm_cache.as_ref(),
            ),
        )
        .await
        {
            Ok(result) => {
                // Update last poll timestamp — iteration returned, poll is alive
                shared_last_poll_at.store(
                    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
                    std::sync::atomic::Ordering::Relaxed,
                );
                match result {
                    Ok(processed) => {
                        if !processed {
                            // No task available, short sleep before next poll
                            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                        }
                    }
                    Err(e) => {
                        error!("Worker iteration failed: {}", e);
                        // Sleep before retry to avoid tight error loop
                        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                    }
                }
            }
            Err(_) => {
                error!("⏰ Worker iteration timed out after {}s — reconnecting", iteration_timeout.as_secs());
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        }
    }
}

/// Single iteration of the worker loop
///
/// Returns Ok(true) if a task was processed, Ok(false) if no task available
async fn worker_iteration(
    api_client: &ApiClient,
    compiler: Option<&Compiler>,
    executor: &Executor,
    near_client: &NearClient,
    keystore_client: Option<&KeystoreClient>,
    tdx_client: &tdx_attestation::TdxClient,
    config: &Config,
    wasm_cache: Option<&Arc<Mutex<WasmCache>>>,
) -> Result<bool> {
    // Poll for a task (with long-polling) - specify capabilities to poll correct queue
    let capabilities = config.capabilities.to_array();
    debug!("🔄 Polling for task (timeout={}s)...", config.poll_timeout_seconds);
    let task = api_client
        .poll_task(config.poll_timeout_seconds, &capabilities, &config.execute_excludes)
        .await
        .context("Failed to poll for task")?;
    debug!("🔄 Poll returned: {}", if task.is_some() { "task received" } else { "no task" });

    let Some(execution_request) = task else {
        // No execution request available
        return Ok(false);
    };

    info!("📨 Received execution request: request_id={} project_uuid={:?} project_id={:?}",
        execution_request.request_id, execution_request.project_uuid, execution_request.project_id);

    // Extract request details
    let request_id = execution_request.request_id;
    let data_id = execution_request.data_id.clone();
    let mut resource_limits = execution_request.resource_limits.clone();
    // Apply worker-level cap on execution time
    resource_limits.max_execution_seconds = resource_limits.max_execution_seconds.min(config.max_execution_seconds_cap);
    let input_data = execution_request.input_data.clone();
    let secrets_ref = execution_request.secrets_ref.clone();
    let response_format = execution_request.response_format.clone();
    let context = execution_request.context.clone();
    let user_account_id = execution_request.user_account_id.clone();
    let near_payment_yocto = execution_request.near_payment_yocto.clone();
    let attached_usd = execution_request.attached_usd.clone();
    let transaction_hash = context.transaction_hash.clone();
    let store_on_fastfs = execution_request.store_on_fastfs;
    let compile_only = execution_request.compile_only;
    let force_rebuild = execution_request.force_rebuild;
    let compile_result = execution_request.compile_result.clone();
    let is_https_call = execution_request.is_https_call;
    let call_id = execution_request.call_id.clone();
    let payment_key_owner = execution_request.payment_key_owner.clone();
    let binding_kind = execution_request.binding_kind.clone();
    let payment_key_nonce = execution_request.payment_key_nonce;
    let usd_payment = execution_request.usd_payment.clone();
    let wallet_id = execution_request.wallet_id.clone();

    // Invariant: HTTPS calls must have call_id to route responses back to the user.
    // Without it, complete_https_call cannot update https_calls table → user gets 524 timeout.
    if is_https_call && call_id.is_none() {
        anyhow::bail!("HTTPS call missing call_id for request_id={}", request_id);
    }


    /// Result of resolving project: code_source + project_uuid
    struct ResolvedProject {
        code_source: api_client::CodeSource,
        project_uuid: String,
    }

    // Helper to resolve code_source from project_id
    async fn resolve_code_source_from_project(
        near_client: &near_client::NearClient,
        project_id: &str,
        version_key: Option<&str>,
    ) -> Result<ResolvedProject> {
        // Treat empty string as None
        let version_key = version_key.filter(|v| !v.is_empty());

        // Fetch project from contract
        let project = near_client.fetch_project(project_id).await?
            .ok_or_else(|| anyhow::anyhow!("Project not found: {}", project_id))?;

        let project_uuid = project.uuid.clone();

        // Use provided version_key or fall back to active_version
        let version_to_fetch = version_key.unwrap_or(&project.active_version);
        let using_explicit_version = version_key.is_some();

        info!(
            "📦 Resolving project: {} version: {} ({})",
            project_id,
            version_to_fetch,
            if using_explicit_version { "explicit" } else { "active" }
        );

        // Fetch version info
        let version_view = near_client.fetch_project_version(project_id, version_to_fetch).await?
            .ok_or_else(|| anyhow::anyhow!("Project version not found: {} @ {}", project_id, version_to_fetch))?;

        // Convert contract's CodeSource to worker's api_client::CodeSource
        let code_source = match version_view.source {
            near_client::ContractCodeSource::GitHub { repo, commit, build_target } => {
                let build_target = build_target.unwrap_or_else(|| "wasm32-wasip1".to_string());
                info!("✅ Resolved: repo={} commit={} target={}", repo, commit, build_target);
                api_client::CodeSource::GitHub { repo, commit, build_target }
            }
            near_client::ContractCodeSource::WasmUrl { url, hash, build_target } => {
                let build_target = build_target.unwrap_or_else(|| "wasm32-wasip1".to_string());
                info!("✅ Resolved: url={} hash={} target={}", url, hash, build_target);
                api_client::CodeSource::WasmUrl { url, hash, build_target }
            }
        };

        Ok(ResolvedProject { code_source, project_uuid })
    }

    // Resolve code_source: either from request directly, or from project_id via contract
    // Also resolve project_uuid if resolving from project
    // Code is resolved from the CHAIN (§C3). An HTTPS job's own `code_source` is
    // never taken on trust: it is accepted only when it is exactly what the chain
    // names for the project — the compile-queue task the coordinator builds for
    // an HTTPS call carries the chain's answer as a copy, and that is the one
    // legitimate case. Anything else is somebody naming code for a project.
    let provided_source = execution_request.code_source.clone().map(|cs| cs.normalize());
    let (code_source, resolved_project_uuid): (api_client::CodeSource, Option<String>) = match provided_source {
        // Blockchain requests arrive from the contract with their source and run as given.
        Some(cs) if !is_https_call => (cs, None),
        provided => {
            let project_id = match execution_request.project_id.as_ref() {
                Some(p) => p,
                None => {
                    let msg = "No code_source and no project_id in request";
                    if refuse_https_call(api_client, is_https_call, call_id.as_deref(), msg).await {
                        return Ok(true);
                    }
                    anyhow::bail!(msg);
                }
            };

            let resolved = match resolve_code_source_from_project(near_client, project_id, execution_request.version_key.as_deref()).await {
                Ok(resolved) => {
                    info!("✅ Resolved project_uuid={} from project_id={}", resolved.project_uuid, project_id);
                    resolved
                }
                Err(e) => {
                    if refuse_https_call(api_client, is_https_call, call_id.as_deref(), &format!("Failed to resolve project: {}", e)).await {
                        return Ok(true);
                    }
                    return Err(e);
                }
            };
            let chain_source = resolved.code_source.normalize();

            if refuses_own_code_source(is_https_call, provided.as_ref(), &chain_source)
                && !config.capabilities.can_execute()
            {
                // A compile-only worker never runs anything: its whole job is
                // to cache what the chain names, and the executor resolves and
                // checks the chain again on its own. So a task whose copy has
                // gone stale (a version published between the coordinator's
                // resolution and this one) is not refused here — the chain's
                // answer is cached instead, which is what the executor will
                // ask for. Refusing would also go unreported: the call
                // completion endpoint needs a TEE session, which a
                // compile-only worker does not hold.
                warn!(
                    "compile task names a code_source other than the contract's; caching the contract's. contract={:?} task={:?}",
                    chain_source, provided
                );
            } else if refuses_own_code_source(is_https_call, provided.as_ref(), &chain_source) {
                // Both sources are named so a mismatch can be told apart from an
                // attack: a version published between the coordinator's
                // resolution and this one looks exactly like a forged task, and
                // only the two values say which it was.
                let msg = format!(
                    "Refusing an HTTPS job whose code_source is not what the contract names for \
this project. Code is resolved from the chain on this path, so a job naming other code did not \
come from the coordinator's own flow. contract={:?} task={:?}",
                    chain_source, provided
                );
                if refuse_https_call(api_client, is_https_call, call_id.as_deref(), &msg).await {
                    return Ok(true);
                }
                anyhow::bail!(msg);
            }

            (chain_source, Some(resolved.project_uuid))
        }
    };

    // Claim jobs for this task with worker capabilities
    let has_compile_result = compile_result.is_some();

    // Log if task appears to be misrouted (useful for debugging)
    if force_rebuild && !has_compile_result && !config.capabilities.can_compile() {
        warn!("⚠️ Task with force_rebuild=true but no compile_result routed to executor - may be waiting for compiler");
    }

    // Get project_uuid: prefer resolved from contract, fallback to execution_request
    let project_uuid = resolved_project_uuid.or(execution_request.project_uuid.clone());
    let project_id = execution_request.project_id.clone();

    info!("🎯 Claiming jobs for request_id={} data_id={} with capabilities={:?} compile_only={} force_rebuild={} has_compile_result={} project_uuid={:?}",
          request_id, data_id, config.capabilities.to_array(), compile_only, force_rebuild, has_compile_result, project_uuid);
    let claim_response = match api_client
        .claim_job(
            request_id,
            data_id.clone(),
            config.worker_id.clone(),
            &code_source,
            &resource_limits,
            user_account_id.clone(),
            near_payment_yocto.clone(),
            transaction_hash.clone(),
            config.capabilities.to_array(),
            compile_only,
            force_rebuild,
            has_compile_result,
            project_uuid,
            project_id,
        )
        .await
    {
        Ok(response) => response,
        Err(e) => {
            warn!("⚠️ Failed to claim job (likely already claimed): {}", e);
            return Ok(true); // Not an error, just means another worker got it first
        }
    };

    if claim_response.jobs.is_empty() {
        warn!("⚠️ No jobs returned for request_id={}", request_id);
        return Ok(true);
    }

    info!("✅ Claimed {} job(s) for request_id={}", claim_response.jobs.len(), request_id);

    // Agent Connect: a job whose context sender differs from the party that
    // actually called is claiming to run under a bound account's name. The
    // claim arrives from the coordinator, but "acting as agent.tla" is an
    // identity statement, so it is settled by the CHAIN, here in the TEE: the
    // named account must list the caller as a live extension. Any fault —
    // including not being able to ask — refuses the job rather than falling
    // back to the caller's own name: a guest that derives keys from its sender
    // must never run under an unverified one. Sits AFTER the claim so the
    // refusal completes the job with a readable reason instead of leaving it
    // queued for another worker to hit the same wall.
    //
    // BOTH entry paths, so one agent's module behaves the same whichever way
    // it was started. What differs is only who has to prove the claim, and in
    // both cases it is the party that paid — the identity that stays in
    // `NEAR_USER_ACCOUNT_ID`:
    //
    //   HTTPS    → the payment key's owner, which for an agent key IS the
    //              wallet's own implicit account (asserted below);
    //   on-chain → the account that sent the transaction. It may be NAMED —
    //              a user's own account, or a contract relaying for them — so
    //              the implicit-account assert must NOT be applied here. It
    //              exists to catch a credential path attaching a wallet to a
    //              named owner, which is an HTTPS-only concern.
    let claim = identity_claim(
        is_https_call,
        context.sender_id.as_deref(),
        payment_key_owner.as_deref(),
        user_account_id.as_deref(),
    );

    let bound_sender: Option<String> = match claim {
        // The coordinator was asked for a bound identity and had none to give.
        // Refused rather than run under the caller's own name: the request
        // named the identity it wanted, and quietly substituting another
        // answers a question nobody asked.
        Some((claimed, _, _)) if claimed.is_empty() => {
            let error_msg =
                "Refusing to run: use_bound_identity was requested, but this caller has no \
                 active binding to run as".to_string();
            error!("❌ {}", error_msg);
            refuse_claimed_jobs(api_client, near_client, claim_response.jobs, request_id, is_https_call, call_id.as_deref(), error_msg).await?;
            return Ok(true);
        }
        Some((claimed, payer, require_implicit)) => {
            use shared_tee_helpers::binding::{
                admit, status_query, BindingKind, ChainObservation, PlainStatus, StatusQuery,
            };
            let now_ns = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            // The job's kind is a HINT for which evidence to gather; absent
            // (queued before the field existed) means the partner mode,
            // exactly the pre-kind behavior. The verdict itself comes from
            // `admit`, which is fail-closed against evidence of the wrong
            // shape — a lying hint can only refuse the job.
            // The account whose membership we are about to check IS the payer,
            // and that holds only because a job carries a wallet solely when
            // the credential was an AGENT key, whose payment_keys.owner is the
            // wallet's own implicit account. Assert the shape rather than trust
            // the chain of reasoning: if a future credential path ever attaches
            // a wallet to a NAMED owner, this refuses instead of quietly
            // verifying the wrong account's extension set.
            let kind = if require_implicit && !shared_tee_helpers::is_implicit_account(payer) {
                Err(format!(
                    "Refusing to run as '{}': the executor identity '{}' is not an implicit \
                     account, so it cannot be this wallet's own",
                    claimed, payer
                ))
            } else {
                match binding_kind.as_deref() {
                    None => Ok(BindingKind::HosLease),
                    Some(s) => BindingKind::parse(s).ok_or_else(|| {
                        format!(
                            "Refusing to run as '{}': unknown binding kind '{}'",
                            claimed, s
                        )
                    }),
                }
            };
            let verdict: Result<(), String> = match kind {
                Err(msg) => Err(msg),
                Ok(kind) => {
                    let observation = match status_query(kind) {
                        StatusQuery::HosAgentStatus => near_client
                            .fetch_hos_agent_status(claimed, payer)
                            .await
                            .map(ChainObservation::HosLease)
                            .map_err(|e| {
                                format!(
                                    "Refusing to run as '{}': cannot verify the binding on chain ({})",
                                    claimed, e
                                )
                            }),
                        StatusQuery::ExtensionAndCodeHash => {
                            let code = near_client.fetch_code_hash(claimed).await;
                            let enabled = near_client.fetch_extension_enabled(claimed, payer).await;
                            // Whether the build is recognized is the
                            // coordinator's list, not this binary's; a list
                            // that cannot be fetched recognizes nothing and
                            // the verdict is the reversible `CodeHashUnknown`.
                            let recognized = api_client.wallet_code_hashes().await;
                            match (code, enabled, recognized) {
                                (Ok(code_hash), Ok(extension_enabled), Ok(recognized)) => {
                                    let code_recognized = recognized
                                        .iter()
                                        .any(|h| h == &bs58::encode(code_hash).into_string());
                                    Ok(ChainObservation::PersonalAccount(PlainStatus {
                                        extension_enabled,
                                        code_hash,
                                        code_recognized,
                                    }))
                                }
                                (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => Err(format!(
                                    "Refusing to run as '{}': cannot verify the binding on chain ({})",
                                    claimed, e
                                )),
                            }
                        }
                    };
                    observation.and_then(|obs| {
                        admit(kind, &obs, now_ns).map(|_| ()).map_err(|fault| {
                            format!("Refusing to run as '{}': {}", claimed, fault)
                        })
                    })
                }
            };
            match verdict {
                Ok(()) => {
                    info!("🔗 Verified bound sender: {} (executor {})", claimed, payer);
                    Some(claimed.to_string())
                }
                Err(error_msg) => {
                    error!("❌ {}", error_msg);
                    refuse_claimed_jobs(api_client, near_client, claim_response.jobs, request_id, is_https_call, call_id.as_deref(), error_msg).await?;
                    return Ok(true);
                }
            }
        }
        // Nobody claimed anything: the sender is the caller, as always.
        None => None,
    };

    // Extract pricing from response
    let pricing = &claim_response.pricing;
    info!(
        "💰 Pricing: per_compile_ms={} max_compile_sec={}",
        pricing.per_compile_ms_fee, pricing.max_compilation_seconds
    );

    // Local WASM cache - if we compile, we keep it in memory for execute job
    let mut compiled_wasm: Option<(String, Vec<u8>, u64, Option<String>, Option<String>)> = None; // (checksum, bytes, compile_time_ms, created_at, published_url)

    // Process each job in order
    for job in claim_response.jobs {
        info!("🔧 Processing job_id={} type={:?}", job.job_id, job.job_type);

        if !job.allowed {
            warn!("⚠️ Job {} not allowed (already completed or failed)", job.job_id);
            continue;
        }

        match job.job_type {
            JobType::Compile => {
                // Skip compile jobs if compilation capability is disabled
                let Some(compiler_ref) = compiler else {
                    warn!("⚠️ Skipping Compile job {} - compilation capability disabled (COMPILATION_ENABLED=false)", job.job_id);
                    continue;
                };

                match handle_compile_job(
                    api_client,
                    compiler_ref,
                    near_client,
                    keystore_client,
                    tdx_client,
                    &job,
                    &code_source,
                    &context,
                    &user_account_id,
                    pricing,
                    near_payment_yocto.as_ref(),
                    request_id,
                    config,
                    store_on_fastfs,
                    force_rebuild,
                    compile_only,
                )
                .await {
                    Ok((checksum, wasm_bytes, compile_time_ms, created_at, published_url)) => {
                        // Store in local cache for execute job (including compile time, created_at, and published_url)
                        compiled_wasm = Some((checksum, wasm_bytes, compile_time_ms, created_at, published_url));
                    }
                    Err(e) => {
                        // Compilation failed - complete_job already called in handle_compile_job
                        // Coordinator will create execute task with compile_error for executor to report
                        error!("❌ Compilation failed: {}", e);
                        return Err(e);
                    }
                }
            }
            JobType::Execute => {
                handle_execute_job(
                    api_client,
                    executor,
                    near_client,
                    keystore_client,
                    tdx_client,
                    &job,
                    &code_source,
                    &resource_limits,
                    &input_data,
                    secrets_ref.as_ref(),
                    &response_format,
                    &context,
                    user_account_id.as_ref(),
                    near_payment_yocto.as_ref(),
                    attached_usd.as_ref(),
                    transaction_hash.as_ref(),
                    request_id,
                    &data_id,
                    compiled_wasm.as_ref().map(|(cs, b, ct, ca, pu)| (cs, b, ct, ca.as_deref(), pu.as_deref())), // Pass local WASM cache with published_url
                    compile_result.as_ref(), // Pass compile_result (published_url or result for compile_only)
                    compile_only,
                    config.use_tee_registration,
                    config,
                    is_https_call,
                    call_id.as_ref(),
                    payment_key_owner.as_ref(),
                    bound_sender.as_ref(),
                    payment_key_nonce,
                    usd_payment.as_ref(),
                    wallet_id.as_ref(),
                    wasm_cache,
                )
                .await?;
            }
        }
    }

    // Note: WASM upload now happens inside handle_compile_job BEFORE complete_job
    // This ensures WASM exists on coordinator when execute task is created

    Ok(true)
}

/// Who is claiming an identity, and who has to prove it.
///
/// `Some((claimed, prover, require_implicit))` when the job runs under a name
/// that is not the caller's own; `None` when the sender IS the caller and there
/// is nothing to verify.
///
/// The verdict is the same on both doors — the claim is settled against the
/// chain — but the PROVER differs, because the two doors know different things:
///
/// * HTTPS has no signature to identify anyone, so the party that proves the
///   claim is the payment key's owner, which for an agent key is the wallet's
///   own implicit account. `require_implicit` asks for that shape to be checked
///   rather than assumed: if a future credential path ever attaches a wallet to
///   a NAMED owner, this refuses instead of quietly verifying the wrong
///   account's extension set.
/// * On-chain the caller is already established by a signature, and the claim
///   is constrained before it ever reaches here: the coordinator resolves it by
///   looking a binding up under `executor_account_id = <the caller>`, and an
///   executor is derived from the wallet's own ed25519 key — always a 64-hex
///   implicit account. A NAMED account cannot match, which is what limits this
///   door to agents holding a keypair; a user's own `alice.near` is the ASSET
///   side of a binding, never the executor side.
///
///   So `require_implicit` is false there not as a relaxation but because the
///   check would be dead: nothing named can arrive with a claim. The invariant
///   it leans on is pinned by `binding::executor_shape` in the coordinator,
///   because if the derivation ever changed this door would open silently.
///
/// In both cases the prover is the party that paid, which is the identity that
/// stays in `NEAR_USER_ACCOUNT_ID`.
/// Whose name separates one VRF domain from another.
///
/// **The payer, on both doors** — and the two have to agree, because the whole
/// point of `use_bound_identity` is that one WASI module behaves the same
/// whichever way it was started.
///
/// They very nearly did not. `context.sender_id` used to be the account that
/// sent the transaction, and reading it here was the same as reading the payer.
/// It is not any more: with a binding the coordinator replaces it with the
/// BOUND account, which is the guest's name. Falling through to it would have
/// made the same module draw a different random stream depending on the door —
/// on chain the alpha would follow the bound name, over HTTPS the payment key's
/// owner, for one flag and one request.
///
/// `user_account_id` is the transaction's own sender and is never rewritten,
/// so it slots in ahead of the fallback. For every request that carries no
/// binding the three are the same account and nothing changes at all — which
/// is also why this cannot be observed as a regression by anything running
/// today. Storage already resolves its account this way (see
/// `storage_account_id` below); this brings VRF back in line with it.
fn vrf_domain_identity(
    payment_key_owner: Option<&String>,
    user_account_id: Option<&String>,
    context_sender: Option<&String>,
) -> Option<String> {
    payment_key_owner
        .or(user_account_id)
        .or(context_sender)
        .cloned()
}

fn identity_claim<'a>(
    is_https_call: bool,
    context_sender: Option<&'a str>,
    payment_key_owner: Option<&'a str>,
    user_account_id: Option<&'a str>,
) -> Option<(&'a str, &'a str, bool)> {
    let (claimed, prover, require_implicit) = if is_https_call {
        (context_sender?, payment_key_owner?, true)
    } else {
        (context_sender?, user_account_id?, false)
    };
    // Same name on both sides: nobody is claiming anything.
    if claimed == prover {
        return None;
    }
    Some((claimed, prover, require_implicit))
}

/// Every environment variable the WORKER owns. A guest may read these as
/// facts about its run; nothing a caller supplies may occupy one.
///
/// This is the authoritative list, and two tests keep it that way:
/// `every_injected_variable_is_declared_a_system_name` here (the list covers
/// every name this file writes) and, in the keystore,
/// `every_worker_system_variable_is_a_reserved_secret_key` (every name on this
/// list is refused as a secret key on the way in). Add a variable to the
/// worker and the first test names the list; add it to the list and the second
/// names the keystore.
pub const SYSTEM_ENV_VARS: &[&str] = &[
    // Identity — who the guest acts as, and who pays.
    "NEAR_SENDER_ID",
    "NEAR_USER_ACCOUNT_ID",
    "NEAR_PREDECESSOR_ID",
    "NEAR_SIGNER_PUBLIC_KEY",
    // Where and what kind of run.
    "NEAR_NETWORK_ID",
    "OUTLAYER_EXECUTION_TYPE",
    // Correlation.
    "NEAR_REQUEST_ID",
    "OUTLAYER_CALL_ID",
    "NEAR_TRANSACTION_HASH",
    "NEAR_RECEIPT_ID",
    // On-chain context.
    "NEAR_CONTRACT_ID",
    "NEAR_BLOCK_HEIGHT",
    "NEAR_BLOCK_TIMESTAMP",
    "NEAR_GAS_BURNT",
    // Money.
    "NEAR_PAYMENT_YOCTO",
    "ATTACHED_USD",
    "USD_PAYMENT",
    // Limits.
    "NEAR_MAX_INSTRUCTIONS",
    "NEAR_MAX_MEMORY_MB",
    "NEAR_MAX_EXECUTION_SECONDS",
    // Project.
    "OUTLAYER_PROJECT_ID",
    "OUTLAYER_PROJECT_UUID",
    "OUTLAYER_PROJECT_NAME",
    "OUTLAYER_PROJECT_OWNER",
    // Custody. Written outside `merge_env_vars`, and stripped there like the
    // rest — the guest's authoritative answer is the `wallet::get_id` host
    // function, but a forged value in the environment would still mislead
    // anything that reads it instead.
    "WALLET_ID",
    // Capability advertisement, written by the P2 executor straight onto the
    // WASI builder rather than through the map above. Present only when the
    // proxy exists — and a name written CONDITIONALLY is exactly the shape a
    // caller's secret survives in, so it belongs here regardless of the fact
    // that, today, the executor happens to write it after the secrets.
    "NEAR_RPC_PROXY_AVAILABLE",
];

/// Merge user secrets with system environment variables
///
/// For HTTPS calls, blockchain-related env vars are set to empty strings
/// and additional HTTPS-specific vars are added (OUTLAYER_EXECUTION_TYPE, USD_PAYMENT, etc.)
fn merge_env_vars(
    user_secrets: Option<std::collections::HashMap<String, String>>,
    context: &api_client::ExecutionContext,
    resource_limits: &api_client::ResourceLimits,
    request_id: u64,
    user_account_id: Option<&String>,
    near_payment_yocto: Option<&String>,
    attached_usd: Option<&String>,
    transaction_hash: Option<&String>,
    project_id: Option<&String>,
    project_uuid: Option<&String>,
    // HTTPS-specific parameters
    is_https_call: bool,
    call_id: Option<&String>,
    payment_key_owner: Option<&String>,
    // Agent Connect: the CHAIN-VERIFIED bound asset account (verified by the
    // caller against hos_agent_status before this function runs). When set,
    // the guest's sender identity; billing stays on payment_key_owner.
    bound_sender: Option<&String>,
    usd_payment: Option<&String>,
    // Network configuration
    near_rpc_url: &str,
) -> std::collections::HashMap<String, String> {

    let mut env_vars = user_secrets.unwrap_or_default();

    // Take every system name away from the secrets BEFORE a single system
    // value is written.
    //
    // The old guarantee was positional — secrets go in first, system variables
    // are written over them — and it only ever held for the names that are
    // written UNCONDITIONALLY. Most are not: `NEAR_PREDECESSOR_ID` and its
    // neighbours are written `if let Some(..)` from the on-chain context, and
    // `OUTLAYER_PROJECT_OWNER` only when a project id exists and contains a
    // slash. For those, a secret of the same name simply survived, and the
    // guest read a caller-chosen value as system truth.
    //
    // Stripping instead of overwriting also keeps ABSENT distinct from EMPTY:
    // a guest doing `env::var("OUTLAYER_PROJECT_OWNER").ok()?` must still see
    // "no project" rather than a blank string that reads as one.
    for key in SYSTEM_ENV_VARS {
        env_vars.remove(*key);
    }

    // Determine network from RPC URL
    let network_id = if near_rpc_url.contains("mainnet") { "mainnet" } else { "testnet" };
    env_vars.insert("NEAR_NETWORK_ID".to_string(), network_id.to_string());

    // Set execution type
    env_vars.insert(
        "OUTLAYER_EXECUTION_TYPE".to_string(),
        if is_https_call { "HTTPS".to_string() } else { "NEAR".to_string() }
    );

    if is_https_call {
        // HTTPS mode: set blockchain vars to empty.
        //
        // NEAR_SENDER_ID — the guest-visible identity: the verified bound
        // asset account when the wallet operates one (Agent Connect), the
        // payment key owner otherwise. NEAR_USER_ACCOUNT_ID always stays the
        // payment key owner: it is the BILLING identity, and a binding
        // renames who the guest acts as, not who pays.
        if let Some(sender) = bound_sender.or(payment_key_owner) {
            env_vars.insert("NEAR_SENDER_ID".to_string(), sender.clone());
        }
        if let Some(owner) = payment_key_owner {
            env_vars.insert("NEAR_USER_ACCOUNT_ID".to_string(), owner.clone());
        }

        // Blockchain vars = empty strings (not available for HTTPS)
        env_vars.insert("NEAR_CONTRACT_ID".to_string(), "".to_string());
        env_vars.insert("NEAR_BLOCK_HEIGHT".to_string(), "".to_string());
        env_vars.insert("NEAR_BLOCK_TIMESTAMP".to_string(), "".to_string());
        env_vars.insert("NEAR_RECEIPT_ID".to_string(), "".to_string());
        env_vars.insert("NEAR_PREDECESSOR_ID".to_string(), "".to_string());
        env_vars.insert("NEAR_SIGNER_PUBLIC_KEY".to_string(), "".to_string());
        env_vars.insert("NEAR_GAS_BURNT".to_string(), "".to_string());
        env_vars.insert("NEAR_TRANSACTION_HASH".to_string(), "".to_string());
        env_vars.insert("NEAR_REQUEST_ID".to_string(), "".to_string());

        // HTTPS has no NEAR payment or attached deposit
        env_vars.insert("NEAR_PAYMENT_YOCTO".to_string(), "0".to_string());
        env_vars.insert("ATTACHED_USD".to_string(), "0".to_string());

        // HTTPS-specific: USD payment to project owner
        env_vars.insert(
            "USD_PAYMENT".to_string(),
            usd_payment.cloned().unwrap_or_else(|| "0".to_string())
        );

        // HTTPS-specific: call ID (UUID)
        if let Some(cid) = call_id {
            env_vars.insert("OUTLAYER_CALL_ID".to_string(), cid.clone());
        } else {
            env_vars.insert("OUTLAYER_CALL_ID".to_string(), "".to_string());
        }
    } else {
        // NEAR transaction mode: use context values

        // Add execution context
        if let Some(ref sender_id) = context.sender_id {
            env_vars.insert("NEAR_SENDER_ID".to_string(), sender_id.clone());
        }
        if let Some(ref contract_id) = context.contract_id {
            env_vars.insert("NEAR_CONTRACT_ID".to_string(), contract_id.clone());
        }
        if let Some(block_height) = context.block_height {
            env_vars.insert("NEAR_BLOCK_HEIGHT".to_string(), block_height.to_string());
        }
        if let Some(block_timestamp) = context.block_timestamp {
            env_vars.insert("NEAR_BLOCK_TIMESTAMP".to_string(), block_timestamp.to_string());
        }
        if let Some(ref receipt_id) = context.receipt_id {
            env_vars.insert("NEAR_RECEIPT_ID".to_string(), receipt_id.clone());
        }
        if let Some(ref predecessor_id) = context.predecessor_id {
            env_vars.insert("NEAR_PREDECESSOR_ID".to_string(), predecessor_id.clone());
        }
        if let Some(ref signer_public_key) = context.signer_public_key {
            env_vars.insert("NEAR_SIGNER_PUBLIC_KEY".to_string(), signer_public_key.clone());
        }
        if let Some(gas_burnt) = context.gas_burnt {
            env_vars.insert("NEAR_GAS_BURNT".to_string(), gas_burnt.to_string());
        }

        // Add user account and payment info
        if let Some(user_id) = user_account_id {
            env_vars.insert("NEAR_USER_ACCOUNT_ID".to_string(), user_id.clone());
        }
        if let Some(payment) = near_payment_yocto {
            env_vars.insert("NEAR_PAYMENT_YOCTO".to_string(), payment.clone());
        }
        if let Some(deposit) = attached_usd {
            env_vars.insert("ATTACHED_USD".to_string(), deposit.clone());
        } else {
            env_vars.insert("ATTACHED_USD".to_string(), "0".to_string());
        }
        if let Some(tx_hash) = transaction_hash {
            env_vars.insert("NEAR_TRANSACTION_HASH".to_string(), tx_hash.clone());
        }

        // Add request ID
        env_vars.insert("NEAR_REQUEST_ID".to_string(), request_id.to_string());

        // NEAR mode doesn't have USD payment or call_id
        env_vars.insert("USD_PAYMENT".to_string(), "0".to_string());
        env_vars.insert("OUTLAYER_CALL_ID".to_string(), "".to_string());
    }

    // Add resource limits (same for both modes)
    env_vars.insert("NEAR_MAX_INSTRUCTIONS".to_string(), resource_limits.max_instructions.to_string());
    env_vars.insert("NEAR_MAX_MEMORY_MB".to_string(), resource_limits.max_memory_mb.to_string());
    env_vars.insert("NEAR_MAX_EXECUTION_SECONDS".to_string(), resource_limits.max_execution_seconds.to_string());

    // Add project context (same for both modes)
    if let Some(proj_id) = project_id {
        env_vars.insert("OUTLAYER_PROJECT_ID".to_string(), proj_id.clone());
        // Split by first '/' only (project name may contain '/')
        if let Some(slash_pos) = proj_id.find('/') {
            let owner = &proj_id[..slash_pos];
            let name = &proj_id[slash_pos + 1..];
            env_vars.insert("OUTLAYER_PROJECT_OWNER".to_string(), owner.to_string());
            env_vars.insert("OUTLAYER_PROJECT_NAME".to_string(), name.to_string());
        }
    }
    if let Some(proj_uuid) = project_uuid {
        env_vars.insert("OUTLAYER_PROJECT_UUID".to_string(), proj_uuid.clone());
    }

    env_vars
}

/// Fetch WASM bytes from coordinator or local cache
///
/// For P1: uses WasmCache (raw bytes LRU cache)
/// For P2: downloads directly (CompiledCache handles caching in executor)
async fn fetch_wasm_bytes(
    api_client: &ApiClient,
    wasm_checksum: &str,
    wasm_cache: Option<&Arc<Mutex<WasmCache>>>,
    is_p2: bool,
    meta: &Option<api_client::WasmMeta>,
) -> Result<Vec<u8>> {
    // The raw-bytes LRU serves both targets. `get()` re-hashes the file
    // against the hash it recorded in memory when the bytes were stored, so a
    // P2 guest that reached the cache directory through its `/tmp` preopen
    // (the fallback location) could corrupt an entry, never substitute one;
    // and a coordinates-keyed entry (a GitHub build) is served only while the
    // coordinator still holds those same bytes under the key.
    let created_at = meta.as_ref().and_then(|m| m.created_at.clone());
    let current_content_hash = meta.as_ref().and_then(|m| m.content_hash.as_deref());
    if let Some(cache) = wasm_cache {
        if let Some(cached_bytes) = cache.lock().ok().and_then(|mut c| c.get(wasm_checksum, current_content_hash)) {
            info!("✅ WASM LRU cache hit: {} ({}KB) is_p2={}", wasm_checksum, cached_bytes.len() / 1024, is_p2);
            return Ok(cached_bytes);
        }
    }

    // Download from coordinator
    info!("📥 Downloading WASM: checksum={} (cached since: {:?}) is_p2={}", wasm_checksum, created_at, is_p2);
    let bytes = api_client.download_wasm(wasm_checksum).await
        .map_err(|e| {
            error!("❌ Failed to download WASM: {}", e);
            anyhow::anyhow!("Failed to download WASM: {}", e)
        })?;

    info!("✅ Downloaded WASM: {} bytes", bytes.len());
    Ok(bytes)
}

/// Handle a compile job
/// Returns (checksum, wasm_bytes, compile_time_ms) for local caching
async fn handle_compile_job(
    api_client: &ApiClient,
    compiler: &Compiler,
    _near_client: &NearClient,
    _keystore_client: Option<&KeystoreClient>,
    tdx_client: &tdx_attestation::TdxClient,
    job: &JobInfo,
    code_source: &CodeSource,
    context: &api_client::ExecutionContext,
    user_account_id: &Option<String>,
    pricing: &api_client::PricingConfig,
    user_payment: Option<&String>,
    request_id: u64,
    config: &Config,
    store_on_fastfs: bool,
    force_rebuild: bool,
    _compile_only: bool,
) -> Result<(String, Vec<u8>, u64, Option<String>, Option<String>)> {
    // Returns (checksum, wasm_bytes, compile_time_ms, created_at, published_url)
    info!("🔨 Starting compilation job_id={} request_id={}", job.job_id, request_id);

    // Check if this is a WasmUrl source - if so, download instead of compile
    if let CodeSource::WasmUrl { url, hash, build_target } = code_source {
        info!("📥 WasmUrl source detected - downloading from URL instead of compiling");
        info!("   URL: {}", url);
        info!("   Hash: {}", hash);

        let start_time = std::time::Instant::now();

        // Download and cache WASM
        let result = compiler.download_and_cache_wasm(url, hash, build_target).await;
        let download_time_ms = start_time.elapsed().as_millis() as u64;

        match result {
            Ok((checksum, wasm_bytes, created_at)) => {
                info!("✅ WASM downloaded: checksum={} size={} bytes time={}ms cached={:?}",
                    checksum, wasm_bytes.len(), download_time_ms, created_at.is_some());

                // Report completion to coordinator
                // Note: For downloads, we report 0 compile_cost (no compilation happened)
                if let Err(e) = api_client
                    .complete_job(
                        job.job_id,
                        true,
                        None,
                        None,
                        download_time_ms,
                        0, // No instructions for download
                        Some(checksum.clone()),
                        None, // No actual_cost for download jobs
                        Some("0".to_string()), // Zero compile cost - just download
                        None, // No error category for success
                        None, // No compile_result
                    )
                    .await
                {
                    warn!("⚠️ Failed to report download job completion: {}", e);
                }

                return Ok((checksum, wasm_bytes, download_time_ms, created_at, None)); // No FastFS for WasmUrl downloads
            }
            Err(e) => {
                let error_msg = e.to_string();
                warn!("❌ WASM download failed: {}", error_msg);

                // Report failure to coordinator
                if let Err(report_err) = api_client
                    .complete_job(
                        job.job_id,
                        false,
                        None,
                        Some(error_msg.clone()),
                        download_time_ms,
                        0,
                        None,
                        None,
                        None,
                        Some(api_client::JobStatus::CompilationFailed), // Reuse status for download failures
                        None, // No compile_result
                    )
                    .await
                {
                    warn!("⚠️ Failed to report download job failure: {}", report_err);
                }

                return Err(e);
            }
        }
    }

    // Extract GitHub fields - compile jobs for GitHub source
    let (repo, commit, build_target) = match code_source {
        CodeSource::GitHub { repo, commit, build_target } => {
            // If commit is empty, use "main" as default
            let commit_str = if commit.is_empty() {
                info!("⚠️ Commit is empty, using 'main' as default branch");
                "main"
            } else {
                commit.as_str()
            };
            (repo.as_str(), commit_str, build_target.as_str())
        },
        CodeSource::WasmUrl { .. } => unreachable!("WasmUrl handled above"),
    };

    // Validate compilation budget
    if let Some(payment_str) = user_payment {
        // Parse pricing and payment
        let per_compile_ms_fee: u128 = pricing.per_compile_ms_fee.parse()
            .context("Failed to parse per_compile_ms_fee")?;
        let user_payment_yocto: u128 = payment_str.parse()
            .context("Failed to parse user_payment")?;

        // Calculate max affordable compilation time
        let max_affordable_seconds = if per_compile_ms_fee > 0 {
            (user_payment_yocto / per_compile_ms_fee / 1000) as u64
        } else {
            u64::MAX
        };

        info!(
            "💰 Compilation budget check: payment={} yoctoNEAR, max_affordable={}s, contract_limit={}s",
            user_payment_yocto, max_affordable_seconds, pricing.max_compilation_seconds
        );

        // Check if user's payment covers at least minimum compilation time (30 seconds)
        const MIN_COMPILATION_SECONDS: u64 = 30;
        if max_affordable_seconds < MIN_COMPILATION_SECONDS {
            let min_payment = (MIN_COMPILATION_SECONDS as u128) * 1000 * per_compile_ms_fee;
            let error_msg = format!(
                "Insufficient payment for compilation: payment covers only {}s but minimum is {}s. Need at least {} yoctoNEAR",
                max_affordable_seconds,
                MIN_COMPILATION_SECONDS,
                min_payment
            );
            error!("❌ {}", error_msg);

            // Report budget error to coordinator
            if let Err(e) = api_client
                .complete_job(job.job_id, false, None, Some(error_msg.clone()), 0, 0, None, None, None, Some(api_client::JobStatus::InsufficientPayment), None)
                .await
            {
                warn!("⚠️ Failed to report budget error: {}", e);
            }

            return Err(anyhow::anyhow!(error_msg));
        }
    }

    let start_time = std::time::Instant::now();

    // Calculate timeout: min(contract_limit, user_budget_limit)
    let timeout_seconds = if let Some(payment_str) = user_payment {
        let per_compile_ms_fee: u128 = pricing.per_compile_ms_fee.parse().unwrap_or(1);
        let user_payment_yocto: u128 = payment_str.parse().unwrap_or(0);
        let budget_limit = if per_compile_ms_fee > 0 {
            (user_payment_yocto / per_compile_ms_fee / 1000) as u64
        } else {
            pricing.max_compilation_seconds
        };
        Some(std::cmp::min(budget_limit, pricing.max_compilation_seconds))
    } else {
        Some(pricing.max_compilation_seconds)
    };

    // Compile the code with timeout (returns checksum and bytes, does NOT upload yet)
    let compile_result = compiler.compile_local_with_options(code_source, timeout_seconds, force_rebuild).await;
    let compile_time_ms = start_time.elapsed().as_millis() as u64;

    match compile_result {
        Ok((checksum, wasm_bytes, created_at)) => {
            info!("✅ Compilation successful: checksum={} size={} bytes time={}ms cached={:?}",
                checksum, wasm_bytes.len(), compile_time_ms, created_at.is_some());

            // Calculate compilation cost: compile_time_ms * per_compile_ms_fee
            let per_compile_ms_fee: u128 = pricing.per_compile_ms_fee.parse()
                .unwrap_or_else(|_| {
                    warn!("Failed to parse per_compile_ms_fee, using 0");
                    0
                });
            let compile_cost_yocto = compile_time_ms as u128 * per_compile_ms_fee;

            if compile_cost_yocto > 0 {
                info!("💰 Compilation cost: {} yoctoNEAR ({:.6} NEAR) = {}ms * {} yoctoNEAR/ms",
                    compile_cost_yocto,
                    compile_cost_yocto as f64 / 1e24,
                    compile_time_ms,
                    per_compile_ms_fee
                );
            }

            // Upload WASM to coordinator BEFORE complete_job
            // This ensures WASM exists when coordinator creates execute task
            info!("📤 Uploading compiled WASM to coordinator...");
            if let Err(e) = api_client
                .upload_wasm(
                    checksum.clone(),
                    repo.to_string(),
                    commit.to_string(),
                    build_target.to_string(),
                    wasm_bytes.clone(),
                )
                .await
            {
                warn!("⚠️ Failed to upload WASM to coordinator: {}", e);
                // Continue anyway - complete_job will still work, but execute task may fail
            } else {
                info!("✅ WASM uploaded successfully");
            }

            // Upload to FastFS if requested (before complete_job to include result)
            let mut compile_result_for_executor: Option<String> = None;
            let mut published_url: Option<String> = None;

            if store_on_fastfs {
                if let Some(ref fastfs_receiver) = config.fastfs_receiver {
                    // Use dedicated FastFS sender if configured, otherwise use operator
                    let signer = config.fastfs_sender_signer.clone()
                        .unwrap_or_else(|| config.get_operator_signer().clone());

                    info!("📦 Uploading compiled WASM to FastFS...");
                    info!("   Sender: {}", signer.account_id);
                    info!("   Receiver: {}", fastfs_receiver);

                    let fastfs_client = fastfs::FastFsClient::new(
                        &config.near_rpc_url,
                        signer.clone(),
                        fastfs_receiver,
                    );

                    // Build the FastFS URL (same format regardless of transaction success)
                    let fastfs_url = format!(
                        "https://{}.fastfs.io/{}/{}.wasm",
                        signer.account_id,
                        fastfs_receiver,
                        checksum
                    );

                    match fastfs_client.upload_wasm(&wasm_bytes, &checksum).await {
                        Ok(url) => {
                            info!("✅ FastFS upload successful: {}", url);
                        }
                        Err(_) => {
                            // FastFS transaction "fails" but indexer picks up the file - this is expected
                            // The info message was already logged in fastfs.rs
                            info!("📁 FastFS URL: {}", fastfs_url);
                        }
                    }

                    // Always save published URL for compilation_note
                    published_url = Some(fastfs_url.clone());

                    // Always pass the URL to executor via compile_result
                    // For compile_only: executor sends URL to contract as result
                    // For normal: executor uses URL in compilation_note
                    info!("📤 Setting compile_result for executor: {}", fastfs_url);
                    compile_result_for_executor = Some(fastfs_url);
                } else {
                    warn!("⚠️ store_on_fastfs=true but FASTFS_RECEIVER not configured, skipping upload");
                }
            }

            // Report completion to coordinator
            // If compile_result is set, coordinator will create execute task for executor to send result
            if let Err(e) = api_client
                .complete_job(
                    job.job_id,
                    true,
                    None,
                    None,
                    compile_time_ms,
                    0, // No instructions for compilation
                    Some(checksum.clone()),
                    None, // No actual_cost for compile jobs
                    Some(compile_cost_yocto.to_string()), // Send compile cost
                    None, // No error category for success
                    compile_result_for_executor, // Pass FastFS URL to executor
                )
                .await
            {
                warn!("⚠️ Failed to report compile job completion: {}", e);
                // Continue anyway - will upload later
            }

            // Generate and store TDX attestation only if TEE registration is enabled
            if config.use_tee_registration {
                match tdx_client.generate_task_attestation(
                    "compile",
                    job.job_id,
                    Some(repo),
                    Some(commit),
                    Some(build_target),
                    None, // No wasm_hash for compile (we produce it)
                    None, // No input_hash for compile
                    &checksum, // output_hash is the compiled WASM checksum
                    context.block_height,
                    user_account_id.as_deref(),
                    job.project_id.as_deref(),
                    None, // No secrets_ref for compile
                    job.created_at,
                    None, // No attached_usd for compile
                ).await {
                    Ok(tdx_quote) => {
                        // Send attestation to coordinator
                        let attestation_request = api_client::StoreAttestationRequest {
                            task_id: job.job_id,
                            task_type: api_client::TaskType::Compile,
                            tdx_quote,
                            request_id: Some(request_id as i64),
                            caller_account_id: user_account_id.clone(),
                            transaction_hash: context.transaction_hash.clone(),
                            block_height: context.block_height,
                            // HTTPS call context - None for NEAR calls
                            call_id: None,
                            payment_key_owner: None,
                            payment_key_nonce: None,
                            repo_url: Some(repo.to_string()),
                            commit_hash: Some(commit.to_string()),
                            build_target: Some(build_target.to_string()),
                            wasm_hash: None,
                            executed_wasm_sha256: None,
                            input_hash: None,
                            output_hash: checksum.clone(),
                            // V1 fields
                            project_id: job.project_id.clone(),
                            secrets_ref: None, // No secrets for compile
                            attached_usd: None, // No attached_usd for compile
                            timestamp: Some(job.created_at),
                        };

                        if let Err(e) = api_client.store_attestation(attestation_request).await {
                            warn!("⚠️ Failed to store compilation attestation: {}", e);
                            // Non-critical - continue anyway
                        } else {
                            info!("✅ Stored compilation attestation for task_id={}", job.job_id);
                        }
                    }
                    Err(e) => {
                        warn!("⚠️ Failed to generate TDX attestation for compilation: {}", e);
                        // Non-critical - continue anyway
                    }
                }
            } else {
                debug!("Skipping attestation generation (USE_TEE_REGISTRATION=false)");
            }

            Ok((checksum, wasm_bytes, compile_time_ms, created_at, published_url))
        }
        Err(e) => {
            let error_msg = e.to_string();
            warn!("❌ Compilation failed: {}", error_msg);

            // Check if this is a CompilationError with raw logs
            if let Some(comp_err) = e.downcast_ref::<compiler::CompilationError>() {
                // Store raw logs for admin debugging ONLY if enabled
                // WARNING: system_hidden_logs table should NEVER be exposed via public API
                if config.save_system_hidden_logs_to_debug {
                    if let Err(log_err) = api_client
                        .store_system_log(
                            request_id,
                            Some(job.job_id),
                            "compilation",
                            Some(comp_err.stderr.clone()),
                            Some(comp_err.stdout.clone()),
                            comp_err.exit_code,
                            None,
                        )
                        .await
                    {
                        warn!("⚠️ Failed to store compilation logs: {}", log_err);
                    }
                }
            }

            // Report failure to coordinator with detailed user-facing error message
            // The error_msg already contains safe, user-facing description from classify_compilation_error()
            if let Err(report_err) = api_client
                .complete_job(
                    job.job_id,
                    false,
                    None,
                    Some(error_msg.clone()),
                    compile_time_ms,
                    0,
                    None,
                    None,
                    None,
                    Some(api_client::JobStatus::CompilationFailed),
                    None, // No compile_result
                )
                .await
            {
                warn!("⚠️ Failed to report compile job failure: {}", report_err);
            }

            Err(e)
        }
    }
}

/// Handle an execute job
#[allow(clippy::too_many_arguments)]
async fn handle_execute_job(
    api_client: &ApiClient,
    executor: &Executor,
    near_client: &NearClient,
    keystore_client: Option<&KeystoreClient>,
    tdx_client: &tdx_attestation::TdxClient,
    job: &JobInfo,
    code_source: &CodeSource,
    resource_limits: &api_client::ResourceLimits,
    input_data: &str,
    secrets_ref: Option<&api_client::SecretsReference>,
    response_format: &api_client::ResponseFormat,
    context: &api_client::ExecutionContext,
    user_account_id: Option<&String>,
    near_payment_yocto: Option<&String>,
    attached_usd: Option<&String>,
    transaction_hash: Option<&String>,
    request_id: u64,
    data_id: &str,
    compiled_wasm: Option<(&String, &Vec<u8>, &u64, Option<&str>, Option<&str>)>, // Local cache from compile job (checksum, bytes, compile_time_ms, created_at, published_url)
    compile_result: Option<&String>, // Result from compile job (published_url or result for compile_only)
    compile_only: bool,
    use_tee_registration: bool,
    config: &Config, // For storage config
    is_https_call: bool, // HTTPS API call - skip NEAR contract, call coordinator
    call_id: Option<&String>, // HTTPS call ID for coordinator completion
    payment_key_owner: Option<&String>, // Payment Key owner for HTTPS calls
    bound_sender: Option<&String>, // Agent Connect: chain-verified bound asset account (verified in worker_iteration)
    payment_key_nonce: Option<i32>, // Payment Key nonce for HTTPS calls
    usd_payment: Option<&String>, // USD payment amount for HTTPS calls
    wallet_id: Option<&String>, // Wallet ID for wallet-enabled WASM executions
    wasm_cache: Option<&Arc<Mutex<WasmCache>>>, // Local raw-bytes LRU cache (both targets)
) -> Result<()> {
    info!("⚙️ Starting execution job_id={}", job.job_id);

    // Extract published_url from compile_result (if set by compiler)
    // For compile_only=true: send as result, for compile_only=false: use in compilation_note
    let published_url_from_compile_result = compile_result.cloned();

    // Check if this is a compile-only task
    // Return compile_result (FastFS URL) if available, otherwise return WASM checksum
    if compile_only {
        let result_to_send = if let Some(cr) = compile_result {
            cr.clone()
        } else if let Some((checksum, _, _, _, _)) = compiled_wasm {
            checksum.clone()
        } else {
            anyhow::bail!("compile_only=true but no compile result or WASM checksum available");
        };
        info!("📤 Compile-only task: sending result: {}", result_to_send);

        // Use consistent "Published to" format for URLs
        let compilation_note = if result_to_send.starts_with("http") {
            format!("Published to {}", result_to_send)
        } else {
            format!("Result from compilation: {}", result_to_send)
        };

        let result = api_client::ExecutionResult {
            success: true,
            output: Some(api_client::ExecutionOutput::Text(result_to_send.clone())),
            error: None,
            execution_time_ms: 0, // No execution
            instructions: 0, // No execution
            compile_time_ms: None, // Already counted in compile job
            compilation_note: Some(compilation_note),
            refund_usd: None,
        };

        if is_https_call {
            // HTTPS calls: report compile result to coordinator
            let call_id_str = call_id.as_ref()
                .ok_or_else(|| anyhow::anyhow!("HTTPS call missing call_id for compile_only result"))?;
            let output_json = Some(serde_json::Value::String(result_to_send.clone()));
            match api_client.complete_https_call(
                call_id_str,
                true,
                output_json,
                None,
                0, // No instructions
                0, // No execution time
                Some(job.job_id),
            ).await {
                Ok(()) => {
                    info!("✅ Compile result submitted to coordinator successfully");

                    if let Err(e) = api_client
                        .complete_job(
                            job.job_id,
                            true,
                            Some(api_client::ExecutionOutput::Text(result_to_send.clone())),
                            None,
                            0,
                            0,
                            None,
                            None,
                            None,
                            None,
                            None,
                        )
                        .await
                    {
                        warn!("⚠️ Failed to report execute job completion: {}", e);
                    }
                }
                Err(e) => {
                    error!("❌ Failed to submit compile result to coordinator: {}", e);

                    if let Err(report_err) = api_client
                        .complete_job(
                            job.job_id,
                            false,
                            None,
                            Some(format!("Failed to submit result: {}", e)),
                            0,
                            0,
                            None,
                            None,
                            None,
                            Some(api_client::JobStatus::Failed),
                            None,
                        )
                        .await
                    {
                        warn!("⚠️ Failed to report execute job failure: {}", report_err);
                    }
                }
            }
        } else {
            // Blockchain calls: submit to NEAR contract
            match near_client.submit_execution_result(request_id, &result).await {
                Ok((tx_hash, outcome)) => {
                    info!("✅ Compile result submitted to NEAR successfully: tx_hash={}", tx_hash);

                    let actual_cost = NearClient::extract_payment_from_logs(&outcome);
                    if actual_cost > 0 {
                        info!("💰 Extracted cost from contract: {} yoctoNEAR ({:.6} NEAR)",
                            actual_cost, actual_cost as f64 / 1e24);
                    }

                    if let Err(e) = api_client
                        .complete_job(
                            job.job_id,
                            true,
                            Some(api_client::ExecutionOutput::Text(result_to_send.clone())),
                            None,
                            0,
                            0,
                            None,
                            if actual_cost > 0 { Some(actual_cost.to_string()) } else { None },
                            None,
                            None,
                            None,
                        )
                        .await
                    {
                        warn!("⚠️ Failed to report execute job completion: {}", e);
                    }
                }
                Err(e) => {
                    error!("❌ Failed to submit compile result to contract: {}", e);

                    if let Err(report_err) = api_client
                        .complete_job(
                            job.job_id,
                            false,
                            None,
                            Some(format!("Failed to submit result to contract: {}", e)),
                            0,
                            0,
                            None,
                            None,
                            None,
                            Some(api_client::JobStatus::Failed),
                            None,
                        )
                        .await
                    {
                        warn!("⚠️ Failed to report execute job failure: {}", report_err);
                    }
                }
            }
        }

        return Ok(());
    }

    // Check if compilation failed - if so, report the error
    if let Some(compile_error) = &job.compile_error {
        // Calculate compile cost (from job info)
        let compile_cost: u128 = job.compile_cost_yocto
            .as_ref()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        if is_https_call {
            // HTTPS calls: report compile error to coordinator (not NEAR contract)
            info!("❌ Compilation failed for HTTPS call, reporting to coordinator: {}", compile_error);

            if let Some(ref call_id_str) = call_id {
                if let Err(https_err) = api_client.complete_https_call(
                    call_id_str,
                    false,
                    None,
                    Some(compile_error.clone()),
                    0,
                    0,
                    Some(job.job_id),
                ).await {
                    error!("❌ Failed to report HTTPS call compile error: {}", https_err);
                }
            }

            // Report failure to coordinator job tracking
            if let Err(e) = api_client
                .complete_job(
                    job.job_id,
                    false,
                    None,
                    Some(compile_error.clone()),
                    0,
                    0,
                    None,
                    Some(compile_cost.to_string()),
                    None,
                    Some(api_client::JobStatus::CompilationFailed),
                    None,
                )
                .await
            {
                warn!("⚠️ Failed to report job completion: {}", e);
            }
        } else {
            // Blockchain calls: report compile error to NEAR contract
            info!("❌ Compilation failed, reporting error to contract: {}", compile_error);

            let error_result = api_client::ExecutionResult {
                success: false,
                output: None,
                error: Some(compile_error.clone()),
                execution_time_ms: 0,
                instructions: 0,
                compile_time_ms: None,
                compilation_note: Some("Compilation failed".to_string()),
                refund_usd: None,
            };

            let near_result = near_client
                .submit_execution_result(request_id, &error_result)
                .await;

            match near_result {
                Ok((tx_hash, _outcome)) => {
                    info!("✅ Compilation error submitted to NEAR successfully: tx_hash={}", tx_hash);

                    if let Err(e) = api_client
                        .complete_job(
                            job.job_id,
                            false,
                            None,
                            Some(compile_error.clone()),
                            0,
                            0,
                            None,
                            Some(compile_cost.to_string()),
                            None,
                            Some(api_client::JobStatus::CompilationFailed),
                            None,
                        )
                        .await
                    {
                        warn!("⚠️ Failed to report job completion: {}", e);
                    }
                }
                Err(e) => {
                    error!("❌ Failed to submit compilation error to contract: {}", e);
                    if let Err(report_err) = api_client
                        .complete_job(
                            job.job_id,
                            false,
                            None,
                            Some(format!("Failed to submit to contract: {}", e)),
                            0,
                            0,
                            None,
                            None,
                            None,
                            Some(api_client::JobStatus::Failed),
                            None,
                        )
                        .await
                    {
                        warn!("⚠️ Failed to report job failure: {}", report_err);
                    }
                }
            }
        }

        return Ok(());
    }

    // Extract compile_cost from job (if compilation was done)
    let compile_cost: u128 = job.compile_cost_yocto
        .as_ref()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    if compile_cost > 0 {
        info!("💰 Compile cost from compiler: {} yoctoNEAR ({:.6} NEAR)",
            compile_cost, compile_cost as f64 / 1e24);
    }

    // Get WASM checksum from job
    let wasm_checksum = job.wasm_checksum.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Execute job missing wasm_checksum"))?;

    // Get build target early to decide caching strategy
    // P2 uses CompiledCache (native code), P1 uses WasmCache (raw bytes)
    let build_target = match code_source {
        CodeSource::GitHub { build_target, .. } => build_target.as_str(),
        CodeSource::WasmUrl { build_target, .. } => build_target.as_str(),
    };
    let is_p2 = build_target == "wasm32-wasip2";

    // The raw bytes are ALWAYS fetched, even when the executor will load a
    // compiled component from its cache: the manifest (allowlist, connector
    // identity, declared limits) and the attested `executed_wasm_sha256` are
    // read from these bytes, and a run that skipped them would resolve an
    // empty allowlist and attest the hash of nothing. The compiled cache only
    // saves the compilation; the raw LRU (`WasmCache`) saves the download.
    let (wasm_bytes, compile_time_ms, created_at, published_url) = if let Some((cached_checksum, cached_bytes, cached_compile_time, cached_created_at, cached_published_url)) = compiled_wasm {
        // Local compile cache from same execution (freshly compiled)
        if cached_checksum == wasm_checksum {
            info!("✅ Using locally compiled WASM: {} bytes (freshly compiled!) compiled in {}ms", cached_bytes.len(), cached_compile_time);
            (cached_bytes.clone(), Some(*cached_compile_time), cached_created_at.map(|s| s.to_string()), cached_published_url.map(|s| s.to_string()))
        } else {
            warn!("⚠️ Checksum mismatch - need to fetch WASM");
            let meta = api_client.wasm_meta(wasm_checksum).await.ok();
            let created_at = meta.as_ref().and_then(|m| m.created_at.clone());
            match fetch_wasm_bytes(api_client, wasm_checksum, wasm_cache, is_p2, &meta).await {
                Ok(bytes) => (bytes, job.compile_time_ms, created_at, None),
                Err(e) => {
                    let error_msg = format!("Failed to download WASM: {}", e);
                    error!("❌ {}", error_msg);
                    report_refusal(api_client, near_client, job, request_id, is_https_call, call_id.map(|s| s.as_str()), error_msg, Some(api_client::JobStatus::Failed)).await?;
                    return Ok(());
                }
            }
        }
    } else {
        // Fetch the bytes: the raw LRU when it has them, otherwise the
        // coordinator
        let meta = api_client.wasm_meta(wasm_checksum).await.ok();
        let created_at = meta.as_ref().and_then(|m| m.created_at.clone());
        match fetch_wasm_bytes(api_client, wasm_checksum, wasm_cache, is_p2, &meta).await {
            Ok(bytes) => (bytes, job.compile_time_ms, created_at, None),
            Err(e) => {
                let error_msg = format!("Failed to download WASM: {}", e);
                error!("❌ {}", error_msg);
                report_refusal(api_client, near_client, job, request_id, is_https_call, call_id.map(|s| s.as_str()), error_msg, Some(api_client::JobStatus::Failed)).await?;
                return Ok(());
            }
        }
    };

    // Project UUID comes from the contract via coordinator - no need to extract from WASM metadata
    // The contract determines which CodeSource to use for a project, and the coordinator passes project_uuid
    // This is secure because WASM cannot fake its project - the binding is enforced by the contract
    let project_uuid = job.project_uuid.clone();
    if let Some(ref uuid) = project_uuid {
        info!("📋 Running in project context: project_id={:?}, project_uuid={}", job.project_id, uuid);
    } else {
        debug!("No project context - running as standalone WASM (storage disabled)");
    }

    // Decrypt secrets from contract if provided (new repo-based system)
    // SHA256 of the bytes that will actually run.
    //
    // Computed from the buffer handed to the runtime, so it is what ran rather
    // than what was asked for. `wasm_checksum` is a cache key: for a GitHub
    // source it hashes the source coordinates, and two different binaries built
    // from one commit share it.
    //
    // Computed before execution rather than after, so the attestation and the
    // egress report describe the same bytes even if the run itself fails.
    let executed_wasm_sha256 = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(&wasm_bytes))
    };

    // The manifest of what actually ran: read once, from the bytes that run,
    // and used for the author's secrets, the network policy, the sub-key
    // gate and the report below.
    let declared_manifest = match connector_manifest::manifest_from_wasm(&wasm_bytes) {
        Ok(m) => m,
        Err(reason) => {
            // A declaration nobody can read is refused, not dropped: with the
            // author's secret would go the author's admission gate.
            let msg = format!(
                "The artefact's manifest cannot be read: {reason}. The run is refused rather than \
                 run without the author's declaration."
            );
            error!("❌ {}", msg);
            report_refusal(
                api_client,
                near_client,
                job,
                request_id,
                is_https_call,
                call_id.map(|s| s.as_str()),
                msg,
                Some(api_client::JobStatus::Custom),
            )
            .await?;
            return Ok(());
        }
    };
    if declared_manifest.is_some() {
        debug!("📄 Manifest read from the wasm's own custom section");
    }

    debug!(
        "secrets_ref: {}; keystore: {}",
        if secrets_ref.is_some() { "present" } else { "none" },
        if keystore_client.is_some() { "configured" } else { "none" }
    );

    // Whether this run belongs to a curated connector. Structural — decided by
    // the project's owner account on chain, which a project cannot claim about
    // itself. Secrets do not care: a connector names and reads them exactly as
    // any other project does. What does care is the operation check just
    // below, and later the outbound allowlist and the sub-key gate.
    let is_connector_call = job
        .project_id
        .as_deref()
        .map(|pid| connector_manifest::is_connector_project(pid, connectors_namespace(&config.near_rpc_url)))
        .unwrap_or(false);

    // A connector call must name its operation, or it does not run.
    //
    // Last of the three checks on the same field, and the only one inside the
    // TEE. The contract priced this call by reading `operation` out of these
    // very bytes; the coordinator billed it the same way. This one asserts the
    // invariant where the code actually runs: if a connector is about to
    // execute a body that names no operation, then something upstream priced
    // nothing, and the safe answer is to run nothing.
    //
    // Refused BEFORE execution, deliberately. Running and then charging would
    // mean the side effect — the email — has already happened, and no amount of
    // money kept afterwards undoes it. The timing is the protection; the money
    // is not.
    //
    // And before the secrets: a call that will not run has nothing to decrypt
    // for, so no keystore round trip is made and no plaintext exists in this
    // process for a run that was never going to happen.
    if let Err(e) = connector_manifest::may_run(is_connector_call, &input_data) {
        let msg = format!("This is a connector call and {} Nothing was executed.", e.message());
        error!("❌ {}", msg);
        report_refusal(
            api_client,
            near_client,
            job,
            request_id,
            is_https_call,
            call_id.map(|s| s.as_str()),
            msg,
            Some(api_client::JobStatus::Custom),
        )
        .await?;
        return Ok(());
    }

    let user_secrets = if let (Some(secrets_ref), Some(keystore)) = (secrets_ref, keystore_client) {
        // A reference the contract could never hold is refused here, naming
        // the rule, before any keystore round trip — the contract's own rule,
        // mirrored with the coordinator's door in shared_tee_helpers.
        if let Err(shape) = shared_tee_helpers::secrets_ref::well_formed_secrets_ref(&secrets_ref.profile, &secrets_ref.account_id) {
            let msg = shape.to_string();
            error!("❌ {}", msg);
            report_refusal(
                api_client,
                near_client,
                job,
                request_id,
                is_https_call,
                call_id.map(|s| s.as_str()),
                msg,
                Some(api_client::JobStatus::Custom),
            )
            .await?;
            return Ok(());
        }
        info!("🔐 Decrypting secrets: profile={}, owner={}", secrets_ref.profile, secrets_ref.account_id);

        // The subject the keystore judges the secret's on-chain
        // `AccessCondition` against. A run with no proven sender decrypts
        // nothing — see `proven_sender`.
        let caller = match proven_sender(user_account_id.map(|s| s.as_str()), &secrets_ref.account_id) {
            Ok(sender) => sender,
            Err(msg) => {
                error!("❌ {}", msg);
                report_refusal(
                    api_client,
                    near_client,
                    job,
                    request_id,
                    is_https_call,
                    call_id.map(|s| s.as_str()),
                    msg,
                    Some(api_client::JobStatus::AccessDenied),
                )
                .await?;
                return Ok(());
            }
        };

        // Decrypt secrets based on project_id (if present) or code_source type
        let secrets_result = if let Some(ref proj_id) = job.project_id {
            // Project-scoped secrets: the same set for every version.
            //
            // Carrying secrets across versions is much of the point of having
            // projects — publish v2 and it keeps working. A secret that must
            // NOT carry over says so in its access condition: a `WasmHash`
            // leaf admits one build only, judged by the keystore against the
            // hash this worker measured on the bytes it is about to run
            // (`executed_wasm_sha256`, sent with every decrypt). There is no
            // project-plus-version accessor, deliberately: the condition
            // already says it, and `update_access` moves it to the next build
            // without re-encrypting.
            info!("📦 Decrypting project-based secrets for project: {}", proj_id);
            keystore.decrypt_secrets_by_project(proj_id, &secrets_ref.profile, &secrets_ref.account_id, caller, Some(data_id), Some(executed_wasm_sha256.as_str())).await
        } else {
            // Non-project execution: use code_source type for secrets
            match code_source {
                CodeSource::GitHub { repo, commit, .. } => {
                    info!("📦 Decrypting repo-based secrets for GitHub source");

                    // Resolve branch from commit via coordinator API (with caching)
                    let branch = match api_client.resolve_branch(repo, commit).await {
                        Ok(b) => {
                            if let Some(ref branch_name) = b {
                                info!("✅ Coordinator resolved '{}' → branch '{}'", commit, branch_name);
                            } else {
                                info!("⚠️  Coordinator: commit '{}' not found, using wildcard (branch=None)", commit);
                            }
                            b
                        }
                        Err(e) => {
                            warn!("⚠️  Coordinator API failed: {}, using wildcard (branch=None)", e);
                            None
                        }
                    };

                    // Call keystore to decrypt secrets by repo
                    keystore.decrypt_secrets_from_contract(repo, branch.as_deref(), &secrets_ref.profile, &secrets_ref.account_id, caller, Some(data_id), Some(executed_wasm_sha256.as_str())).await
                }
                CodeSource::WasmUrl { hash, .. } => {
                    info!("📦 Decrypting wasm_hash-based secrets for WasmUrl source: {}", hash);

                    // Call keystore to decrypt secrets by wasm_hash
                    keystore.decrypt_secrets_by_wasm_hash(hash, &secrets_ref.profile, &secrets_ref.account_id, caller, Some(data_id), Some(executed_wasm_sha256.as_str())).await
                }
            }
        };

        match secrets_result {
            Ok(secrets) => {
                info!("✅ Secrets decrypted successfully: {} environment variables", secrets.len());
                Some(secrets)
            }
            Err(e) => {
                // Error message already user-friendly from keystore_client
                let error_msg = e.to_string();

                // "There is no such secret" is not fatal — the module may not
                // need one. Asked of the typed error rather than of the prose:
                // a REFUSAL whose wording happened to contain "not found" would
                // otherwise start the job with no credential at all.
                if keystore_client::SecretsNotFound::is_missing(&e) {
                    info!("ℹ️  No secrets configured for this project/source, continuing without secrets");
                    Some(std::collections::HashMap::new())
                } else {
                    error!("❌ Secrets decryption failed: {}", error_msg);
                    let error_category = secrets_failure_category(&error_msg);
                    report_refusal(api_client, near_client, job, request_id, is_https_call, call_id.map(|s| s.as_str()), error_msg, Some(error_category)).await?;
                    return Ok(());
                }
            }
        }
    } else {
        None
    };

    // The author's credential, named by the artefact rather than by the call
    // (`author_secrets` in the manifest), decrypted into the same environment
    // as the caller's. A connector whose manifest asks for it and cannot get
    // it does not run: it was written on the assumption the credential is
    // there, and running it without one is running it against the wrong
    // upstream.
    let user_secrets = match author_secrets_for_run(
        declared_manifest.as_ref(),
        job.project_id.as_deref(),
        keystore_client,
        user_account_id.map(|s| s.as_str()),
        &data_id,
        &executed_wasm_sha256,
        user_secrets,
    )
    .await
    {
        Ok(secrets) => secrets,
        Err((msg, category)) => {
            error!("❌ Author secrets: {}", msg);
            report_refusal(api_client, near_client, job, request_id, is_https_call, call_id.map(|s| s.as_str()), msg, Some(category)).await?;
            return Ok(());
        }
    };

    // Merge environment variables
    let mut env_vars = merge_env_vars(
        user_secrets,
        context,
        resource_limits,
        request_id,
        user_account_id,
        near_payment_yocto,
        attached_usd,
        transaction_hash,
        job.project_id.as_ref(),
        project_uuid.as_ref(),
        // HTTPS-specific parameters
        is_https_call,
        call_id,
        payment_key_owner,
        bound_sender,
        usd_payment,
        // Network configuration
        &config.near_rpc_url,
    );

    // Add WALLET_ID to env vars if wallet is available
    if let Some(ref wid) = wallet_id {
        env_vars.insert("WALLET_ID".to_string(), wid.to_string());
    }

    // Get build target from code source
    let build_target = match code_source {
        CodeSource::GitHub { build_target, .. } => Some(build_target.as_str()),
        CodeSource::WasmUrl { build_target, .. } => Some(build_target.as_str()),
    };

    // Create storage config if keystore is configured AND project_uuid exists
    // Storage requires both: keystore for encryption/decryption AND project for data organization
    let storage_config = match (keystore_client, &config.keystore_auth_token, &project_uuid) {
        (Some(kc), Some(keystore_token), Some(uuid)) => {
            // The instance serving now and the session held on it, fixed for this job.
            let (keystore_url, keystore_tee_session_id) = kc.current_endpoint();
            // Determine account_id for storage (user who triggered execution)
            let storage_account_id = user_account_id
                .cloned()
                .unwrap_or_else(|| "anonymous".to_string());

            info!(
                "📦 Storage enabled: project_uuid={}, wasm_hash={}, account={}",
                uuid, wasm_checksum, storage_account_id
            );

            Some(StorageConfig {
                coordinator_url: config.api_base_url.clone(),
                coordinator_token: config.api_auth_token.clone(),
                keystore_url,
                keystore_token: keystore_token.clone(),
                project_uuid: uuid.clone(),
                wasm_hash: wasm_checksum.clone(),
                account_id: storage_account_id,
                keystore_tee_session_id,
            })
        }
        (None, _, _) | (_, None, _) => {
            debug!("Storage not enabled (keystore not configured)");
            None
        }
        (_, _, None) => {
            debug!("Storage not enabled (no project - WASM running standalone)");
            None
        }
    };

    // Create VRF config if keystore is configured (VRF requires keystore + request_id)
    let vrf_config = match (keystore_client, &config.keystore_auth_token) {
        (Some(kc), Some(keystore_token)) => {
            let (keystore_url, tee_session_id) = kc.current_endpoint();
            let sender_id: String = vrf_domain_identity(
                payment_key_owner,
                user_account_id,
                context.sender_id.as_ref(),
            )
                .unwrap_or_else(|| {
                    panic!("VRF requires sender_id but neither payment_key_owner nor user_account_id nor context.sender_id is set (request_id={})", request_id);
                });
            Some(executor::VrfConfig {
                keystore_url,
                keystore_auth_token: keystore_token.clone(),
                tee_session_id,
                request_id,
                sender_id,
            })
        }
        _ => None,
    };

    // Outbound-domain allowlist (§C3).
    //
    // The manifest comes from the ARTEFACT, never from the coordinator — an
    // allowlist the coordinator supplies is one an operator can widen without
    // anyone seeing it, and the product's claim is precisely that they cannot.
    //
    // ONE source: a custom section inside the wasm. The wasm's hash is recorded
    // on chain and checked before execution, so the section is covered by it —
    // which is the whole claim. It also works for a project published as a
    // `WasmUrl`, which has no repository at all.
    //
    // Nothing else may become a second source — a `manifest.json` read from
    // the repository would make the claim above untrue: `validate_git_ref`
    // accepts `main` and `release/2024-01`, so the ref moves when somebody
    // pushes and the network policy would move with it while nothing on chain
    // changed.
    //
    // A connector whose manifest cannot be read gets an EMPTY allowlist: no
    // network at all.
    let in_namespace = is_connector_call;

    let network_config = {
        let manifest = declared_manifest.clone();

        // What the artefact CLAIMS about its own rate limits. Enforcement is the
        // coordinator's, since a limit has to be counted across calls and a
        // guest sees only its own — but the claim travels inside the wasm, so
        // it is covered by the on-chain hash and can be compared against what
        // is actually enforced. Logged because that comparison is a human one
        // today; nothing checks it automatically.
        if let Some(declared) = manifest.as_ref().and_then(|m| m.declared_limits_summary()) {
            info!(
                "📋 Limits declared by {}: {}",
                job.project_id.as_deref().unwrap_or("<no project>"),
                declared
            );
        }

        let policy = connector_manifest::resolve_network_policy(in_namespace, manifest.as_ref());
        if policy.is_enforced() {
            info!(
                "🔒 Outbound allowlist for {}: {:?}",
                job.project_id.as_deref().unwrap_or("<no project>"),
                policy
            );
        }
        executor::NetworkConfig {
            policy,
            egress_log: Arc::new(Mutex::new(Vec::new())),
        }
    };
    let egress_log = network_config.egress_log.clone();

    // Wallet config, once the manifest is known: the guest may name sub-keys
    // only of the connector this execution IS — decided from the verified
    // manifest and the project it is published under, never from the task.
    let sub_key_connector = connector_manifest::sub_key_connector_id(
        in_namespace,
        job.project_id.as_deref(),
        declared_manifest.as_ref(),
    );
    let wallet_config = wallet_id.map(|wid| {
        debug!("Wallet enabled for execution: wallet_id={}", wid);
        executor::WalletConfig {
            wallet_id: wid.to_string(),
            coordinator_url: config.api_base_url.clone(),
            wallet_auth_token: config.api_auth_token.clone(),
            connector_id: sub_key_connector.clone(),
        }
    });

    // Execute WASM.
    //
    // The compiled cache is keyed by the CONTENT hash, never by `wasm_checksum`.
    // For a GitHub source that checksum is `sha256(repo:commit:target)` — the
    // coordinates, shared by every binary ever built from that commit — so a
    // cache keyed on it can hand the engine native code compiled from other
    // bytes than the ones measured just above. The measurement would then be
    // honest about a wasm that did not run, which is exactly what an attested
    // `executed_wasm_sha256` must never be, and what a secret locked to a build
    // must never admit.
    info!("🚀 Executing WASM...");
    let exec_result = executor
        .execute(
            &wasm_bytes,
            Some(executed_wasm_sha256.as_str()),
            input_data.as_bytes(),
            resource_limits,
            Some(env_vars),
            build_target,
            response_format,
            storage_config,
            vrf_config,
            wallet_config,
            Some(network_config),
        )
        .await;

    // Submit the egress audit (§C3). Read AFTER execution and unconditionally,
    // including for a run that trapped or timed out — a connector that was
    // killed mid-flight is exactly the run whose outbound attempts one wants to
    // see. Failure to record is logged and never fails the execution: the audit
    // is a report, and losing it must not also lose the user's result.
    {
        let records = egress_log
            .lock()
            .map(|log| log.clone())
            .unwrap_or_default();
        // Sent when there is anything to say: outbound attempts, or a
        // manifest whose declarations the coordinator has to know about in
        // order to enforce them.
        let has_declarations = declared_manifest
            .as_ref()
            .and_then(|m| m.limits.as_ref())
            .is_some_and(|l| !l.is_empty());
        if !records.is_empty() || has_declarations {
            if let Err(e) = api_client
                .submit_egress_audit(
                    job.job_id,
                    job.project_id.as_deref(),
                    wasm_checksum,
                    Some(&executed_wasm_sha256),
                    declared_manifest.as_ref(),
                    &records,
                )
                .await
            {
                warn!("Failed to submit egress audit (non-critical): {}", e);
            }
        }
    }

    // Cache the raw bytes only after the guest has exited: a P2 guest has a
    // `/tmp` preopen, and when the cache lives there (the fallback location) a
    // write during the run would race the guest. `get()` verifies every read
    // against the hash recorded here, so a tampered entry is detected, never
    // served.
    if !wasm_bytes.is_empty() {
        if let Some(cache) = wasm_cache {
            if let Ok(mut c) = cache.lock() {
                if let Err(e) = c.put(wasm_checksum, &wasm_bytes) {
                    warn!("Failed to cache WASM after execution: {}", e);
                } else {
                    info!("📦 Cached WASM after execution: {} ({}KB)", wasm_checksum, wasm_bytes.len() / 1024);
                }
            }
        }
    }

    match exec_result {
        Ok(mut execution_result) => {
            // Add compilation time if WASM was compiled in this execution
            execution_result.compile_time_ms = compile_time_ms;

            // Add compilation note - prioritize published_url, then check if freshly compiled or cached
            // published_url can come from local cache (compiled_wasm) or from compile_result (separate executor)
            let effective_published_url = published_url.or(published_url_from_compile_result.clone());

            execution_result.compilation_note = if let Some(url) = &effective_published_url {
                // WASM was published to FastFS/IPFS
                Some(format!("Published to {}", url))
            } else if compile_time_ms.is_some() {
                // Freshly compiled in this task (no published_url)
                Some("Freshly compiled".to_string())
            } else if compile_cost > 0 {
                // Compiled by separate compiler worker (compile_cost indicates compilation happened)
                Some("Freshly compiled".to_string())
            } else if let Some(timestamp) = &created_at {
                // Downloaded from cache
                Some(format!("Cached WASM from {}", timestamp))
            } else {
                None
            };

            info!("🔍 DEBUG: effective_published_url={:?}, compile_time_ms={:?}, compile_cost={}, created_at={:?}, compilation_note={:?}",
                &effective_published_url, &compile_time_ms, compile_cost, &created_at, &execution_result.compilation_note);

            // Check if WASM execution actually succeeded (executor returns Ok even for WASM errors)
            if !execution_result.success {
                let error_msg = execution_result.error.clone().unwrap_or_else(|| "Unknown error".to_string());
                error!("❌ WASM execution failed: {}", error_msg);

                // HTTPS calls: report error to coordinator
                if is_https_call {
                    if let Some(ref call_id_str) = call_id {
                        info!("📤 HTTPS call: reporting WASM error to coordinator (call_id={})", call_id_str);
                        if let Err(https_err) = api_client.complete_https_call(
                            call_id_str,
                            false,
                            None,
                            Some(error_msg.clone()),
                            execution_result.instructions,
                            execution_result.execution_time_ms,
                            Some(job.job_id),
                        ).await {
                            error!("❌ Failed to report HTTPS call error: {}", https_err);
                        }

                        // Report failure to coordinator job tracking
                        if let Err(e) = api_client
                            .complete_job(
                                job.job_id,
                                false,
                                None,
                                Some(error_msg),
                                execution_result.execution_time_ms,
                                execution_result.instructions,
                                None,
                                None,
                                if compile_cost > 0 { Some(compile_cost.to_string()) } else { None },
                                Some(JobStatus::ExecutionFailed),
                                None,
                            )
                            .await
                        {
                            warn!("⚠️ Failed to report execute job failure: {}", e);
                        }

                        return Ok(());
                    }
                }

                // NEAR contract calls: continue to normal flow (will be handled below)
                // The result (including success=false) will be submitted to NEAR contract
            }

            // Log execution result (only log success for successful executions)
            if execution_result.success {
                if let Some(ct) = compile_time_ms {
                    info!(
                        "✅ Execution successful: compile={}ms execute={}ms instructions={}{}",
                        ct, execution_result.execution_time_ms, execution_result.instructions,
                        effective_published_url.as_ref().map(|u| format!(" published: {}", u)).unwrap_or_default()
                    );
                } else {
                    info!(
                        "✅ Execution successful: time={}ms instructions={} (using cached WASM{})",
                        execution_result.execution_time_ms,
                        execution_result.instructions,
                        created_at.as_ref().map(|t| format!(" from {}", t)).unwrap_or_default()
                    );
                }
            }

            // HTTPS calls go to coordinator, not NEAR contract
            if is_https_call {
                let call_id_str = call_id.ok_or_else(|| anyhow::anyhow!("HTTPS call missing call_id"))?;
                info!("📤 HTTPS call: submitting result to coordinator (call_id={})", call_id_str);

                // Convert ExecutionOutput to serde_json::Value
                let output_json = execution_result.output.as_ref().map(|out| match out {
                    api_client::ExecutionOutput::Bytes(bytes) => {
                        use base64::{engine::general_purpose::STANDARD, Engine};
                        serde_json::Value::String(STANDARD.encode(bytes))
                    }
                    api_client::ExecutionOutput::Text(text) => {
                        serde_json::Value::String(text.clone())
                    }
                    api_client::ExecutionOutput::Json(json) => json.clone(),
                });

                match api_client.complete_https_call(
                    call_id_str,
                    true,
                    output_json.clone(),
                    None,
                    execution_result.instructions,
                    execution_result.execution_time_ms,
                    Some(job.job_id),
                ).await {
                    Ok(()) => {
                        info!("✅ HTTPS call result submitted to coordinator successfully");

                        // Report success to coordinator job tracking
                        if let Err(e) = api_client
                            .complete_job(
                                job.job_id,
                                true,
                                execution_result.output.clone(),
                                None,
                                execution_result.execution_time_ms,
                                execution_result.instructions,
                                None,
                                None, // No cost extraction for HTTPS calls - handled by coordinator
                                if compile_cost > 0 { Some(compile_cost.to_string()) } else { None },
                                None,
                                None,
                            )
                            .await
                        {
                            warn!("⚠️ Failed to report execute job completion: {}", e);
                        }

                        // Generate and store attestation for HTTPS call
                        if use_tee_registration {
                            use sha2::{Sha256, Digest};

                            // Compute hashes
                            let mut input_hasher = Sha256::new();
                            input_hasher.update(input_data.as_bytes());
                            let input_hash = hex::encode(input_hasher.finalize());

                            let output_hash = if let Some(ref json) = output_json {
                                let mut output_hasher = Sha256::new();
                                output_hasher.update(json.to_string().as_bytes());
                                hex::encode(output_hasher.finalize())
                            } else {
                                // Empty output
                                let mut output_hasher = Sha256::new();
                                output_hasher.update(b"");
                                hex::encode(output_hasher.finalize())
                            };

                            // Format secrets_ref for attestation (None if empty fields)
                            let secrets_ref_str = secrets_ref.and_then(|sr| sr.as_attestation_ref());

                            // Generate TDX quote
                            match tdx_client.generate_task_attestation(
                                "execute",
                                job.job_id,
                                code_source.repo(),
                                code_source.commit(),
                                code_source.build_target(),
                                Some(wasm_checksum),
                                Some(&input_hash),
                                &output_hash,
                                None, // No block_height for HTTPS calls
                                payment_key_owner.map(|s| s.as_str()), // caller = payment key owner
                                job.project_id.as_deref(),
                                secrets_ref_str.as_deref(),
                                job.created_at,
                                usd_payment.map(|s| s.as_str()),
                            ).await {
                                Ok(tdx_quote) => {
                                    // Send attestation to coordinator with HTTPS fields
                                    let attestation_request = api_client::StoreAttestationRequest {
                                        task_id: job.job_id,
                                        task_type: api_client::TaskType::Execute,
                                        tdx_quote,
                                        // NEAR context - None for HTTPS calls
                                        request_id: None,
                                        caller_account_id: payment_key_owner.cloned(), // Store caller for verification
                                        transaction_hash: None,
                                        block_height: None,
                                        // HTTPS call context
                                        call_id: Some(call_id_str.to_string()),
                                        payment_key_owner: payment_key_owner.cloned(),
                                        payment_key_nonce,
                                        repo_url: code_source.repo().map(|s| s.to_string()),
                                        commit_hash: code_source.commit().map(|s| s.to_string()),
                                        build_target: code_source.build_target().map(|s| s.to_string()),
                                        wasm_hash: Some(wasm_checksum.clone()),
                                        executed_wasm_sha256: Some(executed_wasm_sha256.clone()),
                                        input_hash: Some(input_hash),
                                        output_hash,
                                        // V1 fields
                                        project_id: job.project_id.clone(),
                                        secrets_ref: secrets_ref_str.clone(),
                                        attached_usd: usd_payment.cloned(),
                                        timestamp: Some(job.created_at),
                                    };

                                    if let Err(e) = api_client.store_attestation(attestation_request).await {
                                        warn!("⚠️ Failed to store HTTPS execution attestation: {}", e);
                                        // Non-critical - continue anyway
                                    } else {
                                        info!("✅ Stored HTTPS execution attestation for call_id={}", call_id_str);
                                    }
                                }
                                Err(e) => {
                                    warn!("⚠️ Failed to generate TDX attestation for HTTPS execution: {}", e);
                                    // Non-critical - continue anyway
                                }
                            }
                        } else {
                            debug!("Skipping attestation generation for HTTPS call (USE_TEE_REGISTRATION=false)");
                        }
                    }
                    Err(e) => {
                        error!("❌ Failed to submit HTTPS call result: {}", e);

                        if let Err(report_err) = api_client
                            .complete_job(
                                job.job_id,
                                false,
                                None,
                                Some(format!("Failed to submit HTTPS call result: {}", e)),
                                execution_result.execution_time_ms,
                                execution_result.instructions,
                                None,
                                None,
                                None,
                                Some(api_client::JobStatus::Failed),
                                None,
                            )
                            .await
                        {
                            warn!("⚠️ Failed to report execute job failure: {}", report_err);
                        }

                        return Err(e);
                    }
                }

                return Ok(());
            }

            // Submit result to NEAR contract (critical path - highest priority)
            info!("📤 Submitting result to NEAR contract...");
            let near_result = near_client.submit_execution_result(request_id, &execution_result).await;

            // Report to coordinator (can wait, non-critical)
            match near_result {
                Ok((tx_hash, outcome)) => {
                    // Check if contract panicked (shouldn't happen for success=true!)
                    if matches!(outcome.status, near_primitives::views::FinalExecutionStatus::Failure(_)) {
                        error!("⚠️  WARNING: Contract panicked unexpectedly on successful execution! tx_hash={}", tx_hash);
                        error!("    This should NOT happen - contract should only panic on failures!");
                    } else {
                        info!("✅ Result submitted to NEAR successfully: tx_hash={}", tx_hash);
                    }

                    // Extract actual cost from contract logs
                    let actual_cost = NearClient::extract_payment_from_logs(&outcome);
                    if actual_cost > 0 {
                        info!("💰 Extracted execution cost from contract: {} yoctoNEAR ({:.6} NEAR)",
                            actual_cost, actual_cost as f64 / 1e24);
                    }

                    // Report to coordinator (async, can fail without breaking flow)
                    // The one completion the earnings ledger reads: an on-chain
                    // execute. The refund travels to the CONTRACT separately via
                    // `resolve_execution`, so leaving it out here does not
                    // misplace a single token — it only makes
                    // `earnings_history` credit the author with money the caller
                    // was given back.
                    if let Err(e) = api_client
                        .complete_job_with_refund(
                            job.job_id,
                            execution_result.success,
                            execution_result.output.clone(),
                            execution_result.error.clone(),
                            execution_result.execution_time_ms,
                            execution_result.instructions,
                            None,
                            if actual_cost > 0 { Some(actual_cost.to_string()) } else { None },
                            if compile_cost > 0 { Some(compile_cost.to_string()) } else { None },
                            None, // No error category for success
                            None, // No compile_result
                            execution_result.refund_usd,
                        )
                        .await
                    {
                        warn!("⚠️ Failed to report execute job completion: {}", e);
                        // Continue anyway - NEAR transaction is already submitted
                    }

                    // Generate and store TDX attestation
                    {
                        // Calculate output hash to match what the contract returns to the user
                        // The contract converts ExecutionOutput to serde_json::Value and returns it
                        use sha2::{Digest, Sha256};
                        let output_hash = if let Some(ref output) = execution_result.output {
                            let mut hasher = Sha256::new();

                            // Hash the JSON value that the contract returns (see contract/src/execution.rs:308-322)
                            let json_value = match output {
                                api_client::ExecutionOutput::Bytes(bytes) => {
                                    // Contract returns base64-encoded string for bytes
                                    use base64::{engine::general_purpose::STANDARD, Engine};
                                    serde_json::Value::String(STANDARD.encode(bytes))
                                },
                                api_client::ExecutionOutput::Text(text) => {
                                    // Contract returns text as JSON string
                                    serde_json::Value::String(text.clone())
                                },
                                api_client::ExecutionOutput::Json(json) => {
                                    // Contract returns JSON value directly
                                    json.clone()
                                },
                            };

                            // Serialize the JSON value to string (this is what gets returned from contract)
                            let json_string = serde_json::to_string(&json_value)
                                .unwrap_or_else(|_| "null".to_string());
                            hasher.update(json_string.as_bytes());

                            hex::encode(hasher.finalize())
                        } else {
                            // No output — hash known sentinel so verifiers can match
                            hex::encode(Sha256::digest("[EXECUTION-FAILED]"))
                        };

                        // Generate and store TDX attestation only if TEE registration is enabled
                        if use_tee_registration {
                            // Calculate input hash
                            let mut input_hasher = Sha256::new();
                            input_hasher.update(input_data.as_bytes());
                            let input_hash = hex::encode(input_hasher.finalize());

                            // Format secrets_ref for attestation (None if empty fields)
                            let secrets_ref_str = secrets_ref.and_then(|sr| sr.as_attestation_ref());

                            match tdx_client.generate_task_attestation(
                                "execute",
                                job.job_id,
                                code_source.repo(),
                                code_source.commit(),
                                code_source.build_target(),
                                Some(wasm_checksum),
                                Some(&input_hash),
                                &output_hash,
                                context.block_height,
                                user_account_id.map(|s| s.as_str()), // caller = NEAR account
                                job.project_id.as_deref(),
                                secrets_ref_str.as_deref(),
                                job.created_at,
                                attached_usd.map(|s| s.as_str()),
                            ).await {
                                Ok(tdx_quote) => {
                                    // Send attestation to coordinator
                                    let attestation_request = api_client::StoreAttestationRequest {
                                        task_id: job.job_id,
                                        task_type: api_client::TaskType::Execute,
                                        tdx_quote,
                                        request_id: Some(request_id as i64),
                                        caller_account_id: user_account_id.cloned(),
                                        transaction_hash: transaction_hash.cloned(),
                                        block_height: context.block_height,
                                        // HTTPS call context - None for NEAR calls
                                        call_id: None,
                                        payment_key_owner: None,
                                        payment_key_nonce: None,
                                        repo_url: code_source.repo().map(|s| s.to_string()),
                                        commit_hash: code_source.commit().map(|s| s.to_string()),
                                        build_target: code_source.build_target().map(|s| s.to_string()),
                                        wasm_hash: Some(wasm_checksum.clone()),
                                        executed_wasm_sha256: Some(executed_wasm_sha256.clone()),
                                        input_hash: Some(input_hash),
                                        output_hash,
                                        // V1 fields
                                        project_id: job.project_id.clone(),
                                        secrets_ref: secrets_ref_str.clone(),
                                        attached_usd: attached_usd.cloned(),
                                        timestamp: Some(job.created_at),
                                    };

                                    if let Err(e) = api_client.store_attestation(attestation_request).await {
                                        warn!("⚠️ Failed to store execution attestation: {}", e);
                                        // Non-critical - continue anyway
                                    } else {
                                        info!("✅ Stored execution attestation for task_id={}", job.job_id);
                                    }
                                }
                                Err(e) => {
                                    warn!("⚠️ Failed to generate TDX attestation for execution: {}", e);
                                    // Non-critical - continue anyway
                                }
                            }
                        } else {
                            debug!("Skipping attestation generation (USE_TEE_REGISTRATION=false)");
                        }
                    }
                }
                Err(e) => {
                    // Use {:#} to show full error chain from anyhow
                    let error_msg = format!("Failed to submit to NEAR: {:#}", e);
                    error!("❌ {}", error_msg);

                    // Report failure to coordinator
                    if let Err(report_err) = api_client
                        .complete_job(
                            job.job_id,
                            false,
                            None,
                            Some(error_msg.clone()),
                            execution_result.execution_time_ms,
                            execution_result.instructions,
                            None,
                            None,
                            None,
                            Some(api_client::JobStatus::Failed), // Infrastructure error - can't reach NEAR
                            None, // No compile_result
                        )
                        .await
                    {
                        warn!("⚠️ Failed to report execute job failure: {}", report_err);
                    }

                    return Err(e);
                }
            }
        }
        Err(e) => {
            let error_msg = format!("Execution failed: {}", e);
            error!("❌ {}", error_msg);

            // Handle HTTPS call errors
            if is_https_call {
                if let Some(call_id_str) = call_id {
                    info!("📤 HTTPS call: reporting error to coordinator (call_id={})", call_id_str);

                    if let Err(https_err) = api_client.complete_https_call(
                        call_id_str,
                        false,
                        None,
                        Some(error_msg.clone()),
                        0,
                        0,
                        Some(job.job_id),
                    ).await {
                        error!("❌ Failed to report HTTPS call error: {}", https_err);
                    }

                    // Report to coordinator job tracking
                    if let Err(report_err) = api_client
                        .complete_job(
                            job.job_id,
                            false,
                            None,
                            Some(error_msg.clone()),
                            0,
                            0,
                            None,
                            None,
                            None,
                            Some(api_client::JobStatus::ExecutionFailed),
                            None,
                        )
                        .await
                    {
                        warn!("⚠️ Failed to report execute job failure: {}", report_err);
                    }

                    return Err(e);
                }
            }

            let result = ExecutionResult {
                success: false,
                output: None,
                error: Some(error_msg.clone()),
                execution_time_ms: 0,
                instructions: 0,
                compile_time_ms,
                compilation_note: None,
                refund_usd: None,
            };

            // Submit error to NEAR contract (critical path) and extract actual cost
            let actual_cost = match near_client.submit_execution_result(request_id, &result).await {
                Ok((tx_hash, outcome)) => {
                    info!("✅ Failure reported to NEAR contract (contract panicked as expected): tx_hash={}", tx_hash);
                    let cost = NearClient::extract_payment_from_logs(&outcome);
                    if cost > 0 {
                        info!("💰 Extracted cost from contract: {} yoctoNEAR ({:.6} NEAR)",
                            cost, cost as f64 / 1e24);
                    }
                    cost
                }
                Err(submit_err) => {
                    error!("❌ Failed to report failure to NEAR: {}", submit_err);
                    0
                }
            };

            // Report to coordinator with actual cost (non-critical)
            if let Err(report_err) = api_client
                .complete_job(
                    job.job_id,
                    false,
                    None,
                    Some(error_msg.clone()),
                    0,
                    0,
                    None,
                    if actual_cost > 0 { Some(actual_cost.to_string()) } else { None },
                    None,
                    Some(api_client::JobStatus::ExecutionFailed), // WASM execution error (panic, trap, timeout)
                    None, // No compile_result
                )
                .await
            {
                warn!("⚠️ Failed to report execute job failure: {}", report_err);
            }

            return Err(e);
        }
    }

    Ok(())
}

// Tests moved to coordinator/src/handlers/github.rs
// Branch resolution is now done via coordinator API with Redis caching

/// Send startup attestation to coordinator using pre-generated TDX quote
///
/// This registers the worker with the coordinator and updates its RTMR3 measurement.
/// Called ONCE on worker startup after successful key registration.
/// If this fails, the worker will stop (no retries).
///
/// # Arguments
/// * `tdx_quote_hex` - Pre-generated TDX quote from registration (hex-encoded)
async fn send_startup_attestation_with_quote(
    api_client: &ApiClient,
    tdx_quote_hex: &str,
    config: &Config,
) -> Result<()> {
    use api_client::{StoreAttestationRequest, TaskType};

    info!("Using TDX quote from registration (length: {} bytes)", tdx_quote_hex.len() / 2);

    // Create attestation request with pre-generated quote
    let request = StoreAttestationRequest {
        task_id: -1,
        task_type: TaskType::Execute, // Use Execute type for startup
        tdx_quote: tdx_quote_hex.to_string(),
        request_id: None,
        caller_account_id: None,
        transaction_hash: None,
        block_height: None,
        // HTTPS call context - None for startup
        call_id: None,
        payment_key_owner: None,
        payment_key_nonce: None,
        repo_url: Some(format!("worker://{}", config.worker_id)),
        commit_hash: Some("startup".to_string()),
        build_target: Some(config.tee_mode.clone()),
        wasm_hash: None,
        executed_wasm_sha256: None,
        input_hash: None, // Not required for startup attestation (task_id = -1)
        output_hash: "worker_startup".to_string(),
        // V1 fields - None for startup
        project_id: None,
        secrets_ref: None,
        attached_usd: None,
        timestamp: None, // Startup uses current time
    };

    // Send to coordinator (fail fast - no retries)
    api_client
        .store_attestation(request)
        .await
        .context("Failed to store startup attestation")?;

    Ok(())
}

// =============================================================================
// Contract System Callbacks Handler
// =============================================================================
//
// This handler processes contract business logic that requires yield/resume:
// - TopUp: decrypt Payment Key → add balance → re-encrypt → resume on contract
// - Delete: delete from coordinator PostgreSQL → resume on contract
// - (Future: Withdraw, UpdateLimits, etc.)
//
// Separated from main worker loop to avoid blocking WASM compile/execute tasks.
// This is NOT directly related to running user code - it's contract system operations.
// =============================================================================

/// Contract System Callbacks Handler - processes TopUp, Delete, and other contract callbacks
///
/// Polls multiple task queues and processes contract system operations that require
/// yield/resume mechanism. These are business logic operations, not WASM execution.
async fn run_contract_system_callbacks_handler(
    api_client: ApiClient,
    keystore_client: Option<KeystoreClient>,
    near_client: NearClient,
    capabilities: Vec<String>,
) {
    use api_client::SystemCallbackTask;

    info!("📋 Contract System Callbacks Handler loop started (unified queue, 60s timeout)");

    loop {
        // Poll unified queue for any system callback task (blocking, 60s timeout like execution queue)
        match api_client.poll_system_callback_task(60, &capabilities).await {
            Ok(Some(task)) => {
                match task {
                    // =================================================================
                    // TopUp Payment Key - requires keystore
                    // =================================================================
                    SystemCallbackTask::TopUp(payload) => {
                        info!(
                            "💰 Processing TopUp task: owner={} nonce={} amount={}",
                            payload.owner, payload.nonce, payload.amount
                        );

                        // TopUp requires keystore
                        if let Some(ref ks_client) = keystore_client {
                            // Convert payload to the format expected by process_topup_task
                            let task_data = api_client::TopUpTaskData {
                                data_id: payload.data_id.clone(),
                                owner: payload.owner.clone(),
                                nonce: payload.nonce,
                                amount: payload.amount.clone(),
                                encrypted_data: payload.encrypted_data.clone(),
                            };

                            match process_topup_task(ks_client, &near_client, &api_client, &task_data).await {
                                Ok(result) => {
                                    info!(
                                        "✅ TopUp completed: owner={} nonce={} tx={} new_balance={}",
                                        payload.owner, payload.nonce, result.tx_hash, result.new_balance
                                    );

                                    // Notify coordinator of payment key metadata (non-critical)
                                    if let Err(e) = api_client
                                        .complete_topup(
                                            &payload.owner,
                                            payload.nonce,
                                            &result.new_balance,
                                            &payload.amount,
                                            &result.key_hash,
                                            &result.project_ids,
                                            result.max_per_call.as_deref(),
                                        )
                                        .await
                                    {
                                        warn!(
                                            "Failed to notify coordinator of payment key update (non-critical): {}",
                                            e
                                        );
                                    }
                                }
                                Err(e) => {
                                    error!(
                                        "❌ TopUp failed: owner={} nonce={} error={}",
                                        payload.owner, payload.nonce, e
                                    );

                                    // Only resume with error if there's a real yield (amount > 0).
                                    // For amount=0 (PaymentKey creation), there's no yield to resume —
                                    // the data_id is a generated hash, not a real yield promise.
                                    if payload.amount != "0" {
                                        if let Err(resume_err) = near_client
                                            .resume_topup_error(&payload.data_id, &format!("TopUp failed: {}", e))
                                            .await
                                        {
                                            error!(
                                                "❌ Failed to resume TopUp with error: {} (original error: {})",
                                                resume_err, e
                                            );
                                        }
                                    } else {
                                        warn!(
                                            "Skipping resume_topup_error for amount=0 (PaymentKey creation) — no yield to resume"
                                        );
                                    }
                                }
                            }
                        } else {
                            error!(
                                "❌ TopUp task received but keystore not configured! owner={} nonce={}",
                                payload.owner, payload.nonce
                            );

                            // Only resume with error if there's a real yield (amount > 0)
                            if payload.amount != "0" {
                                if let Err(e) = near_client
                                    .resume_topup_error(&payload.data_id, "Keystore not configured on this worker")
                                    .await
                                {
                                    error!(
                                        "❌ Failed to resume TopUp with error: {}",
                                        e
                                    );
                                }
                            }
                        }
                    }

                    // =================================================================
                    // Delete Payment Key - doesn't require keystore
                    // =================================================================
                    SystemCallbackTask::DeletePaymentKey(payload) => {
                        info!(
                            "🗑️ Processing DeletePaymentKey task: owner={} nonce={}",
                            payload.owner, payload.nonce
                        );

                        // Step 1: Delete from coordinator PostgreSQL
                        if let Err(e) = api_client
                            .delete_payment_key(&payload.owner, payload.nonce)
                            .await
                        {
                            error!(
                                "❌ Failed to delete payment key from coordinator: owner={} nonce={} error={}",
                                payload.owner, payload.nonce, e
                            );

                            // Resume with error so contract doesn't delete the secret
                            if let Err(e) = near_client
                                .resume_delete_payment_key_error(
                                    &payload.data_id,
                                    &format!("Failed to delete from coordinator: {}", e),
                                )
                                .await
                            {
                                error!(
                                    "❌ Failed to resume delete with error: data_id={} error={}",
                                    payload.data_id, e
                                );
                            }
                            continue;
                        }

                        // Step 2: Call resume_delete_payment_key on contract
                        match near_client.resume_delete_payment_key(&payload.data_id).await {
                            Ok(tx_hash) => {
                                info!(
                                    "✅ DeletePaymentKey completed: owner={} nonce={} tx={}",
                                    payload.owner, payload.nonce, tx_hash
                                );
                            }
                            Err(e) => {
                                error!(
                                    "❌ Failed to resume DeletePaymentKey on contract: owner={} nonce={} error={}",
                                    payload.owner, payload.nonce, e
                                );
                            }
                        }
                    }

                    // =================================================================
                    // Project Storage Cleanup - clear compiled WASM and storage
                    // =================================================================
                    SystemCallbackTask::ProjectStorageCleanup(payload) => {
                        info!(
                            "🧹 Processing ProjectStorageCleanup task: project_id={} uuid={}",
                            payload.project_id, payload.project_uuid
                        );

                        match api_client.clear_project_storage(&payload.project_uuid).await {
                            Ok(()) => {
                                info!(
                                    "✅ ProjectStorageCleanup completed: uuid={}",
                                    payload.project_uuid
                                );
                            }
                            Err(e) => {
                                error!(
                                    "❌ Failed to clear project storage: uuid={} error={}",
                                    payload.project_uuid, e
                                );
                            }
                        }
                    }
                }
            }
            Ok(None) => {
                // Timeout - blocking BRPOP already waited 60s, continue immediately
            }
            Err(e) => {
                error!("❌ Failed to poll system callback task: {}", e);
                // Sleep before retry to avoid tight error loop
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            }
        }
    }
}


/// Refuse an HTTPS job before it is claimed, and SAY SO on the call.
///
/// Refused before the claim, nothing downstream would ever settle the call:
/// without this report it sits `pending` until the stale sweeper bills it as a
/// timeout an hour later. A refusal is an answer, and the caller gets it now.
/// Blockchain jobs have no call to answer on and are left to the contract.
/// Returns whether the call was answered. `true` means the task is DONE — the
/// caller has its refusal — and the iteration should end as handled rather
/// than as a failure, which would park the whole executor for the error
/// back-off. `false` (not an HTTPS job, no call_id, or the report itself
/// failed) leaves the caller to fail the iteration as before.
async fn refuse_https_call(api_client: &ApiClient, is_https_call: bool, call_id: Option<&str>, msg: &str) -> bool {
    if !is_https_call {
        return false;
    }
    match call_id {
        Some(cid) => match api_client
            .complete_https_call(cid, false, None, Some(msg.to_string()), 0, 0, None)
            .await
        {
            Ok(()) => true,
            Err(e) => {
                error!("❌ Failed to report the refused HTTPS call {}: {}", cid, e);
                false
            }
        },
        None => {
            error!("❌ HTTPS job refused with no call_id to report on: {}", msg);
            false
        }
    }
}

/// Refuse every job claimed for one request, after the claim. The request —
/// the contract's or the HTTPS caller's — is answered ONCE, on the first job;
/// every job is then completed with the same reason, so nothing stays claimed.
/// The category is left to the coordinator's default, as it was.
async fn refuse_claimed_jobs(
    api_client: &ApiClient,
    near_client: &NearClient,
    jobs: Vec<JobInfo>,
    request_id: u64,
    is_https_call: bool,
    call_id: Option<&str>,
    error_msg: String,
) -> Result<()> {
    let mut jobs = jobs.into_iter();
    if let Some(first) = jobs.next() {
        report_refusal(api_client, near_client, &first, request_id, is_https_call, call_id, error_msg.clone(), None).await?;
    }
    for job in jobs {
        api_client
            .complete_job(job.job_id, false, None, Some(error_msg.clone()), 0, 0, None, None, None, None, None)
            .await?;
    }
    Ok(())
}

/// The account a run is PROVEN to come from, for the keystore to judge a
/// secret's `AccessCondition` against: on chain the transaction's own signer,
/// over HTTPS the owner of the payment key that paid. Never `context.sender_id`,
/// which is what a call claims about itself.
///
/// Every door fills it — the contract's event carries `sender_id` as a plain
/// account, the event monitor and both HTTPS paths forward it — so its absence
/// is a request none of our doors produced. Such a run decrypts nothing. The
/// only other answer would be to judge the condition as if the secret's owner
/// had asked, and that is a way for an impossible request to read as the owner.
fn proven_sender<'a>(sender: Option<&'a str>, secrets_owner: &str) -> Result<&'a str, String> {
    sender.ok_or_else(|| {
        format!(
            "this run names secrets owned by {secrets_owner} but carries no sender to judge their \
             access condition against, so nothing was decrypted."
        )
    })
}

/// Which job status a failed secrets decryption maps to.
fn secrets_failure_category(error_msg: &str) -> api_client::JobStatus {
    if error_msg.contains("Access") && error_msg.contains("denied") {
        api_client::JobStatus::AccessDenied
    } else if error_msg.contains("Invalid secrets format") {
        api_client::JobStatus::Custom // Invalid format - user configuration issue
    } else {
        api_client::JobStatus::Failed // Generic secret error - infrastructure issue
    }
}

/// Report a run that was refused before the guest ran — its secrets could not
/// be obtained, its binding did not verify, its connector call named no
/// operation, its wasm could not be fetched — so that whoever is waiting hears
/// the reason now rather than at a timeout.
///
/// For an on-chain request the contract hears of the failure and prices it.
/// For an HTTPS call the CALL is settled here, with the reason: the coordinator
/// settles an HTTPS call only through `complete_https_call`, never from the
/// job, and a call nobody settles sits `pending` until the timeout sweeper
/// bills the caller for a run that never started. Then the job is completed
/// with the message and the category (`None` keeps the coordinator's default).
async fn report_refusal(
    api_client: &ApiClient,
    near_client: &NearClient,
    job: &JobInfo,
    request_id: u64,
    is_https_call: bool,
    call_id: Option<&str>,
    error_msg: String,
    error_category: Option<api_client::JobStatus>,
) -> Result<()> {
    let actual_cost = settle_refusal(api_client, near_client, job.job_id, request_id, is_https_call, call_id, &error_msg).await;

    api_client
        .complete_job(
            job.job_id,
            false,
            None,
            Some(error_msg),
            0,
            0,
            None,
            if actual_cost > 0 { Some(actual_cost.to_string()) } else { None },
            None,
            error_category,
            None, // No compile_result
        )
        .await
}

/// Answer the party waiting on a refused run — the contract or the HTTPS
/// caller — and return what the contract charged (0 over HTTPS). Failures to
/// answer are logged, never propagated: the job still has to be completed, and
/// the coordinator's timeout sweeper remains the backstop for the call.
async fn settle_refusal(
    api_client: &ApiClient,
    near_client: &NearClient,
    job_id: i64,
    request_id: u64,
    is_https_call: bool,
    call_id: Option<&str>,
    error_msg: &str,
) -> u128 {
    if is_https_call {
        match call_id {
            Some(cid) => {
                if let Err(e) = api_client
                    .complete_https_call(cid, false, None, Some(error_msg.to_string()), 0, 0, Some(job_id))
                    .await
                {
                    error!("❌ Failed to settle HTTPS call {} with the refusal: {}", cid, e);
                }
            }
            None => error!("❌ HTTPS job {} carries no call_id; its call cannot be settled", job_id),
        }
        return 0;
    }

    let error_result = ExecutionResult {
        success: false,
        output: None,
        error: Some(error_msg.to_string()),
        execution_time_ms: 0,
        instructions: 0,
        compile_time_ms: None,
        compilation_note: None,
        refund_usd: None,
    };
    match near_client.submit_execution_result(request_id, &error_result).await {
        Ok((tx_hash, outcome)) => {
            info!("✅ Failure reported to NEAR contract (contract panicked as expected): tx_hash={}", tx_hash);
            let cost = NearClient::extract_payment_from_logs(&outcome);
            if cost > 0 {
                info!("💰 Extracted cost from contract: {} yoctoNEAR ({:.6} NEAR)", cost, cost as f64 / 1e24);
            }
            cost
        }
        Err(e) => {
            error!("❌ Failed to report failure to NEAR: {}", e);
            0
        }
    }
}

/// The environment a run gets: the caller's secrets plus, when the manifest
/// names them, the author's — decrypted under the accessor of the project
/// being run, for the owner and profile the manifest names, with the access
/// condition evaluated against the caller. A name on both sides refuses the
/// run; so does a manifest that asks for secrets nobody stored.
///
/// The error carries the job status it is reported under: what the manifest
/// or the stored secrets got wrong is `Custom` (a configuration the author
/// can fix), a keystore that could not answer is whatever
/// `secrets_failure_category` makes of it, as for the caller's own secrets.
async fn author_secrets_for_run(
    manifest: Option<&connector_manifest::ProjectManifest>,
    project_id: Option<&str>,
    keystore_client: Option<&KeystoreClient>,
    caller: Option<&str>,
    data_id: &str,
    executed_wasm_sha256: &str,
    agent_secrets: Option<std::collections::HashMap<String, String>>,
) -> std::result::Result<Option<std::collections::HashMap<String, String>>, (String, api_client::JobStatus)> {
    use api_client::JobStatus;
    if manifest.and_then(|m| m.author_secrets.as_ref()).is_none() {
        return Ok(agent_secrets);
    }
    let Some(project_id) = project_id else {
        return Err((
            "the manifest names author_secrets, but this run has no project to store them under".to_string(),
            JobStatus::Custom,
        ));
    };
    let Some(author) = connector_manifest::author_secrets_ref(project_id, manifest).map_err(|m| (m, JobStatus::Custom))? else {
        return Ok(agent_secrets);
    };
    // The manifest is author-written bytes: a reference the contract could
    // never hold is refused here, naming the rule, before it is echoed into
    // any message or sent to the keystore — the same door a caller's
    // `secrets_ref` goes through.
    if let Err(shape) = shared_tee_helpers::secrets_ref::well_formed_secrets_ref(&author.profile, &author.owner) {
        return Err((
            format!(
                "the manifest's author_secrets names no row the contract could hold: {}",
                shape.sentence("author_secrets.profile", "author_secrets.owner")
            ),
            JobStatus::Custom,
        ));
    }
    let Some(keystore) = keystore_client else {
        return Err((
            "the manifest names author_secrets, but this worker has no keystore to decrypt them with".to_string(),
            JobStatus::Failed,
        ));
    };

    info!(
        "🔐 Decrypting the author's secrets: project={}, owner={}, profile={}",
        project_id, author.owner, author.profile
    );
    let caller = proven_sender(caller, &author.owner).map_err(|m| (m, JobStatus::AccessDenied))?;
    let decrypted = keystore
        .decrypt_secrets_by_project(project_id, &author.profile, &author.owner, caller, Some(data_id), Some(executed_wasm_sha256))
        .await
        .map_err(|e| {
            if keystore_client::SecretsNotFound::is_missing(&e) {
                (
                    format!(
                        "the manifest names author secrets owner={} profile={} for project {}, but none are stored — \
                         store them with accessor Project({}) or drop author_secrets from the manifest",
                        author.owner, author.profile, project_id, project_id
                    ),
                    JobStatus::Custom,
                )
            } else {
                let msg = format!("the author's secrets could not be decrypted: {}", e);
                let category = secrets_failure_category(&msg);
                (msg, category)
            }
        })?;
    info!("✅ Author secrets decrypted: {} environment variables", decrypted.len());

    connector_manifest::merge_secret_maps(decrypted, agent_secrets.unwrap_or_default())
        .map(Some)
        .map_err(|m| (m, JobStatus::Custom))
}

/// May this job name its own code? (§C3)
///
/// A supplied `code_source` names a repository and a ref that nothing on chain
/// has committed to. For a connector that would hollow out the domain allowlist
/// — the manifest is read from exactly that repo at exactly that ref, so a
/// payload-chosen source is a payload-chosen allowlist, the one thing §C3 says
/// the allowlist must never be.
///
/// The test is the PATH, not the project. On the blockchain path this field is
/// filled by the contract itself: `request_execution` with a `Project` source
/// resolves the project's active version and puts the result in the event, so
/// `code_source` and `project_id` arrive together and both come from the chain.
/// A check that refused that pairing would refuse every legitimate on-chain
/// execution of a project — and the earlier version of this one did exactly that
/// for any connector published under the curated namespace, which is the shape
/// we would move to.
///
/// On the HTTPS path the code is whatever the CONTRACT names for the project, and
/// the worker resolves it itself. The one HTTPS task that legitimately carries a
/// `code_source` is the coordinator's compile-queue task for an uncached version
/// — a copy of the chain's answer so the compile worker can download without
/// resolving — and it is accepted only because the resolution here finds it
/// identical. The execute task the coordinator re-queues after that download
/// carries none (`requeued_code_source` in the coordinator). A job naming
/// anything else is refused, and the refusal is reported back on the call so it
/// fails now rather than waiting for the stale sweeper.
///
/// A function rather than an inline condition so the test can exercise the rule
/// that actually runs. Written inline, the rule could be deleted from the job
/// path and a test asserting the same expression would keep passing.
fn refuses_own_code_source(
    is_https_call: bool,
    provided: Option<&api_client::CodeSource>,
    chain: &api_client::CodeSource,
) -> bool {
    match provided {
        Some(named) if is_https_call => named != chain,
        _ => false,
    }
}

/// The curated connector namespace for the network this worker serves (§14.1).
///
/// Membership is decided by comparing the owner account of a `project_id`
/// against this, so it is a structural fact rather than something a project can
/// claim about itself. The network is read off the configured RPC URL, the same
/// way `merge_env_vars` derives `NEAR_NETWORK_ID`, so the two can never
/// disagree about which chain this worker is on.
fn connectors_namespace(near_rpc_url: &str) -> &'static str {
    if near_rpc_url.contains("mainnet") {
        "connectors.outlayer.near"
    } else {
        "connectors.outlayer.testnet"
    }
}

/// TopUp result containing tx_hash, new balance, and key metadata for coordinator
struct TopUpResult {
    tx_hash: String,
    new_balance: String,
    key_hash: String,
    project_ids: Vec<String>,
    max_per_call: Option<String>,
}

/// The public name of a payment key, as `payment_keys.key_hash` holds it.
///
/// A key's name is the HASH of its key string. Publishing the string itself
/// would hand out an oracle for guessing it, so the hash is what the row carries
/// and what every later rule compares against.
///
/// `None` when the blob carries no usable `key`. That used to mean an AGENT key
/// — a key with no string, named after the wallet's account instead — and the
/// account was substituted here. Those keys are not issued any more: a wallet
/// pays with a key it owns and presents, like every other caller. So a blob
/// without a key is not a second kind of key, it is a blob this worker cannot
/// name, and the caller refuses it rather than inventing a name for a row that
/// decides who may spend what.
///
/// A blob may not claim the answer either way: it is written by the key's owner,
/// and the only thing it can do here is omit a field.
fn public_key_name(blob: &serde_json::Value) -> Option<String> {
    use sha2::{Digest, Sha256};
    blob.get("key")
        .and_then(|v| v.as_str())
        .map(|key| hex::encode(Sha256::digest(key.as_bytes())))
}

/// Process a single TopUp task
///
/// 1. Decrypt current Payment Key data via keystore
/// 2. Parse JSON and update initial_balance
/// 3. Re-encrypt via keystore
/// 4. Call resume_topup on contract
///
/// Returns: tx_hash and new_balance for coordinator notification
///
/// Special case: amount=0 means PaymentKey was just created (store_secrets).
/// In this case we only decrypt to get key_hash and init the key in coordinator.
/// No re-encrypt or resume_topup (there's no yield promise to resume).
async fn process_topup_task(
    keystore_client: &KeystoreClient,
    near_client: &NearClient,
    api_client: &ApiClient,
    task: &api_client::TopUpTaskData,
) -> Result<TopUpResult> {
    // 1. Decrypt current Payment Key data
    // Seed format: "system:payment_key:{owner}:{nonce}"
    let seed = format!("system:payment_key:{}:{}", task.owner, task.nonce);

    // Which master this blob was written under, read from the CHAIN.
    //
    // A key created by a wallet with a per-customer vault lives under that
    // vault's master; every other key lives under the default. Taking the
    // answer from the task instead would let whoever queued it choose the
    // key-space — and the whole point of a vault is that we cannot.
    //
    // A failure here is NOT treated as "no vault": guessing the default for a
    // vault-bound key would fail to decrypt anyway, but reporting it as a
    // missing RPC rather than as corrupt data is the difference between an
    // operator retrying and an operator debugging the wrong thing.
    let vault_id = near_client
        .fetch_payment_key_vault(&task.owner, task.nonce)
        .await
        .context("Failed to read the payment key's vault binding from the contract")?;

    let decrypted_bytes = keystore_client
        .decrypt_raw(&seed, &task.encrypted_data, vault_id.as_deref())
        .await
        .context("Failed to decrypt Payment Key data")?;

    let decrypted_str = String::from_utf8(decrypted_bytes)
        .context("Payment Key data is not valid UTF-8")?;

    // 2. Parse JSON and extract fields
    // Payment Key format: {"key":"base64_key","initial_balance":"123","project_ids":[],"max_per_call":"1000"}
    let mut payment_key_data: serde_json::Value = serde_json::from_str(&decrypted_str)
        .context("Failed to parse Payment Key JSON")?;

    // Refused, not renamed. A blob with no `key` was an agent key, and those are
    // gone; naming the row after the account would resurrect the second kind of
    // key inside a top-up, where nobody would look for it.
    let key_hash = public_key_name(&payment_key_data).with_context(|| {
        format!(
            "payment key {}:{} has no `key` in its blob — keyless (agent) payment keys are no \
             longer issued, and this worker will not name a key row after an account",
            task.owner, task.nonce
        )
    })?;

    // Extract project_ids
    let project_ids: Vec<String> = payment_key_data
        .get("project_ids")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    // Extract max_per_call
    let max_per_call = payment_key_data
        .get("max_per_call")
        .and_then(|v| v.as_str())
        .map(String::from);

    let current_balance = payment_key_data
        .get("initial_balance")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing initial_balance field"))?;

    let current_balance_u128: u128 = current_balance
        .parse()
        .context("Failed to parse initial_balance as u128")?;

    let topup_amount: u128 = task.amount.parse()
        .context("Failed to parse topup amount as u128")?;

    // Special case: amount=0 means PaymentKey creation (store_secrets emitted this)
    // Only initialize key in coordinator, no re-encrypt or resume
    if topup_amount == 0 {
        info!(
            "🔑 PaymentKey creation (amount=0): owner={} nonce={}, initializing with key_hash={}...",
            task.owner, task.nonce, &key_hash[..8]
        );

        // Call POST /payment-keys/init with key_hash
        api_client.init_payment_key(
            &task.owner,
            task.nonce,
            &key_hash,
            &project_ids,
            max_per_call.as_deref(),
        ).await.context("Failed to init payment key in coordinator")?;

        // Return dummy result (no tx_hash since no resume)
        return Ok(TopUpResult {
            tx_hash: "init_only".to_string(),
            new_balance: "0".to_string(),
            key_hash: key_hash.clone(),
            project_ids,
            max_per_call,
        });
    }

    // Normal TopUp flow.
    //
    // A top-up is a top-up: the whole payment becomes spendable balance, on an
    // agent's key exactly as on any other. The payment key's job is to pay for
    // execution, and a transfer to it must not quietly turn the customer's
    // money into subscription allowance — an allowance burns at `expires_at`
    // and money does not.
    //
    // An allowance is GRANTED (the trial, a purchase, an admin gift) and is
    // accounted for by the coordinator; nothing here converts one into the
    // other. That is also why this function asks for no price at all: buying an
    // allowance is a separate, explicit act, and a payment path that could
    // convert would eventually convert by accident — a whole payment turned
    // into something that expires, from a customer who only meant to fund their
    // key.
    let new_balance = current_balance_u128 + topup_amount;

    info!(
        "💰 Updating balance: {} + {} = {} (key_hash={}...)",
        current_balance_u128, topup_amount, new_balance, &key_hash[..8]
    );

    payment_key_data["initial_balance"] = serde_json::json!(new_balance.to_string());

    // 3. Re-encrypt via keystore
    let updated_json = serde_json::to_string(&payment_key_data)
        .context("Failed to serialize updated Payment Key")?;

    let new_encrypted_data = keystore_client
        .encrypt(&seed, updated_json.as_bytes(), vault_id.as_deref())
        .await
        .context("Failed to encrypt updated Payment Key data")?;

    // 4. Call resume_topup on contract
    let tx_hash = near_client
        .resume_topup(&task.data_id, &new_encrypted_data)
        .await
        .context("Failed to resume TopUp on contract")?;

    Ok(TopUpResult {
        tx_hash,
        new_balance: new_balance.to_string(),
        key_hash,
        project_ids,
        max_per_call,
    })
}


#[cfg(test)]
mod payment_key_name_tests {
    use super::public_key_name;
    use serde_json::json;

    const OWNER: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";

    /// A key is named by the hash of its string, and a blob without one has no
    /// name at all — the caller refuses it rather than naming the row after an
    /// account, which is what the removed agent keys did.
    #[test]
    fn a_key_is_named_by_its_hash_and_a_keyless_blob_has_no_name() {
        assert_eq!(
            public_key_name(&json!({"initial_balance": "0"})),
            None,
            "no key means no name: keyless keys are not issued and must not be invented"
        );

        let ordinary = public_key_name(&json!({"key": "aa", "initial_balance": "0"}))
            .expect("a blob with a key has a name");
        assert_ne!(
            ordinary, OWNER,
            "a key that HAS a key string is named by its hash, never by an account"
        );
        assert_eq!(
            ordinary,
            hex::encode(<sha2::Sha256 as sha2::Digest>::digest(b"aa")),
            "and an ordinary key's name is the hash of its key, unchanged"
        );
    }

    /// An old blob predates agent keys, has a `key`, and must keep reading as
    /// the ordinary key it is. Migration is silent by construction — there is no
    /// field to add and nothing rewrites anything.
    #[test]
    fn an_old_blob_still_reads_as_an_ordinary_key() {
        let old = json!({
            "key": "deadbeef",
            "initial_balance": "1000",
            "project_ids": [],
            "max_per_call": "0"
        });
        assert!(public_key_name(&old).is_some());
    }

    /// A blob cannot CLAIM a name, only carry a key or fail to. Written by the
    /// key's owner, so anything it asserts about itself is unverified input.
    #[test]
    fn a_blob_cannot_declare_its_own_name() {
        let forged = json!({
            "key": "aa",
            "target": OWNER,
            "is_agent": true,
            "allowance_usd": 999_999_999u64,
        });
        assert_eq!(
            public_key_name(&forged),
            public_key_name(&json!({"key": "aa"})),
            "the extra fields change nothing — only `key` is read"
        );
    }

    /// A non-string `key` is not a key, and a blob this malformed did not come
    /// from us. It gets no name, so the caller refuses it — the same answer as
    /// any blob without a key, and the one that cannot be mistaken for a row.
    #[test]
    fn a_key_that_is_not_a_string_has_no_name() {
        assert_eq!(public_key_name(&json!({"key": 42})), None);
    }
}

#[cfg(test)]
mod verified_sender_tests {
    use super::*;
    use crate::api_client::{ExecutionContext, ResourceLimits};

    fn empty_context() -> ExecutionContext {
        serde_json::from_str("{}").expect("ExecutionContext must deserialize from an empty object")
    }

    fn limits() -> ResourceLimits {
        ResourceLimits {
            max_instructions: 1_000_000,
            max_memory_mb: 64,
            max_execution_seconds: 30,
        }
    }

    /// Every name this file injects must be DECLARED a system name.
    ///
    /// Reads the source rather than the list, because the source is the ground
    /// truth: a variable reaches a guest by being inserted, and a name that is
    /// inserted but undeclared is one nothing protects — the keystore will not
    /// refuse it as a secret key, and `merge_env_vars` will not strip it.
    /// Adding an insert and forgetting the list is the exact mistake that let
    /// `OUTLAYER_PROJECT_OWNER` and `WALLET_ID` be forgeable.
    #[test]
    fn every_injected_variable_is_declared_a_system_name() {
        let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs"))
            .expect("the worker can read its own source");
        // Production code only. The tests below quote `env_vars.insert(` as a
        // string, and scanning them would make this test read its own scanner.
        let production = src
            .split_once("#[cfg(test)]")
            .map(|(before, _)| before)
            .expect("the test modules sit at the end of this file");
        // The guest's environment is not assembled in one file. `main.rs` fills
        // the map, and the P2 executor writes straight onto the WASI builder
        // afterwards — which is how `NEAR_RPC_PROXY_AVAILABLE` came to be
        // injected, undeclared and unreserved, until a live `env` probe on
        // 2026-08-21 reported it as a name it did not recognise. Reading only
        // this file is what let that happen.
        let p2 = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/executor/wasi_p2.rs"
        ))
        .expect("the P2 executor writes to the same environment and must be read too");
        let mut injected = injected_env_names(production);
        for name in injected_env_names(&p2) {
            if !injected.contains(&name) {
                injected.push(name);
            }
        }

        // If a refactor renames the map, the scan would find nothing and this
        // test would pass while checking nothing at all.
        assert!(
            injected.len() >= 20,
            "found only {} `env_vars.insert(..)` names — the scan stopped matching the code it \
             is supposed to read, so this guard is no longer guarding anything",
            injected.len()
        );

        let undeclared: Vec<&String> = injected
            .iter()
            .filter(|name| !SYSTEM_ENV_VARS.contains(&name.as_str()))
            .collect();
        assert!(
            undeclared.is_empty(),
            "these variables are injected into the guest but missing from SYSTEM_ENV_VARS: \
             {undeclared:?} — add them there (the keystore test will then ask you to reserve them)"
        );
    }

    /// Names passed to `env_vars.insert(..)` anywhere in the given source.
    ///
    /// Deliberately not line-based: two of the real call sites put the name on
    /// the line after the open paren, and a line-based scan silently missed
    /// both.
    fn injected_env_names(src: &str) -> Vec<String> {
        let mut names = Vec::new();
        for marker in ["env_vars.insert(", "wasi_builder.env("] {
            let mut rest = src;
            while let Some(at) = rest.find(marker) {
                rest = &rest[at + marker.len()..];
                // The name must be a LITERAL right here. `wasi_builder.env(&key,
                // &value)` — the loop that writes the caller's own secrets —
                // passes a variable, and reaching past it for the next quote in
                // the file would attribute somebody else's string to this call.
                let literal = rest.trim_start();
                let Some(after) = literal.strip_prefix('"') else { continue };
                let Some(close) = after.find('"') else { break };
                let name = &after[..close];
                if !name.is_empty() && !names.iter().any(|n: &String| n == name) {
                    names.push(name.to_string());
                }
            }
        }
        names
    }

    /// No secret may occupy ANY system variable, on EITHER path.
    ///
    /// The previous version of this check tested one name (`NEAR_SENDER_ID`)
    /// on one path (HTTPS) and rested on "secrets are merged first, system
    /// values written over them". That order only protects names that are
    /// written every time, and most are conditional — the on-chain branch
    /// writes `NEAR_PREDECESSOR_ID` and its neighbours only when the context
    /// carries them, and the project names only when a project id exists.
    /// With an EMPTY context and no project — the case where the fewest
    /// system writes happen — a secret of each name must still not survive.
    #[test]
    fn no_secret_can_occupy_a_system_variable_on_either_path() {
        for https in [true, false] {
            let secrets: std::collections::HashMap<String, String> = SYSTEM_ENV_VARS
                .iter()
                .map(|k| ((*k).to_string(), format!("forged-{k}")))
                .collect();

            let env = merge_env_vars(
                Some(secrets),
                &empty_context(),
                &limits(),
                1,
                None,
                None,
                None,
                None,
                None, // no project id — the project names are never written
                None,
                https,
                None,
                None,
                None,
                None,
                "https://rpc.testnet.fastnear.com",
            );

            for key in SYSTEM_ENV_VARS {
                let value = env.get(*key);
                assert!(
                    !value.is_some_and(|v| v.starts_with("forged-")),
                    "https={https}: the caller's own secret survived as {key}={value:?} — \
                     a guest would read it as a fact about its run"
                );
            }

            // Absent must stay absent: writing a blank instead of stripping
            // would tell a guest doing `.ok()?` that there IS a project.
            assert!(
                !env.contains_key("OUTLAYER_PROJECT_OWNER"),
                "https={https}: no project id was given, so the name must be ABSENT, not blank"
            );
        }
    }

    /// §C2: on the HTTPS path the guest's idea of "who is calling" comes from
    /// the payment key's `owner`, and from nothing else.
    ///
    /// This is the whole of verified sender. near-email reads
    /// `env::signer_account_id()`, which is `NEAR_SENDER_ID`; if this mapping
    /// ever moved to some other field, every connector would start acting on
    /// behalf of the wrong account with no error anywhere.
    #[test]
    fn https_calls_take_the_sender_from_the_payment_key_owner() {
        let owner = "alice.near".to_string();
        let env = merge_env_vars(
            None,
            &empty_context(),
            &limits(),
            1,
            None,
            None,
            None,
            None,
            None,
            None,
            true, // is_https_call
            Some(&"call-id".to_string()),
            Some(&owner),
            None, // no bound sender
            None,
            "https://rpc.mainnet.fastnear.com",
        );

        assert_eq!(env.get("NEAR_SENDER_ID"), Some(&owner));
        assert_eq!(env.get("NEAR_USER_ACCOUNT_ID"), Some(&owner));
        assert_eq!(
            env.get("OUTLAYER_EXECUTION_TYPE").map(String::as_str),
            Some("HTTPS")
        );
    }

    /// The opt-in itself: with no bound identity asked for, NOTHING is claimed
    /// and the verification never runs.
    ///
    /// This is the default every existing agent lands on, and it has to be
    /// bit-for-bit what it was before bindings existed — the coordinator sets
    /// the context sender to the caller's own name unless the call asked
    /// otherwise, and then there is nothing here to check.
    #[test]
    fn without_a_claim_there_is_nothing_to_verify() {
        // HTTPS: sender is the paying key's owner, as always.
        assert_eq!(
            identity_claim(true, Some("alice.near"), Some("alice.near"), None),
            None
        );
        // On-chain: sender is the account that signed.
        assert_eq!(
            identity_claim(false, Some("alice.near"), None, Some("alice.near")),
            None
        );
        // Nothing to compare against is also nothing to claim.
        assert_eq!(identity_claim(true, Some("agent.tla"), None, None), None);
        assert_eq!(identity_claim(false, None, None, Some("alice.near")), None);
    }

    /// Both doors settle the SAME claim, and each names the party that paid as
    /// the one who must prove it.
    ///
    /// The two differ in one bit only. On HTTPS the prover must be an implicit
    /// account — the shape an agent key's owner has — and that is asserted
    /// rather than assumed, so a future credential path attaching a wallet to a
    /// NAMED owner refuses instead of verifying the wrong account's extension
    /// set. On-chain the caller is established by a signature and may perfectly
    /// well be named (a user's own account, or a contract relaying), so the
    /// same demand there would refuse correct calls.
    #[test]
    fn both_doors_claim_alike_but_the_prover_differs() {
        let https = identity_claim(true, Some("agent.tla"), Some("aaaa"), Some("ignored"));
        assert_eq!(https, Some(("agent.tla", "aaaa", true)));

        let onchain = identity_claim(false, Some("agent.tla"), Some("ignored"), Some("bob.near"));
        assert_eq!(
            onchain,
            Some(("agent.tla", "bob.near", false)),
            "on-chain the prover is the signer, and it may be a NAMED account"
        );
    }

    /// Agent Connect: a verified bound asset account renames WHO THE GUEST
    /// ACTS AS, and nothing else.
    ///
    /// `NEAR_SENDER_ID` becomes the asset account — near-email derives its
    /// mailbox from it, so this line is what makes a bound agent write from
    /// `agent.tla@near.email`. `NEAR_USER_ACCOUNT_ID` must STAY the payment
    /// key owner: it is the billing identity, and if it followed the binding,
    /// usage attribution would move to an account that never paid.
    #[test]
    fn a_bound_sender_renames_the_guest_but_not_the_payer() {
        let owner = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
        let bound = "agent.tla".to_string();
        let env = merge_env_vars(
            None,
            &empty_context(),
            &limits(),
            1,
            None,
            None,
            None,
            None,
            None,
            None,
            true, // is_https_call
            Some(&"call-id".to_string()),
            Some(&owner),
            Some(&bound),
            None,
            "https://rpc.mainnet.fastnear.com",
        );

        assert_eq!(env.get("NEAR_SENDER_ID"), Some(&bound));
        assert_eq!(
            env.get("NEAR_USER_ACCOUNT_ID"),
            Some(&owner),
            "billing identity must not follow the binding"
        );
    }

    /// One flag, one module, one random stream — whichever door it came through.
    ///
    /// The defect this pins was invisible by construction: both doors agreed
    /// while `context.sender_id` still meant "who sent the transaction", and
    /// they silently stopped agreeing the moment a binding could rewrite it.
    /// Nothing would have reported it — the VRF still works, it just answers a
    /// different question on each door.
    #[test]
    fn the_vrf_domain_follows_the_payer_on_both_doors() {
        let payer = "alice.near".to_string();
        let bound = "agent.tla".to_string();
        let key_owner = "aaaa".to_string();

        // On chain WITH a binding: `context.sender_id` carries the bound
        // account, and the domain must NOT follow it.
        assert_eq!(
            super::vrf_domain_identity(None, Some(&payer), Some(&bound)),
            Some(payer.clone()),
            "the bound account is the guest's name, not the caller's"
        );

        // Over HTTPS the payment key's owner answers first, as it always did.
        assert_eq!(
            super::vrf_domain_identity(Some(&key_owner), None, Some(&bound)),
            Some(key_owner.clone())
        );

        // No binding: all three are the same account, so every live request
        // keeps the domain it has today.
        assert_eq!(
            super::vrf_domain_identity(None, Some(&payer), Some(&payer)),
            Some(payer.clone())
        );

        // The last-resort fallback still exists — a request with neither
        // identity is the panic case, not a silent empty domain.
        assert_eq!(
            super::vrf_domain_identity(None, None, Some(&payer)),
            Some(payer)
        );
        assert_eq!(super::vrf_domain_identity(None, None, None), None);
    }

    /// A caller's own secrets must never be able to name the sender.
    ///
    /// Secrets are merged in FIRST and the system variables are written over
    /// them. If that order inverted, a project owner could set
    /// `NEAR_SENDER_ID` in their project secrets and have every connector call
    /// act as whoever they named. (The keystore also rejects reserved keys on
    /// the way in; this is the second of the two locks.)
    #[test]
    fn a_secret_cannot_impersonate_the_sender() {
        let mut secrets = std::collections::HashMap::new();
        secrets.insert("NEAR_SENDER_ID".to_string(), "victim.near".to_string());
        secrets.insert("NEAR_USER_ACCOUNT_ID".to_string(), "victim.near".to_string());

        let owner = "alice.near".to_string();
        let env = merge_env_vars(
            Some(secrets),
            &empty_context(),
            &limits(),
            1,
            None,
            None,
            None,
            None,
            None,
            None,
            true,
            Some(&"call-id".to_string()),
            Some(&owner),
            None, // no bound sender
            None,
            "https://rpc.mainnet.fastnear.com",
        );

        assert_eq!(
            env.get("NEAR_SENDER_ID"),
            Some(&owner),
            "a project secret must not be able to name the verified sender"
        );
        assert_eq!(env.get("NEAR_USER_ACCOUNT_ID"), Some(&owner));
    }

    /// Which jobs may name their own code, and which may not.
    ///
    /// The distinction is the PATH. On the blockchain path the contract fills
    /// `code_source` itself — `request_execution` with a `Project` source
    /// resolves the active version into the event — so a job arriving with both
    /// a code source and a project id is the ordinary, signed case. An earlier
    /// version of this rule refused exactly that pairing for connectors in the
    /// curated namespace, which would have broken every on-chain call to one
    /// the day we published a connector there.
    ///
    /// On the HTTPS path the coordinator builds the job and never sets the
    /// field, so anything that arrives with one came from somewhere else.
    #[test]
    fn only_an_https_job_naming_other_code_is_refused() {
        use api_client::CodeSource;
        let chain = CodeSource::WasmUrl {
            url: "https://test.fastfs.io/a.wasm".into(),
            hash: "aa".into(),
            build_target: "wasm32-wasip2".into(),
        };
        let other = CodeSource::WasmUrl {
            url: "https://evil.example/b.wasm".into(),
            hash: "bb".into(),
            build_target: "wasm32-wasip2".into(),
        };
        let refuses = refuses_own_code_source;

        assert!(
            refuses(true, Some(&other), &chain),
            "an HTTPS job may not name code other than what the contract names for the project"
        );
        assert!(
            !refuses(true, Some(&chain), &chain),
            "the coordinator's compile-queue task carries the chain's own answer and runs"
        );
        assert!(!refuses(true, None, &chain), "the ordinary HTTPS job is untouched");
        assert!(
            !refuses(false, Some(&other), &chain),
            "on chain the contract fills this field — refusing it would refuse every \
             legitimate project execution, connectors included"
        );
        assert!(!refuses(false, None, &chain));
    }

    /// §14.1: the connector namespace is per-network, and picking the wrong one
    /// would mean either treating real connectors as ordinary projects (losing
    /// the fail-closed allowlist) or treating ordinary projects as connectors.
    #[test]
    fn the_connector_namespace_follows_the_network() {
        assert_eq!(
            connectors_namespace("https://rpc.mainnet.fastnear.com"),
            "connectors.outlayer.near"
        );
        assert_eq!(
            connectors_namespace("https://rpc.testnet.fastnear.com"),
            "connectors.outlayer.testnet"
        );
        // Anything unrecognised is testnet, matching how NEAR_NETWORK_ID is
        // derived a few lines above. Defaulting the other way would put a
        // misconfigured worker on the mainnet namespace.
        assert_eq!(
            connectors_namespace("http://localhost:3030"),
            "connectors.outlayer.testnet"
        );
    }
}

#[cfg(test)]
mod refusal_settlement_tests {
    fn production() -> String {
        let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs"))
            .expect("the worker can read its own source");
        src.split_once("#[cfg(test)]").map(|(before, _)| before.to_string()).expect("tests sit last")
    }

    /// The one refusal path answers BOTH doors before completing the job: the
    /// contract with `submit_execution_result`, the HTTPS caller with
    /// `complete_https_call`. The coordinator settles an HTTPS call only through
    /// the latter; a refusal that only completes the job leaves the call pending
    /// until the timeout sweeper bills the caller for a run that never started.
    #[test]
    fn the_refusal_path_answers_both_doors_then_completes_the_job() {
        let src = production();
        let start = src.find("async fn settle_refusal(").expect("the settlement exists");
        let end = start + src[start..].find("\n}\n").expect("it ends");
        let settle = &src[start..end];
        assert!(settle.contains("complete_https_call("), "HTTPS door not answered");
        assert!(settle.contains("submit_execution_result("), "on-chain door not answered");
        let start = src.find("async fn report_refusal(").expect("the refusal path exists");
        let end = start + src[start..].find("\n}\n").expect("it ends");
        let report = &src[start..end];
        assert!(report.contains("settle_refusal("), "the refusal path does not settle first");
        assert!(report.contains("complete_job("), "and it still completes the job");
    }

    /// Every refusal that happens after the claim goes through that path — a
    /// site that only completes the job is the bug this module exists for.
    #[test]
    fn every_post_claim_refusal_goes_through_the_refusal_path() {
        let src = production();
        let after = |anchor: &str, window: usize| -> String {
            let at = src.find(anchor).unwrap_or_else(|| panic!("anchor moved: {anchor}"));
            src[at..src.len().min(at + window)].to_string()
        };
        // The binding refusals: both arms.
        assert!(after("Refusing to run: use_bound_identity was requested", 600).contains("refuse_claimed_jobs("));
        let verdict = after("match verdict {", 900);
        assert!(verdict.contains("refuse_claimed_jobs("), "the verdict's Err arm does not refuse through the path");
        // refuse_claimed_jobs itself answers the request on the first job.
        assert!(after("async fn refuse_claimed_jobs(", 900).contains("report_refusal("));
        // The connector operation check.
        assert!(after("connector_manifest::may_run(is_connector_call, &input_data)", 500).contains("report_refusal("));
        // And it runs BEFORE any secret is decrypted: a call that will not run
        // has nothing to decrypt for (catalogue C9).
        let op_check = src.find("connector_manifest::may_run(is_connector_call, &input_data)").expect("the operation check exists");
        let decryption = src.find("let user_secrets = if let (Some(secrets_ref), Some(keystore))").expect("the secrets block exists");
        assert!(op_check < decryption, "a connector call naming no operation must be refused before its secrets are decrypted");
        assert!(!src.contains("anyhow::bail!(\n            \"This is a connector call and"), "may_run bails instead of refusing");
        // Both wasm download failures.
        let mut rest = src.as_str();
        let mut seen = 0;
        // The two SITES, not the helper that formats the error they carry.
        while let Some(at) = rest.find("let error_msg = format!(\"Failed to download WASM: {}\", e);") {
            seen += 1;
            let window = &rest[at..rest.len().min(at + 500)];
            assert!(window.contains("report_refusal("), "a wasm download failure only completes the job");
            rest = &rest[at + 1..];
        }
        assert_eq!(seen, 2, "both download branches are checked");
        // A caller's secrets_ref that can match no row is refused through the
        // path, and before the sender is even looked at.
        assert!(after("secrets_ref::well_formed_secrets_ref(&secrets_ref.profile", 700).contains("report_refusal("));
        let shape_check = src.find("secrets_ref::well_formed_secrets_ref(&secrets_ref.profile").expect("the caller-reference check exists");
        let sender_check = src.find("proven_sender(user_account_id.map(").expect("the sender check exists");
        assert!(shape_check < sender_check, "the reference's shape is judged before the sender");
        // The author's reference from the manifest goes through the same rule.
        assert!(after("secrets_ref::well_formed_secrets_ref(&author.profile", 500).contains("JobStatus::Custom"));
        // The secrets refusals (caller's, author's, unknown sender).
        assert!(src.matches("report_refusal(").count() >= 7, "fewer refusal sites than expected");
    }
}

#[cfg(test)]
mod proven_sender_tests {
    use super::proven_sender;

    /// A sender is passed through untouched; its absence refuses and names the
    /// secret's owner, never substitutes them.
    #[test]
    fn a_run_without_a_sender_decrypts_nothing() {
        assert_eq!(proven_sender(Some("alice.near"), "bob.near"), Ok("alice.near"));
        let refusal = proven_sender(None, "bob.near").expect_err("no sender, no decryption");
        assert!(refusal.contains("bob.near") && refusal.contains("no sender"), "{refusal}");
    }
}

#[cfg(test)]
mod k2_a_keystore_that_cannot_answer_refuses_the_run {
    //! Plan, catalogue K2: "keystore unreachable during an author-secret run →
    //! refused `Failed`, never run without the credential". The run is refused
    //! in `author_secrets_for_run` — an `Err` here is what `report_refusal`
    //! turns into a refused job, and an `Ok(None)` would be a run without the
    //! author's credential and without the author's admission gate. Two ways
    //! the keystore cannot answer: there is none, and there is one nobody can
    //! reach. Both must be `Failed` (an infrastructure fault, not the caller's).
    use super::*;

    fn manifest_naming_an_author_secret() -> connector_manifest::ProjectManifest {
        serde_json::from_str(r#"{"author_secrets":{"profile":"author"}}"#)
            .expect("a manifest with only an author profile parses")
    }

    fn run<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(f)
    }

    #[test]
    fn no_keystore_client_at_all_refuses_as_failed() {
        let manifest = manifest_naming_an_author_secret();
        let out = run(author_secrets_for_run(
            Some(&manifest),
            Some("alice.near/app"),
            None,
            Some("bob.near"),
            "data-id",
            "sha256-of-the-bytes-under-test",
            None,
        ));
        match out {
            Err((msg, api_client::JobStatus::Failed)) => {
                assert!(msg.contains("keystore"), "the refusal names the missing keystore: {msg}");
            }
            Err((msg, other)) => panic!("refused, but as {other:?} rather than Failed: {msg}"),
            Ok(_) => panic!("the run proceeded without the author's credential"),
        }
    }

    #[test]
    fn an_unreachable_keystore_refuses_as_failed_and_never_runs() {
        let manifest = manifest_naming_an_author_secret();
        // Port 9 is the discard service; nothing listens on it here, so the
        // connection is refused at once rather than timing out.
        let keystore = KeystoreClient::new(vec!["http://127.0.0.1:9".to_string()], "token".to_string())
            .expect("a client over one unreachable instance");
        let out = run(async {
            tokio::time::timeout(
                std::time::Duration::from_secs(30),
                author_secrets_for_run(
                    Some(&manifest),
                    Some("alice.near/app"),
                    Some(&keystore),
                    Some("bob.near"),
                    "data-id",
                    "sha256-of-the-bytes-under-test",
                    None,
                ),
            )
            .await
        });
        match out {
            Err(_) => panic!("30 s and no answer — an unreachable keystore must refuse, not hang"),
            Ok(Err((msg, api_client::JobStatus::Failed))) => {
                assert!(
                    !msg.contains("none are stored"),
                    "an unreachable keystore must not read as 'no secrets stored': {msg}"
                );
            }
            Ok(Err((msg, other))) => panic!("refused, but as {other:?} rather than Failed: {msg}"),
            Ok(Ok(_)) => panic!("the run proceeded without the author's credential"),
        }
    }
}

/// The compiled cache is keyed by the bytes, not by the coordinates.
///
/// Read from the source rather than exercised, because the mistake this guards
/// against is a single argument at a single call site, and the failure it
/// produces is silent: the run succeeds, the attestation reports a hash, and
/// the wasm that actually executed is whatever was compiled under the same
/// coordinates earlier. Nothing downstream can notice — the keystore judges a
/// build lock honestly, against a number describing code that did not run.
#[cfg(test)]
mod the_compiled_cache_is_keyed_by_content {
    const SOURCE: &str = include_str!("main.rs");

    /// The call that hands the engine its cache key must pass the measured
    /// hash. `wasm_checksum` is `sha256(repo:commit:target)` for a GitHub
    /// source — shared by every binary ever built from that commit.
    #[test]
    fn the_execute_call_passes_the_measured_hash() {
        let call = SOURCE
            .split_once(".execute(\n")
            .map(|(_, rest)| rest.split_once(")\n").map(|(c, _)| c).unwrap_or(rest))
            .expect("handle_execute_job still calls executor.execute");
        let key_argument = call
            .lines()
            .nth(1)
            .expect("the cache key is the second argument")
            .trim();
        assert_eq!(
            key_argument, "Some(executed_wasm_sha256.as_str()),",
            "the compiled cache key must be the hash measured from the bytes about to run"
        );
    }

    /// And that hash must be measured from the buffer, not taken from the job.
    #[test]
    fn the_measured_hash_comes_from_the_bytes() {
        let measured = SOURCE
            .split_once("let executed_wasm_sha256 = {")
            .expect("the measurement is still there")
            .1;
        // The block is three lines; a `use` inside it carries its own braces,
        // so the window is taken by line count rather than by the next `}`.
        let body: String = measured.lines().take(4).collect::<Vec<_>>().join("\n");
        assert!(
            body.contains("Sha256::digest(&wasm_bytes)"),
            "executed_wasm_sha256 must be the hash of the loaded buffer, not a value from the task: {body}"
        );
    }
}
