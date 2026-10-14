use anyhow::{Context, Result};
use near_crypto::{InMemorySigner, SecretKey};
use near_primitives::types::AccountId;
use std::env;
use std::str::FromStr;

/// Worker configuration loaded from environment variables
#[derive(Debug, Clone)]
pub struct Config {
    // Coordinator API
    pub api_base_url: String,
    pub api_auth_token: String,

    // NEAR configuration
    pub near_rpc_url: String,
    pub neardata_api_url: String,
    pub start_block_height: u64,
    pub offchainvm_contract_id: AccountId,
    #[allow(dead_code)]
    pub operator_account_id: AccountId,
    pub operator_signer: Option<InMemorySigner>,

    // Worker settings
    pub worker_id: String,
    pub enable_event_monitor: bool,
    pub poll_timeout_seconds: u64,
    pub scan_interval_ms: u64,

    // Event filter (filter events by standard, function name and min version)
    pub event_filter_standard_name: String,   // default: "near-outlayer"
    pub event_filter_function_name: String,   // default: "execution_requested"
    pub event_filter_min_version: Option<String>, // e.g., "1.0.0" - only process events >= this version

    // Compilation mode
    // "docker" - use Docker containers (requires Docker socket)
    // "native" - use native Rust toolchain with bubblewrap (for TEE/Phala)
    pub compilation_mode: String,

    // Docker for compilation (only used in "docker" mode)
    pub docker_image: String,
    pub compile_timeout_seconds: u64,
    pub compile_memory_limit_mb: u64,
    pub compile_cpu_limit: f64,

    // WASM execution limits (defaults)
    pub default_max_instructions: u64,
    #[allow(dead_code)]
    pub default_max_memory_mb: u32,
    #[allow(dead_code)]
    pub default_max_execution_seconds: u64,
    /// Hard cap on WASM execution time regardless of request (seconds)
    pub max_execution_seconds_cap: u64,
    /// The least linear memory a run is given, whatever `max_memory_mb` it
    /// asked (MB). A guest that declared less and used more kept running
    /// while the limit was not enforced, and keeps running under the floor.
    pub wasm_memory_floor_mb: u32,
    /// The most linear memory a run can be given (MB); wasm32's own bound.
    pub wasm_memory_ceiling_mb: u32,
    /// The stdout capacity (bytes); a write past it fails.
    pub max_output_bytes: usize,
    /// Extra time budget for RPC calls, WASM download, result upload etc. (seconds)
    pub iteration_overhead_seconds: u64,

    // Keystore instances in preference order (KEYSTORE_BASE_URLS). Optional outside TEE
    // registration mode; required in it, since a TEE worker without a keystore fails every
    // secrets job with a message blaming the user's configuration.
    pub keystore_base_urls: Option<Vec<String>>,
    pub keystore_auth_token: Option<String>,
    pub tee_mode: String,

    // Worker registration mode
    // If true - use TEE registration flow (INIT_ACCOUNT_*)
    // Register-contract is deployed at OPERATOR_ACCOUNT_ID (same account)
    // If false - use legacy mode with OPERATOR_PRIVATE_KEY (for testnet without TEE)
    // CRITICAL: OPERATOR_PRIVATE_KEY is ONLY for resolve_execution(), NEVER for user transactions!
    pub use_tee_registration: bool,

    // Signature scheme for the on-chain worker access key.
    // ed25519 (default) or ml-dsa-65 (FIPS-204 post-quantum). Switchable via WORKER_KEY_TYPE.
    pub worker_key_type: near_crypto::KeyType,

    // Init account (optional - for paying gas on worker registration)
    // If not set, operator_signer will be used for registration
    pub init_account_id: Option<AccountId>,
    pub init_account_signer: Option<InMemorySigner>,

    // Debug logging (admin only - stores raw stderr/stdout in system_hidden_logs table)
    // WARNING: These logs should NEVER be exposed via public API for security reasons
    // Set to false in production to disable raw log storage
    pub save_system_hidden_logs_to_debug: bool,

    // Print WASM stderr to worker logs (for debugging WASM execution)
    // Set to false in production to reduce log noise
    pub print_wasm_stderr: bool,

    // Worker capabilities (what this worker can do)
    pub capabilities: WorkerCapabilities,
    /// Routes this worker will NOT run, as `<project_id>:<operation>` or
    /// `<project_id>:*` (`EXECUTE_EXCLUDES`, comma-separated).
    ///
    /// The operator sets this because only the operator knows what the node
    /// cannot reach: a venue that geofences the country it sits in, a host its
    /// network blocks. The coordinator then hands those tasks to another
    /// worker instead of this one, and the guest never sees a failure it could
    /// not have avoided.
    pub execute_excludes: Vec<String>,

    // FastFS receiver contract (optional - for storing compiled WASM)
    pub fastfs_receiver: Option<String>,

    // FastFS sender account (optional - separate account for paying FastFS storage)
    pub fastfs_sender_signer: Option<InMemorySigner>,

    // RPC Proxy configuration (for WASM host functions)
    #[allow(dead_code)]
    pub rpc_proxy: RpcProxyConfig,

    // WASM cache configuration
    /// Maximum size of local WASM cache in MB (0 = disabled)
    pub wasm_cache_max_size_mb: u64,
    /// Directory for cached WASM files
    pub wasm_cache_dir: String,
}

/// RPC Proxy configuration for WASM host functions
#[derive(Debug, Clone)]
pub struct RpcProxyConfig {
    /// Enable RPC proxy host functions for WASM
    #[allow(dead_code)]
    pub enabled: bool,
    /// RPC URL with API key (separate from worker's NEAR_RPC_URL)
    /// If not set, falls back to worker's near_rpc_url
    pub rpc_url: Option<String>,
    /// Maximum RPC calls per execution (rate limiting)
    pub max_calls_per_execution: u32,
    /// Allow transaction methods (send_tx, broadcast_tx_*)
    /// If false, only view methods are allowed
    pub allow_transactions: bool,
}

/// Worker capabilities - what jobs this worker can handle
#[derive(Debug, Clone)]
pub struct WorkerCapabilities {
    pub compilation: bool, // Can compile GitHub repos to WASM
    pub execution: bool,   // Can execute WASM code
}

impl WorkerCapabilities {
    /// Convert capabilities to string array for API
    pub fn to_array(&self) -> Vec<String> {
        let mut result = Vec::new();
        if self.compilation {
            result.push("compilation".to_string());
        }
        if self.execution {
            result.push("execution".to_string());
        }
        result
    }

    /// Check if worker can handle compilation
    pub fn can_compile(&self) -> bool {
        self.compilation
    }

    /// Check if worker can handle execution
    #[allow(dead_code)]
    pub fn can_execute(&self) -> bool {
        self.execution
    }
}

impl Config {
    /// Load configuration from environment variables
    ///
    /// Required environment variables:
    /// - API_BASE_URL: Coordinator API URL (e.g., http://localhost:8080)
    /// - API_AUTH_TOKEN: Bearer token for API authentication
    /// - NEAR_RPC_URL: NEAR RPC endpoint (e.g., https://rpc.testnet.near.org)
    /// - OFFCHAINVM_CONTRACT_ID: OffchainVM contract account ID
    /// - OPERATOR_ACCOUNT_ID: Worker operator account ID
    /// - OPERATOR_PRIVATE_KEY: Worker operator private key (ed25519:...)
    ///   ⚠️ CRITICAL: This key is ONLY for calling resolve_execution() on OutLayer contract!
    ///   This key is NEVER passed to WASM and NEVER used for signing user transactions.
    ///   User transactions are signed with keys provided by WASM via secrets mechanism.
    ///
    /// Optional environment variables (with defaults):
    /// - WORKER_ID: Unique worker identifier (default: random UUID)
    /// - ENABLE_EVENT_MONITOR: Enable NEAR event monitoring (default: false)
    /// - POLL_TIMEOUT_SECONDS: Long-poll timeout (default: 60)
    /// - DOCKER_IMAGE: Docker image for compilation (default: rust:1.75)
    /// - COMPILE_TIMEOUT_SECONDS: Compilation timeout (default: 300)
    /// - COMPILE_MEMORY_LIMIT_MB: Compilation memory limit (default: 2048)
    /// - COMPILE_CPU_LIMIT: Compilation CPU limit (default: 2.0)
    /// - DEFAULT_MAX_INSTRUCTIONS: Default instruction limit (default: 10_000_000_000)
    /// - DEFAULT_MAX_MEMORY_MB: Default memory limit (default: 128)
    /// - DEFAULT_MAX_EXECUTION_SECONDS: Default execution timeout (default: 60)
    pub fn from_env() -> Result<Self> {
        // Load .env file if present
        dotenv::dotenv().ok();

        // Required fields
        let api_base_url = env::var("API_BASE_URL")
            .context("API_BASE_URL environment variable is required")?;

        let api_auth_token = env::var("API_AUTH_TOKEN")
            .context("API_AUTH_TOKEN environment variable is required")?;

        let near_rpc_url = env::var("NEAR_RPC_URL")
            .context("NEAR_RPC_URL environment variable is required")?;

        let neardata_api_url = env::var("NEARDATA_API_URL")
            .unwrap_or_else(|_| "https://testnet.neardata.xyz/v0/block".to_string());

        let start_block_height = env::var("START_BLOCK_HEIGHT")
            .unwrap_or_else(|_| "0".to_string())
            .parse::<u64>()
            .context("START_BLOCK_HEIGHT must be a valid number")?;

        let offchainvm_contract_id = env::var("OFFCHAINVM_CONTRACT_ID")
            .context("OFFCHAINVM_CONTRACT_ID environment variable is required")?;
        let offchainvm_contract_id = AccountId::from_str(&offchainvm_contract_id)
            .context("Invalid OFFCHAINVM_CONTRACT_ID format")?;

        let operator_account_id = env::var("OPERATOR_ACCOUNT_ID")
            .context("OPERATOR_ACCOUNT_ID environment variable is required")?;
        let operator_account_id = AccountId::from_str(&operator_account_id)
            .context("Invalid OPERATOR_ACCOUNT_ID format")?;

        // Check if TEE registration is enabled
        let use_tee_registration = env::var("USE_TEE_REGISTRATION")
            .unwrap_or_else(|_| "true".to_string()) // Default: true (TEE mode for production)
            .parse::<bool>()
            .context("USE_TEE_REGISTRATION must be 'true' or 'false'")?;

        // Worker key signature scheme (ed25519 | ml-dsa-65). Default ed25519.
        let worker_key_type = {
            let s = env::var("WORKER_KEY_TYPE").unwrap_or_else(|_| "ed25519".to_string());
            near_crypto::KeyType::from_str(&s).map_err(|e| {
                anyhow::anyhow!("Invalid WORKER_KEY_TYPE '{}': {} (use 'ed25519' or 'ml-dsa-65')", s, e)
            })?
        };

        // Load operator_signer based on registration mode
        // CRITICAL: operator_signer is ONLY used for calling resolve_execution() on OutLayer contract
        // This key is NEVER passed to WASM and NEVER used for user transactions!
        // User transactions are signed with keys from WASM (provided via secrets mechanism).
        let operator_signer = if use_tee_registration {
            // TEE mode: operator_signer will be set after registration in main.rs
            None
        } else {
            // Legacy mode: load OPERATOR_PRIVATE_KEY from env
            // CRITICAL: This key is ONLY for resolve_execution(), NOT for user transactions!
            let operator_private_key = env::var("OPERATOR_PRIVATE_KEY")
                .context("OPERATOR_PRIVATE_KEY is required when USE_TEE_REGISTRATION=false")?;

            let secret_key: SecretKey = operator_private_key
                .parse()
                .context("Invalid OPERATOR_PRIVATE_KEY format (expected ed25519:...)")?;

            Some(InMemorySigner {
                account_id: operator_account_id.clone(),
                public_key: secret_key.public_key(),
                secret_key,
            })
        };

        // Optional fields with defaults
        let worker_id = env::var("WORKER_ID")
            .unwrap_or_else(|_| uuid::Uuid::new_v4().to_string());

        let enable_event_monitor = env::var("ENABLE_EVENT_MONITOR")
            .unwrap_or_else(|_| "false".to_string())
            .parse::<bool>()
            .context("ENABLE_EVENT_MONITOR must be 'true' or 'false'")?;

        let poll_timeout_seconds = env::var("POLL_TIMEOUT_SECONDS")
            .unwrap_or_else(|_| "60".to_string())
            .parse::<u64>()
            .context("POLL_TIMEOUT_SECONDS must be a valid number")?;

        let scan_interval_ms = env::var("SCAN_INTERVAL_MS")
            .unwrap_or_else(|_| "0".to_string())
            .parse::<u64>()
            .context("SCAN_INTERVAL_MS must be a valid number")?;

        // Event filter (filter events by standard, function name and min version)
        let event_filter_standard_name = env::var("EVENT_FILTER_STANDARD_NAME")
            .unwrap_or_else(|_| "near-outlayer".to_string());
        let event_filter_function_name = env::var("EVENT_FILTER_FUNCTION_NAME")
            .unwrap_or_else(|_| "execution_requested".to_string());
        let event_filter_min_version = env::var("EVENT_FILTER_MIN_VERSION").ok();

        // Compilation mode: docker (default) or native (bubblewrap)
        let compilation_mode = env::var("COMPILATION_MODE")
            .unwrap_or_else(|_| "docker".to_string())
            .to_lowercase();

        // Validate compilation mode
        if !["docker", "native"].contains(&compilation_mode.as_str()) {
            anyhow::bail!("Invalid COMPILATION_MODE: '{}'. Must be 'docker' or 'native'", compilation_mode);
        }

        // Deployments should override this with a digest pin: the compiler decides which
        // toolchain produces the wasm whose hash the enclave attests, and `ensure_image` pulls
        // on every job, so a floating tag lets a registry push change production silently.
        let docker_image = env::var("DOCKER_IMAGE")
            .unwrap_or_else(|_| "outlayer/wasmedge-compiler:rust1.85-wasi25".to_string());

        let compile_timeout_seconds = env::var("COMPILE_TIMEOUT_SECONDS")
            .unwrap_or_else(|_| "300".to_string())
            .parse::<u64>()
            .context("COMPILE_TIMEOUT_SECONDS must be a valid number")?;

        let compile_memory_limit_mb = env::var("COMPILE_MEMORY_LIMIT_MB")
            .unwrap_or_else(|_| "2048".to_string())
            .parse::<u64>()
            .context("COMPILE_MEMORY_LIMIT_MB must be a valid number")?;

        let compile_cpu_limit = env::var("COMPILE_CPU_LIMIT")
            .unwrap_or_else(|_| "2.0".to_string())
            .parse::<f64>()
            .context("COMPILE_CPU_LIMIT must be a valid number")?;

        let default_max_instructions = env::var("DEFAULT_MAX_INSTRUCTIONS")
            .unwrap_or_else(|_| "10000000000".to_string())
            .parse::<u64>()
            .context("DEFAULT_MAX_INSTRUCTIONS must be a valid number")?;

        let default_max_memory_mb = env::var("DEFAULT_MAX_MEMORY_MB")
            .unwrap_or_else(|_| "128".to_string())
            .parse::<u32>()
            .context("DEFAULT_MAX_MEMORY_MB must be a valid number")?;

        let default_max_execution_seconds = env::var("DEFAULT_MAX_EXECUTION_SECONDS")
            .unwrap_or_else(|_| "60".to_string())
            .parse::<u64>()
            .context("DEFAULT_MAX_EXECUTION_SECONDS must be a valid number")?;

        let max_execution_seconds_cap = env::var("MAX_EXECUTION_SECONDS_CAP")
            .unwrap_or_else(|_| "180".to_string())
            .parse::<u64>()
            .context("MAX_EXECUTION_SECONDS_CAP must be a valid number")?;

        let wasm_memory_floor_mb = env::var("WASM_MEMORY_FLOOR_MB")
            .unwrap_or_else(|_| crate::executor::DEFAULT_MEMORY_FLOOR_MB.to_string())
            .parse::<u32>()
            .context("WASM_MEMORY_FLOOR_MB must be a valid number")?;

        let wasm_memory_ceiling_mb = env::var("WASM_MEMORY_CEILING_MB")
            .unwrap_or_else(|_| crate::executor::DEFAULT_MEMORY_CEILING_MB.to_string())
            .parse::<u32>()
            .context("WASM_MEMORY_CEILING_MB must be a valid number")?;
        anyhow::ensure!(
            wasm_memory_ceiling_mb >= wasm_memory_floor_mb,
            "WASM_MEMORY_CEILING_MB ({wasm_memory_ceiling_mb}) must be at least WASM_MEMORY_FLOOR_MB ({wasm_memory_floor_mb})"
        );

        let max_output_bytes = env::var("MAX_OUTPUT_BYTES")
            .unwrap_or_else(|_| crate::executor::DEFAULT_MAX_OUTPUT_BYTES.to_string())
            .parse::<usize>()
            .context("MAX_OUTPUT_BYTES must be a valid number")?;

        let iteration_overhead_seconds = env::var("ITERATION_OVERHEAD_SECONDS")
            .unwrap_or_else(|_| "60".to_string())
            .parse::<u64>()
            .context("ITERATION_OVERHEAD_SECONDS must be a valid number")?;

        // Keystore configuration. An unset or blank KEYSTORE_BASE_URLS means "no keystore"
        // (compose files pass the variable through with an empty default); a non-empty value
        // must parse, so a typo fails the start instead of every secrets job.
        let keystore_base_urls = match env::var("KEYSTORE_BASE_URLS") {
            Ok(raw) if !raw.trim().is_empty() => Some(crate::keystore_client::parse_base_urls(&raw)?),
            _ => None,
        };
        let keystore_auth_token = env::var("KEYSTORE_AUTH_TOKEN")
            .ok()
            .filter(|t| !t.trim().is_empty());

        let tee_mode_raw = env::var("TEE_MODE")
            .unwrap_or_else(|_| "none".to_string());
        // Remove quotes if present (Phala Cloud may add them)
        let tee_mode = tee_mode_raw
            .trim()
            .trim_matches('"')
            .trim_matches('\'')
            .to_lowercase();

        // Validate TEE mode (case-insensitive, trimmed)
        if !["outlayer_tee", "none"].contains(&tee_mode.as_str()) {
            anyhow::bail!(
                "Invalid TEE_MODE: received '{}' (raw: '{:?}'), must be 'outlayer_tee' or 'none' (case-insensitive)",
                tee_mode,
                tee_mode_raw
            );
        }

        // Debug logging flag (default: true = enabled)
        // WARNING: Stores raw stderr/stdout in system_hidden_logs table
        // Set SAVE_SYSTEM_HIDDEN_LOGS_TO_DEBUG=false in production to disable
        let save_system_hidden_logs_to_debug = env::var("SAVE_SYSTEM_HIDDEN_LOGS_TO_DEBUG")
            .unwrap_or_else(|_| "true".to_string())
            .parse::<bool>()
            .unwrap_or(true);

        // Set PRINT_WASM_STDERR=true to see WASM stderr in worker logs
        let print_wasm_stderr = env::var("PRINT_WASM_STDERR")
            .unwrap_or_else(|_| "false".to_string())
            .parse::<bool>()
            .unwrap_or(false);

        // Worker capabilities - what this worker can do
        let compilation_enabled = env::var("COMPILATION_ENABLED")
            .unwrap_or_else(|_| "true".to_string())
            .parse::<bool>()
            .context("COMPILATION_ENABLED must be 'true' or 'false'")?;

        let execution_enabled = env::var("EXECUTION_ENABLED")
            .unwrap_or_else(|_| "true".to_string())
            .parse::<bool>()
            .context("EXECUTION_ENABLED must be 'true' or 'false'")?;

        // At least one capability must be enabled
        if !compilation_enabled && !execution_enabled {
            anyhow::bail!("At least one capability must be enabled (COMPILATION_ENABLED or EXECUTION_ENABLED)");
        }

        let capabilities = WorkerCapabilities {
            compilation: compilation_enabled,
            execution: execution_enabled,
        };

        // FastFS receiver contract (optional)
        let fastfs_receiver = env::var("FASTFS_RECEIVER").ok();

        // FastFS sender account (optional - separate account for paying storage)
        let fastfs_sender_signer = if let Ok(sender_account_id) = env::var("FASTFS_SENDER_ACCOUNT_ID") {
            let sender_private_key = env::var("FASTFS_SENDER_PRIVATE_KEY")
                .context("FASTFS_SENDER_PRIVATE_KEY is required when FASTFS_SENDER_ACCOUNT_ID is set")?;

            let sender_account = AccountId::from_str(&sender_account_id)
                .context("Invalid FASTFS_SENDER_ACCOUNT_ID format")?;

            let secret_key: SecretKey = sender_private_key
                .parse()
                .context("Invalid FASTFS_SENDER_PRIVATE_KEY format (expected ed25519:...)")?;

            Some(InMemorySigner {
                account_id: sender_account,
                public_key: secret_key.public_key(),
                secret_key,
            })
        } else {
            None
        };

        // Init account (optional - for paying gas on worker registration)
        let (init_account_id, init_account_signer) = if let Ok(init_account_str) = env::var("INIT_ACCOUNT_ID") {
            let init_account_id = AccountId::from_str(&init_account_str)
                .context("Invalid INIT_ACCOUNT_ID format")?;

            let init_private_key_str = env::var("INIT_ACCOUNT_PRIVATE_KEY")
                .context("INIT_ACCOUNT_PRIVATE_KEY is required when INIT_ACCOUNT_ID is set")?;

            let init_private_key = SecretKey::from_str(&init_private_key_str)
                .context("Invalid INIT_ACCOUNT_PRIVATE_KEY format")?;

            let init_signer = InMemorySigner {
                account_id: init_account_id.clone(),
                public_key: init_private_key.public_key(),
                secret_key: init_private_key,
            };

            (Some(init_account_id), Some(init_signer))
        } else {
            (None, None)
        };

        // NEAR RPC Proxy configuration (for WASM host functions)
        let rpc_proxy_enabled = env::var("NEAR_RPC_PROXY_ENABLED")
            .unwrap_or_else(|_| "true".to_string())
            .parse::<bool>()
            .context("NEAR_RPC_PROXY_ENABLED must be 'true' or 'false'")?;

        let rpc_proxy_url = env::var("NEAR_RPC_PROXY_URL").ok();

        let rpc_proxy_max_calls = env::var("NEAR_RPC_PROXY_MAX_CALLS")
            .unwrap_or_else(|_| "100".to_string())
            .parse::<u32>()
            .context("NEAR_RPC_PROXY_MAX_CALLS must be a valid number")?;

        let rpc_proxy_allow_transactions = env::var("NEAR_RPC_PROXY_ALLOW_TRANSACTIONS")
            .unwrap_or_else(|_| "true".to_string())
            .parse::<bool>()
            .context("NEAR_RPC_PROXY_ALLOW_TRANSACTIONS must be 'true' or 'false'")?;

        let rpc_proxy = RpcProxyConfig {
            enabled: rpc_proxy_enabled,
            rpc_url: rpc_proxy_url,
            max_calls_per_execution: rpc_proxy_max_calls,
            allow_transactions: rpc_proxy_allow_transactions,
        };

        // WASM cache configuration
        let wasm_cache_max_size_mb = env::var("WASM_CACHE_MAX_SIZE_MB")
            .unwrap_or_else(|_| "100".to_string()) // Default: 100MB
            .parse::<u64>()
            .context("WASM_CACHE_MAX_SIZE_MB must be a valid number")?;

        // WASM cache directory - MUST be outside /tmp because WASI P2 has access to /tmp
        // Default to ~/.cache/outlayer/wasm or /var/cache/outlayer/wasm
        let wasm_cache_dir = env::var("WASM_CACHE_DIR").unwrap_or_else(|_| {
            // Try user cache dir first
            if let Some(cache_dir) = dirs::cache_dir() {
                cache_dir.join("outlayer").join("wasm").to_string_lossy().to_string()
            } else {
                // Fallback to /var/cache (requires proper permissions)
                "/var/cache/outlayer/wasm".to_string()
            }
        });

        let execute_excludes: Vec<String> = env::var("EXECUTE_EXCLUDES")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        Ok(Self {
            api_base_url,
            execute_excludes,
            api_auth_token,
            near_rpc_url,
            neardata_api_url,
            start_block_height,
            offchainvm_contract_id,
            operator_account_id,
            operator_signer,
            worker_key_type,
            worker_id,
            enable_event_monitor,
            poll_timeout_seconds,
            scan_interval_ms,
            event_filter_standard_name,
            event_filter_function_name,
            event_filter_min_version,
            compilation_mode,
            docker_image,
            compile_timeout_seconds,
            compile_memory_limit_mb,
            compile_cpu_limit,
            default_max_instructions,
            default_max_memory_mb,
            default_max_execution_seconds,
            max_execution_seconds_cap,
            wasm_memory_floor_mb,
            wasm_memory_ceiling_mb,
            max_output_bytes,
            iteration_overhead_seconds,
            keystore_base_urls,
            keystore_auth_token,
            tee_mode,
            use_tee_registration,
            init_account_id,
            init_account_signer,
            save_system_hidden_logs_to_debug,
            print_wasm_stderr,
            capabilities,
            fastfs_receiver,
            fastfs_sender_signer,
            rpc_proxy,
            wasm_cache_max_size_mb,
            wasm_cache_dir,
        })
    }

    /// Set operator signer after registration
    pub fn set_operator_signer(&mut self, signer: InMemorySigner) {
        self.operator_signer = Some(signer);
    }

    /// Set worker_id (used for auto-generation based on Phala app info)
    pub fn set_worker_id(&mut self, worker_id: String) {
        self.worker_id = worker_id;
    }

    /// Check if WORKER_ID was explicitly set via environment variable
    pub fn is_worker_id_from_env() -> bool {
        std::env::var("WORKER_ID").is_ok()
    }

    /// Detect network from OFFCHAINVM_CONTRACT_ID
    /// Returns "testnet" or "mainnet"
    pub fn detect_network(&self) -> &'static str {
        let contract_str = self.offchainvm_contract_id.to_string();
        if contract_str.ends_with(".testnet") {
            "testnet"
        } else {
            "mainnet"
        }
    }

    /// Get worker type string based on capabilities
    /// Returns "executor", "compiler", or "executor-compiler"
    pub fn worker_type_string(&self) -> &'static str {
        match (self.capabilities.execution, self.capabilities.compilation) {
            (true, true) => "executor-compiler",
            (true, false) => "executor",
            (false, true) => "compiler",
            (false, false) => "unknown", // Should never happen due to validation
        }
    }

    /// Generate worker_id from network, type, and optional Phala app_id
    /// Format: {network}-{type}-{app_id} or {network}-{type}-{uuid}
    /// Full app_id allows verification via https://trust.phala.com/app/{app_id}
    pub fn generate_worker_id(&self, phala_app_id: Option<&str>) -> String {
        let network = self.detect_network();
        let worker_type = self.worker_type_string();

        let suffix = match phala_app_id {
            Some(app_id) => {
                // Use full Phala app_id (40 hex chars) for TEE verification
                // Users can verify at: https://trust.phala.com/app/{app_id}
                app_id.to_string()
            }
            None => {
                // Fallback: use full UUID (32 hex chars)
                uuid::Uuid::new_v4().to_string().replace('-', "")
            }
        };

        format!("{}-{}-{}", network, worker_type, suffix)
    }

    /// Get operator signer (panics if not set)
    pub fn get_operator_signer(&self) -> &InMemorySigner {
        self.operator_signer.as_ref().expect("Operator signer not set - registration must have failed")
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<()> {
        if self.api_base_url.is_empty() {
            anyhow::bail!("API base URL cannot be empty");
        }

        // A TEE executor registers a session with the keystore at startup and decrypts through
        // it; without one it would come up and fail every job that carries secrets.
        if self.use_tee_registration && self.capabilities.execution {
            if self.keystore_base_urls.is_none() {
                anyhow::bail!("KEYSTORE_BASE_URLS is required when USE_TEE_REGISTRATION=true and EXECUTION_ENABLED=true");
            }
            if self.keystore_auth_token.is_none() {
                anyhow::bail!("KEYSTORE_AUTH_TOKEN is required when USE_TEE_REGISTRATION=true and EXECUTION_ENABLED=true");
            }
        }

        if self.api_auth_token.is_empty() {
            anyhow::bail!("API auth token cannot be empty");
        }

        if self.near_rpc_url.is_empty() {
            anyhow::bail!("NEAR RPC URL cannot be empty");
        }

        if self.poll_timeout_seconds == 0 || self.poll_timeout_seconds > 300 {
            anyhow::bail!("Poll timeout must be between 1 and 300 seconds");
        }

        if self.compile_timeout_seconds == 0 || self.compile_timeout_seconds > 3600 {
            anyhow::bail!("Compile timeout must be between 1 and 3600 seconds");
        }

        if self.compile_memory_limit_mb < 512 {
            anyhow::bail!("Compile memory limit must be at least 512 MB");
        }

        if self.compile_cpu_limit <= 0.0 {
            anyhow::bail!("Compile CPU limit must be positive");
        }

        // Security check: native compilation mode must be isolated
        // because malicious build scripts can steal secrets via environment variables
        if self.compilation_mode == "native" {
            // Native compilation requires strict isolation
            if self.capabilities.execution {
                anyhow::bail!(
                    "Security error: Native compilation mode (COMPILATION_MODE=native) \
                     must NOT have EXECUTION_ENABLED=true. \
                     Malicious build scripts can steal secrets from environment variables. \
                     Set EXECUTION_ENABLED=false for native compiler workers."
                );
            }
            if self.init_account_signer.is_some() {
                anyhow::bail!(
                    "Security error: Native compilation mode (COMPILATION_MODE=native) \
                     must NOT have INIT_ACCOUNT_PRIVATE_KEY set. \
                     Malicious build scripts can steal secrets from environment variables. \
                     Remove INIT_ACCOUNT_PRIVATE_KEY from .env for native compiler workers."
                );
            }
            if self.operator_signer.is_some() {
                anyhow::bail!(
                    "Security error: Native compilation mode (COMPILATION_MODE=native) \
                     must NOT have OPERATOR_PRIVATE_KEY set. \
                     Malicious build scripts can steal secrets from environment variables. \
                     Remove OPERATOR_PRIVATE_KEY from .env for native compiler workers."
                );
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_validation() {
        let mut config = create_test_config();
        assert!(config.validate().is_ok());

        // Test invalid poll timeout
        config.poll_timeout_seconds = 0;
        assert!(config.validate().is_err());

        config.poll_timeout_seconds = 60;
        assert!(config.validate().is_ok());

        // Test invalid memory limit
        config.compile_memory_limit_mb = 100;
        assert!(config.validate().is_err());
    }

    /// A TEE executor without a keystore would boot and then fail every secrets job, so the
    /// start is refused; a compile-only TEE worker and a non-TEE worker need no keystore.
    #[test]
    fn tee_executor_must_have_a_keystore() {
        let mut config = create_test_config();
        config.use_tee_registration = true;
        config.capabilities.execution = true;
        config.keystore_base_urls = None;
        config.keystore_auth_token = None;
        assert!(format!("{:#}", config.validate().unwrap_err()).contains("KEYSTORE_BASE_URLS"));

        config.keystore_base_urls = Some(vec!["https://a.example".to_string()]);
        assert!(format!("{:#}", config.validate().unwrap_err()).contains("KEYSTORE_AUTH_TOKEN"));

        config.keystore_auth_token = Some("token".to_string());
        assert!(config.validate().is_ok());

        let mut compile_only = create_test_config();
        compile_only.use_tee_registration = true;
        compile_only.capabilities.execution = false;
        compile_only.capabilities.compilation = true;
        assert!(compile_only.validate().is_ok());

        let mut legacy = create_test_config();
        legacy.use_tee_registration = false;
        legacy.capabilities.execution = true;
        assert!(legacy.validate().is_ok());
    }

    fn create_test_config() -> Config {
        Config {
            api_base_url: "http://localhost:8080".to_string(),
            api_auth_token: "test-token".to_string(),
            near_rpc_url: "https://rpc.testnet.near.org".to_string(),
            neardata_api_url: "https://testnet.neardata.xyz/v0/block".to_string(),
            start_block_height: 0,
            offchainvm_contract_id: "outlayer.testnet".parse().unwrap(),
            operator_account_id: "worker.testnet".parse().unwrap(),
            operator_signer: Some({
                let secret_key: SecretKey = "ed25519:3D4YudUahN1nawWvHfEKBGpmJLfbCTbvdXDJKqfLhQ98XewyWK4tEDWvmAYPZqcgz7qfkCEHyWD15m8JVVWJ3LXD".parse().unwrap();
                InMemorySigner {
                    account_id: "worker.testnet".parse().unwrap(),
                    public_key: secret_key.public_key(),
                    secret_key,
                }
            }),
            worker_key_type: near_crypto::KeyType::ED25519,
            worker_id: "test-worker".to_string(),
            enable_event_monitor: false,
            poll_timeout_seconds: 60,
            scan_interval_ms: 0,
            event_filter_standard_name: "near-outlayer".to_string(),
            event_filter_function_name: "execution_requested".to_string(),
            event_filter_min_version: None,
            compilation_mode: "docker".to_string(),
            docker_image: "rust:1.75".to_string(),
            compile_timeout_seconds: 300,
            compile_memory_limit_mb: 2048,
            compile_cpu_limit: 2.0,
            default_max_instructions: 10_000_000_000,
            default_max_memory_mb: 128,
            default_max_execution_seconds: 60,
            max_execution_seconds_cap: 180,
            wasm_memory_floor_mb: crate::executor::DEFAULT_MEMORY_FLOOR_MB,
            wasm_memory_ceiling_mb: crate::executor::DEFAULT_MEMORY_CEILING_MB,
            max_output_bytes: crate::executor::DEFAULT_MAX_OUTPUT_BYTES,
            iteration_overhead_seconds: 60,
            keystore_base_urls: None,
            keystore_auth_token: None,
            tee_mode: "none".to_string(),
            use_tee_registration: false, // Test mode: use legacy with OPERATOR_PRIVATE_KEY
            init_account_id: None,
            init_account_signer: None,
            save_system_hidden_logs_to_debug: true, // Default: enabled for debugging
            print_wasm_stderr: false,
            capabilities: WorkerCapabilities {
                compilation: true,
                execution: true,
            },
            fastfs_receiver: None,
            fastfs_sender_signer: None,
            rpc_proxy: RpcProxyConfig {
                enabled: true,
                rpc_url: None,
                max_calls_per_execution: 100,
                allow_transactions: true,
            },
            wasm_cache_max_size_mb: 100,
            execute_excludes: Vec::new(),
            wasm_cache_dir: "/tmp/wasm_cache_test".to_string(),
        }
    }
}
