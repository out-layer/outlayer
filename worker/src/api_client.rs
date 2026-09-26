use anyhow::{Context, Result};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Job status for error classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
    CompilationFailed,
    ExecutionFailed,
    AccessDenied,
    InsufficientPayment,
    Custom,
}

/// Response format for execution output
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum ResponseFormat {
    Bytes,
    #[default]
    Text,
    Json,
}

/// Execution context metadata passed to WASM via environment variables
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExecutionContext {
    #[serde(default)]
    pub sender_id: Option<String>,
    #[serde(default)]
    pub block_height: Option<u64>,
    #[serde(default)]
    pub block_timestamp: Option<u64>,
    #[serde(default)]
    pub contract_id: Option<String>,
    #[serde(default)]
    pub transaction_hash: Option<String>,
    #[serde(default)]
    pub receipt_id: Option<String>,
    #[serde(default)]
    pub predecessor_id: Option<String>,
    #[serde(default)]
    pub signer_public_key: Option<String>,
    #[serde(default)]
    pub gas_burnt: Option<u64>,
}

/// Request from user to execute WASM code off-chain
///
/// Flow:
/// 1. Event Monitor detects on-chain execution request
/// 2. Sends ExecutionRequest to Coordinator API
/// 3. Coordinator places in Redis queue for workers
/// 4. Worker polls and receives ExecutionRequest
/// 5. Worker claims jobs via coordinator (which decides: compile+execute or just execute)
/// 6. Worker processes jobs and returns result to contract
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionRequest {
    pub request_id: u64,
    pub data_id: String,
    /// Code source - optional for HTTPS calls where project_id is used instead
    /// Worker resolves project_id -> code_source from contract
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_source: Option<CodeSource>,
    pub resource_limits: ResourceLimits,
    pub input_data: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secrets_ref: Option<SecretsReference>,
    #[serde(default)]
    pub response_format: ResponseFormat,
    #[serde(default)]
    pub context: ExecutionContext,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_account_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub near_payment_yocto: Option<String>,
    /// Payment to project developer (stablecoin, minimal token units)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attached_usd: Option<String>,
    /// If true, only compile the code without executing
    #[serde(default)]
    pub compile_only: bool,
    /// Force recompilation even if WASM exists in cache
    #[serde(default)]
    pub force_rebuild: bool,
    /// Store compiled WASM to FastFS after compilation
    #[serde(default)]
    pub store_on_fastfs: bool,
    /// Result from compile job to pass to executor (e.g., FastFS URL or compilation error)
    /// When set, executor should call resolve_execution with this value without running WASM
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compile_result: Option<String>,
    /// Project UUID for persistent storage (None for standalone WASM)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_uuid: Option<String>,
    /// Project ID for project-based secrets (e.g., "alice.near/my-app")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    /// Version key for specific project version (if None, uses active_version)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_key: Option<String>,
    /// HTTPS API call flag - if true, don't call contract, call coordinator instead
    #[serde(default)]
    pub is_https_call: bool,
    /// HTTPS API call ID - used to complete the call on coordinator
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_id: Option<String>,
    /// Payment Key owner for HTTPS calls (NEAR account ID)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_key_owner: Option<String>,
    /// Payment Key nonce for HTTPS calls
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_key_nonce: Option<i32>,
    /// Agent Connect: the binding kind behind a bound context sender — the
    /// hint for WHICH verifier to run before adopting that sender. A hint,
    /// not truth: each verifier is fail-closed against the wrong contract.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_kind: Option<String>,
    /// USD payment amount for HTTPS calls (X-Attached-Deposit, in minimal token units)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usd_payment: Option<String>,
    /// Wallet ID for wallet-enabled executions (e.g. "ed25519:abc..." from X-Wallet-Id header)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallet_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum CodeSource {
    GitHub {
        repo: String,
        commit: String,
        build_target: String,
    },
    /// Pre-compiled WASM file accessible via URL
    /// Worker downloads from URL, verifies SHA256 hash, then executes without compilation
    WasmUrl {
        url: String,           // URL for downloading (https://, ipfs://, ar://)
        hash: String,          // SHA256 hash for verification (hex encoded)
        build_target: String,
    },
}

/// Reference to secrets stored in contract (new repo-based system)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsReference {
    pub profile: String,
    pub account_id: String,
}

impl SecretsReference {
    /// Format as "{account_id}/{profile}" for attestation hash.
    /// Returns None if either field is empty.
    pub fn as_attestation_ref(&self) -> Option<String> {
        if self.account_id.is_empty() || self.profile.is_empty() {
            None
        } else {
            Some(format!("{}/{}", self.account_id, self.profile))
        }
    }
}

impl CodeSource {
    pub fn repo(&self) -> Option<&str> {
        match self {
            CodeSource::GitHub { repo, .. } => Some(repo),
            CodeSource::WasmUrl { .. } => None,
        }
    }

    pub fn commit(&self) -> Option<&str> {
        match self {
            CodeSource::GitHub { commit, .. } => Some(commit),
            CodeSource::WasmUrl { .. } => None,
        }
    }

    pub fn build_target(&self) -> Option<&str> {
        match self {
            CodeSource::GitHub { build_target, .. } => Some(build_target),
            CodeSource::WasmUrl { build_target, .. } => Some(build_target),
        }
    }

    /// Get the hash for WasmUrl sources (used for verification)
    #[allow(dead_code)]
    pub fn hash(&self) -> Option<&str> {
        match self {
            CodeSource::GitHub { .. } => None,
            CodeSource::WasmUrl { hash, .. } => Some(hash),
        }
    }

    /// Get the URL for WasmUrl sources
    #[allow(dead_code)]
    pub fn url(&self) -> Option<&str> {
        match self {
            CodeSource::GitHub { .. } => None,
            CodeSource::WasmUrl { url, .. } => Some(url),
        }
    }

    /// Check if this is a WasmUrl source (pre-compiled, no compilation needed)
    #[allow(dead_code)]
    pub fn is_wasm_url(&self) -> bool {
        matches!(self, CodeSource::WasmUrl { .. })
    }

    /// Normalize repo URL to full https:// format for git clone
    /// Examples:
    /// - "github.com/user/repo" -> "https://github.com/user/repo"
    /// - "https://github.com/user/repo" -> "https://github.com/user/repo" (unchanged)
    /// - "user/repo" -> "https://github.com/user/repo"
    /// - "git@github.com:user/repo.git" -> "https://github.com/user/repo"
    /// - "ssh://git@github.com/user/repo" -> "https://github.com/user/repo"
    pub fn normalize(mut self) -> Self {
        match &mut self {
            CodeSource::GitHub { repo, .. } => {
                // Skip if already has https/http protocol
                if repo.starts_with("https://") || repo.starts_with("http://") {
                    return self;
                }

                // Handle SSH format: git@github.com:user/repo.git
                if repo.starts_with("git@github.com:") {
                    let path = repo.strip_prefix("git@github.com:").unwrap();
                    let path = path.strip_suffix(".git").unwrap_or(path);
                    *repo = format!("https://github.com/{}", path);
                    return self;
                }

                // Handle SSH URL format: ssh://git@github.com/user/repo
                if repo.starts_with("ssh://git@github.com/") {
                    let path = repo.strip_prefix("ssh://git@github.com/").unwrap();
                    let path = path.strip_suffix(".git").unwrap_or(path);
                    *repo = format!("https://github.com/{}", path);
                    return self;
                }

                // Handle ssh:// without git@ prefix
                if repo.starts_with("ssh://") {
                    // Leave as is, will fail later with better error
                    return self;
                }

                // Add https:// prefix
                if repo.starts_with("github.com/") {
                    *repo = format!("https://{}", repo);
                } else if !repo.contains('/') {
                    // Invalid format - leave as is, will fail later with better error
                    return self;
                } else {
                    // Assume it's "user/repo" format
                    *repo = format!("https://github.com/{}", repo);
                }

                self
            }
            CodeSource::WasmUrl { .. } => {
                // WasmUrl already has full URL, no normalization needed
                self
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub max_instructions: u64,
    pub max_memory_mb: u32,
    pub max_execution_seconds: u64,
}

/// Parameters for creating a new task in coordinator
#[derive(Debug, Clone)]
pub struct CreateTaskParams {
    pub request_id: u64,
    pub data_id: String,
    pub code_source: CodeSource,
    pub resource_limits: ResourceLimits,
    pub input_data: String,
    pub secrets_ref: Option<SecretsReference>,
    pub response_format: ResponseFormat,
    pub context: ExecutionContext,
    pub user_account_id: Option<String>,
    pub near_payment_yocto: Option<String>,
    /// Payment to project developer (stablecoin, minimal token units)
    pub attached_usd: Option<String>,
    pub compile_only: bool,
    pub force_rebuild: bool,
    pub store_on_fastfs: bool,
    /// Agent Connect: the on-chain caller asked to be seen as its bound
    /// account. A CLAIM, settled against the chain in the TEE before the guest
    /// is given any name.
    pub use_bound_identity: bool,
    /// Project UUID for persistent storage (from request_execution_project)
    pub project_uuid: Option<String>,
    /// Project ID for project-based secrets (e.g., "alice.near/my-app")
    pub project_id: Option<String>,
}

/// Execution output - can be bytes, text, or parsed JSON
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExecutionOutput {
    Bytes(Vec<u8>),
    Text(String),
    Json(serde_json::Value),
}

/// Project UUID info from coordinator
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectUuidInfo {
    pub project_id: String,
    pub uuid: String,
    pub active_version: String,
    pub cached: bool,
}

/// Execution result to send back to coordinator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub success: bool,
    pub output: Option<ExecutionOutput>,
    pub error: Option<String>,
    pub execution_time_ms: u64,
    pub instructions: u64,
    pub compile_time_ms: Option<u64>, // Compilation time if WASM was compiled in this execution
    pub compilation_note: Option<String>, // e.g., "Cached WASM from 2025-01-10 14:30 UTC"
    /// Refund amount to return to user from attached_usd (stablecoin, minimal token units)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refund_usd: Option<u64>,
}

/// Job type - compile or execute
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JobType {
    Compile,
    Execute,
}

/// Job information returned by claim_job
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobInfo {
    pub job_id: i64,
    pub job_type: JobType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wasm_checksum: Option<String>,
    pub allowed: bool,
    /// Compilation cost from compile job (for execute jobs to include in total cost)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compile_cost_yocto: Option<String>,
    /// Compilation error message (for execute jobs to report failure to contract)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compile_error: Option<String>,
    /// Compilation time in milliseconds from compile job
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compile_time_ms: Option<u64>,
    /// Project UUID for persistent storage (None for standalone WASM)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_uuid: Option<String>,
    /// Project ID for project-based secrets (e.g., "alice.near/my-app")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    /// Job creation timestamp (unix seconds) - used for attestation V1 format
    #[serde(default)]
    pub created_at: i64,
}

/// Pricing configuration from coordinator (fetched from NEAR contract)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PricingConfig {
    pub base_fee: String,                // yoctoNEAR
    pub per_instruction_fee: String,     // yoctoNEAR per million instructions
    pub per_ms_fee: String,              // yoctoNEAR per millisecond (execution)
    pub per_compile_ms_fee: String,      // yoctoNEAR per millisecond (compilation)
    pub max_compilation_seconds: u64,    // Maximum compilation time
}

/// Response from claim_job endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimJobResponse {
    pub jobs: Vec<JobInfo>,
    pub pricing: PricingConfig,
}


/// The coordinator has answered, and its answer will not change.
///
/// Marks a relay the worker must stop retrying: a 4xx is a decision, not an
/// outage. Retrying one forever would wedge the event monitor on a single
/// unacceptable event and stop every other block from being scanned.
///
/// Everything else is transient by default, which is the safe direction — a
/// relay retried once too often costs a request, a relay dropped once too early
/// costs a customer the subscription they paid for on chain.
#[derive(Debug)]
pub struct TerminalRelay;

impl std::fmt::Display for TerminalRelay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the coordinator refused this relay outright")
    }
}

impl std::error::Error for TerminalRelay {}

impl TerminalRelay {
    /// Is this failure one that retrying cannot fix?
    pub fn is_terminal(error: &anyhow::Error) -> bool {
        error.downcast_ref::<TerminalRelay>().is_some()
    }
}

/// The pauses between the attempts [`retry_relay`] makes: eight attempts
/// within about a hundred seconds, enough to ride out a coordinator redeploy
/// or a 503 while it cannot yet read the contract.
pub const RELAY_RETRY_DELAYS: [Duration; 7] = [
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
    Duration::from_secs(16),
    Duration::from_secs(32),
    Duration::from_secs(32),
];

/// How long one attempt of an event relay [`retry_relay`] repeats may take:
/// with the pauses, a coordinator that hangs holds the scan three minutes at
/// most.
pub const RELAY_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10);

/// Run `relay` until it succeeds or fails with a [`TerminalRelay`], pausing
/// `delays[i]` after the `i`-th failure; the error of the last attempt is
/// returned once the delays run out. `what` names the relay in the log line
/// each retry writes.
pub async fn retry_relay<T, F, Fut>(what: &str, delays: &[Duration], mut relay: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let mut delays = delays.iter();
    loop {
        match relay().await {
            Ok(value) => return Ok(value),
            Err(e) if TerminalRelay::is_terminal(&e) => return Err(e),
            Err(e) => match delays.next() {
                Some(delay) => {
                    tracing::warn!("{} failed, retrying in {:?}: {:#}", what, delay, e);
                    tokio::time::sleep(*delay).await;
                }
                None => return Err(e),
            },
        }
    }
}

/// `GET /wasm/exists/{checksum}`: whether the coordinator has the artefact,
/// when it was first stored, and the sha256 of the bytes it holds now.
#[derive(Debug, Clone, Deserialize)]
pub struct WasmMeta {
    pub exists: bool,
    pub created_at: Option<String>,
    #[serde(default)]
    pub content_hash: Option<String>,
}

/// API client for communicating with Coordinator API
#[derive(Clone)]
pub struct ApiClient {
    client: Client,
    base_url: String,
    auth_token: String,
    /// TEE session ID (set after successful TEE registration)
    tee_session_id: std::sync::Arc<std::sync::Mutex<Option<String>>>,
    /// Per-attempt timeout of the event relays [`retry_relay`] repeats.
    relay_timeout: Duration,
}

impl ApiClient {
    /// Create a new API client
    pub fn new(base_url: String, auth_token: String) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(120)) // 2 minutes default timeout
            .connect_timeout(Duration::from_secs(10)) // Fast fail on connection issues
            .tcp_keepalive(Duration::from_secs(30)) // Detect dead connections
            .pool_idle_timeout(Duration::from_secs(60)) // Don't reuse stale connections
            .build()
            .context("Failed to build HTTP client")?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            auth_token,
            tee_session_id: std::sync::Arc::new(std::sync::Mutex::new(None)),
            relay_timeout: RELAY_ATTEMPT_TIMEOUT,
        })
    }

    #[cfg(test)]
    fn with_relay_timeout(mut self, timeout: Duration) -> Self {
        self.relay_timeout = timeout;
        self
    }

    /// Add standard auth headers (bearer token + optional TEE session)
    fn add_auth_headers(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        let builder = builder.bearer_auth(&self.auth_token);
        if let Some(session_id) = self.tee_session_id.lock().unwrap().as_ref() {
            builder.header("X-TEE-Session", session_id)
        } else {
            builder
        }
    }

    /// Add wallet internal auth header (X-Internal-Wallet-Auth) for /internal/wallet-* endpoints.
    /// These endpoints use a different auth scheme than the standard Bearer token.
    fn add_wallet_internal_auth(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        builder.header("X-Internal-Wallet-Auth", &self.auth_token)
    }

    /// Perform a challenge-response TEE registration against the given endpoint path prefix.
    ///
    /// 1. POST {base_url}/{path_prefix}/tee-challenge → get challenge
    /// 2. Sign challenge with ed25519 key
    /// 3. POST {base_url}/{path_prefix}/register-tee → get session_id
    async fn do_tee_challenge_response(
        &self,
        path_prefix: &str,
        secret_key: &near_crypto::SecretKey,
    ) -> Result<String> {
        // NEAR canonical form encodes the scheme (ed25519 / ml-dsa-65) in the prefix, so the
        // server learns how we signed without a side channel.
        let near_public_key = secret_key.public_key().to_string();

        // 1. Request challenge
        let url = format!("{}/{}/tee-challenge", self.base_url, path_prefix);
        let response = self.add_auth_headers(self.client.post(&url))
            .send()
            .await
            .with_context(|| format!("Failed to request TEE challenge from {}", path_prefix))?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("{} TEE challenge failed ({}): {}", path_prefix, status, text);
        }

        #[derive(Deserialize)]
        struct ChallengeResponse {
            challenge: String,
        }
        let challenge_resp: ChallengeResponse = response.json().await
            .with_context(|| format!("Failed to parse {} TEE challenge", path_prefix))?;

        // 2. Sign challenge with TEE key (ed25519 or ml-dsa-65), send signature in NEAR form.
        let challenge_bytes = hex::decode(&challenge_resp.challenge)
            .context("Invalid challenge hex")?;
        let signature = secret_key.sign(&challenge_bytes).to_string();

        // 3. Submit registration
        let url = format!("{}/{}/register-tee", self.base_url, path_prefix);
        let response = self.add_auth_headers(self.client.post(&url))
            .json(&serde_json::json!({
                "public_key": near_public_key,
                "challenge": challenge_resp.challenge,
                "signature": signature,
            }))
            .send()
            .await
            .with_context(|| format!("Failed to submit {} TEE registration", path_prefix))?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("{} TEE registration failed ({}): {}", path_prefix, status, text);
        }

        #[derive(Deserialize)]
        struct RegisterResponse {
            session_id: String,
        }
        let register_resp: RegisterResponse = response.json().await
            .with_context(|| format!("Failed to parse {} TEE registration response", path_prefix))?;

        Ok(register_resp.session_id)
    }

    /// Register a TEE session with the coordinator via challenge-response.
    /// Stores the session ID so all subsequent requests include X-TEE-Session.
    pub async fn register_tee_session(
        &self,
        secret_key: &near_crypto::SecretKey,
    ) -> Result<String> {
        let session_id = self.do_tee_challenge_response("workers", secret_key).await?;
        *self.tee_session_id.lock().unwrap() = Some(session_id.clone());
        tracing::info!("TEE session registered with coordinator: {}", session_id);
        Ok(session_id)
    }

    /// Poll for a new execution request (long-polling)
    ///
    /// # Arguments
    /// * `timeout` - Timeout in seconds for long-polling (max 60)
    /// * `capabilities` - Worker capabilities (e.g., ["compilation", "execution"])
    ///
    /// # Returns
    /// * `Ok(Some(request))` - New execution request received
    /// * `Ok(None)` - No request available (timeout reached)
    /// * `Err(_)` - Request failed
    pub async fn poll_task(
        &self,
        timeout: u64,
        capabilities: &[String],
        excludes: &[String],
    ) -> Result<Option<ExecutionRequest>> {
        // Build URL with query parameters
        let capabilities_param = capabilities.join(",");
        // Routes this node will not run. Sent on every poll so the coordinator
        // can hand them to another worker; an empty list is the ordinary path
        // and leaves the coordinator's blocking pop untouched.
        let excludes_param = if excludes.is_empty() {
            String::new()
        } else {
            format!("&excludes={}", urlencoding::encode(&excludes.join(",")))
        };
        let url = format!(
            "{}/executions/poll?timeout={}&capabilities={}{}",
            self.base_url, timeout, capabilities_param, excludes_param
        );

        tracing::debug!("🔍 Polling for execution request: {}", url);

        // Use a fresh HTTP client for poll to avoid stale TCP connections.
        // Poll is long-lived (60s BRPOP) and reusing pooled connections
        // can cause hangs when the coordinator restarts.
        let poll_client = Client::builder()
            .timeout(Duration::from_secs(timeout + 10))
            .connect_timeout(Duration::from_secs(10))
            .pool_max_idle_per_host(0) // No connection reuse
            .build()
            .context("Failed to build poll HTTP client")?;

        let response = self.add_auth_headers(
            poll_client
                .get(&url),
            )
            .send()
            .await
            .context("Failed to send poll request")?;

        tracing::debug!("📡 Poll response status: {}", response.status());

        match response.status() {
            StatusCode::OK => {
                let body_text = response.text().await?;
                tracing::debug!("📦 Poll response body: {}", body_text);
                let request: ExecutionRequest = serde_json::from_str(&body_text)
                    .context(format!("Failed to parse execution request JSON: {}", body_text))?;
                Ok(Some(request))
            }
            StatusCode::NO_CONTENT => Ok(None), // No request available
            status => {
                let error_text = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "Unknown error".to_string());
                tracing::error!("❌ Poll failed with status {}: {}", status, error_text);
                anyhow::bail!("Poll failed with status {}: {}", status, error_text)
            }
        }
    }

    /// Complete a task with result
    ///
    /// # Arguments
    /// * `request_id` - ID of the execution request
    /// * `data_id` - Data ID from blockchain
    /// * `result` - Execution result (success/failure, output, timing)
    /// * `resolve_tx_id` - Transaction ID of resolve_execution call
    /// * `user_account_id` - User who requested execution
    /// * `near_payment_yocto` - Payment amount in yoctoNEAR
    /// * `worker_id` - This worker's ID
    #[allow(dead_code)]
    pub async fn complete_task(
        &self,
        request_id: u64,
        data_id: Option<String>,
        result: ExecutionResult,
        resolve_tx_id: Option<String>,
        user_account_id: Option<String>,
        near_payment_yocto: Option<String>,
        worker_id: String,
        github_repo: Option<String>,
        github_commit: Option<String>,
    ) -> Result<()> {
        let url = format!("{}/tasks/complete", self.base_url);

        #[derive(Serialize)]
        struct CompleteRequest {
            request_id: u64,
            success: bool,
            output: Option<ExecutionOutput>,
            error: Option<String>,
            execution_time_ms: u64,
            instructions: u64,
            data_id: Option<String>,
            resolve_tx_id: Option<String>,
            user_account_id: Option<String>,
            near_payment_yocto: Option<String>,
            worker_id: Option<String>,
            github_repo: Option<String>,
            github_commit: Option<String>,
        }

        let request = CompleteRequest {
            request_id,
            success: result.success,
            output: result.output.clone(),
            error: result.error,
            execution_time_ms: result.execution_time_ms,
            instructions: result.instructions,
            data_id,
            resolve_tx_id,
            user_account_id,
            near_payment_yocto,
            worker_id: Some(worker_id),
            github_repo,
            github_commit,
        };

        let response = self.add_auth_headers(self.client.post(&url))
            .json(&request)
            .send()
            .await
            .context("Failed to send complete request")?;

        if !response.status().is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            anyhow::bail!("Complete task failed: {}", error_text)
        }

        Ok(())
    }

    /// Mark a task as failed
    ///
    /// # Arguments
    /// * `request_id` - ID of the execution request
    /// * `error` - Error message describing the failure
    #[allow(dead_code)]
    pub async fn fail_task(&self, request_id: u64, error: String) -> Result<()> {
        let url = format!("{}/tasks/fail", self.base_url);

        #[derive(Serialize)]
        struct FailRequest {
            request_id: u64,
            error: String,
        }

        let request = FailRequest { request_id, error };

        let response = self.add_auth_headers(self.client.post(&url))
            .json(&request)
            .send()
            .await
            .context("Failed to send fail request")?;

        if !response.status().is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            anyhow::bail!("Fail task failed: {}", error_text)
        }

        Ok(())
    }

    /// Claim job(s) for a task
    ///
    /// # Arguments
    /// * `request_id` - Request ID from contract
    /// * `data_id` - Data ID from contract event
    /// * `worker_id` - This worker's ID
    /// * `code_source` - Code source details
    /// * `resource_limits` - Resource limits for execution
    /// * `user_account_id` - Optional user account ID from contract
    /// * `near_payment_yocto` - Optional payment amount from contract
    /// * `transaction_hash` - Optional transaction hash from contract
    ///
    /// # Returns
    /// * `Ok(jobs)` - Array of jobs to process (compile and/or execute)
    /// * `Err(_)` - Request failed or task already claimed
    pub async fn claim_job(
        &self,
        request_id: u64,
        data_id: String,
        worker_id: String,
        code_source: &CodeSource,
        resource_limits: &ResourceLimits,
        user_account_id: Option<String>,
        near_payment_yocto: Option<String>,
        transaction_hash: Option<String>,
        capabilities: Vec<String>,
        compile_only: bool,
        force_rebuild: bool,
        has_compile_result: bool,
        project_uuid: Option<String>,
        project_id: Option<String>,
    ) -> Result<ClaimJobResponse> {
        let url = format!("{}/jobs/claim", self.base_url);

        #[derive(Serialize)]
        struct ClaimRequest {
            request_id: u64,
            data_id: String,
            worker_id: String,
            code_source: CodeSource,
            resource_limits: ResourceLimits,
            #[serde(skip_serializing_if = "Option::is_none")]
            user_account_id: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            near_payment_yocto: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            transaction_hash: Option<String>,
            capabilities: Vec<String>,
            compile_only: bool,
            force_rebuild: bool,
            has_compile_result: bool,
            #[serde(skip_serializing_if = "Option::is_none")]
            project_uuid: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            project_id: Option<String>,
        }

        let request = ClaimRequest {
            request_id,
            data_id,
            worker_id,
            code_source: code_source.clone(),
            resource_limits: resource_limits.clone(),
            user_account_id,
            near_payment_yocto,
            transaction_hash,
            capabilities,
            compile_only,
            force_rebuild,
            has_compile_result,
            project_uuid,
            project_id,
        };

        tracing::debug!("🎯 Claiming job for request_id={}", request_id);

        let response = self.add_auth_headers(self.client.post(&url))
            .json(&request)
            .send()
            .await
            .context("Failed to send claim job request")?;

        match response.status() {
            StatusCode::OK => {
                let claim_response: ClaimJobResponse = response
                    .json()
                    .await
                    .context("Failed to parse claim job response")?;
                tracing::info!(
                    "✅ Claimed {} job(s) for request_id={}",
                    claim_response.jobs.len(),
                    request_id
                );
                Ok(claim_response)
            }
            StatusCode::CONFLICT => {
                anyhow::bail!("Task already claimed by another worker")
            }
            status => {
                let error_text = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "Unknown error".to_string());
                tracing::error!("❌ Claim job failed with status {}: {}", status, error_text);
                anyhow::bail!("Claim job failed with status {}: {}", status, error_text)
            }
        }
    }

    /// Complete a job with result
    ///
    /// # Arguments
    /// * `job_id` - Job ID from coordinator
    /// * `success` - Whether job succeeded
    /// * `output` - Execution output (for execute jobs)
    /// * `error` - Error message (if failed)
    /// * `time_ms` - Time taken in milliseconds
    /// * `instructions` - Instructions consumed (for execute jobs, 0 for compile)
    /// * `wasm_checksum` - WASM checksum (for compile jobs)
    /// * `actual_cost_yocto` - Total cost from contract (for execute jobs)
    /// * `compile_cost_yocto` - Compilation cost calculated by worker (for compile jobs)
    /// * `compile_result` - Result to pass to executor (e.g., FastFS URL)
    ///
    /// Reports no refund. Compile jobs and every failure path have none to
    /// report; the execute paths that do call [`Self::complete_job_with_refund`].
    #[allow(clippy::too_many_arguments)]
    pub async fn complete_job(
        &self,
        job_id: i64,
        success: bool,
        output: Option<ExecutionOutput>,
        error: Option<String>,
        time_ms: u64,
        instructions: u64,
        wasm_checksum: Option<String>,
        actual_cost_yocto: Option<String>,
        compile_cost_yocto: Option<String>,
        error_category: Option<JobStatus>,
        compile_result: Option<String>,
    ) -> Result<()> {
        self.complete_job_with_refund(
            job_id,
            success,
            output,
            error,
            time_ms,
            instructions,
            wasm_checksum,
            actual_cost_yocto,
            compile_cost_yocto,
            error_category,
            compile_result,
            None,
        )
        .await
    }

    /// [`Self::complete_job`] plus the refund the guest asked for.
    ///
    /// The coordinator computes the author's share as
    /// `attached_usd - refund_usd` for `earnings_history`. Without this the
    /// refund reads as zero there and the ledger credits the author with money
    /// the caller got back — the CHAIN settles correctly either way, because
    /// `resolve_execution` carries the refund of its own accord, so the defect
    /// is silent and shows up only as a wrong number on the earnings page.
    ///
    /// A separate entry point rather than a twelfth argument on a function
    /// already called from two dozen places: the refund exists on exactly the
    /// execute paths that have an `ExecutionResult` in hand, and threading
    /// `None` through the rest would be two dozen chances to put it in the
    /// wrong position.
    #[allow(clippy::too_many_arguments)]
    pub async fn complete_job_with_refund(
        &self,
        job_id: i64,
        success: bool,
        output: Option<ExecutionOutput>,
        error: Option<String>,
        time_ms: u64,
        instructions: u64,
        wasm_checksum: Option<String>,
        actual_cost_yocto: Option<String>,
        compile_cost_yocto: Option<String>,
        error_category: Option<JobStatus>,
        compile_result: Option<String>,
        refund_usd: Option<u64>,
    ) -> Result<()> {
        let url = format!("{}/jobs/complete", self.base_url);

        #[derive(Serialize)]
        struct CompleteJobRequest {
            job_id: i64,
            success: bool,
            output: Option<ExecutionOutput>,
            error: Option<String>,
            time_ms: u64,
            instructions: u64,
            wasm_checksum: Option<String>,
            actual_cost_yocto: Option<String>,
            compile_cost_yocto: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            error_category: Option<JobStatus>,
            #[serde(skip_serializing_if = "Option::is_none")]
            compile_result: Option<String>,
            /// Stringified: the coordinator parses it as a decimal string, the
            /// same shape `attached_usd` arrives in.
            #[serde(skip_serializing_if = "Option::is_none")]
            refund_usd: Option<String>,
        }

        let request = CompleteJobRequest {
            job_id,
            success,
            output,
            error: error.clone(),
            time_ms,
            instructions,
            wasm_checksum,
            actual_cost_yocto,
            compile_cost_yocto,
            error_category,
            compile_result,
            refund_usd: refund_usd.map(|v| v.to_string()),
        };

        tracing::debug!(
            "📤 Completing job_id={} success={} time_ms={}",
            job_id,
            success,
            time_ms
        );

        let response = self.add_auth_headers(self.client.post(&url))
            .json(&request)
            .send()
            .await
            .context("Failed to send complete job request")?;

        if !response.status().is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            tracing::error!("❌ Complete job failed: {}", error_text);
            anyhow::bail!("Complete job failed: {}", error_text)
        }

        tracing::info!("✅ Job {} completed successfully", job_id);
        Ok(())
    }

    /// Complete an HTTPS API call (without NEAR contract interaction)
    ///
    /// Used for HTTPS /call endpoint where results go directly to coordinator
    /// instead of being submitted to the NEAR contract.
    ///
    /// # Arguments
    /// * `call_id` - UUID of the HTTPS call
    /// * `success` - Whether execution succeeded
    /// * `output` - Execution output (JSON)
    /// * `error` - Error message (if failed)
    /// * `instructions` - Instructions consumed
    /// * `time_ms` - Execution time in milliseconds
    /// * `job_id` - Job ID for attestation linking
    pub async fn complete_https_call(
        &self,
        call_id: &str,
        success: bool,
        output: Option<serde_json::Value>,
        error: Option<String>,
        instructions: u64,
        time_ms: u64,
        job_id: Option<i64>,
    ) -> Result<()> {
        let url = format!("{}/https-calls/complete", self.base_url);

        #[derive(Serialize)]
        struct CompleteHttpsCallRequest {
            call_id: String,
            success: bool,
            #[serde(skip_serializing_if = "Option::is_none")]
            output: Option<serde_json::Value>,
            #[serde(skip_serializing_if = "Option::is_none")]
            error: Option<String>,
            instructions: u64,
            time_ms: u64,
            #[serde(skip_serializing_if = "Option::is_none")]
            job_id: Option<i64>,
        }

        let request = CompleteHttpsCallRequest {
            call_id: call_id.to_string(),
            success,
            output,
            error: error.clone(),
            instructions,
            time_ms,
            job_id,
        };

        tracing::info!(
            "📤 Completing HTTPS call: call_id={} success={} instructions={} time_ms={}",
            call_id, success, instructions, time_ms
        );

        let response = self.add_auth_headers(self.client.post(&url))
            .json(&request)
            .send()
            .await
            .context("Failed to send complete HTTPS call request")?;

        if !response.status().is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            tracing::error!("❌ Complete HTTPS call failed: {}", error_text);
            anyhow::bail!("Complete HTTPS call failed: {}", error_text)
        }

        tracing::info!("✅ HTTPS call {} completed successfully", call_id);
        Ok(())
    }

    /// Store system logs (compilation/execution) for admin debugging
    /// This endpoint does NOT require authentication (internal endpoint)
    ///
    /// # Arguments
    /// * `request_id` - Execution request ID
    /// * `job_id` - Job ID (optional)
    /// * `log_type` - "compilation" or "execution"
    /// * `stderr` - Raw stderr output
    /// * `stdout` - Raw stdout output
    /// * `exit_code` - Exit code from process
    /// * `execution_error` - WASM execution error (optional)
    pub async fn store_system_log(
        &self,
        request_id: u64,
        job_id: Option<i64>,
        log_type: &str,
        stderr: Option<String>,
        stdout: Option<String>,
        exit_code: Option<i32>,
        execution_error: Option<String>,
    ) -> Result<()> {
        let url = format!("{}/internal/system-logs", self.base_url);

        let payload = serde_json::json!({
            "request_id": request_id,
            "job_id": job_id,
            "log_type": log_type,
            "stderr": stderr,
            "stdout": stdout,
            "exit_code": exit_code,
            "execution_error": execution_error,
        });

        let response = self
            .client
            .post(&url)
            .json(&payload)
            .send()
            .await
            .context("Failed to store system log")?;

        if !response.status().is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            tracing::warn!("⚠️ Failed to store system log: {}", error_text);
            // Don't fail the job if logging fails - just warn
            return Ok(());
        }

        tracing::debug!("📝 Stored system log ({}) for request_id={}", log_type, request_id);
        Ok(())
    }

    /// Download WASM binary from cache
    ///
    /// # Arguments
    /// * `checksum` - SHA256 checksum of the WASM file
    ///
    /// # Returns
    /// * `Ok(bytes)` - WASM binary data
    /// * `Err(_)` - Download failed or file not found
    pub async fn download_wasm(&self, checksum: &str) -> Result<Vec<u8>> {
        let url = format!("{}/wasm/{}", self.base_url, checksum);

        let response = self.add_auth_headers(self.client.get(&url))
            .send()
            .await
            .context("Failed to download WASM")?;

        if response.status() == StatusCode::NOT_FOUND {
            anyhow::bail!("WASM file not found: {}", checksum)
        }

        if !response.status().is_success() {
            anyhow::bail!("Download failed with status: {}", response.status())
        }

        let bytes = response
            .bytes()
            .await
            .context("Failed to read WASM bytes")?
            .to_vec();

        Ok(bytes)
    }

    /// Upload compiled WASM binary to cache
    ///
    /// # Arguments
    /// * `checksum` - SHA256 checksum of the WASM file
    /// * `repo` - GitHub repository URL
    /// * `commit` - Git commit hash
    /// * `build_target` - Build target (e.g., wasm32-wasip1, wasm32-wasip2)
    /// * `bytes` - WASM binary data
    pub async fn upload_wasm(
        &self,
        checksum: String,
        repo: String,
        commit: String,
        build_target: String,
        bytes: Vec<u8>,
    ) -> Result<()> {
        let url = format!("{}/wasm/upload", self.base_url);

        // Create multipart form with correct field names (matching coordinator's handler)
        let file_part = reqwest::multipart::Part::bytes(bytes.clone())
            .file_name(format!("{}.wasm", checksum))
            .mime_str("application/wasm")
            .context("Failed to create file part")?;

        let form = reqwest::multipart::Form::new()
            .text("checksum", checksum.clone())
            .text("repo_url", repo.clone())         // coordinator expects "repo_url"
            .text("commit_hash", commit.clone())    // coordinator expects "commit_hash"
            .text("build_target", build_target.clone()) // coordinator expects "build_target"
            .part("wasm_file", file_part);          // coordinator expects "wasm_file"

        tracing::info!(
            "Uploading WASM: checksum={} size={} bytes repo={} commit={} target={}",
            checksum, bytes.len(), repo, commit, build_target
        );

        let response = self.add_auth_headers(self.client.post(&url))
            .multipart(form)
            .send()
            .await
            .context("Failed to upload WASM")?;

        if !response.status().is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            anyhow::bail!("Upload failed: {}", error_text)
        }

        Ok(())
    }

    /// Check if WASM file exists in cache
    ///
    /// # Arguments
    /// * `checksum` - SHA256 checksum of the WASM file
    ///
    /// # Returns
    /// * `Ok((exists, created_at))` - Whether file exists and optional creation timestamp
    pub async fn wasm_exists(&self, checksum: &str) -> Result<(bool, Option<String>)> {
        let meta = self.wasm_meta(checksum).await?;
        Ok((meta.exists, meta.created_at))
    }

    /// What the coordinator holds under `checksum` right now.
    ///
    /// `content_hash` is the sha256 of the stored bytes. The checksum is a
    /// cache key — for a GitHub build a hash of the source coordinates, kept
    /// across rebuilds of the same commit — so this hash, not the checksum,
    /// is what identifies the current build. Absent when the coordinator does
    /// not report one.
    pub async fn wasm_meta(&self, checksum: &str) -> Result<WasmMeta> {
        let url = format!("{}/wasm/exists/{}", self.base_url, checksum);

        let response = self.add_auth_headers(self.client.get(&url))
            .send()
            .await
            .context("Failed to check WASM existence")?;

        if !response.status().is_success() {
            anyhow::bail!("Check failed with status: {}", response.status())
        }

        response
            .json::<WasmMeta>()
            .await
            .context("Failed to parse exists response")
    }

    /// Acquire a distributed lock
    ///
    /// # Arguments
    /// * `lock_key` - Unique key for the lock (e.g., "compile:{repo}:{commit}")
    /// * `worker_id` - ID of this worker
    /// * `ttl` - Time-to-live in seconds
    ///
    /// # Returns
    /// * `Ok(true)` - Lock acquired
    /// * `Ok(false)` - Lock already held by another worker
    pub async fn acquire_lock(&self, lock_key: String, worker_id: String, ttl: u64) -> Result<bool> {
        let url = format!("{}/locks/acquire", self.base_url);

        #[derive(Serialize)]
        struct AcquireRequest {
            lock_key: String,
            worker_id: String,
            ttl_seconds: u64,
        }

        let request = AcquireRequest {
            lock_key,
            worker_id,
            ttl_seconds: ttl,
        };

        let response = self.add_auth_headers(self.client.post(&url))
            .json(&request)
            .send()
            .await
            .context("Failed to acquire lock")?;

        if !response.status().is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            anyhow::bail!("Lock acquire failed: {}", error_text)
        }

        #[derive(Deserialize)]
        struct AcquireResponse {
            acquired: bool,
        }

        let result = response
            .json::<AcquireResponse>()
            .await
            .context("Failed to parse lock response")?;

        Ok(result.acquired)
    }

    /// Release a distributed lock
    ///
    /// # Arguments
    /// * `lock_key` - Key of the lock to release
    pub async fn release_lock(&self, lock_key: &str) -> Result<()> {
        // URL-encode the lock key to handle special characters like : and /
        let encoded_key = urlencoding::encode(lock_key);
        let url = format!("{}/locks/release/{}", self.base_url, encoded_key);

        let response = self.add_auth_headers(self.client.delete(&url))
            .send()
            .await
            .context("Failed to release lock")?;

        if !response.status().is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            anyhow::bail!("Lock release failed: {}", error_text)
        }

        Ok(())
    }

    /// Create a new execution request (used by event monitor)
    ///
    /// # Arguments
    /// * `request_id` - Execution request ID from contract
    /// * `data_id` - Input data identifier (hex string)
    /// * `repo` - GitHub repository URL
    /// * `commit` - Git commit hash
    /// * `max_instructions` - Maximum WASM instructions
    /// * `max_memory_mb` - Maximum memory in MB
    /// * `max_execution_seconds` - Maximum execution time
    /// * `input_data` - Input data JSON string
    /// * `secrets_ref` - Optional reference to secrets stored in contract
    /// * `context` - Execution context (includes transaction_hash from neardata)
    /// * `user_account_id` - User who requested execution
    /// * `near_payment_yocto` - Payment amount in yoctoNEAR
    ///
    /// Returns `Ok(Some(request_id))` if request was created, `Ok(None)` if duplicate
    pub async fn create_task(&self, params: CreateTaskParams) -> Result<Option<u64>> {
        let url = format!("{}/executions/create", self.base_url);

        #[derive(Serialize)]
        struct CreateRequest {
            request_id: u64,
            data_id: String,
            code_source: CodeSource,
            resource_limits: ResourceLimits,
            input_data: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            secrets_ref: Option<SecretsReference>,
            response_format: ResponseFormat,
            context: ExecutionContext,
            #[serde(skip_serializing_if = "Option::is_none")]
            user_account_id: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            near_payment_yocto: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            attached_usd: Option<String>,
            compile_only: bool,
            force_rebuild: bool,
            store_on_fastfs: bool,
            /// Sent unconditionally, NOT skipped when false. The coordinator
            /// reads it with `#[serde(default)]`, so an omitted field and an
            /// explicit `false` are the same to it — but only one of them keeps
            /// this body a faithful record of what the chain asked for.
            use_bound_identity: bool,
            #[serde(skip_serializing_if = "Option::is_none")]
            project_uuid: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            project_id: Option<String>,
        }

        #[derive(Deserialize)]
        struct CreateResponse {
            request_id: i64,
            created: bool,
        }

        let request = CreateRequest {
            request_id: params.request_id,
            data_id: params.data_id,
            code_source: params.code_source,
            resource_limits: params.resource_limits,
            input_data: params.input_data,
            secrets_ref: params.secrets_ref,
            response_format: params.response_format,
            context: params.context,
            user_account_id: params.user_account_id,
            near_payment_yocto: params.near_payment_yocto,
            attached_usd: params.attached_usd,
            compile_only: params.compile_only,
            force_rebuild: params.force_rebuild,
            store_on_fastfs: params.store_on_fastfs,
            use_bound_identity: params.use_bound_identity,
            project_uuid: params.project_uuid,
            project_id: params.project_id,
        };

        let response = self.add_auth_headers(self.client.post(&url))
            .json(&request)
            .send()
            .await
            .context("Failed to create task")?;

        if !response.status().is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            anyhow::bail!("Create task failed: {}", error_text)
        }

        let create_response: CreateResponse = response.json().await.context("Failed to parse create task response")?;

        if create_response.created {
            Ok(Some(create_response.request_id as u64))
        } else {
            Ok(None)
        }
    }

    /// Initialize a Payment Key in coordinator (amount=0 creation event)
    ///
    /// Called when store_secrets creates a PaymentKey (TopUp event with amount=0).
    /// Creates a record in payment_keys with initial_balance=0.
    /// Key cannot be used until real TopUp or admin grant.
    ///
    /// # Arguments
    /// * `owner` - Payment Key owner (NEAR account)
    /// * `nonce` - Payment Key nonce
    /// * `key_hash` - SHA256 hash of the key (hex encoded) for validation
    /// * `project_ids` - List of allowed project IDs (empty = all projects)
    /// * `max_per_call` - Max amount per API call (optional)
    /// * `agent` - the agent binding read out of the decrypted blob (§A1).
    ///   All-default for an ordinary key, which is what every older blob
    ///   produces.
    pub async fn init_payment_key(
        &self,
        owner: &str,
        nonce: u32,
        key_hash: &str,
        project_ids: &[String],
        max_per_call: Option<&str>,
    ) -> Result<()> {
        let url = format!("{}/payment-keys/init", self.base_url);

        /// Nothing here says whether the key is an agent's: `key_hash` already
        /// does. A blob with no `key` in it has nothing to hash, so the hash is
        /// the owner's own account, and the coordinator generates
        /// `payment_keys.is_agent` from precisely that.
        ///
        /// A `target` field used to travel here for the same purpose. The
        /// allowance and its expiry never did and never may: a blob is written
        /// by the key's owner, so an allowance read out of one would be an
        /// allowance anyone could mint for themselves.
        #[derive(Serialize)]
        struct InitPaymentKeyRequest {
            owner: String,
            nonce: u32,
            key_hash: String,
            project_ids: Vec<String>,
            max_per_call: Option<String>,
        }

        let request = InitPaymentKeyRequest {
            owner: owner.to_string(),
            nonce,
            key_hash: key_hash.to_string(),
            project_ids: project_ids.to_vec(),
            max_per_call: max_per_call.map(String::from),
        };

        let response = self.add_auth_headers(self.client.post(&url))
            .json(&request)
            .send()
            .await
            .context("Failed to init payment key")?;

        if !response.status().is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            anyhow::bail!("Init payment key failed: {}", error_text)
        }

        tracing::info!(
            owner = owner,
            nonce = nonce,
            key_hash_prefix = &key_hash[..8.min(key_hash.len())],
            "Payment key initialized in coordinator"
        );

        Ok(())
    }

    /// Submit the outbound-request audit for one execution (§C3).
    ///
    /// Records what the guest attempted to reach and whether the project's
    /// manifest allowlist permitted it. Produced inside the TEE and submitted
    /// under this worker's authenticated session, so the trail is a report by
    /// an attested component rather than a coordinator-side claim.
    ///
    /// Only the HOST is recorded, never the path or query — those routinely
    /// carry tokens and recipient addresses, and an audit trail must not become
    /// a store of other people's secrets.
    /// Report what a run reached for, and what its artefact declares about
    /// itself.
    ///
    /// The declared limits ride along here rather than on their own endpoint
    /// because this is already the "what did that execution look like from the
    /// inside" report, and it is already sent from the one component that has
    /// the bytes to read them from.
    pub async fn submit_egress_audit(
        &self,
        job_id: i64,
        project_id: Option<&str>,
        wasm_checksum: &str,
        executed_wasm_sha256: Option<&str>,
        manifest: Option<&crate::connector_manifest::ProjectManifest>,
        records: &[crate::connector_manifest::EgressRecord],
    ) -> Result<()> {
        let url = format!("{}/egress-audit", self.base_url);

        #[derive(Serialize)]
        struct DeclaredLimit<'a> {
            operation: &'a str,
            period: &'a str,
            max_count: u32,
            applies: &'a str,
        }

        #[derive(Serialize)]
        struct EgressAuditRequest<'a> {
            job_id: i64,
            project_id: Option<&'a str>,
            wasm_checksum: &'a str,
            executed_wasm_sha256: Option<&'a str>,
            connector_id: Option<&'a str>,
            declared_limits: Vec<DeclaredLimit<'a>>,
            records: &'a [crate::connector_manifest::EgressRecord],
        }

        let declared_limits: Vec<DeclaredLimit> = manifest
            .and_then(|m| m.limits.as_ref())
            .map(|limits| {
                limits
                    .iter()
                    .map(|l| DeclaredLimit {
                        operation: &l.operation,
                        period: &l.window,
                        max_count: l.max_count,
                        applies: &l.applies,
                    })
                    .collect()
            })
            .unwrap_or_default();

        let response = self
            .add_auth_headers(self.client.post(&url))
            .json(&EgressAuditRequest {
                job_id,
                project_id,
                wasm_checksum,
                executed_wasm_sha256,
                connector_id: manifest.and_then(|m| m.connector_id.as_deref()),
                declared_limits,
                records,
            })
            .send()
            .await
            .context("Failed to submit egress audit")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Egress audit rejected: HTTP {} {}", status, body);
        }

        Ok(())
    }

    // =========================================================================
    // Event Monitor Block Cursor
    // =========================================================================

    /// Get the last saved block cursor from coordinator.
    /// Returns None if no cursor was saved yet.
    pub async fn get_block_cursor(&self) -> Result<Option<u64>> {
        let url = format!("{}/workers/block-cursor", self.base_url);

        let response = self.add_auth_headers(self.client.get(&url))
            .send()
            .await
            .context("Failed to get block cursor")?;

        if !response.status().is_success() {
            // Non-critical — fall back to env var
            tracing::warn!("Failed to get block cursor: HTTP {}", response.status());
            return Ok(None);
        }

        #[derive(Deserialize)]
        struct BlockCursorResponse {
            block_height: Option<u64>,
        }

        let resp: BlockCursorResponse = response.json().await
            .context("Failed to parse block cursor response")?;

        Ok(resp.block_height)
    }

    /// Create a TopUp task for Payment Key balance update
    ///
    /// This is used when ft_on_transfer emits SystemEvent::TopUpPaymentKey
    /// Worker will decrypt/update balance/encrypt and call promise_yield_resume
    pub async fn create_topup_task(&self, params: TopUpTaskData) -> Result<Option<i64>> {
        let url = format!("{}/topup/create", self.base_url);

        #[derive(Serialize)]
        struct CreateTopUpRequest {
            data_id: String,
            owner: String,
            nonce: u32,
            amount: String,
            encrypted_data: String,
        }

        #[derive(Deserialize)]
        struct CreateTopUpResponse {
            task_id: i64,
            created: bool,
        }

        let request = CreateTopUpRequest {
            data_id: params.data_id.clone(),
            owner: params.owner,
            nonce: params.nonce,
            amount: params.amount,
            encrypted_data: params.encrypted_data,
        };

        let response = self.add_auth_headers(self.client.post(&url))
            .json(&request)
            .send()
            .await
            .context("Failed to create topup task")?;

        if !response.status().is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            anyhow::bail!("Create topup task failed: {}", error_text)
        }

        let create_response: CreateTopUpResponse = response.json().await
            .context("Failed to parse create topup task response")?;

        if create_response.created {
            tracing::info!(
                task_id = create_response.task_id,
                data_id = %params.data_id,
                "TopUp task created in coordinator"
            );
            Ok(Some(create_response.task_id))
        } else {
            tracing::info!(
                data_id = %params.data_id,
                "TopUp task already exists (duplicate)"
            );
            Ok(None)
        }
    }

    /// Complete TopUp - notify coordinator of new balance
    ///
    /// Called after successfully calling resume_topup on the contract.
    /// This stores payment key metadata in coordinator's PostgreSQL for validation.
    ///
    /// # Arguments
    /// * `owner` - Payment Key owner (NEAR account)
    /// * `nonce` - Payment Key nonce
    /// * `new_initial_balance` - The new total balance after top-up
    /// * `amount` - The topup amount (delta) - used for atomic additive update
    /// * `key_hash` - SHA256 hash of the key (hex encoded) for validation
    /// * `project_ids` - List of allowed project IDs (empty = all projects)
    /// * `max_per_call` - Max amount per API call (optional)
    /// * `agent` - the agent binding as read from the blob (§A1)
    pub async fn complete_topup(
        &self,
        owner: &str,
        nonce: u32,
        new_initial_balance: &str,
        amount: &str,
        key_hash: &str,
        project_ids: &[String],
        max_per_call: Option<&str>,
    ) -> Result<()> {
        let url = format!("{}/topup/complete", self.base_url);

        /// As for `init`: `key_hash` carries whether this is an agent's key,
        /// because it IS the answer — see [`ApiClient::init_payment_key`].
        #[derive(Serialize)]
        struct CompleteTopUpRequest {
            owner: String,
            nonce: u32,
            new_initial_balance: String,
            amount: String,
            key_hash: String,
            project_ids: Vec<String>,
            max_per_call: Option<String>,
        }

        let request = CompleteTopUpRequest {
            owner: owner.to_string(),
            nonce,
            new_initial_balance: new_initial_balance.to_string(),
            amount: amount.to_string(),
            key_hash: key_hash.to_string(),
            project_ids: project_ids.to_vec(),
            max_per_call: max_per_call.map(String::from),
        };

        tracing::info!(
            "📊 Notifying coordinator of TopUp completion: owner={} nonce={} amount={} balance={} key_hash={}...",
            owner, nonce, amount, new_initial_balance, &key_hash[..8.min(key_hash.len())]
        );

        let response = self.add_auth_headers(self.client.post(&url))
            .json(&request)
            .send()
            .await
            .context("Failed to notify coordinator of topup completion")?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            tracing::warn!(
                "Failed to update balance cache (non-critical): {}",
                error_text
            );
            // Non-critical error - TopUp still succeeded on contract
            return Ok(());
        }

        tracing::info!("Balance cache updated successfully");
        Ok(())
    }

    /// Delete payment key from coordinator PostgreSQL (soft delete)
    ///
    /// Called when processing DeletePaymentKey event from contract.
    /// This marks the key as deleted in PostgreSQL so it's no longer valid for HTTPS API calls.
    ///
    /// # Arguments
    /// * `owner` - Payment Key owner (NEAR account)
    /// * `nonce` - Payment Key nonce
    pub async fn delete_payment_key(&self, owner: &str, nonce: u32) -> Result<()> {
        let url = format!("{}/payment-keys/delete", self.base_url);

        #[derive(Serialize)]
        struct DeletePaymentKeyRequest {
            owner: String,
            nonce: u32,
        }

        let request = DeletePaymentKeyRequest {
            owner: owner.to_string(),
            nonce,
        };

        tracing::info!(
            "🗑️ Deleting payment key from coordinator: owner={} nonce={}",
            owner, nonce
        );

        let response = self.add_auth_headers(self.client.post(&url))
            .json(&request)
            .send()
            .await
            .context("Failed to delete payment key from coordinator")?;

        if !response.status().is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            anyhow::bail!("Delete payment key failed: {}", error_text)
        }

        tracing::info!(
            "✅ Payment key deleted from coordinator: owner={} nonce={}",
            owner, nonce
        );
        Ok(())
    }

    /// Create a DeletePaymentKey task in coordinator queue
    ///
    /// Called by event monitor when DeletePaymentKey event is detected.
    /// Worker will poll for these tasks and process them.
    pub async fn create_delete_payment_key_task(
        &self,
        params: DeletePaymentKeyTaskData,
    ) -> Result<Option<i64>> {
        let url = format!("{}/payment-keys/delete-task/create", self.base_url);

        #[derive(Serialize)]
        struct CreateDeleteTaskRequest {
            data_id: String,
            owner: String,
            nonce: u32,
        }

        #[derive(Deserialize)]
        struct CreateDeleteTaskResponse {
            task_id: i64,
            created: bool,
        }

        let request = CreateDeleteTaskRequest {
            data_id: params.data_id.clone(),
            owner: params.owner,
            nonce: params.nonce,
        };

        tracing::info!(
            "📝 Creating DeletePaymentKey task: data_id={} owner={} nonce={}",
            &params.data_id[..8.min(params.data_id.len())],
            request.owner,
            request.nonce
        );

        let response = self.add_auth_headers(self.client.post(&url))
            .json(&request)
            .send()
            .await
            .context("Failed to create delete payment key task")?;

        if !response.status().is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            anyhow::bail!("Create delete task failed: {}", error_text)
        }

        let result: CreateDeleteTaskResponse = response.json().await?;
        if result.created {
            Ok(Some(result.task_id))
        } else {
            Ok(None)
        }
    }

    /// Notify coordinator that a wallet policy was created/updated on-chain.
    /// Coordinator will decrypt via keystore and sync authorized key hashes.
    /// Tell the coordinator a subscription was bought and paid for on chain.
    ///
    /// Sends what was PAID and nothing about what it is worth: the plan's
    /// allowance and validity are the coordinator's own table. A worker that
    /// could state them would be a worker that could grant itself a
    /// subscription.
    pub async fn notify_subscription_purchased(
        &self,
        receipt_id: &str,
        owner: &str,
        nonce: u32,
        plan: u8,
        paid_usd: &str,
        payer: &str,
    ) -> Result<()> {
        let url = format!("{}/internal/subscription-purchased", self.base_url);

        let response = self
            .add_auth_headers(self.client.post(&url))
            .json(&serde_json::json!({
                "receipt_id": receipt_id,
                "owner": owner,
                "nonce": nonce,
                "plan": plan,
                "paid_usd": paid_usd,
                "payer": payer,
            }))
            .send()
            .await
            .context("Failed to notify subscription purchase")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            // A 4xx is the coordinator's considered answer: an unknown plan, a
            // key that is not there, a body it will not accept. It will say the
            // same thing tomorrow, so it is TERMINAL and the block moves on.
            // Anything else — a connection refused while the coordinator
            // restarts, a 5xx during its migrations — is the failure that goes
            // away on its own, and the one worth holding the block for.
            if status.is_client_error() {
                return Err(anyhow::Error::new(TerminalRelay).context(format!(
                    "Subscription purchase notify refused ({}): {}",
                    status, body
                )));
            }
            anyhow::bail!("Subscription purchase notify failed ({}): {}", status, body);
        }

        Ok(())
    }

    pub async fn notify_wallet_policy_updated(
        &self,
        wallet_pubkey: &str,
        owner: &str,
        encrypted_data: &str,
        frozen: bool,
    ) -> Result<()> {
        let url = format!("{}/internal/wallet-policy-sync", self.base_url);

        let response = self
            .add_wallet_internal_auth(self.client.post(&url))
            .json(&serde_json::json!({
                "wallet_pubkey": wallet_pubkey,
                "owner": owner,
                "encrypted_data": encrypted_data,
                "frozen": frozen,
            }))
            .send()
            .await
            .context("Failed to notify wallet policy sync")?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("Wallet policy sync failed: {}", error_text);
        }

        tracing::info!("✅ Wallet policy sync notified: wallet={}", wallet_pubkey);
        Ok(())
    }

    /// The wallet builds the coordinator recognizes for `personal_account`
    /// bindings, base58 code hashes. The crate's verdict on a bound account
    /// needs the deployment's answer to "is this build recognized?", and that
    /// list is data in the coordinator's database — not a constant in this
    /// binary, so a new wallet build costs a row there rather than a worker
    /// release. Read per bound run; the path is rare and the answer small.
    pub async fn wallet_code_hashes(&self) -> Result<Vec<String>> {
        let url = format!("{}/internal/wallet-code-hashes", self.base_url);
        let response = self
            .add_wallet_internal_auth(self.client.get(&url))
            .send()
            .await
            .context("Failed to fetch the recognized wallet code hashes")?;
        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("Fetching wallet code hashes failed: {}", error_text);
        }
        #[derive(serde::Deserialize)]
        struct Row {
            code_hash: String,
        }
        #[derive(serde::Deserialize)]
        struct Body {
            code_hashes: Vec<Row>,
        }
        let body: Body = response
            .json()
            .await
            .context("Failed to parse the recognized wallet code hashes")?;
        Ok(body.code_hashes.into_iter().map(|r| r.code_hash).collect())
    }

    /// Notify coordinator that a wallet policy was deleted on-chain.
    pub async fn notify_wallet_policy_deleted(
        &self,
        wallet_pubkey: &str,
        owner: &str,
    ) -> Result<()> {
        let url = format!("{}/internal/wallet-policy-delete", self.base_url);

        let response = self
            .add_wallet_internal_auth(self.client.post(&url))
            .json(&serde_json::json!({
                "wallet_pubkey": wallet_pubkey,
                "owner": owner,
            }))
            .send()
            .await
            .context("Failed to notify wallet policy delete")?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("Wallet policy delete failed: {}", error_text);
        }

        tracing::info!("✅ Wallet policy delete notified: wallet={}", wallet_pubkey);
        Ok(())
    }

    /// Notify coordinator that a wallet's frozen status changed on-chain.
    pub async fn notify_wallet_frozen_changed(
        &self,
        wallet_pubkey: &str,
        owner: &str,
        frozen: bool,
    ) -> Result<()> {
        let url = format!("{}/internal/wallet-frozen-change", self.base_url);

        let response = self
            .add_wallet_internal_auth(self.client.post(&url))
            .json(&serde_json::json!({
                "wallet_pubkey": wallet_pubkey,
                "owner": owner,
                "frozen": frozen,
            }))
            .send()
            .await
            .context("Failed to notify wallet frozen change")?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("Wallet frozen change failed: {}", error_text);
        }

        tracing::info!("✅ Wallet frozen change notified: wallet={} frozen={}", wallet_pubkey, frozen);
        Ok(())
    }

    /// Drop the coordinator's cached name → uuid entries for `project_ids`
    /// (`owner/name`). Idempotent: a name with no entry is not an error. A 4xx
    /// is a [`TerminalRelay`].
    pub async fn invalidate_project_uuid_cache(&self, project_ids: &[String]) -> Result<()> {
        let url = format!("{}/projects/cache/invalidate", self.base_url);

        let response = self
            .add_auth_headers(self.client.post(&url))
            .timeout(self.relay_timeout)
            .json(&serde_json::json!({ "project_ids": project_ids }))
            .send()
            .await
            .context("Failed to send project uuid cache invalidation")?;

        let status = response.status();
        if !status.is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            let message = format!(
                "Project uuid cache invalidation failed with status {}: {}",
                status, error_text
            );
            if status.is_client_error() {
                return Err(anyhow::Error::new(TerminalRelay).context(message));
            }
            anyhow::bail!(message)
        }
        Ok(())
    }

    /// Create a project storage cleanup task in the coordinator's queue.
    ///
    /// Called by the event monitor for a `ProjectStorageCleanup` event written
    /// in `block_height`; the coordinator confirms the deletion on the contract
    /// at that block. A 4xx — among them the 409 of a project the contract
    /// still holds — is a [`TerminalRelay`] carrying the coordinator's reason;
    /// a 2xx whose body does not parse is retried.
    pub async fn create_project_storage_cleanup_task(
        &self,
        project_id: &str,
        project_uuid: &str,
        block_height: u64,
    ) -> Result<Option<i64>> {
        let url = format!("{}/projects/cleanup-task/create", self.base_url);

        #[derive(Serialize)]
        struct CreateCleanupTaskRequest {
            project_id: String,
            project_uuid: String,
            block_height: u64,
        }

        #[derive(Deserialize)]
        struct CreateCleanupTaskResponse {
            task_id: i64,
            created: bool,
        }

        let request = CreateCleanupTaskRequest {
            project_id: project_id.to_string(),
            project_uuid: project_uuid.to_string(),
            block_height,
        };

        tracing::info!(
            "📝 Creating ProjectStorageCleanup task: project_id={} uuid={} block={}",
            project_id, project_uuid, block_height
        );

        let response = self.add_auth_headers(self.client.post(&url))
            .timeout(self.relay_timeout)
            .json(&request)
            .send()
            .await
            .context("Failed to create project storage cleanup task")?;

        let status = response.status();
        if !status.is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            let message = format!("Create cleanup task failed with status {}: {}", status, error_text);
            if status.is_client_error() {
                return Err(anyhow::Error::new(TerminalRelay).context(message));
            }
            anyhow::bail!(message)
        }

        // A body that does not parse is transient: a proxy in front of the
        // coordinator can answer 200 with a page of its own.
        let result: CreateCleanupTaskResponse = response.json().await.map_err(|e| {
            anyhow::anyhow!(
                "Create cleanup task answered with a body that does not parse: {}",
                e.without_url()
            )
        })?;
        if result.created {
            Ok(Some(result.task_id))
        } else {
            Ok(None)
        }
    }

    // =========================================================================
    // Unified System Callbacks Polling
    // =========================================================================

    /// Poll for ANY system callback task (TopUp, Delete, etc.) from unified queue
    ///
    /// This is the preferred method - replaces separate poll_topup_task and
    /// poll_delete_payment_key_task methods. Worker polls a single queue and
    /// dispatches based on task type.
    ///
    /// # Arguments
    /// * `timeout` - Seconds to wait (0 for non-blocking, max 120)
    ///
    /// # Returns
    /// * `Ok(Some(task))` - Task received, dispatch based on task_type
    /// * `Ok(None)` - No tasks available (timeout)
    /// * `Err(_)` - Request failed
    pub async fn poll_system_callback_task(&self, timeout: u64, capabilities: &[String]) -> Result<Option<SystemCallbackTask>> {
        let capabilities_param = capabilities.join(",");
        let url = format!("{}/system-callbacks/poll?timeout={}&capabilities={}", self.base_url, timeout, capabilities_param);

        let response = self.add_auth_headers(self.client.get(&url))
            .send()
            .await
            .context("Failed to poll system callback task")?;

        if !response.status().is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            anyhow::bail!("Poll system callback task failed: {}", error_text)
        }

        let task: Option<SystemCallbackTask> = response.json().await
            .context("Failed to parse system callback task response")?;

        if let Some(ref t) = task {
            match t {
                SystemCallbackTask::TopUp(payload) => {
                    tracing::info!(
                        "📥 System callback: TopUp task_id={} owner={} nonce={}",
                        payload.task_id, payload.owner, payload.nonce
                    );
                }
                SystemCallbackTask::DeletePaymentKey(payload) => {
                    tracing::info!(
                        "📥 System callback: Delete task_id={} owner={} nonce={}",
                        payload.task_id, payload.owner, payload.nonce
                    );
                }
                SystemCallbackTask::ProjectStorageCleanup(payload) => {
                    tracing::info!(
                        "📥 System callback: ProjectStorageCleanup task_id={} project_id={} uuid={}",
                        payload.task_id, payload.project_id, payload.project_uuid
                    );
                }
            }
        }

        Ok(task)
    }

    /// Send heartbeat to coordinator
    ///
    /// # Arguments
    /// * `worker_id` - Unique worker identifier
    /// * `worker_name` - Human-readable worker name
    /// * `status` - Current status (online, busy, offline)
    /// * `current_task_id` - ID of currently executing task (if any)
    pub async fn send_heartbeat(
        &self,
        worker_id: String,
        worker_name: String,
        status: &str,
        current_task_id: Option<i64>,
        event_monitor_block_height: Option<u64>,
        last_poll_at: Option<u64>,
    ) -> Result<()> {
        let url = format!("{}/workers/heartbeat", self.base_url);

        #[derive(Serialize)]
        struct HeartbeatRequest {
            worker_id: String,
            worker_name: String,
            status: String,
            current_task_id: Option<i64>,
            #[serde(skip_serializing_if = "Option::is_none")]
            event_monitor_block_height: Option<u64>,
            #[serde(skip_serializing_if = "Option::is_none")]
            last_poll_at: Option<u64>,
        }

        let request = HeartbeatRequest {
            worker_id,
            worker_name,
            status: status.to_string(),
            current_task_id,
            event_monitor_block_height,
            last_poll_at,
        };

        let response = self.add_auth_headers(self.client.post(&url))
            .json(&request)
            .send()
            .await
            .context("Failed to send heartbeat")?;

        if !response.status().is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            anyhow::bail!("Heartbeat failed: {}", error_text)
        }

        Ok(())
    }

    /// Resolve which branch contains a specific commit hash
    ///
    /// Calls coordinator's GitHub API integration with caching.
    ///
    /// # Arguments
    /// * `repo` - Repository URL (e.g., "alice/project" or full URL)
    /// * `commit` - Commit hash or branch name
    ///
    /// # Returns
    /// * `Ok(Some(branch))` - Branch name found
    /// * `Ok(None)` - Commit not found or branch could not be determined
    /// * `Err(_)` - API error
    pub async fn resolve_branch(&self, repo: &str, commit: &str) -> Result<Option<String>> {
        let url = format!("{}/github/resolve-branch", self.base_url);

        #[derive(Deserialize)]
        struct ResolveBranchResponse {
            branch: Option<String>,
            #[allow(dead_code)]
            repo_normalized: String,
            #[allow(dead_code)]
            cached: bool,
        }

        let response = self
            .add_auth_headers(self.client.get(&url))
            .query(&[("repo", repo), ("commit", commit)])
            .send()
            .await
            .context("Failed to send resolve-branch request")?;

        match response.status() {
            StatusCode::OK => {
                let data: ResolveBranchResponse = response
                    .json()
                    .await
                    .context("Failed to parse resolve-branch response")?;
                Ok(data.branch)
            }
            StatusCode::NOT_FOUND => Ok(None), // Commit not found
            status => {
                let error_text = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "Unknown error".to_string());
                anyhow::bail!(
                    "Resolve-branch failed with status {}: {}",
                    status,
                    error_text
                )
            }
        }
    }

    /// Resolve project_id to project_uuid via coordinator
    ///
    /// Calls coordinator's project API, which caches name → uuid in Redis
    /// until a delete or transfer of that project drops the entry, and for at
    /// most 24 hours.
    ///
    /// # Arguments
    /// * `project_id` - Project ID in format "owner.near/name"
    ///
    /// # Returns
    /// * `Ok(Some(ProjectInfo))` - Project found with UUID and active version
    /// * `Ok(None)` - Project not found
    /// * `Err(_)` - API error
    #[allow(dead_code)]
    pub async fn resolve_project_uuid(&self, project_id: &str) -> Result<Option<ProjectUuidInfo>> {
        let url = format!("{}/projects/uuid", self.base_url);

        let response = self.add_auth_headers(self.client.get(&url))
            .query(&[("project_id", project_id)])
            .send()
            .await
            .context("Failed to send resolve-project-uuid request")?;

        match response.status() {
            StatusCode::OK => {
                let data: ProjectUuidInfo = response
                    .json()
                    .await
                    .context("Failed to parse project-uuid response")?;
                Ok(Some(data))
            }
            StatusCode::NOT_FOUND => Ok(None),
            status => {
                let error_text = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "Unknown error".to_string());
                anyhow::bail!(
                    "Resolve-project-uuid failed with status {}: {}",
                    status,
                    error_text
                )
            }
        }
    }

    /// Store task attestation in coordinator
    ///
    /// Sends TDX quote and task metadata to coordinator for public verification.
    /// This endpoint requires worker auth token.
    ///
    /// # Arguments
    /// * `request` - Attestation data with TDX quote and task metadata
    ///
    /// # Returns
    /// * `Ok(())` if attestation was stored successfully
    /// * `Err` if request failed
    pub async fn store_attestation(&self, request: StoreAttestationRequest) -> Result<()> {
        let url = format!("{}/attestations", self.base_url);

        tracing::debug!(
            task_id = request.task_id,
            task_type = %request.task_type,
            "Storing attestation in coordinator"
        );

        let response = self.add_auth_headers(self.client.post(&url))
            .json(&request)
            .send()
            .await
            .context("Failed to send attestation to coordinator")?;

        match response.status() {
            StatusCode::CREATED => {
                tracing::info!(
                    task_id = request.task_id,
                    task_type = %request.task_type,
                    "Successfully stored attestation in coordinator"
                );
                Ok(())
            }
            StatusCode::BAD_REQUEST => {
                let error_text = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "Invalid request".to_string());
                anyhow::bail!("Attestation validation failed: {}", error_text)
            }
            StatusCode::UNAUTHORIZED => {
                anyhow::bail!("Worker authentication failed - check API_AUTH_TOKEN")
            }
            status => {
                let error_text = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "Unknown error".to_string());
                anyhow::bail!(
                    "Failed to store attestation with status {}: {}",
                    status,
                    error_text
                )
            }
        }
    }

    /// Clear all storage for a project (called when project is deleted)
    pub async fn clear_project_storage(&self, project_uuid: &str) -> Result<()> {
        let url = format!("{}/storage/clear-project", self.base_url);

        tracing::info!(
            project_uuid = project_uuid,
            "Clearing project storage in coordinator"
        );

        let response = self.add_auth_headers(self.client.post(&url))
            .json(&serde_json::json!({ "project_uuid": project_uuid }))
            .send()
            .await
            .context("Failed to send clear-project request to coordinator")?;

        match response.status() {
            StatusCode::OK => {
                tracing::info!(
                    project_uuid = project_uuid,
                    "Successfully cleared project storage"
                );
                Ok(())
            }
            StatusCode::UNAUTHORIZED => {
                anyhow::bail!("Worker authentication failed - check API_AUTH_TOKEN")
            }
            status => {
                let error_text = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "Unknown error".to_string());
                anyhow::bail!(
                    "Failed to clear project storage with status {}: {}",
                    status,
                    error_text
                )
            }
        }
    }
}

/// Task type enum matching coordinator's TaskType
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TaskType {
    Compile,
    Execute,
    /// TopUp Payment Key - process yield/resume for balance update
    Topup,
}

impl std::fmt::Display for TaskType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TaskType::Compile => write!(f, "compile"),
            TaskType::Execute => write!(f, "execute"),
            TaskType::Topup => write!(f, "topup"),
        }
    }
}

/// Parameters for creating a TopUp task
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopUpTaskData {
    /// data_id for yield/resume (hex encoded)
    pub data_id: String,
    /// Payment Key owner
    pub owner: String,
    /// Payment Key nonce (profile)
    pub nonce: u32,
    /// TopUp amount in minimal token units
    pub amount: String,
    /// Current encrypted secret (base64)
    pub encrypted_data: String,
}

/// Data for a DeletePaymentKey task
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletePaymentKeyTaskData {
    /// data_id for yield/resume (hex encoded)
    pub data_id: String,
    /// Payment Key owner
    pub owner: String,
    /// Payment Key nonce (profile)
    pub nonce: u32,
}

// =============================================================================
// Unified System Callback Task Type
// =============================================================================

/// Unified system callback task - matches coordinator's SystemCallbackTask
///
/// All contract business logic that requires yield/resume is processed through this.
/// Workers poll a single queue and dispatch based on task_type.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "task_type", rename_all = "snake_case")]
pub enum SystemCallbackTask {
    /// TopUp Payment Key - requires keystore to decrypt/re-encrypt
    TopUp(TopUpTaskPayload),
    /// Delete Payment Key - no keystore needed
    DeletePaymentKey(DeletePaymentKeyPayload),
    /// Project Storage Cleanup - clear compiled WASM and storage for deleted project
    ProjectStorageCleanup(ProjectStorageCleanupPayload),
}

/// TopUp task payload from unified queue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopUpTaskPayload {
    pub task_id: i64,
    pub data_id: String,
    pub owner: String,
    pub nonce: u32,
    pub amount: String,
    pub encrypted_data: String,
    pub created_at: i64,
}

/// DeletePaymentKey task payload from unified queue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletePaymentKeyPayload {
    pub task_id: i64,
    pub data_id: String,
    pub owner: String,
    pub nonce: u32,
    pub created_at: i64,
}

/// ProjectStorageCleanup task payload from unified queue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectStorageCleanupPayload {
    pub task_id: i64,
    pub project_id: String,
    pub project_uuid: String,
    pub created_at: i64,
}

/// Request to store task attestation in coordinator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreAttestationRequest {
    pub task_id: i64,
    pub task_type: TaskType,

    // TDX attestation data
    pub tdx_quote: String, // base64 encoded

    // NEAR context (NULL for HTTPS calls)
    pub request_id: Option<i64>,
    pub caller_account_id: Option<String>,
    pub transaction_hash: Option<String>,
    pub block_height: Option<u64>,

    // HTTPS call context (NULL for NEAR calls)
    pub call_id: Option<String>,
    pub payment_key_owner: Option<String>,
    pub payment_key_nonce: Option<i32>,

    // Code source
    pub repo_url: Option<String>,
    pub commit_hash: Option<String>,
    pub build_target: Option<String>,

    // Task data hashes
    /// Cache key for the artefact. For a `WasmUrl` source this IS the SHA256 of
    /// the binary; for a GitHub source it is a hash of the source COORDINATES
    /// (repo:commit:target), which identifies what was asked for rather than
    /// what was produced.
    pub wasm_hash: Option<String>,
    /// SHA256 of the bytes this worker actually executed (§D3).
    ///
    /// The post-hoc half of version pinning: the client compares it against the
    /// version it expected. Separate from `wasm_hash` on purpose — that field
    /// answers "which artefact was requested", and for a non-reproducible
    /// GitHub build two different binaries can share it. This one answers
    /// "which bytes ran", which is the question a verifier actually has.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executed_wasm_sha256: Option<String>,
    pub input_hash: Option<String>,
    pub output_hash: String,

    // V1 attestation fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secrets_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attached_usd: Option<String>,
    /// Job creation timestamp (unix seconds) - must match what was hashed in TDX quote
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every field the caller hands to `create_task` must survive into the JSON
    /// body, and this reads the source to prove it.
    ///
    /// `use_bound_identity` reached `CreateTaskParams` and stopped there: the
    /// wire struct inside `create_task` is declared separately and simply did
    /// not list it. Nothing failed. The coordinator reads that field with
    /// `#[serde(default)]`, so a body without it is a body that asked for
    /// nothing, and the on-chain half of Agent Connect did nothing at all while
    /// every unit test on both sides stayed green — the defect lives in the gap
    /// between two correct programs, which is the one place unit tests cannot
    /// look.
    ///
    /// Field-by-field equality, not a whitelist: a field added to the carrier
    /// and forgotten in the body fails here rather than in production.
    #[test]
    fn create_task_sends_every_field_it_was_given() {
        let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/api_client.rs"))
            .expect("api_client.rs must be readable");

        // The two structs sit at different indentation levels — one at the top
        // of the file, one inside a function — so the end is found by matching
        // the brace rather than by guessing how far it is indented.
        fn fields_of(src: &str, header: &str) -> Vec<String> {
            let start = src.find(header).unwrap_or_else(|| panic!("{header} not found"));
            let body = &src[start + header.len()..];
            let mut depth = 1usize;
            let mut end = body.len();
            for (i, c) in body.char_indices() {
                match c {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            end = i;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            body[..end]
                .lines()
                .map(str::trim)
                .filter(|l| !l.starts_with("//") && !l.starts_with("#[") && !l.is_empty())
                .filter_map(|l| l.split(':').next().map(|n| n.trim_start_matches("pub ").trim().to_string()))
                .filter(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_lowercase() || c == '_'))
                .collect()
        }

        let carried = fields_of(&src, "pub struct CreateTaskParams {");
        let sent = fields_of(&src, "struct CreateRequest {");
        assert!(!carried.is_empty() && !sent.is_empty(), "the parser found nothing — it is broken, not the code");

        let dropped: Vec<_> = carried.iter().filter(|f| !sent.contains(f)).collect();
        assert!(
            dropped.is_empty(),
            "create_task never sends {dropped:?} — the coordinator will read the default \
             instead of what the chain asked for. Add the field to the CreateRequest struct \
             and assign it from `params`."
        );
    }

    /// The completion carries the refund, and the money says so.
    ///
    /// Same defect shape as the test above and the second half of the same
    /// day's findings: a value the guest produced never reached the body, so
    /// `earnings_history` recorded the whole `attached_usd` as the author's and
    /// the refund existed only in the worker's memory. Nothing failed, no test
    /// went red, and the ledger was quietly wrong.
    ///
    /// Read from the source because that gap is between two programs. Both
    /// halves are asserted: the field on the wire, and the ASSIGNMENT that
    /// fills it — a struct field left at `None` would satisfy a shape check and
    /// lose exactly as much money.
    #[test]
    fn a_completed_job_reports_what_it_gave_back() {
        let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/api_client.rs"))
            .expect("api_client.rs must be readable");

        let (_, after) = src
            .split_once("struct CompleteJobRequest {")
            .expect("the completion body this test follows is gone");
        let (fields, _) = after
            .split_once('}')
            .expect("the CompleteJobRequest struct is not closed");
        assert!(
            fields.contains("refund_usd"),
            "CompleteJobRequest no longer carries `refund_usd`, so a guest that gave money back \
             is billed as though it had not"
        );

        // Scoped to the struct literal, NOT to the rest of the file. Searching
        // the remainder found this very assertion's own text and passed with
        // the assignment deleted — a guard that reads itself proves only that
        // it exists.
        let (_, built) = src
            .split_once("let request = CompleteJobRequest {")
            .expect("the completion is no longer built from a struct literal");
        let (assignments, _) = built
            .split_once("};")
            .expect("the CompleteJobRequest literal is not closed");
        assert!(
            assignments.contains("refund_usd: refund_usd.map("),
            "`refund_usd` is on the wire but is not assigned from the parameter — a field that \
             is always None costs the caller the same as a missing one"
        );
    }

    #[test]
    fn test_api_client_creation() {
        let client = ApiClient::new(
            "http://localhost:8080".to_string(),
            "test-token".to_string(),
        );
        assert!(client.is_ok());
    }

    #[test]
    fn test_base_url_trimming() {
        let client = ApiClient::new(
            "http://localhost:8080/".to_string(),
            "test-token".to_string(),
        )
        .unwrap();
        assert_eq!(client.base_url, "http://localhost:8080");
    }

    /// A coordinator that answers once with a chosen status.
    fn coordinator_answering(code: u16, body: &'static str) -> String {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        std::thread::spawn(move || {
            if let Some(Ok(mut stream)) = listener.incoming().next() {
                let mut buf = [0u8; 8192];
                let _ = stream.read(&mut buf);
                let response = format!(
                    "HTTP/1.1 {code} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        format!("http://{}", addr)
    }

    async fn relay_to(base_url: String) -> anyhow::Error {
        ApiClient::new(base_url, "t".to_string())
            .unwrap()
            .notify_subscription_purchased("rcpt-1", "a.near", 1, 0, "10000000", "p.near")
            .await
            .expect_err("a failed relay must be an error")
    }

    /// Which relay failures the event monitor may walk away from.
    ///
    /// The customer's transaction has already succeeded and the contract has
    /// already kept the payment, so a dropped relay means an allowance that is
    /// never granted and nobody finding out but them. The monitor therefore
    /// HOLDS the block for anything that might pass, and only gives up on an
    /// answer that will not change.
    ///
    /// Getting this backwards is bad in both directions: treat a 4xx as
    /// transient and one unacceptable event stops the monitor scanning forever;
    /// treat a restart as terminal and the purchase is lost.
    #[tokio::test]
    async fn only_a_refusal_lets_a_purchase_be_dropped() {
        assert!(
            TerminalRelay::is_terminal(
                &relay_to(coordinator_answering(400, r#"{"error":"unknown plan"}"#)).await
            ),
            "a 4xx is the coordinator's decision and will not change"
        );
        assert!(
            TerminalRelay::is_terminal(
                &relay_to(coordinator_answering(404, r#"{"error":"no such key"}"#)).await
            ),
            "so is a 404"
        );

        assert!(
            !TerminalRelay::is_terminal(
                &relay_to(coordinator_answering(503, r#"{"error":"migrating"}"#)).await
            ),
            "a 503 during startup migrations passes on its own — hold the block"
        );

        // Nothing listening at all: the coordinator is restarting. This is the
        // common case and the whole reason the hold exists.
        let refused = relay_to("http://127.0.0.1:1".to_string()).await;
        assert!(
            !TerminalRelay::is_terminal(&refused),
            "a coordinator that is not up yet is the most transient failure there is: {refused:#}"
        );
    }

    /// What `retry_relay` repeats: anything but a refusal, and only as often
    /// as it has pauses for.
    #[tokio::test]
    async fn a_relay_is_retried_until_it_is_refused_or_the_pauses_run_out() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let no_pause = [Duration::ZERO; 4];

        let calls = AtomicU32::new(0);
        let passed = retry_relay("test", &no_pause, || async {
            if calls.fetch_add(1, Ordering::SeqCst) < 2 {
                anyhow::bail!("503")
            }
            Ok(7)
        })
        .await
        .unwrap();
        assert_eq!((passed, calls.load(Ordering::SeqCst)), (7, 3), "a transient failure is asked again");

        let calls = AtomicU32::new(0);
        let refused = retry_relay("test", &no_pause, || async {
            calls.fetch_add(1, Ordering::SeqCst);
            Err::<(), _>(anyhow::Error::new(TerminalRelay).context("409: project still exists"))
        })
        .await
        .unwrap_err();
        assert_eq!(calls.load(Ordering::SeqCst), 1, "a refusal is not asked again");
        assert!(format!("{refused:#}").contains("409: project still exists"));

        let calls = AtomicU32::new(0);
        let failed = retry_relay("test", &no_pause, || async {
            calls.fetch_add(1, Ordering::SeqCst);
            Err::<(), _>(anyhow::anyhow!("connection refused"))
        })
        .await
        .unwrap_err();
        assert_eq!(calls.load(Ordering::SeqCst), 5, "one attempt, then one per pause");
        assert!(!TerminalRelay::is_terminal(&failed));
    }

    /// The cleanup relay carries the event's block, and the coordinator's 409
    /// comes back as a refusal with its reason; a 503 does not.
    #[tokio::test]
    async fn a_cleanup_relay_is_refused_by_a_409_and_retried_after_a_503() {
        let cleanup = |base_url: String| async move {
            ApiClient::new(base_url, "t".to_string())
                .unwrap()
                .create_project_storage_cleanup_task("alice.near/app", "p0000000000000001", 123)
                .await
        };
        let refused = cleanup(coordinator_answering(409, "project alice.near/app still exists")).await.unwrap_err();
        assert!(TerminalRelay::is_terminal(&refused));
        assert!(format!("{refused:#}").contains("still exists"), "{refused:#}");
        let unavailable = cleanup(coordinator_answering(503, "cannot confirm")).await.unwrap_err();
        assert!(!TerminalRelay::is_terminal(&unavailable), "{unavailable:#}");
        let created = cleanup(coordinator_answering(200, r#"{"task_id":5,"created":true}"#)).await.unwrap();
        assert_eq!(created, Some(5));
    }

    /// A 200 whose body is not the coordinator's — a proxy's HTML page — is
    /// retried, never taken as the coordinator's refusal.
    #[tokio::test]
    async fn a_cleanup_relay_answered_by_a_page_that_does_not_parse_is_retried() {
        let proxy_page = ApiClient::new(coordinator_answering(200, "<html>upstream warming up</html>"), "t".to_string())
            .unwrap()
            .create_project_storage_cleanup_task("alice.near/app", "p0000000000000001", 123)
            .await
            .unwrap_err();
        assert!(!TerminalRelay::is_terminal(&proxy_page), "{proxy_page:#}");
        assert!(format!("{proxy_page:#}").contains("does not parse"), "{proxy_page:#}");
    }

    #[tokio::test]
    async fn a_cache_invalidation_is_refused_by_a_4xx_only() {
        let invalidate = |base_url: String| async move {
            ApiClient::new(base_url, "t".to_string())
                .unwrap()
                .invalidate_project_uuid_cache(&["alice.near/app".to_string()])
                .await
        };
        assert!(TerminalRelay::is_terminal(&invalidate(coordinator_answering(400, "bad")).await.unwrap_err()));
        assert!(!TerminalRelay::is_terminal(&invalidate(coordinator_answering(500, "boom")).await.unwrap_err()));
        assert!(!TerminalRelay::is_terminal(&invalidate("http://127.0.0.1:1".to_string()).await.unwrap_err()));
        invalidate(coordinator_answering(200, "{}")).await.unwrap();
    }

    /// A coordinator that accepts the connection and never answers is given
    /// up on after the relay timeout, and that failure is retried, not final.
    #[tokio::test]
    async fn a_hanging_coordinator_is_abandoned_after_the_relay_timeout() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let base_url = format!("http://{}", listener.local_addr().expect("addr"));
        std::thread::spawn(move || {
            let held: Vec<_> = listener.incoming().take(2).collect();
            std::thread::sleep(Duration::from_secs(10));
            drop(held);
        });
        let client = ApiClient::new(base_url, "t".to_string())
            .unwrap()
            .with_relay_timeout(Duration::from_millis(200));
        let started = std::time::Instant::now();
        let cleanup = client
            .create_project_storage_cleanup_task("alice.near/app", "p0000000000000001", 123)
            .await
            .unwrap_err();
        let invalidate = client.invalidate_project_uuid_cache(&["alice.near/app".to_string()]).await.unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(5), "took {:?}", started.elapsed());
        assert!(!TerminalRelay::is_terminal(&cleanup), "{cleanup:#}");
        assert!(!TerminalRelay::is_terminal(&invalidate), "{invalidate:#}");
    }

    /// A coordinator that refuses connections is asked for about a hundred
    /// seconds; one that hangs every attempt holds the scan three minutes at
    /// most.
    #[test]
    fn a_relay_is_retried_for_about_a_hundred_seconds() {
        let pauses: Duration = RELAY_RETRY_DELAYS.iter().sum();
        assert!(pauses >= Duration::from_secs(90) && pauses <= Duration::from_secs(100), "{pauses:?}");
        let worst = RELAY_ATTEMPT_TIMEOUT * (RELAY_RETRY_DELAYS.len() as u32 + 1) + pauses;
        assert!(worst <= Duration::from_secs(180), "{worst:?}");
    }
}
