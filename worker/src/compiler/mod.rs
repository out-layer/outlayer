//! WASM compiler with support for multiple build targets
//!
//! This module provides compilation from GitHub repositories to WASM for different targets:
//! - WASI Preview 2 (P2): Modern component model with HTTP support (wasm32-wasip2)
//! - WASI Preview 1 (P1): Standard WASI modules (wasm32-wasip1, wasm32-wasi)
//!
//! ## Adding New Build Targets
//!
//! To add support for a new build target (e.g., wasm32-unknown-unknown):
//!
//! 1. Create a new module file: `src/compiler/wasm32_unknown.rs`
//! 2. Implement the compilation function with signature:
//!    ```rust,ignore
//!    pub async fn compile(
//!        docker: &Docker,
//!        container_id: &str,
//!        repo: &str,
//!        commit: &str,
//!        build_target: &str,
//!    ) -> Result<Vec<u8>>
//!    ```
//! 3. Add module declaration: `mod wasm32_unknown;`
//! 4. Add match arm in `compile_in_container()` to call your compiler
//! 5. Add unit tests
//!
//! ## Architecture
//!
//! The compiler selects the appropriate compilation strategy based on build_target:
//! 1. wasm32-wasip2 → P2 compiler (cargo build + wasm-tools)
//! 2. wasm32-wasip1/wasm32-wasi → P1 compiler (cargo build + wasm-opt)
//! 3. Unknown target → return error with helpful message

use anyhow::{Context, Result};
use bollard::Docker;
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use crate::api_client::{ApiClient, CodeSource};
use crate::config::Config;

/// Maximum WASM file size for URL downloads (10 MB)
const MAX_WASM_SIZE_BYTES: u64 = 10 * 1024 * 1024;

/// Timeout for WASM file downloads (30 seconds)
const DOWNLOAD_TIMEOUT_SECONDS: u64 = 30;

/// How many redirects a `wasm_url` fetch follows, each one checked like the URL.
const MAX_REDIRECTS: usize = 3;

/// A `wasm_url` as it may be fetched: https, with a host, on port 443 — so a
/// fetch never reaches any other service of a public host.
fn https_url(raw: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(raw).context("wasm_url is not a valid URL")?;
    // `port()` is None for the scheme's default, 443, written or not.
    if url.scheme() != "https" || url.host_str().is_none() || url.port().is_some() {
        anyhow::bail!("wasm_url must be an https:// URL on the default port");
    }
    Ok(url)
}

/// GET a `wasm_url`, connecting only where `net_guard` allows. The URL and
/// every redirect are each resolved once, every address is checked, and the
/// connection is pinned to the checked addresses; TLS verifies the host name.
async fn fetch_checked(raw: &str) -> Result<reqwest::Response> {
    let mut url = https_url(raw)?;
    for _ in 0..=MAX_REDIRECTS {
        let host = url.host_str().unwrap_or_default().to_string();
        // An IPv6 literal comes bracketed; the resolver takes it bare.
        let name = host.trim_start_matches('[').trim_end_matches(']');
        let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((name, 443))
            .await
            .with_context(|| format!("wasm_url host {host} does not resolve"))?
            .collect();
        let addrs = crate::net_guard::checked_addresses(addrs)
            .ok_or_else(|| anyhow::anyhow!("wasm_url points to an address that is not allowed"))?;
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(DOWNLOAD_TIMEOUT_SECONDS))
            .redirect(reqwest::redirect::Policy::none())
            // A proxy would resolve the name again, past the check.
            .no_proxy()
            .resolve_to_addrs(&host, &addrs)
            .build()
            .context("Failed to create HTTP client")?;
        let response = client
            .get(url.clone())
            .send()
            .await
            .context("Failed to send request")?;
        if !response.status().is_redirection() {
            return Ok(response);
        }
        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| anyhow::anyhow!("wasm_url redirects without a location"))?;
        let next = url.join(location).context("wasm_url redirects to an invalid URL")?;
        url = https_url(next.as_str())?;
    }
    anyhow::bail!("wasm_url redirects more than {MAX_REDIRECTS} times")
}

mod docker;
mod native; // Native compilation with bubblewrap (for TEE/Phala)
mod wasm32_wasip1;
mod wasm32_wasip2;

pub use docker::CompilationError;

/// Lock TTL for compilation in seconds (5 minutes)
/// This prevents stale locks from blocking compilation forever
const COMPILATION_LOCK_TTL_SECONDS: u64 = 300;

/// Compiler for building GitHub repositories into WASM binaries
pub struct Compiler {
    api_client: ApiClient,
    config: Config,
    docker: Option<Docker>,
}

impl Compiler {
    /// Create a new compiler instance
    pub fn new(api_client: ApiClient, config: Config) -> Result<Self> {
        // Docker is for builds only: a downloader fetches wasm_url and never
        // starts a build container.
        let docker = if config.capabilities.can_compile() && config.compilation_mode == "docker" {
            Some(Docker::connect_with_socket_defaults()
                .context("Failed to connect to Docker")?)
        } else {
            None
        };

        Ok(Self {
            api_client,
            config,
            docker,
        })
    }

    /// Compile a GitHub repository to WASM
    ///
    /// This function:
    /// 1. Checks if WASM already exists in cache
    /// 2. If not, acquires a distributed lock
    /// 3. Compiles the WASM using target-specific compiler
    /// 4. Uploads the result to the coordinator
    /// 5. Releases the lock
    ///
    /// # Arguments
    /// * `code_source` - GitHub repository information
    ///
    /// # Returns
    /// * `Ok(checksum)` - SHA256 checksum of compiled WASM
    /// * `Err(_)` - Compilation failed
    /// Compile WASM and return checksum + bytes (does NOT upload to coordinator)
    /// Use this for job-based workflow where upload happens after execution
    ///
    /// # Arguments
    /// * `code_source` - GitHub repo, commit, and build target
    /// * `timeout_seconds` - Optional timeout for compilation (kills process if exceeded)
    pub async fn compile_local(
        &self,
        code_source: &CodeSource,
        timeout_seconds: Option<u64>,
    ) -> Result<(String, Vec<u8>, Option<String>)> {
        // Default: check cache
        self.compile_local_with_options(code_source, timeout_seconds, false).await
    }

    /// Compile with force_rebuild option
    pub async fn compile_local_with_options(
        &self,
        code_source: &CodeSource,
        timeout_seconds: Option<u64>,
        force_rebuild: bool,
    ) -> Result<(String, Vec<u8>, Option<String>)> {
        // A downloader never builds, whatever COMPILATION_MODE says.
        if !self.config.capabilities.can_compile() {
            anyhow::bail!("Building from a GitHub repository is not available on this worker");
        }
        let (repo, commit, build_target) = match code_source {
            CodeSource::GitHub { repo, commit, build_target } => (repo, commit, build_target),
            CodeSource::WasmUrl { hash, .. } => {
                anyhow::bail!("Cannot compile a WasmUrl source (hash: {}). WasmUrl provides pre-compiled WASM.", hash);
            }
        };

        // Generate checksum for this specific compilation
        let checksum = self.compute_checksum(repo, commit, build_target);

        // Check if WASM already exists (skip if force_rebuild)
        if !force_rebuild {
            let (exists, created_at) = self.api_client.wasm_exists(&checksum).await?;
            if exists {
                info!("WASM already exists in cache: {} (created: {:?})", checksum, created_at);
                // Download and return it
                let wasm_bytes = self.api_client.download_wasm(&checksum).await?;
                return Ok((checksum, wasm_bytes, created_at));
            }
        } else {
            info!("🔄 force_rebuild=true, skipping cache check");
        }

        // Try to acquire distributed lock to prevent duplicate compilations
        let lock_key = format!("compile:{}:{}", repo, commit);
        let acquired = self
            .api_client
            .acquire_lock(
                lock_key.clone(),
                self.config.worker_id.clone(),
                COMPILATION_LOCK_TTL_SECONDS,
            )
            .await?;

        if !acquired {
            // Another worker is compiling
            info!("Another worker is compiling {}", repo);

            if force_rebuild {
                // force_rebuild=true - we need fresh compilation, can't use any cache
                // Just fail immediately - the other worker will complete and we can retry
                anyhow::bail!(
                    "Another worker is compiling {} (force_rebuild=true). Wait for it to complete.",
                    checksum
                );
            } else {
                // Check if compilation already completed
                let (exists, created_at) = self.api_client.wasm_exists(&checksum).await?;
                if exists {
                    info!("WASM compilation completed by another worker (created: {:?})", created_at);
                    let wasm_bytes = self.api_client.download_wasm(&checksum).await?;
                    return Ok((checksum, wasm_bytes, created_at));
                }

                anyhow::bail!("Failed to acquire compilation lock and WASM not available");
            }
        }

        info!("Acquired compilation lock for {}", repo);

        // Compile WASM from GitHub repository with timeout
        // IMPORTANT: Always release lock on success or failure!
        let compile_result = if let Some(timeout) = timeout_seconds {
            info!("⏱️  Compiling with timeout: {}s", timeout);
            tokio::time::timeout(
                std::time::Duration::from_secs(timeout),
                self.compile_from_github(repo, commit, build_target)
            )
            .await
            .map_err(|_| anyhow::anyhow!("Compilation timeout exceeded: {}s", timeout))
            .and_then(|r| r)
        } else {
            self.compile_from_github(repo, commit, build_target).await
        };

        // Always release lock - regardless of compilation result
        info!("🔓 Releasing compilation lock for {}", repo);
        if let Err(e) = self.api_client.release_lock(&lock_key).await {
            warn!("Failed to release lock {}: {}", lock_key, e);
        }

        // Now handle the result
        let wasm_bytes = compile_result?;

        info!("✅ WASM compilation complete: {} ({} bytes)", checksum, wasm_bytes.len());
        Ok((checksum, wasm_bytes, None)) // Fresh compilation, no created_at yet
    }

    /// OLD METHOD - kept for backward compatibility
    /// Compile WASM and upload to coordinator immediately
    #[allow(dead_code)]
    pub async fn compile(&self, code_source: &CodeSource) -> Result<String> {
        let (checksum, wasm_bytes, _created_at) = self.compile_local(code_source, None).await?;

        // Upload to coordinator
        info!("Uploading compiled WASM to coordinator");
        let (repo, commit, build_target) = match code_source {
            CodeSource::GitHub { repo, commit, build_target } => (repo.as_str(), commit.as_str(), build_target.as_str()),
            CodeSource::WasmUrl { .. } => {
                anyhow::bail!("Cannot upload a WasmUrl source - it's already compiled");
            }
        };
        self.api_client
            .upload_wasm(checksum.clone(), repo.to_string(), commit.to_string(), build_target.to_string(), wasm_bytes)
            .await?;

        info!("✅ WASM compilation and upload complete: {}", checksum);
        Ok(checksum)
    }

    /// Compile WASM from GitHub repository
    ///
    /// Compilation method depends on config.compilation_mode:
    /// - "docker": Use Docker containers (requires Docker socket)
    /// - "native": Use native Rust toolchain with bubblewrap (for TEE/Phala)
    ///
    /// # Not safe for untrusted repositories as it stands
    ///
    /// Builds are off (`BUILDS_ENABLED=false` on the coordinator) and must stay
    /// off until all of the following holds. A build runs the repository's own
    /// code: cargo executes any `build.rs` it finds (the manifest need not
    /// name it), the build scripts of every dependency and every proc-macro.
    /// No check of the manifest stops that, so the build itself is the code
    /// to contain.
    /// - Network: dependencies fetched first (`cargo fetch` against the lock),
    ///   the build then run with no network at all. Today the docker build runs
    ///   on the `bridge` network: the host's listeners on docker0 (172.17.0.1)
    ///   and the internet are reachable, which is how a build opened a tunnel
    ///   out and scanned the host's networks.
    /// - Privilege: the build as an unprivileged user in a read-only image, not
    ///   root (today the container runs as root and lives `sleep 600`).
    /// - Output: the coordinator takes a build only for the compile job this
    ///   worker holds. `/wasm/upload` accepts bytes under a coordinates key
    ///   from any worker token while builds are on.
    /// - Credentials: nothing in reach of the build that a worker token, or
    ///   anything else, can be read from.
    /// - Narrower alternative: builds only for an allowlist of repositories.
    async fn compile_from_github(&self, repo: &str, commit: &str, build_target: &str) -> Result<Vec<u8>> {
        info!("Compiling {} @ {} for target {}", repo, commit, build_target);

        // Validate untrusted repo/commit at the single choke point so BOTH the
        // native and docker backends are covered (the docker scripts interpolate
        // these into a shell where unvalidated input is git-arg / ext injection).
        native::validate_repo_url(repo)?;
        native::validate_git_ref(commit)?;

        // Validate and normalize build target
        let normalized_target = self.validate_build_target(build_target)?;

        info!("Using build target: {}", normalized_target);
        info!("Compilation mode: {}", self.config.compilation_mode);

        // Select compilation method based on config
        match self.config.compilation_mode.as_str() {
            "native" => {
                // Native compilation with bubblewrap (for TEE/Phala)
                info!("🔒 Using native compilation with bubblewrap sandboxing");
                native::compile(
                    self.docker.as_ref(),
                    repo,
                    commit,
                    &normalized_target,
                    Some(self.config.compile_timeout_seconds),
                ).await
            }
            "docker" => {
                // Docker-based compilation (traditional method)
                info!("🐳 Using Docker-based compilation");
                self.compile_from_github_docker(repo, commit, &normalized_target).await
            }
            _ => {
                anyhow::bail!(
                    "Invalid compilation mode: '{}'. Must be 'docker' or 'native'",
                    self.config.compilation_mode
                )
            }
        }
    }

    /// Compile WASM from GitHub repository using Docker (traditional method)
    async fn compile_from_github_docker(&self, repo: &str, commit: &str, build_target: &str) -> Result<Vec<u8>> {
        // Get Docker client (guaranteed to exist in docker mode)
        let docker = self.docker.as_ref()
            .context("Docker client not initialized. Set COMPILATION_MODE=docker")?;

        // Create unique container name
        let container_name = format!("offchainvm-compile-{}", uuid::Uuid::new_v4());

        // Ensure Docker image is available
        docker::ensure_image(docker, &self.config.docker_image).await?;

        // Create container
        let container_id = docker::create_container(
            docker,
            &container_name,
            &self.config,
            repo,
            commit,
            build_target,
        )
        .await?;

        // Execute compilation using target-specific compiler
        let result = self.compile_in_container(&container_id, build_target).await;

        // Always cleanup container
        if let Err(e) = docker::cleanup_container(docker, &container_id).await {
            warn!("Failed to cleanup container {}: {}", container_id, e);
        }

        // Return result
        result
    }

    /// Compile WASM in container using target-specific compiler
    async fn compile_in_container(&self, container_id: &str, build_target: &str) -> Result<Vec<u8>> {
        info!("Executing compilation in container {} for target {}", container_id, build_target);

        // Get Docker client (guaranteed to exist in docker mode)
        let docker = self.docker.as_ref()
            .context("Docker client not initialized")?;

        // Select compiler based on build target
        match build_target {
            "wasm32-wasip2" => {
                wasm32_wasip2::compile(docker, container_id, build_target).await
            }
            "wasm32-wasip1" | "wasm32-wasi" => {
                wasm32_wasip1::compile(docker, container_id, build_target).await
            }
            _ => {
                anyhow::bail!(
                    "Unsupported build target: {}\n\
                     Supported targets:\n\
                     - wasm32-wasip2 (WASI Preview 2)\n\
                     - wasm32-wasip1, wasm32-wasi (WASI Preview 1)\n\
                     \n\
                     To add support for a new target, see module documentation.",
                    build_target
                )
            }
        }
    }

    /// Validate and normalize build target
    fn validate_build_target(&self, target: &str) -> Result<String> {
        match target {
            "wasm32-wasip1" | "wasm32-wasi" | "wasm32-wasip2" => Ok(target.to_string()),
            _ => anyhow::bail!(
                "Unsupported build target: {}. Supported: wasm32-wasip1, wasm32-wasi, wasm32-wasip2",
                target
            ),
        }
    }

    /// Compute checksum for a specific compilation
    fn compute_checksum(&self, repo: &str, commit: &str, build_target: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(repo.as_bytes());
        hasher.update(b":");
        hasher.update(commit.as_bytes());
        hasher.update(b":");
        hasher.update(build_target.as_bytes());
        let result = hasher.finalize();
        hex::encode(result)
    }

    /// Download WASM from URL and verify hash
    ///
    /// Downloads pre-compiled WASM from URL (https://, ipfs://, ar://)
    /// with security protections:
    /// - 10 MB size limit
    /// - 30 second timeout
    /// - SHA256 hash verification
    ///
    /// # Arguments
    /// * `url` - URL to download from
    /// * `expected_hash` - Expected SHA256 hash (hex-encoded)
    ///
    /// # Returns
    /// * `Ok(bytes)` - Downloaded and verified WASM bytes
    /// * `Err(_)` - Download failed or hash mismatch
    pub async fn download_wasm_from_url(
        &self,
        url: &str,
        expected_hash: &str,
    ) -> Result<Vec<u8>> {
        info!("📥 Downloading WASM from URL: {}", url);
        info!("   Expected hash: {}", expected_hash);
        info!("   Size limit: {} MB, timeout: {}s",
            MAX_WASM_SIZE_BYTES / 1024 / 1024,
            DOWNLOAD_TIMEOUT_SECONDS
        );

        let mut response = fetch_checked(url).await?;

        // Check status
        if !response.status().is_success() {
            anyhow::bail!("HTTP error: {} - {}", response.status(), url);
        }

        // Check Content-Length header before downloading
        if let Some(content_length) = response.content_length() {
            if content_length > MAX_WASM_SIZE_BYTES {
                anyhow::bail!(
                    "File too large: {} MB (max {} MB)",
                    content_length / 1024 / 1024,
                    MAX_WASM_SIZE_BYTES / 1024 / 1024
                );
            }
            info!("   Content-Length: {} bytes", content_length);
        } else {
            warn!("   Content-Length header missing, will check during download");
        }

        // Read chunk by chunk and stop at the limit: a body without (or with a
        // false) Content-Length never grows past it in memory.
        let mut downloaded_bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.context("Failed to read response body")? {
            if (downloaded_bytes.len() + chunk.len()) as u64 > MAX_WASM_SIZE_BYTES {
                anyhow::bail!("File too large (max {} MB)", MAX_WASM_SIZE_BYTES / 1024 / 1024);
            }
            downloaded_bytes.extend_from_slice(&chunk);
        }

        info!("   Downloaded: {} bytes", downloaded_bytes.len());

        // Verify SHA256 hash
        let mut hasher = Sha256::new();
        hasher.update(&downloaded_bytes);
        let actual_hash = hex::encode(hasher.finalize());

        if actual_hash != expected_hash {
            anyhow::bail!(
                "Hash mismatch!\n  Expected: {}\n  Actual:   {}\n  URL: {}",
                expected_hash,
                actual_hash,
                url
            );
        }

        info!("✅ WASM downloaded and verified: {} bytes, hash matches", downloaded_bytes.len());
        Ok(downloaded_bytes)
    }

    /// Download WASM from URL and upload to coordinator cache
    ///
    /// This function:
    /// 1. Checks if WASM already exists in cache
    /// 2. If not, downloads from URL with security protections
    /// 3. Verifies SHA256 hash
    /// 4. Uploads to coordinator cache
    ///
    /// # Arguments
    /// * `url` - URL to download from
    /// * `hash` - SHA256 hash for verification and cache key
    /// * `build_target` - Build target (for metadata)
    ///
    /// # Returns
    /// * `Ok((checksum, bytes, created_at))` - Downloaded WASM info
    pub async fn download_and_cache_wasm(
        &self,
        url: &str,
        hash: &str,
        build_target: &str,
    ) -> Result<(String, Vec<u8>, Option<String>)> {
        // For WasmUrl, the hash IS the checksum
        let checksum = hash.to_string();

        // Check if WASM already exists in cache
        let (exists, created_at) = self.api_client.wasm_exists(&checksum).await?;
        if exists {
            info!("WASM already exists in cache: {} (created: {:?})", checksum, created_at);
            // Download and return it
            let wasm_bytes = self.api_client.download_wasm(&checksum).await?;
            return Ok((checksum, wasm_bytes, created_at));
        }

        // Download from URL and verify hash
        let wasm_bytes = self.download_wasm_from_url(url, hash).await?;

        // Upload to coordinator cache
        // Note: For WasmUrl, repo="url:<url>", commit="hash:<hash>"
        info!("📤 Uploading downloaded WASM to coordinator cache...");
        self.api_client
            .upload_wasm(
                checksum.clone(),
                format!("url:{}", url),
                format!("hash:{}", hash),
                build_target.to_string(),
                wasm_bytes.clone(),
            )
            .await
            .context("Failed to upload WASM to coordinator")?;

        info!("✅ WASM downloaded and cached: {}", checksum);
        Ok((checksum, wasm_bytes, None)) // Fresh download, no created_at yet
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wasm_url_is_https_with_a_host() {
        assert!(https_url("https://wasmhub.near.fastfs.io/fastfs.near/abc.wasm").is_ok());
        assert!(https_url("https://wasmhub.near.fastfs.io:443/x.wasm").is_ok());
        assert!(https_url("https://wasmhub.near.fastfs.io:8443/x.wasm").is_err());
        assert!(https_url("https://1.2.3.4:22/x.wasm").is_err());
        assert!(https_url("http://wasmhub.near.fastfs.io/x.wasm").is_err());
        assert!(https_url("ftp://example.com/x.wasm").is_err());
        assert!(https_url("file:///etc/passwd").is_err());
        assert!(https_url("not a url").is_err());
    }

    #[tokio::test]
    async fn a_wasm_url_to_a_blocked_address_is_refused_before_any_connection() {
        // Literals and localhost resolve without the network.
        for url in [
            "https://127.0.0.1/x.wasm",
            "https://10.0.2.2/x.wasm",
            "https://169.254.169.254/latest/meta-data/",
            "https://localhost/x.wasm",
            "https://[::1]/x.wasm",
            "https://[::ffff:10.0.2.2]/x.wasm",
        ] {
            let err = fetch_checked(url).await.unwrap_err().to_string();
            assert!(err.contains("not allowed"), "{url}: {err}");
        }
    }

    /// Live: a public https URL is fetched through the checked, pinned path.
    /// `cargo test -- --ignored a_public_wasm_url_is_fetched`
    #[tokio::test]
    #[ignore]
    async fn a_public_wasm_url_is_fetched() {
        let response = fetch_checked("https://example.com/").await.expect("fetched");
        assert!(response.status().is_success(), "status {}", response.status());
    }

    #[test]
    fn test_checksum_computation() {
        // Test checksum computation without needing full Compiler struct
        let mut hasher = Sha256::new();
        hasher.update(b"https://github.com/user/repo:");
        hasher.update(b"abc123:");
        hasher.update(b"wasm32-wasip1");
        let checksum1 = hex::encode(hasher.finalize());

        let mut hasher = Sha256::new();
        hasher.update(b"https://github.com/user/repo:");
        hasher.update(b"abc123:");
        hasher.update(b"wasm32-wasip2");
        let checksum2 = hex::encode(hasher.finalize());

        // Different targets should produce different checksums
        assert_ne!(checksum1, checksum2);

        // Same inputs should produce same checksum
        let mut hasher = Sha256::new();
        hasher.update(b"https://github.com/user/repo:");
        hasher.update(b"abc123:");
        hasher.update(b"wasm32-wasip1");
        let checksum3 = hex::encode(hasher.finalize());
        assert_eq!(checksum1, checksum3);
    }
}
