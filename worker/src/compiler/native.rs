//! Native WASI compilation with env isolation (TEE-friendly)
//!
//! This module provides compilation without Docker-in-Docker, using:
//! - env -i for environment variable isolation
//! - ulimit for resource limits (memory, CPU time, processes)
//! - Temporary isolated directories for each compilation
//! - build.rs validation to prevent malicious build scripts
//!
//! Security model:
//! 1. Environment isolation (env -i clears all worker secrets)
//! 2. Process isolation (Linux kernel isolates process memory)
//! 3. Intel TDX hardware isolation (TEE protects from host)
//! 4. Resource limits prevent DoS (memory, CPU, time)
//! 5. Build.rs validation prevents code execution attacks
//! 6. Temporary directories prevent filesystem conflicts
//!
//! This is designed for TEE environments (Phala, Intel TDX) where
//! advanced sandboxing (bubblewrap, pivot_root) is blocked by seccomp.
//!
//! ## The same commit compiles to the same bytes
//!
//! The hash of the compiled wasm is what an enclave measures before running the
//! code and what a secret locked to a build is judged against, so a commit that
//! compiled to different bytes on a rebuild would quietly lock its own project
//! out. Three things here decide it: every rustc invocation is given a
//! `--remap-path-prefix` so this compilation's randomly named directory — and
//! the cargo registry under it, where every dependency's paths come from —
//! reads the same everywhere; a project that ships a Cargo.lock is held to it;
//! and when a project builds several binaries, the one that runs is chosen by
//! name rather than by directory order.
//!
//! What is left outside this module: the toolchain. A different rustc, or a
//! different wasi-sdk, compiles the same source to different bytes, so the
//! guarantee is per compiler image. `scripts/build_github_wasm.sh` runs this
//! same recipe in a named image, which is how a hash can be known before
//! publishing.

use anyhow::{Context, Result};
use bollard::Docker;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use sha2::{Digest, Sha256};
use tokio::process::Command;
use tracing::{debug, error, info, warn};

use crate::compiler::CompilationError;

/// Maximum memory for compilation (bytes): 2GB
const MAX_MEMORY_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Maximum CPU time for compilation (seconds): 300s = 5 minutes
const MAX_CPU_TIME_SECONDS: u64 = 300;

/// Maximum number of processes during compilation
const MAX_PROCESSES: u32 = 1024;

/// Compile WASM using native Rust toolchain with bubblewrap sandboxing
///
/// # Arguments
/// * `repo` - GitHub repository URL (e.g., "https://github.com/user/repo")
/// * `commit` - Git commit hash or branch name
/// * `build_target` - WASM target (wasm32-wasip1, wasm32-wasip2)
/// * `timeout_seconds` - Optional timeout override
///
/// # Returns
/// * `Ok(Vec<u8>)` - Compiled WASM binary
/// * `Err(CompilationError)` - Compilation failed with user-friendly error
///
/// # Security
/// - Environment isolation: env -i clears all worker secrets (OPERATOR_PRIVATE_KEY, etc.)
/// - Process isolation: Linux kernel prevents reading worker memory
/// - Hardware isolation: Intel TDX protects from host and other processes
/// - Resource limits: 2GB RAM, 5min CPU time, 1024 processes (ulimit)
/// - Build.rs validation: rejects projects with build scripts
/// - Temporary directories: compilation isolated in /tmp/compile-{uuid}
///
/// # Determinism
/// For one compiler image, the same commit yields the same bytes; see the
/// module documentation.
pub async fn compile(
    _docker: Option<&Docker>, // Unused in native mode
    repo: &str,
    commit: &str,
    build_target: &str,
    timeout_seconds: Option<u64>,
) -> Result<Vec<u8>> {
    let timeout = timeout_seconds.unwrap_or(MAX_CPU_TIME_SECONDS);

    info!("🔨 Native compilation: {} @ {} ({})", repo, commit, build_target);
    info!("⏱️  Timeout: {}s, Memory limit: {}MB", timeout, MAX_MEMORY_BYTES / 1024 / 1024);

    // 1. Create isolated working directory
    let work_dir = create_temp_dir("compile-")?;
    info!("📁 Work directory: {}", work_dir.display());

    // The rustc shim lives outside the cloned tree. Inside it, a repository
    // that ships a file of the same name is written through — and if that file
    // is a symlink, the write lands wherever it points, as the worker.
    let tools_dir = create_temp_dir("outlayer-tools-")?;

    let result = async {
        // 2. Clone repository (outside sandbox, faster)
        clone_repo(repo, commit, &work_dir).await?;

        // 3. Validate no build.rs (security check)
        validate_no_build_scripts(&work_dir)?;

        // 4. Compile with env isolation + ulimit
        compile_with_isolation(&work_dir, &tools_dir, build_target, timeout).await
    }
    .await;

    // 5. Cleanup. Both directories go whether the build succeeded or not; a
    // failed build reports through CompilationError, which already carries the
    // compiler's stderr, so nothing is learned from the leftover tree.
    for dir in [&work_dir, &tools_dir] {
        if let Err(e) = cleanup_dir(dir) {
            warn!("Failed to clean up {}: {}", dir.display(), e);
        }
    }

    let wasm_bytes = result?;

    // The hash of the bytes themselves — what the keystore judges a secret
    // locked to a build against, and what a reproducible build must land on
    // again. Named here so an operator can read it out of the compile log.
    info!(
        "✅ Compilation successful: {} bytes, sha256 {}",
        wasm_bytes.len(),
        hex::encode(Sha256::digest(&wasm_bytes))
    );
    Ok(wasm_bytes)
}

/// Create temporary directory for compilation
fn create_temp_dir(prefix: &str) -> Result<PathBuf> {
    // Use `tempfile` instead of a hand-built `/tmp/compile-{uuid}` path. The native compiler
    // (git clone + cargo build) runs OUTSIDE the TEE, so it can share a host with other
    // processes; `/tmp` is world-writable and `compile-{uuid}` is a guessable name, which
    // opens a TOCTOU / symlink-pre-creation race and lets a co-tenant read the cloned source
    // or build artifacts. `tempfile` creates the directory with 0700 permissions and a random,
    // unguessable suffix. We `keep()` (persist past the guard's Drop) so the existing manual
    // `cleanup_dir()` lifecycle still applies — the caller removes it after compilation.
    let dir = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir()
        .context("Failed to create secure temp dir")?
        .keep();

    Ok(dir)
}

/// Maximum time for a git clone operation (shallow clone with --branch)
const GIT_SHALLOW_CLONE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
/// Maximum time for a full git clone (fallback for commit hashes)
const GIT_FULL_CLONE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);
/// Maximum time for a git checkout operation
const GIT_CHECKOUT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Run a git command with a timeout, killing the process if it exceeds the limit
async fn run_git_with_timeout(
    args: &[&str],
    work_dir: &Path,
    timeout: std::time::Duration,
    operation: &str,
) -> Result<std::process::Output> {
    let fut = tokio::process::Command::new("git")
        .args(args)
        .current_dir(work_dir)
        .kill_on_drop(true)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();

    match tokio::time::timeout(timeout, fut).await {
        Ok(result) => result.with_context(|| format!("git {} failed", operation)),
        Err(_) => {
            anyhow::bail!(
                "Git {} timed out after {}s. The repository may be too large or the ref is invalid.",
                operation, timeout.as_secs()
            );
        }
    }
}

/// Reject argument/transport injection and clone-time SSRF before the value
/// reaches `git`. A repo like `ext::sh -c …` is arbitrary command execution via
/// git's `ext` transport; `file://` reads the host FS; a leading `-` is parsed
/// by git as an option (`--upload-pack=…`); and an arbitrary `https://<host>`
/// would let a guest clone from internal/attacker hosts. We require a plain
/// https URL pinned to github.com.
pub(crate) fn validate_repo_url(repo: &str) -> Result<()> {
    let rest = repo
        .strip_prefix("https://")
        .ok_or_else(|| anyhow::anyhow!("Invalid repo URL (must start with https://): {}", repo))?;
    if repo.len() > 512 || repo.contains(|c: char| c.is_whitespace() || c.is_control()) {
        anyhow::bail!("Invalid repo URL (too long or contains whitespace/control chars)");
    }
    // Authority = text before the first '/', after any `user@`, minus `:port`.
    // (`github.com@evil.com` correctly resolves to host evil.com and is rejected.)
    let authority = rest.split('/').next().unwrap_or("");
    let host = authority.rsplit('@').next().unwrap_or(authority);
    let host = host.split(':').next().unwrap_or(host);
    if host != "github.com" && host != "codeload.github.com" {
        anyhow::bail!("Invalid repo host (only github.com is allowed): {}", repo);
    }
    Ok(())
}

/// A git ref (branch/tag/commit) must not start with `-` (option injection) and
/// must use a safe charset.
pub(crate) fn validate_git_ref(r: &str) -> Result<()> {
    if r.is_empty() || r.starts_with('-') {
        anyhow::bail!("Invalid git ref (empty or starts with '-'): {}", r);
    }
    if r.len() > 256
        || r.contains("..")
        || !r.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '-' | '+'))
    {
        anyhow::bail!("Invalid git ref (illegal characters): {}", r);
    }
    Ok(())
}

/// Clone Git repository
async fn clone_repo(repo: &str, commit: &str, work_dir: &Path) -> Result<()> {
    // Validate untrusted inputs before they reach git (see fns above).
    validate_repo_url(repo)?;
    validate_git_ref(commit)?;

    info!("📥 Cloning {} @ {}", repo, commit);

    // Try shallow clone at the specific ref first (works for branches and tags).
    // `--` terminates option parsing so `repo` can never be read as a flag.
    let output = run_git_with_timeout(
        &["clone", "--depth", "1", "--branch", commit, "--", repo, "."],
        work_dir,
        GIT_SHALLOW_CLONE_TIMEOUT,
        "clone --branch",
    ).await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);

        // If --branch failed (e.g. commit hash), fall back to shallow fetch by hash
        // Uses git init + fetch --depth 1 to avoid cloning entire history (DoS protection)
        if stderr.contains("not found in upstream") || stderr.contains("Remote branch") {
            let output = run_git_with_timeout(
                &["init"],
                work_dir,
                GIT_CHECKOUT_TIMEOUT,
                "init",
            ).await?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                anyhow::bail!("Git init failed: {}", stderr);
            }

            let output = run_git_with_timeout(
                &["remote", "add", "origin", repo],
                work_dir,
                GIT_CHECKOUT_TIMEOUT,
                "remote add",
            ).await?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                anyhow::bail!("Git remote add failed: {}", stderr);
            }

            let output = run_git_with_timeout(
                &["fetch", "--depth", "1", "origin", commit],
                work_dir,
                GIT_FULL_CLONE_TIMEOUT,
                "fetch",
            ).await?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                if stderr.contains("Repository not found") || stderr.contains("not found") {
                    classify_clone_error(&stderr, repo)?;
                }
                anyhow::bail!("Git fetch failed for '{}': {}. Make sure the commit hash exists.", commit, stderr);
            }

            let output = run_git_with_timeout(
                &["checkout", "FETCH_HEAD"],
                work_dir,
                GIT_CHECKOUT_TIMEOUT,
                "checkout",
            ).await?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                anyhow::bail!("Git checkout failed for '{}': {}", commit, stderr);
            }
        } else {
            classify_clone_error(&stderr, repo)?;
        }
    }

    info!("✅ Repository cloned");
    Ok(())
}

/// Classify git clone errors into user-friendly messages
fn classify_clone_error(stderr: &str, repo: &str) -> Result<()> {
    if stderr.contains("Repository not found") || stderr.contains("not found") {
        anyhow::bail!("Repository not found: {}. Please check the URL is correct and the repository is public.", repo);
    } else if stderr.contains("could not read Username") || stderr.contains("authentication") {
        anyhow::bail!("Cannot access repository: {}. Only public repositories are supported.", repo);
    } else {
        anyhow::bail!("Git clone failed: {}", stderr);
    }
}

/// Validate that project doesn't use build.rs or git dependencies (security requirement)
///
/// Build scripts can execute arbitrary code during compilation, which is a security risk.
/// We reject projects with build.rs to prevent:
/// - Reading worker environment variables (secrets, keys)
/// - Accessing dstack.sock or other sensitive files
/// - Network exfiltration of data
///
/// Git dependencies are also rejected because:
/// - They bypass crates.io verification
/// - Can point to malicious or unreviewed code
/// - Enable typosquatting attacks (git = "https://evil.com/fake-serde")
fn validate_no_build_scripts(work_dir: &Path) -> Result<()> {
    let cargo_toml_path = work_dir.join("Cargo.toml");

    if !cargo_toml_path.exists() {
        anyhow::bail!("Cargo.toml not found in repository");
    }

    let cargo_toml = std::fs::read_to_string(&cargo_toml_path)
        .context("Failed to read Cargo.toml")?;

    // Judge the manifest's code, not its prose. A `#` starts a TOML comment, and
    // repositories routinely leave the rejected forms in one as a note to the
    // reader — `# outlayer = { git = "https://…" }` is in an OutLayer example —
    // so a match against the raw text refuses projects that declare nothing of
    // the kind. Truncating at the first `#` can only ever make a line shorter,
    // and a URL that really carried a fragment still matches on the half before
    // it, so nothing that should be refused escapes.
    let cargo_toml: String = cargo_toml
        .lines()
        .map(|line| line.split('#').next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n");

    // Check for build = "build.rs" or build = 'build.rs' with flexible whitespace
    // Matches: build = "...", build="...", build  =  "...", etc.
    let build_patterns = [
        "build\\s*=",  // build = or build=
    ];

    for pattern in &build_patterns {
        let regex = regex::Regex::new(pattern).unwrap();
        if regex.is_match(&cargo_toml) {
            return Err(CompilationError {
                user_message: "Security: build.rs scripts are not allowed. Please remove the build script from your Cargo.toml. Build scripts can execute arbitrary code during compilation and access sensitive data.".to_string(),
                stderr: "Cargo.toml contains 'build =' directive".to_string(),
                stdout: String::new(),
                exit_code: None,
            }.into());
        }
    }

    // Check for git dependencies: git = "https://..." or git = 'https://...'
    // Matches: git = "https://...", git="https://...", git = "http://...", etc.
    let git_dep_regex = regex::Regex::new(r#"git\s*=\s*["']https?://"#).unwrap();
    if git_dep_regex.is_match(&cargo_toml) {
        return Err(CompilationError {
            user_message: "Security: Git dependencies are not allowed. Please use published crates from crates.io only. Git dependencies bypass crates.io verification and can point to malicious code. This protects against typosquatting attacks like git = 'https://evil.com/fake-serde'.".to_string(),
            stderr: "Cargo.toml contains git dependency".to_string(),
            stdout: String::new(),
            exit_code: None,
        }.into());
    }

    // Check for common dependencies that require build.rs
    let dangerous_deps = [
        ("ring", "ring requires build.rs for native crypto compilation"),
        ("openssl-sys", "openssl-sys requires build.rs"),
        ("libsodium-sys", "libsodium-sys requires build.rs"),
        ("secp256k1-sys", "secp256k1-sys requires build.rs"),
    ];

    for (dep, reason) in &dangerous_deps {
        if cargo_toml.contains(dep) {
            warn!("⚠️  Detected potentially problematic dependency: {}", dep);
            warn!("⚠️  Reason: {}", reason);
            // Note: We log but don't reject, as some deps might work without build.rs
        }
    }

    info!("✅ Validation passed: no build.rs, no git dependencies");
    Ok(())
}

/// Compile with env isolation and ulimit (TEE-friendly, no pivot_root)
async fn compile_with_isolation(
    work_dir: &Path,
    tools_dir: &Path,
    build_target: &str,
    timeout: u64,
) -> Result<Vec<u8>> {
    info!("🔒 Starting compilation with env isolation + ulimit");

    // Prepare cargo home directory inside work_dir
    let cargo_home = work_dir.join(".cargo");
    std::fs::create_dir_all(&cargo_home)
        .context("Failed to create .cargo directory")?;

    // The shim that keeps the work directory out of the compiled bytes.
    let rustc_shim = write_rustc_shim(tools_dir, work_dir)?;

    let locked = locked_flag(work_dir);

    // Build cargo command with resource limits
    // ulimit is executed inside bash, before cargo build
    // Export PATH explicitly so cargo can be found
    let cargo_cmd = format!(
        "export PATH=/usr/local/cargo/bin:/usr/local/bin:/usr/bin:/bin && export RUSTUP_HOME=/usr/local/rustup && ulimit -v {} && ulimit -t {} && ulimit -u {} && cargo build --target {} --release{}",
        MAX_MEMORY_BYTES / 1024, // ulimit -v expects KB
        timeout,
        MAX_PROCESSES,
        build_target,
        locked
    );

    info!("Cargo command: {}", cargo_cmd);

    // Use env -i to clear all environment variables
    // Then set only safe variables needed for compilation
    let mut cmd = Command::new("env");
    cmd.arg("-i"); // Clear all env vars

    // Set only safe environment variables
    cmd.env("HOME", work_dir.to_str().unwrap());
    cmd.env("CARGO_HOME", cargo_home.to_str().unwrap());
    cmd.env("PATH", "/usr/local/cargo/bin:/usr/local/bin:/usr/bin:/bin");
    cmd.env("RUST_BACKTRACE", "1"); // For debugging compilation errors
    cmd.env("RUSTUP_HOME", "/usr/local/rustup"); // Rustup installation directory
    cmd.env("RUSTC_WRAPPER", &rustc_shim); // see write_rustc_shim

    // WASI SDK environment (for C dependencies like ring, openssl-sys)
    cmd.env("CC_wasm32_wasip1", "/opt/wasi-sdk/bin/clang");
    cmd.env("AR_wasm32_wasip1", "/opt/wasi-sdk/bin/llvm-ar");
    cmd.env("CARGO_TARGET_WASM32_WASIP1_LINKER", "/opt/wasi-sdk/bin/clang");

    // DO NOT SET (these are worker secrets):
    // - OPERATOR_PRIVATE_KEY
    // - API_AUTH_TOKEN
    // - KEYSTORE_AUTH_TOKEN
    // - Any other sensitive environment variables

    // Execute bash -c with the cargo command (bash required for ulimit -u)
    cmd.arg("bash");
    cmd.arg("-c");
    cmd.arg(&cargo_cmd);

    // Set working directory
    cmd.current_dir(work_dir);

    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    info!("Executing: env -i bash -c '{}'", cargo_cmd);

    // Spawn process
    let child = cmd.spawn()
        .context("Failed to spawn compilation process")?;

    // Wait with timeout
    let output = tokio::time::timeout(
        Duration::from_secs(timeout + 10), // Extra 10s buffer
        child.wait_with_output(),
    )
    .await
    .context("Compilation timeout exceeded")??;

    // Check exit code
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();

        error!("❌ Compilation failed");
        error!("STDERR: {}", stderr);
        error!("STDOUT: {}", stdout);

        // Classify error for user-friendly message
        let (_category, user_message) = classify_compilation_error(&stderr, output.status.code());

        return Err(CompilationError {
            user_message: user_message.to_string(),
            stderr,
            stdout,
            exit_code: output.status.code().map(|c| c as i32),
        }.into());
    }

    info!("✅ Compilation finished, extracting WASM");

    // Find compiled WASM file
    let wasm_path = find_wasm_file(work_dir, build_target)?;

    // Read WASM bytes
    let wasm_bytes = std::fs::read(&wasm_path)
        .with_context(|| format!("Failed to read WASM file: {}", wasm_path.display()))?;

    info!("✅ WASM extracted: {} bytes from {}", wasm_bytes.len(), wasm_path.display());

    Ok(wasm_bytes)
}

/// `--locked`, when the repository pinned its dependencies.
///
/// Without a Cargo.lock cargo resolves against whatever crates.io offers at
/// build time, so one commit compiles to different bytes on different days and
/// a secret locked to a build stops opening for a project nobody touched. With
/// one, the resolution is part of the commit and cargo is held to it.
///
/// A repository that ships no lock still builds. Refusing it would break
/// projects that run today, and the damage it does is to liveness, not to
/// safety: an unexpected rebuild fails to open the secret rather than opening
/// it for the wrong bytes.
fn locked_flag(work_dir: &Path) -> &'static str {
    if work_dir.join("Cargo.lock").exists() {
        " --locked"
    } else {
        warn!(
            "⚠️  No Cargo.lock in the repository: dependency versions are resolved at build time, \
             so this commit will not compile to the same bytes on a later day"
        );
        ""
    }
}

/// What the build directory is called inside the compiled binary.
///
/// Any fixed string would do; the point is that it is the same one on every
/// machine, so two builds of one commit agree.
const REMAPPED_BUILD_DIR: &str = "/outlayer/build";

/// Write the rustc shim that keeps the build directory out of the binary.
///
/// Dependency source paths reach the binary through debug info and through the
/// line numbers a panic prints, and they are absolute — rooted at the cargo
/// registry, which lives under this compilation's own randomly named
/// directory. Two builds of the same commit therefore differ, which is enough
/// to make a secret locked to a build unopenable. `--remap-path-prefix` rewrites
/// that root to a constant.
///
/// A shim rather than `RUSTFLAGS`: cargo does not merge rustflags across
/// layers — the highest-priority source wins outright — so exporting the
/// variable would silently discard a `.cargo/config.toml` the repository ships,
/// and a project that asks for a larger stack would compile into something that
/// no longer runs. Flags appended by the shim compose with every layer instead
/// of replacing one.
fn write_rustc_shim(tools_dir: &Path, work_dir: &Path) -> Result<PathBuf> {
    let from = work_dir
        .to_str()
        .context("Work directory path is not valid UTF-8")?;
    // The path is interpolated into a shell script inside single quotes, so a
    // quote or a newline in it would end the string and run as script. It comes
    // from `tempfile` under the system temp directory and cannot normally hold
    // either; refuse rather than assume.
    if from.contains('\'') || from.contains('\n') {
        anyhow::bail!("Work directory path contains a quote or newline: {}", from);
    }

    let script = format!(
        "#!/bin/sh\n\
         # Written by the OutLayer compiler. cargo runs this in place of rustc,\n\
         # as `shim rustc <args>`, so the flag below is appended to every\n\
         # invocation without replacing any the project set for itself.\n\
         exec \"$@\" --remap-path-prefix='{from}'={REMAPPED_BUILD_DIR}\n"
    );

    let path = tools_dir.join("rustc-shim.sh");
    std::fs::write(&path, script)
        .with_context(|| format!("Failed to write rustc shim: {}", path.display()))?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
        .context("Failed to make the rustc shim executable")?;

    Ok(path)
}

/// Find compiled WASM file in target directory
fn find_wasm_file(work_dir: &Path, build_target: &str) -> Result<PathBuf> {
    let target_dir = work_dir.join("target").join(build_target).join("release");

    if !target_dir.exists() {
        anyhow::bail!("Target directory not found: {}", target_dir.display());
    }

    // Collect every .wasm the build produced and sort them. Directory order is
    // whatever the filesystem hands back, so a project that builds more than one
    // binary would otherwise have one of them picked at random — a different one
    // on a rebuild, and the hash of the bytes the enclave attests changing with
    // it. Sorted, the choice is a property of the project rather than of the run.
    let mut candidates: Vec<PathBuf> = std::fs::read_dir(&target_dir)
        .with_context(|| format!("Failed to read target directory: {}", target_dir.display()))?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| path.extension().and_then(|s| s.to_str()) == Some("wasm"))
        .collect();
    candidates.sort();

    let chosen = candidates
        .first()
        .ok_or_else(|| anyhow::anyhow!("No .wasm file found in {}", target_dir.display()))?;

    if candidates.len() > 1 {
        let names: Vec<&str> = candidates
            .iter()
            .filter_map(|p| p.file_name().and_then(|n| n.to_str()))
            .collect();
        warn!(
            "⚠️  The project built {} wasm binaries ({}); running the first by name. \
             Build one binary per project if that is not the one you meant.",
            candidates.len(),
            names.join(", ")
        );
    }

    Ok(chosen.clone())
}

/// Classify compilation error for user-friendly message
fn classify_compilation_error(stderr: &str, exit_code: Option<i32>) -> (&'static str, &'static str) {
    let stderr_lower = stderr.to_lowercase();

    // Git errors
    if stderr_lower.contains("fatal: repository") && stderr_lower.contains("not found") {
        return ("repository_not_found", "Repository not found. Please check that the repository URL is correct and publicly accessible.");
    }

    if stderr_lower.contains("fatal: could not read username") || stderr_lower.contains("authentication") {
        return ("repository_access_denied", "Cannot access repository. The repository may be private or the URL may be incorrect. Only public repositories are supported.");
    }

    // The lock file does not match Cargo.toml. The build is refused rather than
    // resolved afresh, because resolving afresh is what makes one commit compile
    // to different bytes on different days.
    if stderr_lower.contains("lock file") && stderr_lower.contains("needs to be updated") {
        return ("lockfile_out_of_date", "Cargo.lock does not match Cargo.toml. Run `cargo update` (or `cargo build`) locally, commit the updated Cargo.lock, and publish that commit. The lock file is what makes your project compile to the same bytes every time, which is what a secret locked to a build depends on.");
    }

    // A project with no lock file at all resolves its dependencies at build
    // time, so the same commit can stop compiling when a dependency publishes.
    if stderr_lower.contains("no matching package named") && stderr_lower.contains("found") {
        return ("dependency_not_found", "Dependency resolution failed. One or more dependencies in Cargo.toml could not be found. If your project has no Cargo.lock, commit one: without it the versions are chosen afresh on every build.");
    }

    // Rust compilation errors
    if stderr_lower.contains("error[e") || stderr_lower.contains("error: could not compile") {
        return ("rust_compilation_error", "Rust compilation failed. Your code contains syntax errors or type errors. Please check your Rust code for correctness.");
    }

    // Dependency errors
    if stderr_lower.contains("error: no matching package") || stderr_lower.contains("failed to select a version") {
        return ("dependency_not_found", "Dependency resolution failed. One or more dependencies specified in Cargo.toml could not be found or resolved.");
    }

    // Build script errors (should be caught earlier, but just in case)
    if stderr_lower.contains("build.rs") || stderr_lower.contains("build script") {
        return ("build_script_error", "Build script detected. Build scripts (build.rs) are not allowed for security reasons. Please remove the build script from your project.");
    }

    // Resource limit errors
    if stderr_lower.contains("out of memory") || stderr_lower.contains("cannot allocate memory") {
        return ("out_of_memory", "Compilation ran out of memory. Please reduce the complexity of your project or optimize dependencies.");
    }

    // Timeout
    if exit_code == Some(137) { // SIGKILL
        return ("timeout", "Compilation timeout exceeded. Please reduce compilation time or simplify your project.");
    }

    // Generic error
    ("compilation_error", "Compilation failed. Please check your code and try again. See documentation for supported features.")
}

/// Cleanup temporary directory
fn cleanup_dir(work_dir: &Path) -> Result<()> {
    if work_dir.exists() {
        std::fs::remove_dir_all(work_dir)
            .with_context(|| format!("Failed to remove temp dir: {}", work_dir.display()))?;
        debug!("🧹 Cleaned up: {}", work_dir.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_rejects_build_rs() {
        let temp_dir = std::env::temp_dir().join("test-build-rs");
        std::fs::create_dir_all(&temp_dir).unwrap();

        let cargo_toml = temp_dir.join("Cargo.toml");
        std::fs::write(&cargo_toml, r#"
[package]
name = "test"
version = "0.1.0"
build = "build.rs"
        "#).unwrap();

        let result = validate_no_build_scripts(&temp_dir);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("build.rs"));

        std::fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn test_validate_rejects_build_rs_with_extra_spaces() {
        let temp_dir = std::env::temp_dir().join("test-build-rs-spaces");
        std::fs::create_dir_all(&temp_dir).unwrap();

        let cargo_toml = temp_dir.join("Cargo.toml");
        std::fs::write(&cargo_toml, r#"
[package]
name = "test"
version = "0.1.0"
build  =  "build.rs"
        "#).unwrap();

        let result = validate_no_build_scripts(&temp_dir);
        assert!(result.is_err(), "Should reject build.rs with extra spaces");
        assert!(result.unwrap_err().to_string().contains("build.rs"));

        std::fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn test_validate_rejects_git_dependencies() {
        let temp_dir = std::env::temp_dir().join("test-git-dep");
        std::fs::create_dir_all(&temp_dir).unwrap();

        let cargo_toml = temp_dir.join("Cargo.toml");
        std::fs::write(&cargo_toml, r#"
[package]
name = "test"
version = "0.1.0"

[dependencies]
serde = { git = "https://evil.com/fake-serde" }
        "#).unwrap();

        let result = validate_no_build_scripts(&temp_dir);
        assert!(result.is_err(), "Should reject git dependencies");
        assert!(result.unwrap_err().to_string().contains("Git dependencies are not allowed"));

        std::fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn test_validate_accepts_clean_project() {
        let temp_dir = std::env::temp_dir().join("test-clean");
        std::fs::create_dir_all(&temp_dir).unwrap();

        let cargo_toml = temp_dir.join("Cargo.toml");
        std::fs::write(&cargo_toml, r#"
[package]
name = "test"
version = "0.1.0"

[dependencies]
serde = "1.0"
serde_json = "1.0"
        "#).unwrap();

        let result = validate_no_build_scripts(&temp_dir);
        assert!(result.is_ok(), "Should accept clean project with crates.io deps");

        std::fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn test_classify_compilation_error() {
        let (category, msg) = classify_compilation_error("error[E0425]: cannot find value", None);
        assert_eq!(category, "rust_compilation_error");
        assert!(msg.contains("syntax errors"));

        let (category, msg) = classify_compilation_error("fatal: repository not found", Some(128));
        assert_eq!(category, "repository_not_found");
        assert!(msg.contains("Repository not found"));
    }

    #[test]
    fn validate_repo_url_accepts_https_github() {
        assert!(validate_repo_url("https://github.com/owner/repo").is_ok());
        assert!(validate_repo_url("https://github.com/owner/repo.git").is_ok());
        assert!(validate_repo_url("https://tok@github.com/owner/repo").is_ok());
    }

    #[test]
    fn validate_repo_url_rejects_transport_and_option_injection() {
        // git `ext::` transport = arbitrary command execution
        assert!(validate_repo_url("ext::sh -c 'touch /tmp/pwned'").is_err());
        // file:// reads the host filesystem
        assert!(validate_repo_url("file:///etc/passwd").is_err());
        // leading '-' is parsed by git as an option
        assert!(validate_repo_url("--upload-pack=evil").is_err());
        // non-https / unnormalized forms — validate_repo_url is the gate itself,
        // it does not depend on normalize() pinning anything
        assert!(validate_repo_url("git@github.com:owner/repo").is_err());
        assert!(validate_repo_url("ssh://git@github.com/owner/repo").is_err());
        assert!(validate_repo_url("http://github.com/owner/repo").is_err());
        assert!(validate_repo_url("owner/repo").is_err());
        // whitespace / control chars
        assert!(validate_repo_url("https://github.com/a repo").is_err());
        // clone-time SSRF / arbitrary host — must be pinned to github.com
        assert!(validate_repo_url("https://169.254.169.254/x").is_err());
        assert!(validate_repo_url("https://attacker.tld/owner/repo").is_err());
        assert!(validate_repo_url("https://github.com.evil.com/x").is_err());
        assert!(validate_repo_url("https://github.com@evil.com/x").is_err()); // userinfo confusion
    }

    #[test]
    fn validate_git_ref_accepts_normal_refs() {
        assert!(validate_git_ref("main").is_ok());
        assert!(validate_git_ref("v1.2.3").is_ok());
        assert!(validate_git_ref("release/2024-01").is_ok());
        assert!(validate_git_ref("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0").is_ok()); // 40-hex sha
    }

    #[test]
    fn validate_git_ref_rejects_option_injection_and_bad_chars() {
        assert!(validate_git_ref("--upload-pack=evil").is_err()); // option injection (fetch fallback)
        assert!(validate_git_ref("-x").is_err());
        assert!(validate_git_ref("").is_err());
        assert!(validate_git_ref("a b").is_err()); // space
        assert!(validate_git_ref("foo;bar").is_err()); // outside safe charset
        assert!(validate_git_ref("foo$(id)").is_err());
        assert!(validate_git_ref("../../etc/passwd").is_err()); // '..'
    }
}

/// A build of one commit must land on the same bytes every time — that is what
/// a secret locked to a build is judged against, and what an attestation names.
/// These cover the three things in this module that decide it: the paths the
/// compiler bakes in, the dependency versions it picks, and which of the
/// produced binaries is the one that runs.
#[cfg(test)]
mod the_same_commit_compiles_to_the_same_bytes {
    use super::*;
    use std::process::Command as SyncCommand;

    #[test]
    fn the_shim_runs_what_cargo_asked_for_and_appends_the_remap() {
        let tools = tempfile::tempdir().unwrap();
        let work = tempfile::tempdir().unwrap();
        let shim = write_rustc_shim(tools.path(), work.path()).unwrap();

        // cargo invokes a wrapper as `wrapper <program> <args…>`. Standing in
        // for rustc with `echo` shows both that the program is run and that the
        // arguments reach it untouched, with ours added at the end.
        let out = SyncCommand::new(&shim)
            .args(["echo", "--crate-name", "demo"])
            .output()
            .expect("the shim must be executable");
        let printed = String::from_utf8_lossy(&out.stdout).trim().to_string();

        assert_eq!(
            printed,
            format!(
                "--crate-name demo --remap-path-prefix={}={}",
                work.path().display(),
                REMAPPED_BUILD_DIR
            ),
            "the shim must pass cargo's arguments through and append the remap"
        );
    }

    #[test]
    fn the_remap_covers_the_registry_the_dependencies_are_read_from() {
        // Dependency paths are the ones that leak: they are absolute, and they
        // are rooted at CARGO_HOME, which this compiler puts inside the work
        // directory. A remap of the work directory only helps because it covers
        // that too — if CARGO_HOME ever moves out, this test fails and says so.
        let work = tempfile::tempdir().unwrap();
        let cargo_home = work.path().join(".cargo");
        assert!(
            cargo_home.starts_with(work.path()),
            "CARGO_HOME must sit under the remapped work directory"
        );
    }

    #[test]
    fn a_work_directory_that_cannot_be_quoted_is_refused() {
        let tools = tempfile::tempdir().unwrap();
        let parent = tempfile::tempdir().unwrap();
        // A quote in the path would close the shell string the path is written
        // into, and the rest of it would run as script.
        let hostile = parent.path().join("it's-here");
        std::fs::create_dir(&hostile).unwrap();

        let err = write_rustc_shim(tools.path(), &hostile)
            .expect_err("a path with a quote must be refused, not escaped by hand");
        assert!(
            err.to_string().contains("quote"),
            "the refusal must say why: {err}"
        );
    }

    #[test]
    fn a_lock_file_is_what_turns_on_locked() {
        let work = tempfile::tempdir().unwrap();
        assert_eq!(
            locked_flag(work.path()),
            "",
            "a project with no lock file still builds"
        );

        std::fs::write(work.path().join("Cargo.lock"), "# pinned\n").unwrap();
        assert_eq!(
            locked_flag(work.path()),
            " --locked",
            "a pinned project must be held to its lock, not re-resolved"
        );
    }

    #[test]
    fn the_binary_that_runs_is_chosen_by_name_not_by_directory_order() {
        let work = tempfile::tempdir().unwrap();
        let release = work.path().join("target").join("wasm32-wasip1").join("release");
        std::fs::create_dir_all(&release).unwrap();
        // Written in the reverse of the order they must be chosen in, so a
        // function that returned whatever the directory listed first would have
        // to get lucky to pass.
        for name in ["zeta.wasm", "beta.wasm", "alpha.wasm", "notes.txt"] {
            std::fs::write(release.join(name), b"\0asm").unwrap();
        }

        let chosen = find_wasm_file(work.path(), "wasm32-wasip1").unwrap();
        assert_eq!(
            chosen.file_name().unwrap(),
            "alpha.wasm",
            "with several binaries the choice must be a property of the project, \
             not of the filesystem"
        );
    }

    #[test]
    fn a_build_that_produced_no_wasm_is_an_error() {
        let work = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(work.path().join("target/wasm32-wasip1/release")).unwrap();
        assert!(find_wasm_file(work.path(), "wasm32-wasip1").is_err());
    }

    #[test]
    fn a_rejected_form_inside_a_comment_is_not_a_rejected_form() {
        // Taken from out-layer/test-secrets-example, which carries the git
        // dependency form in a comment as a note for people copying the file.
        // Refusing it would refuse one of the platform's own examples.
        let work = tempfile::tempdir().unwrap();
        std::fs::write(
            work.path().join("Cargo.toml"),
            r#"
[package]
name = "example"
version = "0.1.0"
# build = "build.rs" is not allowed here
[dependencies]
# For external projects after publishing: outlayer = { git = "https://github.com/out-layer/outlayer" }
outlayer = "0.1.0"
"#,
        )
        .unwrap();
        assert!(
            validate_no_build_scripts(work.path()).is_ok(),
            "a commented-out git dependency is prose, not a dependency"
        );
    }

    #[test]
    fn a_rejected_form_outside_a_comment_is_still_refused() {
        for manifest in [
            "[package]\nname = \"x\"\nbuild = \"build.rs\"\n",
            "[dependencies]\nserde = { git = \"https://evil.example/serde\" }\n",
            "[dependencies]\nserde = \"1\"  # pinned\nfoo = { git = \"https://evil.example/foo\" }\n",
        ] {
            let work = tempfile::tempdir().unwrap();
            std::fs::write(work.path().join("Cargo.toml"), manifest).unwrap();
            assert!(
                validate_no_build_scripts(work.path()).is_err(),
                "not refused: {manifest}"
            );
        }
    }

    #[test]
    fn a_stale_lock_file_is_explained_rather_than_resolved_away() {
        // What cargo says when `--locked` meets a Cargo.lock that no longer
        // matches Cargo.toml. The user has to be told to commit the lock; the
        // generic "check your code" message would send them looking in the
        // wrong place.
        let (category, message) = classify_compilation_error(
            "error: the lock file /outlayer/build/Cargo.lock needs to be updated but --locked was passed to prevent this\n",
            Some(101),
        );
        assert_eq!(category, "lockfile_out_of_date");
        assert!(
            message.contains("Cargo.lock"),
            "the message must name the file to commit: {message}"
        );
    }
}
