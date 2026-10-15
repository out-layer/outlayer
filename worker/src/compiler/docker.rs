//! Docker container operations for WASM compilation

use anyhow::{Context, Result};
use bollard::container::{Config as ContainerConfig, CreateContainerOptions, RemoveContainerOptions, DownloadFromContainerOptions};
use bollard::exec::{CreateExecOptions, StartExecResults};
use bollard::image::CreateImageOptions;
use bollard::Docker;
use futures_util::stream::StreamExt;
use futures_util::TryStreamExt;
use tracing::{debug, error, info, warn};

use crate::config::Config;

/// Compilation error with both user-facing description and raw logs for admin
#[derive(Debug)]
pub struct CompilationError {
    pub user_message: String,
    pub stderr: String,
    pub stdout: String,
    pub exit_code: Option<i32>,
}

impl std::fmt::Display for CompilationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Compilation failed: {}", self.user_message)
    }
}

impl std::error::Error for CompilationError {}

/// Ensure Docker image is available (pull if needed)
pub async fn ensure_image(docker: &Docker, image: &str) -> Result<()> {
    info!("Ensuring Docker image is available: {}", image);

    let mut stream = docker.create_image(
        Some(CreateImageOptions {
            from_image: image.to_string(),
            ..Default::default()
        }),
        None,
        None,
    );

    while let Some(result) = stream.next().await {
        match result {
            Ok(info_msg) => {
                if let Some(status) = info_msg.status {
                    debug!("Docker: {}", status);
                }
            }
            Err(e) => {
                error!("Failed to pull Docker image: {}", e);
                return Err(e.into());
            }
        }
    }

    info!("Docker image ready: {}", image);
    Ok(())
}

/// Create and start a Docker container for compilation
///
/// Not a sandbox for untrusted code: root, the `bridge` network (the host's
/// docker0 listeners and the internet reachable), ten minutes alive. What
/// must change before builds are enabled: `Compiler::compile_from_github`.
pub async fn create_container(
    docker: &Docker,
    name: &str,
    config: &Config,
    repo: &str,
    commit: &str,
    build_target: &str,
) -> Result<String> {
    info!("Creating Docker container: {}", name);

    let container_config = ContainerConfig {
        image: Some(config.docker_image.clone()),
        cmd: Some(vec!["sleep".to_string(), "600".to_string()]),
        working_dir: Some("/workspace".to_string()),
        host_config: Some(bollard::models::HostConfig {
            network_mode: Some("bridge".to_string()),
            memory: Some((config.compile_memory_limit_mb as i64) * 1024 * 1024),
            nano_cpus: Some((config.compile_cpu_limit * 1_000_000_000.0) as i64),
            ..Default::default()
        }),
        env: Some(vec![
            format!("REPO={}", repo),
            format!("COMMIT={}", commit),
            format!("BUILD_TARGET={}", build_target),
        ]),
        ..Default::default()
    };

    let response = docker
        .create_container(
            Some(CreateContainerOptions {
                name: name.to_string(),
                ..Default::default()
            }),
            container_config,
        )
        .await
        .context("Failed to create container")?;

    docker
        .start_container::<String>(&response.id, None)
        .await
        .context("Failed to start container")?;

    info!("Container created and started: {}", response.id);
    Ok(response.id)
}

/// Execute a shell command in container
pub async fn exec_in_container(docker: &Docker, container_id: &str, cmd: &str) -> Result<()> {
    debug!("Executing in container: {}", cmd);

    let exec = docker
        .create_exec(
            container_id,
            CreateExecOptions {
                cmd: Some(vec!["sh", "-c", cmd]),
                attach_stdout: Some(true),
                attach_stderr: Some(true),
                ..Default::default()
            },
        )
        .await
        .context("Failed to create exec")?;

    let mut output = match docker.start_exec(&exec.id, None).await? {
        StartExecResults::Attached { output, .. } => output,
        StartExecResults::Detached => {
            anyhow::bail!("Unexpected detached exec");
        }
    };

    let mut stdout_lines = Vec::new();
    let mut stderr_lines = Vec::new();

    while let Some(msg) = output.next().await {
        match msg {
            Ok(log) => {
                use bollard::container::LogOutput;
                match log {
                    LogOutput::StdOut { message } => {
                        let text = String::from_utf8_lossy(&message);
                        for line in text.lines() {
                            info!("📦 [stdout] {}", line);
                            stdout_lines.push(line.to_string());
                        }
                    }
                    LogOutput::StdErr { message } => {
                        let text = String::from_utf8_lossy(&message);
                        for line in text.lines() {
                            warn!("📦 [stderr] {}", line);
                            stderr_lines.push(line.to_string());
                        }
                    }
                    _ => {}
                }
            }
            Err(e) => {
                error!("Error reading container output: {}", e);
                return Err(e.into());
            }
        }
    }

    // Check exit code
    let inspect = docker.inspect_exec(&exec.id).await?;
    if let Some(exit_code) = inspect.exit_code {
        if exit_code != 0 {
            error!("❌ Container command failed with exit code: {}", exit_code);
            let (_error_category, error_description) = classify_compilation_error(&stderr_lines, exit_code);

            // Extract raw logs for admin debugging
            let (stderr_text, stdout_text) = extract_compilation_logs(&stderr_lines, &stdout_lines);

            // Return compilation error with both user-facing message and raw logs
            return Err(CompilationError {
                user_message: error_description.to_string(),
                stderr: stderr_text,
                stdout: stdout_text,
                exit_code: Some(exit_code as i32),
            }.into());
        }
    }

    Ok(())
}

/// Extract raw compilation logs from stderr/stdout for admin debugging
/// SECURITY WARNING: These logs are stored in system_hidden_logs table
/// and should NEVER be exposed via public API to prevent exploits
/// Returns tuple: (stderr_text, stdout_text) with relevant error lines
pub fn extract_compilation_logs(stderr_lines: &[String], stdout_lines: &[String]) -> (String, String) {
    let mut error_lines = Vec::new();

    // Extract error lines from stderr (last 50 lines with context)
    for line in stderr_lines.iter().rev().take(50) {
        if line.contains("error:") || line.contains("error[E") || line.contains("fatal:") {
            error_lines.insert(0, line.clone());
        } else if !error_lines.is_empty() && (line.starts_with("   ") || line.starts_with("  ")) {
            // Include indented context lines (error details)
            error_lines.insert(0, line.clone());
        }
    }

    // If no specific errors found, take last 10 lines of stderr
    let stderr_text = if !error_lines.is_empty() {
        error_lines.join("\n")
    } else {
        stderr_lines
            .iter()
            .rev()
            .take(10)
            .rev()
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    };

    // Extract ERROR lines from stdout
    let mut stdout_errors = Vec::new();
    for line in stdout_lines.iter().rev().take(20) {
        if line.contains("ERROR") || line.contains("error:") {
            stdout_errors.insert(0, line.clone());
        }
    }

    // If no errors in stdout, take last 5 lines
    let stdout_text = if !stdout_errors.is_empty() {
        stdout_errors.join("\n")
    } else {
        stdout_lines
            .iter()
            .rev()
            .take(5)
            .rev()
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    };

    (stderr_text, stdout_text)
}

/// Classify compilation error and return (category, user-facing description)
/// SECURITY: Never return raw stderr/stdout to prevent potential exploits
fn classify_compilation_error(stderr_lines: &[String], exit_code: i64) -> (&'static str, &'static str) {
    let stderr_text = stderr_lines.join("\n").to_lowercase();

    // Git clone errors - repository not found
    if stderr_text.contains("fatal: repository") && stderr_text.contains("not found") {
        return ("repository_not_found", "Repository not found. Please check that the repository URL is correct and publicly accessible.");
    }

    // Git clone errors - authentication required
    if stderr_text.contains("fatal: could not read username")
        || stderr_text.contains("no such device or address")
        || stderr_text.contains("could not read from remote repository") {
        return ("repository_access_denied", "Cannot access repository. The repository may be private or the URL may be incorrect. Only public repositories are supported.");
    }

    // Invalid repository URL format
    if stderr_text.contains("fatal: too many arguments") {
        return ("invalid_repository_url", "Invalid repository URL format. The URL should not contain spaces or special characters. Example: https://github.com/owner/repo");
    }

    // Generic git errors during clone
    if stderr_text.contains("fatal:") && (stderr_text.contains("clone") || stderr_text.contains("git")) {
        return ("git_error", "Git operation failed. Please verify the repository URL and ensure it's a valid Git repository.");
    }

    // Network/timeout errors
    if stderr_text.contains("connection timed out") || stderr_text.contains("connection refused") {
        return ("network_error", "Network connection error. The repository server may be unreachable or experiencing issues. Please try again later.");
    }

    // Rust compilation errors
    if stderr_text.contains("error[e") || stderr_text.contains("error: could not compile") {
        return ("rust_compilation_error", "Rust compilation failed. Your code contains syntax errors or type errors. Please check your Rust code for correctness.");
    }

    // Cargo/dependency errors
    if stderr_text.contains("error: no matching package named") || stderr_text.contains("failed to select a version") {
        return ("dependency_not_found", "Dependency resolution failed. One or more dependencies specified in Cargo.toml could not be found or resolved.");
    }

    // Build script errors
    if stderr_text.contains("build failed") || stderr_text.contains("build.rs") {
        return ("build_script_error", "Build script execution failed. The build.rs script encountered an error during compilation.");
    }

    // Git exit codes
    if exit_code == 128 {
        return ("git_fatal_error", "Git fatal error occurred. The repository may be inaccessible, corrupted, or the URL may be invalid.");
    }
    if exit_code == 129 {
        return ("git_usage_error", "Git command error. The repository URL or parameters are invalid. Please check the repository URL format.");
    }

    // Generic compilation failure (fallback when no specific pattern matches)
    ("compilation_error", "Please check documentation and try to run your code on the playground.")
}

/// Extract WASM file from container
pub async fn extract_wasm(docker: &Docker, container_id: &str, wasm_path: &str) -> Result<Vec<u8>> {
    info!("Extracting WASM from container: {}", wasm_path);

    use tar::Archive;
    use std::io::Read;

    let mut tar_stream = docker.download_from_container(
        container_id,
        Some(DownloadFromContainerOptions {
            path: wasm_path.to_string(),
        }),
    );

    let mut tar_data = Vec::new();
    while let Some(chunk) = tar_stream.try_next().await? {
        tar_data.extend_from_slice(&chunk);
    }

    let mut archive = Archive::new(&tar_data[..]);

    for entry in archive.entries().context("Failed to read tar entries")? {
        let mut entry = entry.context("Failed to read tar entry")?;

        let mut wasm_bytes = Vec::new();
        entry
            .read_to_end(&mut wasm_bytes)
            .context("Failed to read WASM from tar")?;

        if !wasm_bytes.is_empty() {
            info!("✅ Extracted WASM: {} bytes", wasm_bytes.len());
            return Ok(wasm_bytes);
        }
    }

    anyhow::bail!("WASM file not found in container at {}", wasm_path);
}

/// Cleanup container (stop and remove)
pub async fn cleanup_container(docker: &Docker, container_id: &str) -> Result<()> {
    info!("Cleaning up container: {}", container_id);

    let _ = docker.stop_container(container_id, None).await;

    docker
        .remove_container(
            container_id,
            Some(RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await
        .context("Failed to remove container")?;

    info!("Container removed: {}", container_id);
    Ok(())
}

