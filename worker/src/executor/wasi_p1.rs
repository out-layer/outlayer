//! WASI Preview 1 executor
//!
//! Executes WASM modules compiled with wasm32-wasip1 or wasm32-wasi targets.
//!
//! ## Features
//! - Standard WASI functions (stdio, random, environment)
//! - Binary format with `main()` entry point
//! - Fuel metering for instruction counting
//!
//! ## Requirements
//! - wasmtime 28+ with WASI P1 compatibility layer
//! - Core WASM module (not component)
//! - `_start` export (created by Rust from `fn main()`)

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::sync::OnceLock;
use tracing::debug;
use wasmtime::*;
use wasmtime_wasi::preview1::{self, WasiP1Ctx};
use wasmtime_wasi::WasiCtxBuilder;

use crate::api_client::ResourceLimits;

/// Global WASM engine for WASI P1 modules (core modules, NOT components)
///
/// IMPORTANT: This engine is ONLY for P1 modules. P2 components have their own engine.
///
/// Configuration:
/// - wasm_component_model = false (P1 uses core modules)
/// - async_support = true (for async execution)
/// - consume_fuel = true (instruction metering)
///
/// Creating Engine is expensive (~50-100ms). By reusing a single instance,
/// we avoid this overhead on every execution.
static WASM_ENGINE_P1: OnceLock<Engine> = OnceLock::new();

/// Get or initialize the global P1 engine
///
/// This engine has component_model=false and is NOT compatible with P2 components.
fn get_p1_engine() -> &'static Engine {
    WASM_ENGINE_P1.get_or_init(|| {
        let mut config = Config::new();
        // NO component_model - P1 uses core modules
        config.async_support(true);        // Async execution
        config.consume_fuel(true);         // Instruction metering
        config.epoch_interruption(true);   // Allow interrupting host calls
        tracing::info!("⚡ Initialized global WASM engine for P1 (core modules)");
        Engine::new(&config).expect("Failed to create P1 WASM engine")
    })
}

/// Execute WASI Preview 1 module
///
/// # Arguments
/// * `wasm_bytes` - WASM module binary
/// * `input_data` - JSON input via stdin
/// * `limits` - Resource limits (memory, instructions, time)
/// * `env_vars` - Environment variables (from encrypted secrets)
/// * `print_stderr` - Print WASM stderr to worker logs
///
/// # Returns
/// * `Ok((output, fuel_consumed, refund_usd))` - Execution succeeded
///   - `refund_usd` is always None for P1 (no payment host function support)
/// * `Err(_)` - Not a valid P1 module or execution failed
pub async fn execute(
    wasm_bytes: &[u8],
    input_data: &[u8],
    limits: &ResourceLimits,
    env_vars: Option<HashMap<String, String>>,
    print_stderr: bool,
) -> Result<(Vec<u8>, u64, Option<u64>)> {
    // Use global P1 engine (avoids ~50-100ms overhead per execution)
    let engine = get_p1_engine();

    // Try to load as module
    let module = wasmtime::Module::from_binary(&engine, wasm_bytes)
        .context("Not a valid WASI Preview 1 module")?;

    debug!("Loaded as WASI Preview 1 module (wasmtime)");

    // Create linker for WASI P1
    let mut linker = wasmtime::Linker::new(&engine);
    preview1::add_to_linker_async(&mut linker, |t: &mut WasiP1Ctx| t)?;

    // Prepare stdin/stdout pipes
    let stdin_pipe = wasmtime_wasi::pipe::MemoryInputPipe::new(input_data.to_vec());
    let stdout_pipe =
        wasmtime_wasi::pipe::MemoryOutputPipe::new((limits.max_memory_mb as usize) * 1024 * 1024);
    let stderr_pipe = wasmtime_wasi::pipe::MemoryOutputPipe::new(1024 * 1024);

    // Build WASI P1 context
    let mut wasi_builder = WasiCtxBuilder::new();
    wasi_builder.stdin(stdin_pipe);
    wasi_builder.stdout(stdout_pipe.clone());
    wasi_builder.stderr(stderr_pipe.clone());

    // No raw sockets (same rule as the P2 path): the allowlist and the egress
    // audit cover HTTP only, so nothing else may reach the network.
    wasi_builder.allow_tcp(false);
    wasi_builder.allow_udp(false);
    wasi_builder.allow_ip_name_lookup(false);
    wasi_builder.socket_addr_check(|_, _| Box::pin(async { false }));

    // Add environment variables (from encrypted secrets)
    if let Some(env_map) = env_vars {
        for (key, value) in env_map {
            wasi_builder.env(&key, &value);
            debug!("Added env var: {}", key);
        }
    }

    let wasi_p1_ctx = wasi_builder.build_p1();

    // Create store with fuel limit
    let mut store = Store::new(&engine, wasi_p1_ctx);
    store.set_fuel(limits.max_instructions)?;
    let timeout_secs = limits.max_execution_seconds.max(5);
    store.set_epoch_deadline(timeout_secs);
    store.epoch_deadline_trap();
    // Note: Engine::clone() is Arc clone — epoch counter is shared across all executions.
    // This is fine because main loop executes tasks sequentially (one at a time).
    // Stopped when dropped — on every return below, a module that does not
    // instantiate or has no `_start` included: the engine is shared, and a
    // ticker left running would end the next run early.
    let _ticker = super::sandbox::Ticker::start(engine.clone(), timeout_secs + 5);

    // Instantiate module
    debug!("Instantiating WASI P1 module");
    let instance = linker
        .instantiate_async(&mut store, &module)
        .await
        .context("Failed to instantiate WASI P1 module")?;

    // Get and call _start function (WASI entry point from main())
    debug!("Calling _start");
    let start = instance
        .get_typed_func::<(), ()>(&mut store, "_start")
        .context(
            "Failed to find _start function. \
             Make sure you're using [[bin]] format with fn main(), not [lib] with cdylib",
        )?;

    // Wall-clock bound on the run itself: the epoch deadline traps only when
    // wasm code executes, and a guest suspended in a host await (`poll_oneoff`
    // on a clock) never returns to wasm. Dropping the future cancels the run;
    // the store is read afterwards as after any trap. Two seconds past the
    // epoch deadline, so this fires only where the epoch could not.
    let mut wall_clock_hit = false;
    let call_result = match tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs + 2),
        start.call_async(&mut store, ()),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => {
            wall_clock_hit = true;
            Err(anyhow::anyhow!(
                "interrupt: wall-clock limit of {}s reached while the guest waited in a host call",
                timeout_secs
            ))
        }
    };
    // What the run consumed, whichever way it ended.
    let fuel_consumed = limits.max_instructions - store.get_fuel().unwrap_or(0);
    // An explicit exit with status 0 is a success like returning from `_start`.
    let call_result = match call_result {
        Err(e) if matches!(super::sandbox::ended(&e, false), super::sandbox::Ended::Exited(0)) => Ok(()),
        other => other,
    };
    drop(_ticker);

    if let Err(e) = &call_result {
        if matches!(super::sandbox::ended(e, wall_clock_hit), super::sandbox::Ended::TimedOut) {
            return Err(super::sandbox::RunFailed {
                message: format!(
                    "WASM execution timed out after {} seconds (penalty). \
                     Full execution cost is charged with no refund (consumed {} instructions)",
                    timeout_secs, fuel_consumed
                ),
                instructions: fuel_consumed,
                penalty: true,
            }
            .into());
        }
    }

    if let Err(e) = call_result {
        let failed = |message: String| -> anyhow::Error {
            super::sandbox::RunFailed { message, instructions: fuel_consumed, penalty: false }.into()
        };
        let exit_status = match super::sandbox::ended(&e, false) {
            super::sandbox::Ended::Exited(code) => Some(code),
            _ => None,
        };
        let error_str = e.to_string();
        tracing::error!("❌ WASI P1 _start failed: {}", error_str);

        // Read stderr to get program's error message
        let stderr_contents = stderr_pipe.contents();
        let stderr_msg = if !stderr_contents.is_empty() {
            String::from_utf8_lossy(&stderr_contents).to_string()
        } else {
            String::new()
        };

        // An exit with a status: include stderr, or the input, in the message.
        if exit_status.is_some() {
            if !stderr_msg.is_empty() {
                // Program printed error to stderr
                return Err(failed(stderr_msg));
            }

            let preview = input_preview(input_data);

            return Err(failed(format!(
                "WASM program exited with error status. This usually means invalid input_data or panic in code. Input received: {}. Original error: {}",
                preview, error_str
            )));
        }

        // Other execution errors
        return Err(failed(format!("WASM execution failed: {}", error_str)));
    }

    debug!("WASI P1 module execution completed");

    // Get results
    debug!("WASM execution consumed {} instructions", fuel_consumed);

    // Print stderr if flag is enabled (even on success)
    let stderr_contents = stderr_pipe.contents();
    if print_stderr && !stderr_contents.is_empty() {
        let stderr_str = String::from_utf8_lossy(&stderr_contents);
        tracing::info!("📝 WASM stderr output:\n{}", stderr_str);
    }

    let output = stdout_pipe.contents().to_vec();

    // P1 does not support payment host functions, so refund_usd is always None
    Ok((output, fuel_consumed, None))
}

/// The first 200 characters of the input, for an error that quotes it — cut
/// at a character, never inside one: a byte cut through a multibyte
/// character panics, and a panic here ends the worker's process.
fn input_preview(input: &[u8]) -> String {
    let text = String::from_utf8_lossy(input);
    match text.char_indices().nth(200) {
        Some((at, _)) => format!("{}...", &text[..at]),
        None => text.into_owned(),
    }
}

#[cfg(test)]
mod preview_tests {
    use super::input_preview;

    #[test]
    fn a_preview_is_cut_at_a_character_whatever_the_bytes() {
        // 199 ASCII bytes and then a two-byte character across byte 200: the
        // old byte cut panicked here.
        let input = format!("{}é and more", "a".repeat(199));
        let p = input_preview(input.as_bytes());
        assert!(p.starts_with(&"a".repeat(199)) && p.ends_with("..."), "{p}");
        assert_eq!(input_preview("короткий".as_bytes()), "короткий");
        let long = "я".repeat(500);
        assert_eq!(input_preview(long.as_bytes()).chars().count(), 203);
        assert_eq!(input_preview(&[0xff, 0xfe]), "\u{fffd}\u{fffd}");
    }
}
