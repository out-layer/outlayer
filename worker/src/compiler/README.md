# WASM Compiler Module

This module provides compilation from GitHub repositories to WASM for different build targets.

## Supported Build Targets

### WASI Preview 1 (P1)
- **Targets**: `wasm32-wasip1`, `wasm32-wasi`
- **Module**: `wasm32_wasip1.rs`
- **Optimization**: `wasm-opt` (Binaryen) with `-Oz` flag
- **Output**: Standard WASM module

### WASI Preview 2 (P2)
- **Targets**: `wasm32-wasip2`
- **Module**: `wasm32_wasip2.rs`
- **Optimization**: `wasm-tools strip --delete …` removes debug info and build metadata by name, keeping `outlayer.manifest`; the build then fails if any custom section other than `name`, `component-type*`, `dylink.0` or `outlayer.manifest` survived, naming it
- **Output**: WASM component with CLI interface

## Architecture

```
compiler/
├── mod.rs              - Main orchestration, lock management, checksum
├── docker.rs           - Docker container operations (shared)
├── wasm32_wasip1.rs    - WASI P1 compilation (wasm-opt)
└── wasm32_wasip2.rs    - WASI P2 compilation (wasm-tools)
```

The compiler:
1. Checks if WASM already exists in cache (by checksum)
2. Acquires a distributed lock to prevent duplicate compilations
3. Selects the appropriate compiler based on `build_target`
4. Creates a Docker container with Rust toolchain
5. Executes target-specific compilation script
6. Extracts and uploads the compiled WASM
7. Releases the lock

## Adding a New Build Target

To add support for a new build target (e.g., `wasm32-unknown-unknown`):

### 1. Create Compiler Module

Create `src/compiler/wasm32_unknown.rs`:

```rust
//! wasm32-unknown-unknown compiler
//!
//! Compiles bare WASM without WASI support

use anyhow::Result;
use bollard::Docker;
use tracing::info;

use super::docker;

pub async fn compile(docker: &Docker, container_id: &str, build_target: &str) -> Result<Vec<u8>> {
    info!("Compiling wasm32-unknown-unknown module: target={}", build_target);
    let start_time = std::time::Instant::now();

    let compile_script = r#"
set -ex
cd /workspace

# Setup Rust
. /usr/local/cargo/env || . $HOME/.cargo/env

# Add target
rustup target add wasm32-unknown-unknown

# Clone and build
git clone $REPO repo
cd repo
git checkout $COMMIT

cargo build --release --target wasm32-unknown-unknown
WASM_FILE=$(find target/wasm32-unknown-unknown/release -maxdepth 1 -name "*.wasm" -type f | head -1)

if [ -z "$WASM_FILE" ]; then
    echo "❌ ERROR: No WASM file found!"
    exit 1
fi

# Copy to output
mkdir -p /workspace/output
cp "$WASM_FILE" /workspace/output/output.wasm

# Optional: Add optimization for bare WASM
# ...

echo "✅ Compilation complete"
"#;

    docker::exec_in_container(docker, container_id, compile_script).await?;
    let wasm_bytes = docker::extract_wasm(docker, container_id, "/workspace/output/output.wasm").await?;

    let elapsed = start_time.elapsed();
    info!(
        "✅ wasm32-unknown-unknown compilation successful: {} bytes, {:.2}s",
        wasm_bytes.len(),
        elapsed.as_secs_f64()
    );

    Ok(wasm_bytes)
}
```

### 2. Register Module

In `src/compiler/mod.rs`, add:

```rust
mod wasm32_unknown;

// In compile_in_container():
match build_target {
    "wasm32-wasip2" => { /* ... */ }
    "wasm32-wasip1" | "wasm32-wasi" => { /* ... */ }
    "wasm32-unknown-unknown" => {
        wasm32_unknown::compile(&self.docker, container_id, build_target).await
    }
    _ => { /* error */ }
}
```

### 3. Update Validation

In `validate_build_target()`:

```rust
fn validate_build_target(&self, target: &str) -> Result<String> {
    match target {
        "wasm32-wasip1" | "wasm32-wasi" | "wasm32-wasip2" | "wasm32-unknown-unknown" => {
            Ok(target.to_string())
        }
        _ => anyhow::bail!("Unsupported build target: {}", target),
    }
}
```

### 4. Add Tests

Create `tests/test_wasm32_unknown.rs`:

```rust
#[tokio::test]
#[ignore] // Run with --ignored flag
async fn test_wasm32_unknown_unknown_compilation() {
    // Test compilation for your target
}
```

### 5. Update Documentation

- Add your target to this README's "Supported Build Targets" section
- Update contract documentation if needed
- Add examples to `worker/test_transactions.txt`

## Common Docker Operations

All target-specific compilers use shared Docker operations from `docker.rs`:

- **`ensure_image()`** - Pull Docker image if needed
- **`create_container()`** - Create and start compilation container
- **`exec_in_container()`** - Execute shell commands in container
- **`extract_wasm()`** - Extract compiled WASM from container
- **`cleanup_container()`** - Stop and remove container

## Testing

Run all compiler tests:
```bash
cargo test --lib compiler
```

Run integration tests (requires Docker):
```bash
cargo test test_real_github_compilation -- --ignored
```

Test specific target:
```bash
cargo test test_wasm32_wasip1 -- --ignored
cargo test test_wasm32_wasip2 -- --ignored
```

## Best Practices

1. **Keep compilation scripts idempotent** - They should work even if run multiple times
2. **Handle missing tools gracefully** - Check if optimization tools exist before using
3. **Log sizes before/after optimization** - Helps track optimization effectiveness
4. **Use proper error extraction** - Parse cargo/rustc errors from stderr
5. **Clean up containers** - Always cleanup even on failure
6. **Test with real repositories** - Use actual GitHub repos in integration tests

## Performance Considerations

- **Caching**: WASM files are cached by checksum (repo + commit + target)
- **Distributed locks**: Only one worker compiles each unique combination
- **Container reuse**: Could be added in the future for faster compilation
- **Parallel compilation**: Multiple workers can compile different repos simultaneously

## Security

- **Network access**: Containers have network enabled for `git clone` and `rustup`
- **Resource limits**: CPU and memory limits prevent resource exhaustion
- **Timeout**: Compilation has implicit timeout via container `sleep` command
- **No arbitrary code**: Only trusted Rust toolchain runs in containers

## Future Improvements

- [ ] Add `wasm32-wasi-preview1-threads` support
- [ ] Implement container reuse for faster compilation
- [ ] Add caching for `rustup target add` step
- [ ] Support custom Cargo.toml profiles
- [ ] Add `wasm-pack` support for browser targets
- [ ] Implement network-isolated compilation after dependencies are cached
