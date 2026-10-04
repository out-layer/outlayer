# Executor Module

WASM execution engine supporting multiple WASI versions.

## Architecture

```
executor/
├── mod.rs       - Main executor logic, format detection
├── wasi_p1.rs   - WASI Preview 1 executor (wasm32-wasip1)
└── wasi_p2.rs   - WASI Preview 2 executor (wasm32-wasip2)
```

## Supported Formats

### WASI Preview 2 (P2)
- **File**: `wasi_p2.rs`
- **Target**: `wasm32-wasip2`
- **Format**: Component model
- **Features**: HTTP/HTTPS and the OutLayer host interfaces; no directory is preopened while `sandbox::GUEST_FILES_ALLOWED` is false, and no raw sockets
- **Runtime**: wasmtime 28+
- **Entry**: `wasi:cli/run` interface

### WASI Preview 1 (P1)
- **File**: `wasi_p1.rs`
- **Target**: `wasm32-wasip1`, `wasm32-wasi`
- **Format**: Core WASM module
- **Features**: Basic I/O, random, environment
- **Runtime**: wasmtime 28+ (P1 compatibility layer)
- **Entry**: `_start` export (from `fn main()`)

## Execution Flow

```
Executor::execute()
  ↓
execute_async()
  ↓
  ├─→ Try wasi_p2::execute() → Success? Return
  ├─→ Try wasi_p1::execute() → Success? Return
  └─→ Return error with supported formats
```

## Adding New Build Targets

To add support for a new target (e.g., `wasm32-unknown-unknown`):

### 1. Create Module File

Create `src/executor/wasi_unknown.rs`:

```rust
//! WASI Unknown executor
//!
//! Executes WASM modules compiled with wasm32-unknown-unknown target.

use anyhow::{Context, Result};
use std::collections::HashMap;
use tracing::debug;

use crate::api_client::ResourceLimits;

/// Execute WASI unknown module
pub async fn execute(
    wasm_bytes: &[u8],
    input_data: &[u8],
    limits: &ResourceLimits,
    env_vars: Option<HashMap<String, String>>,
) -> Result<(Vec<u8>, u64)> {
    // Your implementation here
    // 1. Configure engine
    // 2. Load WASM
    // 3. Set up environment
    // 4. Execute
    // 5. Return (output, fuel_consumed)

    todo!("Implement wasm32-unknown-unknown execution")
}
```

### 2. Add Module Declaration

In `mod.rs`, add:

```rust
mod wasi_unknown;
```

### 3. Add Detection Logic

In `execute_async()`, add:

```rust
// Try WASI unknown module
if let Ok(result) = wasi_unknown::execute(wasm_bytes, input_data, limits, env_vars.clone()).await
{
    return Ok(result);
}
```

### 4. Update Compiler

In `worker/src/compiler.rs`, add validation:

```rust
fn validate_build_target(&self, target: &str) -> Result<String> {
    match target {
        "wasm32-wasi" => Ok("wasm32-wasi".to_string()),
        "wasm32-wasip1" => Ok("wasm32-wasi".to_string()),
        "wasm32-wasip2" => Ok("wasm32-wasip2".to_string()),
        "wasm32-unknown-unknown" => Ok("wasm32-unknown-unknown".to_string()), // New!
        _ => anyhow::bail!("Unsupported build target: '{}'", target)
    }
}
```

### 5. Add Tests

Create `tests/test_wasi_unknown.rs`:

```rust
use offchainvm_worker::executor::Executor;
use offchainvm_worker::api_client::ResourceLimits;

#[tokio::test]
async fn test_wasi_unknown_execution() {
    // Load test WASM
    let wasm_bytes = std::fs::read("path/to/test.wasm").unwrap();

    let executor = Executor::new(1_000_000_000);
    let limits = ResourceLimits {
        max_instructions: 1_000_000_000,
        max_memory_mb: 128,
        max_execution_seconds: 60,
    };

    let input = b"{}";
    let result = executor.execute(&wasm_bytes, input, &limits, None).await;

    assert!(result.is_ok());
    assert!(result.unwrap().success);
}
```

### 6. Update Documentation

- Add to `/wasi-examples/WASI_TUTORIAL.md`
- Update `/tests/README.md`
- Add example in `/wasi-examples/`

## Testing

### Unit Tests

```bash
cargo test --lib executor
```

### Integration Tests

```bash
# Build test WASM modules
cd ../wasi-examples/get-random
cargo build --target wasm32-wasip1 --release

cd ../ai-example
cargo build --target wasm32-wasip2 --release

# Run tests
cd ../../worker
cargo test
```

### Manual Testing

```bash
# Start worker
RUST_LOG=debug cargo run

# In another terminal, send execution request
cd ../tests
./transactions.sh
```

## Common Issues

### "Not a valid WASI P2 component"
**Problem**: Binary is not component format
**Solution**: Build with `wasm32-wasip2` target

### "Failed to find _start function"
**Problem**: Using `[lib]` instead of `[[bin]]` format
**Solution**: Change Cargo.toml to binary format

### "Failed to load WASM binary"
**Problem**: Binary doesn't match any supported format
**Solution**: Check build target and WASM format

## Performance

Expected metrics:

| Format | Size | Load Time | Execution | Features |
|--------|------|-----------|-----------|----------|
| WASI P2 | ~500KB | ~10ms | Variable | HTTP, I/O |
| WASI P1 | ~100KB | ~5ms | Fast | Basic I/O |

## See Also

- [WASI Tutorial](../../../wasi-examples/WASI_TUTORIAL.md)
- [Worker Testing](../../TESTING.md)
- [Main README](../../../README.md)
