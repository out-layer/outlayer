# WASI Test Runner

A local tool that runs a WASM module the way an OutLayer worker starts one —
stdin in, stdout out, fuel metering, wasmtime 28 — and checks the result.

## What It Checks

✅ Binary format (WASI P1 module or P2 component)
✅ Fuel metering (instruction counting, with a fuel limit)
✅ Input/output handling (stdin → stdout, non-empty output)
✅ JSON output (a warning, not a failure, when stdout is not JSON)
✅ NEAR RPC host functions (`near:rpc/api@0.1.0`, with `--rpc`)

## Where It Differs From the Worker

Passing here does not prove a module runs on OutLayer. The runner:

- links only `near:rpc`, not `near:storage`, `near:payment`, `near:vrf`,
  `outlayer:wallet`, `outlayer:signing-keys`, `outlayer:encryption-keys` or
  `outlayer:tasks`: a component that imports one of those fails to instantiate
  here;
- preopens the host's `/tmp` as `.` for a P2 component, while the worker gives a
  run no directory at all: a module that writes files passes here and fails
  there;
- does not enforce `max_memory_mb` (the flag sizes the stdout buffer) and has
  no time limit, while the worker enforces both (`WASI_TUTORIAL.md`, Overview);
- does not apply the worker's outbound-HTTP rules (no internal addresses, a
  manifest's network allowlist, the 30-second per-request timeout);
- warns about output over 900 bytes, a limit OutLayer does not have: stdout
  holds up to 10 MiB, and an on-chain answer of 1024 bytes or more is
  delivered in two steps;
- sets none of the worker's environment variables: pass what your module
  reads with `--env`.

## Installation

```bash
cd wasi-examples/wasi-test-runner
cargo build --release
```

## Usage

### Basic Test

```bash
./target/release/wasi-test --wasm path/to/your-app.wasm --input '{"test":"data"}'
```

### Test with Input File

```bash
./target/release/wasi-test --wasm your-app.wasm --input-file input.json
```

### Test with a Custom Fuel Limit

```bash
./target/release/wasi-test \
  --wasm your-app.wasm \
  --input '{"value":42}' \
  --max-instructions 50000000
```

### Verbose Mode

```bash
./target/release/wasi-test --wasm your-app.wasm --input '{}' --verbose
```

### Test Specific Examples

```bash
# Test random-example (WASI P1)
./target/release/wasi-test \
  --wasm ../random-example/target/wasm32-wasip1/release/random-example.wasm \
  --input '{"min":1,"max":100}'

# Test ai-example (WASI P2)
./target/release/wasi-test \
  --wasm ../ai-example/target/wasm32-wasip2/release/ai-example.wasm \
  --input '{"prompt":"What is NEAR Protocol?"}'

# Test oracle-example (WASI P2)
./target/release/wasi-test \
  --wasm ../oracle-example/target/wasm32-wasip2/release/oracle-example.wasm \
  --input '{"tokens":[{"token_id":"bitcoin","sources":[{"name":"coingecko","token_id":null}],"aggregation_method":"average","min_sources_num":1}],"max_price_deviation_percent":10.0}' \
  --max-instructions 50000000000
```

### Test with NEAR RPC (View Calls Only)

```bash
# rpc-test-ark runs its fixed testnet suite; it reads no input
./target/release/wasi-test \
  --wasm ../rpc-test-ark/target/wasm32-wasip2/release/rpc-test-ark.wasm \
  --input '{}' \
  --rpc \
  --rpc-url "https://rpc.testnet.fastnear.com" \
  --max-instructions 50000000000
```

### Test with NEAR RPC (Transactions)

```bash
# botfather-example - create accounts (requires credentials via env)
./target/release/wasi-test \
  --wasm ../botfather-example/target/wasm32-wasip2/release/bot-father.wasm \
  --input '{"action":"create_accounts","prompt":"space theme","count":3,"deposit_per_account":"1000000000000000000000000"}' \
  --env OPENAI_API_KEY=sk-... \
  --env PROTECTED_MASTER_KEY=ed25519:... \
  --env NEAR_SENDER_ID=alice.testnet \
  --env NEAR_SENDER_PRIVATE_KEY=ed25519:... \
  --rpc \
  --rpc-allow-transactions \
  --max-instructions 50000000000

# botfather-example - list accounts (no credentials needed)
./target/release/wasi-test \
  --wasm ../botfather-example/target/wasm32-wasip2/release/bot-father.wasm \
  --input '{"action":"list_accounts","indices":[]}' \
  --env PROTECTED_MASTER_KEY=ed25519:... \
  --env NEAR_SENDER_ID=alice.testnet \
  --rpc \
  --max-instructions 50000000000
```

`NEAR_SENDER_ID` stands in for the variable the worker sets to the caller's
account; on OutLayer no secret can set it. `PROTECTED_MASTER_KEY` stands in for
a secret the keystore generates.

## Example Output

### Successful Test

```
Testing WASM module: random-example.wasm
Input: {"min":1,"max":100}
Max instructions: 10000000000
Max memory: 128 MB

Detected: WASI Preview 1 Module
Execution successful!

Results:
  - Fuel consumed: 456789 instructions
  - Output size: 20 bytes

Output:
{"random_number":42}

Output is valid JSON
All checks passed! Module is compatible with NEAR OutLayer.
```

### Failed Test

```
Testing WASM module: broken-app.wasm
Input: {}
Max instructions: 10000000000
Max memory: 128 MB

Detected: WASI Preview 1 Module
Execution failed!

Error: Failed to find _start function. Make sure you're using [[bin]] format with fn main()

Common issues:
  - Make sure you're using [[bin]] format, not [lib]
  - Check that you have fn main() as entry point
  - Verify you're reading from stdin and writing to stdout
  - Use correct build target (wasm32-wasip1 or wasm32-wasip2)

See WASI_TUTORIAL.md for detailed guide
```

## Testing Your Own Module

### Step 1: Build Your WASM

```bash
# WASI P1
cargo build --target wasm32-wasip1 --release

# WASI P2
cargo build --target wasm32-wasip2 --release
```

### Step 2: Prepare Test Input

Create `test-input.json`:
```json
{
  "name": "Alice",
  "value": 42
}
```

### Step 3: Run Test

```bash
cd wasi-examples/wasi-test-runner
cargo run --release -- \
  --wasm ../../your-project/target/wasm32-wasip1/release/your-app.wasm \
  --input-file test-input.json \
  --verbose
```

## Common Issues & Solutions

### "Failed to find _start function"

**Problem**: Using library format instead of binary

**Solution**: Change Cargo.toml:
```toml
# ✅ Use this
[[bin]]
name = "my-app"
path = "src/main.rs"

# ❌ Not this
[lib]
crate-type = ["cdylib"]
```

### "Output is empty"

**Problem**: Not writing to stdout or not flushing

**Solution**:
```rust
print!("{}", output);
io::stdout().flush()?; // Don't forget this!
```

### "Not a valid WASI P1 module or P2 component"

**Problem**: Wrong build target

**Solution**:
```bash
# Use one of these targets
cargo build --target wasm32-wasip1 --release
cargo build --target wasm32-wasip2 --release

# ❌ Not these
cargo build --target wasm32-unknown-unknown --release
```

## Integration with CI/CD

### GitHub Actions Example

```yaml
name: Test WASM

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust
        run: rustup target add wasm32-wasip1

      - name: Build WASM
        run: cargo build --target wasm32-wasip1 --release

      - name: Install Test Runner
        run: |
          cd wasi-examples/wasi-test-runner
          cargo build --release

      - name: Test WASM
        run: |
          ./wasi-examples/wasi-test-runner/target/release/wasi-test \
            --wasm target/wasm32-wasip1/release/my-app.wasm \
            --input '{"test":"data"}'
```

## Command-Line Options

```
Options:
  -w, --wasm <WASM>
          Path to WASM file

  -i, --input <INPUT>
          Input JSON data (or use --input-file)

      --input-file <INPUT_FILE>
          Path to input JSON file

      --max-instructions <MAX_INSTRUCTIONS>
          Maximum instructions (fuel limit)
          [default: 10000000000]

      --max-memory-mb <MAX_MEMORY_MB>
          Sizes the stdout buffer; memory itself is not limited
          [default: 128]

  -e, --env <ENV>
          Environment variables (format: KEY=value, can be specified multiple times)

  -v, --verbose
          Verbose output

      --rpc
          Enable NEAR RPC proxy (provides near:rpc/api host functions)

      --rpc-url <RPC_URL>
          NEAR RPC URL for proxy
          [default: https://rpc.testnet.fastnear.com]

      --rpc-max-calls <RPC_MAX_CALLS>
          Maximum RPC calls per execution
          [default: 100]

      --rpc-allow-transactions
          Allow transaction methods (send-tx, call, transfer); implies --rpc

  -h, --help
          Print help
```

## NEAR RPC Host Functions

With `--rpc`, the runner provides the `near:rpc/api@0.1.0` interface — the same
WIT as the worker's (`worker/wit/world.wit`). Every function returns
`(result, error)`; `finality-or-block` takes `"final"`, `"optimistic"`, a block
height or hash, empty meaning `"final"`. The full list is in
[rpc-test-ark](../rpc-test-ark/README.md#wit-interface).

**Transaction Functions** (require `--rpc-allow-transactions` and credentials
the module supplies):
- `call(signer_id, signer_key, receiver_id, method_name, args_json, deposit_yocto, gas, wait_until)`
- `transfer(signer_id, signer_key, receiver_id, amount_yocto, wait_until)`
- `send-tx(signed_tx_base64, wait_until)`

The runner waits for `FINAL` on `call` and `transfer` whatever `wait_until`
says.

### Security Model

Neither the runner nor a worker signs with a key of its own. The module passes
the signer's account and private key (NEAR format, `ed25519:base58...`) to
`call()` or `transfer()`. On OutLayer the private key comes from a secret, and
`NEAR_SENDER_ID` is the caller's account set by the worker.

### Example: Testing WASM with RPC

```rust
// In your WASM code (Rust)
use std::env;

let signer_id = env::var("NEAR_SENDER_ID").unwrap_or_default();
let signer_key = env::var("NEAR_SENDER_PRIVATE_KEY").unwrap_or_default();

// View call ("" = final)
let (result, error) = near::rpc::api::view_account(&signer_id, "");

// Transaction, signed with the key the module was given
let (tx_hash, error) = near::rpc::api::transfer(
    &signer_id,
    &signer_key,
    "receiver.testnet",
    "1000000000000000000000000",  // 1 NEAR in yoctoNEAR
    "",                           // wait_until: "" = FINAL
);
```

Test this WASM:
```bash
./target/release/wasi-test \
  --wasm your-app.wasm \
  --input '{"action":"transfer"}' \
  --env NEAR_SENDER_ID=alice.testnet \
  --env NEAR_SENDER_PRIVATE_KEY=ed25519:... \
  --rpc \
  --rpc-allow-transactions
```

## Requirements

- Rust 1.85+ (for building test runner)
- wasmtime 28 (included as dependency)
- Valid WASI P1 or P2 WASM binary

## See Also

- [WASI_TUTORIAL.md](../WASI_TUTORIAL.md) - Complete WASI development guide
- [random-example](../random-example/) - Example WASI P1 module
- [ai-example](../ai-example/) - Example WASI P2 component
- [rpc-test-ark](../rpc-test-ark/) - Example with NEAR RPC host functions
- [botfather-example](../botfather-example/) - Example with RPC transactions and secrets
