# WASI Development Tutorial for NEAR OutLayer

This guide explains how to create WASM modules that work with NEAR OutLayer platform.

## ⚠️ CRITICAL: WASI vs NEAR Smart Contracts

**DO NOT CONFUSE THESE TWO!**

| Type | Target | Build Command | rust-toolchain.toml? | Purpose |
|------|--------|---------------|---------------------|---------|
| **WASI Module** | `wasm32-wasip1` or `wasm32-wasip2` | `cargo build --target wasm32-wasip1 --release` | ❌ No | Off-chain computation |
| **NEAR Contract** | `wasm32-unknown-unknown` | `cargo near build` | ✅ **YES** (1.85.0) | On-chain smart contract |

**NEVER use `cargo build --target wasm32-unknown-unknown` for WASI modules!**
**NEVER use `cargo build --target wasm32-wasip1` for NEAR contracts!**

### For NEAR Smart Contracts (on-chain):
```bash
# ✅ CORRECT - Use cargo-near
cargo near build

# ❌ WRONG - DO NOT use raw cargo build
cargo build --target wasm32-unknown-unknown --release
```

**CRITICAL: NEAR contracts MUST have rust-toolchain.toml:**
```toml
# dao-contract/rust-toolchain.toml
[toolchain]
channel = "1.85.0"
```

**Why rust-toolchain.toml is required:**
- `cargo near build` requires **specific Rust version** (currently 1.85.0)
- Without this file, build may fail with ABI incompatibility errors
- WASI modules **don't need** this file (work with any recent Rust)
- Always copy rust-toolchain.toml from working NEAR contract examples

### For WASI Modules (off-chain OutLayer):
```bash
# ✅ CORRECT - Use wasip1 or wasip2
cargo build --target wasm32-wasip1 --release

# ❌ WRONG - DO NOT use wasm32-unknown-unknown
cargo build --target wasm32-unknown-unknown --release
```

## Table of Contents

1. [Overview](#overview)
2. [WASI Preview 1 vs Preview 2](#wasi-preview-1-vs-preview-2)
3. [Quick Start: WASI P1](#quick-start-wasi-p1)
4. [Quick Start: WASI P2](#quick-start-wasi-p2)
5. [Input/Output Format](#inputoutput-format)
6. [OutLayer SDK](#outlayer-sdk)
7. [Host Interfaces](#host-interfaces)
8. [Important Requirements](#important-requirements)
9. [Testing Your Module](#testing-your-module)
10. [Common Pitfalls](#common-pitfalls)
11. [Examples](#examples)

## Overview

NEAR OutLayer executes WASM modules off-chain with the wasmtime runtime (28), inside Intel TDX workers. Your code runs in a sandboxed environment with:
- **Stdin** for input data (JSON)
- **Stdout** for output data (JSON); stderr becomes the error message of a failed run
- **WASI** for system interfaces (random, clocks, environment variables)
- **Fuel metering** for instruction counting
- **Resource limits** (memory, time, instructions)

What a run does NOT have: files (no directory is preopened, on P1 or P2 — keep
data in memory) and raw sockets (TCP, UDP and name lookups are refused; the only
way out is `wasi:http` on P2).

The limits a request may ask for, enforced by the contract (`get_max_limits`)
and the worker:

| Limit | Default | Maximum |
|---|---|---|
| `max_instructions` | 1 billion | 500 billion |
| `max_execution_seconds` | 60 | 180 (the worker never times a run below 5 s) |
| `max_memory_mb` | 128 | 4096 — by default the worker gives every run at least 1024 MB whatever it asks |
| stdout | — | 10 MiB; a write past it fails |

A run that hits its time limit fails, and so does a run in which two HTTP
requests each exceed the 30-second per-request timeout; either is charged for
the instructions and time it consumed.

## WASI Preview 1 vs Preview 2

### WASI Preview 1 (P1)
- **Target**: `wasm32-wasip1` or `wasm32-wasi`
- **Format**: Binary with `main()` function
- **Use case**: Simple computations, random numbers, basic I/O
- **Features**: Core WASI functions (random, stdio, environment)
- **Size**: Smaller binaries (~100-200KB)
- **Example**: [random-example](./random-example/)

### WASI Preview 2 (P2)
- **Target**: `wasm32-wasip2`
- **Format**: Component model with typed interfaces
- **Use case**: HTTP requests, complex I/O, modern features
- **Features**: HTTP client and the OutLayer host interfaces (see [Host Interfaces](#host-interfaces)). No files and no raw sockets: keep a run's data in memory
- **Size**: Larger binaries (~500KB-1MB)
- **Example**: [ai-example](./ai-example/)

### Which to Choose?

| Feature | WASI P1 | WASI P2 |
|---------|---------|---------|
| HTTP requests | ❌ | ✅ |
| JSON processing | ✅ | ✅ |
| Random numbers | ✅ | ✅ |
| OutLayer host interfaces (RPC, storage, wallet, keys…) | ❌ | ✅ |
| File I/O | ❌ | ❌ |
| Binary size | 🟢 Small | 🟡 Larger |
| Compilation speed | 🟢 Fast | 🟡 Slower |
| Stability | 🟢 Stable | 🟡 Newer |

**Rule of thumb**: Use P1 unless you need HTTP or advanced I/O.

## Quick Start: WASI P1

### 1. Create Binary Project

```bash
cargo new my-wasi-app
cd my-wasi-app
```

### 2. Configure Cargo.toml

```toml
[package]
name = "my-wasi-app"
version = "0.1.0"
edition = "2021"

# IMPORTANT: Must be a binary, not a library
[[bin]]
name = "my-wasi-app"
path = "src/main.rs"

[dependencies]
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

[profile.release]
opt-level = "z"  # Optimize for size
lto = true       # Link-time optimization
strip = true     # Strip debug symbols
```

### 3. Write Code (src/main.rs)

```rust
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

#[derive(Deserialize)]
struct Input {
    name: String,
}

#[derive(Serialize)]
struct Output {
    greeting: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Read input from stdin
    let mut input_string = String::new();
    io::stdin().read_to_string(&mut input_string)?;

    // Parse JSON input
    let input: Input = serde_json::from_str(&input_string)?;

    // Process
    let output = Output {
        greeting: format!("Hello, {}!", input.name),
    };

    // Write JSON output to stdout
    let json = serde_json::to_string(&output)?;
    print!("{}", json);
    io::stdout().flush()?;

    Ok(())
}
```

### 4. Build

```bash
# Add target
rustup target add wasm32-wasip1

# Build
cargo build --target wasm32-wasip1 --release

# Output: target/wasm32-wasip1/release/my-wasi-app.wasm
```

### 5. Test Locally

```bash
# Test with wasmtime
echo '{"name":"World"}' | wasmtime target/wasm32-wasip1/release/my-wasi-app.wasm

# Expected: {"greeting":"Hello, World!"}
```

## Quick Start: WASI P2

### 1. Create Component Project

```bash
cargo new my-http-app
cd my-http-app
```

### 2. Configure Cargo.toml

```toml
[package]
name = "my-http-app"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "my-http-app"
path = "src/main.rs"

[dependencies]
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
wasi-http-client = "0.2"  # For HTTP requests

[profile.release]
opt-level = "z"
lto = true
strip = true
```

### 3. Write Code (src/main.rs)

```rust
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use std::time::Duration;
use wasi_http_client::Client;

#[derive(Deserialize)]
struct Input {
    url: String,
}

#[derive(Serialize)]
struct Output {
    status: u16,
    body: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Read input
    let mut input_string = String::new();
    io::stdin().read_to_string(&mut input_string)?;
    let input: Input = serde_json::from_str(&input_string)?;

    // Make HTTP request
    let response = Client::new()
        .get(&input.url)
        .connect_timeout(Duration::from_secs(10))
        .send()?;

    // Process response (`body()` consumes the response)
    let status = response.status();
    let body = response.body()?;
    let output = Output {
        status,
        body: String::from_utf8_lossy(&body).to_string(),
    };

    // Write output
    let json = serde_json::to_string(&output)?;
    print!("{}", json);
    io::stdout().flush()?;

    Ok(())
}
```

### 4. Build

```bash
# Add target
rustup target add wasm32-wasip2

# Build
cargo build --target wasm32-wasip2 --release

# Output: target/wasm32-wasip2/release/my-http-app.wasm
```

### 5. Test Locally

```bash
# Test with wasmtime (-S http enables wasi:http)
echo '{"url":"https://api.example.com/data"}' | wasmtime run -S http target/wasm32-wasip2/release/my-http-app.wasm
```

## Input/Output Format

### CRITICAL REQUIREMENTS

1. **Input**: Always read from `stdin` (not command-line arguments)
2. **Output**: Always write to `stdout` (not stderr)
3. **Format**: stdout is read as the request's `response_format` — `Text` (the on-chain default), `Json` or `Bytes`. With `Json` (every HTTPS call uses it) stdout must be exactly one JSON value, or the run fails; so print nothing else to stdout
4. **Size limit**: stdout holds up to 10 MiB. On chain, an answer of 1024 bytes or more is delivered in two steps (`submit_execution_output_and_resolve`, used automatically by the worker) and remains bounded by NEAR's transaction size
5. **No buffering**: Call `stdout().flush()` after writing

### Example Pattern

```rust
use std::io::{self, Read, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ✅ CORRECT: Read from stdin
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;

    // Process...
    let output = process(&input)?;

    // ✅ CORRECT: Write to stdout and flush
    print!("{}", output);
    io::stdout().flush()?;

    Ok(())
}

// ❌ WRONG: Reading from args
fn main() {
    let args: Vec<String> = std::env::args().collect(); // Won't work!
}

// ❌ WRONG: Writing the result to stderr
fn main() {
    eprintln!("result"); // Not the output: stderr is the error message of a failed run
}
```

## OutLayer SDK

The `outlayer` crate provides access to OutLayer-specific features for WASI P2 modules.

### Installation

```toml
[dependencies]
outlayer = "0.2"
```

### Getting the Caller's NEAR Account

When your WASI module is called via blockchain transaction, you can identify who called it:

```rust
use outlayer::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Returns the NEAR account that signed the transaction
    let signer = env::signer_account_id()
        .ok_or("No signer - must be called via NEAR transaction or Payment Key")?;

    println!("Called by: {}", signer);  // e.g., "alice.near"

    // Use signer for:
    // - Access control
    // - Per-user data isolation
    // - Audit logging
    Ok(())
}
```

**Note**: `signer_account_id()` reads `NEAR_SENDER_ID` and returns:
- `Some(account_id)` when called via blockchain transaction (the transaction's signer; for a meta-transaction, the account that signed the delegate action)
- `Some(payment_key_owner)` when called via HTTPS API — every HTTPS call carries a payment key
- the bound account instead, when the request sets `use_bound_identity` (Agent Connect)
- `None` only outside OutLayer (e.g. local wasmtime)

`predecessor_account_id()` (`NEAR_PREDECESSOR_ID`) names the account that
called the contract, and `relayer_account_id()` the relayer of a
meta-transaction. See [WASM_ENV_VARS.md](./WASM_ENV_VARS.md) for every variable.

### Persistent Storage

OutLayer provides encrypted storage that persists across executions. It
exists only on a run through a **project** (`Project` source or an HTTPS call):
a component that imports `near:storage/api` is refused before it starts on any
other run.

```rust
use outlayer::storage;

// Per-account storage: the caller's own cell of this project
storage::set("my_key", b"my_value")?;

// Project-wide storage shared by every caller; only the module reads it
storage::set_worker("my_key", b"my_value")?;

// Read data
if let Some(data) = storage::get_worker("my_key")? {
    let value = String::from_utf8(data)?;
    println!("Stored value: {}", value);
}
```

Values are encrypted by the keystore before they are stored. Every version of
the project reads the same records. Which account's cell `set`/`get` use is the
manifest's `storage_account` (`CONNECTOR_MANIFEST.md`). The full API and the
key layout are in [test-storage-ark](./test-storage-ark/README.md).

**Use cases:**
- Cache expensive computations
- Maintain state between executions
- Per-user data that only that user's runs read

### Environment Variables

OutLayer injects useful environment variables:

```rust
// Detect network (mainnet/testnet)
let network = std::env::var("NEAR_NETWORK_ID").unwrap_or("mainnet".to_string());
let suffix = if network == "testnet" { ".testnet" } else { ".near" };

// Example: construct email address
let email = format!("{}@near.email", account_id.strip_suffix(suffix).unwrap_or(&account_id));
```

### Complete Example

```rust
use outlayer::{env, storage};
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

#[derive(Deserialize)]
struct Input {
    action: String,
    data: Option<String>,
}

#[derive(Serialize)]
struct Output {
    success: bool,
    account: String,
    result: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Get caller
    let account = env::signer_account_id()
        .ok_or("Authentication required")?;

    // 2. Read input
    let mut input_str = String::new();
    io::stdin().read_to_string(&mut input_str)?;
    let input: Input = serde_json::from_str(&input_str)?;

    // 3. Process based on action
    let result = match input.action.as_str() {
        "save" => {
            let key = format!("user:{}", account);
            storage::set_worker(&key, input.data.unwrap_or_default().as_bytes())?;
            "Data saved".to_string()
        }
        "load" => {
            let key = format!("user:{}", account);
            storage::get_worker(&key)?
                .map(|d| String::from_utf8_lossy(&d).to_string())
                .unwrap_or_else(|| "No data".to_string())
        }
        _ => "Unknown action".to_string(),
    };

    // 4. Output
    let output = Output { success: true, account, result };
    print!("{}", serde_json::to_string(&output)?);
    io::stdout().flush()?;

    Ok(())
}
```

## Host Interfaces

A WASI P2 component reaches the platform through host interfaces declared in
`worker/wit/`. The worker links an interface only when the component imports
it; a P1 module gets none of them. Each published version is a frozen ABI
(`worker/wit/README.md`).

| Interface | What it gives | Condition |
|---|---|---|
| `near:rpc/api@0.1.0` | NEAR RPC: views, blocks, transactions — a transaction is signed with a key the module supplies, never the worker's | the worker's RPC proxy is on (`NEAR_RPC_PROXY_AVAILABLE=1`); at most `NEAR_RPC_PROXY_MAX_CALLS` calls per run (default 100) |
| `near:storage/api@0.2.0` (and `@0.1.0` for older builds) | persistent storage — the `outlayer` crate's `storage` module | a run through a project; otherwise refused before it starts |
| `near:payment/api@0.1.0` | `refund-usd`: give part of `ATTACHED_USD` back | — |
| `near:vrf/api@0.1.0` | verifiable randomness — `outlayer::vrf` | the worker has a keystore; otherwise refused before it starts |
| `outlayer:wallet/api@0.1.0` | the custody wallet's operations | a run that names a wallet (below); without one every call answers `no_wallet` |
| `outlayer:signing-keys/api@0.1.0` | keys declared in the manifest, by path | `signing_keys` in the manifest (`CONNECTOR_MANIFEST.md`) |
| `outlayer:encryption-keys/api@0.1.0` | symmetric keys declared in the manifest | `encryption_keys` in the manifest |
| `outlayer:tasks/api@0.1.0` | tasks for the owner of the run's secret row | `tasks: true` in the manifest (`docs/TASKS.md`) |

Outbound HTTP (`wasi:http`) is open to public addresses only: loopback,
private, link-local and other internal ranges are refused. A manifest's
`capabilities.network` turns it into an exact-host allowlist, mandatory for a
connector.

## Important Requirements

### ⚠️ 0. CRITICAL: Use Exact Versions from Examples

**DO NOT blindly use latest versions** of dependencies! The WASI ecosystem is extremely version-sensitive. Using wrong versions will cause cryptic errors like "import not found" or "failed to instantiate".

#### For WASI Applications

**✅ CORRECT**: Copy `Cargo.toml` from existing working examples:
- [random-example/Cargo.toml](./random-example/Cargo.toml) - WASI P1 template
- [ai-example/Cargo.toml](./ai-example/Cargo.toml) - WASI P2 template
- [oracle-example/Cargo.toml](./oracle-example/Cargo.toml) - WASI P2 with HTTP
- [wallet-probe/Cargo.toml](./wallet-probe/Cargo.toml) - WASI P2 importing a host interface with `wit-bindgen = "0.36"`

**Tested and working versions:**
```toml
[dependencies]
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
rand = "0.8"
getrandom = { version = "0.2", features = ["custom"] }

# For WASI P2 (HTTP support):
wasi-http-client = "0.2"

# OutLayer SDK (persistent storage, env access) - WASI P2 only:
outlayer = "0.2"

# Host interfaces the SDK does not wrap (RPC, wallet, payment):
wit-bindgen = "0.36"
```

**❌ WRONG**: Using `cargo add` or updating to latest:
```bash
# These commands may install incompatible versions:
cargo add serde serde_json
cargo update  # Can break working builds!
```

#### Why This Matters

1. **wasmtime runtime** expects specific WASI interface versions
2. **Newer crates** may use unstable WASI preview features not yet supported
3. **Older crates** may have missing imports or incompatible ABIs
4. **NEAR contracts** you write next to the module are a separate crate with their own pins (below)

**Common errors from wrong versions:**
```
❌ error: import 'wasi:http/types@0.3' has not been defined
❌ failed to instantiate WASM module
❌ entry symbol not defined: _initialize
```

**Bottom line**: Always start from a working example, don't experiment with versions until your app works.

### 1. Wrong Build Target (CRITICAL!)

**THIS IS THE #1 MISTAKE!**

```bash
# ❌ CRITICAL ERROR: Using wrong target for WASI modules
cargo build --target wasm32-unknown-unknown --release
# This produces NEAR contract WASM, NOT WASI module!
# It will NOT work with OutLayer worker!

# ✅ CORRECT: Use wasip1 for WASI modules
cargo build --target wasm32-wasip1 --release

# ✅ CORRECT: Use wasip2 for WASI modules with HTTP
cargo build --target wasm32-wasip2 --release
```

**Why this matters:**
- `wasm32-unknown-unknown` = NEAR contracts (on-chain, no WASI)
- `wasm32-wasip1/wasip2` = OutLayer modules (off-chain, with WASI)
- Using wrong target produces incompatible WASM that will fail at runtime

**For NEAR contracts (different from WASI modules!):**
```bash
# ✅ CORRECT: Use cargo-near for NEAR contracts
cargo near build

# ❌ WRONG: DO NOT use raw cargo build
cargo build --target wasm32-unknown-unknown --release
```

**See the difference?**
| What you're building | Target | Build command |
|---------------------|--------|---------------|
| **WASI Module** (OutLayer) | `wasm32-wasip1` | `cargo build --target wasm32-wasip1 --release` |
| **NEAR Contract** (on-chain) | `wasm32-unknown-unknown` | `cargo near build` |

**NEAR Contract Setup Checklist:**

```bash
# 1. Create rust-toolchain.toml (REQUIRED!)
cat > rust-toolchain.toml <<EOF
[toolchain]
channel = "1.85.0"
EOF

# 2. Update Cargo.toml dependencies
# Add these to [dependencies]:
# near-sdk = { version = "5.9.0", features = ["legacy"] }
# schemars = "0.8"

# 3. In types.rs, add:
# use schemars::JsonSchema;

# 4. Add JsonSchema derive to all types:
# #[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, JsonSchema, ...)]

# 5. For AccountId fields, use:
# #[schemars(with = "String")]
# pub owner: AccountId,

# 6. Build with cargo-near
cargo near build
```

**Example NEAR Contract Cargo.toml:**
```toml
[package]
name = "my-contract"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
near-sdk = { version = "5.9.0", features = ["legacy"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
schemars = "0.8"  # REQUIRED for contract ABI

[profile.release]
codegen-units = 1
opt-level = "z"
lto = true
debug = false
panic = "abort"
overflow-checks = true
```

**Example types.rs with JsonSchema:**
```rust
use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::AccountId;
use schemars::JsonSchema;  // REQUIRED!

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, JsonSchema, Clone, Debug)]
#[borsh(crate = "near_sdk::borsh")]
#[serde(crate = "near_sdk::serde")]
pub enum Status {
    Active,
    Completed,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, JsonSchema, Clone, Debug)]
#[borsh(crate = "near_sdk::borsh")]
#[serde(crate = "near_sdk::serde")]
pub struct MyData {
    pub id: u64,
    pub title: String,
    #[schemars(with = "String")]  // REQUIRED for AccountId!
    pub owner: AccountId,
    pub status: Status,
}
```

### 2. Binary Format (Not Library)

```toml
# ✅ CORRECT
[[bin]]
name = "my-app"
path = "src/main.rs"

# ❌ WRONG
[lib]
crate-type = ["cdylib"]
```

### 2. Entry Point

```rust
// ✅ CORRECT: main() function
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Your code
    Ok(())
}

// ❌ WRONG: Custom exports
#[no_mangle]
pub extern "C" fn execute() { } // Old pattern, don't use
```

### 3. Error Handling

```rust
// ✅ CORRECT: Return errors from main
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let data = serde_json::from_str(&input)?; // Propagates error
    Ok(())
}

// ❌ WRONG: a panic traps the run; the caller gets the panic text from stderr
// instead of an answer your code chose
fn main() {
    let data = serde_json::from_str(&input).unwrap();
}
```

### 3a. Wallet calls: the error is half the answer

Every `wallet::*` host function returns `(result, error)`. The call reaches the
network, a policy engine and a chain — it fails for reasons that have nothing
to do with your code, and an ignored error leaves you parsing an empty string
as if it were an answer.

The error string leads with a **machine code**, then a message, then any field
that changes what to do next:

```
"<code>: <message>[ key=value]..."
```

Match on the code, never on the wording:

```rust
// ✅ CORRECT: route on the code, and treat an empty result as no answer
let (result, error) = wallet::transfer("near", &to, &amount);
if !error.is_empty() {
    let code = error.split(':').next().unwrap_or("");
    match code {
        // Something else holds the wallet right now — it clears by itself.
        // `in_flight_request_id=<id>` names the operation to poll.
        "wallet_busy" => return Ok(json!({ "retry": true, "reason": error })),
        // The owner has to act. Retrying is noise.
        "policy_denied" | "wallet_frozen" => {
            return Ok(json!({ "needs_owner": true, "reason": error }))
        }
        // Agent Connect refused before signing, so no gas was spent.
        // `terminal=true` means the same request will never work.
        "agent_connect_denied" if error.contains("terminal=true") => {
            return Ok(json!({ "needs_owner": true, "reason": error }))
        }
        _ => return Err(error.into()),
    }
}
let moved: serde_json::Value = serde_json::from_str(&result)?;

// ❌ WRONG: the error is dropped and `result` is "" on every failure path
let (result, _) = wallet::transfer("near", &to, &amount);
let moved: serde_json::Value = serde_json::from_str(&result)?; // fails obscurely
```

Codes worth knowing: `no_wallet`, `wallet_busy`, `policy_denied`,
`wallet_frozen`, `agent_connect_denied`, `insufficient_balance`. A failure that is not one of
ours arrives verbatim rather than dressed in an invented code.

**A wallet runs one money operation at a time.** Two of your own calls in
flight together — two WASI runs paid by the same key, or one run doing two
things at once — will meet `wallet_busy`, and it waits a couple of seconds
before it says so. That is deliberate: spending limits are counted per wallet,
and counting them correctly means one decision at a time.

**A run has a wallet only when the call names one.** The worker links these
host functions whenever your component imports `outlayer:wallet/api`. A run
that named no wallet — an on-chain `request_execution`, an HTTPS call without
`X-Wallet-Id` — still starts, and every wallet function answers:

```
no_wallet: this run has no wallet; the operation needs a call made with the wallet's own payment key and X-Wallet-Id
```

A run gets the wallet over HTTPS with a payment key the wallet itself owns
(`X-Payment-Key`, its owner the wallet's implicit account) plus
`X-Wallet-Id: <wallet id>` — the id `GET /wallet/v1/address` returns. The
header confirms the wallet the key identifies and never selects another: a
different id is refused, and an absent or empty header means no wallet at all.
`wasi-examples/wallet-probe` is the smallest working example, and its README
covers the calling conventions.

### 3b. EVM signing and sub-keys (connectors)

`outlayer:wallet/api` signs on EVM chains too: `evm-sign-typed-data`,
`evm-sign-message`, `evm-sign-transaction`, each taking a `label` as its last
argument, and `get-sub-key-address(chain, label)`. A label names a **sub-key**
— a distinct address of the same wallet, under the keystore path
`connector.{connector_id}.{label}` that the worker builds from the connector's
verified manifest. The empty label is the sub-key `default`; the wallet's own
EVM key (what `get-address` returns) is never signable from inside a module.
Only a connector published under the connectors namespace whose manifest
`connector_id` equals its project name has sub-keys; elsewhere every label
answers `sub_key_unavailable`. Labels are `[a-z0-9][a-z0-9_-]{0,31}`; anything
else is `invalid_label`.

```rust
// The connector's trading address on Base — stable for this connector + label.
let (addr, err) = wallet::get_sub_key_address("base", "trading");
// Sign a CLOB order with the trading key; the keystore computes the digest.
let (sig, err) = wallet::evm_sign_typed_data("base", &typed_data_json, "trading");
```

Signatures are gated by the wallet's `evm_sign` capability (`raw_tx` for
`evm-sign-transaction`); a refusal comes back as `policy_denied`. The worker
forwards everything as-is and hashes nothing — the digest is the keystore's.
See `docs/CONNECTORS.md` §4.5 for what a sub-key is and is not.

The way funds travel between a venue and the wallet: `deposit-intent(chain,
token, amount)` returns a 1Click deposit address that brings funds from
another chain INTO the wallet's intents balance, `get-intents-balance(token)`
reads that balance per asset, and `withdraw`/`swap` draw from it. The same
three exist for the wallet's CONFIDENTIAL balance
(`confidential-deposit-intent`, `get-confidential-balance`,
`confidential-withdraw`): same policy, but a movement out of it does not name
the wallet's NEAR account on chain. A connector that funds a venue lets the
caller choose the source (`intents` or `confidential`) and pays into the
same address either way.

### 3c. Secrets: the author's, yours, the agent's

Three kinds of secret can reach a run, and every project — not only a
connector — may use all three. All of them are rows stored on chain with
`store_secrets` under an **accessor** (`Project` or `WasmHash`), a
**profile** and an **owner**, encrypted to the keystore; the keystore decrypts
them inside the TEE and the worker hands them to your module as environment
variables.

**The author's.** Your own credential — an upstream API key, an SMTP password
— the same for every caller. Store it under your account with the accessor of
the project you publish, and name the profile in a manifest embedded in the
wasm (`outlayer.manifest` custom section, see `CONNECTOR_MANIFEST.md`):

```jsonc
{ "author_secrets": { "profile": "author" } }
```

The worker decrypts that profile into **every** run of the project; the call
carries nothing. Its access condition is judged against the real caller — the
transaction's signer, or, where the condition says `Predecessor`, the account
that called the contract — which makes it the project's admission gate:
`AllowAll` for a public app, a
`Whitelist` or `DaoMember` for a circle — a caller the condition refuses gets a
refused run before anything executes. A declared profile nobody stored refuses
the run too, with a message saying what to store. Two cautions: a manifest that
carries `connector_id` turns the outbound allowlist mandatory (a connector's
rule), so leave it out; and a run that has no project — a `WasmUrl` source
executed directly — has nowhere to hold an author secret, so build the
manifest into the artefact you publish as a project only
(`test-secrets-example` does this with a cargo feature).

**The caller's.** A secret the caller names in the request — `secrets_ref:
{account_id, profile}` in the HTTPS wrapper or in `request_execution` — gated
by the condition its owner stored. The dashboard and the CLI default a new
personal secret under a project to `Whitelist[you]`: anyone who names an
`AllowAll` row can run the project with it. An owner hands a credential to
their agents by storing it once and whitelisting the agents' wallet accounts
(`outlayer secrets access --access whitelist:me.near,<agent>@2026-10-01` —
the `@date` makes the grant lapse on its own); the agent names `{owner,
profile}` in `secrets_ref`. Revoking is editing the whitelist; the ciphertext
never moves.

**The agent's.** A secret stored FOR a custody wallet under the wallet's own
account (`outlayer secrets set-for-agent`), which a connector call fetches with
`X-Use-Owner-Secret: 1` and nothing else can read.

A key defined on both the author's and the caller's side refuses the run rather
than picking a winner. System names (every variable in `WASM_ENV_VARS.md`) are
refused by the keystore when secrets are stored and stripped at run time, so
whatever your module reads under a system name came from the worker. The
`PROTECTED_` prefix is reserved for secrets the keystore generates.

### 3d. Who may call your project

A manifest's `callers` block decides which doors a run may come through —
a direct call, a call through a contract, a NEP-366 meta-transaction, an HTTPS
call — and the worker refuses any other before it decrypts or runs anything:

```jsonc
{ "callers": { "contract": { "only": ["game.near"] } } }   // only game.near may call it
{ "callers": { "contract": "deny", "https": "deny" } }      // direct calls only
{ "callers": { "direct": "deny", "contract": "deny" } }     // HTTPS only
```

No block admits every door. A block leaves open every door it does not name,
except meta-transactions, which need `"meta_tx": "allow"`. `only` lists every
account that may call OutLayer for the project, so it shuts HTTPS, direct
calls and meta-transactions by itself. The rule is in the wasm, so it binds the
version and its owner alike — and only that version: remove the versions
published without it, or a caller pins one of them with `version_key`. The table of doors, the refusal sentences and
the limits on `only` are in `CONNECTOR_MANIFEST.md` (`callers`).

### 4. Output Size

stdout holds up to 10 MiB; a write past it fails the run. An on-chain answer is
also bounded by NEAR's transaction size, and whatever a contract receives it
pays gas to read: return a digest or a reference for anything large.

### 5. Dependencies

```rust
// ✅ Safe dependencies
serde, serde_json          // JSON processing
rand                       // Random numbers (P1 & P2)
wasi-http-client          // HTTP requests (P2 only)

// ⚠️ Avoid these
tokio                      // Async runtime (not needed in WASM)
reqwest                    // Use wasi-http-client instead
std::thread               // Threading not supported
```

## Testing Your Module

### Option 1: Quick Test with wasmtime

```bash
# Install wasmtime
curl https://wasmtime.dev/install.sh -sSf | bash

# Test your WASM
echo '{"test":"data"}' | wasmtime your-app.wasm
```

### Option 2: Use Universal Test Runner

See [wasi-test-runner](./wasi-test-runner/README.md) for a local runner that checks:
- ✅ Binary format correctness
- ✅ Fuel metering
- ✅ Input/output handling
- ✅ JSON output
- ✅ `near:rpc` host functions (with `--rpc`)

It is not the worker: it links only `near:rpc`, preopens a directory and does
not enforce the memory or time limit (see its README).

## Common Pitfalls

### 1. "entry symbol not defined: _initialize"

**Problem**: Using `[lib]` with `crate-type = ["cdylib"]`

**Solution**: Use `[[bin]]` format (see Quick Start)

### 2. Empty output

**Problem**: Forgot to flush stdout

**Solution**:
```rust
print!("{}", output);
io::stdout().flush()?; // ← Add this!
```

### 3. "Failed to instantiate WASM module"

**Problem**: Wrong target or missing `main()`

**Solution**:
- Use `wasm32-wasip1` or `wasm32-wasip2` target
- Ensure you have `fn main()` function

### 4. "Failed to parse output as JSON" on an HTTPS call

**Problem**: An HTTPS call reads stdout as `Json`, and something besides the
answer was printed (a log line, a banner)

**Solution**: print exactly one JSON value to stdout; send diagnostics to stderr

### 5. "use of unstable library feature" when building

**Problem**: Test dependencies in WASM build

**Solution**: Use optional dependencies with features (see ai-example example)

### 6. HTTP requests fail

**Problem**: Using WASI P1 instead of P2

**Solution**: Use `wasm32-wasip2` target and `wasi-http-client` crate

### 7. Popup window blocked in browser

**Problem**: Multiple consecutive wallet calls trigger browser popup blocker

**Error**: `Popup window blocked. Please allow popups for this site.`

**Solution**: Only make ONE wallet call per user action. Never chain multiple `signMessage` or `signAndSendTransaction` calls:

```typescript
// ❌ WRONG - Multiple calls in sequence
async function badPattern() {
  const sig1 = await wallet.signMessage({...}); // First popup OK
  const sig2 = await wallet.signMessage({...}); // BLOCKED!
}

// ✅ CORRECT - One call per user click
async function handleUserClick() {
  const sig = await wallet.signMessage({...}); // User initiated
  // Cache signature for reuse
}
```

**Best practice**: Cache signatures on frontend (50-60 min) to avoid repeated popups.

See [BEST_PRACTICES_OUTLAYER_NEAR.md](./BEST_PRACTICES_OUTLAYER_NEAR.md) for signature caching pattern.

### 8. Frontend transaction errors with wallet-selector

**Problem**: Using manual action format like `{ type: 'FunctionCall', params: {...} }`

**Error**: `Enum key (type) not found in enum schema`

**Solution**: Use `actionCreators` from `@near-js/transactions`:

```typescript
import { actionCreators } from '@near-js/transactions';

// ❌ WRONG - This will fail with enum schema error
await wallet.signAndSendTransaction({
  receiverId: contractId,
  actions: [{
    type: 'FunctionCall',
    params: {
      methodName: 'my_method',
      args: { foo: 'bar' },
      gas: '100000000000000',
      deposit: '1000000000000000000000',
    },
  }],
});

// ✅ CORRECT - Use actionCreators
const action = actionCreators.functionCall(
  'my_method',           // method name
  { foo: 'bar' },        // args object
  BigInt('100000000000000'),                // gas (BigInt)
  BigInt('1000000000000000000000')         // deposit in yoctoNEAR (BigInt)
);

await wallet.signAndSendTransaction({
  receiverId: contractId,
  actions: [action],
});
```

**Why**: @near-wallet-selector expects properly formatted actions from `@near-js/transactions`, not raw objects.

**See working example**: `wasi-examples/captcha-example/launchpad-app/src/App.tsx`

### 9. OutLayer callback deserialization errors

**Problem**: A contract's callback fails to deserialize what OutLayer returned

**Error**: `Failed to deserialize callback using JSON. Error: 'missing field ...'` or `invalid type: map, expected a string`

**Root cause**: the callback receives the run's output as a JSON value, in the
request's `response_format`: the guest's JSON for `Json`, a string for `Text`,
base64 for `Bytes` — and `null` when the run failed or produced nothing. There
is no wrapper of OutLayer's around it. A type that expects a different shape
than the guest prints fails here.

**Solution**: request `Json`, and deserialize into exactly what your module prints:

```rust
#[derive(Deserialize, JsonSchema)]
#[serde(crate = "near_sdk::serde")]
pub struct YourActualResponse {
    pub some_field: String,
}

#[private]
pub fn on_outlayer_callback(
    &mut self,
    user: AccountId,
    #[callback_result] result: Result<Option<YourActualResponse>, PromiseError>,
) {
    match result {
        Ok(Some(response)) => log!("Received: {}", response.some_field),
        // The run failed or printed nothing: OutLayer returned null
        Ok(None) => log!("OutLayer execution failed"),
        // request_execution itself failed (refused at the door)
        Err(e) => log!("Promise error: {:?}", e),
    }
}
```

A module may print its own envelope — `private-dao-example`'s prints
`{"success", "result", "error"}`, and its contract deserializes that
(`wasi-examples/private-dao-example/dao-contract/src/lib.rs`, `on_key_derived`)
— but the shape is the module's choice, not the platform's.

## Examples

### Complete Working Examples

1. **[random-example](./random-example/)** - WASI P1
   - Random number generation
   - JSON input/output
   - ~111KB binary

2. **[ai-example](./ai-example/)** - WASI P2
   - HTTP POST requests
   - OpenAI API integration
   - Component model

3. **[near-email](https://github.com/out-layer/near-email)** - WASI P2 (Complex)
   - Full email service with encryption
   - OutLayer SDK: `signer_account_id()`, `storage`
   - External HTTP API (db-api) integration
   - Next.js frontend with wallet-selector
   - NEP-413 signature verification
   - See [BEST_PRACTICES_OUTLAYER_NEAR.md](./BEST_PRACTICES_OUTLAYER_NEAR.md) for patterns

### Minimal Example (Copy-Paste Ready)

```rust
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

#[derive(Deserialize)]
struct Input {
    value: i32,
}

#[derive(Serialize)]
struct Output {
    result: i32,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;

    let data: Input = serde_json::from_str(&input)?;

    let output = Output {
        result: data.value * 2,
    };

    print!("{}", serde_json::to_string(&output)?);
    io::stdout().flush()?;

    Ok(())
}
```

**Cargo.toml**:
```toml
[package]
name = "example"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "example"
path = "src/main.rs"

[dependencies]
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

[profile.release]
opt-level = "z"
lto = true
strip = true
```

**Build & Test**:
```bash
cargo build --target wasm32-wasip1 --release
echo '{"value":21}' | wasmtime target/wasm32-wasip1/release/example.wasm
# Output: {"result":42}
```

## Deployment to NEAR OutLayer

OutLayer runs a published `.wasm`, named by its sha256: build it, publish it,
and register it as a project version. The worker refuses a file whose bytes do
not match the hash.

```bash
cargo build --target wasm32-wasip1 --release
outlayer upload target/wasm32-wasip1/release/example.wasm
# prints SHA256 and: FastFS URL: https://test.fastfs.io/your.testnet/outlayer.testnet/<sha256>.wasm
outlayer deploy example <FastFS URL> --target wasm32-wasip1   # creates the project or adds a version, activates it
```

Any https URL works for `outlayer deploy`; FastFS is the default. On the
dashboard, Projects → Create Project / Add Version take the WASM URL and its
SHA256.

### Option 1: Blockchain Mode (via NEAR transaction)

1. **Deploy the project** (above)
2. **Call contract**:

```bash
near call outlayer.testnet request_execution '{
  "source": {
    "Project": {"project_id": "your.testnet/example", "version_key": null}
  },
  "resource_limits": {
    "max_instructions": 10000000,
    "max_memory_mb": 128,
    "max_execution_seconds": 60
  },
  "input_data": "{\"value\":21}"
}' --accountId your.testnet --deposit 0.1
```

Attach at least `estimate_execution_cost(resource_limits, input_len)` (a view
method of the contract); what the run does not use comes back.

3. **Check result** in NEAR Explorer: the output is the transaction's return value

**Pros:** On-chain request and result, callable from other contracts
**Cons:** Requires a signed transaction per call

### Option 2: HTTPS API Mode (via Payment Key)

For better UX (no popups, larger payloads), use Payment Keys:

1. **Create Payment Key** at OutLayer Dashboard
2. **Call via HTTPS**:

```bash
curl -X POST https://api.outlayer.ai/call/your-account.near/your-project \
  -H "Content-Type: application/json" \
  -H "X-Payment-Key: alice.near:1:your-secret-key" \
  -d '{
    "input": {"action": "process", "data": "hello"},
    "resource_limits": {
      "max_instructions": 2000000000,
      "max_memory_mb": 512,
      "max_execution_seconds": 120
    }
  }'
```

The response's `output` field is the module's JSON (an HTTPS call always reads
stdout as `Json`). Add `"async": true` to get a `call_id` back at once and poll
`GET /calls/{call_id}`.

**Pros:** No popups, faster, request body up to 10 MB
**Cons:** Requires pre-paid balance

### Frontend Integration

See [BEST_PRACTICES_OUTLAYER_NEAR.md](./BEST_PRACTICES_OUTLAYER_NEAR.md) for:
- Wallet-selector setup (avoid popup blocking)
- Payment Key integration
- NEP-413 signature authentication

## A NEAR Contract Next to Your Module

A contract that calls OutLayer (a proxy contract) is a separate crate with its
own pins, built with `cargo near build`: `rust-toolchain.toml` at
`channel = "1.85.0"`, `near-sdk` 5.9.0, `schemars = "0.8"`. How to write one is
in [PROXY_CONTRACTS_TUTORIAL.md](./PROXY_CONTRACTS_TUTORIAL.md);
[random-example/random-contract](./random-example/random-contract/) is a
working one next to its module.

## Need Help?

- Check [examples](./random-example/) for working code
- Use [test runner](./wasi-test-runner/README.md) to validate your module
- Review [common pitfalls](#common-pitfalls) section
- Read [BEST_PRACTICES_OUTLAYER_NEAR.md](./BEST_PRACTICES_OUTLAYER_NEAR.md) for frontend patterns
- Test locally with wasmtime before deploying
