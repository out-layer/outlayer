# WASI Development Tutorial for NEAR OutLayer

This guide explains how to create WASM modules that work with NEAR OutLayer platform.

> **🚨 IMPORTANT:** If you just need to know which build command to use, read [BUILD_TARGETS.md](BUILD_TARGETS.md) first!

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
7. [Important Requirements](#important-requirements)
8. [Testing Your Module](#testing-your-module)
9. [Common Pitfalls](#common-pitfalls)
10. [Examples](#examples)

## Overview

NEAR OutLayer executes WASM modules off-chain using wasmtime runtime. Your code runs in a sandboxed environment with:
- **Stdin** for input data (JSON)
- **Stdout** for output data (JSON)
- **WASI** for system interfaces (random, time, etc.)
- **Fuel metering** for instruction counting
- **Resource limits** (memory, time, instructions)

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
- **Features**: HTTP client, advanced filesystem, sockets
- **Size**: Larger binaries (~500KB-1MB)
- **Example**: [ai-example](./ai-example/)

### Which to Choose?

| Feature | WASI P1 | WASI P2 |
|---------|---------|---------|
| HTTP requests | ❌ | ✅ |
| JSON processing | ✅ | ✅ |
| Random numbers | ✅ | ✅ |
| File I/O | ⚠️ Limited | ✅ Full |
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
use wasi_http_client::{Client, Request, Method};

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
    let client = Client::new();
    let request = Request::new(Method::Get, &input.url);
    let response = client.send(request)?;

    // Process response
    let output = Output {
        status: response.status(),
        body: String::from_utf8_lossy(response.body()).to_string(),
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
# Test with wasmtime
echo '{"url":"https://api.example.com/data"}' | wasmtime target/wasm32-wasip2/release/my-http-app.wasm
```

## Input/Output Format

### CRITICAL REQUIREMENTS

1. **Input**: Always read from `stdin` (not command-line arguments)
2. **Output**: Always write to `stdout` (not stderr)
3. **Format**: JSON only (UTF-8 encoded)
4. **Size limit**: Depends on how OutLayer is called:
   - **Blockchain mode** (via `near call`): ≤900 bytes (NEAR Protocol limit)
   - **HTTPS API mode** (via Payment Key): Up to 25MB
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

// ❌ WRONG: Writing to stderr
fn main() {
    eprintln!("result"); // Won't be captured!
}
```

## OutLayer SDK

The `outlayer` crate provides access to OutLayer-specific features for WASI P2 modules.

### Installation

```toml
[dependencies]
outlayer = "0.1"
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

**Note**: `signer_account_id()` returns:
- `Some(account_id)` when called via blockchain transaction
- `Some(payment_key_owner)` when called via HTTPS API with Payment Key
- `None` when called via HTTPS API without authentication

### Persistent Storage

OutLayer provides worker-encrypted storage that persists across executions:

```rust
use outlayer::storage;

// Write data (encrypted at rest, only this worker can read)
storage::set_worker("my_key", b"my_value")?;

// Read data
if let Some(data) = storage::get_worker("my_key")? {
    let value = String::from_utf8(data)?;
    println!("Stored value: {}", value);
}
```

**Use cases:**
- Store API keys/secrets (migrated from env vars)
- Cache expensive computations
- Maintain state between executions

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

## Important Requirements

### ⚠️ 0. CRITICAL: Use Exact Versions from Examples

**DO NOT blindly use latest versions** of dependencies! The WASI ecosystem is extremely version-sensitive. Using wrong versions will cause cryptic errors like "import not found" or "failed to instantiate".

#### For WASI Applications

**✅ CORRECT**: Copy `Cargo.toml` from existing working examples:
- [random-example/Cargo.toml](./random-example/Cargo.toml) - WASI P1 template
- [ai-example/Cargo.toml](./ai-example/Cargo.toml) - WASI P2 template
- [oracle-example/Cargo.toml](./oracle-example/Cargo.toml) - WASI P2 with HTTP

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
outlayer = "0.1"

# For WASI P1 with NEAR contracts embedded (advanced):
borsh = { version = "1.5", features = ["derive"] }
base64 = "0.21"
ed25519-dalek = "2.1"
```

**❌ WRONG**: Using `cargo add` or updating to latest:
```bash
# These commands may install incompatible versions:
cargo add serde serde_json
cargo update  # Can break working builds!
```

#### For Embedded NEAR Contracts (Advanced)

If your WASI app needs to **build and deploy NEAR contracts inside WASM** (like [intents-example](https://github.com/out-layer/intents-example/)), this is **EVEN MORE CRITICAL**:

**✅ CORRECT**: Use exact versions from [intents-example/intents-contract/Cargo.toml](https://github.com/out-layer/intents-example/blob/main/intents-contract/Cargo.toml):
```toml
[package]
edition = "2018"  # ← Must be 2018, not 2021!

[lib]
crate-type = ["cdylib"]

[dependencies]
near-sdk = { version = "5.9.0", features = ["legacy", "unit-testing"] }
serde_json = { version = "1.0.133", features = ["preserve_order"] }

[profile.release]
codegen-units = 1
opt-level = "s"  # ← "s" for contracts, not "z"
lto = true
panic = "abort"
overflow-checks = true
```

**Build command for embedded contracts:**
```bash
cd your-contract-dir
cargo near build non-reproducible-wasm
```

**Why `non-reproducible-wasm`?**
- Reproducible builds require Docker and specific environment
- Inside WASI, we can't use Docker
- Non-reproducible is fine for testing and development

**Example structure:**
```
your-wasi-app/
├── Cargo.toml           # WASI app (edition = "2021", [[bin]])
├── src/
│   └── main.rs          # WASI entry point
└── embedded-contract/
    ├── Cargo.toml       # NEAR contract (edition = "2018", [lib])
    ├── build.sh         # ← cargo near build non-reproducible-wasm
    └── src/
        └── lib.rs       # Contract code
```

#### Why This Matters

1. **wasmtime runtime** expects specific WASI interface versions
2. **Newer crates** may use unstable WASI preview features not yet supported
3. **Older crates** may have missing imports or incompatible ABIs
4. **NEAR SDK** is tightly coupled to specific rustc versions
5. **cargo-near** expects exact near-sdk versions for builds

**Common errors from wrong versions:**
```
❌ error: import 'wasi:http/types@0.3' has not been defined
❌ failed to instantiate WASM module
❌ entry symbol not defined: _initialize
❌ cannot find trait Serialize in module `borsh`
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

// ❌ WRONG: Panics crash the worker
fn main() {
    let data = serde_json::from_str(&input).unwrap(); // Don't use unwrap()!
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
let (result, error) = wallet::transfer("near", &to, &amount, "");
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
let (result, _) = wallet::transfer("near", &to, &amount, "");
let moved: serde_json::Value = serde_json::from_str(&result)?; // fails obscurely
```

Codes worth knowing: `wallet_busy`, `policy_denied`, `wallet_frozen`,
`agent_connect_denied`, `insufficient_balance`. A failure that is not one of
ours arrives verbatim rather than dressed in an invented code.

**A wallet runs one money operation at a time.** Two of your own calls in
flight together — two WASI runs paid by the same key, or one run doing two
things at once — will meet `wallet_busy`, and it waits a couple of seconds
before it says so. That is deliberate: spending limits are counted per wallet,
and counting them correctly means one decision at a time.

**Importing the wallet makes it required.** The worker decides whether to
provide these host functions by looking at what your component imports, and a
component that imports `outlayer:wallet/api` is refused outright when the
request carries no wallet:

```
WASM imports outlayer:wallet/api but wallet is not available.
Wallet requires: X-Wallet-Id header in the execution request.
```

That happens before `main` runs, so it fails every call — including the ones
that were never going to touch the wallet. A module that imports the wallet can
only ever be called **with** one: `Authorization: Bearer wk_...` plus an
explicit `X-Wallet-Id`. An absent header, or one with an empty value, means no
wallet at all rather than "my own".

So keep wallet-using code in its own module rather than adding it to one that
also serves payment-key or on-chain calls. `wasi-examples/wallet-probe` is the
smallest working example of that shape, and its README covers the calling
conventions.

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
`store_secrets` under an **accessor** (`Project`, `Repo` or `WasmHash`), a
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
that called the contract — which makes it the project's admission gate: `AllowAll` for a public app, a
`Whitelist` or `DaoMember` for a circle — a caller the condition refuses gets a
refused run before anything executes. A declared profile nobody stored refuses
the run too, with a message saying what to store. Two cautions: a manifest that
carries `connector_id` turns the outbound allowlist mandatory (a connector's
rule), so leave it out; and a run that has no project — a `Repo` source
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
than picking a winner. Reserved names (`NEAR_SENDER_ID`, `PROTECTED_*`, …) are
refused at storage time and stripped at run time, so whatever your module reads
under a system name came from the worker.

### 4. Output Size

```rust
// ✅ CORRECT: Truncate large outputs
let mut output = generate_large_output();
if output.len() > 800 {
    output.truncate(800);
    output.push_str("...");
}
print!("{}", output);
```

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

See [WASI_TEST_RUNNER.md](./WASI_TEST_RUNNER.md) for a comprehensive test tool that validates:
- ✅ Binary format correctness
- ✅ Fuel metering
- ✅ Input/output handling
- ✅ Resource limits
- ✅ Compatibility with NEAR OutLayer

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

### 4. Output truncated in NEAR explorer

**Problem**: Output > 900 bytes

**Solution**: Truncate before returning:
```rust
if output.len() > 800 {
    output.truncate(800);
}
```

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

**Problem**: Callback receives OutLayer response but fails to deserialize

**Error**: `Failed to deserialize callback using JSON. Error: 'missing field pubkey'` or `invalid type: map, expected a string`

**Root cause**: OutLayer returns wrapped response format:
```json
{
  "success": true,
  "result": {"your_data": "here"},
  "error": null
}
```

**Solution**: Use `OutLayerResponse` wrapper type in callback:

```rust
// types.rs - Define wrapper type
#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct OutLayerResponse {
    pub success: bool,
    pub result: serde_json::Value,
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct YourActualResponse {
    pub some_field: String,
}

// lib.rs - Callback implementation
#[private]
pub fn on_outlayer_callback(
    &mut self,
    user: AccountId,
    #[callback_result] result: Result<Option<OutLayerResponse>, PromiseError>,
) {
    match result {
        Ok(Some(outlayer_response)) => {
            // Check success flag
            if !outlayer_response.success {
                let error_msg = outlayer_response.error.unwrap_or_else(|| "Unknown error".to_string());
                env::panic_str(&format!("OutLayer error: {}", error_msg));
            }

            // Parse result field to get your actual data
            let your_data: YourActualResponse = match serde_json::from_value(outlayer_response.result) {
                Ok(r) => r,
                Err(e) => {
                    env::panic_str(&format!("Invalid result format: {}", e));
                }
            };

            // Use your_data.some_field here
            log!("Received: {}", your_data.some_field);
        }
        Ok(None) => {
            env::panic_str("OutLayer execution returned None");
        }
        Err(e) => {
            env::panic_str(&format!("Promise error: {:?}", e));
        }
    }
}
```

**Why this works**:
- NEAR SDK automatically deserializes the JSON response into `OutLayerResponse`
- You then manually parse the `result` field using `serde_json::from_value`
- This two-step approach handles the wrapper format correctly

**See working example**: `wasi-examples/private-dao-example/dao-contract/src/lib.rs` (on_key_derived callback)

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

### Option 1: Blockchain Mode (via NEAR transaction)

1. **Push code to GitHub**
2. **Call contract**:

```bash
near call outlayer.testnet request_execution '{
  "code_source": {
    "repo": "https://github.com/username/repo",
    "commit": "main",
    "build_target": "wasm32-wasip1"
  },
  "resource_limits": {
    "max_instructions": 10000000,
    "max_memory_mb": 128,
    "max_execution_seconds": 60
  },
  "input_data": "{\"value\":21}"
}' --accountId your.testnet --deposit 0.1
```

3. **Check result** in NEAR Explorer

**Pros:** Fully on-chain, trustless
**Cons:** Requires transaction approval, output ≤900 bytes

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

**Pros:** No popups, faster, output up to 25MB
**Cons:** Requires pre-paid balance

### Frontend Integration

See [BEST_PRACTICES_OUTLAYER_NEAR.md](./BEST_PRACTICES_OUTLAYER_NEAR.md) for:
- Wallet-selector setup (avoid popup blocking)
- Payment Key integration
- NEP-413 signature authentication

## Working with Embedded NEAR Contracts

Some WASI applications need to **build, deploy, or interact with NEAR smart contracts** at runtime. Examples: [intents-example](https://github.com/out-layer/intents-example/), [random-example](./random-example/).

### When to Use Embedded Contracts

- **Dynamic contract deployment** - Deploy contracts from WASI at runtime
- **Contract factories** - Create multiple contract instances
- **Intent-based systems** - Deploy contracts per user/session
- **Testing infrastructure** - Automated contract testing

### Project Structure

```
your-wasi-app/
├── Cargo.toml              # Workspace root
├── src/
│   └── main.rs             # WASI entry point (reads stdin/stdout)
│   └── lib.rs              # (optional) shared logic
├── build.sh                # Build WASI module
└── your-contract/          # ← Embedded NEAR contract
    ├── Cargo.toml          # Contract dependencies
    ├── rust-toolchain.toml # Pin Rust version
    ├── build.sh            # Build contract WASM
    ├── res/local/          # Built contract output
    └── src/
        └── lib.rs          # Contract code
```

### Critical Configuration

#### 1. Workspace Cargo.toml (Root)

```toml
[workspace]
members = [".", "your-contract"]  # Include contract as member
resolver = "2"

[package]
name = "your-wasi-app"
version = "0.1.0"
edition = "2021"  # ← 2021 for WASI app

[[bin]]
name = "your-wasi-app"
path = "src/main.rs"

[dependencies]
# WASI dependencies
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
wasi-http-client = "0.2"  # For WASI P2

# NEAR interaction (if needed)
borsh = { version = "1.5", features = ["derive"] }
base64 = "0.21"
ed25519-dalek = "2.1"

[profile.release]
opt-level = "z"
lto = true
strip = true
```

#### 2. Contract Cargo.toml

**⚠️ CRITICAL: Copy from existing examples!**

```toml
[package]
name = "your-contract"
version = "0.1.0"
edition = "2018"  # ← Must be 2018 for near-sdk 5.9.0!

[lib]
crate-type = ["cdylib"]  # ← For WASM contract

[dependencies]
near-sdk = { version = "5.9.0", features = ["legacy", "unit-testing"] }
serde_json = { version = "1.0.133", features = ["preserve_order"] }

[profile.release]
codegen-units = 1
opt-level = "s"  # ← "s" for contracts (not "z")
lto = true
debug = false
panic = "abort"
overflow-checks = true
```

#### 3. rust-toolchain.toml (In Contract Directory)

```toml
[toolchain]
channel = "1.85.0"  # ← Pin exact version!
components = ["rustfmt"]
targets = ["wasm32-unknown-unknown"]
```

**Why pin version?**
- near-sdk 5.9.0 requires specific Rust version
- Newer Rust may have breaking changes
- Older Rust may miss required features

#### 4. Contract build.sh

```bash
#!/bin/bash
set -e

cd $(dirname $0)
mkdir -p res/local

echo "Building contract..."

# Build the contract (requires cargo-near installed)
cargo near build non-reproducible-wasm

# Copy output to res/local/
cp ../target/near/your_contract/your_contract.wasm res/local/

echo "✅ Contract built: res/local/your_contract.wasm"
ls -lh res/local/your_contract.wasm
```

**Important notes:**
- Use `non-reproducible-wasm` (reproducible needs Docker)
- `cargo-near` outputs to workspace `target/near/` directory
- Copy final WASM to `res/local/` for easy access from WASI code

### Building Process

```bash
# 1. Install cargo-near (one time)
cargo install cargo-near

# 2. Build the contract first
cd your-contract
./build.sh
cd ..

# 3. Build the WASI module
cargo build --target wasm32-wasip2 --release

# 4. Your WASI code can now embed the contract WASM
# Read from: your-contract/res/local/your_contract.wasm
```

### Loading Contract WASM in Rust Code

```rust
// In your src/main.rs or src/lib.rs

// Option 1: Embed at compile time (increases WASI binary size)
const CONTRACT_WASM: &[u8] = include_bytes!(
    "../your-contract/res/local/your_contract.wasm"
);

// Option 2: Read from filesystem (if available in WASI env)
fn load_contract() -> Result<Vec<u8>, std::io::Error> {
    std::fs::read("./your-contract/res/local/your_contract.wasm")
}

// Use the contract WASM
fn deploy_contract(contract_wasm: &[u8]) {
    // Your deployment logic here
    // - Encode as base64
    // - Send via NEAR RPC
    // - Handle transaction
}
```

### Examples to Study

1. **[random-example/random-contract](./random-example/random-contract/)** - Simple contract
   - Single contract in subdirectory
   - Basic workspace setup
   - Clean build script

2. **[intents-example/intents-contract](https://github.com/out-layer/intents-example/tree/main/intents-contract/)** - Advanced contract
   - Workspace with complex dependencies
   - Contract deployment at runtime
   - Full transaction handling

### Common Issues

#### "near-sdk version mismatch"
```bash
# ❌ Wrong: Using different near-sdk versions
your-contract/Cargo.toml: near-sdk = "5.5.0"  # Old
your-contract/Cargo.toml: near-sdk = "6.0.0"  # Too new

# ✅ Correct: Use 5.9.0
near-sdk = { version = "5.9.0", features = ["legacy", "unit-testing"] }
```

#### "edition 2021 not supported"
```bash
# ❌ Wrong: Using edition 2021 for contract
[package]
edition = "2021"

# ✅ Correct: Use edition 2018
[package]
edition = "2018"
```

#### "cargo near: command not found"
```bash
# Install cargo-near
cargo install cargo-near

# Verify installation
cargo near --version
```

#### "contract WASM not found"
```bash
# ❌ Wrong path - contract outputs to workspace target/
./your-contract/target/wasm32-unknown-unknown/release/contract.wasm

# ✅ Correct path - cargo-near uses target/near/
./target/near/your_contract/your_contract.wasm

# Or copy to res/local/ in build.sh
./your-contract/res/local/your_contract.wasm
```

### Best Practices

1. **Always use `non-reproducible-wasm` for WASI-embedded contracts**
   - Reproducible builds need Docker environment
   - WASI can't run Docker
   - Non-reproducible is fine for development and production

2. **Pin Rust version with rust-toolchain.toml**
   - Ensures consistent builds
   - Prevents breaking changes
   - Required for near-sdk compatibility

3. **Use workspace structure**
   - Keep contract and WASI app separate
   - Share dependencies via workspace
   - Easier to maintain

4. **Copy examples, don't start from scratch**
   - Version compatibility is complex
   - Examples are tested and working
   - Saves hours of debugging

5. **Test contract separately before embedding**
   ```bash
   # Test contract standalone first
   cd your-contract
   cargo near build non-reproducible-wasm
   near deploy test.testnet ./res/local/your_contract.wasm

   # Then integrate into WASI
   ```

## Need Help?

- Check [examples](./random-example/) for working code
- Use [test runner](./WASI_TEST_RUNNER.md) to validate your module
- Review [common pitfalls](#common-pitfalls) section
- Read [BEST_PRACTICES_OUTLAYER_NEAR.md](./BEST_PRACTICES_OUTLAYER_NEAR.md) for frontend patterns
- Test locally with wasmtime before deploying

---

**Last updated**: 2025-01
**Compatible with**: wasmtime 28+, NEAR OutLayer
