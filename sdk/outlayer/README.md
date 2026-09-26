# OutLayer SDK

Rust SDK for building WASM applications on [OutLayer](https://app.outlayer.ai) - verifiable compute and custody for AI agents, on NEAR.

[![Crates.io](https://img.shields.io/crates/v/outlayer.svg)](https://crates.io/crates/outlayer)
[![Documentation](https://docs.rs/outlayer/badge.svg)](https://docs.rs/outlayer)

## Installation

```toml
[dependencies]
outlayer = "0.1"
```

Signing keys and encryption keys (with sealed storage) are opt-in features:

```toml
[dependencies]
outlayer = { version = "0.1.2", features = ["signing-keys", "encryption-keys"] }
```

| Feature | Adds | Host interface |
|---------|------|----------------|
| `signing-keys` | `outlayer::signing_keys` | `outlayer:signing-keys` |
| `encryption-keys` | `outlayer::encryption_keys`, `outlayer::storage::sealed` | `outlayer:encryption-keys` |

A component imports only the host interfaces whose functions it calls, so
enabling a feature changes nothing for a component that does not call it.

**Requirements:** WASI Preview 2 (`wasm32-wasip2` target)

```bash
rustup target add wasm32-wasip2
cargo build --target wasm32-wasip2 --release
```

## Quick Start

```rust
use outlayer::{env, storage};

fn main() {
    // Get caller info
    let signer = env::signer_account_id().unwrap_or_default();

    // Read input
    let input = env::input_string().unwrap_or_default();

    // Use persistent storage
    let count = storage::increment("visits", 1).unwrap();

    // Output result
    env::output_json(&serde_json::json!({
        "signer": signer,
        "visits": count,
        "input": input
    })).unwrap();
}
```

## Features

### Environment (`outlayer::env`)

Access execution context and I/O:

```rust
use outlayer::env;

// Get NEAR account info
let signer = env::signer_account_id();           // User who signed tx (alice.near)
let predecessor = env::predecessor_account_id(); // Contract that called OutLayer
let tx_hash = env::transaction_hash();

// Input/Output
let input: MyRequest = env::input_json()?.unwrap();
env::output_json(&response)?;

// Environment variables (including secrets)
let api_key = env::var("OPENAI_API_KEY");
```

**Available environment variables:**
- `NEAR_SENDER_ID` - Account that signed the transaction
- `NEAR_PREDECESSOR_ID` - Contract that called OutLayer
- `NEAR_TRANSACTION_HASH` - Transaction hash
- `USD_PAYMENT` - Attached USD payment (micro-units)
- Custom secrets stored via dashboard

### Storage (`outlayer::storage`)

Encrypted persistent key-value storage:

```rust
use outlayer::storage;

// Basic operations
storage::set("key", b"value")?;
let data = storage::get("key")?;
let exists = storage::has("key");
storage::delete("key");
let keys = storage::list_keys("prefix:")?;

// Convenience methods
storage::set_string("name", "Alice")?;
storage::set_json("config", &my_struct)?;
let config: Config = storage::get_json("config")?.unwrap();

// Atomic operations (concurrent-safe)
storage::increment("counter", 1)?;
storage::decrement("stock", 1)?;
storage::set_if_absent("init", b"done")?;
storage::set_if_equals("balance", &old, &new)?;

// Worker-private storage (shared across all users)
storage::set_worker("global_state", b"data")?;
let state = storage::get_worker("global_state")?;

// Public storage (readable by other projects)
storage::set_worker_with_options("oracle:ETH", &price, Some(false))?;
// Another project is named by "owner.near/project-name" or by its uuid "p0000000000000001"
let price = storage::get_worker_from_project("oracle:ETH", Some("oracle.near/price-feed"))?;
```

**Storage isolation:**
- User storage: Isolated per caller (`alice.near` can't read `bob.near`'s data)
- Worker storage: Shared across all users, only accessible from WASM
- Public storage: Cross-project readable (for oracles, shared configs)

### Version Migration

```rust
// Read data from previous WASM version
let old_data = storage::get_by_version("key", "abc123...")?;

// Clean up old version's data after migration
storage::clear_version("abc123...")?;
```

### Raw Storage (`outlayer::storage`)

Bytes stored as given, with no keystore encryption, in the same per-account
storage and key namespace as `set`/`get`:

```rust
storage::set_raw("blob", &bytes)?;
let blob = storage::get_raw("blob")?;
storage::set_if_absent_raw("blob", &bytes)?;
storage::set_if_equals_raw("blob", &current, &next)?;
```

**The key name and the value are stored in plaintext, and the operator can read
both.** Encrypt the value first (with `encryption_keys`) and keep secrets out of
key names — `storage::sealed` does both. A key holds one record in one mode:
`get_raw` on a key written with `set` (or `get` on one written with `set_raw`) is
an error; delete the record before writing it in the other mode. `has`, `delete`
and `list_keys` work on both.

### Signing Keys (`outlayer::signing_keys`, feature `signing-keys`)

Keys the keystore derives inside the TEE for the project (or the exact build)
and the caller. Declare them in the component's `outlayer.manifest`
(`"signing_keys": [{"path": "records", "type": "ed25519"}]`); the component
names a key by path and never sees it:

```rust
use outlayer::signing_keys;

let public_key = signing_keys::public_key("records", None)?;
let signature = signing_keys::sign("records", None, b"myapp:record:v1:42")?;

// NEP-413 (NEAR signMessage); the host builds the signed bytes
let signed = signing_keys::sign_nep413("records", None, "login", "myapp.near", &nonce, None)?;
// signed.account_id, signed.public_key, signed.signature
```

`vault` is the key's declared vault: `None` for a key declared without one.
Never sign bytes or digests the caller supplied: the public key is a real NEAR
implicit account (ed25519) or EVM address (secp256k1). Sign only messages the
component composes itself.

### Encryption Keys (`outlayer::encryption_keys`, feature `encryption-keys`)

Symmetric keys that seal data only the component can open again, declared as
`"encryption_keys": [{"path": "records"}]`:

```rust
use outlayer::encryption_keys;

let sealed = encryption_keys::encrypt("records", None, b"secret", b"record:42")?;
let opened = encryption_keys::decrypt("records", None, &sealed, b"record:42")?;
let tag = encryption_keys::mac("records", None, b"record:42")?; // HMAC-SHA256, 32 bytes
```

### Sealed Storage (`outlayer::storage::sealed`, feature `encryption-keys`)

Raw storage the component encrypts itself. Record `name` is stored under
`hex(mac(path, vault, name))` with the value `encrypt(path, vault, value,
aad = name)`, so the operator sees neither the name nor the value, and a
ciphertext copied onto another record fails to decrypt:

```rust
use outlayer::storage::sealed;

sealed::set("records", None, "balance:alice", b"100")?;
if let Some(record) = sealed::get("records", None, "balance:alice")? {
    let value = record.plaintext();
}
sealed::set_if_absent("records", None, "init", b"1")?;
sealed::has("records", None, "init")?;
sealed::delete("records", None, "init")?;
```

`has` and `delete` answer `false` both for no record and for a failed storage
call (the host returns a plain `bool`), so `false` is not proof of absence;
`get` returns a failed call as `Err`.

Encryption is randomized, so compare-and-swap compares the stored ciphertext,
never a plaintext: `get` returns a `Sealed` holding both, and it is the
`expected` argument of `set_if_equals` for the same record. A `Sealed` read
from another record (another name, path or vault) is refused with an `Err`:

```rust
let mut current = sealed::get("records", None, "balance:alice")?.ok_or("missing")?;
loop {
    let next = update(current.plaintext());
    match sealed::set_if_equals("records", None, "balance:alice", &current, &next)? {
        (true, _) => break,
        (false, Some(actual)) => current = actual, // changed by another run
        (false, None) => return Err("deleted".into()),
    }
}
```

The operator still sees that a record exists, when it is touched, and its length
(plaintext + 41 bytes). `list_keys` returns tags, not names.

## Example Project

```toml
# Cargo.toml
[package]
name = "my-outlayer-app"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "my-outlayer-app"
path = "src/main.rs"

[dependencies]
outlayer = "0.1"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

[profile.release]
opt-level = "s"
lto = true
strip = true
```

```rust
// src/main.rs
use outlayer::{env, storage};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct Request {
    action: String,
}

#[derive(Serialize)]
struct Response {
    success: bool,
    message: String,
}

fn main() {
    let result = run();
    let response = match result {
        Ok(msg) => Response { success: true, message: msg },
        Err(e) => Response { success: false, message: e.to_string() },
    };
    env::output_json(&response).unwrap();
}

fn run() -> Result<String, Box<dyn std::error::Error>> {
    let signer = env::signer_account_id()
        .ok_or("No signer")?;

    let request: Request = env::input_json()?
        .ok_or("No input")?;

    match request.action.as_str() {
        "increment" => {
            let count = storage::increment(&format!("count:{}", signer), 1)?;
            Ok(format!("Count: {}", count))
        }
        "get" => {
            let count = storage::get_json::<i64>(&format!("count:{}", signer))?
                .unwrap_or(0);
            Ok(format!("Count: {}", count))
        }
        _ => Err("Unknown action".into())
    }
}
```

Build and test:

```bash
cargo build --target wasm32-wasip2 --release
echo '{"action":"increment"}' | wasmtime target/wasm32-wasip2/release/my-outlayer-app.wasm
```

## Publishing to crates.io

```bash
cd sdk/outlayer

# 1. Bump version in Cargo.toml
#    0.1.2 -> 0.1.3 (patch)
#    0.1.2 -> 0.2.0 (minor)

# 2. Verify it compiles for the target, with and without the features
cargo check --target wasm32-wasip2
cargo check --target wasm32-wasip2 --all-features
cargo test --all-features

# 3. Dry-run publish (checks packaging without uploading)
cargo publish --dry-run

# 4. Publish
cargo publish
```

**Before publishing:**
- Ensure `version` in `Cargo.toml` is bumped
- Ensure `wit/` directory is included (check that `.gitignore` doesn't exclude it)
- WIT files (`wit/world.wit`, `wit/deps/*.wit`) must be in the published crate — `wit-bindgen` reads them at compile time

**If WIT files are missing from the published crate**, add to `Cargo.toml`:
```toml
[package]
include = ["src/**/*", "wit/**/*", "Cargo.toml", "README.md", "LICENSE*"]
```

## Documentation

- [OutLayer Docs](https://app.outlayer.ai/docs) - Full documentation
- [Storage Guide](https://app.outlayer.ai/docs/storage) - Persistent storage
- [WASI Tutorial](https://github.com/out-layer/outlayer/blob/main/wasi-examples/WASI_TUTORIAL.md) - Building WASM apps
- [Examples](https://github.com/out-layer/outlayer/tree/main/wasi-examples) - Working examples

## License

MIT OR Apache-2.0
