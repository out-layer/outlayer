# Proxy Contracts for OutLayer

How to build NEAR smart contracts that call OutLayer for off-chain computation.

## Overview

A proxy contract is a NEAR smart contract that:
1. Accepts user calls with attached NEAR
2. Forwards computation requests to OutLayer
3. Receives results via callback
4. Returns results to users or updates state

```
User → Your Contract → OutLayer Contract → Worker → Callback → Your Contract
```

`request_execution` yields until the worker resolves the run, and its return
value is the run's output. Your callback, chained with `.then(...)`, receives
that output.

A working proxy is [random-example/random-contract](./random-example/random-contract/):
everything below is taken from it.

## Basic Setup

### Dependencies

```toml
# Cargo.toml
[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
near-sdk = { version = "5.9.0", features = ["legacy"] }
serde_json = "1.0"
schemars = "0.8"

[profile.release]
codegen-units = 1
opt-level = "s"
lto = true
debug = false
panic = "abort"
overflow-checks = true
```

### Toolchain

```toml
# rust-toolchain.toml
[toolchain]
channel = "1.85.0"
```

Build with `cargo near build`.

## OutLayer Contract Interface

Define the external contract interface. Every argument but `source` is
optional:

```rust
use near_sdk::{ext_contract, AccountId};

#[ext_contract(ext_outlayer)]
#[allow(dead_code)]
trait OutLayer {
    fn request_execution(
        &mut self,
        source: near_sdk::serde_json::Value,
        resource_limits: Option<near_sdk::serde_json::Value>,
        input_data: Option<String>,
        secrets_ref: Option<near_sdk::serde_json::Value>,
        response_format: Option<String>,
        payer_account_id: Option<AccountId>,
        params: Option<near_sdk::serde_json::Value>,
    );
}
```

The contract is `outlayer.near` on mainnet and `outlayer.testnet` on testnet.

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `source` | JSON | The code to run: a `Project` or a `WasmUrl` (see [Code Source Formats](#code-source-formats)) |
| `resource_limits` | JSON | `max_instructions`, `max_memory_mb`, `max_execution_seconds`; a missing field takes its default (1 billion, 128, 60). Always pass it (`{}` takes the defaults): a request without it compiles only and runs nothing. Caps: 500 billion instructions, 180 seconds, 4096 MB |
| `input_data` | String | Input for your WASM, delivered on stdin |
| `secrets_ref` | JSON | `{"profile": "...", "account_id": "..."}` — the stored secrets to decrypt for the run |
| `response_format` | String | `"Text"` (default), `"Json"` or `"Bytes"` — how the run's stdout is returned |
| `payer_account_id` | AccountId | Who receives the unused deposit; defaults to the account that called OutLayer, i.e. your contract |
| `params` | JSON | Optional extras, e.g. `attached_usd` (a stablecoin payment to the project's owner, drawn from the calling account's stablecoin balance in the contract) |

## Simple Example: Coin Flip

A minimal proxy that calls OutLayer for a random number. The module prints
`{"random_number": 0}` or `{"random_number": 1}`, so the request asks for
`Json` and the callback deserializes exactly that.

```rust
use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{env, ext_contract, near_bindgen, AccountId, Gas, PanicOnDefault, Promise, PromiseError};

const CALLBACK_GAS: Gas = Gas::from_tgas(5);

#[derive(Serialize, Deserialize, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct RandomResponse {
    pub random_number: u32,
}

#[ext_contract(ext_outlayer)]
#[allow(dead_code)]
trait OutLayer {
    fn request_execution(
        &mut self,
        source: near_sdk::serde_json::Value,
        resource_limits: Option<near_sdk::serde_json::Value>,
        input_data: Option<String>,
        secrets_ref: Option<near_sdk::serde_json::Value>,
        response_format: Option<String>,
        payer_account_id: Option<AccountId>,
        params: Option<near_sdk::serde_json::Value>,
    );
}

#[ext_contract(ext_self)]
#[allow(dead_code)]
trait ExtSelf {
    fn on_flip_result(
        &mut self,
        player: AccountId,
        #[callback_result] result: Result<Option<RandomResponse>, PromiseError>,
    ) -> String;
}

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, PanicOnDefault)]
#[borsh(crate = "near_sdk::borsh")]
pub struct CoinFlip {
    outlayer_contract_id: AccountId,
    wins: u64,
    losses: u64,
}

#[near_bindgen]
impl CoinFlip {
    #[init]
    pub fn new(outlayer_contract_id: AccountId) -> Self {
        Self { outlayer_contract_id, wins: 0, losses: 0 }
    }

    #[payable]
    pub fn flip(&mut self) -> Promise {
        let player = env::predecessor_account_id();

        // The active version of a project
        let source = near_sdk::serde_json::json!({
            "Project": { "project_id": "alice.near/random-wasm", "version_key": null }
        });

        let resource_limits = near_sdk::serde_json::json!({
            "max_instructions": 10_000_000_000u64,
            "max_memory_mb": 128u32,
            "max_execution_seconds": 60u64
        });

        ext_outlayer::ext(self.outlayer_contract_id.clone())
            .with_attached_deposit(env::attached_deposit())
            .with_unused_gas_weight(1) // all gas not reserved below goes to OutLayer
            .request_execution(
                source,
                Some(resource_limits),
                Some(r#"{"min":0,"max":1}"#.to_string()),
                None,                       // no secrets
                Some("Json".to_string()),
                Some(player.clone()),       // the unused deposit goes to the player
                None,
            )
            .then(
                ext_self::ext(env::current_account_id())
                    .with_static_gas(CALLBACK_GAS)
                    .on_flip_result(player),
            )
    }

    #[private]
    pub fn on_flip_result(
        &mut self,
        player: AccountId,
        #[callback_result] result: Result<Option<RandomResponse>, PromiseError>,
    ) -> String {
        match result {
            Ok(Some(r)) if r.random_number == 0 => {
                self.wins += 1;
                format!("{} won", player)
            }
            Ok(Some(_)) => {
                self.losses += 1;
                format!("{} lost", player)
            }
            // The run failed or printed nothing: OutLayer returned null and has
            // already refunded the unused deposit to the player
            Ok(None) => "Execution failed".to_string(),
            // request_execution itself was refused (see Error Handling)
            Err(_) => "Request refused".to_string(),
        }
    }

    pub fn stats(&self) -> (u64, u64) {
        (self.wins, self.losses)
    }
}
```

## Code Source Formats

OutLayer runs a published `.wasm`, named by its sha256; the worker refuses a
file whose bytes do not match the hash. A project version's source is always a
`WasmUrl`.

### Project (normal case)

```rust
let source = near_sdk::serde_json::json!({
    "Project": {
        "project_id": "alice.near/my-app",
        "version_key": null  // null = active version; otherwise the version's wasm hash
    }
});
```

### WasmUrl (direct run of a published file)

```rust
let source = near_sdk::serde_json::json!({
    "WasmUrl": {
        "url": "https://main.fastfs.io/alice.near/outlayer.near/<sha256>.wasm",
        "hash": "<sha256>",
        "build_target": "wasm32-wasip2"
    }
});
```

The URL must be `https://`; `hash` is 64 lowercase hex characters. A direct run
has no project: no project storage, no author secrets and no `Project`-bound
keys.

## Reading the Result

What the callback receives is the run's output as a JSON value, in the
requested `response_format`:

| `response_format` | The callback receives | Deserialize as |
|---|---|---|
| `Json` | the JSON the module printed | `Option<YourType>` |
| `Text` | the output as a JSON string | `Option<String>` |
| `Bytes` | the output as a base64 string | `Option<String>` |
| any, failed run | `null` | `None` |

There is no envelope of OutLayer's around the output. If your module prints
one of its own — `private-dao-example`'s prints `{"success", "result",
"error"}` — the callback deserializes that shape, because it is what the module
printed.

```rust
#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde")]
struct VoteResult {
    yes_votes: u64,
    no_votes: u64,
    passed: bool,
}

#[private]
pub fn on_tally_result(
    &mut self,
    proposal_id: u64,
    #[callback_result] result: Result<Option<VoteResult>, PromiseError>,
) {
    let Ok(Some(vote_result)) = result else {
        env::log_str("Execution failed");
        return;
    };
    if let Some(proposal) = self.proposals.get_mut(&proposal_id) {
        proposal.yes_votes = vote_result.yes_votes;
        proposal.no_votes = vote_result.no_votes;
        proposal.passed = Some(vote_result.passed);
    }
}
```

## Using Secrets

For WASM that needs encrypted secrets (API keys, private keys):

```rust
// The secrets this contract stored under profile "default"
let secrets_ref = near_sdk::serde_json::json!({
    "profile": "default",
    "account_id": env::current_account_id()
});

ext_outlayer::ext(self.outlayer_contract_id.clone())
    .with_attached_deposit(env::attached_deposit())
    .with_unused_gas_weight(1)
    .request_execution(
        source,
        Some(resource_limits),
        Some(input_data),
        Some(secrets_ref),          // <- secrets reference
        Some("Json".to_string()),
        Some(player),
        None,
    )
    .then(/* callback */)
```

A secret's access condition is judged against the transaction's **signer** —
the user who called your contract — unless it names the predecessor
(`Predecessor{…}`), which is your contract. Store the row with a condition
that admits the callers you mean.

The WASM code reads secrets as env vars:

```rust
// In your WASM
let api_key = std::env::var("API_KEY").ok();
```

## Gas Management

`request_execution` reserves the gas of its own settlement callback out of the
gas it is given, and more for a large `input_data` (25 MGas per byte above
32 KB). Reserve a fixed amount for your callback and give OutLayer the rest:

```rust
ext_outlayer::ext(...)
    .with_unused_gas_weight(1)              // OutLayer gets all unreserved gas
    .request_execution(...)
    .then(
        ext_self::ext(env::current_account_id())
            .with_static_gas(Gas::from_tgas(5)) // your callback's fixed share
            .on_result(...)
    )
```

Have users attach 300 TGas to the call into your contract.

## Deposit Requirements

The deposit must cover the compute estimate for the requested limits, plus
storage for an `input_data` over 32 KB. The contract answers the exact figure:

```bash
near view outlayer.testnet estimate_execution_cost \
  '{"resource_limits":{"max_instructions":10000000000,"max_memory_mb":128,"max_execution_seconds":60},"input_len":null}'
```

A request with less is refused. What the run does not use is refunded to
`payer_account_id`.

## Multiple OutLayer Calls

For complex workflows with multiple OutLayer calls, start the second call from
the first one's callback:

```rust
#[payable]
pub fn complex_workflow(&mut self) -> Promise {
    let half_deposit = NearToken::from_yoctonear(env::attached_deposit().as_yoctonear() / 2);

    ext_outlayer::ext(self.outlayer_contract_id.clone())
        .with_attached_deposit(half_deposit)
        .with_static_gas(Gas::from_tgas(50))
        .request_execution(/* step 1 params */)
        .then(
            ext_self::ext(env::current_account_id())
                .with_static_gas(Gas::from_tgas(100))
                .on_first_result()
        )
}

#[private]
pub fn on_first_result(
    &mut self,
    #[callback_result] result: Result<Option<String>, PromiseError>,
) -> Promise {
    // Process first result, then call OutLayer again with the rest of the deposit
    ext_outlayer::ext(self.outlayer_contract_id.clone())
        .with_attached_deposit(self.reserved_for_step_two())
        .with_static_gas(Gas::from_tgas(50))
        .request_execution(/* step 2 params */)
        .then(
            ext_self::ext(env::current_account_id())
                .with_static_gas(Gas::from_tgas(5))
                .on_final_result()
        )
}
```

## Error Handling

### Callback Result Types

| Result | Meaning | The deposit |
|--------|---------|-------------|
| `Ok(Some(output))` | The run succeeded and printed `output` | the unused part is refunded to `payer_account_id` |
| `Ok(None)` | The run failed, timed out or printed nothing | the run is charged what it used (the base fee if it never started); the rest goes to `payer_account_id` |
| `Err(PromiseError)` | `request_execution` panicked: refused at the door (insufficient deposit, a limit above its cap, an invalid source, a paused contract) | NEAR returns the whole attached deposit to **your contract**, the predecessor of the failed call — forward it to the user if it was theirs |

## Build & Deploy

```bash
# Build
cargo near build

# Deploy with the init call
near deploy your-contract.testnet ./target/near/your_contract.wasm \
  --initFunction new --initArgs '{"outlayer_contract_id":"outlayer.testnet"}'
```

## Testing

```bash
# Call your proxy contract
near call your-contract.testnet flip '{}' \
    --accountId alice.testnet \
    --deposit 0.1 \
    --gas 300000000000000
```

## Complete Example Structure

```
my-proxy/
├── Cargo.toml
├── rust-toolchain.toml
├── src/
│   └── lib.rs
└── build.sh
```

### build.sh

```bash
#!/bin/bash
set -e
cargo near build
```

## See Also

- [WASI Tutorial](./WASI_TUTORIAL.md) - Building WASM modules for OutLayer
- [WASM Environment Variables](./WASM_ENV_VARS.md) - Env vars available in WASM
- [random-example](./random-example/) - Coin flip: module and proxy contract
- [private-dao-example](./private-dao-example/) - DAO with encrypted voting
- [test-storage-ark/relay-contract](./test-storage-ark/README.md#relay-contract-relay-contract) - A relay that forwards a refused request's deposit back to its caller

## Examples in This Repository

| Example | Description | Complexity |
|---------|-------------|------------|
| [random-example](./random-example/) | Coin flip with random number | Simple |
| [private-dao-example](./private-dao-example/) | DAO with encrypted voting | Advanced |
