# WASM Environment Variables

Environment variables available to your WASM code during execution.

> **Note**: For WASI P2 modules, consider using the [OutLayer SDK](./WASI_TUTORIAL.md#outlayer-sdk) instead of raw env vars. The SDK provides type-safe access via `outlayer::env::signer_account_id()` and persistent storage via `outlayer::storage`.

## Safe Access Pattern

**IMPORTANT**: Not all variables are always set. Use safe access patterns:

```rust
// CORRECT - won't panic
let value = std::env::var("VAR_NAME").ok();                    // Option<String>
let value = std::env::var("VAR_NAME").unwrap_or_default();     // String, "" if not set
let value = std::env::var("VAR_NAME").unwrap_or("fallback".to_string());

// WRONG - may panic
let value = std::env::var("VAR_NAME").unwrap();  // panics if not set!
```

## Execution Type

| Variable | Values | Always Set |
|----------|--------|------------|
| `OUTLAYER_EXECUTION_TYPE` | `"NEAR"` or `"HTTPS"` | Yes |
| `NEAR_NETWORK_ID` | `"testnet"` or `"mainnet"` | Yes |

```rust
let is_https = std::env::var("OUTLAYER_EXECUTION_TYPE")
    .map(|v| v == "HTTPS")
    .unwrap_or(false);

let is_mainnet = std::env::var("NEAR_NETWORK_ID")
    .map(|v| v == "mainnet")
    .unwrap_or(false);

// Common pattern: determine account suffix for user-facing strings
let account_suffix = match std::env::var("NEAR_NETWORK_ID").as_deref() {
    Ok("testnet") => ".testnet",
    _ => ".near",
};

// Example: strip suffix for display
let display_name = sender_id.strip_suffix(account_suffix).unwrap_or(&sender_id);
```

## User Identity

| Variable | NEAR Mode | HTTPS Mode |
|----------|-----------|------------|
| `NEAR_SENDER_ID` | Transaction signer account; for a meta-transaction, the account that signed the delegate action | Payment Key owner |
| `NEAR_USER_ACCOUNT_ID` | Same as sender | Same as sender |

Always set in both modes.

**Recommended**: For WASI P2, use the OutLayer SDK instead:

```rust
use outlayer::env;

// Type-safe, returns Option<String>
let signer = env::signer_account_id();
```

See [OutLayer SDK](./WASI_TUTORIAL.md#outlayer-sdk) for details.

## Project Variables

| Variable | Description | When Set |
|----------|-------------|----------|
| `OUTLAYER_PROJECT_ID` | Full project ID: `owner/name` | Only via Project |
| `OUTLAYER_PROJECT_OWNER` | Owner account: `alice.near` | Only via Project |
| `OUTLAYER_PROJECT_NAME` | Project name: `my-app` | Only via Project |
| `OUTLAYER_PROJECT_UUID` | Internal UUID for storage | Only via Project |

**NOT SET** when running directly with GitHub URL or WASM hash (without project).

```rust
// Safe pattern for project vars
fn get_project_info() -> Option<(String, String)> {
    let owner = std::env::var("OUTLAYER_PROJECT_OWNER").ok()?;
    let name = std::env::var("OUTLAYER_PROJECT_NAME").ok()?;
    Some((owner, name))
}

// Check if running via project
let is_project_execution = std::env::var("OUTLAYER_PROJECT_ID").is_ok();
```

**Note**: Project name may contain `/`. For `zavodil.near/my/nested/app`:
- `OUTLAYER_PROJECT_OWNER` = `zavodil.near`
- `OUTLAYER_PROJECT_NAME` = `my/nested/app` (split by first `/` only)

## Payment Variables

| Variable | NEAR Mode | HTTPS Mode |
|----------|-----------|------------|
| `NEAR_PAYMENT_YOCTO` | Attached NEAR (yoctoNEAR) | `"0"` |
| `ATTACHED_USD` | USD from contract (micro-USD) | `"0"` |
| `USD_PAYMENT` | `"0"` | X-Attached-Deposit (micro-USD) |

```rust
// Parse payment (1_000_000 = $1.00)
let usd_payment: u64 = std::env::var("USD_PAYMENT")
    .unwrap_or_default()
    .parse()
    .unwrap_or(0);

let usd_amount = usd_payment as f64 / 1_000_000.0;
```

## Blockchain Context (NEAR Mode Only)

| Variable | Description | HTTPS Mode Value |
|----------|-------------|------------------|
| `NEAR_CONTRACT_ID` | OutLayer contract | `""` |
| `NEAR_BLOCK_HEIGHT` | Block number | `""` |
| `NEAR_BLOCK_TIMESTAMP` | Block timestamp (nanoseconds) | `""` |
| `NEAR_RECEIPT_ID` | Receipt ID | `""` |
| `NEAR_PREDECESSOR_ID` | Predecessor account | `""` |
| `NEAR_SIGNER_PUBLIC_KEY` | Signer's public key; for a meta-transaction, the key that signed the delegate action | `""` |
| `NEAR_RELAYER_ID` | The account that relayed a meta-transaction and paid its gas; `""` for every other call | `""` |
| `NEAR_GAS_BURNT` | Gas used | `""` |
| `NEAR_TRANSACTION_HASH` | Transaction hash | `""` |
| `NEAR_REQUEST_ID` | Internal request ID | `""` |

In HTTPS mode these are set to empty strings `""`, not missing.

```rust
// Safe pattern for blockchain vars
let block_height: Option<u64> = std::env::var("NEAR_BLOCK_HEIGHT")
    .ok()
    .filter(|s| !s.is_empty())
    .and_then(|s| s.parse().ok());
```

## HTTPS-Specific Variables

| Variable | NEAR Mode | HTTPS Mode |
|----------|-----------|------------|
| `OUTLAYER_CALL_ID` | `""` | Call UUID |

```rust
let call_id = std::env::var("OUTLAYER_CALL_ID")
    .ok()
    .filter(|s| !s.is_empty());
```

## Resource Limits

| Variable | Description | Always Set |
|----------|-------------|------------|
| `NEAR_MAX_INSTRUCTIONS` | Max WASM instructions | Yes |
| `NEAR_MAX_MEMORY_MB` | Max memory in MB | Yes |
| `NEAR_MAX_EXECUTION_SECONDS` | Max execution time | Yes |

Always set in both modes.

## User Secrets

Your encrypted secrets are also available as env vars by their names.

```rust
let api_key = std::env::var("MY_API_KEY").ok();
let private_key = std::env::var("NEAR_SENDER_PRIVATE_KEY").ok();
```

## Complete Example

```rust
use std::env;

fn main() {
    // Detect execution mode
    let exec_type = env::var("OUTLAYER_EXECUTION_TYPE").unwrap_or_default();
    let is_https = exec_type == "HTTPS";

    // Get user (always available)
    let sender = env::var("NEAR_SENDER_ID").unwrap_or_default();

    // Get project info (optional)
    let project_owner = env::var("OUTLAYER_PROJECT_OWNER").ok();
    let project_name = env::var("OUTLAYER_PROJECT_NAME").ok();

    // Get payment based on mode
    let payment = if is_https {
        env::var("USD_PAYMENT").unwrap_or_default()
    } else {
        env::var("NEAR_PAYMENT_YOCTO").unwrap_or_default()
    };

    // Get blockchain context (NEAR mode only)
    let tx_hash = env::var("NEAR_TRANSACTION_HASH")
        .ok()
        .filter(|s| !s.is_empty());

    println!("Mode: {}", exec_type);
    println!("Sender: {}", sender);
    if let (Some(owner), Some(name)) = (&project_owner, &project_name) {
        println!("Project: {}/{}", owner, name);
    }
    println!("Payment: {}", payment);
    if let Some(hash) = tx_hash {
        println!("TX: {}", hash);
    }
}
```

## Summary Table

| Variable | NEAR | HTTPS | Project-only |
|----------|------|-------|--------------|
| `OUTLAYER_EXECUTION_TYPE` | `"NEAR"` | `"HTTPS"` | No |
| `NEAR_NETWORK_ID` | `"testnet"` or `"mainnet"` | `"testnet"` or `"mainnet"` | No |
| `NEAR_SENDER_ID` | Yes | Yes | No |
| `NEAR_USER_ACCOUNT_ID` | Yes | Yes | No |
| `OUTLAYER_PROJECT_ID` | If project | If project | **Yes** |
| `OUTLAYER_PROJECT_OWNER` | If project | If project | **Yes** |
| `OUTLAYER_PROJECT_NAME` | If project | If project | **Yes** |
| `OUTLAYER_PROJECT_UUID` | If project | If project | **Yes** |
| `NEAR_PAYMENT_YOCTO` | Value | `"0"` | No |
| `ATTACHED_USD` | Value | `"0"` | No |
| `USD_PAYMENT` | `"0"` | Value | No |
| `OUTLAYER_CALL_ID` | `""` | UUID | No |
| `NEAR_BLOCK_HEIGHT` | Value | `""` | No |
| `NEAR_TRANSACTION_HASH` | Value | `""` | No |
| `NEAR_RELAYER_ID` | Relayer or `""` | `""` | No |
| `NEAR_MAX_INSTRUCTIONS` | Yes | Yes | No |
| `NEAR_MAX_MEMORY_MB` | Yes | Yes | No |
| `NEAR_MAX_EXECUTION_SECONDS` | Yes | Yes | No |
| `WALLET_ID` | If wallet | If wallet | No |
| `NEAR_RPC_PROXY_AVAILABLE` | If proxy | If proxy | No |

Every name in this table is **reserved**: `store_secrets` refuses it as a secret
key, and the worker strips it from your secrets before writing its own value. So
what you read here always came from the worker — never from whoever called you.

`WALLET_ID` is informational. The authoritative answer is the `wallet::get_id`
host function, which cannot be influenced by the environment at all.

## See Also

- [WASI Tutorial](./WASI_TUTORIAL.md) - Complete guide to WASI development
- [OutLayer SDK](./WASI_TUTORIAL.md#outlayer-sdk) - Type-safe access to env vars and storage
- [Best Practices](./BEST_PRACTICES_OUTLAYER_NEAR.md) - Frontend integration patterns
