# test-storage-ark

Test WASM for OutLayer persistent storage host functions.

This WASI Preview 2 component demonstrates and tests the `near:storage@0.1.0` host functions provided by the OutLayer worker for encrypted persistent storage.

`relay-contract/` beside it is a testnet NEAR contract that makes a call reach OutLayer through a contract — see [Relay contract](#relay-contract-relay-contract).

## Features

- **Persistent Storage**: Data persists across executions
- **Encrypted**: All data is encrypted before storage using keystore TEE
- **Per-User Isolation**: Each user's data is isolated using different encryption keys
- **Worker-Private Storage**: Special storage only accessible by WASM, not users
- **Public Storage**: Unencrypted storage readable by other projects (e.g., oracle price feeds)
- **Conditional Writes**: Compare-and-swap, set-if-absent, atomic increment/decrement
- **Cross-Project Reads**: Read public data from another project, named by `owner/name` or by its uuid
- **HTTP Verification**: Verify public storage via coordinator HTTP API
- **Version Migration**: Read data from previous WASM versions

## Build

```bash
# Add WASI P2 target
rustup target add wasm32-wasip2

# Build
cargo build --target wasm32-wasip2 --release
```

Output: `target/wasm32-wasip2/release/test-storage-ark.wasm`

## Environment Variables

Set by OutLayer runtime:

| Variable | Example | Description |
|----------|---------|-------------|
| `OUTLAYER_PROJECT_UUID` | `p0000000000000001` | Project UUID for cross-project reads |
| `OUTLAYER_PROJECT_ID` | `owner/name` | Project identifier |
| `OUTLAYER_PROJECT_OWNER` | `alice.near` | Project owner account |
| `OUTLAYER_PROJECT_NAME` | `my-project` | Project name |

## Input Format

```json
{
    "command": "set",
    "key": "my-key",
    "value": "my-value",
    "prefix": "",           // for list command
    "expected": "",         // for set_if_equals
    "delta": 0,             // for increment/decrement
    "project": "",          // for get_public_cross: "owner.near/name" or a uuid like "p0000000000000001"
    "coordinator_url": ""   // for verify_public_http/test_public_storage
}
```

## Commands

### Basic Storage

| Command | Description | Required Fields |
|---------|-------------|-----------------|
| `set` | Store a key-value pair | `key`, `value` |
| `get` | Retrieve value by key | `key` |
| `delete` | Delete a key | `key` |
| `has` | Check if key exists | `key` |
| `list` | List all keys | `prefix` (optional) |
| `set_worker` | Store worker-private data (encrypted) | `key`, `value` |
| `get_worker` | Get worker-private data | `key` |
| `clear_all` | Clear all storage | - |

### Conditional Writes

| Command | Description | Required Fields |
|---------|-------------|-----------------|
| `set_if_absent` | Store only if key doesn't exist | `key`, `value` |
| `set_if_equals` | Compare-and-swap | `key`, `expected`, `value` |
| `increment` | Atomic increment (creates if missing) | `key`, `delta` |
| `decrement` | Atomic decrement (creates if missing) | `key`, `delta` |

### Public Storage (Cross-Project Readable)

| Command | Description | Required Fields |
|---------|-------------|-----------------|
| `set_public` | Store unencrypted data | `key`, `value` |
| `get_public_cross` | Read public data from another project | `key`, `project` (`owner/name` or uuid) |
| `verify_public_http` | Verify public storage via HTTP API | `key`, `coordinator_url` |

### Tests

| Command | Description | Required Fields |
|---------|-------------|-----------------|
| `test_all` | Run all storage tests | - |
| `test_public_storage` | Run public storage tests | `coordinator_url` (optional) |

## Examples

### Store a value

```json
{"command": "set", "key": "counter", "value": "42"}
```

Response:
```json
{"success": true, "command": "set", "value": "Stored 2 bytes at key 'counter'"}
```

### Get a value

```json
{"command": "get", "key": "counter"}
```

Response:
```json
{"success": true, "command": "get", "value": "42", "exists": true}
```

### List keys with prefix

```json
{"command": "list", "prefix": "user:"}
```

Response:
```json
{"success": true, "command": "list", "keys": ["user:alice", "user:bob"]}
```

### Conditional Write: Set if absent

```json
{"command": "set_if_absent", "key": "unique-id", "value": "first-value"}
```

Response:
```json
{"success": true, "command": "set_if_absent", "inserted": true, "value": "Inserted 11 bytes at key 'unique-id'"}
```

### Atomic Counter

```json
{"command": "increment", "key": "visits", "delta": 1}
```

Response:
```json
{"success": true, "command": "increment", "numeric_value": 42, "value": "Key 'visits' incremented by 1, new value: 42"}
```

### Public Storage (Cross-Project)

```json
{"command": "set_public", "key": "oracle:ETH", "value": "{\"price\":\"3500.00\"}"}
```

Response:
```json
{"success": true, "command": "set_public", "value": "Stored 21 bytes as PUBLIC at key 'oracle:ETH'"}
```

Read from another project, by its name or by its uuid:
```json
{"command": "get_public_cross", "key": "oracle:ETH", "project": "oracle.near/price-feed"}
{"command": "get_public_cross", "key": "oracle:ETH", "project": "p0000000000000001"}
```

Verify via HTTP (`project` takes the name or the uuid; `project_uuid` is an alias of it, in either form):
```bash
# JSON format (default) - base64 encoded value
curl "http://localhost:8080/public/storage/get?project=oracle.near/price-feed&key=oracle:ETH"
curl "http://localhost:8080/public/storage/get?project_uuid=p0000000000000001&key=oracle:ETH"
# {"exists":true,"value":"eyJwcmljZSI6IjM1MDAuMDAifQ=="}

# Raw format - returns raw bytes
curl "http://localhost:8080/public/storage/get?project_uuid=p0000000000000001&key=oracle:ETH&format=raw"
# {"price":"3500.00"}
```

### Run all tests

```json
{"command": "test_all"}
```

Response:
```json
{
  "success": true,
  "command": "test_all",
  "value": "28/28 tests passed",
  "tests": {
    "total": 28,
    "passed": 28,
    "failed": 0,
    "results": [...]
  }
}
```

## Storage API (WIT)

The functions of `near:storage@0.1.0` (`worker/wit/deps/storage.wit`) this example calls:

```wit
interface api {
    // Basic operations
    set: func(key: string, value: list<u8>) -> string;
    get: func(key: string) -> tuple<list<u8>, string>;
    has: func(key: string) -> bool;
    delete: func(key: string) -> bool;
    list-keys: func(prefix: string) -> tuple<string, string>;

    // Conditional writes
    set-if-absent: func(key: string, value: list<u8>) -> tuple<bool, string>;
    set-if-equals: func(key: string, expected: list<u8>, new-value: list<u8>) -> tuple<bool, list<u8>, string>;
    increment: func(key: string, delta: s64) -> tuple<s64, string>;
    decrement: func(key: string, delta: s64) -> tuple<s64, string>;

    // Worker storage (with public option for cross-project reads)
    set-worker: func(key: string, value: list<u8>, is-encrypted: option<bool>) -> string;
    // `project`: none = this project; some("owner.near/name") or some("p0000000000000001") = another one's public data
    get-worker: func(key: string, project: option<string>) -> tuple<list<u8>, string>;

    // Version migration
    get-by-version: func(key: string, wasm-hash: string) -> tuple<list<u8>, string>;

    // Cleanup
    clear-all: func() -> string;
    clear-version: func(wasm-hash: string) -> string;
}
```

## Architecture

```
WASM (this module)
    │ WIT host function calls
    ▼
OutLayer Worker (host_functions.rs)
    │ calls StorageClient
    ▼
StorageClient → Keystore (encrypt/decrypt)
    │ encrypted data
    ▼
Coordinator API (/storage/*)
    │
    ▼
PostgreSQL (storage_data table)
```

## Security Notes

- All data is encrypted using keystore TEE before storage
- Encryption key is derived from: `storage:{project_uuid}:{account_id}`
- Worker-private storage uses `@worker` as account_id
- Data is isolated per user - each user can only read/write their own data
- User isolation is automatic at protocol level: `alice.near` cannot access `bob.near`'s data

## Storage Key Structure

Understanding how storage keys work is essential for using OutLayer storage correctly.

### User Storage (isolated per account)

When a user calls `storage::set("balance", "100")`, the actual database key includes the account ID
of the run's storage cell. This example embeds no manifest, so that account is the
signer (the payment key's owner over HTTPS); a module that declares
`storage_account: "predecessor"` uses the calling account's cell instead — see
`wasi-examples/CONNECTOR_MANIFEST.md`, `storage_account`:

```
// alice.near calls execution:
storage::set("balance", "100")
// Database key: project_uuid:alice.near:balance = "100"

// bob.near calls execution:
storage::set("balance", "200")
// Database key: project_uuid:bob.near:balance = "200"

// alice.near reads:
storage::get("balance")  // → "100" (her data)

// bob.near reads:
storage::get("balance")  // → "200" (his data)
```

**Key points:**
- WASM code CANNOT read another user's data
- There is no function like `storage::get_for_account("bob.near", "balance")`
- User data is only accessible when that user triggers the execution

### Worker Storage (shared across all users)

When WASM calls `storage::set_worker("key", value)`, the account is replaced with `@worker`:

```
// Any user calls execution:
storage::set_worker("total_count", "100")
// Database key: project_uuid:@worker:total_count = "100" (encrypted)

// Any other user reads:
storage::get_worker("total_count")  // → "100" (same data)
```

**Key point:** Worker storage is shared, but users cannot directly access it. Only WASM code can call `get_worker`/`set_worker`. Users interact with worker data only through WASM logic (e.g., calling a method that returns aggregated stats).

### Public Storage (cross-project readable)

Public storage is unencrypted worker storage that can be read by other projects. Use case: oracle price feeds, shared configuration.

```rust
// Store public data (is_encrypted = false)
storage::set_worker_with_options("oracle:ETH", price_json.as_bytes(), Some(false))

// Read from current project
storage::get_worker("oracle:ETH")

// Read from another project, by name or by uuid
storage::get_worker_from_project("oracle:ETH", Some("oracle.near/price-feed"))
storage::get_worker_from_project("oracle:ETH", Some("p0000000000000001"))
```

**External HTTP API:**
```bash
# JSON format (default)
curl "http://coordinator/public/storage/get?project=oracle.near/price-feed&key=oracle:ETH"
curl "http://coordinator/public/storage/get?project_uuid=p0000000000000001&key=oracle:ETH"
# {"exists":true,"value":"<base64-encoded-value>"}

# Raw format - returns raw bytes
curl "http://coordinator/public/storage/get?...&format=raw"
```

**Key points:**
- `is_encrypted=false` makes data readable by other projects
- Other projects read it by the project's name (`oracle.near/price-feed`) or its uuid (`p0000000000000001`)
- External clients read via HTTP endpoint (returns base64-encoded value)
- Encrypted (default) worker data is NOT accessible cross-project

### Version Migration

The `wasm_hash` is stored with each record but NOT included in the unique key. This means:
- New WASM versions automatically read data written by old versions
- Use `storage::get_by_version("key", "old_wasm_hash")` to explicitly read old version's data

## Use Cases

1. **User Preferences**: Store user settings that persist across executions
2. **Counters/State**: Maintain state between invocations (use `increment`/`decrement` for thread-safe counters)
3. **Caching**: Cache expensive computation results
4. **Session Data**: Store session-specific data
5. **Worker State**: Private data for WASM logic (not user-accessible)
6. **Oracle Price Feeds**: Public storage for sharing data across projects
7. **Distributed Locks**: Use `set_if_absent` for implementing locks
8. **Optimistic Updates**: Use `set_if_equals` for compare-and-swap operations

## Relay contract (`relay-contract/`)

A **test fixture for testnet**, not a product. It calls OutLayer's
`request_execution` on its caller's behalf, so the run has two accounts: the
receipt's **predecessor** is the relay contract, the transaction's **signer** is
whoever called `relay`. A direct call cannot produce that shape, and it is the
one the platform's predecessor-bound features are about: a signing or
encryption key declared with `caller: "predecessor"`, and a module whose manifest
keeps its storage in the predecessor's cell. The e2e suites use it to watch those
land on the contract rather than the user.

Storage in this example is keyed by the signer, so a call to it relayed through
the contract reads and writes the same records as the signer's direct call.

### Interface

| Method | Kind | What it does |
|---|---|---|
| `new(outlayer: AccountId)` | init | The OutLayer contract every call goes to. Initialises only on a `.testnet` account and only with a `.testnet` OutLayer; init in the deploy transaction. |
| `relay(source, input_data?, resource_limits?, secrets_ref?, response_format?)` | call, payable | Calls `outlayer.request_execution` from the relay with these fields as given (an absent one stays absent), the whole attached deposit, and `payer_account_id` = the caller. Returns the run's answer. Attach 300 Tgas. |
| `outlayer()` | view | The OutLayer contract it relays to. |
| `on_relayed(caller, deposit)` | private | The callback: returns `request_execution`'s bytes unchanged, or — when that call failed — sends the deposit back to the caller. |

`source`, `resource_limits`, `secrets_ref` and `response_format` are OutLayer's
own types (`contract/src/execution.rs`), passed through as JSON; OutLayer
validates them. `params` is not forwarded: its `attached_usd` would draw on the
relay's own stablecoin balance.

**How the answer comes back.** `request_execution` yields until the worker
resolves the run, and its return value is the run's output — the guest's
answer in the requested `response_format`, or `null` for a failed run. The
relay's callback returns those bytes as they are, so the output is the relay
transaction's return value, read exactly as for a direct `request_execution`
(`near` prints it as "Function execution return value"; the RPC `tx` result
carries it in `status.SuccessValue`). The `execution_completed` event is in the
same transaction's logs.

**Money.** The relay keeps nothing of the caller's. OutLayer refunds the unused
deposit straight to the caller (`payer_account_id`). If `request_execution`
itself fails, the deposit comes back to the relay and the callback sends it on,
paid from the relay's free balance (the refund receipt may land a block later),
so keep a couple of NEAR free above storage. If OutLayer's own response callback
failed after accepting a deposit, the relay would pay that caller back from its
own balance: keep the balance small. There is no owner and no admin method.

### Build and deploy (the owner deploys)

```bash
cd wasi-examples/test-storage-ark/relay-contract
./build.sh          # cargo near build → res/outlayer_test_relay.wasm, prints its sha256
```

On testnet, as a subaccount of the suites' `PARENT` (the code is ~140 KB, about
1.4 NEAR of storage; 3 NEAR leaves room for the refund path):

```bash
near account create-account fund-myself relay.<parent>.testnet '3 NEAR' \
  autogenerate-new-keypair save-to-keychain sign-as <parent>.testnet network-config testnet sign-with-keychain send
near contract deploy relay.<parent>.testnet use-file wasi-examples/test-storage-ark/relay-contract/res/outlayer_test_relay.wasm \
  with-init-call new json-args '{"outlayer":"outlayer.testnet"}' prepaid-gas '30.0 Tgas' attached-deposit '0 NEAR' \
  network-config testnet sign-with-keychain send
near contract call-function as-read-only relay.<parent>.testnet outlayer json-args '{}' network-config testnet now
```

A call through it by hand, as any signer:

```bash
near contract call-function as-transaction relay.<parent>.testnet relay json-args \
  '{"source":{"Project":{"project_id":"<owner>.testnet/<name>"}},"input_data":"{\"command\":\"get\",\"key\":\"counter\"}","resource_limits":{"max_instructions":10000000000,"max_memory_mb":128,"max_execution_seconds":60},"response_format":"Json"}' \
  prepaid-gas '300.0 Tgas' attached-deposit '0.1 NEAR' sign-as <you>.testnet network-config testnet sign-with-keychain send
```

### How the suites use it

Export `RELAY_CONTRACT=relay.<parent>.testnet`. Each suite checks first that
`outlayer()` is the suite's `CONTRACT_ID`; a relay that is set but relays
elsewhere stops `--apply`, and an unset `RELAY_CONTRACT` SKIPs the relayed rows
loudly.

- `tests/signing_keys_e2e.sh` S22 — a `caller: "predecessor"` signing key
  (probe build `project-pred`): relayed, the guest sees the relay as
  `NEAR_PREDECESSOR_ID` and the signer as `NEAR_USER_ACCOUNT_ID`, the key is not
  the signer's, and two signers through one relay get one key — the relay's.
- `tests/encryption_keys_e2e.sh` E6 (relayed half) — the same for a predecessor
  encryption key (`encryption-pred`), plus: what one signer seals through the
  relay, another opens through it, and the first cannot open directly.
- `tests/encryption_keys_e2e.sh` SC1, SC2 — the storage cell: relayed,
  `encryption-storage-pred` (`storage_account: "predecessor"`) writes into the
  relay's cell, and `encryption-storage` (no field) into the signer's.
