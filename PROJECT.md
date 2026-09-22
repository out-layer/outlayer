# NEAR OutLayer — Technical Specification

**Verifiable compute and custody for AI agents, on NEAR — Intel TDX**

## Executive Summary

**NEAR OutLayer** gives an AI agent two things inside one attested Intel TDX enclave: a multi-chain **custody wallet** whose keys never leave the enclave and whose spending policy its owner sets, and **verifiable compute** — arbitrary untrusted code executed with hardware-enforced guarantees and an enclave-signed attestation of what ran.

Compute reaches customers primarily as **connectors**: named operations with on-chain prices (`send_email`, `pay_invoice`) that run in the same enclave that holds the keys. It is also callable directly by a NEAR smart contract via the yield/resume mechanism, or by any backend over HTTPS.

Two integration modes:
- **Blockchain (NEAR transactions)**: Smart contract calls `request_execution()` → worker executes in TEE → result resumes on-chain
- **HTTPS API (Payment Keys)**: `POST /call/{owner}/{project}` with prepaid stablecoin balance → worker executes in TEE → JSON response

**Contract**: `outlayer.near` (mainnet) / `outlayer.testnet` (testnet)
**Dashboard**: https://app.outlayer.ai
**API**: https://api.outlayer.ai

---

## Architecture Overview

### Core Components

| Component | Description |
|-----------|-------------|
| `contract/` | Main NEAR contract (`outlayer.near`) — execution requests, secrets, projects, payments |
| `coordinator/` | HTTP API server — task queue (PostgreSQL + Redis), WASM cache, HTTPS API gateway |
| `worker/` | Polls tasks, compiles GitHub repos, executes WASM in TEE (Intel TDX via Phala Cloud) |
| `keystore-worker/` | Secrets decryption service running in TEE, accessed directly by worker (not via coordinator) |
| `register-contract/` | NEAR contract for TEE worker key registration with TDX quote verification (deployed to `worker.outlayer.near`) |
| `keystore-dao-contract/` | DAO governance contract for keystore worker registration |
| `dashboard/` | Next.js UI — project management, secrets, executions, earnings, documentation |
| `sdk/` | `outlayer` crate for WASM components (storage, env, RPC) — wasm32-wasip2 only |
| `self-hosted-scheduler/` | [Generic scheduler](https://github.com/out-layer/self-hosted-scheduler) for autonomous agents — interval, storage-diff, webhook triggers |
| [outlayer-cli](https://github.com/out-layer/outlayer-cli) | CLI for deploying, running, and managing agents (separate repo) |
| `wasi-examples/` | Example WASI containers |

### Execution Flow (Blockchain)

```
User Contract → request_execution(source, limits, input, secrets_ref)
    ↓
OutLayer Contract → yield (data_id) + emit event
    ↓
Worker Network → poll event, compile/cache WASM, execute in TEE
    ↓
Worker → resolve_execution(request_id, response) → resume
    ↓
User Contract → on_execution_response(response) callback
```

### Execution Flow (HTTPS API)

```
Client → POST /call/{owner}/{project} with X-Payment-Key header
    ↓
Coordinator → validate payment key, deduct balance, create task
    ↓
Worker → poll task, execute WASM in TEE
    ↓
Coordinator → return JSON response (or poll via GET /calls/{call_id})
```

---

## Contract Types

### ExecutionSource

How users specify code to execute. Passed to `request_execution()`.

```rust
pub enum ExecutionSource {
    /// Compile from GitHub repository
    GitHub {
        repo: String,              // e.g., "https://github.com/user/repo"
        commit: String,            // Git commit hash
        build_target: Option<String>, // e.g., "wasm32-wasip1", "wasm32-wasip2"
    },
    /// Pre-compiled WASM from URL
    WasmUrl {
        url: String,               // https://, ipfs://, ar://
        hash: String,              // SHA256 hex (64 chars)
        build_target: Option<String>,
    },
    /// Registered project reference
    Project {
        project_id: String,        // "alice.near/my-app"
        version_key: Option<String>, // None = active version
    },
}
```

### CodeSource

Resolved source sent to workers (no `Project` variant — resolved to `GitHub` or `WasmUrl`).

```rust
pub enum CodeSource {
    GitHub { repo: String, commit: String, build_target: Option<String> },
    WasmUrl { url: String, hash: String, build_target: Option<String> },
}
```

### ResourceLimits

```rust
pub struct ResourceLimits {
    pub max_instructions: Option<u64>,        // Default: 1B (1_000_000_000)
    pub max_memory_mb: Option<u32>,           // Default: 128
    pub max_execution_seconds: Option<u64>,   // Default: 60
}
```

**Hard caps** (contract-enforced):

| Limit | Value |
|-------|-------|
| `MAX_INSTRUCTIONS` | 500,000,000,000 (500 billion) |
| `MAX_EXECUTION_SECONDS` | 180 (3 minutes) |
| `MAX_COMPILATION_SECONDS` | 300 (5 minutes) |

### RequestParams

```rust
pub struct RequestParams {
    pub force_rebuild: bool,           // Force recompilation even if cached
    pub store_on_fastfs: bool,         // Store compiled WASM to FastFS
    pub compile_only: bool,            // Compile only, no execution
    pub project_uuid: Option<String>,  // Set automatically for Project source
    pub attached_usd: Option<U128>,    // Payment to project developer (stablecoin micro-units)
}
```

### ExecutionRequest (stored in contract)

```rust
pub struct ExecutionRequest {
    pub request_id: u64,
    pub data_id: CryptoHash,            // For yield/resume
    pub sender_id: AccountId,
    pub execution_source: ExecutionSource,  // Original source
    pub resolved_source: CodeSource,        // Resolved for worker
    pub resource_limits: ResourceLimits,
    pub payment: Balance,                   // NEAR payment
    pub timestamp: u64,
    pub secrets_ref: Option<SecretsReference>,
    pub response_format: ResponseFormat,    // Bytes | Text | Json
    pub input_data: Option<String>,
    pub payer_account_id: AccountId,
    pub attached_usd: u128,                 // Developer payment (stablecoin)
    pub pending_output: Option<StoredOutput>,
    pub output_submitted: bool,
}
```

### ExecutionResponse (from worker)

```rust
pub struct ExecutionResponse {
    pub success: bool,
    pub output: Option<ExecutionOutput>,    // Bytes | Text | Json
    pub error: Option<String>,
    pub resources_used: ResourceMetrics,
    pub compilation_note: Option<String>,
    pub refund_usd: Option<u64>,            // Partial refund via refund_usd() host function
}

pub struct ResourceMetrics {
    pub instructions: u64,
    pub time_ms: u64,
    pub compile_time_ms: Option<u64>,
}
```

---

## Contract Methods

### request_execution

```rust
#[payable]
pub fn request_execution(
    &mut self,
    source: ExecutionSource,
    resource_limits: Option<ResourceLimits>,  // None = compile-only mode
    input_data: Option<String>,
    secrets_ref: Option<SecretsReference>,     // { profile, account_id }
    response_format: Option<ResponseFormat>,   // Bytes | Text | Json (default: Text)
    payer_account_id: Option<AccountId>,       // Refund recipient (default: sender)
    params: Option<RequestParams>,
);
```

**Compile-only mode**: When `resource_limits` is `None` or `params.compile_only` is `true`, only compilation occurs (no execution). Useful for pre-warming cache.

**Large payloads**: Input data >= 10KB is stored in contract state only (not in event log). Workers fetch via `get_request()`.

### resolve_execution (operator-only)

Called by worker after execution completes. Resumes the yield with the response.

### submit_execution_output_and_resolve (operator-only)

Two-call flow for large outputs: first submit output data, then resolve. Used when output exceeds event log limits.

### cancel_stale_execution

Anyone can cancel requests older than 10 minutes (`EXECUTION_TIMEOUT = 600 * 1_000_000_000` nanoseconds). Refunds payment to payer.

---

## Secret Management

### SecretAccessor — What Code Can Access Secrets

```rust
pub enum SecretAccessor {
    Repo { repo: String, branch: Option<String> },   // GitHub repo secrets
    WasmHash { hash: String },                         // WASM hash secrets
    Project { project_id: String },                    // Project secrets (all versions)
    System(SystemSecretType),                           // Payment Keys
}
```

### SecretKey — Composite Storage Key

```rust
pub struct SecretKey {
    pub accessor: SecretAccessor,
    pub profile: String,      // "default", "production", etc.
    pub owner: AccountId,     // Creator account
}
```

### store_secrets

```rust
#[payable]
pub fn store_secrets(
    &mut self,
    accessor: SecretAccessor,
    profile: String,
    encrypted_secrets_base64: String,
    access: AccessCondition,
);
```

Requires storage deposit (refunded on deletion). Secrets encrypted client-side with keystore's public key.

### AccessCondition — Who Can Trigger Decryption

9 variants with full compositional logic:

```rust
pub enum AccessCondition {
    AllowAll,
    Whitelist { accounts: Vec<AccountId> },
    AccountPattern { pattern: String },                // Regex, e.g., ".*\\.gov\\.near"
    NearBalance { operator: ComparisonOperator, value: NearToken },
    FtBalance { contract: AccountId, operator: ComparisonOperator, value: NearToken },
    NftOwned { contract: AccountId, token_id: Option<String> },
    DaoMember { dao_contract: AccountId, role: String },
    Logic { operator: LogicOperator, conditions: Vec<AccessCondition> },
    Not { condition: Box<AccessCondition> },
}

pub enum ComparisonOperator { Gte, Lte, Gt, Lt, Eq, Ne }
pub enum LogicOperator { And, Or }
```

### Secret Decryption Flow

1. User stores encrypted secrets in contract via `store_secrets()`
2. Execution request includes `secrets_ref: { profile, account_id }`
3. Worker fetches encrypted secrets from contract
4. Worker sends to keystore (running in TEE) for decryption
5. Keystore validates access conditions (balance checks, whitelist, etc. via NEAR RPC)
6. If authorized, keystore decrypts using derived keypair (CKD/MPC)
7. Decrypted secrets injected as environment variables to WASM runtime

---

## Project System

Projects provide persistent identity for WASM applications with versioning.

### Data Structures

```rust
pub struct Project {
    pub uuid: String,              // "p{16 hex digits}" (e.g., "p0000000000000001")
    pub owner: AccountId,
    pub name: String,
    pub active_version: String,    // Version key of active version
    pub created_at: u64,
    pub storage_deposit: Balance,
}

pub struct VersionInfo {
    pub source: CodeSource,
    pub added_at: u64,
    pub storage_deposit: Balance,
}
```

**Project ID format**: `{owner}/{name}` (e.g., `alice.near/my-app`)
**Version key**: WASM hash for `WasmUrl`, `{repo}@{commit}` for `GitHub`

### Methods

| Method | Description |
|--------|-------------|
| `create_project(name, source)` | Create project, assigns UUID, compiles first version via yield/resume |
| `add_version(project_name, source, set_active)` | Add version, optionally set as active |
| `set_active_version(project_name, version_key)` | Switch active version |
| `remove_version(project_name, version_key)` | Remove version (cannot remove active) |
| `delete_project(project_name)` | Delete project and all versions |
| `transfer_project(project_name, new_owner)` | Transfer ownership |

### View Methods

| Method | Returns |
|--------|---------|
| `get_project(project_id)` | `Option<ProjectView>` |
| `list_user_projects(account_id, from_index, limit)` | `Vec<ProjectView>` |
| `get_version(project_id, version_key)` | `Option<VersionView>` |
| `list_versions(project_id, from_index, limit)` | `Vec<VersionView>` |
| `get_version_count(project_id)` | `u32` |

---

## Payment Keys & HTTPS API

### Payment Key Format

```
owner:nonce:secret
```

- **owner**: NEAR account ID (e.g., `alice.near`)
- **nonce**: Key number, starts at 1
- **secret**: Base64-encoded secret

Payment keys are stored as secrets with `accessor: System(PaymentKey)`, `profile: nonce.to_string()`.

### Creating Payment Keys

Payment keys are created via the dashboard or by calling `store_secrets()` with `System(PaymentKey)` accessor. The `get_next_payment_key_nonce(account_id)` view method returns the next available nonce.

### Top-Up Methods

**With stablecoin (ft_transfer_call)**:
```json
{
  "action": "top_up_payment_key",
  "nonce": 1,
  "owner": "alice.near"
}
```

Minimum top-up: $0.01 (`MIN_TOP_UP_AMOUNT = 10_000` micro-units).

**Buying a subscription (ft_transfer_call)** — a different action with different
consequences: the money does NOT become the key's balance, so it is never
withdrawable, and no encrypted blob is touched.

```json
{
  "action": "buy_subscription",
  "nonce": 1,
  "owner": "alice.near",
  "plan": 0
}
```

The plan index and its price come from the contract (`get_subscription_plans`).
A payment that names a plan not on sale, or does not cover it, or names a key
that does not exist, fails the transfer — which returns the money.

**With NEAR**:
`top_up_payment_key_with_near(nonce)` — wraps NEAR → wNEAR → swaps via Intents to stablecoin (mainnet only). Minimum: 0.01 NEAR deposit + execution fees.

**With any whitelisted token**:
`top_up_payment_key_with_token(token_contract, amount, nonce)` — swaps via Intents.

### Deleting Payment Keys

`delete_payment_key(nonce)` — yield/resume flow. Coordinator deletes key data and returns remaining balance.

### HTTPS API

**Endpoint**: `POST https://api.outlayer.ai/call/{project_owner}/{project_name}`

**Headers**:

| Header | Required | Description |
|--------|----------|-------------|
| `X-Payment-Key` | Yes | `owner:nonce:secret` |
| `X-Compute-Limit` | No | Max compute cost in stablecoin micro-units (default: 10000 = $0.01) |
| `X-Attached-Deposit` | No | Payment to project author in micro-units |
| `Content-Type` | Yes | `application/json` |

**Request body**:
```json
{
  "input": { ... },
  "secrets_ref": { "profile": "default", "account_id": "alice.near" },
  "resource_limits": { "max_instructions": 10000000000 },
  "async": false
}
```

**Sync response**:
```json
{
  "status": "completed",
  "output": "...",
  "compute_cost": "45000",
  "job_id": 12345,
  "attestation_url": "https://app.outlayer.ai/attestations/12345"
}
```

**Async mode**: Set `"async": true` → returns `{ "call_id": "uuid", "status": "pending", "poll_url": "..." }`. Poll with `GET /calls/{call_id}`.

---

## Developer Earnings

Project developers earn stablecoins when users pay for execution.

### Blockchain Flow

1. User deposits stablecoins: `ft_transfer_call` with `msg: {"action": "deposit_balance"}`
2. User calls `request_execution` with `params: { attached_usd: U128(amount) }`
3. Amount deducted from user's stablecoin balance
4. On successful execution: credited to project owner's `developer_earnings`
5. WASM can call `refund_usd(amount)` to return partial payment
6. Owner withdraws: `withdraw_developer_earnings()` (1 yoctoNEAR deposit required)

### HTTPS Flow

1. User calls API with `X-Attached-Deposit` header
2. Deducted from payment key balance
3. On success: credited to project owner in coordinator DB (`project_owner_earnings`)
4. Tracked in `earnings_history` table

### Pricing

**NEAR pricing** (blockchain transactions):
```
cost = base_fee + (instructions / 1M) × per_million_instructions_fee
     + time_ms × per_ms_fee + compile_time_ms × per_compile_ms_fee
```

**USD pricing** (HTTPS API):
```
cost = base_fee_usd + (instructions / 1M) × per_million_instructions_fee_usd
     + execution_seconds × per_sec_fee_usd + compile_time_ms × per_compile_ms_fee_usd
```

View current pricing: `get_pricing()` (NEAR tuple) or `get_pricing_full()` (PricingView with both).

---

## Worker Security — Intel TDX

### TEE Platform

All workers run inside **Intel TDX** (Trust Domain Extension) confidential VMs on **Phala Cloud**. The TEE provides:

- Hardware-encrypted memory (host OS cannot read worker memory)
- Hardware-measured code identity (5 measurements)
- Cryptographic attestation quotes signed by Intel

### 5-Measurement TDX Verification

The register-contract (deployed to `worker.outlayer.near` — there is no separate `register.outlayer.near` account) verifies all 5 TDX measurements:

```rust
pub struct ApprovedMeasurements {
    pub mrtd: String,   // 96 hex chars — TD measurement (code + config)
    pub rtmr0: String,  // 96 hex chars — Firmware measurement
    pub rtmr1: String,  // 96 hex chars — OS/kernel measurement
    pub rtmr2: String,  // 96 hex chars — Application measurement
    pub rtmr3: String,  // 96 hex chars — Runtime measurement
}
```

All 5 measurements must match an admin-approved set. This prevents dev/debug TDX images (which may have SSH access) from passing verification.

### Worker Registration Flow

1. Worker generates ed25519 keypair inside TEE
2. Worker requests TDX quote from hardware (public key embedded in `report_data`)
3. Worker calls `register_worker_key()` on `worker.outlayer.near` with the quote
4. Contract verifies Intel TDX signature, extracts all 5 measurements, checks against approved list
5. Contract adds worker's public key as a scoped access key (can only call `resolve_execution`, `submit_execution_output_and_resolve`, `resume_topup`, `resume_delete_payment_key`)

### TEE Session Protocol (Challenge-Response)

After on-chain registration, workers establish sessions with coordinator and keystore:

```
Worker → POST /tee-challenge → Server returns 32-byte challenge
Worker → Sign challenge with TEE private key
Worker → POST /register-tee { public_key, challenge, signature }
Server → Verify signature + NEAR RPC view_access_key (key exists on worker.outlayer.near?)
Server → Issue session UUID
Worker → All requests include X-TEE-Session: {session_id}
```

Coordinator stores sessions in PostgreSQL. Keystore stores sessions in memory (workers auto-re-register on 403).

### Trust Model

**What operator CANNOT do** (hardware-enforced):
- Extract decrypted secrets from TEE
- Modify execution results without detection
- Run different code than attested
- Forge attestation reports

**What operator CAN do**:
- Refuse to execute (censorship)
- Shut down infrastructure (availability)

### Verification

- **Phala Trust Center**: View exact image hash and measurements
- **GitHub Releases**: Release binaries with Sigstore certification (cryptographic proof that binary matches source)
- **On-chain**: `near view worker.outlayer.near get_approved_measurements` shows all approved measurement sets

---

## SDK — `outlayer` Crate

The `outlayer` crate on crates.io provides high-level APIs for WASM components. **Requires wasm32-wasip2** (WASI Preview 2 / Component Model).

### Modules

| Module | Description |
|--------|-------------|
| `outlayer::storage` | Persistent encrypted storage across executions |
| `outlayer::env` | Execution context — input, output, signer |
| `outlayer::raw` | Low-level WIT bindings (`near:storage/api@0.1.0`, `near:rpc/api`) |

### Example

```rust
use outlayer::{storage, env};

fn main() {
    let input = env::input();
    storage::set("counter", b"42").unwrap();
    let value = storage::get("counter").unwrap();
    env::output(b"result");
}
```

### Build

```bash
cargo build --target wasm32-wasip2 --release
```

---

## Coordinator API Routes

### Protected Routes (worker auth required)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/jobs/claim` | Worker claims a job |
| POST | `/jobs/complete` | Worker completes a job |
| GET | `/executions/poll` | Poll for new tasks |
| POST | `/executions/create` | Create execution task |
| GET | `/wasm/:checksum` | Download cached WASM |
| POST | `/wasm/upload` | Upload compiled WASM |
| GET | `/wasm/exists/:checksum` | Check WASM cache |
| POST | `/locks/acquire` | Acquire distributed lock |
| DELETE | `/locks/release/:lock_key` | Release lock |
| POST | `/workers/heartbeat` | Worker heartbeat |
| POST | `/workers/task-completion` | Notify task done |
| POST | `/workers/tee-challenge` | TEE challenge request |
| POST | `/workers/register-tee` | TEE session registration |
| POST | `/attestations` | Store attestation |
| GET | `/github/resolve-branch` | Resolve branch to commit |
| POST | `/storage/set`, `set-if-absent`, `set-if-equals` | Worker storage operations |
| POST | `/storage/get`, `get-by-version`, `has`, `delete` | Worker storage queries |
| GET | `/storage/list`, `usage` | Storage metadata |
| POST | `/storage/clear-all`, `clear-version`, `clear-project` | Storage cleanup |
| POST | `/storage/get-public` | Read public storage |
| GET | `/projects/uuid` | Resolve project UUID |
| DELETE | `/projects/cache` | Invalidate project cache |
| POST | `/topup/create` | Create top-up task |
| POST | `/topup/complete` | Complete top-up |
| POST | `/payment-keys/delete-task/create` | Create delete key task |
| POST | `/projects/cleanup-task/create` | Create storage cleanup task |
| GET | `/system-callbacks/poll` | Poll system callback tasks |
| POST | `/https-calls/complete` | Complete HTTPS call |
| POST | `/payment-keys/delete` | Delete payment key data |
| POST | `/payment-keys/init` | Initialize payment key |

### Public Routes (no auth)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/public/workers` | List active workers |
| GET | `/public/jobs` | List recent jobs |
| GET | `/public/stats` | Platform statistics |
| GET | `/public/repos/popular` | Popular repositories |
| GET | `/public/wasm/info` | WASM cache info |
| GET | `/public/wasm/exists/:checksum` | Check WASM exists |
| GET | `/public/pricing` | Current pricing |
| POST | `/public/pricing/refresh` | Refresh pricing from contract |
| GET | `/public/users/:user_account_id/earnings` | User earnings |
| GET | `/public/projects/storage` | Project storage info |
| GET | `/public/payment-keys/:owner/:nonce/balance` | Payment key balance |
| GET | `/public/payment-keys/:owner/:nonce/usage` | Payment key usage history |
| GET | `/public/project-earnings/:project_owner` | Project owner earnings |
| GET | `/public/project-earnings/:project_owner/history` | Earnings history |
| GET | `/health` | Health check |
| GET | `/health/detailed` | Detailed health |
| GET | `/attestations/:job_id` | Get attestation |

### HTTPS API Routes (Payment Key auth, permissive CORS, 100 req/min IP limit)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/call/:project_owner/:project_name` | Execute project |
| GET | `/calls/:call_id` | Poll async result |
| GET | `/payment-keys/balance` | Authenticated balance check |

### Other Routes

| Group | Auth | Routes |
|-------|------|--------|
| Secrets | IP rate limited (10/min) | `/secrets/pubkey`, `/secrets/add_generated_secret`, `/secrets/update_user_secrets` |
| Public Storage | IP rate limited (100/min), permissive CORS | `/public/storage/get`, `/public/storage/batch` |
| Internal | None (worker network only) | `/internal/system-logs` |
| Admin | Admin bearer token | `/admin/compile-logs/:job_id`, `/admin/grant-payment-key`, `/admin/grant-keys`, `/admin/grant-keys/:owner/:nonce`, `/admin/workers/:worker_id` |

---

## View Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `get_request(request_id)` | `Option<ExecutionRequest>` | Get pending request |
| `get_stats()` | `(u64, U128)` | Total executions, total fees |
| `get_pricing()` | `(U128, U128, U128, U128)` | NEAR pricing tuple |
| `get_pricing_full()` | `PricingView` | Full NEAR + USD pricing |
| `get_payment_token_contract()` | `Option<AccountId>` | Stablecoin contract |
| `estimate_execution_cost(resource_limits)` | `U128` | Cost estimate |
| `get_max_limits()` | `(u64, u64, u64)` | Hard caps: instructions, exec_sec, compile_sec |
| `is_paused()` | `bool` | Contract pause status |
| `get_config()` | `(AccountId, AccountId)` | Owner, operator |
| `get_event_metadata()` | `(String, String)` | Event standard + version |
| `get_pending_output(request_id)` | `Option<ExecutionOutput>` | Large output data |
| `has_pending_output(request_id)` | `bool` | Output submitted flag |
| `get_developer_earnings(account_id)` | `U128` | Developer stablecoin balance |
| `get_user_stablecoin_balance(account_id)` | `U128` | User deposit balance |
| `get_pending_request_ids(from_index, limit)` | `Vec<u64>` | Paginated pending IDs |
| `get_next_payment_key_nonce(account_id)` | `u32` | Next available nonce (starts at 1) |

---

## Event Schema

```json
{
  "standard": "near-outlayer",
  "version": "1.0.0",
  "event": "execution_request",
  "data": {
    "request_id": 12345,
    "data_id": "0x...",
    "sender_id": "client.near",
    "execution_source": { "GitHub": { "repo": "...", "commit": "...", "build_target": "wasm32-wasip2" } },
    "resolved_source": { "GitHub": { "repo": "...", "commit": "...", "build_target": "wasm32-wasip2" } },
    "secrets_ref": { "profile": "default", "account_id": "alice.near" },
    "input_data": "{}",
    "resource_limits": { "max_instructions": 1000000000, "max_memory_mb": 128, "max_execution_seconds": 60 },
    "response_format": "Text",
    "payment": "1000000000000000000000000",
    "params": { "project_uuid": "p0000000000000001" }
  }
}
```

---

## WASM Environment Variables

Variables injected into WASM execution context:

| Variable | Blockchain | HTTPS API |
|----------|------------|-----------|
| `OUTLAYER_EXECUTION_TYPE` | `"NEAR"` | `"HTTPS"` |
| `NEAR_NETWORK_ID` | `"mainnet"` / `"testnet"` | `"mainnet"` / `"testnet"` |
| `NEAR_SENDER_ID` | Transaction signer | Payment Key owner |
| `USD_PAYMENT` | `"0"` | X-Attached-Deposit value |
| `NEAR_PAYMENT_YOCTO` | Attached NEAR | `"0"` |
| `OUTLAYER_CALL_ID` | `""` | call_id UUID |
| `NEAR_TRANSACTION_HASH` | Transaction hash | `""` |
| `NEAR_BLOCK_HEIGHT` | Block number | `""` |
| `NEAR_BLOCK_TIMESTAMP` | Block timestamp | `""` |
| `OUTLAYER_PROJECT_ID` | owner/name | owner/name |
| `OUTLAYER_PROJECT_OWNER` | Project owner | Project owner |
| `OUTLAYER_PROJECT_NAME` | Project name | Project name |

Plus all decrypted secrets as environment variables (if `secrets_ref` provided).

---

## Production Application: near.email

Blockchain-native email for NEAR accounts. Every NEAR account has an email: `alice.near` → `alice@near.email`.

**Architecture**: SMTP server → encrypt with derived public key → store in PostgreSQL → OutLayer TEE decrypts on read

**Key derivation** (BIP32-style): SMTP server derives per-user public keys from master public key without knowing the master secret. Master private key lives only inside OutLayer TEE.

**Security**: Emails encrypted on receipt, stored encrypted, decrypted only inside TEE with wallet owner's authorization.

---

## Implementation Status

### Completed

| Component | Status |
|-----------|--------|
| Smart Contract | Production — yield/resume, secrets (4 accessor types, 9 access conditions), projects, pricing (NEAR + USD), developer earnings |
| Coordinator | Production — PostgreSQL + Redis, task queue, WASM cache (LRU eviction), HTTPS API, earnings tracking |
| Worker | Production — wasmi with fuel metering, WASI env vars, Docker sandboxed compilation, TEE attestation (Intel TDX) |
| Keystore | Production — TEE-based decryption, CKD/MPC key derivation, access condition validation, TEE session auth |
| Register Contract | Production — 5-measurement TDX verification, scoped access keys |
| Dashboard | Production — project management, secrets UI, executions view, earnings page, documentation |
| SDK | Published — `outlayer` crate on crates.io, wasm32-wasip2, storage + env + RPC |
| Agent Custody | Production — multi-chain wallets for AI agents, MPC+TEE key derivation, policy engine, multisig, NEAR Intents |
| Scheduler | Production — [self-hosted-scheduler](https://github.com/out-layer/self-hosted-scheduler), config-driven (TOML), interval/storage-diff/webhook triggers, Telegram alerts |

---

## Agent Custody

Multi-chain custody wallets for AI agents. Agent gets an API key, private keys live in TEE, wallet owner controls policy. Full spec: [CUSTODY.md](CUSTODY.md).

### Architecture

- **Coordinator** (`coordinator/src/wallet/`) — stateless proxy. Auth API key, forward to keystore, track usage in PostgreSQL
- **Keystore TEE** (`keystore-worker/src/api.rs` wallet routes) — key derivation (`HMAC-SHA256(MPC_master, "wallet:{id}:{chain}")`), tx signing, policy evaluation. All inside Intel TDX
- **Contract** (`contract/src/wallet.rs`) — encrypted policy storage, freeze/unfreeze, on-chain signature verification
- **Worker WASI** (`worker/src/outlayer_wallet/`) — `outlayer:wallet/api@0.1.0` host functions for WASI containers
- **Dashboard** (`dashboard/app/wallet/`) — policy management, approvals, audit log

### Key Files

| File | Description |
|------|-------------|
| `coordinator/src/wallet/handlers.rs` | HTTP handlers: register, withdraw, call, approve, policy |
| `coordinator/src/wallet/auth.rs` | API key auth (SHA-256 hash lookup) |
| `coordinator/src/wallet/policy.rs` | Negative cache, NEAR RPC `has_wallet_policy()` |
| `coordinator/src/wallet/backend/intents.rs` | NEAR Intents integration |
| `keystore-worker/src/api.rs` | Wallet endpoints: `/wallet/derive-address`, `/wallet/sign`, `/wallet/{evm,solana}/sign-*`, `/wallet/*-policy`, `/wallet/sign-secret-*` |
| `keystore-worker/src/crypto.rs` | `derive_keypair()` — HMAC-SHA256 from MPC master secret |
| `contract/src/wallet.rs` | `WalletPolicyEntry`, store/freeze/unfreeze/has/get methods |
| `worker/wit/deps/wallet.wit` | WASI WIT interface |
| `dashboard/app/wallet/` | 5 pages: handoff, manage, approvals, approval detail, audit |
| `dashboard/app/docs/agent-custody/page.tsx` | User-facing documentation |

### API Endpoints

Base: `https://api.outlayer.ai`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/register` | None | Create wallet → API key + NEAR address |
| GET | `/wallet/v1/address?chain=` | Bearer | Derive address for any chain |
| POST | `/wallet/v1/intents/withdraw` | Bearer | Gasless withdraw via Intents. `chain=near`: `token=near`/omitted (default) delivers native NEAR (unwraps wNEAR, no recipient storage), `token=nep141:wrap.near` delivers wNEAR. Other chains delivered native via 1Click |
| POST | `/wallet/v1/intents/withdraw/dry-run` | Bearer | Simulate withdrawal |
| POST | `/wallet/v1/call` | Bearer | Native NEAR contract call |
| GET | `/wallet/v1/requests/{id}` | Bearer | Poll async status |
| GET | `/wallet/v1/policy` | Bearer | View decrypted policy |
| POST | `/wallet/v1/encrypt-policy` | Bearer | Encrypt policy for on-chain storage |
| POST | `/wallet/v1/approve/{id}` | Bearer | Multisig approval (NEP-413 sig) |
| GET | `/wallet/v1/audit` | Bearer | Full event history |

### Database Tables

`coordinator/migrations/20260220000001_wallet.sql`

| Table | Purpose |
|-------|---------|
| `wallet_accounts` | wallet_id → near_pubkey, policy cache, frozen flag |
| `wallet_api_keys` | SHA-256(api_key) → wallet_id |
| `wallet_requests` | Async operations (withdraw, deposit, call) |
| `wallet_pending_approvals` | Multisig state machine |
| `wallet_approval_signatures` | Individual approver signatures |
| `wallet_usage` | Per-token per-period spending (hourly/daily/monthly) |
| `wallet_audit_log` | Complete event history |
| `wallet_webhook_deliveries` | Webhook retry queue |

### Policy Engine

Encrypted on NEAR blockchain → decrypted only inside TEE. Rules: per-tx limits, velocity limits (hourly/daily/monthly), address whitelist/blacklist, time restrictions, rate limits, multisig approval thresholds, emergency freeze. See [CUSTODY.md](CUSTODY.md) for full policy format.

---

## System Hidden Logs — Admin Debugging Guide

### CRITICAL SECURITY WARNING

The `system_hidden_logs` table contains **RAW stderr/stdout** from compilation and execution containers. This data **MUST NEVER** be exposed via public API endpoints.

#### Security Risk

Malicious users can craft code that outputs system file contents:

```rust
// In build.rs or main.rs
fn main() {
    std::process::Command::new("cat")
        .arg("/etc/passwd")
        .output()
        .unwrap();
}
```

If these logs are exposed publicly, attackers can read server configuration, leak environment variables, discover internal paths, and enumerate packages.

### Access Control

#### Safe Access Methods

1. **SSH/Localhost Only**
   ```bash
   ssh admin@coordinator-server
   curl http://localhost:8080/admin/compile-logs/186
   ```

2. **Direct Database Access**
   ```sql
   psql postgres://postgres:password@localhost/offchainvm
   SELECT * FROM system_hidden_logs WHERE request_id = 186;
   ```

#### NEVER Do This

- Expose `/admin/compile-logs/:request_id` via public URL
- Add log data to `/public/*` endpoints
- Return raw logs in API responses to users
- Include in dashboard frontend

### Configuration

**Disable log storage** (production):
```bash
# worker/.env
SAVE_SYSTEM_HIDDEN_LOGS_TO_DEBUG=false
```

Users still see safe, classified error messages (e.g., "Repository not found", "Rust compilation failed").

**Enable log storage** (development):
```bash
SAVE_SYSTEM_HIDDEN_LOGS_TO_DEBUG=true  # Default
```

### Database Schema

```sql
CREATE TABLE system_hidden_logs (
    id BIGSERIAL PRIMARY KEY,
    request_id BIGINT NOT NULL,
    job_id BIGINT,
    log_type VARCHAR(50) NOT NULL,  -- 'compilation' or 'execution'
    stderr TEXT,                     -- May contain leaked data
    stdout TEXT,                     -- May contain leaked data
    exit_code INTEGER,
    execution_error TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);
```

### Error Classification System

The worker classifies errors into safe, user-facing descriptions:

| Classification | User Message |
|---------------|-------------|
| `repository_not_found` | "Repository not found. Please check that the repository URL is correct..." |
| `repository_access_denied` | "Cannot access repository. The repository may be private..." |
| `invalid_repository_url` | "Invalid repository URL format..." |
| `git_error` | "Git operation failed..." |
| `network_error` | "Network connection error..." |
| `rust_compilation_error` | "Rust compilation failed. Your code contains syntax errors..." |
| `dependency_not_found` | "Dependency resolution failed..." |
| `build_script_error` | "Build script execution failed..." |
| `compilation_error` | Generic fallback |

### Related Files

- `coordinator/migrations/20251027000001_add_compilation_logs.sql`
- `coordinator/src/handlers/internal.rs` — admin endpoints
- `worker/src/compiler/docker.rs` — error extraction and classification
- `worker/src/config.rs` — `SAVE_SYSTEM_HIDDEN_LOGS_TO_DEBUG` flag
