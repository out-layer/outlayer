# NEAR OutLayer — Technical Specification

**Verifiable compute and custody for AI agents, on NEAR — Intel TDX**

## Executive Summary

**NEAR OutLayer** gives an AI agent two things inside one attested Intel TDX enclave: a multi-chain **custody wallet** whose keys are derived and used inside the enclave and whose spending policy its owner sets, and **verifiable compute** — arbitrary untrusted code executed with hardware-enforced guarantees and an enclave-signed attestation of what ran.

Compute reaches customers primarily as **connectors**: named operations with on-chain prices (`send_email`, `pay_invoice`) that run in the same enclave that holds the keys. It is also callable directly by a NEAR smart contract via the yield/resume mechanism, or by any backend over HTTPS.

What OutLayer as operator can and cannot do — including the governance keys it holds at this stage (a full-access key on `dao.outlayer.near`, owner-only measurement approval, contracts upgraded by key) — is in [docs/NON_CUSTODIAL.md](docs/NON_CUSTODIAL.md#governance-at-this-stage).

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
| `contract/` | Main NEAR contract (`outlayer.near`) — execution requests, secrets, projects, payments, wallet policies |
| coordinator (private repo `out-layer/coordinator`) | HTTP API server — task queue (PostgreSQL + Redis), WASM cache, HTTPS API gateway, Agent Custody wallet API |
| `worker/` | Polls tasks, fetches a published WASM and checks its sha256, executes it with wasmtime inside an Intel TDX CVM (self-hosted dstack); its compiler exists but is off by default (see [Code sources and builds](#code-sources-and-builds)) |
| `keystore-worker/` | Key derivation, signing and secrets decryption, running in TEE. Workers call it directly for secrets; the coordinator forwards wallet requests to it |
| `register-contract/` | NEAR contract for TEE worker key registration with TDX quote verification (deployed to `worker.outlayer.near`) |
| `keystore-dao-contract/` | DAO governance contract for keystore registration (`dao.outlayer.near`) |
| `vault-contract/` | Per-customer vault: a customer's own custody root |
| [dashboard](https://github.com/out-layer/dashboard) (separate repo) | Next.js UI — project management, secrets, executions, earnings, wallet policy and approvals, documentation |
| `sdk/outlayer/` | `outlayer` crate for WASM components (storage, env, RPC, VRF; signing keys, encryption keys, tasks behind features) — wasm32-wasip2 only |
| `connectors/` | Connectors: public ones in-tree, pro ones as private submodules |
| `self-hosted-scheduler/` | [Generic scheduler](https://github.com/out-layer/self-hosted-scheduler) for autonomous agents — interval, storage-diff, webhook triggers |
| [outlayer-cli](https://github.com/out-layer/outlayer-cli) | CLI for deploying, running, and managing agents (separate repo) |
| `wasi-examples/` | Example WASI containers |

### Execution Flow (Blockchain)

```
User Contract → request_execution(source, limits, input, secrets_ref)
    ↓
OutLayer Contract → yield (data_id) + emit event
    ↓
Worker Network → poll event, fetch/cache WASM (sha256 checked), execute in TEE
    ↓
Worker (operator key) → resolve_execution(request_id, response) → resume
    ↓
OutLayer Contract → on_execution_response: charge, refund, emit execution_completed
    ↓
User Contract → its own callback receives the output (JSON value, or null on failure)
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

### Code sources and builds

A user names one of two sources: `Project` (the normal case) or `WasmUrl` (a
direct run of a published file). A project version created by the CLI or dashboard is a `WasmUrl`. A
version is a file named by its hash, so what a caller runs and pays for cannot
change under that version afterwards — a repository can change under the same
name and commit history can be rewritten. The worker fetches a `wasm_url` only
over `https://` on the default port (443), to a public address, and refuses a
file whose bytes do not match `hash`.

The contract's enums carry a `GitHub` variant, and the worker has a
compiler (`worker/src/compiler/`, Docker-sandboxed). Builds are off by default:

| Switch | Where | Default | Effect |
|--------|-------|---------|--------|
| `BUILDS_ENABLED` | coordinator | `false` | Off: a `GitHub` task whose wasm is not cached, or that asks for `force_rebuild`, is refused (`worker_roles::BUILD_REFUSED`) |
| `COMPILATION_ENABLED` | worker | `false` | The builder role: builds a GitHub repository and fetches `wasm_url`; builds run only where the coordinator has `BUILDS_ENABLED=true` |
| `DOWNLOAD_ENABLED` | worker | `false` | The downloader role: fetches a `WasmUrl`, checks its sha256 and caches it; no Docker, no build, runs nothing |
| `EXECUTION_ENABLED` | worker | `true` | Runs a cached wasm (TEE workers) |

A worker needs at least one of the three roles. Nothing user-facing (CLI,
dashboard, docs) names a `GitHub` source.

### ExecutionSource

How users specify code to execute. Passed to `request_execution()`.

```rust
pub enum ExecutionSource {
    /// Build from a GitHub repository (builds off by default, see above)
    GitHub {
        repo: String,              // e.g., "https://github.com/user/repo"
        commit: String,            // Git commit hash
        build_target: Option<String>, // e.g., "wasm32-wasip1", "wasm32-wasip2"
    },
    /// Pre-compiled WASM from URL
    WasmUrl {
        url: String,               // https:// on port 443
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

Resolved source sent to workers (no `Project` variant — resolved to `WasmUrl`, or `GitHub` for a build).

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
| `MAX_MEMORY_MB` | 4096 |
| `MAX_COMPILATION_SECONDS` | 300 (5 minutes; builds only) |

### RequestParams

```rust
pub struct RequestParams {
    pub force_rebuild: bool,           // Build parameter: force recompilation even if cached
    pub store_on_fastfs: bool,         // Build parameter: store compiled WASM to FastFS
    pub compile_only: bool,            // Build parameter: compile only, no execution
    pub project_uuid: Option<String>,  // Set by the contract from a Project source; a caller's value is ignored
    pub attached_usd: Option<U128>,    // Payment to project developer (stablecoin micro-units), Project source only
    pub use_bound_identity: bool,      // Agent Connect: run the guest under the caller's bound account name
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

**Compile-only mode**: When `resource_limits` is `None` or `params.compile_only` is `true`, only compilation occurs (no execution); the required deposit is the base fee. It is a build path: with builds off it runs nothing. A caller that wants a run passes `resource_limits`, even as `{}`.

**Large payloads**: Input data >= 10,000 bytes is stored in contract state only (not in the event log); workers fetch it via `get_request()`. Input beyond 32 KB holds a storage deposit of 0.00001 NEAR per byte while the request is pending, returned at settlement — `estimate_execution_cost(resource_limits, input_len)` includes it.

### resolve_execution (operator-only)

Called by a worker after execution completes; resumes the yield with the response. The operator account is `worker.outlayer.near`: each registered worker holds a function-call access key on it, scoped to `resolve_execution`, `submit_execution_output_and_resolve`, `resume_topup` and `resume_delete_payment_key`.

### submit_execution_output / submit_execution_output_and_resolve (operator-only)

Large outputs: the output is stored in contract state first, then the request is resolved with metadata only. `submit_execution_output_and_resolve` does both in one call.

### cancel_stale_execution

The sender can cancel a request still pending after 10 minutes (`EXECUTION_TIMEOUT = 600 * 1_000_000_000` nanoseconds). Refunds the whole `attached_usd` to the sender and the payment above the charge to the payer: the base fee when no output was delivered, the compute estimate for the limits when the output was delivered through the 2-call flow (`output_submitted`) and the callback never settled it. The contract owner's `emergency_cancel_execution(request_id)` cancels any pending request and refunds in full.

---

## Secret Management

### SecretAccessor — What Code Can Access Secrets

```rust
pub enum SecretAccessor {
    Repo { repo: String, branch: Option<String> },   // listed and deleted; the CLI and dashboard refuse new values under it
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
    vault_id: Option<AccountId>,   // null = default master; Some = encrypted under that vault's master
);
```

Requires storage deposit (refunded on deletion). Secrets are encrypted client-side with a public key the keystore derives from its master over a seed naming the accessor and owner (`POST /secrets/pubkey`). Off-chain callers pass `vault_id` explicitly (`null` for the default master). `store_agent_secret` stores a secret owned by a custody wallet (proven by the wallet's keystore signature), paid for by the caller; it takes only `Project` and `WasmHash` accessors.

### AccessCondition — Who Can Trigger Decryption

12 variants with full compositional logic (stored versioned; new variants are appended, never inserted):

```rust
pub enum AccessCondition {
    Logic { operator: LogicOperator, conditions: Vec<AccessCondition> },
    Not { condition: Box<AccessCondition> },
    AllowAll,
    Whitelist { accounts: Vec<AccountId> },
    AccountPattern { pattern: String },                // Regex, e.g., ".*\\.gov\\.near"
    NearBalance { operator: ComparisonOperator, value: NearToken },
    FtBalance { contract: AccountId, operator: ComparisonOperator, value: NearToken },
    NftOwned { contract: AccountId, token_id: Option<String> },
    DaoMember { dao_contract: AccountId, role: String },
    ValidUntil { until_ns: U64 },                      // Admits until this block timestamp
    WasmHash { hash: String },                         // Only a run of this exact build (hash measured by the worker)
    Predecessor { condition: Box<AccessCondition> },   // Judge the inner condition on the calling account, not the signer
}

pub enum ComparisonOperator { Gte, Lte, Gt, Lt, Eq, Ne }
pub enum LogicOperator { And, Or }
```

### Secret Decryption Flow

1. User stores encrypted secrets in contract via `store_secrets()`
2. Execution request includes `secrets_ref: { profile, account_id }`
3. Worker asks the keystore (running in TEE) to decrypt, naming the accessor (project, WASM hash or repo), profile and owner, the caller, and the sha256 it measured on the WASM it is about to run
4. Keystore reads the ciphertext and access condition from the contract
5. Keystore validates the access condition (balance checks, whitelist, `WasmHash` against the measured hash, etc. via NEAR RPC)
6. If authorized, keystore decrypts with a key derived from its master secret (obtained from NEAR MPC via CKD), or the vault's master for a vault-bound secret
7. Decrypted secrets are injected as environment variables into the WASM run

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
**Version key**: the WASM hash of the version's `WasmUrl` (the contract keys a `GitHub` source as `{repo}@{commit}`; nothing user-facing creates one)

### Methods

| Method | Description |
|--------|-------------|
| `create_project(name, source)` | Create project, assigns UUID, stores the first version |
| `add_version(project_name, source, set_active)` | Add version, optionally set as active |
| `set_active_version(project_name, version_key)` | Switch active version |
| `remove_version(project_name, version_key)` | Remove version (cannot remove active) |
| `delete_project(project_name)` | Delete project and all versions |
| `accept_project_transfer(from, name)` | Payable. The future owner agrees to take `from/name`; required before `transfer_project`. Emits `ProjectTransferAccepted` |
| `revoke_project_transfer(from, name)` | Withdraw that acceptance, deposit returned. Emits `ProjectTransferRevoked` |
| `transfer_project(project_name, new_owner)` | Transfer ownership onto `new_owner`'s acceptance (consumed); refused for a priced project. Emits `system_event` `ProjectTransferred` |
| `estimate_transfer_acceptance_cost(new_owner, from, name)` | View: the deposit `accept_project_transfer` charges |
| `get_project_transfer_acceptance(new_owner, from, name)` | View: `Option<U128>`, the deposit held for a pending acceptance |

### View Methods

| Method | Returns |
|--------|---------|
| `get_project(project_id)` | `Option<ProjectView>` |
| `list_user_projects(account_id)` | `Vec<ProjectView>` |
| `get_version(project_id, version_key)` | `Option<VersionView>` |
| `list_versions(project_id, from_index, limit)` | `Vec<VersionView>` (default limit 50, max 100) |
| `get_version_count(project_id)` | `u64` |

---

## Payment Keys & HTTPS API

### Payment Key Format

```
owner:nonce:secret
```

- **owner**: NEAR account ID (e.g., `alice.near`)
- **nonce**: Key number, starts at 1
- **secret**: random secret (the CLI generates 32 random bytes, hex-encoded)

Payment keys are stored as secrets with `accessor: System(PaymentKey)`, `profile: nonce.to_string()`.

### Creating Payment Keys

Payment keys are created via the dashboard, `outlayer keys create`, or directly by calling `store_secrets()` with the `System(PaymentKey)` accessor. The `get_next_payment_key_nonce(account_id)` view method returns the next available nonce. A custody wallet can also create one over HTTPS (`POST /wallet/v1/create-payment-key`); its trial or sponsored key lives at nonce 0, which the contract never issues, and exists only in the coordinator.

### Top-Up Methods

**With stablecoin (ft_transfer_call)**:
```json
{
  "action": "top_up_payment_key",
  "nonce": 1,
  "owner": "alice.near"
}
```

`owner` is optional and defaults to the sender (it is needed when the transfer comes from `intents.near`). Minimum top-up: $0.01 (`MIN_TOP_UP_AMOUNT = 10_000` micro-units).

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
`top_up_payment_key_with_near(nonce, swap_contract_id)` — wraps NEAR → wNEAR → swaps via Intents to stablecoin (mainnet only). The deposit must cover 0.01 NEAR execution cost plus at least 0.01 NEAR to wrap.

`top_up_payment_key_with_token` exists in the contract ABI but is disabled: it panics.

### Deleting Payment Keys

`delete_payment_key(nonce)` — yield/resume flow. Coordinator deletes key data and returns remaining balance.

### HTTPS API

**Endpoint**: `POST https://api.outlayer.ai/call/{project_owner}/{project_name}`

**Headers**:

| Header | Required | Description |
|--------|----------|-------------|
| `X-Payment-Key` | Yes | `owner:nonce:secret` |
| `X-Compute-Limit` | No | Max compute cost in stablecoin micro-units (coordinator default `DEFAULT_COMPUTE_LIMIT`, 10000 = $0.01) |
| `X-Attached-Deposit` | No | Payment to project author in micro-units (refused for a granted key, e.g. a trial) |
| `X-Wallet-Id` | No | The paying key's own wallet, for a connector that acts on it |
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
  "call_id": "uuid",
  "status": "completed",
  "output": "...",
  "compute_cost": "45000",
  "instructions": 123456,
  "time_ms": 42,
  "attestation_url": "/attestations/by-call/{call_id}"
}
```

`attestation_url` is relative to the API base and is omitted for a failed call.

**Async mode**: Set `"async": true` → returns `{ "call_id": "uuid", "status": "pending", "poll_url": "..." }`. Poll with `GET /calls/{call_id}`, authenticated with the same `X-Payment-Key` (or the owning wallet's `Bearer wk_`).

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

`compile_time_ms` is reported only by a build; a run of a published wasm reports none.

View current pricing: `get_pricing()` (NEAR tuple) or `get_pricing_full()` (PricingView with both).

---

## Worker Security — Intel TDX

### TEE Platform

Workers and keystores run inside **Intel TDX** (Trust Domain Extensions) confidential VMs on OutLayer's own TDX hosts, deployed with dstack (`deploy/self-hosted-tdx/`). The TEE provides:

- Hardware-encrypted memory (the host OS cannot read worker memory)
- Hardware-measured code identity (5 measurements)
- Attestation quotes whose signature chains to Intel's root certificate (collateral from Intel PCS, verified with Intel DCAP)

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

All 5 measurements must match an approved set. This prevents dev/debug TDX images (which may have SSH access) from passing verification. Approved sets are added by the register-contract's owner (`add_approved_measurements`); at this stage that is a single OutLayer key.

### Worker Registration Flow

1. Worker generates an ed25519 (or ML-DSA-65) keypair inside the TEE
2. Worker requests a TDX quote with the key bound in `report_data` (the ed25519 public key itself, or the SHA-256 of an ML-DSA-65 key)
3. Worker calls `register_worker_key()` on `worker.outlayer.near` with the quote
4. Contract verifies the quote's Intel signature chain against the stored collateral, extracts all 5 measurements, checks them against the approved list
5. Contract adds the worker's public key as a function-call access key on `worker.outlayer.near`, scoped to `resolve_execution`, `submit_execution_output_and_resolve`, `resume_topup`, `resume_delete_payment_key` on `outlayer.near`

### TEE Session Protocol (Challenge-Response)

After on-chain registration, workers establish sessions with coordinator and keystore:

```
Worker → POST /workers/tee-challenge → Server returns 32-byte challenge
Worker → Sign challenge with TEE private key
Worker → POST /workers/register-tee { public_key, challenge, signature }
Server → Verify challenge freshness + signature + NEAR RPC: key exists on worker.outlayer.near
Server → Issue session id
Worker → Requests include X-TEE-Session: {session_id}
```

Coordinator stores sessions in PostgreSQL. Keystore stores sessions in memory (workers re-register on 403).

### Trust Model

**What the operator cannot do with the TEE** (hardware-enforced):
- Read decrypted secrets or keys from TEE memory
- Modify execution results without breaking the attestation
- Run code other than the attested build under a registered worker key
- Forge attestation reports

**What the operator can do**:
- Refuse to execute (censorship), shut down infrastructure (availability)
- Everything the governance keys allow at this stage: approve measurements alone, upgrade contracts by key, and use the full-access key on `dao.outlayer.near` — see [docs/NON_CUSTODIAL.md](docs/NON_CUSTODIAL.md#governance-at-this-stage)
- As coordinator: withhold or misroute requests, and the residual custody trust listed in [docs/NON_CUSTODIAL.md](docs/NON_CUSTODIAL.md#11-limits-we-state-plainly)

### Verification

- **Docker images**: the worker and keystore images are built by GitHub Actions with Sigstore build-provenance attestations (`gh attestation verify oci://…@<digest>`)
- **On-chain**: `near view worker.outlayer.near get_approved_measurements` shows all approved measurement sets
- **Per execution**: `GET /attestations/by-call/{call_id}` (or `/by-tx/{tx_hash}`, `/by-request/{request_id}`) returns the TDX quote; `GET /public/collateral` serves the Intel collateral to verify it. Walkthrough: https://app.outlayer.ai/docs/trust-verification

---

## SDK — `outlayer` Crate

The `outlayer` crate on crates.io provides high-level APIs for WASM components. **Requires wasm32-wasip2** (WASI Preview 2 / Component Model). See [sdk/outlayer/README.md](sdk/outlayer/README.md).

### Modules

| Module | Description |
|--------|-------------|
| `outlayer::storage` | Persistent encrypted storage across executions |
| `outlayer::env` | Execution context — input, output, signer, predecessor |
| `outlayer::vrf` | Verifiable random function |
| `outlayer::signing_keys` | Feature `signing-keys`: sign with keys the keystore derives (`outlayer:signing-keys@0.1.0`) |
| `outlayer::encryption_keys` | Feature `encryption-keys`: seal data only the component can open (`outlayer:encryption-keys@0.1.0`) |
| `outlayer::tasks` | Feature `tasks`: tasks between an agent and its owner (`outlayer:tasks@0.1.0`) |
| `outlayer::raw` | Low-level WIT bindings (`near:storage/api@0.2.0`, `near:rpc/api@0.1.0`, `near:vrf/api@0.1.0`) |

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

The public HTTPS API is listed in [API.md](API.md); admin routes and their auth model are in [docs/ADMIN.md](docs/ADMIN.md). The routes below serve workers.

### Worker Routes (worker bearer token)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/jobs/claim` · `/jobs/complete` | Claim / complete a job |
| GET | `/executions/poll` | Poll for new tasks |
| GET | `/wasm/:checksum` · `/wasm/exists/:checksum` | Download / check cached WASM |
| POST | `/wasm/upload` | Upload a built WASM (builder role) |
| POST / DELETE | `/locks/acquire` · `/locks/release/:lock_key` | Distributed lock |
| POST | `/workers/heartbeat` | Worker heartbeat |
| POST | `/workers/tee-challenge` · `/workers/register-tee` | TEE session setup |
| POST | `/attestations` | Store attestation |
| GET | `/github/resolve-branch` | Resolve commit to branch (builds only) |
| POST | `/internal/system-logs` | Store raw logs (see below) |

### Worker Routes (worker token + TEE session)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/executions/create` | Create execution task |
| POST | `/workers/task-completion` · GET `/workers/block-cursor` | Task completion notice / event-monitor cursor |
| POST | `/storage/set`, `set-if-absent`, `set-if-equals`, `get`, `get-by-version`, `has`, `delete`, `get-public` | Project storage |
| GET | `/storage/list`, `/storage/usage` | Storage metadata |
| POST | `/storage/clear-all`, `clear-version`, `clear-project` | Storage cleanup |
| GET / DELETE / POST | `/projects/uuid` · `/projects/cache` · `/projects/cache/invalidate` | Resolve project UUID / invalidate cached name → uuid |
| POST | `/topup/create` · `/topup/complete` | Payment key top-up |
| POST | `/payment-keys/init` · `/payment-keys/delete` · `/payment-keys/delete-task/create` | Payment key lifecycle |
| POST | `/projects/cleanup-task/create` | Storage cleanup task for a deleted project |
| GET | `/system-callbacks/poll` | Poll system callback tasks |
| POST | `/https-calls/complete` | Complete HTTPS call |
| POST | `/egress-audit` | Record a run's outbound connections |
| POST | `/owner-tasks/*` | Owner tasks host interface ([docs/TASKS.md](docs/TASKS.md)) |

### Other Routes

| Group | Auth | Routes |
|-------|------|--------|
| Secrets | IP rate limited (10/min) | `/secrets/pubkey`, `/secrets/add_generated_secret`, `/secrets/update_user_secrets` |
| Public | None | `/public/*`, `/attestations/*`, `/vrf/pubkey`, `/health` — see [API.md](API.md) |
| Admin | Admin bearer token | `/admin/*` — see [docs/ADMIN.md](docs/ADMIN.md) |

---

## View Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `get_request(request_id)` | `Option<ExecutionRequest>` | Get pending request |
| `get_stats()` | `(u64, U128)` | Total executions, total fees |
| `get_pricing()` | `(U128, U128, U128, U128)` | NEAR pricing tuple |
| `get_pricing_full()` | `PricingView` | Full NEAR + USD pricing |
| `get_payment_token_contract()` | `Option<AccountId>` | Stablecoin contract |
| `estimate_execution_cost(resource_limits, input_len)` | `U128` | What to attach: the compute estimate plus the deposit held for `input_data` beyond the free 32 KB |
| `get_max_limits()` | `(u64, u64, u64)` | Hard caps: instructions, exec_sec, compile_sec (builds only) |
| `is_paused()` | `bool` | Contract pause status |
| `get_config()` | `(AccountId, AccountId)` | Owner, operator |
| `get_event_metadata()` | `(String, String)` | Event standard + version |
| `get_pending_output(request_id)` | `Option<ExecutionOutput>` | Large output data |
| `has_pending_output(request_id)` | `bool` | Output submitted flag |
| `get_developer_earnings(account_id)` | `U128` | Developer stablecoin balance |
| `get_user_stablecoin_balance(account_id)` | `U128` | User deposit balance |
| `get_pending_request_ids(from_index, limit)` | `Vec<u64>` | Paginated pending IDs |
| `get_next_payment_key_nonce(account_id)` | `u32` | Next available nonce (starts at 1) |
| `get_payment_key_nonce_floor(account_id)` | `u32` | Highest nonce the contract has seen the owner create or delete |
| `get_subscription_plans()` | `Vec<SubscriptionPlan>` | Plans on sale |
| `get_project_pricing(project_id)` · `get_project_max_price(project_id)` | `Option<ProjectPricing>` · `U128` | What a priced (curated) project charges |
| `get_priced_projects(from_index, limit)` · `get_priced_project_count()` | `Vec<String>` · `u64` | Priced projects |

---

## Event Schema

Events are NEP-297 logs (`EVENT_JSON:` prefix) with `standard` and `version` from `get_event_metadata()` (defaults `near-outlayer`, `1.0.0`). `data` is a one-element array.

```json
{
  "standard": "near-outlayer",
  "version": "1.0.0",
  "event": "execution_requested",
  "data": [{
    "request_data": "{\"request_id\":12345,\"sender_id\":\"client.near\",\"predecessor_id\":\"client.near\",\"code_source\":{\"WasmUrl\":{...}},\"resource_limits\":{...},\"input_data\":\"{}\",\"input_data_in_state\":false,\"secrets_ref\":null,\"response_format\":\"Text\",\"payment\":\"...\",\"attached_usd\":\"0\",\"timestamp\":...,\"compile_only\":false,\"force_rebuild\":false,\"store_on_fastfs\":false,\"use_bound_identity\":false,\"project_uuid\":\"p0000000000000001\",\"project_id\":\"alice.near/my-app\"}",
    "data_id": [/* 32 bytes */],
    "timestamp": 1730000000000000000
  }]
}
```

`request_data` is a JSON string; `code_source` is the resolved source. When `input_data_in_state` is true, `input_data` is empty and the worker reads it with `get_request()`.

On settlement the contract emits `execution_completed` with `sender_id`, `code_source`, `resources_used`, `success`, `error_message`, `payment_charged`, `payment_refunded`, `compilation_note`, `timestamp`.

---

## WASM Environment Variables

Variables injected into WASM execution context (system names are stripped from secrets before they are set; full list: `SYSTEM_ENV_VARS` in `worker/src/main.rs`):

| Variable | Blockchain | HTTPS API |
|----------|------------|-----------|
| `OUTLAYER_EXECUTION_TYPE` | `"NEAR"` | `"HTTPS"` |
| `NEAR_NETWORK_ID` | `"mainnet"` / `"testnet"` | `"mainnet"` / `"testnet"` |
| `NEAR_SENDER_ID` | Transaction signer | Payment key owner (or the bound account with `use_bound_identity`) |
| `NEAR_USER_ACCOUNT_ID` | Paying account | Payment key owner |
| `NEAR_PREDECESSOR_ID` | Calling account | `""` |
| `USD_PAYMENT` | `"0"` | X-Attached-Deposit value |
| `ATTACHED_USD` | `attached_usd` | `"0"` |
| `NEAR_PAYMENT_YOCTO` | Attached NEAR | `"0"` |
| `OUTLAYER_CALL_ID` | `""` | call_id UUID |
| `NEAR_REQUEST_ID` | Request id | `""` |
| `NEAR_TRANSACTION_HASH` | Transaction hash | `""` |
| `NEAR_BLOCK_HEIGHT` · `NEAR_BLOCK_TIMESTAMP` | Block number / timestamp | `""` |
| `NEAR_MAX_INSTRUCTIONS` · `NEAR_MAX_MEMORY_MB` · `NEAR_MAX_EXECUTION_SECONDS` | Limits | Limits |
| `OUTLAYER_PROJECT_ID` · `OUTLAYER_PROJECT_OWNER` · `OUTLAYER_PROJECT_NAME` · `OUTLAYER_PROJECT_UUID` | Set for a project | Set for a project |

Plus all decrypted secrets as environment variables (if `secrets_ref` provided).

---

## Production Application: near.email

Blockchain-native email for NEAR accounts. Every NEAR account has an email: `alice.near` → `alice@near.email`. Source: `wasi-examples/near-email` (submodule).

**Architecture**: SMTP server → encrypt with derived public key → store in PostgreSQL → OutLayer TEE decrypts on read

**Key derivation** (BIP32-style): the SMTP server derives per-user public keys from the master public key without knowing the master secret. The master private key is an OutLayer secret, decrypted only inside the TEE worker (subject to the [governance caveats](docs/NON_CUSTODIAL.md#governance-at-this-stage)).

**Security**: Emails encrypted on receipt, stored encrypted, decrypted only inside the TEE for the account's owner.

---

## Agent Custody

Multi-chain custody wallets for AI agents. The agent gets an API key, wallet keys are derived and used in the keystore TEE, the wallet owner controls the policy. User-facing reference: https://app.outlayer.ai/docs/agent-custody. Custody model and its limits: [docs/NON_CUSTODIAL.md](docs/NON_CUSTODIAL.md).

### Architecture

- **Coordinator** (`src/wallet/` in the coordinator repo) — authenticates API keys (stores only SHA-256 hashes of `wk_` keys), forwards to the keystore; keeps usage counters, pending approvals and a readable copy of wallet policies in PostgreSQL. Trusted for custody: cumulative limits are counted here, and for swaps, cross-chain withdrawals, confidential transfers, limit orders and payment checks it supplies the intents message the enclave signs
- **Keystore TEE** (`keystore-worker/src/api.rs` wallet routes) — key derivation (`HMAC-SHA256(master, "wallet:{id}:{chain}")`, master from NEAR MPC), tx signing, policy evaluation against the policy it reads from the chain before signing. All inside Intel TDX
- **Contract** (`contract/src/wallet.rs`) — encrypted policy storage, freeze/unfreeze, on-chain signature verification
- **Worker WASI** (`worker/src/outlayer_wallet/`) — `outlayer:wallet/api@0.1.0` host functions for WASI containers
- **Dashboard** (`app/wallet/` in the dashboard repo) — policy management, approvals, audit log

### Key Files

| File | Description |
|------|-------------|
| coordinator `src/wallet/handlers.rs` | HTTP handlers: register, withdraw, call, approve, policy |
| coordinator `src/wallet/auth.rs` | API key auth (SHA-256 hash lookup), `Bearer near:` auth |
| coordinator `src/wallet/policy.rs` | Negative policy cache, NEAR RPC `has_wallet_policy()`; a wallet with a policy is checked by the keystore every time |
| coordinator `src/wallet/backend/intents.rs` | NEAR Intents integration |
| `keystore-worker/src/api.rs` | Wallet endpoints: `/wallet/derive-address`, `/wallet/derive-ephemeral-key`, `/wallet/sign`, `/wallet/{evm,solana}/sign-*`, `/wallet/{check,decrypt,encrypt,sign}-policy`, `/wallet/sign-secret-{store,delete}` |
| `keystore-worker/src/crypto.rs` | `derive_keypair()` — HMAC-SHA256 from the master secret |
| `contract/src/wallet.rs` | `WalletPolicyEntry`, store/freeze/unfreeze/delete/has/get methods |
| `worker/wit/deps/wallet.wit` | WASI WIT interface |

### API Endpoints

Base: `https://api.outlayer.ai`. Full list: [API.md](API.md#agent-custody-wallet-api).

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/register` | None | Create wallet → API key + NEAR address |
| GET | `/wallet/v1/address?chain=` | Bearer | Derive address for any chain |
| POST | `/wallet/v1/intents/withdraw` | Bearer | Gasless withdraw via Intents (mainnet only). `chain=near`: `token=near`/omitted (default) delivers native NEAR (unwraps wNEAR, no recipient storage), `token=nep141:wrap.near` delivers wNEAR. Other chains delivered native via 1Click |
| POST | `/wallet/v1/intents/withdraw/dry-run` | Bearer | Simulate withdrawal |
| POST | `/wallet/v1/call` | Bearer | Native NEAR contract call |
| GET | `/wallet/v1/requests/{id}` | Bearer | Poll async status |
| GET | `/wallet/v1/policy` | Bearer | View the wallet's policy |
| POST | `/wallet/v1/encrypt-policy` | Bearer | Encrypt policy for on-chain storage |
| POST | `/wallet/v1/approve/{id}` | None — the vote proves the voter | Multisig vote: a NEP-413 signature by an approver's access key, or an authorization a keyless approver's wallet contract resolves |
| POST | `/wallet/v1/reject/{id}` | None — the vote proves the voter | Multisig NO vote, proven the same two ways; a policy approver's reject vetoes |
| GET | `/wallet/v1/audit` | Bearer | Full event history |

### Database Tables

Coordinator migrations (`migrations/20260220000001_wallet.sql` and later):

| Table | Purpose |
|-------|---------|
| `wallet_accounts` | wallet_id → near_pubkey, policy copy, frozen flag |
| `wallet_api_keys` | SHA-256(api_key) → wallet_id |
| `wallet_requests` | Async operations (withdraw, deposit, call) |
| `wallet_pending_approvals` | Multisig state machine |
| `wallet_approval_signatures` | One vote per account per approval: a NEP-413 signature, or a contract wallet's authorization (`proof_kind`) |
| `contract_wallet_code_hashes` | Wallet builds whose contract votes are accepted, and the resolver each runs |
| `wallet_usage` | Per-token per-period spending (hourly/daily/monthly) |
| `wallet_audit_log` | Complete event history |
| `wallet_webhook_deliveries` | Webhook retry queue |

### Policy Engine

The policy is stored encrypted on NEAR (`store_wallet_policy`). The keystore TEE reads it from the chain (one RPC, latest block) and decrypts it before signing; the coordinator also keeps a readable copy in PostgreSQL. Rules: per-tx limits, velocity limits (hourly/daily/monthly), address whitelist/blacklist, time restrictions, rate limits, multisig approval thresholds, emergency freeze. Per-transaction limits, multisig and freeze are enforced in the enclave; cumulative limits are counted by the coordinator and are best-effort under concurrency. Policy format: https://app.outlayer.ai/docs/agent-custody.

---

## System Hidden Logs — Admin Debugging

The coordinator's `system_hidden_logs` table holds **raw stderr/stdout** from compilation and execution containers. It is never exposed through `/public/*` or any user-facing response: code a user submits can print file contents, environment variables or internal paths to stderr (`cat /etc/passwd` in a `build.rs`), so the raw text is admin-only.

- **Reading**: `GET /admin/compile-logs/:job_id` with the admin bearer token ([docs/ADMIN.md](docs/ADMIN.md)), or the table directly
- **Writing**: workers store logs only when `SAVE_SYSTEM_HIDDEN_LOGS_TO_DEBUG=true` (the worker's built-in default; the TDX deployment sets it to `false`)
- Users always get a classified, safe message instead

```sql
CREATE TABLE system_hidden_logs (
    id BIGSERIAL PRIMARY KEY,
    request_id BIGINT NOT NULL,
    job_id BIGINT,
    log_type VARCHAR(50) NOT NULL,  -- 'compilation' or 'execution'
    stderr TEXT,
    stdout TEXT,
    exit_code INTEGER,
    execution_error TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);
```

### Error Classification

The worker classifies errors into safe, user-facing descriptions (the repository, git and build classes come from the compiler, which runs only where builds are enabled):

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

Related files: coordinator `migrations/20251027000001_add_compilation_logs.sql` and `src/handlers/internal.rs`; `worker/src/compiler/docker.rs` (classification); `worker/src/config.rs` (`SAVE_SYSTEM_HIDDEN_LOGS_TO_DEBUG`).
