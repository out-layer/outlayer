# OffchainVM Worker

Worker implementation for executing off-chain computations triggered by NEAR smart contracts.

## Features

- **Task Polling**: Long-polling from Coordinator API for new tasks
- **WASM Download**: Fetches a published `WasmUrl` (`https://` on port 443), checks its sha256 and caches it
- **Compiler (off by default)**: Clones and compiles GitHub repositories to WASM (Docker-sandboxed); runs only on a builder worker where the coordinator enables builds
- **WASM Execution**: Executes WASM with resource limits using wasmi
- **NEAR Integration**: Submits execution results back to blockchain via `resolve_execution`
- **Event Monitoring** (optional): Monitors NEAR blockchain for `execution_requested` events
- **Distributed Locking**: Prevents duplicate compilation across multiple workers

## Roles

What a worker does is set by three switches (`src/config.rs`); at least one must be on.

| Variable | Default | Role |
|----------|---------|------|
| `EXECUTION_ENABLED` | `true` | Runs a cached wasm (TEE workers) |
| `DOWNLOAD_ENABLED` | `false` | Downloader: fetches a `WasmUrl`, checks its sha256 and caches it; no Docker, no build, runs nothing |
| `COMPILATION_ENABLED` | `false` | Builder: builds a GitHub repository and fetches a `WasmUrl`; builds run only where the coordinator has `BUILDS_ENABLED=true` (default `false`) |

A fourth switch picks the engine that runs the wasm:

| Variable | Default | Engine |
|----------|---------|--------|
| `EXECUTION_ENGINE` | `outlayer` | `outlayer`: this worker's own wasmtime runtime with every host interface under `wit/`. `defuse-worker`: the Defuse Outlayer worker running beside this one in the same CVM (`docker/docker-compose.phala.yml`, service `outlayer-core`, compose profile `defuse-worker`); jobs go to its gRPC `Call` with the wasm inline |
| `DEFUSE_WORKER_URL` | `http://127.0.0.1:50051` | The sidecar's gRPC endpoint, inside the CVM |

On the `defuse-worker` engine the worker takes only the execute queue of the
projects the coordinator lists in `DEFUSE_WORKER_PROJECTS` (it states the
`defuse-worker` capability when it polls), and refuses to start with
`COMPILATION_ENABLED` or `DOWNLOAD_ENABLED`. The sidecar's rules apply to the
guest: an empty environment, no OutLayer host interfaces, `https` to port 443 of
public names only, no monotonic clock. A component built with the SDK's
`defuse-engine` feature carries the `outlayer.engine` section and receives what
the environment would have held as a stdin envelope `{"meta": …, "input": …}`,
with a one-time call token its storage calls present to the coordinator and the
keystore (`/app-calls/*`); any other component receives the caller's input as it
is, and a project with secrets is refused on this engine unless its build carries
the section. Connectors (an enforced outbound allowlist) and components importing
`outlayer:crypto` are refused on this engine. At startup `API_BASE_URL` and every
`KEYSTORE_BASE_URLS` entry are checked against the sidecar's egress policy
(`https`, port 443, a public multi-label name).

Builds are off by default on both sides. The code sources a user can name are
`Project` and `WasmUrl`, and a project version's source is a `WasmUrl`: a
published `.wasm` named by its sha256, which the worker refuses when the bytes
do not match. With builds off the coordinator refuses a `GitHub` task whose
wasm is not cached. A downloader configuration is in `.env.example` (ROLES).

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Worker Process                         │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐    ┌────────────────┐    ┌─────────────┐ │
│  │Event Monitor │───▶│ Coordinator API│◀───│ Main Loop   │ │
│  │(optional)    │    │   Client       │    │(long-poll)  │ │
│  └──────────────┘    └────────────────┘    └─────────────┘ │
│         │                    │                      │        │
│         │                    ▼                      ▼        │
│         │            ┌──────────────┐      ┌──────────────┐ │
│         │            │  Compiler    │      │  Executor    │ │
│         │            │  (Docker)    │      │  (wasmi)     │ │
│         │            └──────────────┘      └──────────────┘ │
│         │                                          │         │
│         └──────────────────────────────────────────┼────────┐│
│                                                     ▼        ││
│                                            ┌──────────────┐ ││
│                                            │ NEAR Client  │ ││
│                                            │(resolve tx)  │ ││
│                                            └──────────────┘ ││
└─────────────────────────────────────────────────────────────┘│
                                                      │         │
                                                      ▼         │
                                            ┌──────────────────┐│
                                            │  NEAR Blockchain ││
                                            │  (testnet/main)  ││
                                            └──────────────────┘│
                                                                 │
                                                                 ▼
```

## Components

### 1. Config (`src/config.rs`)
Loads configuration from environment variables:
- Coordinator API credentials
- NEAR RPC endpoint and operator keys
- Worker roles (`EXECUTION_ENABLED`, `DOWNLOAD_ENABLED`, `COMPILATION_ENABLED`)
- Docker compilation settings (builder role)
- Default resource limits

### 2. API Client (`src/api_client.rs`)
HTTP client for Coordinator API:
- `poll_task()` - Long-poll for new tasks (download, compile or execute; the queues follow the worker's roles)
- `complete_task()` / `fail_task()` - Report task status
- `upload_wasm()` / `download_wasm()` - WASM cache management
- `acquire_lock()` / `release_lock()` - Distributed locking for compilation

### 3. Compiler (`src/compiler.rs`)
Downloads a `WasmUrl` (`https://` on port 443, public address only, 10 MB cap),
checks its sha256 and uploads it to the coordinator's cache. On a builder
worker with builds enabled (both off by default, see [Roles](#roles)) it also
compiles GitHub repositories to WASM using Docker:
- Checks WASM cache before compiling
- Acquires distributed lock to prevent duplicate work
- **Runs real Docker-based compilation** from public GitHub repositories
- Supports `wasm32-wasi` and `wasm32-wasip1` targets (extensible to more targets)
- Extracts compiled WASM via tar streaming
- Uploads compiled WASM to coordinator

**Supported Build Targets:**
- ✅ `wasm32-wasi` (primary target)
- ✅ `wasm32-wasip1` (normalized to wasm32-wasi)
- 🔜 `wasm32-unknown-unknown` (planned)
- 🔜 `wasm32-wasip2` (planned)

### 4. Executor (`src/executor.rs`)
Executes WASM with resource metering:
- Uses wasmi engine with fuel metering (instruction counting)
- Enforces memory and time limits
- Provides minimal WASI interface
- Returns execution results with timing metrics

### 5. NEAR Client (`src/near_client.rs`)
Interacts with NEAR blockchain:
- Calls `resolve_execution(data_id, response)` on OffchainVM contract
- Handles transaction signing and submission
- Waits for finalization

### 6. Event Monitor (`src/event_monitor.rs`) (Optional)
Monitors blockchain for events:
- Reads every block from neardata, in order, from the coordinator's saved cursor
- Parses `EVENT_JSON` logs of committed receipts of the contract
- Relays them to the Coordinator API (tasks, top-ups, wallet policies, …)

A block neardata will not serve within 15 s is **deferred**: the head moves
on, and the block is read again on its own backoff (2 → 30 s, for up to 3000
blocks) and delivered **out of order**. When the blocks after it do not read
either, neardata is down rather than the block, and the head waits — up to
5 minutes, then it looks further ahead for a block that reads and defers the
range before it — so the blocks keep their order. An event that could not be
relayed for a reason that may pass is kept with its block and delivered again;
an event relayed once is never delivered again. The queue is logged every 100
blocks; a restart starts from the head and does not read it.

A block can also be **late** — more than 100 blocks behind the chain tip,
after a slow head or a restart's catch-up — against the contract's 200-block
yield window. What each event may do late or out of order is decided in
`relay_decision`:

| event | late | out of order |
|---|---|---|
| `execution_requested` | run only if still pending at the final block | same |
| top-up (amount > 0) | relayed; the chain refuses a late resume and nothing is credited | relayed |
| payment key creation (amount 0) | relayed | relayed only if the key still exists at the final block |
| `delete_payment_key` | not relayed: the contract keeps the key, the owner deletes again (an unknown tip: tried again) | same rule |
| wallet policy / freeze | relayed | the wallet's state at the final block is relayed, not the event's |
| subscription purchase, project cleanup, project transfer | relayed | relayed |

A block within 10 blocks after an unread one that holds a call which may be a
meta-transaction waits for it, so the call is not judged by the wrong door.

### 7. Main Loop (`src/main.rs`)
Orchestrates all components:
1. Poll for task from Coordinator API
2. If preparation task: download the `WasmUrl` and check its sha256 (or, on a builder with builds enabled, compile), then upload the WASM to the cache
3. If execute task: download WASM, execute, submit result to NEAR
4. Repeat

### Stopping
SIGTERM or SIGINT (Ctrl-C) is a soft stop: the main loop and the system-callbacks loop poll
for nothing more, the task in hand runs to its end, and the worker exits 0. A poll already in
flight is not cancelled — the task it returns is finished too. In a dstack CVM the signal comes
from a non-forced `vmm stop` (`worker-ctl.sh stop`); the compose gives the worker 85 s before
the guest kills it.

## Setup

### Prerequisites

- Rust 1.75+ with `wasm32-unknown-unknown` target
- Docker (builder role only: the compilation sandbox)
- NEAR account with operator role on OffchainVM contract
- Access to Coordinator API

### Installation

```bash
# Clone repository
cd worker

# Build worker
cargo build --release

# Create .env file (see Configuration below)
cp .env.example .env
nano .env

# Run worker
cargo run --release
```

## Configuration

Create a `.env` file with the following variables:

### Required

```bash
# Coordinator API
API_BASE_URL=http://localhost:8080
API_AUTH_TOKEN=your_secret_token_here

# NEAR Configuration
NEAR_RPC_URL=https://rpc.testnet.near.org
OFFCHAINVM_CONTRACT_ID=outlayer.testnet
OPERATOR_ACCOUNT_ID=worker1.testnet
OPERATOR_PRIVATE_KEY=ed25519:YOUR_PRIVATE_KEY_HERE
```

### Optional (with defaults)

```bash
# Worker Settings
WORKER_ID=worker-1                    # default: random UUID
ENABLE_EVENT_MONITOR=false            # default: false
POLL_TIMEOUT_SECONDS=60               # default: 60

# Roles (see Roles above)
EXECUTION_ENABLED=true                # default: true
DOWNLOAD_ENABLED=false                # default: false
COMPILATION_ENABLED=false             # default: false — builds also need BUILDS_ENABLED=true on the coordinator
EXECUTION_ENGINE=outlayer             # default: outlayer; defuse-worker = the sidecar (see Roles)
DEFUSE_WORKER_URL=http://127.0.0.1:50051  # default; the compose uses http://outlayer-core:50051

# Docker Compilation (builder role only)
DOCKER_IMAGE=rust:1.75                # default: rust:1.75
COMPILE_TIMEOUT_SECONDS=300           # default: 300 (5 minutes)
COMPILE_MEMORY_LIMIT_MB=2048          # default: 2048
COMPILE_CPU_LIMIT=2.0                 # default: 2.0

# WASM Execution Defaults
DEFAULT_MAX_INSTRUCTIONS=10000000000  # default: 10 billion
DEFAULT_MAX_MEMORY_MB=128             # default: 128 MB
DEFAULT_MAX_EXECUTION_SECONDS=60      # default: 60 seconds

# WASM Run Bounds
WASM_MEMORY_FLOOR_MB=1024             # default: 1024 — the least linear memory a run is given, whatever max_memory_mb it asked; a growth past the bound is refused (memory.grow answers -1)
WASM_MEMORY_CEILING_MB=4096           # default: 4096 — the most (wasm32's own bound)
MAX_OUTPUT_BYTES=10485760             # default: 10 MiB — the stdout capacity; a write past it fails
```

## Usage

### Running the Worker

```bash
# Development mode (with logs)
RUST_LOG=offchainvm_worker=debug cargo run

# Production mode
cargo run --release
```

### Environment Variables for Logging

```bash
# Info level (default)
RUST_LOG=offchainvm_worker=info cargo run

# Debug level (verbose)
RUST_LOG=offchainvm_worker=debug cargo run

# Trace level (very verbose)
RUST_LOG=offchainvm_worker=trace cargo run
```

## Task Flow

### Download Task

1. Receive the task for a `WasmUrl` source (downloader or builder role)
2. Check if WASM with that sha256 exists in cache → return if yes
3. Fetch the URL (`https://`, port 443, public address, 10 MB cap)
4. Refuse the file if its sha256 does not match `hash`
5. Upload to coordinator with the checksum
6. Complete task

### Compile Task (builder role, builds enabled only)

1. Receive `Task::Compile` from coordinator
2. Compute checksum for (repo, commit, build_target)
3. Check if WASM exists in cache → return if yes
4. Acquire distributed lock for this compilation
5. **Clone GitHub repository in Docker container**
6. **Run `cargo build --target wasm32-wasi` in Docker sandbox**
7. **Extract WASM binary via tar streaming**
8. Upload to coordinator with checksum
9. Release lock
10. Complete task

### Execute Task

1. Receive `Task::Execute` from coordinator
2. Download WASM binary from cache using checksum
3. Fetch input data using data_id (TODO: implement proper data fetching)
4. Execute WASM with resource limits:
   - Fuel metering for instruction counting
   - Memory limit enforcement
   - Timeout enforcement
5. Collect execution metrics
6. Submit result to NEAR via `resolve_execution(data_id, response)`
7. Complete task in coordinator

## WASM Interface

Compiled WASM modules must export:

```rust
#[no_mangle]
pub extern "C" fn execute(input_ptr: i32, input_len: i32) -> i32 {
    // Read input data from memory
    // Perform computation
    // Write output to memory as: [4-byte length][output data]
    // Return pointer to output (or negative for error)
}
```

Memory layout:
- Input: written at offset 0 by executor
- Output: 4-byte little-endian length followed by data

### Host functions

WASI P2 components import host interfaces from `wit/` (`near:rpc`,
`near:storage`, `near:payment`, `near:vrf`, `outlayer:wallet`,
`outlayer:signing-keys`). The wallet
interface is provided only when the execution carries a wallet (`X-Wallet-Id`);
a component that imports it without one is refused before `main`. Its EVM
signing functions take a sub-key `label`; the worker maps it to the keystore
path `connector.{connector_id}.{label}` only for a connector in the connectors
namespace whose verified in-wasm manifest names `connector_id` equal to its
project name (`connector_manifest::sub_key_connector_id`), so a guest can only
name its own connector's keys. The empty label is the sub-key `default`; the
wallet's own EVM key is not reachable from a guest at all. Each execution has
a budget of 200 wallet host calls.

`outlayer:signing-keys` serves the ed25519 and secp256k1 keys a component
declares in its manifest (`signing_keys`, at most 3), by `path` and declared
`vault` (`src/signing_keys/`): `public-key`, `sign` (ed25519 over the raw
message; secp256k1 over a 32-byte prehash, 65 bytes `r ‖ s ‖ v`, low-s,
`v ∈ {0,1}`) and `sign-nep413` (ed25519 only; the host builds the NEP-413
bytes). How the run was started is read off the job — its
`project_id`, the variant of its resolved `code_source` and its predecessor —
and the run's one `/decrypt` request carries the `project_id` (present for a
run through a project, absent for a direct run of a wasm URL), the declared
keys (`path`, `type`, `bind`, `caller`, `vault`), the caller, the predecessor
and the measured build, beside its secret row. The keystore checks what the
chain can answer (the project's version, owner and uuid, the vault's
ownership) and takes the rest on this worker's attestation; the one rule only
this worker can apply — no key for code built from GitHub, which reaches the
keystore as nothing but a hash — is applied here. A declaration whose `bind`
does not match how the code is run, a `caller: "predecessor"` key on a run
with no predecessor, or any key on code built from GitHub, refuses the run
before any secret is decrypted; the executor refuses a component that declares
keys and was handed none. The seeds stay in that run's memory and are dropped
with it.

### Routes this node will not run

`EXECUTE_EXCLUDES` is a comma-separated list of `<project_id>:<operation>` (or
`<project_id>:*`) that this worker refuses. The operator sets it, because only
the operator knows what the node cannot reach: a venue that geofences the
country the node sits in, a host its network blocks. The worker sends the list
on every poll; the coordinator then skips those tasks for this worker and
leaves them in the queue, in order, for one that will take them. A task nobody
will take waits until the caller's own timeout, exactly as it would if every
worker were busy.

```
EXECUTE_EXCLUDES=connectors.outlayer.near/polymarket:order
```

`scripts/deploy_tdx.sh` fills this in from a per-node table (`node_excludes`,
keyed by the host in `--node`) and prints what it set, so a deploy carries the
node's geography with it. The table answers one of three things, and they differ:
a rule list is written; `none` means the node is KNOWN to refuse nothing, so any
stale value on it is CLEARED; an empty answer means the node is not in the table
at all and whatever the operator set by hand is left exactly as it is.
`--execute-excludes "<rules>"` overrides the table, and `--execute-excludes ""`
forces none. The value travels to the node as base64, so a rule is never
interpolated into a shell word or a `sed` replacement.

Compile jobs are never excluded: compiling reaches no venue. An empty list is
the ordinary path and leaves the coordinator's blocking pop untouched.

Guests have no raw sockets: both WASI contexts deny TCP, UDP and name lookup
(`src/executor/wasi_p1.rs`, `wasi_p2.rs`); the only network path is
`wasi:http`, which runs through the outbound allowlist and the egress audit.

## Security

### Sandboxing

- **Docker Isolation**: Compilation runs in isolated Docker containers
- **Resource Limits**: CPU, memory, and timeout constraints
- **WASM Sandbox**: Execution in wasmi with no access to host system
- **Fuel Metering**: Instruction-level resource tracking

### Authentication

- **API Token**: Bearer token authentication for Coordinator API
- **NEAR Keys**: Ed25519 private key for operator transactions
- **Distributed Locks**: Prevent race conditions in multi-worker setup

## Testing

### Unit Tests

```bash
# Run all unit tests
cargo test

# Run specific test
cargo test test_validate_build_target
```

### Integration Tests

**Test real GitHub compilation** (requires Docker):

```bash
# Using test script
./scripts/test_github_compilation.sh

# Or manually
cargo test test_real_github_compilation -- --ignored --nocapture
```

This test:
- Compiles https://github.com/out-layer/random-example @ `6491b31`
- Validates WASM magic number
- Compares with pre-compiled version if available
- Shows compilation metrics (size, checksum)

### Manual Testing

```bash
# Run with test configuration
API_BASE_URL=http://localhost:8080 \
API_AUTH_TOKEN=test-token \
NEAR_RPC_URL=https://rpc.testnet.near.org \
OFFCHAINVM_CONTRACT_ID=outlayer.testnet \
OPERATOR_ACCOUNT_ID=test.testnet \
OPERATOR_PRIVATE_KEY=ed25519:... \
cargo run
```

## Development

### Adding New Features

1. **Config** - Add environment variable to `config.rs`
2. **API Client** - Add new endpoint methods to `api_client.rs`
3. **Compilation** - Extend `compiler.rs` with Docker integration
4. **Execution** - Extend `executor.rs` with new WASI functions
5. **NEAR** - Add contract methods to `near_client.rs`

### TODO

- [x] ~~Implement Docker-based GitHub compilation~~ ✅ **DONE**
- [x] ~~Support wasm32-wasi build target~~ ✅ **DONE**
- [ ] Add support for more build targets (wasm32-unknown-unknown, wasm32-wasip2)
- [ ] Implement proper input data fetching via data_id
- [ ] Add metrics collection and reporting
- [ ] Implement health checks and worker registration
- [ ] Add graceful shutdown handling
- [ ] Implement WASM caching on worker disk
- [ ] Add support for multiple WASM runtimes (wasmtime, wasmer)
- [ ] Implement full WASI support for more complex programs
- [ ] Optimize Docker image caching for faster compilations

## Troubleshooting

### Worker can't connect to Coordinator API

- Check `API_BASE_URL` is correct
- Verify coordinator is running: `curl http://localhost:8080/health`
- Check `API_AUTH_TOKEN` matches coordinator configuration

### NEAR transaction failures

- Verify `OPERATOR_ACCOUNT_ID` has operator role on contract
- Check `OPERATOR_PRIVATE_KEY` is valid and has sufficient balance
- Ensure contract ID is correct for your network (testnet/mainnet)
- Check RPC endpoint is responsive

### Compilation errors (builder role)

- Verify Docker is running: `docker ps`
- Check Docker image is available: `docker pull rust:1.75`
- Ensure sufficient disk space for compilation
- Check GitHub repository is accessible

### Execution timeouts

- Increase `DEFAULT_MAX_EXECUTION_SECONDS` for longer computations
- Check WASM binary is optimized (release build)
- Verify resource limits are not too restrictive

## Production Deployment

### Systemd Service

Create `/etc/systemd/system/offchainvm-worker.service`:

```ini
[Unit]
Description=OffchainVM Worker
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
User=offchainvm
WorkingDirectory=/opt/offchainvm-worker
EnvironmentFile=/opt/offchainvm-worker/.env
ExecStart=/opt/offchainvm-worker/target/release/offchainvm-worker
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl enable offchainvm-worker
sudo systemctl start offchainvm-worker
sudo systemctl status offchainvm-worker
```

### Docker Deployment

```dockerfile
FROM rust:1.75 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/offchainvm-worker /usr/local/bin/
CMD ["offchainvm-worker"]
```

Run with:

```bash
docker build -t offchainvm-worker .
docker run -d \
  --name worker1 \
  --env-file .env \
  -v /var/run/docker.sock:/var/run/docker.sock \
  offchainvm-worker
```

### Multi-Worker Setup

Run multiple workers for redundancy and load balancing:

```bash
# Worker 1
WORKER_ID=worker-1 cargo run --release &

# Worker 2
WORKER_ID=worker-2 cargo run --release &

# Worker 3
WORKER_ID=worker-3 cargo run --release &
```

Workers coordinate via distributed locks in Redis to avoid duplicate work.

## License

MIT
