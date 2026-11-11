# OutLayer Worker

The worker takes tasks from the coordinator, prepares the wasm for a run
(downloads a published `WasmUrl` or, on a builder, compiles a GitHub
repository), executes it under resource limits and returns the result: to the
contract for an on-chain request, to the coordinator for an HTTPS call.
Production execution workers run inside Intel TDX CVMs on our own hosts (see
[`deploy/self-hosted-tdx`](../deploy/self-hosted-tdx/README.md)); compilation
never runs in the enclave.

## Roles

What a worker does is set by three switches (`src/config.rs`); at least one must be on.

| Variable | Default | Role |
|----------|---------|------|
| `EXECUTION_ENABLED` | `true` | Runs a cached wasm (TEE workers) |
| `DOWNLOAD_ENABLED` | `false` | Downloader: fetches a `WasmUrl`, checks its sha256 and caches it; no Docker, no build, runs nothing |
| `COMPILATION_ENABLED` | `false` | Builder: builds a GitHub repository and fetches a `WasmUrl`; builds run only where the coordinator has `BUILDS_ENABLED=true` (default `false`) |

Builds are off by default on both sides. The code sources a user can name are
`Project` and `WasmUrl`, and a project version's source is a `WasmUrl`: a
published `.wasm` named by its sha256, which the worker refuses when the bytes
do not match. With builds off the coordinator refuses a `GitHub` task whose
wasm is not cached. A downloader configuration is in `.env.example` (ROLES).

A build is not a sandbox for untrusted code: cargo runs every `build.rs` and
proc-macro of the repository and its dependencies, and the docker build
container runs as root on the `bridge` network. What must hold before builds
are enabled for arbitrary repositories is listed on
`Compiler::compile_from_github` (`src/compiler/mod.rs`).

## Components

| Module | What it does |
|---|---|
| `config.rs` | Configuration from environment variables |
| `api_client.rs` | Coordinator API: `poll_task`, `claim_job`, `complete_job`, `complete_https_call`, `fail_task`, `upload_wasm` / `download_wasm`, `acquire_lock` / `release_lock`, heartbeats, event relays |
| `registration.rs`, `tdx_attestation.rs` | TEE registration: generates the worker key in the CVM and registers it with a TDX quote on the register-contract at `OPERATOR_ACCOUNT_ID` |
| `compiler/` | `WasmUrl` download and GitHub builds ([README](src/compiler/README.md)) |
| `executor/` | wasmtime execution of WASI P1 modules and P2 components ([README](src/executor/README.md)) |
| `wasm_cache.rs`, `compiled_cache.rs` | Local cache of wasm bytes and of compiled modules |
| `near_client.rs` | Submits results on chain: `resolve_execution` for a small result, `submit_execution_output_and_resolve` for a large one; top-up and payment-key resumes |
| `keystore_client.rs` | Secret decryption (`/decrypt`) against the keystore TEE |
| `event_monitor.rs` | Optional: reads contract events from neardata and relays them to the coordinator |
| `outlayer_*`, `signing_keys/`, `encryption_keys/`, `tasks/` | Host interfaces for components (see [Host functions](#host-functions)) |

### Event monitor (`ENABLE_EVENT_MONITOR=true`)

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
| top-up, before the resume | the worker asks `POST /payment-keys/creditable`; a key whose coordinator row is deleted — closed by the chain or deleted by an admin — is resumed with an error (the contract returns the transfer to the payer), never credited nowhere. A deleted key does not come back; the owner creates another | same |
| top-up, after the resume | the credit (`POST /topup/complete`) carries the yield's `data_id` and is recorded once per yield in `payment_key_topups`, so it is repeated through `retry_relay` until it lands (a 5xx, a 429, a dropped connection, the relay timeout); a 4xx ends it. The chain took the resume, so a credit that ends without landing is money the chain KEPT and the coordinator does not have: a 409 is a row the chain closed after the resume, recorded by the coordinator as owed (`payment_key_topups.credited = FALSE`); anything else has no record but the worker's `OWED` error line. Both are the operator's to reconcile. **Deploy order is a money rule:** the coordinator that records `data_id` (migration `20261109000005`) goes FIRST on each network, the workers after — an older coordinator accepts `data_id`, ignores it, and credits every repeat again | same |
| payment key creation (amount 0) | relayed | relayed only if the key still exists at the final block |
| `delete_payment_key` / `close_payment_key` | not relayed: the contract keeps the key, the owner deletes or closes again (an unknown tip: tried again) | same rule |
| `claim_payment_key_refund` | not relayed: the contract keeps the key closing, the owner claims again (an unknown tip: tried again). The quote itself (`POST /payment-keys/refund-quote`) is asked again on a transport failure or a 5xx for about a minute, inside the yield window — a failed quote costs the owner a day; a 4xx is the coordinator's refusal and is relayed as is | same rule |

The three payment-key yields — delete, close, refund claim — are all resumed
through `resume_delete_payment_key`, the one method the worker's access key on
the operator account is scoped to (`register-contract`): the `data_id` names
the yield, and each callback acts only on the `DeletePaymentKeyResult`
variants that answer its question (`Success` / `Error` for a delete or a
close, `Refund { amount }` / `Error` for a claim).
| wallet policy / freeze | relayed | the wallet's state at the final block is relayed, not the event's |
| subscription purchase, project cleanup, project transfer | relayed | relayed |

A block within 10 blocks after an unread one that holds a call which may be a
meta-transaction waits for it, so the call is not judged by the wrong door.

## Task flow

### Preparation (`WasmUrl`)

1. Receive the task (downloader or builder role)
2. Return at once if a wasm with that sha256 is cached
3. Fetch the URL (`https://`, port 443, public address only, 10 MB cap)
4. Refuse the file if its sha256 does not match `hash`
5. Upload it to the coordinator's cache

### Compile (`GitHub`, builder role with builds enabled)

1. Compute the checksum of (repo, commit, build_target); return if cached
2. Acquire the coordinator lock for that checksum
3. Build in Docker (`COMPILATION_MODE=docker`, default) or natively
   (`COMPILATION_MODE=native`), for `wasm32-wasip1` / `wasm32-wasi` or `wasm32-wasip2`
4. Upload the wasm, release the lock

### Execute

1. Claim the job; load the wasm from the local cache or the coordinator
2. Decrypt the run's secrets through the keystore, when the request names any
3. Run it: input on stdin, output from stdout, with fuel (instruction)
   metering, a memory bound and a time limit
4. Return the result: on chain for a contract request, to the coordinator for
   an HTTPS call

## WASM interface

A guest is a WASI program: a P1 module exporting `_start` (a Rust `fn main()`
built for `wasm32-wasip1`) or a P2 component exporting `wasi:cli/run`
(`wasm32-wasip2`). It reads its JSON input from stdin and writes its output to
stdout; secrets arrive as environment variables. The executor tries P2 first,
then P1. Writing a guest: [wasi-examples/WASI_TUTORIAL.md](../wasi-examples/WASI_TUTORIAL.md).

### Host functions

WASI P2 components import host interfaces from `wit/` (`near:rpc`,
`near:storage`, `near:payment`, `near:vrf`, `outlayer:wallet`,
`outlayer:signing-keys`, `outlayer:encryption-keys`, `outlayer:tasks`); each
published version is a fixed ABI ([wit/README.md](wit/README.md)). The wallet
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

### Network

Guests have no raw sockets: both WASI contexts deny TCP, UDP and name lookup
(`src/executor/wasi_p1.rs`, `wasi_p2.rs`); the only network path is
`wasi:http`, which runs through the outbound allowlist and the egress audit.

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

## Stopping

SIGTERM or SIGINT (Ctrl-C) is a soft stop: the main loop and the system-callbacks loop poll
for nothing more, the task in hand runs to its end, and the worker exits 0. A poll already in
flight is not cancelled — the task it returns is finished too. In a dstack CVM the signal comes
from a non-forced `vmm stop` (`worker-ctl.sh stop`); the compose gives the worker 85 s before
the guest kills it.

## Configuration

`.env.example` documents every variable; `src/config.rs` is the authority. A
production worker's env is `deploy/self-hosted-tdx/worker/<net>-worker.env.template`.

### Required

| Variable | Meaning |
|---|---|
| `API_BASE_URL` | Coordinator URL. A deployed worker uses the public API host (`https://api.outlayer.ai`, `https://testnet-api.outlayer.ai`), through nginx; a call straight to `:8080` carries no `X-Real-IP` and is refused |
| `API_AUTH_TOKEN` | The worker's coordinator token |
| `NEAR_RPC_URL` | NEAR RPC endpoint |
| `OFFCHAINVM_CONTRACT_ID` | `outlayer.near` / `outlayer.testnet` |
| `OPERATOR_ACCOUNT_ID` | Account holding the register-contract (`worker.outlayer.near` / `worker.outlayer.testnet`) |

### Registration

- `USE_TEE_REGISTRATION=true` (default): the worker generates its key in the
  CVM and registers it with a TDX quote; `INIT_ACCOUNT_ID` and
  `INIT_ACCOUNT_PRIVATE_KEY` pay the registration gas. `TEE_MODE=outlayer_tee`
  reads the quote from the dstack guest agent. `WORKER_KEY_TYPE` is `ed25519`
  (default) or `ml-dsa-65`.
  Keep at least 0.4 NEAR available on the init account (a registration
  prepays 300 TGas and spends about 0.025 NEAR). A registration can be taken
  by the RPC and never included by the chain while the balance still covers
  its prepaid gas, with no error from either; the protocol rule behind it is
  not known, and 0.4 NEAR is a margin, not a protocol figure. On every start
  the worker logs the init account's balance and, under 0.4 NEAR, an error
  line starting `❌❌❌ INIT ACCOUNT BALANCE LOW`; before it registers it
  refuses when the balance cannot cover the prepaid gas, and follows the
  registration for two minutes. A transaction the RPC took and the chain did
  not see in two rounds in a row ends with "taken by the RPC and not seen by
  the chain".
- `USE_TEE_REGISTRATION=false`: `OPERATOR_PRIVATE_KEY` signs results directly
  (local development). A worker with `EXECUTION_ENABLED=false` needs no
  operator key.

### Optional (defaults)

```bash
WORKER_ID=                            # default: random UUID
ENABLE_EVENT_MONITOR=false
POLL_TIMEOUT_SECONDS=60
KEYSTORE_BASE_URLS=                   # comma-separated; empty = no keystore
EXECUTE_EXCLUDES=                     # see "Routes this node will not run"

# Builder role
COMPILATION_MODE=docker               # docker | native
DOCKER_IMAGE=outlayer/wasmedge-compiler:rust1.85-wasi25   # pin by digest in a deployment, see docker/BUILD.md
COMPILE_TIMEOUT_SECONDS=300
COMPILE_MEMORY_LIMIT_MB=2048
COMPILE_CPU_LIMIT=2.0

# Execution
DEFAULT_MAX_INSTRUCTIONS=10000000000
DEFAULT_MAX_MEMORY_MB=128
DEFAULT_MAX_EXECUTION_SECONDS=60
MAX_EXECUTION_SECONDS_CAP=180         # the most a request may ask for
WASM_MEMORY_FLOOR_MB=1024             # the least linear memory a run is given, whatever max_memory_mb it asked; a growth past the bound is refused (memory.grow answers -1)
WASM_MEMORY_CEILING_MB=4096           # the most (wasm32's own bound)
MAX_OUTPUT_BYTES=10485760             # 10 MiB — the stdout capacity; a write past it fails
WASM_CACHE_MAX_SIZE_MB=100            # local wasm cache; 0 disables it
```

## Running locally

```bash
cd worker
cp .env.example .env     # fill in; never commit it
RUST_LOG=offchainvm_worker=debug cargo run
```

The toolchain is pinned by `rust-toolchain.toml`. A builder needs Docker
(`COMPILATION_MODE=docker`).

## Tests

```bash
cargo test                       # unit tests and tests/*.rs
```

Component tests under `tests/` build their fixtures from `wasi-examples/`; see
[TESTING.md](TESTING.md). Live end-to-end suites are in [`tests/`](../tests/README.md).

## Deployment

Release images are built by `.github/workflows/release-docker.yml` from
`docker/Dockerfile.worker-phala` and attested with Sigstore
([docker/DOCKER_RELEASE.md](../docker/DOCKER_RELEASE.md)). A worker CVM is
deployed with `scripts/deploy_tdx.sh worker <net> --version <ver> --node <host>`,
which also approves its measurements on the register-contract.

## License

Apache-2.0 (`Cargo.toml`).
