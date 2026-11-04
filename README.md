# NEAR OutLayer

**Verifiable compute and custody for AI agents, on NEAR**

An agent gets a multi-chain wallet whose keys are derived and used inside an Intel TDX enclave, spends it under a policy its owner sets, and calls priced **connectors** — named operations like `send_email` or `pay_invoice` — that run inside that same enclave. Keys and the code that uses them never end up in different trust zones.

The same compute layer is callable directly: a NEAR smart contract can request an execution and resume on the verified result, and a web2 backend can call it over HTTPS. Every execution produces a TDX attestation quote whose signature chains to Intel's root certificate, binding the result to the WASM hash, the input and the measured worker that ran it.

What the operator can and cannot do today — including the governance keys OutLayer still holds at this stage — is stated in [docs/NON_CUSTODIAL.md](docs/NON_CUSTODIAL.md).

## Quick Links

- **Dashboard & Docs**: [app.outlayer.ai](https://app.outlayer.ai) (no API is served from this host)
- **HTTPS API (mainnet)**: `https://api.outlayer.ai` → `POST /call/{owner}/{project}`
- **HTTPS API (testnet)**: `https://testnet-api.outlayer.ai` → `POST /call/{owner}/{project}`
- **Contract**: `outlayer.near` (mainnet) / `outlayer.testnet` (testnet)
- **API reference**: [API.md](API.md) — endpoints, base URLs, authentication
- **For AI coding assistants**: [llms.txt](https://app.outlayer.ai/llms.txt) — link index, or [llms-full.txt](https://app.outlayer.ai/llms-full.txt) for every doc in a single fetch
- **Production App**: [near.email](https://near.email) — blockchain-native email built on OutLayer

## How It Works

1. A NEAR smart contract (or HTTPS client) submits a computation request naming the code: a registered project, or a WASM file by URL and sha256
2. A TEE worker picks up the task, fetches the WASM binary, checks its sha256 and executes it under the request's resource limits
3. The result is returned on-chain (via yield/resume) or in the HTTPS response, together with an attestation record

The contract also accepts a GitHub repository and commit as a source. Building from GitHub is off unless the operator enables it (`BUILDS_ENABLED` on the coordinator, default off); where it is on, builds run on separate compile workers outside the TEE, in Docker. The TEE workers that execute code and receive secrets never compile.

## Project Structure

```
outlayer/
├── contract/              # Main NEAR contract (outlayer.near)
├── register-contract/     # TEE worker registration contract (5-measurement TDX verification)
├── keystore-dao-contract/ # DAO governance for keystore registration (dao.outlayer.near)
├── vault-contract/        # Per-customer vault contract
├── worker/                # Execution workers (Rust + Tokio, wasmtime runtime)
├── keystore-worker/       # Key derivation, signing and secrets decryption (Rust, runs in TEE)
├── sdk/outlayer/          # Rust SDK for WASI apps (crate `outlayer`)
├── connectors/            # Connectors (public ones in-tree, pro ones as private submodules)
├── wasi-examples/         # Example WASI projects and the local test runner
├── self-hosted-scheduler/ # Scheduler for autonomous agents (submodule)
├── deploy/                # Self-hosted TDX deployment tooling
├── docker/                # Docker configurations
├── scripts/               # Deployment & utility scripts
└── tests/                 # Integration tests
```

Separate repositories:

| Component | Repository |
|-----------|------------|
| Coordinator (task queue, HTTPS API, PostgreSQL + Redis) | private: `out-layer/coordinator` |
| Dashboard (web UI + documentation) | [out-layer/dashboard](https://github.com/out-layer/dashboard) |
| CLI | [out-layer/outlayer-cli](https://github.com/out-layer/outlayer-cli) |
| TEE challenge-response auth | [out-layer/shared-tee-helpers](https://github.com/out-layer/shared-tee-helpers) |
| TypeScript SDK | [out-layer/sdk-js](https://github.com/out-layer/sdk-js) |

## Two Integration Modes

### Blockchain (NEAR Smart Contracts)

Your contract calls `request_execution` on `outlayer.near`, attaching NEAR for compute. The result comes back via NEAR's yield/resume mechanism. Best for on-chain workflows that need verified computation.

```rust
// In your NEAR contract
#[ext_contract(ext_outlayer)]
trait OutLayer {
    fn request_execution(
        &mut self,
        source: ExecutionSource,
        resource_limits: Option<ResourceLimits>,
        input_data: Option<String>,
        secrets_ref: Option<SecretsReference>,
        response_format: Option<ResponseFormat>,
        payer_account_id: Option<AccountId>,
        params: Option<RequestParams>,
    );
}
```

A request without `resource_limits` only compiles and runs nothing — pass `{}` to take the defaults. See [contract/README.md](contract/README.md).

### HTTPS API (Web2 Apps)

Call the API directly with a payment key. Best for web apps, bots, and services that need off-chain computation without a smart contract.

```bash
curl -X POST https://api.outlayer.ai/call/alice.near/my-project \
  -H "X-Payment-Key: alice.near:1:your_secret_key" \
  -H "Content-Type: application/json" \
  -d '{"input": {"prompt": "Hello"}}'
```

## Security Model

- **Intel TDX**: Hardware memory encryption and isolation — the host operator cannot read TEE memory
- **5-Measurement Verification**: Workers are registered only when all 5 TDX measurements (MRTD + RTMR0-3) match an approved set, so a dev/debug image fails attestation even when the application matches
- **Sigstore build provenance**: The worker and keystore Docker images are built by GitHub Actions with Sigstore-backed build-provenance attestations, so an image digest can be traced to the source commit it was built from
- **No builds in the TEE**: TEE execution workers run a WASM binary whose sha256 they measure and report to the keystore with every secret decryption; they run no build scripts
- **Stage caveats**: governance currently runs on single keys held by OutLayer (DAO full-access key, owner-only measurement approval, contracts upgraded by key) — see [docs/NON_CUSTODIAL.md](docs/NON_CUSTODIAL.md#governance-at-this-stage)

## Development

The coordinator is a private repository, so the full stack (coordinator + workers + keystore) cannot be run from this repository alone. What you can do from here:

- **Build and test the contracts** — `cd contract && ./build.sh` (uses `cargo near build`); the same for `register-contract/`, `keystore-dao-contract/`, `vault-contract/`
- **Build and unit-test the worker and keystore** — `cargo build` / `cargo test` in `worker/` and `keystore-worker/`; rebuild the release images to compare digests against the Sigstore attestations
- **Write and test a WASI app locally** — follow [wasi-examples/WASI_TUTORIAL.md](wasi-examples/WASI_TUTORIAL.md) and check the binary with [wasi-examples/wasi-test-runner](wasi-examples/wasi-test-runner/README.md)
- **Deploy and call it on the hosted network** — with the [OutLayer CLI](docs/CLI.md) against `testnet-api.outlayer.ai` or `api.outlayer.ai`

### Prerequisites

- Rust (each component pins its toolchain in `rust-toolchain.toml`)
- `cargo-near` (for contract builds)
- NEAR CLI
- Docker (for reproducible image builds)

## Documentation

| Document | Description |
|----------|-------------|
| [app.outlayer.ai/docs](https://app.outlayer.ai/docs) | Developer documentation (getting started, HTTPS API, NEAR integration, agent custody) |
| [API.md](API.md) | HTTPS API endpoints |
| [docs/CLI.md](docs/CLI.md) | Command-line interface |
| [docs/NON_CUSTODIAL.md](docs/NON_CUSTODIAL.md) | Custody model and its current limits |
| [WORKER_ATTESTATION.md](WORKER_ATTESTATION.md) | TEE attestation deep dive |
| [PROJECT.md](PROJECT.md) | Technical specification |
| [contract/README.md](contract/README.md) | Contract API reference |
| [worker/README.md](worker/README.md) | Worker configuration |
| [sdk/outlayer/README.md](sdk/outlayer/README.md) | Rust SDK |
| [VRF.md](VRF.md) | Verifiable random function |
| [docs/CONNECTORS.md](docs/CONNECTORS.md) | Building a connector |
| [wasi-examples/WASI_TUTORIAL.md](wasi-examples/WASI_TUTORIAL.md) | WASI development tutorial |
| [wasi-examples/BEST_PRACTICES_OUTLAYER_NEAR.md](wasi-examples/BEST_PRACTICES_OUTLAYER_NEAR.md) | Best practices guide |

### Using OutLayer with an AI coding assistant

Point the assistant at one of these instead of pasting files by hand:

| File | Contents |
|------|----------|
| [`/llms.txt`](https://app.outlayer.ai/llms.txt) | Index of every documentation page, with a one-line summary each, in the [llms.txt](https://llmstxt.org) format |
| [`/llms-full.txt`](https://app.outlayer.ai/llms-full.txt) | Full text of all developer docs inlined, one fetch |
| [OpenAPI spec](https://api.outlayer.ai/openapi.json) | Machine-readable HTTPS API schema |
| [Agent Custody skill](https://skills.outlayer.ai/agent-custody/SKILL.md) | Drop-in skill file for agent frameworks |

Both `llms` files are built by the [dashboard](https://github.com/out-layer/dashboard) repository (`npm run llms`, also run before every build), partly from the markdown in this repository.

## License

Apache-2.0, except `sdk/outlayer/` and `wasi-examples/`, which are MIT OR Apache-2.0. See [LICENSING.md](LICENSING.md) for the full map.
