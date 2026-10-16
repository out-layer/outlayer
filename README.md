# NEAR OutLayer

**Verifiable compute and custody for AI agents, on NEAR**

An agent gets a multi-chain wallet whose keys never leave an Intel TDX enclave, spends it under a policy its owner sets, and calls priced **connectors** — named operations like `send_email` or `pay_invoice` — that run inside that same enclave. Keys and the code that uses them never end up in different trust zones.

The same compute layer is callable directly: a NEAR smart contract can request an execution and resume on the verified result, and a web2 backend can call it over HTTPS. Neither the operator nor any third party can tamper with what runs or read the secrets it uses, and every execution returns an enclave-signed attestation that chains to Intel's root certificate.

## Quick Links

- **Dashboard & Docs**: [app.outlayer.ai](https://app.outlayer.ai)
- **HTTPS API (mainnet)**: `https://api.outlayer.ai` → `/call/{owner}/{project}`
- **HTTPS API (testnet)**: `https://testnet-api.outlayer.ai` → `/call/{owner}/{project}`
- **Contract**: `outlayer.near` (mainnet) / `outlayer.testnet` (testnet)
- **API reference**: [API.md](API.md) — endpoints, base URLs, and source-availability notes
- **For AI coding assistants**: [llms.txt](https://app.outlayer.ai/llms.txt) — link index, or [llms-full.txt](https://app.outlayer.ai/llms-full.txt) for every doc in a single fetch
- **Production App**: [near.email](https://near.email) — blockchain-native email built on OutLayer

## How It Works

1. A NEAR smart contract (or HTTP client) submits a computation request
2. A TEE worker picks up the task, fetches the published WASI binary, checks its sha256 and executes it with resource limits
3. The verified result is returned on-chain (via yield/resume) or via HTTP response

## Project Structure

```
outlayer/
├── contract/              # Main NEAR contract (outlayer.near)
├── register-contract/     # TEE worker registration contract (5-measurement TDX verification)
├── keystore-dao-contract/ # DAO governance for keystore worker registration
├── coordinator/           # Task queue & API server (Rust + Axum, PostgreSQL + Redis)
├── worker/                # Execution workers (Rust + Tokio, wasmi runtime)
├── keystore-worker/       # Secrets decryption service (Rust, runs in TEE)
├── dashboard/             # Web UI + documentation (Next.js + React)
├── sdk/                   # OutLayer SDK for WASI apps (Rust, wasm32-wasip2)
├── wasi-examples/         # Example WASI projects
├── scripts/               # Deployment & utility scripts
├── docker/                # Docker configurations (Phala Cloud deployment)
├── tee-auth/              # TEE authentication utilities
└── tests/                 # Integration tests
```

## Two Integration Modes

### Blockchain (NEAR Smart Contracts)

Your contract calls `request_execution()` on `outlayer.near`. The result comes back via NEAR's yield/resume mechanism. Best for on-chain workflows that need verified computation.

```rust
// In your NEAR contract
#[ext_contract(ext_outlayer)]
trait OutLayer {
    fn request_execution(
        &mut self,
        execution_source: ExecutionSource,
        request_params: RequestParams,
    ) -> Promise;
}
```

### HTTPS API (Web2 Apps)

Call the API directly with a payment key. Best for web apps, bots, and services that need off-chain computation without a smart contract.

```bash
curl -X POST https://api.outlayer.ai/call/alice.near/my-project \
  -H "X-Payment-Key: alice.near:1:your_secret_key" \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Hello"}'
```

## Security Model

- **Intel TDX**: Hardware-level memory encryption and isolation — the host operator cannot read TEE memory
- **5-Measurement Verification**: Workers are verified using all 5 TDX measurements (MRTD + RTMR0-3), preventing dev/debug images from passing attestation
- **Sigstore Certification**: Release binaries are cryptographically linked to source code via [Sigstore](https://www.sigstore.dev/)
- **Only Published WASM Runs**: TEE workers with access to secrets execute a published `.wasm` named by its sha256 and run no build scripts, preventing supply chain attacks via malicious build scripts

## Development

### Prerequisites

- Rust 1.85+ (see `rust-toolchain.toml` in each component)
- Docker & Docker Compose
- Node.js 18+ (for dashboard)
- NEAR CLI
- `cargo-near` (for contract builds)
- `sqlx-cli` (for coordinator migrations)

### Build & Run

```bash
# Contract
cd contract && ./build.sh

# Coordinator (requires PostgreSQL + Redis)
cd coordinator && cargo run

# Worker
cd worker && cargo run

# Keystore Worker
cd keystore-worker && cargo run

# Dashboard
cd dashboard && npm install && npm run dev
```

See [QUICK_START.md](QUICK_START.md) for full setup instructions including database initialization and Docker services.

## Documentation

| Document | Description |
|----------|-------------|
| [PROJECT.md](PROJECT.md) | Complete technical specification |
| [QUICK_START.md](QUICK_START.md) | Setup and deployment guide |
| [WORKER_ATTESTATION.md](WORKER_ATTESTATION.md) | TEE attestation deep dive |
| [AUTHENTICATION.md](AUTHENTICATION.md) | Authentication configuration |
| [Onepager.md](Onepager.md) | Project overview one-pager |
| [contract/README.md](contract/README.md) | Contract API reference |
| [worker/README.md](worker/README.md) | Worker configuration |
| [wasi-examples/WASI_TUTORIAL.md](wasi-examples/WASI_TUTORIAL.md) | WASI development tutorial |
| [wasi-examples/BEST_PRACTICES_OUTLAYER_NEAR.md](wasi-examples/BEST_PRACTICES_OUTLAYER_NEAR.md) | Best practices guide |
| [dashboard/DOCS_INDEX.md](dashboard/DOCS_INDEX.md) | Dashboard documentation index |

### Using OutLayer with an AI coding assistant

Point the assistant at one of these instead of pasting files by hand:

| File | Contents |
|------|----------|
| [`/llms.txt`](https://app.outlayer.ai/llms.txt) | Index of every documentation page, with a one-line summary each, in the [llms.txt](https://llmstxt.org) format |
| [`/llms-full.txt`](https://app.outlayer.ai/llms-full.txt) | Full text of all developer docs inlined, ~310 KB, one fetch |
| [OpenAPI spec](https://api.outlayer.ai/openapi.json) | Machine-readable HTTPS API schema |
| [Agent Custody skill](https://skills.outlayer.ai/agent-custody/SKILL.md) | Drop-in skill file for agent frameworks |

Both `llms` files are generated from [dashboard/scripts/llms-manifest.mjs](dashboard/scripts/llms-manifest.mjs) by `npm run llms` in `dashboard/`, and regenerate automatically on `npm run build`.

## Default Ports

| Service | Port |
|---------|------|
| Dashboard | 3000 |
| Coordinator API | 8080 |
| Keystore Worker | 8081 |
| PostgreSQL | 5432 |
| Redis | 6379 |

## License

MIT
