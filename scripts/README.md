# Scripts

Deployment, build, maintenance and utility scripts. Each script's header
comment is its reference; this table is an index. Scripts that need
credentials read them from `scripts/.env` (template: `scripts/.env.example`)
or near-cli's keychain; never pass a secret on a command line you log.

## Deploy (self-hosted Intel TDX)

| Script | Description |
|--------|-------------|
| `deploy_tdx.sh` | Deploy a worker or keystore CVM to a TDX node from the Mac: resolve and check the release digest, deploy over SSH, read measurements, approve them locally (register-contract for a worker, DAO for a keystore), wait for registration / vote. `--os-image` upgrades a CVM's guest image in place; `--kms-url` selects the KMS |
| `keystore_urls.sh` | Set `KEYSTORE_BASE_URLS` for a network from the keystores that are live; dry run by default, `--apply` writes, `--up` recreates the coordinator |
| `smoke_after_deploy.sh` | Post-deploy smoke test of coordinator + keystore endpoints; config from `scripts/.env`, missing config is reported SKIP |

## Phala Cloud (not the production path)

| Script | Description |
|--------|-------------|
| `deploy_phala.sh` | Deploy a worker or keystore to Phala Cloud, approve its measurements, vote. Production runs on self-hosted TDX (`deploy_tdx.sh`) |

## Build and inspect images

| Script | Description |
|--------|-------------|
| `build_and_push_phala.sh` | Build and push a worker image: `worker` (`docker/Dockerfile.worker-phala`) or `worker-compiler` (`docker/Dockerfile.compiler-worker`, default). Unattested; release images come from CI ([docker/DOCKER_RELEASE.md](../docker/DOCKER_RELEASE.md)) |
| `build_and_push_keystore_tee.sh` | Build and push the keystore image (`docker/Dockerfile.keystore-phala`), unattested |
| `build_and_push_keystore.sh` | Same image with buildx caching; runs `inspect_docker_context.sh` first and a local start test |
| `build_local_fast.sh` | Local `docker build` of the keystore or worker image, no push |
| `dry_run_docker_build.sh` | Show exactly which files a worker image build copies |
| `inspect_docker_context.sh` | Show the build context of a Dockerfile, to catch secrets in it |
| `verify_built_image.sh` | Check a built image for secrets |
| `build_github_wasm.sh` | Build a project reproducibly in the pinned compiler image and print the wasm sha256 (`--twice` checks it reproduces, `--keep` keeps the file to publish) |
| `test_compiler.sh` | Build a repository the way the worker's docker compiler does: `<repo_url> <commit> <build_target> [output]` |

## Run locally

| Script | Description |
|--------|-------------|
| `run_worker.sh` | `cargo run` the worker with an env file from `worker/`: `<env-file> [--verbose]` |
| `run_worker_local.sh` | Same, for a local development config: `[env-file-path]` |
| `run_keystore.sh` | Run the keystore with `keystore-worker/.env.dev`, `.env.testnet` or `.env`: `[dev\|testnet\|mainnet]` |

## On-chain maintenance

| Script | Description |
|--------|-------------|
| `update_collateral.sh` | Write an Intel collateral into a register-contract slot (one slot per FMSPC; slot 1 = self-hosted TDX): `<collateral.json> <index> [network] [contract]` |
| `update_collateral_mainnet.sh` | `update_collateral` on `dao.outlayer.near` from `collateral.json` |
| `fetch_intel_collateral.sh` | Fetch TDX collateral (TCB info, QE identity, CRLs) from Intel PCS |
| `collateral.json`, `our_collateral.json` | Collateral files those scripts take; public Intel data |
| `revoke_old_worker_keys.sh` | Report, and with `--send` remove, access keys on `worker.outlayer.<net>` of workers no longer running |
| `revoke_old_keystore_keys.sh` | Report, and with `--send` retire, the keys of old keystore images; last step of a keystore upgrade |
| `set_connector_prices_testnet.sh` | Put the connector prices on chain on testnet; an unpriced connector call is refused |
| `refresh_keystore_stats.sh` | Clear the coordinator's cached keystore vault/session counters so Grafana shows fresh ones: `<testnet\|mainnet>` (admin token from `scripts/.env`) |

## Tests

| Script | Description |
|--------|-------------|
| `test_execution_request.sh` | `request_execution` on `outlayer.testnet` for `out-layer/random-example` |
| `test_register_contract.sh` | Register-contract key registration with a simulated TDX attestation: `<register-contract-id> <operator-account-id>` |
| `test_intents_e2e.sh` | Wallet + NEAR Intents cycle (register, wrap, swap to USDT, `ft_transfer` out) against `https://api.outlayer.ai` by default — **mainnet, real funds**; testnet has no Intents |

Live e2e suites are in [`tests/`](../tests/README.md).

## Data tools

| Script | Description |
|--------|-------------|
| `scan_signature_wallet_balances.py` | Read-only scan of signature-origin wallets in the coordinator DB and their on-chain balances, before a wallet-id migration |
| `upload_wasm_fastfs.py` | Upload a wasm to FastFS (Borsh `FastfsData`): `<wasm_file> [env_file]` |
| `customer-recovery/` | Standalone tool for a customer to recover a per-customer vault master after `finalize_recovery` ([README](customer-recovery/README.md)) |
