# OutLayer Test Suites

Shell suites against a deployed stack (coordinator, keystore, workers,
contracts), plus a fast local gate. Each suite's header comment is its
reference: what it proves, its inputs, how to run it. This page is the map
and the rules every live run follows.

- Worker unit and integration tests (no live stack): [worker/TESTING.md](../worker/TESTING.md)
- Custody / wallet / intents run order and the fund-safety model: [TESTING.md](TESTING.md)
- Smaller wallet suites and the unit tests behind them: [WALLET_TESTS.md](WALLET_TESTS.md)
- Superseded suites kept for reference: [legacy/README.md](legacy/README.md)
- Last full connector-pricing run: [CONNECTOR_TEST_LOG.md](CONNECTOR_TEST_LOG.md)

## Rules for every live run

- **A keyed RPC, always.** A suite that reads the chain builds `RPC_URL`
  through `lib/rpc.sh` (directly or via `lib/hos_common.sh`): an `RPC_URL` in
  the environment wins; otherwise the FastNEAR key comes from
  `FASTNEAR_API_KEY` or near-cli's own config. Without a key the suite prints
  `⚠ no FastNEAR API key` and runs unkeyed — stop there: the unkeyed host's
  rate limits and timeouts read exactly like product failures. A suite that
  only shells out to near-cli uses near-cli's `rpc_url`, which must be the
  keyed one. Suites print the endpoint with `rpc_url_public` (host and
  `(keyed)` / `(UNKEYED)`), never `$RPC_URL`.
- **Secrets never reach the terminal.** No keyed URL, payment key, `wk_`
  token, admin bearer or private key is echoed or written to a tracked file.
  Credentials come from the environment or gitignored env files; a missing one
  is a `${VAR:?}` failure, never a default literal.
- **Testnet by default.** Everything that does not touch NEAR Intents runs on
  testnet (`https://testnet-api.outlayer.ai`, `outlayer.testnet`). Intents
  exist on mainnet only — testnet answers their routes with 503 — so the
  intents suites run on mainnet with real funds; see the table below.
- **Dry run first.** Most suites print their plan and move nothing unless
  given `--apply`.
- **Sequentially.** The wallet routes are rate-limited per IP (100 requests a
  minute); two suites in parallel produce 429s and resets indistinguishable
  from defects. The runners below sleep between suites.
- **Database reads** go through `PSQL_CMD`, a wrapper that runs one SQL
  statement on the coordinator's host; the database is not reachable from
  elsewhere.
- **Webhooks**: `hook_receiver.sh ensure` gives a public receiver
  (Cloudflare quick tunnel) for suites that need one.

## Runners

| Runner | What it runs |
|---|---|
| `unit.sh` | Builds the example wasm and runs the worker's `cargo test`; no network |
| `run_all.sh` | `unit.sh`, then the wallet suites against a **local** coordinator on `localhost:8080` (skipped when none answers) |
| `run_custody.sh` | Every custody suite, sequentially, against testnet; prints the plan without `--apply`; needs `PARENT` and, for some suites, `PSQL_CMD` |
| `run_hos_suite.sh` | Every HoS Agent Connect suite, sequentially, with a coverage report |
| `run_tests.py` | Runs suites under a pty (for keychain prompts); env from `tests/.env.tests` (gitignored): `MPC_PUBLIC_KEY`, `PARENT`, `APPROVER`, `NETWORK`; `--list`, `--group`, `--all` |

## Suites by area

Network is the suite's default; most take `NETWORK` / `COORDINATOR_URL`.

### Custody and wallet

| Suite | Network |
|---|---|
| `unified_op_e2e.sh` — canonical wallet operations: auth, sign, approve/reject, multisig, negatives, delete guards, vault scope | testnet |
| `unified_op_e2e_intents.sh` — intents value flows, payment checks, swaps under multisig, confidential smoke | **mainnet, real funds** |
| `unified_vault_e2e.sh` — vault isolation, sovereign exit, secret decrypt before/after recovery (V1–V6) | testnet |
| `wallet_confidential_e2e.sh` — confidential intents deep-dive | **mainnet, real funds** |
| `route_gaps_e2e.sh` — withdraw and swap routes, dry and quoted only | mainnet, moves nothing |
| `money_settlement_step{1,2,3}_e2e.sh` — settlement after a coordinator release | **mainnet, real funds** |
| `approval_flow_wk_e2e.sh`, `approval_votes_e2e.sh`, `contract_wallet_votes_e2e.sh`, `full_access_key_e2e.sh` — who may approve, and with which key | testnet |
| `velocity_accounting_e2e.sh`, `velocity_two_doors_e2e.sh`, `wallet_concurrent_spend_e2e.sh`, `custody_limit_e2e.sh` — limits and counters | testnet |
| `wallet_policy_mode_e2e.sh`, `policy_storage_refund_e2e.sh`, `internal_policy_sync_e2e.sh` — policy storage and sync | testnet |
| `vault_key_rotation_e2e.sh`, `vault_recovery_e2e.sh`, `vault_backward_compat.sh` — vault keys and recovery | testnet |
| `wallet_probe_e2e.sh` — wallet host functions as a WASI guest sees them | testnet |
| `refusals_e2e.sh`, `stuck_request_repair_e2e.sh` | testnet |
| `wallet_*` mode, signing and dry-run suites | see [WALLET_TESTS.md](WALLET_TESTS.md) |

### HoS Agent Connect

`hos_fixture.sh` (shared fixture), `hos_endpoints_e2e.sh`,
`hos_decoder_policy_e2e.sh`, `hos_custody_matrix_e2e.sh`,
`hos_identity_e2e.sh`, `hos_lifecycle_e2e.sh`, `hos_dos_e2e.sh`,
`hos_gas_floor_e2e.sh`, `hos_lease_stub_e2e.sh`, `hos_lease_live_e2e.sh`,
`hos_lease_bravo_e2e.sh`, `binding_lifecycle_e2e.sh`,
`bound_identity_onchain_e2e.sh`, `personal_wallet_e2e.sh`,
`personal_wallet_global_e2e.sh` — testnet; run them with `run_hos_suite.sh`.
Stub contracts: `deputy-stub/`, `hos-status-stub/`.

### Secrets and keys

`secret_access_conditions_e2e.sh`, `secret_build_lock_e2e.sh`,
`secret_build_lock_fresh_project_e2e.sh`, `secret_predecessor_e2e.sh`,
`secret_predecessor_cli_e2e.sh`, `secret_prepublish_hash_e2e.sh`,
`secrets_security_e2e.sh`, `signing_keys_e2e.sh`, `encryption_keys_e2e.sh`,
`storage_scope_e2e.sh`, `gmail_delegation_e2e.sh` — testnet.

### Connectors, payments, subscriptions

`connector_pricing_e2e.sh`, `connector_budget_parallel_e2e.sh`,
`connector_probe_ops_e2e.sh`, `guess_game_e2e.sh`, `mercury_rules_e2e.sh`,
`tasks_e2e.sh`, `call_credentials_e2e.sh` (claims the account's one trial),
`sponsor_e2e.sh`, `gift_subscription_e2e.sh`, `gift_followup_e2e.sh` — testnet.

### Contract and platform

`contract_probe_e2e.sh`, `contract_hotfix_e2e.sh`, `caller_gate_e2e.sh`,
`input_storage_e2e.sh`, `project_transfer_e2e.sh`,
`cleanup_verification_e2e.sh`, `system_event_effects_e2e.sh`,
`worker_memory_e2e.sh` (fixture `mem-probe/`), `worker_soft_stop_e2e.sh` —
testnet.

`dao/` — governance of the three contracts by the keystore DAO, on a separate set
deployed under `testoutlayerdao.testnet` (never the live contracts): `deploy.sh`
(once), `upgrade_e2e.sh` (each contract upgrades through a vote from a stored blob,
the new code upgrades again, a failing `migrate` reverts the switch, the DAO
upgrades itself only with nothing else open),
`governance_e2e.sh` (electorate snapshot, the owner as a brake, `Call` proposals,
members-only governance, keystore-key check, the owner's money),
`fa_removal.sh --yes` (deletes the accounts' full-access keys for good, then both
suites again) — testnet.

### Basic execution

| Script | What it does |
|---|---|
| `e2e.sh` | One `request_execution` on `outlayer.testnet` for `out-layer/random-example`; result checked by hand |
| `transactions.sh` | Sends the requests in `worker/test_transactions.txt` to the testnet contract |
| `parallel_execution.sh`, `parallel_ai_execution.sh` | Concurrent requests across several workers |
| `verify_jobs.sh` | Job statistics, timings, cache use and duplicate detection from the coordinator DB; `PSQL_CMD=<wrapper> ./verify_jobs.sh` |

## Vault contract and monitor tests (no live stack)

```bash
cargo test --manifest-path keystore-dao-contract/Cargo.toml --lib
cargo test --manifest-path vault-contract/Cargo.toml --lib
cargo test --manifest-path vault-contract/Cargo.toml --features test-timing --test integration   # near-sandbox
cargo test --manifest-path outlayer-monitor/Cargo.toml --bins
cargo test --manifest-path outlayer-monitor/Cargo.toml --bins --features lake-source
cargo test --manifest-path wasi-examples/vault-checker/Cargo.toml --bins
```

`vault_recovery_e2e.sh unilateral [--apply]` builds the vault contract with
`test-timing` (cessation delay 30 s, unilateral exit window 10 s), deploys it
to a fresh testnet sub-account and drives a unilateral recovery to
`unlocked == true`. That build's hash differs from the production one and
fails `vault-checker` by design. `vault_e2e.sh` is a manual runbook that
prints and runs CLI steps; it asserts nothing.

## Helpers

`lib/` holds what the suites share: `rpc.sh` (keyed RPC, `rpc_url_public`),
`near_sign.sh`, `hos_common.sh`, `money_e2e.sh`, `secrets_common.sh`,
`tasks_common.sh`, and the node helpers for signing, passkey and EVM votes,
the webhook receiver and the tasks page. A new suite sources `lib/rpc.sh`
rather than naming an RPC host of its own.
