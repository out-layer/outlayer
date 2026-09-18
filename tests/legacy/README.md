# tests/legacy/ — superseded standalone tests (coverage ported into the unified suite)

These are the OLD standalone wallet/custody/intents tests whose coverage was **ported into the
unified suite** (`../unified_op_e2e.sh`, `../unified_op_e2e_intents.sh`, `../unified_vault_e2e.sh`).
Kept for reference / diffing — **not part of the canonical run** (see `../TESTING.md`). They are NOT
maintained: helpers here predate the fund-safety fixes (subshell-file tracking, constant
`BENEFICIARY`, `verify_all_drained`). If you find a real behavior asserted ONLY here, port it INTO the
unified suite — do not re-grow this folder.

## Mapping (legacy file → unified test that replaced it)

| Legacy file | Ported into |
|-------------|-------------|
| `payment_checks_e2e.sh` | **T13** (intents) — partial-claim → `partially_claimed`, double-CLAIM rejection |
| `gasless_e2e.sh` | **T14** (intents) — swap-quote, insufficient-balance, withdraw-dry-run |
| `wallet_deposit_intent_chains_e2e.sh` | **T15** (intents) — deposit-intent address matrix across 6 chains |
| `wallet_sign_message_roundtrip.sh` | **T13** (testnet) — ed25519-VERIFY + tamper + cross-scope |
| `api_key_signed_derive_e2e.sh` | **T14** (testnet) — PUT /api-key NEAR-sig + cross-account refusal |
| `bearer_vault_endpoint_parity_e2e.sh` | **T15** (testnet) + **V1** (vault) — endpoint vault-scope parity / isolation |
| `v2_policy_invariants_e2e.sh` | **T16** (testnet) — seed validation, idempotency, reverse-lookup |
| `approval_flow_e2e.sh` | **T17** (testnet) — on-chain `signer_id == sub-wallet` |
| `approval_threshold_e2e.sh` | **T4** (testnet) — 2-of-2 multisig threshold (subsumed) |
| `vault_multi_customer_isolation.sh` | **V1** (vault) — two scopes → distinct addresses; header ignored |
| `multi_wallet_vault_e2e.sh` | **V2** (vault) — N wallets per one vault; sub-agent inherits |
| `bearer_near_recovery_e2e.sh` | **V3** (vault) — Bearer-near sovereign exit + offline re-derive |
| `vault_detach_test.sh` | **V4** (vault) — secret-decrypt before/after recovery |
| `sovereignty_e2e.sh` | **V5** (vault) — wk_-path sovereign exit + real local-key tx |

## Still standalone (NOT moved — unique coverage not yet in the unified suite)

- `wallet_confidential_e2e.sh` — the FULL phase-based confidential deep-dive (the intents-suite T16 is only the shield/unshield+swap-multisig smoke slice).
- `internal_policy_sync_e2e.sh` — `/internal/wallet-policy-sync` decrypt path (needs a worker token).
- `approval_flow_wk_e2e.sh` — the `wk_`/`POST /register` WF-3 vault_id INSERT/fallback guard.
- `vault_e2e.sh`, `vault_recovery_e2e.sh` — CLI-driven vault deploy + the vault **contract** recovery state machine (contract-layer, not coordinator).
- `wallet_intents_e2e.sh`, `wallet_mode1_agent.sh`, `wallet_mode2_policy.sh` — `/tokens`, `/audit`, `/requests`, `/invalidate-cache`, idempotency-dedup, rate-limit (small deltas; partly covered by T14).
- `vault_backward_compat.sh` — legacy non-vault `/register` default-master.

(Everything else in `../` is infra: compilation, jobs, parallel, unit, integration, transactions, run_all, e2e, verify_jobs.)
