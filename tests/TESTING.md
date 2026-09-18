# OutLayer agent-custody test stack — how it works + what to run

This documents the **wallet / custody / NEAR-Intents** e2e surface (the TEE keystore + coordinator
signing path). It is the single source of truth for **what must be run to be confident the whole
custody stack works**, and how the suite keeps real funds safe.

> EVM signing v1 (one shared secp256k1 `0x` address + EIP-191 / EIP-712 v4 / raw-tx signing) is
> covered by `wallet_evm_sign_e2e.sh` (wired into `run_all.sh`) — read-only, no funds, runs on
> testnet (needs only coordinator + keystore). See [WALLET_TESTS.md → EVM signing](WALLET_TESTS.md#evm-signing).

## The split principle

> Everything that does NOT touch NEAR Intents runs on **testnet**.
> Everything that DOES touch Intents (regular + confidential) runs on **mainnet** — there are no
> testnet solvers and the coordinator returns HTTP 503 for intents endpoints off-mainnet.

## Canonical files (run THESE for full-stack confidence)

| File | Network | Covers |
|------|---------|--------|
| `unified_op_e2e.sh` | **testnet** | auth-sign, sign_message (+ed25519-verify), approve/reject + **2-of-2 multisig**, negatives (hash-substitution, cross-wallet replay), delete-account guards + destructive delete, api-key signed derive, vault-scope parity, wallet_id v2 invariants, on-chain-signer proof |
| `unified_op_e2e_intents.sh` | **mainnet** | cross_chain_withdraw gate, payment_check gate + claim/reclaim/batch + **partial-claim/double-claim**, FT withdraw→external via solver, swap gate, swap & cross-chain under multisig, gasless swap-quote/insufficient/withdraw-dry-run, deposit-intent chain matrix, **confidential** shield/unshield/swap-multisig |
| `wallet_confidential_e2e.sh` | **mainnet** | standalone phase-based confidential deep-dive (shield/unshield/balance/x-chain deposit+withdraw/conf-swap). T16 in the intents file is the smoke-test slice; this file is the full exploration. |
| `unified_vault_e2e.sh` | **testnet** | _(planned)_ vault sovereign-exit/recovery/isolation: finalize_recovery→keystore-refuses→re-derive, detach secret-decrypt, multi-wallet-per-vault, multi-customer isolation, endpoint parity; **V6** a secret CREATED for an agent under a vault (both money paths, and what the wallet's signature covers) |
| `call_credentials_e2e.sh` | **testnet** | who may call what, K1–K6 — the whole credential matrix on one stack: no credential is refused on both a connector and an ordinary project; a `wk_` authenticates a WALLET route in the same run and still buys nothing (the removed second credential must not come back); a claimed trial reaches a connector and is refused on an ordinary project **by scope**, not by balance; a funded payment key reaches both. **Claims this account's one trial — it cannot be undone or repeated.** |
| `connector_pricing_e2e.sh` | **testnet** | connector money, C1–C11 — results of the last full run are logged in [CONNECTOR_TEST_LOG.md](CONNECTOR_TEST_LOG.md): the on-chain admission gate (exact price, the `operation` field, refusals), the author's share per OPERATION in the contract's ledger, the same connector over HTTPS incl. the outbound allowlist, `/admin/earnings` against the chain, the fee landing on top of compute + the reservation returning, the owner's secret reaching the guest only when asked, the trial's ten calls and the funded key's absence of a call limit (C7), the egress audit / call log, what a timed-out or never-claimed call costs (C9, needs the fleet arranged — see its comment), the trial key with its scope and its author-pays-nothing rule (C10), and the refusals — a trial cannot pay an author, a deposit to a connector is void, and `agent: true` is refused — every key is a string its holder presents (C11). **C7 and C10 each claim a trial; when none is on offer (`trial_unavailable`) the rows skip** (C7 on a wallet it mints itself, so order does not matter) — `ONLY=C1,C2,C3,C4,C5,C8,C11` repeats the rest without claiming. |

`tests/legacy/` holds the **older standalone tests whose coverage was ported into the unified suite**
(approval_flow, approval_threshold, payment_checks, gasless, wallet_intents, sign_message_roundtrip,
api_key_signed_derive, the vault_* / sovereignty / bearer_* recovery scripts, …). Kept for reference;
NOT part of the canonical run. If you change a helper in the unified files, you do NOT need to touch
legacy — but if you find a real behavior only legacy asserts, port it into the unified suite (don't
re-grow legacy).

## How to run

**Always dry-run first** (prints the plan, exits 0, moves nothing) by dropping `--apply`.

```bash
# ── 1. TESTNET (everything non-intents) ──────────────────────────────────────
#   prereq: outlayer login testnet (as PARENT); APPROVER creds in ~/.near-credentials/testnet/
PARENT=zavodil.testnet APPROVER1=zavodil2.testnet APPROVER2=zavodil2.testnet \
  ./tests/unified_op_e2e.sh --apply

# ── 2. MAINNET intents (real money) ──────────────────────────────────────────
#   prereq: outlayer login mainnet (as PARENT=fastjambo.near); a MAINNET approver with creds;
#           EXTERNAL_ACCT must be storage-registered on wrap.near (zavodil.near is)
NETWORK=mainnet PARENT=fastjambo.near EXTERNAL_ACCT=zavodil.near \
  APPROVER1=<mainnet-approver> APPROVER2=<mainnet-approver> \
  ./tests/unified_op_e2e_intents.sh --apply

#   confidential (T16) additionally needs the JWT + the coordinator's confidential upstream:
ONECLICK_CONFIDENTIAL_JWT=1 ./tests/unified_op_e2e_intents.sh --apply   # (with the env above)

# ── 3. CONFIDENTIAL deep-dive (optional, mainnet, phase-based) ────────────────
ONECLICK_CONFIDENTIAL_JWT=1 COORDINATOR_URL=https://api.outlayer.ai \
  NETWORK=mainnet PARENT=fastjambo.near ./tests/wallet_confidential_e2e.sh roundtrip

# ── 4. VAULT sovereign-exit (testnet) — planned ──────────────────────────────
#   ./tests/unified_vault_e2e.sh --apply
```

Subset: `ONLY=T1,T11 …` runs just those. The mainnet file targets mainnet by default (its env
defaults are `outlayer.near` / `api.outlayer.ai` / `wrap.near`).

## Fund-safety model (why a money test never leaks)

Every value-moving test is wrapped so a real-money run cannot strand funds:

- **`MONEY=true` fail-fast** — while a money test runs, a `fail()` doesn't just record; it HALTS the
  run (so funds aren't left mid-flight by a continuing suite). The EXIT trap then sweeps.
- **Per-test return** — each money test calls `return_test_funds` (sweep) at its end; the EXIT trap
  is the abort-path safety net.
- **`sweep_one`** — drains a throwaway sub-wallet back to the constant `BENEFICIARY`
  (**zavodil.near** mainnet / **zavodil.testnet** testnet — a real, existing, wNEAR-registered sink, so
  DeleteAccount never burns): withdraw any intents wNEAR FIRST, then DeleteAccount the native, then
  reclaim the on-chain policy-storage deposit.
- **`verify_all_drained`** — final pass over EVERY sub-wallet created this run; any residual native
  >0.01 NEAR or non-zero intents balance is a **LEAK** (fails the suite, prints the recovery seed).
- **Seed log** — every throwaway sub-wallet seed is appended to `~/.outlayer/uop-seeds.log`
  (`<ts> <seed> <wallet_id> <addr>`), so even a leaked wallet is recoverable
  (`customer-recovery compute-wallet-id` + `sign-bearer-near` → bearer → sweep, no keystore master
  needed).

> ⚠️ **Tracking lives in FILES, not bash arrays** (`SWEEP_QUEUE`/`RUN_LEDGER`). `new_subwallet` runs
> inside the `read … < <(new_subwallet …)` process-substitution subshell, where bash-array appends
> are lost — a file append survives. This was the root cause of every historical test-fund leak.
> The helper section is DUPLICATED across `unified_op_e2e.sh` ↔ `unified_op_e2e_intents.sh` — fix BOTH.

> ⚠️ **Cross-chain is one-way.** T10 (cross_chain_withdraw) and the confidential x-chain withdraw
> target other chains (ethereum burn / solana) and CANNOT be swept back. They run **UNFUNDED** —
> only the multisig control-flow (pending→approve→sign) is asserted; the downstream transfer fails on
> "no balance" so nothing actually leaves. Do NOT fund them.

## What "the whole stack works" means

Green = all three canonical runs pass with `verify_all_drained` reporting **0 leaks**:
1. `unified_op_e2e.sh` on testnet (op-signing + auth + delete + multisig + vault-scope).
2. `unified_op_e2e_intents.sh` on mainnet (intents value-flow + multisig + payment-checks + confidential smoke).
3. (deep) `wallet_confidential_e2e.sh roundtrip` on mainnet, and `unified_vault_e2e.sh` on testnet
   (sovereign-exit) once they're in place.
