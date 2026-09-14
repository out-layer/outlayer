#!/bin/bash
# MANUAL RUNBOOK for Phase 6+7 sovereign vaults — NOT an automated test.
#
# Read this before trusting a green run: nothing here asserts anything. `run()`
# hands its command to `eval` and ignores the result, several steps tell the
# operator to read a `wk_` off the screen and paste it into the next one, and
# the isolation scenario ends by printing a response for a human to compare.
# A run that reports no failures has verified nothing — it has printed a
# procedure.
#
# THE AUTOMATED COVERAGE IS ELSEWHERE, and it is better:
#   tests/unified_vault_e2e.sh V1  two vault scopes under one parent derive
#                                  DIFFERENT addresses, sign with DIFFERENT
#                                  public keys, and a client-supplied
#                                  `X-Customer-Vault` header is IGNORED — the
#                                  exact claims scenario 5 below asks a human
#                                  to eyeball
#   tests/unified_vault_e2e.sh V3/V5  sovereign exit: finalize_recovery, the
#                                  keystore refusing afterwards, and the
#                                  customer re-deriving the same address
#                                  offline
#   tests/unified_vault_e2e.sh V4/V6  per-vault secret decrypt before/after
#                                  recovery, and creating a secret FOR an agent
#
# What is left here is the part no script can do: DAO votes, 7-day windows, and
# deploying under a second real NEAR login. Kept as a procedure, labelled as
# one.
#
# Drives the testable subset of Phase 10's 7 scenarios from the
# per-vault master plan (partitioned-dreaming-patterson.md lines
# 814-822). Scenarios that need DAO governance actions, 7-day waits,
# or human alpha testers are documented inline as MANUAL steps.
#
# Prerequisites:
#   * `outlayer` CLI on PATH (built from outlayer-cli)
#   * Coordinator running and reachable (default localhost:8080)
#   * Keystore worker running with TEE registration completed
#   * NEAR account on testnet/mainnet logged in via `outlayer login`
#   * Account has at least 5 NEAR for two atomic-deploy attempts
#
# Run subsets via: ./vault_e2e.sh happy | isolation | compat | all
#
# Defaults to dry-run (printing the steps); pass `--apply` to execute.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPLY=false
SCENARIO="${1:-all}"
[[ "${2:-}" == "--apply" ]] && APPLY=true
[[ "${1:-}" == "--apply" ]] && { APPLY=true; SCENARIO="all"; }

NETWORK="${NETWORK:-testnet}"
# EXPORTED, or the value above is a decoration.
#
# Every `outlayer …` call below follows `~/.outlayer/default-network` unless
# this is in the environment, and on a machine whose default is mainnet that
# means a script announcing testnet acts on MAINNET. Caught on 2026-08-22:
# this suite reported `parent: fastjambo.near / vault account:
# vault.fastjambo.near` and was stopped from deploying a real mainnet vault
# only by that account holding 0.2 NEAR against the 1.1 it needed.
export OUTLAYER_NETWORK="$NETWORK"

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/rpc.sh"   # keyed RPC_URL, or a warning

# Is this account on chain at all? Used to tell "deploy a vault" from "a vault
# is already deployed" — `vault init` refuses the second case outright.
account_exists() {
  local acct=$1 rpc amount err
  rpc=$(curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"query\",\"params\":{\"request_type\":\"view_account\",\"finality\":\"final\",\"account_id\":\"$acct\"}}" 2>/dev/null || echo '')
  err=$(echo "$rpc" | jq -r '.error // .result.error // empty' 2>/dev/null)
  amount=$(echo "$rpc" | jq -r '.result.amount // empty' 2>/dev/null)
  [[ -z "$err" && -n "$amount" ]]
}
COORDINATOR_URL="${COORDINATOR_URL:-http://localhost:8080}"

# Two distinct test accounts so multi-customer isolation can be
# exercised without re-logging in mid-script. The operator is
# expected to have logged in as customer-a; customer-b is whatever
# account the operator passes via env.
CUSTOMER_A="${CUSTOMER_A:-}"
CUSTOMER_B="${CUSTOMER_B:-}"

# ─── helpers ───────────────────────────────────────────────────────

log()   { printf '\n\033[36m▶ %s\033[0m\n' "$*"; }
warn()  { printf '\033[33m⚠ %s\033[0m\n' "$*"; }
fail()  { printf '\033[31m✗ %s\033[0m\n' "$*"; exit 1; }
pass()  { printf '\033[32m✓ %s\033[0m\n' "$*"; }
# A step whose verdict a human has to reach. Deliberately NOT `pass`: this
# script used to end its isolation scenario with a green tick over a printed
# response nobody compared, which reads as covered and is worse than silence.
manual() { printf '\033[33m☐ MANUAL — %s\033[0m\n' "$*"; }

# Either run a command, or just print it — depending on $APPLY.
#
# The exit status is REPORTED but not judged: what these commands mean is what
# the operator reads in their output, and there is no assertion here to hang a
# failure on. A non-zero status at least stops looking like success.
#
# `|| rc=$?` and not a bare `eval`: this file runs under `set -e` (line 45), so
# an unguarded `eval` would abort the whole runbook on the first non-zero step
# and never reach the warning below — the opposite of what a procedure someone
# is following by hand should do.
run() {
  if [[ "$APPLY" == true ]]; then
    log "$ $*"
    local rc=0
    eval "$@" || rc=$?
    (( rc != 0 )) && warn "^ exited $rc — read the output above before continuing"
    return 0
  else
    printf '\033[90m  (dry-run) $ %s\033[0m\n' "$*"
  fi
}

require_account() {
  if [[ -z "${1:-}" ]]; then
    fail "$2 not set. Export it before running this scenario."
  fi
}

# ─── Scenario 1: happy path ────────────────────────────────────────

scenario_happy() {
  log "Scenario 1: happy path — init-vault → verify → wallet API"
  require_account "$CUSTOMER_A" "CUSTOMER_A"

  log "1.1: pre-flight — confirm $CUSTOMER_A has no existing vault"
  run "outlayer vault verify vault.$CUSTOMER_A || true"

  log "1.2: deploy a fresh vault (default 24h exit window)"
  # Reuse what is already there, the way `unified_vault_e2e.sh` does.
  #
  # `vault init` refuses outright when the account exists, so on any environment
  # where this suite has run before, every scenario below died at step 1.2 —
  # and the failure read as a broken deploy rather than as a vault that was
  # already deployed. `vault resume` is idempotent and is what the CLI's own
  # error message recommends.
  if account_exists "vault.$CUSTOMER_A" 2>/dev/null; then
    warn "vault.$CUSTOMER_A already on chain — reusing it (running vault resume idempotently)"
    run "outlayer vault resume vault.$CUSTOMER_A || true"
  else
    run "outlayer vault init"
  fi

  log "1.3: status — vault should be verified, locked, no recovery"
  run "outlayer vault status vault.$CUSTOMER_A"

  log "1.4: verify — runs full 5-check defense-in-depth"
  run "outlayer vault verify vault.$CUSTOMER_A"

  log "1.5: derive a wallet address using the vault-bound API key"
  warn "Use the API key returned by step 1.2 (look for 'wk_...' in the output)."
  warn "Replace WK_A below with the actual key, then export OUTLAYER_WALLET_KEY."
  run "curl -s -H 'Authorization: Bearer \$OUTLAYER_WALLET_KEY' '$COORDINATOR_URL/wallet/v1/address?chain=near'"

  log "1.6: round-trip — sign a NEP-413 message via the vault wallet"
  run "outlayer checks sign-message --api-key \$OUTLAYER_WALLET_KEY 'hello vault' 'verifier.testnet' --nonce \$(openssl rand -base64 32)"

  manual "Scenario 1: confirm the address derives from the PER-VAULT master, not the OutLayer default one. Automated equivalent: unified_vault_e2e.sh V1/V2."
}

# ─── Scenario 5: multi-customer isolation ──────────────────────────

scenario_isolation() {
  log "Scenario 5: multi-customer isolation"
  require_account "$CUSTOMER_A" "CUSTOMER_A"
  require_account "$CUSTOMER_B" "CUSTOMER_B"

  log "5.1: customer A deploys vault.A and gets API key WK_A"
  warn "Re-run scenario_happy as $CUSTOMER_A first if not done. Capture WK_A."

  log "5.2: customer B (different NEAR account) deploys vault.B"
  warn "Re-login as $CUSTOMER_B then run: outlayer vault init"
  warn "Capture WK_B."

  log "5.3: with WK_A, derive an address — record A_ADDR"
  run "curl -s -H 'Authorization: Bearer \$WK_A' '$COORDINATOR_URL/wallet/v1/address?chain=near'"

  log "5.4: with WK_B, derive an address — record B_ADDR"
  run "curl -s -H 'Authorization: Bearer \$WK_B' '$COORDINATOR_URL/wallet/v1/address?chain=near'"

  log "5.5: assert A_ADDR != B_ADDR (they MUST differ — different per-vault masters)"
  warn "Manual check: addresses must be different despite identical wallet_id namespaces."

  log "5.6: client-supplied X-Customer-Vault header is IGNORED — coordinator binds vault to API key"
  run "curl -s -i -H 'Authorization: Bearer \$WK_A' -H 'X-Customer-Vault: vault.$CUSTOMER_B' '$COORDINATOR_URL/wallet/v1/address?chain=near'"
  warn "Expected: 200 OK with A_ADDR — coordinator derives vault_id from the API-key binding (DB), \
NOT from the request header. The cross-vault header is silently ignored. The auth gate IS the API key, \
not the X-Customer-Vault header — confirm this by checking the response equals 5.3's A_ADDR."

  manual "Scenario 5: compare 5.6's response against 5.3's A_ADDR yourself. This claim IS automated — unified_vault_e2e.sh V1 asserts distinct addresses, distinct signing keys, and the ignored header."
}

# ─── Scenario 6: backward compat ───────────────────────────────────

scenario_compat() {
  log "Scenario 6: backward compat — existing default-master API keys still work"
  require_account "$CUSTOMER_A" "CUSTOMER_A"

  log "6.1: register a wallet WITHOUT vault scope (legacy random-wallet path)"
  # Empty body / `{}` is the LEGITIMATE legacy random-wallet shape: the
  # coordinator's /register handler treats an empty body as the
  # random-wallet branch (no NEAR signature, no vault). Deterministic
  # wallets need all 5 fields (account_id, seed, pubkey, message,
  # signature) — covered separately. See `wallet/types.rs::RegisterRequest`.
  run "curl -s -X POST '$COORDINATOR_URL/register' -H 'Content-Type: application/json' -d '{}'"
  warn "Capture wk_legacy from the response."

  log "6.2: derive an address using the legacy API key — should succeed without X-Customer-Vault"
  run "curl -s -H 'Authorization: Bearer \$WK_LEGACY' '$COORDINATOR_URL/wallet/v1/address?chain=near'"

  log "6.3: confirm the address is derived from the OutLayer default master (NOT a per-vault one)"
  warn "Manual check: the address should match what a Phase 4-pre-vault keystore returned for the same wallet_id."

  manual "Scenario 6: confirm from the output above that the legacy path still works."
}

# ─── Scenarios that require manual / governance work ───────────────

scenario_manual_notes() {
  cat <<'EOF'

╔══════════════════════════════════════════════════════════════════╗
║  Manual scenarios — cannot be automated from this script         ║
╚══════════════════════════════════════════════════════════════════╝

S2 — Code update simulation
   1. Build a v2 keystore-worker binary.
   2. Operator's submitter account calls keystore-DAO
      `submit_keystore_registration(public_key, tdx_quote_hex, app_id)`
      with the v2 attestation.
   3. DAO members vote `vote(proposal_id, true)` until the threshold
      passes.
   4. For each existing vault: `outlayer vault status <account>` then
      anyone calls `propose_tee_key` on the vault with the v2 pubkey.
   5. The vault contract verifies the new key against
      `is_keystore_approved` and adds it as a function-call key.
   6. `outlayer vault verify <account>` should pass with both the v1
      and v2 TEE keys present in the access-key list.

S3 — Recovery happy path (cessation)
   1. DAO members call `keystore-dao.declare_cessation()`.
   2. Anyone calls `outlayer vault initiate-recovery <account>` —
      vault contract re-checks `is_ceased() == true` via callback.
   3. Wait 7 days (or build the contract with the `test-timing`
      feature for a 30-second collapsed window in test environments).
   4. `outlayer vault finalize-recovery <account>` flips
      `unlocked = true`.
   5. `outlayer vault unlocked-add-key <account> <pubkey>` to install
      a parent-controlled key. Funds + per-customer master are now
      under the customer's direct control.

S4 — Recovery cancelled
   1. DAO declares cessation, customer initiates recovery.
   2. During the 7-day window, DAO calls `revoke_cessation()`.
   3. Customer calls `finalize-recovery` — the contract callback
      re-checks `is_ceased()`, sees false, and resets the recovery
      state without unlocking the vault.
   4. Verify: `outlayer vault status` shows `recovery: none, unlocked:
      false`.
   5. To re-attempt: DAO must `declare_cessation` again before
      `initiate-recovery` is allowed.

S7 — Alpha tester onboarding
   1. Walk one trusted user through:
      a. `outlayer login`
      b. `outlayer vault init`  (capture the API key prompt)
      c. Use the API key to derive an address + sign a transaction
      d. `outlayer vault verify` to read the on-chain trust signal
      e. `outlayer vault initiate-unilateral-recovery` (do NOT
         finalize — this just exercises the timer)
   2. Collect feedback on:
      - "Save the API key" prompt clarity
      - Vault-account name validation messages
      - Wallet popup confusion when signing a 5-action atomic deploy
      - Resume command discoverability after a simulated failure

EOF
}

# ─── Driver ─────────────────────────────────────────────────────────

usage() {
  cat <<EOF
Usage: $0 [scenario] [--apply]

Scenarios:
  happy       — Scenario 1 (init + verify + wallet API)
  isolation   — Scenario 5 (multi-customer isolation)
  compat      — Scenario 6 (default-master backward compat)
  manual      — Print manual procedure for scenarios 2, 3, 4, 7
  all         — Run happy, isolation, compat, then print manual notes

Flags:
  --apply     — Execute commands. Without this flag the script prints
                what it WOULD run (dry-run) for review.

Env vars:
  NETWORK         (default: testnet)
  COORDINATOR_URL (default: http://localhost:8080)
  CUSTOMER_A      NEAR account currently logged in via outlayer login
  CUSTOMER_B      Second NEAR account for isolation scenario
EOF
}

case "$SCENARIO" in
  happy)     scenario_happy ;;
  isolation) scenario_isolation ;;
  compat)    scenario_compat ;;
  manual)    scenario_manual_notes ;;
  all)
    scenario_happy
    scenario_isolation
    scenario_compat
    scenario_manual_notes
    ;;
  -h|--help|help) usage; exit 0 ;;
  *) usage; exit 1 ;;
esac
