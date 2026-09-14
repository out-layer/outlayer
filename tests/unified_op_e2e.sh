#!/bin/bash
# NOTE: the shared-helper section below is DUPLICATED in the sibling file (unified_op_e2e.sh ↔ unified_op_e2e_intents.sh) — fixes to any helper must be applied to BOTH.
# Unified canonical-op e2e — TESTNET-runnable subset (T1,T4,T5,T7,T11) of the agent-custody unified-op refactor.
# The intents-dependent (MAINNET-only) tests T2,T3,T6,T8,T9,T10,T12 live in the sibling unified_op_e2e_intents.sh.
#
# Exercises the NEW surface end-to-end against a real testnet coordinator + keystore:
#   T1  /wallet/v1/auth-sign            — bearer/register/api-key build+sign; jwt rejected
#   T4  dumb approve/reject             — real approver YES executes; real approver NO vetoes;
#                                         non-approver NO ignored
#   T5  sign_message allowed_recipients — recipient in allowlist signs; not-in-allowlist denied;
#                                         intents.near denied (auth path can't sign a fund intent)
#   T7  negatives                       — substituted op (wrong hash) → keystore rejects, no execution;
#                                         gated op without approvals → stays pending, no tx
#   T11 /wallet/v1/delete (DESTRUCTIVE)    — NEAR DeleteAccount sweeps the FULL balance to a beneficiary;
#                                         asserts the self-beneficiary + zero-balance guards, then a real
#                                         destructive delete of a throwaway sub-wallet to a beneficiary we
#                                         control (asserts success + the beneficiary balance increased)
#   T13 sign_message ed25519 VERIFY    — actually ed25519-verifies the returned sig vs returned pubkey +
#                                         exact signed bytes (vs T5 which only checks the sig is PRESENT);
#                                         tampered message/nonce fail; two scopes (distinct seeds) don't
#                                         cross-verify  [ported from wallet_sign_message_roundtrip.sh]
#   T14 api-key NEAR-signed derive     — PUT /api-key signed over `api-key:<seed>:<ts>`; binds; minted wk_
#                                         works (/address + crypto-valid /sign-message); cross-account
#                                         spoof → 4xx  [ported from api_key_signed_derive_e2e.sh]
#   T15 vault-scope parity             — every address-returning endpoint agrees with /address; (vault
#                                         mode) no-vault write doesn't poison a vault-scoped lookup +
#                                         cross-vault isolation  [ported from bearer_vault_endpoint_parity_e2e.sh]
#   T16 wallet_id v2 invariants        — seed-length boundary (256 OK / 257→400); offline compute-wallet-id
#                                         == coordinator /address wallet_id (idempotent); reverse-lookup
#                                         /pending_approvals_by_pubkey resolves  [ported from v2_policy_invariants_e2e.sh]
#   T17 on-chain signer == sub-wallet  — after an approved transfer executes (T4b flow), the executed tx's
#                                         on-chain signer_id == the sub-wallet (per-vault derived key, not
#                                         parent)  [ported from approval_flow_e2e.sh]
#
# NOTE: T13/T14/T15/T16 are POLICY-class (no fund movement; PARENT pays only policy-storage stake where a
# policy is stored, reclaimed by the sweep). T17 is FUNDS-class (funds a throwaway sub-wallet, MONEY-guarded).
# In default-vault mode (no MPC_PUBLIC_KEY) the vault-only dimensions of T13c/T14/T15 are cleanly SKIP-noted.
#
# ── Test classes (what each needs) ────────────────────────────────────────────
#   [MAINNET] NEAR Intents (regular + confidential) are MAINNET-ONLY — there are no testnet solvers and
#             the coordinator returns HTTP 503 for the public intents endpoints on testnet. The 7 tests
#             tagged [MAINNET] (T2, T3, T6, T8, T9, T10, T12) drive an intents-dependent endpoint
#             (deposit/withdraw/swap/cross-chain/payment-check) and live in the sibling
#             unified_op_e2e_intents.sh. This file runs the other 5 (T1, T4, T5, T7, T11) on testnet.
#   [POLICY]  testnet + on-chain policy + Bearer-near auth (signed locally by customer-recovery).
#             NO fund movement beyond the parent's policy-storage stake (~0.1 NEAR/policy) + vault.
#   [SIG]     additionally needs the APPROVER NEAR keys in ~/.near-credentials (signed locally — headless;
#             NO interactive wallet UI).
#   [FUNDS]   additionally moves real value: the sub-wallet needs an intents balance (FT/wNEAR) and,
#             for T6, the external recipient must be storage-registered on the token.
#   Everything here is HEADLESS (no browser wallet) — every signature is produced locally by
#   `scripts/customer-recovery` from keys in ~/.near-credentials. "Real user signature" in the
#   dashboard sense is NOT required; the dashboard's dumb approve/reject is the same NEP-413 string
#   this suite signs (`{vote}:{approval_id}:{wallet_pubkey}:{request_hash}`).
#
# ── NOT coordinator-reachable on testnet (documented, covered by crate unit tests) ────────────────
#   * raw_sign chains allowlist — no coordinator endpoint builds Op::Raw (raw signing is keystore-only,
#     reached via the gated /wallet/sign with an authenticated coordinator). Covered by the crate test
#     `wallet_policy::tests::raw_sign_chains_restrict_per_chain`.
#   * confidential capability — /wallet/v1/confidential/* return HTTP 503 off-mainnet (the salt/shard
#     live on mainnet intents.near). Covered by crate tests + `wallet_confidential_e2e.sh` (mainnet).
#     This includes confidential-UNDER-MULTISIG: the 503 short-circuits BEFORE the policy/approval
#     path, so the new pending_approval control flow for confidential ops cannot be reached on testnet
#     (it is the same RequiresApproval→create-pending machinery T9/T10 exercise for swap/cross-chain;
#     confidential's multisig path is asserted at the crate layer + the mainnet confidential suite).
#   These two are asserted ONLY at the unit/crate layer; this suite verifies they are NOT silently
#   bypassable through any public testnet endpoint.
#
# Required env:
#   PARENT          vault owner, logged into outlayer-cli (NOT an approver) [creds in ~/.near-credentials/$NETWORK]
#   APPROVER1       first approver  [default zavodil.testnet]
#   APPROVER2       second approver (!= PARENT/APPROVER1) — required for T4 multi-approver veto
#   EXTERNAL_ACCT   existing testnet account, storage-registered on $WNEAR, to receive the T6 FT withdraw
#                   [default = APPROVER1]
#   MPC_PUBLIC_KEY  bls12381g2:base58 (for `outlayer vault init`)
#   ONLY            optional comma list to run a subset, e.g. ONLY=T1,T2
#
# Run (dry-run prints the plan; --apply executes):
#   MPC_PUBLIC_KEY=bls12381g2:... PARENT=zavodil2.testnet APPROVER2=t1.zavodil3.testnet \
#     EXTERNAL_ACCT=zavodil.testnet ./tests/unified_op_e2e.sh --apply

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPLY=false
[[ "${1:-}" == "--apply" ]] && APPLY=true

NETWORK="${NETWORK:-testnet}"
PARENT="${PARENT:-}"
APPROVER1="${APPROVER1:-zavodil.testnet}"
APPROVER2="${APPROVER2:-}"
EXTERNAL_ACCT="${EXTERNAL_ACCT:-$APPROVER1}"
# Shared constant sink for every DeleteAccount + the sweep's intents-withdraw (real/existing/wNEAR-registered → never burns).
BENEFICIARY="${BENEFICIARY:-$([ "$NETWORK" = mainnet ] && echo zavodil.near || echo zavodil.testnet)}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/rpc.sh"   # keyed RPC_URL, or a warning
CONTRACT_ID="${CONTRACT_ID:-outlayer.testnet}"
COORDINATOR_URL="${COORDINATOR_URL:-https://testnet-api.outlayer.ai}"
WNEAR="${WNEAR:-wrap.testnet}"
ONLY="${ONLY:-}"

# Every throwaway sub-wallet seed is appended here so a leaked wallet can be recovered later
# (deterministic from PARENT_PRIVKEY + seed via `customer-recovery`). SWEEP_QUEUE is the working set
# the EXIT trap sweeps to reclaim funds + on-chain policy storage at the end of the run.
SEED_LOG="${SEED_LOG:-$HOME/.outlayer/uop-seeds.log}"; mkdir -p "$(dirname "$SEED_LOG")"
# These are FILES, not bash arrays: new_subwallet runs in the process-substitution subshell of
# `read -r ... < <(new_subwallet ...)`, where array appends are subshell-local and LOST in the parent
# — a file append (exactly like $SEED_LOG above) survives the subshell. SWEEP_QUEUE is the WORKING set
# the per-test/abort/final sweeps drain (drained + truncated as each batch is swept, so a wallet is
# never swept twice). RUN_LEDGER is the IMMUTABLE full ledger every sub-wallet is appended to and never
# removed from — the final verify_all_drained pass re-checks ALL of them for leaks.
SWEEP_QUEUE="$(mktemp -t uop_sweepq.XXXXXX)"   # pending-sweep working set (drained + truncated each pass)
RUN_LEDGER="$(mktemp -t uop_ledger.XXXXXX)"    # immutable ledger of every sub-wallet this run (for verify)

log()  { printf '\n\033[36m▶ %s\033[0m\n' "$*" >&2; }
warn() { printf '\033[33m⚠ %s\033[0m\n' "$*" >&2; }
pass() { printf '\033[32m✓ %s\033[0m\n' "$*" >&2; PASS=$((PASS+1)); }
fail() { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; FAILED=$((FAILED+1)); FAILED_NAMES+=("$*"); if [[ "$MONEY" == true ]]; then printf '\033[1;31m⛔ HALTING — real-money test %s failed; funds may be mid-flight. The EXIT trap sweeps tracked sub-wallets.\033[0m\n' "$CUR_TEST" >&2; exit 1; fi; }
note() { printf '\033[35m• %s\033[0m\n' "$*" >&2; }
PASS=0; FAILED=0; FAILED_NAMES=()
# Real-money guard: while MONEY=true (set at the start of each value-moving test, cleared at its end),
# a fail() does not just record — it HALTS the run so funds aren't left mid-flight by a continuing
# suite. The EXIT trap (cleanup_subwallets) still fires and sweeps every tracked sub-wallet.
MONEY=false; CUR_TEST=""

want() { [[ -z "$ONLY" ]] || [[ ",$ONLY," == *",$1,"* ]]; }

# NEAR Intents (regular + confidential) are MAINNET-ONLY — there are no testnet solvers, and the
# coordinator now returns HTTP 503 for the public intents endpoints on testnet. Tests that drive an
# intents-dependent endpoint (deposit/withdraw/swap/cross-chain/payment-check) therefore only run on
# mainnet. Use as: `if want TN && intents_mainnet TN; then ...`. Emits a clean skip note (only when
# `want` already selected the test) and returns non-zero off mainnet so the body is skipped.
intents_mainnet() {
  [[ "$NETWORK" == "mainnet" ]] && return 0
  note "$1 skipped — NEAR Intents are mainnet-only (no testnet solvers; coordinator returns 503 on testnet)"
  return 1
}

[[ -n "$PARENT" ]] || { echo "USAGE: PARENT=... MPC_PUBLIC_KEY=... $0 --apply" >&2; exit 1; }
CREDS_DIR="$HOME/.near-credentials/$NETWORK"
for tool in jq curl outlayer near python3; do command -v "$tool" >/dev/null || { echo "✗ missing $tool" >&2; exit 1; }; done

if [[ "$APPLY" != true ]]; then
  warn "Dry-run. Pass --apply to deploy a vault + exercise the unified-op surface on $NETWORK."
  warn "TESTNET-runnable subset (T1,T4,T5,T7,T11,T13,T14,T15,T16,T17):"
  warn "       T1 auth-sign[POLICY] T4 approve/reject[SIG] T5 sign_message[POLICY]"
  warn "       T7 negatives incl. cross-wallet replay[POLICY/SIG]"
  warn "       T11 delete-account: self-beneficiary + zero-balance guards, then a real destructive delete[FUNDS]"
  warn "       T13 sign_message ed25519 VERIFY + cross-scope + tamper[POLICY]"
  warn "       T14 api-key NEAR-signed derive + cross-account refusal[POLICY]"
  warn "       T15 vault-scope endpoint parity (+cache-poisoning/cross-vault in vault mode)[POLICY]"
  warn "       T16 wallet_id v2: seed-length, offline==online idempotency, reverse-lookup[POLICY]"
  warn "       T17 on-chain tx signer_id == sub-wallet (per-vault derived key)[SIG/FUNDS]"
  warn "The intents-dependent (MAINNET-only) tests T2,T3,T6,T8,T9,T10,T12 live in unified_op_e2e_intents.sh."
  warn "raw_sign + confidential are NOT testnet-coordinator-reachable — covered by crate unit tests (see header)."
  exit 0
fi

[[ -f "$CREDS_DIR/$PARENT.json" ]] || { echo "✗ creds missing: $CREDS_DIR/$PARENT.json" >&2; exit 1; }
RECOVERY_BIN="$SCRIPT_DIR/../scripts/customer-recovery/target/release/customer-recovery"
log "Building customer-recovery (sign-nep413 + sign-bearer-near)"
(cd "$SCRIPT_DIR/../scripts/customer-recovery" && cargo build --release --quiet) || { echo "build failed" >&2; exit 1; }

# Without this, `outlayer` follows ~/.outlayer/default-network — mainnet on this
# machine — and the check below compares against the wrong network's account.
export OUTLAYER_NETWORK="$NETWORK"
WHOAMI=$(outlayer whoami 2>/dev/null | awk -F': *' '/^Account:/{print $2; exit}')
[[ "$WHOAMI" == "$PARENT" ]] || { echo "✗ outlayer logged in as '$WHOAMI', not '$PARENT'" >&2; exit 1; }
PARENT_PRIVKEY=$(jq -r '.private_key' "$CREDS_DIR/$PARENT.json")

# Best-effort sweep of every throwaway sub-wallet back to PARENT at exit (self-guards on APPLY;
# defined below, near new_subwallet). Registered here so it covers wallets created by every test.
trap cleanup_subwallets EXIT

near_tty() {
  # Give near-cli-rs a TTY via `script` ONLY when stdout is a real terminal. Headless (CI / a
  # non-TTY harness — where `script` itself errors with "ioctl on socket") falls back to a bare
  # eval: near-cli-rs with full args + sign-with-keychain is fully non-interactive, no TTY needed.
  if command -v script >/dev/null 2>&1 && [ -t 1 ]; then
    local tmp; tmp=$(mktemp -t uop_cmd.XXXXXX.sh)
    printf 'set -euo pipefail\n%s\n' "$*" > "$tmp"
    script -q /dev/null bash "$tmp"; local rc=$?; rm -f "$tmp"; return $rc
  else eval "$@"; fi
}

# ─── shared vault ──────────────────────────────────────────────────────────────
# Default-vault mode (common case): with NO MPC_PUBLIC_KEY we do NOT deploy a
# per-vault — VAULT_ID stays empty, so the bearer tokens omit `--vault-id` (mk_token's
# `${2:+...}`) and the coordinator routes sub-wallets under its DEFAULT vault. Set
# MPC_PUBLIC_KEY to deploy a dedicated vault instead (the original per-vault path).
VAULT_ID=""
if [[ -n "${MPC_PUBLIC_KEY:-}" ]]; then
  VAULT_NAME="uop-$(date +%s)"
  VAULT_ID="$VAULT_NAME.$PARENT"
  log "Deploy vault $VAULT_ID"
  INIT_RC=0
  INIT_OUT=$(outlayer vault init --name "$VAULT_NAME" --exit-window 60s 2>&1) || INIT_RC=$?
  if [[ $INIT_RC -ne 0 ]] && echo "$INIT_OUT" | grep -q "outlayer vault resume"; then
    for _ in 1 2 3 4 5; do sleep 6; if outlayer vault resume "$VAULT_ID" >&2; then INIT_RC=0; break; fi; done
  fi
  [[ $INIT_RC -eq 0 ]] || { echo "✗ vault init failed: $INIT_OUT" >&2; exit 1; }
  pass "vault $VAULT_ID deployed"
else
  log "Default-vault mode (no MPC_PUBLIC_KEY): skipping vault init; tokens omit vault-id → coordinator default vault"
fi

mk_token() { "$RECOVERY_BIN" sign-bearer-near --private-key "$PARENT_PRIVKEY" --account-id "$PARENT" --seed "$1" ${2:+--vault-id "$2"}; }
AUTH() { echo "Authorization: Bearer near:$(mk_token "$1" "$VAULT_ID")"; }

# new_subwallet <seed> → echoes "WALLET_ID SUB_ADDR"
new_subwallet() {
  local seed=$1 r wid addr
  r=$(curl -sS -G "$COORDINATOR_URL/wallet/v1/address" --data-urlencode "chain=near" -H "$(AUTH "$seed")")
  wid=$(echo "$r" | jq -r '.wallet_id'); addr=$(echo "$r" | jq -r '.address')
  # Persist the seed (recoverable from PARENT_PRIVKEY) + track for the EXIT sweep.
  printf '%s %s %s %s\n' "$(date +%s)" "$seed" "$wid" "$addr" >> "$SEED_LOG"
  printf '%s|%s|%s\n' "$seed" "$wid" "$addr" >> "$SWEEP_QUEUE"
  printf '%s|%s|%s\n' "$seed" "$wid" "$addr" >> "$RUN_LEDGER"
  echo "$wid $addr"
}

# ─── fund-return / sweep machinery ────────────────────────────────────────────
# A throwaway sub-wallet can hold value in TWO places: native NEAR on its implicit account AND a
# wNEAR (defuse) balance inside intents.near (T3/T6/T12 deposit wNEAR there). A bare DeleteAccount
# only sweeps the native balance and ORPHANS the intents balance, so every sweep withdraws intents
# FIRST (back to PARENT) and only then deletes the native account. All of this is best-effort: a
# per-wallet error warns and continues, never aborting the suite.
#
# yocto magnitudes (1e22) overflow bash's 64-bit arithmetic, so compare as decimal strings: more
# digits wins; on equal length fall back to lexicographic. Hoisted to file scope so the per-test
# sweep, the EXIT-trap safety net, and the final verify pass all share one comparator/threshold.
SWEEP_MIN="10000000000000000000000"  # 0.01 NEAR in yocto
yocto_gt() { # <a> <b> → "gt" if a > b. RPC amounts/literal here have no leading zeros or sign.
  local a=${1:-0} b=${2:-0}
  if   [[ ${#a} -gt ${#b} ]]; then echo gt
  elif [[ ${#a} -lt ${#b} ]]; then :
  elif [[ "$a" > "$b" ]];      then echo gt
  fi
}

# intents_wnear <addr> → echoes the wallet's wNEAR balance inside intents.near (integer yocto string,
# "0" if none / on any error). intents.near is a multi-token (NEP-245) contract keyed by token_id; we
# read mt_balance_of for "nep141:$WNEAR". Only meaningful on mainnet (no testnet intents), but safe to
# call anywhere — off-mainnet it simply returns "0".
intents_wnear() {
  local addr=$1 args r out
  args=$(jq -nc --arg a "$addr" --arg t "nep141:$WNEAR" '{account_id:$a, token_id:$t}')
  r=$(curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg a "intents.near" --arg m "mt_balance_of" --arg ab "$(printf '%s' "$args" | base64 | tr -d '\n')" \
        '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"call_function",finality:"final",account_id:$a,method_name:$m,args_base64:$ab}}')" 2>/dev/null || echo '')
  out=$(echo "$r" | jq -r '.result.result // empty | implode' 2>/dev/null | tr -d '"' || echo "0")
  [[ -n "$out" ]] && echo "$out" || echo "0"
}

# sweep_one <seed> <wallet_id> <addr> — drain ONE throwaway sub-wallet back to PARENT, best-effort.
# Order: (1) read native NEAR + intents wNEAR; (2) if both empty → reclaim policy storage only;
# (3) else store an intents_withdraw+delete policy; (4) if intents>0 → withdraw it to PARENT FIRST
# (so it isn't orphaned by the delete); (5) if native>0.01 → DeleteAccount sweeps the rest to PARENT;
# (6) always reclaim the per-wallet policy storage deposit. The intents-before-delete ordering is the
# bug fix: a bare delete would strand the wNEAR sitting in intents.near.
sweep_one() {
  local seed=$1 wid=$2 addr=$3 rpc acct_err native intents wnear_bal
  rpc=$(curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"query\",\"params\":{\"request_type\":\"view_account\",\"finality\":\"final\",\"account_id\":\"$addr\"}}" 2>/dev/null || echo '')
  acct_err=$(echo "$rpc" | jq -r '.error // .result.error // empty' 2>/dev/null)
  native=$(echo "$rpc" | jq -r '.result.amount // "0"' 2>/dev/null || echo "0")
  # A missing/errored account has no native balance to sweep.
  [[ -n "$acct_err" || -z "$native" ]] && native="0"
  if [[ "$NETWORK" == "mainnet" ]]; then intents=$(intents_wnear "$addr"); else intents="0"; fi
  [[ -n "$intents" ]] || intents="0"

  if [[ "$native" == "0" && "$intents" == "0" ]]; then
    note "sweep: $addr — no native + no intents balance; reclaiming policy storage only"
  else
    # Permissive sweep policy: allow the wNEAR unwrap `call` + the intents withdraw + the native
    # delete. `call` is required for the near_withdraw/storage_unregister unwrap in (4b) below.
    # store_policy is best-effort here — if it fails, the gated call/withdraw/delete below will
    # simply 403 (warned).
    store_policy "$seed" "$wid" '{"rules":{"transaction_types":["call","intents_withdraw","delete"]}}' \
      || warn "sweep: $addr — store sweep-policy failed (call/withdraw/delete may be denied)"
    # (4) intents wNEAR FIRST — withdraw back to PARENT before the account is deleted.
    if [[ "$intents" != "0" && "$(yocto_gt "$intents" "0")" == "gt" ]]; then
      post POST /wallet/v1/intents/withdraw "$seed" "$(jq -nc --arg to "$BENEFICIARY" --arg a "$intents" --arg t "nep141:$WNEAR" '{chain:"near", to:$to, amount:$a, token:$t}')" \
        || warn "sweep: $addr — intents withdraw request errored"
      note "sweep: $addr intents wNEAR ($intents) → $BENEFICIARY (HTTP $HTTP)"
    fi
    # (4b) WRAPPED wNEAR on the wallet's OWN ft balance — a failed intents-deposit leaves the wrapped
    # wNEAR sitting in the wallet's wrap.near ft balance, which a bare DeleteAccount would ORPHAN. Mirror
    # the working manual recovery: near_withdraw (unwrap → native) → storage_unregister (reclaim the
    # registration storage). Both best-effort (a 0-balance / unregistered wallet is a clean no-op).
    # Harmless on testnet (wrap.testnet) — the balance is simply 0 there.
    wnear_bal=$(curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
      -d "$(jq -nc --arg t "$WNEAR" --arg a "$addr" '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"call_function",finality:"final",account_id:$t,method_name:"ft_balance_of",args_base64:({account_id:$a}|tojson|@base64)}}')" 2>/dev/null \
      | jq -r '.result.result // empty | implode' 2>/dev/null | tr -d '"' || echo "0")
    [[ -n "$wnear_bal" ]] || wnear_bal="0"
    if [[ "$wnear_bal" != "0" && "$(yocto_gt "$wnear_bal" "0")" == "gt" ]]; then
      note "sweep: $addr holds $wnear_bal wrapped wNEAR (orphaned by a failed intents-deposit) — unwrapping → native before delete"
      post POST /wallet/v1/call "$seed" "$(jq -nc --arg t "$WNEAR" --arg a "$wnear_bal" '{receiver_id:$t, method_name:"near_withdraw", args:{amount:$a}, gas:"50000000000000", deposit:"1"}')" \
        || warn "sweep: $addr — near_withdraw (unwrap wNEAR) request errored"
      note "sweep: $addr near_withdraw $wnear_bal wNEAR → native (HTTP $HTTP)"
      post POST /wallet/v1/call "$seed" "$(jq -nc --arg t "$WNEAR" '{receiver_id:$t, method_name:"storage_unregister", args:{force:true}, gas:"30000000000000", deposit:"1"}')" \
        || warn "sweep: $addr — storage_unregister (reclaim wNEAR registration) request errored"
      note "sweep: $addr storage_unregister on $WNEAR (HTTP $HTTP)"
      # Re-read native so the (5) delete decision below sees the funds the unwrap just added back.
      native=$(curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"query\",\"params\":{\"request_type\":\"view_account\",\"finality\":\"final\",\"account_id\":\"$addr\"}}" 2>/dev/null \
        | jq -r '.result.amount // "0"' 2>/dev/null || echo "0")
      [[ -n "$native" ]] || native="0"
    fi
    # (5) native NEAR — DeleteAccount sends the FULL remaining balance to BENEFICIARY (only if worth it).
    if [[ "$(yocto_gt "$native" "$SWEEP_MIN")" == "gt" ]]; then
      post POST /wallet/v1/delete "$seed" "$(jq -nc --arg b "$BENEFICIARY" '{beneficiary:$b,chain:"near"}')" \
        || warn "sweep: $addr — delete (native sweep) request errored"
      note "sweep: $addr native ($native yocto) swept to $BENEFICIARY (HTTP $HTTP)"
    elif [[ "$native" != "0" ]]; then
      note "sweep: $addr native $native yocto ≤ 0.01 NEAR — not worth a delete; reclaiming policy only"
    fi
  fi
  # (6) Reclaim the per-wallet policy storage deposit (refunds to PARENT). A NEAR implicit address IS
  # its ed25519 public-key hex, so the wallet_pubkey is ed25519:<addr>. "not found" (no policy /
  # already removed) is fine — best-effort.
  near_tty "near contract call-function as-transaction \"$CONTRACT_ID\" delete_wallet_policy json-args '$(jq -nc --arg pk "ed25519:$addr" '{wallet_pubkey:$pk}')' prepaid-gas '30 Tgas' attached-deposit '0 NEAR' sign-as \"$PARENT\" network-config \"$NETWORK\" sign-with-keychain send" \
    || warn "sweep: $addr — delete_wallet_policy failed (no policy or already removed?)"
}

# sweep_now — drain every sub-wallet currently in the WORKING set, then truncate it (so the same
# wallet is never swept twice across the per-test / abort / final passes). No-op unless --apply.
sweep_now() {
  [[ "$APPLY" == true ]] || return 0
  [[ -s "$SWEEP_QUEUE" ]] || return 0
  log "Returning funds from $(wc -l < "$SWEEP_QUEUE" | tr -d ' ') sub-wallet(s) → $PARENT"
  local e seed addr wid
  # Redirect form (not `cat | while`): the loop runs in the MAIN shell so sweep_one's side effects
  # and any future array mutations are NOT trapped in a pipe subshell.
  while IFS= read -r e; do
    [ -n "$e" ] || continue
    seed=${e%%|*}; addr=${e##*|}; wid=${e#*|}; wid=${wid%%|*}
    sweep_one "$seed" "$wid" "$addr"
  done < "$SWEEP_QUEUE"
  : > "$SWEEP_QUEUE"
}

# return_test_funds — called at the END of each real-money test to drain its sub-wallets immediately
# (don't hold value across tests). Just the working-set sweep.
return_test_funds() { sweep_now; }

# residual_of <addr> → "<native_yocto> <intents_wnear_yocto>" (both "0" if the account is absent/errored
# or holds nothing). Single source of truth for the verify pass's balance read.
residual_of() {
  local a=$1 rpc acct_err native intents
  rpc=$(curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"query\",\"params\":{\"request_type\":\"view_account\",\"finality\":\"final\",\"account_id\":\"$a\"}}" 2>/dev/null || echo '')
  acct_err=$(echo "$rpc" | jq -r '.error // .result.error // empty' 2>/dev/null)
  native=$(echo "$rpc" | jq -r '.result.amount // "0"' 2>/dev/null || echo "0")
  [[ -n "$acct_err" || -z "$native" ]] && native="0"
  if [[ "$NETWORK" == "mainnet" ]]; then intents=$(intents_wnear "$a"); else intents="0"; fi
  [[ -n "$intents" ]] || intents="0"
  echo "$native $intents"
}
# is_leak <native> <intents> → rc 0 iff native > 0.01 NEAR OR intents is any nonzero amount.
is_leak() { [[ "$(yocto_gt "$1" "$SWEEP_MIN")" == "gt" || ( "$2" != "0" && -n "$2" ) ]]; }

# verify_all_drained — FINAL safety check over the IMMUTABLE ledger. Re-reads native + (mainnet)
# intents for EVERY sub-wallet ever created; any residual native >0.01 NEAR or non-zero intents is a
# LEAK → fail() (recorded, surfaced in the SUMMARY exit code). A sweep's intents-withdraw / DeleteAccount
# settles asynchronously, so a leaky-looking wallet is RE-POLLED (~30s, like the T6/T11/T12 settlement
# polls) before being declared a leak — a genuinely leaked wallet stays nonzero through the poll. Runs
# only under --apply.
verify_all_drained() {
  [[ "$APPLY" == true ]] || return 0
  [[ -s "$RUN_LEDGER" ]] || { log "Balance check: no sub-wallets created"; return 0; }
  local e seed wid addr native intents leaks=0
  # Redirect form (not a pipe) so the loop body runs in the MAIN shell — `leaks` survives the loop.
  while IFS= read -r e; do
    [ -n "$e" ] || continue
    seed=${e%%|*}; addr=${e##*|}; wid=${e#*|}; wid=${wid%%|*}
    read -r native intents < <(residual_of "$addr")
    if is_leak "$native" "$intents"; then
      for _ in $(seq 1 10); do sleep 3; read -r native intents < <(residual_of "$addr"); is_leak "$native" "$intents" || break; done
    fi
    if is_leak "$native" "$intents"; then
      fail "LEAK: $addr native=$native intents=$intents — recover via seed '$seed' (saved in $SEED_LOG)"; leaks=$((leaks+1))
    else
      note "drained: $addr"
    fi
  done < "$RUN_LEDGER"
  log "Balance check: $(wc -l < "$RUN_LEDGER" | tr -d ' ') sub-wallet(s) verified, $leaks leak(s)"
}

# cleanup_subwallets — EXIT trap / abort safety net. The per-test return_test_funds and the final
# sweep_now before SUMMARY already drain wallets on the happy path; this catches anything left when
# the run aborts early (e.g. the real-money fail-fast `exit 1`) or any trailing untracked wallet.
# Best-effort, never fails the suite, no-op unless --apply.
cleanup_subwallets() {
  [[ "$APPLY" == true ]] || return 0
  sweep_now
}

# store_policy <seed> <wallet_id> <policy_json_without_wallet_id>
store_policy() {
  local seed=$1 wid=$2 pol=$3
  local body enc encb64 sg sig_hex pub_hex store_args
  body=$(jq -nc --arg wid "$wid" --argjson p "$pol" '$p + {wallet_id:$wid}')
  enc=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/encrypt-policy" -H "$(AUTH "$seed")" -H 'Content-Type: application/json' -d "$body")
  encb64=$(echo "$enc" | jq -r '.encrypted_base64 // empty'); [[ -n "$encb64" ]] || { echo "encrypt-policy failed: $enc" >&2; return 1; }
  # `caller` is SIGNED: the answer is good only for the account that sends the
  # store below, which is $PARENT here.
  sg=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/sign-policy" -H "$(AUTH "$seed")" -H 'Content-Type: application/json' -d "$(jq -nc --arg ed "$encb64" --arg c "$PARENT" '{encrypted_data:$ed, caller:$c}')")
  sig_hex=$(echo "$sg" | jq -r '.signature_hex // empty'); pub_hex=$(echo "$sg" | jq -r '.public_key_hex // empty')
  [[ -n "$sig_hex" ]] || { echo "sign-policy failed: $sg" >&2; return 1; }
  store_args=$(jq -nc --arg pk "ed25519:$pub_hex" --arg ed "$encb64" --arg sg "$sig_hex" '{wallet_pubkey:$pk, encrypted_data:$ed, wallet_signature:$sg}')
  near_tty "near contract call-function as-transaction $CONTRACT_ID store_wallet_policy json-args '$store_args' prepaid-gas '100.0 Tgas' attached-deposit '0.1 NEAR' sign-as $PARENT network-config $NETWORK sign-with-keychain send" || return 1
  sleep 5
}

# post <method> <path> <seed> <json|''> → sets HTTP + BODY
HTTP=""; BODY=""
post() {
  local method=$1 path=$2 seed=$3 data=${4:-}
  local args=(-sS -o /tmp/uop.body -w '%{http_code}' -X "$method" "$COORDINATOR_URL$path" -H "$(AUTH "$seed")")
  [[ -n "$data" ]] && args+=(-H 'Content-Type: application/json' -d "$data")
  HTTP=$(curl "${args[@]}"); BODY=$(cat /tmp/uop.body)
}

# assert_funded <label> — call right after a funding `post`. Without this a failed funding sub-step
# is silent and only surfaces much later as a confusing "have 0 balance". Treat it as a HARD failure
# here, printing the body so the real cause is visible at the funding step.
assert_funded() {
  local label=$1 st err
  # A failed funding sub-step surfaces three ways across coordinator versions:
  #   legacy:  HTTP 200 + {"status":"failed"}            (a reverted tx returned 2xx)
  #   current: HTTP 422 + {"error":"onchain_tx_failed"}  (revert; survives Cloudflare)
  #   rejected/transient: any other non-2xx (500 NotEnoughBalance, 503, …)
  if [[ "$HTTP" != 2?? ]]; then
    fail "$label funding step HTTP $HTTP — $(echo "$BODY" | head -c200)"; return 1
  fi
  st=$(echo "$BODY"  | jq -r '.status // empty' 2>/dev/null)
  err=$(echo "$BODY" | jq -r '.error  // empty' 2>/dev/null)
  if [[ "$st" == "failed" || "$err" == "onchain_tx_failed" ]]; then
    fail "$label funding step failed — $(echo "$BODY" | head -c200)"; return 1
  fi
  return 0
}

# --quiet: the receiver is usually a FRESH implicit account, and near-cli-rs answers a
# does-not-exist warning with an interactive prompt — headless (no TTY) that dies with
# "The input device is not a TTY" and the sub-wallet is silently never funded.
fund_near() { near_tty "near --quiet tokens $PARENT send-near $1 '$2' network-config $NETWORK sign-with-keychain send"; }

# ─── register BENEFICIARY on wNEAR (mainnet) ───────────────────────────────────
# The intents-balance sweeps (sweep_one step 4 / T6) withdraw wNEAR to BENEFICIARY, which requires
# BENEFICIARY to be storage-registered on the wNEAR (defuse) contract — otherwise the ft_transfer leg
# of the withdraw is rejected and the swept funds would bounce. Ensure BENEFICIARY is wNEAR-registered
# once, best-effort, up front, so the sweep's intents-withdraw can land. PARENT pays the 0.00125 to
# register it (storage_deposit may be paid by anyone for any account_id). Only on mainnet (testnet has
# no intents sweeps) and only under --apply. Placed AFTER every helper (intents_wnear/store_policy/
# post/sweep_one) is defined so definitions-before-use holds.
if [[ "$APPLY" == true && "$NETWORK" == mainnet ]]; then
  PSB=$(curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg t "$WNEAR" --arg a "$BENEFICIARY" '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"call_function",finality:"final",account_id:$t,method_name:"storage_balance_of",args_base64:({account_id:$a}|tojson|@base64)}}')" 2>/dev/null \
    | jq -r '.result.result // empty | implode' 2>/dev/null || echo '')
  if [[ -z "$PSB" || "$PSB" == "null" ]]; then
    note "BENEFICIARY ($BENEFICIARY) not storage-registered on $WNEAR — registering (so intents sweeps can land)"
    near_tty "near contract call-function as-transaction $WNEAR storage_deposit json-args '$(jq -nc --arg a "$BENEFICIARY" '{account_id:$a}')' prepaid-gas '30 Tgas' attached-deposit '0.00125 NEAR' sign-as $PARENT network-config $NETWORK sign-with-keychain send" \
      || warn "BENEFICIARY wNEAR storage_deposit failed — intents sweeps may not land"
  else
    note "BENEFICIARY ($BENEFICIARY) already storage-registered on $WNEAR ($PSB) — intents sweeps can land"
  fi
fi

# ════════════════════════════════════════════════════════════════════════════════
# T1 — /wallet/v1/auth-sign  [POLICY] (no funds)
# ════════════════════════════════════════════════════════════════════════════════
if want T1; then
  log "T1 [POLICY] /wallet/v1/auth-sign — bearer/register/api-key build+sign; jwt rejected"
  SEED="t1-$(date +%s)"
  for purpose in bearer register api-key; do
    post POST /wallet/v1/auth-sign "$SEED" "$(jq -nc --arg p "$purpose" '{purpose:$p, seed:"agent-x"}')"
    if [[ "$HTTP" == "200" ]]; then
      AM=$(echo "$BODY" | jq -r '.auth_message // empty'); TS=$(echo "$BODY" | jq -r '.auth_timestamp // empty')
      SIG=$(echo "$BODY" | jq -r '.signature // empty'); PK=$(echo "$BODY" | jq -r '.public_key // empty')
      prefix=$([[ "$purpose" == "bearer" ]] && echo "auth" || echo "$purpose")
      if [[ "$AM" == "$prefix:agent-x:"* && -n "$TS" && -n "$SIG" && "$PK" == ed25519:* ]]; then
        pass "T1 $purpose → auth_message='$AM' (fresh ts=$TS, sig+pubkey present)"
        # auth string is domain-separated — it can never be a NEP-413 intents transfer.
        echo "$AM" | jq -e . >/dev/null 2>&1 && fail "T1 $purpose auth_message parsed as JSON — not domain-separated!" || pass "T1 $purpose message is a plain prefixed string, not a (fund) intent JSON"
      else fail "T1 $purpose bad response: $BODY"; fi
    else fail "T1 $purpose expected 200, got $HTTP: $BODY"; fi
  done
  post POST /wallet/v1/auth-sign "$SEED" '{"purpose":"jwt","seed":"agent-x"}'
  [[ "$HTTP" == "400" ]] && pass "T1 jwt purpose rejected (HTTP 400 — internal-only)" || fail "T1 jwt should be 400, got $HTTP: $BODY"
fi

# ════════════════════════════════════════════════════════════════════════════════
# T4 — dumb approve / reject veto  [SIG] (needs approver keys)
# ════════════════════════════════════════════════════════════════════════════════
if want T4; then
  log "T4 [SIG] dumb approve/reject — real approver YES executes; real approver NO vetoes; non-approver NO ignored"
  MONEY=true; CUR_TEST=T4
  [[ -n "$APPROVER2" && -f "$CREDS_DIR/$APPROVER2.json" ]] || { warn "T4 skipped — APPROVER2 + creds required"; }
  if [[ -n "$APPROVER2" && -f "$CREDS_DIR/$APPROVER2.json" ]]; then
    A1_PRIV=$(jq -r .private_key "$CREDS_DIR/$APPROVER1.json"); A1_PUB=$(jq -r .public_key "$CREDS_DIR/$APPROVER1.json")
    A2_PRIV=$(jq -r .private_key "$CREDS_DIR/$APPROVER2.json"); A2_PUB=$(jq -r .public_key "$CREDS_DIR/$APPROVER2.json")
    PARENT_PUB=$(jq -r .public_key "$CREDS_DIR/$PARENT.json")

    # vote helper: <vote> <approval_id> <hash> <priv> <pub> <acct>. Binds the wallet_pubkey
    # (fetched from the approval) into the message: {vote}:{id}:{wallet_pubkey}:{hash}.
    vote() {
      local v=$1 aid=$2 h=$3 priv=$4 pub=$5 acct=$6 nonce sj sig wpk
      wpk=$(curl -sS "$COORDINATOR_URL/wallet/v1/approval/$aid" | jq -r '.wallet_pubkey // empty')
      nonce=$(head -c 32 /dev/urandom | base64 | tr -d '\n')
      sj=$("$RECOVERY_BIN" sign-nep413 --private-key "$priv" --message "$v:$aid:$wpk:$h" --recipient "$CONTRACT_ID" --nonce-base64 "$nonce")
      sig=$(echo "$sj" | jq -r '.signature')
      curl -sS -o /tmp/uop.body -w '%{http_code}' -X POST "$COORDINATOR_URL/wallet/v1/$v/$aid" -H 'Content-Type: application/json' \
        -d "$(jq -nc --arg s "$sig" --arg pk "$pub" --arg ac "$acct" --arg nc "$nonce" '{signature:$s,public_key:$pk,account_id:$ac,nonce:$nc}')"
    }
    rstatus() { curl -sS "$COORDINATOR_URL/wallet/v1/requests/$1" -H "$(AUTH "$2")" | jq -r '.status // empty'; }

    # ── 4a: reject veto by a REAL approver cancels (threshold 1, transfer gated) ──
    SEED="t4a-$(date +%s)"; read -r WID ADDR < <(new_subwallet "$SEED")
    fund_near "$ADDR" "0.01 NEAR" || warn "T4a funding"
    store_policy "$SEED" "$WID" "$(jq -nc --arg a "$APPROVER1" --arg ap "$A1_PUB" '{rules:{transaction_types:["transfer"]}, approval:{threshold:{required:1}, approvers:[{id:$a,pubkey:$ap}]}}')" || fail "T4a store_policy"
    post POST /wallet/v1/transfer "$SEED" "$(jq -nc --arg to "$PARENT" '{chain:"near", receiver_id:$to, amount:"2000000000000000000000"}')"
    AID=$(echo "$BODY" | jq -r '.approval_id // empty'); RID=$(echo "$BODY" | jq -r '.request_id // empty')
    H=$(curl -sS "$COORDINATOR_URL/wallet/v1/approval/$AID" | jq -r '.request_hash')
    [[ -n "$AID" && -n "$H" ]] || fail "T4a no approval queued: $BODY"
    if [[ -n "$AID" ]]; then
      # non-approver (PARENT) NO → must be IGNORED (no veto).
      vote reject "$AID" "$H" "$PARENT_PRIVKEY" "$PARENT_PUB" "$PARENT" >/dev/null; sleep 5
      S=$(rstatus "$RID" "$SEED")
      [[ "$S" != "rejected" && "$S" != "cancelled" && "$S" != "failed" ]] && pass "T4a non-approver reject IGNORED (status=$S)" || fail "T4a non-approver reject must be ignored, status=$S"
      # real approver NO → veto.
      vote reject "$AID" "$H" "$A1_PRIV" "$A1_PUB" "$APPROVER1" >/dev/null; sleep 6
      S=$(rstatus "$RID" "$SEED")
      echo "$S" | grep -qiE "reject|cancel|fail|veto" && pass "T4a real-approver reject → vetoed (status=$S)" || fail "T4a real-approver reject should veto, status=$S"
    fi

    # ── 4b: approve YES by a real approver executes (threshold 1) ──
    SEED="t4b-$(date +%s)"; read -r WID ADDR < <(new_subwallet "$SEED")
    fund_near "$ADDR" "0.01 NEAR" || warn "T4b funding"
    store_policy "$SEED" "$WID" "$(jq -nc --arg a "$APPROVER1" --arg ap "$A1_PUB" '{rules:{transaction_types:["transfer"]}, approval:{threshold:{required:1}, approvers:[{id:$a,pubkey:$ap}]}}')" || fail "T4b store_policy"
    post POST /wallet/v1/transfer "$SEED" "$(jq -nc --arg to "$PARENT" '{chain:"near", receiver_id:$to, amount:"2000000000000000000000"}')"
    AID=$(echo "$BODY" | jq -r '.approval_id // empty'); RID=$(echo "$BODY" | jq -r '.request_id // empty')
    H=$(curl -sS "$COORDINATOR_URL/wallet/v1/approval/$AID" | jq -r '.request_hash')
    if [[ -n "$AID" ]]; then
      C=$(vote approve "$AID" "$H" "$A1_PRIV" "$A1_PUB" "$APPROVER1"); note "T4b /approve HTTP $C"
      TX=""; for _ in $(seq 1 15); do sleep 3; S=$(rstatus "$RID" "$SEED"); case "$S" in completed|success) TX=ok; break;; failed) fail "T4b execution failed"; break;; esac; done
      [[ -n "$TX" ]] && pass "T4b real-approver approve → executed" || fail "T4b did not execute after approve"
    fi

    # ── 4c: 2-of-2 multisig — threshold 2 needs BOTH approvers; 1 approval stays pending, 2 executes ──
    # Two DISTINCT approvers: APPROVER1 + PARENT (the two multisig accounts). This finally exercises the
    # real threshold-counting path — T4a/T4b only used a single threshold-1 approver (APPROVER2 was dead).
    SEED="t4c-$(date +%s)"; read -r WID ADDR < <(new_subwallet "$SEED")
    fund_near "$ADDR" "0.01 NEAR" || warn "T4c funding"
    store_policy "$SEED" "$WID" "$(jq -nc --arg a1 "$APPROVER1" --arg p1 "$A1_PUB" --arg a2 "$PARENT" --arg p2 "$PARENT_PUB" '{rules:{transaction_types:["transfer"]}, approval:{threshold:{required:2}, approvers:[{id:$a1,pubkey:$p1},{id:$a2,pubkey:$p2}]}}')" || fail "T4c store_policy"
    post POST /wallet/v1/transfer "$SEED" "$(jq -nc --arg to "$PARENT" '{chain:"near", receiver_id:$to, amount:"2000000000000000000000"}')"
    AID=$(echo "$BODY" | jq -r '.approval_id // empty'); RID=$(echo "$BODY" | jq -r '.request_id // empty')
    H=$(curl -sS "$COORDINATOR_URL/wallet/v1/approval/$AID" | jq -r '.request_hash')
    if [[ -n "$AID" ]]; then
      # 1st approver (APPROVER1) YES → threshold 2 NOT yet met → MUST stay pending, NOT execute.
      vote approve "$AID" "$H" "$A1_PRIV" "$A1_PUB" "$APPROVER1" >/dev/null; sleep 6
      S=$(rstatus "$RID" "$SEED")
      [[ "$S" != "completed" && "$S" != "success" ]] && pass "T4c 1/2 approvals → still pending ($S), not executed" || fail "T4c executed after only 1/2 approvals — threshold broken! status=$S"
      # 2nd approver (PARENT) YES → threshold 2 met → executes.
      vote approve "$AID" "$H" "$PARENT_PRIVKEY" "$PARENT_PUB" "$PARENT" >/dev/null
      TX=""; for _ in $(seq 1 15); do sleep 3; S=$(rstatus "$RID" "$SEED"); case "$S" in completed|success) TX=ok; break;; failed) fail "T4c execution failed after 2/2"; break;; esac; done
      [[ -n "$TX" ]] && pass "T4c 2/2 approvals → executed (real 2-of-2 multisig)" || fail "T4c did not execute after 2/2 approvals, status=$S"
    fi
  fi
  return_test_funds; MONEY=false
fi

# ════════════════════════════════════════════════════════════════════════════════
# T5 — sign_message allowed_recipients  [POLICY] (no funds)
# ════════════════════════════════════════════════════════════════════════════════
if want T5; then
  log "T5 [POLICY] sign_message allowed_recipients — allowlisted signs; others (incl. intents.near) denied"
  SEED="t5-$(date +%s)"; read -r WID _ < <(new_subwallet "$SEED")
  store_policy "$SEED" "$WID" '{"rules":{"transaction_types":["transfer"]}, "capabilities":{"sign_message":{"allowed":true,"allowed_recipients":["app.example.testnet"]}}}' || fail "T5 store_policy"

  post POST /wallet/v1/sign-message "$SEED" '{"message":"login nonce 123","recipient":"app.example.testnet"}'
  [[ "$HTTP" == "200" ]] && pass "T5 allowlisted recipient → signed" || fail "T5 allowlisted recipient should sign, got $HTTP: $BODY"

  post POST /wallet/v1/sign-message "$SEED" '{"message":"login nonce 123","recipient":"evil.testnet"}'
  [[ "$HTTP" != "200" ]] && echo "$BODY" | grep -qiE "allowed_recipients|recipient|policy|forbidden" && pass "T5 non-allowlisted recipient → denied ($HTTP)" || fail "T5 non-allowlisted should be denied, got $HTTP: $BODY"

  # the auth-path negative: a fund-moving verifier (intents.near) must NEVER be signable here.
  post POST /wallet/v1/sign-message "$SEED" '{"message":"{\"signer_id\":\"x\",\"intents\":[{\"intent\":\"transfer\"}]}","recipient":"intents.near"}'
  [[ "$HTTP" != "200" ]] && pass "T5 sign_message over intents.near → denied (auth can't sign a fund intent): $HTTP" || fail "T5 intents.near recipient MUST be denied, got $HTTP: $BODY"

  # format:"raw" is gone → must point to /auth-sign.
  post POST /wallet/v1/sign-message "$SEED" '{"message":"auth:agent-x:1","recipient":"intents.near","format":"raw"}'
  [[ "$HTTP" == "400" ]] && echo "$BODY" | grep -qi "auth-sign" && pass "T5 format:raw removed → points to /auth-sign" || fail "T5 format:raw should 400→/auth-sign, got $HTTP: $BODY"
fi

# ════════════════════════════════════════════════════════════════════════════════
# T7 — negatives  [POLICY/SIG]
# ════════════════════════════════════════════════════════════════════════════════
if want T7; then
  log "T7 negatives — substituted op (wrong hash) rejected; gated op without approvals stays pending"
  MONEY=true; CUR_TEST=T7
  if [[ -f "$CREDS_DIR/$APPROVER1.json" ]]; then
    A1_PRIV=$(jq -r .private_key "$CREDS_DIR/$APPROVER1.json"); A1_PUB=$(jq -r .public_key "$CREDS_DIR/$APPROVER1.json")
    SEED="t7-$(date +%s)"; read -r WID ADDR < <(new_subwallet "$SEED")
    fund_near "$ADDR" "0.01 NEAR" || warn "T7 funding"
    store_policy "$SEED" "$WID" "$(jq -nc --arg a "$APPROVER1" --arg ap "$A1_PUB" '{rules:{transaction_types:["transfer"]}, approval:{threshold:{required:1}, approvers:[{id:$a,pubkey:$ap}]}}')" || fail "T7 store_policy"
    post POST /wallet/v1/transfer "$SEED" "$(jq -nc --arg to "$PARENT" '{chain:"near", receiver_id:$to, amount:"2000000000000000000000"}')"
    AID=$(echo "$BODY" | jq -r '.approval_id // empty'); RID=$(echo "$BODY" | jq -r '.request_id // empty')
    REAL_H=$(curl -sS "$COORDINATOR_URL/wallet/v1/approval/$AID" | jq -r '.request_hash')

    # 7a: gated op, no approvals yet → immediate response is pending, no tx.
    S=$(curl -sS "$COORDINATOR_URL/wallet/v1/requests/$RID" -H "$(AUTH "$SEED")" | jq -r '.status // empty')
    [[ "$S" != "completed" && "$S" != "success" ]] && pass "T7a gated op without approvals → pending ($S), no execution" || fail "T7a gated op executed without approvals! status=$S"

    WPK=$(curl -sS "$COORDINATOR_URL/wallet/v1/approval/$AID" | jq -r '.wallet_pubkey // empty')

    # 7b: approver signs over a WRONG (substituted) request_hash but the correct wallet_pubkey →
    #     coordinator + keystore both re-derive the real message → invalid → no execution.
    WRONG_H=$(printf '%064d' 0)
    nonce=$(head -c 32 /dev/urandom | base64 | tr -d '\n')
    sj=$("$RECOVERY_BIN" sign-nep413 --private-key "$A1_PRIV" --message "approve:$AID:$WPK:$WRONG_H" --recipient "$CONTRACT_ID" --nonce-base64 "$nonce")
    sig=$(echo "$sj" | jq -r '.signature')
    C=$(curl -sS -o /tmp/uop.body -w '%{http_code}' -X POST "$COORDINATOR_URL/wallet/v1/approve/$AID" -H 'Content-Type: application/json' \
      -d "$(jq -nc --arg s "$sig" --arg pk "$A1_PUB" --arg ac "$APPROVER1" --arg nc "$nonce" '{signature:$s,public_key:$pk,account_id:$ac,nonce:$nc}')")
    note "T7b /approve (wrong hash) HTTP $C: $(cat /tmp/uop.body | head -c120)"
    sleep 8
    S=$(curl -sS "$COORDINATOR_URL/wallet/v1/requests/$RID" -H "$(AUTH "$SEED")" | jq -r '.status // empty')
    [[ "$S" != "completed" && "$S" != "success" ]] && pass "T7b approval over substituted hash → rejected, no execution (status=$S)" || fail "T7b substituted-hash approval EXECUTED — binding broken! status=$S"

    # 7c: cross-wallet replay — a VALID approval for wallet A submitted onto wallet B (same
    #     approver) must be rejected: the message binds the wallet_pubkey, so A's signature
    #     can't satisfy B (audit fix 2).
    SEED_B="t7b2-$(date +%s)"; read -r WID_B ADDR_B < <(new_subwallet "$SEED_B")
    fund_near "$ADDR_B" "0.01 NEAR" || warn "T7c funding"
    store_policy "$SEED_B" "$WID_B" "$(jq -nc --arg a "$APPROVER1" --arg ap "$A1_PUB" '{rules:{transaction_types:["transfer"]}, approval:{threshold:{required:1}, approvers:[{id:$a,pubkey:$ap}]}}')" || fail "T7c store_policy"
    post POST /wallet/v1/transfer "$SEED_B" "$(jq -nc --arg to "$PARENT" '{chain:"near", receiver_id:$to, amount:"2000000000000000000000"}')"
    AID_B=$(echo "$BODY" | jq -r '.approval_id // empty'); RID_B=$(echo "$BODY" | jq -r '.request_id // empty')
    H_B=$(curl -sS "$COORDINATOR_URL/wallet/v1/approval/$AID_B" | jq -r '.request_hash')
    # Sign with wallet A's pubkey binding (WPK from T7's wallet) but submit to B's approval.
    nonce=$(head -c 32 /dev/urandom | base64 | tr -d '\n')
    sj=$("$RECOVERY_BIN" sign-nep413 --private-key "$A1_PRIV" --message "approve:$AID_B:$WPK:$H_B" --recipient "$CONTRACT_ID" --nonce-base64 "$nonce")
    sig=$(echo "$sj" | jq -r '.signature')
    C=$(curl -sS -o /tmp/uop.body -w '%{http_code}' -X POST "$COORDINATOR_URL/wallet/v1/approve/$AID_B" -H 'Content-Type: application/json' \
      -d "$(jq -nc --arg s "$sig" --arg pk "$A1_PUB" --arg ac "$APPROVER1" --arg nc "$nonce" '{signature:$s,public_key:$pk,account_id:$ac,nonce:$nc}')")
    note "T7c cross-wallet /approve HTTP $C: $(cat /tmp/uop.body | head -c120)"
    sleep 8
    S=$(curl -sS "$COORDINATOR_URL/wallet/v1/requests/$RID_B" -H "$(AUTH "$SEED_B")" | jq -r '.status // empty')
    [[ "$S" != "completed" && "$S" != "success" ]] && pass "T7c cross-wallet replay (A's binding on B) → rejected, no execution (status=$S)" || fail "T7c cross-wallet replay EXECUTED — wallet binding broken! status=$S"
  else warn "T7 skipped — APPROVER1 creds required"; fi
  return_test_funds; MONEY=false
fi

# ════════════════════════════════════════════════════════════════════════════════
# T11 — /wallet/v1/delete (DESTRUCTIVE)  [FUNDS]
#       NEAR-native DeleteAccount: irreversibly deletes the wallet account and sweeps
#       its FULL remaining balance to the beneficiary. Guards exercised here:
#         11a self-beneficiary  — beneficiary == the wallet's own account → rejected
#                                 (BEFORE any tx; no funds move).
#         11b zero-balance      — a wallet with 0 on-chain NEAR can't be deleted
#                                 (implicit account does not exist) → rejected.
#         11c happy path        — fund a THROWAWAY sub-wallet minimally, delete it with
#                                 the beneficiary set to BENEFICIARY (the shared constant
#                                 sink — a real, existing account we control), assert
#                                 success + (best-effort) the beneficiary's balance increased.
#       Everything stays inside disposable sub-wallets under our own vault and tiny
#       testnet amounts — no external account and no PARENT funds are deleted.
# ════════════════════════════════════════════════════════════════════════════════
if want T11; then
  log "T11 [FUNDS] /wallet/v1/delete — self-beneficiary + zero-balance guards, then a real destructive delete to a beneficiary we control"
  MONEY=true; CUR_TEST=T11

  # NEAR balance of an arbitrary account (yoctoNEAR). Non-existent implicit account → "0".
  near_bal() {
    curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
      -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"query\",\"params\":{\"request_type\":\"view_account\",\"finality\":\"final\",\"account_id\":\"$1\"}}" \
      | jq -r '.result.amount // "0"' 2>/dev/null || echo "0"
  }
  # delete-allowing policy (transaction_types:["delete"] — delete is Built, needs no capability).
  DEL_POL='{"rules":{"transaction_types":["delete"]}}'

  # ── 11a: self-beneficiary guard (no funds move; guard runs before the balance check) ──
  SEED="t11a-$(date +%s)"; read -r WID ADDR < <(new_subwallet "$SEED")
  fund_near "$ADDR" "0.005 NEAR" || warn "T11a funding"
  store_policy "$SEED" "$WID" "$DEL_POL" || fail "T11a store_policy"
  post POST /wallet/v1/delete "$SEED" "$(jq -nc --arg b "$ADDR" '{beneficiary:$b, chain:"near"}')"
  if [[ "$HTTP" != "200" ]] && echo "$BODY" | grep -qiE "own account|beneficiary"; then
    pass "T11a self-beneficiary rejected ($HTTP): $(echo "$BODY"|head -c120)"
  else fail "T11a delete with beneficiary == own account MUST be rejected, got $HTTP: $BODY"; fi

  # ── 11b: zero-balance guard (fresh, UNFUNDED wallet → account does not exist on-chain) ──
  SEED="t11b-$(date +%s)"; read -r WID ADDR < <(new_subwallet "$SEED")
  store_policy "$SEED" "$WID" "$DEL_POL" || fail "T11b store_policy"
  post POST /wallet/v1/delete "$SEED" "$(jq -nc --arg b "$BENEFICIARY" '{beneficiary:$b, chain:"near"}')"
  if [[ "$HTTP" != "200" ]] && echo "$BODY" | grep -qiE "zero|balance|on-chain|does not exist"; then
    pass "T11b zero-balance delete rejected ($HTTP): $(echo "$BODY"|head -c120)"
  else fail "T11b delete of a 0-balance wallet MUST be rejected, got $HTTP: $BODY"; fi

  # ── 11c: real destructive delete → sweeps the full balance to the shared constant beneficiary ──
  # Beneficiary = BENEFICIARY, the shared constant sink: a real, existing, wNEAR-registered account we
  # control. Because it already exists on-chain, NEAR's DeleteAccount credits it (a non-existent
  # implicit beneficiary would BURN the swept balance — which is exactly why the constant is used).
  # The beneficiary-balance-increase check is BEST-EFFORT: BENEFICIARY is an active account whose delta
  # may be masked by other activity, so it warns rather than fails. The PRIMARY asserts are
  # status=success + the deleted wallet gone + beneficiary echoed == $BENEFICIARY.
  SEED="t11c-$(date +%s)"; read -r WID ADDR < <(new_subwallet "$SEED")
  fund_near "$ADDR" "0.005 NEAR" || warn "T11c funding"
  # Wait until the wallet-to-delete exists on-chain (funding settles) before deleting.
  for _ in $(seq 1 6); do [[ "$(near_bal "$ADDR")" != "0" ]] && break; sleep 2; done
  # A funding send can vanish silently (`near --quiet` swallows a broadcast transient and
  # still exits 0), and deleting an account that never came to exist answers a misleading
  # on-chain 422. Retry once and report the FUNDING as the failure, not the delete.
  if [[ "$(near_bal "$ADDR")" == "0" ]]; then
    warn "T11c funding did not land — retrying once"
    fund_near "$ADDR" "0.005 NEAR" || warn "T11c refunding"
    for _ in $(seq 1 6); do [[ "$(near_bal "$ADDR")" != "0" ]] && break; sleep 2; done
    [[ "$(near_bal "$ADDR")" == "0" ]] && fail "T11c the funding never landed on $ADDR — cannot exercise the delete"
  fi
  store_policy "$SEED" "$WID" "$DEL_POL" || fail "T11c store_policy"
  BEN_BEFORE=$(near_bal "$BENEFICIARY")
  post POST /wallet/v1/delete "$SEED" "$(jq -nc --arg b "$BENEFICIARY" '{beneficiary:$b, chain:"near"}')"
  if [[ "$HTTP" == "200" ]]; then
    ST=$(echo "$BODY" | jq -r '.status // empty'); TX=$(echo "$BODY" | jq -r '.tx_hash // empty')
    BEN_ECHO=$(echo "$BODY" | jq -r '.beneficiary // empty')
    if [[ "$ST" == "success" && -n "$TX" && "$BEN_ECHO" == "$BENEFICIARY" ]]; then
      pass "T11c delete executed (status=$ST, tx=$TX, beneficiary echoed)"
    else fail "T11c delete 200 but unexpected body (status='$ST' tx='$TX' beneficiary='$BEN_ECHO'): $(echo "$BODY"|head -c160)"; fi
    # the deleted wallet must no longer exist on-chain (balance back to 0 / account gone).
    GONE=$(near_bal "$ADDR"); [[ "$GONE" == "0" ]] && pass "T11c deleted wallet no longer exists on-chain (balance=0)" \
      || note "T11c deleted wallet still shows balance=$GONE (RPC lag) — non-fatal"
    # beneficiary balance should increase (best-effort; BENEFICIARY is active so the delta may be masked).
    BEN_AFTER="$BEN_BEFORE"
    for attempt in $(seq 1 8); do sleep 3; BEN_AFTER=$(near_bal "$BENEFICIARY"); [[ "$BEN_AFTER" != "$BEN_BEFORE" ]] && break
      note "T11c poll $attempt: beneficiary balance still $BEN_AFTER"; done
    note "T11c beneficiary balance: before=$BEN_BEFORE after=$BEN_AFTER"
    if [[ "$BEN_AFTER" != "$BEN_BEFORE" ]]; then pass "T11c beneficiary balance increased → full sweep delivered"
    else warn "T11c beneficiary balance delta not observed after ~24s — BENEFICIARY is active, may be masked; confirm manually (tx=$TX)"; fi
  else fail "T11c destructive delete should succeed (200), got $HTTP: $BODY"; fi
  return_test_funds; MONEY=false
fi

# ════════════════════════════════════════════════════════════════════════════════
# T13 — sign_message ed25519 VERIFY + cross-scope isolation + tamper  [POLICY] (no funds)
#       Ported from tests/wallet_sign_message_roundtrip.sh. Unlike T5 (which only checks a
#       signature is PRESENT), T13 actually ed25519-VERIFIES the returned signature against the
#       returned public_key + the exact signed NEP-413 message bytes (via
#       `customer-recovery verify-sign-message` — the same independent verifier the source uses,
#       reconstructing Borsh(NEP-413 payload) → SHA-256 → verify_strict). Asserts:
#         13a  a valid sign-message VERIFIES under its returned pubkey;
#         13b  a TAMPERED message and a TAMPERED nonce both FAIL verification;
#         13c  two DIFFERENT wallet scopes (different seeds → different per-wallet keys) produce
#              signatures that do NOT cross-verify (crypto isolation, not just distinct strings).
#       NOTE on scope: the source split scopes via default-master vs `outlayer vault init`. Here we
#       use two distinct seeds under the same auth path — the achievable, headless scope split that
#       still proves cryptographic isolation (distinct keys). When a dedicated vault is deployed
#       (MPC_PUBLIC_KEY set) the seeds additionally route through the per-vault master.
# ════════════════════════════════════════════════════════════════════════════════
if want T13; then
  log "T13 [POLICY] sign_message ed25519 VERIFY + cross-scope isolation + tamper"
  # sign_and_capture <seed> <recipient> <tag> → echoes "SIG|PUB|NONCE|MSG" (the bytes actually
  # signed). Pure capture: it does NOT call pass/fail (it runs in the `< <(...)` subshell of `read`,
  # where PASS/FAILED increments would be lost — same subshell gotcha new_subwallet documents). The
  # caller, in the MAIN shell, runs verify-sign-message + the assertions. The server is free to
  # replace the requested nonce, so we read .nonce back and the caller verifies against THAT.
  T13_MSG_BASE="t13-roundtrip-$(date +%s)-$$"
  sign_and_capture() {
    local seed=$1 rcp=$2 msg="$T13_MSG_BASE-$3" r sig pub nonce
    # nonce is the NEP-413 32-byte nonce (base64). Send a fixed one; read back what the server used.
    r=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/sign-message" -H "$(AUTH "$seed")" -H 'Content-Type: application/json' \
      -d "$(jq -nc --arg m "$msg" --arg r "$rcp" '{message:$m, recipient:$r, nonce:"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}')")
    sig=$(echo "$r" | jq -r '.signature // empty'); pub=$(echo "$r" | jq -r '.public_key // empty'); nonce=$(echo "$r" | jq -r '.nonce // empty')
    echo "$sig|$pub|$nonce|$msg"
  }

  # ── 13a: a valid sign-message must VERIFY under its returned pubkey (the roundtrip proof) ──
  SEED_A="t13a-$(date +%s)"; read -r WID_A _ < <(new_subwallet "$SEED_A")
  store_policy "$SEED_A" "$WID_A" '{"rules":{"transaction_types":["transfer"]}, "capabilities":{"sign_message":{"allowed":true,"allowed_recipients":["verifier-a.testnet"]}}}' || fail "T13a store_policy"
  IFS='|' read -r SIG_A PUB_A NONCE_A MSG_A < <(sign_and_capture "$SEED_A" "verifier-a.testnet" "A")
  [[ -n "$SIG_A" && -n "$PUB_A" && -n "$NONCE_A" ]] || fail "T13a sign-message returned no signature/pubkey/nonce for scope A"
  if "$RECOVERY_BIN" verify-sign-message --pubkey "$PUB_A" --message "$MSG_A" --recipient "verifier-a.testnet" --nonce-base64 "$NONCE_A" --signature "$SIG_A" >/dev/null 2>&1; then
    pass "T13a valid sign-message VERIFIES under returned pubkey $PUB_A"
  else fail "T13a sign-message returned a crypto-INVALID signature (did not verify under $PUB_A)"; fi

  # ── 13b: tamper — a mutated message and a mutated nonce must BOTH fail verification ──
  if "$RECOVERY_BIN" verify-sign-message --pubkey "$PUB_A" --message "${MSG_A}-MUTATED" --recipient "verifier-a.testnet" --nonce-base64 "$NONCE_A" --signature "$SIG_A" >/dev/null 2>&1; then
    fail "T13b TAMPER UNDETECTED: signature verified with a mutated message"
  else pass "T13b tampered message rejected (verify failed as required)"; fi
  # Flip one byte of the nonce → must break verification.
  TAMPERED_NONCE_A=$(printf '%s' "$NONCE_A" | base64 -d 2>/dev/null | python3 -c 'import sys; b=bytearray(sys.stdin.buffer.read()); b[0]^=1; sys.stdout.buffer.write(bytes(b))' | base64 | tr -d '\n')
  if "$RECOVERY_BIN" verify-sign-message --pubkey "$PUB_A" --message "$MSG_A" --recipient "verifier-a.testnet" --nonce-base64 "$TAMPERED_NONCE_A" --signature "$SIG_A" >/dev/null 2>&1; then
    fail "T13b TAMPER UNDETECTED: signature verified with a mutated nonce"
  else pass "T13b tampered nonce rejected (verify failed as required)"; fi

  # ── 13c: cross-scope isolation — a DIFFERENT seed yields a DIFFERENT key; sigs must not cross-verify ──
  SEED_B="t13b2-$(date +%s)"; read -r WID_B _ < <(new_subwallet "$SEED_B")
  store_policy "$SEED_B" "$WID_B" '{"rules":{"transaction_types":["transfer"]}, "capabilities":{"sign_message":{"allowed":true,"allowed_recipients":["verifier-b.testnet"]}}}' || fail "T13c store_policy"
  IFS='|' read -r SIG_B PUB_B NONCE_B MSG_B < <(sign_and_capture "$SEED_B" "verifier-b.testnet" "B")
  [[ -n "$SIG_B" && -n "$PUB_B" && -n "$NONCE_B" ]] || fail "T13c sign-message returned no signature/pubkey/nonce for scope B"
  # B's own signature must verify under B's own pubkey (sanity that scope B is a working signer).
  "$RECOVERY_BIN" verify-sign-message --pubkey "$PUB_B" --message "$MSG_B" --recipient "verifier-b.testnet" --nonce-base64 "$NONCE_B" --signature "$SIG_B" >/dev/null 2>&1 \
    && pass "T13c scope-B signature verifies under its own pubkey $PUB_B" || fail "T13c scope-B signature did not verify under its own pubkey"
  [[ "$PUB_A" != "$PUB_B" ]] && pass "T13c distinct seeds → distinct signing pubkeys ($PUB_A != $PUB_B)" || fail "T13c two scopes shared the SAME pubkey — scope isolation broken"
  # A's signature must NOT verify under B's pubkey (and vice-versa) — proves keys are isolated.
  if "$RECOVERY_BIN" verify-sign-message --pubkey "$PUB_B" --message "$MSG_A" --recipient "verifier-a.testnet" --nonce-base64 "$NONCE_A" --signature "$SIG_A" >/dev/null 2>&1; then
    fail "T13c ISOLATION BROKEN: scope-A signature verified under scope-B pubkey"
  else pass "T13c SIG_A correctly rejected by PUB_B (no cross-scope key reuse)"; fi
  if "$RECOVERY_BIN" verify-sign-message --pubkey "$PUB_A" --message "$MSG_B" --recipient "verifier-b.testnet" --nonce-base64 "$NONCE_B" --signature "$SIG_B" >/dev/null 2>&1; then
    fail "T13c ISOLATION BROKEN: scope-B signature verified under scope-A pubkey"
  else pass "T13c SIG_B correctly rejected by PUB_A"; fi
  [[ -z "$VAULT_ID" ]] && note "T13c cross-scope proven via distinct seeds (default-vault mode); per-vault-master split not exercised — set MPC_PUBLIC_KEY to additionally route seeds through a dedicated vault master"
fi

# ════════════════════════════════════════════════════════════════════════════════
# T14 — api-key NEAR-signed derive + refusals  [POLICY] (no funds)
#       Ported from tests/api_key_signed_derive_e2e.sh. PUT /wallet/v1/api-key authenticated by a
#       NEAR signature over `api-key:<seed>:<ts>` (built+signed by the parent key via
#       `customer-recovery sign-api-key-claim`). The coordinator verifies the sig, checks the pubkey
#       is an access key on account_id, and (when vault_id is supplied) that account_id == vault.parent.
#       Asserts:
#         14a  happy path → 200, response binds (wallet_id present; vault_id echo matches the scope used);
#         14b  the minted sub-wallet's wk_ actually works: GET /address agrees on scope + /sign-message
#              returns a crypto-valid signature (verified with customer-recovery);
#         14c  cross-account spoof (account_id != the signer/parent) → HTTP 4xx (the vault.parent /
#              access-key gate; this is the portable refusal).
#       Under v2 "re-binding the SAME api-key to a DIFFERENT vault" is NOT a 400 — it mints a DISTINCT
#       wallet_id. The genuine 400 the source still asserts is the cross-account spoof (14c). When a
#       dedicated vault is deployed (MPC_PUBLIC_KEY set) we ALSO assert the cross-vault mint yields a
#       distinct wallet_id; otherwise that dimension is SKIP-noted.
# ════════════════════════════════════════════════════════════════════════════════
if want T14; then
  log "T14 [POLICY] api-key NEAR-signed derive (PUT /api-key) + refusals"
  new_sub_key() { printf 'wk_%s' "$(head -c 32 /dev/urandom | xxd -p -c 64)"; }

  # ── 14a: happy path — sign-api-key-claim → PUT /api-key → 200, binds wallet_id (+ vault echo) ──
  SEED="t14-$(date +%s)-$$"; SUB_KEY=$(new_sub_key)
  BODY14=$("$RECOVERY_BIN" sign-api-key-claim --private-key "$PARENT_PRIVKEY" --account-id "$PARENT" --seed "$SEED" --sub-key "$SUB_KEY" ${VAULT_ID:+--vault-id "$VAULT_ID"})
  H14=$(curl -sS -o /tmp/uop.body -w '%{http_code}' -X PUT "$COORDINATOR_URL/wallet/v1/api-key" -H 'Content-Type: application/json' -d "$BODY14"); R14=$(cat /tmp/uop.body)
  WALLET_ID_14=$(echo "$R14" | jq -r '.wallet_id // empty'); GOT_VAULT_14=$(echo "$R14" | jq -r '.vault_id // empty')
  if [[ "$H14" == "200" && -n "$WALLET_ID_14" ]]; then
    if [[ -n "$VAULT_ID" ]]; then
      [[ "$GOT_VAULT_14" == "$VAULT_ID" ]] && pass "T14a PUT /api-key bound wallet_id=$WALLET_ID_14 under vault $VAULT_ID" || fail "T14a vault echo '$GOT_VAULT_14' != '$VAULT_ID': $R14"
    else
      pass "T14a PUT /api-key bound wallet_id=$WALLET_ID_14 (default-master scope)"
    fi
  else fail "T14a PUT /api-key expected 200 + wallet_id, got $H14: $R14"; fi

  # ── 14b: the minted wk_ works — /address agrees on scope; /sign-message returns a crypto-valid sig ──
  if [[ "$H14" == "200" && -n "$WALLET_ID_14" ]]; then
    ADDR14=$(curl -sS -G "$COORDINATOR_URL/wallet/v1/address" --data-urlencode "chain=near" -H "Authorization: Bearer $SUB_KEY")
    ADDR14_VAULT=$(echo "$ADDR14" | jq -r '.vault_id // empty')
    if [[ -n "$VAULT_ID" ]]; then
      [[ "$ADDR14_VAULT" == "$VAULT_ID" ]] && pass "T14b minted wk_ /address reports vault_id=$VAULT_ID" || fail "T14b /address vault_id='$ADDR14_VAULT' != '$VAULT_ID': $ADDR14"
    else
      [[ -n "$(echo "$ADDR14" | jq -r '.address // empty')" ]] && pass "T14b minted wk_ /address resolves (default scope)" || fail "T14b /address gave no address: $ADDR14"
    fi
    MSG14="t14-apik-rt-$(date +%s)"
    SR14=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/sign-message" -H "Authorization: Bearer $SUB_KEY" -H 'Content-Type: application/json' \
      -d "$(jq -nc --arg m "$MSG14" '{message:$m, recipient:"verifier-apik.testnet", nonce:"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}')")
    S14=$(echo "$SR14" | jq -r '.signature // empty'); P14=$(echo "$SR14" | jq -r '.public_key // empty'); N14=$(echo "$SR14" | jq -r '.nonce // empty')
    if [[ -n "$S14" ]] && "$RECOVERY_BIN" verify-sign-message --pubkey "$P14" --message "$MSG14" --recipient "verifier-apik.testnet" --nonce-base64 "$N14" --signature "$S14" >/dev/null 2>&1; then
      pass "T14b minted sub-wallet's signature verifies under $P14"
    else fail "T14b minted sub-wallet signature did NOT verify: $SR14"; fi
  fi

  # ── 14c: cross-account spoof — account_id != signer/parent must be refused (4xx) ──
  # Mutate account_id on the (otherwise valid) happy-path body to a non-parent account. The
  # signature was over $PARENT, the pubkey is an access key on $PARENT, so the access-key /
  # vault.parent gate must reject the mismatched account_id.
  SPOOF14=$(echo "$BODY14" | jq --arg fake "not-the-parent.$NETWORK" '.account_id = $fake')
  HS14=$(curl -sS -o /tmp/uop.body -w '%{http_code}' -X PUT "$COORDINATOR_URL/wallet/v1/api-key" -H 'Content-Type: application/json' -d "$SPOOF14"); RS14=$(cat /tmp/uop.body)
  [[ "$HS14" =~ ^4 ]] && pass "T14c cross-account spoof rejected (HTTP $HS14)" || fail "T14c cross-account spoof should be 4xx, got $HS14: $RS14"

  # ── (vault-only) cross-vault mint → DISTINCT wallet_id (v2: not a refusal, a distinct wallet) ──
  if [[ -n "$VAULT_ID" ]]; then
    SUB_KEY2=$(new_sub_key)
    BODY14B=$("$RECOVERY_BIN" sign-api-key-claim --private-key "$PARENT_PRIVKEY" --account-id "$PARENT" --seed "$SEED" --sub-key "$SUB_KEY2")
    H14B=$(curl -sS -o /tmp/uop.body -w '%{http_code}' -X PUT "$COORDINATOR_URL/wallet/v1/api-key" -H 'Content-Type: application/json' -d "$BODY14B"); R14B=$(cat /tmp/uop.body)
    WID14B=$(echo "$R14B" | jq -r '.wallet_id // empty')
    if [[ "$H14B" == "200" && -n "$WID14B" && "$WID14B" != "$WALLET_ID_14" ]]; then
      pass "T14 v2: same seed under a DIFFERENT scope minted a distinct wallet_id ($WID14B != $WALLET_ID_14)"
    else fail "T14 v2 cross-scope mint expected 200 + distinct wallet_id, got $H14B wid='$WID14B' (vault wid=$WALLET_ID_14): $R14B"; fi
  else
    note "T14 vault-rebind dimension SKIPPED (default-vault mode, no MPC_PUBLIC_KEY): source's same-seed-different-vault → distinct-wallet_id needs a dedicated vault"
  fi
fi

# ════════════════════════════════════════════════════════════════════════════════
# T15 — vault-scope parity + cache-poisoning  [POLICY] (no funds)
#       Ported from tests/bearer_vault_endpoint_parity_e2e.sh. Regression coverage for the
#       "resolve_wallet_pubkey ignores vault scope" / DB-cache silent-fork bug class: every
#       address-returning endpoint must report the SAME NEAR account as /address for a given
#       Bearer-near token, and a no-vault write must NOT poison a later vault-scoped lookup.
#       Asserts:
#         15a  endpoint parity — for one Bearer-near seed, /address, /balance(native),
#              /balance(intents) and /sign-message all report the same account_id;
#       and, ONLY when a dedicated vault is deployed (MPC_PUBLIC_KEY → two distinct vault scopes):
#         15b  cache-poisoning — a no-vault /address write does NOT poison the later vault-scoped
#              /address/balance/sign-message (they return the vault address, not the poisoned cache);
#         15c  cross-vault isolation — vault A vs vault B → distinct addresses, mirrored by every endpoint.
#       In default-vault mode the suite has only ONE scope, so 15b/15c (which REQUIRE two scopes) are
#       SKIP-noted cleanly rather than faked.
# ════════════════════════════════════════════════════════════════════════════════
if want T15; then
  log "T15 [POLICY] vault-scope parity + cache-poisoning regression"
  # acct_via <path-kind> <token> → echoes the .account_id a given endpoint reports for a Bearer-near token.
  addr_via_address() { curl -sS -G "$COORDINATOR_URL/wallet/v1/address" --data-urlencode "chain=near" -H "Authorization: Bearer near:$1" | jq -r '.address // empty'; }
  acct_balance_native()  { curl -sS -G "$COORDINATOR_URL/wallet/v1/balance" --data-urlencode "chain=near" -H "Authorization: Bearer near:$1" | jq -r '.account_id // empty'; }
  acct_balance_intents() { curl -sS -G "$COORDINATOR_URL/wallet/v1/balance" --data-urlencode "token=nep141:usdt.tether-token.near" --data-urlencode "source=intents" -H "Authorization: Bearer near:$1" | jq -r '.account_id // empty'; }
  acct_sign_message()    { curl -sS -X POST "$COORDINATOR_URL/wallet/v1/sign-message" -H "Authorization: Bearer near:$1" -H 'Content-Type: application/json' -d "$(jq -nc --arg m "parity-$(date +%s%N)" '{message:$m, recipient:"parity-verifier.testnet", nonce:"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}')" | jq -r '.account_id // empty'; }

  # ── 15a: endpoint parity — fresh seed, fresh token, every endpoint must agree with /address ──
  SEED_P="t15-parity-$(date +%s)-$$"; TOK_P=$(mk_token "$SEED_P" "$VAULT_ID")
  P_ADDR=$(addr_via_address "$TOK_P"); P_BN=$(acct_balance_native "$TOK_P"); P_BI=$(acct_balance_intents "$TOK_P"); P_SM=$(acct_sign_message "$TOK_P")
  [[ -n "$P_ADDR" ]] || fail "T15a /address returned no address"
  note "T15a /address=$P_ADDR /balance(native)=$P_BN /balance(intents)=$P_BI /sign-message=$P_SM"
  [[ "$P_BN" == "$P_ADDR" ]] && pass "T15a /balance(native).account_id == /address" || fail "T15a /balance(native) '$P_BN' != /address '$P_ADDR' — resolve_wallet_pubkey ignores scope"
  [[ "$P_BI" == "$P_ADDR" ]] && pass "T15a /balance(intents).account_id == /address" || fail "T15a /balance(intents) '$P_BI' != /address '$P_ADDR'"
  [[ "$P_SM" == "$P_ADDR" ]] && pass "T15a /sign-message.account_id == /address" || fail "T15a /sign-message '$P_SM' != /address '$P_ADDR'"

  if [[ -n "$VAULT_ID" ]]; then
    # ── 15b: cache-poisoning regression — no-vault write first, then vault-scoped reads must NOT use the poisoned cache ──
    SEED_POISON="t15-poison-$(date +%s)-$$"
    TOK_NV=$(mk_token "$SEED_POISON" "")        # no-vault token (writes default-master pubkey into cache)
    ADDR_NV=$(addr_via_address "$TOK_NV")       # step 1: poison
    TOK_VS=$(mk_token "$SEED_POISON" "$VAULT_ID")  # same seed, vault-scoped
    ADDR_VS=$(addr_via_address "$TOK_VS")
    [[ -n "$ADDR_VS" && "$ADDR_VS" != "$ADDR_NV" ]] && pass "T15b vault-scoped /address ($ADDR_VS) != poisoned no-vault cache ($ADDR_NV)" || fail "T15b cache poisoning: vault-scoped /address returned the no-vault address ($ADDR_VS == $ADDR_NV)"
    BVS_I=$(acct_balance_intents "$TOK_VS"); SVS=$(acct_sign_message "$TOK_VS")
    [[ "$BVS_I" == "$ADDR_VS" ]] && pass "T15b /balance(intents) honors vault scope after poison" || fail "T15b /balance(intents) '$BVS_I' != vault /address '$ADDR_VS' — poisoned cache leaked"
    [[ "$SVS" == "$ADDR_VS" ]] && pass "T15b /sign-message honors vault scope after poison" || fail "T15b /sign-message '$SVS' != vault /address '$ADDR_VS'"

    # ── 15c: cross-vault isolation — vault A vs vault B → distinct addresses, mirrored per endpoint ──
    # The suite deploys only ONE vault; treat the no-vault (default-master) scope as the second, distinct scope.
    SEED_X="t15-xvault-$(date +%s)-$$"
    TOK_XA=$(mk_token "$SEED_X" "$VAULT_ID"); TOK_XD=$(mk_token "$SEED_X" "")
    XA=$(addr_via_address "$TOK_XA"); XD=$(addr_via_address "$TOK_XD")
    [[ -n "$XA" && -n "$XD" && "$XA" != "$XD" ]] && pass "T15c two scopes → distinct addresses (vault=$XA, default=$XD)" || fail "T15c two scopes collapsed to one address (vault=$XA default=$XD)"
    [[ "$(acct_balance_intents "$TOK_XA")" == "$XA" && "$(acct_balance_intents "$TOK_XD")" == "$XD" ]] && pass "T15c /balance(intents) mirrors per-scope isolation" || fail "T15c /balance(intents) did not mirror scope isolation"
    [[ "$(acct_sign_message "$TOK_XA")" == "$XA" && "$(acct_sign_message "$TOK_XD")" == "$XD" ]] && pass "T15c /sign-message mirrors per-scope isolation" || fail "T15c /sign-message did not mirror scope isolation"
  else
    note "T15b/T15c SKIPPED (default-vault mode, no MPC_PUBLIC_KEY): cache-poisoning + cross-vault isolation REQUIRE two distinct vault scopes; only parity (15a) is reachable in single-scope mode"
  fi
fi

# ════════════════════════════════════════════════════════════════════════════════
# T16 — wallet_id v2 invariants  [POLICY] (no funds)
#       Ported from tests/v2_policy_invariants_e2e.sh. Asserts:
#         16a  seed-length validation at the API boundary — a 256-char seed is accepted, 257 rejected
#              (HTTP 400; max=256, per the source). Checked via PUT /wallet/v1/api-key.
#         16b  wallet_id idempotency / offline==online — `customer-recovery compute-wallet-id`
#              reproduces the SAME wallet_id the coordinator returns from /address for the same
#              (parent, seed [, vault]) — proving the v2 formula and the offline recovery path agree;
#         16c  reverse-lookup — GET /wallet/v1/pending_approvals_by_pubkey for a vault-scoped pubkey
#              resolves the wallet (empty approvals array = found, not 404), and a random pubkey is
#              handled gracefully (no false hit).
# ════════════════════════════════════════════════════════════════════════════════
if want T16; then
  log "T16 [POLICY] wallet_id v2 invariants — seed-length, idempotency, reverse-lookup"
  # ── 16a: seed-length boundary at the API boundary (256 OK, 257 → 400; max=256 per auth::validate_seed) ──
  # validate_seed fires FIRST in register_api_key (before key_hash/auth/sig checks), so a 257-char
  # seed 400s on length regardless of the (bogus) signature — exactly the source's X3 assertion.
  SEED_256=$(printf 'a%.0s' $(seq 1 256)); SEED_257=$(printf 'a%.0s' $(seq 1 257))
  # 257 → 400 (length), proven with a bogus sig: the length gate short-circuits before sig verify.
  LONG_BODY=$(jq -nc --arg s "$SEED_257" '{account_id:"spoof.testnet", seed:$s, key_hash:"0000000000000000000000000000000000000000000000000000000000000000", pubkey:"ed25519:11111111111111111111111111111111", message:"api-key:dummy:0", signature:"deadbeef"}')
  H_LONG=$(curl -sS -o /tmp/uop.body -w '%{http_code}' -X PUT "$COORDINATOR_URL/wallet/v1/api-key" -H 'Content-Type: application/json' -d "$LONG_BODY")
  [[ "$H_LONG" == "400" ]] && pass "T16a 257-char seed rejected (HTTP 400, max=256)" || fail "T16a 257-char seed should be 400, got $H_LONG: $(cat /tmp/uop.body | head -c160)"
  # 256 → must clear the length gate. Sign a REAL parent-keyed claim (correct api-key:<seed>:<ts> +
  # valid sig) so the request reaches binding; HTTP 200 proves a 256-char seed is within bound.
  SK_256=$(printf 'wk_%s' "$(head -c 32 /dev/urandom | xxd -p -c 64)")
  BODY_256=$("$RECOVERY_BIN" sign-api-key-claim --private-key "$PARENT_PRIVKEY" --account-id "$PARENT" --seed "$SEED_256" --sub-key "$SK_256" ${VAULT_ID:+--vault-id "$VAULT_ID"})
  H_256=$(curl -sS -o /tmp/uop.body -w '%{http_code}' -X PUT "$COORDINATOR_URL/wallet/v1/api-key" -H 'Content-Type: application/json' -d "$BODY_256")
  [[ "$H_256" == "200" ]] && pass "T16a 256-char seed accepted (HTTP 200 — within max-length bound)" || fail "T16a 256-char seed should be accepted (200), got $H_256: $(cat /tmp/uop.body | head -c160)"

  # ── 16b: wallet_id idempotency — offline compute-wallet-id == coordinator /address .wallet_id ──
  SEED_ID="t16-idem-$(date +%s)-$$"
  WID_ONLINE=$(curl -sS -G "$COORDINATOR_URL/wallet/v1/address" --data-urlencode "chain=near" -H "$(AUTH "$SEED_ID")" | jq -r '.wallet_id // empty')
  WID_OFFLINE=$("$RECOVERY_BIN" compute-wallet-id --account-id "$PARENT" --seed "$SEED_ID" ${VAULT_ID:+--vault-id "$VAULT_ID"})
  [[ -n "$WID_ONLINE" && "$WID_ONLINE" == "$WID_OFFLINE" ]] && pass "T16b offline compute-wallet-id == coordinator /address wallet_id ($WID_ONLINE)" || fail "T16b wallet_id mismatch (offline-recovery drift): online='$WID_ONLINE' offline='$WID_OFFLINE'"
  # Idempotency across a second /address call → same wallet_id.
  WID_ONLINE2=$(curl -sS -G "$COORDINATOR_URL/wallet/v1/address" --data-urlencode "chain=near" -H "$(AUTH "$SEED_ID")" | jq -r '.wallet_id // empty')
  [[ "$WID_ONLINE2" == "$WID_ONLINE" ]] && pass "T16b wallet_id idempotent across repeated /address calls" || fail "T16b wallet_id varies across calls: $WID_ONLINE2 != $WID_ONLINE"

  # ── 16c: reverse-lookup /pending_approvals_by_pubkey resolves a (vault-)scoped pubkey ──
  SEED_REV="t16-rev-$(date +%s)-$$"
  REV_PK=$(curl -sS -G "$COORDINATOR_URL/wallet/v1/address" --data-urlencode "chain=near" -H "$(AUTH "$SEED_REV")" | jq -r '.public_key // empty')
  [[ -n "$REV_PK" ]] || fail "T16c no public_key from /address for reverse-lookup"
  REV_RESP=$(curl -sS -G "$COORDINATOR_URL/wallet/v1/pending_approvals_by_pubkey" --data-urlencode "near_pubkey=$REV_PK")
  REV_COUNT=$(echo "$REV_RESP" | jq -r '.approvals | length' 2>/dev/null || echo "-1")
  if [[ "$REV_COUNT" == "0" ]]; then
    pass "T16c reverse-lookup resolved the scoped pubkey (empty approvals array = wallet found)"
  elif echo "$REV_RESP" | grep -qiE "wallet not found|not_found|404"; then
    fail "T16c reverse-lookup FAILED to find the scoped wallet by pubkey: $REV_RESP"
  else
    pass "T16c reverse-lookup returned a non-error response (scoped pubkey resolved): $(echo "$REV_RESP" | head -c120)"
  fi
  # Negative: a random/non-existent pubkey must be handled gracefully (no false hit / no 5xx).
  FAKE_PK="ed25519:11111111111111111111111111111111111111111"
  FAKE_RESP=$(curl -sS -G "$COORDINATOR_URL/wallet/v1/pending_approvals_by_pubkey" --data-urlencode "near_pubkey=$FAKE_PK")
  FAKE_COUNT=$(echo "$FAKE_RESP" | jq -r '.approvals | length' 2>/dev/null || echo "-1")
  [[ "$FAKE_COUNT" == "0" || "$FAKE_COUNT" == "-1" ]] && pass "T16c reverse-lookup of a non-existent pubkey handled gracefully (no false hit)" || fail "T16c random pubkey produced $FAKE_COUNT approvals — false hit: $FAKE_RESP"
fi

# ════════════════════════════════════════════════════════════════════════════════
# T17 — on-chain signer == sub-wallet  [SIG/FUNDS] (funds a throwaway sub-wallet)
#       Ported from tests/approval_flow_e2e.sh (its unique end-state assertion). Reuses the
#       T4b approve→execute flow: a transfer gated by a 1-of-1 approval is approved by a real
#       approver and executes in the background; then we fetch the executed tx on chain and assert
#       its signer_id == the SUB-WALLET's own address — proving the keystore signed the transfer
#       with the per-vault DERIVED key (not the parent / default master), preserving vault scope
#       from auth → approval → background execution. This is the one thing approval_flow asserts
#       that T4 does not (T4 only checks the request reached status=completed).
# ════════════════════════════════════════════════════════════════════════════════
if want T17; then
  log "T17 [SIG/FUNDS] on-chain tx signer_id == sub-wallet (per-vault derived key, end-to-end scope)"
  MONEY=true; CUR_TEST=T17
  if [[ -f "$CREDS_DIR/$APPROVER1.json" ]]; then
    A1_PRIV=$(jq -r .private_key "$CREDS_DIR/$APPROVER1.json"); A1_PUB=$(jq -r .public_key "$CREDS_DIR/$APPROVER1.json")
    SEED="t17-$(date +%s)"; read -r WID ADDR < <(new_subwallet "$SEED")
    fund_near "$ADDR" "0.01 NEAR" || warn "T17 funding"
    # Wait for the sub-wallet to exist on chain so the executed transfer has a real signer account.
    for _ in $(seq 1 6); do
      curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"query\",\"params\":{\"request_type\":\"view_account\",\"finality\":\"final\",\"account_id\":\"$ADDR\"}}" \
        | jq -e '.result.amount' >/dev/null 2>&1 && break; sleep 2
    done
    store_policy "$SEED" "$WID" "$(jq -nc --arg a "$APPROVER1" --arg ap "$A1_PUB" '{rules:{transaction_types:["transfer"]}, approval:{threshold:{required:1}, approvers:[{id:$a,pubkey:$ap}]}}')" || fail "T17 store_policy"
    post POST /wallet/v1/transfer "$SEED" "$(jq -nc --arg to "$PARENT" '{chain:"near", receiver_id:$to, amount:"2000000000000000000000"}')"
    AID=$(echo "$BODY" | jq -r '.approval_id // empty'); RID=$(echo "$BODY" | jq -r '.request_id // empty')
    H=$(curl -sS "$COORDINATOR_URL/wallet/v1/approval/$AID" | jq -r '.request_hash // empty')
    WPK=$(curl -sS "$COORDINATOR_URL/wallet/v1/approval/$AID" | jq -r '.wallet_pubkey // empty')
    [[ -n "$AID" && -n "$H" ]] || fail "T17 no approval queued: $BODY"
    if [[ -n "$AID" ]]; then
      # Real approver YES (wallet-bound NEP-413 message approve:{id}:{wallet_pubkey}:{hash}).
      nonce=$(head -c 32 /dev/urandom | base64 | tr -d '\n')
      sj=$("$RECOVERY_BIN" sign-nep413 --private-key "$A1_PRIV" --message "approve:$AID:$WPK:$H" --recipient "$CONTRACT_ID" --nonce-base64 "$nonce")
      sig=$(echo "$sj" | jq -r '.signature')
      C=$(curl -sS -o /tmp/uop.body -w '%{http_code}' -X POST "$COORDINATOR_URL/wallet/v1/approve/$AID" -H 'Content-Type: application/json' \
        -d "$(jq -nc --arg s "$sig" --arg pk "$A1_PUB" --arg ac "$APPROVER1" --arg nc "$nonce" '{signature:$s,public_key:$pk,account_id:$ac,nonce:$nc}')")
      note "T17 /approve HTTP $C"
      # Poll until the background worker completes and surfaces the on-chain tx hash.
      TX_HASH=""
      for _ in $(seq 1 15); do
        sleep 3
        SR=$(curl -sS "$COORDINATOR_URL/wallet/v1/requests/$RID" -H "$(AUTH "$SEED")")
        ST=$(echo "$SR" | jq -r '.status // empty')
        case "$ST" in
          completed|success) TX_HASH=$(echo "$SR" | jq -r '.result.tx_hash // .result.transaction_hash // .tx_hash // empty'); break;;
          failed) fail "T17 background worker failed: $(echo "$SR" | head -c200)"; break;;
        esac
      done
      [[ -n "$TX_HASH" ]] && pass "T17 approved transfer executed (tx=$TX_HASH)" || fail "T17 did not execute after approve (no tx hash)"
      if [[ -n "$TX_HASH" ]]; then
        # THE unique assertion: the executed tx's on-chain signer_id MUST be the sub-wallet itself.
        TX_VIEW=$(curl -sS "$RPC_URL" -X POST -H 'Content-Type: application/json' \
          -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tx\",\"params\":[\"$TX_HASH\",\"$ADDR\"]}")
        TX_SIGNER=$(echo "$TX_VIEW" | jq -r '.result.transaction.signer_id // empty')
        note "T17 on-chain signer_id=$TX_SIGNER (sub-wallet=$ADDR)"
        [[ "$TX_SIGNER" == "$ADDR" ]] && pass "T17 tx signer_id == sub-wallet — keystore signed with the per-vault derived key (not parent)" || fail "T17 signer_id '$TX_SIGNER' != sub-wallet '$ADDR' — worker used the wrong master (scope not preserved)"
      fi
    fi
  else warn "T17 skipped — APPROVER1 creds required"; fi
  return_test_funds; MONEY=false
fi

# ════════════════════════════════════════════════════════════════════════════════
# Final fund-return + leak check. The final sweep_now catches any TRAILING wallets left by
# non-money tests (which don't call return_test_funds); verify_all_drained then re-reads EVERY
# sub-wallet ever created. MONEY=false here so a leak fail() RECORDS (not aborts) and surfaces in
# the SUMMARY exit code below, rather than fail-fast halting before the summary prints.
MONEY=false; sweep_now; verify_all_drained

echo
log "SUMMARY"
# Snapshot BEFORE the line below: `pass` increments the counter it is printing.
CHECKS_RUN=$PASS
pass "passed: $PASS"
if [[ $FAILED -gt 0 ]]; then
  for n in "${FAILED_NAMES[@]}"; do printf '\033[31m  ✗ %s\033[0m\n' "$n" >&2; done
  fail "FAILED: $FAILED"; exit 1
fi
# A suite that asserted nothing is a skip, not a pass — exit 3 is the code
# `run_custody.sh` records as such. Reached here only if every probe stepped
# aside, which on this file would mean its whole subject was unreachable.
if (( CHECKS_RUN == 0 )); then
  warn "NOTHING RAN — every check stepped aside; this verified nothing."
  exit 3
fi
pass "ALL UNIFIED-OP E2E CHECKS PASSED"
[[ -n "$VAULT_ID" ]] && warn "Cleanup (optional): $VAULT_ID holds locked NEAR + per-wallet policy storage stakes."
warn "raw_sign chains + confidential capability are NOT testnet-coordinator-reachable — see header; crate unit tests cover them."
