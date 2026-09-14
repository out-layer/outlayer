#!/usr/bin/env bash
#
# LIVE probes for the personal_account binding mode's on-chain half: the
# upstream no-sign wallet (`defuse-wallet-no-sign`) behaving, on real testnet
# accounts with real NEAR, exactly the way our verifier, setup kit and docs
# claim it does. Unit tests pin our reading of the source; these pin the
# chain's reading of the same source.
#
# What is deliberately DIFFERENT from production setup: the wasm is deployed
# directly (DeployContract) instead of by global-contract reference, because
# publishing the global is a one-off human action. The two paths install the
# same bytes, and `view_account.code_hash` reports the same sha256 either way —
# which probe P2 turns into evidence: the hash our allowlist pins is the hash
# the CHAIN reports for this artifact.
#
# Probes:
#   P1  the kit's transaction shape works: install + w_init(1y) +
#       w_execute_extension(AddExtension(executor), 1y) — ONE tx, three actions
#   P2  view_account.code_hash == the pinned WALLET_NO_SIGN_6095765F (base58)
#   P3  w_is_extension_enabled: true for the executor, false for a stranger
#   P4  the lane moves funds: executor sends 0.05 NEAR from the wallet balance to a
#       recipient through w_execute_extension (1-yocto marker, funds from the
#       account, not the executor)
#   P5  w_init with 0 yocto fails and rolls back the whole batch (the account
#       stays codeless)
#   P6  w_init by a NON-self caller fails (#[private])
#   P7  a second w_init fails (already initialized)
#   P8  RemoveExtension(executor) by the owner → membership answers false —
#       the mode's one revocation event, observable without any webhook
#   P9  the owner's keys stay the higher power: DeleteAccount by key works,
#       funds return to the funder
#
# Run (spends testnet NEAR; ~6 NEAR out, returned by the P9 cleanups):
#   FUNDER=zavodil.testnet EXECUTOR=zavodil2.testnet RECIPIENT=zavodil3.testnet \
#     ./tests/personal_wallet_e2e.sh --apply
#
# Read-only by default: prints the plan and exits.

set -uo pipefail

APPLY=false
[[ "${1:-}" == "--apply" ]] && APPLY=true

NETWORK="${NETWORK:-testnet}"
# The RPC every probe here reads through — keyed, or a warning (lib/rpc.sh).
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/rpc.sh"
FUNDER="${FUNDER:-}"
EXECUTOR="${EXECUTOR:-}"
RECIPIENT="${RECIPIENT:-}"
WASM="${WASM:-$HOME/projects/defuse_wallet/target/near/defuse_wallet_no_sign/defuse_wallet_no_sign.wasm}"
# sha256 of the reproducible no-sign build @6095765f, base58 — MUST match
# WALLET_NO_SIGN_6095765F in shared-tee-helpers/src/binding.rs.
PINNED_HASH_B58="BwjDnyemmBhrCyuviDGpoQAm9mdjTfrX7ZjqgZB4MHvM"

PASS=0; FAILED=0; FAILED_NAMES=()
log()  { printf '\n\033[36m▶ %s\033[0m\n' "$*" >&2; }
note() { printf '\033[35m• %s\033[0m\n' "$*" >&2; }
pass() { printf '\033[32m✓ %s\033[0m\n' "$*" >&2; PASS=$((PASS+1)); }
fail() { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; FAILED=$((FAILED+1)); FAILED_NAMES+=("$*"); }

# A view call against an arbitrary account's contract.
view_on() { # view_on <account> <method> <json-args>
  curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg c "$1" --arg m "$2" --arg a "$(printf '%s' "$3" | base64 | tr -d '\n')" \
      '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"call_function",finality:"final",account_id:$c,method_name:$m,args_base64:$a}}')" \
    | jq -r '.result.result | implode' 2>/dev/null || echo 'null'
}

account_field() { # account_field <account> <jq-path over .result>
  curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg a "$1" \
      '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"view_account",finality:"final",account_id:$a}}')" \
    | jq -r ".result.$2" 2>/dev/null || echo 'null'
}

# A change call to a specific contract. Whole output kept in $OUT.
OUT=""
call_on() { # call_on <contract> <signer> <method> <json-args> <deposit> [gas]
  OUT=$(near contract call-function as-transaction "$1" "$3" \
          json-args "$4" prepaid-gas "${6:-100.0 Tgas}" attached-deposit "$5" \
          sign-as "$2" network-config "$NETWORK" sign-with-keychain send 2>&1)
  grep -q "succeeded" <<<"$OUT"
}
refused_with() { grep -qi "$1" <<<"$OUT"; }

if [[ "$APPLY" != true ]]; then
  sed -n '3,32p' "$0" >&2
  echo "  Pass --apply to run." >&2
  exit 0
fi

[[ -n "$FUNDER" ]]    || { echo "FUNDER=<account> is required" >&2; exit 1; }
[[ -n "$EXECUTOR" ]]  || { echo "EXECUTOR=<account with a key> is required" >&2; exit 1; }
[[ -n "$RECIPIENT" ]] || { echo "RECIPIENT=<account> is required" >&2; exit 1; }
[[ -f "$WASM" ]]      || { echo "wasm not found at $WASM (WASM=<path> to override)" >&2; exit 1; }

RAND=$(openssl rand -hex 3)
ACC_A="pwa-$RAND.$FUNDER"
ACC_B="pwb-$RAND.$FUNDER"

note "wallet account A: $ACC_A (kit-shape install + lane probes)"
note "wallet account B: $ACC_B (w_init refusal probes)"
note "executor stand-in: $EXECUTOR; recipient: $RECIPIENT"

# Accounts this run brought into existence and has not yet deleted. The trap
# below empties it, so an interrupted run does not leave 3.5 NEAR apiece parked
# in accounts whose only keys are in this machine's keychain.
CREATED=()
cleanup_created() {
  for acc in "${CREATED[@]:-}"; do
    [[ -z "$acc" ]] && continue
    printf '\033[35m• cleaning up %s\033[0m\n' "$acc" >&2
    near account delete-account "$acc" beneficiary "$FUNDER" \
      network-config "$NETWORK" sign-with-keychain send >/dev/null 2>&1 || true
  done
}
trap cleanup_created EXIT

forget_created() { # drop an account the script deleted on purpose
  local keep=() a
  for a in "${CREATED[@]:-}"; do [[ -n "$a" && "$a" != "$1" ]] && keep+=("$a"); done
  CREATED=("${keep[@]:-}")
}

create_account() { # create_account <name> <amount>
  near account create-account fund-myself "$1" "$2" \
    autogenerate-new-keypair save-to-keychain sign-as "$FUNDER" \
    network-config "$NETWORK" sign-with-keychain send >/dev/null 2>&1
  # Judged by the CHAIN, not by the exit status: near-cli-rs can swallow a
  # broadcast transient and still exit 0, and an account that never came to
  # exist surfaces three probes later as "the kit transaction failed".
  for _ in 1 2 3 4 5 6; do
    [[ "$(account_field "$1" amount)" != "null" ]] && { CREATED+=("$1"); return 0; }
    sleep 2
  done
  return 1
}

log "creating $ACC_A and $ACC_B"
# 278 KB of contract code costs ~2.78 NEAR in storage; fund with headroom.
create_account "$ACC_A" '3.5 NEAR' || { echo "$ACC_A never appeared on chain" >&2; exit 1; }
create_account "$ACC_B" '3.5 NEAR' || { echo "$ACC_B never appeared on chain" >&2; exit 1; }

# ── P1: the kit's transaction — one tx, three actions ────────────────────────
log "P1 install + w_init(1y) + AddExtension(executor) in ONE transaction"

ADD_EXT_ARGS=$(jq -nc --arg e "$EXECUTOR" \
  '{request:{internal:[{op:"add_extension",payload:{account_id:$e}}]}}')

OUT=$(near transaction construct-transaction "$ACC_A" receiver-id "$ACC_A" \
  add-action deploy-contract use-file "$WASM" without-init-call \
  add-action function-call w_init json-args '{}' \
    prepaid-gas '30.0 Tgas' attached-deposit '1 yoctoNEAR' \
  add-action function-call w_execute_extension json-args "$ADD_EXT_ARGS" \
    prepaid-gas '30.0 Tgas' attached-deposit '1 yoctoNEAR' \
  skip network-config "$NETWORK" sign-with-keychain send 2>&1)

if grep -q "succeeded" <<<"$OUT"; then
  pass "P1 the three-action install transaction succeeded"
else
  fail "P1 the kit-shape transaction failed"
  printf '%s\n' "$OUT" | tail -12 >&2
fi

# ── P2: the chain reports the hash our allowlist pins ────────────────────────
log "P2 view_account.code_hash equals the pinned build hash"

GOT_HASH=$(account_field "$ACC_A" code_hash)
if [[ "$GOT_HASH" == "$PINNED_HASH_B58" ]]; then
  pass "P2 code_hash is $GOT_HASH — exactly WALLET_NO_SIGN_6095765F"
else
  fail "P2 code_hash is '$GOT_HASH', pinned is '$PINNED_HASH_B58' — the verifier would refuse this install"
fi

# ── P3: membership answers ───────────────────────────────────────────────────
log "P3 w_is_extension_enabled: executor true, stranger false"

EXEC_ON=$(view_on "$ACC_A" w_is_extension_enabled "$(jq -nc --arg a "$EXECUTOR" '{account_id:$a}')")
STRANGER_ON=$(view_on "$ACC_A" w_is_extension_enabled "$(jq -nc --arg a "$RECIPIENT" '{account_id:$a}')")
[[ "$EXEC_ON" == "true" ]] \
  && pass "P3 the executor is an enabled extension" \
  || fail "P3 the executor is NOT enabled after AddExtension (got '$EXEC_ON')"
[[ "$STRANGER_ON" == "false" ]] \
  && pass "P3 a stranger is not" \
  || fail "P3 a stranger reads as enabled (got '$STRANGER_ON')"

# ── P4: the lane moves the WALLET's funds on the executor's signature ────────
log "P4 executor sends 0.05 NEAR from the wallet account through the lane"

RCPT_BEFORE=$(account_field "$RECIPIENT" amount)
A_BEFORE=$(account_field "$ACC_A" amount)

TRANSFER_ARGS=$(jq -nc --arg r "$RECIPIENT" \
  '{request:{external:[{receiver_id:$r,actions:[{action:"transfer",payload:{amount:"50000000000000000000000"}}]}]}}')

if call_on "$ACC_A" "$EXECUTOR" w_execute_extension "$TRANSFER_ARGS" '1 yoctoNEAR'; then
  RCPT_AFTER=$(account_field "$RECIPIENT" amount)
  A_AFTER=$(account_field "$ACC_A" amount)
  RCPT_DELTA=$(python3 -c "print(int('$RCPT_AFTER')-int('$RCPT_BEFORE'))")
  A_DELTA=$(python3 -c "print(int('$A_BEFORE')-int('$A_AFTER'))")
  [[ "$RCPT_DELTA" == "50000000000000000000000" ]] \
    && pass "P4 the recipient received exactly 0.05 NEAR" \
    || fail "P4 recipient delta is $RCPT_DELTA, expected 50000000000000000000000"
  # ≥0.049 NEAR, not ≥0.05 exactly: gas refunds land back on the account and
  # shave a few 1e19 off the raw delta. What matters is that the WALLET paid.
  python3 -c "exit(0 if int('$A_DELTA') >= 49000000000000000000000 else 1)" \
    && pass "P4 the funds left the WALLET account's balance (delta $A_DELTA)" \
    || fail "P4 the wallet account's balance did not drop (delta $A_DELTA)"
else
  fail "P4 the lane transfer failed"
  printf '%s\n' "$OUT" | tail -8 >&2
fi

# ── P5: w_init with 0 yocto rolls the whole batch back ───────────────────────
log "P5 install + w_init(0 yocto) in one tx fails and leaves B codeless"

OUT=$(near transaction construct-transaction "$ACC_B" receiver-id "$ACC_B" \
  add-action deploy-contract use-file "$WASM" without-init-call \
  add-action function-call w_init json-args '{}' \
    prepaid-gas '30.0 Tgas' attached-deposit '0 NEAR' \
  skip network-config "$NETWORK" sign-with-keychain send 2>&1)

if grep -q "succeeded" <<<"$OUT"; then
  fail "P5 w_init with 0 yocto SUCCEEDED — the FunctionCall-key guard is not there"
else
  pass "P5 the 0-yocto w_init was refused"
  B_HASH=$(account_field "$ACC_B" code_hash)
  [[ "$B_HASH" == "11111111111111111111111111111111" ]] \
    && pass "P5 the failed batch rolled back the deploy too (B is codeless)" \
    || fail "P5 B carries code after a failed batch (hash $B_HASH)"
fi

# ── P6/P7: w_init is self-only, and once ─────────────────────────────────────
log "P6 deploy to B, then w_init by a NON-self caller must fail"

# Success is judged by the CHAIN (code_hash landed), not by grepping CLI
# phrasing — `near contract deploy` words its success differently from
# `call-function`, and an output-format change must not fail a probe.
near contract deploy "$ACC_B" use-file "$WASM" without-init-call \
  network-config "$NETWORK" sign-with-keychain send >/dev/null 2>&1
B_HASH=$(account_field "$ACC_B" code_hash)
[[ "$B_HASH" == "$PINNED_HASH_B58" ]] \
  && pass "P6 plain deploy to B landed (code_hash matches)" \
  || fail "P6 plain deploy to B did not land (code_hash $B_HASH)"

if call_on "$ACC_B" "$EXECUTOR" w_init '{}' '1 yoctoNEAR'; then
  fail "P6 a NON-self w_init SUCCEEDED — #[private] does not hold"
elif refused_with "private"; then
  pass "P6 w_init by another account was refused (#[private])"
else
  fail "P6 w_init failed, but NOT for the #[private] reason — see output"
  printf '%s\n' "$OUT" | tail -6 >&2
fi

log "P7 self w_init once — and only once"
if call_on "$ACC_B" "$ACC_B" w_init '{}' '1 yoctoNEAR'; then
  pass "P7 self w_init succeeded"
  if call_on "$ACC_B" "$ACC_B" w_init '{}' '1 yoctoNEAR'; then
    fail "P7 a SECOND w_init succeeded — state can be re-initialized"
  elif refused_with "initialized"; then
    pass "P7 a second w_init was refused (already initialized)"
  else
    fail "P7 the second w_init failed for an unexpected reason — see output"
    printf '%s\n' "$OUT" | tail -6 >&2
  fi
else
  fail "P7 self w_init failed"
  printf '%s\n' "$OUT" | tail -6 >&2
fi

# ── P8: the mode's one revocation event ──────────────────────────────────────
log "P8 owner removes the executor; membership flips to false"

RM_EXT_ARGS=$(jq -nc --arg e "$EXECUTOR" \
  '{request:{internal:[{op:"remove_extension",payload:{account_id:$e}}]}}')

if call_on "$ACC_A" "$ACC_A" w_execute_extension "$RM_EXT_ARGS" '1 yoctoNEAR'; then
  EXEC_ON=$(view_on "$ACC_A" w_is_extension_enabled "$(jq -nc --arg a "$EXECUTOR" '{account_id:$a}')")
  [[ "$EXEC_ON" == "false" ]] \
    && pass "P8 the executor is gone from the extension set — pre-flight would refuse the next call with no webhook involved" \
    || fail "P8 membership still answers '$EXEC_ON' after RemoveExtension"
else
  fail "P8 the owner's RemoveExtension failed"
  printf '%s\n' "$OUT" | tail -6 >&2
fi

# ── P9: the owner's keys outrank the construction ────────────────────────────
log "P9 DeleteAccount by key returns the funds"

FUNDER_BEFORE=$(account_field "$FUNDER" amount)
DEL_OK=true
for ACC in "$ACC_A" "$ACC_B"; do
  OUT=$(near account delete-account "$ACC" beneficiary "$FUNDER" \
    network-config "$NETWORK" sign-with-keychain send 2>&1)
  if grep -q "succeeded\|deleted" <<<"$OUT"; then
    forget_created "$ACC"
  else
    DEL_OK=false; fail "P9 could not delete $ACC"; printf '%s\n' "$OUT" | tail -4 >&2
  fi
done
if $DEL_OK; then
  FUNDER_AFTER=$(account_field "$FUNDER" amount)
  python3 -c "exit(0 if int('$FUNDER_AFTER') > int('$FUNDER_BEFORE') else 1)" \
    && pass "P9 both accounts deleted by their keys; balance returned to $FUNDER" \
    || fail "P9 accounts deleted but no balance returned"
fi

printf '\n\033[1m%d passed, %d failed\033[0m\n' "$PASS" "$FAILED" >&2
for n in "${FAILED_NAMES[@]:-}"; do [[ -n "$n" ]] && printf '  \033[31m✗ %s\033[0m\n' "$n" >&2; done
[[ "$FAILED" -eq 0 ]]
