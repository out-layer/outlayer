#!/usr/bin/env bash
#
# LIVE validation of the setup kit's EXACT transaction against the PUBLISHED
# global contract — the production path, end to end:
#
#   UseGlobalContract(by hash) + w_init(1y) + w_execute_extension(AddExtension)
#
# Companion to personal_wallet_e2e.sh (which installs the same bytes by direct
# deploy and covers the refusal matrix). This one proves what only a real
# publication can: the by-hash reference resolves, the account's reported
# code_hash equals the pinned constant, the lane works — and the owner does
# NOT pay the ~2.8 NEAR code-storage price (the account is funded with far
# less than the code would cost, so a regression to paid storage fails here).
#
# Run (spends testnet NEAR, returned by the cleanup):
#   FUNDER=zavodil.testnet EXECUTOR=zavodil2.testnet RECIPIENT=zavodil3.testnet \
#     ./tests/personal_wallet_global_e2e.sh --apply

set -uo pipefail

APPLY=false
[[ "${1:-}" == "--apply" ]] && APPLY=true

NETWORK="${NETWORK:-testnet}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/rpc.sh"   # keyed RPC_URL, or a warning
FUNDER="${FUNDER:-}"
EXECUTOR="${EXECUTOR:-}"
RECIPIENT="${RECIPIENT:-}"
# sha256 of the published no-sign build, base58 — MUST match
# WALLET_NO_SIGN_6095765F in shared-tee-helpers/src/binding.rs.
PINNED_HASH_B58="${PINNED_HASH_B58:-BwjDnyemmBhrCyuviDGpoQAm9mdjTfrX7ZjqgZB4MHvM}"

PASS=0; FAILED=0; FAILED_NAMES=()
log()  { printf '\n\033[36m▶ %s\033[0m\n' "$*" >&2; }
pass() { printf '\033[32m✓ %s\033[0m\n' "$*" >&2; PASS=$((PASS+1)); }
fail() { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; FAILED=$((FAILED+1)); FAILED_NAMES+=("$*"); }

view_on() { # view_on <account> <method> <json-args>
  curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg c "$1" --arg m "$2" --arg a "$(printf '%s' "$3" | base64 | tr -d '\n')" \
      '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"call_function",finality:"final",account_id:$c,method_name:$m,args_base64:$a}}')" \
    | jq -r '.result.result | implode' 2>/dev/null || echo 'null'
}
account_field() { # account_field <account> <field>
  curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg a "$1" \
      '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"view_account",finality:"final",account_id:$a}}')" \
    | jq -r ".result.$2" 2>/dev/null || echo 'null'
}

if [[ "$APPLY" != true ]]; then
  sed -n '3,17p' "$0" >&2
  echo "  Pass --apply to run." >&2
  exit 0
fi

[[ -n "$FUNDER" && -n "$EXECUTOR" && -n "$RECIPIENT" ]] \
  || { echo "FUNDER, EXECUTOR, RECIPIENT are required" >&2; exit 1; }

ACC="pwg-$(openssl rand -hex 3).$FUNDER"

# The account exists from here on; the trap gets it back to $FUNDER even if a
# probe below dies, rather than leaving it parked with a keychain-only key.
CREATED=""
cleanup_created() {
  [[ -z "$CREATED" ]] && return 0
  printf '\033[35m• cleaning up %s\033[0m\n' "$CREATED" >&2
  near account delete-account "$CREATED" beneficiary "$FUNDER" \
    network-config "$NETWORK" sign-with-keychain send >/dev/null 2>&1 || true
}
trap cleanup_created EXIT

# 0.5 NEAR: enough for w_init state + gas, NOT enough for 278 KB of code
# storage — so the probe doubles as proof that global reference is free of it.
log "creating $ACC with 0.5 NEAR (deliberately below the code-storage price)"
near account create-account fund-myself "$ACC" '0.5 NEAR' \
  autogenerate-new-keypair save-to-keychain sign-as "$FUNDER" \
  network-config "$NETWORK" sign-with-keychain send >/dev/null 2>&1
# Judged by the CHAIN: near-cli-rs can swallow a broadcast transient and still
# exit 0, and an account that never came to exist would surface as G1 failing.
for _ in 1 2 3 4 5 6; do
  [[ "$(account_field "$ACC" amount)" != "null" ]] && { CREATED="$ACC"; break; }
  sleep 2
done
[[ -n "$CREATED" ]] || { echo "$ACC never appeared on chain" >&2; exit 1; }

log "G1 the kit transaction verbatim: UseGlobalContract($PINNED_HASH_B58) + w_init + AddExtension"
ADD_EXT_ARGS=$(jq -nc --arg e "$EXECUTOR" \
  '{request:{internal:[{op:"add_extension",payload:{account_id:$e}}]}}')

OUT=$(near transaction construct-transaction "$ACC" receiver-id "$ACC" \
  add-action use-global-contract use-global-hash "$PINNED_HASH_B58" without-init-call \
  add-action function-call w_init json-args '{}' \
    prepaid-gas '30.0 Tgas' attached-deposit '1 yoctoNEAR' \
  add-action function-call w_execute_extension json-args "$ADD_EXT_ARGS" \
    prepaid-gas '30.0 Tgas' attached-deposit '1 yoctoNEAR' \
  skip network-config "$NETWORK" sign-with-keychain send 2>&1)

# NEP-591: with UseGlobalContract the account's own code_hash stays at the
# zero sentinel and the referenced hash sits in global_contract_hash — the
# same effective-hash rule the verifiers apply (found BY this probe).
INLINE_HASH=$(account_field "$ACC" code_hash)
GLOBAL_HASH=$(account_field "$ACC" global_contract_hash)
if [[ "$INLINE_HASH" == "11111111111111111111111111111111" && "$GLOBAL_HASH" == "$PINNED_HASH_B58" ]]; then
  pass "G1 the published global resolved by hash; global_contract_hash reports the pin (code_hash stays the zero sentinel)"
else
  fail "G1 code_hash='$INLINE_HASH' global_contract_hash='$GLOBAL_HASH' — expected sentinel + pin"
  printf '%s\n' "$OUT" | tail -10 >&2
fi

EXEC_ON=$(view_on "$ACC" w_is_extension_enabled "$(jq -nc --arg a "$EXECUTOR" '{account_id:$a}')")
[[ "$EXEC_ON" == "true" ]] \
  && pass "G1 the executor is enabled — the whole kit worked in one transaction" \
  || fail "G1 executor membership is '$EXEC_ON' after the kit transaction"

log "G2 the lane moves the wallet's funds on the executor's signature"
RCPT_BEFORE=$(account_field "$RECIPIENT" amount)
TRANSFER_ARGS=$(jq -nc --arg r "$RECIPIENT" \
  '{request:{external:[{receiver_id:$r,actions:[{action:"transfer",payload:{amount:"50000000000000000000000"}}]}]}}')
# Output KEPT. A send that never landed would otherwise report itself as a
# zero delta — i.e. as the wallet failing to move funds — and that is a whole
# evening spent on the contract instead of on the RPC. Same mistake C2 in
# connector_pricing_e2e.sh made, seen live 2026-08-18.
OUT=$(near contract call-function as-transaction "$ACC" w_execute_extension \
  json-args "$TRANSFER_ARGS" prepaid-gas '100.0 Tgas' attached-deposit '1 yoctoNEAR' \
  sign-as "$EXECUTOR" network-config "$NETWORK" sign-with-keychain send 2>&1)
if ! grep -q "succeeded" <<<"$OUT"; then
  fail "G2 the lane transfer was never accepted — this is the SEND failing, not the wallet: $(tail -c 300 <<<"$OUT")"
else
  RCPT_AFTER=$(account_field "$RECIPIENT" amount)
  RCPT_DELTA=$(python3 -c "print(int('$RCPT_AFTER')-int('$RCPT_BEFORE'))" 2>/dev/null || echo unreadable)
  [[ "$RCPT_DELTA" == "50000000000000000000000" ]] \
    && pass "G2 recipient received exactly 0.05 NEAR through the global-referenced wallet" \
    || fail "G2 recipient delta is $RCPT_DELTA"
fi

log "G3 cleanup: the owner's key deletes the account"
OUT=$(near account delete-account "$ACC" beneficiary "$FUNDER" \
  network-config "$NETWORK" sign-with-keychain send 2>&1)
if [[ "$(account_field "$ACC" amount)" == "null" ]]; then
  CREATED=""
  pass "G3 account deleted, funds returned to $FUNDER"
else
  fail "G3 the account still exists — the delete did not land: $(tail -c 300 <<<"$OUT")"
fi

printf '\n\033[1m%d passed, %d failed\033[0m\n' "$PASS" "$FAILED" >&2
for n in "${FAILED_NAMES[@]:-}"; do [[ -n "$n" ]] && printf '  \033[31m✗ %s\033[0m\n' "$n" >&2; done
[[ "$FAILED" -eq 0 ]]
