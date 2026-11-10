#!/usr/bin/env bash
#
# The refund and withdrawal doors, tried by the WRONG account, live on TESTNET.
# ATTACKER (default outlayer-bob.testnet) goes at VICTIM's (outlayer-alice.testnet)
# closing payment key and at the contract's privileged methods; every attempt
# must be refused and leave the victim's state and both balances exactly as they
# were (.idea/_todo/dao/user-withdrawals-plan.md §1, §4).
#
#   A1  attacker close_payment_key(victim's nonce)        → "Payment key not found" (keyed by caller)
#   A2  attacker claim_payment_key_refund(victim's nonce) → "is not closing" (keyed by caller)
#   A3  attacker withdraw_balance with no balance          → "Insufficient stablecoin balance"
#   A4  attacker calls the #[private] callbacks directly   → "Method … is private" (every one)
#   A5  attacker resume_delete_payment_key with a forged Refund, resume_topup → "Only operator"
#   A6  attacker tops up the victim's CLOSING key (owner in msg) → refused, USDC back to attacker
#   A7  attacker delete_secrets(System PaymentKey, victim's nonce) → refused
#   A8  the VICTIM calls the private callbacks / the operator resumes → refused too
#   A9  afterwards: the victim's ledger, closing count, contract balance and the
#       attacker's USDC and contract balance are unchanged
#
# Needs: both accounts' legacy-keychain keys; a closing key of the victim
# (VICTIM_NONCE, default: the first closing one found among the last 30 nonces);
# the attacker holds the stablecoin and is registered on it (A6). RPC keyed
# through tests/lib/rpc.sh. Prints no secret.
#
# Run:  ./tests/payment_key_refund_attack_e2e.sh              # dry run
#       ./tests/payment_key_refund_attack_e2e.sh --apply

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/hos_common.sh"   # NETWORK, CONTRACT_ID, keyed RPC_URL, pass/fail/verdict

APPLY=false; [[ "${1:-}" == "--apply" ]] && APPLY=true
[[ "$NETWORK" == testnet ]] || { echo "✗ NETWORK=$NETWORK: testnet only" >&2; exit 2; }

ATTACKER="${ATTACKER:-outlayer-bob.testnet}"
VICTIM="${VICTIM:-outlayer-alice.testnet}"
VICTIM_NONCE="${VICTIM_NONCE:-}"
CREDS_DIR="$HOME/.near-credentials/$NETWORK"
NO_YIELD="0101010101010101010101010101010101010101010101010101010101010101"

rpc_post() {
  printf 'url = "%s"\n' "$RPC_URL" | command curl -sS --max-time 45 -K - -X POST \
    -H 'Content-Type: application/json' --data-binary "$1" 2>/dev/null
}
view() { # view <contract> <method> <args-json>
  rpc_post "$(jq -nc --arg m "$2" --arg g "$(printf '%s' "$3" | base64 | tr -d '\n')" --arg c "$1" \
    '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"call_function",finality:"final",account_id:$c,method_name:$m,args_base64:$g}}')" \
    | jq -r 'if .result.result then (.result.result | implode) else empty end' 2>/dev/null
}
call() { # call <signer> <contract> <method> <args-json> <deposit> [gas]
  local out i
  for i in 1 2; do
    out=$(near contract call-function as-transaction "$2" "$3" json-args "$4" \
      prepaid-gas "${6:-100.0 Tgas}" attached-deposit "$5" sign-as "$1" network-config "$NETWORK" \
      sign-with-legacy-keychain send 2>&1)
    grep -q 'Transaction ID' <<<"$out" && break
    grep -qiE 'error sending request|failed to fetch' <<<"$out" || break
    sleep 5
  done
  printf '%s\n' "$out"
}
succeeded() { grep -q 'succeeded' <<<"$1"; }
tx_of() { grep -oE 'Transaction ID: *[1-9A-HJ-NP-Za-km-z]{40,50}' <<<"$1" | grep -oE '[1-9A-HJ-NP-Za-km-z]{40,50}' | head -1; }
why_of() {
  local m
  m=$(grep -oE 'Smart contract panicked: [^"\\]*|panicked at [^"\\]*|ExecutionError\("[^"]*|MethodNotFound|Private[^"\\]*|is private[^"\\]*' <<<"$1" | grep -viE 'https?:|apikey' | head -2 | tr '\n' ' ' | head -c 240)
  [[ -n "$m" ]] && printf '%s' "$m" || printf 'near-cli failed without a contract panic (output withheld)'
}
# refused <label> <near-cli output> <expected-fragment>
refused() {
  if ! succeeded "$2" && grep -qi -- "$3" <<<"$2"; then pass "$1 refused: $(why_of "$2" | head -c 160)"
  elif ! succeeded "$2"; then fail "$1 refused, but not for the expected reason ($3): $(why_of "$2")"
  else fail "$1 WENT THROUGH ($(tx_of "$2")) — must be refused"; fi
}
tx_failures() { # the Failure texts of a transaction's receipts, one JSON array
  local r i
  for i in 1 2 3 4 5 6; do
    r=$(rpc_post "$(jq -nc --arg t "$1" --arg s "$2" '{jsonrpc:"2.0",id:1,method:"tx",params:{tx_hash:$t,sender_account_id:$s,wait_until:"FINAL"}}')")
    jq -e '.result' <<<"$r" >/dev/null 2>&1 && {
      jq -c '[.result.receipts_outcome[]?.outcome.status.Failure? // empty | tojson]' <<<"$r"; return 0; }
    sleep 5
  done
  echo '[]'
}
ledger() { view "$CONTRACT_ID" get_payment_key_refund_ledger "$(jq -nc --arg o "$VICTIM" --argjson n "$1" '{owner:$o, nonce:$n}')"; }
closing_count() { view "$CONTRACT_ID" get_closing_payment_key_count "$(jq -nc --arg o "$1" '{owner:$o}')"; }
user_balance() { view "$CONTRACT_ID" get_user_stablecoin_balance "$(jq -nc --arg a "$1" '{account_id:$a}')" | tr -d '"'; }
token_balance() { view "$TOKEN" ft_balance_of "$(jq -nc --arg a "$1" '{account_id:$a}')" | tr -d '"'; }
wait_eq() { local i v; for i in $(seq 1 20); do v=$("$@"); [[ "$v" == "$EXPECT" ]] && { printf '%s' "$v"; return 0; }; sleep 6; done; printf '%s' "$v"; return 1; }

# ── preflight ────────────────────────────────────────────────────────────────
log "payment_key_refund_attack_e2e — $NETWORK, $( $APPLY && echo APPLY || echo 'dry run' )"
note "RPC: $(rpc_url_public)"
for tool in jq curl near; do command -v "$tool" >/dev/null || { echo "✗ missing $tool" >&2; exit 1; }; done
for a in "$ATTACKER" "$VICTIM"; do [[ -f "$CREDS_DIR/$a.json" ]] || { echo "✗ no legacy-keychain key for $a" >&2; exit 1; }; done
TOKEN=$(view "$CONTRACT_ID" get_payment_token_contract '{}' | jq -r '. // empty')
[[ -n "$TOKEN" ]] || { echo "✗ the contract names no payment token" >&2; exit 1; }
[[ "$(view "$CONTRACT_ID" get_storage_version '{}')" == '"13"' ]] || { echo "✗ storage version is not 13" >&2; exit 1; }
if [[ -z "$VICTIM_NONCE" ]]; then
  next=$(view "$CONTRACT_ID" get_next_payment_key_nonce "$(jq -nc --arg a "$VICTIM" '{account_id:$a}')")
  for (( n = next - 1; n > next - 30 && n > 0; n-- )); do
    l=$(ledger "$n"); [[ -n "$l" && "$l" != null && "$(jq -r '.closing_since // empty' <<<"$l")" != "" ]] && { VICTIM_NONCE=$n; break; }
  done
fi
[[ -n "$VICTIM_NONCE" ]] || { echo "✗ no closing key of $VICTIM found; set VICTIM_NONCE" >&2; exit 1; }
L0=$(ledger "$VICTIM_NONCE")
note "attacker $ATTACKER; victim $VICTIM, closing key nonce $VICTIM_NONCE: $(jq -c '{refundable_cap,closing_since}' <<<"$L0")"
note "attacker holds $(token_balance "$ATTACKER") of $TOKEN; contract balance $(user_balance "$ATTACKER")"
if ! $APPLY; then sed -n '3,/^$/p' "$0" >&2; echo "  Pass --apply to run." >&2; exit 0; fi

VC0=$(closing_count "$VICTIM"); VB0=$(user_balance "$VICTIM"); AT0=$(token_balance "$ATTACKER"); AB0=$(user_balance "$ATTACKER")
nonce_arg=$(jq -nc --argjson n "$VICTIM_NONCE" '{nonce:$n}')

log "A1 attacker closes the victim's key"
refused "A1 close_payment_key($VICTIM_NONCE) by $ATTACKER" "$(call "$ATTACKER" "$CONTRACT_ID" close_payment_key "$nonce_arg" '1 yoctoNEAR')" "Payment key not found"

log "A2 attacker claims the victim's refund"
refused "A2 claim_payment_key_refund($VICTIM_NONCE) by $ATTACKER" "$(call "$ATTACKER" "$CONTRACT_ID" claim_payment_key_refund "$nonce_arg" '1 yoctoNEAR')" "is not closing"

log "A3 attacker withdraws a balance it does not have"
refused "A3 withdraw_balance(10000) by $ATTACKER (balance $AB0)" "$(call "$ATTACKER" "$CONTRACT_ID" withdraw_balance '{"amount":"10000"}' '1 yoctoNEAR')" "Insufficient stablecoin balance"

log "A4 attacker calls the private callbacks directly"
for m in on_payment_key_refund_response on_close_payment_key_response on_delete_payment_key_response on_top_up_response; do
  args=$(jq -nc --arg o "$VICTIM" --argjson n "$VICTIM_NONCE" '{owner:$o, nonce:$n, amount:"100000"}')
  refused "A4 $m by $ATTACKER" "$(call "$ATTACKER" "$CONTRACT_ID" "$m" "$args" '0 NEAR')" "private"
done
refused "A4 on_payment_key_refund_transfer by $ATTACKER" \
  "$(call "$ATTACKER" "$CONTRACT_ID" on_payment_key_refund_transfer "$(jq -nc --arg o "$VICTIM" --argjson n "$VICTIM_NONCE" '{owner:$o, nonce:$n, amount:"100000", closing_since:1}')" '0 NEAR')" "private"
refused "A4 on_withdraw_balance by $ATTACKER" \
  "$(call "$ATTACKER" "$CONTRACT_ID" on_withdraw_balance "$(jq -nc --arg a "$ATTACKER" '{account:$a, amount:"100000"}')" '0 NEAR')" "private"

log "A5 attacker resumes yields with a forged refund"
refused "A5 resume_delete_payment_key(Refund 100000) by $ATTACKER" \
  "$(call "$ATTACKER" "$CONTRACT_ID" resume_delete_payment_key "$(jq -nc --arg d "$NO_YIELD" '{data_id:$d, result:{Refund:{amount:"100000"}}}')" '0 NEAR')" "Only operator"
refused "A5 resume_topup by $ATTACKER" \
  "$(call "$ATTACKER" "$CONTRACT_ID" resume_topup "$(jq -nc --arg d "$NO_YIELD" '{data_id:$d, result:{Success:{new_encrypted_data:"x"}}}')" '0 NEAR')" "Only operator"

log "A6 attacker tops up the victim's closing key"
out=$(call "$ATTACKER" "$TOKEN" ft_transfer_call \
  "$(jq -nc --arg r "$CONTRACT_ID" --arg o "$VICTIM" --argjson n "$VICTIM_NONCE" \
      '{receiver_id:$r, amount:"10000", msg:({action:"top_up_payment_key", nonce:$n, owner:$o}|tojson)}')" '1 yoctoNEAR' '150.0 Tgas')
TX=$(tx_of "$out")
if [[ -n "$TX" ]]; then
  fails=$(tx_failures "$TX" "$ATTACKER")
  jq -e --arg s "is closing since" 'any(.[]; contains($s))' <<<"$fails" >/dev/null 2>&1 \
    && pass "A6 the contract refused the top-up on the closing key" || fail "A6 no closing refusal in $TX: $(head -c 240 <<<"$fails")"
  EXPECT=$AT0; t=$(wait_eq token_balance "$ATTACKER") && pass "A6 attacker's USDC unchanged ($t): the transfer came back" || fail "A6 attacker's USDC '$t', expected $AT0"
else
  fail "A6 transfer not sent: $(why_of "$out")"
fi

log "A7 attacker deletes the victim's secret through delete_secrets"
refused "A7 delete_secrets(System PaymentKey, $VICTIM_NONCE) by $ATTACKER" \
  "$(call "$ATTACKER" "$CONTRACT_ID" delete_secrets "$(jq -nc --argjson n "$VICTIM_NONCE" '{accessor:{System:"PaymentKey"}, profile:($n|tostring)}')" '0 NEAR')" "not deleted here"

log "A8 the victim itself cannot shortcut the callbacks or the resume"
refused "A8 on_payment_key_refund_response by $VICTIM" \
  "$(call "$VICTIM" "$CONTRACT_ID" on_payment_key_refund_response "$(jq -nc --arg o "$VICTIM" --argjson n "$VICTIM_NONCE" '{owner:$o, nonce:$n}')" '0 NEAR')" "private"
refused "A8 resume_delete_payment_key(Refund) by $VICTIM" \
  "$(call "$VICTIM" "$CONTRACT_ID" resume_delete_payment_key "$(jq -nc --arg d "$NO_YIELD" '{data_id:$d, result:{Refund:{amount:"100000"}}}')" '0 NEAR')" "Only operator"
refused "A8 delete_secrets(System PaymentKey) by $VICTIM (its own key)" \
  "$(call "$VICTIM" "$CONTRACT_ID" delete_secrets "$(jq -nc --argjson n "$VICTIM_NONCE" '{accessor:{System:"PaymentKey"}, profile:($n|tostring)}')" '0 NEAR')" "not deleted here"

log "A9 nothing moved"
L1=$(ledger "$VICTIM_NONCE")
[[ "$L1" == "$L0" ]] && pass "A9 victim's ledger unchanged: $(jq -c '{refundable_cap,refunded,closing_since}' <<<"$L1")" || fail "A9 victim's ledger changed: $L0 → $L1"
[[ "$(closing_count "$VICTIM")" == "$VC0" ]] && pass "A9 victim's closing count unchanged ($VC0)" || fail "A9 closing count $(closing_count "$VICTIM"), was $VC0"
[[ "$(user_balance "$VICTIM")" == "$VB0" ]] && pass "A9 victim's contract balance unchanged ($VB0)" || fail "A9 victim's contract balance $(user_balance "$VICTIM"), was $VB0"
[[ "$(user_balance "$ATTACKER")" == "$AB0" ]] && pass "A9 attacker's contract balance unchanged ($AB0)" || fail "A9 attacker's contract balance $(user_balance "$ATTACKER"), was $AB0"
[[ "$(token_balance "$ATTACKER")" == "$AT0" ]] && pass "A9 attacker's USDC unchanged ($AT0)" || fail "A9 attacker's USDC $(token_balance "$ATTACKER"), was $AT0"
f=$(view "$CONTRACT_ID" get_payment_key_flight "$(jq -nc --arg o "$VICTIM" --argjson n "$VICTIM_NONCE" '{owner:$o, nonce:$n}')")
[[ -z "$f" || "$f" == null || "$(jq -r '.top_ups_in_flight // 0' <<<"$f")" == 0 ]] && pass "A9 nothing left in flight on the victim's key" || fail "A9 flight: $f"

verdict
