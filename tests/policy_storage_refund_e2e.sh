#!/usr/bin/env bash
#
# Who a wallet policy's storage deposit goes back to (`storage_refund_to`).
#
# A sponsor pays the deposit for a policy the owner signs; the beneficiary
# named at creation receives every refund — the excess at creation, the
# difference on a shrink, the whole deposit on a delete — and only it can move
# that. Refunds are read EXACTLY from the transaction's own receipts (transfers
# the contract made, by receiver and yoctoNEAR), so gas never blurs them.
#
#   R1  alice creates a policy naming bob → the excess goes to bob
#   R2  alice shrinks it → the difference goes to bob
#   R3  alice tries set_storage_refund_to(carol) → "Only the storage beneficiary"
#   R6  alice deletes → the whole deposit goes to bob; the policy is gone
#   R7  alice creates again under the same key without the argument → no beneficiary
#   R5  alice tries to name one on that policy → refused: named only at creation
#   R4  a new policy naming bob; bob hands it to alice → nothing moves; alice
#       shrinks → the difference goes to alice; she deletes → the deposit too
#   R8  a policy without the argument: create, shrink, delete → all to alice
#   R9  a policy created BEFORE the v10 deploy (R9_SEED) has no beneficiary and
#       cannot get one; deleting it refunds alice
#   R10 estimate_wallet_policy_cost with a beneficiary − without = the record's bytes
#
# Run:
#   PARENT=outlayer-alice.testnet SPONSOR=outlayer-bob.testnet STRANGER=outlayer-carol.testnet \
#     [R9_SEED=…] ./tests/policy_storage_refund_e2e.sh --apply
#   ./tests/policy_storage_refund_e2e.sh --prepare-r9     # BEFORE the deploy: prints R9_SEED

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/hos_common.sh"
source "$HOS_LIB_DIR/near_sign.sh"

MODE="${1:-}"
[[ "$MODE" == "--apply" || "$MODE" == "--prepare-r9" ]] || { warn "Dry run. Pass --apply (or --prepare-r9 before the deploy)."; exit 0; }

PARENT="${PARENT:-outlayer-alice.testnet}"
SPONSOR="${SPONSOR:-outlayer-bob.testnet}"
STRANGER="${STRANGER:-outlayer-carol.testnet}"
hos_require
PRICE=10000000000000000000   # yoctoNEAR per byte, as the contract charges

# policy <n> — a policy whose size grows with n (an address list, mode none).
policy() {
  jq -nc --argjson n "$1" '{rules:{transaction_types:["transfer"], addresses:{mode:"none", list:[range(0;$n) | "addr-\(.)-padding-to-make-the-policy-larger.testnet"]}}}'
}

# prep <seed> <n> — encrypt and sign a policy for the wallet of <seed>, sent by PARENT.
# Sets ENC, SIG, WPK.
prep() {
  local seed=$1 body enc sg
  body=$(jq -nc --arg wid "$(wallet_address "$seed" | cut -d' ' -f1)" --argjson p "$(policy "$2")" '$p + {wallet_id:$wid}')
  throttle
  enc=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/encrypt-policy" --max-time 60 \
    -H "$(AUTH_FOR "$seed")" -H 'Content-Type: application/json' -d "$body")
  ENC=$(jq -r '.encrypted_base64 // empty' <<<"$enc")
  [[ -n "$ENC" ]] || { warn "encrypt-policy failed: $(head -c 200 <<<"$enc")"; return 1; }
  throttle
  sg=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/sign-policy" --max-time 60 \
    -H "$(AUTH_FOR "$seed")" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg ed "$ENC" --arg c "$PARENT" '{encrypted_data:$ed, caller:$c}')")
  SIG=$(jq -r '.signature_hex // empty' <<<"$sg")
  WPK="ed25519:$(jq -r '.public_key_hex // empty' <<<"$sg")"
  [[ -n "$SIG" ]] || { warn "sign-policy failed: $(head -c 200 <<<"$sg")"; return 1; }
}

# tx <signer> <method> <args-json> <deposit> — sets OUT, RC, TXH, WHY.
tx() {
  OUT=$(near contract call-function as-transaction "$CONTRACT_ID" "$2" json-args "$3" \
    prepaid-gas '100.0 Tgas' attached-deposit "$4" sign-as "$1" network-config "$NETWORK" \
    sign-with-keychain send 2>&1); RC=$?
  TXH=$(grep -aoE 'Transaction ID: [1-9A-HJ-NP-Za-km-z]{43,44}' <<<"$OUT" | head -1 | awk '{print $3}')
  WHY=$(near_why "$OUT")
}

# refunds <tx-hash> <sender> — "receiver amount" for every transfer the contract made.
refunds() {
  curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' --max-time 60 \
    -d "$(jq -nc --arg h "$1" --arg s "$2" '{jsonrpc:"2.0",id:1,method:"EXPERIMENTAL_tx_status",params:{tx_hash:$h,sender_account_id:$s,wait_until:"FINAL"}}')" \
  | jq -r --arg c "$CONTRACT_ID" '.result.receipts[]? | select(.predecessor_id == $c)
      | .receiver_id as $r | .receipt.Action.actions[]? | select(.Transfer) | "\($r) \(.Transfer.deposit)"'
}

store() { # store <deposit> [refund_to]
  local args
  args=$(jq -nc --arg k "$WPK" --arg e "$ENC" --arg s "$SIG" --arg r "${2:-}" \
    '{wallet_pubkey:$k, encrypted_data:$e, wallet_signature:$s} + (if $r == "" then {} else {storage_refund_to:$r} end)')
  tx "$PARENT" store_wallet_policy "$args" "$1"
}
set_to() { # set_to <caller> <account>
  tx "$1" set_storage_refund_to "$(jq -nc --arg k "$WPK" --arg t "$2" '{item:{WalletPolicy:{wallet_pubkey:$k}}, storage_refund_to:$t}')" "0 NEAR"
}
view() { near_view "$CONTRACT_ID" get_wallet_policy "$(jq -nc --arg k "$WPK" '{wallet_pubkey:$k}')"; }
held() { jq -r '.storage_deposit // "null"' <<<"$(view)"; }
# "none" only for a policy that EXISTS without a beneficiary; "absent" when there is
# no policy at all — the two must never read alike, or a deleted policy passes as
# one without a beneficiary.
beneficiary() { jq -r 'if . == null then "absent" else (.storage_refund_to // "none") end' <<<"$(view)"; }
estimate() { # estimate [refund_to] — for the current ENC
  near_view "$CONTRACT_ID" estimate_wallet_policy_cost \
    "$(jq -nc --arg k "$WPK" --arg e "$ENC" --arg r "${1:-}" '{wallet_pubkey:$k, encrypted_data:$e} + (if $r == "" then {} else {storage_refund_to:$r} end)')" | jq -r .
}
yocto() { python3 -c 'import decimal,sys; print(int(decimal.Decimal(sys.argv[1]) * 10**24))' "$1"; }
sub() { python3 -c 'import sys; print(int(sys.argv[1]) - int(sys.argv[2]))' "$1" "$2"; }

# expect_refunds <case> <expected "receiver amount" lines, or empty>
expect_refunds() {
  local got; got=$(refunds "$TXH" "${SENDER:-$PARENT}" | sort)
  local want; want=$(printf '%s' "$2" | sort)
  if [[ "$got" == "$want" ]]; then pass "$1 refunds: ${want:-none}"; else fail "$1 refunds: got [${got//$'\n'/; }], want [${want//$'\n'/; }]"; fi
}
ok_tx()  { if [[ $RC -eq 0 && -n "$TXH" ]]; then return 0; fi; fail "$1 failed: $WHY"; return 1; }
refused() { if [[ $RC -ne 0 ]] && grep -qi "$2" <<<"$WHY"; then pass "$1 refused: $(head -c 120 <<<"$WHY")"; else fail "$1 expected a refusal naming /$2/, got rc=$RC: $WHY"; fi; }

DEP="0.05 NEAR"; DEP_Y=$(yocto 0.05)

if [[ "$MODE" == "--prepare-r9" ]]; then
  SEED="refund-r9-$(date +%s)-$$"
  prep "$SEED" 5 || exit 1
  store "$DEP"; ok_tx "R9 prepare" || exit 1
  echo "R9_SEED=$SEED"
  exit 0
fi

# ── R10 ───────────────────────────────────────────────────────────────────────
SEED="refund-$(date +%s)-$$"
prep "$SEED" 40 || { echo "✗ could not prepare a policy" >&2; exit 1; }
BIG_ENC=$ENC; BIG_SIG=$SIG
log "R10 the estimate with a beneficiary is the record more"
WITH=$(estimate "$SPONSOR"); WITHOUT=$(estimate)
RECORD=$(( (40 + 1 + 4 + ${#WPK} + 4 + 64) ))
[[ "$(sub "$WITH" "$WITHOUT")" == "$(python3 -c "print($RECORD * $PRICE)")" ]] \
  && pass "R10 estimate(with) − estimate(without) = $RECORD bytes" || fail "R10 with=$WITH without=$WITHOUT record=$RECORD"

# ── R1–R7: a policy created naming the sponsor ───────────────────────────────
log "R1 create naming $SPONSOR"
store "$DEP" "$SPONSOR"
if ok_tx R1; then
  expect_refunds R1 "$SPONSOR $(sub "$DEP_Y" "$WITH")"
  [[ "$(beneficiary)" == "$SPONSOR" ]] && pass "R1 the view names $SPONSOR" || fail "R1 view beneficiary $(beneficiary)"
  [[ "$(held)" == "$WITH" ]] && pass "R1 the view holds the charge" || fail "R1 held $(held), charged $WITH"
fi

log "R2 alice shrinks"
prep "$SEED" 2 || exit 1
SMALL_WITH=$(estimate "$SPONSOR"); BEFORE=$(held)
store "0 NEAR"
ok_tx R2 && expect_refunds R2 "$SPONSOR $(sub "$BEFORE" "$SMALL_WITH")"

log "R3 alice tries to move the refunds to $STRANGER"
set_to "$PARENT" "$STRANGER"
refused R3 "Only the storage beneficiary"

log "R6 alice deletes"
DEPOSIT=$(held)
tx "$PARENT" delete_wallet_policy "$(jq -nc --arg k "$WPK" '{wallet_pubkey:$k}')" "0 NEAR"
if ok_tx R6; then
  expect_refunds R6 "$SPONSOR $DEPOSIT"
  [[ "$(view)" == null ]] && pass "R6 the policy is gone" || fail "R6 view $(view | head -c 120)"
fi

log "R7 alice creates again under the same key, no argument"
prep "$SEED" 1 || exit 1
store "$DEP"
if ok_tx R7; then
  [[ "$(beneficiary)" == none ]] && pass "R7 starts without a beneficiary" || fail "R7 beneficiary $(beneficiary)"
  expect_refunds R7 "$PARENT $(sub "$DEP_Y" "$(estimate)")"
fi

log "R5 alice tries to name $SPONSOR on a policy created without one"
set_to "$PARENT" "$SPONSOR"
refused R5 "named only when the item is created"
tx "$PARENT" delete_wallet_policy "$(jq -nc --arg k "$WPK" '{wallet_pubkey:$k}')" "0 NEAR"

log "R4 a new policy naming $SPONSOR, handed to alice"
SEED4="refund4-$(date +%s)-$$"
prep "$SEED4" 40 || exit 1
store "$DEP" "$SPONSOR"; ok_tx "R4 create" || exit 1
SENDER=$SPONSOR set_to "$SPONSOR" "$PARENT"
if ok_tx "R4 hand over"; then
  SENDER=$SPONSOR expect_refunds "R4 hand over" ""
  [[ "$(beneficiary)" == "$PARENT" ]] && pass "R4 alice is the beneficiary" || fail "R4 beneficiary $(beneficiary)"
fi
prep "$SEED4" 2 || exit 1
BEFORE=$(held); SMALL=$(estimate "$PARENT")
store "0 NEAR"
ok_tx "R4 shrink" && expect_refunds "R4 shrink" "$PARENT $(sub "$BEFORE" "$SMALL")"
DEPOSIT=$(held)
tx "$PARENT" delete_wallet_policy "$(jq -nc --arg k "$WPK" '{wallet_pubkey:$k}')" "0 NEAR"
ok_tx "R4 delete" && expect_refunds "R4 delete" "$PARENT $DEPOSIT"

# ── R8: no argument, as before ───────────────────────────────────────────────
log "R8 a policy without the argument"
SEED8="refund8-$(date +%s)-$$"
prep "$SEED8" 40 || exit 1
NEED=$(estimate)
store "$DEP"
ok_tx "R8 create" && expect_refunds "R8 create" "$PARENT $(sub "$DEP_Y" "$NEED")"
prep "$SEED8" 2 || exit 1
BEFORE=$(held); NEED=$(estimate)
store "0 NEAR"
ok_tx "R8 shrink" && expect_refunds "R8 shrink" "$PARENT $(sub "$BEFORE" "$NEED")"
DEPOSIT=$(held)
tx "$PARENT" delete_wallet_policy "$(jq -nc --arg k "$WPK" '{wallet_pubkey:$k}')" "0 NEAR"
ok_tx "R8 delete" && expect_refunds "R8 delete" "$PARENT $DEPOSIT"

# ── R9: a policy from before the deploy ──────────────────────────────────────
if [[ -n "${R9_SEED:-}" ]]; then
  log "R9 a policy created before v10 ($R9_SEED)"
  prep "$R9_SEED" 5 || exit 1
  if [[ "$(beneficiary)" == absent ]]; then
    skip "R9 the policy of $R9_SEED no longer exists (deleted by an earlier run?) — a pre-v10 policy can only be prepared before the deploy"
  else
  [[ "$(beneficiary)" == none ]] && pass "R9 the old policy has no beneficiary" || fail "R9 beneficiary $(beneficiary)"
  set_to "$PARENT" "$SPONSOR"
  refused "R9 cannot get one" "named only when the item is created"
  DEPOSIT=$(held)
  tx "$PARENT" delete_wallet_policy "$(jq -nc --arg k "$WPK" '{wallet_pubkey:$k}')" "0 NEAR"
  ok_tx "R9 delete" && expect_refunds "R9 delete" "$PARENT $DEPOSIT"
  fi
else
  skip "R9 needs R9_SEED: run --prepare-r9 BEFORE the v10 deploy"
fi

verdict "policy storage refund"
