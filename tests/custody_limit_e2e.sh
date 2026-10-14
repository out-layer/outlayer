#!/usr/bin/env bash
#
# The custody ceiling on testnet: a wallet without a subscription may run 100
# custody operations a day, the 101st is a typed 429, and a subscription on
# the wallet's own key lifts it.
#
# The counted operation is a `transfer` the wallet's policy DENIES: the ceiling
# is checked before the policy, so every call counts, none reaches the chain,
# and the answer is deterministic (403 policy_denied) until the ceiling says
# 429. Nothing is moved; the run costs one `store_wallet_policy` and, for the
# subscription, the PARENT's testnet USDC (the cheapest plan's price) and NEAR.
#
#   L1  LIMIT denied transfers answer 403 policy_denied, none 429
#   L2  the next one is 429 operation_limit_reached: limit, window=day,
#       operation=custody:*, terminal=false, 0 < retry_after_seconds <= 86400,
#       and the Retry-After header carries the same number
#   L3  a subscription bought on the wallet's own key lifts the ceiling: a
#       payment key (nonce >= 1) funded with the cheapest plan's price, the
#       plan bought from it (POST /subscription/purchase), then the same
#       transfer is 403 policy_denied again
#   L4  a swap quote does not count — on testnet the route answers 503
#       service_unavailable before anything is counted, so this is a skip
#
# Run:
#   PARENT=outlayer-alice.testnet ./tests/custody_limit_e2e.sh --apply
#   LIMIT=100 is the free-tier ceiling (`operation_limits`, custody:* / day).

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/hos_common.sh"

[[ "${1:-}" == "--apply" ]] || { warn "Dry run. Pass --apply."; exit 0; }
LIMIT="${LIMIT:-100}"
hos_require

# transfer_h — a denied transfer; sets HTTP, BODY and RETRY_AFTER (the header).
RETRY_AFTER=""
transfer_h() {
  local out hdr; out=$(mktemp -t cl.XXXXXX); hdr=$(mktemp -t clh.XXXXXX); throttle
  HTTP=$(curl -sS -o "$out" -D "$hdr" -w '%{http_code}' -X POST "$COORDINATOR_URL/wallet/v1/transfer" --max-time 60 \
    -H "$(AUTH_FOR "$SEED")" -H 'Content-Type: application/json' \
    --data-binary "$(jq -nc --arg to "$PARENT" '{chain:"near", to:$to, amount:"1000000000000000000"}')" 2>/dev/null)
  BODY=$(tr -d '\n' < "$out")
  RETRY_AFTER=$(awk 'tolower($1)=="retry-after:"{gsub("\r","",$2); print $2}' "$hdr")
  rm -f "$out" "$hdr"
}

log "setup: a fresh wallet under $PARENT whose policy denies transfers"
SEED="custody-limit-$(date +%s)-$$"
read -r WALLET_ID ADDR < <(wallet_address "$SEED") || { echo "✗ no wallet" >&2; exit 1; }
note "wallet $WALLET_ID / $ADDR"
store_policy "$SEED" "$WALLET_ID" '{"rules":{"transaction_types":["call"]}}' || { echo "✗ policy not stored" >&2; exit 1; }

log "L1 $LIMIT denied transfers, each counted"
limited_at=""
for n in $(seq 1 "$LIMIT"); do
  transfer_h
  if [[ "$HTTP" == 429 ]]; then limited_at=$n; break; fi
  if [[ "$HTTP" != 403 || "$(err_of)" != policy_denied ]]; then
    fail "L1 transfer #$n answered HTTP $HTTP $(err_of): $(msg_of)"; break
  fi
done
if [[ -n "$limited_at" ]]; then fail "L1 the ceiling hit at #$limited_at, before $LIMIT"
elif [[ "$HTTP" == 403 ]]; then pass "L1 $LIMIT transfers refused by the policy, none by the ceiling"; fi

log "L2 the ${LIMIT}+1st is the ceiling"
# Checked directly, not through the assert_* helpers: those skip on a reached
# ceiling, and here the ceiling is the thing under test.
transfer_h
if [[ "$HTTP" == 429 ]]; then
  pass "L2 refused 429"
  [[ "$(err_of)" == operation_limit_reached ]] && pass "L2 error operation_limit_reached" || fail "L2 error $(err_of)"
  [[ "$(jq -r .limit <<<"$BODY")" == "$LIMIT" ]] && pass "L2 limit=$LIMIT" || fail "L2 limit $(jq -r .limit <<<"$BODY")"
  [[ "$(jq -r .window <<<"$BODY")" == day ]] && pass "L2 window=day" || fail "L2 window $(jq -r .window <<<"$BODY")"
  [[ "$(jq -r .operation <<<"$BODY")" == 'custody:*' ]] && pass "L2 operation=custody:*" || fail "L2 operation $(jq -r .operation <<<"$BODY")"
  [[ "$(bool_of terminal)" == false ]] && pass "L2 terminal=false" || fail "L2 terminal=$(bool_of terminal)"
  grep -q "limit reached: $LIMIT per day for custody" <<<"$BODY" && pass "L2 message names the ceiling" || fail "L2 message: $(msg_of)"
  RAS=$(jq -r '.retry_after_seconds // empty' <<<"$BODY")
  if [[ "$RAS" =~ ^[0-9]+$ ]] && (( RAS > 0 && RAS <= 86400 )); then pass "L2 retry_after_seconds=$RAS"
  else fail "L2 retry_after_seconds '$RAS'"; fi
  [[ -n "$RETRY_AFTER" && "$RETRY_AFTER" == "$RAS" ]] && pass "L2 Retry-After header = $RETRY_AFTER" \
    || fail "L2 Retry-After header '${RETRY_AFTER:-absent}' vs body $RAS"
else
  fail "L2 expected 429, got HTTP $HTTP $(err_of): $(msg_of)"
fi

log "L3 a subscription on the wallet's own key lifts the ceiling"
# api_pk <payment-key> <METHOD> <path> [body] — presented as X-Payment-Key.
api_pk() {
  local key=$1 method=$2 path=$3 body=${4:-} out; throttle; out=$(mktemp -t clpk.XXXXXX)
  local -a args=(-sS -o "$out" -w '%{http_code}' -X "$method" "$COORDINATOR_URL$path" --max-time 90 -H @-)
  [[ -n "$body" ]] && args+=(-H 'Content-Type: application/json' --data-binary "$body")
  HTTP=$(printf 'X-Payment-Key: %s\n' "$key" | curl "${args[@]}" 2>/dev/null); BODY=$(tr -d '\n' < "$out"); rm -f "$out"
}
SUB_KEY="wk_$(head -c 32 /dev/urandom | xxd -p -c 64)"
CLAIM=$(CUSTOMER_RECOVERY_PRIVATE_KEY="$PARENT_PRIVKEY" "$RECOVERY_BIN" sign-api-key-claim --account-id "$PARENT" --seed "$SEED" --sub-key "$SUB_KEY")
api - PUT /wallet/v1/api-key "$CLAIM" >/dev/null
if [[ "$HTTP" != 200 ]]; then
  fail "L3 could not claim a wk_ for the wallet: HTTP $HTTP $(msg_of)"
else
  # The cheapest plan's price, from the catalogue the coordinator sells from.
  api_wk "$SUB_KEY" GET /wallet/v1/subscription/purchase-info >/dev/null
  PRICE=$(jq -r '.pricing.min_purchase_usd // empty' <<<"$BODY")
  if [[ ! "$PRICE" =~ ^[0-9]+$ ]] || (( PRICE == 0 )); then
    fail "L3 purchase-info names no price (HTTP $HTTP): $(msg_of)"
  elif FUND_USDC_MINIMAL="$PRICE" DEPOSIT_USDC="$(awk -v p="$PRICE" 'BEGIN{printf "%.6f", p/1000000}')" buy_payment_key "$SUB_KEY" "$ADDR"; then
    api_pk "$PAID_KEY" POST /subscription/purchase "$(jq -nc --arg a "$PRICE" '{amount_usd:$a}')"
    BOUGHT=$(jq -r '.allowance_purchased_usd // "0"' <<<"$BODY")
    if [[ "$HTTP" == 200 && "$BOUGHT" =~ ^[0-9]+$ ]] && (( BOUGHT > 0 )); then
      pass "L3 plan '$(jq -r .plan <<<"$BODY")' bought: allowance $BOUGHT, spent $(jq -r .spent_usd <<<"$BODY")"
      transfer_h
      if [[ "$HTTP" == 403 && "$(err_of)" == policy_denied ]]; then pass "L3 the ceiling is lifted: 403 policy_denied again"
      else fail "L3 after the purchase: HTTP $HTTP $(err_of): $(msg_of)"; fi
    else
      fail "L3 purchase refused (HTTP $HTTP): $(head -c 240 <<<"$BODY")"
    fi
  else
    fail "L3 could not fund a payment key with $PRICE minimal units for the wallet"
  fi
fi

log "L4 a swap quote is not counted"
api "$SEED" POST /wallet/v1/intents/swap/quote \
  '{"token_in":"nep141:wrap.near","token_out":"nep141:usdt.tether-token.near","amount_in":"1000000000000000000000000"}' >/dev/null
if [[ "$HTTP" == 503 && "$(err_of)" == service_unavailable ]]; then
  skip "L4 swap quotes are mainnet-only (503 service_unavailable on testnet); the quote is not counted by construction (no authorize_custody_operation on the route)"
else
  fail "L4 unexpected answer to a quote on testnet: HTTP $HTTP $(err_of)"
fi

verdict "custody ceiling"
