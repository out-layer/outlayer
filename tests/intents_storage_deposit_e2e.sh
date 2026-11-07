#!/usr/bin/env bash
# POST /wallet/v1/intents/storage-deposit — a token registration paid from the
# wallet's wNEAR inside intents.near. MAINNET ONLY: NEAR Intents has no testnet
# solvers and the coordinator answers 503 there before reading the body.
#
#   S1 a token that is not a NEAR contract id → 400 bad_request, nothing asked
#   S2 an account already registered (intents.near on USDC) → success,
#      already_registered, no amount, nothing paid
#   S3 a withdraw dry-run to a fresh implicit account → storage_not_registered,
#      and the message names both registering calls with the receiver
#   S4 [MONEY, SD_MONEY=1] a fresh implicit account is registered on USDC:
#      success (or processing, polled to success), the amount is the token's
#      storage_balance_bounds().min, the chain shows the registration, the
#      same call again is already_registered, the dry-run would now succeed.
#      Costs the token's storage minimum in wNEAR (0.00125 NEAR on USDC),
#      never refunded.
#
# Required env:
#   WALLET_API_KEY   wk_… of a MAINNET custody wallet; for S4 it holds at least
#                    the storage minimum of USDC in intents wNEAR
# Optional:
#   API              default https://api.outlayer.ai
#   TOKEN            default USDC 17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1
#   SD_MONEY=1       run S4
#
# Run:
#   set -a; source <file holding WALLET_API_KEY>; set +a; SD_MONEY=1 ./tests/intents_storage_deposit_e2e.sh
set -uo pipefail

: "${WALLET_API_KEY:?the wk_ key of a mainnet wallet, exported from a file and never typed on the command line}"
NETWORK=mainnet
API="${API:-https://api.outlayer.ai}"
TOKEN="${TOKEN:-17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1}"
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib/rpc.sh
source "$HERE/lib/rpc.sh"

PASS=0; FAIL=0
pass() { echo "  ✓ $*"; PASS=$((PASS + 1)); }
fail() { echo "  ✗ $*"; FAIL=$((FAIL + 1)); }
log()  { echo; echo "── $*"; }

# post <path> <json> → HTTP, BODY
post() {
  local out
  out=$(curl -s -w '\n%{http_code}' -X POST "$API$1" \
    -H "Authorization: Bearer $WALLET_API_KEY" -H 'Content-Type: application/json' -d "$2")
  HTTP=$(tail -n1 <<<"$out"); BODY=$(sed '$d' <<<"$out")
}
get() {
  local out
  out=$(curl -s -w '\n%{http_code}' "$API$1" -H "Authorization: Bearer $WALLET_API_KEY")
  HTTP=$(tail -n1 <<<"$out"); BODY=$(sed '$d' <<<"$out")
}
# view <contract> <method> <args-json> → the view's JSON value
view() {
  local args
  args=$(printf '%s' "$3" | base64 | tr -d '\n')
  curl -s "$RPC_URL" -H 'Content-Type: application/json' -d "$(jq -nc --arg c "$1" --arg m "$2" --arg a "$args" \
    '{jsonrpc:"2.0",id:"v",method:"query",params:{request_type:"call_function",finality:"final",account_id:$c,method_name:$m,args_base64:$a}}')" \
    | jq -r '.result.result // empty | implode' 2>/dev/null
}

KEY_HEAD=${WALLET_API_KEY:0:4}; KEY_LEN=${#WALLET_API_KEY}
echo "API $API | RPC $(rpc_url_public) | token $TOKEN | wallet key $KEY_HEAD... ($KEY_LEN chars)"

# ── S1 ───────────────────────────────────────────────────────────────────────
log "S1 a token that is not a NEAR contract"
post /wallet/v1/intents/storage-deposit '{"token":"1cs_v1:near:nep141:usdc.near"}'
[[ "$HTTP" == 400 && "$(jq -r .error <<<"$BODY")" == bad_request ]] && pass "S1 400 bad_request" \
  || fail "S1 HTTP $HTTP $(head -c 200 <<<"$BODY")"

# ── S2 ───────────────────────────────────────────────────────────────────────
log "S2 an account already registered costs nothing"
post /wallet/v1/intents/storage-deposit "$(jq -nc --arg t "$TOKEN" '{token:$t,account_id:"intents.near"}')"
if [[ "$HTTP" == 200 && "$(jq -r .status <<<"$BODY")" == success && "$(jq -r .already_registered <<<"$BODY")" == true ]]; then
  pass "S2 success, already_registered"
  [[ "$(jq -r '.amount // empty' <<<"$BODY")" == "" ]] && pass "S2 no amount paid" || fail "S2 amount $(jq -r .amount <<<"$BODY")"
else
  fail "S2 HTTP $HTTP $(head -c 200 <<<"$BODY")"
fi

# ── S3 ───────────────────────────────────────────────────────────────────────
FRESH=$(openssl rand -hex 32)
log "S3 a withdraw dry-run to a fresh account ($FRESH)"
post /wallet/v1/intents/withdraw/dry-run "$(jq -nc --arg t "$TOKEN" --arg to "$FRESH" '{to:$to,amount:"1",token:$t,chain:"near"}')"
if [[ "$(jq -r .reason <<<"$BODY")" == storage_not_registered ]]; then
  pass "S3 storage_not_registered"
  msg=$(jq -r .message <<<"$BODY")
  [[ "$msg" == *"POST /wallet/v1/intents/storage-deposit"* && "$msg" == *"POST /wallet/v1/storage-deposit"* && "$msg" == *"\"account_id\":\"$FRESH\""* ]] \
    && pass "S3 the message names both calls with the receiver" || fail "S3 message: $msg"
else
  fail "S3 HTTP $HTTP $(head -c 200 <<<"$BODY")"
fi

# ── S4 ───────────────────────────────────────────────────────────────────────
if [[ "${SD_MONEY:-}" != 1 ]]; then
  log "S4 skipped (SD_MONEY=1 pays the storage minimum in wNEAR)"
else
  log "S4 register $FRESH on $TOKEN from intents wNEAR"
  MIN=$(view "$TOKEN" storage_balance_bounds '{}' | jq -r .min)
  [[ "$MIN" =~ ^[0-9]+$ ]] || fail "S4 storage_balance_bounds unreadable"
  post /wallet/v1/intents/storage-deposit "$(jq -nc --arg t "$TOKEN" --arg a "$FRESH" '{token:$t,account_id:$a}')"
  ST=$(jq -r .status <<<"$BODY"); RID=$(jq -r .request_id <<<"$BODY")
  echo "  answer: HTTP $HTTP status $ST request $RID"
  [[ "$(jq -r .amount <<<"$BODY")" == "$MIN" ]] && pass "S4 paid the token's minimum ($MIN)" || fail "S4 amount $(jq -r .amount <<<"$BODY") ≠ $MIN"
  for _ in $(seq 1 30); do
    [[ "$ST" == processing ]] || break
    sleep 2   # the registration is a detached receipt after the intent; poll the request until it lands
    get "/wallet/v1/requests/$RID"; ST=$(jq -r .status <<<"$BODY")
  done
  [[ "$ST" == success ]] && pass "S4 success" || fail "S4 ended $ST: $(head -c 300 <<<"$BODY")"
  [[ "$(view "$TOKEN" storage_balance_of "$(jq -nc --arg a "$FRESH" '{account_id:$a}')")" != null ]] \
    && pass "S4 the chain shows the registration" || fail "S4 storage_balance_of is null"

  post /wallet/v1/intents/storage-deposit "$(jq -nc --arg t "$TOKEN" --arg a "$FRESH" '{token:$t,account_id:$a}')"
  [[ "$(jq -r .already_registered <<<"$BODY")" == true ]] && pass "S4 the same call again is already_registered" \
    || fail "S4 repeat: $(head -c 200 <<<"$BODY")"

  post /wallet/v1/intents/withdraw/dry-run "$(jq -nc --arg t "$TOKEN" --arg to "$FRESH" '{to:$to,amount:"1",token:$t,chain:"near"}')"
  [[ "$(jq -r .reason <<<"$BODY")" != storage_not_registered ]] && pass "S4 the dry-run no longer refuses for storage" \
    || fail "S4 dry-run still storage_not_registered"
fi

echo; echo "passed $PASS, failed $FAIL"
[[ "$FAIL" == 0 ]]
