#!/usr/bin/env bash
# A wallet call whose outcome the node cannot report in time is charged once and answered
# `processing` — never an error, never uncharged.
#
# `POST /wallet/v1/call` broadcasts with `broadcast_tx_commit`. A call that yields —
# `request_execution` waits for a worker — outlives the node's wait, and the node answers
# PENDING / TIMEOUT_ERROR while the transaction runs. The coordinator then:
#   U1  answers HTTP 200 `status: "processing"` with the request id, the tx hash and a
#       `poll_url` (not a 500 with no id);
#   U2  has already charged the call to the wallet's velocity counters (the deposit, one
#       transaction) and marked the row `usage_charged`, the row still `processing`;
#   U3  settles the row from the chain when the `poll_url` is read: `success`;
#   U4  and charges nothing a second time doing so.
# A call the node answers in time proves nothing here and is reported INCONCLUSIVE (raise
# SLEEP_SECONDS).
#
#   PSQL_CMD=.idea/testnet-runners/psql_testnet.sh tests/wallet_call_unknown_outcome_e2e.sh --apply
#
# Testnet. FUNDER (default outlayer-alice.testnet) funds a fresh wallet with FUND NEAR; the
# wallet attaches DEPOSIT NEAR to one request_execution of the `sleep` of PROJECT's active
# wasm, named by its URL: a project prices its operations in attached_usd, a bare wasm is paid
# in NEAR alone. PSQL_CMD runs one
# SQL statement against the coordinator's database (the counters have no API).
set -uo pipefail
[[ "${1:-}" == "--apply" ]] || { sed -n 2,22p "$0"; exit 0; }
cd "$(dirname "$0")/.."
source tests/lib/rpc.sh

NETWORK="${NETWORK:-testnet}"
COORDINATOR_URL="${COORDINATOR_URL:-https://testnet-api.outlayer.ai}"
CONTRACT_ID="${CONTRACT_ID:-outlayer.testnet}"
FUNDER="${FUNDER:-outlayer-alice.testnet}"
FUND="${FUND:-0.5}"
DEPOSIT="${DEPOSIT:-0.1}"
PROJECT="${PROJECT:-connectors.outlayer.testnet/connector-probe}"
SLEEP_SECONDS="${SLEEP_SECONDS:-40}"
PSQL_CMD="${PSQL_CMD:?PSQL_CMD — one SQL statement against the coordinator database}"

PASS=0; FAIL=0
pass() { echo "✓ $*"; PASS=$((PASS + 1)); }
fail() { echo "✗ $*"; FAIL=$((FAIL + 1)); }
sql() { bash "$PSQL_CMD" "$1" 2>/dev/null; }
yocto() { python3 -I -c "from decimal import Decimal; print(int(Decimal('$1') * 10**24))"; }
finish() { echo; echo "▶ wallet call, unknown outcome — $PASS passed, $FAIL failed"; [[ $FAIL -eq 0 ]]; exit $?; }

echo "• RPC: $(rpc_url_public)"
echo "▶ Fixture: a fresh wallet, funded"
REG=$(curl -sS --max-time 30 -X POST "$COORDINATOR_URL/register")
KEY=$(jq -r '.api_key // empty' <<<"$REG"); WALLET_ID=$(jq -r '.wallet_id // empty' <<<"$REG")
[[ -n "$KEY" && -n "$WALLET_ID" ]] || { fail "register: $(head -c 200 <<<"$REG")"; finish; }
ADDR=$(curl -sS --max-time 30 -H @<(printf '%s\n' "Authorization: Bearer $KEY") "$COORDINATOR_URL/wallet/v1/address?chain=near" | jq -r '.address // empty')
[[ -n "$ADDR" ]] || { fail "no NEAR address for the wallet"; finish; }
echo "• wallet $WALLET_ID, NEAR account $ADDR"
# A plain transfer transaction: `near tokens send-near` asks on a TTY before it funds an
# implicit account that does not exist yet.
near transaction construct-transaction "$FUNDER" "$ADDR" add-action transfer "$FUND NEAR" skip \
  network-config "$NETWORK" sign-with-legacy-keychain send >/dev/null 2>&1 \
  || { fail "could not fund $ADDR from $FUNDER"; finish; }
for _ in $(seq 1 20); do
  curl -sS "$RPC_URL" -H 'content-type: application/json' \
    -d "$(jq -nc --arg a "$ADDR" '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"view_account",finality:"final",account_id:$a}}')" \
    | jq -e '.result.amount' >/dev/null 2>&1 && break
  sleep 2
done
echo "• funded with $FUND NEAR by $FUNDER"

echo "▶ U1 a call that outlives the node's wait"
DEP_Y=$(yocto "$DEPOSIT")
view() { near contract call-function as-read-only "$CONTRACT_ID" "$1" json-args "$2" network-config "$NETWORK" now 2>/dev/null | sed -n '/^{/,$p'; }
ACTIVE=$(view get_project "$(jq -nc --arg p "$PROJECT" '{project_id:$p}')" | jq -r '.active_version // empty')
SOURCE=$(view get_version "$(jq -nc --arg p "$PROJECT" --arg v "$ACTIVE" '{project_id:$p, version_key:$v}')" | jq -c '.source.WasmUrl // empty | {WasmUrl:.}')
[[ -n "$SOURCE" ]] || { fail "no WasmUrl for the active version of $PROJECT"; finish; }
echo "• source: $(jq -r '.WasmUrl.url' <<<"$SOURCE")"
ARGS=$(jq -nc --argjson src "$SOURCE" --arg i "$(jq -nc --argjson s "$SLEEP_SECONDS" '{operation:"sleep", seconds:$s}')" --argjson t "$((SLEEP_SECONDS + 20))" \
  '{source:$src, input_data:$i, resource_limits:{max_instructions:1000000000, max_memory_mb:128, max_execution_seconds:$t}}')
BODY=$(jq -nc --arg r "$CONTRACT_ID" --argjson a "$ARGS" --arg d "$DEP_Y" \
  '{receiver_id:$r, method_name:"request_execution", args:$a, gas:"300000000000000", deposit:$d}')
OUT=$(curl -sS --max-time 400 -w '\n%{http_code}' -X POST "$COORDINATOR_URL/wallet/v1/call" \
  -H @<(printf '%s\n' "Authorization: Bearer $KEY") -H 'Content-Type: application/json' -d "$BODY")
CODE=$(tail -1 <<<"$OUT"); ANS=$(sed '$d' <<<"$OUT")
STATUS=$(jq -r '.status // empty' <<<"$ANS" 2>/dev/null); RID=$(jq -r '.request_id // empty' <<<"$ANS" 2>/dev/null)
POLL=$(jq -r '.poll_url // empty' <<<"$ANS" 2>/dev/null); TX=$(jq -r '.tx_hash // empty' <<<"$ANS" 2>/dev/null)
echo "• HTTP $CODE: $(head -c 300 <<<"$ANS")"
if [[ "$CODE" == "200" && "$STATUS" == "success" ]]; then
  echo "• INCONCLUSIVE: the node waited out the call; nothing here is about an unknown outcome (raise SLEEP_SECONDS)"
  finish
fi
if [[ "$CODE" == "200" && "$STATUS" == "processing" && -n "$RID" && -n "$TX" && "$POLL" == "/wallet/v1/requests/$RID" ]]; then
  pass "U1 answered processing with request $RID, tx $TX and its poll_url"
else
  fail "U1 expected 200 processing with request_id, tx_hash and poll_url, got HTTP $CODE"
  [[ -z "$RID" ]] && finish
fi

echo "▶ U2 charged at once, the row still open"
ROW=$(sql "SELECT status, COALESCE(result_data->>'usage_charged','') FROM wallet_requests WHERE request_id = '$RID'")
USAGE=$(sql "SELECT total_amount, tx_count FROM wallet_usage WHERE wallet_id = '$WALLET_ID' AND token = 'native' AND period = 'daily:' || to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD')")
echo "• row: $ROW · native usage today: ${USAGE:-none}"
[[ "$ROW" == "processing|true" || "$ROW" == "success|true" ]] \
  && pass "U2 the row is marked usage_charged ($ROW)" || fail "U2 the row is not marked charged: '$ROW'"
[[ "$USAGE" == "$DEP_Y|1" ]] && pass "U2 the deposit is in the counters, one transaction ($USAGE)" \
  || fail "U2 counters read '${USAGE:-none}', not $DEP_Y|1"

echo "▶ U3 the poll_url settles it from the chain"
SETTLED=""
for _ in $(seq 1 40); do
  SETTLED=$(curl -sS --max-time 60 -H @<(printf '%s\n' "Authorization: Bearer $KEY") "$COORDINATOR_URL$POLL" | jq -r '.status // empty')
  [[ "$SETTLED" == "success" || "$SETTLED" == "failed" ]] && break
  sleep 6
done
[[ "$SETTLED" == "success" ]] && pass "U3 the request settled success" || fail "U3 the request settled '$SETTLED'"

echo "▶ U4 charged once"
USAGE2=$(sql "SELECT total_amount, tx_count FROM wallet_usage WHERE wallet_id = '$WALLET_ID' AND token = 'native' AND period = 'daily:' || to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD')")
[[ "$USAGE2" == "$DEP_Y|1" ]] && pass "U4 the settlement charged nothing again ($USAGE2)" \
  || fail "U4 counters moved to '${USAGE2:-none}' — charged twice?"
finish
