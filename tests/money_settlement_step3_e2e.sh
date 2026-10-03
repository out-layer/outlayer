#!/usr/bin/env bash
#
# Money settlement, step 3 — run after the coordinator redeploy that ships it.
#
# What step 3 promises, checked on the live mainnet API with real money:
#   - `X-Answer-Within: N` makes a synchronous call answer `processing` with
#     `request_id` and `poll_url` within N seconds; the money still settles;
#   - a value past the budget is refused before anything runs, and reserves
#     nothing;
#   - a re-send under a seen idempotency key answers the request it belongs
#     to: `request_id`, `status`, `result`, `poll_url` while open — in flight,
#     settled, or ended `failed` before anything was sent; for a check create,
#     the check and its `check_key`;
#   - nothing of this run is left for review.
#
# MAINNET ONLY (no NEAR Intents on testnet). Two withdrawals of 0.01 NEAR from
# wallet A's intents balance to A's own account, and one 0.05 USDC check created
# and reclaimed; each row prints what it spent.
#
# Requires what step 1 requires (I_UNDERSTAND_MAINNET=1, .env.money-e2e with
# MONEY_E2E_WALLET_KEY and MONEY_E2E_WALLET_ID, a keyed FastNEAR RPC; PSQL_CMD
# and COORDINATOR_SSH optional — their rows SKIP loudly without them).
#
# Usage:
#   I_UNDERSTAND_MAINNET=1 PSQL_CMD=./psql_main.sh ./tests/money_settlement_step3_e2e.sh
#
# Rows print PASS / FAIL / SKIP — reason. Any FAIL exits non-zero.
set -uo pipefail

[[ "${I_UNDERSTAND_MAINNET:-}" == "1" ]] || {
  echo "✗ mainnet only, real money: set I_UNDERSTAND_MAINNET=1 to run" >&2
  exit 2
}

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NETWORK=mainnet
source "$REPO/tests/lib/rpc.sh"
[[ "$RPC_URL" == *apiKey=* ]] || { echo "✗ no FastNEAR API key — refusing to judge mainnet through the unkeyed RPC" >&2; exit 2; }

ENV_FILE="${MONEY_E2E_ENV:-$REPO/.env.money-e2e}"
[[ -r "$ENV_FILE" ]] || { echo "✗ $ENV_FILE not found" >&2; exit 2; }
set -a; source "$ENV_FILE"; set +a
: "${MONEY_E2E_WALLET_KEY:?MONEY_E2E_WALLET_KEY missing in $ENV_FILE}"
: "${MONEY_E2E_WALLET_ID:?MONEY_E2E_WALLET_ID missing in $ENV_FILE}"
export MONEY_E2E_WALLET_KEY RPC_URL

API="${API_BASE:-https://api.outlayer.ai}"
PSQL_CMD="${PSQL_CMD:-}"
ONE_HUNDREDTH_NEAR="10000000000000000000000"

IDEM_PREFIX=s3
source "$REPO/tests/lib/money_e2e.sh"

echo "Money settlement step 3 — mainnet, $API"
echo "RPC: $(rpc_url_public)"
echo "wallet key: present, ${#MONEY_E2E_WALLET_KEY} chars"
[[ -n "$PSQL_CMD" ]] && echo "DB asserts: on" || echo "⚠ DB asserts SKIPPED (no PSQL_CMD)"
ACCOUNT="$(body_of "$(api GET "$API/wallet/v1/address?chain=near" MONEY_E2E_WALLET_KEY)" | jget '["address"]')"
[[ -n "$ACCOUNT" ]] || { echo "✗ wallet A did not answer /address" >&2; exit 2; }
USDC="nep141:17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1"
WNEAR0="$(intents_balance nep141:wrap.near MONEY_E2E_WALLET_KEY)"
USDC0="$(intents_balance "$USDC" MONEY_E2E_WALLET_KEY)"
echo "wallet A $ACCOUNT: intents wNEAR=$WNEAR0 USDC=$USDC0"

new_key() { echo "$IDEM_PREFIX-$(uuidgen | tr 'A-Z' 'a-z')"; }
wbody="{\"to\":\"$ACCOUNT\",\"amount\":\"$ONE_HUNDREDTH_NEAR\",\"token\":\"near\",\"chain\":\"near\"}"
# One yocto more than the wallet holds: refused for the balance, inside the
# execution, after the row is reserved — not by the policy before it.
TOO_MUCH_NEAR="$(python3 -c "print(int('${WNEAR0:-0}')+1)")"
toomuch="{\"to\":\"$ACCOUNT\",\"amount\":\"$TOO_MUCH_NEAR\",\"token\":\"near\",\"chain\":\"near\"}"

check_status() {  # CHECK_ID → the status body
  body_of "$(api GET "$API/wallet/v1/payment-check/status?check_id=$1" MONEY_E2E_WALLET_KEY)"
}
# Wait for a check to leave `creating` (up to 5 min); prints its status body.
check_settled() {  # CHECK_ID
  local body st i
  for i in $(seq 1 60); do
    body="$(check_status "$1")"; st="$(jget '["status"]' <<<"$body")"
    [[ -n "$st" && "$st" != creating && "$st" != claiming && "$st" != reclaiming ]] && { echo "$body"; return 0; }
    sleep 5
  done
  echo "$body"
}
# Reclaim whatever a check still holds, as cleanup; prints the final status.
reclaim_all() {  # CHECK_ID
  local resp st
  resp="$(api POST "$API/wallet/v1/payment-check/reclaim" MONEY_E2E_WALLET_KEY "{\"check_id\":\"$1\"}" 120 "$(new_key)")"
  st="$(body_of "$resp" | jget '["status"]')"
  [[ "$st" == processing ]] && poll "$(body_of "$resp" | jget '["request_id"]')" MONEY_E2E_WALLET_KEY >/dev/null
  jget '["status"]' <<<"$(check_settled "$1")"
}
# What a re-send under a seen key names: `request_id` off the duplicate, or
# `in_flight_request_id` off the busy answer; retried for up to 10 s while the
# busy answer names nothing yet (the row is being written). Prints "how id".
named_by_resend() {  # PATH BODY KEY → "duplicate|busy <id>" or ""
  local path="$1" body="$2" key="$3" resp b code err id i
  for i in $(seq 1 10); do
    resp="$(api POST "$API$path" MONEY_E2E_WALLET_KEY "$body" 30 "$key")"
    b="$(body_of "$resp")"; code="$(code_of "$resp")"; err="$(jget '["error"]' <<<"$b")"
    case "$code/$err" in
      200/duplicate_idempotency_key) echo "duplicate $(jget '["request_id"]' <<<"$b")"; return 0 ;;
      409/wallet_busy) id="$(jget '["in_flight_request_id"]' <<<"$b")"; [[ -n "$id" && "$id" != None ]] && { echo "busy $id"; return 0; } ;;
      *) echo "other $code $err"; return 1 ;;
    esac
    sleep 1
  done
  echo "busy-unnamed"; return 1
}

# ── S3-A1: X-Answer-Within: 0 — processing at once, settles on its own ───────
row=S3-A1
key1="$(new_key)"; near0="$(near_balance "$ACCOUNT")"
t0=$(date +%s)
resp="$(api POST "$API/wallet/v1/intents/withdraw" MONEY_E2E_WALLET_KEY "$wbody" 60 "$key1" "X-Answer-Within: 0")"
took=$(( $(date +%s) - t0 ))
id1="$(body_of "$resp" | jget '["request_id"]')"; st="$(body_of "$resp" | jget '["status"]')"
[[ -n "$id1" ]] && echo "$id1" >>"$RUN_IDS"
if [[ "$(code_of "$resp")" != 200 || -z "$id1" ]]; then fail $row "HTTP $(code_of "$resp"): $(body_of "$resp" | head -c 300)"
elif [[ "$st" != processing ]]; then fail $row "status $st, expected processing at once"
elif [[ -z "$(body_of "$resp" | jget '["poll_url"]')" ]]; then fail $row "processing without a poll_url"
elif [[ $took -gt 25 ]]; then fail $row "answered after ${took}s, asked to answer at once"
else pass "$row answered processing in ${took}s with request_id and poll_url (0.01 NEAR to own account)"; fi

# ── S3-A2: the same key again, right away — the request it belongs to ────────
row=S3-A2
if [[ -z "$id1" ]]; then skip $row "no request from S3-A1"
else
  resp="$(api POST "$API/wallet/v1/intents/withdraw" MONEY_E2E_WALLET_KEY "$wbody" 30 "$key1")"
  body="$(body_of "$resp")"
  code="$(code_of "$resp")"; err="$(jget '["error"]' <<<"$body")"
  if [[ "$code" == 409 && "$err" == wallet_busy ]]; then
    [[ "$(jget '["in_flight_request_id"]' <<<"$body")" == "$id1" ]] && pass "$row still in flight: busy names the request" \
      || fail $row "busy names $(jget '["in_flight_request_id"]' <<<"$body"), not $id1"
  elif [[ "$code" != 200 || "$err" != duplicate_idempotency_key ]]; then fail $row "HTTP $code: $(head -c 300 <<<"$body")"
  elif [[ "$(jget '["request_id"]' <<<"$body")" != "$id1" ]]; then fail $row "request_id $(jget '["request_id"]' <<<"$body"), not $id1"
  elif [[ "$(jget '["message"]' <<<"$body")" != "Request already processed: $id1" ]]; then fail $row "message changed: $(jget '["message"]' <<<"$body")"
  elif [[ "$(jget '["type"]' <<<"$body")" != withdraw ]]; then fail $row "type $(jget '["type"]' <<<"$body")"
  else
    st="$(jget '["status"]' <<<"$body")"; purl="$(jget '["poll_url"]' <<<"$body")"
    if [[ "$st" == processing && "$purl" == "/wallet/v1/requests/$id1" ]]; then pass "$row duplicate → processing, poll_url set"
    elif [[ "$st" == success && -z "$purl" ]]; then pass "$row duplicate → already success, nothing to poll"
    else fail $row "status $st with poll_url '$purl'"; fi
  fi
fi

# ── S3-A3: settled; the same key names the settled request ───────────────────
row=S3-A3
if [[ -z "$id1" ]]; then skip $row "no request from S3-A1"
else
  final="$(poll "$id1" MONEY_E2E_WALLET_KEY)"; st="$(jget '["status"]' <<<"$final")"
  near1="$(near_balance "$ACCOUNT")"; grew="$(python3 -c "print(int('$near1')-int('$near0'))")"
  body="$(body_of "$(api POST "$API/wallet/v1/intents/withdraw" MONEY_E2E_WALLET_KEY "$wbody" 30 "$key1")")"
  if [[ "$st" != success ]]; then fail $row "the withdraw ended $st: $(head -c 300 <<<"$final")"
  elif [[ "$grew" != "$ONE_HUNDREDTH_NEAR" ]]; then fail $row "the account grew by $grew, not exactly 0.01 NEAR once"
  elif [[ "$(jget '["error"]' <<<"$body")" != duplicate_idempotency_key || "$(jget '["request_id"]' <<<"$body")" != "$id1" ]]; then fail $row "re-send: $(head -c 300 <<<"$body")"
  elif [[ "$(jget '["status"]' <<<"$body")" != success ]]; then fail $row "duplicate says $(jget '["status"]' <<<"$body") after settlement"
  elif [[ -n "$(jget '["poll_url"]' <<<"$body")" ]]; then fail $row "a settled duplicate still offers a poll_url"
  elif [[ "$(jget '["result"]["delivered"]' <<<"$body")" != native_near ]]; then fail $row "result not carried: $(jget '["result"]' <<<"$body" | head -c 200)"
  else pass "$row settled once (0.01 NEAR); the duplicate carries success and the result"; fi
fi

# ── S3-A4: X-Answer-Within past the budget — refused first, reserves nothing ─
row=S3-A4
key4="$(new_key)"
resp="$(api POST "$API/wallet/v1/intents/withdraw" MONEY_E2E_WALLET_KEY "$toomuch" 30 "$key4" "X-Answer-Within: 81")"
body="$(body_of "$resp")"
if [[ "$(code_of "$resp")" != 400 || "$(jget '["error"]' <<<"$body")" != bad_request ]]; then fail $row "HTTP $(code_of "$resp"): $(head -c 200 <<<"$body")"
elif ! grep -q "X-Answer-Within" <<<"$(jget '["message"]' <<<"$body")"; then fail $row "the refusal does not name the header: $(jget '["message"]' <<<"$body")"
else
  # Nothing was reserved under the key: the same key without the header runs,
  # and is refused for the balance — not answered as a duplicate.
  resp="$(api POST "$API/wallet/v1/intents/withdraw" MONEY_E2E_WALLET_KEY "$toomuch" 60 "$key4")"
  body="$(body_of "$resp")"; refused="$(jget '["error"]' <<<"$body")"
  if [[ "$(code_of "$resp")" != 4* || "$refused" == duplicate_idempotency_key ]]; then fail $row "after the refused header the key was already held: HTTP $(code_of "$resp") $(head -c 200 <<<"$body")"
  else pass "$row 81 → 400 naming the header; the key was not reserved (then refused: $refused)"; fi
fi

# ── S3-A5: a key held by a request that failed before sending ────────────────
row=S3-A5
if [[ "${refused:-}" == policy_denied ]]; then skip $row "the wallet's policy refused $TOO_MUCH_NEAR before the reserve; raise its per-transaction limit above A's wNEAR balance to judge this row"
else
body="$(body_of "$(api POST "$API/wallet/v1/intents/withdraw" MONEY_E2E_WALLET_KEY "$toomuch" 30 "$key4")")"
if [[ "$(jget '["error"]' <<<"$body")" != duplicate_idempotency_key ]]; then fail $row "the refused withdraw holds no key: $(head -c 200 <<<"$body")"
elif [[ "$(jget '["status"]' <<<"$body")" != failed ]]; then fail $row "status $(jget '["status"]' <<<"$body"), expected failed"
elif [[ "$(jget '["result"]["never_submitted"]' <<<"$body")" != True ]]; then fail $row "result does not say never_submitted: $(jget '["result"]' <<<"$body" | head -c 200)"
elif [[ -n "$(jget '["poll_url"]' <<<"$body")" ]]; then fail $row "a failed request still offers a poll_url"
else pass "$row the key names the failed request: failed, never_submitted, nothing to poll"; fi
fi

# ── S3-B1: re-send while the first is in flight ──────────────────────────────
row=S3-B1
keyb="$(new_key)"; near0="$(near_balance "$ACCOUNT")"
api POST "$API/wallet/v1/intents/withdraw" MONEY_E2E_WALLET_KEY "$wbody" 90 "$keyb" "X-Answer-Within: 20" >"$WORK/b1.first" &
first_pid=$!
sleep 2
answer="$(named_by_resend /wallet/v1/intents/withdraw "$wbody" "$keyb")"
wait "$first_pid"
idb="$(body_of "$(cat "$WORK/b1.first")" | jget '["request_id"]')"; [[ -n "$idb" ]] && echo "$idb" >>"$RUN_IDS"
how="${answer%% *}"; named="${answer#* }"
final="$(poll "$idb" MONEY_E2E_WALLET_KEY)"; st="$(jget '["status"]' <<<"$final")"
near1="$(near_balance "$ACCOUNT")"; grew="$(python3 -c "print(int('$near1')-int('$near0'))")"
if [[ -z "$idb" ]]; then fail $row "the first call answered no request_id: $(head -c 200 "$WORK/b1.first")"
elif [[ "$how" != duplicate && "$how" != busy ]]; then fail $row "the re-send in flight named no request within 10 s: $answer"
elif [[ "$named" != "$idb" ]]; then fail $row "the re-send named $named, the first call $idb"
elif [[ "$st" != success ]]; then fail $row "the withdraw ended $st"
elif [[ "$grew" != "$ONE_HUNDREDTH_NEAR" ]]; then fail $row "the account grew by $grew: paid twice or not at all"
else pass "$row re-send in flight → $how naming the request; paid once (0.01 NEAR)"; fi

# ── S3-C1: a check create under X-Answer-Within: 0; its key comes back on a re-send ──
row=S3-C1
CHECK_AMOUNT=50000  # 0.05 USDC
if (( ${USDC0:-0} < CHECK_AMOUNT )); then skip $row "wallet A holds $USDC0 USDC in intents, the row needs $CHECK_AMOUNT"
else
  keyc="$(new_key)"; cbody="{\"token\":\"$USDC\",\"amount\":\"$CHECK_AMOUNT\",\"memo\":\"s3-c1\"}"
  resp="$(api POST "$API/wallet/v1/payment-check/create" MONEY_E2E_WALLET_KEY "$cbody" 60 "$keyc" "X-Answer-Within: 0")"
  body="$(body_of "$resp")"; cid="$(jget '["check_id"]' <<<"$body")"; ckey="$(jget '["check_key"]' <<<"$body")"; cst="$(jget '["status"]' <<<"$body")"
  if [[ "$(code_of "$resp")" != 200 || -z "$cid" || -z "$ckey" ]]; then fail $row "create: HTTP $(code_of "$resp") $(head -c 200 <<<"$body")"
  elif [[ "$cst" != creating && "$cst" != unclaimed ]]; then fail $row "create under a 0 s wait answered $cst"
  elif [[ "$cst" == creating && -z "$(jget '["poll_url"]' <<<"$body")" ]]; then fail $row "creating without a poll_url"
  else
    dup="$(body_of "$(api POST "$API/wallet/v1/payment-check/create" MONEY_E2E_WALLET_KEY "$cbody" 30 "$keyc")")"
    dkey="$(jget '["checks"][0]["check_key"]' <<<"$dup")"; did="$(jget '["checks"][0]["check_id"]' <<<"$dup")"
    settled="$(jget '["status"]' <<<"$(check_settled "$cid")")"
    back="$(reclaim_all "$cid")"
    if [[ "$(jget '["error"]' <<<"$dup")" != duplicate_idempotency_key ]]; then fail $row "re-send: $(head -c 200 <<<"$dup")"
    elif [[ "$did" != "$cid" ]]; then fail $row "the duplicate names check $did, created $cid"
    elif [[ "$dkey" != "$ckey" ]]; then fail $row "the duplicate's check_key is not the one the create answered"
    elif [[ "$settled" != unclaimed ]]; then fail $row "the check settled $settled, not unclaimed"
    elif [[ "$back" != reclaimed ]]; then fail $row "reclaim left the check $back"
    else pass "$row create answered $cst at once; the re-send carried the check and its key; settled unclaimed, reclaimed (0.05 USDC round trip)"; fi
  fi
fi

# ── S3-D1: DB — nothing of this run is open or for review ────────────────────
row=S3-D1
if [[ -z "$PSQL_CMD" ]]; then skip $row "no PSQL_CMD"
elif [[ ! -s "$RUN_IDS" ]]; then skip $row "no request of this run to judge"
else
  ids="$(sort -u "$RUN_IDS" | sed "s/.*/'&'/" | paste -sd, -)"
  bad="$(sql "SELECT count(*) FROM wallet_requests WHERE request_id IN ($ids) AND status IN ('needs_review','processing')")"
  [[ "$bad" == 0 ]] && pass "$row this run's requests: none open, none for review" || fail $row "$bad request(s) open or for review"
fi

# ── S3-L1: the duplicate is visible in the coordinator log ───────────────────
row=S3-L1
if [[ -z "${COORDINATOR_SSH:-}" ]]; then skip $row "set COORDINATOR_SSH=root@host to read the coordinator log (read-only)"
elif [[ -z "$id1" ]]; then skip $row "no request from S3-A1"
else
  n="$(ssh -o ConnectTimeout=15 -o BatchMode=yes -o ControlMaster=no -o ControlPath=none "$COORDINATOR_SSH" \
        "docker logs --since 30m offchainvm-coordinator-mainnet 2>&1 | grep -c 'idempotency key seen again.*$id1' || true")"
  [[ "${n:-0}" -ge 2 ]] && pass "$row $n log lines name the re-sends of S3-A1's key" || fail $row "${n:-0} log line(s) for the re-sends of $id1"
fi

echo "── step 3: $PASS pass, $FAIL fail, $SKIP skip"
[[ $FAIL -eq 0 ]]
