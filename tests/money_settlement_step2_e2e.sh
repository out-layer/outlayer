#!/usr/bin/env bash
#
# Money settlement, step 2 — run after the coordinator redeploy that ships it.
# Runs step 1's rows first (`money_settlement_step1_e2e.sh --rows-only`).
#
# What step 2 promises, checked on the live mainnet API with real money:
#   - a caller that hangs up does not stop a payment check leg (create, claim,
#     reclaim, batch), a limit order's funding or a confidential op;
#   - each settles on its own to the state the chain (or the confidential
#     status) implies: a check's amounts applied exactly once, an order funded
#     and charged once, a confidential op charged once;
#   - nothing of this run is left for review or open.
#
# MAINNET ONLY. Money moves in small amounts between accounts we own, and every
# row puts it back (reclaims its checks, cancels its order, unshields what it
# shielded); each row prints what it spent.
#
# Requires what step 1 requires, plus:
#   MONEY_E2E_PEER_KEY      wk_ of custody wallet B — claims the check (S2-P2)
#   USDC in A's intents balance: 0.1 (P1) + 0.1 (P2/P3) + 0.09 (P4) + 0.2 (O1)
#     + 0.1 (C1), all returned by the end of the run
#
# Usage:
#   I_UNDERSTAND_MAINNET=1 PSQL_CMD=./psql_main.sh ./tests/money_settlement_step2_e2e.sh
#
# Rows print PASS / FAIL / SKIP — reason. Any FAIL exits non-zero.

set -uo pipefail

[[ "${I_UNDERSTAND_MAINNET:-}" == "1" ]] || {
  echo "✗ mainnet only, real money: set I_UNDERSTAND_MAINNET=1 to run" >&2
  exit 2
}

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "── step 1 rows"
"$REPO/tests/money_settlement_step1_e2e.sh" --rows-only
STEP1=$?

NETWORK=mainnet
source "$REPO/tests/lib/rpc.sh"
[[ "$RPC_URL" == *apiKey=* ]] || { echo "✗ no FastNEAR API key — refusing to judge mainnet through the unkeyed RPC" >&2; exit 2; }

ENV_FILE="${MONEY_E2E_ENV:-$REPO/.env.money-e2e}"
[[ -r "$ENV_FILE" ]] || { echo "✗ $ENV_FILE not found" >&2; exit 2; }
set -a; source "$ENV_FILE"; set +a
: "${MONEY_E2E_WALLET_KEY:?MONEY_E2E_WALLET_KEY missing in $ENV_FILE}"
: "${MONEY_E2E_WALLET_ID:?MONEY_E2E_WALLET_ID missing in $ENV_FILE}"
export MONEY_E2E_WALLET_KEY MONEY_E2E_PEER_KEY="${MONEY_E2E_PEER_KEY:-}" RPC_URL

API="${API_BASE:-https://api.outlayer.ai}"
PSQL_CMD="${PSQL_CMD:-}"
USDC="nep141:17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1"
WNEAR="nep141:wrap.near"
IDEM_PREFIX=s2
source "$REPO/tests/lib/money_e2e.sh"

echo "── step 2 rows"
# A fact about the key, never the key: `${VAR:-absent}` would print it whole.
if [[ -n "$MONEY_E2E_PEER_KEY" ]]; then echo "wallet B key: present, ${#MONEY_E2E_PEER_KEY} chars"; else echo "wallet B key: absent"; fi
ACCOUNT="$(body_of "$(api GET "$API/wallet/v1/address?chain=near" MONEY_E2E_WALLET_KEY)" | jget '["address"]')"
[[ -n "$ACCOUNT" ]] || { echo "✗ wallet A did not answer /address" >&2; exit 2; }
USDC0="$(intents_balance "$USDC" MONEY_E2E_WALLET_KEY)"
echo "wallet A $ACCOUNT: intents USDC=$USDC0"

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
  resp="$(api POST "$API/wallet/v1/payment-check/reclaim" MONEY_E2E_WALLET_KEY "{\"check_id\":\"$1\"}" 120 "s2-$(uuidgen)")"
  st="$(body_of "$resp" | jget '["status"]')"
  [[ "$st" == processing ]] && poll "$(body_of "$resp" | jget '["request_id"]')" MONEY_E2E_WALLET_KEY >/dev/null
  jget '["status"]' <<<"$(check_settled "$1")"
}

check_row_clean() {  # CHECK_ID → "status|pending" from the DB, or "" without PSQL_CMD
  sql "SELECT status || '|' || (pending_request_id IS NULL)::text FROM payment_checks WHERE check_id = '$1'"
}

# ── S2-P1: create a 0.1 USDC check, hang up at 3 s ───────────────────────────
row=S2-P1
cbody="{\"token\":\"$USDC\",\"amount\":\"100000\",\"memo\":\"s2-p1\"}"
id="$(hang_up_and_recover /wallet/v1/payment-check/create "$cbody" MONEY_E2E_WALLET_KEY)" || { fail $row "no request id after the hang-up"; id=""; }
if [[ -n "$id" ]]; then
  final="$(poll "$id" MONEY_E2E_WALLET_KEY)"; st="$(jget '["status"]' <<<"$final")"
  check_id="$(jget '["result"]["check_id"]' <<<"$final")"
  if [[ "$st" == failed && "$(jget '["result"]["error"]' <<<"$final")" == *PolicyDenied* ]]; then skip $row "the policy does not grant payment_check"
  elif [[ "$st" != completed || -z "$check_id" ]]; then fail $row "request $st: $(head -c 300 <<<"$final")"
  else
    cst="$(jget '["status"]' <<<"$(check_settled "$check_id")")"
    clean="$(check_row_clean "$check_id")"
    if [[ "$cst" != unclaimed ]]; then fail $row "check $cst"
    elif [[ -n "$PSQL_CMD" && "$clean" != "unclaimed|true" ]]; then fail $row "DB row $clean"
    else
      back="$(reclaim_all "$check_id")"
      [[ "$back" == reclaimed ]] && pass "$row create after a hang-up → unclaimed, funded once; reclaimed (net 0)" \
        || fail $row "funded, but the cleanup reclaim ended $back — reclaim $check_id by hand"
    fi
  fi
fi

# ── S2-P2 / S2-P3: claim 0.04 by B with a hang-up, reclaim the rest with one ──
if [[ -z "$MONEY_E2E_PEER_KEY" ]]; then
  skip S2-P2 "MONEY_E2E_PEER_KEY not set (wallet B claims)"
  skip S2-P3 "needs S2-P2's check"
else
  row=S2-P2
  resp="$(api POST "$API/wallet/v1/payment-check/create" MONEY_E2E_WALLET_KEY "{\"token\":\"$USDC\",\"amount\":\"100000\",\"memo\":\"s2-p2\"}" 120 "s2-$(uuidgen)")"
  check_id="$(body_of "$resp" | jget '["check_id"]')"
  export S2_CHECK_KEY; S2_CHECK_KEY="$(body_of "$resp" | jget '["check_key"]')"
  if [[ -z "$check_id" || -z "$S2_CHECK_KEY" ]]; then fail $row "create answered $(code_of "$resp"): $(body_of "$resp" | jget '["error"]')"
  else
    [[ "$(jget '["status"]' <<<"$(check_settled "$check_id")")" == unclaimed ]] || fail $row "the check never reached unclaimed"
    b0="$(intents_balance "$USDC" MONEY_E2E_PEER_KEY)"
    # The key is a bearer secret: the body that carries it is built and read
    # from the environment, never put on a command line.
    export S2_CLAIM_BODY
    S2_CLAIM_BODY="$(python3 -c 'import json,os; print(json.dumps({"check_key": os.environ["S2_CHECK_KEY"], "amount": "40000"}))')"
    id="$(hang_up_and_recover /wallet/v1/payment-check/claim "@env:S2_CLAIM_BODY" MONEY_E2E_PEER_KEY)" || { fail $row "no request id after the hang-up"; id=""; }
    if [[ -n "$id" ]]; then
      final="$(poll "$id" MONEY_E2E_PEER_KEY)"; st="$(jget '["status"]' <<<"$final")"
      body="$(check_settled "$check_id")"
      got="$(python3 -c "print(int('$(intents_balance "$USDC" MONEY_E2E_PEER_KEY)')-int('$b0'))")"
      if [[ "$st" != completed ]]; then fail $row "claim request $st: $(head -c 300 <<<"$final")"
      elif [[ "$(jget '["claimed_amount"]' <<<"$body")" != 40000 ]]; then fail $row "claimed_amount=$(jget '["claimed_amount"]' <<<"$body"), not 40000 once"
      elif [[ "$(jget '["status"]' <<<"$body")" != partially_claimed ]]; then fail $row "check $(jget '["status"]' <<<"$body")"
      elif [[ "$got" != 40000 ]]; then fail $row "B grew by $got, not 40000"
      else pass "$row partial claim after a hang-up → 0.04 USDC to B once, check partially_claimed"; fi
    fi

    row=S2-P3
    a0="$(intents_balance "$USDC" MONEY_E2E_WALLET_KEY)"
    id="$(hang_up_and_recover /wallet/v1/payment-check/reclaim "{\"check_id\":\"$check_id\"}" MONEY_E2E_WALLET_KEY)" || { fail $row "no request id after the hang-up"; id=""; }
    if [[ -n "$id" ]]; then
      final="$(poll "$id" MONEY_E2E_WALLET_KEY)"; st="$(jget '["status"]' <<<"$final")"
      body="$(check_settled "$check_id")"
      got="$(python3 -c "print(int('$(intents_balance "$USDC" MONEY_E2E_WALLET_KEY)')-int('$a0'))")"
      if [[ "$st" != completed ]]; then fail $row "reclaim request $st: $(head -c 300 <<<"$final")"
      elif [[ "$(jget '["status"]' <<<"$body")" != reclaimed || "$(jget '["reclaimed_amount"]' <<<"$body")" != 60000 ]]; then
        fail $row "check $(jget '["status"]' <<<"$body"), reclaimed $(jget '["reclaimed_amount"]' <<<"$body")"
      elif [[ "$got" != 60000 ]]; then fail $row "A grew by $got, not 60000"
      else pass "$row reclaim after a hang-up → 0.06 USDC back once, check reclaimed (spent 0.04 USDC, to B)"; fi
    fi
    # B's 0.04 goes back to A.
    api POST "$API/wallet/v1/intents/transfer" MONEY_E2E_PEER_KEY "{\"to\":\"$ACCOUNT\",\"amount\":\"40000\",\"token\":\"$USDC\"}" 120 "s2-$(uuidgen)" >/dev/null
  fi
fi

# ── S2-P4: batch of three 0.03 USDC checks, hang up at 3 s ───────────────────
row=S2-P4
one="{\"token\":\"$USDC\",\"amount\":\"30000\"}"
id="$(hang_up_and_recover /wallet/v1/payment-check/batch-create "{\"checks\":[$one,$one,$one]}" MONEY_E2E_WALLET_KEY)" || { fail $row "no request id after the hang-up"; id=""; }
if [[ -n "$id" ]]; then
  ids=""
  for i in $(seq 1 30); do
    ids="$(body_of "$(api GET "$API/wallet/v1/requests/$id" MONEY_E2E_WALLET_KEY)" | jget '["result"]["check_ids"]')"
    [[ -n "$ids" ]] && break; sleep 3
  done
  ids="$(python3 -c 'import json,sys; print(" ".join(json.loads(sys.argv[1] or "[]")))' "$ids")"
  n=0; ok=1
  for c in $ids; do
    n=$((n+1))
    [[ "$(jget '["status"]' <<<"$(check_settled "$c")")" == unclaimed ]] || ok=0
    [[ "$(reclaim_all "$c")" == reclaimed ]] || ok=0
  done
  if [[ $n -ne 3 ]]; then fail $row "the batch lists $n checks, not 3"
  elif [[ $ok -ne 1 ]]; then fail $row "a check did not reach unclaimed, or did not reclaim — look at: $ids"
  else pass "$row batch after a hang-up → 3 checks funded once, all reclaimed (net 0)"; fi
fi

# ── S2-O1: rest a USDC→wNEAR sell that cannot fill, hang up at 3 s ───────────
row=S2-O1
# 0.2 USDC, above the 0.1 USD order minimum; a price no market reaches, so the
# order rests until it is cancelled and the 0.2 USDC comes back.
obody="{\"base_asset\":\"$USDC\",\"quote_asset\":\"$WNEAR\",\"side\":\"sell\",\"quantity\":\"200000\",\"price\":\"1000\"}"
before="$(usage_count "$USDC")"
id="$(hang_up_and_recover /wallet/v1/limit-orders "$obody" MONEY_E2E_WALLET_KEY)" || { fail $row "no request id after the hang-up"; id=""; }
if [[ -n "$id" ]]; then
  final="$(poll "$id" MONEY_E2E_WALLET_KEY)"; st="$(jget '["status"]' <<<"$final")"
  order_id="$(jget '["result"]["order_id"]' <<<"$final")"
  if [[ "$st" != success || -z "$order_id" ]]; then fail $row "request $st: $(head -c 300 <<<"$final")"
  elif [[ -n "$PSQL_CMD" && "$(usage_count "$USDC")" != "$((${before:-0}+1))" ]]; then fail $row "velocity not charged exactly once"
  else
    fill="$(body_of "$(api GET "$API/wallet/v1/limit-orders/$order_id" MONEY_E2E_WALLET_KEY)" | jget '["fill_status"]')"
    api POST "$API/wallet/v1/limit-orders/$order_id/cancel" MONEY_E2E_WALLET_KEY "" 60 >/dev/null
    if [[ "$fill" == canceled || "$fill" == cancelled ]]; then fail $row "the funded order was already cancelled"
    else pass "$row limit order after a hang-up → funded once, charged once (fill $fill); cancelled, 0.2 USDC refunds"; fi
  fi
fi

# ── S2-C1: shield 0.1 USDC, hang up at 3 s ───────────────────────────────────
row=S2-C1
sbody="{\"token\":\"$USDC\",\"amount\":\"100000\"}"
probe="$(api GET "$API/wallet/v1/confidential/balance" MONEY_E2E_WALLET_KEY)"
if [[ "$(code_of "$probe")" == 503 ]]; then skip $row "confidential intents are not enabled on this deployment"
else
  before="$(usage_count "$USDC")"
  # This call's rows only: a run minutes earlier has shield rows of its own.
  since="$(sql "SELECT now()")"
  id="$(hang_up_and_recover /wallet/v1/confidential/shield "$sbody" MONEY_E2E_WALLET_KEY)" || { fail $row "no request id after the hang-up"; id=""; }
  if [[ -n "$id" ]]; then
    st=""
    for i in $(seq 1 60); do
      st="$(body_of "$(api GET "$API/wallet/v1/requests/$id" MONEY_E2E_WALLET_KEY)" | jget '["status"]')"
      [[ "$st" == success || "$st" == failed || "$st" == refunded || "$st" == needs_review ]] && break
      sleep 5
    done
    rows="$(sql "SELECT count(*) FROM wallet_requests WHERE wallet_id='$MONEY_E2E_WALLET_ID' AND request_type='confidential_shield' AND created_at >= '$since'")"
    # Whatever the judgement, a shield that succeeded is put back.
    [[ "$st" == success ]] && back="$(api POST "$API/wallet/v1/confidential/unshield" MONEY_E2E_WALLET_KEY "$sbody" 120 "s2-$(uuidgen)")"
    if [[ "$st" != success ]]; then fail $row "status $st"
    elif [[ -n "$PSQL_CMD" && "$rows" != 1 ]]; then fail $row "$rows shield rows for one call"
    elif [[ -n "$PSQL_CMD" && "$(usage_count "$USDC")" != "$((${before:-0}+1))" ]]; then fail $row "velocity not charged exactly once"
    else
      pass "$row shield after a hang-up → success, one row, charged once; unshield back answered $(body_of "$back" | jget '["status"]')"
    fi
  fi
fi

# ── S2-D1: the rows of this run ──────────────────────────────────────────────
row=S2-D1
if [[ -z "$PSQL_CMD" ]]; then skip $row "needs PSQL_CMD"
else
  ids="$(sort -u "$RUN_IDS" | sed "s/.*/'&'/" | paste -sd, -)"
  if [[ -z "$ids" ]]; then skip $row "no request ids recorded"
  else
    bad="$(sql "SELECT count(*) FROM wallet_requests WHERE request_id IN ($ids) AND (status='needs_review' OR (status IN ('processing','pending_deposit') AND created_at < NOW() - INTERVAL '5 minutes'))")"
    open_checks="$(sql "SELECT count(*) FROM payment_checks WHERE wallet_id='$MONEY_E2E_WALLET_ID' AND created_at > NOW() - INTERVAL '1 hour' AND (status IN ('creating','claiming','reclaiming') OR pending_request_id IS NOT NULL)")"
    if [[ "$bad" != 0 ]]; then fail $row "$bad request(s) of this run open past 5 min or for review"
    elif [[ "$open_checks" != 0 ]]; then fail $row "$open_checks check(s) with a leg still in flight"
    else pass "$row nothing of this run open or for review"; fi
  fi
fi

echo "USDC in A: $USDC0 → $(intents_balance "$USDC" MONEY_E2E_WALLET_KEY)"
echo "── step 2: $PASS pass, $FAIL fail, $SKIP skip (step 1 rows exited $STEP1)"
[[ $FAIL -eq 0 && $STEP1 -eq 0 ]]
