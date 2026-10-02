#!/usr/bin/env bash
#
# Money settlement, step 1 — run after the coordinator redeploy that ships it.
#
# What step 1 promises, checked on the live mainnet API with real money:
#   - a caller that hangs up does not stop a withdraw, swap or transfer;
#   - the request then settles on its own, from the chain, to the status the
#     chain implies, and velocity is charged exactly once;
#   - a request refused before anything was sent is closed `failed`, not left
#     for review;
#   - a synchronous answer that is still `processing` carries a `poll_url`.
#
# MAINNET ONLY: NEAR Intents do not exist on testnet. Money moves, in small
# amounts, between accounts we own; each row prints what it spent.
#
# Requires:
#   I_UNDERSTAND_MAINNET=1
#   MONEY_E2E_ENV  file (default .env.money-e2e at the repo root, gitignored) with
#     MONEY_E2E_WALLET_KEY   wk_ of custody wallet A (USDC in its intents balance)
#     MONEY_E2E_WALLET_ID    its wallet id (for the DB asserts)
#     MONEY_E2E_PEER_ACCOUNT optional: custody wallet B's account (transfer rows)
#     MONEY_E2E_PEER_KEY     optional: wk_ of wallet B (to send the transfer back)
#   PSQL_CMD   optional: read-only mainnet SQL wrapper (one statement per call);
#              without it the DB asserts SKIP loudly.
#   FASTNEAR_API_KEY or near-cli config with a keyed mainnet RPC.
#
# Usage:
#   I_UNDERSTAND_MAINNET=1 PSQL_CMD=./psql_main.sh ./tests/money_settlement_step1_e2e.sh
#   ... --rows-only   (no header/summary; for money_settlement_step2_e2e.sh)
#
# Rows print PASS / FAIL / SKIP — reason. Any FAIL exits non-zero.

set -uo pipefail

ROWS_ONLY=0
[[ "${1:-}" == "--rows-only" ]] && ROWS_ONLY=1

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
export MONEY_E2E_WALLET_KEY MONEY_E2E_PEER_KEY="${MONEY_E2E_PEER_KEY:-}" RPC_URL

API="${API_BASE:-https://api.outlayer.ai}"
PSQL_CMD="${PSQL_CMD:-}"
USDC="nep141:17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1"
WNEAR="nep141:wrap.near"
ONE_HUNDREDTH_NEAR="10000000000000000000000"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# ── HTTP through Python: keys are read from the environment by name, never
#    put on a command line (`ps` shows argv to every process on the box).
cat >"$WORK/api.py" <<'PY'
import json, os, sys, urllib.request, urllib.error, socket
method, url, key_var = sys.argv[1], sys.argv[2], sys.argv[3]
body = sys.argv[4] if len(sys.argv) > 4 and sys.argv[4] else None
timeout = float(sys.argv[5]) if len(sys.argv) > 5 and sys.argv[5] else 120.0
idem = sys.argv[6] if len(sys.argv) > 6 and sys.argv[6] else None
headers = {"User-Agent": "curl/8.7.1", "Content-Type": "application/json"}
if key_var:
    headers["Authorization"] = "Bearer " + os.environ[key_var]
if idem:
    headers["X-Idempotency-Key"] = idem
req = urllib.request.Request(url, data=body.encode() if body else None, headers=headers, method=method)
try:
    with urllib.request.urlopen(req, timeout=timeout) as r:
        print(r.status); print(r.read().decode())
except urllib.error.HTTPError as e:
    print(e.code); print(e.read().decode())
except (socket.timeout, TimeoutError, urllib.error.URLError) as e:
    print("HUNGUP"); print(json.dumps({"error": str(e)}))
PY
api() { python3 "$WORK/api.py" "$@"; }          # METHOD URL KEYVAR [BODY] [TIMEOUT] [IDEM]
code_of() { head -1 <<<"$1"; }
body_of() { tail -n +2 <<<"$1"; }
jget() { python3 -c 'import json,sys; d=json.loads(sys.stdin.read() or "null"); v=eval("d"+sys.argv[1]) if d is not None else None; print("" if v is None else (json.dumps(v) if isinstance(v,(dict,list)) else v))' "$1" 2>/dev/null; }

PASS=0; FAIL=0; SKIP=0
pass() { echo "PASS  $1"; PASS=$((PASS+1)); }
fail() { echo "FAIL  $1 — $2"; FAIL=$((FAIL+1)); }
skip() { echo "SKIP  $1 — $2"; SKIP=$((SKIP+1)); }
sql() { [[ -n "$PSQL_CMD" ]] && $PSQL_CMD "$1"; }

RUN_IDS="$WORK/ids"; : >"$RUN_IDS"

# Send once and hang up after 3 s; then recover the request id the way an
# integrator does — re-send with the same key and read the duplicate answer
# (or the busy answer naming the request in flight).
hang_up_and_recover() {  # PATH BODY KEYVAR → prints request_id
  local path="$1" body="$2" keyvar="$3" idem="s1-$(uuidgen | tr 'A-Z' 'a-z')" resp id i
  api POST "$API$path" "$keyvar" "$body" 3 "$idem" >/dev/null
  for i in $(seq 1 30); do
    resp="$(api POST "$API$path" "$keyvar" "$body" 30 "$idem")"
    id="$(body_of "$resp" | jget '["message"]' | grep -oE '[0-9a-f-]{36}' | head -1)"
    [[ -z "$id" ]] && id="$(body_of "$resp" | jget '["in_flight_request_id"]')"
    [[ -n "$id" ]] && { echo "$id"; echo "$id" >>"$RUN_IDS"; return 0; }
    sleep 1
  done
  return 1
}

poll() {  # REQUEST_ID KEYVAR → prints the final body; waits up to 5 min
  local id="$1" keyvar="$2" resp st i
  for i in $(seq 1 60); do
    resp="$(api GET "$API/wallet/v1/requests/$id" "$keyvar")"
    st="$(body_of "$resp" | jget '["status"]')"
    [[ "$st" != "processing" && -n "$st" ]] && { body_of "$resp"; return 0; }
    sleep 5
  done
  body_of "$resp"
}

intents_balance() {  # TOKEN KEYVAR
  body_of "$(api GET "$API/wallet/v1/balance?chain=near&source=intents&token=$1" "$2")" | jget '["balance"]'
}

usage_count() {  # TOKEN → today's tx_count for wallet A
  sql "SELECT COALESCE(tx_count,0) FROM wallet_usage WHERE wallet_id = '$MONEY_E2E_WALLET_ID' AND token = '$1' AND period = 'daily:$(date -u +%Y-%m-%d)'" | head -1
}

near_balance() {  # ACCOUNT → native yocto
  python3 - "$1" <<'PY'
import json, os, sys, urllib.request
body = {"jsonrpc":"2.0","id":1,"method":"query","params":{"request_type":"view_account","finality":"final","account_id":sys.argv[1]}}
r = urllib.request.Request(os.environ["RPC_URL"], data=json.dumps(body).encode(), headers={"content-type":"application/json"})
print(json.load(urllib.request.urlopen(r, timeout=20))["result"]["amount"])
PY
}

# ── Preconditions ────────────────────────────────────────────────────────────
if [[ $ROWS_ONLY -eq 0 ]]; then
  echo "Money settlement step 1 — mainnet, $API"
  echo "RPC: $(rpc_url_public)"
  echo "wallet key: present, ${#MONEY_E2E_WALLET_KEY} chars; peer: ${MONEY_E2E_PEER_ACCOUNT:+present}${MONEY_E2E_PEER_ACCOUNT:-absent}"
  [[ -n "$PSQL_CMD" ]] && echo "DB asserts: on" || echo "⚠ DB asserts SKIPPED (no PSQL_CMD)"
fi
ACCOUNT="$(body_of "$(api GET "$API/wallet/v1/address?chain=near" MONEY_E2E_WALLET_KEY)" | jget '["address"]')"
[[ -n "$ACCOUNT" ]] || { echo "✗ wallet A did not answer /address" >&2; exit 2; }
USDC0="$(intents_balance "$USDC" MONEY_E2E_WALLET_KEY)"
echo "wallet A $ACCOUNT: intents USDC=$USDC0 wNEAR=$(intents_balance "$WNEAR" MONEY_E2E_WALLET_KEY)"

# ── S1-S1: swap 0.5 USDC → wNEAR, hang up at 3 s ─────────────────────────────
row=S1-S1
quote="$(api POST "$API/wallet/v1/intents/swap/quote" MONEY_E2E_WALLET_KEY "{\"token_in\":\"$USDC\",\"token_out\":\"$WNEAR\",\"amount_in\":\"500000\"}")"
if [[ "$(code_of "$quote")" != 200 ]]; then
  skip $row "the quote is refused for 0.5 USDC: $(body_of "$quote" | head -c 200)"
else
  before="$(usage_count "$USDC")"
  id="$(hang_up_and_recover /wallet/v1/intents/swap "{\"token_in\":\"$USDC\",\"token_out\":\"$WNEAR\",\"amount_in\":\"500000\"}" MONEY_E2E_WALLET_KEY)" \
    || { fail $row "no request id came back after the hang-up"; id=""; }
  if [[ -n "$id" ]]; then
    final="$(poll "$id" MONEY_E2E_WALLET_KEY)"
    st="$(jget '["status"]' <<<"$final")"
    if [[ "$st" != success ]]; then fail $row "status $st: $(head -c 300 <<<"$final")"
    elif [[ -n "$PSQL_CMD" && "$(usage_count "$USDC")" != "$((${before:-0}+1))" ]]; then fail $row "velocity not charged exactly once"
    else pass "$row swap after a hang-up → success, amount_out=$(jget '["result"]["amount_out"]' <<<"$final") (spent 0.5 USDC)"; fi
  fi
fi

# ── S1-W1: native withdraw 0.01 NEAR to A's own account, normal sync ─────────
row=S1-W1
wbody="{\"to\":\"$ACCOUNT\",\"amount\":\"$ONE_HUNDREDTH_NEAR\",\"token\":\"near\",\"chain\":\"near\"}"
resp="$(api POST "$API/wallet/v1/intents/withdraw" MONEY_E2E_WALLET_KEY "$wbody" 120 "s1-$(uuidgen)")"
id="$(body_of "$resp" | jget '["request_id"]')"; [[ -n "$id" ]] && echo "$id" >>"$RUN_IDS"
st="$(body_of "$resp" | jget '["status"]')"
if [[ "$st" == processing ]]; then
  [[ -n "$(body_of "$resp" | jget '["poll_url"]')" ]] || fail $row "processing without a poll_url"
  st="$(poll "$id" MONEY_E2E_WALLET_KEY | jget '["status"]')"
fi
final="$(body_of "$(api GET "$API/wallet/v1/requests/$id" MONEY_E2E_WALLET_KEY)")"
if [[ "$st" != success ]]; then fail $row "status $st: $(body_of "$resp" | head -c 300)"
elif [[ "$(jget '["result"]["delivered"]' <<<"$final")" != native_near ]]; then fail $row "delivered=$(jget '["result"]["delivered"]' <<<"$final")"
elif [[ -z "$(jget '["result"]["intent"]["nonce"]' <<<"$final")" ]]; then fail $row "no intent recorded on the row"
else pass "$row withdraw → success, native_near, intent recorded (0.01 NEAR to own account)"; fi

# ── S1-W2: same, hang up at 3 s ──────────────────────────────────────────────
row=S1-W2
before="$(usage_count native)"; near0="$(near_balance "$ACCOUNT")"
id="$(hang_up_and_recover /wallet/v1/intents/withdraw "$wbody" MONEY_E2E_WALLET_KEY)" || { fail $row "no request id after the hang-up"; id=""; }
if [[ -n "$id" ]]; then
  final="$(poll "$id" MONEY_E2E_WALLET_KEY)"; st="$(jget '["status"]' <<<"$final")"
  near1="$(near_balance "$ACCOUNT")"
  grew="$(python3 -c "print(int('$near1')-int('$near0'))")"
  if [[ "$st" != success ]]; then fail $row "status $st: $(head -c 300 <<<"$final")"
  elif [[ "$grew" != "$ONE_HUNDREDTH_NEAR" ]]; then fail $row "the account grew by $grew, not exactly 0.01 NEAR once"
  elif [[ -n "$PSQL_CMD" && "$(usage_count native)" != "$((${before:-0}+1))" ]]; then fail $row "velocity not charged exactly once"
  else pass "$row withdraw after a hang-up → success, delivered once (0.01 NEAR)"; fi
fi

# ── S1-W3: withdraw more than the balance ────────────────────────────────────
row=S1-W3
resp="$(api POST "$API/wallet/v1/intents/withdraw" MONEY_E2E_WALLET_KEY "{\"to\":\"$ACCOUNT\",\"amount\":\"1000000000000000000000000000\",\"token\":\"near\",\"chain\":\"near\"}" 60 "s1-$(uuidgen)")"
code="$(code_of "$resp")"
if [[ "$code" != 4* ]]; then fail $row "HTTP $code instead of a 4xx: $(body_of "$resp" | head -c 200)"
else
  bad="$(sql "SELECT count(*) FROM wallet_requests WHERE wallet_id='$MONEY_E2E_WALLET_ID' AND status='processing' AND request_data->>'amount'='1000000000000000000000000000'")"
  if [[ -n "$PSQL_CMD" && "$bad" != 0 ]]; then fail $row "the refused withdraw left a processing row"
  else pass "$row refusal before sending → HTTP $code, no open row"; fi
fi

# ── S1-S3: swap with an impossible min_amount_out ────────────────────────────
row=S1-S3
resp="$(api POST "$API/wallet/v1/intents/swap" MONEY_E2E_WALLET_KEY "{\"token_in\":\"$USDC\",\"token_out\":\"$WNEAR\",\"amount_in\":\"500000\",\"min_amount_out\":\"999999999999999999999999999999\"}" 60 "s1-$(uuidgen)")"
rid="$(sql "SELECT request_id FROM wallet_requests WHERE wallet_id='$MONEY_E2E_WALLET_ID' AND request_type='swap' AND request_data->>'min_amount_out'='999999999999999999999999999999' ORDER BY created_at DESC LIMIT 1")"
if [[ -z "$PSQL_CMD" ]]; then skip $row "needs PSQL_CMD to read the row (HTTP $(code_of "$resp"))"
else
  st="$(sql "SELECT status FROM wallet_requests WHERE request_id='$rid'")"
  [[ "$st" == failed ]] && pass "$row refused swap → failed, not needs_review (nothing spent)" || fail $row "row status $st"
fi

# ── S1-T1 / S1-T2: transfer 0.1 USDC to the peer and back ────────────────────
if [[ -z "${MONEY_E2E_PEER_ACCOUNT:-}" ]]; then
  skip S1-T1 "MONEY_E2E_PEER_ACCOUNT not set"
  skip S1-T2 "MONEY_E2E_PEER_ACCOUNT not set"
else
  row=S1-T1
  peer0=0
  [[ -n "$MONEY_E2E_PEER_KEY" ]] && peer0="$(intents_balance "$USDC" MONEY_E2E_PEER_KEY)"
  tbody="{\"to\":\"$MONEY_E2E_PEER_ACCOUNT\",\"amount\":\"100000\",\"token\":\"$USDC\"}"
  id="$(hang_up_and_recover /wallet/v1/intents/transfer "$tbody" MONEY_E2E_WALLET_KEY)" || { fail $row "no request id after the hang-up"; id=""; }
  if [[ -n "$id" ]]; then
    seen="$(code_of "$(api GET "$API/wallet/v1/requests/$id" MONEY_E2E_WALLET_KEY)")"
    final="$(poll "$id" MONEY_E2E_WALLET_KEY)"; st="$(jget '["status"]' <<<"$final")"
    if [[ "$seen" != 200 ]]; then fail $row "the request answered $seen before settlement"
    elif [[ "$st" != success ]]; then fail $row "status $st: $(head -c 300 <<<"$final")"
    elif [[ -n "$MONEY_E2E_PEER_KEY" && "$(python3 -c "print(int('$(intents_balance "$USDC" MONEY_E2E_PEER_KEY)')-int('$peer0'))")" != 100000 ]]; then
      fail $row "the peer did not receive exactly 0.1 USDC once"
    else pass "$row transfer after a hang-up → success (0.1 USDC to the peer)"; fi
  fi
  row=S1-T2
  if [[ -z "$MONEY_E2E_PEER_KEY" ]]; then skip $row "MONEY_E2E_PEER_KEY not set — 0.1 USDC stays with the peer (ours)"
  else
    resp="$(api POST "$API/wallet/v1/intents/transfer" MONEY_E2E_PEER_KEY "{\"to\":\"$ACCOUNT\",\"amount\":\"100000\",\"token\":\"$USDC\"}" 120 "s1-$(uuidgen)")"
    st="$(body_of "$resp" | jget '["status"]')"
    [[ "$st" == processing ]] && st="$(poll "$(body_of "$resp" | jget '["request_id"]')" MONEY_E2E_PEER_KEY | jget '["status"]')"
    [[ "$st" == success ]] && pass "$row transfer back → success" || fail $row "status $st"
  fi
fi

# ── S1-D1: the rows of this run ──────────────────────────────────────────────
row=S1-D1
if [[ -z "$PSQL_CMD" ]]; then skip $row "needs PSQL_CMD"
else
  ids="$(sort -u "$RUN_IDS" | sed "s/.*/'&'/" | paste -sd, -)"
  if [[ -z "$ids" ]]; then skip $row "no request ids recorded"
  else
    bad="$(sql "SELECT count(*) FROM wallet_requests WHERE request_id IN ($ids) AND (status='needs_review' OR (status='processing' AND created_at < NOW() - INTERVAL '5 minutes') OR NOT (result_data ? 'intent'))")"
    [[ "$bad" == 0 ]] && pass "$row every row settled, none for review, every one recorded its intent" || fail $row "$bad row(s) open, for review, or without an intent"
  fi
fi

# ── S1-D2: the nine rows of the 2026-10-02 report ────────────────────────────
row=S1-D2
if [[ -z "$PSQL_CMD" ]]; then skip $row "needs PSQL_CMD"
else
  left="$(sql "SELECT count(*) FROM wallet_requests WHERE request_id IN ('04b9bdff-a529-4645-a2a4-1fbbf717cfd7','14eb73e4-cc07-44b2-a221-c0e5e7a889b5','7d45cad4-3b67-47c9-84fd-8d9ff3b9e913','79f3a712-eee2-45df-a588-11375721ce2b','34328f01-0165-4df2-9631-67743c8fa517','2b52ae73-9138-46a2-9403-8f365b5ccc0c','38984332-1112-4955-9c2f-69d190f3fc4e','36189c8c-e665-4e39-9c1e-e29a91ce9f72','14119bbc-d8be-4144-9f20-f992ebd0b113') AND status <> 'success'")"
  [[ "$left" == 0 ]] && pass "$row the nine reported rows are success" || fail $row "$left of the nine reported rows are not success (Q5 not applied yet?)"
fi

# ── S1-L1: the coordinator log since this run started ────────────────────────
row=S1-L1
if [[ -z "${COORDINATOR_SSH:-}" ]]; then skip $row "set COORDINATOR_SSH=root@host to read the coordinator log (read-only)"
else
  hits=0
  while read -r id; do
    n="$(ssh -o ConnectTimeout=15 -o BatchMode=yes -o ControlMaster=no -o ControlPath=none "$COORDINATOR_SSH" \
          "docker logs --since 30m offchainvm-coordinator-mainnet 2>&1 | grep -c 'needs_review.*$id' || true")"
    hits=$((hits + ${n:-0}))
  done < <(sort -u "$RUN_IDS")
  [[ $hits -eq 0 ]] && pass "$row no request of this run went to review" || fail $row "$hits review line(s) for this run's requests"
fi

if [[ $ROWS_ONLY -eq 0 ]]; then
  echo "USDC in A: $USDC0 → $(intents_balance "$USDC" MONEY_E2E_WALLET_KEY)"
  echo "── step 1: $PASS pass, $FAIL fail, $SKIP skip"
fi
[[ $FAIL -eq 0 ]]
