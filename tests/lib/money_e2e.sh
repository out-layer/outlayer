# Shared by the money-settlement live checks (step 1 and step 2). Sourced
# after the caller has set API, PSQL_CMD, RPC_URL and IDEM_PREFIX and sourced
# its env file: keys stay in the environment and are read there by name.

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# ── HTTP through Python: keys are read from the environment by name, never
#    put on a command line (`ps` shows argv to every process on the box).
cat >"$WORK/api.py" <<'PY'
import json, os, sys, urllib.request, urllib.error, socket
method, url, key_var = sys.argv[1], sys.argv[2], sys.argv[3]
body = sys.argv[4] if len(sys.argv) > 4 and sys.argv[4] else None
# A body that carries a secret is passed by the NAME of the variable holding it.
if body and body.startswith("@env:"):
    body = os.environ[body[5:]]
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
api() { python3 "$WORK/api.py" "$@"; }          # METHOD URL KEYVAR [BODY|@env:VAR] [TIMEOUT] [IDEM]
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
  local path="$1" body="$2" keyvar="$3" idem="$IDEM_PREFIX-$(uuidgen | tr 'A-Z' 'a-z')" resp id i
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

