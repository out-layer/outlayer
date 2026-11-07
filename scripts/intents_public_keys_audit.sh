#!/usr/bin/env bash
# Which custody wallets have a key on intents.near other than their own?
#
# intents.near takes a transaction from the wallet's own NEAR account as the
# owner of the wallet's intents account (auth by predecessor), so before
# `capabilities.intents_call` fenced it, an agent with `call` could
# `add_public_key` a key of its own there — one that signs intents for the
# wallet outside the TEE, past any later policy, freeze or lock. This lists
# every wallet whose intents account holds any key but the one its implicit
# account id stands for (`public_keys_of` always includes that one).
#
# Read-only: one SELECT on the coordinator's application database, one view
# call per wallet. Moves nothing.
#
# Usage:
#   scripts/intents_public_keys_audit.sh          # wallets from the mainnet DB (ssh to $AMS_HOST, .env.nodes)
#   scripts/intents_public_keys_audit.sh FILE     # one `wallet_id|ed25519:<hex>`, `ed25519:<hex>` or `<hex>` per line
#
# Exit: 0 no extra key, 1 at least one extra key, 2 some wallets could not be read.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
NETWORK=mainnet
# shellcheck source=../tests/lib/rpc.sh
source "$ROOT/tests/lib/rpc.sh"
echo "RPC $(rpc_url_public)" >&2

LIST="$(mktemp)"
trap 'rm -f "$LIST"' EXIT

if [[ $# -ge 1 ]]; then
  cp "$1" "$LIST"
else
  set -a; source "$ROOT/.env.nodes"; set +a
  : "${AMS_HOST:?AMS_HOST is not in .env.nodes}"
  ssh -o ConnectTimeout=15 -o BatchMode=yes -o ControlMaster=no -o ControlPath=none "root@${AMS_HOST}" \
    "docker exec -i outlayer-mainnet-api-postgres-1 psql -U postgres -d outlayer -Atq -c \"SELECT wallet_id || '|' || near_pubkey FROM wallet_accounts WHERE near_pubkey IS NOT NULL ORDER BY created_at\"" \
    > "$LIST"
  # ssh multiplexing failures answer an empty string, not an error: an empty
  # list is a failed read, never "no wallets".
  [[ -s "$LIST" ]] || { echo "the wallet list came back empty — the read failed" >&2; exit 2; }
fi
echo "wallets: $(grep -c . "$LIST")" >&2

# RPC_URL carries the API key: it reaches python through the environment only.
export RPC_URL
python3 -I - "$LIST" <<'PY'
import base64, json, os, sys, time, urllib.request
from concurrent.futures import ThreadPoolExecutor

RPC = os.environ["RPC_URL"]
A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def b58(b):
    n = int.from_bytes(b, "big"); s = ""
    while n:
        n, r = divmod(n, 58); s = A[r] + s
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + s

def parse(line):
    line = line.strip()
    if not line:
        return None
    wallet_id, _, key = line.rpartition("|")
    hexpart = key.split(":", 1)[1] if key.startswith("ed25519:") else key
    hexpart = hexpart.lower()
    if len(hexpart) != 64 or any(c not in "0123456789abcdef" for c in hexpart):
        return (wallet_id or "?", key, None)
    return (wallet_id or "?", hexpart, "ed25519:" + b58(bytes.fromhex(hexpart)))

def keys_of(account):
    args = base64.b64encode(json.dumps({"account_id": account}).encode()).decode()
    body = json.dumps({"jsonrpc": "2.0", "id": "a", "method": "query", "params": {
        "request_type": "call_function", "finality": "final", "account_id": "intents.near",
        "method_name": "public_keys_of", "args_base64": args}}).encode()
    last = None
    for attempt in range(4):
        try:
            req = urllib.request.Request(RPC, body, {"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=20) as r:
                out = json.load(r)
            if "result" in out and "result" in out["result"]:
                return json.loads(bytes(out["result"]["result"]).decode())
            last = (out.get("error") or out.get("result", {}).get("error") or "no result")
        except Exception as e:  # the URL holds the key: report the kind, never the text
            last = type(e).__name__
        time.sleep(1 + attempt)
    raise RuntimeError(str(last)[:160])

rows = [p for p in (parse(l) for l in open(sys.argv[1])) if p]
bad_format = [r for r in rows if r[2] is None]
todo = [r for r in rows if r[2] is not None]

def check(row):
    wallet_id, account, own = row
    try:
        keys = keys_of(account)
    except Exception as e:
        return ("error", wallet_id, account, str(e))
    extra = sorted(set(keys) - {own})
    return ("extra" if extra else "ok", wallet_id, account, extra)

with ThreadPoolExecutor(max_workers=8) as pool:
    results = list(pool.map(check, todo))

extra = [r for r in results if r[0] == "extra"]
errors = [r for r in results if r[0] == "error"]
print(f"checked {len(results)}, clean {len(results) - len(extra) - len(errors)}, "
      f"EXTRA KEY {len(extra)}, unreadable {len(errors)}, not an implicit key {len(bad_format)}")
for _, wallet_id, account, keys in extra:
    print(f"EXTRA  wallet {wallet_id}  account {account}  keys {', '.join(keys)}")
for _, wallet_id, account, why in errors:
    print(f"ERROR  wallet {wallet_id}  account {account}  {why}")
for wallet_id, key, _ in bad_format:
    print(f"SKIP   wallet {wallet_id}  near_pubkey {key[:20]}… is not ed25519:<64 hex>")
sys.exit(1 if extra else 2 if errors else 0)
PY
