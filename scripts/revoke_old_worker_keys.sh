#!/bin/bash
# Report — and optionally retire — the access keys of workers that are no longer running.
#
# Why this matters: a worker key is written to disk inside its CVM
# (`~/.near-credentials/worker-keypair.json`) and survives restarts, unlike the keystore's
# in-memory key. Every key on `worker.outlayer.*` may call `resolve_execution` and
# `submit_execution_output_and_resolve` on the main contract — which authorizes by
# `predecessor == operator_id` and never re-checks the registry. So a key left behind by a
# decommissioned worker can still submit execution results as long as a copy of its key file
# exists anywhere.
#
# How "live" is decided — no heuristics: the coordinator records each worker's public key when
# the worker opens its TEE session (`worker_status.worker_public_key`), and the worker uses the
# SAME key it registered on-chain (worker/src/main.rs: `tee_secret_key = secret_key.clone()`).
# Every live key is then confirmed against the chain with `view_access_key`.
#
# Full key forms come from the registration history: `register_worker_key` carries the public
# key in its arguments, and the indexer returns those arguments. This matters for ml-dsa-65
# keys — the chain only exposes them as `ml-dsa-65-hash:...`, which `PublicKey` cannot parse,
# so `remove_worker_keys` would be unable to name them without the history.
#
# Usage:
#   ./scripts/revoke_old_worker_keys.sh <testnet|mainnet> [--expect-live N] [--send]
#
#   --expect-live N   optional; abort unless the coordinator reports exactly N worker keys.
#                     The coordinator PRUNES worker_status rows, so a running worker can drop
#                     out of the KEEP set and land in the revoke list. Without the flag the
#                     report states how many workers it keeps — compare it with your fleet.
#
# Where each network's coordinator database is, in scripts/.env (scripts/.env.example) — one set
# per network, because each network's API runs on its own node:
#   WORKER_CLEANUP_SSH_<NET>    ssh target of the node running that network's API (root@…)
#   WORKER_CLEANUP_PG_<NET>     its postgres container
#   WORKER_CLEANUP_DB_<NET>     its database
#   WORKER_CLEANUP_NODES        every TDX node (ssh targets), for the fleet cross-check below
#   WORKER_CLEANUP_SSH_KEY      ssh key (default ~/.ssh/id_ed25519)
#   NEARBLOCKS_API_KEY          optional; raises the indexer rate limit
# <NET> is TESTNET or MAINNET. The chain is read through the keyed RPC of the repo .env
# (TESTNET_NEAR_RPC_URL / MAINNET_NEAR_RPC_URL).
#
# Two checks stand between a wrong database and a revoked live worker, and both stop the run:
#   * the freshest heartbeat in worker_status must be under WORKER_CLEANUP_MAX_HEARTBEAT_MIN
#     minutes (default 10) — a copy of the database that no coordinator writes to any more
#     (the pre-2026-10-17 one on the old API host is such a copy) fails it;
#   * the workers with a fresh heartbeat must be exactly the worker CVMs running on the nodes
#     (`<net>-worker-*` / `outlayer-worker-<net>-*` in lsvm), counted — unless --expect-live N
#     states the fleet size by hand.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."
[ -f "$SCRIPT_DIR/.env" ] && set -a && . "$SCRIPT_DIR/.env" && set +a || true

[ -z "${WORKER_CLEANUP_SSH:-}" ] || echo "note: WORKER_CLEANUP_SSH is not read any more (one host cannot serve both networks); set WORKER_CLEANUP_SSH_TESTNET / _MAINNET" >&2
SSH_KEY="${WORKER_CLEANUP_SSH_KEY:-$HOME/.ssh/id_ed25519}"
MAX_HB_MIN="${WORKER_CLEANUP_MAX_HEARTBEAT_MIN:-10}"

NETWORK="${1:-}"
shift || true
case "$NETWORK" in
  testnet) REGISTER="worker.outlayer.testnet"; OWNER="owner.outlayer.testnet"; INIT="init-worker.outlayer.testnet"
           RPC="https://rpc.testnet.fastnear.com"; IDX="https://api-testnet.nearblocks.io" ;;
  mainnet) REGISTER="worker.outlayer.near"; OWNER="owner.outlayer.near"; INIT="init-worker.outlayer.near"
           RPC="https://rpc.mainnet.fastnear.com"; IDX="https://api.nearblocks.io" ;;
  *) echo "Usage: $0 <testnet|mainnet> [--send]" >&2; exit 1 ;;
esac
NET_UC=$(printf '%s' "$NETWORK" | tr '[:lower:]' '[:upper:]')
v="WORKER_CLEANUP_SSH_$NET_UC"; SSH_TARGET="${!v:-}"
v="WORKER_CLEANUP_PG_$NET_UC";  PG="${!v:-}"
v="WORKER_CLEANUP_DB_$NET_UC";  DB="${!v:-}"
NODES="${WORKER_CLEANUP_NODES:-}"
missing=""
for v in "WORKER_CLEANUP_SSH_$NET_UC:$SSH_TARGET" "WORKER_CLEANUP_PG_$NET_UC:$PG" "WORKER_CLEANUP_DB_$NET_UC:$DB" "WORKER_CLEANUP_NODES:$NODES"; do
  [ -n "${v#*:}" ] || missing="$missing ${v%%:*}"
done
[ -z "$missing" ] || { echo "not set in scripts/.env:$missing (see scripts/.env.example)" >&2; exit 1; }
# The keyed RPC: the public host rate-limits the many view calls a run makes.
v="${NET_UC}_NEAR_RPC_URL"
if [ -f .env ] && keyed=$(grep -E "^$v=" .env | tail -1 | cut -d= -f2- | tr -d "\"'") && [ -n "$keyed" ]; then
  RPC="$keyed"
else
  echo "⚠ no keyed RPC ($v in the repo .env): reading the chain through the public host" >&2
fi

SEND=false
EXPECT_LIVE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --send) SEND=true; shift ;;
    --expect-live)
      [ $# -ge 2 ] || { echo "--expect-live needs a number" >&2; exit 1; }
      EXPECT_LIVE="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

# Every worker the coordinator currently knows about — deliberately NOT filtered by heartbeat
# age. A worker that is merely quiet (coordinator restart, network blip) is still running with
# its key file on disk; revoking it would break it until someone notices and restarts it. The
# heartbeat age is reported per key instead, so a genuinely dead row is visible before you sign.
LIVE=$(ssh -n -o BatchMode=yes "$SSH_TARGET" -i "$SSH_KEY" \
  "docker exec $PG psql -U postgres -d $DB -t -A -F'|' -c \
   \"SELECT worker_public_key, worker_id, round(extract(epoch from now()-last_heartbeat_at)/60) FROM worker_status WHERE worker_public_key IS NOT NULL AND worker_public_key <> '';\"") \
  || { echo "Could not read workers from $PG on $SSH_TARGET" >&2; exit 1; }

# An empty answer is the one failure that would sweep the whole fleet into the revoke list.
if [ -z "$(printf '%s' "$LIVE" | tr -d '[:space:]')" ]; then
  echo "The coordinator reports NO workers with a public key — refusing to build a plan." >&2
  echo "(Every installed key would look retired. Check $PG on $SSH_TARGET.)" >&2
  exit 1
fi

# Is this the database a coordinator writes to right now? A copy left behind (the old API host)
# answers with rows too — only none of them is fresh.
FRESHEST=$(printf '%s\n' "$LIVE" | awk -F'|' 'NF>=3 && $3 ~ /^[0-9]+$/ {print $3}' | sort -n | head -1)
if [ -z "$FRESHEST" ] || [ "$FRESHEST" -gt "$MAX_HB_MIN" ]; then
  echo "The freshest worker heartbeat in $PG on $SSH_TARGET is ${FRESHEST:-?} min old (limit $MAX_HB_MIN):" >&2
  echo "no coordinator is writing to this database now. Refusing to build a plan — point" >&2
  echo "WORKER_CLEANUP_SSH_$NET_UC / _PG_ / _DB_ at the $NETWORK API that is running." >&2
  exit 1
fi
FRESH_COUNT=$(printf '%s\n' "$LIVE" | awk -F'|' -v m="$MAX_HB_MIN" 'NF>=3 && $3 ~ /^[0-9]+$/ && $3 <= m' | wc -l | tr -d ' ')

# The fleet as the nodes see it: the worker CVMs running there. Counted against the workers with
# a fresh heartbeat; --expect-live N replaces this count with one stated by hand.
if [ -z "$EXPECT_LIVE" ]; then
  RUNNING=0
  for node in $NODES; do
    out=$(ssh -n -o BatchMode=yes -o ConnectTimeout=10 "$node" -i "$SSH_KEY" \
      "su - outlayer -c 'python3 /home/outlayer/meta-dstack/dstack/vmm/src/vmm-cli.py --url http://127.0.0.1:11000 lsvm'" 2>/dev/null) \
      || { echo "$node: no answer from its vmm — refusing to build a plan (pass --expect-live N to state the fleet by hand)" >&2; exit 1; }
    n=$(printf '%s\n' "$out" | sed 's/│/|/g' | awk -F'|' -v net="$NETWORK" '
      { name=$4; status=$5; gsub(/[[:space:]]/,"",name); gsub(/[[:space:]]/,"",status)
        if (status == "running" && (index(name, net "-worker-") == 1 || index(name, "outlayer-worker-" net "-") == 1)) c++ }
      END { print c+0 }')
    echo "  $node: $n running $NETWORK worker CVM(s)" >&2
    RUNNING=$((RUNNING + n))
  done
  if [ "$RUNNING" -ne "$FRESH_COUNT" ]; then
    echo "The nodes run $RUNNING $NETWORK worker CVM(s), the coordinator has $FRESH_COUNT with a heartbeat in the last $MAX_HB_MIN min." >&2
    echo "Refusing to build a plan: a running worker would land in the revoke list. Wait for a heartbeat, or pass --expect-live N." >&2
    exit 1
  fi
  echo "  fleet: $RUNNING running worker CVM(s) = $FRESH_COUNT fresh coordinator row(s)" >&2
fi

PLAN="$(mktemp -t worker_revoke.XXXXXX)"
trap 'rm -f "$PLAN"' EXIT

export REGISTER OWNER INIT RPC IDX NETWORK LIVE EXPECT_LIVE
python3 - <<'PY' > "$PLAN"
import json, os, sys, time, urllib.error, urllib.request

REGISTER, OWNER, INIT = os.environ['REGISTER'], os.environ['OWNER'], os.environ['INIT']
RPC, IDX, NETWORK = os.environ['RPC'], os.environ['IDX'], os.environ['NETWORK']
API_KEY = os.environ.get('NEARBLOCKS_API_KEY', '')
EXPECT_LIVE = os.environ.get('EXPECT_LIVE', '').strip()
live_rows = []
for line in os.environ['LIVE'].splitlines():
    line = line.strip()
    if not line:
        continue
    parts = line.split('|')
    live_rows.append((parts[0], parts[1] if len(parts) > 1 else '?',
                      parts[2] if len(parts) > 2 else '?'))
live_keys = [r[0] for r in live_rows]
if EXPECT_LIVE:
    # The coordinator deletes worker_status rows (stale-instance cleanup, superseded-version
    # pruning), so a RUNNING worker can silently vanish from the KEEP set. State the expected
    # fleet size and the run stops if reality disagrees.
    if len(live_keys) != int(EXPECT_LIVE):
        raise SystemExit(f"--expect-live {EXPECT_LIVE} but the coordinator reports "
                         f"{len(live_keys)} worker key(s). Refusing to build a plan.")
w = sys.stderr.write
# remove_worker_keys spends gas per key, and an ml-dsa-65 key (~2.6 KB as a string) is expensive
# to parse: one measured at 65 Tgas on worker.outlayer.testnet (2026-10-20), an ed25519 key a few.
# Calls are filled up to a budget below the 300 Tgas a transaction may carry.
GAS_PER_KEY = {'ml-dsa-65': 70, 'ed25519': 6}  # Tgas, with headroom
GAS_BUDGET = 250


def batches(keys):
    out, cur, used = [], [], 0
    for pk in keys:
        g = GAS_PER_KEY.get(pk.split(':', 1)[0], 70)
        if cur and used + g > GAS_BUDGET:
            out.append(cur); cur, used = [], 0
        cur.append(pk); used += g
    if cur:
        out.append(cur)
    return out


def rpc(params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "query", "params": params}).encode()
    return json.load(urllib.request.urlopen(
        urllib.request.Request(RPC, body, {'Content-Type': 'application/json'}), timeout=30))


_ak_cache = {}


def access_key(pk):
    """The full access key as the chain sees it, or None. Handles ml-dsa: the node resolves the
    full key to its stored hash form itself, which no local string comparison can do."""
    if pk not in _ak_cache:
        r = rpc({"request_type": "view_access_key", "finality": "final",
                 "account_id": REGISTER, "public_key": pk})
        res = r.get('result', {})
        if 'nonce' in res:
            _ak_cache[pk] = res
        elif (r.get('error') or {}).get('cause', {}).get('name') == 'UNKNOWN_ACCESS_KEY' \
                or 'does not exist' in str(res.get('error', '')):
            _ak_cache[pk] = None
        else:
            # A failed call is not an absent key: an answer like "the key is gone" from a
            # rate-limited RPC would take a live worker out of the picture.
            raise SystemExit(f"RPC error on view_access_key {pk[:24]}…: {json.dumps(r)[:300]}")
    return _ak_cache[pk]


def key_on_account(pk):
    ak = access_key(pk)
    return ak['nonce'] if ak else None


def indexer(path):
    headers = {'Accept': 'application/json', 'User-Agent': 'outlayer-ops/1.0'}
    if API_KEY:
        headers['Authorization'] = f'Bearer {API_KEY}'
    req = urllib.request.Request(IDX + path, headers=headers)
    # NearBlocks counts requests per minute-window (~10/min on the free tier; an API key raises
    # the ceiling but not the window). Once rejected, only a full minute clears it — a shorter
    # wait just burns another rejection.
    for attempt in range(8):
        try:
            return json.load(urllib.request.urlopen(req, timeout=40))
        except urllib.error.HTTPError as e:
            if e.code in (429, 403) and attempt < 7:
                wait = 60
                w(f"  indexer {e.code} (rate limit), waiting {wait}s…\n")
                time.sleep(wait)
                continue
            raise SystemExit(f"indexer error {e.code} on {path}: set NEARBLOCKS_API_KEY in "
                             f"scripts/.env to avoid the 60s waits")
    raise SystemExit("indexer unreachable")


# 1. Every key ever registered, in FULL form, from the registration arguments.
registered = {}   # public_key -> block_timestamp
page = 1
while True:
    d = indexer(f"/v1/account/{INIT}/txns?page={page}&per_page=50&order=desc")
    txns = d.get('txns', [])
    if not txns:
        break
    for t in txns:
        # Provenance matters: this endpoint is receipt-based and returns INBOUND rows from any
        # sender, including failed ones. Without these three checks anybody could put a key of
        # their choosing into the revoke list by sending a failing `register_worker_key` to the
        # init account — including this account's own full-access keys.
        if t.get('receiver_account_id') != REGISTER:
            continue
        if t.get('predecessor_account_id') != INIT:
            continue
        status = (t.get('outcomes') or {}).get('status')
        if status is not True:
            continue
        for a in (t.get('actions') or []):
            if a.get('method') != 'register_worker_key':
                continue
            try:
                args = json.loads(a.get('args') or '{}')
            except json.JSONDecodeError:
                continue
            pk = args.get('public_key')
            if pk:
                registered.setdefault(pk, t.get('block_timestamp'))
    w(f"  history page {page}: {len(registered)} key(s) so far\n")
    if len(txns) < 50:
        break
    page += 1
    if page > 20:                                   # sanity bound
        w("!! stopped paging the indexer at 1000 transactions\n")
        break

w(f"\nregistration history: {len(registered)} distinct key(s) ever registered by {INIT}\n")

# 2. Which of them are still installed, and which are live.
live_set = set(live_keys)
for pk in live_keys:
    if key_on_account(pk) is None:
        raise SystemExit(f"Live worker key is NOT on {REGISTER}: {pk[:40]}…\n"
                         "Refusing to build a plan — the coordinator and the chain disagree.")
    registered.setdefault(pk, None)

# The permission profile of the LIVE keys defines what a worker key looks like on this account.
# Anything that does not match it is not ours to delete — this is what structurally prevents a
# full-access key from ever entering the plan, whatever the indexer claims.
live_receivers = set()
for pk in live_keys:
    perm = access_key(pk)['permission']
    if not isinstance(perm, dict):
        raise SystemExit(f"Live worker key {pk[:34]}… is NOT a FunctionCall key — refusing to "
                         f"reason about this account.")
    live_receivers.add(perm['FunctionCall']['receiver_id'])

installed, stale, foreign = [], [], []
for pk in registered:
    ak = access_key(pk)
    if ak is None:
        continue                                    # already deleted earlier
    installed.append(pk)
    if pk in live_set:
        continue
    perm = ak['permission']
    if not isinstance(perm, dict) or perm['FunctionCall']['receiver_id'] not in live_receivers:
        kind = 'FullAccess' if not isinstance(perm, dict) else \
            f"FunctionCall->{perm['FunctionCall']['receiver_id']}"
        foreign.append((pk, kind))
        continue
    stale.append((pk, ak['nonce'] % 1_000_000, registered[pk]))

# The account's own key count, as a cross-check of the history. An account with very many keys
# is refused by the RPC (TOO_MANY_ACCESS_KEYS); the plan does not depend on the count — every key
# above was checked one by one — so only the cross-check is skipped then.
_akl = rpc({"request_type": "view_access_key_list", "finality": "final", "account_id": REGISTER})
if 'result' in _akl:
    onchain_total = len([k for k in _akl['result']['keys']
                         if isinstance(k['access_key']['permission'], dict)])
    w(f"on {REGISTER}: {onchain_total} FunctionCall key(s); recovered from history: {len(installed)}\n")
elif 'TOO_MANY_ACCESS_KEYS' in json.dumps(_akl):
    onchain_total = None
    w(f"on {REGISTER}: too many keys for the RPC to list them; recovered from history: "
      f"{len(installed)} (each checked on chain one by one)\n")
else:
    raise SystemExit(f"RPC error on view_access_key_list {REGISTER}: {json.dumps(_akl)[:300]}")
if onchain_total is not None and onchain_total > len(installed):
    w(f"!! {onchain_total - len(installed)} key(s) on the account are NOT in the registration "
      f"history — they were not installed by register_worker_key. Inspect them manually; this "
      f"script will not touch them.\n")

w(f"\nKEEP — known to the coordinator ({len(live_keys)}):\n")
quiet = []
for pk, wid, age in sorted(live_rows, key=lambda r: r[1]):
    try:
        age_i = int(float(age))
    except ValueError:
        age_i = -1
    if age_i > 15:
        quiet.append((wid, age_i))
    w(f"    {pk[:34]}…  tx={key_on_account(pk) % 1_000_000:<4} {wid[:44]}  "
      f"heartbeat {age_i if age_i >= 0 else '?'}m ago\n")
if quiet:
    w(f"!! {len(quiet)} kept worker(s) have not sent a heartbeat recently — they are kept "
      f"anyway; confirm they are still meant to run: {quiet}\n")

def ts(v):
    if not v:
        return "unknown"
    import datetime
    return datetime.datetime.fromtimestamp(int(v) / 1e9, datetime.timezone.utc).strftime('%Y-%m-%d')

if foreign:
    w(f"\n!! {len(foreign)} key(s) came out of the history but do NOT look like worker keys "
      f"(expected FunctionCall -> {sorted(live_receivers)}). NOT revoked:\n")
    for pk, kind in foreign:
        w(f"    {pk[:34]}…  {kind}\n")

w(f"\nSTALE — revoke ({len(stale)}):\n")
for pk, used, when in sorted(stale, key=lambda s: -s[1]):
    w(f"    {pk[:34]}…  tx={used:<4} registered={ts(when)}\n")

calls = batches([pk for pk, _, _ in stale])
w(f"\n=> remove {len(stale)} key(s) in {len(calls)} call(s), signed by {OWNER}\n")
if stale:
    w(f"\n   CHECK BEFORE SIGNING: this keeps {len(live_keys)} worker(s). If MORE than "
      f"{len(live_keys)} workers are running right now, some are missing from the coordinator's\n"
      f"   table (it prunes rows) and their keys are in the list above — stop and re-run with "
      f"--expect-live <real count>.\n")
if not stale:
    print("echo 'Nothing to retire — every installed key belongs to a live worker.'")
for keys in calls:
    args = json.dumps({"public_keys": keys})
    print(f"near contract call-function as-transaction {REGISTER} remove_worker_keys "
          f"json-args '{args}' prepaid-gas '300.0 Tgas' attached-deposit '0 NEAR' "
          f"sign-as {OWNER} network-config {NETWORK} sign-with-legacy-keychain send")
PY

VERIFY="near account list-keys $REGISTER network-config $NETWORK now"

if [ "$SEND" = true ]; then
  read -r -p "Send these transactions as $OWNER? Type 'yes': " CONFIRM
  [ "$CONFIRM" = "yes" ] || { echo "Aborted."; exit 1; }
  bash -e "$PLAN"
  echo
  echo "Verify: $VERIFY"
else
  echo "--- run these where the $OWNER key lives ---"
  echo
  cat "$PLAN"
  echo
  echo "Then verify: $VERIFY"
fi
