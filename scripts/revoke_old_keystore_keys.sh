#!/bin/bash
# Report — and optionally retire — everything belonging to OLD keystore versions.
#
# Run it as the LAST step of an upgrade: new keystore deployed and voted in, workers and
# coordinator repointed at it, everything verified. Then this drops the previous versions.
#
# How "old" is decided: every approved key is grouped by the IMAGE it registered under (the
# measurements recorded in its registration proposal). The image of the most recent
# registration is CURRENT; every other image is OLD. Grouping by image — not by key — is what
# makes this stable:
#   * a fleet of several instances of the current version keeps ALL of its keys;
#   * an instance that restarted and re-registered produces a new proposal with the SAME
#     measurements, so it stays in the current group instead of looking "newer";
#   * keys whose proposal is unreadable (they pre-date the current proposal format) are old by
#     construction — those proposals are the oldest ones on the contract.
#   * gateway-mode instances carry their instance-id in RTMR3, so two instances of ONE version
#     register with the same MRTD/RTMR0-2 and different RTMR3 — exactly what a version bump on
#     the same dstack image looks like. The chain cannot tell the two apart, so the script does
#     not guess: when such keys exist and no live key was named (KEEP_* / --keep), the run aborts
#     before printing a plan; once live keys are named, they are the WHOLE keep set and every
#     other key is retired — including the stale key an instance left behind when it restarted
#     (same measurements, new ephemeral key; only the node knows which one is alive).
#
# What it retires, in one run:
#   1. the OLD keys    — `propose_revoke_keystore_keys` (one proposal per <=16 keys, signed by
#                        zavodil.*). With a single DAO member the proposal executes in the same
#                        call; with more members the others just vote by id, with the same
#                        `vote {"proposal_id":N,"approve":true}` used for registrations
#   2. the OLD images  — each removed with `remove_approved_measurements` (owner-signed), so a
#                        retired image can never register again. The kept images are never
#                        touched: there is no moment in which the allowlist is empty or partial,
#                        so an instance that happens to boot mid-run still registers.
# Both belong here rather than at deploy time: while an old instance is still serving, removing
# its key or its image breaks it — its registration key is ephemeral, so it cannot re-register
# after a restart.
#
# A retired instance keeps answering from RAM for vaults it already loaded, but cannot derive a
# master for a NEW vault and cannot survive a restart. Shut it down afterwards.
#
# Which keys are live is taken from the nodes, not guessed. On every TDX node
#   outlayer keystore-keys <testnet|mainnet>
# prints `export KEEP_<SITE>="<key> <key>"` (KEEP_DAL on dal, KEEP_AMS on ams) with the registration
# key of each running keystore CVM there (read from its log). The script asks both nodes itself,
# over ssh as root, for any KEEP_* not already in the environment, and stops if a node does not
# answer with its line: every key in them is kept, everything else is retired — one command per
# network after a release. Exporting a KEEP_* by hand (empty is fine for a node without
# keystores) overrides what its node would say.
#
# Usage:
#   ./scripts/revoke_old_keystore_keys.sh <testnet|mainnet> [--keep ed25519:KEY]... [--send]
#
#   --keep   the same as a key in a KEEP_* variable: a live instance (or one deliberately kept)
#   --send   execute here after a confirmation prompt; without it the script only prints the
#            report and ready-to-run commands (mainnet keys usually live on another machine)
set -euo pipefail

NETWORK="${1:-}"
shift || true
case "$NETWORK" in
  testnet) DAO="dao.outlayer.testnet"; SIGNER="zavodil.testnet"; OWNER="owner.outlayer.testnet"; RPC="https://rpc.testnet.fastnear.com"; RPC_VAR=TESTNET_NEAR_RPC_URL ;;
  mainnet) DAO="dao.outlayer.near";    SIGNER="zavodil.near";    OWNER="owner.outlayer.near";    RPC="https://rpc.mainnet.fastnear.com"; RPC_VAR=MAINNET_NEAR_RPC_URL ;;
  *) echo "Usage: $0 <testnet|mainnet> [--keep ed25519:KEY]... [--send]" >&2; exit 1 ;;
esac
# The keyed RPC from the repo .env when present: the script reads every proposal on the DAO, and
# the public host rate-limits that mid-run.
HERE="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$HERE/../.env" ]; then
  keyed="$(grep -E "^${RPC_VAR}=" "$HERE/../.env" | tail -1 | cut -d= -f2- | tr -d '"' | tr -d "'")"
  [ -z "$keyed" ] || RPC="$keyed"
fi

KEEP=()
# Keys from the nodes, one variable per TDX node as printed by `outlayer keystore-keys`. All of
# them must be set (empty allowed): an unset one is a node that was not asked.
KEEP_VARS="KEEP_DAL KEEP_AMS"
# A variable not set in the environment is asked of its node here, over ssh, with the same
# command (`worker-ctl.sh keystore-keys`, what `outlayer keystore-keys` runs). It fails closed:
# the node prints no export line when a running keystore's key cannot be read, and an
# unreachable node, a refusal or a line for another site stops the run — a node that did not
# answer would otherwise have its live keystore revoked. A variable already set wins (a node
# asked by hand, or a deliberate value). `ssh -n`: the confirmation prompt below reads stdin.
node_of() { case "$1" in KEEP_DAL) echo 173.237.9.76 ;; KEEP_AMS) echo 23.109.254.164 ;; esac; }
for var in $KEEP_VARS; do
  [ -z "${!var+x}" ] || continue
  host="$(node_of "$var")"
  out=$(ssh -n -o BatchMode=yes -o ConnectTimeout=10 "root@$host" \
    "su - outlayer -c 'cd /home/outlayer/self-hosted-tdx && ./worker-ctl.sh keystore-keys $NETWORK'" 2>&1) \
    || { echo "$var: root@$host did not give its live keys (keystore-keys failed or the node is unreachable):" >&2
         printf '%s\n' "$out" | sed 's/^/    /' >&2; exit 1; }
  line=$(printf '%s\n' "$out" | grep -E "^export $var=\"[^\"]*\"$" | tail -1)
  [ -n "$line" ] || { echo "$var: root@$host answered without an 'export $var=...' line:" >&2
                      printf '%s\n' "$out" | sed 's/^/    /' >&2; exit 1; }
  printf '%s\n' "$out" | sed "s/^/  [$var from root@$host] /" >&2
  eval "$line"
done
missing=""
for var in $KEEP_VARS; do
  if [ -z "${!var+x}" ]; then missing="$missing $var"; continue; fi
  for k in ${!var}; do KEEP+=("$k"); done
done
if [ -n "$missing" ]; then
  echo "not set:$missing — run 'outlayer keystore-keys' on that node and paste its export line (an empty value is fine)" >&2
  exit 1
fi
SEND=false
while [ $# -gt 0 ]; do
  case "$1" in
    --keep)
      [ $# -ge 2 ] || { echo "--keep needs a public key" >&2; exit 1; }
      KEEP+=("$2"); shift 2 ;;
    --send) SEND=true; shift ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done
# MAX_REVOKE_BATCH in keystore-dao-contract: the contract rejects a larger ballot.
BATCH=16

PLAN="$(mktemp -t revoke_plan.XXXXXX)"
trap 'rm -f "$PLAN"' EXIT

export DAO RPC BATCH SIGNER OWNER NETWORK
echo "keeping ${#KEEP[@]} live key(s): $(for var in $KEEP_VARS; do printf '%s="%s" ' "$var" "${!var}"; done)" >&2
KEEP_ARGS="${KEEP[*]:-}" python3 - <<'PY' > "$PLAN"
import base64, datetime, json, os, sys, urllib.request

RPC, DAO, BATCH = os.environ['RPC'], os.environ['DAO'], int(os.environ['BATCH'])
SIGNER, OWNER, NETWORK = os.environ['SIGNER'], os.environ['OWNER'], os.environ['NETWORK']
forced_keep = sorted({k for k in os.environ.get('KEEP_ARGS', '').split() if k})
w = sys.stderr.write


def rpc(params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "query", "params": params}).encode()
    return json.load(urllib.request.urlopen(
        urllib.request.Request(RPC, body, {'Content-Type': 'application/json'})))


def call(method, args):
    return rpc({"request_type": "call_function", "finality": "final", "account_id": DAO,
                "method_name": method,
                "args_base64": base64.b64encode(json.dumps(args).encode()).decode()})


def view(method, args):
    """Decoded view result; any failure is fatal — silently skipping a read is how a live key
    ends up in the revoke list."""
    r = call(method, args)
    if 'result' not in r or 'result' not in r['result']:
        err = json.dumps(r)
        if 'MethodNotFound' in err and method == 'get_approved_keystores':
            raise SystemExit(
                f"{DAO} does not have `get_approved_keystores` — the wasm with "
                f"`propose_revoke_keystore_keys` is not deployed on {NETWORK} yet. Deploy "
                f"keystore-dao-contract/res/keystore_dao_contract.wasm, then call migrate().")
        raise SystemExit(f"RPC error on {method}({args}): {err[:400]}")
    return json.loads(bytes(r['result']['result']).decode())


def read_proposal(pid):
    """('ok', p) | ('legacy', None). Proposals older than the current format no longer
    deserialize — permanent and harmless. Any OTHER error aborts: a plan built from partial
    data is exactly how the wrong key gets revoked."""
    r = call('get_proposal', {"proposal_id": pid})
    if 'result' in r and 'result' in r['result']:
        return ('ok', json.loads(bytes(r['result']['result']).decode()))
    err = json.dumps(r)
    if 'Borsh' in err or 'deserialize' in err.lower():
        return ('legacy', None)
    raise SystemExit(f"RPC error reading proposal {pid}: {err[:400]}\n"
                     "Refusing to build a plan from partial data — re-run.")


approved, i = [], 0
while True:
    chunk = view('get_approved_keystores', {"from_index": i, "limit": 50})
    approved += chunk
    if len(chunk) < 50:
        break
    i += 50
cfg = view('get_config', {})

# Integrity check: the contract's set must match the FunctionCall keys actually installed on
# the account. A key on the account but NOT in the set cannot be revoked through the DAO at all
# (the contract only removes set members), so it is worth seeing before you trust the plan.
akl = rpc({"request_type": "view_access_key_list", "finality": "final", "account_id": DAO})
account_fc = {k['public_key'] for k in akl.get('result', {}).get('keys', [])
              if isinstance(k['access_key'].get('permission'), dict)}

# Key -> its (latest) executed registration proposal, which carries the image measurements.
by_key, legacy = {}, 0
for pid in range(0, cfg['next_proposal_id']):
    kind, p = read_proposal(pid)
    if kind == 'legacy':
        legacy += 1
    elif p and p.get('status') == 'Executed':
        prev = by_key.get(p['public_key'])
        if not prev or p['created_at'] > prev['created_at']:
            by_key[p['public_key']] = p

# Group approved keys by image; None = unknown image (unreadable proposal) => old.
groups = {}
for k in approved:
    p = by_key.get(k)
    img = json.dumps(p['measurements'], sort_keys=True) if p else None
    g = groups.setdefault(img, {"keys": [], "latest": -1})
    g["keys"].append(k)
    if p:
        g["latest"] = max(g["latest"], p['created_at'])

known = {img: g for img, g in groups.items() if img is not None}
if not known:
    raise SystemExit("No approved key has a readable registration proposal — cannot tell "
                     "versions apart. Re-run with explicit --keep key(s).")
current_img = max(known, key=lambda img: known[img]["latest"])

unknown_forced = [k for k in forced_keep if k not in approved]
if unknown_forced:
    raise SystemExit("KEEP_*/--keep key(s) not in approved_keystores: " + ", ".join(unknown_forced))

# Images that equal the current one except for RTMR3 are ambiguous: a live sibling instance of
# the current version (gateway mode puts the instance-id into RTMR3) looks exactly like an old
# version on the same dstack image. Without any named live key the script refuses to decide;
# with live keys named (KEEP_* from the nodes), every other key is old.
def os_image(img):
    m = json.loads(img)
    return tuple(m[k] for k in ('mrtd', 'rtmr0', 'rtmr1', 'rtmr2'))

ambiguous = [k for img, g in known.items() if img != current_img
             and os_image(img) == os_image(current_img)
             for k in g["keys"] if k not in forced_keep]
if ambiguous and not forced_keep:
    cur = groups[current_img]
    lines = [f"    {k}   proposal #{by_key[k]['id']}, registered "
             f"{datetime.datetime.fromtimestamp(by_key[k]['created_at'] / 1e9, datetime.timezone.utc):%Y-%m-%d %H:%M}"
             for k in sorted(ambiguous, key=lambda k: -by_key[k]['created_at'])]
    raise SystemExit(
        f"Cannot tell these key(s) apart from the current version (registered "
        f"{datetime.datetime.fromtimestamp(cur['latest'] / 1e9, datetime.timezone.utc):%Y-%m-%d %H:%M}, "
        f"{len(cur['keys'])} key(s)): same MRTD/RTMR0-2, different RTMR3 — a live sibling instance "
        "(gateway mode) and an old version on the same dstack image look identical on chain.\n"
        "  Name the live instances first: run `outlayer keystore-keys` on every node and paste its "
        "`export KEEP_<SITE>=...` line here (or --keep KEY); everything else is then retired.\n"
        + "\n".join(lines))

if forced_keep:
    # Live keys were named: they ARE the keep set. Everything else is retired — an old version,
    # and also the stale key of a CURRENT-version instance that has restarted since (its new
    # registration has the same measurements incl. RTMR3, so grouping by image cannot see that
    # the earlier key died with the earlier boot). The kept images are those the live keys
    # registered under.
    keep_keys = set(forced_keep)
    keep_images = []
    for k in forced_keep:
        p = by_key.get(k)
        if p and p['measurements'] not in keep_images:
            keep_images.append(p['measurements'])
else:
    keep_keys = set(groups[current_img]["keys"])
    keep_images = [json.loads(current_img)]
old_keys = [k for k in approved if k not in keep_keys]
forced_unknown_image = [k for k in forced_keep if k not in by_key]


def stamp(ts):
    return (datetime.datetime.fromtimestamp(ts / 1e9, datetime.timezone.utc)
            .strftime('%Y-%m-%d %H:%M')) if ts > 0 else 'unknown'


def show(img, g, label):
    m = json.loads(img) if img else None
    head = (f"mrtd={m['mrtd'][:8]}… rtmr3={m['rtmr3'][:8]}…" if m
            else "image unknown (proposal unreadable)")
    w(f"\n{label}  {head}   last registered {stamp(g['latest'])}   {len(g['keys'])} key(s)\n")
    for k in sorted(g['keys']):
        missing = "" if k in account_fc else "  (not on the account)"
        tag = "  [keep]" if k in keep_keys else "  [revoke]"
        w(f"    {k}{missing}{tag}\n")


w(f"\nDAO {DAO}  —  {len(approved)} approved key(s) in {len(groups)} image group(s), "
  f"threshold {cfg['approval_threshold']} of {cfg['dao_members_count']} member(s)\n")
if legacy:
    w(f"note: {legacy} proposal(s) pre-date the current format and cannot be read\n")

show(current_img, groups[current_img], "CURRENT")
for img, g in sorted(known.items(), key=lambda kv: -kv[1]["latest"]):
    if img != current_img:
        show(img, g, "OLD    ")
if None in groups:
    show(None, groups[None], "OLD    ")

orphans = sorted(account_fc - set(approved))
if orphans:
    w(f"\n!! {len(orphans)} FunctionCall key(s) on the account are NOT in approved_keystores, "
      f"so a revoke proposal cannot remove them (owner must delete them directly):\n")
    for k in orphans:
        w(f"    {k}\n")

images_onchain = view('get_approved_measurements', {})
stale_images = [m for m in images_onchain if m not in keep_images]

w(f"\n=> revoke {len(old_keys)} key(s) via {-(-len(old_keys) // BATCH)} proposal(s); "
  f"drop {len(stale_images)} of {len(images_onchain)} approved image(s)\n")

for n in range(0, len(old_keys), BATCH):
    args = json.dumps({"public_keys": old_keys[n:n + BATCH]})
    print(f"near contract call-function as-transaction {DAO} propose_revoke_keystore_keys "
          f"json-args '{args}' prepaid-gas '300.0 Tgas' attached-deposit '0 NEAR' "
          f"sign-as {SIGNER} network-config {NETWORK} sign-with-legacy-keychain send")

if forced_unknown_image:
    w("\nImage cleanup SKIPPED: a kept key has no readable proposal, so its image is unknown and "
      "any approved image could be the one it runs on.\n")
elif stale_images:
    # One removal per stale image, never a rebuild: the kept images stay on the list throughout,
    # so a keystore booting between two of these calls still finds its measurements approved.
    for m in stale_images:
        args = json.dumps({"measurements": m})
        print(f"near contract call-function as-transaction {DAO} remove_approved_measurements "
              f"json-args '{args}' prepaid-gas '30.0 Tgas' attached-deposit '0 NEAR' "
              f"sign-as {OWNER} network-config {NETWORK} sign-with-legacy-keychain send")

if not old_keys and not stale_images:
    print("echo 'Nothing to retire — only the current version is approved.'")
PY

VERIFY="near contract call-function as-read-only $DAO get_approved_keystores json-args '{\"from_index\":0,\"limit\":50}' network-config $NETWORK now"

if [ "$SEND" = true ]; then
  read -r -p "Send these transactions as $SIGNER / $OWNER? Type 'yes': " CONFIRM
  [ "$CONFIRM" = "yes" ] || { echo "Aborted."; exit 1; }
  bash -e "$PLAN"
  echo
  echo "Verify: $VERIFY"
else
  echo "--- run these where the $SIGNER / $OWNER keys live ---"
  echo "(each proposal records the proposer's vote; with $(printf '%s' "$DAO") at threshold 1 it executes at once,"
  echo " otherwise other members vote with: vote {\"proposal_id\":N,\"approve\":true})"
  echo
  cat "$PLAN"
  echo
  echo "Then verify: $VERIFY"
fi
