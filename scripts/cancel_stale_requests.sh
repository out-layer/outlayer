#!/usr/bin/env bash
# Find execution requests on the main contract still pending past EXECUTION_TIMEOUT, and with
# --send cancel them. Not for routine use: every request_execution already settles the stale
# requests before it (up to 2 per call, each holding at most 256 KB). Run it in an incident —
# the free balance of outlayer.<net> runs low, or a stuck request holds more than the sweep
# takes.
#
#   scripts/cancel_stale_requests.sh <testnet|mainnet> [--as <account>] [--send] [--contract <id>]
#
#   --as        the account that signs the cancels (near-cli legacy keychain). Any account:
#               `cancel_stale_execution` is open to anyone after the timeout, and the money
#               goes to each request's payer and sender, never to the caller. It pays only the
#               gas burnt: about 1 TGas per small request in a batch, up to ~75 TGas for one
#               with a large output (300 TGas attached per transaction).
#   --send      cancel what is found; without it the script only reports
#   --contract  default outlayer.<net>
#
# A request stale by the contract's rule (400 blocks after admission) is one whose settlement callback never ran
# to the end: its yield window (200 blocks) is long over. While it stays, its stored input and
# output hold the contract's storage. The cancel charges what the contract's own rule says
# (the base fee, or the compute estimate when the output was delivered) and refunds the rest.
#
# Reads go through the keyed RPC (tests/lib/rpc.sh); near-cli signs through its own rpc_url.
set -euo pipefail

NETWORK="${1:-}"
case "$NETWORK" in testnet|mainnet) shift ;; *) echo "usage: $0 <testnet|mainnet> [--as <account>] [--send] [--contract <id>]" >&2; exit 1 ;; esac
SUFFIX=$([ "$NETWORK" = mainnet ] && echo near || echo testnet)
CONTRACT="outlayer.$SUFFIX" SIGNER="" SEND=false
while [ $# -gt 0 ]; do
    case "$1" in
        --as) SIGNER="${2:?}"; shift 2 ;;
        --send) SEND=true; shift ;;
        --contract) CONTRACT="${2:?}"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 1 ;;
    esac
done
if $SEND && [ -z "$SIGNER" ]; then echo "--send needs --as <account>" >&2; exit 1; fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export NETWORK
# shellcheck source=../tests/lib/rpc.sh
source "$REPO_ROOT/tests/lib/rpc.sh"
echo "RPC: $(rpc_url_public)   contract: $CONTRACT"

# view <method> <json-args> — prints the method's JSON result, or fails with the RPC error.
view() {
    curl -sS --max-time 30 "$RPC_URL" -H 'content-type: application/json' -d "$(python3 -I -c '
import json, sys, base64
print(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "query", "params": {
    "request_type": "call_function", "finality": "final", "account_id": sys.argv[1],
    "method_name": sys.argv[2], "args_base64": base64.b64encode(sys.argv[3].encode()).decode()}}))
' "$CONTRACT" "$1" "$2")" | python3 -I -c '
import json, sys
r = json.load(sys.stdin)
res = r.get("result") or {}
if "result" not in res:
    sys.exit("view failed: " + str(res.get("error") or r.get("error"))[:300])
print(bytes(res["result"]).decode())'
}

# Every pending id, newest first, page by page.
ids=() from="null"
while :; do
    page=$(view get_pending_request_ids "{\"from_id\":$from,\"limit\":100}")
    read -r next found < <(python3 -I -c '
import json, sys
p = json.loads(sys.argv[1])
if isinstance(p, list):
    sys.exit("the contract runs code older than the paged get_pending_request_ids; upgrade it first")
print("null" if p["next_from_id"] is None else p["next_from_id"], " ".join(map(str, p["ids"])))
' "$page")
    [ -z "$found" ] || ids+=($found)
    [ "$next" = "null" ] && break
    from="$next"
done
echo "pending: ${#ids[@]}"

# Staleness is the contract's, by the time of the block the view runs at (`get_request_status`
# reads no input or output, so a request holding megabytes is read like any other). A request
# that cannot be read is still tried: the cancel checks the timeout itself and refuses a live one.
# Each stale request goes into a batch with its estimated gas. Measured on a sandbox: 0.81 TGas
# for a small request plus ~0.35 for its refund receipt, 3.58 with 32 KB of input and 32 KB of
# output, ~2 TGas for the call itself. Budgeted as 2.5 TGas per request plus 55 TGas per MiB of
# stored input and output; a batch stays under 250 TGas of the 300 attached. An unreadable
# request is cancelled alone.
# At most 100 per batch: the contract's MAX_STALE_CANCEL_BATCH.
stale=() batches=() batch="" batch_gas=0 batch_n=0 singles=()
add_to_batch() {  # <id> <estimated TGas>
    if [ -n "$batch" ] && { [ $((batch_gas + $2)) -gt 250 ] || [ $batch_n -ge 100 ]; }; then
        batches+=("$batch"); batch="" batch_gas=0 batch_n=0
    fi
    batch="${batch:+$batch,}$1"; batch_gas=$((batch_gas + $2)); batch_n=$((batch_n + 1))
}
for id in ${ids[@]+"${ids[@]}"}; do
    if ! st=$(view get_request_status "{\"request_id\":$id}" 2>&1); then
        stale+=("$id"); singles+=("$id")
        echo "  ?      #$id  unreadable ($st): will try the cancel alone"
        continue
    fi
    [ "$st" = "null" ] && continue
    read -r is_stale delivered payer out_bytes gas < <(python3 -I -c '
import json, sys
r = json.loads(sys.argv[1])
held = r["input_bytes"] + r["output_bytes"]
print("yes" if r["stale"] else "no", "output-delivered" if r["output_submitted"] else "no-output",
      r["payer_account_id"], r["output_bytes"], 3 + (held * 55) // (1 << 20))
' "$st")
    if [ "$is_stale" = yes ]; then
        stale+=("$id"); add_to_batch "$id" "$gas"
        echo "  stale  #$id  $delivered (${out_bytes} B)  payer $payer"
    else
        echo "  live   #$id"
    fi
done
[ -n "$batch" ] && batches+=("$batch")
echo "stale: ${#stale[@]}"

if ! $SEND; then
    [ ${#stale[@]} -gt 0 ] && echo "rerun with --as <account> --send to cancel them"
    exit 0
fi

call() {  # <method> <json-args> — sends as $SIGNER, prints the return value
    near contract call-function as-transaction "$CONTRACT" "$1" json-args "$2" \
        prepaid-gas '300 Tgas' attached-deposit '0 NEAR' \
        sign-as "$SIGNER" network-config "$NETWORK" sign-with-legacy-keychain send 2>&1
}

failed=0
for b in ${batches[@]+"${batches[@]}"}; do
    n=$(tr ',' '\n' <<<"$b" | wc -l | tr -d ' ')
    # A request settled or cancelled by someone else meanwhile is skipped by the contract.
    if out=$(call cancel_stale_executions "{\"request_ids\":[$b]}"); then
        echo "  batch of $n: cancelled $(grep -oE 'Cancelled [0-9]+ stale executions' <<<"$out" | grep -oE '[0-9]+' || echo '?')"
    else
        echo "  FAILED batch [$b]"; failed=$((failed + 1))
    fi
done
for id in ${singles[@]+"${singles[@]}"}; do
    if call cancel_stale_execution "{\"request_id\":$id}" >/dev/null; then
        echo "  cancelled #$id"
    elif [ "$(view get_request_status "{\"request_id\":$id}" 2>/dev/null)" = "null" ]; then
        echo "  #$id is gone already"
    else
        echo "  FAILED #$id (still pending, or not stale yet)"; failed=$((failed + 1))
    fi
done
[ $failed -eq 0 ]
