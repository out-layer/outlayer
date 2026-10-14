#!/usr/bin/env bash
#
# A large `input_data` is paid for while the request holds it. Against the
# DEPLOYED contract.
#
#   E0  estimate_execution_cost takes input_len and quotes more for 40 KB than
#       for none (otherwise the deploy is pending: every probe SKIPs)
#   E1  a 40 KB request at the compute estimate alone → "Insufficient payment",
#       naming the free allowance
#   E2  the same request at the quote is admitted, and the admission event
#       shows the quote as its payment
#   E3  it settles on its own within the yield window: the source cannot be
#       fetched, the run fails having used nothing, and the admission tx's
#       receipts refund exactly quote − base fee (the storage part included)
#
# Run (spends a base fee and gas on testnet):
#   ./tests/input_storage_e2e.sh --apply
#   OWNER=… overrides the account (default below).

set -uo pipefail

APPLY=false
[[ "${1:-}" == "--apply" ]] && APPLY=true

NETWORK="${NETWORK:-testnet}"
CONTRACT_ID="${CONTRACT_ID:-outlayer.testnet}"
OWNER="${OWNER:-outlayer-alice.testnet}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/rpc.sh"
source "$SCRIPT_DIR/lib/near_sign.sh"

PASS=0; FAILED=0; SKIPPED=0; FAILED_NAMES=()
log()  { printf '\n\033[36m▶ %s\033[0m\n' "$*" >&2; }
note() { printf '\033[35m• %s\033[0m\n' "$*" >&2; }
pass() { printf '\033[32m✓ %s\033[0m\n' "$*" >&2; PASS=$((PASS+1)); }
fail() { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; FAILED=$((FAILED+1)); FAILED_NAMES+=("$*"); }
skip() { printf '\033[33m∅ SKIP: %s\033[0m\n' "$*" >&2; SKIPPED=$((SKIPPED+1)); }

view() {
  curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' --max-time 30 \
    -d "$(jq -nc --arg c "$CONTRACT_ID" --arg m "$1" --arg a "$(printf '%s' "$2" | base64 | tr -d '\n')" \
      '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"call_function",finality:"final",account_id:$c,method_name:$m,args_base64:$a}}')" \
    | jq -r '.result.result | implode' 2>/dev/null || echo 'null'
}

# tx <signer> <method> <json-args-file> <deposit-yocto> — sets OUT, RC, WHY.
# The arguments come from a FILE: a 40 KB string is past what a command line
# should carry.
tx() {
  OUT=$(near contract call-function as-transaction "$CONTRACT_ID" "$2" file-args "$3" \
    prepaid-gas '150.0 Tgas' attached-deposit "$4 yoctoNEAR" sign-as "$1" network-config "$NETWORK" \
    sign-with-keychain send 2>&1); RC=$?
  grep -q "succeeded" <<<"$OUT" || RC=1
  TXH=$(grep -aoE 'Transaction ID: [1-9A-HJ-NP-Za-km-z]{43,44}' <<<"$OUT" | head -1 | awk '{print $3}')
  WHY=$(near_why "$OUT")
}

# refunds <tx-hash> <sender> — "receiver amount" for every transfer the
# contract made inside that transaction's receipt tree. The settlement
# callback of a yield is a receipt of the ADMISSION transaction, so once the
# request has settled, its refund shows up here.
refunds() {
  curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' --max-time 60 \
    -d "$(jq -nc --arg h "$1" --arg s "$2" '{jsonrpc:"2.0",id:1,method:"EXPERIMENTAL_tx_status",params:{tx_hash:$h,sender_account_id:$s,wait_until:"FINAL"}}')" \
  | jq -r --arg c "$CONTRACT_ID" '.result.receipts[]? | select(.predecessor_id == $c)
      | .receiver_id as $r | .receipt.Action.actions[]? | select(.Transfer) | "\($r) \(.Transfer.deposit)"'
}
refused() { if [[ $RC -ne 0 ]] && grep -qi "$2" <<<"$WHY"; then pass "$1 refused: $(head -c 160 <<<"$WHY")"; else fail "$1 expected a refusal naming /$2/, got rc=$RC: $WHY"; fi; }
succeeded() { if [[ $RC -eq 0 ]]; then pass "$1"; else fail "$1: $WHY"; fi; }

LIMITS='{"max_instructions":1000000,"max_memory_mb":128,"max_execution_seconds":5}'
SOURCE='{"WasmUrl":{"url":"https://example.invalid/input-storage-probe.wasm","hash":"cbf80ed0080dd62f2041745cdc958ec0fbd192f33aeaa756f7873d742204b2f8","build_target":null}}'
INPUT_LEN=40960

if [[ "$APPLY" != true ]]; then
  cat >&2 <<PLAN
  (dry-run) contract $CONTRACT_ID on $NETWORK, RPC $(rpc_url_public), signer $OWNER
  Pass --apply to run E0–E3.
PLAN
  exit 0
fi

note "RPC: $(rpc_url_public)"
for tool in near jq curl python3; do command -v "$tool" >/dev/null || { echo "✗ missing $tool" >&2; exit 1; }; done

log "E0 the estimate takes input_len"
BASE=$(view estimate_execution_cost "$(jq -nc --argjson l "$LIMITS" '{resource_limits:$l}')" | tr -d '"')
QUOTE=$(view estimate_execution_cost "$(jq -nc --argjson l "$LIMITS" --argjson n "$INPUT_LEN" '{resource_limits:$l, input_len:$n}')" | tr -d '"')
note "estimate without input $BASE, with $INPUT_LEN bytes $QUOTE"
if ! python3 -c 'import sys; sys.exit(0 if int(sys.argv[2]) > int(sys.argv[1]) else 1)' "$BASE" "$QUOTE" 2>/dev/null; then
  skip "the deployed contract quotes the same with and without input_len — the deploy is pending"
  echo "PASS=$PASS FAILED=$FAILED SKIPPED=$SKIPPED" >&2; exit 0
fi
EXPECTED=$(python3 -c 'import sys; print(int(sys.argv[1]) + (int(sys.argv[2]) - 32*1024) * 10**19)' "$BASE" "$INPUT_LEN")
[[ "$QUOTE" == "$EXPECTED" ]] && pass "the quote is the estimate plus 0.00001 NEAR per byte above 32 KB" || fail "quote $QUOTE, expected $EXPECTED"

ARGS=$(mktemp -t input_storage.XXXXXX.json)
trap 'rm -f "$ARGS"' EXIT
python3 - "$ARGS" "$INPUT_LEN" "$SOURCE" "$LIMITS" <<'PY'
import json, sys
path, n, source, limits = sys.argv[1], int(sys.argv[2]), json.loads(sys.argv[3]), json.loads(sys.argv[4])
json.dump({"source": source, "resource_limits": limits, "input_data": "x" * n,
           "secrets_ref": None, "response_format": None, "payer_account_id": None, "params": None}, open(path, "w"))
PY

log "E1 the request at the compute estimate alone"
tx "$OWNER" request_execution "$ARGS" "$BASE"
refused "E1" "beyond the free"

log "E2 the request at the quote"
tx "$OWNER" request_execution "$ARGS" "$QUOTE"
succeeded "E2 admitted at the quote"
# The id is in the execution_requested event, inside the JSON-escaped
# request_data string: `\"request_id\":12`.
RID=$(grep -aoE 'request_id\\?"?:[0-9]+' <<<"$OUT" | head -1 | grep -oE '[0-9]+$')
# The payment the request holds, from the same event (the worker can settle a
# request that fails to fetch within seconds, before a view would see it).
HELD=$(grep -aoE 'payment\\?"?:\\?"?[0-9]+' <<<"$OUT" | head -1 | grep -oE '[0-9]+$')
[[ -n "$RID" ]] && pass "request $RID admitted" || fail "no request_id in the admission output"
[[ "$HELD" == "$QUOTE" ]] && pass "the request holds the quote as its payment" || fail "payment '$HELD' in the event, expected $QUOTE"
ADMIT_TX="$TXH"

log "E3 it settles on its own and the deposit above the base fee comes back"
if [[ -n "$RID" ]]; then
  for _ in $(seq 1 60); do
    [[ "$(view get_request "$(jq -nc --argjson r "$RID" '{request_id:$r}')")" == "null" ]] && break
    sleep 5
  done
  if [[ "$(view get_request "$(jq -nc --argjson r "$RID" '{request_id:$r}')")" == "null" ]]; then
    pass "request $RID settled within five minutes"
    # The source cannot be fetched, so the run FAILS: the refund is everything
    # above the base fee — the storage part included.
    BASE_FEE=$(view get_pricing '{}' | jq -r '.[0]')
    EXPECTED_BACK=$(python3 -c 'import sys; print(int(sys.argv[1]) - int(sys.argv[2]))' "$QUOTE" "$BASE_FEE")
    BACK=""
    for _ in $(seq 1 12); do
      BACK=$(refunds "$ADMIT_TX" "$OWNER" | awk -v o="$OWNER" '$1==o {print $2}' | head -1)
      [[ -n "$BACK" ]] && break
      sleep 5
    done
    if [[ "$BACK" == "$EXPECTED_BACK" ]]; then pass "refunded $BACK = quote − base fee ($BASE_FEE): the storage part came back"
    elif [[ -z "$BACK" ]]; then fail "no refund to $OWNER in the receipts of $ADMIT_TX"
    else fail "refunded $BACK, expected $EXPECTED_BACK (quote $QUOTE − base fee $BASE_FEE)"; fi
  else
    fail "request $RID is still pending after five minutes"
  fi
else
  skip "no request to watch"
fi

echo >&2
echo "PASS=$PASS FAILED=$FAILED SKIPPED=$SKIPPED" >&2
for n in "${FAILED_NAMES[@]:-}"; do [[ -n "$n" ]] && echo "  ✗ $n" >&2; done
[[ $FAILED -eq 0 ]]
