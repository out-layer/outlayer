#!/usr/bin/env bash
#
# A large `input_data` is paid for while the request holds it. Against the
# DEPLOYED contract.
#
#   E0  estimate_execution_cost takes input_len and quotes more for 40 KB than
#       for none (otherwise the deploy is pending: every probe SKIPs)
#   E1  a 40 KB request at the compute estimate alone → "Insufficient payment",
#       naming the free allowance
#   E2  the same request at the quote is admitted, and get_request shows the
#       quote as its payment
#   E3  it settles on its own within the yield window (the source cannot be
#       fetched, so the run fails and the deposit above the base fee comes back
#       — the arithmetic is the unit tests'; here only that the request is gone)
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
  WHY=$(near_why "$OUT")
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
if [[ -n "$RID" ]]; then
  HELD=$(view get_request "$(jq -nc --argjson r "$RID" '{request_id:$r}')" | jq -r '.payment // empty')
  [[ "$HELD" == "$QUOTE" ]] && pass "request $RID holds the quote as its payment" || fail "request $RID payment '$HELD', expected $QUOTE"
else
  fail "no request_id in the admission output"; RID=""
fi

log "E3 it settles on its own"
if [[ -n "$RID" ]]; then
  for _ in $(seq 1 60); do
    [[ "$(view get_request "$(jq -nc --argjson r "$RID" '{request_id:$r}')")" == "null" ]] && break
    sleep 5
  done
  [[ "$(view get_request "$(jq -nc --argjson r "$RID" '{request_id:$r}')")" == "null" ]] \
    && pass "request $RID settled within five minutes" || fail "request $RID is still pending after five minutes"
else
  skip "no request to watch"
fi

echo >&2
echo "PASS=$PASS FAILED=$FAILED SKIPPED=$SKIPPED" >&2
for n in "${FAILED_NAMES[@]:-}"; do [[ -n "$n" ]] && echo "  ✗ $n" >&2; done
[[ $FAILED -eq 0 ]]
