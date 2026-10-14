#!/usr/bin/env bash
#
# A run's linear memory is bounded by its max_memory_mb, never below the
# worker's floor (WASM_MEMORY_FLOOR_MB, 1024) and never above 4096; growth past
# the bound is refused, not trapped, and the work is billed. A failed run pays
# the success formula on what the worker reports. Against the DEPLOYED worker
# and contract, through tests/mem-probe (wasm32-wasip1) from a FastFS URL.
#
#   W1  max_memory_mb 128, grows to 900 MiB   → succeeds, reached=900 (the floor)
#   W2  max_memory_mb 128, grows to 2000 MiB  → succeeds, reached=1024 (refused at the floor)
#   W3  max_memory_mb 2048, grows to 3000 MiB → succeeds, reached=2048 (refused at the request)
#   W4  W1–W3 report their instructions and are charged the formula on them
#   C1  max_memory_mb 4097 → refused at admission, naming the hard limit
#   C2  max_memory_mb 4096 → admitted and runs
#   C3  W2 then exit 1    → fails; charged base + instructions + time, the rest
#       refunded in the admission tx's receipts
#
# Run (spends a FastFS upload, six runs at ~the estimate, gas; testnet):
#   ./tests/worker_memory_e2e.sh --apply
#   OWNER=… overrides the signer (default below).

set -uo pipefail

APPLY=false
[[ "${1:-}" == "--apply" ]] && APPLY=true

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/hos_common.sh"   # NETWORK, CONTRACT_ID, keyed RPC_URL, pass/fail/skip/verdict, fastfs_upload
source "$SCRIPT_DIR/lib/near_sign.sh"    # near_why

OWNER="${OWNER:-outlayer-alice.testnet}"
PROBE_DIR="$SCRIPT_DIR/mem-probe"
PROBE_WASM="$PROBE_DIR/target/wasm32-wasip1/release/mem-probe.wasm"
CREDS_DIR="$HOME/.near-credentials/$NETWORK"

if [[ "$APPLY" != true ]]; then
  cat >&2 <<PLAN
  (dry-run) contract $CONTRACT_ID on $NETWORK, RPC $(rpc_url_public), signer $OWNER
  Pass --apply to run W1–W4 and C1–C3.
PLAN
  exit 0
fi

note "RPC: $(rpc_url_public)"
for tool in near jq curl outlayer cargo shasum; do command -v "$tool" >/dev/null || { echo "✗ missing $tool" >&2; exit 1; }; done
[[ -f "$CREDS_DIR/$OWNER.json" ]] || { echo "✗ creds missing: $CREDS_DIR/$OWNER.json" >&2; exit 1; }

OL_HOME=$(mktemp -d -t worker_memory_ol.XXXXXX)
trap 'rm -rf "$OL_HOME"' EXIT

# ── helpers ──────────────────────────────────────────────────────────────────

# The keyed RPC URL reaches curl on stdin, never on a command line.
rpc_post() { # rpc_post <json-body>
  printf 'url = "%s"\n' "$RPC_URL" | curl -sS --max-time 60 -K - -X POST \
    -H 'Content-Type: application/json' --data-binary "$1" 2>/dev/null
}
view() { # view <method> <args-json> — the decoded result, or empty
  rpc_post "$(jq -nc --arg a "$CONTRACT_ID" --arg m "$1" --arg g "$(printf '%s' "$2" | base64 | tr -d '\n')" \
    '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"call_function",finality:"final",account_id:$a,method_name:$m,args_base64:$g}}')" \
    | jq -r 'if .result.result then (.result.result | implode) else empty end' 2>/dev/null
}
call() { # call <method> <args-json> <deposit-yocto> — the whole transcript
  local out i
  for i in 1 2 3; do
    out=$(near contract call-function as-transaction "$CONTRACT_ID" "$1" json-args "$2" \
      prepaid-gas '300.0 Tgas' attached-deposit "$3 yoctoNEAR" sign-as "$OWNER" network-config "$NETWORK" \
      sign-with-legacy-keychain send 2>&1)
    grep -qE 'Transaction nonce .* must be|InvalidNonce|Transaction has expired' <<<"$out" || break
    sleep $((i * 3))
  done
  printf '%s\n' "$out"
}
tx_of() { grep -oE 'Transaction ID: *[1-9A-HJ-NP-Za-km-z]{40,50}' <<<"$1" | grep -oE '[1-9A-HJ-NP-Za-km-z]{40,50}' | head -1; }
why_of() {
  local m
  m=$(grep -oE 'Smart contract panicked: [^"\\]*|panicked at [^"\\]*' <<<"$1" | grep -viE 'https?:|apikey' | head -2 | tr '\n' ' ' | head -c 400)
  [[ -n "$m" ]] && printf '%s' "$m" || near_why "$1"
}
py() { python3 -c "$@"; }

limits() { jq -nc --argjson m "$1" '{max_instructions:1000000000, max_memory_mb:$m, max_execution_seconds:30}'; }
args_for() { # args_for <max_memory_mb> <input>
  jq -nc --argjson s "$SOURCE" --argjson l "$(limits "$1")" --arg i "$2" \
    '{source:$s, resource_limits:$l, input_data:$i, response_format:"Text"}'
}

# run <max_memory_mb> <input> — admits one request at the exact estimate and
# waits for its settlement. Sets PAY, TX, ADMIT_ERR (a refused admission),
# EV (the execution_completed data), OUT (the guest's text), BACK (the
# transfer to OWNER in the admission tx's receipts).
run() {
  local out res i
  PAY=$(view estimate_execution_cost "$(jq -nc --argjson l "$(limits "$1")" '{resource_limits:$l}')" | tr -d '"')
  EV=""; OUT=""; BACK=""; ADMIT_ERR=""
  out=$(call request_execution "$(args_for "$1" "$2")" "$PAY")
  TX=$(tx_of "$out")
  if [[ -z "$TX" ]] || ! grep -q 'execution_requested' <<<"$out"; then
    ADMIT_ERR=$(why_of "$out")
    # The panic's message follows its location after an escaped newline.
    grep -q 'exceeds hard limit' <<<"$out" && ADMIT_ERR="$ADMIT_ERR exceeds hard limit"
    return 0
  fi
  for i in $(seq 1 40); do
    res=$(rpc_post "$(jq -nc --arg t "$TX" --arg s "$OWNER" \
      '{jsonrpc:"2.0",id:1,method:"EXPERIMENTAL_tx_status",params:{tx_hash:$t,sender_account_id:$s,wait_until:"FINAL"}}')")
    EV=$(jq -c '[.result.receipts_outcome[]?.outcome.logs[]? | select(startswith("EVENT_JSON:")) | ltrimstr("EVENT_JSON:")
                 | (try fromjson catch empty) | select(.event == "execution_completed") | .data[0]] | first // empty' <<<"$res" 2>/dev/null)
    [[ -n "$EV" ]] && break
    (( i % 6 == 0 )) && note "still waiting for the run… ~$((i*10))s"
    sleep 10
  done
  OUT=$(jq -r '.result.status.SuccessValue // empty | @base64d' <<<"$res" 2>/dev/null | jq -r 'if type=="string" then . else tostring end' 2>/dev/null)
  BACK=$(jq -r --arg c "$CONTRACT_ID" --arg o "$OWNER" '[.result.receipts[]? | select(.predecessor_id == $c and .receiver_id == $o)
           | .receipt.Action.actions[]? | select(.Transfer) | .Transfer.deposit] | first // empty' <<<"$res" 2>/dev/null)
}
reached() { grep -oE 'reached=[0-9]+' <<<"$OUT" | cut -d= -f2; }
ev() { jq -r "$1 | if . == null then \"\" else tostring end" <<<"${EV:-null}"; }

# The charge the contract must apply: base + ⌊instructions / 1M⌋ × per-M +
# time_ms × per-ms + compile_ms × per-compile-ms, capped at the payment.
expected_charge() {
  py 'import json,sys
p=json.loads(sys.argv[1]); r=json.loads(sys.argv[2]); pay=int(sys.argv[3])
c=int(p[0])+(int(r["instructions"])//1000000)*int(p[1])+int(r["time_ms"])*int(p[2])+int(r.get("compile_time_ms") or 0)*int(p[3])
print(min(c,pay))' "$PRICING" "$(ev .resources_used)" "$PAY"
}
check_billing() { # check_billing <label> — W4/C3: instructions reported, charge = formula, refund = rest
  local want instr
  instr=$(ev .resources_used.instructions)
  if [[ -n "$instr" ]] && (( instr > 10000000 )); then pass "$1 reports its work: $instr instructions"
  else fail "$1 reports ${instr:-no} instructions; the probe burns ~10M iterations"; fi
  want=$(expected_charge)
  [[ "$(ev .payment_charged)" == "$want" ]] && pass "$1 charged $want = the formula on what it used" \
    || fail "$1 charged $(ev .payment_charged), the formula gives $want ($(ev .resources_used))"
  local rest; rest=$(py 'import sys; print(int(sys.argv[1])-int(sys.argv[2]))' "$PAY" "$want")
  if [[ "$rest" == "0" ]]; then
    [[ -z "$BACK" ]] && pass "$1 nothing to refund" || fail "$1 refunded $BACK with nothing left"
  else
    [[ "$BACK" == "$rest" && "$(ev .payment_refunded)" == "$rest" ]] && pass "$1 refunded $rest = payment − charge" \
      || fail "$1 refunded ${BACK:-nothing} (event $(ev .payment_refunded)), expected $rest"
  fi
}
expect_reached() { # expect_reached <label> <MiB>
  if [[ "$(ev .success)" == "true" && "$(reached)" == "$2" ]]; then pass "$1 succeeded, reached=$2"
  else fail "$1 success=$(ev .success) out='${OUT:0:120}' err='$(ev .error_message | head -c 200)', expected reached=$2"; fi
}

# ── setup: build, upload ─────────────────────────────────────────────────────

log "setup: mem-probe, uploaded as $OWNER"
(cd "$PROBE_DIR" && cargo build --release --target wasm32-wasip1 --quiet) || { echo "✗ mem-probe build failed" >&2; exit 1; }
HASH=$(shasum -a 256 "$PROBE_WASM" | cut -d' ' -f1)
mkdir -p "$OL_HOME/$NETWORK" && chmod 700 "$OL_HOME"
( umask 077; jq --arg c "$CONTRACT_ID" --arg a "$OWNER" '{account_id:$a, public_key, private_key, contract_id:$c, auth_type:"near_key"}' \
    "$CREDS_DIR/$OWNER.json" > "$OL_HOME/$NETWORK/credentials.json" )
export OUTLAYER_HOME="$OL_HOME"
URL=$(fastfs_upload "$PROBE_WASM" "$HASH") || { echo "✗ mem-probe never served its bytes from FastFS" >&2; exit 1; }
note "mem-probe $HASH at $URL"
SOURCE=$(jq -nc --arg u "$URL" --arg h "$HASH" '{WasmUrl:{url:$u, hash:$h, build_target:"wasm32-wasip1"}}')
PRICING=$(view get_pricing '{}')
note "pricing $PRICING"

# ── W: the bound ─────────────────────────────────────────────────────────────

log "W1 max_memory_mb 128, grows to 900 MiB — the floor admits it"
run 128 900
[[ -n "$ADMIT_ERR" ]] && fail "W1 not admitted: $ADMIT_ERR" || { expect_reached W1 900; check_billing W1; }

log "W2 max_memory_mb 128, grows to 2000 MiB — refused at the floor"
run 128 2000
[[ -n "$ADMIT_ERR" ]] && fail "W2 not admitted: $ADMIT_ERR" || { expect_reached W2 1024; check_billing W2; }

log "W3 max_memory_mb 2048, grows to 3000 MiB — refused at the request"
run 2048 3000
[[ -n "$ADMIT_ERR" ]] && fail "W3 not admitted: $ADMIT_ERR" || { expect_reached W3 2048; check_billing W3; }

# ── C: the contract ──────────────────────────────────────────────────────────

log "C1 max_memory_mb 4097 — refused at admission"
run 4097 1
if [[ -n "$ADMIT_ERR" ]] && grep -qi 'hard limit' <<<"$ADMIT_ERR"; then pass "C1 refused: $(head -c 160 <<<"$ADMIT_ERR")"
else fail "C1 expected a refusal naming the hard limit, got: ${ADMIT_ERR:-admitted (success=$(ev .success))}"; fi

log "C2 max_memory_mb 4096 — admitted"
run 4096 1
[[ -n "$ADMIT_ERR" ]] && fail "C2 not admitted: $ADMIT_ERR" || expect_reached C2 1

log "C3 grows to 2000 MiB under 128, then exits 1 — a failure after real work"
run 128 "2000 fail"
if [[ -n "$ADMIT_ERR" ]]; then fail "C3 not admitted: $ADMIT_ERR"
else
  [[ "$(ev .success)" == "false" ]] && pass "C3 failed: $(ev .error_message | head -c 160)" || fail "C3 success=$(ev .success), expected a failure"
  check_billing C3
fi

verdict "worker_memory_e2e"
