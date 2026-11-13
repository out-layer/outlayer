#!/usr/bin/env bash
# The main contract's request lifecycle on the testnet set (accounts from deploy.sh): stored-output
# pricing, block staleness, the batch cancel and the self-cleaning sweep.
#
#   R1  estimate_execution_cost quotes the compute plus 0.00001 NEAR per byte of output_len
#   R2  an output the payment cannot hold is not stored: the request fails with
#       output_storage_unpaid, nothing stays pending
#   R3  an output the payment holds is stored and returned to the caller
#   R4  two requests made stuck on purpose (a proxy chains callbacks on the request, so its
#       settlement callback runs out of gas): pending, output stored, live until 400 blocks
#   R5  after 400 blocks both are stale; cancel_stale_executions by a stranger settles one and
#       refunds the payer
#   R6  an ordinary request from another account settles the other before storing its own
#       (sweep_stale), and the payer is refunded
#
# The suite acts as the main contract's operator for a while: the DAO sets OPERATOR as operator
# (one vote, delay 0) and sets the register account back at the end, also on failure.
# Testnet only. Needs: the DAO delay at 0, wasm-tools (builds the proxy), ~3 NEAR on CALLER.
# Takes ~10 minutes (400 blocks).

source "$(dirname "$0")/lib.sh"
set +e

OPERATOR="${OPERATOR:-outlayer-elena.testnet}"
CALLER="${CALLER:-$STRANGER}"
HONEST="${HONEST:-outlayer-carol.testnet}"
PROXY="${PROXY:-reqproxy.$CALLER}"
STALE_AFTER_BLOCKS=400
OUT_LEN=131072          # 128 KiB: under the sweep's 256 KB bound
CHAINED=12              # callbacks on the request promise: starve a 128 KiB settlement
WORK="$(mktemp -d)"

vote() { call "$1" "$DAO" vote "{\"proposal_id\":$2,\"approve\":$3}"; }
exec_() { call "$M3" "$DAO" execute "{\"proposal_id\":$1}" "300 Tgas"; }
b64() { printf '%s' "$1" | base64 | tr -d '\n'; }

set_operator() {
    local p
    p=$(propose "$M1" "{\"Call\":{\"target\":\"$MAIN\",\"method\":\"set_operator\",\"args\":\"$(b64 "{\"new_operator_id\":\"$1\"}")\",\"deposit\":\"0\",\"gas_tgas\":30}}") || return 1
    vote "$M2" "$p" true && exec_ "$p"
}
restore() {
    wait 2>/dev/null
    set_operator "$WORKER" && echo "operator set back to $WORKER" || echo "!! set the operator of $MAIN back to $WORKER by a DAO proposal"
    rm -rf "$WORK"
}

[ "$(view "$DAO" get_gov_delay_sec)" = "0" ] || { echo "the DAO delay must be 0 for this suite"; exit 1; }
command -v wasm-tools >/dev/null || { echo "wasm-tools is needed to build the proxy"; exit 1; }

limits='{"max_instructions":1000000000,"max_memory_mb":64,"max_execution_seconds":10}'
source_json='{"GitHub":{"repo":"https://github.com/out-layer/random-example","commit":"main","build_target":"wasm32-wasip1"}}'
estimate() { view "$MAIN" estimate_execution_cost "{\"resource_limits\":$limits,\"output_len\":$1}" | tr -d '"'; }
# yoctoNEAR as NEAR, rounded up to 6 decimals: never less than the amount.
yocto_near() { python3 -I -c 'import sys; y=int(sys.argv[1]); u=10**18; print(f"{-(-y//u)/1e6:.6f}")' "$1"; }
next_id() { view "$MAIN" gov_health; }
status() { view "$MAIN" get_request_status "{\"request_id\":$1}"; }
field() { python3 -I -c 'import sys,json; d=json.loads(sys.argv[1]); print("none" if d is None else d[sys.argv[2]])' "$1" "$2"; }
height() { curl -s "$RPC_URL" -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"block","params":{"finality":"final"}}' | python3 -I -c 'import sys,json; print(json.load(sys.stdin)["result"]["header"]["height"])'; }
balance() { rpc_query "{\"request_type\":\"view_account\",\"finality\":\"final\",\"account_id\":\"$1\"}" | python3 -I -c 'import sys,json; print(json.load(sys.stdin)["result"]["result"]["amount"])'; }

# submit <id> <bytes> — the output as the operator, success, small resources.
submit() {
    local text
    text=$(python3 -I -c 'import sys; print("x"*int(sys.argv[1]))' "$2")
    printf '{"request_id":%s,"output":{"Text":"%s"},"success":true,"error":null,"resources_used":{"instructions":1000,"time_ms":1,"compile_time_ms":null},"compilation_note":null}' \
        "$1" "$text" > "$WORK/submit-$1.json"
    call_file "$OPERATOR" "$MAIN" submit_execution_output_and_resolve "$WORK/submit-$1.json" "300 Tgas"
}

# request_bg <tag> <signer> <deposit-yocto> — request_execution from <signer>, in the background
# (the call waits for its yield); prints the request id.
request_bg() {
    local id; id=$(next_id)
    near contract call-function as-transaction "$MAIN" request_execution \
        json-args "{\"source\":$source_json,\"resource_limits\":$limits,\"input_data\":\"{}\",\"response_format\":\"Text\"}" \
        prepaid-gas '200 Tgas' attached-deposit "$(yocto_near "$3") NEAR" sign-as "$2" \
        network-config "$NETWORK" sign-with-legacy-keychain send > "$WORK/$1.out" 2>&1 &
    printf '%s\n' "$id"
}

# stuck_bg <tag> — request_execution through the proxy with CHAINED callbacks on its promise and
# just enough gas for its own callback; prints the request id.
stuck_bg() {
    local id args; id=$(next_id)
    args=$(python3 -I -c '
import struct, sys, json, base64
main, limits, src = sys.argv[1], json.loads(sys.argv[2]), json.loads(sys.argv[3])
req = json.dumps({"source": src, "resource_limits": limits, "input_data": "{}", "response_format": "Text"}).encode()
gas = 60 * 10**12
print(base64.b64encode(struct.pack("<Q", gas) + bytes([int(sys.argv[4]), len(main)]) + main.encode() + req).decode())
' "$MAIN" "$limits" "$source_json" "$CHAINED")
    near contract call-function as-transaction "$PROXY" go base64-args "$args" \
        prepaid-gas '300 Tgas' attached-deposit "$(yocto_near "$(estimate $OUT_LEN)") NEAR" sign-as "$CALLER" \
        network-config "$NETWORK" sign-with-legacy-keychain send > "$WORK/$1.out" 2>&1 &
    printf '%s\n' "$id"
}

wait_pending() {  # <id> — until the request is admitted
    local i; for i in $(seq 1 20); do [ "$(status "$1")" != "null" ] && return 0; sleep 2; done; return 1
}

step "setup"
if [ -z "$(rpc_query "{\"request_type\":\"view_code\",\"finality\":\"final\",\"account_id\":\"$PROXY\"}" 2>/dev/null)" ]; then
    near account create-account fund-myself "$PROXY" '1 NEAR' autogenerate-new-keypair save-to-legacy-keychain \
        sign-as "$CALLER" network-config "$NETWORK" sign-with-legacy-keychain send >/dev/null 2>&1 \
        || { echo "could not create $PROXY"; exit 1; }
    wasm-tools parse "$(dirname "$0")/proxy.wat" -o "$WORK/proxy.wasm" \
        && near contract deploy "$PROXY" use-file "$WORK/proxy.wasm" without-init-call \
            network-config "$NETWORK" sign-with-legacy-keychain send >/dev/null 2>&1 \
        || { echo "could not deploy the proxy"; exit 1; }
    ok "proxy $PROXY deployed"
fi
set_operator "$OPERATOR" && ok "operator of $MAIN is $OPERATOR for the suite" || { bad "set_operator"; exit 1; }
trap restore EXIT

step "R1 the estimate quotes the stored output"
base=$(estimate 0); with=$(estimate 2000)
[ "$((with - base))" = "20000000000000000000000" ] && ok "2000 bytes of output add 0.02 NEAR" || bad "estimate: $base -> $with"

step "R2 an output the payment cannot hold"
id=$(request_bg r2 "$CALLER" "$base")
wait_pending "$id" && submit "$id" 2000; wait
# The reason is in the settlement callback, which belongs to the request's transaction.
if grep -q "output_storage_unpaid" "$WORK/r2.out" && [ "$(status "$id")" = "null" ]; then
    ok "refused with output_storage_unpaid; request $id settled"
else
    bad "request $id: $(status "$id")"
fi

step "R3 an output the payment holds"
id=$(request_bg r3 "$CALLER" "$with")
wait_pending "$id" && submit "$id" 2000; wait
grep -q "xxxxxxxxxx" "$WORK/r3.out" && [ "$(status "$id")" = "null" ] \
    && ok "stored, returned to the caller, settled ($id)" || bad "request $id: $(status "$id"); $(grep -iE 'error|panick' "$WORK/r3.out" | head -1)"

step "R4 two stuck requests"
a=$(stuck_bg stuck-a); wait_pending "$a"
b=$(stuck_bg stuck-b); wait_pending "$b"
submit "$a" "$OUT_LEN"; submit "$b" "$OUT_LEN"
sleep 5
for id in "$a" "$b"; do
    st=$(status "$id")
    [ "$(field "$st" output_submitted)" = "True" ] && [ "$(field "$st" output_bytes)" = "$OUT_LEN" ] && [ "$(field "$st" stale)" = "False" ] \
        && ok "request $id stuck: output stored, live" || bad "request $id: $st"
done

step "R5 stale after 400 blocks; a stranger's batch cancel"
from=$(height); waited=0
until [ "$(field "$(status "$a")" stale)" = "True" ] || [ $waited -ge 1200 ]; do sleep 20; waited=$((waited + 20)); done
[ "$(field "$(status "$a")" stale)" = "True" ] && ok "stale after $(( $(height) - from )) more blocks" || bad "not stale after ${waited}s"
before=$(balance "$PROXY")
call "$OPERATOR" "$MAIN" cancel_stale_executions "{\"request_ids\":[$b]}" "300 Tgas" \
    && [ "$(status "$b")" = "null" ] && ok "request $b cancelled by a batch" || bad "batch cancel: $(status "$b")"
after=$(balance "$PROXY")
python3 -I -c 'import sys; sys.exit(0 if int(sys.argv[2]) - int(sys.argv[1]) >= 131072 * 10**19 else 1)' "$before" "$after" \
    && ok "the payer got the output deposit back" || bad "refund: $before -> $after"

step "R6 the next ordinary request cleans the stuck one"
before=$(balance "$PROXY")
c=$(request_bg r6 "$HONEST" "$base"); wait_pending "$c"
[ "$(status "$a")" = "null" ] && ok "request $a settled by $HONEST's request $c" || bad "sweep: $(status "$a")"
after=$(balance "$PROXY")
python3 -I -c 'import sys; sys.exit(0 if int(sys.argv[2]) - int(sys.argv[1]) >= 131072 * 10**19 else 1)' "$before" "$after" \
    && ok "the payer got the output deposit back" || bad "refund: $before -> $after"
call "$OPERATOR" "$MAIN" resolve_execution "{\"request_id\":$c,\"response\":{\"success\":true,\"output\":{\"Text\":\"ok\"},\"error\":null,\"resources_used\":{\"instructions\":1000,\"time_ms\":1,\"compile_time_ms\":null},\"compilation_note\":null}}" "300 Tgas"; wait

summary
