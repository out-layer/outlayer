#!/usr/bin/env bash
# Worker soft stop, live: a queue of HTTPS calls and one on-chain request, then
# `worker-ctl.sh stop` (soft) of the worker holding the first call while it runs.
#
# What must hold (W1–W6):
#   W1 the stopped worker logs the SIGTERM WHILE it holds a call, finishes and reports that
#      call after the signal (`Completing HTTPS call` for it), then `Drained`
#   W1b after the SIGTERM it takes no new task: no `Received execution request` follows it
#   W2 the held call's result reaches the caller, complete, with the probe's answer
#   W3 every other call and the on-chain request complete, wherever they run (the on-chain
#      one: its yield resumed, execution_completed success=true)
#   W4 the stop takes at most the task's remainder plus the poweroff, never the forced path
#   W5 the stopped worker starts again and takes work: a call made afterwards completes
#   W6 the worker-ctl exit code is 0 on the soft path
#
# An operator's suite: it needs ssh (as root) to the TDX nodes and the synced tree
# /home/outlayer/self-hosted-tdx on each. Nothing is forced; a worker that does not
# drain in time is reported and left running.
#
#   WORKER_A=testnet-worker-0191-101@dal WORKER_B=testnet-worker-0191-102@ams \
#     bash tests/worker_soft_stop_e2e.sh --apply
#
# `@dal` / `@ams` resolve through DAL_HOST / AMS_HOST in .env.nodes (repo root,
# gitignored); a literal host works too.
#
# Keys come from .env.testnet-keys through the environment (ALICE/BOB/CAROL_PAYMENT_KEY)
# and are never printed; the on-chain request signs as ON_CHAIN_SIGNER (outlayer-alice.testnet)
# from the legacy keychain and pays `sleep`'s price from its stablecoin balance on the contract.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/hos_common.sh"   # NETWORK, CONTRACT_ID, keyed RPC_URL, COORDINATOR_URL, pass/fail/verdict
source "$SCRIPT_DIR/lib/near_sign.sh"    # near_why: a near-cli error without its keyed URL

[[ "${1:-}" == "--apply" ]] || { sed -n 2,24p "$0"; exit 0; }
WORKER_A="${WORKER_A:?WORKER_A=<cvm-name>@<dal|ams|host>}"; WORKER_B="${WORKER_B:?WORKER_B=<cvm-name>@<dal|ams|host>}"
node_host() { # node_host <dal|ams|host>
  case "$1" in
    dal) echo "${DAL_HOST:?DAL_HOST unset — put it in .env.nodes at the repo root}" ;;
    ams) echo "${AMS_HOST:?AMS_HOST unset — put it in .env.nodes at the repo root}" ;;
    *)   echo "$1" ;;
  esac
}
A_NAME=${WORKER_A%@*}; A_HOST=$(node_host "${WORKER_A#*@}") || exit 1
B_NAME=${WORKER_B%@*}; B_HOST=$(node_host "${WORKER_B#*@}") || exit 1
ON_CHAIN_SIGNER="${ON_CHAIN_SIGNER:-outlayer-alice.testnet}"
PROBE="connectors.outlayer.testnet/connector-probe"
set -a; source "$SCRIPT_DIR/../.env.testnet-keys" >/dev/null 2>&1 || true; set +a
for k in ALICE_PAYMENT_KEY BOB_PAYMENT_KEY CAROL_PAYMENT_KEY; do [[ -n "${!k:-}" ]] || { echo "$k missing in .env.testnet-keys" >&2; exit 1; }; done
WORK=$(mktemp -d -t worker_soft_stop.XXXXXX); chmod 700 "$WORK"; trap 'rm -rf "$WORK"' EXIT
SSH="ssh -o ConnectTimeout=15 -o BatchMode=yes -o ControlMaster=no -o ControlPath=none"
ts() { date -u +%H:%M:%S; }

# ── node helpers ─────────────────────────────────────────────────────────────
# worker-ctl in the node's synced tree, with the node's vmm-cli (the outlayer
# profile's VMM_CLI where set, else the script's default).
ctl() { # ctl <host> <args...>
  local h=$1; shift
  $SSH "root@$h" "cd /home/outlayer/self-hosted-tdx && v=\$(grep -oE 'VMM_CLI=[^ ]+' /home/outlayer/.profile 2>/dev/null | cut -d= -f2); VMM_CLI=\${v:-/opt/mpc/dstack/vmm/src/vmm-cli.py} ./worker-ctl.sh $*"
}
# The guest-agent log dies with the VM: copy it to the host as it is written.
capture() { # capture <host> <name>
  # A separate ssh: a pkill sharing its command line with the `follow` it starts matches its own shell.
  $SSH "root@$1" "pkill -f 'worker-ctl[.]sh follow' >/dev/null 2>&1; true"
  $SSH "root@$1" "cd /home/outlayer/self-hosted-tdx && v=\$(grep -oE 'VMM_CLI=[^ ]+' /home/outlayer/.profile 2>/dev/null | cut -d= -f2); : > /tmp/$2.log; VMM_CLI=\${v:-/opt/mpc/dstack/vmm/src/vmm-cli.py} NAME=$2 TAIL=20 nohup ./worker-ctl.sh follow >> /tmp/$2.log 2>&1 & sleep 1"
}
nodelog() { $SSH "root@$1" "grep -v event_monitor /tmp/$2.log 2>/dev/null"; } # nodelog <host> <name>
host_of() { [[ "$1" == "$A_NAME" ]] && echo "$A_HOST" || echo "$B_HOST"; }

# ── API helpers ───────────────────────────────────────────────────────────────
call_sleep() { # call_sleep <key-var> <seconds> → "<http> <call_id>" on stdout (it runs in a $(…) subshell, so nothing global)
  local out="$WORK/call.json" code
  code=$(printf 'X-Payment-Key: %s\n' "${!1}" | curl -sS -o "$out" -w '%{http_code}' -H @- -H 'Content-Type: application/json' \
    -X POST "$COORDINATOR_URL/call/$PROBE" --data "{\"input\":{\"operation\":\"sleep\",\"seconds\":$2},\"async\":true}" 2>/dev/null)
  echo "$code $(jq -r '.call_id // empty' "$out")"
}
called() { # called <key-var> <seconds> → sets HTTP and CALL_ID
  local r; r=$(call_sleep "$1" "$2"); HTTP=${r%% *}; CALL_ID=${r#* }; [[ "$CALL_ID" == "$r" ]] && CALL_ID=""
}
result_of() { # result_of <key-var> <call_id> → status; body in $WORK/res.json
  printf 'X-Payment-Key: %s\n' "${!1}" | curl -sS -o "$WORK/res.json" -H @- "$COORDINATOR_URL/calls/$2" 2>/dev/null
  jq -r '.status // empty' "$WORK/res.json"
}
wait_done() { # wait_done <key-var> <call_id> <max-s> → final status
  local i st; for i in $(seq 1 $(( $3 / 3 ))); do st=$(result_of "$1" "$2"); [[ "$st" == completed || "$st" == failed ]] && { echo "$st"; return; }; sleep 3; done; echo "${st:-none}"
}
rpc_post() { printf 'url = "%s"\n' "$RPC_URL" | curl -sS --max-time 45 -K - -X POST -H 'Content-Type: application/json' --data-binary "$1" 2>/dev/null; }
tx_read() { rpc_post "$(jq -nc --arg t "$1" --arg s "$2" '{jsonrpc:"2.0",id:1,method:"tx",params:{tx_hash:$t,sender_account_id:$s,wait_until:"FINAL"}}')"; }
tx_of() { grep -oE 'Transaction ID: *[1-9A-HJ-NP-Za-km-z]{40,50}' <<<"$1" | grep -oE '[1-9A-HJ-NP-Za-km-z]{40,50}' | head -1; }

# ── the run ───────────────────────────────────────────────────────────────────
log "capturing both workers' logs on their hosts"
capture "$A_HOST" "$A_NAME"; capture "$B_HOST" "$B_NAME"

log "queue: on-chain (alice, 20 s) in the background; HTTPS #1 (alice, 30 s), #2 (bob, 30 s), #3 (carol, 15 s)"
# `send` waits for the whole yield to resolve, so it runs alongside the rest.
( near contract call-function as-transaction "$CONTRACT_ID" request_execution \
    json-args "$(jq -nc --arg p "$PROBE" --arg i '{"operation":"sleep","seconds":20}' \
      '{source:{Project:{project_id:$p}}, input_data:$i, response_format:"Json",
        resource_limits:{max_instructions:1000000000,max_memory_mb:128,max_execution_seconds:30}, params:{attached_usd:"10000"}}')" \
    prepaid-gas '300.0 Tgas' attached-deposit '0.1 NEAR' sign-as "$ON_CHAIN_SIGNER" network-config "$NETWORK" sign-with-legacy-keychain send \
    > "$WORK/onchain.out" 2>&1 ) &
ONCHAIN_PID=$!
called ALICE_PAYMENT_KEY 30; C1=$CALL_ID; [[ "$HTTP" == 200 && -n "$C1" ]] || { fail "HTTPS #1 not accepted (HTTP $HTTP)"; verdict; exit 1; }
called BOB_PAYMENT_KEY 30; C2=$CALL_ID;   [[ "$HTTP" == 200 && -n "$C2" ]] || { fail "HTTPS #2 not accepted (HTTP $HTTP)"; verdict; exit 1; }
called CAROL_PAYMENT_KEY 15; C3=$CALL_ID; [[ "$HTTP" == 200 && -n "$C3" ]] || fail "HTTPS #3 not accepted (HTTP $HTTP)"
note "call ids: #1=$C1 #2=$C2 #3=$C3"

# Which worker holds #1: its log names the call once claimed.
HOLDER=""; for i in $(seq 1 20); do
  nodelog "$A_HOST" "$A_NAME" | grep -q "$C1" && { HOLDER=$A_NAME; break; }
  nodelog "$B_HOST" "$B_NAME" | grep -q "$C1" && { HOLDER=$B_NAME; break; }
  sleep 1
done
[[ -n "$HOLDER" ]] || { fail "no worker's log names call #1 within 20 s"; verdict; exit 1; }
H_HOST=$(host_of "$HOLDER")
note "#1 is held by $HOLDER; soft-stopping it at $(ts)"

T0=$(date +%s); STOP_OUT=$(ctl "$H_HOST" stop "$HOLDER" 2>&1); RC=$?; T_STOP=$(( $(date +%s) - T0 ))
echo "$STOP_OUT" | sed 's/^/    /' >&2
[[ $RC -eq 0 ]] && pass "W6 soft stop returned 0 after ${T_STOP}s" || fail "W6 soft stop rc=$RC: $(tail -1 <<<"$STOP_OUT")"
grep -q 'stopped .* (soft)' <<<"$STOP_OUT" && pass "W4 the soft path, nothing forced" || fail "W4 not the soft path"
# ≤ the task's 30 s plus a poll and the poweroff
[[ $T_STOP -le 75 ]] && pass "W4 stop took ${T_STOP}s (≤ 75)" || fail "W4 stop took ${T_STOP}s"

HLOG=$(nodelog "$H_HOST" "$HOLDER")
line_of() { grep -nE "$1" <<<"$HLOG" | head -1 | cut -d: -f1; }
L_SIG=$(line_of 'SIGTERM: finishing the current task'); L_DONE=$(line_of "Completing HTTPS call: call_id=$C1"); L_DRAIN=$(line_of 'Drained: no task in hand')
[[ -n "$L_SIG" ]] && pass "W1 SIGTERM logged" || fail "W1 no SIGTERM line"
[[ -n "$L_SIG" && -n "$L_DONE" && $L_DONE -gt $L_SIG ]] \
  && pass "W1 #1 was in hand at the signal and completed after it" \
  || fail "W1 #1 completion (line ${L_DONE:-none}) not after the SIGTERM (line ${L_SIG:-none})"
[[ -n "$L_DRAIN" && -n "$L_DONE" && $L_DRAIN -gt $L_DONE ]] && pass "W1 Drained after the completion" || fail "W1 Drained (line ${L_DRAIN:-none}) not after the completion"
if [[ -n "$L_SIG" ]]; then
  NEW=$(tail -n +"$L_SIG" <<<"$HLOG" | grep -c 'Received execution request')
  [[ "$NEW" -eq 0 ]] && pass "W1b no new task after the SIGTERM" || fail "W1b $NEW task(s) received after the SIGTERM"
fi

S1=$(wait_done ALICE_PAYMENT_KEY "$C1" 30)
[[ "$S1" == completed && "$(jq -r '.output.detail // ""' "$WORK/res.json")" == "slept 30s and was still alive to say so" ]] \
  && pass "W2 #1 completed with the probe's answer" || fail "W2 #1 status=$S1 $(jq -c '.error // .output' "$WORK/res.json" | head -c 160)"

S2=$(wait_done BOB_PAYMENT_KEY "$C2" 120)
[[ "$S2" == completed ]] && pass "W3 #2 completed" || fail "W3 #2 status=$S2"
S3=$(wait_done CAROL_PAYMENT_KEY "$C3" 120)
[[ "$S3" == completed && "$(jq -r '.output.slept_ms // 0' "$WORK/res.json")" -ge 15000 ]] && pass "W3 #3 completed" || fail "W3 #3 status=$S3"

wait "$ONCHAIN_PID" 2>/dev/null; OUT=$(cat "$WORK/onchain.out"); TX=$(tx_of "$OUT")
[[ -n "$TX" ]] && note "on-chain request: tx $TX" || fail "W3 on-chain request did not land: $(near_why "$OUT" 2>/dev/null | head -c 200)"
if [[ -n "$TX" ]]; then
  EV=""; for i in $(seq 1 25); do
    LOGS=$(tx_read "$TX" "$ON_CHAIN_SIGNER")
    EV=$(jq -r '[.result.receipts_outcome[]?.outcome.logs[]?] | join("\n")' <<<"$LOGS" 2>/dev/null | grep -o 'EVENT_JSON:.*execution_completed.*' | sed 's/^EVENT_JSON://' | head -1)
    [[ -n "$EV" ]] && break; sleep 6
  done
  OK=$(jq -r '.data[0].success // "absent"' <<<"$EV" 2>/dev/null)
  [[ "$OK" == true ]] && pass "W3 on-chain request resumed: execution_completed success=true" || fail "W3 on-chain: success=$OK $(jq -c '.data[0].error_message // empty' <<<"$EV" 2>/dev/null | head -c 160)"
fi

log "start $HOLDER again and give it work"
ctl "$H_HOST" start "$HOLDER" >/dev/null 2>&1
UP=""; for i in $(seq 1 25); do sleep 4; ctl "$H_HOST" logs "$HOLDER" 2>/dev/null | grep -q 'Starting worker loop' && { UP=$((i*4)); break; }; done
[[ -n "$UP" ]] && pass "W5 $HOLDER polls again after ${UP}s" || fail "W5 $HOLDER did not come back within 100 s"
called ALICE_PAYMENT_KEY 5; C4=$CALL_ID; S4=$(wait_done ALICE_PAYMENT_KEY "$C4" 60)
[[ "$S4" == completed ]] && pass "W5 a call after the restart completed" || fail "W5 call after restart: $S4"

$SSH "root@$A_HOST" "pkill -f 'worker-ctl[.]sh follow' >/dev/null 2>&1; true"; $SSH "root@$B_HOST" "pkill -f 'worker-ctl[.]sh follow' >/dev/null 2>&1; true"
verdict
