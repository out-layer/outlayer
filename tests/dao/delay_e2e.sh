#!/usr/bin/env bash
# Governance under a delay, live on dao.outlayer.testnet — the state mainnet starts in.
#   T1  SetDelay DELAY (from the delay in force) → get_gov_delay_sec = DELAY
#   T2  an approved proposal records executable_after = approval + DELAY; execute before it is
#       refused; the owner cancels another inside the window; a revocation stays uncancellable
#   T3  dao_drive (the deploy scripts' path) on an approved proposal under the delay: no execute,
#       return code 2, and it names when the proposal executes — in send and in print mode
#   T4  after DELAY the same proposal executes
# Each throwaway compose it approves is removed by the owner at the end. The delay stays DELAY
# (RESTORE_DELAY=<seconds> proposes it back after the run; that proposal itself waits DELAY).
#
#   TEST_ROOT=outlayer.testnet M1=zavodil2.testnet M2=zavodil.testnet M3=zavodil3.testnet \
#     DELAY=600 bash tests/dao/delay_e2e.sh --apply
[ "${1:-}" = "--apply" ] || { sed -n 2,15p "$0"; exit 0; }
shift

source "$(dirname "$0")/lib.sh"
set +e
# lib.sh's `call`, resending a transaction refused before it reached a block (expired, or its
# nonce taken): that changed nothing, and a check must not read it as the contract's answer.
call() {
    local signer="$1" acc="$2" method="$3" args="$4" gas="${5:-100 Tgas}" dep="${6:-0 NEAR}" try rc
    for try in 1 2 3; do
        LAST_OUT=$(near contract call-function as-transaction "$acc" "$method" json-args "$args" \
            prepaid-gas "$gas" attached-deposit "$dep" sign-as "$signer" \
            network-config "$NETWORK" sign-with-legacy-keychain send 2>&1); rc=$?
        printf '%s' "$LAST_OUT" | grep -qE 'Transaction has expired|must be account\[access_key\]\.nonce' || return $rc
        sleep 3
    done
    return $rc
}
DELAY="${DELAY:-600}"
RUN=$(date +%s)

vote() { call "$1" "$DAO" vote "{\"proposal_id\":$2,\"approve\":$3}"; }
exec_() { call "$M3" "$DAO" execute "{\"proposal_id\":$1}" "300 Tgas"; }
gp() { view "$DAO" get_gov_proposal "{\"proposal_id\":$1}"; }
field() { gp "$1" | python3 -I -c "import sys,json; print(json.load(sys.stdin).get('$2'))"; }
compose() { python3 -I -c "import hashlib,sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest())" "$1"; }
composes() { view "$DAO" get_approved_composes | tr -d '\n '; }

step "T1 SetDelay $DELAY"
NOW=$(view "$DAO" get_gov_delay_sec | tr -d '\n ')
echo "  delay in force: $NOW s"
p=$(propose "$M1" "{\"SetDelay\":{\"seconds\":$DELAY}}")
vote "$M2" "$p" true
if [ "$NOW" = 0 ]; then
    exec_ "$p"
else
    echo "  waiting the $NOW s in force before #$p executes"; sleep $((NOW + 5)); exec_ "$p"
fi
[ "$(view "$DAO" get_gov_delay_sec | tr -d '\n ')" = "$DELAY" ] && ok "the delay is $DELAY (proposal $p)" \
    || { bad "delay $(view "$DAO" get_gov_delay_sec | tr -d '\n '), proposal $p $(gov_status "$p")"; summary; exit 1; }

step "T2 an approved proposal waits"
C1=$(compose "probe-delay-a-$RUN"); C2=$(compose "probe-delay-b-$RUN")
p1=$(propose "$M1" "{\"ApproveCompose\":{\"compose_hash\":\"$C1\"}}"); vote "$M2" "$p1" true
python3 -I -c 'import json,sys
p=json.loads(sys.argv[1]); sys.exit(0 if p["status"]=="Approved" and p["executable_after"]-p["approved_at"]==int(sys.argv[2])*10**9 else 1)' \
    "$(gp "$p1")" "$DELAY" && ok "#$p1 approved, executable $DELAY s after approval" || bad "#$p1: $(gp "$p1" | tr -d '\n ' | cut -c1-200)"
expect_refused "Proposal executes from block timestamp" "$M3" "$DAO" execute "{\"proposal_id\":$p1}" "300 Tgas"
p2=$(propose "$M1" "{\"ApproveCompose\":{\"compose_hash\":\"$C2\"}}"); vote "$M2" "$p2" true
call "$OWNER" "$DAO" cancel "{\"proposal_id\":$p2}" && [ "$(gov_status "$p2")" = Cancelled ] \
    && ok "the owner cancelled approved #$p2 inside the window" || bad "cancel #$p2: $(gov_status "$p2")"
p3=$(propose "$M1" "{\"RevokeCompose\":{\"compose_hash\":\"$C2\"}}")
expect_refused "cannot be cancelled by the owner" "$OWNER" "$DAO" cancel "{\"proposal_id\":$p3}"
vote "$M2" "$p3" false; vote "$M3" "$p3" false
[ "$(gov_status "$p3")" = Rejected ] && ok "the revocation was voted down instead" || bad "#$p3 $(gov_status "$p3")"

step "T3 dao_drive under the delay"
for mode in send print; do
    out=$(bash -c "NETWORK=testnet DAO_CHAIN=$mode; source '$REPO_ROOT/scripts/lib/dao_gov.sh'; dao_drive '$DAO' '$M1' '{\"ApproveCompose\":{\"compose_hash\":\"$C1\"}}'; echo rc=\$?" 2>&1)
    printf '%s\n' "$out" | sed 's/^/    /' | head -6
    printf '%s' "$out" | grep -q 'rc=2' && printf '%s' "$out" | grep -qE "#$p1 is approved; it executes from [0-9-]+ [0-9:]+ UTC" \
        && ok "$mode mode: no execute, rc 2, names when #$p1 executes" || bad "$mode mode: $(printf '%s' "$out" | tail -2 | tr '\n' ' ')"
done
[ "$(gov_status "$p1")" = Approved ] && ok "#$p1 still Approved" || bad "#$p1 $(gov_status "$p1")"

step "T4 after the delay"
AFTER=$(field "$p1" executable_after)
WAIT=$(python3 -I -c "import time,sys; print(max(0, int(int(sys.argv[1])/1e9 - time.time()) + 10))" "$AFTER")
echo "  waiting ${WAIT} s"
sleep "$WAIT"
exec_ "$p1" && [ "$(gov_status "$p1")" = Executed ] && composes | grep -q "$C1" \
    && ok "#$p1 executed after the delay; the compose is approved" || bad "#$p1 $(gov_status "$p1")"

step "cleanup"
for c in "$C1" "$C2"; do
    composes | grep -q "$c" && call "$OWNER" "$DAO" remove_approved_compose "{\"compose_hash\":\"$c\"}" >/dev/null && echo "  removed ${c:0:12}…"
done
if [ -n "${RESTORE_DELAY:-}" ]; then
    p=$(propose "$M1" "{\"SetDelay\":{\"seconds\":$RESTORE_DELAY}}"); vote "$M2" "$p" true
    echo "  SetDelay $RESTORE_DELAY proposed as #$p; execute it after $DELAY s"
fi
echo "  delay now: $(view "$DAO" get_gov_delay_sec | tr -d '\n ') s"

summary
