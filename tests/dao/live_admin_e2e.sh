#!/usr/bin/env bash
# The owner's and the DAO's remaining powers, live on the testnet contracts (outlayer.testnet,
# dao.outlayer.testnet), each one changed and put back:
#   A1  the payment token is the DAO's: the owner is refused; a Call proposal sets another one,
#       a second sets the original back (both read back from the contract);
#   A2  clear_all_pending_requests is the owner's: a stranger is refused; the owner clears a
#       request of this suite that is still pending, and the payer is refunded;
#   A3  emergency_cancel_execution, the same for one request by id;
#   A4  a guest OS image: approved by vote, revoked by vote (the owner cannot cancel the
#       revocation), and the owner's fast path removes another without one;
#   A5  ApproveMeasurements / RevokeMeasurements are no longer proposed;
#   A6  vault versions: approved by quorum (a non-member refused), deprecated by one member,
#       revoked by quorum;
#   A7  a vault banned by a member, unbanned by a member only.
#
#   TEST_ROOT=outlayer.testnet M1=zavodil2.testnet M2=zavodil.testnet M3=zavodil3.testnet \
#     bash tests/dao/live_admin_e2e.sh --apply
#
# Testnet only, DAO delay 0. A1 leaves the contract on another token for about a minute:
# stablecoin deposits in that minute go to the wrong contract's ft_on_transfer and are
# refused back to their senders. A2/A3 cost CALLER (default outlayer-alice.testnet) a 0.1 NEAR
# request each, refunded by the clear.
[ "${1:-}" = "--apply" ] || { sed -n 2,23p "$0"; exit 0; }
shift

source "$(dirname "$0")/lib.sh"
set +e

[ "$NETWORK" = testnet ] || { echo "testnet only"; exit 1; }
[ "$(view "$DAO" get_gov_delay_sec)" = "0" ] || { echo "the DAO delay must be 0 for this suite"; exit 1; }
CALLER="${CALLER:-outlayer-alice.testnet}"

# lib.sh's `call`, resending a transaction the node refused before it reached a block (expired,
# or its nonce taken): that changed nothing, and a check must not read it as the contract's answer.
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

vote() { call "$1" "$DAO" vote "{\"proposal_id\":$2,\"approve\":$3}"; }
exec_() { call "$M3" "$DAO" execute "{\"proposal_id\":$1}" "300 Tgas"; }
b64() { printf '%s' "$1" | base64 | tr -d '\n'; }
# Proposed by M1, voted by M2, executed: 0 when the DAO records it Executed.
pass_by_vote() {
    local p; p=$(propose "$M1" "$1") || return 1
    vote "$M2" "$p" true && exec_ "$p"
    [ "$(gov_status "$p")" = "Executed" ]
}
logs_have() { printf '%s' "$LAST_OUT" | grep -qF "$1"; }
RUN=$(date +%s)

step "A1 the payment token belongs to the DAO"
TOKEN0=$(view "$MAIN" get_payment_token_contract | tr -d '"\n ')
echo "  token now: $TOKEN0"
PROBE_TOKEN="probe-token-$RUN.testnet"
expect_refused "Only governance" "$OWNER" "$MAIN" set_payment_token_contract "{\"token_contract\":\"$PROBE_TOKEN\"}"
set_token() { # <token json or null>
    pass_by_vote "{\"Call\":{\"target\":\"$MAIN\",\"method\":\"set_payment_token_contract\",\"args\":\"$(b64 "{\"token_contract\":$1}")\",\"deposit\":\"0\",\"gas_tgas\":30}}"
}
if set_token "\"$PROBE_TOKEN\"" && [ "$(view "$MAIN" get_payment_token_contract | tr -d '"\n ')" = "$PROBE_TOKEN" ]; then
    ok "a DAO Call set the token to $PROBE_TOKEN"
else
    bad "the DAO did not set the token: $(view "$MAIN" get_payment_token_contract | tr -d '\n')"
fi
if set_token "\"$TOKEN0\"" && [ "$(view "$MAIN" get_payment_token_contract | tr -d '"\n ')" = "$TOKEN0" ]; then
    ok "a second DAO Call set it back to $TOKEN0"
else
    bad "THE TOKEN IS NOT BACK: $(view "$MAIN" get_payment_token_contract | tr -d '\n') — propose a Call set_payment_token_contract {\"token_contract\":\"$TOKEN0\"} now"
fi

# A request of this suite's own, held pending by a run that sleeps: the connector-probe's
# `sleep` from the active version's WASM URL, paid in NEAR.
slow_request() { # prints the request id once it is pending
    local src args since id i ids st
    src=$(view "$MAIN" get_version "{\"project_id\":\"connectors.outlayer.testnet/connector-probe\",\"version_key\":$(view "$MAIN" get_project '{"project_id":"connectors.outlayer.testnet/connector-probe"}' | python3 -I -c 'import sys,json; print(json.dumps(json.load(sys.stdin)["active_version"]))')}" \
        | python3 -I -c 'import sys,json; print(json.dumps({"WasmUrl": json.load(sys.stdin)["source"]["WasmUrl"]}))')
    args=$(python3 -I -c 'import json,sys; print(json.dumps({"source": json.loads(sys.argv[1]), "input_data": json.dumps({"operation":"sleep","seconds":60}), "resource_limits": {"max_instructions":1000000000,"max_memory_mb":128,"max_execution_seconds":80}}))' "$src")
    since=$(python3 -I -c 'import time; print(int(time.time()*1e9))')
    ( near contract call-function as-transaction "$MAIN" request_execution json-args "$args" prepaid-gas '300 Tgas' \
        attached-deposit '0.1 NEAR' sign-as "$CALLER" network-config "$NETWORK" sign-with-legacy-keychain send >/dev/null 2>&1 & )
    for i in $(seq 1 30); do
        sleep 2
        ids=$(view "$MAIN" get_pending_request_ids '{"limit":10}' | python3 -I -c 'import sys,json; print(" ".join(map(str, json.load(sys.stdin)["ids"])))')
        for id in $ids; do
            st=$(view "$MAIN" get_request_status "{\"request_id\":$id}")
            if printf '%s' "$st" | python3 -I -c 'import sys,json
s=json.load(sys.stdin); sys.exit(0 if s and s["sender_id"]==sys.argv[1] and s["timestamp"]>=int(sys.argv[2]) and not s["output_submitted"] else 1)' "$CALLER" "$since"; then
                echo "$id"; return 0
            fi
        done
    done
    return 1
}
pending() { [ "$(view "$MAIN" get_request_status "{\"request_id\":$1}" | tr -d '\n ')" != "null" ]; }

step "A2 clear_all_pending_requests is the owner's"
expect_refused "Only owner" "$STRANGER" "$MAIN" clear_all_pending_requests '{"from_id":null,"limit":1}'
if R=$(slow_request); then
    echo "  pending request $R (by $CALLER)"
    # From this id, one request: this suite's own, still pending (checked again just before).
    if pending "$R" && call "$OWNER" "$MAIN" clear_all_pending_requests "{\"from_id\":$R,\"limit\":1}" "100 Tgas"; then
        [ "$(returned)" = "1" ] && ok "the owner cleared one request" || bad "cleared $(returned), not 1"
        logs_have "Cleared request $R and refunded" && logs_have "to $CALLER" \
            && ok "request $R refunded to $CALLER" || bad "no refund log for $R: $(printf '%s' "$LAST_OUT" | grep -a 'Cleared' | head -1)"
        pending "$R" && bad "request $R is still pending" || ok "request $R is no longer pending"
    else
        bad "the clear failed or $R finished first: $(printf '%s' "$LAST_OUT" | grep -iE 'panicked|error' | head -1 | cut -c1-200)"
    fi
else
    bad "no pending request of $CALLER appeared"
fi

step "A3 emergency_cancel_execution is the owner's"
if R=$(slow_request); then
    echo "  pending request $R (by $CALLER)"
    expect_refused "Only owner" "$STRANGER" "$MAIN" emergency_cancel_execution "{\"request_id\":$R}"
    if call "$OWNER" "$MAIN" emergency_cancel_execution "{\"request_id\":$R}" "100 Tgas"; then
        logs_have "Emergency cancelled execution $R and refunded" && ok "request $R cancelled and refunded" \
            || bad "no cancel log for $R"
        pending "$R" && bad "request $R is still pending" || ok "request $R is no longer pending"
    else
        bad "cancel: $(printf '%s' "$LAST_OUT" | grep -iE 'panicked|error' | head -1 | cut -c1-200)"
    fi
else
    bad "no pending request of $CALLER appeared"
fi

step "A4 a guest OS image: by vote, and the owner's fast path"
img() { local h; h=$(python3 -I -c "import hashlib,sys; print(hashlib.sha384(sys.argv[1].encode()).hexdigest())" "$1"); printf '{"mrtd":"%s","rtmr0":"%s","rtmr1":"%s","rtmr2":"%s"}' "$h" "$h" "$h" "$h"; }
listed() { view "$DAO" get_approved_os_images | python3 -I -c 'import sys,json; im=json.loads(sys.argv[1]); sys.exit(0 if im in json.load(sys.stdin) else 1)' "$1"; }
I1=$(img "probe-os-a-$RUN"); I2=$(img "probe-os-b-$RUN")
# The revocation proves something only of an image that is on the list.
if pass_by_vote "{\"ApproveOsImage\":{\"image\":$I1}}" && listed "$I1"; then
    ok "an OS image approved by vote"
    p=$(propose "$M1" "{\"RevokeOsImage\":{\"image\":$I1}}")
    expect_refused "cannot be cancelled by the owner" "$OWNER" "$DAO" cancel "{\"proposal_id\":$p}"
    vote "$M2" "$p" true && exec_ "$p"
    listed "$I1" && bad "image 1 still approved after RevokeOsImage ($(gov_status "$p"))" \
        || ok "RevokeOsImage by vote took it off (proposal $p)"
else
    bad "approve image 1 — its revocation not tried"
fi
pass_by_vote "{\"ApproveOsImage\":{\"image\":$I2}}" && listed "$I2" && ok "a second image approved" || bad "approve image 2"
expect_refused "Only owner" "$STRANGER" "$DAO" remove_approved_os_image "{\"image\":$I2}"
call "$OWNER" "$DAO" remove_approved_os_image "{\"image\":$I2}" && ! listed "$I2" \
    && ok "the owner removed it without a vote" || bad "owner remove image 2"

step "A5 measurements proposals are gone"
M_A=$(python3 -I -c 'print("a"*96)')
MEAS="{\"mrtd\":\"$M_A\",\"rtmr0\":\"$M_A\",\"rtmr1\":\"$M_A\",\"rtmr2\":\"$M_A\",\"rtmr3\":\"$M_A\"}"
for kind in ApproveMeasurements RevokeMeasurements; do
    expect_refused "propose ApproveOsImage and ApproveCompose" "$M1" "$DAO" propose "{\"action\":{\"$kind\":{\"measurements\":$MEAS}}}" "100 Tgas" "0.1 NEAR"
done

step "A6 vault versions"
VH=$(python3 -I -c '
import hashlib,sys
A="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
n=int.from_bytes(hashlib.sha256(sys.argv[1].encode()).digest(),"big"); o=""
while n: n,r=divmod(n,58); o=A[r]+o
print(o)' "probe-vault-$RUN")
vlisted() { view "$DAO" list_approved_vault_versions | python3 -I -c 'import sys,json; h=sys.argv[1]
for k,v in json.load(sys.stdin):
    if k==h: print("deprecated" if v.get("deprecated") else "listed"); sys.exit(0)
print("absent")' "$1"; }
VA="{\"hash\":\"$VH\",\"label\":\"probe $RUN\",\"audit_url\":null}"
expect_refused "only DAO members" "$STRANGER" "$DAO" approve_vault_version "$VA"
call "$M1" "$DAO" approve_vault_version "$VA" && [ "$(vlisted "$VH")" = absent ] \
    && ok "one vote does not approve a vault version" || bad "after one vote: $(vlisted "$VH")"
call "$M2" "$DAO" approve_vault_version "$VA" && [ "$(vlisted "$VH")" = listed ] \
    && ok "two votes approve it" || bad "after two votes: $(vlisted "$VH")"
call "$M1" "$DAO" deprecate_vault_version "{\"hash\":\"$VH\"}" && [ "$(vlisted "$VH")" = deprecated ] \
    && ok "one member deprecates it" || bad "deprecate: $(vlisted "$VH")"
call "$M1" "$DAO" revoke_vault_version "{\"hash\":\"$VH\"}" && [ "$(vlisted "$VH")" != absent ] \
    && ok "one vote does not revoke it" || bad "after one revoke vote: $(vlisted "$VH")"
call "$M2" "$DAO" revoke_vault_version "{\"hash\":\"$VH\"}" && [ "$(vlisted "$VH")" = absent ] \
    && ok "two votes revoke it" || bad "after two revoke votes: $(vlisted "$VH")"

step "A7 a vault ban"
VAULT="probe-vault-$RUN.testnet"
banned() { view "$DAO" is_vault_banned "{\"vault_id\":\"$VAULT\"}" | tr -d '\n '; }
expect_refused "only an approved keystore" "$STRANGER" "$DAO" ban_vault "{\"vault_id\":\"$VAULT\",\"reason\":\"probe\"}"
call "$M1" "$DAO" ban_vault "{\"vault_id\":\"$VAULT\",\"reason\":\"probe $RUN\"}" && [ "$(banned)" = true ] \
    && ok "a member banned it" || bad "ban: $(banned)"
expect_refused "only DAO members" "$STRANGER" "$DAO" unban_vault "{\"vault_id\":\"$VAULT\"}"
call "$M2" "$DAO" unban_vault "{\"vault_id\":\"$VAULT\"}" && [ "$(banned)" = false ] \
    && ok "a member unbanned it" || bad "unban: $(banned)"

summary
