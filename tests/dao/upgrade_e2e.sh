#!/usr/bin/env bash
# Every contract upgrades through the DAO, and the code it switches to can upgrade again.
# For each of main, register and the DAO itself:
#   1. upgrade to a variant of the built wasm (same code, an extra custom section: another
#      hash) — the account reports the variant's hash;
#   2. upgrade back to the built wasm — the variant's own upgrade path works;
#   3. an upgrade whose migrate fails — the built wasm's `migrate` is this release's one-time
#      migration and panics on the state it already migrated — the batch reverts and the code
#      stays; the proposal is Executed (there is no callback) and its blob is gone;
#   4. an upgrade WITH migrate that succeeds: to the `migrate-probe` build, whose `migrate()`
#      takes no arguments and reads the current layout, as every later release's does; then
#      back to the built wasm.
# Build the probes once, before the built wasms (both write target/near/):
#   (cd contract && cargo near build non-reproducible-wasm --features migrate-probe \
#     && mkdir -p target/near/migrate-probe && cp target/near/outlayer_contract.wasm target/near/migrate-probe/)
#   and the same in register-contract/ and keystore-dao-contract/ (with their build.sh flags),
#   then build the three contracts as usual.
# Then: the DAO upgrades itself while other proposals are open, and a proposal opened between
# execute and the deploy (one transaction: [execute, propose]) stays readable by the new code —
# proposals are stored versioned.
# Testnet, the accounts from deploy.sh. Needs the DAO delay at 0.

source "$(dirname "$0")/lib.sh"
# A failed check is counted and reported; the suite goes on.
set +e

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A valid wasm with the same code and another hash: an appended custom section.
variant() {
    python3 -I -c '
import sys
def leb(n):
    o=b""
    while True:
        b=n&0x7f; n>>=7
        if n: o+=bytes([b|0x80])
        else: return o+bytes([b])
name=b"outlayer-test-variant"; payload=sys.argv[3].encode()
content=leb(len(name))+name+payload
open(sys.argv[2],"wb").write(open(sys.argv[1],"rb").read()+b"\x00"+leb(len(content))+content)' "$1" "$2" "$3"
}

[ "$(view "$DAO" get_gov_delay_sec)" = "0" ] || { echo "the DAO delay must be 0 for this suite"; exit 1; }

# upgrade <target> <wasm> <migrate:true|false> — prints the proposal id; 0 when executed.
upgrade() {
    local target="$1" wasm="$2" migrate="$3" h id
    h=$(store_blob "$wasm") || return 2
    id=$(propose "$M1" "{\"Upgrade\":{\"target\":\"$target\",\"code_hash\":\"$h\",\"migrate\":$migrate}}") || return 2
    call "$M2" "$DAO" vote "{\"proposal_id\":$id,\"approve\":true}" || return 2
    echo "$id"
    call "$M3" "$DAO" execute "{\"proposal_id\":$id}" "300 Tgas" || return 1
}

for target in "$MAIN" "$WORKER" "$DAO"; do
    case "$target" in
        "$MAIN") wasm="$WASM_MAIN" ;;
        "$WORKER") wasm="$WASM_WORKER" ;;
        "$DAO") wasm="$WASM_DAO" ;;
    esac
    step "$target"
    original=$(wasm_hash "$wasm")
    v="$WORK/variant-$(date +%s).wasm"
    variant "$wasm" "$v" "$(date +%s%N)"
    vhash=$(wasm_hash "$v")

    id=$(upgrade "$target" "$v" false) || true
    if [ "$(gov_status "$id")" = "Executed" ] && [ "$(code_hash "$target")" = "$vhash" ]; then
        ok "upgraded to the variant $vhash (proposal $id)"
    else
        bad "upgrade to the variant: status $(gov_status "$id"), code $(code_hash "$target")"
    fi
    [ "$(view "$DAO" get_blob "{\"hash\":\"$vhash\"}")" = "null" ] && ok "the executed blob is gone" || bad "the blob is still stored"

    id=$(upgrade "$target" "$wasm" false) || true
    if [ "$(gov_status "$id")" = "Executed" ] && [ "$(code_hash "$target")" = "$original" ]; then
        ok "the variant upgraded back to $original (proposal $id)"
    else
        bad "upgrade back: status $(gov_status "$id"), code $(code_hash "$target")"
    fi
    view "$target" gov_health >/dev/null && ok "state reads after two upgrades" || bad "gov_health"

    # The release's one-time migrate panics on the state it already migrated: the batch reverts.
    variant "$wasm" "$v" "migrate-$(date +%s%N)"
    vhash=$(wasm_hash "$v")
    id=$(upgrade "$target" "$v" true) || true
    sleep 3
    st=$(gov_status "$id")
    if [ "$st" = "Executed" ] && [ "$(code_hash "$target")" = "$original" ]; then
        ok "a failing migrate reverted the code switch (proposal $id executed, code unchanged)"
    else
        bad "failing migrate: status $st, code $(code_hash "$target") (expected Executed, $original)"
    fi
    [ "$(view "$DAO" get_blob "{\"hash\":\"$vhash\"}")" = "null" ] && ok "its blob is gone" || bad "the blob is still stored"

    case "$target" in
        "$MAIN") probe="$WASM_MAIN_PROBE" ;;
        "$WORKER") probe="$WASM_WORKER_PROBE" ;;
        "$DAO") probe="$WASM_DAO_PROBE" ;;
    esac
    if [ ! -f "$probe" ]; then
        bad "no migrate-probe build at $probe (see the header): the migrating upgrade is not tested"
        continue
    fi
    phash=$(wasm_hash "$probe")
    id=$(upgrade "$target" "$probe" true) || true
    if [ "$(gov_status "$id")" = "Executed" ] && [ "$(code_hash "$target")" = "$phash" ]; then
        ok "an upgrade with migrate switched to the probe $phash (proposal $id)"
    else
        bad "upgrade with migrate: status $(gov_status "$id"), code $(code_hash "$target") (expected $phash)"
    fi
    view "$target" gov_health >/dev/null && ok "state reads after the migrating upgrade" || bad "gov_health after migrate"
    id=$(upgrade "$target" "$wasm" false) || true
    if [ "$(gov_status "$id")" = "Executed" ] && [ "$(code_hash "$target")" = "$original" ]; then
        ok "the probe upgraded back to $original (proposal $id)"
    else
        bad "upgrade back from the probe: status $(gov_status "$id"), code $(code_hash "$target")"
    fi
done

step "the DAO upgrades itself while another proposal is open"
v="$WORK/variant-open.wasm"
variant "$WASM_DAO" "$v" "open-$(date +%s%N)"
h=$(store_blob "$v")
up=$(propose "$M1" "{\"Upgrade\":{\"target\":\"$DAO\",\"code_hash\":\"$h\",\"migrate\":false}}")
other=$(propose "$M1" '{"SetDelay":{"seconds":0}}')
call "$M2" "$DAO" vote "{\"proposal_id\":$up,\"approve\":true}"
call "$M3" "$DAO" execute "{\"proposal_id\":$up}" "300 Tgas"
sleep 3
[ "$(code_hash "$DAO")" = "$(wasm_hash "$v")" ] && ok "upgraded with #$other still open" || bad "self-upgrade: $(gov_status "$up"), code $(code_hash "$DAO")"
[ "$(gov_status "$other")" = "Pending" ] && ok "#$other reads on the new code" || bad "#$other: $(gov_status "$other")"
call "$OWNER" "$DAO" cancel "{\"proposal_id\":$other}" && ok "and is cancelled as usual" || bad "cancel #$other"

step "a proposal opened between execute and the deploy"
h=$(store_blob "$WASM_DAO")
up=$(propose "$M1" "{\"Upgrade\":{\"target\":\"$DAO\",\"code_hash\":\"$h\",\"migrate\":false}}")
call "$M2" "$DAO" vote "{\"proposal_id\":$up,\"approve\":true}"
next_id=$(view "$DAO" get_config | python3 -I -c 'import sys,json; print(json.load(sys.stdin)["next_proposal_id"])')
LAST_OUT=$(near transaction construct-transaction "$M3" "$DAO" \
    add-action function-call execute json-args "{\"proposal_id\":$up}" prepaid-gas '200 Tgas' attached-deposit '0 NEAR' \
    add-action function-call propose json-args '{"action":{"SetDelay":{"seconds":0}}}' prepaid-gas '60 Tgas' attached-deposit '0.1 NEAR' \
    skip network-config "$NETWORK" sign-with-legacy-keychain send 2>&1) || true
sleep 4
[ "$(code_hash "$DAO")" = "$(wasm_hash "$WASM_DAO")" ] && ok "the DAO upgraded back to the built code" || bad "the DAO runs $(code_hash "$DAO")"
[ "$(gov_status "$next_id")" = "Pending" ] && ok "the proposal opened in flight (#$next_id) reads on the new code" || bad "in-flight proposal: $(gov_status "$next_id")"
call "$M1" "$DAO" vote "{\"proposal_id\":$next_id,\"approve\":true}" \
    && call "$M3" "$DAO" execute "{\"proposal_id\":$next_id}" "300 Tgas" \
    && [ "$(gov_status "$next_id")" = "Executed" ] \
    && ok "and closes normally" || bad "close the in-flight proposal"

summary
