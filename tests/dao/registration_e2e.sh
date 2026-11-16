#!/usr/bin/env bash
# Keystore registration, live on testnet, on the separate DAO of TEST_ROOT: a real keystore's TDX
# quote and boot event log through the real contract, and what a hostile submitter can send
# instead — with the gas each transaction burns.
#
# The data is public, from testnet (keystore-dao-contract/tests/fixtures/):
#   keystore_dal.json         a real keystore's key, quote and RTMR3 events (registration #175
#                             on dao.outlayer.testnet)
#   keystore_ams_events.json  the RTMR3 events of another CVM of the same release
#   keystore_ams_quote.json   another real keystore's quote
#   collaterals.json          Intel's collateral as dao.outlayer.testnet cached it
#
#   R0  the DAO of TEST_ROOT runs the code under test (upgraded through its own DAO when not)
#   R1  collateral cached; the dal keystore's guest OS and release approved by governance
#   R2  refused: another CVM's log, a forged fact, a key the quote does not carry, a changed
#       quote byte, a stranger submitting, an unapproved release, no event log
#   R3  the real registration is taken and states the fixture's compose, instance and app;
#       its gas leaves room under the 300 TGas the keystore attaches
#   R4  sent again: the same id, and no quote verification spent
#   R5  a vote naming another key is refused; two votes for its key install it on the DAO account
#   R6  cleanup: the key is revoked by vote, the build taken off the lists by the owner
#
# The key installed in R5 is a testnet keystore's, held in its CVM: it could call request_key on
# this test DAO until R6 revokes it. MPC derives a different master for this account.
#
# Run:
#   TEST_ROOT=tod3.outlayer-alice.testnet bash tests/dao/registration_e2e.sh
# WASM_DAO (default: keystore-dao-contract/target/near/) is what R0 deploys when needed.

source "$(dirname "$0")/lib.sh"
FX="$REPO_ROOT/keystore-dao-contract/tests/fixtures"
INIT=$(view "$DAO" get_config | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["init_account_id"])')
DAO_OWNER=$(view "$DAO" get_owner | tr -d '"\n ')
GAS_LIMIT_TGAS=300

fx() { python3 -I -c 'import json,sys; v=json.load(open(sys.argv[1]))
for k in sys.argv[2].split("."): v=v[k]
print(v if isinstance(v,str) else json.dumps(v, separators=(",",":")))' "$FX/$1" "$2"; }

KEY=$(fx keystore_dal.json public_key)
QUOTE=$(fx keystore_dal.json tdx_quote_hex)
EVENTS=$(fx keystore_dal.json rtmr3_events)
COMPOSE=$(fx keystore_dal.json compose_hash)
INSTANCE=$(fx keystore_dal.json instance_id)
APP=$(fx keystore_dal.json app_id)
OS_IMAGE=$(fx keystore_dal.json measurements | python3 -I -c 'import json,sys
m=json.load(sys.stdin); print(json.dumps({k: m[k] for k in ("mrtd","rtmr0","rtmr1","rtmr2")}, separators=(",",":")))')

# Gas the last transaction burnt, all its receipts included, in TGas (from the keyed RPC).
last_gas_tgas() {
    local tx
    tx=$(printf '%s' "$LAST_OUT" | grep -oE 'Transaction ID: [1-9A-HJ-NP-Za-km-z]+' | tail -1 | awk '{print $3}')
    [ -n "$tx" ] || { echo "?"; return; }
    curl -s --max-time 30 "$RPC_URL" -H 'content-type: application/json' \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"EXPERIMENTAL_tx_status\",\"params\":{\"tx_hash\":\"$tx\",\"sender_account_id\":\"$SIGNER\",\"wait_until\":\"FINAL\"}}" \
        | python3 -I -c 'import json,sys
r=json.load(sys.stdin)["result"]
g=r["transaction_outcome"]["outcome"]["gas_burnt"]+sum(o["outcome"]["gas_burnt"] for o in r["receipts_outcome"])
print(f"{g/1e12:.1f}")' 2>/dev/null || echo "?"
}

# The balance of <account>, in yoctoNEAR.
balance_of() {
    rpc_query "{\"request_type\":\"view_account\",\"finality\":\"final\",\"account_id\":\"$1\"}" \
        | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["result"]["amount"])'
}

# What <account> paid since <balance-before>, as TGas at the current gas price. For a failed
# transaction, whose id near-cli does not print: the unused gas comes back, so this is the gas
# burnt. Waits for the refund receipt.
paid_tgas() {
    local before="$1" after price
    sleep 4
    after=$(balance_of "$SIGNER")
    price=$(curl -s --max-time 30 "$RPC_URL" -H 'content-type: application/json' \
        -d '{"jsonrpc":"2.0","id":1,"method":"gas_price","params":[null]}' | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["result"]["gas_price"])')
    python3 -I -c 'import sys; b,a,p=map(int,sys.argv[1:4]); print(f"≈{(b-a)/p/1e12:.1f}")' "$before" "$after" "$price" 2>/dev/null || echo "?"
}

# submit <signer> <key> <quote-hex> <events-json> — submit_keystore_registration, 300 TGas.
submit() {
    SIGNER="$1"
    local args
    args=$(python3 -I -c 'import json,sys
ev=json.loads(sys.argv[3])
print(json.dumps({"public_key":sys.argv[1],"tdx_quote_hex":sys.argv[2],"app_id":None,"event_log":ev}, separators=(",",":")))' "$2" "$3" "$4")
    call "$SIGNER" "$DAO" submit_keystore_registration "$args" "$GAS_LIMIT_TGAS Tgas"
}

# refused <reason> <submit args...>
refused() {
    local want="$1" before
    shift
    SIGNER="$1"; before=$(balance_of "$SIGNER")
    if submit "$@"; then
        bad "expected a refusal ($want), the registration was taken: #$(returned)"
    elif printf '%s' "$LAST_OUT" | grep -qF "$want"; then
        ok "refused: $want  (paid $(paid_tgas "$before") TGas)"
    else
        bad "refused, but not with \"$want\": $(printf '%s' "$LAST_OUT" | grep -iE 'panicked|error' | head -1 | cut -c1-200)"
    fi
}

# gov <action-json> — propose as M1, vote as M2, execute; 0 when Executed.
gov() {
    local id
    call "$M1" "$DAO" propose "{\"action\":$1}" "100 Tgas" "0.1 NEAR" || { bad "propose $1: $(printf '%s' "$LAST_OUT" | grep -iE 'panicked|error' | head -1 | cut -c1-160)"; return 1; }
    id=$(returned)
    call "$M2" "$DAO" vote "{\"proposal_id\":$id,\"approve\":true}" || true
    call "$M1" "$DAO" execute "{\"proposal_id\":$id}" "300 Tgas" || true
    [ "$(gov_status "$id")" = Executed ]
}

flip_byte() {  # flip_byte <hex> <index>
    python3 -I -c 'import sys
b=bytearray(bytes.fromhex(sys.argv[1])); b[int(sys.argv[2])]^=1; print(b.hex())' "$1" "$2"
}

step "R0 the DAO of $TEST_ROOT runs the code under test"
if [ "$(code_hash "$DAO")" = "$(wasm_hash "$WASM_DAO")" ]; then
    ok "$DAO runs $(wasm_hash "$WASM_DAO")"
else
    echo "  upgrading $DAO to $WASM_DAO through its DAO"
    if scripts_out=$("$REPO_ROOT/scripts/dao_upgrade.sh" --network testnet --root "$TEST_ROOT" --target dao \
            --wasm "$WASM_DAO" --member "$M1" 2>&1) && [ "$(code_hash "$DAO")" = "$(wasm_hash "$WASM_DAO")" ]; then
        ok "upgraded"
    else
        printf '%s\n' "$scripts_out" | tail -5
        bad "upgrade of $DAO"; summary; exit 1
    fi
fi

step "R1 collateral and the build"
python3 -I -c 'import json,sys
for i,c in enumerate(json.load(open(sys.argv[1]))["collaterals"]): open(f"{sys.argv[2]}.{i}","w").write(json.dumps({"collateral":c,"index":i}))' \
    "$FX/collaterals.json" "${TMPDIR:-/tmp}/reg_e2e_collateral"
for i in 0 1; do
    if call "$DAO_OWNER" "$DAO" update_collateral "$(cat "${TMPDIR:-/tmp}/reg_e2e_collateral.$i")" "100 Tgas"; then
        ok "collateral slot $i cached (gas $(SIGNER=$DAO_OWNER last_gas_tgas) TGas)"
    else
        bad "update_collateral $i: $(printf '%s' "$LAST_OUT" | grep -iE 'panicked|error' | head -1 | cut -c1-160)"
    fi
done
# The release is approved only after R2 has checked that an unapproved one is refused.
if view "$DAO" get_approved_os_images | python3 -I -c 'import json,sys; sys.exit(0 if json.loads(sys.argv[1]) in json.load(sys.stdin) else 1)' "$OS_IMAGE"; then
    ok "guest OS already approved"
elif gov "{\"ApproveOsImage\":{\"image\":$OS_IMAGE}}"; then
    ok "guest OS approved by vote"
else
    bad "ApproveOsImage"
fi
call "$DAO_OWNER" "$DAO" remove_approved_compose "{\"compose_hash\":\"$COMPOSE\"}" >/dev/null || true

step "R2 what a hostile submitter sends"
refused "Compose not approved" "$INIT" "$KEY" "$QUOTE" "$EVENTS"
gov "{\"ApproveCompose\":{\"compose_hash\":\"$COMPOSE\"}}" && ok "release $COMPOSE approved by vote" || bad "ApproveCompose"
refused "Only $INIT can submit" "$STRANGER" "$KEY" "$QUOTE" "$EVENTS"
refused "does not replay to the quote's RTMR3" "$INIT" "$KEY" "$QUOTE" "$(fx keystore_ams_events.json rtmr3_events)"
refused "does not replay to the quote's RTMR3" "$INIT" "$(fx keystore_ams_quote.json public_key)" "$(fx keystore_ams_quote.json tdx_quote_hex)" "$EVENTS"
FORGED=$(printf '%s' "$EVENTS" | python3 -I -c 'import json,sys
ev=json.load(sys.stdin)
for e in ev:
    if e["event"]=="compose-hash": e["event_payload"]="ee"*32
print(json.dumps(ev, separators=(",",":")))')
refused "digest does not match" "$INIT" "$KEY" "$QUOTE" "$FORGED"
refused "Public key mismatch" "$INIT" "$(fx keystore_ams_quote.json public_key)" "$QUOTE" "$EVENTS"
refused "TDX quote verification failed" "$INIT" "$KEY" "$(flip_byte "$QUOTE" 568)" "$EVENTS"
refused "Event log refused" "$INIT" "$KEY" "$QUOTE" "[]"

step "R3 the real registration"
if submit "$INIT" "$KEY" "$QUOTE" "$EVENTS"; then
    ID=$(returned)
    GAS=$(last_gas_tgas)
    ok "registered: #$ID, gas $GAS TGas of the $GAS_LIMIT_TGAS the keystore attaches"
    python3 -I -c 'import sys; g=float(sys.argv[1]); sys.exit(0 if g < 0.8*float(sys.argv[2]) else 1)' "$GAS" "$GAS_LIMIT_TGAS" 2>/dev/null \
        && ok "room left: more than 20%" || bad "gas $GAS TGas leaves less than 20% of $GAS_LIMIT_TGAS"
    FACTS=$(view "$DAO" get_registration_facts "{\"proposal_id\":$ID}" | python3 -I -c 'import json,sys
f=json.load(sys.stdin); print(f["compose_hash"], f["instance_id"], f["app_id"])')
    [ "$FACTS" = "$COMPOSE $INSTANCE $APP" ] && ok "it states the fixture's compose, instance and app" || bad "facts: $FACTS"
else
    bad "the real registration was refused: $(printf '%s' "$LAST_OUT" | grep -iE 'panicked|error' | head -1 | cut -c1-200)"
    summary; exit 1
fi

step "R4 sent again"
if submit "$INIT" "$KEY" "$QUOTE" "$EVENTS" && [ "$(returned)" = "$ID" ]; then
    ok "the same id #$ID, gas $(last_gas_tgas) TGas (no quote verified)"
else
    bad "a second submission: $(returned) $(printf '%s' "$LAST_OUT" | grep -iE 'panicked|error' | head -1 | cut -c1-160)"
fi

step "R5 the votes"
OTHER_KEY=$(fx keystore_ams_quote.json public_key)
expect_refused "is for another key" "$M1" "$DAO" vote "{\"proposal_id\":$ID,\"approve\":true,\"public_key\":\"$OTHER_KEY\"}"
expect_refused "names its key" "$M1" "$DAO" vote "{\"proposal_id\":$ID,\"approve\":true}"
why() { printf '%s' "$LAST_OUT" | grep -iE 'panicked|error' | head -1 | cut -c1-200; }
call "$M1" "$DAO" vote "{\"proposal_id\":$ID,\"approve\":true,\"public_key\":\"$KEY\"}" && ok "vote 1 for its key" || bad "vote 1: $(why)"
call "$M2" "$DAO" vote "{\"proposal_id\":$ID,\"approve\":true,\"public_key\":\"$KEY\"}" && ok "vote 2 for its key (gas $(SIGNER=$M2 last_gas_tgas) TGas)" || bad "vote 2: $(why)"
[ "$(view "$DAO" is_keystore_approved "{\"public_key\":\"$KEY\"}")" = true ] && ok "the key is approved" || bad "the key is not approved"
sleep 3
if rpc_query "{\"request_type\":\"view_access_key\",\"finality\":\"final\",\"account_id\":\"$DAO\",\"public_key\":\"$KEY\"}" \
    | python3 -I -c 'import json,sys
p=json.load(sys.stdin)["result"]["permission"]["FunctionCall"]
sys.exit(0 if sorted(p["method_names"])==["ban_vault","mark_vault_verified","request_key"] and p["receiver_id"]==sys.argv[1] else 1)' "$DAO"; then
    ok "the access key is on $DAO: receiver $DAO, request_key / mark_vault_verified / ban_vault"
else
    bad "no such access key on $DAO"
fi

step "R6 cleanup"
call "$M1" "$DAO" propose_revoke_keystore_keys "{\"public_keys\":[\"$KEY\"]}" "100 Tgas" && RID=$(returned) || RID=""
[ -n "$RID" ] && call "$M2" "$DAO" vote "{\"proposal_id\":$RID,\"approve\":true}" || true
[ "$(view "$DAO" is_keystore_approved "{\"public_key\":\"$KEY\"}")" = false ] && ok "the key is revoked" || bad "the key is still approved"
call "$DAO_OWNER" "$DAO" remove_approved_compose "{\"compose_hash\":\"$COMPOSE\"}" && ok "release taken off the list by the owner" || bad "remove_approved_compose"
call "$DAO_OWNER" "$DAO" remove_approved_os_image "{\"image\":$OS_IMAGE}" && ok "guest OS taken off the list by the owner" || bad "remove_approved_os_image"

summary
