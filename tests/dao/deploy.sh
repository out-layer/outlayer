#!/usr/bin/env bash
# Deploy the three contracts on the test accounts under TEST_ROOT and hand governance of the
# main and register contracts to the DAO. Testnet only; refuses an account that already has
# code. Build first:
#   (cd contract && cargo near build non-reproducible-wasm --locked)
#   (cd keystore-dao-contract && ./build.sh)    # or cargo near build ... --no-abi --no-wasmopt
#   (cd register-contract && ./build.sh)
# GOV_DELAY_SEC (default 0) is the DAO's delay between quorum and execute.

source "$(dirname "$0")/lib.sh"

GOV_DELAY_SEC="${GOV_DELAY_SEC:-0}"
EMPTY_HASH="11111111111111111111111111111111"

for f in "$WASM_MAIN" "$WASM_DAO" "$WASM_WORKER"; do
    [ -f "$f" ] || { echo "missing $f — build it first"; exit 1; }
done
for acc in "$MAIN" "$DAO" "$WORKER"; do
    h=$(code_hash "$acc")
    [ "$h" = "$EMPTY_HASH" ] || { echo "$acc already has code ($h); this script deploys once"; exit 1; }
done

deploy() {
    local acc="$1" wasm="$2" args="$3"
    near contract deploy "$acc" use-file "$wasm" with-init-call new json-args "$args" \
        prepaid-gas '100 Tgas' attached-deposit '0 NEAR' \
        network-config "$NETWORK" sign-with-legacy-keychain send >/dev/null 2>&1 \
        || { echo "deploy $acc failed"; exit 1; }
    [ "$(code_hash "$acc")" = "$(wasm_hash "$wasm")" ] && ok "$acc deployed ($(wasm_hash "$wasm"))" || bad "$acc code hash"
}

step "deploy"
deploy "$DAO" "$WASM_DAO" "{\"owner_id\":\"$OWNER\",\"init_account_id\":\"$OWNER\",\"dao_members\":[\"$M1\",\"$M2\",\"$M3\"],\"mpc_contract_id\":\"$MPC_CONTRACT\",\"gov_delay_sec\":$GOV_DELAY_SEC}"
deploy "$MAIN" "$WASM_MAIN" "{\"owner_id\":\"$OWNER\",\"operator_id\":\"$WORKER\"}"
deploy "$WORKER" "$WASM_WORKER" "{\"owner_id\":\"$OWNER\",\"init_worker_account\":\"$OWNER\",\"outlayer_contract_id\":\"$MAIN\",\"governance_id\":\"$DAO\"}"

step "governance handed to the DAO"
# A fresh main contract is governed by its owner until the owner hands it over.
call "$OWNER" "$MAIN" set_governance "{\"governance_id\":\"$DAO\"}" && ok "main: set_governance by the owner" || bad "main: set_governance"
[ "$(view "$MAIN" get_governance | tr -d '"')" = "$DAO" ] && ok "main governed by $DAO" || bad "main governance"
[ "$(view "$WORKER" get_governance | tr -d '"')" = "$DAO" ] && ok "register governed by $DAO" || bad "register governance"
cfg=$(view "$DAO" get_config)
python3 -I -c 'import json,sys; c=json.loads(sys.argv[1]); assert c["dao_members_count"]==3 and c["approval_threshold"]==2, c; print("ok")' "$cfg" >/dev/null \
    && ok "DAO: 3 members, threshold 2, delay $(view "$DAO" get_gov_delay_sec)s" || bad "DAO config: $cfg"

summary
