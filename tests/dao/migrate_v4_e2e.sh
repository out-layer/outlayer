#!/usr/bin/env bash
# The mainnet DAO's own migration, rehearsed on testnet: the V4 wasm `dao.outlayer.near` runs
# today, on a fresh testnet account, migrated by the release wasm exactly as the mainnet deploy
# will do it — `deploy … with-init-call migrate {"gov_delay_sec": DELAY}`.
#   M1  the V4 contract answers its V4 config (members, owner, measurements count)
#   M2  after the deploy + migrate: the delay is DELAY; members, owner, threshold, init account,
#       MPC contract and the proposal counter are those of V4; the approved measurements are gone
#       (a build is OS + compose from V5 on); gov_health answers
#   M3  migrate cannot run again: not by a stranger (private), not by the account (no V4 state)
#   M4  governance works on the migrated state: a member proposes, the proposal waits DELAY
#
#   V4_WASM=<path to dao.outlayer.near's wasm> bash tests/dao/migrate_v4_e2e.sh --apply
#
# Get V4_WASM with `near contract download-wasm regular dao.outlayer.near save-to-file <path>
# network-config mainnet now` (a read). NEW_WASM defaults to the built release DAO wasm.
# FUNDER (default outlayer-elena.testnet) funds the account with 9 NEAR; it is deleted at the
# end, the balance back to FUNDER.
[ "${1:-}" = "--apply" ] || { sed -n 2,18p "$0"; exit 0; }
shift

source "$(dirname "$0")/lib.sh"
set +e

V4_WASM="${V4_WASM:?V4_WASM — the mainnet DAO wasm, see the header}"
NEW_WASM="${NEW_WASM:-$WASM_DAO}"
FUNDER="${FUNDER:-outlayer-elena.testnet}"
DELAY="${DELAY:-600}"
ACC="mig4-$(date +%s).$FUNDER"
[ -f "$V4_WASM" ] && [ -f "$NEW_WASM" ] || { echo "missing wasm: $V4_WASM / $NEW_WASM"; exit 1; }
echo "  V4 wasm $(wasm_hash "$V4_WASM"), new wasm $(wasm_hash "$NEW_WASM"), account $ACC, delay $DELAY"

cfg() { view "$ACC" get_config | python3 -I -c "import sys,json; print(json.load(sys.stdin).get('$1'))"; }

step "M1 a V4 DAO"
near account create-account fund-myself "$ACC" '9 NEAR' autogenerate-new-keypair save-to-legacy-keychain \
    sign-as "$FUNDER" network-config "$NETWORK" sign-with-legacy-keychain send >/dev/null 2>&1 \
    || { bad "could not create $ACC"; summary; exit 1; }
INIT=$(python3 -I -c 'import json,sys; print(json.dumps({"owner_id":sys.argv[1],"init_account_id":sys.argv[1],"dao_members":[sys.argv[1]],"mpc_contract_id":"v1.signer-prod.testnet"}))' "$FUNDER")
if near contract deploy "$ACC" use-file "$V4_WASM" with-init-call new json-args "$INIT" prepaid-gas '100 Tgas' \
    attached-deposit '0 NEAR' network-config "$NETWORK" sign-with-legacy-keychain send >/dev/null 2>&1; then
    [ "$(code_hash "$ACC")" = "$(wasm_hash "$V4_WASM")" ] && ok "the V4 wasm is deployed and initialised" || bad "V4 code hash"
else
    bad "the V4 deploy failed"
fi
# One approved measurement tuple, as the 20 on mainnet: V4 approved builds this way.
M_A=$(python3 -I -c 'print("a"*96)')
call "$FUNDER" "$ACC" add_approved_measurements "{\"measurements\":{\"mrtd\":\"$M_A\",\"rtmr0\":\"$M_A\",\"rtmr1\":\"$M_A\",\"rtmr2\":\"$M_A\",\"rtmr3\":\"$M_A\"}}" \
    && [ "$(cfg approved_measurements_count)" = 1 ] && ok "V4: one measurement tuple approved by the owner" \
    || bad "V4 add_approved_measurements: $(printf '%s' "$LAST_OUT" | grep -aE 'panicked|Error\(' | head -1 | cut -c1-200)"
V4_NEXT=$(cfg next_proposal_id); V4_THR=$(cfg approval_threshold)
[ "$(cfg dao_members_count)" = 1 ] && [ "$(cfg owner_id)" = "$FUNDER" ] \
    && ok "V4 config: 1 member, owner $FUNDER, next proposal $V4_NEXT" || bad "V4 config: $(view "$ACC" get_config | tr -d '\n ')"
view "$ACC" get_gov_delay_sec >/dev/null 2>&1 && bad "V4 already answers get_gov_delay_sec" || ok "V4 has no governance delay"

step "M2 deploy + migrate {\"gov_delay_sec\":$DELAY}"
OUT=$(near contract deploy "$ACC" use-file "$NEW_WASM" with-init-call migrate json-args "{\"gov_delay_sec\":$DELAY}" \
    prepaid-gas '300 Tgas' attached-deposit '0 NEAR' network-config "$NETWORK" sign-with-legacy-keychain send 2>&1)
# Everything after this reads the migrated contract; on the V4 one the checks would pass by
# reading V4 itself.
if [ "$(code_hash "$ACC")" = "$(wasm_hash "$NEW_WASM")" ]; then
    ok "the release wasm is deployed"
else
    bad "the deploy with migrate failed: $(printf '%s' "$OUT" | grep -aE 'Error\(|Execution' | head -1 | cut -c1-200)"
    near account delete-account "$ACC" beneficiary "$FUNDER" network-config "$NETWORK" sign-with-legacy-keychain send >/dev/null 2>&1
    summary; exit 1
fi
[ "$(view "$ACC" get_gov_delay_sec | tr -d '\n ')" = "$DELAY" ] && ok "the delay is $DELAY" \
    || bad "delay $(view "$ACC" get_gov_delay_sec | tr -d '\n ')"
[ "$(view "$ACC" get_dao_members | tr -d '\n "[] ')" = "$FUNDER" ] && ok "members kept" || bad "members: $(view "$ACC" get_dao_members | tr -d '\n ')"
[ "$(view "$ACC" get_owner | tr -d '\n "')" = "$FUNDER" ] && ok "owner kept" || bad "owner: $(view "$ACC" get_owner | tr -d '\n')"
[ "$(cfg next_proposal_id)" = "$V4_NEXT" ] && [ "$(cfg approval_threshold)" = "$V4_THR" ] \
    && [ "$(cfg init_account_id)" = "$FUNDER" ] && [ "$(cfg mpc_contract_id)" = "v1.signer-prod.testnet" ] \
    && ok "proposal counter, threshold, init account and MPC contract kept" || bad "config: $(view "$ACC" get_config | tr -d '\n ')"
# V5 approves a build as OS + compose, and has none yet: a keystore registers only after both
# are approved by vote.
[ "$(cfg approved_os_images_count)" = 0 ] && [ "$(cfg approved_composes_count)" = 0 ] \
    && ok "no build approved after the migration: OS images 0, composes 0" \
    || bad "approved after migrate: os $(cfg approved_os_images_count), composes $(cfg approved_composes_count)"
view "$ACC" gov_health >/dev/null && ok "gov_health answers" || bad "gov_health"

step "M3 migrate runs once"
expect_refused "Method migrate is private" "$STRANGER" "$ACC" migrate '{}' "300 Tgas"
if call "$ACC" "$ACC" migrate "{\"gov_delay_sec\":0}" "300 Tgas"; then
    bad "migrate ran a second time"
else
    ok "a second migrate by the account itself is refused: $(printf '%s' "$LAST_OUT" | grep -aoE 'Smart contract panicked: [^"]*|ExecutionError\([^)]*' | head -1 | cut -c1-160)"
fi
[ "$(view "$ACC" get_gov_delay_sec | tr -d '\n ')" = "$DELAY" ] && ok "the delay is still $DELAY" || bad "delay changed"

step "M4 governance on the migrated state"
if p=$(call "$FUNDER" "$ACC" propose '{"action":{"SetDelay":{"seconds":0}}}' "100 Tgas" "0.1 NEAR" && returned); then
    st=$(view "$ACC" get_gov_proposal "{\"proposal_id\":$p}")
    python3 -I -c 'import json,sys,time
p=json.loads(sys.argv[1]); d=int(sys.argv[2])
ok = p["status"]=="Approved" and p["executable_after"] and (p["executable_after"]-p["approved_at"])==d*10**9
sys.exit(0 if ok else 1)' "$st" "$DELAY" && ok "proposal $p approved by the single member, executable $DELAY s later" \
        || bad "proposal $p: $(printf '%s' "$st" | tr -d '\n ' | cut -c1-200)"
    expect_refused "Proposal executes from block timestamp" "$FUNDER" "$ACC" execute "{\"proposal_id\":$p}" "300 Tgas"
else
    bad "propose on the migrated DAO: $(printf '%s' "$LAST_OUT" | grep -iE 'panicked|error' | head -1 | cut -c1-200)"
fi

step "cleanup"
near account delete-account "$ACC" beneficiary "$FUNDER" network-config "$NETWORK" sign-with-legacy-keychain send >/dev/null 2>&1 \
    && echo "  $ACC deleted, balance back to $FUNDER" || echo "  !! delete $ACC by hand (beneficiary $FUNDER)"

summary
