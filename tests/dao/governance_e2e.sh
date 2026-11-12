#!/usr/bin/env bash
# Governance and the owner's limits on the three contracts deployed by deploy.sh:
#   - a proposal's electorate is fixed when it is created; members change only by vote;
#   - the owner cancels, but not its own replacement (on the DAO, main or register); members
#     reject it instead;
#   - the DAO approves worker builds and replaces the operator through Call proposals;
#     the owner cannot, and revokes builds without a vote;
#   - only a DAO-installed keystore key reaches request_key — not the account's own keys;
#   - the owner takes NEAR fees only up to what was collected.
# Testnet, delay 0.

source "$(dirname "$0")/lib.sh"
# A failed check is counted and reported; the suite goes on.
set +e

[ "$(view "$DAO" get_gov_delay_sec)" = "0" ] || { echo "the DAO delay must be 0 for this suite"; exit 1; }

vote() { call "$1" "$DAO" vote "{\"proposal_id\":$2,\"approve\":$3}"; }
exec_() { call "$M3" "$DAO" execute "{\"proposal_id\":$1}" "300 Tgas"; }
b64() { printf '%s' "$1" | base64 | tr -d '\n'; }
M_A=$(python3 -I -c 'print("a"*96)')
MEAS="{\"mrtd\":\"$M_A\",\"rtmr0\":\"$M_A\",\"rtmr1\":\"$M_A\",\"rtmr2\":\"$M_A\",\"rtmr3\":\"$M_A\"}"

step "electorate snapshot"
x=$(propose "$M1" '{"SetDelay":{"seconds":0}}')
add=$(propose "$M1" "{\"AddMember\":{\"member\":\"$STRANGER\"}}")
vote "$M2" "$add" true && exec_ "$add" && [ "$(gov_status "$add")" = "Executed" ] \
    && ok "$STRANGER added by vote" || bad "add member: $(gov_status "$add")"
expect_refused "Not in this proposal's electorate" "$STRANGER" "$DAO" vote "{\"proposal_id\":$x,\"approve\":true}"
vote "$M2" "$x" true && [ "$(gov_status "$x")" = "Approved" ] \
    && ok "2 votes pass a proposal made with 3 members, though 4 are members now" || bad "snapshot: $(gov_status "$x")"
exec_ "$x" || true
# Four members now: threshold 3.
rm_=$(propose "$M1" "{\"RemoveMember\":{\"member\":\"$STRANGER\"}}")
vote "$M2" "$rm_" true && vote "$M3" "$rm_" true && exec_ "$rm_" && [ "$(view "$DAO" get_config | python3 -I -c 'import sys,json; print(json.load(sys.stdin)["dao_members_count"])')" = "3" ] \
    && ok "$STRANGER removed by vote" || bad "remove member"
expect_refused "Only owner" "$M1" "$DAO" cancel "{\"proposal_id\":$x}"

step "the owner is a brake"
p=$(propose "$M1" '{"SetDelay":{"seconds":60}}')
call "$OWNER" "$DAO" cancel "{\"proposal_id\":$p}" && [ "$(gov_status "$p")" = "Cancelled" ] \
    && ok "the owner cancelled a pending proposal" || bad "cancel"
p=$(propose "$M1" "{\"SetOwner\":{\"owner\":\"$M3\"}}")
expect_refused "cannot be cancelled by the owner" "$OWNER" "$DAO" cancel "{\"proposal_id\":$p}"
vote "$M2" "$p" false; vote "$M3" "$p" false
[ "$(gov_status "$p")" = "Rejected" ] && ok "members rejected the owner's replacement" || bad "reject: $(gov_status "$p")"
for target in "$MAIN" "$WORKER"; do
    args=$(b64 "{\"new_owner_id\":\"$M3\"}")
    p=$(propose "$M1" "{\"Call\":{\"target\":\"$target\",\"method\":\"set_owner\",\"args\":\"$args\",\"deposit\":\"0\",\"gas_tgas\":30}}")
    expect_refused "cannot be cancelled by the owner" "$OWNER" "$DAO" cancel "{\"proposal_id\":$p}"
    vote "$M2" "$p" false; vote "$M3" "$p" false
    [ "$(gov_status "$p")" = "Rejected" ] && ok "$target: members rejected it instead" || bad "reject: $(gov_status "$p")"
done

step "worker builds and the operator: through the DAO"
expect_refused "Only governance" "$OWNER" "$WORKER" add_approved_measurements "{\"measurements\":$MEAS}"
args=$(b64 "{\"measurements\":$MEAS}")
p=$(propose "$M1" "{\"Call\":{\"target\":\"$WORKER\",\"method\":\"add_approved_measurements\",\"args\":\"$args\",\"deposit\":\"0\",\"gas_tgas\":30}}")
vote "$M2" "$p" true && exec_ "$p"
[ "$(view "$WORKER" is_measurements_approved "{\"measurements\":$MEAS}")" = "true" ] \
    && ok "the DAO approved a worker build (proposal $p)" || bad "worker build: $(gov_status "$p")"
call "$OWNER" "$WORKER" remove_approved_measurements "{\"measurements\":$MEAS}" \
    && [ "$(view "$WORKER" is_measurements_approved "{\"measurements\":$MEAS}")" = "false" ] \
    && ok "the owner revoked it without a vote" || bad "owner revoke"
expect_refused "Only governance" "$OWNER" "$MAIN" set_operator "{\"new_operator_id\":\"$OWNER\"}"
args=$(b64 "{\"new_operator_id\":\"$WORKER\"}")
p=$(propose "$M1" "{\"Call\":{\"target\":\"$MAIN\",\"method\":\"set_operator\",\"args\":\"$args\",\"deposit\":\"0\",\"gas_tgas\":30}}")
vote "$M2" "$p" true && exec_ "$p" && [ "$(gov_status "$p")" = "Executed" ] \
    && ok "the DAO set the operator (proposal $p)" || bad "set_operator: $(gov_status "$p")"
expect_refused "cannot target this contract" "$M1" "$DAO" propose "{\"action\":{\"Call\":{\"target\":\"$DAO\",\"method\":\"request_key\",\"args\":\"e30=\",\"deposit\":\"0\",\"gas_tgas\":30}}}"
expect_refused "Upgrade a contract with an Upgrade proposal" "$M1" "$DAO" propose "{\"action\":{\"Call\":{\"target\":\"$MAIN\",\"method\":\"upgrade\",\"args\":\"AGFzbQ==\",\"deposit\":\"0\",\"gas_tgas\":30}}}" "100 Tgas" "0.1 NEAR"
args=$(b64 "{\"new_operator_id\":\"$OWNER\"}")
p=$(propose "$M1" "{\"Call\":{\"target\":\"$MAIN\",\"method\":\"set_operator\",\"args\":\"$args\",\"deposit\":\"0\",\"gas_tgas\":30}}")
expect_refused "cannot be cancelled by the owner" "$OWNER" "$DAO" cancel "{\"proposal_id\":$p}"
vote "$M2" "$p" false; vote "$M3" "$p" false
[ "$(gov_status "$p")" = "Rejected" ] && ok "an operator replacement: members rejected it instead" || bad "reject: $(gov_status "$p")"

step "members only"
expect_refused "only DAO members" "$STRANGER" "$DAO" propose '{"action":{"SetDelay":{"seconds":0}}}'
p=$(propose "$M1" '{"SetDelay":{"seconds":0}}')
vote "$M2" "$p" true
expect_refused "only DAO members" "$STRANGER" "$DAO" execute "{\"proposal_id\":$p}" "300 Tgas"
exec_ "$p" && ok "a member executed it" || bad "execute"

step "keystore keys"
if [ -z "${NO_FA_KEYS:-}" ]; then
    # The DAO account's own full-access key signs request_key: refused.
    expect_refused "signer key is not an approved keystore key" "$DAO" "$DAO" request_key \
        '{"request":{"derivation_path":"","app_public_key":"bls12381g1:x","domain_id":2}}' "150 Tgas"
else
    echo "  (the DAO account has no full-access key left to try request_key with)"
fi

step "the owner's money"
expect_refused "the platform's fees available are 0" "$OWNER" "$MAIN" withdraw_platform_near \
    "{\"amount\":\"1\",\"receiver_id\":\"$OWNER\"}" "50 Tgas" "1 yoctoNEAR"
expect_refused "Only owner" "$STRANGER" "$MAIN" withdraw_platform_token \
    "{\"amount\":\"1\",\"receiver_id\":\"$STRANGER\"}" "50 Tgas" "1 yoctoNEAR"
expect_refused "Only governance" "$OWNER" "$MAIN" gov_transfer \
    "{\"token\":null,\"amount\":\"1\",\"receiver_id\":\"$OWNER\"}"

summary
