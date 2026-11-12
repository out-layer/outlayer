# DAO governance helpers for the deploy and upgrade scripts. Source, do not run.
#
# The keystore DAO (dao.outlayer.<net>) governs itself, the register contract and the main
# contract: approving a build, upgrading code and replacing a role are proposals that members
# vote on and that a member executes once the delay has passed (72 h on mainnet). These helpers
# drive one proposal as far as it can go now and say what is left.
#
# Every function takes the network as $NETWORK and signs with near-cli's legacy keychain.

# dao_has_governance <dao> — 0 when the DAO contract on chain carries governance (v5+).
dao_has_governance() {
    near contract call-function as-read-only "$1" get_gov_delay_sec json-args '{}' \
        network-config "$NETWORK" now >/dev/null 2>&1
}

_dao_view() {
    near contract call-function as-read-only "$1" "$2" json-args "$3" network-config "$NETWORK" now 2>/dev/null
}

# dao_find_open <dao> <action-json> — prints "<id> <status> <executable_after_ns>" of the newest
# Pending or Approved proposal with exactly this action, or nothing.
dao_find_open() {
    local dao="$1" action="$2" next from
    next=$(_dao_view "$dao" get_config '{}' | python3 -I -c 'import sys,json; print(json.load(sys.stdin)["next_proposal_id"])')
    from=$(( next > 200 ? next - 200 : 0 ))
    _dao_view "$dao" get_gov_proposals "{\"from_index\":$from,\"limit\":200}" | python3 -I -c '
import sys, json
want = json.loads(sys.argv[1])
hit = None
for p in json.load(sys.stdin):
    if p["action"] == want and p["status"] in ("Pending", "Approved"):
        hit = p
if hit:
    print(hit["id"], hit["status"], hit.get("executable_after") or 0)' "$action"
}

# dao_tx <signer> <dao> <method> <json-args> [gas] [deposit] — prints the call's return value.
dao_tx() {
    local out
    out=$(near contract call-function as-transaction "$2" "$3" json-args "$4" \
        prepaid-gas "${5:-100 Tgas}" attached-deposit "${6:-0 NEAR}" sign-as "$1" \
        network-config "$NETWORK" sign-with-legacy-keychain send 2>&1) || {
        printf '%s\n' "$out" | grep -iE 'panicked|error' | head -3 >&2
        return 1
    }
    printf '%s\n' "$out" | sed -n '/Function execution return value/,$p' | sed -n '2p' | tr -d ' "'
}

# dao_drive <dao> <member> <action-json> — propose (or find the open proposal), vote as
# <member>, and execute when it is approved and its delay has passed.
# Returns 0 when executed, 2 when it waits for votes or for the delay (the next steps are
# printed), 1 on an error. "Executed" is the DAO's record: an Upgrade or a Call is dispatched
# after it, so the caller checks the target to know the call took effect.
dao_drive() {
    local dao="$1" member="$2" action="$3" found id status after now voted
    found=$(dao_find_open "$dao" "$action")
    if [ -z "$found" ]; then
        # A proposal pays its storage; the excess of the 0.1 NEAR comes back.
        id=$(dao_tx "$member" "$dao" propose "{\"action\":$action}" '100 Tgas' '0.1 NEAR') || return 1
        echo "  proposed: #$id (by $member)"
    else
        id=${found%% *}
        echo "  open proposal #$id ($(echo "$found" | cut -d' ' -f2))"
        voted=$(_dao_view "$dao" get_gov_proposal "{\"proposal_id\":$id}" | python3 -I -c '
import sys,json; p=json.load(sys.stdin); m=sys.argv[1]
print("yes" if m in p["votes_for"] or m in p["votes_against"] else "no")' "$member")
        if [ "$voted" = no ] && [ "$(echo "$found" | cut -d' ' -f2)" = Pending ]; then
            dao_tx "$member" "$dao" vote "{\"proposal_id\":$id,\"approve\":true}" >/dev/null || return 1
            echo "  voted for #$id as $member"
        fi
    fi

    read -r status after < <(_dao_view "$dao" get_gov_proposal "{\"proposal_id\":$id}" | python3 -I -c '
import sys,json; p=json.load(sys.stdin); print(p["status"], p.get("executable_after") or 0)')
    now=$(python3 -I -c 'import time; print(int(time.time()*1e9))')
    if [ "$status" = Approved ] && [ "$now" -ge "$after" ]; then
        local call_ok=yes
        dao_tx "$member" "$dao" execute "{\"proposal_id\":$id}" '300 Tgas' >/dev/null 2>&1 || call_ok=no
        status=$(_dao_view "$dao" get_gov_proposal "{\"proposal_id\":$id}" | python3 -I -c 'import sys,json; print(json.load(sys.stdin)["status"])')
        if [ "$status" != Executed ]; then
            echo "  #$id did not execute (status $status)"; return 1
        fi
        if [ "$call_ok" = no ]; then
            echo "  #$id is executed, but the call it made failed on the target; propose again once fixed"
            return 1
        fi
        echo "  executed #$id"
        return 0
    fi

    if [ "$status" = Pending ]; then
        echo "  #$id waits for votes. Each other member runs:"
        echo "    near contract call-function as-transaction $dao vote json-args '{\"proposal_id\":$id,\"approve\":true}' \\"
        echo "      prepaid-gas '100 Tgas' attached-deposit '0 NEAR' sign-as <member> network-config $NETWORK sign-with-legacy-keychain send"
    else
        echo "  #$id is approved; it executes from $(python3 -I -c 'import sys,datetime; print(datetime.datetime.fromtimestamp(int(sys.argv[1])/1e9, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))' "$after")."
    fi
    echo "  Then a member executes it (or rerun this script):"
    echo "    near contract call-function as-transaction $dao execute json-args '{\"proposal_id\":$id}' \\"
    echo "      prepaid-gas '300 Tgas' attached-deposit '0 NEAR' sign-as <member> network-config $NETWORK sign-with-legacy-keychain send"
    return 2
}

# dao_measurements_action <component> <register> <measurements-json> — the action that approves
# a build: the DAO's own ApproveMeasurements for a keystore, a Call to the register contract
# for a worker.
dao_measurements_action() {
    local component="$1" register="$2" meas="$3" args
    if [ "$component" = keystore ]; then
        printf '{"ApproveMeasurements":{"measurements":%s}}' "$meas"
    else
        args=$(printf '{"measurements":%s,"clear_others":false}' "$meas" | base64 | tr -d '\n')
        printf '{"Call":{"target":"%s","method":"add_approved_measurements","args":"%s","deposit":"0","gas_tgas":30}}' "$register" "$args"
    fi
}
