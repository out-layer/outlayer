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

# DAO_CHAIN picks how far the helpers go on chain:
#   send  — every transaction is sent: the proposal, the vote of every member whose key is in the
#           local legacy keychain (~/.near-credentials/<net>/), and the execute. Testnet, where
#           the members' keys are on this machine.
#   print — nothing is sent: the ready commands are printed, one per member who still has to vote,
#           and the execute. Mainnet always prints: its members sign on their own machines.
dao_chain_mode() {
    if [ "$NETWORK" = mainnet ]; then echo print; else echo "${DAO_CHAIN:-send}"; fi
}

# dao_local_key <account> — 0 when the legacy keychain holds a key for <account>.
dao_local_key() {
    local d="$HOME/.near-credentials/$NETWORK"
    [ -f "$d/$1.json" ] || [ -n "$(ls "$d/$1"/*.json 2>/dev/null | head -1)" ]
}

# dao_vote_local <dao> <id> [keystore-key] — vote for <id> with every member whose key is
# local, until it no longer waits for votes. Governance proposals name who voted; for a
# registration or a key revocation a member who already voted is refused by the contract, which
# is skipped. A keystore registration takes <keystore-key>, the key read from the operator's own
# CVM: the vote names it and the DAO refuses it on a registration for another key.
dao_vote_local() {
    local dao="$1" id="$2" key="${3:-}" m status args
    args="{\"proposal_id\":$id,\"approve\":true${key:+,\"public_key\":\"$key\"}}"
    for m in $(dao_members_json "$dao" | python3 -I -c 'import json,sys; print(" ".join(json.load(sys.stdin)["members"]))'); do
        status=$(dao_status "$dao" "$id")
        [ "$status" = Pending ] || break
        if dao_has_voted "$dao" "$id" "$m"; then continue; fi
        dao_local_key "$m" || { echo "  (no local key for $m)"; continue; }
        if dao_tx "$m" "$dao" vote "$args" >/dev/null 2>&1; then
            echo "  voted for #$id as $m"
        fi
    done
}

# dao_status <dao> <id> — the status of a governance proposal, a registration or a key revocation.
dao_status() {
    local m
    for m in get_gov_proposal get_proposal get_revoke_proposal; do
        local s
        s=$(_dao_view "$1" "$m" "{\"proposal_id\":$2}" | python3 -I -c 'import json,sys
p=json.load(sys.stdin)
print(p["status"] if p else "")' 2>/dev/null)
        [ -n "$s" ] && { echo "$s"; return 0; }
    done
}

# dao_has_voted <dao> <id> <member> — 0 when a governance proposal records <member>'s vote.
dao_has_voted() {
    _dao_view "$1" get_gov_proposal "{\"proposal_id\":$2}" | python3 -I -c '
import json,sys
p=json.load(sys.stdin); m=sys.argv[1]
sys.exit(0 if p and (m in p["votes_for"] or m in p["votes_against"]) else 1)' "$3"
}

# dao_drive <dao> <member> <action-json> — the proposal for <action-json> as far as it can go now
# (DAO_CHAIN, above): proposed by <member>, voted, executed once approved and past its delay.
# Returns 0 when executed, 2 when it waits for votes or for the delay, or when nothing is sent
# (the next steps are printed), 1 on an error. "Executed" is the DAO's record: an Upgrade or a
# Call is dispatched after it, so the caller checks the target to know the call took effect.
dao_drive() {
    local dao="$1" member="$2" action="$3" mode found id status after now
    mode=$(dao_chain_mode)
    found=$(dao_find_open "$dao" "$action")
    if [ -z "$found" ]; then
        if [ "$mode" = print ]; then
            echo "  Nothing sent (print mode). Propose — it returns the id — then the members vote and one executes:"
            echo "    near contract call-function as-transaction $dao propose json-args '{\"action\":$action}' prepaid-gas '100 Tgas' attached-deposit '0.1 NEAR' sign-as $member network-config $NETWORK sign-with-legacy-keychain send"
            return 2
        fi
        # A proposal pays its storage; the excess of the 0.1 NEAR comes back. The proposer's
        # vote comes with it.
        id=$(dao_tx "$member" "$dao" propose "{\"action\":$action}" '100 Tgas' '0.1 NEAR') || return 1
        echo "  proposed: #$id (by $member, who voted with it)"
    else
        id=${found%% *}
        echo "  open proposal #$id ($(echo "$found" | cut -d' ' -f2))"
    fi
    [ "$mode" = send ] && dao_vote_local "$dao" "$id"

    read -r status after < <(_dao_view "$dao" get_gov_proposal "{\"proposal_id\":$id}" | python3 -I -c '
import sys,json; p=json.load(sys.stdin); print(p["status"], p.get("executable_after") or 0)')
    now=$(python3 -I -c 'import time; print(int(time.time()*1e9))')
    if [ "$mode" = send ] && [ "$status" = Approved ] && [ "$now" -ge "$after" ]; then
        local call_ok=yes
        dao_tx "$member" "$dao" execute "{\"proposal_id\":$id}" '300 Tgas' >/dev/null 2>&1 || call_ok=no
        status=$(dao_status "$dao" "$id")
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

    case "$status" in
        Pending) dao_print_votes "$dao" "$id" ;;
        Approved)
            if [ "$now" -lt "$after" ]; then
                echo "  #$id is approved; it executes from $(python3 -I -c 'import sys,datetime; print(datetime.datetime.fromtimestamp(int(sys.argv[1])/1e9, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))' "$after")."
            else
                echo "  #$id is approved and executable."
            fi ;;
        *) echo "  #$id is $status"; return 1 ;;
    esac
    echo "  Execute (any member):"
    echo "    near contract call-function as-transaction $dao execute json-args '{\"proposal_id\":$id}' prepaid-gas '300 Tgas' attached-deposit '0 NEAR' sign-as $member network-config $NETWORK sign-with-legacy-keychain send"
    return 2
}

# dao_print_votes <dao> <id> [keystore-key] — how many votes proposal <id> still needs, and the
# ready `vote` command for every member of its electorate who has not voted. Works for
# governance proposals, key revocations and keystore registrations (one `vote` method, one id
# counter). A registration's commands name <keystore-key> — the key the operator read from
# their own CVM, never the one the chain shows for the id.
dao_print_votes() {
    local dao="$1" id="$2" key="${3:-}" p kind
    p=$(_dao_view "$dao" get_gov_proposal "{\"proposal_id\":$id}")
    kind=gov
    if [ -z "$p" ] || [ "$p" = null ]; then p=$(_dao_view "$dao" get_proposal "{\"proposal_id\":$id}"); kind=registration; fi
    if [ -z "$p" ] || [ "$p" = null ]; then p=$(_dao_view "$dao" get_revoke_proposal "{\"proposal_id\":$id}"); kind=revoke; fi
    if [ -z "$p" ] || [ "$p" = null ]; then echo "  #$id: no such proposal on $dao" >&2; return 1; fi
    printf '%s' "$p" | python3 -I -c '
import json, sys
dao, pid, net, kind, members_json, key = sys.argv[1:7]
p = json.load(sys.stdin)
members = json.loads(members_json)
if kind == "gov":
    electorate, threshold = p["electorate"], p["threshold"]
    voted = set(p["votes_for"]) | set(p["votes_against"])
    have = len(p["votes_for"])
else:
    # A registration or a key revocation counts the votes of the current members against the
    # current threshold.
    electorate, threshold = members["members"], members["threshold"]
    voted, have = set(), int(p.get("votes_for") or 0)
need = max(threshold - have, 0)
todo = [m for m in electorate if m not in voted]
vote = {"proposal_id": int(pid), "approve": True}
if kind == "registration":
    vote["public_key"] = key or "<the key your own CVM printed: Using keystore public key>"
    chain_key = p["public_key"]
    if key and chain_key != key:
        print(f"  !! registration #{pid} on chain is for {chain_key}, not for {key}: no vote for {key} will land on it")
vote_json = json.dumps(vote, separators=(",", ":"))
print(f"  #{pid} waits for votes: {have} of {threshold}; {need} more needed. Ready commands"
      + (" (any of them; a member who already voted is refused):" if kind != "gov" else ":"))
for m in todo:
    print(f"    near contract call-function as-transaction {dao} vote json-args \x27{vote_json}\x27 "
          f"prepaid-gas \x27100 Tgas\x27 attached-deposit \x270 NEAR\x27 sign-as {m} network-config {net} sign-with-legacy-keychain send")
' "$dao" "$id" "$NETWORK" "$kind" "$(dao_members_json "$dao")" "$key"
}

# dao_members_json <dao> — {"members":[...],"threshold":N} of the DAO as it stands.
dao_members_json() {
    local m t
    m=$(_dao_view "$1" get_dao_members '{}' | tr -d '\n')
    t=$(_dao_view "$1" get_config '{}' | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["approval_threshold"])')
    printf '{"members":%s,"threshold":%s}' "${m:-[]}" "${t:-1}"
}

# dao_measurements_action <component> <register> <measurements-json> — the action that approves
# a worker build: a Call to the register contract. A keystore build is not a measurements tuple:
# it is approved as ApproveOsImage + ApproveCompose (scripts/deploy_tdx.sh).
dao_measurements_action() {
    local component="$1" register="$2" meas="$3" args
    [ "$component" = worker ] || { echo "dao_measurements_action: workers only; a keystore build is ApproveOsImage + ApproveCompose" >&2; return 1; }
    args=$(printf '{"measurements":%s,"clear_others":false}' "$meas" | base64 | tr -d '\n')
    printf '{"Call":{"target":"%s","method":"add_approved_measurements","args":"%s","deposit":"0","gas_tgas":30}}' "$register" "$args"
}
