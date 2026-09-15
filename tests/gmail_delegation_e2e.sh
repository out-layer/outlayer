#!/usr/bin/env bash
#
# Gmail through the one secret model: the owner stores the credential ONCE
# under their own account and grants an agent by whitelist; the agent names the
# owner's row in `secrets_ref` and sends. No X-Use-Owner-Secret, no agent row,
# no credential handed to anybody.
#
#   G2  the delegated send: the agent's key, the owner's row, a real message;
#       the OWNER's policy governs it (its subject_prefix is the one in force,
#       its counter moves). That the message's From is the owner's address is
#       not readable from the send's answer and is reported as a skip, not
#       assumed
#   G1  a policy without max_per_day sends, and the answer then carries no
#       remaining_today at all; the cap is put back afterwards and read back
#       through `status`, because a live mailbox must not stay uncapped
#   G4  the owner's max_per_day is counted PER CALLING AGENT. Two whitelisted
#       agents under a cap of 2: each sends what its own counter still allows
#       and is refused on the next — the owner decides whom to admit, and each
#       admission carries its own allowance. Up to six real messages; needs
#       AGENT2_PAYMENT_KEY and AGENT2_ACCOUNT, and both agents' connector quota
#
# Every send is a REAL email to GMAIL_TEST_TO: one for G2, one for G1, up to
# six for G4. Whatever happens, the capped policy is put back on exit.
#
# Needs: PARENT (the owner; the CLI logged in as it), AGENT_PAYMENT_KEY and
# AGENT_ACCOUNT (a custody wallet the owner grants), GMAIL_TEST_TO (an address
# the policy allows), and the credential in GMAIL_ENV (default
# connectors/gmail-connector/.env.gmail: CLIENT_ID, SECRET, REFRESH_TOKEN) —
# read into this shell, never exported, never printed. It reaches jq through
# the environment of that one process; it reaches `outlayer secrets set` as an
# argument, which is visible to `ps` on this machine for the length of the call.
#
# Run:
#   PARENT=you.testnet AGENT_PAYMENT_KEY=… AGENT_ACCOUNT=… GMAIL_TEST_TO=… \
#     ./tests/gmail_delegation_e2e.sh --apply
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/hos_common.sh"

PARENT="${PARENT:-}"
GMAIL="${GMAIL:-connectors.outlayer.testnet/gmail}"
GMAIL_ENV="${GMAIL_ENV:-$SCRIPT_DIR/../connectors/gmail-connector/.env.gmail}"
AGENT_PAYMENT_KEY="${AGENT_PAYMENT_KEY:-}"
AGENT_ACCOUNT="${AGENT_ACCOUNT:-}"
AGENT2_PAYMENT_KEY="${AGENT2_PAYMENT_KEY:-}"
AGENT2_ACCOUNT="${AGENT2_ACCOUNT:-}"
GMAIL_TEST_TO="${GMAIL_TEST_TO:-}"
ONLY="${ONLY:-}"
# Row selection, the way every suite spells it: ONLY unset runs everything.
want() { [[ -z "$ONLY" ]] || [[ ",$ONLY," == *",$1,"* ]]; }
APPLY=false; [[ "${1:-}" == "--apply" ]] && APPLY=true

if [[ "$APPLY" != true ]]; then
  sed -n '3,34p' "$0" >&2; echo "  Pass --apply to run." >&2; exit 0
fi
[[ -n "$PARENT" ]] || { echo "✗ PARENT is required" >&2; exit 1; }
for v in AGENT_PAYMENT_KEY AGENT_ACCOUNT GMAIL_TEST_TO; do
  [[ -n "${!v}" ]] || { echo "✗ $v is required" >&2; exit 1; }
done
[[ -r "$GMAIL_ENV" ]] || { echo "✗ no credential file at $GMAIL_ENV" >&2; exit 1; }
hos_require
PROJECT="$GMAIL"
source "$SCRIPT_DIR/lib/secrets_common.sh"

# The credential: read into this shell (not exported — a child process must
# not inherit it, and a variable the caller's shell had already exported is
# un-exported here) and never echoed. `store` reports project/profile/access.
source "$GMAIL_ENV"
export -n CLIENT_ID SECRET REFRESH_TOKEN 2>/dev/null || true
for v in CLIENT_ID SECRET REFRESH_TOKEN; do
  [[ -n "${!v:-}" ]] || { echo "✗ $GMAIL_ENV lacks $v" >&2; exit 1; }
done

CAPPED=$(jq -nc --arg to "$GMAIL_TEST_TO" \
  '{recipients:[$to], max_recipients:1, subject_prefix:"[agent]", max_per_day:50}')
CAPLESS=$(jq -c 'del(.max_per_day)' <<<"$CAPPED")
credential_with() { # credential_with <policy-json> → the secrets JSON
  # The credential reaches jq through the environment of this one process,
  # never through its arguments.
  CLIENT_ID="$CLIENT_ID" SECRET="$SECRET" REFRESH_TOKEN="$REFRESH_TOKEN" \
    jq -nc --argjson p "$1" \
    '{GMAIL_CLIENT_ID:env.CLIENT_ID, GMAIL_CLIENT_SECRET:env.SECRET, GMAIL_REFRESH_TOKEN:env.REFRESH_TOKEN, GMAIL_POLICY:($p|tojson)}'
}
# The policy on chain. A live mailbox must not be left uncapped (G1) or under
# G4's cap of 2, so the EXIT trap puts the capped policy back unless the LAST
# CONFIRMED store was the capped one. Two flags: what a store was ASKED to put
# on chain (set before the store — a transaction that landed while its
# finality wait timed out is on chain all the same) and what a store CONFIRMED
# (set after it returned). The cap is known to be there only when both agree.
POLICY_ASKED=""
POLICY_CONFIRMED=""
store_policy() { # store_policy <policy-json> [more grantees…] — the owner's row, granted to the agent(s)
  local pol=$1; shift
  local grant="whitelist:$PARENT,$AGENT_ACCOUNT"; for a in "$@"; do grant="$grant,$a"; done
  POLICY_ASKED="$pol"
  store "$GMAIL" gmail "$(credential_with "$pol")" "$grant"
  POLICY_CONFIRMED="$pol"
}
restore_cap() {
  if [[ -n "$POLICY_ASKED" && ( "$POLICY_ASKED" != "$CAPPED" || "$POLICY_CONFIRMED" != "$CAPPED" ) ]]; then
    note "putting the capped policy back before exit"
    ( store_policy "$CAPPED" ) || echo "✗ THE CAP WAS NOT RESTORED — store the capped policy for $GMAIL by hand" >&2
  fi
}
trap restore_cap EXIT
# gmail <input-json> [payment-key] — an AGENT calls, naming the OWNER's row.
gmail() {
  https_post "${2:-$AGENT_PAYMENT_KEY}" "$GMAIL" \
    "$(jq -nc --argjson i "$1" --arg o "$PARENT" '{input:$i, secrets_ref:{account_id:$o, profile:"gmail"}}')"
}
# gmail is a connector, and a connector call is refused once the WALLET has
# spent its calls for the day — an answer that says nothing about the policy
# under test. `gmail_ready` makes the status call a row needs anyway and steps
# the row aside when the quota is what answered; the rows that cannot start
# with a status call ask `quota_refused` at each of their own refusals.
gmail_ready() { # gmail_ready <row> [key] — leaves the status answer in RUN_*
  gmail '{"operation":"status"}' "${2:-}"
  quota_refused "$RUN_ERR" || return 0
  skip "$1 the wallet spent its connector calls for the day ($(head -c 80 <<<"$RUN_ERR")) — run it on a wallet minted for the run"
  return 1
}

RUN="$(date -u +%Y%m%dT%H%M%SZ)"

log "Fixture: the owner's row, capped, granted to $AGENT_ACCOUNT"
store_policy "$CAPPED"

# ── G2 the delegated send ────────────────────────────────────────────────────
if ! want G2; then
  :
elif ! gmail_ready G2; then
  :
else
  log "G2 the agent sends with the owner's credential"
  G2_BEFORE=$(field .output.sent_today); G2_PREFIX=$(field .output.policy.subject_prefix)
  [[ "$RUN_OK" == "true" && "$(field .output.credential)" == "ok" ]] \
    && pass "G2 control: the agent reads the owner's row through the grant (credential=$(field .output.credential), sent_today=$G2_BEFORE)" \
    || fail "G2 control failed — the agent cannot read the owner's row: success=$RUN_OK err='$(head -c 160 <<<"$RUN_ERR")'"
  [[ "$G2_PREFIX" == "[agent]" ]] \
    && pass "G2 the OWNER's policy is the one in force (subject_prefix=$G2_PREFIX)" \
    || fail "G2 subject_prefix is '$G2_PREFIX', expected the owner's [agent]"

  gmail "$(jq -nc --arg to "$GMAIL_TEST_TO" --arg s "delegated send $RUN" \
    --arg b "sent by an agent holding a grant on the owner row, named through secrets_ref" \
    '{operation:"send", to:$to, subject:$s, body:$b}')"
  if [[ "$RUN_OK" != "true" ]]; then
    fail "G2 the send did not run: success=$RUN_OK HTTP $HTTP_CODE err='$(head -c 160 <<<"$RUN_ERR")'"
  else
    [[ -n "$(field .output.message_id)" ]] \
      && pass "G2 a real message left the owner's mailbox: message_id=$(field .output.message_id)" \
      || fail "G2 the send answered without a message_id: $(head -c 200 <<<"$RUN_OUT")"
    [[ "$(field .output.sent_today)" == "$((G2_BEFORE + 1))" ]] \
      && pass "G2 and the owner's counter moved ($G2_BEFORE → $(field .output.sent_today))" \
      || fail "G2 sent_today is '$(field .output.sent_today)', expected $((G2_BEFORE + 1))"
    [[ "$(field .output.remaining_today)" == "$((50 - G2_BEFORE - 1))" ]] \
      && pass "G2 and the remaining allowance is the owner's cap minus the sends" \
      || fail "G2 remaining_today is '$(field .output.remaining_today)', expected $((50 - G2_BEFORE - 1))"
    skip "G2 the message's From is the owner's address — the send's answer carries no From header; read it in $GMAIL_TEST_TO's mailbox"
  fi
fi

# ── G1 a policy with no daily cap ────────────────────────────────────────────
if want G1; then
  log "G1 the owner stores the same credential with NO max_per_day"
  store_policy "$CAPLESS"
  gmail '{"operation":"status"}'
  # A policy that is PRESENT (its recipients read back) and has no cap — an
  # absent or unreadable policy has no max_per_day either.
  if [[ "$RUN_OK" == "true" && -n "$(field .output.policy.recipients)" && "$(field .output.policy.max_per_day)" == "" ]]; then
    pass "G1 status reads the policy back with no cap"
  elif quota_refused "$RUN_ERR"; then
    skip "G1 the wallet spent its connector calls for the day ($(head -c 80 <<<"$RUN_ERR")) — the capless policy is stored and unread"
  else
    fail "G1 status: success=$RUN_OK recipients='$(field .output.policy.recipients)' max_per_day='$(field .output.policy.max_per_day)' (expected a policy with no cap)"
  fi
  gmail "$(jq -nc --arg to "$GMAIL_TEST_TO" --arg s "capless send $RUN" \
    --arg b "sent under a policy with no daily cap" \
    '{operation:"send", to:$to, subject:$s, body:$b}')"
  if quota_refused "$RUN_ERR"; then
    skip "G1 the send never reached the connector: the wallet's calls for the day are spent"
  elif [[ "$RUN_OK" != "true" ]]; then
    fail "G1 the send did not run: success=$RUN_OK HTTP $HTTP_CODE err='$(head -c 160 <<<"$RUN_ERR")'"
  else
    [[ -n "$(field .output.message_id)" ]] \
      && pass "G1 a capless policy sends: message_id=$(field .output.message_id)" \
      || fail "G1 the send answered without a message_id: $(head -c 200 <<<"$RUN_OUT")"
    [[ "$(field .output.remaining_today)" == "" ]] \
      && pass "G1 and the answer carries no remaining_today — there is no cap to count down" \
      || fail "G1 remaining_today='$(field .output.remaining_today)' under a policy with no cap"
  fi

  log "G1 the cap goes back — a live mailbox does not stay uncapped"
  store_policy "$CAPPED"
  gmail '{"operation":"status"}'
  if [[ "$RUN_OK" == "true" && "$(field .output.policy.max_per_day)" == "50" ]]; then
    pass "G1 the capped policy is back (max_per_day=$(field .output.policy.max_per_day))"
  elif quota_refused "$RUN_ERR"; then
    skip "G1 the restore was STORED but could not be read back — the wallet's calls for the day are spent; check max_per_day by hand"
  else
    fail "G1 THE CAP WAS NOT RESTORED: success=$RUN_OK max_per_day='$(field .output.policy.max_per_day)' — put it back by hand"
  fi
fi

# ── G4 the cap is per calling agent ─────────────────────────────────────────
if ! want G4; then
  :
elif [[ -z "$AGENT2_PAYMENT_KEY" || -z "$AGENT2_ACCOUNT" ]]; then
  skip "G4 needs AGENT2_PAYMENT_KEY and AGENT2_ACCOUNT (a second granted agent)"
else
  log "G4 two agents under max_per_day=2: each gets its own allowance"
  # Each agent's counter is its own, so a cap of 2 means 2 for each — less
  # whatever a run earlier today already spent. Read both counters first.
  G4_CAP=$(jq -c '.max_per_day = 2' <<<"$CAPPED")
  store_policy "$G4_CAP" "$AGENT2_ACCOUNT"
  g4_send() { # g4_send <who> <key> <n> — one send, echoes ok|refused|other
    gmail "$(jq -nc --arg to "$GMAIL_TEST_TO" --arg s "per-agent cap $RUN $1 #$3" --arg b "G4: the cap is counted per agent" \
      '{operation:"send", to:$to, subject:$s, body:$b}')" "$2"
    # The connector's envelope: {success, operation, error, output, logs}. A
    # cap hit is a COMPLETED run whose envelope says success:false and
    # error:"policy_denied: N of the owner's M messages a day are used; …".
    # Only THAT sentence is a refusal by the cap; every other policy_denied
    # (a recipient the policy does not allow, an attachment too big) is a
    # different rule and reads as "other".
    if [[ "$RUN_OK" == "true" && "$(field .success)" == "true" && -n "$(field .output.message_id)" ]]; then echo ok
    elif [[ "$(field .success)" == "false" ]] && grep -q "messages a day are used" <<<"$(field .error)"; then echo refused
    elif quota_refused "$RUN_ERR"; then echo quota
    else echo "other: status=$RUN_OK success=$(field .success) error=$(field .error | head -c 90)"; fi
  }
  # g4_agent <who> <key> <room> — sends room+1 times: every send inside the
  # room must go, the one past it must be refused by the cap. Leaves G4_SENT
  # and G4_REFUSED_AT (the index of the refused send, or empty).
  g4_agent() {
    local who=$1 key=$2 room=$3 i r
    G4_SENT=0; G4_REFUSED_AT=""; G4_QUOTA=false
    for i in $(seq 1 $(( room + 1 ))); do
      r=$(g4_send "$who" "$key" "$i")
      case "$r" in
        ok)      G4_SENT=$((G4_SENT+1));;
        refused) G4_REFUSED_AT=$i; break;;
        quota)   G4_QUOTA=true; break;;
        *)       fail "G4 $who send #$i: $r"; break;;
      esac
    done
  }
  gmail '{"operation":"status"}'; G4_A1=$(field .output.sent_today)
  gmail '{"operation":"status"}' "$AGENT2_PAYMENT_KEY"; G4_A2=$(field .output.sent_today)
  note "G4 counters before: agent1=$G4_A1 agent2=$G4_A2"
  A1_ROOM=$(( 2 - ${G4_A1:-0} )); (( A1_ROOM < 0 )) && A1_ROOM=0
  A2_ROOM=$(( 2 - ${G4_A2:-0} )); (( A2_ROOM < 0 )) && A2_ROOM=0

  G4_JUDGED=false
  g4_agent agent1 "$AGENT_PAYMENT_KEY" "$A1_ROOM"
  if [[ "$G4_QUOTA" == true ]]; then
    skip "G4 agent 1: the wallet's connector calls for the day ran out after $G4_SENT of $A1_ROOM — the owner's cap is not what refused it"
  elif [[ "$G4_SENT" == "$A1_ROOM" && "$G4_REFUSED_AT" == "$(( A1_ROOM + 1 ))" ]]; then
    G4_JUDGED=true
    pass "G4 agent 1 sent its room ($A1_ROOM) and was refused by the cap on send #$G4_REFUSED_AT"
  else
    fail "G4 agent 1: sent $G4_SENT of room $A1_ROOM, refused at '${G4_REFUSED_AT:-never}' (expected #$(( A1_ROOM + 1 )))"
  fi

  # Agent 2 after agent 1 is capped: its own room, its own refusal past it.
  g4_agent agent2 "$AGENT2_PAYMENT_KEY" "$A2_ROOM"
  if [[ "$G4_QUOTA" == true ]]; then
    skip "G4 agent 2: the second wallet's connector calls for the day ran out after $G4_SENT of $A2_ROOM — the owner's cap is not what refused it"
  elif (( A2_ROOM > 0 )); then
    [[ "$G4_SENT" == "$A2_ROOM" && "$G4_REFUSED_AT" == "$(( A2_ROOM + 1 ))" ]] \
      && pass "G4 agent 2 sent its own room ($A2_ROOM) after agent 1 was capped and was refused on send #$G4_REFUSED_AT — counted per agent" \
      || fail "G4 agent 2: sent $G4_SENT of room $A2_ROOM, refused at '${G4_REFUSED_AT:-never}' (expected #$(( A2_ROOM + 1 ))) — agent 1's spend reached agent 2's counter?"
  else
    # With no room left, a refusal on #1 is what a SHARED counter would show
    # too. Only the refusal is asserted; independence is the skipped half.
    [[ "$G4_REFUSED_AT" == "1" ]] \
      && pass "G4 agent 2, at its cap already, was refused by the cap on send #1" \
      || fail "G4 agent 2 at its cap: refused at '${G4_REFUSED_AT:-never}', expected #1"
    skip "G4 agent 2 had no room left today (counter $G4_A2 of 2): that it still sends after agent 1 is capped needs a fresh day"
  fi
  # The per-agent cap is what this suite exists to show. A run where it stepped
  # aside is not a run that passed: say so with an exit code, not only a line.
  if [[ "${G4_JUDGED:-false}" != true ]]; then
    warn "G4 was not judged — the owner's cap per calling agent is unproven by this run"
    G4_UNJUDGED=true
  fi
  store_policy "$CAPPED"
fi

verdict "gmail delegation"; RC=$?

# A suite whose central row never ran exits 3 (NOTHING), the same code the
# runner renders as "silent about what it covers". A real failure keeps its
# own status: 3 is for a run that judged nothing, not for one that judged and
# found something wrong.
if [[ "${G4_UNJUDGED:-false}" == true && $RC -eq 0 ]]; then RC=3; fi
exit $RC
