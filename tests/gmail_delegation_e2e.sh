#!/usr/bin/env bash
#
# Gmail through the one secret model: the owner stores the credential ONCE
# under their own account and grants an agent by whitelist; the agent names the
# owner's row in `secrets_ref` and sends. No X-Use-Owner-Secret, no agent row,
# no credential handed to anybody.
#
#   G2  the delegated send — plan G2: "owner-delegated credential: agent sends
#       from the owner's mailbox". The agent's key, the owner's row, a real
#       message; the OWNER's policy governs it (its subject_prefix is applied,
#       its counter moves), and the sender the guest saw is the agent
#   G1  plan G1: "policy without max_per_day → sends". The answer then carries
#       no remaining_today at all; the cap is put back afterwards and read back
#       through `status`, because a live mailbox must not stay uncapped
#   G4  plan G4: the owner's max_per_day is counted PER CALLING AGENT. Two
#       whitelisted agents under a cap of 2: each sends 2, each is refused on
#       its 3rd — the owner decides whom to admit, and each admission carries
#       its own allowance. Six real messages; needs AGENT2_PAYMENT_KEY and
#       AGENT2_ACCOUNT, and both agents' connector quota
#   (G3, the manifest's 400/day per wallet, is not run: the coordinator's
#   counter is visible only at refusal, and reaching it costs 400 messages)
#
# Every send is a REAL email to GMAIL_TEST_TO. Two per run.
#
# Needs: PARENT (the owner; the CLI logged in as it), AGENT_PAYMENT_KEY and
# AGENT_ACCOUNT (a custody wallet the owner grants), GMAIL_TEST_TO (an address
# the policy allows), and the credential in GMAIL_ENV (default
# connectors/gmail-connector/.env.gmail: CLIENT_ID, SECRET, REFRESH_TOKEN) —
# sourced, never printed.
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
  sed -n '3,30p' "$0" >&2; echo "  Pass --apply to run." >&2; exit 0
fi
[[ -n "$PARENT" ]] || { echo "✗ PARENT is required" >&2; exit 1; }
for v in AGENT_PAYMENT_KEY AGENT_ACCOUNT GMAIL_TEST_TO; do
  [[ -n "${!v}" ]] || { echo "✗ $v is required" >&2; exit 1; }
done
[[ -r "$GMAIL_ENV" ]] || { echo "✗ no credential file at $GMAIL_ENV" >&2; exit 1; }
hos_require
PROJECT="$GMAIL"
source "$SCRIPT_DIR/lib/secrets_common.sh"

# The credential: sourced into this shell and never echoed. Nothing below
# prints an environment variable, and `store` reports project/profile/access.
set -a; source "$GMAIL_ENV"; set +a
for v in CLIENT_ID SECRET REFRESH_TOKEN; do
  [[ -n "${!v:-}" ]] || { echo "✗ $GMAIL_ENV lacks $v" >&2; exit 1; }
done

CAPPED=$(jq -nc --arg to "$GMAIL_TEST_TO" \
  '{recipients:[$to], max_recipients:1, subject_prefix:"[agent]", max_per_day:50}')
CAPLESS=$(jq -c 'del(.max_per_day)' <<<"$CAPPED")
credential_with() { # credential_with <policy-json> → the secrets JSON
  jq -nc --arg id "$CLIENT_ID" --arg sec "$SECRET" --arg rt "$REFRESH_TOKEN" --argjson p "$1" \
    '{GMAIL_CLIENT_ID:$id, GMAIL_CLIENT_SECRET:$sec, GMAIL_REFRESH_TOKEN:$rt, GMAIL_POLICY:($p|tojson)}'
}
store_policy() { # store_policy <policy-json> [more grantees…] — the owner's row, granted to the agent(s)
  local pol=$1; shift
  local grant="whitelist:$PARENT,$AGENT_ACCOUNT"; for a in "$@"; do grant="$grant,$a"; done
  store "$GMAIL" gmail "$(credential_with "$pol")" "$grant"
}
# gmail <input-json> [payment-key] — an AGENT calls, naming the OWNER's row.
gmail() {
  https_post "${2:-$AGENT_PAYMENT_KEY}" "$GMAIL" \
    "$(jq -nc --argjson i "$1" --arg o "$PARENT" '{input:$i, secrets_ref:{account_id:$o, profile:"gmail"}}')"
}
RUN="$(date -u +%Y%m%dT%H%M%SZ)"

log "Fixture: the owner's row, capped, granted to $AGENT_ACCOUNT"
store_policy "$CAPPED"

# ── G2 the delegated send ────────────────────────────────────────────────────
if want G2; then
  log "G2 the agent sends with the owner's credential"
  gmail '{"operation":"status"}'
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
  fi
fi

# ── G1 a policy with no daily cap ────────────────────────────────────────────
if want G1; then
  log "G1 the owner stores the same credential with NO max_per_day"
  store_policy "$CAPLESS"
  gmail '{"operation":"status"}'
  [[ "$RUN_OK" == "true" && "$(field .output.policy.max_per_day)" == "" ]] \
    && pass "G1 status reads the policy back with no cap" \
    || fail "G1 status: success=$RUN_OK max_per_day='$(field .output.policy.max_per_day)' (expected absent)"
  gmail "$(jq -nc --arg to "$GMAIL_TEST_TO" --arg s "capless send $RUN" \
    --arg b "sent under a policy with no daily cap" \
    '{operation:"send", to:$to, subject:$s, body:$b}')"
  if [[ "$RUN_OK" != "true" ]]; then
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
  [[ "$RUN_OK" == "true" && "$(field .output.policy.max_per_day)" == "50" ]] \
    && pass "G1 the capped policy is back (max_per_day=$(field .output.policy.max_per_day))" \
    || fail "G1 THE CAP WAS NOT RESTORED: success=$RUN_OK max_per_day='$(field .output.policy.max_per_day)' — put it back by hand"
fi

# ── G4 the cap is per calling agent ─────────────────────────────────────────
if ! want G4; then
  :
elif [[ -z "$AGENT2_PAYMENT_KEY" || -z "$AGENT2_ACCOUNT" ]]; then
  skip "G4 needs AGENT2_PAYMENT_KEY and AGENT2_ACCOUNT (a second granted agent)"
else
  log "G4 two agents under max_per_day=2: each gets its own allowance"
  # Each agent's counter is its own, so a fresh cap of 2 means 2 for each —
  # but a run earlier today already moved agent 1's counter. Read both first.
  G4_CAP=$(jq -c '.max_per_day = 2' <<<"$CAPPED")
  store_policy "$G4_CAP" "$AGENT2_ACCOUNT"
  g4_send() { # g4_send <who> <key> <n> — one send, echoes ok|refused|other
    gmail "$(jq -nc --arg to "$GMAIL_TEST_TO" --arg s "per-agent cap $RUN $1 #$3" --arg b "G4: the cap is counted per agent" \
      '{operation:"send", to:$to, subject:$s, body:$b}')" "$2"
    if [[ "$RUN_OK" == "true" && -n "$(field .output.message_id)" ]]; then echo ok
    elif grep -qiE "max_per_day|daily|cap|limit" <<<"$RUN_ERR$(field .output.error)"; then echo refused
    else echo "other:$(head -c 100 <<<"$RUN_ERR")"; fi
  }
  gmail '{"operation":"status"}'; G4_A1=$(field .output.sent_today)
  gmail '{"operation":"status"}' "$AGENT2_PAYMENT_KEY"; G4_A2=$(field .output.sent_today)
  note "G4 counters before: agent1=$G4_A1 agent2=$G4_A2"
  # Agent 1 sends until refused; the refusal must come at 2 - sent_today + 1.
  A1_ROOM=$(( 2 - ${G4_A1:-0} )); (( A1_ROOM < 0 )) && A1_ROOM=0
  A1_OK=0; A1_REF=""
  for i in $(seq 1 $(( A1_ROOM + 1 ))); do
    r=$(g4_send agent1 "$AGENT_PAYMENT_KEY" "$i")
    case "$r" in ok) A1_OK=$((A1_OK+1));; refused) A1_REF=$i; break;; *) fail "G4 agent1 send #$i: $r"; break;; esac
  done
  [[ "$A1_OK" == "$A1_ROOM" && -n "$A1_REF" ]] \
    && pass "G4 agent 1 sent its room ($A1_ROOM) and was refused on the next — its own counter" \
    || fail "G4 agent 1: sent $A1_OK of room $A1_ROOM, refused at '${A1_REF:-never}'"
  # Agent 2 is NOT affected by agent 1's spend: it has its own room.
  A2_ROOM=$(( 2 - ${G4_A2:-0} )); (( A2_ROOM < 0 )) && A2_ROOM=0
  A2_OK=0
  for i in $(seq 1 "$A2_ROOM"); do
    r=$(g4_send agent2 "$AGENT2_PAYMENT_KEY" "$i")
    [[ "$r" == ok ]] && A2_OK=$((A2_OK+1)) || { fail "G4 agent2 send #$i: $r — agent 1's spend reached agent 2's counter?"; break; }
  done
  [[ "$A2_OK" == "$A2_ROOM" ]] \
    && pass "G4 agent 2 still had its own room ($A2_ROOM) after agent 1 was capped — counted per agent, as decided" \
    || fail "G4 agent 2 sent $A2_OK of its own room $A2_ROOM"
  store_policy "$CAPPED"
fi

verdict "gmail delegation"
