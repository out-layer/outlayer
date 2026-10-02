#!/usr/bin/env bash
#
# The guessing game of connector-probe, live: a conversation of several turns
# between an agent and its owner, every turn the agent's. The agent's
# `guess_start` picks a number and leaves the owner a task; the owner's page
# answers it with a guess and one signature; the platform starts `guess` as a
# run of the agent, which judges the guess, reports the turn and opens the
# next task of the same thread; the agent follows the game with `task_status`
# on each `next_task_id`. Nobody sends a transaction to answer, and nobody but
# the agent's runs opens a task.
#
# The owner's page is played by `lib/tasks_owner.mjs`: it signs in with the
# owner's wallet key, reads the inbox on a device of its own, seals the guess
# and signs the approval. The suite reads the secret nowhere: it plays by the
# hints, from 1 to `max`, and is right within log2(max) + 1 turns.
#
#   G1   `guess_start` answers awaiting_owner: a task of the agent's in the
#        owner's inbox, the first of its thread, showing the question
#   G2   each turn: the owner's guess, sealed and signed, is approved; the
#        run that acts is the agent's (payment_key_owner); the agent reads the
#        turn done with {attempt, guess, verdict, max, detail} and, while the
#        game goes on, next_task_id; the next task waits in the inbox from the
#        agent, in the same thread, showing the hint
#   G3   the right guess ends the game: done with verdict right and no
#        next_task_id, and a notice in the thread — notice_task_id — that
#        shows the number and the count and asks nothing; the agent reads it
#        open, the owner's Got it closes it, the agent reads it done; nothing
#        more waits
#   G4   the agent's `tasks` lists every turn, and only turns of this thread
#        were made; the owner signed one message per turn
#   N1   the owner's `tasks_unlock` on connector-probe — a build that imports
#        the wallet — starts and answers; it is the owner's one transaction
#
# Needs: PARENT (the owner; its key in ~/.near-credentials/<network>/),
# AGENT_PAYMENT_KEY and AGENT_ACCOUNT (a wallet the owner grants by name).
# CONNECTOR_PROBE names the project (default
# connectors.outlayer.testnet/connector-probe); GUESS_MAX the range (default
# 16, so the game is short). The suite writes the owner's row for the probe,
# profile `connector-probe`, and deletes it and every task it made when it
# ends. The row's secrets are a placeholder: the game reads none.
#
# Run:
#   PARENT=you.testnet AGENT_PAYMENT_KEY=… AGENT_ACCOUNT=… ./tests/guess_game_e2e.sh --apply
#   ONLY=G … --apply      the game alone;  ONLY=N1 … --apply   the unlock row alone
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/hos_common.sh"

PARENT="${PARENT:-}"
AGENT_PAYMENT_KEY="${AGENT_PAYMENT_KEY:-}"
AGENT_ACCOUNT="${AGENT_ACCOUNT:-}"
CONNECTOR_PROBE="${CONNECTOR_PROBE:-connectors.outlayer.testnet/connector-probe}"
PROFILE="${PROFILE:-connector-probe}"
GUESS_MAX="${GUESS_MAX:-16}"
DEPOSIT="${DEPOSIT:-0.1 NEAR}"
ONLY="${ONLY:-}"
want() { [[ -z "$ONLY" ]] || [[ ",$ONLY," == *",$1,"* ]]; }
APPLY=false; [[ "${1:-}" == "--apply" ]] && APPLY=true

if [[ "$APPLY" != true ]]; then
  awk 'NR >= 3 && !/^#/ { exit } NR >= 3' "$0" >&2; echo "  Pass --apply to run." >&2; exit 0
fi
for v in PARENT AGENT_PAYMENT_KEY AGENT_ACCOUNT; do
  [[ -n "${!v}" ]] || { echo "✗ $v is required" >&2; exit 1; }
done
command -v node >/dev/null || { echo "✗ node is required: it plays the owner's page" >&2; exit 1; }
hos_require
PROJECT="$CONNECTOR_PROBE"
source "$SCRIPT_DIR/lib/secrets_common.sh"

OWNER_KEY_FILE="${OWNER_KEY_FILE:-$HOME/.near-credentials/$NETWORK/$PARENT.json}"
[[ -r "$OWNER_KEY_FILE" ]] || { echo "✗ no key file for $PARENT at ~/.near-credentials/$NETWORK/ — the owner's statement is signed with it" >&2; exit 1; }
STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/guess-e2e.XXXXXX")"
chmod 700 "$STATE_DIR"

# The owner's page, the approval and the run it starts: lib/tasks_common.sh.
source "$SCRIPT_DIR/lib/tasks_common.sh"
# agent <input-json> — one call of the probe over HTTPS, paid with the agent's
# key, naming the owner's row. The key reaches curl as a line of its
# configuration on stdin.
HTTP_CODE=""; ANS=""; RUN_OUT=""; RUN_ERR=""; RUN_OK=false
agent() {
  local key body raw
  key="$AGENT_PAYMENT_KEY"
  key=${key//\\/\\\\}; key=${key//\"/\\\"}
  body=$(jq -nc --argjson i "$1" --arg o "$PARENT" --arg pr "$PROFILE" '{input:$i, secrets_ref:{profile:$pr, account_id:$o}}')
  throttle
  raw=$(printf 'header = "X-Payment-Key: %s"\n' "$key" \
    | curl -sS --max-time 90 -K - -w '\nHTTP:%{http_code}' -X POST "$COORDINATOR_URL/call/$CONNECTOR_PROBE" \
        -H 'Content-Type: application/json' --data-binary "$body" 2>&1)
  HTTP_CODE=${raw##*HTTP:}; ANS=${raw%$'\n'HTTP:*}
  RUN_OUT=$(jq -c '.output | if type=="string" then fromjson else . end' <<<"$ANS" 2>/dev/null)
  RUN_ERR=$(jq -r '.error // .message // .status // ""' <<<"$ANS" 2>/dev/null)
  if [[ "$HTTP_CODE" == 2* ]] && [[ "$(jq -r '.status // ""' <<<"$ANS" 2>/dev/null)" == "completed" ]]; then RUN_OK=true; else RUN_OK=false; fi
}
# The probe's answer: {"ok", "operation", "detail", …the task's members}.
said() { jq -r "$1 | if . == null then \"\" else tostring end" <<<"$RUN_OUT" 2>/dev/null; }
status_of() { agent "$(jq -nc --arg t "$1" '{operation:"task_status", task_id:$t}')"; }
# The probe's task_status answer, for the library: the task's members sit
# beside `ok` and `detail`.
task_field() { said "$1"; }

MADE=()
cleanup() {
  local id
  if (( ${#MADE[@]} > 0 )); then
    for id in "${MADE[@]}"; do
      agent "$(jq -nc --arg t "$id" '{operation:"task_delete", task_id:$t}')" >/dev/null 2>&1
    done
  fi
  owner sign-out a >/dev/null 2>&1
  rm -rf "$STATE_DIR"
  delete_row "$CONNECTOR_PROBE" "$PROFILE" >/dev/null 2>&1 || true
}
trap cleanup EXIT

log "setup: the owner's row for $CONNECTOR_PROBE, granted to $AGENT_ACCOUNT by name"
store "$CONNECTOR_PROBE" "$PROFILE" '{"GUESS_GAME":"on"}' "whitelist:$PARENT,$AGENT_ACCOUNT"
owner sign-in a
[[ "$(own .status)" == "200" && "$(own .token_returned)" == "true" ]] || { fail "the owner's sign-in answered $(own .status) $(own .reason)"; verdict "guessing game"; exit 1; }

# ── G1 the game starts ───────────────────────────────────────────────────────
# The game is one row: G (ONLY=G plays it; ONLY=N1 does not).
if ! want G; then
  :
else
log "G1 the agent starts a game of 1 to $GUESS_MAX"
agent "$(jq -nc --argjson m "$GUESS_MAX" '{operation:"guess_start", max:$m}')"
FIRST=$(said .task_id)
if [[ "$RUN_OK" == "true" && "$(said .ok)" == "true" && "$(said .status)" == "awaiting_owner" && -n "$FIRST" ]]; then
  MADE+=("$FIRST")
  pass "G1 awaiting_owner: the task $FIRST, with its hash and link"
  [[ "$(said .thread)" == "$FIRST" ]] && pass "G1 the first task of its thread" || fail "G1 thread '$(said .thread)'"
  if in_inbox "$FIRST"; then
    [[ "$(row .preparer)" == "$AGENT_ACCOUNT" && "$(row .read.envelope.preparer)" == "$AGENT_ACCOUNT" && "$(row .kind)" == "input" ]] \
      && pass "G1 it waits in the owner's inbox, from the agent, asking for text" || fail "G1 in the inbox: $ROW"
    [[ "$(shown Question)" == *"$GUESS_MAX"* ]] && pass "G1 the question names the range: '$(shown Question)'" \
      || fail "G1 the question shown: '$(shown Question)'"
  else
    fail "G1 the task is not in the inbox: $(own .failed | head -c 160)"
  fi
else
  fail "G1 guess_start: run=$RUN_OK HTTP $HTTP_CODE ok='$(said .ok)' detail='$(said .detail | head -c 160)' err='$(head -c 160 <<<"$RUN_ERR")'"
  verdict "guessing game"; exit 1
fi

# ── G2 / G3 the turns ────────────────────────────────────────────────────────
TASK=$FIRST; LOW=1; HIGH=$GUESS_MAX; TURNS=0; SIGNED=0; ENDED_RIGHT=false
MOST_TURNS=$(( $(awk -v m="$GUESS_MAX" 'BEGIN{print int(log(m)/log(2))+2}') ))
while [[ $TURNS -lt $MOST_TURNS ]]; do
  TURNS=$((TURNS + 1))
  GUESS=$(( (LOW + HIGH) / 2 ))
  log "G2 turn $TURNS: the owner guesses $GUESS"
  owner approve "$TASK" "$GUESS" - a
  SIGNED=$((SIGNED + 1))
  if [[ "$(own .status)" != "200" || "$(own .state)" != "approved" || -z "$(own .run)" ]]; then
    fail "G2 turn $TURNS: approve answered $(own .status) state='$(own .state)' reason='$(own .reason)' failure='$(own .failure_reason)' $(own .said)"
    break
  fi
  RUN=$(own .run)
  await_run "$TASK"
  if [[ "$ENDED" != "done" ]]; then
    fail "G2 turn $TURNS ended '$ENDED' (failure_reason '$(said .failure_reason)')"
    break
  fi
  VERDICT=$(said .result.verdict)
  [[ "$(said .result.guess)" == "$GUESS" && "$(said .result.attempt)" == "$TURNS" && "$(said .result.max)" == "$GUESS_MAX" && -n "$(said .result.detail)" ]] \
    && pass "G2 turn $TURNS: done — attempt $TURNS, guess $GUESS, $VERDICT: $(said .result.detail)" \
    || fail "G2 turn $TURNS: the result $(said .result | head -c 200)"
  [[ $TURNS -eq 1 ]] && run_is_the_agents "G2" "$RUN"
  NEXT=$(said .result.next_task_id)
  case "$VERDICT" in
    higher) LOW=$((GUESS + 1)) ;;
    lower) HIGH=$((GUESS - 1)) ;;
    right)
      ENDED_RIGHT=true
      [[ -z "$NEXT" ]] && pass "G3 right in $TURNS turns: no next task" || fail "G3 right, and yet a next task $NEXT"
      TOLD=$(said .result.notice_task_id)
      if [[ -z "$TOLD" ]]; then
        fail "G3 right, and no notice: $(said .result.notice_error | head -c 160)"
      else
        MADE+=("$TOLD")
        if in_inbox "$TOLD"; then
          [[ "$(row .kind)" == "notice" && "$(row .preparer)" == "$AGENT_ACCOUNT" && "$(row .read.envelope.thread)" == "$FIRST" \
             && "$(shown Number)" == "$GUESS" && "$(shown Attempts)" == "$TURNS" \
             && "$(row .read.envelope.display.title)" == "You guessed it: $GUESS, in $TURNS attempt"* ]] \
            && pass "G3 a notice in the thread: $(row .read.envelope.display.title)" \
            || fail "G3 the notice: kind '$(row .kind)' thread '$(row .read.envelope.thread)' title '$(row .read.envelope.display.title)'"
          agent "$(jq -nc --arg t "$TOLD" '{operation:"task_status", task_id:$t}')"
          [[ "$(said .state)" == "open" && "$(said .kind)" == "notice" ]] \
            && pass "G3 the agent reads the notice open" || fail "G3 the notice's status: '$(said .state)' kind '$(said .kind)'"
          owner got-it "$TOLD" a
          agent "$(jq -nc --arg t "$TOLD" '{operation:"task_status", task_id:$t}')"
          [[ "$(own .status)" == "200" && "$(said .state)" == "done" ]] \
            && pass "G3 the owner's Got it: the agent reads it done" \
            || fail "G3 Got it answered $(own .status) $(own .body.reason); the agent reads '$(said .state)'"
        else
          fail "G3 the notice $TOLD is not in the inbox"
        fi
      fi
      break ;;
    *) fail "G2 turn $TURNS: a verdict the suite does not know: '$VERDICT' ($(said .result.next_error))"; break ;;
  esac
  if [[ -z "$NEXT" ]]; then
    fail "G2 turn $TURNS: the game goes on and no next task was opened: $(said .result.next_error | head -c 160)"
    break
  fi
  MADE+=("$NEXT")
  if in_inbox "$NEXT"; then
    [[ "$(row .preparer)" == "$AGENT_ACCOUNT" && "$(row .read.envelope.preparer)" == "$AGENT_ACCOUNT" && "$(row .read.envelope.thread)" == "$FIRST" ]] \
      && pass "G2 the next task waits in the inbox, from the agent, in the thread $FIRST" || fail "G2 the next task: $ROW"
    [[ "$(shown 'Your guess')" == "$GUESS" && "$(shown Answer)" == *"$VERDICT"* && "$(shown Attempts)" == "$TURNS" ]] \
      && pass "G2 it shows the guess, the hint and the attempts so far" \
      || fail "G2 shown: guess '$(shown 'Your guess')' answer '$(shown Answer)' attempts '$(shown Attempts)'"
  else
    fail "G2 the next task $NEXT is not in the inbox"
  fi
  TASK=$NEXT
done
[[ "$ENDED_RIGHT" == true ]] || fail "G3 the game did not end within $MOST_TURNS turns"
owner list a waiting
if ! inbox_listed; then
  fail "G3 the inbox was not read: $(own .failed | head -c 120)"
elif [[ "$(jq -r --arg f "$FIRST" '[.tasks[]? | select(.read.envelope.thread == $f)] | length' <<<"$OWN")" == "0" ]]; then
  pass "G3 nothing of the game waits in the inbox"
else
  fail "G3 tasks of the thread still wait"
fi

# ── G4 the agent's view ──────────────────────────────────────────────────────
log "G4 the agent's tasks"
agent '{"operation":"tasks"}'
LISTED=$(said '[.tasks[]?.task_id] | sort | join(" ")')
EXPECTED=$(printf '%s\n' "${MADE[@]}" | sort | tr '\n' ' ' | sed 's/ $//')
if [[ "$RUN_OK" != "true" || "$(said '.tasks | type')" != "array" ]]; then
  fail "G4 the agent's tasks were not read: run=$RUN_OK detail='$(said .detail | head -c 120)'"
elif [[ "$LISTED" == "$EXPECTED" ]]; then
  pass "G4 the agent's tasks are exactly the ${#MADE[@]} turns of the game"
else
  fail "G4 the agent lists '$LISTED', the game made '$EXPECTED'"
fi
[[ "$SIGNED" == "$TURNS" ]] && pass "G4 the owner signed one message per turn ($SIGNED), and sent no transaction" \
  || fail "G4 signed $SIGNED messages over $TURNS turns"
fi

# ── N1 the owner's one transaction ───────────────────────────────────────────
if want N1; then
  log "N1 the owner's tasks_unlock on a build that imports the wallet"
  run_as "$PARENT" "$PARENT/$PROFILE" '{"operation":"tasks_unlock"}'
  if [[ "$RUN_OK" == "true" && "$(field .ok)" == "true" ]]; then
    pass "N1 the run started with no wallet and answered: $(field .detail | head -c 120)"
  else
    fail "N1 tasks_unlock: run=$RUN_OK ok='$(field .ok)' detail='$(field .detail | head -c 160)' err='$(head -c 160 <<<"$RUN_ERR")'"
  fi
fi

verdict "guessing game"
