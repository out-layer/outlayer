#!/usr/bin/env bash
# The owner's page and the approval flow, shared by the suites that play an
# owner: tasks_e2e.sh, gmail_delegation_e2e.sh, guess_game_e2e.sh. Sourced
# after lib/hos_common.sh, once the suite has set PARENT, OWNER_KEY_FILE,
# STATE_DIR, COORDINATOR_URL, CONTRACT_ID and AGENT_ACCOUNT.
#
# The suite defines two functions of its own, because the connector's answer
# is shaped by the connector:
#   status_of <task>      the agent's `task_status`, leaving the answer where
#                         the suite keeps a run's output
#   task_field <jq-path>  a member of that answer's task, e.g. `.state`,
#                         `.run`, `.failure_reason`, `.result.message_id`
#
# Nothing here prints a secret: the owner's key file reaches the page through
# the environment, and the page prints facts about what it did.

TASKS_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# owner_as <account> <key-file> <command> [args…] — an owner's page; leaves
# its one JSON document in OWN.
OWN=""
owner_as() {
  local account=$1 key_file=$2; shift 2
  throttle
  OWN=$(INBOX_URL="$COORDINATOR_URL" OWNER="$account" OWNER_KEY_FILE="$key_file" RECIPIENT="$CONTRACT_ID" \
        STATE_DIR="$STATE_DIR" node "$TASKS_LIB_DIR/tasks_owner.mjs" "$@" 2>/dev/null)
  [[ -n "$OWN" ]] || OWN='{"failed":"the page gave no answer"}'
}
# owner <command> [args…] — the page of the owner under test.
owner() { owner_as "$PARENT" "$OWNER_KEY_FILE" "$@"; }
own() { jq -r "$1 | if . == null then \"\" else tostring end" <<<"$OWN" 2>/dev/null; }

# inbox_listed — the last `owner list` answered a list. An absence is read as
# one only after this: a page that gave no answer lists nothing too.
inbox_listed() { [[ -z "$(own .failed)" && "$(own '.tasks | type')" == "array" ]]; }

# in_inbox <task> [device] — the task as the owner's page lists it among what
# waits; leaves ROW. False when it is not listed, or the inbox was not read:
# tell the two apart with `inbox_listed`.
ROW=""
in_inbox() {
  owner list "${2:-a}" waiting
  ROW=$(jq -c --arg t "$1" '.tasks[]? | select(.id == $t)' <<<"$OWN" 2>/dev/null)
  [[ -n "$ROW" ]]
}
row() { jq -r "$1 | if . == null then \"\" else tostring end" <<<"$ROW" 2>/dev/null; }
# shown <label> — a field of the task in ROW, by its label.
shown() { jq -r --arg l "$1" '[.read.envelope.display.fields[]? | select(.label == $l)][0].values[0] // ""' <<<"$ROW" 2>/dev/null; }

# gone_from_inbox <row-label> <task> [device] — the inbox was read, and the
# task does not wait in it. A read that failed is a FAIL, never an absence.
gone_from_inbox() {
  owner list "${3:-a}" waiting
  if ! inbox_listed; then
    fail "$1 the inbox was not read: $(own .failed | head -c 120)"; return 1
  fi
  local state
  state=$(jq -r --arg t "$2" '[.tasks[]? | select(.id == $t)] | .[0].state // ""' <<<"$OWN" 2>/dev/null)
  if [[ -z "$state" ]]; then
    pass "$1 the task left what waits"
  else
    fail "$1 the task still waits in the inbox (state '$state')"; return 1
  fi
}

# waiting_ids [device] — the ids of what waits, one line, sorted. When the
# inbox was not read the line is `unread:<random>`: two such lines are never
# equal, so a comparison over them fails rather than passes, and `unread`
# tells the row what happened.
waiting_ids() {
  owner list "${1:-a}" waiting
  if inbox_listed; then
    jq -r '[.tasks[]?.id] | sort | join(" ")' <<<"$OWN" 2>/dev/null
  else
    printf 'unread:%s%s' "$RANDOM" "$RANDOM"
  fi
}

# approves <task> [supplied|-] [note|-] [device] [--flag value…] — the owner's
# approval: one signature of the owner's key, posted; leaves OWN with
# {status, state, run, failure_reason, reason, said}. The flags are the
# helper's, for the rows that sign for the wrong thing.
approves() { owner approve "$@"; }

# await_run <task> [polls] — the agent's `task_status` polled every five
# seconds until the task leaves open/approved/answering, or the polls run
# out; leaves the state in ENDED and the last answer where `status_of` leaves
# it. Not a subshell: the answer is the caller's to read. A run that never
# starts leaves the task approved: the caller fails on the state, and never
# hangs on it.
ENDED=""
await_run() {
  local i
  ENDED=""
  for i in $(seq 1 "${2:-24}"); do
    status_of "$1"
    ENDED=$(task_field .state)
    case "$ENDED" in open|approved|answering|"") sleep 5 ;; *) break ;; esac
  done
}

# approved_and_done <row> <task> [supplied|-] [note|-] [--flag value…] — the
# owner approves and the agent's run carries it out: true when the task ended
# done. Leaves the agent's `task_status` answer and RUN_OF, the run the
# approval started. Flags after the note reach `approves` as they are.
RUN_OF=""
approved_and_done() {
  RUN_OF=""
  approves "$2" "${3:--}" "${4:--}" a "${@:5}"
  if [[ "$(own .status)" != "200" || "$(own .state)" != "approved" || -z "$(own .run)" ]]; then
    fail "$1 approve answered $(own .status) state='$(own .state)' run='$(own .run)' reason='$(own .reason)' failure='$(own .failure_reason)' $(own .said)"
    return 1
  fi
  RUN_OF=$(own .run)
  await_run "$2"
  if [[ "$ENDED" != "done" ]]; then
    fail "$1 the task ended '$ENDED' (failure_reason '$(task_field .failure_reason)', run '$(task_field .run)'), expected done"
    return 1
  fi
  [[ "$(task_field .run)" == "$RUN_OF" ]] || fail "$1 task_status names the run '$(task_field .run)', the approval named $RUN_OF"
  return 0
}

# attestation_of_run <run> [tries] — the public attestation of the call
# `run`, waited for: the worker uploads it as a step of its own after the run
# ends, and the coordinator answers 404 until then. Prints the document, or
# nothing after the tries.
attestation_of_run() {
  local i found
  for i in $(seq 1 "${2:-8}"); do
    found=$(curl -sS --max-time 30 "$COORDINATOR_URL/attestations/by-call/$1" 2>/dev/null)
    if [[ -n "$found" && "$(jq -r 'type' <<<"$found" 2>/dev/null)" == "object" && -n "$(jq -r '.output_hash // ""' <<<"$found" 2>/dev/null)" ]]; then
      printf '%s' "$found"; return 0
    fi
    sleep 10
  done
  return 1
}

# run_is_the_agents <row> <run> [account] [project] — the attestation of the
# run named is a call of that account (the agent's by default), and of that
# project when one is named. A worker that attests nothing is a SKIP, after
# the wait.
run_is_the_agents() {
  local found who=${3:-$AGENT_ACCOUNT} project=${4:-} owner_of project_of
  if ! found=$(attestation_of_run "$2"); then
    skip "$1 the run $2 has no attestation after the wait: whose run it was is not read"; return
  fi
  owner_of=$(jq -r '.payment_key_owner // ""' <<<"$found")
  project_of=$(jq -r '.project_id // ""' <<<"$found")
  if [[ "$owner_of" == "$who" && ( -z "$project" || "$project_of" == "$project" ) ]]; then
    pass "$1 the run that acted was a call of $who${project:+ in $project}"
  else
    fail "$1 the run that acted: payment_key_owner '$owner_of' project '$project_of' caller '$(jq -r '.caller_account_id // ""' <<<"$found")', expected $who${project:+ in $project}"
  fi
}

# an_id <value> — a task id or an account as a statement is built from: the
# suite's own values, held to their shape before they reach SQL.
an_id() { [[ "$1" =~ ^[A-Za-z0-9._-]+$ ]]; }
