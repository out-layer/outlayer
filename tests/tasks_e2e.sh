#!/usr/bin/env bash
#
# Tasks between an agent and its owner, live: an agent's run of `tasks-probe`
# leaves the owner a task, the owner reads it in the inbox with no run and
# acts with a call of their own, and the agent learns the outcome.
#
# The owner's page is played by `lib/tasks_owner.mjs` on WebCrypto: it signs
# in with the owner's wallet key, reads the inbox with a device key of its
# own, opens files, and seals what an owner writes. The agent calls over
# HTTPS with its payment key; the owner acts with a transaction.
#
#   S1   a statement opens one session; the same statement again opens none
#   A1   no session, or a token that is none: 401 session_required, no list
#   A18  what waits on a wallet, without a session: 401; one approval by
#        its id needs none
#   E1   an inbox with nothing: 200 and an empty list
#   F1   the agent prepares: awaiting_owner, and nothing was acted on
#   F3   the owner reads the task; the hash is the one the run answered
#   F4   the proof: the run that made the task is attested, what it answered
#        hashes to the attested hash, and that answer names the task with
#        the hash of what the page opened. The quote itself is verified by
#        the dashboard, not here; a worker that attests nothing is a SKIP
#   F6a  the agent asks: open
#   A7   the agent calls the operation that answers: not_the_owner
#   D8   the owner answers naming a wrong hash: task_hash_mismatch
#   D16  the owner answers through another operation: task_answer_invalid
#   F5   the owner confirms: done, and the task leaves the inbox
#   F6   the agent asks: done, with the result and the run
#   C6   the same answer again: task_closed
#   F13  a file: listed, opened by the owner, handed back on the answer
#   F7   the owner rejects with a reason; the agent reads it as written
#   F8   a turn: what the owner supplied arrives, and the next task opens as the agent's
#   F9   the agent cancels
#   F12  the owner deletes; the agent finds nothing
#   C7   the run that acts traps: failed, with the run
#   F11  the policy changed since: void
#   F10  past its life: expired
#   A10  a row open to everyone: the run works, the task is refused
#   A12  a run that names no row: no_owner
#   A13  a muted agent is refused; unmuted, it opens again
#   D11  a display outside the bounds: display_invalid
#   L3   a life longer than the maximum: task_life_too_long
#   E6   a task never made: task_not_found
#   V1   a device signed in later: locked, and open after tasks_unlock
#   V3   two devices in force read a new task at once; a sixth sign-in
#        retires the first, which is told session_replaced
#   V5   a session's token in another browser lists and opens nothing
#   E9   a list that is whole says so: `more` is false
#   A2   another owner's session: the first owner's task by its id is
#        task_not_found, and is in no list of theirs
#   A5   a second agent of the same owner reads, cancels and deletes nothing
#        of the first's
#   A11  a run whose grant was removed does not start, and no task is made
#   O1   a payment key of the owner's account acts as the owner, and this is
#        the rule: it answers a task over HTTPS. The agent's own key is
#        not_the_owner
#   A13a a mute deletes what waits and keeps outcomes: the agent reads done
#        for the task answered and task_not_found for the one that waited
#   L2   one agent's share: its sixth task is inbox_full, another agent's opens
#   L1   the owner's limit: the twenty-first task is inbox_full from a preparer
#        with room of its own; one answered, one more opens
#   L6   more tasks than one run may open: five open, the sixth is refused
#        task_run_limit
#   K5   the transaction of an answer, read from the chain: the id, the hash
#        and ciphertext, and not the words the owner wrote
#   X1   an answer a contract relayed: relayed, and the task stays open
#   X2   a prepare a contract relayed: relayed, and no task
#   M1   an answer whose run outlasts the caller's connection: answering,
#        then done with its result, never failed. Needs OWNER_PAYMENT_KEY
#   S2   the settings: a project muted by its uuid, listed, unmuted; one
#        device listed, marked `this`
#   W2   a webhook's URL that is not HTTPS, is on a private host, carries
#        credentials, or writes a private address another way: invalid_request
#   W1   an owner who named a URL is told of a task made, answered and
#        expired; a body holds nothing of what the task shows
#   W3   a receiver that answers 307 is not followed: the address it names is
#        sent nothing, and the delivery is recorded as failed with the status
#   A14  a statement signed by a key that is not the account's: invalid_statement
#   A15  a statement signed by a function-call key of the account:
#        invalid_statement. A key removed from the account after sign-in
#        vouches for no copy of the next task, and its session ends
#   A17  a device that signed out: 401 session_required, and no copy of the
#        next task
#   W4   a webhook after a second sign-in: set_here is false, set_by_key and
#        set_at are the first session's
#   W5   naming or removing the webhook without the owner's signature: 403
#        confirmation_required, and nothing changed; with one: 200
#   P9   withdrawing another device without the signature: 403, its session
#        goes on; with it: revoked, and its token is 401 session_required
#   L5   the inbox API called in a loop: 429, with no number and no window.
#        Runs last, and only when asked for by name: ONLY=L5
#
# Needs: PARENT (the owner; its key in ~/.near-credentials/<network>/, and
# the CLI logged in as it), AGENT_PAYMENT_KEY and AGENT_ACCOUNT (a wallet the
# owner grants by name), TASKS_PROBE (the project `connectors/tasks-probe` is
# published under). The suite writes the owner's row for the probe, profile
# `tasks-probe`, and deletes it and every task it made when it ends.
#
# A row whose fixture the environment does not supply is a SKIP:
#   OWNER_B              a second owner, e.g. outlayer-bob.testnet; its key
#                        file is OWNER_B_KEY_FILE, or the one in
#                        ~/.near-credentials/<network>/ (A2)
#   AGENT2_PAYMENT_KEY, AGENT2_ACCOUNT   a second agent wallet (A5, L2, L1)
#   AGENT3_…, AGENT4_…   a third and a fourth (L1: twenty tasks at five a
#                        preparer fill four preparers, and the twenty-first
#                        has to come from a fifth, the owner)
#   OWNER_PAYMENT_KEY    a payment key of the owner's own account (O1)
#   RELAY_CONTRACT       the relay of wasi-examples/test-storage-ark, relaying
#                        to CONTRACT_ID, e.g. relay.outlayer-alice.testnet (X1, X2)
#   HOOK_URL, HOOK_LOG_URL   a public HTTPS receiver that answers 200 and
#                        records what it is sent, and where its log is read
#                        (W1, W3). The log's shape is in lib/tasks_hook.mjs:
#                        [{"method", "headers": {…}, "body"}], or that list
#                        under "requests"
#   HOOK_REDIRECT_URL, HOOK_REDIRECT_LOG_URL   a second receiver, which
#                        answers 307 to HOOK_URL, and its log (W3)
#   PSQL_CMD             one statement of SQL against the coordinator's
#                        database (W3's record of the delivery)
#   WAIT_FOR_RECHECK=1   wait out the two rechecks of a session's key, ten
#                        minutes apart (the second half of A15)
#   IP_WHITELISTED=1     this address is exempt from the limiter (L5 skips)
# A payment key and a receiver's URL are read from the environment where they
# are used, and are neither printed nor put on a command line.
#
# Run:
#   PARENT=you.testnet AGENT_PAYMENT_KEY=… AGENT_ACCOUNT=… TASKS_PROBE=you.testnet/tasks-probe \
#     ./tests/tasks_e2e.sh --apply
#   ONLY=F1,F3,F5 … --apply     some rows; S1 and the setup always run
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/hos_common.sh"

PARENT="${PARENT:-}"
AGENT_PAYMENT_KEY="${AGENT_PAYMENT_KEY:-}"
AGENT_ACCOUNT="${AGENT_ACCOUNT:-}"
TASKS_PROBE="${TASKS_PROBE:-}"
PROFILE="${PROFILE:-tasks-probe}"
DEPOSIT="${DEPOSIT:-0.1 NEAR}"
ONLY="${ONLY:-}"
# M1: how long the slow answer acts, when the caller gives up, and how the
# task's end is waited for. The run outlasts the caller and fits the
# platform's longest run.
M1_RUN_SECONDS="${M1_RUN_SECONDS:-40}"
M1_CALLER_SECONDS="${M1_CALLER_SECONDS:-10}"
M1_POLLS="${M1_POLLS:-12}"
M1_POLL_SECONDS="${M1_POLL_SECONDS:-10}"
want() { [[ -z "$ONLY" ]] || [[ ",$ONLY," == *",$1,"* ]]; }
APPLY=false; [[ "${1:-}" == "--apply" ]] && APPLY=true

if [[ "$APPLY" != true ]]; then
  awk 'NR >= 3 && !/^#/ { exit } NR >= 3' "$0" >&2; echo "  Pass --apply to run." >&2; exit 0
fi
for v in PARENT AGENT_PAYMENT_KEY AGENT_ACCOUNT TASKS_PROBE; do
  [[ -n "${!v}" ]] || { echo "✗ $v is required" >&2; exit 1; }
done
command -v node >/dev/null || { echo "✗ node is required: it plays the owner's page" >&2; exit 1; }
hos_require
PROJECT="$TASKS_PROBE"
source "$SCRIPT_DIR/lib/secrets_common.sh"

OWNER_KEY_FILE="${OWNER_KEY_FILE:-$HOME/.near-credentials/$NETWORK/$PARENT.json}"
[[ -r "$OWNER_KEY_FILE" ]] || { echo "✗ no key file for $PARENT at ~/.near-credentials/$NETWORK/ — the owner's statement is signed with it" >&2; exit 1; }
STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/tasks-e2e.XXXXXX")"
chmod 700 "$STATE_DIR"

# owner_as <account> <key-file> <command> [args…] — an owner's page. Leaves its
# one JSON document in OWN.
OWN=""
owner_as() {
  local account=$1 key_file=$2; shift 2
  throttle
  OWN=$(INBOX_URL="$COORDINATOR_URL" OWNER="$account" OWNER_KEY_FILE="$key_file" RECIPIENT="$CONTRACT_ID" \
        STATE_DIR="$STATE_DIR" node "$SCRIPT_DIR/lib/tasks_owner.mjs" "$@" 2>/dev/null)
  [[ -n "$OWN" ]] || OWN='{"failed":"the page gave no answer"}'
}
# owner <command> [args…] — the page of the owner under test.
owner() { owner_as "$PARENT" "$OWNER_KEY_FILE" "$@"; }
own() { jq -r "$1 | if . == null then \"\" else tostring end" <<<"$OWN" 2>/dev/null; }

# The device the suite signed in last, whose session it cleans up with. An
# account has several devices in force; every one the suite signs in is
# signed out when it ends.
NOW_ON=a
SIGNED_IN=(a)
# sign_in_on <device> [key-file] — a new session, beside the ones in force.
sign_in_on() {
  owner sign-in "$1" ${2:+"$2"}
  [[ "$(own .status)" == "200" ]] || return 1
  NOW_ON=$1
  SIGNED_IN+=("$1")
}

# asked <row> — the row was asked for by name.
asked() { [[ -n "$ONLY" && ",$ONLY," == *",$1,"* ]]; }

what_is() {
  case "$1" in
    OWNER_B) echo "a second owner's account, e.g. outlayer-bob.testnet" ;;
    AGENT[234]_PAYMENT_KEY) echo "the payment key of one more agent wallet" ;;
    AGENT[234]_ACCOUNT) echo "the account of one more agent wallet" ;;
    OWNER_PAYMENT_KEY) echo "a payment key of the owner's own account" ;;
    RELAY_CONTRACT) echo "a relay contract on testnet, e.g. relay.outlayer-alice.testnet" ;;
    HOOK_URL) echo "a public HTTPS receiver that records what it is sent" ;;
    HOOK_LOG_URL) echo "where that receiver's log is read" ;;
    HOOK_REDIRECT_URL) echo "a public HTTPS receiver that answers 307 to HOOK_URL" ;;
    HOOK_REDIRECT_LOG_URL) echo "where the redirecting receiver's log is read" ;;
    *) echo "a fixture" ;;
  esac
}
# lacks <row> <VARIABLE>… — true, with a SKIP, when the environment does not
# supply one of them.
lacks() {
  local row=$1 v; shift
  for v in "$@"; do
    [[ -n "${!v:-}" ]] && continue
    skip "$row needs $v — $(what_is "$v") — which the environment does not supply"
    return 0
  done
  return 1
}

# https_as <VARIABLE holding a payment key> <owner/profile|""> <input-json> —
# one call of the probe over HTTPS, paid with that key. The key reaches curl
# as a line of its configuration on stdin. Judged as `https_post` judges.
https_as() {
  local name=$1 ref=$2 input=$3 key body raw
  key="${!name:?$name is not set: a payment key}"
  key=${key//\\/\\\\}; key=${key//\"/\\\"}
  body=$(jq -nc --argjson i "$input" '{input:$i}')
  if [[ -n "$ref" ]]; then
    body=$(jq -c --arg o "${ref%%/*}" --arg pr "${ref#*/}" '. + {secrets_ref:{profile:$pr, account_id:$o}}' <<<"$body")
  fi
  RUN_RAW=""
  throttle
  raw=$(printf 'header = "X-Payment-Key: %s"\n' "$key" \
    | curl -sS --max-time "${CALLER_SECONDS:-90}" -K - -w '\nHTTP:%{http_code}' -X POST "$COORDINATOR_URL/call/$TASKS_PROBE" \
        -H 'Content-Type: application/json' --data-binary "$body" 2>&1)
  HTTP_CODE=${raw##*HTTP:}; ANS=${raw%$'\n'HTTP:*}
  RUN_OUT=$(jq -c '.output | if type=="string" then fromjson else . end' <<<"$ANS" 2>/dev/null)
  RUN_ERR=$(jq -r '.error // .message // .status // ""' <<<"$ANS" 2>/dev/null)
  if [[ "$HTTP_CODE" == 2* ]] && [[ "$(jq -r '.status // ""' <<<"$ANS" 2>/dev/null)" == "completed" ]]; then
    RUN_OK=true
  elif jq -e . <<<"$ANS" >/dev/null 2>&1; then
    RUN_OK=false
  else
    RUN_OK=absent
    note "no JSON answer (HTTP $HTTP_CODE)"
  fi
}

# agent <input-json> [owner/profile] — the agent calls, naming the owner's row.
agent() { https_as AGENT_PAYMENT_KEY "${2-$PARENT/$PROFILE}" "$1"; }
# acts <input-json> — the owner's own call: a transaction.
acts() { run_as "$PARENT" "$PARENT/$PROFILE" "$1"; }
# The module's answer: {"success", "output", "error"}.
said() { field "$1"; }
code() { local e; e=$(said .error); printf '%s' "${e%%:*}"; }

# expect_refusal <row> <code> — the module answered, and refused by that code.
expect_refusal() {
  if [[ "$(said .success)" == "false" && "$(code)" == "$2" ]]; then
    pass "$1 refused $2"
  else
    fail "$1 expected the refusal $2, got success=$(said .success) error='$(said .error | head -c 160)' run=$RUN_OK/$RUN_ERR"
  fi
}

# prepare_as <owner|VARIABLE holding a payment key> <input-json> — that
# preparer opens a task; leaves TASK and HASH.
TASK=""; HASH=""
prepare_as() {
  local input
  input=$(jq -c '. + {operation:(.operation // "prepare")}' <<<"$2")
  if [[ "$1" == owner ]]; then acts "$input"; else https_as "$1" "$PARENT/$PROFILE" "$input"; fi
  TASK=$(said .output.task_id); HASH=$(said .output.task_hash)
  [[ "$(said .output.status)" == "awaiting_owner" && -n "$TASK" ]]
}
# prepare <input-json> — the agent prepares.
prepare() { prepare_as AGENT_PAYMENT_KEY "$1"; }
# fill <preparer> <count> <title> — that many tasks of one preparer; true when
# every one opened.
fill() {
  local opened=0 i
  for i in $(seq 1 "$2"); do
    prepare_as "$1" "$(jq -nc --arg t "$3 $i" '{title:$t}')" && opened=$((opened + 1))
  done
  [[ "$opened" == "$2" ]]
}
status_of() { agent "$(jq -nc --arg t "$1" '{operation:"task_status", task_id:$t}')"; }
# in_inbox <task> [device] — the task as the owner's page lists it; leaves ROW.
ROW=""
in_inbox() {
  owner list "${2:-a}" waiting
  ROW=$(jq -c --arg t "$1" '.tasks[]? | select(.id == $t)' <<<"$OWN" 2>/dev/null)
  [[ -n "$ROW" ]]
}
row() { jq -r "$1 | if . == null then \"\" else tostring end" <<<"$ROW" 2>/dev/null; }
# waiting_ids [device] — the ids of what waits, one line.
waiting_ids() {
  owner list "${1:-a}" waiting
  jq -r '[.tasks[]?.id] | sort | join(" ")' <<<"$OWN" 2>/dev/null
}

# clear_tasks — every task of the owner deleted, so that a row starts with
# the agent's share empty. Through the device signed in last, or a new one when
# that session is over.
clear_tasks() {
  owner raw DELETE /inbox/tasks "" "$NOW_ON"
  [[ "$(own .status)" == "200" ]] && return 0
  sign_in_on cleared && owner raw DELETE /inbox/tasks "" cleared
}

# ── the chain ────────────────────────────────────────────────────────────────

# The keyed RPC URL reaches curl on stdin, never on a command line.
rpc_post() { # rpc_post <json-body>
  printf 'url = "%s"\n' "$RPC_URL" | curl -sS --max-time 45 -K - -X POST \
    -H 'Content-Type: application/json' --data-binary "$1" 2>/dev/null
}
tx_of() { grep -oE 'Transaction ID: *[1-9A-HJ-NP-Za-km-z]{40,50}' <<<"$1" | grep -oE '[1-9A-HJ-NP-Za-km-z]{40,50}' | head -1; }
tx_read() { # tx_read <hash> <signer> — the transaction, final
  rpc_post "$(jq -nc --arg t "$1" --arg s "$2" \
    '{jsonrpc:"2.0",id:1,method:"tx",params:{tx_hash:$t,sender_account_id:$s,wait_until:"FINAL"}}')"
}

# key_on_chain <account> <public key> — full, function, absent, or unknown
# when the chain did not say.
key_on_chain() {
  local said
  said=$(rpc_post "$(jq -nc --arg a "$1" --arg k "$2" \
    '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"view_access_key",finality:"final",account_id:$a,public_key:$k}}')" \
    | jq -r 'if .result.permission == "FullAccess" then "full"
             elif (.result.permission | type) == "object" and (.result.permission | has("FunctionCall")) then "function"
             elif (.error.cause.name // "") == "UNKNOWN_ACCESS_KEY" then "absent"
             elif ((.result.error // "") | test("does not exist")) then "absent"
             else "unknown" end' 2>/dev/null)
  printf '%s' "${said:-unknown}"
}
wait_key() { # wait_key <account> <public key> <full|function|absent>
  local i
  for i in $(seq 1 20); do
    [[ "$(key_on_chain "$1" "$2")" == "$3" ]] && return 0
    sleep 3
  done
  return 1
}
# The keys this suite added to the owner's account and has not removed yet.
ADDED_KEYS=""
WHY=""
add_key() { # add_key <full|function> <public key> — leaves WHY when it was refused
  local out rc
  if [[ "$1" == full ]]; then
    out=$(near --quiet account add-key "$PARENT" grant-full-access \
      use-manually-provided-public-key "$2" network-config "$NETWORK" sign-with-keychain send 2>&1); rc=$?
  else
    out=$(near --quiet account add-key "$PARENT" grant-function-call-access --allowance '0.1 NEAR' \
      --contract-account-id "$CONTRACT_ID" --function-names 'request_execution' \
      use-manually-provided-public-key "$2" network-config "$NETWORK" sign-with-keychain send 2>&1); rc=$?
  fi
  if [[ $rc -ne 0 ]]; then WHY=$(near_why "$out"); return 1; fi
  ADDED_KEYS="$ADDED_KEYS $2"
  wait_key "$PARENT" "$2" "$1" || { WHY="the key is not on the account as a $1 key after a minute"; return 1; }
}
remove_key() { # remove_key <public key>
  local out rc
  out=$(near --quiet account delete-keys "$PARENT" public-keys "$1" \
    network-config "$NETWORK" sign-with-keychain send 2>&1); rc=$?
  if [[ $rc -ne 0 ]]; then WHY=$(near_why "$out"); return 1; fi
  ADDED_KEYS=${ADDED_KEYS// $1/}
  wait_key "$PARENT" "$1" absent || { WHY="the key is still on the account after a minute"; return 1; }
}

# relayed <input-json> — the owner signs a transaction to the relay, and the
# relay asks OutLayer for the run: the account that called is the relay, the
# account that signed is the owner. Judged as `run_as` judges; the event is
# read from the transaction when the send's transcript does not hold it.
relayed() {
  local args out tx logs="" ev i
  RUN_OK=absent; RUN_ERR=""; RUN_OUT=""
  args=$(jq -nc --arg p "$TASKS_PROBE" --arg i "$1" --arg o "$PARENT" --arg pr "$PROFILE" \
    '{source:{Project:{project_id:$p}}, input_data:$i, secrets_ref:{profile:$pr, account_id:$o},
      resource_limits:{max_instructions:1000000000,max_memory_mb:128,max_execution_seconds:30}}')
  out=$(near contract call-function as-transaction "$RELAY_CONTRACT" relay json-args "$args" \
    prepaid-gas '300.0 Tgas' attached-deposit "$DEPOSIT" \
    sign-as "$PARENT" network-config "$NETWORK" sign-with-keychain send 2>&1)
  RUN_RAW="$out"
  ev=$(grep -o 'EVENT_JSON:.*execution_completed.*' <<<"$out" | sed 's/^EVENT_JSON://' | head -1)
  tx=$(tx_of "$out")
  if [[ -z "$ev" && -n "$tx" ]]; then
    for i in $(seq 1 20); do
      logs=$(tx_read "$tx" "$PARENT")
      ev=$(jq -r '[.result.receipts_outcome[]?.outcome.logs[]?] | join("\n")' <<<"$logs" 2>/dev/null \
        | grep -o 'EVENT_JSON:.*execution_completed.*' | sed 's/^EVENT_JSON://' | head -1)
      [[ -n "$ev" ]] && break
      jq -e '[.result.receipts_outcome[]?.outcome.status | select(has("Failure"))] | length > 0' <<<"$logs" >/dev/null 2>&1 && break
      sleep 6
    done
  fi
  if [[ -z "$ev" ]]; then
    note "no completion event from the relayed run: $(near_why "$out")"
    return 0
  fi
  RUN_OK=$(jq -r '.data[0] | if has("success") then (.success|tostring) else "absent" end' <<<"$ev" 2>/dev/null)
  RUN_ERR=$(jq -r '.data[0].error_message // ""' <<<"$ev" 2>/dev/null)
  RUN_OUT=$(awk '/Function execution return value/{f=1; next} f && /^The "/{exit} f{print}' <<<"$out" \
    | jq -c 'select(. != null) | if type=="string" then fromjson else . end' 2>/dev/null)
  if [[ -z "$RUN_OUT" && -n "$logs" ]]; then
    RUN_OUT=$(jq -r '.result.status.SuccessValue // empty | @base64d' <<<"$logs" 2>/dev/null \
      | jq -c 'select(. != null) | if type=="string" then fromjson else . end' 2>/dev/null)
  fi
}
# The relay is usable when it relays to the contract under test.
relay_lacks() { # relay_lacks <row>
  lacks "$1" RELAY_CONTRACT && return 0
  local target
  target=$(near_view "$RELAY_CONTRACT" outlayer '{}' | tr -d '"')
  [[ "$target" == "$CONTRACT_ID" ]] && return 1
  skip "$1 needs a relay that relays to $CONTRACT_ID; $RELAY_CONTRACT names '${target:-nothing readable}'"
  return 0
}

# ── the receiver of events ───────────────────────────────────────────────────

# hook_log <VARIABLE holding the URL of a receiver's log> [needle…] — what the
# receiver was sent, in HOOK: the events, and the needles found in a body.
HOOK=""
hook_log() {
  local name=$1; shift
  HOOK=$(HOOK_LOG_URL="${!name:?$name is not set: the URL the log of a receiver is read at}" \
         node "$SCRIPT_DIR/lib/tasks_hook.mjs" events "$@" 2>/dev/null)
  [[ -n "$HOOK" ]] || HOOK='{"failed":"the log gave no answer"}'
}
# told <VARIABLE> <event> <task> <tries> [needle…] — waits, ten seconds a try,
# for that event of that task; leaves it in EVENT.
EVENT=""
told() {
  local name=$1 event=$2 task=$3 tries=$4 i; shift 4
  EVENT=""
  for i in $(seq 1 "$tries"); do
    hook_log "$name" "$@"
    EVENT=$(jq -c --arg e "$event" --arg t "$task" '[.events[]? | select(.type == $e and .task_id == $t)][0] // empty' <<<"$HOOK" 2>/dev/null)
    [[ -n "$EVENT" ]] && return 0
    [[ "$i" == "$tries" ]] || sleep 10
  done
  return 1
}
event() { jq -r "$1 | if . == null then \"\" else tostring end" <<<"$EVENT" 2>/dev/null; }
# The names an event's body may hold: who asked whom, of what kind and when.
EVENT_MEMBERS="expires_at kind link owner preparer project_id project_uuid run state task_id type"
# judge_event <row> <event> — the event in EVENT says who asked whom, is
# signed, and holds no member beyond the ones an event has.
judge_event() {
  local extra
  extra=$(jq -r --arg known "$EVENT_MEMBERS" '.members - ($known | split(" ")) | join(" ")' <<<"$EVENT" 2>/dev/null)
  if [[ "$(event .owner)" == "$PARENT" && "$(event .preparer)" == "$AGENT_ACCOUNT" \
        && "$(event .signed)" == "true" && "$(event .wallet_id)" == "owner:$PARENT" \
        && "$(event .event_type)" == "$2" && -z "$extra" ]]; then
    pass "$1 $2: who asked whom, signed, sent as owner:$PARENT, and nothing else"
  else
    fail "$1 $2: owner=$(event .owner) preparer=$(event .preparer) signed=$(event .signed) sent as '$(event .wallet_id)' header '$(event .event_type)' unknown members '$extra'"
  fi
}
HOOK_NAMED=false
PROJECT_UUID=""

POLICY_V1='{"v":1}'
# The access is written as the contract holds it (`whitelist` above, or
# `"AllowAll"`) and handed to the CLI in the CLI's spelling.
store_row() { # store_row <policy-json> <access-json>
  local access
  access=$(jq -r 'if . == "AllowAll" then "allow-all"
                  elif has("Whitelist") then "whitelist:" + (.Whitelist.accounts | join(","))
                  else error("an access the suite does not spell: \(.)") end' <<<"$2") || exit 1
  store "$TASKS_PROBE" "$PROFILE" "$(jq -nc --arg p "$1" '{TASKS_PROBE_POLICY:$p}')" "$access"
}
# Every agent the environment supplies is granted by name.
GRANTED=$(whitelist "$PARENT" "$AGENT_ACCOUNT" ${AGENT2_ACCOUNT:+"$AGENT2_ACCOUNT"} \
  ${AGENT3_ACCOUNT:+"$AGENT3_ACCOUNT"} ${AGENT4_ACCOUNT:+"$AGENT4_ACCOUNT"})

cleanup() {
  local key
  for key in $ADDED_KEYS; do remove_key "$key" >/dev/null 2>&1 || true; done
  # When the device signed in last is gone — signed out, or retired by a row
  # that signed in one too many — a new sign-in is what reaches the owner's
  # tasks.
  owner raw DELETE /inbox/tasks "" "$NOW_ON" >/dev/null 2>&1
  if [[ "$(own .status)" != "200" ]]; then
    sign_in_on swept >/dev/null 2>&1 && owner raw DELETE /inbox/tasks "" swept >/dev/null 2>&1
  fi
  [[ "$HOOK_NAMED" == true ]] && owner webhook delete "$NOW_ON" >/dev/null 2>&1
  # A row that stopped between a mute and its unmute leaves no mute behind.
  owner unmute agent "$AGENT_ACCOUNT" "$NOW_ON" >/dev/null 2>&1
  [[ -n "$PROJECT_UUID" ]] && owner unmute project "$PROJECT_UUID" "$NOW_ON" >/dev/null 2>&1
  local device
  for device in "${SIGNED_IN[@]}"; do
    owner sign-out "$device" >/dev/null 2>&1
  done
  rm -rf "$STATE_DIR"
  delete_row "$TASKS_PROBE" "$PROFILE" >/dev/null 2>&1 || true
}
trap cleanup EXIT

log "setup: the owner's row for $TASKS_PROBE, granted to $AGENT_ACCOUNT by name"
store_row "$POLICY_V1" "$GRANTED"

# ── the session ──────────────────────────────────────────────────────────────

log "S1 a statement opens one session"
owner sign-in a
if [[ "$(own .status)" == "200" && "$(own .token_returned)" == "true" && "$(own .account_id)" == "$PARENT" ]]; then
  pass "S1 the owner signed in on a device"
else
  fail "S1 sign-in answered $(own .status): $(own '.error // .failed' | head -c 200)"
  verdict "tasks"; exit $?
fi
owner replay a
[[ "$(own .status)" == "400" && "$(own .reason)" == "invalid_statement" ]] \
  && pass "S1 the same statement again opens no session" \
  || fail "S1 a replayed statement answered $(own .status) $(own .reason)"
owner raw DELETE /inbox/tasks "" a

if want A1; then
  log "A1 without a session nothing is told"
  for who in none garbage; do
    owner raw GET /inbox/tasks "" "$who"
    if [[ "$(own .status)" == "401" && "$(own .body.reason)" == "session_required" && "$(own '.body | has("tasks")')" == "false" ]]; then
      pass "A1 ($who) 401 session_required, and no list"
    else
      fail "A1 ($who) answered $(own .status) $(own .body.reason) $(own .body | head -c 120)"
    fi
  done
fi

if want A18; then
  log "A18 what waits on a wallet is listed inside a session; one approval is told by its id"
  owner raw GET "/wallet/v1/pending_approvals_by_pubkey?near_pubkey=ed25519:11111111111111111111111111111111" "" none
  [[ "$(own .status)" == "401" && "$(own .body.error)" == "session_required" ]] \
    && pass "A18 the list without a session: 401 session_required" \
    || fail "A18 the list without a session answered $(own .status) $(own .body.error)"
  owner raw GET "/wallet/v1/approval/00000000-0000-4000-8000-000000000000" "" none
  [[ "$(own .status)" == "404" ]] \
    && pass "A18 one approval is asked for with no session: an id that is none is 404" \
    || fail "A18 an unknown approval without a session answered $(own .status)"
fi

if want E1; then
  log "E1 an inbox with nothing"
  owner raw GET /inbox/tasks "" a
  [[ "$(own .status)" == "200" && "$(own '.body.tasks | length')" == "0" ]] \
    && pass "E1 200 and an empty list" \
    || fail "E1 answered $(own .status) $(own .body | head -c 120)"
fi

# ── the flow ─────────────────────────────────────────────────────────────────

if want F1 || want F3 || want F5 || want F6 || want F6a || want A7 || want D8 || want D16 || want C6; then
  log "F1 the agent prepares"
  if prepare '{"title":"Send an email","body":"Hello Bob, the report is attached."}'; then
    pass "F1 awaiting_owner, task $TASK"
    [[ "$(said .output.devices)" == "1" ]] && pass "F1 one device of the owner reads it at once" \
      || fail "F1 devices: $(said .output.devices), expected 1"
  else
    fail "F1 prepare answered success=$(said .success) error='$(said .error | head -c 200)' run=$RUN_OK/$RUN_ERR"
  fi
  FLOW_TASK=$TASK; FLOW_HASH=$HASH

  if [[ -n "$FLOW_TASK" ]]; then
    log "F3 the owner reads it, with no run"
    if in_inbox "$FLOW_TASK" && [[ "$(row .read.hash)" == "$FLOW_HASH" ]]; then
      pass "F3 the hash of what the page opened is the one the run answered"
      [[ "$(row .read.envelope.display.title)" == "Send an email" && "$(row '.read.envelope.display.fields[0].values[0]')" == "Hello Bob, the report is attached." ]] \
        && pass "F3 what is shown is what the agent prepared" \
        || fail "F3 shown: $(row .read.envelope.display | head -c 200)"
      [[ "$(row .read.envelope.owner)" == "$PARENT" && "$(row .read.envelope.preparer)" == "$AGENT_ACCOUNT" ]] \
        && pass "F3 addressed to the owner, prepared by the agent" \
        || fail "F3 owner/preparer: $(row .read.envelope.owner) / $(row .read.envelope.preparer)"
    else
      fail "F3 the task is not read in the inbox: $(row '.unread // "not listed"') (hash $(row .read.hash) vs $FLOW_HASH)"
    fi

    if want F4; then
      log "F4 the proof"
      owner proof "$FLOW_TASK" a
      if [[ "$(own .attested)" == "false" ]]; then
        skip "F4 the run $(own .run) has no attestation: this worker attests nothing, so the proof is unproven by this run"
      elif [[ "$(own .attested)" == "true" ]]; then
        [[ "$(own .project_matches)" == "true" && -n "$(own .build)" ]] \
          && pass "F4 the attested run was of $TASKS_PROBE, and names the build that ran" \
          || fail "F4 the attested run: project_matches=$(own .project_matches) build='$(own .build)'"
        [[ "$(own .output_kept)" == "true" && "$(own .answer_matches)" == "true" ]] \
          && pass "F4 what the run answered hashes to the attested hash" \
          || fail "F4 the answer: kept=$(own .output_kept) matches=$(own .answer_matches)"
        [[ "$(own .names_task)" == "true" && "$(own .names_another_hash)" == "false" ]] \
          && pass "F4 the answer names this task with the hash of what the page opened, and with no other" \
          || fail "F4 the answer names the task: $(own .names_task), another hash: $(own .names_another_hash)"
        BUILD=$(own .build)
        VERSION=$(near_view "$CONTRACT_ID" get_version "$(jq -nc --arg p "$TASKS_PROBE" --arg v "$BUILD" '{project_id:$p, version_key:$v}')" 2>/dev/null)
        [[ "$(jq -r '.source.WasmUrl.hash // ""' <<<"$VERSION" 2>/dev/null)" == "$BUILD" ]] \
          && pass "F4 the build that ran is a version of the project on the contract" \
          || fail "F4 the build $BUILD is not a version of $TASKS_PROBE on the contract"
      else
        fail "F4 the proof could not be read: $(own .failed | head -c 200)"
      fi
    fi

    log "F6a the agent asks"
    status_of "$FLOW_TASK"
    [[ "$(said .output.state)" == "open" ]] && pass "F6a open" || fail "F6a state '$(said .output.state)' error='$(said .error)'"

    log "A7 the agent calls the operation that answers"
    agent "$(jq -nc --arg t "$FLOW_TASK" --arg h "$FLOW_HASH" '{operation:"confirm", task_id:$t, task_hash:$h}')"
    expect_refusal A7 not_the_owner

    log "D8 the owner answers naming a wrong hash"
    acts "$(jq -nc --arg t "$FLOW_TASK" '{operation:"confirm", task_id:$t, task_hash:("0"*64)}')"
    expect_refusal D8 task_hash_mismatch

    log "D16 the owner answers through another operation"
    acts "$(jq -nc --arg t "$FLOW_TASK" --arg h "$FLOW_HASH" '{operation:"supply", task_id:$t, task_hash:$h}')"
    expect_refusal D16 task_answer_invalid
    status_of "$FLOW_TASK"
    [[ "$(said .output.state)" == "open" ]] && pass "A7/D8/D16 left the task open" \
      || fail "after three refused answers the task is '$(said .output.state)'"

    log "F5 the owner confirms"
    acts "$(jq -nc --arg t "$FLOW_TASK" --arg h "$FLOW_HASH" '{operation:"confirm", task_id:$t, task_hash:$h}')"
    if [[ "$(said .output.status)" == "done" && "$(said .output.result.acted_on.body)" == "Hello Bob, the report is attached." ]]; then
      pass "F5 acted on exactly what was prepared"
    else
      fail "F5 confirm answered success=$(said .success) error='$(said .error | head -c 200)' run=$RUN_OK/$RUN_ERR"
    fi
    in_inbox "$FLOW_TASK" && [[ "$(row .state)" == "open" ]] \
      && fail "F5 the task still waits in the inbox" || pass "F5 the task left what waits"
    owner list a closed
    CLOSED=$(jq -c --arg t "$FLOW_TASK" '.tasks[]? | select(.id == $t)' <<<"$OWN")
    [[ "$(jq -r .state <<<"$CLOSED")" == "done" && "$(jq -r .has_content <<<"$CLOSED")" == "false" && "$(jq -r .has_copy <<<"$CLOSED")" == "false" ]] \
      && pass "F5/K2 closed as done, and what it showed is gone" \
      || fail "F5/K2 closed row: $CLOSED"

    log "F6 the agent asks"
    status_of "$FLOW_TASK"
    [[ "$(said .output.state)" == "done" && -n "$(said .output.run)" && "$(said .output.result.prepared_by)" == "$AGENT_ACCOUNT" ]] \
      && pass "F6 done, with the result and the run $(said .output.run)" \
      || fail "F6 status: $(said .output | head -c 240) error='$(said .error)'"

    log "C6 the same answer again"
    acts "$(jq -nc --arg t "$FLOW_TASK" --arg h "$FLOW_HASH" '{operation:"confirm", task_id:$t, task_hash:$h}')"
    expect_refusal C6 task_closed
  fi
fi

if want F13; then
  log "F13 a file"
  if prepare '{"title":"A report","files":[{"name":"report.pdf","content_type":"application/pdf","text":"%PDF-1.7 0123456","repeat":65536}]}'; then
    in_inbox "$TASK"
    [[ "$(row '.read.envelope.files[0].name')" == "report.pdf" && "$(row '.read.envelope.files[0].size')" == "1048576" ]] \
      && pass "F13 the file is listed by name and size" || fail "F13 files listed: $(row .read.envelope.files)"
    owner file "$TASK" 0 a
    [[ "$(own .size)" == "1048576" && "$(own .starts)" == "%PDF-1.7 0123456" ]] \
      && pass "F13 the owner opened it, and it is the file the task names" \
      || fail "F13 opening the file: $(own . | head -c 200)"
    acts "$(jq -nc --arg t "$TASK" --arg h "$(row .read.hash)" '{operation:"confirm", task_id:$t, task_hash:$h}')"
    [[ "$(said '.output.result.files[0].bytes')" == "1048576" ]] \
      && pass "F13 the operation that acts got it back whole" \
      || fail "F13 confirm: success=$(said .success) error='$(said .error | head -c 200)' files=$(said .output.result.files)"
    owner raw GET "/inbox/tasks/$TASK/files/0" "" a
    [[ "$(own .status)" == "404" ]] && pass "F13/K2 the file is gone with the answer" || fail "F13/K2 the file still answers $(own .status)"
  else
    fail "F13 prepare with a file: error='$(said .error | head -c 200)'"
  fi
fi

if want F7; then
  log "F7 the owner rejects with a reason"
  if prepare '{"title":"To be rejected"}'; then
    REASON="не тому адресату — wrong recipient"
    owner reject "$TASK" "$REASON" a
    [[ "$(own .status)" == "200" && "$(own .body.state)" == "rejected" ]] && pass "F7 rejected, with no run" \
      || fail "F7 reject answered $(own .status) $(own .body | head -c 160)"
    status_of "$TASK"
    [[ "$(said .output.state)" == "rejected" && "$(said .output.reason)" == "$REASON" ]] \
      && pass "F7 the agent reads the reason as written" \
      || fail "F7 status: $(said .output | head -c 240)"
    owner reject "$TASK" "" a
    [[ "$(own .status)" == "409" && "$(own .body.reason)" == "task_closed" ]] && pass "F7 a second rejection: 409 task_closed" \
      || fail "F7 a second rejection answered $(own .status) $(own .body.reason)"
  else
    fail "F7 prepare: error='$(said .error | head -c 200)'"
  fi
fi

if want F8; then
  log "F8 a turn"
  if prepare '{"title":"Give me your photo","kind":"file","again":true}'; then
    FIRST=$TASK
    in_inbox "$FIRST"
    owner seal "$FIRST" answer "ipfs://photo#sha256=abc" a
    SEALED=$(own .sealed)
    acts "$(jq -nc --arg t "$FIRST" --arg h "$(row .read.hash)" --arg s "$SEALED" '{operation:"supply", task_id:$t, task_hash:$h, supplied:$s}')"
    [[ "$(said .output.result.supplied)" == "ipfs://photo#sha256=abc" ]] && pass "F8 what the owner supplied reached the project" \
      || fail "F8 supply: success=$(said .success) error='$(said .error | head -c 200)'"
    NEXT=$(said .output.next.task_id)
    [[ "$(said .output.next.status)" == "awaiting_owner" && "$(said .output.next.thread)" == "$FIRST" ]] \
      && pass "F8 the turn opened the next task of the same conversation" \
      || fail "F8 next: $(said .output.next)"
    # A turn keeps the conversation's preparer: the next task is the agent's,
    # sealed and listed so, though the owner's run opened it.
    in_inbox "$NEXT" && [[ "$(row .read.envelope.thread)" == "$FIRST" && "$(row .preparer)" == "$AGENT_ACCOUNT" \
        && "$(row .read.envelope.preparer)" == "$AGENT_ACCOUNT" ]] \
      && pass "F8 the next task waits in the inbox, from the agent" || fail "F8 the next task in the inbox: $ROW"
    status_of "$NEXT"
    [[ "$(said .output.state)" == "open" ]] && pass "F8 the agent's task_status reads the turn open" \
      || fail "F8 the agent's status of the turn: '$(said .output.state)' error='$(said .error | head -c 200)'"
  else
    fail "F8 prepare: error='$(said .error | head -c 200)'"
  fi
fi

if want F9; then
  log "F9 the agent cancels"
  if prepare '{"title":"To be withdrawn"}'; then
    agent "$(jq -nc --arg t "$TASK" '{operation:"task_cancel", task_id:$t}')"
    [[ "$(said .output.state)" == "cancelled" ]] && pass "F9 cancelled" || fail "F9 cancel: error='$(said .error)'"
    in_inbox "$TASK" && fail "F9 the task still waits in the inbox" || pass "F9 gone from what waits"
  else
    fail "F9 prepare: error='$(said .error | head -c 200)'"
  fi
fi

if want F12; then
  log "F12 the owner deletes"
  if prepare '{"title":"To be deleted"}'; then
    owner delete "$TASK" a
    [[ "$(own .status)" == "200" && "$(own .body.deleted)" == "1" ]] && pass "F12 deleted" || fail "F12 delete answered $(own .status)"
    status_of "$TASK"
    expect_refusal F12 task_not_found
  else
    fail "F12 prepare: error='$(said .error | head -c 200)'"
  fi
fi

if want C7; then
  log "C7 the run that acts traps"
  if prepare '{"title":"A run that traps","answer_by":"confirm_trap"}'; then
    in_inbox "$TASK"
    acts "$(jq -nc --arg t "$TASK" --arg h "$(row .read.hash)" '{operation:"confirm_trap", task_id:$t, task_hash:$h}')"
    [[ "$RUN_OK" != "true" ]] && pass "C7 the run failed" || fail "C7 the run that traps reported success"
    status_of "$TASK"
    [[ "$(said .output.state)" == "failed" && -n "$(said .output.run)" && -z "$(said .output.result)" ]] \
      && pass "C7 failed, with the run and no result" || fail "C7 status: $(said .output | head -c 240)"
    in_inbox "$TASK" && [[ "$(row .state)" == "open" ]] && fail "C7 the task reopened" || pass "C7 the task did not reopen"
  else
    fail "C7 prepare: error='$(said .error | head -c 200)'"
  fi
fi

if want F11; then
  log "F11 the policy changed since"
  if prepare '{"title":"Made under the old policy"}'; then
    in_inbox "$TASK"; OLD_HASH=$(row .read.hash)
    store_row '{"v":2}' "$GRANTED"
    acts "$(jq -nc --arg t "$TASK" --arg h "$OLD_HASH" '{operation:"confirm", task_id:$t, task_hash:$h}')"
    expect_refusal F11 task_void
    status_of "$TASK"
    [[ "$(said .output.state)" == "void" ]] && pass "F11 void to the agent" || fail "F11 status '$(said .output.state)'"
    store_row "$POLICY_V1" "$GRANTED"
  else
    fail "F11 prepare: error='$(said .error | head -c 200)'"
  fi
fi

if want F10; then
  log "F10 past its life"
  if prepare '{"title":"Short-lived","life_seconds":20}'; then
    in_inbox "$TASK"; SHORT_HASH=$(row .read.hash)
    note "waiting out the task's 20 seconds"
    sleep 25
    status_of "$TASK"
    [[ "$(said .output.state)" == "expired" ]] && pass "F10 expired to the agent" || fail "F10 status '$(said .output.state)'"
    in_inbox "$TASK" && fail "F10 an expired task still waits" || pass "F10 gone from what waits"
    acts "$(jq -nc --arg t "$TASK" --arg h "$SHORT_HASH" '{operation:"confirm", task_id:$t, task_hash:$h}')"
    expect_refusal F10 task_expired
  else
    fail "F10 prepare: error='$(said .error | head -c 200)'"
  fi
fi

# ── who may ──────────────────────────────────────────────────────────────────

if want A10; then
  log "A10 a row open to everyone"
  store_row "$POLICY_V1" '"AllowAll"'
  agent '{"operation":"tasks"}'
  [[ "$(said .success)" == "true" ]] && pass "A10 the run works" || fail "A10 the run on an open row: error='$(said .error)' run=$RUN_OK/$RUN_ERR"
  agent '{"operation":"prepare"}'
  expect_refusal A10 not_granted_by_name
  store_row "$POLICY_V1" "$GRANTED"
fi

if want A12; then
  log "A12 a run that names no row"
  agent '{"operation":"prepare"}' ""
  expect_refusal A12 no_owner
fi

if want A13; then
  log "A13 a muted agent"
  owner mute agent "$AGENT_ACCOUNT" a
  [[ "$(own .status)" == "200" ]] || fail "A13 mute answered $(own .status)"
  agent '{"operation":"prepare"}'
  expect_refusal A13 muted
  owner unmute agent "$AGENT_ACCOUNT" a
  prepare '{"title":"After the mute"}' && pass "A13 unmuted, it opens again" || fail "A13 after unmute: error='$(said .error | head -c 200)'"
fi

# ── refused before anything is made ──────────────────────────────────────────

if want D11; then
  log "D11 a display outside the bounds"
  agent "$(jq -nc '{operation:"prepare_raw", display:{title:("x"*81), fields:[]}}')"
  expect_refusal D11 display_invalid
  agent "$(jq -nc '{operation:"prepare_raw", display:{title:"Pay", fields:[{label:"To", kind:"address", value:"evil‮moc.knab"}]}}')"
  expect_refusal D12a display_invalid
fi

if want L3; then
  log "L3 a life longer than the maximum"
  agent '{"operation":"prepare","life_seconds":86401}'
  expect_refusal L3 task_life_too_long
fi

if want E6; then
  log "E6 a task never made"
  status_of "00000000-0000-4000-8000-000000000000-0"
  expect_refusal E6 task_not_found
  status_of "../x"
  expect_refusal D10 task_not_found
fi

if want E9; then
  log "E9 a list that is whole says so"
  for show in waiting closed; do
    owner raw GET "/inbox/tasks?show=$show" "" a
    [[ "$(own .status)" == "200" && "$(own '.body.tasks | type')" == "array" && "$(own .body.more)" == "false" ]] \
      && pass "E9 ($show) the list, and more: false" \
      || fail "E9 ($show) answered $(own .status), tasks a $(own '.body.tasks | type'), more '$(own .body.more)'"
  done
fi

# ── who may, with a second owner and a second agent ──────────────────────────

if want A2; then
  log "A2 another owner's session"
  OWNER_B="${OWNER_B:-}"
  OWNER_B_KEY_FILE="${OWNER_B_KEY_FILE:-$HOME/.near-credentials/$NETWORK/$OWNER_B.json}"
  if lacks A2 OWNER_B; then :
  elif [[ "$OWNER_B" == "$PARENT" ]]; then
    skip "A2 needs a second owner, and OWNER_B is the owner under test"
  elif [[ ! -r "$OWNER_B_KEY_FILE" ]]; then
    skip "A2 needs the key file of $OWNER_B (OWNER_B_KEY_FILE, or ~/.near-credentials/$NETWORK/): its statement is signed with it"
  elif prepare '{"title":"Addressed to the first owner"}'; then
    THEIRS=$TASK
    owner_as "$OWNER_B" "$OWNER_B_KEY_FILE" sign-in other
    if [[ "$(own .status)" == "200" && "$(own .account_id)" == "$OWNER_B" ]]; then
      for asks in "GET /inbox/tasks/$THEIRS/origin" "GET /inbox/tasks/$THEIRS/files/0" \
                  "POST /inbox/tasks/$THEIRS/reject" "DELETE /inbox/tasks/$THEIRS"; do
        BODY_B=""; [[ "$asks" == POST* ]] && BODY_B='{"reason":null}'
        owner_as "$OWNER_B" "$OWNER_B_KEY_FILE" raw "${asks%% *}" "${asks#* }" "$BODY_B" other
        [[ "$(own .status)" == "404" && "$(own .body.reason)" == "task_not_found" ]] \
          && pass "A2 ${asks%% *} …${asks##*/} in $OWNER_B's session: 404 task_not_found" \
          || fail "A2 ${asks%% *} …${asks##*/} in $OWNER_B's session answered $(own .status) $(own .body.reason)"
      done
      for show in waiting closed; do
        owner_as "$OWNER_B" "$OWNER_B_KEY_FILE" list other "$show"
        [[ -z "$(own .failed)" && "$(jq -r --arg t "$THEIRS" '[.tasks[]? | select(.id == $t)] | length' <<<"$OWN")" == "0" ]] \
          && pass "A2 $OWNER_B's list ($show) holds nothing of $PARENT's" \
          || fail "A2 $OWNER_B's list ($show): $(own .failed | head -c 160) holds the task of $PARENT"
      done
      in_inbox "$THEIRS" && [[ "$(row .state)" == "open" ]] \
        && pass "A2 the task still waits for its owner" || fail "A2 after $OWNER_B's requests the task is '$(row .state)' to its owner"
      owner_as "$OWNER_B" "$OWNER_B_KEY_FILE" sign-out other
    else
      fail "A2 $OWNER_B's sign-in answered $(own .status) $(own .reason)"
    fi
  else
    fail "A2 prepare: error='$(said .error | head -c 200)'"
  fi
fi

if want A5; then
  log "A5 a second agent of the same owner"
  if lacks A5 AGENT2_PAYMENT_KEY AGENT2_ACCOUNT; then :
  elif prepare '{"title":"Made by the first agent"}'; then
    FIRST=$TASK
    for op in task_status task_cancel task_delete; do
      https_as AGENT2_PAYMENT_KEY "$PARENT/$PROFILE" "$(jq -nc --arg o "$op" --arg t "$FIRST" '{operation:$o, task_id:$t}')"
      expect_refusal "A5 ($op by the second agent)" task_not_found
    done
    https_as AGENT2_PAYMENT_KEY "$PARENT/$PROFILE" '{"operation":"tasks"}'
    [[ "$(said .success)" == "true" && "$(said '.output.tasks | type')" == "array" \
       && "$(jq -r --arg t "$FIRST" '[.output.tasks[]? | select(.task_id == $t)] | length' <<<"$RUN_OUT")" == "0" ]] \
      && pass "A5 the second agent's own list holds nothing of the first's" \
      || fail "A5 the second agent's list: success=$(said .success) error='$(said .error | head -c 160)'"
    status_of "$FIRST"
    [[ "$(said .output.state)" == "open" ]] && pass "A5 the task is open to the agent that made it" \
      || fail "A5 after the second agent's calls the task is '$(said .output.state)' error='$(said .error | head -c 160)'"
  else
    fail "A5 prepare: error='$(said .error | head -c 200)'"
  fi
fi

if want A11; then
  log "A11 a run whose grant was removed"
  agent '{"operation":"tasks"}'
  if [[ "$RUN_OK" == "true" && "$(said .success)" == "true" ]]; then
    BEFORE=$(waiting_ids)
    store_row "$POLICY_V1" "$(whitelist "$PARENT")"
    agent '{"operation":"prepare","title":"Made without a grant"}'
    # The run is refused where the row is opened: there is no code of the
    # tasks' own to compare, so the run's status and the module's silence are.
    if [[ "$RUN_OK" == "false" && -z "$(said .success)" ]] && grep -qiE 'denied|access condition' <<<"$RUN_ERR"; then
      pass "A11 the run did not start: the row did not open for the agent"
    else
      fail "A11 the run without a grant: run=$RUN_OK module success='$(said .success)' error='$(said .error | head -c 160)'"
    fi
    [[ "$(waiting_ids)" == "$BEFORE" ]] && pass "A11 no task was made" \
      || fail "A11 what waits for the owner changed over a run that had no grant"
    store_row "$POLICY_V1" "$GRANTED"
    agent '{"operation":"tasks"}'
    [[ "$RUN_OK" == "true" && "$(said .success)" == "true" ]] && pass "A11 granted again, the agent's run works" \
      || fail "A11 after the grant was restored: run=$RUN_OK error='$(said .error | head -c 160)'"
  else
    fail "A11 the agent's run with its grant: run=$RUN_OK/$RUN_ERR error='$(said .error | head -c 160)'"
  fi
fi

if want O1; then
  log "O1 a payment key of the owner's account acts as the owner"
  if lacks O1 OWNER_PAYMENT_KEY; then :
  elif prepare '{"title":"Answered over HTTPS","body":"Paid with the key of the owner."}'; then
    ANSWER=$(jq -nc --arg t "$TASK" --arg h "$HASH" '{operation:"confirm", task_id:$t, task_hash:$h}')
    agent "$ANSWER"
    expect_refusal "O1 (the agent's own key)" not_the_owner
    # The rule, and no hole: a call over HTTPS is made as the account whose
    # payment key pays for it, so the owner's key is the owner.
    https_as OWNER_PAYMENT_KEY "$PARENT/$PROFILE" "$ANSWER"
    if [[ "$(said .output.status)" == "done" && "$(said .output.result.acted_on.body)" == "Paid with the key of the owner." \
          && "$(said .output.result.prepared_by)" == "$AGENT_ACCOUNT" ]]; then
      pass "O1 the owner's own payment key answered the task over HTTPS: done"
    else
      fail "O1 confirm with the owner's key: success=$(said .success) error='$(said .error | head -c 200)' run=$RUN_OK/$RUN_ERR"
    fi
    status_of "$TASK"
    [[ "$(said .output.state)" == "done" ]] && pass "O1 the agent reads done" || fail "O1 status '$(said .output.state)'"
  else
    fail "O1 prepare: error='$(said .error | head -c 200)'"
  fi
fi

if want A13a; then
  log "A13a a mute deletes what waits and keeps outcomes"
  if prepare '{"title":"Answered before the mute"}'; then
    KEPT=$TASK
    acts "$(jq -nc --arg t "$KEPT" --arg h "$HASH" '{operation:"confirm", task_id:$t, task_hash:$h}')"
    if [[ "$(said .output.status)" == "done" ]] && prepare '{"title":"Waiting at the mute"}'; then
      WAITED=$TASK
      owner mute agent "$AGENT_ACCOUNT" a
      [[ "$(own .status)" == "200" && "$(own .body.deleted)" -ge 1 ]] && pass "A13a muted, and what waited was deleted" \
        || fail "A13a mute answered $(own .status) deleted='$(own .body.deleted)'"
      status_of "$KEPT"
      [[ "$(said .output.state)" == "done" ]] && pass "A13a the agent reads done for the task answered" \
        || fail "A13a the answered task: state '$(said .output.state)' error='$(said .error | head -c 160)'"
      status_of "$WAITED"
      expect_refusal "A13a (the task that waited)" task_not_found
      owner list a closed
      [[ "$(jq -r --arg t "$KEPT" '[.tasks[]? | select(.id == $t and .state == "done")] | length' <<<"$OWN")" == "1" ]] \
        && pass "A13a the outcome stays in the owner's closed list" || fail "A13a the outcome is not in the closed list"
    else
      fail "A13a the setup: confirm '$(said .output.status)' error='$(said .error | head -c 200)'"
    fi
    owner unmute agent "$AGENT_ACCOUNT" a
    [[ "$(own .status)" == "200" ]] || fail "A13a unmute answered $(own .status)"
  else
    fail "A13a prepare: error='$(said .error | head -c 200)'"
  fi
fi

# ── limits ───────────────────────────────────────────────────────────────────

if want L2; then
  log "L2 one agent's share"
  if lacks L2 AGENT2_PAYMENT_KEY AGENT2_ACCOUNT; then :
  else
    owner raw DELETE /inbox/tasks "" a
    if fill AGENT_PAYMENT_KEY 5 "L2 of the first agent"; then
      agent '{"operation":"prepare","title":"L2 the sixth of the first agent"}'
      expect_refusal L2 inbox_full
      prepare_as AGENT2_PAYMENT_KEY '{"title":"L2 of the second agent"}' \
        && pass "L2 another agent's task opens" \
        || fail "L2 the second agent's task: error='$(said .error | head -c 200)'"
    else
      fail "L2 the first agent's five tasks did not all open: error='$(said .error | head -c 200)'"
    fi
    owner raw DELETE /inbox/tasks "" a
    [[ "$(own .status)" == "200" ]] || fail "L2 deleting its tasks answered $(own .status)"
  fi
fi

if want L1; then
  log "L1 the owner's limit"
  if lacks L1 AGENT2_PAYMENT_KEY AGENT2_ACCOUNT AGENT3_PAYMENT_KEY AGENT3_ACCOUNT AGENT4_PAYMENT_KEY AGENT4_ACCOUNT; then :
  else
    owner raw DELETE /inbox/tasks "" a
    # Twenty, and the owner holds one of them: the next is refused by the
    # owner's limit, the owner's own share being four short of full.
    if fill AGENT_PAYMENT_KEY 5 "L1 first" && fill AGENT2_PAYMENT_KEY 5 "L1 second" \
       && fill AGENT3_PAYMENT_KEY 5 "L1 third" && fill AGENT4_PAYMENT_KEY 4 "L1 fourth" \
       && prepare_as owner '{"title":"L1 of the owner"}'; then
      OWN_TASK=$TASK; OWN_HASH=$HASH
      acts '{"operation":"prepare","title":"L1 the twenty-first"}'
      expect_refusal L1 inbox_full
      acts "$(jq -nc --arg t "$OWN_TASK" --arg h "$OWN_HASH" '{operation:"confirm", task_id:$t, task_hash:$h}')"
      if [[ "$(said .output.status)" == "done" ]]; then
        prepare_as owner '{"title":"L1 after one was answered"}' \
          && pass "L1 one answered, one more opens" \
          || fail "L1 after an answer the next task: error='$(said .error | head -c 200)'"
      else
        fail "L1 the owner's answer: success=$(said .success) error='$(said .error | head -c 200)'"
      fi
    else
      fail "L1 the twenty tasks did not all open: error='$(said .error | head -c 200)'"
    fi
    owner raw DELETE /inbox/tasks "" a
    [[ "$(own .status)" == "200" ]] || fail "L1 deleting its tasks answered $(own .status)"
  fi
fi

if want L6; then
  log "L6 more tasks than one run may open"
  BEFORE=$(waiting_ids | wc -w | tr -d ' ')
  agent '{"operation":"prepare_many","count":6,"title":"One of six"}'
  if [[ "$(said .success)" == "true" ]]; then
    [[ "$(said .output.opened)" == "5" && "$(said .output.refused.number)" == "6" \
        && "$(said .output.refused.code)" == "task_run_limit" ]] \
      && pass "L6 five tasks opened in one run, the sixth refused task_run_limit" \
      || fail "L6 opened $(said .output.opened), refused number $(said .output.refused.number) with '$(said .output.refused.code)'"
    MADE=$(said '.output.tasks | map(.task_id) | join(" ")')
    AFTER=$(waiting_ids | wc -w | tr -d ' ')
    [[ "$AFTER" == "$((BEFORE + 5))" ]] && pass "L6 the five wait for the owner" \
      || fail "L6 $BEFORE waited before the run and $AFTER after it"
    for made in $MADE; do
      owner delete "$made" a
      [[ "$(own .status)" == "200" ]] || warn "L6 the task $made was not deleted: $(own .status)"
    done
  else
    fail "L6 prepare_many: error='$(said .error | head -c 200)' run=$RUN_OK/$RUN_ERR"
  fi
fi

# ── what the chain holds ─────────────────────────────────────────────────────

if want K5; then
  log "K5 the transaction of an answer"
  WORDS="k5-$(openssl rand -hex 8) words of the owner"
  if prepare '{"title":"Tell me a word","kind":"text"}'; then
    owner seal "$TASK" answer "$WORDS" a
    SEALED=$(own .sealed)
    acts "$(jq -nc --arg t "$TASK" --arg h "$HASH" --arg s "$SEALED" '{operation:"supply", task_id:$t, task_hash:$h, supplied:$s}')"
    TX=$(tx_of "$RUN_RAW")
    if [[ -n "$SEALED" && "$(said .output.result.supplied)" == "$WORDS" && -n "$TX" ]]; then
      ON_CHAIN=$(tx_read "$TX" "$PARENT")
      # What the owner signed. What the probe answers is its own to choose,
      # and it echoes what was supplied, so the receipts are not judged.
      SIGNED=$(jq -r '[.result.transaction.actions[]?.FunctionCall.args // empty | @base64d] | join("\n")' <<<"$ON_CHAIN" 2>/dev/null)
      SENT=$(jq -r '.input_data // empty' <<<"$SIGNED" 2>/dev/null | jq -c . 2>/dev/null)
      if [[ -z "$SENT" ]]; then
        fail "K5 the transaction $TX could not be read from the chain"
      else
        [[ "$(jq -r .task_id <<<"$SENT")" == "$TASK" && "$(jq -r .task_hash <<<"$SENT")" == "$HASH" \
           && "$(jq -r .supplied <<<"$SENT")" == "$SEALED" ]] \
          && pass "K5 the transaction names the task, its hash, and what was sealed" \
          || fail "K5 the transaction's input names task '$(jq -r .task_id <<<"$SENT")' and a hash of $(jq -r '.task_hash | length' <<<"$SENT") characters"
        if grep -qF "$WORDS" <<<"$SIGNED$(jq -c '.result.transaction' <<<"$ON_CHAIN")" \
           || printf '%s' "$SEALED" | base64 --decode 2>/dev/null | LC_ALL=C grep -aqF "$WORDS"; then
          fail "K5 the words the owner wrote are in the transaction"
        else
          pass "K5 the words the owner wrote are not in the transaction"
        fi
      fi
    else
      fail "K5 the answer: success=$(said .success) error='$(said .error | head -c 200)' transaction '${TX:-none}'"
    fi
  else
    fail "K5 prepare: error='$(said .error | head -c 200)'"
  fi
fi

# ── a run a contract relayed ─────────────────────────────────────────────────

if want X1; then
  log "X1 an answer a contract relayed"
  if relay_lacks X1; then :
  elif prepare '{"title":"Answered through a relay","body":"Not to be acted on."}'; then
    relayed "$(jq -nc --arg t "$TASK" --arg h "$HASH" '{operation:"confirm", task_id:$t, task_hash:$h}')"
    if [[ "$RUN_OK" == "absent" ]]; then
      skip "X1 the relayed run gave no completion event, so nothing was judged"
    else
      expect_refusal X1 relayed
      status_of "$TASK"
      [[ "$(said .output.state)" == "open" && -z "$(said .output.run)" ]] \
        && pass "X1 the task stays open, and no run acted on it" \
        || fail "X1 after the relayed answer the task is '$(said .output.state)' run '$(said .output.run)'"
      in_inbox "$TASK" && [[ "$(row .state)" == "open" ]] \
        && pass "X1 the task still waits in the inbox" || fail "X1 the inbox: '$(row .state)'"
    fi
  else
    fail "X1 prepare: error='$(said .error | head -c 200)'"
  fi
fi

if want X2; then
  log "X2 a prepare a contract relayed"
  if relay_lacks X2; then :
  else
    BEFORE=$(waiting_ids)
    relayed '{"operation":"prepare","title":"Prepared through a relay"}'
    if [[ "$RUN_OK" == "absent" ]]; then
      skip "X2 the relayed run gave no completion event, so nothing was judged"
    else
      expect_refusal X2 relayed
      [[ -z "$(said .output.task_id)" && "$(waiting_ids)" == "$BEFORE" ]] && pass "X2 no task was made" \
        || fail "X2 what waits for the owner changed over a relayed run"
    fi
  fi
fi

if want M1; then
  log "M1 an answer whose run outlasts the caller's connection"
  if lacks M1 OWNER_PAYMENT_KEY; then :
  elif prepare '{"title":"Answered slowly","body":"Acted on after the caller left.","answer_by":"confirm_slow"}'; then
    SLOW=$TASK
    ANSWER=$(jq -nc --arg t "$SLOW" --arg h "$HASH" --argjson s "$M1_RUN_SECONDS" \
      '{operation:"confirm_slow", task_id:$t, task_hash:$h, seconds:$s}')
    # The caller leaves before the run ends: the connection is given up after
    # M1_CALLER_SECONDS.
    CALLER_SECONDS=$M1_CALLER_SECONDS https_as OWNER_PAYMENT_KEY "$PARENT/$PROFILE" "$ANSWER"
    [[ "$RUN_OK" == "absent" ]] && pass "M1 the caller left after ${M1_CALLER_SECONDS}s with no answer, the run still going" \
      || warn "M1 the call answered before the caller left (run=$RUN_OK): the run did not outlast it"
    SEEN=""; ENDED=""
    for attempt in $(seq 1 "$M1_POLLS"); do
      status_of "$SLOW"
      ENDED=$(said .output.state)
      SEEN="$SEEN $ENDED"
      [[ "$ENDED" == "done" || "$ENDED" == "failed" ]] && break
      sleep "$M1_POLL_SECONDS"
    done
    case "$ENDED" in
      done)
        [[ "$(said .output.result.acted_on.body)" == "Acted on after the caller left." ]] \
          && pass "M1 the task is done, with what the run left" \
          || fail "M1 done without its result: $(said .output | head -c 200)"
        [[ "$SEEN" != *failed* ]] && pass "M1 it was never failed on the way:$SEEN" || fail "M1 the states seen:$SEEN" ;;
      failed) fail "M1 the task is failed though its run acted; the states seen:$SEEN" ;;
      *) fail "M1 the task did not end within $((M1_POLLS * M1_POLL_SECONDS))s; the states seen:$SEEN" ;;
    esac
  else
    fail "M1 prepare: error='$(said .error | head -c 200)'"
  fi
fi

# ── the settings ─────────────────────────────────────────────────────────────

if want S2; then
  log "S2 the settings"
  owner devices a
  if [[ "$(own .status)" == "200" && "$(own .count)" -ge 1 && "$(own .marked_this)" == "1" && "$(own .this_is_this_device)" == "true" ]]; then
    pass "S2 the devices are listed, one is marked this, and it is this device"
  else
    fail "S2 devices answered $(own .status): $(own .count) listed, $(own .marked_this) marked this, this device: $(own .this_is_this_device)"
  fi
  [[ "$(own .signer_pubkey)" == "$(jq -r '.public_key // ""' "$OWNER_KEY_FILE")" ]] \
    && pass "S2 the device names the wallet key that signed it in" \
    || fail "S2 the device names the key '$(own .signer_pubkey)'"
  if prepare '{"title":"Of the project to be muted"}' && in_inbox "$TASK"; then
    PROJECT_UUID=$(row .project_uuid)
    owner mute project "$PROJECT_UUID" a
    [[ "$(own .status)" == "200" ]] && pass "S2 the project is muted by its uuid" || fail "S2 mute answered $(own .status) $(own .body.reason)"
    owner raw GET /inbox/mutes "" a
    [[ "$(own .status)" == "200" \
       && "$(jq -r --arg u "$PROJECT_UUID" '[.body.mutes[]? | select(.subject_is == "project" and .subject == $u)] | length' <<<"$OWN")" == "1" ]] \
      && pass "S2 the mute is listed" || fail "S2 the mutes answered $(own .status): $(own '.body.mutes | length') listed"
    agent '{"operation":"prepare","title":"Of a muted project"}'
    expect_refusal "S2 (a task of the muted project)" muted
    owner unmute project "$PROJECT_UUID" a
    [[ "$(own .status)" == "200" \
       && "$(jq -r --arg u "$PROJECT_UUID" '[.body.mutes[]? | select(.subject == $u)] | length' <<<"$OWN")" == "0" ]] \
      && pass "S2 unmuted, and the list says so" || fail "S2 unmute answered $(own .status)"
    prepare '{"title":"After the project was unmuted"}' && pass "S2 the project opens tasks again" \
      || fail "S2 after unmute: error='$(said .error | head -c 200)'"
  else
    fail "S2 prepare: error='$(said .error | head -c 200)'"
  fi
fi

# ── events ───────────────────────────────────────────────────────────────────

if want W2; then
  log "W2 a URL the inbox does not take"
  owner webhook get a
  NAMED_BEFORE="$(own .url_set) $(own .set_at)"
  while IFS='|' read -r what url <&3; do
    owner raw PUT /inbox/webhook "$(jq -nc --arg u "$url" '{url:$u}')" a
    [[ "$(own .status)" == "400" && "$(own .body.reason)" == "invalid_request" ]] \
      && pass "W2 $what: 400 invalid_request" \
      || fail "W2 $what answered $(own .status) $(own .body.reason)"
  done 3<<'URLS'
not HTTPS|http://example.com/hook
a loopback address|https://127.0.0.1/hook
a private address|https://10.0.0.8/hook
the metadata address|https://169.254.169.254/latest/meta-data
the name localhost|https://localhost/hook
a loopback address of IPv6|https://[::1]/hook
credentials and a private host|https://x@127.0.0.1/
credentials and a public host|https://user:word@example.com/hook
a private address as one number|https://2130706433/
a private address cut short|https://127.1/
a private address in hexadecimal|https://0x7f.0.0.1/
a private address inside an IPv6 one|https://[::ffff:127.0.0.1]/
URLS
  owner webhook get a
  [[ "$(own .status)" == "200" && "$(own .url_set) $(own .set_at)" == "$NAMED_BEFORE" ]] \
    && pass "W2 nothing was named by a refused request" \
    || fail "W2 after the refusals the webhook answered $(own .status) and is not as it was"
fi

if want W1; then
  log "W1 the owner is told at a URL"
  if lacks W1 HOOK_URL HOOK_LOG_URL; then :
  else
    export HOOK_URL
    owner webhook set HOOK_URL a
    if [[ "$(own .status)" == "200" && "$(own .url_matches)" == "true" && "$(own .set_here)" == "true" ]]; then
      HOOK_NAMED=true
      SHOWN_TITLE="W1 title $(openssl rand -hex 6)"; SHOWN_BODY="W1 body $(openssl rand -hex 6)"
      if prepare "$(jq -nc --arg t "$SHOWN_TITLE" --arg b "$SHOWN_BODY" '{title:$t, body:$b}')"; then
        TOLD_TASK=$TASK
        told HOOK_LOG_URL task_created "$TOLD_TASK" 9 "$SHOWN_TITLE" "$SHOWN_BODY" \
          && judge_event W1 task_created || fail "W1 task_created of $TOLD_TASK did not reach the receiver: $(jq -r '.failed // "not among the events"' <<<"$HOOK")"
        acts "$(jq -nc --arg t "$TOLD_TASK" --arg h "$HASH" '{operation:"confirm", task_id:$t, task_hash:$h}')"
        [[ "$(said .output.status)" == "done" ]] || fail "W1 confirm: error='$(said .error | head -c 200)'"
        if told HOOK_LOG_URL task_answered "$TOLD_TASK" 9 "$SHOWN_TITLE" "$SHOWN_BODY"; then
          judge_event W1 task_answered
          [[ -n "$(event .run)" ]] && pass "W1 task_answered names the run that acts" || fail "W1 task_answered names no run"
        else
          fail "W1 task_answered of $TOLD_TASK did not reach the receiver"
        fi
      else
        fail "W1 prepare: error='$(said .error | head -c 200)'"
      fi
      if prepare "$(jq -nc --arg t "$SHOWN_TITLE" --arg b "$SHOWN_BODY" '{title:$t, body:$b, life_seconds:20}')"; then
        note "waiting out the task's 20 seconds, and the sweep that finds it"
        sleep 25
        told HOOK_LOG_URL task_expired "$TASK" 15 "$SHOWN_TITLE" "$SHOWN_BODY" \
          && judge_event W1 task_expired || fail "W1 task_expired of $TASK did not reach the receiver"
      else
        fail "W1 prepare of a short-lived task: error='$(said .error | head -c 200)'"
      fi
      hook_log HOOK_LOG_URL "$SHOWN_TITLE" "$SHOWN_BODY"
      [[ "$(jq -r '.status // ""' <<<"$HOOK")" == "200" && "$(jq -r '.leaked | length' <<<"$HOOK")" == "0" ]] \
        && pass "W1 no body holds what the tasks showed" \
        || fail "W1 the receiver's log: $(jq -r '.failed // ""' <<<"$HOOK") $(jq -r '.leaked | length' <<<"$HOOK" 2>/dev/null) of what the tasks showed found in a body"
      owner webhook delete a
      [[ "$(own .status)" == "200" && "$(own .url_set)" == "false" ]] && HOOK_NAMED=false || fail "W1 removing the webhook answered $(own .status)"
    else
      fail "W1 naming the URL answered $(own .status) $(own .reason)"
    fi
  fi
fi

if want W3; then
  log "W3 a receiver that redirects"
  if lacks W3 HOOK_REDIRECT_URL HOOK_REDIRECT_LOG_URL HOOK_LOG_URL; then :
  else
    export HOOK_REDIRECT_URL
    owner webhook set HOOK_REDIRECT_URL a
    if [[ "$(own .status)" == "200" && "$(own .url_matches)" == "true" ]]; then
      HOOK_NAMED=true
      if prepare '{"title":"Told to a receiver that redirects"}'; then
        if told HOOK_REDIRECT_LOG_URL task_created "$TASK" 9; then
          pass "W3 the receiver that redirects was sent the event"
          # The sender tries again after ten seconds: the second address is
          # read once that try is over.
          sleep 30
          hook_log HOOK_LOG_URL
          if [[ "$(jq -r '.status // ""' <<<"$HOOK")" != "200" ]]; then
            fail "W3 the second receiver's log could not be read: $(jq -r '.failed // ""' <<<"$HOOK")"
          elif [[ "$(jq -r --arg t "$TASK" '[.events[]? | select(.task_id == $t)] | length' <<<"$HOOK")" == "0" ]]; then
            pass "W3 the address the redirect names was sent nothing"
          else
            fail "W3 the redirect was followed: the second address was sent the event"
          fi
          if ! sql_alive; then
            skip "W3 the record of the delivery needs PSQL_CMD: the coordinator's database is not read from here"
          elif [[ ! "$PARENT" =~ ^[a-z0-9._-]+$ || ! "$TASK" =~ ^[A-Za-z0-9-]+$ ]]; then
            skip "W3 the record of the delivery: the account or the task's id is not one a statement is built from"
          else
            RECORD=$(sql_row "SELECT status || ' ' || COALESCE(substring(last_error from '^HTTP [0-9]+'), 'no status') FROM wallet_webhook_deliveries WHERE wallet_id = 'owner:$PARENT' AND event_type = 'task_created' AND payload->>'task_id' = '$TASK' AND status = 'failed'" 40)
            [[ "$RECORD" == "failed HTTP 307" ]] && pass "W3 the delivery is recorded as failed, with the status 307" \
              || fail "W3 the delivery's record: '${RECORD:-not failed after two minutes}'"
          fi
        else
          fail "W3 the receiver that redirects was sent nothing: $(jq -r '.failed // "not among the events"' <<<"$HOOK")"
        fi
      else
        fail "W3 prepare: error='$(said .error | head -c 200)'"
      fi
      owner webhook delete a
      [[ "$(own .status)" == "200" && "$(own .url_set)" == "false" ]] && HOOK_NAMED=false || fail "W3 removing the webhook answered $(own .status)"
    else
      fail "W3 naming the URL answered $(own .status) $(own .reason)"
    fi
  fi
fi

# ── devices ──────────────────────────────────────────────────────────────────

if want V1 || want V5; then
  log "V1 a device signed in later"
  if prepare '{"title":"Made before the second device"}'; then
    sign_in_on b || fail "V1 the second device's sign-in answered $(own .status)"
    in_inbox "$TASK" b
    [[ "$(row .locked)" == "true" && "$(row .has_copy)" == "false" ]] \
      && pass "V1 locked on the new device, and listed" || fail "V1 on the new device: $ROW"
    acts '{"operation":"tasks_unlock"}'
    [[ "$(said .success)" == "true" && "$(said .output.waiting)" -ge 1 ]] && pass "V1 one run opened what waits" \
      || fail "V1 tasks_unlock: error='$(said .error | head -c 200)'"
    in_inbox "$TASK" b && [[ "$(row .read.hash)" == "$HASH" ]] \
      && pass "V1 the new device reads it, free from then on" || fail "V1 after the run: $ROW"
    in_inbox "$TASK" a && [[ "$(row .read.hash)" == "$HASH" ]] \
      && pass "V3 the first device reads it still" || fail "V3 the first device: $ROW"
    FIRST_TASK=$TASK
    if prepare '{"title":"Made with two devices in force"}'; then
      in_inbox "$TASK" a; ON_A=$(row .read.hash)
      in_inbox "$TASK" b; ON_B=$(row .read.hash)
      [[ "$ON_A" == "$HASH" && "$ON_B" == "$HASH" ]] && pass "V3 both devices read a new task at once, with no run" \
        || fail "V3 a new task: the first device read '$ON_A', the second '$ON_B', the run answered '$HASH'"
    else
      fail "V3 prepare: error='$(said .error | head -c 200)'"
    fi
    TASK=$FIRST_TASK
    # Five devices are in force at most: with a and b signed in, four more retire a.
    RETIRED=true
    for device in c d e f; do
      sign_in_on "$device" || { RETIRED=false; fail "V3 the sign-in of $device answered $(own .status)"; }
    done
    if [[ "$RETIRED" == true ]]; then
      owner raw GET /inbox/tasks "" a
      [[ "$(own .status)" == "401" && "$(own .body.reason)" == "session_replaced" ]] \
        && pass "V3 one device too many retired the one signed in longest ago, which is told why" \
        || fail "V3 the first device: $(own .status) $(own .body.reason)"
      owner raw GET /inbox/tasks "" b
      [[ "$(own .status)" == "200" ]] && pass "V3 the second device is in force still" \
        || fail "V3 the second device: $(own .status) $(own .body.reason)"
    fi

    log "V5 a session's token in another browser"
    owner copy-token b stolen
    in_inbox "$TASK" stolen
    [[ -n "$ROW" && -z "$(row .read)" && "$(row .unread)" == "decryption failed" ]] \
      && pass "V5 it lists the task and opens nothing" || fail "V5 with a copied token: $ROW"
  else
    fail "V1 prepare: error='$(said .error | head -c 200)'"
  fi
fi

# ── sessions and keys ────────────────────────────────────────────────────────
#
# Each row below opens sessions of its own, beside the ones in force; the
# device it signed in last is NOW_ON.

if want A14; then
  log "A14 a statement signed by a key that is not the account's"
  owner sign-in-stranger stranger
  [[ "$(own .status)" == "400" && "$(own .reason)" == "invalid_statement" && "$(own .token_returned)" == "false" ]] \
    && pass "A14 400 invalid_statement, and no session" \
    || fail "A14 a stranger's statement answered $(own .status) $(own .reason)"
  owner raw GET /inbox/tasks "" "$NOW_ON"
  [[ "$(own .status)" == "200" ]] && pass "A14 the refused statement ended no session" \
    || fail "A14 the session in force answers $(own .status) $(own .body.reason)"
fi

if want A15; then
  log "A15 a function-call key, and a key removed after sign-in"
  clear_tasks
  owner keygen calls
  CALLS_KEY=$(own .public_key); CALLS_FILE=$(own .file)
  if [[ -z "$CALLS_KEY" ]]; then
    fail "A15 no key was made: $(own .failed | head -c 160)"
  elif ! add_key function "$CALLS_KEY"; then
    skip "A15 needs a function-call key on $PARENT, and it could not be added: $WHY"
  else
    owner sign-in calls "$CALLS_FILE"
    [[ "$(own .status)" == "400" && "$(own .reason)" == "invalid_statement" && "$(own .signed_by)" == "$CALLS_KEY" ]] \
      && pass "A15 a function-call key of the account: 400 invalid_statement" \
      || fail "A15 a function-call key's statement answered $(own .status) $(own .reason)"
    remove_key "$CALLS_KEY" || warn "A15 the function-call key is still on $PARENT: $WHY"
  fi

  owner keygen second
  SECOND_KEY=$(own .public_key); SECOND_FILE=$(own .file)
  if [[ -z "$SECOND_KEY" ]]; then
    fail "A15 no key was made: $(own .failed | head -c 160)"
  elif ! add_key full "$SECOND_KEY"; then
    skip "A15 needs a second full-access key on $PARENT, and it could not be added: $WHY"
  elif ! sign_in_on second "$SECOND_FILE"; then
    fail "A15 a second full-access key's statement answered $(own .status) $(own .reason)"
    remove_key "$SECOND_KEY" || warn "A15 the second key is still on $PARENT: $WHY"
  else
    # The account holds several devices; what is judged is this device's copy
    # and the count of devices dropping by one when its key leaves.
    DEVICES_BEFORE=""
    if prepare '{"title":"Made while the key is on the account"}'; then
      DEVICES_BEFORE=$(said .output.devices)
      owner list second waiting
      GIVEN=$(jq -c --arg t "$TASK" '.tasks[]? | select(.id == $t)' <<<"$OWN" 2>/dev/null)
      [[ "$(jq -r '.has_copy' <<<"$GIVEN")" == "true" ]] \
        && pass "A15 while its key is on the account the device is given a copy ($DEVICES_BEFORE devices)" \
        || fail "A15 before the key was removed, the device's row: ${GIVEN:-not listed} $(own .failed | head -c 120)"
    else
      fail "A15 before the key was removed: error='$(said .error | head -c 160)'"
    fi
    if remove_key "$SECOND_KEY"; then
      if prepare '{"title":"Made after the key was removed"}'; then
        [[ -n "$DEVICES_BEFORE" && "$(said .output.devices)" == "$((DEVICES_BEFORE - 1))" ]] \
          && pass "A15 the key removed, the next task is encrypted to one device fewer" \
          || fail "A15 after the key was removed: devices '$(said .output.devices)', before '$DEVICES_BEFORE'"
        owner list second waiting
        GIVEN=$(jq -c --arg t "$TASK" '.tasks[]? | select(.id == $t)' <<<"$OWN" 2>/dev/null)
        if [[ "$(own .failed)" == *" 401"* ]]; then
          pass "A15 the session is over already"
        elif [[ "$(jq -r '.has_copy' <<<"$GIVEN")" == "false" && "$(jq -r '.locked' <<<"$GIVEN")" == "true" ]]; then
          pass "A15 the device is given no copy of it: locked"
        else
          fail "A15 the device's row of the next task: ${GIVEN:-not listed} $(own .failed | head -c 120)"
        fi
      else
        fail "A15 prepare after the key was removed: error='$(said .error | head -c 200)'"
      fi
      if [[ "${WAIT_FOR_RECHECK:-}" == "1" ]]; then
        note "waiting for the chain to be asked twice, ten minutes apart: up to 25 minutes"
        ENDED=""
        for minute in $(seq 1 25); do
          owner raw GET /inbox/devices "" second
          [[ "$(own .status)" == "401" ]] && { ENDED=$(own .body.reason); break; }
          sleep 60
        done
        [[ "$ENDED" == "session_required" ]] && pass "A15 the session ended: 401 session_required" \
          || fail "A15 after 25 minutes the session answers $(own .status) '${ENDED:-still in force}'"
      else
        skip "A15 the session's end takes two rechecks of its key, ten minutes apart: run with WAIT_FOR_RECHECK=1"
      fi
    else
      fail "A15 the second key could not be removed from $PARENT: $WHY"
    fi
  fi
fi

if want A17; then
  log "A17 a device that signed out"
  clear_tasks
  if sign_in_on left; then
    # How many devices a task is encrypted to while this one is in force.
    WITH_LEFT=""
    prepare '{"title":"Made before the sign-out"}' && WITH_LEFT=$(said .output.devices)
    owner sign-out left
    [[ "$(own .status)" == "200" && "$(own .body.revoked)" == "true" ]] && pass "A17 signed out" \
      || fail "A17 sign-out answered $(own .status) $(own .body.reason)"
    owner raw GET /inbox/tasks "" left
    [[ "$(own .status)" == "401" && "$(own .body.reason)" == "session_required" && "$(own '.body | has("tasks")')" == "false" ]] \
      && pass "A17 its token: 401 session_required, and no list" \
      || fail "A17 its token answered $(own .status) $(own .body.reason)"
    if prepare '{"title":"Made after the sign-out"}'; then
      # The account holds other devices; the one signed out is not among
      # those the task is encrypted to.
      [[ -n "$WITH_LEFT" && "$(said .output.devices)" == "$((WITH_LEFT - 1))" ]] \
        && pass "A17 the next task is encrypted to the devices in force, the signed-out one not among them" \
        || fail "A17 after the sign-out: devices '$(said .output.devices)', with it '$WITH_LEFT'"
      sign_in_on back || fail "A17 signing in again answered $(own .status) $(own .reason)"
    else
      fail "A17 prepare: error='$(said .error | head -c 200)'"
    fi
  else
    fail "A17 sign-in answered $(own .status) $(own .reason)"
  fi
fi

if want W4; then
  log "W4 a webhook after a second sign-in"
  # Named and removed with no task made in between, so nothing is sent to it.
  export NAMED_URL="${HOOK_URL:-https://example.com/outlayer-tasks-e2e}"
  if sign_in_on first; then
    owner webhook set NAMED_URL first
    if [[ "$(own .status)" == "200" && "$(own .url_matches)" == "true" && "$(own .set_here)" == "true" ]]; then
      HOOK_NAMED=true
      SET_AT=$(own .set_at); SET_BY=$(own .set_by_key)
      [[ -n "$SET_AT" && "$SET_BY" == "$(jq -r '.public_key // ""' "$OWNER_KEY_FILE")" ]] \
        && pass "W4 named in this session: set_here, when, and by the key that signed in" \
        || fail "W4 the webhook says set_at '$SET_AT' set_by_key '$SET_BY'"
      if sign_in_on later; then
        owner webhook get later NAMED_URL
        [[ "$(own .status)" == "200" && "$(own .url_matches)" == "true" && "$(own .set_here)" == "false" \
           && "$(own .set_at)" == "$SET_AT" && "$(own .set_by_key)" == "$SET_BY" ]] \
          && pass "W4 after a second sign-in: set_here is false, set_at and set_by_key are the first session's" \
          || fail "W4 after a second sign-in: $(own .status) set_here=$(own .set_here) set_at=$(own .set_at) (was $SET_AT) set_by_key=$(own .set_by_key)"
      else
        fail "W4 the second sign-in answered $(own .status) $(own .reason)"
      fi
      owner webhook delete "$NOW_ON"
      [[ "$(own .status)" == "200" && "$(own .url_set)" == "false" ]] && HOOK_NAMED=false || fail "W4 removing the webhook answered $(own .status)"
    else
      fail "W4 naming the URL answered $(own .status) $(own .reason)"
    fi
  else
    fail "W4 sign-in answered $(own .status) $(own .reason)"
  fi
fi

if want W5; then
  log "W5 the webhook takes the owner's signature"
  export UNSIGNED_URL="https://example.com/outlayer-tasks-unsigned"
  owner webhook set UNSIGNED_URL "$NOW_ON" unsigned
  [[ "$(own .status)" == "403" && "$(own .reason)" == "confirmation_required" ]] \
    && pass "W5 naming a URL on the token alone: 403 confirmation_required" \
    || fail "W5 naming a URL unsigned answered $(own .status) $(own .reason)"
  owner webhook get "$NOW_ON" UNSIGNED_URL
  [[ "$(own .url_matches)" != "true" ]] && pass "W5 the unsigned URL was not named" || fail "W5 the unsigned URL is in force"
  owner webhook set UNSIGNED_URL "$NOW_ON"
  if [[ "$(own .status)" == "200" ]]; then
    pass "W5 signed by the owner's wallet key: named"
    HOOK_NAMED=true
    owner webhook delete "$NOW_ON" unsigned
    [[ "$(own .status)" == "403" && "$(own .reason)" == "confirmation_required" ]] \
      && pass "W5 removing it on the token alone: 403" || fail "W5 removing unsigned answered $(own .status) $(own .reason)"
    owner webhook delete "$NOW_ON"
    [[ "$(own .status)" == "200" && "$(own .url_set)" == "false" ]] && { pass "W5 removed, signed"; HOOK_NAMED=false; } \
      || fail "W5 removing signed answered $(own .status) $(own .reason)"
  else
    fail "W5 naming the URL signed answered $(own .status) $(own .reason)"
  fi
fi

if want P9; then
  log "P9 withdrawing another device takes the owner's signature"
  if sign_in_on victim && sign_in_on holder; then
    owner devices holder
    VICTIM_ID=$(jq -r --arg n "$(jq -r '.device_id' "$STATE_DIR/device-victim.json" 2>/dev/null)" '.others[]? | select(. == $n)' <<<"$OWN")
    if [[ -z "$VICTIM_ID" ]]; then
      fail "P9 the device to withdraw is not listed among the others: $(own .others)"
    else
      owner withdraw "$VICTIM_ID" holder unsigned
      [[ "$(own .status)" == "403" && "$(own .reason)" == "confirmation_required" ]] \
        && pass "P9 on the token alone: 403 confirmation_required" \
        || fail "P9 unsigned withdrawal answered $(own .status) $(own .reason)"
      owner raw GET /inbox/tasks "" victim
      [[ "$(own .status)" == "200" ]] && pass "P9 the device's session goes on" || fail "P9 the device answers $(own .status)"
      owner withdraw "$VICTIM_ID" holder
      [[ "$(own .status)" == "200" && "$(own .revoked)" == "true" ]] && pass "P9 signed: withdrawn" \
        || fail "P9 signed withdrawal answered $(own .status) $(own .reason)"
      owner raw GET /inbox/tasks "" victim
      [[ "$(own .status)" == "401" && "$(own .body.reason)" == "session_required" ]] \
        && pass "P9 the withdrawn device is signed out" || fail "P9 the withdrawn device answers $(own .status) $(own .body.reason)"
    fi
  else
    fail "P9 the sign-ins answered $(own .status) $(own .reason)"
  fi
fi

# ── the limiter ──────────────────────────────────────────────────────────────
#
# Last, and only by name: the address stays refused for a while afterwards.

if asked L5; then
  log "L5 the inbox API called in a loop"
  if [[ "${IP_WHITELISTED:-}" == "1" ]]; then
    skip "L5 this address is exempt from the limiter (IP_WHITELISTED=1)"
  else
    owner flood 400 /inbox/tasks none
    if [[ "$(own '.limited | type')" == "object" ]]; then
      pass "L5 429 after $(own .sent) requests"
      [[ "$(own .limited.names_a_number)" == "false" && -z "$(own .limited.retry_after)" && "$(own '.limited.headers_of_a_limit | length')" == "0" ]] \
        && pass "L5 the answer names no number and no window, in its words or its headers" \
        || fail "L5 the 429 says '$(own .limited.said | head -c 120)', Retry-After '$(own .limited.retry_after)', headers $(own .limited.headers_of_a_limit)"
      [[ "$(own '.statuses | keys | map(select(. != "401" and . != "429")) | length')" == "0" ]] \
        && pass "L5 before the limit every request was 401, and none a list" \
        || fail "L5 the statuses met: $(own .statuses)"
    elif [[ -n "$(own .failed)" ]]; then
      fail "L5 the loop could not run: $(own .failed | head -c 160)"
    else
      fail "L5 no 429 in $(own .sent) requests: $(own .statuses)"
    fi
  fi
elif want L5; then
  skip "L5 runs only when asked for by name, and last: ONLY=L5"
fi

verdict "tasks"
