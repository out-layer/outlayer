#!/usr/bin/env bash
#
# Tasks between an agent and its owner, live: an agent's run of `tasks-probe`
# leaves the owner a task, the owner reads it in the inbox with no run and
# approves it with one signature, the platform starts a run of the agent that
# carries it out, and the agent learns the outcome.
#
# The owner's page is played by `lib/tasks_owner.mjs` on WebCrypto: it signs
# in with the owner's wallet key, reads the inbox with a device key of its
# own, opens files, seals what an owner writes, and signs the approval with
# the owner's key — no transaction, except the owner's own `tasks_unlock`
# (V1). The agent calls over HTTPS with its payment key; the run that carries
# a task out is the agent's too, started by the platform on the approval.
#
#   S1   a statement opens one session; the same statement again opens none
#   S3   a custody account that is not on chain yet signs in with its own
#        key, through its wallet's sign-message
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
#   A7   the operation that answers, called directly: by the agent without an
#        approval, task_answer_invalid; with a forged one, task_approval_invalid
#        (the task is open: nobody approved); by a key of the owner's account
#        with a forged one, the same — no call answers a task. The task stays
#        open through all three
#   F5   the owner approves with one signature: approved, with the run the
#        platform started; the run is the agent's (payment_key_owner); done,
#        and the task leaves the inbox
#   F6   the agent asks: done, with the result and that run
#   C6   the same approval again: 409 task_closed, state done
#   D8   the owner signs a wrong hash: the door cannot know, the enclave
#        refuses: failed with run_refused:hash-mismatch, and a second approval
#        is 409 task_closed with state failed
#   F13  a file: listed, opened by the owner, handed back to the agent's run
#   F7   the owner rejects with a reason; the agent reads it as written
#   F8   a turn: what the owner supplied reaches the agent's run, which opens
#        the next task of the conversation, as the agent's
#   F9   the agent cancels
#   F12  the owner deletes; the agent finds nothing
#   C7   the run that acts reports, then traps: failed as run_trapped, with
#        the run and what it reported
#   F11  the policy changed since: the run meets it, void
#   F10  past its life (shortened in the store, PSQL_CMD): expired, and an
#        approval is 409
#   N13  a note beside the approval reaches the agent's run with the result;
#        a note swapped after signing is 403 at the door; a note over the
#        bound is 400
#   N19  what the owner supplies is held to the task's kind at the door, 400,
#        before the nonce is spent: the same nonce then approves
#   N5   a replayed approval: on its task 409 task_closed; on another task 403;
#        on a failed task 409 with state failed
#   N9   two approvals at once: one 200 approved, one 409; one run; done once
#   N15  an approval for the wrong thing: for another task, for another
#        recipient, or eleven minutes old — 403 confirmation_required each
#   N14  an approval signed by a key that is not the owner's: 403, and the
#        task stays open
#   N3   an approval signed by a function-call key of the owner's account: 403
#        at the door; a full-access key REMOVED after the door last asked the
#        chain about it passes the door (its word is kept five minutes) and is
#        refused in the enclave: failed, run_refused:approval-invalid
#   N6   the preparer's key cannot pay: a key of the owner's own, made and
#        funded here, prepares a task and is deleted; the approval is 200 with
#        state failed and failure_reason preparer_key_unavailable, the
#        preparer reads it, and no run was started (nothing attested by the
#        run named). The owner's key is a preparer like any other (L1)
#   N7   the admin bearer reaches no task: every reading /admin route answers
#        without naming the task, every invented task route under /admin is
#        404 or 405, and the task is as it was. The routes that spend or break
#        things are not called
#   N2   another owner's session: the task is task_not_found; their key
#        signing as the owner, in the owner's session: 403
#   N10  the supply swapped after signing: 403 at the door
#   N8   a task approved past its life (shortened in the store, PSQL_CMD):
#        409 task_expired
#   N19  a task that takes an answer asked to live 899 s: display-invalid
#   N18  a device signed in after the task was made reads it locked; the
#        owner's tasks_unlock opens it; the approval from that device: done
#   N11  the voucher's compute limit raised in the store (PSQL_CMD): the run
#        carries more than the consent, not-the-preparer, failed
#   N17  the sealed task changed in the store (PSQL_CMD): unreadable, failed,
#        nothing acts
#   N4   the voucher rewritten in the store (PSQL_CMD): its owner column
#        naming another agent decides nothing — the run goes on the
#        preparer's key, done; its nonce naming another FUNDED key of the
#        same agent (AGENT_SPARE_NONCE) runs on that key, and the enclave
#        refuses it: failed, run_refused:not-the-preparer
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
#   A13a a mute deletes what waits and keeps outcomes: the agent reads done
#        for the task answered and task_not_found for the one that waited
#   L2   one agent's share: its eleventh task is inbox_full, another agent's
#        opens
#   L1   the owner's limit: the twenty-first task is inbox_full from a preparer
#        with room of its own; one approved and done, one more opens. The
#        owner's own payment key is a preparer like any other, and the owner
#        approves their own task
#   L6   more tasks than one run may open: five open, the sixth is refused
#        task_run_limit
#   K5   the input of the run that answered, read as the origin of the turn it
#        opened: the id, the hash, the approval and ciphertext, and not the
#        words the owner wrote. No transaction carries an answer
#   X1   an answer a contract relayed: relayed, and the task stays open
#   X2   a prepare a contract relayed: relayed, and no task
#   M1   a slow run: approved, then answering while it works, then done with
#        its result, never failed. The platform is the caller; nothing of the
#        owner's waits on it
#   S2   the settings: a project muted by its uuid, listed, unmuted; one
#        device listed, marked `this`
#   W2   a webhook's URL that is not HTTPS, is on a private host, carries
#        credentials, or writes a private address another way: invalid_request
#   W1   an owner who named a URL is told of a task made, approved (with the
#        run), answered and expired; a body holds nothing of what the task
#        shows
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
#   NT1  the agent notifies: `notified` with id and hash; the owner reads a
#        notice — no operation, no reply key — and the hash is the run's; the
#        agent reads it open; no voucher is kept for it (PSQL_CMD)
#   NT2  an approval sent to a notice: 400 before the nonce is spent — the
#        same body then approves the task it was signed for
#   NT3  Got it: the agent reads done; a second Got it 409; a reject of a
#        notice 400; another notice deleted: the agent finds nothing
#   NT4  a run on chain, with no payment key, notifies: the owner's own call
#   NT5  not granted by name, relayed, muted: refused as a task is
#   NT6  ten notices of one agent: its next task of any kind is inbox_full;
#        one Got it, and it opens
#   NT7  a notice reaches the owner's URL as task_created, kind notice, and
#        nothing of what it shows; Got it sends no event (HOOK_URL)
#   NT8  the proof holds for a notice: the run's answer names it with its hash
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
#   AGENT2_PAYMENT_KEY, AGENT2_ACCOUNT   a second agent wallet (A5, L2, L1, N4)
#   OWNER_PAYMENT_KEY    a payment key of the owner's own account (A7, L1: it
#                        prepares the twentieth task, and the owner approves it)
#   ADMIN_BEARER_TOKEN_TESTNET in scripts/.env (or ENV_FILE): the admin bearer
#                        for N7, read where it is used and never printed
#   RELAY_CONTRACT       the relay of wasi-examples/test-storage-ark, relaying
#                        to CONTRACT_ID, e.g. relay.outlayer-alice.testnet (X1, X2)
#   HOOK_URL, HOOK_LOG_URL   a public HTTPS receiver that answers 200 and
#                        records what it is sent, and where its log is read
#                        (W1, W3). The log's shape is in lib/tasks_hook.mjs:
#                        [{"method", "headers": {…}, "body"}], or that list
#                        under "requests"
#   HOOK_REDIRECT_URL, HOOK_REDIRECT_LOG_URL   a second receiver, which
#                        answers 307 to HOOK_URL, and its log (W3)
#                        All four come from `tests/hook_receiver.sh start`
#                        (a receiver on this machine behind a Cloudflare quick
#                        tunnel): `set -a; source ~/.local/state/outlayer-hook/hook.env; set +a`
#   AGENT_SPARE_NONCE    the nonce of a second FUNDED payment key of AGENT_ACCOUNT (N4)
#   CUSTODY_WALLET_KEY   the `wk_` key of a custody wallet whose implicit
#                        account was never sent NEAR (S3); read where it is used
#   PSQL_CMD             one statement of SQL against the coordinator's
#                        database (W3's record of the delivery; N4, N11 and
#                        N17 rewrite a task's voucher or its sealed copy)
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
# M1: how long the slow run works, and how the task's end is waited for. The
# time is sealed with the task; the run fits the platform's longest.
M1_RUN_SECONDS="${M1_RUN_SECONDS:-40}"
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

# The owner's page, the approval and the run it starts: lib/tasks_common.sh
# (owner, own, in_inbox, row, gone_from_inbox, waiting_ids, approves,
# await_run, approved_and_done, run_is_the_agents, an_id).
source "$SCRIPT_DIR/lib/tasks_common.sh"
# The probe's task_status answer, for the library.
task_field() { said ".output$1"; }

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
    AGENT2_PAYMENT_KEY) echo "the payment key of a second agent wallet" ;;
    AGENT2_ACCOUNT) echo "the account of a second agent wallet" ;;
    OWNER_PAYMENT_KEY) echo "a payment key of the owner's own account" ;;
    PSQL_CMD) echo "one statement of SQL against the coordinator's database" ;;
    AGENT_SPARE_NONCE) echo "the nonce of a second funded payment key of the agent" ;;
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
# acts <input-json> — the owner's own call: a transaction. Only `tasks_unlock`
# is the owner's to call; nothing answers a task by calling.
acts() { run_as "$PARENT" "$PARENT/$PROFILE" "$1"; }
# forged <task> <hash> [operation] — the input of a direct call of the
# answering operation with an approval that is well formed and signed by
# nobody: what a caller sends who did not get the owner's yes.
forged() {
  jq -nc --arg t "$1" --arg h "$2" --arg op "${3:-confirm}" --argjson at "$(date +%s)" \
    '{operation:$op, task_id:$t, task_hash:$h,
      approval:{at:$at, public_key:"ed25519:AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9",
                signature:("AAAA" * 21 + "AA=="), nonce:("AAAA" * 10 + "AAA=")}}'
}
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

# prepare_as <VARIABLE holding a payment key> <input-json> — that preparer
# opens a task over HTTPS; leaves TASK and HASH. A task is opened with a
# payment key and no other way: the key is what pays for the run that
# carries it out.
TASK=""; HASH=""
prepare_as() {
  local input
  input=$(jq -c '. + {operation:(.operation // "prepare")}' <<<"$2")
  https_as "$1" "$PARENT/$PROFILE" "$input"
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
# status_of <task> — `task_status` by the key that prepared it: the agent's,
# or the one STATUS_KEY names (a task is its preparer's to read).
STATUS_KEY=AGENT_PAYMENT_KEY
status_of() { https_as "$STATUS_KEY" "$PARENT/$PROFILE" "$(jq -nc --arg t "$1" '{operation:"task_status", task_id:$t}')"; }
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
EVENT_MEMBERS="expires_at failure_reason kind link owner preparer project_id project_uuid run state task_id type"
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

if want S3; then
  log "S3 a custody account not on chain yet signs in with its own key"
  if [[ -z "${CUSTODY_WALLET_KEY:-}" ]]; then
    skip "S3 no CUSTODY_WALLET_KEY"
  else
    owner sign-in-custody custody
    custody_account=$(own .account)
    custody_on_chain=$(curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' --max-time 30 \
      -d "$(jq -nc --arg a "$custody_account" '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"view_account",finality:"final",account_id:$a}}')" \
      2>/dev/null | jq -r 'if .result.amount then "made" elif .error.cause.name == "UNKNOWN_ACCOUNT" then "not made" else "no answer" end' 2>/dev/null)
    if [[ ! "$custody_account" =~ ^[0-9a-f]{64}$ ]]; then
      fail "S3 the wallet named no implicit account: sign-message $(own .sign_message_status) $(own '.said // .failed' | head -c 200)"
    elif [[ "$custody_on_chain" != "not made" ]]; then
      skip "S3 ${custody_account:0:8}… is $custody_on_chain on chain; the row needs a custody account never sent NEAR"
    elif [[ "$(own .status)" == "200" && "$(own .token_returned)" == "true" && "$(own .account_id)" == "$custody_account" ]]; then
      pass "S3 ${custody_account:0:8}…, not on chain, signed in with its own key"
      owner_as "$custody_account" "" sign-out custody
      [[ "$(own .status)" == "200" ]] && pass "S3 and signed out" || fail "S3 sign-out answered $(own .status)"
    else
      fail "S3 sign-in answered $(own .status) $(own .reason): $(own '.error // .said // .failed' | head -c 200)"
    fi
  fi
fi

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
    owner devices a
    [[ "$(said .output.devices)" == "$(own .count)" && "$(own .count)" -ge 1 ]] \
      && pass "F1 the task is encrypted to every device of the owner in force ($(own .count))" \
      || fail "F1 devices: $(said .output.devices), the owner has $(own .count) in force"
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

    log "A7 the operation that answers, called directly"
    agent "$(jq -nc --arg t "$FLOW_TASK" --arg h "$FLOW_HASH" '{operation:"confirm", task_id:$t, task_hash:$h}')"
    expect_refusal "A7 (the agent, no approval)" task_answer_invalid
    agent "$(forged "$FLOW_TASK" "$FLOW_HASH")"
    expect_refusal "A7 (the agent, a forged approval)" task_approval_invalid
    if [[ -n "${OWNER_PAYMENT_KEY:-}" ]]; then
      # A key of the owner's account is a caller like any other: nothing
      # answers a task by calling, approved or not.
      https_as OWNER_PAYMENT_KEY "$PARENT/$PROFILE" "$(forged "$FLOW_TASK" "$FLOW_HASH")"
      expect_refusal "A7 (a key of the owner's account, a forged approval)" task_approval_invalid
    else
      skip "A7 (a key of the owner's account) needs OWNER_PAYMENT_KEY, which the environment does not supply"
    fi
    status_of "$FLOW_TASK"
    [[ "$(said .output.state)" == "open" && -z "$(said .output.run)" ]] && pass "A7 left the task open, with no run" \
      || fail "after three refused calls the task is '$(said .output.state)' run '$(said .output.run)'"

    log "F5 the owner approves"
    if approved_and_done F5 "$FLOW_TASK"; then
      pass "F5 approved with one signature; the run $RUN_OF carried it out: done"
      [[ "$(said .output.result.acted_on.body)" == "Hello Bob, the report is attached." ]] \
        && pass "F5 acted on exactly what was prepared" \
        || fail "F5 the result: $(said .output.result | head -c 200)"
      run_is_the_agents F5 "$RUN_OF"
    fi
    gone_from_inbox F5 "$FLOW_TASK"
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

    log "C6 the same approval again"
    owner replay-approval "$FLOW_TASK" a
    [[ "$(own .status)" == "409" && "$(own .reason)" == "task_closed" ]] \
      && pass "C6 409 task_closed" || fail "C6 approving again answered $(own .status) reason='$(own .reason)' $(own .said)"
  fi
fi

if want D8; then
  log "D8 the owner signs a wrong hash"
  if prepare '{"title":"Approved under a wrong hash"}'; then
    in_inbox "$TASK"
    approves "$TASK" - - a --hash "$(printf '0%.0s' $(seq 1 64))"
    if [[ "$(own .status)" == "200" && "$(own .state)" == "approved" ]]; then
      pass "D8 the door cannot know the hash: approved, the run $(own .run) started"
      await_run "$TASK"
      [[ "$ENDED" == "failed" && "$(said .output.failure_reason)" == "run_refused:hash-mismatch" ]] \
        && pass "D8 the enclave refused: failed, run_refused:hash-mismatch" \
        || fail "D8 the task ended '$ENDED' with failure_reason '$(said .output.failure_reason)'"
      owner replay-approval "$TASK" a
      [[ "$(own .status)" == "409" && "$(own .reason)" == "task_closed" ]] \
        && pass "D8 a second approval: 409 task_closed" || fail "D8 a second approval answered $(own .status) $(own .reason)"
      owner list a closed
      [[ "$(jq -r --arg t "$TASK" '[.tasks[]? | select(.id == $t and .state == "failed")] | length' <<<"$OWN")" == "1" ]] \
        && pass "D8 the owner's closed list shows it failed" || fail "D8 the closed list does not show the task failed"
    else
      fail "D8 approve answered $(own .status) state='$(own .state)' reason='$(own .reason)' $(own .said)"
    fi
  else
    fail "D8 prepare: error='$(said .error | head -c 200)'"
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
    if approved_and_done F13 "$TASK"; then
      [[ "$(said '.output.result.files[0].bytes')" == "1048576" ]] \
        && pass "F13 the agent's run got it back whole" \
        || fail "F13 the result's files: $(said .output.result.files | head -c 200)"
    fi
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
    if approved_and_done F8 "$FIRST" "ipfs://photo#sha256=abc"; then
      [[ "$(said .output.result.supplied)" == "ipfs://photo#sha256=abc" ]] && pass "F8 what the owner supplied reached the agent's run" \
        || fail "F8 the result: $(said .output.result | head -c 200)"
    fi
    # The run that took the answer opened the next task of the conversation:
    # the agent's, as every task of the conversation is.
    owner list a waiting
    NEXT=$(jq -r --arg f "$FIRST" '[.tasks[]? | select(.id != $f and .read.envelope.thread == $f)] | .[0].id // ""' <<<"$OWN")
    if [[ -n "$NEXT" ]]; then
      pass "F8 the turn opened the next task of the same conversation: $NEXT"
      in_inbox "$NEXT" && [[ "$(row .read.envelope.thread)" == "$FIRST" && "$(row .preparer)" == "$AGENT_ACCOUNT" \
          && "$(row .read.envelope.preparer)" == "$AGENT_ACCOUNT" ]] \
        && pass "F8 the next task waits in the inbox, from the agent" || fail "F8 the next task in the inbox: $ROW"
      status_of "$NEXT"
      [[ "$(said .output.state)" == "open" ]] && pass "F8 the agent's task_status reads the turn open" \
        || fail "F8 the agent's status of the turn: '$(said .output.state)' error='$(said .error | head -c 200)'"
    else
      fail "F8 no next task of the conversation $FIRST waits in the inbox"
    fi
  else
    fail "F8 prepare: error='$(said .error | head -c 200)'"
  fi
fi

if want F9; then
  log "F9 the agent cancels"
  if prepare '{"title":"To be withdrawn"}'; then
    agent "$(jq -nc --arg t "$TASK" '{operation:"task_cancel", task_id:$t}')"
    [[ "$(said .output.state)" == "cancelled" ]] && pass "F9 cancelled" || fail "F9 cancel: error='$(said .error)'"
    gone_from_inbox F9 "$TASK"
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
    approves "$TASK" - - a
    if [[ "$(own .status)" == "200" && "$(own .state)" == "approved" ]]; then
      await_run "$TASK"
      [[ "$ENDED" == "failed" && "$(said .output.failure_reason)" == "run_trapped" && -n "$(said .output.run)" \
         && "$(said .output.result)" == "reported before the trap" ]] \
        && pass "C7 failed as run_trapped, with the run $(said .output.run) and what it reported" || fail "C7 the task ended '$ENDED': $(said .output | head -c 240)"
      in_inbox "$TASK" && [[ "$(row .state)" == "open" ]] && fail "C7 the task reopened" || pass "C7 the task did not reopen"
    else
      fail "C7 approve answered $(own .status) state='$(own .state)' reason='$(own .reason)' $(own .said)"
    fi
  else
    fail "C7 prepare: error='$(said .error | head -c 200)'"
  fi
fi

if want F11; then
  log "F11 the policy changed since"
  if prepare '{"title":"Made under the old policy"}'; then
    in_inbox "$TASK"
    store_row '{"v":2}' "$GRANTED"
    approves "$TASK" - - a
    if [[ "$(own .status)" == "200" && "$(own .state)" == "approved" ]]; then
      await_run "$TASK"
      [[ "$ENDED" == "void" ]] && pass "F11 the run met the changed policy: void to the agent" \
        || fail "F11 the task ended '$ENDED' (failure_reason '$(said .output.failure_reason)')"
    else
      fail "F11 approve answered $(own .status) state='$(own .state)' reason='$(own .reason)' $(own .said)"
    fi
    store_row "$POLICY_V1" "$GRANTED"
  else
    fail "F11 prepare: error='$(said .error | head -c 200)'"
  fi
fi

# A task that ends `$2` seconds from now. The host holds a task that takes an
# answer to fifteen minutes at least, so a short life is set in the store.
shorten() {
  sql "UPDATE owner_tasks SET expires_at = NOW() + make_interval(secs => $2) WHERE id = '$1'" >/dev/null
}

if want F10 && ! sql_alive; then
  skip "F10 needs PSQL_CMD to shorten the task's life — the host holds it to fifteen minutes"
elif want F10; then
  log "F10 past its life"
  if prepare '{"title":"Short-lived"}'; then
    shorten "$TASK" 20
    in_inbox "$TASK"; SHORT_HASH=$(row .read.hash)
    note "waiting out the task's 20 seconds"
    sleep 25
    status_of "$TASK"
    [[ "$(said .output.state)" == "expired" ]] && pass "F10 expired to the agent" || fail "F10 status '$(said .output.state)'"
    gone_from_inbox F10 "$TASK"
    # The page no longer lists it, so the approval is made blind, with the hash it read.
    approves "$TASK" - - a --blind --hash "$SHORT_HASH"
    [[ "$(own .status)" == "409" && ( "$(own .reason)" == "task_expired" || "$(own .state)" == "expired" ) ]] \
      && pass "F10 an approval of it: 409, expired" || fail "F10 approving an expired task answered $(own .status) reason='$(own .reason)' state='$(own .state)'"
  else
    fail "F10 prepare: error='$(said .error | head -c 200)'"
  fi
fi

# ── the approval's door ──────────────────────────────────────────────────────
#
# What the coordinator refuses before the nonce is spent, and what the enclave
# refuses when the door was passed. The rows that rewrite the store need
# PSQL_CMD; without it they SKIP.

if want N13; then
  log "N13 a note beside the approval"
  if prepare '{"title":"With a note"}'; then
    if approved_and_done N13 "$TASK" - "go ahead, but today only"; then
      [[ "$(said .output.result.note)" == "go ahead, but today only" ]] \
        && pass "N13 the agent's run read the note with the result" \
        || fail "N13 the result's note: '$(said .output.result.note)'"
    fi
  else
    fail "N13 prepare: error='$(said .error | head -c 200)'"
  fi
  if prepare '{"title":"With a note swapped after signing"}'; then
    approves "$TASK" - "signed for this note" a --swap-note
    [[ "$(own .status)" == "403" && "$(own .reason)" == "confirmation_required" ]] \
      && pass "N13 a note sealed again after signing: 403 confirmation_required" \
      || fail "N13 the swapped note answered $(own .status) $(own .reason) state='$(own .state)'"
    approves "$TASK" - "$(head -c 8200 /dev/zero | tr '\0' n)" a
    [[ "$(own .status)" == "400" && "$(own .reason)" == "invalid_request" ]] \
      && pass "N13 a note over its bound: 400 invalid_request" \
      || fail "N13 an 8200-byte note answered $(own .status) $(own .reason)"
    status_of "$TASK"
    [[ "$(said .output.state)" == "open" ]] && pass "N13 the refused approvals left the task open" || fail "N13 the task is '$(said .output.state)'"
  else
    fail "N13 prepare: error='$(said .error | head -c 200)'"
  fi
fi

if want N19; then
  log "N19 what is supplied is held to the task's kind at the door"
  NONCE=$(openssl rand -base64 32)
  if prepare '{"title":"Asks for nothing"}'; then
    approves "$TASK" "something anyway" - a --nonce "$NONCE"
    [[ "$(own .status)" == "400" && "$(own .reason)" == "invalid_request" ]] \
      && pass "N19 a supply on a confirm task: 400 invalid_request" \
      || fail "N19 a supply on a confirm task answered $(own .status) $(own .reason)"
    approves "$TASK" - - a --nonce "$NONCE"
    [[ "$(own .status)" == "200" && "$(own .state)" == "approved" ]] \
      && pass "N19 the same nonce then approves: the refusal spent nothing" \
      || fail "N19 the same nonce afterwards answered $(own .status) $(own .reason) state='$(own .state)'"
    await_run "$TASK"
  else
    fail "N19 prepare: error='$(said .error | head -c 200)'"
  fi
  if prepare '{"title":"Asks for text","kind":"text"}'; then
    approves "$TASK" - - a
    [[ "$(own .status)" == "400" && "$(own .reason)" == "invalid_request" ]] \
      && pass "N19 no supply on an input task: 400 invalid_request" \
      || fail "N19 no supply on an input task answered $(own .status) $(own .reason)"
    status_of "$TASK"
    [[ "$(said .output.state)" == "open" ]] && pass "N19 the task stays open" || fail "N19 the task is '$(said .output.state)'"
  else
    fail "N19 prepare: error='$(said .error | head -c 200)'"
  fi
fi

if want N5; then
  log "N5 a replayed approval"
  if prepare '{"title":"Approved once"}' && approved_and_done N5 "$TASK"; then
    DONE_TASK=$TASK
    owner replay-approval "$DONE_TASK" a
    [[ "$(own .status)" == "409" && "$(own .reason)" == "task_closed" ]] \
      && pass "N5 the same body on its task: 409 task_closed" || fail "N5 replay on its task answered $(own .status) $(own .reason)"
    if prepare '{"title":"Another task, the same body"}'; then
      owner replay-approval "$DONE_TASK" a against "$TASK"
      [[ "$(own .status)" == "403" && "$(own .reason)" == "confirmation_required" ]] \
        && pass "N5 the same body on another task: 403 confirmation_required" \
        || fail "N5 replay on another task answered $(own .status) $(own .reason) state='$(own .state)'"
      status_of "$TASK"
      [[ "$(said .output.state)" == "open" ]] && pass "N5 the other task stays open" || fail "N5 the other task is '$(said .output.state)'"
    fi
    if prepare '{"title":"Failed, then replayed"}'; then
      in_inbox "$TASK"
      approves "$TASK" - - a --hash "$(printf '0%.0s' $(seq 1 64))"
      await_run "$TASK"
      if [[ "$(own .status)" == "200" && "$ENDED" == "failed" ]]; then
        owner replay-approval "$TASK" a
        [[ "$(own .status)" == "409" && "$(own .reason)" == "task_closed" && "$(own .state)" == "failed" ]] \
          && pass "N5 the same body on a failed task: 409 task_closed, state failed" \
          || fail "N5 replay on a failed task answered $(own .status) $(own .reason) state='$(own .state)'"
      else
        fail "N5 the task meant to fail did not: $(own .status) '$(said .output.state)'"
      fi
    fi
  else
    fail "N5 the setup: error='$(said .error | head -c 200)'"
  fi
fi

if want N9; then
  log "N9 two approvals at once"
  if prepare '{"title":"Approved twice at once"}'; then
    in_inbox "$TASK"
    N9_A=$(mktemp "$STATE_DIR/n9a.XXXXXX"); N9_B=$(mktemp "$STATE_DIR/n9b.XXXXXX")
    ( owner approve "$TASK" - - a; printf '%s' "$OWN" > "$N9_A" ) &
    ( owner approve "$TASK" - - a; printf '%s' "$OWN" > "$N9_B" ) &
    wait
    STATUSES=$(jq -r '.status' "$N9_A" "$N9_B" | sort | tr '\n' ' ')
    RUNS=$(jq -r 'select(.status == 200) | .run // empty' "$N9_A" "$N9_B" | sort -u | grep -c .)
    [[ "$STATUSES" == "200 409 " && "$RUNS" == "1" ]] \
      && pass "N9 one 200 approved and one 409, one run" \
      || fail "N9 the two approvals answered: $STATUSES, runs started: $RUNS ($(jq -c '{status,reason,state}' "$N9_A" "$N9_B" | tr '\n' ' '))"
    await_run "$TASK"
    [[ "$ENDED" == "done" ]] && pass "N9 done once" || fail "N9 the task ended '$ENDED'"
  else
    fail "N9 prepare: error='$(said .error | head -c 200)'"
  fi
fi

if want N15; then
  log "N15 an approval for the wrong thing"
  if prepare '{"title":"N15 the task approved"}'; then
    N15_TASK=$TASK
    if prepare '{"title":"N15 the task signed for"}'; then
      approves "$N15_TASK" - - a --for "$TASK"
      [[ "$(own .status)" == "403" && "$(own .reason)" == "confirmation_required" ]] \
        && pass "N15 signed for another task: 403 confirmation_required" \
        || fail "N15 signed for another task answered $(own .status) $(own .reason) state='$(own .state)'"
    fi
    approves "$N15_TASK" - - a --recipient "other-contract.testnet"
    [[ "$(own .status)" == "403" && "$(own .reason)" == "confirmation_required" ]] \
      && pass "N15 signed for another recipient: 403" || fail "N15 another recipient answered $(own .status) $(own .reason)"
    approves "$N15_TASK" - - a --at "$(( $(date +%s) - 660 ))"
    [[ "$(own .status)" == "403" && "$(own .reason)" == "confirmation_required" ]] \
      && pass "N15 eleven minutes old: 403" || fail "N15 an old approval answered $(own .status) $(own .reason)"
    approves "$N15_TASK" - - a --unsigned
    [[ "$(own .status)" == "400" || "$(own .status)" == "403" ]] \
      && pass "N15 no approval at all: $(own .status)" || fail "N15 no approval answered $(own .status) $(own .reason)"
    status_of "$N15_TASK"
    [[ "$(said .output.state)" == "open" ]] && pass "N15 the task stays open" || fail "N15 the task is '$(said .output.state)'"
  else
    fail "N15 prepare: error='$(said .error | head -c 200)'"
  fi
fi

if want N14 || want N3; then
  log "N14 an approval signed by a key that is not the owner's"
  if prepare '{"title":"Approved by a stranger"}'; then
    owner keygen stranger
    STRANGER_FILE=$(own .file)
    approves "$TASK" - - a --key "$STRANGER_FILE"
    [[ "$(own .status)" == "403" && "$(own .reason)" == "confirmation_required" ]] \
      && pass "N14 a key on no account: 403 confirmation_required" || fail "N14 a stranger's key answered $(own .status) $(own .reason)"
    if want N3; then
      owner keygen calls2
      CALLS2_KEY=$(own .public_key); CALLS2_FILE=$(own .file)
      if [[ -z "$CALLS2_KEY" ]]; then
        fail "N3 no key was made: $(own .failed | head -c 160)"
      elif ! add_key function "$CALLS2_KEY"; then
        skip "N3 needs a function-call key on $PARENT, and it could not be added: $WHY"
      else
        approves "$TASK" - - a --key "$CALLS2_FILE"
        [[ "$(own .status)" == "403" && "$(own .reason)" == "confirmation_required" ]] \
          && pass "N3 a function-call key of the owner's account: 403 confirmation_required" \
          || fail "N3 a function-call key answered $(own .status) $(own .reason)"
        remove_key "$CALLS2_KEY" || warn "N3 the function-call key is still on $PARENT: $WHY"
      fi
    fi
    status_of "$TASK"
    [[ "$(said .output.state)" == "open" ]] && pass "N14 the task stays open" || fail "N14 the task is '$(said .output.state)'"
  else
    fail "N14 prepare: error='$(said .error | head -c 200)'"
  fi
fi

if want N2; then
  log "N2 another owner"
  if lacks N2 OWNER_B; then :
  elif prepare '{"title":"Not for the other owner"}'; then
    OWNER_B_KEY_FILE="${OWNER_B_KEY_FILE:-$HOME/.near-credentials/$NETWORK/$OWNER_B.json}"
    if [[ ! -r "$OWNER_B_KEY_FILE" ]]; then
      skip "N2 needs the key file of $OWNER_B at $OWNER_B_KEY_FILE"
    else
      owner_as "$OWNER_B" "$OWNER_B_KEY_FILE" sign-in b-n2
      if [[ "$(own .status)" != "200" ]]; then
        fail "N2 the second owner's sign-in answered $(own .status) $(own .reason)"
      else
        owner_as "$OWNER_B" "$OWNER_B_KEY_FILE" approve "$TASK" - - b-n2 --blind --hash "$HASH"
        [[ "$(own .status)" == "404" && "$(own .reason)" == "task_not_found" ]] \
          && pass "N2 in the other owner's session the task is task_not_found" \
          || fail "N2 the other owner's approval answered $(own .status) $(own .reason)"
        # The other owner's key, signing as this owner, sent in this owner's
        # session: a stolen token with the wrong key.
        approves "$TASK" - - a --key "$OWNER_B_KEY_FILE"
        [[ "$(own .status)" == "403" && "$(own .reason)" == "confirmation_required" ]] \
          && pass "N2 the other owner's key in this owner's session: 403 confirmation_required" \
          || fail "N2 the other owner's key answered $(own .status) $(own .reason)"
        owner_as "$OWNER_B" "$OWNER_B_KEY_FILE" sign-out b-n2
      fi
      status_of "$TASK"
      [[ "$(said .output.state)" == "open" ]] && pass "N2 the task stays open" || fail "N2 the task is '$(said .output.state)'"
    fi
  else
    fail "N2 prepare: error='$(said .error | head -c 200)'"
  fi
fi

if want N10; then
  log "N10 the supply swapped after signing"
  if prepare '{"title":"Tell me a word","kind":"text"}'; then
    approves "$TASK" "the words signed for" - a --swap-supplied
    [[ "$(own .status)" == "403" && "$(own .reason)" == "confirmation_required" ]] \
      && pass "N10 a supply sealed again after signing: 403 confirmation_required" \
      || fail "N10 the swapped supply answered $(own .status) $(own .reason) state='$(own .state)'"
    status_of "$TASK"
    [[ "$(said .output.state)" == "open" ]] && pass "N10 the task stays open" || fail "N10 the task is '$(said .output.state)'"
  else
    fail "N10 prepare: error='$(said .error | head -c 200)'"
  fi
fi

if want N19; then
  log "N19 a task that takes an answer lives fifteen minutes at least"
  agent '{"operation":"prepare","title":"Too short","life_seconds":899}'
  expect_refusal N19 display_invalid
fi

if want N8 && ! sql_alive; then
  skip "N8 needs PSQL_CMD to shorten the task's life — the host holds it to fifteen minutes"
elif want N8; then
  log "N8 a task approved past its life"
  if prepare '{"title":"Short-lived, approved late"}'; then
    shorten "$TASK" 30
    in_inbox "$TASK"; N8_HASH=$(row .read.hash)
    note "waiting out the task's 30 seconds"
    sleep 40
    approves "$TASK" - - a --blind --hash "$N8_HASH"
    [[ "$(own .status)" == "409" && ( "$(own .reason)" == "task_expired" || "$(own .state)" == "expired" ) ]] \
      && pass "N8 409, expired, and no nonce spent on it" || fail "N8 approving past its life answered $(own .status) reason='$(own .reason)' state='$(own .state)'"
    status_of "$TASK"
    [[ "$(said .output.state)" == "expired" && -z "$(said .output.run)" ]] && pass "N8 expired to the agent, with no run" \
      || fail "N8 status '$(said .output.state)' run '$(said .output.run)'"
  else
    fail "N8 prepare: error='$(said .error | head -c 200)'"
  fi
fi

if want N18; then
  log "N18 a device signed in after the task was made approves it"
  if prepare '{"title":"Made before the device"}'; then
    if sign_in_on n18; then
      in_inbox "$TASK" n18
      [[ "$(row .locked)" == "true" ]] && pass "N18 locked on the new device" || fail "N18 on the new device: $ROW"
      acts '{"operation":"tasks_unlock"}'
      [[ "$(said .success)" == "true" ]] || fail "N18 tasks_unlock: error='$(said .error | head -c 200)'"
      in_inbox "$TASK" n18 && [[ "$(row .read.hash)" == "$HASH" ]] \
        && pass "N18 the new device reads it after the owner's tasks_unlock" || fail "N18 after the run: $ROW"
      approves "$TASK" - - n18
      if [[ "$(own .status)" == "200" && "$(own .state)" == "approved" ]]; then
        await_run "$TASK"
        [[ "$ENDED" == "done" ]] && pass "N18 approved from the new device: done" \
          || fail "N18 the task ended '$(said .output.state)' (failure_reason '$(said .output.failure_reason)')"
      else
        fail "N18 approve from the new device answered $(own .status) $(own .reason) state='$(own .state)'"
      fi
    else
      fail "N18 the second device's sign-in answered $(own .status)"
    fi
  else
    fail "N18 prepare: error='$(said .error | head -c 200)'"
  fi
fi

if want N3; then
  log "N3 a key removed after the door last asked the chain about it"
  owner keygen n3
  N3_KEY=$(own .public_key); N3_FILE=$(own .file)
  if [[ -z "$N3_KEY" ]]; then
    fail "N3 no key was made: $(own .failed | head -c 160)"
  elif ! add_key full "$N3_KEY"; then
    skip "N3 needs a second full-access key on $PARENT, and it could not be added: $WHY"
  else
    # The door asks the chain about the key once and keeps its word five
    # minutes: this approval, by the key while it is on the account, is what
    # the door remembers.
    if prepare '{"title":"N3 approved while the key is on the account"}' && approved_and_done "N3 (with the key on the account)" "$TASK" - - --key "$N3_FILE"; then
      pass "N3 the key approved a task while on the account: done"
      if remove_key "$N3_KEY"; then
        if prepare '{"title":"N3 approved after the key was removed"}'; then
          approves "$TASK" - - a --key "$N3_FILE"
          if [[ "$(own .status)" == "200" && "$(own .state)" == "approved" ]]; then
            pass "N3 the door still takes the removed key: its word is kept, the run $(own .run) started"
            await_run "$TASK"
            [[ "$ENDED" == "failed" && "$(said .output.failure_reason)" == "run_refused:approval-invalid" ]] \
              && pass "N3 the enclave asked the chain: failed, run_refused:approval-invalid" \
              || fail "N3 the task ended '$ENDED' with failure_reason '$(said .output.failure_reason)'"
          elif [[ "$(own .status)" == "403" ]]; then
            skip "N3 the door asked the chain again and refused the removed key itself (403): the enclave's refusal was not reached this time"
          else
            fail "N3 approve with the removed key answered $(own .status) $(own .reason) state='$(own .state)'"
          fi
        else
          fail "N3 prepare: error='$(said .error | head -c 200)'"
        fi
      else
        fail "N3 the key could not be removed from $PARENT: $WHY"
      fi
    else
      remove_key "$N3_KEY" || warn "N3 the key is still on $PARENT: $WHY"
    fi
  fi
fi

if want N6; then
  log "N6 the preparer's key cannot pay for the run"
  # A payment key made for this row and deleted in it, so that nothing else
  # of the suite depends on it. The suite's CLI signs as the owner, so the key
  # is the owner's: the owner's own key is a preparer like any other (L1), and
  # the consent it leaves is the one the run is admitted with. The key's
  # string is read back from the CLI's home and reaches curl through the
  # environment; refusals are counted, not printed.
  N6_LOG=$(mktemp -d "$STATE_DIR/n6.XXXXXX")
  N6_OUT=$(OUTLAYER_NETWORK="$NETWORK" "$OUTLAYER_BIN" keys create 2>"$N6_LOG/err")
  N6_NONCE=$({ cat "$N6_LOG/err"; printf '%s\n' "$N6_OUT"; } | grep -oE 'nonce: [0-9]+' | grep -oE '[0-9]+' | tail -1)
  if [[ -z "$N6_NONCE" ]]; then
    skip "N6 a key of $PARENT could not be made (outlayer keys create: $(wc -c < "$N6_LOG/err" | tr -d ' ') bytes of refusal, not printed) — the row is left alone"
  else
    N6_KEY=$(OUTLAYER_NETWORK="$NETWORK" "$OUTLAYER_BIN" keys show "$N6_NONCE" 2>/dev/null | tr -d ' \r\n')
    n6_delete() { OUTLAYER_NETWORK="$NETWORK" "$OUTLAYER_BIN" keys delete "$N6_NONCE" >/dev/null 2>"$N6_LOG/delete"; }
    if [[ ! "$N6_KEY" =~ ^[a-z0-9._-]+:[0-9]+:[0-9a-fA-F]{16,}$ ]]; then
      fail "N6 the key at nonce $N6_NONCE could not be read back from the CLI's home"
      n6_delete || true
    else
      note "N6 a key of $PARENT at nonce $N6_NONCE was made"
      OUTLAYER_NETWORK="$NETWORK" "$OUTLAYER_BIN" keys topup "$N6_NONCE" --usd 1 >/dev/null 2>"$N6_LOG/topup" \
        || warn "N6 topping the key up was refused ($(wc -c < "$N6_LOG/topup" | tr -d ' ') bytes); trying to prepare with it as it is"
      if prepare_as N6_KEY '{"title":"Paid by a key about to be deleted"}'; then
        N6_TASK=$TASK
        if n6_delete; then
          pass "N6 the key that prepared the task is deleted"
          approves "$N6_TASK" - - a
          if [[ "$(own .status)" == "200" && "$(own .state)" == "failed" && "$(own .failure_reason)" == "preparer_key_unavailable" ]]; then
            pass "N6 the approval answered 200 with state failed, preparer_key_unavailable"
            N6_RUN=$(own .run)
            STATUS_KEY=OWNER_PAYMENT_KEY
            status_of "$N6_TASK"
            STATUS_KEY=AGENT_PAYMENT_KEY
            [[ "$(said .output.state)" == "failed" && "$(said .output.failure_reason)" == "preparer_key_unavailable" ]] \
              && pass "N6 the preparer's account reads failed with the reason" || fail "N6 status: $(said .output | head -c 200) error='$(said .error | head -c 120)'"
            owner list a closed
            [[ "$(jq -r --arg t "$N6_TASK" '[.tasks[]? | select(.id == $t and .state == "failed" and .failure_reason == "preparer_key_unavailable")] | length' <<<"$OWN")" == "1" ]] \
              && pass "N6 the owner's closed list shows why" || fail "N6 the closed list: $(jq -c --arg t "$N6_TASK" '.tasks[]? | select(.id == $t)' <<<"$OWN")"
            if [[ -n "$N6_RUN" ]]; then
              # A run that did start attests within the wait; one that was never queued never does.
              if attestation_of_run "$N6_RUN" 6 >/dev/null; then
                fail "N6 the run $N6_RUN attested: something ran on a key that could not pay"
              else
                pass "N6 no run was started: nothing attested by the run named after the wait"
              fi
            else
              pass "N6 no run named"
            fi
          else
            fail "N6 approve answered $(own .status) state='$(own .state)' failure='$(own .failure_reason)' reason='$(own .reason)' $(own .said)"
          fi
        else
          fail "N6 the key could not be deleted ($(wc -c < "$N6_LOG/delete" | tr -d ' ') bytes of refusal, not printed)"
        fi
      else
        skip "N6 the new key could not prepare a task (it may hold no balance): run=$RUN_OK error='$(said .error | head -c 120)' — the row is left alone"
        n6_delete || warn "N6 the key at nonce $N6_NONCE is still on $PARENT"
      fi
    fi
    N6_KEY=""
  fi
  rm -rf "$N6_LOG"
fi

if want N7; then
  log "N7 the admin bearer reaches no task"
  ENV_FILE="${ENV_FILE:-$SCRIPT_DIR/../scripts/.env}"
  ADMIN_TOKEN=""
  [[ -r "$ENV_FILE" ]] && ADMIN_TOKEN="$(set -a; source "$ENV_FILE" >/dev/null 2>&1; set +a; printf '%s' "${ADMIN_BEARER_TOKEN_TESTNET:-}")"
  if [[ -z "$ADMIN_TOKEN" ]]; then
    skip "N7 needs ADMIN_BEARER_TOKEN_TESTNET in $ENV_FILE — the admin bearer — which is not there"
  elif prepare '{"title":"N7 out of the admin bearer'"'"'s reach"}'; then
    N7_TASK=$TASK
    note "N7 admin bearer: present (length ${#ADMIN_TOKEN})"
    # admin <method> <path> [body] — one request with the bearer, which reaches
    # curl on stdin; leaves N7_CODE and N7_BODY.
    admin() {
      local body=${3:-} extra=()
      [[ -n "$body" ]] && extra=(-H 'Content-Type: application/json' --data-binary "$body")
      N7_BODY=$(printf 'header = "Authorization: Bearer %s"\n' "$ADMIN_TOKEN" \
        | curl -sS --max-time 30 -K - -w '\nHTTP:%{http_code}' -X "$1" "$COORDINATOR_URL$2" ${extra[@]+"${extra[@]}"} 2>/dev/null)
      N7_CODE=${N7_BODY##*HTTP:}; N7_BODY=${N7_BODY%$'\n'HTTP:*}
    }
    # What a bearer may read (docs/ADMIN.md): none of it names the task.
    READS=0; NAMED=0; ANSWERED=0
    for path in /admin/compile-logs/0 /admin/connector-calls /admin/earnings /admin/egress-audit /admin/grant-keys \
                /admin/health/detailed /admin/collateral/status /admin/binding-zones /admin/hos-impl-code-hashes \
                /admin/hos-impl-versions /admin/wallet-code-hashes /admin/contract-wallet-code-hashes \
                /admin/binding-implementations; do
      admin GET "$path"
      READS=$((READS + 1))
      [[ "$N7_CODE" == "200" ]] && ANSWERED=$((ANSWERED + 1))
      if grep -qF "$N7_TASK" <<<"$N7_BODY"; then NAMED=$((NAMED + 1)); fail "N7 GET $path names the task"; fi
      [[ "$N7_CODE" == 5* ]] && warn "N7 GET $path answered $N7_CODE"
    done
    [[ "$NAMED" == 0 && "$ANSWERED" -ge 1 ]] && pass "N7 $READS reading routes, $ANSWERED answered 200, none names the task"
    [[ "$ANSWERED" -ge 1 ]] || fail "N7 no reading route answered 200: the bearer is not taken, so nothing below judges its reach"
    # The routes that would reach a task, had there been any.
    BAD=0
    while IFS=' ' read -r method path body; do
      admin "$method" "$path" "$body"
      if [[ "$N7_CODE" == "404" || "$N7_CODE" == "405" ]]; then :; else BAD=$((BAD + 1)); fail "N7 $method $path answered $N7_CODE: $(head -c 120 <<<"$N7_BODY")"; fi
    done <<ROUTES
GET /admin/owner-tasks
GET /admin/owner-tasks/$N7_TASK
POST /admin/owner-tasks/$N7_TASK/approve {"task_hash":"$HASH"}
DELETE /admin/owner-tasks/$N7_TASK
GET /admin/inbox/tasks
POST /admin/inbox/tasks/$N7_TASK/approve {"task_hash":"$HASH"}
POST /admin/approve {"task_id":"$N7_TASK","task_hash":"$HASH"}
GET /admin/tasks/$N7_TASK
POST /admin/tasks/$N7_TASK/run {}
GET /admin/vouchers
GET /admin/owner-task-vouchers
ROUTES
    [[ "$BAD" == 0 ]] && pass "N7 every invented task route under /admin is 404 or 405"
    # And the owner's own routes refuse the bearer: it is no session.
    admin POST "/inbox/tasks/$N7_TASK/approve" "$(jq -nc --arg h "$HASH" '{task_hash:$h, approval:{at:0, public_key:"ed25519:11111111111111111111111111111111", signature:"", nonce:""}}')"
    [[ "$N7_CODE" == "401" ]] && pass "N7 the inbox's approve with the admin bearer: 401, it is no session" \
      || fail "N7 the inbox's approve with the admin bearer answered $N7_CODE"
    status_of "$N7_TASK"
    [[ "$(said .output.state)" == "open" && -z "$(said .output.run)" ]] && pass "N7 the task is as it was: open, no run" \
      || fail "N7 after the admin's calls the task is '$(said .output.state)' run '$(said .output.run)'"
    unset ADMIN_TOKEN
  else
    fail "N7 prepare: error='$(said .error | head -c 200)'"
  fi
fi

# The rows that rewrite the store: the door is passed honestly, and the
# enclave meets what the store now says.
if want N11 || want N17 || want N4; then
  if ! sql_alive; then
    for r in N11 N17 N4; do want $r && skip "$r needs PSQL_CMD — one statement of SQL against the coordinator's database — and it does not answer"; done
  else
    # The rows before leave tasks of the agent's waiting: each of these opens one.
    clear_tasks
    if want N11; then
      log "N11 the voucher's compute limit raised in the store"
      if prepare '{"title":"More compute than consented"}' && an_id "$TASK"; then
        sql "UPDATE owner_task_vouchers SET compute_limit_usd = '999999' WHERE task_id = '$TASK'" >/dev/null
        approves "$TASK" - - a
        if [[ "$(own .status)" == "200" && "$(own .state)" == "approved" ]]; then
          await_run "$TASK"
          [[ "$ENDED" == "failed" && "$(said .output.failure_reason)" == "run_refused:not-the-preparer" ]] \
            && pass "N11 the run carried more than the consent: failed, run_refused:not-the-preparer" \
            || fail "N11 the task ended '$ENDED' with failure_reason '$(said .output.failure_reason)'"
        else
          fail "N11 approve answered $(own .status) state='$(own .state)' reason='$(own .reason)' failure='$(own .failure_reason)'"
        fi
      else
        fail "N11 prepare: error='$(said .error | head -c 200)'"
      fi
    fi
    if want N17; then
      log "N17 the sealed task changed in the store"
      if prepare '{"title":"Changed under seal"}' && an_id "$TASK"; then
        in_inbox "$TASK"
        sql "UPDATE owner_tasks SET sealed = set_byte(sealed, 40, get_byte(sealed, 40) # 1) WHERE id = '$TASK'" >/dev/null
        in_inbox "$TASK" && [[ "$(row .read.hash)" == "$HASH" ]] && pass "N17 the owner's page still reads the clear copy" \
          || fail "N17 the page: $ROW"
        approves "$TASK" - - a
        if [[ "$(own .status)" == "200" && "$(own .state)" == "approved" ]]; then
          await_run "$TASK"
          [[ "$ENDED" == "failed" && "$(said .output.failure_reason)" == "run_refused:unreadable" && -z "$(said .output.result)" ]] \
            && pass "N17 the enclave could not open it: failed, run_refused:unreadable, nothing acted" \
            || fail "N17 the task ended '$ENDED' with failure_reason '$(said .output.failure_reason)' result '$(said .output.result | head -c 80)'"
        else
          fail "N17 approve answered $(own .status) state='$(own .state)' reason='$(own .reason)'"
        fi
      else
        fail "N17 prepare: error='$(said .error | head -c 200)'"
      fi
    fi
    if want N4; then
      log "N4 the voucher rewritten in the store"
      # Who pays is not the voucher's to say: the coordinator loads the key of
      # the task's PREPARER, by the voucher's nonce. So a voucher whose owner
      # column names another agent still runs on the preparer's key — and one
      # whose nonce names another key of the preparer runs on that key, which
      # the enclave holds to the consent sealed in the task and refuses.
      if prepare '{"title":"N4 a voucher that names another agent"}' && an_id "$TASK" && an_id "${AGENT2_ACCOUNT:-x}"; then
        sql "UPDATE owner_task_vouchers SET payment_key_owner = '${AGENT2_ACCOUNT:-other.testnet}' WHERE task_id = '$TASK'" >/dev/null
        if approved_and_done "N4 (another agent named)" "$TASK"; then
          pass "N4 a voucher naming another agent decided nothing: the run went on the preparer's key, done"
          run_is_the_agents "N4 (another agent named)" "$RUN_OF" "$AGENT_ACCOUNT"
        fi
      else
        fail "N4 prepare: error='$(said .error | head -c 200)'"
      fi
      if lacks N4 AGENT_SPARE_NONCE; then :
      elif ! [[ "$AGENT_SPARE_NONCE" =~ ^[0-9]+$ ]]; then
        fail "N4 AGENT_SPARE_NONCE is not a nonce"
      elif prepare '{"title":"N4 carried out on another key of the agent"}' && an_id "$TASK"; then
        sql "UPDATE owner_task_vouchers SET payment_key_nonce = $AGENT_SPARE_NONCE WHERE task_id = '$TASK'" >/dev/null
        approves "$TASK" - - a
        if [[ "$(own .status)" == "200" && "$(own .state)" == "approved" ]]; then
          N4_RUN=$(own .run)
          await_run "$TASK"
          [[ "$ENDED" == "failed" && "$(said .output.failure_reason)" == "run_refused:not-the-preparer" ]] \
            && pass "N4 the run on another key of the agent: failed, run_refused:not-the-preparer" \
            || fail "N4 the task ended '$ENDED' with failure_reason '$(said .output.failure_reason)'"
          if N4_ATT=$(attestation_of_run "$N4_RUN"); then
            [[ "$(jq -r '.payment_key_nonce // ""' <<<"$N4_ATT")" == "$AGENT_SPARE_NONCE" ]] \
              && pass "N4 and the run was indeed on the key at nonce $AGENT_SPARE_NONCE" \
              || fail "N4 the run was on the key at nonce '$(jq -r '.payment_key_nonce // ""' <<<"$N4_ATT")', not $AGENT_SPARE_NONCE"
          else
            skip "N4 the run $N4_RUN has no attestation after the wait: which key it ran on is not read"
          fi
        else
          fail "N4 approve answered $(own .status) state='$(own .state)' reason='$(own .reason)' failure='$(own .failure_reason)' — the key at nonce $AGENT_SPARE_NONCE must be funded"
        fi
      else
        fail "N4 prepare: error='$(said .error | head -c 200)'"
      fi
    fi
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
    [[ "$BEFORE" == unread:* ]] && fail "A11 the inbox was not read before the row: $(own .failed | head -c 120)"
    store_row "$POLICY_V1" "$(whitelist "$PARENT")"
    agent '{"operation":"prepare","title":"Made without a grant"}'
    # The run is refused where the row is opened: there is no code of the
    # tasks' own to compare, so the run's status and the module's silence are.
    if [[ "$RUN_OK" == "false" && -z "$(said .success)" ]] && grep -qiE 'denied|access condition' <<<"$RUN_ERR"; then
      pass "A11 the run did not start: the row did not open for the agent"
    else
      fail "A11 the run without a grant: run=$RUN_OK module success='$(said .success)' error='$(said .error | head -c 160)'"
    fi
    AFTER=$(waiting_ids)
    [[ "$AFTER" == unread:* ]] && fail "A11 the inbox was not read after the row: $(own .failed | head -c 120)"
    [[ "$AFTER" == "$BEFORE" ]] && pass "A11 no task was made" \
      || fail "A11 what waits for the owner changed over a run that had no grant"
    store_row "$POLICY_V1" "$GRANTED"
    agent '{"operation":"tasks"}'
    [[ "$RUN_OK" == "true" && "$(said .success)" == "true" ]] && pass "A11 granted again, the agent's run works" \
      || fail "A11 after the grant was restored: run=$RUN_OK error='$(said .error | head -c 160)'"
  else
    fail "A11 the agent's run with its grant: run=$RUN_OK/$RUN_ERR error='$(said .error | head -c 160)'"
  fi
fi

if want A13a; then
  log "A13a a mute deletes what waits and keeps outcomes"
  if prepare '{"title":"Answered before the mute"}'; then
    KEPT=$TASK
    if approved_and_done A13a "$KEPT" && prepare '{"title":"Waiting at the mute"}'; then
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
      fail "A13a the setup: the approved task ended '$(said .output.state)' error='$(said .error | head -c 200)'"
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
    if fill AGENT_PAYMENT_KEY 10 "L2 of the first agent"; then
      agent '{"operation":"prepare","title":"L2 the eleventh of the first agent"}'
      expect_refusal L2 inbox_full
      prepare_as AGENT2_PAYMENT_KEY '{"title":"L2 of the second agent"}' \
        && pass "L2 another agent's task opens" \
        || fail "L2 the second agent's task: error='$(said .error | head -c 200)'"
    else
      fail "L2 the first agent's ten tasks did not all open: error='$(said .error | head -c 200)'"
    fi
    owner raw DELETE /inbox/tasks "" a
    [[ "$(own .status)" == "200" ]] || fail "L2 deleting its tasks answered $(own .status)"
  fi
fi

if want L1; then
  log "L1 the owner's limit"
  if lacks L1 AGENT2_PAYMENT_KEY AGENT2_ACCOUNT OWNER_PAYMENT_KEY; then :
  else
    owner raw DELETE /inbox/tasks "" a
    # Twenty, and the owner's own key holds one of them: the next is refused
    # by the owner's limit, the owner's own share being nine short of full.
    if fill AGENT_PAYMENT_KEY 10 "L1 first" && fill AGENT2_PAYMENT_KEY 9 "L1 second" \
       && prepare_as OWNER_PAYMENT_KEY '{"title":"L1 of the owner"}'; then
      OWN_TASK=$TASK
      https_as OWNER_PAYMENT_KEY "$PARENT/$PROFILE" '{"operation":"prepare","title":"L1 the twenty-first"}'
      expect_refusal L1 inbox_full
      # The owner approves the task their own key prepared: the run is that
      # key's, and the key is the owner's — the legitimate twin of N14. The
      # task is that key's to read, so task_status is asked with it.
      STATUS_KEY=OWNER_PAYMENT_KEY
      if approved_and_done L1 "$OWN_TASK"; then
        run_is_the_agents L1 "$RUN_OF" "$PARENT"
        prepare_as OWNER_PAYMENT_KEY '{"title":"L1 after one was answered"}' \
          && pass "L1 one answered, one more opens" \
          || fail "L1 after an answer the next task: error='$(said .error | head -c 200)'"
      fi
      STATUS_KEY=AGENT_PAYMENT_KEY
    else
      fail "L1 the twenty tasks did not all open: error='$(said .error | head -c 200)'"
    fi
    owner raw DELETE /inbox/tasks "" a
    [[ "$(own .status)" == "200" ]] || fail "L1 deleting its tasks answered $(own .status)"
  fi
fi

if want L6; then
  log "L6 more tasks than one run may open"
  BEFORE_IDS=$(waiting_ids); BEFORE=$(wc -w <<<"$BEFORE_IDS" | tr -d ' ')
  [[ "$BEFORE_IDS" == unread:* ]] && fail "L6 the inbox was not read before the run: $(own .failed | head -c 120)"
  agent '{"operation":"prepare_many","count":6,"title":"One of six"}'
  if [[ "$(said .success)" == "true" ]]; then
    [[ "$(said .output.opened)" == "5" && "$(said .output.refused.number)" == "6" \
        && "$(said .output.refused.code)" == "task_run_limit" ]] \
      && pass "L6 five tasks opened in one run, the sixth refused task_run_limit" \
      || fail "L6 opened $(said .output.opened), refused number $(said .output.refused.number) with '$(said .output.refused.code)'"
    MADE=$(said '.output.tasks | map(.task_id) | join(" ")')
    AFTER_IDS=$(waiting_ids); AFTER=$(wc -w <<<"$AFTER_IDS" | tr -d ' ')
    [[ "$AFTER_IDS" == unread:* ]] && fail "L6 the inbox was not read after the run: $(own .failed | head -c 120)"
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
  log "K5 the input of the run that answered"
  WORDS="k5-$(openssl rand -hex 8) words of the owner"
  if prepare '{"title":"Tell me a word","kind":"text","again":true}'; then
    FIRST=$TASK
    if approved_and_done K5 "$FIRST" "$WORDS"; then
      [[ "$(said .output.result.supplied)" == "$WORDS" ]] && pass "K5 the agent's run read the words" \
        || fail "K5 the result: $(said .output.result | head -c 200)"
      # The run that answered opened the next turn, so it is the next turn's
      # origin: its input is what the platform started it with.
      owner list a waiting
      NEXT=$(jq -r --arg f "$FIRST" '[.tasks[]? | select(.id != $f and .read.envelope.thread == $f)] | .[0].id // ""' <<<"$OWN")
      if [[ -z "$NEXT" ]]; then
        fail "K5 the run opened no next turn, so its input is not served"
      else
        owner origin "$NEXT" a "$WORDS"
        if [[ "$(own .status)" != "200" ]]; then
          fail "K5 the origin of $NEXT answered $(own .status) $(own .reason)"
        else
          [[ "$(own .run)" == "$RUN_OF" && "$(own .door)" == "https" ]] \
            && pass "K5 the next turn was made by the run the approval started, over HTTPS: no transaction carries an answer" \
            || fail "K5 the next turn's origin: run '$(own .run)' (the approval's $RUN_OF), door '$(own .door)'"
          [[ "$(own .input_kept)" == "true" && "$(own .input_task_id)" == "$FIRST" && "$(own .input_has_hash)" == "true" \
             && "$(own .input_has_approval)" == "true" && "$(own .input_supplied_is_sealed)" == "true" ]] \
            && pass "K5 the input names the task, its hash, the approval, and the supply as sealed bytes" \
            || fail "K5 the input: kept=$(own .input_kept) task=$(own .input_task_id) hash=$(own .input_has_hash) approval=$(own .input_has_approval) sealed=$(own .input_supplied_is_sealed)"
          [[ "$(own .words_in_input)" == "false" ]] && pass "K5 the words the owner wrote are not in the input" \
            || fail "K5 the words the owner wrote are in the run's input"
        fi
      fi
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
    relayed "$(forged "$TASK" "$HASH")"
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
    [[ "$BEFORE" == unread:* ]] && fail "X2 the inbox was not read before the row: $(own .failed | head -c 120)"
    relayed '{"operation":"prepare","title":"Prepared through a relay"}'
    if [[ "$RUN_OK" == "absent" ]]; then
      skip "X2 the relayed run gave no completion event, so nothing was judged"
    else
      expect_refusal X2 relayed
      AFTER=$(waiting_ids)
      [[ "$AFTER" == unread:* ]] && fail "X2 the inbox was not read after the row: $(own .failed | head -c 120)"
      [[ -z "$(said .output.task_id)" && "$AFTER" == "$BEFORE" ]] && pass "X2 no task was made" \
        || fail "X2 what waits for the owner changed over a relayed run"
    fi
  fi
fi

if want M1; then
  log "M1 a slow run"
  if prepare "$(jq -nc --argjson s "$M1_RUN_SECONDS" '{title:"Answered slowly", body:"Acted on while nobody waited.", answer_by:"confirm_slow", seconds:$s}')"; then
    SLOW=$TASK
    approves "$SLOW" - - a
    if [[ "$(own .status)" == "200" && "$(own .state)" == "approved" ]]; then
      pass "M1 approved; the run $(own .run) works for ${M1_RUN_SECONDS}s with nobody waiting on it"
      SEEN=""; ENDED=""
      for attempt in $(seq 1 "$M1_POLLS"); do
        status_of "$SLOW"
        ENDED=$(said .output.state)
        SEEN="$SEEN $ENDED"
        [[ "$ENDED" == "done" || "$ENDED" == "failed" || "$ENDED" == "void" || "$ENDED" == "expired" ]] && break
        sleep "$M1_POLL_SECONDS"
      done
      case "$ENDED" in
        done)
          [[ "$(said .output.result.acted_on.body)" == "Acted on while nobody waited." && "$(said .output.result.worked_ms)" -ge $((M1_RUN_SECONDS * 1000 - 1000)) ]] \
            && pass "M1 the task is done, with what the run left after ${M1_RUN_SECONDS}s of work" \
            || fail "M1 done without its result: $(said .output | head -c 200)"
          [[ "$SEEN" == *answering* || "$SEEN" == *approved* ]] && pass "M1 it was approved or answering on the way:$SEEN" \
            || warn "M1 the run ended before a poll saw it on the way:$SEEN"
          [[ "$SEEN" != *failed* ]] && pass "M1 it was never failed on the way:$SEEN" || fail "M1 the states seen:$SEEN" ;;
        failed) fail "M1 the task is failed (failure_reason '$(said .output.failure_reason)') though its run acted; the states seen:$SEEN" ;;
        *) fail "M1 the task did not end within $((M1_POLLS * M1_POLL_SECONDS))s; the states seen:$SEEN" ;;
      esac
    else
      fail "M1 approve answered $(own .status) state='$(own .state)' reason='$(own .reason)' $(own .said)"
    fi
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
        approved_and_done W1 "$TOLD_TASK" || fail "W1 the approved task did not end done"
        if told HOOK_LOG_URL task_approved "$TOLD_TASK" 9 "$SHOWN_TITLE" "$SHOWN_BODY"; then
          judge_event W1 task_approved
          [[ "$(event .run)" == "$RUN_OF" ]] && pass "W1 task_approved names the run the platform started" \
            || fail "W1 task_approved names the run '$(event .run)', the approval named '$RUN_OF'"
        else
          fail "W1 task_approved of $TOLD_TASK did not reach the receiver"
        fi
        if told HOOK_LOG_URL task_answered "$TOLD_TASK" 9 "$SHOWN_TITLE" "$SHOWN_BODY"; then
          judge_event W1 task_answered
          [[ -n "$(event .run)" ]] && pass "W1 task_answered names the run that acted" || fail "W1 task_answered names no run"
        else
          fail "W1 task_answered of $TOLD_TASK did not reach the receiver"
        fi
      else
        fail "W1 prepare: error='$(said .error | head -c 200)'"
      fi
      if ! sql_alive; then
        skip "W1 task_expired needs PSQL_CMD to shorten the task's life — the host holds it to fifteen minutes"
      elif prepare "$(jq -nc --arg t "$SHOWN_TITLE" --arg b "$SHOWN_BODY" '{title:$t, body:$b}')"; then
        shorten "$TASK" 20
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

# ── notices ──────────────────────────────────────────────────────────────────

# notify_as <VARIABLE holding a payment key> <input-json> — that preparer
# notifies over HTTPS; leaves TASK and HASH.
notify_as() {
  https_as "$1" "$PARENT/$PROFILE" "$(jq -c '. + {operation:"notify"}' <<<"$2")"
  TASK=$(said .output.task_id); HASH=$(said .output.task_hash)
  [[ "$(said .output.status)" == "notified" && -n "$TASK" ]]
}
notify() { notify_as AGENT_PAYMENT_KEY "$1"; }

if want NT1 || want NT2 || want NT3 || want NT8; then
  log "NT1 the agent notifies"
  NOTICE_TITLE="NT1 sent $(openssl rand -hex 4)"
  if notify "$(jq -nc --arg t "$NOTICE_TITLE" '{title:$t, body:"The email to Bob was sent."}')"; then
    NOTICE=$TASK NOTICE_HASH=$HASH
    pass "NT1 notified, task $NOTICE"
    in_inbox "$NOTICE" "$NOW_ON"
    [[ "$(row .kind)" == "notice" && "$(row .state)" == "open" && "$(row .reply_pubkey)" == "" ]] \
      && pass "NT1 listed as an open notice, with no reply key" || fail "NT1 the listed row: $(jq -c 'del(.read)' <<<"$ROW")"
    [[ "$(row .read.hash)" == "$NOTICE_HASH" && "$(row .read.envelope.kind)" == "notice" \
       && "$(row '.read.envelope | has("answer_by")')" == "false" && "$(row '.read.envelope | has("reply_pubkey")')" == "false" \
       && "$(row .read.envelope.display.title)" == "$NOTICE_TITLE" ]] \
      && pass "NT1 the owner reads it: the run's hash, kind notice, no operation, no reply key" \
      || fail "NT1 the page read: hash '$(row .read.hash)' kind '$(row .read.envelope.kind)' title '$(row .read.envelope.display.title)'"
    status_of "$NOTICE"
    [[ "$(said .output.state)" == "open" && "$(said .output.kind)" == "notice" ]] \
      && pass "NT1 the agent reads it open" || fail "NT1 task_status: state '$(said .output.state)' kind '$(said .output.kind)'"
    if [[ -z "${PSQL_CMD:-}" ]]; then
      skip "NT1 no voucher: needs PSQL_CMD — $(what_is PSQL_CMD)"
    else
      VOUCHERS=$(sql_row "SELECT count(*) FROM owner_task_vouchers WHERE task_id = '$NOTICE'" 3)
      [[ "$VOUCHERS" == "0" ]] && pass "NT1 no voucher is kept for a notice" || fail "NT1 vouchers of the notice: '$VOUCHERS'"
    fi

    if want NT8; then
      log "NT8 the proof of a notice"
      owner proof "$NOTICE" "$NOW_ON"
      if [[ "$(own .attested)" == "false" ]]; then
        skip "NT8 the run $(own .run) has no attestation: this worker attests nothing"
      elif [[ "$(own .attested)" == "true" ]]; then
        [[ "$(own .answer_matches)" == "true" && "$(own .names_task)" == "true" && "$(own .names_another_hash)" == "false" ]] \
          && pass "NT8 the attested answer names the notice with the hash of what the page opened" \
          || fail "NT8 matches=$(own .answer_matches) names_task=$(own .names_task) another=$(own .names_another_hash)"
      else
        fail "NT8 the proof could not be read: $(own .failed | head -c 200)"
      fi
    fi

    if want NT2; then
      log "NT2 an approval sent to a notice"
      if prepare '{"title":"NT2 the task the approval is for"}'; then
        NONCE=$(openssl rand -base64 32)
        approves "$NOTICE" - - "$NOW_ON" --for "$TASK" --hash "$HASH" --nonce "$NONCE"
        [[ "$(own .status)" == "400" && "$(own .reason)" == "invalid_request" ]] \
          && pass "NT2 approve of a notice: 400" || fail "NT2 approve of a notice answered $(own .status) $(own .reason)"
        owner replay-approval "$NOTICE" "$NOW_ON" against "$TASK"
        if [[ "$(own .status)" == "200" && "$(own .state)" == "approved" ]]; then
          pass "NT2 the same signature and nonce then approve the task they were for"
          await_run "$TASK"
          [[ "$ENDED" == "done" ]] || fail "NT2 the approved task ended '$ENDED'"
        else
          fail "NT2 the same body on its task answered $(own .status) $(own .reason) state '$(own .state)'"
        fi
        in_inbox "$NOTICE" "$NOW_ON" && [[ "$(row .state)" == "open" ]] \
          && pass "NT2 the notice is as it was" || fail "NT2 the notice after the approval: '$(row .state)'"
      else
        fail "NT2 prepare: error='$(said .error | head -c 200)'"
      fi
    fi

    if want NT3; then
      log "NT3 Got it"
      owner reject "$NOTICE" "" "$NOW_ON"
      [[ "$(own .status)" == "400" && "$(own .body.reason)" == "invalid_request" ]] \
        && pass "NT3 a reject of a notice: 400" || fail "NT3 reject of a notice answered $(own .status) $(own .body.reason)"
      owner got-it "$NOTICE" "$NOW_ON"
      [[ "$(own .status)" == "200" && "$(own .body.state)" == "done" ]] \
        && pass "NT3 Got it: done" || fail "NT3 Got it answered $(own .status) $(own .body.reason) $(own .body.state)"
      status_of "$NOTICE"
      [[ "$(said .output.state)" == "done" && -z "$(said .output.run)" ]] \
        && pass "NT3 the agent reads it done, with no run" || fail "NT3 task_status after Got it: '$(said .output.state)' run '$(said .output.run)'"
      gone_from_inbox NT3 "$NOTICE" "$NOW_ON" && pass "NT3 it left the inbox"
      owner got-it "$NOTICE" "$NOW_ON"
      [[ "$(own .status)" == "409" && "$(own .body.reason)" == "task_closed" ]] \
        && pass "NT3 a second Got it: 409 task_closed" || fail "NT3 a second Got it answered $(own .status) $(own .body.reason)"
      if prepare '{"title":"NT3 a task, not a notice"}'; then
        owner got-it "$TASK" "$NOW_ON"
        [[ "$(own .status)" == "400" ]] && pass "NT3 Got it on a task that takes an answer: 400" \
          || fail "NT3 Got it on a confirm answered $(own .status) $(own .body.reason)"
      fi
      if notify '{"title":"NT3 deleted unseen"}'; then
        owner delete "$TASK" "$NOW_ON"
        status_of "$TASK"
        [[ "$(code)" == "task_not_found" ]] && pass "NT3 a deleted notice: the agent finds nothing" \
          || fail "NT3 after a delete the agent read '$(said .output.state)' error '$(said .error | head -c 120)'"
      else
        fail "NT3 notify: error='$(said .error | head -c 200)'"
      fi
    fi
  else
    fail "NT1 notify: error='$(said .error | head -c 200)' run=$RUN_OK/$RUN_ERR"
  fi
fi

if want NT4; then
  log "NT4 a run on chain notifies"
  acts '{"operation":"notify","title":"NT4 from a transaction"}'
  if [[ "$(said .success)" == "true" && "$(said .output.status)" == "notified" ]]; then
    TASK=$(said .output.task_id)
    pass "NT4 a run with no payment key notified: $TASK"
    in_inbox "$TASK" "$NOW_ON"
    [[ "$(row .kind)" == "notice" && "$(row .preparer)" == "$PARENT" && "$(row .read.envelope.display.title)" == "NT4 from a transaction" ]] \
      && pass "NT4 the owner reads it, the owner's own" || fail "NT4 the listed row: $(jq -c 'del(.read)' <<<"$ROW")"
  else
    fail "NT4 the owner's call answered success=$(said .success) status='$(said .output.status)' error='$(said .error | head -c 200)' run=$RUN_OK/$RUN_ERR"
  fi
  acts '{"operation":"prepare","title":"NT4 a confirm from a transaction"}'
  expect_refusal NT4 task_no_payment_key
fi

if want NT5; then
  log "NT5 who may notify"
  store_row "$POLICY_V1" '"AllowAll"'
  agent '{"operation":"notify"}'
  expect_refusal NT5 not_granted_by_name
  store_row "$POLICY_V1" "$GRANTED"
  owner mute agent "$AGENT_ACCOUNT" "$NOW_ON"
  agent '{"operation":"notify"}'
  expect_refusal NT5 muted
  owner unmute agent "$AGENT_ACCOUNT" "$NOW_ON"
  if relay_lacks NT5; then :
  else
    relayed '{"operation":"notify"}'
    if [[ "$RUN_OK" == "absent" ]]; then
      skip "NT5 the relayed run gave no completion event, so nothing was judged"
    else
      expect_refusal NT5 relayed
    fi
  fi
fi

if want NT6; then
  log "NT6 notices count in the agent's share"
  clear_tasks
  https_as AGENT_PAYMENT_KEY "$PARENT/$PROFILE" '{"operation":"prepare_many","count":5,"kind":"notice","title":"NT6"}'
  FIRST=$(said .output.opened); SEEN_FIRST=$(said '.output.tasks[0].task_id')
  https_as AGENT_PAYMENT_KEY "$PARENT/$PROFILE" '{"operation":"prepare_many","count":5,"kind":"notice","title":"NT6"}'
  if [[ "$FIRST" == "5" && "$(said .output.opened)" == "5" && "$(said .output.status)" == "notified" ]]; then
    pass "NT6 ten notices opened"
    prepare '{"title":"NT6 the eleventh, a confirm"}'
    expect_refusal NT6 inbox_full
    notify '{"title":"NT6 the eleventh, a notice"}'
    expect_refusal NT6 inbox_full
    owner got-it "$SEEN_FIRST" "$NOW_ON"
    [[ "$(own .status)" == "200" ]] || fail "NT6 Got it answered $(own .status) $(own .body.reason)"
    prepare '{"title":"NT6 after one was seen"}' && pass "NT6 one seen, and a task opens" \
      || fail "NT6 after Got it: error='$(said .error | head -c 200)'"
  else
    fail "NT6 opened $FIRST and $(said .output.opened): $(said .output.refused | head -c 200)"
  fi
  clear_tasks
fi

if want NT7; then
  log "NT7 a notice at the owner's URL"
  if lacks NT7 HOOK_URL HOOK_LOG_URL; then :
  else
    export HOOK_URL
    owner webhook set HOOK_URL "$NOW_ON"
    if [[ "$(own .status)" == "200" && "$(own .url_matches)" == "true" ]]; then
      HOOK_NAMED=true
      SHOWN_TITLE="NT7 title $(openssl rand -hex 6)"; SHOWN_BODY="NT7 body $(openssl rand -hex 6)"
      if notify "$(jq -nc --arg t "$SHOWN_TITLE" --arg b "$SHOWN_BODY" '{title:$t, body:$b}')"; then
        TOLD_TASK=$TASK
        if told HOOK_LOG_URL task_created "$TOLD_TASK" 9 "$SHOWN_TITLE" "$SHOWN_BODY"; then
          judge_event NT7 task_created
          [[ "$(event .kind)" == "notice" ]] && pass "NT7 the event says kind notice" || fail "NT7 the event's kind is '$(event .kind)'"
          [[ "$(jq -r '.leaked | length' <<<"$HOOK")" == "0" ]] && pass "NT7 nothing of what the notice shows reached the receiver" \
            || fail "NT7 $(jq -r '.leaked | length' <<<"$HOOK") of what the notice shows found in a body"
        else
          fail "NT7 task_created of $TOLD_TASK did not reach the receiver: $(jq -r '.failed // "not among the events"' <<<"$HOOK")"
        fi
        owner got-it "$TOLD_TASK" "$NOW_ON"
        # The events of the notice are sent within seconds of their move;
        # the receiver's log is read once that long has passed.
        sleep 20
        hook_log HOOK_LOG_URL
        AFTER=$(jq -r --arg t "$TOLD_TASK" '[.events[]? | select(.task_id == $t and .type != "task_created")] | length' <<<"$HOOK" 2>/dev/null)
        [[ "$AFTER" == "0" ]] && pass "NT7 Got it sends no event" || fail "NT7 events after Got it: $AFTER"
      else
        fail "NT7 notify: error='$(said .error | head -c 200)'"
      fi
    else
      fail "NT7 naming the URL answered $(own .status)"
    fi
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
