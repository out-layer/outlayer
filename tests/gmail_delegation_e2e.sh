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
#       AGENT2_PAYMENT_KEY and AGENT2_ACCOUNT, both funded keys
#
# A send the owner approves. The owner's page is played by
# `lib/tasks_owner.mjs`: it signs in with the owner's wallet key, reads the
# inbox on a device of its own, and approves with one signature of that key —
# no transaction. The platform then runs the connector's `confirm` as the
# agent, on the agent's payment key, and that run sends. The rows are named
# GT, so that ONLY tells them from the rows above.
#
#   GT1  with `confirm: ["send"]` in the owner's policy the agent's `send`
#        answers awaiting_owner with the task's id, hash and link, and no
#        message id; the task waits in the owner's inbox under that hash; the
#        agent's `task_status` says open, and its counter did not move
#   GT2  the owner's approval, signed, moves the task to approved with the run
#        the platform started; that run — the agent's, by the attestation's
#        payment_key_owner — sends the message once: the agent's `task_status`
#        says done with the message id and the run, and its confirmed count
#        moved; approving again is refused 409 task_closed and the result
#        stays the one message
#   GT3  with no `confirm` in the policy `send` acts at once: the answer has
#        the members of a sent message and none of a task, and neither the
#        owner's inbox nor the agent's `tasks` gains one
#   GT4  a message with an attachment under `confirm`: the task lists the file
#        by name and size, the owner's page opens it to the same bytes
#        (sha256), and the agent's run on the owner's approval sends it with
#        one attachment. The file is made here: 512 bytes, the same every run
#   GT5  the prices on chain: `confirm`, `task_status`, `task_cancel`,
#        `task_delete`, `tasks` and `tasks_unlock` cost 0 and `send` costs
#        GMAIL_SEND_PRICE. SKIPs when the project has no price rows
#
# Every send is a REAL email to GMAIL_TEST_TO and to no other address: one for
# G2, one for G1, up to six for G4, one each for GT2, GT3 and GT4 — the GT2 and
# GT4 sends by the run the platform starts on the owner's approval. Whatever
# happens, the capped policy is put back on exit, and the tasks the GT rows
# made are deleted.
#
# Needs: PARENT (the owner; the CLI logged in as it), AGENT_PAYMENT_KEY and
# AGENT_ACCOUNT (a custody wallet the owner grants), GMAIL_TEST_TO (an address
# the policy allows), and one of two owner rows:
#   token      GMAIL_ENV (default connectors/gmail-connector/.env.gmail:
#              CLIENT_ID, SECRET, REFRESH_TOKEN) — the suite writes the row
#              itself, whitelist PARENT + AGENT_ACCOUNT, under its own capped
#              policy. The credential is read into this shell, never exported,
#              never printed; it reaches jq through the environment of that one
#              process and `outlayer secrets set` as an argument, visible to `ps`
#              on this machine for the length of the call.
#   connected  no GMAIL_ENV, or one without REFRESH_TOKEN: the row the owner
#              connected through the dashboard, used as it is. The credential is
#              never written. The owner's policy, read through `status`, is the
#              one every row expects and the one put back; G1/G4 change only
#              GMAIL_POLICY (`outlayer secrets update`, merged by the keystore)
#              and G4 only the whitelist (`update_access`), both restored.
#              AGENT_ACCOUNT must already be on the row's whitelist. Without
#              GMAIL_TEST_TO the sends SKIP.
#
# GT1–GT4 need, besides: `node`; the owner's key file (OWNER_KEY_FILE, default
# ~/.near-credentials/<network>/<PARENT>.json), which signs the owner's
# statement; NEAR on PARENT for DEPOSIT (default `0.1 NEAR`), attached to each
# approve. Signing in here is one device more of the owner's, signed out when
# the suite ends; the owner's own devices stay signed in. On a connected row they run only when
# `status` tells whether the owner's policy lists `confirm`; a policy whose
# `confirm` cannot be read could not be put back as it was, and the rows SKIP.
# GT5 reads the chain and needs nothing more; GMAIL_SEND_PRICE (default 10000)
# is the price `send` is expected to have.
#
# Run:
#   PARENT=you.testnet AGENT_PAYMENT_KEY=… AGENT_ACCOUNT=… GMAIL_TEST_TO=… \
#     ./tests/gmail_delegation_e2e.sh --apply
#   ONLY=GT1,GT2 … --apply     some rows
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
# What the owner's own call attaches, and the price `send` is expected to have.
DEPOSIT="${DEPOSIT:-0.1 NEAR}"
GMAIL_SEND_PRICE="${GMAIL_SEND_PRICE:-10000}"
ONLY="${ONLY:-}"
# Row selection, the way every suite spells it: ONLY unset runs everything.
want() { [[ -z "$ONLY" ]] || [[ ",$ONLY," == *",$1,"* ]]; }
APPLY=false; [[ "${1:-}" == "--apply" ]] && APPLY=true

if [[ "$APPLY" != true ]]; then
  sed -n '3,83p' "$0" >&2; echo "  Pass --apply to run." >&2; exit 0
fi
[[ -n "$PARENT" ]] || { echo "✗ PARENT is required" >&2; exit 1; }
# Which owner row: a file with a REFRESH_TOKEN line is the token path; anything
# else is the row the owner connected. Only the line's presence is read here.
CONNECTED=true
[[ -r "$GMAIL_ENV" ]] && grep -q '^REFRESH_TOKEN=.' "$GMAIL_ENV" && CONNECTED=false
REQUIRED="AGENT_PAYMENT_KEY AGENT_ACCOUNT"; [[ "$CONNECTED" == true ]] || REQUIRED="$REQUIRED GMAIL_TEST_TO"
for v in $REQUIRED; do
  [[ -n "${!v}" ]] || { echo "✗ $v is required" >&2; exit 1; }
done
hos_require
PROJECT="$GMAIL"
source "$SCRIPT_DIR/lib/secrets_common.sh"

# gmail <input-json> [payment-key] — an AGENT calls, naming the OWNER's row.
gmail() {
  https_post "${2:-$AGENT_PAYMENT_KEY}" "$GMAIL" \
    "$(jq -nc --argjson i "$1" --arg o "$PARENT" '{input:$i, secrets_ref:{account_id:$o, profile:"gmail"}}')"
}

ACCESS_CHANGED=false
if [[ "$CONNECTED" == false ]]; then
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
  CONFIRM_KNOWN=true
else
  # The connected row, as the chain holds it, and the owner's policy, as the
  # connector reads it over HTTPS (every field of it, in the clear).
  ORIG_ACCESS=$(jq -c '.access // empty' <<<"$(row_of "$GMAIL" gmail)" 2>/dev/null)
  [[ -n "$ORIG_ACCESS" ]] || { echo "✗ $PARENT has no gmail row for $GMAIL — connect one in the dashboard, or give GMAIL_ENV" >&2; exit 1; }
  jq -e --arg a "$AGENT_ACCOUNT" '.Whitelist.accounts // [] | index($a) != null' <<<"$ORIG_ACCESS" >/dev/null \
    || { echo "✗ $AGENT_ACCOUNT is not on the connected row's whitelist ($(jq -c . <<<"$ORIG_ACCESS"))" >&2; exit 1; }
  gmail '{"operation":"status"}'
  CAPPED=""
  # Whether the owner asks to confirm is known only when `status` has the
  # member, whatever it holds: a policy read without it cannot be put back.
  CONFIRM_KNOWN=false
  if [[ "$RUN_OK" == "true" && "$(field .output.policy.present)" == "true" && "$(field .output.policy.readable)" != "false" ]]; then
    CAPPED=$(jq -c '.output.policy | del(.present) | with_entries(select(.value != null))' <<<"$RUN_OUT")
    [[ "$(field '.output.policy | has("confirm")')" == "true" ]] && CONFIRM_KNOWN=true
  fi
  note "connected row: access $(jq -c . <<<"$ORIG_ACCESS"), the owner's policy ${CAPPED:-UNREADABLE (success=$RUN_OK err='$(head -c 120 <<<"$RUN_ERR")')}"
fi
NO_POLICY='{}'
CAPLESS=$(jq -c 'del(.max_per_day)' <<<"${CAPPED:-$NO_POLICY}")
EXPECT_PREFIX=$(jq -r '.subject_prefix // ""' <<<"${CAPPED:-$NO_POLICY}")
EXPECT_CAP=$(jq -r '.max_per_day // ""' <<<"${CAPPED:-$NO_POLICY}")
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
# The connected row's policy, merged in by the keystore (`secrets update`): the
# credential is neither read nor sent, and the row keeps its condition.
update_policy() { # update_policy <policy-json>
  local before out
  before=$(jq -r '.updated_at // 0' <<<"$(row_of "$GMAIL" gmail)")
  out=$(OUTLAYER_NETWORK="$NETWORK" "$OUTLAYER_BIN" secrets update "$(jq -nc --arg p "$1" '{GMAIL_POLICY:$p}')" \
        --project "$GMAIL" --profile gmail 2>&1) \
    || { echo "✗ could not update the policy of $GMAIL/gmail: $(tail -1 <<<"$out" | head -c 200)" >&2; exit 1; }
  wait_row_after "$GMAIL" gmail "$before" || { echo "✗ $GMAIL/gmail policy update never became final" >&2; exit 1; }
  note "updated the policy of $GMAIL/gmail to $1"
}
# The connected row's whitelist, widened by `update_access` (the ciphertext
# stays) and put back to what the chain held at the start.
grant_access() { # grant_access <account…>
  local want
  want=$(jq -c 'reduce $ARGS.positional[] as $a (.; if (.Whitelist.accounts | index($a)) then . else .Whitelist.accounts += [$a] end)' \
    --args "$@" <<<"$ORIG_ACCESS")
  [[ "$want" == "$ORIG_ACCESS" ]] && return 0
  ACCESS_CHANGED=true
  set_access "$GMAIL" gmail "$want"
}
restore_access() {
  [[ "$ACCESS_CHANGED" == true ]] || return 0
  set_access "$GMAIL" gmail "$ORIG_ACCESS"
  ACCESS_CHANGED=false
}
store_policy() { # store_policy <policy-json> [more grantees…] — the owner's row, granted to the agent(s)
  local pol=$1; shift
  POLICY_ASKED="$pol"
  if [[ "$CONNECTED" == true ]]; then
    update_policy "$pol"
    if (( $# )); then grant_access "$@"; else restore_access; fi
  else
    local grant="whitelist:$PARENT,$AGENT_ACCOUNT"; for a in "$@"; do grant="$grant,$a"; done
    store "$GMAIL" gmail "$(credential_with "$pol")" "$grant"
  fi
  POLICY_CONFIRMED="$pol"
}
restore_cap() {
  if [[ "$ACCESS_CHANGED" == true ]]; then
    note "putting the connected row's access back before exit"
    ( restore_access ) || echo "✗ THE ACCESS WAS NOT RESTORED — set $GMAIL/gmail back to $ORIG_ACCESS by hand" >&2
    ACCESS_CHANGED=false
  fi
  if [[ -n "$POLICY_ASKED" && ( "$POLICY_ASKED" != "$CAPPED" || "$POLICY_CONFIRMED" != "$CAPPED" ) ]]; then
    note "putting the owner's policy back before exit"
    ( store_policy "$CAPPED" ) || echo "✗ THE POLICY WAS NOT RESTORED — store $CAPPED for $GMAIL by hand" >&2
  fi
}

# The owner, for the rows about a send the owner confirms.
OWNER_KEY_FILE="${OWNER_KEY_FILE:-$HOME/.near-credentials/$NETWORK/$PARENT.json}"
STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/gmail-tasks-e2e.XXXXXX")"
chmod 700 "$STATE_DIR"
# The owner's page, the approval and the run it starts: lib/tasks_common.sh.
# The page prints no key and no token, and what it reads of a task stays in
# OWN: a row prints a fact about it.
source "$SCRIPT_DIR/lib/tasks_common.sh"
# The connector's task_status answer, for the library.
task_field() { field ".output$1"; }
# The code a refusal of the connector opens with.
code() { local e; e=$(field .error); printf '%s' "${e%%:*}"; }
status_of() { gmail "$(jq -nc --arg t "$1" '{operation:"task_status", task_id:$t}')"; }
# How many tasks wait in the owner's inbox, or nothing when it was not read.
inbox_count() {
  owner list a waiting
  jq -r 'if (.tasks | type) == "array" then (.tasks | length) else empty end' <<<"$OWN" 2>/dev/null
}
# How many tasks the agent made for this owner, or nothing when not answered.
agent_count() {
  gmail '{"operation":"tasks"}'
  jq -r 'if .success == true and (.output.tasks | type) == "array" then (.output.tasks | length) else empty end' <<<"$RUN_OUT" 2>/dev/null
}
SIGNED_IN=false
# owner_ready <row> — the owner's page signed in on a device. A task is sealed
# to the devices in force when it is made, so this comes before any send.
owner_ready() {
  [[ "$SIGNED_IN" == true ]] && return 0
  if ! command -v node >/dev/null; then
    skip "$1 node is not installed: it plays the owner's page"; return 1
  fi
  if [[ ! -r "$OWNER_KEY_FILE" ]]; then
    skip "$1 no readable key file of $PARENT (OWNER_KEY_FILE): the owner's statement is signed with it"; return 1
  fi
  owner sign-in a
  if [[ "$(own .status)" == "200" && "$(own .token_returned)" == "true" && "$(own .account_id)" == "$PARENT" ]]; then
    SIGNED_IN=true
    note "the owner signed in on a device"
    return 0
  fi
  fail "$1 the owner's sign-in answered '$(own .status)': $(own '.reason // .error // .failed' | head -c 160)"
  return 1
}
# The tasks the rows made, deleted by the owner, or by the agent that made
# them when the owner's page cannot. One that stays is named.
MADE_TASKS=()
delete_made_tasks() {
  (( ${#MADE_TASKS[@]} > 0 )) || return 0
  local t left=()
  for t in "${MADE_TASKS[@]}"; do
    if [[ "$SIGNED_IN" == true ]]; then
      owner delete "$t" a
      if [[ "$(own .status)" == "200" && "$(own .body.deleted)" == "1" ]]; then note "deleted the task $t"; continue; fi
    fi
    gmail "$(jq -nc --arg t "$t" '{operation:"task_delete", task_id:$t}')"
    if [[ "$(field .output.deleted)" == "true" ]]; then note "deleted the task $t"; continue; fi
    if [[ "$(field .success)" == "false" && "$(code)" == "task_not_found" ]]; then note "the task $t is gone already"; continue; fi
    left+=("$t")
  done
  MADE_TASKS=()
  if (( ${#left[@]} > 0 )); then
    warn "TASKS NOT DELETED: ${left[*]} — delete them in the owner's inbox"
    MADE_TASKS=("${left[@]}")
  fi
  return 0
}
# The policy the chain holds now, and a store only when another is wanted.
policy_now() { printf '%s' "${POLICY_CONFIRMED:-$CAPPED}"; }
ensure_policy() { [[ "$(policy_now)" == "$1" ]] || store_policy "$1"; }
leave() {
  restore_cap
  delete_made_tasks
  if [[ "$SIGNED_IN" == true ]]; then owner sign-out a; SIGNED_IN=false; fi
  rm -rf "$STATE_DIR"
}
trap leave EXIT
# A connector call on a TRIAL key that has made its calls is refused for that —
# an answer that says nothing about the policy under test. `gmail_ready` makes
# the status call a row needs anyway and steps the row aside when a spent trial
# is what answered; the rows that cannot start
# with a status call ask `trial_spent` at each of their own refusals.
gmail_ready() { # gmail_ready <row> [key] — leaves the status answer in RUN_*
  gmail '{"operation":"status"}' "${2:-}"
  trial_spent "$RUN_ERR" || return 0
  skip "$1 the key is a spent TRIAL ($(head -c 80 <<<"$RUN_ERR")) — use a funded key, which has no call limit"
  return 1
}

RUN="$(date -u +%Y%m%dT%H%M%SZ)"

if [[ "$CONNECTED" == true ]]; then
  log "Fixture: the owner's connected row, as it is"
else
  log "Fixture: the owner's row, capped, granted to $AGENT_ACCOUNT"
  store_policy "$CAPPED"
fi
# A send is a real message: none without an address the owner's policy allows.
no_send() { [[ -z "$GMAIL_TEST_TO" ]] && skip "$1 — GMAIL_TEST_TO is not given, so no real message is sent"; }

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
  [[ "$G2_PREFIX" == "$EXPECT_PREFIX" ]] \
    && pass "G2 the OWNER's policy is the one in force (subject_prefix='$G2_PREFIX')" \
    || fail "G2 subject_prefix is '$G2_PREFIX', expected the owner's '$EXPECT_PREFIX'"

  if no_send "G2 the delegated send"; then :; else
  gmail "$(jq -nc --arg to "$GMAIL_TEST_TO" --arg s "delegated send $RUN" \
    --arg b "sent by an agent holding a grant on the owner row, named through secrets_ref" \
    '{operation:"send", to:$to, subject:$s, body:$b}')"
  if [[ "$RUN_OK" != "true" ]]; then
    fail "G2 the send did not run: success=$RUN_OK HTTP $HTTP_CODE err='$(head -c 160 <<<"$RUN_ERR")'"
  else
    [[ -n "$(field .output.message_id)" ]] \
      && pass "G2 a real message left the owner's mailbox: message_id=$(field .output.message_id)" \
      || fail "G2 the send answered without a message_id: $(head -c 200 <<<"$RUN_OUT")"
    if [[ -z "$EXPECT_CAP" ]]; then
      skip "G2 the owner's counter — the owner's policy has no max_per_day, so no counter moves"
    else
      [[ "$(field .output.sent_today)" == "$((G2_BEFORE + 1))" ]] \
        && pass "G2 and the owner's counter moved ($G2_BEFORE → $(field .output.sent_today))" \
        || fail "G2 sent_today is '$(field .output.sent_today)', expected $((G2_BEFORE + 1))"
      [[ "$(field .output.remaining_today)" == "$((EXPECT_CAP - G2_BEFORE - 1))" ]] \
        && pass "G2 and the remaining allowance is the owner's cap minus the sends" \
        || fail "G2 remaining_today is '$(field .output.remaining_today)', expected $((EXPECT_CAP - G2_BEFORE - 1))"
    fi
    skip "G2 the message's From is the owner's address — the send's answer carries no From header; read it in $GMAIL_TEST_TO's mailbox"
  fi
  fi
fi

# ── G1 a policy with no daily cap ────────────────────────────────────────────
if ! want G1; then
  :
elif [[ -z "$CAPPED" ]]; then
  skip "G1 the owner's policy could not be read, so it could not be put back — the row is left alone"
else
  log "G1 the owner stores the same credential with NO max_per_day"
  [[ "$CAPLESS" == "$CAPPED" ]] && note "G1 the owner's policy has no cap already: the capless store rewrites the same policy"
  store_policy "$CAPLESS"
  gmail '{"operation":"status"}'
  # A policy that is PRESENT and readable and has no cap — an absent or
  # unreadable policy has no max_per_day either.
  if [[ "$RUN_OK" == "true" && "$(field .output.policy.present)" == "true" && "$(field .output.policy.readable)" != "false" \
        && "$(field .output.policy.max_per_day)" == "" ]]; then
    pass "G1 status reads the policy back with no cap"
  elif trial_spent "$RUN_ERR"; then
    skip "G1 the key is a spent TRIAL ($(head -c 80 <<<"$RUN_ERR")) — the capless policy is stored and unread"
  else
    fail "G1 status: success=$RUN_OK recipients='$(field .output.policy.recipients)' max_per_day='$(field .output.policy.max_per_day)' (expected a policy with no cap)"
  fi
  if no_send "G1 the capless send"; then :; else
  gmail "$(jq -nc --arg to "$GMAIL_TEST_TO" --arg s "capless send $RUN" \
    --arg b "sent under a policy with no daily cap" \
    '{operation:"send", to:$to, subject:$s, body:$b}')"
  if trial_spent "$RUN_ERR"; then
    skip "G1 the send never reached the connector: the key is a spent TRIAL"
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
  fi

  log "G1 the owner's policy goes back — a live mailbox does not stay uncapped"
  store_policy "$CAPPED"
  gmail '{"operation":"status"}'
  if [[ "$RUN_OK" == "true" && "$(field .output.credential)" == "ok" && "$(field .output.policy.max_per_day)" == "$EXPECT_CAP" ]]; then
    pass "G1 the owner's policy is back (max_per_day='$(field .output.policy.max_per_day)', credential=$(field .output.credential))"
  elif trial_spent "$RUN_ERR"; then
    skip "G1 the restore was STORED but could not be read back — the key is a spent TRIAL; check max_per_day by hand"
  else
    fail "G1 THE POLICY WAS NOT RESTORED: success=$RUN_OK credential='$(field .output.credential)' max_per_day='$(field .output.policy.max_per_day)', expected '$EXPECT_CAP' — put it back by hand"
  fi
fi

# ── G4 the cap is per calling agent ─────────────────────────────────────────
if ! want G4; then
  :
elif [[ -z "$AGENT2_PAYMENT_KEY" || -z "$AGENT2_ACCOUNT" ]]; then
  skip "G4 needs AGENT2_PAYMENT_KEY and AGENT2_ACCOUNT (a second granted agent)"
elif no_send "G4 the per-agent cap (up to six real messages)"; then
  :
elif [[ -z "$CAPPED" ]]; then
  skip "G4 the owner's policy could not be read, so it could not be put back — the row is left alone"
elif [[ "$CONNECTED" == true ]] && ! jq -e '(keys == ["Whitelist"]) and (.Whitelist | keys == ["accounts"])' <<<"$ORIG_ACCESS" >/dev/null; then
  skip "G4 the connected row's access is not a plain whitelist ($(jq -c . <<<"$ORIG_ACCESS")) — the second agent is not added to it"
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
    elif trial_spent "$RUN_ERR"; then echo quota
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
    skip "G4 agent 1: the key is a TRIAL and its calls ran out after $G4_SENT of $A1_ROOM — the owner's cap is not what refused it"
  elif [[ "$G4_SENT" == "$A1_ROOM" && "$G4_REFUSED_AT" == "$(( A1_ROOM + 1 ))" ]]; then
    G4_JUDGED=true
    pass "G4 agent 1 sent its room ($A1_ROOM) and was refused by the cap on send #$G4_REFUSED_AT"
  else
    fail "G4 agent 1: sent $G4_SENT of room $A1_ROOM, refused at '${G4_REFUSED_AT:-never}' (expected #$(( A1_ROOM + 1 )))"
  fi

  # Agent 2 after agent 1 is capped: its own room, its own refusal past it.
  g4_agent agent2 "$AGENT2_PAYMENT_KEY" "$A2_ROOM"
  if [[ "$G4_QUOTA" == true ]]; then
    skip "G4 agent 2: the second key is a TRIAL and its calls ran out after $G4_SENT of $A2_ROOM — the owner's cap is not what refused it"
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

# ── GT a send the owner confirms ─────────────────────────────────────────────
# The policy GT1, GT2 and GT4 run under: the owner's, asking to confirm every
# send and allowing a file. The policy GT3 runs under: the owner's, asking for
# nothing. A task is void once the policy it was made under changes, so the
# policy stays as it is from a send to its `confirm`.
# A cap, the owner's or 50, so that the confirmed send is counted and GT2
# can read the count: a policy without `max_per_day` counts nothing.
ASKS=$(jq -c '.confirm = ["send"] | .max_attachment_kb = (.max_attachment_kb // 64) | .max_per_day = (.max_per_day // 50)' <<<"${CAPPED:-$NO_POLICY}")
ASKS_NOTHING=$(jq -c 'del(.confirm)' <<<"${CAPPED:-$NO_POLICY}")
# The subject as the connector sends it: the owner's prefix, then the subject.
GT_PREFIX=$(jq -rn --arg p "$EXPECT_PREFIX" '$p | gsub("^\\s+|\\s+$"; "")')
sent_subject() { if [[ -n "$GT_PREFIX" ]]; then printf '%s %s' "$GT_PREFIX" "$1"; else printf '%s' "$1"; fi; }
GT_TO=$(jq -rn --arg a "$GMAIL_TEST_TO" '$a | gsub("^\\s+|\\s+$"; "") | ascii_downcase')

# gt_ready <row> — what every row that sends or prepares needs, or a SKIP.
gt_ready() {
  if no_send "$1"; then return 1; fi
  if [[ -z "$CAPPED" ]]; then
    skip "$1 the owner's policy could not be read, so it could not be put back — the row is left alone"; return 1
  fi
  if [[ "$CONFIRM_KNOWN" != true ]]; then
    skip "$1 \`status\` does not tell whether the owner's policy lists \`confirm\`, so the policy could not be put back as it was — the row is left alone"; return 1
  fi
  owner_ready "$1" || return 1
  gmail_ready "$1" || return 1
  if [[ "$RUN_OK" != "true" || "$(field .output.credential)" != "ok" ]]; then
    fail "$1 control failed — the agent cannot read the owner's row: success=$RUN_OK err='$(head -c 160 <<<"$RUN_ERR")'"; return 1
  fi
  return 0
}
# gt_send <subject> <body> [attachments-json] — the agent's send, to GMAIL_TEST_TO.
gt_send() {
  gmail "$(jq -nc --arg to "$GMAIL_TEST_TO" --arg s "$1" --arg b "$2" --argjson a "${3:-[]}" \
    '{operation:"send", to:$to, subject:$s, body:$b} + (if ($a | length) > 0 then {attachments:$a} else {} end)')"
}
# gt_awaits <row> — judges the answer of a send under `confirm`; leaves TASK
# and HASH, and is true when a task was made.
TASK=""; HASH=""
gt_awaits() {
  TASK=""; HASH=""
  if trial_spent "$RUN_ERR"; then
    skip "$1 the send never reached the connector: the key is a spent TRIAL"; return 1
  fi
  if [[ "$RUN_OK" == "true" && -n "$(field .output.message_id)" ]]; then
    fail "$1 A MESSAGE WAS SENT (message_id=$(field .output.message_id)) under a policy that asks the owner first"; return 1
  fi
  if [[ "$RUN_OK" != "true" || "$(field .success)" != "true" || "$(field .output.status)" != "awaiting_owner" ]]; then
    fail "$1 the send answered run=$RUN_OK HTTP $HTTP_CODE success='$(field .success)' status='$(field .output.status)' code='$(code | head -c 60)' err='$(head -c 160 <<<"$RUN_ERR")', expected awaiting_owner"
    return 1
  fi
  TASK=$(field .output.task_id); HASH=$(field .output.task_hash)
  if [[ -z "$TASK" ]]; then
    fail "$1 awaiting_owner names no task_id"; return 1
  fi
  MADE_TASKS+=("$TASK")
  pass "$1 the send answered awaiting_owner, task $TASK"
  return 0
}
# gt_refused <row> <code> — the connector answered, and refused by that code.
gt_refused() {
  if [[ "$(field .success)" == "false" && "$(code)" == "$2" ]]; then
    pass "$1 refused $2"
  else
    fail "$1 expected the refusal $2, got success='$(field .success)' code='$(code | head -c 60)' message_id='$(field .output.message_id)' run=$RUN_OK"
  fi
}
if ! want GT1 && ! want GT2; then
  :
elif ! gt_ready "GT1/GT2"; then
  :
else
  log "GT1 the agent's send under confirm: [\"send\"]"
  GT1_BEFORE=$(field .output.sent_today)
  ensure_policy "$ASKS"
  GT1_SUBJECT="confirmed send $RUN"
  gt_send "$GT1_SUBJECT" "left for the owner to confirm, and sent by the agent's run on their approval"
  if gt_awaits GT1; then
    [[ "$HASH" =~ ^[0-9a-f]{64}$ ]] \
      && pass "GT1 the answer names the task's hash" \
      || fail "GT1 task_hash is not 64 hex characters (${#HASH} characters)"
    [[ "$(field .output.link)" == https://*"/inbox/$TASK" ]] \
      && pass "GT1 the answer carries the link to the task" \
      || fail "GT1 link is '$(field .output.link | head -c 120)', expected one that ends /inbox/$TASK"
    [[ "$(field '.output | has("message_id")')" == "false" ]] \
      && pass "GT1 the answer carries no message id" \
      || fail "GT1 the answer has a message_id member under a policy that asks the owner first"

    if in_inbox "$TASK" && [[ "$(row .read.hash)" == "$HASH" ]]; then
      pass "GT1 the task waits in the owner's inbox, and opens to the hash the run answered"
      [[ "$(row .read.envelope.owner)" == "$PARENT" && "$(row .read.envelope.preparer)" == "$AGENT_ACCOUNT" ]] \
        && pass "GT1 addressed to the owner, prepared by the agent" \
        || fail "GT1 owner/preparer: '$(row .read.envelope.owner)' / '$(row .read.envelope.preparer)'"
      if [[ "$(row .read.envelope.display.title)" == "Send an email" \
         && "$(row '.read.envelope.display.fields[0].values[0]')" == "$GT_TO" \
         && "$(jq -r --arg s "$(sent_subject "$GT1_SUBJECT")" '[.read.envelope.display.fields[] | select(.values[0] == $s)] | length' <<<"$ROW" 2>/dev/null)" == "1" ]]; then
        pass "GT1 the owner is shown the recipient and the subject of this send"
      else
        fail "GT1 shown: title '$(row .read.envelope.display.title | head -c 80)', $(row '.read.envelope.display.fields | length') field(s), first value matches the recipient: $([[ "$(row '.read.envelope.display.fields[0].values[0]')" == "$GT_TO" ]] && echo yes || echo no)"
      fi
    else
      fail "GT1 the task is not read in the inbox: '$(row '.unread // "not listed"' | head -c 120)' $(own .failed | head -c 120) (opened to the hash '$(row .read.hash | head -c 64)', the run answered '$HASH')"
    fi

    status_of "$TASK"
    [[ "$(field .output.state)" == "open" && "$(field '.output | has("result")')" == "false" ]] \
      && pass "GT1 the agent's task_status says open, with no result" \
      || fail "GT1 task_status: state '$(field .output.state)' code='$(code | head -c 60)'"
    gmail '{"operation":"status"}'
    [[ "$RUN_OK" == "true" && "$(field .output.sent_today)" == "$GT1_BEFORE" ]] \
      && pass "GT1 the agent's counter did not move ($GT1_BEFORE)" \
      || fail "GT1 sent_today is '$(field .output.sent_today)', it was '$GT1_BEFORE' before the send"

    if want GT2; then
      log "GT2 the owner approves, and the agent's run sends"
      if approved_and_done GT2 "$TASK"; then
        pass "GT2 approved with one signature: the platform started the run $RUN_OF, and the task ended done"
        GT2_MESSAGE=$(field .output.result.message_id)
        [[ -n "$GT2_MESSAGE" && "$(field .output.result.sent_today)" =~ ^[0-9]+$ && "$(field .output.result.sent_today)" -ge 1 ]] \
          && pass "GT2 the agent reads done, with the message sent (message_id=$GT2_MESSAGE) and its confirmed count at $(field .output.result.sent_today)" \
          || fail "GT2 task_status: result.message_id '$GT2_MESSAGE' sent_today '$(field .output.result.sent_today)' code='$(code | head -c 60)'"
        run_is_the_agents GT2 "$RUN_OF"
        gone_from_inbox GT2 "$TASK"

        log "GT2 the same approval again"
        owner replay-approval "$TASK" a
        [[ "$(own .status)" == "409" && "$(own .reason)" == "task_closed" ]] \
          && pass "GT2 the same approval again: 409 task_closed" \
          || fail "GT2 approving again answered $(own .status) reason='$(own .reason)' state='$(own .state)'"
        status_of "$TASK"
        [[ "$(field .output.state)" == "done" && "$(field .output.result.message_id)" == "$GT2_MESSAGE" ]] \
          && pass "GT2 the result is still the one message" \
          || fail "GT2 after the second approval: state '$(field .output.state)' result.message_id '$(field .output.result.message_id)', expected done with $GT2_MESSAGE"
      fi
    fi
  fi
fi

# ── GT4 a message with an attachment ─────────────────────────────────────────
if ! want GT4; then
  :
elif ! gt_ready GT4; then
  :
else
  log "GT4 a message with an attachment, under confirm"
  ensure_policy "$ASKS"
  # The file: 16 lines of 32 bytes, the same every run.
  GT4_FILE="$STATE_DIR/gt4-note.txt"
  for i in 00 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15; do
    printf 'outlayer gmail task file row %s\n' "$i"
  done > "$GT4_FILE"
  GT4_SIZE=$(wc -c < "$GT4_FILE" | tr -d ' ')
  GT4_SHA=$(openssl dgst -sha256 < "$GT4_FILE" | awk '{print $NF}')
  GT4_STARTS=$(head -c 16 "$GT4_FILE")
  GT4_FILES=$(jq -nc --arg d "$(base64 < "$GT4_FILE" | tr -d '\n')" \
    '[{filename:"gt4-note.txt", content_type:"text/plain", data:$d}]')
  if [[ "$GT4_SIZE" != "512" || ! "$GT4_SHA" =~ ^[0-9a-f]{64}$ ]]; then
    fail "GT4 the file was not made: $GT4_SIZE bytes, a hash of ${#GT4_SHA} characters"
  else
    gt_send "send with a file $RUN" "one file is attached" "$GT4_FILES"
    if gt_awaits GT4; then
      if in_inbox "$TASK" && [[ "$(row .read.hash)" == "$HASH" ]]; then
        [[ "$(row '.read.envelope.files | length')" == "1" && "$(row '.read.envelope.files[0].name')" == "gt4-note.txt" \
           && "$(row '.read.envelope.files[0].size')" == "$GT4_SIZE" ]] \
          && pass "GT4 the task lists the file by name and size (gt4-note.txt, $GT4_SIZE bytes)" \
          || fail "GT4 files listed: $(row '.read.envelope.files | length'), name '$(row '.read.envelope.files[0].name' | head -c 80)', size '$(row '.read.envelope.files[0].size')'"
        # The page opens a file only when its bytes hash to the hash the task
        # names; that hash against the one computed here is the comparison.
        owner file "$TASK" 0 a
        [[ "$(own .size)" == "$GT4_SIZE" && "$(own .sha256)" == "$GT4_SHA" && "$(own .starts)" == "$GT4_STARTS" ]] \
          && pass "GT4 the owner's page opened it to the same bytes (sha256 ${GT4_SHA:0:12}…)" \
          || fail "GT4 opening the file: size '$(own .size)' sha256 '$(own .sha256 | head -c 64)' (expected $GT4_SIZE, $GT4_SHA) $(own .failed | head -c 120)"

        if approved_and_done GT4 "$TASK"; then
          [[ -n "$(field .output.result.message_id)" && "$(field .output.result.attachments)" == "1" ]] \
            && pass "GT4 the agent's run sent it with one attachment: message_id=$(field .output.result.message_id)" \
            || fail "GT4 the result: message_id='$(field .output.result.message_id)' attachments='$(field .output.result.attachments)' code='$(code | head -c 60)'"
        fi
        skip "GT4 the message received carries the file — the answer counts attachments and cannot show the message; read it in $GMAIL_TEST_TO's mailbox"
      else
        fail "GT4 the task is not read in the inbox: '$(row '.unread // "not listed"' | head -c 120)' $(own .failed | head -c 120)"
      fi
    fi
  fi
fi

# ── GT3 no confirm in the policy ─────────────────────────────────────────────
if ! want GT3; then
  :
elif ! gt_ready GT3; then
  :
else
  log "GT3 with no confirm in the policy, send acts at once"
  ensure_policy "$ASKS_NOTHING"
  GT3_INBOX=$(inbox_count); GT3_MADE=$(agent_count)
  gt_send "send at once $RUN" "sent at once: the owner's policy asks for no confirmation"
  if trial_spent "$RUN_ERR"; then
    skip "GT3 the send never reached the connector: the key is a spent TRIAL"
  elif [[ "$RUN_OK" != "true" || "$(field .success)" != "true" ]]; then
    fail "GT3 the send did not run: run=$RUN_OK HTTP $HTTP_CODE success='$(field .success)' code='$(code | head -c 60)' err='$(head -c 160 <<<"$RUN_ERR")'"
    [[ -n "$(field .output.task_id)" ]] && MADE_TASKS+=("$(field .output.task_id)")
  else
    [[ -n "$(field .output.task_id)" ]] && MADE_TASKS+=("$(field .output.task_id)")
    [[ -n "$(field .output.message_id)" ]] \
      && pass "GT3 the message was sent at once: message_id=$(field .output.message_id)" \
      || fail "GT3 the send answered without a message_id (status '$(field .output.status)')"
    [[ "$(field '.output | keys | join(",")')" == "attachments,cc,message_id,remaining_today,sent_today,subject,thread_id,to" ]] \
      && pass "GT3 the answer has the members of a sent message, and none of a task" \
      || fail "GT3 the answer's members are '$(field '.output | keys | join(",")' | head -c 200)'"
    GT3_INBOX_AFTER=$(inbox_count); GT3_MADE_AFTER=$(agent_count)
    if [[ -z "$GT3_INBOX" || -z "$GT3_INBOX_AFTER" ]]; then
      fail "GT3 the owner's inbox was not read (before '$GT3_INBOX', after '$GT3_INBOX_AFTER')"
    elif [[ "$GT3_INBOX_AFTER" == "$GT3_INBOX" ]]; then
      pass "GT3 the owner's inbox did not gain a task ($GT3_INBOX waiting)"
    else
      fail "GT3 the owner's inbox went from $GT3_INBOX to $GT3_INBOX_AFTER waiting"
    fi
    if [[ -z "$GT3_MADE" || -z "$GT3_MADE_AFTER" ]]; then
      fail "GT3 the agent's tasks were not read (before '$GT3_MADE', after '$GT3_MADE_AFTER')"
    elif [[ "$GT3_MADE_AFTER" == "$GT3_MADE" ]]; then
      pass "GT3 the agent's tasks did not gain one ($GT3_MADE)"
    else
      fail "GT3 the agent's tasks went from $GT3_MADE to $GT3_MADE_AFTER"
    fi
  fi
fi

# The owner's policy goes back, and the tasks the rows made go.
if [[ -n "$CAPPED" && "$(policy_now)" != "$CAPPED" ]]; then
  log "GT the owner's policy goes back"
  store_policy "$CAPPED"
fi
delete_made_tasks

# ── GT5 the prices ───────────────────────────────────────────────────────────
if want GT5; then
  log "GT5 the prices on chain for $GMAIL"
  GT5_PRICING=$(near_view "$CONTRACT_ID" get_project_pricing "$(jq -nc --arg p "$GMAIL" '{project_id:$p}')")
  if ! jq -e '(.operations | type) == "array" and (.operations | length) > 0' <<<"$GT5_PRICING" >/dev/null 2>&1; then
    skip "GT5 $GMAIL has no price rows on chain (the contract answered '$(head -c 40 <<<"$GT5_PRICING" | tr -d '\n')') — connectors/gmail-connector/set-prices.sh sets them"
  else
    # gt5_price <operation> <price> — the one row of that operation.
    gt5_price() {
      local rows got
      rows=$(jq -r --arg o "$1" '[.operations[] | select(.operation == $o)] | length' <<<"$GT5_PRICING")
      got=$(jq -r --arg o "$1" '[.operations[] | select(.operation == $o)][0].price_usd // "" | tostring' <<<"$GT5_PRICING")
      if [[ "$rows" == "0" ]]; then
        skip "GT5 \`$1\` has no price row on chain — connectors/gmail-connector/set-prices.sh sets it"
      elif [[ "$rows" == "1" && "$got" == "$2" ]]; then
        pass "GT5 \`$1\` costs $2"
      else
        fail "GT5 \`$1\` has $rows price row(s) and costs '$got' on chain, expected one row of $2"
      fi
    }
    for op in confirm task_status task_cancel task_delete tasks tasks_unlock; do
      gt5_price "$op" 0
    done
    gt5_price send "$GMAIL_SEND_PRICE"
  fi
fi

verdict "gmail delegation"; RC=$?

# A suite whose central row never ran exits 3 (NOTHING), the same code the
# runner renders as "silent about what it covers". A real failure keeps its
# own status: 3 is for a run that judged nothing, not for one that judged and
# found something wrong.
if [[ "${G4_UNJUDGED:-false}" == true && $RC -eq 0 ]]; then RC=3; fi
exit $RC
