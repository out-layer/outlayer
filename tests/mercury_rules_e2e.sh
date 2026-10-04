#!/usr/bin/env bash
#
# Mercury's rules: which of an agent's writes run by themselves, which wait
# for the owner, which are refused — live, against Mercury's sandbox, through
# the one secret model (the owner's row, the agent's key, `secrets_ref`).
#
# The owner's page is played by `lib/tasks_owner.mjs`: it signs in with the
# owner's wallet key, reads the inbox on a device of its own, and approves with
# one signature of that key. The platform then runs the connector's `confirm`
# as the agent, on the agent's payment key, and that run pays.
#
#   MR0  the row's policy is read back through `status`, with `rules` as stored
#   MR1  under `pay_invoice from $1 → ask`, the agent's payment to a saved
#        payee answers awaiting_owner with the task's id, hash and link, and
#        no transaction or request id; the task waits in the owner's inbox
#        under that hash, showing the amount and the rule that asked; the
#        agent's task_status says open
#   MR2  the owner's approval, signed, starts the agent's run of `confirm`,
#        which pays once: task_status says done, with the payment (sent
#        directly, or queued by Mercury's own approval rules) for the amount
#        shown; the run was the agent's; approving again is 409 task_closed
#   MR3  a payment under the rule's bound runs at once: the answer is a
#        payment's, not a task's
#   MR4  `payee: new → refuse` refuses an inline payee, naming the rule, and
#        a payment to a saved payee still runs
#   MR5  a rule naming what its operation does not carry makes the policy
#        unreadable: `status` says broken and names the rule, and a payment
#        is refused with the same sentence
#   MR6  `add_recipient → ask` leaves the payee as a task and saves nothing:
#        the sandbox's payees are the same before and after; the agent
#        withdraws the task (task_cancel → cancelled)
#   MR7  the prices on chain: `confirm` and the five task operations cost 0,
#        `pay_invoice` its price; SKIP when the project has no price rows
#   MR8  a payment the owner approves and the bank then refuses — by ACH to a
#        saved payee Mercury cannot pay by ACH: the agent's task_status says
#        failed as `run_failed`, and `result.error` is the connector's own
#        refusal, saying the task is closed. Needs the coordinator and the
#        worker that keep a failed run's report
#
# Money: sandbox money only (`sandbox: true`, a sandbox token). Two payments
# of under $2 each to a payee saved in the sandbox, amounts unique to the run
# (Mercury refuses the same payee, account and amount twice in 24 hours).
#
# The row: PARENT's own, under the profile `mercury-rules-e2e` (never the
# owner's real `mercury` row), whitelisting PARENT and AGENT_ACCOUNT; deleted
# on exit with the tasks the rows made. The token is read into this shell, not
# exported, never printed; it reaches jq through the environment of one
# process and `outlayer secrets set` as an argument, visible to `ps` on this
# machine for the length of the call.
#
# Needs: PARENT (the owner; the CLI logged in as it), AGENT_PAYMENT_KEY and
# AGENT_ACCOUNT (a custody wallet the owner grants), MERCURY_SANDBOX_ENV
# (default .env.mercury_sandbox in the repo root) with the sandbox token under
# MERCURY_TOKEN_NAME (default TOKEN: read + write), `node`, the owner's key
# file (OWNER_KEY_FILE, default ~/.near-credentials/<network>/<PARENT>.json).
# MERCURY_PAY_PRICE (default 10000) is the price `pay_invoice` is expected to
# have.
#
# Run:
#   PARENT=you.testnet AGENT_PAYMENT_KEY=… AGENT_ACCOUNT=… ./tests/mercury_rules_e2e.sh --apply
#   ONLY=MR1,MR2 … --apply     some rows
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/hos_common.sh"

PARENT="${PARENT:-}"
MERCURY="${MERCURY:-connectors.outlayer.testnet/mercury}"
PROFILE="mercury-rules-e2e"
MERCURY_SANDBOX_ENV="${MERCURY_SANDBOX_ENV:-$SCRIPT_DIR/../.env.mercury_sandbox}"
MERCURY_TOKEN_NAME="${MERCURY_TOKEN_NAME:-TOKEN}"
AGENT_PAYMENT_KEY="${AGENT_PAYMENT_KEY:-}"
AGENT_ACCOUNT="${AGENT_ACCOUNT:-}"
MERCURY_PAY_PRICE="${MERCURY_PAY_PRICE:-10000}"
ONLY="${ONLY:-}"
want() { [[ -z "$ONLY" ]] || [[ ",$ONLY," == *",$1,"* ]]; }
APPLY=false; [[ "${1:-}" == "--apply" ]] && APPLY=true

if [[ "$APPLY" != true ]]; then
  sed -n '3,62p' "$0" >&2; echo "  Pass --apply to run." >&2; exit 0
fi
for v in PARENT AGENT_PAYMENT_KEY AGENT_ACCOUNT; do
  [[ -n "${!v}" ]] || { echo "✗ $v is required" >&2; exit 1; }
done
[[ -r "$MERCURY_SANDBOX_ENV" ]] || { echo "✗ $MERCURY_SANDBOX_ENV is not readable" >&2; exit 1; }
[[ "$MERCURY_TOKEN_NAME" =~ ^[A-Z_][A-Z0-9_]*$ ]] || { echo "✗ MERCURY_TOKEN_NAME is not a variable name" >&2; exit 1; }
hos_require
PROJECT="$MERCURY"
source "$SCRIPT_DIR/lib/secrets_common.sh"

# The sandbox token: one line of the env file, into this shell only.
SANDBOX_TOKEN=$(grep -E "^${MERCURY_TOKEN_NAME}=" "$MERCURY_SANDBOX_ENV" | head -1 | cut -d= -f2-)
SANDBOX_TOKEN="${SANDBOX_TOKEN%\"}"; SANDBOX_TOKEN="${SANDBOX_TOKEN#\"}"
[[ -n "$SANDBOX_TOKEN" ]] || { echo "✗ $MERCURY_SANDBOX_ENV has no $MERCURY_TOKEN_NAME" >&2; exit 1; }
note "sandbox token: present, ${#SANDBOX_TOKEN} characters"

# mercury <input-json> [payment-key] — the AGENT calls, naming the owner's row.
mercury() {
  https_post "${2:-$AGENT_PAYMENT_KEY}" "$MERCURY" \
    "$(jq -nc --argjson i "$1" --arg o "$PARENT" --arg p "$PROFILE" '{input:$i, secrets_ref:{account_id:$o, profile:$p}}')"
}
code() { local e; e=$(field .error); printf '%s' "${e%%:*}"; }
# The connector's own answer: `ok` when it succeeded, its refusal in `why`.
ok() { [[ "$RUN_OK" == "true" && "$(field .success)" == "true" ]]; }
why() { local e; e=$(field .error); printf '%s' "${e:-$RUN_ERR}" | head -c 240; }

# The owner's row: written whole the first time (the token and the policy),
# then only its policy, merged in by the keystore.
ROW_MADE=false
secrets_with() { # secrets_with <policy-json> → the secrets JSON
  T="$SANDBOX_TOKEN" jq -nc --argjson p "$1" '{MERCURY_API_TOKEN:env.T, MERCURY_POLICY:($p|tojson)}'
}
put_policy() { # put_policy <policy-json>
  local before out
  if [[ "$ROW_MADE" != true ]]; then
    store "$MERCURY" "$PROFILE" "$(secrets_with "$1")" "whitelist:$PARENT,$AGENT_ACCOUNT"
    ROW_MADE=true
    return
  fi
  before=$(jq -r '.updated_at // 0' <<<"$(row_of "$MERCURY" "$PROFILE")")
  out=$(OUTLAYER_NETWORK="$NETWORK" "$OUTLAYER_BIN" secrets update "$(jq -nc --arg p "$1" '{MERCURY_POLICY:$p}')" \
        --project "$MERCURY" --profile "$PROFILE" 2>&1) \
    || { echo "✗ could not update the policy: $(near_why "$out")" >&2; exit 1; }
  wait_row_after "$MERCURY" "$PROFILE" "$before" || { echo "✗ the policy update never became final" >&2; exit 1; }
  note "policy now $1"
}

# The owner's page and the approval: lib/tasks_common.sh.
OWNER_KEY_FILE="${OWNER_KEY_FILE:-$HOME/.near-credentials/$NETWORK/$PARENT.json}"
STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/mercury-rules-e2e.XXXXXX")"
chmod 700 "$STATE_DIR"
source "$SCRIPT_DIR/lib/tasks_common.sh"
task_field() { field ".output$1"; }
status_of() { mercury "$(jq -nc --arg t "$1" '{operation:"task_status", task_id:$t}')"; }

SIGNED_IN=false
owner_ready() {
  [[ "$SIGNED_IN" == true ]] && return 0
  command -v node >/dev/null || { skip "$1 node is not installed: it plays the owner's page"; return 1; }
  [[ -r "$OWNER_KEY_FILE" ]] || { skip "$1 no readable key file of $PARENT (OWNER_KEY_FILE)"; return 1; }
  owner sign-in a
  if [[ "$(own .status)" == "200" && "$(own .token_returned)" == "true" && "$(own .account_id)" == "$PARENT" ]]; then
    SIGNED_IN=true; note "the owner signed in on a device"; return 0
  fi
  fail "$1 the owner's sign-in answered '$(own .status)': $(own '.reason // .error // .failed' | head -c 160)"
  return 1
}

MADE_TASKS=()
leave() {
  local t
  for t in "${MADE_TASKS[@]}"; do
    if [[ "$SIGNED_IN" == true ]]; then
      owner delete "$t" a
      [[ "$(own .status)" == "200" ]] && { note "deleted the task $t"; continue; }
    fi
    mercury "$(jq -nc --arg t "$t" '{operation:"task_delete", task_id:$t}')"
    [[ "$(field .output.deleted)" == "true" ]] && note "deleted the task $t" || warn "TASK NOT DELETED: $t"
  done
  [[ "$SIGNED_IN" == true ]] && owner sign-out a
  if [[ "$ROW_MADE" == true ]]; then ( delete_row "$MERCURY" "$PROFILE" ) || warn "THE ROW $MERCURY/$PROFILE WAS NOT DELETED — delete it by hand"; fi
  rm -rf "$STATE_DIR"
}
trap leave EXIT

# Amounts unique to the run: Mercury refuses the same payee, account and
# amount twice within 24 hours.
CENTS=$(( (10#$(date +%S) * 7 + RANDOM) % 89 + 10 ))
ASKED_USD="1.$CENTS"      # at the rule's bound or over: waits for the owner
UNDER_USD="0.$CENTS"      # under it: runs at once

# ── Fixture: the row, the account, a saved payee ─────────────────────────────
log "Fixture: $PARENT's row $MERCURY/$PROFILE, granted to the agent"
BASE=$(jq -nc '{max_payment_usd: 50, max_spend_usd_month: 100000, allow_new_recipients: true, sandbox: true}')
put_policy "$BASE"
mercury '{"operation":"status"}'
if ! ok || [[ "$(field .output.token_valid)" != "true" ]]; then
  echo "✗ status: token_valid='$(field .output.token_valid)' note='$(field .output.token_note | head -c 160)': $(why)" >&2
  exit 1
fi
note "sandbox: $(field .output.sandbox), accounts: $(field .output.account_count)"
mercury '{"operation":"accounts"}'
ACCOUNT=$(field '[.output.accounts[]? | select(.status == "active" or .status == null)][0].id')
[[ -n "$ACCOUNT" ]] || { echo "✗ no account read: $(head -c 160 <<<"$RUN_ERR")" >&2; exit 1; }
mercury '{"operation":"recipients"}'
# A payee Mercury pays by ACH: one that names it as its default rail.
PAYEE=$(field '[.output.recipients[]? | select(.status != "deleted" and .default_payment_method == "ach")][0].id')
PAYEES_BEFORE=$(field '[.output.recipients[]? | select(.status != "deleted")] | length')
# One Mercury does not pay by ACH: the payment passes every check of ours and
# the bank refuses it after the owner's yes (MR8).
NOT_ACH=$(field '[.output.recipients[]? | select(.status != "deleted" and .default_payment_method != "ach")][0].id')
[[ -n "$PAYEE" ]] || { echo "✗ the sandbox has no saved payee paid by ACH: $(why)" >&2; exit 1; }
BASE=$(jq -c --arg a "$ACCOUNT" '. + {account_id: $a}' <<<"$BASE")
note "account $ACCOUNT, saved payee $PAYEE ($PAYEES_BEFORE saved)"

pay() { # pay <usd> [recipient-json]
  local who=${2:-}
  if [[ -n "$who" ]]; then
    mercury "$(jq -nc --argjson a "$1" --argjson r "$who" --arg n "mercury rules e2e $CENTS" '{operation:"pay_invoice", amount_usd:$a, recipient:$r, note:$n}')"
  else
    mercury "$(jq -nc --argjson a "$1" --arg r "$PAYEE" --arg n "mercury rules e2e $CENTS" '{operation:"pay_invoice", amount_usd:$a, recipient_id:$r, note:$n}')"
  fi
}
ASK_FROM_1='[{"when":{"op":"pay_invoice","min_usd":1},"then":"ask"}]'

# ── MR0 the policy reads back ────────────────────────────────────────────────
if want MR0; then
  log "MR0 the policy reads back, rules as stored"
  put_policy "$(jq -c --argjson r "$ASK_FROM_1" '. + {rules: $r}' <<<"$BASE")"
  mercury '{"operation":"status"}'
  RULES_READ=$(jq -c '.output.policy.rules' <<<"$RUN_OUT" 2>/dev/null)
  [[ "$RUN_OK" == "true" && "$(field .output.policy_mode)" == "active" \
     && "$(jq -r 'length == 1 and .[0].when.op == "pay_invoice" and .[0].when.min_usd == 1 and .[0].then == "ask"' <<<"$RULES_READ" 2>/dev/null)" == "true" ]] \
    && pass "MR0 status reports the rules as stored: $RULES_READ" \
    || fail "MR0 status: mode '$(field .output.policy_mode)' rules '$(head -c 200 <<<"$RULES_READ")' err '$(head -c 120 <<<"$RUN_ERR")'"
fi

# ── MR1/MR2 a payment that waits for the owner, approved ─────────────────────
if want MR1 || want MR2; then
  if owner_ready MR1; then
    log "MR1 a payment of \$$ASKED_USD under 'pay_invoice from \$1 → ask'"
    put_policy "$(jq -c --argjson r "$ASK_FROM_1" '. + {rules: $r}' <<<"$BASE")"
    pay "$ASKED_USD"
    TASK=$(field .output.task_id); HASH=$(field .output.task_hash)
    if ok && [[ "$(field .output.status)" == "awaiting_owner" && -n "$TASK" ]]; then
      MADE_TASKS+=("$TASK")
      pass "MR1 the payment answers awaiting_owner (task $TASK)"
      [[ "$HASH" =~ ^[0-9a-f]{64}$ ]] && pass "MR1 the answer names the task's hash" || fail "MR1 task_hash '$HASH'"
      [[ "$(field .output.link)" == */inbox/"$TASK" ]] && pass "MR1 the answer carries the link to the task" || fail "MR1 link '$(field .output.link)'"
      [[ -z "$(field .output.transaction_id)$(field .output.request_id)$(field .output.sent_via)" ]] \
        && pass "MR1 nothing was sent: no transaction, no request, no sent_via" \
        || fail "MR1 the answer carries a payment: $(jq -c '.output' <<<"$RUN_OUT" | head -c 200)"
      if in_inbox "$TASK" a && [[ "$(row .read.hash)" == "$HASH" ]]; then
        pass "MR1 the task waits in the owner's inbox under the hash the run answered"
        [[ "$(shown Amount)" == "\$$ASKED_USD" ]] && pass "MR1 the owner is shown the amount, \$$ASKED_USD" || fail "MR1 Amount shown '$(shown Amount)'"
        [[ "$(shown 'Why you are asked')" == *"rule 1"* ]] && pass "MR1 the owner is shown the rule that asked: $(shown 'Why you are asked')" || fail "MR1 why: '$(shown 'Why you are asked')'"
        [[ "$(shown To)" == *"$PAYEE"* ]] && pass "MR1 the owner is shown the payee" || fail "MR1 To shown '$(shown To | head -c 120)'"
      else
        fail "MR1 the task is not read in the inbox: '$(row '.unread // "not listed"' | head -c 120)' $(own .failed | head -c 120)"
      fi
      status_of "$TASK"
      [[ "$(field .output.state)" == "open" ]] && pass "MR1 the agent's task_status says open" || fail "MR1 task_status '$(field .output.state)': $(why)"

      if want MR2; then
        log "MR2 the owner approves, and the agent's run pays"
        if ! approved_and_done MR2 "$TASK"; then
          note "MR2 the task as the agent reads it: $(jq -c '.output' <<<"$RUN_OUT" | head -c 600)"
        else
          SENT_VIA=$(field .output.result.sent_via)
          PAID_ID="$(field .output.result.transaction_id)$(field .output.result.request_id)"
          [[ ( "$SENT_VIA" == "direct" || "$SENT_VIA" == "approval_request" ) && -n "$PAID_ID" && "$(field .output.result.amount_usd)" == "$ASKED_USD" ]] \
            && pass "MR2 done: paid \$$ASKED_USD, sent_via $SENT_VIA ($PAID_ID)" \
            || fail "MR2 result: sent_via '$SENT_VIA' id '$PAID_ID' amount '$(field .output.result.amount_usd)'"
          run_is_the_agents MR2 "$RUN_OF" "$AGENT_ACCOUNT" "$MERCURY"
          gone_from_inbox MR2 "$TASK"
          owner replay-approval "$TASK" a
          [[ "$(own .status)" == "409" && "$(own .reason)" == "task_closed" ]] \
            && pass "MR2 the same approval again: 409 task_closed" \
            || fail "MR2 approving again answered $(own .status) reason='$(own .reason)' state='$(own .state)'"
          status_of "$TASK"
          [[ "$(field .output.state)" == "done" && "$(field .output.result.transaction_id)$(field .output.result.request_id)" == "$PAID_ID" ]] \
            && pass "MR2 the result is still the one payment" \
            || fail "MR2 after the second approval: state '$(field .output.state)', payment '$(field .output.result.transaction_id)$(field .output.result.request_id)', expected done with $PAID_ID"
        fi
      fi
    else
      fail "MR1 the payment answered status '$(field .output.status)': $(why)"
    fi
  fi
fi

# ── MR3 under the bound: runs at once ────────────────────────────────────────
if want MR3; then
  log "MR3 a payment of \$$UNDER_USD, under the rule's bound"
  put_policy "$(jq -c --argjson r "$ASK_FROM_1" '. + {rules: $r}' <<<"$BASE")"
  pay "$UNDER_USD"
  ok && [[ -n "$(field .output.sent_via)" && -z "$(field .output.task_id)" ]] \
    && pass "MR3 paid at once: sent_via $(field .output.sent_via), no task" \
    || fail "MR3 sent_via '$(field .output.sent_via)' task '$(field .output.task_id)': $(why)"
fi

# ── MR4 a refused payee ──────────────────────────────────────────────────────
if want MR4; then
  log "MR4 'payee: new → refuse'"
  put_policy "$(jq -c '. + {rules: [{when:{op:"pay_invoice", payee:"new"}, then:"refuse"}]}' <<<"$BASE")"
  NEW_PAYEE=$(jq -nc --arg c "$CENTS" '{name:("Rules E2E " + $c), account_number:"000123456789", routing_number:"021000021",
    address:{address1:"1 Main St", city:"Springfield", region:"IL", postal_code:"62701"}}')
  pay "0.$CENTS" "$NEW_PAYEE"
  ! ok && [[ "$(why)" == *"policy_denied: the owner's rule 1 (payments to new payees) refuses this payment"* ]] \
    && pass "MR4 an inline payee is refused, naming the rule" \
    || fail "MR4 success=$(field .success): $(why)"
fi

# ── MR5 an unreadable rule ───────────────────────────────────────────────────
if want MR5; then
  log "MR5 a rule bounding the amount of a cancellation"
  put_policy "$(jq -c '. + {rules: [{when:{op:"cancel_invoice", min_usd:1}, then:"ask"}]}' <<<"$BASE")"
  mercury '{"operation":"status"}'
  [[ "$(field .output.policy_mode)" == "broken" && "$(field .output.policy_note)" == *"rule 1 bounds an amount, and cancel_invoice carries none"* ]] \
    && pass "MR5 status: broken, naming rule 1" \
    || fail "MR5 status mode '$(field .output.policy_mode)' note '$(field .output.policy_note | head -c 200)'"
  pay "0.$CENTS"
  ! ok && [[ "$(why)" == *"rule 1 bounds an amount"* ]] \
    && pass "MR5 a payment is refused with the same sentence" \
    || fail "MR5 success=$(field .success): $(why)"
fi

# ── MR6 a payee that waits, withdrawn ────────────────────────────────────────
if want MR6; then
  log "MR6 'add_recipient → ask', then withdrawn"
  put_policy "$(jq -c '. + {rules: [{when:{op:"add_recipient"}, then:"ask"}]}' <<<"$BASE")"
  ADD=$(jq -nc --arg c "$CENTS" '{operation:"add_recipient", name:("Rules E2E payee " + $c), account_number:"000987654321", routing_number:"021000021",
    address:{address1:"2 Main St", city:"Springfield", region:"IL", postal_code:"62701"}}')
  mercury "$ADD"
  T6=$(field .output.task_id)
  if ok && [[ "$(field .output.status)" == "awaiting_owner" && -n "$T6" ]]; then
    MADE_TASKS+=("$T6")
    pass "MR6 add_recipient answers awaiting_owner (task $T6)"
    mercury '{"operation":"recipients"}'
    [[ "$(field '[.output.recipients[]? | select(.status != "deleted")] | length')" == "$PAYEES_BEFORE" ]] \
      && pass "MR6 nothing was saved: still $PAYEES_BEFORE payees" \
      || fail "MR6 payees now $(field '[.output.recipients[]? | select(.status != "deleted")] | length'), were $PAYEES_BEFORE"
    mercury "$(jq -nc --arg t "$T6" '{operation:"task_cancel", task_id:$t}')"
    [[ "$(field .output.state)" == "cancelled" ]] && pass "MR6 the agent withdrew it: cancelled" || fail "MR6 task_cancel: $(why)"
  else
    fail "MR6 status '$(field .output.status)': $(why)"
  fi
fi

# ── MR7 prices ───────────────────────────────────────────────────────────────
if want MR7; then
  log "MR7 the prices on chain"
  PRICING=$(near_view "$CONTRACT_ID" get_project_pricing "$(jq -nc --arg p "$MERCURY" '{project_id:$p}')")
  if [[ -z "$PRICING" || "$PRICING" == "null" || "$PRICING" == "ERR" ]]; then
    skip "MR7 the project has no price rows"
  else
    price() { jq -r --arg o "$1" '[.operations[]? | select(.operation == $o)][0].price_usd // "unpriced"' <<<"$PRICING"; }
    bad=""
    for op in confirm task_status task_cancel task_delete tasks tasks_unlock; do [[ "$(price $op)" == "0" ]] || bad="$bad $op=$(price $op)"; done
    [[ -z "$bad" && "$(price pay_invoice)" == "$MERCURY_PAY_PRICE" ]] \
      && pass "MR7 confirm and the task operations cost 0, pay_invoice $MERCURY_PAY_PRICE" \
      || fail "MR7 prices:$bad pay_invoice=$(price pay_invoice)"
  fi
fi

# ── MR8 approved, then refused by the bank ───────────────────────────────────
if want MR8; then
  if [[ -z "$NOT_ACH" ]]; then
    skip "MR8 the sandbox has no saved payee that is not paid by ACH"
  elif owner_ready MR8; then
    log "MR8 an approved payment the bank refuses"
    put_policy "$(jq -c --argjson r "$ASK_FROM_1" '. + {rules: $r}' <<<"$BASE")"
    mercury "$(jq -nc --argjson a "1.$CENTS" --arg r "$NOT_ACH" '{operation:"pay_invoice", amount_usd:$a, recipient_id:$r, payment_method:"ach"}')"
    T8=$(field .output.task_id)
    if ok && [[ "$(field .output.status)" == "awaiting_owner" && -n "$T8" ]]; then
      MADE_TASKS+=("$T8")
      approves "$T8" - - a
      if [[ "$(own .status)" == "200" && "$(own .state)" == "approved" ]]; then
        await_run "$T8"
        ERR8=$(field .output.result.error)
        [[ "$ENDED" == "failed" && "$(field .output.failure_reason)" == "run_failed" ]] \
          && pass "MR8 the agent reads failed as run_failed" \
          || fail "MR8 task_status: state '$ENDED' failure_reason '$(field .output.failure_reason)'"
        [[ "$ERR8" == *"Mercury refused"* && "$ERR8" == *"The task is closed: to make this payment, prepare it again"* ]] \
          && pass "MR8 result.error is the connector's refusal: $(head -c 140 <<<"$ERR8")" \
          || fail "MR8 result.error: '$(head -c 200 <<<"$ERR8")'"
      else
        fail "MR8 approve answered $(own .status) state '$(own .state)' reason '$(own .reason)'"
      fi
    else
      fail "MR8 the payment answered status '$(field .output.status)': $(why)"
    fi
  fi
fi

verdict "mercury_rules_e2e"
