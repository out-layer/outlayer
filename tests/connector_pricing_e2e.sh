#!/bin/bash
# Connector pricing, end to end: what a priced operation costs, who is paid out
# of it, and whether the report of all that agrees with the chain.
#
# The money half of `outlayer-coordinator/docs/TESTNET_RUNBOOK.md` §2, as a
# script. The unit tests cover the arithmetic and the refusals in isolation;
# this covers what they cannot — that the contract, the coordinator and the
# worker are wired to each other and agree about the same numbers.
#
#   C1  the admission gate        — the contract reads `operation` out of the
#                                   request and requires EXACTLY that
#                                   operation's price. Seven cases, five of
#                                   which pass by being refused
#   C2  the author's share        — the split lands in the contract's own
#                                   ledger: per OPERATION rather than per
#                                   connector, zero share keeps everything, and
#                                   the one combination that rounds
#   C3  the HTTPS path            — the same connector over `POST /call`, and
#                                   the author paid into the coordinator's
#                                   ledger instead of the chain's
#   C4  the two ledgers agree     — `/admin/earnings` for the period against
#                                   `get_developer_earnings` on chain
#   C5  what the caller paid      — the fixed fee lands ON TOP of compute, and
#                                   the reservation comes back exactly
#   C6  the owner's secret        — nothing is fetched unless the call asks, and
#                                   what arrives is the secret just stored
#   C7  the trial is ten calls    — and a funded key has no call limit
#   C8  our own record            — the egress audit and the connector-call log
#                                   say the same as the guest did
#   C9  a call that never ran     — what a timed-out or unclaimed job costs
#   C10 the trial key             — the way in for an agent that has never paid:
#                                   an allowance scoped to the connectors, which
#                                   pays the author nothing. SKIP-notes when
#                                   no trial is on offer (`trial_unavailable`)
#
# C7 mints a wallet of its own and claims its trial, so it spends nothing of the
# fixtures' and may run in any order.
#
# What this needs, and what SKIPS without it:
#   CALLER      an account with a stablecoin balance INSIDE the contract
#               (`ft_transfer_call` with `{"action":"deposit_balance"}`) and
#               NEAR for the compute deposits. C1 and C2 need it.
#   PAYMENT_KEY a funded key (`outlayer keys create` then `keys topup --usd`).
#               C3 and C5 need it. C5 additionally needs one with NO
#               subscription — under one, a call costs the caller nothing and
#               there is no fee to see landing on top of compute.
#   AGENT_WALLET_KEY  a custody wallet's `wk_`. C6 and C7 need it to STORE the
#               secret (a wallet operation), and
#   AGENT_PAYMENT_KEY a payment key that wallet OWNS, to make the call with.
#               `agent_secrets_ref` keys off the key's `owner`, so the secret is
#               found when the owner is the wallet's own implicit account.
#   ADMIN_TOKEN the coordinator's admin bearer. C4 and C8 need it.
#
# The prices themselves are NOT set here — `scripts/set_connector_prices_testnet.sh`
# owns them, and this script asserts the ones it expects are the ones on chain
# rather than writing its own. A price mismatch is reported, not corrected: the
# numbers below are the same ones the runbook reasons about.
#
# Run (dry-run prints the plan; --apply spends):
#   CALLER=you.testnet ./tests/connector_pricing_e2e.sh --apply

set -uo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/agent_secret_mode.sh"

APPLY=false
[[ "${1:-}" == "--apply" ]] && APPLY=true

NETWORK="${NETWORK:-testnet}"
CONTRACT_ID="${CONTRACT_ID:-outlayer.testnet}"
COORDINATOR_URL="${COORDINATOR_URL:-https://testnet-api.outlayer.ai}"
PROJECT="${PROJECT:-connectors.outlayer.testnet/connector-probe}"
CALLER="${CALLER:-}"
AUTHOR="${AUTHOR:-zavodil.testnet}"
PROJECT_OWNER="${PROJECT_OWNER:-connectors.outlayer.testnet}"
PAYMENT_KEY="${PAYMENT_KEY:-}"
# A custody wallet's `wk_`, for the checks that are about an AGENT rather than
# about a payment key: the owner's secret (C6).
AGENT_WALLET_KEY="${AGENT_WALLET_KEY:-}"
AGENT_PAYMENT_KEY="${AGENT_PAYMENT_KEY:-}"
ADMIN_TOKEN="${ADMIN_TOKEN:-}"
# Which arrangement of the fleet C9 is being run against. See C9's own comment.
C9_PHASE="${C9_PHASE:-}"
# What a timeout charges: the compute the caller AUTHORISED, which is the
# coordinator's DEFAULT_COMPUTE_LIMIT unless the request named its own. Stated
# here rather than inferred, so a deployment that changes it fails loudly
# instead of quietly agreeing with whatever came back.
TIMEOUT_COMPUTE_BUDGET="${TIMEOUT_COMPUTE_BUDGET:-10000}"
# A claimed trial key (C11, C14, C15, C17 — C14 and C15 spend four of its calls a
# run), the agent's account id, and the token the WORKER authenticates with —
# the delete route is internal, not a customer's.
TRIAL_KEY="${TRIAL_KEY:-}"
AGENT_ACCOUNT="${AGENT_ACCOUNT:-}"
INTERNAL_TOKEN="${INTERNAL_TOKEN:-}"
# C13 only. A key whose subscription has ENDED and which still holds money.
EXPIRED_SUB_KEY="${EXPIRED_SUB_KEY:-}"
# C14 and C15. Three keys in states no other section needs, and one project that
# is deliberately NOT a connector:
#   EMPTY_KEY        registered, zero balance, no subscription
#   CAPPED_KEY       `max_per_call` set BELOW compute plus the fee
#   SUB_KEY          a LIVE subscription, so its calls come out of an allowance
#   ORDINARY_PROJECT any non-connector project — a connector's deposit is voided
#                    before the rule C14 is about can be reached
EMPTY_KEY="${EMPTY_KEY:-}"
CAPPED_KEY="${CAPPED_KEY:-}"
SUB_KEY="${SUB_KEY:-}"
ORDINARY_PROJECT="${ORDINARY_PROJECT:-}"
# C17 only. A key with a LIVE subscription, to buy a SECOND one for — it spends a
# whole plan every run, so it is opt-in rather than part of the default sweep.
# The key's own owner signs, so that account must be the one holding the
# stablecoin. `PLAN_PRICE` is what plan 0 costs, read from the chain by
# `get_subscription_plans`.
RENEW_KEY="${RENEW_KEY:-}"
# C18 only. A SECOND funded NEAR account, to show that the authority over an
# agent secret is the `wk_` rather than the account that pays for it.
SECOND_CALLER="${SECOND_CALLER:-}"
PLAN_PRICE="${PLAN_PRICE:-10000000}"
TOKEN_CONTRACT="${TOKEN_CONTRACT:-usdc.fakes.testnet}"
OUTLAYER_BIN="${OUTLAYER_BIN:-outlayer}"
export OUTLAYER_NETWORK="$NETWORK"
ONLY="${ONLY:-}"

# The RPC. `.env` at the repo root may carry the key-bearing URL.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -z "${RPC_URL:-}" && -f "$SCRIPT_DIR/../.env" ]]; then
  RPC_URL=$(grep -E "^$(echo "$NETWORK" | tr '[:lower:]' '[:upper:]')_NEAR_RPC_URL=" "$SCRIPT_DIR/../.env" | cut -d= -f2-)
fi
# Otherwise lib/rpc.sh builds a keyed URL from FASTNEAR_API_KEY or near-cli's
# config, or warns and uses the unkeyed host.
source "$SCRIPT_DIR/lib/rpc.sh"

# Response bodies land in a directory of this run's own and go with it: a fixed
# path in /tmp is shared with every other run on the machine, and a body can
# carry a key.
RUN_TMP=$(mktemp -d)
trap 'rm -rf "$RUN_TMP"' EXIT
# The one thing that must OUTLIVE a run: C9's `queued` phase hands its call id to
# a later `settled` run. A call id is not a secret.
C9_STATE="${C9_STATE:-${TMPDIR:-/tmp}/outlayer_c9_call_id}"

PASS=0; FAILED=0; SKIPPED=0; FAILED_NAMES=()
log()  { printf '\n\033[36m▶ %s\033[0m\n' "$*" >&2; }
note() { printf '\033[35m• %s\033[0m\n' "$*" >&2; }
warn() { printf '\033[33m⚠ %s\033[0m\n' "$*" >&2; }
pass() { printf '\033[32m✓ %s\033[0m\n' "$*" >&2; PASS=$((PASS+1)); }
fail() { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; FAILED=$((FAILED+1)); FAILED_NAMES+=("$*"); }
# A row that could not be exercised is neither a pass nor a failure, and must
# still be visible: without this the call below is an unbound command and the
# row vanishes from the tally altogether.
skip() { printf '\033[33m∅ SKIP: %s\033[0m\n' "$*" >&2; SKIPPED=$((SKIPPED+1)); }
want() { [[ -z "$ONLY" ]] || [[ ",$ONLY," == *",$1,"* ]]; }

for tool in jq curl near; do command -v "$tool" >/dev/null || { echo "✗ missing $tool" >&2; exit 1; }; done

# view <method> <json-args> → the view's JSON text ("null" on any error)
view() {
  curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg c "$CONTRACT_ID" --arg m "$1" --arg a "$(printf '%s' "$2" | base64 | tr -d '\n')" \
      '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"call_function",finality:"final",account_id:$c,method_name:$m,args_base64:$a}}')" \
    | jq -r '.result.result | implode' 2>/dev/null || echo 'null'
}

earnings_of() { view get_developer_earnings "$(jq -nc --arg id "$1" '{account_id:$id}')" | jq -r 'if . == null then 0 else fromjson end'; }

# One operation over the HTTPS route. Defined here rather than inside a section
# so a section can be run on its own — `ONLY=C5` must not depend on C3 having
# executed the definition.
probe() {
  curl -s -X POST "$COORDINATOR_URL/call/$PROJECT" -H "X-Payment-Key: $PAYMENT_KEY" \
    -H 'Content-Type: application/json' -d "{\"input\":{\"operation\":\"$1\"}}"
}

# The prices this script reasons about. Asserted against the chain rather than
# written to it: if they differ, every expectation below is about something
# else, and correcting them here would hide that.
declare -a PRICES=(
  "ping|0|0"
  "whoami|10000|0"
  "secret|10000|7000"
  "burn|10000|3333"
  "fetch|15000|10000"
  "forbidden_fetch|15000|3333"
)

# request <label> <input_data> <attached_usd> <accept|refuse> [expected reason]
request() {
  local label=$1 input=$2 usd=$3 expect=$4 want_reason=${5:-} out rc=0 landed=true
  if [[ "$APPLY" != true ]]; then
    printf '\033[90m  (dry-run) %s → %s\033[0m\n' "$label" "$expect" >&2
    return 0
  fi
  out=$(near --quiet contract call-function as-transaction "$CONTRACT_ID" request_execution \
    json-args "$(jq -nc --arg p "$PROJECT" --arg i "$input" --arg u "$usd" \
      '{source:{Project:{project_id:$p}}, input_data:$i,
        resource_limits:{max_instructions:1000000000,max_memory_mb:128,max_execution_seconds:30},
        params:{attached_usd:$u}}')" \
    prepaid-gas '300.0 Tgas' attached-deposit '0.1 NEAR' \
    sign-as "$CALLER" network-config "$NETWORK" sign-with-keychain send 2>&1) || rc=$?
  { [[ $rc -ne 0 ]] || echo "$out" | grep -qiE "error|panicked|failure"; } && landed=false

  if [[ "$expect" == accept ]]; then
    $landed && pass "$label — accepted" || fail "$label — REFUSED but should have been taken"
  elif $landed; then
    fail "$label — the contract ACCEPTED it"
  elif [[ -n "$want_reason" ]] && ! echo "$out" | grep -q "$want_reason"; then
    fail "$label — refused, but not for the stated reason (wanted '$want_reason')"
  else
    pass "$label — refused${want_reason:+ ($want_reason)}"
  fi
}

# ── the prices on chain are the ones this script is about ────────────────────
log "Prices on chain for $PROJECT"
PRICING=$(view get_project_pricing "$(jq -nc --arg p "$PROJECT" '{project_id:$p}')")
if [[ "$PRICING" == "null" || -z "$PRICING" ]]; then
  fail "no pricing on chain — run scripts/set_connector_prices_testnet.sh first"
else
  ok=true
  for row in "${PRICES[@]}"; do
    IFS='|' read -r op price bp <<< "$row"
    got_p=$(echo "$PRICING" | jq -r --arg o "$op" '.operations[] | select(.operation==$o) | .price_usd // empty')
    got_bp=$(echo "$PRICING" | jq -r --arg o "$op" '.operations[] | select(.operation==$o) | .developer_share_bp // empty')
    [[ "$got_p" == "$price" && "$got_bp" == "$bp" ]] || { fail "price drift: $op is $got_p/$got_bp on chain, this script expects $price/$bp"; ok=false; }
  done
  $ok && pass "all six operations are priced as this script expects"
  got_author=$(echo "$PRICING" | jq -r '.author_account_id // empty')
  [[ "$got_author" == "$AUTHOR" ]] && pass "the author on chain is $AUTHOR" \
    || fail "the author on chain is '$got_author', not '$AUTHOR' — the share checks would credit the wrong account"
fi

# ── C1: the admission gate ───────────────────────────────────────────────────
if want C1; then
  if [[ -z "$CALLER" ]]; then
    note "C1 SKIPPED: set CALLER to an account holding a stablecoin balance inside the contract"
  else
    log "C1 the exact price, and naming the operation"
    request "a free operation, nothing attached"   '{"operation":"ping"}'       "0"     accept
    request "a priced operation, the exact price"  '{"operation":"secret"}'     "10000" accept
    request "a priced operation, nothing attached" '{"operation":"secret"}'     "0"     refuse "attach at least that"
    # Over-attaching is ACCEPTED and the excess comes back at settlement — see
    # C2's change case for the money actually returning.
    request "more than the price"                  '{"operation":"secret"}'     "10001" accept
    request "no operation named"                   '{"to":"x"}'                 "0"     refuse "priced per operation"
    # One field name, or two stay in circulation forever.
    request "the old spelling"                     '{"op":"secret"}'            "10000" refuse "priced per operation"
    request "an operation nobody sells"            '{"operation":"exfiltrate"}' "10000" refuse "does not sell operation"
  fi
fi

# ── C2: the author's share, in the contract's ledger ─────────────────────────
# split <operation> <price> <author delta> <owner delta>
split() {
  local op=$1 usd=$2 want_a=$3 want_o=$4 a0 o0 a1 o1 i
  if [[ "$APPLY" != true ]]; then
    printf '\033[90m  (dry-run) %s → author +%s, owner +%s\033[0m\n' "$op" "$want_a" "$want_o" >&2
    return 0
  fi
  a0=$(earnings_of "$AUTHOR"); o0=$(earnings_of "$PROJECT_OWNER")
  near --quiet contract call-function as-transaction "$CONTRACT_ID" request_execution \
    json-args "$(jq -nc --arg p "$PROJECT" --arg i "{\"operation\":\"$op\"}" --arg u "$usd" \
      '{source:{Project:{project_id:$p}}, input_data:$i,
        resource_limits:{max_instructions:1000000000,max_memory_mb:128,max_execution_seconds:30},
        params:{attached_usd:$u}}')" \
    prepaid-gas '300.0 Tgas' attached-deposit '0.1 NEAR' \
    sign-as "$CALLER" network-config "$NETWORK" sign-with-keychain send >/dev/null 2>&1 \
    || { fail "$op — the call did not land"; return; }

  # The split is credited by the execution CALLBACK, so it arrives a worker-run
  # after the request — poll rather than read once and call it zero.
  a1=$a0; o1=$o0
  for i in $(seq 1 30); do
    a1=$(earnings_of "$AUTHOR"); o1=$(earnings_of "$PROJECT_OWNER")
    [[ $(( a1 - a0 + o1 - o0 )) -ge $usd ]] && break
    sleep 4
  done
  if [[ $(( a1 - a0 )) == "$want_a" && $(( o1 - o0 )) == "$want_o" ]]; then
    pass "$op ($usd) — author +$want_a, owner +$want_o"
  else
    fail "$op ($usd) — author +$(( a1 - a0 )) (wanted $want_a), owner +$(( o1 - o0 )) (wanted $want_o)"
  fi
}

if want C2; then
  if [[ -z "$CALLER" ]]; then
    note "C2 SKIPPED: needs CALLER, same as C1"
  else
    log "C2 the author's share, in the contract's own ledger"
    # 33.33% of 10000. A single share held per CONNECTOR would print 7000 here
    # as well as for `secret`, and prove nothing about which one is in force.
    split burn   10000 3333 6667
    # Priced, and all of it ours — the shape of every connector we own, and so
    # the commonest case in production.
    split whoami 10000 0    10000
    # 15000 × 3333/10000 = 4999.5. The floor goes to the platform, and the call
    # RUNS and returns an error — charged and paid all the same.
    split forbidden_fetch 15000 4999 10001

    # Change. Attaching more than the price is allowed; the excess is the
    # caller's and comes back at settlement, and the split is computed on the
    # PRICE — not on what was sent, which would pay the author a share of the
    # caller's own change.
    log "C2 change on an over-attached call"
    user_balance() {
      view get_user_stablecoin_balance "$(jq -nc --arg a "$CALLER" '{account_id:$a}')" | jq -r 'if . == null then 0 else fromjson end'
    }
    U0=$(user_balance); A0=$(earnings_of "$AUTHOR"); O0=$(earnings_of "$PROJECT_OWNER")
    # Output is KEPT: a suppressed send that fails reports itself as a product
    # failure in all three checks below (seen live 2026-08-18 — a broadcast
    # transient read as "the split was 0/0"). C17 made the same mistake first.
    OVER_OUT=$(near --quiet contract call-function as-transaction "$CONTRACT_ID" request_execution \
      json-args "$(jq -nc --arg p "$PROJECT" --arg i '{"operation":"secret"}' \
        '{source:{Project:{project_id:$p}}, input_data:$i,
          resource_limits:{max_instructions:1000000000,max_memory_mb:128,max_execution_seconds:30},
          params:{attached_usd:"15000"}}')" \
      prepaid-gas '300.0 Tgas' attached-deposit '0.1 NEAR' \
      sign-as "$CALLER" network-config "$NETWORK" sign-with-keychain send 2>&1) \
      || fail "C2 the over-attached call did not land: $(tail -c 300 <<<"$OVER_OUT")"
    A1=$A0; O1=$O0; U1=$U0
    for _ in $(seq 1 30); do
      A1=$(earnings_of "$AUTHOR"); O1=$(earnings_of "$PROJECT_OWNER"); U1=$(user_balance)
      [[ $(( A1 - A0 + O1 - O0 )) -ge 10000 ]] && break
      sleep 4
    done
    # The split is on 10000: 7000 to the author, 3000 to the owner.
    if [[ $(( A1 - A0 )) == 7000 && $(( O1 - O0 )) == 3000 ]]; then
      pass "C2 an over-attached call splits the PRICE — author +7000, owner +3000"
    else
      fail "C2 the split was author +$(( A1 - A0 )), owner +$(( O1 - O0 )) — expected 7000/3000 on a price of 10000"
    fi
    # And the caller is out 10000, not the 15000 they sent.
    if [[ $(( U0 - U1 )) == 10000 ]]; then
      pass "C2 the change came back — the caller paid the price, not what they attached"
    else
      fail "C2 the caller's balance fell by $(( U0 - U1 )), not 10000 — the change of 5000 did not return"
    fi
  fi
fi

# ── C3: the same connector over HTTPS ────────────────────────────────────────
if want C3; then
  if [[ -z "$PAYMENT_KEY" ]]; then
    note "C3 SKIPPED: set PAYMENT_KEY to a funded key (outlayer keys create, then keys topup --usd)"
  elif [[ "$APPLY" != true ]]; then
    printf '\033[90m  (dry-run) six operations over POST /call, and the author paid off chain\033[0m\n' >&2
  else
    log "C3 the HTTPS path"

    R=$(probe ping)
    [[ "$(echo "$R" | jq -r '.output.ok // false')" == true ]] \
      && pass "C3 a free operation still needs a live key, and runs" \
      || fail "C3 ping: $(echo "$R" | head -c 200)"

    R=$(probe whoami)
    [[ -n "$(echo "$R" | jq -r '.output.sender_id // empty')" ]] \
      && pass "C3 whoami reports the caller the worker injected ($(echo "$R" | jq -r .output.sender_id))" \
      || fail "C3 whoami: $(echo "$R" | head -c 200)"

    # Every system variable the worker is supposed to inject, checked from
    # INSIDE the guest. `merge_env_vars` has unit tests, but nothing covered
    # the rest of the chain — worker to wasmtime to guest — so a variable lost
    # downstream would show up as a connector acting on the wrong identity
    # months later, with no error anywhere. `env` reports every one of them,
    # and `ok` is false the moment a single one fails to arrive.
    R=$(probe env)
    if [[ "$(echo "$R" | jq -r '.output.ok')" == true ]]; then
      SEEN=$(echo "$R" | jq -r '.output.system_env | length')
      SENDER=$(echo "$R" | jq -r '.output.system_env[] | select(.key=="NEAR_SENDER_ID") | .value')
      # Named explicitly on top of the blanket check: this is the one every
      # connector acts on. near-email turns it into a mailbox, so a blank here
      # is mail sent from the wrong account rather than an error.
      if [[ -n "$SENDER" ]]; then
        pass "C3 all $SEEN system variables arrived, NEAR_SENDER_ID=$SENDER"
      else
        fail "C3 env: every variable is present but NEAR_SENDER_ID is blank — a connector would act as nobody"
      fi
    else
      fail "C3 env: $(echo "$R" | jq -r '.output.detail // .' | head -c 300)"
    fi

    # A variable the worker sends that this build of the probe does not know.
    # Not a failure — it is how a RENAME announces itself, and it is worth
    # seeing next to the missing one it replaced.
    UNKNOWN=$(echo "$R" | jq -r '.output.unknown_system_vars // [] | join(", ")')
    [[ -n "$UNKNOWN" ]] && note "C3 the worker also sent variables the probe does not know: $UNKNOWN (add them to SYSTEM_VARS)"

    # Refused before the module runs: an unpriced operation is not a free one.
    R=$(probe unpriced)
    if [[ "$(echo "$R" | jq -r '.reason // empty')" == "unknown_operation" && "$(echo "$R" | jq -r '.output // "none"')" == "none" ]]; then
      pass "C3 an unpriced operation is refused and the guest never ran"
    else
      fail "C3 unpriced: $(echo "$R" | head -c 200)"
    fi

    # The declared host is reachable; an undeclared one is refused by the
    # WORKER, not by the module. A success there would mean a host nobody
    # declared was reachable from inside a TEE that holds keys.
    R=$(probe fetch)
    [[ "$(echo "$R" | jq -r '.output.ok')" == true ]] \
      && pass "C3 the declared host is reachable" || fail "C3 fetch: $(echo "$R" | head -c 200)"

    # Read WITHOUT jq's `//`: its alternative operator fires on `false` as well
    # as on null, so `.output.ok // true` turns the very answer this checks for
    # into its opposite. A refusal read as a success is the one direction this
    # check must never fail in.
    R=$(probe forbidden_fetch)
    if [[ "$(echo "$R" | jq -r '.output.ok')" == false ]] \
       && echo "$R" | grep -q "allowlist"; then
      pass "C3 an undeclared host is refused by the worker (this one passes by failing)"
    else
      fail "C3 forbidden_fetch was NOT refused: $(echo "$R" | head -c 250)"
    fi

    # And the author is paid, out of the coordinator's ledger this time. Read
    # through /admin/earnings rather than the database, so this needs no DB.
    # Who a paid call pays, and it depends on WHAT paid for it. Only money pays
    # the author: a call covered by a subscription's allowance cost the caller
    # nothing at the moment of the call, so there is nothing passing through to
    # anybody. Both halves are checked here, because which one applies is a
    # property of the key the operator handed us, not of this script.
    if [[ -n "$ADMIN_TOKEN" ]]; then
      # ONE window, fixed before the call: recomputing "ten minutes ago" for the
      # second read moves the period under the comparison, and the delta stops
      # being about the call.
      SINCE=$(date -u -v-10M +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '10 minutes ago' +%Y-%m-%dT%H:%M:%SZ)
      report() { curl -s "$COORDINATOR_URL/admin/earnings?from=$SINCE" -H "Authorization: Bearer $ADMIN_TOKEN"; }
      SUBBED=$(curl -s "$COORDINATOR_URL/subscription/status" -H "X-Payment-Key: $PAYMENT_KEY" \
                 | jq -r '(.has_subscription == true) and (.expired == false)')

      R0=$(report)
      B0=$(echo "$R0" | jq -r '.earned.by_source.https.developer_share_usd // "0"')
      G0=$(echo "$R0" | jq -r '.given.spent_from_subscriptions_usd // "0"')
      probe secret >/dev/null
      # Settlement is not instant. Wait for one of the two to move rather than
      # sample once and report a lag as a payment that never happened.
      B1=$B0; G1=$G0
      for _ in $(seq 1 20); do
        R1=$(report)
        B1=$(echo "$R1" | jq -r '.earned.by_source.https.developer_share_usd // "0"')
        G1=$(echo "$R1" | jq -r '.given.spent_from_subscriptions_usd // "0"')
        [[ $(( B1 - B0 )) -gt 0 || $(( G1 - G0 )) -gt 0 ]] && break
        sleep 3
      done

      if [[ "$SUBBED" == true ]]; then
        if [[ $(( G1 - G0 )) -gt 0 && $(( B1 - B0 )) == 0 ]]; then
          pass "C3 a subscription pays the author NOTHING — $(( G1 - G0 )) spent from the allowance, nothing earned"
        else
          fail "C3 under a subscription the author's share moved by $(( B1 - B0 )) (must be 0) and the allowance by $(( G1 - G0 )) (must be > 0)"
        fi
      elif [[ $(( B1 - B0 )) == 7000 ]]; then
        pass "C3 money pays the author 7000 over HTTPS — 70% of the fee, same rule, other ledger"
      else
        fail "C3 the author's HTTPS share moved by $(( B1 - B0 )), not 7000"
      fi
    else
      note "C3 who the fee pays SKIPPED — needs ADMIN_TOKEN"
    fi
  fi
fi

# ── C4: the report and the chain say the same thing ──────────────────────────
if want C4; then
  if [[ -z "$ADMIN_TOKEN" ]]; then
    note "C4 SKIPPED: set ADMIN_TOKEN to read /admin/earnings"
  elif [[ "$APPLY" != true ]]; then
    printf '\033[90m  (dry-run) /admin/earnings against get_developer_earnings\033[0m\n' >&2
  else
    log "C4 the two ledgers"
    # A window wide enough to hold this run. The on-chain half is compared
    # against the chain, which is where that money actually is — the report is
    # a record of what the contract did, and the contract is the ledger.
    FROM="${FROM:-$(date -u -v-3H +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '3 hours ago' +%Y-%m-%dT%H:%M:%SZ)}"
    REPORT=$(curl -s "$COORDINATOR_URL/admin/earnings?from=$FROM" -H "Authorization: Bearer $ADMIN_TOKEN")
    R_GROSS=$(echo "$REPORT" | jq -r '.earned.gross_usd // "0"')
    R_SHARE=$(echo "$REPORT" | jq -r '.earned.developer_share_usd // "0"')
    R_TOTAL=$(echo "$REPORT" | jq -r '.earned.total_usd // "0"')
    R_ON=$(echo "$REPORT" | jq -r '.earned.by_source.onchain.calls // 0')
    R_HTTPS=$(echo "$REPORT" | jq -r '.earned.by_source.https.calls // 0')
    note "C4 report: gross=$R_GROSS share=$R_SHARE ours=$R_TOTAL (onchain=$R_ON https=$R_HTTPS calls)"

    [[ $(( R_GROSS - R_SHARE )) == "$R_TOTAL" ]] \
      && pass "C4 what we kept is the gross less the author's cut" \
      || fail "C4 gross($R_GROSS) − share($R_SHARE) ≠ total($R_TOTAL) — the author's cut is being counted as ours"

    # The on-chain half against the chain itself. Only comparable when the
    # window covers the author's whole history, so this is stated as a note
    # unless FROM_ZERO says the accounts started empty.
    ON_SHARE=$(echo "$REPORT" | jq -r '.earned.by_source.onchain.developer_share_usd // "0"')
    CHAIN_AUTHOR=$(earnings_of "$AUTHOR")
    if [[ "${FROM_ZERO:-false}" == true ]]; then
      [[ "$CHAIN_AUTHOR" == "$ON_SHARE" ]] \
        && pass "C4 the chain's ledger for $AUTHOR ($CHAIN_AUTHOR) equals the report's on-chain share" \
        || fail "C4 chain says $CHAIN_AUTHOR for $AUTHOR, the report says $ON_SHARE"
    else
      note "C4 chain=$CHAIN_AUTHOR vs report(on-chain)=$ON_SHARE — set FROM_ZERO=true when the window covers the author's whole history to assert equality"
    fi
  fi
fi

# ── C5: what a paid call actually costs the caller ───────────────────────────
# Needs a key paying with MONEY — a subscription covers the fee, so under one
# there is nothing to see here. Skipped rather than faked when the key has one.
if want C5; then
  if [[ -z "$PAYMENT_KEY" ]]; then
    note "C5 SKIPPED: needs PAYMENT_KEY, same as C3"
  elif [[ "$APPLY" != true ]]; then
    printf '\033[90m  (dry-run) the fee on top of compute, and the reservation coming back\033[0m\n' >&2
  else
    status() { curl -s "$COORDINATOR_URL/subscription/status" -H "X-Payment-Key: $PAYMENT_KEY"; }
    S0=$(status)
    if [[ "$(echo "$S0" | jq -r '.has_subscription')" == true ]]; then
      note "C5 SKIPPED: this key has a subscription, so its calls cost it nothing — use a money-only key"
    else
      log "C5 the fee on top of compute, and the reservation"
      BAL0=$(echo "$S0" | jq -r '.balance')
      # `ping` is priced at zero, so it costs compute ALONE — which is what the
      # fee has to be measured against. Without this baseline "the balance went
      # down" says nothing about whether the operation was charged for.
      probe ping >/dev/null; sleep 6
      BAL_PING=$(curl -s "$COORDINATOR_URL/subscription/status" -H "X-Payment-Key: $PAYMENT_KEY" | jq -r '.balance')
      COMPUTE=$(( BAL0 - BAL_PING ))

      R=$(probe secret); sleep 6
      S2=$(curl -s "$COORDINATOR_URL/subscription/status" -H "X-Payment-Key: $PAYMENT_KEY")
      BAL2=$(echo "$S2" | jq -r '.balance')
      PAID=$(( BAL_PING - BAL2 ))

      # The whole point of §8.2: before it, a connector call cost fractions of a
      # cent and the operation itself was free.
      #
      # Bounded on both sides, and loosely on purpose. The two calls are metered
      # separately and compute varies between runs of the SAME operation — three
      # consecutive `ping`s came to 1000, 1001, 1001 — so `PAID` and `COMPUTE`
      # cannot be compared to the unit without failing on that jitter alone. The
      # width is one whole baseline call rather than a number chosen to fit:
      # anything inside it is the fee plus one call's compute, and the two
      # failures worth catching are outside it either way — no fee at all lands
      # near COMPUTE, and a fee charged twice lands near 20000.
      #
      # There is no tighter form available: `compute_cost` on the call row is the
      # TOTAL, so the priced call's own compute cannot be read back, and deriving
      # it from `instructions` would put a second copy of the coordinator's
      # pricing in this script.
      if [[ $PAID -ge 10000 && $PAID -le $(( 10000 + 2 * COMPUTE )) ]]; then
        pass "C5 a priced operation costs the fee ON TOP of compute ($PAID vs $COMPUTE for a free one)"
      else
        fail "C5 a priced operation took $PAID while a free one took $COMPUTE — that is not the 10000 fee plus one call's compute"
      fi

      # Nothing left reserved. A residue is spending power the customer has
      # silently lost; a shortfall means a concurrent call's reservation was
      # eaten. `withdrawable` is the balance minus what is still held.
      WD=$(echo "$S2" | jq -r '.withdrawable')
      [[ "$WD" == "$BAL2" ]] \
        && pass "C5 the reservation came back exactly — withdrawable equals the balance" \
        || fail "C5 balance $BAL2 but withdrawable $WD — $(( BAL2 - WD )) is still held after the call settled"

      # The balance fell by what the call says it cost, and by nothing else.
      #
      # `secret` pays its author 70% of the fee, and that share is a slice of a
      # fee the caller has already paid — so it must not move this number. It
      # did: the balance fell by the charge PLUS the share, and the extra was
      # credited to nobody. Invisible on a connector whose share is zero, which
      # is every connector we own, so the probe's real shares are what makes
      # this checkable at all.
      if [[ -n "$ADMIN_TOKEN" ]]; then
        CID=$(echo "$R" | jq -r '.call_id // empty')
        ROW_CHARGED=$(curl -s "$COORDINATOR_URL/admin/connector-calls?limit=20" -H "Authorization: Bearer $ADMIN_TOKEN" \
                        | jq -r --arg c "$CID" 'first(.calls[]|select(.call_id==$c)) | .charged_usd // empty')
        if [[ -z "$ROW_CHARGED" ]]; then
          note "C5 the charge cross-check SKIPPED — the call is not in the log yet"
        elif [[ "$PAID" == "$ROW_CHARGED" ]]; then
          pass "C5 the balance fell by exactly what the call was charged ($PAID) — the author's share is not billed twice"
        else
          fail "C5 the balance fell by $PAID while the call was charged $ROW_CHARGED — the difference is the author's share, taken from the caller a second time and credited to nobody"
        fi
      fi
    fi
  fi
fi

# ── C6: the owner's secret reaches the guest, and only when asked ────────────
# Needs a key a custody WALLET owns: `agent_secrets_ref` reads the key's `owner`
# and returns nothing when that owner is a NAMED account, because its holder
# addresses their own secrets through the body. So this is the custody path —
# the wallet's `wk_` stores the secret, and a payment key the wallet owns makes
# the call.
if want C6 && agent_secret_mode C6; then
  if [[ -z "$AGENT_WALLET_KEY" || -z "$AGENT_PAYMENT_KEY" ]]; then
    note "C6 SKIPPED: set AGENT_WALLET_KEY (a wallet's wk_) and AGENT_PAYMENT_KEY (a key that wallet owns)"
  elif ! "$OUTLAYER_BIN" secrets set-for-agent --help >/dev/null 2>&1; then
    note "C6 SKIPPED: '$OUTLAYER_BIN secrets set-for-agent' is not available to store the secret"
  elif [[ "$APPLY" != true ]]; then
    printf '\033[90m  (dry-run) store two secrets for the agent, then read them back through the guest\033[0m\n' >&2
  else
    log "C6 the owner's secret"
    agent_probe() {
      curl -s -X POST "$COORDINATOR_URL/call/$PROJECT" -H "X-Payment-Key: $AGENT_PAYMENT_KEY" \
        "$@" -H 'Content-Type: application/json' -d '{"input":{"operation":"secret"}}'
    }
    # Fresh values each run, and the expectation is computed from them rather
    # than written down: a hard-coded prefix would keep passing against a stale
    # secret, which is the one thing this must not do.
    T1="probe-token-$$-$(date +%s)"
    T2="probe-second-$$-$(date +%s)"
    P1=$(printf '%s' "$T1" | shasum -a 256 | cut -c1-8)
    P2=$(printf '%s' "$T2" | shasum -a 256 | cut -c1-8)

    if OUTLAYER_WALLET_KEY="$AGENT_WALLET_KEY" "$OUTLAYER_BIN" secrets set-for-agent \
         "$(jq -nc --arg a "$T1" --arg b "$T2" '{PROBE_TOKEN:$a,PROBE_SECOND:$b}')" \
         --project "$PROJECT" >&2; then
      # Nothing is looked up unless the call asks: a connector that needs no
      # credential pays for no lookup, and a compromised one gets nothing by
      # default.
      R=$(agent_probe)
      # A call that never RAN has no `output` at all, and `.output.secrets[]`
      # on null makes jq fail — which the old reading turned into "a secret
      # reached the guest", announcing a leak where there was not even a run.
      # On a TRIAL key the commonest cause is a trial that has made its calls.
      C6_SECRETS=$(echo "$R" | jq -c '.output.secrets // empty' 2>/dev/null)
      if [[ -z "$C6_SECRETS" ]]; then
        # Only a spent trial is a reason to stand aside: this suite is one of
        # the plan's "run unchanged" regressions, and any other refusal here is
        # the regression it exists to catch.
        if echo "$R" | grep -qiE "trial_exhausted|trial_expired"; then
          skip "C6 the call did not run (the trial key is spent), so nothing can be said about what a guest saw: $(echo "$R" | jq -r '.error // .reason // .' 2>/dev/null | head -c 110)"
        else
          fail "C6 the call without the header did not run, and not for a spent trial: $(echo "$R" | jq -r '.error // .reason // .' 2>/dev/null | head -c 160)"
        fi
        C6_DEAD=1
      elif [[ "$(echo "$C6_SECRETS" | jq -r '[.[].found] | any')" == false ]]; then
        pass "C6 without the header no secret is fetched at all"
      else
        fail "C6 a secret reached the guest without X-Use-Owner-Secret: $C6_SECRETS"
      fi

      R=$(agent_probe -H 'X-Use-Owner-Secret: 1')
      GOT1=$(echo "$R" | jq -r '.output.secrets[]? | select(.key=="PROBE_TOKEN") | .sha256_prefix' 2>/dev/null)
      GOT2=$(echo "$R" | jq -r '.output.secrets[]? | select(.key=="PROBE_SECOND") | .sha256_prefix' 2>/dev/null)
      if [[ "${C6_DEAD:-0}" == "1" ]]; then
        skip "C6 with the header: not judged, the half without the header could not run"
      elif [[ -z "$GOT1" && -z "$GOT2" ]]; then
        if echo "$R" | grep -qiE "trial_exhausted|trial_expired"; then
          skip "C6 with the header: the call did not run (the trial key is spent) — $(echo "$R" | jq -r '.error // .reason // .' 2>/dev/null | head -c 110)"
        else
          fail "C6 with the header the call did not run, and not for a spent trial: $(echo "$R" | jq -r '.error // .reason // .' 2>/dev/null | head -c 160)"
        fi
      elif [[ "$GOT1" == "$P1" && "$GOT2" == "$P2" ]]; then
        # Not just "a secret arrived" — THE secret, hashed on the way out so the
        # value never leaves the enclave to be checked.
        pass "C6 with the header both secrets arrive, and their hashes are the ones just stored"
      else
        fail "C6 the guest saw $GOT1/$GOT2, the secrets stored hash to $P1/$P2"
      fi
      unset C6_DEAD
    else
      fail "C6 could not store the secrets for the agent"
    fi
  fi
fi

# ── C8: what our own side recorded ───────────────────────────────────────────
# The guest's word for "the undeclared host was refused" and ours must agree.
# Seen from here it is the proof the allowlist was ENFORCED rather than merely
# declared — the guest could say anything.
if want C8; then
  if [[ -z "$ADMIN_TOKEN" ]]; then
    note "C8 SKIPPED: needs ADMIN_TOKEN"
  elif [[ "$APPLY" != true ]]; then
    printf '\033[90m  (dry-run) the egress audit and the connector-call log\033[0m\n' >&2
  else
    log "C8 the egress audit and the call log"
    EG=$(curl -s "$COORDINATOR_URL/admin/egress-audit?project_id=$PROJECT" -H "Authorization: Bearer $ADMIN_TOKEN")
    REFUSED=$(echo "$EG" | jq -r '.hosts[] | select(.host=="example.com") | .refused // 0')
    ALLOWED=$(echo "$EG" | jq -r '.hosts[] | select(.host=="rpc.testnet.fastnear.com") | (.attempts - .refused)')
    [[ "${REFUSED:-0}" -gt 0 ]] \
      && pass "C8 the undeclared host is logged as refused ($REFUSED times) — enforced, not just declared" \
      || fail "C8 no refused attempt on example.com in the egress audit: $(echo "$EG" | head -c 200)"
    # A log of refusals alone cannot answer where a connector actually went.
    [[ "${ALLOWED:-0}" -gt 0 ]] \
      && pass "C8 the allowed destination is logged too ($ALLOWED reached)" \
      || fail "C8 the declared host has no allowed attempt recorded: $(echo "$EG" | head -c 200)"

    CALLS=$(curl -s "$COORDINATOR_URL/admin/connector-calls?limit=20" -H "Authorization: Bearer $ADMIN_TOKEN")
    ROW=$(echo "$CALLS" | jq -c --arg p "$PROJECT" 'first(.calls[] | select(.project_id==$p))')
    if [[ -n "$ROW" && "$ROW" != "null" ]]; then
      # The log exists to answer "who ran what, and what were they charged".
      MISSING=$(echo "$ROW" | jq -r '[if .operation == null then "operation" else empty end,
                                      if .status == null then "status" else empty end,
                                      if .owner == null then "owner" else empty end,
                                      if .operation_fee_usd == null then "operation_fee_usd" else empty end] | join(",")')
      [[ -z "$MISSING" ]] \
        && pass "C8 the call log names the caller, the operation, the outcome and the fee" \
        || fail "C8 the call log row is missing: $MISSING"
    else
      fail "C8 no call for $PROJECT in the connector-call log"
    fi
  fi
fi

# ── C9: a call that never ran ────────────────────────────────────────────────
# Our capacity is not the customer's bill. Before this was settled, a timed-out
# call was settled by nobody at all: the row was marked failed, the worker
# finished into a closed door, and the work was free.
#
# Needs the fleet arranged around it, so it is driven by C9_PHASE rather than
# guessed at:
#
#   queued   — workers STOPPED. The call never leaves the queue; nothing may be
#              charged and the whole reservation must come back.
#   settled  — workers STARTED again, right after `queued`. The late completion
#              must change nothing: one usage row for that call, not two.
#   timeout  — workers RUNNING and HTTPS_CALL_TIMEOUT_SECONDS low enough that a
#              real call outruns it. Which rule applies is then decided by
#              whether a worker managed to CLAIM the job inside that window: it
#              charges the compute budget if one did and nothing if none did,
#              and the phase asserts whichever actually happened. A window short
#              enough to be reachable is usually shorter than the pickup itself,
#              so at one second this lands on the second branch even with the
#              fleet up — and the fee is never charged either way.
#
# `queued` waits out the coordinator's timeout, so with the default 300s it
# takes five minutes. Lower HTTPS_CALL_TIMEOUT_SECONDS to make it quick.
if want C9; then
  if [[ -z "$PAYMENT_KEY" ]]; then
    note "C9 SKIPPED: needs PAYMENT_KEY"
  elif [[ -z "$C9_PHASE" ]]; then
    note "C9 SKIPPED: set C9_PHASE to queued | settled | timeout — each needs the fleet arranged differently"
  elif [[ "$APPLY" != true ]]; then
    printf '\033[90m  (dry-run) C9 phase %s\033[0m\n' "$C9_PHASE" >&2
  else
    money() { curl -s "$COORDINATOR_URL/subscription/status" -H "X-Payment-Key: $PAYMENT_KEY" | jq -r "$1"; }
    # The call's own row, which is the only account of it that separates money
    # SPENT from money merely RESERVED. `/subscription/status`'s `balance` nets
    # the reservation out, so measuring a charge with it reports a call that is
    # still running as one that took the money.
    call_row() {
      curl -s "$COORDINATOR_URL/admin/connector-calls?limit=100" -H "Authorization: Bearer $ADMIN_TOKEN" \
        | jq -c --arg c "$1" 'first(.calls[] | select(.call_id==$c)) // empty'
    }
    case "$C9_PHASE" in
      queued)
        log "C9 (queued) a call with nobody to run it — workers must be STOPPED"
        if [[ -z "$ADMIN_TOKEN" ]]; then
          fail "C9 needs ADMIN_TOKEN to read the call's row"
        else
        # `burn` so that if a worker DID pick it up the difference is obvious in
        # the numbers rather than hidden in rounding.
        R=$(curl -s -X POST "$COORDINATOR_URL/call/$PROJECT" -H "X-Payment-Key: $PAYMENT_KEY" \
              -H 'Content-Type: application/json' -d '{"input":{"operation":"burn","rounds":50}}')
        CID=$(echo "$R" | jq -r '.call_id // empty' 2>/dev/null)
        if [[ -z "$CID" ]]; then
          # No JSON came back — the connection died before the coordinator
          # answered. Fall back to the newest row for this key, which is the
          # call just made.
          CID=$(curl -s "$COORDINATOR_URL/admin/connector-calls?limit=5" -H "Authorization: Bearer $ADMIN_TOKEN" \
                  | jq -r '.calls[0].call_id // empty')
          warn "C9 the request returned no JSON — the connection died before the coordinator answered"
        fi
        echo "$CID" > "$C9_STATE"

        # Wait for the coordinator to settle it, and no longer than its own
        # window plus a margin.
        ROW=""
        for _ in $(seq 1 24); do
          ROW=$(call_row "$CID")
          [[ "$(echo "$ROW" | jq -r '.status // empty')" == "pending" ]] || break
          sleep 5
        done
        STATUS=$(echo "$ROW" | jq -r '.status // "missing"')
        CHARGED=$(echo "$ROW" | jq -r '.charged_usd // "?"')

        if [[ "$STATUS" == "pending" ]]; then
          # The settlement runs INSIDE the request handler, after the wait
          # returns. If the connection dies first the handler's future is
          # dropped and nothing ever settles the row — so it sits `pending`
          # holding its reservation, with no reaper behind it. Cloudflare cuts
          # an idle request at about 100 seconds, so any window longer than
          # that is unreachable for a synchronous call.
          fail "C9 the call is STILL pending — nothing settled it, and its reservation is still held. Set HTTPS_CALL_TIMEOUT_SECONDS below Cloudflare's ~100s edge timeout so the handler can reach its own settlement"
        elif [[ "$STATUS" == "failed" && "$CHARGED" == "0" ]]; then
          # Our capacity is not the customer's bill: a job no worker ever
          # claimed has no compute to charge for.
          pass "C9 a call that never left the queue is failed and charged nothing"
        else
          fail "C9 the call ended '$STATUS' charged $CHARGED — a job no worker claimed must be failed and free"
        fi
        note "C9 now START the workers and run C9_PHASE=settled"
        fi
        ;;
      settled)
        log "C9 (settled) the late completion changes nothing — workers must be RUNNING again"
        CID=$(cat "$C9_STATE" 2>/dev/null)
        if [[ -z "$CID" ]]; then
          fail "C9 no call id from the queued phase — run C9_PHASE=queued first"
        else
          # Give the worker time to pick the old job up and finish it into a
          # door that is already closed.
          for _ in $(seq 1 20); do
            [[ "$(call_row "$CID" | jq -r '.status // "missing"')" == "pending" ]] || break
            sleep 5
          done
          ROW=$(call_row "$CID")
          ROWS=$(curl -s "$COORDINATOR_URL/admin/connector-calls?limit=100" -H "Authorization: Bearer $ADMIN_TOKEN" \
                   | jq --arg c "$CID" '[.calls[] | select(.call_id==$c)] | length')
          WD=$(money '.withdrawable'); BAL=$(money '.balance')

          [[ "${ROWS:-0}" -le 1 ]] \
            && pass "C9 the call is settled once ($ROWS row for $CID), not twice" \
            || fail "C9 $ROWS rows for call $CID — the late completion settled it a second time"
          # Whatever it ended as, nothing may stay reserved: a residue is
          # spending power the customer has silently lost.
          [[ "$WD" == "$BAL" ]] \
            && pass "C9 nothing is left reserved once the late run has settled" \
            || fail "C9 $(( BAL - WD )) still reserved after the call settled"
          note "C9 the late run ended '$(echo "$ROW" | jq -r '.status')' and charged $(echo "$ROW" | jq -r '.charged_usd')"
          # Judged, so spent: a later `settled` with no `queued` before it must
          # find nothing, not this call again.
          rm -f "$C9_STATE"
        fi
        ;;
      timeout)
        log "C9 (timeout) a call that reached a worker and outran the window"
        # `fetch`, whose fee is 15000 — distinct from the 10000 compute budget,
        # so the two numbers cannot be confused for one another. With `secret`
        # (fee 10000) a charge of 10000 would say nothing about WHICH of them
        # was taken.
        R=$(curl -s -X POST "$COORDINATOR_URL/call/$PROJECT" -H "X-Payment-Key: $PAYMENT_KEY" \
              -H 'Content-Type: application/json' -d '{"input":{"operation":"fetch"}}')
        CID=$(echo "$R" | jq -r '.call_id // empty' 2>/dev/null)
        [[ -n "$CID" ]] || CID=$(curl -s "$COORDINATOR_URL/admin/connector-calls?limit=5" -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.calls[0].call_id // empty')
        for _ in $(seq 1 12); do
          [[ "$(call_row "$CID" | jq -r '.status // "missing"')" == "pending" ]] || break
          sleep 5
        done
        ROW=$(call_row "$CID")
        STATUS=$(echo "$ROW" | jq -r '.status // "missing"')
        CHARGED=$(echo "$ROW" | jq -r '.charged_usd // "?"')

        # Which of the two rules applies is decided by whether a worker ever
        # claimed the job, not by which phase this is called. A window short
        # enough to be reachable is often shorter than the pickup itself, so
        # asking for one branch and asserting the other's number would fail
        # against correct behaviour. `time_ms` is stamped by a run; its absence
        # is "nobody took it".
        STARTED=$([[ "$(echo "$ROW" | jq -r '.time_ms')" == "null" ]] && echo false || echo true)
        if [[ "$STATUS" != "failed" ]]; then
          fail "C9 the call ended '$STATUS', not failed — it did not outrun the window at all"
        elif [[ "$STARTED" == true && "$CHARGED" == "$TIMEOUT_COMPUTE_BUDGET" ]]; then
          # They occupied a worker for the whole window they asked for, so the
          # compute budget is theirs to pay. The fee is not: a fee is for a
          # result, and there was none.
          pass "C9 a timed-out call that RAN is charged the compute budget ($CHARGED) and not the 15000 fee"
        elif [[ "$STARTED" == false && "$CHARGED" == "0" ]]; then
          # Our capacity is not the customer's bill.
          pass "C9 a timed-out call that no worker ever claimed is charged nothing"
        else
          fail "C9 ended failed, worker-claimed=$STARTED, charged $CHARGED — expected $TIMEOUT_COMPUTE_BUDGET if claimed, 0 if not"
        fi
        BAL=$(money '.balance'); WD=$(money '.withdrawable')
        [[ "$WD" == "$BAL" ]] \
          && pass "C9 the reservation came back after the timeout" \
          || fail "C9 $(( BAL - WD )) still reserved after a timed-out call"
        ;;
      *)
        fail "C9 unknown C9_PHASE '$C9_PHASE' — use queued, settled or timeout"
        ;;
    esac
  fi
fi

# ── C10: the trial key ───────────────────────────────────────────────────────
# The way in for an agent that has never paid: an ALLOWANCE, not money, scoped
# to the connector namespace and nothing else. Self-contained — it registers its
# own wallet, because a trial is one per account and a shared one would be
# claimed already.
if want C10; then
  if [[ "$APPLY" != true ]]; then
    printf '\033[90m  (dry-run) claim a trial key, spend it on a connector, and check its edges\033[0m\n' >&2
  else
    log "C10 the trial key"
    T_WK=$(curl -s -X POST "$COORDINATOR_URL/register" -H 'Content-Type: application/json' -d '{}' | jq -r '.api_key // empty')
    T_CLAIM=$(curl -s -X POST "$COORDINATOR_URL/trial-key" -H "Authorization: Bearer $T_WK" -H 'Content-Type: application/json' -d '{}')
    T_PK=$(echo "$T_CLAIM" | jq -r '.payment_key // empty')

    if [[ "$(echo "$T_CLAIM" | jq -r '.reason // empty')" == "trial_unavailable" ]]; then
      # Not a failure: a trial is not always on offer, and a test that cannot
      # get its fixture says so rather than reporting that as a fault.
      note "C10 SKIPPED: no trial is on offer to this run ($(echo "$T_CLAIM" | jq -r '.error'))."
    elif [[ -z "$T_PK" ]]; then
      fail "C10 no trial key came back: $(echo "$T_CLAIM" | head -c 200)"
    else
      NONCE=$(echo "$T_CLAIM" | jq -r '.nonce'); T10_CALLS=$(echo "$T_CLAIM" | jq -r '.calls // 0')
      T10_ENDS=$(echo "$T_CLAIM" | jq -r '.expires_at // empty')
      SCOPE=$(echo "$T_CLAIM" | jq -r '.project_ids | join(",")')
      # Nonce zero is reserved for exactly this: a key with no on-chain record,
      # which is why it costs no gas to give away.
      [[ "$NONCE" == "0" && "$T10_CALLS" =~ ^[1-9][0-9]*$ && -n "$T10_ENDS" ]] \
        && pass "C10 claimed: nonce 0, $T10_CALLS calls, until $T10_ENDS" \
        || fail "C10 claimed with nonce=$NONCE calls=$T10_CALLS expires_at='$T10_ENDS' — expected nonce 0, a number of calls and an end"
      [[ "$SCOPE" == *"$(dirname "$PROJECT")"* ]] \
        && pass "C10 scoped to the connector namespace and nothing else ($SCOPE)" \
        || fail "C10 scope is '$SCOPE' — it must not reach beyond the connectors"

      # A trial pays the connector's author NOTHING. The customer paid nothing
      # for the call, so there is nothing passing through — the rule that
      # decides whether curation costs us money on every free call.
      if [[ -n "$ADMIN_TOKEN" ]]; then
        SINCE=$(date -u -v-10M +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '10 minutes ago' +%Y-%m-%dT%H:%M:%SZ)
        rep() { curl -s "$COORDINATOR_URL/admin/earnings?from=$SINCE" -H "Authorization: Bearer $ADMIN_TOKEN"; }
        R0=$(rep)
        A0=$(echo "$R0" | jq -r '.earned.by_source.https.developer_share_usd // "0"')
        G0=$(echo "$R0" | jq -r '.given.spent_from_grants_usd // "0"')
        curl -s -X POST "$COORDINATOR_URL/call/$PROJECT" -H "X-Payment-Key: $T_PK" \
          -H 'Content-Type: application/json' -d '{"input":{"operation":"secret"}}' >/dev/null
        A1=$A0; G1=$G0
        for _ in $(seq 1 20); do
          R1=$(rep)
          A1=$(echo "$R1" | jq -r '.earned.by_source.https.developer_share_usd // "0"')
          G1=$(echo "$R1" | jq -r '.given.spent_from_grants_usd // "0"')
          [[ $(( G1 - G0 )) -gt 0 ]] && break
          sleep 3
        done
        if [[ $(( G1 - G0 )) -gt 0 && $(( A1 - A0 )) == 0 ]]; then
          pass "C10 a trial pays the author NOTHING — $(( G1 - G0 )) spent from the grant, nothing earned"
        else
          fail "C10 under a trial the author's share moved by $(( A1 - A0 )) (must be 0) and the grant by $(( G1 - G0 )) (must be > 0)"
        fi
      else
        note "C10 the author-payout rule SKIPPED — needs ADMIN_TOKEN"
      fi

      # The scope is the whole of what a trial may reach.
      OUT=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$COORDINATOR_URL/call/zavodil.testnet/some-other-project" \
              -H "X-Payment-Key: $T_PK" -H 'Content-Type: application/json' -d '{"input":{}}')
      [[ "$OUT" == "403" ]] \
        && pass "C10 a project outside the namespace is refused (403)" \
        || fail "C10 a project outside the namespace answered $OUT, not 403"

      # One per account, and the key is shown once — so a second claim must be a
      # refusal rather than a second key.
      #
      # WHICH refusal depends on which guard is reached first: the account's own
      # (`409 trial_already_claimed`) or `403 trial_unavailable`, which stands in
      # front of it. What must never happen is a second key, so that is what
      # this asserts.
      AGAIN=$(curl -s -o "$RUN_TMP"/c10_again -w '%{http_code}' -X POST "$COORDINATOR_URL/trial-key" \
                -H "Authorization: Bearer $T_WK" -H 'Content-Type: application/json' -d '{}')
      SECOND_KEY=$(jq -r '.payment_key // empty' "$RUN_TMP"/c10_again 2>/dev/null)
      if [[ -n "$SECOND_KEY" ]]; then
        fail "C10 a SECOND trial key was handed out — one per account is not being held"
      elif [[ "$AGAIN" == "409" || ( "$AGAIN" == "403" && "$(jq -r '.reason // empty' "$RUN_TMP"/c10_again 2>/dev/null)" == "trial_unavailable" ) ]]; then
        pass "C10 a second claim is refused ($AGAIN: $(jq -r '.reason // "?"' "$RUN_TMP"/c10_again 2>/dev/null))"
      else
        fail "C10 the second claim answered $AGAIN — expected 409 trial_already_claimed or 403 trial_unavailable"
      fi
    fi
  fi
fi

# ── C11: what a key may NOT do ───────────────────────────────────────────────
# Four refusals, each guarding a different way money or identity could leak
# sideways. All are cheap — one request each — and all of them are the kind of
# rule that stays correct only while something checks it.
if want C11; then
  if [[ "$APPLY" != true ]]; then
    printf '\033[90m  (dry-run) a trial cannot pay an author; a connector deposit is void; agent:true is refused\033[0m\n' >&2
  else
    log "C11 the refusals"

    # 1. A TRIAL cannot pay a developer. The allowance is ours to give away, so
    #    letting it be forwarded to somebody else would make the giveaway a
    #    money printer: claim, forward to an account you control, repeat.
    if [[ -n "$TRIAL_KEY" ]]; then
      RC=$(curl -s -o "$RUN_TMP"/c11_a -w '%{http_code}' -X POST "$COORDINATOR_URL/call/$PROJECT" \
             -H "X-Payment-Key: $TRIAL_KEY" -H 'X-Attached-Deposit: 50000' \
             -H 'Content-Type: application/json' -d '{"input":{"operation":"ping"}}')
      if [[ "$RC" == "403" ]] && grep -qi "deposit" "$RUN_TMP"/c11_a; then
        pass "C11 a trial key cannot send a deposit to an author (403)"
      else
        fail "C11 a trial key with X-Attached-Deposit answered $RC — expected 403: $(head -c 160 "$RUN_TMP"/c11_a)"
      fi
    else
      note "C11 the trial-deposit refusal SKIPPED — set TRIAL_KEY to a claimed trial key"
    fi

    # 2. A deposit on a CONNECTOR is void. Connectors are priced per operation
    #    and their author is paid out of that price; an extra payment on the
    #    side would be a second, unpriced channel to the same account.
    if [[ -n "$PAYMENT_KEY" && -n "$ADMIN_TOKEN" ]]; then
      R=$(curl -s -X POST "$COORDINATOR_URL/call/$PROJECT" -H "X-Payment-Key: $PAYMENT_KEY" \
            -H 'X-Attached-Deposit: 50000' -H 'Content-Type: application/json' \
            -d '{"input":{"operation":"ping"}}')
      CID=$(echo "$R" | jq -r '.call_id // empty')
      sleep 6
      ROW=$(curl -s "$COORDINATOR_URL/admin/connector-calls?limit=20" -H "Authorization: Bearer $ADMIN_TOKEN" \
              | jq -c --arg c "$CID" 'first(.calls[]|select(.call_id==$c)) // empty')
      CHARGED=$(echo "$ROW" | jq -r '.charged_usd // "?"')
      # `ping` is free, so anything above the compute would be the deposit
      # having gone through.
      if [[ -n "$ROW" && "$CHARGED" -lt 50000 ]]; then
        pass "C11 a deposit sent to a connector is void — charged $CHARGED, not the 50000 offered"
      else
        fail "C11 the connector call was charged $CHARGED with a 50000 deposit attached: $ROW"
      fi
    else
      note "C11 the connector-deposit check SKIPPED — needs PAYMENT_KEY and ADMIN_TOKEN"
    fi

    # 3. `agent: true` is refused rather than ignored. Keyless keys are gone —
    #    a wallet pays with a key it owns and presents — and a caller asking for
    #    one must be told, not handed a different kind of key in silence.
    if [[ -n "$AGENT_WALLET_KEY" ]]; then
      RC=$(curl -s -o "$RUN_TMP"/c11_c -w '%{http_code}' -X POST "$COORDINATOR_URL/wallet/v1/create-payment-key" \
             -H "Authorization: Bearer $AGENT_WALLET_KEY" -H 'Content-Type: application/json' \
             -d '{"agent":true,"initial_deposit_usdc":"0.10"}')
      if [[ "$RC" == 4?? ]] && grep -qi "no longer issued" "$RUN_TMP"/c11_c; then
        pass "C11 agent:true is refused and says why ($RC)"
      else
        fail "C11 agent:true answered $RC: $(head -c 160 "$RUN_TMP"/c11_c)"
      fi
    else
      note "C11 the agent:true refusal SKIPPED — needs AGENT_WALLET_KEY"
    fi

  fi
fi

# ── C12: who may read an agent's secret ──────────────────────────────────────
# The keystore's rule is unit-tested where it lives (`enforce_agent_secret`).
# What no unit test can say is whether the whole stack — coordinator, keystore,
# worker, guest — actually applies it to a real credential. These are the ways
# somebody could try to reach a secret that is not theirs, run end to end.
#
# Needs AGENT_WALLET_KEY (a wallet's wk_) with a secret already stored for it —
# C6 stores one, so run `ONLY=C6,C12`.
if want C12 && agent_secret_mode C12; then
  if [[ -z "$AGENT_WALLET_KEY" || -z "$AGENT_ACCOUNT" || -z "$AGENT_PAYMENT_KEY" ]]; then
    note "C12 SKIPPED: needs AGENT_WALLET_KEY, AGENT_PAYMENT_KEY and AGENT_ACCOUNT"
  elif [[ "$APPLY" != true ]]; then
    printf '\033[90m  (dry-run) another agent, the owner themselves, another project, and a planted credential\033[0m\n' >&2
  else
    log "C12 who may read an agent's secret"
    # → `yes` | `no` | `refused:<reason>`.
    #
    # Three states, not two. A call the coordinator REFUSED never reached the
    # guest, so it says nothing at all about who may read a secret — and read as
    # a plain "no" it would turn every refusal into a passing isolation check.
    # A spent trial is the one that bites on a trial key: every call from it is
    # then refused.
    secret_seen() {
      local r out
      r=$(curl -s -X POST "$COORDINATOR_URL/call/$PROJECT" "$@" -H 'X-Use-Owner-Secret: 1' \
            -H 'Content-Type: application/json' -d '{"input":{"operation":"secret"}}')
      out=$(echo "$r" | jq -r '.output // "null"' 2>/dev/null)
      if [[ "$out" == "null" ]]; then
        echo "refused:$(echo "$r" | jq -r '.reason // .error // "unparseable"' 2>/dev/null | head -c 60)"
      elif [[ "$(echo "$r" | jq -r '[.output.secrets[]?.found] | any')" == true ]]; then
        echo yes
      else
        echo no
      fi
    }

    # The owner's own agent reads it. Stated first so the refusals below mean
    # "not for you" rather than "nothing is there".
    #
    # Paid for with the agent's OWN PAYMENT KEY, not with its `wk_`. A `wk_`
    # names a wallet and buys nothing — the coordinator refuses it as
    # `wk_is_not_a_payer`, which this probe then read as "the agent cannot see
    # its own secret" and reported a working stack as broken. The two are the
    # same identity to the keystore: `agent_secrets_ref` keys off the payment
    # key's `owner`, and that owner is the wallet's own account.
    MINE=$(secret_seen -H "X-Payment-Key: $AGENT_PAYMENT_KEY")
    if [[ "$MINE" == yes ]]; then
      pass "C12 the agent the secret is named after does read it"
    else
      fail "C12 the agent cannot read its own secret ($MINE) — every refusal below would then pass for the wrong reason. Use a funded key, or a trial key that still has calls."
      MINE=broken
    fi

    # 1. ANOTHER agent, belonging to the same person. Its own key resolves to
    #    its own account, so it asks for a secret of its own and finds none —
    #    and would be refused by the keystore even if one existed under this
    #    name, because the profile it may read is its own.
    OTHER_WK=$(curl -s -X POST "$COORDINATOR_URL/register" -H 'Content-Type: application/json' -d '{}' | jq -r '.api_key // empty')
    OTHER_CLAIM=$(curl -s -X POST "$COORDINATOR_URL/trial-key" -H "Authorization: Bearer $OTHER_WK" -H 'Content-Type: application/json' -d '{}')
    OTHER_PK=$(echo "$OTHER_CLAIM" | jq -r '.payment_key // empty')
    if [[ -z "$OTHER_PK" ]]; then
      note "C12 the other-agent check SKIPPED — could not fund a second agent ($(echo "$OTHER_CLAIM" | jq -r '.reason // "?"'))"
    else
      THEIRS=$(secret_seen -H "X-Payment-Key: $OTHER_PK")
      case "$THEIRS" in
        no)  pass "C12 a DIFFERENT agent of the same person sees nothing" ;;
        yes) fail "C12 another agent reached this secret — the name is not binding" ;;
        *)   note "C12 the other-agent check is INCONCLUSIVE — its call was $THEIRS, so it never reached the guest" ;;
      esac
    fi

    # 2. The person themselves, through an ordinary payment key. Their key is
    #    owned by a NAMED account, and a named account addresses its own
    #    secrets through the body — pointing it at an agent's would be
    #    inventing a meaning nobody asked for.
    if [[ -n "$PAYMENT_KEY" ]]; then
      OWNERS=$(secret_seen -H "X-Payment-Key: $PAYMENT_KEY")
      case "$OWNERS" in
        no)  pass "C12 the person who PAID for the secret cannot read it through their own key" ;;
        yes) fail "C12 an ordinary payment key reached an agent's secret" ;;
        *)   note "C12 the owner's-own-key check is INCONCLUSIVE — its call was $OWNERS" ;;
      esac
    else
      note "C12 the owner's-own-key check SKIPPED — needs PAYMENT_KEY"
    fi

    # 3. Another PROJECT. The seed names the project, so the same agent under a
    #    different connector is a different secret — one sealed for one cannot
    #    be opened for the other.
    K1=$(curl -s -G "$COORDINATOR_URL/wallet/v1/agent-secret/pubkey" --data-urlencode "project_id=$PROJECT" \
           -H "Authorization: Bearer $AGENT_WALLET_KEY" | jq -r '.pubkey // empty')
    K2=$(curl -s -G "$COORDINATOR_URL/wallet/v1/agent-secret/pubkey" --data-urlencode "project_id=$PROJECT-other" \
           -H "Authorization: Bearer $AGENT_WALLET_KEY" | jq -r '.pubkey // empty')
    [[ -n "$K1" && -n "$K2" && "$K1" != "$K2" ]] \
      && pass "C12 the same agent under another project gets a different key" \
      || fail "C12 two projects share one key for this agent ($K1 / $K2)"

    # 4. A credential PLANTED under the agent's name by somebody else. Anyone
    #    may call `store_secrets` and an agent's account is public, so this is
    #    the attack the ownership half of the rule exists for: the connector
    #    running on the planter's token instead of the agent's.
    if [[ -n "$CALLER" ]] && "$OUTLAYER_BIN" secrets set --help >/dev/null 2>&1; then
      PLANT_OK=1
      "$OUTLAYER_BIN" secrets set "$(jq -nc '{PROBE_TOKEN:"planted-by-a-stranger"}')" \
        --project "$PROJECT" --profile "$AGENT_ACCOUNT" >&2 2>/dev/null || PLANT_OK=0
      sleep 5
      R=$(curl -s -X POST "$COORDINATOR_URL/call/$PROJECT" -H "Authorization: Bearer $AGENT_WALLET_KEY" \
            -H 'X-Use-Owner-Secret: 1' -H 'Content-Type: application/json' \
            -d '{"input":{"operation":"secret"}}')
      STILL=$(echo "$R" | jq -r '.output.secrets[]? | select(.key=="PROBE_TOKEN") | .sha256_prefix')
      PLANTED=$(printf '%s' "planted-by-a-stranger" | shasum -a 256 | cut -c1-8)
      if [[ "$(echo "$R" | jq -r '.output // "null"')" == "null" ]]; then
        # An empty answer is not evidence: the call has to have RUN for "the
        # planted secret was not served" to mean anything.
        note "C12 the planted-credential check is INCONCLUSIVE — the call was $(echo "$R" | jq -r '.reason // .error' | head -c 50)"
      elif [[ "$STILL" == "$PLANTED" ]]; then
        fail "C12 the guest received the PLANTED credential — a stranger's secret was served under the agent's name"
      elif [[ "$PLANT_OK" != 1 ]]; then
        # The contract refuses an implicit-account profile to a non-agent owner,
        # so the plant never landed. Saying "not served" here would be a pass
        # for a credential that was never stored.
        skip "C12 the planted-credential check is INCONCLUSIVE — the store itself was refused, so nothing was planted to serve"
      else
        pass "C12 a credential planted under the agent's name by another owner is not served (guest saw ${STILL:-nothing}, not $PLANTED)"
      fi
    else
      note "C12 the planted-credential check SKIPPED — needs CALLER and the outlayer CLI"
    fi

    # 5. Nothing hands out plaintext. The pubkey endpoint answers with a public
    #    key and a name; the store endpoint takes ciphertext or nothing.
    PUB=$(curl -s -G "$COORDINATOR_URL/wallet/v1/agent-secret/pubkey" --data-urlencode "project_id=$PROJECT" \
            -H "Authorization: Bearer $AGENT_WALLET_KEY")
    EXTRA=$(echo "$PUB" | jq -r 'keys - ["pubkey","seed","agent_account"] | join(",")')
    [[ -z "$EXTRA" ]] \
      && pass "C12 the pubkey endpoint returns a key and a name, nothing else" \
      || fail "C12 the pubkey endpoint also returned: $EXTRA"
    RC=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$COORDINATOR_URL/wallet/v1/agent-secret" \
           -H "Authorization: Bearer $AGENT_WALLET_KEY" -H 'Content-Type: application/json' \
           -d "$(jq -nc --arg p "$PROJECT" '{project_id:$p, encrypted_secrets_base64:""}')")
    [[ "$RC" == 4?? ]] \
      && pass "C12 storing without ciphertext is refused ($RC) — this process must never see a plaintext credential" \
      || fail "C12 an empty ciphertext answered $RC"
  fi
fi

# ── C13: when the subscription runs out ──────────────────────────────────────
# A key can hold both: money it was funded with, and an allowance a subscription
# bought. While the subscription is live its calls cost the money nothing. The
# question this answers is what happens the day after — the money must still be
# there, and the next call must come out of it.
#
# `EXPIRED_SUB_KEY` is a key whose subscription has ENDED and which still holds
# money. Thirty days is not a thing a test can wait for, so the operator makes
# one: `UPDATE payment_keys SET expires_at = NOW() - interval '1 day'`.
if want C13; then
  if [[ -z "$EXPIRED_SUB_KEY" ]]; then
    note "C13 SKIPPED: set EXPIRED_SUB_KEY to a key whose subscription has expired and which still has a balance"
  elif [[ -z "$ADMIN_TOKEN" ]]; then
    note "C13 SKIPPED: needs ADMIN_TOKEN to read how the call was paid for"
  elif [[ "$APPLY" != true ]]; then
    printf '\033[90m  (dry-run) a call on an expired subscription falls back to the money balance\033[0m\n' >&2
  else
    log "C13 an expired subscription falls back to the balance"
    ST=$(curl -s "$COORDINATOR_URL/subscription/status" -H "X-Payment-Key: $EXPIRED_SUB_KEY")
    EXPIRED=$(echo "$ST" | jq -r '.expired'); AVAIL=$(echo "$ST" | jq -r '.allowance_available_usd // "0"')
    BAL0=$(echo "$ST" | jq -r '.balance')

    if [[ "$EXPIRED" != true ]]; then
      fail "C13 this key's subscription has not expired — the fixture is wrong, nothing below would mean anything"
    else
      # An expired subscription grants nothing. Reporting time left on it would
      # be the same mistake as honouring it.
      [[ "${AVAIL:-0}" == "0" ]] \
        && pass "C13 an expired subscription offers no allowance at all" \
        || fail "C13 the expired subscription still reports $AVAIL available"

      R=$(curl -s -X POST "$COORDINATOR_URL/call/$PROJECT" -H "X-Payment-Key: $EXPIRED_SUB_KEY" \
            -H 'Content-Type: application/json' -d '{"input":{"operation":"secret"}}')
      CID=$(echo "$R" | jq -r '.call_id // empty')
      if [[ -z "$CID" ]]; then
        fail "C13 the call did not run: $(echo "$R" | head -c 160)"
      else
        sleep 8
        ROW=$(curl -s "$COORDINATOR_URL/admin/connector-calls?limit=30" -H "Authorization: Bearer $ADMIN_TOKEN" \
                | jq -c --arg c "$CID" 'first(.calls[]|select(.call_id==$c)) // empty')
        FROM_ALLOW=$(echo "$ROW" | jq -r '.from_allowance')
        CHARGED=$(echo "$ROW" | jq -r '.charged_usd // "?"')
        BAL1=$(curl -s "$COORDINATOR_URL/subscription/status" -H "X-Payment-Key: $EXPIRED_SUB_KEY" | jq -r '.balance')

        [[ "$FROM_ALLOW" == false ]] \
          && pass "C13 the call is paid from the BALANCE, not from a dead allowance (charged $CHARGED)" \
          || fail "C13 the call reports from_allowance=$FROM_ALLOW — an expired subscription is still paying"
        # The money was there all along: an allowance covering calls must not
        # have been quietly spending it.
        [[ $(( BAL0 - BAL1 )) == "$CHARGED" ]] \
          && pass "C13 the balance fell by exactly what was charged ($CHARGED)" \
          || fail "C13 the balance moved by $(( BAL0 - BAL1 )) while the call was charged $CHARGED"
      fi
    fi
  fi
fi

# ── C14: the refusals a key can hit before anything runs, and one that is not ─
#
# Every one of these is a 4xx the caller is supposed to act on, so what matters
# is not only THAT the call is refused but that the answer names a number the
# caller can do something with.
#
# Its last row is the counterpart: a TRIAL is never refused for a sum, so an
# oversized compute budget on one is clamped and the call runs. The one-call-at-
# a-time refusal (`call_already_in_flight`) is judged in C16.
if want C14; then
  if [[ "$APPLY" != true ]]; then
    printf '\033[90m  (dry-run) insufficient balance, max_per_call, allowance+deposit, allowance too small; an oversized compute budget on a trial key runs (spends one trial call)\033[0m\n' >&2
  else
    log "C14 the refusals that come before the work"

    # 1. No money at all. EMPTY_KEY must be a key with NO subscription either:
    #    an allowance pays for the call and there is nothing to refuse.
    if [[ -n "$EMPTY_KEY" ]]; then
      RC=$(curl -s -o "$RUN_TMP"/c14_a -w '%{http_code}' -X POST "$COORDINATOR_URL/call/$PROJECT" \
             -H "X-Payment-Key: $EMPTY_KEY" -H 'Content-Type: application/json' \
             -d '{"input":{"operation":"secret"}}')
      if [[ "$RC" == "402" ]] && grep -qi "insufficient balance" "$RUN_TMP"/c14_a; then
        pass "C14 a key with nothing in it is refused with 402 ($(jq -r '.error' "$RUN_TMP"/c14_a 2>/dev/null | head -c 60))"
      else
        fail "C14 an empty key answered $RC: $(head -c 160 "$RUN_TMP"/c14_a)"
      fi
    else
      note "C14 the balance refusal SKIPPED — needs EMPTY_KEY (registered, no balance, no subscription)"
    fi

    # 2. A cap below what the call reserves. The cap is on the RESERVATION, so
    #    it has to sit below compute plus the fee, not below the fee alone.
    if [[ -n "$CAPPED_KEY" ]]; then
      RC=$(curl -s -o "$RUN_TMP"/c14_c -w '%{http_code}' -X POST "$COORDINATOR_URL/call/$PROJECT" \
             -H "X-Payment-Key: $CAPPED_KEY" -H 'Content-Type: application/json' \
             -d '{"input":{"operation":"secret"}}')
      if [[ "$RC" == "400" ]] && grep -qi "max per call exceeded" "$RUN_TMP"/c14_c; then
        pass "C14 a call over the key's max_per_call is refused ($(jq -r '.error' "$RUN_TMP"/c14_c 2>/dev/null | head -c 60))"
      else
        fail "C14 a capped key answered $RC: $(head -c 160 "$RUN_TMP"/c14_c)"
      fi
    else
      note "C14 max_per_call SKIPPED — need CAPPED_KEY (create one with max_per_call below the fee)"
    fi

    # 2b. One call, two refusals, two prices.
    #
    # The balance refusal says what the caller must HOLD; the `max_per_call`
    # refusal says what the same call RESERVES. A caller who funds to the first
    # figure and retries is refused again by the second, so these two agreeing
    # is the whole content of "the error tells you what to do".
    #
    # Read off the two refusals above rather than by funding a key to the quoted
    # figure: the operation and the compute limit are identical in both, so the
    # reservation is the same number either way, and this needs no money to move.
    SAID=$(jq -r '.error' "$RUN_TMP"/c14_a 2>/dev/null | sed -n 's/.*required=\([0-9]*\).*/\1/p')
    RESERVED=$(jq -r '.error' "$RUN_TMP"/c14_c 2>/dev/null | sed -n 's/.*requested=\([0-9]*\).*/\1/p')
    if [[ -z "$SAID" || -z "$RESERVED" ]]; then
      note "C14 the two-figure check SKIPPED — needs both the balance and the max_per_call refusals to have run"
    elif [[ "$SAID" == "$RESERVED" ]]; then
      pass "C14 both refusals quote the same cost for the same call ($SAID)"
    else
      fail "C14 the balance refusal asks for $SAID and the same call reserves $RESERVED — a caller who funds to the quoted figure is refused again"
    fi

    # 3. A deposit on a call an allowance is paying for. Only reachable on an
    #    ORDINARY project: a connector's deposit is zeroed before this rule is
    #    reached, because a connector is paid by its fee and not by a deposit.
    #    That is why this needs a second project rather than the probe.
    if [[ -n "$SUB_KEY" && -n "$ORDINARY_PROJECT" ]]; then
      RC=$(curl -s -o "$RUN_TMP"/c14_d -w '%{http_code}' --max-time 45 -X POST "$COORDINATOR_URL/call/$ORDINARY_PROJECT" \
             -H "X-Payment-Key: $SUB_KEY" -H 'X-Attached-Deposit: 50000' \
             -H 'Content-Type: application/json' -d '{"input":{"operation":"ping"}}')
      if [[ "$RC" == "402" ]] && grep -q "allowance_no_deposit" "$RUN_TMP"/c14_d; then
        pass "C14 an allowance cannot be paid to a developer (402 allowance_no_deposit)"
      else
        fail "C14 a deposit on an allowance-covered call answered $RC: $(head -c 200 "$RUN_TMP"/c14_d)"
      fi
    else
      note "C14 allowance+deposit SKIPPED — needs SUB_KEY and ORDINARY_PROJECT (a NON-connector project)"
    fi

    # 4. An allowance too small for the job. Reached by asking for more compute
    #    than the allowance has left, rather than by draining it: the ceiling
    #    admission checks is the price PLUS the compute the caller authorised,
    #    so a large job refuses itself against a small allowance. Judged on a
    #    SUBSCRIBED key, whose allowance is a figure its holder is shown — and
    #    one with NO money on it: a key that also holds a balance pays the call
    #    from that instead of refusing.
    if [[ -n "$SUB_KEY" ]]; then
      LEFT=$(curl -s "$COORDINATOR_URL/subscription/status" -H "X-Payment-Key: $SUB_KEY" | jq -r '.allowance_available_usd // 0')
      BIG=$(( LEFT * 5 + 1000000 ))
      RC=$(curl -s -o "$RUN_TMP"/c14_e -w '%{http_code}' --max-time 45 -X POST "$COORDINATOR_URL/call/$PROJECT" \
             -H "X-Payment-Key: $SUB_KEY" -H "X-Compute-Limit: $BIG" \
             -H 'Content-Type: application/json' -d '{"input":{"operation":"secret"}}')
      if [[ "$RC" == "402" ]] && grep -q "insufficient_allowance" "$RUN_TMP"/c14_e; then
        pass "C14 a job larger than the allowance is refused before it starts (asked $BIG, had $LEFT)"
      else
        fail "C14 an oversized job on a $LEFT allowance answered $RC: $(head -c 200 "$RUN_TMP"/c14_e)"
      fi
    else
      note "C14 the allowance refusal SKIPPED — needs SUB_KEY"
    fi

    # 5. A TRIAL is never refused for a sum: its holder is shown calls, not
    #    dollars, so a compute budget above what stands behind the trial is
    #    clamped and the call runs. Spends one of the trial's calls.
    if [[ -n "$TRIAL_KEY" ]]; then
      RC=$(curl -s -o "$RUN_TMP"/c14_f -w '%{http_code}' --max-time 60 -X POST "$COORDINATOR_URL/call/$PROJECT" \
             -H "X-Payment-Key: $TRIAL_KEY" -H "X-Compute-Limit: 1000000000" \
             -H 'Content-Type: application/json' -d '{"input":{"operation":"ping"}}')
      if [[ "$RC" == "200" ]]; then
        pass "C14 a trial call asking for an oversized compute budget is clamped and runs"
      elif [[ "$(jq -r '.reason' "$RUN_TMP"/c14_f 2>/dev/null)" == "trial_expired" ]] \
           || [[ "$(jq -r '.reason' "$RUN_TMP"/c14_f 2>/dev/null)" == "trial_exhausted" \
                 && "$(jq -r '.used' "$RUN_TMP"/c14_f)" == "$(jq -r '.limit' "$RUN_TMP"/c14_f)" ]]; then
        note "C14 the trial clamp SKIPPED — TRIAL_KEY is spent or past its week"
      else
        fail "C14 a trial call with an oversized compute budget answered $RC: $(head -c 200 "$RUN_TMP"/c14_f)"
      fi
    else
      note "C14 the trial clamp SKIPPED — needs TRIAL_KEY"
    fi
  fi
fi

# ── C15: an allowance across the KINDS of operation ──────────────────────────
#
# C10 and C13 each exercise one operation, which cannot distinguish "the
# allowance works" from "the allowance works for that one price". Three kinds
# differ in what they should cost and in who they should pay: free, priced with
# no author, priced with an author.
#
# The claim under test is the one that costs us money if it is wrong: an
# allowance pays the author NOTHING. We sold the credit wholesale, so a share
# paid out of it would be funded from our own revenue on every free call we give
# away.
if want C15; then
  if [[ "$APPLY" != true ]]; then
    printf '\033[90m  (dry-run) free / no-author / author operations under an allowance\033[0m\n' >&2
  elif [[ -z "$ADMIN_TOKEN" ]]; then
    note "C15 SKIPPED: needs ADMIN_TOKEN to read what the author was paid"
  else
    log "C15 an allowance across the kinds of operation"
    # A DELTA across a wide fixed window, not the contents of a narrow one.
    #
    # The claim is "these calls paid the author nothing", and a window is the
    # wrong instrument for it: made narrow it can miss a credit that lands a
    # moment late, and made wide it catches the money calls C5 and C11 just
    # made — which pay the author correctly, and which made this read 59831
    # against 46002 of allowance spend the first time the whole suite ran in one
    # go. Reading the same window before and after cancels everything that is
    # not these calls, whatever else shares the window.
    SINCE15=$(date -u -v-30M +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '30 minutes ago' +%Y-%m-%dT%H:%M:%SZ)
    author_share_now() {
      curl -s "$COORDINATOR_URL/admin/earnings?from=$SINCE15" -H "Authorization: Bearer $ADMIN_TOKEN" \
        | jq -r '.earned.developer_share_usd'
    }
    SHARE_BEFORE=$(author_share_now)
    # How many of the six calls actually RAN. The ledger check below is a claim
    # about those calls, so with none of them made it has no subject and must
    # say so rather than read an empty window as a verdict.
    C15_RAN=0

    # ping is free, whoami is priced with a zero share, secret is priced with a
    # 7000bp share. Under an allowance all three must come out of the allowance
    # and none of them may reach the author.
    for CRED in TRIAL SUB; do
      KEY=$([[ "$CRED" == TRIAL ]] && echo "$TRIAL_KEY" || echo "$SUB_KEY")
      [[ -z "$KEY" ]] && { note "C15 $CRED SKIPPED — no key"; continue; }
      for OP in ping whoami secret; do
        # A subscription is read in dollars; a trial in the only unit its holder
        # is shown, calls. What neither may do — reach the author — is judged
        # below from the ledger, for both.
        C15_READ=$([[ "$CRED" == TRIAL ]] && echo '.trial.calls_used // 0' || echo '.allowance_available_usd // 0')
        A=$(curl -s "$COORDINATOR_URL/subscription/status" -H "X-Payment-Key: $KEY" | jq -r "$C15_READ")
        RC=$(curl -s -o "$RUN_TMP"/c15_r -w '%{http_code}' --max-time 60 -X POST "$COORDINATOR_URL/call/$PROJECT" \
          -H "X-Payment-Key: $KEY" -H 'Content-Type: application/json' \
          -d "{\"input\":{\"operation\":\"$OP\"}}")
        # A call that never ran spends nothing, and "spent nothing" is exactly
        # what this section reads as "the fee was not charged". They have to be
        # told apart or a refusal is reported as a pricing failure — which is
        # what a run on a spent trial key would otherwise produce.
        if [[ "$RC" != "200" ]]; then
          note "C15 $CRED $OP INCONCLUSIVE — the call was refused ($RC $(jq -r '.reason // "?"' "$RUN_TMP"/c15_r 2>/dev/null)), so nothing was charged either way"
          continue
        fi
        C15_RAN=$((C15_RAN + 1))
        sleep 5
        B=$(curl -s "$COORDINATOR_URL/subscription/status" -H "X-Payment-Key: $KEY" | jq -r "$C15_READ")
        if [[ "$CRED" == TRIAL ]]; then
          [[ $(( B - A )) -eq 1 ]] \
            && pass "C15 TRIAL $OP counted as one trial call ($A → $B)" \
            || fail "C15 TRIAL $OP moved calls_used $A → $B — one accepted call is one trial call"
          continue
        fi
        SPENT=$(( A - B ))
        # A free operation costs compute alone; a priced one costs the fee on
        # top of it. Stated as a comparison against the free reading rather than
        # a literal, because compute is metered per call — see C5.
        case "$OP" in
          ping)  [[ $SPENT -gt 0 && $SPENT -lt 10000 ]] \
                   && pass "C15 $CRED ping came out of the allowance at compute only ($SPENT)" \
                   || fail "C15 $CRED ping took $SPENT from the allowance — a free operation should cost compute alone" ;;
          *)     [[ $SPENT -ge 10000 ]] \
                   && pass "C15 $CRED $OP took the fee out of the allowance ($SPENT)" \
                   || fail "C15 $CRED $OP took only $SPENT from the allowance — the fee was not charged" ;;
        esac
      done
    done

    # And the ledger: none of the calls above reached the author.
    if [[ "$C15_RAN" -eq 0 ]]; then
      # Both credentials were missing, so nothing was called and the window is
      # empty for that reason alone. Asserting here reported "credit moved by 0 —
      # an allowance must pay nobody", which is the PASSING condition spelled as
      # a failure: the delta was right and the run had simply not happened.
      note "C15 the ledger check SKIPPED — none of the six calls ran (set TRIAL_KEY and/or SUB_KEY)"
    else
      R15=$(curl -s "$COORDINATOR_URL/admin/earnings?from=$SINCE15" -H "Authorization: Bearer $ADMIN_TOKEN")
      SHARE_AFTER=$(echo "$R15" | jq -r '.earned.developer_share_usd')
      SPENT15=$(echo "$R15" | jq -r '(.given.spent_from_grants_usd|tonumber) + (.given.spent_from_subscriptions_usd|tonumber)')
      CREDITED=$(( SHARE_AFTER - SHARE_BEFORE ))
      if [[ $CREDITED != 0 ]]; then
        fail "C15 $C15_RAN allowance calls moved the author's credit by $CREDITED ($SHARE_BEFORE → $SHARE_AFTER) — an allowance must pay nobody"
      elif [[ "$SPENT15" -le 0 ]]; then
        # Credit did not move, but neither did allowance spend — so the zero
        # above proves nothing about who was paid. Separated from the case
        # above because the two have different causes and different fixes.
        fail "C15 $C15_RAN allowance calls ran, yet the window shows no allowance spend ($SPENT15) — the ledger is not seeing them, so 'the author got 0' is unproven"
      else
        pass "C15 $C15_RAN allowance calls credited the author 0 (window holds $SPENT15 of allowance spend)"
      fi
    fi
  fi
fi

# ── C16: one call at a time on a subscription, money unaffected ──────────────
#
# The rule seen from outside: a subscription runs ONE call at a time, and a key
# paying with money is not limited that way.
#
# Ordered rather than raced, and that is not a weaker test — it is the only
# honest one. `async: true` returns once the call is ACCEPTED, and the call row
# is written before that answer is sent, so when the first request comes back
# its call is on record as pending. Sending the second only then removes the one
# window the limit does not close (two requests arriving before either has
# written its row), which is documented and deliberate. Firing both at once
# would be testing that race instead of the rule.
#
# `secret` rather than `burn`: only `burn` carries a declared per-day cap, and
# four calls a run would spend it in two runs — after which this section would
# be measuring that cap instead.
#
# SUB_KEY must have an allowance and NO balance for the refusal half to be
# reachable: with money in the same key the second call is answered from the
# balance instead, which is the deliberate fallback and is the third check here.
if want C16; then
  if [[ "$APPLY" != true ]]; then
    printf '\033[90m  (dry-run) two subscription calls at once, and a money call alongside one\033[0m\n' >&2
  elif [[ -z "$SUB_KEY" || -z "$PAYMENT_KEY" ]]; then
    note "C16 SKIPPED: needs SUB_KEY (a live subscription) and PAYMENT_KEY (money, no subscription)"
  else
    log "C16 one call at a time on a subscription"

    fire() { # fire <key> <outfile> — returns as soon as the call is ACCEPTED
      curl -s -o "$2" -w '%{http_code}' --max-time 60 -X POST "$COORDINATOR_URL/call/$PROJECT" \
        -H "X-Payment-Key: $1" -H 'Content-Type: application/json' \
        -d '{"input":{"operation":"secret"},"async":true}'
    }

    # Is the call named in <file> still running? A first call that finished
    # before the second was sent proves nothing either way, and saying so is
    # better than reporting a pass nobody can rely on.
    still_pending() {
      local cid
      cid=$(jq -r '.call_id // empty' "$1" 2>/dev/null)
      [[ -z "$cid" ]] && return 1
      [[ "$(curl -s "$COORDINATOR_URL/calls/$cid" -H "X-Payment-Key: $2" | jq -r '.status')" == "pending" ]]
    }

    # Wait for it to stop running. Each part of this section arranges a call to
    # be IN FLIGHT, so a part that starts while the previous one's call is still
    # going measures the leftover instead of what it set up — which is exactly
    # how this first went wrong: part 2's subscription call was refused by the
    # limit part 1 had just triggered, and the section reported a product
    # failure that was its own sequencing.
    wait_settled() {
      local i
      for i in $(seq 1 30); do
        still_pending "$1" "$2" || return 0
        sleep 1
      done
      return 1
    }

    SUB_MONEY=$(curl -s "$COORDINATOR_URL/subscription/status" -H "X-Payment-Key: $SUB_KEY" | jq -r '.balance')

    # 1. A second call on the SUBSCRIPTION while the first is still running.
    RC_A=$(fire "$SUB_KEY" "$RUN_TMP"/c16_a)
    if [[ "$RC_A" != "200" ]]; then
      fail "C16 the first subscription call was refused ($RC_A): $(head -c 160 "$RUN_TMP"/c16_a)"
    elif ! still_pending "$RUN_TMP"/c16_a "$SUB_KEY"; then
      note "C16 INCONCLUSIVE: the first call finished before the second could be sent — nothing was in flight to collide with"
    else
      RC_B=$(fire "$SUB_KEY" "$RUN_TMP"/c16_b)
      if [[ "$SUB_MONEY" -gt 0 ]]; then
        # Money in the same key: the second is ANSWERED rather than refused, out
        # of the balance. That is the fallback working, not a hole in the limit.
        [[ "$RC_B" == "200" ]] \
          && pass "C16 a subscription key holding money answers a second call — it comes out of the balance" \
          || fail "C16 a funded subscription key refused the second call ($RC_B): $(head -c 160 "$RUN_TMP"/c16_b)"
        note "C16 the refusal half needs a subscription key with a ZERO balance; this one holds $SUB_MONEY"
      else
        [[ "$RC_B" == "429" ]] \
          && pass "C16 a second subscription call is refused while the first runs (429)" \
          || fail "C16 a second concurrent subscription call answered $RC_B, not 429: $(head -c 200 "$RUN_TMP"/c16_b)"
        # And the RIGHT 429: the IP rate limiter also answers 429 and would
        # satisfy the code above while meaning something else entirely.
        if grep -q "call_already_in_flight" "$RUN_TMP"/c16_b 2>/dev/null; then
          [[ "$(jq -r '.terminal' "$RUN_TMP"/c16_b)" == "false" ]] \
            && pass "C16 the refusal is call_already_in_flight and says it is worth retrying" \
            || fail "C16 call_already_in_flight came back terminal — a client would stop instead of waiting"
        else
          fail "C16 the refusal was not call_already_in_flight: $(head -c 200 "$RUN_TMP"/c16_b)"
        fi
      fi
    fi

    # 2. A MONEY key while a subscription call runs. Two different keys, so the
    #    limit must not reach across them — it is keyed per (owner, nonce), and
    #    nothing but this says so.
    #
    #    Part 1's call has to be out of the way first, or the subscription call
    #    below is refused by part 1's own limit rather than running.
    if ! wait_settled "$RUN_TMP"/c16_a "$SUB_KEY"; then
      note "C16 the first call never settled — skipping the money-key check rather than measuring it"
    else
    RC_C=$(fire "$SUB_KEY" "$RUN_TMP"/c16_c)
    if [[ "$RC_C" != "200" ]]; then
      fail "C16 the subscription call was refused ($RC_C): $(head -c 160 "$RUN_TMP"/c16_c)"
    elif ! still_pending "$RUN_TMP"/c16_c "$SUB_KEY"; then
      note "C16 INCONCLUSIVE: the subscription call finished before the money call was sent"
    else
      RC_D=$(fire "$PAYMENT_KEY" "$RUN_TMP"/c16_d)
      [[ "$RC_D" == "200" ]] \
        && pass "C16 a money key runs alongside a subscription call ($RC_D)" \
        || fail "C16 the money key was refused ($RC_D) while a subscription call ran: $(head -c 160 "$RUN_TMP"/c16_d)"
    fi
    fi
  fi
fi

# ── C17: buying a subscription a SECOND time, and the trial's ceiling ────────
#
# What a paying customer does after the first month, and what a trial user tries
# when they want more. Neither had a live test, and both are money paths.
if want C17; then
  if [[ "$APPLY" != true ]]; then
    printf '\033[90m  (dry-run) renewing a live subscription, and funding a trial key\033[0m\n' >&2
  else
    log "C17 renewal, and what a trial key may not do"

    # 1. Renewing while the subscription is still live.
    #
    # The two ways this goes wrong are opposite and both silent: a renewal that
    # REPLACES throws away the allowance still on the key, and one that dates
    # the new period from `now` throws away the days. Gated behind its own
    # variable because it spends a real plan's worth every run.
    if [[ -z "$RENEW_KEY" || -z "$CALLER" ]]; then
      note "C17 renewal SKIPPED — set RENEW_KEY (a key with a LIVE subscription) and CALLER to spend a plan on it"
    else
      B=$(curl -s "$COORDINATOR_URL/subscription/status" -H "X-Payment-Key: $RENEW_KEY")
      T0=$(echo "$B" | jq -r '.allowance_total_usd'); S0=$(echo "$B" | jq -r '.allowance_spent_usd')
      E0=$(echo "$B" | jq -r '.expires_at')
      NONCE=$(echo "$RENEW_KEY" | cut -d: -f2)
      OWNER=$(echo "$RENEW_KEY" | cut -d: -f1)

      # Output KEPT. Discarded, a transaction that never landed reads downstream
      # as "the allowance did not move", which this section then reports as the
      # product replacing an allowance instead of adding to it — a failure
      # invented by the harness, about code that was never reached.
      # Built on its own line, NOT inline as `json-args "$(jq ...)"`.
      #
      # This filter contains double quotes inside its single quotes — the `msg`
      # is itself JSON — and nesting that in a double-quoted command
      # substitution ends the quoting early enough for bash to brace-expand the
      # `{...,...,...}` inside it: jq runs three times on three fragments, the
      # argument list gains two entries nobody wrote, and near answers
      # `unexpected argument '--quiet'`, which says nothing about the cause.
      # Every other `near` call here has a filter with no inner quotes, which is
      # why this is the first one to hit it.
      BUY_ARGS=$(jq -nc --arg r "$CONTRACT_ID" --arg a "$PLAN_PRICE" --arg n "$NONCE" \
        '{receiver_id:$r, amount:$a, msg:("{\"action\":\"buy_subscription\",\"nonce\":" + $n + ",\"plan\":0}")}')

      if ! near --quiet contract call-function as-transaction "$TOKEN_CONTRACT" ft_transfer_call \
        json-args "$BUY_ARGS" \
        prepaid-gas '300.0 Tgas' attached-deposit '1 yoctoNEAR' \
        sign-as "$OWNER" network-config "$NETWORK" sign-with-keychain send >"$RUN_TMP"/c17_buy 2>&1
      then
        fail "C17 the renewal transaction did not send: $(tail -c 200 "$RUN_TMP"/c17_buy)"
      fi
      # The transfer answers with the amount USED. Zero means the contract
      # refused and handed it all back, which is a different failure from a
      # renewal that applied wrongly — and it must not be read as the latter.
      if ! grep -q "$PLAN_PRICE" "$RUN_TMP"/c17_buy; then
        note "C17 the renewal was not accepted by the contract: $(tail -c 200 "$RUN_TMP"/c17_buy)"
      fi
      sleep 14

      A=$(curl -s "$COORDINATOR_URL/subscription/status" -H "X-Payment-Key: $RENEW_KEY")
      T1=$(echo "$A" | jq -r '.allowance_total_usd'); S1=$(echo "$A" | jq -r '.allowance_spent_usd')
      E1=$(echo "$A" | jq -r '.expires_at')

      [[ $(( T1 - T0 )) -gt 0 ]] \
        && pass "C17 a renewal ADDS to the allowance ($T0 → $T1) — it does not replace it" \
        || fail "C17 the allowance went $T0 → $T1 on renewal; a replacement throws away what the customer already paid for"
      [[ "$S1" == "$S0" ]] \
        && pass "C17 and what was already spent is untouched ($S0)" \
        || fail "C17 spent moved $S0 → $S1 on a renewal — nothing was consumed by buying"

      # The one that cannot be seen by eye: the new period has to start where
      # the old one ENDED. Dated from `now` instead, renewing on day one of a
      # month silently costs the customer the other twenty-nine.
      GAP=$(python3 - "$E0" "$E1" <<'PY'
import sys, datetime
def p(s): return datetime.datetime.fromisoformat(s.replace('Z','+00:00'))
print(int((p(sys.argv[2]) - p(sys.argv[1])).total_seconds()))
PY
)
      if [[ $GAP -gt 2000000 ]]; then
        pass "C17 the new period starts where the old one ended — expiry moved $(( GAP / 86400 )) days from the OLD date"
      else
        fail "C17 expiry moved only $GAP seconds from the old date ($E0 → $E1) — a renewal dated from now loses the days still paid for"
      fi
    fi

    # 2. A trial key cannot be turned into a funded one.
    #
    # A trial lives at nonce 0, in the coordinator's database only, with no
    # on-chain record — so the top-up finds no key and the transfer has to come
    # back WHOLE. This is the NEP-141 refund-on-panic path, which nothing else
    # here exercises, and getting it wrong means keeping money for nothing.
    if [[ -z "$TRIAL_KEY" || -z "$CALLER" ]]; then
      note "C17 the trial ceiling SKIPPED — needs TRIAL_KEY and CALLER"
    else
      TRIAL_OWNER=$(echo "$TRIAL_KEY" | cut -d: -f1)
      bal_of() {
        near --quiet contract call-function as-read-only "$TOKEN_CONTRACT" ft_balance_of \
          json-args "$(jq -nc --arg a "$CALLER" '{account_id:$a}')" network-config "$NETWORK" now 2>/dev/null \
          | tr -d '"' | tr -d '[:space:]'
      }
      U0=$(bal_of)
      # Same reason as the renewal above: built on its own line.
      TOPUP_ARGS=$(jq -nc --arg r "$CONTRACT_ID" --arg o "$TRIAL_OWNER" \
        '{receiver_id:$r, amount:"10000", msg:("{\"action\":\"top_up_payment_key\",\"nonce\":0,\"owner\":\"" + $o + "\"}")}')

      near --quiet contract call-function as-transaction "$TOKEN_CONTRACT" ft_transfer_call \
        json-args "$TOPUP_ARGS" \
        prepaid-gas '300.0 Tgas' attached-deposit '1 yoctoNEAR' \
        sign-as "$CALLER" network-config "$NETWORK" sign-with-keychain send >"$RUN_TMP"/c17_topup 2>&1
      sleep 6
      U1=$(bal_of)

      if [[ -z "$U0" || -z "$U1" ]]; then
        note "C17 the trial ceiling INCONCLUSIVE — could not read the stablecoin balance"
      elif [[ "$U0" == "$U1" ]]; then
        pass "C17 funding a trial key is refused and the whole transfer comes back ($U0 unchanged)"
      else
        fail "C17 funding a trial key took $(( U0 - U1 )) and did not give it back — a refusal must keep nothing"
      fi
    fi
  fi
fi

# ── C18: what an agent secret's authority actually is ────────────────────────
#
# Two properties that decide who controls a credential, and neither is visible
# from the contract alone.
#
# The signing key is `wallet:{wallet_id}:near`, derived inside the keystore and
# never rotated — an agent's account IS that key, so rotating it would rename
# the agent and orphan every secret it owns. What CAN be rotated is the `wk_`
# that authorises asking the keystore to sign.
#
# Written against OVERWRITE rather than delete: it asks the same question — can
# this credential still act on this secret — and needs nothing that is not
# already deployed. The delete path is the same authority with a different verb.
if want C18 && agent_secret_mode C18; then
  if [[ "$APPLY" != true ]]; then
    printf '\033[90m  (dry-run) a rotated wk_ still writes; the wk_ is the authority, not the payer\033[0m\n' >&2
  elif [[ -z "$AGENT_WALLET_KEY" || -z "$CALLER" ]]; then
    note "C18 SKIPPED — needs AGENT_WALLET_KEY (a wallet's wk_) and CALLER"
  else
    log "C18 rotation, and where the authority sits"

    C18_PROJECT="${ORDINARY_PROJECT:-$PROJECT}"

    # Which agent this wk_ speaks for on this project.
    agent_of() { # agent_of <wk_> <project>
      curl -s "$COORDINATOR_URL/wallet/v1/agent-secret/pubkey?project_id=$2" \
        -H "Authorization: Bearer $1" | jq -r '.agent_account // empty'
    }

    # The ciphertext currently stored for <agent> under <project>, off the chain.
    # This is what makes an overwrite OBSERVABLE — the plaintext never leaves the
    # agent, so the bytes changing is the only evidence there is.
    stored_ciphertext() { # stored_ciphertext <agent> <project>
      view get_secrets "$(jq -nc --arg a "$1" --arg p "$2" \
        '{accessor:{Project:{project_id:$p}}, profile:$a, owner:$a}')" \
        | jq -r '.encrypted_secrets // empty' 2>/dev/null
    }

    # The same read, waited for.
    #
    # `view` asks at FINAL finality, which trails the block a transaction just
    # landed in by a couple of seconds. Reading straight after a write returns
    # nothing and looks exactly like a write that failed — which is how this
    # section spent two runs blaming rotation for a lag. <> is "different from
    # what was there before"; empty means "anything at all".
    ciphertext_after_write() { # ciphertext_after_write <agent> <project> [previous]
      local i got
      for i in $(seq 1 12); do
        got=$(stored_ciphertext "$1" "$2")
        if [[ -n "$got" && "$got" != "$3" ]]; then echo "$got"; return 0; fi
        sleep 2
      done
      echo "$got"
      [[ -n "$got" && "$got" != "$3" ]]
    }

    # Write a secret with the CLI, which owns the ECIES format. Encrypting in
    # this script would be a second implementation of it, and the one that
    # drifts.
    # Output KEPT in "$RUN_TMP"/c18_write. Discarded, a write that never happened
    # reads downstream as "the ciphertext did not change", and this section then
    # reports a rotation failure about code that was never reached — which is
    # exactly what it did on its first two runs.
    write_with_cli() { # write_with_cli <wk_> <project> <plaintext-json>
      OUTLAYER_NETWORK="$NETWORK" "$OUTLAYER_BIN" secrets set-for-agent "$3" \
        --project "$2" --api-key "$1" >"$RUN_TMP"/c18_write 2>&1
    }

    # Re-store a GIVEN ciphertext, prepared under <wk_> and paid by <payer>.
    #
    # Re-using bytes already on chain is what makes the payer choosable at all:
    # the CLI pays from whoever it is logged in as, and the second half of this
    # section is about somebody else paying. The bytes stay sealed to the same
    # agent+project seed, so it is the same secret either way.
    write_as_payer() { # write_as_payer <wk_> <payer> <project> <ciphertext>
      local prep args
      prep=$(curl -s -X POST "$COORDINATOR_URL/wallet/v1/agent-secret/prepare" \
               -H "Authorization: Bearer $1" -H 'Content-Type: application/json' \
               -d "$(jq -nc --arg p "$3" --arg c "$4" --arg pay "$2" \
                     '{project_id:$p, encrypted_secrets_base64:$c, payer:$pay}')")
      args=$(echo "$prep" | jq -c '.args // empty')
      [[ -z "$args" ]] && return 1
      near --quiet contract call-function as-transaction "$CONTRACT_ID" store_agent_secret \
        json-args "$args" prepaid-gas '100.0 Tgas' attached-deposit '0.1 NEAR' \
        sign-as "$2" network-config "$NETWORK" sign-with-keychain send >"$RUN_TMP"/c18_pay 2>&1
    }

    # ── 1. Rotating the wk_ must not strand the secret ──────────────────────
    #
    # Rotation means a SECOND key on the same seed, then revoking the first.
    # That is the only form it takes: `PUT /api-key` derives the wallet from the
    # seed, so registering a different seed makes a different wallet with a
    # different agent — not a new key for an existing one. Knowing the seed is
    # therefore what makes rotation possible at all, which is worth knowing
    # before the day somebody needs it.
    #
    # The section mints its OWN sub-wallet rather than rotating a fixture,
    # because an existing wallet's seed is not recoverable from its wk_ — and a
    # test that cannot arrange its own preconditions is a test that skips.
    ROT_SEED="c18rot$(openssl rand -hex 3)"
    WK_A="wk_$(openssl rand -hex 32)"; H_A=$(printf '%s' "$WK_A" | shasum -a 256 | cut -d' ' -f1)
    WK_B="wk_$(openssl rand -hex 32)"; H_B=$(printf '%s' "$WK_B" | shasum -a 256 | cut -d' ' -f1)

    mint_key() { # mint_key <parent_wk> <seed> <key_hash> → wallet_id
      curl -s -X PUT "$COORDINATOR_URL/wallet/v1/api-key" \
        -H "Authorization: Bearer $1" -H 'Content-Type: application/json' \
        -d "$(jq -nc --arg s "$2" --arg kh "$3" '{seed:$s, key_hash:$kh}')" \
        | jq -r '.wallet_id // empty'
    }

    WID_A=$(mint_key "$AGENT_WALLET_KEY" "$ROT_SEED" "$H_A")
    WID_B=$(mint_key "$AGENT_WALLET_KEY" "$ROT_SEED" "$H_B")

    if [[ -z "$WID_A" || "$WID_A" != "$WID_B" ]]; then
      note "C18 rotation INCONCLUSIVE — two keys on one seed did not land on one wallet ('$WID_A' vs '$WID_B')"
    else
      pass "C18 two keys on one seed are two credentials for ONE wallet ($WID_A)"

      AGENT=$(agent_of "$WK_A" "$C18_PROJECT")
      write_with_cli "$WK_A" "$C18_PROJECT" '{"C18":"before-rotation"}'
      CT_BEFORE=$(ciphertext_after_write "$AGENT" "$C18_PROJECT" "")

      if [[ -z "$AGENT" || -z "$CT_BEFORE" ]]; then
        note "C18 rotation INCONCLUSIVE — nothing landed for agent '''$AGENT''': $(tail -c 200 "$RUN_TMP"/c18_write)"
      else
        pass "C18 a secret is on chain under the fresh agent ($AGENT)"

        RV=$(curl -s -o "$RUN_TMP"/c18_rv -w '%{http_code}' -X DELETE \
               "$COORDINATOR_URL/wallet/v1/api-key/$H_A" -H "Authorization: Bearer $WK_B")
        # The answer is READ, not discarded. A revoke that quietly refuses —
        # "cannot revoke the last active key" is a real answer here — would
        # leave everything below measuring the key that was supposed to be gone.
        if [[ "$RV" != 2?? ]]; then
          fail "C18 the revoke was refused ($RV): $(head -c 140 "$RUN_TMP"/c18_rv)"
        else
          OLD_RC=$(curl -s -o /dev/null -w '%{http_code}' \
                     "$COORDINATOR_URL/wallet/v1/address?chain=near" -H "Authorization: Bearer $WK_A")
          [[ "$OLD_RC" == 401 ]] \
            && pass "C18 the rotated-out wk_ is refused (401)" \
            || fail "C18 the old wk_ still answers $OLD_RC — nothing was rotated, so what follows proves nothing"

          write_with_cli "$WK_B" "$C18_PROJECT" '{"C18":"after-rotation"}'
          CT_AFTER=$(ciphertext_after_write "$AGENT" "$C18_PROJECT" "$CT_BEFORE")
          if [[ -n "$CT_AFTER" && "$CT_AFTER" != "$CT_BEFORE" ]]; then
            pass "C18 the NEW wk_ rewrote the same agent's secret — the wallet never moved, so the new credential speaks for it"
          else
            fail "C18 the rotated wk_ could not rewrite the secret — rotating an API key would freeze everything behind it"
          fi
        fi
      fi
    fi

    # ── 2. The boundary is the wk_, not the NEAR account ────────────────────
    #
    # A second NEAR account holding the SAME wk_ can write. That is by design —
    # the mechanism exists so somebody else can pay for an agent that has no
    # NEAR — and pinning it says where the security boundary actually is:
    # possession of the wk_, not ownership of an account.
    if [[ -z "$SECOND_CALLER" ]]; then
      note "C18 the second-payer half SKIPPED — set SECOND_CALLER to another funded NEAR account"
    else
      WK2="${WK_B:-$AGENT_WALLET_KEY}"
      AGENT2=$(agent_of "$WK2" "$C18_PROJECT")
      # Take a copy, change the secret, then have the OTHER account put the copy
      # back. The chain holding the earlier bytes again is unambiguous evidence
      # that the second payer's write landed.
      CT_COPY=$(stored_ciphertext "$AGENT2" "$C18_PROJECT")
      write_with_cli "$WK2" "$C18_PROJECT" '{"C18":"changed-by-the-first-payer"}'
      CT_MID=$(ciphertext_after_write "$AGENT2" "$C18_PROJECT" "$CT_COPY")

      if [[ -z "$CT_COPY" || -z "$CT_MID" || "$CT_COPY" == "$CT_MID" ]]; then
        note "C18 the second-payer half INCONCLUSIVE — could not arrange two distinct ciphertexts"
      elif ! write_as_payer "$WK2" "$SECOND_CALLER" "$C18_PROJECT" "$CT_COPY"; then
        # A contract that does not have the method yet is not a product failure.
        # This half sends the call itself, so it is the first thing here to meet
        # the renamed method — the CLI half above goes through the coordinator,
        # which still names whatever is deployed.
        if grep -q "MethodNotFound" "$RUN_TMP"/c18_pay; then
          note "C18 the second-payer half SKIPPED — the chain has no store_agent_secret yet; deploy the contract and re-run"
        else
          fail "C18 a second payer holding the same wk_ could not write: $(tail -c 220 "$RUN_TMP"/c18_pay)"
        fi
      else
        CT_END=$(ciphertext_after_write "$AGENT2" "$C18_PROJECT" "$CT_MID")
        [[ "$CT_END" == "$CT_COPY" ]] \
          && pass "C18 a DIFFERENT payer with the same wk_ wrote the secret ($SECOND_CALLER paid, $AGENT2 owns)" \
          || fail "C18 the second payer's write did not land — chain still holds the other ciphertext"
      fi
    fi
  fi
fi

# ── C19: the two things an agent secret gained — a WASM scope, and a way out ──
#
# Both are new wire, in four places at once: the CLI names a scope, the
# coordinator forwards it, the keystore seals and signs under it, and the
# contract files it. A test that only read the chain could not tell which of
# them dropped it, so this drives the CLI — the same path a person uses — and
# reads the chain for the result.
#
# The WASM scope is deliberately a hash of NOTHING. The contract does not check
# that a hash names a real build, and it should not: a secret may be stored for
# a version that has not been published yet. Using a made-up one is therefore
# the honest test of the accessor rather than a shortcut around publishing.
if want C19 && agent_secret_mode C19; then
  if [[ "$APPLY" != true ]]; then
    printf '\033[90m  (dry-run) a wasm-scoped secret is stored and read back; a delete removes it\033[0m\n' >&2
  elif [[ -z "$AGENT_WALLET_KEY" ]]; then
    note "C19 SKIPPED — needs AGENT_WALLET_KEY (a wallet's wk_)"
  else
    log "C19 a WASM-scoped secret, and deleting one"

    C19_PROJECT="${ORDINARY_PROJECT:-$PROJECT}"
    # A hash of this run, so a re-run is a fresh secret rather than a rewrite of
    # the last one — the delete below must remove something it can see arrive.
    C19_HASH=$(printf 'c19-%s' "$(openssl rand -hex 8)" | shasum -a 256 | cut -d' ' -f1)

    # The agent this wk_ speaks for. Asked for under the WASM scope, because
    # that is the request whose answer everything below depends on: a
    # coordinator that does not know the scope answers with an error here rather
    # than sealing a secret nobody can read.
    #
    # ONE call, read twice. Two calls would be two answers, and a section that
    # asserts a seed from one request against an agent from another is asserting
    # nothing when they disagree.
    #
    # A deployment that predates the scope answers this in PLAIN TEXT
    # ("missing field `project_id`", 400), so the reads tolerate a body that is
    # not JSON at all — jq's complaint would otherwise be printed as if the test
    # itself had gone wrong.
    C19_PUBKEY=$(curl -s "$COORDINATOR_URL/wallet/v1/agent-secret/pubkey?wasm_hash=$C19_HASH" \
                   -H "Authorization: Bearer $AGENT_WALLET_KEY")
    C19_AGENT=$(echo "$C19_PUBKEY" | jq -r '.agent_account // empty' 2>/dev/null)
    C19_SEED=$(echo "$C19_PUBKEY" | jq -r '.seed // empty' 2>/dev/null)

    if [[ -z "$C19_AGENT" ]]; then
      note "C19 SKIPPED — the coordinator does not answer the pubkey endpoint for a wasm_hash yet; deploy it and re-run"
    else
      # The seed decides what can ever open this secret, and it is the one thing
      # a mistake here would not show until read time, months later.
      [[ "$C19_SEED" == "wasm_hash:$C19_HASH:$C19_AGENT" ]] \
        && pass "C19 a wasm scope seals to wasm_hash:{hash}:{agent} — the seed the worker rebuilds" \
        || fail "C19 the wasm scope sealed to '$C19_SEED', which is not what the read path rebuilds"

      OUTLAYER_NETWORK="$NETWORK" "$OUTLAYER_BIN" secrets set-for-agent '{"C19":"wasm-scoped"}' \
        --wasm-hash "$C19_HASH" --api-key "$AGENT_WALLET_KEY" >"$RUN_TMP"/c19_store 2>&1
      # Output KEPT: a store that never happened reads downstream as "the chain
      # holds nothing", and this section would then report a contract problem
      # about code it never reached.
      C19_STORED=""
      for _ in $(seq 1 12); do
        C19_STORED=$(view get_secrets "$(jq -nc --arg h "$C19_HASH" --arg a "$C19_AGENT" \
          '{accessor:{WasmHash:{hash:$h}}, profile:$a, owner:$a}')" \
          | jq -r '.encrypted_secrets // empty' 2>/dev/null)
        [[ -n "$C19_STORED" ]] && break
        sleep 2
      done

      if [[ -z "$C19_STORED" ]]; then
        fail "C19 nothing landed under the wasm accessor: $(tail -c 220 "$RUN_TMP"/c19_store)"
      else
        pass "C19 a wasm-scoped secret is on chain under WasmHash($(printf '%.8s' "$C19_HASH")…)"

        # And the SAME agent under a project is a different secret entirely —
        # otherwise the scope would be a label rather than a boundary.
        C19_CROSS=$(view get_secrets "$(jq -nc --arg p "$C19_PROJECT" --arg a "$C19_AGENT" \
          '{accessor:{Project:{project_id:$p}}, profile:$a, owner:$a}')" \
          | jq -r '.encrypted_secrets // empty' 2>/dev/null)
        [[ "$C19_CROSS" != "$C19_STORED" ]] \
          && pass "C19 the same agent's project secret is a DIFFERENT secret — the scope is a boundary" \
          || fail "C19 the wasm scope and the project scope name one secret — one of them is being ignored"

        # ── The way out ────────────────────────────────────────────────────
        # `--yes` because a script has no keyboard: without it the command waits
        # on a confirmation prompt that nothing will ever answer.
        OUTLAYER_NETWORK="$NETWORK" "$OUTLAYER_BIN" secrets delete-for-agent --yes \
          --wasm-hash "$C19_HASH" --api-key "$AGENT_WALLET_KEY" >"$RUN_TMP"/c19_del 2>&1
        C19_RC=$?

        if [[ $C19_RC -ne 0 ]] && grep -qiE "unrecognized subcommand|404|not found" "$RUN_TMP"/c19_del; then
          note "C19 the delete SKIPPED — this build has no delete route yet: $(tail -c 160 "$RUN_TMP"/c19_del)"
        elif [[ $C19_RC -ne 0 ]]; then
          fail "C19 the delete was refused: $(tail -c 220 "$RUN_TMP"/c19_del)"
        else
          C19_LEFT="$C19_STORED"
          for _ in $(seq 1 12); do
            C19_LEFT=$(view get_secrets "$(jq -nc --arg h "$C19_HASH" --arg a "$C19_AGENT" \
              '{accessor:{WasmHash:{hash:$h}}, profile:$a, owner:$a}')" \
              | jq -r '.encrypted_secrets // empty' 2>/dev/null)
            [[ -z "$C19_LEFT" ]] && break
            sleep 2
          done
          [[ -z "$C19_LEFT" ]] \
            && pass "C19 the secret is gone from the chain — an owner can take a credential back" \
            || fail "C19 the delete reported success and the chain still holds the ciphertext"
        fi
      fi
    fi
  fi
fi

# ── C7: a trial is ten calls, and paying has no call limit ──────────────────
# The whole of the count-based metering on a connector. A fresh wallet claims
# its trial, makes every call the answer promised, and is refused on the next
# one — for good (`terminal: true`), in calls and never in dollars. A funded key
# is then called MORE times than a trial allows and none of those is refused:
# a caller who pays is bounded by money and by nothing else.
#
# Mints its own wallet, so it spends nothing of the fixtures' and can run in any
# order. It does claim a trial.
if want C7; then
  if [[ "$APPLY" != true ]]; then
    printf '\033[90m  (dry-run) mint a wallet, claim its trial, call ping to the limit and once more; then pass the limit on a funded key\033[0m\n' >&2
  else
    log "C7 a trial is ten calls; a funded key has no call limit"
    REG=$(curl -sS --max-time 60 -X POST "$COORDINATOR_URL/register" -H 'Content-Type: application/json' -d '{}')
    T_WK=$(jq -r '.api_key // empty' <<<"$REG")
    OFFER=$(jq -c '.trial // {}' <<<"$REG")
    if ! jq -e '(.calls | type == "number" and . > 0) and (.days | type == "number" and . > 0)' <<<"$OFFER" >/dev/null; then
      fail "C7 /register does not offer a trial in calls and days: $OFFER"
    elif jq -e 'has("allowance_usd") or has("claim_within_days")' <<<"$OFFER" >/dev/null; then
      fail "C7 /register describes the trial in dollars or with a claim window: $OFFER"
    else
      pass "C7 /register offers the trial in calls and days: $OFFER"
    fi
    CLAIM=$(curl -sS --max-time 60 -X POST "$COORDINATOR_URL/trial-key" -H "Authorization: Bearer $T_WK")
    T_KEY=$(jq -r '.payment_key // empty' <<<"$CLAIM")
    T_CALLS=$(jq -r '.calls // empty' <<<"$CLAIM")
    C7_WHY=$(jq -r '.reason // empty' <<<"$CLAIM" 2>/dev/null)
    if [[ -z "$T_KEY" && ( "$C7_WHY" == "trial_unavailable" || "$C7_WHY" == "trial_disabled" ) ]]; then
      skip "C7 no trial is on offer ($C7_WHY)"
    elif [[ -z "$T_KEY" ]]; then
      fail "C7 a fresh wallet could not claim its trial: $(jq -c 'del(.payment_key)' <<<"$CLAIM" 2>/dev/null | head -c 200)"
    elif [[ -z "$T_CALLS" ]] || jq -e 'has("allowance_usd")' <<<"$CLAIM" >/dev/null; then
      fail "C7 the claim must answer with \`calls\` and no dollar figure: $(jq -c 'del(.payment_key)' <<<"$CLAIM")"
    else
      ran=0
      for _ in $(seq 1 "$T_CALLS"); do
        R=$(curl -s -X POST "$COORDINATOR_URL/call/$PROJECT" -H "X-Payment-Key: $T_KEY" \
              -H 'Content-Type: application/json' -d '{"input":{"operation":"ping"}}')
        [[ "$(jq -r '.status // empty' <<<"$R")" == "completed" ]] && ran=$((ran + 1))
      done
      [[ "$ran" -eq "$T_CALLS" ]] && pass "C7 all $T_CALLS trial calls ran" \
        || fail "C7 only $ran of the trial's $T_CALLS calls ran"

      C7_BODY="$RUN_TMP/c7_over"
      CODE=$(curl -s -o "$C7_BODY" -w '%{http_code}' -X POST "$COORDINATOR_URL/call/$PROJECT" -H "X-Payment-Key: $T_KEY" \
               -H 'Content-Type: application/json' -d '{"input":{"operation":"ping"}}')
      OVER=$(cat "$C7_BODY")
      if [[ "$CODE" == "402" && "$(jq -r '.reason' <<<"$OVER")" == "trial_exhausted" && "$(jq -r '.terminal' <<<"$OVER")" == "true" \
            && "$(jq -r '.used' <<<"$OVER")" == "$T_CALLS" && "$(jq -r '.limit' <<<"$OVER")" == "$T_CALLS" ]]; then
        pass "C7 the next call is 402 trial_exhausted, terminal, $T_CALLS of $T_CALLS: $(jq -r '.error' <<<"$OVER" | head -c 110)"
      else
        fail "C7 call $((T_CALLS + 1)) should be 402 trial_exhausted/terminal/used=limit=$T_CALLS, got HTTP $CODE: $(head -c 200 <<<"$OVER")"
      fi
      # A refused attempt is not a call: asking again must not move `used` past the limit.
      AGAIN=$(curl -s -X POST "$COORDINATOR_URL/call/$PROJECT" -H "X-Payment-Key: $T_KEY" \
                -H 'Content-Type: application/json' -d '{"input":{"operation":"ping"}}')
      [[ "$(jq -r '.used' <<<"$AGAIN")" == "$T_CALLS" ]] && pass "C7 a refused attempt does not count: still $T_CALLS of $T_CALLS" \
        || fail "C7 a refusal moved the count: $(jq -c '{used,limit}' <<<"$AGAIN")"

      ST=$(curl -s "$COORDINATOR_URL/subscription/status" -H "X-Payment-Key: $T_KEY")
      if [[ "$(jq -r '.trial.calls_left' <<<"$ST")" == "0" ]] && ! jq -e 'has("allowance_total_usd") or has("allowance_available_usd")' <<<"$ST" >/dev/null; then
        pass "C7 /subscription/status reports the trial in calls (calls_left 0) and shows no allowance figures"
      else
        fail "C7 status should carry trial.calls_left=0 and no allowance_* for a trial key: $(jq -c '{trial, allowance_total_usd, allowance_available_usd}' <<<"$ST")"
      fi

      # The funded half judges a key with MONEY. A nonce-0 key is a trial, and
      # running it here would report a trial's own limit as a paying caller's.
      if [[ -n "$AGENT_PAYMENT_KEY" && "$(cut -d: -f2 <<<"$AGENT_PAYMENT_KEY")" == "0" ]]; then
        note "C7 the funded-key half SKIPPED: AGENT_PAYMENT_KEY is a trial key (nonce 0) — set a funded one"
      elif [[ -n "$AGENT_PAYMENT_KEY" ]]; then
        refused=0
        for _ in $(seq 1 $((T_CALLS + 2))); do
          R=$(curl -s -X POST "$COORDINATOR_URL/call/$PROJECT" -H "X-Payment-Key: $AGENT_PAYMENT_KEY" \
                -H 'Content-Type: application/json' -d '{"input":{"operation":"ping"}}')
          [[ "$(jq -r '.status // empty' <<<"$R")" == "completed" ]] || refused=$((refused + 1))
        done
        [[ "$refused" -eq 0 ]] && pass "C7 a funded key made $((T_CALLS + 2)) calls in a row — past a trial's count — and none was refused" \
          || fail "C7 a funded key was refused $refused of $((T_CALLS + 2)) calls: $(head -c 200 <<<"$R")"
      else
        note "C7 the funded-key half SKIPPED: needs AGENT_PAYMENT_KEY"
      fi
    fi
  fi
fi


echo
log "SUMMARY"
if [[ "$APPLY" != true ]]; then
  warn "Dry-run: nothing was spent. Pass --apply to run it."
  warn "C1 and C2 spend the operations' prices out of CALLER's in-contract balance, plus 0.1 NEAR of compute deposit per call."
fi
pass "passed: $PASS"
[[ $SKIPPED -gt 0 ]] && warn "skipped: $SKIPPED"
if [[ $FAILED -gt 0 ]]; then
  for n in "${FAILED_NAMES[@]}"; do printf '\033[31m  ✗ %s\033[0m\n' "$n" >&2; done
  echo "FAILED: $FAILED" >&2
  exit 1
fi
