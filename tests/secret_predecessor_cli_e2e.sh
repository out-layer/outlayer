#!/usr/bin/env bash
#
# `outlayer secrets set/access --direct --via --drop-callers`, live: what the
# CLI actually STORES on chain for a calling-account rule.
#
# The rule itself is judged by the keystore and covered by
# `secret_predecessor_e2e.sh`. This suite is about the other half — the
# command an owner types — and every row reads the condition back from the
# CONTRACT rather than trusting the CLI's own print, which would only prove
# the CLI agrees with itself.
#
#   F1  `set --direct` stores exactly `And[Whitelist[owner], Predecessor{Whitelist[owner]}]`
#   F2  `access --direct --via <dao>` names the readers and the DAO in one rule
#   F3  `--access` alone is REFUSED while such a rule stands — replacing the
#       condition would drop it, and the refusal names the way past
#   F4  `--access … --direct` follows the new readers AND keeps the via
#       contract the row already named. The live case that caught the bug:
#       the new condition is built from `--access` and carries no rule, so the
#       contracts can only come from the stored row
#   F5  a rule under an OR is the owner's own composition: refused, not
#       rewritten, and the row on chain is untouched
#   F6  `--drop-callers` removes the rule it owns and leaves the readers; a
#       second one is refused rather than sending a no-op transaction
#   F7  `secrets list` shows the rule as `from:<accounts>`
#
# Needs: PARENT (owns the row and signs; the outlayer CLI's credentials must
# be this account) and its project $PARENT/test-secrets, published. No payment
# key: every row here is a contract call, not a run.
#
# Money: six `update_access`/`store_secrets` transactions on one row, deleted
# at the end.
#
# Run:
#   PARENT=you.testnet ./tests/secret_predecessor_cli_e2e.sh --apply

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."
source tests/lib/hos_common.sh
PARENT="${PARENT:-}"
PROJECT="${SECRETS_PROJECT:-${PARENT:-}/test-secrets}"
PROFILE="${PROFILE:-cliflags}"
VIA_CONTRACT="${VIA_CONTRACT:-dao.sputnik-dao.testnet}"
DEPOSIT='0.1 NEAR'

[[ "${1:-}" == "--apply" ]] || { sed -n '3,34p' "$0" >&2; echo "  Pass --apply to run." >&2; exit 0; }
[[ -n "$PARENT" ]] || { echo "✗ set PARENT" >&2; exit 1; }
hos_require
source tests/lib/secrets_common.sh
[[ -x "$OUTLAYER_BIN_PATH" ]] || { echo "✗ the outlayer CLI was not found (OUTLAYER_BIN=$OUTLAYER_BIN)" >&2; exit 1; }
note "project: $PROJECT   profile: $PROFILE   via: $VIA_CONTRACT"

CLI="$OUTLAYER_BIN_PATH"
run_cli() { OUTLAYER_NETWORK="$NETWORK" OUTLAYER_RPC_URL="$RPC_URL" "$CLI" "$@" 2>&1; }

# The stored condition, canonicalised so two spellings of the same tree compare
# equal (jq sorts object keys; arrays keep their order, which is meaning here).
stored() { row_of "$PROJECT" "$PROFILE" | jq -Sc '.access // "none"'; }
callers() { stored | jq -r '[.. | objects | select(has("Predecessor")) | .Predecessor.condition.Whitelist.accounts // empty] | flatten | join(",")'; }
readers() { stored | jq -r '[.. | objects | select(has("Whitelist")) | .Whitelist.accounts] | flatten | unique | join(",")'; }

log "F1 secrets set --direct writes one rule naming the row's readers"
BEFORE=$(jq -r '.updated_at // 0' <<<"$(row_of "$PROJECT" "$PROFILE")")
OUT=$(run_cli secrets set "$(jq -nc '{CLI_CANARY:"x"}')" --project "$PROJECT" --profile "$PROFILE" \
      --access "whitelist:$PARENT" --direct)
if ! wait_row_after "$PROJECT" "$PROFILE" "$BEFORE"; then
  fail "F1 the store never became final: $(tail -3 <<<"$OUT" | tr '\n' ' ' | head -c 240)"
else
  WANT=$(jq -nSc --arg p "$PARENT" '{Logic:{operator:"And",conditions:[{Whitelist:{accounts:[$p]}},{Predecessor:{condition:{Whitelist:{accounts:[$p]}}}}]}}')
  [[ "$(stored)" == "$WANT" ]] \
    && pass "F1 stored exactly And[Whitelist[owner], Predecessor{Whitelist[owner]}]" \
    || fail "F1 stored $(stored) — wanted $WANT"
fi

log "F2 secrets access --direct --via adds the contract beside the readers"
run_cli secrets access --project "$PROJECT" --profile "$PROFILE" --direct --via "$VIA_CONTRACT" >/dev/null
sleep 4
[[ "$(callers)" == "$PARENT,$VIA_CONTRACT" ]] \
  && pass "F2 the rule names the owner and the DAO" \
  || fail "F2 the rule names '$(callers)'"

log "F3 --access alone is refused while a calling-account rule stands"
OUT=$(run_cli secrets access --project "$PROJECT" --profile "$PROFILE" --access "whitelist:$PARENT,agent.testnet")
if grep -q "drop-callers" <<<"$OUT"; then
  pass "F3 refused, naming the way past it"
else
  fail "F3 not refused for the rule: $(tail -2 <<<"$OUT" | tr '\n' ' ' | head -c 200)"
fi

log "F4 --access with --direct follows the new readers AND keeps the via contract"
run_cli secrets access --project "$PROJECT" --profile "$PROFILE" --access "whitelist:$PARENT,agent.testnet" --direct >/dev/null
sleep 4
GOT=$(callers)
[[ "$GOT" == "$PARENT,agent.testnet,$VIA_CONTRACT" ]] \
  && pass "F4 the rule followed the grant and kept the DAO" \
  || fail "F4 the rule names '$GOT' — wanted owner,agent,dao"

log "F5 a rule under an OR is refused rather than rewritten"
# Put one there by hand, through the contract.
OR_TREE=$(jq -nc --arg p "$PARENT" --arg v "$VIA_CONTRACT" '{Logic:{operator:"Or",conditions:[{Whitelist:{accounts:[$p]}},{Predecessor:{condition:{Whitelist:{accounts:[$v]}}}}]}}')
set_access "$PROJECT" "$PROFILE" "$OR_TREE"
BEFORE_OR=$(stored)
OUT=$(run_cli secrets access --project "$PROJECT" --profile "$PROFILE" --direct)
if grep -q "cannot rewrite" <<<"$OUT" && [[ "$(stored)" == "$BEFORE_OR" ]]; then
  pass "F5 refused, and the row on chain is untouched"
else
  fail "F5 got '$(tail -2 <<<"$OUT" | tr '\n' ' ' | head -c 200)'; row now $(stored)"
fi

log "F6 --drop-callers removes the rule when it owns one, and refuses when it does not"
set_access "$PROJECT" "$PROFILE" "$(jq -nc --arg p "$PARENT" '{Logic:{operator:"And",conditions:[{Whitelist:{accounts:[$p]}},{Predecessor:{condition:{Whitelist:{accounts:[$p]}}}}]}}')"
run_cli secrets access --project "$PROJECT" --profile "$PROFILE" --drop-callers >/dev/null
sleep 4
if [[ -z "$(callers)" && "$(readers)" == "$PARENT" ]]; then
  pass "F6 the rule is gone and the readers are untouched"
else
  fail "F6 callers='$(callers)' readers='$(readers)'"
fi
OUT=$(run_cli secrets access --project "$PROJECT" --profile "$PROFILE" --drop-callers)
grep -q "no calling-account rule to drop" <<<"$OUT" \
  && pass "F6 a second --drop-callers is refused rather than sending a no-op transaction" \
  || fail "F6 the no-op was not refused: $(tail -2 <<<"$OUT" | tr '\n' ' ' | head -c 200)"

log "F7 the list shows the rule"
run_cli secrets access --project "$PROJECT" --profile "$PROFILE" --direct >/dev/null
sleep 4
LIST=$(run_cli secrets list)
grep -q "from:$PARENT" <<<"$LIST" \
  && pass "F7 secrets list prints the rule as from:<accounts>" \
  || fail "F7 the rule is not in the listing: $(grep -i "$PROFILE" <<<"$LIST" | head -c 200)"

log "cleanup"
delete_row "$PROJECT" "$PROFILE"
verdict "predecessor CLI flags"
