#!/usr/bin/env bash
#
# §6 of the HoS test plan — lifecycle and invalidation (acceptance R5) for the
# `personal_account` mode, live on chain.
#
# In this mode there is exactly one lifecycle event: the executor leaving the
# account's extension set. The partner's mode has more (lease, rotation,
# freeze), and those live behind the stub in §10 — but the machinery that
# CARRIES a fault into a refusal is the same one, and this suite proves it end
# to end against a real account whose control set really changes.
#
# It builds and destroys its OWN account and binding. The shared fixture is
# deliberately not used: removing an executor is TERMINAL, and a suite that
# ended the fixture would take every later run with it.
#
# What is pinned:
#   R5a  the lane works, so the refusals below are refusals of something
#   R5b  RemoveExtension(executor) → `executor_not_in_control_set`, terminal
#   R5c  the refusal arrives within the observation cache window (5 s), i.e.
#        a permission cached a moment ago does not outlive the fact
#   R5d  the binding ends up `revoked` and a later GET says so
#   R5e  a revoked binding cannot be nursed back — the owner must re-bind,
#        and re-binding the same account works
#   R5f  DELETE cancels what was pending
#   R5g  a wiped account is refused, not silently allowed
#   R5h  code redeployed over a bound account → `unrecognized_wallet_code`,
#        the one reachable fault class the matrix did not assert
#
#   PARENT=you.testnet ./tests/hos_lifecycle_e2e.sh --apply

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/hos_common.sh"

[[ "${1:-}" == "--apply" ]] || { sed -n '3,28p' "$0" >&2; echo "  Pass --apply to run." >&2; exit 0; }
hos_require

WL="${WL:-zavodil2.testnet}"
TINY="500000000000000000000"

SEED_L="hos-life-$(date +%s)-$$"
read -r WID_L EXEC_L < <(wallet_address "$SEED_L")
[[ -n "$WID_L" ]] || { echo "✗ could not mint the wallet" >&2; exit 1; }
ACC="hos-life-$(openssl rand -hex 3).$PARENT"
note "wallet $WID_L / executor $EXEC_L / account $ACC"

cleanup() {
  local rc=$?
  api "$SEED_L" DELETE /wallet/v1/binding >/dev/null 2>&1 || true
  account_exists "$ACC" && { note "cleaning up $ACC"; delete_account "$ACC"; }
  return $rc
}
trap cleanup EXIT

log "Building the account, the wallet contract and the binding"
create_subaccount "$ACC" 0.7 || { echo "✗ $ACC never appeared" >&2; exit 1; }
api "$SEED_L" PUT /wallet/v1/binding "$(jq -nc --arg a "$ACC" '{asset_account_id:$a, kind:"personal_account"}')" >/dev/null
[[ "$HTTP" == "200" ]] || { echo "✗ PUT failed $HTTP: $BODY" >&2; exit 1; }
install_wallet "$ACC" "$EXEC_L" || { echo "✗ the setup transaction did not land" >&2; exit 1; }
fund_account "$EXEC_L" 0.25 || warn "the executor was not funded; a refusal below may be about gas, not about the binding"
store_policy "$SEED_L" "$WID_L" "$(jq -nc --arg a "$ACC" --arg w "$WL" \
  '{rules:{addresses:{mode:"whitelist",list:[$a,$w]},limits:{per_transaction:{native:"1000000000000000000000000"}}}}')" \
  || { echo "✗ policy not stored" >&2; exit 1; }

STATUS=""
for _ in 1 2 3 4 5 6 7 8; do
  api "$SEED_L" GET /wallet/v1/binding >/dev/null
  STATUS=$(jq -r '.binding_status // ""' <<<"$BODY"); [[ "$STATUS" == "active" ]] && break; sleep 3
done
[[ "$STATUS" == "active" ]] && pass "R5a the binding is ACTIVE" || { fail "R5a never went active ('$STATUS')"; verdict "§6 lifecycle"; exit 1; }

log "R5a control — the lane spends before anything is broken"
call_ext "$SEED_L" "$ACC" "$(ext_transfer "$WL" "$TINY")" >/dev/null
assert_status "R5a the lane works" 200

# ── R5b/R5c the executor is cut from the control set ───────────────────────
log "R5b the owner signs RemoveExtension(executor) directly on the account"
REMOVE=$(jq -nc --arg e "$EXEC_L" '{request:{internal:[{op:"remove_extension",payload:{account_id:$e}}]}}')
CUT_LANDED=false
if extension_op "$ACC" "$REMOVE"; then
  pass "R5b the removal landed on chain"
  CUT_LANDED=true
else
  fail "R5b the removal transaction did not land — nothing below is judgeable"
fi

# Straight away: the cached ALLOW is at most five seconds old, so a call now is
# the interesting one. Waiting first would prove only that a cache expires.
CUT_AT=$(date +%s)
call_ext "$SEED_L" "$ACC" "$(ext_transfer "$WL" "$TINY")" >/dev/null
IMMEDIATE_HTTP=$HTTP; IMMEDIATE_CLASS=$(class_of)
IMMEDIATE_ERR=$(jq -r '.error // empty' <<<"$BODY" 2>/dev/null)
if [[ "$IMMEDIATE_HTTP" == "403" && "$IMMEDIATE_CLASS" == "executor_not_in_control_set" ]]; then
  pass "R5c refused $(( $(date +%s) - CUT_AT ))s after the cut, class '$IMMEDIATE_CLASS' — inside the 5 s window, so no cached permission outlived the fact"
elif [[ "$IMMEDIATE_HTTP" == "200" || "$IMMEDIATE_ERR" == "onchain_tx_failed" ]]; then
  # Two shapes, one cause: inside the window the gate still holds the cached
  # ALLOW. Either it admits the call, or it sends it to the chain — which
  # refuses it as a contract panic carrying no class and no terminal flag,
  # because `onchain_tx_failed` has neither. Both are the cache speaking, not a
  # verdict about the cut, so the row re-asks past the TTL and judges THAT.
  [[ "$IMMEDIATE_HTTP" == "200" ]] \
    && note "the call inside the cache window was still admitted — re-asking after the TTL" \
    || note "inside the cache window the call reached the CHAIN and was refused there, unclassified — re-asking after the TTL"
  sleep 7
  call_ext "$SEED_L" "$ACC" "$(ext_transfer "$WL" "$TINY")" >/dev/null
  assert_class "R5c refused once the 5 s observation cache expired" "executor_not_in_control_set"
  # Only when the executor really was cut AND the gate really did let the call
  # through: an unlanded removal, or a wallet skipped at its custody cap, would
  # otherwise file a report about a window nobody opened.
  [[ "$CUT_LANDED" == true && "$(class_of)" == "executor_not_in_control_set" ]] && finding "a cut executor is still let through the GATE for up to OBSERVATION_TTL_SECS (5 s) after RemoveExtension landed: the call is either admitted or sent to the chain, which refuses it as \`onchain_tx_failed\` with no class and no terminal flag — so inside that window a client cannot route on the answer. That is the documented cache, and the partner's R5 wording is 'immediately' — worth stating to them as a bounded 5 s window rather than letting them discover it."
else
  fail "R5c refused as HTTP $IMMEDIATE_HTTP class '${IMMEDIATE_CLASS:-none}', expected executor_not_in_control_set: $(msg_of)"
fi

log "R5b' the refusal is marked TERMINAL — an agent must stop, not retry"
if [[ "$(bool_of terminal)" == "true" ]]; then
  pass "R5b' terminal=true"
else
  fail "R5b' the answer is not marked terminal: $(head -c 200 <<<"$BODY")"
fi

# ── R5d the record follows the chain ───────────────────────────────────────
log "R5d GET /binding after the cut"
api "$SEED_L" GET /wallet/v1/binding >/dev/null
S1=$HTTP; ST=$(jq -r '.binding_status // ""' <<<"$BODY")
if [[ "$ST" == "revoked" ]]; then
  pass "R5d the record reports 'revoked' once, informatively, rather than a bare 404"
  api "$SEED_L" GET /wallet/v1/binding >/dev/null
  assert_status "R5d the NEXT read is a 404 — the binding is gone" 404
elif [[ "$S1" == "404" ]]; then
  pass "R5d the binding is gone (404)"
else
  fail "R5d status after the cut is '$ST' (HTTP $S1), expected revoked or 404"
fi

# ── R5e re-binding is the only way back ────────────────────────────────────
log "R5e the owner puts the executor back and re-binds"
READD=$(jq -nc --arg e "$EXEC_L" '{request:{internal:[{op:"add_extension",payload:{account_id:$e}}]}}')
if extension_op "$ACC" "$READD"; then
  api "$SEED_L" PUT /wallet/v1/binding "$(jq -nc --arg a "$ACC" '{asset_account_id:$a, kind:"personal_account"}')" >/dev/null
  if [[ "$HTTP" == "200" ]]; then
    ST2=""
    for _ in 1 2 3 4 5 6; do
      api "$SEED_L" GET /wallet/v1/binding >/dev/null
      ST2=$(jq -r '.binding_status // ""' <<<"$BODY"); [[ "$ST2" == "active" ]] && break; sleep 3
    done
    [[ "$ST2" == "active" ]] \
      && pass "R5e a NEW binding on the same account goes active — a terminal fault ends a lane, not an account" \
      || fail "R5e the new binding never went active ('$ST2')"
  else
    fail "R5e re-binding the same account was refused (HTTP $HTTP): $(msg_of)"
  fi
else
  fail "R5e the re-add transaction did not land"
fi

# ── R5f DELETE cancels what was pending ────────────────────────────────────
#
# The method list promises this in one line: "In-flight requests for the binding
# are cancelled or rejected rather than completing." It is the promise that
# makes revocation mean something. An approval raised while the lane was alive
# and approved after it was cut would execute against an account whose owner has
# already withdrawn the executor — the revocation would be a formality with a
# window in it.
#
# So the lane is given something to lose FIRST: a threshold policy turns the
# next spend into a held approval instead of a transfer, and the DELETE has to
# answer for it.
log "R5f a held approval, then DELETE"
HELD=""
POL_MS=$(jq -nc --arg a "$ACC" --arg w "$WL" --arg p "$PARENT" \
  '{rules:{addresses:{mode:"whitelist",list:[$a,$w]},limits:{per_transaction:{native:"1000000000000000000000000"}}},
    approval:{threshold:2, approvers:[{id:$p},{id:"second-approver.testnet"}]}}')
if store_policy "$SEED_L" "$WID_L" "$POL_MS"; then
  call_ext "$SEED_L" "$ACC" "$(ext_transfer "$WL" "$TINY")" >/dev/null
  HELD=$(jq -r '.approval_id // .request_id // ""' <<<"$BODY")
  if [[ -n "$HELD" && "$(jq -r '.status // ""' <<<"$BODY")" != "success" ]]; then
    pass "R5f a spend under a 2-of-N threshold is HELD ($HELD), so there is something in flight to cancel"
  else
    HELD=""
    note "R5f the threshold did not hold the spend (HTTP $HTTP, $(jq -r '.status // .error // "?"' <<<"$BODY")) — the cancellation below is judged on the DELETE's own count only"
  fi
else
  note "R5f the threshold policy could not be stored — nothing is in flight"
fi

log "R5f DELETE the binding, then try to spend"
api "$SEED_L" DELETE /wallet/v1/binding >/dev/null
assert_status "R5f DELETE" 200
# The DELETE must SAY what it cancelled. A revocation that silently leaves work
# behind is indistinguishable from one that cancelled nothing, and the owner has
# no way to tell which they got.
CANCELLED=$(jq -r '.cancelled_approvals // ""' <<<"$BODY")
if [[ -z "$CANCELLED" ]]; then
  fail "R5f the DELETE answer does not say what it cancelled — the owner cannot tell a clean revocation from one with work left behind"
elif [[ -n "$HELD" ]]; then
  [[ "$CANCELLED" -ge 1 ]] \
    && pass "R5f and it cancelled the $CANCELLED approval(s) that were in flight" \
    || fail "R5f a spend was held for approval and the DELETE cancelled $CANCELLED — an approver could still sign it against a revoked lane"
else
  pass "R5f and it reports its count ($CANCELLED), which is the field an owner reads"
fi
if [[ -n "$HELD" ]]; then
  api "$SEED_L" GET "/wallet/v1/requests/$HELD" >/dev/null
  HELD_ST=$(jq -r '.status // ""' <<<"$BODY")
  [[ "$HELD_ST" == "success" ]] \
    && fail "R5f the held request reached 'success' after the binding was deleted" \
    || pass "R5f and the held request did not complete (status '${HELD_ST:-gone}')"
fi
# Back to the plain policy: R5g asks whether a WIPED account is refused, and a
# spend held for approval would answer a different question.
store_policy "$SEED_L" "$WID_L" "$(jq -nc --arg a "$ACC" --arg w "$WL" \
  '{rules:{addresses:{mode:"whitelist",list:[$a,$w]},limits:{per_transaction:{native:"1000000000000000000000000"}}}}')" \
  || note "R5f the plain policy could not be restored — R5g may be judged under a threshold"

call_ext "$SEED_L" "$ACC" "$(ext_transfer "$WL" "$TINY")" >/dev/null
# With no binding the pre-flight has nothing of ours to enforce; the account's
# own contract still refuses a stranger. What must NOT happen is the call being
# admitted AND signed as though the binding were alive.
if [[ "$HTTP" == "200" && "$(jq -r '.status // ""' <<<"$BODY")" == "success" ]]; then
  fail "R5f a spend on the unbound account still succeeded — DELETE left the lane open"
else
  pass "R5f after DELETE the spend does not go through (HTTP $HTTP, $(jq -r '.status // .error // "?"' <<<"$BODY"))"
fi

# ── R5g a wiped account ────────────────────────────────────────────────────
log "R5g deleting the account from under a live binding"
api "$SEED_L" PUT /wallet/v1/binding "$(jq -nc --arg a "$ACC" '{asset_account_id:$a, kind:"personal_account"}')" >/dev/null
for _ in 1 2 3 4 5 6; do
  api "$SEED_L" GET /wallet/v1/binding >/dev/null
  [[ "$(jq -r '.binding_status // ""' <<<"$BODY")" == "active" ]] && break; sleep 3
done
delete_account "$ACC"
sleep 8
call_ext "$SEED_L" "$ACC" "$(ext_transfer "$WL" "$TINY")" >/dev/null
# The CLASS, not just a 4xx. This used to assert `^4` and then announce "the
# code hash is no longer one we recognize" — a cause it never read. A wallet out
# of money, a policy that stopped matching, a scope, are all 4xx too, and each
# would have passed this probe while the deleted account went unnoticed.
#
# Two classes are defensible here and the difference is real, so the probe names
# which one it got rather than flattening them: an account that no longer exists
# has no code hash to recognise (`unrecognized_wallet_code`), and reading a
# deleted account can equally come back as no reading at all
# (`chain_status_unreadable`). Anything else means the refusal came from
# somewhere other than the binding check.
if [[ ! "$HTTP" =~ ^4 ]]; then
  fail "R5g a spend against a deleted account answered $HTTP: $(msg_of)"
elif [[ "$(class_of)" == "unrecognized_wallet_code" || "$(class_of)" == "chain_status_unreadable" ]]; then
  pass "R5g a wiped account is refused by the BINDING check ($HTTP $(err_of)/$(class_of))"
else
  fail "R5g the wiped account was refused $HTTP as '$(err_of)/$(class_of)' — a 4xx, but not from the binding check, so this probe says nothing about a deleted account: $(msg_of | head -c 160)"
fi

# ── R5h the account's code changed under a live binding ────────────────────
#
# The one fault class the whole HoS matrix left unasserted:
# `unrecognized_wallet_code`. Of the three that had none, the other two cannot
# be reached from here at all — `account_expired` has no variant in any contract
# this build knows, and `binding_evidence_mismatch` needs a plumbing bug — so
# they are unit-vector territory. This one is reachable, and it is the shape a
# real owner reaches: the account is bound, the owner redeploys something else
# onto it, and every later spend has to stop.
#
# Its OWN wallet and account rather than a hand-off from the probes above: that
# account is walked through cut, re-bind and delete in a fixed order, and
# deploying foreign code into the middle of it would decide which rule the later
# refusals came from.
log "R5h a foreign contract deployed over a bound account"
STUB_WASM="$REPO_ROOT/tests/hos-status-stub/target/near/hos_status_stub.wasm"
if [[ ! -f "$STUB_WASM" ]]; then
  skip "R5h — no artifact to deploy: build it with (cd tests/hos-status-stub && cargo near build non-reproducible-wasm)"
elif ! new_bound_wallet codehash; then
  skip "R5h — the fresh bound wallet could not be built, so a refusal below would not be judgeable"
else
  # The pinned wallet is installed BY GLOBAL HASH, so `global_contract_hash` is
  # what the verifier reads. Deploying a local wasm replaces it with an ordinary
  # `code_hash` — which is exactly what a redeploy does to a real account.
  # WITHOUT the init call: the stub's `new` is `#[init]`, and an init on an
  # account that already carries the wallet's state panics and reverts the whole
  # transaction — deploy included. Nothing here needs the stub to work; only its
  # code hash matters, and that is what the verifier reads.
  if near_tty "near contract deploy $ASSET use-file $STUB_WASM \
      without-init-call network-config $NETWORK sign-with-keychain send" >/dev/null 2>&1; then
    pass "R5h the foreign contract is on $ASSET"
  else
    fail "R5h the deploy did not land — nothing below judges the code-hash rule"
  fi
  sleep 6
  call_ext "$SEED" "$ASSET" "$(ext_transfer "$WL" "$TINY")" >/dev/null
  # THREE outcomes, not two. Written as "refused == 4xx" this reported a 503 —
  # the answer the coordinator actually gave — as "the spend went through",
  # which is the opposite of what happened and the same class of mistake the
  # probe exists to catch.
  if [[ "$HTTP" == 2?? ]]; then
    fail "R5h a spend went through an account running code we do not recognize (HTTP $HTTP): $(msg_of)"
  elif [[ "$(class_of)" == "unrecognized_wallet_code" ]]; then
    pass "R5h refused as unrecognized_wallet_code — the code hash is read on every spend, not once at binding time"
  elif [[ "$HTTP" == 503 ]]; then
    fail "R5h refused 503 '$(msg_of | head -c 90)' — a TRANSIENT answer to a permanent state. The account runs foreign code and will until its owner redeploys; being told to retry never becomes true. The engine has unrecognized_wallet_code for exactly this and the caller never sees it"
  else
    fail "R5h refused $HTTP as '$(err_of)/$(class_of)', not unrecognized_wallet_code. The account runs a contract the allowlist does not name, and that is the rule that must speak: $(msg_of | head -c 160)"
  fi
  account_exists "$ASSET" && { note "cleaning up $ASSET"; delete_account "$ASSET"; }
fi

verdict "§6 lifecycle"
