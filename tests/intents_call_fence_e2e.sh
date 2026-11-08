#!/usr/bin/env bash
# The fence on calls to the NEAR Intents contract, live on testnet.
#
# intents.near takes a transaction from an account as the owner of that
# account's intents balance (auth by predecessor): a call from a wallet we sign
# for could `add_public_key` a key that signs for it outside the TEE, or move any
# balance past every limit. So a call whose receiver is the intents contract is
# refused unless the policy sets `capabilities.intents_call.allowed` — with no
# policy too — and so is an Agent Connect promise aimed at it, which would act
# as the BOUND account. The refusal is the policy's, before anything is signed,
# so it is visible on testnet although intents.near exists on mainnet only.
#
#   C0 control: the same /call aimed at another contract is not refused by the
#      policy — so C1's refusal is the fence, not a door that refuses everything
#   C1 no policy: /call intents.near add_public_key → 403 naming intents_call
#   C2 no policy: /call intents.near ft_withdraw → 403 naming intents_call
#   C3 a policy permitting `call` and silent on intents_call → 403
#   C4 a policy opening intents_call → not refused by the policy
#   C5 a multisig policy permitting call → 403 at once, no approval filed: the
#      fence decides before the approval threshold would
#   N1 no policy: a NEP-413 signature for recipient intents.near → 403 (a signed
#      intent acts for the intents account as surely as a call does)
#   N2 a policy LISTING intents.near / intents.far as sign_message recipients →
#      still 403: the owner cannot open this one
#   N3 control: a recipient the policy lists → 200
#   E1 Agent Connect: a nested storage_deposit aimed at intents.near → 403
#      naming intents_call (a method the decoder knows, so only the fence stops it)
#   E2 the same nested storage_deposit aimed at a token contract → passes
#   S1 POST /wallet/v1/intents/storage-deposit → 503 (intents are mainnet-only)
#
# Not here: raw signing with the NEAR key (no public route builds it; crate and
# keystore unit tests), and a Trusted op's artifact (the coordinator builds it;
# a compromised coordinator is out of reach of a client test). Spends testnet
# NEAR: four policies (0.1 each) and one bound account (1.2 + 0.3, deleted at
# the end).
#
#   PARENT=outlayer-alice.testnet ./tests/intents_call_fence_e2e.sh --apply
set -uo pipefail
source "$(dirname "$0")/lib/hos_common.sh"
[[ "${1:-}" == "--apply" ]] || { sed -n 2,26p "$0"; exit 0; }
hos_require

# A well-formed key nobody holds: the call is refused before it is signed.
PUB="ed25519:$(python3 -I -c 'import os
a="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
n=int.from_bytes(os.urandom(32),"big");s=""
while n:n,r=divmod(n,58);s=a[r]+s
print(s)')"

call_intents() { # <seed> <method> <args-json> [receiver]
  api "$1" POST /wallet/v1/call "$(jq -nc --arg r "${4:-intents.near}" --arg m "$2" --argjson a "$3" \
    '{receiver_id:$r, method_name:$m, args:$a, deposit:"1", gas:"30000000000000"}')" >/dev/null
}
fenced() { # <desc> — refused 403 and the refusal names intents_call
  if [[ "$HTTP" == 403 ]] && grep -q "intents_call" <<<"$BODY"; then
    pass "$1 — 403 $(err_of): $(msg_of | head -c 110)"
  else
    fail "$1 — expected 403 naming intents_call, got HTTP $HTTP: $(msg_of)"
  fi
}

# ── C1, C2: no policy ────────────────────────────────────────────────────────
SEED_A="fence-a-$(date +%s)-$$"
read -r WID_A ADDR_A < <(wallet_address "$SEED_A")
[[ -n "${WID_A:-}" ]] || { echo "✗ could not derive a wallet" >&2; exit 1; }
note "wallet without a policy: ${ADDR_A:0:12}…"

log "C0 control: the same call shape aimed at another contract"
call_intents "$SEED_A" add_public_key "$(jq -nc --arg k "$PUB" '{public_key:$k}')" usdc.fakes.testnet
if grep -q "intents_call" <<<"$BODY" || [[ "$(err_of)" == policy_denied ]]; then
  fail "C0 a call to another contract was refused by the policy: HTTP $HTTP $(msg_of)"
else
  pass "C0 another contract is not fenced (then HTTP $HTTP $(err_of): $(msg_of | head -c 80))"
fi

log "C1 no policy: add_public_key on intents.near"
call_intents "$SEED_A" add_public_key "$(jq -nc --arg k "$PUB" '{public_key:$k}')"
fenced "C1 a wallet with no policy cannot add a key to its intents account"

log "C2 no policy: ft_withdraw on intents.near"
call_intents "$SEED_A" ft_withdraw '{"token":"wrap.near","receiver_id":"someone.near","amount":"1"}'
fenced "C2 a wallet with no policy cannot withdraw from intents through call"

# ── C3, C4: with a policy ────────────────────────────────────────────────────
SEED_B="fence-b-$(date +%s)-$$"
read -r WID_B _ < <(wallet_address "$SEED_B")
log "C3 a policy that permits call and says nothing of intents_call"
if store_policy "$SEED_B" "$WID_B" '{"rules":{"transaction_types":["call","transfer"]}}'; then
  call_intents "$SEED_B" add_public_key "$(jq -nc --arg k "$PUB" '{public_key:$k}')"
  fenced "C3 permitting call does not permit a call to intents.near"
else
  fail "C3 the policy could not be stored; the case is unjudged"
fi

log "C4 the owner opens intents_call"
if store_policy "$SEED_B" "$WID_B" '{"rules":{"transaction_types":["call","transfer"]},"capabilities":{"intents_call":{"allowed":true}}}'; then
  call_intents "$SEED_B" add_public_key "$(jq -nc --arg k "$PUB" '{public_key:$k}')"
  # Past the policy the call goes to signing: this wallet holds no NEAR and
  # intents.near has no account on testnet, so whatever answers is the chain's
  # or the account's — never the fence.
  if grep -q "intents_call" <<<"$BODY" || [[ "$(err_of)" == policy_denied ]]; then
    fail "C4 an owner who opened intents_call is still refused by the policy: HTTP $HTTP $(msg_of)"
  else
    pass "C4 opened, the policy lets it through (then HTTP $HTTP $(err_of): $(msg_of | head -c 90))"
  fi
else
  fail "C4 the policy could not be stored; the case is unjudged"
fi

log "C5 a multisig policy that permits call"
SEED_D="fence-d-$(date +%s)-$$"
read -r WID_D _ < <(wallet_address "$SEED_D")
if store_policy "$SEED_D" "$WID_D" "$(jq -nc '{rules:{transaction_types:["call","transfer"]}, approval:{threshold:{required:1}, approvers:[{id:"outlayer-carol.testnet"}]}}')"; then
  call_intents "$SEED_D" add_public_key "$(jq -nc --arg k "$PUB" '{public_key:$k}')"
  if [[ "$(jq -r '.status // ""' <<<"$BODY")" == pending_approval ]]; then
    fail "C5 the call was filed for approval — approvers would be asked to hand over the intents account"
  else
    fenced "C5 refused at once on a multisig wallet, no approval filed"
  fi
else
  fail "C5 the policy could not be stored; the case is unjudged"
fi

# ── N1–N3: NEP-413 signatures for the intents verifiers ──────────────────────
sign_for() { api "$1" POST /wallet/v1/sign-message "$(jq -nc --arg r "$2" '{message:"fence e2e", recipient:$r}')" >/dev/null; }
refused_403() { # <desc>
  [[ "$HTTP" == 403 ]] && pass "$1 — 403 $(err_of): $(msg_of | head -c 100)" || fail "$1 — expected 403, got HTTP $HTTP: $(msg_of)"
}
log "N1 no policy: a NEP-413 signature for intents.near"
sign_for "$SEED_A" intents.near; refused_403 "N1 no NEP-413 signature for intents.near"
sign_for "$SEED_A" intents.far;  refused_403 "N1 no NEP-413 signature for intents.far"

log "N2 a policy that lists the intents verifiers as recipients"
SEED_C="fence-c-$(date +%s)-$$"
read -r WID_C _ < <(wallet_address "$SEED_C")
if store_policy "$SEED_C" "$WID_C" '{"rules":{},"capabilities":{"sign_message":{"allowed":true,"allowed_recipients":["intents.near","intents.far","fence-e2e.app"]}}}'; then
  sign_for "$SEED_C" intents.near; refused_403 "N2 listed or not, intents.near is never a sign_message recipient"
  sign_for "$SEED_C" fence-e2e.app
  [[ "$HTTP" == 200 ]] && pass "N3 control: a listed recipient is signed" || fail "N3 control: a listed recipient answered HTTP $HTTP: $(msg_of)"
else
  fail "N2 the policy could not be stored; the case is unjudged"
fi

# ── E1, E2: Agent Connect ────────────────────────────────────────────────────
log "E Agent Connect: a bound account of its own"
if new_bound_wallet fence; then
  CLEAN_ASSET="$ASSET"
  cleanup() {
    api "$SEED" DELETE /wallet/v1/binding >/dev/null 2>&1 || true
    account_exists "$CLEAN_ASSET" && { note "cleaning up $CLEAN_ASSET"; delete_account "$CLEAN_ASSET"; }
  }
  trap cleanup EXIT
  SD_ARGS=$(jq -nc --arg a "$ASSET" '{account_id:$a}')

  log "E1 a nested storage_deposit aimed at intents.near"
  call_ext "$SEED" "$ASSET" "$(ext_call intents.near storage_deposit "$SD_ARGS" 1250000000000000000000)" >/dev/null
  fenced "E1 a bound account's promise to intents.near is refused"

  log "E2 the same promise aimed at a token contract"
  call_ext "$SEED" "$ASSET" "$(ext_call usdc.fakes.testnet storage_deposit "$SD_ARGS" 1250000000000000000000)" >/dev/null
  if grep -q "intents_call" <<<"$BODY"; then
    fail "E2 a promise to a token contract was refused by the intents fence: $(msg_of)"
  elif [[ "$HTTP" == 200 ]]; then
    pass "E2 a promise to a token contract passes ($(jq -r '.status // ""' <<<"$BODY"))"
  else
    fail "E2 expected the control to pass, got HTTP $HTTP $(err_of): $(msg_of)"
  fi
else
  fail "E the bound wallet could not be built; E1 and E2 are unjudged"
fi

# ── S1 ───────────────────────────────────────────────────────────────────────
log "S1 the storage deposit from intents on testnet"
api "$SEED_A" POST /wallet/v1/intents/storage-deposit '{"token":"usdc.fakes.testnet"}' >/dev/null
[[ "$HTTP" == 503 ]] && pass "S1 503: $(msg_of | head -c 100)" || fail "S1 expected 503, got HTTP $HTTP: $(msg_of)"

verdict
