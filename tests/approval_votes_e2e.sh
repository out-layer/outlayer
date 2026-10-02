#!/usr/bin/env bash
#
# Multisig votes on testnet: who may cast one, and what counts.
#
#   V1  a vote signed with ANOTHER account's key in an approver's name is
#       refused (401 invalid_signature) and stores nothing
#   V2  the same for a reject
#   V3  a stranger's reject is refused (403 not_approver), nothing stored
#   V3a a stranger's approve is refused the same way
#   V4  the real approver then votes — accepted, not `already_approved`, and
#       the approval stays pending at 1 of 2
#   V5  that approver's second vote, a reject, is 409 already_approved (not 500)
#   V6  the second approver's vote crosses the threshold and the transfer runs
#   V7  a vote after the decision is 409 conflict naming the state (not 500)
#   V8  a reject from an unpinned approver, by key, cancels the request at once
#   V10 an approver added to the policy on chain just before voting is
#       accepted — a stale copy of the policy never turns a voter away
#   V9  a vote signed by a FUNCTION-CALL key of the approver itself is refused
#       (401): only a full-access key is the approver's word. The suite adds
#       that key to APPROVER and removes it on exit.
#
# Actors: PARENT owns the wallet and is the second approver; APPROVER is the
# first; STRANGER is in no policy. Each signs with its own key from
# ~/.near-credentials.
#
# Run:
#   PARENT=outlayer-alice.testnet APPROVER=outlayer-bob.testnet \
#     STRANGER=outlayer-carol.testnet ./tests/approval_votes_e2e.sh --apply

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/hos_common.sh"

[[ "${1:-}" == "--apply" ]] || { warn "Dry run. Pass --apply."; exit 0; }

APPROVER="${APPROVER:-outlayer-bob.testnet}"
STRANGER="${STRANGER:-outlayer-carol.testnet}"
hos_require

creds() { jq -r ".$2" "$HOME/.near-credentials/$NETWORK/$1.json"; }
for a in "$APPROVER" "$STRANGER"; do
  [[ -f "$HOME/.near-credentials/$NETWORK/$a.json" ]] || { echo "✗ creds missing for $a" >&2; exit 1; }
done

# vote <approve|reject> <named-account> <signing-account> — a NEP-413 vote in
# <named-account>'s name, signed with <signing-account>'s key.
vote() {
  local verb=$1 named=$2 signer=$3 msg nonce sig body
  msg="$verb:$AID:$WPK:$RHASH"
  nonce=$(head -c 32 /dev/urandom | base64 | tr -d '\n')
  sig=$(CUSTOMER_RECOVERY_PRIVATE_KEY="$(creds "$signer" private_key)" "$RECOVERY_BIN" sign-nep413 \
    --message "$msg" --recipient "$CONTRACT_ID" --nonce-base64 "$nonce" | jq -r '.signature')
  body=$(jq -nc --arg s "$sig" --arg pk "$(creds "$signer" public_key)" --arg a "$named" --arg n "$nonce" \
    '{signature:$s, public_key:$pk, account_id:$a, nonce:$n}')
  [[ "$verb" == reject ]] && body=$(jq -c '. + {reason:"e2e"}' <<<"$body")
  api - POST "/wallet/v1/$verb/$AID" "$body" >/dev/null
}

# vote_with <approve|reject> <named-account> <private-key> <public-key> — the
# same, signed with an explicit key.
vote_with() {
  local verb=$1 named=$2 sk=$3 pk=$4 msg nonce sig
  msg="$verb:$AID:$WPK:$RHASH"
  nonce=$(head -c 32 /dev/urandom | base64 | tr -d '\n')
  sig=$(CUSTOMER_RECOVERY_PRIVATE_KEY="$sk" "$RECOVERY_BIN" sign-nep413 \
    --message "$msg" --recipient "$CONTRACT_ID" --nonce-base64 "$nonce" | jq -r '.signature')
  api - POST "/wallet/v1/$verb/$AID" \
    "$(jq -nc --arg s "$sig" --arg pk "$pk" --arg a "$named" --arg n "$nonce" '{signature:$s, public_key:$pk, account_id:$a, nonce:$n}')" >/dev/null
}

# votes_by <account> — how many rows the approval holds for this account.
votes_by() {
  api - GET "/wallet/v1/approval/$AID" >/dev/null
  jq --arg a "$1" '[.approvers[]? | select(.approver_id == $a)] | length' <<<"$BODY"
}

# ── setup ───────────────────────────────────────────────────────────────────
SEED="votes-$(date +%s)-$$"
log "setup: wallet $SEED under $PARENT, 2-of-2 approvers $APPROVER + $PARENT"
read -r WALLET_ID ADDR < <(wallet_address "$SEED") || { echo "✗ no wallet" >&2; exit 1; }
fund_account "$ADDR" 0.02 || { echo "✗ could not fund $ADDR" >&2; exit 1; }
POLICY=$(jq -nc --arg a "$APPROVER" --arg p "$PARENT" \
  '{rules:{transaction_types:["transfer"]}, approval:{threshold:{required:2}, approvers:[{id:$a},{id:$p}]}}')
store_policy "$SEED" "$WALLET_ID" "$POLICY" || { echo "✗ policy not stored" >&2; exit 1; }

api "$SEED" POST /wallet/v1/transfer \
  "$(jq -nc --arg to "$PARENT" '{chain:"near", to:$to, amount:"1000000000000000000000"}')" >/dev/null
AID=$(jq -r '.approval_id // empty' <<<"$BODY")
RID=$(jq -r '.request_id // empty' <<<"$BODY")
[[ -n "$AID" ]] || { echo "✗ transfer was not held for approval: HTTP $HTTP $(msg_of)" >&2; exit 1; }
api - GET "/wallet/v1/approval/$AID" >/dev/null
RHASH=$(jq -r '.request_hash' <<<"$BODY"); WPK=$(jq -r '.wallet_pubkey' <<<"$BODY")
note "approval $AID held; request $RID"

# ── V1/V2: a key that is not the named account's ────────────────────────────
log "V1 approve in $APPROVER's name, signed with $STRANGER's key"
vote approve "$APPROVER" "$STRANGER"
assert_status "V1 refused" 401 && assert_msg "V1 names the key and the account" "not a key of $APPROVER"
[[ "$(votes_by "$APPROVER")" == 0 ]] && pass "V1 stored nothing in $APPROVER's name" \
  || fail "V1 a row in $APPROVER's name was stored"

log "V2 reject in $APPROVER's name, signed with $STRANGER's key"
vote reject "$APPROVER" "$STRANGER"
assert_status "V2 refused" 401
api - GET "/wallet/v1/approval/$AID" >/dev/null
[[ "$(jq -r .status <<<"$BODY")" == pending ]] && pass "V2 approval still pending" \
  || fail "V2 approval is $(jq -r .status <<<"$BODY")"

# ── V9: the approver's own function-call key ────────────────────────────────
log "V9 approve in $APPROVER's name, signed with a function-call key of $APPROVER"
FC=$(node "$HOS_LIB_DIR/ed25519_keypair.mjs"); FC_PK=$(jq -r .public_key <<<"$FC"); FC_SK=$(jq -r .private_key <<<"$FC")
drop_fc_key() {
  near --quiet account delete-keys "$APPROVER" public-keys "$FC_PK" network-config "$NETWORK" \
    sign-with-keychain send >/dev/null 2>&1 || warn "could not remove the function-call key $FC_PK from $APPROVER"
}
if near --quiet account add-key "$APPROVER" grant-function-call-access --allowance '0.01 NEAR' \
     --contract-account-id "$CONTRACT_ID" --function-names '' use-manually-provided-public-key "$FC_PK" \
     network-config "$NETWORK" sign-with-keychain send >/dev/null 2>&1; then
  trap drop_fc_key EXIT
  sleep 4
  vote_with approve "$APPROVER" "$FC_SK" "$FC_PK"
  assert_status "V9 refused" 401 && assert_msg "V9 says the key may only call functions" "may only call functions"
  [[ "$(votes_by "$APPROVER")" == 0 ]] && pass "V9 stored nothing" || fail "V9 a row was stored"
else
  fail "V9 could not add a function-call key to $APPROVER"
fi

# ── V3/V4: a stranger's reject does not count toward the threshold ──────────
log "V3 $STRANGER rejects in its own name (in no policy)"
vote reject "$STRANGER" "$STRANGER"
if assert_status "V3 refused" 403; then
  [[ "$(err_of)" == not_approver ]] && pass "V3 not_approver" || fail "V3 error $(err_of)"
fi
log "V3a $STRANGER approves in its own name"
vote approve "$STRANGER" "$STRANGER"
if assert_status "V3a refused" 403; then
  [[ "$(err_of)" == not_approver ]] && pass "V3a not_approver" || fail "V3a error $(err_of)"
fi
[[ "$(votes_by "$STRANGER")" == 0 ]] && pass "V3/V3a nothing stored for $STRANGER" || fail "V3/V3a a stranger's vote was stored"

log "V4 $APPROVER approves"
vote approve "$APPROVER" "$APPROVER"
assert_status "V4 accepted, not already_approved" 200
if [[ "$(jq -r .status <<<"$BODY")" == pending && "$(jq -r .approved <<<"$BODY")" == 1 ]]; then
  pass "V4 pending at 1 of 2 — the stranger's reject is not a yes"
else
  fail "V4 expected pending 1/2, got $(jq -c '{status,approved,required}' <<<"$BODY")"
fi

# ── V5: a second vote by the same account ───────────────────────────────────
log "V5 $APPROVER rejects after approving"
vote reject "$APPROVER" "$APPROVER"
if assert_status "V5 second vote" 409; then
  [[ "$(err_of)" == already_approved ]] && pass "V5 already_approved" || fail "V5 error $(err_of)"
fi

# ── V6: the second real approver crosses the threshold ──────────────────────
log "V6 $PARENT approves"
vote approve "$PARENT" "$PARENT"
assert_status "V6 accepted" 200
[[ "$(jq -r .status <<<"$BODY")" == approved ]] && pass "V6 threshold met" \
  || fail "V6 status $(jq -c '{status,approved,required}' <<<"$BODY")"
ST=""
for _ in $(seq 1 15); do
  sleep 3
  api "$SEED" GET "/wallet/v1/requests/$RID" >/dev/null
  ST=$(jq -r .status <<<"$BODY")
  [[ "$ST" == success || "$ST" == completed || "$ST" == failed ]] && break
done
[[ "$ST" == success || "$ST" == completed ]] && pass "V6 transfer executed ($ST)" \
  || fail "V6 request ended $ST: $(jq -c .result <<<"$BODY" | head -c 200)"

# ── V7: a vote after the decision ───────────────────────────────────────────
log "V7 $STRANGER votes on the decided approval"
vote approve "$STRANGER" "$STRANGER"
if assert_status "V7 late vote" 409; then
  [[ "$(err_of)" == conflict ]] && assert_msg "V7 names the state" "already approved" || fail "V7 error $(err_of)"
fi

# ── V8: an unpinned approver's key reject is decisive ───────────────────────
log "V8 a new held transfer, $APPROVER rejects by key"
api "$SEED" POST /wallet/v1/transfer \
  "$(jq -nc --arg to "$PARENT" '{chain:"near", to:$to, amount:"1000000000000000000000"}')" >/dev/null
AID=$(jq -r '.approval_id // empty' <<<"$BODY"); RID=$(jq -r '.request_id // empty' <<<"$BODY")
if [[ -z "$AID" ]]; then
  fail "V8 transfer was not held for approval: HTTP $HTTP $(msg_of)"
else
  api - GET "/wallet/v1/approval/$AID" >/dev/null
  RHASH=$(jq -r '.request_hash' <<<"$BODY"); WPK=$(jq -r '.wallet_pubkey' <<<"$BODY")
  vote reject "$APPROVER" "$APPROVER"
  assert_status "V8 reject accepted" 200
  [[ "$(jq -r .status <<<"$BODY")" == rejected ]] && pass "V8 the approval is rejected at once" \
    || fail "V8 status $(jq -r .status <<<"$BODY")"
  api "$SEED" GET "/wallet/v1/requests/$RID" >/dev/null
  [[ "$(jq -r .status <<<"$BODY")" == rejected ]] && pass "V8 the request is rejected" \
    || fail "V8 request $(jq -r .status <<<"$BODY")"
fi

# ── V10: an approver added on chain a moment ago ───────────────────────────
log "V10 the policy adds $STRANGER, then $STRANGER votes at once"
POLICY2=$(jq -nc --arg a "$APPROVER" --arg p "$PARENT" --arg s "$STRANGER" \
  '{rules:{transaction_types:["transfer"]}, approval:{threshold:{required:2}, approvers:[{id:$a},{id:$p},{id:$s}]}}')
if store_policy "$SEED" "$WALLET_ID" "$POLICY2"; then
  api "$SEED" POST /wallet/v1/transfer \
    "$(jq -nc --arg to "$PARENT" '{chain:"near", to:$to, amount:"1000000000000000000000"}')" >/dev/null
  AID=$(jq -r '.approval_id // empty' <<<"$BODY")
  if [[ -z "$AID" ]]; then
    fail "V10 transfer was not held for approval: HTTP $HTTP $(msg_of)"
  else
    api - GET "/wallet/v1/approval/$AID" >/dev/null
    RHASH=$(jq -r '.request_hash' <<<"$BODY"); WPK=$(jq -r '.wallet_pubkey' <<<"$BODY")
    vote approve "$STRANGER" "$STRANGER"
    assert_status "V10 the newly added approver is accepted" 200
  fi
else
  fail "V10 the policy adding $STRANGER was not stored"
fi

verdict "approval votes"
