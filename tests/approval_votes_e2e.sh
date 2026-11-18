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
#   V11 an approver removed from the policy on chain is refused at once, even
#       while the coordinator's copy still names it (needs PSQL_CMD: the probe
#       puts the copy one policy behind, as a lost chain event leaves it)
#   V12 a reject cast before a final block holds the policy it was admitted
#       under does not cancel yet (`reject_vote_recorded`); the same account's
#       reject sent again is proven like a first one — a forged one is 401 and
#       changes nothing — and cancels once the block is final; the vote is
#       stored once. The window is a block or two: the probe tries three times
#       and is SKIPPED, not passed, when it never lands in it.
#
# Actors: PARENT owns the wallet and is the second approver; APPROVER is the
# first; STRANGER is in no policy. Each signs with its own key from
# ~/.near-credentials.
#
# Run:
#   PARENT=outlayer-alice.testnet APPROVER=outlayer-bob.testnet \
#     STRANGER=outlayer-carol.testnet PSQL_CMD=… ./tests/approval_votes_e2e.sh --apply

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/hos_common.sh"

[[ "${1:-}" == "--apply" ]] || { warn "Dry run. Pass --apply."; exit 0; }

APPROVER="${APPROVER:-outlayer-bob.testnet}"
STRANGER="${STRANGER:-outlayer-carol.testnet}"
hos_require

creds() { jq -r ".$2" "$HOME/.near-credentials/$NETWORK/$1.json"; }
for a in "$APPROVER" "$STRANGER"; do
  [[ -f "$HOME/.near-credentials/$NETWORK/$a.json" ]] || { echo "✗ creds missing for $a" >&2; exit 1; }
done

# signed_vote <approve|reject> <named-account> <signing-account> — the body of
# a NEP-413 vote on the current approval in <named-account>'s name, signed with
# <signing-account>'s key.
signed_vote() {
  local verb=$1 named=$2 signer=$3 msg nonce sig body
  msg="$verb:$AID:$WPK:$RHASH"
  nonce=$(head -c 32 /dev/urandom | base64 | tr -d '\n')
  sig=$(CUSTOMER_RECOVERY_PRIVATE_KEY="$(creds "$signer" private_key)" "$RECOVERY_BIN" sign-nep413 \
    --message "$msg" --recipient "$CONTRACT_ID" --nonce-base64 "$nonce" | jq -r '.signature')
  body=$(jq -nc --arg s "$sig" --arg pk "$(creds "$signer" public_key)" --arg a "$named" --arg n "$nonce" \
    '{signature:$s, public_key:$pk, account_id:$a, nonce:$n}')
  [[ "$verb" == reject ]] && body=$(jq -c '. + {reason:"e2e"}' <<<"$body")
  printf '%s' "$body"
}

# vote <approve|reject> <named-account> <signing-account> — cast it.
vote() { api - POST "/wallet/v1/$1/$AID" "$(signed_vote "$@")" >/dev/null; }

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

# hold_transfer <label> — a new transfer held for approval; sets AID, RID, RHASH, WPK.
hold_transfer() {
  api "$SEED" POST /wallet/v1/transfer \
    "$(jq -nc --arg to "$PARENT" '{chain:"near", to:$to, amount:"1000000000000000000000"}')" >/dev/null
  AID=$(jq -r '.approval_id // empty' <<<"$BODY"); RID=$(jq -r '.request_id // empty' <<<"$BODY")
  [[ -n "$AID" ]] || { fail "$1 transfer was not held for approval: HTTP $HTTP $(msg_of)"; return 1; }
  api - GET "/wallet/v1/approval/$AID" >/dev/null
  RHASH=$(jq -r '.request_hash' <<<"$BODY"); WPK=$(jq -r '.wallet_pubkey' <<<"$BODY")
}
request_status() { api "$SEED" GET "/wallet/v1/requests/$RID" >/dev/null; jq -r .status <<<"$BODY"; }

# ── V11: an approver removed on chain, while the copy still names it ───────
POLICY_TWO=$(jq -nc --arg a "$APPROVER" --arg p "$PARENT" \
  '{rules:{transaction_types:["transfer"]}, approval:{threshold:{required:2}, approvers:[{id:$a},{id:$p}]}}')
log "V11 the policy removes $STRANGER; the copy is put one policy behind; $STRANGER votes"
if ! sql_alive; then
  skip "V11 needs PSQL_CMD: without the copy put behind, the removal is not judged against a copy that still names $STRANGER"
elif ! store_policy "$SEED" "$WALLET_ID" "$POLICY_TWO"; then
  fail "V11 the policy removing $STRANGER was not stored"
elif hold_transfer V11; then
  copy_names() { sql "SELECT (policy_json::text LIKE '%\"$STRANGER\"%')::text FROM wallet_accounts WHERE wallet_id = '$WALLET_ID'"; }
  copy_digest() { sql "SELECT COALESCE(policy_ciphertext_sha256, 'NULL') FROM wallet_accounts WHERE wallet_id = '$WALLET_ID'"; }
  # The worker's sync of the removal lands first: a sync arriving after the
  # tamper would put the right copy back and let a copy-admitting coordinator
  # pass, and one arriving after the vote would replace the copy in its place.
  SYNCED=""
  for _ in $(seq 1 30); do [[ "$(copy_names)" == false && "$(copy_digest)" =~ ^[0-9a-f]{64}$ ]] && { SYNCED=1; break; }; sleep 4; done
  [[ -n "$SYNCED" ]] || warn "V11 the worker's sync of the removal was not seen in the row; a late sync can mask the probe"
  sql "UPDATE wallet_accounts SET policy_json = '$POLICY2'::jsonb, policy_ciphertext_sha256 = 'an-earlier-ciphertext' WHERE wallet_id = '$WALLET_ID'" >/dev/null
  if [[ "$(copy_names)" != true ]]; then
    fail "V11 fixture: the copy was not put behind"
  else
    vote approve "$STRANGER" "$STRANGER"
    if assert_status "V11 the removed approver is refused" 403; then
      [[ "$(err_of)" == not_approver ]] && pass "V11 not_approver, judged on the chain's policy" || fail "V11 error $(err_of)"
    fi
    [[ "$(votes_by "$STRANGER")" == 0 ]] && pass "V11 nothing stored for $STRANGER" || fail "V11 a vote of the removed approver was stored"
    [[ "$(copy_names)" == false ]] && pass "V11 the vote's read replaced the copy with the chain's policy" \
      || fail "V11 the copy still names $STRANGER after the read"
  fi
fi

# ── V12: a reject before a final block holds its policy, then again ────────
log "V12 $APPROVER rejects the moment a new policy is in; then again"
V12_DONE=""
for attempt in 1 2 3; do
  hold_transfer "V12 (try $attempt)" || { V12_DONE=1; break; }
  NO=$(signed_vote reject "$APPROVER" "$APPROVER")
  # Each try stores a different policy, so the record the vote is admitted
  # under is never the one a final block already holds.
  TYPES=$([[ $((attempt % 2)) == 1 ]] && echo '["transfer","call"]' || echo '["transfer"]')
  NEXT=$(jq -c --argjson t "$TYPES" '.rules.transaction_types = $t' <<<"$POLICY_TWO")
  STORE_POLICY_WAIT=optimistic store_policy "$SEED" "$WALLET_ID" "$NEXT" || { fail "V12 (try $attempt) the policy was not stored"; V12_DONE=1; break; }
  api - POST "/wallet/v1/reject/$AID" "$NO" >/dev/null
  FIRST_STATUS=$(jq -r '.status // empty' <<<"$BODY")
  if [[ "$HTTP" == 200 && "$FIRST_STATUS" == rejected ]]; then
    note "V12 try $attempt: a final block already held the new policy (cancelled at once); trying again"
    sleep 4
    continue
  fi
  if [[ "$HTTP" != 200 || "$FIRST_STATUS" != reject_vote_recorded ]]; then
    fail "V12a the first reject: HTTP $HTTP $(jq -c . <<<"$BODY" | head -c 200)"; V12_DONE=1; break
  fi
  V12_DONE=1
  pass "V12a cast before a final block held the policy: reject_vote_recorded"
  [[ "$(request_status)" == pending_approval ]] && pass "V12a the request is still pending" \
    || fail "V12a the request is $(request_status) after a deferred reject"
  sleep 4
  vote reject "$APPROVER" "$STRANGER"
  assert_status "V12b a repeat in $APPROVER's name signed with $STRANGER's key is refused" 401
  [[ "$(request_status)" == pending_approval ]] && pass "V12b the forged repeat changed nothing" \
    || fail "V12b the request is $(request_status) after a forged repeat"
  # The same repeat as a contract-wallet vote with an authorization nobody
  # proved: it is verified like a first contract vote and refused, never
  # taken as the stored NO's word.
  api - POST "/wallet/v1/reject/$AID" "$(jq -nc --arg a "$APPROVER" '{account_id:$a, authorization:"x", reason:"e2e"}')" >/dev/null
  [[ "$HTTP" != 200 ]] && pass "V12b an unproven contract-vote repeat is refused (HTTP $HTTP $(err_of))" \
    || fail "V12b an unproven contract-vote repeat was answered 200: $(jq -c . <<<"$BODY" | head -c 160)"
  [[ "$(request_status)" == pending_approval ]] && pass "V12b the unproven repeat changed nothing" \
    || fail "V12b the request is $(request_status) after an unproven repeat"
  vote reject "$APPROVER" "$APPROVER"
  if assert_status "V12c the repeat is answered like a first vote" 200; then
    [[ "$(jq -r .status <<<"$BODY")" == rejected ]] && pass "V12c the repeat cancels once the block is final" \
      || fail "V12c the repeat answered $(jq -r .status <<<"$BODY")"
  fi
  [[ "$(request_status)" == rejected ]] && pass "V12c the request is rejected" || fail "V12c the request is $(request_status)"
  [[ "$(votes_by "$APPROVER")" == 1 ]] && pass "V12d the vote is stored once" || fail "V12d $APPROVER holds $(votes_by "$APPROVER") rows"
  break
done
[[ -n "$V12_DONE" ]] || skip "V12 the window before a final block was not reached in 3 tries; the repeated reject was not exercised live"

verdict "approval votes"
