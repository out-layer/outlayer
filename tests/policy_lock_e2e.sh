#!/usr/bin/env bash
#
# A locked policy on testnet: the owner alone cannot change it.
#
#   L0  the contract is at storage version 12 or later (policy_meta exists)
#   L1  a 2-of-2 policy with `approval.locked` is stored by the owner alone —
#       a tightening — and the chain shows version 1, locked
#   L2  a lock nobody could lift (threshold 3 of 2) is refused by encrypt-policy
#   L3  delete_wallet_policy under the lock is refused on chain
#   L4  freeze_wallet under the lock works: freezing is the owner's
#   L5  sign-policy with an open policy answers pending_approval; the approvers
#       see the new policy and the version they vote on; GET /policy is unchanged
#   L6  the first write's signature cannot be filed again (version), nor
#       relabelled with the right version (signature), nor with a past
#       deadline (expired, said before the signature check)
#   L7  one vote keeps it pending; the second releases the signature on the
#       request; the owner stores it — version 2, unlocked, still frozen
#   L5w the held write is announced (`approval_needed`) to the webhook of the
#       policy in force, judged as L7w judges
#   L7w the first vote is announced (`approval_received`) to the webhook of the
#       policy it was cast under, in a request whose signature the receiver
#       verified under this API's webhook-keys and which, being a wallet's
#       event, carries the wallet's id and no `X-Webhook-Signature`; no
#       webhook the receiver was sent failed that check (with HOOK_URL /
#       HOOK_LOG_URL from
#       `tests/hook_receiver.sh ensure`; skipped without them)
#   L7s the signed write is announced (`policy_update_signed`), judged as
#       L7w judges
#   L8  the same signed write a second time is refused (version)
#   L9  unfreeze works
#   L10 the owner alone re-locks (version 3)
#   L11 a reject by one approver ends the write: rejected, no signature
#   L12 three writes held over the same version: A and B gather their quorum
#       and are both signed; A (still locked, same approvers) stores, B is
#       refused on chain (version); C gathers its quorum AFTER A stored and
#       fails on the coordinator with the keystore's words (the chain moved
#       on). A keeps the lock on purpose: had A unlocked the policy, C's
#       approvers would no longer be approvers and their votes would be
#       refused at the door, never reaching the keystore
#   L13 the quorum unlocks the policy (version 5) and it deletes
#   L14 a second wallet of PARENT names the same receiver: its held write is
#       announced under ITS wallet id, verified, and a wait keyed on the first
#       wallet's id does not take it; its policy is then unlocked and deleted
#       (three more transactions of PARENT; skipped without a receiver)
#
# Not here: the keystore's direct refusals (unit-tested, keystore
# `policy_lock_tests`), approval expiry (needs the database), a contract-wallet
# approver (its own suite). Approvers vote by key from ~/.near-credentials.
#
# Run:
#   tests/hook_receiver.sh ensure; set -a; source "$(tests/hook_receiver.sh env-file)"; set +a
#   PARENT=outlayer-alice.testnet APPROVER=outlayer-carol.testnet \
#     APPROVER2=outlayer-daniel.testnet ./tests/policy_lock_e2e.sh --apply

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/hos_common.sh"
source "$HOS_LIB_DIR/near_sign.sh"

[[ "${1:-}" == "--apply" ]] || { warn "Dry run. Pass --apply."; exit 0; }

APPROVER="${APPROVER:-outlayer-carol.testnet}"
APPROVER2="${APPROVER2:-outlayer-daniel.testnet}"
hos_require

creds() { jq -r ".$2" "$HOME/.near-credentials/$NETWORK/$1.json"; }
for a in "$APPROVER" "$APPROVER2"; do
  [[ -f "$HOME/.near-credentials/$NETWORK/$a.json" ]] || { echo "✗ creds missing for $a" >&2; exit 1; }
done

# vote <approve|reject> <account> — a NEP-413 vote by <account>'s own key over
# the approval AID / wallet WPK / hash RHASH.
vote() {
  local verb=$1 who=$2 msg nonce sig body
  msg="$verb:$AID:$WPK:$RHASH"
  nonce=$(head -c 32 /dev/urandom | base64 | tr -d '\n')
  sig=$(CUSTOMER_RECOVERY_PRIVATE_KEY="$(creds "$who" private_key)" "$RECOVERY_BIN" sign-nep413 \
    --message "$msg" --recipient "$CONTRACT_ID" --nonce-base64 "$nonce" | jq -r '.signature')
  body=$(jq -nc --arg s "$sig" --arg pk "$(creds "$who" public_key)" --arg a "$who" --arg n "$nonce" \
    '{signature:$s, public_key:$pk, account_id:$a, nonce:$n}')
  [[ "$verb" == reject ]] && body=$(jq -c '. + {reason:"e2e"}' <<<"$body")
  api - POST "/wallet/v1/$verb/$AID" "$body" >/dev/null
}

# call <signer> <method> <args-json> <deposit> — a contract call; OUT, RC.
OUT=""; RC=0
# A transaction refused for its nonce was never applied — near-cli read the
# key's nonce from a node a block behind — so it is sent again. Any other
# refusal is the answer the probe judges, and is kept.
call() {
  local attempt
  for attempt in 1 2 3; do
    OUT=$(near --quiet contract call-function as-transaction "$CONTRACT_ID" "$2" json-args "$3" \
      prepaid-gas '100.0 Tgas' attached-deposit "$4" sign-as "$1" network-config "$NETWORK" \
      sign-with-keychain send 2>&1); RC=$?
    sleep 3
    grep -q "Transaction nonce .* must be account\[access_key\].nonce" <<<"$OUT" || return 0
    warn "$2: a stale nonce (attempt $attempt), sent again"
  done
}
refused() { # refused <desc> <pattern> — the last call panicked naming <pattern>
  local why; why=$(near_why "$OUT")
  if [[ $RC -ne 0 ]] && grep -qiE "$2" <<<"$why"; then pass "$1 refused: $(head -c 140 <<<"$why")"
  else fail "$1 expected a refusal naming /$2/, got rc=$RC: $why"; fi
}
landed() { [[ $RC -eq 0 ]] && { pass "$1"; return 0; } || { fail "$1: $(near_why "$OUT")"; return 1; }; }

# store_write <json> — store_wallet_policy with {wallet_pubkey, encrypted_data,
# wallet_signature, version, locked} taken from <json>, as PARENT.
store_write() {
  call "$PARENT" store_wallet_policy \
    "$(jq -c '{wallet_pubkey, encrypted_data, wallet_signature, version, locked, valid_until}' <<<"$1")" '0.1 NEAR'
}
meta() { near_view "$CONTRACT_ID" get_wallet_policy "$(jq -nc --arg k "$WALLET_PUBKEY" '{wallet_pubkey:$k}')"; }
meta_is() { # meta_is <desc> <version> <locked> [frozen]
  local m; m=$(meta)
  local got; got="$(jq -r '.version' <<<"$m")/$(jq -r '.locked' <<<"$m")${4:+/$(jq -r '.frozen' <<<"$m")}"
  local want="$2/$3${4:+/$4}"
  [[ "$got" == "$want" ]] && pass "$1 chain shows version/locked${4:+/frozen} $got" || fail "$1 chain shows $got, expected $want"
}
api_policy_is() { # api_policy_is <desc> <version> <locked> <has-approval true|false>
  api "$SEED" GET /wallet/v1/policy >/dev/null
  local got; got="$(jq -r '.version' <<<"$BODY")/$(jq -r '.locked' <<<"$BODY")/$(jq -r '.approval != null' <<<"$BODY")"
  [[ "$got" == "$2/$3/$4" ]] && pass "$1 GET /policy version/locked/approval $got" || fail "$1 GET /policy $got, expected $2/$3/$4"
}
# hold <desc> <policy-json> — sign-policy on a locked chain: pending. Sets AID, RID, RHASH, WPK.
hold() {
  store_policy "$SEED" "$WALLET_ID" "$2"; local rc=$?
  if [[ $rc -ne 2 ]]; then fail "$1 expected pending_approval (rc 2), got rc=$rc"; return 1; fi
  AID=$POLICY_APPROVAL_ID; RID=$POLICY_REQUEST_ID; RHASH=$POLICY_REQUEST_HASH
  api - GET "/wallet/v1/approval/$AID" >/dev/null
  WPK=$(jq -r '.wallet_pubkey' <<<"$BODY")
  pass "$1 held: approval $AID, request $RID"
}
wait_request() { # wait_request <rid> — ST, BODY
  local i; ST=""
  for i in $(seq 1 20); do
    sleep 3
    api "$SEED" GET "/wallet/v1/requests/$1" >/dev/null
    ST=$(jq -r .status <<<"$BODY")
    [[ "$ST" == success || "$ST" == failed || "$ST" == rejected ]] && break
  done
}

LOCKED=$(jq -nc --arg a "$APPROVER" --arg b "$APPROVER2" \
  '{rules:{transaction_types:["transfer"]}, approval:{threshold:{required:2}, approvers:[{id:$a},{id:$b}], locked:true}}')
# The receiver's URL carries its token: it goes into the policy, never onto a
# command line or the terminal.
[[ -n "${HOOK_URL:-}" ]] && LOCKED=$(HOOK_URL="$HOOK_URL" jq -c '. + {webhook_url: env.HOOK_URL}' <<<"$LOCKED")
# hook_saw <event> <needle>… — one delivery in the receiver's log is of
# <event> (the `x-event-type` header), its body holds every needle, the
# receiver verified its signature (`signature.ok`, lib/hook_receiver.mjs), it
# was sent as this suite's wallet (`X-Wallet-Id` is WALLET_ID) and, a wallet's
# event, it carries no `X-Webhook-Signature`. Left behind:
#   HOOK_LOG_READ     false when the receiver's log could not be read
#   HOOK_UNVERIFIED   why the receiver refused any webhook it was sent — a
#                     signature that does not hold, a stale timestamp — empty
#                     when it refused none
#   HOOK_KEYS_FAILED  how many requests the receiver answered 503 because it
#                     could not read the API's webhook-keys. That is the
#                     receiver's failure, not a webhook's: the delivery is sent
#                     again, so it is told apart from HOOK_UNVERIFIED
#   HOOK_MISDRESSED   the verified webhooks that carry `X-Webhook-Signature`
#                     without being an owner's (`signature.owner_hmac` against
#                     `signature.owner_hmac_expected`), or are one and carry none
# The log is read through stdin: its URL is a secret too.
HOOK_LOG_READ=false
HOOK_UNVERIFIED=""
HOOK_KEYS_FAILED=0
HOOK_MISDRESSED=""
hook_saw() {
  local event=$1 log; shift
  HOOK_LOG_READ=false
  log=$(printf 'url = "%s"\n' "$HOOK_LOG_URL" | curl -sS --max-time 20 -K - 2>/dev/null) || return 1
  jq -e '.requests | type == "array"' >/dev/null 2>&1 <<<"$log" || return 1
  HOOK_LOG_READ=true
  HOOK_KEYS_FAILED=$(jq -r '[.requests[] | select(.method == "POST" and .signature.reason == "keys_unavailable")] | length' <<<"$log" 2>/dev/null)
  HOOK_UNVERIFIED=$(jq -r '[.requests[] | select(.method == "POST" and (.headers["x-replayed-by-suite"] // "") == "" and .signature.ok != true and .signature.reason != "keys_unavailable") | "\(.headers["x-event-type"] // "no event type"): \(.signature.reason // "the receiver kept no verdict")"] | unique | join("; ")' <<<"$log" 2>/dev/null)
  HOOK_MISDRESSED=$(jq -r '[.requests[] | select(.method == "POST" and (.headers["x-replayed-by-suite"] // "") == "" and .signature.ok == true and .signature.owner_hmac != .signature.owner_hmac_expected) | "\(.headers["x-event-type"] // "no event type") sent as \(.signature.wallet_id)"] | unique | join("; ")' <<<"$log" 2>/dev/null)
  HOOK_WALLET_ID="$WALLET_ID" jq -e --arg e "$event" --args '[.requests[] | select((.headers["x-event-type"] // "") == $e and .signature.ok == true and .signature.owner_hmac == false and ((.headers["x-webhook-signature"] // "") == "") and .signature.wallet_id == env.HOOK_WALLET_ID) | (.body // "") as $b | select(all($ARGS.positional[]; . as $n | $b | contains($n)))] | length > 0' "$@" <<<"$log" >/dev/null 2>&1
}
# hook_ready <row> <what is not checked without it> — true when a receiver
# that verifies this API's webhooks is in the environment; otherwise a SKIP,
# or a failure when the receiver there verifies another API's.
hook_ready() {
  if [[ -z "${HOOK_URL:-}" || -z "${HOOK_LOG_URL:-}" ]]; then
    skip "$1 no webhook receiver (HOOK_URL / HOOK_LOG_URL): $2 is not checked"
    return 1
  fi
  if [[ "${HOOK_API_BASE:-}" != "$COORDINATOR_URL" ]]; then
    fail "$1 the receiver verifies the webhooks of '${HOOK_API_BASE:-no API}', and this suite runs against $COORDINATOR_URL: run tests/hook_receiver.sh ensure with COORDINATOR_URL set to it, and source its env file again"
    return 1
  fi
}
# hook_await <row> <event> <needle> <what it shows> — waits 45 s for that
# event of this suite's wallet in the receiver's log, and judges the log: the
# event verified, sent as the wallet, without `X-Webhook-Signature`; no
# webhook refused; none misdressed. A receiver that could not read the
# webhook-keys is said so, apart from a webhook that failed.
hook_await() {
  local row=$1 event=$2 needle=$3 what=$4 saw=""
  for _ in $(seq 1 9); do hook_saw "$event" "$needle" && { saw=1; break; }; sleep 5; done
  if [[ -n "$saw" ]]; then
    pass "$row $what: $event verified, sent as the wallet, no X-Webhook-Signature"
  elif [[ "$HOOK_LOG_READ" != true ]]; then
    fail "$row the receiver's log could not be read: no webhook was judged (is the receiver up? tests/hook_receiver.sh status)"
    return 1
  elif (( HOOK_KEYS_FAILED > 0 )); then
    fail "$row no verified $event for $needle in 45 s, and THE RECEIVER could not read the API's webhook-keys: it answered $HOOK_KEYS_FAILED request(s) 503 without judging them. This is the receiver's failure, not a webhook's — check GET $COORDINATOR_URL/wallet/v1/webhook-keys from this machine, then run the row again"
    return 1
  else
    fail "$row no $event for $needle that verifies, is sent as $WALLET_ID and carries no X-Webhook-Signature reached the webhook in 45 s"
  fi
  [[ -z "$HOOK_UNVERIFIED" ]] && pass "$row every webhook the receiver judged verifies under the API's webhook-keys" \
    || fail "$row the receiver refused webhooks: $HOOK_UNVERIFIED"
  [[ -z "$HOOK_MISDRESSED" ]] && pass "$row no wallet event carries X-Webhook-Signature" \
    || fail "$row X-Webhook-Signature is where it must not be, or missing: $HOOK_MISDRESSED"
  (( HOOK_KEYS_FAILED == 0 )) \
    || warn "$row THE RECEIVER could not read the API's webhook-keys for $HOOK_KEYS_FAILED request(s) and answered them 503; the coordinator sent them again. The receiver's failure, not a webhook's: those attempts were not judged"
}
OPEN='{"rules":{"transaction_types":["transfer"]}}'
OPEN_B='{"rules":{"transaction_types":["transfer","call"]}}'
OPEN_C='{"rules":{"transaction_types":["transfer","delete"]}}'
# Locked like LOCKED, other rules: a write that keeps the approvers in office.
LOCKED_B=$(jq -c '.rules.transaction_types = ["transfer","call"]' <<<"$LOCKED")

# ── L0 ───────────────────────────────────────────────────────────────────────
log "L0 storage version"
SV=$(near_view "$CONTRACT_ID" get_storage_version '{}' | jq -r .)
[[ "$SV" =~ ^[0-9]+$ ]] && (( SV >= 12 )) && pass "L0 contract storage version $SV (policy_meta since 12)" || { fail "L0 storage version $SV — deploy the v12 contract first"; verdict "policy lock"; exit 1; }

# ── setup + L1 ───────────────────────────────────────────────────────────────
SEED="lock-$(date +%s)-$$"
log "setup: wallet $SEED under $PARENT; approvers $APPROVER + $APPROVER2 (2 of 2)"
read -r WALLET_ID ADDR < <(wallet_address "$SEED") || { echo "✗ no wallet" >&2; exit 1; }

log "L1 the owner alone stores a locked 2-of-2 policy"
if store_policy "$SEED" "$WALLET_ID" "$LOCKED"; then
  pass "L1 stored"; FIRST_SIG=$POLICY_SIG; FIRST_ENC=$POLICY_ENC; FIRST_UNTIL=$POLICY_VALID_UNTIL
  meta_is L1 1 true
  api_policy_is L1 1 true true
else
  fail "L1 the first, locked policy was not stored"; verdict "policy lock"; exit 1
fi

# ── L2 ───────────────────────────────────────────────────────────────────────
log "L2 a lock nobody could lift"
api "$SEED" POST /wallet/v1/encrypt-policy "$(jq -nc --arg w "$WALLET_ID" --arg a "$APPROVER" --arg b "$APPROVER2" \
  '{wallet_id:$w, rules:{transaction_types:["transfer"]}, approval:{threshold:3, approvers:[{id:$a},{id:$b}], locked:true}}')" >/dev/null
assert_status "L2 refused" 400 && assert_msg "L2 says why" "never be lifted"

# ── L3 / L4 ──────────────────────────────────────────────────────────────────
log "L3 delete under the lock"
call "$PARENT" delete_wallet_policy "$(jq -nc --arg k "$WALLET_PUBKEY" '{wallet_pubkey:$k}')" '0 NEAR'
refused L3 "policy is locked"

log "L4 freeze under the lock"
call "$PARENT" freeze_wallet "$(jq -nc --arg k "$WALLET_PUBKEY" '{wallet_pubkey:$k}')" '0 NEAR'
landed "L4 frozen" && meta_is L4 1 true true

# ── L5 ───────────────────────────────────────────────────────────────────────
log "L5 the owner asks for an open policy"
if hold L5 "$OPEN"; then
  [[ "$(jq -r .request_type <<<"$BODY")" == policy_update ]] && pass "L5 approval type policy_update" || fail "L5 type $(jq -r .request_type <<<"$BODY")"
  [[ "$(jq -r '.request_data.policy.approval' <<<"$BODY")" == null ]] && pass "L5 the approvers see the new policy (no approval block)" \
    || fail "L5 request_data.policy carries an approval block"
  [[ "$(jq -r '.request_data.version' <<<"$BODY")" == 2 && "$(jq -r '.request_data.locked' <<<"$BODY")" == false ]] \
    && pass "L5 they vote on version 2, unlocked" || fail "L5 request_data $(jq -c '{version,locked}' <<<"$BODY")"
  [[ "$(jq -r '.required_approvals' <<<"$BODY")" == 2 ]] && pass "L5 2 approvals required" || fail "L5 required $(jq -r .required_approvals <<<"$BODY")"
  hook_ready L5w "the held write's webhook (approval_needed)" \
    && hook_await L5w approval_needed "$AID" "the held write was announced to the policy's webhook"
  api_policy_is L5 1 true true
fi

# ── L6 ───────────────────────────────────────────────────────────────────────
log "L6 the first write's signature, filed again"
store_write "$(jq -nc --arg k "$WALLET_PUBKEY" --arg e "$FIRST_ENC" --arg s "$FIRST_SIG" --argjson u "$FIRST_UNTIL" '{wallet_pubkey:$k, encrypted_data:$e, wallet_signature:$s, version:1, locked:true, valid_until:$u}')"
refused "L6 at version 1" "policy version is 1"
store_write "$(jq -nc --arg k "$WALLET_PUBKEY" --arg e "$FIRST_ENC" --arg s "$FIRST_SIG" --argjson u "$FIRST_UNTIL" '{wallet_pubkey:$k, encrypted_data:$e, wallet_signature:$s, version:2, locked:true, valid_until:$u}')"
refused "L6 relabelled as version 2" "Invalid Ed25519 wallet signature"
store_write "$(jq -nc --arg k "$WALLET_PUBKEY" --arg e "$FIRST_ENC" --arg s "$FIRST_SIG" '{wallet_pubkey:$k, encrypted_data:$e, wallet_signature:$s, version:2, locked:true, valid_until:1}')"
refused "L6 with a deadline in the past" "signature expired at 1"

# ── L7 ───────────────────────────────────────────────────────────────────────
if [[ -n "${AID:-}" ]]; then
  log "L7 $APPROVER approves"
  vote approve "$APPROVER"
  assert_status "L7 first vote" 200
  [[ "$(jq -r .status <<<"$BODY")" == pending ]] && pass "L7 pending at 1 of 2" || fail "L7 $(jq -c '{status,approved,required}' <<<"$BODY")"
  hook_ready L7w "the policy-update vote's webhook (approval_received)" \
    && hook_await L7w approval_received "$AID" "the vote was announced to the policy's webhook"
  api "$SEED" GET "/wallet/v1/requests/$RID" >/dev/null
  [[ "$(jq -r .status <<<"$BODY")" == pending_approval ]] && pass "L7 request still pending_approval" || fail "L7 request $(jq -r .status <<<"$BODY")"

  log "L7 $APPROVER2 approves"
  vote approve "$APPROVER2"
  assert_status "L7 second vote" 200
  wait_request "$RID"
  if [[ "$ST" == success ]]; then
    pass "L7 the signature is on the request"
    hook_ready L7s "the signed write's webhook (policy_update_signed)" \
      && hook_await L7s policy_update_signed "$RID" "the signed write was announced to the policy's webhook"
    WRITE=$(jq -c '.result' <<<"$BODY")
    [[ "$(jq -r .version <<<"$WRITE")" == 2 && "$(jq -r .locked <<<"$WRITE")" == false ]] && pass "L7 signed version 2, unlocked" \
      || fail "L7 result $(jq -c '{version,locked}' <<<"$WRITE")"
    store_write "$WRITE"
    if landed "L7 the owner stores the approved policy"; then
      meta_is L7 2 false true
      api "$SEED" POST /wallet/v1/invalidate-cache "$(jq -nc --arg w "$WALLET_ID" '{wallet_id:$w}')" >/dev/null
      api_policy_is L7 2 false false

      log "L8 the same signed write again"
      store_write "$WRITE"
      refused L8 "policy version is 2"
    fi
  else
    fail "L7 request ended $ST: $(jq -c '.result' <<<"$BODY" | head -c 200)"
  fi
fi

# ── L9 / L10 ─────────────────────────────────────────────────────────────────
log "L9 unfreeze"
call "$PARENT" unfreeze_wallet "$(jq -nc --arg k "$WALLET_PUBKEY" '{wallet_pubkey:$k}')" '0 NEAR'
landed "L9 unfrozen" && meta_is L9 2 false false

log "L10 the owner alone re-locks"
if store_policy "$SEED" "$WALLET_ID" "$LOCKED"; then pass "L10 stored"; meta_is L10 3 true; else fail "L10 re-lock not stored"; fi

# ── L11 ──────────────────────────────────────────────────────────────────────
log "L11 a reject ends the write"
if hold L11 "$OPEN"; then
  vote reject "$APPROVER"
  assert_status "L11 reject accepted" 200
  [[ "$(jq -r .status <<<"$BODY")" == rejected ]] && pass "L11 approval rejected at once" || fail "L11 status $(jq -r .status <<<"$BODY")"
  wait_request "$RID"
  [[ "$ST" == rejected ]] && pass "L11 request rejected" || fail "L11 request $ST"
  [[ "$(jq -r '.result.wallet_signature // empty' <<<"$BODY")" == "" ]] && pass "L11 no signature" || fail "L11 a signature was issued"
  meta_is L11 3 true
fi

# ── L12 ──────────────────────────────────────────────────────────────────────
log "L12 three writes over version 4"
hold "L12 A" "$LOCKED_B"; A_AID=$AID; A_RID=$RID; A_HASH=$RHASH
hold "L12 B" "$OPEN_B";   B_AID=$AID; B_RID=$RID; B_HASH=$RHASH
hold "L12 C" "$OPEN_C";   C_AID=$AID; C_RID=$RID; C_HASH=$RHASH
# quorum <desc> <aid> <hash> — both approvers vote YES; a vote the coordinator
# refuses is a failure here, not a silent miss.
quorum() {
  local desc=$1 who; AID=$2; RHASH=$3
  for who in "$APPROVER" "$APPROVER2"; do
    vote approve "$who"
    [[ "$HTTP" == 200 ]] || fail "$desc vote by $who → HTTP $HTTP: $(head -c 160 <<<"$BODY")"
  done
}
if [[ -n "${A_AID:-}" && -n "${B_AID:-}" && -n "${C_AID:-}" ]]; then
  quorum "L12 A" "$A_AID" "$A_HASH"; wait_request "$A_RID"; A_ST=$ST; A_WRITE=$(jq -c '.result' <<<"$BODY")
  quorum "L12 B" "$B_AID" "$B_HASH"; wait_request "$B_RID"; B_ST=$ST; B_WRITE=$(jq -c '.result' <<<"$BODY")
  [[ "$A_ST" == success && "$B_ST" == success ]] && pass "L12 A and B both signed before either stored" \
    || fail "L12 A $A_ST, B $B_ST"
  store_write "$A_WRITE"
  landed "L12 A stores (version 4, still locked)" && meta_is "L12 A" 4 true
  store_write "$B_WRITE"
  refused "L12 B after A" "policy version is 4"

  quorum "L12 C" "$C_AID" "$C_HASH"; wait_request "$C_RID"
  if [[ "$ST" == failed ]]; then
    pass "L12 C, voted after A stored, failed: $(jq -r '.result.error' <<<"$BODY" | head -c 160)"
  else
    fail "L12 C ended $ST, expected failed (the chain moved on under it)"
  fi
  meta_is "L12 end" 4 true
fi

# ── L13 ──────────────────────────────────────────────────────────────────────
log "L13 the quorum unlocks, then the policy deletes"
if hold "L13" "$OPEN"; then
  quorum "L13" "$AID" "$RHASH"; wait_request "$RID"
  if [[ "$ST" == success ]]; then
    store_write "$(jq -c '.result' <<<"$BODY")"
    landed "L13 unlocked (version 5)" && meta_is "L13" 5 false
  else
    fail "L13 unlock ended $ST: $(jq -c '.result' <<<"$BODY" | head -c 200)"
  fi
fi
call "$PARENT" delete_wallet_policy "$(jq -nc --arg k "$WALLET_PUBKEY" '{wallet_pubkey:$k}')" '0 NEAR'
landed "L13 deleted" && { [[ "$(meta)" == null ]] && pass "L13 gone from the chain" || fail "L13 still on chain: $(meta | head -c 120)"; }

# ── L14 ──────────────────────────────────────────────────────────────────────
log "L14 a second wallet's webhook at the same receiver"
if hook_ready L14 "a second wallet's event at the same receiver"; then
  FIRST_WALLET_ID=$WALLET_ID
  SEED="lock2-$(date +%s)-$$"
  if read -r WALLET_ID ADDR < <(wallet_address "$SEED") && [[ -n "$WALLET_ID" && "$WALLET_ID" != "$FIRST_WALLET_ID" ]] \
      && store_policy "$SEED" "$WALLET_ID" "$LOCKED"; then
    pass "L14 a second wallet ($WALLET_ID) stores a locked policy naming the same receiver"
    if hold L14 "$OPEN"; then
      hook_await L14 approval_needed "$AID" "the second wallet's held write was announced under its own wallet id"
      if WALLET_ID=$FIRST_WALLET_ID hook_saw approval_needed "$AID"; then
        fail "L14 the second wallet's event was taken for the first wallet's ($FIRST_WALLET_ID)"
      else
        pass "L14 a wait keyed on the first wallet's id does not take the second wallet's event"
      fi
      # The second wallet's policy is unlocked and deleted, as L13 does.
      quorum "L14" "$AID" "$RHASH"; wait_request "$RID"
      if [[ "$ST" == success ]]; then
        store_write "$(jq -c '.result' <<<"$BODY")"
        landed "L14 the second wallet's policy unlocked"
      else
        fail "L14 unlock ended $ST: $(jq -c '.result' <<<"$BODY" | head -c 200) — the second wallet's locked policy stays on chain"
      fi
      call "$PARENT" delete_wallet_policy "$(jq -nc --arg k "$WALLET_PUBKEY" '{wallet_pubkey:$k}')" '0 NEAR'
      landed "L14 the second wallet's policy deleted"
    fi
  else
    fail "L14 the second wallet's locked policy was not stored"
  fi
fi

verdict "policy lock"
