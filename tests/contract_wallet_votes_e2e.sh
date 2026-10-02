#!/usr/bin/env bash
#
# Contract-wallet votes on testnet: an approver WITHOUT access keys votes with
# an authorization its own wallet contract resolves (NEP-641, passkey).
#
# The approver is HoS's testnet passkey wallet `0s107c8e57…`, owned by their
# throwaway P-256 key (32 bytes of 0x07 — a public test vector: anyone can vote
# with this wallet, so nothing here holds real value). Blobs come from
# `lib/passkey_vote.mjs`, a port of HoS's `passkey-vote.ts`.
#
#   C1  a valid approve is stored and, at threshold 1, executes
#   C2  a blob signed by another key is refused (401), nothing stored
#   C3  a valid signature over ANOTHER approval's message is refused (401)
#   C4  a valid reject from the (unpinned) wallet vetoes: approval and request rejected
#   C5  a NEP-413 body in the wallet's name is refused (401: the wallet has no keys)
#   C6  a blob in the name of an account outside the policy is refused (403 not_approver)
#   C7  a wallet pinned to a key in the policy: its contract vote is refused (403)
#   C8  threshold 2: the wallet's vote plus a key holder's vote executes
#   C9  a message timestamped in the future is refused with the wallet's own words
#   C10 the same vote twice is 409 already_approved
#   C11 the build removed from the allowlist → 400; restored → accepted
#
# Needs ADMIN_TOKEN (the testnet admin bearer) to make sure the passkey build is
# listed, and for C11.
#
# Run:
#   ADMIN_TOKEN=… PARENT=outlayer-alice.testnet KEYHOLDER=outlayer-bob.testnet \
#     ./tests/contract_wallet_votes_e2e.sh --apply

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/hos_common.sh"

[[ "${1:-}" == "--apply" ]] || { warn "Dry run. Pass --apply."; exit 0; }

KEYHOLDER="${KEYHOLDER:-outlayer-bob.testnet}"
PASSKEY="${PASSKEY:-0s107c8e57b9fd8c0a11869a33e193b55d822c65d9}"
PASSKEY_HASH="${PASSKEY_HASH:-BBL8qKk7uKDDairkMqtqGa3QBuZLiXS8zTowDeeL823y}"
hos_require
[[ -n "${ADMIN_TOKEN:-}" ]] || { echo "✗ ADMIN_TOKEN is required (allowlist setup and C11)" >&2; exit 1; }
command -v node >/dev/null || { echo "✗ missing node" >&2; exit 1; }
[[ -f "$HOME/.near-credentials/$NETWORK/$KEYHOLDER.json" ]] || { echo "✗ creds missing for $KEYHOLDER" >&2; exit 1; }
creds() { jq -r ".$2" "$HOME/.near-credentials/$NETWORK/$1.json"; }

# admin <METHOD> <path> [body] — the token travels in a curl config on stdin,
# never on the command line.
admin() {
  local body=${3:-} extra=()
  [[ -n "$body" ]] && extra=(-H 'Content-Type: application/json' --data-binary "$body")
  BODY=$(printf 'header = "Authorization: Bearer %s"\n' "$ADMIN_TOKEN" \
    | curl -sS --max-time 60 -K - -w '\nHTTP:%{http_code}' -X "$1" "$COORDINATOR_URL$2" ${extra[@]+"${extra[@]}"} 2>/dev/null)
  HTTP=${BODY##*HTTP:}; BODY=${BODY%$'\n'HTTP:*}
}
listed() { admin GET /admin/contract-wallet-code-hashes; jq -e --arg h "$PASSKEY_HASH" '.code_hashes[]? | select(.code_hash == $h and .shape == "nep641")' <<<"$BODY" >/dev/null; }
list_passkey() { admin POST /admin/contract-wallet-code-hashes "$(jq -nc --arg h "$PASSKEY_HASH" '{code_hash:$h, shape:"nep641", note:"HoS passkey wallet, testnet build of near/intents 32a7836"}')"; }

blob() { node "$HOS_LIB_DIR/passkey_vote.mjs" "$1" "$PASSKEY" testnet "${2:-7}" "${3:--60}"; }

# held <tag> — a 0.001 NEAR transfer held for approval. Sets AID RID MSG_A MSG_R.
held() {
  api "$SEED" POST /wallet/v1/transfer \
    "$(jq -nc --arg to "$PARENT" '{chain:"near", to:$to, amount:"1000000000000000000000"}')" >/dev/null
  AID=$(jq -r '.approval_id // empty' <<<"$BODY"); RID=$(jq -r '.request_id // empty' <<<"$BODY")
  [[ -n "$AID" ]] || { fail "$1: transfer was not held for approval: HTTP $HTTP $(msg_of)"; return 1; }
  api - GET "/wallet/v1/approval/$AID" >/dev/null
  local wpk rh; wpk=$(jq -r .wallet_pubkey <<<"$BODY"); rh=$(jq -r .request_hash <<<"$BODY")
  MSG_A="approve:$AID:$wpk:$rh"; MSG_R="reject:$AID:$wpk:$rh"
  note "$1: approval $AID"
}

# cvote <approve|reject> <authorization> [account] — a contract vote.
cvote() {
  api - POST "/wallet/v1/$1/$AID" "$(jq -nc --arg a "${3:-$PASSKEY}" --arg z "$2" '{account_id:$a, authorization:$z}')" >/dev/null
}

# kvote <approve|reject> <named-account> <signing-account> — a NEP-413 vote.
kvote() {
  local msg nonce sig
  [[ "$1" == approve ]] && msg=$MSG_A || msg=$MSG_R
  nonce=$(head -c 32 /dev/urandom | base64 | tr -d '\n')
  sig=$(CUSTOMER_RECOVERY_PRIVATE_KEY="$(creds "$3" private_key)" "$RECOVERY_BIN" sign-nep413 \
    --message "$msg" --recipient "$CONTRACT_ID" --nonce-base64 "$nonce" | jq -r '.signature')
  api - POST "/wallet/v1/$1/$AID" "$(jq -nc --arg s "$sig" --arg pk "$(creds "$3" public_key)" --arg a "$2" --arg n "$nonce" \
    '{signature:$s, public_key:$pk, account_id:$a, nonce:$n}')" >/dev/null
}

votes_by() { api - GET "/wallet/v1/approval/$AID" >/dev/null; jq --arg a "$1" '[.approvers[]? | select(.approver_id == $a)] | length' <<<"$BODY"; }

# settled — poll the request until it ends; echoes its status.
settled() {
  local st=""
  for _ in $(seq 1 15); do
    sleep 3
    api "$SEED" GET "/wallet/v1/requests/$RID" >/dev/null
    st=$(jq -r .status <<<"$BODY")
    [[ "$st" == success || "$st" == completed || "$st" == failed || "$st" == rejected ]] && break
  done
  echo "$st"
}

policy_with() { store_policy "$SEED" "$WALLET_ID" "$(jq -nc --argjson a "$1" --argjson t "$2" \
  '{rules:{transaction_types:["transfer"]}, approval:{threshold:{required:$t}, approvers:$a}}')"; }

# ── setup ───────────────────────────────────────────────────────────────────
log "setup: allowlist, wallet under $PARENT"
if listed; then note "passkey build $PASSKEY_HASH already listed"; else
  list_passkey; [[ "$HTTP" == 200 ]] && listed || { echo "✗ could not list the passkey build: HTTP $HTTP $BODY" >&2; exit 1; }
  note "listed the passkey build $PASSKEY_HASH"
fi
SEED="cvotes-$(date +%s)-$$"
read -r WALLET_ID ADDR < <(wallet_address "$SEED") || { echo "✗ no wallet" >&2; exit 1; }
fund_account "$ADDR" 0.03 || { echo "✗ could not fund $ADDR" >&2; exit 1; }

# ── threshold 1, the wallet the only approver ───────────────────────────────
log "policy: threshold 1, approvers [$PASSKEY]"
policy_with "$(jq -nc --arg p "$PASSKEY" '[{id:$p}]')" 1 || { echo "✗ policy not stored" >&2; exit 1; }
held "A1" || exit 1

log "C2 a blob signed by another key"
cvote approve "$(blob "$MSG_A" 8)"
assert_status "C2 refused" 401 && assert_msg "C2 names the wallet's reason" "invalid signature"

log "C3 a valid signature over another approval's message"
cvote approve "$(blob "approve:00000000-0000-0000-0000-000000000000:${MSG_A#*:*:}")"
assert_status "C3 refused" 401 && assert_msg "C3 says the payload differs" "different payload"

log "C5 a NEP-413 body in the wallet's name"
kvote approve "$PASSKEY" "$PARENT"
assert_status "C5 refused: the wallet holds no keys" 401

log "C6 a blob in the name of an account outside the policy"
cvote approve "$(blob "$MSG_A")" "$KEYHOLDER"
if assert_status "C6 refused" 403; then
  [[ "$(err_of)" == not_approver ]] && pass "C6 not_approver, before its wallet is read" || fail "C6 error $(err_of)"
fi

log "C9 a message from the future"
cvote approve "$(blob "$MSG_A" 7 600)"
assert_status "C9 refused" 401 && assert_msg "C9 names the wallet's reason" "from the future"

[[ "$(votes_by "$PASSKEY")" == 0 ]] && pass "C2-C9 nothing stored" || fail "C2-C9 a refused vote was stored"

log "C11 the build removed from the allowlist"
admin DELETE "/admin/contract-wallet-code-hashes/$PASSKEY_HASH"
if [[ "$HTTP" == 200 ]] && ! listed; then
  cvote approve "$(blob "$MSG_A")"
  assert_status "C11 refused while unlisted" 400
  list_passkey
  listed && pass "C11 build listed again" || fail "C11 could not restore the allowlist row: HTTP $HTTP"
else
  fail "C11 could not remove the row: HTTP $HTTP"
  listed || list_passkey
fi

log "C1 a valid approve"
cvote approve "$(blob "$MSG_A")"
assert_status "C1 accepted" 200
[[ "$(jq -r .status <<<"$BODY")" == approved ]] && pass "C1 threshold met" || fail "C1 status $(jq -c '{status,approved,required}' <<<"$BODY")"
api - GET "/wallet/v1/approval/$AID" >/dev/null
[[ "$(jq -r --arg p "$PASSKEY" '.approvers[] | select(.approver_id == $p) | .proof_kind' <<<"$BODY")" == contract ]] \
  && pass "C1 the vote is listed as a contract vote" || fail "C1 proof_kind: $(jq -c .approvers <<<"$BODY")"
[[ "$(jq -r --arg p "$PASSKEY" '.approvers[] | select(.approver_id == $p) | .signature | type' <<<"$BODY")" == null ]] \
  && pass "C1 a contract vote carries no signature (null)" || fail "C1 signature: $(jq -c .approvers <<<"$BODY")"
ST=$(settled); [[ "$ST" == success || "$ST" == completed ]] && pass "C1 executed ($ST)" \
  || fail "C1 request ended $ST: $(jq -c .result <<<"$BODY" | head -c 240)"

# ── threshold 2, the wallet and a key holder ────────────────────────────────
log "policy: threshold 2, approvers [$PASSKEY, $KEYHOLDER]"
policy_with "$(jq -nc --arg p "$PASSKEY" --arg k "$KEYHOLDER" '[{id:$p},{id:$k}]')" 2 || { echo "✗ policy not stored" >&2; exit 1; }
held "B1" || exit 1

log "C10 the same contract vote twice"
B=$(blob "$MSG_A")
cvote approve "$B"
assert_status "C10 first vote" 200
[[ "$(jq -r .approved <<<"$BODY")" == 1 ]] && pass "C10 pending at 1 of 2" || fail "C10 $(jq -c . <<<"$BODY")"
cvote approve "$B"
if assert_status "C10 replay" 409; then [[ "$(err_of)" == already_approved ]] && pass "C10 already_approved" || fail "C10 $(err_of)"; fi

log "C8 the key holder's vote completes the threshold"
kvote approve "$KEYHOLDER" "$KEYHOLDER"
assert_status "C8 accepted" 200
ST=$(settled); [[ "$ST" == success || "$ST" == completed ]] && pass "C8 executed with one contract and one key vote ($ST)" \
  || fail "C8 request ended $ST: $(jq -c .result <<<"$BODY" | head -c 240)"

held "B2" || exit 1
log "C4 a valid reject from the wallet"
cvote reject "$(blob "$MSG_R")"
assert_status "C4 accepted" 200
[[ "$(jq -r .status <<<"$BODY")" == rejected ]] && pass "C4 the approval is rejected" || fail "C4 status $(jq -r .status <<<"$BODY")"
api "$SEED" GET "/wallet/v1/requests/$RID" >/dev/null
[[ "$(jq -r .status <<<"$BODY")" == rejected ]] && pass "C4 the request is rejected" || fail "C4 request $(jq -r .status <<<"$BODY")"

# ── a pinned approver ───────────────────────────────────────────────────────
log "policy: threshold 1, $PASSKEY pinned to $KEYHOLDER's key"
policy_with "$(jq -nc --arg p "$PASSKEY" --arg pk "$(creds "$KEYHOLDER" public_key)" '[{id:$p, pubkey:$pk}]')" 1 \
  || { echo "✗ policy not stored" >&2; exit 1; }
held "P1" || exit 1
log "C7 a valid contract vote from a pinned approver"
cvote approve "$(blob "$MSG_A")"
assert_status "C7 refused" 403 && assert_msg "C7 says the approver votes with its key" "not through a wallet contract"
[[ "$(votes_by "$PASSKEY")" == 0 ]] && pass "C7 nothing stored" || fail "C7 a pinned approver's contract vote was stored"

verdict "contract wallet votes"
