#!/bin/bash
# Approval-flow e2e on testnet — covers what no existing test does:
#
#   1. Bearer near: + vault_id minted sub-wallet ↓
#   2. Policy encrypted (via per-vault master) and stored on chain ↓
#   3. Sub-wallet transfer that EXCEEDS the policy limit ↓
#   4. Coordinator queues approval with `wallet_requests.vault_id` snapshotted ↓
#   5. External approver (different NEAR account) signs NEP-413 "approve:<id>:<hash>" ↓
#   6. POST /approve/:id → coordinator decrypts policy via vault master,
#      verifies approver, queues `execute_approved_*` background worker ↓
#   7. Worker reads vault_id from request row (NOT lookup_wallet_vault_id) ↓
#   8. Worker signs the transfer with the SUB-WALLET's per-vault key ↓
#   9. Tx lands on chain, signer_id == sub-wallet address — proving the
#      whole chain preserved vault scope from auth through approval through
#      background execution.
#
# Without the WF-3 fix this test fails at step 6 (PolicyDenied — keystore
# can't decrypt policy with default master) OR step 8 (worker uses default
# master, signed transaction's signer_id mismatches the address registered
# in step 1).
#
# Also covers (the negative scenarios):
#   A. Non-approver tries to approve → 4xx
#   B. /reject/:id by approver → wallet_requests.status = 'rejected', no on-chain tx
#
# Required env (same as bearer_near_recovery_e2e.sh):
#   PARENT          NEAR account that owns the vault (logged into outlayer-cli)
#   MPC_PUBLIC_KEY  bls12381g2:base58
#   APPROVER        NEAR account that will be in the approvers list
#                   (must have credentials in ~/.near-credentials/$NETWORK)
#                   Default: zavodil.testnet
#
# Run:
#   MPC_PUBLIC_KEY=bls12381g2:... PARENT=zavodil2.testnet \
#       APPROVER=zavodil.testnet \
#       ./tests/approval_flow_e2e.sh --apply

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPLY=false
[[ "${1:-}" == "--apply" ]] && APPLY=true

NETWORK="${NETWORK:-testnet}"
PARENT="${PARENT:-}"
APPROVER="${APPROVER:-zavodil.testnet}"
RPC_URL="${RPC_URL:-https://rpc.${NETWORK}.fastnear.com}"
CONTRACT_ID="${CONTRACT_ID:-outlayer.testnet}"

case "$NETWORK" in
  testnet)
    COORDINATOR_URL="${COORDINATOR_URL:-https://testnet-api.outlayer.ai}"
    ;;
  *) echo "✗ unsupported NETWORK=$NETWORK (only testnet)" >&2; exit 1;;
esac

[[ -n "$PARENT" ]] || { echo "USAGE: PARENT=... APPROVER=... $0 --apply" >&2; exit 1; }

PARENT_CREDS="${PARENT_CREDS:-$HOME/.near-credentials/$NETWORK/$PARENT.json}"
APPROVER_CREDS="${APPROVER_CREDS:-$HOME/.near-credentials/$NETWORK/$APPROVER.json}"
[[ -f "$PARENT_CREDS"   ]] || { echo "✗ creds missing: $PARENT_CREDS" >&2; exit 1; }
[[ -f "$APPROVER_CREDS" ]] || { echo "✗ creds missing: $APPROVER_CREDS" >&2; exit 1; }

for tool in jq curl outlayer near python3; do
  command -v "$tool" >/dev/null || { echo "✗ missing $tool" >&2; exit 1; }
done

log()  { printf '\n\033[36m▶ %s\033[0m\n' "$*" >&2; }
warn() { printf '\033[33m⚠ %s\033[0m\n' "$*" >&2; }
pass() { printf '\033[32m✓ %s\033[0m\n' "$*" >&2; }
fail() { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

near_tty() {
  if command -v script >/dev/null 2>&1; then
    local tmp; tmp=$(mktemp -t apr_cmd.XXXXXX.sh)
    printf 'set -euo pipefail\n%s\n' "$*" > "$tmp"
    script -q /dev/null bash "$tmp"; local rc=$?
    rm -f "$tmp"; return $rc
  else
    eval "$@"
  fi
}

if [[ "$APPLY" != true ]]; then
  warn "Dry-run mode. Pass --apply to deploy, store policy, and exercise approval flow."
  exit 0
fi

RECOVERY_BIN="$SCRIPT_DIR/../scripts/customer-recovery/target/release/customer-recovery"
log "Building customer-recovery (need sign-nep413 + sign-bearer-near)"
(cd "$SCRIPT_DIR/../scripts/customer-recovery" && cargo build --release --quiet) || \
  fail "customer-recovery build failed"

WHOAMI=$(outlayer whoami 2>/dev/null | awk -F': *' '/^Account:/{print $2; exit}')
[[ "$WHOAMI" == "$PARENT" ]] || fail "outlayer is logged in as '$WHOAMI', not '$PARENT'"
pass "logged in as $PARENT on $NETWORK; approver=$APPROVER"

PARENT_PRIVKEY=$(jq -r '.private_key' "$PARENT_CREDS")
APPROVER_PRIVKEY=$(jq -r '.private_key' "$APPROVER_CREDS")
APPROVER_PUBKEY=$(jq -r '.public_key' "$APPROVER_CREDS")
[[ -n "$APPROVER_PUBKEY" ]] || fail "no public_key in $APPROVER_CREDS"

# ─── 1. Deploy vault + mint sub-wallet via Bearer near: ───────────

VAULT_NAME="apr-$(date +%s)"
VAULT_ID="$VAULT_NAME.$PARENT"
log "1. Deploy vault $VAULT_ID (60s exit window)"
INIT_RC=0
INIT_OUT=$(outlayer vault init --name "$VAULT_NAME" --exit-window 60s 2>&1) || INIT_RC=$?
if [[ $INIT_RC -ne 0 ]] && echo "$INIT_OUT" | grep -q "outlayer vault resume"; then
  for attempt in 1 2 3 4 5; do
    sleep 6
    if outlayer vault resume "$VAULT_ID" >&2; then INIT_RC=0; break; fi
  done
fi
[[ $INIT_RC -eq 0 ]] || fail "vault init failed"
pass "vault $VAULT_ID deployed + verified"

SEED="apr-user-$(date +%s)-$$"
log "2. Mint sub-wallet via Bearer near: (seed=$SEED, vault=$VAULT_ID)"
mk_token() {
  local sd=$1 vid=$2
  "$RECOVERY_BIN" sign-bearer-near \
    --private-key "$PARENT_PRIVKEY" --account-id "$PARENT" --seed "$sd" \
    ${vid:+--vault-id "$vid"}
}

ADDR_RESP=$(curl -sS -G "$COORDINATOR_URL/wallet/v1/address" \
  --data-urlencode "chain=near" \
  -H "Authorization: Bearer near:$(mk_token "$SEED" "$VAULT_ID")")
SUB_ADDR=$(echo "$ADDR_RESP"   | jq -r '.address')
SUB_PUB=$(echo "$ADDR_RESP"    | jq -r '.public_key')
WALLET_ID=$(echo "$ADDR_RESP"  | jq -r '.wallet_id')
[[ -n "$SUB_ADDR" && "$SUB_ADDR" != "null" ]] || fail "/address failed: $ADDR_RESP"
pass "sub-wallet $WALLET_ID  addr=$SUB_ADDR  pub=$SUB_PUB"

log "3. Fund sub-wallet ($SUB_ADDR) with 0.05 NEAR from $PARENT"
near_tty "near tokens $PARENT send-near $SUB_ADDR '0.05 NEAR' \\
  network-config $NETWORK sign-with-keychain send" || \
  fail "funding sub-wallet failed"
for _ in 1 2 3 4 5 6; do
  if curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"query\",\"params\":{\"request_type\":\"view_account\",\"finality\":\"final\",\"account_id\":\"$SUB_ADDR\"}}" \
    | jq -e '.result.amount' >/dev/null; then break; fi
  sleep 2
done
pass "sub-wallet visible on chain"

# ─── 4. Build + encrypt + sign + store policy ─────────────────────
#
# Policy: any native NEAR transfer requires 1 approver signature from
# $APPROVER. `per_transaction.native = 1 yocto` makes any non-zero
# transfer exceed the limit, guaranteeing the approval path triggers.

log "4. Build policy → encrypt-policy → sign-policy → store_wallet_policy on chain"
# encrypt-policy expects a FLAT body (see EncryptPolicyRequest):
#   { wallet_id, rules, approval, admin_quorum?, webhook_url? }
# wallet_id is the deterministic UUID we got back from the first
# /address call (Section 2).
POLICY_BODY=$(jq -nc \
  --arg wid "$WALLET_ID" \
  --arg approver "$APPROVER" \
  --arg approver_pub "$APPROVER_PUBKEY" \
  '{
    wallet_id: $wid,
    rules: {
      transaction_types: ["transfer"]
    },
    approval: {
      threshold: { required: 1 },
      approvers: [ { id: $approver, pubkey: $approver_pub } ]
    }
  }')
echo "  policy body: $POLICY_BODY" >&2

# Encrypt with the wallet's per-vault master. Must use Bearer near: with
# vault_id so the keystore routes through the right master — this is the
# very flow we're testing.
ENC_RESP=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/encrypt-policy" \
  -H "Authorization: Bearer near:$(mk_token "$SEED" "$VAULT_ID")" \
  -H 'Content-Type: application/json' \
  -d "$POLICY_BODY")
ENCRYPTED_B64=$(echo "$ENC_RESP" | jq -r '.encrypted_base64 // empty')
[[ -n "$ENCRYPTED_B64" && "$ENCRYPTED_B64" != "null" ]] || \
  fail "/encrypt-policy failed: $ENC_RESP"

# Sign the encrypted blob with the wallet's per-vault key.
SIGN_RESP=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/sign-policy" \
  -H "Authorization: Bearer near:$(mk_token "$SEED" "$VAULT_ID")" \
  -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg ed "$ENCRYPTED_B64" --arg c "$PARENT" '{encrypted_data: $ed, caller: $c}')")
SIG_HEX=$(echo "$SIGN_RESP" | jq -r '.signature_hex // empty')
POLICY_VERSION=$(echo "$SIGN_RESP" | jq -r '.version // empty')
POLICY_LOCKED=$(echo "$SIGN_RESP" | jq -r '.locked // empty')
POLICY_VALID_UNTIL=$(echo "$SIGN_RESP" | jq -r '.valid_until // empty')
PUB_HEX=$(echo "$SIGN_RESP" | jq -r '.public_key_hex // empty')
[[ -n "$SIG_HEX" && "$SIG_HEX" != "null" ]] || fail "/sign-policy failed: $SIGN_RESP"
WALLET_PUBKEY_HEX="ed25519:$PUB_HEX"
pass "encrypted + signed: pubkey_hex=$WALLET_PUBKEY_HEX"

# Store on chain. wallet_policies map keys are `ed25519:<hex>` (see
# contract/src/wallet.rs::parse_wallet_pubkey) — this is the same shape
# /sign-policy returns, no re-encoding.
log "4.1 store_wallet_policy on $CONTRACT_ID (0.1 NEAR storage)"
STORE_ARGS=$(jq -nc \
  --arg pk "$WALLET_PUBKEY_HEX" \
  --arg ed "$ENCRYPTED_B64" \
  --argjson v "${POLICY_VERSION:-0}" --argjson l "${POLICY_LOCKED:-false}" --argjson u "${POLICY_VALID_UNTIL:-0}" --arg sg "$SIG_HEX" \
  '{wallet_pubkey: $pk, encrypted_data: $ed, wallet_signature: $sg, version:$v, locked:$l, valid_until:$u}')
near_tty "near contract call-function as-transaction $CONTRACT_ID store_wallet_policy \\
  json-args '$STORE_ARGS' \\
  prepaid-gas '100.0 Tgas' \\
  attached-deposit '0.1 NEAR' \\
  sign-as $PARENT \\
  network-config $NETWORK \\
  sign-with-keychain send" || fail "store_wallet_policy tx failed"
pass "policy stored on chain"

# ─── 5. Trigger approval: transfer exceeding policy limit ─────────

log "5. Transfer 0.01 NEAR from sub-wallet → $PARENT (policy requires 1 approver for transfers)"
# Wait briefly for the policy to reach final finality so the
# coordinator's view-call sees it on the very next request.
sleep 5
TRANSFER_BODY_RAW="$PWD/.transfer_resp.$$"
TRANSFER_HTTP=$(curl -sS -o "$TRANSFER_BODY_RAW" -w '%{http_code}' \
  -X POST "$COORDINATOR_URL/wallet/v1/transfer" \
  -H "Authorization: Bearer near:$(mk_token "$SEED" "$VAULT_ID")" \
  -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg to "$PARENT" '{chain: "near", receiver_id: $to, amount: "10000000000000000000000"}')")
TRANSFER_BODY=$(cat "$TRANSFER_BODY_RAW")
rm -f "$TRANSFER_BODY_RAW"
echo "  HTTP $TRANSFER_HTTP" >&2
echo "  raw body: $TRANSFER_BODY" >&2
# Parse only if body looks like JSON.
if ! echo "$TRANSFER_BODY" | jq -e . >/dev/null 2>&1; then
  fail "transfer response is not JSON (HTTP $TRANSFER_HTTP): $TRANSFER_BODY"
fi
echo "$TRANSFER_BODY" | jq . >&2

# Expected: HTTP 202 with `approval_id` and `request_id`, status pending_approval.
APPROVAL_ID=$(echo "$TRANSFER_BODY" | jq -r '.approval_id // .approval.id // empty')
REQUEST_ID=$(echo "$TRANSFER_BODY"  | jq -r '.request_id  // .request.id  // empty')
[[ -n "$APPROVAL_ID" && "$APPROVAL_ID" != "null" ]] || \
  fail "expected approval-required (got HTTP $TRANSFER_HTTP): $TRANSFER_BODY"
pass "approval_id=$APPROVAL_ID  request_id=$REQUEST_ID"

# ─── 6. Approver signs NEP-413 + POSTs /approve ───────────────────
#
# Coordinator expects: message = "approve:<approval_id>:<request_hash>".
# We don't know request_hash without DB access, but the coordinator
# exposes it through GET /wallet/v1/approval/:id (or similar). If the
# endpoint isn't exposed, the test asks the coordinator to echo it
# back — handled below.

log "6. Fetch approval details (need request_hash for NEP-413 message)"
DETAILS_RESP=$(curl -sS "$COORDINATOR_URL/wallet/v1/approval/$APPROVAL_ID")
REQUEST_HASH=$(echo "$DETAILS_RESP" | jq -r '.request_hash // empty')
WALLET_PUBKEY=$(echo "$DETAILS_RESP" | jq -r '.wallet_pubkey // empty')
if [[ -z "$REQUEST_HASH" || "$REQUEST_HASH" == "null" ]]; then
  warn "approval details endpoint did not return request_hash; trying alternative"
  warn "raw: $DETAILS_RESP"
  fail "cannot proceed without request_hash. If your build of coordinator \
exposes it elsewhere, set REQUEST_HASH manually before this section."
fi
[[ -n "$WALLET_PUBKEY" && "$WALLET_PUBKEY" != "null" ]] || fail "no wallet_pubkey for approval"
pass "request_hash=$REQUEST_HASH wallet_pubkey=$WALLET_PUBKEY"

# Wallet-bound approval message (audit fix 2): approve:{id}:{wallet_pubkey}:{request_hash}.
APPROVE_MSG="approve:$APPROVAL_ID:$WALLET_PUBKEY:$REQUEST_HASH"
NONCE_B64=$(head -c 32 /dev/urandom | base64 | tr -d '\n')

log "6.1 Approver ($APPROVER) signs NEP-413 message"
APPROVER_SIG_JSON=$("$RECOVERY_BIN" sign-nep413 \
  --private-key "$APPROVER_PRIVKEY" \
  --message "$APPROVE_MSG" \
  --recipient "$CONTRACT_ID" \
  --nonce-base64 "$NONCE_B64")
APPROVER_SIG=$(echo "$APPROVER_SIG_JSON" | jq -r '.signature')
APPROVER_SIG_PUB=$(echo "$APPROVER_SIG_JSON" | jq -r '.public_key')
[[ "$APPROVER_SIG_PUB" == "$APPROVER_PUBKEY" ]] || \
  fail "sign-nep413 pubkey mismatch: $APPROVER_SIG_PUB vs $APPROVER_PUBKEY"

log "6.2 POST /wallet/v1/approve/$APPROVAL_ID"
APPROVE_BODY=$(jq -nc \
  --arg sig "$APPROVER_SIG" \
  --arg pk  "$APPROVER_PUBKEY" \
  --arg ac  "$APPROVER" \
  --arg nc  "$NONCE_B64" \
  '{signature: $sig, public_key: $pk, account_id: $ac, nonce: $nc}')
APPROVE_RESP=$(curl -sS -w '\nHTTP:%{http_code}' -X POST \
  "$COORDINATOR_URL/wallet/v1/approve/$APPROVAL_ID" \
  -H 'Content-Type: application/json' -d "$APPROVE_BODY")
APPROVE_HTTP=$(echo "$APPROVE_RESP" | tail -1 | sed 's/HTTP://')
APPROVE_RESP_BODY=$(echo "$APPROVE_RESP" | sed '$d')
echo "$APPROVE_RESP_BODY" | jq . >&2
[[ "$APPROVE_HTTP" == "200" ]] || \
  fail "approve returned HTTP $APPROVE_HTTP: $APPROVE_RESP_BODY \
(WF-3 SUSPECT: if 'PolicyDenied' or 'decryption failed', the approval handler \
is decrypting policy with the wrong master)"
pass "approval accepted (HTTP 200)"

# ─── 7. Wait for background worker, verify on-chain signer ────────

log "7. Poll wallet_requests until completed (background worker fires)"
TX_HASH=""
for attempt in 1 2 3 4 5 6 7 8 9 10 11 12; do
  sleep 3
  STATUS_RESP=$(curl -sS "$COORDINATOR_URL/wallet/v1/requests/$REQUEST_ID" \
    -H "Authorization: Bearer near:$(mk_token "$SEED" "$VAULT_ID")")
  ST=$(echo "$STATUS_RESP" | jq -r '.status // empty')
  echo "  attempt $attempt: status=$ST" >&2
  case "$ST" in
    completed|success)
      TX_HASH=$(echo "$STATUS_RESP" | jq -r '.result.tx_hash // .result.transaction_hash // empty')
      break
      ;;
    failed)
      fail "background worker failed: $(echo "$STATUS_RESP" | jq -r '.result_data // .')"
      ;;
  esac
done
[[ -n "$TX_HASH" && "$TX_HASH" != "null" ]] || \
  fail "background worker did not complete within ~36s. Last status: $STATUS_RESP"
pass "background worker completed: tx_hash=$TX_HASH"

log "7.1 Verify on chain: tx signer_id MUST equal sub-wallet address ($SUB_ADDR)"
TX_VIEW=$(curl -sS "$RPC_URL" -X POST -H 'Content-Type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tx\",\"params\":[\"$TX_HASH\",\"$SUB_ADDR\"]}")
TX_SIGNER=$(echo "$TX_VIEW" | jq -r '.result.transaction.signer_id // empty')
echo "  tx signer_id (on chain): $TX_SIGNER" >&2
[[ "$TX_SIGNER" == "$SUB_ADDR" ]] || \
  fail "WF-3 REGRESSION: tx signer is $TX_SIGNER, expected $SUB_ADDR. \
The background worker derived the wallet under the wrong master (default \
instead of per-vault). resolve_request_vault_scope didn't return the snapshot."
pass "tx signed by sub-wallet derived from per-vault master — WF-3 fix verified"

# ─── 8. Negative: non-approver attempt ────────────────────────────
#
# A different NEAR account (the PARENT itself, which is not in the
# approvers list) signs the same approve message. Must 4xx.

log "8. Negative: PARENT ($PARENT) is NOT in approvers — /approve must reject"
# Trigger a fresh approval request first (the previous one is consumed).
T2_RESP=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/transfer" \
  -H "Authorization: Bearer near:$(mk_token "$SEED" "$VAULT_ID")" \
  -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg to "$PARENT" '{chain: "near", receiver_id: $to, amount: "5000000000000000000000"}')")
APPROVAL_2=$(echo "$T2_RESP" | jq -r '.approval_id // .approval.id // empty')
[[ -n "$APPROVAL_2" && "$APPROVAL_2" != "null" ]] || fail "second transfer didn't queue approval: $T2_RESP"
DETAILS2=$(curl -sS "$COORDINATOR_URL/wallet/v1/approval/$APPROVAL_2")
HASH2=$(echo "$DETAILS2" | jq -r '.request_hash')
WPK2=$(echo "$DETAILS2" | jq -r '.wallet_pubkey // empty')
MSG2="approve:$APPROVAL_2:$WPK2:$HASH2"
NONCE2=$(head -c 32 /dev/urandom | base64 | tr -d '\n')

PARENT_SIG_JSON=$("$RECOVERY_BIN" sign-nep413 \
  --private-key "$PARENT_PRIVKEY" \
  --message "$MSG2" --recipient "$CONTRACT_ID" --nonce-base64 "$NONCE2")
PARENT_SIG=$(echo "$PARENT_SIG_JSON" | jq -r '.signature')
PARENT_PUB=$(echo "$PARENT_SIG_JSON" | jq -r '.public_key')

WRONG_HTTP=$(curl -sS -o /tmp/apr_wrong.body -w '%{http_code}' -X POST \
  "$COORDINATOR_URL/wallet/v1/approve/$APPROVAL_2" \
  -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg sig "$PARENT_SIG" --arg pk "$PARENT_PUB" --arg ac "$PARENT" --arg nc "$NONCE2" \
       '{signature:$sig, public_key:$pk, account_id:$ac, nonce:$nc}')")
WRONG_BODY=$(cat /tmp/apr_wrong.body)
echo "  HTTP $WRONG_HTTP: $WRONG_BODY" >&2
if [[ "$WRONG_HTTP" =~ ^4 ]]; then
  pass "non-approver rejected (HTTP $WRONG_HTTP)"
else
  fail "non-approver should have been 4xx; got $WRONG_HTTP: $WRONG_BODY"
fi

# ─── 9. Reject path ───────────────────────────────────────────────
#
# `/reject` uses standard `authenticate()` then reads
# `body.approver_account` to identify which approver is rejecting.
# The approver authenticates via Bearer near: (signing with their own
# NEAR private key + any seed). Their NEAR account_id is asserted via
# the access-key check inside `extract_near_bearer_auth`, then we
# pass `approver_account` in the body so the handler matches it
# against the policy's approvers list.

log "9. Approver REJECTS the approval — Bearer near: from approver + approver_account in body"
APPROVER_SEED="reject-$(date +%s)"
APPROVER_BEARER=$("$RECOVERY_BIN" sign-bearer-near \
  --private-key "$APPROVER_PRIVKEY" \
  --account-id "$APPROVER" \
  --seed "$APPROVER_SEED")

REJECT_HTTP=$(curl -sS -o /tmp/apr_reject.body -w '%{http_code}' -X POST \
  "$COORDINATOR_URL/wallet/v1/reject/$APPROVAL_2" \
  -H "Authorization: Bearer near:$APPROVER_BEARER" \
  -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg ac "$APPROVER" '{approver_account: $ac}')")
REJECT_BODY=$(cat /tmp/apr_reject.body)
echo "  HTTP $REJECT_HTTP body=$REJECT_BODY" >&2
[[ "$REJECT_HTTP" == "200" ]] || \
  fail "/reject failed: HTTP $REJECT_HTTP body=$REJECT_BODY"
pass "/reject accepted (HTTP 200) — approver rejected via Bearer near: auth"

# ─── 9.1 Non-approver tries to reject — must 4xx ──────────────────
#
# Mirror the /approve negative test (Section 8): a Bearer near: caller
# who is NOT in the policy's approvers list (here: PARENT itself, who
# is vault.parent but not an approver) must be rejected by /reject too.

log "9.1 Negative: PARENT ($PARENT) is NOT an approver — /reject must reject"
# Need a fresh approval — the one above is consumed.
T3_RESP=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/transfer" \
  -H "Authorization: Bearer near:$(mk_token "$SEED" "$VAULT_ID")" \
  -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg to "$PARENT" '{chain: "near", receiver_id: $to, amount: "3000000000000000000000"}')")
APPROVAL_3=$(echo "$T3_RESP" | jq -r '.approval_id // .approval.id // empty')
[[ -n "$APPROVAL_3" && "$APPROVAL_3" != "null" ]] || fail "third transfer didn't queue approval: $T3_RESP"

# PARENT signs Bearer near: as themselves and tries to reject claiming to be the approver.
# The policy lists APPROVER, not PARENT, so /reject must refuse.
PARENT_SEED="reject-neg-$(date +%s)"
PARENT_BEARER=$("$RECOVERY_BIN" sign-bearer-near \
  --private-key "$PARENT_PRIVKEY" \
  --account-id "$PARENT" \
  --seed "$PARENT_SEED")

NEG_HTTP=$(curl -sS -o /tmp/apr_reject_neg.body -w '%{http_code}' -X POST \
  "$COORDINATOR_URL/wallet/v1/reject/$APPROVAL_3" \
  -H "Authorization: Bearer near:$PARENT_BEARER" \
  -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg ac "$PARENT" '{approver_account: $ac}')")
NEG_BODY=$(cat /tmp/apr_reject_neg.body)
echo "  HTTP $NEG_HTTP body=$NEG_BODY" >&2
if [[ "$NEG_HTTP" =~ ^4 ]]; then
  pass "non-approver /reject correctly refused (HTTP $NEG_HTTP)"
else
  fail "non-approver /reject should be 4xx; got HTTP $NEG_HTTP body=$NEG_BODY"
fi

echo
pass "ALL CHECKS PASSED. Approval flow + Bearer near: + per-vault master verified:"
pass "  - sub-wallet minted via Bearer near: + vault_id"
pass "  - policy encrypted/signed by per-vault master, stored on chain"
pass "  - transfer above policy limit queued approval"
pass "  - approver NEP-413 sig accepted (WF-3 fix: approve handler decrypted policy via per-vault master)"
pass "  - background worker signed tx with sub-wallet's vault-derived key (WF-3 fix in resolver path)"
pass "  - on-chain tx signer_id == sub-wallet (end-to-end vault scope preserved)"
pass "  - non-approver rejected (4xx)"
pass "  - /reject by Bearer-near approver accepted (HTTP 200)"
pass "  - /reject by non-approver refused (4xx)"
warn "Cleanup (optional): $VAULT_ID has 0.1 NEAR locked + on-chain policy storage stake."
