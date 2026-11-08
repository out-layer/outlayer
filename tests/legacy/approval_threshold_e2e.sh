#!/bin/bash
# Multisig THRESHOLD e2e on testnet (2-of-2) — coverage the suite lacks
# (approval_flow_e2e.sh only does 1-of-1).
#
# What it proves end-to-end:
#   1. Vault + sub-wallet (Bearer near:), policy with TWO approvers, threshold 2.
#   2. Transfer above the limit → coordinator queues ONE approval.
#   3. APPROVER1 signs NEP-413 → /approve accepted, but request stays PENDING
#      (1 of 2 is not enough — nothing executes, no on-chain tx).
#   4. APPROVER2 signs NEP-413 → /approve accepted, threshold reached →
#      background worker fires → on-chain tx, signer_id == sub-wallet.
#
# This exercises the keystore's NEW independent verification: it counts
# DISTINCT valid approver signatures and only signs when >= threshold. Before
# the keystore/coordinator update the happy path still works (coordinator
# counts), so run this BOTH before and after the update to confirm no
# regression — the 1-of-2 "stays pending" and 2-of-2 "executes" assertions
# must hold either way.
#
# Required env:
#   PARENT      vault owner, logged into outlayer-cli (NOT an approver)
#   APPROVER1   first approver  (creds in ~/.near-credentials/$NETWORK) [default outlayer-bob.testnet]
#   APPROVER2   second approver (creds in ~/.near-credentials/$NETWORK) [REQUIRED, != PARENT/APPROVER1]
#   MPC_PUBLIC_KEY  bls12381g2:base58 (for `outlayer vault init`)
#
# Run:
#   MPC_PUBLIC_KEY=bls12381g2:... PARENT=outlayer-alice.testnet \
#     APPROVER1=outlayer-bob.testnet APPROVER2=outlayer-carol.testnet \
#     ./tests/approval_threshold_e2e.sh --apply

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPLY=false
[[ "${1:-}" == "--apply" ]] && APPLY=true

NETWORK="${NETWORK:-testnet}"
PARENT="${PARENT:-}"
APPROVER1="${APPROVER1:-outlayer-bob.testnet}"
APPROVER2="${APPROVER2:-}"
# The keyed FastNEAR RPC (tests/lib/rpc.sh): an RPC_URL in the environment wins.
source "$SCRIPT_DIR/../lib/rpc.sh"
CONTRACT_ID="${CONTRACT_ID:-outlayer.testnet}"
COORDINATOR_URL="${COORDINATOR_URL:-https://testnet-api.outlayer.ai}"

[[ -n "$PARENT"    ]] || { echo "USAGE: PARENT=... APPROVER2=... $0 --apply" >&2; exit 1; }
[[ -n "$APPROVER2" ]] || { echo "✗ APPROVER2 is required (second distinct approver)" >&2; exit 1; }
[[ "$APPROVER2" != "$PARENT" && "$APPROVER2" != "$APPROVER1" ]] || { echo "✗ APPROVER2 must differ from PARENT and APPROVER1" >&2; exit 1; }

CREDS_DIR="$HOME/.near-credentials/$NETWORK"
for a in "$PARENT" "$APPROVER1" "$APPROVER2"; do
  [[ -f "$CREDS_DIR/$a.json" ]] || { echo "✗ creds missing: $CREDS_DIR/$a.json" >&2; exit 1; }
done
for tool in jq curl outlayer near python3; do
  command -v "$tool" >/dev/null || { echo "✗ missing $tool" >&2; exit 1; }
done

log()  { printf '\n\033[36m▶ %s\033[0m\n' "$*" >&2; }
warn() { printf '\033[33m⚠ %s\033[0m\n' "$*" >&2; }
pass() { printf '\033[32m✓ %s\033[0m\n' "$*" >&2; }
fail() { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

near_tty() {
  if command -v script >/dev/null 2>&1; then
    local tmp; tmp=$(mktemp -t thr_cmd.XXXXXX.sh)
    printf 'set -euo pipefail\n%s\n' "$*" > "$tmp"
    script -q /dev/null bash "$tmp"; local rc=$?
    rm -f "$tmp"; return $rc
  else
    eval "$@"
  fi
}

if [[ "$APPLY" != true ]]; then
  warn "Dry-run. Pass --apply to deploy + exercise the 2-of-2 threshold flow."
  exit 0
fi

RECOVERY_BIN="$SCRIPT_DIR/../../scripts/customer-recovery/target/release/customer-recovery"
log "Building customer-recovery (sign-nep413 + sign-bearer-near)"
(cd "$SCRIPT_DIR/../../scripts/customer-recovery" && cargo build --release --quiet) || fail "build failed"

WHOAMI=$(outlayer whoami 2>/dev/null | awk -F': *' '/^Account:/{print $2; exit}')
[[ "$WHOAMI" == "$PARENT" ]] || fail "outlayer logged in as '$WHOAMI', not '$PARENT'"
pass "logged in as $PARENT; approvers = $APPROVER1, $APPROVER2 (threshold 2)"

PARENT_PRIVKEY=$(jq -r '.private_key'  "$CREDS_DIR/$PARENT.json")
A1_PRIVKEY=$(jq -r '.private_key'      "$CREDS_DIR/$APPROVER1.json")
A1_PUBKEY=$(jq -r '.public_key'        "$CREDS_DIR/$APPROVER1.json")
A2_PRIVKEY=$(jq -r '.private_key'      "$CREDS_DIR/$APPROVER2.json")
A2_PUBKEY=$(jq -r '.public_key'        "$CREDS_DIR/$APPROVER2.json")

# ─── 1. vault + sub-wallet ────────────────────────────────────────
VAULT_NAME="thr-$(date +%s)"
VAULT_ID="$VAULT_NAME.$PARENT"
log "1. Deploy vault $VAULT_ID"
INIT_RC=0
INIT_OUT=$(outlayer vault init --name "$VAULT_NAME" --exit-window 60s 2>&1) || INIT_RC=$?
if [[ $INIT_RC -ne 0 ]] && echo "$INIT_OUT" | grep -q "outlayer vault resume"; then
  for _ in 1 2 3 4 5; do sleep 6; if outlayer vault resume "$VAULT_ID" >&2; then INIT_RC=0; break; fi; done
fi
[[ $INIT_RC -eq 0 ]] || fail "vault init failed: $INIT_OUT"
pass "vault $VAULT_ID deployed"

SEED="thr-user-$(date +%s)-$$"
mk_token() { CUSTOMER_RECOVERY_PRIVATE_KEY="$PARENT_PRIVKEY" "$RECOVERY_BIN" sign-bearer-near --account-id "$PARENT" --seed "$1" ${2:+--vault-id "$2"}; }

ADDR_RESP=$(curl -sS -G "$COORDINATOR_URL/wallet/v1/address" --data-urlencode "chain=near" \
  -H "Authorization: Bearer near:$(mk_token "$SEED" "$VAULT_ID")")
SUB_ADDR=$(echo "$ADDR_RESP"  | jq -r '.address')
WALLET_ID=$(echo "$ADDR_RESP" | jq -r '.wallet_id')
[[ -n "$SUB_ADDR" && "$SUB_ADDR" != "null" ]] || fail "/address failed: $ADDR_RESP"
pass "sub-wallet $WALLET_ID  addr=$SUB_ADDR"

log "2. Fund sub-wallet with 0.05 NEAR"
near_tty "near --quiet tokens $PARENT send-near $SUB_ADDR '0.05 NEAR' network-config $NETWORK sign-with-keychain send" || fail "funding failed"
for _ in 1 2 3 4 5 6; do
  curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"query\",\"params\":{\"request_type\":\"view_account\",\"finality\":\"final\",\"account_id\":\"$SUB_ADDR\"}}" \
    | jq -e '.result.amount' >/dev/null && break; sleep 2
done
pass "sub-wallet funded"

# ─── 3. policy: 2 approvers, threshold 2 ──────────────────────────
log "3. Store policy (2 approvers, threshold 2, transfers need approval)"
POLICY_BODY=$(jq -nc --arg wid "$WALLET_ID" \
  --arg a1 "$APPROVER1" --arg a1p "$A1_PUBKEY" \
  --arg a2 "$APPROVER2" --arg a2p "$A2_PUBKEY" \
  '{wallet_id:$wid, rules:{transaction_types:["transfer"]},
    approval:{threshold:{required:2}, approvers:[{id:$a1,pubkey:$a1p},{id:$a2,pubkey:$a2p}]}}')
ENC_RESP=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/encrypt-policy" \
  -H "Authorization: Bearer near:$(mk_token "$SEED" "$VAULT_ID")" -H 'Content-Type: application/json' -d "$POLICY_BODY")
ENCRYPTED_B64=$(echo "$ENC_RESP" | jq -r '.encrypted_base64 // empty')
[[ -n "$ENCRYPTED_B64" ]] || fail "/encrypt-policy failed: $ENC_RESP"
SIGN_RESP=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/sign-policy" \
  -H "Authorization: Bearer near:$(mk_token "$SEED" "$VAULT_ID")" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg ed "$ENCRYPTED_B64" --arg c "$PARENT" '{encrypted_data:$ed, caller:$c}')")
SIG_HEX=$(echo "$SIGN_RESP" | jq -r '.signature_hex // empty')
POLICY_VERSION=$(echo "$SIGN_RESP" | jq -r '.version // empty')
POLICY_LOCKED=$(echo "$SIGN_RESP" | jq -r '.locked // empty')
POLICY_VALID_UNTIL=$(echo "$SIGN_RESP" | jq -r '.valid_until // empty')
PUB_HEX=$(echo "$SIGN_RESP" | jq -r '.public_key_hex // empty')
[[ -n "$SIG_HEX" ]] || fail "/sign-policy failed: $SIGN_RESP"
STORE_ARGS=$(jq -nc --arg pk "ed25519:$PUB_HEX" --arg ed "$ENCRYPTED_B64" --argjson v "${POLICY_VERSION:-0}" --argjson l "${POLICY_LOCKED:-false}" --argjson u "${POLICY_VALID_UNTIL:-0}" --arg sg "$SIG_HEX" \
  '{wallet_pubkey:$pk, encrypted_data:$ed, wallet_signature:$sg, version:$v, locked:$l, valid_until:$u}')
near_tty "near contract call-function as-transaction $CONTRACT_ID store_wallet_policy json-args '$STORE_ARGS' \\
  prepaid-gas '100.0 Tgas' attached-deposit '0.1 NEAR' sign-as $PARENT network-config $NETWORK sign-with-keychain send" \
  || fail "store_wallet_policy failed"
pass "policy stored (threshold 2)"
sleep 5

# ─── 4. transfer → one pending approval ───────────────────────────
log "4. Transfer above limit → expect ONE pending approval"
T_RESP=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/transfer" \
  -H "Authorization: Bearer near:$(mk_token "$SEED" "$VAULT_ID")" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg to "$PARENT" '{chain:"near", receiver_id:$to, amount:"10000000000000000000000"}')")
APPROVAL_ID=$(echo "$T_RESP" | jq -r '.approval_id // .approval.id // empty')
REQUEST_ID=$(echo "$T_RESP"  | jq -r '.request_id  // .request.id  // empty')
[[ -n "$APPROVAL_ID" && "$APPROVAL_ID" != "null" ]] || fail "no approval queued: $T_RESP"
APPROVAL_DETAIL=$(curl -sS "$COORDINATOR_URL/wallet/v1/approval/$APPROVAL_ID")
REQUEST_HASH=$(echo "$APPROVAL_DETAIL" | jq -r '.request_hash // empty')
WALLET_PUBKEY=$(echo "$APPROVAL_DETAIL" | jq -r '.wallet_pubkey // empty')
[[ -n "$REQUEST_HASH" ]] || fail "no request_hash for $APPROVAL_ID"
[[ -n "$WALLET_PUBKEY" ]] || fail "no wallet_pubkey for $APPROVAL_ID"
pass "approval_id=$APPROVAL_ID  wallet_pubkey=$WALLET_PUBKEY  request_hash=$REQUEST_HASH"

# helper: approver signs approve:{id}:{wallet_pubkey}:{hash} (wallet-bound) and POSTs /approve
approve_with() {
  local acct=$1 priv=$2 pub=$3
  local msg="approve:$APPROVAL_ID:$WALLET_PUBKEY:$REQUEST_HASH"
  local nonce; nonce=$(head -c 32 /dev/urandom | base64 | tr -d '\n')
  local sj; sj=$(CUSTOMER_RECOVERY_PRIVATE_KEY="$priv" "$RECOVERY_BIN" sign-nep413 --message "$msg" --recipient "$CONTRACT_ID" --nonce-base64 "$nonce")
  local sig; sig=$(echo "$sj" | jq -r '.signature')
  curl -sS -o /tmp/thr_approve.body -w '%{http_code}' -X POST "$COORDINATOR_URL/wallet/v1/approve/$APPROVAL_ID" \
    -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg sig "$sig" --arg pk "$pub" --arg ac "$acct" --arg nc "$nonce" '{signature:$sig,public_key:$pk,account_id:$ac,nonce:$nc}')"
}

req_status() { curl -sS "$COORDINATOR_URL/wallet/v1/requests/$REQUEST_ID" -H "Authorization: Bearer near:$(mk_token "$SEED" "$VAULT_ID")" | jq -r '.status // empty'; }

# ─── 5. first approval → must stay pending (1 of 2) ───────────────
log "5. APPROVER1 ($APPROVER1) signs — 1 of 2, request must NOT execute"
H1=$(approve_with "$APPROVER1" "$A1_PRIVKEY" "$A1_PUBKEY"); echo "  /approve HTTP $H1: $(cat /tmp/thr_approve.body)" >&2
[[ "$H1" == "200" ]] || fail "first /approve rejected (HTTP $H1)"
sleep 8
ST1=$(req_status); echo "  status after 1 approval: $ST1" >&2
case "$ST1" in
  completed|success|failed) fail "request must stay pending after 1 of 2 approvals, got '$ST1' — threshold NOT enforced" ;;
esac
pass "still pending after 1 of 2 — threshold holds"

# ─── 6. second approval → threshold reached → executes ────────────
log "6. APPROVER2 ($APPROVER2) signs — 2 of 2, request must execute"
H2=$(approve_with "$APPROVER2" "$A2_PRIVKEY" "$A2_PUBKEY"); echo "  /approve HTTP $H2: $(cat /tmp/thr_approve.body)" >&2
[[ "$H2" == "200" ]] || fail "second /approve rejected (HTTP $H2)"
TX_HASH=""
for attempt in $(seq 1 15); do
  sleep 3; ST=$(req_status); echo "  attempt $attempt: status=$ST" >&2
  case "$ST" in
    completed|success) TX_HASH=$(curl -sS "$COORDINATOR_URL/wallet/v1/requests/$REQUEST_ID" -H "Authorization: Bearer near:$(mk_token "$SEED" "$VAULT_ID")" | jq -r '.result.tx_hash // .result.transaction_hash // empty'); break ;;
    failed) fail "execution failed after 2 approvals: $(curl -sS "$COORDINATOR_URL/wallet/v1/requests/$REQUEST_ID" -H "Authorization: Bearer near:$(mk_token "$SEED" "$VAULT_ID")" | jq -r '.result_data // .')" ;;
  esac
done
[[ -n "$TX_HASH" && "$TX_HASH" != "null" ]] || fail "did not execute within ~45s after 2 approvals"
pass "executed after 2 of 2: tx_hash=$TX_HASH"

log "6.1 Verify on chain: signer_id == sub-wallet ($SUB_ADDR)"
TX_SIGNER=$(curl -sS "$RPC_URL" -X POST -H 'Content-Type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tx\",\"params\":[\"$TX_HASH\",\"$SUB_ADDR\"]}" | jq -r '.result.transaction.signer_id // empty')
[[ "$TX_SIGNER" == "$SUB_ADDR" ]] || fail "tx signer is $TX_SIGNER, expected $SUB_ADDR"
pass "tx signed by sub-wallet"

echo
pass "ALL CHECKS PASSED (2-of-2 threshold):"
pass "  - policy threshold=2 with 2 approvers stored on chain"
pass "  - 1 of 2 approvals → request stayed pending (no execution)"
pass "  - 2 of 2 approvals → executed, on-chain signer == sub-wallet"
warn "Cleanup (optional): $VAULT_ID holds locked NEAR + policy storage stake."
