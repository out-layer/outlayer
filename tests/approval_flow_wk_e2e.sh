#!/bin/bash
# Approval-flow e2e on testnet — wk_ Bearer (legacy Flow 4a) variant.
#
# Regression sibling to `approval_flow_e2e.sh` (which exercises the
# Bearer near: stateless path). Same end-to-end shape:
#
#   POST /register {vault_id}  →  wk_ + wallet_id bound to vault
#   encrypt-policy / sign-policy / store_wallet_policy on chain
#   transfer above policy limit → pending_approval
#   approver NEP-413 sig → /approve
#   background worker fires → on-chain tx
#   verify tx signer_id == sub-wallet address (proves vault master used)
#
# **Why this test exists**: WF-3 added `wallet_requests.vault_id` and
# `resolve_request_vault_scope` (snapshot + fallback). The fallback
# path is what carries wk_-based requests for legacy in-flight rows.
# This test exercises the NEW INSERT (vault_id populated) AND verifies
# the wk_ approval flow still completes end-to-end with the correct
# vault-derived signing key. If WF-3 broke the wk_ path, this fails
# loud (PolicyDenied at approve, or wrong signer at on-chain tx).
#
# Required env (same as approval_flow_e2e.sh):
#   PARENT          NEAR account that owns the vault (outlayer login)
#   APPROVER        NEAR account in the approvers list (default zavodil.testnet)
#
# Run:
#   PARENT=zavodil2.testnet APPROVER=zavodil.testnet \
#       ./tests/approval_flow_wk_e2e.sh --apply

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPLY=false
[[ "${1:-}" == "--apply" ]] && APPLY=true

NETWORK="${NETWORK:-testnet}"
PARENT="${PARENT:-}"
APPROVER="${APPROVER:-zavodil.testnet}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/rpc.sh"   # keyed RPC_URL, or a warning
CONTRACT_ID="${CONTRACT_ID:-outlayer.testnet}"
COORDINATOR_URL="${COORDINATOR_URL:-https://testnet-api.outlayer.ai}"

[[ -n "$PARENT" ]] || { echo "USAGE: PARENT=... APPROVER=... $0 --apply" >&2; exit 1; }

APPROVER_CREDS="${APPROVER_CREDS:-$HOME/.near-credentials/$NETWORK/$APPROVER.json}"
[[ -f "$APPROVER_CREDS" ]] || { echo "✗ creds missing: $APPROVER_CREDS" >&2; exit 1; }

for tool in jq curl outlayer near python3; do
  command -v "$tool" >/dev/null || { echo "✗ missing $tool" >&2; exit 1; }
done

log()  { printf '\n\033[36m▶ %s\033[0m\n' "$*" >&2; }
warn() { printf '\033[33m⚠ %s\033[0m\n' "$*" >&2; }
pass() { printf '\033[32m✓ %s\033[0m\n' "$*" >&2; }
fail() { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

near_tty() {
  # `-t 1` as well as the binary: without a terminal `script` dies with
    # `tcgetattr/ioctl: Operation not supported on socket` and takes the step
    # with it — which surfaces as whatever that step was called, not as a
    # missing terminal. Guarded this way in the other copies of this helper.
    if command -v script >/dev/null 2>&1 && [ -t 1 ]; then
    local tmp; tmp=$(mktemp -t aprwk_cmd.XXXXXX.sh)
    printf 'set -euo pipefail\n%s\n' "$*" > "$tmp"
    script -q /dev/null bash "$tmp"; local rc=$?
    rm -f "$tmp"; return $rc
  else
    eval "$@"
  fi
}

if [[ "$APPLY" != true ]]; then
  warn "Dry-run mode. Pass --apply to deploy + exercise wk_ approval flow."
  exit 0
fi

RECOVERY_BIN="$SCRIPT_DIR/../scripts/customer-recovery/target/release/customer-recovery"
log "Building customer-recovery (need sign-nep413)"
(cd "$SCRIPT_DIR/../scripts/customer-recovery" && cargo build --release --quiet) || \
  fail "customer-recovery build failed"

# Without this, `outlayer` follows ~/.outlayer/default-network — mainnet on this
# machine — and the check below compares against the wrong network's account.
export OUTLAYER_NETWORK="$NETWORK"
WHOAMI=$(outlayer whoami 2>/dev/null | awk -F': *' '/^Account:/{print $2; exit}')
[[ "$WHOAMI" == "$PARENT" ]] || fail "outlayer is logged in as '$WHOAMI', not '$PARENT'"
pass "logged in as $PARENT on $NETWORK; approver=$APPROVER"

APPROVER_PRIVKEY=$(jq -r '.private_key' "$APPROVER_CREDS")
APPROVER_PUBKEY=$(jq -r '.public_key' "$APPROVER_CREDS")

# ─── 1. Deploy vault ─────────────────────────────────────────────

VAULT_NAME="aprwk-$(date +%s)"
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

# ─── 2. Mint wallet via POST /register {vault_id} (wk_ Bearer) ────

log "2. POST /register with vault_id → wk_ Bearer wallet bound to vault"
REG_RESP=$(curl -sS -X POST "$COORDINATOR_URL/register" \
  -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg vid "$VAULT_ID" '{vault_id: $vid}')")
WK_API_KEY=$(echo "$REG_RESP" | jq -r '.api_key')
WALLET_ID=$(echo "$REG_RESP"  | jq -r '.wallet_id')
SUB_ADDR=$(echo "$REG_RESP"   | jq -r '.near_account_id')
[[ -n "$WK_API_KEY" && "$WK_API_KEY" != "null" ]] || fail "/register failed: $REG_RESP"
pass "wallet $WALLET_ID  addr=$SUB_ADDR  api_key=${WK_API_KEY:0:12}…"

# /register doesn't echo vault_id in the response by current API shape —
# verify the binding via the /address endpoint (which DOES expose vault_id).
ADDR_RESP=$(curl -sS -G "$COORDINATOR_URL/wallet/v1/address" --data-urlencode "chain=near" \
  -H "Authorization: Bearer $WK_API_KEY")
GOT_VAULT=$(echo "$ADDR_RESP" | jq -r '.vault_id // empty')
[[ "$GOT_VAULT" == "$VAULT_ID" ]] || \
  fail "/address vault_id mismatch: got '$GOT_VAULT', expected '$VAULT_ID'. /register response: $REG_RESP"
PUB_HEX_SHORT=$(echo "$ADDR_RESP" | jq -r '.public_key' | sed 's/^ed25519://')
WALLET_PUBKEY_HEX="ed25519:$PUB_HEX_SHORT"

log "2.1 Fund sub-wallet ($SUB_ADDR) with 0.05 NEAR from $PARENT"
near_tty "near --quiet tokens $PARENT send-near $SUB_ADDR '0.05 NEAR' \\
  network-config $NETWORK sign-with-keychain send" || \
  fail "funding sub-wallet failed"
for _ in 1 2 3 4 5 6; do
  if curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"query\",\"params\":{\"request_type\":\"view_account\",\"finality\":\"final\",\"account_id\":\"$SUB_ADDR\"}}" \
    | jq -e '.result.amount' >/dev/null; then break; fi
  sleep 2
done
pass "sub-wallet funded + visible"

# ─── 3. Encrypt + sign + store policy (same as Bearer near: test) ─

log "3. encrypt-policy / sign-policy via wk_ Bearer, store on chain"
# Flat body shape per EncryptPolicyRequest.
POLICY_BODY=$(jq -nc \
  --arg wid "$WALLET_ID" \
  --arg approver "$APPROVER" \
  --arg approver_pub "$APPROVER_PUBKEY" \
  '{
    wallet_id: $wid,
    rules: { transaction_types: ["transfer"] },
    approval: { threshold: { required: 1 },
                approvers: [ { id: $approver, pubkey: $approver_pub } ] }
  }')
ENC_RESP=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/encrypt-policy" \
  -H "Authorization: Bearer $WK_API_KEY" \
  -H 'Content-Type: application/json' \
  -d "$POLICY_BODY")
ENCRYPTED_B64=$(echo "$ENC_RESP" | jq -r '.encrypted_base64 // empty')
[[ -n "$ENCRYPTED_B64" && "$ENCRYPTED_B64" != "null" ]] || fail "/encrypt-policy: $ENC_RESP"

SIGN_RESP=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/sign-policy" \
  -H "Authorization: Bearer $WK_API_KEY" \
  -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg ed "$ENCRYPTED_B64" --arg c "$PARENT" '{encrypted_data: $ed, caller: $c}')")
SIG_HEX=$(echo "$SIGN_RESP" | jq -r '.signature_hex // empty')
[[ -n "$SIG_HEX" && "$SIG_HEX" != "null" ]] || fail "/sign-policy: $SIGN_RESP"
pass "policy encrypted+signed under wk_ wallet"

log "3.1 store_wallet_policy on $CONTRACT_ID"
STORE_ARGS=$(jq -nc --arg pk "$WALLET_PUBKEY_HEX" --arg ed "$ENCRYPTED_B64" --arg sg "$SIG_HEX" \
  '{wallet_pubkey: $pk, encrypted_data: $ed, wallet_signature: $sg}')
near_tty "near contract call-function as-transaction $CONTRACT_ID store_wallet_policy \\
  json-args '$STORE_ARGS' \\
  prepaid-gas '100.0 Tgas' attached-deposit '0.1 NEAR' \\
  sign-as $PARENT network-config $NETWORK sign-with-keychain send" \
  || fail "store_wallet_policy tx failed"
pass "policy stored on chain"

# ─── 4. Trigger approval via wk_ Bearer ──────────────────────────

log "4. Transfer 0.01 NEAR (approval-gated by policy) → pending_approval"
T_RESP=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/transfer" \
  -H "Authorization: Bearer $WK_API_KEY" \
  -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg to "$PARENT" '{chain: "near", to: $to, amount: "10000000000000000000000"}')")
echo "$T_RESP" | jq . >&2
APPROVAL_ID=$(echo "$T_RESP" | jq -r '.approval_id // .approval.id // empty')
REQUEST_ID=$(echo "$T_RESP"  | jq -r '.request_id  // .request.id  // empty')
[[ -n "$APPROVAL_ID" && "$APPROVAL_ID" != "null" ]] || fail "no approval_id: $T_RESP"
pass "approval_id=$APPROVAL_ID  request_id=$REQUEST_ID"

# ─── 5. Approver signs NEP-413 → /approve ────────────────────────

DETAILS=$(curl -sS "$COORDINATOR_URL/wallet/v1/approval/$APPROVAL_ID")
REQUEST_HASH=$(echo "$DETAILS" | jq -r '.request_hash')
WALLET_PUBKEY=$(echo "$DETAILS" | jq -r '.wallet_pubkey // empty')
[[ -n "$REQUEST_HASH" && "$REQUEST_HASH" != "null" ]] || fail "no request_hash: $DETAILS"
[[ -n "$WALLET_PUBKEY" && "$WALLET_PUBKEY" != "null" ]] || fail "no wallet_pubkey: $DETAILS"

# Wallet-bound approval message (audit fix 2): approve:{id}:{wallet_pubkey}:{request_hash}.
APPROVE_MSG="approve:$APPROVAL_ID:$WALLET_PUBKEY:$REQUEST_HASH"
NONCE_B64=$(head -c 32 /dev/urandom | base64 | tr -d '\n')
APP_SIG_JSON=$("$RECOVERY_BIN" sign-nep413 \
  --private-key "$APPROVER_PRIVKEY" --message "$APPROVE_MSG" \
  --recipient "$CONTRACT_ID" --nonce-base64 "$NONCE_B64")
APP_SIG=$(echo "$APP_SIG_JSON" | jq -r '.signature')

log "5. POST /wallet/v1/approve/$APPROVAL_ID (approver NEP-413 sig)"
APP_RESP=$(curl -sS -w '\nHTTP:%{http_code}' -X POST \
  "$COORDINATOR_URL/wallet/v1/approve/$APPROVAL_ID" \
  -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg sig "$APP_SIG" --arg pk "$APPROVER_PUBKEY" --arg ac "$APPROVER" --arg nc "$NONCE_B64" \
       '{signature:$sig, public_key:$pk, account_id:$ac, nonce:$nc}')")
APP_HTTP=$(echo "$APP_RESP" | tail -1 | sed 's/HTTP://')
APP_BODY=$(echo "$APP_RESP" | sed '$d')
echo "$APP_BODY" | jq . >&2
[[ "$APP_HTTP" == "200" ]] || \
  fail "/approve returned HTTP $APP_HTTP: $APP_BODY \
(REGRESSION SUSPECT: WF-3 fix broke the legacy wk_ approval-decrypt path)"
pass "approval accepted (HTTP 200)"

# ─── 6. Wait for background worker, verify on-chain signer ───────

log "6. Poll status until 'completed'"
TX_HASH=""
for attempt in 1 2 3 4 5 6 7 8 9 10 11 12; do
  sleep 3
  S=$(curl -sS "$COORDINATOR_URL/wallet/v1/requests/$REQUEST_ID" \
    -H "Authorization: Bearer $WK_API_KEY")
  ST=$(echo "$S" | jq -r '.status')
  echo "  attempt $attempt: status=$ST" >&2
  case "$ST" in
    completed|success) TX_HASH=$(echo "$S" | jq -r '.result.tx_hash // .result.transaction_hash // empty'); break;;
    failed)    fail "worker failed: $(echo "$S" | jq -r '.result')";;
  esac
done
[[ -n "$TX_HASH" && "$TX_HASH" != "null" ]] || fail "worker did not complete within ~36s"
pass "background worker completed: tx_hash=$TX_HASH"

log "6.1 Verify on chain: tx signer_id == $SUB_ADDR"
TX_VIEW=$(curl -sS "$RPC_URL" -X POST -H 'Content-Type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tx\",\"params\":[\"$TX_HASH\",\"$SUB_ADDR\"]}")
TX_SIGNER=$(echo "$TX_VIEW" | jq -r '.result.transaction.signer_id // empty')
echo "  tx signer_id (on chain): $TX_SIGNER" >&2
[[ "$TX_SIGNER" == "$SUB_ADDR" ]] || \
  fail "REGRESSION: tx signer is $TX_SIGNER, expected $SUB_ADDR. \
WF-3 broke wk_ path — worker derived wrong key."
pass "tx signed by wk_-flow sub-wallet — wk_ regression NOT triggered"

echo
pass "ALL CHECKS PASSED. wk_ approval flow + per-vault master verified:"
pass "  - /register {vault_id} mints vault-scoped wk_ wallet (legacy Flow 4a)"
pass "  - wk_ Bearer encrypt-policy / sign-policy use per-vault master"
pass "  - policy stored on chain via parent"
pass "  - transfer triggers approval (policy enforcement intact)"
pass "  - approver NEP-413 sig accepted (approval decrypt uses correct master)"
pass "  - background worker signs with vault-derived key"
pass "  - on-chain tx signer_id == wallet address (WF-3 didn't regress wk_ flow)"
warn "Cleanup (optional): $VAULT_ID + storage stake."
