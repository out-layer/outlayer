#!/bin/bash
# /internal/wallet-policy-sync e2e — exercises the indexer-triggered
# decrypt path for two wallet creation flows:
#
#   A. Bearer near: + vault_id (the stateless flow that doesn't write
#      `wallet_accounts.vault_id` or `wallet_api_keys.customer_account_id`)
#   B. POST /register {vault_id} (legacy wk_ path — writes both)
#
# Pre-fix expectation:
#   A → 500 (AEAD failure: policy encrypted under per-vault master,
#         decrypt path resolves scope=None via lookup_wallet_vault_id)
#   B → 200 ok (lookup_wallet_vault_id returns the vault)
#
# Post-fix expectation (encrypt-policy persists wallet_accounts.vault_id):
#   A → 200 ok
#   B → 200 ok (unchanged)
#
# Required env:
#   PARENT              NEAR account that owns the vault (must have outlayer login)
#   API_AUTH_TOKEN      plaintext worker token (hash is in worker_auth_tokens)
#   COORDINATOR_URL     default https://testnet-api.outlayer.ai
#
# Run:
#   API_AUTH_TOKEN=... PARENT=zavodil2.testnet \
#       ./tests/internal_policy_sync_e2e.sh --apply

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPLY=false
[[ "${1:-}" == "--apply" ]] && APPLY=true

NETWORK="${NETWORK:-testnet}"
PARENT="${PARENT:-}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/rpc.sh"   # keyed RPC_URL, or a warning
CONTRACT_ID="${CONTRACT_ID:-outlayer.testnet}"
COORDINATOR_URL="${COORDINATOR_URL:-https://testnet-api.outlayer.ai}"
APPROVER="${APPROVER:-zavodil.testnet}"

[[ -n "$PARENT" ]] || { echo "USAGE: PARENT=... API_AUTH_TOKEN=... $0 --apply" >&2; exit 1; }
[[ -n "${API_AUTH_TOKEN:-}" ]] || { echo "✗ API_AUTH_TOKEN env required (worker plaintext token)" >&2; exit 1; }

CREDS_FILE="${CREDS_FILE:-$HOME/.near-credentials/$NETWORK/$PARENT.json}"
APPROVER_CREDS="${APPROVER_CREDS:-$HOME/.near-credentials/$NETWORK/$APPROVER.json}"
[[ -f "$CREDS_FILE" ]] || { echo "✗ creds missing: $CREDS_FILE" >&2; exit 1; }

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
    local tmp; tmp=$(mktemp -t ipsync_cmd.XXXXXX.sh)
    printf 'set -euo pipefail\n%s\n' "$*" > "$tmp"
    script -q /dev/null bash "$tmp"; local rc=$?
    rm -f "$tmp"; return $rc
  else
    eval "$@"
  fi
}

if [[ "$APPLY" != true ]]; then
  warn "Dry-run. Pass --apply to deploy + exercise the internal sync path."
  exit 0
fi

RECOVERY_BIN="$SCRIPT_DIR/../scripts/customer-recovery/target/release/customer-recovery"
log "Building customer-recovery"
(cd "$SCRIPT_DIR/../scripts/customer-recovery" && cargo build --release --quiet) || \
  fail "customer-recovery build failed"

# Without this, `outlayer` follows ~/.outlayer/default-network — mainnet on this
# machine — and the check below compares against the wrong network's account.
export OUTLAYER_NETWORK="$NETWORK"
WHOAMI=$(outlayer whoami 2>/dev/null | awk -F': *' '/^Account:/{print $2; exit}')
[[ "$WHOAMI" == "$PARENT" ]] || fail "outlayer logged in as '$WHOAMI', not '$PARENT'"
pass "logged in as $PARENT on $NETWORK"

PARENT_PRIVKEY=$(jq -r '.private_key' "$CREDS_FILE")
APPROVER_PUBKEY=$(jq -r '.public_key' "$APPROVER_CREDS" 2>/dev/null || echo "")

# ─── 1. Deploy one vault for both scenarios ───────────────────────

VAULT_NAME="ipsync-$(date +%s)"
VAULT_ID="$VAULT_NAME.$PARENT"
log "1. Deploy vault $VAULT_ID"
INIT_RC=0
INIT_OUT=$(outlayer vault init --name "$VAULT_NAME" --exit-window 60s 2>&1) || INIT_RC=$?
if [[ $INIT_RC -ne 0 ]] && echo "$INIT_OUT" | grep -q "outlayer vault resume"; then
  for attempt in 1 2 3 4 5; do
    sleep 6
    if outlayer vault resume "$VAULT_ID" >&2; then INIT_RC=0; break; fi
  done
fi
# The CLI's own words, not just the exit code: this step deploys a sub-account
# and can fail for reasons the operator can act on — a name already taken, a
# balance too small, a network pointed elsewhere — and none of them survive an
# exit status.
[[ $INIT_RC -eq 0 ]] || fail "vault init failed (rc=$INIT_RC): $(tail -c 500 <<<"$INIT_OUT")"
pass "vault $VAULT_ID deployed + verified"

# ─── Helper: end-to-end "encrypt → sign → store policy" for one wallet ────
#
# Inputs:
#   $1 — bearer arg ("near:<token>" or "<wk_apikey>")
#   $2 — wallet_pubkey ("ed25519:<hex>" — for on-chain store_wallet_policy)
#   $3 — wallet_id (coord uuid, for body)
# Output (echoed): ENCRYPTED_BASE64
prepare_and_store_policy() {
  local bearer=$1 wallet_pub=$2 wallet_id=$3
  local body
  body=$(jq -nc \
    --arg wid "$wallet_id" \
    --arg approver "$APPROVER" \
    --arg approver_pub "$APPROVER_PUBKEY" \
    '{
      wallet_id: $wid,
      rules: { transaction_types: ["transfer"] },
      approval: { threshold: { required: 1 },
                  approvers: [ { id: $approver, pubkey: $approver_pub } ] },
      authorized_key_hashes: ["0000000000000000000000000000000000000000000000000000000000000001"]
    }')
  local enc
  enc=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/encrypt-policy" \
    -H "Authorization: Bearer $bearer" \
    -H 'Content-Type: application/json' \
    -d "$body")
  local enc_b64
  enc_b64=$(echo "$enc" | jq -r '.encrypted_base64 // empty')
  [[ -n "$enc_b64" && "$enc_b64" != "null" ]] || { echo "encrypt-policy FAIL: $enc" >&2; return 1; }

  local sig_resp
  sig_resp=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/sign-policy" \
    -H "Authorization: Bearer $bearer" \
    -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg ed "$enc_b64" --arg c "$PARENT" '{encrypted_data: $ed, caller: $c}')")
  local sig_hex
  sig_hex=$(echo "$sig_resp" | jq -r '.signature_hex // empty')
  [[ -n "$sig_hex" && "$sig_hex" != "null" ]] || { echo "sign-policy FAIL: $sig_resp" >&2; return 1; }

  local store_args
  store_args=$(jq -nc --arg pk "$wallet_pub" --arg ed "$enc_b64" --arg sg "$sig_hex" \
    '{wallet_pubkey: $pk, encrypted_data: $ed, wallet_signature: $sg}')
  near_tty "near contract call-function as-transaction $CONTRACT_ID store_wallet_policy \\
    json-args '$store_args' \\
    prepaid-gas '100.0 Tgas' attached-deposit '0.1 NEAR' \\
    sign-as $PARENT network-config $NETWORK sign-with-keychain send" >&2 \
    || return 1

  echo "$enc_b64"
}

# ─── Helper: invoke /internal/wallet-policy-sync ─────────────────────────
sync_call() {
  local wallet_pub=$1 enc_b64=$2 owner=$3 out_file=$4
  # verify_internal_auth reads `x-internal-wallet-auth` header (the
  # plaintext token; coordinator SHA256s and compares against the
  # `worker_auth_tokens.token_hash` allowlist).
  curl -sS -o "$out_file" -w '%{http_code}' \
    -X POST "$COORDINATOR_URL/internal/wallet-policy-sync" \
    -H "x-internal-wallet-auth: $API_AUTH_TOKEN" \
    -H 'Content-Type: application/json' \
    -d "$(jq -nc \
      --arg wp "$wallet_pub" \
      --arg ed "$enc_b64" \
      --arg ow "$owner" \
      '{wallet_pubkey: $wp, encrypted_data: $ed, owner: $ow}')"
}

# ─── 2. Scenario A: Bearer near: + vault (the bug-prone path) ─────

log "2. Scenario A: mint sub-wallet via Bearer near: + vault_id"
SEED_A="ipsync-A-$(date +%s)-$$"
TOKEN_A=$("$RECOVERY_BIN" sign-bearer-near \
  --private-key "$PARENT_PRIVKEY" --account-id "$PARENT" --seed "$SEED_A" \
  --vault-id "$VAULT_ID")
ADDR_RESP_A=$(curl -sS -G "$COORDINATOR_URL/wallet/v1/address" --data-urlencode "chain=near" \
  -H "Authorization: Bearer near:$TOKEN_A")
SUB_PUB_A=$(echo "$ADDR_RESP_A" | jq -r '.public_key')
WALLET_ID_A=$(echo "$ADDR_RESP_A" | jq -r '.wallet_id')
SUB_ADDR_A=$(echo "$ADDR_RESP_A" | jq -r '.address')
[[ -n "$SUB_PUB_A" && "$SUB_PUB_A" != "null" ]] || fail "Scenario A /address failed: $ADDR_RESP_A"
pass "Scenario A sub-wallet: $SUB_ADDR_A (wallet_id=$WALLET_ID_A)"

log "2.1 encrypt-policy + sign-policy + store_wallet_policy under Bearer near:"
ENC_A=$(prepare_and_store_policy "near:$TOKEN_A" "$SUB_PUB_A" "$WALLET_ID_A") || \
  fail "Scenario A policy storage failed"
pass "Scenario A policy stored on chain (len=${#ENC_A} base64 chars)"

log "2.2 POST /internal/wallet-policy-sync as the worker (simulates indexer event)"
RESP_A_FILE=$(mktemp)
HTTP_A=$(sync_call "$SUB_PUB_A" "$ENC_A" "$PARENT" "$RESP_A_FILE")
BODY_A=$(cat "$RESP_A_FILE"); rm -f "$RESP_A_FILE"
echo "  HTTP $HTTP_A body=$BODY_A" >&2

# Expected before fix: 500 with AEAD/decrypt error. After fix: 200.
if [[ "$HTTP_A" == "200" ]]; then
  pass "Scenario A: /internal/wallet-policy-sync succeeded (HTTP 200 — fix is live)"
else
  warn "Scenario A: HTTP $HTTP_A — confirms the indexer-path bug before the fix"
  warn "  body: $BODY_A"
fi

# ─── 3. Scenario B: /register {vault_id} (control, wk_ flow) ───────

log "3. Scenario B: POST /register with vault_id → wk_ wallet bound to vault"
REG_B=$(curl -sS -X POST "$COORDINATOR_URL/register" \
  -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg vid "$VAULT_ID" '{vault_id: $vid}')")
WK_B=$(echo "$REG_B" | jq -r '.api_key')
WALLET_ID_B=$(echo "$REG_B" | jq -r '.wallet_id')
SUB_ADDR_B=$(echo "$REG_B" | jq -r '.near_account_id')
[[ -n "$WK_B" && "$WK_B" != "null" ]] || fail "Scenario B /register failed: $REG_B"
ADDR_RESP_B=$(curl -sS -G "$COORDINATOR_URL/wallet/v1/address" --data-urlencode "chain=near" \
  -H "Authorization: Bearer $WK_B")
SUB_PUB_B=$(echo "$ADDR_RESP_B" | jq -r '.public_key')
pass "Scenario B sub-wallet: $SUB_ADDR_B (wallet_id=$WALLET_ID_B)"

log "3.1 encrypt-policy + sign-policy + store under wk_ Bearer"
ENC_B=$(prepare_and_store_policy "$WK_B" "$SUB_PUB_B" "$WALLET_ID_B") || \
  fail "Scenario B policy storage failed"
pass "Scenario B policy stored on chain"

log "3.2 POST /internal/wallet-policy-sync for Scenario B"
RESP_B_FILE=$(mktemp)
HTTP_B=$(sync_call "$SUB_PUB_B" "$ENC_B" "$PARENT" "$RESP_B_FILE")
BODY_B=$(cat "$RESP_B_FILE"); rm -f "$RESP_B_FILE"
echo "  HTTP $HTTP_B body=$BODY_B" >&2

if [[ "$HTTP_B" == "200" ]]; then
  pass "Scenario B: /internal/wallet-policy-sync succeeded (HTTP 200) — control path intact"
elif [[ "$HTTP_B" == "401" ]] && grep -q 'internal wallet auth token' <<<"$BODY_B"; then
  # The control path refusing the CREDENTIAL says nothing about the decrypt
  # path this file exists to test. `/internal/*` accepts a worker token whose
  # sha256 is registered in the coordinator's `worker_auth_tokens`, which the
  # running worker holds and a checkout does not — so the token in a local
  # `worker/.env*` is usually some other deployment's. Reported as a skip and
  # not a failure: called red, it sends whoever reads the run looking for a
  # regression in code that was never reached.
  warn "SKIPPED — API_AUTH_TOKEN is not one of the tokens this coordinator has registered"
  warn "Supply the token the LIVE testnet worker runs with (its sha256 must be in worker_auth_tokens); a local worker/.env* copy is usually a different deployment's."
  exit 3
else
  fail "Scenario B (control) UNEXPECTEDLY failed: HTTP $HTTP_B body=$BODY_B"
fi

# ─── 4. Summary ───────────────────────────────────────────────────

echo
if [[ "$HTTP_A" == "200" && "$HTTP_B" == "200" ]]; then
  pass "BOTH scenarios PASSED — internal policy sync works for Bearer near: AND wk_ flows"
  pass "  (this means the encrypt-policy → wallet_accounts.vault_id persistence fix is live)"
elif [[ "$HTTP_A" != "200" && "$HTTP_B" == "200" ]]; then
  warn "EXPECTED PRE-FIX RESULT: Scenario A fails (indexer-path bug), B succeeds"
  warn "  Bearer near: wallets' policies aren't synced by indexer until the fix lands"
  warn "  Run again after the encrypt-policy persistence patch."
  # Exit non-zero so CI catches the missing fix
  exit 2
else
  fail "Unexpected combination: A=HTTP $HTTP_A, B=HTTP $HTTP_B"
fi
warn "Cleanup (optional): $VAULT_ID has 0.1 NEAR locked + on-chain policy storage stake."
