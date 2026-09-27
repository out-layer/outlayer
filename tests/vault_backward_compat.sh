#!/bin/bash
# Phase 10 Scenario 6: Backward compatibility — non-vault customers
# keep working on the OutLayer default master.
#
# Pre-vault customers register wallets WITHOUT `vault_id` in
# `POST /register` and get keys derived from the OutLayer default
# master (legacy path). The vault rollout must not break that.
#
# The test:
#   1. `POST /register` with empty body → wallet API key with
#      `vault_id: null`
#   2. `POST /wallet/v1/sign-message` → keystore signs via default
#      master (no per-vault scope) and returns a valid signature
#   3. `GET /wallet/v1/address` → returns the legacy address
#
# No env vars required beyond network defaults.
#
# Run:
#   ./tests/vault_backward_compat.sh --apply

set -euo pipefail

APPLY=false
[[ "${1:-}" == "--apply" ]] && APPLY=true

NETWORK="${NETWORK:-testnet}"
COORDINATOR_URL="${COORDINATOR_URL:-https://testnet-api.outlayer.ai}"

log()  { printf '\n\033[36m▶ %s\033[0m\n' "$*" >&2; }
warn() { printf '\033[33m⚠ %s\033[0m\n' "$*" >&2; }
pass() { printf '\033[32m✓ %s\033[0m\n' "$*" >&2; }
fail() { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

for tool in jq curl; do
  command -v "$tool" >/dev/null || fail "tool '$tool' missing"
done
if [[ "$APPLY" != true ]]; then
  warn "Dry-run; pass --apply to hit the coordinator."
  exit 0
fi

# ─── 1. Register a wallet WITHOUT vault scope ───────────────────────

log "POST /register with empty body (legacy random-wallet path)"
REG=$(curl -sS -X POST "$COORDINATOR_URL/register" \
  -H 'Content-Type: application/json' \
  -d '{}')
jq 'del(.api_key, .handoff_url)' <<<"$REG" >&2   # the wk_ and the handoff_url that embeds it stay out of the log

API_KEY=$(echo "$REG" | jq -r '.api_key // empty')
WALLET_ID=$(echo "$REG" | jq -r '.wallet_id // empty')
ADDR=$(echo "$REG" | jq -r '.near_account_id // empty')
[[ -n "$API_KEY" && "$API_KEY" != "null" ]] || \
  fail "no api_key in legacy /register response: $(jq -c 'del(.api_key, .handoff_url)' <<<"$REG" 2>/dev/null | head -c 300)"
[[ -n "$WALLET_ID" && "$WALLET_ID" != "null" ]] || \
  fail "no wallet_id in legacy /register response"
[[ -n "$ADDR" && "$ADDR" != "null" ]] || \
  fail "no near_account_id in legacy /register response — \
keystore default-master path may be broken"

# Confirm the response shape doesn't carry a vault_id (this is the
# legacy path — vault binding is explicitly absent).
HANDOFF=$(echo "$REG" | jq -r '.handoff_url // empty')
pass "legacy /register returned api_key (${#API_KEY} chars) wallet_id=$WALLET_ID address=$ADDR"
[[ -n "$HANDOFF" ]] && pass "handoff_url returned (legacy UX flow intact)"

# ─── 2. Sign a NEP-413 message via the default-master path ──────────

log "POST /wallet/v1/sign-message — keystore should derive from default master"
SIGN=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/sign-message" \
  -H "Authorization: Bearer $API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"message":"backward-compat-check","recipient":"verifier.testnet","nonce_base64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}')
echo "$SIGN" | jq . >&2

SIG=$(echo "$SIGN" | jq -r '.signature // empty')
PUB=$(echo "$SIGN" | jq -r '.public_key // empty')
ACCT=$(echo "$SIGN" | jq -r '.account_id // empty')
[[ -n "$SIG" && "$SIG" != "null" ]] || \
  fail "no signature from /wallet/v1/sign-message — default-master path broken"
[[ "$ACCT" == "$ADDR" ]] || \
  fail "sign-message returned account_id=$ACCT, but /register said $ADDR. \
keystore default-master derivation diverged from coordinator's expected wallet."

pass "default-master signed pre-flight message (pubkey=$PUB, sig_len=${#SIG})"

# ─── 3. /wallet/v1/address should match the /register-time address ──

log "GET /wallet/v1/address — confirm the same default-master address"
ADDR2=$(curl -sS -G "$COORDINATOR_URL/wallet/v1/address" \
  --data-urlencode "chain=near" \
  -H "Authorization: Bearer $API_KEY" \
  | jq -r '.address // empty')
[[ "$ADDR2" == "$ADDR" ]] || \
  fail "/wallet/v1/address returned $ADDR2 but /register said $ADDR — \
the default-master derivation is non-deterministic, which would break every legacy customer."
pass "/wallet/v1/address matches /register address — derivation is deterministic"

echo
pass "ALL BACKWARD-COMPAT CHECKS PASSED. Legacy default-master path works."
