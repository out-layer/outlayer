#!/bin/bash
# ============================================================================
# Wallet Integration Tests — Solana signing (sign-message / sign-transaction)
#
# Exercises the Solana signing surface end-to-end (coordinator → keystore) with
# a fresh, UNFUNDED wallet — no on-chain funds, no broadcast, read/sign only:
#   1. base58 ed25519 address; alias `sol` == canonical `solana` address
#   2. POST /wallet/v1/solana/sign-message (utf8 + hex) → 64-byte base58 sig;
#      response `chain` is canonicalized to `solana` even for alias requests
#   3. message/transaction guard: a valid serialized tx message sent to
#      sign-message is REJECTED (400) — the raw_tx bypass protection
#   4. POST /wallet/v1/solana/sign-transaction with the same bytes → 64-byte
#      base58 sig (a no-policy wallet is unrestricted, so raw-tx is allowed)
#
#   Each signature is checked against the wallet's own address: ed25519 over the exact message
#   bytes with the key test 1 returned, and the same signature over changed bytes must not
#   verify (tests/lib/sig_verify.py).
#
# NOT covered here (covered elsewhere, no extra infra needed):
#   - solana_sign / solana_sign.raw_tx capability GATING — proven by the
#     shared-tee-helpers unit test
#     wallet_policy.rs::solana_sign_capability_defaults_and_raw_tx_subflag.
#     (An end-to-end gating check needs an on-chain policy, which needs a
#     funded wallet; gated/SKIPped like the other policy tests.)
#
# Prerequisites:
#   - Coordinator reachable at COORDINATOR_URL (default: mainnet
#     https://api.outlayer.ai; override for testnet/local, e.g.
#     COORDINATOR_URL=http://localhost:8080 ./tests/wallet_solana_sign_e2e.sh)
#   - Keystore running behind that coordinator
#   - Keystore configured with a reachable NEAR RPC. The sign endpoints
#     (tests 2-4) read the wallet's on-chain policy via load_wallet_policy even
#     for a no-policy wallet, so without RPC they return 503 (not a signing bug).
#     Test 1 (address derivation) is pure key derivation and needs no RPC.
#   - python3 (base58 length checks + tx-message construction; stdlib only)
# ============================================================================

set -euo pipefail

COORDINATOR_URL="${COORDINATOR_URL:-https://api.outlayer.ai}"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

PASSED=0
FAILED=0
SKIPPED=0
TOTAL=0

# ============================================================================
# Helpers (mirror tests/wallet_evm_sign_e2e.sh)
# ============================================================================

assert_status() {
    local expected="$1" actual="$2" name="$3"
    TOTAL=$((TOTAL + 1))
    if [ "$actual" = "$expected" ]; then
        echo -e "  ${GREEN}PASS${NC} $name (HTTP $actual)"
        PASSED=$((PASSED + 1))
    else
        echo -e "  ${RED}FAIL${NC} $name (expected HTTP $expected, got $actual)"
        FAILED=$((FAILED + 1))
    fi
}

assert_equals() {
    local expected="$1" actual="$2" name="$3"
    TOTAL=$((TOTAL + 1))
    if [ "$expected" = "$actual" ]; then
        echo -e "  ${GREEN}PASS${NC} $name ($actual)"
        PASSED=$((PASSED + 1))
    else
        echo -e "  ${RED}FAIL${NC} $name (expected '$expected', got '$actual')"
        FAILED=$((FAILED + 1))
    fi
}

# Decoded byte length of a base58 string (0 on invalid chars). stdlib only.
b58_len() {
    python3 - "$1" <<'PY'
import sys
ALPH = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
s = sys.argv[1]
try:
    n = 0
    for ch in s:
        n = n * 58 + ALPH.index(ch)
except ValueError:
    print(0); sys.exit()
body = n.to_bytes((n.bit_length() + 7) // 8, 'big') if n else b''
pad = len(s) - len(s.lstrip('1'))
print(pad + len(body))
PY
}

# A valid Solana signature is base58 decoding to exactly 64 bytes.
assert_solana_sig() {
    local sig="$1" name="$2"
    TOTAL=$((TOTAL + 1))
    local n
    n=$(b58_len "$sig")
    if [ "$n" = "64" ]; then
        echo -e "  ${GREEN}PASS${NC} $name (64-byte base58 ed25519 sig)"
        PASSED=$((PASSED + 1))
    else
        echo -e "  ${RED}FAIL${NC} $name (base58 decodes to $n bytes, want 64: ${sig:0:24}...)"
        FAILED=$((FAILED + 1))
    fi
}

# assert_signed_by <kind> <address> <signature> <payload> <changed-payload> <name>: the signature
# is the wallet's own — it recovers (EVM) or verifies (ed25519) to <address> over <payload>
# (tests/lib/sig_verify.py) — and the same signature over <changed-payload> is NOT, so a check
# that passes anything cannot pass here.
SIG_VERIFY="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/sig_verify.py"
assert_signed_by() {
    local kind="$1" addr="$2" sig="$3" payload="$4" changed="$5" name="$6" out
    TOTAL=$((TOTAL + 1))
    if ! out=$(python3 -I "$SIG_VERIFY" "$kind" "$addr" "$sig" "$payload" 2>&1); then
        echo -e "  ${RED}FAIL${NC} $name — not the wallet's signature: $out"
        FAILED=$((FAILED + 1))
    elif python3 -I "$SIG_VERIFY" "$kind" "$addr" "$sig" "$changed" >/dev/null 2>&1; then
        echo -e "  ${RED}FAIL${NC} $name — the check passed a changed payload too: it proves nothing"
        FAILED=$((FAILED + 1))
    else
        echo -e "  ${GREEN}PASS${NC} $name ($out; a changed payload does not verify)"
        PASSED=$((PASSED + 1))
    fi
}

curl_get() {
    curl -s -w "\n%{http_code}" -H "Authorization: Bearer $API_KEY" "${COORDINATOR_URL}$1"
}

curl_post() {
    curl -s -w "\n%{http_code}" -X POST -H "Content-Type: application/json" \
        -H "Authorization: Bearer $API_KEY" -d "$2" "${COORDINATOR_URL}$1"
}

parse_response() {
    RESP_BODY=$(echo "$1" | sed '$d')
    RESP_CODE=$(echo "$1" | tail -1)
}

# ============================================================================
# Setup
# ============================================================================

echo ""
echo "==============================================="
echo " Wallet: Solana signing (message / transaction)"
echo "==============================================="
echo ""

if ! curl -s "${COORDINATOR_URL}/health" > /dev/null 2>&1; then
    echo -e "${RED}ERROR: Coordinator not running at ${COORDINATOR_URL}${NC}"
    exit 1
fi

echo "Registering new wallet..."
parse_response "$(curl -s -w "\n%{http_code}" -X POST "${COORDINATOR_URL}/register")"
assert_status "200" "$RESP_CODE" "POST /register"
API_KEY=$(echo "$RESP_BODY" | jq -r '.api_key')
WALLET_ID=$(echo "$RESP_BODY" | jq -r '.wallet_id')
echo "  Wallet ID: $WALLET_ID"
echo ""

# ============================================================================
# Test 1: base58 ed25519 address; `sol` alias == canonical `solana`
# ============================================================================

echo "1. Solana address derivation (base58 ed25519; alias canonicalization)"
parse_response "$(curl_get "/wallet/v1/address?chain=solana")"
assert_status "200" "$RESP_CODE" "GET /address?chain=solana"
SOL_ADDR=$(echo "$RESP_BODY" | jq -r '.address')
TOTAL=$((TOTAL + 1))
if [ "$(b58_len "$SOL_ADDR")" = "32" ]; then
    echo -e "  ${GREEN}PASS${NC} solana address is a 32-byte base58 pubkey ($SOL_ADDR)"
    PASSED=$((PASSED + 1))
else
    echo -e "  ${RED}FAIL${NC} solana address is not a 32-byte base58 pubkey (got '$SOL_ADDR')"
    FAILED=$((FAILED + 1))
fi
parse_response "$(curl_get "/wallet/v1/address?chain=sol")"
assert_status "200" "$RESP_CODE" "GET /address?chain=sol"
assert_equals "$SOL_ADDR" "$(echo "$RESP_BODY" | jq -r '.address')" "sol alias address == solana address"
echo ""

# ============================================================================
# Test 2: sign-message (utf8 + hex + canonical chain echo + bad encoding)
# ============================================================================

echo "2. POST /wallet/v1/solana/sign-message"
SIWS_MSG="example.com wants you to sign in with your Solana account:\n${SOL_ADDR}\n\nSign in to Example\n\nVersion: 1\nNonce: deadbeef01"
MSG_BODY=$(printf '{"chain":"solana","message":"%s"}' "$SIWS_MSG")
parse_response "$(curl_post "/wallet/v1/solana/sign-message" "$MSG_BODY")"
assert_status "200" "$RESP_CODE" "POST /solana/sign-message (utf8)"
SIG=$(echo "$RESP_BODY" | jq -r '.signature')
assert_solana_sig "$SIG" "utf8 message signature shape"
MSG_HEX=$(jq -j '.message' <<<"$MSG_BODY" | xxd -p | tr -d '\n')
assert_signed_by solana "$SOL_ADDR" "$SIG" "$MSG_HEX" "${MSG_HEX}00" "utf8 message signature is the wallet's"

# Alias request: response `chain` must be canonicalized to `solana`.
parse_response "$(curl_post "/wallet/v1/solana/sign-message" '{"chain":"sol","message":"deadbeef","encoding":"hex"}')"
assert_status "200" "$RESP_CODE" "POST /solana/sign-message (hex, chain=sol)"
SIG=$(echo "$RESP_BODY" | jq -r '.signature')
assert_solana_sig "$SIG" "hex message signature shape"
assert_signed_by solana "$SOL_ADDR" "$SIG" "deadbeef" "deadbeee" "hex message signature is the wallet's"
assert_equals "solana" "$(echo "$RESP_BODY" | jq -r '.chain')" "response chain canonicalized (sol → solana)"

# Unknown encoding must be rejected, not sniffed.
parse_response "$(curl_post "/wallet/v1/solana/sign-message" '{"chain":"solana","message":"hi","encoding":"base58"}')"
assert_status "400" "$RESP_CODE" "POST /solana/sign-message (encoding=base58 rejected)"
echo ""

# ============================================================================
# Test 3+4: the message/transaction guard, then real transaction signing
# ============================================================================

# A minimal VALID legacy Solana transaction message (1 signer, 2 static keys,
# 1 instruction) — structurally broadcastable, hand-built with stdlib only.
TX_MSG_B64=$(python3 - <<'PY'
import base64
msg  = bytes([1, 0, 1])          # header: 1 required sig, 0 ro-signed, 1 ro-unsigned
msg += bytes([2])                # 2 static account keys (compact-u16)
msg += bytes(32)                 # key 0: fee payer
msg += bytes(range(32))          # key 1: program
msg += bytes([7]) * 32           # recent blockhash
msg += bytes([1])                # 1 instruction (compact-u16)
msg += bytes([1])                # program_id_index = 1
msg += bytes([1, 0])             # 1 account index: [0]
msg += bytes([4]) + b'\x02\x00\x00\x00'  # 4-byte instruction data
print(base64.b64encode(msg).decode())
PY
)

echo "3. Guard: a valid tx message must be REJECTED by sign-message"
GUARD_BODY=$(printf '{"chain":"solana","message":"%s","encoding":"base64"}' "$TX_MSG_B64")
parse_response "$(curl_post "/wallet/v1/solana/sign-message" "$GUARD_BODY")"
assert_status "400" "$RESP_CODE" "sign-message(tx bytes) rejected — raw_tx bypass closed"
echo ""

echo "4. POST /wallet/v1/solana/sign-transaction (same bytes, no-policy wallet)"
TX_BODY=$(printf '{"chain":"solana","unsigned_tx":"%s"}' "$TX_MSG_B64")
parse_response "$(curl_post "/wallet/v1/solana/sign-transaction" "$TX_BODY")"
assert_status "200" "$RESP_CODE" "POST /solana/sign-transaction (no policy ⇒ raw-tx unrestricted)"
SIG=$(echo "$RESP_BODY" | jq -r '.signature')
assert_solana_sig "$SIG" "tx signature shape"
TX_HEX=$(base64 -d <<<"$TX_MSG_B64" | xxd -p | tr -d '\n')
assert_signed_by solana "$SOL_ADDR" "$SIG" "$TX_HEX" "${TX_HEX%00}01" "tx signature is the wallet's (over the message bytes)"
echo ""

# Capability gating (solana_sign disabled / raw_tx default-OFF) requires an
# on-chain policy → a funded wallet. Logic is unit-tested in shared-tee-helpers
# (solana_sign_capability_defaults_and_raw_tx_subflag); skip the on-chain leg here.
TOTAL=$((TOTAL + 1)); SKIPPED=$((SKIPPED + 1))
echo -e "  ${YELLOW}SKIP${NC} solana_sign/raw_tx gating e2e (needs a funded wallet to store a policy; logic is unit-tested)"
echo ""

# ============================================================================
# Results
# ============================================================================

echo "============================================="
echo -e " Results: ${GREEN}${PASSED} passed${NC}, ${RED}${FAILED} failed${NC}, ${YELLOW}${SKIPPED} skipped${NC} (${TOTAL} total)"
echo "============================================="
[ "$FAILED" -eq 0 ]
