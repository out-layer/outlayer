#!/bin/bash
# ============================================================================
# Wallet Integration Tests — EVM signing (sign-typed-data / sign-message /
# sign-transaction)
#
# Exercises the EVM signing surface end-to-end (coordinator → keystore) with a
# fresh, UNFUNDED wallet — no on-chain funds, no broadcast, read/sign only:
#   1. one shared EVM address across all EVM chains (ethereum == polygon == base)
#   2. POST /wallet/v1/evm/sign-typed-data  (EIP-712 v4) → a 65-byte r‖s‖v sig
#   3. POST /wallet/v1/evm/sign-message     (EIP-191)    → a 65-byte r‖s‖v sig
#   4. POST /wallet/v1/evm/sign-transaction (raw tx)     → a 65-byte r‖s‖v sig
#      (a no-policy wallet is unrestricted, so raw-tx is allowed here)
#   Each signature is checked against the wallet's own address: ecrecover over the EIP-712
#   digest, the EIP-191 digest and keccak256 of the unsigned typed tx must give the address of
#   test 1, and the same signature over a changed payload must not (tests/lib/sig_verify.py).
#
# NOT covered here (covered elsewhere, no extra infra needed):
#   - evm_sign / evm_sign.raw_tx capability GATING — proven by the
#     shared-tee-helpers unit test
#     wallet_policy.rs::evm_sign_capability_defaults_and_raw_tx_subflag.
#     (An end-to-end gating check needs an on-chain policy, which needs a
#     funded wallet; gated/SKIPped like the other policy tests.)
#
# Prerequisites:
#   - Coordinator running on localhost:8080
#   - Keystore running on localhost:8081
#   - Keystore configured with a reachable NEAR RPC. The three sign endpoints
#     (tests 2-4) read the wallet's on-chain policy via load_wallet_policy even
#     for a no-policy wallet, so without RPC they return 503 (not a signing bug).
#     Test 1 (address derivation) is pure key derivation and needs no RPC.
# ============================================================================

set -euo pipefail

COORDINATOR_URL="${COORDINATOR_URL:-http://localhost:8080}"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

PASSED=0
FAILED=0
SKIPPED=0
TOTAL=0

# ============================================================================
# Helpers (mirror tests/wallet_mode1_agent.sh)
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

# A valid EVM signature is 0x + 130 hex chars (r‖s‖v = 65 bytes) with v=0x1b/0x1c.
assert_evm_sig() {
    local sig="$1" name="$2"
    TOTAL=$((TOTAL + 1))
    if [[ "$sig" =~ ^0x[0-9a-fA-F]{130}$ ]]; then
        local v="${sig: -2}"
        if [ "$v" = "1b" ] || [ "$v" = "1c" ]; then
            echo -e "  ${GREEN}PASS${NC} $name (65-byte r‖s‖v, v=0x$v)"
            PASSED=$((PASSED + 1))
        else
            echo -e "  ${RED}FAIL${NC} $name (v must be 0x1b/0x1c, got 0x$v)"
            FAILED=$((FAILED + 1))
        fi
    else
        echo -e "  ${RED}FAIL${NC} $name (not 0x + 130 hex: ${sig:0:24}...)"
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
echo "============================================="
echo " Wallet: EVM signing (EIP-712 / EIP-191 / tx)"
echo "============================================="
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
# Test 1: one shared EVM address across all EVM chains
# ============================================================================

echo "1. EVM address derivation (one 0x address across all EVM chains)"
parse_response "$(curl_get "/wallet/v1/address?chain=ethereum")"
assert_status "200" "$RESP_CODE" "GET /address?chain=ethereum"
EVM_ADDR=$(echo "$RESP_BODY" | jq -r '.address')
TOTAL=$((TOTAL + 1))
if [[ "$EVM_ADDR" =~ ^0x[0-9a-fA-F]{40}$ ]]; then
    echo -e "  ${GREEN}PASS${NC} ethereum address is a 0x EOA ($EVM_ADDR)"
    PASSED=$((PASSED + 1))
else
    echo -e "  ${RED}FAIL${NC} ethereum address is not a 0x EOA (got '$EVM_ADDR')"
    FAILED=$((FAILED + 1))
fi
parse_response "$(curl_get "/wallet/v1/address?chain=polygon")"
assert_status "200" "$RESP_CODE" "GET /address?chain=polygon"
assert_equals "$EVM_ADDR" "$(echo "$RESP_BODY" | jq -r '.address')" "polygon address == ethereum address"
parse_response "$(curl_get "/wallet/v1/address?chain=base")"
assert_status "200" "$RESP_CODE" "GET /address?chain=base"
assert_equals "$EVM_ADDR" "$(echo "$RESP_BODY" | jq -r '.address')" "base address == ethereum address"
echo ""

# ============================================================================
# Test 2: sign EIP-712 typed data (the canonical "Mail" example)
# ============================================================================

echo "2. POST /wallet/v1/evm/sign-typed-data (EIP-712 v4)"
TYPED_BODY='{
  "chain": "polygon",
  "typed_data": {
    "domain": { "name": "Ether Mail", "version": "1", "chainId": 137, "verifyingContract": "0xcccccccccccccccccccccccccccccccccccccccc" },
    "types": {
      "EIP712Domain": [ {"name":"name","type":"string"}, {"name":"version","type":"string"}, {"name":"chainId","type":"uint256"}, {"name":"verifyingContract","type":"address"} ],
      "Person": [ {"name":"name","type":"string"}, {"name":"wallet","type":"address"} ],
      "Mail": [ {"name":"from","type":"Person"}, {"name":"to","type":"Person"}, {"name":"contents","type":"string"} ]
    },
    "primaryType": "Mail",
    "message": {
      "from": { "name": "Cow", "wallet": "0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826" },
      "to": { "name": "Bob", "wallet": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" },
      "contents": "Hello, Bob!"
    }
  }
}'
parse_response "$(curl_post "/wallet/v1/evm/sign-typed-data" "$TYPED_BODY")"
assert_status "200" "$RESP_CODE" "POST /evm/sign-typed-data"
SIG=$(echo "$RESP_BODY" | jq -r '.signature')
assert_evm_sig "$SIG" "EIP-712 signature shape"
assert_signed_by eip712 "$EVM_ADDR" "$SIG" "$(jq -c '.typed_data' <<<"$TYPED_BODY")" \
    "$(jq -c '.typed_data.message.contents = "Hello, Eve!"' <<<"$TYPED_BODY")" "EIP-712 signature is the wallet's"
echo ""

# ============================================================================
# Test 3: sign EIP-191 personal_sign message
# ============================================================================

echo "3. POST /wallet/v1/evm/sign-message (EIP-191)"
parse_response "$(curl_post "/wallet/v1/evm/sign-message" '{"chain":"polygon","message":"Sign in to Polymarket"}')"
assert_status "200" "$RESP_CODE" "POST /evm/sign-message"
SIG=$(echo "$RESP_BODY" | jq -r '.signature')
assert_evm_sig "$SIG" "EIP-191 signature shape"
assert_signed_by eip191 "$EVM_ADDR" "$SIG" "Sign in to Polymarket" "Sign in to Polymarket!" "EIP-191 signature is the wallet's"
echo ""

# ============================================================================
# Test 4: sign a raw EVM transaction (no-policy wallet ⇒ unrestricted)
# ============================================================================

echo "4. POST /wallet/v1/evm/sign-transaction (serialized unsigned EIP-1559 tx)"
# 0x02 ‖ rlp(chainId, nonce, maxPrio, maxFee, gas, to, value, data, accessList[])
UNSIGNED_TX="0x02f86c0180843b9aca00851bf08eb00082520894abababababababababababababababababababab880de0b6b3a764000080c0"
# Build the body in a variable (printf) so the `{...,...}` literal can't undergo
# bash brace/word-splitting — same safe pattern as the typed-data body above.
TX_BODY=$(printf '{"chain":"polygon","unsigned_tx":"%s"}' "$UNSIGNED_TX")
parse_response "$(curl_post "/wallet/v1/evm/sign-transaction" "$TX_BODY")"
assert_status "200" "$RESP_CODE" "POST /evm/sign-transaction (no policy ⇒ raw-tx unrestricted)"
SIG=$(echo "$RESP_BODY" | jq -r '.signature')
assert_evm_sig "$SIG" "raw-tx signature shape"
assert_signed_by evmtx "$EVM_ADDR" "$SIG" "$UNSIGNED_TX" "${UNSIGNED_TX%c0}c1" "raw-tx signature is the wallet's"
echo ""

# Capability gating (evm_sign disabled / raw_tx default-OFF) requires an
# on-chain policy → a funded wallet. Logic is unit-tested in shared-tee-helpers
# (evm_sign_capability_defaults_and_raw_tx_subflag); skip the on-chain leg here.
TOTAL=$((TOTAL + 1)); SKIPPED=$((SKIPPED + 1))
echo -e "  ${YELLOW}SKIP${NC} evm_sign/raw_tx gating e2e (needs a funded wallet to store a policy; logic is unit-tested)"
echo ""

# ============================================================================
# Results
# ============================================================================

echo "============================================="
echo -e " Results: ${GREEN}${PASSED} passed${NC}, ${RED}${FAILED} failed${NC}, ${YELLOW}${SKIPPED} skipped${NC} (${TOTAL} total)"
echo "============================================="
[ "$FAILED" -eq 0 ]
