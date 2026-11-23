#!/bin/bash
# ============================================================================
# Wallet Integration Tests — Mode 1: Simple Agent (no policy)
#
# Full cycle: register → get API key → get address → withdraw → check status
#
# Prerequisites:
#   - Coordinator running on localhost:8080
#   - Keystore running on localhost:8081
#   - PostgreSQL + Redis running
# ============================================================================

set -euo pipefail

COORDINATOR_URL="${COORDINATOR_URL:-http://localhost:8080}"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

PASSED=0
FAILED=0
SKIPPED=0
TOTAL=0

# ============================================================================
# Helpers
# ============================================================================

# Mark a test as skipped (counts toward TOTAL but is not a failure). Used
# for assertions that need on-chain funds the suite can't provision itself.
skip_test() {
    local test_name="$1"
    local reason="$2"
    TOTAL=$((TOTAL + 1))
    SKIPPED=$((SKIPPED + 1))
    echo -e "  ${YELLOW}SKIP${NC} $test_name ($reason)"
}

assert_status() {
    local expected="$1"
    local actual="$2"
    local test_name="$3"
    TOTAL=$((TOTAL + 1))
    if [ "$actual" = "$expected" ]; then
        echo -e "  ${GREEN}PASS${NC} $test_name (HTTP $actual)"
        PASSED=$((PASSED + 1))
    else
        echo -e "  ${RED}FAIL${NC} $test_name (expected HTTP $expected, got $actual)"
        FAILED=$((FAILED + 1))
    fi
}

assert_json_field() {
    local json="$1"
    local field="$2"
    local expected="$3"
    local test_name="$4"
    TOTAL=$((TOTAL + 1))
    local actual
    actual=$(echo "$json" | jq -r "$field" 2>/dev/null || echo "PARSE_ERROR")
    if [ "$actual" = "$expected" ]; then
        echo -e "  ${GREEN}PASS${NC} $test_name ($field = $actual)"
        PASSED=$((PASSED + 1))
    else
        echo -e "  ${RED}FAIL${NC} $test_name ($field: expected '$expected', got '$actual')"
        FAILED=$((FAILED + 1))
    fi
}

assert_json_not_empty() {
    local json="$1"
    local field="$2"
    local test_name="$3"
    TOTAL=$((TOTAL + 1))
    local actual
    actual=$(echo "$json" | jq -r "$field" 2>/dev/null || echo "")
    if [ -n "$actual" ] && [ "$actual" != "null" ] && [ "$actual" != "" ]; then
        echo -e "  ${GREEN}PASS${NC} $test_name ($field = ${actual:0:40}...)"
        PASSED=$((PASSED + 1))
    else
        echo -e "  ${RED}FAIL${NC} $test_name ($field is empty or null)"
        FAILED=$((FAILED + 1))
    fi
}

# Build curl with API key for GET requests
curl_get() {
    local path="$1"
    curl -s -w "\n%{http_code}" \
        -H @<(printf '%s\n' "Authorization: Bearer $API_KEY") \
        "${COORDINATOR_URL}${path}"
}

# Build curl with API key for POST requests
curl_post() {
    local path="$1"
    local body="$2"
    local idem_key="${3:-}"
    local extra_headers=()
    if [ -n "$idem_key" ]; then
        extra_headers+=(-H "X-Idempotency-Key: $idem_key")
    fi
    curl -s -w "\n%{http_code}" \
        -X POST \
        -H "Content-Type: application/json" \
        -H @<(printf '%s\n' "Authorization: Bearer $API_KEY") \
        ${extra_headers[@]+"${extra_headers[@]}"} \
        -d "$body" \
        "${COORDINATOR_URL}${path}"
}

# Parse response: last line = HTTP code, rest = body
parse_response() {
    local response="$1"
    RESP_BODY=$(echo "$response" | sed '$d')
    RESP_CODE=$(echo "$response" | tail -1)
}

# ============================================================================
# Setup: Register wallet
# ============================================================================

echo ""
echo "============================================="
echo " Wallet Mode 1: Simple Agent (no policy)"
echo "============================================="
echo ""

if ! curl -s "${COORDINATOR_URL}/health" > /dev/null 2>&1; then
    echo -e "${RED}ERROR: Coordinator not running at ${COORDINATOR_URL}${NC}"
    exit 1
fi

echo "Registering new wallet..."
REGISTER_RESP=$(curl -s -w "\n%{http_code}" -X POST "${COORDINATOR_URL}/register")
parse_response "$REGISTER_RESP"
assert_status "200" "$RESP_CODE" "POST /register"
assert_json_not_empty "$RESP_BODY" ".api_key" "api_key present"
assert_json_not_empty "$RESP_BODY" ".wallet_id" "wallet_id present"
assert_json_not_empty "$RESP_BODY" ".handoff_url" "handoff_url present"
API_KEY=$(echo "$RESP_BODY" | jq -r '.api_key')
WALLET_ID=$(echo "$RESP_BODY" | jq -r '.wallet_id')
echo "  Wallet ID: $WALLET_ID"
echo "  API Key: ${API_KEY:0:10}..."
echo ""

# ============================================================================
# Test 1: Get NEAR address
# ============================================================================

echo "1. Get NEAR address"
parse_response "$(curl_get "/wallet/v1/address?chain=near")"
assert_status "200" "$RESP_CODE" "GET /address?chain=near"
assert_json_not_empty "$RESP_BODY" ".address" "address present"
NEAR_ADDRESS=$(echo "$RESP_BODY" | jq -r '.address')
echo ""

# Funding precheck — the withdraw tests (5,6,7,8,15) need on-chain funds.
# A freshly registered wallet has 0 balance, so gate those on real funding
# (NEAR or Intents) and SKIP them otherwise instead of reporting false
# failures. Fund $NEAR_ADDRESS on testnet to exercise the full flow.
parse_response "$(curl_get "/wallet/v1/balance?chain=near")"
NEAR_BAL=$(echo "$RESP_BODY" | jq -r '.balance // "0"')
parse_response "$(curl_get "/wallet/v1/balance?chain=near&source=intents&token=nep141:wrap.testnet")"
INTENTS_BAL=$(echo "$RESP_BODY" | jq -r '.balance // "0"')
FUNDED=false
if { [ -n "$NEAR_BAL" ] && [ "$NEAR_BAL" != "0" ] && [ "$NEAR_BAL" != "null" ]; } \
   || { [ -n "$INTENTS_BAL" ] && [ "$INTENTS_BAL" != "0" ] && [ "$INTENTS_BAL" != "null" ]; }; then
    FUNDED=true
fi
echo "  Balance check: near=$NEAR_BAL intents(wrap.testnet)=$INTENTS_BAL → funded=$FUNDED"
if [ "$FUNDED" != true ]; then
    echo -e "  ${YELLOW}NOTE${NC}: wallet unfunded — withdraw tests (5-8,15) will SKIP. Fund $NEAR_ADDRESS to run them."
fi
echo ""

# ============================================================================
# Test 2: Get Ethereum address
# ============================================================================

echo "2. Get Ethereum address (EVM now supported → 200; one 0x address across all EVM chains)"
parse_response "$(curl_get "/wallet/v1/address?chain=ethereum")"
assert_status "200" "$RESP_CODE" "GET /address?chain=ethereum"
EVM_ADDR=$(echo "$RESP_BODY" | jq -r '.address' 2>/dev/null || echo "PARSE_ERROR")
TOTAL=$((TOTAL + 1))
if [[ "$EVM_ADDR" =~ ^0x[0-9a-fA-F]{40}$ ]]; then
    echo -e "  ${GREEN}PASS${NC} ethereum address is a 0x EOA ($EVM_ADDR)"
    PASSED=$((PASSED + 1))
else
    echo -e "  ${RED}FAIL${NC} ethereum address is not a 0x EOA (got '$EVM_ADDR')"
    FAILED=$((FAILED + 1))
fi
# All EVM chains share ONE derived secp256k1 address.
parse_response "$(curl_get "/wallet/v1/address?chain=polygon")"
assert_status "200" "$RESP_CODE" "GET /address?chain=polygon"
assert_json_field "$RESP_BODY" ".address" "$EVM_ADDR" "polygon address == ethereum address (one EVM address)"
echo ""

# ============================================================================
# Test 3: Unsupported chain
# ============================================================================

echo "3. Unsupported chains (bitcoin + solana still gated)"
parse_response "$(curl_get "/wallet/v1/address?chain=bitcoin")"
assert_status "400" "$RESP_CODE" "GET /address?chain=bitcoin"
assert_json_field "$RESP_BODY" ".error" "unsupported_chain" "error code"
parse_response "$(curl_get "/wallet/v1/address?chain=solana")"
assert_status "400" "$RESP_CODE" "GET /address?chain=solana (no signing path yet)"
echo ""

# ============================================================================
# Test 4: List tokens
# ============================================================================

echo "4. List tokens"
parse_response "$(curl_get "/wallet/v1/tokens")"
assert_status "200" "$RESP_CODE" "GET /tokens"
echo ""

# ============================================================================
# Test 5: Withdraw dry-run (no policy = should succeed)
# ============================================================================

echo "5. Withdraw dry-run (no policy)"
DRY_RUN_BODY='{"chain":"near","to":"recipient.near","amount":"1000000000000000000000000"}'
parse_response "$(curl_post "/wallet/v1/intents/withdraw/dry-run" "$DRY_RUN_BODY" "dry-run-$(date +%s)")"
# The endpoint always returns 200; `would_succeed` reflects balance, so the
# success assertion only holds for a funded wallet.
assert_status "200" "$RESP_CODE" "POST /withdraw/dry-run"
if [ "$FUNDED" = true ]; then
    assert_json_field "$RESP_BODY" ".would_succeed" "true" "would_succeed=true (no policy)"
else
    skip_test "would_succeed=true (no policy)" "wallet unfunded — would_succeed reflects 0 balance"
fi
echo ""

# ============================================================================
# Test 6: Withdraw (with idempotency key)
# ============================================================================

echo "6. Withdraw"
IDEM_KEY="agent-test-$(date +%s%N)"
WITHDRAW_BODY='{"chain":"near","to":"recipient.near","amount":"1000000000000000000000000"}'
REQUEST_ID=""
if [ "$FUNDED" = true ]; then
    parse_response "$(curl_post "/wallet/v1/intents/withdraw" "$WITHDRAW_BODY" "$IDEM_KEY")"
    assert_status "200" "$RESP_CODE" "POST /withdraw"
    assert_json_not_empty "$RESP_BODY" ".request_id" "request_id present"
    REQUEST_ID=$(echo "$RESP_BODY" | jq -r '.request_id')
    WITHDRAW_STATUS=$(echo "$RESP_BODY" | jq -r '.status')
    echo "  request_id=$REQUEST_ID status=$WITHDRAW_STATUS"
else
    skip_test "POST /withdraw" "wallet unfunded (would return insufficient_balance)"
    skip_test "request_id present" "wallet unfunded"
fi
echo ""

# ============================================================================
# Test 7: Idempotent duplicate (same key = same result)
# ============================================================================

echo "7. Idempotent duplicate"
if [ "$FUNDED" = true ]; then
    parse_response "$(curl_post "/wallet/v1/intents/withdraw" "$WITHDRAW_BODY" "$IDEM_KEY")"
    assert_status "200" "$RESP_CODE" "POST /withdraw (duplicate idempotency key)"
    assert_json_field "$RESP_BODY" ".error" "duplicate_idempotency_key" "duplicate detected"
else
    skip_test "POST /withdraw (duplicate idempotency key)" "wallet unfunded — no original request to dedupe"
    skip_test "duplicate detected" "wallet unfunded"
fi
echo ""

# ============================================================================
# Test 8: Get request status
# ============================================================================

echo "8. Get request status"
if [ -n "$REQUEST_ID" ] && [ "$REQUEST_ID" != "null" ]; then
    parse_response "$(curl_get "/wallet/v1/requests/$REQUEST_ID")"
    assert_status "200" "$RESP_CODE" "GET /requests/{id}"
    assert_json_field "$RESP_BODY" ".request_id" "$REQUEST_ID" "matching request_id"
else
    skip_test "GET /requests/{id}" "no request created (wallet unfunded)"
    skip_test "matching request_id" "no request created (wallet unfunded)"
fi
echo ""

# ============================================================================
# Test 9: List requests
# ============================================================================

echo "9. List requests"
parse_response "$(curl_get "/wallet/v1/requests")"
assert_status "200" "$RESP_CODE" "GET /requests"
echo ""

# ============================================================================
# Test 10: Get policy (should be empty — no policy set)
# ============================================================================

echo "10. Get policy (no policy set)"
parse_response "$(curl_get "/wallet/v1/policy")"
assert_status "200" "$RESP_CODE" "GET /policy"
echo ""

# ============================================================================
# Test 11: Get audit log
# ============================================================================

echo "11. Get audit log"
parse_response "$(curl_get "/wallet/v1/audit")"
assert_status "200" "$RESP_CODE" "GET /audit"
echo ""

# ============================================================================
# Test 12: Deposit
# ============================================================================

echo "12. Deposit address"
# There is no POST /wallet/v1/deposit endpoint — a NEAR custody wallet
# receives funds at its own implicit account, which is the address returned
# by GET /address. (Cross-chain bridging is a separate /deposit-intent flow.)
parse_response "$(curl_get "/wallet/v1/address?chain=near")"
assert_status "200" "$RESP_CODE" "GET /address?chain=near (deposit target)"
assert_json_not_empty "$RESP_BODY" ".address" "deposit address present"
echo ""

# ============================================================================
# Test 13: Missing auth headers → 401 with helpful message
# ============================================================================

echo "13. Missing auth headers"
RESP=$(curl -s -w "\n%{http_code}" "${COORDINATOR_URL}/wallet/v1/address?chain=near")
parse_response "$RESP"
assert_status "401" "$RESP_CODE" "no auth headers -> 401"
assert_json_field "$RESP_BODY" ".error" "missing_auth" "error=missing_auth"
echo ""

# ============================================================================
# Test 14: Invalid API key
# ============================================================================

echo "14. Invalid API key"
RESP=$(curl -s -w "\n%{http_code}" \
    -H "Authorization: Bearer wk_invalid_key_that_does_not_exist" \
    "${COORDINATOR_URL}/wallet/v1/address?chain=near")
parse_response "$RESP"
assert_status "401" "$RESP_CODE" "bad api key -> 401"
assert_json_field "$RESP_BODY" ".error" "invalid_api_key" "error=invalid_api_key"
echo ""

# ============================================================================
# Test 15: Missing idempotency key on POST
# ============================================================================

echo "15. Missing idempotency key (server auto-generates one → request proceeds)"
if [ "$FUNDED" = true ]; then
    parse_response "$(curl_post "/wallet/v1/intents/withdraw" "$WITHDRAW_BODY" "")"
    assert_status "200" "$RESP_CODE" "no idempotency key -> 200 (auto-generated)"
else
    skip_test "no idempotency key -> 200 (auto-generated)" "wallet unfunded — withdraw needs balance regardless of key"
fi
echo ""

# ============================================================================
# Test 16: Invalidate cache
# ============================================================================

echo "16. Invalidate cache"
CACHE_BODY="{\"wallet_id\":\"$WALLET_ID\"}"
RESP=$(curl -s -w "\n%{http_code}" -X POST \
    -H "Content-Type: application/json" \
    -d "$CACHE_BODY" \
    "${COORDINATOR_URL}/wallet/v1/invalidate-cache")
parse_response "$RESP"
assert_status "200" "$RESP_CODE" "POST /invalidate-cache"
echo ""

# ============================================================================
# Test 17: Internal wallet-check (simulating worker)
# ============================================================================

echo "17. Internal wallet-check (requires X-Internal-Wallet-Auth → 401 without it)"
RESP=$(curl -s -w "\n%{http_code}" \
    "${COORDINATOR_URL}/internal/wallet-check?wallet_id=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$WALLET_ID'))")")
parse_response "$RESP"
assert_status "401" "$RESP_CODE" "GET /internal/wallet-check (no auth → 401)"
echo ""

# Tests 18-21: API key management endpoints (not yet implemented)
# TODO: uncomment when /wallet/v1/api-keys is implemented

# ============================================================================
# Summary
# ============================================================================

echo "============================================="
echo "Results: $PASSED/$TOTAL passed, $FAILED failed, $SKIPPED skipped"
if [ "$SKIPPED" -gt 0 ]; then
    echo -e "${YELLOW}$SKIPPED test(s) skipped — fund the wallet to exercise the withdraw flow${NC}"
fi
if [ "$FAILED" -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
else
    echo -e "${RED}$FAILED test(s) failed${NC}"
    exit 1
fi
echo ""
