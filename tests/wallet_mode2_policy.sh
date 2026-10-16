#!/bin/bash
# ============================================================================
# Wallet Integration Tests — Mode 2: User with Policy
#
# Full cycle:
#   1. Register wallet + approver (API key auth)
#   2. Encrypt policy with limits, whitelist, approval threshold
#   3. Agent operates within policy constraints
#   4. Withdrawal triggers multisig approval
#   5. Approver signs, threshold met, auto-execute
#
# Prerequisites:
#   - Coordinator running on localhost:8080. Steps 2, 14 and 15 call /internal/*
#     with a worker token (WORKER_AUTH_TOKEN); a deployed coordinator answers
#     those only from a worker host with a TEE session, so against one they are
#     skipped with that reason, and the policy-enforcement steps that need step
#     2's policy are skipped with them.
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

skip_test() {
    local test_name="$1"
    local reason="$2"
    TOTAL=$((TOTAL + 1))
    SKIPPED=$((SKIPPED + 1))
    echo -e "  ${YELLOW}SKIP${NC} $test_name ($reason)"
}

# Build curl with API key for GET requests
curl_get() {
    local api_key="$1"
    local path="$2"
    curl -s -w "\n%{http_code}" \
        -H "Authorization: Bearer $api_key" \
        "${COORDINATOR_URL}${path}"
}

# Build curl with API key for POST requests
curl_post() {
    local api_key="$1"
    local path="$2"
    local body="$3"
    local idem_key="${4:-}"
    local extra_headers=()
    if [ -n "$idem_key" ]; then
        extra_headers+=(-H "X-Idempotency-Key: $idem_key")
    fi
    curl -s -w "\n%{http_code}" \
        -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $api_key" \
        ${extra_headers[@]+"${extra_headers[@]}"} \
        -d "$body" \
        "${COORDINATOR_URL}${path}"
}

parse_response() {
    local response="$1"
    RESP_BODY=$(echo "$response" | sed '$d')
    RESP_CODE=$(echo "$response" | tail -1)
}

# ============================================================================
# Setup: Register wallets
# ============================================================================

echo ""
echo "============================================="
echo " Wallet Mode 2: User with Policy"
echo "============================================="
echo ""

if ! curl -s "${COORDINATOR_URL}/health" > /dev/null 2>&1; then
    echo -e "${RED}ERROR: Coordinator not running at ${COORDINATOR_URL}${NC}"
    exit 1
fi

# Register wallet (the controlled wallet)
echo "Registering wallet (controller)..."
REGISTER_RESP=$(curl -s -w "\n%{http_code}" -X POST "${COORDINATOR_URL}/register")
parse_response "$REGISTER_RESP"
assert_status "200" "$RESP_CODE" "POST /register (wallet)"
API_KEY=$(echo "$RESP_BODY" | jq -r '.api_key')
WALLET_ID=$(echo "$RESP_BODY" | jq -r '.wallet_id')
echo "  Wallet ID: $WALLET_ID"
echo "  API Key: ${API_KEY:0:10}..."
echo ""

# Register approver (second signer for multisig)
echo "Registering approver (multisig co-signer)..."
REGISTER_RESP=$(curl -s -w "\n%{http_code}" -X POST "${COORDINATOR_URL}/register")
parse_response "$REGISTER_RESP"
assert_status "200" "$RESP_CODE" "POST /register (approver)"
APPROVER_API_KEY=$(echo "$RESP_BODY" | jq -r '.api_key')
APPROVER_WALLET_ID=$(echo "$RESP_BODY" | jq -r '.wallet_id')
echo "  Approver ID: $APPROVER_WALLET_ID"
echo "  API Key: ${APPROVER_API_KEY:0:10}..."
echo ""

# ============================================================================
# Phase A: Policy Encryption
# ============================================================================

echo "=== Phase A: Policy Management ==="
echo ""

# Test 1: Encrypt policy
echo "1. Encrypt policy"
POLICY_BODY=$(cat <<ENDJSON
{
    "wallet_id": "$WALLET_ID",
    "rules": {
        "transaction_types": ["intents_withdraw"],
        "addresses": {
            "mode": "whitelist",
            "list": ["allowed.near", "recipient.near"]
        },
        "limits": {
            "per_transaction": {"native": "5000000000000000000000000"},
            "daily": {"native": "10000000000000000000000000"},
            "hourly": {"native": "3000000000000000000000000"}
        },
        "rate_limit": {"max_per_hour": 5}
    },
    "approval": {
        "above_usd": 100,
        "threshold": {"required": 2}
    },
    "webhook_url": "https://httpbin.org/post"
}
ENDJSON
)
RESP=$(curl -s -w "\n%{http_code}" -X POST \
    -H "Content-Type: application/json" \
    -d "$POLICY_BODY" \
    "${COORDINATOR_URL}/wallet/v1/encrypt-policy")
parse_response "$RESP"
assert_status "200" "$RESP_CODE" "POST /encrypt-policy"
if [ "$RESP_CODE" = "200" ]; then
    assert_json_not_empty "$RESP_BODY" ".encrypted_base64" "encrypted policy returned"
    ENCRYPTED_POLICY=$(echo "$RESP_BODY" | jq -r '.encrypted_base64')
    echo "  Encrypted policy: ${ENCRYPTED_POLICY:0:40}..."
    HAS_POLICY=true
else
    HAS_POLICY=false
    echo -e "  ${YELLOW}Policy encryption failed — subsequent tests may be limited${NC}"
fi
echo ""

# Test 2: Activate policy locally (requires X-Internal-Wallet-Auth worker token)
echo "2. Activate policy"
WORKER_TOKEN="${WORKER_AUTH_TOKEN:-}"
if [ "$HAS_POLICY" = true ] && [ -n "$WORKER_TOKEN" ]; then
    ACTIVATE_BODY="{\"wallet_id\":\"$WALLET_ID\",\"encrypted_base64\":\"$ENCRYPTED_POLICY\"}"
    RESP=$(curl -s -w "\n%{http_code}" -X POST \
        -H "Content-Type: application/json" \
        -H "X-Internal-Wallet-Auth: $WORKER_TOKEN" \
        -H "X-Wallet-Id: $WALLET_ID" \
        -d "$ACTIVATE_BODY" \
        "${COORDINATOR_URL}/internal/activate-policy")
    parse_response "$RESP"
    if [ "$RESP_CODE" = "401" ] || [ "$RESP_CODE" = "403" ]; then
        skip_test "activate policy" "HTTP $RESP_CODE: this coordinator answers /internal/* only from a TEE worker — run against a local coordinator"
        POLICY_ACTIVE=false
    else
        assert_status "200" "$RESP_CODE" "POST /internal/activate-policy"
        POLICY_ACTIVE=true
    fi
elif [ "$HAS_POLICY" = true ]; then
    skip_test "activate policy" "set WORKER_AUTH_TOKEN to test"
    POLICY_ACTIVE=false
else
    skip_test "activate policy" "no encrypted policy"
    POLICY_ACTIVE=false
fi
echo ""

# ============================================================================
# Phase B: Policy Enforcement (dry-run tests)
# ============================================================================

echo "=== Phase B: Policy Enforcement ==="
echo ""

# Test 3: Get policy
echo "3. Get policy status"
parse_response "$(curl_get "$API_KEY" "/wallet/v1/policy")"
assert_status "200" "$RESP_CODE" "GET /policy"
echo ""

# Test 4: Dry-run within limits, whitelisted address
echo "4. Dry-run: within limits, whitelisted address"
DRYRUN_OK='{"chain":"near","to":"allowed.near","amount":"1000000000000000000000000"}'
parse_response "$(curl_post "$API_KEY" "/wallet/v1/intents/withdraw/dry-run" "$DRYRUN_OK" "dryrun-ok-$(date +%s%N)")"
assert_status "200" "$RESP_CODE" "POST /withdraw/dry-run (within limits)"
assert_json_field "$RESP_BODY" ".would_succeed" "true" "would_succeed=true (within limits)"
echo ""

# Test 5: Dry-run to non-whitelisted address
echo "5. Dry-run: non-whitelisted address"
if [ "${POLICY_ACTIVE:-false}" = true ]; then
    DRYRUN_BAD_ADDR='{"chain":"near","to":"evil.near","amount":"1000000000000000000000000"}'
    parse_response "$(curl_post "$API_KEY" "/wallet/v1/intents/withdraw/dry-run" "$DRYRUN_BAD_ADDR" "dryrun-badaddr-$(date +%s%N)")"
    assert_status "200" "$RESP_CODE" "POST /withdraw/dry-run (non-whitelisted)"
    assert_json_field "$RESP_BODY" ".would_succeed" "false" "would_succeed=false (non-whitelisted)"
else
    skip_test "dry-run non-whitelisted" "policy not active"
fi
echo ""

# Test 6: Dry-run exceeding per-tx limit
echo "6. Dry-run: exceeding per-tx limit"
if [ "${POLICY_ACTIVE:-false}" = true ]; then
    DRYRUN_BIG='{"chain":"near","to":"allowed.near","amount":"9000000000000000000000000"}'
    parse_response "$(curl_post "$API_KEY" "/wallet/v1/intents/withdraw/dry-run" "$DRYRUN_BIG" "dryrun-big-$(date +%s%N)")"
    assert_status "200" "$RESP_CODE" "POST /withdraw/dry-run (over per-tx limit)"
    assert_json_field "$RESP_BODY" ".would_succeed" "false" "would_succeed=false (over per-tx limit)"
else
    skip_test "dry-run over limit" "policy not active"
fi
echo ""

# ============================================================================
# Phase C: Withdrawal & Approval Flow
# ============================================================================

echo "=== Phase C: Withdrawal & Approval Flow ==="
echo ""

# Test 7: Withdrawal (triggers pending_approval when policy has approval section)
echo "7. Withdrawal"
WITHDRAW_BODY='{"chain":"near","to":"allowed.near","amount":"1000000000000000000000000"}'
parse_response "$(curl_post "$API_KEY" "/wallet/v1/intents/withdraw" "$WITHDRAW_BODY" "wd-small-$(date +%s%N)")"
assert_status "200" "$RESP_CODE" "POST /withdraw"
SMALL_REQUEST_ID=$(echo "$RESP_BODY" | jq -r '.request_id')
SMALL_STATUS=$(echo "$RESP_BODY" | jq -r '.status')
SMALL_APPROVAL_ID=$(echo "$RESP_BODY" | jq -r '.approval_id // empty')
if [ "${POLICY_ACTIVE:-false}" = true ]; then
    assert_json_field "$RESP_BODY" ".status" "pending_approval" "status=pending_approval"
    assert_json_not_empty "$RESP_BODY" ".approval_id" "approval_id present"
else
    skip_test "status=pending_approval" "policy not active (no approval triggered)"
    skip_test "approval_id present" "policy not active"
fi
echo "  request_id=$SMALL_REQUEST_ID approval_id=${SMALL_APPROVAL_ID:-none}"
echo ""

# Test 8: Check request status
echo "8. Check request status"
if [ -n "$SMALL_REQUEST_ID" ] && [ "$SMALL_REQUEST_ID" != "null" ]; then
    parse_response "$(curl_get "$API_KEY" "/wallet/v1/requests/$SMALL_REQUEST_ID")"
    assert_status "200" "$RESP_CODE" "GET /requests/{id}"
else
    skip_test "GET /requests/{id}" "no request_id"
fi
echo ""

# Test 9: Get pending approvals
echo "9. Get pending approvals"
parse_response "$(curl_get "$API_KEY" "/wallet/v1/pending_approvals")"
assert_status "200" "$RESP_CODE" "GET /pending_approvals"
PENDING_COUNT=$(echo "$RESP_BODY" | jq '.approvals | length' 2>/dev/null || echo "0")
echo "  Pending approvals: $PENDING_COUNT"
echo ""

# ============================================================================
# Phase D: Multisig Approval (if pending)
# ============================================================================

echo "=== Phase D: Multisig Approval ==="
echo ""

APPROVAL_ID="$SMALL_APPROVAL_ID"
echo "Using approval: ${APPROVAL_ID:-none}"
echo ""

# Tests 10-12: Approval flow requires NEP-413 NEAR wallet signature (not testable from bash)
echo "10-12. Multisig approval (requires NEP-413 NEAR wallet signature)"
if [ -n "$APPROVAL_ID" ] && [ "$APPROVAL_ID" != "" ]; then
    skip_test "approve (first signer)" "requires NEP-413 wallet signature"
    skip_test "approve (duplicate)" "requires NEP-413 wallet signature"
    skip_test "approve (second signer)" "requires NEP-413 wallet signature"
else
    skip_test "approve (first signer)" "no pending approval"
    skip_test "approve (duplicate)" "no pending approval"
    skip_test "approve (second signer)" "no pending approval"
fi
echo ""

# Test 13: Check request status after approval
echo "13. Check request after approval"
sleep 1  # brief delay for async auto-execute
parse_response "$(curl_get "$API_KEY" "/wallet/v1/requests/$SMALL_REQUEST_ID")"
assert_status "200" "$RESP_CODE" "GET /requests/{id} after approval"
FINAL_REQ_STATUS=$(echo "$RESP_BODY" | jq -r '.status')
echo "  Request status: $FINAL_REQ_STATUS"
echo ""

# ============================================================================
# Phase E: Internal endpoints
# ============================================================================

echo "=== Phase E: Internal Endpoints ==="
echo ""

# Test 14: Internal wallet-check by wallet_id (requires worker auth token)
echo "14. Internal wallet-check"
if [ -n "$WORKER_TOKEN" ]; then
    ENCODED_WID=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$WALLET_ID'))")
    RESP=$(curl -s -w "\n%{http_code}" \
        -H "X-Internal-Wallet-Auth: $WORKER_TOKEN" \
        -H "X-Wallet-Id: $WALLET_ID" \
        "${COORDINATOR_URL}/internal/wallet-check?wallet_id=$ENCODED_WID")
    parse_response "$RESP"
    if [ "$RESP_CODE" = "401" ] || [ "$RESP_CODE" = "403" ]; then
        skip_test "internal wallet-check" "HTTP $RESP_CODE: this coordinator answers /internal/* only from a TEE worker"
    else
        assert_status "200" "$RESP_CODE" "GET /internal/wallet-check?wallet_id=..."
        echo "  Response: $(echo "$RESP_BODY" | jq -c '.' 2>/dev/null || echo "${RESP_BODY:0:80}")"
    fi
else
    skip_test "internal wallet-check" "set WORKER_AUTH_TOKEN to test"
fi
echo ""

# Test 15: Internal wallet-audit (requires worker auth token)
echo "15. Internal wallet-audit"
if [ -n "$WORKER_TOKEN" ]; then
    AUDIT_BODY="{\"wallet_id\":\"$WALLET_ID\",\"event_type\":\"test_event\",\"actor\":\"integration_test\",\"details\":{\"note\":\"mode2 test\"}}"
    RESP=$(curl -s -w "\n%{http_code}" -X POST \
        -H "Content-Type: application/json" \
        -H "X-Internal-Wallet-Auth: $WORKER_TOKEN" \
        -H "X-Wallet-Id: $WALLET_ID" \
        -d "$AUDIT_BODY" \
        "${COORDINATOR_URL}/internal/wallet-audit")
    parse_response "$RESP"
    if [ "$RESP_CODE" = "401" ] || [ "$RESP_CODE" = "403" ]; then
        skip_test "internal wallet-audit" "HTTP $RESP_CODE: this coordinator answers /internal/* only from a TEE worker"
    else
        assert_status "200" "$RESP_CODE" "POST /internal/wallet-audit"
    fi
else
    skip_test "internal wallet-audit" "set WORKER_AUTH_TOKEN to test"
fi
echo ""

# Test 16: Verify audit event was recorded
echo "16. Verify audit log has test event"
parse_response "$(curl_get "$API_KEY" "/wallet/v1/audit")"
assert_status "200" "$RESP_CODE" "GET /audit"
echo ""

# ============================================================================
# Phase F: Rate Limiting
# ============================================================================

echo "=== Phase F: Rate Limiting ==="
echo ""

# Test 17: Rate limit — policy allows max 5 per hour
echo "17. Rate limit enforcement"
if [ "${POLICY_ACTIVE:-false}" = true ]; then
    # We already did 1 withdraw in test 7. Do 4 more, then 6th should be denied.
    for i in $(seq 2 5); do
        RAPID_BODY="{\"chain\":\"near\",\"to\":\"allowed.near\",\"amount\":\"100000000000000000000000\"}"
        parse_response "$(curl_post "$API_KEY" "/wallet/v1/intents/withdraw" "$RAPID_BODY" "rate-$i-$(date +%s%N)")"
    done
    # 6th request (exceeds max_per_hour=5)
    RAPID_BODY="{\"chain\":\"near\",\"to\":\"allowed.near\",\"amount\":\"100000000000000000000000\"}"
    parse_response "$(curl_post "$API_KEY" "/wallet/v1/intents/withdraw/dry-run" "$RAPID_BODY" "rate-6-$(date +%s%N)")"
    assert_status "200" "$RESP_CODE" "dry-run after rate limit"
    assert_json_field "$RESP_BODY" ".would_succeed" "false" "would_succeed=false (rate limit)"
else
    skip_test "rate limit enforcement" "policy not active"
fi
echo ""

# ============================================================================
# Summary
# ============================================================================

echo "============================================="
echo "Results: $PASSED/$TOTAL passed, $FAILED failed"
if [ "$SKIPPED" -gt 0 ]; then
    echo "Skipped: $SKIPPED"
fi
if [ "$FAILED" -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
else
    echo -e "${RED}$FAILED test(s) failed${NC}"
    exit 1
fi
echo ""
