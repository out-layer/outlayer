#!/bin/bash
# ============================================================================
# Wallet Integration Tests — withdraw dry-run (pre-flight fidelity)
#
# Regression net for https://github.com/out-layer/outlayer/issues/28:
# `POST /wallet/v1/intents/withdraw/dry-run` answered `would_succeed: true` for
# a USDC→ethereum amount the real withdraw then refused with
# `1Click: Amount is too low for bridge, try at least 303064`. The dry-run never
# asked the bridge — and never checked the balance, never mirrored the input
# validation, and evaluated the wrong policy op for cross-chain.
#
# The invariant under test: THE DRY-RUN AND THE REAL WITHDRAW AGREE. Every case
# below asserts the dry-run's verdict AND (for predicted failures) that the real
# `POST /wallet/v1/intents/withdraw` fails too.
#
# Runs on a fresh, UNFUNDED wallet — no funds move, so it is safe to run on
# every deploy, repeatedly:
#   - the `amount: "0"` cases pass the balance gate (0 >= 0) and get refused
#     further down the pipeline (bridge / storage / recipient), so they reach
#     the deep checks with an empty wallet;
#   - the parity calls to the REAL withdraw are only made for cases the dry-run
#     predicts will FAIL, so a correct coordinator cannot move anything. If one
#     of them ever returns 2xx, that IS the bug this suite exists to catch (and
#     it would move at most the zero / unfunded amount requested).
#
# Prerequisites:
#   - Coordinator running (default localhost:8080) with a MAINNET config.
#     NEAR Intents are mainnet-only; on testnet the coordinator 503-gates every
#     intents route and this suite skips itself.
#   - Keystore running (address derivation + policy read).
#   - Outbound network to 1Click (the cross-chain dry-run quotes for real).
#
# Usage:
#   ./tests/wallet_dry_run_e2e.sh
#   COORDINATOR_URL=https://api.outlayer.ai ./tests/wallet_dry_run_e2e.sh
#   SKIP_PARITY=1 ./tests/wallet_dry_run_e2e.sh   # dry-run assertions only
# ============================================================================

set -euo pipefail

COORDINATOR_URL="${COORDINATOR_URL:-http://localhost:8080}"
SKIP_PARITY="${SKIP_PARITY:-0}"

# Mainnet asset ids — the intents/1Click routes only exist on mainnet.
USDC_NEAR="nep141:17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1"
ETH_RECIPIENT="0x1111111111111111111111111111111111111111"
ONE_NEAR_YOCTO="1000000000000000000000000"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
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

skip() {
    TOTAL=$((TOTAL + 1)); SKIPPED=$((SKIPPED + 1))
    echo -e "  ${YELLOW}SKIP${NC} $1"
}

curl_post() {
    curl -s -w "\n%{http_code}" -X POST -H "Content-Type: application/json" \
        -H "Authorization: Bearer $API_KEY" -d "$2" "${COORDINATOR_URL}$1"
}

parse_response() {
    RESP_BODY=$(echo "$1" | sed '$d')
    RESP_CODE=$(echo "$1" | tail -1)
}

DRY_RUN_PATH="/wallet/v1/intents/withdraw/dry-run"
WITHDRAW_PATH="/wallet/v1/intents/withdraw"

# dry_run <body> — leaves the verdict in WOULD_SUCCEED / REASON / MESSAGE.
dry_run() {
    parse_response "$(curl_post "$DRY_RUN_PATH" "$1")"
    # `tostring`, NOT `// "null"` — jq's alternative operator treats `false` as empty, so
    # `.would_succeed // "null"` reports "null" for the exact verdict this suite exists to check.
    WOULD_SUCCEED=$(echo "$RESP_BODY" | jq -r '.would_succeed | tostring')
    REASON=$(echo "$RESP_BODY" | jq -r '.reason | tostring')
    MESSAGE=$(echo "$RESP_BODY" | jq -r '.message // ""')
}

# expect_would_fail <name> <expected_reason> <body>
#
# Asserts the dry-run predicts failure with `expected_reason`, then (unless
# SKIP_PARITY) asserts the REAL withdraw refuses the same body. The real call is
# only ever made for a predicted failure — see the fund-safety note in the header.
expect_would_fail() {
    local name="$1" expected_reason="$2" body="$3"

    dry_run "$body"
    assert_status "200" "$RESP_CODE" "$name — dry-run answers"
    assert_equals "false" "$WOULD_SUCCEED" "$name — would_succeed"
    # `expected_reason` may name alternatives (`a|b`): 1Click words a refusal
    # as it sees fit, and each wording has its own code.
    TOTAL=$((TOTAL + 1))
    if [[ "$REASON" =~ ^($expected_reason)$ ]]; then
        echo -e "  ${GREEN}PASS${NC} $name — reason ($REASON)"
        PASSED=$((PASSED + 1))
    else
        echo -e "  ${RED}FAIL${NC} $name — reason (expected '$expected_reason', got '$REASON')"
        FAILED=$((FAILED + 1))
    fi
    [ -n "$MESSAGE" ] && echo "       ↳ $MESSAGE"

    if [ "$SKIP_PARITY" = "1" ]; then
        skip "$name — real-withdraw parity (SKIP_PARITY=1)"
        return
    fi
    parse_response "$(curl_post "$WITHDRAW_PATH" "$body")"
    TOTAL=$((TOTAL + 1))
    if [ "$RESP_CODE" -ge 400 ]; then
        echo -e "  ${GREEN}PASS${NC} $name — real withdraw refuses too (HTTP $RESP_CODE)"
        PASSED=$((PASSED + 1))
    else
        echo -e "  ${RED}FAIL${NC} $name — dry-run said NO but real withdraw returned HTTP $RESP_CODE"
        echo "       ↳ $RESP_BODY"
        FAILED=$((FAILED + 1))
    fi
}

# ============================================================================
# Setup
# ============================================================================

echo ""
echo -e "${CYAN}=============================================${NC}"
echo -e "${CYAN} Wallet: withdraw dry-run fidelity (issue #28)${NC}"
echo -e "${CYAN}=============================================${NC}"
echo ""

if ! curl -s "${COORDINATOR_URL}/health" > /dev/null 2>&1; then
    echo -e "${RED}ERROR: Coordinator not running at ${COORDINATOR_URL}${NC}"
    exit 1
fi

echo "Registering new wallet (unfunded)..."
parse_response "$(curl -s -w "\n%{http_code}" -X POST "${COORDINATOR_URL}/register")"
assert_status "200" "$RESP_CODE" "POST /register"
API_KEY=$(echo "$RESP_BODY" | jq -r '.api_key')
WALLET_ID=$(echo "$RESP_BODY" | jq -r '.wallet_id')
NEAR_ADDRESS=$(echo "$RESP_BODY" | jq -r '.near_account_id')
echo "  Wallet ID:    $WALLET_ID"
echo "  NEAR account: $NEAR_ADDRESS"
echo ""

# Intents are mainnet-only; a testnet coordinator 503s every route below.
dry_run '{"chain":"near","token":"near","amount":"0"}'
if [ "$RESP_CODE" = "503" ]; then
    echo -e "${YELLOW}Intents unavailable on this coordinator (HTTP 503).${NC}"
    echo -e "${YELLOW}This suite needs a MAINNET-configured coordinator — skipping.${NC}"
    echo "  ↳ $(echo "$RESP_BODY" | jq -r '.error // .message // .' 2>/dev/null || echo "$RESP_BODY")"
    exit 0
fi

# ============================================================================
# Test 1: same-chain native NEAR to self — the happy path still passes
# ============================================================================

echo "1. Same-chain native NEAR, amount 0, to self (implicit account)"
assert_status "200" "$RESP_CODE" "dry-run answers"
assert_equals "true" "$WOULD_SUCCEED" "would_succeed"
assert_equals "NEAR" "$(echo "$RESP_BODY" | jq -r '.fee_token | tostring')" "fee_token"
assert_equals "true" "$(echo "$RESP_BODY" | jq -r '.policy_check.within_limits | tostring')" "policy_check.within_limits"
echo ""

# ============================================================================
# Test 2: balance is checked (the dry-run used to ignore it entirely)
# ============================================================================

echo "2. Same-chain native NEAR, 1 NEAR from an empty wallet"
expect_would_fail "insufficient balance" "insufficient_balance" \
    "$(printf '{"chain":"near","token":"near","amount":"%s"}' "$ONE_NEAR_YOCTO")"
echo ""

# ============================================================================
# Test 3: native NEAR to a non-existent named account would burn the wNEAR
# ============================================================================

echo "3. Same-chain native NEAR to a non-existent named account"
expect_would_fail "recipient not found" "recipient_not_found" \
    '{"chain":"near","token":"near","amount":"0","to":"this-account-does-not-exist-outlayer-dryrun.near"}'
echo ""

# ============================================================================
# Test 4: NEP-141 delivery needs recipient storage (checked before balance,
#         mirroring execute_near_withdraw's order)
# ============================================================================

echo "4. Same-chain USDC to a fresh account with no storage"
expect_would_fail "storage not registered" "storage_not_registered" \
    "$(printf '{"chain":"near","token":"%s","amount":"0"}' "$USDC_NEAR")"
echo ""

# ============================================================================
# Test 5: THE issue-#28 case — the bridge gets asked before the user confirms
# ============================================================================

echo "5. Cross-chain USDC → ethereum, amount the bridge refuses"
# 1Click answers a zero amount in its own words — "Amount is too low for
# bridge" (upstream_rejected) or "No liquidity available" (no_liquidity) —
# and the dry-run's reason is the code the real withdraw answers with.
expect_would_fail "bridge refused" "upstream_rejected|no_liquidity" \
    "$(printf '{"chain":"ethereum","token":"%s","amount":"0","to":"%s"}' "$USDC_NEAR" "$ETH_RECIPIENT")"
echo ""

# ============================================================================
# Test 6: cross-chain balance gate fires before the bridge quote (ordering
#         mirrors execute_cross_chain_withdraw: balance → quote)
# ============================================================================

echo "6. Cross-chain USDC → ethereum, 10000 units from an empty wallet"
expect_would_fail "cross-chain insufficient balance" "insufficient_balance" \
    "$(printf '{"chain":"ethereum","token":"%s","amount":"10000","to":"%s"}' "$USDC_NEAR" "$ETH_RECIPIENT")"
echo ""

# ============================================================================
# Test 7: input validation is mirrored, not skipped
# ============================================================================

echo "7. Cross-chain without an explicit source token"
expect_would_fail "invalid request" "invalid_request" \
    "$(printf '{"chain":"ethereum","amount":"0","to":"%s"}' "$ETH_RECIPIENT")"
echo ""

echo "8. Unsupported chain is rejected by both (HTTP 4xx, not a verdict)"
parse_response "$(curl_post "$DRY_RUN_PATH" '{"chain":"dogecoin","token":"near","amount":"0"}')"
assert_status "400" "$RESP_CODE" "dry-run rejects unknown chain"
parse_response "$(curl_post "$WITHDRAW_PATH" '{"chain":"dogecoin","token":"near","amount":"0"}')"
assert_status "400" "$RESP_CODE" "real withdraw rejects unknown chain"
echo ""

# ============================================================================
# Test 9: confidential withdraw dry-run mirrors its real handler's input gate
# ============================================================================

echo "9. Confidential withdraw dry-run requires \`to\` (same gate as the real call)"
CONF_BODY="$(printf '{"chain":"ethereum","token":"%s","amount":"1000000"}' "$USDC_NEAR")"
parse_response "$(curl_post "/wallet/v1/confidential/withdraw/dry-run" "$CONF_BODY")"
if [ "$RESP_CODE" = "503" ]; then
    skip "confidential dry-run (ENABLE_CONFIDENTIAL_INTENTS is off on this coordinator)"
else
    assert_status "400" "$RESP_CODE" "confidential dry-run rejects a missing \`to\`"
    parse_response "$(curl_post "/wallet/v1/confidential/withdraw" "$CONF_BODY")"
    assert_status "400" "$RESP_CODE" "confidential withdraw rejects a missing \`to\`"
fi
echo ""

# ============================================================================
# Not covered here
# ============================================================================

# Policy verdicts (`policy_denied`, `wallet_frozen`) and the cross-chain op
# variant (`cross_chain_withdraw` is default-DENY and NOT covered by a
# `withdraw` capability) need an encrypted policy stored on-chain, which needs a
# funded wallet. The op-type logic is unit-tested in shared-tee-helpers
# (wallet_policy.rs::cross_chain_withdraw_is_default_deny_own_type).
skip "policy_denied / wallet_frozen verdicts (need an on-chain policy ⇒ funded wallet)"
skip "cross-chain op is gated by cross_chain_withdraw, not withdraw (same reason; unit-tested)"
echo ""

# ============================================================================
# Results
# ============================================================================

echo "============================================="
echo -e " Results: ${GREEN}${PASSED} passed${NC}, ${RED}${FAILED} failed${NC}, ${YELLOW}${SKIPPED} skipped${NC} (${TOTAL} total)"
echo "============================================="
[ "$FAILED" -eq 0 ]
