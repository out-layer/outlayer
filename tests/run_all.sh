#!/bin/bash
# Run all tests in sequence

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo ""
echo "🧪 Running All Tests"
echo "===================="
echo ""

# Test 1: Unit Tests
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}Test 1/4: Unit Tests${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo ""
"$SCRIPT_DIR/unit.sh"
echo ""

# Test 4: Wallet Tests (Mode 1 — Agent)
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}Test 4/6: Wallet Mode 1 — Simple Agent${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo ""

if curl -s http://localhost:8080/health > /dev/null 2>&1; then
    "$SCRIPT_DIR/wallet_mode1_agent.sh"
    echo ""
else
    echo "⚠️  Skipping wallet agent tests - Coordinator not running"
    echo "   cd coordinator && cargo run"
    echo ""
fi

# Wallet — EVM signing (EIP-712 / EIP-191 / raw tx); read/sign only, no funds
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}Wallet — EVM signing (EIP-712 / EIP-191 / raw tx)${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo ""

if curl -s http://localhost:8080/health > /dev/null 2>&1; then
    "$SCRIPT_DIR/wallet_evm_sign_e2e.sh"
    echo ""
else
    echo "⚠️  Skipping EVM signing tests - Coordinator not running"
    echo ""
fi

# Wallet — Solana signing (message / transaction); read/sign only, no funds
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}Wallet — Solana signing (message / transaction)${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo ""

if curl -s http://localhost:8080/health > /dev/null 2>&1; then
    "$SCRIPT_DIR/wallet_solana_sign_e2e.sh"
    echo ""
else
    echo "⚠️  Skipping Solana signing tests - Coordinator not running"
    echo ""
fi

# Wallet — withdraw dry-run fidelity (issue #28); no funds. Self-skips unless
# the coordinator is mainnet-configured (intents are mainnet-only).
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}Wallet — withdraw dry-run fidelity${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo ""

if curl -s http://localhost:8080/health > /dev/null 2>&1; then
    "$SCRIPT_DIR/wallet_dry_run_e2e.sh"
    echo ""
else
    echo "⚠️  Skipping withdraw dry-run tests - Coordinator not running"
    echo ""
fi

# Test 5: Wallet Tests (Mode 2 — Policy)
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}Test 5/6: Wallet Mode 2 — User with Policy${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo ""

if curl -s http://localhost:8080/health > /dev/null 2>&1; then
    "$SCRIPT_DIR/wallet_mode2_policy.sh"
    echo ""
else
    echo "⚠️  Skipping wallet policy tests - Coordinator not running"
    echo "   cd coordinator && cargo run"
    echo ""
fi

# Test 6: E2E Tests
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}Test 6/6: End-to-End Tests${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo "⚠️  E2E tests require manual execution (requires testnet contract)"
echo "   Run manually: $SCRIPT_DIR/e2e.sh"
echo ""

echo "═══════════════════════════════════════════════════════════"
echo -e "${GREEN}✅ Test suite completed!${NC}"
echo "═══════════════════════════════════════════════════════════"
echo ""
