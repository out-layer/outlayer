#!/bin/bash
set -e

echo "Building register-contract..."

# Build with LLVM for WASM target (required for ring crate)
# --no-abi: Don't embed ABI into the contract (prevents deserialization errors)
# --no-wasmopt: cargo-near's wasm-opt has bulk-memory validation issues
CC=/Users/alice/.local/opt/llvm/bin/clang \
AR=/Users/alice/.local/opt/llvm/bin/llvm-ar \
cargo near build non-reproducible-wasm --no-abi --no-wasmopt

# Create res directory if not exists
mkdir -p res

# Copy WASM file (without wasm-opt post-processing)
cp target/near/register_contract.wasm res/register_contract.wasm

# Show file size
ls -lh res/register_contract.wasm

echo "✅ Build complete: res/register_contract.wasm"
echo "Note: Built without wasm-opt due to bulk-memory operations in dcap-qvl/ring dependencies"

# A fresh account: deploy and `new` in one transaction.
# near contract deploy worker.outlayer.testnet use-file res/register_contract.wasm with-init-call new json-args '{"owner_id": "owner.outlayer.testnet", "init_worker_account": "init-worker.outlayer.testnet", "outlayer_contract_id": "outlayer.testnet", "governance_id": "dao.outlayer.testnet"}' prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR' network-config testnet sign-with-keychain send
#
# The release that hands the contract to the DAO, signed with the account's full-access key:
# deploy and `migrate` in ONE transaction, so a failing migrate leaves the old code in place.
# `migrate` takes the DAO account; check `get_governance` afterwards.
# near contract deploy worker.outlayer.testnet use-file res/register_contract.wasm with-init-call migrate json-args '{"governance_id": "dao.outlayer.testnet"}' prepaid-gas '300.0 Tgas' attached-deposit '0 NEAR' network-config testnet sign-with-keychain send
# near contract deploy worker.outlayer.near use-file res/register_contract.wasm with-init-call migrate json-args '{"governance_id": "dao.outlayer.near"}' prepaid-gas '300.0 Tgas' attached-deposit '0 NEAR' network-config mainnet sign-with-keychain send
#
# Every later upgrade goes through the DAO: scripts/dao_upgrade.sh --target worker
# (scripts/dao_upgrade_plan.sh prints the same transactions). Worker builds are approved by a
# DAO `Call` proposal to `add_approved_measurements` (scripts/deploy_tdx.sh makes it).
