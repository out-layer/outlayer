#!/bin/bash
set -e

echo "Building keystore-dao-contract..."

# Build with LLVM for WASM target (required for ring crate)
# --no-abi: Don't embed ABI into the contract (prevents deserialization errors)
# --no-wasmopt: cargo-near's wasm-opt has bulk-memory validation issues
CC=/Users/alice/.local/opt/llvm/bin/clang \
AR=/Users/alice/.local/opt/llvm/bin/llvm-ar \
cargo near build non-reproducible-wasm --no-abi --no-wasmopt

# Create res directory if not exists
mkdir -p res

# Copy WASM file (without wasm-opt post-processing)
cp target/near/keystore_dao_contract.wasm res/keystore_dao_contract.wasm

# Show file size
ls -lh res/keystore_dao_contract.wasm

echo "✅ Build complete: res/keystore_dao_contract.wasm"
echo "Note: Built without wasm-opt due to bulk-memory operations in dcap-qvl/ring dependencies"

# A fresh account: deploy and `new` in one transaction.
# near contract deploy dao.outlayer.testnet use-file res/keystore_dao_contract.wasm with-init-call new json-args '{"owner_id": "owner.outlayer.testnet", "init_account_id": "init-keystore.outlayer.testnet", "dao_members": ["zavodil.testnet"], "mpc_contract_id": "v1.signer-prod.testnet", "gov_delay_sec": null}' prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR' network-config testnet sign-with-keychain send
#
# The release that brings governance, signed with the account's full-access key: deploy and
# `migrate` in ONE transaction, so a failing migrate leaves the old code in place.
# near contract deploy dao.outlayer.testnet use-file res/keystore_dao_contract.wasm with-init-call migrate json-args '{}' prepaid-gas '300.0 Tgas' attached-deposit '0 NEAR' network-config testnet sign-with-keychain send
# near contract deploy dao.outlayer.near use-file res/keystore_dao_contract.wasm with-init-call migrate json-args '{}' prepaid-gas '300.0 Tgas' attached-deposit '0 NEAR' network-config mainnet sign-with-keychain send
#
# Every later upgrade goes through the DAO itself: scripts/dao_upgrade.sh --target dao.
# Collateral: ./scripts/update_collateral.sh (owner). Keystore builds are approved by an
# `ApproveMeasurements` proposal (scripts/deploy_tdx.sh makes it).
