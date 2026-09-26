#!/bin/bash
# Builds the relay into res/outlayer_test_relay.wasm and prints its sha256.
set -e

cd "$(dirname "$0")"

cargo near build non-reproducible-wasm

mkdir -p res
cp target/near/outlayer_test_relay.wasm res/outlayer_test_relay.wasm

ls -lh res/outlayer_test_relay.wasm
echo "SHA256: $(shasum -a 256 res/outlayer_test_relay.wasm | cut -d' ' -f1)"
