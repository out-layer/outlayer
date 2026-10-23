#!/bin/bash
set -e

cd "$(dirname "$0")"

rustup target add wasm32-wasip2 2>/dev/null || true
cargo build --target wasm32-wasip2 --release

for name in defuse-core-probe defuse-plain-probe; do
    WASM_FILE="target/wasm32-wasip2/release/$name.wasm"
    echo "WASM: $WASM_FILE"
    echo "SHA256: $(shasum -a 256 "$WASM_FILE" | cut -d' ' -f1)"
done
