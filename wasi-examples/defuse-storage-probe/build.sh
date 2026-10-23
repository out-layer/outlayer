#!/bin/bash
set -e

cd "$(dirname "$0")"

rustup target add wasm32-wasip2 2>/dev/null || true
cargo build --target wasm32-wasip2 --release

WASM_FILE="target/wasm32-wasip2/release/defuse-storage-probe.wasm"
echo "WASM: $WASM_FILE"
echo "SHA256: $(shasum -a 256 "$WASM_FILE" | cut -d' ' -f1)"

# No OutLayer host interface may be imported: the Defuse worker links none.
if command -v wasm-tools >/dev/null 2>&1; then
    if wasm-tools component wit "$WASM_FILE" | grep -qE 'import (near|outlayer):'; then
        echo "ERROR: the component imports an OutLayer host interface; build with the defuse-engine feature only"
        exit 1
    fi
    echo "Host imports: none (WASI only)"
fi
