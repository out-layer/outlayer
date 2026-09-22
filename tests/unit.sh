#!/bin/bash
# Unit tests for WASM execution

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "🧪 Unit Tests - WASM Execution"
echo "==============================="
echo ""

# Build test WASM modules
echo "🔨 Building test WASM modules..."
echo ""

# The examples this gate compiles. Each is OPTIONAL, and the reason is what broke
# this script: `random-ark` was renamed to `random-example` (9c156ad) and the
# build, unguarded, failed on a missing directory — so the worker's unit tests
# below, the thing this file exists to run, never ran at all. A named example
# that is gone SAYS SO and the gate carries on; the tests are what must not be
# skipped.
build_example() { # build_example <dir> <target>
    local dir="$PROJECT_ROOT/wasi-examples/$1" target=$2
    if [ ! -d "$dir" ]; then
        echo "⊘ $1 not present — skipping (renamed or moved?)"
        return 0
    fi
    echo "📦 Building $1 ($target)..."
    ( cd "$dir" && cargo build --release --target "$target" --quiet ) \
        || { echo "✗ $1 failed to build"; return 1; }
    echo "✓ $1 built successfully"
}

build_example random-example wasm32-wasip1 || exit 1
build_example ai-example    wasm32-wasip2 || exit 1

echo ""

# Run worker unit tests
echo "🧪 Running worker unit tests..."
echo ""
cd "$PROJECT_ROOT/worker"
cargo test --quiet

echo ""
echo "✅ All unit tests passed!"
