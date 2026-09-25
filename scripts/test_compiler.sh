#!/bin/bash

# Test compiler for WASM projects
# This script mimics the worker compiler logic without modifying the worker code
#
# Usage:
#   ./scripts/test_compiler.sh <repo_url> <commit> <build_target> [output_file]
#
# Required arguments:
#   repo_url     - GitHub repository URL
#   commit       - Git commit hash or branch name (e.g., 'main', 'abc123def')
#   build_target - WASM target: wasm32-wasip1, wasm32-wasip2, or wasm32-wasi
#
# Examples:
#   ./scripts/test_compiler.sh https://github.com/substance-labs/rust-pds-poc 250bca1ac58b5bd46549ec4c32b2447e07a78e8b wasm32-wasip1
#   ./scripts/test_compiler.sh https://github.com/user/repo main wasm32-wasip2 output.wasm

set -e

# Parse arguments
REPO="${1}"
COMMIT="${2}"
BUILD_TARGET="${3}"
OUTPUT_FILE="${4:-output.wasm}"

# Docker image (same as worker uses)
DOCKER_IMAGE="${DOCKER_IMAGE:-outlayer/wasmedge-compiler@sha256:5c996303f707381f463e591d7b0650e64816e63e7bc1d98ab72a62abf55b146e}"

# Compilation limits (same defaults as worker)
COMPILE_MEMORY_LIMIT="${COMPILE_MEMORY_LIMIT:-2048}"  # MB
COMPILE_CPU_LIMIT="${COMPILE_CPU_LIMIT:-1.0}"  # CPUs
COMPILE_TIMEOUT="${COMPILE_TIMEOUT:-300}"  # seconds

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Docker is not installed or not in PATH${NC}"
    exit 1
fi

# Validate arguments
if [ -z "$REPO" ] || [ -z "$COMMIT" ] || [ -z "$BUILD_TARGET" ]; then
    echo -e "${RED}❌ Usage: $0 <repo_url> <commit> <build_target> [output_file]${NC}"
    echo ""
    echo "All three arguments are required:"
    echo "  repo_url     - GitHub repository URL"
    echo "  commit       - Git commit hash or branch name"
    echo "  build_target - WASM compilation target (wasm32-wasip1, wasm32-wasip2, wasm32-wasi)"
    echo "  output_file  - Optional output filename (default: output.wasm)"
    echo ""
    echo "Examples:"
    echo "  $0 https://github.com/user/repo main wasm32-wasip1"
    echo "  $0 https://github.com/user/repo abc123def wasm32-wasip2 myapp.wasm"
    echo "  $0 https://github.com/substance-labs/rust-pds-poc 250bca1ac58b wasm32-wasip1"
    exit 1
fi

# Validate build target
case "$BUILD_TARGET" in
    wasm32-wasip1|wasm32-wasip2|wasm32-wasi)
        # Valid targets
        ;;
    *)
        echo -e "${RED}❌ Invalid build target: $BUILD_TARGET${NC}"
        echo "Supported targets:"
        echo "  - wasm32-wasip1 (WASI Preview 1)"
        echo "  - wasm32-wasip2 (WASI Preview 2)"
        echo "  - wasm32-wasi   (legacy, will be upgraded to wasip1 if available)"
        exit 1
        ;;
esac

echo -e "${GREEN}🔧 Test Compiler Starting...${NC}"
echo "Repository: $REPO"
echo "Commit: $COMMIT"
echo "Target: $BUILD_TARGET"
echo "Docker image: $DOCKER_IMAGE"
echo "Output: $OUTPUT_FILE"
echo "Memory limit: ${COMPILE_MEMORY_LIMIT}MB"
echo "CPU limit: ${COMPILE_CPU_LIMIT} CPUs"
echo "Timeout: ${COMPILE_TIMEOUT}s"
echo ""

# Pull Docker image (quick if already up to date)
echo -e "${GREEN}📦 Pulling Docker image...${NC}"
docker pull "$DOCKER_IMAGE"
if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Failed to pull Docker image${NC}"
    exit 1
fi

# Create temporary directory for output
TMP_OUTPUT_DIR=$(mktemp -d)
trap "rm -rf $TMP_OUTPUT_DIR" EXIT

echo -e "${GREEN}📦 Starting compilation...${NC}"

# Run Docker container with same logic as worker
# This mirrors the logic in worker/src/compiler/wasm32_wasip1.rs and wasm32_wasip2.rs
docker run --rm \
  -e REPO="$REPO" \
  -e COMMIT="$COMMIT" \
  -e BUILD_TARGET="$BUILD_TARGET" \
  -v "$TMP_OUTPUT_DIR:/workspace/output" \
  --memory="${COMPILE_MEMORY_LIMIT}m" \
  --cpus="$COMPILE_CPU_LIMIT" \
  "$DOCKER_IMAGE" \
  bash -c '
set -ex
cd /workspace

# Track compilation time
START_TIME=$(date +%s)

# Setup Rust environment
if [ -f /usr/local/cargo/env ]; then
    . /usr/local/cargo/env
elif [ -f $HOME/.cargo/env ]; then
    . $HOME/.cargo/env
fi

# Determine compilation strategy based on target
if [ "$BUILD_TARGET" = "wasm32-wasip2" ]; then
    echo "🔧 Compiling for WASI Preview 2..."

    # Add WASM target for WASI Preview 2
    rustup target add wasm32-wasip2
    echo "🔧 TARGET: wasm32-wasip2"

    # Clone repository
    git clone $REPO repo
    cd repo
    git checkout $COMMIT

    # Build WASM component with cargo
    cargo build --release --target wasm32-wasip2
    WASM_FILE=$(find target/wasm32-wasip2/release -maxdepth 1 -name "*.wasm" -type f | head -1)

    # Find compiled WASM
    if [ -z "$WASM_FILE" ]; then
        echo "❌ ERROR: No WASM file found!"
        find target/wasm32-wasip2/release -type f
        exit 1
    fi

    echo "📦 Original WASM component: $WASM_FILE"
    ls -lah "$WASM_FILE"

    # Copy to output
    mkdir -p /workspace/output
    cp "$WASM_FILE" /workspace/output/output.wasm

    # Optimize WASM P2 component
    ORIGINAL_SIZE=$(stat -c%s /workspace/output/output.wasm 2>/dev/null || stat -f%z /workspace/output/output.wasm)

    # WASI Preview 2: already a proper CLI component from cargo
    # Just strip debug info and optimize
    if command -v wasm-tools &> /dev/null; then
        echo "🔧 Optimizing WASI P2 CLI component..."

        # Strip debug information from component
        wasm-tools strip --delete "^(\.debug_.*|producers|target_features|linking|reloc\..*|sourceMappingURL|external_debug_info|component-name)$" /workspace/output/output.wasm -o /workspace/output/output_optimized.wasm
        mv /workspace/output/output_optimized.wasm /workspace/output/output.wasm
        # What is left after the strip, by section name. Only what this platform
        # expects may remain — `name`, `component-type*` and `dylink.0`, which
        # wasm-tools keeps by design, and `outlayer.manifest` — so a section the
        # delete list does not name fails the build with its name rather than
        # shipping in the bytes.
        STRAY=$(wasm-tools objdump /workspace/output/output.wasm | sed -n "s/^ *custom \"\([^\"]*\)\".*/\1/p" | sort -u | grep -v -E "^(name|component-type.*|dylink\.0|outlayer\.manifest)$" || true)
        [ -z "$STRAY" ] || { echo "ERROR: custom sections survived the strip: $STRAY"; exit 1; }

        OPTIMIZED_SIZE=$(stat -c%s /workspace/output/output.wasm 2>/dev/null || stat -f%z /workspace/output/output.wasm)
        SAVED=$((ORIGINAL_SIZE - OPTIMIZED_SIZE))
        PERCENT=$((SAVED * 100 / ORIGINAL_SIZE))
        echo "✅ Component optimization complete: $ORIGINAL_SIZE bytes → $OPTIMIZED_SIZE bytes (saved $SAVED bytes / $PERCENT%)"
    else
        echo "ℹ️  wasm-tools not available - skipping WASI Preview 2 component optimization"
        echo "   Component size: $ORIGINAL_SIZE bytes"
    fi

else
    # Default: WASI Preview 1 or wasm32-wasi
    echo "🔧 Compiling for WASI Preview 1..."

    # Add WASM target
    TARGET_TO_ADD=$BUILD_TARGET
    if [ "$BUILD_TARGET" = "wasm32-wasi" ]; then
        # Try wasip1 first (Rust 1.78+), fallback to wasi
        if rustup target list | grep -q wasm32-wasip1; then
            TARGET_TO_ADD="wasm32-wasip1"
            echo "ℹ️  Using wasm32-wasip1 (recommended for Rust 1.78+)"
        fi
    fi
    rustup target add $TARGET_TO_ADD
    echo "🔧 TARGET_TO_ADD: $TARGET_TO_ADD"

    # Clone repository
    git clone $REPO repo
    cd repo
    git checkout $COMMIT

    # Build WASM with size optimizations
    cargo build --release --target $TARGET_TO_ADD
    WASM_FILE=$(find target/$TARGET_TO_ADD/release -maxdepth 1 -name "*.wasm" -type f | head -1)

    # Find compiled WASM
    if [ -z "$WASM_FILE" ]; then
        echo "❌ ERROR: No WASM file found!"
        find target/$TARGET_TO_ADD/release -type f
        exit 1
    fi

    echo "📦 Original WASM: $WASM_FILE"
    ls -lah "$WASM_FILE"

    # Copy to output
    mkdir -p /workspace/output
    cp "$WASM_FILE" /workspace/output/output.wasm

    # Optimize WASM module with wasm-opt
    ORIGINAL_SIZE=$(stat -c%s /workspace/output/output.wasm 2>/dev/null || stat -f%z /workspace/output/output.wasm)

    echo "🔧 Optimizing WASM module with wasm-opt..."

    # Apply optimizations as per cargo-wasi:
    # -Oz: optimize aggressively for size
    # --strip-dwarf: remove DWARF debug info
    # --strip-producers: remove producers section
    # --enable-sign-ext: enable sign extension operations
    # --enable-bulk-memory: enable bulk memory operations
    if command -v wasm-opt &> /dev/null; then
        wasm-opt -Oz \
            --strip-dwarf \
            --strip-producers \
            --enable-sign-ext \
            --enable-bulk-memory \
            /workspace/output/output.wasm \
            -o /workspace/output/output_optimized.wasm

        mv /workspace/output/output_optimized.wasm /workspace/output/output.wasm
        OPTIMIZED_SIZE=$(stat -c%s /workspace/output/output.wasm 2>/dev/null || stat -f%z /workspace/output/output.wasm)
        SAVED=$((ORIGINAL_SIZE - OPTIMIZED_SIZE))
        PERCENT=$((SAVED * 100 / ORIGINAL_SIZE))
        echo "✅ Module optimization complete: $ORIGINAL_SIZE bytes → $OPTIMIZED_SIZE bytes (saved $SAVED bytes / $PERCENT%)"
    else
        echo "⚠️  wasm-opt not available, skipping module optimization"
    fi
fi

ls -lah /workspace/output/output.wasm

# Calculate total compilation time
END_TIME=$(date +%s)
COMPILE_TIME=$((END_TIME - START_TIME))
echo "⏱️  Total compilation time: $COMPILE_TIME seconds"
'

# Check if compilation was successful
if [ ! -f "$TMP_OUTPUT_DIR/output.wasm" ]; then
    echo -e "${RED}❌ Compilation failed - no output WASM file${NC}"
    exit 1
fi

# Copy output file to desired location
cp "$TMP_OUTPUT_DIR/output.wasm" "$OUTPUT_FILE"

# Calculate SHA256
CHECKSUM=$(sha256sum "$OUTPUT_FILE" | cut -d' ' -f1)

# Get file size
FILE_SIZE=$(stat -c%s "$OUTPUT_FILE" 2>/dev/null || stat -f%z "$OUTPUT_FILE")

echo ""
echo -e "${GREEN}✅ Compilation successful!${NC}"
echo "📝 WASM saved to: $OUTPUT_FILE"
echo "📊 Size: $FILE_SIZE bytes"
echo "🔐 SHA256: $CHECKSUM"
echo ""
echo "You can now test this WASM with:"
echo "  wasmtime $OUTPUT_FILE"
echo "  wasmedge $OUTPUT_FILE"