#!/bin/bash
# Builds every variant of the probe into target/variants/:
#
#   signing-key-probe-project.wasm        alpha, beta — bind "project"
#   signing-key-probe-project-v2.wasm     the same manifest, another sha256
#   signing-key-probe-wasm.wasm           code — bind "wasm"
#   signing-key-probe-wasm-v2.wasm        the same manifest, another sha256
#   signing-key-probe-project-vault.wasm  alpha, and treasury with a vault
#
# and checks each: the manifest section is in the artefact and is the right
# one, the module imports outlayer:signing-keys and nothing else of ours, and
# the two builds of one manifest really are two hashes.
set -e

cd "$(dirname "$0")"

OUT="target/variants"
BUILT="target/wasm32-wasip2/release/signing-key-probe.wasm"
WORKER_WIT="../../worker/wit/deps/signing-keys.wit"
MAX_SIZE=$((2 * 1024 * 1024))  # 2MB in bytes

# The WIT here is a COPY of the worker's. A drifted copy compiles against an
# interface the host no longer provides, and fails at runtime as a missing
# import — so a drift is reported, not fixed: which side is right is a decision.
if [ -f "$WORKER_WIT" ]; then
    if ! diff -q "$WORKER_WIT" wit/signing-keys.wit >/dev/null; then
        echo "ERROR: wit/signing-keys.wit has drifted from $WORKER_WIT"
        echo ""
        diff "$WORKER_WIT" wit/signing-keys.wit || true
        echo ""
        echo "Copy the worker's version over if the interface changed:"
        echo "  cp $WORKER_WIT wit/signing-keys.wit"
        exit 1
    fi
    echo "WIT: matches the worker's"
else
    echo "WIT: worker copy not found at $WORKER_WIT — skipping the drift check"
fi

rustup target add wasm32-wasip2 2>/dev/null || true
mkdir -p "$OUT"

# build <variant> <features> <manifest> <key paths…>
build() {
    local variant=$1 features=$2 manifest=$3; shift 3
    local wasm="$OUT/signing-key-probe-$variant.wasm"
    echo ""
    echo "── $variant (--features $features) ──"
    cargo build --target wasm32-wasip2 --release --no-default-features --features "$features"
    cp "$BUILT" "$wasm"

    # The manifest must be in the artefact, and be this variant's: without it
    # the worker would hand out no keys and every call would be refused.
    if ! grep -qa 'outlayer.manifest' "$wasm"; then
        echo "ERROR: the outlayer.manifest custom section is missing from $wasm"
        exit 1
    fi
    local path
    for path in "$@"; do
        if ! grep -qa "\"path\": \"$path\"" "$wasm"; then
            echo "ERROR: $wasm does not carry the key \"$path\" of $manifest"
            exit 1
        fi
    done
    echo "Manifest section: present ($manifest: $*)"

    # The import this module exists for, and nothing of ours besides it.
    if command -v wasm-tools >/dev/null 2>&1; then
        local imports
        imports=$(wasm-tools component wit "$wasm" 2>/dev/null | grep -E '^\s*import ' || true)
        if ! grep -q 'outlayer:signing-keys/api' <<<"$imports"; then
            echo "ERROR: $wasm does not import outlayer:signing-keys/api"
            exit 1
        fi
        local foreign
        foreign=$(grep -vE 'wasi:|outlayer:signing-keys/api' <<<"$imports" || true)
        if [ -n "$foreign" ]; then
            echo "ERROR: $wasm imports more than WASI and outlayer:signing-keys:"
            echo "$foreign"
            exit 1
        fi
        echo "Imports: WASI + outlayer:signing-keys/api only"

        # The platform strips a GitHub build with `wasm-tools strip`. Whether
        # the manifest survives that step decides what a GitHub run of this
        # code declares — reported, since tests/signing_keys_e2e.sh relies on it.
        local stripped
        stripped=$(mktemp)
        wasm-tools strip "$wasm" -o "$stripped"
        if grep -qa 'outlayer.manifest' "$stripped"; then
            echo "After wasm-tools strip: the manifest survives"
        else
            echo "After wasm-tools strip: the manifest is GONE — a GitHub build of this code declares no keys"
        fi
        rm -f "$stripped"
    else
        echo "Imports: NOT CHECKED (install wasm-tools to verify)"
    fi

    local size
    size=$(stat -f%z "$wasm" 2>/dev/null || stat -c%s "$wasm" 2>/dev/null)
    if [ "$size" -gt "$MAX_SIZE" ]; then
        echo "WARNING: $wasm is over the 2MB limit for FastFS upload"
    fi
    echo "Size: $((size / 1024)) KB"
    echo "SHA256: $(shasum -a 256 "$wasm" | cut -d' ' -f1)"
}

build project        project                manifests/project.json       alpha beta
build project-v2     project,v2             manifests/project.json       alpha beta
build wasm           wasm                   manifests/wasm.json          code
build wasm-v2        wasm,v2                manifests/wasm.json          code
build project-vault  project-vault          manifests/project-vault.json alpha treasury

# Two builds of one manifest must be two hashes, or "a new version" and
# "another build" test nothing.
for pair in "project project-v2" "wasm wasm-v2"; do
    set -- $pair
    a=$(shasum -a 256 "$OUT/signing-key-probe-$1.wasm" | cut -d' ' -f1)
    b=$(shasum -a 256 "$OUT/signing-key-probe-$2.wasm" | cut -d' ' -f1)
    if [ "$a" = "$b" ]; then
        echo "ERROR: $1 and $2 have one sha256 ($a)"
        exit 1
    fi
done

echo ""
echo "OK: five variants in $OUT/"
