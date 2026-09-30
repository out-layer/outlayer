#!/bin/bash
# Builds every variant of the probe into target/variants/:
#
#   caller-gate-probe-open.wasm               no callers block
#   caller-gate-probe-open-v2.wasm            the same manifest, another sha256
#   caller-gate-probe-direct-only.wasm        contract deny, https deny
#   caller-gate-probe-contract-any.wasm       direct deny, https deny
#   caller-gate-probe-contract-relay.wasm     contract only relay.outlayer-alice.testnet
#   caller-gate-probe-contract-deputy.wasm    contract only deputy.outlayer-alice.testnet
#   caller-gate-probe-https-only.wasm         direct deny, contract deny
#   caller-gate-probe-meta-tx.wasm            contract deny, meta_tx allow
#   caller-gate-probe-tasks-direct-deny.wasm  tasks with direct deny (refused)
#
# and checks each: the manifest section is in the artefact and is this
# variant's, the module imports nothing but WASI, the platform's strip keeps
# the section, and the two builds of one manifest are two hashes.
set -e

cd "$(dirname "$0")"

OUT="target/variants"
BUILT="target/wasm32-wasip2/release/caller-gate-probe.wasm"

rustup target add wasm32-wasip2 2>/dev/null || true
mkdir -p "$OUT"

# build <variant> <features> <a string only this variant's manifest carries>
build() {
    local variant=$1 features=$2 marker=$3
    local wasm="$OUT/caller-gate-probe-$variant.wasm"
    echo ""
    echo "── $variant (--features $features) ──"
    cargo build --target wasm32-wasip2 --release --no-default-features --features "$features"
    cp "$BUILT" "$wasm"

    if ! grep -qa 'outlayer.manifest' "$wasm"; then
        echo "ERROR: the outlayer.manifest custom section is missing from $wasm"
        exit 1
    fi
    if ! grep -qa "$marker" "$wasm"; then
        echo "ERROR: $wasm does not carry its manifest ($marker)"
        exit 1
    fi
    echo "Manifest section: present ($marker)"

    if command -v wasm-tools >/dev/null 2>&1; then
        local foreign
        foreign=$(wasm-tools component wit "$wasm" 2>/dev/null | grep -E '^\s*import ' | grep -v 'wasi:' || true)
        if [ -n "$foreign" ]; then
            echo "ERROR: $wasm imports more than WASI:"
            echo "$foreign"
            exit 1
        fi
        echo "Imports: WASI only"
        local stripped
        stripped=$(mktemp)
        wasm-tools strip --delete '^(\.debug_.*|producers|target_features|linking|reloc\..*|sourceMappingURL|external_debug_info|component-name)$' "$wasm" -o "$stripped"
        if ! grep -qa 'outlayer.manifest' "$stripped"; then
            echo "ERROR: the platform's strip removed the manifest" >&2
            exit 1
        fi
        rm -f "$stripped"
        echo "After the platform's strip: the manifest survives"
    else
        echo "Imports: NOT CHECKED (install wasm-tools to verify)"
    fi
    echo "SHA256: $(shasum -a 256 "$wasm" | cut -d' ' -f1)"
}

build open              open              'no callers block'
build open-v2           open,v2           'no callers block'
build direct-only       direct-only       'Caller-gate probe (direct only)'
build contract-any      contract-any      'Caller-gate probe (through a contract only)'
build contract-relay    contract-relay    '"only": \["relay.outlayer-alice.testnet"\]'
build contract-deputy   contract-deputy   '"only": \["deputy.outlayer-alice.testnet"\]'
build https-only        https-only        'Caller-gate probe (HTTPS only)'
build meta-tx           meta-tx           '"meta_tx": "allow"'
build tasks-direct-deny tasks-direct-deny '"tasks": true'

a=$(shasum -a 256 "$OUT/caller-gate-probe-open.wasm" | cut -d' ' -f1)
b=$(shasum -a 256 "$OUT/caller-gate-probe-open-v2.wasm" | cut -d' ' -f1)
if [ "$a" = "$b" ]; then
    echo "ERROR: open and open-v2 have one sha256 ($a)"
    exit 1
fi

# Only the open builds go without a callers block.
for variant in open open-v2 direct-only contract-any contract-relay contract-deputy https-only meta-tx tasks-direct-deny; do
    has=no; grep -qa '"callers"' "$OUT/caller-gate-probe-$variant.wasm" && has=yes
    want=yes; case "$variant" in open|open-v2) want=no ;; esac
    if [ "$has" != "$want" ]; then
        echo "ERROR: caller-gate-probe-$variant.wasm: a callers block $has (want $want)"
        exit 1
    fi
done

echo ""
echo "OK: nine variants in $OUT/"
