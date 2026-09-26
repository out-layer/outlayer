#!/bin/bash
# Builds every variant of the probe into target/variants/:
#
#   signing-key-probe-project.wasm        alpha, beta — bind "project"
#   signing-key-probe-project-v2.wasm     the same manifest, another sha256
#   signing-key-probe-project-pred.wasm   alpha — caller "predecessor", bind "project"
#   signing-key-probe-wasm.wasm           code — bind "wasm"
#   signing-key-probe-wasm-v2.wasm        the same manifest, another sha256
#   signing-key-probe-project-vault.wasm  alpha, and treasury with a vault
#   signing-key-probe-project-secp.wasm   evm (secp256k1), alpha (ed25519) — bind "project"
#   signing-key-probe-wasm-secp.wasm      code-evm (secp256k1) — bind "wasm"
#   signing-key-probe-encryption.wasm        signing alpha; encryption alpha, beta
#   signing-key-probe-encryption-v2.wasm     the same manifest, another sha256
#   signing-key-probe-encryption-storage.wasm  the encryption keys, and near:storage
#   signing-key-probe-encryption-storage-pred.wasm  the same, storage_account "predecessor"
#   signing-key-probe-encryption-wasm.wasm   encryption code — bind "wasm"
#   signing-key-probe-encryption-wasm-v2.wasm  the same manifest, another sha256
#   signing-key-probe-encryption-vault.wasm  encryption alpha, and treasury with a vault
#   signing-key-probe-encryption-pred.wasm   encryption alpha — caller "predecessor"
#   signing-key-probe-encryption-typed.wasm  encryption alpha with a `type` (refused)
#
# and checks each: the manifest section is in the artefact and is the right
# one, the module imports outlayer:signing-keys — and, for the encryption
# builds only, outlayer:encryption-keys; for the two `encryption-storage`
# builds only, near:storage — and nothing else of ours, and the two builds of one
# manifest really are two hashes.
set -e

cd "$(dirname "$0")"

OUT="target/variants"
BUILT="target/wasm32-wasip2/release/signing-key-probe.wasm"
MAX_SIZE=$((2 * 1024 * 1024))  # 2MB in bytes

# The WIT here is a COPY of the worker's. A drifted copy compiles against an
# interface the host no longer provides, and fails at runtime as a missing
# import — so a drift is reported, not fixed: which side is right is a decision.
# check_wit <worker's file> <this probe's copy>
check_wit() {
    local worker=$1 copy=$2
    if [ -f "$worker" ]; then
        if ! diff -q "$worker" "$copy" >/dev/null; then
            echo "ERROR: $copy has drifted from $worker"
            echo ""
            diff "$worker" "$copy" || true
            echo ""
            echo "Copy the worker's version over if the interface changed:"
            echo "  cp $worker $copy"
            exit 1
        fi
        echo "WIT: $copy matches the worker's"
    else
        echo "WIT: worker copy not found at $worker — skipping the drift check"
    fi
}
check_wit ../../worker/wit/deps/signing-keys.wit wit/signing-keys.wit
check_wit ../../worker/wit/deps/encryption-keys.wit wit-encryption/encryption-keys.wit
check_wit ../../worker/wit/deps/storage.wit wit-storage/storage.wit

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

    # The imports this module exists for, and nothing of ours besides them:
    # outlayer:encryption-keys exactly in the encryption builds, near:storage
    # exactly in the `encryption-storage` builds. A build that runs directly
    # from its wasm URL must not import near:storage: the worker refuses a
    # module that does on a run with no project.
    if command -v wasm-tools >/dev/null 2>&1; then
        local imports
        imports=$(wasm-tools component wit "$wasm" 2>/dev/null | grep -E '^\s*import ' || true)
        if ! grep -q 'outlayer:signing-keys/api' <<<"$imports"; then
            echo "ERROR: $wasm does not import outlayer:signing-keys/api"
            exit 1
        fi
        local wants_enc=no
        case "$features" in encryption*) wants_enc=yes ;; esac
        if [ "$wants_enc" = yes ] && ! grep -q 'outlayer:encryption-keys/api' <<<"$imports"; then
            echo "ERROR: $wasm does not import outlayer:encryption-keys/api"
            exit 1
        fi
        if [ "$wants_enc" = no ] && grep -q 'outlayer:encryption-keys/api' <<<"$imports"; then
            echo "ERROR: $wasm imports outlayer:encryption-keys/api and declares no encryption key"
            exit 1
        fi
        local wants_storage=no
        case "$features" in encryption-storage|encryption-storage,*|encryption-storage-pred|encryption-storage-pred,*) wants_storage=yes ;; esac
        if [ "$wants_storage" = yes ] && ! grep -q 'near:storage/api' <<<"$imports"; then
            echo "ERROR: $wasm does not import near:storage/api"
            exit 1
        fi
        if [ "$wants_storage" = no ] && grep -q 'near:storage/api' <<<"$imports"; then
            echo "ERROR: $wasm imports near:storage/api — only the encryption-storage builds may"
            exit 1
        fi
        local foreign
        foreign=$(grep -vE 'wasi:|outlayer:signing-keys/api|outlayer:encryption-keys/api|near:storage/api' <<<"$imports" || true)
        if [ -n "$foreign" ]; then
            echo "ERROR: $wasm imports more than WASI, outlayer:signing-keys, outlayer:encryption-keys and near:storage:"
            echo "$foreign"
            exit 1
        fi
        if [ "$wants_storage" = yes ]; then
            echo "Imports: WASI + outlayer:signing-keys/api + outlayer:encryption-keys/api + near:storage/api only"
        elif [ "$wants_enc" = yes ]; then
            echo "Imports: WASI + outlayer:signing-keys/api + outlayer:encryption-keys/api only"
        else
            echo "Imports: WASI + outlayer:signing-keys/api only"
        fi

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
build project-pred   project-pred           manifests/project-pred.json  alpha
build wasm           wasm                   manifests/wasm.json          code
build wasm-v2        wasm,v2                manifests/wasm.json          code
build project-vault  project-vault          manifests/project-vault.json alpha treasury
build project-secp   project-secp           manifests/project-secp.json  evm alpha
build wasm-secp      wasm-secp              manifests/wasm-secp.json     code-evm
build encryption         encryption          manifests/encryption.json       alpha beta
build encryption-v2      encryption,v2       manifests/encryption.json       alpha beta
build encryption-storage encryption-storage  manifests/encryption-storage.json alpha beta
build encryption-storage-pred encryption-storage-pred manifests/encryption-storage-pred.json alpha beta
build encryption-wasm    encryption-wasm     manifests/encryption-wasm.json  code
build encryption-wasm-v2 encryption-wasm,v2  manifests/encryption-wasm.json  code
build encryption-vault   encryption-vault    manifests/encryption-vault.json alpha treasury
build encryption-pred    encryption-pred     manifests/encryption-pred.json  alpha
build encryption-typed   encryption-typed    manifests/encryption-typed.json alpha

# Two builds of one manifest must be two hashes, or "a new version" and
# "another build" test nothing.
for pair in "project project-v2" "wasm wasm-v2" "encryption encryption-v2" "encryption-wasm encryption-wasm-v2"; do
    set -- $pair
    a=$(shasum -a 256 "$OUT/signing-key-probe-$1.wasm" | cut -d' ' -f1)
    b=$(shasum -a 256 "$OUT/signing-key-probe-$2.wasm" | cut -d' ' -f1)
    if [ "$a" = "$b" ]; then
        echo "ERROR: $1 and $2 have one sha256 ($a)"
        exit 1
    fi
done

# The secp256k1 builds must declare a secp256k1 key, and no other build one.
for variant in project project-v2 project-pred wasm wasm-v2 project-vault project-secp wasm-secp \
               encryption encryption-v2 encryption-storage encryption-storage-pred encryption-wasm encryption-wasm-v2 \
               encryption-vault encryption-pred encryption-typed; do
    wasm="$OUT/signing-key-probe-$variant.wasm"
    case "$variant" in
        *-secp)
            if ! grep -qa '"type": "secp256k1"' "$wasm"; then
                echo "ERROR: $wasm declares no secp256k1 key"
                exit 1
            fi ;;
        *)
            if grep -qa '"type": "secp256k1"' "$wasm"; then
                echo "ERROR: $wasm declares a secp256k1 key"
                exit 1
            fi ;;
    esac
done

# Exactly one build names a `type` on an encryption key, exactly one
# declares a predecessor key, and exactly one keeps its storage in the
# predecessor's cell.
for variant in encryption encryption-v2 encryption-storage encryption-storage-pred encryption-wasm encryption-wasm-v2 \
               encryption-vault encryption-pred encryption-typed; do
    wasm="$OUT/signing-key-probe-$variant.wasm"
    typed=no; grep -qa '"type": "xchacha20poly1305"' "$wasm" && typed=yes
    pred=no; grep -qa '"caller": "predecessor"' "$wasm" && pred=yes
    cell=no; grep -qa '"storage_account": "predecessor"' "$wasm" && cell=yes
    want_typed=no; [ "$variant" = encryption-typed ] && want_typed=yes
    want_pred=no; [ "$variant" = encryption-pred ] && want_pred=yes
    want_cell=no; [ "$variant" = encryption-storage-pred ] && want_cell=yes
    if [ "$typed" != "$want_typed" ] || [ "$pred" != "$want_pred" ] || [ "$cell" != "$want_cell" ]; then
        echo "ERROR: $wasm: a type on an encryption key $typed (want $want_typed), a predecessor key $pred (want $want_pred), a predecessor storage cell $cell (want $want_cell)"
        exit 1
    fi
done

# Exactly one of the signing-only builds declares a predecessor key.
for variant in project project-v2 project-pred wasm wasm-v2 project-vault project-secp wasm-secp; do
    wasm="$OUT/signing-key-probe-$variant.wasm"
    pred=no; grep -qa '"caller": "predecessor"' "$wasm" && pred=yes
    want_pred=no; [ "$variant" = project-pred ] && want_pred=yes
    if [ "$pred" != "$want_pred" ]; then
        echo "ERROR: $wasm: a predecessor signing key $pred (want $want_pred)"
        exit 1
    fi
done

echo ""
echo "OK: seventeen variants in $OUT/"
