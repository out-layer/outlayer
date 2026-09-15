#!/bin/bash
set -e

cd "$(dirname "$0")"

WASM_FILE="target/wasm32-wasip2/release/connector-probe.wasm"
MAX_SIZE=$((2 * 1024 * 1024))  # 2MB in bytes

echo "Building WASI module (wasm32-wasip2)..."

# Add target if needed
rustup target add wasm32-wasip2 2>/dev/null || true

# The WIT copies must match the worker's, or this module is generated against
# an interface the host does not implement — which shows up at runtime as a
# component that will not instantiate, long after the change that caused it.
for w in vrf payment; do
    WORKER_WIT="../../worker/wit/deps/$w.wit"
    if [ -f "$WORKER_WIT" ]; then
        if ! diff -q "$WORKER_WIT" "wit/deps/$w.wit" >/dev/null; then
            echo "ERROR: wit/deps/$w.wit has drifted from $WORKER_WIT"
            echo ""
            diff "$WORKER_WIT" "wit/deps/$w.wit" || true
            echo ""
            echo "Update the copy in the same change that moved the worker's:"
            echo "  cp $WORKER_WIT wit/deps/$w.wit"
            exit 1
        fi
    else
        echo "WARNING: $WORKER_WIT not found — cannot check wit/deps/$w.wit for drift"
    fi
done

# Build
cargo build --target wasm32-wasip2 --release

echo ""

# Note: wasm-opt doesn't support WASI P2 components yet
# https://github.com/WebAssembly/binaryen/issues/6728

# Show file size
SIZE=$(stat -f%z "$WASM_FILE" 2>/dev/null || stat -c%s "$WASM_FILE" 2>/dev/null)
SIZE_MB=$(echo "scale=2; $SIZE / 1024 / 1024" | bc)
SIZE_KB=$(echo "scale=0; $SIZE / 1024" | bc)

echo "WASM module: $WASM_FILE"
echo "Size: ${SIZE_KB} KB (${SIZE_MB} MB)"

# The connector manifest must be present in the artefact.
#
# It declares the outbound allowlist the TEE worker enforces, and it is covered
# by the SHA256 below — which is the whole reason it lives inside the wasm
# rather than in a file next to it. If the linker dropped the static (a missing
# `#[used]`, say), this module would publish with NO allowlist and, being a
# connector, would be refused all outbound network at runtime. Loud here beats
# discovering it in production.
# Both host interfaces must actually be imported. A build that dropped them
# would still run every existing operation and silently test nothing in the two
# that were added for it.
if command -v wasm-tools >/dev/null 2>&1; then
    for iface in "near:vrf" "near:payment"; do
        if ! wasm-tools component wit "$WASM_FILE" 2>/dev/null | grep -q "$iface"; then
            echo ""
            echo "ERROR: $WASM_FILE does not import $iface"
            echo "The vrf/refund operations depend on it; a build without it tests nothing."
            exit 1
        fi
    done
    echo "OK: near:vrf and near:payment are imported"
fi

if ! grep -qa 'outlayer.manifest' "$WASM_FILE"; then
    echo ""
    echo "ERROR: outlayer.manifest custom section is missing from $WASM_FILE"
    echo "See wasi-examples/CONNECTOR_MANIFEST.md"
    exit 1
fi
echo "Manifest section: present"

# Validate the words the manifest uses, HERE rather than at runtime.
#
# A `window` or `applies` the coordinator does not recognise is not an error
# there — it is read at its strictest, which binds more callers than the author
# meant and is noticed only when somebody is refused. A typo belongs where it
# can be seen: at the build that produces the artefact.
python3 - "$(dirname "$0")/manifest.json" <<'PY'
import json, sys
WINDOWS = {"day", "week", "month"}
APPLIES = {"everyone", "unpaid", "covered"}
m = json.load(open(sys.argv[1]))
bad = []
for limit in m.get("limits", []):
    if limit.get("window") not in WINDOWS:
        bad.append(f"window {limit.get('window')!r} (allowed: {sorted(WINDOWS)})")
    if limit.get("applies", "everyone") not in APPLIES:
        bad.append(f"applies {limit.get('applies')!r} (allowed: {sorted(APPLIES)})")
if bad:
    print("ERROR: manifest declares words the coordinator does not know:")
    for b in bad:
        print("  -", b)
    print("Unknown values are read at their STRICTEST, which silently binds more")
    print("callers than you meant. See wasi-examples/CONNECTOR_MANIFEST.md")
    sys.exit(1)
print("Manifest vocabulary: ok")
PY

# The manifest, the code and the README must name the SAME operations.
#
# Three lists drift apart silently and each way costs something different. An
# operation the code serves but the manifest omits is undeclared surface; one
# the manifest declares and the code does not serve answers every caller with a
# refusal that reads like a platform fault; one that no README documents is one
# nobody will ever call. The module cannot be host-compiled to check this from
# inside — `outlayer.manifest` is a wasm-only link section — so it is read off
# the source here, where every build passes.
python3 - "$(dirname "$0")" <<'OPSPY'
import json, re, sys, pathlib
root = pathlib.Path(sys.argv[1])
manifest = set(json.load(open(root / "manifest.json")).get("operations", []))

source = (root / "src" / "main.rs").read_text(encoding="utf-8")
start = source.index("fn run(")
end = source.index("\n}\n", start)
# `run`'s own match only: `budget` holds a nested one whose arms are MODES.
dispatched = set(re.findall(r'"([a-z_]+)" =>', source[start:end]))

readme = (root / "README.md").read_text(encoding="utf-8")
documented = {op for op in manifest | dispatched if re.search(r"`" + re.escape(op) + r"`", readme)}

problems = []
if dispatched - manifest:
    problems.append("served but not declared in the manifest: %s" % sorted(dispatched - manifest))
if manifest - dispatched:
    problems.append("declared in the manifest but not served: %s" % sorted(manifest - dispatched))
if manifest - documented:
    problems.append("not documented in README.md: %s" % sorted(manifest - documented))
if problems:
    print("ERROR: the manifest, the code and the README disagree about the operations:")
    for p in problems:
        print("  -", p)
    sys.exit(1)
print("Operations: manifest, code and README agree (%d)" % len(manifest))
OPSPY

# The variables this probe reports on are the ones the worker injects. A
# variable the worker gained and this list lacks is reported by `env` as
# "unknown" — which is fine at runtime — but a list that drifted is a probe
# that no longer knows what it is checking, so the drift is caught here.
WORKER_MAIN="../../worker/src/main.rs"
WORKER_P2="../../worker/src/executor/wasi_p2.rs"
if [ -f "$WORKER_MAIN" ] && [ -f "$WORKER_P2" ]; then
    python3 - src/main.rs "$WORKER_MAIN" "$WORKER_P2" <<'PY'
import re, sys
probe, worker_main, worker_p2 = (open(p).read() for p in sys.argv[1:4])
def block(name):
    m = re.search(r'const %s: &\[&str\] = &\[(.*?)\];' % name, probe, re.S)
    return set(re.findall(r'"([A-Z_]+)"', m.group(1))) if m else set()
known = block("SYSTEM_VARS") | block("CONDITIONAL_VARS")
injected = set(re.findall(r'env_vars\.insert\(\s*"([A-Z_]+)"', worker_main))
injected |= set(re.findall(r'"([A-Z_]+)"\.to_string\(\),', worker_main))
injected |= set(re.findall(r'wasi_builder\.env\("([A-Z_]+)"', worker_p2))
injected.discard("_")
missing = sorted(injected - known)
stale = sorted(known - injected)
if missing or stale:
    if missing:
        print("ERROR: the worker injects variables this probe does not list:", ", ".join(missing))
    if stale:
        print("ERROR: this probe lists variables the worker does not inject:", ", ".join(stale))
    print("Update SYSTEM_VARS / CONDITIONAL_VARS in src/main.rs.")
    sys.exit(1)
print("System variables: probe list matches the worker's")
PY
else
    echo "WARNING: worker sources not found — skipping the system-variable drift check"
fi

# Show SHA256 hash (for FastFS/contract)
HASH=$(shasum -a 256 "$WASM_FILE" | cut -d' ' -f1)
echo "SHA256: $HASH"

# Warning if over 2MB
if [ "$SIZE" -gt "$MAX_SIZE" ]; then
    echo ""
    echo "WARNING: File size exceeds 2MB limit for FastFS upload!"
    echo "Current: ${SIZE_MB} MB, Limit: 2.00 MB"
    echo ""
    echo "Tips to reduce size:"
    echo "  - Install wasm-opt: brew install binaryen"
    echo "  - Check for unused dependencies in Cargo.toml"
    echo "  - Use 'cargo bloat' to find largest functions"
else
    echo "OK: Size is within 2MB limit for FastFS"
fi
