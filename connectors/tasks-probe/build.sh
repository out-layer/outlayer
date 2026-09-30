#!/bin/bash
set -e

cd "$(dirname "$0")"

WASM_FILE="target/wasm32-wasip2/release/tasks-probe.wasm"
MAX_SIZE=$((2 * 1024 * 1024))  # 2MB in bytes

echo "Building WASI module (wasm32-wasip2)..."
rustup target add wasm32-wasip2 2>/dev/null || true

# The SDK's copy of the interface must be the worker's, or this module is
# generated against an interface the host does not implement.
if ! diff -q ../../worker/wit/deps/tasks.wit ../../sdk/outlayer/wit/deps/tasks.wit >/dev/null; then
    echo "ERROR: sdk/outlayer/wit/deps/tasks.wit has drifted from worker/wit/deps/tasks.wit"
    exit 1
fi

cargo build --target wasm32-wasip2 --release
echo ""

SIZE=$(stat -f%z "$WASM_FILE" 2>/dev/null || stat -c%s "$WASM_FILE" 2>/dev/null)
echo "WASM module: $WASM_FILE"
echo "Size: $((SIZE / 1024)) KB"

if ! grep -qa 'outlayer.manifest' "$WASM_FILE"; then
    echo "ERROR: outlayer.manifest custom section is missing from $WASM_FILE"
    exit 1
fi
echo "Manifest section: present"

if command -v wasm-tools >/dev/null 2>&1; then
    if ! wasm-tools component wit "$WASM_FILE" 2>/dev/null | grep -q "outlayer:tasks"; then
        echo "ERROR: $WASM_FILE does not import outlayer:tasks; a build without it tests nothing"
        exit 1
    fi
    echo "OK: outlayer:tasks is imported"
fi

# The manifest and the code must name the same operations.
python3 - manifest.json src/main.rs ../../sdk/outlayer/src/tasks.rs <<'PY'
import json, re, sys
m = json.load(open(sys.argv[1]))
src = open(sys.argv[2]).read()
declared = set(m["operations"])
advertised = set(re.findall(r'"([a-z_]+)"', re.search(r'const OPERATIONS.*?\];', src, re.S).group(0)))
dispatched = set(re.findall(r'^\s*"([a-z_]+)" => ', re.search(r'fn run\(.*?\n\}\n', src, re.S).group(0), re.M))
sdk = {"task_status", "task_cancel", "task_delete", "tasks", "tasks_unlock"}
bad = []
if declared != advertised:
    bad.append(f"manifest {sorted(declared)} vs the OPERATIONS list {sorted(advertised)}")
if declared != dispatched | sdk:
    bad.append(f"manifest {sorted(declared)} vs dispatched {sorted(dispatched | sdk)}")
if m.get("tasks") is not True:
    bad.append('the manifest does not say "tasks": true')
# `describe`: every operation described and nothing else, and every parameter
# a name the code reads off the input — here, or in the SDK for the answer to
# a task and for the operations the SDK serves.
desc = m.get("describe") or {}
described = desc.get("operations") or {}
if set(described) != declared:
    bad.append(f"describe.operations {sorted(described)} vs the manifest {sorted(declared)}")
if not isinstance(desc.get("summary"), str) or not desc.get("summary", "").strip():
    bad.append("describe.summary is missing")
read = set()
for text in (src, open(sys.argv[3]).read()):
    read |= set(re.findall(r'\binput\s*\.get\("([a-z_]+)"\)', text))
    read |= set(re.findall(r'\btext(?:_of)?\(input, "([a-z_]+)"', text))
for name, o in described.items():
    if o.get("class") not in {"read", "write"}:
        bad.append(f"describe.{name}.class {o.get('class')!r}")
    if not isinstance(o.get("doc"), str) or not o["doc"].strip():
        bad.append(f"describe.{name}.doc is missing")
    for prm in o.get("params", []):
        if prm.get("name") not in read:
            bad.append(f"describe.{name}: parameter {prm.get('name')!r} is not read off the input")
        if not isinstance(prm.get("type"), str):
            bad.append(f"describe.{name}.{prm.get('name')}: no type")
for prm in read - {"operation"} - {p.get("name") for o in described.values() for p in o.get("params", [])}:
    bad.append(f"the code reads `{prm}` off the input and no operation describes it")
if bad:
    print("ERROR:"); [print("  -", b) for b in bad]; sys.exit(1)
print(f"Manifest: {len(declared)} operations agree with the code")
PY

HASH=$(shasum -a 256 "$WASM_FILE" | cut -d' ' -f1)
echo "SHA256: $HASH"

if [ "$SIZE" -gt "$MAX_SIZE" ]; then
    echo "ERROR: Size exceeds the 2MB FastFS limit"
    exit 1
fi
echo "OK: Size is within 2MB limit for FastFS"
