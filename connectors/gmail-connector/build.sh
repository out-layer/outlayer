#!/bin/bash
set -e

cd "$(dirname "$0")"

WASM_FILE="target/wasm32-wasip2/release/gmail-connector.wasm"
MAX_SIZE=$((2 * 1024 * 1024))  # 2MB in bytes

echo "Building WASI module (wasm32-wasip2)..."
rustup target add wasm32-wasip2 2>/dev/null || true
cargo build --target wasm32-wasip2 --release
echo ""

SIZE=$(stat -f%z "$WASM_FILE" 2>/dev/null || stat -c%s "$WASM_FILE" 2>/dev/null)
echo "WASM module: $WASM_FILE"
echo "Size: $((SIZE / 1024)) KB"

# The manifest must be in the artefact: it is the outbound allowlist the worker
# enforces, and it is covered by the SHA256 below. A build that dropped it would
# publish with no allowlist and, being a connector, be refused all network.
if ! grep -qa 'outlayer.manifest' "$WASM_FILE"; then
    echo "ERROR: outlayer.manifest custom section is missing from $WASM_FILE"
    echo "See docs/CONNECTORS.md"
    exit 1
fi
echo "Manifest section: present"

# The manifest's operations must be exactly the ones the code dispatches on, and
# its limit words must be ones the platform knows: an unknown word is read at its
# strictest, which would bind every caller instead of the intended few.
python3 - manifest.json src/main.rs <<'PY'
import json, re, sys
m = json.load(open(sys.argv[1]))
src = open(sys.argv[2]).read()
declared = set(m["operations"])
advertised = set(re.findall(r'"([a-z_]+)"', re.search(r'const OPERATIONS.*?\];', src, re.S).group(0)))
dispatched = set(re.findall(r'^\s*"([a-z_]+)" => ', re.search(r'fn run\(.*?\n\}\n', src, re.S).group(0), re.M))
WINDOWS = {"day", "week", "month"}; APPLIES = {"everyone", "unpaid", "covered"}
bad = []
if declared != advertised:
    bad.append(f"manifest {sorted(declared)} vs the OPERATIONS list {sorted(advertised)}")
if declared != dispatched:
    bad.append(f"manifest {sorted(declared)} vs dispatched {sorted(dispatched)}")
for limit in m.get("limits", []):
    if limit.get("window") not in WINDOWS:
        bad.append(f"window {limit.get('window')!r}")
    if limit.get("applies", "everyone") not in APPLIES:
        bad.append(f"applies {limit.get('applies')!r}")
    if limit.get("operation", "").split(":")[0] not in declared:
        bad.append(f"limit on unknown operation {limit.get('operation')!r}")
# An account connected through app.outlayer.ai/connect/gmail stores only a
# refresh token, and OUR OAuth client completes it at run time. That client
# reaches a run only as this connector's author secret: undeclared, every such
# account is refused for want of a client; declared but unstored, every run of
# the project is refused.
profile = (m.get("author_secrets") or {}).get("profile")
if not isinstance(profile, str) or not profile.strip():
    bad.append("author_secrets.profile: a connected account brings only a refresh token, and the OAuth client that completes it arrives only as an author secret")
# `describe`: what the developer page shows. Held to the code here — every
# dispatched operation described and nothing else, every parameter a field
# some input struct declares — so a description that falls behind the code
# fails the build rather than the page.
import glob
desc = m.get("describe") or {}
described = set((desc.get("operations") or {}).keys())
if described != dispatched:
    bad.append(f"describe.operations {sorted(described)} vs dispatched {sorted(dispatched)}")
if not isinstance(desc.get("summary"), str) or not desc.get("summary", "").strip():
    bad.append("describe.summary is missing")
fields = set()
for f in glob.glob("src/**/*.rs", recursive=True):
    for body in re.findall(r'struct \w+\s*\{(.*?)\n\}', open(f).read(), re.S):
        fields |= set(re.findall(r'^\s*(?:pub(?:\(crate\))? )?([a-z_][a-z0-9_]*)\s*:', body, re.M))
        fields |= set(re.findall(r'#\[serde\(rename = "([a-z_]+)"', body))
    # A field read straight off the JSON (`input.get("reply_pubkey")`) is a
    # parameter too.
    fields |= set(re.findall(r'\.get\("([a-z_]+)"\)', open(f).read()))
for name, o in (desc.get("operations") or {}).items():
    if o.get("class") not in {"read", "write"}:
        bad.append(f"describe.{name}.class {o.get('class')!r}")
    if not isinstance(o.get("doc"), str) or not o["doc"].strip():
        bad.append(f"describe.{name}.doc is missing")
    for prm in o.get("params", []):
        if prm.get("name") not in fields:
            bad.append(f"describe.{name}: parameter {prm.get('name')!r} is not a field of any input struct")
        if not isinstance(prm.get("type"), str):
            bad.append(f"describe.{name}.{prm.get('name')}: no type")
if bad:
    print("ERROR:"); [print("  -", b) for b in bad]; sys.exit(1)
print(f"Manifest: {len(declared)} operations agree with the code; limits are well formed")
PY

HASH=$(shasum -a 256 "$WASM_FILE" | cut -d' ' -f1)
echo "SHA256: $HASH"

if [ "$SIZE" -gt "$MAX_SIZE" ]; then
    echo "ERROR: Size exceeds the 2MB FastFS limit"
    exit 1
fi
echo "OK: Size is within 2MB limit for FastFS"
