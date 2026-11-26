#!/usr/bin/env bash
# A DAO release rehearsed on near-sandbox (tests/upgrade_sandbox.rs): the code that runs on
# dao.outlayer.<net> today builds a state, then governance upgrades it to the release.
#
#   keystore-dao-contract/tests/upgrade_sandbox.sh [--network testnet|mainnet] [--old <wasm>] [--new <wasm>]
#
#   --network  whose deployed code to start from (default testnet)
#   --old      start from this wasm instead of the deployed code
#   --new      the release (default target/near/keystore_dao_contract.wasm, the output of
#              `cargo near build reproducible-wasm`)
#
# The deployed code is read through the keyed RPC (tests/lib/rpc.sh). The sandbox runs in
# docker on this machine; nothing is sent to testnet or mainnet.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE="$(dirname "$HERE")"
REPO="$(dirname "$CRATE")"
SANDBOX_IMAGE="nearprotocol/sandbox:2.14.0@sha256:41ddcc333e821b2914f853e8a19436a34df1b5e89e253ae7afba39186c2a7240"

NETWORK=testnet
OLD=""
NEW="$CRATE/target/near/keystore_dao_contract.wasm"
while [ $# -gt 0 ]; do
    case "$1" in
        --network) NETWORK="$2"; shift 2 ;;
        --old) OLD="$2"; shift 2 ;;
        --new) NEW="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
case "$NETWORK" in
    testnet) DAO=dao.outlayer.testnet ;;
    mainnet) DAO=dao.outlayer.near ;;
    *) echo "--network is testnet or mainnet" >&2; exit 2 ;;
esac
[ -f "$NEW" ] || { echo "no release wasm at $NEW: cargo near build reproducible-wasm" >&2; exit 1; }

WORK="$(mktemp -d)"
NAME="dao-upgrade-sandbox-$$"
SANDBOX_HOME="$WORK/sandbox"
mkdir -p "$SANDBOX_HOME"
cleanup() {
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    # The sandbox writes its home as the container's user: empty it from inside.
    docker run --rm -v "$SANDBOX_HOME:/data" --entrypoint sh "$SANDBOX_IMAGE" -c 'rm -rf /data/*' >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

if [ -z "$OLD" ]; then
    # shellcheck source=../../tests/lib/rpc.sh
    source "$REPO/tests/lib/rpc.sh"
    echo "RPC: $(rpc_url_public)"
    OLD="$WORK/deployed.wasm"
    # The URL carries the key: python reads it from the environment, never from a command line.
    RPC_URL="$RPC_URL" python3 -I - "$DAO" "$OLD" <<'EOF'
import base64, hashlib, json, os, sys, urllib.request

dao, out = sys.argv[1], sys.argv[2]
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def query(params):
    body = json.dumps({"jsonrpc": "2.0", "id": "x", "method": "query", "params": params}).encode()
    req = urllib.request.Request(os.environ["RPC_URL"], body, {"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        answer = json.load(r)
    if "result" not in answer:
        sys.exit(f"{params['request_type']} of {dao}: {answer.get('error')}")
    return answer["result"]

def b58(b):
    n, s = int.from_bytes(b, "big"), ""
    while n:
        n, r = divmod(n, 58)
        s = B58[r] + s
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + s

account = query({"request_type": "view_account", "finality": "final", "account_id": dao})
code = base64.b64decode(query({"request_type": "view_code", "block_id": account["block_height"], "account_id": dao})["code_base64"])
digest = b58(hashlib.sha256(code).digest())
if digest != account["code_hash"]:
    sys.exit(f"the code read from {dao} hashes to {digest}, the account reports {account['code_hash']}")
open(out, "wb").write(code)
print(f"deployed code of {dao}: {digest} ({len(code)} bytes, block {account['block_height']})")
EOF
fi
[ -f "$OLD" ] || { echo "no wasm at $OLD" >&2; exit 1; }

# A fresh sandbox home, then a state view without the RPC's size limit (the test compares the
# DAO's raw state, which a blob and the collaterals put far above it).
docker run --rm -v "$SANDBOX_HOME:/data" --entrypoint near-sandbox "$SANDBOX_IMAGE" \
    --home /data init --fast --account-id sandbox --test-seed sandbox --chain-id sandbox >/dev/null
python3 -I - "$SANDBOX_HOME/config.json" <<'EOF'
import json, sys
path = sys.argv[1]
config = json.load(open(path))
config["trie_viewer_state_size_limit"] = 1_000_000_000
json.dump(config, open(path, "w"), indent=2)
EOF

PORT="$(python3 -I -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
docker run -d --name "$NAME" -p "127.0.0.1:$PORT:3030" -v "$SANDBOX_HOME:/data" "$SANDBOX_IMAGE" >/dev/null
python3 -I - "$PORT" <<'EOF'
import sys, time, urllib.request
url = f"http://127.0.0.1:{sys.argv[1]}/status"
for _ in range(120):
    try:
        urllib.request.urlopen(url, timeout=2).read()
        sys.exit(0)
    except Exception:
        time.sleep(1)
sys.exit("the sandbox did not answer in 120 s")
EOF
echo "sandbox: $SANDBOX_IMAGE on 127.0.0.1:$PORT"

DAO_SANDBOX_RPC="http://127.0.0.1:$PORT" \
DAO_SANDBOX_HOME="$SANDBOX_HOME" \
DAO_OLD_WASM="$OLD" \
DAO_NEW_WASM="$NEW" \
    cargo test --manifest-path "$CRATE/Cargo.toml" --test upgrade_sandbox -- --ignored --nocapture
