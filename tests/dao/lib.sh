# Shared helpers for the DAO governance suites (tests/dao/*.sh). Source, do not run.
#
# A separate set of the three contracts on testnet, under TEST_ROOT:
#   $TEST_ROOT              main contract (the outlayer.<net> role)
#   dao.$TEST_ROOT          keystore DAO — governance of all three
#   worker.$TEST_ROOT       register contract (worker keys)
#   owner.$TEST_ROOT        the ops owner of all three
# The DAO account differs from dao.outlayer.testnet, so nothing here touches the live
# contracts, and MPC would derive a different master for it.
#
# Keys: every account above and the members are in near-cli's legacy keychain
# (~/.near-credentials/testnet). Reads go through the keyed RPC (tests/lib/rpc.sh).

set -euo pipefail

NETWORK=testnet
_DAO_SUITE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$_DAO_SUITE_DIR/../.." && pwd)"
# shellcheck source=../lib/rpc.sh
source "$REPO_ROOT/tests/lib/rpc.sh"

TEST_ROOT="${TEST_ROOT:-testoutlayerdao.testnet}"
MAIN="$TEST_ROOT"
DAO="dao.$TEST_ROOT"
WORKER="worker.$TEST_ROOT"
OWNER="owner.$TEST_ROOT"
M1="${M1:-outlayer-alice.testnet}"
M2="${M2:-outlayer-bob.testnet}"
M3="${M3:-outlayer-carol.testnet}"
STRANGER="${STRANGER:-outlayer-daniel.testnet}"
# Pays blob deposits (refunded when the upgrade executes or the blob is removed).
STORER="${STORER:-$M1}"
MPC_CONTRACT="v1.signer-prod.testnet"

WASM_MAIN="${WASM_MAIN:-$REPO_ROOT/contract/target/near/outlayer_contract.wasm}"
WASM_DAO="${WASM_DAO:-$REPO_ROOT/keystore-dao-contract/target/near/keystore_dao_contract.wasm}"
WASM_WORKER="${WASM_WORKER:-$REPO_ROOT/register-contract/target/near/register_contract.wasm}"
FIXTURES="$REPO_ROOT/keystore-dao-contract/src/testdata"

PASS=0
FAIL=0
LAST_OUT=""

ok()   { PASS=$((PASS + 1)); printf '  \033[32m✓\033[0m %s\n' "$*"; }
bad()  { FAIL=$((FAIL + 1)); printf '  \033[31m✗\033[0m %s\n' "$*"; }
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
summary() {
    printf '\n%s passed, %s failed\n' "$PASS" "$FAIL"
    [ "$FAIL" -eq 0 ]
}

# view <account> <method> [json-args] — prints the JSON result.
view() {
    local args="${3:-}" out i
    [ -n "$args" ] || args='{}'
    # Reads retry: a dropped RPC answer must not read as a product failure.
    for i in 1 2 3; do
        if out=$(near contract call-function as-read-only "$1" "$2" json-args "$args" \
            network-config "$NETWORK" now 2>/dev/null); then
            printf '%s\n' "$out"
            return 0
        fi
        sleep 2
    done
    return 1
}

# rpc <json-params-for-query> — a keyed RPC query, retried; prints the JSON answer.
rpc_query() {
    local out i
    for i in 1 2 3; do
        out=$(curl -s --max-time 30 "$RPC_URL" -H 'content-type: application/json' \
            -d "{\"jsonrpc\":\"2.0\",\"id\":\"x\",\"method\":\"query\",\"params\":$1}") || true
        if printf '%s' "$out" | python3 -I -c 'import sys,json; json.load(sys.stdin)["result"]' 2>/dev/null; then
            printf '%s\n' "$out"
            return 0
        fi
        sleep 2
    done
    return 1
}

# call <signer> <account> <method> <json-args> [gas] [deposit] — 0 on success; the CLI output
# is kept in LAST_OUT (return value and logs) for the caller to inspect.
call() {
    local signer="$1" acc="$2" method="$3" args="$4" gas="${5:-100 Tgas}" dep="${6:-0 NEAR}"
    if LAST_OUT=$(near contract call-function as-transaction "$acc" "$method" json-args "$args" \
        prepaid-gas "$gas" attached-deposit "$dep" sign-as "$signer" \
        network-config "$NETWORK" sign-with-legacy-keychain send 2>&1); then
        return 0
    fi
    return 1
}

# call_file <signer> <account> <method> <file> [gas] [deposit] — the file is the raw input.
call_file() {
    local signer="$1" acc="$2" method="$3" file="$4" gas="${5:-100 Tgas}" dep="${6:-0 NEAR}"
    if LAST_OUT=$(near contract call-function as-transaction "$acc" "$method" file-args "$file" \
        prepaid-gas "$gas" attached-deposit "$dep" sign-as "$signer" \
        network-config "$NETWORK" sign-with-legacy-keychain send 2>&1); then
        return 0
    fi
    return 1
}

# The value the last successful call returned (the CLI prints it after this line).
returned() {
    printf '%s\n' "$LAST_OUT" | sed -n '/Function execution return value/,$p' | sed -n '2p' | tr -d ' "'
}

# expect_refused <substring> <call args...> — the call must fail and name the reason.
expect_refused() {
    local want="$1"; shift
    if call "$@"; then
        bad "expected a refusal ($want), the call succeeded"
    elif printf '%s' "$LAST_OUT" | grep -qF "$want"; then
        ok "refused: $want"
    else
        bad "refused, but not with \"$want\": $(printf '%s' "$LAST_OUT" | grep -iE 'panicked|error' | head -1 | cut -c1-200)"
    fi
}

# Base58 sha256 of a file — what NEAR reports as the code hash once it is deployed.
wasm_hash() {
    python3 -I -c '
import hashlib,sys
A="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
b=hashlib.sha256(open(sys.argv[1],"rb").read()).digest(); n=int.from_bytes(b,"big"); o=""
while n: n,r=divmod(n,58); o=A[r]+o
print("1"*(len(b)-len(b.lstrip(b"\0")))+o)' "$1"
}

# The code hash deployed on an account.
code_hash() {
    rpc_query "{\"request_type\":\"view_account\",\"finality\":\"final\",\"account_id\":\"$1\"}" \
        | python3 -I -c 'import sys,json; print(json.load(sys.stdin)["result"]["code_hash"])'
}

# Deposit for a blob of <file>: its bytes at 1e19 yoctoNEAR each plus 10% for the record.
blob_deposit() {
    python3 -I -c 'import os,sys; print(f"{os.path.getsize(sys.argv[1])*1e19*1.1/1e24:.4f} NEAR")' "$1"
}

gov_status() {
    view "$DAO" get_gov_proposal "{\"proposal_id\":$1}" | python3 -I -c 'import sys,json; d=json.load(sys.stdin); print(d["status"] if d else "none")'
}

# Store <file> as a blob (as STORER); prints its hash.
store_blob() {
    local file="$1"
    call_file "$STORER" "$DAO" store_blob "$file" "100 Tgas" "$(blob_deposit "$file")" \
        || { printf '%s\n' "$LAST_OUT" | grep -iE 'panicked|error' | head -3 >&2; return 1; }
    returned
}

# propose <member> <GovAction json> — prints the proposal id. The proposal pays its storage; the
# excess of the 0.1 NEAR comes back.
propose() {
    call "$1" "$DAO" propose "{\"action\":$2}" "100 Tgas" "0.1 NEAR" \
        || { printf '%s\n' "$LAST_OUT" | grep -iE 'panicked|error' | head -3 >&2; return 1; }
    returned
}

echo "RPC: $(rpc_url_public)"
