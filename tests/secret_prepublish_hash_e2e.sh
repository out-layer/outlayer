#!/usr/bin/env bash
#
# A build hash computed BEFORE anything is published, live.
#
# The claim under test: you can compile a GitHub project yourself, get the
# sha256 the enclave will measure, store a secret locked to that number, and
# have the very first run read it — without ever having run the project to
# discover the number first.
#
# That claim has exactly one honest proof, and it is not a string comparison:
# the keystore decides whether to hand the secret over by comparing the stored
# lock against `executed_wasm_sha256`, the hash the attested worker measured on
# the bytes it loaded. So if a secret locked to a locally computed hash arrives
# in the guest, the local number and the enclave's measurement are the same
# number. Every row below is arranged around that.
#
# What each row pins:
#   P0  the hash is computed locally, twice, in the compiler image the deployed
#       worker uses. Two builds that disagree stop the suite: a number that is
#       not reproducible cannot be locked to, and a suite that carried on would
#       be testing a coincidence
#   P1  the secret is stored locked to that hash BEFORE the project exists.
#       The order is the point — a row written after a first run proves nothing
#       about knowing the hash in advance
#   P2  the project is published from the same repo and commit
#   P3  the first run reads the secret. THE CLAIM
#   P4  the attestation of that run names the same hash. P3 already implies it;
#       this makes it readable, and catches a keystore that answered for some
#       other reason
#   P5  control: re-pointed at another build, the same run is refused. Without
#       it P3 would also pass against a keystore that never consults the lock
#
# Needs: PARENT (signs and owns the row), PAYMENT_KEY (the run goes over HTTPS
# so it yields a call id and therefore an attestation), docker (the hash is
# computed in the platform's compiler image).
#
# Run:
#   PARENT=you.testnet PAYMENT_KEY=… ./tests/secret_prepublish_hash_e2e.sh --apply

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/hos_common.sh"

PARENT="${PARENT:-}"
PAYMENT_KEY="${PAYMENT_KEY:-}"
PROFILE="${PROFILE:-prepublish}"
CANARY="prepublish-canary-$$"

# The fixture: a project that returns the environment variables it is asked
# for, which is how a secret becomes observable from outside the guest. Pinned
# to a commit, not a branch — the hash is a property of a commit, and a moving
# branch would let the platform build something else.
SRC_REPO="${SRC_REPO:-https://github.com/out-layer/env-test-example}"
SRC_COMMIT="${SRC_COMMIT:-74fb4db65ae5bcd7feb819b7cbb9dc969b6fcd65}"
SRC_TARGET="${SRC_TARGET:-wasm32-wasip1}"
PROJECT_NAME="${PROJECT_NAME:-env-test-buildlock}"
PROJECT="$PARENT/$PROJECT_NAME"

[[ "${1:-}" == "--apply" ]] || { sed -n '3,40p' "$0" | sed 's/^# \{0,1\}//'; echo "  Pass --apply to run." >&2; exit 0; }
[[ -n "$PARENT" ]] || { echo "✗ set PARENT" >&2; exit 1; }
[[ -n "$PAYMENT_KEY" ]] || { echo "✗ set PAYMENT_KEY — the run must leave an attestation, so it goes over HTTPS" >&2; exit 1; }
hos_require
source "$SCRIPT_DIR/lib/secrets_common.sh"

build_leaf() { jq -nc --arg h "$1" '{WasmHash:{hash:$h}}'; }
and_of()     { jq -nc --argjson a "$1" --argjson b "$2" '{Logic:{operator:"And",conditions:[$a,$b]}}'; }

note "project: $PROJECT   profile: $PROFILE"
note "source:  $SRC_REPO @ $SRC_COMMIT ($SRC_TARGET)"

# ── the deployment gate ──────────────────────────────────────────────────────
#
# The contract has to know the variant before a locked row can be stored at
# all. Asked of the deployed contract rather than of the checkout, and asked of
# the RPC directly rather than through `near_view`, which maps a contract panic
# to the literal string "ERR" and would wave the suite through against a
# contract that refuses every row.
gate() {
  local args raw price why
  args=$(jq -nc --argjson a "$(accessor_json "$PROJECT")" --arg o "$PARENT" \
          --argjson x "$(build_leaf "$(printf 'a%.0s' {1..64})")" \
          '{accessor:$a, profile:"probe", owner:$o, encrypted_secrets_base64:"", access:$x, vault_id:null}')
  raw=$(curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' --max-time 30 \
    -d "$(jq -nc --arg a "$CONTRACT_ID" --arg g "$(printf '%s' "$args" | base64 | tr -d '\n')" \
      '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"call_function",finality:"final",
        account_id:$a,method_name:"estimate_storage_cost",args_base64:$g}}')" 2>&1)
  price=$(jq -r 'if .result.result then (.result.result | implode) else empty end' <<<"$raw" 2>/dev/null | tr -d '"')
  [[ "$price" =~ ^[0-9]+$ ]] && return 0
  why=$(jq -r '.result.error // .error.data // .error.message // empty' <<<"$raw" 2>/dev/null | head -c 300)
  skip "the deployed contract will not price a WasmHash condition — deploy keystore, then contract, then workers, then re-run. It answered: ${why:-$(head -c 200 <<<"$raw")}"
  verdict "pre-published build hash"; exit $?
}
gate

command -v docker >/dev/null 2>&1 || {
  skip "docker is not available, and the whole point of this suite is computing the hash in the platform's compiler image"
  verdict "pre-published build hash"; exit $?
}

# ── P0 the hash, computed locally, before anything exists ────────────────────
log "P0 computing the build hash locally, in the platform's compiler image"
BUILD_OUT=$("$SCRIPT_DIR/../scripts/build_github_wasm.sh" \
  --repo "$SRC_REPO" --commit "$SRC_COMMIT" --target "$SRC_TARGET" --twice 2>&1)
LOCAL_HASH=$(tail -1 <<<"$BUILD_OUT" | tr -d '[:space:]')
if [[ ! "$LOCAL_HASH" =~ ^[0-9a-f]{64}$ ]]; then
  fail "P0 the local build did not yield a hash. A build that does not reproduce cannot be locked to: $(tail -6 <<<"$BUILD_OUT" | head -c 600)"
  verdict "pre-published build hash"; exit $?
fi
pass "P0 two local builds agree on $LOCAL_HASH"

# A build that is certainly not the one that will run: the same hash with its
# first hex digit rotated, so it is well formed and cannot collide.
OTHER="$(printf '%x%s' "$(( (16#${LOCAL_HASH:0:1} + 1) % 16 ))" "${LOCAL_HASH:1}")"

# ── P1 the secret, locked, before the project is published ───────────────────
log "P1 storing the secret locked to that hash — before the project exists"
store "$PROJECT" "$PROFILE" "$(jq -nc --arg v "$CANARY" '{USER_SECRET:$v}')" "whitelist:$PARENT"
set_access "$PROJECT" "$PROFILE" "$(and_of "$(whitelist "$PARENT")" "$(build_leaf "$LOCAL_HASH")")"
STORED=$(jq -c '.access // empty' <<<"$(row_of "$PROJECT" "$PROFILE")" 2>/dev/null)
if grep -q "$LOCAL_HASH" <<<"$STORED"; then
  pass "P1 the row on chain is locked to the locally computed build"
else
  fail "P1 the stored condition does not name the local hash: $(head -c 300 <<<"$STORED")"
  verdict "pre-published build hash"; exit $?
fi

# ── P2 publish the same commit ───────────────────────────────────────────────
log "P2 publishing the project from the same repo and commit"
CLONE=$(mktemp -d)
trap 'rm -rf "$CLONE"' EXIT
if ! git clone -q "$SRC_REPO" "$CLONE" 2>/dev/null || ! git -C "$CLONE" checkout -q "$SRC_COMMIT" 2>/dev/null; then
  skip "P2 could not clone $SRC_REPO at $SRC_COMMIT"
  verdict "pre-published build hash"; exit $?
fi
DEPLOY_OUT=$(cd "$CLONE" && OUTLAYER_NETWORK="$NETWORK" "$OUTLAYER_BIN" deploy "$PROJECT_NAME" --github --target "$SRC_TARGET" 2>&1)
if grep -qiE "error|failed" <<<"$DEPLOY_OUT" && ! grep -qiE "deployed|activated|version" <<<"$DEPLOY_OUT"; then
  fail "P2 deploy failed: $(tail -3 <<<"$DEPLOY_OUT" | head -c 400)"
  verdict "pre-published build hash"; exit $?
fi
pass "P2 published $PROJECT at $SRC_COMMIT"

# ── the run ──────────────────────────────────────────────────────────────────
#
# The module returns the environment variables it is asked for, so the secret is
# observable from outside the guest. The first call may also compile, which is
# slower than one HTTP timeout; a timeout is retried once rather than reported
# as a refusal.
run() {
  local body
  body=$(jq -nc --arg pr "$PROFILE" --arg o "$PARENT" \
    '{input:{env_vars:["USER_SECRET"]}, secrets_ref:{profile:$pr, account_id:$o}}')
  https_post "$PAYMENT_KEY" "$PROJECT" "$body"
  if [[ "$RUN_OK" == absent ]]; then
    note "no answer within the timeout — the first call compiles; retrying once"
    https_post "$PAYMENT_KEY" "$PROJECT" "$body"
  fi
}
secret_arrived() { [[ "$(jq -r '.values.USER_SECRET // empty' <<<"$RUN_OUT" 2>/dev/null)" == "$CANARY" ]]; }

# ── P3 the claim ─────────────────────────────────────────────────────────────
log "P3 the first run reads the secret — the claim"
run
if secret_arrived; then
  pass "P3 a secret locked to a hash computed before publishing was read on the first run"
else
  fail "P3 the secret did not arrive. The platform's build of $SRC_COMMIT is not the one computed locally, or the lock refused it: $(jq -r '.error // .message // .status // empty' <<<"$ANS" | head -c 400)"
fi

# ── P4 the attestation names the same hash ───────────────────────────────────
log "P4 the attestation of that run names the same build"
executed_build() {
  local call_id att h i
  call_id=$(jq -r '.call_id // empty' <<<"$ANS" 2>/dev/null)
  [[ -n "$call_id" ]] || return 1
  for i in $(seq 1 10); do
    att=$(curl -sS --max-time 20 "$COORDINATOR_URL/attestations/by-call/$call_id" 2>/dev/null)
    h=$(jq -r '.executed_wasm_sha256 // empty' <<<"$att" 2>/dev/null)
    [[ -n "$h" ]] && { printf '%s' "$h"; return 0; }
    sleep 3
  done
  return 1
}
MEASURED="$(executed_build || true)"
if [[ "$MEASURED" == "$LOCAL_HASH" ]]; then
  pass "P4 the enclave measured the number computed on a laptop: $MEASURED"
elif [[ -z "$MEASURED" ]]; then
  fail "P4 the run left no executed_wasm_sha256, so the measurement cannot be read back"
else
  fail "P4 the enclave measured $MEASURED but the local build gave $LOCAL_HASH — the platform does not compile this commit the way scripts/build_github_wasm.sh does"
fi

# ── P5 the control ───────────────────────────────────────────────────────────
log "P5 control — re-pointed at another build, the same run is refused"
set_access "$PROJECT" "$PROFILE" "$(and_of "$(whitelist "$PARENT")" "$(build_leaf "$OTHER")")"
run
if secret_arrived; then
  fail "P5 the secret arrived for a build the row does not name — the lock is not being consulted, so P3 proved nothing"
else
  REASON=$(jq -r '.error // .message // empty' <<<"$ANS" 2>/dev/null)
  if grep -q "$LOCAL_HASH" <<<"$REASON" || grep -qi "build" <<<"$REASON"; then
    pass "P5 refused, and the refusal is about the build: $(head -c 160 <<<"$REASON")"
  else
    pass "P5 refused (reason not worded around the build: $(head -c 160 <<<"$REASON"))"
  fi
fi

# ── put the row back where P1 left it ────────────────────────────────────────
set_access "$PROJECT" "$PROFILE" "$(and_of "$(whitelist "$PARENT")" "$(build_leaf "$LOCAL_HASH")")"
delete_row "$PROJECT" "$PROFILE" 2>/dev/null || note "left $PROJECT/$PROFILE in place"

verdict "pre-published build hash"
