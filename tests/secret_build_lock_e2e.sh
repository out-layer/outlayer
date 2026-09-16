#!/usr/bin/env bash
#
# A secret locked to ONE BUILD: the `WasmHash` access condition, live.
#
# The condition says "only a run of these exact bytes may read this row". The
# keystore judges it against the SHA-256 the attested worker measured on the
# wasm it loaded — `executed_wasm_sha256`, the same value the dashboard shows
# as "Executed binary" — so every row here learns that hash from a real
# attestation rather than being told one.
#
# What each row pins:
#   B0  baseline: the row is readable, and the running build is discovered from
#       the attestation of the very call that read it. Everything below is
#       judged against that hash, so a wrong one here would make the suite lie
#   B1  locked to the running build → the secret still arrives
#   B2  locking does not re-encrypt: the ciphertext on chain is byte-identical
#       across the edit. This is what lets a generated PROTECTED_ key keep its
#       value while its lock moves from release to release
#   B3  locked to ANOTHER build → refused, and the refusal names both the build
#       the row is locked to and the one that ran. A refusal that named neither
#       would leave the owner with nothing to act on
#   B4  moved back with update_access → readable again, ciphertext still
#       identical. B2+B4 together are the claim "re-pointing is not re-storing"
#   B5  a whitelist the caller fails, beside a build that MATCHES → refused,
#       and the message must NOT claim a lock. Naming a build here would send
#       the owner to re-point a row whose build was never the problem
#   B6  Or[whitelist, other build] → the whitelisted caller still reads it on
#       any build: a lock in one branch of an OR is not a lock on the row
#   B7  Not{running build} → refused, worded as refusing the build that ran,
#       not as a lock to some other one
#   B8  the contract refuses a leaf the keystore could never match — 63 hex,
#       upper case, non-hex — before it is ever stored
#   B9  a DIFFERENT build of the same project, pinned by version_key: the row
#       locked to B0's build refuses it. The rebuild case, without waiting for
#       a rebuild
#   C1  `outlayer secrets set --build` stores exactly one lock, and a second
#       `set --build` leaves exactly one — the nesting that grows a row's paid
#       storage on every release
#   C2  `secrets access --build` moves the lock, and `list` reads it back
#   C3  a malformed --build is refused by the CLI with no transaction at all
#
# NOT covered here, and deliberately: that a locked secret still reaches the
# guest as an environment variable and can be printed by the guest itself.
# Locking says which build may READ a secret, never that the build keeps it.
#
# Needs: PARENT (owns the row and signs), PAYMENT_KEY (a funded key — every run
# here goes over HTTPS so each one yields a call id and therefore an
# attestation). The project is $PARENT/test-secrets, published, as the other
# secrets suites use it.
#
# Run:
#   PARENT=you.testnet PAYMENT_KEY=… ./tests/secret_build_lock_e2e.sh --apply

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/hos_common.sh"

PARENT="${PARENT:-}"
PROJECT="${SECRETS_PROJECT:-${PARENT:-}/test-secrets}"
PAYMENT_KEY="${PAYMENT_KEY:-}"
PROFILE="${PROFILE:-buildlock}"
DEPOSIT='0.1 NEAR'
CANARY="build-lock-canary-$$"

[[ "${1:-}" == "--apply" ]] || { sed -n '3,60p' "$0" >&2; echo "  Pass --apply to run." >&2; exit 0; }
[[ -n "$PARENT" ]] || { echo "✗ set PARENT" >&2; exit 1; }
[[ -n "$PAYMENT_KEY" ]] || { echo "✗ set PAYMENT_KEY — every row here needs an attestation, so every run goes over HTTPS" >&2; exit 1; }
hos_require
source "$SCRIPT_DIR/lib/secrets_common.sh"

note "project: $PROJECT   profile: $PROFILE"

# ── condition builders ───────────────────────────────────────────────────────
build_leaf() { jq -nc --arg h "$1" '{WasmHash:{hash:$h}}'; }
and_of()     { jq -nc --argjson a "$1" --argjson b "$2" '{Logic:{operator:"And",conditions:[$a,$b]}}'; }
or_of()      { jq -nc --argjson a "$1" --argjson b "$2" '{Logic:{operator:"Or",conditions:[$a,$b]}}'; }
not_of()     { jq -nc --argjson c "$1" '{Not:{condition:$c}}'; }

# ── the deployment gate ──────────────────────────────────────────────────────
#
# The contract must know the variant before anything below can be stored. Asked
# of the deployed contract itself rather than of the checkout: a working tree
# that carries the change proves nothing about what testnet is running, and a
# suite that stored nothing would otherwise report a wall of green.
#
# Asked of the RPC directly, NOT through `near_view`: that helper maps a
# contract panic to the literal string `ERR` (`.error.cause.name // "ERR"`,
# while a panicking view puts its message in `.result.error`), so a gate built
# on it greps for "unknown variant" in a string that never carries it and waves
# the whole suite through against a contract that would refuse every row.
#
# Fail-closed: only a numeric price — the contract pricing a WasmHash condition
# it understands — opens the gate. Anything else stops the run and says what
# answered, because a gate that cannot tell is a gate that must not pass.
gate() {
  local args raw price
  args=$(jq -nc --argjson a "$(accessor_json "$PROJECT")" --arg o "$PARENT" \
          --argjson x "$(build_leaf "$(printf 'a%.0s' {1..64})")" \
          '{accessor:$a, profile:"probe", owner:$o, encrypted_secrets_base64:"", access:$x, vault_id:null}')
  raw=$(curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' --max-time 30 \
    -d "$(jq -nc --arg a "$CONTRACT_ID" --arg g "$(printf '%s' "$args" | base64 | tr -d '\n')" \
      '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"call_function",finality:"final",
        account_id:$a,method_name:"estimate_storage_cost",args_base64:$g}}')" 2>&1)
  price=$(jq -r 'if .result.result then (.result.result | implode) else empty end' <<<"$raw" 2>/dev/null | tr -d '"')
  if [[ "$price" =~ ^[0-9]+$ ]]; then
    note "the deployed contract prices a WasmHash condition ($price yoctoNEAR) — it knows the variant"
    return 0
  fi
  local why; why=$(jq -r '.result.error // .error.data // .error.message // empty' <<<"$raw" 2>/dev/null | head -c 300)
  if grep -q "unknown variant" <<<"$why"; then
    skip "the deployed contract does not know the WasmHash condition — deploy keystore, then contract, then workers (.idea/_todo/SECRETS-WASM-HASH-PINNING.md), then re-run"
  else
    skip "the contract would not price a WasmHash condition, and not because the variant is unknown — nothing below can be trusted until this is understood"
  fi
  note "the contract answered: ${why:-$(head -c 200 <<<"$raw")}"
  verdict "secret build lock"; exit $?
}
gate

# ── runs, over HTTPS so every one leaves an attestation ──────────────────────

# run [version_key] — names this suite's row; leaves RUN_OK/RUN_OUT/ANS.
run() {
  local version=${1:-} body
  body=$(jq -nc --arg o "$PARENT" --arg pr "$PROFILE" \
    '{input:{message:"build-lock"}, secrets_ref:{profile:$pr, account_id:$o}}')
  [[ -n "$version" ]] && body=$(jq -c --arg v "$version" '. + {version_key:$v}' <<<"$body")
  https_post "$PAYMENT_KEY" "$PROJECT" "$body"
}

# The build the last call actually ran, from its attestation. Empty if the
# coordinator has not recorded one yet — polled, because the worker stores the
# attestation after answering.
executed_build() {
  local call_id att i
  call_id=$(jq -r '.call_id // empty' <<<"$ANS" 2>/dev/null)
  [[ -n "$call_id" ]] || return 1
  for i in $(seq 1 10); do
    att=$(curl -sS --max-time 20 "$COORDINATOR_URL/attestations/by-call/$call_id" 2>/dev/null)
    local h; h=$(jq -r '.executed_wasm_sha256 // empty' <<<"$att" 2>/dev/null)
    [[ -n "$h" ]] && { printf '%s' "$h"; return 0; }
    sleep 3
  done
  return 1
}

secret_arrived() { [[ "$(secret_value USER_SECRET)" == "$CANARY" ]]; }
ciphertext_of()  { jq -r '.encrypted_secrets // empty' <<<"$(row_of "$PROJECT" "$PROFILE")"; }

# ── B0 the row reads, and the running build is learned from the attestation ──
log "B0 baseline — the row is readable, and the attestation names the build that read it"
store "$PROJECT" "$PROFILE" "$(jq -nc --arg v "$CANARY" '{USER_SECRET:$v}')" "whitelist:$PARENT"
run
if ! secret_arrived; then
  fail "B0 the row does not read even unlocked, so nothing below would mean anything — $(head -c 300 <<<"$ANS")"
  verdict "secret build lock"; exit $?
fi
RUNNING="$(executed_build || true)"
if [[ ! "$RUNNING" =~ ^[0-9a-f]{64}$ ]]; then
  fail "B0 no executed_wasm_sha256 in the attestation (got '${RUNNING:-}') — a coordinator that does not report it cannot be tested against"
  verdict "secret build lock"; exit $?
fi
pass "B0 the secret arrived and the run's build is $RUNNING"
CIPHER_BEFORE="$(ciphertext_of)"

# A build that is certainly not the one running: the same hash with its first
# hex digit rotated, so it is well-formed and cannot collide.
OTHER="$(printf '%x%s' "$(( (16#${RUNNING:0:1} + 1) % 16 ))" "${RUNNING:1}")"

# ── B1 locked to the running build ───────────────────────────────────────────
log "B1 locked to the build that runs — the secret still arrives"
set_access "$PROJECT" "$PROFILE" "$(and_of "$(whitelist "$PARENT")" "$(build_leaf "$RUNNING")")"
run
if secret_arrived; then pass "B1 the locked row read for the build it names"
else fail "B1 a row locked to its own running build refused it: $(jq -r '.error // .message // empty' <<<"$ANS" | head -c 300)"; fi

# ── B2 the lock did not re-encrypt ───────────────────────────────────────────
log "B2 the ciphertext is untouched by the lock"
if [[ -n "$CIPHER_BEFORE" && "$(ciphertext_of)" == "$CIPHER_BEFORE" ]]; then
  pass "B2 the stored ciphertext is byte-identical across the edit"
else
  fail "B2 the ciphertext changed when the condition did — a PROTECTED_ key would not survive a re-lock"
fi

# ── B3 locked to another build ───────────────────────────────────────────────
log "B3 locked to another build — refused, naming both builds"
set_access "$PROJECT" "$PROFILE" "$(and_of "$(whitelist "$PARENT")" "$(build_leaf "$OTHER")")"
run
REASON=$(jq -r '.error // .message // empty' <<<"$ANS" 2>/dev/null)
if secret_arrived; then
  fail "B3 a row locked to a DIFFERENT build handed its secret over — the lock does not hold"
elif grep -q "$OTHER" <<<"$REASON" && grep -q "$RUNNING" <<<"$REASON"; then
  pass "B3 refused, naming the locked build and the running one"
elif [[ "$RUN_OK" != "true" ]]; then
  finding "B3 refused, but the reason names neither build: $(head -c 300 <<<"$REASON")"
else
  fail "B3 the run succeeded without the secret rather than being refused: $(head -c 300 <<<"$ANS")"
fi

# ── B4 moved back, still the same ciphertext ─────────────────────────────────
log "B4 update_access moves the lock back — readable again, ciphertext still identical"
set_access "$PROJECT" "$PROFILE" "$(and_of "$(whitelist "$PARENT")" "$(build_leaf "$RUNNING")")"
run
if secret_arrived && [[ "$(ciphertext_of)" == "$CIPHER_BEFORE" ]]; then
  pass "B4 re-pointing a lock is not re-storing a secret"
elif ! secret_arrived; then
  fail "B4 the row did not come back after the lock moved to the running build"
else
  fail "B4 the row reads again but its ciphertext changed on the way"
fi

# ── B5 a build that matches, beside a whitelist that does not ────────────────
log "B5 the whitelist refuses while the build matches — no lock may be claimed"
set_access "$PROJECT" "$PROFILE" "$(and_of "$(whitelist "stranger-$$.testnet")" "$(build_leaf "$RUNNING")")"
run
REASON=$(jq -r '.error // .message // empty' <<<"$ANS" 2>/dev/null)
if secret_arrived; then
  fail "B5 a whitelist that names nobody real still admitted the caller"
elif [[ "$RUN_OK" == "absent" ]]; then
  fail "B5 nothing answered — a timeout is not a refusal, and this row would otherwise pass on one: $(head -c 200 <<<"$ANS")"
elif [[ "$RUN_OK" == "true" ]]; then
  fail "B5 the run succeeded without the secret rather than being refused: $(head -c 300 <<<"$ANS")"
elif grep -qi "locked to build\|refuses the running build" <<<"$REASON"; then
  fail "B5 the refusal blames the build, which MATCHED — the owner would go re-point a correct lock: $(head -c 300 <<<"$REASON")"
else
  pass "B5 refused without blaming the build"
fi

# ── B6 a lock in one branch of an OR is not a lock ───────────────────────────
log "B6 Or[whitelist, another build] — the whitelisted caller still reads it"
set_access "$PROJECT" "$PROFILE" "$(or_of "$(whitelist "$PARENT")" "$(build_leaf "$OTHER")")"
run
if secret_arrived; then pass "B6 the OR's other branch admitted the caller, whatever the build"
else fail "B6 an OR branch that does not mention builds was overruled by one that does: $(jq -r '.error // empty' <<<"$ANS" | head -c 300)"; fi

# ── B7 a negated lock ────────────────────────────────────────────────────────
log "B7 Not{running build} — refused, worded as refusing the build that ran"
set_access "$PROJECT" "$PROFILE" "$(not_of "$(build_leaf "$RUNNING")")"
run
REASON=$(jq -r '.error // .message // empty' <<<"$ANS" 2>/dev/null)
if secret_arrived; then
  fail "B7 a condition that excludes the running build still handed the secret over"
elif [[ "$RUN_OK" == "absent" ]]; then
  fail "B7 nothing answered — a timeout is not a refusal: $(head -c 200 <<<"$ANS")"
elif grep -q "refuses the running build" <<<"$REASON"; then
  pass "B7 refused, and worded as an exclusion rather than as a lock"
elif grep -q "locked to build" <<<"$REASON"; then
  fail "B7 a negated leaf was reported as a LOCK; the owner would re-point a row that has no lock: $(head -c 300 <<<"$REASON")"
else
  fail "B7 refused, but the reason says nothing about the build that caused it: $(head -c 300 <<<"$REASON")"
fi

# ── B8 shapes the contract must refuse ───────────────────────────────────────
log "B8 a leaf the keystore could never match is refused before it is stored"
B8_OK=1
for bad in "${RUNNING:0:63}" "$(tr 'a-f' 'A-F' <<<"$RUNNING")" "${RUNNING:0:63}g"; do
  args=$(jq -nc --argjson a "$(accessor_json "$PROJECT")" --arg pr "$PROFILE" \
          --argjson x "$(and_of "$(whitelist "$PARENT")" "$(build_leaf "$bad")")" \
          '{accessor:$a, profile:$pr, new_access:$x}')
  if out=$(update_access_call "$args" '1 NEAR' 2>&1); then
    fail "B8 the contract stored a malformed build leaf: '${bad:0:12}…' (${#bad} chars)"
    B8_OK=0
  elif ! grep -qi "64 lowercase hex\|WasmHash condition" <<<"$out"; then
    finding "B8 '${bad:0:12}…' was refused, but not for its shape: $(grep -oE 'panic_msg: [^,}]*' <<<"$out" | head -c 200)"
  fi
done
(( B8_OK == 1 )) && pass "B8 all three malformed leaves were refused on chain"
# Put the row back where B9 needs it.
set_access "$PROJECT" "$PROFILE" "$(and_of "$(whitelist "$PARENT")" "$(build_leaf "$RUNNING")")"

# ── B9 another build of the same project ─────────────────────────────────────
log "B9 a different published version — the row locked to B0's build refuses it"
OTHER_VERSION="${OTHER_VERSION:-d39dfee85c0085604e516d37f83032ed98abba4a43322ed4b5c455b33c13c8f7}"
if [[ -z "$OTHER_VERSION" ]]; then
  skip "B9 — no second build named. The contract has no view that LISTS versions (only get_version_count), so pass OTHER_VERSION=<wasm hash of a published, non-active version>"
else
  run "$OTHER_VERSION"
  OTHER_RAN="$(executed_build || true)"
  REASON=$(jq -r '.error // .message // empty' <<<"$ANS" 2>/dev/null)
  if [[ -n "$OTHER_RAN" && "$OTHER_RAN" == "$RUNNING" ]]; then
    skip "B9 — version ${OTHER_VERSION:0:16}… executes the same bytes as the active one, so it is not a second build"
  elif secret_arrived; then
    fail "B9 a build whose bytes are not the locked ones read the secret — the lock follows the project, not the build"
  elif grep -q "$RUNNING" <<<"$REASON"; then
    pass "B9 the other build was refused, and the locked build is named (it ran ${OTHER_RAN:-unknown})"
  elif [[ "$RUN_OK" != "true" ]]; then
    finding "B9 the other build was refused, but the reason does not name the locked build: $(head -c 300 <<<"$REASON")"
  else
    fail "B9 the other build ran without the secret rather than being refused: $(head -c 300 <<<"$ANS")"
  fi
fi

# ── C1 the CLI stores one lock, and a repeat leaves one ──────────────────────
log "C1 outlayer secrets set --build, twice — exactly one lock either time"
leaf_count() { # every WasmHash leaf in the stored condition
  jq '[.. | objects | select(has("WasmHash"))] | length' <<<"$(jq -c '.access // {}' <<<"$(row_of "$PROJECT" "$PROFILE")")" 2>/dev/null
}
cli_set_build() {
  local before out
  before=$(jq -r '.updated_at // 0' <<<"$(row_of "$PROJECT" "$PROFILE")")
  out=$(OUTLAYER_NETWORK="$NETWORK" "$OUTLAYER_BIN" secrets set "$(jq -nc --arg v "$CANARY" '{USER_SECRET:$v}')" \
        --project "$PROJECT" --profile "$PROFILE" --build "$1" 2>&1) || { echo "$out" | tail -3 >&2; return 1; }
  wait_row_after "$PROJECT" "$PROFILE" "$before"
}
if ! cli_set_build "$RUNNING"; then
  fail "C1 outlayer secrets set --build did not store"
else
  ONE=$(leaf_count)
  cli_set_build "$RUNNING" || true
  TWO=$(leaf_count)
  if [[ "$ONE" == "1" && "$TWO" == "1" ]]; then
    pass "C1 one lock after the first store and still one after the second"
  else
    fail "C1 the lock nests: $ONE leaf after one store, $TWO after two — every release would pay for another wrapper"
  fi
fi

# ── C2 the CLI moves the lock ────────────────────────────────────────────────
log "C2 secrets access --build moves the lock, and list reads it back"
if OUTLAYER_NETWORK="$NETWORK" "$OUTLAYER_BIN" secrets access --project "$PROJECT" --profile "$PROFILE" \
     --access "whitelist:$PARENT" --build "$OTHER" >/dev/null 2>&1; then
  wait_row_after "$PROJECT" "$PROFILE" "$(jq -r '.updated_at // 0' <<<"$(row_of "$PROJECT" "$PROFILE")")" || true
  STORED=$(jq -r '[.. | objects | select(has("WasmHash")) | .WasmHash.hash] | join(",")' <<<"$(jq -c '.access // {}' <<<"$(row_of "$PROJECT" "$PROFILE")")")
  LISTED=$(OUTLAYER_NETWORK="$NETWORK" "$OUTLAYER_BIN" secrets list 2>&1 | grep -c "build:$OTHER")
  if [[ "$STORED" == "$OTHER" && "$LISTED" != "0" ]]; then
    pass "C2 the lock moved to the new build and list shows it"
  else
    fail "C2 after --build the row holds '$STORED' and list matched $LISTED line(s)"
  fi
else
  fail "C2 secrets access --build was refused"
fi

# ── C3 a malformed --build never reaches the chain ───────────────────────────
log "C3 a malformed --build is refused by the CLI, with no transaction"
BEFORE_C3=$(jq -r '.updated_at // 0' <<<"$(row_of "$PROJECT" "$PROFILE")")
if OUTLAYER_NETWORK="$NETWORK" "$OUTLAYER_BIN" secrets access --project "$PROJECT" --profile "$PROFILE" \
     --access "whitelist:$PARENT" --build "${RUNNING:0:63}" >/dev/null 2>&1; then
  fail "C3 the CLI accepted a 63-character build"
elif [[ "$(jq -r '.updated_at // 0' <<<"$(row_of "$PROJECT" "$PROFILE")")" == "$BEFORE_C3" ]]; then
  pass "C3 refused, and the row on chain is untouched"
else
  fail "C3 the CLI refused but the row changed anyway"
fi

# ── cleanup ──────────────────────────────────────────────────────────────────
log "cleanup"
delete_row "$PROJECT" "$PROFILE"

verdict "secret build lock"
