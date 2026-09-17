#!/usr/bin/env bash
#
# A build lock end to end on a project that does NOT cooperate: published
# fresh, from a third-party repository, running code that never reads the
# secret.
#
# WHEN TO RUN THIS. Only when the build-lock machinery itself changes — the
# `WasmHash` access condition, the compiler recipe, the pinned compiler image,
# `scripts/build_github_wasm.sh`, or how the worker measures
# `executed_wasm_sha256`. It is not part of a normal test round: it publishes a
# project under a fresh account, compiles a repository from scratch on the
# platform (minutes), and leaves that account and project behind. Everything it
# checks about the condition ITSELF is covered far more cheaply by
# `secret_build_lock_e2e.sh`; what only this suite covers is the end-to-end
# claim that the three moving parts agree on one number for code nobody here
# wrote.
#
# WHY IT IS WORTH THE MINUTES. Every other suite proves the lock against
# `test-secrets-example` — a guest we control, which cooperates by returning
# its own environment. Here the guest returns a random number and touches no
# environment at all, so the only observable is whether the run HAPPENS: a
# `secrets_ref` the keystore refuses refuses the whole run before the module
# starts. Nothing inside the module can affect the verdict.
#
# And the hash is computed BEFORE anything is published, locally, in the pinned
# compiler image. That is the order the docs promise an owner —
# know the number, lock against it, and let the FIRST run be the one that reads
# the secret — and it only holds if the platform, compiling the same commit
# itself, arrives at the same bytes.
#
#   R1  the project is published under a fresh account from $REPO@$COMMIT
#   R2  locked to a WRONG build → the run does not happen, and the refusal
#       names the build the row is locked to and the build that ran. That
#       second number is the platform's own measurement of a repository it
#       compiled for the first time: if it matches what was computed here
#       before publishing, the reproducible build holds for third-party code
#   R3  `secrets access --build <right>` → the same call runs
#
# Needs: PARENT (owns the secret and signs the runs), APP_PARENT (funds the
# app's account; its key must be in the keychain), docker (for the hash) unless
# RIGHT is passed, and the outlayer CLI.
#
# Money: a 1 NEAR sub-account and ~0.3 NEAR of project storage on the first
# run only, then two on-chain runs at 0.1 NEAR.
#
# Run:
#   PARENT=you.testnet APP_PARENT=you.testnet ./tests/secret_build_lock_fresh_project_e2e.sh --apply
#   RIGHT=<sha256> … --apply        # skip the local build, use a known hash

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."
source tests/lib/hos_common.sh

PARENT="${PARENT:-}"
APP_PARENT="${APP_PARENT:-$PARENT}"
APP_OWNER="${APP_OWNER:-test.$APP_PARENT}"
APP_NAME="${APP_NAME:-random}"
PROJECT="$APP_OWNER/$APP_NAME"
PROFILE="${PROFILE:-rndlock}"
REPO="${REPO:-https://github.com/out-layer/random-example}"
COMMIT="${COMMIT:-67ec8004666f01d2bcd63db6c8beae82292977f0}"
BUILD_TARGET="${BUILD_TARGET:-wasm32-wasip1}"
# The guest's own input shape. Built with jq rather than spelled inline: a
# hand-escaped brace inside a ${VAR:-default} is how the first version of this
# suite fed the module malformed JSON and read the panic as a refusal.
INPUT="${INPUT:-$(jq -nc '{min:0, max:100}')}"
DEPOSIT='0.1 NEAR'

[[ "${1:-}" == "--apply" ]] || { sed -n '3,48p' "$0" >&2; echo "  Pass --apply to run." >&2; exit 0; }
[[ -n "$PARENT" ]] || { echo "✗ set PARENT" >&2; exit 1; }
hos_require
source tests/lib/secrets_common.sh

# The hash the platform will measure, computed here first — the whole point of
# the suite. `--twice` is not used: reproducibility across two local builds is
# `build_github_wasm.sh`'s own business, and what this suite tests is the
# platform agreeing with ONE local build.
if [[ -z "${RIGHT:-}" ]]; then
  if ! docker info >/dev/null 2>&1; then
    skip "no docker: the platform's hash cannot be computed here. Pass RIGHT=<sha256> to run anyway"
    verdict "fresh-project build lock"; exit $?
  fi
  note "computing the platform's hash for $REPO@${COMMIT:0:10} — minutes"
  RIGHT=$(./scripts/build_github_wasm.sh --repo "$REPO" --commit "$COMMIT" --target "$BUILD_TARGET" 2>/dev/null | tail -1)
fi
if [[ ! "$RIGHT" =~ ^[0-9a-f]{64}$ ]]; then
  fail "the local build produced no usable hash (got '${RIGHT:0:32}') — nothing below could be judged"
  verdict "fresh-project build lock"; exit $?
fi
# A build that is certainly not the one running: the same hash with its first
# hex digit rotated — well formed, and cannot collide.
WRONG="$(printf '%x%s' "$(( (16#${RIGHT:0:1} + 1) % 16 ))" "${RIGHT:1}")"
note "project $PROJECT   right=$RIGHT"

# ── R1 publish ───────────────────────────────────────────────────────────────
log "R1 publish $PROJECT from $REPO@${COMMIT:0:10}"
if ! account_exists "$APP_OWNER"; then
  near account create-account fund-myself "$APP_OWNER" '1 NEAR' \
    autogenerate-new-keypair save-to-keychain sign-as "$APP_PARENT" \
    network-config "$NETWORK" sign-with-keychain send >/dev/null 2>&1
  for _ in 1 2 3 4 5 6; do account_exists "$APP_OWNER" && break; sleep 2; done
  account_exists "$APP_OWNER" || { echo "✗ could not create $APP_OWNER" >&2; exit 1; }
  note "created $APP_OWNER"
fi
project_on_chain() { near_view "$CONTRACT_ID" get_project "$(jq -nc --arg p "$PROJECT" '{project_id:$p}')" | jq -r '.project_id // empty'; }
if [[ -z "$(project_on_chain)" ]]; then
  CREATE=$(near contract call-function as-transaction "$CONTRACT_ID" create_project \
    json-args "$(jq -nc --arg n "$APP_NAME" --arg r "$REPO" --arg c "$COMMIT" --arg t "$BUILD_TARGET" \
      '{name:$n, source:{GitHub:{repo:$r, commit:$c, build_target:$t}}}')" \
    prepaid-gas '100.0 Tgas' attached-deposit '0.3 NEAR' \
    sign-as "$APP_OWNER" network-config "$NETWORK" sign-with-keychain send 2>&1) || true
  sleep 4
fi
if [[ -n "$(project_on_chain)" ]]; then
  pass "R1 $PROJECT is published"
else
  fail "R1 the project was not created: $(grep -iE 'panick|Error' <<<"${CREATE:-}" | head -2 | tr '\n' ' ' | head -c 240)"
  verdict "fresh-project build lock"; exit $?
fi

# ── one run, on chain, polled long enough for a first compile ────────────────
send() {
  local args out tx logs ev i
  args=$(jq -nc --arg p "$PROJECT" --arg o "$PARENT" --arg pr "$PROFILE" --arg i "$INPUT" \
    '{source:{Project:{project_id:$p}}, input_data:$i,
      resource_limits:{max_instructions:1000000000,max_memory_mb:128,max_execution_seconds:30},
      secrets_ref:{profile:$pr, account_id:$o}}')
  out=$(near contract call-function as-transaction "$CONTRACT_ID" request_execution \
    json-args "$args" prepaid-gas '300.0 Tgas' attached-deposit "$DEPOSIT" \
    sign-as "$PARENT" network-config "$NETWORK" sign-with-keychain send 2>&1)
  tx=$(grep -oE 'Transaction ID: *[1-9A-HJ-NP-Za-km-z]{40,50}' <<<"$out" | grep -oE '[1-9A-HJ-NP-Za-km-z]{40,50}' | head -1)
  RUN_OK=absent; RUN_ERR=""; RUN_OUT=""
  [[ -z "$tx" ]] && { note "the send never landed: $(grep -iE 'panick|Error' <<<"$out" | head -2 | tr '\n' ' ' | head -c 240)"; return 0; }
  note "tx=$tx"
  ev=$(grep -o 'EVENT_JSON:.*execution_completed.*' <<<"$out" | sed 's/^EVENT_JSON://' | head -1)
  # The yield resolves in a later receipt of this same transaction, and the
  # first run of a fresh project compiles the repository first.
  for i in $(seq 1 90); do
    [[ -n "$ev" ]] && break
    logs=$(curl -sS --max-time 45 "$RPC_URL" -X POST -H 'Content-Type: application/json' \
      -d "$(jq -nc --arg t "$tx" --arg s "$PARENT" \
        '{jsonrpc:"2.0",id:1,method:"tx",params:{tx_hash:$t,sender_account_id:$s,wait_until:"FINAL"}}')" \
      | jq -r '[.result.receipts_outcome[]?.outcome.logs[]?] | join("\n")' 2>/dev/null)
    ev=$(grep -o 'EVENT_JSON:.*execution_completed.*' <<<"$logs" | sed 's/^EVENT_JSON://' | head -1)
    [[ -n "$ev" ]] && { note "completed after ~$((i*20))s"; break; }
    (( i % 9 == 0 )) && note "still working… ~$((i*20))s"
    sleep 20
  done
  [[ -z "$ev" ]] && return 0
  RUN_OK=$(jq -r '.data[0] | if has("success") then (.success|tostring) else "absent" end' <<<"$ev")
  RUN_ERR=$(jq -r '.data[0].error_message // ""' <<<"$ev")
  RUN_OUT=$(awk '/Function execution return value/{getline; print}' <<<"$out" | jq -c 'select(.!=null) | if type=="string" then fromjson else . end' 2>/dev/null)
}

# ── R2 the wrong build ───────────────────────────────────────────────────────
log "R2 the secret is locked to a build that is NOT this one — the run must not happen"
store "$PROJECT" "$PROFILE" "$(jq -nc '{UNUSED:"the module never reads this"}')" "whitelist:$PARENT"
set_access "$PROJECT" "$PROFILE" \
  "$(jq -nc --arg p "$PARENT" --arg h "$WRONG" '{Logic:{operator:"And",conditions:[{Whitelist:{accounts:[$p]}},{WasmHash:{hash:$h}}]}}')"
note "R2 this run compiles the project for the first time — minutes"
send
if [[ "$RUN_OK" == "true" ]]; then
  fail "R2 the run HAPPENED although the secret is locked to another build: $(head -c 200 <<<"$RUN_OUT")"
elif [[ "$RUN_OK" == "absent" ]]; then
  fail "R2 nothing answered in 30 minutes — a timeout is not a refusal"
elif grep -q "$WRONG" <<<"$RUN_ERR" && grep -q "$RIGHT" <<<"$RUN_ERR"; then
  pass "R2 refused, naming the locked build and the one that ran — and the platform measured the hash computed here before publishing"
elif grep -q "$WRONG" <<<"$RUN_ERR"; then
  # The lock held, but the platform's own bytes are not the ones this machine
  # built: the reproducible recipe has drifted, which is the finding.
  fail "R2 refused for the lock, but the build that RAN is not the one computed here ($RIGHT): $(head -c 240 <<<"$RUN_ERR")"
elif grep -qi "denied\|locked to build" <<<"$RUN_ERR"; then
  finding "R2 refused, but the reason names neither build: $(head -c 240 <<<"$RUN_ERR")"
else
  fail "R2 the run failed for something other than the lock: $(head -c 240 <<<"$RUN_ERR")"
fi

# ── R3 the right build ───────────────────────────────────────────────────────
log "R3 the lock moves to the build that runs — the same call now runs"
MOVE=$(OUTLAYER_NETWORK="$NETWORK" OUTLAYER_RPC_URL="$RPC_URL" "$OUTLAYER_BIN_PATH" \
  secrets access --project "$PROJECT" --profile "$PROFILE" --build "$RIGHT" 2>&1) \
  || fail "R3 the CLI would not move the lock: $(tail -3 <<<"$MOVE" | tr '\n' ' ' | head -c 240)"
sleep 5
STORED=$(jq -r '[.. | objects | select(has("WasmHash")) | .WasmHash.hash] | join(",")' <<<"$(jq -c '.access // {}' <<<"$(row_of "$PROJECT" "$PROFILE")")")
[[ "$STORED" == "$RIGHT" ]] && note "R3 the row is now locked to $STORED" || note "R3 the row holds '$STORED'"
send
if [[ "$RUN_OK" == "true" ]]; then
  pass "R3 the run happened once the lock named the real build$(jq -r 'if .random_number then " (random_number=\(.random_number))" else "" end' <<<"${RUN_OUT:-{\}}" 2>/dev/null)"
elif [[ "$RUN_OK" == "absent" ]]; then
  fail "R3 nothing answered — the run did not finish"
else
  fail "R3 still refused with the correct build locked: $(head -c 240 <<<"$RUN_ERR")"
fi

log cleanup
delete_row "$PROJECT" "$PROFILE"
note "the account $APP_OWNER and the project $PROJECT are LEFT BEHIND — a re-run reuses them"
verdict "fresh-project build lock"
