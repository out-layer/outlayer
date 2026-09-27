#!/usr/bin/env bash
#
# The coordinator's cleanup verification, live on TESTNET: what
# `POST /projects/cleanup-task/create` (worker bearer) answers for each
# combination of a live/deleted project and the block the request names
# (release-test-plan.md §8 "cleanup verification", L428–L430;
# prod-checks-after-hotfix.md C5). The rules it pins are
# `storage_cleanup_verdict` in the coordinator's src/handlers/topup.rs:
#
#   CV1  live project's uuid + a block_height from before the project existed
#        → 409 "… still exists …" (the `final` read decides; nothing queued)
#   CV2  deleted project + a pruned block (10000000) → 200, a task created; the
#        coordinator logs "block 10000000 is pruned on this node … deciding at
#        final"
#   CV3  deleted project + a block from before the delete → 409 "… still
#        exists … (block N)" — the event's block must show the project gone too
#   CV4  live project + a pruned block → 409 (the `final` read refuses alone)
#   CV5  a free project id carrying a live uuid → 409 "uuid … still belongs to a
#        live project"
#   CV6  block_height ahead of head → 503, never 409 and never a task: for the
#        deleted project (its block cannot be read yet) and for the live one
#        (this node's final is behind the event's block)
#   CV7  no block_height (an older worker) → the `final` reads alone: deleted →
#        200, live → 409 "(final block N)"
#   CV8  no refusal queued anything: no `project_storage_cleanup:uuid:<live>`
#        marker in Redis, and the live project is still on chain
#
# The two projects are created here, on OWNER's account, and both are deleted
# by the end (the live one at teardown). Nothing here names a project this run
# did not create. Their source is a WasmUrl nobody fetches — they never run.
#
# CV2 needs a NEW task, and the worker's own relay of the delete has already
# queued one (a 25 h dedupe marker per uuid): the suite deletes THAT marker for
# its own deleted project first (REDIS_CMD), so the answer shows `created:true`.
# The extra task erases a uuid that holds nothing.
#
# Secrets: the worker bearer comes from ONE line of scripts/.env
# (SMOKE_COORDINATOR_TOKEN_TESTNET), is held in this process only and reaches
# curl on stdin (`-H @-`). Never printed.
#
# Needs: OWNER (default outlayer-bob.testnet) with its key in the legacy
# keychain; REDIS_CMD (redis-cli args, testnet) for CV2/CV8; COORD_SSH for the
# coordinator log (read-only). The RPC is keyed through tests/lib/rpc.sh.
#
# Run:
#   REDIS_CMD=… ./tests/cleanup_verification_e2e.sh            # dry run
#   REDIS_CMD=… ./tests/cleanup_verification_e2e.sh --apply

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/lib/hos_common.sh"   # NETWORK, CONTRACT_ID, keyed RPC_URL, pass/fail/skip/verdict

APPLY=false
[[ "${1:-}" == "--apply" ]] && APPLY=true

OWNER="${OWNER:-outlayer-bob.testnet}"
ENV_FILE="${ENV_FILE:-$REPO_ROOT/scripts/.env}"
REDIS_CMD="${REDIS_CMD:-}"
COORD_SSH="${COORD_SSH:-root@138.201.58.122}"
COORD_CONTAINER="${COORD_CONTAINER:-offchainvm-coordinator-testnet}"
RUN_START=$(date +%s)
TAG="$RUN_START"
LIVE="cvlive-$TAG"
DEAD="cvdead-$TAG"
FREE="cvfree-$TAG"          # never created
PRUNED=10000000

# ── helpers ──────────────────────────────────────────────────────────────────

rpc_post() { # the keyed URL reaches curl on stdin
  printf 'url = "%s"\n' "$RPC_URL" | command curl -sS --max-time 45 -K - -X POST \
    -H 'Content-Type: application/json' --data-binary "$1" 2>/dev/null
}
view() { # view <method> <args-json>
  rpc_post "$(jq -nc --arg m "$1" --arg g "$(printf '%s' "$2" | base64 | tr -d '\n')" --arg c "$CONTRACT_ID" \
    '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"call_function",finality:"final",account_id:$c,method_name:$m,args_base64:$g}}')" \
    | jq -r 'if .result.result then (.result.result | implode) else empty end' 2>/dev/null
}
project_uuid() { view get_project "$(jq -nc --arg p "$1" '{project_id:$p}')" | jq -r '.uuid // empty' 2>/dev/null; }
has_uuid()     { view has_project_uuid "$(jq -nc --arg u "$1" '{project_uuid:$u}')"; }
final_height() { rpc_post '{"jsonrpc":"2.0","id":1,"method":"block","params":{"finality":"final"}}' | jq -r '.result.header.height // empty'; }
height_of_block() { rpc_post "$(jq -nc --arg h "$1" '{jsonrpc:"2.0",id:1,method:"block",params:{block_id:$h}}')" | jq -r '.result.header.height // empty'; }

call() { # call <method> <args-json> <deposit> — the whole transcript
  near contract call-function as-transaction "$CONTRACT_ID" "$1" json-args "$2" \
    prepaid-gas '100.0 Tgas' attached-deposit "$3" sign-as "$OWNER" network-config "$NETWORK" \
    sign-with-legacy-keychain send 2>&1
}
succeeded() { grep -q 'succeeded' <<<"$1"; }
tx_of() { grep -oE 'Transaction ID: *[1-9A-HJ-NP-Za-km-z]{40,50}' <<<"$1" | grep -oE '[1-9A-HJ-NP-Za-km-z]{40,50}' | head -1; }
# Why a near-cli call failed: the contract's panic message only. near-cli's
# own transport errors quote the request URL — the keyed RPC — so nothing else
# of its output is ever printed.
why_of() {
  local m
  m=$(grep -oE 'Smart contract panicked: [^"\\]*|panicked at [^"\\]*|ExecutionError\("[^"]*' <<<"$1" | grep -viE 'https?:|apikey' | head -2 | tr '\n' ' ' | head -c 300)
  if [[ -n "$m" ]]; then printf '%s' "$m"
  elif grep -qiE 'error sending request|failed to fetch|timed out|connection' <<<"$1"; then printf 'near-cli transport error (its text names the RPC URL, not printed)'
  else printf 'near-cli failed without a contract panic (output withheld)'; fi
}
# The height of the block the contract's receipt of <tx> executed in.
receipt_height() { # receipt_height <tx>
  local r h
  r=$(rpc_post "$(jq -nc --arg t "$1" --arg s "$OWNER" '{jsonrpc:"2.0",id:1,method:"tx",params:{tx_hash:$t,sender_account_id:$s,wait_until:"FINAL"}}')")
  h=$(jq -r --arg c "$CONTRACT_ID" '[.result.receipts_outcome[] | select(.outcome.executor_id == $c)][0].block_hash // empty' <<<"$r")
  [[ -n "$h" ]] && height_of_block "$h"
}

WORKER_TOKEN=""
if [[ -r "$ENV_FILE" ]]; then
  WORKER_TOKEN=$(grep '^SMOKE_COORDINATOR_TOKEN_TESTNET=' "$ENV_FILE" | head -1 | cut -d= -f2- | tr -d "\"'")
fi

# cleanup_req <project_id> <uuid> [block_height] — sets HTTP and BODY.
cleanup_req() {
  local body out
  body=$(jq -nc --arg p "$1" --arg u "$2" --arg h "${3:-}" \
    '{project_id:$p, project_uuid:$u} + (if $h == "" then {} else {block_height:($h|tonumber)} end)')
  out=$(mktemp -t cv_body.XXXXXX)
  HTTP=$(printf 'Authorization: Bearer %s\n' "$WORKER_TOKEN" | command curl -sS -o "$out" -w '%{http_code}' \
    --max-time 120 -X POST -H @- -H 'Content-Type: application/json' --data-binary "$body" \
    "$COORDINATOR_URL/projects/cleanup-task/create" 2>/dev/null)
  BODY=$(tr -d '\n' < "$out"); rm -f "$out"
}
short() { head -c "${2:-260}" <<<"${1:-$BODY}"; }

rds() { [[ -n "$REDIS_CMD" ]] && $REDIS_CMD "$@" 2>/dev/null | tr -d '\r'; }
coord_lines() { # coord_lines <fixed-string> — this run's coordinator log lines holding it
  local since=$(( $(date +%s) - RUN_START + 120 ))
  ssh -o ConnectTimeout=15 -o BatchMode=yes -o ControlMaster=no -o ControlPath=none "$COORD_SSH" \
    "docker logs $COORD_CONTAINER --since ${since}s 2>&1 | grep -F -- $(printf '%q' "$1") | tail -20" 2>/dev/null \
    | sed $'s/\x1b\\[[0-9;]*m//g'
}

# ── preflight ────────────────────────────────────────────────────────────────

log "cleanup_verification_e2e — $NETWORK, $( [[ $APPLY == true ]] && echo APPLY || echo 'dry run' )"
note "RPC: $(rpc_url_public)"
note "coordinator: ${COORDINATOR_URL#*://}; owner: $OWNER"
for tool in jq curl near ssh; do command -v "$tool" >/dev/null || { echo "✗ missing $tool" >&2; exit 1; }; done
[[ -f "$HOME/.near-credentials/$NETWORK/$OWNER.json" ]] || { echo "✗ no legacy-keychain key for $OWNER" >&2; exit 1; }
[[ -n "$WORKER_TOKEN" ]] && note "worker bearer: present (length ${#WORKER_TOKEN})" \
  || { echo "✗ no SMOKE_COORDINATOR_TOKEN_TESTNET in $ENV_FILE" >&2; exit 1; }
[[ "$(has_uuid p0000000000000000)" == false ]] || { echo "✗ $CONTRACT_ID answers no has_project_uuid" >&2; exit 1; }
REDIS_OK=false; [[ "$(rds PING)" == PONG ]] && REDIS_OK=true || warn "REDIS_CMD unset or silent: CV2's fresh task and CV8's marker check will SKIP"
LOGS_OK=false
ssh -o ConnectTimeout=15 -o BatchMode=yes -o ControlMaster=no -o ControlPath=none "$COORD_SSH" \
  "docker inspect -f '{{.State.Running}}' $COORD_CONTAINER" 2>/dev/null | grep -q true && LOGS_OK=true \
  || warn "coordinator log unreadable: CV2's log half will SKIP"

# The bearer is accepted: `{}` passes the auth layer and is refused by the
# body extractor (422) before the handler runs — nothing is read or queued.
# (Not an empty project/uuid: the handler takes those and queues a task.)
out=$(mktemp -t cv_body.XXXXXX)
HTTP=$(printf 'Authorization: Bearer %s\n' "$WORKER_TOKEN" | command curl -sS -o "$out" -w '%{http_code}' --max-time 30 \
  -X POST -H @- -H 'Content-Type: application/json' --data-binary '{}' "$COORDINATOR_URL/projects/cleanup-task/create" 2>/dev/null)
rm -f "$out"
[[ "$HTTP" == 422 ]] || { echo "✗ the worker route answered HTTP $HTTP to {} (expected 422: bearer accepted, body refused)" >&2; exit 1; }

if [[ "$APPLY" != true ]]; then
  sed -n '3,/^$/p' "$0" >&2
  note "would create $OWNER/$LIVE and $OWNER/$DEAD, delete $DEAD, run CV1–CV8, delete $LIVE"
  echo "  Pass --apply to run." >&2
  exit 0
fi

# ── fixtures: two projects, one deleted ─────────────────────────────────────

SRC=$(jq -nc --arg h "$(printf 'cleanup-verification-%s' "$TAG" | shasum -a 256 | cut -d' ' -f1)" \
  '{WasmUrl:{url:"https://cleanup-verification.invalid/never-fetched.wasm", hash:$h, build_target:"wasm32-wasip1"}}')

log "fixtures: $OWNER/$LIVE and $OWNER/$DEAD"
out=$(call create_project "$(jq -nc --arg n "$LIVE" --argjson s "$SRC" '{name:$n, source:$s}')" '0.3 NEAR')
succeeded "$out" || { echo "✗ create_project $LIVE: $(why_of "$out")" >&2; exit 1; }
LIVE_CREATED_AT=$(receipt_height "$(tx_of "$out")")
out=$(call create_project "$(jq -nc --arg n "$DEAD" --argjson s "$SRC" '{name:$n, source:$s}')" '0.3 NEAR')
succeeded "$out" || { echo "✗ create_project $DEAD: $(why_of "$out")" >&2; exit 1; }
LIVE_UUID=$(project_uuid "$OWNER/$LIVE"); DEAD_UUID=$(project_uuid "$OWNER/$DEAD")
[[ "$LIVE_UUID" =~ ^p[0-9a-f]{16}$ && "$DEAD_UUID" =~ ^p[0-9a-f]{16}$ && -n "$LIVE_CREATED_AT" ]] \
  || { echo "✗ fixtures incomplete: live '$LIVE_UUID' dead '$DEAD_UUID' created at '$LIVE_CREATED_AT'" >&2; exit 1; }
note "live $LIVE_UUID (created in block $LIVE_CREATED_AT), to-delete $DEAD_UUID"

teardown() {
  local rc=$?
  if [[ -n "$(project_uuid "$OWNER/$LIVE")" ]]; then
    call delete_project "$(jq -nc --arg n "$LIVE" '{project_name:$n}')" '0 NEAR' >/dev/null
    note "teardown: $OWNER/$LIVE deleted"
  fi
  return $rc
}
trap teardown EXIT

# A block at which DEAD exists: final, read after its create is final.
BEFORE_DELETE=$(final_height)
out=$(call delete_project "$(jq -nc --arg n "$DEAD" '{project_name:$n}')" '0 NEAR')
succeeded "$out" || { echo "✗ delete_project $DEAD: $(why_of "$out")" >&2; exit 1; }
DELETED_AT=$(receipt_height "$(tx_of "$out")")
note "$DEAD deleted in block $DELETED_AT (a block before the delete: $BEFORE_DELETE)"
[[ "$(has_uuid "$DEAD_UUID")" == false && "$(has_uuid "$LIVE_UUID")" == true ]] \
  || { echo "✗ chain state: has_project_uuid dead=$(has_uuid "$DEAD_UUID") live=$(has_uuid "$LIVE_UUID")" >&2; exit 1; }

# The worker's own relay of the delete comes first; wait for its marker so
# the requests below are judged after it, not raced against it.
if $REDIS_OK; then
  for i in $(seq 1 30); do [[ "$(rds EXISTS "project_storage_cleanup:uuid:$DEAD_UUID")" == 1 ]] && break; sleep 6; done
  [[ "$(rds EXISTS "project_storage_cleanup:uuid:$DEAD_UUID")" == 1 ]] \
    && note "the worker relayed the delete: task $(rds GET "project_storage_cleanup:uuid:$DEAD_UUID") queued for $DEAD_UUID" \
    || warn "no cleanup marker for $DEAD_UUID after 3 min — the worker's relay did not arrive"
fi

# ── CV1 live uuid + a block before the project existed ─────────────────────
log "CV1 live project + a block_height from before it existed"
H=$(( LIVE_CREATED_AT - 20 ))
cleanup_req "$OWNER/$LIVE" "$LIVE_UUID" "$H"
[[ "$HTTP" == 409 && "$BODY" == *"project $OWNER/$LIVE still exists on the contract with uuid $LIVE_UUID"* && "$BODY" == *"(final block "* ]] \
  && pass "CV1 block $H (before the create at $LIVE_CREATED_AT) → 409: $(short)" \
  || fail "CV1 → HTTP $HTTP: $(short)"

# ── CV2 deleted project + a pruned block ────────────────────────────────────
log "CV2 deleted project + block_height $PRUNED"
if $REDIS_OK; then
  prev=$(rds GET "project_storage_cleanup:uuid:$DEAD_UUID")
  rds DEL "project_storage_cleanup:uuid:$DEAD_UUID" >/dev/null
  note "dropped this run's own dedupe marker for $DEAD_UUID (worker task ${prev:-none})"
fi
cleanup_req "$OWNER/$DEAD" "$DEAD_UUID" "$PRUNED"
CV2_TASK=$(jq -r '.task_id // empty' <<<"$BODY" 2>/dev/null)
if $REDIS_OK; then
  [[ "$HTTP" == 200 && "$(jq -r .created <<<"$BODY" 2>/dev/null)" == true && "$CV2_TASK" =~ ^[0-9]+$ ]] \
    && pass "CV2 → 200 created:true, task_id $CV2_TASK" || fail "CV2 → HTTP $HTTP: $(short)"
  [[ "$(rds GET "project_storage_cleanup:uuid:$DEAD_UUID")" == "$CV2_TASK" ]] \
    && pass "CV2 the task is queued: marker project_storage_cleanup:uuid:$DEAD_UUID = $CV2_TASK" \
    || fail "CV2 marker for $DEAD_UUID reads '$(rds GET "project_storage_cleanup:uuid:$DEAD_UUID")', expected $CV2_TASK"
else
  [[ "$HTTP" == 200 && "$CV2_TASK" =~ ^[0-9]+$ ]] && pass "CV2 → 200 task_id $CV2_TASK (created:$(jq -r .created <<<"$BODY"))" \
    || fail "CV2 → HTTP $HTTP: $(short)"
fi
if $LOGS_OK; then
  line=""
  for i in 1 2 3 4 5 6; do
    line=$(coord_lines "ProjectStorageCleanup $DEAD_UUID: block $PRUNED is pruned on this node" | tail -1)
    [[ -n "$line" ]] && break; sleep 5
  done
  [[ -n "$line" && "$line" == *"deciding at final"* ]] \
    && pass "CV2 coordinator: block $PRUNED is pruned on this node … deciding at final" \
    || fail "CV2 no 'block $PRUNED is pruned on this node … deciding at final' line for $DEAD_UUID — the block was read, or the log is elsewhere"
else
  skip "CV2 the coordinator log line — log unreadable"
fi

# ── CV3 deleted project + a block before the delete ─────────────────────────
log "CV3 deleted project + block_height $BEFORE_DELETE (before the delete at $DELETED_AT)"
cleanup_req "$OWNER/$DEAD" "$DEAD_UUID" "$BEFORE_DELETE"
[[ "$HTTP" == 409 && "$BODY" == *"project $OWNER/$DEAD still exists on the contract with uuid $DEAD_UUID"* && "$BODY" == *"(block $BEFORE_DELETE)"* ]] \
  && pass "CV3 → 409: $(short)" || fail "CV3 → HTTP $HTTP: $(short)"

# ── CV4 live project + a pruned block ───────────────────────────────────────
log "CV4 live project + block_height $PRUNED"
cleanup_req "$OWNER/$LIVE" "$LIVE_UUID" "$PRUNED"
[[ "$HTTP" == 409 && "$BODY" == *"still exists on the contract with uuid $LIVE_UUID"* ]] \
  && pass "CV4 → 409: $(short)" || fail "CV4 → HTTP $HTTP: $(short)"

# ── CV5 a free project id carrying a live uuid ──────────────────────────────
log "CV5 $OWNER/$FREE (never created) + the live uuid"
[[ -z "$(project_uuid "$OWNER/$FREE")" ]] || fail "CV5 precondition: $OWNER/$FREE exists"
for h in "" "$PRUNED"; do
  cleanup_req "$OWNER/$FREE" "$LIVE_UUID" "$h"
  [[ "$HTTP" == 409 && "$BODY" == *"uuid $LIVE_UUID still belongs to a live project on the contract (the event names $OWNER/$FREE)"* ]] \
    && pass "CV5 ${h:-no block} → 409: $(short)" || fail "CV5 ${h:-no block} → HTTP $HTTP: $(short)"
done

# ── CV6 a block ahead of head ───────────────────────────────────────────────
HEAD=$(final_height); AHEAD=$(( HEAD + 1000 ))
log "CV6 block_height $AHEAD (final is $HEAD)"
cleanup_req "$OWNER/$DEAD" "$DEAD_UUID" "$AHEAD"
[[ "$HTTP" == 503 && "$BODY" == *"cannot confirm on the contract that project $OWNER/$DEAD is deleted"*"at block $AHEAD"* ]] \
  && pass "CV6 deleted project, block ahead → 503: $(short)" || fail "CV6 deleted project, block ahead → HTTP $HTTP: $(short)"
cleanup_req "$OWNER/$LIVE" "$LIVE_UUID" "$AHEAD"
[[ "$HTTP" == 503 && "$BODY" == *"is behind the event's block $AHEAD"* ]] \
  && pass "CV6 live project, block ahead → 503 (not 409): $(short)" || fail "CV6 live project, block ahead → HTTP $HTTP: $(short)"

# ── CV7 no block_height ─────────────────────────────────────────────────────
log "CV7 requests without block_height"
cleanup_req "$OWNER/$DEAD" "$DEAD_UUID"
[[ "$HTTP" == 200 && "$(jq -r .task_id <<<"$BODY" 2>/dev/null)" =~ ^[0-9]+$ ]] \
  && pass "CV7 deleted project, final only → 200 $(short)" || fail "CV7 deleted project, no block → HTTP $HTTP: $(short)"
cleanup_req "$OWNER/$LIVE" "$LIVE_UUID"
[[ "$HTTP" == 409 && "$BODY" == *"still exists on the contract with uuid $LIVE_UUID; its storage is not erased (final block "* ]] \
  && pass "CV7 live project, final only → 409: $(short)" || fail "CV7 live project, no block → HTTP $HTTP: $(short)"

# ── CV8 nothing queued for the live uuid ────────────────────────────────────
log "CV8 the refusals queued nothing"
if $REDIS_OK; then
  [[ "$(rds EXISTS "project_storage_cleanup:uuid:$LIVE_UUID")" == 0 ]] \
    && pass "CV8 no cleanup marker for the live uuid $LIVE_UUID" \
    || fail "CV8 a cleanup marker exists for the LIVE uuid $LIVE_UUID (task $(rds GET "project_storage_cleanup:uuid:$LIVE_UUID"))"
else
  skip "CV8 marker check — no Redis"
fi
[[ "$(has_uuid "$LIVE_UUID")" == true && "$(project_uuid "$OWNER/$LIVE")" == "$LIVE_UUID" ]] \
  && pass "CV8 $OWNER/$LIVE is still $LIVE_UUID on chain" || fail "CV8 the live project changed on chain"

verdict "cleanup_verification_e2e"
