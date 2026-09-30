#!/usr/bin/env bash
#
# The contract/coordinator hotfix, end to end on testnet: the contract's code
# source rules, the storage namespace it names, `has_project_uuid`, the delete
# path through the coordinator, and the coordinator's project name → uuid cache
# across a delete and a transfer.
#
# What each row pins (.idea/_todo/prod-checks-after-hotfix.md §C,
# .idea/_todo/release-test-plan.md §7):
#   C1   `create_project`, `add_version` and an inline `request_execution` refuse
#        a WasmUrl hash spelling `EVENT_JSON:{…}`, a repo / commit / url holding
#        `EVENT_JSON` or a newline, a url with whitespace or over 2048 bytes
#   C1a  the rest of `code_source_error`, each a panic naming the field: hash in
#        UPPERCASE or 63 chars; url `http://…` / `ipfs://…`; repo starting `-` or
#        holding `..`; commit with `..` or over 256 bytes; build_target
#        `wasm32 wasip2` or over 64 bytes. No refused project exists afterwards
#   C1b still accepted: a WasmUrl with a 64-lowercase-hex hash over https://
#        (build_target wasm32-wasip2); GitHub `https://github.com/<o>/<r>` at a
#        40-hex sha, a branch `feature/x`, a tag `v1.0.0+build`; a Project-source
#        run of a version stored before the rules (found by scanning the testnet
#        projects the coordinator has seen; SKIP when none is left)
#   C2   an inline run with `params.project_uuid` set to a live project's uuid →
#        its `execution_requested` event carries `project_uuid: null` and the run
#        does not read that project's storage; a Project run whose params name
#        another uuid carries the project's own and reads its own storage
#   C3   `has_project_uuid`: live → true, deleted → false, p0000000000000000 → false
#   C4   a genuine `delete_project` → the coordinator creates the cleanup task
#        (its log), the project's `storage_data` rows are erased, and a public
#        read by the old uuid finds nothing
#   C5   cleanup refusals need the worker bearer: SKIP here, always, loudly —
#        tests/cleanup_verification_e2e.sh runs them
#   C10  a project run logs `Resolved project: …, version: "<key>"` (quoted); a
#        Text answer with a line break logs `Text: "…\n…"` in one log;
#        `set_active_version` logs `version="…"`
#   R7-cache-ttl     a by-name public read caches `project_uuid_by_name:<owner>/<name>`
#                    with a TTL in 1..86400
#   R7-cache-delete  after `delete_project` the coordinator logs
#                    `Invalidated project uuid cache: project_id=<owner>/<name> removed=1`,
#                    `project_invalidated:<name>` lives 1..120 s and a read inside
#                    that window caches nothing; the project created again under
#                    the name is read by name (its value, not the deleted one's);
#                    after the window the name caches the NEW uuid
#   R7-cache-transfer `transfer_project` → the `ProjectTransferred` event, the
#                    coordinator invalidates both names; the new name reads the
#                    transferred value; a project created again under the old name
#                    reads its own, and the transferred uuid still reads the old
#   R7-bookkeeping   the run of a project created again after a delete and after a
#                    transfer is booked (`execution_requests.project_uuid`) under
#                    the NEW uuid — on chain always; over `POST /call` only with
#                    PAYMENT_KEY (a funded key of OWNER_A), else SKIP
#
# The public worker record comes from wasi-examples/test-storage-ark
# (`set_public` = `set_worker_with_options(k, v, Some(false))`); the Text row
# from wasi-examples/echo-example. Both are uploaded to FastFS as OWNER_A (a
# private OUTLAYER_HOME built from OWNER_A's key file, removed on exit).
#
# Needs: OWNER_A and OWNER_B (defaults a01.zt0.testnet / a02.zt0.testnet), each
# with its key in the legacy keychain ~/.near-credentials/testnet/<acct>.json;
# near, outlayer, jq, curl, python3, shasum. The RPC is keyed through
# tests/lib/rpc.sh. Read-only operator access, each optional — a row that needs
# one it lacks SKIPS, loudly:
#   PSQL_CMD   a command taking one SELECT (coordinator DB)       — C4, bookkeeping, C1b legacy scan
#   REDIS_CMD  a command taking redis-cli arguments (TTL/EXISTS/GET) — cache rows
#   COORD_SSH  ssh target whose `docker logs $COORD_CONTAINER` is read
#              (default root@138.201.58.122 / offchainvm-coordinator-testnet)
#   PAYMENT_KEY  OWNER_A's funded payment key (`owner:nonce:secret`) — the /call half
#
# Money: two FastFS uploads (~500 KB + ~65 KB), ~27 refused transactions (gas
# only; deposits come back), five projects' storage (refunded on delete), and
# ~8 runs at $DEPOSIT (the unused part comes back).
#
# Env: KEEP=1 leaves the run's projects on chain (default: deleted at the end).
#
# Run:
#   PSQL_CMD=… REDIS_CMD=… ./tests/contract_hotfix_e2e.sh            # dry run: checks, no writes
#   PSQL_CMD=… REDIS_CMD=… ./tests/contract_hotfix_e2e.sh --apply    # everything

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/lib/hos_common.sh"   # NETWORK, CONTRACT_ID, keyed RPC_URL, pass/fail/skip/verdict, sql

APPLY=false
[[ "${1:-}" == "--apply" ]] && APPLY=true

OWNER_A="${OWNER_A:-a01.zt0.testnet}"
OWNER_B="${OWNER_B:-a02.zt0.testnet}"
DEPOSIT="${DEPOSIT:-0.1 NEAR}"
REDIS_CMD="${REDIS_CMD:-}"
COORD_SSH="${COORD_SSH:-root@138.201.58.122}"
COORD_CONTAINER="${COORD_CONTAINER:-offchainvm-coordinator-testnet}"
PAYMENT_KEY="${PAYMENT_KEY:-}"
KEEP="${KEEP:-0}"
RUN_START=$(date +%s)
TAG="$RUN_START"
NAME="cachetest-$TAG"          # the project deleted, recreated, transferred, recreated
SCRATCH="hfsrc-$TAG"           # the project add_version is tried on
BADNAME="hfbad-$TAG"           # a project no refused create_project may leave behind
STORE_DIR="$REPO_ROOT/wasi-examples/test-storage-ark"
STORE_WASM="$STORE_DIR/target/wasm32-wasip2/release/test-storage-ark.wasm"
ECHO_WASM="$REPO_ROOT/wasi-examples/echo-example/target/wasm32-wasip1/release/echo-example.wasm"
export OUTLAYER_NETWORK="$NETWORK"

OL_HOME=$(mktemp -d -t contract_hotfix_ol.XXXXXX)
trap 'rm -rf "$OL_HOME"' EXIT

# ── helpers ──────────────────────────────────────────────────────────────────

# The keyed RPC URL reaches curl on stdin (a config line written by a shell
# builtin), never on a command line.
rpc_post() { # rpc_post <json-body>
  printf 'url = "%s"\n' "$RPC_URL" | curl -sS --max-time 45 -K - -X POST \
    -H 'Content-Type: application/json' --data-binary "$1" 2>/dev/null
}

view() { # view <account> <method> <args-json> — the decoded result, or empty
  rpc_post "$(jq -nc --arg a "$1" --arg m "$2" --arg g "$(printf '%s' "$3" | base64 | tr -d '\n')" \
    '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"call_function",finality:"final",account_id:$a,method_name:$m,args_base64:$g}}')" \
    | jq -r 'if .result.result then (.result.result | implode) else empty end' 2>/dev/null
}
has_uuid()     { view "$CONTRACT_ID" has_project_uuid "$(jq -nc --arg u "$1" '{project_uuid:$u}')"; }
project_uuid() { view "$CONTRACT_ID" get_project "$(jq -nc --arg p "$1" '{project_id:$p}')" | jq -r '.uuid // empty' 2>/dev/null; }

sha_of() { shasum -a 256 "$1" | cut -d' ' -f1; }
is_uuid() { [[ "$1" =~ ^p[0-9a-f]{16}$ ]]; }

signer_flag() { [[ -f "$HOME/.near-credentials/$NETWORK/$1.json" ]] && echo with-legacy-keychain || echo with-keychain; }

# One contract call, its whole transcript on stdout. near-cli takes the key's
# nonce from the RPC, which can answer with the state of a block before the
# signer's previous transaction; that call is sent once more, after a pause.
call() { # call <signer> <method> <args-json> <deposit>
  local out i
  for i in 1 2 3; do
    out=$(near contract call-function as-transaction "$CONTRACT_ID" "$2" json-args "$3" \
      prepaid-gas '300.0 Tgas' attached-deposit "$4" sign-as "$1" network-config "$NETWORK" "sign-$(signer_flag "$1")" send 2>&1)
    grep -qE 'Transaction nonce .* must be|InvalidNonce|Transaction has expired' <<<"$out" || break
    sleep $((i * 3))
  done
  printf '%s\n' "$out"
}
succeeded() { grep -q 'succeeded' <<<"$1"; }
tx_of() { grep -oE 'Transaction ID: *[1-9A-HJ-NP-Za-km-z]{40,50}' <<<"$1" | grep -oE '[1-9A-HJ-NP-Za-km-z]{40,50}' | head -1; }
# The contract's panic, or near-cli's own reason line through `near_why`
# (lib/near_sign.sh): near-cli's transport errors quote the request URL (the
# keyed RPC), so no other line of its output is printed.
source "$SCRIPT_DIR/lib/near_sign.sh"
why_of() {
  local m
  m=$(grep -oE 'Smart contract panicked: [^"\\]*|panicked at [^"\\]*' <<<"$1" | grep -viE 'https?:|apikey' | head -2 | tr '\n' ' ' | head -c 400)
  [[ -n "$m" ]] && printf '%s' "$m" || near_why "$1"
}

# Every log of a transaction, as a JSON array, once it is final.
tx_logs() { # tx_logs <tx> <signer>
  local r i
  for i in 1 2 3 4 5 6; do
    r=$(rpc_post "$(jq -nc --arg t "$1" --arg s "$2" \
      '{jsonrpc:"2.0",id:1,method:"tx",params:{tx_hash:$t,sender_account_id:$s,wait_until:"FINAL"}}')")
    jq -e '.result' <<<"$r" >/dev/null 2>&1 && {
      jq -c '[.result.transaction_outcome.outcome.logs[]?, .result.receipts_outcome[]?.outcome.logs[]?]' <<<"$r"; return 0; }
    sleep 5
  done
  echo '[]'
}
events_of() { # events_of <logs-json> <event> — the matching events' data[0], one per line
  jq -c --arg e "$2" '.[] | select(startswith("EVENT_JSON:")) | ltrimstr("EVENT_JSON:") | (try fromjson catch empty)
    | select(.event == $e) | .data[0]' <<<"$1" 2>/dev/null
}

# ── one run, on chain ────────────────────────────────────────────────────────
#
# `run <signer> <args-json>` sets RUN_OK (true / false / absent), RUN_ERR, RUN_OUT
# (the guest's answer), RUN_LOGS (every log of the transaction, JSON array),
# RUN_REQ (the `execution_requested` request_data, JSON) and RUN_TX.
RUN_OK=""; RUN_ERR=""; RUN_OUT=""; RUN_LOGS="[]"; RUN_REQ=""; RUN_TX=""
exec_args() { # exec_args <source-json> <input-string> [params-json] [format]
  jq -nc --argjson s "$1" --arg i "$2" --argjson p "${3:-null}" --arg f "${4:-Json}" \
    '{source:$s, input_data:$i, response_format:$f,
      resource_limits:{max_instructions:10000000000,max_memory_mb:128,max_execution_seconds:60}}
     + (if $p == null then {} else {params:$p} end)'
}
run() { # run <signer> <args-json>
  local out res i ev
  RUN_OK=""; RUN_ERR=""; RUN_OUT=""; RUN_LOGS="[]"; RUN_REQ=""; RUN_TX=""
  out=$(call "$1" request_execution "$2" "$DEPOSIT")
  RUN_TX=$(tx_of "$out")
  if [[ -z "$RUN_TX" ]]; then RUN_OK=absent; RUN_ERR=$(why_of "$out"); return 0; fi
  for i in $(seq 1 40); do
    res=$(rpc_post "$(jq -nc --arg t "$RUN_TX" --arg s "$1" \
      '{jsonrpc:"2.0",id:1,method:"tx",params:{tx_hash:$t,sender_account_id:$s,wait_until:"FINAL"}}')")
    if jq -e '.result' <<<"$res" >/dev/null 2>&1; then
      RUN_LOGS=$(jq -c '[.result.transaction_outcome.outcome.logs[]?, .result.receipts_outcome[]?.outcome.logs[]?]' <<<"$res")
      grep -q 'execution_completed' <<<"$RUN_LOGS" && break
      jq -e '[.result.receipts_outcome[]?.outcome.status | select(has("Failure"))] | length > 0' <<<"$res" >/dev/null 2>&1 && break
    fi
    (( i % 6 == 0 )) && note "still waiting for the run… ~$((i*10))s"
    sleep 10
  done
  RUN_REQ=$(events_of "$RUN_LOGS" execution_requested | head -1 | jq -c '.request_data | fromjson' 2>/dev/null)
  RUN_OUT=$(jq -r '.result.status.SuccessValue // empty | @base64d' <<<"$res" 2>/dev/null \
    | jq -c 'select(. != null) | if type=="string" then (try fromjson catch .) else . end' 2>/dev/null)
  ev=$(events_of "$RUN_LOGS" execution_completed | head -1)
  if [[ -z "$ev" ]]; then
    RUN_OK=absent
    RUN_ERR=$(jq -r '.result.receipts_outcome[]?.outcome.status.Failure? // empty | tostring' <<<"$res" 2>/dev/null | head -2 | tr '\n' ' ' | head -c 300)
    return 0
  fi
  RUN_OK=$(jq -r 'if has("success") then (.success|tostring) else "absent" end' <<<"$ev")
  RUN_ERR=$(jq -r '.error_message // ""' <<<"$ev")
}
req_uuid() { # the event's project_uuid, `null`, or `<no event>`
  [[ -n "$RUN_REQ" ]] || { printf '<no event>'; return 0; }
  jq -r 'if .project_uuid == null then "null" else .project_uuid end' <<<"$RUN_REQ" 2>/dev/null
}
req_id() { [[ -n "$RUN_REQ" ]] && jq -r '.request_id // empty' <<<"$RUN_REQ" 2>/dev/null; }
out_field() { jq -r "$1 | if . == null then \"\" else tostring end" <<<"${RUN_OUT:-null}" 2>/dev/null; }

wasm_src() { jq -nc --arg u "$1" --arg h "$2" --arg t "${3:-wasm32-wasip2}" '{WasmUrl:{url:$u, hash:$h, build_target:$t}}'; }
gh_src()   { jq -nc --arg r "$1" --arg c "$2" --arg t "${3:-wasm32-wasip2}" '{GitHub:{repo:$r, commit:$c, build_target:$t}}'; }
proj_src() { # proj_src <project_id> [version_key]
  if [[ -n "${2:-}" ]]; then jq -nc --arg p "$1" --arg v "$2" '{Project:{project_id:$p, version_key:$v}}'
  else jq -nc --arg p "$1" '{Project:{project_id:$p}}'; fi
}
put_public() { # put_public <signer> <project_id> <value> — run test-storage-ark set_public k=<value>
  run "$1" "$(exec_args "$(proj_src "$2")" "$(jq -nc --arg v "$3" '{command:"set_public",key:"k",value:$v}')")"
}

# ── coordinator: public API, logs, DB, Redis ─────────────────────────────────

# pub_get <project-name-or-uuid> <key> — the value, `<absent>`, or `<HTTP nnn>`.
pub_get() {
  local r code body
  throttle
  r=$(curl -sS --max-time 30 -G "$COORDINATOR_URL/public/storage/get" \
        --data-urlencode "project=$1" --data-urlencode "key=$2" -w $'\n%{http_code}' 2>/dev/null)
  code=${r##*$'\n'}; body=${r%$'\n'*}
  [[ "$code" == 200 ]] || { printf '<HTTP %s>' "$code"; return 0; }
  if [[ "$(jq -r '.exists' <<<"$body" 2>/dev/null)" == true ]]; then
    jq -r '.value' <<<"$body" | base64 -d 2>/dev/null
  else
    printf '<absent>'
  fi
}

LOGS_OK=false; REDIS_OK=false; SQL_OK=false
# Coordinator log lines since the run began that hold the fixed string <s>,
# colour codes stripped. Read-only: `docker logs | grep -F`.
coord_lines() { # coord_lines <fixed-string>
  local since=$(( $(date +%s) - RUN_START + 120 ))
  ssh -o ConnectTimeout=15 -o BatchMode=yes -o ControlMaster=no -o ControlPath=none "$COORD_SSH" \
    "docker logs $COORD_CONTAINER --since ${since}s 2>&1 | grep -F -- $(printf '%q' "$1") | tail -40" 2>/dev/null \
    | sed $'s/\x1b\\[[0-9;]*m//g'
}
# coord_wait <fixed-string> <min-count> [tries] [ERE] — waits for at least
# <min-count> lines holding the string (and matching the ERE); prints the last
# one. Returns 1 when they never came.
coord_wait() {
  local n i lines
  for i in $(seq 1 "${3:-24}"); do
    lines=$(coord_lines "$1" | grep -E -- "${4:-.}")
    n=$(grep -c . <<<"$lines")
    (( n >= $2 )) && { tail -1 <<<"$lines" | head -c 300; return 0; }
    sleep 10
  done
  return 1
}
rds() { [[ -n "$REDIS_CMD" ]] && $REDIS_CMD "$@" 2>/dev/null | tr -d '\r'; }
sq() { sql "$1" 2>/dev/null; }

# ── preflight ────────────────────────────────────────────────────────────────

note "RPC: $(rpc_url_public)"
for tool in jq curl near outlayer python3 shasum ssh; do
  command -v "$tool" >/dev/null || { echo "✗ missing $tool" >&2; exit 1; }
done
[[ "$OWNER_A" != "$OWNER_B" ]] || { echo "✗ OWNER_B must be another account than OWNER_A" >&2; exit 1; }
CREDS_DIR="$HOME/.near-credentials/$NETWORK"
for acct in "$OWNER_A" "$OWNER_B"; do
  [[ -f "$CREDS_DIR/$acct.json" ]] || { echo "✗ no key in the legacy keychain for $acct ($CREDS_DIR/$acct.json)" >&2; exit 1; }
done

HAS_VIEW=$(has_uuid p0000000000000000)
[[ "$HAS_VIEW" == "false" || "$HAS_VIEW" == "true" ]] \
  || { echo "✗ $CONTRACT_ID has no has_project_uuid (answer: '${HAS_VIEW:-none}') — the hotfix contract is not deployed here" >&2; exit 1; }

if ssh -o ConnectTimeout=15 -o BatchMode=yes -o ControlMaster=no -o ControlPath=none "$COORD_SSH" \
     "docker inspect -f '{{.State.Running}}' $COORD_CONTAINER" 2>/dev/null | grep -q true; then
  LOGS_OK=true
else
  warn "coordinator logs unreadable ($COORD_SSH / $COORD_CONTAINER): the log halves will SKIP"
fi
[[ "$(rds PING)" == "PONG" ]] && REDIS_OK=true || warn "REDIS_CMD unset or not answering: the Redis halves will SKIP"
sql_alive && SQL_OK=true || warn "PSQL_CMD unset or not answering: the DB halves will SKIP"

# A version stored before the rules: the first version of a project the
# coordinator has seen whose source `code_source_error` would refuse today, on
# an unpriced project. Prints `<project_id> <version_key>`.
legacy_version() {
  local p
  for p in $(sq "SELECT DISTINCT project_id FROM execution_requests WHERE project_id LIKE '%/%' ORDER BY 1"); do
    [[ -n "$(view "$CONTRACT_ID" get_project_pricing "$(jq -nc --arg p "$p" '{project_id:$p}')" | jq -r 'select(. != null) | 1' 2>/dev/null)" ]] && continue
    view "$CONTRACT_ID" list_versions "$(jq -nc --arg p "$p" '{project_id:$p, limit:100}')" \
      | jq -c --arg p "$p" '.[]? | {p:$p, k:.wasm_hash, s:.source}' 2>/dev/null
  done | python3 -c '
import json, re, sys
def bad(s):
    if "WasmUrl" in s:
        w = s["WasmUrl"]; u, h, bt = w["url"], w["hash"], w.get("build_target")
        if not re.fullmatch(r"[0-9a-f]{64}", h): return True
        if not u.startswith("https://") or len(u) <= 8 or len(u) > 2048: return True
        if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in u) or "EVENT_JSON" in u: return True
    else:
        g = s["GitHub"]; r, c, bt = g["repo"], g["commit"], g.get("build_target")
        if not 1 <= len(r) <= 512 or r.startswith("-") or ".." in r or not re.fullmatch(r"[A-Za-z0-9._/:-]+", r): return True
        if not 1 <= len(c) <= 256 or c.startswith("-") or ".." in c or not re.fullmatch(r"[A-Za-z0-9._/+-]+", c): return True
        if "EVENT_JSON" in r + c: return True
    return bt is not None and (not bt or len(bt) > 64 or not re.fullmatch(r"[A-Za-z0-9._-]+", bt))
for line in sys.stdin:
    d = json.loads(line)
    if bad(d["s"]): print(d["p"], d["k"]); break
'
}

if [[ "$APPLY" != true ]]; then
  log "dry run — nothing is uploaded, created, run or deleted"
  sed -n '3,/^$/p' "$0" >&2
  note "owners: A=$OWNER_A B=$OWNER_B; projects this run would use: $NAME, $SCRATCH (and $BADNAME, refused)"
  [[ -f "$STORE_WASM" ]] && note "test-storage-ark: built, sha256 $(sha_of "$STORE_WASM")" || note "test-storage-ark: not built (--apply runs its build.sh)"
  [[ -f "$ECHO_WASM" ]] && note "echo-example: built, sha256 $(sha_of "$ECHO_WASM")" || warn "echo-example not built: C10's Text half will SKIP"
  note "operator access: logs=$LOGS_OK redis=$REDIS_OK db=$SQL_OK; /call half: $([[ -n "$PAYMENT_KEY" ]] && echo 'PAYMENT_KEY present' || echo 'SKIP (no PAYMENT_KEY)')"
  if [[ "$SQL_OK" == true ]]; then
    lv=$(legacy_version)
    [[ -n "$lv" ]] && note "C1b legacy version: $lv" || warn "C1b legacy half will SKIP: no pre-rule version found"
  fi
  echo "  Pass --apply to run." >&2
  exit 0
fi

# ── setup: build, upload ─────────────────────────────────────────────────────

log "setup: the storage probe and the echo module, uploaded as $OWNER_A"
if [[ ! -f "$STORE_WASM" ]]; then
  (cd "$STORE_DIR" && ./build.sh >/dev/null) || { echo "✗ $STORE_DIR/build.sh failed" >&2; exit 1; }
fi
H_S=$(sha_of "$STORE_WASM")
# The upload signs as OWNER_A: a private OUTLAYER_HOME holding OWNER_A's key,
# written file to file, readable by this user only, removed on exit.
mkdir -p "$OL_HOME/$NETWORK" && chmod 700 "$OL_HOME"
# The account comes from OWNER_A: near-cli key files do not always carry `account_id`.
( umask 077; jq --arg c "$CONTRACT_ID" --arg a "$OWNER_A" '{account_id:$a, public_key, private_key, contract_id:$c, auth_type:"near_key"}' \
    "$CREDS_DIR/$OWNER_A.json" > "$OL_HOME/$NETWORK/credentials.json" )
export OUTLAYER_HOME="$OL_HOME"
U_S=$(fastfs_upload "$STORE_WASM" "$H_S") || { echo "✗ the storage probe never served its bytes from FastFS" >&2; exit 1; }
note "test-storage-ark $H_S at $U_S"
U_E=""; H_E=""
if [[ -f "$ECHO_WASM" ]]; then
  H_E=$(sha_of "$ECHO_WASM")
  U_E=$(fastfs_upload "$ECHO_WASM" "$H_E") || { warn "echo-example never served its bytes: C10's Text half will SKIP"; U_E=""; }
  [[ -n "$U_E" ]] && note "echo-example $H_E at $U_E"
fi
unset OUTLAYER_HOME

# ── C1b a WasmUrl source, accepted ───────────────────────────────────────────

log "C1b a WasmUrl source over https:// with a 64-hex hash, build_target wasm32-wasip2"
for p in "$NAME" "$SCRATCH"; do
  out=$(call "$OWNER_A" create_project "$(jq -nc --arg n "$p" --argjson s "$(wasm_src "$U_S" "$H_S")" '{name:$n, source:$s}')" '0.3 NEAR')
  succeeded "$out" || { echo "✗ create_project $p failed: $(why_of "$out")" >&2; exit 1; }
done
sleep 3
UUID1=$(project_uuid "$OWNER_A/$NAME")
is_uuid "$UUID1" && pass "C1b create_project with a WasmUrl source — $OWNER_A/$NAME is $UUID1" \
  || { fail "C1b create_project — $OWNER_A/$NAME has no uuid on chain ('$UUID1')"; verdict "contract hotfix"; exit $?; }

log "C1b GitHub sources: a 40-hex sha, a branch feature/x, a tag v1.0.0+build"
GH_REPO="https://github.com/out-layer/outlayer"
for c in "$(git -C "$REPO_ROOT" rev-parse HEAD)" "feature/x" "v1.0.0+build"; do
  out=$(call "$OWNER_A" add_version "$(jq -nc --arg n "$SCRATCH" --argjson s "$(gh_src "$GH_REPO" "$c")" '{project_name:$n, source:$s, set_active:false}')" '0.1 NEAR')
  kind=$(view "$CONTRACT_ID" get_version "$(jq -nc --arg p "$OWNER_A/$SCRATCH" --arg v "$GH_REPO@$c" '{project_id:$p, version_key:$v}')" \
    | jq -r 'select(. != null) | .source | keys[0] // empty' 2>/dev/null)
  if succeeded "$out" && [[ "$kind" == GitHub ]]; then pass "C1b add_version GitHub @ $c — accepted, stored"
  else fail "C1b add_version GitHub @ $c — $(succeeded "$out" && echo "succeeded but get_version says '${kind:-nothing}'" || why_of "$out")"; fi
done

# ── C1 / C1a refusals ────────────────────────────────────────────────────────

LONG_URL="https://example.com/$(printf 'a%.0s' $(seq 1 2040)).wasm"
LONG_COMMIT=$(printf 'c%.0s' $(seq 1 257))
LONG_TARGET=$(printf 't%.0s' $(seq 1 65))
UPPER_H=$(tr 'a-f' 'A-F' <<<"$H_S")
# label | source-json | the refusal's pattern (ERE)
BAD_CASES=$(cat <<EOF
W1 hash EVENT_JSON:{…}|$(wasm_src "$U_S" 'EVENT_JSON:{"standard":"nep297","event":"x"}')|source\.hash must be the SHA-256
W2 hash UPPERCASE hex|$(wasm_src "$U_S" "$UPPER_H")|source\.hash must be the SHA-256
W3 hash 63 chars|$(wasm_src "$U_S" "${H_S:0:63}")|source\.hash must be the SHA-256
W4 url http://|$(wasm_src "http://example.com/a.wasm" "$H_S")|source\.url must be an https:// URL
W5 url ipfs://|$(wasm_src "ipfs://bafybeih5kokcb2qvxn2ukurakx4rt33ac5sfmfpmzvkrchpkuwtovpnhiy" "$H_S")|source\.url must be an https:// URL
W6 url with a space|$(wasm_src "https://example.com/a b.wasm" "$H_S")|source\.url must not contain whitespace
W7 url with a newline + EVENT_JSON|$(wasm_src $'https://example.com/a.wasm\nEVENT_JSON:{}' "$H_S")|source\.url must not contain whitespace
W8 url holding EVENT_JSON|$(wasm_src "https://example.com/EVENT_JSON:x.wasm" "$H_S")|source\.url must not contain .EVENT_JSON.
W9 url over 2048 bytes|$(wasm_src "$LONG_URL" "$H_S")|source\.url is longer than 2048 bytes
G1 repo holding EVENT_JSON|$(gh_src "https://github.com/EVENT_JSON/x" main)|source\.repo must not contain .EVENT_JSON.
G2 repo with a newline|$(gh_src $'https://github.com/o/r\nEVENT_JSON:{}' main)|source\.repo must be a GitHub repository
G3 repo starting -|$(gh_src "-o/r" main)|source\.repo must be a GitHub repository
G4 repo holding ..|$(gh_src "https://github.com/../r" main)|source\.repo must be a GitHub repository
G5 commit holding EVENT_JSON|$(gh_src "$GH_REPO" "EVENT_JSON")|source\.commit must not contain .EVENT_JSON.
G6 commit with a newline|$(gh_src "$GH_REPO" $'main\nEVENT_JSON:{}')|source\.commit must be a commit hash, branch or tag
G7 commit holding ..|$(gh_src "$GH_REPO" "a..b")|source\.commit must be a commit hash, branch or tag
G8 commit over 256 bytes|$(gh_src "$GH_REPO" "$LONG_COMMIT")|source\.commit must be 1.{1,12}256 bytes
B1 build_target 'wasm32 wasip2'|$(wasm_src "$U_S" "$H_S" "wasm32 wasip2")|source\.build_target must be 1.{1,12}64 bytes
B2 build_target over 64 bytes|$(wasm_src "$U_S" "$H_S" "$LONG_TARGET")|source\.build_target must be 1.{1,12}64 bytes
EOF
)
# Each case refused, with its own message, and the call did not succeed.
refused() { # refused <row> <method> <args-json> <deposit> <pattern>
  local out; out=$(call "$OWNER_A" "$2" "$3" "$4")
  if succeeded "$out"; then fail "$1 — ACCEPTED"; return; fi
  local ev; ev=$(grep -oE -- "$5.{0,40}" <<<"$out" | head -1)
  if [[ -n "$ev" ]]; then pass "$1 — refused: $ev"
  else fail "$1 — refused, but not by the rule (/$5/): $(why_of "$out")"; fi
}

log "C1/C1a create_project refuses every malformed source"
while IFS='|' read -r label src pat; do
  [[ -n "$label" ]] || continue
  refused "C1 create_project: $label" create_project "$(jq -nc --arg n "$BADNAME" --argjson s "$src" '{name:$n, source:$s}')" '0.3 NEAR' "$pat"
done <<<"$BAD_CASES"
[[ -z "$(project_uuid "$OWNER_A/$BADNAME")" ]] && pass "C1a no refused create_project left $OWNER_A/$BADNAME behind" \
  || fail "C1a $OWNER_A/$BADNAME EXISTS after only refused creates"

log "C1 add_version refuses them too"
while IFS='|' read -r label src pat; do
  case "$label" in W1*|W6*|W8*|G1*|G6*|B1*) ;; *) continue ;; esac
  refused "C1 add_version: $label" add_version "$(jq -nc --arg n "$SCRATCH" --argjson s "$src" '{project_name:$n, source:$s, set_active:false}')" '0.1 NEAR' "$pat"
done <<<"$BAD_CASES"

log "C1 an inline request_execution refuses them too"
while IFS='|' read -r label src pat; do
  case "$label" in W1*|W7*|W8*|G1*|G2*|G6*) ;; *) continue ;; esac
  refused "C1 request_execution: $label" request_execution "$(exec_args "$src" '{}')" "$DEPOSIT" "$pat"
done <<<"$BAD_CASES"

# ── a project run: C10, C2, C3 live ──────────────────────────────────────────

log "C10 / setup: $OWNER_A/$NAME writes the public record k = old"
put_public "$OWNER_A" "$OWNER_A/$NAME" old
if [[ "$RUN_OK" == true && "$(out_field .success)" == true ]]; then pass "setup set_public k=old on $OWNER_A/$NAME"
else fail "setup set_public on $OWNER_A/$NAME — run $RUN_OK: $(head -c 300 <<<"$RUN_ERR$RUN_OUT")"; fi
resolved=$(jq -r '.[] | select(startswith("Resolved project:"))' <<<"$RUN_LOGS" | head -1)
[[ "$resolved" == "Resolved project: $OWNER_A/$NAME, version: \"$H_S\", source: "* ]] \
  && pass "C10 the contract logs the version key quoted: ${resolved:0:110}…" \
  || fail "C10 Resolved project line is not '…, version: \"<key>\", …': '${resolved:0:200}'"
[[ "$(req_uuid)" == "$UUID1" ]] && pass "C2 a Project run's event carries its uuid $UUID1" \
  || fail "C2 a Project run's event carries project_uuid '$(req_uuid)', not $UUID1"

log "C2 a Project run whose params name another uuid runs in its own"
run "$OWNER_A" "$(exec_args "$(proj_src "$OWNER_A/$NAME")" '{"command":"get_worker","key":"k"}' '{"project_uuid":"p0000000000000001"}')"
[[ "$(req_uuid)" == "$UUID1" ]] && pass "C2 params.project_uuid=p0000000000000001 → the event carries the project's own $UUID1" \
  || fail "C2 params.project_uuid=p0000000000000001 → the event carries '$(req_uuid)', not $UUID1"
[[ "$(out_field .value)" == old ]] && pass "C2 … and the run reads its own record k=old" \
  || fail "C2 the Project run did not read its own k: run $RUN_OK, answer $(head -c 200 <<<"$RUN_OUT") $RUN_ERR"

log "C2 an inline run naming $UUID1 in params runs with no project storage"
run "$OWNER_A" "$(exec_args "$(wasm_src "$U_S" "$H_S")" '{"command":"get_worker","key":"k"}' "$(jq -nc --arg u "$UUID1" '{project_uuid:$u}')")"
if [[ -z "$RUN_REQ" ]]; then fail "C2 inline run — no execution_requested event: $RUN_ERR"
else
  [[ "$(req_uuid)" == null ]] && pass "C2 inline run with params.project_uuid=$UUID1 → the event carries project_uuid: null" \
    || fail "C2 inline run → the event carries project_uuid '$(req_uuid)' — the caller's uuid was kept"
  [[ "$(out_field .value)" != old ]] && pass "C2 … and it does not read $UUID1's storage (run $RUN_OK: $(head -c 120 <<<"$(out_field .error)$RUN_ERR"))" \
    || fail "C2 an inline run READ $UUID1's record k=old"
fi

log "C10 a Text answer with a line break is logged on one line, quoted"
if [[ -n "$U_E" ]]; then
  run "$OWNER_A" "$(exec_args "$(wasm_src "$U_E" "$H_E" wasm32-wasip1)" $'a\nb' null Text)"
  # The log, as the chain holds it: `Text: "… said \"a\nb\" …"` — the break
  # escaped (a backslash and an n), no raw line break in it.
  textlog=$(jq -c '[.[] | select(contains("Text: "))][0] // empty' <<<"$RUN_LOGS")
  if [[ -z "$textlog" ]]; then fail "C10 Text — no 'Text: ' log in the run (run $RUN_OK: $RUN_ERR)"
  elif jq -e 'contains("\n")' <<<"$textlog" >/dev/null 2>&1; then fail "C10 Text — the log holds a raw line break: $textlog"
  elif jq -e 'contains("said \\\"a\\nb\\\"")' <<<"$textlog" >/dev/null 2>&1; then pass "C10 Text logged quoted on one line: $(head -c 120 <<<"$textlog")"
  else fail "C10 Text — the log is not the quoted answer: $textlog"; fi
else
  skip "C10 Text half — the echo module is not built or never reached FastFS"
fi

log "C10 set_active_version logs version=\"…\""
out=$(call "$OWNER_A" set_active_version "$(jq -nc --arg n "$NAME" --arg v "$H_S" '{project_name:$n, version_key:$v}')" '0 NEAR')
tx=$(tx_of "$out"); logs=$(tx_logs "$tx" "$OWNER_A")
jq -e --arg l "Active version changed: project=$OWNER_A/$NAME, version=\"$H_S\"" 'any(.[]; . == $l)' <<<"$logs" >/dev/null 2>&1 \
  && pass "C10 set_active_version logs version=\"$H_S\"" \
  || fail "C10 set_active_version logs: $(jq -r '.[]' <<<"$logs" | head -3 | tr '\n' ' ' | head -c 300) $(why_of "$out")"

log "C3 has_project_uuid on a live uuid and on p0000000000000000"
[[ "$(has_uuid "$UUID1")" == true ]] && pass "C3 has_project_uuid($UUID1) → true (live)" || fail "C3 has_project_uuid($UUID1) → '$(has_uuid "$UUID1")', live"
[[ "$(has_uuid p0000000000000000)" == false ]] && pass "C3 has_project_uuid(p0000000000000000) → false" || fail "C3 has_project_uuid(p0000000000000000) is not false"

# ── R7 cache TTL ─────────────────────────────────────────────────────────────

log "R7-cache-ttl a by-name read caches the uuid with a TTL"
v=$(pub_get "$OWNER_A/$NAME" k)
[[ "$v" == old ]] && pass "R7 by-name read of $OWNER_A/$NAME → old" || fail "R7 by-name read of $OWNER_A/$NAME → '$v', not old"
if [[ "$REDIS_OK" == true ]]; then
  ttl=$(rds TTL "project_uuid_by_name:$OWNER_A/$NAME"); cached=$(rds GET "project_uuid_by_name:$OWNER_A/$NAME")
  [[ "$ttl" =~ ^[0-9]+$ ]] && (( ttl > 0 && ttl <= 86400 )) && [[ "$cached" == "$UUID1" ]] \
    && pass "R7-cache-ttl project_uuid_by_name:$OWNER_A/$NAME = $cached, TTL $ttl" \
    || fail "R7-cache-ttl project_uuid_by_name:$OWNER_A/$NAME = '$cached', TTL '$ttl'"
else
  skip "R7-cache-ttl — no Redis access (REDIS_CMD)"
fi

# ── C4 + R7 delete ───────────────────────────────────────────────────────────

log "C4 delete_project $OWNER_A/$NAME ($UUID1)"
rows_before=""
if [[ "$SQL_OK" == true ]]; then
  rows_before=$(sq "SELECT count(*) FROM storage_data WHERE project_uuid='$UUID1'")
  note "storage_data rows of $UUID1 before the delete: $rows_before"
fi
out=$(call "$OWNER_A" delete_project "$(jq -nc --arg n "$NAME" '{project_name:$n}')" '0 NEAR')
succeeded "$out" || { fail "C4 delete_project failed: $(why_of "$out")"; verdict "contract hotfix"; exit $?; }
logs=$(tx_logs "$(tx_of "$out")" "$OWNER_A")
events_of "$logs" system_event | jq -e --arg u "$UUID1" '.ProjectStorageCleanup.project_uuid == $u' >/dev/null 2>&1 \
  && pass "C4 the delete emits ProjectStorageCleanup for $UUID1" || fail "C4 no ProjectStorageCleanup event for $UUID1 in the delete: $logs"

if [[ "$LOGS_OK" == true ]]; then
  # Every worker relays the event, so the name is invalidated once per worker:
  # the first drops the cached uuid (removed=1), the rest find nothing.
  if line=$(coord_wait "Invalidated project uuid cache: project_id=$OWNER_A/$NAME " 1 24 'removed=1'); then
    pass "R7-cache-delete coordinator: ${line##*INFO }"
  else
    fail "R7-cache-delete no 'Invalidated project uuid cache: project_id=$OWNER_A/$NAME removed=1' in the coordinator log after 4 min: $(coord_lines "Invalidated project uuid cache: project_id=$OWNER_A/$NAME " | tail -2 | tr '\n' ' ' | head -c 300)"
  fi
else
  skip "R7-cache-delete coordinator log half — logs unreadable"
fi
INV_TTL=""
if [[ "$REDIS_OK" == true ]]; then
  # The pause starts when the worker relays the event; wait for it.
  for i in $(seq 1 18); do
    INV_TTL=$(rds TTL "project_invalidated:$OWNER_A/$NAME")
    [[ "$INV_TTL" =~ ^[1-9][0-9]*$ ]] && break
    sleep 10
  done
  [[ "$INV_TTL" =~ ^[0-9]+$ ]] && (( INV_TTL >= 1 && INV_TTL <= 120 )) \
    && pass "R7-cache-delete project_invalidated:$OWNER_A/$NAME TTL $INV_TTL (1..120)" \
    || fail "R7-cache-delete project_invalidated:$OWNER_A/$NAME TTL '$INV_TTL', not 1..120"
  v=$(pub_get "$OWNER_A/$NAME" k)
  [[ "$v" == "<absent>" ]] && pass "R7-cache-delete by-name read of the deleted name → absent" || fail "R7-cache-delete by-name read of the deleted name → '$v'"
  if [[ "$(rds TTL "project_invalidated:$OWNER_A/$NAME")" =~ ^[1-9][0-9]*$ ]]; then
    e1=$(rds EXISTS "project_uuid_by_name:$OWNER_A/$NAME"); e2=$(rds EXISTS "project_missing:$OWNER_A/$NAME")
    [[ "$e1/$e2" == 0/0 ]] && pass "R7-cache-delete a read inside the window cached nothing (uuid/missing EXISTS 0/0)" \
      || fail "R7-cache-delete a read inside the window cached: project_uuid_by_name EXISTS $e1, project_missing EXISTS $e2"
  else
    skip "R7-cache-delete in-window read — the window had closed before the read was judged"
  fi
else
  skip "R7-cache-delete Redis half — no Redis access"
fi

if [[ "$LOGS_OK" == true ]]; then
  refusal=$(coord_lines "Refusing ProjectStorageCleanup task: project_id=$OWNER_A/$NAME " | tail -1)
  if line=$(coord_wait "uuid=$UUID1" 1 18 'ProjectStorageCleanup task created: task_id='); then
    pass "C4 coordinator created the cleanup task: ${line##*INFO }"
  else
    fail "C4 no 'ProjectStorageCleanup task created … uuid=$UUID1' in the coordinator log${refusal:+ — it REFUSED: ${refusal##*WARN }}"
  fi
else
  skip "C4 coordinator log half — logs unreadable"
fi
if [[ "$SQL_OK" == true ]]; then
  rows=""
  for i in $(seq 1 30); do
    rows=$(sq "SELECT count(*) FROM storage_data WHERE project_uuid='$UUID1'")
    [[ "$rows" == 0 ]] && break
    sleep 10
  done
  [[ "$rows" == 0 && "${rows_before:-0}" -gt 0 ]] && pass "C4 storage_data rows of $UUID1: $rows_before → 0" \
    || fail "C4 storage_data rows of $UUID1: before '${rows_before}', now '$rows' after 5 min"
else
  skip "C4 storage erase in the DB — no DB access (PSQL_CMD)"
fi
[[ "$LOGS_OK" == true ]] && { l=$(coord_lines "storage_clear_project: project_uuid=$UUID1" | tail -1)
  [[ -n "$l" ]] && note "coordinator: ${l##*INFO }"; }
v=$(pub_get "$UUID1" k)
[[ "$v" == "<absent>" ]] && pass "C4 a public read by the deleted uuid $UUID1 → absent" || fail "C4 a public read by the deleted uuid $UUID1 → '$v'"
[[ "$(has_uuid "$UUID1")" == false ]] && pass "C3 has_project_uuid($UUID1) → false (deleted)" || fail "C3 has_project_uuid($UUID1) → '$(has_uuid "$UUID1")' after the delete"

log "R7-cache-delete $OWNER_A recreates $NAME and writes k = new"
out=$(call "$OWNER_A" create_project "$(jq -nc --arg n "$NAME" --argjson s "$(wasm_src "$U_S" "$H_S")" '{name:$n, source:$s}')" '0.3 NEAR')
succeeded "$out" || { fail "R7 recreate $NAME failed: $(why_of "$out")"; verdict "contract hotfix"; exit $?; }
sleep 3
UUID2=$(project_uuid "$OWNER_A/$NAME")
[[ -n "$UUID2" && "$UUID2" != "$UUID1" ]] && pass "R7 the recreated $OWNER_A/$NAME has a new uuid $UUID2" || fail "R7 recreated uuid '$UUID2' vs deleted $UUID1"
put_public "$OWNER_A" "$OWNER_A/$NAME" new
R2=$(req_id); R2_UUID=$(req_uuid)
[[ "$RUN_OK" == true && "$(out_field .success)" == true ]] || fail "R7 set_public k=new on the recreated project — run $RUN_OK: $(head -c 300 <<<"$RUN_ERR$RUN_OUT")"
v=$(pub_get "$OWNER_A/$NAME" k)
[[ "$v" == new ]] && pass "R7-cache-delete by-name read of the recreated project → new" || fail "R7-cache-delete by-name read → '$v', not new"
[[ "$R2_UUID" == "$UUID2" ]] && pass "R7-bookkeeping the recreated project's run requests uuid $UUID2" || fail "R7-bookkeeping the run's event carries '$R2_UUID', not $UUID2"
if [[ "$SQL_OK" == true && -n "$R2" ]]; then
  b=$(sql_row "SELECT coalesce(project_uuid,'<null>') FROM execution_requests WHERE request_id=$R2 AND NOT coalesce(is_https_call,false)" 10)
  [[ "$b" == "$UUID2" ]] && pass "R7-bookkeeping on chain: execution_requests[$R2].project_uuid = $UUID2 (after delete+recreate)" \
    || fail "R7-bookkeeping on chain: execution_requests[$R2].project_uuid = '$b', not $UUID2"
else
  skip "R7-bookkeeping on-chain after delete — no DB access or no request id"
fi

if [[ "$REDIS_OK" == true ]]; then
  for i in $(seq 1 15); do
    t=$(rds TTL "project_invalidated:$OWNER_A/$NAME"); [[ "$t" =~ ^[1-9][0-9]*$ ]] || break
    sleep 10
  done
  v=$(pub_get "$OWNER_A/$NAME" k)
  ttl=$(rds TTL "project_uuid_by_name:$OWNER_A/$NAME"); cached=$(rds GET "project_uuid_by_name:$OWNER_A/$NAME")
  [[ "$v" == new && "$cached" == "$UUID2" && "$ttl" =~ ^[0-9]+$ ]] && (( ttl > 86000 && ttl <= 86400 )) \
    && pass "R7-cache-delete after the window the name caches the NEW uuid $cached, TTL $ttl" \
    || fail "R7-cache-delete after the window: read '$v', cached '$cached', TTL '$ttl'"
fi

# ── R7 transfer ──────────────────────────────────────────────────────────────

log "R7-cache-transfer $OWNER_A/$NAME ($UUID2) → $OWNER_B"
before_a=0; before_b=0
if [[ "$LOGS_OK" == true ]]; then
  before_a=$(coord_lines "Invalidated project uuid cache: project_id=$OWNER_A/$NAME " | grep -c .)
  before_b=$(coord_lines "Invalidated project uuid cache: project_id=$OWNER_B/$NAME " | grep -c .)
fi
out=$(call "$OWNER_A" transfer_project "$(jq -nc --arg n "$NAME" --arg o "$OWNER_B" '{project_name:$n, new_owner:$o}')" '0 NEAR')
succeeded "$out" || { fail "R7 transfer_project failed: $(why_of "$out")"; verdict "contract hotfix"; exit $?; }
logs=$(tx_logs "$(tx_of "$out")" "$OWNER_A")
events_of "$logs" system_event | jq -e --arg u "$UUID2" --arg o "$OWNER_A/$NAME" --arg n "$OWNER_B/$NAME" \
  '.ProjectTransferred | .project_uuid == $u and .old_project_id == $o and .new_project_id == $n' >/dev/null 2>&1 \
  && pass "R7-cache-transfer the contract emits ProjectTransferred $OWNER_A/$NAME → $OWNER_B/$NAME ($UUID2)" \
  || fail "R7-cache-transfer no ProjectTransferred event: $(jq -r '.[]' <<<"$logs" | tail -2 | tr '\n' ' ' | head -c 300)"
if [[ "$LOGS_OK" == true ]]; then
  la=$(coord_wait "Invalidated project uuid cache: project_id=$OWNER_A/$NAME " $((before_a + 1))) \
    && pass "R7-cache-transfer coordinator invalidated the old name: ${la##*INFO }" \
    || fail "R7-cache-transfer no new invalidation of $OWNER_A/$NAME after the transfer (the worker did not relay ProjectTransferred?)"
  lb=$(coord_wait "Invalidated project uuid cache: project_id=$OWNER_B/$NAME " $((before_b + 1)) 6) \
    && pass "R7-cache-transfer coordinator invalidated the new name: ${lb##*INFO }" \
    || fail "R7-cache-transfer no invalidation of $OWNER_B/$NAME after the transfer"
else
  skip "R7-cache-transfer coordinator log half — logs unreadable (the worker's own 'Found system_event ProjectTransferred' is on the TEE worker, not read here)"
fi
if [[ "$REDIS_OK" == true ]]; then
  ta=$(rds TTL "project_invalidated:$OWNER_A/$NAME"); tb=$(rds TTL "project_invalidated:$OWNER_B/$NAME")
  [[ "$ta" =~ ^[0-9]+$ && "$tb" =~ ^[0-9]+$ ]] && (( ta >= 1 && ta <= 120 && tb >= 1 && tb <= 120 )) \
    && pass "R7-cache-transfer both names paused: project_invalidated TTL $ta / $tb" \
    || fail "R7-cache-transfer project_invalidated TTLs: $OWNER_A/$NAME '$ta', $OWNER_B/$NAME '$tb'"
fi
v=$(pub_get "$OWNER_B/$NAME" k)
[[ "$v" == new ]] && pass "R7-cache-transfer $OWNER_B/$NAME by name → new (the transferred record)" || fail "R7-cache-transfer $OWNER_B/$NAME by name → '$v', not new"

log "R7-cache-transfer $OWNER_A recreates $NAME and writes k = fresh"
out=$(call "$OWNER_A" create_project "$(jq -nc --arg n "$NAME" --argjson s "$(wasm_src "$U_S" "$H_S")" '{name:$n, source:$s}')" '0.3 NEAR')
succeeded "$out" || { fail "R7 recreate after transfer failed: $(why_of "$out")"; verdict "contract hotfix"; exit $?; }
sleep 3
UUID3=$(project_uuid "$OWNER_A/$NAME")
[[ -n "$UUID3" && "$UUID3" != "$UUID2" && "$UUID3" != "$UUID1" ]] && pass "R7 recreated after the transfer: $OWNER_A/$NAME is $UUID3" || fail "R7 recreated uuid '$UUID3'"
put_public "$OWNER_A" "$OWNER_A/$NAME" fresh
R3=$(req_id); R3_UUID=$(req_uuid)
[[ "$RUN_OK" == true && "$(out_field .success)" == true ]] || fail "R7 set_public k=fresh — run $RUN_OK: $(head -c 300 <<<"$RUN_ERR$RUN_OUT")"
v=$(pub_get "$OWNER_A/$NAME" k)
[[ "$v" == fresh ]] && pass "R7-cache-transfer $OWNER_A/$NAME by name → fresh, not the transferred new" || fail "R7-cache-transfer $OWNER_A/$NAME by name → '$v', not fresh"
v=$(pub_get "$UUID2" k)
[[ "$v" == new ]] && pass "R7-cache-transfer ?project_uuid=$UUID2 still → new" || fail "R7-cache-transfer ?project_uuid=$UUID2 → '$v', not new"
[[ "$(has_uuid "$UUID2")" == true ]] && pass "C3 has_project_uuid($UUID2) → true (transferred, live)" || fail "C3 has_project_uuid($UUID2) is not true after a transfer"
[[ "$R3_UUID" == "$UUID3" ]] && pass "R7-bookkeeping after transfer+recreate the run requests uuid $UUID3" || fail "R7-bookkeeping the run carries '$R3_UUID', not $UUID3"
if [[ "$SQL_OK" == true && -n "$R3" ]]; then
  b=$(sql_row "SELECT coalesce(project_uuid,'<null>') FROM execution_requests WHERE request_id=$R3 AND NOT coalesce(is_https_call,false)" 10)
  [[ "$b" == "$UUID3" ]] && pass "R7-bookkeeping on chain: execution_requests[$R3].project_uuid = $UUID3 (after transfer+recreate)" \
    || fail "R7-bookkeeping on chain: execution_requests[$R3].project_uuid = '$b', not $UUID3"
else
  skip "R7-bookkeeping on-chain after transfer — no DB access or no request id"
fi

log "R7-bookkeeping POST /call/$OWNER_A/$NAME"
if [[ -z "$PAYMENT_KEY" ]]; then
  skip "R7-bookkeeping /call half — no PAYMENT_KEY: $OWNER_A holds no funded payment key here (a trial key is for connectors only)"
elif [[ "$PAYMENT_KEY" != "$OWNER_A:"* ]]; then
  skip "R7-bookkeeping /call half — PAYMENT_KEY is not $OWNER_A's (first 4 chars: ${PAYMENT_KEY:0:4})"
else
  throttle
  r=$(printf 'header = "X-Payment-Key: %s"\n' "$PAYMENT_KEY" | curl -sS --max-time 120 -K - -X POST \
        "$COORDINATOR_URL/call/$OWNER_A/$NAME" -H 'Content-Type: application/json' \
        -d '{"input":{"command":"get_worker","key":"k"}}' -w $'\n%{http_code}' 2>/dev/null)
  code=${r##*$'\n'}; body=${r%$'\n'*}
  cid=$(jq -r '.call_id // empty' <<<"$body" 2>/dev/null)
  val=$(jq -r '.output.value // (.output | if type=="string" then (try fromjson catch {}) else . end | .value) // empty' <<<"$body" 2>/dev/null)
  [[ "$code" == 200 && "$val" == fresh ]] && pass "R7-bookkeeping /call ran the recreated project's code: k → fresh" \
    || fail "R7-bookkeeping /call → HTTP $code, $(jq -c 'del(.. | .payment_key?)' <<<"$body" 2>/dev/null | head -c 300)"
  if [[ "$SQL_OK" == true && -n "$cid" ]]; then
    b=$(sql_row "SELECT coalesce(project_uuid,'<null>') FROM execution_requests WHERE is_https_call AND call_id::text='$cid'" 10)
    [[ "$b" == "$UUID3" ]] && pass "R7-bookkeeping /call booked under $UUID3" || fail "R7-bookkeeping /call booked under '$b', not $UUID3"
  else
    skip "R7-bookkeeping /call DB half — no DB access or no call_id"
  fi
fi

# ── C1b a version stored before the rules ────────────────────────────────────

log "C1b a Project-source run of a version stored before the rules"
if [[ "$SQL_OK" != true ]]; then
  skip "C1b legacy — no DB access to find the testnet projects"
else
  lv=$(legacy_version)
  if [[ -z "$lv" ]]; then
    skip "C1b legacy — no project version on testnet breaks today's rules"
  else
    lp=${lv%% *}; lk=${lv#* }
    note "legacy version: $lp @ ${lk:0:20}… ($(view "$CONTRACT_ID" get_version "$(jq -nc --arg p "$lp" --arg v "$lk" '{project_id:$p, version_key:$v}')" | jq -c '.source' | head -c 160))"
    run "$OWNER_A" "$(exec_args "$(proj_src "$lp" "$lk")" '{}')"
    [[ -n "$RUN_REQ" ]] && pass "C1b the contract accepted the run of $lp's pre-rule version (execution_requested emitted; run: $RUN_OK)" \
      || fail "C1b the contract refused the run of $lp's pre-rule version: $RUN_ERR"
  fi
fi

# ── C5 ───────────────────────────────────────────────────────────────────────

skip "C5 coordinator cleanup refusals — tests/cleanup_verification_e2e.sh runs them with the worker bearer, which this suite does not hold"

# ── teardown ─────────────────────────────────────────────────────────────────

if [[ "$KEEP" == 1 ]]; then
  note "KEEP=1: left on chain: $OWNER_B/$NAME ($UUID2), $OWNER_A/$NAME ($UUID3), $OWNER_A/$SCRATCH"
else
  log "teardown: delete this run's projects"
  for pair in "$OWNER_B $NAME" "$OWNER_A $NAME" "$OWNER_A $SCRATCH"; do
    s=${pair%% *}; n=${pair#* }
    out=$(call "$s" delete_project "$(jq -nc --arg n "$n" '{project_name:$n}')" '0 NEAR')
    succeeded "$out" && note "deleted $s/$n" || warn "could not delete $s/$n: $(why_of "$out")"
  done
fi

verdict "contract hotfix"
