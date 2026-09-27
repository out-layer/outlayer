#!/usr/bin/env bash
#
# Storage scope end to end, on testnet: `wasi-examples/signing-key-probe`'s
# storage builds under projects of $OWNER, run on chain by a deployed worker
# against a deployed coordinator.
#
# What each row pins:
#   V  version-addressed storage is scoped to the calling project. $OWNER
#      writes k (encrypted) in project B at version W_B (the encryption-storage
#      build). Project A, whose active version is the SAME build: from A,
#      get_by_version(k, W_B) → None and clear_version(W_B) → Ok; B's k is
#      still readable from B and B's storage_data rows for $OWNER are
#      unchanged. B moved to another version (encryption-storage-pred, active):
#      from B, get_by_version(k, W_B) → the value, clear_version(W_B) → Ok and
#      k is gone (from the guest and from storage_data). The coordinator's
#      `storage_clear_version` log lines carry A's uuid (0 rows) and B's
#      (≥ 1 row)
#   M  an unknown TOP-LEVEL manifest member: the project-misspelled build (the
#      project manifest plus "storage_acount": "predecessor"), published as a
#      version of A and run through it → refused before the module runs,
#      naming the member and the known ones; no probe answer, no key
#   D  deleting a project erases every per-account record: $OWNER (raw,
#      sealed through the probe, sealed through the SDK, encrypted) and
#      $CALLER2 (raw, encrypted) write into a fresh project; storage_data holds
#      rows of both accounts and both modes; delete_project → the coordinator's
#      cleanup task → no storage_data row for the uuid
#
# Needs: OWNER (owns the projects, first caller) and CALLER2, each with its key
# in the legacy keychain ~/.near-credentials/testnet/<acct>.json; PSQL_CMD (a
# command taking one SELECT on the coordinator DB) — V and D read storage_data;
# the `outlayer` CLI logged in on testnet (pays the FastFS uploads); near,
# outlayer, jq, curl, shasum, cargo + wasm-tools (the build). The RPC is keyed
# through tests/lib/rpc.sh. COORD_SSH (default root@138.201.58.122) and
# COORD_CONTAINER (default offchainvm-coordinator-testnet): the coordinator log
# V reads; unreadable → that half SKIPS, loudly.
#
# Money: four FastFS uploads (~300 KB each), three projects (A and B stay for
# the next run; D's is deleted, its storage deposit refunded), five versions,
# ~30 on-chain runs at $DEPOSIT (the unused part refunded).
#
# Env: ONLY=V,M,D (a subset), DEPOSIT (default 0.1 NEAR).
#
# Run:
#   OWNER=you.testnet CALLER2=friend.testnet PSQL_CMD=… ./tests/storage_scope_e2e.sh            # dry run
#   OWNER=you.testnet CALLER2=friend.testnet PSQL_CMD=… ./tests/storage_scope_e2e.sh --apply    # build, publish, run

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/lib/hos_common.sh"   # NETWORK, CONTRACT_ID, keyed RPC_URL, sql, pass/fail/skip/verdict

APPLY=false
[[ "${1:-}" == "--apply" ]] && APPLY=true

OWNER="${OWNER:-}"
CALLER2="${CALLER2:-}"
DEPOSIT="${DEPOSIT:-0.1 NEAR}"
NAME_A="${NAME_A:-storage-scope-a}"
NAME_B="${NAME_B:-storage-scope-b}"
COORD_SSH="${COORD_SSH:-root@138.201.58.122}"
COORD_CONTAINER="${COORD_CONTAINER:-offchainvm-coordinator-testnet}"
PROBE_DIR="$REPO_ROOT/wasi-examples/signing-key-probe"
VARIANTS="$PROBE_DIR/target/variants"
BUILDS="encryption-storage encryption-storage-pred project-misspelled"
RUN_START=$(date +%s)
TAG="scope-$RUN_START"
export OUTLAYER_NETWORK="$NETWORK"

# ── helpers ──────────────────────────────────────────────────────────────────

want() { [[ -z "${ONLY:-}" ]] || [[ ",$ONLY," == *",$1,"* ]]; }

# The keyed RPC URL reaches curl on stdin, never on a command line.
rpc_post() { # rpc_post <json-body>
  printf 'url = "%s"\n' "$RPC_URL" | curl -sS --max-time 45 -K - -X POST \
    -H 'Content-Type: application/json' --data-binary "$1" 2>/dev/null
}
view() { # view <account> <method> <args-json> — the decoded result, or empty
  rpc_post "$(jq -nc --arg a "$1" --arg m "$2" --arg g "$(printf '%s' "$3" | base64 | tr -d '\n')" \
    '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"call_function",finality:"final",account_id:$a,method_name:$m,args_base64:$g}}')" \
    | jq -r 'if .result.result then (.result.result | implode) else empty end' 2>/dev/null
}
uuid_of() { view "$CONTRACT_ID" get_project "$(jq -nc --arg p "$1" '{project_id:$p}')" | jq -r '.uuid // empty' 2>/dev/null; }
version_on_chain() { # version_on_chain <project_id> <version_key> — the source kind, or empty
  view "$CONTRACT_ID" get_version "$(jq -nc --arg p "$1" --arg v "$2" '{project_id:$p, version_key:$v}')" \
    | jq -r 'select(. != null) | .source | keys[0] // empty' 2>/dev/null
}
sha_of() { shasum -a 256 "$1" | cut -d' ' -f1; }
hex_of() { printf '%s' "$1" | xxd -p | tr -d '\n'; }
key_hash() { printf '%s' "$1" | shasum -a 256 | cut -d' ' -f1; }

# Per-build values in plain variables (bash 3.2): `var_name hash project-misspelled` → H_project_misspelled.
var_name() { printf '%s_%s' "$( [[ $1 == hash ]] && echo H || echo U )" "${2//-/_}"; }
set_for() { printf -v "$(var_name "$1" "$2")" '%s' "$3"; }
get_for() { local n; n=$(var_name "$1" "$2"); printf '%s' "${!n:-}"; }

call() { # call <signer> <method> <args-json> <deposit> — the whole transcript
  near contract call-function as-transaction "$CONTRACT_ID" "$2" json-args "$3" \
    prepaid-gas '300.0 Tgas' attached-deposit "$4" sign-as "$1" network-config "$NETWORK" sign-with-legacy-keychain send 2>&1
}
succeeded() { grep -q 'succeeded' <<<"$1"; }
why_of() { near_why "$1"; }

# `run <signer> <project_id> <version_key> <input-json>` sets RUN_OK (true /
# false / absent), RUN_ERR (the refusal) and RUN_OUT (the probe's answer).
RUN_OK=""; RUN_ERR=""; RUN_OUT=""
run() {
  local out ev
  out=$(call "$1" request_execution "$(jq -nc --arg p "$2" --arg v "$3" --arg i "$4" \
    '{source:{Project:{project_id:$p, version_key:$v}}, input_data:$i, response_format:"Json",
      resource_limits:{max_instructions:10000000000,max_memory_mb:128,max_execution_seconds:60}}')" "$DEPOSIT")
  ev=$(grep -o 'EVENT_JSON:.*execution_completed.*' <<<"$out" | sed 's/^EVENT_JSON://' | head -1)
  RUN_OUT=$(awk '/Function execution return value/{f=1; next} f && /^The "/{exit} f{print}' <<<"$out" \
    | jq -c 'select(. != null) | if type=="string" then fromjson else . end' 2>/dev/null)
  if [[ -z "$ev" ]]; then
    RUN_OK=absent; RUN_ERR=$(why_of "$out"); return 0
  fi
  RUN_OK=$(jq -r '.data[0] | if has("success") then (.success|tostring) else "absent" end' <<<"$ev" 2>/dev/null)
  RUN_ERR=$(jq -r '.data[0].error_message // ""' <<<"$ev" 2>/dev/null)
}
out_field() { jq -r "$1 | if . == null then \"\" else tostring end" <<<"$RUN_OUT" 2>/dev/null; }
ran_ok() { # ran_ok <row> — 0 when the run happened and the probe answered ok
  if [[ "$RUN_OK" != "true" ]]; then fail "$1 — the run did not happen ($RUN_OK): $(head -c 300 <<<"$RUN_ERR")"; return 1; fi
  if [[ "$(out_field .status)" != "ok" ]]; then fail "$1 — the probe answered $(out_field .status): $(out_field .message | head -c 300)"; return 1; fi
  return 0
}

# Coordinator log lines since the run began holding the fixed string <s>.
LOGS_OK=false
coord_lines() { # coord_lines <fixed-string>
  local since=$(( $(date +%s) - RUN_START + 120 ))
  ssh -o ConnectTimeout=15 -o BatchMode=yes -o ControlMaster=no -o ControlPath=none "$COORD_SSH" \
    "docker logs $COORD_CONTAINER --since ${since}s 2>&1 | grep -F -- $(printf '%q' "$1") | tail -40" 2>/dev/null \
    | sed $'s/\x1b\\[[0-9;]*m//g'
}

# A project of $OWNER holding these builds as versions, <active> active.
ensure_project() { # ensure_project <name> <active build> <other builds…>
  local name=$1 active=$2 b out; shift 2
  if [[ -z "$(uuid_of "$OWNER/$name")" ]]; then
    out=$(call "$OWNER" create_project "$(jq -nc --arg n "$name" --argjson s "$(src_of "$active")" '{name:$n, source:$s}')" '0.3 NEAR')
    succeeded "$out" || { echo "✗ create_project $name failed: $(why_of "$out")" >&2; exit 1; }
    sleep 4
  fi
  for b in "$active" "$@"; do
    [[ -n "$(version_on_chain "$OWNER/$name" "$(get_for hash "$b")")" ]] && continue
    out=$(call "$OWNER" add_version "$(jq -nc --arg n "$name" --argjson s "$(src_of "$b")" '{project_name:$n, source:$s, set_active:false}')" '0.1 NEAR')
    succeeded "$out" || { echo "✗ add_version $b to $name failed: $(why_of "$out")" >&2; exit 1; }
    sleep 4
  done
  set_active "$name" "$active"
}
set_active() { # set_active <name> <build>
  local out
  out=$(call "$OWNER" set_active_version "$(jq -nc --arg n "$1" --arg v "$(get_for hash "$2")" '{project_name:$n, version_key:$v}')" '0 NEAR')
  succeeded "$out" || { echo "✗ set_active_version $2 on $1 failed: $(why_of "$out")" >&2; exit 1; }
  sleep 3
}
src_of() { jq -nc --arg u "$(get_for url "$1")" --arg h "$(get_for hash "$1")" '{WasmUrl:{url:$u, hash:$h, build_target:"wasm32-wasip2"}}'; }

# ── preflight ────────────────────────────────────────────────────────────────

note "RPC: $(rpc_url_public)"
for tool in jq curl near outlayer cargo shasum xxd ssh; do
  command -v "$tool" >/dev/null || { echo "✗ missing $tool" >&2; exit 1; }
done
[[ -n "$OWNER" && -n "$CALLER2" && "$OWNER" != "$CALLER2" ]] || { echo "USAGE: OWNER=you.testnet CALLER2=friend.testnet PSQL_CMD=… $0 [--apply]" >&2; exit 1; }
for acct in "$OWNER" "$CALLER2"; do
  [[ -f "$HOME/.near-credentials/$NETWORK/$acct.json" ]] || { echo "✗ no key in ~/.near-credentials/$NETWORK for $acct" >&2; exit 1; }
done
if ! sql_alive; then
  echo "✗ PSQL_CMD unset or not answering: V and D judge storage_data rows and cannot run without it" >&2; exit 1
fi
if ssh -o ConnectTimeout=15 -o BatchMode=yes -o ControlMaster=no -o ControlPath=none "$COORD_SSH" \
     "docker inspect -f '{{.State.Running}}' $COORD_CONTAINER" 2>/dev/null | grep -q true; then
  LOGS_OK=true
else
  warn "coordinator logs unreadable ($COORD_SSH / $COORD_CONTAINER): V's log half will SKIP"
fi

if [[ "$APPLY" != true ]]; then
  log "dry run — nothing is built, uploaded, published or run"
  sed -n '3,/^$/p' "$0" >&2
  for n in "$NAME_A" "$NAME_B"; do note "$OWNER/$n: $( [[ -n "$(uuid_of "$OWNER/$n")" ]] && echo on chain || echo 'not on chain yet')"; done
  echo "  Pass --apply to run." >&2
  exit 0
fi

# ── setup: build, upload, publish ────────────────────────────────────────────

log "build the probe"
(cd "$PROBE_DIR" && ./build.sh >/dev/null) || { echo "✗ $PROBE_DIR/build.sh failed" >&2; exit 1; }
for b in $BUILDS; do
  set_for hash "$b" "$(sha_of "$VARIANTS/signing-key-probe-$b.wasm")"
  url=$(fastfs_upload "$VARIANTS/signing-key-probe-$b.wasm" "$(get_for hash "$b")") || { echo "✗ upload of $b never served its bytes" >&2; exit 1; }
  set_for url "$b" "$url"
  note "$b sha256 $(get_for hash "$b") at $url"
done
W_B=$(get_for hash encryption-storage); W_P=$(get_for hash encryption-storage-pred); W_M=$(get_for hash project-misspelled)

# ── V version-addressed storage, scoped to the calling project ─────────────

if want V; then
  log "V get_by_version / clear_version reach only the calling project's records"
  ensure_project "$NAME_B" encryption-storage encryption-storage-pred
  ensure_project "$NAME_A" encryption-storage project-misspelled
  PB="$OWNER/$NAME_B"; PA="$OWNER/$NAME_A"
  UB=$(uuid_of "$PB"); UA=$(uuid_of "$PA")
  note "A = $PA ($UA), B = $PB ($UB); both run $W_B"
  K="$TAG/k"; V="value of $TAG"; VH=$(hex_of "$V"); KH=$(key_hash "$K")

  run "$OWNER" "$PB" "$W_B" "$(jq -nc --arg k "$K" --arg v "$VH" '{operation:"enc_set",key:$k,value_hex:$v}')"
  ran_ok "V B writes k at W_B" && pass "V $OWNER wrote $K in B at W_B (${W_B:0:12})"
  row=$(sql_row "SELECT wasm_hash||'|'||is_encrypted::text FROM storage_data WHERE project_uuid='$UB' AND account_id='$OWNER' AND key_hash='$KH'" 5)
  [[ "$row" == "$W_B|true" ]] && pass "V storage_data: B's row for k carries wasm_hash W_B, encrypted" || fail "V B's row for k: '$row' (want $W_B|true)"
  n_before=$(sql "SELECT count(*) FROM storage_data WHERE project_uuid='$UB' AND account_id='$OWNER'")

  run "$OWNER" "$PA" "$W_B" "$(jq -nc --arg k "$K" --arg w "$W_B" '{operation:"storage_get_by_version",key:$k,wasm_hash:$w}')"
  ran_ok "V A get_by_version" && { [[ "$(out_field .found)" == false ]] \
    && pass "V from A (the same build), get_by_version(k, W_B) → None" || fail "V from A get_by_version found B's record: $(out_field .value_hex)"; }
  run "$OWNER" "$PA" "$W_B" "$(jq -nc --arg w "$W_B" '{operation:"storage_clear_version",wasm_hash:$w}')"
  ran_ok "V A clear_version" && pass "V from A, clear_version(W_B) → Ok"
  run "$OWNER" "$PB" "$W_B" "$(jq -nc --arg k "$K" '{operation:"enc_get",key:$k}')"
  ran_ok "V B reads k after A's clear" && { [[ "$(out_field .found)/$(out_field .value_hex)" == "true/$VH" ]] \
    && pass "V B still reads k after A's clear_version" || fail "V B's k after A's clear: found=$(out_field .found) $(out_field .value_hex)"; }
  n_after=$(sql "SELECT count(*) FROM storage_data WHERE project_uuid='$UB' AND account_id='$OWNER'")
  [[ -n "$n_before" && "$n_after" == "$n_before" ]] && pass "V B's storage_data rows for $OWNER unchanged by A's clear ($n_after)" \
    || fail "V B's rows for $OWNER: $n_before before A's clear, $n_after after"

  set_active "$NAME_B" encryption-storage-pred
  [[ "$(view "$CONTRACT_ID" get_project "$(jq -nc --arg p "$PB" '{project_id:$p}')" | jq -r '.active_version // empty')" == "$W_P" ]] \
    && pass "V B moved to another version (${W_P:0:12})" || fail "V B's active version is not ${W_P:0:12}"
  run "$OWNER" "$PB" "$W_P" "$(jq -nc --arg k "$K" --arg w "$W_B" '{operation:"storage_get_by_version",key:$k,wasm_hash:$w}')"
  ran_ok "V B@new get_by_version" && { [[ "$(out_field .found)/$(out_field .value_hex)" == "true/$VH" ]] \
    && pass "V from B at its new version, get_by_version(k, W_B) → the value" || fail "V B@new get_by_version: found=$(out_field .found) $(out_field .value_hex)"; }
  run "$OWNER" "$PB" "$W_P" "$(jq -nc --arg w "$W_B" '{operation:"storage_clear_version",wasm_hash:$w}')"
  ran_ok "V B@new clear_version" && pass "V from B, clear_version(W_B) → Ok"
  run "$OWNER" "$PB" "$W_P" "$(jq -nc --arg k "$K" '{operation:"storage_has",key:$k}')"
  ran_ok "V B has k after its clear" && { [[ "$(out_field .exists)" == false ]] \
    && pass "V B's clear_version(W_B) removed k" || fail "V k survived B's clear_version"; }
  [[ "$(sql "SELECT count(*) FROM storage_data WHERE project_uuid='$UB' AND account_id='$OWNER' AND key_hash='$KH'")" == 0 ]] \
    && pass "V storage_data: no row for k in B" || fail "V storage_data still holds B's k"
  set_active "$NAME_B" encryption-storage

  if [[ "$LOGS_OK" == true ]]; then
    sleep 5
    la=$(coord_lines "storage_clear_version: deleted" | grep -F "project=$UA wasm_hash=$W_B" | tail -1)
    lb=$(coord_lines "storage_clear_version: deleted" | grep -F "project=$UB wasm_hash=$W_B" | tail -1)
    [[ "$la" =~ deleted\ 0\ rows ]] && pass "V coordinator: ${la##*INFO }" || fail "V no 'deleted 0 rows for project=$UA' line: '$la'"
    [[ "$lb" =~ deleted\ [1-9][0-9]*\ rows ]] && pass "V coordinator: ${lb##*INFO }" || fail "V no 'deleted N≥1 rows for project=$UB' line: '$lb'"
  else
    skip "V coordinator log lines — the log is unreadable"
  fi
fi

# ── M an unknown top-level manifest member ──────────────────────────────────

if want M; then
  log "M a manifest with an unknown top-level member refuses the run"
  [[ -n "$(uuid_of "$OWNER/$NAME_A")" ]] || ensure_project "$NAME_A" encryption-storage project-misspelled
  if [[ -z "$(version_on_chain "$OWNER/$NAME_A" "$W_M")" ]]; then
    out=$(call "$OWNER" add_version "$(jq -nc --arg n "$NAME_A" --argjson s "$(src_of project-misspelled)" '{project_name:$n, source:$s, set_active:false}')" '0.1 NEAR')
    succeeded "$out" || fail "M add_version of the misspelled build: $(why_of "$out")"
    sleep 4
  fi
  [[ "$(version_on_chain "$OWNER/$NAME_A" "$W_M")" == WasmUrl ]] && pass "M the misspelled build (${W_M:0:12}) is a version of $OWNER/$NAME_A" \
    || fail "M the misspelled build is not a version of $OWNER/$NAME_A"
  run "$OWNER" "$OWNER/$NAME_A" "$W_M" '{"operation":"all_public_keys"}'
  if [[ "$RUN_OK" == true ]]; then
    fail "M the run HAPPENED: $(head -c 300 <<<"$RUN_OUT")"
  elif [[ "$RUN_OK" == absent ]]; then
    fail "M nothing answered; a timeout is not a refusal: $RUN_ERR"
  else
    pass "M the run was refused (success false): $(head -c 300 <<<"$RUN_ERR")"
    missing=""
    for m in storage_acount storage_account signing_keys encryption_keys capabilities; do
      grep -qF "\`$m\`" <<<"$RUN_ERR" || missing+="$m "
    done
    [[ -z "$missing" ]] && pass "M the refusal names \`storage_acount\` and the known members (storage_account, signing_keys, encryption_keys, capabilities)" \
      || fail "M the refusal does not name: $missing"
    [[ -z "$(out_field .build)" && -z "$(out_field .keys)" ]] && pass "M no probe answer came back: the module never ran" \
      || fail "M the probe answered: $(head -c 300 <<<"$RUN_OUT")"
  fi
fi

# ── D deleting a project erases its per-account records ─────────────────────

if want D; then
  NAME_D="storage-cleanup-$RUN_START"; PD="$OWNER/$NAME_D"
  log "D delete_project erases the raw, sealed and encrypted records of every account ($PD)"
  ensure_project "$NAME_D" encryption-storage
  UD=$(uuid_of "$PD")
  note "D $PD ($UD)"
  run "$OWNER" "$PD" "$W_B" "$(jq -nc --arg k "$TAG/raw" '{operation:"raw_set",key:$k,value_hex:"d0d0"}')";     ran_ok "D $OWNER raw_set" >/dev/null
  run "$OWNER" "$PD" "$W_B" "$(jq -nc --arg k "$TAG/sealed" '{operation:"sealed_put",path:"alpha",key:$k,value:"sealed"}')"; ran_ok "D $OWNER sealed_put" >/dev/null
  run "$OWNER" "$PD" "$W_B" "$(jq -nc --arg k "$TAG/sdk" '{operation:"sealed_handle",path:"alpha",key:$k,value:"sdk"}')"; ran_ok "D $OWNER sealed_handle" >/dev/null
  run "$OWNER" "$PD" "$W_B" "$(jq -nc --arg k "$TAG/enc" '{operation:"enc_set",key:$k,value_hex:"e0"}')";        ran_ok "D $OWNER enc_set" >/dev/null
  run "$CALLER2" "$PD" "$W_B" "$(jq -nc --arg k "$TAG/raw" '{operation:"raw_set",key:$k,value_hex:"c2"}')";     ran_ok "D $CALLER2 raw_set" >/dev/null
  run "$CALLER2" "$PD" "$W_B" "$(jq -nc --arg k "$TAG/enc" '{operation:"enc_set",key:$k,value_hex:"c2"}')";     ran_ok "D $CALLER2 enc_set" >/dev/null
  before=$(sql "SELECT string_agg(account_id||':'||is_encrypted::text||'='||n, ',' ORDER BY account_id, is_encrypted) FROM (SELECT account_id, is_encrypted, count(*) n FROM storage_data WHERE project_uuid='$UD' GROUP BY 1,2) t")
  # $OWNER: raw + sealed + SDK sealed (3 raw rows), enc (1); $CALLER2: raw (1), enc (1).
  [[ "$before" == "$CALLER2:false=1,$CALLER2:true=1,$OWNER:false=3,$OWNER:true=1" ]] \
    && pass "D storage_data before the delete: $before" || fail "D storage_data before the delete: '$before'"
  out=$(call "$OWNER" delete_project "$(jq -nc --arg n "$NAME_D" '{project_name:$n}')" '0 NEAR')
  if succeeded "$out"; then
    grep -q "ProjectStorageCleanup" <<<"$out" && pass "D delete_project emits ProjectStorageCleanup" || note "D the delete's transcript shows no ProjectStorageCleanup event (read from the receipts below)"
    left=""
    for i in $(seq 1 24); do
      left=$(sql "SELECT count(*) FROM storage_data WHERE project_uuid='$UD'")
      [[ "$left" == 0 ]] && break
      sleep 10
    done
    [[ "$left" == 0 ]] && pass "D storage_data rows for $UD after the cleanup task: 0 (~$((i*10)) s)" \
      || fail "D $left storage_data rows for $UD remain 4 min after the delete"
    if [[ "$LOGS_OK" == true ]]; then
      l=$(coord_lines "$UD" | grep -iE 'cleanup' | tail -2 | tr '\n' ' ')
      [[ -n "$l" ]] && note "D coordinator: $(head -c 300 <<<"$l")"
    fi
  else
    fail "D delete_project failed: $(why_of "$out")"
  fi
fi

verdict "storage scope"
