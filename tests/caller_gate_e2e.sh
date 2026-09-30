#!/usr/bin/env bash
#
# The manifest's `callers` block end to end, on testnet:
# `wasi-examples/caller-gate-probe` published as versions of one project and
# called through every door — directly, through a relay contract, through a
# second contract, as a NEP-366 meta-transaction and over HTTPS.
#
# What each row pins (a refused row: the completion event says
# success=false, its error starts "This project's manifest", names the door,
# ends "Nothing was executed.", and the probe's answer is absent):
#   G1  open (no callers block): direct, relayed, through the deputy, HTTPS and
#       a meta-transaction all run. The meta-transaction row reads the run's
#       identity: sender, user and predecessor are $PARENT, NEAR_RELAYER_ID is
#       $RELAYER, and the signer's key is not the relayer's
#   G2  direct-only: direct runs; relayed, HTTPS and a meta-transaction are
#       refused (a callers block refuses meta-transactions unless it admits them)
#   G3  contract-relay (`only: [$RELAY_CONTRACT]`): relayed runs; through the
#       deputy refused, naming the deputy and not the relay; direct refused —
#       $PARENT publishes the project, and the owner gets no exception; HTTPS
#       and a meta-transaction refused
#   G4  contract-any: relayed and through the deputy run; direct refused
#   G5  https-only: HTTPS runs; direct refused
#   G6  meta-tx (`contract: deny`, `meta_tx: allow`): a meta-transaction runs;
#       direct runs; relayed refused
#   G7  a refusal's price: the refused direct run of G3 charges the base fee
#       and refunds the rest of the deposit (execution_completed's
#       payment_charged + payment_refunded = the deposit)
#   G8  tasks-direct-deny: refused as an unreadable manifest naming tasks
#
# Attacks — a caller trying to get through a door the manifest shuts:
#   A1  pin another version: a project that still publishes a version with no
#       callers block is callable through it by anyone — the rule is the
#       version's. Printed as a FINDING, not a failure: it is the design, and
#       the author's remedy is to remove the open versions
#   A2  skip the project: run the contract-relay build directly from its wasm
#       URL (no project) → still refused; the manifest travels with the bytes
#   A3  claim a payer: a direct call naming the listed relay as
#       payer_account_id → refused; the payer is not the caller
#   A4  a meta-transaction THROUGH a contract (the delegate calls the relay,
#       the relay calls OutLayer) against meta-tx (`contract: deny`,
#       `meta_tx: allow`) → refused as a contract call, not admitted as a
#       meta-transaction
#   A5  a delegate its own sender relays, against direct-only → runs as a
#       direct call, NEAR_RELAYER_ID empty
#   A6  a listed account as the relayer (contract-deputy, `only: [$DEPUTY]`):
#       $DEPUTY relays $PARENT's delegate → refused (the caller is $PARENT);
#       control: $DEPUTY calling OutLayer itself → runs
#   A7  the gate comes first: a refused run naming a secret row that does not
#       exist fails with the gate's sentence, not a secrets error
#   A8  claim a context over HTTPS: a /call body carrying predecessor_id,
#       relayer_id and a context against direct-only → does not run
#   A9  claim an identity in the input: whoami with sender_id / relayer_id /
#       predecessor_id in the input → the answer is the worker's, not the input's
#
# Needs: PARENT (publishes the project, signs the direct and delegated calls),
# RELAYER (a second account that relays the meta-transactions and pays their
# gas), both keys in the legacy keychain; RELAY_CONTRACT, the deployed
# wasi-examples/test-storage-ark/relay-contract relaying to $CONTRACT_ID (G3's
# allowlist names it: `relay.outlayer-alice.testnet`, the probe's manifest);
# DEPUTY, a tests/deputy-stub owned by $PARENT and funded (the second contract;
# its rows SKIP without it); PAYMENT_KEY, a testnet payment key of $PARENT
# (`ALICE_PAYMENT_KEY` in .env.testnet-keys; the HTTPS rows SKIP without it); the `outlayer` CLI logged in on testnet (it pays the FastFS
# uploads); near, jq, curl, cargo + wasm-tools, python3.
# The RPC is keyed through tests/lib/rpc.sh.
#
# Money: eight FastFS uploads (~60 KB each), project storage, ~30 runs at
# $DEPOSIT (a refused run keeps the base fee and refunds the rest), and the
# relayer's gas for four meta-transactions.
#
# Run:
#   PARENT=outlayer-alice.testnet RELAYER=outlayer-bob.testnet ./tests/caller_gate_e2e.sh          # dry run
#   PARENT=… RELAYER=… RELAY_CONTRACT=relay.outlayer-alice.testnet DEPUTY=deputy.outlayer-alice.testnet \
#     PAYMENT_KEY=… ./tests/caller_gate_e2e.sh --apply

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/lib/hos_common.sh"   # NETWORK, CONTRACT_ID, keyed RPC_URL, COORDINATOR_URL, pass/fail/skip/verdict

APPLY=false
[[ "${1:-}" == "--apply" ]] && APPLY=true

PARENT="${PARENT:-}"
RELAYER="${RELAYER:-}"
RELAY_CONTRACT="${RELAY_CONTRACT:-}"
DEPUTY="${DEPUTY:-}"
PAYMENT_KEY="${PAYMENT_KEY:-}"
PROJECT_NAME="${PROJECT_NAME:-caller-gate-probe}"
PROJECT="$PARENT/$PROJECT_NAME"
DEPOSIT="${DEPOSIT:-0.1 NEAR}"
DEPOSIT_YOCTO="${DEPOSIT_YOCTO:-100000000000000000000000}"
PROBE_DIR="$REPO_ROOT/wasi-examples/caller-gate-probe"
VARIANTS="$PROBE_DIR/target/variants"
ALL_VARIANTS="open direct-only contract-any contract-relay contract-deputy https-only meta-tx tasks-direct-deny"
export OUTLAYER_NETWORK="$NETWORK"
source "$SCRIPT_DIR/lib/secrets_common.sh"   # https_post: RUN_OK / RUN_ERR / RUN_OUT of one HTTPS call

WORK=$(mktemp -d -t caller_gate_e2e.XXXXXX)
chmod 700 "$WORK"
trap 'rm -rf "$WORK"' EXIT

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
tx_read() { # tx_read <hash> <signer> — the transaction, final
  rpc_post "$(jq -nc --arg t "$1" --arg s "$2" \
    '{jsonrpc:"2.0",id:1,method:"tx",params:{tx_hash:$t,sender_account_id:$s,wait_until:"FINAL"}}')"
}
tx_of() { grep -oE 'Transaction ID: *[1-9A-HJ-NP-Za-km-z]{40,50}' <<<"$1" | grep -oE '[1-9A-HJ-NP-Za-km-z]{40,50}' | head -1; }
sha_of() { shasum -a 256 "$1" | cut -d' ' -f1; }
version_on_chain() { # version_on_chain <version_key> — the version's source kind, or empty
  view "$CONTRACT_ID" get_version "$(jq -nc --arg p "$PROJECT" --arg v "$1" '{project_id:$p, version_key:$v}')" \
    | jq -r 'select(. != null) | .source | keys[0] // empty' 2>/dev/null
}
# Per-variant values in plain variables — the macOS bash (3.2) has no
# associative arrays. `var_of hash contract-relay` → H_contract_relay.
var_of() { printf '%s_%s' "$( [[ $1 == hash ]] && echo H || echo U )" "${2//-/_}"; }
set_for() { printf -v "$(var_of "$1" "$2")" '%s' "$3"; }
get_for() { local n; n=$(var_of "$1" "$2"); printf '%s' "${!n:-}"; }

call_on() { # call_on <signer> <receiver> <method> <args-json> <deposit>
  near contract call-function as-transaction "$2" "$3" json-args "$4" \
    prepaid-gas '300.0 Tgas' attached-deposit "$5" sign-as "$1" network-config "$NETWORK" sign-with-legacy-keychain send 2>&1
}

WHOAMI='{"operation":"whoami"}'
exec_args() { # exec_args <version_key>
  jq -nc --arg p "$PROJECT" --arg v "$1" --arg i "$WHOAMI" \
    '{source:{Project:{project_id:$p, version_key:$v}}, input_data:$i, response_format:"Json",
      resource_limits:{max_instructions:1000000000,max_memory_mb:128,max_execution_seconds:30}}'
}

# One run's verdict: RUN_OK (true / false / absent), RUN_ERR, RUN_OUT (the
# probe's answer), RUN_EVENT (execution_completed's data). `settle <tx>
# <signer> <transcript>` reads them off the send's own transcript, or off the
# final transaction when the run outlived it.
RUN_OK=""; RUN_ERR=""; RUN_OUT=""; RUN_EVENT=""
settle() {
  local tx=$1 signer=$2 out=$3 ev logs="" i
  ev=$(grep -o 'EVENT_JSON:.*execution_completed.*' <<<"$out" | sed 's/^EVENT_JSON://' | head -1)
  if [[ -n "$tx" ]]; then
    for i in $(seq 1 20); do
      logs=$(tx_read "$tx" "$signer")
      [[ -z "$ev" ]] && ev=$(jq -r '[.result.receipts_outcome[]?.outcome.logs[]?] | join("\n")' <<<"$logs" 2>/dev/null \
        | grep -o 'EVENT_JSON:.*execution_completed.*' | sed 's/^EVENT_JSON://' | head -1)
      [[ -n "$ev" ]] && break
      jq -e '[.result.receipts_outcome[]?.outcome.status | select(has("Failure"))] | length > 0' <<<"$logs" >/dev/null 2>&1 && break
      sleep 6
    done
  fi
  RUN_EVENT=$(jq -c '.data[0] // empty' <<<"$ev" 2>/dev/null)
  # The probe's answer is the value some receipt of the contract returned: on
  # a direct call the transaction's own, through a relay or a delegate a
  # receipt inside it.
  RUN_OUT=$(jq -r --arg c "$CONTRACT_ID" \
    '[.result.status.SuccessValue?, (.result.receipts_outcome[]? | .outcome.status.SuccessValue?)] | .[] | select(. != null and . != "")' \
    <<<"$logs" 2>/dev/null | while read -r b; do printf '%s' "$b" | base64 --decode 2>/dev/null; echo; done \
    | jq -c 'if type=="string" then (fromjson? // .) else . end | select(type=="object" and has("build"))' 2>/dev/null | head -1)
  if [[ -z "$RUN_EVENT" ]]; then
    RUN_OK=absent; RUN_ERR=$(near_why "$out" | head -c 300)
    return 0
  fi
  RUN_OK=$(jq -r 'if has("success") then (.success|tostring) else "absent" end' <<<"$RUN_EVENT")
  RUN_ERR=$(jq -r '.error_message // ""' <<<"$RUN_EVENT")
}

direct() { # direct <signer> <variant> [jq filter over the args]
  local out args
  args=$(jq -c "${3:-.}" <<<"$(exec_args "$(get_for hash "$2")")")
  out=$(call_on "$1" "$CONTRACT_ID" request_execution "$args" "$DEPOSIT")
  settle "$(tx_of "$out")" "$1" "$out"
}
relayed() { # relayed <variant> — through $RELAY_CONTRACT, signed by $PARENT
  local out
  out=$(call_on "$PARENT" "$RELAY_CONTRACT" relay "$(exec_args "$(get_for hash "$1")")" "$DEPOSIT")
  settle "$(tx_of "$out")" "$PARENT" "$out"
}
deputied() { # deputied <variant> — through $DEPUTY, which pays the deposit itself
  local out args
  args=$(jq -nc --arg c "$CONTRACT_ID" --arg p "$PROJECT" --arg v "$(get_for hash "$1")" --arg d "$DEPOSIT_YOCTO" \
    '{outlayer:$c, source:{Project:{project_id:$p, version_key:$v}}, secrets_ref:null, deposit:$d}')
  out=$(call_on "$PARENT" "$DEPUTY" relay "$args" '0 NEAR')
  settle "$(tx_of "$out")" "$PARENT" "$out"
}
# A NEP-366 meta-transaction: $PARENT signs a delegate action calling
# request_execution, $RELAYER signs and sends the transaction carrying it. The
# signed delegate action goes through a file of this run's own directory,
# never a command line or the terminal: until it expires anyone holding it
# could relay it.
meta_tx() { # meta_tx <variant>
  delegated "$PARENT" "$RELAYER" "$CONTRACT_ID" request_execution "$(exec_args "$(get_for hash "$1")")"
}
delegated() { # delegated <sender> <relayer> <receiver> <method> <args-json>
  local sender=$1 relayer=$2 out file="$WORK/delegate.json"
  rm -f "$file"
  out=$(near transaction construct-meta-transaction "$sender" "$3" \
    add-action function-call "$4" json-args "$5" \
    prepaid-gas '150.0 Tgas' attached-deposit "$DEPOSIT" skip \
    network-config "$NETWORK" sign-with-legacy-keychain --meta-transaction-valid-for 600 save-to-file "$file" 2>&1)
  if ! jq -e '.signed_delegate_action_as_base64 | length > 0' "$file" >/dev/null 2>&1; then
    RUN_OK=absent; RUN_ERR="the delegate action was not signed: $(near_why "$out" | head -c 200)"; RUN_OUT=""; RUN_EVENT=""
    return 0
  fi
  out=$(near transaction send-meta-transaction file-with-base64-signed-meta-transaction "$file" \
    sign-as "$relayer" network-config "$NETWORK" sign-with-legacy-keychain send 2>&1)
  rm -f "$file"
  settle "$(tx_of "$out")" "$relayer" "$out"
}
over_https() { # over_https <variant>
  https_post "$PAYMENT_KEY" "$PROJECT" \
    "$(jq -nc --argjson i "$WHOAMI" --arg v "$(get_for hash "$1")" '{input:$i, version_key:$v}')"
  RUN_EVENT=""
}

out_field() { jq -r "$1 | if . == null then \"\" else tostring end" <<<"$RUN_OUT" 2>/dev/null; }

expect_ran() { # expect_ran <row>
  if [[ "$RUN_OK" != "true" ]]; then
    fail "$1 — did not run ($RUN_OK): $(head -c 300 <<<"$RUN_ERR")"; return 1
  fi
  pass "$1 — ran"
}
expect_refused() { # expect_refused <row> <door-regex> [account that must be named] [account that must not be]
  local row=$1 door=$2 named=${3:-} unnamed=${4:-}
  if [[ "$RUN_OK" == "true" ]]; then fail "$row — RAN: $(head -c 200 <<<"$RUN_OUT")"; return 1; fi
  if [[ "$RUN_OK" == "absent" ]]; then fail "$row — nothing answered; a timeout is not a refusal: $RUN_ERR"; return 1; fi
  if ! grep -qF "This project's manifest" <<<"$RUN_ERR" || ! grep -qE "$door" <<<"$RUN_ERR"; then
    fail "$row — refused, but not by the caller gate: $(head -c 300 <<<"$RUN_ERR")"; return 1
  fi
  if ! grep -qF 'Nothing was executed.' <<<"$RUN_ERR"; then fail "$row — the sentence does not say 'Nothing was executed.': $RUN_ERR"; return 1; fi
  if [[ -n "$RUN_OUT" && "$RUN_OUT" != "null" ]]; then fail "$row — refused, yet the probe answered: $RUN_OUT"; return 1; fi
  if [[ -n "$named" ]] && ! grep -qF "$named" <<<"$RUN_ERR"; then fail "$row — does not name $named: $RUN_ERR"; return 1; fi
  if [[ -n "$unnamed" ]] && grep -qF "$unnamed" <<<"$RUN_ERR"; then fail "$row — names $unnamed, which it must not: $RUN_ERR"; return 1; fi
  pass "$row — refused: $(head -c 160 <<<"$RUN_ERR")"
}

have() { # have <row> <VARIABLE…> — SKIP the row when one is unset
  local row=$1 v; shift
  for v in "$@"; do
    [[ -n "${!v:-}" ]] && continue
    skip "$row needs $v"
    return 1
  done
  return 0
}

# ── preflight ────────────────────────────────────────────────────────────────

note "RPC: $(rpc_url_public)"
for tool in jq curl near outlayer cargo python3 shasum; do
  command -v "$tool" >/dev/null || { echo "✗ missing $tool" >&2; exit 1; }
done
[[ -n "$PARENT" && -n "$RELAYER" ]] || { echo "USAGE: PARENT=you.testnet RELAYER=friend.testnet $0 [--apply]" >&2; exit 1; }
[[ "$PARENT" != "$RELAYER" ]] || { echo "✗ RELAYER must be another account than PARENT" >&2; exit 1; }
CREDS_DIR="$HOME/.near-credentials/$NETWORK"
for acct in "$PARENT" "$RELAYER"; do
  [[ -f "$CREDS_DIR/$acct.json" ]] && continue
  [[ "$APPLY" == true ]] && { echo "✗ no key in $CREDS_DIR for $acct" >&2; exit 1; }
  warn "no key in $CREDS_DIR for $acct — --apply will stop here"
done
if [[ -n "$RELAY_CONTRACT" ]]; then
  target=$(view "$RELAY_CONTRACT" outlayer '{}' | jq -r 'select(type == "string")' 2>/dev/null)
  if [[ "$target" != "$CONTRACT_ID" ]]; then
    warn "$RELAY_CONTRACT does not relay to $CONTRACT_ID (its outlayer(): '${target:-unreadable}') — its rows SKIP"
    RELAY_CONTRACT=""
  fi
fi
if [[ -n "$RELAY_CONTRACT" ]] && ! grep -qF "\"$RELAY_CONTRACT\"" "$PROBE_DIR/manifests/contract-relay.json"; then
  warn "the contract-relay manifest does not name $RELAY_CONTRACT — G3's allowlist rows judge another relay"
fi
if [[ -n "$DEPUTY" ]]; then
  owner=$(view "$DEPUTY" owner '{}' | jq -r 'select(type == "string")' 2>/dev/null)
  if [[ "$owner" != "$PARENT" ]]; then
    warn "$DEPUTY is not a deputy owned by $PARENT (its owner(): '${owner:-unreadable}') — its rows SKIP"
    DEPUTY=""
  fi
fi
[[ -n "$PAYMENT_KEY" ]] && note "PAYMENT_KEY: present (${#PAYMENT_KEY} chars)" || warn "PAYMENT_KEY unset — the HTTPS rows SKIP"

if [[ "$APPLY" != true ]]; then
  log "dry run — nothing is built, uploaded, published or run"
  sed -n '3,/^$/p' "$0" >&2
  for v in $ALL_VARIANTS; do
    f="$VARIANTS/caller-gate-probe-$v.wasm"
    if [[ -f "$f" ]]; then note "$v: built, sha256 $(sha_of "$f"); as a version of $PROJECT: $(version_on_chain "$(sha_of "$f")" || true)"
    else note "$v: not built yet (--apply runs $PROBE_DIR/build.sh)"; fi
  done
  echo "  Pass --apply to run." >&2
  exit 0
fi

# ── setup: build, upload, publish ────────────────────────────────────────────

log "build the probe"
(cd "$PROBE_DIR" && ./build.sh >/dev/null) || { echo "✗ $PROBE_DIR/build.sh failed" >&2; exit 1; }
for v in $ALL_VARIANTS; do set_for hash "$v" "$(sha_of "$VARIANTS/caller-gate-probe-$v.wasm")"; done

log "upload to FastFS"
for v in $ALL_VARIANTS; do
  url=$(fastfs_upload "$VARIANTS/caller-gate-probe-$v.wasm" "$(get_for hash "$v")") || { echo "✗ upload of $v never served its bytes" >&2; exit 1; }
  set_for url "$v" "$url"
done

wasm_src() { jq -nc --arg u "$(get_for url "$1")" --arg h "$(get_for hash "$1")" '{WasmUrl:{url:$u, hash:$h, build_target:"wasm32-wasip2"}}'; }
log "publish $PROJECT"
if [[ -z "$(view "$CONTRACT_ID" get_project "$(jq -nc --arg p "$PROJECT" '{project_id:$p}')" | jq -r '.project_id // empty' 2>/dev/null)" ]]; then
  out=$(call_on "$PARENT" "$CONTRACT_ID" create_project "$(jq -nc --arg n "$PROJECT_NAME" --argjson s "$(wasm_src open)" '{name:$n, source:$s}')" '0.3 NEAR')
  grep -q 'succeeded' <<<"$out" || { echo "✗ create_project failed: $(near_why "$out")" >&2; exit 1; }
  sleep 4
fi
for v in $ALL_VARIANTS; do
  [[ -n "$(version_on_chain "$(get_for hash "$v")")" ]] && continue
  out=$(call_on "$PARENT" "$CONTRACT_ID" add_version "$(jq -nc --arg n "$PROJECT_NAME" --argjson s "$(wasm_src "$v")" '{project_name:$n, source:$s, set_active:false}')" '0.1 NEAR')
  grep -q 'succeeded' <<<"$out" || { echo "✗ add_version $v failed: $(near_why "$out")" >&2; exit 1; }
  sleep 4
done
for v in $ALL_VARIANTS; do
  [[ "$(version_on_chain "$(get_for hash "$v")")" == "WasmUrl" ]] || { echo "✗ $v is not a WasmUrl version of $PROJECT" >&2; exit 1; }
done

# ── G1 open ──────────────────────────────────────────────────────────────────

log "G1 no callers block: every door"
direct "$PARENT" open
if [[ "$RUN_OK" != "true" ]] && [[ "$RUN_ERR" == *"unknown field \`callers\`"* ]]; then
  skip "the worker predates the callers block: $(head -c 200 <<<"$RUN_ERR")"
  verdict "caller gate"; exit $?
fi
expect_ran "G1a direct" && {
  [[ "$(out_field .relayer_id)" == "" ]] && pass "G1a direct — NEAR_RELAYER_ID is empty" \
    || fail "G1a direct — NEAR_RELAYER_ID is '$(out_field .relayer_id)'"
}
if have "G1b relayed" RELAY_CONTRACT; then relayed open; expect_ran "G1b relayed"; fi
if have "G1c deputy" DEPUTY; then deputied open; expect_ran "G1c through the deputy"; fi
if have "G1d HTTPS" PAYMENT_KEY; then over_https open; expect_ran "G1d HTTPS"; fi
meta_tx open
if expect_ran "G1e meta-transaction"; then
  for f in sender_id user_account_id predecessor_id; do
    [[ "$(out_field ".$f")" == "$PARENT" ]] && pass "G1e meta-transaction — $f is $PARENT, who signed the delegate action" \
      || fail "G1e meta-transaction — $f is '$(out_field ".$f")', not $PARENT"
  done
  [[ "$(out_field .relayer_id)" == "$RELAYER" ]] && pass "G1e meta-transaction — NEAR_RELAYER_ID is $RELAYER" \
    || fail "G1e meta-transaction — NEAR_RELAYER_ID is '$(out_field .relayer_id)', not $RELAYER"
  relayer_key=$(jq -r '.public_key // empty' "$CREDS_DIR/$RELAYER.json" 2>/dev/null)
  parent_key=$(jq -r '.public_key // empty' "$CREDS_DIR/$PARENT.json" 2>/dev/null)
  key=$(out_field .signer_public_key)
  if [[ -n "$parent_key" && "$key" == "$parent_key" ]]; then pass "G1e meta-transaction — the signer's key is $PARENT's"
  elif [[ -n "$relayer_key" && "$key" == "$relayer_key" ]]; then fail "G1e meta-transaction — the signer's key is the relayer's"
  else finding "G1e meta-transaction — the signer's key $key is neither key file's (compare by hand)"; fi
fi

# ── G2 direct only ───────────────────────────────────────────────────────────

log "G2 direct-only"
direct "$PARENT" direct-only
if [[ "$RUN_OK" != "true" ]] && grep -q 'unknown field `callers`' <<<"$RUN_ERR"; then
  skip "the worker predates the callers block — G1 ran on it; the gate rows wait for the deploy: $(head -c 160 <<<"$RUN_ERR")"
  verdict "caller gate"; exit $?
fi
expect_ran "G2a direct"
if have "G2b relayed" RELAY_CONTRACT; then relayed direct-only; expect_refused "G2b relayed" "through a contract" "$RELAY_CONTRACT"; fi
if have "G2c HTTPS" PAYMENT_KEY; then over_https direct-only; expect_refused "G2c HTTPS" "HTTPS"; fi
meta_tx direct-only; expect_refused "G2d meta-transaction (a callers block refuses them by default)" "meta-transactions" "$RELAYER"

# ── G3 only the relay ────────────────────────────────────────────────────────

log "G3 contract-relay: only $RELAY_CONTRACT"
if have "G3a relayed" RELAY_CONTRACT; then relayed contract-relay; expect_ran "G3a relayed (on the list)"; fi
if have "G3b deputy" DEPUTY; then
  deputied contract-relay
  expect_refused "G3b through the deputy" "admits calls only from the contracts it names" "$DEPUTY" "${RELAY_CONTRACT:-relay.outlayer-alice.testnet}"
fi
direct "$PARENT" contract-relay
expect_refused "G3c direct by the project's own owner" "admits calls only from the contracts it names.*directly" "$PARENT"
G3C_EVENT=$RUN_EVENT
if have "G3d HTTPS" PAYMENT_KEY; then over_https contract-relay; expect_refused "G3d HTTPS" "HTTPS call comes through no contract"; fi
meta_tx contract-relay; expect_refused "G3e meta-transaction" "meta-transaction relayed by" "$RELAYER"

# ── G4 any contract ──────────────────────────────────────────────────────────

log "G4 contract-any"
if have "G4a relayed" RELAY_CONTRACT; then relayed contract-any; expect_ran "G4a relayed"; fi
if have "G4b deputy" DEPUTY; then deputied contract-any; expect_ran "G4b through the deputy"; fi
direct "$PARENT" contract-any; expect_refused "G4c direct" "does not admit direct calls" "$PARENT"

# ── G5 HTTPS only ────────────────────────────────────────────────────────────

log "G5 https-only"
if have "G5a HTTPS" PAYMENT_KEY; then over_https https-only; expect_ran "G5a HTTPS"; fi
direct "$PARENT" https-only; expect_refused "G5b direct" "does not admit direct calls"

# ── G6 meta-transactions admitted ────────────────────────────────────────────

log "G6 meta-tx: contract deny, meta_tx allow"
meta_tx meta-tx; expect_ran "G6a meta-transaction"
direct "$PARENT" meta-tx; expect_ran "G6b direct"
if have "G6c relayed" RELAY_CONTRACT; then relayed meta-tx; expect_refused "G6c relayed" "through a contract"; fi

# ── G7 the price of a refusal ────────────────────────────────────────────────

log "G7 a refused run keeps the base fee and refunds the rest"
if [[ -n "$G3C_EVENT" ]]; then
  charged=$(jq -r '.payment_charged // empty' <<<"$G3C_EVENT"); refunded=$(jq -r '.payment_refunded // empty' <<<"$G3C_EVENT")
  if [[ -n "$charged" && -n "$refunded" ]] && python3 -c "import sys; c,r,d=map(int,sys.argv[1:]); sys.exit(0 if c+r==d and 0<c<d else 1)" "$charged" "$refunded" "$DEPOSIT_YOCTO"; then
    pass "G7 charged $charged yoctoNEAR, refunded $refunded of $DEPOSIT_YOCTO"
  else
    fail "G7 charged '$charged', refunded '$refunded' of $DEPOSIT_YOCTO"
  fi
else
  fail "G7 — G3c left no completion event to read"
fi

# ── G8 tasks with the direct door shut ───────────────────────────────────────

log "G8 tasks-direct-deny"
direct "$PARENT" tasks-direct-deny
if [[ "$RUN_OK" == "false" ]] && grep -q "manifest cannot be read" <<<"$RUN_ERR" && grep -q "declares tasks" <<<"$RUN_ERR"; then
  pass "G8 refused as an unreadable manifest: $(head -c 160 <<<"$RUN_ERR")"
else
  fail "G8 — $RUN_OK: $(head -c 300 <<<"$RUN_ERR")"
fi

# ── attacks ──────────────────────────────────────────────────────────────────

log "A1 pin a version that declares no rule"
direct "$PARENT" open
if [[ "$RUN_OK" == "true" ]]; then
  finding "A1 a published version without a callers block stays callable by anyone who pins it; gating a project means removing its open versions"
else
  fail "A1 the open version did not run ($RUN_OK): $(head -c 200 <<<"$RUN_ERR")"
fi

log "A2 run the gated build directly from its wasm URL"
out=$(call_on "$PARENT" "$CONTRACT_ID" request_execution "$(jq -nc --argjson s "$(wasm_src contract-relay)" --arg i "$WHOAMI" \
  '{source:{WasmUrl:$s.WasmUrl}, input_data:$i, response_format:"Json",
    resource_limits:{max_instructions:1000000000,max_memory_mb:128,max_execution_seconds:30}}')" "$DEPOSIT")
settle "$(tx_of "$out")" "$PARENT" "$out"
expect_refused "A2 contract-relay run from its URL" "admits calls only from the contracts it names" "$PARENT"

log "A3 name the listed relay as the payer"
direct "$PARENT" contract-relay "$(printf '. + {payer_account_id: "%s"}' "${RELAY_CONTRACT:-relay.outlayer-alice.testnet}")"
expect_refused "A3 payer_account_id is not the caller" "admits calls only from the contracts it names" "$PARENT"

log "A4 a meta-transaction through a contract"
if have "A4" RELAY_CONTRACT; then
  delegated "$PARENT" "$RELAYER" "$RELAY_CONTRACT" relay "$(exec_args "$(get_for hash meta-tx)")"
  expect_refused "A4 delegate → relay → OutLayer is a contract call" "through a contract" "$RELAY_CONTRACT"
fi

log "A5 a delegate its own sender relays"
delegated "$PARENT" "$PARENT" "$CONTRACT_ID" request_execution "$(exec_args "$(get_for hash direct-only)")"
if expect_ran "A5 self-relayed delegate against direct-only"; then
  [[ -z "$(out_field .relayer_id)" ]] && pass "A5 — NEAR_RELAYER_ID is empty: a direct call" \
    || fail "A5 — NEAR_RELAYER_ID is '$(out_field .relayer_id)'"
fi

log "A6 a listed account as the relayer"
if have "A6" DEPUTY; then
  if [[ -f "$CREDS_DIR/$DEPUTY.json" ]]; then
    delegated "$PARENT" "$DEPUTY" "$CONTRACT_ID" request_execution "$(exec_args "$(get_for hash contract-deputy)")"
    expect_refused "A6 $DEPUTY relaying $PARENT's delegate" "meta-transaction relayed by" "$PARENT"
    direct "$DEPUTY" contract-deputy
    expect_ran "A6 control: $DEPUTY calling OutLayer itself"
  else
    skip "A6 needs $DEPUTY's key in $CREDS_DIR"
  fi
fi

log "A7 the gate before the secrets"
direct "$PARENT" contract-any "$(printf '. + {secrets_ref: {account_id: "%s", profile: "caller-gate-no-such-row"}}' "$PARENT")"
expect_refused "A7 a refused run naming a missing secret row" "does not admit direct calls" "$PARENT"

log "A8 claim a context over HTTPS"
if have "A8" PAYMENT_KEY; then
  https_post "$PAYMENT_KEY" "$PROJECT" "$(jq -nc --argjson i "$WHOAMI" --arg v "$(get_for hash direct-only)" --arg r "${RELAY_CONTRACT:-relay.outlayer-alice.testnet}" \
    '{input:$i, version_key:$v, predecessor_id:$r, relayer_id:$r, is_https_call:false, context:{predecessor_id:$r, sender_id:$r}}')"
  if [[ "$RUN_OK" == "true" ]]; then fail "A8 — RAN with a claimed context: $(head -c 200 <<<"$RUN_OUT")"
  else pass "A8 — did not run (HTTP $HTTP_CODE): $(head -c 160 <<<"$RUN_ERR")"; fi
fi

log "A9 claim an identity in the input"
out=$(call_on "$PARENT" "$CONTRACT_ID" request_execution "$(jq -c --arg i '{"operation":"whoami","sender_id":"x.testnet","relayer_id":"y.testnet","predecessor_id":"z.testnet"}' \
  '.input_data = $i' <<<"$(exec_args "$(get_for hash open)")")" "$DEPOSIT")
settle "$(tx_of "$out")" "$PARENT" "$out"
if expect_ran "A9 whoami with claims in the input"; then
  [[ "$(out_field .sender_id)/$(out_field .predecessor_id)/$(out_field .relayer_id)" == "$PARENT/$PARENT/" ]] \
    && pass "A9 — the identity is the worker's" || fail "A9 — the input reached the identity: $RUN_OUT"
fi

verdict "caller gate"
