#!/usr/bin/env bash
#
# What the coordinator does with the contract's system events, live on TESTNET
# (.idea/_todo/failed-receipt-events-onchain-tests.md §A, rows A5 A6 A8 A9 A10).
# Each row drives the event ON CHAIN with the owner's own transaction and then
# reads the COORDINATOR's copy — its DB rows and its API — without replaying
# anything itself: the worker's event monitor is the only path between the two.
#
#   A5   `ft_transfer_call` → `top_up_payment_key` on a fresh key: the
#        coordinator's `payment_keys.initial_balance` grows by exactly the amount,
#        `GET /payment-keys/balance` (the key itself) says so, the callback logs
#        `Payment key topped up … amount=<amount>` in the owner's transaction, and
#        the worker's `resume_topup` transaction logs `TopUp yield resumed:
#        data_id=<the event's data_id>`
#   A6   `delete_payment_key` on that key: the coordinator's row gets
#        `deleted_at`, the key is refused by `GET /payment-keys/balance`, the
#        callback logs `Payment key deleted`, and the worker's transaction logs
#        `DeletePaymentKey yield resumed: data_id=<the event's data_id>`
#   R1   after A6, the deleted nonce is not handed out again: the owner's
#        floor holds it, get_next_payment_key_nonce answers past it, and a
#        store_secrets at it is refused ("has already been used"). Skipped on a
#        contract without get_payment_key_nonce_floor
#   A8   `store_wallet_policy` twice (v1, then v2 with a different address
#        list): `wallet_accounts.policy_json` follows the chain each time. v2
#        replaces a NON-NULL copy, which only `/internal/wallet-policy-sync`
#        writes (the lazy readers fill a NULL copy only) — and this suite calls
#        no wallet route between the transaction and the read
#   A9   `freeze_wallet`: `wallet_accounts.frozen` = t, a transfer → 403
#        `wallet_frozen`; `unfreeze_wallet`: frozen = f, the same transfer → 200
#   A10  `delete_wallet_policy`: `policy_json` NULL, `frozen` f
#
# Accounts: KEY_OWNER (default outlayer-bob.testnet) owns the payment key,
# WALLET_OWNER (default outlayer-carol.testnet) the wallet and its policy. Both
# are created here and removed by the end: the key by A6, the wallet's account
# by a sweep back to its owner, the policy by A10.
#
# Money: 0.1 NEAR key storage (refunded by A6), TOPUP minimal units of the
# payment token (lost with the key), 0.1 NEAR per policy store (refunded by
# A10), FUND NEAR into the wallet (swept back), two 0.001 NEAR transfers.
#
# Secrets: the payment key is read from the private OUTLAYER_HOME the CLI wrote
# it to, held in this process only, and reaches curl on stdin (`-H @-`). The
# wallet bearer is signed by scripts/customer-recovery with the owner's key in
# its environment (CUSTOMER_RECOVERY_PRIVATE_KEY), never on a command line, and
# reaches curl on stdin. Nothing secret is printed.
#
# Needs: both owners' keys in the legacy keychain; PSQL_CMD (the testnet
# coordinator DB, one statement); COORD_SSH for the coordinator log and
# WORKER_SSH + WORKER_CVM for the TEE worker's log (both read-only).
#
# Run:
#   PSQL_CMD=… ./tests/system_event_effects_e2e.sh            # dry run
#   PSQL_CMD=… ./tests/system_event_effects_e2e.sh --apply
#   ONLY=keys|wallet … --apply                                 # one half

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/lib/hos_common.sh"   # NETWORK, CONTRACT_ID, keyed RPC_URL, pass/fail/skip/verdict, sql

APPLY=false
[[ "${1:-}" == "--apply" ]] && APPLY=true

KEY_OWNER="${KEY_OWNER:-outlayer-bob.testnet}"
WALLET_OWNER="${WALLET_OWNER:-outlayer-carol.testnet}"
TOPUP="${TOPUP:-50000}"                   # $0.05 in the token's 6 decimals
FUND="${FUND:-0.05}"
SEND_YOCTO="1000000000000000000000"       # 0.001 NEAR
ONLY="${ONLY:-}"
COORD_SSH="${COORD_SSH:-root@138.201.58.122}"
COORD_CONTAINER="${COORD_CONTAINER:-offchainvm-coordinator-testnet}"
WORKER_SSH="${WORKER_SSH:-root@173.237.9.76}"
WORKER_CVM="${WORKER_CVM:-testnet-worker-0178-1}"
RUN_START=$(date +%s)
TAG="$RUN_START"
CREDS_DIR="$HOME/.near-credentials/$NETWORK"
RECOVERY_BIN="$REPO_ROOT/scripts/customer-recovery/target/release/customer-recovery"
SSH_OPTS=(-o ConnectTimeout=15 -o BatchMode=yes -o ControlMaster=no -o ControlPath=none)

OL_HOME=$(mktemp -d -t sysev_ol.XXXXXX)
chmod 700 "$OL_HOME"
trap 'rm -rf "$OL_HOME"' EXIT

# ── chain ────────────────────────────────────────────────────────────────────

rpc_post() { # the keyed URL reaches curl on stdin
  printf 'url = "%s"\n' "$RPC_URL" | command curl -sS --max-time 45 -K - -X POST \
    -H 'Content-Type: application/json' --data-binary "$1" 2>/dev/null
}
view() { # view <contract> <method> <args-json>
  rpc_post "$(jq -nc --arg c "$1" --arg m "$2" --arg g "$(printf '%s' "$3" | base64 | tr -d '\n')" \
    '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"call_function",finality:"final",account_id:$c,method_name:$m,args_base64:$g}}')" \
    | jq -r 'if .result.result then (.result.result | implode) else empty end' 2>/dev/null
}
# call <signer> <contract> <method> <args-json> <deposit> [gas] — the transcript.
# A transport failure before any transaction exists is retried once; one that
# produced a transaction id is never re-sent.
call() {
  local out i
  for i in 1 2; do
    out=$(near contract call-function as-transaction "$2" "$3" json-args "$4" \
      prepaid-gas "${6:-100.0 Tgas}" attached-deposit "$5" sign-as "$1" network-config "$NETWORK" \
      sign-with-legacy-keychain send 2>&1)
    grep -q 'Transaction ID' <<<"$out" && break
    grep -qiE 'error sending request|failed to fetch' <<<"$out" || break
    sleep 5
  done
  printf '%s\n' "$out"
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
# tx_logs <tx> <sender> — every log of the transaction's receipts, a JSON array.
tx_logs() {
  local r i
  for i in 1 2 3 4 5 6; do
    r=$(rpc_post "$(jq -nc --arg t "$1" --arg s "$2" '{jsonrpc:"2.0",id:1,method:"tx",params:{tx_hash:$t,sender_account_id:$s,wait_until:"FINAL"}}')")
    jq -e '.result' <<<"$r" >/dev/null 2>&1 && {
      jq -c '[.result.transaction_outcome.outcome.logs[]?, .result.receipts_outcome[]?.outcome.logs[]?]' <<<"$r"; return 0; }
    sleep 5
  done
  echo '[]'
}
# wait_log <tx> <sender> <fixed-string> — waits (≤ 3 min) for a log holding it
# among the transaction's receipts (a yield's callback lands after the resume).
wait_log() {
  local i logs
  for i in $(seq 1 18); do
    logs=$(tx_logs "$1" "$2")
    jq -e --arg s "$3" 'any(.[]; contains($s))' <<<"$logs" >/dev/null 2>&1 && {
      jq -r --arg s "$3" '[.[] | select(contains($s))][0]' <<<"$logs"; return 0; }
    sleep 10
  done
  return 1
}
# The data_id of the system event <name> in a log array, as hex.
event_data_id_hex() {
  jq -r --arg e "$2" '.[] | select(startswith("EVENT_JSON:")) | ltrimstr("EVENT_JSON:") | (try fromjson catch empty)
    | select(.event == "system_event") | .data[0][$e]? // empty | .data_id
    | if type == "array" then (map(. as $b | "0123456789abcdef"[($b/16|floor):($b/16|floor)+1] + "0123456789abcdef"[($b%16):($b%16)+1]) | join(""))
      else tostring end' <<<"$1" 2>/dev/null | head -1
}
# The worker's resume transaction for a data_id, from the TEE worker's log.
worker_resume_tx() { # worker_resume_tx <"TopUp"|"DeletePaymentKey"> <data_id-hex>
  local i line
  for i in 1 2; do
    line=$(ssh "${SSH_OPTS[@]}" "$WORKER_SSH" \
      "outlayer logs $WORKER_CVM 2>&1 | grep -F -- $(printf '%q' "✅ $1 resumed: data_id=$2 tx=") | tail -1" 2>/dev/null)
    [[ -n "$line" ]] && { grep -oE 'tx=[1-9A-HJ-NP-Za-km-z]{40,50}' <<<"$line" | cut -d= -f2; return 0; }
    sleep 10
  done
  return 1
}
# The same transaction found on chain when another worker took the task: the
# operator's <method> call carrying the data_id, included in one of the blocks
# just before the one the yield's callback ran in.
chain_resume_tx() { # chain_resume_tx <method> <data_id-hex> <callback-block-height>
  local h b c tx
  for (( h = $3; h >= $3 - 8; h-- )); do   # not `seq`: macOS prints large heights as 2.7e+08
    b=$(rpc_post "$(jq -nc --argjson h "$h" '{jsonrpc:"2.0",id:1,method:"block",params:{block_id:$h}}')")
    for c in $(jq -r '.result.chunks[]? | select(.height_included == '"$h"') | .chunk_hash' <<<"$b"); do
      tx=$(rpc_post "$(jq -nc --arg c "$c" '{jsonrpc:"2.0",id:1,method:"chunk",params:{chunk_id:$c}}')" \
        | jq -r --arg op "$OPERATOR" --arg ct "$CONTRACT_ID" --arg m "$1" --arg d "$2" '
            .result.transactions[]? | select(.signer_id == $op and .receiver_id == $ct)
            | select(any(.actions[]?; (.FunctionCall.method_name? == $m)
                and ((.FunctionCall.args | @base64d | fromjson? | .data_id) == $d))) | .hash' 2>/dev/null | head -1)
      [[ -n "$tx" ]] && { printf '%s' "$tx"; return 0; }
    done
  done
  return 1
}
# The height of the block the receipt holding <fixed-string> ran in, in <tx>.
log_block_height() { # log_block_height <tx> <sender> <fixed-string>
  local r bh
  r=$(rpc_post "$(jq -nc --arg t "$1" --arg s "$2" '{jsonrpc:"2.0",id:1,method:"tx",params:{tx_hash:$t,sender_account_id:$s,wait_until:"FINAL"}}')")
  bh=$(jq -r --arg s "$3" '[.result.receipts_outcome[] | select(any(.outcome.logs[]; contains($s)))][0].block_hash // empty' <<<"$r")
  [[ -n "$bh" ]] && rpc_post "$(jq -nc --arg h "$bh" '{jsonrpc:"2.0",id:1,method:"block",params:{block_id:$h}}')" | jq -r '.result.header.height // empty'
}
# resume_tx <"TopUp"|"DeletePaymentKey"> <method> <data_id> <user-tx> <callback-log> —
# the worker's resume transaction: from the TEE worker's log, else from the chain.
# Prints "<tx>|<where it was found>".
resume_tx() {
  local t h
  if t=$(worker_resume_tx "$1" "$3"); then printf '%s|%s log' "$t" "$WORKER_CVM"; return 0; fi
  h=$(log_block_height "$4" "$KEY_OWNER" "$5") || return 1
  [[ -n "$h" ]] || return 1
  t=$(chain_resume_tx "$2" "$3" "$h") || return 1
  printf '%s|chain (blocks %s..%s)' "$t" "$(( h - 8 ))" "$h"
}
OPERATOR=$(view "$CONTRACT_ID" get_config '{}' | jq -r '.[1] // empty' 2>/dev/null)

# ── coordinator ──────────────────────────────────────────────────────────────

coord_count() { # coord_count <fixed-string> — this run's coordinator log lines holding it
  local since=$(( $(date +%s) - RUN_START + 120 ))
  ssh "${SSH_OPTS[@]}" "$COORD_SSH" \
    "docker logs $COORD_CONTAINER --since ${since}s 2>&1 | grep -F -- $(printf '%q' "$1") | wc -l" 2>/dev/null | tr -d ' \n'
}
# pk_get <path> — GET with the payment key from $PK on stdin. Sets HTTP, BODY.
pk_get() {
  local out; out=$(mktemp -t sysev_b.XXXXXX)
  HTTP=$(printf 'X-Payment-Key: %s\n' "$PK" | command curl -sS -o "$out" -w '%{http_code}' --max-time 60 -H @- \
    "$COORDINATOR_URL$1" 2>/dev/null)
  BODY=$(tr -d '\n' < "$out"); rm -f "$out"
}
# The wallet bearer: signed with the owner's key held in the signer's environment.
W_PRIV=""
mk_bearer() { CUSTOMER_RECOVERY_PRIVATE_KEY="$W_PRIV" "$RECOVERY_BIN" sign-bearer-near --account-id "$WALLET_OWNER" --seed "$1"; }
# wapi <seed> <METHOD> <path> [body] — sets HTTP, BODY.
wapi() {
  local out; out=$(mktemp -t sysev_w.XXXXXX)
  local -a a=(-sS -o "$out" -w '%{http_code}' --max-time 90 -X "$2" -H @-)
  [[ -n "${4:-}" ]] && a+=(-H 'Content-Type: application/json' --data-binary "$4")
  throttle
  HTTP=$(printf 'Authorization: Bearer near:%s\n' "$(mk_bearer "$1")" | command curl "${a[@]}" "$COORDINATOR_URL$3" 2>/dev/null)
  BODY=$(tr -d '\n' < "$out"); rm -f "$out"
}
short() { head -c "${2:-240}" <<<"${1:-$BODY}"; }
q() { sql "$1" 2>/dev/null; }
# wait_sql <statement> <expected> [tries] — until the answer is the expected one.
wait_sql() {
  local i v=""
  for i in $(seq 1 "${3:-30}"); do
    v=$(q "$1"); [[ "$v" == "$2" ]] && { printf '%s' "$v"; return 0; }
    sleep 6
  done
  printf '%s' "$v"; return 1
}

# ── preflight ────────────────────────────────────────────────────────────────

log "system_event_effects_e2e — $NETWORK, $( [[ $APPLY == true ]] && echo APPLY || echo 'dry run' )"
note "RPC: $(rpc_url_public)"
note "coordinator: ${COORDINATOR_URL#*://}; key owner $KEY_OWNER; wallet owner $WALLET_OWNER; operator ${OPERATOR:-?}"
for tool in jq curl near outlayer ssh; do command -v "$tool" >/dev/null || { echo "✗ missing $tool" >&2; exit 1; }; done
for a in "$KEY_OWNER" "$WALLET_OWNER"; do
  [[ -f "$CREDS_DIR/$a.json" ]] || { echo "✗ no legacy-keychain key for $a" >&2; exit 1; }
done
sql_alive || { echo "✗ PSQL_CMD unset or not answering — every row here reads the coordinator DB" >&2; exit 1; }
[[ -n "$OPERATOR" ]] || { echo "✗ could not read the contract's operator (get_config)" >&2; exit 1; }
TOKEN=$(view "$CONTRACT_ID" get_payment_token_contract '{}' | jq -r '. // empty' 2>/dev/null)
[[ -n "$TOKEN" ]] || { echo "✗ the contract names no payment token" >&2; exit 1; }
note "payment token: $TOKEN"
if [[ ! -x "$RECOVERY_BIN" ]]; then
  (cd "$REPO_ROOT/scripts/customer-recovery" && cargo build --release --quiet) || { echo "✗ customer-recovery build failed" >&2; exit 1; }
fi

if [[ "$APPLY" != true ]]; then
  sed -n '3,/^$/p' "$0" >&2
  echo "  Pass --apply to run." >&2
  exit 0
fi

# ══ payment key: A5, A6 ══════════════════════════════════════════════════════
if [[ -z "$ONLY" || "$ONLY" == keys ]]; then
  log "fixture: a new payment key of $KEY_OWNER (outlayer keys create, private OUTLAYER_HOME)"
  mkdir -p "$OL_HOME/$NETWORK"
  ( umask 077; jq --arg a "$KEY_OWNER" --arg c "$CONTRACT_ID" \
      '{account_id:$a, public_key, private_key, contract_id:$c, auth_type:"near_key"}' \
      "$CREDS_DIR/$KEY_OWNER.json" > "$OL_HOME/$NETWORK/credentials.json" )
  # create_key — one `outlayer keys create`; sets NONCE and PK (the key, never printed).
  create_key() {
    local err
    NONCE=""; PK=""
    err=$(OUTLAYER_HOME="$OL_HOME" OUTLAYER_NETWORK="$NETWORK" outlayer keys create 2>&1 >/dev/null)
    NONCE=$(grep -oE 'Payment key created \(nonce: [0-9]+\)' <<<"$err" | grep -oE '[0-9]+' | tail -1)
    [[ -n "$NONCE" ]] && PK=$(OUTLAYER_HOME="$OL_HOME" OUTLAYER_NETWORK="$NETWORK" outlayer keys show "$NONCE" 2>/dev/null | tr -d ' \r\n')
    [[ -n "$NONCE" && "$PK" == "$KEY_OWNER:$NONCE:"* ]] && return 0
    warn "key not created (nonce '${NONCE}', key $( [[ -n $PK ]] && echo present || echo absent)): $(near_why "$err")"
    return 1
  }
  # A5/A6 need a nonce the coordinator has never seen. A key deleted without a
  # floor entry leaves its row at a nonce the contract can still hand out; a key
  # created on one is pinned and deleted at the end.
  FLOOR=$(view "$CONTRACT_ID" get_payment_key_nonce_floor "$(jq -nc --arg a "$KEY_OWNER" '{account_id:$a}')")
  PINNED=()
  FRESH=false
  cleanup_pinned() {
    local n out
    for n in "${PINNED[@]:-}"; do
      [[ -n "$n" ]] || continue
      out=$(call "$KEY_OWNER" "$CONTRACT_ID" delete_payment_key "$(jq -nc --argjson n "$n" '{nonce:$n}')" '1 yoctoNEAR')
      succeeded "$out" && note "teardown: the key stored at used nonce $n deleted on chain ($(tx_of "$out"))" \
        || warn "teardown: delete of nonce $n failed: $(near_why "$out")"
    done
  }
  for attempt in 1 2 3 4; do
    next=$(view "$CONTRACT_ID" get_next_payment_key_nonce "$(jq -nc --arg a "$KEY_OWNER" '{account_id:$a}')")
    prior=$(q "SELECT 1 FROM payment_keys WHERE owner = '$KEY_OWNER' AND nonce = ${next:-0}")
    create_key || break
    [[ "$NONCE" == "$next" ]] || warn "the CLI created nonce $NONCE, the contract said $next would be next"
    if [[ -z "$prior" ]]; then FRESH=true; break; fi
    note "nonce $NONCE carries the coordinator row of a key deleted without a floor entry — pinned, deleted at the end"
    PINNED+=("$NONCE")
  done
  if ! $FRESH; then
    fail "fixture: no payment key at a nonce the coordinator has never seen (A5/A6 not run)"
    cleanup_pinned
  else
    note "key $KEY_OWNER nonce $NONCE, never seen by the coordinator (length ${#PK})"
    ROW="SELECT initial_balance::text FROM payment_keys WHERE owner = '$KEY_OWNER' AND nonce = $NONCE AND deleted_at IS NULL"
    B0=$(wait_sql "$ROW" 0 30) && note "A4 (setup) the coordinator registered the key: initial_balance $B0" \
      || fail "setup: the coordinator has no payment_keys row for nonce $NONCE after 3 min (initial_balance '$B0')"

    # ── A5 top-up ──
    log "A5 ft_transfer_call $TOPUP → top_up_payment_key nonce $NONCE"
    out=$(call "$KEY_OWNER" "$TOKEN" ft_transfer_call \
      "$(jq -nc --arg r "$CONTRACT_ID" --arg a "$TOPUP" --argjson n "$NONCE" \
          '{receiver_id:$r, amount:$a, msg:({action:"top_up_payment_key", nonce:$n}|tojson)}')" '1 yoctoNEAR' '150.0 Tgas')
    TX=$(tx_of "$out")
    if [[ -z "$TX" ]]; then
      fail "A5 the transfer was not sent: $(why_of "$out")"
    else
      note "A5 tx $TX"
      logs=$(tx_logs "$TX" "$KEY_OWNER")
      DID=$(event_data_id_hex "$logs" TopUpPaymentKey)
      [[ "$DID" =~ ^[0-9a-f]{64}$ ]] && pass "A5 the transfer emitted TopUpPaymentKey (data_id $DID)" \
        || fail "A5 no TopUpPaymentKey event with a data_id in $TX"
      want=$(( B0 + TOPUP ))
      B1=$(wait_sql "$ROW" "$want" 30) \
        && pass "A5 coordinator payment_keys.initial_balance $B0 → $B1 (+$TOPUP)" \
        || fail "A5 coordinator initial_balance is '$B1', expected $want"
      pk_get /payment-keys/balance
      [[ "$HTTP" == 200 && "$(jq -r .initial_balance <<<"$BODY")" == "$want" && "$(jq -r .available <<<"$BODY")" == "$want" ]] \
        && pass "A5 GET /payment-keys/balance: initial_balance $want, available $want" \
        || fail "A5 /payment-keys/balance → HTTP $HTTP: $(jq -c '{initial_balance, available, spent}' <<<"$BODY" 2>/dev/null || short)"
      cb=$(wait_log "$TX" "$KEY_OWNER" "Payment key topped up: owner=$KEY_OWNER, nonce=$NONCE, amount=$TOPUP") \
        && pass "A5 the yield's callback committed: \"$cb\"" \
        || fail "A5 no 'Payment key topped up' callback log in $TX"
      if [[ "$DID" =~ ^[0-9a-f]{64}$ ]] && R=$(resume_tx TopUp resume_topup "$DID" "$TX" "Payment key topped up: owner=$KEY_OWNER, nonce=$NONCE"); then
        RTX=${R%%|*}; RESUME_FROM=${R#*|}
        rl=$(tx_logs "$RTX" "$OPERATOR")
        jq -e --arg s "TopUp yield resumed: data_id=$DID" 'any(.[]; . == $s)' <<<"$rl" >/dev/null \
          && pass "A5 the worker's resume_topup $RTX (found in the $RESUME_FROM) logs \"TopUp yield resumed: data_id=$DID\"" \
          || fail "A5 resume tx $RTX has no 'TopUp yield resumed: data_id=$DID': $(short "$rl")"
      else
        fail "A5 the worker's resume_topup for data_id $DID was found neither in $WORKER_CVM's log nor on chain"
      fi
    fi

    # ── A6 delete ──
    log "A6 delete_payment_key nonce $NONCE"
    out=$(call "$KEY_OWNER" "$CONTRACT_ID" delete_payment_key "$(jq -nc --argjson n "$NONCE" '{nonce:$n}')" '1 yoctoNEAR')
    TX=$(tx_of "$out")
    if [[ -z "$TX" ]]; then
      fail "A6 delete not sent: $(why_of "$out")"
    else
      note "A6 tx $TX"
      logs=$(tx_logs "$TX" "$KEY_OWNER")
      DID=$(event_data_id_hex "$logs" DeletePaymentKey)
      [[ "$DID" =~ ^[0-9a-f]{64}$ ]] && pass "A6 the delete emitted DeletePaymentKey (data_id $DID)" \
        || fail "A6 no DeletePaymentKey event with a data_id in $TX"
      d=$(wait_sql "SELECT (deleted_at IS NOT NULL)::text FROM payment_keys WHERE owner = '$KEY_OWNER' AND nonce = $NONCE ORDER BY created_at DESC LIMIT 1" true 30) \
        && pass "A6 coordinator payment_keys row of nonce $NONCE has deleted_at set" \
        || fail "A6 coordinator row deleted_at set: '$d'"
      live=$(q "SELECT count(*) FROM payment_keys WHERE owner = '$KEY_OWNER' AND nonce = $NONCE AND deleted_at IS NULL")
      [[ "$live" == 0 ]] && pass "A6 no live payment_keys row for nonce $NONCE" || fail "A6 $live live row(s) remain"
      refused=""
      for i in $(seq 1 12); do
        pk_get /payment-keys/balance
        [[ "$HTTP" == 401 ]] && { refused=yes; break; }
        sleep 10
      done
      [[ -n "$refused" ]] && pass "A6 GET /payment-keys/balance with the deleted key → 401: $(short "$BODY" 120)" \
        || fail "A6 the deleted key still answers /payment-keys/balance → HTTP $HTTP after 2 min"
      cb=$(wait_log "$TX" "$KEY_OWNER" "Payment key deleted: owner=$KEY_OWNER, nonce=$NONCE") \
        && pass "A6 the yield's callback committed: \"$cb\"" || fail "A6 no 'Payment key deleted' callback log in $TX"
      [[ -z "$(view "$CONTRACT_ID" get_secrets "$(jq -nc --arg o "$KEY_OWNER" --arg p "$NONCE" '{accessor:{System:"PaymentKey"}, profile:$p, owner:$o}')" | jq -r 'select(. != null) | 1' 2>/dev/null)" ]] \
        && note "A6 the contract holds no secret for the key any more" || note "A6 get_secrets still answers for the key (view shape may differ)"
      if [[ "$DID" =~ ^[0-9a-f]{64}$ ]] && R=$(resume_tx DeletePaymentKey resume_delete_payment_key "$DID" "$TX" "Payment key deleted: owner=$KEY_OWNER, nonce=$NONCE"); then
        RTX=${R%%|*}; RESUME_FROM=${R#*|}
        rl=$(tx_logs "$RTX" "$OPERATOR")
        jq -e --arg s "DeletePaymentKey yield resumed: data_id=$DID" 'any(.[]; . == $s)' <<<"$rl" >/dev/null \
          && pass "A6 the worker's resume_delete_payment_key $RTX (found in the $RESUME_FROM) logs \"DeletePaymentKey yield resumed: data_id=$DID\"" \
          || fail "A6 resume tx $RTX has no 'DeletePaymentKey yield resumed: data_id=$DID': $(short "$rl")"
      else
        fail "A6 the worker's resume_delete_payment_key for data_id $DID was found neither in $WORKER_CVM's log nor on chain"
      fi
    fi

    # ── R1 the deleted nonce is not handed out again ──
    log "R1 nonce $NONCE after its key was deleted"
    if [[ ! "$FLOOR" =~ ^[0-9]+$ ]]; then
      skip "R1: the contract has no get_payment_key_nonce_floor — it predates the nonce floor"
    else
      args=$(jq -nc --arg a "$KEY_OWNER" '{account_id:$a}')
      fl=$(view "$CONTRACT_ID" get_payment_key_nonce_floor "$args")
      nx=$(view "$CONTRACT_ID" get_next_payment_key_nonce "$args")
      [[ "$fl" =~ ^[0-9]+$ ]] && (( fl >= NONCE )) \
        && pass "R1 the floor of $KEY_OWNER ($fl) holds the deleted nonce $NONCE" \
        || fail "R1 the floor of $KEY_OWNER is '$fl', below the deleted nonce $NONCE"
      [[ "$nx" =~ ^[0-9]+$ ]] && (( nx > NONCE )) \
        && pass "R1 get_next_payment_key_nonce answers $nx, past the deleted $NONCE" \
        || fail "R1 get_next_payment_key_nonce answers '$nx' — the deleted nonce $NONCE (or below) again"
      out=$(call "$KEY_OWNER" "$CONTRACT_ID" store_secrets \
        "$(jq -nc --arg n "$NONCE" '{accessor:{System:"PaymentKey"}, profile:$n, encrypted_secrets_base64:"cjE=", access:"AllowAll"}')" '0.1 NEAR')
      if succeeded "$out"; then
        fail "R1 a payment key was stored at deleted nonce $NONCE ($(tx_of "$out")) — the coordinator's deleted row is now reachable again"
        PINNED+=("$NONCE")
      elif grep -q 'has already been used' <<<"$out"; then
        pass "R1 a store at deleted nonce $NONCE is refused: $(near_why "$out")"
      else
        fail "R1 a store at deleted nonce $NONCE failed, but not for the used nonce: $(near_why "$out")"
      fi
    fi
    cleanup_pinned
  fi
  PK=""
fi

# ══ wallet policy: A8, A9, A10 ═══════════════════════════════════════════════
if [[ -z "$ONLY" || "$ONLY" == wallet ]]; then
  W_PRIV=$(jq -r '.private_key' "$CREDS_DIR/$WALLET_OWNER.json")
  SEED="sysev-$TAG"
  log "fixture: wallet ($WALLET_OWNER, seed $SEED)"
  wapi "$SEED" GET "/wallet/v1/address?chain=near"
  WID=$(jq -r '.wallet_id // empty' <<<"$BODY" 2>/dev/null); ADDR=$(jq -r '.address // empty' <<<"$BODY" 2>/dev/null)
  if [[ -z "$WID" || -z "$ADDR" ]]; then
    fail "fixture: /wallet/v1/address → HTTP $HTTP: $(short)"
  else
    note "wallet $WID, account $ADDR"
    near --quiet tokens "$WALLET_OWNER" send-near "$ADDR" "$FUND NEAR" network-config "$NETWORK" \
      sign-with-legacy-keychain send >/dev/null 2>&1 || warn "funding $ADDR may have failed"
    POLROW="SELECT COALESCE(policy_json::text, 'NULL') || '|' || frozen::text FROM wallet_accounts WHERE wallet_id = '$WID'"
    note "coordinator copy before any policy: $(q "$POLROW" | head -c 120)"

    PUBKEY=""
    # store_policy <policy-json> — encrypt + sign through the coordinator, store
    # on chain as the owner. Sets PUBKEY, STORE_TX.
    store_policy() {
      local body encb64 sig pub args out
      body=$(jq -nc --arg w "$WID" --argjson p "$1" '$p + {wallet_id:$w}')
      wapi "$SEED" POST /wallet/v1/encrypt-policy "$body"
      encb64=$(jq -r '.encrypted_base64 // empty' <<<"$BODY" 2>/dev/null)
      [[ -n "$encb64" ]] || { warn "encrypt-policy → HTTP $HTTP: $(short)"; return 1; }
      wapi "$SEED" POST /wallet/v1/sign-policy "$(jq -nc --arg e "$encb64" --arg c "$WALLET_OWNER" '{encrypted_data:$e, caller:$c}')"
      sig=$(jq -r '.signature_hex // empty' <<<"$BODY" 2>/dev/null); pub=$(jq -r '.public_key_hex // empty' <<<"$BODY" 2>/dev/null)
      [[ -n "$sig" && -n "$pub" ]] || { warn "sign-policy → HTTP $HTTP: $(short)"; return 1; }
      PUBKEY="ed25519:$pub"
      args=$(jq -nc --arg k "$PUBKEY" --arg e "$encb64" --arg s "$sig" '{wallet_pubkey:$k, encrypted_data:$e, wallet_signature:$s}')
      out=$(call "$WALLET_OWNER" "$CONTRACT_ID" store_wallet_policy "$args" '0.1 NEAR')
      STORE_TX=$(tx_of "$out")
      succeeded "$out" || { warn "store_wallet_policy: $(why_of "$out")"; return 1; }
    }
    list_of() { q "SELECT COALESCE((policy_json->'rules'->'addresses'->'list')::text, 'NULL') FROM wallet_accounts WHERE wallet_id = '$WID'"; }
    POL1=$(jq -nc --arg a "$WALLET_OWNER" '{rules:{transaction_types:["transfer","delete"], addresses:{mode:"none", list:[$a]}}}')
    POL2=$(jq -nc --arg a "$WALLET_OWNER" --arg b "$KEY_OWNER" '{rules:{transaction_types:["transfer","delete"], addresses:{mode:"none", list:[$a,$b]}}}')
    L1=$(jq -c '.rules.addresses.list' <<<"$POL1"); L2=$(jq -c '.rules.addresses.list' <<<"$POL2")

    # ── A8 ──
    log "A8 store_wallet_policy v1, then v2 — the coordinator's copy follows the chain"
    if store_policy "$POL1"; then
      note "A8 v1 stored on chain: $STORE_TX (wallet pubkey $PUBKEY)"
      got=""
      for i in $(seq 1 30); do got=$(list_of | tr -d ' '); [[ "$got" == "$L1" ]] && break; sleep 6; done
      [[ "$got" == "$L1" ]] && pass "A8 v1: wallet_accounts.policy_json addresses.list = $got" \
        || fail "A8 v1: the coordinator's copy reads '$got', expected $L1"
      n1=$(coord_count "Policy sync complete: wallet=$WID")
      if store_policy "$POL2"; then
        note "A8 v2 stored on chain: $STORE_TX"
        got=""
        for i in $(seq 1 30); do got=$(list_of | tr -d ' '); [[ "$got" == "$L2" ]] && break; sleep 6; done
        [[ "$got" == "$L2" ]] && pass "A8 v2 replaced the non-null copy with no wallet call in between: addresses.list = $got" \
          || fail "A8 v2: the coordinator's copy reads '$got', expected $L2"
        n2=$(coord_count "Policy sync complete: wallet=$WID"); nl=$(coord_count "Lazy-synced policy for wallet=$WID")
        (( n2 > n1 )) && [[ "$nl" == 0 ]] \
          && pass "A8 coordinator log: 'Policy sync complete: wallet=$WID' $n1 → $n2 (the worker's /internal/wallet-policy-sync), 'Lazy-synced' 0" \
          || fail "A8 coordinator log: policy sync lines $n1 → $n2, lazy-sync lines $nl"
      else
        fail "A8 v2 not stored"
      fi
    else
      fail "A8 v1 not stored"
    fi

    # ── A9 ──
    log "A9 freeze_wallet → a transfer refused; unfreeze_wallet → allowed"
    FROW="SELECT frozen::text FROM wallet_accounts WHERE wallet_id = '$WID'"
    if [[ -n "$PUBKEY" ]]; then
      out=$(call "$WALLET_OWNER" "$CONTRACT_ID" freeze_wallet "$(jq -nc --arg k "$PUBKEY" '{wallet_pubkey:$k}')" '0 NEAR')
      if succeeded "$out"; then
        f=$(wait_sql "$FROW" true 30) && pass "A9 after freeze_wallet ($(tx_of "$out")): wallet_accounts.frozen = true" \
          || fail "A9 after freeze_wallet: frozen reads '$f'"
        wapi "$SEED" POST /wallet/v1/transfer "$(jq -nc --arg t "$KEY_OWNER" --arg a "$SEND_YOCTO" '{chain:"near", to:$t, amount:$a}')"
        [[ "$HTTP" == 403 && "$(jq -r .error <<<"$BODY" 2>/dev/null)" == wallet_frozen ]] \
          && pass "A9 transfer while frozen → 403 wallet_frozen: $(short "$BODY" 120)" \
          || fail "A9 transfer while frozen → HTTP $HTTP: $(short)"
        out=$(call "$WALLET_OWNER" "$CONTRACT_ID" unfreeze_wallet "$(jq -nc --arg k "$PUBKEY" '{wallet_pubkey:$k}')" '0 NEAR')
        if succeeded "$out"; then
          f=$(wait_sql "$FROW" false 30) && pass "A9 after unfreeze_wallet ($(tx_of "$out")): wallet_accounts.frozen = false" \
            || fail "A9 after unfreeze_wallet: frozen reads '$f'"
          wapi "$SEED" POST /wallet/v1/transfer "$(jq -nc --arg t "$KEY_OWNER" --arg a "$SEND_YOCTO" '{chain:"near", to:$t, amount:$a}')"
          [[ "$HTTP" == 200 ]] && pass "A9 the same transfer after unfreeze → 200: $(jq -c '{request_id, status}' <<<"$BODY" 2>/dev/null)" \
            || fail "A9 transfer after unfreeze → HTTP $HTTP: $(short)"
        else
          fail "A9 unfreeze_wallet: $(why_of "$out")"
        fi
      else
        fail "A9 freeze_wallet: $(why_of "$out")"
      fi
    else
      skip "A9 no wallet pubkey (A8's policy was not stored)"
    fi

    # Sweep the wallet account back while the policy still allows `delete`.
    wapi "$SEED" POST /wallet/v1/delete "$(jq -nc --arg b "$WALLET_OWNER" '{beneficiary:$b, chain:"near"}')"
    note "sweep: $ADDR → $WALLET_OWNER: HTTP $HTTP $(jq -c '{status}' <<<"$BODY" 2>/dev/null)"

    # ── A10 ──
    log "A10 delete_wallet_policy — the coordinator drops its copy"
    if [[ -n "$PUBKEY" ]]; then
      before=$(q "$POLROW" | head -c 40)
      out=$(call "$WALLET_OWNER" "$CONTRACT_ID" delete_wallet_policy "$(jq -nc --arg k "$PUBKEY" '{wallet_pubkey:$k}')" '0 NEAR')
      if succeeded "$out"; then
        r=$(wait_sql "$POLROW" "NULL|false" 30) \
          && pass "A10 after delete_wallet_policy ($(tx_of "$out")): policy_json NULL, frozen false (was '${before}…')" \
          || fail "A10 the coordinator's copy after the delete reads '$(head -c 80 <<<"$r")'"
        nd=$(coord_count "Policy deleted sync: wallet=$WID")
        (( nd >= 1 )) && pass "A10 coordinator log: 'Policy deleted sync: wallet=$WID' ×$nd" \
          || fail "A10 no 'Policy deleted sync: wallet=$WID' in the coordinator log"
      else
        fail "A10 delete_wallet_policy: $(why_of "$out")"
      fi
    else
      skip "A10 no policy was stored"
    fi
  fi
  W_PRIV=""
fi

verdict "system_event_effects_e2e"
