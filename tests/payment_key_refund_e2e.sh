#!/usr/bin/env bash
#
# Money back to its owner, live on TESTNET: `withdraw_balance` on the
# stablecoin balance, and a payment key's refund — close, a day, claim
# (.idea/_todo/dao/user-withdrawals-plan.md §2, §3, §6).
#
# Two phases, because a claim is accepted 24 h after the close and the contract
# will not be hurried:
#
#   --apply            phase 1, today:
#     W1   deposit_balance $0.05 → get_user_stablecoin_balance +50000
#     W2   withdraw_balance 30000 → balance −30000, the token balance +30000
#     W3   withdraw_balance below $0.01 / over the balance / without a yocto → refused
#     W4   deposit_balance below $0.01 → the transfer comes back (token balance unchanged)
#     R1   a fresh key: ledger {0, 0, 0}, not closing
#     R2   top-up $0.05 → ledger user_funded 50000, refundable_cap 50000
#     R3   one HTTPS call with the key → settled, spent > 0
#     R4   close_payment_key → tx ok; coordinator deleted_at set; ledger closing_since
#          set, claimable_at = since + 24 h; closing count 1; the secret still on chain
#     R5   a top-up on the closing key → refused, the transfer comes back
#     R6   claim_payment_key_refund now → refused "can be claimed from"
#     R7   close again → refused "already closing"
#     G1   a second fresh key, admin grant $0.05 (scripts/.env), close → closing, cap 0
#     Prints the two nonces for phase 2.
#
#   --claim <nonce> [--grant <nonce>]   phase 2, a day later:
#     C1   claim → tx ok, the returned value = paid; logs "Payment key refunded"
#     C2   the token balance of the owner rose by paid; paid = min(quote, cap)
#     C3   coordinator payment_key_refunds row = the quote; payment_keys.initial_balance = spent
#     C4   on chain: ledger gone, secret gone, closing count 0, nonce floor ≥ nonce
#     C5   (--grant) the grant key claims 0: "refund capped" logged, key gone, no transfer
#
# Accounts: KEY_OWNER (default outlayer-alice.testnet) signs everything and must
# hold the stablecoin the contract names (get_payment_token_contract) and be
# registered on it. Secrets: the payment key stays in a private OUTLAYER_HOME and
# is sent on curl's stdin; the admin bearer is read from one line of scripts/.env
# and never printed. RPC keyed through tests/lib/rpc.sh (via hos_common.sh).
#
# Needs: near-cli (legacy keychain key of KEY_OWNER), outlayer CLI, jq, curl,
# PSQL_CMD for the coordinator rows (without it the DB checks are SKIPPED).
#
# Run:
#   PSQL_CMD=… ./tests/payment_key_refund_e2e.sh                 # dry run
#   PSQL_CMD=… ./tests/payment_key_refund_e2e.sh --apply         # phase 1
#   PSQL_CMD=… ./tests/payment_key_refund_e2e.sh --claim 7 --grant 8   # phase 2

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/lib/hos_common.sh"   # NETWORK, CONTRACT_ID, keyed RPC_URL, pass/fail/skip/verdict, sql, throttle

MODE=dry; CLAIM_NONCE=""; GRANT_NONCE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply) MODE=apply ;;
    --claim) MODE=claim; CLAIM_NONCE="${2:?--claim needs a nonce}"; shift ;;
    --grant) GRANT_NONCE="${2:?--grant needs a nonce}"; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

KEY_OWNER="${KEY_OWNER:-outlayer-alice.testnet}"
CONNECTORS="${CONNECTORS:-connectors.outlayer.$NETWORK}"
PROJECT="${PROJECT:-$CONNECTORS/connector-probe}"
AMOUNT="${AMOUNT:-50000}"          # $0.05
WITHDRAW="${WITHDRAW:-30000}"      # $0.03
ENV_FILE="${ENV_FILE:-$REPO_ROOT/scripts/.env}"
CREDS_DIR="$HOME/.near-credentials/$NETWORK"
DAY_NS=$((24 * 60 * 60 * 1000000000))

# Money moves here: testnet only, whatever near-cli or the CLI default to.
[[ "$NETWORK" == testnet ]] || { echo "✗ NETWORK=$NETWORK: this suite moves money and runs on testnet only" >&2; exit 2; }

RUN_TMP=$(mktemp -d -t pk_refund.XXXXXX); chmod 700 "$RUN_TMP"
OL_HOME="$RUN_TMP/ol"; mkdir -p "$OL_HOME/$NETWORK"
# The private OUTLAYER_HOME holds a copy of the signing key: gone on any exit,
# a signal included.
trap 'rm -rf "$RUN_TMP"' EXIT INT TERM HUP

ADMIN_TOKEN=""
[[ -r "$ENV_FILE" ]] && ADMIN_TOKEN=$(grep '^ADMIN_BEARER_TOKEN_TESTNET=' "$ENV_FILE" | head -1 | cut -d= -f2- | tr -d "\"'")

# ── chain ────────────────────────────────────────────────────────────────────

rpc_post() {
  printf 'url = "%s"\n' "$RPC_URL" | command curl -sS --max-time 45 -K - -X POST \
    -H 'Content-Type: application/json' --data-binary "$1" 2>/dev/null
}
view() { # view <contract> <method> <args-json>
  rpc_post "$(jq -nc --arg m "$2" --arg g "$(printf '%s' "$3" | base64 | tr -d '\n')" --arg c "$1" \
    '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"call_function",finality:"final",account_id:$c,method_name:$m,args_base64:$g}}')" \
    | jq -r 'if .result.result then (.result.result | implode) else empty end' 2>/dev/null
}
call() { # call <signer> <contract> <method> <args-json> <deposit> [gas]
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
# near-cli's transport errors quote the keyed RPC URL: only a contract panic is printed.
why_of() {
  local m
  m=$(grep -oE 'Smart contract panicked: [^"\\]*|panicked at [^"\\]*|ExecutionError\("[^"]*' <<<"$1" | grep -viE 'https?:|apikey' | head -2 | tr '\n' ' ' | head -c 300)
  [[ -n "$m" ]] && printf '%s' "$m" || printf 'near-cli failed without a contract panic (output withheld)'
}
tx_logs() { # tx_logs <tx> <sender> — every log of the transaction's receipts, a JSON array
  local r i
  for i in 1 2 3 4 5 6; do
    r=$(rpc_post "$(jq -nc --arg t "$1" --arg s "$2" '{jsonrpc:"2.0",id:1,method:"tx",params:{tx_hash:$t,sender_account_id:$s,wait_until:"FINAL"}}')")
    jq -e '.result' <<<"$r" >/dev/null 2>&1 && {
      jq -c '[.result.transaction_outcome.outcome.logs[]?, .result.receipts_outcome[]?.outcome.logs[]?]' <<<"$r"; return 0; }
    sleep 5
  done
  echo '[]'
}
tx_value() { # tx_value <tx> <sender> — the transaction's SuccessValue, decoded
  rpc_post "$(jq -nc --arg t "$1" --arg s "$2" '{jsonrpc:"2.0",id:1,method:"tx",params:{tx_hash:$t,sender_account_id:$s,wait_until:"FINAL"}}')" \
    | jq -r '.result.status.SuccessValue // empty' | base64 -d 2>/dev/null
}
has_log() { jq -e --arg s "$2" 'any(.[]; contains($s))' <<<"$1" >/dev/null 2>&1; }
# A refusal inside ft_on_transfer is a FAILED receipt: its text is in the receipt's
# status.Failure, not in a log. tx_failures <tx> <sender> — every failure text, one JSON array.
tx_failures() {
  local r i
  for i in 1 2 3 4 5 6; do
    r=$(rpc_post "$(jq -nc --arg t "$1" --arg s "$2" '{jsonrpc:"2.0",id:1,method:"tx",params:{tx_hash:$t,sender_account_id:$s,wait_until:"FINAL"}}')")
    jq -e '.result' <<<"$r" >/dev/null 2>&1 && {
      jq -c '[.result.receipts_outcome[]?.outcome.status.Failure? // empty | tojson]' <<<"$r"; return 0; }
    sleep 5
  done
  echo '[]'
}
has_failure() { jq -e --arg s "$2" 'any(.[]; contains($s))' <<<"$1" >/dev/null 2>&1; }
ledger_shape() { ledger "$1" | jq -c '{user_funded,refunded,refundable_cap,closing_since,claimable_at}' 2>/dev/null; }
ledger() { view "$CONTRACT_ID" get_payment_key_refund_ledger "$(jq -nc --arg o "$KEY_OWNER" --argjson n "$1" '{owner:$o, nonce:$n}')"; }
cap_of() { ledger "$1" | jq -c '.refundable_cap // empty'; }
flight() { view "$CONTRACT_ID" get_payment_key_flight "$(jq -nc --arg o "$KEY_OWNER" --argjson n "$1" '{owner:$o, nonce:$n}')"; }
closing_count() { view "$CONTRACT_ID" get_closing_payment_key_count "$(jq -nc --arg o "$KEY_OWNER" '{owner:$o}')"; }
user_balance() { view "$CONTRACT_ID" get_user_stablecoin_balance "$(jq -nc --arg a "$KEY_OWNER" '{account_id:$a}')" | tr -d '"'; }
token_balance() { view "$TOKEN" ft_balance_of "$(jq -nc --arg a "$KEY_OWNER" '{account_id:$a}')" | tr -d '"'; }
secret_exists() { # secret_exists <nonce>
  local r; r=$(view "$CONTRACT_ID" get_secrets "$(jq -nc --argjson n "$1" --arg o "$KEY_OWNER" '{accessor:{System:"PaymentKey"}, profile:($n|tostring), owner:$o}')")
  [[ -n "$r" && "$r" != "null" ]]
}
ft_call() { # ft_call <amount> <msg-json> — ft_transfer_call to the contract; prints near-cli output
  call "$KEY_OWNER" "$TOKEN" ft_transfer_call \
    "$(jq -nc --arg r "$CONTRACT_ID" --arg a "$1" --arg m "$2" '{receiver_id:$r, amount:$a, msg:$m}')" '1 yoctoNEAR' '150.0 Tgas'
}
wait_eq() { # wait_eq <command…> — until the command's output equals $EXPECT (≤ 3 min)
  local i v
  for i in $(seq 1 30); do v=$("$@"); [[ "$v" == "$EXPECT" ]] && { printf '%s' "$v"; return 0; }; sleep 6; done
  printf '%s' "$v"; return 1
}
q() { sql "$1" 2>/dev/null; }
wait_sql() { # wait_sql <statement> <expected> [tries]
  local i v=""
  for i in $(seq 1 "${3:-30}"); do v=$(q "$1"); [[ "$v" == "$2" ]] && { printf '%s' "$v"; return 0; }; sleep 6; done
  printf '%s' "$v"; return 1
}
req_pk() { # req_pk <METHOD> <path> [body] — with the payment key from $PK on stdin
  local out; out=$(mktemp -t pk_refund_b.XXXXXX)
  local -a a=(-sS -o "$out" -w '%{http_code}' --max-time 150 -X "$1" -H @-)
  [[ -n "${3:-}" ]] && a+=(-H 'Content-Type: application/json' --data-binary "$3")
  throttle
  HTTP=$(printf 'X-Payment-Key: %s\n' "$PK" | command curl "${a[@]}" "$COORDINATOR_URL$2" 2>/dev/null)
  BODY=$(tr -d '\n' < "$out"); rm -f "$out"
}
req_admin() { # req_admin <METHOD> <path> [body]
  local out; out=$(mktemp -t pk_refund_a.XXXXXX)
  local -a a=(-sS -o "$out" -w '%{http_code}' --max-time 60 -X "$1" -H @-)
  [[ -n "${3:-}" ]] && a+=(-H 'Content-Type: application/json' --data-binary "$3")
  throttle
  HTTP=$(printf 'Authorization: Bearer %s\n' "$ADMIN_TOKEN" | command curl "${a[@]}" "$COORDINATOR_URL$2" 2>/dev/null)
  BODY=$(tr -d '\n' < "$out"); rm -f "$out"
}
short() { head -c "${2:-240}" <<<"${1:-$BODY}"; }

# create_key — one `outlayer keys create` under the private OUTLAYER_HOME; sets NONCE and PK.
create_key() {
  local err
  NONCE=""; PK=""
  err=$(OUTLAYER_HOME="$OL_HOME" OUTLAYER_NETWORK="$NETWORK" outlayer keys create 2>&1 >/dev/null)
  NONCE=$(grep -oE 'Payment key created \(nonce: [0-9]+\)' <<<"$err" | grep -oE '[0-9]+' | tail -1)
  [[ -n "$NONCE" ]] && PK=$(OUTLAYER_HOME="$OL_HOME" OUTLAYER_NETWORK="$NETWORK" outlayer keys show "$NONCE" 2>/dev/null | tr -d ' \r\n')
  [[ -n "$NONCE" && "$PK" == "$KEY_OWNER:$NONCE:"* ]] && return 0
  warn "key not created (nonce '${NONCE}', key $( [[ -n $PK ]] && echo present || echo absent)): $(why_of "$err")"
  return 1
}

# ── preflight ────────────────────────────────────────────────────────────────

log "payment_key_refund_e2e — $NETWORK, $MODE${CLAIM_NONCE:+ nonce $CLAIM_NONCE}${GRANT_NONCE:+, grant nonce $GRANT_NONCE}"
note "RPC: $(rpc_url_public)"
note "coordinator: ${COORDINATOR_URL#*://}; key owner $KEY_OWNER; project $PROJECT"
for tool in jq curl near outlayer; do command -v "$tool" >/dev/null || { echo "✗ missing $tool" >&2; exit 1; }; done
[[ -f "$CREDS_DIR/$KEY_OWNER.json" ]] || { echo "✗ no legacy-keychain key for $KEY_OWNER" >&2; exit 1; }
TOKEN=$(view "$CONTRACT_ID" get_payment_token_contract '{}' | jq -r '. // empty' 2>/dev/null)
[[ -n "$TOKEN" ]] || { echo "✗ the contract names no payment token" >&2; exit 1; }
note "payment token: $TOKEN; storage version $(view "$CONTRACT_ID" get_storage_version '{}')"
[[ "$(view "$CONTRACT_ID" get_storage_version '{}')" == '"13"' ]] || { echo "✗ the contract is not at storage version 13: the refund methods are not deployed" >&2; exit 1; }
if sql_alive; then note "coordinator DB: reachable"; else warn "PSQL_CMD unset or not answering: the coordinator-row checks will be SKIPPED"; fi
[[ -n "$ADMIN_TOKEN" ]] && note "admin bearer: present (length ${#ADMIN_TOKEN})" || warn "no ADMIN_BEARER_TOKEN_TESTNET in $ENV_FILE: G1 (the grant key) will be SKIPPED"

if [[ "$MODE" == dry ]]; then
  sed -n '3,/^$/p' "$0" >&2
  echo "  Pass --apply (phase 1) or --claim <nonce> (phase 2)." >&2
  exit 0
fi

( umask 077; jq --arg a "$KEY_OWNER" --arg c "$CONTRACT_ID" \
    '{account_id:$a, public_key, private_key, contract_id:$c, auth_type:"near_key"}' \
    "$CREDS_DIR/$KEY_OWNER.json" > "$OL_HOME/$NETWORK/credentials.json" )

# ══ phase 1 ═══════════════════════════════════════════════════════════════════
if [[ "$MODE" == apply ]]; then
  # Keys of earlier runs may still be closing: counts are relative to now.
  C0=$(closing_count); note "closing keys of $KEY_OWNER before this run: $C0"
  # ── W: the stablecoin balance ──
  log "W1 deposit_balance $AMOUNT"
  B0=$(user_balance); T0=$(token_balance)
  note "before: contract balance $B0, token balance $T0"
  out=$(ft_call "$AMOUNT" '{"action":"deposit_balance"}')
  succeeded "$out" && pass "W1 deposit_balance sent ($(tx_of "$out"))" || fail "W1 deposit_balance: $(why_of "$out")"
  EXPECT=$((B0 + AMOUNT)); b=$(wait_eq user_balance) && pass "W1 get_user_stablecoin_balance $B0 → $b" || fail "W1 balance is '$b', expected $EXPECT"

  log "W2 withdraw_balance $WITHDRAW"
  T1=$(token_balance)
  out=$(call "$KEY_OWNER" "$CONTRACT_ID" withdraw_balance "$(jq -nc --arg a "$WITHDRAW" '{amount:$a}')" '1 yoctoNEAR')
  if succeeded "$out"; then
    pass "W2 withdraw_balance sent ($(tx_of "$out"))"
    EXPECT=$((B0 + AMOUNT - WITHDRAW)); b=$(wait_eq user_balance) && pass "W2 contract balance → $b (−$WITHDRAW)" || fail "W2 contract balance is '$b', expected $EXPECT"
    EXPECT=$((T1 + WITHDRAW)); t=$(wait_eq token_balance) && pass "W2 token balance → $t (+$WITHDRAW)" || fail "W2 token balance is '$t', expected $EXPECT"
    logs=$(tx_logs "$(tx_of "$out")" "$KEY_OWNER")
    has_log "$logs" "Balance withdrawn: $KEY_OWNER received $WITHDRAW" && pass "W2 callback logged the transfer" || fail "W2 no 'Balance withdrawn' log"
    [[ "$(view "$CONTRACT_ID" is_withdrawing "$(jq -nc --arg a "$KEY_OWNER" '{account:$a}')")" == false ]] && pass "W2 is_withdrawing false after the callback" || fail "W2 is_withdrawing still true"
  else
    fail "W2 withdraw_balance: $(why_of "$out")"
  fi

  log "W3 refusals"
  out=$(call "$KEY_OWNER" "$CONTRACT_ID" withdraw_balance '{"amount":"9999"}' '1 yoctoNEAR')
  ! succeeded "$out" && grep -q 'Minimum withdrawal' <<<"$out" && pass "W3 below \$0.01 refused: $(why_of "$out")" || fail "W3 below-minimum not refused as expected: $(why_of "$out")"
  out=$(call "$KEY_OWNER" "$CONTRACT_ID" withdraw_balance "$(jq -nc --arg a "$(( B0 + AMOUNT + 1 ))" '{amount:$a}')" '1 yoctoNEAR')
  ! succeeded "$out" && grep -q 'Insufficient stablecoin balance' <<<"$out" && pass "W3 over the balance refused" || fail "W3 over-balance not refused as expected: $(why_of "$out")"
  out=$(call "$KEY_OWNER" "$CONTRACT_ID" withdraw_balance "$(jq -nc --arg a "$WITHDRAW" '{amount:$a}')" '0 NEAR')
  ! succeeded "$out" && grep -q '1 yoctoNEAR' <<<"$out" && pass "W3 without a yocto refused" || fail "W3 no-yocto not refused as expected: $(why_of "$out")"

  log "W4 deposit_balance below \$0.01 comes back"
  T2=$(token_balance)
  out=$(ft_call 9999 '{"action":"deposit_balance"}')
  TX=$(tx_of "$out")
  if [[ -n "$TX" ]]; then
    fails=$(tx_failures "$TX" "$KEY_OWNER")
    has_failure "$fails" "Minimum deposit is" && pass "W4 the contract refused the deposit (receipt failed with 'Minimum deposit')" || fail "W4 no 'Minimum deposit' refusal in $TX: $(short "$fails")"
    EXPECT=$T2; t=$(wait_eq token_balance) && pass "W4 token balance unchanged ($t): the transfer came back" || fail "W4 token balance '$t', expected $EXPECT"
  else
    fail "W4 the transfer was not sent: $(why_of "$out")"
  fi

  # ── R: a payment key's refund, phase 1 ──
  log "R1 fixture: a fresh payment key of $KEY_OWNER"
  if ! create_key; then
    fail "R1 no key: R2–R7 not run"
  else
    note "key nonce $NONCE (length ${#PK})"
    # The CLI returns on the optimistic outcome; the view reads at final a few
    # seconds later.
    EXPECT='{"user_funded":"0","refunded":"0","refundable_cap":"0","closing_since":null,"claimable_at":null}'
    l=$(wait_eq ledger_shape "$NONCE") && pass "R1 a new key's ledger is zero and not closing (created with the key)" || fail "R1 ledger of the new key: $l"
    if sql_alive; then
      wait_sql "SELECT initial_balance FROM payment_keys WHERE owner = '$KEY_OWNER' AND nonce = $NONCE AND deleted_at IS NULL" 0 30 >/dev/null \
        && pass "R1 the coordinator registered the key" || fail "R1 no coordinator row for nonce $NONCE after 3 min"
    fi

    log "R2 top-up $AMOUNT"
    out=$(ft_call "$AMOUNT" "$(jq -nc --argjson n "$NONCE" '{action:"top_up_payment_key", nonce:$n}|tojson' | jq -r .)")
    TX=$(tx_of "$out")
    [[ -n "$TX" ]] && pass "R2 top-up sent ($TX)" || fail "R2 top-up not sent: $(why_of "$out")"
    EXPECT="\"$AMOUNT\""; c=$(wait_eq cap_of "$NONCE") \
      && pass "R2 ledger refundable_cap $c, user_funded counted the top-up" || fail "R2 refundable_cap is '$c' (expected \"$AMOUNT\"): the top-up callback did not count"

    log "R3 one HTTPS call with the key"
    for i in 1 2 3 4 5 6; do
      req_pk POST "/call/$PROJECT" '{"input":{"operation":"ping"}}'
      [[ "$HTTP" == 200 ]] && break
      sleep 10   # the coordinator credits the key after the worker's resume
    done
    [[ "$HTTP" == 200 ]] && pass "R3 call → 200 ($(jq -r '.status // empty' <<<"$BODY"))" || fail "R3 call → HTTP $HTTP: $(short)"
    if sql_alive; then
      for i in $(seq 1 20); do
        n=$(q "SELECT count(*) FROM https_calls WHERE owner = '$KEY_OWNER' AND nonce = $NONCE AND status NOT IN ('completed','failed')"); [[ "$n" == 0 ]] && break; sleep 3
      done
      SPENT=$(q "SELECT COALESCE(spent::text,'0') FROM payment_key_balances WHERE owner = '$KEY_OWNER' AND nonce = $NONCE")
      [[ -n "$SPENT" && "$SPENT" != 0 ]] && pass "R3 settled: spent $SPENT" || warn "R3 spent is '$SPENT' (a free ping?): the refund will be the whole top-up"
    fi

    # A second top-up, and a close sent right behind it: the key cannot be
    # closed while the top-up is in flight — or the worker was faster and the
    # close goes through. Either way the chain, the ledger and the coordinator
    # row must agree afterwards.
    log "R2b a second top-up, then close while it may still be in flight"
    out=$(ft_call "$AMOUNT" "$(jq -nc --argjson n "$NONCE" '{action:"top_up_payment_key", nonce:$n}|tojson' | jq -r .)")
    TX=$(tx_of "$out")
    [[ -n "$TX" ]] && pass "R2b second top-up sent ($TX)" || fail "R2b second top-up not sent: $(why_of "$out")"
    out=$(call "$KEY_OWNER" "$CONTRACT_ID" close_payment_key "$(jq -nc --argjson n "$NONCE" '{nonce:$n}')" '1 yoctoNEAR')
    if succeeded "$out"; then
      note "R2b the top-up had settled first: the close went through ($(tx_of "$out")) — R4 reads it as already closing"
      CLOSED_EARLY=true
    elif grep -q 'in flight' <<<"$out"; then
      pass "R2b close refused while the top-up is in flight: $(why_of "$out" | head -c 160)"
      CLOSED_EARLY=false
    else
      fail "R2b close neither succeeded nor was refused as in flight: $(why_of "$out")"
      CLOSED_EARLY=false
    fi
    TOTAL=$(( AMOUNT * 2 ))
    EXPECT="\"$TOTAL\""; c=$(wait_eq cap_of "$NONCE") \
      && pass "R2b ledger refundable_cap $c: both top-ups counted, whichever way the close landed" || fail "R2b refundable_cap is '$c' (expected \"$TOTAL\")"
    [[ "$(flight "$NONCE" | jq -r '.top_ups_in_flight // 0')" == 0 ]] && pass "R2b nothing in flight once answered" || fail "R2b flight: $(flight "$NONCE")"
    if sql_alive; then
      b=$(wait_sql "SELECT initial_balance FROM payment_keys WHERE owner = '$KEY_OWNER' AND nonce = $NONCE" "$TOTAL" 20) \
        && pass "R2b coordinator initial_balance $b agrees with the chain" || fail "R2b coordinator initial_balance '$b', expected $TOTAL"
    fi

    log "R4 close_payment_key $NONCE"
    if [[ "${CLOSED_EARLY:-false}" == true ]]; then
      out=""; TX=""
      note "R4 closed in R2b already; checking the state it left"
    else
      out=$(call "$KEY_OWNER" "$CONTRACT_ID" close_payment_key "$(jq -nc --argjson n "$NONCE" '{nonce:$n}')" '1 yoctoNEAR')
      TX=$(tx_of "$out")
    fi
    if [[ "${CLOSED_EARLY:-false}" == true ]] || succeeded "$out"; then
      [[ -n "$TX" ]] && pass "R4 close sent and resumed ($TX)"
      if [[ -n "$TX" ]]; then
        logs=$(tx_logs "$TX" "$KEY_OWNER")
        has_log "$logs" "Payment key closing: owner=$KEY_OWNER, nonce=$NONCE" && pass "R4 the callback marked the key closing" || fail "R4 no 'Payment key closing' log in $TX"
      fi
      l=$(ledger "$NONCE")
      since=$(jq -r '.closing_since // empty' <<<"$l"); at=$(jq -r '.claimable_at // empty' <<<"$l")
      [[ -n "$since" && "$at" == "$((since + DAY_NS))" ]] && pass "R4 ledger closing_since $since, claimable_at = since + 24 h" || fail "R4 ledger after close: $(short "$l")"
      [[ "$(jq -r .refundable_cap <<<"$l")" == "$TOTAL" ]] && pass "R4 cap still $TOTAL" || fail "R4 cap $(jq -r .refundable_cap <<<"$l")"
      [[ "$(closing_count)" == $(( C0 + 1 )) ]] && pass "R4 closing count $(( C0 + 1 ))" || fail "R4 closing count $(closing_count), expected $(( C0 + 1 ))"
      secret_exists "$NONCE" && pass "R4 the secret stays on chain until the claim" || fail "R4 the secret is gone after the close"
      if sql_alive; then
        d=$(wait_sql "SELECT (deleted_at IS NOT NULL)::text FROM payment_keys WHERE owner = '$KEY_OWNER' AND nonce = $NONCE" true 10) \
          && pass "R4 coordinator row deleted_at set" || fail "R4 coordinator deleted_at: '$d'"
      fi
      req_pk POST "/call/$PROJECT" '{"input":{"operation":"ping"}}'
      [[ "$HTTP" != 200 ]] && pass "R4 a call on the closed key → HTTP $HTTP" || fail "R4 the closed key still runs calls (200)"
    else
      fail "R4 close: $(why_of "$out")"
    fi

    log "R5 a top-up on the closing key comes back"
    T3=$(token_balance)
    out=$(ft_call "$AMOUNT" "$(jq -nc --argjson n "$NONCE" '{action:"top_up_payment_key", nonce:$n}|tojson' | jq -r .)")
    TX=$(tx_of "$out")
    if [[ -n "$TX" ]]; then
      fails=$(tx_failures "$TX" "$KEY_OWNER")
      has_failure "$fails" "is closing since" && pass "R5 refused at admission (receipt failed with 'is closing since')" || fail "R5 no closing refusal in $TX: $(short "$fails")"
      EXPECT=$T3; t=$(wait_eq token_balance) && pass "R5 token balance unchanged" || fail "R5 token balance '$t', expected $EXPECT"
      [[ "$(ledger "$NONCE" | jq -r .refundable_cap)" == "$TOTAL" ]] && pass "R5 cap unchanged" || fail "R5 cap changed"
    else
      fail "R5 the transfer was not sent: $(why_of "$out")"
    fi

    log "R6 claim now → refused"
    out=$(call "$KEY_OWNER" "$CONTRACT_ID" claim_payment_key_refund "$(jq -nc --argjson n "$NONCE" '{nonce:$n}')" '1 yoctoNEAR')
    ! succeeded "$out" && grep -q 'can be claimed from' <<<"$out" && pass "R6 refused: $(why_of "$out" | head -c 160)" || fail "R6 not refused as expected: $(why_of "$out")"
    [[ -z "$(flight "$NONCE" | jq -r '.claim_open // empty' | grep true)" ]] && pass "R6 a refused claim leaves no claim open" || fail "R6 claim_open after a refusal: $(flight "$NONCE")"

    log "R7 close again → refused"
    out=$(call "$KEY_OWNER" "$CONTRACT_ID" close_payment_key "$(jq -nc --argjson n "$NONCE" '{nonce:$n}')" '1 yoctoNEAR')
    ! succeeded "$out" && grep -q 'already closing' <<<"$out" && pass "R7 refused: already closing" || fail "R7 not refused as expected: $(why_of "$out")"
    REFUND_NONCE=$NONCE
  fi

  # ── G: a grant key ──
  log "G1 a grant-only key: close → closing with cap 0"
  if [[ -z "$ADMIN_TOKEN" ]]; then
    skip "G1 needs ADMIN_BEARER_TOKEN_TESTNET"
  elif ! create_key; then
    fail "G1 no key"
  else
    G_NONCE=$NONCE
    if sql_alive; then
      wait_sql "SELECT initial_balance FROM payment_keys WHERE owner = '$KEY_OWNER' AND nonce = $G_NONCE AND deleted_at IS NULL" 0 30 >/dev/null || warn "G1 coordinator row not seen yet"
    else
      sleep 60
    fi
    req_admin POST /admin/grant-payment-key "$(jq -nc --arg o "$KEY_OWNER" --argjson n "$G_NONCE" --arg a "$AMOUNT" '{owner:$o, nonce:$n, amount:$a, note:"payment_key_refund_e2e G1"}')"
    [[ "$HTTP" == 200 ]] && pass "G1 granted $AMOUNT to nonce $G_NONCE" || fail "G1 grant → HTTP $HTTP: $(short)"
    out=$(call "$KEY_OWNER" "$CONTRACT_ID" close_payment_key "$(jq -nc --argjson n "$G_NONCE" '{nonce:$n}')" '1 yoctoNEAR')
    if succeeded "$out"; then
      l=$(ledger "$G_NONCE")
      [[ "$(jq -r .refundable_cap <<<"$l")" == 0 && -n "$(jq -r '.closing_since // empty' <<<"$l")" ]] \
        && pass "G1 closing, refundable_cap 0 (a grant is not a deposit)" || fail "G1 ledger: $(short "$l")"
      [[ "$(closing_count)" == $(( C0 + 2 )) ]] && pass "G1 closing count $(( C0 + 2 ))" || fail "G1 closing count $(closing_count), expected $(( C0 + 2 ))"
    else
      fail "G1 close: $(why_of "$out")"
    fi
  fi

  echo >&2
  note "phase 2, after 24 h:  PSQL_CMD=… $0 --claim ${REFUND_NONCE:-?}${G_NONCE:+ --grant $G_NONCE}"
fi

# ══ phase 2 ═══════════════════════════════════════════════════════════════════
claim_key() { # claim_key <nonce> <expect-paid|"cap">
  local nonce=$1 l cap tag out TX logs paid T0 T1 quote spent
  l=$(ledger "$nonce")
  if [[ -z "$l" || "$l" == null || "$(jq -r '.closing_since // empty' <<<"$l")" == "" ]]; then
    fail "C0 nonce $nonce is not closing on chain: $(short "$l")"; return
  fi
  cap=$(jq -r .refundable_cap <<<"$l")
  at=$(jq -r .claimable_at <<<"$l")
  now=$(( $(date +%s) * 1000000000 ))
  (( now >= at )) || { fail "C0 nonce $nonce is claimable at $at, now $now: come back later"; return; }
  note "nonce $nonce: cap $cap, deposited $(jq -r .user_funded <<<"$l"), refunded $(jq -r .refunded <<<"$l")"

  T0=$(token_balance)
  out=$(call "$KEY_OWNER" "$CONTRACT_ID" claim_payment_key_refund "$(jq -nc --argjson n "$nonce" '{nonce:$n}')" '1 yoctoNEAR' '150.0 Tgas')
  TX=$(tx_of "$out")
  if ! succeeded "$out"; then fail "C1 claim of nonce $nonce: $(why_of "$out")"; return; fi
  paid=$(tx_value "$TX" "$KEY_OWNER" | tr -d '"')
  logs=$(tx_logs "$TX" "$KEY_OWNER")
  if has_log "$logs" "PaymentKeyRefund refused"; then
    fail "C1 the coordinator refused the quote (money in flight?): $(jq -r '[.[] | select(contains("PaymentKeyRefund refused"))][0]' <<<"$logs" | head -c 240) — the key stays closing"
    return
  fi
  pass "C1 claim resumed ($TX), paid $paid"
  out=$(call "$KEY_OWNER" "$CONTRACT_ID" claim_payment_key_refund "$(jq -nc --argjson n "$nonce" '{nonce:$n}')" '1 yoctoNEAR')
  ! succeeded "$out" && pass "C1 a second claim right after is refused: $(why_of "$out" | head -c 120)" || fail "C1 a second claim went through"
  has_log "$logs" "Payment key refunded: owner=$KEY_OWNER, nonce=$nonce" && pass "C1 'Payment key refunded' logged" || fail "C1 no 'Payment key refunded' log"

  if [[ "$2" == cap ]]; then
    [[ "$paid" == "$cap" ]] && pass "C2 paid = cap ($cap)" || fail "C2 paid $paid, cap $cap"
  else
    [[ "$paid" == "$2" ]] && pass "C2 paid $paid as expected" || fail "C2 paid $paid, expected $2"
  fi
  if [[ "$paid" != 0 ]]; then
    EXPECT=$((T0 + paid)); t=$(wait_eq token_balance) && pass "C2 token balance +$paid" || fail "C2 token balance '$t', expected $EXPECT"
  else
    has_log "$logs" "refund capped" && pass "C2 'refund capped' logged (quoted above the cap)" || note "C2 nothing was quoted above the cap"
    [[ "$(token_balance)" == "$T0" ]] && pass "C2 token balance unchanged: no transfer for 0" || fail "C2 token balance moved on a 0 payout"
  fi

  if sql_alive; then
    quote=$(q "SELECT amount_usd::text FROM payment_key_refunds WHERE owner = '$KEY_OWNER' AND nonce = $nonce")
    [[ -n "$quote" ]] && pass "C3 coordinator payment_key_refunds quote $quote" || fail "C3 no payment_key_refunds row"
    if [[ -n "$quote" ]]; then
      if (( quote <= cap )); then [[ "$paid" == "$quote" ]] && pass "C3 paid = quote (within the cap)" || fail "C3 paid $paid ≠ quote $quote"
      else [[ "$paid" == "$cap" ]] && pass "C3 quote $quote above the cap: paid the cap" || fail "C3 quote $quote above the cap but paid $paid"; fi
    fi
    spent=$(q "SELECT pk.initial_balance || '|' || COALESCE(b.spent::text,'0') FROM payment_keys pk LEFT JOIN payment_key_balances b USING (owner, nonce) WHERE pk.owner = '$KEY_OWNER' AND pk.nonce = $nonce")
    [[ "${spent%%|*}" == "${spent##*|}" ]] && pass "C3 payment_keys.initial_balance = spent ($spent)" || fail "C3 initial|spent = $spent"
  else
    skip "C3 coordinator rows (no PSQL_CMD)"
  fi

  l=$(ledger "$nonce")
  [[ -z "$l" || "$l" == null ]] && pass "C4 ledger gone" || fail "C4 ledger still there: $(short "$l")"
  ! secret_exists "$nonce" && pass "C4 secret gone (storage deposit refunded)" || fail "C4 the secret is still on chain"
  floor=$(view "$CONTRACT_ID" get_payment_key_nonce_floor "$(jq -nc --arg a "$KEY_OWNER" '{account_id:$a}')")
  (( floor >= nonce )) && pass "C4 nonce floor $floor ≥ $nonce" || fail "C4 nonce floor $floor < $nonce"
}

if [[ "$MODE" == claim ]]; then
  log "C claim nonce $CLAIM_NONCE"
  claim_key "$CLAIM_NONCE" cap
  if [[ -n "$GRANT_NONCE" ]]; then
    log "C5 the grant key $GRANT_NONCE claims 0"
    claim_key "$GRANT_NONCE" 0
  fi
  [[ "$(closing_count)" == 0 ]] && pass "C4 closing count 0" || warn "closing count $(closing_count): other keys of $KEY_OWNER are closing"
fi

verdict
