#!/usr/bin/env bash
#
# A grant pays for calls and for nothing else — live on TESTNET.
#
# Every row reads the effect, not the answer alone: the coordinator's rows
# (PSQL_CMD), the chain, or the money a call moved. Each one names the result
# the same steps would give if the rule it checks were missing, so a pass
# cannot come from a refusal that happens for some other reason. Each grant
# check that has a money counterpart runs it on a money key (a key funded with
# the owner's own top-up): the same request must behave the other way there.
#
#   S1  /public/stats carries computed_at (RFC 3339); two reads in a row return
#       the same copy, each answered in under a second; a newer copy appears
#       within 75 s. Without the cache every read is a fresh 3 s scan.
#   G1  /admin/grant-payment-key: an amount past i64 → 400, the key untouched;
#       $0.05 on a fresh key → 200, is_grant, balance +50000, exactly one new
#       payment_key_grants row of 50000; onto the money key → 409, untouched
#   P1  /subscription/purchase on the grant key → 403 grant_key_not_purchasable,
#       terminal, nothing spent, no allowance. The money key with the same body
#       → refused for another reason, nothing spent
#   D1  X-Attached-Deposit from the grant key → 403 no_deposit
#   A1  connector-probe `secret` (price 10000, author share 7000 bp to the
#       probe's author) from the grant key → settled, the fee charged to the
#       grant (spent ≥ 10000), the call row quotes developer_share_bp 0 and no
#       author, no earnings_history credit for the call. The same call from the
#       money key → bp 7000, the author named, a 7000 credit for that call_id
#   R1  DELETE /admin/grant-keys on the money key → 404, untouched
#   R2  DELETE on the grant key → 204: deleted, the unspent grant revoked —
#       initial_balance − revoked, one payment_key_grant_revocations row
#   R3  a $0.01 on-chain top-up revives the key with exactly $0.01 to spend,
#       never the grant; it is still a grant key, so a purchase is still 403
#   R4  DELETE again → 204, nothing more revoked, the owner's cent stays
#   W1  a wallet minted for this run funds itself, creates a $0.01 key, the key
#       is granted: purchase-info does not name it (it would name the newest
#       key, and that key is a grant key)
#   W2  the wallet creates a second, own key: purchase-info names that one
#
# Accounts: KEY_OWNER (default outlayer-alice.testnet) signs every transaction,
# holds the stablecoin the contract names, and funds the wallet of W1/W2
# (0.03 USDC, FUND_NEAR NEAR). Payment keys, the wk_ and the admin bearer reach
# curl on stdin and are never printed. RPC keyed through tests/lib/rpc.sh.
#
# Needs: near-cli (legacy keychain key of KEY_OWNER), the outlayer CLI
# (OUTLAYER, default ~/projects/outlayer-cli/target/release/outlayer), jq,
# curl, python3, scripts/.env with ADMIN_BEARER_TOKEN_TESTNET, and PSQL_CMD —
# one SQL statement, tuples only, on the testnet coordinator DB `offchainvm`.
# Without PSQL_CMD the suite refuses to run: the DB rows are the evidence.
#
# Run:
#   PSQL_CMD=… ./tests/grant_keys_e2e.sh            # dry run: preflight only
#   PSQL_CMD=… ./tests/grant_keys_e2e.sh --apply    # everything
#   ROWS="S1 P1" PSQL_CMD=… ./tests/grant_keys_e2e.sh --apply

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/lib/hos_common.sh"   # NETWORK, CONTRACT_ID, keyed RPC_URL, pass/fail/skip/verdict, sql, throttle

APPLY=false
for a in "$@"; do
  case "$a" in
    --apply) APPLY=true ;;
    -h|--help) sed -n '2,/^$/p' "$0"; exit 0 ;;
    *) echo "unknown argument: $a" >&2; exit 2 ;;
  esac
done

KEY_OWNER="${KEY_OWNER:-outlayer-alice.testnet}"
CONNECTORS="${CONNECTORS:-connectors.outlayer.$NETWORK}"
PROJECT="${PROJECT:-$CONNECTORS/connector-probe}"
OUTLAYER="${OUTLAYER:-$HOME/projects/outlayer-cli/target/release/outlayer}"
ENV_FILE="${ENV_FILE:-$REPO_ROOT/scripts/.env}"
FUND_NEAR="${FUND_NEAR:-0.3}"
ROWS="${ROWS:-S1 G1 P1 D1 A1 R1 R2 R3 R4 W1 W2}"
GRANT=50000        # $0.05
MONEY=50000        # $0.05, the money key's own top-up
CENT=10000         # $0.01, the smallest top-up
CREDS_DIR="$HOME/.near-credentials/$NETWORK"
want() { [[ " $ROWS " == *" $1 "* ]]; }

[[ "$NETWORK" == testnet ]] || { echo "✗ NETWORK=$NETWORK: this suite moves money and runs on testnet only" >&2; exit 2; }

RUN_TMP=$(mktemp -d -t grant_keys.XXXXXX); chmod 700 "$RUN_TMP"
OL_HOME="$RUN_TMP/ol"; mkdir -p "$OL_HOME/$NETWORK"
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
call() { # call <contract> <method> <args-json> <deposit> [gas] — signed by KEY_OWNER
  local out i
  for i in 1 2; do
    out=$(near contract call-function as-transaction "$1" "$2" json-args "$3" \
      prepaid-gas "${5:-100.0 Tgas}" attached-deposit "$4" sign-as "$KEY_OWNER" network-config "$NETWORK" \
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
top_up() { # top_up <nonce> <amount> — ft_transfer_call top_up_payment_key for KEY_OWNER's key
  call "$TOKEN" ft_transfer_call \
    "$(jq -nc --arg r "$CONTRACT_ID" --arg a "$2" --arg m "$(jq -nc --argjson n "$1" '{action:"top_up_payment_key", nonce:$n}')" \
       '{receiver_id:$r, amount:$a, msg:$m}')" '1 yoctoNEAR' '150.0 Tgas'
}

# ── coordinator ──────────────────────────────────────────────────────────────

q() { sql "$1" 2>/dev/null; }
wait_sql() { # wait_sql <statement> <expected> [tries] — every 6 s
  local i v=""
  for i in $(seq 1 "${3:-30}"); do v=$(q "$1"); [[ "$v" == "$2" ]] && { printf '%s' "$v"; return 0; }; sleep 6; done
  printf '%s' "$v"; return 1
}
key_row() { # key_row <owner> <nonce> → initial|spent|reserved|is_grant|deleted|allowance
  q "SELECT pk.initial_balance, COALESCE(b.spent,0)::text, COALESCE(b.reserved,0)::text, pk.is_grant,
            pk.deleted_at IS NOT NULL, COALESCE(pk.allowance_usd,0)
     FROM payment_keys pk LEFT JOIN payment_key_balances b ON b.owner = pk.owner AND b.nonce = pk.nonce
     WHERE pk.owner = '$1' AND pk.nonce = $2"
}
granted_sum() { q "SELECT COALESCE(SUM(amount_usd),0) FROM payment_key_grants WHERE owner = '$1' AND nonce = $2"; }
granted_rows() { q "SELECT count(*) FROM payment_key_grants WHERE owner = '$1' AND nonce = $2"; }
revoked_sum() { q "SELECT COALESCE(SUM(amount_usd),0) FROM payment_key_grant_revocations WHERE owner = '$1' AND nonce = $2"; }
revoked_rows() { q "SELECT count(*) FROM payment_key_grant_revocations WHERE owner = '$1' AND nonce = $2"; }
field() { cut -d'|' -f"$2" <<<"$1"; }

# req <auth-header-name> <secret> <METHOD> <path> [body] [extra-header] — sets HTTP, BODY, SECS.
# The secret reaches curl on stdin (`-H @-`), never argv.
req() {
  local out; out=$(mktemp "$RUN_TMP/b.XXXXXX")
  local -a a=(-sS -o "$out" -w '%{http_code} %{time_total}' --max-time 150 -X "$3" -H @-)
  [[ -n "${5:-}" ]] && a+=(-H 'Content-Type: application/json' --data-binary "$5")
  [[ -n "${6:-}" ]] && a+=(-H "$6")
  throttle
  local r; r=$(printf '%s: %s\n' "$1" "$2" | command curl "${a[@]}" "$COORDINATOR_URL$4" 2>/dev/null)
  HTTP=${r%% *}; SECS=${r#* }
  BODY=$(tr -d '\n' < "$out"); rm -f "$out"
}
req_pk()    { req X-Payment-Key "$PK_SECRET" "$@"; }
req_admin() { req Authorization "Bearer $ADMIN_TOKEN" "$@"; }
req_wk()    { req Authorization "Bearer $WK" "$@"; }
req_none()  { # req_none <METHOD> <path> — no credential
  local out; out=$(mktemp "$RUN_TMP/b.XXXXXX")
  throttle
  local r; r=$(command curl -sS -o "$out" -w '%{http_code} %{time_total}' --max-time 60 -X "$1" "$COORDINATOR_URL$2" 2>/dev/null)
  HTTP=${r%% *}; SECS=${r#* }
  BODY=$(tr -d '\n' < "$out"); rm -f "$out"
}
j() { jq -r "$1 // empty" <<<"$BODY" 2>/dev/null; }
short() { head -c "${2:-220}" <<<"${1:-$BODY}"; }

# create_key — one `outlayer keys create` under the private OUTLAYER_HOME; sets NONCE and KEY.
create_key() {
  local err
  NONCE=""; KEY=""
  err=$(OUTLAYER_HOME="$OL_HOME" OUTLAYER_NETWORK="$NETWORK" "$OUTLAYER" keys create 2>&1 >/dev/null)
  NONCE=$(grep -oE 'Payment key created \(nonce: [0-9]+\)' <<<"$err" | grep -oE '[0-9]+' | tail -1)
  [[ -n "$NONCE" ]] && KEY=$(OUTLAYER_HOME="$OL_HOME" OUTLAYER_NETWORK="$NETWORK" "$OUTLAYER" keys show "$NONCE" 2>/dev/null | tr -d ' \r\n')
  [[ -n "$NONCE" && "$KEY" == "$KEY_OWNER:$NONCE:"* ]] && return 0
  warn "key not created (nonce '${NONCE}', key $( [[ -n $KEY ]] && echo present || echo absent)): $(why_of "$err")"
  return 1
}

# probe_call <operation> — POST /call on the probe with $PK_SECRET; waits for the
# row to settle; sets CALL_ID and CALL_ROW (status|bp|author|fee).
probe_call() {
  CALL_ID=""; CALL_ROW=""
  req_pk POST "/call/$PROJECT" "$(jq -nc --arg o "$1" '{input:{operation:$o}}')"
  CALL_ID=$(j .call_id)
  [[ -n "$CALL_ID" ]] || return 1
  local i
  for i in $(seq 1 30); do
    CALL_ROW=$(q "SELECT status, developer_share_bp, COALESCE(fee_author_account_id,'<none>'), COALESCE(operation_fee_usd,0)::text
                  FROM https_calls WHERE call_id = '$CALL_ID'")
    [[ "$(field "$CALL_ROW" 1)" == completed || "$(field "$CALL_ROW" 1)" == failed ]] && return 0
    sleep 3
  done
  return 1
}
credits_for() { # credits_for <call_id> <payee> → count|sum
  q "SELECT count(*), COALESCE(SUM(amount),0)::text FROM earnings_history WHERE call_id::text = '$1' AND project_owner = '$2'"
}

# ── preflight ────────────────────────────────────────────────────────────────

log "grant_keys_e2e — $NETWORK, $( $APPLY && echo apply || echo dry-run ), rows: $ROWS"
note "RPC: $(rpc_url_public)"
note "coordinator: ${COORDINATOR_URL#*://}; key owner $KEY_OWNER; project $PROJECT"
for tool in jq curl near python3; do command -v "$tool" >/dev/null || { echo "✗ missing $tool" >&2; exit 1; }; done
[[ -x "$OUTLAYER" ]] || { echo "✗ no outlayer CLI at $OUTLAYER" >&2; exit 1; }
note "outlayer CLI: $("$OUTLAYER" --version 2>/dev/null)"
[[ -f "$CREDS_DIR/$KEY_OWNER.json" ]] || { echo "✗ no legacy-keychain key for $KEY_OWNER" >&2; exit 1; }
[[ -n "$ADMIN_TOKEN" ]] || { echo "✗ no ADMIN_BEARER_TOKEN_TESTNET in $ENV_FILE" >&2; exit 1; }
note "admin bearer: present (length ${#ADMIN_TOKEN})"
sql_alive || { echo "✗ PSQL_CMD unset or not answering: the DB rows are the evidence here, nothing runs without them" >&2; exit 1; }
[[ "$(q "SELECT to_regclass('payment_key_grant_revocations') IS NOT NULL")" == t ]] \
  || { echo "✗ the coordinator DB has no payment_key_grant_revocations: the fix is not deployed" >&2; exit 1; }
note "coordinator DB: reachable, revocation ledger present"
TOKEN=$(view "$CONTRACT_ID" get_payment_token_contract '{}' | jq -r '. // empty' 2>/dev/null)
[[ -n "$TOKEN" ]] || { echo "✗ the contract names no payment token" >&2; exit 1; }
PRICING=$(view "$CONTRACT_ID" get_project_pricing "$(jq -nc --arg p "$PROJECT" '{project_id:$p}')")
AUTHOR=$(jq -r '.author_account_id // empty' <<<"$PRICING")
SECRET_OP=$(jq -c '.operations[] | select(.operation=="secret") | {price_usd, developer_share_bp}' <<<"$PRICING")
[[ "$SECRET_OP" == '{"price_usd":"10000","developer_share_bp":7000}' && -n "$AUTHOR" ]] \
  || { echo "✗ $PROJECT 'secret' is priced $SECRET_OP by '$AUTHOR', not 10000 / 7000 bp: A1's expectations are about something else" >&2; exit 1; }
note "probe 'secret': price 10000, author share 7000 bp to $AUTHOR"

if ! $APPLY; then
  sed -n '3,/^$/p' "$0" >&2
  echo "  Pass --apply to run." >&2
  exit 0
fi

( umask 077; jq --arg a "$KEY_OWNER" --arg c "$CONTRACT_ID" \
    '{account_id:$a, public_key, private_key, contract_id:$c, auth_type:"near_key"}' \
    "$CREDS_DIR/$KEY_OWNER.json" > "$OL_HOME/$NETWORK/credentials.json" )

# ══ S1: /public/stats ═════════════════════════════════════════════════════════
if want S1; then
  log "S1 /public/stats is served from a copy refreshed every minute"
  req_none GET /public/stats; A=$(j .computed_at); T1=$SECS; X1=$(j .total_executions)
  req_none GET /public/stats; B=$(j .computed_at); T2=$SECS
  if [[ "$HTTP" == 200 && -n "$A" ]] && python3 -c "import datetime,sys; datetime.datetime.fromisoformat(sys.argv[1].replace('Z','+00:00'))" "$A" 2>/dev/null; then
    pass "S1 computed_at is RFC 3339 ($A), total_executions $X1"
  else
    fail "S1 no readable computed_at (HTTP $HTTP): $(short)"
  fi
  [[ -n "$A" && "$A" == "$B" ]] && pass "S1 two reads in a row return the same copy" \
    || fail "S1 two reads returned different copies ($A / $B): each read computed its own"
  python3 -c "import sys; sys.exit(0 if float(sys.argv[1]) < 1.0 and float(sys.argv[2]) < 1.0 else 1)" "$T1" "$T2" \
    && pass "S1 answered in ${T1}s and ${T2}s" || fail "S1 answered in ${T1}s and ${T2}s: not from memory"
  AGE=$(python3 -c "import datetime,sys; t=datetime.datetime.fromisoformat(sys.argv[1].replace('Z','+00:00')); print(int((datetime.datetime.now(datetime.timezone.utc)-t).total_seconds()))" "$A" 2>/dev/null)
  [[ -n "$AGE" && "$AGE" -le 75 ]] && pass "S1 the copy is ${AGE}s old" || fail "S1 the copy is ${AGE:-?}s old: the refresher is not keeping it fresh"
  C="$A"
  for _ in $(seq 1 16); do sleep 5; req_none GET /public/stats; C=$(j .computed_at); [[ -n "$C" && "$C" != "$A" ]] && break; done
  [[ -n "$C" && "$C" != "$A" ]] && pass "S1 a newer copy appeared ($C)" || fail "S1 no newer copy within 80 s: the refresher stopped"
fi

# ══ fixtures: a grant key and a money key ═════════════════════════════════════
NEED_KEYS=false
for r in G1 P1 D1 A1 R1 R2 R3 R4; do want "$r" && NEED_KEYS=true; done
G_NONCE=""; G_KEY=""; M_NONCE=""; M_KEY=""
if $NEED_KEYS; then
  log "fixture: two fresh keys of $KEY_OWNER"
  if create_key; then G_NONCE=$NONCE; G_KEY=$KEY; note "grant key: nonce $G_NONCE"; else fail "fixture: no grant key"; fi
  if create_key; then M_NONCE=$NONCE; M_KEY=$KEY; note "money key: nonce $M_NONCE"; else fail "fixture: no money key"; fi
  for n in $G_NONCE $M_NONCE; do
    wait_sql "SELECT count(*) FROM payment_keys WHERE owner = '$KEY_OWNER' AND nonce = $n AND deleted_at IS NULL" 1 30 >/dev/null \
      || fail "fixture: the coordinator never registered nonce $n"
  done
  if [[ -n "$M_NONCE" ]]; then
    out=$(top_up "$M_NONCE" "$MONEY")
    [[ -n "$(tx_of "$out")" ]] || fail "fixture: the money key's top-up was not sent: $(why_of "$out")"
    wait_sql "SELECT initial_balance FROM payment_keys WHERE owner = '$KEY_OWNER' AND nonce = $M_NONCE" "$MONEY" 30 >/dev/null \
      && note "money key: $MONEY of the owner's own money on it" || fail "fixture: the money key's balance never reached $MONEY"
  fi
fi

# ══ G1: the admin grant ═══════════════════════════════════════════════════════
if want G1 && [[ -n "$G_NONCE" ]]; then
  log "G1 the admin grant"
  R0=$(key_row "$KEY_OWNER" "$G_NONCE"); N0=$(granted_rows "$KEY_OWNER" "$G_NONCE")
  req_admin POST /admin/grant-payment-key "$(jq -nc --arg o "$KEY_OWNER" --argjson n "$G_NONCE" '{owner:$o, nonce:$n, amount:"9223372036854775808", note:"grant_keys_e2e overflow"}')"
  [[ "$HTTP" == 400 && "$(key_row "$KEY_OWNER" "$G_NONCE")" == "$R0" && "$(granted_rows "$KEY_OWNER" "$G_NONCE")" == "$N0" ]] \
    && pass "G1 an amount past i64 → 400 ($(short "$BODY" 80)), the key and the ledger untouched" \
    || fail "G1 overflow amount → HTTP $HTTP, key $(key_row "$KEY_OWNER" "$G_NONCE") (was $R0): $(short)"

  I0=$(field "$R0" 1)
  req_admin POST /admin/grant-payment-key "$(jq -nc --arg o "$KEY_OWNER" --argjson n "$G_NONCE" --arg a "$GRANT" '{owner:$o, nonce:$n, amount:$a, note:"grant_keys_e2e"}')"
  R1=$(key_row "$KEY_OWNER" "$G_NONCE")
  if [[ "$HTTP" == 200 && "$(field "$R1" 4)" == t && "$(field "$R1" 1)" == "$(( I0 + GRANT ))" \
        && "$(granted_rows "$KEY_OWNER" "$G_NONCE")" == "$(( N0 + 1 ))" && "$(granted_sum "$KEY_OWNER" "$G_NONCE")" == "$GRANT" ]]; then
    pass "G1 \$0.05 granted → 200: is_grant, balance $I0 → $(field "$R1" 1), one ledger row of $GRANT"
  else
    fail "G1 grant → HTTP $HTTP, key $R1, ledger $(granted_rows "$KEY_OWNER" "$G_NONCE") rows / $(granted_sum "$KEY_OWNER" "$G_NONCE"): $(short)"
  fi

  if [[ -n "$M_NONCE" ]]; then
    MR0=$(key_row "$KEY_OWNER" "$M_NONCE")
    req_admin POST /admin/grant-payment-key "$(jq -nc --arg o "$KEY_OWNER" --argjson n "$M_NONCE" --arg a "$GRANT" '{owner:$o, nonce:$n, amount:$a, note:"grant_keys_e2e user-funded"}')"
    [[ "$HTTP" == 409 && "$(key_row "$KEY_OWNER" "$M_NONCE")" == "$MR0" && "$(granted_rows "$KEY_OWNER" "$M_NONCE")" == 0 ]] \
      && pass "G1 a grant onto the owner's funded key → 409, untouched" \
      || fail "G1 grant onto the money key → HTTP $HTTP, key $(key_row "$KEY_OWNER" "$M_NONCE") (was $MR0): $(short)"
  fi
fi

# ══ P1: no subscription from a grant ═════════════════════════════════════════
purchase_body='{"amount_usd":"50000"}'
if want P1 && [[ -n "$G_NONCE" ]]; then
  log "P1 a grant cannot buy a subscription"
  R0=$(key_row "$KEY_OWNER" "$G_NONCE")
  PK_SECRET=$G_KEY; req_pk POST /subscription/purchase "$purchase_body"
  if [[ "$HTTP" == 403 && "$(j .reason)" == grant_key_not_purchasable && "$(j .terminal)" == true \
        && "$(key_row "$KEY_OWNER" "$G_NONCE")" == "$R0" ]]; then
    pass "P1 grant key → 403 grant_key_not_purchasable, terminal; spent, balance and allowance unchanged ($R0)"
  else
    fail "P1 grant key → HTTP $HTTP reason '$(j .reason)', key $(key_row "$KEY_OWNER" "$G_NONCE") (was $R0): $(short)"
  fi
  if [[ -n "$M_NONCE" ]]; then
    MR0=$(key_row "$KEY_OWNER" "$M_NONCE")
    PK_SECRET=$M_KEY; req_pk POST /subscription/purchase "$purchase_body"
    MR1=$(key_row "$KEY_OWNER" "$M_NONCE")
    if [[ "$(j .reason)" == grant_key_not_purchasable ]]; then
      fail "P1 the money key was refused as a grant key: the refusal is not about is_grant"
    elif [[ "$HTTP" == 200 ]]; then
      note "P1 the money key bought a plan with the same body ($(short "$BODY" 120)): its own money may"
      pass "P1 control: the same purchase from the owner's money is not refused as a grant"
    else
      [[ "$MR1" == "$MR0" ]] && pass "P1 control: the money key → HTTP $HTTP $(j .reason), not grant_key_not_purchasable; nothing spent" \
        || fail "P1 control: the money key was refused ($HTTP) yet its row moved: $MR0 → $MR1"
    fi
  fi
fi

# ══ D1: no deposit from a grant ══════════════════════════════════════════════
if want D1 && [[ -n "$G_NONCE" ]]; then
  log "D1 a grant cannot be attached as a deposit"
  R0=$(key_row "$KEY_OWNER" "$G_NONCE")
  PK_SECRET=$G_KEY; req_pk POST "/call/$PROJECT" '{"input":{"operation":"ping"}}' 'X-Attached-Deposit: 1000'
  [[ "$HTTP" == 403 && "$(key_row "$KEY_OWNER" "$G_NONCE")" == "$R0" ]] \
    && pass "D1 X-Attached-Deposit from the grant key → 403 ($(short "$BODY" 80)), nothing spent" \
    || fail "D1 deposit from the grant key → HTTP $HTTP, key $(key_row "$KEY_OWNER" "$G_NONCE") (was $R0): $(short)"
fi

# ══ A1: no author share from a grant ═════════════════════════════════════════
if want A1 && [[ -n "$G_NONCE" ]]; then
  log "A1 a call paid from a grant pays the connector's author nothing"
  S0=$(field "$(key_row "$KEY_OWNER" "$G_NONCE")" 2)
  PK_SECRET=$G_KEY
  if probe_call secret; then
    S1=$(field "$(key_row "$KEY_OWNER" "$G_NONCE")" 2)
    CR=$(credits_for "$CALL_ID" "$AUTHOR")
    note "grant call $CALL_ID: row $CALL_ROW, spent $S0 → $S1, credits to $AUTHOR: $CR"
    [[ $(( S1 - S0 )) -ge 10000 ]] && pass "A1 the fee was charged to the grant: spent +$(( S1 - S0 ))" \
      || fail "A1 spent moved by $(( S1 - S0 )) (< the 10000 fee): the fee did not stand, so nothing below says who it paid"
    [[ "$(field "$CALL_ROW" 2)" == 0 && "$(field "$CALL_ROW" 3)" == "<none>" ]] \
      && pass "A1 the call row quotes developer_share_bp 0 and no author" \
      || fail "A1 the call row quotes bp $(field "$CALL_ROW" 2), author $(field "$CALL_ROW" 3)"
    [[ "$(field "$CR" 1)" == 0 ]] && pass "A1 no earnings credit to $AUTHOR for the call" \
      || fail "A1 $AUTHOR was credited $(field "$CR" 2) for a call paid from a grant"
  else
    fail "A1 the grant call did not settle (HTTP $HTTP, call '$CALL_ID', row '$CALL_ROW'): $(short)"
  fi
  if [[ -n "$M_NONCE" ]]; then
    PK_SECRET=$M_KEY
    if probe_call secret; then
      CR=$(credits_for "$CALL_ID" "$AUTHOR")
      note "money call $CALL_ID: row $CALL_ROW, credits to $AUTHOR: $CR"
      [[ "$(field "$CALL_ROW" 2)" == 7000 && "$(field "$CALL_ROW" 3)" == "$AUTHOR" && "$CR" == "1|7000" ]] \
        && pass "A1 control: the same call from the owner's money quotes 7000 bp to $AUTHOR and credits them 7000" \
        || fail "A1 control: the money call quotes bp $(field "$CALL_ROW" 2) to $(field "$CALL_ROW" 3), credits $CR — the grant result above proves nothing"
    else
      fail "A1 control: the money call did not settle (HTTP $HTTP, call '$CALL_ID'): $(short)"
    fi
  fi
fi

# ══ R1–R4: deleting a grant key ══════════════════════════════════════════════
if want R1 && [[ -n "$M_NONCE" ]]; then
  log "R1 the grant delete touches grant keys only"
  MR0=$(key_row "$KEY_OWNER" "$M_NONCE")
  req_admin DELETE "/admin/grant-keys/$KEY_OWNER/$M_NONCE"
  [[ "$HTTP" == 404 && "$(key_row "$KEY_OWNER" "$M_NONCE")" == "$MR0" && "$(revoked_rows "$KEY_OWNER" "$M_NONCE")" == 0 ]] \
    && pass "R1 the money key → 404, untouched" \
    || fail "R1 delete on the money key → HTTP $HTTP, key $(key_row "$KEY_OWNER" "$M_NONCE") (was $MR0)"
fi

if want R2 && [[ -n "$G_NONCE" ]]; then
  log "R2 deleting the grant key revokes the unspent grant"
  R0=$(key_row "$KEY_OWNER" "$G_NONCE")
  I0=$(field "$R0" 1); S0=$(field "$R0" 2); V0=$(field "$R0" 3)
  G=$(granted_sum "$KEY_OWNER" "$G_NONCE"); RV0=$(revoked_sum "$KEY_OWNER" "$G_NONCE")
  EXP=$(python3 -c "import sys; i,s,r,g,rv=map(int,sys.argv[1:]); print(min(max(0,g-rv-s), max(0,i-s-r)))" "$I0" "$S0" "$V0" "$G" "$RV0")
  note "before: initial $I0, spent $S0, reserved $V0, granted $G, revoked $RV0 → expected revocation $EXP"
  [[ "$EXP" -gt 0 ]] || fail "R2 nothing is left of the grant to revoke: the row below cannot show the revocation"
  req_admin DELETE "/admin/grant-keys/$KEY_OWNER/$G_NONCE"
  R1=$(key_row "$KEY_OWNER" "$G_NONCE")
  if [[ "$HTTP" == 204 && "$(field "$R1" 5)" == t && "$(field "$R1" 1)" == "$(( I0 - EXP ))" \
        && "$(revoked_sum "$KEY_OWNER" "$G_NONCE")" == "$(( RV0 + EXP ))" && "$(revoked_rows "$KEY_OWNER" "$G_NONCE")" == 1 ]]; then
    pass "R2 → 204: deleted, initial_balance $I0 → $(field "$R1" 1), one revocation row of $EXP (the unspent grant)"
  else
    fail "R2 delete → HTTP $HTTP, key $R1, revoked $(revoked_sum "$KEY_OWNER" "$G_NONCE") in $(revoked_rows "$KEY_OWNER" "$G_NONCE") rows (expected $EXP)"
  fi
fi

if want R3 && [[ -n "$G_NONCE" ]]; then
  log "R3 a cent revives the deleted key with the cent, not the grant"
  R0=$(key_row "$KEY_OWNER" "$G_NONCE"); I0=$(field "$R0" 1); S0=$(field "$R0" 2)
  out=$(top_up "$G_NONCE" "$CENT")
  [[ -n "$(tx_of "$out")" ]] && note "top-up of $CENT sent ($(tx_of "$out"))" || fail "R3 the top-up was not sent: $(why_of "$out")"
  if wait_sql "SELECT initial_balance FROM payment_keys WHERE owner = '$KEY_OWNER' AND nonce = $G_NONCE AND deleted_at IS NULL" "$(( I0 + CENT ))" 30 >/dev/null; then
    req_none GET "/public/payment-keys/$KEY_OWNER/$G_NONCE/balance"
    AV=$(j .available)
    [[ "$AV" == "$CENT" ]] \
      && pass "R3 revived: initial_balance $I0 → $(( I0 + CENT )), available $AV — the cent, none of the grant" \
      || fail "R3 revived with available '$AV' (expected $CENT): $(short)"
  else
    fail "R3 the key is $(key_row "$KEY_OWNER" "$G_NONCE") after the top-up (expected live with initial $(( I0 + CENT )))"
  fi
  PK_SECRET=$G_KEY; req_pk POST /subscription/purchase "$purchase_body"
  [[ "$HTTP" == 403 && "$(j .reason)" == grant_key_not_purchasable ]] \
    && pass "R3 the revived key is still a grant key: purchase → 403" \
    || fail "R3 purchase on the revived key → HTTP $HTTP $(j .reason)"
fi

if want R4 && [[ -n "$G_NONCE" ]]; then
  log "R4 a second delete takes nothing more"
  R0=$(key_row "$KEY_OWNER" "$G_NONCE"); RV0=$(revoked_sum "$KEY_OWNER" "$G_NONCE"); N0=$(revoked_rows "$KEY_OWNER" "$G_NONCE")
  req_admin DELETE "/admin/grant-keys/$KEY_OWNER/$G_NONCE"
  R1=$(key_row "$KEY_OWNER" "$G_NONCE")
  [[ "$HTTP" == 204 && "$(field "$R1" 5)" == t && "$(field "$R1" 1)" == "$(field "$R0" 1)" \
     && "$(revoked_sum "$KEY_OWNER" "$G_NONCE")" == "$RV0" && "$(revoked_rows "$KEY_OWNER" "$G_NONCE")" == "$N0" ]] \
    && pass "R4 → 204: deleted, no new revocation, the owner's cent stays (initial $(field "$R1" 1), spent $(field "$R1" 2))" \
    || fail "R4 → HTTP $HTTP, key $R0 → $R1, revoked $RV0 → $(revoked_sum "$KEY_OWNER" "$G_NONCE")"
fi

# ══ W1/W2: purchase-info never names a grant key ═════════════════════════════
if want W1 || want W2; then
  log "W fixture: a wallet minted for this run, funded by $KEY_OWNER"
  WK=$(command curl -sS --max-time 30 -X POST "$COORDINATOR_URL/register" -H 'Content-Type: application/json' -d '{}' | jq -r '.api_key // empty')
  ADDR=""
  if [[ -n "$WK" ]]; then
    req_wk GET "/wallet/v1/address?chain=near"; ADDR=$(j .address)
  fi
  if [[ -z "$ADDR" ]]; then
    fail "W no wallet (wk_ $( [[ -n $WK ]] && echo present || echo absent), address '$ADDR'): $(short)"
  else
    note "wallet $ADDR"
    out=$(call "$TOKEN" storage_deposit "$(jq -nc --arg a "$ADDR" '{account_id:$a, registration_only:true}')" '0.00125 NEAR' '30.0 Tgas')
    succeeded "$out" || warn "storage_deposit: $(why_of "$out")"
    out=$(call "$TOKEN" ft_transfer "$(jq -nc --arg a "$ADDR" '{receiver_id:$a, amount:"30000"}')" '1 yoctoNEAR' '30.0 Tgas')
    succeeded "$out" || fail "W the stablecoin was not sent: $(why_of "$out")"
    near --quiet tokens "$KEY_OWNER" send-near "$ADDR" "$FUND_NEAR NEAR" network-config "$NETWORK" sign-with-legacy-keychain send >/dev/null 2>&1 \
      || fail "W $FUND_NEAR NEAR was not sent"
    for _ in $(seq 1 10); do [[ "$(view "$TOKEN" ft_balance_of "$(jq -nc --arg a "$ADDR" '{account_id:$a}')" | tr -d '"')" == 30000 ]] && break; sleep 3; done

    wallet_key() { # creates a $0.01 key for the wallet; sets W_NONCE
      W_NONCE=""
      req_wk POST /wallet/v1/create-payment-key '{"initial_deposit_usdc":"0.01"}'
      W_NONCE=$(j .nonce)
      [[ -n "$W_NONCE" ]] && wait_sql "SELECT initial_balance FROM payment_keys WHERE owner = '$ADDR' AND nonce = $W_NONCE" "$CENT" 30 >/dev/null
    }

    if want W1; then
      log "W1 purchase-info does not name the wallet's grant key"
      if wallet_key; then
        WG=$W_NONCE
        req_admin POST /admin/grant-payment-key "$(jq -nc --arg o "$ADDR" --argjson n "$WG" --arg a "$GRANT" '{owner:$o, nonce:$n, amount:$a, note:"grant_keys_e2e wallet"}')"
        [[ "$HTTP" == 200 && "$(field "$(key_row "$ADDR" "$WG")" 4)" == t ]] && note "key #$WG granted: balance $(field "$(key_row "$ADDR" "$WG")" 1)" \
          || fail "W1 the wallet key was not granted (HTTP $HTTP): $(short)"
        req_wk GET /wallet/v1/subscription/purchase-info
        NA=$(j .next_action); INS=$(j .instruction); TU=$(jq -r '.top_up.msg // ""' <<<"$BODY")
        note "purchase-info: next_action $NA; keys listed: $(jq -c '[.keys[]?.nonce]' <<<"$BODY")"
        if [[ "$HTTP" == 200 && "$NA" != purchase_allowance && "$NA" != top_up_key \
              && "$INS" != *"Key #$WG "* && "$TU" != *"\"nonce\":$WG"* ]]; then
          pass "W1 the only key is a grant key → next_action $NA, key #$WG named nowhere"
        else
          fail "W1 purchase-info → HTTP $HTTP next_action '$NA' (instruction: $(short "$INS" 120)): it sends the buyer to the grant key"
        fi
      else
        fail "W1 the wallet created no key: $(short)"
      fi
    fi

    if want W2; then
      log "W2 purchase-info names the wallet's own key"
      if wallet_key; then
        WO=$W_NONCE
        req_wk GET /wallet/v1/subscription/purchase-info
        NA=$(j .next_action); INS=$(j .instruction)
        [[ "$HTTP" == 200 && "$NA" == purchase_allowance && "$INS" == *"Key #$WO "* ]] \
          && pass "W2 a second, own key (#$WO) → purchase_allowance on key #$WO" \
          || fail "W2 purchase-info → HTTP $HTTP next_action '$NA': $(short "$INS" 160)"
      else
        fail "W2 the wallet created no second key: $(short)"
      fi
    fi
  fi
fi

verdict
