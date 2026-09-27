#!/usr/bin/env bash
#
# Gifted subscriptions — the rows `gift_subscription_e2e.sh` cannot reach with
# HTTP alone, live on TESTNET (.idea/_todo/release-test-plan.md §9b G6, §9d D2;
# test-coverage-audit features 4 and 5):
#
#   GC   G6 for a CUSTOMER key: a payment key created on chain by CUSTOMER
#        (nonce ≥ 1, balance 0), gifted → 200 trial_converted:false, allowance
#        = the cap; a connector call made WITH THAT KEY → 200 completed; then
#        `GET /admin/connector-calls` lists that call `from_allowance:true`,
#        `paid_by_grant:true` (and `https_calls.allowance_covered`)
#   GP   a gift onto a PARTIALLY SPENT trial: a fresh wallet's trial, a few
#        calls, then the gift → 200 trial_converted:true, allowance available =
#        the cap; DB `trial_allowance_usd` = the trial's allowance X, one ledger
#        row = cap − (X − S) where S is what the trial had spent (settled), and
#        `allowance_usd` = S + cap; the key's status has no `trial` block and
#        the key runs past the trial's call limit (calls 1..LIMIT+1 all 200)
#   GS   the converted trial keeps its connectors-only scope: a call to a
#        non-connector project → 403 `project_not_allowed`; DB `project_ids`
#        still `{connectors.<net>/*}`
#   D2c  (DESCRIBE_SWITCH=1) the describe cache: `set_active_version` of a
#        registry connector's project to another of its versions → describe
#        keeps the old `version` after the transaction is final, and serves the
#        new answer within 60 s (+ the poll step); switched back the same way.
#        Signs as the connectors account; the original active version is
#        restored on exit whatever happens
#
# Accounts: CUSTOMER (default outlayer-carol.testnet) owns the GC key; the GP
# wallet is minted by the coordinator (`POST /register`). Trial claims are
# capped per IP per day (testnet 3): a `trial_unavailable` refusal is reported
# as such — clear `trial_key_ip:<this ip>` (`.idea/testnet-runners/redis_testnet.sh`)
# and rerun.
#
# Secrets: the admin bearer comes from ONE line of scripts/.env, the payment
# keys from the CLI's private OUTLAYER_HOME and from `/trial-key`, the `wk_` from
# `/register` — each held in this process only, sent on curl's stdin (`-H @-`),
# never printed; `/register` and `/trial-key` answers are reduced to their other
# fields before anything is shown. KEY_OUT=<file>: the GC key is written there
# (0600) for reuse as a fixture.
#
# Needs: CUSTOMER's key in the legacy keychain; PSQL_CMD (testnet coordinator
# DB); for D2c the connectors account's key. RPC keyed through tests/lib/rpc.sh.
#
# Run:
#   PSQL_CMD=… ./tests/gift_followup_e2e.sh            # dry run
#   PSQL_CMD=… ./tests/gift_followup_e2e.sh --apply    # GC, GP, GS
#   PSQL_CMD=… DESCRIBE_SWITCH=1 ONLY=D2c ./tests/gift_followup_e2e.sh --apply

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/lib/hos_common.sh"   # NETWORK, CONTRACT_ID, keyed RPC_URL, pass/fail/skip/verdict, sql, throttle

APPLY=false
[[ "${1:-}" == "--apply" ]] && APPLY=true

CUSTOMER="${CUSTOMER:-outlayer-carol.testnet}"
CONNECTORS="${CONNECTORS:-connectors.outlayer.$NETWORK}"
PROJECT="${PROJECT:-$CONNECTORS/connector-probe}"
ORDINARY_PROJECT="${ORDINARY_PROJECT:-zavodil.testnet/wallet-probe}"
SPEND="${SPEND:-3}"
TRIAL_LIMIT="${TRIAL_LIMIT:-50}"
DESCRIBE_SWITCH="${DESCRIBE_SWITCH:-0}"
DESCRIBE_ID="${DESCRIBE_ID:-github}"
ONLY="${ONLY:-}"
ENV_FILE="${ENV_FILE:-$REPO_ROOT/scripts/.env}"
KEY_OUT="${KEY_OUT:-}"
CREDS_DIR="$HOME/.near-credentials/$NETWORK"

RUN_TMP=$(mktemp -d -t gift_followup.XXXXXX); chmod 700 "$RUN_TMP"
OL_HOME="$RUN_TMP/ol"; mkdir -p "$OL_HOME/$NETWORK"
EXIT_HOOKS=()
on_exit() { local rc=$? h; for h in "${EXIT_HOOKS[@]:-}"; do [[ -n "$h" ]] && $h; done; rm -rf "$RUN_TMP"; return $rc; }
trap on_exit EXIT
want() { [[ -z "$ONLY" || ",$ONLY," == *",$1,"* ]]; }

ADMIN_TOKEN=""
[[ -r "$ENV_FILE" ]] && ADMIN_TOKEN=$(grep '^ADMIN_BEARER_TOKEN_TESTNET=' "$ENV_FILE" | head -1 | cut -d= -f2- | tr -d "\"'")

# ── client ───────────────────────────────────────────────────────────────────

# The one header that authenticates a request, for `curl -H @-`.
auth_line() { # auth_line <none|admin|wk|pk> <secret>
  case "$1" in
    admin) printf 'Authorization: Bearer %s\n' "$ADMIN_TOKEN" ;;
    wk)    printf 'Authorization: Bearer %s\n' "$2" ;;
    pk)    printf 'X-Payment-Key: %s\n' "$2" ;;
    *)     printf 'X-Suite: gift-followup-e2e\n' ;;
  esac
}
# req <none|admin|wk|pk> <secret|-> <METHOD> <path> [body] — sets HTTP, BODY.
req() {
  local auth=$1 secret=$2 method=$3 path=$4 body=${5:-} out="$RUN_TMP/body"
  throttle
  local -a a=(-sS -o "$out" -w '%{http_code}' -X "$method" --max-time 150 -H @-)
  [[ -n "$body" ]] && a+=(-H 'Content-Type: application/json' --data-binary "$body")
  HTTP=$(auth_line "$auth" "$secret" | command curl "${a[@]}" "$COORDINATOR_URL$path" 2>/dev/null)
  BODY=$(tr -d '\n' < "$out" 2>/dev/null); rm -f "$out"
}
j() { jq -r "$1" <<<"$BODY" 2>/dev/null; }
short() { head -c "${2:-220}" <<<"${1:-$BODY}"; }
q() { sql "$1" 2>/dev/null; }
now_rfc() { date -u +%Y-%m-%dT%H:%M:%SZ; }
later_rfc() { date -u -v+10M +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '+10 minutes' +%Y-%m-%dT%H:%M:%SZ; }
safe_ident() { [[ "$1" =~ ^[A-Za-z0-9._-]+$ ]]; }
ping_call() { req pk "$1" POST "/call/$PROJECT" '{"input":{"operation":"ping"}}'; }
settled() { # settled <owner> <nonce> — waits until no call of the key is pending
  local i n
  for i in $(seq 1 20); do
    n=$(q "SELECT count(*) FROM https_calls WHERE owner = '$1' AND nonce = $2 AND status = 'pending'")
    [[ "$n" == 0 ]] && return 0; sleep 3
  done
  return 1
}

# ── chain ────────────────────────────────────────────────────────────────────

rpc_post() {
  printf 'url = "%s"\n' "$RPC_URL" | command curl -sS --max-time 45 -K - -X POST \
    -H 'Content-Type: application/json' --data-binary "$1" 2>/dev/null
}
view() { # view <method> <args-json>
  rpc_post "$(jq -nc --arg m "$1" --arg g "$(printf '%s' "$2" | base64 | tr -d '\n')" --arg c "$CONTRACT_ID" \
    '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"call_function",finality:"final",account_id:$c,method_name:$m,args_base64:$g}}')" \
    | jq -r 'if .result.result then (.result.result | implode) else empty end' 2>/dev/null
}
call() { # call <signer> <method> <args-json> <deposit> — transport failures before a tx retried once
  local out i
  for i in 1 2; do
    out=$(near contract call-function as-transaction "$CONTRACT_ID" "$2" json-args "$3" \
      prepaid-gas '100.0 Tgas' attached-deposit "$4" sign-as "$1" network-config "$NETWORK" \
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
  m=$(grep -oE 'Smart contract panicked: [^"\\]*' <<<"$1" | grep -viE 'https?:|apikey' | head -1 | head -c 300)
  [[ -n "$m" ]] && printf '%s' "$m" || printf 'near-cli failed without a contract panic (output withheld)'
}

# ── preflight ────────────────────────────────────────────────────────────────

log "gift_followup_e2e — $NETWORK, $( [[ $APPLY == true ]] && echo APPLY || echo 'dry run' )${ONLY:+ (ONLY=$ONLY)}"
note "RPC: $(rpc_url_public)"
note "coordinator: ${COORDINATOR_URL#*://}; customer $CUSTOMER; project $PROJECT; ordinary $ORDINARY_PROJECT"
for tool in jq curl near outlayer; do command -v "$tool" >/dev/null || { echo "✗ missing $tool" >&2; exit 1; }; done
[[ -n "$ADMIN_TOKEN" ]] && note "admin bearer: present (length ${#ADMIN_TOKEN})" || { echo "✗ no ADMIN_BEARER_TOKEN_TESTNET in $ENV_FILE" >&2; exit 1; }
sql_alive || { echo "✗ PSQL_CMD unset or not answering" >&2; exit 1; }
[[ -f "$CREDS_DIR/$CUSTOMER.json" ]] || { echo "✗ no legacy-keychain key for $CUSTOMER" >&2; exit 1; }
req admin - POST /admin/grant-subscription '{"owner":"gift-followup-nobody.testnet","nonce":1,"amount_usd":"0"}'
CAP=$(grep -oE 'from 1 to [0-9]+ \(GIFT_SUBSCRIPTION_USD\)' <<<"$BODY" | grep -oE '[0-9]+' | tail -1)
[[ -n "$CAP" ]] && note "GIFT_SUBSCRIPTION_USD (from the refusal): $CAP" || { echo "✗ could not read the gift cap (HTTP $HTTP): $(short)" >&2; exit 1; }

if [[ "$APPLY" != true ]]; then
  sed -n '3,/^$/p' "$0" >&2
  echo "  Pass --apply to run." >&2
  exit 0
fi
RUN_FROM=$(date -u -v-1M +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '-1 minute' +%Y-%m-%dT%H:%M:%SZ)

# ══ GC: a customer key's own call ════════════════════════════════════════════
if want GC; then
  log "GC fixture: a payment key of $CUSTOMER (outlayer keys create, private OUTLAYER_HOME)"
  ( umask 077; jq --arg a "$CUSTOMER" --arg c "$CONTRACT_ID" \
      '{account_id:$a, public_key, private_key, contract_id:$c, auth_type:"near_key"}' \
      "$CREDS_DIR/$CUSTOMER.json" > "$OL_HOME/$NETWORK/credentials.json" )
  C_NONCE=""; C_PK=""; PINNED=()
  # A nonce the coordinator has already seen belongs to a deleted key, whose
  # row a re-created key does not replace (system_event_effects_e2e.sh R1):
  # keep such a key live so the next create moves on, delete it at the end.
  for attempt in 1 2 3 4; do
    next=$(view get_next_payment_key_nonce "$(jq -nc --arg a "$CUSTOMER" '{account_id:$a}')")
    prior=$(q "SELECT count(*) FROM payment_keys WHERE owner = '$CUSTOMER' AND nonce = ${next:-0}")
    err=$(OUTLAYER_HOME="$OL_HOME" OUTLAYER_NETWORK="$NETWORK" outlayer keys create 2>&1 >/dev/null)
    n=$(grep -oE 'Payment key created \(nonce: [0-9]+\)' <<<"$err" | grep -oE '[0-9]+' | tail -1)
    [[ -n "$n" ]] || { warn "outlayer keys create failed: $(why_of "$err")"; break; }
    if [[ "$prior" == 0 ]]; then
      C_NONCE=$n
      C_PK=$(OUTLAYER_HOME="$OL_HOME" OUTLAYER_NETWORK="$NETWORK" outlayer keys show "$n" 2>/dev/null | tr -d ' \r\n')
      break
    fi
    warn "nonce $n was used before (a deleted key's row): kept live, trying the next"
    PINNED+=("$n"); sleep 30
  done
  drop_pinned() {
    local n out
    for n in "${PINNED[@]:-}"; do
      [[ -n "$n" ]] || continue
      out=$(call "$CUSTOMER" delete_payment_key "$(jq -nc --argjson n "$n" '{nonce:$n}')" '1 yoctoNEAR')
      succeeded "$out" && note "teardown: re-created key at nonce $n deleted" || warn "teardown: delete of nonce $n: $(why_of "$out")"
    done
  }
  EXIT_HOOKS+=(drop_pinned)
  if [[ -z "$C_NONCE" || "$C_PK" != "$CUSTOMER:$C_NONCE:"* ]]; then
    fail "GC fixture: no fresh customer key (nonce '$C_NONCE', key $( [[ -n $C_PK ]] && echo present || echo absent))"
  else
    note "GC key $CUSTOMER nonce $C_NONCE (length ${#C_PK})"
    row=""
    for i in $(seq 1 30); do
      row=$(q "SELECT initial_balance || '|' || allowance_usd || '|' || is_grant::text FROM payment_keys WHERE owner = '$CUSTOMER' AND nonce = $C_NONCE AND deleted_at IS NULL")
      [[ -n "$row" ]] && break; sleep 6
    done
    [[ "$row" == "0|0|false" ]] && note "GC the coordinator registered it: balance 0, allowance 0, not a grant" \
      || fail "GC fixture: coordinator row '$row', expected 0|0|false"
    req admin - POST /admin/grant-subscription "$(jq -nc --arg o "$CUSTOMER" --argjson n "$C_NONCE" '{owner:$o, nonce:$n, note:"gift-followup GC"}')"
    [[ "$HTTP" == 200 && "$(j .trial_converted)" == false && "$(j .allowance_available_usd)" == "$CAP" ]] \
      && pass "GC gift on the customer key → 200 trial_converted:false, allowance_available_usd $CAP, until $(j .expires_at)" \
      || fail "GC gift → HTTP $HTTP: $(short)"
    ping_call "$C_PK"
    CALL_ID=$(j '.call_id // empty')
    [[ "$HTTP" == 200 && "$(j .status)" == completed ]] && pass "GC connector call WITH the customer key → 200 completed (call ${CALL_ID:-?})" \
      || fail "GC connector call with the customer key → HTTP $HTTP: $(short)"
    settled "$CUSTOMER" "$C_NONCE" || warn "GC the call is still pending"
    ac=$(q "SELECT allowance_covered::text FROM https_calls WHERE owner = '$CUSTOMER' AND nonce = $C_NONCE ORDER BY created_at DESC LIMIT 1")
    [[ "$ac" == true ]] && pass "GC https_calls.allowance_covered = true (paid from the gift)" || fail "GC https_calls.allowance_covered = '$ac'"
    req admin - GET "/admin/connector-calls?owner=$CUSTOMER&from=$RUN_FROM&to=$(later_rfc)&limit=100"
    sel=$(jq -c --argjson n "$C_NONCE" '[.calls[]? | select(.nonce == $n)]' <<<"$BODY" 2>/dev/null)
    if [[ "$HTTP" == 200 ]] && jq -e 'length >= 1 and all(.[]; .paid_by_grant == true and .from_allowance == true)' <<<"$sel" >/dev/null 2>&1; then
      pass "GC /admin/connector-calls: the customer key's $(jq length <<<"$sel") call(s) read from_allowance:true, paid_by_grant:true ($(jq -c '.[0] | {call_id, operation, status}' <<<"$sel"))"
    else
      fail "GC /admin/connector-calls → HTTP $HTTP, the key's calls: $(short "$sel" 300)"
    fi
    if [[ -n "$KEY_OUT" ]]; then ( umask 077; printf '%s\n' "$C_PK" > "$KEY_OUT" ); note "GC key written to KEY_OUT (0600)"; fi
  fi
fi

# ══ GP + GS: a partially spent trial ═════════════════════════════════════════
if want GP || want GS; then
  log "GP fixture: a fresh wallet and its trial"
  req none - POST /register '{}'
  W_WK=$(j '.api_key // empty'); W_ACC=$(j '.near_account_id // empty')
  BODY=""
  T_PK=""
  if [[ -z "$W_WK" ]] || ! safe_ident "$W_ACC"; then
    fail "GP /register minted no usable wallet (HTTP $HTTP)"
  else
    note "wallet ${W_ACC:0:12}… (wk_ present, length ${#W_WK})"
    req wk "$W_WK" POST /trial-key
    T_PK=$(j '.payment_key // empty'); claim=$(jq -c 'del(.payment_key)' <<<"$BODY" 2>/dev/null); BODY=""
    if [[ -z "$T_PK" ]]; then
      fail "GP trial claim refused: $(short "$claim") — trial_unavailable is the per-IP daily ceiling: DEL trial_key_ip:<this ip> and rerun"
    else
      note "GP trial: $(jq -c '{nonce, calls, expires_at, project_ids}' <<<"$claim")"
    fi
  fi
  W_WK=""
  if [[ -n "$T_PK" ]]; then
    ran=0
    for i in $(seq 1 "$SPEND"); do ping_call "$T_PK"; [[ "$HTTP" == 200 && "$(j .status)" == completed ]] && ran=$((ran + 1)); done
    [[ "$ran" == "$SPEND" ]] && note "GP spent $SPEND trial calls" || fail "GP only $ran of $SPEND trial calls ran (last HTTP $HTTP $(j .reason))"
    settled "$W_ACC" 0 || warn "GP calls still pending — the gift will count their ceiling"
    X=$(q "SELECT allowance_usd FROM payment_keys WHERE owner = '$W_ACC' AND nonce = 0")
    S=$(q "SELECT COALESCE(b.allowance_spent_usd, 0) FROM payment_keys pk LEFT JOIN payment_key_balances b USING (owner, nonce) WHERE pk.owner = '$W_ACC' AND pk.nonce = 0")
    note "GP before the gift: trial allowance X=$X, settled spend S=$S (left $(( X - S )))"
    if (( S > 0 )); then pass "GP the trial is partially spent (S=$S of X=$X)"; else fail "GP nothing settled after $SPEND calls (S=$S) — not a partial trial"; fi
    req admin - POST /admin/grant-subscription "$(jq -nc --arg o "$W_ACC" '{owner:$o, nonce:0, note:"gift-followup GP"}')"
    [[ "$HTTP" == 200 && "$(j .trial_converted)" == true && "$(j .allowance_available_usd)" == "$CAP" ]] \
      && pass "GP gift → 200 trial_converted:true, allowance_available_usd $CAP" || fail "GP gift → HTTP $HTTP: $(short)"
    R=$(q "SELECT trial_converted::text || '|' || COALESCE(trial_allowance_usd::text, 'null') || '|' || allowance_usd FROM payment_keys WHERE owner = '$W_ACC' AND nonce = 0")
    L=$(q "SELECT count(*) || '|' || COALESCE(max(amount_usd)::text, '-') FROM payment_key_grants WHERE owner = '$W_ACC' AND nonce = 0")
    WANT_L=$(( CAP - (X - S) ))
    [[ "$R" == "true|$X|$(( S + CAP ))" ]] \
      && pass "GP DB trial_converted, trial_allowance_usd = $X (the trial's), allowance_usd = S + cap = $(( S + CAP ))" \
      || fail "GP DB trial_converted|trial_allowance|allowance = '$R', expected true|$X|$(( S + CAP ))"
    [[ "$L" == "1|$WANT_L" ]] \
      && pass "GP one ledger row of $WANT_L = cap − (X − S) = $CAP − $(( X - S ))$( [[ $WANT_L == "$S" ]] && echo " = what was spent" || echo " (≠ S=$S: the trial's allowance X=$X is not the cap)")" \
      || fail "GP ledger '$L', expected '1|$WANT_L'"
    req pk "$T_PK" GET /subscription/status
    [[ "$HTTP" == 200 && "$(bool_of trial)" == absent && "$(j .has_subscription)" == true ]] \
      && pass "GP status: no trial block, has_subscription:true, available $(j .allowance_available_usd)" \
      || fail "GP status → HTTP $HTTP: $(jq -c '{has_subscription, trial, allowance_available_usd}' <<<"$BODY" 2>/dev/null)"
    if want GP; then
      total=$ran; stop=""
      while (( total <= TRIAL_LIMIT )); do
        ping_call "$T_PK"
        if [[ "$HTTP" == 200 && "$(j .status)" == completed ]]; then total=$((total + 1)); else stop="HTTP $HTTP $(j .reason)"; break; fi
      done
      n_db=$(q "SELECT count(*) FROM https_calls WHERE owner = '$W_ACC' AND nonce = 0 AND status = 'completed'")
      (( total > TRIAL_LIMIT )) \
        && pass "GP the converted key ran $total calls (> the trial's $TRIAL_LIMIT), none refused; https_calls completed = $n_db" \
        || fail "GP call $((total + 1)) refused ($stop) after $total — the trial limit still applies"
    fi
    # ── GS ──
    if want GS; then
      log "GS the converted trial calls a non-connector project"
      req pk "$T_PK" POST "/call/$ORDINARY_PROJECT" '{"input":{}}'
      [[ "$HTTP" == 403 && "$(j .reason)" == project_not_allowed ]] \
        && pass "GS /call/$ORDINARY_PROJECT with the converted key → 403 project_not_allowed: $(j .error)" \
        || fail "GS /call/$ORDINARY_PROJECT with the converted key → HTTP $HTTP: $(short)"
      pids=$(q "SELECT project_ids::text FROM payment_keys WHERE owner = '$W_ACC' AND nonce = 0")
      [[ "$pids" == "{$CONNECTORS/*}" ]] && pass "GS DB project_ids still $pids" || fail "GS DB project_ids = '$pids'"
    fi
    note "GP/GS wallet: ${W_ACC} (converted trial, nonce 0)"
  fi
  T_PK=""
fi

# ══ D2c: the describe cache across a version switch ══════════════════════════
if want D2c; then
  if [[ "$DESCRIBE_SWITCH" != 1 ]]; then
    skip "D2c describe cache — set DESCRIBE_SWITCH=1 (switches $CONNECTORS/$DESCRIBE_ID's active version for ~3 min)"
  elif [[ ! -f "$CREDS_DIR/$CONNECTORS.json" ]]; then
    skip "D2c no legacy-keychain key for $CONNECTORS"
  else
    DPROJ="$CONNECTORS/$DESCRIBE_ID"
    VERS=$(view list_versions "$(jq -nc --arg p "$DPROJ" '{project_id:$p, limit:50}')")
    ORIG=$(jq -r '.[] | select(.is_active) | .wasm_hash' <<<"$VERS" | head -1)
    ALT=${DESCRIBE_ALT:-$(jq -r --arg o "$ORIG" '[.[] | select(.wasm_hash != $o)] | last | .wasm_hash // empty' <<<"$VERS")}
    if [[ -z "$ORIG" || -z "$ALT" ]]; then
      skip "D2c $DPROJ has no second version (active '${ORIG:0:8}')"
    else
      restore_active() {
        local cur out
        cur=$(view get_project "$(jq -nc --arg p "$DPROJ" '{project_id:$p}')" | jq -r '.active_version // empty')
        [[ "$cur" == "$ORIG" ]] && return 0
        out=$(call "$CONNECTORS" set_active_version "$(jq -nc --arg n "$DESCRIBE_ID" --arg v "$ORIG" '{project_name:$n, version_key:$v}')" '0 NEAR')
        succeeded "$out" && note "restore: $DPROJ active version back to ${ORIG:0:8}" || warn "restore of $DPROJ FAILED: $(why_of "$out") — set_active_version $ORIG by hand"
      }
      EXIT_HOOKS+=(restore_active)
      dver() { # the describe answer's version, or "<HTTP n: first words>"
        local out code
        out=$(command curl -sS --max-time 30 -w $'\n%{http_code}' "$COORDINATOR_URL/public/connectors/$DESCRIBE_ID/describe" 2>/dev/null)
        code=${out##*$'\n'}; out=${out%$'\n'*}
        [[ "$code" == 200 ]] && jq -r '.version // "<no version>"' <<<"$out" || printf '<HTTP %s: %s>' "$code" "$(jq -r '.error // ""' <<<"$out" | head -c 50)"
      }
      # switch <to> <label> — set_active_version, then poll describe every 5 s.
      switch() {
        local to=$1 from out t0 t v first="" changed=""
        from=$(dver)
        out=$(call "$CONNECTORS" set_active_version "$(jq -nc --arg n "$DESCRIBE_ID" --arg v "$to" '{project_name:$n, version_key:$v}')" '0 NEAR')
        succeeded "$out" || { fail "D2c $2: set_active_version ${to:0:8}: $(why_of "$out")"; return 1; }
        t0=$(date +%s)
        for i in $(seq 1 30); do
          v=$(dver); t=$(( $(date +%s) - t0 ))
          [[ -z "$first" ]] && first="$v@${t}s"
          [[ "$v" != "$from" ]] && { changed="$v@${t}s"; break; }
          sleep 5
        done
        note "D2c $2: before '${from:0:16}', first read after the final tx '${first:0:22}', changed to '${changed:0:40}'"
        [[ "${first%@*}" == "$from" ]] && pass "D2c $2: describe still served the old answer (${from:0:12}…) after set_active_version was final" \
          || fail "D2c $2: the first read after the tx already served '${first:0:30}' — the old answer was not kept"
        if [[ -n "$changed" && "${changed##*@}" =~ ^([0-9]+)s$ ]] && (( ${BASH_REMATCH[1]} <= 65 )); then
          pass "D2c $2: the new answer (${changed%@*}) served ${BASH_REMATCH[1]} s after the tx (≤ 60 s TTL + poll)"
        else
          fail "D2c $2: describe did not change within 150 s ('${changed:-no change}')"
        fi
      }
      log "D2c $DPROJ: ${ORIG:0:8} → ${ALT:0:8} → back"
      switch "$ALT" "switch to ${ALT:0:8}" && switch "$ORIG" "switch back to ${ORIG:0:8}"
      restore_active
    fi
  fi
fi

verdict "gift_followup_e2e"
