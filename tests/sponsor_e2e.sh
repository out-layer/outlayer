#!/usr/bin/env bash
#
# Sponsor codes, the derived nonce-0 key and the trial by `near:`, live on
# TESTNET. Every row reads what the coordinator answers
# (src/handlers/sponsor.rs, trial_key.rs, call.rs IN_FLIGHT_SQL,
# operation_limits.rs):
#
#   SP1  admin creates codes; `code` comes back once (GET lists no code);
#        one_per_ip defaults to true with max_uses and false without
#   SP2  a FRESH `near:` wallet (never asked for an address) redeems → 200 with
#        payment_key, sponsor, allowance; GET /wallet/v1/payment-key answers the
#        same string, subscription:true; wallet_accounts.near_pubkey is set
#   SP3  that key runs a wallet-reaching connector call (hyperliquid `status`,
#        free) — `/call` finds the wallet by near_pubkey; with no owner, the
#        policy `effect` is the built-in default
#   SP4  the same wallet redeems the same code again → 200, nothing changed,
#        `uses` still 1; another code while the grant is live → same answer
#   SP5  max_uses: N+1 fresh wallets redeem a max_uses=N code at once → exactly
#        N carry it, the rest 404 sponsor_code_invalid; `uses` = N
#   SP6  one_per_ip: a second wallet from this address → 404
#   SP7  end_now → the key's next connector call is refused; redeeming the same
#        code again does NOT re-grant; another code is taken
#   SP8  extend_days → expires_at moves to ≥ now + days, `extended` counts it
#   SP9  active:false → a new wallet's redeem is 404; admin validation 400s
#   SP10 max_parallel=2: two `sleep` calls in flight run, a third →
#        429 call_already_in_flight
#   SP11 the trial by `near:`: POST /trial-key → 200 (or trial_unavailable at
#        this address's daily ceiling → SKIP); GET payment-key repeats it
#   SP12 GET payment-key: no nonce-0 → 404 no_payment_key; a legacy random
#        trial (TRIAL_WALLET_KEY in .env.testnet-keys) → 409
#        payment_key_not_recoverable
#   SP14 the nonce-0 key is bound to the wk_ that claimed it: another wk_ of
#        the same wallet → 403 payment_key_other_credential, on the GET and on a
#        redeem (which takes no use of the code); the claiming wk_
#        revoked → the key's /call is 401 invalid_key, the GET 409
#        payment_key_revoked
#   SP15 owner policy on hyperliquid: a wallet WITH an owner (policy stored on
#        chain by PARENT): no HL row of the owner's → the built-in default (or,
#        when PARENT's HL row does not name this wallet, `Access denied`);
#        naming the agent's own row → 403 policy_row_not_owner; the next HL call
#        → 403 calls_suspended; connector-probe still answers (the block is the
#        trading connectors' only)
#   SP16 (VAULT_ID=<vault whose parent is PARENT>) a `near:` wallet under a
#        vault: redeem → key owned by the vault-derived account
#        (= /wallet/v1/address); hyperliquid `status` reports the trading
#        sub-key the public address route derives under the same vault — the
#        worker's host functions read the vault the near: request wrote
#   SP13 (CEILING=1, spends NEAR) custody ceiling: a sponsored wallet makes
#        more transfers than `custody:*` allows and none is refused; a
#        bare-trial wallet is refused operation_limit_reached past it
#
# Secrets: the admin bearer, `wk_`s and payment keys reach curl through stdin
# (`-H @-`), bodies that carry a code through a 0600 file, never argv; none is
# printed, and answers that carry one are reduced first. The `near:` bearer is
# a short-lived signature made per request. Scratch files live in a 0700
# directory removed on EXIT, after every code this run created is switched off.
#
# Requires: jq, curl, near-cli, PARENT (a testnet account whose full-access key
# is in ~/.near-credentials — use outlayer-alice.testnet), scripts/.env with
# ADMIN_BEARER_TOKEN_TESTNET. PSQL_CMD for the DB rows (else they SKIP).
#
# Run:
#   PARENT=outlayer-alice.testnet ./tests/sponsor_e2e.sh            # dry run
#   PARENT=outlayer-alice.testnet ./tests/sponsor_e2e.sh --apply
#   PARENT=outlayer-alice.testnet CEILING=1 ./tests/sponsor_e2e.sh --apply

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPLY=false
for a in "$@"; do
  case "$a" in
    --apply) APPLY=true ;;
    -h|--help) awk 'NR>1 && /^#/{sub(/^# ?/,""); print; next} NR>1{exit}' "$0"; exit 0 ;;
    *) echo "unknown argument: $a" >&2; exit 2 ;;
  esac
done

NETWORK=testnet
ENV_FILE="${ENV_FILE:-$SCRIPT_DIR/../scripts/.env}"
if [[ -z "${COORDINATOR_URL:-}" && -r "$ENV_FILE" ]]; then
  COORDINATOR_URL="$(set -a; source "$ENV_FILE" >/dev/null 2>&1; set +a; printf '%s' "${COORDINATOR_URL_TESTNET:-}")"
fi
COORDINATOR_URL="${COORDINATOR_URL:-https://testnet-api.outlayer.ai}"
COORDINATOR_URL="${COORDINATOR_URL%/}"
source "$SCRIPT_DIR/lib/hos_common.sh"

CEILING="${CEILING:-0}"
VAULT_ID="${VAULT_ID:-}"
# The near: bearer, with the vault folded into the signature while TOKEN_VAULT
# is set (SP16). Overrides hos_common's, which signs no vault.
TOKEN_VAULT=""
mk_token() {
  local v=(); [[ -n "$TOKEN_VAULT" ]] && v=(--vault-id "$TOKEN_VAULT")
  CUSTOMER_RECOVERY_PRIVATE_KEY="$PARENT_PRIVKEY" "$RECOVERY_BIN" sign-bearer-near --account-id "$PARENT" --seed "$1" ${v[@]+"${v[@]}"}
}
HL_PROJECT="connectors.outlayer.testnet/hyperliquid"
PROBE_PROJECT="connectors.outlayer.testnet/connector-probe"
RUN="sp$(date +%s)"

RUN_TMP="$(mktemp -d -t sponsor_e2e.XXXXXX)"
chmod 700 "$RUN_TMP"
CODE_IDS=()
cleanup() {
  local id
  for id in ${CODE_IDS[@]+"${CODE_IDS[@]}"}; do
    req admin - PATCH "/admin/sponsor-codes/$id" '{"active":false}' >/dev/null 2>&1
  done
  rm -rf "$RUN_TMP"
}
trap cleanup EXIT

ADMIN_TOKEN=""
if [[ -r "$ENV_FILE" ]]; then
  ADMIN_TOKEN="$(set -a; source "$ENV_FILE" >/dev/null 2>&1; set +a; printf '%s' "${ADMIN_BEARER_TOKEN_TESTNET:-}")"
fi

# ── client ───────────────────────────────────────────────────────────────────

# req <admin|pk|wk> <secret|-> <METHOD> <path> [body] — sets HTTP and BODY;
# the credential goes through stdin, the body through a 0600 file. WALLET_HDR,
# when set, adds `X-Wallet-Id` (not a secret).
WALLET_HDR=""
req() {
  local auth=$1 secret=$2 method=$3 path=$4 body=${5:-} out="$RUN_TMP/body"
  throttle
  local -a args=(-sS -o "$out" -w '%{http_code}' -X "$method" --max-time 150 -H @-)
  [[ -n "$WALLET_HDR" ]] && args+=(-H "X-Wallet-Id: $WALLET_HDR")
  if [[ -n "$body" ]]; then
    ( umask 077; printf '%s' "$body" > "$RUN_TMP/req" )
    args+=(-H 'Content-Type: application/json' --data-binary @"$RUN_TMP/req")
  fi
  args+=("$COORDINATOR_URL$path")
  case "$auth" in
    admin) HTTP=$(printf 'Authorization: Bearer %s\n' "$ADMIN_TOKEN" | curl "${args[@]}" 2>/dev/null) ;;
    pk)    HTTP=$(printf 'X-Payment-Key: %s\n' "$secret" | curl "${args[@]}" 2>/dev/null) ;;
    wk)    HTTP=$(printf 'Authorization: Bearer %s\n' "$secret" | curl "${args[@]}" 2>/dev/null) ;;
  esac
  rm -f "$RUN_TMP/req"
  BODY="$(tr -d '\n' < "$out" 2>/dev/null)"
}
# nreq <seed> <METHOD> <path> [body] — the same under a near: bearer for <seed>
# (a short-lived signature, on argv like hos_common's), the body through a file.
nreq() {
  local seed=$1 method=$2 path=$3 body=${4:-} out="$RUN_TMP/body"
  throttle
  local -a args=(-sS -o "$out" -w '%{http_code}' -X "$method" --max-time 150 -H "Authorization: Bearer near:$(mk_token "$seed")")
  if [[ -n "$body" ]]; then
    ( umask 077; printf '%s' "$body" > "$RUN_TMP/req" )
    args+=(-H 'Content-Type: application/json' --data-binary @"$RUN_TMP/req")
  fi
  HTTP=$(curl "${args[@]}" "$COORDINATOR_URL$path" 2>/dev/null)
  rm -f "$RUN_TMP/req"
  BODY="$(tr -d '\n' < "$out" 2>/dev/null)"
}
j() { jq -r "$1" <<<"$BODY" 2>/dev/null; }
short() { head -c "${2:-220}" <<<"${1:-$BODY}"; }
seed() { printf '%s-%s' "$RUN" "$1"; }
q() { sql "$1" 2>/dev/null; }
HAVE_SQL=false

# redeem <seed> <code> — sets HTTP, BODY (key removed), PK (the key or "").
redeem() {
  nreq "$1" POST /wallet/v1/sponsorship "$(jq -nc --arg c "$2" '{code:$c}')"
  PK=$(j '.payment_key // empty'); BODY=$(jq -c 'del(.payment_key)' <<<"$BODY" 2>/dev/null || printf '%s' "$BODY")
}
# create_code <json> — sets CODE_ID and CODE (secret, never printed).
create_code() {
  req admin - POST /admin/sponsor-codes "$1"
  CODE_ID=$(j '.id // empty'); CODE=$(j '.code // empty')
  [[ -n "$CODE_ID" ]] && CODE_IDS+=("$CODE_ID")
  BODY=$(jq -c 'del(.code)' <<<"$BODY" 2>/dev/null)
}
code_uses() { # code_uses <id> — uses|live from the admin list
  req admin - GET /admin/sponsor-codes
  jq -r --arg id "$1" '.codes[] | select(.id == $id) | "\(.uses)|\(.live)"' <<<"$BODY" 2>/dev/null
}
# wallet_of <seed> — the near: wallet's id (for X-Wallet-Id).
wallet_of() { nreq "$1" GET "/wallet/v1/address?chain=near"; j '.wallet_id // empty'; }
# hl_call <pk> <wallet_id> <input-json> [secrets_ref-json] — sets HTTP, BODY and
# OUT (the connector's own output object). The wallet goes in X-Wallet-Id:
# without it the run has no wallet.
hl_call() {
  local body; body=$(jq -nc --argjson i "$3" --argjson r "${4:-null}" '{input:$i} + (if $r == null then {} else {secrets_ref:$r} end)')
  WALLET_HDR="$2" req pk "$1" POST "/call/$HL_PROJECT" "$body"
  OUT=$(jq -c '.output | if type=="string" then (fromjson? // {}) else . end | .output // . | if type=="string" then (fromjson? // {}) else . end' <<<"$BODY" 2>/dev/null)
}
hl_status() { # hl_status <pk> <wallet_id> — sets HTTP, BODY, OUT, NETWORK_SEEN, EFFECT
  hl_call "$1" "$2" '{"operation":"status"}'
  NETWORK_SEEN=$(jq -r '.network // empty' <<<"$OUT" 2>/dev/null)
  EFFECT=$(jq -r '.policy.effect // empty' <<<"$OUT" 2>/dev/null)
}

# ── preflight ────────────────────────────────────────────────────────────────

log "sponsor_e2e — $NETWORK, $( [[ $APPLY == true ]] && echo APPLY || echo 'dry run' ), run $RUN"
note "coordinator: ${COORDINATOR_URL#*://}"
hos_require
if [[ -n "$ADMIN_TOKEN" ]]; then note "admin bearer: present (length ${#ADMIN_TOKEN})"
else echo "✗ admin bearer ABSENT (ADMIN_BEARER_TOKEN_TESTNET in $ENV_FILE)" >&2; exit 1; fi
if sql_alive; then HAVE_SQL=true; note "PSQL_CMD: answers"; else warn "PSQL_CMD: unset or silent — DB checks SKIP"; fi

if [[ "$APPLY" != true ]]; then
  cat >&2 <<'EOF'
  (dry-run) with --apply this suite will mint sponsor codes on testnet (allowance
  $0.10 each, 1–2 days), derive ~12 `near:` wallets from PARENT with run-unique
  seeds, redeem, call connector-probe / hyperliquid `status`, extend and end the
  codes. CEILING=1 also funds two wallets with NEAR and makes ~2×(limit+1)
  transfers.
EOF
  exit 0
fi

ALLOW=100000   # $0.10 of allowance per grant

# ── SP1 ──────────────────────────────────────────────────────────────────────
log "SP1 codes"
create_code "{\"name\":\"$RUN-a\",\"allowance_usd\":\"$ALLOW\",\"grant_days\":1,\"max_parallel\":2}"
A_ID=$CODE_ID; A=$CODE
[[ "$HTTP" == 201 && -n "$A" && "$(j .one_per_ip)" == false && "$(j .max_parallel)" == 2 ]] \
  && pass "SP1 uncapped code → 201, code once, one_per_ip defaults false" || fail "SP1 code A → HTTP $HTTP: $(short)"
create_code "{\"name\":\"$RUN-b\",\"allowance_usd\":\"$ALLOW\",\"grant_days\":1}"; B_ID=$CODE_ID; B=$CODE
create_code "{\"name\":\"$RUN-m\",\"allowance_usd\":\"$ALLOW\",\"grant_days\":1,\"max_uses\":2,\"one_per_ip\":false}"; M_ID=$CODE_ID; M=$CODE
create_code "{\"name\":\"$RUN-v\",\"allowance_usd\":\"$ALLOW\",\"grant_days\":1,\"max_uses\":5}"; V_ID=$CODE_ID; V=$CODE
[[ "$HTTP" == 201 && "$(j .one_per_ip)" == true ]] && pass "SP1 capped code → one_per_ip defaults true" \
  || fail "SP1 code V → HTTP $HTTP: $(short)"
req admin - GET /admin/sponsor-codes
[[ "$HTTP" == 200 && "$(jq '[.codes[] | has("code")] | any' <<<"$BODY")" == false ]] \
  && pass "SP1 the list carries no code" || fail "SP1 list → HTTP $HTTP, a code in it?"

# ── SP2 / SP3 ────────────────────────────────────────────────────────────────
log "SP2 a fresh near: wallet redeems"
W1=$(seed w1)
redeem "$W1" "$A"; W1_PK=$PK
[[ "$HTTP" == 200 && -n "$W1_PK" && "$(j .sponsor)" == "$RUN-a" && "$(j .allowance_usd)" == "$ALLOW" ]] \
  && pass "SP2 redeem → 200, key, sponsor $RUN-a, allowance $ALLOW" || fail "SP2 redeem → HTTP $HTTP: $(short)"
nreq "$W1" GET /wallet/v1/payment-key
[[ "$HTTP" == 200 && "$(j .payment_key)" == "$W1_PK" && "$(j .subscription)" == true ]] \
  && pass "SP2 GET payment-key answers the same key, subscription:true" || fail "SP2 GET payment-key → HTTP $HTTP"
W1_OWNER=${W1_PK%%:*}
if $HAVE_SQL; then
  n=$(q "SELECT COUNT(*) FROM wallet_accounts WHERE regexp_replace(near_pubkey,'^ed25519:','') = '$W1_OWNER'")
  [[ "$n" == 1 ]] && pass "SP2 wallet_accounts.near_pubkey written by the redeem" || fail "SP2 near_pubkey rows: '$n'"
else skip "SP2 near_pubkey — PSQL_CMD"; fi
log "SP3 the key reaches the wallet through a connector"
W1_WID=$(wallet_of "$W1")
hl_status "$W1_PK" "$W1_WID"
[[ "$HTTP" == 200 && "$NETWORK_SEEN" == testnet ]] && pass "SP3 hyperliquid status on the sponsored key → network testnet" \
  || fail "SP3 hyperliquid status → HTTP $HTTP: $(short)"
[[ "$EFFECT" == default:* ]] && pass "SP3 no owner, no policy → the built-in default" || fail "SP3 policy effect: '$EFFECT'"

# ── SP4 ──────────────────────────────────────────────────────────────────────
log "SP4 repeat redeems while the grant is live"
redeem "$W1" "$A"
[[ "$HTTP" == 200 && "$(j .sponsor)" == "$RUN-a" && "$(j .note)" == *"nothing was changed"* ]] \
  && pass "SP4 same code again → 200, nothing changed" || fail "SP4 same code → HTTP $HTTP: $(short)"
redeem "$W1" "$B"
[[ "$HTTP" == 200 && "$(j .sponsor)" == "$RUN-a" ]] && pass "SP4 another code while live → still $RUN-a" \
  || fail "SP4 other code → HTTP $HTTP: $(short)"
[[ "$(code_uses "$A_ID")" == "1|1" && "$(code_uses "$B_ID" | cut -d'|' -f1)" == 0 ]] \
  && pass "SP4 uses: A 1, B 0" || fail "SP4 uses A=$(code_uses "$A_ID") B=$(code_uses "$B_ID")"

# ── SP5 ──────────────────────────────────────────────────────────────────────
log "SP5 max_uses=2 under 4 simultaneous redeems"
for i in 1 2 3 4; do
  ( RUN_TMP_SUB="$RUN_TMP/m$i.d"; mkdir -p "$RUN_TMP_SUB"; RUN_TMP="$RUN_TMP_SUB"
    nreq "$(seed m$i)" POST /wallet/v1/sponsorship "$(jq -nc --arg c "$M" '{code:$c}')"
    printf '%s' "$HTTP" > "$RUN_TMP/../m$i" ) &
done
wait
ok=0; refused=0
for i in 1 2 3 4; do c=$(cat "$RUN_TMP/m$i"); [[ $c == 200 ]] && ok=$((ok+1)); [[ $c == 404 ]] && refused=$((refused+1)); done
[[ $ok == 2 && $refused == 2 && "$(code_uses "$M_ID" | cut -d'|' -f1)" == 2 ]] \
  && pass "SP5 exactly 2 redeemed, 2 refused, uses 2" || fail "SP5 ok=$ok refused=$refused uses=$(code_uses "$M_ID")"

# ── SP6 ──────────────────────────────────────────────────────────────────────
log "SP6 one_per_ip"
redeem "$(seed v1)" "$V"; c1=$HTTP
redeem "$(seed v2)" "$V"
[[ $c1 == 200 && "$HTTP" == 404 && "$(j .reason)" == sponsor_code_invalid ]] \
  && pass "SP6 second wallet from this address → 404 sponsor_code_invalid" || fail "SP6 first=$c1 second=$HTTP: $(short)"
for hint in address ip limit; do
  grep -qiw "$hint" <<<"$(j .error)" && fail "SP6 the refusal names '$hint': $(j .error)"
done

# ── SP7 ──────────────────────────────────────────────────────────────────────
log "SP7 end_now, then the same code and another"
req admin - PATCH "/admin/sponsor-codes/$A_ID" '{"end_now":true}'
[[ "$HTTP" == 200 && "$(j .ended)" -ge 1 ]] && pass "SP7 end_now → ended $(j .ended)" || fail "SP7 end_now → HTTP $HTTP: $(short)"
req pk "$W1_PK" POST "/call/$PROBE_PROJECT" '{"input":{"operation":"ping"}}'
case "$(j .reason)" in
  out_of_funds|expires_too_soon|insufficient_allowance) pass "SP7 the ended key's call → HTTP $HTTP $(j .reason)" ;;
  *) fail "SP7 ended key → HTTP $HTTP $(j .reason)" ;;
esac
redeem "$W1" "$A"
[[ "$HTTP" == 200 && "$(j .sponsor)" == "$RUN-a" && "$(code_uses "$A_ID" | cut -d'|' -f1)" == 1 ]] \
  && pass "SP7 same code after end → not re-granted, uses still 1" || fail "SP7 same code after end → HTTP $HTTP: $(short)"
redeem "$W1" "$B"
[[ "$HTTP" == 200 && "$(j .sponsor)" == "$RUN-b" ]] && pass "SP7 another code after end → taken ($RUN-b)" \
  || fail "SP7 other code after end → HTTP $HTTP: $(short)"

# ── SP8 ──────────────────────────────────────────────────────────────────────
log "SP8 extend_days"
req admin - PATCH "/admin/sponsor-codes/$B_ID" '{"extend_days":2}'
[[ "$HTTP" == 200 && "$(j .extended)" == 1 ]] && pass "SP8 extend_days 2 → extended 1" || fail "SP8 → HTTP $HTTP: $(short)"
nreq "$W1" GET /wallet/v1/payment-key
exp=$(j .expires_at); left=$(( $(date -d "$exp" +%s 2>/dev/null || python3 -c 'import sys,datetime;print(int(datetime.datetime.fromisoformat(sys.argv[1].replace("Z","+00:00")).timestamp()))' "$exp") - $(date +%s) ))
(( left > 2*86400 - 600 )) && pass "SP8 expires_at ≥ now + 2 days" || fail "SP8 expires in ${left}s"

# ── SP9 ──────────────────────────────────────────────────────────────────────
log "SP9 switched off, and admin validation"
req admin - PATCH "/admin/sponsor-codes/$V_ID" '{"active":false}'
redeem "$(seed v3)" "$V"
[[ "$HTTP" == 404 ]] && pass "SP9 active:false → 404" || fail "SP9 → HTTP $HTTP: $(short)"
for body in '{"name":"x","allowance_usd":"999999999999"}' '{"name":"x","grant_days":0}' '{"name":"x","max_parallel":0}' '{"name":"x","max_uses":0}'; do
  req admin - POST /admin/sponsor-codes "$body"
  [[ "$HTTP" == 400 ]] && pass "SP9 $body → 400" || fail "SP9 $body → HTTP $HTTP"
done
req admin - PATCH "/admin/sponsor-codes/$B_ID" '{"extend_days":1,"end_now":true}'
[[ "$HTTP" == 400 ]] && pass "SP9 extend_days + end_now → 400" || fail "SP9 contradiction → HTTP $HTTP"

# ── SP10 ─────────────────────────────────────────────────────────────────────
log "SP10 max_parallel=2"
create_code "{\"name\":\"$RUN-p\",\"allowance_usd\":\"$ALLOW\",\"grant_days\":1,\"max_parallel\":2}"; P=$CODE
redeem "$(seed p1)" "$P"; P_PK=$PK
for i in 1 2; do
  req pk "$P_PK" POST "/call/$PROBE_PROJECT" '{"input":{"operation":"sleep","seconds":20},"async":true}'
  echo "$HTTP" > "$RUN_TMP/p$i"
done
req pk "$P_PK" POST "/call/$PROBE_PROJECT" '{"input":{"operation":"sleep","seconds":20},"async":true}'
[[ "$(cat "$RUN_TMP/p1")" =~ ^2 && "$(cat "$RUN_TMP/p2")" =~ ^2 && "$HTTP" == 429 && "$(j .reason)" == call_already_in_flight ]] \
  && pass "SP10 two in flight run, the third → 429 call_already_in_flight" \
  || fail "SP10 p1=$(cat "$RUN_TMP/p1") p2=$(cat "$RUN_TMP/p2") third=$HTTP $(j .reason)"

# ── SP11 ─────────────────────────────────────────────────────────────────────
log "SP11 the trial by near:"
T=$(seed t1)
nreq "$T" POST /trial-key
if [[ "$HTTP" == 200 ]]; then
  t_pk=$(j .payment_key); BODY=""
  nreq "$T" GET /wallet/v1/payment-key
  [[ "$(j .payment_key)" == "$t_pk" && "$(j .subscription)" == false ]] \
    && pass "SP11 near: trial → 200; GET repeats it, subscription:false" || fail "SP11 GET → HTTP $HTTP"
  nreq "$T" POST /trial-key
  [[ "$HTTP" == 409 && "$(j .reason)" == trial_already_claimed ]] && pass "SP11 second claim → 409" || fail "SP11 second claim → HTTP $HTTP"
elif [[ "$(j .reason)" == trial_unavailable ]]; then
  skip "SP11 this address is at its daily trial ceiling (trial_unavailable)"
else
  fail "SP11 near: trial → HTTP $HTTP: $(short)"
fi

# ── SP12 ─────────────────────────────────────────────────────────────────────
log "SP12 payment-key refusals"
nreq "$(seed none)" GET /wallet/v1/payment-key
[[ "$HTTP" == 404 && "$(j .reason)" == no_payment_key ]] && pass "SP12 no nonce-0 → 404 no_payment_key" || fail "SP12 → HTTP $HTTP: $(short)"
LEGACY_WK="$(set -a; source "$SCRIPT_DIR/../.env.testnet-keys" >/dev/null 2>&1; set +a; printf '%s' "${TRIAL_WALLET_KEY:-}")"
if [[ -n "$LEGACY_WK" ]]; then
  req wk "$LEGACY_WK" GET /wallet/v1/payment-key
  [[ "$HTTP" == 409 && "$(j .reason)" == payment_key_not_recoverable ]] \
    && pass "SP12 a legacy random trial → 409 payment_key_not_recoverable" || fail "SP12 legacy → HTTP $HTTP: $(short)"
else skip "SP12 legacy trial — TRIAL_WALLET_KEY absent"; fi

# ── SP14 ─────────────────────────────────────────────────────────────────────
log "SP14 the nonce-0 key is bound to the wk_ that claimed it"
SUB=$(seed sub)
K1="wk_$(openssl rand -hex 32)"; K1_HASH=$(printf '%s' "$K1" | shasum -a 256 | cut -d' ' -f1)
K2="wk_$(openssl rand -hex 32)"; K2_HASH=$(printf '%s' "$K2" | shasum -a 256 | cut -d' ' -f1)
K_SEED=$(seed bind)
nreq "$K_SEED" PUT /wallet/v1/api-key "$(jq -nc --arg s "$SUB" --arg h "$K1_HASH" '{seed:$s, key_hash:$h}')" ; r1=$HTTP
nreq "$K_SEED" PUT /wallet/v1/api-key "$(jq -nc --arg s "$SUB" --arg h "$K2_HASH" '{seed:$s, key_hash:$h}')"; r2=$HTTP
if [[ $r1 =~ ^2 && $r2 =~ ^2 ]]; then
  create_code "{\"name\":\"$RUN-k\",\"allowance_usd\":\"$ALLOW\",\"grant_days\":1}"
  req wk "$K1" POST /wallet/v1/sponsorship "$(jq -nc --arg c "$CODE" '{code:$c}')"
  K_PK=$(j '.payment_key // empty'); BODY=""
  [[ "$HTTP" == 200 && -n "$K_PK" ]] && pass "SP14 redeemed with wk_ #1" || fail "SP14 redeem with wk_ #1 → HTTP $HTTP"
  req wk "$K2" GET /wallet/v1/payment-key
  [[ "$HTTP" == 403 && "$(j .reason)" == payment_key_other_credential ]] \
    && pass "SP14 wk_ #2 of the same wallet → 403 payment_key_other_credential" || fail "SP14 wk_ #2 → HTTP $HTTP: $(short)"
  create_code "{\"name\":\"$RUN-k2\",\"allowance_usd\":\"$ALLOW\",\"grant_days\":1,\"max_uses\":1,\"one_per_ip\":false}"; K2_CODE_ID=$CODE_ID
  req wk "$K2" POST /wallet/v1/sponsorship "$(jq -nc --arg c "$CODE" '{code:$c}')"
  k2_http=$HTTP; k2_reason=$(j .reason)
  [[ "$k2_http" == 403 && "$k2_reason" == payment_key_other_credential && "$(code_uses "$K2_CODE_ID")" == 0\|* ]] \
    && pass "SP14 wk_ #2 redeems → 403 payment_key_other_credential, no use taken" \
    || fail "SP14 wk_ #2 redeem → HTTP $k2_http $k2_reason, uses|live $(code_uses "$K2_CODE_ID")"
  req wk "$K2" DELETE "/wallet/v1/api-key/$K1_HASH"
  [[ "$HTTP" =~ ^2 ]] && pass "SP14 wk_ #1 revoked" || fail "SP14 revoke → HTTP $HTTP: $(short)"
  req pk "$K_PK" POST "/call/$PROBE_PROJECT" '{"input":{"operation":"ping"}}'
  [[ "$HTTP" == 401 && "$(j .reason)" == invalid_key ]] && pass "SP14 the key after its wk_ was revoked → 401 invalid_key" \
    || fail "SP14 revoked key's call → HTTP $HTTP: $(short)"
  req wk "$K2" GET /wallet/v1/payment-key
  [[ "$HTTP" == 409 && "$(j .reason)" == payment_key_revoked ]] && pass "SP14 GET → 409 payment_key_revoked" \
    || fail "SP14 GET after revoke → HTTP $HTTP: $(short)"
else
  fail "SP14 could not register two wk_ keys (HTTP $r1 / $r2)"
fi

# ── SP15 ─────────────────────────────────────────────────────────────────────
log "SP15 the owner's policy on hyperliquid"
O=$(seed owned)
read -r O_WID O_ADDR < <(wallet_address "$O") || true
if [[ -n "${O_WID:-}" ]] && store_policy "$O" "$O_WID" '{"rules":{"transaction_types":["call"]}}'; then
  note "owned wallet ${O_ADDR:0:12}… — owner $PARENT"
  create_code "{\"name\":\"$RUN-o\",\"allowance_usd\":\"$ALLOW\",\"grant_days\":1}"
  redeem "$O" "$CODE"; O_PK=$PK
  hl_status "$O_PK" "$O_WID"
  if [[ "$HTTP" == 200 && "$EFFECT" == default:* ]]; then
    pass "SP15 owner with no HL row → the built-in default"
  elif grep -qi "access denied" <<<"$BODY"; then
    pass "SP15 PARENT's HL row does not name this wallet → Access denied (the owner adds the wallet)"
  else
    fail "SP15 status → HTTP $HTTP effect '$EFFECT': $(short)"
  fi
  hl_call "$O_PK" "$O_WID" '{"operation":"status"}' "$(jq -nc --arg a "$O_ADDR" '{account_id:$a, profile:"hyperliquid"}')"
  [[ "$HTTP" == 403 && "$(j .reason)" == policy_row_not_owner ]] && pass "SP15 own row → 403 policy_row_not_owner" \
    || fail "SP15 own row → HTTP $HTTP: $(short)"
  hl_status "$O_PK" "$O_WID"
  [[ "$HTTP" == 403 && "$(j .reason)" == calls_suspended ]] && pass "SP15 the next HL call → 403 calls_suspended" \
    || fail "SP15 after the offence → HTTP $HTTP: $(short)"
  for hint in minute minutes hour day limit 10 600; do
    grep -qiw "$hint" <<<"$(j .error)" && fail "SP15 the block names '$hint': $(j .error)"
  done
  WALLET_HDR="" req pk "$O_PK" POST "/call/$PROBE_PROJECT" '{"input":{"operation":"ping"}}'
  [[ "$HTTP" == 200 ]] && pass "SP15 connector-probe still answers (the block is the trading connectors' only)" \
    || fail "SP15 connector-probe while blocked → HTTP $HTTP: $(short)"
else
  fail "SP15 could not give the wallet an owner"
fi

# ── SP16 ─────────────────────────────────────────────────────────────────────
if [[ -n "$VAULT_ID" ]]; then
  log "SP16 a near: wallet under vault $VAULT_ID"
  TOKEN_VAULT="$VAULT_ID"
  VS=$(seed vault)
  create_code "{\"name\":\"$RUN-vault\",\"allowance_usd\":\"$ALLOW\",\"grant_days\":1}"
  redeem "$VS" "$CODE"; V_PK=$PK
  nreq "$VS" GET "/wallet/v1/address?chain=near"; V_ADDR=$(j .address); V_WID=$(j .wallet_id)
  [[ -n "$V_PK" && "${V_PK%%:*}" == "$V_ADDR" ]] && pass "SP16 the key is owned by the vault-derived account" \
    || fail "SP16 key owner ${V_PK%%:*} vs address $V_ADDR"
  nreq "$VS" GET "/wallet/v1/address?chain=ethereum&sub_path=connector.hyperliquid.trading"
  V_SUB=$(j '.address // empty'); sub_http=$HTTP
  TOKEN_VAULT=""
  hl_status "$V_PK" "$V_WID"
  V_TRADING=$(jq -r '.addresses.trading // empty' <<<"$OUT")
  if [[ "$sub_http" == 200 && -n "$V_SUB" ]]; then
    lc() { tr '[:upper:]' '[:lower:]' <<<"$1"; }
    [[ -n "$V_TRADING" && "$(lc "$V_TRADING")" == "$(lc "$V_SUB")" ]] \
      && pass "SP16 the connector's trading sub-key is the vault's ($V_TRADING)" \
      || fail "SP16 connector trading ${V_TRADING:-?} ≠ vault sub-key $V_SUB — host functions used another master"
  else
    skip "SP16 the public route did not derive the connector sub-key (HTTP $sub_http) — compare by hand: status trading = ${V_TRADING:-?}"
  fi
  if $HAVE_SQL; then
    wv=$(q "SELECT vault_id FROM wallet_accounts WHERE regexp_replace(near_pubkey,'^ed25519:','') = '$V_ADDR'" | tr -d ' ')
    [[ "$wv" == "$VAULT_ID" ]] && pass "SP16 wallet_accounts.vault_id written by the near: request" || fail "SP16 vault_id '$wv'"
  fi
else
  skip "SP16 vault — VAULT_ID=<a vault whose parent is PARENT>"
fi

# ── SP13 ─────────────────────────────────────────────────────────────────────
if [[ "$CEILING" == 1 ]]; then
  log "SP13 the custody ceiling: sponsored lifts it, a bare trial does not"
  LIMIT=$($HAVE_SQL && q "SELECT max_count FROM operation_limits WHERE operation = 'custody:*' AND applies = 'unpaid'" | tr -d ' ')
  if [[ ! "$LIMIT" =~ ^[0-9]+$ ]]; then
    skip "SP13 no custody:* unpaid rule on testnet (or no PSQL_CMD)"
  else
    for who in sponsored trial; do
      S=$(seed "ce-$who")
      nreq "$S" GET "/wallet/v1/address?chain=near"; addr=$(j .address)
      fund_account "$addr" 0.2 || { fail "SP13 could not fund $who"; continue; }
      # The other wallet holds nothing or a bare trial — pay-as-you-go either way.
      if [[ $who == sponsored ]]; then create_code "{\"name\":\"$RUN-ce\",\"allowance_usd\":\"$ALLOW\",\"grant_days\":1}"; redeem "$S" "$CODE"
      else nreq "$S" POST /trial-key; fi
      refused_at=""
      for n in $(seq 1 $((LIMIT + 1))); do
        nreq "$S" POST /wallet/v1/transfer "{\"to\":\"$PARENT\",\"amount\":\"1000000000000000000\"}"
        [[ "$BODY" == *"limit reached:"*"for custody:"* ]] && { refused_at=$n; break; }
      done
      if [[ $who == sponsored ]]; then
        [[ -z "$refused_at" ]] && pass "SP13 sponsored: $((LIMIT + 1)) transfers, none refused" || fail "SP13 sponsored refused at $refused_at"
      else
        [[ "$refused_at" == $((LIMIT + 1)) ]] && pass "SP13 bare trial refused at $((LIMIT + 1))" || fail "SP13 bare trial refused at '${refused_at:-never}'"
      fi
    done
  fi
else
  skip "SP13 custody ceiling — CEILING=1 (spends NEAR, ~$((2 * 101)) transfers)"
fi

verdict
