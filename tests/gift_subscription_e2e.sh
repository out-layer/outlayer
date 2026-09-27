#!/usr/bin/env bash
#
# Gifted subscriptions and the subscription-purchase refusals, live on TESTNET
# (.idea/_todo/release-test-plan.md §9b G1–G12, §9c S1–S6, §9d D1–D5).
#
# HTTP only. Nothing here signs a NEAR transaction: the wallets are minted by
# the coordinator (`POST /register`), their keys are trial keys
# (`POST /trial-key`, no chain), and the gifts are admin grants
# (`POST /admin/grant-subscription`, no money). A row that needs an on-chain
# action says so as a SKIP with the reason.
#
# What each row pins, and against what the coordinator actually answers
# (src/handlers/grant_keys.rs, subscription_api.rs, trial_key.rs,
# connector_describe.rs, middleware/ip_rate_limit.rs):
#   G1  a fresh wallet's trial, gifted with defaults → 200 trial_converted:true,
#       allowance_available_usd = GIFT_SUBSCRIPTION_USD, expires_at = now + the
#       gift days; DB trial_converted, trial_allowance_usd = the trial's
#       allowance, one payment_key_grants row = gift − what the trial had left
#   G2  the converted key: status without a `trial` block, has_subscription;
#       a connector call runs from the allowance (LONG=1: 51 calls, none refused)
#   G3  spend, gift again → available back to the cap, end not earlier, a
#       ledger row = what was spent; a gift onto a full key → 200, no row
#   G4  a customer's key (nonce ≥ 1, no allowance, some balance; picked from
#       the DB, or G4_OWNER/G4_NONCE) → 200 trial_converted:false, balance and
#       is_grant untouched; a shorter second gift keeps the later end
#   G5  /admin/grant-keys lists the converted trial, not a claimed untouched one
#   G6  /admin/earnings counts the converted trial once, at its trial
#       allowance, plus each ledger row; /admin/connector-calls shows the
#       converted trial's call paid_by_grant
#   G8  amount_usd cap+1 / "0" / "abc" → 400 naming GIFT_SUBSCRIPTION_USD; days
#       0 / 3651 → 400; the key untouched
#   G9  a key that can already spend more than the gift → 409, unchanged
#   G10 unknown (owner, nonce) → 404; nonce 0 of an unclaimed wallet → 404
#       naming POST /trial-key
#   G11 grant-payment-key on nonce 0 → 400 naming grant-subscription;
#       grant-subscription without the bearer → 401
#   S1  purchase on a trial key, converted or not → 400
#       trial_key_not_purchasable, terminal, names create-payment-key; nothing
#       spent
#   S2  (FUNDED_KEY_FILE) invalid amount_usd → 400 invalid_request
#   S3  PUT /subscription/notifications webhook 127.0.0.1 → 400
#       invalid_request "webhook_url: …", nothing stored
#   S4  (FUNDED_KEY_FILE + S4_BUY=1) the cheapest plan bought → 200
#   S5  the trial claim is scoped to connectors and counted in calls (LONG=1:
#       the calls, then 402 trial_exhausted)
#   D2  describe: unknown id → 404; a registry connector with no project → 404
#       "… is not published on testnet" when one exists
#   D3  70 describe GETs in a minute → 429 with exactly
#       `Too many requests. Try again later.`, no digit, no Retry-After
#   D4  no response met in this run carries an RPC key; 503 / chain_unavailable
#       bodies carry no URL
#
# Secrets: the admin bearer, the `wk_`s and the payment keys reach curl through
# stdin (`-H @-`), never argv, and are never printed. Responses that carry one
# (`/register`, `/trial-key`) are reduced to their other fields before anything
# is shown. Scratch files live in a 0700 directory removed on EXIT.
#
# Requires: jq, curl, python3; `scripts/.env` with ADMIN_BEARER_TOKEN_TESTNET
# (and COORDINATOR_URL_TESTNET); PSQL_CMD for the DB rows (one SQL statement,
# tuples only, testnet db `offchainvm`) — without it those checks SKIP.
#
# Run:
#   PSQL_CMD=/path/to/psql_testnet.sh ./tests/gift_subscription_e2e.sh           # dry run
#   PSQL_CMD=/path/to/psql_testnet.sh LONG=1 ./tests/gift_subscription_e2e.sh --apply
# ADOPT_IDLE_TRIAL=1: when this address is refused a fresh trial
# (`trial_unavailable`), the admin-side rows (G1 DB, G3 full-key, G5, G6, G8)
# run on an EXPIRED, idle, test-minted trial picked from the DB instead; the
# rows that need the key's secret (G2, S1, S3, the G3 spend half) then SKIP.
# Optional: FUNDED_KEY_FILE=<0600 file holding owner:nonce:key, nonce ≥ 1> for
# S2 (and S4 with S4_BUY=1 — spends that key's balance on the cheapest plan);
# GIFT_DAYS (default 30) when the deployment sets GIFT_SUBSCRIPTION_DAYS.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPLY=false
for a in "$@"; do
  case "$a" in
    --apply) APPLY=true ;;
    -h|--help) sed -n '2,70p' "$0"; exit 0 ;;
    *) echo "unknown argument: $a" >&2; exit 2 ;;
  esac
done

NETWORK=testnet
ENV_FILE="${ENV_FILE:-$SCRIPT_DIR/../scripts/.env}"
# Not a secret, and read the same way the admin bearer is: from the file, in
# this process, without printing it.
if [[ -z "${COORDINATOR_URL:-}" && -r "$ENV_FILE" ]]; then
  COORDINATOR_URL="$(set -a; source "$ENV_FILE" >/dev/null 2>&1; set +a; printf '%s' "${COORDINATOR_URL_TESTNET:-}")"
fi
COORDINATOR_URL="${COORDINATOR_URL:-https://testnet-api.outlayer.ai}"
COORDINATOR_URL="${COORDINATOR_URL%/}"
source "$SCRIPT_DIR/lib/hos_common.sh"

LONG="${LONG:-0}"
GIFT_DAYS="${GIFT_DAYS:-30}"
PROJECT="${PROJECT:-connectors.outlayer.testnet/connector-probe}"
DESCRIBE_ID="${DESCRIBE_ID:-mercury}"
ADOPT_IDLE_TRIAL="${ADOPT_IDLE_TRIAL:-0}"

RUN_TMP="$(mktemp -d -t gift_e2e.XXXXXX)"
chmod 700 "$RUN_TMP"
trap 'rm -rf "$RUN_TMP"' EXIT
: > "$RUN_TMP/non2xx"

ADMIN_TOKEN=""
if [[ -r "$ENV_FILE" ]]; then
  ADMIN_TOKEN="$(set -a; source "$ENV_FILE" >/dev/null 2>&1; set +a; printf '%s' "${ADMIN_BEARER_TOKEN_TESTNET:-}")"
fi

# ── client ───────────────────────────────────────────────────────────────────

# The one header that authenticates a request, on stdout, for `curl -H @-`.
auth_header() { # auth_header <none|admin|wk|pk> <secret>
  case "$1" in
    admin) printf 'Authorization: Bearer %s\n' "$ADMIN_TOKEN" ;;
    wk)    printf 'Authorization: Bearer %s\n' "$2" ;;
    pk)    printf 'X-Payment-Key: %s\n' "$2" ;;
    *)     printf 'X-Suite: gift-subscription-e2e\n' ;;
  esac
}

# req <none|admin|wk|pk> <secret|-> <METHOD> <path> [body] — sets HTTP, BODY,
# and HDRS (the response headers file). A non-2xx body is kept for D4.
HDRS="$RUN_TMP/hdr"
req() {
  local auth=$1 secret=$2 method=$3 path=$4 body=${5:-}
  local out="$RUN_TMP/body"
  throttle
  local -a args=(-sS -o "$out" -D "$HDRS" -w '%{http_code}' -X "$method" --max-time 150 -H @-)
  [[ -n "$body" ]] && args+=(-H 'Content-Type: application/json' --data-binary "$body")
  args+=("$COORDINATOR_URL$path")
  HTTP=$(auth_header "$auth" "$secret" | curl "${args[@]}" 2>/dev/null)
  BODY="$(tr -d '\n' < "$out" 2>/dev/null)"
  if [[ ! "$HTTP" =~ ^2 && "$path" != /register && "$path" != /trial-key ]]; then
    printf '%s %s %s\n' "$HTTP" "$path" "$BODY" >> "$RUN_TMP/non2xx"
  fi
}

j()     { jq -r "$1" <<<"$BODY" 2>/dev/null; }
short() { head -c "${2:-220}" <<<"${1:-$BODY}"; }
# What a status or gift answer says, for evidence lines.
epoch() { python3 -c 'import sys,datetime;print(int(datetime.datetime.fromisoformat(sys.argv[1].strip().replace("Z","+00:00").replace(" ","T")).timestamp()))' "$1" 2>/dev/null; }
now_rfc() { date -u +%Y-%m-%dT%H:%M:%SZ; }

HAVE_SQL=false
q() { sql "$1" 2>/dev/null; }
safe_ident() { [[ "$1" =~ ^[A-Za-z0-9._-]+$ ]]; }

# ── fixtures ─────────────────────────────────────────────────────────────────

# register_wallet — a coordinator-minted wallet. Sets REG_WK, REG_ACCOUNT.
register_wallet() {
  REG_WK=""; REG_ACCOUNT=""
  req none - POST /register '{}'
  REG_WK=$(j '.api_key // empty'); REG_ACCOUNT=$(j '.near_account_id // empty')
  local shown; shown=$(jq -c '{wallet_id, near_account_id, trial}' <<<"$BODY" 2>/dev/null)
  BODY=""; rm -f "$RUN_TMP/body"
  if [[ -z "$REG_WK" || -z "$REG_ACCOUNT" ]] || ! safe_ident "$REG_ACCOUNT"; then
    warn "/register minted no usable wallet (HTTP $HTTP)"; return 1
  fi
  note "wallet ${REG_ACCOUNT:0:12}… minted (wk_ present, length ${#REG_WK}); $shown"
}

# claim_trial <wk> — sets TRIAL_PK and CLAIM (the answer without the key).
claim_trial() {
  TRIAL_PK=""; CLAIM=""
  req wk "$1" POST /trial-key
  TRIAL_PK=$(j '.payment_key // empty')
  CLAIM=$(jq -c 'del(.payment_key)' <<<"$BODY" 2>/dev/null)
  BODY=""; rm -f "$RUN_TMP/body"
  [[ -n "$TRIAL_PK" ]]
}

# An empty answer from the ssh transport is not an absent row (hos_common
# `sql_row`): every key read here is of a row that exists, so it is retried.
key_row() { # key_row <owner> <nonce> — allowance|expires_epoch|trial_converted|trial_allowance|initial_balance|is_grant|allowance_spent
  sql_row "SELECT pk.allowance_usd, COALESCE(EXTRACT(EPOCH FROM pk.expires_at)::bigint, 0), pk.trial_converted,
            COALESCE(pk.trial_allowance_usd::text, 'null'), pk.initial_balance, pk.is_grant,
            COALESCE(b.allowance_spent_usd, 0)
     FROM payment_keys pk LEFT JOIN payment_key_balances b USING (owner, nonce)
     WHERE pk.owner = '$1' AND pk.nonce = $2 AND pk.deleted_at IS NULL" 3
}
ledger() { # ledger <owner> <nonce> — count|last amount
  sql_row "SELECT COUNT(*) || '|' || COALESCE((SELECT amount_usd FROM payment_key_grants WHERE owner = '$1' AND nonce = $2 ORDER BY id DESC LIMIT 1)::text, '-')
     FROM payment_key_grants WHERE owner = '$1' AND nonce = $2" 3
}
gift() { # gift <json-body>
  req admin - POST /admin/grant-subscription "$1"
}

# ── preflight ────────────────────────────────────────────────────────────────

log "gift_subscription_e2e — $NETWORK, $( [[ $APPLY == true ]] && echo APPLY || echo 'dry run' )"
note "coordinator: ${COORDINATOR_URL#*://}"
note "RPC: $(rpc_url_public) (this suite reads nothing on chain)"
for tool in jq curl python3; do command -v "$tool" >/dev/null || { echo "✗ missing $tool" >&2; exit 1; }; done
H=$(curl -sS --max-time 20 "$COORDINATOR_URL/health" 2>/dev/null)
note "health: $(jq -c '{status, version, git_sha}' <<<"$H" 2>/dev/null || echo unreachable)"
if [[ -n "$ADMIN_TOKEN" ]]; then note "admin bearer: present (length ${#ADMIN_TOKEN})"
else warn "admin bearer: ABSENT (ADMIN_BEARER_TOKEN_TESTNET in $ENV_FILE)"; fi
if sql_alive; then HAVE_SQL=true; note "PSQL_CMD: answers"
else warn "PSQL_CMD: $( [[ -n $PSQL_CMD ]] && echo 'does not answer' || echo unset ) — the DB checks will SKIP"; fi
FUNDED_PK=""
if [[ -n "${FUNDED_KEY_FILE:-}" && -r "${FUNDED_KEY_FILE}" ]]; then
  FUNDED_PK="$(tr -d ' \n\r' < "$FUNDED_KEY_FILE")"
  if [[ "$(cut -d: -f2 <<<"$FUNDED_PK")" =~ ^[1-9][0-9]*$ ]]; then note "funded key: present (nonce $(cut -d: -f2 <<<"$FUNDED_PK"))"
  else warn "FUNDED_KEY_FILE does not hold owner:nonce:key with nonce ≥ 1 — ignored"; FUNDED_PK=""; fi
fi

if [[ "$APPLY" != true ]]; then
  cat >&2 <<'EOF'
  (dry-run) with --apply this suite will:
    • mint two wallets (POST /register) and claim their trial keys (POST /trial-key) — no chain
    • G11/G8/G10 refusals on the admin grant routes (no writes)
    • S1/S3 refusals with the trial key (no writes)
    • G1–G3 gift the first wallet's trial three times (admin grant, ≤ GIFT_SUBSCRIPTION_USD, testnet)
    • G2 one connector-probe `ping` on the converted key (LONG=1: 50 more)
    • G5/G6 read /admin/grant-keys, /admin/earnings, /admin/connector-calls
    • G4 gift one idle, test-minted customer key (nonce ≥ 1, no allowance) twice
    • G9 a refused gift on a key holding more than the cap (409, nothing written)
    • S5 LONG=1: the second trial's calls to exhaustion, then 402 trial_exhausted
    • D2/D3/D4 describe 404s, 70 describe GETs for the 429, a scan of the refusals
EOF
  [[ -n "$ADMIN_TOKEN" ]] || { fail "preflight: no admin bearer"; }
  verdict "gift_subscription_e2e (dry run)"; rc=$?
  [[ $rc -eq 3 ]] && exit 0 || exit $rc
fi

[[ -n "$ADMIN_TOKEN" ]] || { echo "✗ no ADMIN_BEARER_TOKEN_TESTNET in $ENV_FILE" >&2; exit 1; }
SUITE_START_RFC=$(now_rfc)

# The cap, from the coordinator's own refusal: validated before any key is
# looked up, so a made-up owner is enough and nothing is read or written.
req admin - POST /admin/grant-subscription '{"owner":"gift-e2e-nobody.testnet","nonce":1,"amount_usd":"0"}'
CAP=$(grep -oE 'from 1 to [0-9]+ \(GIFT_SUBSCRIPTION_USD\)' <<<"$BODY" | grep -oE '[0-9]+' | tail -1)
[[ -n "$CAP" ]] && note "GIFT_SUBSCRIPTION_USD (from the refusal): $CAP" \
  || { echo "✗ could not read the gift cap from /admin/grant-subscription (HTTP $HTTP): $(short)" >&2; exit 1; }

# ── wallet A: the trial that gets converted ─────────────────────────────────
log "fixture: wallet A and its trial key"
A_ACC=""; A_PK=""; A_WK=""
if register_wallet; then
  A_ACC="$REG_ACCOUNT"; A_WK="$REG_WK"
  if claim_trial "$A_WK"; then
    A_PK="$TRIAL_PK"; A_CLAIM="$CLAIM"
    note "A trial claimed: $(jq -c '{owner: (.owner[0:12]), nonce, calls, expires_at, project_ids}' <<<"$A_CLAIM")"
  else
    warn "A's trial claim refused: $(short "$CLAIM")"
  fi
fi
A_OWNER="${A_ACC}"
A_READY=false; A_ADOPTED=false
[[ -n "$A_PK" ]] && A_READY=true
if ! $A_READY && [[ "$ADOPT_IDLE_TRIAL" == 1 ]] && $HAVE_SQL; then
  # An expired trial a test minted and nobody holds: hex owner, never
  # converted, no call for a day. One that made calls, so the settled spend
  # is not zero.
  A_OWNER=$(q "SELECT pk.owner FROM payment_keys pk LEFT JOIN payment_key_balances b USING (owner, nonce)
     WHERE pk.nonce = 0 AND pk.is_grant AND NOT pk.trial_converted AND pk.deleted_at IS NULL
       AND pk.owner ~ '^[0-9a-f]{64}\$' AND pk.expires_at < NOW()
       AND COALESCE(b.allowance_spent_usd, 0) > 0
       AND NOT EXISTS (SELECT 1 FROM https_calls c WHERE c.owner = pk.owner AND c.nonce = 0
                        AND (c.created_at > NOW() - interval '1 day' OR c.status = 'pending'))
     ORDER BY pk.created_at DESC LIMIT 1")
  if [[ -n "$A_OWNER" ]]; then
    A_READY=true; A_ADOPTED=true
    warn "ADOPTED an expired idle trial ${A_OWNER:0:12}… for the admin-side rows; rows that need the key itself will SKIP"
  fi
fi

# S5 (claim half): a trial is scoped to the connectors and counted in calls.
log "S5 the trial claim — scope and unit"
if [[ -n "$A_PK" ]]; then
  if jq -e '.nonce == 0 and (.calls|type=="number" and .>0) and (.project_ids == ["connectors.outlayer.testnet/*"]) and (has("allowance_usd")|not) and (has("balance")|not)' <<<"$A_CLAIM" >/dev/null; then
    pass "S5 trial claim: nonce 0, $(jq -r .calls <<<"$A_CLAIM") calls, scope connectors.outlayer.testnet/* only, no dollar figure"
  else
    fail "S5 trial claim shape: $(short "$A_CLAIM")"
  fi
  [[ "$(jq -r .calls <<<"$A_CLAIM")" == "50" ]] && pass "S5 the trial is fifty calls" \
    || fail "S5 the trial is $(jq -r .calls <<<"$A_CLAIM") calls, expected 50 (TRIAL_KEY_CALLS)"
else
  skip "S5 no trial key for wallet A (claim refused — see above)"
fi

# ── G11: the other grant route, and the bearer ──────────────────────────────
log "G11 grant-payment-key on nonce 0; grant-subscription without the bearer"
G11_OWNER="${A_OWNER:-gift-e2e-nobody.testnet}"
req admin - POST /admin/grant-payment-key "$(jq -nc --arg o "$G11_OWNER" '{owner:$o, nonce:0, amount:"1", note:"gift-e2e G11"}')"
if [[ "$HTTP" == 400 ]] && grep -q '/admin/grant-subscription' <<<"$BODY"; then
  pass "G11 grant-payment-key nonce 0 → 400 naming /admin/grant-subscription: $(short "$BODY" 140)"
else
  fail "G11 grant-payment-key nonce 0 → HTTP $HTTP: $(short)"
fi
req none - POST /admin/grant-subscription "$(jq -nc --arg o "$G11_OWNER" '{owner:$o, nonce:0}')"
[[ "$HTTP" == 401 ]] && pass "G11 grant-subscription without the bearer → 401" \
  || fail "G11 grant-subscription without the bearer → HTTP $HTTP (expected 401): $(short)"

# ── G8: the gift's bounds; learns the cap ───────────────────────────────────
log "G8 amount_usd and days out of bounds"
if ! $A_READY; then
  skip "G8 no trial key on wallet A"
else
  A_BEFORE=$($HAVE_SQL && key_row "$A_OWNER" 0)
  for bad in 0 "$((CAP + 1))" abc; do
    req admin - POST /admin/grant-subscription "$(jq -nc --arg o "$A_OWNER" --arg a "$bad" '{owner:$o, nonce:0, amount_usd:$a, note:"gift-e2e G8"}')"
    [[ "$HTTP" == 400 ]] && grep -q 'GIFT_SUBSCRIPTION_USD' <<<"$BODY" \
      && pass "G8 amount_usd \"$bad\" → 400 naming GIFT_SUBSCRIPTION_USD" \
      || fail "G8 amount_usd \"$bad\" → HTTP $HTTP: $(short)"
  done
  for d in 0 3651; do
    req admin - POST /admin/grant-subscription "$(jq -nc --arg o "$A_OWNER" --argjson d "$d" '{owner:$o, nonce:0, days:$d, note:"gift-e2e G8"}')"
    [[ "$HTTP" == 400 && "$BODY" == *"days must be from 1 to 3650"* ]] \
      && pass "G8 days $d → 400 \"days must be from 1 to 3650\"" \
      || fail "G8 days $d → HTTP $HTTP: $(short)"
  done
  if $HAVE_SQL; then
    A_AFTER=$(key_row "$A_OWNER" 0); L=$(ledger "$A_OWNER" 0)
    [[ -n "$A_BEFORE" && "$A_BEFORE" == "$A_AFTER" && "${L%%|*}" == 0 ]] \
      && pass "G8 the key is untouched (row $A_AFTER, no ledger row)" \
      || fail "G8 the key moved: before '$A_BEFORE' after '$A_AFTER', ledger '$L'"
  else
    skip "G8 key-untouched check — needs PSQL_CMD"
  fi
fi

# ── S1 / S3 on the unconverted trial ────────────────────────────────────────
s1_check() { # s1_check <label> <pk> <owner>
  local label=$1 pk=$2 owner=$3 before after
  before=$($HAVE_SQL && key_row "$owner" 0)
  req pk "$pk" POST /subscription/purchase '{"amount_usd":"1000000"}'
  if [[ "$HTTP" == 400 && "$(j .reason)" == trial_key_not_purchasable && "$(j .terminal)" == true \
        && "$(j .error)" == *"POST /wallet/v1/create-payment-key"* ]]; then
    pass "S1 purchase on the $label trial key → 400 trial_key_not_purchasable, terminal, names POST /wallet/v1/create-payment-key"
  else
    fail "S1 purchase on the $label trial key → HTTP $HTTP: $(short)"
  fi
  if $HAVE_SQL; then
    after=$(key_row "$owner" 0)
    [[ -n "$before" && "$before" == "$after" ]] && pass "S1 ($label) nothing spent: key row unchanged ($after)" \
      || fail "S1 ($label) the key moved: '$before' → '$after'"
  else
    skip "S1 ($label) nothing-spent check — needs PSQL_CMD"
  fi
}

log "S1 purchase on the (unconverted) trial key; S3 notifications webhook"
if [[ -n "$A_PK" ]]; then
  s1_check unconverted "$A_PK" "$A_OWNER"
  req pk "$A_PK" PUT /subscription/notifications '{"webhook_url":"http://127.0.0.1/x"}'
  if [[ "$HTTP" == 400 && "$(j .reason)" == invalid_request && "$(j .error)" == "webhook_url: "* ]]; then
    pass "S3 webhook_url http://127.0.0.1/x → 400 invalid_request: $(j .error | head -c 120)"
  else
    fail "S3 webhook_url http://127.0.0.1/x → HTTP $HTTP: $(short)"
  fi
  if $HAVE_SQL; then
    n=$(q "SELECT COUNT(*) FROM notification_targets WHERE owner = '$A_OWNER'")
    [[ "$n" == 0 ]] && pass "S3 nothing stored (no notification_targets row)" || fail "S3 a notification_targets row exists ($n)"
  fi
else
  skip "S1/S3 no trial key held for wallet A (the key's secret is needed)"
fi

# ── G1: the conversion ──────────────────────────────────────────────────────
log "G1 gift the trial with the defaults"
G1_OK=false; A_EXP1=""
if ! $A_READY; then
  skip "G1 no trial key on wallet A"
else
  T_ALLOW=""; T_LEFT=""
  if $HAVE_SQL; then
    T_ALLOW=$(key_row "$A_OWNER" 0 | cut -d'|' -f1)
    # What the trial could still spend: nothing once expired.
    T_LEFT=$(q "SELECT CASE WHEN pk.expires_at <= NOW() THEN 0 ELSE GREATEST(pk.allowance_usd - COALESCE(b.allowance_spent_usd, 0), 0) END
                FROM payment_keys pk LEFT JOIN payment_key_balances b USING (owner, nonce) WHERE pk.owner = '$A_OWNER' AND pk.nonce = 0")
  fi
  gift "$(jq -nc --arg o "$A_OWNER" '{owner:$o, nonce:0, note:"release-test"}')"
  NOW=$(date +%s)
  if [[ "$HTTP" == 200 && "$(j .trial_converted)" == true && "$(j .allowance_available_usd)" == "$CAP" ]]; then
    G1_OK=true; A_EXP1=$(j .expires_at)
    pass "G1 → 200 trial_converted:true, allowance_available_usd $CAP, expires_at $A_EXP1"
    left=$(( $(epoch "$A_EXP1") - NOW ))
    want=$(( GIFT_DAYS * 86400 ))
    (( left > want - 300 && left < want + 300 )) \
      && pass "G1 expires_at ≈ now + $GIFT_DAYS days ($(( left / 3600 )) h)" \
      || fail "G1 expires_at is $(( left / 3600 )) h away, expected ≈ $(( GIFT_DAYS * 24 )) h (GIFT_DAYS=$GIFT_DAYS; set it if the deployment's GIFT_SUBSCRIPTION_DAYS differs)"
  else
    fail "G1 gift on the trial → HTTP $HTTP: $(short)"
  fi
  if $HAVE_SQL && $G1_OK; then
    R=$(key_row "$A_OWNER" 0); L=$(ledger "$A_OWNER" 0)
    IFS='|' read -r r_allow r_exp r_conv r_tallow r_bal r_grant r_spent <<<"$R"
    [[ "$r_conv" == t && "$r_tallow" == "$T_ALLOW" ]] \
      && pass "G1 DB trial_converted=t, trial_allowance_usd=$r_tallow (the trial's allowance)" \
      || fail "G1 DB trial_converted=$r_conv trial_allowance_usd=$r_tallow, expected t / $T_ALLOW"
    [[ "$L" == "1|$(( CAP - T_LEFT ))" ]] \
      && pass "G1 one payment_key_grants row of $(( CAP - T_LEFT )) (gift − the $T_LEFT the trial had left)" \
      || fail "G1 ledger is '$L', expected '1|$(( CAP - T_LEFT ))'"
  elif ! $HAVE_SQL; then
    skip "G1 DB checks — needs PSQL_CMD"
  fi
fi

# ── G2: the converted key at work ───────────────────────────────────────────
log "G2 the converted key: status and a connector call"
G2_CALLED=false
if ! $G1_OK; then
  skip "G2 wallet A's trial was not converted (G1)"
elif [[ -z "$A_PK" ]]; then
  skip "G2 status and connector call — the adopted trial's key secret is not held (a fresh trial was refused)"
else
  req pk "$A_PK" GET /subscription/status
  if [[ "$HTTP" == 200 && "$(bool_of trial)" == absent && "$(j .has_subscription)" == true \
        && "$(j .allowance_available_usd)" == "$CAP" ]]; then
    pass "G2 status: no trial block, has_subscription:true, allowance_available_usd $CAP"
  else
    fail "G2 status → HTTP $HTTP: $(jq -c '{has_subscription, trial, allowance_available_usd, expires_at}' <<<"$BODY" 2>/dev/null || short)"
  fi
  req pk "$A_PK" POST "/call/$PROJECT" '{"input":{"operation":"ping"}}'
  if [[ "$HTTP" == 200 && "$(j .status)" == completed ]]; then
    G2_CALLED=true
    pass "G2 connector call on the converted key → 200 completed"
  else
    fail "G2 connector call → HTTP $HTTP: $(short)"
  fi
  if $HAVE_SQL && $G2_CALLED; then
    ac=$(sql_row "SELECT allowance_covered FROM https_calls WHERE owner = '$A_OWNER' AND nonce = 0 AND status <> 'pending' ORDER BY created_at DESC LIMIT 1" 5)
    [[ "$ac" == t ]] && pass "G2 the call was paid from the allowance (https_calls.allowance_covered)" \
      || fail "G2 https_calls.allowance_covered is '$ac', expected t"
  fi
  if [[ "$LONG" == 1 ]] && $G2_CALLED; then
    ran=1; refused=""
    for _ in $(seq 2 51); do
      req pk "$A_PK" POST "/call/$PROJECT" '{"input":{"operation":"ping"}}'
      if [[ "$HTTP" == 200 && "$(j .status)" == completed ]]; then ran=$((ran + 1)); else refused="HTTP $HTTP $(j .reason)"; break; fi
    done
    [[ "$ran" == 51 ]] && pass "G2 51 calls on the converted key, the 51st ran — no trial_exhausted" \
      || fail "G2 call $((ran + 1)) of 51 refused: $refused"
  else
    skip "G2 the 51-call check (optional in the plan) — run with LONG=1"
  fi
fi

# ── S1 on the converted key ─────────────────────────────────────────────────
log "S1 purchase on the converted trial key"
if $G1_OK && [[ -n "$A_PK" ]]; then
  sleep 3   # let the G2 call settle, so the nothing-spent check compares settled rows
  s1_check converted "$A_PK" "$A_OWNER"
else
  skip "S1 (converted) no converted trial whose key is held"
fi

# ── G3: spend, gift again; a gift onto a full key ───────────────────────────
log "G3 gift after spending; gift onto a full key"
if ! $G1_OK; then
  skip "G3 wallet A's trial was not converted"
elif ! $HAVE_SQL; then
  skip "G3 needs PSQL_CMD (settled spend and ledger rows)"
else
  pend=$(q "SELECT COUNT(*) FROM https_calls WHERE owner = '$A_OWNER' AND nonce = 0 AND status = 'pending'")
  [[ "$pend" == 0 ]] || { sleep 10; pend=$(q "SELECT COUNT(*) FROM https_calls WHERE owner = '$A_OWNER' AND nonce = 0 AND status = 'pending'"); }
  SPENT=$(key_row "$A_OWNER" 0 | cut -d'|' -f7)
  L0=$(ledger "$A_OWNER" 0)
  EXP_BEFORE=$(key_row "$A_OWNER" 0 | cut -d'|' -f2)
  if [[ -z "$A_PK" ]]; then
    skip "G3 spend-then-gift — needs a call on the key, whose secret is not held (adopted trial)"
  elif [[ "${SPENT:-0}" == 0 ]]; then
    skip "G3 the key has spent nothing settled (${pend} pending) — the spend-then-gift half cannot be judged"
  else
    gift "$(jq -nc --arg o "$A_OWNER" '{owner:$o, nonce:0, note:"gift-e2e G3"}')"
    if [[ "$HTTP" == 200 && "$(j .allowance_available_usd)" == "$CAP" && "$(j .trial_converted)" == true ]]; then
      pass "G3 second gift after spending $SPENT → 200, allowance_available_usd $CAP"
    else
      fail "G3 second gift → HTTP $HTTP: $(short)"
    fi
    E2=$(epoch "$(j .expires_at)")
    [[ -n "$E2" ]] && (( E2 >= EXP_BEFORE )) && pass "G3 expires_at not moved earlier ($(j .expires_at))" \
      || fail "G3 expires_at $(j .expires_at) is earlier than the stored end (epoch $EXP_BEFORE)"
    L1=$(ledger "$A_OWNER" 0)
    [[ "$L1" == "$(( ${L0%%|*} + 1 ))|$SPENT" ]] && pass "G3 a second ledger row = what was spent ($SPENT)" \
      || fail "G3 ledger '$L0' → '$L1', expected a new row of $SPENT"
    req pk "$A_PK" GET /subscription/status
    [[ "$(j .allowance_available_usd)" == "$CAP" ]] && pass "G3 status reads allowance_available_usd $CAP" \
      || fail "G3 status reads allowance_available_usd $(j .allowance_available_usd), expected $CAP"
  fi
  L1=$(ledger "$A_OWNER" 0)
  gift "$(jq -nc --arg o "$A_OWNER" '{owner:$o, nonce:0, note:"gift-e2e G3 full"}')"
  L2=$(ledger "$A_OWNER" 0)
  if [[ "$HTTP" == 200 && "${L2%%|*}" == "${L1%%|*}" ]]; then
    pass "G3 a gift onto a full key → 200, no new ledger row (${L2%%|*} rows)"
  else
    fail "G3 a gift onto a full key → HTTP $HTTP, ledger '$L1' → '$L2': $(short)"
  fi
fi

# ── wallet B: G10 before its claim, then the claim ──────────────────────────
log "G10 unknown keys; wallet B before and after its claim"
B_ACC=""; B_PK=""
if register_wallet; then
  B_ACC="$REG_ACCOUNT"; B_WK="$REG_WK"
  req admin - POST /admin/grant-subscription "$(jq -nc --arg o "$B_ACC" '{owner:$o, nonce:0, note:"gift-e2e G10"}')"
  [[ "$HTTP" == 404 && "$BODY" == *"POST /trial-key"* ]] \
    && pass "G10 nonce 0 of a wallet that never claimed → 404 naming POST /trial-key" \
    || fail "G10 nonce 0 of an unclaimed wallet → HTTP $HTTP: $(short)"
else
  skip "G10 (unclaimed wallet half) — /register minted nothing"
fi
req admin - POST /admin/grant-subscription '{"owner":"gift-e2e-nobody.testnet","nonce":7,"note":"gift-e2e G10"}'
[[ "$HTTP" == 404 && "$BODY" == *"Payment key not found"* ]] \
  && pass "G10 unknown (owner, nonce) → 404: $(short "$BODY" 100)" \
  || fail "G10 unknown (owner, nonce) → HTTP $HTTP: $(short)"
if [[ -n "$B_ACC" ]]; then
  if claim_trial "$B_WK"; then B_PK="$TRIAL_PK"; note "B trial claimed (${B_ACC:0:12}…)"
  else warn "B's trial claim refused: $(short "$CLAIM")"; fi
fi

B_LIST_OWNER="$B_ACC"
if [[ -z "$B_PK" && "$ADOPT_IDLE_TRIAL" == 1 ]] && $HAVE_SQL; then
  # Read-only: any claimed trial that never made a call and was never converted.
  B_LIST_OWNER=$(q "SELECT pk.owner FROM payment_keys pk WHERE pk.nonce = 0 AND pk.is_grant AND NOT pk.trial_converted
     AND pk.deleted_at IS NULL AND pk.owner <> '$A_OWNER'
     AND NOT EXISTS (SELECT 1 FROM https_calls c WHERE c.owner = pk.owner AND c.nonce = 0)
     ORDER BY pk.created_at DESC LIMIT 1")
  [[ -n "$B_LIST_OWNER" ]] && note "G5 uses an existing claimed-but-untouched trial ${B_LIST_OWNER:0:12}… (read only)"
fi

# ── G5: the admin's list ────────────────────────────────────────────────────
log "G5 /admin/grant-keys"
req admin - "GET" "/admin/grant-keys?limit=500"
if [[ "$HTTP" != 200 ]]; then
  fail "G5 /admin/grant-keys → HTTP $HTTP: $(short)"
else
  if $G1_OK; then
    [[ "$(jq -r --arg o "$A_OWNER" '[.keys[] | select(.owner == $o and .nonce == 0)] | length' <<<"$BODY")" == 1 ]] \
      && pass "G5 the converted trial is listed" || fail "G5 the converted trial is NOT listed (total $(j .total))"
  else
    skip "G5 (listed half) — no converted trial"
  fi
  if [[ -n "$B_PK" || ( "$B_LIST_OWNER" != "$B_ACC" && -n "$B_LIST_OWNER" ) ]]; then
    [[ "$(jq -r --arg o "$B_LIST_OWNER" '[.keys[] | select(.owner == $o)] | length' <<<"$BODY")" == 0 ]] \
      && pass "G5 a claimed-but-untouched trial is not listed" || fail "G5 the untouched trial of wallet B IS listed"
  else
    skip "G5 (not-listed half) — wallet B has no trial"
  fi
fi

# ── G4: a customer's key ────────────────────────────────────────────────────
log "G4 a customer's key (nonce ≥ 1)"
G4_KEY=""
if ! $HAVE_SQL; then
  skip "G4 needs PSQL_CMD to pick the key and judge its balance"
else
  if [[ -n "${G4_OWNER:-}" && -n "${G4_NONCE:-}" ]]; then
    safe_ident "$G4_OWNER" && [[ "$G4_NONCE" =~ ^[1-9][0-9]*$ ]] && G4_KEY="$G4_OWNER|$G4_NONCE"
  else
    # An idle key a test minted and nobody holds any more: a coordinator-minted
    # (implicit) owner, a real balance left, no allowance ever, untouched for a
    # week — so the gift lands on nothing anybody is running.
    G4_KEY=$(q "SELECT pk.owner || '|' || pk.nonce FROM payment_keys pk LEFT JOIN payment_key_balances b USING (owner, nonce)
       WHERE pk.deleted_at IS NULL AND pk.nonce >= 1 AND NOT pk.is_grant AND pk.owner ~ '^[0-9a-f]{64}\$'
         AND pk.allowance_usd = 0 AND pk.expires_at IS NULL
         AND pk.initial_balance::numeric - COALESCE(b.spent, 0) - COALESCE(b.reserved, 0) > 0
         AND pk.updated_at < NOW() - interval '7 days' AND COALESCE(b.last_used_at, pk.created_at) < NOW() - interval '7 days'
         AND NOT EXISTS (SELECT 1 FROM payment_key_grants g WHERE g.owner = pk.owner AND g.nonce = pk.nonce)
       ORDER BY pk.created_at DESC LIMIT 1")
  fi
  if [[ -z "$G4_KEY" ]]; then
    skip "G4 no idle customer key with a balance and no allowance was found"
  else
    K_OWNER="${G4_KEY%|*}"; K_NONCE="${G4_KEY#*|}"
    note "G4 key: ${K_OWNER:0:12}… nonce $K_NONCE"
    KB=$(key_row "$K_OWNER" "$K_NONCE"); KL0=$(ledger "$K_OWNER" "$K_NONCE")
    gift "$(jq -nc --arg o "$K_OWNER" --argjson n "$K_NONCE" '{owner:$o, nonce:$n, note:"release-test G4"}')"
    if [[ "$HTTP" == 200 && "$(j .trial_converted)" == false && "$(j .allowance_available_usd)" == "$CAP" ]]; then
      pass "G4 → 200 trial_converted:false, allowance_available_usd $CAP, until $(j .expires_at)"
    else
      fail "G4 gift on a customer key → HTTP $HTTP: $(short)"
    fi
    K_EXP1=$(j .expires_at)
    KA=$(key_row "$K_OWNER" "$K_NONCE"); KL1=$(ledger "$K_OWNER" "$K_NONCE")
    [[ "$(cut -d'|' -f5,6 <<<"$KB")" == "$(cut -d'|' -f5,6 <<<"$KA")" ]] \
      && pass "G4 DB initial_balance and is_grant unchanged ($(cut -d'|' -f5,6 <<<"$KA"))" \
      || fail "G4 initial_balance|is_grant moved: $(cut -d'|' -f5,6 <<<"$KB") → $(cut -d'|' -f5,6 <<<"$KA")"
    [[ "$(cut -d'|' -f3 <<<"$KA")" == f ]] && pass "G4 DB trial_converted stays false" \
      || fail "G4 DB trial_converted is $(cut -d'|' -f3 <<<"$KA")"
    [[ "$KL1" == "$(( ${KL0%%|*} + 1 ))|$CAP" ]] && pass "G4 one ledger row of $CAP" \
      || fail "G4 ledger '$KL0' → '$KL1', expected one row of $CAP"
    # A shorter gift keeps the later end.
    gift "$(jq -nc --arg o "$K_OWNER" --argjson n "$K_NONCE" '{owner:$o, nonce:$n, days:1, note:"release-test G4 days:1"}')"
    KL2=$(ledger "$K_OWNER" "$K_NONCE")
    if [[ "$HTTP" == 200 && "$(epoch "$(j .expires_at)")" == "$(epoch "$K_EXP1")" ]]; then
      pass "G4 a days:1 gift on a key ending later keeps its end ($(j .expires_at))"
    else
      fail "G4 days:1 gift → HTTP $HTTP, expires_at $(j .expires_at) vs $K_EXP1: $(short)"
    fi
    [[ "${KL2%%|*}" == "${KL1%%|*}" ]] && pass "G4 that gift added nothing, so no ledger row" \
      || fail "G4 the days:1 gift wrote a ledger row ('$KL1' → '$KL2')"
  fi
fi

# ── G9: a gift below what the key can spend ─────────────────────────────────
log "G9 a key that can already spend more than the gift"
if ! $HAVE_SQL; then
  skip "G9 needs PSQL_CMD to find a key above the cap"
else
  G9_KEY=$(q "SELECT pk.owner || '|' || pk.nonce FROM payment_keys pk LEFT JOIN payment_key_balances b USING (owner, nonce)
     WHERE pk.deleted_at IS NULL AND pk.nonce >= 1 AND pk.expires_at > NOW() + interval '1 day'
       AND pk.allowance_usd - COALESCE(b.allowance_spent_usd, 0) > $CAP + 1000000
     ORDER BY pk.expires_at DESC LIMIT 1")
  if [[ -z "$G9_KEY" ]]; then
    skip "G9 no testnet key holds more than $CAP of live allowance (needs a bought plan above the cap — an on-chain or funded-key purchase)"
  else
    N_OWNER="${G9_KEY%|*}"; N_NONCE="${G9_KEY#*|}"
    NB=$(key_row "$N_OWNER" "$N_NONCE"); NL0=$(ledger "$N_OWNER" "$N_NONCE")
    gift "$(jq -nc --arg o "$N_OWNER" --argjson n "$N_NONCE" '{owner:$o, nonce:$n, note:"gift-e2e G9"}')"
    [[ "$HTTP" == 409 && "$BODY" == *"tops up and never takes away"* ]] \
      && pass "G9 ${N_OWNER:0:12}… nonce $N_NONCE → 409: $(short "$BODY" 150)" \
      || fail "G9 gift below the key's allowance → HTTP $HTTP: $(short)"
    NA=$(key_row "$N_OWNER" "$N_NONCE"); NL1=$(ledger "$N_OWNER" "$N_NONCE")
    [[ "$(cut -d'|' -f1,2 <<<"$NB")" == "$(cut -d'|' -f1,2 <<<"$NA")" && "$NL0" == "$NL1" ]] \
      && pass "G9 allowance and expires_at unchanged, no ledger row" \
      || fail "G9 the key moved: $(cut -d'|' -f1,2 <<<"$NB") → $(cut -d'|' -f1,2 <<<"$NA"), ledger $NL0 → $NL1"
  fi
fi

# ── G6: what the reports say ────────────────────────────────────────────────
log "G6 /admin/earnings and /admin/connector-calls"
if ! $G1_OK; then
  skip "G6 no converted trial"
elif ! $HAVE_SQL; then
  skip "G6 needs PSQL_CMD to reconcile the report"
else
  sleep 2
  W_FROM=$(q "SELECT to_char((created_at - interval '1 second') AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') FROM payment_keys WHERE owner = '$A_OWNER' AND nonce = 0")
  W_TO=$(date -u -v+5M +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '+5 minutes' +%Y-%m-%dT%H:%M:%SZ)
  req admin - GET "/admin/earnings?from=$W_FROM&to=$W_TO"
  E_USD=$(j .given.granted_usd); E_N=$(j .given.grants)
  DB_GIVEN=$(q "SELECT COUNT(*) || '|' || COALESCE(SUM(amount), 0) FROM (
       SELECT COALESCE(trial_allowance_usd, allowance_usd) AS amount FROM payment_keys
        WHERE created_at >= '$W_FROM' AND created_at < '$W_TO' AND nonce = 0 AND is_grant
       UNION ALL SELECT amount_usd FROM payment_key_grants WHERE created_at >= '$W_FROM' AND created_at < '$W_TO') g")
  OURS_OWNERS="'$A_OWNER'${B_ACC:+,'$B_ACC'}${K_OWNER:+,'$K_OWNER'}"
  DB_OURS=$(q "SELECT COUNT(*) || '|' || COALESCE(SUM(amount), 0) FROM (
       SELECT COALESCE(trial_allowance_usd, allowance_usd) AS amount FROM payment_keys
        WHERE created_at >= '$W_FROM' AND created_at < '$W_TO' AND nonce = 0 AND is_grant AND owner IN ($OURS_OWNERS)
       UNION ALL SELECT amount_usd FROM payment_key_grants WHERE created_at >= '$W_FROM' AND created_at < '$W_TO' AND owner IN ($OURS_OWNERS)) g")
  A_TRIAL_READ=$(q "SELECT COALESCE(trial_allowance_usd, allowance_usd) || '|' || allowance_usd FROM payment_keys WHERE owner = '$A_OWNER' AND nonce = 0")
  A_GRANTS=$(q "SELECT COALESCE(SUM(amount_usd), 0) FROM payment_key_grants WHERE owner = '$A_OWNER' AND nonce = 0")
  if [[ "$HTTP" != 200 ]]; then
    fail "G6 /admin/earnings → HTTP $HTTP: $(short)"
  else
    [[ "$E_N|$E_USD" == "$DB_GIVEN" ]] \
      && pass "G6 earnings.given over [$W_FROM, $W_TO) = $E_N grants / $E_USD — equals the DB (ours: $DB_OURS)" \
      || fail "G6 earnings.given is $E_N|$E_USD, the DB says $DB_GIVEN (ours $DB_OURS)"
    [[ "${A_TRIAL_READ%%|*}" == "${T_ALLOW:-x}" ]] \
      && pass "G6 the converted trial is counted at its trial allowance ${T_ALLOW}, not its allowance now (${A_TRIAL_READ#*|}), plus its $A_GRANTS of gift rows" \
      || fail "G6 the converted trial is counted at ${A_TRIAL_READ%%|*}, expected its trial allowance ${T_ALLOW:-?}"
    [[ "$DB_GIVEN" != "$DB_OURS" ]] && note "G6 other gifts/trials fell in the window: all $DB_GIVEN vs ours $DB_OURS"
  fi
  if $G2_CALLED || $A_ADOPTED; then
    req admin - GET "/admin/connector-calls?owner=$A_OWNER&from=$W_FROM&to=$W_TO&limit=100"
    n_calls=$(jq -r '[.calls[] | select(.nonce == 0)] | length' <<<"$BODY" 2>/dev/null)
    n_grant=$(jq -r '[.calls[] | select(.nonce == 0 and .paid_by_grant == true and .from_allowance == true)] | length' <<<"$BODY" 2>/dev/null)
    [[ "$HTTP" == 200 && "${n_calls:-0}" -ge 1 && "$n_calls" == "$n_grant" ]] \
      && pass "G6 connector-calls: the converted trial's $n_calls call(s) read from_allowance + paid_by_grant:true" \
      || fail "G6 connector-calls → HTTP $HTTP, $n_calls call(s), $n_grant paid_by_grant: $(short)"
  fi
  skip "G6 G4's allowance call paid_by_grant — needs a call on the customer key, whose secret this suite does not hold; tests/gift_followup_e2e.sh GC runs it"
fi

# ── S2 / S4: a funded key ───────────────────────────────────────────────────
log "S2 / S4 purchase refusals and the cheapest plan on a funded key"
if [[ -z "$FUNDED_PK" ]]; then
  skip "S2 needs a funded key (nonce ≥ 1) — creating one funds a wallet on chain; pass FUNDED_KEY_FILE"
  skip "S4 needs a funded key and buys a plan with its balance — FUNDED_KEY_FILE + S4_BUY=1"
else
  req pk "$FUNDED_PK" GET /subscription/status; BAL0=$(j .balance)
  CHEAPEST=""
  for amt in abc 0 1; do
    req pk "$FUNDED_PK" POST /subscription/purchase "$(jq -nc --arg a "$amt" '{amount_usd:$a}')"
    msg=$(j .error)
    [[ $amt == 1 ]] && CHEAPEST=$(grep -oE 'The cheapest is .* at [0-9]+' <<<"$msg" | grep -oE '[0-9]+$')
    if [[ "$HTTP" == 400 && "$(j .reason)" == invalid_request && "$msg" != *"Invalid X-Payment-Key format"* ]] \
       && { [[ $amt == 1 ]] && [[ "$msg" == *"The cheapest"* ]] || [[ $amt != 1 && "$msg" == *amount_usd* ]]; }; then
      pass "S2 amount_usd \"$amt\" → 400 invalid_request: $(head -c 110 <<<"$msg")"
    else
      fail "S2 amount_usd \"$amt\" → HTTP $HTTP: $(short)"
    fi
  done
  req pk "$FUNDED_PK" GET /subscription/status
  [[ "$(j .balance)" == "$BAL0" ]] && pass "S2 balance unchanged ($BAL0)" || fail "S2 balance moved $BAL0 → $(j .balance)"
  if [[ "${S4_BUY:-0}" == 1 && -n "$CHEAPEST" ]]; then
    OLD_EXP=$(j .expires_at); OLD_AV=$(j '.allowance_available_usd // "0"')
    req pk "$FUNDED_PK" POST /subscription/purchase "$(jq -nc --arg a "$CHEAPEST" '{amount_usd:$a}')"
    if [[ "$HTTP" == 200 ]]; then
      days=$(j .days_added); newexp=$(epoch "$(j .expires_at)"); now=$(date +%s)
      base=$now; [[ -n "$OLD_EXP" && "$OLD_EXP" != null ]] && (( $(epoch "$OLD_EXP") > now )) && base=$(epoch "$OLD_EXP")
      (( newexp - (base + days * 86400) < 120 && (base + days * 86400) - newexp < 120 )) \
        && pass "S4 cheapest plan bought: $(jq -c '{plan, spent_usd, allowance_total_usd, expires_at, days_added}' <<<"$BODY")" \
        || fail "S4 expires_at $(j .expires_at) is not max(now, old end) + $days days"
      req pk "$FUNDED_PK" GET /subscription/status
      [[ "$(j .has_subscription)" == true ]] && pass "S4 status has_subscription:true" || fail "S4 status has_subscription $(j .has_subscription)"
    else
      fail "S4 purchase of $CHEAPEST → HTTP $HTTP: $(short)"
    fi
  else
    skip "S4 the purchase itself — S4_BUY=1 (spends the funded key's balance)"
  fi
fi

# ── S5 (count half): the trial's calls to exhaustion ────────────────────────
log "S5 the trial runs its calls, then trial_exhausted"
if [[ "$LONG" != 1 ]]; then
  skip "S5 the fifty-call exhaustion — run with LONG=1 (or connector_pricing_e2e.sh C7)"
elif [[ -z "$B_PK" ]]; then
  skip "S5 wallet B has no trial key"
else
  T_CALLS=50; ran=0; stop=""
  for _ in $(seq 1 $T_CALLS); do
    req pk "$B_PK" POST "/call/$PROJECT" '{"input":{"operation":"ping"}}'
    if [[ "$HTTP" == 200 && "$(j .status)" == completed ]]; then ran=$((ran + 1)); else stop="HTTP $HTTP $(j .reason)"; break; fi
  done
  [[ $ran == $T_CALLS ]] && pass "S5 all $T_CALLS trial calls ran" || fail "S5 only $ran of $T_CALLS trial calls ran ($stop)"
  req pk "$B_PK" POST "/call/$PROJECT" '{"input":{"operation":"ping"}}'
  [[ "$HTTP" == 402 && "$(j .reason)" == trial_exhausted && "$(j .terminal)" == true && "$(j .used)" == $T_CALLS ]] \
    && pass "S5 call $((T_CALLS + 1)) → 402 trial_exhausted, terminal, used $T_CALLS" \
    || fail "S5 call $((T_CALLS + 1)) → HTTP $HTTP: $(short)"
fi

# ── D2: describe refusals ───────────────────────────────────────────────────
log "D2 describe: unknown id, a connector not on this network, one not published"
req none - GET "/public/connectors/gift-e2e-no-such-connector/describe"
[[ "$HTTP" == 404 && "$(j .error)" == *"on testnet"* ]] && pass "D2 unknown id → 404: $(j .error)" \
  || fail "D2 unknown id → HTTP $HTTP: $(short)"
req none - GET "/public/connectors/polymarket/describe"
[[ "$HTTP" == 404 && "$(j .error)" == *"polymarket"*"testnet"* ]] && pass "D2 a mainnet-only connector on testnet → 404: $(j .error)" \
  || fail "D2 polymarket on testnet → HTTP $HTTP: $(short)"
unpub=""
for id in connector-probe mercury subkey-probe hyperliquid gmail github; do
  req none - GET "/public/connectors/$id/describe"
  note "D2 describe $id → $HTTP $( [[ $HTTP == 200 ]] && j '.version // empty' | head -c 16 || j .error | head -c 120)"
  [[ "$HTTP" == 404 && "$(j .error)" == *"is not published on testnet"* ]] && unpub="$id: $(j .error)"
  [[ "$HTTP" == 404 && "$(j .error)" == *"describes no operations"* ]] && finding "D2 testnet $id's active version carries no describe block (404 \"$(j .error | head -c 60)…\")"
done
[[ -n "$unpub" ]] && pass "D2 a registry connector with no project → 404 \"$unpub\"" \
  || skip "D2 'not published on testnet' — every testnet registry connector is published; forcing one needs an on-chain removal"
skip "D2 cache (old version ≤ 60 s after set_active_version) — on-chain; tests/gift_followup_e2e.sh D2c runs it (DESCRIBE_SWITCH=1)"
skip "D1 describe 503 on an unreachable WasmUrl — needs an on-chain add_version with a 404ing URL"

# ── D3: the opaque IP limit ─────────────────────────────────────────────────
log "D3 70 describe GETs inside a minute"
sleep 1
codes=""; n429=0; bad_body=""; retry_after=""
for i in $(seq 1 70); do
  c=$(curl -sS -o "$RUN_TMP/d3" -D "$RUN_TMP/d3h" -w '%{http_code}' --max-time 20 "$COORDINATOR_URL/public/connectors/$DESCRIBE_ID/describe" 2>/dev/null)
  codes="${codes:+$codes }$c"
  if [[ "$c" == 429 ]]; then
    n429=$((n429 + 1))
    b=$(cat "$RUN_TMP/d3")
    [[ "$b" == "Too many requests. Try again later." ]] || bad_body="$(head -c 160 <<<"$b")"
    grep -qi '^retry-after:' "$RUN_TMP/d3h" && retry_after=yes
  fi
done
note "D3 codes: $(tr ' ' '\n' <<<"$codes" | sort | uniq -c | awk '{printf "%s×%s ", $1, $2}')"
if (( n429 == 0 )); then
  fail "D3 70 GETs of one describe URL drew no 429"
else
  [[ -z "$bad_body" ]] && pass "D3 $n429 answers were 429 with exactly \`Too many requests. Try again later.\` (no digit, no window)" \
    || fail "D3 a 429 body was not the opaque sentence: $bad_body"
  [[ -z "$retry_after" ]] && pass "D3 no Retry-After header on the 429s" || fail "D3 a 429 carried Retry-After"
fi
skip "D3 the coordinator log line 'IP rate limit exceeded' — needs the coordinator host's log"

# ── D4: nothing leaks an RPC URL ────────────────────────────────────────────
log "D4 refusals met in this run"
n_body=$(wc -l < "$RUN_TMP/non2xx" | tr -d ' ')
n_key=$(grep -ciE 'apikey|api_key=' "$RUN_TMP/non2xx"); n_key=${n_key:-0}
n_503=$(grep -cE '^503 |chain_unavailable' "$RUN_TMP/non2xx"); n_503=${n_503:-0}
n_503url=$(grep -E '^503 |chain_unavailable' "$RUN_TMP/non2xx" | grep -ciE 'https?://'); n_503url=${n_503url:-0}
[[ "$n_key" == 0 ]] && pass "D4 none of the $n_body non-2xx bodies carries an RPC key" \
  || fail "D4 $n_key non-2xx bodies mention an api key (count only; not printed)"
if [[ "$n_503" == 0 ]]; then
  note "D4 no 503 / chain_unavailable body was met in this run"
else
  [[ "$n_503url" == 0 ]] && pass "D4 $n_503 503/chain_unavailable bodies, none with a URL" \
    || fail "D4 $n_503url of $n_503 503/chain_unavailable bodies carry a URL"
fi
skip "D4 the coordinator-log count (grep -ci apikey) — needs the coordinator host's log"

# ── what this suite cannot reach ────────────────────────────────────────────
skip "G7 converted-trial warnings — unit test a_converted_trial_is_pointed_at_another_key; live needs a notification target and a threshold hit"
skip "G12 a purchase onto an expired key — unit tests with TEST_DATABASE_URL on a scratch DB; not reachable live on demand"
skip "S6 dashboard /subscription on nonce 0 — after the dashboard deploy, in a browser"
skip "D5 dashboard /connectors/<id> retry/not-published states — after the dashboard deploy, in a browser"

note "fixtures: wallet A ${A_OWNER:0:12}… (converted trial), wallet B ${B_ACC:0:12}…${K_OWNER:+, G4 key ${K_OWNER:0:12}… nonce ${K_NONCE}}"
verdict "gift_subscription_e2e"
