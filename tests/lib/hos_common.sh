#!/usr/bin/env bash
#
# Shared harness for the HoS Agent Connect testnet suites (§1 of
# .idea/hos-testnet-test-plan.md).
#
# Sourced, never executed. Gives every hos_* script the same coordinator
# client, the same chain client, the same assertion vocabulary and — the part
# that decides whether a run finishes at all — the same IP-rate-limit
# throttle. The wallet routes allow 100 requests/minute per IP and the limiter
# is in-memory in the coordinator, so nothing outside can reset it: a suite
# that fires faster than that reads its own 429s as product defects.

set -uo pipefail

HOS_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HOS_LIB_DIR/../.." && pwd)"

NETWORK="${NETWORK:-testnet}"
CONTRACT_ID="${CONTRACT_ID:-outlayer.testnet}"
COORDINATOR_URL="${COORDINATOR_URL:-https://testnet-api.outlayer.ai}"
# The RPC every probe here reads through — keyed, or a warning (lib/rpc.sh).
source "$HOS_LIB_DIR/rpc.sh"
PARENT="${PARENT:-}"
export OUTLAYER_NETWORK="$NETWORK"

# The published no-sign wallet artifact the verifier's allowlist pins.
PINNED_HASH_B58="${PINNED_HASH_B58:-BwjDnyemmBhrCyuviDGpoQAm9mdjTfrX7ZjqgZB4MHvM}"

PASS=0; FAILED=0; SKIPPED=0; FINDINGS=0
declare -a FAILED_NAMES=()
declare -a SKIP_NAMES=()
declare -a FINDING_NAMES=()

log()  { printf '\n\033[36m▶ %s\033[0m\n' "$*" >&2; }
note() { printf '\033[35m• %s\033[0m\n' "$*" >&2; }
warn() { printf '\033[33m⚠ %s\033[0m\n' "$*" >&2; }
pass() { printf '\033[32m✓ %s\033[0m\n' "$*" >&2; PASS=$((PASS+1)); }
fail() { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; FAILED=$((FAILED+1)); FAILED_NAMES+=("$*"); }
skip() { printf '\033[33m∅ SKIP: %s\033[0m\n' "$*" >&2; SKIPPED=$((SKIPPED+1)); SKIP_NAMES+=("$*"); }
# A behaviour that is not a broken assertion but IS something the partner will
# meet on their first run and we would rather tell them than have them find.
# Counted apart from failures so a real regression never hides inside a list of
# known deviations.
finding() { printf '\033[33m⚑ FINDING: %s\033[0m\n' "$*" >&2; FINDINGS=$((FINDINGS+1)); FINDING_NAMES+=("$*"); }

verdict() {
  local name="${1:-suite}"
  log "$name — $PASS passed, $FAILED failed, $SKIPPED skipped, $FINDINGS finding(s)"
  if (( ${#FINDING_NAMES[@]} > 0 )); then
    for n in "${FINDING_NAMES[@]}"; do printf '  \033[33m⚑ %s\033[0m\n' "$n" >&2; done
  fi
  if (( ${#SKIP_NAMES[@]} > 0 )); then
    for n in "${SKIP_NAMES[@]}"; do printf '  \033[33m∅ %s\033[0m\n' "$n" >&2; done
  fi
  if (( FAILED > 0 )); then
    for n in "${FAILED_NAMES[@]}"; do printf '  \033[31m✗ %s\033[0m\n' "$n" >&2; done
    return 1
  fi
  # A suite that asserted NOTHING is not a suite that passed. Its subject may be
  # unreachable from here — a quota spent, a credential this machine does not
  # hold — and the run is then worth exactly as much as it judged. Returning 0
  # here would print a green tick over a count of zero, which is the reading
  # every skip in this harness exists to prevent. 3 is the runner's
  # "ran nothing" code (`run_hos_suite.sh`, `run_custody.sh`).
  if (( PASS == 0 )); then
    warn "NOTHING RAN in $name — every probe stepped aside; see the SKIP lines above for why"
    return 3
  fi
  return 0
}

# ── preflight ────────────────────────────────────────────────────────────────

hos_require() {
  local tool
  for tool in jq curl near openssl base64; do
    command -v "$tool" >/dev/null || { echo "✗ missing $tool" >&2; exit 1; }
  done
  [[ -n "$PARENT" ]] || { echo "USAGE: PARENT=you.testnet $0 --apply" >&2; exit 1; }
  CREDS_DIR="$HOME/.near-credentials/$NETWORK"
  [[ -f "$CREDS_DIR/$PARENT.json" ]] || { echo "✗ creds missing: $CREDS_DIR/$PARENT.json" >&2; exit 1; }
  PARENT_PRIVKEY=$(jq -r '.private_key' "$CREDS_DIR/$PARENT.json")
  RECOVERY_BIN="$REPO_ROOT/scripts/customer-recovery/target/release/customer-recovery"
  if [[ ! -x "$RECOVERY_BIN" ]]; then
    note "building customer-recovery (bearer-token signer)"
    (cd "$REPO_ROOT/scripts/customer-recovery" && cargo build --release --quiet) \
      || { echo "✗ customer-recovery build failed" >&2; exit 1; }
  fi
}

# ── coordinator client, throttled ────────────────────────────────────────────
#
# One bucket for the whole process. 78/minute against a 100/minute limiter
# leaves headroom for the chain-side calls a suite makes through near-cli and
# for anything else running from this IP.

HOS_RL_LIMIT="${HOS_RL_LIMIT:-78}"
HOS_RL_COUNT=0
HOS_RL_WINDOW=$(date +%s)

throttle() {
  local now elapsed
  now=$(date +%s); elapsed=$(( now - HOS_RL_WINDOW ))
  if (( elapsed >= 60 )); then HOS_RL_COUNT=0; HOS_RL_WINDOW=$now; return; fi
  if (( HOS_RL_COUNT >= HOS_RL_LIMIT )); then
    local wait=$(( 61 - elapsed ))
    note "IP rate-limit throttle: sleeping ${wait}s (${HOS_RL_COUNT} calls this window)"
    sleep "$wait"
    HOS_RL_COUNT=0; HOS_RL_WINDOW=$(date +%s)
  fi
  HOS_RL_COUNT=$(( HOS_RL_COUNT + 1 ))
}

mk_token() { "$RECOVERY_BIN" sign-bearer-near --private-key "$PARENT_PRIVKEY" --account-id "$PARENT" --seed "$1"; }
AUTH_FOR() { echo "Authorization: Bearer near:$(mk_token "$1")"; }

# api <seed|-> <METHOD> <path> [body-json] [extra curl args…]
# `-` as the seed sends NO Authorization header. Echoes "<http> <body>".
HTTP=""; BODY=""
api() {
  local seed=$1 method=$2 path=$3 body=${4:-}; shift 4 2>/dev/null || shift $#
  local out http
  throttle
  out=$(mktemp -t hos_api.XXXXXX)
  local -a args=(-sS -o "$out" -w '%{http_code}' -X "$method" "$COORDINATOR_URL$path" --max-time 60)
  [[ "$seed" != "-" ]] && args+=(-H "$(AUTH_FOR "$seed")")
  if [[ -n "$body" ]]; then args+=(-H 'Content-Type: application/json' --data-binary "$body"); fi
  args+=("$@")
  http=$(curl "${args[@]}" 2>/dev/null)
  HTTP="$http"; BODY="$(tr -d '\n' < "$out")"
  rm -f "$out"
  printf '%s %s\n' "$HTTP" "$BODY"
}

# api_raw <seed> <METHOD> <path> <raw-body> — body sent verbatim (may be
# invalid JSON on purpose).
api_raw() { api "$1" "$2" "$3" "$4"; }

# api_wk <wk_key> <METHOD> <path> [body] — the same, authenticated by a `wk_`
# rather than a NEAR-signed bearer. Needed wherever the wallet under test is
# one the coordinator MINTED (POST /register) rather than one derived from an
# account we hold the key for.
api_wk() {
  local key=$1 method=$2 path=$3 body=${4:-} out http
  throttle
  out=$(mktemp -t hos_apiwk.XXXXXX)
  local -a args=(-sS -o "$out" -w '%{http_code}' -X "$method" "$COORDINATOR_URL$path" --max-time 90
                 -H "Authorization: Bearer $key")
  [[ -n "$body" ]] && args+=(-H 'Content-Type: application/json' --data-binary "$body")
  http=$(curl "${args[@]}" 2>/dev/null)
  HTTP="$http"; BODY="$(tr -d '\n' < "$out")"
  rm -f "$out"
  printf '%s %s\n' "$HTTP" "$BODY"
}

# bool_of <field> [body] — a BOOLEAN out of a JSON body, or "absent".
#
# Not `jq -r '.terminal // ""'`: jq's `//` treats FALSE as empty, exactly like
# null, so a correct `terminal: false` reads as absent and a probe asserting it
# can never pass — while its failure message sends the reader looking for a
# field that was there all along.
bool_of() {
  local body=${2:-$BODY}
  # An EMPTY body needs its own arm: jq reads no input, prints nothing and exits
  # 0, so neither a catch nor a `||` ever fires and the caller is back to
  # comparing against a blank — which is the whole reason this helper exists.
  [[ -n "${body// /}" ]] || { echo absent; return; }
  # `try … catch` INSIDE jq, not just `2>/dev/null` outside it: `has` throws on a
  # body that is not an object — an HTML error page, a bare array — and the
  # swallowed error printed nothing at all.
  jq -r --arg f "$1" 'try (if has($f) then (.[$f]|tostring) else "absent" end) catch "absent"' \
    <<<"$body" 2>/dev/null || echo absent
}

err_of()   { jq -r '.error // ""' <<<"${1:-$BODY}" 2>/dev/null; }
class_of() { jq -r '.class // ""' <<<"${1:-$BODY}" 2>/dev/null; }
msg_of()   { jq -r '.message // .error // ""' <<<"${1:-$BODY}" 2>/dev/null | head -c 300; }

# ── assertions ───────────────────────────────────────────────────────────────

# Has the wallet under test run out of allowance rather than been refused by a
# rule? The monthly custody cap and the daily connector quota are LIMITS, and a
# suite that reports one as a policy failure sends the reader to fix the wrong
# thing — the mistake the admin runbook calls out by name.
exhausted() {
  grep -qiE "limit reached: [0-9]+ per (month|day) for custody|Daily connector quota reached|already has its trial key" <<<"$BODY"
}

# assert_status <desc> <expected-http>
assert_status() {
  if exhausted; then skip "$1 — the wallet has spent its monthly custody allowance; the rule was never reached"; return 0; fi
  local desc=$1 want=$2
  if [[ "$HTTP" == "$want" ]]; then pass "$desc (HTTP $HTTP)"; return 0; fi
  fail "$desc — expected HTTP $want, got $HTTP: $(msg_of)"; return 1
}

# assert_denied <desc> [error-code] — any 4xx refusal, optionally with the
# coordinator's own error code.
assert_denied() {
  if exhausted; then skip "$1 — the wallet has spent its monthly custody allowance; the rule was never reached"; return 0; fi
  local desc=$1 want_err=${2:-}
  if [[ ! "$HTTP" =~ ^4 ]]; then
    fail "$desc — expected a refusal, got HTTP $HTTP: $(msg_of)"; return 1
  fi
  if [[ -n "$want_err" && "$(err_of)" != "$want_err" ]]; then
    fail "$desc — refused ($HTTP) but as '$(err_of)', not '$want_err': $(msg_of)"; return 1
  fi
  pass "$desc — refused $HTTP $(err_of): $(msg_of | head -c 120)"; return 0
}

# assert_class <desc> <class> — an agent_connect_denied carrying exactly this
# class (`rule` or `rule:subcode`).
assert_class() {
  if exhausted; then skip "$1 — the wallet has spent its monthly custody allowance; the rule was never reached"; return 0; fi
  local desc=$1 want=$2 got
  got=$(class_of)
  if [[ "$HTTP" == "403" && "$got" == "$want" ]]; then
    pass "$desc — class '$got'"; return 0
  fi
  fail "$desc — expected 403 class '$want', got HTTP $HTTP class '${got:-none}' err '$(err_of)': $(msg_of | head -c 160)"
  return 1
}

# assert_msg <desc> <grep-pattern> — the refusal NAMES the thing. A bare status
# assertion passes on any generic error; the point of most of these refusals is
# that the caller is told which rule bit.
# The quota guard is needed HERE too, and not only in the status assertions
# above: these two are chained after them — `assert_denied … && assert_msg …` —
# and a skip returns 0, so the chain runs on. Without this, an exhausted wallet
# skipped the status and then FAILED on the sentence, reporting a monthly cap as
# a missing diagnostic.
assert_msg() {
  if exhausted; then skip "$1 — the wallet has spent its monthly custody allowance; the rule was never reached"; return 0; fi
  local desc=$1 pat=$2
  if grep -qiE "$pat" <<<"$BODY"; then pass "$desc — message names /$pat/"; return 0; fi
  fail "$desc — message does not name /$pat/: $(msg_of | head -c 200)"; return 1
}

assert_json() {
  if exhausted; then skip "$1 — the wallet has spent its monthly custody allowance; the rule was never reached"; return 0; fi
  local desc=$1 expr=$2 want=$3 got
  got=$(jq -r "$expr // \"\"" <<<"$BODY" 2>/dev/null)
  if [[ "$got" == "$want" ]]; then pass "$desc ($expr = $got)"; return 0; fi
  fail "$desc — $expr is '$got', expected '$want'"; return 1
}

# ── the coordinator's own rows ───────────────────────────────────────────────
#
# `PSQL_CMD` is a command the operator supplies that runs ONE statement of SQL
# against the coordinator's database and prints tuples only — see
# `.idea/TESTING-WITH-ADMIN.md`. The database is not reachable off the
# coordinator's host, so a suite that needs it either is given a command or says
# out loud that it judged nothing.
#
# An empty answer means two entirely different things: the row is not there
# (yet), or the transport died on the way. A wrapper over ssh returns the empty
# string for the second as readily as for the first — with ssh multiplexing left
# on it does so on every call after the first — and a probe that then compares
# "" against "" reports a pass. So nothing here interprets an absence until
# `sql_alive` has shown the command works at all, and `sql_row` waits for a row
# that may simply be late.
PSQL_CMD="${PSQL_CMD:-}"

sql() { [[ -n "$PSQL_CMD" ]] && $PSQL_CMD "$1"; }

# Does reading the coordinator's rows work at all? Asks a question whose answer
# cannot be empty, so a broken command is told apart from an absent row BEFORE
# either is believed.
sql_alive() {
  [[ -n "$PSQL_CMD" ]] || return 1
  [[ "$(sql "SELECT 'alive'")" == "alive" ]]
}

# sql_row <statement> [attempts] — one row, waited for. A row written by the
# worker's callback lands seconds after the answer the client already has, so an
# immediate read of a correct system finds nothing. Empty only after the wait.
sql_row() {
  local q=$1 n=${2:-10} out
  for _ in $(seq 1 "$n"); do
    out=$(sql "$q"); [[ -n "$out" ]] && { printf '%s' "$out"; return 0; }
    sleep 3
  done
  return 1
}

# ── chain ────────────────────────────────────────────────────────────────────

account_field() {
  curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' --max-time 30 \
    -d "$(jq -nc --arg a "$1" '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"view_account",finality:"final",account_id:$a}}')" \
    2>/dev/null | jq -r ".result.$2 // \"null\"" 2>/dev/null || echo null
}

account_exists() { [[ "$(account_field "$1" amount)" != "null" ]]; }

near_view() {
  local acc=$1 method=$2 args=${3:-'{}'}
  curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' --max-time 30 \
    -d "$(jq -nc --arg a "$acc" --arg m "$method" --arg g "$(printf '%s' "$args" | base64)" \
        '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"call_function",finality:"final",account_id:$a,method_name:$m,args_base64:$g}}')" \
    2>/dev/null | jq -r 'if .result.result then (.result.result | implode) else (.error.cause.name // "ERR") end' 2>/dev/null
}

near_tty() {
  if command -v script >/dev/null 2>&1 && [ -t 1 ]; then
    local tmp; tmp=$(mktemp -t hos_cmd.XXXXXX.sh)
    printf 'set -euo pipefail\n%s\n' "$*" > "$tmp"
    script -q /dev/null bash "$tmp"; local rc=$?; rm -f "$tmp"; return $rc
  else eval "$@"; fi
}

fund_account() {
  near --quiet tokens "$PARENT" send-near "$1" "$2 NEAR" \
    network-config "$NETWORK" sign-with-keychain send >/dev/null 2>&1
}

create_subaccount() {
  local acc=$1 amount=$2
  near account create-account fund-myself "$acc" "$amount NEAR" \
    autogenerate-new-keypair save-to-keychain sign-as "$PARENT" \
    network-config "$NETWORK" sign-with-keychain send >/dev/null 2>&1
  local i
  for i in 1 2 3 4 5 6; do account_exists "$acc" && return 0; sleep 2; done
  return 1
}

delete_account() {
  near account delete-account "$1" beneficiary "$PARENT" \
    network-config "$NETWORK" sign-with-keychain send >/dev/null 2>&1 || true
}

# install_wallet <asset-account> <executor> — the setup kit's three actions,
# signed by the account's own key (which we hold, since we created it).
install_wallet() {
  local acc=$1 executor=$2 add_args
  add_args=$(jq -nc --arg e "$executor" '{request:{internal:[{op:"add_extension",payload:{account_id:$e}}]}}')
  near transaction construct-transaction "$acc" receiver-id "$acc" \
    add-action use-global-contract use-global-hash "$PINNED_HASH_B58" without-init-call \
    add-action function-call w_init json-args '{}' \
      prepaid-gas '30.0 Tgas' attached-deposit '1 yoctoNEAR' \
    add-action function-call w_execute_extension json-args "$add_args" \
      prepaid-gas '30.0 Tgas' attached-deposit '1 yoctoNEAR' \
    skip network-config "$NETWORK" sign-with-keychain send >/dev/null 2>&1
  [[ "$(account_field "$acc" global_contract_hash)" == "$PINNED_HASH_B58" ]]
}

# extension_op <asset-account> <op-json> — an owner-signed w_execute_extension
# (used to add/remove an executor out of band, i.e. §6 lifecycle).
extension_op() {
  local acc=$1 req=$2
  near --quiet contract call-function as-transaction "$acc" w_execute_extension \
    json-args "$req" prepaid-gas '30.0 Tgas' attached-deposit '1 yoctoNEAR' \
    sign-as "$acc" network-config "$NETWORK" sign-with-keychain send >/dev/null 2>&1
}

# ── policy ───────────────────────────────────────────────────────────────────

# store_policy <seed> <wallet_id> <rules-json> — encrypt, sign, put on chain.
store_policy() {
  local seed=$1 wid=$2 pol=$3 body enc encb64 sg sig_hex pub_hex store_args
  body=$(jq -nc --arg wid "$wid" --argjson p "$pol" '$p + {wallet_id:$wid}')
  throttle
  enc=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/encrypt-policy" --max-time 60 \
    -H "$(AUTH_FOR "$seed")" -H 'Content-Type: application/json' -d "$body")
  encb64=$(jq -r '.encrypted_base64 // empty' <<<"$enc")
  [[ -n "$encb64" ]] || { warn "encrypt-policy failed: $(head -c 200 <<<"$enc")"; return 1; }
  throttle
  sg=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/sign-policy" --max-time 60 \
    -H "$(AUTH_FOR "$seed")" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg ed "$encb64" --arg c "$PARENT" '{encrypted_data:$ed, caller:$c}')")
  sig_hex=$(jq -r '.signature_hex // empty' <<<"$sg")
  pub_hex=$(jq -r '.public_key_hex // empty' <<<"$sg")
  [[ -n "$sig_hex" ]] || { warn "sign-policy failed: $(head -c 200 <<<"$sg")"; return 1; }
  # Side effect on purpose: this is the only place the wallet's own public key
  # is revealed, and `freeze_wallet` needs it. Asking for it separately means a
  # second sign-policy call, which the keystore refuses without a genuine
  # ciphertext to attest.
  WALLET_PUBKEY="ed25519:$pub_hex"
  store_args=$(jq -nc --arg pk "ed25519:$pub_hex" --arg ed "$encb64" --arg sg "$sig_hex" \
    '{wallet_pubkey:$pk, encrypted_data:$ed, wallet_signature:$sg}')
  # Retried once: several suites store policies back to back from the same
  # key, and a swallowed nonce collision would otherwise leave the NEXT case
  # judged against the PREVIOUS policy — the worst possible failure, because it
  # reads as a product defect in whichever case runs next.
  local attempt
  for attempt in 1 2; do
    if near_tty "near contract call-function as-transaction $CONTRACT_ID store_wallet_policy \
      json-args '$store_args' prepaid-gas '100.0 Tgas' attached-deposit '0.1 NEAR' \
      sign-as $PARENT network-config $NETWORK sign-with-keychain send" >/dev/null 2>&1; then
      sleep 4
      return 0
    fi
    warn "store_wallet_policy attempt $attempt failed"
    sleep 5
  done
  return 1
}

WALLET_PUBKEY=""

# ── wallets ──────────────────────────────────────────────────────────────────

# wallet_address <seed> — echoes "<wallet_id> <near-address>".
wallet_address() {
  local r
  api "$1" GET "/wallet/v1/address?chain=near" >/dev/null
  r="$BODY"
  printf '%s %s\n' "$(jq -r '.wallet_id // empty' <<<"$r")" "$(jq -r '.address // empty' <<<"$r")"
}

# new_bound_wallet <tag> — mint a wallet, create a named account, install the
# pinned no-sign contract with this wallet's executor in its extension set, and
# wait for the binding to go ACTIVE. Sets SEED / WALLET_ID / EXECUTOR / ASSET.
#
# Exists because the monthly custody cap is per WALLET (100 operations) and the
# heavier suites spend most of one on their own. Sharing a fixture across all of
# them made whichever ran last fail on the cap — which reads exactly like a
# policy defect and is not one.
new_bound_wallet() {
  local tag=$1 status=""
  SEED="hos-$tag-$(date +%s)-$$"
  read -r WALLET_ID EXECUTOR < <(wallet_address "$SEED")
  [[ -n "$WALLET_ID" ]] || { warn "$tag: /address failed"; return 1; }
  ASSET="hos-$tag-$(openssl rand -hex 3).$PARENT"
  note "$tag: wallet $WALLET_ID / executor $EXECUTOR / account $ASSET"
  create_subaccount "$ASSET" 1.2 || { warn "$tag: $ASSET never appeared"; return 1; }
  api "$SEED" PUT /wallet/v1/binding "$(jq -nc --arg a "$ASSET" '{asset_account_id:$a, kind:"personal_account"}')" >/dev/null
  [[ "$HTTP" == "200" ]] || { warn "$tag: PUT failed $HTTP: $BODY"; return 1; }
  install_wallet "$ASSET" "$EXECUTOR" || { warn "$tag: the setup transaction did not land"; return 1; }
  fund_account "$EXECUTOR" 0.3
  local i
  for i in 1 2 3 4 5 6 7 8; do
    api "$SEED" GET /wallet/v1/binding >/dev/null
    status=$(jq -r '.binding_status // ""' <<<"$BODY")
    [[ "$status" == "active" ]] && break
    sleep 3
  done
  [[ "$status" == "active" ]] || { warn "$tag: the binding never went active ('$status')"; return 1; }
  pass "$tag: a fresh bound wallet, with its full monthly custody allowance"
}

# buy_payment_key <wk_key> <wallet-near-address> — a payment key for a wallet
# the coordinator MINTED, bought with stablecoin instead of claimed as a trial.
#
# The trial route is capped at three keys per IP and the counter is in the
# coordinator's memory, so a suite that can only claim trials loses itself to a
# quota — and §5, which judges the HTTPS half of `use_bound_identity`, is the
# suite that finds things. This route spends the PARENT's testnet USDC instead
# and is not capped.
#
# NOT the NEAR-deposit route: `top_up_payment_key_with_near` wraps NEAR and
# swaps it through Intents, and its own contract doc says it works on mainnet
# only. On testnet its third promise calls `request_execution` for a project
# that does not exist there and the whole call panics with "Project not found",
# which reads as a coordinator defect and is not one.
#
# Sets PAID_KEY on success.
PAID_KEY=""
buy_payment_key() {
  local wk=$1 addr=$2 reg="" have="" i
  local token="${TOKEN_CONTRACT:-usdc.fakes.testnet}"
  local minimal="${FUND_USDC_MINIMAL:-1500000}" deposit="${DEPOSIT_USDC:-0.30}"
  PAID_KEY=""

  near --quiet contract call-function as-transaction "$token" storage_deposit \
    json-args "$(jq -nc --arg a "$addr" '{account_id:$a, registration_only:true}')" \
    prepaid-gas '30.0 Tgas' attached-deposit '0.00125 NEAR' \
    sign-as "$PARENT" network-config "$NETWORK" sign-with-keychain send >/dev/null 2>&1
  # The registration has to be FINAL before the tokens are sent: NEP-141 refuses
  # a transfer to an account it has not registered, and the two calls go out on
  # one access key back to back.
  for i in $(seq 1 10); do
    reg=$(near_view "$token" storage_balance_of "$(jq -nc --arg a "$addr" '{account_id:$a}')")
    [[ -n "$reg" && "$reg" != "null" && "$reg" != "ERR" ]] && break
    reg=""; sleep 2
  done
  [[ -n "$reg" ]] || { warn "$token never registered $addr — the storage_deposit did not land"; return 1; }

  near --quiet contract call-function as-transaction "$token" ft_transfer \
    json-args "$(jq -nc --arg a "$addr" --arg m "$minimal" '{receiver_id:$a, amount:$m}')" \
    prepaid-gas '30.0 Tgas' attached-deposit '1 yoctoNEAR' \
    sign-as "$PARENT" network-config "$NETWORK" sign-with-keychain send >/dev/null 2>&1
  # NEAR as well as tokens: the key is created by transactions the KEYSTORE
  # signs as this wallet, and they pay their own gas and storage deposits.
  fund_account "$addr" 1.0

  for i in $(seq 1 10); do
    have=$(near_view "$token" ft_balance_of "$(jq -nc --arg a "$addr" '{account_id:$a}')" | tr -d '"')
    [[ -n "$have" && "$have" != "null" && "$have" != "ERR" ]] \
      && python3 -c "exit(0 if int('$have') >= int('$minimal') else 1)" && break
    have=""; sleep 3
  done
  [[ -n "$have" ]] || { warn "the stablecoin never arrived at $addr — create-payment-key would answer 402, correctly"; return 1; }

  api_wk "$wk" POST /wallet/v1/create-payment-key "$(jq -nc --arg d "$deposit" '{initial_deposit_usdc:$d}')" >/dev/null
  PAID_KEY=$(jq -r '.payment_key // empty' <<<"$BODY")
  # The SENTENCE first, the code second: these refusals name the figure that is
  # short, and a bare `wallet_underfunded` sends the reader to the coordinator
  # instead of to the funding above.
  [[ -n "$PAID_KEY" ]] || { warn "create-payment-key refused (HTTP $HTTP): $(jq -r '.message // .error // .' <<<"$BODY" | head -c 200)"; return 1; }
  return 0
}

# ── the w_execute_extension envelope ─────────────────────────────────────────

b64() { printf '%s' "$1" | base64 | tr -d '\n'; }

# ext_transfer <receiver> <yocto> [refund_to]
ext_transfer() {
  local to=$1 amt=$2 refund=${3:-}
  if [[ -n "$refund" ]]; then
    jq -nc --arg r "$to" --arg a "$amt" --arg f "$refund" \
      '{request:{external:[{receiver_id:$r, refund_to:$f, actions:[{action:"transfer",payload:{amount:$a}}]}]}}'
  else
    jq -nc --arg r "$to" --arg a "$amt" \
      '{request:{external:[{receiver_id:$r, actions:[{action:"transfer",payload:{amount:$a}}]}]}}'
  fi
}

# ext_call <receiver> <method> <args-json> <deposit-yocto> [gas]
ext_call() {
  local to=$1 m=$2 a=$3 dep=$4 gas=${5:-30000000000000}
  jq -nc --arg r "$to" --arg m "$m" --arg a "$(b64 "$3")" --arg d "$dep" --arg g "$gas" \
    '{request:{external:[{receiver_id:$r, actions:[{action:"function_call",payload:{function_name:$m,args:$a,deposit:$d,gas:$g}}]}]}}'
}

# call_ext <seed> <asset-account> <envelope-json> [deposit] — POST /wallet/v1/call
# with the envelope in args_base64, exactly as a client would build it.
call_ext() {
  local seed=$1 acc=$2 env=$3 dep=${4:-1}
  api "$seed" POST /wallet/v1/call "$(jq -nc --arg r "$acc" --arg a "$(b64 "$env")" --arg d "$dep" \
      '{receiver_id:$r, method_name:"w_execute_extension", args_base64:$a, deposit:$d, gas:"90000000000000"}')"
}

# call_ext_raw <seed> <asset-account> <raw-args-base64> [deposit] — for the
# cases where the args are deliberately not a valid envelope.
call_ext_raw() {
  local seed=$1 acc=$2 a=$3 dep=${4:-1}
  api "$seed" POST /wallet/v1/call "$(jq -nc --arg r "$acc" --arg a "$a" --arg d "$dep" \
      '{receiver_id:$r, method_name:"w_execute_extension", args_base64:$a, deposit:$d, gas:"90000000000000"}')"
}
