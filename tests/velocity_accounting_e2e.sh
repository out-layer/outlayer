#!/usr/bin/env bash
#
# What the velocity counters are actually fed, on a live chain.
#
# Every other velocity test in this repo asks whether a limit REFUSES. This one
# asks the prior question — whether the number the limit is compared against is
# the money that moved. A ceiling checked against an inflated total refuses
# lawful calls, and nothing in the product says so: the owner sees a policy
# denial and concludes the policy is wrong.
#
# The rule the counters follow: what you attach is what you spend. A call that
# attaches a generous deposit against a refund is charged the whole deposit.
# Crediting the change back would take a second RPC round trip per call to read
# the receipts, a credit that must land in the bucket the charge went to rather
# than the current one, and a clamp so a contract PAYING the wallet cannot be
# mistaken for change. U7/U8 pin the rule so nobody "fixes" it by accident.
#
# Probes:
#   U5   a native transfer that succeeded charges its amount
#   U6   a native transfer that failed on chain charges nothing, and still
#        consumes the hourly TRANSACTION count — the cap is max_per_hour, not
#        max_successful_per_hour, and a limiter a caller walks past by failing
#        its own transfers is not a limiter
#   U7   an ordinary call charges its ATTACHED deposit, not what it cost — the
#        rule, pinned: attach less if you want to spend less
#   U8   an ordinary call that panicked still charges its deposit — same rule,
#        and the conservative side of it
#   U9   the buckets are CALENDAR periods keyed `hourly:<UTC>T<HH>` / `daily:<UTC>`,
#        not a rolling window, and the charge landed in the current one
#   U10  the ceiling holds: a spend past the remaining headroom is refused, the
#        refusal names the window it broke, and it charges nothing
#
# Deltas are read against the DAILY bucket, not the hourly one: the run is short
# but an hour boundary inside it would make every hourly delta a lie. U9 checks
# the hourly key separately, which is where the calendar-vs-rolling question
# belongs anyway.
#
# Requires $PSQL_CMD — the counters are not exposed by any endpoint, and a probe
# that judged them by whether a later call was refused would pass on a
# coordinator that never counted at all.
#
# Money: the probes move ~0.02 NEAR out of the wallet under test, plus gas and
# one 0.1 NEAR storage deposit per policy store. Nothing is swept automatically
# — a caller may be reusing the wallet — so the run prints what it left behind.
#
# Run (spends real testnet NEAR):
#   PARENT=you.testnet PSQL_CMD=./tsql ./tests/velocity_accounting_e2e.sh --apply
#
# Reuse a wallet of an earlier run instead of minting one:
#   PARENT=you.testnet PSQL_CMD=./tsql WALLET_SEED=velacct-... \
#     ./tests/velocity_accounting_e2e.sh --apply

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPLY=false
[[ "${1:-}" == "--apply" ]] && APPLY=true

NETWORK="${NETWORK:-testnet}"
CONTRACT_ID="${CONTRACT_ID:-outlayer.testnet}"
COORDINATOR_URL="${COORDINATOR_URL:-https://testnet-api.outlayer.ai}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/rpc.sh"   # keyed RPC_URL, or a warning
TOKEN_CONTRACT="${TOKEN_CONTRACT:-usdc.fakes.testnet}"
PARENT="${PARENT:-}"
PSQL_CMD="${PSQL_CMD:-}"
WALLET_SEED="${WALLET_SEED:-}"

# The ceiling the run is built around, and the amounts either side of it.
DAILY_LIMIT="200000000000000000000000"   # 0.2  NEAR — daily native
PER_TX_LIMIT="50000000000000000000000"   # 0.05 NEAR — per transaction
SMALL="10000000000000000000000"          # 0.01 NEAR
TINY="1000000000000000000000"            # 0.001 NEAR
FUND_NEAR="0.25"

PASS=0; FAILED=0; FAILED_NAMES=()
log()  { printf '\n\033[36m▶ %s\033[0m\n' "$*" >&2; }
note() { printf '\033[35m• %s\033[0m\n' "$*" >&2; }
warn() { printf '\033[33m⚠ %s\033[0m\n' "$*" >&2; }
pass() { printf '\033[32m✓ %s\033[0m\n' "$*" >&2; PASS=$((PASS+1)); }
fail() { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; FAILED=$((FAILED+1)); FAILED_NAMES+=("$*"); }

if [[ "$APPLY" != true ]]; then
  sed -n '3,51p' "$0" >&2
  echo "  Pass --apply to run." >&2
  exit 0
fi

[[ -n "$PARENT" ]] || { echo "USAGE: PARENT=you.testnet PSQL_CMD=./tsql $0 --apply" >&2; exit 1; }
[[ -n "$PSQL_CMD" ]] \
  || { echo "✗ PSQL_CMD is required — the counters live only in the database" >&2; exit 1; }
for tool in jq curl near python3 cargo; do
  command -v "$tool" >/dev/null || { echo "✗ missing $tool" >&2; exit 1; }
done
CREDS_DIR="$HOME/.near-credentials/$NETWORK"
[[ -f "$CREDS_DIR/$PARENT.json" ]] || { echo "✗ creds missing: $CREDS_DIR/$PARENT.json" >&2; exit 1; }
# Without this `outlayer` follows ~/.outlayer/default-network, which is mainnet
# on this machine — and a mainnet run of this script spends real money.
export OUTLAYER_NETWORK="$NETWORK"
PARENT_PRIVKEY=$(jq -r '.private_key' "$CREDS_DIR/$PARENT.json")

RECOVERY_BIN="$SCRIPT_DIR/../scripts/customer-recovery/target/release/customer-recovery"
log "Building customer-recovery (sign-bearer-near)"
(cd "$SCRIPT_DIR/../scripts/customer-recovery" && cargo build --release --quiet) \
  || { echo "✗ customer-recovery build failed" >&2; exit 1; }

near_tty() {
  if command -v script >/dev/null 2>&1 && [ -t 1 ]; then
    local tmp; tmp=$(mktemp -t velacct_cmd.XXXXXX.sh)
    printf 'set -euo pipefail\n%s\n' "$*" > "$tmp"
    script -q /dev/null bash "$tmp"; local rc=$?; rm -f "$tmp"; return $rc
  else eval "$@"; fi
}

sql() { $PSQL_CMD "$1"; }
# Every assertion here reads the counters, and `usage_of` turns any error into
# "0" — so a wrapper that does not work makes half this suite pass on silence.
sql "SELECT 1" >/dev/null 2>&1 \
  || { echo "✗ PSQL_CMD does not work — every counter would read 0 and most probes would pass blind" >&2; exit 1; }
mk_token() { CUSTOMER_RECOVERY_PRIVATE_KEY="$PARENT_PRIVKEY" "$RECOVERY_BIN" sign-bearer-near --account-id "$PARENT" --seed "$1"; }
AUTH() { echo "Authorization: Bearer near:$(mk_token "$1")"; }

chain_balance() {
  curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg a "$1" '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"view_account",finality:"final",account_id:$a}}')" \
    2>/dev/null | jq -r 'if .result.amount then .result.amount else "0" end' 2>/dev/null || echo "0"
}

# Big-integer helpers. Yocto amounts are 24 digits: shell arithmetic silently
# truncates them and `[[ a < b ]]` compares them as strings, where 0.2 sorts
# below 0.05. Both of those produced false passes here before.
sub() { python3 -c "print(int('${1:-0}')-int('${2:-0}'))"; }
eq()  { python3 -c "exit(0 if int('${1:-0}')==int('${2:-0}') else 1)"; }

# The counter for one token in one period, "0" when the row does not exist yet.
usage_of() { # usage_of <wallet_id> <period>
  local v
  v=$(sql "SELECT total_amount FROM wallet_usage WHERE wallet_id='$1' AND token='native' AND period='$2'" 2>/dev/null | tr -d '[:space:]')
  [[ -n "$v" ]] || v=0
  echo "$v"
}
today_daily() { echo "daily:$(date -u +%Y-%m-%d)"; }
this_hour()   { echo "hourly:$(date -u +%Y-%m-%dT%H)"; }

# The transaction COUNT for one period — a different cap from the amount
# windows (`rate_limit.max_per_hour`), and fed by the same writer.
txcount_of() { # txcount_of <wallet_id> <period>
  local v
  v=$(sql "SELECT tx_count FROM wallet_usage WHERE wallet_id='$1' AND token='native' AND period='$2'" 2>/dev/null | tr -d '[:space:]')
  [[ -n "$v" ]] || v=0
  echo "$v"
}

# judge <probe> <wallet_id> <before> <expected-delta> <why>
judge() {
  local probe=$1 wid=$2 before=$3 want=$4 why=$5 after got
  after=$(usage_of "$wid" "$(today_daily)")
  got=$(sub "$after" "$before")
  if eq "$got" "$want"; then
    pass "$probe charged $got — $why"
  else
    fail "$probe charged $got, expected $want — $why"
    note "$probe   daily native: $before → $after"
  fi
}

store_policy() { # store_policy <seed> <wallet_id> <rules-json>
  local seed=$1 wid=$2 pol=$3 body enc encb64 sg sig_hex pub_hex store_args
  body=$(jq -nc --arg wid "$wid" --argjson p "$pol" '$p + {wallet_id:$wid}')
  enc=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/encrypt-policy" \
    -H "$(AUTH "$seed")" -H 'Content-Type: application/json' -d "$body")
  encb64=$(jq -r '.encrypted_base64 // empty' <<<"$enc")
  [[ -n "$encb64" ]] || { warn "encrypt-policy failed: $(head -c 200 <<<"$enc")"; return 1; }
  sg=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/sign-policy" \
    -H "$(AUTH "$seed")" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg ed "$encb64" --arg c "$PARENT" '{encrypted_data:$ed, caller:$c}')")
  sig_hex=$(jq -r '.signature_hex // empty' <<<"$sg")
  POLICY_VERSION=$(jq -r '.version // empty' <<<"$sg")
  POLICY_LOCKED=$(jq -r '.locked // empty' <<<"$sg")
  POLICY_VALID_UNTIL=$(jq -r '.valid_until // empty' <<<"$sg")
  pub_hex=$(jq -r '.public_key_hex // empty' <<<"$sg")
  [[ -n "$sig_hex" ]] || { warn "sign-policy failed: $(head -c 200 <<<"$sg")"; return 1; }
  store_args=$(jq -nc --arg pk "ed25519:$pub_hex" --arg ed "$encb64" --argjson v "${POLICY_VERSION:-0}" --argjson l "${POLICY_LOCKED:-false}" --argjson u "${POLICY_VALID_UNTIL:-0}" --arg sg "$sig_hex" \
    '{wallet_pubkey:$pk, encrypted_data:$ed, wallet_signature:$sg, version:$v, locked:$l, valid_until:$u}')
  near_tty "near contract call-function as-transaction $CONTRACT_ID store_wallet_policy \
    json-args '$store_args' prepaid-gas '100.0 Tgas' attached-deposit '0.1 NEAR' \
    sign-as $PARENT network-config $NETWORK sign-with-keychain send" >&2 || return 1
  sleep 5
}

# Nothing here deletes anything. A caller who passed WALLET_SEED means to keep
# using the wallet; a run that swept it would break the next one. So the exit
# path REPORTS instead — an accounting test that quietly consumed accounts
# would be its own kind of leak.
cleanup() {
  local rc=$?
  [[ -n "$WID" ]] || return $rc
  log "Left in place"
  note "  wallet $WID  ($ADDR, balance $(chain_balance "$ADDR"))"
  note "  its policy still carries the run's daily/per-transaction ceilings — replace it before reusing the wallet for anything else"
  [[ -n "$MINTED" ]] && note "  it was created by THIS run (WALLET_SEED=$WALLET_SEED); reclaim it when done"
  return $rc
}
WID=""; ADDR=""
MINTED=""
trap cleanup EXIT

# ── setup: a funded wallet with a policy ─────────────────────────────────────
[[ -n "$WALLET_SEED" ]] || { WALLET_SEED="velacct-$(date +%s)-$$"; MINTED=1; }
ADDR_RESP=$(curl -sS -G "$COORDINATOR_URL/wallet/v1/address" --data-urlencode "chain=near" \
  -H "$(AUTH "$WALLET_SEED")")
WID=$(jq -r '.wallet_id // empty' <<<"$ADDR_RESP")
ADDR=$(jq -r '.address // empty' <<<"$ADDR_RESP")
[[ -n "$WID" && -n "$ADDR" ]] || { fail "setup the seed does not resolve to a wallet: $(head -c 160 <<<"$ADDR_RESP")"; exit 1; }

# The wallet pays gas for every call and spends its own balance in U5–U8. A
# drained one turns four probes into product-bug reports, so the balance is
# topped up here rather than assumed.
BAL=$(chain_balance "$ADDR")
if python3 -c "exit(0 if int('${BAL:-0}') < 200000000000000000000000 else 1)"; then
  note "wallet $ADDR holds $BAL — topping up $FUND_NEAR NEAR"
  near_tty "near --quiet tokens $PARENT send-near $ADDR '$FUND_NEAR NEAR' \
    network-config $NETWORK sign-with-keychain send" >/dev/null 2>&1
  BAL=$(chain_balance "$ADDR")
fi
python3 -c "exit(0 if int('${BAL:-0}') >= 200000000000000000000000 else 1)" \
  && pass "setup wallet $WID funded ($BAL)" \
  || { fail "setup the wallet holds $BAL — U5-U8 would fail for want of gas, not for a defect"; exit 1; }

store_policy "$WALLET_SEED" "$WID" \
  "$(jq -nc --arg d "$DAILY_LIMIT" --arg t "$PER_TX_LIMIT" \
     '{rules:{transaction_types:["call","transfer","delete"],
              limits:{daily:{native:$d}, per_transaction:{native:$t}}}}')" \
  || { fail "setup could not store the wallet's policy"; exit 1; }
pass "setup policy stored — daily $DAILY_LIMIT, per-transaction $PER_TX_LIMIT"

STRANGER="nope-$(date +%s)-$$.testnet"

# ── U5/U6: the plain transfer lane ───────────────────────────────────────────
log "U5 native /transfer of $TINY to $PARENT"
B=$(usage_of "$WID" "$(today_daily)")
XFER=$(curl -sS -w ' %{http_code}' -X POST "$COORDINATOR_URL/wallet/v1/transfer" \
  -H "$(AUTH "$WALLET_SEED")" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg to "$PARENT" --arg a "$TINY" '{chain:"near", to:$to, amount:$a}')")
sleep 4
note "U5 answer: ${XFER##* } $(head -c 120 <<<"${XFER% *}")"
judge "U5" "$WID" "$B" "$TINY" "a transfer that landed"

log "U6 native /transfer of $TINY to $STRANGER, which does not exist"
B=$(usage_of "$WID" "$(today_daily)")
HK6_BEFORE=$(this_hour)
C6_BEFORE=$(txcount_of "$WID" "$HK6_BEFORE")
# The body is KEPT. A zero delta proves nothing on its own: a 401, a 500, or an
# `HTTP 000` from the rate limiter all leave the counter untouched and would
# have passed this probe while the request never reached the chain.
XFER=$(curl -sS -w ' %{http_code}' -X POST "$COORDINATOR_URL/wallet/v1/transfer" \
  -H "$(AUTH "$WALLET_SEED")" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg to "$STRANGER" --arg a "$TINY" '{chain:"near", to:$to, amount:$a}')")
sleep 4
XCODE=${XFER##* }
note "U6 answer: $XCODE $(head -c 120 <<<"${XFER% *}")"
case "$XCODE" in
  422|200|202) pass "U6 the request reached the chain and was rejected there ($XCODE)" ;;
  000|401|403|5??) fail "U6 the request never got as far as the chain ($XCODE) — the zero below proves nothing" ;;
  *) warn "U6 unexpected $XCODE; read the body above before trusting the delta" ;;
esac
judge "U6" "$WID" "$B" 0 "a transfer the chain rejected moved nothing"
# …and it is STILL a request against the hourly rate cap. `max_per_hour` counts
# requests that reached the chain, not successes — a limiter a caller can walk
# past by making its own transfers fail is not a limiter.
# The two reads must name the same bucket or the comparison is between
# different counters.
HK6=$(this_hour)
C6=$(txcount_of "$WID" "$HK6")
if [[ "$HK6" != "$HK6_BEFORE" ]]; then
  warn "U6 SKIPPED the count half — the clock crossed an hour boundary mid-probe"
elif [[ "$C6" -gt "${C6_BEFORE:-0}" ]]; then
  pass "U6 the reverted transfer still consumed one of the hourly allowance"
else
  fail "U6 the transaction count did not move (${C6_BEFORE:-0} → $C6) — failed transfers are free against rate_limit.max_per_hour"
fi

# ── U7/U8: the ordinary call lane — PINS TODAY'S DEFECT ──────────────────────
# `storage_deposit` on an account that is already registered is a no-op: the
# token contract refunds the whole attached deposit. The money comes straight
# back and the counter keeps all of it, deliberately — see the header. If this
# assertion ever needs changing, it is because the RULE changed, and that is a
# decision, not a cleanup.
log "U7 ordinary call with $SMALL attached that the callee refunds in full"
B=$(usage_of "$WID" "$(today_daily)")
curl -sS -o /dev/null -X POST "$COORDINATOR_URL/wallet/v1/call" \
  -H "$(AUTH "$WALLET_SEED")" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg t "$TOKEN_CONTRACT" --arg d "$SMALL" \
      '{receiver_id:$t, method_name:"storage_deposit", args:{}, gas:"30000000000000", deposit:$d}')"
sleep 5
judge "U7" "$WID" "$B" "$SMALL" "the rule: the attached deposit is the spend, change is not credited back"

log "U8 ordinary call that panics, with $TINY attached"
B=$(usage_of "$WID" "$(today_daily)")
curl -sS -o /dev/null -X POST "$COORDINATOR_URL/wallet/v1/call" \
  -H "$(AUTH "$WALLET_SEED")" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg t "$TOKEN_CONTRACT" --arg d "$TINY" \
      '{receiver_id:$t, method_name:"no_such_method_here", args:{}, gas:"30000000000000", deposit:$d}')"
sleep 5
judge "U8" "$WID" "$B" "$TINY" "same rule on a refund the PROTOCOL made — the counter still keeps it"

# ── U9: the buckets are calendar periods ─────────────────────────────────────
log "U9 the period keys are calendar buckets, not a rolling window"
HOUR_KEY="hourly:$(date -u +%Y-%m-%dT%H)"
ROWS=$(sql "SELECT period FROM wallet_usage WHERE wallet_id='$WID' ORDER BY period")
note "U9 periods on this wallet: $(tr '\n' ' ' <<<"$ROWS")"
grep -q "^hourly:[0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\}T[0-9]\{2\}$" <<<"$ROWS" \
  && pass "U9 the hourly key is a clock-hour bucket (hourly:YYYY-MM-DDTHH)" \
  || fail "U9 no clock-hour bucket found — if this became a rolling window, every delta above is measuring something else"
if grep -qx "$HOUR_KEY" <<<"$ROWS"; then
  pass "U9 the run's charges landed in the CURRENT hour's bucket ($HOUR_KEY)"
elif [[ "$(this_hour)" != "$HOUR_KEY" ]]; then
  # The clock rolled between the last charge and this read, so the charge is in
  # the previous bucket and correctly so.
  warn "U9 SKIPPED the current-bucket half — the clock crossed an hour boundary mid-probe"
else
  fail "U9 nothing in $HOUR_KEY — the charge did not land in the bucket of its own timestamp"
fi

# ── U10: the ceiling still refuses ───────────────────────────────────────────
# The point is not that a limit exists — it is that it is compared against a
# total this run can predict. Spend the remaining headroom plus a little.
log "U10 a spend past the remaining daily headroom is refused, and says why"
# The headroom is CLOSED first rather than hoping the run spent enough to
# approach the ceiling. Written the other way — overshoot = headroom + a bit,
# capped by the per-transaction limit — the probe silently skipped every time,
# because 0.2 of daily room minus the ~0.02 the run spends never falls below
# the 0.05 per-transaction cap.
SPENT=$(usage_of "$WID" "$(today_daily)")
note "U10 spent $SPENT — re-storing the policy with the daily cap AT that figure"
if store_policy "$WALLET_SEED" "$WID" \
     "$(jq -nc --arg d "$SPENT" --arg t "$PER_TX_LIMIT" \
        '{rules:{transaction_types:["call","transfer","delete"],
                 limits:{daily:{native:$d}, per_transaction:{native:$t}}}}')"; then
  B=$(usage_of "$WID" "$(today_daily)")
  R=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/transfer" \
    -H "$(AUTH "$WALLET_SEED")" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg to "$PARENT" --arg a "$TINY" '{chain:"near", to:$to, amount:$a}')")
  ERR=$(jq -r '.error // ""' <<<"$R"); MSG=$(jq -r '.message // ""' <<<"$R")
  [[ "$ERR" == "policy_denied" ]] \
    && pass "U10 the ceiling refused the next yocto" \
    || fail "U10 expected policy_denied with zero headroom, got '$ERR': $(head -c 160 <<<"$MSG")"
  grep -qi "daily\|limit" <<<"$MSG" \
    && pass "U10 the refusal names the window it broke" \
    || fail "U10 the refusal says nothing an owner could act on: $(head -c 160 <<<"$MSG")"
  judge "U10" "$WID" "$B" 0 "a refusal costs nothing, so a wallet cannot be walled in by retrying"
else
  fail "U10 could not re-store the policy — the ceiling was never actually tested"
fi

# ── verdict ──────────────────────────────────────────────────────────────────
log "velocity accounting — $PASS passed, $FAILED failed"
if (( FAILED > 0 )); then
  for n in "${FAILED_NAMES[@]}"; do printf '  \033[31m✗ %s\033[0m\n' "$n" >&2; done
  exit 1
fi
exit 0
