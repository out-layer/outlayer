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
# It exists because of a measured incident (testnet, 2026-08-22, wallet
# 1895a49f). Four requests, 0.01 NEAR actually spent, 0.21 NEAR on the counter:
#
#   12:58  door transfer 0.01           → success        → charged 0.01   ✓
#   13:10  request_execution, 0.1 dep.  → never on chain → charged 0      ✓
#   13:10  request_execution, 0.1 dep.  → cost 0.0025    → charged 0.1    ✗ gross
#   13:14  door transfer 0.1            → CONTRACT REFUSED → charged 0.1  ✗ phantom
#
# The last line was a defect and U1 is its regression probe. The third is NOT a
# defect — it is the rule: what you attach is what you spend. Attaching a
# generous deposit against a refund is the caller's choice, and crediting the
# change back would mean a second RPC round trip per call to read the receipts,
# a credit that must land in the bucket the charge went to rather than the
# current one, and a clamp so a contract PAYING the wallet cannot be mistaken
# for change. Decided 2026-08-22: not worth it. U7/U8 pin the rule so nobody
# "fixes" it back by accident.
#
# Probes:
#   U1   a door call the WALLET CONTRACT refused charges nothing
#   U2   a door call that ran charges the decoded amount, never the 1-yocto marker
#   U3   two promises, one to an account that does not exist → only the one that
#        ran is charged
#   U4   a call the POLICY refused charges nothing — it never reached a chain
#   U5   a native transfer that succeeded charges its amount
#   U6   a native transfer that failed on chain charges nothing
#   U7   an ordinary call charges its ATTACHED deposit, not what it cost — the
#        rule, pinned: attach less if you want to spend less
#   U8   an ordinary call that panicked still charges its deposit — same rule,
#        and the conservative side of it
#   U9   the buckets are CALENDAR periods keyed `hourly:<UTC>T<HH>` / `daily:<UTC>`,
#        not a rolling window, and the charge landed in the current one
#   U11  a call the chain refused still consumes the hourly TRANSACTION count —
#        the cap is max_per_hour, not max_successful_per_hour, and a limiter a
#        caller walks past by failing its own calls is not a limiter
#   U10  the ceiling holds: a spend past the remaining headroom is refused, and
#        the refusal names spent + amount > limit
#   U12  the OUTER deposit of a door call is spent too, and is counted — the
#        caller picks it, so a door that did not meter it was a way past the
#        ceiling. Charged less the 1-yocto marker, which proves a key rather
#        than paying anyone
#   U13  the outer deposit AND the decoded effects, in one request: two
#        different balances, one ceiling, no double count and no missed half
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
# Money: the probes move ~0.03 NEAR out of the bound account and back to
# $PARENT, plus gas and one 0.1 NEAR storage deposit per policy store. Nothing
# is swept automatically — the wallet under test belongs to the binding, which
# a caller may be reusing — so the run prints what it left behind.
#
# Run (spends real testnet NEAR):
#   PARENT=you.testnet PSQL_CMD=./tsql ./tests/velocity_accounting_e2e.sh --apply
#
# Reuse an existing binding instead of minting one (much faster):
#   PARENT=you.testnet PSQL_CMD=./tsql BINDING_SEED=binding-... ASSET=bind-....testnet \
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
BINDING_SEED="${BINDING_SEED:-}"
ASSET="${ASSET:-}"

# The ceiling the run is built around, and the amounts either side of it.
DAILY_LIMIT="200000000000000000000000"   # 0.2  NEAR — daily native
PER_TX_LIMIT="50000000000000000000000"   # 0.05 NEAR — per transaction
SMALL="10000000000000000000000"          # 0.01 NEAR
TINY="1000000000000000000000"            # 0.001 NEAR
OVER_TX="60000000000000000000000"        # 0.06 NEAR — over the per-tx cap
FUND_NEAR="0.25"

PASS=0; FAILED=0; FAILED_NAMES=()
log()  { printf '\n\033[36m▶ %s\033[0m\n' "$*" >&2; }
note() { printf '\033[35m• %s\033[0m\n' "$*" >&2; }
warn() { printf '\033[33m⚠ %s\033[0m\n' "$*" >&2; }
pass() { printf '\033[32m✓ %s\033[0m\n' "$*" >&2; PASS=$((PASS+1)); }
fail() { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; FAILED=$((FAILED+1)); FAILED_NAMES+=("$*"); }

if [[ "$APPLY" != true ]]; then
  sed -n '3,50p' "$0" >&2
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
mk_token() { "$RECOVERY_BIN" sign-bearer-near --private-key "$PARENT_PRIVKEY" --account-id "$PARENT" --seed "$1"; }
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
  pub_hex=$(jq -r '.public_key_hex // empty' <<<"$sg")
  [[ -n "$sig_hex" ]] || { warn "sign-policy failed: $(head -c 200 <<<"$sg")"; return 1; }
  store_args=$(jq -nc --arg pk "ed25519:$pub_hex" --arg ed "$encb64" --arg sg "$sig_hex" \
    '{wallet_pubkey:$pk, encrypted_data:$ed, wallet_signature:$sg}')
  near_tty "near contract call-function as-transaction $CONTRACT_ID store_wallet_policy \
    json-args '$store_args' prepaid-gas '100.0 Tgas' attached-deposit '0.1 NEAR' \
    sign-as $PARENT network-config $NETWORK sign-with-keychain send" >&2 || return 1
  sleep 5
}

# Nothing here deletes anything. The wallet under test is the binding's, and a
# caller who passed BINDING_SEED means to keep using it; a run that swept it
# would break the next one. So the exit path REPORTS instead — an accounting
# test that quietly consumed accounts would be its own kind of leak.
cleanup() {
  local rc=$? addr
  [[ -n "$BOUND_WID" ]] || return $rc
  addr=$(curl -sS -G "$COORDINATOR_URL/wallet/v1/address" --data-urlencode chain=near \
    -H "$(AUTH "$BINDING_SEED")" 2>/dev/null | jq -r '.address // empty')
  log "Left in place"
  note "  custody wallet $BOUND_WID  ($addr, balance $(chain_balance "$addr"))"
  note "  bound account  $ASSET      (balance $(chain_balance "$ASSET"))"
  note "  its policy still carries the run's daily/per-transaction ceilings — replace it before reusing the wallet for anything else"
  [[ -n "$MADE_BINDING" ]] && note "  both were created by THIS run; reclaim them when done"
  return $rc
}
BOUND_WID=""
MADE_BINDING=""
trap cleanup EXIT

# ── setup: a binding to spend through ────────────────────────────────────────
if [[ -z "$BINDING_SEED" || -z "$ASSET" ]]; then
  log "No binding supplied — minting one with binding_lifecycle_e2e.sh (KEEP=1)"
  BL=$(mktemp -t velacct_bind.XXXXXX)
  PARENT="$PARENT" KEEP=1 "$SCRIPT_DIR/binding_lifecycle_e2e.sh" --apply 2>&1 | tee "$BL" >&2
  # binding_lifecycle prints that line through its coloured `note()`, so the
  # LAST field on it carries the trailing reset escape and `[^ ]*` swallows it.
  # A seed with `\033[0m` glued on derives a different wallet with no binding,
  # and the run then dies at the status check below having already spent the
  # NEAR it took to mint the account.
  strip_ansi() { sed $'s/\033\[[0-9;]*m//g' "$1"; }
  BINDING_SEED=$(strip_ansi "$BL" | grep -o 'BINDING_SEED=[^ ]*' | tail -1 | cut -d= -f2)
  ASSET=$(strip_ansi "$BL" | grep -o 'ASSET=[^ ]*' | tail -1 | cut -d= -f2)
  rm -f "$BL"
  [[ -n "$BINDING_SEED" && -n "$ASSET" ]] \
    || { fail "could not mint a binding — pass BINDING_SEED and ASSET instead"; exit 1; }
  MADE_BINDING=1
fi
BOUND_WID=$(curl -sS -G "$COORDINATOR_URL/wallet/v1/address" --data-urlencode "chain=near" \
  -H "$(AUTH "$BINDING_SEED")" | jq -r '.wallet_id // empty')
[[ -n "$BOUND_WID" ]] || { fail "the binding seed does not resolve to a wallet"; exit 1; }
BSTATUS=$(curl -sS "$COORDINATOR_URL/wallet/v1/binding" -H "$(AUTH "$BINDING_SEED")" | jq -r '.binding_status // "none"')
[[ "$BSTATUS" == "active" ]] \
  && pass "setup binding on $ASSET is active (wallet $BOUND_WID)" \
  || { fail "setup the binding is '$BSTATUS', not active — every door probe below would fail for the wrong reason"; exit 1; }

# The executor pays gas for every door call and spends its own balance in U5–U8.
# A reused binding whose executor has been drained turns four probes into
# product-bug reports, so the balance is topped up here rather than assumed.
# ($FUND_NEAR exists for exactly this; an earlier version declared it and never
# used it, which is how the gap went unnoticed.)
EXEC_ADDR=$(curl -sS -G "$COORDINATOR_URL/wallet/v1/address" --data-urlencode chain=near \
  -H "$(AUTH "$BINDING_SEED")" | jq -r '.address // empty')
EXEC_BAL=$(chain_balance "$EXEC_ADDR")
if python3 -c "exit(0 if int('${EXEC_BAL:-0}') < 200000000000000000000000 else 1)"; then
  note "executor $EXEC_ADDR holds $EXEC_BAL — topping up $FUND_NEAR NEAR"
  near_tty "near --quiet tokens $PARENT send-near $EXEC_ADDR '$FUND_NEAR NEAR' \
    network-config $NETWORK sign-with-keychain send" >/dev/null 2>&1
  EXEC_BAL=$(chain_balance "$EXEC_ADDR")
fi
python3 -c "exit(0 if int('${EXEC_BAL:-0}') >= 200000000000000000000000 else 1)" \
  && pass "setup executor funded ($EXEC_BAL)" \
  || { fail "setup the executor holds $EXEC_BAL — U5-U8 would fail for want of gas, not for a defect"; exit 1; }

# The bound wallet needs a policy that PERMITS the door, or U1–U3 measure the
# policy engine instead of the accounting.
store_policy "$BINDING_SEED" "$BOUND_WID" \
  "$(jq -nc --arg d "$DAILY_LIMIT" --arg t "$PER_TX_LIMIT" \
     '{rules:{transaction_types:["call","transfer","delete"],
              limits:{daily:{native:$d}, per_transaction:{native:$t}}}}')" \
  || { fail "setup could not store the bound wallet's policy"; exit 1; }
pass "setup policy stored — daily $DAILY_LIMIT, per-transaction $PER_TX_LIMIT"

STRANGER="nope-$(date +%s)-$$.testnet"

# door_call <envelope-json> — one w_execute_extension through the coordinator.
# Leaves the raw answer in $OUT.
# `$OUT` is the body, `$OUT_HTTP` the status. Both are needed: a call whose
# transaction REVERTED comes back as 422 `onchain_tx_failed` with `tx_hash` and
# `failure` and NO `status` field, so judging by the body alone reports a
# correct product as broken.
OUT=""; OUT_HTTP=""
# door_call <args-json> [outer-deposit-yocto]
#
# The deposit defaults to the 1-yoctoNEAR marker a payable method demands, which
# is what a legitimate lane call carries. It is a PARAMETER because the caller
# picks it on the real endpoint too, and what happens then is a rule with money
# behind it — see U12.
door_call() {
  local tmp; tmp=$(mktemp -t velacct_call.XXXXXX)
  OUT_HTTP=$(curl -sS -o "$tmp" -w '%{http_code}' -X POST "$COORDINATOR_URL/wallet/v1/call" \
    -H "$(AUTH "$BINDING_SEED")" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg a "$ASSET" --argjson args "$1" --arg dep "${2:-1}" \
        '{receiver_id:$a, method_name:"w_execute_extension", args:$args,
          gas:"100000000000000", deposit:$dep}')")
  OUT=$(tr -d '\n' < "$tmp"); rm -f "$tmp"
  sleep 4
}

# The newest request row for the wallet: `<status>|<result_data>`. `promises`
# lives HERE, not in the /call response — `CallResponse` has no such field, and
# on a revert there is no response body to read at all.
last_row() {
  sql "SELECT status || '|' || COALESCE(result_data::text, '{}') FROM wallet_requests \
       WHERE wallet_id = '$BOUND_WID' ORDER BY created_at DESC LIMIT 1" 2>/dev/null | tr -d '\n'
}
transfer_env() { # transfer_env <receiver> <amount> [receiver2 amount2]
  if [[ $# -le 2 ]]; then
    jq -nc --arg r "$1" --arg m "$2" \
      '{request:{external:[{receiver_id:$r,actions:[{action:"transfer",payload:{amount:$m}}]}]}}'
  else
    jq -nc --arg r "$1" --arg m "$2" --arg r2 "$3" --arg m2 "$4" \
      '{request:{external:[{receiver_id:$r,actions:[{action:"transfer",payload:{amount:$m}}]},
                           {receiver_id:$r2,actions:[{action:"transfer",payload:{amount:$m2}}]}]}}'
  fi
}

# ── U1: a call the CONTRACT refused ──────────────────────────────────────────
# The wallet rejects a promise aimed at itself (`self-calls are not allowed`),
# so the request reaches the chain, panics at action 0, and detaches nothing.
# This is the exact request that cost 0.1 NEAR of a window it never spent.
log "U1 door call the wallet contract refuses — self-transfer of $SMALL"
B=$(usage_of "$BOUND_WID" "$(today_daily)")
door_call "$(transfer_env "$ASSET" "$SMALL")"
note "U1 answer: HTTP $OUT_HTTP $(jq -r '.error // .status // "?"' <<<"$OUT" 2>/dev/null)"
# A reverted transaction is a 422 `onchain_tx_failed`, not a 200 with a status
# field — the handler refuses to let a client read a revert as success.
if [[ "$OUT_HTTP" == "422" && "$(jq -r '.error // ""' <<<"$OUT")" == "onchain_tx_failed" ]]; then
  pass "U1 the chain refused it (422 onchain_tx_failed)"
else
  fail "U1 expected 422 onchain_tx_failed for a self-transfer, got HTTP $OUT_HTTP $(head -c 160 <<<"$OUT") — the probe measured nothing"
fi
judge "U1" "$BOUND_WID" "$B" 0 "a refused call detaches no promise and must cost no limit"
# `promises` must be present and empty, not absent: a client reading the row
# should see "nothing ran", not "this told me nothing". It lives in the request
# row, which is the only place it is ever written.
ROW=$(last_row)
PROM=$(jq -r 'if has("promises") then (.promises | length) else "absent" end' <<<"${ROW#*|}" 2>/dev/null)
[[ "$PROM" == "0" ]] \
  && pass "U1 the request row carries promises: [] " \
  || fail "U1 the request row's promises is '$PROM' — expected an empty list (see the api-spec note)"

# ── U2: a call that ran ──────────────────────────────────────────────────────
log "U2 door transfer of $SMALL to $PARENT"
B=$(usage_of "$BOUND_WID" "$(today_daily)")
door_call "$(transfer_env "$PARENT" "$SMALL")"
note "U2 answer: HTTP $OUT_HTTP $(jq -r '.status // .error // "?"' <<<"$OUT" 2>/dev/null)"
judge "U2" "$BOUND_WID" "$B" "$SMALL" "the decoded amount, never the 1-yocto marker"

# ── U3: one of two promises fails ────────────────────────────────────────────
log "U3 two promises — $TINY to $PARENT and $TINY to $STRANGER, which does not exist"
B=$(usage_of "$BOUND_WID" "$(today_daily)")
door_call "$(transfer_env "$PARENT" "$TINY" "$STRANGER" "$TINY")"
note "U3 answer: HTTP $OUT_HTTP $(jq -r '.status // .error // "?"' <<<"$OUT" 2>/dev/null)"
judge "U3" "$BOUND_WID" "$B" "$TINY" "only the promise that ran — the other moved nothing"

# ── U4: a call the POLICY refused ────────────────────────────────────────────
log "U4 door transfer of $OVER_TX — over the per-transaction cap"
B=$(usage_of "$BOUND_WID" "$(today_daily)")
door_call "$(transfer_env "$PARENT" "$OVER_TX")"
ERR=$(jq -r '.error // ""' <<<"$OUT" 2>/dev/null)
MSG=$(jq -r '.message // ""' <<<"$OUT" 2>/dev/null)
note "U4 answer: HTTP $OUT_HTTP $ERR"
[[ "$ERR" == "policy_denied" ]] \
  && pass "U4 refused as policy_denied" \
  || fail "U4 expected policy_denied, got '$ERR' — $(head -c 160 <<<"$MSG")"
judge "U4" "$BOUND_WID" "$B" 0 "a refusal never reaches a chain and must cost nothing"

# ── U5/U6: the plain transfer lane ───────────────────────────────────────────
log "U5 native /transfer of $TINY from the bound wallet's own account"
B=$(usage_of "$BOUND_WID" "$(today_daily)")
XFER=$(curl -sS -w ' %{http_code}' -X POST "$COORDINATOR_URL/wallet/v1/transfer" \
  -H "$(AUTH "$BINDING_SEED")" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg to "$PARENT" --arg a "$TINY" '{chain:"near", to:$to, amount:$a}')")
sleep 4
note "U5 answer: ${XFER##* } $(head -c 120 <<<"${XFER% *}")"
judge "U5" "$BOUND_WID" "$B" "$TINY" "a transfer that landed"

log "U6 native /transfer of $TINY to $STRANGER, which does not exist"
B=$(usage_of "$BOUND_WID" "$(today_daily)")
HK6_BEFORE=$(this_hour)
C6_BEFORE=$(txcount_of "$BOUND_WID" "$HK6_BEFORE")
# The body is KEPT. A zero delta proves nothing on its own: a 401, a 500, or an
# `HTTP 000` from the rate limiter all leave the counter untouched and would
# have passed this probe while the request never reached the chain.
XFER=$(curl -sS -w ' %{http_code}' -X POST "$COORDINATOR_URL/wallet/v1/transfer" \
  -H "$(AUTH "$BINDING_SEED")" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg to "$STRANGER" --arg a "$TINY" '{chain:"near", to:$to, amount:$a}')")
sleep 4
XCODE=${XFER##* }
note "U6 answer: $XCODE $(head -c 120 <<<"${XFER% *}")"
case "$XCODE" in
  422|200|202) pass "U6 the request reached the chain and was rejected there ($XCODE)" ;;
  000|401|403|5??) fail "U6 the request never got as far as the chain ($XCODE) — the zero below proves nothing" ;;
  *) warn "U6 unexpected $XCODE; read the body above before trusting the delta" ;;
esac
judge "U6" "$BOUND_WID" "$B" 0 "a transfer the chain rejected moved nothing"
# …and it is STILL a request against the hourly rate cap. `max_per_hour` counts
# requests that reached the chain, not successes — a limiter a caller can walk
# past by making its own transfers fail is not a limiter. U11 pins the same rule
# on the door; this pins it on the plain transfer lane, which kept counting only
# successes until 2026-08-22.
# Same boundary guard U11 carries: the two reads must name the same bucket or
# the comparison is between different counters.
HK6=$(this_hour)
C6=$(txcount_of "$BOUND_WID" "$HK6")
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
B=$(usage_of "$BOUND_WID" "$(today_daily)")
BAL_B=$(chain_balance "$(curl -sS -G "$COORDINATOR_URL/wallet/v1/address" --data-urlencode chain=near -H "$(AUTH "$BINDING_SEED")" | jq -r .address)")
curl -sS -o /dev/null -X POST "$COORDINATOR_URL/wallet/v1/call" \
  -H "$(AUTH "$BINDING_SEED")" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg t "$TOKEN_CONTRACT" --arg d "$SMALL" \
      '{receiver_id:$t, method_name:"storage_deposit", args:{}, gas:"30000000000000", deposit:$d}')"
sleep 5
judge "U7" "$BOUND_WID" "$B" "$SMALL" "the rule: the attached deposit is the spend, change is not credited back"

log "U8 ordinary call that panics, with $TINY attached"
B=$(usage_of "$BOUND_WID" "$(today_daily)")
curl -sS -o /dev/null -X POST "$COORDINATOR_URL/wallet/v1/call" \
  -H "$(AUTH "$BINDING_SEED")" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg t "$TOKEN_CONTRACT" --arg d "$TINY" \
      '{receiver_id:$t, method_name:"no_such_method_here", args:{}, gas:"30000000000000", deposit:$d}')"
sleep 5
judge "U8" "$BOUND_WID" "$B" "$TINY" "same rule on a refund the PROTOCOL made — the counter still keeps it"

# ── U9: the buckets are calendar periods ─────────────────────────────────────
log "U9 the period keys are calendar buckets, not a rolling window"
HOUR_KEY="hourly:$(date -u +%Y-%m-%dT%H)"
ROWS=$(sql "SELECT period FROM wallet_usage WHERE wallet_id='$BOUND_WID' ORDER BY period")
note "U9 periods on this wallet: $(tr '\n' ' ' <<<"$ROWS")"
grep -q "^hourly:[0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\}T[0-9]\{2\}$" <<<"$ROWS" \
  && pass "U9 the hourly key is a clock-hour bucket (hourly:YYYY-MM-DDTHH)" \
  || fail "U9 no clock-hour bucket found — if this became a rolling window, every delta above is measuring something else"
if grep -qx "$HOUR_KEY" <<<"$ROWS"; then
  pass "U9 the run's charges landed in the CURRENT hour's bucket ($HOUR_KEY)"
elif [[ "$(this_hour)" != "$HOUR_KEY" ]]; then
  # The clock rolled between the last charge and this read, so the charge is in
  # the previous bucket and correctly so. Same guard U11 carries.
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
SPENT=$(usage_of "$BOUND_WID" "$(today_daily)")
note "U10 spent $SPENT — re-storing the policy with the daily cap AT that figure"
if store_policy "$BINDING_SEED" "$BOUND_WID" \
     "$(jq -nc --arg d "$SPENT" --arg t "$PER_TX_LIMIT" \
        '{rules:{transaction_types:["call","transfer","delete"],
                 limits:{daily:{native:$d}, per_transaction:{native:$t}}}}')"; then
  B=$(usage_of "$BOUND_WID" "$(today_daily)")
  R=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/transfer" \
    -H "$(AUTH "$BINDING_SEED")" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg to "$PARENT" --arg a "$TINY" '{chain:"near", to:$to, amount:$a}')")
  ERR=$(jq -r '.error // ""' <<<"$R"); MSG=$(jq -r '.message // ""' <<<"$R")
  [[ "$ERR" == "policy_denied" ]] \
    && pass "U10 the ceiling refused the next yocto" \
    || fail "U10 expected policy_denied with zero headroom, got '$ERR': $(head -c 160 <<<"$MSG")"
  grep -qi "daily\|limit" <<<"$MSG" \
    && pass "U10 the refusal names the window it broke" \
    || fail "U10 the refusal says nothing an owner could act on: $(head -c 160 <<<"$MSG")"
  judge "U10" "$BOUND_WID" "$B" 0 "a refusal costs nothing, so a wallet cannot be walled in by retrying"
else
  fail "U10 could not re-store the policy — the ceiling was never actually tested"
fi

# ── U11: a refused call is still a transaction ───────────────────────────────
# The spend windows must not move — that is U1. This is the other half: the
# hourly transaction cap must move anyway, or a compromised key can loop
# refused calls forever, burning the bound account's gas, with every counter
# reading zero.
#
# U10 leaves the daily cap AT what the run has spent, so from here the wallet is
# walled and every call is refused by the POLICY — before any chain sees it, and
# correctly free, transaction count included. Judged against that state this
# probe measured U10's ceiling instead of its own rule and called a working
# coordinator broken. So the headroom is restored first, and the answer must be
# a CHAIN refusal before a single count is compared. Restoring it also hands the
# next run a wallet it can actually spend from, which $BINDING_SEED reuse needs.
log "U11 a refused door call consumes the hourly transaction count but no spend"
if ! store_policy "$BINDING_SEED" "$BOUND_WID" \
     "$(jq -nc --arg d "$DAILY_LIMIT" --arg t "$PER_TX_LIMIT" \
        '{rules:{transaction_types:["call","transfer","delete"],
                 limits:{daily:{native:$d}, per_transaction:{native:$t}}}}')"; then
  fail "U11 could not restore the headroom U10 closed — nothing it sent could reach a chain"
else
  HK=$(this_hour)
  CB=$(txcount_of "$BOUND_WID" "$HK")
  AB=$(usage_of "$BOUND_WID" "$HK")
  door_call "$(transfer_env "$ASSET" "$TINY")"
  note "U11 answer: HTTP $OUT_HTTP $(jq -r '.error // .status // "?"' <<<"$OUT" 2>/dev/null)"
  if [[ "$OUT_HTTP" != "422" || "$(jq -r '.error // ""' <<<"$OUT")" != "onchain_tx_failed" ]]; then
    fail "U11 the call never reached a chain (HTTP $OUT_HTTP $(head -c 160 <<<"$OUT")) — a refusal that costs nothing by design proves nothing about this rule"
  elif [[ "$(this_hour)" != "$HK" ]]; then
    warn "U11 SKIPPED — the clock crossed an hour boundary mid-probe, the counts are in different buckets"
  else
    CA=$(txcount_of "$BOUND_WID" "$HK")
    AA=$(usage_of "$BOUND_WID" "$HK")
    [[ "$CA" -gt "$CB" ]] \
      && pass "U11 the transaction count moved ($CB → $CA)" \
      || fail "U11 the transaction count did not move ($CB → $CA) — refused calls are free against rate_limit.max_per_hour"
    eq "$AA" "$AB" \
      && pass "U11 and no spend was charged for it" \
      || fail "U11 a refused call moved the spend window: $AB → $AA"
  fi
fi

# ── U12 the OUTER deposit of a door call is spent, and is counted ───────────
#
# The one amount nothing counted for a long time. The gates on the way IN meter
# `Op::amount()`, which for a call is the attached deposit; the charge on the way
# OUT read only the decoded effects. So the deposit was compared against a
# `spent` it never added to, and every call saw the same headroom again.
#
# The caller picks both the deposit and the receiver, so this is not a corner:
# it is the shape an agent would use to move money past its own ceiling.
#
# EMPTY request on purpose — no decoded effects at all, so the only thing that
# can move the counter is the deposit itself. Minus the marker, which proves a
# key rather than paying anyone.
log "U12 a door call with an outer deposit above the marker"
OUTER=1000001
U12_POLICY="missing"
if ! store_policy "$BINDING_SEED" "$BOUND_WID" \
     "$(jq -nc --arg d "$DAILY_LIMIT" --arg t "$PER_TX_LIMIT" \
        '{rules:{transaction_types:["call","transfer","delete"],
                 limits:{daily:{native:$d}, per_transaction:{native:$t}}}}')"; then
  fail "U12 the policy could not be stored — nothing below is judgeable"
else
  U12_POLICY="stored"
  B=$(usage_of "$BOUND_WID" "$(today_daily)")
  door_call '{"request":{}}' "$OUTER"
  note "U12 answer: HTTP $OUT_HTTP $(jq -r '.status // .error // "?"' <<<"$OUT" 2>/dev/null)"
  if [[ "$OUT_HTTP" != "200" ]]; then
    fail "U12 the call did not reach the chain (HTTP $OUT_HTTP: $(head -c 160 <<<"$OUT")) — a refusal costs nothing by design and proves nothing about this rule"
  else
    judge "U12" "$BOUND_WID" "$B" "$((OUTER - 1))" "the deposit the caller attached, less the 1-yocto marker — the door is not a free way past the ceiling"
  fi
fi

# ── U13 the outer deposit and the decoded effects are BOTH counted ──────────
#
# Composition, because that is where a regression hides: charging one or the
# other reads as correct in every single-sided probe. The two are different
# money — the deposit leaves the executor that signed, the effects move the
# BOUND account's balance — and one ceiling is measured over both.
log "U13 an outer deposit alongside a decoded transfer"
# Guarded by U12's policy write: without it the ceiling U10 deliberately closed
# is still shut, this call is refused for THAT, and the probe reports "the call
# did not reach the chain" — true, and pointing at the wrong rule.
if [[ "$U12_POLICY" != "stored" ]]; then
  fail "U13 skipped — the policy U12 stores is what reopens the headroom U10 closed, and it did not land"
else
  B=$(usage_of "$BOUND_WID" "$(today_daily)")
  INNER=1000000000000000000000
  door_call "$(jq -nc --arg to "$PARENT" --arg amt "$INNER" \
      '{request:{external:[{receiver_id:$to, actions:[{action:"transfer", payload:{amount:$amt}}]}]}}')" \
    "$OUTER"
  note "U13 answer: HTTP $OUT_HTTP $(jq -r '.status // .error // "?"' <<<"$OUT" 2>/dev/null)"
  if [[ "$OUT_HTTP" != "200" ]]; then
    fail "U13 the call did not reach the chain (HTTP $OUT_HTTP: $(head -c 160 <<<"$OUT"))"
  else
    judge "U13" "$BOUND_WID" "$B" "$(python3 -c "print($INNER + $OUTER - 1)")" \
      "the decoded transfer AND the attached deposit, less one marker — two balances, one ceiling"
  fi
fi

# ── verdict ──────────────────────────────────────────────────────────────────
log "velocity accounting — $PASS passed, $FAILED failed"
if (( FAILED > 0 )); then
  for n in "${FAILED_NAMES[@]}"; do printf '  \033[31m✗ %s\033[0m\n' "$n" >&2; done
  exit 1
fi
exit 0
