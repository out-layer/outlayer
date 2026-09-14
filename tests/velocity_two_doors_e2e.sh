#!/usr/bin/env bash
#
# One wallet, two doors, one purse.
#
# A wallet can be spent from two places that share no code between them: the
# HTTPS wallet API, where the caller signs as the wallet's owner, and a WASI
# guest inside the enclave calling `outlayer:wallet/api`, where the caller is a
# module the owner deployed. They meet at `wallet_usage`, which is keyed on the
# wallet and NOTHING else — no door, no caller, no key.
#
# That is the design, and until this suite existed nothing proved it. Split the
# counter by door and every velocity test in this repository stays green while
# an agent doubles its daily limit by alternating doors: both halves enforce
# correctly, each against half the truth. The owner's ceiling would simply be
# twice what they wrote, and the product would never say so.
#
# There is a source-side guard for the same invariant
# (`one_wallet_is_one_purse_however_the_spend_arrived`, in the coordinator). It
# reads the schema and the accessors. This one spends real money through both
# doors and reads the row they landed in.
#
# Probes:
#   T1  the HTTPS door charges what it moved
#   T2  the GUEST door charges what it moved — to the same row, so the counter
#       after both is the sum and not either half
#   T3  the ceiling is met by the SUM: a third spend, lawful against each half
#       on its own, is refused, and the refusal names the DAILY window
#   T4  the control — with the cap raised past the sum, that same third spend
#       goes through. Without it T3 passes on a wallet that refuses everything
#   T5  the tx COUNT is shared too: both doors fed one `tx_count`
#
# Money: three transfers of 0.001 NEAR to $RECIPIENT, plus gas, plus 0.1 NEAR
# per policy store (three stores) and ~1 NEAR + 1.5 USDC funding a wallet of
# this run's own. A disposable wallet is deliberate: velocity probes eat the
# monthly custody allowance, and a shared wallet's is somebody else's.
#
# Requires $PSQL_CMD. The counters are exposed by no endpoint, and a probe that
# judged them by whether a later call was refused would pass on a coordinator
# that never counted at all.
#
# Run (spends real testnet NEAR):
#   PARENT=you.testnet RECIPIENT=friend.testnet PSQL_CMD=./tsql \
#     ./tests/velocity_two_doors_e2e.sh --apply

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPLY=false
[[ "${1:-}" == "--apply" ]] && APPLY=true

NETWORK="${NETWORK:-testnet}"
CONTRACT_ID="${CONTRACT_ID:-outlayer.testnet}"
COORDINATOR_URL="${COORDINATOR_URL:-https://testnet-api.outlayer.ai}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/rpc.sh"   # keyed RPC_URL, or a warning
PROJECT="${PROJECT:-zavodil.testnet/wallet-probe}"
PARENT="${PARENT:-}"
RECIPIENT="${RECIPIENT:-}"
PSQL_CMD="${PSQL_CMD:-}"
WALLET_SEED="${WALLET_SEED:-}"
PAYMENT_KEY="${PAYMENT_KEY:-}"

# Each door moves this much; the cap is set to exactly two of them, so the
# third spend is over the ceiling by the whole of its own amount and by
# nothing else.
STEP="1000000000000000000000"                   # 0.001 NEAR
CAP_TWO="2000000000000000000000"                # 0.002 NEAR — exactly T1 + T2
CAP_WIDE="10000000000000000000000"              # 0.01 NEAR  — the T4 control
TOKEN_CONTRACT="${TOKEN_CONTRACT:-usdc.fakes.testnet}"
FUND_NEAR="${FUND_NEAR:-1.0}"
FUND_USDC_MINIMAL="${FUND_USDC_MINIMAL:-1500000}"
DEPOSIT_USDC="${DEPOSIT_USDC:-0.30}"

PASS=0; FAILED=0; FAILED_NAMES=()
log()  { printf '\n\033[36m▶ %s\033[0m\n' "$*" >&2; }
note() { printf '\033[35m• %s\033[0m\n' "$*" >&2; }
warn() { printf '\033[33m⚠ %s\033[0m\n' "$*" >&2; }
pass() { printf '\033[32m✓ %s\033[0m\n' "$*" >&2; PASS=$((PASS+1)); }
fail() { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; FAILED=$((FAILED+1)); FAILED_NAMES+=("$*"); }

if [[ "$APPLY" != true ]]; then
  sed -n '3,44p' "$0" >&2
  echo "  Pass --apply to run." >&2
  exit 0
fi

for v in PARENT RECIPIENT; do
  [[ -n "${!v}" ]] || { echo "$v=<value> is required" >&2; exit 1; }
done
[[ -n "$PSQL_CMD" ]] \
  || { echo "✗ PSQL_CMD is required — the counter this suite is about lives only in the database" >&2; exit 1; }
for tool in jq curl near python3 cargo; do
  command -v "$tool" >/dev/null || { echo "✗ missing $tool" >&2; exit 1; }
done
CREDS_DIR="$HOME/.near-credentials/$NETWORK"
[[ -f "$CREDS_DIR/$PARENT.json" ]] || { echo "✗ creds missing: $CREDS_DIR/$PARENT.json" >&2; exit 1; }
# Without this `outlayer` follows ~/.outlayer/default-network, mainnet on this
# machine, and a mainnet run of this script spends real money.
export OUTLAYER_NETWORK="$NETWORK"
PARENT_PRIVKEY=$(jq -r '.private_key' "$CREDS_DIR/$PARENT.json")

sql() { $PSQL_CMD "$1"; }
# An ssh wrapper answers "" for a dead transport as readily as for an absent
# row, and every counter read below would then compare "" against "".
[[ "$(sql "SELECT 'alive'" | tr -d '[:space:]')" == "alive" ]] \
  || { echo "✗ PSQL_CMD does not work — every counter would read empty and the suite would pass blind" >&2; exit 1; }

RECOVERY_BIN="$SCRIPT_DIR/../scripts/customer-recovery/target/release/customer-recovery"
log "Building customer-recovery (sign-bearer-near)"
(cd "$SCRIPT_DIR/../scripts/customer-recovery" && cargo build --release --quiet) \
  || { echo "✗ customer-recovery build failed" >&2; exit 1; }

[[ -n "$WALLET_SEED" ]] || { WALLET_SEED="twodoors-$(date +%s)-$$"; MINTED=true; }
MINTED="${MINTED:-false}"

# A function, not a value: the token carries a timestamp and the coordinator
# refuses a stale one partway through a run that waits on chain.
AUTH() {
  echo "Authorization: Bearer near:$("$RECOVERY_BIN" sign-bearer-near \
    --private-key "$PARENT_PRIVKEY" --account-id "$PARENT" --seed "$WALLET_SEED")"
}

# Big-integer helpers. Yocto amounts are 22+ digits: shell arithmetic truncates
# them and `[[ a < b ]]` compares them as strings, where 0.002 sorts below
# 0.0001.
sub() { python3 -c "print(int('${1:-0}')-int('${2:-0}'))"; }
eq()  { python3 -c "exit(0 if int('${1:-0}')==int('${2:-0}') else 1)"; }

today_daily() { echo "daily:$(date -u +%Y-%m-%d)"; }

# WAIT for the counter to move, rather than sleeping and hoping.
#
# The counter is written after the transaction settles, and "not yet" and
# "never" look identical at a fixed eight seconds — a slow coordinator would
# report `charged 0` and make timing look like a metering defect, which is the
# one conclusion this suite must never invite. Bounded, so a counter that truly
# never moves still fails rather than hanging.
#
# Returns the value it settled on; on timeout, the last value it saw, so the
# caller judges a real figure and says what it expected.
await_charge() { # await_charge <wallet_id> <baseline> [attempts]
  local wid=$1 base=$2 n=${3:-20} now
  for _ in $(seq 1 "$n"); do
    now=$(usage_of "$wid")
    [[ "$now" != "$base" ]] && { echo "$now"; return 0; }
    sleep 2
  done
  echo "$now"
  return 1
}

usage_of() { # usage_of <wallet_id>
  local v
  v=$(sql "SELECT total_amount FROM wallet_usage WHERE wallet_id='$1' AND token='native' AND period='$(today_daily)'" 2>/dev/null | tr -d '[:space:]')
  [[ -n "$v" ]] || v=0
  echo "$v"
}
txcount_of() {
  local v
  v=$(sql "SELECT tx_count FROM wallet_usage WHERE wallet_id='$1' AND token='native' AND period='$(today_daily)'" 2>/dev/null | tr -d '[:space:]')
  [[ -n "$v" ]] || v=0
  echo "$v"
}

store_policy() { # store_policy <policy-json>
  local pol=$1 body enc encb64 sg sig_hex pub_hex store_args out rc=0
  body=$(jq -nc --arg wid "$WALLET_ID" --argjson p "$pol" '$p + {wallet_id:$wid}')
  enc=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/encrypt-policy" \
    -H "$(AUTH)" -H 'Content-Type: application/json' -d "$body")
  encb64=$(jq -r '.encrypted_base64 // empty' <<<"$enc")
  [[ -n "$encb64" ]] || { warn "encrypt-policy failed: $(head -c 200 <<<"$enc")"; return 1; }
  sg=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/sign-policy" \
    -H "$(AUTH)" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg ed "$encb64" --arg c "$PARENT" '{encrypted_data:$ed, caller:$c}')")
  sig_hex=$(jq -r '.signature_hex // empty' <<<"$sg")
  pub_hex=$(jq -r '.public_key_hex // empty' <<<"$sg")
  [[ -n "$sig_hex" ]] || { warn "sign-policy failed: $(head -c 200 <<<"$sg")"; return 1; }
  store_args=$(jq -nc --arg pk "ed25519:$pub_hex" --arg ed "$encb64" --arg sg "$sig_hex" \
    '{wallet_pubkey:$pk, encrypted_data:$ed, wallet_signature:$sg}')
  out=$(near --quiet contract call-function as-transaction "$CONTRACT_ID" store_wallet_policy \
    json-args "$store_args" prepaid-gas '100.0 Tgas' attached-deposit '0.1 NEAR' \
    sign-as "$PARENT" network-config "$NETWORK" sign-with-keychain send 2>&1) || rc=$?
  (( rc == 0 )) || { warn "store_wallet_policy failed (rc=$rc): $(tail -c 400 <<<"$out")"; return 1; }
  sleep 6
}

# ── the wallet under test ────────────────────────────────────────────────────
log "Reading the wallet"
R=$(curl -sS -m 30 -G "$COORDINATOR_URL/wallet/v1/address" --data-urlencode "chain=near" -H "$(AUTH)")
WALLET_ID=$(jq -r '.wallet_id // empty' <<<"$R")
ADDRESS=$(jq -r '.address // empty' <<<"$R")
[[ -n "$WALLET_ID" && -n "$ADDRESS" ]] \
  || { echo "✗ /wallet/v1/address failed: $(head -c 250 <<<"$R")" >&2; exit 1; }
note "wallet $WALLET_ID at $ADDRESS"

if [[ "$MINTED" == true ]]; then
  log "Funding a wallet of this run's own"
  near --quiet contract call-function as-transaction "$TOKEN_CONTRACT" storage_deposit \
    json-args "$(jq -nc --arg a "$ADDRESS" '{account_id:$a, registration_only:true}')" \
    prepaid-gas '30.0 Tgas' attached-deposit '0.00125 NEAR' \
    sign-as "$PARENT" network-config "$NETWORK" sign-with-keychain send >/dev/null 2>&1
  # Wait for the registration to be VISIBLE: an `ft_transfer` to an account the
  # token has not registered yet is refused by the token, and the two sends
  # otherwise race on one access key.
  REGISTERED=""
  for _ in $(seq 1 10); do
    REG=$(curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
      -d "$(jq -nc --arg t "$TOKEN_CONTRACT" --arg a "$(jq -nc --arg x "$ADDRESS" '{account_id:$x}' | base64)" \
          '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"call_function",finality:"final",account_id:$t,method_name:"storage_balance_of",args_base64:$a}}')" \
      | jq -r 'try (.result.result | implode) catch "null"' 2>/dev/null)
    [[ -n "$REG" && "$REG" != "null" ]] && { REGISTERED=$REG; break; }
    sleep 2
  done
  [[ -n "$REGISTERED" ]] \
    || { echo "✗ $TOKEN_CONTRACT never registered $ADDRESS — the funding transfer below would be refused by the token, not by us" >&2; exit 1; }
  near --quiet contract call-function as-transaction "$TOKEN_CONTRACT" ft_transfer \
    json-args "$(jq -nc --arg a "$ADDRESS" --arg m "$FUND_USDC_MINIMAL" '{receiver_id:$a, amount:$m}')" \
    prepaid-gas '30.0 Tgas' attached-deposit '1 yoctoNEAR' \
    sign-as "$PARENT" network-config "$NETWORK" sign-with-keychain send >/dev/null 2>&1
  near --quiet tokens "$PARENT" send-near "$ADDRESS" "$FUND_NEAR NEAR" \
    network-config "$NETWORK" sign-with-keychain send >/dev/null 2>&1
  FUNDED=""
  for _ in $(seq 1 10); do
    sleep 3
    HAVE=$(curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
      -d "$(jq -nc --arg t "$TOKEN_CONTRACT" --arg a "$(jq -nc --arg x "$ADDRESS" '{account_id:$x}' | base64)" \
          '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"call_function",finality:"final",account_id:$t,method_name:"ft_balance_of",args_base64:$a}}')" \
      | jq -r 'try (.result.result | implode | fromjson) catch "0"' 2>/dev/null | tr -d '"')
    [[ -n "$HAVE" && "$HAVE" != "null" ]] || HAVE=0
    python3 -c "exit(0 if int('${HAVE:-0}') >= int('$FUND_USDC_MINIMAL') else 1)" 2>/dev/null \
      && { FUNDED=$HAVE; break; }
  done
  [[ -n "$FUNDED" ]] \
    || { echo "✗ the wallet never received its stablecoin (holds ${HAVE:-0}) — create-payment-key would answer 402, correctly" >&2; exit 1; }
  # Retried, because the coordinator answers `chain_unavailable` for a node
  # that would not talk and that is a condition to wait out, not a verdict —
  # and giving up here throws away a wallet that has just been funded.
  PAYMENT_KEY=""
  for _ in $(seq 1 6); do
    K=$(curl -sS -m 120 -X POST "$COORDINATOR_URL/wallet/v1/create-payment-key" \
          -H "$(AUTH)" -H 'Content-Type: application/json' \
          -d "$(jq -nc --arg d "$DEPOSIT_USDC" '{initial_deposit_usdc:$d}')")
    PAYMENT_KEY=$(jq -r '.payment_key // empty' <<<"$K")
    [[ -n "$PAYMENT_KEY" ]] && break
    KERR=$(jq -r '.error // empty' <<<"$K")
    [[ "$KERR" == "chain_unavailable" || "$KERR" == "upstream_unavailable" || "$KERR" == "keystore_error" ]] \
      || break
    warn "create-payment-key: $KERR — transient, waiting"
    sleep 10
  done
  [[ -n "$PAYMENT_KEY" ]] \
    || { echo "✗ could not create a payment key: $(jq -r '.error // .message // .' <<<"$K" | head -c 200)" >&2
         echo "  wallet $WALLET_ID is funded — re-run with WALLET_SEED=$WALLET_SEED once it clears" >&2; exit 1; }
  pass "minted and funded a wallet of this run's own — no shared limits are spent"
fi
[[ -n "$PAYMENT_KEY" ]] || { echo "✗ PAYMENT_KEY is required when WALLET_SEED names an existing wallet" >&2; exit 1; }

WID_HDR="X-Wallet-Id: $WALLET_ID"

# The two doors, each as its own caller would reach it.
https_spend() { # https_spend <amount>
  curl -sS -m 120 -X POST "$COORDINATOR_URL/wallet/v1/transfer" \
    -H "$(AUTH)" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg t "$RECIPIENT" --arg a "$1" '{chain:"near", to:$t, amount:$a}')"
}
guest_spend() { # guest_spend <amount> — the same money, moved from inside the enclave
  curl -sS -m 300 -X POST "$COORDINATOR_URL/call/$PROJECT" \
    -H "X-Payment-Key: $PAYMENT_KEY" -H "$WID_HDR" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg t "$RECIPIENT" --arg a "$1" \
          '{input:{operation:"transfer", to:$t, amount:$a}}')"
}

log "Policy: transfers to $RECIPIENT, daily native cap = $CAP_TWO (exactly T1 + T2)"
store_policy "$(jq -nc --arg r "$RECIPIENT" --arg cap "$CAP_TWO" \
  '{rules:{transaction_types:["transfer","call"],addresses:{list:[$r]},
           limits:{daily:{native:$cap}}}}')" \
  || { echo "✗ policy not stored — every probe below would judge the wrong rules" >&2; exit 1; }

BASE=$(usage_of "$WALLET_ID")
BASE_TX=$(txcount_of "$WALLET_ID")
note "daily native before anything: $BASE (tx $BASE_TX)"

# ── T1: the HTTPS door ───────────────────────────────────────────────────────
log "T1 a spend through the HTTPS wallet API"
B=$(https_spend "$STEP")
if [[ "$(jq -r '.success // .status // empty' <<<"$B")" == "false" ]] \
   || [[ -n "$(jq -r '.error // empty' <<<"$B")" ]]; then
  fail "T1 the HTTPS door refused the first lawful spend: $(jq -r '.error // .message // .' <<<"$B" | head -c 200)"
else
  AFTER1=$(await_charge "$WALLET_ID" "$BASE") \
    || warn "T1 the counter did not move within 40s — judging what is there"
  GOT=$(sub "$AFTER1" "$BASE")
  eq "$GOT" "$STEP" \
    && pass "T1 the HTTPS door charged $GOT" \
    || fail "T1 the HTTPS door charged $GOT, expected $STEP ($BASE → $AFTER1)"
fi

# ── T2: the guest door, into the same row ────────────────────────────────────
log "T2 the same money moved by a guest inside the enclave"
AFTER1=$(usage_of "$WALLET_ID")
B=$(guest_spend "$STEP")
CODE=$(jq -r '.output.error_parsed.code // empty' <<<"$B")
if [[ -n "$CODE" ]]; then
  fail "T2 the guest door refused: $CODE — $(jq -r '.output.detail // empty' <<<"$B" | head -c 160)"
elif [[ "$(jq -r '.output.ok // false' <<<"$B")" != "true" ]]; then
  fail "T2 the guest answered malformed: $(head -c 200 <<<"$B")"
else
  AFTER2=$(await_charge "$WALLET_ID" "$AFTER1") \
    || warn "T2 the counter did not move within 40s — judging what is there"
  GOT=$(sub "$AFTER2" "$AFTER1")
  eq "$GOT" "$STEP" \
    && pass "T2 the guest door charged $GOT to the SAME row the HTTPS door wrote" \
    || fail "T2 the guest door charged $GOT, expected $STEP ($AFTER1 → $AFTER2)"
  # The sum is the point. Two rows would each read $STEP and both halves above
  # would still pass.
  TOTAL=$(sub "$AFTER2" "$BASE")
  eq "$TOTAL" "$CAP_TWO" \
    && pass "T2 one purse: the counter after both doors is their SUM ($TOTAL)" \
    || fail "T2 the counter after both doors is $TOTAL, expected $CAP_TWO — the doors are not sharing a row"
fi

# ── T3: the ceiling is met by the sum ────────────────────────────────────────
log "T3 a third spend, lawful against either half alone, against a full day"
B=$(https_spend "$STEP")
ERR=$(jq -r '.error // empty' <<<"$B")
MSG=$(jq -r '.message // .detail // empty' <<<"$B")
if [[ -z "$ERR" ]]; then
  fail "T3 a spend past the shared ceiling was ACCEPTED — the doors are metering separately"
else
  pass "T3 refused as '$ERR'"
  grep -qi 'daily' <<<"$MSG" \
    && pass "T3 the refusal names the DAILY window: $(head -c 120 <<<"$MSG")" \
    || fail "T3 refused, but not by the day — '$ERR': $(head -c 160 <<<"$MSG")"
fi

# ── T5: the transaction count is shared too ──────────────────────────────────
log "T5 the tx count fed by both doors"
# No wait here: T1, T2 and T3 have each already settled — the first two waited
# for their own charge, and T3 never reached a chain to be waited for.
NOW_TX=$(txcount_of "$WALLET_ID")
DELTA_TX=$(sub "$NOW_TX" "$BASE_TX")
# EXACTLY two. Two spends reached the chain and each charges the count once;
# the refusal in T3 never left the coordinator, and a request the policy stopped
# costs nothing. `-ge 2` would pass at three as well — that is, it would stay
# green through the regression where policy refusals start burning the hourly
# allowance, which is the only direction this probe exists to catch. (U11 in
# velocity_accounting_e2e pins the other half: a call the CHAIN refused DOES
# count, because the cap is transactions and not successful ones.)
if eq "$DELTA_TX" 2; then
  pass "T5 both doors fed one tx count, and only the two that were sent (+$DELTA_TX)"
else
  fail "T5 the tx count moved by $DELTA_TX; two spends were sent and one refusal never left us"
fi

# ── T4: the control ──────────────────────────────────────────────────────────
log "T4 control — with the cap past the sum, that same third spend goes through"
if store_policy "$(jq -nc --arg r "$RECIPIENT" --arg cap "$CAP_WIDE" \
     '{rules:{transaction_types:["transfer","call"],addresses:{list:[$r]},
              limits:{daily:{native:$cap}}}}')"; then
  BEFORE4=$(usage_of "$WALLET_ID")
  # The new cap has to become VISIBLE before this means anything. A policy
  # store lands on chain and the coordinator caches what it read, so a spend
  # fired immediately after can still meet the old ceiling — and this probe
  # would then report that T3 proved nothing, which is the opposite of what
  # happened. Retried while the refusal is still the DAILY one, and only that:
  # any other refusal is a real answer and is reported at once.
  for _ in $(seq 1 12); do
    B=$(https_spend "$STEP")
    ERR=$(jq -r '.error // empty' <<<"$B")
    [[ -n "$ERR" ]] || break
    grep -qi 'daily' <<<"$(jq -r '.message // .detail // empty' <<<"$B")" || break
    sleep 5
  done
  if [[ -n "$ERR" ]]; then
    fail "T4 the same spend is still refused with the cap raised — T3 proved nothing about the day: '$ERR'"
  else
    AFTER4=$(await_charge "$WALLET_ID" "$BEFORE4") \
      || warn "T4 the counter did not move within 40s — judging what is there"
    GOT=$(sub "$AFTER4" "$BEFORE4")
    eq "$GOT" "$STEP" \
      && pass "T4 with headroom the identical spend executed and charged $GOT" \
      || fail "T4 executed but charged $GOT, expected $STEP"
  fi
else
  fail "T4 the control policy did not store — T3 stands unproven"
fi

echo >&2
if (( FAILED == 0 )); then
  printf '\033[32m▶ one wallet, two doors, one purse — %d passed, 0 failed\033[0m\n' "$PASS" >&2
else
  printf '\033[31m▶ one wallet, two doors, one purse — %d passed, %d FAILED\033[0m\n' "$PASS" "$FAILED" >&2
  for n in "${FAILED_NAMES[@]}"; do printf '   \033[31m✗ %s\033[0m\n' "$n" >&2; done
fi
note "wallet $WALLET_ID ($ADDRESS) — nothing is swept, it holds what is left"
# The seed, and NOT the payment key. The key is a live credential; a run that
# printed one left it in a terminal, a scrollback and whatever collected the
# log. A re-run against this wallet needs `WALLET_SEED` plus a key the caller
# already holds — and minting a fresh wallet costs a little testnet NEAR, which
# is the cheaper of the two.
note "re-run against this wallet: WALLET_SEED=$WALLET_SEED PAYMENT_KEY=<the key from that run>"
exit $(( FAILED > 0 ? 1 : 0 ))
