#!/usr/bin/env bash
# How a withdrawal and a swap are sized, and what their bodies may carry.
# MAINNET ONLY: NEAR Intents has no testnet solvers and the coordinator answers
# 503 there before reading the body.
#
# Free rows — nothing is paid for. Each is a dry-run, a quote, or a REAL call
# the API must refuse before anything is signed (each counts against the
# wallet's daily custody ceiling). A dry-run and a quote cannot move funds. A
# real call (marked ‡) is free only while the refusal it tests holds, so every
# ‡ body is sized for the day it does not: what would move is named on the row,
# and the suite ends by checking the balance did not change.
#   B1 a withdrawal with `memo` → dry-run reason memo_not_supported, ‡ real
#      call 400 memo_not_supported, on NEAR and cross-chain (worst: 1 unit of
#      USDC — under the bridge's floor cross-chain, sent and lost on NEAR). `memo: null` is no memo
#   B2 a field the body does not define → 400 bad_request naming it: withdraw
#      dry-run, swap quote, ‡ withdraw (worst: 1 unit), ‡ swap and ‡
#      /intents/transfer (an amount of 0, refused on its own)
#   B3 one size per request: both sizes, an output without its ceiling, a
#      ceiling without its output, a floor beside an exact output, and an
#      output on a NEAR withdrawal are refused (‡ withdraw bodies of 1–2 units)
#   B4 an amount is digits: a sign, a leading zero, a space, a decimal point
#      and a zero are refused by the swap quote and named invalid_request by
#      the withdraw dry-run, for every amount field; ‡ /intents/transfer
#      refuses a signed zero by its spelling (worst: nothing, a zero is
#      refused on its own)
#   Q1 a swap quote, exact input: 1Click's figures as fields, the guarantee
#      not above the estimate
#   Q2 a swap quote, exact output: the output is the one asked, estimate and
#      guarantee alike; a ceiling of 1 names above_max_amount_in
#   Q3 a swap quote with a floor at the ESTIMATE names below_min_amount_out:
#      the floor is held to the guarantee; a floor of 1 is met
#   W1 a cross-chain withdraw dry-run, exact input: the bridge quote as fields
#   W2 the same, exact output: delivers the amount asked, needs more in than
#      out; a ceiling under the quoted input is would_succeed false,
#      above_max_amount_in, with the figures still in the body
#   W3 the same with a floor above the guarantee → below_min_amount_out; a
#      floor of 1 is met
#   W4 an exact output whose ceiling is more than the wallet holds →
#      insufficient_balance: the ceiling is what the request may spend, and the
#      wallet must hold all of it
#   R1 ‡ the swap with a floor twice the estimate → 400 below_min_amount_out
#      carrying quoted_min_amount_out (worst: SWAP_IN of USDC swapped to wNEAR
#      inside the wallet, at the cost of the spread)
#   R2 ‡ the cross-chain withdraw, exact output under a ceiling of 1 unit →
#      400 above_max_amount_in carrying quoted_amount_in (worst: the 1 unit)
#   R3 ‡ the swap, exact output under a ceiling of 1 unit → 400
#      above_max_amount_in (worst: the 1 unit)
#   R4 ‡ the cross-chain withdraw with a floor twice the guarantee → 400
#      below_min_amount_out (worst: WITHDRAW_IN of USDC bridged to the wallet's
#      OWN Solana address, at the cost of the bridge fee)
#   R5 ‡ R2 sent `async` → a request that ends `failed`, never submitted, its
#      result carrying error_code above_max_amount_in and the quote's figure:
#      what a poller of a background or an approved request reads
#   C1 the confidential withdraw dry-run and swap quote, exact output and
#      exact input; a floor and a ceiling the quote misses are named; an
#      unknown field and a memo are 400 in the wallet's own envelope; ‡
#      shield, unshield and the confidential transfer answer a body that does
#      not parse, and a signed zero, the same way (worst: nothing) (skipped
#      when confidential intents are off on the deployment)
#   C2 ‡ the confidential swap and withdraw, exact output under a ceiling of 1
#      unit → 400 above_max_amount_in (worst: 1 unit of a confidential balance)
#
# Not here, and why: an approved (multi-signature) request under these terms
# needs a wallet with a policy and its approvers' keys, and runs on mainnet
# only; the coordinator's fault matrix drives that path
# (`an_approved_cross_chain_withdraw_runs_under_the_terms_on_its_row`).
#
# Money rows [TERMS_MONEY=1]:
#   M1 an exact-output swap: USDC → SWAP_OUT of wNEAR. success, the fill is the
#      amount asked, the result carries the quote it ran with
#   M2 an exact-output withdraw of WITHDRAW_OUT USDC to the wallet's OWN Solana
#      address: success, delivered exactly, the quote and the refunded input on
#      the result, and how long the refund took to show in the balance.
#      Costs the bridge fee, and about 0.18 USDC more the first time (the
#      address's USDC account is opened).
#
# Required env:
#   WALLET_API_KEY   wk_… of a MAINNET custody wallet with no policy (or one
#                    that allows swap and cross_chain_withdraw). The free rows
#                    need 1 USDC in its intents balance (without it the rows
#                    that read the balance first are skipped); the money rows
#                    2 USDC.
# Optional:
#   API              default https://api.outlayer.ai
#   TERMS_MONEY=1    run M1 and M2
#
# Run:
#   set -a; source <file holding WALLET_API_KEY>; set +a; ./tests/withdraw_terms_e2e.sh
set -uo pipefail

: "${WALLET_API_KEY:?the wk_ key of a mainnet wallet, exported from a file and never typed on the command line}"
API="${API:-https://api.outlayer.ai}"
USDC="nep141:17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1"
WNEAR="nep141:wrap.near"
SWAP_IN=300000                          # 0.30 USDC
SWAP_OUT=50000000000000000000000        # 0.05 wNEAR
WITHDRAW_IN=1000000                     # 1 USDC, above 1Click's bridge floor on Solana
WITHDRAW_OUT=300000                     # 0.30 USDC delivered

PASS=0; FAIL=0
pass() { echo "  ✓ $*"; PASS=$((PASS + 1)); }
skip() { echo "  ∅ $*"; }
fail() { echo "  ✗ $*"; FAIL=$((FAIL + 1)); }
log()  { echo; echo "── $*"; }

# post <path> <json> [idempotency key] → HTTP, BODY
post() {
  local out
  out=$(curl -s -m 150 -w '\n%{http_code}' -X POST "$API$1" \
    -H @<(printf '%s\n' "Authorization: Bearer $WALLET_API_KEY" ${3:+"X-Idempotency-Key: $3"}) \
    -H 'Content-Type: application/json' -d "$2")
  HTTP=$(tail -n1 <<<"$out"); BODY=$(sed '$d' <<<"$out")
}
get() {
  local out
  out=$(curl -s -m 60 -w '\n%{http_code}' "$API$1" -H @<(printf '%s\n' "Authorization: Bearer $WALLET_API_KEY"))
  HTTP=$(tail -n1 <<<"$out"); BODY=$(sed '$d' <<<"$out")
}
f() { jq -r "$1 // empty" <<<"$BODY"; }
is_int() { [[ "$1" =~ ^[0-9]+$ ]]; }
# le <a> <b>: a ≤ b, for amounts past 64 bits
le() { [[ "$(echo "$1 <= $2" | bc)" == 1 ]]; }
intents_usdc() { get "/wallet/v1/balance?token=${USDC#nep141:}&source=intents"; f .balance; }

# settle <request id>: poll the request to a terminal status → ST, BODY
settle() {
  local i
  for i in $(seq 1 90); do
    get "/wallet/v1/requests/$1"; ST=$(f .status)
    case "$ST" in success|failed|needs_review) return ;; esac
    sleep 2   # the bridge settles off this call; the request row is the only place its outcome appears
  done
}

KEY_HEAD=${WALLET_API_KEY:0:4}; KEY_LEN=${#WALLET_API_KEY}
echo "API $API | wallet key $KEY_HEAD... ($KEY_LEN chars)"

get "/wallet/v1/address?chain=solana"; SOL_ADDR=$(f .address)
[[ -n "$SOL_ADDR" ]] || { echo "the wallet's Solana address could not be read: HTTP $HTTP $(head -c 200 <<<"$BODY")"; exit 1; }
BAL=$(intents_usdc); is_int "$BAL" || BAL=0
echo "wallet's Solana address $SOL_ADDR | intents USDC $BAL"
FUNDED=0; le "$WITHDRAW_IN" "$BAL" && FUNDED=1

# wbody '<jq object>' [--arg name value …]: a withdrawal body to the wallet's own Solana address.
# The object is SINGLE-quoted and its values arrive by --arg: bash 3.2 brace-expands
# {a,b} inside "$(… "{…}")", which splits the program and sends an empty body.
wbody() {
  local obj=$1; shift
  jq -nc --arg to "$SOL_ADDR" --arg t "$USDC" "$@" "$obj"' + {chain:"solana",to:$to,token:$t}'
}

# ── B1 ───────────────────────────────────────────────────────────────────────
log "B1 a withdrawal with a memo is refused, on every route"
for chain in near solana; do
  body=$(jq -nc --arg c "$chain" --arg to "$SOL_ADDR" --arg t "$USDC" '{chain:$c,to:$to,token:$t,amount:"1",memo:"12345"}')
  post /wallet/v1/intents/withdraw/dry-run "$body"
  [[ "$HTTP" == 200 && "$(f .would_succeed)" != true && "$(f .reason)" == memo_not_supported ]] \
    && pass "B1 $chain dry-run: memo_not_supported" || fail "B1 $chain dry-run HTTP $HTTP $(head -c 200 <<<"$BODY")"
  post /wallet/v1/intents/withdraw "$body"
  [[ "$HTTP" == 400 && "$(f .error)" == memo_not_supported ]] \
    && pass "B1 $chain withdraw: 400 memo_not_supported" || fail "B1 $chain withdraw HTTP $HTTP $(head -c 200 <<<"$BODY")"
done
post /wallet/v1/intents/withdraw/dry-run "$(wbody '{amount:"1",memo:null}')"
[[ "$HTTP" == 200 && "$(f .reason)" != memo_not_supported ]] && pass "B1 a null memo is no memo" || fail "B1 null memo HTTP $HTTP $(head -c 200 <<<"$BODY")"

# ── B2 ───────────────────────────────────────────────────────────────────────
log "B2 a field the body does not define is named and refused"
post /wallet/v1/intents/withdraw "$(wbody '{amount:"1",msg:"{}"}')"
[[ "$HTTP" == 400 && "$(f .message)" == *'unknown field `msg`'* ]] && pass "B2 withdraw: msg" || fail "B2 withdraw HTTP $HTTP $(head -c 200 <<<"$BODY")"
post /wallet/v1/intents/swap/quote "$(jq -nc --arg i "$USDC" --arg o "$WNEAR" '{token_in:$i,token_out:$o,amount_in:"300000",slippage:50}')"
[[ "$HTTP" == 400 && "$(f .message)" == *'unknown field `slippage`'* ]] && pass "B2 swap quote: slippage" || fail "B2 swap quote HTTP $HTTP $(head -c 200 <<<"$BODY")"
post /wallet/v1/intents/withdraw/dry-run "$(wbody '{amount:"1",min_gas:"1"}')"
[[ "$HTTP" == 400 && "$(f .message)" == *'unknown field `min_gas`'* ]] && pass "B2 withdraw dry-run: min_gas" || fail "B2 dry-run HTTP $HTTP $(head -c 200 <<<"$BODY")"
post /wallet/v1/intents/swap "$(jq -nc --arg i "$USDC" --arg o "$WNEAR" '{token_in:$i,token_out:$o,amount_in:"0",slippage:50}')"
[[ "$HTTP" == 400 && "$(f .message)" == *'unknown field `slippage`'* ]] && pass "B2 swap: slippage" || fail "B2 swap HTTP $HTTP $(head -c 200 <<<"$BODY")"
post /wallet/v1/intents/transfer "$(jq -nc --arg t "$USDC" '{to:"intents.near",amount:"0",token:$t,memo:"x"}')"
[[ "$HTTP" == 400 && "$(f .message)" == *'unknown field `memo`'* ]] && pass "B2 intents transfer: memo" || fail "B2 transfer HTTP $HTTP $(head -c 200 <<<"$BODY")"

# ── B3 ───────────────────────────────────────────────────────────────────────
log "B3 one size per request"
post /wallet/v1/intents/withdraw "$(wbody '{amount:"1",amount_out:"1",max_amount_in:"2"}')"
[[ "$HTTP" == 400 && "$(f .message)" == *"not both"* ]] && pass "B3 both sizes" || fail "B3 both sizes HTTP $HTTP $(head -c 200 <<<"$BODY")"
post /wallet/v1/intents/withdraw "$(wbody '{amount_out:"1"}')"
[[ "$HTTP" == 400 && "$(f .message)" == *"requires max_amount_in"* ]] && pass "B3 an output without its ceiling" || fail "B3 no ceiling HTTP $HTTP $(head -c 200 <<<"$BODY")"
post /wallet/v1/intents/withdraw "$(jq -nc --arg t "$USDC" '{chain:"near",to:"intents.near",token:$t,amount_out:"1",max_amount_in:"2"}')"
[[ "$HTTP" == 400 && "$(f .message)" == *'delivers `amount` exactly'* ]] && pass "B3 an output on a NEAR withdrawal" || fail "B3 near HTTP $HTTP $(head -c 200 <<<"$BODY")"
post /wallet/v1/intents/swap/quote "$(jq -nc --arg i "$USDC" --arg o "$WNEAR" '{token_in:$i,token_out:$o}')"
[[ "$HTTP" == 400 && "$(f .message)" == "amount_in is required"* ]] && pass "B3 a swap without a size" || fail "B3 no size HTTP $HTTP $(head -c 200 <<<"$BODY")"
post /wallet/v1/intents/withdraw "$(wbody '{amount:"1",max_amount_in:"2"}')"
[[ "$HTTP" == 400 && "$(f .message)" == *"send it with amount_out"* ]] && pass "B3 a ceiling without its output" || fail "B3 lone ceiling HTTP $HTTP $(head -c 200 <<<"$BODY")"
post /wallet/v1/intents/swap/quote "$(jq -nc --arg i "$USDC" --arg o "$WNEAR" '{token_in:$i,token_out:$o,amount_out:"1",max_amount_in:"2",min_amount_out:"1"}')"
[[ "$HTTP" == 400 && "$(f .message)" == *"the output is exact"* ]] && pass "B3 a floor beside an exact output" || fail "B3 floor+output HTTP $HTTP $(head -c 200 <<<"$BODY")"
post /wallet/v1/intents/swap/quote "$(jq -nc --arg i "$USDC" --arg o "$WNEAR" '{token_in:$i,token_out:$o,amount_in:"1",amount_out:"1",max_amount_in:"2"}')"
[[ "$HTTP" == 400 && "$(f .message)" == *"not both"* ]] && pass "B3 a swap with both sizes" || fail "B3 swap both HTTP $HTTP $(head -c 200 <<<"$BODY")"

# ── B4 ───────────────────────────────────────────────────────────────────────
log "B4 an amount is digits and nothing else"
for junk in "+300000" "0300000" " 300000" "300000.0" "0"; do
  post /wallet/v1/intents/swap/quote "$(jq -nc --arg i "$USDC" --arg o "$WNEAR" --arg a "$junk" '{token_in:$i,token_out:$o,amount_in:$a}')"
  [[ "$HTTP" == 400 && "$(f .error)" == bad_request ]] && pass "B4 swap quote amount_in '$junk'" || fail "B4 swap amount_in '$junk' HTTP $HTTP $(head -c 200 <<<"$BODY")"
done
for junk in "+1" "01"; do
  post /wallet/v1/intents/swap/quote "$(jq -nc --arg i "$USDC" --arg o "$WNEAR" --arg a "$junk" '{token_in:$i,token_out:$o,amount_out:"1",max_amount_in:$a}')"
  [[ "$HTTP" == 400 && "$(f .message)" == "max_amount_in must be"* ]] && pass "B4 swap quote max_amount_in '$junk'" || fail "B4 max_amount_in '$junk' HTTP $HTTP $(head -c 200 <<<"$BODY")"
  post /wallet/v1/intents/swap/quote "$(jq -nc --arg i "$USDC" --arg o "$WNEAR" --arg a "$junk" '{token_in:$i,token_out:$o,amount_out:$a,max_amount_in:"2"}')"
  [[ "$HTTP" == 400 && "$(f .message)" == "amount_out must be"* ]] && pass "B4 swap quote amount_out '$junk'" || fail "B4 amount_out '$junk' HTTP $HTTP $(head -c 200 <<<"$BODY")"
  post /wallet/v1/intents/swap/quote "$(jq -nc --arg i "$USDC" --arg o "$WNEAR" --arg a "$junk" '{token_in:$i,token_out:$o,amount_in:"300000",min_amount_out:$a}')"
  [[ "$HTTP" == 400 && "$(f .message)" == "min_amount_out must be"* ]] && pass "B4 swap quote min_amount_out '$junk'" || fail "B4 min_amount_out '$junk' HTTP $HTTP $(head -c 200 <<<"$BODY")"
  post /wallet/v1/intents/withdraw/dry-run "$(wbody '{amount:$a}' --arg a "$junk")"
  [[ "$HTTP" == 200 && "$(f .would_succeed)" != true && "$(f .reason)" == invalid_request ]] \
    && pass "B4 withdraw dry-run amount '$junk': invalid_request" || fail "B4 dry-run '$junk' HTTP $HTTP $(head -c 200 <<<"$BODY")"
done
post /wallet/v1/intents/transfer "$(jq -nc --arg t "$USDC" '{to:"intents.near",amount:"+0",token:$t}')"
[[ "$HTTP" == 400 && "$(f .message)" == "amount must be an integer amount"* ]] && pass "B4 intents transfer amount '+0'" || fail "B4 transfer '+0' HTTP $HTTP $(head -c 200 <<<"$BODY")"

# ── Q1 ───────────────────────────────────────────────────────────────────────
log "Q1 a swap quote, exact input"
post /wallet/v1/intents/swap/quote "$(jq -nc --arg i "$USDC" --arg o "$WNEAR" --arg a "$SWAP_IN" '{token_in:$i,token_out:$o,amount_in:$a}')"
EST=$(f .amount_out); GUAR=$(f .min_amount_out)
if [[ "$HTTP" == 200 ]] && is_int "$EST" && is_int "$GUAR"; then
  [[ "$(f .amount_in)" == "$SWAP_IN" ]] && pass "Q1 amount_in is the input asked" || fail "Q1 amount_in $(f .amount_in)"
  le "$GUAR" "$EST" && pass "Q1 the guarantee ($GUAR) is not above the estimate ($EST)" || fail "Q1 guarantee $GUAR above estimate $EST"
  [[ -n "$(f .amount_in_usd)" && -n "$(f .amount_out_usd)" ]] && pass "Q1 USD figures present" || fail "Q1 no USD figures: $(head -c 300 <<<"$BODY")"
  [[ -z "$(f .reason)" ]] && pass "Q1 no reason on a quote without bounds" || fail "Q1 reason $(f .reason)"
else
  fail "Q1 HTTP $HTTP $(head -c 300 <<<"$BODY")"; EST=""
fi

# ── Q2 ───────────────────────────────────────────────────────────────────────
log "Q2 a swap quote, exact output"
post /wallet/v1/intents/swap/quote "$(jq -nc --arg i "$USDC" --arg o "$WNEAR" --arg a "$SWAP_OUT" '{token_in:$i,token_out:$o,amount_out:$a,max_amount_in:"100000000"}')"
NEED=$(f .amount_in)
if [[ "$HTTP" == 200 ]] && is_int "$NEED"; then
  [[ "$(f .amount_out)" == "$SWAP_OUT" && "$(f .min_amount_out)" == "$SWAP_OUT" ]] \
    && pass "Q2 estimate and guarantee are the output asked" || fail "Q2 out $(f .amount_out) / min $(f .min_amount_out), asked $SWAP_OUT"
  MIN_IN=$(f .min_amount_in)
  is_int "$MIN_IN" && le "$MIN_IN" "$NEED" && pass "Q2 min_amount_in ($MIN_IN) ≤ amount_in ($NEED)" || fail "Q2 min_amount_in '$MIN_IN' vs amount_in $NEED"
  [[ -z "$(f .reason)" ]] && pass "Q2 a generous ceiling is met" || fail "Q2 reason $(f .reason)"
else
  fail "Q2 HTTP $HTTP $(head -c 300 <<<"$BODY")"; NEED=""
fi
post /wallet/v1/intents/swap/quote "$(jq -nc --arg i "$USDC" --arg o "$WNEAR" --arg a "$SWAP_OUT" '{token_in:$i,token_out:$o,amount_out:$a,max_amount_in:"1"}')"
[[ "$HTTP" == 200 && "$(f .reason)" == above_max_amount_in && -n "$(f .amount_in)" ]] \
  && pass "Q2 a ceiling of 1: above_max_amount_in, with the input the quote needs" || fail "Q2 ceiling 1: HTTP $HTTP $(head -c 300 <<<"$BODY")"

# ── Q3 ───────────────────────────────────────────────────────────────────────
log "Q3 a floor at the estimate is under the guarantee's reach"
if [[ -n "$EST" && "$EST" != "$GUAR" ]]; then
  post /wallet/v1/intents/swap/quote "$(jq -nc --arg i "$USDC" --arg o "$WNEAR" --arg a "$SWAP_IN" --arg m "$EST" '{token_in:$i,token_out:$o,amount_in:$a,min_amount_out:$m}')"
  # The market may have moved between the two quotes; a floor at the earlier
  # estimate is refused unless the new GUARANTEE rose past it.
  if [[ "$(f .reason)" == below_min_amount_out ]]; then pass "Q3 below_min_amount_out (guarantee now $(f .min_amount_out), floor $EST)"
  elif le "$EST" "$(f .min_amount_out)"; then skip "Q3 the market moved up a whole slippage step between two quotes; rerun"
  else fail "Q3 floor $EST passed a guarantee of $(f .min_amount_out)"; fi
else
  skip "Q3 needs Q1's estimate above its guarantee"
fi
post /wallet/v1/intents/swap/quote "$(jq -nc --arg i "$USDC" --arg o "$WNEAR" --arg a "$SWAP_IN" '{token_in:$i,token_out:$o,amount_in:$a,min_amount_out:"1"}')"
[[ "$HTTP" == 200 && -z "$(f .reason)" ]] && is_int "$(f .min_amount_out)" && pass "Q3 a floor of 1 is met" || fail "Q3 floor 1: HTTP $HTTP $(head -c 300 <<<"$BODY")"

# ── W1–W3 ────────────────────────────────────────────────────────────────────
if [[ "$FUNDED" != 1 ]]; then
  log "W1–W4, R1–R5 skipped: the dry-run reads the balance first, and the wallet holds $BAL USDC in intents (needs $WITHDRAW_IN)"
else
  log "W1 a cross-chain withdraw dry-run, exact input"
  post /wallet/v1/intents/withdraw/dry-run "$(wbody '{amount:$a}' --arg a "$WITHDRAW_IN")"
  W_GUAR=$(f .min_amount_out)
  if [[ "$HTTP" == 200 && "$(f .would_succeed)" == true ]] && is_int "$W_GUAR"; then
    [[ "$(f .amount_in)" == "$WITHDRAW_IN" ]] && pass "W1 amount_in is the input asked" || fail "W1 amount_in $(f .amount_in)"
    le "$W_GUAR" "$(f .amount_out)" && pass "W1 guarantee $W_GUAR ≤ estimate $(f .amount_out)" || fail "W1 guarantee above estimate"
    is_int "$(f .withdraw_fee)" && pass "W1 withdraw_fee $(f .withdraw_fee)" || fail "W1 no withdraw_fee: $(head -c 300 <<<"$BODY")"
    [[ "$(f .message)" == *"min $W_GUAR"* ]] && pass "W1 the message carries the same guarantee as the field" || fail "W1 message '$(f .message)' vs field $W_GUAR"
  else
    fail "W1 HTTP $HTTP $(head -c 300 <<<"$BODY")"; W_GUAR=""
  fi

  log "W2 the same, exact output"
  post /wallet/v1/intents/withdraw/dry-run "$(wbody '{amount_out:$o,max_amount_in:$m}' --arg o "$WITHDRAW_OUT" --arg m "$WITHDRAW_IN")"
  W_NEED=$(f .amount_in)
  if [[ "$HTTP" == 200 && "$(f .would_succeed)" == true ]] && is_int "$W_NEED"; then
    [[ "$(f .amount_out)" == "$WITHDRAW_OUT" && "$(f .min_amount_out)" == "$WITHDRAW_OUT" ]] \
      && pass "W2 delivers exactly the amount asked" || fail "W2 out $(f .amount_out) / min $(f .min_amount_out)"
    le "$WITHDRAW_OUT" "$W_NEED" && pass "W2 needs $W_NEED in for $WITHDRAW_OUT out" || fail "W2 amount_in $W_NEED under the output"
  elif [[ "$(f .reason)" == above_max_amount_in ]]; then
    skip "W2 the route needs $(f .amount_in) in, over this suite's $WITHDRAW_IN ceiling"; W_NEED=""
  else
    fail "W2 HTTP $HTTP $(head -c 300 <<<"$BODY")"; W_NEED=""
  fi
  post /wallet/v1/intents/withdraw/dry-run "$(wbody '{amount_out:$o,max_amount_in:$m}' --arg o "$WITHDRAW_OUT" --arg m "1")"
  [[ "$HTTP" == 200 && "$(f .would_succeed)" != true && "$(f .reason)" == above_max_amount_in && -n "$(f .amount_in)" ]] \
    && pass "W2 a ceiling of 1: would not succeed, above_max_amount_in, figures in the body" || fail "W2 ceiling 1: HTTP $HTTP $(head -c 300 <<<"$BODY")"

  log "W3 a floor above the guarantee"
  if [[ -n "$W_GUAR" ]]; then
    FLOOR=$(echo "$W_GUAR * 2" | bc)
    post /wallet/v1/intents/withdraw/dry-run "$(wbody '{amount:$a,min_amount_out:$f}' --arg a "$WITHDRAW_IN" --arg f "$FLOOR")"
    [[ "$HTTP" == 200 && "$(f .would_succeed)" != true && "$(f .reason)" == below_min_amount_out ]] \
      && pass "W3 below_min_amount_out" || fail "W3 HTTP $HTTP $(head -c 300 <<<"$BODY")"
  else
    skip "W3 needs W1's guarantee"
  fi
  post /wallet/v1/intents/withdraw/dry-run "$(wbody '{amount:$a,min_amount_out:$f}' --arg a "$WITHDRAW_IN" --arg f "1")"
  [[ "$HTTP" == 200 && "$(f .would_succeed)" == true ]] && pass "W3 a floor of 1 is met" || fail "W3 floor 1: HTTP $HTTP $(head -c 300 <<<"$BODY")"

  log "W4 the ceiling of an exact output is held in full"
  OVER=$(echo "$BAL + 1" | bc)
  post /wallet/v1/intents/withdraw/dry-run "$(wbody '{amount_out:$o,max_amount_in:$m}' --arg o "$WITHDRAW_OUT" --arg m "$OVER")"
  [[ "$HTTP" == 200 && "$(f .would_succeed)" != true && "$(f .reason)" == insufficient_balance ]] \
    && pass "W4 a ceiling of balance + 1: insufficient_balance" || fail "W4 HTTP $HTTP $(head -c 300 <<<"$BODY")"

  # ── R1, R2: the real calls answer the previews' names ──────────────────────
  log "R1 the real swap with a floor twice the estimate"
  if [[ -n "$EST" ]]; then
    post /wallet/v1/intents/swap "$(jq -nc --arg i "$USDC" --arg o "$WNEAR" --arg a "$SWAP_IN" --arg m "$(echo "$EST * 2" | bc)" '{token_in:$i,token_out:$o,amount_in:$a,min_amount_out:$m}')" "terms-r1-$(uuidgen)"
    if [[ "$HTTP" == 400 && "$(f .error)" == below_min_amount_out ]] && is_int "$(f .quoted_min_amount_out)"; then
      pass "R1 400 below_min_amount_out, quoted_min_amount_out $(f .quoted_min_amount_out)"
    else fail "R1 expected 400 below_min_amount_out, got HTTP $HTTP: $(head -c 300 <<<"$BODY")"; fi
  else
    skip "R1 needs Q1's estimate"
  fi

  log "R2 the real cross-chain withdraw, exact output under a ceiling of 1"
  post /wallet/v1/intents/withdraw "$(wbody '{amount_out:$o,max_amount_in:$m}' --arg o "$WITHDRAW_OUT" --arg m "1")" "terms-r2-$(uuidgen)"
  if [[ "$HTTP" == 400 && "$(f .error)" == above_max_amount_in ]] && is_int "$(f .quoted_amount_in)"; then
    pass "R2 400 above_max_amount_in, quoted_amount_in $(f .quoted_amount_in)"
  else fail "R2 expected 400 above_max_amount_in, got HTTP $HTTP: $(head -c 300 <<<"$BODY")"; fi

  log "R3 the real swap, exact output under a ceiling of 1"
  post /wallet/v1/intents/swap "$(jq -nc --arg i "$USDC" --arg o "$WNEAR" --arg a "$SWAP_OUT" '{token_in:$i,token_out:$o,amount_out:$a,max_amount_in:"1"}')" "terms-r3-$(uuidgen)"
  if [[ "$HTTP" == 400 && "$(f .error)" == above_max_amount_in && "$(f .max_amount_in)" == 1 ]] && is_int "$(f .quoted_amount_in)"; then
    pass "R3 400 above_max_amount_in, quoted_amount_in $(f .quoted_amount_in)"
  else fail "R3 expected 400 above_max_amount_in, got HTTP $HTTP: $(head -c 300 <<<"$BODY")"; fi

  log "R4 the real cross-chain withdraw with a floor twice the guarantee"
  if [[ -n "$W_GUAR" ]]; then
    post /wallet/v1/intents/withdraw "$(wbody '{amount:$a,min_amount_out:$f}' --arg a "$WITHDRAW_IN" --arg f "$(echo "$W_GUAR * 2" | bc)")" "terms-r4-$(uuidgen)"
    if [[ "$HTTP" == 400 && "$(f .error)" == below_min_amount_out ]] && is_int "$(f .quoted_min_amount_out)"; then
      pass "R4 400 below_min_amount_out, quoted_min_amount_out $(f .quoted_min_amount_out)"
    else fail "R4 expected 400 below_min_amount_out, got HTTP $HTTP: $(head -c 300 <<<"$BODY")"; fi
  else
    skip "R4 needs W1's guarantee"
  fi

  log "R5 a refusal met in the background is written to the request"
  post /wallet/v1/intents/withdraw "$(wbody '{amount_out:$o,max_amount_in:$m,async:true}' --arg o "$WITHDRAW_OUT" --arg m "1")" "terms-r5-$(uuidgen)"
  RID=$(f .request_id)
  if [[ "$HTTP" == 400 && "$(f .error)" == above_max_amount_in ]]; then
    pass "R5 refused in the call itself: 400 above_max_amount_in"
  elif [[ -n "$RID" ]]; then
    settle "$RID"
    [[ "$ST" == failed ]] && pass "R5 the request ended failed" || fail "R5 ended $ST: $(head -c 300 <<<"$BODY")"
    [[ "$(f .result.error_code)" == above_max_amount_in && "$(f .result.max_amount_in)" == 1 ]] && is_int "$(f .result.quoted_amount_in)" \
      && pass "R5 result: error_code above_max_amount_in, quoted_amount_in $(f .result.quoted_amount_in)" \
      || fail "R5 result: $(jq -c .result <<<"$BODY" | head -c 300)"
    [[ "$(f .result.never_submitted)" == true ]] && pass "R5 never submitted" || fail "R5 never_submitted: $(jq -c .result <<<"$BODY" | head -c 300)"
    [[ "$(f .result.error)" == *"nothing was signed"* ]] && pass "R5 the row reads as the API answers" || fail "R5 error text: $(f .result.error | head -c 200)"
  else
    fail "R5 no request: HTTP $HTTP $(head -c 300 <<<"$BODY")"
  fi
fi

# ── C1 ───────────────────────────────────────────────────────────────────────
log "C1 the confidential previews, exact output"
post /wallet/v1/confidential/withdraw/dry-run "$(wbody '{amount_out:$o,max_amount_in:$m}' --arg o "$WITHDRAW_OUT" --arg m "$WITHDRAW_IN")"
if [[ "$HTTP" == 503 ]]; then
  skip "C1 confidential intents are off on this deployment"
else
  if [[ "$HTTP" == 200 && "$(f .amount_out)" == "$WITHDRAW_OUT" && "$(f .min_amount_out)" == "$WITHDRAW_OUT" ]] && is_int "$(f .amount_in)"; then
    pass "C1 withdraw dry-run: exactly $WITHDRAW_OUT out for $(f .amount_in) in"
  else fail "C1 withdraw dry-run HTTP $HTTP $(head -c 300 <<<"$BODY")"; fi
  post /wallet/v1/confidential/withdraw/dry-run "$(wbody '{amount_out:$o,max_amount_in:$m}' --arg o "$WITHDRAW_OUT" --arg m "1")"
  [[ "$HTTP" == 200 && "$(f .reason)" == above_max_amount_in ]] && pass "C1 a ceiling of 1: above_max_amount_in" || fail "C1 ceiling 1: HTTP $HTTP $(head -c 300 <<<"$BODY")"
  post /wallet/v1/confidential/swap/quote "$(jq -nc --arg i "$USDC" --arg o "$WNEAR" --arg a "$SWAP_OUT" '{token_in:$i,token_out:$o,amount_out:$a,max_amount_in:"100000000"}')"
  [[ "$HTTP" == 200 && "$(f .amount_out)" == "$SWAP_OUT" ]] && is_int "$(f .amount_in)" \
    && pass "C1 swap quote: exactly $SWAP_OUT out for $(f .amount_in) in" || fail "C1 swap quote HTTP $HTTP $(head -c 300 <<<"$BODY")"
  post /wallet/v1/confidential/withdraw/dry-run "$(wbody '{amount:"1000000",memo:"1"}')"
  [[ "$HTTP" == 400 && "$(f .error)" == memo_not_supported ]] && pass "C1 a memo: 400 memo_not_supported" || fail "C1 memo HTTP $HTTP $(head -c 200 <<<"$BODY")"
  post /wallet/v1/confidential/withdraw/dry-run "$(wbody '{amount:"1000000",msg:"{}"}')"
  [[ "$HTTP" == 400 && "$(f .error)" == bad_request && "$(f .message)" == *'unknown field `msg`'* ]] \
    && pass "C1 withdraw dry-run, unknown field: 400 bad_request naming it" || fail "C1 unknown field HTTP $HTTP $(head -c 200 <<<"$BODY")"
  post /wallet/v1/confidential/swap/quote "$(jq -nc --arg i "$USDC" --arg o "$WNEAR" '{token_in:$i,token_out:$o,amount_in:"300000",slippage:50}')"
  [[ "$HTTP" == 400 && "$(f .error)" == bad_request && "$(f .message)" == *'unknown field `slippage`'* ]] \
    && pass "C1 swap quote, unknown field: 400 bad_request naming it" || fail "C1 swap unknown field HTTP $HTTP $(head -c 200 <<<"$BODY")"
  post /wallet/v1/confidential/swap/quote "$(jq -nc --arg i "$USDC" --arg o "$WNEAR" '{token_in:$i,token_out:$o,amount_in:"+300000"}')"
  [[ "$HTTP" == 400 && "$(f .error)" == bad_request ]] && pass "C1 swap quote, a signed amount: 400" || fail "C1 signed amount HTTP $HTTP $(head -c 200 <<<"$BODY")"

  post /wallet/v1/confidential/swap/quote "$(jq -nc --arg i "$USDC" --arg o "$WNEAR" --arg a "$SWAP_IN" '{token_in:$i,token_out:$o,amount_in:$a}')"
  C_EST=$(f .amount_out); C_GUAR=$(f .min_amount_out)
  if [[ "$HTTP" == 200 ]] && is_int "$C_EST" && is_int "$C_GUAR" && le "$C_GUAR" "$C_EST"; then
    pass "C1 swap quote, exact input: guarantee $C_GUAR ≤ estimate $C_EST"
    post /wallet/v1/confidential/swap/quote "$(jq -nc --arg i "$USDC" --arg o "$WNEAR" --arg a "$SWAP_IN" --arg m "$(echo "$C_EST * 2" | bc)" '{token_in:$i,token_out:$o,amount_in:$a,min_amount_out:$m}')"
    [[ "$HTTP" == 200 && "$(f .reason)" == below_min_amount_out ]] && pass "C1 a floor twice the estimate: below_min_amount_out" || fail "C1 floor: HTTP $HTTP $(head -c 300 <<<"$BODY")"
  else
    fail "C1 swap quote, exact input: HTTP $HTTP $(head -c 300 <<<"$BODY")"
  fi
  post /wallet/v1/confidential/swap/quote "$(jq -nc --arg i "$USDC" --arg o "$WNEAR" --arg a "$SWAP_OUT" '{token_in:$i,token_out:$o,amount_out:$a,max_amount_in:"1"}')"
  [[ "$HTTP" == 200 && "$(f .reason)" == above_max_amount_in ]] && pass "C1 swap quote, a ceiling of 1: above_max_amount_in" || fail "C1 swap ceiling 1: HTTP $HTTP $(head -c 300 <<<"$BODY")"

  for route in shield unshield transfer; do
    post "/wallet/v1/confidential/$route" '{'
    [[ "$HTTP" == 400 && "$(f .error)" == bad_request && "$(f .message)" == "Invalid request body"* ]] \
      && pass "C1 $route, a body that does not parse: 400 bad_request" || fail "C1 $route bad body HTTP $HTTP $(head -c 200 <<<"$BODY")"
  done
  for route in shield unshield; do
    post "/wallet/v1/confidential/$route" "$(jq -nc --arg t "${USDC#nep141:}" '{token:$t,amount:"+0"}')"
    [[ "$HTTP" == 400 && "$(f .message)" == "amount must be an integer amount"* ]] \
      && pass "C1 $route amount '+0': refused by its spelling" || fail "C1 $route '+0' HTTP $HTTP $(head -c 200 <<<"$BODY")"
  done

  log "C2 the real confidential calls, exact output under a ceiling of 1"
  conf_usdc() { get "/wallet/v1/confidential/balance?token=$USDC"; f .balance; }
  C_BAL=$(conf_usdc)
  post /wallet/v1/confidential/swap "$(jq -nc --arg i "$USDC" --arg o "$WNEAR" --arg a "$SWAP_OUT" '{token_in:$i,token_out:$o,amount_out:$a,max_amount_in:"1"}')" "terms-c2s-$(uuidgen)"
  [[ "$HTTP" == 400 && "$(f .error)" == above_max_amount_in ]] && is_int "$(f .quoted_amount_in)" \
    && pass "C2 swap: 400 above_max_amount_in, quoted_amount_in $(f .quoted_amount_in)" || fail "C2 swap HTTP $HTTP $(head -c 300 <<<"$BODY")"
  post /wallet/v1/confidential/withdraw "$(wbody '{amount_out:$o,max_amount_in:$m}' --arg o "$WITHDRAW_OUT" --arg m "1")" "terms-c2w-$(uuidgen)"
  [[ "$HTTP" == 400 && "$(f .error)" == above_max_amount_in ]] && is_int "$(f .quoted_amount_in)" \
    && pass "C2 withdraw: 400 above_max_amount_in, quoted_amount_in $(f .quoted_amount_in)" || fail "C2 withdraw HTTP $HTTP $(head -c 300 <<<"$BODY")"
  C_AFTER=$(conf_usdc)
  [[ "$C_AFTER" == "$C_BAL" ]] && pass "C2 moved nothing: confidential USDC still '${C_BAL:-0}'" || fail "confidential USDC went '$C_BAL' → '$C_AFTER' after the refused calls"
fi

# Every row above is a preview or a refusal: the balance is where a broken one would show.
AFTER=$(intents_usdc)
[[ "$AFTER" == "$BAL" ]] && pass "the free rows moved nothing: intents USDC still $BAL" || fail "intents USDC went $BAL → $AFTER after rows that must move nothing"

# ── M1, M2 ───────────────────────────────────────────────────────────────────

if [[ "${TERMS_MONEY:-}" != 1 ]]; then
  log "M1, M2 skipped (TERMS_MONEY=1 swaps and withdraws real USDC)"
elif [[ "$FAIL" != 0 ]]; then
  log "M1, M2 skipped: $FAIL free row(s) failed, and money is not sent to a deployment that just answered wrong"
elif [[ -z "${NEED:-}" || -z "${W_NEED:-}" ]]; then
  log "M1, M2 skipped: they are priced from Q2 and W2, which did not answer"
else
  log "M1 an exact-output swap: $SWAP_OUT wNEAR"
  CEIL=$(echo "$NEED * 101 / 100" | bc)   # 1% of room over the preview for the swap's own quote
  post /wallet/v1/intents/swap "$(jq -nc --arg i "$USDC" --arg o "$WNEAR" --arg a "$SWAP_OUT" --arg m "$CEIL" '{token_in:$i,token_out:$o,amount_out:$a,max_amount_in:$m}')" "terms-m1-$(uuidgen)"
  RID=$(f .request_id); echo "  answer: HTTP $HTTP status $(f .status) request $RID (ceiling $CEIL)"
  if [[ -n "$RID" ]]; then
    settle "$RID"
    [[ "$ST" == success ]] && pass "M1 success" || fail "M1 ended $ST: $(head -c 300 <<<"$BODY")"
    [[ "$(f .result.amount_out)" == "$SWAP_OUT" ]] && pass "M1 the fill is the amount asked" || fail "M1 filled $(f .result.amount_out), asked $SWAP_OUT"
    [[ "$(f .result.quote.swap_type)" == EXACT_OUTPUT && "$(f .result.quote.max_amount_in)" == "$CEIL" ]] \
      && pass "M1 the result carries its quote: $(f .result.quote.amount_in) in, ceiling $CEIL" || fail "M1 quote: $(jq -c .result.quote <<<"$BODY")"
    le "$(f .result.quote.amount_in)" "$CEIL" && pass "M1 sent no more than the ceiling" || fail "M1 sent $(f .result.quote.amount_in) over $CEIL"
    echo "  refunded_amount: $(f .result.refunded_amount)"
  else
    fail "M1 no request: HTTP $HTTP $(head -c 300 <<<"$BODY")"
  fi

  log "M2 an exact-output withdraw: $WITHDRAW_OUT USDC to $SOL_ADDR"
  BEFORE=$(intents_usdc)
  CEIL=$(echo "$W_NEED * 101 / 100" | bc)
  post /wallet/v1/intents/withdraw "$(wbody '{amount_out:$o,max_amount_in:$m,async:true}' --arg o "$WITHDRAW_OUT" --arg m "$CEIL")" "terms-m2-$(uuidgen)"
  RID=$(f .request_id); echo "  answer: HTTP $HTTP status $(f .status) request $RID (ceiling $CEIL)"
  if [[ -n "$RID" ]]; then
    STARTED=$(date +%s)
    settle "$RID"
    [[ "$ST" == success ]] && pass "M2 success" || fail "M2 ended $ST: $(head -c 300 <<<"$BODY")"
    [[ "$(f .result.amount_out)" == "$WITHDRAW_OUT" ]] && pass "M2 delivered exactly $WITHDRAW_OUT" || fail "M2 delivered $(f .result.amount_out), asked $WITHDRAW_OUT"
    SENT=$(f .result.quote.amount_in)
    [[ "$(f .result.quote.swap_type)" == EXACT_OUTPUT && "$(f .result.quote.amount_out)" == "$WITHDRAW_OUT" ]] && le "$SENT" "$CEIL" \
      && pass "M2 the result carries its quote: $SENT in under $CEIL" || fail "M2 quote: $(jq -c .result.quote <<<"$BODY")"
    [[ -n "$(f .result.destination_tx_hash)" ]] && pass "M2 destination tx $(f .result.destination_tx_hash)" || fail "M2 no destination_tx_hash"
    REFUND=$(f .result.refunded_amount); echo "  refunded_amount: ${REFUND:-none reported}"
    # What left for good is what was sent less what came back; wait for the balance to say so.
    if is_int "${REFUND:-}" && [[ "$REFUND" != 0 ]]; then
      WANT=$(echo "$BEFORE - $SENT + $REFUND" | bc); NOW=""
      for _ in $(seq 1 60); do
        NOW=$(intents_usdc); [[ "$NOW" == "$WANT" ]] && break
        sleep 2   # the refund is 1Click's own transfer after the swap; the balance is where it shows
      done
      [[ "$NOW" == "$WANT" ]] && pass "M2 the refund is in the balance $(( $(date +%s) - STARTED )) s after the request" \
        || fail "M2 balance $NOW, expected $WANT ($BEFORE − $SENT + $REFUND)"
    else
      NOW=$(intents_usdc)
      [[ "$NOW" == "$(echo "$BEFORE - $SENT" | bc)" ]] && pass "M2 the balance fell by the quoted input, nothing came back" \
        || echo "  balance $BEFORE → $NOW with $SENT sent and no refund reported: read the request's result"
    fi
  else
    fail "M2 no request: HTTP $HTTP $(head -c 300 <<<"$BODY")"
  fi
fi

echo; echo "passed $PASS, failed $FAIL"
[[ "$FAIL" == 0 ]]
