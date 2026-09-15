#!/usr/bin/env bash
#
# §R6 of the HoS acceptance list — GAS: whose it is, when the warning comes, and
# what the lane does once the warning has been ignored.
#
# THE SHAPE OF THE PROBLEM. On a bound wallet the two accounts pay for different
# things: the money in a transfer leaves the BOUND account, and the gas for the
# transaction that carries it leaves the EXECUTOR — the wallet's own implicit
# account, whose key is inside the enclave and which nobody can top up by
# accident. So an executor can run dry while the bound account is still full,
# and the lane stops for a reason that is invisible from every balance a partner
# would think to look at.
#
# What the coordinator does about it, and what this suite asks of each part:
#
#   * an ADVISORY flag on the binding — `gas_balance_low` against a 0.05 NEAR
#     threshold, which exists to arrive with several calls still left rather
#     than at the last one (§F1, §F4);
#   * NO pre-flight refusal: the send goes to the node, and the node's
#     `NotEnoughBalance` verdict is turned into `402 wallet_underfunded` with
#     the shortfall spelled out (§F2);
#   * and the request is SETTLED at the moment of that verdict — `failed`, with
#     `never_admitted` recorded — rather than left `processing` for a repair to
#     reconstruct later from an RPC reply that cannot tell "no such transaction"
#     apart from "I could not reach the node" (§F3).
#
# WHY THE CONTROL AT THE END IS NOT OPTIONAL. Every probe here is a refusal, and
# a refusal is satisfied by a lane that is broken for any other reason at all —
# a policy that permits nothing, a binding that went stale, a wallet past its
# monthly cap. §F4 tops the executor up and sends THE SAME envelope, which must
# then go through. Without it this suite would pass against a door that is
# simply shut.
#
#   PARENT=you.testnet ./tests/hos_gas_floor_e2e.sh --apply
#
# Optional: PSQL_CMD=<one-statement SQL command> adds §F3 — that the refused
# request was settled rather than abandoned, which is not visible from the
# answer. See .idea/TESTING-WITH-ADMIN.md.

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/hos_common.sh"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/agent_secret_mode.sh"

[[ "${1:-}" == "--apply" ]] || { sed -n '3,39p' "$0" >&2; echo "  Pass --apply to run." >&2; exit 0; }
hos_require

WL="${WL:-zavodil2.testnet}"                  # the one permitted destination
MOVE="500000000000000000000"                  # 0.0005 NEAR — the money, from the BOUND account

# What the executor is given, and why it is this number rather than zero.
#
# ZERO would not test this: an implicit account that has never been funded does
# not exist, and the node refuses an unknown signer with a different verdict
# entirely (`SignerDoesNotExist`, not `NotEnoughBalance`) — a real case, but not
# the one R6 asks about, and one that would quietly pass §F2's status check
# while saying nothing about the gas rule.
#
# 0.003 NEAR creates the account (an implicit account with one key stakes about
# 0.00182 for its own storage) and leaves roughly 0.0012 spendable. `call_ext`
# prepays 90 TGas, which the node prices at about 0.009 NEAR and demands IN FULL
# before it will admit the transaction — the unburnt remainder is refunded, but
# not until afterwards. Eight times the available balance is a margin that does
# not depend on the gas price of the day.
STARVED_NEAR="${STARVED_NEAR:-0.003}"
# Comfortably over the 0.05 NEAR warning threshold and over the cost of a call.
FED_NEAR="${FED_NEAR:-0.15}"
GAS_LOW_THRESHOLD="50000000000000000000000"   # 0.05 NEAR — binding.rs GAS_LOW_THRESHOLD_YOCTO

# ── a bound wallet whose executor is deliberately poor ─────────────────────
#
# Built here rather than with `new_bound_wallet`, which funds the executor with
# 0.3 NEAR — the very condition this suite has to avoid. Everything else is the
# same, and none of it needs the executor to sign: the setup transaction that
# installs the contract and names the executor as an extension is signed by the
# ASSET account's own key, which is why a binding can go active while the
# account that will operate it cannot afford a single call.
log "Building a bound wallet with a starved executor"
SEED="hos-gas-$(date +%s)-$$"
read -r WALLET_ID EXECUTOR < <(wallet_address "$SEED")
[[ -n "$WALLET_ID" ]] || { echo "✗ /address failed" >&2; exit 1; }
ASSET="hos-gas-$(openssl rand -hex 3).$PARENT"
note "wallet $WALLET_ID / executor $EXECUTOR / account $ASSET"

cleanup() {
  local rc=$?
  api "$SEED" DELETE /wallet/v1/binding >/dev/null 2>&1 || true
  account_exists "$ASSET" && { note "cleaning up $ASSET"; delete_account "$ASSET"; }
  return $rc
}
trap cleanup EXIT

create_subaccount "$ASSET" 1.2 || { echo "✗ $ASSET never appeared" >&2; exit 1; }
api "$SEED" PUT /wallet/v1/binding "$(jq -nc --arg a "$ASSET" '{asset_account_id:$a, kind:"personal_account"}')" >/dev/null
[[ "$HTTP" == "200" ]] || { echo "✗ PUT failed $HTTP: $BODY" >&2; exit 1; }
install_wallet "$ASSET" "$EXECUTOR" || { echo "✗ the setup transaction did not land" >&2; exit 1; }
fund_account "$EXECUTOR" "$STARVED_NEAR" || warn "the starving top-up did not land; the balance this suite reasons about is not the one on chain"

ST=""
for _ in 1 2 3 4 5 6 7 8; do
  api "$SEED" GET /wallet/v1/binding >/dev/null
  ST=$(jq -r '.binding_status // ""' <<<"$BODY"); [[ "$ST" == "active" ]] && break; sleep 3
done
if [[ "$ST" != "active" ]]; then
  fail "the binding never went active ('$ST') — nothing below would be about gas"
  verdict "§R6 gas floor"; exit 1
fi
pass "the binding is ACTIVE while its executor holds $STARVED_NEAR NEAR — a lane can be authorized and unaffordable at the same time"

POL=$(jq -nc --arg w "$WL" --arg s "$ASSET" \
  '{rules:{addresses:{mode:"whitelist",list:[$w,$s]}}}')
store_policy "$SEED" "$WALLET_ID" "$POL" \
  || { echo "✗ policy not stored — every refusal below would be a policy refusal" >&2; exit 1; }
note "policy: $WL and the bound account itself are permitted, no limits"

# ── F1 the warning, while there is still time to act on it ─────────────────
log "F1 the binding's own reading of the executor's balance"
api "$SEED" GET /wallet/v1/binding >/dev/null
GB=$(jq -r '.gas_balance // ""' <<<"$BODY")
LOW=$(bool_of gas_balance_low)
THR=$(jq -r '.gas_balance_threshold // ""' <<<"$BODY")
note "gas_balance=$GB low=$LOW threshold=$THR"
if [[ -z "$GB" ]]; then
  # An unreadable balance is deliberately NOT reported as low — raising a
  # funding alarm on an RPC blip trains people to ignore the alarm — so this is
  # a state to step aside for, not to fail on.
  skip "F1 — the binding carried no gas_balance this time, so there is no reading to judge the flag against"
else
  [[ "$LOW" == "true" ]] \
    && pass "F1 the binding says the executor is LOW — the funder learns it from the status they already poll, not from a failed call" \
    || fail "F1 gas_balance_low is '$LOW' for an executor holding $GB yocto, under the $GAS_LOW_THRESHOLD floor"
  [[ "$THR" == "$GAS_LOW_THRESHOLD" ]] \
    && pass "F1 and it names the threshold it measured against ($THR)" \
    || fail "F1 gas_balance_threshold is '$THR', expected $GAS_LOW_THRESHOLD — a flag whose floor is unstated cannot be acted on"
fi

# ── F2 the refusal itself ──────────────────────────────────────────────────
#
# The envelope is one the policy PERMITS and the bound account can easily
# afford: 0.0005 NEAR to a whitelisted destination, out of the 1.2 NEAR the
# account holds. The only thing missing is the executor's gas. So a refusal here
# is about gas or it is a defect somewhere else — and §F4 proves which.
log "F2 a permitted transfer the executor cannot pay to send"
MARK=""; sql_alive && MARK=$(sql "SELECT (now() AT TIME ZONE 'utc')")
call_ext "$SEED" "$ASSET" "$(ext_transfer "$WL" "$MOVE")" >/dev/null
note "answered HTTP $HTTP: $(msg_of | head -c 180)"
if [[ "$HTTP" == "200" ]]; then
  fail "F2 the transfer EXECUTED from an executor holding $STARVED_NEAR NEAR — either the funding did not take effect or the gas came from somewhere it should not"
  verdict "§R6 gas floor"; exit 1
fi
# 402, and specifically not a 5xx. A payment problem answered as a server error
# reads to a client as "escalate", and Cloudflare replaces an origin 502/504
# with a page of its own — the body naming the shortfall would never arrive.
[[ "$HTTP" == "402" ]] \
  && pass "F2 402 — being unable to pay is the caller's to fix, and it is answered as such rather than as a fault of ours" \
  || fail "F2 answered HTTP $HTTP, expected 402: a 5xx here reads as our defect, and a 502/504 is replaced by Cloudflare with a page that drops the message entirely"
[[ "$(err_of)" == "wallet_underfunded" ]] \
  && pass "F2 and names itself wallet_underfunded — the code a client branches on" \
  || fail "F2 the error code is '$(err_of)', not wallet_underfunded"
# The two numbers that make the message actionable. "Insufficient funds" tells a
# funder to send an unknown amount to an unknown account.
if [[ "$HTTP" == "402" ]]; then
  M=$(msg_of)
  grep -qiE "holds .*NEAR" <<<"$M" \
    && pass "F2 the message says what the wallet HOLDS" \
    || fail "F2 the message does not say what the wallet holds: $M"
  grep -qiE "costs .*NEAR" <<<"$M" \
    && pass "F2 and what the call COSTS — together, the amount to send" \
    || fail "F2 the message does not say what the call costs: $M"
  # WHICH account to send it to. Two numbers and no address leaves the person
  # who actually holds the NEAR — rarely the agent — with nothing to act on, and
  # an executor is an implicit account nobody can derive from the request they
  # made. nearcore names the signer in its own verdict, so the only way to lose
  # it is to throw it away.
  grep -q "$EXECUTOR" <<<"$M" \
    && pass "F2 and names the EXECUTOR as the account to fund — the one thing in this refusal that cannot be worked out from anywhere else" \
    || fail "F2 the message does not name the account to send NEAR to: $M"
  # And not the route that belongs to another feature. `not_enough_balance`
  # classifies every broadcast the node refused for a poor signer; on this lane
  # there is no author who can pay instead. `/wallet/v1/agent-secret/prepare`
  # stores a secret and cannot fund gas, and the store_secrets path is where
  # that advice belongs.
  if agent_secret_mode F2; then
    grep -q "agent-secret" <<<"$M" \
      && fail "F2 the message offers /wallet/v1/agent-secret/prepare, which stores a secret and cannot fund an executor's gas — a partner following it spends their time on the wrong endpoint" \
      || pass "F2 and offers no route that cannot fix this — the only fix is NEAR on that account, which is what it says"
  fi
fi

# ── F3 the request was settled, not abandoned ──────────────────────────────
#
# Invisible from the answer, and the half that decides whether a retry is safe.
# The node refused before executing anything, so the outcome is already known;
# leaving the row `processing` would make something else ask the chain about it
# later, and an RPC that cannot distinguish "no such transaction" from "I could
# not reach the node" is not a source that can settle it.
log "F3 what the coordinator recorded about the refused send"
if ! sql_alive; then
  skip "F3 — set PSQL_CMD to a command that runs one statement of SQL against the coordinator's database (see .idea/TESTING-WITH-ADMIN.md). Whether the request was settled or abandoned is not in the answer"
elif [[ -z "$MARK" ]]; then
  skip "F3 — no watermark was taken before the send, so a row found now could be an older one"
else
  WROW=$(sql_row "SELECT status || '|' || COALESCE(result_data->'failure'->>'never_admitted','') \
                    FROM wallet_requests \
                   WHERE wallet_id = '$WALLET_ID' AND created_at > '$MARK' \
                   ORDER BY created_at DESC LIMIT 1")
  if [[ -z "$WROW" ]]; then
    fail "F3 the refused send left no wallet_requests row at all — a refusal nobody can look up afterwards"
  else
    W_ST="${WROW%%|*}"; W_NA="${WROW#*|}"
    note "request status=$W_ST never_admitted=$(head -c 80 <<<"$W_NA")"
    [[ "$W_ST" == "failed" ]] \
      && pass "F3 the request is settled as failed — at the moment of the verdict, not fifteen minutes later by something reconstructing it" \
      || fail "F3 the request is '$W_ST'; a send the node refused outright must not be left for a repair to work out"
    [[ -n "$W_NA" ]] \
      && pass "F3 and it records that the transaction was NEVER ADMITTED, which is what makes a retry safe to offer" \
      || fail "F3 the row carries no never_admitted reason, so nothing distinguishes this from a send that may have landed"
    grep -q "Underfunded" <<<"$W_NA" \
      && pass "F3 and the reason kept is the gas one, not a generic failure" \
      || fail "F3 the recorded reason is '$(head -c 120 <<<"$W_NA")', which does not name the shortfall the caller was told about"
  fi
fi

# ── F4 the control: the same envelope, once the executor can pay ───────────
log "F4 topping the executor up and sending the identical envelope"
fund_account "$EXECUTOR" "$FED_NEAR" || warn "the feeding top-up did not land; F4 would then fail for gas, not for the envelope"
# The binding response caches the balance for 30 seconds (GAS_BALANCE_TTL_SECS),
# so a read taken straight after the transfer is entitled to be the old one.
sleep 35
api "$SEED" GET /wallet/v1/binding >/dev/null
LOW2=$(bool_of gas_balance_low)
note "gas_balance=$(jq -r '.gas_balance // "-"' <<<"$BODY") low=$LOW2"
[[ "$LOW2" == "false" ]] \
  && pass "F4 the warning cleared once the executor was funded — the flag tracks the balance rather than latching" \
  || fail "F4 gas_balance_low is still '$LOW2' after topping the executor up to $FED_NEAR NEAR"

call_ext "$SEED" "$ASSET" "$(ext_transfer "$WL" "$MOVE")" >/dev/null
if [[ "$HTTP" == "200" ]]; then
  pass "F4 and the identical envelope executed ($(jq -r '.status // "?"' <<<"$BODY"), tx $(jq -r '.tx_hash // "-"' <<<"$BODY" | head -c 12)…) — so every refusal above was about gas and nothing else"
else
  fail "F4 the same transfer is STILL refused with a funded executor (HTTP $HTTP): $(msg_of). Everything above is then a refusal for some other reason, and this suite proves nothing about gas"
fi

verdict "§R6 gas floor"
