#!/usr/bin/env bash
#
# §3 of the HoS test plan — the decoder and the core (mode-blind) policy over
# `w_execute_extension`. The largest attack surface we expose to the partner:
# the outer call says nothing (its receiver is the agent's own wallet contract,
# its deposit is a 1-yocto marker) and every real recipient and amount is
# nested in base64 args. Everything a rule is supposed to measure has to be
# read out of that blob, and everything the blob can be is tried here.
#
# The suite is deliberately built out of REFUSALS: a refusal is decided before
# anything is signed, so it costs no gas and no custody quota, and it is also
# the answer that matters — a decoder that fails open is the whole risk. The
# few allows are the negative controls §9 demands, without which a green run
# would also be green against a door that refuses everything.
#
# Distinguishing a DECODE refusal from a POLICY refusal without reading
# sentences: each decode case is aimed at an address the policy does NOT
# permit, so a working decoder answers with the ADDRESS rule (it got far
# enough to see the destination) and a broken one answers with a parse error.
# The pair pins which layer spoke.
#
#   PARENT=you.testnet ./tests/hos_decoder_policy_e2e.sh --apply
#
# Builds and deletes its own bound wallet — see the note at the top of the body.

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/hos_common.sh"

[[ "${1:-}" == "--apply" ]] || { sed -n '3,25p' "$0" >&2; echo "  Pass --apply to run." >&2; exit 0; }
hos_require
# Its OWN bound wallet. This suite fires forty-odd envelopes at the door, and
# although almost all of them are refused before anything is signed, enough
# reach the chain to eat a visible share of a wallet's daily custody
# allowance — which then failed the next suite on a LIMIT, not a rule.
new_bound_wallet decoder || { echo "✗ could not build this suite's bound wallet" >&2; exit 1; }
CLEAN_ASSET="$ASSET"
cleanup() {
  local rc=$?
  api "$SEED" DELETE /wallet/v1/binding >/dev/null 2>&1 || true
  account_exists "$CLEAN_ASSET" && { note "cleaning up $CLEAN_ASSET"; delete_account "$CLEAN_ASSET"; }
  return $rc
}
trap cleanup EXIT

WL="${WL:-zavodil2.testnet}"                 # the one permitted destination
OUTSIDER="${OUTSIDER:-outsider-nobody.testnet}"
TOKEN="${TOKEN:-usdc.fakes.testnet}"
PER_TX_NATIVE="2000000000000000000000"       # 0.002 NEAR
UNDER="500000000000000000000"                # 0.0005 NEAR
OVER="250000000000000000000000000"           # 250 NEAR — their spec example

# The BOUND ACCOUNT ITSELF is in the whitelist, and it has to be: see A0 below.
log "Policy for this suite: whitelist [$WL, $TOKEN, $ASSET], per-transaction native $PER_TX_NATIVE"
POL=$(jq -nc --arg w "$WL" --arg t "$TOKEN" --arg s "$ASSET" --arg l "$PER_TX_NATIVE" \
  '{rules:{addresses:{mode:"whitelist",list:[$w,$t,$s]},limits:{per_transaction:{native:$l}}}}')
store_policy "$SEED" "$WALLET_ID" "$POL" || { echo "✗ policy not stored — nothing below is judgeable" >&2; exit 1; }

# send <desc> <envelope-json> — one lane call; leaves HTTP/BODY set.
send() { log "$1"; call_ext "$SEED" "$ASSET" "$2" >/dev/null; }
send_raw() { log "$1"; call_ext_raw "$SEED" "$ASSET" "$2" >/dev/null; }

# ── D0 negative control: the lane is OPEN for what the policy permits ────────
send "D0 control — 0.0005 NEAR to the whitelisted $WL" "$(ext_transfer "$WL" "$UNDER")"
if [[ "$HTTP" == "200" ]]; then
  pass "D0 the permitted transfer executed ($(jq -r '.status' <<<"$BODY"), tx $(jq -r '.tx_hash // "-"' <<<"$BODY" | head -c 12)…) — every refusal below is a refusal OF SOMETHING"
else
  fail "D0 the permitted transfer was refused (HTTP $HTTP): $(msg_of) — the suite cannot tell a working rule from a closed door"
fi

# ── A0 the door is a destination to the address filter ──────────────────────
#
# Run only when the suite is asked for it (it costs a second policy write), and
# reported as a FINDING rather than a failure: nothing here is unsafe, but a
# partner who whitelists the accounts they intend to PAY gets a lane that
# refuses everything, and the sentence blames an account they never listed as a
# destination — it is the door, not a payee.
if [[ -n "${WITH_A0:-}" ]]; then
  POL_NO_DOOR=$(jq -nc --arg w "$WL" --arg t "$TOKEN" --arg l "$PER_TX_NATIVE" \
    '{rules:{addresses:{mode:"whitelist",list:[$w,$t]},limits:{per_transaction:{native:$l}}}}')
  if store_policy "$SEED" "$WALLET_ID" "$POL_NO_DOOR"; then
    send "A0 the same permitted transfer, with the BOUND ACCOUNT left out of the whitelist" "$(ext_transfer "$WL" "$UNDER")"
    # The refusal is DELIBERATE: after the decoded effects pass, the op
    # continues through the scalar gates, and there the destination is the outer
    # receiver. What is asserted is that the sentence SAYS so — an owner who
    # listed only real payees is otherwise sent to audit a correct list over an
    # account they never asked to pay.
    if [[ "$HTTP" == "200" ]]; then
      pass "A0 the address filter ignores the outer receiver — only the destinations the owner named are filtered"
    else
      assert_msg "A0 the refusal explains that the OUTER destination is judged too" "outer destination" \
        || note "  got: $(msg_of | head -c 180)"
    fi
    store_policy "$SEED" "$WALLET_ID" "$POL" >/dev/null || warn "could not restore the suite policy"
  else
    skip "A0 — the no-door policy could not be stored"
  fi
fi

# ── D1 the decoder reads BOTH promises and the nested amounts ────────────────
ENV=$(jq -nc --arg w "$WL" --arg o "$OUTSIDER" --arg u "$UNDER" --arg v "$OVER" \
  '{request:{external:[
     {receiver_id:$w, actions:[{action:"transfer",payload:{amount:$u}}]},
     {receiver_id:$o, actions:[{action:"transfer",payload:{amount:$v}}]}]}}')
send "D1 their spec example: a permitted promise plus 250 NEAR to an outsider" "$ENV"
assert_denied "D1 refused" "policy_denied" \
  && assert_msg "D1 names the second promise's outsider" "$OUTSIDER"

# ── D2 unknown action VARIANT fails closed ──────────────────────────────────
ENV=$(jq -nc --arg o "$OUTSIDER" '{request:{external:[{receiver_id:$o, actions:[{action:"delegate",payload:{amount:"1"}}]}]}}')
send "D2 unknown action variant 'delegate' (aimed at an address the policy also refuses)" "$ENV"
if assert_denied "D2 refused"; then
  if grep -qi "not permitted by the address rules" <<<"$BODY"; then
    fail "D2 refused by the ADDRESS rule — the unknown variant was decoded away instead of failing the decode"
  else
    pass "D2 the DECODE refused it, before any rule saw a destination: $(msg_of | head -c 140)"
  fi
fi

# ── D3 unknown FIELD in a known variant is accepted (serde default upstream) ─
ENV=$(jq -nc --arg o "$OUTSIDER" --arg u "$UNDER" \
  '{request:{external:[{receiver_id:$o, unknown_promise_field:1, actions:[{action:"transfer",payload:{amount:$u, unknown_payload_field:"x"}}]}]}}')
send "D3 unknown FIELDS inside known variants — must decode, then be judged by the rules" "$ENV"
if assert_denied "D3 refused (its destination is an outsider)"; then
  grep -qi "not permitted by the address rules" <<<"$BODY" \
    && pass "D3 the address rule spoke — additive upstream fields do not false-refuse" \
    || fail "D3 refused by the decode, not by the address rule: a minor upstream addition would break every request: $(msg_of | head -c 160)"
fi

# ── D4–D6 malformed args ────────────────────────────────────────────────────
# Each of these names the DECODER as the layer that spoke, not merely "a 4xx".
# Malformed args have several ways to be refused later — an address rule, a type
# gate, a limit — and any of them would keep these probes green while the decode
# had started accepting garbage and passing it on.
send_raw "D4 args_base64 that is not base64 at all" '!!!not base64!!!'
assert_denied "D4 refused" && assert_msg "D4 the decode spoke, naming base64" "not valid base64"
send_raw "D5 valid base64 that is not JSON" "$(b64 'this is not json')"
assert_denied "D5 refused" && assert_msg "D5 the decode spoke, naming the parse" "do not parse"
send_raw "D6 truncated JSON" "$(b64 '{"request":{"external":[{"receiver_id":"a.testnet","actions":[')"
assert_denied "D6 refused" && assert_msg "D6 the decode spoke, naming the parse" "do not parse"
send_raw "D7 JSON without the 'request' envelope at all" "$(b64 '{"external":[]}')"
assert_denied "D7 refused — 'request' is not defaulted" \
  && assert_msg "D7 the decode spoke: the envelope has no default" "do not parse"

# ── D8 deeply nested JSON: the parser refuses, the enclave does not fall over ─
DEEP=$(python3 -c 'print("{\"request\":{\"external\":" + "["*2000 + "]"*2000 + "}}")')
send_raw "D8 2000-deep nested JSON" "$(b64 "$DEEP")"
if [[ "$HTTP" =~ ^[45] ]]; then
  [[ "$HTTP" =~ ^4 ]] \
    && pass "D8 refused as a bad request (HTTP $HTTP) — a parser limit, not a crash" \
    || fail "D8 answered $HTTP: nesting reached something that failed as a server error"
else
  fail "D8 was NOT refused (HTTP $HTTP) — deep nesting passed the decoder"
fi

# ── D9 hostile amounts: saturate or refuse, never panic ─────────────────────
U128_MAX="340282366920938463463374607431768211455"
for pair in \
  "u128::MAX|$U128_MAX" \
  "u128::MAX+1|340282366920938463463374607431768211456" \
  "negative|-1" \
  "float-exponent|1e30" \
  "arabic-indic digits|٢٥٠" \
  "empty string|"
do
  name=${pair%%|*}; amt=${pair#*|}
  ENV=$(jq -nc --arg w "$WL" --arg a "$amt" '{request:{external:[{receiver_id:$w, actions:[{action:"transfer",payload:{amount:$a}}]}]}}')
  send "D9 hostile native amount — $name" "$ENV"
  if [[ "$HTTP" =~ ^4 ]]; then
    pass "D9 [$name] refused $HTTP: $(msg_of | head -c 110)"
  elif [[ "$HTTP" =~ ^5 ]]; then
    fail "D9 [$name] answered $HTTP — a hostile amount reached a server error; this is the enclave-DoS class"
  else
    fail "D9 [$name] was ACCEPTED (HTTP $HTTP) — an amount no rule can measure went through"
  fi
done

# `+250` is the one hostile-looking spelling that is NOT hostile: Rust's
# `u128::from_str` accepts a leading plus, and upstream's `NearToken` parses the
# string with the same function — so the chain reads it as 250 too. The rule to
# check is therefore not "refuse it" but "measure it", and the way to see that
# it was measured is to put it over a limit.
ENV=$(jq -nc --arg w "$WL" '{request:{external:[{receiver_id:$w, actions:[{action:"transfer",payload:{amount:"+250000000000000000000000000"}}]}]}}')
send "D9 a leading plus on an amount ABOVE the per-transaction cap" "$ENV"
if [[ "$HTTP" == "403" ]] && grep -qE "Per-transaction|limit" <<<"$BODY"; then
  pass "D9 [leading plus] measured, not waved through: $(msg_of | head -c 110)"
elif [[ "$HTTP" =~ ^5 ]]; then
  fail "D9 [leading plus] answered $HTTP — the enclave-DoS class"
else
  fail "D9 [leading plus] answered $HTTP: an amount the parser accepts must still be METERED — $(msg_of | head -c 140)"
fi

# gas is the other unbounded numeric field
ENV=$(jq -nc --arg w "$WL" --arg g "$U128_MAX" \
  '{request:{external:[{receiver_id:$w, actions:[{action:"function_call",payload:{function_name:"noop",args:"",deposit:"0",gas:$g}}]}]}}')
send "D9 hostile gas — u128::MAX on a function call" "$ENV"
[[ "$HTTP" =~ ^4 ]] && pass "D9 [gas] refused $HTTP: $(msg_of | head -c 110)" \
  || fail "D9 [gas] answered $HTTP — expected a refusal"

# ── D10 unstatable calls fall into unknown_fund_moving ──────────────────────
ENV=$(jq -nc --arg t "$TOKEN" --arg w "$WL" \
  --arg a "$(printf '{"receiver_id":"%s","amount":"1","msg":"anything"}' "$WL" | base64 | tr -d '\n')" \
  '{request:{external:[{receiver_id:$t, actions:[{action:"function_call",payload:{function_name:"ft_transfer_call",args:$a,deposit:"1",gas:"30000000000000"}}]}]}}')
send "D10 ft_transfer_call — its msg reaches a third contract that can move value the args do not state" "$ENV"
assert_denied "D10 refused" && assert_msg "D10 says the effects cannot be stated" "cannot state the effects|unknown"

ENV=$(jq -nc --arg t "$TOKEN" '{request:{external:[{receiver_id:$t, actions:[{action:"function_call",payload:{function_name:"mystery_method",args:"",deposit:"2",gas:"30000000000000"}}]}]}}')
send "D11 an unknown method carrying a deposit above the 1-yocto marker" "$ENV"
assert_denied "D11 refused" && assert_msg "D11 says the effects cannot be stated" "cannot state the effects|unknown"

# ── R2 the limit measures what MOVES, not the marker ────────────────────────
ENV=$(ext_transfer "$WL" "$OVER")
send "R2 250 NEAR hidden in args, 1 yocto on the outside, destination permitted" "$ENV"
if assert_denied "R2 refused" "policy_denied"; then
  grep -qE "250000000000000000000000000|Per-transaction|limit" <<<"$BODY" \
    && pass "R2 the per-transaction limit was measured against the NESTED amount, not the marker" \
    || fail "R2 refused for another reason: $(msg_of | head -c 180)"
fi

ENV=$(jq -nc --arg w "$WL" --arg u "$UNDER" \
  '{request:{external:[
     {receiver_id:$w, actions:[{action:"transfer",payload:{amount:$u}}]},
     {receiver_id:$w, actions:[{action:"transfer",payload:{amount:$u}}]},
     {receiver_id:$w, actions:[{action:"transfer",payload:{amount:$u}}]},
     {receiver_id:$w, actions:[{action:"transfer",payload:{amount:$u}}]},
     {receiver_id:$w, actions:[{action:"transfer",payload:{amount:$u}}]}]}}')
send "R2-aggregate five permitted 0.0005 NEAR promises — 0.0025 total against a 0.002 cap" "$ENV"
assert_denied "R2-aggregate refused — one request is one atomic object, splitting a payment does not split the rule" "policy_denied"

# ── R3 the rule follows the LOGICAL recipient of a token move ───────────────
FT_ARGS=$(printf '{"receiver_id":"%s","amount":"1"}' "$OUTSIDER")
ENV=$(jq -nc --arg t "$TOKEN" --arg a "$(printf '%s' "$FT_ARGS" | base64 | tr -d '\n')" \
  '{request:{external:[{receiver_id:$t, actions:[{action:"function_call",payload:{function_name:"ft_transfer",args:$a,deposit:"1",gas:"30000000000000"}}]}]}}')
send "R3 ft_transfer through the PERMITTED token contract to a NON-permitted recipient" "$ENV"
assert_denied "R3 refused" "policy_denied" \
  && assert_msg "R3 names the decoded recipient, not the contract" "$OUTSIDER"

# ── R3' refund_to is a destination too ─────────────────────────────────────
send "R3' refund_to pointing at an outsider (a failed promise's deposit goes there)" "$(ext_transfer "$WL" "$UNDER" "$OUTSIDER")"
assert_denied "R3' refused" "policy_denied" && assert_msg "R3' names refund_to" "refund_to|$OUTSIDER"

# ── R4 internal operations are hard-denied under ANY policy ────────────────
for op in add_extension remove_extension; do
  ENV=$(jq -nc --arg o "$op" --arg e "$EXECUTOR" '{request:{internal:[{op:$o,payload:{account_id:$e}}]}}')
  send "R4 internal '$op' through the spending lane" "$ENV"
  assert_denied "R4 [$op] refused" "policy_denied" \
    && assert_msg "R4 [$op] says the lane only spends" "internal|never rewires|control"
done
ENV=$(jq -nc '{request:{internal:[{op:"set_signature_mode",payload:{enable:true}}]}}')
send "R4 internal 'set_signature_mode'" "$ENV"
assert_denied "R4 [set_signature_mode] refused" "policy_denied" \
  && assert_msg "R4 [set_signature_mode] says the lane only spends" "internal|never rewires|control"

# mixed: one legal promise carrying an internal op alongside it
ENV=$(jq -nc --arg w "$WL" --arg u "$UNDER" --arg e "$EXECUTOR" \
  '{request:{internal:[{op:"add_extension",payload:{account_id:$e}}], external:[{receiver_id:$w, actions:[{action:"transfer",payload:{amount:$u}}]}]}}')
send "R4 an internal op smuggled alongside a perfectly legal transfer" "$ENV"
# The message matters MOST here. The transfer beside the smuggled op is legal, so
# a refusal for any other reason — a drifted whitelist, a limit — would keep this
# probe green while `add_extension` was no longer hard-denied at all.
assert_denied "R4 [mixed] refused — a legal promise does not launder an illegal one" "policy_denied" \
  && assert_msg "R4 [mixed] and the ACCOUNT-CONTROL rule is the one that spoke" "internal|never rewires|control"

verdict "§3 decoder + core policy"
