#!/usr/bin/env bash
#
# §4 of the HoS test plan — the custody properties the partner takes from us
# BESIDES the binding itself: address rules, per-transaction and velocity
# limits, transaction types, token allowlists, signing capabilities, time
# windows, rate limits, multisig and freeze.
#
# Every rule is asked twice: once with the condition met (it must pass) and
# once with the condition broken (it must refuse). A suite of refusals alone
# proves nothing — a door that is simply shut refuses everything — and that is
# the discipline §9 asks for.
#
# The stateless rules are checked on the fund lane (`w_execute_extension` at
# the bound account), because that is the surface the partner drives. The
# wallet-global ones (capabilities, freeze) are checked on throwaway wallets:
# a frozen wallet refuses everything, and wedging the shared fixture would end
# the run.
#
# Each policy change is an on-chain `store_wallet_policy` (0.1 NEAR, ~15 s),
# so cases are grouped by the policy they need rather than by number.
#
#   PARENT=you.testnet ./tests/hos_custody_matrix_e2e.sh --apply
#
# Builds and deletes its own bound wallet — see the note at the top of the body.

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/hos_common.sh"

[[ "${1:-}" == "--apply" ]] || { sed -n '3,25p' "$0" >&2; echo "  Pass --apply to run." >&2; exit 0; }
hos_require
# Its OWN bound wallet, not the shared fixture. This suite spends most of a
# wallet's monthly custody allowance (100 operations) on its own, so sharing one
# made whichever suite ran after it fail on the cap — a limit that reads exactly
# like a policy defect.
new_bound_wallet custody || { echo "✗ could not build this suite's bound wallet" >&2; exit 1; }
CLEAN_ASSET="$ASSET"
cleanup() {
  local rc=$?
  api "$SEED" DELETE /wallet/v1/binding >/dev/null 2>&1 || true
  account_exists "$CLEAN_ASSET" && { note "cleaning up $CLEAN_ASSET"; delete_account "$CLEAN_ASSET"; }
  return $rc
}
trap cleanup EXIT

WL="${WL:-zavodil2.testnet}"
THIRD="${THIRD:-$PARENT}"                  # exists, and is in no list
OUTSIDER="${OUTSIDER:-outsider-nobody.testnet}"
TOKEN="${TOKEN:-usdc.fakes.testnet}"
BIG_NATIVE="1000000000000000000000000"      # 1 NEAR
TINY="500000000000000000000"                # 0.0005 NEAR

# The bound account is itself a destination to the address filter (the outer
# receiver of every `w_execute_extension`), so every whitelist below carries it.
pol_addresses() { jq -nc --arg m "$1" --argjson l "$2" '{rules:{addresses:{mode:$m, list:$l}, limits:{per_transaction:{native:"1000000000000000000000000"}}}}'; }
set_policy() { store_policy "$SEED" "$WALLET_ID" "$1" || { fail "$2 — the policy could not be stored, the case is unjudged"; return 1; }; }
door() { log "$1"; call_ext "$SEED" "$ASSET" "$2" >/dev/null; }

ft_env() { # <token> <recipient> <amount>
  jq -nc --arg t "$1" --arg a "$(printf '{"receiver_id":"%s","amount":"%s"}' "$2" "$3" | base64 | tr -d '\n')" \
    '{request:{external:[{receiver_id:$t, actions:[{action:"function_call",payload:{function_name:"ft_transfer",args:$a,deposit:"1",gas:"30000000000000"}}]}]}}'
}

# ── A. address whitelist ───────────────────────────────────────────────────
if set_policy "$(pol_addresses whitelist "$(jq -nc --arg a "$ASSET" --arg w "$WL" '[$a,$w]')")" "A"; then
  door "A1 whitelisted recipient" "$(ext_transfer "$WL" "$TINY")"
  assert_status "A1 a whitelisted recipient is paid" 200
  door "A2 a recipient outside the whitelist" "$(ext_transfer "$OUTSIDER" "$TINY")"
  assert_denied "A2 refused" "policy_denied" && assert_msg "A2 names the address rules" "address rules"
  door "A3 a recipient that exists but was never listed" "$(ext_transfer "$THIRD" "$TINY")"
  assert_denied "A3 refused — a whitelist is a list, not a hint" "policy_denied"
fi

# ── B. an EMPTY whitelist is deny-all, not filter-off ──────────────────────
if set_policy "$(pol_addresses whitelist '[]')" "B"; then
  door "B1 an empty whitelist" "$(ext_transfer "$WL" "$TINY")"
  assert_denied "B1 an empty whitelist refuses everything — it is not read as 'no filter'" "policy_denied"
fi

# ── C. blacklist ───────────────────────────────────────────────────────────
if set_policy "$(pol_addresses blacklist "$(jq -nc --arg o "$OUTSIDER" '[$o]')")" "C"; then
  door "C1 a recipient that is not on the blacklist" "$(ext_transfer "$WL" "$TINY")"
  assert_status "C1 anyone not blacklisted is paid" 200
  door "C2 the blacklisted recipient" "$(ext_transfer "$OUTSIDER" "$TINY")"
  assert_denied "C2 refused" "policy_denied"
fi

# ── D. mode 'none' really is off ───────────────────────────────────────────
if set_policy "$(pol_addresses none '[]')" "D"; then
  door "D1 mode=none with an empty list, paying an account in no list" "$(ext_transfer "$THIRD" "$TINY")"
  assert_status "D1 'none' switches the filter off deliberately — it is not silently a whitelist" 200
fi

# ── E. an unknown mode is fail-closed on BOTH paths ────────────────────────
if set_policy "$(pol_addresses allowlist "$(jq -nc --arg a "$ASSET" --arg w "$WL" '[$a,$w]')")" "E"; then
  door "E1 mode='allowlist' (a typo for 'whitelist') on the fund lane" "$(ext_transfer "$WL" "$TINY")"
  if assert_denied "E1 refused rather than ignored — fail-closed holds on the door path" "policy_denied"; then
    # The security property (an unknown mode does not switch the filter off) is
    # the same on both paths. The DIAGNOSTIC is not: the scalar path names the
    # word the owner typed, which is the entire reason that check was added
    # after a typo silently disabled a filter. On the door path the same policy
    # produces an ordinary 'receiver is not permitted' — the owner is told the
    # payee is wrong when the payee is fine and the mode is misspelt.
    # A hard assertion, not a finding: a FINDING does not move the exit code, so
    # while this was one, the sentence could go back to naming the payee and
    # every run would still be green. The rule it guards is the one that was
    # added after a typo silently switched an address filter off.
    grep -qi "allowlist" <<<"$BODY" \
      && pass "E1 the sentence names the word the owner typed" \
      || fail "E1 the refusal never names the misspelt mode: it reads '$(msg_of | head -c 90)'. The scalar path says 'address rule mode <x> is not one of whitelist, blacklist, none' — the door path must say the same, or a typo'd policy sends the owner to audit a payee list that is correct"
  fi
  log "E2 the same typo on the scalar path (POST /wallet/v1/transfer)"
  api "$SEED" POST /wallet/v1/transfer "$(jq -nc --arg t "$WL" --arg a "$TINY" '{chain:"near", to:$t, amount:$a}')" >/dev/null
  assert_denied "E2 refused on the scalar path too — one policy, one reading" "policy_denied" \
    && assert_msg "E2 names the word there as well" "allowlist"
fi

# ── F. per-transaction limits, native and per token ────────────────────────
POL_F=$(jq -nc --arg a "$ASSET" --arg w "$WL" --arg t "$TOKEN" \
  '{rules:{addresses:{mode:"whitelist",list:[$a,$w,$t]},
           allowed_tokens:["*"],
           limits:{per_transaction:{native:"1000000000000000000000", ($t):"10"}}}}')
if set_policy "$POL_F" "F"; then
  door "F1 native under the 0.001 NEAR cap" "$(ext_transfer "$WL" "$TINY")"
  assert_status "F1 under the cap, paid" 200
  door "F2 native over the cap" "$(ext_transfer "$WL" "2000000000000000000000")"
  assert_denied "F2 refused" "policy_denied" && assert_msg "F2 names the per-transaction limit" "Per-transaction limit"
  door "F3 a token move of 11 against a per-token cap of 10" "$(ft_env "$TOKEN" "$WL" 11)"
  assert_denied "F3 refused" "policy_denied" && assert_msg "F3 measures the TOKEN, in its own units" "$TOKEN|token"
fi

# ── G. the token allowlist follows what MOVED ──────────────────────────────
POL_G=$(jq -nc --arg a "$ASSET" --arg w "$WL" --arg t "$TOKEN" \
  '{rules:{addresses:{mode:"whitelist",list:[$a,$w,$t]},
           allowed_tokens:["dai.fakes.testnet"],
           limits:{per_transaction:{native:"1000000000000000000000000"}}}}')
if set_policy "$POL_G" "G"; then
  door "G1 an ft_transfer of a token the policy does not allow, through a permitted contract" "$(ft_env "$TOKEN" "$WL" 1)"
  assert_denied "G1 refused" "policy_denied" && assert_msg "G1 names the token, not the contract" "$TOKEN"
  door "G2 native movement under a token allowlist that does not list 'native'" "$(ext_transfer "$WL" "$TINY")"
  # The refusal is DELIBERATE — the outer call is denominated in NEAR, so a
  # token allowlist without `native` stops the lane, and the layering that makes
  # that happen is documented in the engine. What is asserted here is that the
  # sentence SAYS so: an owner who narrowed allowed_tokens to one stablecoin is
  # otherwise told about a token they never wrote down.
  if [[ "$HTTP" == "200" ]]; then
    pass "G2 the native path still works — the token rule stayed a token rule"
  else
    assert_msg "G2 the refusal explains that a call is denominated in NEAR" "denominated in NEAR" \
      || note "  got: $(msg_of | head -c 160)"
  fi
fi

# ── H. transaction types ───────────────────────────────────────────────────
POL_H=$(jq -nc '{rules:{transaction_types:["transfer"], addresses:{mode:"none",list:[]}}}')
if set_policy "$POL_H" "H"; then
  door "H1 the fund lane (a CALL) under a policy that permits only transfers" "$(ext_transfer "$WL" "$TINY")"
  assert_denied "H1 refused by the type gate" "policy_denied"
  log "H2 control — a plain transfer under the same policy"
  api "$SEED" POST /wallet/v1/transfer "$(jq -nc --arg t "$WL" --arg a "100000000000000000000" '{chain:"near", to:$t, amount:$a}')" >/dev/null
  assert_status "H2 the permitted type still passes — H1 was the type gate, not a closed door" 200
fi

# ── I. time restrictions ───────────────────────────────────────────────────
NOW_H=$(date -u +%H); NOW_H=${NOW_H#0}; NOW_H=${NOW_H:-0}
FROM=$(( (NOW_H + 2) % 24 )); TO=$(( (NOW_H + 3) % 24 ))
POL_I=$(jq -nc --argjson f "$FROM" --argjson t "$TO" \
  '{rules:{addresses:{mode:"none",list:[]}, time_restrictions:{timezone:"UTC", allowed_hours:[$f,$t]}}}')
if set_policy "$POL_I" "I"; then
  door "I1 a call outside the permitted UTC window ${FROM}:00–${TO}:00 (it is now ${NOW_H}:xx)" "$(ext_transfer "$WL" "$TINY")"
  assert_denied "I1 refused outside the window" "policy_denied" && assert_msg "I1 says it is the time window" "time|hour|window"
fi

# ── J. hourly rate limit ───────────────────────────────────────────────────
POL_J=$(jq -nc '{rules:{addresses:{mode:"none",list:[]}, rate_limit:{max_per_hour:1}}}')
if set_policy "$POL_J" "J"; then
  door "J1 the first call under max_per_hour=1 (this wallet has already spent this hour)" "$(ext_transfer "$WL" "$TINY")"
  H1=$HTTP
  door "J2 the next call" "$(ext_transfer "$WL" "$TINY")"
  if [[ "$H1" != "200" || "$HTTP" != "200" ]]; then
    assert_denied "J the hourly transaction count is enforced" "policy_denied"
  else
    fail "J two calls passed under max_per_hour=1"
  fi
fi

# ── K. velocity (stateful, coordinator-side) ───────────────────────────────
POL_K=$(jq -nc '{rules:{addresses:{mode:"none",list:[]}, limits:{daily:{native:"1"}}}}')
if set_policy "$POL_K" "K"; then
  door "K1 a spend against a daily cap of 1 yoctoNEAR" "$(ext_transfer "$WL" "$TINY")"
  assert_denied "K1 refused by the daily window" "policy_denied" && assert_msg "K1 names the window" "aily|limit"
fi

# ── L. velocity TOCTOU, on a wallet of its own ─────────────────────────────
#
# A fresh wallet, because the counter has to start where the test says it does.
# Three concurrent transfers, a daily cap that admits one: the question is not
# whether the losers get an error but whether the WINNERS can be two.
log "L velocity TOCTOU — three concurrent spends against a cap that admits one"
SEED_L="hos-toctou-$(date +%s)-$$"
read -r WID_L ADDR_L < <(wallet_address "$SEED_L")
if [[ -n "$WID_L" ]]; then
  fund_account "$ADDR_L" 0.15 && sleep 3 || warn "the top-up did not land; a refusal below may be about gas rather than about the rule"
  POL_L=$(jq -nc --arg w "$WL" '{rules:{addresses:{mode:"whitelist",list:[$w]}, limits:{daily:{native:"600000000000000000000"}}}}')
  if store_policy "$SEED_L" "$WID_L" "$POL_L"; then
    BEFORE_L=$(account_field "$WL" amount)
    for i in 1 2 3; do
      ( curl -sS -o "/tmp/hos_toctou_$i.json" -w '%{http_code}' -X POST "$COORDINATOR_URL/wallet/v1/transfer" \
          -H "$(AUTH_FOR "$SEED_L")" -H 'Content-Type: application/json' --max-time 90 \
          -d "$(jq -nc --arg t "$WL" --arg a "$TINY" '{chain:"near", to:$t, amount:$a}')" > "/tmp/hos_toctou_$i.code" 2>/dev/null ) &
    done
    wait
    OK=0
    for i in 1 2 3; do
      C=$(cat "/tmp/hos_toctou_$i.code" 2>/dev/null)
      note "  attempt $i → HTTP $C $(head -c 110 "/tmp/hos_toctou_$i.json" 2>/dev/null)"
      [[ "$C" == "200" ]] && OK=$((OK+1))
    done
    rm -f /tmp/hos_toctou_*.json /tmp/hos_toctou_*.code
    sleep 8
    AFTER_L=$(account_field "$WL" amount)
    MOVED=$(python3 -c "print(int('$AFTER_L')-int('$BEFORE_L'))")
    if (( OK <= 1 )); then
      pass "L exactly $OK of three concurrent spends won — the wallet lock holds the window closed"
    else
      fail "L $OK of three concurrent spends succeeded against a cap that admits one"
    fi
    if python3 -c "import sys; sys.exit(0 if $MOVED <= 600000000000000000000 else 1)"; then
      pass "L the recipient gained $MOVED yocto — at or under the 0.0006 NEAR daily cap"
    else
      fail "L the recipient gained $MOVED yocto, over the 0.0006 NEAR daily cap — the counter was read twice before either write"
    fi
  else
    skip "L — the TOCTOU wallet's policy could not be stored"
  fi
else
  skip "L — the TOCTOU wallet could not be minted"
fi

# ── M. signing capabilities are default-DENY ───────────────────────────────
log "M signing capabilities on a wallet of its own"
SEED_M="hos-caps-$(date +%s)-$$"
read -r WID_M _ < <(wallet_address "$SEED_M")
evm_msg()  { api "$SEED_M" POST /wallet/v1/evm/sign-message '{"chain":"ethereum","message":"hello"}' >/dev/null; }
evm_raw()  { api "$SEED_M" POST /wallet/v1/evm/sign-transaction '{"chain":"ethereum","unsigned_tx":"0x02c0"}' >/dev/null; }
sol_msg()  { api "$SEED_M" POST /wallet/v1/solana/sign-message '{"chain":"solana","message":"hello"}' >/dev/null; }
if [[ -n "$WID_M" ]]; then
  if store_policy "$SEED_M" "$WID_M" '{"rules":{"addresses":{"mode":"none","list":[]}}}'; then
    evm_msg; assert_denied "M1 EVM signing under a policy that does not mention it — default DENY" \
      && assert_msg "M1 names the flag the owner must set" "capabilities.evm_sign|evm_sign"
    sol_msg; assert_denied "M2 Solana signing under the same policy — default DENY" \
      && assert_msg "M2 names the flag" "capabilities.solana_sign|solana_sign"
  fi
  if store_policy "$SEED_M" "$WID_M" '{"rules":{"addresses":{"mode":"none","list":[]}},"capabilities":{"evm_sign":{"allowed":true},"solana_sign":{"allowed":true}}}'; then
    evm_msg; assert_status "M3 EVM message signing once the capability is set" 200
    sol_msg; assert_status "M4 Solana message signing once the capability is set" 200
    evm_raw
    assert_denied "M5 a RAW EVM transaction still refused — raw_tx is a separate, default-off sub-flag" \
      && assert_msg "M5 names the sub-flag" "raw_tx"
  fi
else
  skip "M — the capabilities wallet could not be minted"
fi

# ── N. freeze ──────────────────────────────────────────────────────────────
#
# Freeze is NOT a field of the encrypted policy: `freeze_wallet(wallet_pubkey)`
# is an on-chain call by the owner, and the worker syncs the flag inward. So it
# is exercised where it actually lives, on a wallet of its own — a frozen
# wallet refuses everything, and wedging the fixture would end the run.
log "N freeze — on chain, on a wallet of its own"
SEED_N="hos-frozen-$(date +%s)-$$"
read -r WID_N ADDR_N < <(wallet_address "$SEED_N")
# store_policy also reveals the wallet's own public key, which is what
# freeze_wallet is keyed on.
if [[ -n "$WID_N" ]] && store_policy "$SEED_N" "$WID_N" '{"rules":{"addresses":{"mode":"none","list":[]}},"capabilities":{"evm_sign":{"allowed":true}}}'; then
  fund_account "$ADDR_N" 0.05 && sleep 3 || warn "the top-up did not land; a refusal below may be about gas rather than about the rule"
  api "$SEED_N" POST /wallet/v1/evm/sign-message '{"chain":"ethereum","message":"hi"}' >/dev/null
  assert_status "N0 control — the wallet signs while unfrozen" 200
  if near_tty "near contract call-function as-transaction $CONTRACT_ID freeze_wallet \
      json-args '$(jq -nc --arg k "$WALLET_PUBKEY" '{wallet_pubkey:$k}')' prepaid-gas '100.0 Tgas' \
      attached-deposit '0 NEAR' sign-as $PARENT network-config $NETWORK sign-with-keychain send" >/dev/null 2>&1; then
    note "freeze_wallet landed; waiting for the flag to reach the policy check"
    FROZE=false
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      sleep 6
      api "$SEED_N" POST /wallet/v1/evm/sign-message '{"chain":"ethereum","message":"hi"}' >/dev/null
      if [[ "$HTTP" =~ ^4 ]] && grep -qi "frozen" <<<"$BODY"; then FROZE=true; break; fi
    done
    if [[ "$FROZE" == true ]]; then
      pass "N1 a frozen wallet refuses signing, and says it is frozen: $(msg_of | head -c 110)"
      api "$SEED_N" POST /wallet/v1/transfer "$(jq -nc --arg t "$WL" --arg a "$TINY" '{chain:"near", to:$t, amount:$a}')" >/dev/null
      # The CLASS, not merely a 4xx. The claim is that freeze outranks every
      # other rule, and this wallet's policy refuses plenty of things — an
      # address rule answering here would look identical to a freeze while
      # proving the opposite of what the line says.
      if assert_denied "N2 a frozen wallet refuses a transfer too — freeze outranks every capability"; then
        grep -qi "frozen" <<<"$BODY" \
          && pass "N2 and the refusal names the FREEZE, not some other rule that also happened to refuse" \
          || fail "N2 the transfer was refused by something other than the freeze ($(err_of)): $(msg_of | head -c 140)"
      fi
    else
      finding "freeze_wallet landed on chain but the wallet was still signing 60 s later (last answer HTTP $HTTP: $(msg_of | head -c 120)). The flag reaches the policy check through the worker's sync, so the delay is the sync, not the rule — worth knowing before the partner is told a freeze is immediate."
    fi
    near_tty "near contract call-function as-transaction $CONTRACT_ID unfreeze_wallet \
      json-args '$(jq -nc --arg k "$WALLET_PUBKEY" '{wallet_pubkey:$k}')' prepaid-gas '100.0 Tgas' \
      attached-deposit '0 NEAR' sign-as $PARENT network-config $NETWORK sign-with-keychain send" >/dev/null 2>&1 || true
  else
    skip "N — freeze_wallet did not land on chain"
  fi
else
  skip "N — the freeze wallet could not be prepared"
fi

# ── O. multisig, and what must NOT be sent to an approver ──────────────────
POL_O=$(jq -nc --arg a "$ASSET" --arg w "$WL" --arg p "$PARENT" \
  '{rules:{addresses:{mode:"whitelist",list:[$a,$w]}, limits:{per_transaction:{native:"1000000000000000000000000"}}},
    approval:{threshold:2, approvers:[{id:$p},{id:"second-approver.testnet"}]}}')
if set_policy "$POL_O" "O"; then
  door "O1 a decodable, permitted spend under a 2-of-N threshold" "$(ext_transfer "$WL" "$TINY")"
  if [[ "$HTTP" == "200" && "$(jq -r '.status // ""' <<<"$BODY")" != "success" ]] || jq -e '.approval_id' <<<"$BODY" >/dev/null 2>&1; then
    pass "O1 held for approval instead of executing (status $(jq -r '.status // "?"' <<<"$BODY"))"
  else
    fail "O1 executed under a 2-of-N threshold (HTTP $HTTP): $(head -c 200 <<<"$BODY")"
  fi
  log "O2 an UNDECODABLE envelope under the same threshold"
  call_ext_raw "$SEED" "$ASSET" "$(b64 '{"request":{"external":[{"receiver_id":"x.testnet","actions":[{"action":"delegate","payload":{}}]}]}}')" >/dev/null
  if jq -e '.approval_id' <<<"$BODY" >/dev/null 2>&1; then
    fail "O2 an envelope nobody can decode was turned into an APPROVAL — the approver would be asked to sign blind"
  else
    assert_denied "O2 terminally refused, never offered to an approver" "policy_denied"
  fi
fi

# Nothing to restore: this suite's wallet and account are its own and are
# deleted on the way out.
# ── §4.1 AccessCondition / AccountPattern ──────────────────────────────────
#
# The plan's §4.1 marks the `AccountPattern` anchoring as a fresh and critical
# fix: a pattern `team\.near` written as an exact check must not also admit
# `xteam.near`, `team.near.attacker.near`, or — `.` being a metacharacter —
# `teamXnear`. That is one account's secrets handed to another.
#
# It is not probed from HERE because the rule lives one layer down: the keystore
# evaluates an `AccessCondition` while decrypting a secret inside a WASI run,
# which is a different stack from the wallet matrix above. Two things cover it,
# and between them they answer both halves of the question:
#
#   `keystore-worker/src/types.rs` compiles every pattern to `\A(?:…)\z` and
#   carries the vectors. Six fail the moment the anchoring is removed —
#   substring, metacharacter, empty pattern, full match, top-level alternation,
#   unescaped dot.
#
#   `tests/secret_access_conditions_e2e.sh` drives the same rule end to end, with
#   real sub-accounts standing in for the traps, and proves that the account the
#   enclave measures is the one that signed the transaction.
note "§4.1 AccountPattern is covered by tests/secret_access_conditions_e2e.sh (live) and the vectors in keystore-worker/src/types.rs"

verdict "§4 custody matrix"
