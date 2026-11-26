#!/usr/bin/env bash
#
# §3.1 + §0′ of the HoS test plan — the `hos_lease` profile against the PARTNER'S
# REAL leased account, not the stub.
#
# `hos_lease_stub_e2e.sh` proves our side agrees with the SHAPE and RULES of
# their view, in the order their contract checks them, by serving a
# `hos_agent_status` we control. This proves the last line the stub cannot: that
# our pre-flight and THEIR live contract agree on the SAME real grant — the one
# HoS issued on `alpha.tlademo.testnet` with our executor in the control set.
#
# AUTH. The wallet whose executor HoS whitelisted was COORDINATOR-MINTED, so it
# authenticates with a `wk_` payment key, NOT a near:-seed. Every call here goes
# through `api_wk "$WK"`. The key + wallet live in `keystore-worker/.env.hos`
# (executor `5356b2c0…e325806a`, the whitelisted one); HOS_ENV points at another
# such file. One wallet is one live binding, so each leased account has its own.
#
# What this covers (everything a live grant on alpha CAN show):
#   G0  the wk_ resolves to the executor HoS whitelisted
#   G1  PUT hos_lease → 200, executor echoed
#   G2  the binding goes ACTIVE off the real hos_agent_status (grant + extension),
#       and the registry's `nft_token` has the name the account claims in its
#       `nft_item_info` — the pairing the coordinator requires (existence only;
#       ownership is the item's and is not compared)
#   G3  happy: native / wNEAR / USDC to the granted receiver, within budget —
#       the transfer LANDS and the on-chain grant meter increments (this is the
#       exact path the partner ran with a throwaway extension before handover)
#   G7  receiver not in the grant → receiver_not_granted, BEFORE any gas
#   G8  over the per-token budget → token_budget_exceeded
#   G9  over the native budget → grant_exhausted
#   G10 ft_transfer_call (msg forwards value) → refused, method named
#   G11 a granted call carrying a non-1-yocto deposit → grant_call_deposit
#
# What it CANNOT cover, and why: an expired / frozen / parked grant, a lease that
# ran out, an unsupported impl_version (stub suite — a live account cannot be
# made to report those on demand); a rotation, the NFT fences, the reserve floor
# and carry-forward across a refill (`hos_lease_bravo_e2e.sh`, on the second
# leased account whose grant is shaped for them — alpha's has no items and its 5
# NEAR cap trips before the ~0.012 NEAR floor).
#
# ── COST WARNING ─────────────────────────────────────────────────────────────
# G3 SPENDS the grant. HoS refills the budgets (NATIVE_BUDGET NEAR / 5 wNEAR /
# 100 USDC) on request — shout when a run empties it — but not on their own, so
# G3 moves the SMALLEST amounts that still prove a transfer. G7–G11 are refused
# by pre-flight and spend NOTHING, so they are free to repeat. When G3 starts
# failing as grant_exhausted / budget_exceeded, the grant is spent, not the
# product broken — ask HoS to refill.
#
#   ./tests/hos_lease_live_e2e.sh --apply
#     (reads HOS_WK from keystore-worker/.env.hos by default; HOS_ENV=<file> for
#      another wallet file, or pass HOS_WK=wk_…)
#
# Optional: ASSET, RECEIVER, WNEAR, USDC, OWNER, IMPL_VERSION, EXPECTED_EXECUTOR,
# NATIVE_BUDGET (yocto; G9 spends one NEAR over it).

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/hos_common.sh"

[[ "${1:-}" == "--apply" ]] || { sed -n '3,53p' "$0" >&2; echo "  Pass --apply to run." >&2; exit 0; }

# ── credential: the wk_ of the whitelisted-executor wallet ────────────────────
ENV_HOS="${HOS_ENV:-$REPO_ROOT/keystore-worker/.env.hos}"
if [[ -z "${HOS_WK:-}" && -f "$ENV_HOS" ]]; then
  HOS_WK=$(jq -r '.api_key // empty' "$ENV_HOS" 2>/dev/null)
fi
[[ -n "${HOS_WK:-}" ]] || { echo "✗ set HOS_WK to the wk_ of the whitelisted-executor wallet (see keystore-worker/.env.hos)" >&2; exit 1; }
WK="$HOS_WK"

# This suite authenticates as a coordinator-minted wallet, so it does NOT need
# PARENT / RECOVERY_BIN like the seed-based suites. Only jq + curl.
command -v jq >/dev/null || { echo "✗ jq required" >&2; exit 1; }
command -v python3 >/dev/null || { echo "✗ python3 required (yocto arithmetic)" >&2; exit 1; }

# ── the live grant, exactly as HoS provisioned it (verified by RPC 2026-08-22) ─
ASSET="${ASSET:-alpha.tlademo.testnet}"
RECEIVER="${RECEIVER:-hos-e2e-receiver.testnet}"   # the ONLY granted receiver
WNEAR="${WNEAR:-wrap.testnet}"                      # granted token, budget 5 wNEAR
USDC="${USDC:-usdc.fakes.testnet}"                  # granted token, budget 100 USDC
# The registry's own answer for this account (`nft_item_info.owner_id`, read by
# RPC 2026-08-22), not the account itself. The coordinator checks only the shape
# of this field, so a wrong value is accepted silently and then returned to
# clients as if it were established — which is exactly why a fixture should not
# carry a convenient fiction.
OWNER="${OWNER:-council.tlademo.testnet}"
IMPL_VERSION="${IMPL_VERSION:-7}"                   # from the live hos_agent_status (impl v7 since 2026-09-09)
OUTSIDER="${OUTSIDER:-outsider-nobody.testnet}"    # never in the grant
EXPECTED_EXECUTOR="${EXPECTED_EXECUTOR:-5356b2c04da3aa5f134ae59d12e72f5df6ce25db24ffa968c74c8843e325806a}"
NATIVE_BUDGET="${NATIVE_BUDGET:-5000000000000000000000000}"   # 5 NEAR on alpha

# Tiny spends so the grant survives ~100 runs (see COST WARNING).
NEAR_SPEND="${NEAR_SPEND:-50000000000000000000000}"    # 0.05 NEAR
WNEAR_SPEND="${WNEAR_SPEND:-50000000000000000000000}"  # 0.05 wNEAR
USDC_SPEND="${USDC_SPEND:-1000000}"                    # 1 USDC (6 dp)

# Every coordinator call in this suite is wk_-authenticated.
q() { api_wk "$WK" "$@"; }

# Read grant counters straight off the chain — the source of truth, and the only
# way to prove a spend actually LANDED rather than just returned 200.
grant_field() { near_view "$ASSET" hos_agent_status "$(jq -nc --arg e "$EXECUTOR" '{extension:$e}')" | jq -r "$1 // \"0\"" 2>/dev/null; }
spent_native() { grant_field '.grant.spent_yocto'; }
spent_token()  { grant_field ".grant.tokens[\"$1\"].spent"; }

# Poll a counter until it changes from a baseline (a spend settled) or time out.
# The reader is a command STRING (eval'd), so `spent_token <contract>` works.
#
# Called only behind an explicit `HTTP == 200`, never chained off
# `assert_status`: that assertion RETURNS SUCCESS when it steps aside for a
# wallet that has spent its monthly allowance, so a chain would run this against
# a send that never happened and spend thirty seconds proving a meter did not
# move — reported as the product failing to deliver a transfer.
wait_spend() { # <desc> <reader-cmd-string> <baseline>
  local desc=$1 reader=$2 base=$3 now i
  for i in 1 2 3 4 5 6 7 8 9 10; do
    sleep 3; now=$(eval "$reader")
    [[ "$now" != "$base" ]] && { pass "$desc — meter moved on chain: $base → $now"; return 0; }
  done
  fail "$desc — 200 returned but the on-chain meter never moved off $base (transfer did not land)"; return 1
}

# Send a raw w_execute_extension op, wk_-authenticated — for the FORM cases that
# /binding/transfer would never mis-build for us.
call_raw() { # <envelope-json> [deposit]
  local env=$1 dep=${2:-1}
  q POST /wallet/v1/call "$(jq -nc --arg r "$ASSET" --arg a "$(b64 "$env")" --arg d "$dep" \
      '{receiver_id:$r, method_name:"w_execute_extension", args_base64:$a, deposit:$d, gas:"90000000000000"}')"
}

# ── G0: the wk_ resolves to the whitelisted executor ──────────────────────────
log "G0 · executor identity"
q GET "/wallet/v1/address?chain=near" >/dev/null
EXECUTOR=$(jq -r '.executor_account_id // empty' <<<"$BODY")
[[ -n "$EXECUTOR" ]] || { fail "G0 — /address returned no executor for this wk_: $(msg_of)"; verdict "hos_lease live"; exit 1; }
if [[ "$EXECUTOR" == "$EXPECTED_EXECUTOR" ]]; then
  pass "G0 — executor $EXECUTOR matches the whitelisted one"
else
  fail "G0 — this wk_ resolves to executor $EXECUTOR, NOT the whitelisted $EXPECTED_EXECUTOR. Wrong wallet; the grant will not verify."
  verdict "hos_lease live"; exit 1
fi

# ── G1/G2: bind to the real leased account and go active ──────────────────────
log "G1 · PUT hos_lease"
q PUT /wallet/v1/binding \
  "$(jq -nc --arg a "$ASSET" --arg o "$OWNER" --argjson v "$IMPL_VERSION" \
     '{asset_account_id:$a, owner_account_id:$o, impl_version:$v, kind:"hos_lease"}')" >/dev/null
assert_status "G1 · PUT hos_lease accepted" 200
assert_json  "G1 · executor echoed"        '.executor_account_id' "$EXECUTOR"

log "G2 · binding active off the real hos_agent_status"
status=""
for i in 1 2 3 4 5 6 7 8; do
  q GET /wallet/v1/binding >/dev/null
  status=$(jq -r '.binding_status // ""' <<<"$BODY"); [[ "$status" == "active" ]] && break; sleep 3
done
[[ "$status" == "active" ]] && pass "G2 · binding ACTIVE against the live grant" \
  || fail "G2 · binding never went active ('$status') — verify our pre-flight parses their live hos_agent_status: $(msg_of)"

# The account's word and its collection's, read off the chain the way the
# coordinator reads them. Active above already means the coordinator found them
# in agreement; this states what it agreed on, so a registry that changes shape
# is seen here as a shape and not as every leased binding suspending.
ITEM=$(near_view "$ASSET" nft_item_info '{}')
COLL=$(jq -r '.collection_id // empty' <<<"$ITEM"); TOK=$(jq -r '.token_id // empty' <<<"$ITEM")
ITEM_OWNER=$(jq -r '.owner_id // empty' <<<"$ITEM")
if [[ -n "$COLL" && -n "$TOK" ]]; then
  TOKEN=$(near_view "$COLL" nft_token "$(jq -nc --arg t "$TOK" '{token_id:$t}')")
  REG_OWNER=$(jq -r '.owner_id // empty' <<<"$TOKEN" 2>/dev/null)
  # Existence is what the coordinator requires of the collection; ownership is
  # the item's to state and is only noted here. A literal `null` is the
  # collection's answer; anything unparseable is the RPC's, and says nothing.
  if [[ -n "$REG_OWNER" ]]; then
    pass "G2b · $COLL::nft_token('$TOK') exists — the collection minted the name the account claims"
    [[ "$REG_OWNER" == "$ITEM_OWNER" ]] || note "G2b · registry owner $REG_OWNER differs from the item's $ITEM_OWNER — the item is authoritative, nothing to fix"
  elif [[ "$TOKEN" == "null" ]]; then
    fail "G2b · the collection has no token '$TOK' — the coordinator suspends this lane as registry_disagrees"
  else
    skip "G2b · the collection could not be asked ($TOKEN) — the coordinator leaves the pairing unjudged, and so does this"
  fi
else
  fail "G2b · nft_item_info names no collection_id/token_id ($ITEM) — nothing can confirm this account"
fi

# ── G3: happy path — spends land, the on-chain meter increments ───────────────
log "G3 · granted spends land and the meter moves"

base=$(spent_native)
q POST /wallet/v1/binding/transfer \
  "$(jq -nc --arg t "$RECEIVER" --arg a "$NEAR_SPEND" '{to:$t, amount:$a}')" >/dev/null
assert_status "G3a · native transfer to granted receiver accepted" 200
[[ "$HTTP" == "200" ]] && wait_spend "G3a · native meter" spent_native "$base"

base=$(spent_token "$USDC")
q POST /wallet/v1/binding/transfer \
  "$(jq -nc --arg t "$RECEIVER" --arg a "$USDC_SPEND" --arg k "$USDC" '{to:$t, amount:$a, token:$k}')" >/dev/null
assert_status "G3b · USDC ft_transfer to granted receiver accepted" 200
[[ "$HTTP" == "200" ]] && wait_spend "G3b · USDC meter" "spent_token $USDC" "$base"

base=$(spent_token "$WNEAR")
q POST /wallet/v1/binding/transfer \
  "$(jq -nc --arg t "$RECEIVER" --arg a "$WNEAR_SPEND" --arg k "$WNEAR" '{to:$t, amount:$a, token:$k}')" >/dev/null
assert_status "G3c · wNEAR ft_transfer to granted receiver accepted" 200
[[ "$HTTP" == "200" ]] && wait_spend "G3c · wNEAR meter" "spent_token $WNEAR" "$base"

# ── G7–G9: pre-flight refuses before any gas, with the contract's own class ───
log "G7–G9 · budget and receiver walls (refused pre-flight, no spend)"

q POST /wallet/v1/binding/transfer \
  "$(jq -nc --arg t "$OUTSIDER" --arg a "$NEAR_SPEND" '{to:$t, amount:$a}')" >/dev/null
assert_class "G7 · outsider receiver" "receiver_not_granted"

q POST /wallet/v1/binding/transfer \
  "$(jq -nc --arg t "$RECEIVER" --arg a "200000000" --arg k "$USDC" '{to:$t, amount:$a, token:$k}')" >/dev/null
assert_class "G8 · 200 USDC over the 100 USDC token budget" "token_budget_exceeded"

OVER_BUDGET=$(python3 -c "print($NATIVE_BUDGET + 10**24)")
q POST /wallet/v1/binding/transfer \
  "$(jq -nc --arg t "$RECEIVER" --arg a "$OVER_BUDGET" '{to:$t, amount:$a}')" >/dev/null
assert_class "G9 · one NEAR over the native budget" "grant_exhausted"
# The class alone is only half of what R12 asks for. A budget wall is TERMINAL:
# the meter does not refill on its own, and only a fresh grant from the owner
# moves it. An agent that reads this as transient retries until its lease runs
# out while the one person who could fix it is never told, so the flag the
# client routes on is asserted here rather than assumed from the class name.
assert_json "G9 · and the refusal is terminal — only a new grant moves this wall" '.terminal' true

# ── G10/G11: form rules the grant enforces — via raw /call ────────────────────
log "G10–G11 · granted-call FORM (raw w_execute_extension)"

# ft_transfer_call forwards value through `msg`; the grant covers ft_transfer/
# nft_transfer only. Core marks it unstatable → refused, method named.
call_raw "$(ext_call "$USDC" ft_transfer_call "$(jq -nc --arg r "$RECEIVER" '{receiver_id:$r,amount:"1",msg:""}')" 1)" >/dev/null
assert_denied "G10 · ft_transfer_call refused" \
  && assert_msg "G10 · refusal names the method or its unstatability" 'ft_transfer_call|cannot state|not allowed|method'

# A granted token call must attach EXACTLY 1 yocto; here the inner deposit is 2.
call_raw "$(ext_call "$USDC" ft_transfer "$(jq -nc --arg r "$RECEIVER" '{receiver_id:$r,amount:"1"}')" 2)" >/dev/null
assert_class "G11 · non-1-yocto granted call" "grant_shape_violation:grant_call_deposit"

# ── teardown ──────────────────────────────────────────────────────────────────
if [[ "${KEEP:-}" != "1" ]]; then
  q DELETE /wallet/v1/binding >/dev/null
  note "binding row deleted (KEEP=1 to leave it); the leased account and its grant are untouched"
fi

verdict "hos_lease live"
