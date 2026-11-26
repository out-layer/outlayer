#!/usr/bin/env bash
#
# §0′ [REV-0831] of the HoS test plan — the `hos_lease` profile against the
# PARTNER'S SECOND leased account, `bravo.tlademo.testnet`, whose grant is
# shaped for the branches alpha's cannot reach: a native ceiling ABOVE the
# account's balance (so the reserve floor binds), an item fence on a separate
# collection (so the NFT rungs are live), and a refill on request (so
# carry-forward is observable). `hos_lease_live_e2e.sh` covers the rest on
# alpha; the two suites share nothing but the shape.
#
# AUTH. As on alpha: a coordinator-minted wallet, `wk_`-authenticated, one
# wallet per leased account (one wallet is one live binding). The file is
# `keystore-worker/.env.hos2` (executor `68f651d8…f47f41`).
#
# What this covers, and what each needs:
#   B0  the wk_ resolves to the executor HoS whitelisted on bravo
#   B1  PUT hos_lease → 200, executor echoed
#   B2  ACTIVE off the real hos_agent_status; the collection's `nft_token`
#       confirms the account's `nft_item_info`
#   B3  the reserve floor: a spend that would leave the account below
#       `reserve_yocto` is refused BEFORE gas as insufficient_vs_reserve; a
#       small spend lands and the meter moves. The refused probe leaves the
#       account 0.001 NEAR under the floor and costs nothing; the control is
#       SMALL on purpose — "just under the floor" would drain the account to
#       the floor and kill every later native probe.
#   B4  the item fence (needs FENCE_COLLECTION + FENCE_TOKEN_IDS from HoS):
#       a fenced token moves (once — it is gone afterwards, HoS re-mints);
#       an unfenced token in the granted collection → item_not_granted;
#       a collection the grant never named → collection_not_granted;
#       the account's OWN collection (its registry) → own_collection_refused
#   B5  carry-forward: the meter is printed; with CARRY_BASELINE=<spent before
#       the refill> the suite asserts it carried (or, with EXPECT_RESET=1,
#       that a revoke+grant reset it)
#   B6  rotation (ROTATED=1, after HoS rotated bravo at our request, against a
#       binding left by a previous KEEP=1 run): the transitional spend is
#       refused terminally with the chain's own class, a status read records
#       the closure, and the next spend is refused as binding_ended
#
# The suite stops after B2 with a note, not a failure, while bravo is not yet
# provisioned (no grant, executor not in the set): that is a state of theirs,
# not a defect of ours.
#
# ── COST WARNING ─────────────────────────────────────────────────────────────
# B3's control and B4's fenced transfer SPEND the grant; HoS refills on request
# — shout when a run empties it. Everything refused pre-flight spends nothing.
#
#   ./tests/hos_lease_bravo_e2e.sh --apply
#     (reads HOS_WK from keystore-worker/.env.hos2; HOS_ENV=<file> or HOS_WK=wk_…)
#   FENCE_COLLECTION=coll.testnet FENCE_TOKEN_IDS="1 2" ./tests/hos_lease_bravo_e2e.sh --apply
#   KEEP=1 …                      leave the binding for the rotation phase
#   ROTATED=1 …                   the phase after HoS rotated bravo
#   CARRY_BASELINE=<yocto> …      the phase after HoS refilled the grant
#
# Optional: ASSET, RECEIVER, OWNER, IMPL_VERSION, EXPECTED_EXECUTOR, NATIVE_BUDGET,
# OTHER_COLL (a collection never in the grant), FENCE_OTHER_TOKEN (an unfenced
# token_id in the granted collection), NEAR_SPEND.

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/hos_common.sh"

[[ "${1:-}" == "--apply" ]] || { sed -n '3,56p' "$0" >&2; echo "  Pass --apply to run." >&2; exit 0; }

ENV_HOS="${HOS_ENV:-$REPO_ROOT/keystore-worker/.env.hos2}"
if [[ -z "${HOS_WK:-}" && -f "$ENV_HOS" ]]; then
  HOS_WK=$(jq -r '.api_key // empty' "$ENV_HOS" 2>/dev/null)
fi
[[ -n "${HOS_WK:-}" ]] || { echo "✗ set HOS_WK to the wk_ of the bravo wallet (see keystore-worker/.env.hos2)" >&2; exit 1; }
WK="$HOS_WK"
command -v jq >/dev/null || { echo "✗ jq required" >&2; exit 1; }
command -v python3 >/dev/null || { echo "✗ python3 required (yocto arithmetic)" >&2; exit 1; }

ASSET="${ASSET:-bravo.tlademo.testnet}"
RECEIVER="${RECEIVER:-hos-e2e-receiver.testnet}"
OWNER="${OWNER:-council.tlademo.testnet}"          # nft_item_info.owner_id, read by RPC 2026-09-03
IMPL_VERSION="${IMPL_VERSION:-7}"                    # from the live hos_agent_status (impl v7 since 2026-09-09)
EXPECTED_EXECUTOR="${EXPECTED_EXECUTOR:-68f651d8d40d75c75e3831f2bde3a13155261d6d466b47ecc25dd86e00f47f41}"
NATIVE_BUDGET="${NATIVE_BUDGET:-20000000000000000000000000}"  # 20 NEAR, as HoS announced
OTHER_COLL="${OTHER_COLL:-nft.fakes.testnet}"      # never in the grant
FENCE_COLLECTION="${FENCE_COLLECTION:-}"           # from HoS, with the token_ids below
FENCE_TOKEN_IDS="${FENCE_TOKEN_IDS:-}"             # space- or comma-separated
FENCE_OTHER_TOKEN="${FENCE_OTHER_TOKEN:-not-in-the-fence}"
NEAR_SPEND="${NEAR_SPEND:-50000000000000000000000}"   # 0.05 NEAR

q() { api_wk "$WK" "$@"; }
yocto() { python3 -c "print($1)"; }
grant_field() { near_view "$ASSET" hos_agent_status "$(jq -nc --arg e "$EXECUTOR" '{extension:$e}')" | jq -r "$1 // \"0\"" 2>/dev/null; }
spent_native() { grant_field '.grant.spent_yocto'; }
token_owner() { near_view "$1" nft_token "$(jq -nc --arg t "$2" '{token_id:$t}')" | jq -r '.owner_id // empty' 2>/dev/null; }

wait_spend() { # <desc> <reader-cmd-string> <baseline>
  local desc=$1 reader=$2 base=$3 now i
  for i in 1 2 3 4 5 6 7 8 9 10; do
    sleep 3; now=$(eval "$reader")
    [[ "$now" != "$base" ]] && { pass "$desc — meter moved on chain: $base → $now"; return 0; }
  done
  fail "$desc — 200 returned but the on-chain meter never moved off $base (transfer did not land)"; return 1
}
call_raw() { # <envelope-json> [deposit]
  local env=$1 dep=${2:-1}
  q POST /wallet/v1/call "$(jq -nc --arg r "$ASSET" --arg a "$(b64 "$env")" --arg d "$dep" \
      '{receiver_id:$r, method_name:"w_execute_extension", args_base64:$a, deposit:$d, gas:"90000000000000"}')"
}
nft_move() { # <collection> <token_id> — nft_transfer to the granted receiver, 1 yocto
  call_raw "$(ext_call "$1" nft_transfer "$(jq -nc --arg r "$RECEIVER" --arg t "$2" '{receiver_id:$r,token_id:$t}')" 1)" >/dev/null
}

# ── B0: identity ──────────────────────────────────────────────────────────────
log "B0 · executor identity"
q GET "/wallet/v1/address?chain=near" >/dev/null
EXECUTOR=$(jq -r '.executor_account_id // empty' <<<"$BODY")
[[ -n "$EXECUTOR" ]] || { fail "B0 — /address returned no executor for this wk_: $(msg_of)"; verdict "hos_lease bravo"; exit 1; }
if [[ "$EXECUTOR" == "$EXPECTED_EXECUTOR" ]]; then
  pass "B0 — executor $EXECUTOR is the one HoS whitelisted on $ASSET"
else
  fail "B0 — this wk_ resolves to executor $EXECUTOR, NOT $EXPECTED_EXECUTOR; wrong wallet file"
  verdict "hos_lease bravo"; exit 1
fi

# ── B6: the rotation phase, against a binding a previous KEEP=1 run left ──────
if [[ "${ROTATED:-}" == "1" ]]; then
  log "B6 · after HoS rotated $ASSET"
  # Raw /call with the account named, not /binding/transfer: the builder needs
  # a LIVE binding to know the account and answers 404 once the lane is closed,
  # while the gate behind /call is where binding_ended is said.
  call_raw "$(ext_transfer "$RECEIVER" "$NEAR_SPEND")" >/dev/null
  if assert_denied "B6a · the transitional spend is refused"; then
    C=$(class_of)
    case "$C" in
      executor_not_in_control_set|binding_ended|lease_expired)
        pass "B6a · with the chain's own class '$C' — the rotation cleared the grants";;
      *) finding "B6a · refused as '$C' — safe, but not one of the classes a rotation is expected to surface";;
    esac
    assert_json "B6a · and terminal" '.terminal' true
  fi
  q GET /wallet/v1/binding >/dev/null
  ST=$(jq -r '.binding_status // ""' <<<"$BODY")
  [[ "$ST" == "revoked" || "$HTTP" == "404" ]] \
    && pass "B6b · the status read records the closure (status '$ST', HTTP $HTTP) — the rotation pin did its job" \
    || fail "B6b · after the rotation the binding still reads '$ST' (HTTP $HTTP)"
  call_raw "$(ext_transfer "$RECEIVER" "$NEAR_SPEND")" >/dev/null
  assert_class "B6c · the next spend is refused as the lane having ENDED" "binding_ended" \
    && assert_json "B6c · terminal" '.terminal' true
  verdict "hos_lease bravo (rotation phase)"; exit 0
fi

# ── B1/B2: bind and go active ─────────────────────────────────────────────────
log "B1 · PUT hos_lease"
q PUT /wallet/v1/binding \
  "$(jq -nc --arg a "$ASSET" --arg o "$OWNER" --argjson v "$IMPL_VERSION" \
     '{asset_account_id:$a, owner_account_id:$o, impl_version:$v, kind:"hos_lease"}')" >/dev/null
assert_status "B1 · PUT hos_lease accepted" 200
assert_json  "B1 · executor echoed"        '.executor_account_id' "$EXECUTOR"

log "B2 · binding active off the real hos_agent_status"
status=""
for i in 1 2 3 4 5 6 7 8; do
  q GET /wallet/v1/binding >/dev/null
  status=$(jq -r '.binding_status // ""' <<<"$BODY"); [[ "$status" == "active" ]] && break; sleep 3
done
if [[ "$status" != "active" ]]; then
  LIVE=$(near_view "$ASSET" hos_agent_status "$(jq -nc --arg e "$EXECUTOR" '{extension:$e}')")
  if [[ "$(jq -r '.extension_enabled // false' <<<"$LIVE")" != "true" || "$(jq -r '.grant // "null"' <<<"$LIVE")" == "null" ]]; then
    note "B2 · $ASSET is not provisioned for $EXECUTOR yet (extension_enabled=$(jq -r '.extension_enabled' <<<"$LIVE"), grant=$(jq -c '.grant' <<<"$LIVE")) — the binding stays '$status'; nothing further can be judged until HoS provisions it"
    [[ "${KEEP:-}" == "1" ]] || q DELETE /wallet/v1/binding >/dev/null
    verdict "hos_lease bravo (not provisioned)"; exit 0
  fi
  fail "B2 · provisioned on chain but the binding never went active ('$status'): $(msg_of)"
  verdict "hos_lease bravo"; exit 1
fi
pass "B2 · binding ACTIVE against the live grant"

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
    pass "B2b · $COLL::nft_token('$TOK') exists — the collection minted the name the account claims"
    [[ "$REG_OWNER" == "$ITEM_OWNER" ]] || note "B2b · registry owner $REG_OWNER differs from the item's $ITEM_OWNER — the item is authoritative, nothing to fix"
  elif [[ "$TOKEN" == "null" ]]; then
    fail "B2b · the collection has no token '$TOK' — the coordinator suspends this lane as registry_disagrees"
  else
    skip "B2b · the collection could not be asked ($TOKEN) — the coordinator leaves the pairing unjudged, and so does this"
  fi
else
  fail "B2b · nft_item_info names no collection_id/token_id ($ITEM)"
fi

GRANT=$(grant_field '.grant')
note "grant: receivers $(jq -c '.receivers' <<<"$GRANT"), native $(jq -r '.budget_yocto' <<<"$GRANT") spent $(jq -r '.spent_yocto' <<<"$GRANT"), items $(jq -c '.items' <<<"$GRANT")"

# ── B3: the reserve floor ─────────────────────────────────────────────────────
log "B3 · the reserve floor binds before the native ceiling"
BALANCE=$(account_field "$ASSET" amount)
RESERVE=$(grant_field '.reserve_yocto')
BUDGET=$(jq -r '.budget_yocto // "0"' <<<"$GRANT"); SPENT=$(jq -r '.spent_yocto // "0"' <<<"$GRANT")
HEADROOM=$(yocto "$BUDGET - $SPENT")
PROBE=$(yocto "$BALANCE - $RESERVE + 10**21")   # leaves 0.001 NEAR under the floor
note "balance $BALANCE, reserve $RESERVE, grant headroom $HEADROOM → probe $PROBE"
if (( $(yocto "1 if $PROBE <= $HEADROOM else 0") == 1 )); then
  q POST /wallet/v1/binding/transfer "$(jq -nc --arg t "$RECEIVER" --arg a "$PROBE" '{to:$t, amount:$a}')" >/dev/null
  assert_class "B3a · a spend that ends under the floor is refused BEFORE gas" "insufficient_vs_reserve" \
    && assert_json "B3a · terminal — the floor tracks live storage, and only the owner moves it" '.terminal' true
else
  skip "B3a · the grant headroom ($HEADROOM) is below the floor probe ($PROBE): the ceiling would answer first, so the floor cannot be seen — ask HoS to raise the ceiling or lower the balance"
fi
base=$(spent_native)
q POST /wallet/v1/binding/transfer "$(jq -nc --arg t "$RECEIVER" --arg a "$NEAR_SPEND" '{to:$t, amount:$a}')" >/dev/null
assert_status "B3b · a small native spend well above the floor is accepted" 200
[[ "$HTTP" == "200" ]] && wait_spend "B3b · native meter" spent_native "$base"

# ── B4: the item fence ────────────────────────────────────────────────────────
log "B4 · NFT: the fence, the collection wall, the own-collection rule"
if [[ -n "$FENCE_COLLECTION" && -n "$FENCE_TOKEN_IDS" ]]; then
  GRANTED_IDS=$(jq -c --arg c "$FENCE_COLLECTION" '.items[$c] // []' <<<"$GRANT")
  note "grant fences $FENCE_COLLECTION to $GRANTED_IDS"
  MOVED=""
  for id in ${FENCE_TOKEN_IDS//,/ }; do
    if [[ "$(jq -r --arg i "$id" 'index($i) != null' <<<"$GRANTED_IDS")" != "true" ]]; then
      warn "B4a · token '$id' is not in the on-chain fence $GRANTED_IDS — skipping it"; continue
    fi
    if [[ "$(token_owner "$FENCE_COLLECTION" "$id")" != "$ASSET" ]]; then
      note "B4a · token '$id' is no longer held by $ASSET (moved by an earlier run?) — skipping; ask HoS to re-mint"; continue
    fi
    nft_move "$FENCE_COLLECTION" "$id"
    if assert_status "B4a · a fenced token moves to the granted receiver" 200; then
      [[ "$HTTP" == "200" ]] && wait_spend "B4a · nft_token owner" "token_owner $FENCE_COLLECTION $id" "$ASSET"
    fi
    MOVED=1; break
  done
  [[ -n "$MOVED" ]] || skip "B4a · no fenced token still held by $ASSET — nothing to move"
  nft_move "$FENCE_COLLECTION" "$FENCE_OTHER_TOKEN"
  assert_class "B4b · an item outside the fence, in the granted collection" "item_not_granted"
else
  skip "B4a/B4b · FENCE_COLLECTION + FENCE_TOKEN_IDS not set — waiting on HoS for the collection id and the fenced token_ids"
fi
nft_move "$OTHER_COLL" "1"
assert_class "B4c · a collection the grant never named — NOT item_not_granted" "collection_not_granted"
if [[ -n "$COLL" ]]; then
  nft_move "$COLL" "$TOK"
  assert_class "B4d · the account's OWN collection ($COLL) — a grant never moves the account's own name" "own_collection_refused"
fi

# ── B5: carry-forward across a refill ─────────────────────────────────────────
log "B5 · the meter across a refill"
# Judged on SPENT — the meter as this run FOUND it, read before B3b added to
# it — so a reset followed by this run's own spend cannot pass for a carry.
NOW_SPENT=$(spent_native)
note "spent_yocto now: $NOW_SPENT (pass it back as CARRY_BASELINE after HoS refills)"
if [[ -n "${CARRY_BASELINE:-}" ]]; then
  if [[ "${EXPECT_RESET:-}" == "1" ]]; then
    (( $(yocto "1 if $SPENT < $CARRY_BASELINE else 0") == 1 )) \
      && pass "B5 · revoke+grant RESET the meter: $CARRY_BASELINE → $SPENT" \
      || fail "B5 · expected a reset below $CARRY_BASELINE, the meter read $SPENT"
  else
    (( $(yocto "1 if $SPENT >= $CARRY_BASELINE else 0") == 1 )) \
      && pass "B5 · the refill CARRIED the meter forward: $CARRY_BASELINE → $SPENT (not reset)" \
      || fail "B5 · the meter fell from $CARRY_BASELINE to $SPENT across the refill — it was reset, not carried"
  fi
fi

# ── teardown ──────────────────────────────────────────────────────────────────
if [[ "${KEEP:-}" != "1" ]]; then
  q DELETE /wallet/v1/binding >/dev/null
  note "binding row deleted (KEEP=1 to leave it for the rotation phase); the leased account and its grant are untouched"
fi
verdict "hos_lease bravo"
