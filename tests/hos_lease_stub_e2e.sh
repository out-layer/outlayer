#!/usr/bin/env bash
#
# §3.1 + §6(leased) of the HoS test plan — the `hos_lease` profile end to end,
# against the stub contract from §10.
#
# Everything below runs through the real coordinator, the real pre-flight and
# the real chain. What is simulated is only the PARTNER'S ANSWER: the stub
# serves `hos_agent_status` (and `nft_item_info`) and a test sets it to
# whatever state the case is about — no grant, an expired grant, a frozen
# account, a lease that ran out, a version we have no decoder for. A second
# instance of the same stub plays the COLLECTION the leased account says it
# belongs to and serves `nft_token`, so the pairing of the account's word
# with its collection's can be made to agree or disagree.
#
# The boundary, stated so nobody has to infer it: this proves that OUR side
# agrees with the shape and the rules of their view, in the order their
# contract checks them. It does NOT prove their contract panics at the same
# rung — only a leased account can, and that is the one line of acceptance
# that waits for their TLA. The golden vectors in the crate
# (`hos_contract_vectors`, tag `valhalla-2026-08`) already pin the agreement of
# the RULES; this pins the agreement of the FLOW.
#
# Two things the suite is careful about:
#   * the observation cache is 5 s, so every status change is followed by a
#     wait — otherwise a case would be judged against the previous state and
#     the suite would be measuring its own impatience;
#   * the wallet policy is deliberately empty of address/token/limit rules, so
#     that anything refused here is refused by the LEASED PROFILE and not by
#     the ordinary custody rules that §4 already covers.
#
#   PARENT=you.testnet ./tests/hos_lease_stub_e2e.sh --apply
#   KEEP=1 leaves the stub account alive for a re-run.

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/hos_common.sh"

[[ "${1:-}" == "--apply" ]] || { sed -n '3,32p' "$0" >&2; echo "  Pass --apply to run." >&2; exit 0; }
hos_require

STUB_WASM="$REPO_ROOT/tests/hos-status-stub/target/near/hos_status_stub.wasm"
[[ -f "$STUB_WASM" ]] || { echo "✗ build the stub first: (cd tests/hos-status-stub && cargo near build non-reproducible-wasm)" >&2; exit 1; }

WL="${WL:-zavodil2.testnet}"                       # a granted receiver
OUTSIDER="${OUTSIDER:-outsider-nobody.testnet}"    # never in a grant
TOKEN="${TOKEN:-usdc.fakes.testnet}"               # granted fungible
OTHER_TOKEN="${OTHER_TOKEN:-dai.fakes.testnet}"    # never granted
COLL="${COLL:-nft.fakes.testnet}"                  # granted collection
OTHER_COLL="${OTHER_COLL:-other-nft.fakes.testnet}"
# The registry this leased account's own name lives in is the SECOND stub
# instance, deployed below. Deliberately NOT the granted collection: the
# own-collection guard sits at rung 4 and would answer before the item fence at
# rung 10, so sharing them would hide G7. And deliberately a real contract that
# answers `nft_token`: the coordinator asks the collection whether it minted the
# token the account names — a collection that cannot be asked leaves the
# pairing unjudged, one that has no such token suspends the lane, and one that
# names a different owner changes nothing, ownership being the item's to state
# (PAIR1–PAIR3).
FUTURE_NS="4000000000000000000"                    # year 2096
PAST_NS="1000000000000000000"                      # year 2001

SEED_S="hos-stub-$(date +%s)-$$"
read -r WID_S EXEC_S < <(wallet_address "$SEED_S")
[[ -n "$WID_S" ]] || { echo "✗ could not mint the wallet" >&2; exit 1; }
STUB="hos-stub-$(openssl rand -hex 3).$PARENT"
OWN_COLL="hos-registry-$(openssl rand -hex 3).$PARENT"
note "wallet $WID_S / executor $EXEC_S / stub $STUB / its collection $OWN_COLL"

W_ZONE_ADDED=""
cleanup() {
  local rc=$?
  api "$SEED_S" DELETE /wallet/v1/binding >/dev/null 2>&1 || true
  # §W admits $PARENT to the webhook's zones for its own length; a run that
  # died inside it must not leave the deployment wider than it found it.
  if [[ -n "$W_ZONE_ADDED" ]]; then
    [[ "$(adm DELETE "/admin/binding-zones/$PARENT")" == 2?? ]] \
      && note "webhook zone $PARENT removed again" \
      || warn "webhook zone $PARENT is STILL admitted — DELETE /admin/binding-zones/$PARENT by hand"
  fi
  if [[ -z "${KEEP:-}" ]]; then
    local a
    for a in "$STUB" "$OWN_COLL"; do
      account_exists "$a" && { note "cleaning up $a"; delete_account "$a"; }
    done
  fi
  return $rc
}
trap cleanup EXIT

# ── the stub, twice: the leased account and the collection it names ────────
deploy_stub() { # <account>
  create_subaccount "$1" 3 || { echo "✗ $1 never appeared" >&2; exit 1; }
  near_tty "near contract deploy $1 use-file $STUB_WASM \
    with-init-call new json-args '{}' prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR' \
    network-config $NETWORK sign-with-keychain send" >/dev/null 2>&1 \
    || { echo "✗ the stub did not deploy to $1" >&2; exit 1; }
}
log "Deploying the stub to $STUB (the leased account) and $OWN_COLL (its collection)"
deploy_stub "$STUB"
deploy_stub "$OWN_COLL"
pass "both stub instances are deployed and initialised"

# The leased mode believes only accounts running code the coordinator was TOLD
# about (`hos_impl_code_hashes`, admin-managed, see .idea/TESTING-WITH-ADMIN.md).
# A rebuilt stub is a new hash, and a new hash is `pending` forever with no
# message — so register this build's hash when the token is at hand, and say
# what to do when it is not.
# adm <METHOD> <path> [body] — echoes the http code. Admin calls this suite
# makes: the code-hash allowlist below, the webhook zone in §W.
adm() {
  local m=$1 p=$2 b=${3:-}
  local -a a=(-sS -o /dev/null -w '%{http_code}' -X "$m" "$COORDINATOR_URL$p"
              -H "Authorization: Bearer ${ADMIN_TOKEN:-}" --max-time 60)
  [[ -n "$b" ]] && a+=(-H 'Content-Type: application/json' --data-binary "$b")
  curl "${a[@]}" 2>/dev/null
}
STUB_HASH=""
for _ in 1 2 3 4 5 6; do
  STUB_HASH=$(account_field "$STUB" code_hash)
  [[ -n "$STUB_HASH" && "$STUB_HASH" != "null" && "$STUB_HASH" != "11111111111111111111111111111111" ]] && break
  sleep 2   # the deploy is not final yet; a no-code hash must not reach the allowlist
done
if [[ -n "${ADMIN_TOKEN:-}" ]]; then
  curl -s --max-time 30 -X POST "$COORDINATOR_URL/admin/hos-impl-code-hashes" \
    -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg h "$STUB_HASH" '{code_hash:$h, note:"hos-status-stub test fixture, tests/hos-status-stub"}')" >/dev/null \
    && note "stub code hash $STUB_HASH is on the coordinator's allowlist" \
    || warn "could not register the stub's code hash $STUB_HASH"
else
  note "ADMIN_TOKEN not set — the stub's code hash $STUB_HASH must already be on the allowlist, or the binding stays pending"
fi

# set_status <json> — reconfigure the partner's answer, then outwait the 5 s
# observation cache so the NEXT call is judged against the new state.
set_status() {
  near_tty "near contract call-function as-transaction $STUB set_status \
    json-args '$(jq -nc --arg s "$1" '{status_json:$s}')' prepaid-gas '30.0 Tgas' \
    attached-deposit '0 NEAR' sign-as $STUB network-config $NETWORK sign-with-keychain send" >/dev/null 2>&1 \
    || { warn "set_status did not land"; return 1; }
  sleep 7
}
set_item_info() {
  near_tty "near contract call-function as-transaction $STUB set_item_info \
    json-args '$(jq -nc --arg s "$1" '{item_info_json:$s}')' prepaid-gas '30.0 Tgas' \
    attached-deposit '0 NEAR' sign-as $STUB network-config $NETWORK sign-with-keychain send" >/dev/null 2>&1 \
    || { warn "set_item_info did not land"; return 1; }
  sleep 7
}
# The COLLECTION's answer — set on the second instance, which is what the
# coordinator asks once it has read `collection_id` off the first.
set_nft_token() {
  near_tty "near contract call-function as-transaction $OWN_COLL set_nft_token \
    json-args '$(jq -nc --arg s "$1" '{nft_token_json:$s}')' prepaid-gas '30.0 Tgas' \
    attached-deposit '0 NEAR' sign-as $OWN_COLL network-config $NETWORK sign-with-keychain send" >/dev/null 2>&1 \
    || { warn "set_nft_token did not land"; return 1; }
  sleep 7
}

# The healthy answer every case starts from, with the grant it varies.
status_json() { # <grant-json-or-null> [state] [frozen] [lease_ns] [reserve] [impl]
  jq -nc --argjson g "$1" --arg st "${2:-Active}" --arg fr "${3:-Unfrozen}" \
     --arg lu "${4:-$FUTURE_NS}" --arg rv "${5:-0}" --argjson iv "${6:-6}" \
     '{extension_enabled:true, grant:$g, state:$st, frozen:$fr,
       lease_until_ns:$lu, reserve_yocto:$rv, impl_version:$iv}'
}
GRANT_OK=$(jq -nc --arg w "$WL" --arg t "$TOKEN" --arg c "$COLL" --arg e "$FUTURE_NS" \
  '{receivers:[$w], budget_yocto:"1000000000000000000000000", spent_yocto:"0",
    tokens:{($t):{budget:"1000", spent:"0"}}, items:{($c):["1"]}, expires_at:$e}')

# The registry's answer, in the shape the registry sends it. `rotation_seq` is a
# near-sdk `U64` and arrives as a decimal STRING while `rotation_epoch` beside it
# is a plain number, and the five fields we do not read travel too — a stub that
# omits them is not evidence that a registry which sends them is understood.
#
# `owner_id` matches the binding's claim here on purpose: the divergence case is
# its own probe, and a fixture that diverged by accident would log a warning on
# every one of the twenty-two cases below.
# `rotation_epoch` is a NUMBER on the wire where `rotation_seq` is a string —
# the partner's word and the live capture — and the two are pinned together
# with `owner_id` as the account's rotation identity.
item_info_json() { # item_info_json <rotation_seq-json> [owner_id] [rotation_epoch]
  jq -nc --argjson r "$1" --arg o "${2:-$PARENT}" --argjson e "${3:-4}" --arg c "$OWN_COLL" \
    '{spec:"sharded-item-1.0.0", init:true, status:"Active", collection_id:$c,
      token_id:"stub", owner_id:$o, rotation_seq:$r, rotation_epoch:$e}'
}
# The collection's answer, in the shape the registry sends it: NEP-171
# `nft_token`, captured 2026-09-03 from `registry.tlademo.testnet` — `copies` a
# number, `extra` a STRING with JSON inside, no `approved_account_ids`. The
# owner and token agree with `item_info_json` by default; PAIR1 varies the
# owner, PAIR2 removes the token.
nft_token_json() { # nft_token_json [owner_id] [token_id]
  jq -nc --arg o "${1:-$PARENT}" --arg t "${2:-stub}" \
    '{token_id:$t, owner_id:$o,
      metadata:{title:$t, copies:1,
                extra:"{\"rented_at\":\"1787210516312653999\",\"expires_at\":\"1818746516312653999\"}"}}'
}
# A stub is evidence only for the wire form it serves.
#
# The `rotation_seq` bug hid for weeks behind a fixture that sent a JSON number
# where the chain sends a decimal string: fifty checks green over a shape nothing
# produces, and every real leased binding stuck `pending`. So before any of them
# run, the fixtures are held against the types the chain actually sends —
# captured 2026-08-28 from `alpha.tlademo.testnet`, and pinned in Rust beside the
# structs that read them (`hos::the_status_wire_form_the_partner_contract_sends`,
# `near_client::the_item_info_wire_form_the_registry_sends`).
#
# Types only. The VALUES are what each case varies; the shapes are what no case
# may vary by accident.
types_of() { jq -r 'to_entries|map("\(.key):\(.value|type)")|sort|join(" ")' <<<"$1"; }
# The GRANT is checked separately and on purpose. Measuring the status against
# `status_json null` alone pins `grant:null` and leaves out the one nested
# structure in this view — per-token budgets and item fences — which is also the
# structure whose drift refuses every spend on every leased account at once
# (`grant_unreadable`). It was written that way first.
# Shape, not names. `tokens` and `items` are keyed by CONTRACT, and those come
# from this suite's own environment — pinning them would make the guard fail
# when somebody runs it against a different token. What must not drift is the
# structure: a map to objects of two decimal strings, and a map to arrays.
grant_types_of() {
  jq -r '
    def shape:
      if type == "object" then
        if (keys|length) == 0 then "object{}"
        else "object{*:" + ([.[] | shape] | unique | join("|")) + "}" end
      elif type == "array" then "array"
      else type end;
    .grant | to_entries | map("\(.key):\(.value | shape)") | sort | join(" ")' <<<"$1"
}
CHAIN_STATUS_TYPES='extension_enabled:boolean frozen:string grant:null impl_version:number lease_until_ns:string reserve_yocto:string state:string'
CHAIN_GRANTED_TYPES='extension_enabled:boolean frozen:string grant:object impl_version:number lease_until_ns:string reserve_yocto:string state:string'
# Captured 2026-08-28 from alpha.tlademo.testnet, asked with OUR executor: a
# grant is issued to an extension, so any other name answers `"grant": null`.
# Every field below matched that capture except `items`, which is empty on the
# live grant — no item fences are configured there — so its `*:array` form comes
# from the partner's own documented example, `{"collection.near": ["1041"]}`.
# The fixture is deliberately the richer case: an empty map exercises nothing.
CHAIN_GRANT_FIELDS='budget_yocto:string expires_at:string items:object{*:array} receivers:array spent_yocto:string tokens:object{*:object{*:string}}'
CHAIN_ITEM_TYPES='collection_id:string init:boolean owner_id:string rotation_epoch:number rotation_seq:string spec:string status:string token_id:string'
CHAIN_TOKEN_TYPES='metadata:object owner_id:string token_id:string'
CHAIN_TOKEN_META_TYPES='copies:number extra:string title:string'
fixture_shape() { # fixture_shape <label> <expected> <got>
  [[ "$3" == "$2" ]] && return 0
  echo "✗ the $1 fixture no longer matches what the chain sends" >&2
  echo "    chain: $2" >&2
  echo "    stub:  $3" >&2
  exit 1
}
fixture_shape "hos_agent_status (ungranted)" "$CHAIN_STATUS_TYPES" "$(types_of "$(status_json null)")"
fixture_shape "hos_agent_status (granted)"   "$CHAIN_GRANTED_TYPES" "$(types_of "$(status_json "$GRANT_OK")")"
fixture_shape "the spend grant"              "$CHAIN_GRANT_FIELDS" "$(grant_types_of "$(status_json "$GRANT_OK")")"
fixture_shape "nft_item_info"                "$CHAIN_ITEM_TYPES" "$(types_of "$(item_info_json '"1"')")"
fixture_shape "nft_token"                    "$CHAIN_TOKEN_TYPES" "$(types_of "$(nft_token_json)")"
fixture_shape "nft_token.metadata"           "$CHAIN_TOKEN_META_TYPES" "$(types_of "$(nft_token_json | jq -c .metadata)")"
set_item_info "$(item_info_json '"1"')" || true
set_nft_token "$(nft_token_json)" || true

log "Binding the wallet to the stub as kind=hos_lease, impl_version=6"
api "$SEED_S" PUT /wallet/v1/binding \
  "$(jq -nc --arg a "$STUB" --arg o "$PARENT" '{asset_account_id:$a, owner_account_id:$o, kind:"hos_lease", impl_version:6}')" >/dev/null
assert_status "the leased binding was accepted" 200

set_status "$(status_json "$GRANT_OK")" || true
fund_account "$EXEC_S" 0.25 || warn "the executor was not funded; a refusal below may be about gas"
# Empty of custody rules on purpose: whatever refuses below is the leased
# profile speaking, not the address/limit engine §4 already covers.
store_policy "$SEED_S" "$WID_S" '{"rules":{"addresses":{"mode":"none","list":[]}}}' \
  || { echo "✗ policy not stored" >&2; exit 1; }

ST=""
for _ in 1 2 3 4 5 6 7 8; do
  api "$SEED_S" GET /wallet/v1/binding >/dev/null
  ST=$(jq -r '.binding_status // ""' <<<"$BODY"); [[ "$ST" == "active" ]] && break; sleep 4
done
if [[ "$ST" == "active" ]]; then
  pass "the leased binding is ACTIVE — the coordinator read the partner's view and believed it"
  assert_json "impl_version is echoed" '.impl_version' 6
  assert_json "the decoder version it maps to is stated" '.decoder_version' 1
else
  fail "the leased binding never went active ('$ST'): $(msg_of)"
  note "a stub that stays pending usually runs a code hash the coordinator was not told about ($STUB_HASH) — GET /admin/hos-impl-code-hashes, or run with ADMIN_TOKEN so the suite registers it; the other cause is the collection $OWN_COLL still answering null (set_nft_token did not land), which suspends the lane"
  verdict "§3.1 hos_lease via stub"; exit 1
fi

send() { log "$1"; call_ext "$SEED_S" "$STUB" "$2" >/dev/null; }

nft_env() { # <collection> <recipient> <token_id> [approval_id]
  local extra=""; [[ -n "${4:-}" ]] && extra=",\"approval_id\":$4"
  local args; args=$(printf '{"receiver_id":"%s","token_id":"%s"%s}' "$2" "$3" "$extra")
  jq -nc --arg c "$1" --arg a "$(printf '%s' "$args" | base64 | tr -d '\n')" \
    '{request:{external:[{receiver_id:$c, actions:[{action:"function_call",payload:{function_name:"nft_transfer",args:$a,deposit:"1",gas:"30000000000000"}}]}]}}'
}
ft_env() { # <token> <recipient> <amount> [deposit] [extra-arg-json]
  local args; args=$(printf '{"receiver_id":"%s","amount":"%s"%s}' "$2" "$3" "${5:-}")
  jq -nc --arg t "$1" --arg a "$(printf '%s' "$args" | base64 | tr -d '\n')" --arg d "${4:-1}" \
    '{request:{external:[{receiver_id:$t, actions:[{action:"function_call",payload:{function_name:"ft_transfer",args:$a,deposit:$d,gas:"30000000000000"}}]}]}}'
}

# ── G0 the door, and R12: the chain behind it ──────────────────────────────
#
# Two questions here, and they are not the same one.
#
# OURS. Does the pre-flight let a legal request through? A refusal would arrive
# as a 403 before anything was signed, and every refusal below would then be
# unjudgeable — they would all be the same refusal, and the suite would read as
# a wall of correct answers while enforcing nothing.
#
# THE CHAIN'S, which is acceptance R12. The stub answers views and nothing else:
# it has no `w_execute_extension`. So a request the pre-flight admits is refused
# BY THE CHAIN — and that is the one shape none of the grant walls below can
# produce, because our pre-flight mirrors every contract-side panic and nothing
# illegal gets that far on this lane.
#
# What the caller must be told is that the chain ANSWERED. A missing method is
# a fact about the account, not a bad minute: it does not change because
# somebody asked again. So `422` and not `503`, the class `chain_refused`, and
# NO `Retry-After` — which is the only thing in the answer that separates the
# two for a client that routes on headers rather than on prose.
CHAIN_HDRS=""
send_capturing_headers() {
  local env=$1 hdr out
  throttle
  hdr=$(mktemp -t hos_hdr.XXXXXX); out=$(mktemp -t hos_body.XXXXXX)
  HTTP=$(curl -sS -o "$out" -D "$hdr" -w '%{http_code}' -X POST "$COORDINATOR_URL/wallet/v1/call" \
    -H "$(AUTH_FOR "$SEED_S")" -H 'Content-Type: application/json' --max-time 90 \
    -d "$(jq -nc --arg r "$STUB" --arg a "$(b64 "$env")" \
        '{receiver_id:$r, method_name:"w_execute_extension", args_base64:$a, deposit:"1", gas:"90000000000000"}')" 2>/dev/null)
  BODY=$(tr -d '\n' < "$out"); CHAIN_HDRS=$(cat "$hdr")
  rm -f "$out" "$hdr"
}

log "G0 control — a plain transfer to a granted receiver, inside every budget"
send_capturing_headers "$(ext_transfer "$WL" "1000000000000000000000")"
if [[ "$HTTP" == "403" ]]; then
  fail "G0 a fully granted spend was refused before signing: class '$(class_of)' — every refusal below is now unjudgeable"
else
  pass "G0 the pre-flight let a granted spend through (HTTP $HTTP) — the refusals below are refusals of something"
fi

# R12 rides on the same answer: the request got past us, so what came back is
# the chain speaking.
if [[ "$HTTP" == "403" ]]; then
  skip "R12 — the pre-flight refused first, so the chain never answered and there is nothing to judge"
else
  [[ "$HTTP" == "422" ]] \
    && pass "R12 the chain's refusal arrives as 422 — an answer about the account, not an outage of ours" \
    || fail "R12 a chain refusal arrived as HTTP $HTTP; 5xx sends the caller to escalate a state only the account owner can change, and Cloudflare replaces an origin 502/504 with a page that loses this message"
  # TWO classes reach 422 and they are not interchangeable. `chain_refused` is
  # the chain answering BEFORE we signed — no transaction, no gas. This one is
  # `onchain_tx_failed`: the transaction was signed, landed and the receipt
  # failed, so it carries a `tx_hash` and the chain's own fault object. Both are
  # terminal; which one arrives tells the caller whether anything was spent.
  case "$(err_of)" in
    chain_refused|onchain_tx_failed)
      pass "R12 and it is classed '$(err_of)' — a terminal chain fact, not an outage" ;;
    *)
      fail "R12 the class is '$(err_of)', expected chain_refused or onchain_tx_failed: $(msg_of | head -c 160)" ;;
  esac
  if [[ "$(err_of)" == "onchain_tx_failed" ]]; then
    # R8 rides here: a failure the caller cannot locate on chain is a failure
    # they have to take our word for.
    [[ -n "$(jq -r '.tx_hash // ""' <<<"$BODY")" ]] \
      && pass "R12 the failed transaction is named ($(jq -r '.tx_hash' <<<"$BODY")), so the caller can read the receipt themselves" \
      || fail "R12 a transaction was signed and its hash is not in the answer — the caller cannot verify the refusal"
    [[ -n "$(jq -r '.failure // "" | tostring' <<<"$BODY")" ]] \
      && pass "R12 and the chain's own fault object is carried through rather than flattened to prose" \
      || fail "R12 the fault object was dropped"
  fi
  if grep -qiE '^retry-after:' <<<"$CHAIN_HDRS"; then
    fail "R12 the refusal carries a Retry-After — the caller is being told to retry a method that does not exist"
  else
    pass "R12 and it carries NO Retry-After, so a well-behaved client stops instead of spinning"
  fi
  grep -qiE 'try again|retry|temporar|momentarily' <<<"$(msg_of)" \
    && finding "the chain's terminal refusal invites a retry in prose ('$(msg_of | head -c 80)…') while the headers say it is final" \
    || pass "R12 and the sentence promises nothing a retry would change"
fi

# HERE, not at the end of the file, and that is not cosmetic: the cases below
# walk the binding through faults that END it — an expired lease, an ownership
# rotation — after which no call succeeds and a probe needing a HEALTHY lane
# cannot tell its own failure from the fixture's. Written at the tail first,
# this ran after the rotation and reported the lane shut when the lane had been
# shut on purpose two cases earlier.
# ── W. the partner's lifecycle webhook, and what it can honestly prove ─────
#
# §6 of the plan asks for one thing above all: their revoke stops the agent NOW,
# not when our 5 s observation cache happens to expire.
#
# That exact claim CANNOT be driven from outside, and the reason is worth
# writing down rather than rediscovering. The cache is written and read in ONE
# place — `preflight_extension_call` — so the only way to warm it is a call that
# also broadcasts a transaction. The write happens at the start of that request
# and the answer comes back seconds later, so by the time a test can send the
# NEXT call, most of the 5 s window is already spent. Measured here: the cached
# ALLOW was gone before the follow-up call could even start. A probe built on
# that race would pass or fail on network latency, and a green run would say
# nothing about the webhook.
#
# What IS judgeable, and what this probe pins:
#   W1  the endpoint re-reads the CHAIN rather than believing its caller: the
#       body says `frozen`, and the answer must carry the status the chain
#       actually reports, not the word in the request
#   W2  after the event, the lane is refused with the fault the chain reports
#   W3  the zone fence: outside the zones the same event answers `unbound`,
#       the answer an account we do not hold would get — silent by design, so
#       the endpoint cannot be used to map whose accounts we hold
#
# None proves the invalidation beat the TTL. W1 would fail if the webhook were
# a no-op that returned a canned answer, which is the failure this section
# exists to catch.
#
# THE FENCE COMES FIRST. `allowed_zones` (the `BINDING_WEBHOOK_SUFFIXES` env
# plus the `binding_webhook_zones` table) is configured on this deployment, and
# an account outside it is answered `unbound` BEFORE the chain is looked at. The
# stub lives under $PARENT, outside every zone — so the only way to make the
# webhook look at it is to admit $PARENT for the length of this section, and a
# W1 that accepted `unbound` would be reading the fence and calling it the
# chain. Removed again below and in `cleanup`.
log "W the partner's lifecycle webhook re-reads the chain"
WH_SECRET="${BINDING_WEBHOOK_SECRET:-}"
wh_event() { # echoes the binding_status the webhook reports for the stub
  curl -sS -m 30 -X POST "$COORDINATOR_URL/wallet/v1/binding/events" \
    -H "X-Binding-Webhook-Secret: $WH_SECRET" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg a "$STUB" '{asset_account_id:$a, event:"frozen"}')" 2>/dev/null \
    | jq -r '.binding_status // ""'
}
if [[ -z "$WH_SECRET" ]]; then
  skip "W — set BINDING_WEBHOOK_SECRET (it lives in prod_configs/coordinator/.env.testnet) to judge the webhook"
elif [[ -z "${ADMIN_TOKEN:-}" ]]; then
  skip "W — the stub is outside the webhook's zones and only ADMIN_TOKEN can admit it; without it every answer is the fence's, not the chain's"
elif [[ "$(adm POST /admin/binding-zones "$(jq -nc --arg s "$PARENT" '{suffix:$s, note:"e2e webhook probe, removed by the suite"}')")" != 2?? ]]; then
  skip "W — could not admit $PARENT to the webhook's zones, so the webhook would never look at the stub"
elif ! { W_ZONE_ADDED=1; set_status "$(status_json "$GRANT_OK" Active SelfFrozen)"; }; then
  skip "W — the stub would not report a frozen account, so there is nothing for the event to find"
else
  WH_STATUS=$(wh_event)
  note "W the event answered: '${WH_STATUS:-nothing}'"
  # `frozen` is reversible, so the chain's answer for this account is exactly
  # `suspended`. `unbound` is the fence speaking for an account we hold and
  # just admitted — the webhook did not look; anything else is a webhook that
  # believed its caller or answered from memory.
  if [[ "$WH_STATUS" == "suspended" ]]; then
    pass "W1 the event re-read the chain and reported 'suspended' — the body was a hint, the chain was the answer"
  elif [[ "$WH_STATUS" == "unbound" ]]; then
    fail "W1 the event answered 'unbound' for an account we hold and just admitted to the zones — the fence answered, the chain was never asked"
  else
    fail "W1 the event answered '${WH_STATUS:-nothing}' for an account the chain reports as frozen: either it believed the request or it did not look"
  fi

  send "W2 a spend right after the event" "$(ext_transfer "$WL" "1000000000000000000000")"
  assert_class "W2 the lane is refused with the fault the chain reports" "account_frozen"

  # ── W3 the zone fence, switched back off ─────────────────────────────────
  if [[ "$(adm DELETE "/admin/binding-zones/$PARENT")" == 2?? ]]; then
    W_ZONE_ADDED=""
    W3_FENCED=$(wh_event)
    if [[ "$W3_FENCED" == "unbound" ]]; then
      pass "W3 fenced out, the same event answers 'unbound' where it answered '$WH_STATUS' — the zone is the door, and the answer is the one an account we do not hold would get"
    else
      fail "W3 with $PARENT no longer in the zones the webhook still answered '${W3_FENCED:-nothing}' — the fence does not fence, and an operator who configures a zone is getting a promise the code does not keep"
    fi
  else
    fail "W3 THE ZONE '$PARENT' COULD NOT BE REMOVED — the webhook is still admitting it; cleanup retries, else remove it by hand"
  fi

  # RESTORE. Everything below reads the healthy grant this suite set up, and a
  # probe that leaves the stub frozen turns twenty-two later cases into
  # `account_frozen` — which is how this one was first written.
  set_status "$(status_json "$GRANT_OK")" \
    || fail "W the stub could not be returned to a healthy state — every case below is now judging a frozen account"
fi

# ── the grant ladder, in the contract's own order ──────────────────────────
send "G1 a receiver the grant never named (plain transfer)" "$(ext_transfer "$OUTSIDER" "1000000000000000000000")"
assert_class "G1" "receiver_not_granted"
assert_json "G1 names the promise it is about" '.promise_index' 0

send "G2 a receiver the grant never named, reached through a token call" "$(ft_env "$TOKEN" "$OUTSIDER" 5)"
assert_class "G2 (rung 8: only known once the arguments parsed)" "receiver_not_granted"

send "G3 a token the grant never named" "$(ft_env "$OTHER_TOKEN" "$WL" 5)"
assert_class "G3" "token_not_granted"

send "G4 a granted token, over its own budget" "$(ft_env "$TOKEN" "$WL" 5000)"
assert_class "G4" "token_budget_exceeded"

send "G5 native spending past the granted cap" "$(ext_transfer "$WL" "2000000000000000000000000")"
assert_class "G5" "grant_exhausted"
assert_json "G5 names the promise that breached it" '.promise_index' 0

send "G6 a collection the grant never named" "$(nft_env "$OTHER_COLL" "$WL" 1)"
assert_class "G6 — NOT item_not_granted: adding a token_id to a collection nobody granted is the fix that cannot work" "collection_not_granted"

send "G7 a granted collection, an item outside the fence" "$(nft_env "$COLL" "$WL" 9)"
assert_class "G7" "item_not_granted"

send "G8 the account's OWN collection" "$(nft_env "$OWN_COLL" "$WL" 1)"
assert_class "G8 — a grant can never move this account's own names" "own_collection_refused"

# ── the call FORM ──────────────────────────────────────────────────────────
send "F1 a granted spend that redirects refunds" "$(ext_transfer "$WL" "1000000000000000000000" "$OUTSIDER")"
assert_class "F1" "grant_shape_violation:refund_target_not_allowed"

MIXED=$(jq -nc --arg t "$TOKEN" --arg w "$WL" \
  --arg a "$(printf '{"receiver_id":"%s","amount":"5"}' "$WL" | base64 | tr -d '\n')" \
  '{request:{external:[{receiver_id:$t, actions:[
      {action:"function_call",payload:{function_name:"ft_transfer",args:$a,deposit:"1",gas:"30000000000000"}},
      {action:"transfer",payload:{amount:"1"}}]}]}}')
send "F2 a token call sharing its promise with another action" "$MIXED"
assert_class "F2" "grant_shape_violation:grant_call_must_stand_alone"

send "F3 a token call attaching more than the mandated yocto" "$(ft_env "$TOKEN" "$WL" 5 2)"
assert_class "F3" "grant_shape_violation:grant_call_deposit"

send "F4 an nft_transfer spending an approval" "$(nft_env "$OTHER_COLL" "$WL" 1 7)"
assert_class "F4 — approval_id (rung 7) answers before the collection lookup (rung 9)" "grant_shape_violation:grant_approval_not_allowed"

send "F5 a token call carrying an argument the contract cannot parse" "$(ft_env "$TOKEN" "$WL" 5 1 ',"note":"x"')"
assert_class "F5" "grant_shape_violation:grant_args_unreadable"

SD=$(jq -nc --arg t "$TOKEN" --arg a "$(printf '{"account_id":"%s"}' "$WL" | base64 | tr -d '\n')" \
  '{request:{external:[{receiver_id:$t, actions:[{action:"function_call",payload:{function_name:"storage_deposit",args:$a,deposit:"1",gas:"30000000000000"}}]}]}}')
send "F6 storage_deposit under a grant" "$SD"
assert_class "F6 — a grant covers ft_transfer and nft_transfer only" "grant_shape_violation:grant_method_not_allowed"

SI=$(jq -nc --arg w "$WL" \
  '{request:{external:[{receiver_id:$w, actions:[{action:"deterministic_state_init",payload:{code:"AA==",deposit:"1"}}]}]}}')
send "F7 deploying code under a grant" "$SI"
if [[ "$(class_of)" == "grant_shape_violation:grant_action_not_allowed" ]]; then
  pass "F7 — a grant never deploys code (class $(class_of))"
else
  assert_denied "F7 deploying code under a grant is refused" && note "  class: $(class_of), $(msg_of | head -c 140)"
fi

# ── multi-fault: the FIRST class is the one the contract would panic on ────
BOTH=$(jq -nc --arg o "$OUTSIDER" \
  '{request:{external:[{receiver_id:$o, actions:[{action:"transfer",payload:{amount:"9000000000000000000000000"}}]}]}}')
send "M1 an ungranted receiver AND a spend past the budget, in one promise" "$BOTH"
assert_class "M1 the receiver (rung 2) answers before the budget (rung 4)" "receiver_not_granted"
assert_json "M1 says how many further violations the request carries" '.additional_violations' 1

TWO=$(jq -nc --arg w "$WL" --arg o "$OUTSIDER" \
  '{request:{external:[
     {receiver_id:$w, actions:[{action:"transfer",payload:{amount:"1000000000000000000000"}}]},
     {receiver_id:$o, actions:[{action:"transfer",payload:{amount:"1000000000000000000000"}}]}]}}')
send "M2 a legal promise 0 and an illegal promise 1" "$TWO"
assert_class "M2" "receiver_not_granted"
assert_json "M2 blames promise 1, not the request as a whole" '.promise_index' 1

# ── legal shapes that must NOT be refused ─────────────────────────────────
MULTI=$(jq -nc --arg w "$WL" \
  '{request:{external:[{receiver_id:$w, actions:[
      {action:"transfer",payload:{amount:"1000000000000000000000"}},
      {action:"transfer",payload:{amount:"1000000000000000000000"}}]}]}}')
send "L1 several transfers in ONE promise — the contract accepts these" "$MULTI"
[[ "$HTTP" == "403" ]] \
  && fail "L1 refused a request the chain would have executed: class '$(class_of)' — $(msg_of | head -c 140)" \
  || pass "L1 not refused (HTTP $HTTP) — only a promise carrying a CALL must stand alone"

send "L2 a memo alongside the standard ft_transfer arguments" "$(ft_env "$TOKEN" "$WL" 5 1 ',"memo":"invoice 7"')"
[[ "$HTTP" == "403" ]] \
  && fail "L2 refused a legal memo: class '$(class_of)' — $(msg_of | head -c 140)" \
  || pass "L2 not refused (HTTP $HTTP) — memo is part of the standard"

# ── the door rules answer ALONE, before any promise ───────────────────────
if set_status "$(status_json null)"; then
  send "D1 no grant at all" "$(ext_transfer "$WL" "1000000000000000000000")"
  assert_class "D1" "grant_missing"
fi

GRANT_EXPIRED=$(jq -nc --arg w "$WL" --arg e "$PAST_NS" \
  '{receivers:[$w], budget_yocto:"1000000000000000000000000", spent_yocto:"0", tokens:{}, items:{}, expires_at:$e}')
if set_status "$(status_json "$GRANT_EXPIRED")"; then
  send "D2 an expired grant, with a request that ALSO breaks the form" "$(ext_transfer "$OUTSIDER" "1" "$OUTSIDER")"
  assert_class "D2 the expiry answers alone — the owner is not sent to fix the form of a request no grant covers" "grant_expired"
  assert_json "D2 no promise is blamed for a door rule" '.promise_index' ""
fi

GRANT_SPENT=$(jq -nc --arg w "$WL" --arg e "$FUTURE_NS" \
  '{receivers:[$w], budget_yocto:"1000", spent_yocto:"1000", tokens:{}, items:{}, expires_at:$e}')
if set_status "$(status_json "$GRANT_SPENT")"; then
  send "D3 a grant whose budget is already spent" "$(ext_transfer "$WL" "1000000000000000000000")"
  assert_class "D3" "grant_exhausted"
fi

# ── the reserve floor ─────────────────────────────────────────────────────
if set_status "$(status_json "$GRANT_OK" Active Unfrozen "$FUTURE_NS" "1000000000000000000000000000")"; then
  send "R1 a spend that would leave the account below its reserve floor" "$(ext_transfer "$WL" "1000000000000000000000")"
  assert_class "R1 — the floor tracks live storage and only the chain knows it" "insufficient_vs_reserve"
fi

# ── lifecycle faults (§6, leased half) ────────────────────────────────────
for spec in \
  "frozen|SelfFrozen|account_frozen|a frozen account" \
  "state|Parked|account_not_active|a parked account" \
  "state|Suspended|account_not_active|a suspended account"
do
  field=${spec%%|*}; rest=${spec#*|}; val=${rest%%|*}; rest=${rest#*|}; cls=${rest%%|*}; desc=${rest#*|}
  if [[ "$field" == "frozen" ]]; then S=$(status_json "$GRANT_OK" Active "$val"); else S=$(status_json "$GRANT_OK" "$val"); fi
  if set_status "$S"; then
    send "C-$val $desc" "$(ext_transfer "$WL" "1000000000000000000000")"
    assert_class "C-$val" "$cls"
    [[ "$(jq -r '.terminal' <<<"$BODY")" == "false" ]] \
      && pass "C-$val is marked reversible — the owner can lift it" \
      || note "  terminal=$(jq -r '.terminal' <<<"$BODY")"
    # The status read says the same thing the refusal did — in the field, not
    # in a log. Whoever polls the binding learns WHAT to lift.
    api "$SEED_S" GET /wallet/v1/binding >/dev/null
    assert_json "C-$val the status read carries the reason" '.status_reason' "$cls"
  fi
done

if set_status "$(status_json "$GRANT_OK" Active Unfrozen "$PAST_NS")"; then
  send "C-lease a lease that has run out" "$(ext_transfer "$WL" "1000000000000000000000")"
  assert_class "C-lease" "lease_expired"
  assert_json "C-lease is terminal — the lane is over" '.terminal' true
fi

if set_status "$(status_json "$GRANT_OK" Active Unfrozen "$FUTURE_NS" 0 5)"; then
  send "C-version an implementation this build has no decoder for" "$(ext_transfer "$WL" "1000000000000000000000")"
  assert_class "C-version (K8/R9)" "unsupported_wallet_implementation"
  api "$SEED_S" GET /wallet/v1/binding >/dev/null
  assert_json "C-version the status read names the version gate — the lock the operator fixes with one row" '.status_reason' "unsupported_wallet_implementation"
fi

if set_status '{"extension_enabled":true,"grant":null,"state":"Active","frozen":"Unfrozen","lease_until_ns":"not a number","reserve_yocto":"0","impl_version":6}'; then
  send "C-malformed a lease_until_ns that is not a number" "$(ext_transfer "$WL" "1000000000000000000000")"
  assert_class "C-malformed — schema drift shows up as itself, not as a fake 'lease expired'" "chain_status_unreadable"
fi

if set_status "$(jq -nc --argjson g "$GRANT_OK" '{extension_enabled:false, grant:$g, state:"Active", frozen:"Unfrozen", lease_until_ns:"4000000000000000000", reserve_yocto:"0", impl_version:6}')"; then
  send "C-disabled the executor is no longer in the control set" "$(ext_transfer "$WL" "1000000000000000000000")"
  assert_class "C-disabled" "executor_not_in_control_set"
fi

if set_status '{}'; then
  send "C-empty a view that answers with nothing at all" "$(ext_transfer "$WL" "1000000000000000000000")"
  assert_denied "C-empty every default is the value that FAILS verification" "agent_connect_denied"
  note "  class: $(class_of)"
fi

# ── the collection's word against the account's ───────────────────────────
#
# The account's `nft_item_info` is held against its collection's `nft_token`,
# for the one thing a collection can vouch for: that it MINTED the token the
# account names. Ownership is not the collection's to contradict — it lives on
# the item and moves there — so a different `owner_id` on the registry changes
# nothing (PAIR1), while a token the registry has no record of is the hard fail
# (PAIR2). Reversible on purpose: a registry can trail the account by a block,
# so the fault suspends and the lane returns the moment the record is there.
#
# The spend is the property, not the status. The pre-flight does not consult
# the stored status; it re-observes the chain. A pairing that only the status
# refresh performed would show `suspended` on GET and admit the spend anyway.
if set_status "$(status_json "$GRANT_OK")"; then
  if set_nft_token "$(nft_token_json somebody-else.testnet)"; then
    api "$SEED_S" GET /wallet/v1/binding >/dev/null
    assert_json "PAIR1 the collection names another owner → the item wins, the binding stays ACTIVE" '.binding_status' active
    send "PAIR1' a spend while the collection names another owner" "$(ext_transfer "$WL" "1000000000000000000000")"
    if [[ "$HTTP" == "403" ]]; then
      fail "PAIR1' the gate refused on the registry's owner (class '$(class_of)') — ownership is the item's, the registry only proves the mint"
    else
      pass "PAIR1' the gate let the spend through (HTTP $HTTP) — the registry's owner is not compared"
    fi
  fi
  if set_nft_token null; then
    api "$SEED_S" GET /wallet/v1/binding >/dev/null
    assert_json "PAIR2 the collection has no such token → the binding is SUSPENDED, not revoked" '.binding_status' suspended
    assert_json "PAIR2 and the status read says why" '.status_reason' registry_disagrees
    send "PAIR2' a spend while the collection has no such token (NEP-171 null)" "$(ext_transfer "$WL" "1000000000000000000000")"
    if assert_class "PAIR2' refused by the gate itself — a null answer is the collection speaking, not a transport problem" "registry_disagrees"; then
      # `bool_of`, not `assert_json`: the latter reads through `// ""`, and a
      # JSON `false` falls through that to the empty string.
      [[ "$(bool_of terminal)" == "false" ]] \
        && pass "PAIR2' and the refusal is NOT terminal — the registry may be a block behind" \
        || fail "PAIR2' terminal is '$(bool_of terminal)', expected false — a lagging registry would send the agent away for good"
    fi
  fi
  if set_nft_token "$(nft_token_json)"; then
    api "$SEED_S" GET /wallet/v1/binding >/dev/null
    assert_json "PAIR3 the record is back → the lane returns without re-binding" '.binding_status' active
    [[ "$(bool_of status_reason)" == "absent" ]] \
      && pass "PAIR3 and the reason is gone with the fault — nothing stale on an active row" \
      || fail "PAIR3 an active row still carries status_reason='$(jq -r '.status_reason' <<<"$BODY")'"
    send "PAIR3' a spend once the collection has the token again" "$(ext_transfer "$WL" "1000000000000000000000")"
    if [[ "$HTTP" == "403" ]]; then
      fail "PAIR3' the gate still refuses after the record returned: class '$(class_of)'"
    else
      pass "PAIR3' the gate let the spend through again (HTTP $HTTP)"
    fi
  fi
fi

# ── a migration renumbers the seq; only a change INSIDE an epoch is a sale ──
#
# The partner's rule (2026-09-04): the seq is numbered within `rotation_epoch`,
# a migration of the implementation moves the epoch and may reset the seq, and
# a pin that carried only the seq would read that reset as a sale and end a
# live binding. So: same epoch, any change to seq ends the lane; epoch moves
# under the SAME owner, the pin is re-established at the current identity and
# the lane stays. Not "increase only" — a reset takes the seq to 0, and a pin
# waiting for a larger number would sit on a dead binding still live (ROT below
# rotates DOWN on purpose for exactly that reason). And the gap they named
# after (2026-09-07): across the boundary the counters cannot tell an upgrade
# from a sale during it — the OWNER on the item can, and OWN-MIG below is that
# case.
#
# MIG' alone proves little — the gate does not judge rotation, so the spend
# would pass unpinned too. The PROOF that MIG re-pinned at (5, 7) is ROT: a seq
# change inside epoch 5 must end the lane, and against a pin still at (4, 1) it
# would read as another migration and leave it active. Keep the two in the
# same epoch.
if set_status "$(status_json "$GRANT_OK")"; then
  api "$SEED_S" GET /wallet/v1/binding >/dev/null
  note "status before the migration: $(jq -r '.binding_status' <<<"$BODY") (pinned at epoch 4, seq 1)"
  # Epoch 4 → 5 AND the seq renumbered 1 → 7 in the same answer: the seq alone
  # says "rotation", the pair says "migration".
  if set_item_info "$(item_info_json '"7"' "" 5)"; then
    api "$SEED_S" GET /wallet/v1/binding >/dev/null
    assert_json "MIG the epoch moved and the seq was renumbered → the binding STAYS active, re-pinned at the new pair" '.binding_status' active
    send "MIG' a spend after the migration" "$(ext_transfer "$WL" "1000000000000000000000")"
    if [[ "$HTTP" == "403" ]]; then
      fail "MIG' the spend was refused after a migration (class '$(class_of)') — a renumbered seq was read as a sale"
    else
      pass "MIG' the gate let the spend through (HTTP $HTTP) — a migration is not a sale"
    fi
  fi
fi

# ── ownership rotation ends the lane ──────────────────────────────────────
if set_status "$(status_json "$GRANT_OK")"; then
  api "$SEED_S" GET /wallet/v1/binding >/dev/null
  note "status before rotation: $(jq -r '.binding_status' <<<"$BODY") (pinned at epoch 5, seq 7)"
  # Same epoch, seq 7 → 2. DOWN on purpose: a pin that only watched for an
  # increase would miss this. And the NUMBER spelling on purpose: the rotation
  # must be judged by VALUE, not by the JSON type it arrived as — "7" (string)
  # → 2 (number) is a rotation and nothing else.
  if set_item_info "$(item_info_json 2 "" 5)"; then
    api "$SEED_S" GET /wallet/v1/binding >/dev/null
    ST2=$(jq -r '.binding_status // ""' <<<"$BODY")
    if [[ "$ST2" == "revoked" || "$HTTP" == "404" ]]; then
      pass "ROT the account changed owners inside the epoch and the binding ended — the previous owner's authorization does not carry"
    else
      fail "ROT rotation_seq moved 7 → 2 inside epoch 5 and the binding is still '$ST2' (HTTP $HTTP)"
    fi
    send "ROT' a spend after the rotation" "$(ext_transfer "$WL" "1000000000000000000000")"
    # Two questions, and only the first is a security property.
    #
    # SAFETY: the spend must not go through, and the refusal must be terminal —
    # the previous owner's authorization does not survive a sale, and an agent
    # that retries is spinning against an account that is no longer its owner's.
    #
    # DIAGNOSIS: the refusal should say WHY. A rotation ends a binding, and the
    # owner needs to read that. What actually arrives is the leased-mode version
    # gate — true (the binding that carried `impl_version` is gone) but it sends
    # the reader to state a version when the real event was a change of owner.
    # Reported rather than failed: nothing is unsafe, and it is the partner who
    # will read it.
    if assert_denied "ROT' refused after the rotation"; then
      if grep -qiE "binding|rotat|revok|not live|no bound" <<<"$BODY"; then
        pass "ROT' and the refusal names the BINDING — the owner is sent to the thing that changed"
      else
        finding "after an ownership rotation the spend is refused as '$(err_of)' with '$(msg_of | head -c 110)…' — safe, but it names the impl_version gate rather than the rotation that ended the binding, so an owner reads it as a missing field instead of a sold account"
      fi
    fi
  fi
fi

# ── a sale DURING an upgrade: the counters say "migration", the owner says "sold" ─
#
# ROT ended the lane, so this needs a fresh binding on the same stub: the
# revoked row is history, a new PUT is a new authorization (lifecycle §R5 covers
# re-binding itself). It activates at the item's current identity — epoch 5,
# seq 2, owner $PARENT — and then the item reports epoch 6, seq 0 under ANOTHER
# owner: exactly what a name sold inside the upgrade window looks like, and
# exactly what MIG looked like on the counters alone. The owner is the
# difference, and the binding must END, not re-pin.
log "OWN-MIG · re-binding after the rotation, then an upgrade under a new owner"
api "$SEED_S" PUT /wallet/v1/binding \
  "$(jq -nc --arg a "$STUB" --arg o "$PARENT" '{asset_account_id:$a, owner_account_id:$o, kind:"hos_lease", impl_version:6}')" >/dev/null
if assert_status "OWN-MIG a fresh binding after the ended one is accepted" 200; then
  ST=""
  for _ in 1 2 3 4 5 6 7 8; do
    api "$SEED_S" GET /wallet/v1/binding >/dev/null
    ST=$(jq -r '.binding_status // ""' <<<"$BODY"); [[ "$ST" == "active" ]] && break; sleep 4
  done
  if [[ "$ST" != "active" ]]; then
    fail "OWN-MIG the fresh binding never went active ('$ST'): $(msg_of)"
  else
    pass "OWN-MIG the fresh binding is ACTIVE, pinned at epoch 5, seq 2, owner $PARENT"
    if set_item_info "$(item_info_json '"0"' somebody-else.testnet 6)"; then
      api "$SEED_S" GET /wallet/v1/binding >/dev/null
      ST2=$(jq -r '.binding_status // ""' <<<"$BODY")
      if [[ "$ST2" == "revoked" || "$HTTP" == "404" ]]; then
        pass "OWN-MIG the epoch moved AND the owner changed → the binding ENDED — a sale inside the upgrade window is a sale"
      else
        fail "OWN-MIG epoch 5 → 6 with a new owner and the binding is still '$ST2' (HTTP $HTTP) — the re-pin took the new pair as given and a sold name kept its binding"
      fi
      send "OWN-MIG' a spend after the sale-during-upgrade" "$(ext_transfer "$WL" "1000000000000000000000")"
      assert_class "OWN-MIG' refused as the lane having ENDED" "binding_ended" \
        && assert_json "OWN-MIG' terminal" '.terminal' true
    fi
  fi
fi

verdict "§3.1 hos_lease via stub"
