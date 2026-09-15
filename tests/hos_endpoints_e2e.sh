#!/usr/bin/env bash
#
# §2 of the HoS test plan — every endpoint on the partner's method list, run
# through the classes that apply to it: HAPPY / AUTHZ / INPUT / BYPASS / STATE
# / DoS.
#
# `binding_lifecycle_e2e.sh` already drives the happy path of PUT/GET/DELETE
# and the setup kit (L1–L8) and is not repeated here. What this adds is
# everything that is NOT the happy path, plus the endpoints that appeared with
# the fund lane: `/binding/balance`, `/binding/transfer`, `/binding/events`,
# and the regression that the own-wallet endpoints still mean the wallet.
#
# Most probes cost nothing on chain: a refusal is decided before anything is
# signed, and a PUT names an account without proving anything about it (that
# is the point of `pending`). The two that do spend are marked.
#
#   PARENT=you.testnet ./tests/hos_endpoints_e2e.sh --apply
#
# Needs the shared fixture (tests/hos_fixture.sh --apply).

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/hos_common.sh"

HOS_STATE="${HOS_STATE:-$REPO_ROOT/tests/.hos_fixture.env}"
[[ "${1:-}" == "--apply" ]] || { sed -n '3,20p' "$0" >&2; echo "  Pass --apply to run." >&2; exit 0; }
hos_require
[[ -f "$HOS_STATE" ]] || { echo "✗ no fixture — run tests/hos_fixture.sh --apply first" >&2; exit 1; }
# shellcheck disable=SC1090
source "$HOS_STATE"

WL="${WL:-zavodil2.testnet}"
# The setup kit refuses any account that already runs code, and zavodil2 does.
# So the kit's happy path needs an account created for it — cheap, and deleted
# on the way out.
EMPTY="hos-empty-$(openssl rand -hex 3).$PARENT"
SEED_A="hos-ep-a-$(date +%s)-$$"
SEED_B="hos-ep-b-$(date +%s)-$$"
read -r WID_A EXEC_A < <(wallet_address "$SEED_A")
read -r WID_B EXEC_B < <(wallet_address "$SEED_B")
[[ -n "$WID_A" && -n "$WID_B" ]] || { echo "✗ could not mint the throwaway wallets" >&2; exit 1; }
note "throwaway wallets: A=$WID_A B=$WID_B"
log "Creating $EMPTY — an account with no code, for the setup kit"
create_subaccount "$EMPTY" 0.1 || { echo "✗ $EMPTY never appeared" >&2; exit 1; }

# The fixture wallet's policy is whatever the previously-run suite left on it,
# and E11 spends through it. Set our own: no suite may be judged against
# another suite's policy, or the failure lands on whichever ran second.
log "Setting this suite's own policy on the fixture wallet"
store_policy "$SEED" "$WALLET_ID" \
  "$(jq -nc --arg s "$ASSET" --arg w "$WL" --arg e "$EMPTY" \
     '{rules:{addresses:{mode:"whitelist",list:[$s,$w,$e]},limits:{per_transaction:{native:"1000000000000000000000000"}}}}')" \
  || warn "the suite policy could not be stored — E11's spend may be refused by an inherited rule"

cleanup() {
  local rc=$?
  api "$SEED_A" DELETE /wallet/v1/binding >/dev/null 2>&1 || true
  api "$SEED_B" DELETE /wallet/v1/binding >/dev/null 2>&1 || true
  account_exists "$EMPTY" && { note "cleaning up $EMPTY"; delete_account "$EMPTY"; }
  return $rc
}
trap cleanup EXIT

put() { api "$1" PUT /wallet/v1/binding "$2" >/dev/null; }

# ── E1 AUTHZ: every endpoint refuses an unauthenticated caller ──────────────
log "E1 no Authorization header anywhere on the binding surface"
for spec in \
  "PUT|/wallet/v1/binding|{\"asset_account_id\":\"$WL\",\"kind\":\"personal_account\"}" \
  "GET|/wallet/v1/binding|" \
  "DELETE|/wallet/v1/binding|" \
  "GET|/wallet/v1/binding/setup?kind=personal_account|" \
  "GET|/wallet/v1/binding/balance|" \
  "POST|/wallet/v1/binding/transfer|{\"to\":\"$WL\",\"amount\":\"1\"}"
do
  m=${spec%%|*}; rest=${spec#*|}; p=${rest%%|*}; b=${rest#*|}
  api - "$m" "$p" "$b" >/dev/null
  assert_status "E1 $m $p" 401
done

# ── E2 GET on a wallet that has no binding ─────────────────────────────────
log "E2 GET /binding on an unbound wallet"
api "$SEED_A" GET /wallet/v1/binding >/dev/null
assert_status "E2 unbound GET" 404

# ── E3 PUT input validation ────────────────────────────────────────────────
log "E3 PUT input validation"
IMPLICIT="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
LONGNAME="$(python3 -c 'print("a"*300)').testnet"

put "$SEED_A" "$(jq -nc --arg a "$WL" '{asset_account_id:$a, kind:"leased"}')"
assert_denied "E3a unknown kind" && assert_msg "E3a names the accepted kinds" "hos_lease.*personal_account|kind must be"

put "$SEED_A" '{"kind":"personal_account"}'
assert_denied "E3b asset_account_id missing"

put "$SEED_A" "$(jq -nc --arg a "$IMPLICIT" '{asset_account_id:$a, kind:"personal_account"}')"
assert_denied "E3c a 64-hex implicit account" && assert_msg "E3c says a named account is required" "implicit|named account"

put "$SEED_A" "$(jq -nc --arg a "$EXEC_A" '{asset_account_id:$a, kind:"personal_account"}')"
assert_denied "E3d the wallet's OWN executor as the asset" \
  && assert_msg "E3d says which rule bit — an implicit executor is caught by the named-account rule first" "own executor|implicit"

put "$SEED_A" '{"asset_account_id":"Bad Name!.testnet","kind":"personal_account"}'
assert_denied "E3e an invalid account id"

put "$SEED_A" "$(jq -nc --arg a "$LONGNAME" '{asset_account_id:$a, kind:"personal_account"}')"
assert_denied "E3f a 300-character account id"

api_raw "$SEED_A" PUT /wallet/v1/binding 'this is not json at all'
assert_denied "E3g a body that is not JSON"

put "$SEED_A" "$(jq -nc --arg a "$WL" '{asset_account_id:$a, kind:"hos_lease", owner_account_id:"owner.testnet"}')"
assert_denied "E3h hos_lease without impl_version" && assert_msg "E3h names the field" "impl_version"

put "$SEED_A" "$(jq -nc --arg a "$WL" '{asset_account_id:$a, kind:"hos_lease", owner_account_id:"owner.testnet", impl_version:999}')"
assert_denied "E3i hos_lease with an unsupported impl_version (§3.2 version gate)" \
  && assert_msg "E3i names the supported versions and says it is terminal" "supported|terminal"

put "$SEED_A" "$(jq -nc --arg a "$WL" '{asset_account_id:$a, kind:"hos_lease", impl_version:6}')"
assert_denied "E3j hos_lease without owner_account_id" && assert_msg "E3j names the field" "owner_account_id"

put "$SEED_A" "$(jq -nc --arg a "$WL" '{asset_account_id:$a, kind:"personal_account", owner_account_id:"someone-else.testnet"}')"
assert_denied "E3k personal_account with an owner that is not the account" && assert_msg "E3k says the owner IS the account" "owner IS the account|must equal"

put "$SEED_A" "$(jq -nc --arg a "$WL" '{asset_account_id:$a, kind:"personal_account", impl_version:1}')"
assert_denied "E3l personal_account with impl_version — refused, not ignored" && assert_msg "E3l names the field" "impl_version"

# ── E4 the body cannot name a different wallet ─────────────────────────────
log "E4 PUT carrying wallet_id of ANOTHER wallet in the body"
put "$SEED_A" "$(jq -nc --arg a "$EMPTY" --arg w "$WID_B" '{asset_account_id:$a, kind:"personal_account", wallet_id:$w}')"
if [[ "$HTTP" == "200" ]]; then
  [[ "$(jq -r '.wallet_id' <<<"$BODY")" == "$WID_A" ]] \
    && pass "E4 the binding belongs to the AUTHENTICATED wallet, not the one the body named" \
    || fail "E4 the body's wallet_id was honoured — a caller could bind somebody else's wallet"
  api "$SEED_B" GET /wallet/v1/binding >/dev/null
  assert_status "E4 wallet B is still unbound" 404
else
  fail "E4 PUT failed ($HTTP): $(msg_of)"
fi

# ── E5 exclusivity: pending claims nothing, active is exclusive ────────────
log "E5 a second wallet naming the SAME account while A's row is only pending"
put "$SEED_B" "$(jq -nc --arg a "$EMPTY" '{asset_account_id:$a, kind:"personal_account"}')"
if [[ "$HTTP" == "200" ]]; then
  pass "E5 a pending row is anyone's claim to make and nobody's to keep — B was not blocked by A's"
else
  fail "E5 B was blocked ($HTTP) by a row that authorizes nothing: $(msg_of)"
fi
log "E5' the same wallet naming the fixture's ACTIVE account"
put "$SEED_B" "$(jq -nc --arg a "$ASSET" '{asset_account_id:$a, kind:"personal_account"}')"
assert_denied "E5' an account already operated by another wallet" \
  && assert_msg "E5' says which wallet must release it first" "another wallet|already bound|already operated"

# ── E6 STATE: DELETE then re-bind ──────────────────────────────────────────
log "E6 DELETE, then PUT the same account again"
api "$SEED_B" DELETE /wallet/v1/binding >/dev/null; H1=$HTTP
api "$SEED_B" DELETE /wallet/v1/binding >/dev/null; H2=$HTTP
[[ "$H1" =~ ^2 ]] && pass "E6 DELETE removed it (HTTP $H1)" || fail "E6 DELETE answered $H1"
[[ "$H2" =~ ^2 ]] && pass "E6 a second DELETE is still a success (HTTP $H2) — cleanup can be re-run" \
  || fail "E6 the second DELETE answered $H2 — a retried cleanup would fail on it"
put "$SEED_B" "$(jq -nc --arg a "$WL" '{asset_account_id:$a, kind:"personal_account"}')"
assert_status "E6 re-binding the same account after a DELETE" 200
api "$SEED_B" DELETE /wallet/v1/binding >/dev/null

# ── E7 the setup kit ───────────────────────────────────────────────────────
log "E7 the setup kit"
api "$SEED_A" GET "/wallet/v1/binding/setup?kind=personal_account" >/dev/null
if [[ "$HTTP" == "200" ]]; then
  assert_json "E7 one transaction" '.transactions | length' 1
  assert_json "E7 three actions" '.transactions[0].actions | length' 3
  assert_json "E7 the pinned artifact" '.code_hash' "$PINNED_HASH_B58"
  assert_json "E7 signer is the owner's own account" '.transactions[0].signer_id' "$EMPTY"
  assert_json "E7 receiver is the owner's own account" '.transactions[0].receiver_id' "$EMPTY"
else
  fail "E7 the kit failed for a bound, code-free account (HTTP $HTTP): $(msg_of)"
fi

api "$SEED_A" GET "/wallet/v1/binding/setup?kind=hos_lease" >/dev/null
assert_denied "E7' no kit for hos_lease" && assert_msg "E7' says the partner provisions those" "no setup kit|provisioned"

api "$SEED_A" GET "/wallet/v1/binding/setup?kind=nonsense" >/dev/null
assert_denied "E7'' an unknown kind"

api "$SEED_A" GET "/wallet/v1/binding/setup" >/dev/null
assert_denied "E7''' the kit with no kind at all"

api "$SEED_B" GET "/wallet/v1/binding/setup?kind=personal_account" >/dev/null
assert_denied "E7'''' the kit for a wallet with no binding"

log "E8 the kit refuses an account that ALREADY runs code (the 2FA/multisig victim)"
api "$SEED" GET "/wallet/v1/binding/setup?kind=personal_account" >/dev/null
assert_denied "E8 refused" \
  && assert_msg "E8 says the existing state would NOT be cleared" "already has a contract|would NOT be cleared|not be cleared"

# ── E9 the partner webhook ─────────────────────────────────────────────────
log "E9 POST /binding/events — the shared secret is the ONLY thing guarding it"
# The body is UNREADABLE on purpose. The door has to answer before the body is
# parsed, and only an unparseable body can tell the two orders apart: parsed
# first, this returns 422 naming `asset_account_id`, and 422 is not a free code
# here — everywhere else in this API it means `OnChainTxFailed`, the chain
# having answered and a receipt having failed. A partner routing on it would
# read a malformed body as a chain fact. "Some 4xx" is not the assertion.
api - POST /wallet/v1/binding/events '{}' >/dev/null
H_JUNK=$HTTP; B_JUNK=$BODY
api - POST /wallet/v1/binding/events "$(jq -nc --arg a "$ASSET" '{asset_account_id:$a, event:"revoked"}')" >/dev/null
H_NONE=$HTTP; B_NONE=$BODY
api - POST /wallet/v1/binding/events "$(jq -nc --arg a "$ASSET" '{asset_account_id:$a, event:"revoked"}')" \
  -H 'x-binding-webhook-secret: definitely-not-the-secret' >/dev/null
H_WRONG=$HTTP
if [[ "$H_NONE" == "503" ]]; then
  finding "the testnet coordinator has no BINDING_WEBHOOK_SECRET configured: every partner lifecycle event answers 503 'binding events are not configured on this deployment'. Their revoke/rotation webhook is dead on this deployment until an operator sets it — and §6's 'revoke invalidates a cached allow inside the TTL' cannot be proved here."
  skip "E9 webhook HAPPY + zone list + cache invalidation — needs BINDING_WEBHOOK_SECRET on the testnet coordinator"
  [[ "$H_WRONG" =~ ^[45] ]] \
    && pass "E9 a presented secret is still refused while unconfigured (HTTP $H_WRONG) — unconfigured never means open" \
    || fail "E9 an unconfigured deployment ACCEPTED an event (HTTP $H_WRONG)"
  [[ "$H_JUNK" == "$H_NONE" ]] \
    && pass "E9 an unreadable body answers the same as a readable one ($H_JUNK): the door runs first" \
    || fail "E9 an unreadable body answered $H_JUNK where a readable one answered $H_NONE — the body is parsed before the door"
else
  [[ "$H_NONE" == "401" ]] && pass "E9 no secret → 401" || fail "E9 no secret → $H_NONE, expected 401: $(msg_of "$B_NONE")"
  [[ "$H_WRONG" == "401" ]] && pass "E9 a wrong secret → 401" || fail "E9 a wrong secret → $H_WRONG, expected 401"
  [[ "$H_JUNK" == "401" ]] \
    && pass "E9 an unreadable body with no secret → 401, not 422: the secret is checked before the body is read" \
    || fail "E9 an unreadable body with no secret → $H_JUNK, expected 401. 422 here means the extractor parses first and answers an unauthenticated caller with our own field names: $(msg_of "$B_JUNK")"
  grep -qi "asset_account_id\|missing field" <<<"$B_JUNK" \
    && fail "E9 the refusal to an unauthenticated caller names our own schema: $(msg_of "$B_JUNK")" \
    || pass "E9 and it says nothing about the shape it wanted"
fi

# ── E10 /binding/balance ───────────────────────────────────────────────────
log "E10 GET /binding/balance"
api "$SEED" GET "/wallet/v1/binding/balance?chain=near" >/dev/null
if [[ "$HTTP" == "200" ]]; then
  CHAIN_ASSET=$(account_field "$ASSET" amount)
  REPORTED=$(jq -r '.balance // .near_balance // .amount // ""' <<<"$BODY")
  note "reported: $(head -c 200 <<<"$BODY")"
  if [[ -n "$REPORTED" && "${REPORTED:0:6}" == "${CHAIN_ASSET:0:6}" ]]; then
    pass "E10 the answer is the BOUND account's balance, not the executor's"
  else
    # Not a failure by itself — the field name may differ; the account named is
    # the assertion that matters.
    grep -q "$ASSET" <<<"$BODY" \
      && pass "E10 the answer names the bound account $ASSET" \
      || fail "E10 the answer names neither the bound account nor its chain balance: $(head -c 200 <<<"$BODY")"
  fi
else
  fail "E10 balance on the active binding failed (HTTP $HTTP): $(msg_of)"
fi

api "$SEED_A" GET "/wallet/v1/binding/balance?chain=near" >/dev/null
assert_denied "E10' balance on a PENDING binding" \
  && assert_msg "E10' says WHY, without answering about another account" "pending|not active"

api "$SEED_B" GET "/wallet/v1/binding/balance?chain=near" >/dev/null
assert_denied "E10'' balance on an unbound wallet — not the executor's balance silently"

api "$SEED" GET "/wallet/v1/binding/balance?chain=near&source=intents" >/dev/null
assert_denied "E10''' source=intents on the bound account" \
  && assert_msg "E10''' says where to go instead" "GET /wallet/v1/balance|executor"

api "$SEED" GET "/wallet/v1/binding/balance?chain=ethereum" >/dev/null
assert_denied "E10'''' an unsupported chain"

# ── E11 /binding/transfer ──────────────────────────────────────────────────
log "E11 POST /binding/transfer"
api "$SEED_B" POST /wallet/v1/binding/transfer "$(jq -nc --arg t "$WL" '{to:$t, amount:"1"}')" >/dev/null
assert_denied "E11 transfer from an unbound wallet"
api "$SEED_A" POST /wallet/v1/binding/transfer "$(jq -nc --arg t "$WL" '{to:$t, amount:"1"}')" >/dev/null
assert_denied "E11' transfer on a PENDING binding" && assert_msg "E11' says nothing can be spent yet" "pending|not active"
api "$SEED" POST /wallet/v1/binding/transfer '{"to":"Bad Name!","amount":"1"}' >/dev/null
assert_denied "E11'' an invalid recipient"
api "$SEED" POST /wallet/v1/binding/transfer "$(jq -nc --arg t "$WL" '{to:$t, amount:"0.5"}')" >/dev/null
assert_denied "E11''' an amount that is not in the smallest unit" && assert_msg "E11''' says which unit" "smallest unit|yoctoNEAR|decimal"

# SPENDS: 0.0005 NEAR of the BOUND account's money.
AMT="500000000000000000000"
BEFORE_ASSET=$(account_field "$ASSET" amount)
BEFORE_EXEC=$(account_field "$EXECUTOR" amount)
BEFORE_DEST=$(account_field "$WL" amount)
api "$SEED" POST /wallet/v1/binding/transfer "$(jq -nc --arg t "$WL" --arg a "$AMT" '{to:$t, amount:$a}')" >/dev/null
# Kept for E15: the only handle a client is given for this operation, and the
# thing the status road is asked about.
LAST_TRANSFER_REQUEST=$(jq -r '.request_id // ""' <<<"$BODY")
if [[ "$HTTP" == "200" ]]; then
  pass "E11'''' the builder produced an envelope its own pre-flight accepts (status $(jq -r '.status' <<<"$BODY"))"
  sleep 8
  AFTER_ASSET=$(account_field "$ASSET" amount)
  AFTER_EXEC=$(account_field "$EXECUTOR" amount)
  AFTER_DEST=$(account_field "$WL" amount)
  # The recipient is the only exact number available: the bound account also
  # receives the unspent-gas refund of the receipt it spawned, so its own delta
  # is the amount minus a few tens of microNEAR, and asserting equality there
  # would fail on ordinary chain behaviour rather than on a defect.
  if python3 -c "import sys; sys.exit(0 if int('$AFTER_DEST') - int('$BEFORE_DEST') == int('$AMT') else 1)"; then
    pass "E11'''' the recipient received exactly the amount asked for"
  else
    fail "E11'''' the recipient received $(python3 -c "print(int('$AFTER_DEST')-int('$BEFORE_DEST'))"), not $AMT"
  fi
  if python3 -c "import sys; sys.exit(0 if int('$BEFORE_ASSET') - int('$AFTER_ASSET') >= int('$AMT')*9//10 else 1)"; then
    pass "E11'''' the money left the BOUND account (net $(python3 -c "print(int('$BEFORE_ASSET')-int('$AFTER_ASSET'))") after its gas refund)"
  else
    fail "E11'''' the bound account did not pay: $BEFORE_ASSET -> $AFTER_ASSET"
  fi
  if python3 -c "import sys; sys.exit(0 if int('$BEFORE_EXEC') - int('$AFTER_EXEC') < int('$AMT') else 1)"; then
    pass "E11'''' the executor only paid gas — it is the signer, not the source"
  else
    fail "E11'''' the executor paid the transfer: $BEFORE_EXEC -> $AFTER_EXEC"
  fi
else
  fail "E11'''' the builder's own transfer was refused (HTTP $HTTP): $(msg_of)"
fi

# ── E12 /address ───────────────────────────────────────────────────────────
log "E12 GET /address"
api "$SEED" "GET" "/wallet/v1/address?chain=near" >/dev/null
assert_json "E12 names the bound account" '.asset_account_id' "$ASSET"
assert_json "E12 names the executor" '.executor_account_id' "$EXECUTOR"
jq -e 'has("gas_balance")' <<<"$BODY" >/dev/null \
  && pass "E12 carries gas_balance, so the funder learns it BEFORE a call fails" \
  || fail "E12 no gas_balance in the answer"
api "$SEED_B" GET "/wallet/v1/address?chain=near" >/dev/null
if [[ "$(jq -r '.asset_account_id // ""' <<<"$BODY")" == "" ]]; then
  pass "E12' an unbound wallet has no asset account — the executor IS its address"
else
  fail "E12' an unbound wallet reports an asset account: $(head -c 160 <<<"$BODY")"
fi
api "$SEED" GET "/wallet/v1/address?chain=dogecoin" >/dev/null
assert_denied "E12'' an unknown chain"

# ── E13 regression: the own-wallet endpoints still mean the wallet ─────────
log "E13 the default /balance did NOT move to the bound account"
api "$SEED" GET "/wallet/v1/balance?chain=near" >/dev/null
if [[ "$HTTP" == "200" ]]; then
  if grep -q "$ASSET" <<<"$BODY"; then
    fail "E13 /wallet/v1/balance answers about the BOUND account — the default moved, and every pre-binding client now reads a different account's money"
  else
    pass "E13 /wallet/v1/balance still answers about the wallet's own account"
  fi
else
  fail "E13 /balance failed on a bound wallet (HTTP $HTTP): $(msg_of)"
fi

# ── E13b the `account` parameter, which is how a caller ASKS for the other one ─
#
# E13 proves the default did not move. This proves the way to move it, which is
# the other half of the method list's promise and the half a client actually
# writes code against: `account=asset` reads the money the product is about,
# `account=executor` reads the account that pays gas, and `account_id` in the
# answer states which of the two was measured — so a caller can never
# misattribute a balance it asked for by name.
log "E13b GET /balance?account="
api "$SEED" GET "/wallet/v1/balance?chain=near&account=asset" >/dev/null
if [[ "$HTTP" == "200" ]]; then
  assert_json "E13b account=asset answers about the bound account" '.account_id' "$ASSET"
else
  fail "E13b account=asset was refused on a bound wallet (HTTP $HTTP): $(msg_of)"
fi
api "$SEED" GET "/wallet/v1/balance?chain=near&account=executor" >/dev/null
if [[ "$HTTP" == "200" ]]; then
  assert_json "E13b account=executor answers about the signer" '.account_id' "$EXECUTOR"
else
  fail "E13b account=executor was refused (HTTP $HTTP): $(msg_of)"
fi
# A value that is neither must be named back. A door that silently fell through
# to its default would answer about the executor while the caller believed it
# had asked for the asset — the exact misattribution `account_id` exists to stop.
api "$SEED" GET "/wallet/v1/balance?chain=near&account=asssett" >/dev/null
if [[ "$HTTP" == "400" || "$HTTP" == "422" ]]; then
  assert_msg "E13b a value that is neither is refused and the two legal ones are named" "asset.*executor|executor.*asset"
else
  fail "E13b a bogus account value answered HTTP $HTTP instead of refusing: $(msg_of | head -c 160)"
fi
# And on a wallet with no binding there is no asset account to answer about, so
# the ask must fail rather than quietly return the executor's money under the
# name the caller did not ask for.
api "$SEED_B" GET "/wallet/v1/balance?chain=near&account=asset" >/dev/null
if [[ "$HTTP" == "200" ]]; then
  fail "E13b an UNBOUND wallet answered account=asset (HTTP 200) — the caller is reading the executor's balance believing it is the agent's"
else
  pass "E13b an unbound wallet refuses account=asset (HTTP $HTTP) rather than substituting"
fi

# ── E15 GET /requests/{id}: what the status road carries TODAY ──────────────
#
# Pinned rather than aspirational. The partner's method list asks this endpoint
# to grow `binding_id`, `asset_account_id`, `executor_account_id`,
# `policy_version`, `tx_hash`, a per-promise `promises[]` array and `error`. It
# carries none of them, and that divergence is stated in the integration answer
# rather than hidden — but the shape it DOES carry is what their client will be
# written against in the meantime, so it is asserted here. When the fields are
# added, this probe is where the change announces itself.
log "E15 GET /requests/{id}"
if [[ -n "${LAST_TRANSFER_REQUEST:-}" ]]; then
  api "$SEED" GET "/wallet/v1/requests/$LAST_TRANSFER_REQUEST" >/dev/null
  if [[ "$HTTP" == "200" ]]; then
    assert_json "E15 the id echoes the one the transfer returned" '.request_id' "$LAST_TRANSFER_REQUEST"
    if [[ -n "$(jq -r '.status // ""' <<<"$BODY")" ]]; then
      pass "E15 it carries a status ($(jq -r '.status' <<<"$BODY"))"
    else
      fail "E15 no status on the request road"
    fi
    if [[ -n "$(jq -r '.created_at // ""' <<<"$BODY")" ]]; then
      pass "E15 and a created_at, so an operation can be placed in time"
    else
      fail "E15 no created_at"
    fi
    MISSING=""
    for f in binding_id asset_account_id executor_account_id policy_version promises; do
      [[ "$(jq -r --arg f "$f" 'has($f)' <<<"$BODY")" == "true" ]] || MISSING="$MISSING $f"
    done
    if [[ -n "$MISSING" ]]; then
      note "E15 the method list's additive fields are absent:$MISSING — the divergence the integration answer states, not a regression"
    else
      pass "E15 the method list's additive fields are all present — the divergence is closed and the answer document is out of date"
    fi
  else
    fail "E15 the request road answered HTTP $HTTP for an id it had just minted: $(msg_of | head -c 160)"
  fi
else
  skip "E15 — the transfer probe returned no request_id to follow, so there is nothing to read back"
fi

# ── E16 the confidential routes on testnet: OFF is not the same as BUSY ─────
#
# R10 is a mainnet acceptance and cannot be run here — there are no solvers on
# testnet. Its testnet half CAN be run, and it is the half a partner's retry
# logic depends on: a feature that is switched off must not look like a service
# having a bad minute.
#
# Our taxonomy puts the whole weight of that on one header. 503 WITH a
# `Retry-After` means "a node did not answer this second, come back". 503
# WITHOUT one means "this deployment does not have the feature". Sending the
# first to the second is an instruction to poll forever, and it is exactly the
# mistake a client makes when both look alike.
log "E16 /confidential/* is refused on testnet, and says OFF rather than BUSY"
CONF_HDR=$(mktemp -t hos_conf.XXXXXX); CONF_BODY=$(mktemp -t hos_confb.XXXXXX)
throttle
CONF_HTTP=$(curl -sS -o "$CONF_BODY" -D "$CONF_HDR" -w '%{http_code}' -X GET \
  "$COORDINATOR_URL/wallet/v1/confidential/balance" \
  -H "$(AUTH_FOR "$SEED")" --max-time 60 2>/dev/null)
CONF_TEXT=$(tr -d '\n' < "$CONF_BODY")
if [[ "$CONF_HTTP" == "503" ]]; then
  pass "E16 the route answers 503 on a deployment without confidential credentials"
  if grep -qiE '^retry-after:' <<<"$(cat "$CONF_HDR")"; then
    fail "E16 it carries a Retry-After — a client is being told to poll for a feature that is not coming back on this deployment"
  else
    pass "E16 and carries NO Retry-After, so 'off' cannot be read as 'busy'"
  fi
  if grep -qiE 'not configured|not enabled|not available' <<<"$CONF_TEXT"; then
    pass "E16 and the sentence says the deployment lacks it, rather than blaming the moment"
  else
    fail "E16 the message does not say the feature is unconfigured: $(head -c 160 <<<"$CONF_TEXT")"
  fi
else
  fail "E16 the confidential route answered HTTP $CONF_HTTP on testnet, expected 503: $(head -c 160 <<<"$CONF_TEXT")"
fi
rm -f "$CONF_HDR" "$CONF_BODY"

# ── E17 an idempotency key does not buy a second execution ──────────────────
#
# The method list asks for one property: "the same idempotency key never
# produces two independently executable requests, so a timed-out caller can
# retry safely". A caller whose connection dropped cannot tell a lost answer
# from a lost request, and the only safe thing they can do is send it again.
#
# THE REPLAY WAITS. Sent back to back, the second call is refused as
# `wallet_busy` by the nonce holder and never reaches the idempotency check at
# all — which passes for a reason that has nothing to do with the key, and would
# keep passing after the key stopped being read. So the first transfer is left
# to settle, and only then is the key replayed.
#
# AND IT IS CONTROLLED. "The same key returned the same id" is also what a door
# deduplicating on the BODY would say. The control sends the identical body
# under a DIFFERENT key: that one must mint a new id, or the probe above proves
# nothing about keys.
log "E17 replaying an idempotency key"
idem_send() { # idem_send <key> — echoes the raw body
  throttle
  curl -sS -X POST "$COORDINATOR_URL/wallet/v1/binding/transfer" \
    -H "$(AUTH_FOR "$SEED")" -H 'Content-Type: application/json' \
    -H "X-Idempotency-Key: $1" --max-time 90 \
    -d "$(jq -nc --arg t "$WL" '{to:$t, amount:"100000000000000000000"}')" 2>/dev/null
}
# The id this operation is known by, whichever way the door chose to answer:
# a fresh request names it in `request_id`, and a replay the door recognised
# names it inside the duplicate's sentence.
idem_id() { # idem_id <body>
  local r; r=$(jq -r '.request_id // ""' <<<"$1" 2>/dev/null)
  [[ -n "$r" ]] && { echo "$r"; return; }
  jq -r '.in_flight_request_id // ""' <<<"$1" 2>/dev/null | grep . && return
  grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' <<<"$1" | head -1
}

IDEM="hos-idem-$(date +%s)-$$"
IDEM_1=$(idem_send "$IDEM")
RID_1=$(idem_id "$IDEM_1")
if [[ -z "$RID_1" ]]; then
  skip "E17 — the first send named no request ($(head -c 140 <<<"$IDEM_1")), so a replay proves nothing"
else
  # Settle, so the replay is judged by the key and not by the nonce holder.
  for _ in $(seq 1 12); do
    api "$SEED" GET "/wallet/v1/requests/$RID_1" >/dev/null
    [[ "$(jq -r '.status // ""' <<<"$BODY")" =~ ^(success|failed|completed|error)$ ]] && break
    sleep 3
  done
  IDEM_2=$(idem_send "$IDEM")
  RID_2=$(idem_id "$IDEM_2")
  if [[ "$RID_2" == "$RID_1" ]]; then
    pass "E17 the replay named the FIRST request ($RID_1) — one key, one executable request"
  else
    fail "E17 the replay named '$RID_2' where the first was '$RID_1': $(head -c 200 <<<"$IDEM_2")"
  fi
  # The control. Same body, different key — it must be a different operation,
  # or the sameness above was the body being deduplicated and not the key.
  IDEM_3=$(idem_send "hos-idem-other-$(date +%s)-$$")
  RID_3=$(idem_id "$IDEM_3")
  if [[ -z "$RID_3" ]]; then
    note "E17 the control send named no request ($(head -c 140 <<<"$IDEM_3")) — the replay above is unconfirmed as a KEY effect"
  elif [[ "$RID_3" != "$RID_1" ]]; then
    pass "E17 and the identical body under a different key is a NEW request ($RID_3) — the key is what was read"
  else
    fail "E17 a different key returned the same request ($RID_1): the door is deduplicating on the body, so the key is not what stops a double spend"
  fi
fi

# ── E14 DoS: how much body will the door buffer ────────────────────────────
#
# Asked on a wallet with no binding, so nothing but the size can refuse it.
log "E14 oversized PUT bodies"
SEED_BODY="hos-ep-body-$(date +%s)-$$"
read -r WID_BODY _ < <(wallet_address "$SEED_BODY")
for MB in 2 8; do
  BIG=$(mktemp -t hos_big.XXXXXX)
  python3 -c "import json,sys; sys.stdout.write(json.dumps({'asset_account_id':'nonexistent-e14-$MB.testnet','kind':'personal_account','pad':'x'*($MB*1000000)}))" > "$BIG"
  throttle
  H=$(curl -sS -o /dev/null -w '%{http_code}' -X PUT "$COORDINATOR_URL/wallet/v1/binding" \
    -H "$(AUTH_FOR "$SEED_BODY")" -H 'Content-Type: application/json' --data-binary "@$BIG" --max-time 120 2>/dev/null)
  rm -f "$BIG"
  note "${MB} MB → HTTP $H"
  if [[ "$MB" == "8" ]]; then
    [[ "$H" == "413" ]] \
      && pass "E14 an 8 MB body is refused as too large (413) rather than buffered" \
      || fail "E14 an 8 MB body answered $H — the door buffers whatever it is sent"
  else
    [[ "$H" =~ ^[24] ]] && note "E14 a 2 MB body is accepted and parsed (HTTP $H)"
  fi
done
api "$SEED_BODY" DELETE /wallet/v1/binding >/dev/null 2>&1 || true

# ── E18 the admin lists that decide what the door believes ─────────────────
#
# Four live tables, no constants: which implementation code and which wallet
# builds are recognized, which partner impl_version each decoder reads, and
# the watchdog that holds every live binding against them. The refusals here
# are the two an operator in a hurry would trip: a decoder this build does not
# carry, and a version whose grants never bounded token movement.
log "E18 admin lists: versions, wallet builds, the watchdog"
if [[ -n "${ADMIN_TOKEN:-}" ]]; then
  adm() { curl -sS --max-time 60 -X "$1" "$COORDINATOR_URL$2" -H "Authorization: Bearer $ADMIN_TOKEN" \
            -H 'Content-Type: application/json' ${3:+--data-binary "$3"} 2>/dev/null; }
  V=$(adm GET /admin/hos-impl-versions)
  [[ "$(jq -r '[.versions[].impl_version] | index(6) != null and index(7) != null' <<<"$V")" == "true" ]] \
    && pass "E18a impl_version 6 and 7 are mapped ($(jq -c '[.versions[] | "\(.impl_version)→\(.decoder_version)"]' <<<"$V"))" \
    || fail "E18a the version table does not map 6 and 7: $(head -c 200 <<<"$V")"
  [[ "$(jq -c '.decoders' <<<"$V")" == "[1]" ]] \
    && pass "E18a and the build states the decoders it carries: [1]" \
    || fail "E18a decoders read $(jq -c '.decoders' <<<"$V"), expected [1]"
  R=$(adm POST /admin/hos-impl-versions '{"impl_version":99,"decoder_version":2}')
  grep -q 'not carried by this build' <<<"$R" \
    && pass "E18b a version cannot be mapped to a decoder the build does not carry" \
    || fail "E18b mapping 99→2 answered: $(head -c 160 <<<"$R")"
  R=$(adm POST /admin/hos-impl-versions '{"impl_version":5,"decoder_version":1}')
  grep -q 'below 6' <<<"$R" \
    && pass "E18c versions below 6 cannot be mapped — their grants never bounded token movement" \
    || fail "E18c mapping 5→1 answered: $(head -c 160 <<<"$R")"
  W=$(adm GET /admin/wallet-code-hashes)
  grep -q 'BwjDnyemmBhrCyuviDGpoQAm9mdjTfrX7ZjqgZB4MHvM' <<<"$W" \
    && pass "E18d the wallet build the personal profile was written against is recognized" \
    || fail "E18d wallet_code_hashes does not list BwjDnyem…: $(head -c 160 <<<"$W")"
  I=$(adm GET /admin/binding-implementations)
  if [[ "$(jq -r 'has("unrecognized_code") and has("unmapped_versions") and has("unreadable")' <<<"$I")" == "true" ]]; then
    pass "E18e the watchdog answers ($(jq -c '{unrecognized_code, unmapped_versions, unreadable, live: (.bindings|length)}' <<<"$I"))"
    [[ "$(jq -r '.unrecognized_code + .unmapped_versions' <<<"$I")" == "0" ]] \
      && pass "E18e and nothing live runs code or a version the lists do not know" \
      || finding "E18e the watchdog reports $(jq -c '{unrecognized_code, unmapped_versions}' <<<"$I") — a partner shipped, or a list is behind; one POST fixes it"
  else
    fail "E18e the watchdog did not answer with its counts: $(head -c 200 <<<"$I")"
  fi
  H=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 30 "$COORDINATOR_URL/admin/hos-impl-versions" 2>/dev/null)
  [[ "$H" == "401" ]] && pass "E18f the lists are admin-only (401 without the token)" \
    || fail "E18f /admin/hos-impl-versions answered $H without a token"
else
  skip "E18 — set ADMIN_TOKEN (scripts/.env → ADMIN_BEARER_TOKEN_TESTNET) to judge the admin lists"
fi

verdict "§2 endpoints"
