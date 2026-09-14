#!/usr/bin/env bash
#
# The binding API end to end — queue A, item 1.
#
# Everything else about `personal_account` has been proved against the CHAIN
# (`personal_wallet_e2e.sh`, `personal_wallet_global_e2e.sh`): the wallet
# contract behaves, the kit's transaction shape works, the pinned hash is the
# hash the chain reports. None of that goes through the coordinator. This does:
# it drives `PUT` / `GET` / `DELETE /wallet/v1/binding` and the setup kit as a
# client would, and it is the only thing that produces an ACTIVE binding — which
# is what `stuck_request_repair_e2e.sh` R4 and `bound_identity_onchain_e2e.sh`
# B0–B5 are all waiting for.
#
# What each probe pins:
#   L1  PUT with `kind=personal_account` and NO owner: the owner IS the account,
#       so the field is optional and must be filled in for us
#   L2  PUT with the owner stated explicitly and equal to the asset — accepted,
#       and the answer is the same binding, not a second one
#   L3  `impl_version` on a personal_account PUT is REFUSED, not ignored. That
#       mode is versioned by the account's code hash, which no client declares;
#       a caller who sends a version has the two modes confused and silence
#       would hide it
#   L4  the setup kit: one transaction, three actions, and a `code_hash` equal
#       to the artifact the verifier's allowlist pins. A kit that hands back a
#       hash nobody verifies would install a wallet our own door then refuses
#   L5  sign the kit verbatim → the binding turns ACTIVE. This is the whole
#       handshake, and the only place the coordinator's view and the chain's
#       have to agree
#   L6  one-to-one: with a live binding, a PUT naming a different account is
#       refused. A wallet that could hold two bound identities would make
#       "who is the guest" ambiguous at execution time
#   L7  there is no setup kit for `hos_lease`, and asking says why — those
#       accounts are provisioned by the partner, not installed by their owner
#   L8  DELETE removes it, and a second DELETE is still a success. An unbind
#       that errors the second time makes cleanup scripts fail on retry
#
# Money: one account (`bind-*.<PARENT>`) funded with 0.5 NEAR — deliberately
# below the price of 278 KB of code storage, so L5 doubles as proof that the
# global reference carries no storage cost. Returned by the cleanup, which runs
# even on abort. The executor is topped up only if the binding reports its gas
# as low.
#
# Requires: $PARENT with a keychain credential and ~1 NEAR, `outlayer` logged in
# as $PARENT.
#
# Set KEEP=1 to leave the binding ACTIVE and the account alive for the runs that
# need one; the script then skips L8 and prints what to export.
#
# Run (spends real testnet NEAR):
#   PARENT=you.testnet ./tests/binding_lifecycle_e2e.sh --apply
#   PARENT=you.testnet KEEP=1 ./tests/binding_lifecycle_e2e.sh --apply

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPLY=false
[[ "${1:-}" == "--apply" ]] && APPLY=true

NETWORK="${NETWORK:-testnet}"
CONTRACT_ID="${CONTRACT_ID:-outlayer.testnet}"
COORDINATOR_URL="${COORDINATOR_URL:-https://testnet-api.outlayer.ai}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/rpc.sh"   # keyed RPC_URL, or a warning
PARENT="${PARENT:-}"
KEEP="${KEEP:-}"

# The artifact the allowlist pins — `WALLET_NO_SIGN_6095765F` in the crate,
# published as a global contract. L4 asserts the kit names exactly this.
PINNED_HASH_B58="${PINNED_HASH_B58:-BwjDnyemmBhrCyuviDGpoQAm9mdjTfrX7ZjqgZB4MHvM}"
FUND_NEAR="0.5"
EXECUTOR_TOPUP="0.2"

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

[[ -n "$PARENT" ]] || { echo "USAGE: PARENT=you.testnet $0 --apply" >&2; exit 1; }
for tool in jq curl near outlayer cargo openssl; do
  command -v "$tool" >/dev/null || { echo "✗ missing $tool" >&2; exit 1; }
done
CREDS_DIR="$HOME/.near-credentials/$NETWORK"
[[ -f "$CREDS_DIR/$PARENT.json" ]] || { echo "✗ creds missing: $CREDS_DIR/$PARENT.json" >&2; exit 1; }
# Without this, `outlayer` follows ~/.outlayer/default-network — mainnet on this
# machine — and the check below compares against the wrong network's account.
export OUTLAYER_NETWORK="$NETWORK"
WHOAMI=$(outlayer whoami 2>/dev/null | awk -F': *' '/^Account:/{print $2; exit}')
[[ "$WHOAMI" == "$PARENT" ]] || { echo "✗ outlayer logged in as '$WHOAMI', not '$PARENT'" >&2; exit 1; }
PARENT_PRIVKEY=$(jq -r '.private_key' "$CREDS_DIR/$PARENT.json")

RECOVERY_BIN="$SCRIPT_DIR/../scripts/customer-recovery/target/release/customer-recovery"
log "Building customer-recovery (sign-bearer-near)"
(cd "$SCRIPT_DIR/../scripts/customer-recovery" && cargo build --release --quiet) \
  || { echo "✗ customer-recovery build failed" >&2; exit 1; }

SEED="binding-$(date +%s)-$$"
mk_token() { "$RECOVERY_BIN" sign-bearer-near --private-key "$PARENT_PRIVKEY" --account-id "$PARENT" --seed "$SEED"; }
AUTH() { echo "Authorization: Bearer near:$(mk_token)"; }

account_field() {
  curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg a "$1" '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"view_account",finality:"final",account_id:$a}}')" \
    2>/dev/null | jq -r ".result.$2 // \"null\"" 2>/dev/null || echo null
}

# api <METHOD> <path> [json-body] — echoes "<http> <body>".
api() {
  local method=$1 path=$2 body=${3:-} out http
  out=$(mktemp -t binding_api.XXXXXX)
  if [[ -n "$body" ]]; then
    http=$(curl -sS -o "$out" -w '%{http_code}' -X "$method" "$COORDINATOR_URL$path" \
      -H "$(AUTH)" -H 'Content-Type: application/json' -d "$body")
  else
    http=$(curl -sS -o "$out" -w '%{http_code}' -X "$method" "$COORDINATOR_URL$path" -H "$(AUTH)")
  fi
  printf '%s %s\n' "$http" "$(tr -d '\n' < "$out")"
  rm -f "$out"
}

ACC="bind-$(openssl rand -hex 3).$PARENT"
CREATED=""
BOUND=""

# The account exists from here on; the trap returns it to $PARENT even if a
# probe below dies, rather than leaving it parked with a keychain-only key.
cleanup() {
  local rc=$?
  if [[ -n "$KEEP" ]]; then
    [[ -n "$CREATED" ]] && note "KEEP set — leaving $CREATED and its binding in place"
    return $rc
  fi
  if [[ -n "$BOUND" ]]; then
    api DELETE /wallet/v1/binding >/dev/null 2>&1 || true
  fi
  if [[ -n "$CREATED" ]]; then
    printf '\033[35m• cleaning up %s\033[0m\n' "$CREATED" >&2
    near account delete-account "$CREATED" beneficiary "$PARENT" \
      network-config "$NETWORK" sign-with-keychain send >/dev/null 2>&1 || true
  fi
  return $rc
}
trap cleanup EXIT

# ── the wallet whose binding this is ─────────────────────────────────────────
log "Minting the wallet that will carry the binding"
R=$(curl -sS -G "$COORDINATOR_URL/wallet/v1/address" --data-urlencode "chain=near" -H "$(AUTH)")
WALLET_ID=$(jq -r '.wallet_id // empty' <<<"$R")
[[ -n "$WALLET_ID" ]] || { echo "✗ /address failed: $(head -c 300 <<<"$R")" >&2; exit 1; }
note "wallet_id $WALLET_ID"

# 0.5 NEAR: enough for w_init state and gas, NOT enough for 278 KB of code
# storage — so L5 succeeding is also proof the global reference is free of it.
log "Creating the asset account $ACC with $FUND_NEAR NEAR"
near account create-account fund-myself "$ACC" "$FUND_NEAR NEAR" \
  autogenerate-new-keypair save-to-keychain sign-as "$PARENT" \
  network-config "$NETWORK" sign-with-keychain send >/dev/null 2>&1
# Judged by the CHAIN: near-cli-rs can swallow a broadcast transient and exit 0.
for _ in 1 2 3 4 5 6; do
  [[ "$(account_field "$ACC" amount)" != "null" ]] && { CREATED="$ACC"; break; }
  sleep 2
done
[[ -n "$CREATED" ]] || { echo "✗ $ACC never appeared on chain" >&2; exit 1; }
pass "asset account $ACC exists and carries no code"

# ── L1: PUT without an owner ─────────────────────────────────────────────────
log "L1 PUT kind=personal_account with NO owner_account_id"
R=$(api PUT /wallet/v1/binding "$(jq -nc --arg a "$ACC" '{asset_account_id:$a, kind:"personal_account"}')")
HTTP=${R%% *}; BODY=${R#* }
if [[ "$HTTP" == "200" ]]; then
  BOUND=1
  K=$(jq -r '.kind // ""' <<<"$BODY")
  EXECUTOR=$(jq -r '.executor_account_id // ""' <<<"$BODY")
  STATUS1=$(jq -r '.binding_status // ""' <<<"$BODY")
  IMPLV=$(jq -r 'has("impl_version")' <<<"$BODY")
  HAS_OWNER=$(jq -r 'has("owner_account_id")' <<<"$BODY")
  if [[ "$K" == "personal_account" ]]; then
    pass "L1 bound as personal_account, status=$STATUS1"
  else
    fail "L1 kind='$K' — expected personal_account"
  fi
  # The response carries NO owner, by design. It used to, and the value was the
  # caller's own input — required at PUT, checked for shape, compared against
  # nothing, and returned in a field whose name reads as an established fact.
  # (For this mode an omitted owner is still filled in with the asset account;
  # that defaulting is a rule of `validate_put` and is unit-tested there, which
  # is where a rule with no observable output belongs.)
  [[ "$HAS_OWNER" == "false" ]] \
    && pass "L1 the answer states no owner — a claim nobody verified is not returned as a fact" \
    || fail "L1 the answer carries owner_account_id='$(jq -r '.owner_account_id' <<<"$BODY")', which is the caller's own unverified input"
  [[ "$IMPLV" == "false" ]] \
    && pass "L1 no impl_version in the answer — that mode has none" \
    || fail "L1 the answer carries impl_version, which personal_account does not have"
  note "executor: $EXECUTOR"
else
  fail "L1 PUT failed (HTTP $HTTP): $(jq -r '.message // .error // .' <<<"$BODY" 2>/dev/null | head -c 250)"
  EXECUTOR=""
fi

# ── L2: PUT with the owner stated ────────────────────────────────────────────
log "L2 PUT again with owner_account_id stated explicitly"
R=$(api PUT /wallet/v1/binding "$(jq -nc --arg a "$ACC" '{asset_account_id:$a, owner_account_id:$a, kind:"personal_account"}')")
HTTP=${R%% *}; BODY=${R#* }
if [[ "$HTTP" == "200" && "$(jq -r '.asset_account_id // ""' <<<"$BODY")" == "$ACC" ]]; then
  pass "L2 the same binding is returned for an explicit owner equal to the asset"
else
  fail "L2 explicit owner rejected (HTTP $HTTP): $(jq -r '.message // .error // .' <<<"$BODY" 2>/dev/null | head -c 250)"
fi

# ── L3: impl_version must be refused ─────────────────────────────────────────
log "L3 PUT personal_account WITH impl_version — must be refused, not ignored"
R=$(api PUT /wallet/v1/binding "$(jq -nc --arg a "$ACC" '{asset_account_id:$a, kind:"personal_account", impl_version:1}')")
HTTP=${R%% *}; BODY=${R#* }
MSG=$(jq -r '.message // .error // ""' <<<"$BODY" 2>/dev/null)
if [[ "$HTTP" == "400" ]]; then
  # Asserting the 400 alone would pass on a generic "bad request"; the point of
  # refusing rather than ignoring is that the caller is TOLD the modes differ.
  if grep -qi "impl_version\|version" <<<"$MSG"; then
    pass "L3 refused (400) and the message names the field: $(head -c 140 <<<"$MSG")"
  else
    fail "L3 refused (400) but the message does not name impl_version: $(head -c 200 <<<"$MSG")"
  fi
else
  fail "L3 impl_version was NOT refused (HTTP $HTTP) — a caller confusing the modes gets silence"
fi

# ── L4: the setup kit ────────────────────────────────────────────────────────
log "L4 GET the setup kit"
R=$(api GET "/wallet/v1/binding/setup?kind=personal_account")
HTTP=${R%% *}; BODY=${R#* }
KIT_OK=false
if [[ "$HTTP" == "200" ]]; then
  NTX=$(jq -r '.transactions | length' <<<"$BODY")
  NACT=$(jq -r '.transactions[0].actions | length' <<<"$BODY" 2>/dev/null)
  KIT_HASH=$(jq -r '.code_hash // ""' <<<"$BODY")
  KIT_SIGNER=$(jq -r '.transactions[0].signer_id // ""' <<<"$BODY" 2>/dev/null)
  KIT_RECV=$(jq -r '.transactions[0].receiver_id // ""' <<<"$BODY" 2>/dev/null)
  [[ "$NTX" == "1" && "$NACT" == "3" ]] \
    && pass "L4 one transaction, three actions" \
    || fail "L4 kit has $NTX transaction(s) and $NACT action(s) — expected 1 and 3"
  [[ "$KIT_HASH" == "$PINNED_HASH_B58" ]] \
    && pass "L4 the kit names the pinned artifact ($KIT_HASH)" \
    || fail "L4 the kit names $KIT_HASH, but the allowlist pins $PINNED_HASH_B58 — it would install a wallet our own door refuses"
  [[ "$KIT_SIGNER" == "$ACC" && "$KIT_RECV" == "$ACC" ]] \
    && pass "L4 signer and receiver are the owner's own account" \
    || fail "L4 signer='$KIT_SIGNER' receiver='$KIT_RECV' — both must be $ACC"
  KIT_OK=true
else
  fail "L4 setup kit failed (HTTP $HTTP): $(jq -r '.message // .error // .' <<<"$BODY" 2>/dev/null | head -c 250)"
fi

# ── L5: sign the kit, the binding turns active ───────────────────────────────
if [[ "$KIT_OK" == true && -n "$EXECUTOR" ]]; then
  log "L5 signing the kit verbatim, then waiting for the binding to go active"
  ADD_EXT_ARGS=$(jq -nc --arg e "$EXECUTOR" \
    '{request:{internal:[{op:"add_extension",payload:{account_id:$e}}]}}')
  SEND=$(near transaction construct-transaction "$ACC" receiver-id "$ACC" \
    add-action use-global-contract use-global-hash "$PINNED_HASH_B58" without-init-call \
    add-action function-call w_init json-args '{}' \
      prepaid-gas '30.0 Tgas' attached-deposit '1 yoctoNEAR' \
    add-action function-call w_execute_extension json-args "$ADD_EXT_ARGS" \
      prepaid-gas '30.0 Tgas' attached-deposit '1 yoctoNEAR' \
    skip network-config "$NETWORK" sign-with-keychain send 2>&1)
  GLOBAL_NOW=$(account_field "$ACC" global_contract_hash)
  if [[ "$GLOBAL_NOW" == "$PINNED_HASH_B58" ]]; then
    pass "L5 the account now references the global contract by hash"
  else
    fail "L5 the kit transaction did not land: global_contract_hash=$GLOBAL_NOW"
    note "$(tail -c 400 <<<"$SEND")"
  fi
  STATUS=""
  for _ in 1 2 3 4 5 6 7 8; do
    R=$(api GET /wallet/v1/binding); BODY=${R#* }
    STATUS=$(jq -r '.binding_status // ""' <<<"$BODY")
    [[ "$STATUS" == "active" ]] && break
    sleep 3
  done
  if [[ "$STATUS" == "active" ]]; then
    pass "L5 the binding is ACTIVE — the coordinator's view and the chain's agree"
    GAS_LOW=$(jq -r '.gas_balance_low // false' <<<"$BODY")
    GAS_BAL=$(jq -r '.gas_balance // "null"' <<<"$BODY")
    note "executor gas: $GAS_BAL (low=$GAS_LOW)"
    if [[ "$GAS_LOW" == "true" ]]; then
      note "topping the executor up with $EXECUTOR_TOPUP NEAR so the lane can pay for calls"
      near --quiet tokens "$PARENT" send-near "$EXECUTOR" "$EXECUTOR_TOPUP NEAR" \
        network-config "$NETWORK" sign-with-keychain send >/dev/null 2>&1 || warn "top-up did not land"
    fi
  else
    fail "L5 the binding never went active (last status '$STATUS')"
  fi
fi

# ── L6: one-to-one ───────────────────────────────────────────────────────────
log "L6 PUT naming a DIFFERENT account while a binding is live"
OTHER="other-$(openssl rand -hex 3).$PARENT"
R=$(api PUT /wallet/v1/binding "$(jq -nc --arg a "$OTHER" '{asset_account_id:$a, kind:"personal_account"}')")
HTTP=${R%% *}; BODY=${R#* }
if [[ "$HTTP" == "409" ]]; then
  pass "L6 refused with 409 — a wallet holds at most one bound identity"
else
  # Not folded into the failure above: a 400 here means the request died on a
  # different check (the account does not exist) and the one-to-one rule was
  # never reached, which is a gap in this probe rather than in the product.
  fail "L6 expected 409, got $HTTP: $(jq -r '.message // .error // .' <<<"$BODY" 2>/dev/null | head -c 200)"
fi

# ── L7: no kit for hos_lease ─────────────────────────────────────────────────
log "L7 GET the setup kit for kind=hos_lease"
R=$(api GET "/wallet/v1/binding/setup?kind=hos_lease")
HTTP=${R%% *}; BODY=${R#* }
MSG=$(jq -r '.message // .error // ""' <<<"$BODY" 2>/dev/null)
if [[ "$HTTP" == "400" ]] && grep -qi "no setup kit" <<<"$MSG"; then
  pass "L7 refused and says why: $(head -c 130 <<<"$MSG")"
else
  fail "L7 expected a 400 explaining that hos_lease accounts are provisioned by the partner, got $HTTP: $(head -c 200 <<<"$MSG")"
fi

# ── L8: DELETE, twice ────────────────────────────────────────────────────────
if [[ -n "$KEEP" ]]; then
  log "L8 SKIPPED — KEEP is set, the binding stays for the runs that need one"
  note "export for the next scripts:"
  note "  AGENT=$PARENT ASSET=$ACC WALLET_ID=$WALLET_ID BINDING_SEED=$SEED"
else
  log "L8 DELETE, then DELETE again"
  R=$(api DELETE /wallet/v1/binding); HTTP1=${R%% *}
  R=$(api DELETE /wallet/v1/binding); HTTP2=${R%% *}
  if [[ "$HTTP1" == 2?? ]]; then
    pass "L8 the binding was removed (HTTP $HTTP1)"
    BOUND=""
  else
    fail "L8 DELETE failed (HTTP $HTTP1)"
  fi
  [[ "$HTTP2" == 2?? ]] \
    && pass "L8 a second DELETE is still a success (HTTP $HTTP2) — cleanup can be re-run" \
    || fail "L8 the second DELETE answered $HTTP2 — a retried cleanup would fail on it"
fi

# ── verdict ──────────────────────────────────────────────────────────────────
log "binding lifecycle — $PASS passed, $FAILED failed"
if (( FAILED > 0 )); then
  for n in "${FAILED_NAMES[@]}"; do printf '  \033[31m✗ %s\033[0m\n' "$n" >&2; done
  exit 1
fi
exit 0
