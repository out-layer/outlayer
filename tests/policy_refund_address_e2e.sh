#!/usr/bin/env bash
# NOT RUN YET. Written without a live run: it may have bugs of its own, and a
# red line is a suspect in this file before it is one in the product. The
# coordinator refuses every intents route on testnet before it reads a refund
# address, so this runs only on mainnet; the same freshness mechanism is judged
# on testnet by tests/policy_readback_e2e.sh (F1–F6).
#
# The refund address of a cross-chain deposit is the one the policy the chain
# holds NOW names — read on every deposit, never a copy left from an earlier
# policy. MAINNET: NEAR Intents (1Click) exist only there.
#
#   R1  a policy naming refund address A for `ethereum`: a deposit quote whose
#       request names another address is told the refund goes to A
#   R2  the policy rewritten to name B: the very next deposit quote — no
#       invalidate call, no wait for the coordinator's sync — is told B
#   R3  the coordinator's copy put back on the policy naming A (PSQL_CMD): the
#       next quote is still told B, and the copy is replaced
#
# Moves no funds: a deposit quote reserves nothing and nobody pays into its
# address. Costs the policy's storage deposit (returned by the delete at the
# end) and gas. A and B are the derived `ethereum` addresses of two wallets of
# this run, so a refund, if one ever happened, lands in a wallet of ours.
#
# Values come from the repo's env files, never from defaults in this file:
# the coordinator from scripts/.env (COORDINATOR_URL_MAINNET), the RPC from
# .env through lib/rpc.sh, the nodes from .env.nodes.
#
# Run:
#   NETWORK=mainnet PARENT=<owner>.near PSQL_CMD=<mainnet one-statement psql> \
#     ./tests/policy_refund_address_e2e.sh --apply

REPO_ROOT_EARLY="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ "${NETWORK:-}" == mainnet ]] || { echo "✗ NETWORK=mainnet: the refund path runs through NEAR Intents, mainnet only" >&2; exit 1; }
[[ -f "$REPO_ROOT_EARLY/scripts/.env" ]] || { echo "✗ scripts/.env missing: it names the mainnet coordinator" >&2; exit 1; }
COORDINATOR_URL=$(set -a; source "$REPO_ROOT_EARLY/scripts/.env"; set +a; printf '%s' "${COORDINATOR_URL_MAINNET:-}")
[[ -n "$COORDINATOR_URL" ]] || { echo "✗ scripts/.env has no COORDINATOR_URL_MAINNET" >&2; exit 1; }
export COORDINATOR_URL CONTRACT_ID="${CONTRACT_ID:-outlayer.near}"

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/hos_common.sh"
source "$HOS_LIB_DIR/near_sign.sh"   # near_why

[[ "${1:-}" == "--apply" ]] || { warn "Dry run. Pass --apply: stores and deletes one wallet policy on mainnet, quotes two deposits."; exit 0; }
hos_require

SEED="refund-$(date +%s)-$$"
read -r WID _ < <(wallet_address "$SEED") || true
[[ -n "${WID:-}" ]] || { echo "✗ no wallet for seed $SEED" >&2; exit 1; }
eth_of() { api "$1" GET "/wallet/v1/address?chain=ethereum" >/dev/null; jq -r '.address // empty' <<<"$BODY"; }
ADDR_A=$(eth_of "$SEED"); ADDR_B=$(eth_of "$SEED-b")
[[ "$ADDR_A" =~ ^0x[0-9a-fA-F]{40}$ && "$ADDR_B" =~ ^0x[0-9a-fA-F]{40}$ && "$ADDR_A" != "$ADDR_B" ]] \
  || { echo "✗ two distinct derived ethereum addresses expected, got '$ADDR_A' and '$ADDR_B'" >&2; exit 1; }
# The address a request names; the policy overrides it, and the answer says where a refund goes.
ASKED=0x000000000000000000000000000000000000dEaD
note "wallet $WID (seed $SEED), owner $PARENT; A=$ADDR_A B=$ADDR_B"

policy_naming() { jq -nc --arg a "$1" '{rules:{transaction_types:["transfer"]}, refund_addresses:{ethereum:$a}}'; }
# quote — a deposit quote for 1 USDC from ethereum, naming $ASKED as the refund.
quote() {
  api "$SEED" POST /wallet/v1/intents/deposit/cross-chain \
    "$(jq -nc --arg r "$ASKED" '{chain:"ethereum", token:"USDC", amount:"1000000", refund_address:$r}')" >/dev/null
}
refunds_to() { [[ "$HTTP" == 200 ]] && grep -qF "refunds to $1" <<<"$(jq -r '.hint // empty' <<<"$BODY")"; }
chain_call() { # chain_call <method> — a controller call keyed on the wallet's pubkey
  local out
  out=$(near_tty "near contract call-function as-transaction $CONTRACT_ID $1 \
    json-args '$(jq -nc --arg k "$WALLET_PUBKEY" '{wallet_pubkey:$k}')' prepaid-gas '30.0 Tgas' attached-deposit '0 NEAR' \
    sign-as $PARENT network-config $NETWORK sign-with-keychain send" 2>&1) || { warn "$1 failed: $(near_why "$out")"; return 1; }
}
STORED=""
cleanup() { [[ -n "$STORED" ]] && { chain_call delete_wallet_policy && note "policy deleted, storage deposit returned" || warn "delete the policy of wallet $WID by hand"; }; }
trap cleanup EXIT

# ── R1 ───────────────────────────────────────────────────────────────────────
log "R1  the policy names A"
store_policy "$SEED" "$WID" "$(policy_naming "$ADDR_A")" || { fail "R1 fixture: the policy naming A was not stored"; verdict policy_refund_address; exit 1; }
STORED=1
quote
refunds_to "$ADDR_A" && pass "R1 the deposit is told its refund goes to A" \
  || fail "R1 HTTP $HTTP $(err_of): hint=$(jq -r '.hint // empty' <<<"$BODY" | head -c 240)"

# ── R2 ───────────────────────────────────────────────────────────────────────
log "R2  the policy rewritten to name B; the next quote at once"
if STORE_POLICY_NO_SETTLE=1 store_policy "$SEED" "$WID" "$(policy_naming "$ADDR_B")"; then
  quote
  refunds_to "$ADDR_B" && pass "R2 the very next deposit is told B" \
    || fail "R2 HTTP $HTTP $(err_of): the refund still follows an earlier policy: hint=$(jq -r '.hint // empty' <<<"$BODY" | head -c 240)"
else fail "R2 fixture: the policy naming B was not stored"; fi

# ── R3 ───────────────────────────────────────────────────────────────────────
log "R3  the coordinator's copy put back on the policy naming A"
if ! sql_alive; then
  skip "R3 needs PSQL_CMD: without the copy put back, the read is not judged against a stale copy"
else
  copy_names_b() { [[ "$(sql "SELECT COALESCE(policy_json->'refund_addresses'->>'ethereum', '') || ' ' || COALESCE(policy_ciphertext_sha256, '') FROM wallet_accounts WHERE wallet_id = '$WID'")" =~ ^$ADDR_B\ [0-9a-f]{64}$ ]]; }
  SYNCED=""
  for _ in $(seq 1 30); do copy_names_b && { SYNCED=1; break; }; sleep 4; done
  [[ -n "$SYNCED" ]] || warn "R3 the copy of the policy naming B was not seen in the row; a late sync can mask the probe"
  sql "UPDATE wallet_accounts SET policy_json = '$(policy_naming "$ADDR_A")'::jsonb, policy_ciphertext_sha256 = 'an-earlier-ciphertext' WHERE wallet_id = '$WID'" >/dev/null
  if [[ "$(sql "SELECT policy_json->'refund_addresses'->>'ethereum' FROM wallet_accounts WHERE wallet_id = '$WID'")" != "$ADDR_A" ]]; then
    fail "R3 fixture: the copy was not put back"
  else
    quote
    refunds_to "$ADDR_B" && pass "R3 the refund follows the chain's policy over a copy naming A" \
      || fail "R3 HTTP $HTTP $(err_of): hint=$(jq -r '.hint // empty' <<<"$BODY" | head -c 240)"
    [[ "$(sql "SELECT policy_json->'refund_addresses'->>'ethereum' FROM wallet_accounts WHERE wallet_id = '$WID'")" == "$ADDR_B" ]] \
      && pass "R3 the read replaced the copy" || fail "R3 the copy still names an earlier address"
  fi
fi

verdict policy_refund_address
