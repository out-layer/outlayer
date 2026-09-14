#!/usr/bin/env bash
#
# A7.1 + A7.2 — what the `addresses.mode` fix did to wallets that ALREADY EXIST.
#
# The fix closed a fail-open: an unrecognised `mode` used to switch the address
# filter off entirely, with the policy still listing the addresses it had
# stopped enforcing. Reading it at its strictest is right, but it changes the
# answer for live wallets at the moment of deploy — so both directions need a
# live run, and neither can be checked any other way. Policies are encrypted
# for the keystore: nothing can enumerate which wallets use which mode, and no
# database query will ever answer "who is about to break". Only a probe can.
#
# Probes:
#   P1  mode "none" still means none. A destination that is NOT in the list is
#       allowed through. The first attempt at this fix rejected "none" as well —
#       and "none" is a documented value AND the dashboard form's own default,
#       so that would have broken every wallet saved through the UI
#   P2  the control that makes P1 mean something. Same wallet, same list, same
#       destination, `mode` REMOVED — now the destination must be REFUSED.
#       Without this, P1 passes just as well on a build where the address filter
#       never runs at all, which is the one outcome it exists to rule out
#   P3  a listed destination under that same default is allowed — the whitelist
#       is a filter, not a deny-all
#   P4  mode "allowlist" (the plausible typo for "whitelist") is refused, and
#       the refusal is USABLE: it contains the offending word and says what to
#       do about it. This is the whole point of the message — the policy is
#       encrypted, so this sentence is the only thing that will ever show the
#       owner which word broke their wallet. Asserting the 403 alone would pass
#       against "policy denied", which tells them nothing
#
# P4 is deliberately aimed at a LISTED address: under a correct reading an
# unusable rule denies everything, so even an address the owner believes is
# permitted must be refused. An off-list destination would have been refused by
# a plain whitelist too, and the probe would prove nothing.
#
# Money: two sub-wallets funded with 0.15 NEAR each from $PARENT and swept back
# on exit, including on abort. Real cost is gas plus 0.1 NEAR of storage deposit
# per policy store (four stores here). Each transfer moves 0.001 NEAR.
#
# Requires: $PARENT with a keychain credential and ~0.8 NEAR, `outlayer` logged
# in as $PARENT, and $STRANGER — any EXISTING testnet account that is not
# $PARENT (a transfer to a non-existent account fails on chain and would be
# read here as a policy refusal).
#
# Run (spends real testnet NEAR):
#   PARENT=you.testnet STRANGER=other.testnet ./tests/wallet_policy_mode_e2e.sh --apply

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPLY=false
[[ "${1:-}" == "--apply" ]] && APPLY=true

NETWORK="${NETWORK:-testnet}"
CONTRACT_ID="${CONTRACT_ID:-outlayer.testnet}"
COORDINATOR_URL="${COORDINATOR_URL:-https://testnet-api.outlayer.ai}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/rpc.sh"   # keyed RPC_URL, or a warning
PARENT="${PARENT:-}"
STRANGER="${STRANGER:-}"

SEND_YOCTO="1000000000000000000000"   # 0.001 NEAR
FUND_NEAR="0.15"

PASS=0; FAILED=0; FAILED_NAMES=()
log()  { printf '\n\033[36m▶ %s\033[0m\n' "$*" >&2; }
note() { printf '\033[35m• %s\033[0m\n' "$*" >&2; }
warn() { printf '\033[33m⚠ %s\033[0m\n' "$*" >&2; }
pass() { printf '\033[32m✓ %s\033[0m\n' "$*" >&2; PASS=$((PASS+1)); }
fail() { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; FAILED=$((FAILED+1)); FAILED_NAMES+=("$*"); }

if [[ "$APPLY" != true ]]; then
  sed -n '3,46p' "$0" >&2
  echo "  Pass --apply to run." >&2
  exit 0
fi

[[ -n "$PARENT" && -n "$STRANGER" ]] \
  || { echo "USAGE: PARENT=you.testnet STRANGER=other.testnet $0 --apply" >&2; exit 1; }
[[ "$PARENT" != "$STRANGER" ]] \
  || { echo "✗ STRANGER must differ from PARENT — P1 and P2 need an off-list address" >&2; exit 1; }
for tool in jq curl near outlayer cargo; do
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

LEDGER="$(mktemp -t polmode_ledger.XXXXXX)"

near_tty() {
  if command -v script >/dev/null 2>&1 && [ -t 1 ]; then
    local tmp; tmp=$(mktemp -t polmode_cmd.XXXXXX.sh)
    printf 'set -euo pipefail\n%s\n' "$*" > "$tmp"
    script -q /dev/null bash "$tmp"; local rc=$?; rm -f "$tmp"; return $rc
  else eval "$@"; fi
}

mk_token() { "$RECOVERY_BIN" sign-bearer-near --private-key "$PARENT_PRIVKEY" --account-id "$PARENT" --seed "$1"; }
AUTH() { echo "Authorization: Bearer near:$(mk_token "$1")"; }

chain_balance() {
  curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg a "$1" '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"view_account",finality:"final",account_id:$a}}')" \
    2>/dev/null | jq -r 'if .result.amount then .result.amount else "0" end' 2>/dev/null || echo "0"
}

# store_policy <seed> <wallet_id> <rules-json> — encrypt, sign, put on chain.
store_policy() {
  local seed=$1 wid=$2 pol=$3 body enc encb64 sg sig_hex pub_hex store_args
  body=$(jq -nc --arg wid "$wid" --argjson p "$pol" '$p + {wallet_id:$wid}')
  enc=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/encrypt-policy" \
    -H "$(AUTH "$seed")" -H 'Content-Type: application/json' -d "$body")
  encb64=$(echo "$enc" | jq -r '.encrypted_base64 // empty')
  [[ -n "$encb64" ]] || { warn "encrypt-policy failed: $(head -c 200 <<<"$enc")"; return 1; }
  sg=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/sign-policy" \
    -H "$(AUTH "$seed")" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg ed "$encb64" --arg c "$PARENT" '{encrypted_data:$ed, caller:$c}')")
  sig_hex=$(echo "$sg" | jq -r '.signature_hex // empty')
  pub_hex=$(echo "$sg" | jq -r '.public_key_hex // empty')
  [[ -n "$sig_hex" ]] || { warn "sign-policy failed: $(head -c 200 <<<"$sg")"; return 1; }
  store_args=$(jq -nc --arg pk "ed25519:$pub_hex" --arg ed "$encb64" --arg sg "$sig_hex" \
    '{wallet_pubkey:$pk, encrypted_data:$ed, wallet_signature:$sg}')
  near_tty "near contract call-function as-transaction $CONTRACT_ID store_wallet_policy \
    json-args '$store_args' prepaid-gas '100.0 Tgas' attached-deposit '0.1 NEAR' \
    sign-as $PARENT network-config $NETWORK sign-with-keychain send" >&2 || return 1
  sleep 5
}

# An interrupted run must not leave funded accounts whose keys exist only as a
# seed in this process. P4's wallet carries an unusable policy that refuses
# everything including the delete, so the sweep replaces the policy first.
cleanup() {
  local rc=$?
  [[ -s "$LEDGER" ]] || { rm -f "$LEDGER"; return $rc; }
  log "Sweeping sub-wallets back to $PARENT"
  local seed wid addr bal
  while read -r seed wid addr; do
    [[ -n "${addr:-}" ]] || continue
    bal=$(chain_balance "$addr")
    if [[ "$bal" == "0" ]]; then note "sweep: $addr — nothing on chain"; continue; fi
    store_policy "$seed" "$wid" '{"rules":{"transaction_types":["delete"]}}' \
      || warn "sweep: $addr — sweep policy not stored; the delete below will likely 403"
    local out; out=$(mktemp -t polmode_del.XXXXXX)
    curl -sS -o "$out" -w '%{http_code}' -X POST "$COORDINATOR_URL/wallet/v1/delete" \
      -H "$(AUTH "$seed")" -H 'Content-Type: application/json' \
      -d "$(jq -nc --arg b "$PARENT" '{beneficiary:$b, chain:"near"}')" >/dev/null
    note "sweep: $addr deleted → $PARENT ($(jq -r '.status // .error // "?"' "$out" 2>/dev/null))"
    rm -f "$out"
  done < "$LEDGER"
  rm -f "$LEDGER"
  return $rc
}
trap cleanup EXIT

# new_wallet <tag> <rules-json> — mint a sub-wallet, fund it, give it a policy.
# Echoes "seed wallet_id address".
new_wallet() {
  local tag=$1 pol=$2 seed r wid addr before after send_out
  seed="polmode-$tag-$(date +%s)-$$"
  r=$(curl -sS -G "$COORDINATOR_URL/wallet/v1/address" --data-urlencode "chain=near" -H "$(AUTH "$seed")")
  wid=$(echo "$r" | jq -r '.wallet_id // empty'); addr=$(echo "$r" | jq -r '.address // empty')
  [[ -n "$wid" && -n "$addr" ]] || { warn "$tag: /address failed: $(head -c 200 <<<"$r")"; return 1; }
  printf '%s %s %s\n' "$seed" "$wid" "$addr" >> "$LEDGER"

  before=$(chain_balance "$addr")
  # Judged by the chain, never by a return code: near-cli-rs exits 0 on a
  # swallowed broadcast transient, and a funding step that never landed would
  # be read below as "the policy refused it".
  send_out=$(near_tty "near --quiet tokens $PARENT send-near $addr '$FUND_NEAR NEAR' \
    network-config $NETWORK sign-with-keychain send" 2>&1)
  after=$(chain_balance "$addr")
  if [[ "$after" == "$before" || "$after" == "0" ]]; then
    warn "$tag: funding did not land on $addr — the SENDER failed, not the coordinator"
    warn "$(tail -c 400 <<<"$send_out")"
    return 1
  fi
  store_policy "$seed" "$wid" "$pol" || { warn "$tag: policy not stored"; return 1; }
  echo "$seed $wid $addr"
}

# transfer <seed> <dest> — one POST /wallet/v1/transfer. Echoes "<http> <body>".
transfer() {
  local seed=$1 dest=$2 body http out
  out=$(mktemp -t polmode_tx.XXXXXX)
  body=$(jq -nc --arg to "$dest" --arg a "$SEND_YOCTO" '{chain:"near", to:$to, amount:$a}')
  http=$(curl -sS -o "$out" -w '%{http_code}' -X POST "$COORDINATOR_URL/wallet/v1/transfer" \
    -H "$(AUTH "$seed")" -H 'Content-Type: application/json' -d "$body")
  printf '%s %s\n' "$http" "$(tr -d '\n' < "$out")"
  rm -f "$out"
}

# Policies. The list names $PARENT in all three, so the ONLY difference between
# P1 and P2 is the mode field itself.
POL_NONE=$(jq -nc --arg p "$PARENT" \
  '{rules:{transaction_types:["transfer","delete"],addresses:{mode:"none",list:[$p]}}}')
POL_DEFAULT=$(jq -nc --arg p "$PARENT" \
  '{rules:{transaction_types:["transfer","delete"],addresses:{list:[$p]}}}')
POL_TYPO=$(jq -nc --arg p "$PARENT" \
  '{rules:{transaction_types:["transfer","delete"],addresses:{mode:"allowlist",list:[$p]}}}')

log "Minting wallet N with addresses.mode = \"none\", list = [$PARENT]"
read -r SEED_N WID_N ADDR_N < <(new_wallet none "$POL_NONE") || { fail "wallet N setup"; exit 1; }
pass "wallet N: $ADDR_N"

# ── P1: "none" means none ────────────────────────────────────────────────────
log "P1 mode \"none\": send to $STRANGER, which is NOT in the list — must pass"
R=$(transfer "$SEED_N" "$STRANGER")
HTTP=${R%% *}; BODY=${R#* }
if [[ "$HTTP" == "200" ]]; then
  pass "P1 off-list destination allowed under mode \"none\" (HTTP 200)"
else
  fail "P1 mode \"none\" refused an off-list destination (HTTP $HTTP): $(jq -r '.message // .error // .' <<<"$BODY" 2>/dev/null | head -c 200)"
fi

# ── P2: the control — same list, no mode, same destination ───────────────────
log "P2 control: replace the policy with the SAME list and NO mode — $STRANGER must now be refused"
if store_policy "$SEED_N" "$WID_N" "$POL_DEFAULT"; then
  R=$(transfer "$SEED_N" "$STRANGER")
  HTTP=${R%% *}; BODY=${R#* }
  if [[ "$HTTP" == "403" ]]; then
    pass "P2 off-list destination refused under the default whitelist (HTTP 403) — the filter does run, so P1 is not vacuous"
  else
    fail "P2 off-list destination NOT refused (HTTP $HTTP) — the address filter never engaged, which makes P1 meaningless"
  fi
else
  fail "P2 policy not stored — control skipped, P1 unproven"
fi

# ── P3: a listed destination under the same default is allowed ───────────────
log "P3 same default policy: send to $PARENT, which IS in the list — must pass"
R=$(transfer "$SEED_N" "$PARENT")
HTTP=${R%% *}; BODY=${R#* }
if [[ "$HTTP" == "200" ]]; then
  pass "P3 listed destination allowed (HTTP 200) — the whitelist filters, it is not a deny-all"
else
  fail "P3 listed destination refused (HTTP $HTTP): $(jq -r '.message // .error // .' <<<"$BODY" 2>/dev/null | head -c 200)"
fi

# ── P4: the typo is refused, and the refusal is usable ───────────────────────
log "Minting wallet T with addresses.mode = \"allowlist\" (the typo), list = [$PARENT]"
read -r SEED_T WID_T ADDR_T < <(new_wallet typo "$POL_TYPO") || { fail "wallet T setup"; exit 1; }
pass "wallet T: $ADDR_T"

log "P4 mode \"allowlist\": send to $PARENT, which IS in the list — must be refused, readably"
R=$(transfer "$SEED_T" "$PARENT")
HTTP=${R%% *}; BODY=${R#* }
MSG=$(jq -r '.message // ""' <<<"$BODY" 2>/dev/null)
ERR=$(jq -r '.error // ""' <<<"$BODY" 2>/dev/null)
if [[ "$HTTP" != "403" ]]; then
  fail "P4 unusable mode did NOT refuse (HTTP $HTTP) — the fail-open is still live"
elif [[ "$ERR" != "policy_denied" ]]; then
  fail "P4 refused but as '$ERR', not policy_denied"
elif ! grep -qi "allowlist" <<<"$MSG"; then
  fail "P4 refusal does not name the offending word — the owner cannot see which word broke it: $(head -c 200 <<<"$MSG")"
elif ! grep -qi "re-save the policy" <<<"$MSG"; then
  fail "P4 refusal names the word but not what to do about it: $(head -c 200 <<<"$MSG")"
else
  pass "P4 refused (403 policy_denied), names 'allowlist' and says to re-save the policy"
  note "message: $(head -c 220 <<<"$MSG")"
fi

# ── verdict ──────────────────────────────────────────────────────────────────
log "A7.1/A7.2 — $PASS passed, $FAILED failed"
if (( FAILED > 0 )); then
  for n in "${FAILED_NAMES[@]}"; do printf '  \033[31m✗ %s\033[0m\n' "$n" >&2; done
  exit 1
fi
exit 0
