#!/bin/bash
# The two approval rules of a wallet policy, on testnet:
#
#   approval.auto_up_to         a payment runs without the approvers while the
#                               window's total stays at most the entry
#   rules.addresses.unlisted    "ask": an address off the whitelist waits for
#                               the approvers instead of being refused
#
# One fresh wallet. Policy 1: whitelist [PARENT], unlisted = ask, one approver,
# auto_up_to.daily.native = 0.02 NEAR, per_transaction.native = 0.05 NEAR,
# daily.native = 0.045 NEAR, transaction_types = [transfer].
#
#   W1 encrypt-policy refuses a threshold that is not whole units          → 400
#   W2 encrypt-policy refuses a `*` threshold                              → 400
#   W3 encrypt-policy refuses `unlisted: ask` with no approval block       → 400
#   W4 … under a blacklist                                                 → 400
#   W5 … spelled wrongly                                                   → 400
#   X1 sign-typed-data with evm_sign off (the x402 door)                   → 403
#   N1 0.001 to an address off the list, inside the window                 → pending_approval
#   N2 the approver rejects it                                             → nothing sent
#   N3 0.051 to an address off the list (above per_transaction)            → 403, no approval
#   A0 0.03 to a listed address (above the entry by itself)                → pending_approval,
#      rejected
#   A1 0.01 to a listed address                                            → runs, no approval
#   A2 0.01 again (day total 0.02, at the entry)                           → runs, no approval
#   A3 0.001 more (the total would cross the entry)                        → pending_approval,
#      the approver signs                                                  → on chain
#   A4 0.051 (above per_transaction)                                       → 403, no approval
#   A5 0.03 (day total would pass the daily LIMIT)                         → 403, no approval
#
# Policy 2, stored over it — what "approve and add to the list" writes: the
# address of N1 is listed, and the amount is counted per month
# (auto_up_to.monthly.native = 0.04 NEAR, the month's total being 0.021).
#
#   P1 0.01 to the address N1 asked about                                  → runs, no approval
#   P2 0.01 more (month total 0.041, over the entry)                       → pending_approval,
#      rejected
#
# Policy 3: calls and delete permitted as types, both accounts listed, the
# amount counted per hour — the entry is the hour's spend so far plus 0.001.
#
#   H1 0.001 to a listed address (reaches the hour's entry)                → runs, no approval
#   H2 0.001 more                                                          → pending_approval,
#      rejected
#   C1 a contract call to a listed address, no deposit                     → pending_approval,
#      rejected: a call never runs unattended
#   C2 a contract call to an address off the list                          → 403, no approval:
#      only a payment is asked about
#   C3 delete with a beneficiary off the list                              → 403, no approval
#
# Policy 4: policy 3 with transfers excluded from approval.
#
#   E1 0.001 to a listed address, past the hour's entry                    → runs, no approval
#   E2 0.001 to an address off the list                                    → pending_approval,
#      rejected: an exclusion does not let a new address through
#
# The windows are the clock hour, the UTC day and the calendar month: a run
# that straddles the hour between H1 and H2 fails there, 00:00 UTC at A3, the
# month at P1. C3 asks to delete the wallet's account toward an address off the
# list; under a correct engine that is refused, and under a wrong one it would
# wait for an approval this suite never gives.
#
# Required env:
#   PARENT    NEAR account that stores the policy and funds the wallet
#   APPROVER  NEAR account named as the approver (its key in ~/.near-credentials)
#
# Run:
#   PARENT=outlayer-alice.testnet APPROVER=outlayer-bob.testnet \
#       ./tests/policy_auto_approval_e2e.sh --apply

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPLY=false
[[ "${1:-}" == "--apply" ]] && APPLY=true

NETWORK="${NETWORK:-testnet}"
PARENT="${PARENT:-}"
APPROVER="${APPROVER:-}"
source "$SCRIPT_DIR/lib/rpc.sh"   # keyed RPC_URL, or a warning
CONTRACT_ID="${CONTRACT_ID:-outlayer.testnet}"
COORDINATOR_URL="${COORDINATOR_URL:-https://testnet-api.outlayer.ai}"

[[ -n "$PARENT" && -n "$APPROVER" ]] || { echo "USAGE: PARENT=... APPROVER=... $0 --apply" >&2; exit 1; }
[[ "$PARENT" != "$APPROVER" ]] || { echo "✗ APPROVER must differ from PARENT: it is the address off the list" >&2; exit 1; }

APPROVER_CREDS="${APPROVER_CREDS:-$HOME/.near-credentials/$NETWORK/$APPROVER.json}"
[[ -f "$APPROVER_CREDS" ]] || { echo "✗ creds missing: $APPROVER_CREDS" >&2; exit 1; }

for tool in jq curl near bc; do
  command -v "$tool" >/dev/null || { echo "✗ missing $tool" >&2; exit 1; }
done

log()  { printf '\n\033[36m▶ %s\033[0m\n' "$*" >&2; }
warn() { printf '\033[33m⚠ %s\033[0m\n' "$*" >&2; }
pass() { printf '\033[32m✓ %s\033[0m\n' "$*" >&2; }
fail() { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

near_tty() {
  if command -v script >/dev/null 2>&1 && [ -t 1 ]; then
    local tmp; tmp=$(mktemp -t autoapr_cmd.XXXXXX.sh)
    printf 'set -euo pipefail\n%s\n' "$*" > "$tmp"
    script -q /dev/null bash "$tmp"; local rc=$?
    rm -f "$tmp"; return $rc
  else
    eval "$@"
  fi
}

if [[ "$APPLY" != true ]]; then
  warn "Dry-run mode. Pass --apply to create a wallet, store a policy and send testnet NEAR."
  exit 0
fi

RECOVERY_BIN="$SCRIPT_DIR/../scripts/customer-recovery/target/release/customer-recovery"
log "Building customer-recovery (sign-nep413)"
(cd "$SCRIPT_DIR/../scripts/customer-recovery" && cargo build --release --quiet) || fail "customer-recovery build failed"

APPROVER_PRIVKEY=$(jq -r '.private_key' "$APPROVER_CREDS")
APPROVER_PUBKEY=$(jq -r '.public_key' "$APPROVER_CREDS")

NEAR_001="1000000000000000000000"      # 0.001
NEAR_01="10000000000000000000000"      # 0.01
NEAR_02="20000000000000000000000"      # 0.02
NEAR_03="30000000000000000000000"      # 0.03
NEAR_04="40000000000000000000000"      # 0.04
NEAR_045="45000000000000000000000"     # 0.045
NEAR_05="50000000000000000000000"      # 0.05
NEAR_051="51000000000000000000000"     # 0.051

# ─── Wallet ──────────────────────────────────────────────────────

log "Register a wallet and fund it"
REG_RESP=$(curl -sS -X POST "$COORDINATOR_URL/register" -H 'Content-Type: application/json' -d '{}')
WK_API_KEY=$(echo "$REG_RESP" | jq -r '.api_key // empty')
WALLET_ID=$(echo "$REG_RESP"  | jq -r '.wallet_id // empty')
WALLET_ADDR=$(echo "$REG_RESP" | jq -r '.near_account_id // empty')
[[ -n "$WK_API_KEY" && -n "$WALLET_ADDR" ]] || \
  fail "/register failed: $(jq -c 'del(.api_key, .handoff_url)' <<<"$REG_RESP" 2>/dev/null | head -c 300)"
AUTH_HDR="Authorization: Bearer $WK_API_KEY"
ADDR_RESP=$(curl -sS -G "$COORDINATOR_URL/wallet/v1/address" --data-urlencode "chain=near" -H @<(printf '%s\n' "$AUTH_HDR"))
WALLET_PUBKEY_HEX="ed25519:$(echo "$ADDR_RESP" | jq -r '.public_key' | sed 's/^ed25519://')"
pass "wallet $WALLET_ID  addr=$WALLET_ADDR  api_key: ${#WK_API_KEY} chars"

near_tty "near --quiet tokens $PARENT send-near $WALLET_ADDR '0.2 NEAR' \\
  network-config $NETWORK sign-with-keychain send" || fail "funding the wallet failed"
for _ in 1 2 3 4 5 6; do
  if curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"query\",\"params\":{\"request_type\":\"view_account\",\"finality\":\"final\",\"account_id\":\"$WALLET_ADDR\"}}" \
    | jq -e '.result.amount' >/dev/null; then break; fi
  sleep 2
done
pass "wallet funded"

# ─── Policy writes the engine refuses ────────────────────────────

# POST encrypt-policy with the given `rules` and `approval`; prints "<http>\n<body>".
encrypt_policy() {
  local rules="$1" approval="$2" body
  body=$(jq -nc --arg wid "$WALLET_ID" --argjson rules "$rules" --argjson approval "$approval" \
    '{wallet_id: $wid, rules: $rules} + (if $approval == null then {} else {approval: $approval} end)')
  curl -sS -w '\n%{http_code}' -X POST "$COORDINATOR_URL/wallet/v1/encrypt-policy" \
    -H @<(printf '%s\n' "$AUTH_HDR") -H 'Content-Type: application/json' -d "$body"
}

APPROVERS=$(jq -nc --arg a "$APPROVER" --arg pk "$APPROVER_PUBKEY" '[{id: $a, pubkey: $pk}]')
approval_with() {   # $1 = auto_up_to JSON
  jq -nc --argjson approvers "$APPROVERS" --argjson up_to "$1" \
    '{threshold: {required: 1}, approvers: $approvers, auto_up_to: $up_to}'
}
expect_refused() {  # $1 = label, $2 = rules, $3 = approval, $4 = words the refusal must hold
  local out code body
  out=$(encrypt_policy "$2" "$3"); code=$(echo "$out" | tail -n1); body=$(echo "$out" | sed '$d')
  if [[ "$code" == "400" ]] && echo "$body" | grep -q "$4"; then
    pass "$1 → 400: $(echo "$body" | jq -r '.message // .error' | head -c 160)"
  else
    fail "$1: expected 400 naming '$4', got HTTP $code: $(echo "$body" | jq -c 'del(.encrypted_base64)' 2>/dev/null | head -c 300)"
  fi
}

log "W1–W5 encrypt-policy refuses what could not be applied"
PLAIN_RULES='{"transaction_types":["transfer"]}'
expect_refused "W1 a threshold that is not whole units" "$PLAIN_RULES" \
  "$(approval_with '{"daily":{"native":"0.5"}}')" "auto_up_to"
expect_refused "W2 a '*' threshold" "$PLAIN_RULES" \
  "$(approval_with '{"daily":{"*":"1"}}')" "auto_up_to"
expect_refused "W3 unlisted=ask with nobody to ask" \
  "$(jq -nc --arg p "$PARENT" '{addresses: {mode: "whitelist", list: [$p], unlisted: "ask"}}')" \
  "null" "unlisted"
QUORUM=$(jq -nc --argjson approvers "$APPROVERS" '{threshold: {required: 1}, approvers: $approvers}')
expect_refused "W4 unlisted=ask under a blacklist" \
  "$(jq -nc --arg p "$PARENT" '{addresses: {mode: "blacklist", list: [$p], unlisted: "ask"}}')" \
  "$QUORUM" "unlisted"
expect_refused "W5 unlisted spelled wrongly" \
  "$(jq -nc --arg p "$PARENT" '{addresses: {mode: "whitelist", list: [$p], unlisted: "prompt"}}')" \
  "$QUORUM" "unlisted"

# ─── The policy under test ───────────────────────────────────────

# Encrypt, sign and store a policy from PARENT's account.
store_policy() {  # $1 = rules, $2 = approval
  local out code enc b64 sign sig args
  out=$(encrypt_policy "$1" "$2"); code=$(echo "$out" | tail -n1); enc=$(echo "$out" | sed '$d')
  b64=$(echo "$enc" | jq -r '.encrypted_base64 // empty')
  [[ "$code" == "200" && -n "$b64" ]] || fail "encrypt-policy HTTP $code: $(echo "$enc" | head -c 300)"
  sign=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/sign-policy" -H @<(printf '%s\n' "$AUTH_HDR") \
    -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg ed "$b64" --arg c "$PARENT" '{encrypted_data: $ed, caller: $c}')")
  sig=$(echo "$sign" | jq -r '.signature_hex // empty')
  [[ -n "$sig" ]] || fail "sign-policy: $(echo "$sign" | head -c 300)"
  args=$(jq -nc --arg pk "$WALLET_PUBKEY_HEX" --arg ed "$b64" --arg sg "$sig" \
    --argjson v "$(echo "$sign" | jq '.version // 0')" \
    --argjson l "$(echo "$sign" | jq '.locked // false')" \
    --argjson u "$(echo "$sign" | jq '.valid_until // 0')" \
    '{wallet_pubkey: $pk, encrypted_data: $ed, wallet_signature: $sg, version: $v, locked: $l, valid_until: $u}')
  near_tty "near contract call-function as-transaction $CONTRACT_ID store_wallet_policy \\
    json-args '$args' \\
    prepaid-gas '100.0 Tgas' attached-deposit '0.1 NEAR' \\
    sign-as $PARENT network-config $NETWORK sign-with-keychain send" || fail "store_wallet_policy failed"
}
# Wait until a policy read answers the stored one: jq filter $1 must print $2.
policy_reads() {
  local read
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    read=$(curl -sS "$COORDINATOR_URL/wallet/v1/policy" -H @<(printf '%s\n' "$AUTH_HDR"))
    [[ "$(echo "$read" | jq -r "$1 // empty")" == "$2" ]] && return 0
    sleep 3
  done
  fail "the stored policy does not read back $1 = $2"
}

log "Policy 1: whitelist [$PARENT], unlisted=ask, 0.02 NEAR a day without asking, 0.05 per transaction, 0.045 a day"
RULES=$(jq -nc --arg p "$PARENT" --arg per_tx "$NEAR_05" --arg daily "$NEAR_045" '{
  transaction_types: ["transfer"],
  addresses: {mode: "whitelist", list: [$p], unlisted: "ask"},
  limits: {per_transaction: {native: $per_tx}, daily: {native: $daily}}
}')
store_policy "$RULES" "$(approval_with "$(jq -nc --arg d "$NEAR_02" '{daily: {native: $d}}')")"
policy_reads '.rules.addresses.unlisted' "ask"
policy_reads '.approval.auto_up_to.daily.native' "$NEAR_02"
pass "policy 1 on chain, and read back with both rules"

# ─── Helpers ─────────────────────────────────────────────────────

# POST a transfer; prints "<http>\n<body>".
transfer() {  # $1 = to, $2 = yocto
  curl -sS -w '\n%{http_code}' -X POST "$COORDINATOR_URL/wallet/v1/transfer" -H @<(printf '%s\n' "$AUTH_HDR") \
    -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg to "$1" --arg a "$2" '{chain: "near", to: $to, amount: $a}')"
}
# Wait for a request to finish; prints its tx hash.
wait_done() {  # $1 = request_id
  local s st
  for _ in $(seq 1 20); do
    s=$(curl -sS "$COORDINATOR_URL/wallet/v1/requests/$1" -H @<(printf '%s\n' "$AUTH_HDR"))
    st=$(echo "$s" | jq -r '.status')
    case "$st" in
      completed|success) echo "$s" | jq -r '.result.tx_hash // .result.transaction_hash // empty'; return 0;;
      failed) fail "request $1 failed: $(echo "$s" | jq -c '.result' | head -c 300)";;
    esac
    sleep 3
  done
  fail "request $1 did not finish in a minute (last status: $st)"
}
# A transfer that must run with no approver.
runs_alone() {  # $1 = label, $2 = to, $3 = yocto
  local out code body approval req tx
  out=$(transfer "$2" "$3"); code=$(echo "$out" | tail -n1); body=$(echo "$out" | sed '$d')
  approval=$(echo "$body" | jq -r '.approval_id // .approval.id // empty')
  [[ "$code" == "200" && -z "$approval" ]] || fail "$1: expected to run alone, got HTTP $code: $(echo "$body" | head -c 300)"
  tx=$(echo "$body" | jq -r '.tx_hash // .result.tx_hash // empty')
  if [[ -z "$tx" ]]; then
    req=$(echo "$body" | jq -r '.request_id // empty')
    [[ -n "$req" ]] || fail "$1: no tx hash and no request id: $(echo "$body" | head -c 300)"
    tx=$(wait_done "$req")
  fi
  [[ -n "$tx" ]] || fail "$1: finished with no tx hash"
  pass "$1 → ran without approval, tx $tx"
}
# A transfer that must wait; sets APPROVAL_ID and REQUEST_ID.
must_wait() {  # $1 = label, $2 = to, $3 = yocto
  local out code body
  out=$(transfer "$2" "$3"); code=$(echo "$out" | tail -n1); body=$(echo "$out" | sed '$d')
  APPROVAL_ID=$(echo "$body" | jq -r '.approval_id // .approval.id // empty')
  REQUEST_ID=$(echo "$body" | jq -r '.request_id // .request.id // empty')
  [[ -n "$APPROVAL_ID" ]] || fail "$1: expected pending_approval, got HTTP $code: $(echo "$body" | head -c 300)"
  pass "$1 → pending_approval $APPROVAL_ID"
}
# The approver's vote on APPROVAL_ID; prints the HTTP code.
vote() {  # $1 = approve | reject
  local details hash pubkey nonce sig
  details=$(curl -sS "$COORDINATOR_URL/wallet/v1/approval/$APPROVAL_ID")
  hash=$(echo "$details" | jq -r '.request_hash'); pubkey=$(echo "$details" | jq -r '.wallet_pubkey')
  nonce=$(head -c 32 /dev/urandom | base64 | tr -d '\n')
  sig=$(CUSTOMER_RECOVERY_PRIVATE_KEY="$APPROVER_PRIVKEY" "$RECOVERY_BIN" sign-nep413 \
    --message "$1:$APPROVAL_ID:$pubkey:$hash" --recipient "$CONTRACT_ID" --nonce-base64 "$nonce" | jq -r '.signature')
  curl -sS -o /dev/null -w '%{http_code}' -X POST "$COORDINATOR_URL/wallet/v1/$1/$APPROVAL_ID" \
    -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg sig "$sig" --arg pk "$APPROVER_PUBKEY" --arg ac "$APPROVER" --arg nc "$nonce" \
         '{signature: $sig, public_key: $pk, account_id: $ac, nonce: $nc}')"
}

# The approver's reject of APPROVAL_ID, waited for until it cancels.
reject_it() {  # $1 = label
  local code status
  code=$(vote reject)
  [[ "$code" == "200" ]] || fail "$1: reject returned HTTP $code"
  # A reject cancels once the vote is held at a final block; until then it is recorded.
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    status=$(curl -sS "$COORDINATOR_URL/wallet/v1/approval/$APPROVAL_ID" | jq -r '.status')
    [[ "$status" == "rejected" ]] && { pass "$1 rejected, nothing sent"; return 0; }
    sleep 3
  done
  fail "$1: the approval is '$status' after the only approver rejected it"
}
# A transfer that must be refused outright, with no approval opened.
refused() {  # $1 = label, $2 = to, $3 = yocto
  local out code body
  out=$(transfer "$2" "$3"); code=$(echo "$out" | tail -n1); body=$(echo "$out" | sed '$d')
  [[ "$code" == "403" && -z "$(echo "$body" | jq -r '.approval_id // empty')" ]] || \
    fail "$1: expected 403 with no approval, got HTTP $code: $(echo "$body" | head -c 300)"
  pass "$1 → 403: $(echo "$body" | jq -r '.message // .error // empty' | head -c 120)"
}

# ─── X: the x402 door stays shut ─────────────────────────────────

log "X1 sign-typed-data (an EIP-3009 authorization) with evm_sign off"
X_BODY=$(jq -nc --arg to "0x1111111111111111111111111111111111111111" '{
  chain: "base",
  typed_data: {
    domain: {name: "USD Coin", version: "2", chainId: 8453, verifyingContract: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"},
    types: {
      EIP712Domain: [{name: "name", type: "string"}, {name: "version", type: "string"}, {name: "chainId", type: "uint256"}, {name: "verifyingContract", type: "address"}],
      TransferWithAuthorization: [{name: "from", type: "address"}, {name: "to", type: "address"}, {name: "value", type: "uint256"}, {name: "validAfter", type: "uint256"}, {name: "validBefore", type: "uint256"}, {name: "nonce", type: "bytes32"}]
    },
    primaryType: "TransferWithAuthorization",
    message: {from: "0x2222222222222222222222222222222222222222", to: $to, value: "1000000", validAfter: "0", validBefore: "9999999999", nonce: "0x0000000000000000000000000000000000000000000000000000000000000001"}
  }
}')
X_CODE=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$COORDINATOR_URL/wallet/v1/evm/sign-typed-data" -H @<(printf '%s\n' "$AUTH_HDR") \
  -H 'Content-Type: application/json' -d "$X_BODY")
[[ "$X_CODE" == "403" ]] || fail "X1: expected 403 under a policy with evm_sign off, got HTTP $X_CODE"
pass "X1 → 403: no EIP-3009 signature under this policy"

# ─── N: a new address asks ───────────────────────────────────────

log "N1 0.001 NEAR to $APPROVER — not on the list, inside the window"
must_wait "N1 an address off the list" "$APPROVER" "$NEAR_001"
OP_TO=$(curl -sS "$COORDINATOR_URL/wallet/v1/approval/$APPROVAL_ID" | jq -r '.op.to // empty')
[[ "$OP_TO" == "$APPROVER" ]] || fail "N1: the approval does not carry the address the approver signs over (op.to='$OP_TO')"

log "N2 the approver rejects it"
reject_it "N2"

log "N3 0.051 NEAR to the same address: above the per-transaction limit"
refused "N3 a new address above a limit" "$APPROVER" "$NEAR_051"

# ─── A: the window ───────────────────────────────────────────────

log "A0 0.03 NEAR to a listed address: above the entry by itself"
must_wait "A0 an amount above the entry" "$PARENT" "$NEAR_03"
reject_it "A0"

log "A1–A2 two payments of 0.01 NEAR to a listed address: the day's total reaches the entry"
runs_alone "A1 0.01 (total 0.01)" "$PARENT" "$NEAR_01"
runs_alone "A2 0.01 (total 0.02, at the entry)" "$PARENT" "$NEAR_01"

log "A3 0.001 more: the total would cross the entry"
must_wait "A3 the payment that crosses the window" "$PARENT" "$NEAR_001"
CODE=$(vote approve)
[[ "$CODE" == "200" ]] || fail "A3: approve returned HTTP $CODE"
TX=$(wait_done "$REQUEST_ID")
[[ -n "$TX" ]] || fail "A3: approved, finished with no tx hash"
pass "A3 approved → on chain, tx $TX"

log "A4 0.051 NEAR: above the per-transaction limit"
refused "A4 above per_transaction" "$PARENT" "$NEAR_051"

log "A5 0.03 NEAR: the day's total (0.021) would pass the daily limit of 0.045"
refused "A5 above the daily limit" "$PARENT" "$NEAR_03"

# ─── Policy 2: the address is listed, the amount is counted per month ──

log "Policy 2: $APPROVER added to the list, 0.04 NEAR a month without asking"
RULES2=$(jq -nc --arg p "$PARENT" --arg a "$APPROVER" --arg per_tx "$NEAR_05" --arg daily "$NEAR_045" '{
  transaction_types: ["transfer"],
  addresses: {mode: "whitelist", list: [$p, $a], unlisted: "ask"},
  limits: {per_transaction: {native: $per_tx}, daily: {native: $daily}}
}')
store_policy "$RULES2" "$(approval_with "$(jq -nc --arg m "$NEAR_04" '{monthly: {native: $m}}')")"
policy_reads '.approval.auto_up_to.monthly.native' "$NEAR_04"
policy_reads '.rules.addresses.list | length' "2"
pass "policy 2 on chain"

log "P1 0.01 NEAR to $APPROVER, now listed (month total 0.031)"
runs_alone "P1 the address N1 asked about, once listed" "$APPROVER" "$NEAR_01"

log "P2 0.01 NEAR more: the month's total (0.041) would cross the entry"
must_wait "P2 the payment that crosses the month" "$APPROVER" "$NEAR_01"
reject_it "P2"

# ─── Policy 3: per hour; calls and delete ────────────────────────

# POST any wallet operation; prints "<http>\n<body>".
wallet_post() {  # $1 = path, $2 = body
  curl -sS -w '\n%{http_code}' -X POST "$COORDINATOR_URL$1" -H @<(printf '%s\n' "$AUTH_HDR") -H 'Content-Type: application/json' -d "$2"
}
# An operation that must wait; sets APPROVAL_ID.
op_must_wait() {  # $1 = label, $2 = path, $3 = body
  local out code body
  out=$(wallet_post "$2" "$3"); code=$(echo "$out" | tail -n1); body=$(echo "$out" | sed '$d')
  APPROVAL_ID=$(echo "$body" | jq -r '.approval_id // .approval.id // empty')
  [[ -n "$APPROVAL_ID" ]] || fail "$1: expected pending_approval, got HTTP $code: $(echo "$body" | head -c 300)"
  pass "$1 → pending_approval $APPROVAL_ID"
}
# An operation that must be refused for its address, with no approval opened.
op_refused_for_address() {  # $1 = label, $2 = path, $3 = body
  local out code body
  out=$(wallet_post "$2" "$3"); code=$(echo "$out" | tail -n1); body=$(echo "$out" | sed '$d')
  if [[ "$code" == "403" && -z "$(echo "$body" | jq -r '.approval_id // empty')" ]] && echo "$body" | grep -q "not in whitelist"; then
    pass "$1 → 403: $(echo "$body" | jq -r '.message // .error // empty' | head -c 120)"
  else
    fail "$1: expected 403 'not in whitelist' with no approval, got HTTP $code: $(echo "$body" | head -c 300)"
  fi
}

# The wallet has spent today, so the read must state the day's spend; the hour's
# is absent only when the hour turned over since.
USAGE=$(curl -sS "$COORDINATOR_URL/wallet/v1/policy" -H @<(printf '%s\n' "$AUTH_HDR") | jq -c '.usage // {}')
[[ "$(echo "$USAGE" | jq -r '.daily.native.spent // empty')" =~ ^[0-9]+$ ]] || \
  fail "the policy read does not state the day's native spend: $USAGE"
SPENT_HOUR=$(echo "$USAGE" | jq -r '.hourly.native.spent // "0"')
[[ "$SPENT_HOUR" =~ ^[0-9]+$ ]] || fail "the policy read states the hour's native spend as '$SPENT_HOUR'"
HOUR_ENTRY=$(echo "$SPENT_HOUR + $NEAR_001" | bc)
log "Policy 3: calls and delete permitted, 0.001 NEAR more this hour without asking (the hour holds $SPENT_HOUR)"
rules_3() {  # prints the rules of policies 3 and 4
  jq -nc --arg p "$PARENT" --arg a "$APPROVER" --arg per_tx "$NEAR_05" --arg daily "$NEAR_045" '{
    transaction_types: ["transfer", "call", "delete"],
    addresses: {mode: "whitelist", list: [$p, $a], unlisted: "ask"},
    limits: {per_transaction: {native: $per_tx}, daily: {native: $daily}}
  }'
}
APPROVAL_3=$(approval_with "$(jq -nc --arg h "$HOUR_ENTRY" '{hourly: {native: $h}}')")
store_policy "$(rules_3)" "$APPROVAL_3"
policy_reads '.approval.auto_up_to.hourly.native' "$HOUR_ENTRY"
pass "policy 3 on chain"

log "H1–H2 the hour's entry"
runs_alone "H1 0.001 (reaches the hour's entry)" "$PARENT" "$NEAR_001"
must_wait "H2 the payment that crosses the hour" "$PARENT" "$NEAR_001"
reject_it "H2"

log "C1 a contract call to a listed address"
op_must_wait "C1 a call, though nothing is attached" "/wallet/v1/call" \
  "$(jq -nc --arg to "$APPROVER" '{receiver_id: $to, method_name: "noop", args: {}, deposit: "0"}')"
reject_it "C1"

log "C2 a contract call to $CONTRACT_ID, off the list"
op_refused_for_address "C2 a call to an address off the list" "/wallet/v1/call" \
  "$(jq -nc --arg to "$CONTRACT_ID" '{receiver_id: $to, method_name: "noop", args: {}, deposit: "0"}')"

log "C3 delete with beneficiary $CONTRACT_ID, off the list"
op_refused_for_address "C3 a delete toward an address off the list" "/wallet/v1/delete" \
  "$(jq -nc --arg to "$CONTRACT_ID" '{beneficiary: $to}')"

# ─── Policy 4: transfers excluded from approval ──────────────────

log "Policy 4: policy 3 with transfers excluded from approval"
store_policy "$(rules_3)" "$(echo "$APPROVAL_3" | jq -c '. + {excluded_types: ["transfer"]}')"
policy_reads '.approval.excluded_types[0]' "transfer"
pass "policy 4 on chain"

log "E1 0.001 NEAR to a listed address, past the hour's entry"
runs_alone "E1 an excluded type runs whatever the window says" "$PARENT" "$NEAR_001"

log "E2 0.001 NEAR to $CONTRACT_ID, off the list"
must_wait "E2 a new address, though transfers are excluded" "$CONTRACT_ID" "$NEAR_001"
reject_it "E2"

echo
pass "ALL CHECKS PASSED: W1–W5, X1, N1–N3, A0–A5, P1–P2, H1–H2, C1–C3, E1–E2"
warn "Left behind: wallet $WALLET_ADDR with its policy and what remains of 0.2 NEAR."
