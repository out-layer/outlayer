#!/bin/bash
# A wallet policy stored BEFORE an engine release decides the same AFTER it.
#
# Policies are encrypted for the keystore, so nothing can enumerate what an
# engine change does to the wallets that already exist; only a wallet whose
# policy was stored before the release, asked the same questions after it,
# shows that. This suite has two halves, run on the two sides of a release:
#
#   --create   BEFORE the release. Registers a wallet, stores a policy from
#              PARENT's account, asks the questions below, and writes the
#              wallet's key and the policy's version to a fixture file.
#   --apply    AFTER the release. Reads the fixture and asks the same questions
#              of the same wallet and policy. Both halves hold the answers to
#              the expectations below, so a half that passes gave them.
#
# It is a release-time suite and is not in run_custody.sh: without a fixture
# made before the release there is nothing to ask.
#
# The policy holds none of the fields a release may add: whitelist [PARENT],
# one approver, per_transaction.native = 0.05 NEAR, transaction_types
# [transfer].
#
#   B0 the policy on chain is the stored one: same version, and it reads back
#      with no `approval.auto_up_to` and no `rules.addresses.unlisted`
#   B1 0.001 NEAR to a listed address       → pending_approval (then rejected)
#   B2 0.001 NEAR to an address off the list → 403, "not in whitelist"
#   B3 0.051 NEAR to a listed address       → 403, per-transaction limit
#
# Nothing is sent by either half beyond funding the wallet once: every answer
# is a refusal or an approval that is rejected.
#
# The fixture file holds the wallet's API key. It is written with mode 600
# outside the tracked tree (FIXTURE, default .idea/testnet-runners/) and is
# never printed.
#
# Required env:
#   PARENT    (--create) NEAR account that stores the policy and funds the wallet
#   APPROVER  (--create) NEAR account named as the approver; --apply reads both
#             from the fixture and needs APPROVER's key in ~/.near-credentials
#
# Run:
#   PARENT=outlayer-alice.testnet APPROVER=outlayer-bob.testnet \
#       ./tests/policy_predeploy_e2e.sh --create      # before the release
#   ./tests/policy_predeploy_e2e.sh --apply           # after it

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODE="${1:-}"

NETWORK="${NETWORK:-testnet}"
source "$SCRIPT_DIR/lib/rpc.sh"   # keyed RPC_URL, or a warning
CONTRACT_ID="${CONTRACT_ID:-outlayer.testnet}"
COORDINATOR_URL="${COORDINATOR_URL:-https://testnet-api.outlayer.ai}"
FIXTURE="${FIXTURE:-$SCRIPT_DIR/../.idea/testnet-runners/policy-predeploy.$NETWORK.env}"

log()  { printf '\n\033[36m▶ %s\033[0m\n' "$*" >&2; }
warn() { printf '\033[33m⚠ %s\033[0m\n' "$*" >&2; }
pass() { printf '\033[32m✓ %s\033[0m\n' "$*" >&2; }
fail() { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

if [[ "$MODE" != "--create" && "$MODE" != "--apply" ]]; then
  sed -n '2,40p' "$0" >&2
  exit 0
fi

for tool in jq curl near; do
  command -v "$tool" >/dev/null || fail "missing $tool"
done

near_tty() {
  if command -v script >/dev/null 2>&1 && [ -t 1 ]; then
    local tmp; tmp=$(mktemp -t predeploy_cmd.XXXXXX.sh)
    printf 'set -euo pipefail\n%s\n' "$*" > "$tmp"
    script -q /dev/null bash "$tmp"; local rc=$?
    rm -f "$tmp"; return $rc
  else
    eval "$@"
  fi
}

NEAR_001="1000000000000000000000"      # 0.001
NEAR_05="50000000000000000000000"      # 0.05
NEAR_051="51000000000000000000000"     # 0.051

if [[ "$MODE" == "--create" ]]; then
  PARENT="${PARENT:-}"; APPROVER="${APPROVER:-}"
  [[ -n "$PARENT" && -n "$APPROVER" && "$PARENT" != "$APPROVER" ]] || \
    fail "USAGE: PARENT=... APPROVER=... $0 --create (two different accounts)"
  [[ ! -e "$FIXTURE" ]] || fail "a fixture already exists at $FIXTURE — it is the pre-release wallet; move it away to make another"
else
  [[ -f "$FIXTURE" ]] || fail "no fixture at $FIXTURE — run --create before the release"
  set -a; source "$FIXTURE"; set +a
  PARENT="${PREDEPLOY_PARENT:?fixture names no PARENT}"
  APPROVER="${PREDEPLOY_APPROVER:?fixture names no APPROVER}"
fi

APPROVER_CREDS="${APPROVER_CREDS:-$HOME/.near-credentials/$NETWORK/$APPROVER.json}"
[[ -f "$APPROVER_CREDS" ]] || fail "creds missing: $APPROVER_CREDS"
APPROVER_PRIVKEY=$(jq -r '.private_key' "$APPROVER_CREDS")
APPROVER_PUBKEY=$(jq -r '.public_key' "$APPROVER_CREDS")

RECOVERY_BIN="$SCRIPT_DIR/../scripts/customer-recovery/target/release/customer-recovery"
log "Building customer-recovery (sign-nep413)"
(cd "$SCRIPT_DIR/../scripts/customer-recovery" && cargo build --release --quiet) || fail "customer-recovery build failed"

# ─── --create: the wallet and its policy ─────────────────────────

if [[ "$MODE" == "--create" ]]; then
  log "Register a wallet and fund it with 0.05 NEAR"
  REG_RESP=$(curl -sS -X POST "$COORDINATOR_URL/register" -H 'Content-Type: application/json' -d '{}')
  PREDEPLOY_WK=$(echo "$REG_RESP" | jq -r '.api_key // empty')
  PREDEPLOY_WALLET_ID=$(echo "$REG_RESP" | jq -r '.wallet_id // empty')
  PREDEPLOY_WALLET_ADDR=$(echo "$REG_RESP" | jq -r '.near_account_id // empty')
  [[ -n "$PREDEPLOY_WK" && -n "$PREDEPLOY_WALLET_ADDR" ]] || \
    fail "/register failed: $(jq -c 'del(.api_key, .handoff_url)' <<<"$REG_RESP" 2>/dev/null | head -c 300)"
  near_tty "near --quiet tokens $PARENT send-near $PREDEPLOY_WALLET_ADDR '0.05 NEAR' \\
    network-config $NETWORK sign-with-keychain send" || fail "funding the wallet failed"
  pass "wallet $PREDEPLOY_WALLET_ID  addr=$PREDEPLOY_WALLET_ADDR  api_key: ${#PREDEPLOY_WK} chars"
fi

AUTH=(-H "Authorization: Bearer ${PREDEPLOY_WK:?fixture holds no key}")

if [[ "$MODE" == "--create" ]]; then
  log "Store the policy: whitelist [$PARENT], approver $APPROVER, 0.05 NEAR per transaction"
  ADDR_RESP=$(curl -sS -G "$COORDINATOR_URL/wallet/v1/address" --data-urlencode "chain=near" "${AUTH[@]}")
  WALLET_PUBKEY_HEX="ed25519:$(echo "$ADDR_RESP" | jq -r '.public_key' | sed 's/^ed25519://')"
  BODY=$(jq -nc --arg wid "$PREDEPLOY_WALLET_ID" --arg p "$PARENT" --arg a "$APPROVER" --arg pk "$APPROVER_PUBKEY" \
    --arg per_tx "$NEAR_05" '{
      wallet_id: $wid,
      rules: {
        transaction_types: ["transfer"],
        addresses: {mode: "whitelist", list: [$p]},
        limits: {per_transaction: {native: $per_tx}}
      },
      approval: {threshold: {required: 1}, approvers: [{id: $a, pubkey: $pk}]}
    }')
  ENC=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/encrypt-policy" "${AUTH[@]}" \
    -H 'Content-Type: application/json' -d "$BODY")
  B64=$(echo "$ENC" | jq -r '.encrypted_base64 // empty')
  [[ -n "$B64" ]] || fail "encrypt-policy: $(echo "$ENC" | head -c 300)"
  SIGN=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/sign-policy" "${AUTH[@]}" \
    -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg ed "$B64" --arg c "$PARENT" '{encrypted_data: $ed, caller: $c}')")
  SIG=$(echo "$SIGN" | jq -r '.signature_hex // empty')
  [[ -n "$SIG" ]] || fail "sign-policy: $(echo "$SIGN" | head -c 300)"
  ARGS=$(jq -nc --arg pk "$WALLET_PUBKEY_HEX" --arg ed "$B64" --arg sg "$SIG" \
    --argjson v "$(echo "$SIGN" | jq '.version // 0')" \
    --argjson l "$(echo "$SIGN" | jq '.locked // false')" \
    --argjson u "$(echo "$SIGN" | jq '.valid_until // 0')" \
    '{wallet_pubkey: $pk, encrypted_data: $ed, wallet_signature: $sg, version: $v, locked: $l, valid_until: $u}')
  near_tty "near contract call-function as-transaction $CONTRACT_ID store_wallet_policy \\
    json-args '$ARGS' \\
    prepaid-gas '100.0 Tgas' attached-deposit '0.1 NEAR' \\
    sign-as $PARENT network-config $NETWORK sign-with-keychain send" || fail "store_wallet_policy failed"
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    READ=$(curl -sS "$COORDINATOR_URL/wallet/v1/policy" "${AUTH[@]}")
    [[ "$(echo "$READ" | jq -r '.rules.addresses.list[0] // empty')" == "$PARENT" ]] && break
    sleep 3
  done
  [[ "$(echo "$READ" | jq -r '.rules.addresses.list[0] // empty')" == "$PARENT" ]] || fail "the stored policy does not read back"
  PREDEPLOY_POLICY_VERSION=$(echo "$READ" | jq -r '.version // empty')
  [[ -n "$PREDEPLOY_POLICY_VERSION" ]] || fail "the policy read names no version: $(echo "$READ" | jq -c 'keys' | head -c 200)"
  pass "policy on chain, version $PREDEPLOY_POLICY_VERSION"
fi

# Kept as soon as the policy is on chain: a wallet whose questions fail below is
# still the pre-release wallet, and its key must not be lost with the run.
if [[ "$MODE" == "--create" ]]; then
  mkdir -p "$(dirname "$FIXTURE")"
  ( umask 077
    {
      echo "# The wallet of tests/policy_predeploy_e2e.sh: its policy was stored on $(date -u +%Y-%m-%dT%H:%MZ),"
      echo "# before the release it is checked against. PREDEPLOY_WK is a secret."
      echo "PREDEPLOY_WK=$PREDEPLOY_WK"
      echo "PREDEPLOY_WALLET_ID=$PREDEPLOY_WALLET_ID"
      echo "PREDEPLOY_WALLET_ADDR=$PREDEPLOY_WALLET_ADDR"
      echo "PREDEPLOY_POLICY_VERSION=$PREDEPLOY_POLICY_VERSION"
      echo "PREDEPLOY_PARENT=$PARENT"
      echo "PREDEPLOY_APPROVER=$APPROVER"
    } > "$FIXTURE" )
fi

# ─── The questions, the same on both sides of the release ────────

transfer() {  # $1 = to, $2 = yocto; prints "<http>\n<body>"
  curl -sS -w '\n%{http_code}' -X POST "$COORDINATOR_URL/wallet/v1/transfer" "${AUTH[@]}" \
    -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg to "$1" --arg a "$2" '{chain: "near", to: $to, amount: $a}')"
}
refused_with() {  # $1 = label, $2 = to, $3 = yocto, $4 = words of the refusal
  local out code body
  out=$(transfer "$2" "$3"); code=$(echo "$out" | tail -n1); body=$(echo "$out" | sed '$d')
  if [[ "$code" == "403" && -z "$(echo "$body" | jq -r '.approval_id // empty')" ]] && echo "$body" | grep -qi "$4"; then
    pass "$1 → 403: $(echo "$body" | jq -r '.message // .error // empty' | head -c 140)"
  else
    fail "$1: expected 403 naming '$4', got HTTP $code: $(echo "$body" | head -c 300)"
  fi
}

log "B0 the policy is the one stored before the release"
READ=$(curl -sS "$COORDINATOR_URL/wallet/v1/policy" "${AUTH[@]}")
VERSION=$(echo "$READ" | jq -r '.version // empty')
[[ "$VERSION" == "$PREDEPLOY_POLICY_VERSION" ]] || \
  fail "B0: the policy is version '$VERSION', the fixture stored version '$PREDEPLOY_POLICY_VERSION' — it was rewritten, so it is no longer a pre-release policy"
[[ "$(echo "$READ" | jq -r '.approval | has("auto_up_to")')" == "false" ]] || fail "B0: the policy reads back with approval.auto_up_to"
[[ "$(echo "$READ" | jq -r '.rules.addresses | has("unlisted")')" == "false" ]] || fail "B0: the policy reads back with addresses.unlisted"
[[ "$(echo "$READ" | jq -r '.approval.threshold.required // .approval.threshold')" == "1" ]] || fail "B0: the threshold is not 1"
pass "B0 version $VERSION, no auto_up_to, no unlisted"

log "B1 0.001 NEAR to $PARENT (listed): waits for the approver"
OUT=$(transfer "$PARENT" "$NEAR_001"); CODE=$(echo "$OUT" | tail -n1); BODY=$(echo "$OUT" | sed '$d')
APPROVAL_ID=$(echo "$BODY" | jq -r '.approval_id // .approval.id // empty')
[[ -n "$APPROVAL_ID" ]] || fail "B1: expected pending_approval, got HTTP $CODE: $(echo "$BODY" | head -c 300)"
pass "B1 → pending_approval $APPROVAL_ID"

DETAILS=$(curl -sS "$COORDINATOR_URL/wallet/v1/approval/$APPROVAL_ID")
NONCE=$(head -c 32 /dev/urandom | base64 | tr -d '\n')
SIG=$(CUSTOMER_RECOVERY_PRIVATE_KEY="$APPROVER_PRIVKEY" "$RECOVERY_BIN" sign-nep413 \
  --message "reject:$APPROVAL_ID:$(echo "$DETAILS" | jq -r '.wallet_pubkey'):$(echo "$DETAILS" | jq -r '.request_hash')" \
  --recipient "$CONTRACT_ID" --nonce-base64 "$NONCE" | jq -r '.signature')
CODE=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$COORDINATOR_URL/wallet/v1/reject/$APPROVAL_ID" \
  -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg sig "$SIG" --arg pk "$APPROVER_PUBKEY" --arg ac "$APPROVER" --arg nc "$NONCE" \
       '{signature: $sig, public_key: $pk, account_id: $ac, nonce: $nc}')")
[[ "$CODE" == "200" ]] || fail "B1: reject returned HTTP $CODE"
# A reject cancels once the vote is held at a final block; until then it is recorded.
for _ in 1 2 3 4 5 6 7 8 9 10; do
  STATUS=$(curl -sS "$COORDINATOR_URL/wallet/v1/approval/$APPROVAL_ID" | jq -r '.status')
  [[ "$STATUS" == "rejected" ]] && break
  sleep 3
done
[[ "$STATUS" == "rejected" ]] || fail "B1: the approval is '$STATUS' after the only approver rejected it"
pass "B1 rejected, nothing sent"

log "B2 0.001 NEAR to $APPROVER (off the list)"
refused_with "B2 an address off the list" "$APPROVER" "$NEAR_001" "not in whitelist"

log "B3 0.051 NEAR to $PARENT (above the per-transaction limit)"
refused_with "B3 above per_transaction" "$PARENT" "$NEAR_051" "per-transaction limit"

if [[ "$MODE" == "--create" ]]; then
  echo
  pass "FIXTURE CREATED: B0–B3 hold before the release. Run '$0 --apply' after it."
  warn "The wallet $PREDEPLOY_WALLET_ADDR and its policy stay until then; the fixture is at $FIXTURE (mode 600)."
else
  echo
  pass "ALL CHECKS PASSED: the policy stored before the release answers B0–B3 as it did"
fi
