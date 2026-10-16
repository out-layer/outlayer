#!/bin/bash
# The indexer-triggered policy sync, live: a policy stored on chain reaches the
# coordinator through the TEE worker, which reads the chain event and calls
# /internal/wallet-policy-sync with its TEE session. The route answers only a
# TEE worker, so this suite never calls it; it stores the policy and judges what
# the worker's call left behind, for two wallet creation flows:
#
#   A. Bearer near: + vault_id (the stateless flow, whose vault the coordinator
#      learns from encrypt-policy)
#   B. POST /register {vault_id} (the wk_ flow)
#
# For each: the coordinator's copy of the policy (wallet_accounts.policy_json)
# appears with the stored rules, and the coordinator log shows
# "Policy sync complete: wallet=<id>" and no "Lazy-synced policy" for it —
# the copy came from the worker, not from a lazy decrypt on first use.
#
# Required env:
#   PARENT              NEAR account that owns the vault (its key in the legacy keychain;
#                       `outlayer` logged in as it)
#   APPROVER            the policy's approver (default outlayer-bob.testnet)
#   PSQL_CMD            the coordinator's testnet DB, one statement
#   COORD_SSH           the coordinator host, for its log (from .env.nodes)
#   COORDINATOR_URL     default https://testnet-api.outlayer.ai
#
# Run:
#   PARENT=outlayer-alice.testnet PSQL_CMD=… ./tests/internal_policy_sync_e2e.sh --apply

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPLY=false
[[ "${1:-}" == "--apply" ]] && APPLY=true

NETWORK="${NETWORK:-testnet}"
PARENT="${PARENT:-}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/rpc.sh"   # keyed RPC_URL, or a warning
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/near_sign.sh"   # near_why
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ -f "$REPO_ROOT/.env.nodes" ]] && { set -a; source "$REPO_ROOT/.env.nodes"; set +a; }
CONTRACT_ID="${CONTRACT_ID:-outlayer.testnet}"
COORDINATOR_URL="${COORDINATOR_URL:-https://testnet-api.outlayer.ai}"
APPROVER="${APPROVER:-outlayer-bob.testnet}"

[[ -n "$PARENT" ]] || { echo "USAGE: PARENT=... PSQL_CMD=... $0 --apply" >&2; exit 1; }
[[ -n "${PSQL_CMD:-}" ]] || { echo "✗ PSQL_CMD required: the coordinator's copy of the policy is what is judged" >&2; exit 1; }
[[ -n "${COORD_SSH:-}" ]] || { echo "✗ COORD_SSH required (.env.nodes): the coordinator log tells the worker's sync from a lazy one" >&2; exit 1; }
RUN_START=$(date +%s)

CREDS_FILE="${CREDS_FILE:-$HOME/.near-credentials/$NETWORK/$PARENT.json}"
APPROVER_CREDS="${APPROVER_CREDS:-$HOME/.near-credentials/$NETWORK/$APPROVER.json}"
[[ -f "$CREDS_FILE" ]] || { echo "✗ creds missing: $CREDS_FILE" >&2; exit 1; }

for tool in jq curl outlayer near python3; do
  command -v "$tool" >/dev/null || { echo "✗ missing $tool" >&2; exit 1; }
done

log()  { printf '\n\033[36m▶ %s\033[0m\n' "$*" >&2; }
warn() { printf '\033[33m⚠ %s\033[0m\n' "$*" >&2; }
pass() { printf '\033[32m✓ %s\033[0m\n' "$*" >&2; }
fail() { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

near_tty() {
  # `-t 1` as well as the binary: without a terminal `script` dies with
    # `tcgetattr/ioctl: Operation not supported on socket` and takes the step
    # with it — which surfaces as whatever that step was called, not as a
    # missing terminal. Guarded this way in the other copies of this helper.
    if command -v script >/dev/null 2>&1 && [ -t 1 ]; then
    local tmp; tmp=$(mktemp -t ipsync_cmd.XXXXXX.sh)
    printf 'set -euo pipefail\n%s\n' "$*" > "$tmp"
    script -q /dev/null bash "$tmp"; local rc=$?
    rm -f "$tmp"; return $rc
  else
    eval "$@"
  fi
}

if [[ "$APPLY" != true ]]; then
  warn "Dry-run. Pass --apply to deploy + exercise the internal sync path."
  exit 0
fi

RECOVERY_BIN="$SCRIPT_DIR/../scripts/customer-recovery/target/release/customer-recovery"
log "Building customer-recovery"
(cd "$SCRIPT_DIR/../scripts/customer-recovery" && cargo build --release --quiet) || \
  fail "customer-recovery build failed"

# Without this, `outlayer` follows ~/.outlayer/default-network — mainnet on this
# machine — and the check below compares against the wrong network's account.
export OUTLAYER_NETWORK="$NETWORK"
WHOAMI=$(outlayer whoami 2>/dev/null | awk -F': *' '/^Account:/{print $2; exit}')
if [[ "$WHOAMI" == "$PARENT" ]]; then
  pass "logged in as $PARENT on $NETWORK"
else
  fail "outlayer logged in as '$WHOAMI', not '$PARENT'"
fi

PARENT_PRIVKEY=$(jq -r '.private_key' "$CREDS_FILE")
APPROVER_PUBKEY=$(jq -r '.public_key' "$APPROVER_CREDS" 2>/dev/null || echo "")

# ─── 1. Deploy one vault for both scenarios ───────────────────────

VAULT_NAME="ipsync-$(date +%s)"
VAULT_ID="$VAULT_NAME.$PARENT"
log "1. Deploy vault $VAULT_ID"
INIT_RC=0
INIT_OUT=$(outlayer vault init --name "$VAULT_NAME" --exit-window 60s 2>&1) || INIT_RC=$?
if [[ $INIT_RC -ne 0 ]] && echo "$INIT_OUT" | grep -q "outlayer vault resume"; then
  for attempt in 1 2 3 4 5; do
    sleep 6
    if outlayer vault resume "$VAULT_ID" >&2; then INIT_RC=0; break; fi
  done
fi
# The CLI's own words, not just the exit code: this step deploys a sub-account
# and can fail for reasons the operator can act on — a name already taken, a
# balance too small, a network pointed elsewhere — and none of them survive an
# exit status.
if [[ $INIT_RC -eq 0 ]]; then
  pass "vault $VAULT_ID deployed + verified"
else
  fail "vault init failed (rc=$INIT_RC): $(near_why "$INIT_OUT")"
fi

# ─── Helper: end-to-end "encrypt → sign → store policy" for one wallet ────
#
# Inputs:
#   $1 — bearer arg ("near:<token>" or "<wk_apikey>")
#   $2 — wallet_pubkey ("ed25519:<hex>" — for on-chain store_wallet_policy)
#   $3 — wallet_id (coord uuid, for body)
# Output (echoed): ENCRYPTED_BASE64
prepare_and_store_policy() {
  local bearer=$1 wallet_pub=$2 wallet_id=$3
  local body
  body=$(jq -nc \
    --arg wid "$wallet_id" \
    --arg approver "$APPROVER" \
    --arg approver_pub "$APPROVER_PUBKEY" \
    '{
      wallet_id: $wid,
      rules: { transaction_types: ["transfer"] },
      approval: { threshold: { required: 1 },
                  approvers: [ { id: $approver, pubkey: $approver_pub } ] },
      authorized_key_hashes: ["0000000000000000000000000000000000000000000000000000000000000001"]
    }')
  local enc
  enc=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/encrypt-policy" \
    -H "Authorization: Bearer $bearer" \
    -H 'Content-Type: application/json' \
    -d "$body")
  local enc_b64
  enc_b64=$(echo "$enc" | jq -r '.encrypted_base64 // empty')
  [[ -n "$enc_b64" && "$enc_b64" != "null" ]] || { echo "encrypt-policy FAIL: $enc" >&2; return 1; }

  local sig_resp
  sig_resp=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/sign-policy" \
    -H "Authorization: Bearer $bearer" \
    -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg ed "$enc_b64" --arg c "$PARENT" '{encrypted_data: $ed, caller: $c}')")
  local sig_hex
  sig_hex=$(echo "$sig_resp" | jq -r '.signature_hex // empty')
  [[ -n "$sig_hex" && "$sig_hex" != "null" ]] || { echo "sign-policy FAIL: $sig_resp" >&2; return 1; }

  local store_args
  store_args=$(jq -nc --arg pk "$wallet_pub" --arg ed "$enc_b64" --arg sg "$sig_hex" \
    '{wallet_pubkey: $pk, encrypted_data: $ed, wallet_signature: $sg}')
  near_tty "near contract call-function as-transaction $CONTRACT_ID store_wallet_policy \\
    json-args '$store_args' \\
    prepaid-gas '100.0 Tgas' attached-deposit '0.1 NEAR' \\
    sign-as $PARENT network-config $NETWORK sign-with-keychain send" >&2 \
    || return 1

  echo "$enc_b64"
}

# ─── Helper: the worker's sync, judged by what it left behind ─────────────
#
# Waits up to ~3 min for the coordinator's copy of the stored policy, then reads
# the log of this run: the worker's call writes "Policy sync complete" and no
# lazy decrypt may have stood in for it. Echoes "ok" or the reason it is not.
coord_count() { # coord_count <fixed-string> — this run's coordinator log lines holding it
  local since=$(( $(date +%s) - RUN_START + 120 ))
  ssh -o ConnectTimeout=15 -o BatchMode=yes -o ControlMaster=no -o ControlPath=none "$COORD_SSH" \
    "docker logs offchainvm-coordinator-testnet --since ${since}s 2>&1 | grep -F -- $(printf '%q' "$1") | wc -l" 2>/dev/null | tr -d ' \n'
}
synced_by_worker() { # synced_by_worker <wallet_id>
  local wid=$1 got="" i synced lazy
  for i in $(seq 1 30); do
    got=$($PSQL_CMD "SELECT COALESCE((policy_json->'rules'->'transaction_types')::text, 'NULL') FROM wallet_accounts WHERE wallet_id = '$wid'" | tr -d ' ')
    [[ "$got" == '["transfer"]' ]] && break
    sleep 6
  done
  [[ "$got" == '["transfer"]' ]] || { echo "the coordinator's copy reads '${got:-no row}', expected [\"transfer\"]"; return; }
  synced=$(coord_count "Policy sync complete: wallet=$wid")
  lazy=$(coord_count "Lazy-synced policy for wallet=$wid")
  if [[ "${synced:-0}" -ge 1 && "${lazy:-0}" == 0 ]]; then echo ok
  else echo "log: 'Policy sync complete' ${synced:-?} line(s), 'Lazy-synced' ${lazy:-?}"; fi
}

# ─── 2. Scenario A: Bearer near: + vault (the bug-prone path) ─────

log "2. Scenario A: mint sub-wallet via Bearer near: + vault_id"
SEED_A="ipsync-A-$(date +%s)-$$"
TOKEN_A=$(CUSTOMER_RECOVERY_PRIVATE_KEY="$PARENT_PRIVKEY" "$RECOVERY_BIN" sign-bearer-near \
 --account-id "$PARENT" --seed "$SEED_A" \
  --vault-id "$VAULT_ID")
ADDR_RESP_A=$(curl -sS -G "$COORDINATOR_URL/wallet/v1/address" --data-urlencode "chain=near" \
  -H "Authorization: Bearer near:$TOKEN_A")
SUB_PUB_A=$(echo "$ADDR_RESP_A" | jq -r '.public_key')
WALLET_ID_A=$(echo "$ADDR_RESP_A" | jq -r '.wallet_id')
SUB_ADDR_A=$(echo "$ADDR_RESP_A" | jq -r '.address')
if [[ -n "$SUB_PUB_A" && "$SUB_PUB_A" != "null" ]]; then
  pass "Scenario A sub-wallet: $SUB_ADDR_A (wallet_id=$WALLET_ID_A)"
else
  fail "Scenario A /address failed: $ADDR_RESP_A"
fi

log "2.1 encrypt-policy + sign-policy + store_wallet_policy under Bearer near:"
ENC_A=$(prepare_and_store_policy "near:$TOKEN_A" "$SUB_PUB_A" "$WALLET_ID_A") || \
  fail "Scenario A policy storage failed"
pass "Scenario A policy stored on chain (len=${#ENC_A} base64 chars)"

log "2.2 the worker syncs Scenario A's policy from the chain event"
SYNC_A=$(synced_by_worker "$WALLET_ID_A")
[[ "$SYNC_A" == ok ]] && pass "Scenario A: the worker's sync decrypted and stored the policy (Bearer near: + vault)" \
  || fail "Scenario A: $SYNC_A"

# ─── 3. Scenario B: /register {vault_id} (control, wk_ flow) ───────

log "3. Scenario B: POST /register with vault_id → wk_ wallet bound to vault"
REG_B=$(curl -sS -X POST "$COORDINATOR_URL/register" \
  -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg vid "$VAULT_ID" '{vault_id: $vid}')")
WK_B=$(echo "$REG_B" | jq -r '.api_key')
WALLET_ID_B=$(echo "$REG_B" | jq -r '.wallet_id')
SUB_ADDR_B=$(echo "$REG_B" | jq -r '.near_account_id')
[[ -n "$WK_B" && "$WK_B" != "null" ]] || fail "Scenario B /register failed: $(jq -c 'del(.api_key, .handoff_url)' <<<"$REG_B" 2>/dev/null | head -c 300)"
ADDR_RESP_B=$(curl -sS -G "$COORDINATOR_URL/wallet/v1/address" --data-urlencode "chain=near" \
  -H "Authorization: Bearer $WK_B")
SUB_PUB_B=$(echo "$ADDR_RESP_B" | jq -r '.public_key')
pass "Scenario B sub-wallet: $SUB_ADDR_B (wallet_id=$WALLET_ID_B)"

log "3.1 encrypt-policy + sign-policy + store under wk_ Bearer"
ENC_B=$(prepare_and_store_policy "$WK_B" "$SUB_PUB_B" "$WALLET_ID_B") || \
  fail "Scenario B policy storage failed"
pass "Scenario B policy stored on chain"

log "3.2 the worker syncs Scenario B's policy from the chain event"
SYNC_B=$(synced_by_worker "$WALLET_ID_B")
[[ "$SYNC_B" == ok ]] && pass "Scenario B: the worker's sync decrypted and stored the policy (wk_ + vault)" \
  || fail "Scenario B: $SYNC_B"

echo
pass "BOTH scenarios: the indexer path syncs policies for Bearer near: and wk_ wallets"
warn "Cleanup (optional): $VAULT_ID has 0.1 NEAR locked + on-chain policy storage stake."
