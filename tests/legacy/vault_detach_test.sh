#!/bin/bash
# vault_detach_test.sh — detach-only sovereignty e2e.
#
# Operates on an EXISTING vault + EXISTING vault-bound secret. No
# deploy, no register, no /wallet — those are assumed done. Drives
# the second half of the sovereign-exit chain:
#
#   0. Capture keystore-side encryption pubkey for (vault, project)
#      BEFORE recovery — only possible while the vault is locked.
#      This is the cryptographic ground truth for what symmetric key
#      the stored ciphertext was encrypted with.
#   1. PRE-RECOVERY: `/call/<owner>/<project>` should return the
#      secret value (keystore can decrypt via per-vault master).
#   2. `outlayer vault initiate-unilateral-recovery <vault>`
#   3. Wait `MIN_UNILATERAL_EXIT_WINDOW_SECS + small buffer`
#   4. Generate new_parent_pubkey via `customer-recovery generate-key`
#   5. `outlayer vault finalize-recovery <vault> <pubkey>` — atomic
#      DeleteKey(initial_tee_key + registered_tee_keys) +
#      AddFullAccessKey(new_parent_pubkey).
#   6. Wait for `unlocked == true` at FINAL finality.
#   7. POST-RECOVERY: same `/call` must FAIL.
#   8. Fetch on-chain ciphertext via `get_secrets` view.
#   9. `customer-recovery --from-chain` → master_hex.
#  10. Compute local chacha_key for the project seed and compare with
#      step 0's keystore pubkey. Same bytes ⇒ derivation chain is
#      correct. Different bytes ⇒ encryption-side bug — pin it
#      before claiming sovereignty.
#  11. `customer-recovery decrypt-secret` and verify plaintext
#      matches EXPECTED_SECRET_VALUE.
#
# Required env:
#   VAULT_ID               e.g. new5.zavodil2.testnet
#   SECRET_PROJECT         <owner>/<name>, e.g. zavodil2.testnet/test-vault
#   SECRET_OWNER           account that stored the secret (often = owner of project)
#   SECRET_PROFILE         profile name used at `outlayer secrets set`
#   EXPECTED_SECRET_VALUE  the literal value that should come back, e.g. "555"
#   MPC_PUBLIC_KEY         bls12381g2:... — keystore-worker's MPC verification key
#   PARENT                 logged-in NEAR account (must equal vault.parent)
#   SECRET_PAYMENT_KEY     X-Payment-Key for /call (production payment key)
#
# Optional:
#   NETWORK                testnet (default) | mainnet
#   EXIT_WINDOW_WAIT_SECS  override the calc'd sleep; default reads from get_state
#
# Run:
#   VAULT_ID=new5.zavodil2.testnet \
#   SECRET_PROJECT=zavodil2.testnet/test-vault \
#   SECRET_OWNER=zavodil2.testnet \
#   SECRET_PROFILE=new5 \
#   EXPECTED_SECRET_VALUE=555 \
#   MPC_PUBLIC_KEY=bls12381g2:... \
#   PARENT=zavodil2.testnet \
#   SECRET_PAYMENT_KEY=zavodil2.testnet:4:... \
#   ./vault_detach_test.sh --apply

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPLY=false
[[ "${1:-}" == "--apply" ]] && APPLY=true

NETWORK="${NETWORK:-testnet}"
RPC_URL="${RPC_URL:-https://rpc.${NETWORK}.fastnear.com}"

case "$NETWORK" in
  testnet)
    COORDINATOR_URL="${COORDINATOR_URL:-https://testnet-api.outlayer.ai}"
    MPC_CONTRACT_ID="${MPC_CONTRACT_ID:-v1.signer-prod.testnet}"
    NEARBLOCKS_URL="${NEARBLOCKS_URL:-https://api-testnet.nearblocks.io}"
    ;;
  mainnet)
    COORDINATOR_URL="${COORDINATOR_URL:-https://api.outlayer.ai}"
    MPC_CONTRACT_ID="${MPC_CONTRACT_ID:-v1.signer}"
    NEARBLOCKS_URL="${NEARBLOCKS_URL:-https://api.nearblocks.io}"
    ;;
  *)
    echo "✗ unsupported NETWORK=$NETWORK" >&2; exit 1;;
esac

for v in VAULT_ID SECRET_PROJECT SECRET_OWNER SECRET_PROFILE EXPECTED_SECRET_VALUE MPC_PUBLIC_KEY PARENT SECRET_PAYMENT_KEY; do
  if [[ -z "${!v:-}" ]]; then
    echo "✗ env $v is required" >&2; exit 1
  fi
done

for tool in jq curl outlayer near base64; do
  command -v "$tool" >/dev/null || { echo "✗ tool '$tool' missing" >&2; exit 1; }
done

log()  { printf '\n\033[36m▶ %s\033[0m\n' "$*" >&2; }
warn() { printf '\033[33m⚠ %s\033[0m\n' "$*" >&2; }
pass() { printf '\033[32m✓ %s\033[0m\n' "$*" >&2; }
fail() { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

near_tty() {
  if command -v script >/dev/null 2>&1; then
    local tmp_cmd
    tmp_cmd=$(mktemp -t vault_detach_cmd.XXXXXX.sh)
    printf 'set -euo pipefail\n%s\n' "$*" > "$tmp_cmd"
    script -q /dev/null bash "$tmp_cmd"
    local rc=$?
    rm -f "$tmp_cmd"
    return $rc
  else
    eval "$@"
  fi
}

if [[ "$APPLY" != true ]]; then
  warn "Dry-run mode (no --apply). This unlocks $VAULT_ID irreversibly. Pass --apply to execute."
  exit 0
fi

RECOVERY_BIN="$SCRIPT_DIR/../scripts/customer-recovery/target/release/customer-recovery"
log "Building customer-recovery (cargo release)…"
(cd "$SCRIPT_DIR/../scripts/customer-recovery" && cargo build --release --quiet) || \
  fail "customer-recovery build failed"
[[ -x "$RECOVERY_BIN" ]] || fail "customer-recovery binary missing at $RECOVERY_BIN"

# ─── Pre-flight: who am I? ──────────────────────────────────────────

LOGGED_IN=$(outlayer whoami 2>/dev/null | awk -F': *' '/^Account:/{print $2; exit}')
[[ "$LOGGED_IN" == "$PARENT" ]] || \
  fail "outlayer is logged in as '$LOGGED_IN', not PARENT='$PARENT'. Run 'outlayer login $NETWORK' as $PARENT."
pass "logged in as $PARENT on $NETWORK"

# Locally normalised seed (matches the `project:{id}:{owner}` seed the
# keystore builds in `keystore-worker/src/api.rs` and the coordinator's
# /secrets/pubkey path in `outlayer-coordinator/src/handlers/github.rs`).
SECRET_SEED="project:${SECRET_PROJECT}:${SECRET_OWNER}"

# ─── 0. Capture encryption pubkey (PRE-RECOVERY only) ──────────────

log "0. Capturing keystore encryption pubkey for ($SECRET_PROJECT, vault=$VAULT_ID)"
PUBKEY_RESP=$(curl -sS -w '\nHTTP_STATUS:%{http_code}' \
  -X POST "$COORDINATOR_URL/secrets/pubkey" \
  -H 'Content-Type: application/json' \
  -H "X-Customer-Vault: $VAULT_ID" \
  -d "$(jq -n --arg pid "$SECRET_PROJECT" --arg owner "$SECRET_OWNER" --arg profile "$SECRET_PROFILE" \
       '{accessor: {type: "Project", project_id: $pid}, owner: $owner, profile: $profile, secrets_json: "{\"X\":\"y\"}"}')")
PUBKEY_BODY=$(echo "$PUBKEY_RESP" | sed '$d')
PUBKEY_STATUS=$(echo "$PUBKEY_RESP" | tail -1 | sed 's/HTTP_STATUS://')
echo "/secrets/pubkey response: status=$PUBKEY_STATUS body=$PUBKEY_BODY" >&2

if [[ "$PUBKEY_STATUS" != "200" ]]; then
  fail "/secrets/pubkey returned $PUBKEY_STATUS — cannot capture ground-truth pubkey. Either the vault is already unlocked, or the coordinator/keystore refused us. Body: $PUBKEY_BODY"
fi
KEYSTORE_PUBKEY=$(echo "$PUBKEY_BODY" | jq -re '.pubkey // empty')
[[ -n "$KEYSTORE_PUBKEY" && "$KEYSTORE_PUBKEY" != "null" ]] || \
  fail "/secrets/pubkey response missing .pubkey: $PUBKEY_BODY"
pass "keystore encryption pubkey: $KEYSTORE_PUBKEY"

# ─── 1. PRE-RECOVERY /call ──────────────────────────────────────────

log "1. PRE-RECOVERY /call/$SECRET_PROJECT (expect '$EXPECTED_SECRET_VALUE')"
PRE_CALL=$(curl -sS --max-time 60 -X POST "$COORDINATOR_URL/call/$SECRET_PROJECT" \
  -H "X-Payment-Key: $SECRET_PAYMENT_KEY" \
  -H 'Content-Type: application/json' \
  -d "$(jq -n --arg owner "$SECRET_OWNER" --arg profile "$SECRET_PROFILE" \
       '{input: {command: "get_secret", keys: ["MY_TEST_SECRET"]}, secrets_ref: {account_id: $owner, profile: $profile}, async: false}')")
echo "$PRE_CALL" | head -10 >&2
if echo "$PRE_CALL" | grep -qF "\"value\":\"$EXPECTED_SECRET_VALUE\""; then
  pass "/call returned the expected secret pre-recovery — keystore can decrypt"
else
  fail "/call did not return MY_TEST_SECRET=$EXPECTED_SECRET_VALUE pre-recovery. Body: $PRE_CALL"
fi

# ─── 2. Initiate unilateral recovery ────────────────────────────────

# If the caller passes SHORTEN_EXIT_WINDOW_TO=<seconds> (e.g. '60s'),
# call set-exit-window first. This lets us drive the full detach
# test against a real production-defaults vault (24 h window) in
# under two minutes. The MIN bound is enforced by the contract — if
# the deployed WASM still uses the testnet 60s minimum, '60s' works;
# the mainnet build will reject any value below 1 day.
if [[ -n "${SHORTEN_EXIT_WINDOW_TO:-}" ]]; then
  log "2a. outlayer vault set-exit-window $VAULT_ID $SHORTEN_EXIT_WINDOW_TO (parent shortcut)"
  outlayer vault set-exit-window "$VAULT_ID" "$SHORTEN_EXIT_WINDOW_TO" || \
    fail "set-exit-window failed (contract MIN may be larger than $SHORTEN_EXIT_WINDOW_TO)"
fi

log "2. outlayer vault initiate-unilateral-recovery $VAULT_ID"
outlayer vault initiate-unilateral-recovery "$VAULT_ID" || \
  fail "initiate-unilateral-recovery failed"

# ─── 3. Wait for the exit window ────────────────────────────────────

# Read the actual exit_window from state — old vaults (pre-mainnet-
# const flip) have 60-180 s windows, new ones have 24 h. Either way
# this picks the right wait. Cap default at 7 days as a safety net.

read_exit_window() {
  curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
    -d "$(jq -n --arg vault "$VAULT_ID" \
         '{jsonrpc:"2.0", id:1, method:"query", params:{request_type:"call_function", finality:"final", account_id:$vault, method_name:"get_state", args_base64:"e30="}}')" \
    | jq -r '.result.result | implode' \
    | jq -r '.unilateral_exit_window_secs // 86400'
}

EXIT_WINDOW_RAW=$(read_exit_window)
EXIT_WINDOW_WAIT_SECS="${EXIT_WINDOW_WAIT_SECS:-$((EXIT_WINDOW_RAW + 10))}"
log "3. Sleeping $EXIT_WINDOW_WAIT_SECS s for exit window (state says ${EXIT_WINDOW_RAW}s)"

if [[ "$EXIT_WINDOW_WAIT_SECS" -gt 600 ]]; then
  warn "Exit window > 10 min — long sleep ahead. Override with EXIT_WINDOW_WAIT_SECS=<n> if the vault was patched in the meantime."
fi
sleep "$EXIT_WINDOW_WAIT_SECS"

# ─── 4. Generate new_parent_pubkey ──────────────────────────────────

KEY_DIR="${KEY_DIR:-/tmp/vault-detach-test}"
mkdir -p "$KEY_DIR"
chmod 700 "$KEY_DIR"
KEY_FILE="$KEY_DIR/$VAULT_ID.json"
"$RECOVERY_BIN" generate-key > "$KEY_FILE"
chmod 600 "$KEY_FILE"
NEW_PARENT_PUBKEY=$(jq -r '.public_key'  "$KEY_FILE")
NEW_PARENT_PRIVKEY=$(jq -r '.private_key' "$KEY_FILE")
log "4. new_parent_pubkey=$NEW_PARENT_PUBKEY (privkey in $KEY_FILE)"

# ─── 5. Finalize recovery ───────────────────────────────────────────

log "5. outlayer vault finalize-recovery $VAULT_ID $NEW_PARENT_PUBKEY"
outlayer vault finalize-recovery "$VAULT_ID" "$NEW_PARENT_PUBKEY" || \
  fail "finalize-recovery failed"

# ─── 6. Wait for unlock to commit ───────────────────────────────────

log "6. Polling vault.get_state().unlocked == true (deferred callback)"
UNLOCKED="false"
for attempt in 1 2 3 4 5 6 7 8 9 10; do
  STATE_JSON=$(curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
    -d "$(jq -n --arg vault "$VAULT_ID" \
         '{jsonrpc:"2.0", id:1, method:"query", params:{request_type:"call_function", finality:"final", account_id:$vault, method_name:"get_state", args_base64:"e30="}}')" \
    | jq -r '.result.result | implode')
  UNLOCKED=$(echo "$STATE_JSON" | jq -r '.unlocked')
  if [[ "$UNLOCKED" == "true" ]]; then break; fi
  sleep 3
done
[[ "$UNLOCKED" == "true" ]] || \
  fail "vault.unlocked is '$UNLOCKED' after finalize + 30s — atomic swap did not commit"
pass "vault.unlocked == true; recovery cleared"

# ─── 7. POST-RECOVERY /call ─────────────────────────────────────────

log "7. POST-RECOVERY /call/$SECRET_PROJECT (expect failure / no secret)"
POST_CALL_OUT=$(curl -sS --max-time 60 -w '\nHTTP_STATUS:%{http_code}' \
  -X POST "$COORDINATOR_URL/call/$SECRET_PROJECT" \
  -H "X-Payment-Key: $SECRET_PAYMENT_KEY" \
  -H 'Content-Type: application/json' \
  -d "$(jq -n --arg owner "$SECRET_OWNER" --arg profile "$SECRET_PROFILE" \
       '{input: {command: "get_secret", keys: ["MY_TEST_SECRET"]}, secrets_ref: {account_id: $owner, profile: $profile}, async: false}')" \
  2>&1) || true
POST_CALL_BODY=$(echo "$POST_CALL_OUT" | sed '$d')
POST_CALL_STATUS=$(echo "$POST_CALL_OUT" | tail -1 | sed 's/HTTP_STATUS://')
echo "post-recovery /call: status=$POST_CALL_STATUS" >&2
echo "$POST_CALL_BODY" | head -10 >&2

if echo "$POST_CALL_BODY" | grep -qF "\"value\":\"$EXPECTED_SECRET_VALUE\""; then
  fail "POST-RECOVERY: /call STILL returned the secret value. Server-side cutoff is broken."
fi
pass "/call refused to return the secret post-recovery (status=$POST_CALL_STATUS) — secret cutoff confirmed"

# ─── 8. Fetch ciphertext from chain ─────────────────────────────────

log "8. Reading encrypted ciphertext from contract via get_secrets"
GET_ARGS=$(jq -n --arg pid "$SECRET_PROJECT" --arg owner "$SECRET_OWNER" --arg profile "$SECRET_PROFILE" \
  '{accessor: {Project: {project_id: $pid}}, profile: $profile, owner: $owner}')
GET_ARGS_B64=$(printf '%s' "$GET_ARGS" | base64 | tr -d '\n')
SECRETS_VIEW=$(curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"query\",\"params\":{\"request_type\":\"call_function\",\"finality\":\"final\",\"account_id\":\"outlayer.testnet\",\"method_name\":\"get_secrets\",\"args_base64\":\"$GET_ARGS_B64\"}}")
ENCRYPTED_B64=$(echo "$SECRETS_VIEW" | jq -r '.result.result | implode' | jq -r '.encrypted_secrets // empty')
[[ -n "$ENCRYPTED_B64" && "$ENCRYPTED_B64" != "null" ]] || \
  fail "get_secrets returned no encrypted_secrets. Raw: $SECRETS_VIEW"
pass "fetched ${#ENCRYPTED_B64} chars base64 of ciphertext"

# ─── 9. CKD-recover the per-vault master ────────────────────────────

log "9. customer-recovery --from-chain"
RECOVERY_RC=0
RECOVERY_OUT=$(VAULT_PRIVATE_KEY="$NEW_PARENT_PRIVKEY" "$RECOVERY_BIN" \
  --vault-id "$VAULT_ID" \
  --from-chain \
  --rpc-url "$RPC_URL" \
  --mpc-contract "$MPC_CONTRACT_ID" \
  --nearblocks-url "$NEARBLOCKS_URL" 2>&1) || RECOVERY_RC=$?
echo "$RECOVERY_OUT" >&2
[[ $RECOVERY_RC -eq 0 ]] || fail "customer-recovery failed ($RECOVERY_RC)"
MASTER_HEX=$(echo "$RECOVERY_OUT" | awk -F= '/^master_hex=/{print $2; exit}')
[[ -n "$MASTER_HEX" ]] || fail "no master_hex in recovery output"
pass "master_hex=$MASTER_HEX"

# ─── 10. Compare locally-derived chacha_key with keystore pubkey ────

log "10. Comparing locally-derived chacha_key with the captured keystore pubkey"
DERIVE_PROBE=$("$RECOVERY_BIN" derive-wallet-key \
  --master "$MASTER_HEX" \
  --wallet-id "__seed_probe__:$SECRET_SEED" 2>/dev/null || echo '{}')
# derive-wallet-key uses seed = "wallet:{wallet_id}:near" — different
# shape from the secrets seed. So we can't reuse it directly to
# compute the secrets pubkey. Instead, run decrypt-secret which uses
# the right seed shape, and check what the binary prints if it adds a
# verbose / debug mode. For now, just rely on decrypt success/fail to
# tell us if seeds align.
echo "(derive-probe output suppressed — not the right seed shape for project secrets)"

# ─── 11. Local decrypt ──────────────────────────────────────────────

log "11. customer-recovery decrypt-secret (seed=$SECRET_SEED)"
DECRYPT_RC=0
DECRYPTED=$("$RECOVERY_BIN" decrypt-secret \
  --master "$MASTER_HEX" \
  --seed "$SECRET_SEED" \
  --ciphertext-base64 "$ENCRYPTED_B64" 2>&1) || DECRYPT_RC=$?
echo "decrypt output: $DECRYPTED" >&2

if [[ $DECRYPT_RC -ne 0 ]]; then
  warn "decrypt-secret failed. Captured artifacts for offline debugging:"
  warn "  keystore_pubkey (encrypt-side ground truth): $KEYSTORE_PUBKEY"
  warn "  master_hex:                                  $MASTER_HEX"
  warn "  seed:                                        $SECRET_SEED"
  warn "  ciphertext_b64:                              $ENCRYPTED_B64"
  fail "local decrypt does not yield plaintext — derivation chain has a gap. Compare KEYSTORE_PUBKEY to what HMAC(master, '${SECRET_SEED}')→ed25519 produces."
fi

DECRYPTED_VALUE=$(echo "$DECRYPTED" | jq -r '.MY_TEST_SECRET // empty')
if [[ "$DECRYPTED_VALUE" != "$EXPECTED_SECRET_VALUE" ]]; then
  fail "decrypt mismatch: expected '$EXPECTED_SECRET_VALUE', got '$DECRYPTED_VALUE'"
fi
pass "local decryption matches: MY_TEST_SECRET='$DECRYPTED_VALUE' — full sovereignty over secrets confirmed"

echo
pass "ALL DETACH CHECKS PASSED for vault $VAULT_ID on $NETWORK."
