#!/bin/bash
# Sovereignty cutoff — end-to-end demonstration on real testnet.
#
# This is the ONLY test that exercises the full "OutLayer leaves,
# customer keeps wallet access" promise end-to-end. The on-chain
# sandbox/integration suite covers the contract behaviour; this
# script verifies that the keystore-worker actually stops signing
# AFTER `finalize_recovery`, and that the customer can re-derive
# the same wallet's NEAR private key from the per-vault master they
# recovered via MPC CKD.
#
# Flow:
#   1. `outlayer vault init`         — production-flow vault deploy
#                                       (NEP-591 UseGlobalContract,
#                                       TEE FCAK installed by keystore)
#   2. `POST /register {vault_id}`   — mint wallet API key bound to vault
#                                       (captures wallet_id + api_key
#                                       + near_account_id)
#   3. `POST /wallet/v1/sign-message`— PRE-RECOVERY proof that the
#                                       keystore signs for this wallet
#   4. `outlayer vault initiate-unilateral-recovery`
#   5. Wait MIN_UNILATERAL_EXIT_WINDOW_SECS (60s)
#   6. `customer-recovery generate-key` → new_parent_pubkey
#   7. `outlayer vault finalize-recovery <vault> <new_parent_pubkey>`
#      → atomic on-chain key-swap: DeleteKey(TEE_FCAK) +
#        AddFullAccessKey(new_parent_pubkey)
#   8. `POST /wallet/v1/sign-message` — POST-RECOVERY: keystore MUST
#                                       refuse (vault.unlocked == true)
#   9. `customer-recovery --from-chain --signer-private-key $NEW_KEY`
#      → MPC CKD round-trip, prints `master_hex=...`
#  10. `customer-recovery derive-wallet-key --master <hex> --wallet-id`
#      → outputs the wallet's NEAR private key + implicit address
#  11. Sanity: the locally-derived `near_address` MUST equal the
#      `near_account_id` returned in step 2 (proves the customer can
#      reach the same wallet without OutLayer)
#  12. `near tokens <wallet> send-near <PARENT> 0.001 NEAR
#         sign-with-plaintext-private-key <derived-priv-key> send`
#      → REAL testnet tx signed by the recovered key. If it lands,
#        sovereignty is proven.
#
# Required env:
#   PARENT          NEAR account that will own the vault (logged in
#                   via `outlayer login`). Must have >= 5 NEAR for
#                   atomic deploy + funding the wallet.
#   MPC_PUBLIC_KEY  bls12381g2:base58 — same value keystore-worker uses.
#   SECRET_PAYMENT_KEY  a payment key owned by SECRET_PROJECT_OWNER (default
#                   zavodil2.testnet); the suite carries no key of its own.
#                   Ask OutLayer ops or pull from keystore config.
#   NETWORK         testnet (default). mainnet not supported by this
#                   script (different MPC contract / API URL).
#
# Run:
#   MPC_PUBLIC_KEY=bls12381g2:... PARENT=alice.testnet ./sovereignty_e2e.sh --apply

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPLY=false
[[ "${1:-}" == "--apply" ]] && APPLY=true

NETWORK="${NETWORK:-testnet}"
PARENT="${PARENT:-}"
RPC_URL="${RPC_URL:-https://rpc.${NETWORK}.fastnear.com}"
KEYSTORE_DAO_ID="${KEYSTORE_DAO_ID:-dao.outlayer.testnet}"

case "$NETWORK" in
  testnet)
    COORDINATOR_URL="${COORDINATOR_URL:-https://testnet-api.outlayer.ai}"
    MPC_CONTRACT_ID="${MPC_CONTRACT_ID:-v1.signer-prod.testnet}"
    NEARBLOCKS_URL="${NEARBLOCKS_URL:-https://api-testnet.nearblocks.io}"
    ;;
  mainnet)
    echo "✗ mainnet flow not implemented in this script" >&2
    exit 1
    ;;
  *)
    echo "✗ unsupported NETWORK=$NETWORK" >&2
    exit 1
    ;;
esac

if [[ -z "$PARENT" ]]; then
  echo "USAGE:  PARENT=alice.testnet MPC_PUBLIC_KEY=bls12381g2:... $0 --apply" >&2
  echo "Optional env: NETWORK=mainnet|testnet (default testnet)" >&2
  exit 1
fi

if [[ -z "${MPC_PUBLIC_KEY:-}" ]]; then
  echo "✗ MPC_PUBLIC_KEY env var is required (bls12381g2:base58)" >&2
  echo "  Ask OutLayer ops for the testnet value — same key the" >&2
  echo "  keystore-worker uses for its MPC client." >&2
  exit 1
fi

# Asked for HERE rather than at step 3c, which is where it is used: by then the
# suite has deployed a vault, minted a wallet and funded it, and there is no
# trap to give any of that back.
if [[ -z "${SECRET_PAYMENT_KEY:-}" ]]; then
  echo "✗ SECRET_PAYMENT_KEY env var is required: a payment key owned by" >&2
  echo "  SECRET_PROJECT_OWNER (default zavodil2.testnet). A key spends real" >&2
  echo "  balance, so this suite carries none of its own." >&2
  exit 1
fi

for tool in jq curl outlayer near; do
  if ! command -v "$tool" >/dev/null; then
    echo "✗ Required tool '$tool' not found in PATH" >&2
    exit 1
  fi
done

log()  { printf '\n\033[36m▶ %s\033[0m\n' "$*" >&2; }
warn() { printf '\033[33m⚠ %s\033[0m\n' "$*" >&2; }
pass() { printf '\033[32m✓ %s\033[0m\n' "$*" >&2; }
fail() { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

# `near contract deploy` / `near tokens send-near` etc. need a TTY
# even with explicit signing args; faking one with `script` keeps
# the prompt path happy in CI.
near_tty() {
  if command -v script >/dev/null 2>&1; then
    local tmp_cmd
    tmp_cmd=$(mktemp -t sovereignty_e2e_cmd.XXXXXX.sh)
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
  warn "Dry-run mode (no --apply). This is a destructive integration test —"
  warn "it deploys a vault, mints a wallet, and submits real testnet txs."
  warn "Pass --apply to execute. Aborting."
  exit 0
fi

# ─── Pre-flight ──────────────────────────────────────────────────────

log "Pre-flight: outlayer whoami should match PARENT=$PARENT"
WHOAMI_ACCOUNT=$(outlayer whoami 2>/dev/null | awk -F': *' '/^Account:/{print $2; exit}')
if [[ "$WHOAMI_ACCOUNT" != "$PARENT" ]]; then
  fail "outlayer is logged in as '$WHOAMI_ACCOUNT', not '$PARENT'. Run 'outlayer login $NETWORK' as $PARENT first."
fi
pass "logged in as $PARENT on $NETWORK"

# Make sure the customer-recovery binary is up to date — it ships
# both the MPC CKD recovery path AND the new derive-wallet-key
# subcommand this script depends on.
RECOVERY_BIN="$SCRIPT_DIR/../scripts/customer-recovery/target/release/customer-recovery"
log "Building customer-recovery (cargo release)…"
(cd "$SCRIPT_DIR/../scripts/customer-recovery" && cargo build --release --quiet) || \
  fail "customer-recovery build failed"
[[ -x "$RECOVERY_BIN" ]] || fail "customer-recovery binary missing at $RECOVERY_BIN"

# ─── 1. Deploy vault via production flow ─────────────────────────────

log "1. Deploying vault via 'outlayer vault init'…"
# Use a timestamped --name so each run gets a fresh vault account
# (production parent accounts only support one well-known vault name
# but this test deliberately makes throwaway vaults). Use a 60s exit
# window so step 5's sleep is short — production vaults run with 24h.
VAULT_NAME="sov-e2e-$(date +%s)"
VAULT_ID="$VAULT_NAME.$PARENT"
log "    vault account = $VAULT_ID  (exit-window=60s)"
INIT_RC=0
INIT_OUT=$(outlayer vault init --name "$VAULT_NAME" --exit-window 60s 2>&1) || INIT_RC=$?
echo "$INIT_OUT" >&2

# The CLI's atomic-deploy lands on chain before the RPC view-call
# that follows (mark_vault_verified) can see the account. We hit
# UNKNOWN_ACCOUNT often enough that the CLI itself prints "Retry
# with: outlayer vault resume <vault>" instead of failing hard.
# Mirror that retry here.
if [[ $INIT_RC -ne 0 ]]; then
  if echo "$INIT_OUT" | grep -q "outlayer vault resume"; then
    log "    deploy landed but verification raced RPC propagation — running 'outlayer vault resume'…"
    for attempt in 1 2 3 4 5; do
      sleep 6
      if outlayer vault resume "$VAULT_ID" >&2; then
        INIT_RC=0
        break
      fi
      warn "    resume attempt $attempt failed; retrying"
    done
  fi
  [[ $INIT_RC -eq 0 ]] || fail "vault init + resume retries exhausted; manual recovery needed"
fi

outlayer vault status "$VAULT_ID" >/dev/null 2>&1 || \
  fail "vault.status failed right after init/resume — deploy may not have committed"
pass "vault deployed + verified at $VAULT_ID"

# ─── 2. Mint wallet API key bound to vault ───────────────────────────

log "2. POST /register with vault_id=$VAULT_ID"
REGISTER_BODY="{\"vault_id\":\"$VAULT_ID\"}"
REGISTER_RESP=$(curl -s -X POST "$COORDINATOR_URL/register" \
  -H 'Content-Type: application/json' \
  -d "$REGISTER_BODY")
echo "$REGISTER_RESP" | jq . >&2

API_KEY=$(echo "$REGISTER_RESP" | jq -r '.api_key // empty')
WALLET_ID=$(echo "$REGISTER_RESP" | jq -r '.wallet_id // empty')
NEAR_ACCOUNT_ID=$(echo "$REGISTER_RESP" | jq -r '.near_account_id // empty')

[[ -n "$API_KEY" && "$API_KEY" != "null" ]] || \
  fail "/register did not return api_key — response was: $REGISTER_RESP"
[[ -n "$WALLET_ID" && "$WALLET_ID" != "null" ]] || \
  fail "/register did not return wallet_id"
[[ -n "$NEAR_ACCOUNT_ID" && "$NEAR_ACCOUNT_ID" != "null" ]] || \
  fail "/register did not return near_account_id (keystore lazy-load may have failed — check MPC CKD context)"

pass "minted api_key=${API_KEY:0:9}… wallet_id=$WALLET_ID address=$NEAR_ACCOUNT_ID"

# ─── 3. PRE-RECOVERY: prove the keystore signs for this wallet ──────

log "3. PRE-RECOVERY signing — POST /wallet/v1/sign-message"
SIGN_RESP=$(curl -s -X POST "$COORDINATOR_URL/wallet/v1/sign-message" \
  -H "Authorization: Bearer $API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"message":"sovereignty-e2e-preflight","recipient":"verifier.testnet","nonce_base64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}')
echo "$SIGN_RESP" | jq . >&2

PRE_SIG=$(echo "$SIGN_RESP" | jq -r '.signature // empty')
[[ -n "$PRE_SIG" && "$PRE_SIG" != "null" ]] || \
  fail "/wallet/v1/sign-message returned no signature pre-recovery — vault binding is broken"
pass "keystore signed pre-recovery (signature length=${#PRE_SIG})"

# ─── 3a. Fund the wallet so it can broadcast txs ────────────────────
#
# The implicit account just minted by step 2 has 0 NEAR. Fund it once,
# up-front, with enough to cover (a) the keystore-signed transfer in
# step 3b and (b) the locally-signed sovereign transfer at the end.
# 0.1 NEAR is comfortably above the storage-stake floor + two fees.

log "3a. Funding the wallet ($NEAR_ACCOUNT_ID) with 0.1 NEAR from $PARENT"
near_tty "near tokens $PARENT send-near $NEAR_ACCOUNT_ID '0.1 NEAR' \\
  network-config $NETWORK sign-with-keychain send" || \
  fail "funding the wallet from $PARENT failed"

# `send-near` returns once the tx lands in a block but the RPC node
# the keystore queries can still be a few blocks behind for the next
# few seconds, so the very first /wallet/v1/transfer call below
# often hits UNKNOWN_ACCOUNT. Poll until the implicit account is
# observable at FINAL finality before we hand the wallet off to the
# keystore.
log "    waiting for wallet account to appear at final finality…"
for attempt in 1 2 3 4 5 6 7 8 9 10; do
  ACCT_PROBE=$(curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"query\",\"params\":{\"request_type\":\"view_account\",\"finality\":\"final\",\"account_id\":\"$NEAR_ACCOUNT_ID\"}}")
  if echo "$ACCT_PROBE" | jq -e '.result.amount' >/dev/null 2>&1; then
    pass "wallet funded and visible on chain"
    break
  fi
  sleep 2
done

# ─── 3b. PRE-RECOVERY transfer signed by the KEYSTORE ───────────────
#
# Drives the production wallet API: POST /wallet/v1/transfer asks the
# coordinator → keystore-worker to derive the wallet's NEAR keypair
# from the per-vault master and sign+broadcast a transfer back to
# PARENT. This is the "before" half of the BEFORE/AFTER pair —
# whoever holds the API key can move funds via the keystore.

log "3b. PRE-RECOVERY transfer — keystore-signed via POST /wallet/v1/transfer"
PRE_TRANSFER_RESP=$(curl -sS -w '\nHTTP_STATUS:%{http_code}' --max-time 60 \
  -X POST "$COORDINATOR_URL/wallet/v1/transfer" \
  -H "Authorization: Bearer $API_KEY" \
  -H 'Content-Type: application/json' \
  -d "{\"chain\":\"near\",\"receiver_id\":\"$PARENT\",\"amount\":\"10000000000000000000000\"}")
PRE_TRANSFER_BODY=$(echo "$PRE_TRANSFER_RESP" | sed '$d')
PRE_TRANSFER_STATUS=$(echo "$PRE_TRANSFER_RESP" | tail -1 | sed 's/HTTP_STATUS://')
echo "transfer response (status=$PRE_TRANSFER_STATUS): $PRE_TRANSFER_BODY" >&2

# Parse with `jq -e` (sets exit code on failure) but route through
# `|| true` so a non-JSON response doesn't kill the script before we
# can print a useful error.
PRE_TX_HASH=$(echo "$PRE_TRANSFER_BODY" | jq -re '.tx_hash // .transaction_hash // empty' 2>/dev/null || echo "")
PRE_STATUS=$(echo "$PRE_TRANSFER_BODY" | jq -re '.status // .request_status // empty' 2>/dev/null || echo "")
if [[ -z "$PRE_TX_HASH" || "$PRE_TX_HASH" == "null" ]]; then
  fail "/wallet/v1/transfer returned no tx hash pre-recovery (http=$PRE_TRANSFER_STATUS). Response: $PRE_TRANSFER_BODY"
fi
pass "keystore signed + broadcast pre-recovery transfer tx=$PRE_TX_HASH (status=$PRE_STATUS, http=$PRE_TRANSFER_STATUS)"

# ─── 3c. Store a project-scoped secret bound to our test vault ──────
#
# `outlayer secrets set --vault-id <vault>` encrypts via the per-vault
# master's seed-derived pubkey. The contract stores the encrypted
# bytes under (accessor=Project{owner/name}, profile, owner). At call
# time the keystore derives the matching ed25519 keypair from the
# per-vault master to decrypt. Without the master (i.e. when the
# vault is `unlocked == true`), the keystore must refuse.
#
# We reuse the user's pre-deployed `zavodil2.testnet/test-vault`
# project — same WASM as the curl example. We pick a unique
# `profile` so we never collide with the project's existing secrets.

SECRET_PROJECT_OWNER="zavodil2.testnet"
SECRET_PROJECT_NAME="test-vault"
SECRET_PROJECT="${SECRET_PROJECT_OWNER}/${SECRET_PROJECT_NAME}"
SECRET_PROFILE="sov-e2e-$(date +%s)"
SECRET_VALUE="sovereign-secret-value-$(uuidgen 2>/dev/null || date +%s%N)"
# Required at the preflight above, so by here it is set.

log "3c. Storing secret MY_TEST_SECRET (profile=$SECRET_PROFILE, vault=$VAULT_ID) under project $SECRET_PROJECT"
outlayer secrets set \
  --project "$SECRET_PROJECT" \
  --profile "$SECRET_PROFILE" \
  --vault-id "$VAULT_ID" \
  "{\"MY_TEST_SECRET\":\"$SECRET_VALUE\"}" >&2 || \
  fail "outlayer secrets set failed"
pass "secret stored (value=${SECRET_VALUE:0:32}…)"

# ─── 3d. PRE-RECOVERY: project HTTPS call should read the secret ─────
#
# Best-effort: the test-vault project's worker is shared
# infrastructure; if it's down or starved we can't fix it from this
# script. The CORE cutoff claim is proven by steps 3 vs 8 (wallet
# sign-message — same per-vault-master code path). This step is a
# layered "the integration also works end-to-end through the WASI
# runtime" assertion that downgrades to a WARN when the project
# can't be reached.

PROJECT_REACHABLE=true
log "3d. PRE-RECOVERY project call — POST /call/$SECRET_PROJECT (best-effort)"
PRE_CALL_RESP=$(curl -sS --max-time 90 -X POST "$COORDINATOR_URL/call/$SECRET_PROJECT" \
  -H "X-Payment-Key: $SECRET_PAYMENT_KEY" \
  -H 'Content-Type: application/json' \
  -d "{\"input\":{\"command\":\"get_secret\",\"keys\":[\"MY_TEST_SECRET\"]},\"secrets_ref\":{\"account_id\":\"$SECRET_PROJECT_OWNER\",\"profile\":\"$SECRET_PROFILE\"},\"async\":false}" 2>&1) || PROJECT_REACHABLE=false

if [[ "$PROJECT_REACHABLE" == "false" ]]; then
  warn "PRE-RECOVERY /call timed out or errored — project worker likely down. Skipping the project-side cutoff check; the keystore-level cutoff is still covered by step 3 vs step 8."
else
  echo "$PRE_CALL_RESP" | head -40 >&2
  if echo "$PRE_CALL_RESP" | grep -qF "$SECRET_VALUE"; then
    pass "project call returned the live secret pre-recovery — keystore decrypts via per-vault master"
  else
    warn "PRE-RECOVERY: project call did not contain the secret value. This may indicate the project's WASM doesn't echo the secret, or the worker is mis-configured. Continuing without the project-side check."
    PROJECT_REACHABLE=false
  fi
fi

# ─── 4. Initiate unilateral recovery ─────────────────────────────────

log "4. Initiating unilateral recovery on $VAULT_ID"
outlayer vault initiate-unilateral-recovery "$VAULT_ID" || \
  fail "initiate-unilateral-recovery failed"
pass "recovery initiated; exit window timer is running"

# ─── 5. Wait for exit window ─────────────────────────────────────────

WAIT_SECS=70
log "5. Waiting $WAIT_SECS s for unilateral exit window to elapse"
sleep "$WAIT_SECS"

# ─── 6. Generate new_parent_pubkey ───────────────────────────────────

log "6. Generating new parent keypair (this is the sovereign exit key)"
KEY_DIR="${KEY_DIR:-/tmp/sovereignty-e2e}"
mkdir -p "$KEY_DIR"
chmod 700 "$KEY_DIR"
KEY_FILE="$KEY_DIR/$VAULT_ID.json"
"$RECOVERY_BIN" generate-key > "$KEY_FILE"
chmod 600 "$KEY_FILE"
NEW_PARENT_PUBKEY=$(jq -r '.public_key'  "$KEY_FILE")
NEW_PARENT_PRIVKEY=$(jq -r '.private_key' "$KEY_FILE")
pass "new_parent_pubkey=$NEW_PARENT_PUBKEY (private key in $KEY_FILE)"

# ─── 7. Finalize recovery (atomic key-swap) ──────────────────────────

log "7. Finalizing recovery — parent calls finalize_recovery(new_parent_pubkey)"
# `outlayer vault finalize-recovery` issues the parent-only on-chain
# call. The contract atomically: DeleteKey(initial_tee_key +
# registered_tee_keys) + AddFullAccessKey(new_parent_pubkey).
outlayer vault finalize-recovery "$VAULT_ID" "$NEW_PARENT_PUBKEY" || \
  fail "finalize-recovery failed"

# Verify on-chain state flipped to unlocked. State mutation is
# DEFERRED to the post-swap callback (`callback_after_swap`), so the
# `unlocked = true` flip may not be visible at FINAL finality the
# instant the outer tx returns. Poll for ~30s before giving up.
UNLOCKED="false"
for attempt in 1 2 3 4 5 6 7 8 9 10; do
  STATE_JSON=$(curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"query\",\"params\":{\"request_type\":\"call_function\",\"finality\":\"final\",\"account_id\":\"$VAULT_ID\",\"method_name\":\"get_state\",\"args_base64\":\"e30=\"}}" \
    | jq -r '.result.result | implode')
  UNLOCKED=$(echo "$STATE_JSON" | jq -r '.unlocked')
  if [[ "$UNLOCKED" == "true" ]]; then
    break
  fi
  sleep 3
done
[[ "$UNLOCKED" == "true" ]] || \
  fail "vault.get_state().unlocked is '$UNLOCKED' after finalize + 30s — atomic swap did not commit"
pass "vault.unlocked == true; recovery cleared"

# ─── 8. POST-RECOVERY: keystore must refuse ──────────────────────────

log "8. POST-RECOVERY signing attempt — should FAIL (vault unlocked)"
POST_RESP=$(curl -s -w '\nHTTP_STATUS:%{http_code}' -X POST "$COORDINATOR_URL/wallet/v1/sign-message" \
  -H "Authorization: Bearer $API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"message":"sovereignty-e2e-postflight","recipient":"verifier.testnet","nonce_base64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}')
POST_BODY=$(echo "$POST_RESP" | sed '$d')
POST_STATUS=$(echo "$POST_RESP" | tail -1 | sed 's/HTTP_STATUS://')
echo "post-recovery sign response: status=$POST_STATUS body=$POST_BODY" >&2

# Either:
#   * HTTP 4xx/5xx (keystore rejected via the cold-path verify), OR
#   * HTTP 200 but no `.signature` field (some endpoints wrap errors
#     in 200 — defence in depth, check both shapes)
POST_SIG=$(echo "$POST_BODY" | jq -r '.signature // empty' 2>/dev/null || true)
if [[ "$POST_STATUS" -ge 400 ]] || [[ -z "$POST_SIG" || "$POST_SIG" == "null" ]]; then
  pass "keystore refused signing post-recovery (status=$POST_STATUS) — sovereignty cutoff confirmed"
else
  fail "POST-RECOVERY: keystore STILL signed (status=$POST_STATUS sig=$POST_SIG). Cutoff path is broken."
fi

# ─── 8a. POST-RECOVERY: project call must fail too ────────────────────
#
# Same flow as 3d, but now the keystore must refuse to decrypt the
# secret because the vault is `unlocked == true`. A failure here can
# manifest as: HTTP 4xx/5xx, structured error in the body, or the
# response missing the secret value. We accept all three.

if [[ "$PROJECT_REACHABLE" == "true" ]]; then
  log "8a. POST-RECOVERY project call — POST /call/$SECRET_PROJECT (expect failure)"
  POST_CALL_OUT=$(curl -sS --max-time 90 -w '\nHTTP_STATUS:%{http_code}' -X POST "$COORDINATOR_URL/call/$SECRET_PROJECT" \
    -H "X-Payment-Key: $SECRET_PAYMENT_KEY" \
    -H 'Content-Type: application/json' \
    -d "{\"input\":{\"command\":\"get_secret\",\"keys\":[\"MY_TEST_SECRET\"]},\"secrets_ref\":{\"account_id\":\"$SECRET_PROJECT_OWNER\",\"profile\":\"$SECRET_PROFILE\"},\"async\":false}" 2>&1) || true
  POST_CALL_BODY=$(echo "$POST_CALL_OUT" | sed '$d')
  POST_CALL_STATUS=$(echo "$POST_CALL_OUT" | tail -1 | sed 's/HTTP_STATUS://')
  echo "post-recovery /call: status=$POST_CALL_STATUS" >&2
  echo "$POST_CALL_BODY" | head -40 >&2

  if echo "$POST_CALL_BODY" | grep -qF "$SECRET_VALUE"; then
    fail "POST-RECOVERY: project call STILL returned the secret value. Keystore did not enforce the cutoff for vault-bound secrets."
  fi
  pass "project call refused to return the secret post-recovery (status=$POST_CALL_STATUS) — secret cutoff confirmed"
else
  log "8a. SKIPPED (project unreachable pre-recovery — see step 3d warning)"
fi

# ─── 9. CKD-recover per-vault master locally ─────────────────────────

log "9. Recovering per-vault master locally via MPC CKD"
# Capture stdout+stderr and dump it on failure too — earlier runs
# swallowed the binary's panic output because `set -e` killed the
# script before the success echo could run.
RECOVERY_RC=0
RECOVERY_OUT=$(VAULT_PRIVATE_KEY="$NEW_PARENT_PRIVKEY" "$RECOVERY_BIN" \
  --vault-id "$VAULT_ID" \
  --from-chain \
  --rpc-url "$RPC_URL" \
  --mpc-contract "$MPC_CONTRACT_ID" \
  --nearblocks-url "$NEARBLOCKS_URL" 2>&1) || RECOVERY_RC=$?
echo "$RECOVERY_OUT" >&2
[[ $RECOVERY_RC -eq 0 ]] || fail "customer-recovery exited $RECOVERY_RC (output above)"
MASTER_HEX=$(echo "$RECOVERY_OUT" | awk -F= '/^master_hex=/{print $2; exit}')
[[ -n "$MASTER_HEX" ]] || fail "MPC CKD did not return a master_hex"
pass "per-vault master recovered locally (${#MASTER_HEX} hex chars; expect 64)"

# ─── 10. Derive the wallet's NEAR keypair locally ────────────────────

log "10. Re-deriving the wallet keypair from master + wallet_id"
DERIVED_JSON=$("$RECOVERY_BIN" derive-wallet-key \
  --master "$MASTER_HEX" \
  --wallet-id "$WALLET_ID")
echo "$DERIVED_JSON" | jq . >&2
DERIVED_ADDR=$(echo "$DERIVED_JSON" | jq -r '.near_address')
DERIVED_PRIVKEY=$(echo "$DERIVED_JSON" | jq -r '.private_key')
DERIVED_PUBKEY=$(echo "$DERIVED_JSON" | jq -r '.public_key')

# ─── 11. Sanity: derived address must match the wallet ───────────────

log "11. Verifying derived address matches the keystore's address"
if [[ "$DERIVED_ADDR" != "$NEAR_ACCOUNT_ID" ]]; then
  fail "DERIVATION MISMATCH: local=$DERIVED_ADDR vs keystore=$NEAR_ACCOUNT_ID. \
The HMAC seed shape diverged between keystore-worker and customer-recovery."
fi
pass "local derivation matches keystore: $DERIVED_ADDR"

# ─── 12. POST-RECOVERY transfer signed by the LOCAL key ──────────────
#
# Mirror image of step 3b: same wallet sends back to PARENT, but the
# signer is the ed25519 private key we derived locally from the
# recovered per-vault master + wallet_id. The keystore-worker is
# uninvolved. If this tx lands, the customer has demonstrated
# end-to-end sovereign control of the wallet.
#
# The wallet still has ~0.09 NEAR left after step 3b — no funding
# round-trip needed here.

log "12. SOVEREIGN TRANSFER — locally-derived key signs send-near"
near_tty "near tokens $NEAR_ACCOUNT_ID send-near $PARENT '0.01 NEAR' \\
  network-config $NETWORK \\
  sign-with-plaintext-private-key '$DERIVED_PRIVKEY' send" || \
  fail "sovereign send-near with the locally-derived key failed — \
this is the final proof point; if it fails, the wallet is NOT recoverable."
pass "sovereign transfer succeeded — wallet $NEAR_ACCOUNT_ID is now controlled \
by the customer-held private key, independent of OutLayer."

# ─── 13. Fetch the encrypted secret from chain ───────────────────────
#
# The contract exposes `get_secrets(accessor, profile, owner)` as a
# view method. We pull the raw encrypted bytes (base64 string) so we
# can decrypt them locally in the next step without going through
# the keystore at all.

log "13. Reading encrypted secret from chain via get_secrets view-call"
# accessor enum shape: { "Project": { "project_id": "<owner>/<name>" } }
# args base64-encoded for the RPC.
GET_SECRETS_ARGS=$(printf '{"accessor":{"Project":{"project_id":"%s"}},"profile":"%s","owner":"%s"}' \
  "$SECRET_PROJECT" "$SECRET_PROFILE" "$SECRET_PROJECT_OWNER")
GET_SECRETS_ARGS_B64=$(printf '%s' "$GET_SECRETS_ARGS" | base64 | tr -d '\n')

SECRETS_VIEW=$(curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"query\",\"params\":{\"request_type\":\"call_function\",\"finality\":\"final\",\"account_id\":\"outlayer.testnet\",\"method_name\":\"get_secrets\",\"args_base64\":\"$GET_SECRETS_ARGS_B64\"}}")
ENCRYPTED_B64=$(echo "$SECRETS_VIEW" | jq -r '.result.result | implode' | jq -r '.encrypted_secrets // empty')
[[ -n "$ENCRYPTED_B64" && "$ENCRYPTED_B64" != "null" ]] || \
  fail "get_secrets returned no encrypted_secrets. Raw view response: $SECRETS_VIEW"
pass "fetched on-chain ciphertext (${#ENCRYPTED_B64} chars base64) for ($SECRET_PROJECT, $SECRET_PROFILE)"

# ─── 14. Decrypt locally with the recovered master ───────────────────
#
# `customer-recovery decrypt-secret` runs the same HMAC →
# ed25519-public-key-as-ChaCha20-key flow that the keystore's
# `decrypt_legacy` uses. Seed shape mirrors the `project:{id}:{owner}`
# seed the keystore builds in `keystore-worker/src/api.rs`, for Project
# accessors:
#   seed = "project:<owner>/<name>:<owner>"

SECRET_SEED="project:${SECRET_PROJECT}:${SECRET_PROJECT_OWNER}"
log "14. Decrypting locally (seed=$SECRET_SEED)"
DECRYPTED=$("$RECOVERY_BIN" decrypt-secret \
  --master "$MASTER_HEX" \
  --seed "$SECRET_SEED" \
  --ciphertext-base64 "$ENCRYPTED_B64") || \
  fail "customer-recovery decrypt-secret failed — \
the wire format from `outlayer secrets set` doesn't match the keystore's expected ECIES v1 \
shape. This used to be a known gap (CLI used legacy ChaCha20-with-pubkey, keystore expected \
ECIES) — if this fails after the CLI ECIES migration, the migration regressed."
echo "decrypt output: $DECRYPTED" >&2

DECRYPTED_VALUE=$(echo "$DECRYPTED" | jq -r '.MY_TEST_SECRET // empty' 2>/dev/null || echo "")
if [[ "$DECRYPTED_VALUE" != "$SECRET_VALUE" ]]; then
  fail "local decrypt succeeded but value mismatched: expected '$SECRET_VALUE', got '$DECRYPTED_VALUE'"
fi
pass "local decryption matches the stored secret — customer reads secrets without OutLayer"

echo
pass "ALL CHECKS PASSED. End-to-end sovereignty cutoff verified on $NETWORK."
echo
warn "Recovered artifacts (back these up offline; OutLayer cannot regenerate them):"
warn "  vault parent key:  $KEY_FILE"
warn "  per-vault master:  master_hex=$MASTER_HEX"
warn "  wallet private:    $DERIVED_PRIVKEY (account $NEAR_ACCOUNT_ID)"
warn "  pre-tx (keystore): $PRE_TX_HASH"
warn "  secret:            $SECRET_PROJECT [profile=$SECRET_PROFILE]"
