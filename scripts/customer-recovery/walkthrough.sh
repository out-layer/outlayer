#!/bin/bash
# OutLayer sovereign-vault recovery walkthrough.
#
# Takes a vault FROM "OutLayer is serving it under a TEE function-call
# key" TO "I (the customer) own this vault outright and OutLayer can
# no longer sign anything bound to it". After the walkthrough you also
# recover the per-vault master locally so secrets stored against the
# vault stay decryptable.
#
# Run as the PARENT account that originally deployed the vault.
#
# Required tools:
#   * outlayer  (https://github.com/out-layer/cli)
#   * cargo     (to build the customer-recovery helper binary)
#   * jq        (response parsing)
#
# Optional:
#   * curl      (called for RPC view queries — pre-installed on macOS/Linux)
#
# What the script does:
#
#   0. Build the `customer-recovery` binary that lives in this same
#      directory. It owns both the local keygen (step 1) and the
#      master-recovery via MPC (step 5).
#
#   1. Generate a brand-new ed25519 keypair ON YOUR MACHINE. The
#      private key never leaves this shell. The public half is what
#      you'll hand to the vault contract as the future sole owner.
#      Saved to ~/.outlayer-recovery/<vault_id>.json, mode 0600.
#
#   2. Initiate unilateral recovery. The vault timer starts counting
#      down `unilateral_exit_window_secs` (default 24h). A shorter
#      window (`SHORTEN_EXIT_WINDOW_TO`) applies only after the window
#      in force has elapsed; until then the script stops before
#      initiating, so the recovery is not started on the longer one.
#      Idempotent: if a previous run left a recovery in progress,
#      we detect it and skip the call (the timer is already set).
#
#   3. Wait for the window to elapse. The script just sleeps.
#
#   4. Finalize recovery passing your new pubkey. ONE atomic tx
#      simultaneously:
#         * deletes every TEE access key OutLayer was using (initial
#           one installed at deploy + any DAO-rotation keys)
#         * adds your new pubkey as a FullAccess key
#         * sets `unlocked = true` and clears the recovery state
#      After this the vault is on-chain controlled by your private
#      key. OutLayer's keystore physically cannot sign
#      `vault.request_master` anymore (no on-chain access key for it),
#      and the off-chain master cache is dropped within seconds by
#      `outlayer-monitor` reacting to the finalize log event.
#
#   5. Recover the per-vault master via MPC CKD using your new
#      private key. The master is the secret OutLayer was holding in
#      TEE memory; you re-derive it deterministically by calling
#      `mpc.request_app_private_key` with the same parameters
#      OutLayer used. After this you can decrypt every secret ever
#      stored against the vault — entirely offline from OutLayer's
#      infrastructure.
#
# DO NOT lose the private-key file after step 1. It is now the ONLY
# thing that can sign tx for the vault. Back it up to cold storage
# immediately after the script runs.

set -euo pipefail

# ─── Inputs ─────────────────────────────────────────────────────────

VAULT_ID="${VAULT_ID:-}"
NETWORK="${NETWORK:-testnet}"
RPC_URL="${RPC_URL:-https://rpc.${NETWORK}.fastnear.com}"
KEY_DIR="${KEY_DIR:-$HOME/.outlayer-recovery}"

if [[ -z "$VAULT_ID" ]]; then
  echo "USAGE:  VAULT_ID=vault.alice.testnet $0" >&2
  echo "Optional env: NETWORK=mainnet|testnet (default testnet)" >&2
  echo "              KEY_DIR=/path/to/keys (default ~/.outlayer-recovery)" >&2
  echo "              MPC_PUBLIC_KEY=bls12381g2:...  (required, ask OutLayer ops)" >&2
  exit 1
fi

# Per-network constants. The customer-recovery binary's clap defaults
# target testnet only; if we don't override here, mainnet runs would
# silently hit `v1.signer-prod.testnet` and the testnet NEARblocks
# indexer, producing confusing 404s on a real mainnet vault.
case "$NETWORK" in
  mainnet)
    MPC_CONTRACT_ID="${MPC_CONTRACT_ID:-v1.signer}"
    NEARBLOCKS_URL="${NEARBLOCKS_URL:-https://api.nearblocks.io}"
    ;;
  testnet)
    MPC_CONTRACT_ID="${MPC_CONTRACT_ID:-v1.signer-prod.testnet}"
    NEARBLOCKS_URL="${NEARBLOCKS_URL:-https://api-testnet.nearblocks.io}"
    ;;
  *)
    echo "Unsupported NETWORK='$NETWORK' (expected: mainnet|testnet)." >&2
    exit 1
    ;;
esac

# MPC_PUBLIC_KEY has no default in the binary — it's the per-domain
# bls12381g2 verification key and must match the keystore-worker's
# config exactly. Fail early with a clear message instead of having
# clap blow up two steps from now.
if [[ -z "${MPC_PUBLIC_KEY:-}" ]]; then
  echo "MPC_PUBLIC_KEY env var is required (bls12381g2:base58, ask OutLayer ops" >&2
  echo "for the $NETWORK value — same key the keystore-worker uses)." >&2
  exit 1
fi

if ! command -v jq >/dev/null; then
  echo "Required tool 'jq' not found in PATH. Install it before running." >&2
  exit 1
fi
if ! command -v cargo >/dev/null; then
  echo "Required tool 'cargo' not found in PATH (needed to build customer-recovery)." >&2
  exit 1
fi
if ! command -v outlayer >/dev/null; then
  echo "Required tool 'outlayer' not found in PATH (see https://github.com/out-layer/cli)." >&2
  exit 1
fi
if ! command -v curl >/dev/null; then
  echo "Required tool 'curl' not found in PATH (used for RPC view queries)." >&2
  exit 1
fi

# Pre-flight: parent account must be logged in and must match the
# vault's `parent` field on chain. Otherwise `initiate_unilateral_recovery`
# panics with "only the parent account can initiate" deep inside the
# CLI's tx pipeline — a less obvious failure than catching it here.
if ! WHOAMI_OUT=$(outlayer whoami 2>&1); then
  echo "outlayer whoami failed — run 'outlayer login $NETWORK' first." >&2
  echo "$WHOAMI_OUT" >&2
  exit 1
fi
LOGGED_IN_ACCOUNT=$(printf '%s\n' "$WHOAMI_OUT" \
  | awk -F': *' '/^Account:/{print $2; exit}')
if [[ -z "$LOGGED_IN_ACCOUNT" ]]; then
  echo "Could not parse logged-in account from 'outlayer whoami' output:" >&2
  printf '%s\n' "$WHOAMI_OUT" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RECOVERY_BIN="$SCRIPT_DIR/target/release/customer-recovery"

# Create $KEY_DIR with strict perms BEFORE any file lands inside.
# `install -d -m 700` is atomic w.r.t. permissions (mkdir + chmod
# would have a tiny race window where another local user could
# enter the dir). Same idea for the umask switch — we restore the
# previous umask immediately after.
OLD_UMASK=$(umask)
umask 077
install -d -m 700 "$KEY_DIR"

KEY_FILE="$KEY_DIR/$VAULT_ID.json"
if [[ -f "$KEY_FILE" ]]; then
  echo "Refusing to overwrite existing key file: $KEY_FILE" >&2
  echo "(rename or delete it if you intend to start fresh; or unset KEY_DIR" >&2
  echo " and point it to a clean directory)" >&2
  umask "$OLD_UMASK"
  exit 1
fi

# ─── Step 0: build the customer-recovery binary ─────────────────────

echo "▶ Step 0: building customer-recovery binary (~30s on first run)"
(cd "$SCRIPT_DIR" && cargo build --release --quiet)

if [[ ! -x "$RECOVERY_BIN" ]]; then
  echo "Build succeeded but $RECOVERY_BIN is missing — Cargo output may have changed." >&2
  umask "$OLD_UMASK"
  exit 1
fi

# ─── Step 1: generate keypair locally ───────────────────────────────

echo
echo "▶ Step 1: generating ed25519 keypair on this machine"
"$RECOVERY_BIN" generate-key > "$KEY_FILE"
chmod 600 "$KEY_FILE"
NEW_PUBKEY=$(jq -r '.public_key' "$KEY_FILE")
echo "          new_pubkey: $NEW_PUBKEY"
echo "          private key: $KEY_FILE  (mode 0600)"
echo "          ⚠ BACK THIS FILE UP IMMEDIATELY — it's the only thing that"
echo "          can sign for $VAULT_ID after step 4 lands."

# Restore umask for any subsequent file creation outside KEY_DIR
# (cargo build cache, log files, etc).
umask "$OLD_UMASK"

# ─── Helper: read vault state without keeping the JSON in /tmp ──────

read_vault_state() {
  curl -s "$RPC_URL" -X POST -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"query\",\"params\":{\"request_type\":\"call_function\",\"finality\":\"final\",\"account_id\":\"$VAULT_ID\",\"method_name\":\"get_state\",\"args_base64\":\"e30=\"}}" \
    | jq -r '.result.result | implode'
}

# ─── Step 2: check state + pre-flight + (optional) shorten window ───

echo
echo "▶ Step 2: checking vault state"
CURRENT_STATE=$(read_vault_state)
VAULT_PARENT=$(echo "$CURRENT_STATE" | jq -r '.parent')
CURRENT_RECOVERY=$(echo "$CURRENT_STATE" | jq -r '.recovery')
ALREADY_UNLOCKED=$(echo "$CURRENT_STATE" | jq -r '.unlocked')

if [[ "$VAULT_PARENT" != "$LOGGED_IN_ACCOUNT" ]]; then
  echo "Logged-in account ($LOGGED_IN_ACCOUNT) does NOT match vault.parent ($VAULT_PARENT)." >&2
  echo "Recovery is parent-only. Run 'outlayer logout && outlayer login $NETWORK'" >&2
  echo "as $VAULT_PARENT before re-running this script." >&2
  exit 1
fi

# Optional: shorten the exit window before initiating. Set
# `SHORTEN_EXIT_WINDOW_TO=60s` (or 5m, 1h, …). The vault applies a shorter
# window only after the window in force has elapsed (a vault of the first
# contract version applies it at once); while it is pending, the script
# stops here (exit 1, nothing initiated) and says when to run it again. Has no effect if a recovery is
# already in progress (set-exit-window only affects future initiations).
# A drill in minutes needs a vault deployed with that window
# (`outlayer vault init --exit-window 60s` on the testnet test-timing build).
if [[ -n "${SHORTEN_EXIT_WINDOW_TO:-}" && "$CURRENT_RECOVERY" == "null" && "$ALREADY_UNLOCKED" != "true" ]]; then
  echo "          shortening exit window to $SHORTEN_EXIT_WINDOW_TO before initiate"
  outlayer vault set-exit-window "$VAULT_ID" "$SHORTEN_EXIT_WINDOW_TO"
  # Re-read state so subsequent reads see the new window.
  CURRENT_STATE=$(read_vault_state)
  PENDING_AT_NS=$(echo "$CURRENT_STATE" | jq -r '.pending_exit_window.effective_at // empty')
  if [[ -n "$PENDING_AT_NS" ]]; then
    echo "          the vault keeps $(echo "$CURRENT_STATE" | jq -r '.unilateral_exit_window_secs')s in force; the shorter window applies at unix time $((PENDING_AT_NS / 1000000000))."
    echo "          not initiating now: a recovery started now would run on the longer window."
    echo "          run this script again after that time, or without SHORTEN_EXIT_WINDOW_TO to recover on the window in force."
    exit 1
  fi
fi

if [[ "$ALREADY_UNLOCKED" == "true" ]]; then
  echo "          vault is ALREADY unlocked — skipping initiate + finalize."
  echo "          jumping straight to master recovery (step 5)."
  SKIP_TO_RECOVER=1
elif [[ "$CURRENT_RECOVERY" != "null" ]]; then
  TRIGGER=$(echo "$CURRENT_STATE" | jq -r '.recovery.trigger')
  echo "          recovery already in progress (trigger=$TRIGGER) — skipping initiate"
  SKIP_TO_RECOVER=0
else
  echo "          no recovery in progress — initiating unilateral now"
  outlayer vault initiate-unilateral-recovery "$VAULT_ID"
  SKIP_TO_RECOVER=0
fi

# ─── Step 3: wait for the exit window ───────────────────────────────

if [[ "${SKIP_TO_RECOVER}" == "0" ]]; then
  STATE_AFTER=$(read_vault_state)
  EXIT_WINDOW_SECS=$(echo "$STATE_AFTER" | jq -r '.unilateral_exit_window_secs')
  FINALIZE_AFTER_NS=$(echo "$STATE_AFTER" | jq -r '.recovery.finalize_after // empty')

  if [[ -n "$FINALIZE_AFTER_NS" ]]; then
    NOW_NS=$(($(date +%s) * 1000000000))
    WAIT_NS=$((FINALIZE_AFTER_NS - NOW_NS))
    if (( WAIT_NS > 0 )); then
      WAIT_S=$(( WAIT_NS / 1000000000 + 10 ))
      echo
      echo "▶ Step 3: waiting ${WAIT_S}s until finalize window opens"
      echo "          (exit_window=${EXIT_WINDOW_SECS}s)"
      sleep "$WAIT_S"
    else
      echo
      echo "▶ Step 3: finalize window already open"
    fi
  fi

  # ─── Step 4: finalize + atomic key swap ──────────────────────────

  echo
  echo "▶ Step 4: finalizing recovery — installs $NEW_PUBKEY, deletes OutLayer TEE keys"
  outlayer vault finalize-recovery "$VAULT_ID" "$NEW_PUBKEY"

  # Verify the swap actually committed. `finalize_recovery` returns
  # a Promise on the success path; the state mutation
  # (unlocked = true, key swap on the access-key list) only commits
  # AFTER the swap's child receipt resolves successfully in
  # `callback_after_swap`. If the swap action batch failed (e.g.
  # invalid pubkey format, or a regression triggered
  # AccessKeyAlreadyExists), the tx will look successful at the
  # parent-receipt level but the vault stays locked with TEE keys
  # intact. Read state and bail loudly if so — the customer can
  # re-run this script inside the same finalize_before window with
  # a corrected pubkey.
  echo
  echo "▶ Vault state after finalize:"
  POST_STATE=$(read_vault_state)
  echo "$POST_STATE" | jq '{unlocked, recovery, registered_tee_keys, initial_tee_key}'
  POST_UNLOCKED=$(echo "$POST_STATE" | jq -r '.unlocked')
  if [[ "$POST_UNLOCKED" != "true" ]]; then
    echo
    echo "✗ Vault did NOT unlock after finalize. The atomic key-swap" >&2
    echo "  receipt failed — the post-swap callback left state untouched." >&2
    echo "  Common causes:" >&2
    echo "    * new_parent_pubkey collides with an existing access key on the" >&2
    echo "      vault (the AddKey action then panics with AccessKeyAlreadyExists)" >&2
    echo "    * malformed pubkey (the CLI's pre-flight should catch this — file a bug)" >&2
    echo "  You can re-run this script: it will regenerate a fresh keypair" >&2
    echo "  and retry the finalize within the existing finalize_before window." >&2
    echo "  First, delete the stale key file:" >&2
    echo "    rm \"$KEY_FILE\"" >&2
    exit 1
  fi
fi

# ─── Step 5: recover the per-vault master via MPC CKD ───────────────

echo
echo "▶ Step 5: recovering per-vault master via MPC CKD"
echo "          (uses the customer-recovery binary built in step 0)"

# Pass the private key through `env` so VAULT_PRIVATE_KEY is scoped
# to this one child process — no leakage into the parent shell env
# or `ps eww` output of unrelated tools. The child binary reads it
# from its own environment block.
env VAULT_PRIVATE_KEY="$(jq -r '.private_key' "$KEY_FILE")" \
  MPC_PUBLIC_KEY="$MPC_PUBLIC_KEY" \
  "$RECOVERY_BIN" \
    --vault-id "$VAULT_ID" \
    --from-chain \
    --rpc-url "$RPC_URL" \
    --mpc-contract "$MPC_CONTRACT_ID" \
    --nearblocks-url "$NEARBLOCKS_URL"

echo
echo "✓ Done. You now hold:"
echo "    $KEY_FILE  (private key — sole authority over $VAULT_ID)"
echo "    the per-vault master printed above (decrypts secrets bound to $VAULT_ID)"
echo
echo "Back BOTH up offline immediately. From this point OutLayer's"
echo "keystore has no path back into your vault — sovereignty is yours."
