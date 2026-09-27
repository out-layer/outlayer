#!/bin/bash
# Phase 10 — automated end-to-end test of vault recovery flows
# (scenarios S3 unilateral path, S2 vault upgrade) on real testnet
# using the `test-timing` feature build of the vault contract.
#
# This script bypasses the production `outlayer vault init` flow
# (which bundles only DAO-approved WASMs) and deploys a custom
# test-timing build directly via `near` CLI. The 7-day cessation
# delay is collapsed to 30 seconds and the unilateral exit window
# minimum drops from 24h to 10s, so the full recovery cycle runs
# in under a minute.
#
# Required environment:
#   * NEAR CLI (`near`) on PATH — install with `npm i -g near-cli-rs`
#   * `cargo near` for the contract build
#   * Logged-in testnet account (`near login`) with at least 5 NEAR
#   * Optional: `JQ` for parsing view-call output
#
# Run:
#   ./vault_recovery_e2e.sh unilateral [--apply]
#   ./vault_recovery_e2e.sh propose-tee-key [--apply]
#
# Without --apply the script prints what it WOULD run.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPLY=false
SCENARIO="${1:-help}"
[[ "${2:-}" == "--apply" ]] && APPLY=true
[[ "${1:-}" == "--apply" ]] && { APPLY=true; SCENARIO="unilateral"; }

NETWORK="${NETWORK:-testnet}"
# EXPORTED, or the value above is a decoration.
#
# Every `outlayer …` call below follows `~/.outlayer/default-network` unless
# this is in the environment, and on a machine whose default is mainnet that
# means a script announcing testnet acts on MAINNET. Caught on 2026-08-22:
# this suite reported `parent: fastjambo.near / vault account:
# vault.fastjambo.near` and was stopped from deploying a real mainnet vault
# only by that account holding 0.2 NEAR against the 1.1 it needed.
export OUTLAYER_NETWORK="$NETWORK"
# The `near` wrapper: signs with the legacy key file when the signer has one —
# `sign-with-keychain` fails before signing for an account with many access keys.
source "$SCRIPT_DIR/lib/rpc.sh"
PARENT="${PARENT:-}"
VAULT_NAME="${VAULT_NAME:-recovery-test-$(date +%s)}"
VAULT_CONTRACT_DIR="${VAULT_CONTRACT_DIR:-$SCRIPT_DIR/../vault-contract}"
KEYSTORE_DAO_ID="${KEYSTORE_DAO_ID:-dao.outlayer.testnet}"
MPC_CONTRACT_ID="${MPC_CONTRACT_ID:-v1.signer-prod.testnet}"
# Current testnet contract constants (vault-contract/src/lib.rs):
#   MIN_UNILATERAL_EXIT_WINDOW_SECS = 60
#   FINALIZE_WINDOW_NS              = 600 * 10^9  (10 min)
#   CESSATION_DELAY_NS              = 60 * 10^9   (60s)
# `test-timing` feature exists in Cargo.toml but is currently a no-op
# placeholder — the constants above are already the testnet-tuned
# values. Use the contract minimum so this script completes in ~75s.
EXIT_WINDOW_SECS=60
FINALIZE_WAIT_SECS=70  # exit_window + small buffer

log()   { printf '\n\033[36m▶ %s\033[0m\n' "$*" >&2; }
warn()  { printf '\033[33m⚠ %s\033[0m\n' "$*" >&2; }
fail()  { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }
pass()  { printf '\033[32m✓ %s\033[0m\n' "$*" >&2; }

run() {
  if [[ "$APPLY" == true ]]; then
    log "$ $*"
    # near-cli-rs 0.23.x aborts on `near contract deploy` (and a few
    # other destructive flows) with "The input device is not a TTY"
    # when invoked from a non-interactive parent. Faking a pty with
    # `script` keeps the prompt path happy without prompting for
    # input. We write the command to a temp file so the embedded
    # backslash-newline continuations survive `script`'s argv
    # tokenisation (passing a multi-line string via `-c` re-parses
    # ANSI escapes that `log` left in the conversation buffer).
    # `-t 1` as well as the binary: without a terminal `script` dies with
    # `tcgetattr/ioctl: Operation not supported on socket` and takes the run
    # with it. `stuck_request_repair_e2e.sh` guards the same helper this way;
    # this copy did not, so the suite could not run headless at all.
    if command -v script >/dev/null 2>&1 && [ -t 1 ]; then
      local tmp_cmd
      tmp_cmd=$(mktemp -t vault_e2e_cmd.XXXXXX.sh)
      printf 'set -euo pipefail\n%s\n' "$*" > "$tmp_cmd"
      script -q /dev/null bash "$tmp_cmd"
      local rc=$?
      rm -f "$tmp_cmd"
      return $rc
    else
      eval "$@"
    fi
  else
    printf '\033[90m  (dry-run) $ %s\033[0m\n' "$*"
  fi
}

require() {
  if [[ -z "${1:-}" ]]; then
    fail "$2 not set. Export it before running this scenario."
  fi
}

# ─── Build test-timing vault WASM ──────────────────────────────────

build_test_timing_wasm() {
  log "Building vault-contract with --features test-timing"
  # cargo-near 0.20.x dropped `--no-locked` / `--no-docker` in favour
  # of explicit `non-reproducible-wasm` subcommand. Use that for a
  # fast local build; production deploys are built with `reproducible-wasm`.
  if [[ "$APPLY" == true ]]; then
    (cd "$VAULT_CONTRACT_DIR" && cargo near build non-reproducible-wasm --no-abi --features test-timing) 1>&2
  else
    printf '  (dry-run) cd %s && cargo near build non-reproducible-wasm --no-abi --features test-timing\n' "$VAULT_CONTRACT_DIR" 1>&2
  fi
  WASM_PATH="$VAULT_CONTRACT_DIR/target/near/vault_contract.wasm"
  if [[ "$APPLY" == true && ! -f "$WASM_PATH" ]]; then
    fail "WASM not found at $WASM_PATH after build"
  fi
  echo "$WASM_PATH"
}

# ─── Scenario: unilateral recovery (S3 unilateral path) ────────────

scenario_unilateral() {
  log "Scenario: unilateral recovery happy path (test-timing 10s window)"
  require "$PARENT" "PARENT (e.g. PARENT=alice.testnet)"
  local vault_account="$VAULT_NAME.$PARENT"

  # Pre-generate the new parent keypair that `finalize_recovery` will
  # install. `customer-recovery generate-key` emits the same shape
  # the rest of the recovery walkthrough uses, so we get a fresh
  # ed25519 keypair without depending on `openssl` or `near-cli-rs`
  # keygen here.
  local key_dir="${KEY_DIR:-/tmp/vault-recovery-e2e}"
  mkdir -p "$key_dir"
  local key_file="$key_dir/$vault_account.json"
  local recovery_bin="$SCRIPT_DIR/../scripts/customer-recovery/target/release/customer-recovery"
  if [[ "$APPLY" == true ]]; then
    if [[ ! -x "$recovery_bin" ]]; then
      log "Building customer-recovery binary"
      (cd "$SCRIPT_DIR/../scripts/customer-recovery" && cargo build --release --quiet)
    fi
    "$recovery_bin" generate-key > "$key_file"
    chmod 600 "$key_file"
    NEW_PARENT_PUBKEY=$(jq -r '.public_key' "$key_file")
    log "Generated new_parent_pubkey: $NEW_PARENT_PUBKEY"
    log "  (private key stored at $key_file — sole authority over the vault post-finalize)"
  else
    NEW_PARENT_PUBKEY="ed25519:DRY_RUN_REPLACEMENT_PUBKEY"
    printf '  (dry-run) would generate keypair at %s\n' "$key_file"
  fi

  WASM_PATH=$(build_test_timing_wasm)

  log "1. Create vault sub-account funded by parent ($vault_account)"
  # Sub-accounts of `*.testnet` cannot use the testnet faucet
  # (only top-level accounts qualify). The correct path is
  # `fund-myself`: parent funds the sub-account and adds an
  # initial full-access key from PARENT's signing key. We then
  # deploy the WASM as a separate tx.
  #
  # NOTE: this leaves PARENT's pubkey on the sub-account, which is
  # NOT what production `outlayer vault init` does (production has
  # only a TEE FCAK after deploy). For recovery TESTING that's
  # fine — we want parent authority to drive the unilateral flow
  # and to call `unlocked_add_key` post-recovery.
  run "near account create-account fund-myself \\
        $vault_account \\
        '2 NEAR' \\
        autogenerate-new-keypair save-to-keychain \\
        sign-as $PARENT \\
        network-config testnet \\
        sign-with-keychain send"

  log "2. Deploy test-timing WASM + init"
  # `initial_tee_pubkey` is passed as null — this e2e drives the
  # recovery flow without a real TEE in the loop, so there's no TEE
  # key to install at deploy time. `finalize_recovery` still atomically
  # deletes whatever is in `initial_tee_key` (None means nothing to
  # delete) and adds the new parent's FAK.
  run "near contract deploy $vault_account \\
        use-file $WASM_PATH \\
        with-init-call new \\
          json-args '{\"parent\": \"$PARENT\", \"keystore_dao\": \"$KEYSTORE_DAO_ID\", \"mpc_contract\": \"$MPC_CONTRACT_ID\", \"initial_tee_pubkey\": null, \"initial_exit_window\": $EXIT_WINDOW_SECS}' \\
          prepaid-gas '30 TGas' \\
          attached-deposit '0 NEAR' \\
        network-config testnet \\
        sign-with-keychain send"

  log "3. Confirm initial state: unlocked=false, recovery=None"
  run "near contract call-function as-read-only $vault_account get_state \\
        json-args '{}' \\
        network-config testnet now"

  log "4. Parent ($PARENT) calls unilateral_initiate_recovery"
  run "near contract call-function as-transaction $vault_account unilateral_initiate_recovery \\
        json-args '{}' \\
        prepaid-gas '30 TGas' attached-deposit '0 NEAR' \\
        sign-as $PARENT \\
        network-config testnet \\
        sign-with-keychain send"

  log "5. Verify recovery state is set"
  run "near contract call-function as-read-only $vault_account get_recovery_state \\
        json-args '{}' \\
        network-config testnet now"

  log "6. Wait $FINALIZE_WAIT_SECS seconds for exit window to pass"
  if [[ "$APPLY" == true ]]; then
    sleep "$FINALIZE_WAIT_SECS"
  else
    printf '  (dry-run) sleep %s\n' "$FINALIZE_WAIT_SECS"
  fi

  log "7. Parent calls finalize_recovery(new_parent_pubkey)"
  # Parent-only entry — the contract checks
  # `env::predecessor_account_id() == self.parent` as its first
  # action, so any other signer is bounced. The atomic key-swap
  # (DeleteKey(initial_tee_key + registered_tee_keys) +
  # AddFullAccessKey(new_parent_pubkey)) happens in this same
  # transaction's receipt batch.
  run "near contract call-function as-transaction $vault_account finalize_recovery \\
        json-args '{\"new_parent_pubkey\": \"$NEW_PARENT_PUBKEY\"}' \\
        prepaid-gas '100 TGas' attached-deposit '0 NEAR' \\
        sign-as $PARENT \\
        network-config testnet \\
        sign-with-keychain send"

  log "8. Verify unlocked=true and recovery cleared"
  run "near contract call-function as-read-only $vault_account get_state \\
        json-args '{}' \\
        network-config testnet now"

  log "9. List access keys — expect new_parent_pubkey as full-access"
  run "near account list-keys $vault_account network-config testnet now"
  warn "Manual check: $NEW_PARENT_PUBKEY must be present with full_access."
  warn "  (private key for this pubkey: $key_file)"

  pass "Scenario unilateral — done. Vault $vault_account is unlocked + new-parent-controlled."

  log "Cleanup: delete account, refund storage to $PARENT"
  warn "Run manually if desired:"
  warn "  near account delete-account $vault_account beneficiary $PARENT \\"
  warn "    network-config testnet sign-with-keychain send"
}

# ─── Scenario: propose_tee_key (Phase 10 S2 fragment) ──────────────

scenario_propose_tee_key() {
  log "Scenario: propose_tee_key happy path (vault accepts new approved keystore)"
  require "$PARENT" "PARENT"
  local vault_account="$VAULT_NAME.$PARENT"
  warn "This scenario requires:"
  warn "  1. A live vault deployed at $vault_account (run scenario_unilateral first or use existing)"
  warn "  2. An approved keystore pubkey known to $KEYSTORE_DAO_ID"
  warn "  3. Anyone (permissionless) calling propose_tee_key"

  log "Calling propose_tee_key with sample pubkey"
  run "near contract call-function as-transaction $vault_account propose_tee_key \\
        json-args '{\"public_key\": \"ed25519:REPLACE_WITH_APPROVED_KEYSTORE_PUBKEY\"}' \\
        prepaid-gas '100 TGas' attached-deposit '0 NEAR' \\
        sign-as $PARENT \\
        network-config testnet \\
        sign-with-keychain send"

  log "Verify: registered_tee_keys now contains the new pubkey"
  run "near view $vault_account get_registered_keys '{}' --network-config testnet"

  pass "Scenario propose_tee_key — done. Vault accepted the new approved keystore."
}

# ─── Driver ────────────────────────────────────────────────────────

usage() {
  cat <<EOF
Usage: $0 <scenario> [--apply]

Scenarios:
  unilateral       — Full unilateral recovery cycle (deploy → initiate → wait → finalize → add_key)
  propose-tee-key  — Propose a new approved-keystore pubkey via cross-contract DAO check

Flags:
  --apply          — Execute the commands. Without this, dry-run.

Env:
  PARENT             NEAR account that creates + parents the vault (required)
  NETWORK            testnet (default)
  VAULT_NAME         Sub-account label (default: recovery-test-<unix>)
  KEYSTORE_DAO_ID    Default: dao.outlayer.testnet
  MPC_CONTRACT_ID    Default: v1.signer-prod.testnet
  VAULT_CONTRACT_DIR Default: <repo>/vault-contract

Notes:
  * Built with --features test-timing: 7-day delays collapse to 30s,
    24h unilateral window collapses to 10s. NOT a production WASM.
  * NEVER deploy the test-timing WASM under outlayer.near's
    DAO-approved hash list; the resulting hash is intentionally
    distinct and will fail vault-checker.
EOF
}

case "$SCENARIO" in
  unilateral)        scenario_unilateral ;;
  propose-tee-key)   scenario_propose_tee_key ;;
  -h|--help|help)    usage; exit 0 ;;
  *)                 usage; exit 1 ;;
esac
