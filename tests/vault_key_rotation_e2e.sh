#!/usr/bin/env bash
# Key rotation for a vault-bound parent wallet and its sub-agents, end to end,
# on testnet — the path a customer takes after its keys leak:
#
#   R1  parent under the vault + sub-agents keyed as the customer derives them
#       (wk = HKDF-SHA256(master, salt "outlayer-wk-v1", info seed)); one is
#       funded and MOVES money with its v1 key
#   R2  the parent key is replaced through the owner policy
#       (`authorized_key_hashes`), in the dashboard's two saves:
#       [old, new] then [new]
#   R3  with the NEW parent key: same address, same vault, every seed resolves
#       to the SAME sub-agent wallet_id — the defect this suite was written
#       for put the new key on the default master
#   R4  the sub-agent master is rotated: PUT the v2 hash with the new parent,
#       DELETE the v1 hash with the v2 key; the funded sub-agent moves money
#       with its v2 key from the same address; every v1 key is 401, the parent
#       cannot revoke a child's key, re-running is harmless
#   R5  negatives: a policy naming another wallet's hash changes nothing; a
#       frozen wallet refuses to move money with the new key but its owner can
#       still save a policy; a policy with an EMPTY `authorized_key_hashes`
#       after a rotation leaves the wallet with no live key (known; the
#       customer is told to always list the current key)
#
# The parent and the funded sub-agent are throwaway wallets under
# vault.$PARENT; the sub-agent's NEAR goes back to $PARENT at the end
# (DeleteAccount), the policies' storage deposits are reclaimed.
#
# Required env:
#   PARENT   the vault's parent account, keys in ~/.near-credentials/testnet
#            (default outlayer-alice.testnet; vault.$PARENT must exist — see
#            unified_vault_e2e.sh or `outlayer vault init`)
#
#   NETWORK=testnet ./tests/vault_key_rotation_e2e.sh --apply
#
# Dry-run (no --apply) prints the plan. Nothing secret is printed: keys are
# shown as hash prefixes only.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NETWORK="${NETWORK:-testnet}"
[[ "$NETWORK" == testnet ]] || { echo "this suite mints throwaway wallets under a vault: testnet only" >&2; exit 1; }
export NETWORK
source "$SCRIPT_DIR/lib/rpc.sh"   # keyed RPC_URL, or a warning
export RPC_URL
export PARENT="${PARENT:-outlayer-alice.testnet}"
export VAULT="${VAULT:-vault.$PARENT}"
export CONTRACT_ID="${CONTRACT_ID:-outlayer.testnet}"
export COORDINATOR_URL="${COORDINATOR_URL:-https://testnet-api.outlayer.ai}"
export ONLY="${ONLY:-}"
if [[ "${1:-}" != "--apply" ]]; then
  echo "Dry-run. --apply runs R1–R5 on $NETWORK: parent $PARENT, vault $VAULT, $(rpc_url_public)" >&2
  echo "Funds: ~0.03 NEAR from $PARENT (sub-agent funding + two policy deposits), swept back at the end." >&2
  exit 0
fi
exec python3 "$SCRIPT_DIR/lib/vault_key_rotation.py"
