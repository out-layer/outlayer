#!/usr/bin/env bash
#
# Put the GitHub connector's prices on chain and tell the coordinator to read
# them, in one run.
#
# Prices live on chain, not in the manifest: the contract is what the coordinator
# charges by, and the coordinator keeps a cached copy it refreshes on demand.
# Both halves are here so the two cannot be left disagreeing.
#
# The admin token and the coordinator's URL come from the MAIN repo's
# `scripts/.env` — the same file every other script reads them from. Override the
# path with ENV_FILE when this connector is checked out on its own.
#
# Usage:
#   CONTRACT=outlayer.near OWNER=owner.outlayer.near ./set-prices.sh [testnet|mainnet]
#
# Prerequisites, in order:
#   1. the contract is at storage version 8 (`project_pricing` is a v8 field);
#   2. `connectors.outlayer.near/gmail` is published — `set_project_pricing`
#      refuses a project nobody registered.
#
set -euo pipefail

cd "$(dirname "$0")"

# What the caller asked for, kept before the env file is read: that file is the
# operator's and must not quietly replace an account named on the command line.
ARG_CONTRACT="${CONTRACT:-}"
ARG_OWNER="${OWNER:-}"
ARG_AUTHOR="${AUTHOR:-}"
ARG_ADMIN_TOKEN="${ADMIN_TOKEN:-}"
ARG_API="${API:-}"

ENV_FILE="${ENV_FILE:-../../scripts/.env}"
if [ -f "$ENV_FILE" ]; then
    # shellcheck disable=SC1090
    set -a; . "$ENV_FILE"; set +a
else
    echo "NOTE: $ENV_FILE not found — pass ADMIN_TOKEN and API yourself, or the coordinator keeps the old prices"
fi

NETWORK="${1:-testnet}"
case "$NETWORK" in
  testnet) NETWORK_ID=testnet; SUFFIX=testnet; DEFAULT_CONTRACT=outlayer.testnet;
     ADMIN_TOKEN_FROM_ENV="${ADMIN_BEARER_TOKEN_TESTNET:-}"; API_FROM_ENV="${COORDINATOR_URL_TESTNET:-}" ;;
  mainnet) NETWORK_ID=mainnet; SUFFIX=near; DEFAULT_CONTRACT=outlayer.near;
     ADMIN_TOKEN_FROM_ENV="${ADMIN_BEARER_TOKEN_MAINNET:-}"; API_FROM_ENV="${COORDINATOR_URL_MAINNET:-}" ;;
  *) echo "ERROR: network must be testnet or mainnet" >&2; exit 1 ;;
esac

CONTRACT="${ARG_CONTRACT:-$DEFAULT_CONTRACT}"
OWNER="${ARG_OWNER:?set OWNER to the contract owner account that signs this call}"
NAMESPACE="connectors.outlayer.$SUFFIX"
PROJECT="$NAMESPACE/github"
# Who is credited the author's share. Ours, so the share is zero and the whole
# fee stays with the project's owner.
AUTHOR="${ARG_AUTHOR:-$NAMESPACE}"
ADMIN_TOKEN="${ARG_ADMIN_TOKEN:-$ADMIN_TOKEN_FROM_ENV}"
API="${ARG_API:-$API_FROM_ENV}"

# The priced operations must be exactly the manifest's: an operation priced but
# not implemented is money for nothing, and one implemented but unpriced is
# refused before it runs.
python3 - "$0" manifest.json <<'PYCHECK'
import json, re, sys
priced = set(re.findall(r'\{"operation": "([a-z_]+)"', open(sys.argv[1]).read()))
declared = set(json.load(open(sys.argv[2]))["operations"])
if priced != declared:
    print(f"ERROR: priced {sorted(priced)} vs manifest {sorted(declared)}"); sys.exit(1)
print(f"Manifest: {len(declared)} operations agree with the price list")
PYCHECK

# `status` is free, so an agent can see what it may do before spending anything.
# A read is a tenth of a cent; a write is a cent — it leaves a trace in somebody's
# repository under the owner's name, and that is what the price is for.
near call "$CONTRACT" set_project_pricing "$(cat <<JSON
{
  "project_id": "$PROJECT",
  "pricing": {
    "author_account_id": "$AUTHOR",
    "operations": [
      {"operation": "status", "price_usd": "0", "developer_share_bp": 0},
      {"operation": "repo_list", "price_usd": "1000", "developer_share_bp": 0},
      {"operation": "repo_get", "price_usd": "1000", "developer_share_bp": 0},
      {"operation": "dir_list", "price_usd": "1000", "developer_share_bp": 0},
      {"operation": "file_get", "price_usd": "1000", "developer_share_bp": 0},
      {"operation": "branch_list", "price_usd": "1000", "developer_share_bp": 0},
      {"operation": "issue_list", "price_usd": "1000", "developer_share_bp": 0},
      {"operation": "issue_get", "price_usd": "1000", "developer_share_bp": 0},
      {"operation": "pr_list", "price_usd": "1000", "developer_share_bp": 0},
      {"operation": "pr_get", "price_usd": "1000", "developer_share_bp": 0},
      {"operation": "pr_files", "price_usd": "1000", "developer_share_bp": 0},
      {"operation": "gist_list", "price_usd": "1000", "developer_share_bp": 0},
      {"operation": "gist_get", "price_usd": "1000", "developer_share_bp": 0},
      {"operation": "branch_create", "price_usd": "10000", "developer_share_bp": 0},
      {"operation": "file_put", "price_usd": "10000", "developer_share_bp": 0},
      {"operation": "commit", "price_usd": "10000", "developer_share_bp": 0},
      {"operation": "issue_create", "price_usd": "10000", "developer_share_bp": 0},
      {"operation": "issue_comment", "price_usd": "10000", "developer_share_bp": 0},
      {"operation": "issue_update", "price_usd": "10000", "developer_share_bp": 0},
      {"operation": "pr_create", "price_usd": "10000", "developer_share_bp": 0},
      {"operation": "pr_review", "price_usd": "10000", "developer_share_bp": 0},
      {"operation": "pr_merge", "price_usd": "10000", "developer_share_bp": 0},
      {"operation": "gist_create", "price_usd": "10000", "developer_share_bp": 0},
      {"operation": "gist_update", "price_usd": "10000", "developer_share_bp": 0},
      {"operation": "repo_star", "price_usd": "10000", "developer_share_bp": 0},
      {"operation": "repo_unstar", "price_usd": "10000", "developer_share_bp": 0}
    ]
  }
}
JSON
)" --accountId "$OWNER" --networkId "$NETWORK_ID"

echo
near view "$CONTRACT" get_project_pricing "{\"project_id\": \"$PROJECT\"}" --networkId "$NETWORK_ID"

# The coordinator charges from its cached copy, so a price nobody refreshed is a
# price nobody charges.
echo
if [ -n "$ADMIN_TOKEN" ] && [ -n "$API" ]; then
    echo "Refreshing $API/admin/connector-prices/refresh"
    curl -fsS -X POST "$API/admin/connector-prices/refresh" -H "Authorization: Bearer $ADMIN_TOKEN" && echo
    echo "Done: the on-chain row and the coordinator agree"
else
    echo "NOT refreshed: no admin token or API URL. Run it yourself, or the coordinator keeps charging the old prices:"
    echo "  curl -X POST \$API/admin/connector-prices/refresh -H \"Authorization: Bearer \$ADMIN_TOKEN\""
fi
