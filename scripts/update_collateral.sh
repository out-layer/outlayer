#!/bin/bash
# Update a register-contract collateral SLOT (Phase-1 multi-FMSPC support).
#
# The register-contract (worker.outlayer.<net>) now holds up to MAX_COLLATERALS collaterals,
# one per platform/FMSPC. register_worker_key reads the FMSPC out of the worker's quote and
# verifies ONLY the slot whose collateral matches it (a single dcap-qvl verify, regardless of
# how many slots are cached — so adding slots never raises the per-registration gas).
# Slots:   0 = Phala         (FMSPC 20a06f000000)
#          1 = self-hosted TDX (FMSPC B0C06F000000)
# Updating one slot does NOT delete the others (mixed fleet coexists).
#
# The collateral is the Intel DCAP verification material (TCB info, QE identity, PCK CRLs/certs)
# keyed by the platform's FMSPC. It is **platform-specific, NOT network-specific** — the SAME file
# is used for testnet AND mainnet (it certifies the TDX hardware/TCB, not the NEAR network); just
# cache it on each network's contract. It IS time-sensitive: regenerate when Intel's TCB/CRLs
# update or registration fails with a TCB/collateral error (e.g. status != UpToDate).
#
# Generate the collateral JSON per platform FIRST:
#   - Phala:       from the Phala PCCS (as before).
#   - self-hosted: ON THE NODE, as the `outlayer` user, with the patched dcap-qvl (v0.3.12 — dumps
#     QuoteCollateralV3 + accepts the self-signed local PCCS). `--hex` is a FLAG; the arg is a quote
#     FILE (not the hex string). A reusable platform quote is saved at /home/outlayer/platform-quote.hex
#     (any TDX quote from THIS platform works — the collateral is per-FMSPC, not per-quote):
#       ssh root@<node>
#       su - outlayer -c 'cd /tmp && PCCS_URL=https://localhost:8081 \
#         /home/outlayer/dcap-qvl/cli/target/release/dcap-qvl verify --hex /home/outlayer/platform-quote.hex'
#       # prints "Quote verified" (status UpToDate) + writes /tmp/our_collateral.json
#       # then from your laptop, pull it in CANONICAL form (see the strip note below — this is what
#       # keeps the committed file identical no matter which node generated it):
#       #   ssh root@<node> 'jq -S "del(.pck_certificate_chain)" /tmp/our_collateral.json' \
#       #     > scripts/our_collateral.json
#     (If platform-quote.hex is lost, extract any worker's quote from its app_cert ext OID
#      1.3.6.1.4.1.62397.1.8; the FMSPC must be B0C06F000000.)
#
# Usage: ./scripts/update_collateral.sh <collateral.json> <index> [network] [contract]
#   ./scripts/update_collateral.sh our_collateral.json 1 testnet        # self-hosted TDX -> slot 1, testnet
#   ./scripts/update_collateral.sh our_collateral.json 1 mainnet        # SAME file -> slot 1, mainnet
#   ./scripts/update_collateral.sh phala_collateral.json 0 testnet      # Phala -> slot 0
#
# After the on-chain call, the coordinator is asked to capture the new version into its
# `collateral_versions` history (POST /admin/collateral/check). That history is what lets a past
# attestation still be verified once this slot has been overwritten — the contract keeps only the
# newest version per slot and Intel's PCS serves only the current one, so a superseded collateral
# survives nowhere else. The step is best-effort: the on-chain update has already succeeded by then,
# and a missed capture is recoverable later from the transaction history
# (outlayer-coordinator/scripts/backfill_collateral_versions.py).
#
# Put the coordinator credentials in a `.env` NEXT TO THIS SCRIPT (gitignored):
#   COORDINATOR_URL_MAINNET=https://api.outlayer.ai
#   ADMIN_BEARER_TOKEN_MAINNET=...
#   COORDINATOR_URL_TESTNET=https://api-testnet.outlayer.ai
#   ADMIN_BEARER_TOKEN_TESTNET=...
# Missing values just skip the notification with a warning.
set -euo pipefail

COLLATERAL_FILE="${1:?usage: update_collateral.sh <collateral.json> <index: 0=Phala | 1=self-hosted> [network] [contract]}"
INDEX="${2:?need slot index: 0=Phala (20a06f000000), 1=self-hosted TDX (B0C06F000000)}"
NETWORK="${3:-testnet}"
if [ "$NETWORK" = "mainnet" ]; then SUFFIX="near"; else SUFFIX="testnet"; fi
CONTRACT="${4:-worker.outlayer.$SUFFIX}"
OWNER="owner.outlayer.$SUFFIX"

[ -f "$COLLATERAL_FILE" ] || { echo "collateral file not found: $COLLATERAL_FILE" >&2; exit 1; }

# Contract signature: update_collateral(collateral: String, index: u32)
# -> `collateral` is the QuoteCollateralV3 JSON passed AS A STRING; `index` is the slot.
#
# STRIP `pck_certificate_chain` — mandatory, do not "fix" this back.
# That field is the PCK certificate of the ONE machine whose quote generated the collateral (the
# `dcap-qvl verify` path sets it; Intel's/Phala's PCCS path does not). dcap-qvl 0.3.11 PREFERS it
# over the chain embedded in the quote under verification:
#     verify.rs / verify_pck_cert_chain: "Extract PCK certificate chain - prefer collateral,
#                                         fall back to quote"
# PCK certs are per-CPU, so leaving it in pins the whole FMSPC slot to a single physical node: any
# other node with the same FMSPC then fails registration with
#     "TDX quote verification failed (signature/TCB/collateral mismatch):
#      Signature is invalid for qe_report in quote"
# Phala's slot 0 has no such field — that is exactly why one Phala collateral serves every Phala
# worker. TDX quotes carry their own type-5 PCK chain, so dropping it loses nothing and is what
# makes a slot cover the whole fleet on that platform.
ARGS=$(jq -nc --arg c "$(jq -c 'del(.pck_certificate_chain)' "$COLLATERAL_FILE")" --argjson i "$INDEX" '{collateral: $c, index: $i}')

echo "update_collateral on $CONTRACT  slot=$INDEX  signer=$OWNER  network=$NETWORK"
near contract call-function as-transaction "$CONTRACT" update_collateral \
  json-args "$ARGS" \
  prepaid-gas '300.0 Tgas' \
  attached-deposit '0 NEAR' \
  sign-as "$OWNER" \
  network-config "$NETWORK" \
  sign-with-legacy-keychain \
  send

# --- tell the coordinator to archive this version -------------------------------------------
# Deliberately after `send` and deliberately non-fatal: the chain is already updated, so exiting
# non-zero here would report a failure that did not happen.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/.env" ]; then
  set -a; . "$SCRIPT_DIR/.env"; set +a
fi

if [ "$NETWORK" = "mainnet" ]; then
  COORDINATOR_URL="${COORDINATOR_URL_MAINNET:-}"
  ADMIN_TOKEN="${ADMIN_BEARER_TOKEN_MAINNET:-}"
else
  COORDINATOR_URL="${COORDINATOR_URL_TESTNET:-}"
  ADMIN_TOKEN="${ADMIN_BEARER_TOKEN_TESTNET:-}"
fi

if [ -z "$COORDINATOR_URL" ] || [ -z "$ADMIN_TOKEN" ]; then
  # `tr`, not ${VAR^^}: macOS ships bash 3.2, where that expansion is a syntax error.
  NET_UPPER=$(printf '%s' "$NETWORK" | tr '[:lower:]' '[:upper:]')
  echo "⚠️  Skipping coordinator capture: set COORDINATOR_URL_$NET_UPPER and ADMIN_BEARER_TOKEN_$NET_UPPER in $SCRIPT_DIR/.env" >&2
  echo "    (the new collateral is on chain; capture it later with POST /admin/collateral/check)" >&2
  exit 0
fi

echo
echo "capturing into coordinator history: $COORDINATOR_URL/admin/collateral/check"
RESPONSE=$(curl -sS -m 60 -X POST "$COORDINATOR_URL/admin/collateral/check" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -w '\n%{http_code}' 2>&1) || {
    echo "⚠️  Coordinator unreachable — collateral IS on chain, capture it later" >&2
    exit 0
  }

HTTP_CODE=$(printf '%s' "$RESPONSE" | tail -1)
BODY=$(printf '%s' "$RESPONSE" | sed '$d')

if [ "$HTTP_CODE" != "200" ]; then
  echo "⚠️  Coordinator returned HTTP $HTTP_CODE — collateral IS on chain, capture it later" >&2
  printf '%s\n' "$BODY" >&2
  exit 0
fi

# Show what was learned and how much runway each platform has left. `watched` marks the platforms
# whose expiry actually alerts (COLLATERAL_WATCH_FMSPC on the coordinator).
printf '%s' "$BODY" | jq -r '
  (.synced[]? | "  \(.contract_id): \(.new_versions | length) new version(s)"),
  (.failed[]?  | "  ⚠️  \(.)"),
  (.coverage[]? | "  \(.contract_id) \(.fmspc): \(.days_remaining) day(s) left\(if .watched then "" else "  (not watched)" end)")
' 2>/dev/null || printf '%s\n' "$BODY"
