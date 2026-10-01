#!/usr/bin/env bash
#
# Put the connector prices on chain, on TESTNET.
#
# These are the numbers `outlayer-coordinator/docs/TESTNET_RUNBOOK.md` checks
# against, and this script is their only home outside the chain: the coordinator
# keeps no price table of its own, so what is written here is what gets charged.
#
# Until this has run, every connector call is REFUSED — an unpriced project is
# not a free one. That is the safe direction, and it is also why this is not
# optional after a fresh deploy.
#
# Prerequisites, in order:
#   1. the contract is deployed and `migrate()` has run — `get_storage_version`
#      must answer "8", because `project_pricing` is a v8 field;
#   2. the project exists. `set_project_pricing` refuses a project nobody
#      registered: a price on an unregistered name would start applying the day
#      somebody else took that name.
#
# Usage:
#   CONTRACT=outlayer.testnet OWNER=you.testnet ./scripts/set_connector_prices_testnet.sh
#
set -euo pipefail

CONTRACT="${CONTRACT:?set CONTRACT to the testnet contract account}"
OWNER="${OWNER:?set OWNER to the contract owner account}"
NETWORK_ID="${NETWORK_ID:-testnet}"

# Every connector is deployed by us under this account. The project id is
# derived — `{namespace}/{id}` — so there is nothing to look up and no alias.
NAMESPACE="connectors.outlayer.testnet"

# Who is credited the author's share. NOT derivable from the project's owner,
# which is us: deriving it would pay us the author's cut and leave the author
# with nothing, with every total still adding up.
PROBE_AUTHOR="${PROBE_AUTHOR:-zavodil.testnet}"

near_call() {
  near call "$CONTRACT" "$1" "$2" --accountId "$OWNER" --networkId "$NETWORK_ID"
}

# ---------------------------------------------------------------------------
# connector-probe — the testnet stand-in, and the only connector that exercises
# the payout at all.
#
# Our own connectors sit at a zero share (there the author is us), so nothing we
# ship would otherwise run the split. The six operations below cover every price
# the table can hold (free, a cent, a cent and a half) against every share it
# can hold (none, a third, most, all) — including the combination that is the
# commonest in production and was the last one uncovered: PRICED with a ZERO
# share, which is every connector we own ourselves.
#
#   ping               free, share 0     — a share of nothing is nothing, and no
#                                          earnings row should appear at all
#   whoami             10000, share 0    — PRICED, and the whole of it ours.
#                                          This is the shape of every connector
#                                          WE own, and so the commonest case in
#                                          production; without a row like it,
#                                          nothing would exercise "the author is
#                                          us, keep all of it" against a fee that
#                                          actually exists
#   secret             10000, 70%        — 7000, the ordinary case
#   burn               10000, 33.33%     — 3333, and per OPERATION: a single
#                                          share per project would print 7000
#                                          here too and prove nothing
#   vrf                10000, share 0    — priced like `whoami`, because what it
#                                          proves is about the ALPHA and not
#                                          about money; a share would only add
#                                          noise to the earnings rows the refund
#                                          row below is read against
#   refund             10000, 70%        — a share that is NOT zero, deliberately.
#                                          The refund is subtracted from the
#                                          AUTHOR's earnings, so with a zero
#                                          share there would be nothing for it to
#                                          come out of and the ledger row could
#                                          not tell a working refund from a
#                                          dropped one
#   fetch              15000, 100%       — the whole fee to the author
#   sockets            0                 — raw TCP and DNS must be refused;
#                                          free, it moves nothing
#   trap / sleep       10000, 70%        — the run never completes: a trap and
#                                          a timeout must REFUND the fee and
#                                          pay the author nothing
#   fail               10000, 70%        — the module RAN and exited 1: what a
#                                          non-zero exit is billed as
#   forbidden_fetch    15000, 33.33%     — 4999.5 floored to 4999. The ONLY
#                                          combination on the probe that
#                                          produces a fraction, and the floor is
#                                          not decoration: the reporting sum
#                                          divides in NUMERIC, so without a
#                                          per-row floor it comes back
#                                          fractional, fails to parse as an
#                                          integer and reads as ZERO — the whole
#                                          of the authors' money reported as
#                                          ours
#   guess_start        10000, share 0    — a task is paid for when it is
#                                          prepared, as `whoami` is priced
#   guess and the five task operations
#                      0                 — the owner answers a task, and reads
#                                          and withdraws them, for nothing
#                                          (docs/TASKS.md)
#
# `unpriced` is deliberately ABSENT. An operation with no row must be refused
# before anything runs; the probe implements no such operation either, so if a
# call for it ever reaches the guest, the fail-closed lookup has a hole and the
# runbook says so.
#
# `forbidden_fetch` carries the rounding case on purpose: it RUNS — the guest's
# outbound request is refused inside the allowlist and it reports the error — so
# by the rule in CONNECTORS.md a module that ran and returned an error is
# charged and its author is paid. One row, two things checked.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# The price list below must name exactly the operations each probe's manifest
# declares. An operation priced here but absent from the manifest is dead
# money; one declared there but unpriced here is refused before it runs — and
# the probe would then "test" a refusal it never meant to. Checked BEFORE any
# price is written, from this file's own text against the manifests.
# ---------------------------------------------------------------------------
python3 - "$0" "$(dirname "$0")/../connectors" <<'PY'
import json, re, sys
script = open(sys.argv[1]).read()
examples = sys.argv[2]
drift = False
for probe in ("connector-probe", "subkey-probe"):
    block = re.search(r'"project_id": "\$NAMESPACE/%s".*?\n\s*\]' % re.escape(probe), script, re.S)
    if not block:
        print(f"ERROR: no pricing block for {probe} in this script"); sys.exit(1)
    priced = set(re.findall(r'\{"operation": "([a-z_]+)"', block.group(0)))
    declared = set(json.load(open(f"{examples}/{probe}/manifest.json"))["operations"])
    if priced != declared:
        drift = True
        print(f"ERROR: {probe}: priced {sorted(priced)} vs manifest {sorted(declared)}")
if drift:
    print("Fix the manifest or this script; the two must agree before prices go on chain.")
    sys.exit(1)
print("Manifest operations agree with the price list for both probes")
PY

near_call set_project_pricing "$(cat <<EOF
{
  "project_id": "$NAMESPACE/connector-probe",
  "pricing": {
    "author_account_id": "$PROBE_AUTHOR",
    "operations": [
      {"operation": "ping",            "price_usd": "0",     "developer_share_bp": 0},
      {"operation": "env",             "price_usd": "0",     "developer_share_bp": 0},
      {"operation": "whoami",          "price_usd": "10000", "developer_share_bp": 0},
      {"operation": "secret",          "price_usd": "10000", "developer_share_bp": 7000},
      {"operation": "author_secret",   "price_usd": "0",     "developer_share_bp": 0},
      {"operation": "burn",            "price_usd": "10000", "developer_share_bp": 3333},
      {"operation": "fetch",           "price_usd": "15000", "developer_share_bp": 10000},
      {"operation": "forbidden_fetch", "price_usd": "15000", "developer_share_bp": 3333},
      {"operation": "vrf",             "price_usd": "10000", "developer_share_bp": 0},
      {"operation": "refund",          "price_usd": "10000", "developer_share_bp": 7000},
      {"operation": "sockets",         "price_usd": "0",     "developer_share_bp": 0},
      {"operation": "trap",            "price_usd": "10000", "developer_share_bp": 7000},
      {"operation": "fail",            "price_usd": "10000", "developer_share_bp": 7000},
      {"operation": "sleep",           "price_usd": "10000", "developer_share_bp": 7000},
      {"operation": "budget",          "price_usd": "0",     "developer_share_bp": 0},
      {"operation": "guess_start",     "price_usd": "10000", "developer_share_bp": 0},
      {"operation": "guess",           "price_usd": "0",     "developer_share_bp": 0},
      {"operation": "task_status",     "price_usd": "0",     "developer_share_bp": 0},
      {"operation": "task_cancel",     "price_usd": "0",     "developer_share_bp": 0},
      {"operation": "task_delete",     "price_usd": "0",     "developer_share_bp": 0},
      {"operation": "tasks",           "price_usd": "0",     "developer_share_bp": 0},
      {"operation": "tasks_unlock",    "price_usd": "0",     "developer_share_bp": 0}
    ]
  }
}
EOF
)"

# ---------------------------------------------------------------------------
# subkey-probe — the wallet-importing connector: EVM sub-keys end to end.
#
# `address` and `foreign_label` are free (derivations and refusals, no
# signature); `sign` is priced so a paid signing operation is on the ledger.
# ---------------------------------------------------------------------------
near_call set_project_pricing "$(cat <<EOF
{
  "project_id": "$NAMESPACE/subkey-probe",
  "pricing": {
    "author_account_id": "$PROBE_AUTHOR",
    "operations": [
      {"operation": "address",       "price_usd": "0",     "developer_share_bp": 0},
      {"operation": "sign",          "price_usd": "10000", "developer_share_bp": 0},
      {"operation": "foreign_label", "price_usd": "0",     "developer_share_bp": 0}
    ]
  }
}
EOF
)"

# ---------------------------------------------------------------------------
# near-email is MAINNET-ONLY and is deliberately not priced here.
#
# Its addresses are derived from `.near` accounts, so nothing is deployed at
# `connectors.outlayer.testnet/near-email`; the registry says so too
# (`networks()` returns mainnet alone). Pricing a project that does not exist
# would be refused by the contract anyway — which is the check working, not a
# problem to route around.
#
# The mainnet equivalent, for when that deploy happens:
#
#   near call $CONTRACT set_project_pricing '{
#     "project_id": "connectors.outlayer.near/near-email",
#     "pricing": {
#       "author_account_id": "zavodil.near",
#       "operations": [
#         {"operation": "send",                 "price_usd": "10000", "developer_share_bp": 7000},
#         {"operation": "send_with_attachment", "price_usd": "15000", "developer_share_bp": 7000},
#         {"operation": "list",                 "price_usd": "0",     "developer_share_bp": 0},
#         {"operation": "read",                 "price_usd": "0",     "developer_share_bp": 0}
#       ]
#     }
#   }' --accountId $OWNER --networkId mainnet
# ---------------------------------------------------------------------------

echo
echo "Reading it back:"
near view "$CONTRACT" get_project_pricing \
  "{\"project_id\": \"$NAMESPACE/connector-probe\"}" --networkId "$NETWORK_ID"

# The DEAREST operation — what to budget for, not what to attach. The contract
# reads the `operation` field out of the request and requires exactly that
# operation's price, so a `ping` costs nothing and a `fetch` costs 15000.
echo
echo "The dearest operation, for budgeting (expect 15000):"
near view "$CONTRACT" get_project_max_price \
  "{\"project_id\": \"$NAMESPACE/connector-probe\"}" --networkId "$NETWORK_ID"

echo
echo "Done. Now tell the coordinator, or it bills the OLD prices for up to a"
echo "minute and refuses a newly priced connector entirely:"
echo
echo "  curl -X POST \$API/admin/connector-prices/refresh -H \"Authorization: Bearer \$ADMIN_TOKEN\""
