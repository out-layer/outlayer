#!/usr/bin/env bash
#
# Creates (or re-uses) the ONE live fixture the HoS suites share: a custody
# wallet bound `personal_account` to a fresh named account that runs the
# pinned no-sign wallet with our executor in its extension set.
#
# Made once and reused on purpose. Every suite below needs an ACTIVE binding
# and each one costs an account creation, a global-contract reference, two
# 1-yocto calls and ~40 s of chain waiting; rebuilding it per script would
# spend the run's time on setup and its rate-limit budget on nothing.
#
#   PARENT=you.testnet ./tests/hos_fixture.sh --apply
#   PARENT=you.testnet ./tests/hos_fixture.sh --destroy
#
# Writes its coordinates to $HOS_STATE (default tests/.hos_fixture.env).

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/hos_common.sh"

HOS_STATE="${HOS_STATE:-$REPO_ROOT/tests/.hos_fixture.env}"
MODE="${1:-}"
[[ "$MODE" == "--apply" || "$MODE" == "--destroy" ]] || {
  sed -n '3,16p' "$0" >&2; echo "  Pass --apply or --destroy." >&2; exit 0; }
hos_require

if [[ "$MODE" == "--destroy" ]]; then
  [[ -f "$HOS_STATE" ]] || { echo "no fixture at $HOS_STATE" >&2; exit 0; }
  # shellcheck disable=SC1090
  source "$HOS_STATE"
  api "$SEED" DELETE /wallet/v1/binding >/dev/null 2>&1 || true
  note "deleting $ASSET"
  delete_account "$ASSET"
  rm -f "$HOS_STATE"
  exit 0
fi

if [[ -f "$HOS_STATE" ]]; then
  # shellcheck disable=SC1090
  source "$HOS_STATE"
  api "$SEED" GET /wallet/v1/binding >/dev/null
  if [[ "$HTTP" == "200" && "$(jq -r '.binding_status' <<<"$BODY")" == "active" ]]; then
    note "re-using live fixture: wallet $WALLET_ID ↔ $ASSET (executor $EXECUTOR)"
    cat "$HOS_STATE"
    exit 0
  fi
  warn "recorded fixture is not active (HTTP $HTTP, $(jq -r '.binding_status // "-"' <<<"$BODY")) — building a new one"
  rm -f "$HOS_STATE"
fi

SEED="hos-fixture-$(date +%s)-$$"
log "Minting the custody wallet"
# The wallet routes carry ONE 100/min bucket per client address, and a full
# family run — or anything else arriving from the same address — leaves it
# spent for minutes. A fixture that dies on the first 429 has already created
# an account and spends the next one on nothing, so the two calls that build it
# wait the window out instead of failing the run.
# `wallet_address` runs in a process substitution, so the HTTP status and body
# it sets never reach this shell — it says what happened on stderr itself, and
# printing $BODY here would blame /address for some earlier call's answer.
for attempt in 1 2 3; do
  read -r WALLET_ID EXECUTOR < <(wallet_address "$SEED")
  [[ -n "$WALLET_ID" ]] && break
  [[ $attempt -lt 3 ]] || break
  warn "the mint did not answer with a wallet (its reason is above); waiting out the rate-limit window ($attempt/3)"
  sleep 70
done
[[ -n "$WALLET_ID" ]] || { echo "✗ /address never answered with a wallet — see the reason above" >&2; exit 1; }
note "wallet_id $WALLET_ID / executor $EXECUTOR"

ASSET="hos-$(openssl rand -hex 3).$PARENT"
log "Creating the asset account $ASSET"
create_subaccount "$ASSET" 0.6 || { echo "✗ $ASSET never appeared" >&2; exit 1; }

log "PUT the binding"
for attempt in 1 2 3; do
  api "$SEED" PUT /wallet/v1/binding "$(jq -nc --arg a "$ASSET" '{asset_account_id:$a, kind:"personal_account"}')" >/dev/null
  [[ "$HTTP" != "429" ]] && break
  [[ $attempt -lt 3 ]] || break
  warn "the binding PUT was rate limited; waiting out the window ($attempt/3)"
  sleep 70
done
[[ "$HTTP" == "200" ]] || { echo "✗ PUT failed $HTTP: $BODY" >&2; exit 1; }

log "Installing the wallet contract + executor extension"
install_wallet "$ASSET" "$EXECUTOR" || { echo "✗ setup transaction did not land" >&2; exit 1; }

log "Waiting for the binding to go active"
STATUS=""
for _ in 1 2 3 4 5 6 7 8; do
  api "$SEED" GET /wallet/v1/binding >/dev/null
  STATUS=$(jq -r '.binding_status // ""' <<<"$BODY")
  [[ "$STATUS" == "active" ]] && break
  sleep 3
done
[[ "$STATUS" == "active" ]] || { echo "✗ binding never went active (last '$STATUS')" >&2; exit 1; }

GAS_LOW=$(jq -r '.gas_balance_low // false' <<<"$BODY")
if [[ "$GAS_LOW" == "true" ]]; then
  note "topping the executor up so the lane can pay for gas"
  fund_account "$EXECUTOR" 0.3 || warn "top-up did not land"
fi
# The asset account pays for what the lane SPENDS; keep a working float there.
fund_account "$ASSET" 1.0 || warn "asset funding did not land"

cat > "$HOS_STATE" <<EOF
SEED=$SEED
WALLET_ID=$WALLET_ID
EXECUTOR=$EXECUTOR
ASSET=$ASSET
PARENT=$PARENT
EOF
pass "fixture ready"
cat "$HOS_STATE"
