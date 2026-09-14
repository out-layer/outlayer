#!/usr/bin/env bash
#
# The lazy repair of a request left in `processing`.
#
# The window it closes: the coordinator broadcasts, then dies before it can
# write the outcome. The money has moved and the row still says `processing`
# — forever, because nothing else knows a transaction existed. `tx_hash` and
# `signer_id` are written BEFORE the send so a later read can ask the chain
# what happened; `GET /wallet/v1/requests/{id}` does the asking.
#
# Crashing a coordinator is not needed and would not be repeatable. The state
# under test is a row, so this script makes the row: it performs a real call,
# lets it finish, and then puts it back the way a crash would have left it —
# terminal transaction on chain, `processing` in the database, no charge
# recorded. Everything after that is the product's own behaviour.
#
# What each probe pins:
#   R1  a stuck row settles on read — terminal status, `settled_late: true`,
#       and the velocity counter grows. Both halves matter: settling without
#       charging hands the owner's daily ceiling back for money that moved
#   R2  it settles ONCE — a second read must not charge again. This is the
#       `usage_charged` flag, and nothing else tests it
#   R3  a transaction the chain never saw stays `processing` — this is what
#       separates "we died after sending" from "we died before". Without it
#       the repair would declare everything stuck to be finished
#   R4  the door keeps its per-promise detail through the repair —
#       `result.promises[]` with indexes and receivers, which is the G3
#       acceptance condition. SKIPPED without an active binding
#
# R1 is the one that has already been wrong: the repair used to read
# `request_data.args_base64`, a field that does not exist there, so the door's
# envelope never decoded and the charge came out empty. A unit test now pins
# the SOURCE (`op_canonical`), but it cannot see a renamed field inside it —
# only this run can.
#
# Requires: a way to run SQL against the coordinator's database — either
# $PGURL for a direct psql, or $PSQL_CMD when the database is not reachable
# from here (on the deployed environments it is not) — plus $PARENT with a
# keychain credential and ~0.3 NEAR, and `outlayer` logged in as $PARENT.
#
# R4 additionally needs a wallet with an ACTIVE binding, which this script
# cannot create: pass REUSE_SEED and BOUND_TO. Produce one with
#   PARENT=you.testnet KEEP=1 ./tests/binding_lifecycle_e2e.sh --apply
#
# Run (spends real testnet NEAR and writes to the coordinator's database):
#   PGURL=postgres://... PARENT=you.testnet ./tests/stuck_request_repair_e2e.sh --apply
#   PSQL_CMD=./tsql PARENT=you.testnet REUSE_SEED=binding-... BOUND_TO=... \
#     ./tests/stuck_request_repair_e2e.sh --apply

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPLY=false
[[ "${1:-}" == "--apply" ]] && APPLY=true

NETWORK="${NETWORK:-testnet}"
CONTRACT_ID="${CONTRACT_ID:-outlayer.testnet}"
COORDINATOR_URL="${COORDINATOR_URL:-https://testnet-api.outlayer.ai}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/rpc.sh"   # keyed RPC_URL, or a warning
WNEAR="${WNEAR:-wrap.testnet}"
PARENT="${PARENT:-}"
PGURL="${PGURL:-}"
# The RECIPIENT of the door transfer R4 repairs — someone else's account, not
# the bound account itself. Passing the bound account makes the contract panic
# with "self-calls are not allowed", which reads as a broken door and is only a
# misused parameter. Left empty, R4 says so and skips.
BOUND_TO="${BOUND_TO:-}"

# Run against an EXISTING wallet instead of minting one.
#
# R4 is the reason. It needs a wallet with an ACTIVE binding, and a binding is
# not something this script can produce — it takes an on-chain account with the
# wallet contract installed and a handshake (`binding_lifecycle_e2e.sh`). A
# freshly minted `stuckrep-*` wallet has no binding and never will inside one
# run, so R4 was unreachable for as long as this script insisted on its own
# wallet.
#
# The reused wallet is NOT swept at the end: it is somebody else's, it was here
# before this run and is expected to outlive it.
REUSE_SEED="${REUSE_SEED:-}"

# How to run ONE statement of SQL, when a direct `psql "$PGURL"` cannot reach
# the database. On the deployed environments it cannot: the coordinator's
# PostgreSQL is not exposed off its host, which is the reason this script's own
# doc calls PGURL an operator step. A command given here is invoked with the
# statement as its single argument.
PSQL_CMD="${PSQL_CMD:-}"

# The call R1 repairs: a storage registration on wNEAR. Real, cheap, idempotent
# and — the part that matters — it carries a non-zero deposit, which is exactly
# what an ordinary call owes the velocity counters.
CALL_DEPOSIT="1250000000000000000000"   # 0.00125 NEAR
FUND_NEAR="0.1"

PASS=0; FAILED=0; FAILED_NAMES=()
log()  { printf '\n\033[36m▶ %s\033[0m\n' "$*" >&2; }
note() { printf '\033[35m• %s\033[0m\n' "$*" >&2; }
warn() { printf '\033[33m⚠ %s\033[0m\n' "$*" >&2; }
pass() { printf '\033[32m✓ %s\033[0m\n' "$*" >&2; PASS=$((PASS+1)); }
fail() { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; FAILED=$((FAILED+1)); FAILED_NAMES+=("$*"); }

if [[ "$APPLY" != true ]]; then
  sed -n '3,48p' "$0" >&2
  echo "  Pass --apply to run." >&2
  exit 0
fi

[[ -n "$PARENT" ]] || { echo "USAGE: PGURL=... PARENT=you.testnet $0 --apply" >&2; exit 1; }
[[ -n "$PGURL" || -n "$PSQL_CMD" ]] \
  || { echo "✗ PGURL or PSQL_CMD is required — the stuck state can only be produced in the database" >&2; exit 1; }
TOOLS="jq curl near outlayer cargo"
[[ -z "$PSQL_CMD" ]] && TOOLS="$TOOLS psql"
for tool in $TOOLS; do
  command -v "$tool" >/dev/null || { echo "✗ missing $tool" >&2; exit 1; }
done
CREDS_DIR="$HOME/.near-credentials/$NETWORK"
[[ -f "$CREDS_DIR/$PARENT.json" ]] || { echo "✗ creds missing: $CREDS_DIR/$PARENT.json" >&2; exit 1; }
# Without this, `outlayer` follows ~/.outlayer/default-network — mainnet on this
# machine — and the check below compares against the wrong network's account.
export OUTLAYER_NETWORK="$NETWORK"
WHOAMI=$(outlayer whoami 2>/dev/null | awk -F': *' '/^Account:/{print $2; exit}')
[[ "$WHOAMI" == "$PARENT" ]] || { echo "✗ outlayer logged in as '$WHOAMI', not '$PARENT'" >&2; exit 1; }
PARENT_PRIVKEY=$(jq -r '.private_key' "$CREDS_DIR/$PARENT.json")

RECOVERY_BIN="$SCRIPT_DIR/../scripts/customer-recovery/target/release/customer-recovery"
log "Building customer-recovery (sign-bearer-near)"
(cd "$SCRIPT_DIR/../scripts/customer-recovery" && cargo build --release --quiet) \
  || { echo "✗ customer-recovery build failed" >&2; exit 1; }

sql() { if [[ -n "$PSQL_CMD" ]]; then $PSQL_CMD "$1"; else psql "$PGURL" -Atqc "$1"; fi; }
sql "SELECT 1" >/dev/null || { echo "✗ cannot reach the database at PGURL" >&2; exit 1; }

LEDGER="$(mktemp -t stuckrep_ledger.XXXXXX)"

near_tty() {
  if command -v script >/dev/null 2>&1 && [ -t 1 ]; then
    local tmp; tmp=$(mktemp -t stuckrep_cmd.XXXXXX.sh)
    printf 'set -euo pipefail\n%s\n' "$*" > "$tmp"
    script -q /dev/null bash "$tmp"; local rc=$?; rm -f "$tmp"; return $rc
  else eval "$@"; fi
}

mk_token() { "$RECOVERY_BIN" sign-bearer-near --private-key "$PARENT_PRIVKEY" --account-id "$PARENT" --seed "$1"; }
AUTH() { echo "Authorization: Bearer near:$(mk_token "$1")"; }

chain_balance() {
  curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg a "$1" '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"view_account",finality:"final",account_id:$a}}')" \
    2>/dev/null | jq -r 'if .result.amount then .result.amount else "0" end' 2>/dev/null || echo "0"
}

# Today's native total for the wallet, as the counters store it. The period key
# is built from UTC because `record_usage` builds it from `Utc::now()`; using
# local time would read an empty row for most of the day and call it "no
# charge".
usage_native() {
  local wid=$1 period="daily:$(date -u +%Y-%m-%d)" v
  v=$(sql "SELECT total_amount FROM wallet_usage WHERE wallet_id = '$wid' AND token = 'native' AND period = '$period'")
  echo "${v:-0}"
}

store_policy() {
  local seed=$1 wid=$2 pol=$3 body enc encb64 sg sig_hex pub_hex store_args
  body=$(jq -nc --arg wid "$wid" --argjson p "$pol" '$p + {wallet_id:$wid}')
  enc=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/encrypt-policy" \
    -H "$(AUTH "$seed")" -H 'Content-Type: application/json' -d "$body")
  encb64=$(echo "$enc" | jq -r '.encrypted_base64 // empty')
  [[ -n "$encb64" ]] || { warn "encrypt-policy failed: $(head -c 200 <<<"$enc")"; return 1; }
  sg=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/sign-policy" \
    -H "$(AUTH "$seed")" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg ed "$encb64" --arg c "$PARENT" '{encrypted_data:$ed, caller:$c}')")
  sig_hex=$(echo "$sg" | jq -r '.signature_hex // empty')
  pub_hex=$(echo "$sg" | jq -r '.public_key_hex // empty')
  [[ -n "$sig_hex" ]] || { warn "sign-policy failed: $(head -c 200 <<<"$sg")"; return 1; }
  store_args=$(jq -nc --arg pk "ed25519:$pub_hex" --arg ed "$encb64" --arg sg "$sig_hex" \
    '{wallet_pubkey:$pk, encrypted_data:$ed, wallet_signature:$sg}')
  near_tty "near contract call-function as-transaction $CONTRACT_ID store_wallet_policy \
    json-args '$store_args' prepaid-gas '100.0 Tgas' attached-deposit '0.1 NEAR' \
    sign-as $PARENT network-config $NETWORK sign-with-keychain send" >&2 || return 1
  sleep 5
}

cleanup() {
  local rc=$?
  [[ -s "$LEDGER" ]] || { rm -f "$LEDGER"; return $rc; }
  log "Sweeping sub-wallets back to $PARENT"
  local seed wid addr bal out
  while read -r seed wid addr; do
    [[ -n "${addr:-}" ]] || continue
    bal=$(chain_balance "$addr")
    if [[ "$bal" == "0" ]]; then note "sweep: $addr — nothing on chain"; continue; fi
    store_policy "$seed" "$wid" '{"rules":{"transaction_types":["delete"]}}' \
      || warn "sweep: $addr — sweep policy not stored; the delete below will likely 403"
    out=$(mktemp -t stuckrep_del.XXXXXX)
    curl -sS -o "$out" -w '%{http_code}' -X POST "$COORDINATOR_URL/wallet/v1/delete" \
      -H "$(AUTH "$seed")" -H 'Content-Type: application/json' \
      -d "$(jq -nc --arg b "$PARENT" '{beneficiary:$b, chain:"near"}')" >/dev/null
    note "sweep: $addr deleted → $PARENT ($(jq -r '.status // .error // "?"' "$out" 2>/dev/null))"
    rm -f "$out"
  done < "$LEDGER"
  rm -f "$LEDGER"
  return $rc
}
trap cleanup EXIT

# ── a funded wallet that may make calls ──────────────────────────────────────
if [[ -n "$REUSE_SEED" ]]; then
  log "Using the wallet behind REUSE_SEED"
  SEED="$REUSE_SEED"
  ADDR_RESP=$(curl -sS -G "$COORDINATOR_URL/wallet/v1/address" --data-urlencode "chain=near" -H "$(AUTH "$SEED")")
  WID=$(echo "$ADDR_RESP" | jq -r '.wallet_id // empty')
  ADDR=$(echo "$ADDR_RESP" | jq -r '.address // empty')
  [[ -n "$WID" && -n "$ADDR" ]] || { echo "✗ /address failed: $(head -c 200 <<<"$ADDR_RESP")" >&2; exit 1; }
  # Deliberately NOT added to $LEDGER — the sweep deletes the account it is
  # given, and this one is not ours to delete.
  BAL=$(chain_balance "$ADDR")
  [[ "$BAL" != "0" ]] || { echo "✗ $ADDR holds nothing on chain; fund it before reusing it" >&2; exit 1; }
  # The policy is REPLACED rather than assumed: whatever this wallet was doing
  # before, the calls below need `call`, and `delete` is left off precisely
  # because nothing here may delete a wallet somebody else is using.
  store_policy "$SEED" "$WID" '{"rules":{"transaction_types":["call"]}}' \
    || { echo "✗ policy not stored — every call below would be refused for the wrong reason" >&2; exit 1; }
  pass "reusing wallet $ADDR ($BAL yocto), permitted to call"
else
  log "Minting a funded sub-wallet"
  SEED="stuckrep-$(date +%s)-$$"
  ADDR_RESP=$(curl -sS -G "$COORDINATOR_URL/wallet/v1/address" --data-urlencode "chain=near" -H "$(AUTH "$SEED")")
  WID=$(echo "$ADDR_RESP" | jq -r '.wallet_id // empty')
  ADDR=$(echo "$ADDR_RESP" | jq -r '.address // empty')
  [[ -n "$WID" && -n "$ADDR" ]] || { echo "✗ /address failed: $(head -c 200 <<<"$ADDR_RESP")" >&2; exit 1; }
  printf '%s %s %s\n' "$SEED" "$WID" "$ADDR" >> "$LEDGER"

  BEFORE_FUND=$(chain_balance "$ADDR")
  # Output kept, result judged by the chain: near-cli-rs exits 0 on a swallowed
  # broadcast transient, and a funding step that never landed would surface much
  # later as a confusing refusal from the product.
  SEND_OUT=$(near_tty "near --quiet tokens $PARENT send-near $ADDR '$FUND_NEAR NEAR' \
    network-config $NETWORK sign-with-keychain send" 2>&1)
  AFTER_FUND=$(chain_balance "$ADDR")
  if [[ "$AFTER_FUND" == "$BEFORE_FUND" || "$AFTER_FUND" == "0" ]]; then
    echo "✗ funding did not land on $ADDR — the SENDER failed, not the coordinator" >&2
    tail -c 400 <<<"$SEND_OUT" >&2
    exit 1
  fi
  store_policy "$SEED" "$WID" '{"rules":{"transaction_types":["call","delete"]}}' \
    || { echo "✗ policy not stored — every call below would be refused for the wrong reason" >&2; exit 1; }
  pass "wallet $ADDR funded and permitted to call"
fi

# ── a real, finished call to put back into `processing` ──────────────────────
log "Making a real call that finishes normally"
CALL_BODY=$(jq -nc --arg t "$WNEAR" --arg a "$ADDR" --arg d "$CALL_DEPOSIT" \
  '{receiver_id:$t, method_name:"storage_deposit", args:{account_id:$a, registration_only:true},
    gas:"30000000000000", deposit:$d}')
CALL_RESP=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/call" \
  -H "$(AUTH "$SEED")" -H 'Content-Type: application/json' -d "$CALL_BODY")
REQ_ID=$(echo "$CALL_RESP" | jq -r '.request_id // empty')
[[ -n "$REQ_ID" ]] || { echo "✗ the call returned no request_id: $(head -c 300 <<<"$CALL_RESP")" >&2; exit 1; }
note "request $REQ_ID, status $(jq -r '.status // "?"' <<<"$CALL_RESP")"

ROW=$(sql "SELECT status || '|' || COALESCE(op_canonical, '') || '|' || COALESCE(result_data ->> 'tx_hash', '') FROM wallet_requests WHERE request_id = '$REQ_ID'")
# An empty answer means PGURL points at a database that does not hold this
# request — a different environment from $COORDINATOR_URL. Every probe below
# would then report a defect that is really a wiring mistake.
[[ -n "$ROW" ]] || { echo "✗ request $REQ_ID is not in the database at PGURL — is it the same environment as $COORDINATOR_URL?" >&2; exit 1; }
ROW_STATUS="${ROW%%|*}"
ROW_REST="${ROW#*|}"
ROW_OP="${ROW_REST%|*}"
ROW_TX="${ROW_REST##*|}"
[[ -n "$ROW_OP" ]] \
  && pass "the row carries op_canonical — the signed form the repair reads" \
  || fail "op_canonical is empty on this row; the repair has nothing to decode and this run cannot test it"
[[ -n "$ROW_TX" ]] \
  && pass "the row carries tx_hash, written before the broadcast ($ROW_TX)" \
  || fail "no tx_hash on the row — note_pending_broadcast did not run, and no repair is possible for a request like this"
note "final status in the database: $ROW_STATUS"

# ── R1: the repair settles and charges ───────────────────────────────────────
log "R1 put the row back to \`processing\` with no charge recorded, then read it"
USAGE_BEFORE=$(usage_native "$WID")
note "native usage today before the repair: $USAGE_BEFORE"

# Exactly the state a crash between the broadcast and the status write leaves:
# the transaction is on chain, the row is not finished, and nothing says the
# counters have seen it.
sql "UPDATE wallet_requests
     SET status = 'processing',
         result_data = (result_data - 'usage_charged' - 'settled_late' - 'promises' - 'failure')
     WHERE request_id = '$REQ_ID'" >/dev/null
[[ "$(sql "SELECT status FROM wallet_requests WHERE request_id = '$REQ_ID'")" == "processing" ]] \
  || { fail "R1 could not put the row back to processing — nothing below tests anything"; exit 1; }

R1=$(curl -sS "$COORDINATOR_URL/wallet/v1/requests/$REQ_ID" -H "$(AUTH "$SEED")")
R1_STATUS=$(jq -r '.status // empty' <<<"$R1")
R1_LATE=$(jq -r '.result.settled_late // false' <<<"$R1")
USAGE_AFTER=$(usage_native "$WID")

[[ "$R1_STATUS" != "processing" && -n "$R1_STATUS" ]] \
  && pass "R1 the read settled it to '$R1_STATUS' by asking the chain" \
  || fail "R1 the request is still '$R1_STATUS' — a transaction that reached the chain stays unresolved forever, and the owner is told nothing"
[[ "$R1_LATE" == "true" ]] \
  && pass "R1 settled_late marks it as repaired rather than as a normal completion" \
  || fail "R1 settled_late is '$R1_LATE' — the repair is invisible, so nobody can tell how often this happens"
if [[ "$USAGE_AFTER" != "$USAGE_BEFORE" ]]; then
  pass "R1 the velocity counter grew ($USAGE_BEFORE → $USAGE_AFTER)"
else
  fail "R1 the counter did not move — money left the wallet and the daily ceiling was handed back whole. This is the failure mode the repair exists to prevent, and it is silent"
fi

# ── R2: settled once, charged once ───────────────────────────────────────────
log "R2 read it a second time — the charge must NOT repeat"
curl -sS "$COORDINATOR_URL/wallet/v1/requests/$REQ_ID" -H "$(AUTH "$SEED")" >/dev/null
USAGE_TWICE=$(usage_native "$WID")
[[ "$USAGE_TWICE" == "$USAGE_AFTER" ]] \
  && pass "R2 the counter held at $USAGE_TWICE — usage_charged closed the second charge" \
  || fail "R2 the counter moved again ($USAGE_AFTER → $USAGE_TWICE) — every poll of a repaired request eats the owner's limit"

# ── R3: a transaction the chain never saw ────────────────────────────────────
log "R3 a stuck row whose transaction does not exist must STAY stuck"
sql "UPDATE wallet_requests
     SET status = 'processing',
         result_data = jsonb_set(result_data - 'usage_charged' - 'settled_late',
                                 '{tx_hash}', '\"11111111111111111111111111111111\"')
     WHERE request_id = '$REQ_ID'" >/dev/null
USAGE_R3_BEFORE=$(usage_native "$WID")
R3=$(curl -sS "$COORDINATOR_URL/wallet/v1/requests/$REQ_ID" -H "$(AUTH "$SEED")")
R3_STATUS=$(jq -r '.status // empty' <<<"$R3")
USAGE_R3_AFTER=$(usage_native "$WID")
[[ "$R3_STATUS" == "processing" ]] \
  && pass "R3 stayed processing — an unknown transaction is not evidence of anything" \
  || fail "R3 settled to '$R3_STATUS' on a transaction the chain has never seen; a request that died BEFORE its send would be reported as finished"
[[ "$USAGE_R3_AFTER" == "$USAGE_R3_BEFORE" ]] \
  && pass "R3 nothing was charged for it" \
  || fail "R3 charged $USAGE_R3_BEFORE → $USAGE_R3_AFTER for a transaction that does not exist"

# Leave the row honest, so a later reader does not find a lie planted here.
sql "UPDATE wallet_requests SET status = '$ROW_STATUS',
       result_data = jsonb_set(result_data, '{tx_hash}', to_jsonb('$ROW_TX'::text))
     WHERE request_id = '$REQ_ID'" >/dev/null

# ── R4: the door, per-promise ────────────────────────────────────────────────
log "R4 the same repair on an extension-door call keeps its per-promise detail"
if [[ -z "$BOUND_TO" ]]; then
  note "R4 SKIPPED — set BOUND_TO=<recipient> and run against a wallet with an ACTIVE binding."
  note "Nothing else in the queue checks that the repair decodes the ENVELOPE rather than the"
  note "outer 1-yocto marker, which is the half that was broken until 2026-08-20."
else
  D=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/binding/transfer" \
    -H "$(AUTH "$SEED")" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg to "$BOUND_TO" --arg a "$CALL_DEPOSIT" '{to:$to, amount:$a}')")
  DREQ=$(jq -r '.request_id // empty' <<<"$D")
  if grep -q 'self-calls are not allowed' <<<"$D"; then
    # Named separately from the generic failure below: the contract is behaving
    # exactly as designed, and reporting it as a broken door sends whoever reads
    # this run looking at the coordinator instead of at their own invocation.
    fail "R4 BOUND_TO is the bound account itself, so the door refused a self-call — pass someone else's account (see the note at the top of this file)"
  elif [[ -z "$DREQ" ]]; then
    fail "R4 the door call returned no request_id: $(head -c 300 <<<"$D")"
  else
    DUSAGE_BEFORE=$(usage_native "$WID")
    sql "UPDATE wallet_requests
         SET status = 'processing',
             result_data = (result_data - 'usage_charged' - 'settled_late' - 'promises' - 'failure')
         WHERE request_id = '$DREQ'" >/dev/null
    R4=$(curl -sS "$COORDINATOR_URL/wallet/v1/requests/$DREQ" -H "$(AUTH "$SEED")")
    NPROM=$(jq -r '.result.promises | length // 0' <<<"$R4" 2>/dev/null || echo 0)
    DUSAGE_AFTER=$(usage_native "$WID")
    [[ "${NPROM:-0}" -ge 1 ]] \
      && pass "R4 the repair rebuilt $NPROM promise result(s) with receivers — the G3 ladder survives a late settlement" \
      || fail "R4 no promises came back; the repair read the outer marker instead of the envelope, which is exactly the defect fixed on 2026-08-20"
    [[ "$DUSAGE_AFTER" != "$DUSAGE_BEFORE" ]] \
      && pass "R4 the door was charged by its contents ($DUSAGE_BEFORE → $DUSAGE_AFTER), not by its 1-yocto marker" \
      || fail "R4 nothing was charged — a door call repaired late is a free spend against the ceiling"
  fi
fi

printf '\n\033[1m%d passed, %d failed\033[0m\n' "$PASS" "$FAILED" >&2
for n in "${FAILED_NAMES[@]:-}"; do [[ -n "$n" ]] && printf '  \033[31m✗ %s\033[0m\n' "$n" >&2; done
[[ "$FAILED" -eq 0 ]]
