#!/usr/bin/env bash
#
# `use_bound_identity` over the ON-CHAIN door.
#
# The HTTPS half of this is covered elsewhere. This one exists because the two
# doors are the whole point: one agent's WASI module has to answer the same
# thing about who it is whether it was started by an HTTPS call or by a
# transaction, and until the flag existed on `request_execution` it could not.
#
# WHO SIGNS, AND WHY IT IS NOT THE OBVIOUS ACCOUNT. An earlier version of this
# script signed `request_execution` from $PARENT's keychain and never passed a
# single probe. The coordinator matches the binding by `executor_account_id`
# against the CALLER of the transaction (`handlers/tasks.rs`), and the executor
# is the custody wallet's implicit account — whose key lives inside the enclave
# and cannot be signed with locally at all. So the transaction has to be sent BY
# the wallet, through `POST /wallet/v1/call`. That is not a workaround: it is the
# only way an agent sends this transaction in production either.
#
# What each probe pins:
#   B0  baseline — no flag, on-chain: the guest acts as the CALLER
#   B1  flag on, active binding: the guest's sender becomes the bound account
#   B2  billing does NOT follow — the payer stays the executor that paid
#   B3  same answer as the HTTPS door for the same wallet (the reason the flag
#       was added at all)
#   B4  flag on with NO binding → REFUSED, not quietly run under the caller's
#       own name
#   B5  the flag is not a way to borrow a name — see the note at B5
#   B6  the EARNINGS row names the payer, not the account the guest borrowed
#   B7  R8 — one run followed from its transaction hash to the enclave's quote
#
# Requires: an ACTIVE personal_account binding. Produce one with
#   PARENT=you.testnet KEEP=1 ./tests/binding_lifecycle_e2e.sh --apply
# and pass the BINDING_SEED and ASSET it prints.
#
# WHAT IT JUDGES BY. Not the HTTP answer to the send — `request_execution`
# yields, and a transaction that lands can still be reported to the client as a
# timeout. The subject is the row the coordinator writes when it sees the event.
#
# Run (spends testnet NEAR and priced calls):
#   PARENT=you.testnet BINDING_SEED=binding-... ASSET=bind-....testnet \
#     PSQL_CMD=./tsql ./tests/bound_identity_onchain_e2e.sh --apply

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPLY=false
[[ "${1:-}" == "--apply" ]] && APPLY=true

NETWORK="${NETWORK:-testnet}"
COORDINATOR_URL="${COORDINATOR_URL:-https://testnet-api.outlayer.ai}"
CONTRACT_ID="${CONTRACT_ID:-outlayer.testnet}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/rpc.sh"   # keyed RPC_URL, or a warning
PROJECT="${PROJECT:-connectors.outlayer.testnet/connector-probe}"
TOKEN_CONTRACT="${TOKEN_CONTRACT:-usdc.fakes.testnet}"
PARENT="${PARENT:-}"
BINDING_SEED="${BINDING_SEED:-}"
ASSET="${ASSET:-}"
API_KEY="${API_KEY:-}"          # a payment key, for the HTTPS half (B3)

# One statement of SQL, tuple-only. The coordinator's database is not exposed
# off its host, so this is a command the operator supplies (see `tsql`).
# Without it B1/B2 fall back to the guest's own answer, which is weaker: it
# cannot separate "the flag was applied" from "the probe reported oddly".
PSQL_CMD="${PSQL_CMD:-}"

# What one probe run costs, in stablecoin minimal units, and what the executor
# needs inside the contract before it can pay for any of them.
ATTACHED_USD="${ATTACHED_USD:-10000}"
DEPOSIT_USDC="${DEPOSIT_USDC:-1.0}"
# A `request_execution` at 300 Tgas is quoted by the door at 0.3 NEAR, and the
# wallet is refused outright below that — so the floor is the price of a call
# plus room for the several this script makes, not the "is it alive" figure the
# binding endpoint reports.
GAS_FLOOR="900000000000000000000000"    # 0.9 NEAR
EXECUTOR_TOPUP="1.0"

PASS=0; FAILED=0; FAILED_NAMES=()
log()  { printf '\n\033[36m▶ %s\033[0m\n' "$*" >&2; }
note() { printf '\033[35m• %s\033[0m\n' "$*" >&2; }
warn() { printf '\033[33m⚠ %s\033[0m\n' "$*" >&2; }
pass() { printf '\033[32m✓ %s\033[0m\n' "$*" >&2; PASS=$((PASS+1)); }
fail() { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; FAILED=$((FAILED+1)); FAILED_NAMES+=("$*"); }

if [[ "$APPLY" != true ]]; then
  sed -n '3,41p' "$0" >&2
  echo "  Pass --apply to run." >&2
  exit 0
fi

for v in PARENT BINDING_SEED ASSET; do
  [[ -n "${!v}" ]] || { echo "$v=<value> is required" >&2; exit 1; }
done
for tool in jq curl near outlayer cargo; do
  command -v "$tool" >/dev/null || { echo "✗ missing $tool" >&2; exit 1; }
done
CREDS_DIR="$HOME/.near-credentials/$NETWORK"
[[ -f "$CREDS_DIR/$PARENT.json" ]] || { echo "✗ creds missing: $CREDS_DIR/$PARENT.json" >&2; exit 1; }
# Without this, `outlayer` follows ~/.outlayer/default-network — mainnet on this
# machine — and every check below would run against the wrong network.
export OUTLAYER_NETWORK="$NETWORK"
PARENT_PRIVKEY=$(jq -r '.private_key' "$CREDS_DIR/$PARENT.json")

RECOVERY_BIN="$SCRIPT_DIR/../scripts/customer-recovery/target/release/customer-recovery"
log "Building customer-recovery (sign-bearer-near)"
(cd "$SCRIPT_DIR/../scripts/customer-recovery" && cargo build --release --quiet) \
  || { echo "✗ customer-recovery build failed" >&2; exit 1; }

AUTH() { # AUTH <seed>
  echo "Authorization: Bearer near:$("$RECOVERY_BIN" sign-bearer-near \
    --private-key "$PARENT_PRIVKEY" --account-id "$PARENT" --seed "$1")"
}

sql() { [[ -n "$PSQL_CMD" ]] && $PSQL_CMD "$1"; }

view() { # view <contract> <method> <json-args>
  curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg a "$1" --arg m "$2" --arg g "$(printf '%s' "$3" | base64)" \
        '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"call_function",
          finality:"final",account_id:$a,method_name:$m,args_base64:$g}}')" \
    | jq -r 'if .result.result then (.result.result | implode) else "" end' 2>/dev/null
}

chain_balance() {
  curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg a "$1" '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"view_account",finality:"final",account_id:$a}}')" \
    | jq -r '.result.amount // "0"' 2>/dev/null || echo 0
}

# ── the wallet under test ────────────────────────────────────────────────────
log "Reading the binding"
B=$(curl -sS "$COORDINATOR_URL/wallet/v1/binding" -H "$(AUTH "$BINDING_SEED")")
EXECUTOR=$(jq -r '.executor_account_id // empty' <<<"$B")
BSTATUS=$(jq -r '.binding_status // empty' <<<"$B")
BASSET=$(jq -r '.asset_account_id // empty' <<<"$B")
WALLET_ID=$(jq -r '.wallet_id // empty' <<<"$B")
[[ "$BSTATUS" == "active" ]] || { echo "✗ the binding is '$BSTATUS', not active: $(head -c 300 <<<"$B")" >&2; exit 1; }
[[ "$BASSET" == "$ASSET" ]] || { echo "✗ the binding names '$BASSET', not the ASSET '$ASSET' you passed" >&2; exit 1; }
note "wallet $WALLET_ID, executor $EXECUTOR, bound to $ASSET"

# ── the wallet must be allowed to make calls at all ──────────────────────────
store_policy() { # store_policy <seed> <wallet_id> <policy-json>
  local seed=$1 wid=$2 pol=$3 body enc encb64 sg sig_hex pub_hex store_args
  body=$(jq -nc --arg wid "$wid" --argjson p "$pol" '$p + {wallet_id:$wid}')
  enc=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/encrypt-policy" \
    -H "$(AUTH "$seed")" -H 'Content-Type: application/json' -d "$body")
  encb64=$(jq -r '.encrypted_base64 // empty' <<<"$enc")
  [[ -n "$encb64" ]] || { warn "encrypt-policy failed: $(head -c 200 <<<"$enc")"; return 1; }
  sg=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/sign-policy" \
    -H "$(AUTH "$seed")" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg ed "$encb64" --arg c "$PARENT" '{encrypted_data:$ed, caller:$c}')")
  sig_hex=$(jq -r '.signature_hex // empty' <<<"$sg")
  pub_hex=$(jq -r '.public_key_hex // empty' <<<"$sg")
  [[ -n "$sig_hex" ]] || { warn "sign-policy failed: $(head -c 200 <<<"$sg")"; return 1; }
  store_args=$(jq -nc --arg pk "ed25519:$pub_hex" --arg ed "$encb64" --arg sg "$sig_hex" \
    '{wallet_pubkey:$pk, encrypted_data:$ed, wallet_signature:$sg}')
  near --quiet contract call-function as-transaction "$CONTRACT_ID" store_wallet_policy \
    json-args "$store_args" prepaid-gas '100.0 Tgas' attached-deposit '0.1 NEAR' \
    sign-as "$PARENT" network-config "$NETWORK" sign-with-keychain send >/dev/null 2>&1 || return 1
  sleep 5
}

log "Storing a policy that permits calls"
store_policy "$BINDING_SEED" "$WALLET_ID" '{"rules":{"transaction_types":["call"]}}' \
  || { echo "✗ policy not stored — every request_execution below would be refused for the wrong reason" >&2; exit 1; }
pass "the bound wallet may make calls"

# ── the executor must be able to pay, in two different currencies ────────────
#
# Gas is NEAR on the executor's own account. `attached_usd` is stablecoin held
# INSIDE the contract, and `handle_deposit_balance` credits only the SENDER —
# there is no `owner` parameter — so the executor has to make that transfer
# itself. Both were done by hand the first time this ran, which is why neither
# was reproducible; they are setup now.

# Yocto does not fit in a shell integer, and `[[ a < b ]]` on numbers of
# different lengths compares the wrong thing: "2…" sorts before "5…", so
# 0.2 NEAR would read as less than 0.05 NEAR and this would top up forever.
below() { # below <a> <b> — true when a < b, both non-negative decimal integers
  local a=$1 b=$2
  (( ${#a} != ${#b} )) && { (( ${#a} < ${#b} )); return; }
  [[ "$a" < "$b" ]]
}

in_contract_usd() { view "$CONTRACT_ID" get_user_stablecoin_balance \
  "$(jq -nc --arg a "$1" '{account_id:$a}')" | tr -d '"'; }

# Make a custody wallet able to run `request_execution` at all. THREE separate
# purses, and missing any one of them fails in a way that looks like the test's
# subject rather than its setup:
#
#   * NEAR on the executor's own account — the door refuses a poor wallet before
#     it reads anything else;
#   * a NEAR deposit attached to the call — `execution.rs` charges compute in
#     NEAR and panics "Insufficient payment" at zero;
#   * stablecoin held INSIDE the contract — `attached_usd` is paid from there,
#     and `handle_deposit_balance` credits only the SENDER, so the wallet has to
#     make that transfer itself rather than have $PARENT make it for them.
#
# All three were done by hand the first time this ran, which is exactly why none
# of it was reproducible.
fund_wallet() { # fund_wallet <seed> <address> <label>
  local seed=$1 addr=$2 label=$3 gas usd dec amt dep
  gas=$(chain_balance "$addr")
  if [[ "$gas" == "0" ]] || below "$gas" "$GAS_FLOOR"; then
    near --quiet tokens "$PARENT" send-near "$addr" "$EXECUTOR_TOPUP NEAR" \
      network-config "$NETWORK" sign-with-keychain send >/dev/null 2>&1 || warn "$label gas top-up did not land"
    gas=$(chain_balance "$addr")
  fi
  note "$label gas: $gas yocto"

  usd=$(in_contract_usd "$addr")
  if [[ "${usd:-0}" -lt $(( ATTACHED_USD * 4 )) ]]; then
    note "$label in-contract balance is ${usd:-0}; depositing $DEPOSIT_USDC"
    dec=$(view "$TOKEN_CONTRACT" ft_metadata '{}' | jq -r '.decimals // 6')
    amt=$(python3 -c "print(int(float('$DEPOSIT_USDC') * 10**$dec))")
    near --quiet contract call-function as-transaction "$TOKEN_CONTRACT" storage_deposit \
      json-args "$(jq -nc --arg a "$addr" '{account_id:$a, registration_only:true}')" \
      prepaid-gas '30.0 Tgas' attached-deposit '0.00125 NEAR' \
      sign-as "$PARENT" network-config "$NETWORK" sign-with-keychain send >/dev/null 2>&1
    near --quiet contract call-function as-transaction "$TOKEN_CONTRACT" ft_transfer \
      json-args "$(jq -nc --arg a "$addr" --arg m "$amt" '{receiver_id:$a, amount:$m}')" \
      prepaid-gas '30.0 Tgas' attached-deposit '1 yoctoNEAR' \
      sign-as "$PARENT" network-config "$NETWORK" sign-with-keychain send >/dev/null 2>&1
    dep=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/call" \
      -H "$(AUTH "$seed")" -H 'Content-Type: application/json' \
      -d "$(jq -nc --arg t "$TOKEN_CONTRACT" --arg c "$CONTRACT_ID" --arg m "$amt" \
          '{receiver_id:$t, method_name:"ft_transfer_call",
            args:{receiver_id:$c, amount:$m, msg:"{\"action\":\"deposit_balance\"}"},
            gas:"100000000000000", deposit:"1"}')")
    note "$label deposit_balance: $(jq -r '.status // .error // "?"' <<<"$dep")"
    sleep 6
    usd=$(in_contract_usd "$addr")
  fi
  [[ "${usd:-0}" -ge "$ATTACHED_USD" ]] || {
    fail "$label holds ${usd:-0} inside the contract and one run costs $ATTACHED_USD — every probe below would fail as 'Insufficient stablecoin balance', which is this setup's fault and not the product's"
    return 1
  }
  note "$label can pay for a run (${usd} in contract)"
}

log "Funding the executor"
fund_wallet "$BINDING_SEED" "$EXECUTOR" "executor" \
  || { echo "✗ the executor could not be funded; nothing below would test anything" >&2; exit 1; }
pass "the executor can pay for a run"

# ── one on-chain request_execution, signed BY the wallet ─────────────────────
#
# The output is kept and the status checked: a send that never landed would
# otherwise report itself as "the identity did not change", which is a whole
# evening spent on the wrong component (see C2 in connector_pricing_e2e.sh,
# seen live 2026-08-18).
LAST_REQ=""; SEND_ERR=""
onchain_whoami() { # onchain_whoami <seed> <use_bound_identity true|false>
  local seed="$1" flag="$2" args body
  args=$(jq -nc --arg p "$PROJECT" --argjson f "$flag" --arg u "$ATTACHED_USD" \
    '{source:{Project:{project_id:$p}},
      input_data:"{\"operation\":\"whoami\"}",
      resource_limits:{max_instructions:1000000000,max_memory_mb:128,max_execution_seconds:30},
      params:{attached_usd:$u, use_bound_identity:$f}}')
  # The deposit is NOT optional and is not the `attached_usd` above: the
  # contract charges compute in NEAR out of what is attached, and refuses at
  # zero. 0.1 covers a run of this size with change; the remainder is refunded.
  body=$(jq -nc --arg c "$CONTRACT_ID" --argjson a "$args" \
    '{receiver_id:$c, method_name:"request_execution", args:$a,
      gas:"300000000000000", deposit:"100000000000000000000000"}')
  OUT=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/call" \
    -H "$(AUTH "$seed")" -H 'Content-Type: application/json' -d "$body" 2>&1)
  LAST_REQ=$(jq -r '.request_id // empty' <<<"$OUT" 2>/dev/null)
  SEND_ERR=$(jq -r '.error // ""' <<<"$OUT" 2>/dev/null)
}

# The GUEST's own answer, when the send waited long enough to carry it back.
#
# `request_execution` returns the module's output inline in the transaction
# outcome, so this is the module speaking rather than a record of what the
# coordinator decided — the strongest form of the question the flag is about,
# because it is what an agent's code would actually read. Empty when the send
# timed out, and the database row is then the fallback.
guest_answer() { # guest_answer <field>
  jq -r --arg f "$1" '(.result // "") | select(. != "") | fromjson | .[$f] // ""' \
    <<<"$OUT" 2>/dev/null
}

# WHAT THIS SCRIPT JUDGES BY, and why it is not the HTTP answer.
#
# `request_execution` yields, so the transaction takes far longer to reach a
# final outcome than an RPC read waits for. Two sends in a row were reported to
# the client as a timeout and a reset connection — and BOTH had landed and
# queued a run. Judging by the send's reply would have called the product broken
# for a transaction it executed correctly.
#
# So the subject is the row the coordinator writes when it sees the event. It
# appears whatever the client was told, and it holds the two identities the flag
# is about. `since` keeps a slow row from being confused with the previous
# probe's.
# Marked by TIME, not by the highest id. `request_id` is not one sequence: rows
# from the chain are numbered in one space and rows from elsewhere in another,
# and the largest id in the table belongs to the other one. A watermark taken
# from it sits above every row this script will create, so nothing ever matches
# — which reads exactly like "the transaction never landed".
# `AT TIME ZONE 'utc'` because `created_at` is a bare timestamp: comparing it
# against a value that carries an offset makes the answer depend on the
# server's timezone setting.
watermark() { sql "SELECT (now() AT TIME ZONE 'utc')"; }

identity_of() { # identity_of <account> <since-timestamp>
  local acct=$1 since=$2 row=""
  for _ in $(seq 1 20); do
    row=$(sql "SELECT request_id || '|' || COALESCE(context_sender_id,'') || '|' \
                   || COALESCE(user_account_id,'') || '|' || COALESCE(binding_kind,'')
                 FROM execution_requests
                WHERE created_at > '$since'
                  AND (user_account_id = '$acct' OR context_sender_id = '$acct')
                ORDER BY created_at DESC LIMIT 1")
    [[ -n "$row" ]] && { echo "$row"; return 0; }
    sleep 3
  done
  return 1
}

if [[ -z "$PSQL_CMD" ]]; then
  warn "PSQL_CMD is not set — B1/B2 cannot separate the two identities and will be SKIPPED."
  warn "Pass a command that runs one statement of SQL against the coordinator's database."
fi

# ── B0: baseline, no flag ────────────────────────────────────────────────────
log "B0 on-chain WITHOUT the flag — the guest acts as the caller"
MARK=$(watermark)
onchain_whoami "$BINDING_SEED" false
note "send answered: ${SEND_ERR:-ok}${LAST_REQ:+ (wallet request $LAST_REQ)}"
G_SENDER=$(guest_answer sender_id)
if [[ -n "$G_SENDER" ]]; then
  [[ "$G_SENDER" == "$EXECUTOR" ]] \
    && pass "B0 the guest says it is the caller ($G_SENDER), as before the flag existed" \
    || fail "B0 the guest says it is '$G_SENDER', expected the caller '$EXECUTOR' — the default must not rename anyone"
  [[ "$(guest_answer execution_type)" == "NEAR" ]] \
    && pass "B0 the run came through the on-chain door" \
    || fail "B0 execution_type is '$(guest_answer execution_type)', expected NEAR"
elif ROW=$(identity_of "$EXECUTOR" "$MARK"); then
  REQ="${ROW%%|*}"; REST="${ROW#*|}"; SENDER="${REST%%|*}"; REST="${REST#*|}"; KIND="${REST##*|}"
  warn "B0 the send carried no answer back; judging by the coordinator's row $REQ instead"
  [[ "$SENDER" == "$EXECUTOR" ]] \
    && pass "B0 the request names the caller ($SENDER)" \
    || fail "B0 sender is '$SENDER', expected the caller '$EXECUTOR' — the default must not rename anyone"
  [[ -z "$KIND" ]] \
    && pass "B0 no binding_kind recorded — nothing was substituted" \
    || fail "B0 binding_kind is '$KIND' on a request that never asked for a binding"
else
  fail "B0 nothing reached the chain — the send answered '${SEND_ERR:-nothing}': $(head -c 200 <<<"$OUT")"
fi

# ── B1 + B2: the flag renames the guest, and only the guest ──────────────────
log "B1/B2 on-chain WITH the flag — sender becomes the bound account, payer does not"
MARK=$(watermark)
onchain_whoami "$BINDING_SEED" true
note "send answered: ${SEND_ERR:-ok}${LAST_REQ:+ (wallet request $LAST_REQ)}"
G_SENDER=$(guest_answer sender_id)
G_PAYER=$(guest_answer user_account_id)
if [[ -n "$G_SENDER" ]]; then
  [[ "$G_SENDER" == "$ASSET" ]] \
    && pass "B1 the guest says it is the bound account ($G_SENDER)" \
    || fail "B1 the guest says it is '$G_SENDER', expected the bound account '$ASSET' — the flag did not survive the trip from the chain to the guest"
  # The half that would be invisible if it broke: usage would silently move to
  # an account that never paid.
  [[ "$G_PAYER" == "$EXECUTOR" ]] \
    && pass "B2 the payer stayed the caller ($G_PAYER)" \
    || fail "B2 the payer is '$G_PAYER', expected '$EXECUTOR' — billing must NOT follow a binding"
  [[ -n "$G_PAYER" && "$G_SENDER" != "$G_PAYER" ]] \
    && pass "B2 the two identities are DIFFERENT, which is the only state in which this test proves anything" \
    || fail "B2 both identities read '$G_SENDER'; an assertion that cannot tell them apart proves nothing"
elif ROW=$(identity_of "$EXECUTOR" "$MARK"); then
  REQ="${ROW%%|*}"; REST="${ROW#*|}"
  SENDER="${REST%%|*}"; REST="${REST#*|}"; PAYER="${REST%|*}"; KIND="${REST##*|}"
  warn "B1 the send carried no answer back; judging by the coordinator's row $REQ instead"
  [[ "$SENDER" == "$ASSET" ]] \
    && pass "B1 the request names the bound account ($SENDER)" \
    || fail "B1 sender is '$SENDER', expected the bound account '$ASSET' — the flag did not survive the trip from the chain to the coordinator"
  [[ "$PAYER" == "$EXECUTOR" ]] \
    && pass "B2 the payer stayed the caller ($PAYER)" \
    || fail "B2 the payer is '$PAYER', expected '$EXECUTOR' — billing must NOT follow a binding"
  [[ "$SENDER" != "$PAYER" ]] \
    && pass "B2 the two identities are DIFFERENT, which is the only state in which this test proves anything" \
    || fail "B2 both identities are '$SENDER'; an assertion that cannot tell them apart proves nothing"
  [[ "$KIND" == "personal_account" ]] \
    && pass "B1 the row records which kind of binding was used ($KIND)" \
    || fail "B1 binding_kind is '$KIND', expected personal_account"
else
  fail "B1 nothing reached the chain — the send answered '${SEND_ERR:-nothing}': $(head -c 200 <<<"$OUT")"
fi

# ── B6: the LEDGER names the payer, never the borrowed account ───────────────
#
# B2 above asked the request row who paid. This asks the money.
#
# They are different questions with different answers available: the request
# carries both identities, and `earnings_history` carries ONE — the column an
# invoice, a developer's earnings page and every revenue total are built from.
# Filling it from the guest's name would credit this call to an account that
# attached nothing and fold every caller sharing one bound account into a single
# payer, and none of it would look wrong on the page.
#
# The coordinator has a named function for the choice (`earnings_caller`) and
# unit tests over it. This is the same rule asked of the running system, where
# the two columns are populated by a different path than the one the unit test
# hands them.
log "B6 the earnings row for the bound run"
if [[ -z "$PSQL_CMD" ]]; then
  warn "B6 SKIPPED — needs PSQL_CMD"
elif ! BROW=$(identity_of "$EXECUTOR" "$MARK"); then
  fail "B6 the bound request never appeared in the coordinator's rows, so there is no run to follow the money for"
else
  B_REQ="${BROW%%|*}"
  # `attached_usd` is what buys a row at all: nothing is owed on a free call and
  # nothing is written, so an absence here would otherwise read as a defect when
  # it is a run that cost nobody anything.
  B_ATT=$(sql "SELECT COALESCE(attached_usd,'0') FROM execution_requests WHERE request_id = $B_REQ")
  if [[ "${B_ATT:-0}" == "0" || -z "$B_ATT" ]]; then
    warn "B6 SKIPPED — request $B_REQ attached nothing, so no developer was owed anything and no earnings row exists to attribute"
  else
    EROW=""
    for _ in $(seq 1 15); do
      EROW=$(sql "SELECT COALESCE(caller,'NULL') || '|' || source || '|' || COALESCE(tx_hash,'') \
                    FROM earnings_history WHERE request_id = $B_REQ ORDER BY id DESC LIMIT 1")
      [[ -n "$EROW" ]] && break; sleep 4
    done
    if [[ -z "$EROW" ]]; then
      fail "B6 request $B_REQ attached $B_ATT and left no earnings_history row — money was taken and the ledger does not say who from"
    else
      E_CALLER="${EROW%%|*}"; REST="${EROW#*|}"; E_SOURCE="${REST%%|*}"; E_TX="${REST##*|}"
      note "earnings: caller=$E_CALLER source=$E_SOURCE tx=$E_TX"
      [[ "$E_CALLER" == "$EXECUTOR" ]] \
        && pass "B6 the ledger names the PAYER ($E_CALLER)" \
        || fail "B6 the ledger names '$E_CALLER', expected the account that paid, '$EXECUTOR'"
      # Stated separately and on purpose: the assertion above already fails when
      # the borrowed name is used, but it fails the same way for a typo, and the
      # two want different reading. This one can only mean one thing.
      [[ "$E_CALLER" != "$ASSET" ]] \
        && pass "B6 and it is NOT the borrowed account ($ASSET) — a bound run bills the wallet that ran it" \
        || fail "B6 the ledger credits this call against '$ASSET', which attached nothing: usage is being attributed to the name the guest was allowed to borrow"
      [[ "$E_SOURCE" == "blockchain" ]] \
        && pass "B6 recorded as a blockchain earning, which is where the balance lives on this door" \
        || fail "B6 source is '$E_SOURCE', expected blockchain for an on-chain request"
    fi
  fi
fi

# ── B7: R8 — one operation, followed from a hash to the enclave that ran it ──
#
# What a client holds after `request_execution` is a transaction hash. Nothing
# else: not the request id the contract assigned, not the coordinator's job, not
# the worker. So the walk starts there and every rung has to be reachable from
# the one above, or an operation cannot be asked questions about after it has
# happened — which is the whole of R8 in the acceptance list.
log "B7 following the bound run from its transaction to its attestation"
if [[ -z "$PSQL_CMD" ]]; then
  warn "B7 SKIPPED — needs PSQL_CMD"
elif [[ -z "${B_REQ:-}" ]]; then
  warn "B7 SKIPPED — B6 never established which request to follow"
else
  TXH=$(sql "SELECT COALESCE(context_transaction_hash,'') FROM execution_requests WHERE request_id = $B_REQ")
  if [[ -z "$TXH" ]]; then
    fail "B7 rung 1 request $B_REQ records no transaction hash — the only handle the caller has leads nowhere"
  else
    pass "B7 rung 1 the request names the transaction that started it ($TXH)"

    # Rung 2 — the chain's own account of it. Asked of the node rather than of
    # our database, so a row we wrote cannot vouch for itself.
    #
    # Retried, and a node that keeps saying TIMEOUT_ERROR is not counted as a
    # failure of ours: that is what this RPC answers both for a transaction it
    # has not finalised yet and for one it has already pruned — a public node
    # keeps only a few epochs — and neither says anything about whether the run
    # is traceable. Only an answer that comes back and is WRONG is a failure.
    TXST=""; RCPTS=""; RECV=""
    for _ in 1 2 3 4 5; do
      TXST=$(curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' --max-time 30 \
        -d "$(jq -nc --arg h "$TXH" --arg a "$EXECUTOR" \
            '{jsonrpc:"2.0",id:1,method:"EXPERIMENTAL_tx_status",params:[$h,$a]}')" 2>/dev/null)
      RCPTS=$(jq -r '.result.receipts_outcome | length' <<<"$TXST" 2>/dev/null)
      RECV=$(jq -r '.result.transaction.receiver_id // ""' <<<"$TXST" 2>/dev/null)
      [[ -n "$RCPTS" && "$RCPTS" != "null" ]] && break
      sleep 5
    done
    if [[ -z "$RCPTS" || "$RCPTS" == "null" ]]; then
      warn "B7 rung 2 NOT JUDGED — the node would not return the transaction ($(jq -r '.error.cause.name // .error.message // "no answer"' <<<"$TXST")). Rungs 1 and 3-5 below still stand"
    else
      (( RCPTS > 0 )) \
        && pass "B7 rung 2 the chain carries $RCPTS inner receipts for it — the receipts R8 asks to reach" \
        || fail "B7 rung 2 the transaction resolved with no receipts at all"
      [[ "$RECV" == "$CONTRACT_ID" ]] \
        && pass "B7 rung 2 and it was addressed to the contract ($RECV)" \
        || fail "B7 rung 2 the transaction was addressed to '$RECV', not $CONTRACT_ID"
    fi

    # Rung 3 — the run. The link a support question actually needs: which
    # enclave executed this, and did it finish.
    JROW=""
    for _ in $(seq 1 10); do
      JROW=$(sql "SELECT job_id || '|' || COALESCE(worker_id,'') || '|' || status \
                    FROM jobs WHERE request_id = $B_REQ AND job_type = 'execute' \
                   ORDER BY created_at DESC LIMIT 1")
      [[ -n "$JROW" ]] && break; sleep 3
    done
    if [[ -z "$JROW" ]]; then
      fail "B7 rung 3 no execute job for request $B_REQ — the request cannot be tied to a run"
    else
      J_ID="${JROW%%|*}"; JR="${JROW#*|}"; J_WORKER="${JR%%|*}"; J_ST="${JR##*|}"
      note "job $J_ID on worker '${J_WORKER:-none}' — $J_ST"
      [[ -n "$J_WORKER" ]] \
        && pass "B7 rung 3 the run names the worker that did it ($J_WORKER)" \
        || fail "B7 rung 3 the job records no worker; an execution nobody can be named for cannot be attested to afterwards"
      [[ "$J_ST" == "completed" ]] \
        && pass "B7 rung 3 and the run finished" \
        || fail "B7 rung 3 the job is '$J_ST'"
    fi

    # Rung 4 — the priced record of the operation, which is the row a partner's
    # own billing reconciles against.
    OROW=$(sql "SELECT operation || '|' || success || '|' || COALESCE(tx_hash,'') \
                  FROM onchain_calls WHERE request_id = $B_REQ")
    if [[ -z "$OROW" ]]; then
      warn "B7 rung 4 no onchain_calls row for request $B_REQ — nothing priced was recorded for this operation"
    else
      O_OP="${OROW%%|*}"; O_TX="${OROW##*|}"
      # The same hash, not merely A hash. A priced row carrying somebody else's
      # transaction reconciles against the wrong operation, and every total it
      # feeds still adds up — which is why this compares rather than checks for
      # emptiness.
      [[ "$O_TX" == "$TXH" ]] \
        && pass "B7 rung 4 the priced record names the operation ($O_OP) and carries THIS transaction" \
        || fail "B7 rung 4 the priced record for '$O_OP' carries '$O_TX', not the transaction this run came from"
      # And the ledger row B6 read is about the same transaction too, which is
      # what joins "who was billed" to "what happened". Only asked when B6
      # actually found a row: an assertion that also passes on an empty value is
      # how "" comes to be compared against "" and reported as agreement.
      if [[ -n "${E_TX:-}" ]]; then
        [[ "$E_TX" == "$TXH" ]] \
          && pass "B7 rung 4 and the earnings row is about the same transaction — the money and the run are one record" \
          || fail "B7 rung 4 the earnings row names transaction '$E_TX' while the run came from '$TXH'"
      fi
    fi

    # Rung 5 — the enclave's own evidence, addressed by the hash the caller has
    # rather than by any identifier we invented. Uploaded after the run, so this
    # waits instead of reading once.
    ACODE=""
    for _ in 1 2 3 4 5 6 7 8; do
      ACODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 "$COORDINATOR_URL/attestations/by-tx/$TXH" 2>/dev/null)
      [[ "$ACODE" == "200" ]] && break; sleep 5
    done
    if [[ "$ACODE" == "200" ]]; then
      pass "B7 rung 5 the TEE attestation is reachable from the transaction hash alone — the walk closes without a single internal identifier"
    elif [[ "$ACODE" == "404" ]]; then
      fail "B7 rung 5 /attestations/by-tx/$TXH is still 404 after forty seconds: the run is on file and its evidence is not addressable by the only handle the caller holds"
    else
      fail "B7 rung 5 the attestation address answered HTTP $ACODE"
    fi
  fi
fi

# ── B3: the two doors agree ──────────────────────────────────────────────────
log "B3 the HTTPS door answers the same for the same wallet"
if [[ -z "$API_KEY" ]]; then
  note "B3 SKIPPED — set API_KEY=<a payment key owned by this wallet> to run it"
else
  https_whoami() { # https_whoami [extra curl args...]
    curl -s -X POST -H 'Content-Type: application/json' \
      -H "X-Payment-Key: $API_KEY" "$@" \
      -d '{"input":{"operation":"whoami"},"use_bound_identity":true}' \
      "$COORDINATOR_URL/call/${PROJECT%%/*}/${PROJECT##*/}"
  }

  # B3a — the flag ON ITS OWN, with no other header.
  #
  # The probe that carries the section. The binding has to be resolved from the
  # CREDENTIAL, not from the value that decides whether the job may SPEND the
  # wallet's money: that one is absent unless `X-Wallet-Id` was sent, so
  # resolving from it leaves the flag doing nothing here while the on-chain door
  # substitutes normally. Sending the header hides exactly that — see B3b, which
  # is why it is the control and not the test.
  HTTPS_OUT=$(https_whoami)
  HTTPS_SENDER=$(jq -r '.output.sender_id // empty' <<<"$HTTPS_OUT")
  if [[ -z "$HTTPS_SENDER" ]]; then
    fail "B3a the HTTPS call returned no sender: $(head -c 300 <<<"$HTTPS_OUT")"
  elif [[ "$HTTPS_SENDER" == "$ASSET" ]]; then
    pass "B3a the flag alone is enough — both doors answer '$ASSET', and the module cannot tell how it was started"
  else
    fail "B3a HTTPS says '$HTTPS_SENDER' while the on-chain door said '$ASSET' — the doors disagree, which is the bug the flag was added to prevent. If B3b passes, the flag is being resolved from X-Wallet-Id rather than from the credential"
  fi

  # B3b — the same call WITH the header. Kept as the control: it passed
  # throughout the regression above, so on its own it proves nothing.
  HTTPS_OUT=$(https_whoami -H "X-Wallet-Id: $WALLET_ID")
  HTTPS_SENDER=$(jq -r '.output.sender_id // empty' <<<"$HTTPS_OUT")
  [[ "$HTTPS_SENDER" == "$ASSET" ]] \
    && pass "B3b with X-Wallet-Id it also answers '$ASSET'" \
    || fail "B3b even with X-Wallet-Id the sender is '$HTTPS_SENDER', expected '$ASSET'"

  # And the payer never moves, on this door either.
  HTTPS_PAYER=$(jq -r '.output.user_account_id // empty' <<<"$HTTPS_OUT")
  [[ "$HTTPS_PAYER" == "$EXECUTOR" ]] \
    && pass "B3 the payer stayed the key's owner ($HTTPS_PAYER)" \
    || fail "B3 the payer is '$HTTPS_PAYER', expected '$EXECUTOR' — billing must not follow a binding on either door"
fi

# ── B4: asked for and not available → refusal, never a silent fallback ───────
log "B4 flag ON from a wallet with NO binding — must be REFUSED"
STRANGER_SEED="stranger-$(date +%s)-$$"
SR=$(curl -sS -G "$COORDINATOR_URL/wallet/v1/address" --data-urlencode "chain=near" -H "$(AUTH "$STRANGER_SEED")")
SWID=$(jq -r '.wallet_id // empty' <<<"$SR")
SADDR=$(jq -r '.address // empty' <<<"$SR")
if [[ -z "$SWID" ]]; then
  fail "B4 could not mint a stranger wallet: $(head -c 200 <<<"$SR")"
else
  note "stranger wallet $SWID at $SADDR"
  # Funded exactly like the executor. A poor stranger is refused for being
  # poor, and that refusal looks exactly like the one this probe is for — which
  # is how an earlier run of this script "passed" B4 twice without ever reaching
  # the binding check.
  store_policy "$STRANGER_SEED" "$SWID" '{"rules":{"transaction_types":["call"]}}' \
    || warn "B4 the stranger's policy was not stored; a refusal below may be for the wrong reason"
  fund_wallet "$STRANGER_SEED" "$SADDR" "stranger" || true
  MARK=$(watermark)
  onchain_whoami "$STRANGER_SEED" true
  note "send answered: ${SEND_ERR:-ok}"
  # The transaction itself may well succeed — the refusal happens when the
  # coordinator turns the event into a job. What must NOT happen is the run
  # going ahead under the stranger's own name.
  if ROW=$(identity_of "$SADDR" "$MARK"); then
    REQ="${ROW%%|*}"; REST="${ROW#*|}"; SENDER="${REST%%|*}"
    if [[ "$SENDER" == "$SADDR" ]]; then
      fail "B4 the job ran under the caller's own name — a request that asked for a bound identity was quietly answered with a different one"
    elif [[ -z "$SENDER" ]]; then
      pass "B4 the request carries an EMPTY sender — the worker is told to refuse rather than to substitute"
    else
      fail "B4 the job was given the identity '$SENDER', which belongs to nobody in this test"
    fi
  else
    ERR="$SEND_ERR"
    MSG=$(jq -r '.message // ""' <<<"$OUT" 2>/dev/null)
    # Not a pass. Everything here happens BEFORE the binding is consulted, and
    # each of them refuses a request that asked for a bound identity — so an
    # assertion that only looks for "it was refused" is satisfied by a wallet
    # that is merely broke.
    if [[ "$ERR" == wallet_underfunded || "$ERR" == policy_denied || "$ERR" == wallet_busy ]] \
       || grep -qi "Insufficient payment\|Insufficient stablecoin" <<<"$MSG"; then
      fail "B4 could not be judged — refused as '$ERR' ($(head -c 120 <<<"$MSG")), which happens before any binding is looked up"
    else
      pass "B4 refused before it could run: ${ERR:-$(head -c 160 <<<"$MSG")}"
    fi
  fi
fi

# ── B5: the flag is not a way to borrow a name ───────────────────────────────
log "B5 an account that is not an extension cannot become the bound account"
note "Covered by B4 on the coordinator side (no binding matches the caller)."
note "The TEE side is the second wall: even a forged claim is re-read from the"
note "chain in the worker, and admit() refuses when membership is absent."
note "To exercise it deliberately: remove the executor from the extension set"
note "between queueing and execution, then re-run B1 — it must refuse."

printf '\n\033[1m%d passed, %d failed\033[0m\n' "$PASS" "$FAILED" >&2
for n in "${FAILED_NAMES[@]:-}"; do [[ -n "$n" ]] && printf '  \033[31m✗ %s\033[0m\n' "$n" >&2; done
[[ "$FAILED" -eq 0 ]]
