#!/usr/bin/env bash
#
# Two spends at the SAME MOMENT against one velocity limit.
#
# Every other velocity check in this repo makes two calls one after the other,
# and a sequential pair passes even with the per-wallet lock removed entirely.
# The bug that was actually measured in production was the overlapping pair:
# 412 request pairs started while another spend decision had read the usage
# total and not yet written it back (median read→write 2.0s, p90 14.6s). Two
# calls a second apart never reproduce it; two calls at once always do.
#
# What each probe pins:
#   P1  one limit, two simultaneous spends — exactly ONE gets through. The
#       loser is either 409 wallet_busy (the winner still holds the wallet) or
#       403 policy_denied (the winner already wrote its usage). Both are
#       correct; BOTH SUCCEEDING is the defect, and it is silent — two lawful
#       calls, two 200s, and a wallet over its ceiling.
#
#       A 409 must leave the loser something to act on: `in_flight_request_id`
#       once the winner's row exists, or `in_flight_operation` before it does —
#       the id is withheld until the row is written, since one given earlier
#       answers 404 and reads as a request that was lost. Neither field is the
#       failure
#   P2  the 2-second grace still works — two simultaneous spends that BOTH fit
#       under the limit must both succeed. Without the grace every client
#       making two quick calls would see a stream of 409s for doing nothing
#       wrong
#   P3  the lock is per WALLET, not global — two wallets spending at once do
#       not queue behind each other. Serializing the whole service would be a
#       different bug of the same size
#
# P1/P2/P3 are items 1, 3 and 4 of "Осталось на живой стенд" in
# .idea/hos-post-redeploy-plan.md. Items 2 (a long operation in front) and 5
# (the approval path WAITS rather than refusing) are not here: the first needs
# a swap, which is mainnet-only, and the second needs a second approver.
#
# Money: each sub-wallet is funded with 0.15 NEAR from $PARENT and swept back
# on exit, including on abort. What the run actually costs is gas plus the
# storage deposits for the on-chain policies.
#
# Requires: $PARENT with a keychain credential and ~0.4 NEAR, `outlayer` logged
# in as $PARENT, and a coordinator carrying the per-wallet lock.
#
# Run (spends real testnet NEAR):
#   PARENT=you.testnet ./tests/wallet_concurrent_spend_e2e.sh --apply

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPLY=false
[[ "${1:-}" == "--apply" ]] && APPLY=true

NETWORK="${NETWORK:-testnet}"
CONTRACT_ID="${CONTRACT_ID:-outlayer.testnet}"
COORDINATOR_URL="${COORDINATOR_URL:-https://testnet-api.outlayer.ai}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/rpc.sh"   # keyed RPC_URL, or a warning
PARENT="${PARENT:-}"

# The daily ceiling the whole run is built around, and the two amounts that sit
# either side of it. 0.6 L each: under the limit alone, over it together.
LIMIT_YOCTO="20000000000000000000000"      # 0.02 NEAR
HALF_OVER_YOCTO="12000000000000000000000"  # 0.012 NEAR — 0.6 L
TINY_YOCTO="1000000000000000000000"        # 0.001 NEAR — comfortably under
FUND_NEAR="0.15"

PASS=0; FAILED=0; FAILED_NAMES=()
log()  { printf '\n\033[36m▶ %s\033[0m\n' "$*" >&2; }
note() { printf '\033[35m• %s\033[0m\n' "$*" >&2; }
warn() { printf '\033[33m⚠ %s\033[0m\n' "$*" >&2; }
pass() { printf '\033[32m✓ %s\033[0m\n' "$*" >&2; PASS=$((PASS+1)); }
fail() { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; FAILED=$((FAILED+1)); FAILED_NAMES+=("$*"); }

if [[ "$APPLY" != true ]]; then
  sed -n '3,37p' "$0" >&2
  echo "  Pass --apply to run." >&2
  exit 0
fi

[[ -n "$PARENT" ]] || { echo "USAGE: PARENT=you.testnet $0 --apply" >&2; exit 1; }
for tool in jq curl near outlayer cargo; do
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

# Sub-wallets created by this run, one `seed wallet_id address` per line. A
# file rather than an array: the sweep runs from the EXIT trap, and it has to
# see wallets added after the trap was installed.
LEDGER="$(mktemp -t concspend_ledger.XXXXXX)"

near_tty() {
  if command -v script >/dev/null 2>&1 && [ -t 1 ]; then
    local tmp; tmp=$(mktemp -t concspend_cmd.XXXXXX.sh)
    printf 'set -euo pipefail\n%s\n' "$*" > "$tmp"
    script -q /dev/null bash "$tmp"; local rc=$?; rm -f "$tmp"; return $rc
  else eval "$@"; fi
}

mk_token() { "$RECOVERY_BIN" sign-bearer-near --private-key "$PARENT_PRIVKEY" --account-id "$PARENT" --seed "$1"; }
AUTH() { echo "Authorization: Bearer near:$(mk_token "$1")"; }

# The native balance the CHAIN reports, "0" for an account that does not exist.
# near-cli-rs exits 0 on a swallowed broadcast transient, so every funding step
# in this script is judged by this and never by a return code.
chain_balance() {
  curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg a "$1" '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"view_account",finality:"final",account_id:$a}}')" \
    2>/dev/null | jq -r 'if .result.amount then .result.amount else "0" end' 2>/dev/null || echo "0"
}

# spend <auth-header> <amount_yocto> <outfile> — one POST /wallet/v1/transfer.
#
# Takes a READY header rather than a seed, and that is the whole reason this
# script can claim to test concurrency. Building the header runs
# `customer-recovery` — a process spawn plus an ed25519 signature — and while
# that happened inside the backgrounded call, the two requests did not start
# together: whichever branch signed faster went first, and if the gap grew past
# the winner's critical section the pair simply serialized. P1 then passes on a
# coordinator with no lock at all, which is the one outcome it exists to rule
# out. Everything slow happens before the fork; the fork contains one curl.
#
# Writes "<http_code> <body>" so a backgrounded caller can hand its result back
# — a subshell can return nothing to its parent except a file. The duration of
# the request itself goes to "$out.time", measured by curl rather than by the
# shell: P2 reads it to tell a grace that was APPLIED from one that is gone, and
# a wall-clock reading around the fork cannot separate those two.
spend() {
  local auth=$1 amount=$2 out=$3 body meta http secs
  body=$(jq -nc --arg to "$PARENT" --arg a "$amount" '{chain:"near", to:$to, amount:$a}')
  meta=$(curl -sS -o "$out.body" -w '%{http_code} %{time_total}' -X POST "$COORDINATOR_URL/wallet/v1/transfer" \
    -H "$auth" -H 'Content-Type: application/json' -d "$body")
  http=${meta%% *}; secs=${meta##* }
  printf '%s %s\n' "$http" "$(tr -d '\n' < "$out.body")" > "$out"
  printf '%s\n' "$secs" > "$out.time"
  rm -f "$out.body"
}

http_of() { awk '{print $1}' "$1" 2>/dev/null; }
body_of() { cut -d' ' -f2- "$1" 2>/dev/null; }
code_of() { body_of "$1" | jq -r '.error // empty' 2>/dev/null; }
time_of() { cat "$1.time" 2>/dev/null || echo 0; }
# Float compare without bc, which is not installed everywhere.
ge() { awk -v a="$1" -v b="$2" 'BEGIN{exit !(a+0 >= b+0)}'; }

# store_policy <seed> <wallet_id> <rules-json> — encrypt, sign, put on chain.
# The policy is the only place a velocity limit can live: it is encrypted for
# the keystore, so the coordinator cannot read the ceiling and this script
# cannot set one through any other door.
store_policy() {
  local seed=$1 wid=$2 pol=$3 body enc encb64 sg sig_hex pub_hex store_args
  body=$(jq -nc --arg wid "$wid" --argjson p "$pol" '$p + {wallet_id:$wid}')
  enc=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/encrypt-policy" \
    -H "$(AUTH "$seed")" -H 'Content-Type: application/json' -d "$body")
  encb64=$(echo "$enc" | jq -r '.encrypted_base64 // empty')
  [[ -n "$encb64" ]] || { warn "encrypt-policy failed: $(head -c 200 <<<"$enc")"; return 1; }
  # `caller` is signed into the answer: it is good only for the account that
  # sends the store below, which is $PARENT.
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

# ── cleanup ──────────────────────────────────────────────────────────────────
# An interrupted run must not leave funded accounts whose keys exist only as a
# seed in this process. Registered before the first wallet is funded.
cleanup() {
  local rc=$?
  [[ -s "$LEDGER" ]] || { rm -f "$LEDGER"; return $rc; }
  log "Sweeping sub-wallets back to $PARENT"
  local seed wid addr bal
  while read -r seed wid addr; do
    [[ -n "${addr:-}" ]] || continue
    bal=$(chain_balance "$addr")
    if [[ "$bal" == "0" ]]; then
      note "sweep: $addr — nothing on chain"
      continue
    fi
    # The run's own policy caps daily native spending, and a delete moves the
    # whole balance — so the sweep replaces the policy with one that permits
    # exactly the delete and nothing else.
    store_policy "$seed" "$wid" '{"rules":{"transaction_types":["delete"]}}' \
      || warn "sweep: $addr — sweep policy not stored; the delete below will likely 403"
    local out; out=$(mktemp -t concspend_del.XXXXXX)
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

# new_wallet <tag> — mint a sub-wallet, fund it, give it the daily ceiling.
# Echoes "seed wallet_id address".
new_wallet() {
  local tag=$1 seed r wid addr before after
  seed="concspend-$tag-$(date +%s)-$$"
  r=$(curl -sS -G "$COORDINATOR_URL/wallet/v1/address" --data-urlencode "chain=near" -H "$(AUTH "$seed")")
  wid=$(echo "$r" | jq -r '.wallet_id // empty'); addr=$(echo "$r" | jq -r '.address // empty')
  [[ -n "$wid" && -n "$addr" ]] || { warn "$tag: /address failed: $(head -c 200 <<<"$r")"; return 1; }
  printf '%s %s %s\n' "$seed" "$wid" "$addr" >> "$LEDGER"

  before=$(chain_balance "$addr")
  # Output KEPT and the result judged by the chain. A funding step sent to
  # /dev/null turns a transfer that never landed into "the product is broken",
  # which is an evening spent on the wrong component.
  local send_out
  send_out=$(near_tty "near --quiet tokens $PARENT send-near $addr '$FUND_NEAR NEAR' \
    network-config $NETWORK sign-with-keychain send" 2>&1)
  after=$(chain_balance "$addr")
  if [[ "$after" == "$before" || "$after" == "0" ]]; then
    warn "$tag: funding did not land on $addr — the SENDER failed, not the coordinator"
    warn "$(tail -c 400 <<<"$send_out")"
    return 1
  fi

  store_policy "$seed" "$wid" \
    "$(jq -nc --arg l "$LIMIT_YOCTO" '{rules:{transaction_types:["transfer","delete"],limits:{daily:{native:$l}}}}')" \
    || { warn "$tag: policy not stored — every spend below would be refused for the wrong reason"; return 1; }
  echo "$seed $wid $addr"
}

log "Minting two funded sub-wallets with a ${LIMIT_YOCTO} yocto daily native ceiling"
read -r SEED_A WID_A ADDR_A < <(new_wallet a) || { fail "wallet A setup"; exit 1; }
pass "wallet A: $ADDR_A"
read -r SEED_B WID_B ADDR_B < <(new_wallet b) || { fail "wallet B setup"; exit 1; }
pass "wallet B: $ADDR_B"

# ── P1: one limit, two spends at once ────────────────────────────────────────
log "P1 two simultaneous spends of 0.6 L on wallet A — exactly one may pass"
OUT1=$(mktemp -t concspend_p1a.XXXXXX); OUT2=$(mktemp -t concspend_p1b.XXXXXX)
# Two headers for the same wallet, both built BEFORE the fork. They are
# separate tokens on purpose: each carries its own nonce, so this is two
# independent callers of one wallet rather than one credential used twice.
AUTH_A1=$(AUTH "$SEED_A"); AUTH_A2=$(AUTH "$SEED_A")
spend "$AUTH_A1" "$HALF_OVER_YOCTO" "$OUT1" &
P1=$!
spend "$AUTH_A2" "$HALF_OVER_YOCTO" "$OUT2" &
P2=$!
wait $P1; wait $P2
H1=$(http_of "$OUT1"); H2=$(http_of "$OUT2")
OK=0
[[ "$H1" == 2?? ]] && OK=$((OK+1))
[[ "$H2" == 2?? ]] && OK=$((OK+1))
note "P1 responses: $H1 ($(code_of "$OUT1")) / $H2 ($(code_of "$OUT2"))"
case "$OK" in
  1)
    pass "P1 exactly one spend passed — the pair was serialized against one usage total"
    # Which refusal arrived says WHICH half of the mechanism answered, and both
    # are correct: 409 means the winner still held the wallet past the grace,
    # 403 means it had already written its usage and the loser read it.
    LOSER=$([[ "$H1" == 2?? ]] && echo "$OUT2" || echo "$OUT1")
    case "$(code_of "$LOSER")" in
      wallet_busy)
        # A refusal has to leave the caller something to act on, and there are
        # two shapes of that — because the id is withheld until the winner's
        # request row is written. One handed out before that answers 404, which
        # reads as a request that was lost, and the reasonable response to a
        # lost request is to send it again.
        #
        # This probe fires both spends AT ONCE, so the loser arrives just as the
        # winner takes the wallet — before its INSERT far more often than after.
        # Demanding an id here would fail a correct stack nearly every run.
        # `in_flight_operation` is what is always there, and it is the half that
        # decides how long to wait: seconds for a transfer, minutes for a
        # cross-chain withdraw.
        ID=$(body_of "$LOSER" | jq -r '.in_flight_request_id // empty')
        OP=$(body_of "$LOSER" | jq -r '.in_flight_operation // empty')
        if [[ -n "$ID" ]]; then
          pass "P1 the loser got wallet_busy with in_flight_request_id=$ID to poll${OP:+ (a $OP)}"
        elif [[ -n "$OP" ]]; then
          pass "P1 the loser got wallet_busy naming a $OP to wait for — the winner's row is not written yet"
        else
          fail "P1 wallet_busy carried NEITHER an id nor an operation — the caller has nothing to poll, nothing to wait for, and no way to learn the outcome"
        fi
        ;;
      policy_denied)
        pass "P1 the loser was refused by the limit, reading a usage total that already included the winner" ;;
      *)
        fail "P1 the loser was refused as '$(code_of "$LOSER")' — expected wallet_busy or policy_denied: $(body_of "$LOSER" | head -c 200)" ;;
    esac
    ;;
  2)
    fail "P1 BOTH spends passed — 1.2 L went through a ceiling of L. This is the production race: two lawful calls, two 200s, no error anywhere"
    ;;
  *)
    fail "P1 neither spend passed ($H1 / $H2) — the wallet is refusing for some other reason, so this probe proved nothing: $(body_of "$OUT1" | head -c 200)"
    ;;
esac
rm -f "$OUT1" "$OUT2" "$OUT1.time" "$OUT2.time"

# ── P2: the grace ────────────────────────────────────────────────────────────
#
# The grace is `try_acquire`: a `tokio::time::timeout(WALLET_BUSY_GRACE, …)`
# around the lock, so a loser WAITS up to two seconds before it is told "busy".
#
# Asking for "both must pass" cannot test that on a live chain. The winner holds
# the wallet across a real NEAR broadcast — three seconds and up, comfortably
# past the grace — so the loser is refused no matter how healthy the grace is,
# and the probe reported INCONCLUSIVE on every honest run. It measured the
# winner's speed, which is not the thing under test.
#
# What separates a grace that WAS APPLIED from one that is gone is the LOSER's
# own duration. Waited ≈2s then 409 → the timeout ran. Refused in milliseconds →
# somebody swapped the timeout for a bare `try_lock` and every client making two
# quick calls now gets a 409 for doing nothing wrong. curl times each request
# itself, so this reads the request and not the fork around it.
log "P2 two simultaneous spends that BOTH fit — the loser must WAIT out the 2s grace"
OUT3=$(mktemp -t concspend_p2a.XXXXXX); OUT4=$(mktemp -t concspend_p2b.XXXXXX)
AUTH_B1=$(AUTH "$SEED_B"); AUTH_B2=$(AUTH "$SEED_B")
spend "$AUTH_B1" "$TINY_YOCTO" "$OUT3" &
P3=$!
spend "$AUTH_B2" "$TINY_YOCTO" "$OUT4" &
P4=$!
wait $P3; wait $P4
H3=$(http_of "$OUT3"); H4=$(http_of "$OUT4")
T3=$(time_of "$OUT3"); T4=$(time_of "$OUT4")
note "P2 responses: $H3 ($(code_of "$OUT3")) in ${T3}s / $H4 ($(code_of "$OUT4")) in ${T4}s"
# 1.5 rather than 2.0: the timeout fires at two seconds, but the loser's clock
# starts when curl connects, a moment BEFORE the server begins waiting. A margin
# below the grace keeps that skew from failing a healthy stack, and is still far
# above the milliseconds a missing grace would produce.
GRACE_FLOOR=1.5
if [[ "$H3" == 2?? && "$H4" == 2?? ]]; then
  pass "P2 both passed — the winner finished inside the grace and the loser queued behind it"
elif [[ "$(code_of "$OUT3")" == "wallet_busy" ]] || [[ "$(code_of "$OUT4")" == "wallet_busy" ]]; then
  if [[ "$(code_of "$OUT3")" == "wallet_busy" ]]; then LOSER_T=$T3; else LOSER_T=$T4; fi
  if ge "$LOSER_T" "$GRACE_FLOOR"; then
    pass "P2 the loser waited ${LOSER_T}s before wallet_busy — the grace ran (floor ${GRACE_FLOOR}s)"
  else
    fail "P2 wallet_busy returned in ${LOSER_T}s, under the ${GRACE_FLOOR}s floor — the grace is gone, and every client doing two quick calls will now see 409s"
  fi
elif [[ "$(code_of "$OUT3")" == "chain_unavailable" ]] || [[ "$(code_of "$OUT4")" == "chain_unavailable" ]]; then
  # A TRANSIENT is not a refusal, and this probe is about the grace window.
  #
  # The code is `chain_unavailable`, which is the coordinator's name for a node
  # that could not answer this second. It is NOT `service_unavailable`: that one
  # means a feature this deployment does not offer, carries no Retry-After, and
  # nothing on this path can produce it — matching it here would leave the real
  # transient falling through to the failure below.
  #
  # The one seen live: `the transaction expired before it reached the chain` —
  # the block it was signed against left the node's window. Nothing executed
  # and nothing was spent, and the coordinator says exactly that and asks for a
  # retry. Counting it as "a spend inside the limit was refused" reports a
  # working rule as broken because the network was slow for a second.
  note "P2 NOT JUDGED — one side hit a transient: $(body_of "$OUT3" | head -c 120) / $(body_of "$OUT4" | head -c 120)"
  note "P2 re-run to exercise the grace window; nothing here says the limit misbehaved"
else
  fail "P2 a spend inside the limit was refused: $(body_of "$OUT3" | head -c 200) / $(body_of "$OUT4" | head -c 200)"
fi
rm -f "$OUT3" "$OUT4" "$OUT3.time" "$OUT4.time"

# ── P3: the lock is per wallet ───────────────────────────────────────────────
log "P3 two DIFFERENT wallets spending at once — neither may wait on the other"
OUT5=$(mktemp -t concspend_p3a.XXXXXX); OUT6=$(mktemp -t concspend_p3b.XXXXXX)
AUTH_A3=$(AUTH "$SEED_A"); AUTH_B3=$(AUTH "$SEED_B")
spend "$AUTH_A3" "$TINY_YOCTO" "$OUT5" &
P5=$!
spend "$AUTH_B3" "$TINY_YOCTO" "$OUT6" &
P6=$!
wait $P5; wait $P6
H5=$(http_of "$OUT5"); H6=$(http_of "$OUT6")
note "P3 responses: $H5 ($(code_of "$OUT5")) / $H6 ($(code_of "$OUT6"))"
if [[ "$(code_of "$OUT5")" == "wallet_busy" || "$(code_of "$OUT6")" == "wallet_busy" ]]; then
  fail "P3 one wallet was told the OTHER wallet is busy — the lock is global, which serializes every customer behind every other"
elif [[ "$H5" == 2?? && "$H6" == 2?? ]]; then
  pass "P3 both wallets spent concurrently"
else
  # Wallet A has spent 0.6 L of its ceiling in P1, so its remainder is real but
  # small; a refusal by the limit here is the limit working, not the lock.
  note "P3 not both passed, and neither said wallet_busy — the lock is not the cause"
  pass "P3 no cross-wallet blocking"
fi
rm -f "$OUT5" "$OUT6" "$OUT5.time" "$OUT6.time"

printf '\n\033[1m%d passed, %d failed\033[0m\n' "$PASS" "$FAILED" >&2
for n in "${FAILED_NAMES[@]:-}"; do [[ -n "$n" ]] && printf '  \033[31m✗ %s\033[0m\n' "$n" >&2; done
[[ "$FAILED" -eq 0 ]]
