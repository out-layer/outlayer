#!/usr/bin/env bash
#
# The wallet host functions, as a WASI guest actually sees them.
#
# Everything else about custody is tested through HTTPS endpoints. This is the
# other caller: a module inside the enclave calling `outlayer:wallet/api`, where
# a refusal arrives as ONE STRING and everything the agent must decide next has
# to be recoverable from it — which code, whether retrying helps, and, when
# another operation holds the wallet, which request to poll until it frees.
#
# `wallet-probe` does not hand that string back raw. It PARSES it into
# `error_parsed{code, terminal, in_flight_request_id}`, and that is the point:
# these probes prove an agent can ROUTE on a refusal, not merely read one.
#
# WHY A SEPARATE MODULE FROM connector-probe. The worker gives the wallet
# imports only to a component that imports them (`has_wallet_import`), and
# REFUSES to instantiate such a component when the request names no wallet —
# before `main`. Most connector-probe calls name no wallet, so one import would
# have taken all of them down. W1 is the live proof of that contract.
#
# HOW IT IS CALLED — two things, both required:
#   * a payment key the WALLET owns (`X-Payment-Key`). The key names its wallet
#     through `owner`;
#   * `X-Wallet-Id` with that wallet's id, EXPLICITLY. Host functions can spend
#     the wallet's money, so they are opt-in rather than ambient — a call that
#     never named a wallet does not get them, and for this module that is a
#     refusal at startup rather than a quieter run.
#
# What each probe pins:
#   W1  no `X-Wallet-Id` → the job is REFUSED because the module imports wallet
#       and no wallet is available. The negative that defines the contract
#   W2  `whoami` → the host function's `wallet_id` equals `WALLET_ID` from the
#       environment. A mismatch would mean something other than the worker put
#       that variable there
#   W3  `balance` → `address` and `balance` agree with the HTTPS endpoints. Two
#       roads to one fact, and they can diverge silently
#   W4  `transfer` within policy → the money MOVED, judged on chain rather than
#       by a status code, and `result` carries a request id
#   W5  `transfer` outside policy → `error_parsed.code = policy_denied`. Not
#       "was it refused" but "can the refusal be routed on". `terminal` is NOT
#       expected here: `guest_error` appends it only when the body carries it,
#       and a plain policy refusal sends the uniform `{error,message}`
#   W6  `wallet_busy` routed on: hold the wallet with a slower operation, call
#       `transfer` inside the window → `code = wallet_busy` carrying something
#       to act on. TWO shapes are correct, because the coordinator withholds
#       the id until the holder's row is written (one given earlier answers
#       404): either an `in_flight_request_id`, which is then fed to
#       `request_status` and must read back — a refusal naming a request nobody
#       can read is a dead end wrapped in an instruction, and nothing else
#       tests that — or, when the guest met the holder before its INSERT, an
#       `in_flight_operation` and no id, which says what to wait for. NEITHER
#       is the failure
#   W7  `X-Wallet-Id` naming SOMEBODY ELSE's wallet → refused. The header
#       confirms the wallet the credential already names; it never selects one
#
# What these do NOT prove, said plainly: `"network": []` cannot be confirmed
# from inside — the module has no operation that reaches outward, and adding one
# would build exactly the SSRF gadget connector-probe avoids. Enforcement of the
# empty list rests on `forbidden_fetch` over there, and here only on the section
# being present in the artifact (checked by `build.sh`).
#
# Requires: $PARENT with a keychain credential and `outlayer` logged in as it;
# `wallet-probe` deployed under an ORDINARY account (not `connectors.*`, or it
# falls inside trial-key scope); a wallet with a policy permitting transfers to
# $RECIPIENT, and a payment key that wallet owns.
#
# Run (spends real testnet NEAR):
#   PARENT=you.testnet RECIPIENT=friend.testnet OUTSIDER=other.testnet \
#     STRANGER_WALLET=<uuid> ./tests/wallet_probe_e2e.sh --apply
#
# A wallet is MINTED and funded for the run unless WALLET_SEED and PAYMENT_KEY
# name an existing one — W6 fires dozens of transfers, and those come out of
# whatever wallet it is pointed at.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPLY=false
[[ "${1:-}" == "--apply" ]] && APPLY=true

NETWORK="${NETWORK:-testnet}"
COORDINATOR_URL="${COORDINATOR_URL:-https://testnet-api.outlayer.ai}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/rpc.sh"   # keyed RPC_URL, or a warning
PROJECT="${PROJECT:-zavodil.testnet/wallet-probe}"
PARENT="${PARENT:-}"
WALLET_SEED="${WALLET_SEED:-}"
PAYMENT_KEY="${PAYMENT_KEY:-}"
RECIPIENT="${RECIPIENT:-}"
# Any wallet id that is NOT the caller's. W7 says so if it is absent.
STRANGER_WALLET="${STRANGER_WALLET:-}"

# What W4 moves and W6 uses to hold the wallet. Small on purpose: W6 fires
# several and every one of them is real money leaving the wallet.
XFER_YOCTO="${XFER_YOCTO:-1000000000000000000000}"     # 0.001 NEAR
# What a freshly minted wallet is given, when this suite mints its own.
TOKEN_CONTRACT="${TOKEN_CONTRACT:-usdc.fakes.testnet}"
FUND_NEAR="${FUND_NEAR:-1.0}"
FUND_USDC_MINIMAL="${FUND_USDC_MINIMAL:-1500000}"
DEPOSIT_USDC="${DEPOSIT_USDC:-0.30}"

PASS=0; FAILED=0; FAILED_NAMES=()
log()  { printf '\n\033[36m▶ %s\033[0m\n' "$*" >&2; }
note() { printf '\033[35m• %s\033[0m\n' "$*" >&2; }
warn() { printf '\033[33m⚠ %s\033[0m\n' "$*" >&2; }
pass() { printf '\033[32m✓ %s\033[0m\n' "$*" >&2; PASS=$((PASS+1)); }
fail() { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; FAILED=$((FAILED+1)); FAILED_NAMES+=("$*"); }

if [[ "$APPLY" != true ]]; then
  sed -n '3,67p' "$0" >&2
  echo "  Pass --apply to run." >&2
  exit 0
fi

for v in PARENT RECIPIENT; do
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

# A WALLET OF ITS OWN, unless one was passed.
#
# W6 holds the wallet busy by firing transfers at it continuously, and a run
# does dozens. Spent against a wallet somebody else uses, that eats their
# limits: this suite burned a shared wallet's MONTHLY custody allowance (100
# operations) and its daily connector quota in one evening, which then blocked
# unrelated work. A disposable wallet costs a little testnet NEAR and keeps the
# damage inside the run.
#
# WALLET_SEED and PAYMENT_KEY still override, for pointing the suite at a
# specific wallet deliberately.
if [[ -z "$WALLET_SEED" ]]; then
  WALLET_SEED="walletprobe-$(date +%s)-$$"
  MINTED=true
else
  MINTED=false
fi

# A FUNCTION, not a value: the token carries a timestamp and the coordinator
# refuses a stale one. Minted once at startup it expires partway through a run
# that waits on chain, and the failure then reads like a clock problem.
AUTH() {
  echo "Authorization: Bearer near:$("$RECOVERY_BIN" sign-bearer-near \
    --private-key "$PARENT_PRIVKEY" --account-id "$PARENT" --seed "$WALLET_SEED")"
}

# The policy this run needs, stored rather than assumed.
#
# W4 and W5 are a matched pair: one address inside the list and one outside, on
# the SAME wallet in the same run. Left to manual setup they drift apart, and a
# W5 that passes because the wallet forbids every transfer proves nothing about
# addresses.
#
# `addresses.list` with NO `mode` is the whitelist form — `mode: "none"` turns
# the filter off entirely, which is what `wallet_policy_mode_e2e.sh` covers.
store_policy() { # store_policy <policy-json>
  local pol=$1 body enc encb64 sg sig_hex pub_hex store_args
  body=$(jq -nc --arg wid "$WALLET_ID" --argjson p "$pol" '$p + {wallet_id:$wid}')
  enc=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/encrypt-policy" \
    -H "$(AUTH)" -H 'Content-Type: application/json' -d "$body")
  encb64=$(jq -r '.encrypted_base64 // empty' <<<"$enc")
  [[ -n "$encb64" ]] || { warn "encrypt-policy failed: $(head -c 200 <<<"$enc")"; return 1; }
  sg=$(curl -sS -X POST "$COORDINATOR_URL/wallet/v1/sign-policy" \
    -H "$(AUTH)" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg ed "$encb64" --arg c "$PARENT" '{encrypted_data:$ed, caller:$c}')")
  sig_hex=$(jq -r '.signature_hex // empty' <<<"$sg")
  pub_hex=$(jq -r '.public_key_hex // empty' <<<"$sg")
  [[ -n "$sig_hex" ]] || { warn "sign-policy failed: $(head -c 200 <<<"$sg")"; return 1; }
  store_args=$(jq -nc --arg pk "ed25519:$pub_hex" --arg ed "$encb64" --arg sg "$sig_hex" \
    '{wallet_pubkey:$pk, encrypted_data:$ed, wallet_signature:$sg}')
  # The CLI's own words, not just its exit code. The two curl steps above each
  # quote what failed; this one used to send everything to /dev/null, so a run
  # that died here said only "policy not stored" — a contract refusal, an
  # underfunded signer and a network pointed elsewhere all looked identical.
  local out rc=0
  out=$(near --quiet contract call-function as-transaction "${CONTRACT_ID:-outlayer.testnet}" store_wallet_policy \
    json-args "$store_args" prepaid-gas '100.0 Tgas' attached-deposit '0.1 NEAR' \
    sign-as "$PARENT" network-config "$NETWORK" sign-with-keychain send 2>&1) || rc=$?
  if (( rc != 0 )); then
    warn "store_wallet_policy failed (rc=$rc): $(tail -c 500 <<<"$out")"
    return 1
  fi
  sleep 5
}

chain_balance() {
  curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg a "$1" '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"view_account",finality:"final",account_id:$a}}')" \
    | jq -r '.result.amount // "0"' 2>/dev/null || echo 0
}

# probe <input-json> [extra curl args...] — echoes "<http> <body>".
probe() {
  local input=$1; shift
  local out http
  out=$(mktemp -t walletprobe.XXXXXX)
  http=$(curl -sS -m 300 -o "$out" -w '%{http_code}' -X POST "$COORDINATOR_URL/call/$PROJECT" \
    -H "X-Payment-Key: $PAYMENT_KEY" -H 'Content-Type: application/json' "$@" -d "$input")
  printf '%s %s\n' "$http" "$(tr -d '\n' < "$out")"
  rm -f "$out"
}

# ── the wallet under test ────────────────────────────────────────────────────
log "Reading the wallet"
R=$(curl -sS -m 30 -G "$COORDINATOR_URL/wallet/v1/address" --data-urlencode "chain=near" -H "$(AUTH)")
WALLET_ID=$(jq -r '.wallet_id // empty' <<<"$R")
ADDRESS=$(jq -r '.address // empty' <<<"$R")
[[ -n "$WALLET_ID" && -n "$ADDRESS" ]] \
  || { echo "✗ /wallet/v1/address failed: $(head -c 250 <<<"$R")" >&2; exit 1; }
note "wallet $WALLET_ID at $ADDRESS${MINTED:+ (minted for this run)}"

if [[ "$MINTED" == true ]]; then
  log "Funding the fresh wallet"
  near --quiet contract call-function as-transaction "$TOKEN_CONTRACT" storage_deposit \
    json-args "$(jq -nc --arg a "$ADDRESS" '{account_id:$a, registration_only:true}')" \
    prepaid-gas '30.0 Tgas' attached-deposit '0.00125 NEAR' \
    sign-as "$PARENT" network-config "$NETWORK" sign-with-keychain send >/dev/null 2>&1
  # WAIT FOR THE REGISTRATION TO BE VISIBLE before sending the tokens. A NEP-141
  # `ft_transfer` to an account the token has not registered yet is refused BY
  # THE TOKEN, and these two calls used to go out back to back with nothing
  # between them: run by hand, seconds apart, both succeed; run by the script,
  # the transfer overtakes its own registration. Its output went to /dev/null,
  # so the run showed a funded-looking wallet with no stablecoin in it and the
  # coordinator took the blame for answering `wallet_underfunded` correctly.
  REGISTERED=""
  for _ in $(seq 1 10); do
    REG=$(curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
      -d "$(jq -nc --arg t "$TOKEN_CONTRACT" --arg a "$(jq -nc --arg x "$ADDRESS" '{account_id:$x}' | base64)" \
          '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"call_function",finality:"final",account_id:$t,method_name:"storage_balance_of",args_base64:$a}}')" \
      | jq -r 'try (.result.result | implode) catch "null"' 2>/dev/null)
    [[ -n "$REG" && "$REG" != "null" ]] && { REGISTERED=$REG; break; }
    sleep 2
  done
  # Say which step failed, rather than falling through to send tokens that the
  # token contract will refuse. Left silent, the check further down reports "the
  # transfer never arrived" — true, but it names the wrong step, and the next
  # person goes looking at `ft_transfer` instead of at the registration it was
  # waiting on.
  [[ -n "$REGISTERED" ]] || {
    echo "✗ $TOKEN_CONTRACT never registered $ADDRESS (storage_balance_of stayed null for 20s)." >&2
    echo "  The storage_deposit from $PARENT did not land, so the ft_transfer below would be" >&2
    echo "  refused by the token — not by the coordinator." >&2
    exit 1
  }
  near --quiet contract call-function as-transaction "$TOKEN_CONTRACT" ft_transfer \
    json-args "$(jq -nc --arg a "$ADDRESS" --arg m "$FUND_USDC_MINIMAL" '{receiver_id:$a, amount:$m}')" \
    prepaid-gas '30.0 Tgas' attached-deposit '1 yoctoNEAR' \
    sign-as "$PARENT" network-config "$NETWORK" sign-with-keychain send >/dev/null 2>&1
  near --quiet tokens "$PARENT" send-near "$ADDRESS" "$FUND_NEAR NEAR" \
    network-config "$NETWORK" sign-with-keychain send >/dev/null 2>&1

  # WAIT FOR THE STABLECOIN, and say so when it never comes.
  #
  # `create-payment-key` reads the wallet's own token balance and refuses at 402
  # `wallet_underfunded` before doing anything else — so a funding transfer that
  # quietly failed came back as a coordinator error, and one run of this suite
  # was spent looking for a defect in a coordinator that had answered correctly.
  # It happens: the three sends above go out back to back on ONE access key, and
  # a `storage_deposit` that is not final yet, or a nonce that collides, takes
  # the `ft_transfer` down while the plain NEAR send after it succeeds. Their
  # output goes to /dev/null, so nothing says which.
  #
  # Polled rather than slept, because "not yet" and "never" look the same at a
  # fixed four seconds.
  FUNDED=""
  for _ in $(seq 1 10); do
    sleep 3
    HAVE=$(curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
      -d "$(jq -nc --arg t "$TOKEN_CONTRACT" --arg a "$(jq -nc --arg x "$ADDRESS" '{account_id:$x}' | base64)" \
          '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"call_function",finality:"final",account_id:$t,method_name:"ft_balance_of",args_base64:$a}}')" \
      | jq -r 'try (.result.result | implode | fromjson) catch "0"' 2>/dev/null | tr -d '"')
    [[ -n "$HAVE" && "$HAVE" != "null" ]] || HAVE=0
    if python3 -c "exit(0 if int('${HAVE:-0}') >= int('$FUND_USDC_MINIMAL') else 1)" 2>/dev/null; then
      FUNDED=$HAVE; break
    fi
  done
  [[ -n "$FUNDED" ]] || {
    echo "✗ the wallet never received its stablecoin (holds ${HAVE:-0} of $FUND_USDC_MINIMAL $TOKEN_CONTRACT)." >&2
    echo "  The funding transfer from $PARENT failed, not the coordinator: create-payment-key would" >&2
    echo "  answer 402 wallet_underfunded, which is the correct answer to an unfunded wallet." >&2
    exit 1
  }
  K=$(curl -sS -m 120 -X POST "$COORDINATOR_URL/wallet/v1/create-payment-key" \
        -H "$(AUTH)" -H 'Content-Type: application/json' \
        -d "$(jq -nc --arg d "$DEPOSIT_USDC" '{initial_deposit_usdc:$d}')")
  PAYMENT_KEY=$(jq -r '.payment_key // empty' <<<"$K")
  [[ -n "$PAYMENT_KEY" ]] \
    || { echo "✗ could not create a payment key for the fresh wallet: $(jq -r '.error // .message // .' <<<"$K" | head -c 200)" >&2; exit 1; }
  pass "minted and funded a wallet of this run's own — no shared limits are spent"
fi
[[ -n "$PAYMENT_KEY" ]] || { echo "✗ PAYMENT_KEY is required when WALLET_SEED names an existing wallet" >&2; exit 1; }

# The address W5 uses, fixed here because the readiness gate below needs the
# same one. Deliberately NOT derived from $PARENT: an outsider that is a
# subaccount of the owner leaves room to wonder whether some ownership rule let
# it through, and the answer to W5 must not need that argument.
OUTSIDER="${OUTSIDER:-}"
[[ -n "$OUTSIDER" ]] || { echo "✗ OUTSIDER=<an account NOT in the whitelist> is required for W5" >&2; exit 1; }

log "Storing the policy W4/W5 are a pair over: transfers allowed, $RECIPIENT whitelisted"
store_policy "$(jq -nc --arg r "$RECIPIENT" \
  '{rules:{transaction_types:["transfer","call"],addresses:{list:[$r]}}}')" \
  || { echo "✗ policy not stored — W4 and W5 would both be refused for the wrong reason" >&2; exit 1; }

# WAIT for it to bind, rather than sleeping and hoping.
#
# `store_wallet_policy` lands on chain and takes effect asynchronously, so a
# fixed sleep decides by coin toss whether the pair below is testing the policy
# it just wrote or the one before it. Either outcome then reads as a statement
# about custody, which is the worst way to be wrong about custody.
#
# The gate is the refusal itself, on the HTTPS path: it costs nothing, moves
# nothing, and is the very rule W5 asks the guest about a moment later — so
# reaching W5 at all means the list is live and a pass there is about the
# GUEST path rather than about timing.
log "Waiting for the address list to take effect"
BOUND=false
for _ in $(seq 1 20); do
  G=$(curl -sS -m 60 -X POST "$COORDINATOR_URL/wallet/v1/transfer" \
        -H "$(AUTH)" -H 'Content-Type: application/json' \
        -d "$(jq -nc --arg t "$OUTSIDER" '{chain:"near", to:$t, amount:"1"}')")
  if [[ "$(jq -r '.error // empty' <<<"$G")" == "policy_denied" ]]; then BOUND=true; break; fi
  sleep 5
done
if [[ "$BOUND" == true ]]; then
  pass "the wallet may transfer, and only to $RECIPIENT — the list is live"
else
  echo "✗ the address list never took effect: a transfer to $OUTSIDER was not refused." >&2
  echo "  W5 would then pass on a wallet with no filter at all, which is the defect it exists to catch." >&2
  exit 1
fi

# ── W1: no wallet named → the module must not start ──────────────────────────
#
# The refusal is the product's answer, so it is read from the body rather than
# from the status alone: a 4xx for a different reason (an unknown project, a
# rejected key) would pass a status-only check while proving nothing.
log "W1 calling WITHOUT X-Wallet-Id — the module imports wallet and must be refused"
R=$(probe '{"input":{"operation":"whoami"}}')
HTTP=${R%% *}; BODY=${R#* }
MSG=$(jq -r '(.error // "") + " " + (.message // "") + " " + ((.output.error // "")|tostring)' <<<"$BODY" 2>/dev/null)
if [[ "$HTTP" == 2?? ]] && [[ "$(jq -r '.output.ok // false' <<<"$BODY" 2>/dev/null)" == "true" ]]; then
  fail "W1 the module RAN without a wallet — every probe below would then be testing emptiness"
elif grep -qi "wallet is not available\|outlayer:wallet/api\|wallet.*not available" <<<"$MSG$BODY"; then
  pass "W1 refused, and the reason names the missing wallet"
else
  fail "W1 refused ($HTTP) but not for the wallet: $(head -c 200 <<<"$BODY")"
fi

WID_HDR="X-Wallet-Id: $WALLET_ID"

# ── W2: the host function and the environment agree ──────────────────────────
log "W2 whoami — the host function's wallet id equals WALLET_ID in the environment"
R=$(probe '{"input":{"operation":"whoami"}}' -H "$WID_HDR")
HTTP=${R%% *}; BODY=${R#* }
W_ID=$(jq -r '.output.wallet_id // empty' <<<"$BODY")
W_ENV=$(jq -r '.output.wallet_id_env // empty' <<<"$BODY")
if [[ -z "$W_ID" ]]; then
  fail "W2 no wallet_id came back ($HTTP): $(head -c 200 <<<"$BODY")"
else
  [[ "$W_ID" == "$WALLET_ID" ]] \
    && pass "W2 the host function names the wallet we asked for ($W_ID)" \
    || fail "W2 the host function names '$W_ID', we asked for '$WALLET_ID'"
  # The half that catches an environment written by something other than the
  # worker — the reason SYSTEM_ENV_VARS exists at all.
  [[ "$W_ENV" == "$W_ID" ]] \
    && pass "W2 WALLET_ID in the environment agrees with it" \
    || fail "W2 the environment says '$W_ENV' while the host function says '$W_ID' — something other than the worker set that variable"
fi

# ── W3: two roads to one fact ────────────────────────────────────────────────
log "W3 balance — the host function agrees with the HTTPS endpoints"
R=$(probe '{"input":{"operation":"balance"}}' -H "$WID_HDR")
BODY=${R#* }
G_ADDR=$(jq -r '.output.address // empty' <<<"$BODY")
G_BAL=$(jq -r '.output.balance // empty' <<<"$BODY")
H_BAL=$(curl -sS -m 30 -G "$COORDINATOR_URL/wallet/v1/balance" --data-urlencode "chain=near" -H "$(AUTH)" \
        | jq -r '.balance // empty')
[[ "$G_ADDR" == "$ADDRESS" ]] \
  && pass "W3 the address matches /wallet/v1/address ($G_ADDR)" \
  || fail "W3 the host function says '$G_ADDR', the endpoint says '$ADDRESS' — two roads to one fact, and they diverged"
if [[ -z "$G_BAL" || -z "$H_BAL" ]]; then
  fail "W3 a balance was missing (guest '$G_BAL', endpoint '$H_BAL')"
else
  # Not equality: the two reads are separated by a round trip, and gas spent in
  # between is a real difference that says nothing about agreement. Same
  # magnitude is the honest bar.
  [[ "${#G_BAL}" == "${#H_BAL}" ]] \
    && pass "W3 the balances agree in magnitude (guest $G_BAL, endpoint $H_BAL)" \
    || fail "W3 the balances differ by orders of magnitude: guest $G_BAL, endpoint $H_BAL"
fi

# ── W4: money moves, judged on chain ─────────────────────────────────────────
log "W4 transfer within policy — judged by the CHAIN, not by a status code"
BEFORE=$(chain_balance "$RECIPIENT")
R=$(probe "$(jq -nc --arg t "$RECIPIENT" --arg a "$XFER_YOCTO" \
      '{input:{operation:"transfer", to:$t, amount:$a}}')" -H "$WID_HDR")
BODY=${R#* }
OK=$(jq -r '.output.ok // false' <<<"$BODY")
RESULT=$(jq -r '.output.result // empty' <<<"$BODY")
CODE=$(jq -r '.output.error_parsed.code // empty' <<<"$BODY")
sleep 6
AFTER=$(chain_balance "$RECIPIENT")
# `ok` IS NOT THE OUTCOME. The module documents it as "whether the ANSWER was
# well formed — not whether it was yes", because a refusal an agent can route
# on is a working interface. So a correct `policy_denied` also arrives with
# `ok: true`, and reading it as success made this pair report the whitelist as
# broken while the product was enforcing it exactly right.
#
# What separates them is `error_parsed.code`: present means refused, absent
# plus a `result` means it went through.
if [[ "$OK" != "true" ]]; then
  fail "W4 the answer was malformed: $(jq -r '.output.detail // empty' <<<"$BODY" | head -c 160)"
elif [[ -n "$CODE" ]]; then
  fail "W4 refused as '$CODE': $(jq -r '.output.detail // empty' <<<"$BODY" | head -c 160). Is $RECIPIENT inside the wallet's policy?"
else
  pass "W4 the guest reports a receipt rather than silence"
  [[ -n "$RESULT" ]] \
    && pass "W4 the result carries something to poll: $(head -c 80 <<<"$RESULT")" \
    || fail "W4 no code and no result — the call said nothing, and silence is not a receipt"
  [[ "$AFTER" != "$BEFORE" ]] \
    && pass "W4 the chain moved ($BEFORE → $AFTER)" \
    || fail "W4 the chain did NOT move; the guest reported a receipt for a transfer that never happened"
fi

# ── W5: a refusal an agent can route on ──────────────────────────────────────
log "W5 transfer OUTSIDE policy — the refusal must carry a machine code"
R=$(probe "$(jq -nc --arg t "$OUTSIDER" --arg a "$XFER_YOCTO" \
      '{input:{operation:"transfer", to:$t, amount:$a}}')" -H "$WID_HDR")
BODY=${R#* }
OK=$(jq -r '.output.ok // false' <<<"$BODY")
CODE=$(jq -r '.output.error_parsed.code // empty' <<<"$BODY")
RESULT=$(jq -r '.output.result // empty' <<<"$BODY")
# Judged on the code, never on `ok` — see W4.
if [[ "$OK" != "true" ]]; then
  fail "W5 the answer was malformed: $(jq -r '.output.detail // empty' <<<"$BODY" | head -c 160)"
elif [[ -z "$CODE" && -n "$RESULT" ]]; then
  fail "W5 the transfer to '$OUTSIDER' WENT THROUGH — the address policy did not bind"
elif [[ "$CODE" == "policy_denied" ]]; then
  pass "W5 refused as '$CODE' — an agent can branch on this without reading prose"
elif [[ -n "$CODE" ]]; then
  fail "W5 refused as '$CODE', expected policy_denied: $(jq -r '.output.detail // empty' <<<"$BODY" | head -c 160)"
else
  # The failure this probe exists for: a refusal with no code is a sentence, and
  # an agent can only log it.
  fail "W5 the refusal carries NO machine code — nothing to route on: $(jq -r '.output.detail // .output.error // empty' <<<"$BODY" | head -c 200)"
fi

# ── W6: wallet_busy, and the id it hands out is readable ─────────────────────
#
# Not reproducible inside one guest: the host functions block, so one module's
# calls never overlap. Somebody else must hold the wallet — here a slower
# operation started just before, with the guest called inside its window.
log "W6 wallet_busy — hold the wallet, then transfer inside the window"
# A STREAM, not one operation. A single holder finishes long before the guest
# reaches its host call — the guest's request has to be queued, picked up by a
# worker and instantiated first — so a lone holder loses the race every time
# and the probe reports "not reproduced" forever. What is needed is for the
# wallet to be busy at an unknown moment, so it is kept busy throughout.
#
# Every one of these moves real money to $RECIPIENT, which is why the amount is
# small and the loop is bounded.
# TWO loops, back to back, no sleep between them.
#
# One transfer holds the wallet for about 2.5 seconds and the gap between two
# is what the guest slips through: a single loop with a 2-second pause leaves
# the wallet free almost half the time, and this probe missed twice in a row on
# exactly that. Two overlapping loops keep something in flight continuously, so
# the guest arrives during a hold rather than by luck.
#
# Measured, not assumed: a second transfer started 0.3 s into a first is
# refused `409 wallet_busy` with an `in_flight_request_id`.
HOLD_FLAG=$(mktemp -t walletbusy.XXXXXX)
# The token is minted ONCE for the loop rather than per iteration. `AUTH()`
# shells out to a binary, and paying that cost between every transfer left
# gaps wide enough for the guest to walk through — the probe reported "not
# reproduced" twice with the loops apparently saturated. The loop lives well
# under a minute, so one token stays fresh for all of it.
HOLD_AUTH="$(AUTH)"
HOLD_BODY=$(jq -nc --arg t "$RECIPIENT" --arg a "$XFER_YOCTO" '{chain:"near", to:$t, amount:$a}')
hold_loop() {
  while [[ -f "$HOLD_FLAG" ]]; do
    curl -sS -m 60 -X POST "$COORDINATOR_URL/wallet/v1/transfer" \
      -H "$HOLD_AUTH" -H 'Content-Type: application/json' -d "$HOLD_BODY" >/dev/null 2>&1
  done
}
# RETRIED, because the race is genuinely about even.
#
# Measured: with two saturating loops and eight holder transfers fired while
# the guest ran, the guest still got through — and on an identical attempt
# minutes earlier it was refused. Both loops are between requests at the same
# instant often enough to matter. One attempt therefore decides by coin toss
# whether a real contract is reported as unproven, which is worse than slow.
CODE=""; INFLIGHT=""; INFLIGHT_OP=""; BODY=""
for attempt in 1 2 3 4; do
  : > "$HOLD_FLAG"
  hold_loop & HOLD1=$!
  hold_loop & HOLD2=$!
  # Let saturation establish before the guest is asked for anything, so the
  # window it meets is a hold rather than a gap.
  sleep 3
  R=$(probe "$(jq -nc --arg t "$RECIPIENT" --arg a "$XFER_YOCTO" \
        '{input:{operation:"transfer", to:$t, amount:$a}}')" -H "$WID_HDR")
  rm -f "$HOLD_FLAG"
  wait "$HOLD1" "$HOLD2" 2>/dev/null
  BODY=${R#* }
  CODE=$(jq -r '.output.error_parsed.code // empty' <<<"$BODY")
  INFLIGHT=$(jq -r '.output.error_parsed.in_flight_request_id // empty' <<<"$BODY")
  INFLIGHT_OP=$(jq -r '.output.error_parsed.in_flight_operation // empty' <<<"$BODY")
  [[ "$CODE" == "wallet_busy" ]] && break
  note "W6 attempt $attempt: the guest slipped through the gap; trying again"
done
if [[ "$CODE" != "wallet_busy" ]]; then
  # Losing the race is not a product failure, and calling it one would make this
  # probe flap. It IS an unproven contract, and that is what gets reported.
  warn "W6 NOT REPRODUCED this run — the guest saw '${CODE:-success}' rather than wallet_busy."
  warn "W6 the window is the holder's round trip; re-run, or start a slower holding operation."
  note "W6 counts as neither passed nor failed: the contract stays unproven"
else
  pass "W6 the guest saw wallet_busy"
  # TWO valid shapes, and the difference is not a defect.
  #
  # The coordinator withholds the id until the holder's request row is written
  # — one handed out earlier answers 404, which reads as a request that was
  # lost. So a holder has two windows of roughly equal length: the keystore
  # round trip before its INSERT, and the broadcast after it. The guest fires
  # immediately behind the holder and lands in either.
  #
  # Landing in the first is CORRECT behaviour and used to be reported here as
  # "arrived WITHOUT in_flight_request_id" — the very sentence that started the
  # investigation — which would have made this probe flap between red and green
  # on identical builds. What is actually broken is being told neither.
  if [[ -z "$INFLIGHT" && -n "$INFLIGHT_OP" ]]; then
    pass "W6 no id yet, and it says what to wait for ($INFLIGHT_OP) — the row is not written yet"
    note "W6 the id half is unproven this run: the guest met the holder before its INSERT"
  elif [[ -z "$INFLIGHT" ]]; then
    # Every path that takes the wallet names its operation, and the database
    # fallback reads one off the row — so on matching versions this is left only
    # for the sliver between acquiring the lock and announcing, which no real
    # caller lands in twice. Read it as a defect, not as a race.
    fail "W6 wallet_busy carried NEITHER an id nor an operation — the agent is told to wait, and not told for what nor for how long"
  else
    pass "W6 it names the holding request ($INFLIGHT${INFLIGHT_OP:+, a $INFLIGHT_OP})"
    # The second half, which nothing else tests: an id that cannot be read back
    # is a dead end wrapped in an instruction.
    R2=$(probe "$(jq -nc --arg id "$INFLIGHT" '{input:{operation:"request_status", request_id:$id}}')" -H "$WID_HDR")
    B2=${R2#* }
    # `ok` is the answer here, and for once it IS the outcome: `request_status`
    # sets it from whether a status was found, because "no status" is not an
    # answer to somebody polling. The status itself is reported in `detail` —
    # there is no `.status` field, and looking for one failed this probe on a
    # run where the contract held perfectly.
    if [[ "$(jq -r '.output.ok // false' <<<"$B2")" == "true" ]]; then
      pass "W6 and that id reads back: $(jq -r '.output.detail // empty' <<<"$B2" | head -c 120)"
    else
      fail "W6 request_status on '$INFLIGHT' found no status: $(jq -r '.output.detail // empty' <<<"$B2" | head -c 160)"
    fi
  fi
fi

# ── W7: the header confirms, never selects ───────────────────────────────────
log "W7 X-Wallet-Id naming somebody ELSE's wallet"
if [[ -z "$STRANGER_WALLET" ]]; then
  note "W7 SKIPPED — set STRANGER_WALLET=<a wallet id that is not this one> to run it"
else
  R=$(probe '{"input":{"operation":"whoami"}}' -H "X-Wallet-Id: $STRANGER_WALLET")
  HTTP=${R%% *}; BODY=${R#* }
  GOT=$(jq -r '.output.wallet_id // empty' <<<"$BODY")
  if [[ "$GOT" == "$STRANGER_WALLET" ]]; then
    fail "W7 the header SELECTED a wallet the credential does not name — custody authority handed to whoever typed the id"
  elif [[ "$HTTP" == 2?? && -n "$GOT" ]]; then
    fail "W7 the call ran on '$GOT' after naming '$STRANGER_WALLET' — the mismatch was ignored rather than refused"
  else
    pass "W7 refused ($HTTP): $(jq -r '.error // .message // empty' <<<"$BODY" | head -c 140)"
  fi
fi

printf '\n\033[1m%d passed, %d failed\033[0m\n' "$PASS" "$FAILED" >&2
for n in "${FAILED_NAMES[@]:-}"; do [[ -n "$n" ]] && printf '  \033[31m✗ %s\033[0m\n' "$n" >&2; done
[[ "$FAILED" -eq 0 ]]
