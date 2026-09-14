#!/usr/bin/env bash
#
# Who may call what, with which credential — the whole matrix, on one stack.
#
# There is ONE paying credential now: a payment key, presented as
# `X-Payment-Key`. `wk_` authenticates a wallet to `/wallet/v1/*` and names it;
# it does not pay. Agent payment keys — keyless keys resolved from a `wk_` —
# were removed on 2026-08-21 because nothing was left that needed them.
#
# That leaves three ways a call can arrive and two kinds of project, and this
# runs all six. The trial is the interesting row: it is a real payment key with
# a scope, so it reaches a connector and is REFUSED on a plain project — free
# execution exists for trying connectors, not for running arbitrary code.
#
#             │ connector project      │ ordinary WASI project
#   ──────────┼────────────────────────┼───────────────────────────
#   no key    │ 401 missing_payment_key│ 401 missing_payment_key
#   trial key │ runs                   │ 403 project_not_allowed
#   paid key  │ runs                   │ runs
#
# What each probe pins:
#   K1  no credential is refused on BOTH kinds of project, with the same answer.
#       A route that answered differently would tell a stranger which projects
#       exist
#   K2  a `wk_` is not a payment credential, and the refusal SAYS SO. Three
#       parts: the wallet credential works against `/wallet/v1/*` in the same
#       run (K2), a `wk_` on `/call` is refused and told what it is (K2b), and
#       a caller with no payment credential still gets the plain answer (K2c),
#       without which K2b would pass on a door that says the same thing to
#       everyone
#   K3  a trial key reaches a connector
#   K4  the same trial key is refused on an ordinary project, by SCOPE and not
#       by balance — the refusal names the project, and must not read as one a
#       top-up would cure
#   K5  a funded payment key reaches a connector
#   K6  and the same key reaches an ordinary project
#
# K2 is the one that would rot silently: restoring `wk_` as a payer is a small,
# well-meaning change, and every other probe here would still pass.
#
# Money: claims this account's one trial (a real claim — it cannot be undone or
# repeated) and creates one funded payment key. Connector calls cost their
# operation price; `ping` is priced at zero, which is what this uses.
#
# Requires: $PARENT with a keychain credential, `outlayer` logged in as $PARENT,
# and enough of $TOKEN_CONTRACT on $PARENT to fund one payment key — the script
# sends it to the wallet itself, because a wallet with no stablecoin cannot
# create one and K5/K6 would then be skipped rather than run.
#
# Run (spends real testnet NEAR and one trial claim):
#   PARENT=you.testnet ./tests/call_credentials_e2e.sh --apply

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPLY=false
[[ "${1:-}" == "--apply" ]] && APPLY=true

NETWORK="${NETWORK:-testnet}"
COORDINATOR_URL="${COORDINATOR_URL:-https://testnet-api.outlayer.ai}"
CONNECTOR="${CONNECTOR:-connectors.outlayer.testnet/connector-probe}"
# An ordinary project: outside the connector namespace, so a trial's scope does
# not reach it. Which module it is does not matter — the refusal happens before
# anything runs.
ORDINARY="${ORDINARY:-zavodil.testnet/wallet-probe}"
PARENT="${PARENT:-}"
DEPOSIT_USDC="${DEPOSIT_USDC:-0.30}"
FUND_NEAR="${FUND_NEAR:-0.3}"
TOKEN_CONTRACT="${TOKEN_CONTRACT:-usdc.fakes.testnet}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/rpc.sh"   # keyed RPC_URL, or a warning

PASS=0; FAILED=0; FAILED_NAMES=()
log()  { printf '\n\033[36m▶ %s\033[0m\n' "$*" >&2; }
note() { printf '\033[35m• %s\033[0m\n' "$*" >&2; }
warn() { printf '\033[33m⚠ %s\033[0m\n' "$*" >&2; }
pass() { printf '\033[32m✓ %s\033[0m\n' "$*" >&2; PASS=$((PASS+1)); }
fail() { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; FAILED=$((FAILED+1)); FAILED_NAMES+=("$*"); }

if [[ "$APPLY" != true ]]; then
  sed -n '3,45p' "$0" >&2
  echo "  Pass --apply to run." >&2
  exit 0
fi

[[ -n "$PARENT" ]] || { echo "USAGE: PARENT=you.testnet $0 --apply" >&2; exit 1; }
for tool in jq curl outlayer cargo near openssl python3; do
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

SEED="callcred-$(date +%s)-$$"

# TWO DIFFERENT CREDENTIALS, and the difference is the point of K2.
#
# AUTH() mints a NEAR-signed bearer: `Bearer near:<token>`, which is how a wallet
# owner authenticates to `/wallet/v1/*` from a keychain. $WK is a `wk_` — the
# wallet API key. This script used to build only the first and call it "the
# wallet's wk_" throughout, so the probe that claims a `wk_` cannot pay was
# never presenting one; it proved something about a different credential and
# said nothing about the one it named.
#
# The `wk_` is REGISTERED, not merely well-shaped. An unregistered one is
# refused by `/call` too — that door decides while parsing the header — but it
# could not then be shown to WORK anywhere, and "it buys nothing" is only
# interesting about a credential that buys nothing WHILE BEING VALID.
# Registering it also unlocks `/trial-key`, which takes a `wk_` and nothing
# else, deliberately: it is the credential the wallet already holds, so a trial
# costs the caller no new secret.
# A FUNCTION, not a value. The token carries a timestamp and the coordinator
# refuses a stale one — minted once at startup it expired partway through a run
# that had grown a funding step, and the key creation failed as
# `timestamp_expired`, which reads like a clock problem rather than a script
# holding a token too long.
AUTH() {
  echo "Authorization: Bearer near:$("$RECOVERY_BIN" sign-bearer-near \
    --private-key "$PARENT_PRIVKEY" --account-id "$PARENT" --seed "$SEED")"
}

# `PUT /wallet/v1/api-key` under a Bearer derives a SUB-wallet from
# (this wallet, sub-seed) rather than keying the wallet above — which is what
# this wants: the sub-wallet is fresh, so its one trial is unclaimed.
WK_SEED="$SEED-sub"
WK_KEY="wk_$(openssl rand -hex 32)"
WK_HASH=$(printf '%s' "$WK_KEY" | shasum -a 256 | cut -d' ' -f1)
WK="Authorization: Bearer $WK_KEY"

# call <project> [auth-header] — echoes "<http> <body>". An empty (or absent)
# header means "send none", which is K1.
#
# Two branches rather than an array of flags: bash 3.2 is what `bash` is on
# macOS, and expanding an EMPTY array under `set -u` there aborts the script
# with `args[@]: unbound variable`. The one probe that passes no header is K1 —
# so the credential-less case would take the whole run down before its first
# request, and a syntax check would not see it, because the line is valid.
call() {
  local project=$1 header=${2:-} out http
  out=$(mktemp -t callcred.XXXXXX)
  if [[ -n "$header" ]]; then
    http=$(curl -sS -m 300 -o "$out" -w '%{http_code}' -X POST "$COORDINATOR_URL/call/$project" \
      -H "$header" -H 'Content-Type: application/json' -d '{"input":{"operation":"ping"}}')
  else
    http=$(curl -sS -m 300 -o "$out" -w '%{http_code}' -X POST "$COORDINATOR_URL/call/$project" \
      -H 'Content-Type: application/json' -d '{"input":{"operation":"ping"}}')
  fi
  printf '%s %s\n' "$http" "$(tr -d '\n' < "$out")"
  rm -f "$out"
}
code_of() { jq -r '.error // empty' <<<"$1" 2>/dev/null; }

# ── register the wk_ ─────────────────────────────────────────────────────────
log "Registering a wk_ for a fresh sub-wallet"
R=$(curl -sS -m 60 -X PUT "$COORDINATOR_URL/wallet/v1/api-key" \
      -H "$(AUTH)" -H 'Content-Type: application/json' \
      -d "$(jq -nc --arg s "$WK_SEED" --arg h "$WK_HASH" '{seed:$s, key_hash:$h}')")
WK_WALLET=$(jq -r '.wallet_id // empty' <<<"$R")
if [[ -n "$WK_WALLET" ]]; then
  note "wk_ registered for sub-wallet $WK_WALLET"
else
  warn "wk_ not registered: $(jq -r '.error // .message // .' <<<"$R" | head -c 200)"
fi

# ── K1: no credential, on both kinds of project ──────────────────────────────
log "K1 no credential at all"
for project in "$CONNECTOR" "$ORDINARY"; do
  R=$(call "$project" ""); HTTP=${R%% *}; BODY=${R#* }
  if [[ "$HTTP" == "401" ]]; then
    pass "K1 $project refused without a credential (401)"
  else
    fail "K1 $project answered $HTTP without a credential — a call must be paid for before it runs"
  fi
done

# ── K2: a wk_ is not a payment credential ────────────────────────────────────
#
# Proven in two halves, and the second is what makes it a test rather than an
# observation: the same `wk_` is shown to authenticate a wallet route in the
# same run. Without that, a broken token would produce this result too.
log "K2 a wk_ authenticates a wallet but pays for nothing"
R=$(curl -sS -m 30 -o /dev/null -w '%{http_code}' "$COORDINATOR_URL/wallet/v1/address?chain=near" -H "$WK")
if [[ "$R" == "200" ]]; then
  pass "K2 the wk_ is live: /wallet/v1/address answers 200 with it"
else
  fail "K2 the wk_ does not authenticate at all ($R) — the rest of K2 would prove nothing, because a rejected token buys nothing either"
fi

R=$(call "$CONNECTOR" "$WK"); HTTP=${R%% *}; BODY=${R#* }
if [[ "$HTTP" == "401" ]]; then
  pass "K2 and it buys nothing: the connector call is refused (401)"
else
  fail "K2 a wk_ paid for a call ($HTTP) — the removed second credential is back"
fi

# K2b — the refusal names the mistake that was made.
#
# The status alone passed throughout a period when the answer was "Missing
# X-Payment-Key header": true, and useless to the one caller most likely to hit
# it. A wallet that sent a credential is not a caller who forgot one, and
# "missing" reads as "send it again" when sending it again cannot work.
#
# Needs a coordinator built after 2026-08-21; before that this is the old text.
MSG=$(jq -r '.error // .message // ""' <<<"$BODY" 2>/dev/null)
if grep -qi "does not pay\|identifies a wallet" <<<"$MSG"; then
  pass "K2b the refusal says what a wk_ is: $(head -c 90 <<<"$MSG")"
else
  fail "K2b the refusal is '$(head -c 90 <<<"$MSG")' — it does not tell a wallet that the credential it sent cannot pay, so the answer reads as a forgotten header"
fi

# K2c — the control that makes K2b mean something.
#
# A caller who sent NO payment credential at all still gets the plain answer.
# Without this, K2b would be satisfied by a door that gave the `wk_` wording to
# everybody, which is the same undifferentiated answer in a nicer sentence.
R=$(call "$CONNECTOR" "$(AUTH)"); HTTP=${R%% *}; BODY=${R#* }
MSG=$(jq -r '.error // .message // ""' <<<"$BODY" 2>/dev/null)
if [[ "$HTTP" == "401" ]] && ! grep -qi "does not pay" <<<"$MSG"; then
  pass "K2c a credential that is not a wk_ gets the plain answer — the two mistakes are told apart"
else
  fail "K2c a non-wk_ credential answered $HTTP with '$(head -c 90 <<<"$MSG")'; K2b proves nothing if every caller hears the same thing"
fi

# ── the wallet must hold stablecoin before it can buy a key ──────────────────
#
# `create-payment-key` reads the wallet's own token balance and refuses at 402
# before doing anything else, so without this K5/K6 were SKIPPED on every run —
# four of the six cells in the matrix above unexercised, reported as a note.
log "Funding the wallet so it can create a key"
ADDR=$(curl -sS -m 30 -G "$COORDINATOR_URL/wallet/v1/address" --data-urlencode chain=near -H "$(AUTH)" \
        | jq -r '.address // empty')
if [[ -z "$ADDR" ]]; then
  warn "no wallet address — K5/K6 will be skipped"
else
  DEC=$(curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
        -d "$(jq -nc --arg a "$TOKEN_CONTRACT" '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"call_function",finality:"final",account_id:$a,method_name:"ft_metadata",args_base64:"e30="}}')" \
        | jq -r '(.result.result | implode | fromjson).decimals // 6')
  AMT=$(python3 -c "print(int(float('$DEPOSIT_USDC') * 10**$DEC))")
  near --quiet contract call-function as-transaction "$TOKEN_CONTRACT" storage_deposit \
    json-args "$(jq -nc --arg a "$ADDR" '{account_id:$a, registration_only:true}')" \
    prepaid-gas '30.0 Tgas' attached-deposit '0.00125 NEAR' \
    sign-as "$PARENT" network-config "$NETWORK" sign-with-keychain send >/dev/null 2>&1
  near --quiet contract call-function as-transaction "$TOKEN_CONTRACT" ft_transfer \
    json-args "$(jq -nc --arg a "$ADDR" --arg m "$AMT" '{receiver_id:$a, amount:$m}')" \
    prepaid-gas '30.0 Tgas' attached-deposit '1 yoctoNEAR' \
    sign-as "$PARENT" network-config "$NETWORK" sign-with-keychain send >/dev/null 2>&1
  # And gas. Creating a payment key is signed BY the wallet — a `store_secrets`
  # on chain plus an `ft_transfer_call` — so stablecoin alone leaves it able to
  # pay for the key and unable to send the transaction that buys it.
  near --quiet tokens "$PARENT" send-near "$ADDR" "$FUND_NEAR NEAR" \
    network-config "$NETWORK" sign-with-keychain send >/dev/null 2>&1
  note "sent $DEPOSIT_USDC of $TOKEN_CONTRACT and $FUND_NEAR NEAR to $ADDR"
  sleep 4
fi

# ── the two keys ─────────────────────────────────────────────────────────────
log "Claiming the trial and creating a funded key"
R=$(curl -sS -m 60 -X POST "$COORDINATOR_URL/trial-key" -H "$WK")
TRIAL_ANSWER="$R"
TRIAL=$(jq -r '.payment_key // empty' <<<"$R")
TRIAL_SCOPE=$(jq -r '(.project_ids // []) | join(",")' <<<"$R")
if [[ -n "$TRIAL" ]]; then
  note "trial claimed, scope: ${TRIAL_SCOPE:-<none>}"
else
  warn "trial not claimed: $(jq -r '.error // .message // .' <<<"$R" | head -c 160)"
fi

R=$(curl -sS -m 90 -X POST "$COORDINATOR_URL/wallet/v1/create-payment-key" \
      -H "$(AUTH)" -H 'Content-Type: application/json' \
      -d "$(jq -nc --arg d "$DEPOSIT_USDC" '{initial_deposit_usdc:$d}')")
PAID_ANSWER="$R"
PAID=$(jq -r '.payment_key // empty' <<<"$R")
if [[ -n "$PAID" ]]; then
  note "payment key created, nonce $(jq -r '.nonce' <<<"$R")"
else
  warn "payment key not created: $(jq -r '.error // .message // .' <<<"$R" | head -c 160)"
fi

# ── K3 / K4: the trial reaches connectors and nothing else ───────────────────
if [[ -z "$TRIAL" ]]; then
  # The reason is quoted from the answer rather than guessed. It read
  # "already claimed on this account?" through a run whose real cause was an
  # auth-shape mismatch, which sent the reader looking in the wrong place.
  note "K3/K4 SKIPPED — no trial key. The endpoint said: $(jq -r '.error // .message // .' <<<"$TRIAL_ANSWER" | head -c 160)"
else
  log "K3 trial key on a connector"
  R=$(call "$CONNECTOR" "X-Payment-Key: $TRIAL"); HTTP=${R%% *}; BODY=${R#* }
  if [[ "$HTTP" == 2?? ]]; then
    pass "K3 the trial ran a connector call"
  else
    fail "K3 the trial was refused on a connector ($HTTP $(code_of "$BODY")): $(jq -r '.message // empty' <<<"$BODY" | head -c 140)"
  fi

  log "K4 the same trial key on an ordinary project"
  R=$(call "$ORDINARY" "X-Payment-Key: $TRIAL"); HTTP=${R%% *}; BODY=${R#* }
  CODE=$(code_of "$BODY")
  # The REASON matters as much as the refusal: a scope refusal says "this key
  # was never for that", while a balance refusal would say "top it up" and send
  # the caller down a road that does not exist.
  #
  # Matched on the TEXT, because this door has no machine code to match on:
  # `/call` puts the human sentence in `.error` and sends no second field,
  # while `/wallet/v1/*` sends `{error: <snake_code>, message: <sentence>}`.
  # This probe expected the snake code and so reported a correct refusal as a
  # wrong one. `project_not_allowed` exists only as an internal name.
  if [[ "$HTTP" == 2?? ]]; then
    fail "K4 the trial ran an ordinary project — free execution is not supposed to exist"
  elif grep -qi "project not allowed" <<<"$CODE"; then
    # And NOT for money: a trial that was merely out of funds would say so, and
    # topping it up would then look like the fix. It is not one — the scope is
    # what refuses, and no balance changes it.
    if grep -qiE "balance|insufficient|fund" <<<"$CODE"; then
      fail "K4 the refusal mentions money ('$CODE') — a scope refusal must not read as one a top-up would cure"
    else
      pass "K4 refused by SCOPE — a trial buys connectors, not arbitrary code"
    fi
  else
    fail "K4 refused as '$CODE' ($HTTP), which does not name the project scope"
  fi
fi

# ── K5 / K6: a funded key reaches both ───────────────────────────────────────
if [[ -z "$PAID" ]]; then
  note "K5/K6 SKIPPED — no payment key was created. The endpoint said: $(jq -r '.error // .message // .' <<<"$PAID_ANSWER" | head -c 160)"
else
  log "K5 funded key on a connector"
  R=$(call "$CONNECTOR" "X-Payment-Key: $PAID"); HTTP=${R%% *}; BODY=${R#* }
  [[ "$HTTP" == 2?? ]] \
    && pass "K5 the funded key ran a connector call" \
    || fail "K5 refused ($HTTP $(code_of "$BODY")): $(jq -r '.message // empty' <<<"$BODY" | head -c 140)"

  log "K6 funded key on an ordinary project"
  R=$(call "$ORDINARY" "X-Payment-Key: $PAID"); HTTP=${R%% *}; BODY=${R#* }
  CODE=$(code_of "$BODY")
  # `wallet-probe` refuses a run with no wallet attached, which is its own
  # contract and not a credential problem — the credential got that far.
  if [[ "$HTTP" == 2?? ]]; then
    pass "K6 the funded key ran an ordinary project"
  elif grep -qi "wallet is not available" <<<"$BODY"; then
    pass "K6 the credential was accepted; the module refused for its own reason (no wallet attached)"
  else
    fail "K6 refused as '$CODE': $(jq -r '.message // empty' <<<"$BODY" | head -c 160)"
  fi
fi

# ── verdict ──────────────────────────────────────────────────────────────────
log "call credentials — $PASS passed, $FAILED failed"
if (( FAILED > 0 )); then
  for n in "${FAILED_NAMES[@]}"; do printf '  \033[31m✗ %s\033[0m\n' "$n" >&2; done
  exit 1
fi
exit 0
