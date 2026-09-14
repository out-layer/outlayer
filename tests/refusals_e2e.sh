#!/usr/bin/env bash
#
# The endpoints that exist to say NO, and were never tested.
#
# `/wallet/v1/reject` is named in no test file in this repository. Neither are
# `/internal/wallet-policy-delete` and `/internal/wallet-frozen-change`, which
# change what a wallet is allowed to do at all. `/wallet/v1/delete` is
# exercised, but only ever toward a beneficiary the policy permits — and it is
# the one operation that moves the WHOLE balance in a single call, so the
# address rule matters there more than any amount limit.
#
# An untested refusal is worse than an untested feature: a feature that stops
# working gets reported by whoever used it, while a refusal that stops
# refusing is silent until it matters.
#
# Probes:
#   N1  reject with a signature over ANOTHER request's hash is refused — the
#       vote is bound to the operation, not just to the approval id
#   N2  reject with no signature, and with a corrupt one, are refused
#   N3  reject from a STRANGER over a well-formed message is stored (200):
#       the coordinator takes the vote from anyone by design and the KEYSTORE
#       honours a veto only from a real approver. Pins the documented split, so
#       that "anyone can reject" and "anyone can veto" stay different claims
#   N4  /internal/wallet-policy-delete without the internal token is refused,
#       and so is a wrong token
#   N5  /internal/wallet-frozen-change, same
#   N6  /wallet/v1/delete toward a beneficiary OUTSIDE allowed_recipients is
#       refused — the whole balance, one call, one address rule
#
# N4/N5 assert only the auth gate. Driving the endpoints successfully needs the
# real internal token, and a test that carried one would be a test that could
# freeze a wallet by accident.
#
# Run (spends testnet NEAR for the wallet it mints):
#   PARENT=you.testnet ./tests/refusals_e2e.sh --apply

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPLY=false
[[ "${1:-}" == "--apply" ]] && APPLY=true

NETWORK="${NETWORK:-testnet}"
CONTRACT_ID="${CONTRACT_ID:-outlayer.testnet}"
COORDINATOR_URL="${COORDINATOR_URL:-https://testnet-api.outlayer.ai}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/rpc.sh"   # keyed RPC_URL, or a warning
PARENT="${PARENT:-}"
APPROVER="${APPROVER:-$PARENT}"
FUND_NEAR="0.12"
SPEND="1000000000000000000000"   # 0.001 NEAR — enough to need an approval

PASS=0; FAILED=0; FAILED_NAMES=()
log()  { printf '\n\033[36m▶ %s\033[0m\n' "$*" >&2; }
note() { printf '\033[35m• %s\033[0m\n' "$*" >&2; }
warn() { printf '\033[33m⚠ %s\033[0m\n' "$*" >&2; }
pass() { printf '\033[32m✓ %s\033[0m\n' "$*" >&2; PASS=$((PASS+1)); }
fail() { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; FAILED=$((FAILED+1)); FAILED_NAMES+=("$*"); }

if [[ "$APPLY" != true ]]; then
  sed -n '3,34p' "$0" >&2
  echo "  Pass --apply to run." >&2
  exit 0
fi

[[ -n "$PARENT" ]] || { echo "USAGE: PARENT=you.testnet $0 --apply" >&2; exit 1; }
for tool in jq curl near cargo python3 rev; do
  command -v "$tool" >/dev/null || { echo "✗ missing $tool" >&2; exit 1; }
done
CREDS_DIR="$HOME/.near-credentials/$NETWORK"
[[ -f "$CREDS_DIR/$PARENT.json" ]] || { echo "✗ creds missing: $CREDS_DIR/$PARENT.json" >&2; exit 1; }
export OUTLAYER_NETWORK="$NETWORK"
PARENT_PRIVKEY=$(jq -r '.private_key' "$CREDS_DIR/$PARENT.json")
PARENT_PUBKEY=$(jq -r '.public_key' "$CREDS_DIR/$PARENT.json")

RECOVERY_BIN="$SCRIPT_DIR/../scripts/customer-recovery/target/release/customer-recovery"
log "Building customer-recovery (sign-bearer-near, sign-nep413)"
(cd "$SCRIPT_DIR/../scripts/customer-recovery" && cargo build --release --quiet) \
  || { echo "✗ customer-recovery build failed" >&2; exit 1; }

near_tty() {
  if command -v script >/dev/null 2>&1 && [ -t 1 ]; then
    local tmp; tmp=$(mktemp -t refusals_cmd.XXXXXX.sh)
    printf 'set -euo pipefail\n%s\n' "$*" > "$tmp"
    script -q /dev/null bash "$tmp"; local rc=$?; rm -f "$tmp"; return $rc
  else eval "$@"; fi
}
mk_token() { "$RECOVERY_BIN" sign-bearer-near --private-key "$PARENT_PRIVKEY" --account-id "$PARENT" --seed "$1"; }
AUTH()  { echo "Authorization: Bearer near:$(mk_token "$1")"; }
nonce() { head -c 32 /dev/urandom | base64 | tr -d '\n'; }

# Writes "<http_code> <body>" so a probe can judge both.
req() { # req <method> <path> <auth-header|""> <json-body|"">
  local m=$1 path=$2 auth=$3 body=$4 out code
  out=$(mktemp -t refusals_out.XXXXXX)
  if [[ -n "$auth" ]]; then
    code=$(curl -sS -o "$out" -w '%{http_code}' -X "$m" "$COORDINATOR_URL$path" \
      -H "$auth" -H 'Content-Type: application/json' ${body:+-d "$body"})
  else
    code=$(curl -sS -o "$out" -w '%{http_code}' -X "$m" "$COORDINATOR_URL$path" \
      -H 'Content-Type: application/json' ${body:+-d "$body"})
  fi
  printf '%s %s\n' "$code" "$(tr -d '\n' < "$out")"
  rm -f "$out"
}
code_of() { awk '{print $1}' <<<"$1"; }
body_of() { cut -d' ' -f2- <<<"$1"; }

store_policy() { # store_policy <seed> <wallet_id> <rules-json>
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
  WALLET_PUBKEY="ed25519:$pub_hex"
  store_args=$(jq -nc --arg pk "$WALLET_PUBKEY" --arg ed "$encb64" --arg sg "$sig_hex" \
    '{wallet_pubkey:$pk, encrypted_data:$ed, wallet_signature:$sg}')
  near_tty "near contract call-function as-transaction $CONTRACT_ID store_wallet_policy \
    json-args '$store_args' prepaid-gas '100.0 Tgas' attached-deposit '0.1 NEAR' \
    sign-as $PARENT network-config $NETWORK sign-with-keychain send" >&2 || return 1
  sleep 5
}

chain_balance() {
  curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg a "$1" '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"view_account",finality:"final",account_id:$a}}')" \
    2>/dev/null | jq -r 'if .result.amount then .result.amount else "0" end' 2>/dev/null || echo "0"
}

# ── setup: a wallet whose spends need an approval ────────────────────────────
# STABLE per parent, not per run. A timestamped seed mints a fresh account
# every time and strands its balance plus a 0.1 NEAR policy deposit, and this
# suite deletes nothing (N6 must be REFUSED, and after the policy fix even a
# deliberate cleanup would need an approval first). One wallet, reused.
SEED="${SEED:-refusals-$PARENT}"
R=$(curl -sS -G "$COORDINATOR_URL/wallet/v1/address" --data-urlencode "chain=near" -H "$(AUTH "$SEED")")
WID=$(jq -r '.wallet_id // empty' <<<"$R"); ADDR=$(jq -r '.address // empty' <<<"$R")
[[ -n "$WID" && -n "$ADDR" ]] || { fail "setup /address failed: $(head -c 200 <<<"$R")"; exit 1; }
note "wallet $WID ($ADDR)"

# Top up only when it is actually short: on a re-run the account already exists,
# and sending again just piles up testnet NEAR nobody sweeps.
BEFORE=$(chain_balance "$ADDR")
if python3 -c "exit(0 if int('${BEFORE:-0}') < 60000000000000000000000 else 1)"; then
  near_tty "near --quiet tokens $PARENT send-near $ADDR '$FUND_NEAR NEAR' \
    network-config $NETWORK sign-with-keychain send" >/dev/null 2>&1
  [[ "$(chain_balance "$ADDR")" != "$BEFORE" ]] \
    && pass "setup wallet funded" \
    || { fail "setup funding did not land on $ADDR — the SENDER failed, not the product"; exit 1; }
else
  pass "setup wallet already holds $BEFORE"
fi

# `allowed_recipients` names PARENT and nobody else, and every spend needs one
# approval — the first gives N6 something to break, the second gives N1–N3 an
# approval to vote on.
WALLET_PUBKEY=""
# The shape is checked against `shared-tee-helpers/src/wallet_policy.rs`, not
# guessed: `approval` is a SIBLING of `rules` (Policy:483), and the address
# block is `rules.addresses = {mode, list}` (Rules:506). Every field carries
# `#[serde(default)]`, so an invented name is dropped without a word — the
# first version of this file nested `approval` under `rules` and called the
# address block `address_rules`, which left the wallet with no approval
# requirement and no whitelist. N6 would then have deleted it for real.
store_policy "$SEED" "$WID" \
  "$(jq -nc --arg p "$PARENT" \
     '{rules:{transaction_types:["transfer","delete"],
              addresses:{mode:"whitelist", list:[$p]}},
       approval:{threshold:1}}')" \
  || { fail "setup policy not stored — every probe below would refuse for the wrong reason"; exit 1; }
pass "setup policy stored (1 approval required; only $PARENT may receive)"

# ── produce one pending approval to vote on ──────────────────────────────────
SPEND_R=$(req POST /wallet/v1/transfer "$(AUTH "$SEED")" \
  "$(jq -nc --arg to "$PARENT" --arg a "$SPEND" '{chain:"near", to:$to, amount:$a}')")
APPROVAL_ID=$(jq -r '.approval_id // empty' <<<"$(body_of "$SPEND_R")")
REQUEST_HASH=$(jq -r '.request_hash // empty' <<<"$(body_of "$SPEND_R")")
if [[ -z "$APPROVAL_ID" ]]; then
  fail "setup no approval was minted (HTTP $(code_of "$SPEND_R")): $(head -c 200 <<<"$(body_of "$SPEND_R")")"
  note "N1–N3 need one; skipping to N4."
else
  pass "setup approval $APPROVAL_ID awaiting a vote"
fi

# Signs `reject:{id}:{wallet_pubkey}:{request_hash}` and leaves the pieces the
# endpoint needs in $REJ_SIG / $REJ_NONCE. Shaped exactly like the approve half
# in approval_flow_wk_e2e.sh: the nonce is generated HERE and handed to both the
# signer and the request — the signer does not hand one back.
REJ_SIG=""; REJ_NONCE=""
sign_reject() { # sign_reject <approval_id> <wallet_pubkey> <request_hash>
  REJ_NONCE=$(nonce)
  REJ_SIG=$("$RECOVERY_BIN" sign-nep413 \
    --private-key "$PARENT_PRIVKEY" \
    --message "reject:$1:$2:$3" \
    --recipient "$CONTRACT_ID" \
    --nonce-base64 "$REJ_NONCE" | jq -r '.signature')
  [[ -n "$REJ_SIG" && "$REJ_SIG" != "null" ]]
}
reject_body() { # reject_body <signature>
  jq -nc --arg s "$1" --arg p "$PARENT_PUBKEY" --arg a "$PARENT" --arg n "$REJ_NONCE" \
    '{signature:$s, public_key:$p, account_id:$a, nonce:$n}'
}

if [[ -n "$APPROVAL_ID" ]]; then
  # ── N1: the vote is bound to the OPERATION ─────────────────────────────────
  # A signature that names the right approval but the wrong request hash must
  # not count. Otherwise a vote captured for one operation replays onto
  # whatever that approval is later carrying.
  log "N1 reject signed over another request's hash"
  WRONG_HASH=$(printf '%s' "$REQUEST_HASH" | tr '0-9a-f' '1-9a-f0')
  if ! sign_reject "$APPROVAL_ID" "$WALLET_PUBKEY" "$WRONG_HASH"; then
    fail "N1 could not sign — the probe never reached the endpoint"
  else
    R=$(req POST "/wallet/v1/reject/$APPROVAL_ID" "" "$(reject_body "$REJ_SIG")")
    [[ "$(code_of "$R")" == "401" ]] \
      && pass "N1 refused (401) — the vote is bound to the request, not just the id" \
      || fail "N1 answered $(code_of "$R") to a vote signed over a different request; expected 401: $(head -c 200 <<<"$(body_of "$R")")"
  fi

  # ── N2: no signature, and a corrupt one ────────────────────────────────────
  log "N2 reject with a missing and with a corrupt signature"
  R=$(req POST "/wallet/v1/reject/$APPROVAL_ID" "" '{}')
  [[ "$(code_of "$R")" == 4?? ]] \
    && pass "N2 an unsigned rejection is refused (HTTP $(code_of "$R"))" \
    || fail "N2 an unsigned rejection was accepted (HTTP $(code_of "$R"))"
  # A missing field is a 400 and a bad signature a 401 — both 4xx, and which is
  # which is not the claim here, so this one stays broad.
  if ! sign_reject "$APPROVAL_ID" "$WALLET_PUBKEY" "$REQUEST_HASH"; then
    fail "N2 could not sign — the corrupt-signature half never ran"
  else
    R=$(req POST "/wallet/v1/reject/$APPROVAL_ID" "" "$(reject_body "$(rev <<<"$REJ_SIG")")")
    [[ "$(code_of "$R")" == "401" ]] \
      && pass "N2 a corrupt signature is refused (401)" \
      || fail "N2 a corrupt signature answered $(code_of "$R"); expected 401"
  fi

  # ── N3: the documented split ───────────────────────────────────────────────
  # The coordinator stores a well-formed vote from ANYONE; only the keystore
  # decides whose veto counts, because only it can read the approver list. If
  # this ever starts refusing, the split has quietly moved — and if the
  # keystore's half moves instead, anyone can silence anyone.
  log "N3 a well-formed rejection from a non-approver is STORED, not judged"
  if ! sign_reject "$APPROVAL_ID" "$WALLET_PUBKEY" "$REQUEST_HASH"; then
    fail "N3 could not sign — the probe never reached the endpoint"
    R="000 {}"
  else
    R=$(req POST "/wallet/v1/reject/$APPROVAL_ID" "" "$(reject_body "$REJ_SIG")")
  fi
  [[ "$(code_of "$R")" == 2?? ]] \
    && pass "N3 stored (HTTP $(code_of "$R")) — the keystore is what honours or ignores it" \
    || fail "N3 a well-formed vote was refused (HTTP $(code_of "$R")): $(head -c 200 <<<"$(body_of "$R")")"
fi

# ── N4/N5: the internal endpoints are not public ─────────────────────────────
# They change what a wallet may do — deleting its policy, freezing it. The
# probe is the AUTH GATE only: a test holding the real internal token would be
# a test that can freeze a wallet by accident.
# `verify_internal_auth` reads `x-internal-wallet-auth` (handlers.rs:11540) —
# an `Authorization:` header is invisible to it, so sending one would have made
# both rows below the SAME no-header test. The body names `wallet_pubkey`, not
# `wallet_id`; it only ever matters after auth, but a body the handler cannot
# parse would move the refusal to the wrong reason.
#
# 401 exactly, not `4??`: a renamed route answering 404, or an edge proxy
# answering 403, would satisfy `4??` while proving nothing about the gate.
internal_probe() { # internal_probe <probe> <path> <extra-body-json> <what>
  local probe=$1 path=$2 extra=$3 what=$4 hdr label R
  for hdr in "" "x-internal-wallet-auth: not-the-internal-token"; do
    label=${hdr:+wrong token}; label=${label:-no token}
    R=$(req POST "$path" "$hdr" \
      "$(jq -nc --arg k "$WALLET_PUBKEY" --argjson e "$extra" '$e + {wallet_pubkey:$k}')")
    [[ "$(code_of "$R")" == "401" ]] \
      && pass "$probe refused with $label (401)" \
      || fail "$probe answered $(code_of "$R") with $label — expected 401; $what"
  done
}

log "N4 /internal/wallet-policy-delete rejects an unauthenticated and a wrong-token caller"
internal_probe N4 /internal/wallet-policy-delete '{}' "anyone could delete a wallet's policy"

log "N5 /internal/wallet-frozen-change rejects the same"
internal_probe N5 /internal/wallet-frozen-change '{"frozen":true}' "anyone could freeze a wallet"

# ── N6: delete moves everything, so its address rule matters most ────────────
log "N6 /wallet/v1/delete toward a beneficiary outside the whitelist"
STRANGER="nope-$(date +%s)-$$.testnet"
R=$(req POST /wallet/v1/delete "$(AUTH "$SEED")" \
  "$(jq -nc --arg b "$STRANGER" '{beneficiary:$b, chain:"near"}')")
if [[ "$(code_of "$R")" == 2?? ]]; then
  fail "N6 the whole balance was sent to an address the policy does not list (HTTP $(code_of "$R"))"
else
  pass "N6 refused (HTTP $(code_of "$R")) — $(jq -r '.error // .message // ""' <<<"$(body_of "$R")" | head -c 90)"
fi
[[ "$(chain_balance "$ADDR")" != "0" ]] \
  && pass "N6 and the account still holds its balance" \
  || fail "N6 the account is empty — the refusal above did not prevent the sweep"

note "left in place: wallet $WID ($ADDR), ~$FUND_NEAR NEAR plus a 0.1 NEAR policy deposit."
note "  Reclaiming it needs a policy without the approval threshold first — this run's policy"
note "  requires one approval for every spend, delete included."

# ── verdict ──────────────────────────────────────────────────────────────────
log "refusals — $PASS passed, $FAILED failed"
if (( FAILED > 0 )); then
  for n in "${FAILED_NAMES[@]}"; do printf '  \033[31m✗ %s\033[0m\n' "$n" >&2; done
  exit 1
fi
exit 0
