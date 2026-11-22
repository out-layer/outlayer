#!/usr/bin/env bash
#
# Owner exit on testnet: an account registers in the keystore DAO, gets wallets from an
# agent's link, and leaves with their keys — through the DAO, NEAR MPC and the recovery tool,
# with no OutLayer service on the way out.
#
#   P   the DAO offers the exit; MPC's key for CKD domain 2 is read from the MPC contract
#   L1  a link before its owner acts: the key answers 401; an unregistered account is told
#       so and gets no message to sign; a wallet cannot be created for it; `/register`
#       refuses an owner scope
#   D1  registration: refused below the fee and outside the window bounds; taken once with
#       the fee; refused twice
#   D2  the keystore's methods are refused to an ordinary account; an exit with no escrow
#       is refused
#   D3  the window: raised at once; a lowering waits and the window in force stays; a raise
#       drops the pending lowering
#   W1  the owner's signature creates the wallet: the key answers with the address and
#       `exit_owner`; the escrow of the generation is on chain
#   W2  the link again, and a link for a seed the owner has: 409. A link signed by another
#       account in the owner's name, and a link with a changed payload: refused
#   W3  a second wallet (seed 1); the keystore signs for the owner's scope
#   X1  an exit without the fee is refused; started with it; a second one is refused; a
#       claim before the window is refused; cancelled; started again; the wallet still signs
#   X2  after the window: the claim hands the master over once — generation +1, nothing
#       pending, a second claim refused; the claim file opens the same master again
#   X3  the tool finds both wallets by their numbered seeds, and each derived key is the
#       wallet's; a transfer signed with a derived key lands
#   X4  the wallets' API keys are refused (403, naming the owner's exit) after it
#   G1  a new link, the same seed: a wallet in generation 2 at another address
#   K0  a policy that is not locked is signed for the owner's wallet whatever the DAO holds
#   K1  a locked policy while the owner has no exit approvers: the keystore refuses to sign
#       it and says to set them first
#   Q1  approvers: refused over the maximum, with threshold 0, with a threshold above the
#       count; the first set is in force at once
#   K2  a locked policy whose approvers or threshold differ from the DAO's: refused
#   K3  a locked policy the DAO could not hold an exit to — an approver with no id, an id
#       that is not an account id as written, a pinned key, more approvers than the DAO
#       takes: each refused, with its reason
#   K4  the same accounts and threshold as the DAO's, in another order and with one named
#       twice: signed, stored on chain by the owner, locked. Q2 is then an exit under a
#       locked policy in force
#   Q2  an exit under a 2-of-2 set: a change of the set, a vote for another nonce, a
#       stranger's vote and a second vote of one approver are refused; a claim with one vote
#       is refused; with two votes the claim succeeds
#   Q3  a change of the set waits for the set in force: one reject drops it; approved by
#       both, it is in force
#
# The owner is a fresh sub-account of PARENT, made for the run and deleted after it; its
# registration stays in the DAO. A run burns the registration fee and three exit fees —
# under 0.1 NEAR on testnet, read from the DAO's config — plus the storage of one wallet
# policy, and waits two exit windows (about three minutes). What each part proves and how
# to read a failure: `.idea/_todo/owner-exit-tests.md`, section I.
#
# Run:
#   PARENT=outlayer-alice.testnet ./tests/owner_exit_e2e.sh --apply
# APPROVER1 / APPROVER2 / STRANGER (default outlayer-bob / -carol / -daniel) vote from
# near-cli's legacy keychain. DAO and MPC_CONTRACT default to testnet's.

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/hos_common.sh"
source "$HOS_LIB_DIR/near_sign.sh"

[[ "${1:-}" == "--apply" ]] || { warn "Dry run. Pass --apply."; exit 0; }
[[ "$NETWORK" == testnet ]] || { echo "✗ this suite runs on testnet" >&2; exit 1; }

DAO="${DAO:-dao.outlayer.testnet}"
MPC_CONTRACT="${MPC_CONTRACT:-v1.signer-prod.testnet}"
APPROVER1="${APPROVER1:-outlayer-bob.testnet}"
APPROVER2="${APPROVER2:-outlayer-carol.testnet}"
STRANGER="${STRANGER:-outlayer-daniel.testnet}"
hos_require
for a in "$APPROVER1" "$APPROVER2" "$STRANGER"; do
  [[ -f "$CREDS_DIR/$a.json" ]] || { echo "✗ creds missing for $a" >&2; exit 1; }
done

OWNER="oe$(date +%s).$PARENT"
OWNER_CREDS="$CREDS_DIR/$OWNER.json"
WORK=$(mktemp -d -t owner_exit.XXXXXX) || exit 1
chmod 700 "$WORK"
IMPLICIT=""
# Removes only what this run made: the key file of the wallet it left with, the throwaway
# owner (account and key file), the run's temporary directory.
cleanup() {
  if [[ -n "$IMPLICIT" ]]; then rm -f -- "${CREDS_DIR:?}/${IMPLICIT:?}.json"; fi
  if [[ -f "$OWNER_CREDS" ]]; then
    near account delete-account "$OWNER" beneficiary "$PARENT" \
      network-config "$NETWORK" sign-with-keychain send >/dev/null 2>&1 || true
    rm -f -- "${OWNER_CREDS:?}"
  fi
  [[ -d "$WORK" ]] && rm -rf -- "${WORK:?}"
}
trap cleanup EXIT

# ── chain ────────────────────────────────────────────────────────────────────

# dao_call <signer> <method> <json-args> [deposit] — 0 when the transaction succeeded; the
# CLI's output stays in OUT and is shown only through near_why.
OUT=""
dao_call() {
  OUT=$(near contract call-function as-transaction "$DAO" "$2" json-args "$3" \
    prepaid-gas '100 Tgas' attached-deposit "${4:-1 yoctoNEAR}" sign-as "$1" \
    network-config "$NETWORK" sign-with-keychain send 2>&1)
}
# refused <name> <words> <dao_call args…> — the call fails and the contract says why.
refused() {
  local name=$1 want=$2; shift 2
  if dao_call "$@"; then fail "$name: the call was taken"
  elif grep -qF "$want" <<<"$OUT"; then pass "$name"
  else fail "$name: refused, but not with \"$want\": $(near_why "$OUT")"; fi
}
taken() { # taken <name> <dao_call args…>
  local name=$1; shift
  if dao_call "$@"; then pass "$name"; else fail "$name: $(near_why "$OUT")"; fi
}
record() { near_view "$DAO" get_exit_owner "$(jq -nc --arg a "$OWNER" '{account:$a}')"; }
rec() { record | jq -r "$1"; }
yocto_near() { python3 -I -c 'import sys; print(f"{int(sys.argv[1])/1e24:.4f} NEAR")' "$1"; }

# The recovery tool as the owner. The RPC URL and the key go through the environment; what
# the tool prints on failure can name the endpoint, so only near_why's reading is shown.
exit_tool() {
  local cmd=$1; shift
  RPC_URL="$RPC_URL" OWNER_PRIVATE_KEY="$(jq -r .private_key "$OWNER_CREDS")" MPC_PUBLIC_KEY="$MPC_PK" \
    "$RECOVERY_BIN" owner-exit "$cmd" --owner "$OWNER" --dao "$DAO" "$@" 2>&1
}
# claim <claim-file> → RC, MASTER (kept in a variable, never shown), OUT without the master.
claim() {
  OUT=$(exit_tool claim --claim-file "$1"); RC=$?
  MASTER=$(grep -oE '^master_hex=[0-9a-f]{64}$' <<<"$OUT" | cut -d= -f2)
  OUT=$(grep -v '^master_hex=' <<<"$OUT")
}

# ── coordinator ──────────────────────────────────────────────────────────────

new_link() { # new_link [seed] → LINK, KEY
  local body='{}'
  [[ $# -gt 0 ]] && body=$(jq -nc --arg s "$1" '{seed:$s}')
  api - POST /wallet/v1/exit-link "$body" >/dev/null
  LINK=$(jq -r '.link // ""' <<<"$BODY"); KEY=$(jq -r '.api_key // ""' <<<"$BODY")
  [[ "$HTTP" == 200 && -n "$LINK" && "$KEY" == wk_* ]]
}
prepare() { api - POST /wallet/v1/owner-wallet/prepare "$(jq -nc --arg l "$1" --arg a "$OWNER" '{link:$l, account_id:$a}')" >/dev/null; }
# create_wallet <link> <signing-creds-file> [message] — the owner's proof for the link,
# signed with the key in that file, in OWNER's name.
create_wallet() {
  local link=$1 creds=$2 msg=${3:-} nonce sig
  if [[ -z "$msg" ]]; then prepare "$link"; msg=$(jq -r '.message // ""' <<<"$BODY"); fi
  [[ -n "$msg" ]] || return 1
  nonce=$(head -c 32 /dev/urandom | base64 | tr -d '\n')
  sig=$(CUSTOMER_RECOVERY_PRIVATE_KEY="$(jq -r .private_key "$creds")" "$RECOVERY_BIN" sign-nep413 \
    --message "$msg" --recipient outlayer:owner-wallet --nonce-base64 "$nonce" | jq -r .signature)
  api - POST /wallet/v1/owner-wallet "$(jq -nc --arg l "$link" --arg a "$OWNER" --arg pk "$(jq -r .public_key "$creds")" \
    --arg s "$sig" --arg n "$nonce" '{link:$l, account_id:$a, public_key:$pk, signature:$s, nonce:$n}')" >/dev/null
}
# Why the last API call was refused, safe to print: the answer's error code and message. The
# body itself is never shown — an answer that should have been a refusal can hold a key or a
# signature.
why() { jq -r '"\(.error // "no error code"): \(.message // "" | .[0:160])"' <<<"$BODY" 2>/dev/null || echo "an answer that is not JSON"; }
# sign_policy <wk> <wallet_id> <policy-json> — what the keystore says to signing this policy
# for the wallet: encrypt it, then ask for the signature as the owner would before storing
# it. Sets PSTEP (the step that answered last: encrypt | sign), HTTP, BODY and, when the
# encryption went through, PENC. Nothing is stored. A signed answer holds a signature and
# is never printed.
PSTEP=""; PENC=""
sign_policy() {
  local wk=$1 wid=$2 pol=$3
  PSTEP=encrypt; PENC=""
  api_wk "$wk" POST /wallet/v1/encrypt-policy "$(jq -c --arg w "$wid" '. + {wallet_id:$w}' <<<"$pol")" >/dev/null
  PENC=$(jq -r '.encrypted_base64 // ""' <<<"$BODY" 2>/dev/null)
  [[ "$HTTP" == 200 && -n "$PENC" ]] || return 1
  PSTEP=sign
  api_wk "$wk" POST /wallet/v1/sign-policy "$(jq -nc --arg ed "$PENC" --arg c "$OWNER" '{encrypted_data:$ed, caller:$c}')" >/dev/null
  [[ "$HTTP" == 200 && -n "$(jq -r '.signature_hex // ""' <<<"$BODY" 2>/dev/null)" ]]
}
# policy_refused <name> <words> <wk> <wallet_id> <policy-json> — the keystore does not sign
# it, and says why in these words. A refusal for another reason, or at the encryption, is
# reported as what it was.
policy_refused() {
  local name=$1 words=$2; shift 2
  if sign_policy "$@"; then fail "$name: the policy was signed"
  elif grep -qF "$words" <<<"$BODY"; then pass "$name ($PSTEP: $HTTP)"
  else fail "$name: refused at $PSTEP with $HTTP, but not with \"$words\": $(why)"; fi
}
# A locked policy naming these approvers: lock <threshold> <approver-json>…
lock() {
  local t=$1; shift
  jq -nc --argjson t "$t" '{rules:{transaction_types:["transfer"]}, approval:{locked:true, threshold:{required:$t}, approvers:$ARGS.positional}}' --jsonargs "$@"
}
by_id() { jq -nc --arg a "$1" '{id:$a}'; }

# The keystore signing for the wallet's scope: an auth challenge, which moves nothing.
signs() { api_wk "$1" POST /wallet/v1/auth-sign '{"purpose":"bearer","seed":"probe"}' >/dev/null; }

# ── P: preflight ─────────────────────────────────────────────────────────────
log "P  the DAO's exit terms"
EXIT_CFG=$(near_view "$DAO" get_config | jq -c '.exit // empty' 2>/dev/null)
[[ -n "$EXIT_CFG" ]] || { echo "✗ $DAO has no exit in get_config: it does not run this release" >&2; exit 1; }
REG_FEE=$(jq -r .registration_fee <<<"$EXIT_CFG"); EXIT_FEE=$(jq -r .exit_fee <<<"$EXIT_CFG")
MIN_W=$(jq -r .min_window_secs <<<"$EXIT_CFG"); MAX_W=$(jq -r .max_window_secs <<<"$EXIT_CFG")
MAX_APPROVERS=$(jq -r .max_approvers <<<"$EXIT_CFG")
RAISED_W=$((MIN_W * 2))
note "registration $(yocto_near "$REG_FEE"), exit $(yocto_near "$EXIT_FEE"), window ${MIN_W}–${MAX_W}s"
MPC_PK=$(near_view "$MPC_CONTRACT" public_key '{"domain_id":2}' | tr -d '"')
[[ "$MPC_PK" == bls12381g2:* ]] || { echo "✗ $MPC_CONTRACT did not answer with its key for domain 2" >&2; exit 1; }
pass "P  $DAO offers the exit; MPC's CKD key read"

log "Creating the owner $OWNER"
KP=$(node "$HOS_LIB_DIR/ed25519_keypair.mjs")
( umask 077; jq -c --arg a "$OWNER" '. + {account_id:$a}' <<<"$KP" > "$OWNER_CREDS" )
near account create-account fund-myself "$OWNER" '2 NEAR' \
  use-manually-provided-public-key "$(jq -r .public_key <<<"$KP")" sign-as "$PARENT" \
  network-config "$NETWORK" sign-with-keychain send >/dev/null 2>&1
unset KP
for _ in 1 2 3 4 5 6; do account_exists "$OWNER" && break; sleep 2; done
account_exists "$OWNER" || { echo "✗ $OWNER never appeared on chain" >&2; exit 1; }

# ── L1: a link before its owner acts ─────────────────────────────────────────
log "L1 a link before its owner acts"
new_link || { fail "L1 exit-link answered $HTTP"; verdict owner_exit; exit 1; }
LINK0=$LINK; KEY0=$KEY
api_wk "$KEY0" GET '/wallet/v1/address?chain=near' >/dev/null
if [[ "$HTTP" == 401 ]]; then pass "L1 the link's key answers 401 until the owner has acted"
else fail "L1 the key answered $HTTP before any wallet exists"; fi
prepare "$LINK0"
if [[ "$HTTP" == 200 && "$(bool_of registered)" == false && "$(jq -r '.message' <<<"$BODY")" == null ]]; then
  pass "L1 an unregistered account is told so and gets nothing to sign"
else fail "L1 prepare for an unregistered account: $HTTP $(why)"; fi
create_wallet "$LINK0" "$OWNER_CREDS" \
  "outlayer-owner-wallet:v1:$DAO:$OWNER:1:next:$(jq -r .key_hash <<<"$BODY"):$(jq -r .expires_at <<<"$BODY")"
# The refusal for THIS reason: a 429 or a 500 would say nothing about registration.
if [[ "$HTTP" == 400 ]] && grep -qF "is not registered for an exit" <<<"$BODY"; then pass "L1 no wallet for an unregistered account: 400, told to register"
else fail "L1 a wallet was created for an unregistered account"; fi

api - POST /register '{"master":"owner"}' >/dev/null
if [[ "$HTTP" == 400 ]] && grep -qF "exit-link" <<<"$BODY"; then pass "L1 /register refuses an owner scope and names the link"
# The body is not shown: a coordinator that took the request answers with a new `wk_`.
else fail "L1 /register with master=owner answered $HTTP ($(jq -r '.error // "no error code"' <<<"$BODY" 2>/dev/null))"; fi

# ── D1–D3: the DAO's rules ───────────────────────────────────────────────────
log "D1 registration"
W() { jq -nc --argjson w "$1" '{exit_window_sec:$w}'; }
FEE=$(yocto_near "$REG_FEE"); XFEE=$(yocto_near "$EXIT_FEE")
refused "D1 below the fee" "registration takes" "$OWNER" register_exit_owner "$(W "$MIN_W")" '1 yoctoNEAR'
refused "D1 a window below the minimum" "the exit window must be between" "$OWNER" register_exit_owner "$(W $((MIN_W - 1)))" "$FEE"
refused "D1 a window above the maximum" "the exit window must be between" "$OWNER" register_exit_owner "$(W $((MAX_W + 1)))" "$FEE"
if [[ "$(record)" == null ]]; then pass "D1 nothing recorded by the refusals"; else fail "D1 a refused registration left a record"; fi
taken "D1 registered with the fee" "$OWNER" register_exit_owner "$(W "$MIN_W")" "$FEE"
if [[ "$(rec '[.generation, .exit_window_secs, (.approvers|length), .pending] | @json')" == "[1,$MIN_W,0,null]" ]]; then
  pass "D1 the record: generation 1, the window asked for, no approvers, nothing pending"
else fail "D1 the record is $(record | head -c 300)"; fi
refused "D1 a second registration" "already registered" "$OWNER" register_exit_owner "$(W "$MIN_W")" "$FEE"

log "D2 what an ordinary account cannot do"
# No deposit: the method takes none, and a call with one is refused for that before the
# caller is looked at.
refused "D2 store_escrow from an ordinary account" "approved-keystore access key" "$STRANGER" store_escrow \
  "$(jq -nc --arg o "$OWNER" '{owner:$o, generation:1, ct:"AAAA", check:"AAAA"}')" '0 NEAR'
if [[ "$(near_view "$DAO" get_escrow "$(jq -nc --arg a "$OWNER" '{account:$a, generation:1}')")" == null ]]; then
  pass "D2 no escrow was stored by it"
else fail "D2 an ordinary account stored an escrow"; fi
refused "D2 an exit with no escrow" "no escrow for this generation yet" "$OWNER" initiate_exit '{}' "$XFEE"

log "D3 the exit window"
window() { rec '[.exit_window_secs, .pending_exit_window.secs] | @json'; }
taken "D3 raised to ${RAISED_W}s" "$OWNER" set_exit_window "$(W "$RAISED_W")"
if [[ "$(window)" == "[$RAISED_W,null]" ]]; then pass "D3 a raise is in force at once"; else fail "D3 after the raise: $(window)"; fi
taken "D3 lowered to ${MIN_W}s" "$OWNER" set_exit_window "$(W "$MIN_W")"
if [[ "$(window)" == "[$RAISED_W,$MIN_W]" ]]; then pass "D3 a lowering waits; the window in force stays"; else fail "D3 after the lowering: $(window)"; fi
taken "D3 raised again" "$OWNER" set_exit_window "$(W "$RAISED_W")"
if [[ "$(window)" == "[$RAISED_W,null]" ]]; then pass "D3 a raise drops the pending lowering"; else fail "D3 the lowering survived a raise: $(window)"; fi
taken "D3 lowered again, left to take effect" "$OWNER" set_exit_window "$(W "$MIN_W")"

# ── W1–W3: wallets ───────────────────────────────────────────────────────────
log "W1 the owner's signature creates the wallet"
create_wallet "$LINK0" "$OWNER_CREDS"
# The FIRST wallet of a generation is the one whose request writes the escrow. A refusal
# that says the escrow is "not on chain after its write" is the keystore reading its own
# write back too early: it is a failure of this row, and the request is sent once more
# after the escrow shows on chain, so that the rows below still run.
if [[ "$HTTP" != 200 && "$(jq -r '.message // ""' <<<"$BODY")" == *"is not on chain after its write"* ]]; then
  fail "W1 the first owner-wallet request answered $HTTP $(why) — the escrow was written; the keystore did not see its own write"
  for _ in $(seq 1 15); do
    [[ "$(near_view "$DAO" get_escrow "$(jq -nc --arg a "$OWNER" '{account:$a, generation:1}')")" != null ]] && break
    sleep 2
  done
  create_wallet "$LINK0" "$OWNER_CREDS"
fi
if [[ "$HTTP" == 200 && "$(jq -r '[.owner, .generation, .seed] | @json' <<<"$BODY")" == "[\"$OWNER\",1,\"0\"]" ]]; then
  WALLET0=$(jq -r .wallet_id <<<"$BODY"); ACCOUNT0=$(jq -r .near_account_id <<<"$BODY")
  pass "W1 wallet created: generation 1, seed 0"
else fail "W1 owner-wallet answered $HTTP $(why)"; verdict owner_exit; exit 1; fi
api_wk "$KEY0" GET '/wallet/v1/address?chain=near' >/dev/null
if [[ "$HTTP" == 200 && "$(jq -r '[.address, .exit_owner.account_id, .exit_owner.generation, .vault_id] | @json' <<<"$BODY")" == "[\"$ACCOUNT0\",\"$OWNER\",1,null]" ]]; then
  pass "W1 the link's key answers with the address and exit_owner, and no vault"
else fail "W1 /address: $HTTP $(why)"; fi
ESCROW=$(near_view "$DAO" get_escrow "$(jq -nc --arg a "$OWNER" '{account:$a, generation:1}')")
if [[ "$(jq -r '[(.ct|length > 0), (.check|length > 0), .domain_id] | @json' <<<"$ESCROW")" == "[true,true,2]" ]]; then
  pass "W1 the generation's escrow is on chain"
else fail "W1 no escrow on chain for a wallet that exists"; fi
RCHECK=$(rec '.escrow_check // empty')
if [[ -n "$RCHECK" && "$RCHECK" == "$(jq -r '.check // empty' <<<"$ESCROW")" ]]; then pass "W1 the record shows the escrow's check"
else fail "W1 escrow_check differs from the escrow"; fi

log "W2 what a link cannot do"
create_wallet "$LINK0" "$OWNER_CREDS"
if [[ "$HTTP" == 409 ]]; then pass "W2 a link used twice: 409"; else fail "W2 the link again answered $HTTP"; fi
new_link 0 && create_wallet "$LINK" "$OWNER_CREDS"
if [[ "$HTTP" == 409 ]]; then pass "W2 a link for a seed the owner has: 409"; else fail "W2 a link for an existing seed answered $HTTP"; fi
api_wk "$KEY" GET '/wallet/v1/address?chain=near' >/dev/null
if [[ "$HTTP" == 401 ]]; then pass "W2 its key was not added to the existing wallet"; else fail "W2 the refused link's key answers $HTTP"; fi
new_link 1; LINK1=$LINK; KEY1=$KEY
create_wallet "$LINK1" "$CREDS_DIR/$PARENT.json"
if [[ "$HTTP" == 401 || "$HTTP" == 403 ]]; then pass "W2 another account's key in the owner's name: $HTTP"
else fail "W2 a proof signed by another account answered $HTTP"; fi
BENT="$(tr 'A-Za-z' 'B-ZAb-za' <<<"${LINK1%%.*}").${LINK1#*.}"
prepare "$BENT"
if [[ "$HTTP" == 400 ]]; then pass "W2 a link with a changed payload: 400"; else fail "W2 a changed link answered $HTTP"; fi

log "W3 a second wallet; the keystore signs for the scope"
create_wallet "$LINK1" "$OWNER_CREDS"
if [[ "$HTTP" == 200 && "$(jq -r '[.generation, .seed] | @json' <<<"$BODY")" == '[1,"1"]' ]]; then
  WALLET1=$(jq -r .wallet_id <<<"$BODY"); ACCOUNT1=$(jq -r .near_account_id <<<"$BODY")
  if [[ "$WALLET1" != "$WALLET0" && "$ACCOUNT1" != "$ACCOUNT0" ]]; then pass "W3 seed 1 is another wallet at another address"
  else fail "W3 seed 1 repeats seed 0"; fi
else fail "W3 the second wallet: $HTTP $(why)"; verdict owner_exit; exit 1; fi
signs "$KEY0"
if [[ "$HTTP" == 200 ]]; then pass "W3 the keystore signs for the owner's wallet"; else fail "W3 auth-sign answered $HTTP $(why)"; fi
signs "$KEY1"
if [[ "$HTTP" == 200 ]]; then pass "W3 and for the second"; else fail "W3 auth-sign for seed 1 answered $HTTP"; fi
# Both wallets on chain: the tool finds a wallet by its account, and X3 spends from one.
if ! { fund_account "$ACCOUNT0" 0.05 && fund_account "$ACCOUNT1" 0.01; }; then fail "W3 the wallets could not be funded"; fi

# ── X1–X4: the exit ──────────────────────────────────────────────────────────
# 0 when no exit is pending: every reader of it then fails its own row, with no jq error.
finalize_after() { rec '(.pending.kind.Exit.finalize_after // 0) / 1e9 | floor'; }
wait_for_window() {
  local after now
  after=$(finalize_after); now=$(date +%s)
  if (( after > now )); then note "waiting $((after - now + 6))s for the exit window"; sleep $((after - now + 6)); fi
}

log "X1 starting and cancelling an exit"
refused "X1 an exit without the fee" "an exit takes" "$OWNER" initiate_exit '{}' '1 yoctoNEAR'
T0=$(date +%s)
if OUT=$(exit_tool initiate); then pass "X1 the exit is started"; else fail "X1 initiate: $(near_why "$OUT")"; fi
LEFT=$(( $(finalize_after) - T0 ))
if (( LEFT > MIN_W + 10 && LEFT <= RAISED_W + 30 )); then pass "X1 started before the lowering took effect, it waits the window in force (${LEFT}s)"
else fail "X1 the exit waits ${LEFT}s, the window in force is ${RAISED_W}s"; fi
refused "X1 a second exit while one is pending" "an action is already pending" "$OWNER" initiate_exit '{}' "$XFEE"
claim "$WORK/early.json"
if [[ $RC -ne 0 ]] && grep -qF "the exit window has not elapsed" <<<"$OUT"; then pass "X1 a claim before the window is refused"
else fail "X1 the early claim: rc=$RC $(near_why "$OUT")"; fi
if [[ "$(rec .generation)" == 1 ]]; then pass "X1 the generation did not move"; else fail "X1 generation $(rec .generation) after a refused claim"; fi
if OUT=$(exit_tool cancel) && [[ "$(rec .pending)" == null ]]; then pass "X1 cancelled: nothing pending"; else fail "X1 cancel: $(near_why "$OUT")"; fi
claim "$WORK/cancelled.json"
if [[ $RC -ne 0 ]] && grep -qF "no exit is pending" <<<"$OUT"; then pass "X1 a cancelled exit cannot be claimed"
else fail "X1 the claim of a cancelled exit: rc=$RC $(near_why "$OUT")"; fi
if OUT=$(exit_tool initiate); then pass "X1 started again"; else fail "X1 the second initiate: $(near_why "$OUT")"; fi
signs "$KEY0"
if [[ "$HTTP" == 200 ]]; then pass "X1 the wallet signs while the exit is pending"; else fail "X1 auth-sign during a pending exit answered $HTTP"; fi

log "X2 the claim"
wait_for_window
CLAIM="$WORK/claim1.json"
claim "$CLAIM"; MASTER1=$MASTER
if [[ $RC -eq 0 && -n "$MASTER1" ]]; then pass "X2 the claim opened the escrow: a 32-byte master"
else fail "X2 claim: $(near_why "$OUT")"; verdict owner_exit; exit 1; fi
if [[ -s "$CLAIM" && "$(stat -f '%Lp' "$CLAIM" 2>/dev/null || stat -c '%a' "$CLAIM")" == 600 ]]; then pass "X2 the claim file is kept, readable by its owner only"
else fail "X2 the claim file is missing or readable by others"; fi
if [[ "$(rec '[.generation, .pending, .claim_in_flight] | @json')" == "[2,null,false]" ]]; then pass "X2 generation 2, nothing pending, no claim in flight"
else fail "X2 the record after the claim: $(record | head -c 300)"; fi
claim "$WORK/second.json"
if [[ $RC -ne 0 && -z "$MASTER" ]] && grep -qF "no exit is pending" <<<"$OUT"; then pass "X2 a second claim is refused"
else fail "X2 the second claim: rc=$RC $(near_why "$OUT")"; fi
AGAIN=$(RPC_URL="$RPC_URL" MPC_PUBLIC_KEY="$MPC_PK" "$RECOVERY_BIN" owner-exit open --claim-file "$CLAIM" 2>/dev/null \
  | grep -oE '^master_hex=[0-9a-f]{64}$' | cut -d= -f2)
if [[ -n "$AGAIN" && "$AGAIN" == "$MASTER1" ]]; then pass "X2 the claim file opens the same master again"
else fail "X2 open --claim-file did not give the master back"; fi
unset AGAIN

log "X3 the keys are the owner's"
FOUND=$(CUSTOMER_RECOVERY_MASTER="$MASTER1" exit_tool wallets --generation 1 --max 12)
if grep -qF "seed=0 wallet_id=$WALLET0 near_account=$ACCOUNT0 on_chain=true" <<<"$FOUND" \
  && grep -qF "seed=1 wallet_id=$WALLET1 near_account=$ACCOUNT1 on_chain=true" <<<"$FOUND"; then
  pass "X3 the tool finds both wallets by their numbered seeds"
else fail "X3 wallets listed $(grep -c '^seed=' <<<"$FOUND") seeds, not these two"; fi
DERIVED=$(CUSTOMER_RECOVERY_MASTER="$MASTER1" "$RECOVERY_BIN" derive-wallet-key --wallet-id "$WALLET0" 2>/dev/null)
if [[ "$(jq -r .near_address <<<"$DERIVED")" == "$ACCOUNT0" ]]; then
  pass "X3 the key derived from the master is the wallet's"
  IMPLICIT=$ACCOUNT0
  ( umask 077; jq -c --arg a "$IMPLICIT" '{account_id:$a, public_key, private_key}' <<<"$DERIVED" > "$CREDS_DIR/$IMPLICIT.json" )
  BEFORE=$(account_field "$IMPLICIT" amount)
  # near-cli's `send` returns once the transaction is final: a read after it sees it.
  if ! [[ "$BEFORE" =~ ^[0-9]+$ ]]; then fail "X3 the wallet's balance could not be read before the transfer"
  elif ! near --quiet tokens "$IMPLICIT" send-near "$PARENT" '0.01 NEAR' network-config "$NETWORK" sign-with-keychain send >/dev/null 2>&1; then
    fail "X3 the transfer signed with the derived key was refused"
  else
    AFTER=$(account_field "$IMPLICIT" amount)
    if [[ "$AFTER" =~ ^[0-9]+$ ]] && python3 -I -c 'import sys; sys.exit(0 if int(sys.argv[2]) <= int(sys.argv[1]) - 10**22 else 1)' "$BEFORE" "$AFTER"; then
      pass "X3 a transfer signed with the derived key landed"
    else fail "X3 the derived key's transfer did not land (balance before ${#BEFORE} digits, after: ${AFTER:-unreadable})"; fi
  fi
else fail "X3 the derived key is not the wallet's"; fi
unset DERIVED

log "X4 OutLayer no longer serves the generation that left"
signs "$KEY0"
# The exit's own refusal: a 403 for another reason — a freeze, a blocked scope — is not it.
if [[ "$HTTP" == 403 ]] && grep -qF "($OWNER) has exited generation 1" <<<"$BODY"; then pass "X4 the wallet's key is refused: 403, naming the owner's exit"
else fail "X4 auth-sign after the exit answered $HTTP $(why)"; fi
signs "$KEY1"
if [[ "$HTTP" == 403 ]] && grep -qF "($OWNER) has exited generation 1" <<<"$BODY"; then pass "X4 and the second wallet's"
else fail "X4 auth-sign for seed 1 after the exit answered $HTTP"; fi

# ── G1: the next generation ──────────────────────────────────────────────────
log "G1 the same seed in the next generation"
new_link 0 && create_wallet "$LINK" "$OWNER_CREDS"; KEY2=$KEY
if [[ "$HTTP" == 200 && "$(jq -r '[.generation, .seed] | @json' <<<"$BODY")" == '[2,"0"]' ]]; then
  if [[ "$(jq -r .wallet_id <<<"$BODY")" != "$WALLET0" && "$(jq -r .near_account_id <<<"$BODY")" != "$ACCOUNT0" ]]; then
    WALLET2=$(jq -r .wallet_id <<<"$BODY")
    pass "G1 generation 2, seed 0: a new wallet at a new address"
  else fail "G1 generation 2 repeats generation 1's wallet"; fi
else fail "G1 the wallet of generation 2: $HTTP $(why)"; verdict owner_exit; exit 1; fi
signs "$KEY2"
if [[ "$HTTP" == 200 ]]; then pass "G1 it signs"; else fail "G1 auth-sign in generation 2 answered $HTTP"; fi

# ── Q1–Q3: approvers ─────────────────────────────────────────────────────────
log "Q1 the approver set"
SET() { local t=$1; shift; jq -nc --argjson t "$t" '{approvers: $ARGS.positional, threshold: $t}' --args "$@"; }
VOTE() { jq -nc --arg o "$OWNER" --argjson n "$1" '{owner:$o, nonce:$n}'; }
MANY=$(jq -nc --argjson n "$((MAX_APPROVERS + 1))" '{approvers: [range(0; $n) | "a\(.).testnet"], threshold: 1}')
refused "Q1 more than $MAX_APPROVERS approvers" "at most" "$OWNER" set_exit_approvers "$MANY"
refused "Q1 threshold 0 with approvers" "threshold must be between" "$OWNER" set_exit_approvers "$(SET 0 "$APPROVER1" "$APPROVER2")"
refused "Q1 a threshold above the count" "threshold must be between" "$OWNER" set_exit_approvers "$(SET 3 "$APPROVER1" "$APPROVER2")"

# ── K0–K1: a policy before the owner has exit approvers ──────────────────────
log "K0 a policy that is not locked needs nothing of the DAO"
if sign_policy "$KEY2" "$WALLET2" '{"rules":{"transaction_types":["transfer"]}}'; then pass "K0 an unlocked policy is signed for the owner's wallet"
else fail "K0 an unlocked policy was refused at $PSTEP with $HTTP: $(why)"; fi
if sign_policy "$KEY2" "$WALLET2" "$(jq -c '.approval.locked = false' <<<"$(lock 2 "$(by_id "$APPROVER1")" "$(by_id "$APPROVER2")")")"; then
  pass "K0 approvers with no lock are signed too: only a lock is held to the exit"
else fail "K0 a policy with approvers and no lock was refused at $PSTEP with $HTTP: $(why)"; fi

log "K1 a locked policy with no exit approvers in the DAO"
policy_refused "K1 refused, and told to set the exit approvers first" "set_exit_approvers" \
  "$KEY2" "$WALLET2" "$(lock 2 "$(by_id "$APPROVER1")" "$(by_id "$APPROVER2")")"
if grep -qF "$OWNER" <<<"$BODY" && grep -qF "$DAO" <<<"$BODY"; then pass "K1 the refusal names the owner and the DAO"
else fail "K1 the refusal does not name the owner and the DAO: $(why)"; fi

taken "Q1 the first set" "$OWNER" set_exit_approvers "$(SET 2 "$APPROVER1" "$APPROVER2")"
if [[ "$(rec '[.approvers, .threshold, .pending] | @json')" == "[[\"$APPROVER1\",\"$APPROVER2\"],2,null]" ]]; then pass "Q1 the first set is in force at once"
else fail "Q1 after the first set: $(record | head -c 300)"; fi

# ── K2–K4: a locked policy against the set in force ──────────────────────────
log "K2 a locked policy whose quorum is not the DAO's"
SAME_QUORUM="needs the same quorum for its owner's exit"
policy_refused "K2 another account among the approvers" "$SAME_QUORUM" \
  "$KEY2" "$WALLET2" "$(lock 2 "$(by_id "$APPROVER1")" "$(by_id "$STRANGER")")"
policy_refused "K2 the same accounts, another threshold" "$SAME_QUORUM" \
  "$KEY2" "$WALLET2" "$(lock 1 "$(by_id "$APPROVER1")" "$(by_id "$APPROVER2")")"
policy_refused "K2 one approver fewer" "$SAME_QUORUM" \
  "$KEY2" "$WALLET2" "$(lock 1 "$(by_id "$APPROVER1")")"

log "K3 a locked policy the DAO could not hold an exit to"
policy_refused "K3 an approver with no account id" "needs an account id on every approver" \
  "$KEY2" "$WALLET2" "$(lock 1 "$(by_id "$APPROVER1")" '{"pubkey":"ed25519:11111111111111111111111111111111"}')"
policy_refused "K3 an id that is not an account id as written" "is not an account id as written" \
  "$KEY2" "$WALLET2" "$(lock 2 "$(by_id "$APPROVER1")" "$(by_id "$(tr 'a-z' 'A-Z' <<<"${APPROVER2:0:1}")${APPROVER2:1}")")"
policy_refused "K3 an approver pinned to a key" "is pinned to a key" \
  "$KEY2" "$WALLET2" "$(lock 2 "$(by_id "$APPROVER1")" "$(jq -nc --arg a "$APPROVER2" --arg k "$(jq -r .public_key "$CREDS_DIR/$APPROVER2.json")" '{id:$a, pubkey:$k}')")"
MANY_IDS=(); for i in $(seq 1 $((MAX_APPROVERS + 1))); do MANY_IDS+=("$(by_id "k3-approver-$i.testnet")"); done
policy_refused "K3 more approvers than the DAO takes" "takes at most $MAX_APPROVERS approvers" \
  "$KEY2" "$WALLET2" "$(lock 1 "${MANY_IDS[@]}")"

log "K4 the DAO's own quorum, written another way"
if sign_policy "$KEY2" "$WALLET2" "$(lock 2 "$(by_id "$APPROVER2")" "$(by_id "$APPROVER1")" "$(by_id "$APPROVER2")")"; then
  if [[ "$(jq -r '[.locked, (.version|type)] | @json' <<<"$BODY")" == '[true,"number"]' ]]; then pass "K4 signed: order and a repeated name do not matter"
  else fail "K4 signed, but the answer does not say locked with a version"; fi
  # Stored by the owner, as the page would: the signature names the owner as the sender.
  K4_ARGS=$(jq -c --arg ed "$PENC" '{wallet_pubkey:("ed25519:" + .public_key_hex), encrypted_data:$ed, wallet_signature:.signature_hex, version, locked, valid_until}' <<<"$BODY")
  K4_PUBKEY=$(jq -r .wallet_pubkey <<<"$K4_ARGS")
  if OUT=$(near contract call-function as-transaction "$CONTRACT_ID" store_wallet_policy json-args "$K4_ARGS" \
      prepaid-gas '100 Tgas' attached-deposit '0.1 NEAR' sign-as "$OWNER" network-config "$NETWORK" sign-with-keychain send 2>&1); then
    sleep 4
    K4_ON_CHAIN=$(near_view "$CONTRACT_ID" get_wallet_policy "$(jq -nc --arg k "$K4_PUBKEY" '{wallet_pubkey:$k}')")
    if [[ "$(jq -r '[.locked, .owner] | @json' <<<"$K4_ON_CHAIN")" == "[true,\"$OWNER\"]" ]]; then pass "K4 stored by the owner: the chain shows the policy locked"
    else fail "K4 the chain shows $(jq -c '{locked, owner, version}' <<<"$K4_ON_CHAIN" 2>/dev/null)"; fi
  else fail "K4 store_wallet_policy: $(near_why "$OUT")"; fi
  unset K4_ARGS
  # Locked now: the owner alone no longer changes it — the lock asks its approvers.
  sign_policy "$KEY2" "$WALLET2" '{"rules":{"transaction_types":["transfer","call"]}}'
  if [[ "$PSTEP" == sign && "$(jq -r '.status // ""' <<<"$BODY")" == pending_approval ]]; then pass "K4 a change of the locked policy waits for its approvers"
  else fail "K4 a change of the locked policy answered $HTTP at $PSTEP: $(why)"; fi
else fail "K4 the DAO's own quorum was refused at $PSTEP with $HTTP: $(why)"; fi

log "Q2 an exit under the set — the wallet's policy is locked to the same two"
T0=$(date +%s)
if OUT=$(exit_tool initiate); then pass "Q2 the exit is started"; else fail "Q2 initiate: $(near_why "$OUT")"; fi
LEFT=$(( $(finalize_after) - T0 ))
if (( LEFT > 0 && LEFT <= MIN_W + 30 )); then pass "Q2 the lowered window is in force now (${LEFT}s)"; else fail "Q2 the exit waits ${LEFT}s after the lowering took effect"; fi
NONCE=$(rec '.pending.nonce // empty')
[[ -n "$NONCE" ]] || { fail "Q2 the record shows no pending exit after it was started"; verdict owner_exit; exit 1; }
refused "Q2 a change of the set while an exit is pending" "an action is already pending" "$OWNER" set_exit_approvers "$(SET 1 "$APPROVER1")"
refused "Q2 a vote for another nonce" "no pending action with this nonce" "$APPROVER1" approve_exit "$(VOTE $((NONCE + 1)))"
refused "Q2 a stranger's vote" "not an approver of this owner" "$STRANGER" approve_exit "$(VOTE "$NONCE")"
taken "Q2 the first approver votes" "$APPROVER1" approve_exit "$(VOTE "$NONCE")"
refused "Q2 its second vote" "has voted on this action" "$APPROVER1" approve_exit "$(VOTE "$NONCE")"
refused "Q2 its reject after approving" "has voted on this action" "$APPROVER1" reject_exit "$(VOTE "$NONCE")"
wait_for_window
claim "$WORK/short.json"
if [[ $RC -ne 0 && -z "$MASTER" ]] && grep -qF "1 of 2 approvals" <<<"$OUT"; then pass "Q2 a claim below the quorum is refused"
else fail "Q2 a claim with one vote of two: rc=$RC $(near_why "$OUT")"; fi
if [[ "$(rec .generation)" == 2 ]]; then pass "Q2 the generation did not move"; else fail "Q2 generation $(rec .generation) after a refused claim"; fi
taken "Q2 the second approver votes" "$APPROVER2" approve_exit "$(VOTE "$NONCE")"
claim "$WORK/claim2.json"
if [[ $RC -eq 0 && -n "$MASTER" && "$(rec .generation)" == 3 ]]; then pass "Q2 with the quorum the claim succeeds: generation 3"
else fail "Q2 the claim with the quorum: $(near_why "$OUT")"; fi
if [[ -n "$MASTER" && "$MASTER" != "$MASTER1" ]]; then pass "Q2 generation 2's master is not generation 1's"; else fail "Q2 two generations share a master"; fi
unset MASTER MASTER1

log "Q3 changing the set"
taken "Q3 a change is proposed" "$OWNER" set_exit_approvers "$(SET 0)"
if [[ "$(rec '[(.approvers|length), .threshold, (.pending.kind | has("SetApprovers"))] | @json')" == "[2,2,true]" ]]; then pass "Q3 it waits; the set in force stays"
else fail "Q3 after the proposal: $(record | head -c 300)"; fi
NONCE=$(rec .pending.nonce)
taken "Q3 one approver rejects" "$APPROVER2" reject_exit "$(VOTE "$NONCE")"
if [[ "$(rec '[(.approvers|length), .pending] | @json')" == "[2,null]" ]]; then pass "Q3 one reject drops the change"; else fail "Q3 after the reject: $(record | head -c 300)"; fi
taken "Q3 proposed again" "$OWNER" set_exit_approvers "$(SET 0)"
NONCE=$(rec .pending.nonce)
taken "Q3 the first approver approves" "$APPROVER1" approve_exit "$(VOTE "$NONCE")"
if [[ "$(rec '.approvers|length')" == 2 ]]; then pass "Q3 one approval of two changes nothing"; else fail "Q3 the set changed below its quorum"; fi
taken "Q3 the second approver approves" "$APPROVER2" approve_exit "$(VOTE "$NONCE")"
if [[ "$(rec '[(.approvers|length), .threshold, .pending] | @json')" == "[0,0,null]" ]]; then pass "Q3 approved by the set in force, the change is in force"
else fail "Q3 after the quorum: $(record | head -c 300)"; fi

verdict owner_exit
