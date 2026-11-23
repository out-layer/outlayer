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
#       — and a view at the block that executed the raise shows it (the worker's in-order
#       relay reads there). D1 and W1 also measure what the DAO stores against the fees
#   W1  the owner's signature creates the wallet: the key answers with the address and
#       `exit_owner`; the escrow of the generation is on chain
#   W2  the link again, and a link for a seed the owner has: 409. A link signed by another
#       account in the owner's name, and a link with a changed payload: refused
#   W3  a second wallet (seed 1); the keystore signs for the owner's scope
#   E1  the same proof for one link sent twice at once: one 200, one 409, one wallet
#   E3  the owner's own `Bearer near:` with "master":"owner" acts on the owner's wallet of
#       that seed — generation 1's before the exit, generation 2's after it
#   E4  a sub-wallet of the owner's wallet (`PUT /wallet/v1/api-key` with its key): after
#       the exit `compute-wallet-id --vault-id owner:<account>:1` gives its id and the
#       master gives its key
#   A1  what OutLayer serves for wallet 0 before the exit: its near, EVM (base), solana and
#       EVM sub-key (`sub_path`) addresses and public keys, kept for X5
#   E7  a NEAR-signed api-key claim whose body names another key_hash, or a vault the
#       signature does not name: 400 each, saying which; the claim as signed is taken
#   E8  an agent secret through the owner's wallet: stored with the keystore's signature
#       (no vault), opens under the wallet's own key, deleted
#   E9  a trial key claimed with the owner's wallet runs a call (skipped while this
#       machine has no trial available)
#   E11 a funded payment key of the owner's wallet — bought with PARENT's testnet stablecoin;
#       the NEAR-deposit route swaps through Intents, which testnet lacks — runs a call
#   E10 sign-message refuses a NEP-641 recipient (`<chain>: <account>[ -> …][ @ <time>]`)
#       with its own words; an ordinary recipient is signed (wallet 0 has no policy)
#   B1  `PUT /wallet/v1/binding` with the owner's wallet: to another account (personal mode)
#       and in the leased mode (another account, the owner's own) refused with the
#       coordinator's words; the owner's own account in the personal mode taken, pending,
#       then deleted
#   B2  a w_execute_extension of the owner's wallet on another account: refused in the
#       keystore's words
#   E5  a full-access key deleted from the owner's account stops opening the owner's
#       wallets; the row says how long the coordinator kept it
#   X1  an exit without the fee is refused; started with it; a second one is refused; a
#       claim before the window is refused; cancelled; started again; the wallet still signs
#   X2  after the window: the claim hands the master over once — generation +1, nothing
#       pending, a second claim refused; the claim file opens the same master again
#   E6  a claim onto an existing claim file is refused and leaves the file as it was
#   X3  the tool finds both wallets by their numbered seeds, and each derived key is the
#       wallet's; a transfer signed with a derived key lands
#   X5  every key of wallet 0 that `derive-wallet-key --chain all --sub-path` derives from
#       the master is the one A1 was served: near address; EVM, solana and sub-key address
#       and public key
#   X4  the wallets' API keys are refused (403, naming the owner's exit) after it
#   X6  no payment key of the wallet that left spends: E9's trial key (when E9 got one) and
#       E11's funded key answer 403 `wallet_exited`, the funded key's naming `outlayer keys
#       close <nonce>`; close_payment_key signed with X3's derived key is still taken, the
#       key closing on chain and unknown to the coordinator after it
#   G1  a new link, the same seed: a wallet in generation 2 at another address
#   C1  a claim MPC refuses (a key that is no point) leaves no claim in flight and the
#       generation where it was; the owner's wallet still signs
#   C2  a claim with less gas than it reserves fails whole and leaves nothing
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
# policy, and waits two exit windows (about three minutes). E11 sends wallet 0 1 NEAR and
# 0.05 of PARENT's testnet stablecoin; the closed key's refund is claimable a day later by
# the wallet's account, whose key the run deletes, so it stays where it is. What each part proves and how
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
E9_KEPT=""
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

# pk_call <payment-key> — a ping of connector-probe paid with the key. The key reaches curl
# on stdin, never on its command line; sets HTTP and BODY.
pk_call() {
  local out; out=$(mktemp -t oe_call.XXXXXX)
  HTTP=$(printf 'X-Payment-Key: %s\n' "$1" | curl -sS -o "$out" -w '%{http_code}' -X POST \
    "$COORDINATOR_URL/call/connectors.outlayer.testnet/connector-probe" -H @- -H 'Content-Type: application/json' \
    --data-binary '{"input":{"operation":"ping"}}' --max-time 150 2>/dev/null)
  BODY=$(tr -d '\n' < "$out"); rm -f "$out"
}

# One JSON-RPC call to the keyed RPC: the URL reaches curl on stdin, never on its command line.
rpc_post() { printf 'url = "%s"\n' "$RPC_URL" | curl -sS --max-time 30 -K - -H 'Content-Type: application/json' --data-binary "$1"; }
# The DAO account's storage, in bytes.
dao_storage() { rpc_post "$(jq -nc --arg a "$DAO" '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"view_account",finality:"final",account_id:$a}}')" | jq -r '.result.storage_usage // empty'; }
# storage_row <name> <bytes before> <bytes after> <yocto it may cost at most> — the DAO grew,
# and by no more than the amount paid covers at NEAR's storage price (1e19 yocto a byte).
storage_row() {
  local name=$1 before=$2 after=$3 cap=$4
  if ! [[ "$before" =~ ^[0-9]+$ && "$after" =~ ^[0-9]+$ ]]; then fail "$name: the DAO's storage could not be read"; return; fi
  local grew=$(( after - before ))
  if (( grew > 0 )) && python3 -I -c 'import sys; sys.exit(0 if int(sys.argv[1]) * 10**19 <= int(sys.argv[2]) else 1)' "$grew" "$cap"; then
    pass "$name: $grew bytes, $(yocto_near "$((grew))0000000000000000000"), within $(yocto_near "$cap")"
  else fail "$name: the DAO grew by $grew bytes, which $(yocto_near "$cap") does not cover"; fi
}
# The hash of the transaction near-cli just sent (its output is in OUT).
sent_tx() { grep -oE 'Transaction ID: [1-9A-HJ-NP-Za-km-z]{43,44}' <<<"$OUT" | tail -1 | cut -d' ' -f3; }
# The owner's `Bearer near:` for a seed, with "master":"owner": the owner's wallet of that
# seed in the owner's current generation. bearer_owner <seed> <METHOD> <path> [creds-file]
bearer_owner() {
  local seed=$1 method=$2 path=$3 creds=${4:-$OWNER_CREDS} token out
  token=$(CUSTOMER_RECOVERY_PRIVATE_KEY="$(jq -r .private_key "$creds")" "$RECOVERY_BIN" sign-bearer-near \
    --account-id "$OWNER" --seed "$seed" --owner 2>/dev/null)
  out=$(mktemp -t oe_bearer.XXXXXX)
  HTTP=$(printf 'Authorization: Bearer near:%s\n' "$token" \
    | curl -sS -o "$out" -w '%{http_code}' -X "$method" "$COORDINATOR_URL$path" --max-time 60 -H @- 2>/dev/null)
  BODY=$(tr -d '\n' < "$out"); rm -f "$out"
}

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
ST_BEFORE_REG=$(dao_storage)
taken "D1 registered with the fee" "$OWNER" register_exit_owner "$(W "$MIN_W")" "$FEE"
if [[ "$(rec '[.generation, .exit_window_secs, (.approvers|length), .pending] | @json')" == "[1,$MIN_W,0,null]" ]]; then
  pass "D1 the record: generation 1, the window asked for, no approvers, nothing pending"
else fail "D1 the record is $(record | head -c 300)"; fi
refused "D1 a second registration" "already registered" "$OWNER" register_exit_owner "$(W "$MIN_W")" "$FEE"
storage_row "D1 the registration's storage" "$ST_BEFORE_REG" "$(dao_storage)" "$REG_FEE"

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
# The worker reads a wallet's state at the block of the event that changed it: a view at the
# block that EXECUTED a change must show the change.
RAISE_TX=$(sent_tx)
RAISE_BLOCK=""
if [[ -n "$RAISE_TX" ]]; then
  TXQ=$(jq -nc --arg h "$RAISE_TX" --arg s "$OWNER" '{jsonrpc:"2.0",id:1,method:"tx",params:{tx_hash:$h,sender_account_id:$s,wait_until:"FINAL"}}')
  RAISE_BLOCK=$(rpc_post "$TXQ" | jq -r --arg d "$DAO" '[.result.receipts_outcome[] | select(.outcome.executor_id == $d)][0].block_hash // empty')
fi
if [[ -z "$RAISE_BLOCK" ]]; then fail "D3 the block that executed the raise could not be read (tx ${RAISE_TX:-not found in the output of near-cli})"
else
  ARGS64=$(jq -nc --arg a "$OWNER" '{account:$a}' | base64 | tr -d '\n')
  VQ=$(jq -nc --arg d "$DAO" --arg b "$RAISE_BLOCK" --arg a "$ARGS64" '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"call_function",block_id:$b,account_id:$d,method_name:"get_exit_owner",args_base64:$a}}')
  AT=$(rpc_post "$VQ" | jq -r '.result.result // empty | implode | fromjson | .exit_window_secs' 2>/dev/null)
  if [[ "$AT" == "$RAISED_W" ]]; then pass "D3 a view at the block that executed the raise shows it (${RAISED_W}s)"
  else fail "D3 a view at the executing block shows ${AT:-nothing}, not ${RAISED_W}s: the in-order relay would read the state before the change"; fi
fi
if [[ "$(window)" == "[$RAISED_W,null]" ]]; then pass "D3 a raise is in force at once"; else fail "D3 after the raise: $(window)"; fi
taken "D3 lowered to ${MIN_W}s" "$OWNER" set_exit_window "$(W "$MIN_W")"
if [[ "$(window)" == "[$RAISED_W,$MIN_W]" ]]; then pass "D3 a lowering waits; the window in force stays"; else fail "D3 after the lowering: $(window)"; fi
taken "D3 raised again" "$OWNER" set_exit_window "$(W "$RAISED_W")"
if [[ "$(window)" == "[$RAISED_W,null]" ]]; then pass "D3 a raise drops the pending lowering"; else fail "D3 the lowering survived a raise: $(window)"; fi
taken "D3 lowered again, left to take effect" "$OWNER" set_exit_window "$(W "$MIN_W")"

# ── W1–W3: wallets ───────────────────────────────────────────────────────────
log "W1 the owner's signature creates the wallet"
ST_BEFORE_ESCROW=$(dao_storage)
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
# The escrow of generation 1 is paid out of the registration fee; what an exit pays for
# the next one is the exit fee less the keystore's gas allowance (0.005 NEAR).
storage_row "W1 the escrow's storage" "$ST_BEFORE_ESCROW" "$(dao_storage)" "$(python3 -I -c 'import sys; print(int(sys.argv[1]) - 5 * 10**21)' "$EXIT_FEE")"

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
# Seed 0 also pays E8's agent-secret call (0.2 NEAR attached, the storage returned by the
# deletion) and its gas.
if ! { fund_account "$ACCOUNT0" 0.35 && fund_account "$ACCOUNT1" 0.01; }; then fail "W3 the wallets could not be funded"; fi

# ── E1: one link, the same proof twice at once ───────────────────────────────
log "E1 the same wallet request twice at once"
if new_link e1-race; then
  KEY_RACE=$KEY; prepare "$LINK"; E1_MSG=$(jq -r '.message // ""' <<<"$BODY")
  E1_NONCE=$(head -c 32 /dev/urandom | base64 | tr -d '\n')
  E1_SIG=$(CUSTOMER_RECOVERY_PRIVATE_KEY="$(jq -r .private_key "$OWNER_CREDS")" "$RECOVERY_BIN" sign-nep413 \
    --message "$E1_MSG" --recipient outlayer:owner-wallet --nonce-base64 "$E1_NONCE" | jq -r .signature)
  E1_BODY=$(jq -nc --arg l "$LINK" --arg a "$OWNER" --arg pk "$(jq -r .public_key "$OWNER_CREDS")" --arg s "$E1_SIG" --arg n "$E1_NONCE" \
    '{link:$l, account_id:$a, public_key:$pk, signature:$s, nonce:$n}')
  ( api - POST /wallet/v1/owner-wallet "$E1_BODY" >/dev/null; echo "$HTTP" > "$WORK/e1a" ) &
  ( api - POST /wallet/v1/owner-wallet "$E1_BODY" >/dev/null; echo "$HTTP" > "$WORK/e1b" ) &
  wait
  E1_CODES=$(sort <<<"$(cat "$WORK/e1a" "$WORK/e1b")" | tr '\n' ' ')
  if [[ "$E1_CODES" == "200 409 " ]]; then pass "E1 one 200, one 409"
  else fail "E1 two requests at once answered: ${E1_CODES:-nothing}"; fi
  api_wk "$KEY_RACE" GET '/wallet/v1/address?chain=near' >/dev/null
  [[ "$HTTP" == 200 && "$(jq -r .exit_owner.account_id <<<"$BODY")" == "$OWNER" ]] && pass "E1 the link's one key answers for the one wallet" \
    || fail "E1 the link's key answered $HTTP after the race"
else fail "E1 no link: $HTTP $(why)"; fi

# ── E3: the owner's own Bearer near: with "master":"owner" ───────────────────
log "E3 the owner's NEAR signature acts on the owner's wallets"
bearer_owner 0 GET '/wallet/v1/address?chain=near'
[[ "$HTTP" == 200 && "$(jq -r .address <<<"$BODY")" == "$ACCOUNT0" ]] && pass "E3 seed 0 is the owner's first wallet" \
  || fail "E3 Bearer near (owner, seed 0): $HTTP, address $(jq -r '.address // "none"' <<<"$BODY" 2>/dev/null)"
bearer_owner 1 GET '/wallet/v1/address?chain=near'
[[ "$HTTP" == 200 && "$(jq -r .address <<<"$BODY")" == "$ACCOUNT1" ]] && pass "E3 seed 1 is the second" \
  || fail "E3 Bearer near (owner, seed 1): $HTTP"

# ── E4: a sub-wallet of an owner's wallet ────────────────────────────────────
log "E4 a sub-wallet of the owner's wallet"
SUB_KEY="wk_$(head -c 32 /dev/urandom | xxd -p -c 64)"
SUB_HASH=$(printf '%s' "$SUB_KEY" | shasum -a 256 | cut -d' ' -f1)
api_wk "$KEY0" PUT /wallet/v1/api-key "$(jq -nc --arg h "$SUB_HASH" '{seed:"sub1", key_hash:$h}')" >/dev/null
SUB_WALLET=$(jq -r '.wallet_id // empty' <<<"$BODY"); SUB_ACCOUNT=$(jq -r '.near_account_id // empty' <<<"$BODY")
if [[ "$HTTP" == 200 && -n "$SUB_WALLET" && "$SUB_WALLET" != "$WALLET0" ]]; then
  pass "E4 a sub-wallet of the owner's wallet: another wallet"
  [[ "$(jq -r '.vault_id // "none"' <<<"$BODY")" != owner:* ]] && pass "E4 the answer names no owner path as a vault" \
    || fail "E4 the answer shows the owner path as vault_id"
  api_wk "$SUB_KEY" GET '/wallet/v1/address?chain=near' >/dev/null
  [[ "$HTTP" == 200 && "$(jq -r .address <<<"$BODY")" == "$SUB_ACCOUNT" ]] && pass "E4 its key answers with its address" \
    || fail "E4 the sub-wallet's key: $HTTP"
else fail "E4 PUT /wallet/v1/api-key with the owner's wallet key: $HTTP $(why)"; SUB_WALLET=""; fi

# ── A1: what OutLayer serves for wallet 0, while its key still works ─────────
# After the exit the generation's keys answer 403, so X5 compares the master's keys with
# what is kept here. Addresses and public keys only: nothing here is a secret.
log "A1 the addresses OutLayer serves for wallet 0"
A1_SUB_PATH="owner-exit.a1"
# served <query> — what `GET /wallet/v1/address?<query>` answers for wallet 0, as
# "address public_key sub_path" ("-" for a field it leaves out); "- - - <status> <why>" when
# it refuses. It runs in a command substitution, so its answer is all the caller sees of
# the request: HTTP and BODY stay the subshell's.
served() {
  api_wk "$KEY0" GET "/wallet/v1/address?$1" >/dev/null
  if [[ "$HTTP" == 200 ]]; then jq -r '"\(.address // "-") \(.public_key // "-") \(.sub_path // "-")"' <<<"$BODY"
  else echo "- - - $HTTP $(why)"; fi
}
read -r SERVED_NEAR _ _ WHY <<<"$(served chain=near)"
[[ "$SERVED_NEAR" == "$ACCOUNT0" ]] && pass "A1 near: the wallet's account" \
  || fail "A1 near: $SERVED_NEAR ${WHY:+($WHY)}, the wallet is $ACCOUNT0"
read -r SERVED_EVM SERVED_EVM_PK _ WHY <<<"$(served chain=base)"
[[ "$SERVED_EVM" =~ ^0x[0-9a-f]{40}$ && "$SERVED_EVM_PK" == secp256k1:* ]] && pass "A1 evm (base): $SERVED_EVM" \
  || fail "A1 evm (base): $SERVED_EVM ${WHY:+($WHY)}"
read -r SERVED_SOL SERVED_SOL_PK _ WHY <<<"$(served chain=solana)"
[[ "$SERVED_SOL" =~ ^[1-9A-HJ-NP-Za-km-z]{32,44}$ && "$SERVED_SOL_PK" == "$SERVED_SOL" ]] && pass "A1 solana: $SERVED_SOL" \
  || fail "A1 solana: $SERVED_SOL ${WHY:+($WHY)}"
read -r SERVED_SUB SERVED_SUB_PK SERVED_SUB_PATH WHY <<<"$(served "chain=base&sub_path=$A1_SUB_PATH")"
if [[ "$SERVED_SUB" =~ ^0x[0-9a-f]{40}$ && "$SERVED_SUB_PK" == secp256k1:* && "$SERVED_SUB_PATH" == "$A1_SUB_PATH" ]]; then
  [[ "$SERVED_SUB" != "$SERVED_EVM" ]] && pass "A1 evm sub-key $A1_SUB_PATH: $SERVED_SUB, not the wallet's own" \
    || fail "A1 the sub-key $A1_SUB_PATH is served at the wallet's own EVM address"
else fail "A1 evm sub-key $A1_SUB_PATH: $SERVED_SUB, sub_path $SERVED_SUB_PATH ${WHY:+($WHY)}"; fi

# ── E7: a NEAR-signed api-key claim is held to what it signs ─────────────────
log "E7 a signed api-key claim is held to the key and the vault it names"
E7_KEY="wk_$(head -c 32 /dev/urandom | xxd -p -c 64)"
E7_CLAIM=$(CUSTOMER_RECOVERY_PRIVATE_KEY="$(jq -r .private_key "$OWNER_CREDS")" "$RECOVERY_BIN" sign-api-key-claim \
  --account-id "$OWNER" --seed e7 --sub-key "$E7_KEY" 2>/dev/null)
OTHER_HASH=$(printf '%s' "wk_another" | shasum -a 256 | cut -d' ' -f1)
api - PUT /wallet/v1/api-key "$(jq -c --arg h "$OTHER_HASH" '.key_hash = $h' <<<"$E7_CLAIM")" >/dev/null
[[ "$HTTP" == 400 ]] && grep -qF "key_hash in the signed message does not match" <<<"$BODY" \
  && pass "E7 another key_hash than the one signed: 400, named" || fail "E7 a changed key_hash: $HTTP $(why)"
api - PUT /wallet/v1/api-key "$(jq -c --arg v "$OWNER" '.vault_id = $v' <<<"$E7_CLAIM")" >/dev/null
[[ "$HTTP" == 400 ]] && grep -qF "vault_id in the signed message does not match" <<<"$BODY" \
  && pass "E7 a vault_id the signature does not name: 400, named" || fail "E7 an added vault_id: $HTTP $(why)"
api - PUT /wallet/v1/api-key "$E7_CLAIM" >/dev/null
[[ "$HTTP" == 200 ]] && pass "E7 the claim as signed is taken" || fail "E7 the unchanged claim: $HTTP $(why)"

# ── E8: an agent secret through the owner's wallet ───────────────────────────
# A secret is the wallet's ACCOUNT's, never under the owner's master: the contract takes
# the keystore's signature with no vault in it, the keystore reads what it stored, and
# the deletion is taken.
log "E8 an agent secret stored, read and deleted through the owner's wallet"
E8_PROJECT="${E8_PROJECT:-connectors.outlayer.testnet/connector-probe}"
e8_view() {
  local args q
  args=$(jq -nc --arg p "$E8_PROJECT" --arg a "$ACCOUNT0" '{accessor:{Project:{project_id:$p}}, profile:$a, owner:$a}' | base64 | tr -d '\n')
  q=$(jq -nc --arg a "$args" '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"call_function",finality:"final",account_id:"outlayer.testnet",method_name:"get_secret_with_vault",args_base64:$a}}')
  rpc_post "$q" | jq -r '.result.result // empty | implode' 2>/dev/null
}
# One attempt; on a failure the row reports the step and the CLI's exit code, never its output.
E8_SET_EXIT=0
OUTLAYER_NETWORK=testnet OUTLAYER_WALLET_KEY="$KEY0" outlayer secrets set-for-agent '{"E8_PROBE":"owner-exit"}' \
  --project "$E8_PROJECT" --agent-pays >/dev/null 2>&1 || E8_SET_EXIT=$?
if [[ "$E8_SET_EXIT" == 0 ]]; then
  pass "E8 the secret is stored: the contract took the keystore's signature for the owner's wallet"
  # The CLI answers once the store has executed; a read at final finality sees it a block or
  # two later.
  E8_SEEN=""; E8_CT=""
  for _ in $(seq 1 10); do
    E8_SEEN=$(e8_view); E8_CT=$(jq -r '.profile.encrypted_secrets // empty' <<<"$E8_SEEN" 2>/dev/null)
    [[ -n "$E8_CT" ]] && break; sleep 2
  done
  if [[ -n "$E8_CT" ]]; then
    [[ "$(jq -r '.vault_id // "none"' <<<"$E8_SEEN")" == none ]] && pass "E8 on chain under the wallet's account, with no vault" \
      || fail "E8 the stored secret names a vault: $(jq -r '.vault_id' <<<"$E8_SEEN")"
    api_wk "$KEY0" POST /wallet/v1/agent-secret/prepare \
      "$(jq -nc --arg p "$E8_PROJECT" --arg c "$E8_CT" --arg payer "$PARENT" '{project_id:$p, encrypted_secrets_base64:$c, payer:$payer}')" >/dev/null
    [[ "$HTTP" == 2?? ]] && pass "E8 what is stored opens under the wallet's own key (prepare $HTTP)" \
      || fail "E8 the stored secret does not open for the wallet: prepare $HTTP $(why)"
  else fail "E8 no secret on chain for $ACCOUNT0 under $E8_PROJECT"; fi
  if [[ -z "$E8_CT" ]]; then fail "E8 the deletion is not judged: the secret was never seen on chain"
  elif OUTLAYER_NETWORK=testnet OUTLAYER_WALLET_KEY="$KEY0" outlayer secrets delete-for-agent --project "$E8_PROJECT" --yes >/dev/null 2>&1; then
    E8_GONE=""
    for _ in $(seq 1 10); do [[ -z "$(e8_view | jq -r '.profile.encrypted_secrets // empty' 2>/dev/null)" ]] && { E8_GONE=1; break; }; sleep 2; done
    [[ -n "$E8_GONE" ]] && pass "E8 the deletion is taken: nothing left on chain" || fail "E8 the secret is still on chain after its deletion"
  else fail "E8 delete-for-agent was refused"; fi
else fail "E8 set-for-agent through the owner's wallet failed (outlayer exited $E8_SET_EXIT)"; fi

# ── E9: a trial key of an owner's wallet ─────────────────────────────────────
log "E9 a trial key claimed with the owner's wallet"
api_wk "$KEY0" POST /trial-key >/dev/null
E9_PK=$(jq -r '.payment_key // empty' <<<"$BODY")
if [[ "$(jq -r '.reason // ""' <<<"$BODY")" == trial_unavailable ]]; then
  skip "E9 no trial is available to this machine now (trial_unavailable): run E9 again when one is"
elif [[ "$HTTP" != 200 || -z "$E9_PK" ]]; then
  fail "E9 /trial-key with the owner's wallet: $HTTP $(why)"
else
  pass "E9 a trial key for the owner's wallet: nonce $(jq -r .nonce <<<"$BODY")"
  # Kept for X6, never shown.
  E9_KEPT=$E9_PK; unset E9_PK
  pk_call "$E9_KEPT"
  [[ "$HTTP" == 200 && "$(jq -r .status <<<"$BODY")" == completed ]] && pass "E9 the trial key runs a call" \
    || fail "E9 a call on the trial key: $HTTP $(why)"
fi

# ── E11: a funded payment key of the owner's wallet ──────────────────────────
# Bought with PARENT's testnet stablecoin: the NEAR-deposit route swaps through Intents,
# which testnet does not have. X6 spends it after the exit, and closes it.
log "E11 a funded payment key of the owner's wallet"
E11_PK=""; E11_NONCE=""
if FUND_USDC_MINIMAL=50000 DEPOSIT_USDC=0.05 buy_payment_key "$KEY0" "$ACCOUNT0"; then
  E11_PK=$PAID_KEY; PAID_KEY=""; E11_NONCE=$(jq -r '.nonce // empty' <<<"$BODY")
  pass "E11 a funded key for the owner's wallet: nonce $E11_NONCE"
  pk_call "$E11_PK"
  [[ "$HTTP" == 200 && "$(jq -r .status <<<"$BODY")" == completed ]] && pass "E11 the funded key runs a call" \
    || fail "E11 a call on the funded key: $HTTP $(why)"
else fail "E11 no funded key could be made for the owner's wallet"; fi

# ── E10: the owner's wallet signs no offchain authorization ──────────────────
# A NEP-413 signature over a NEP-641 recipient would be the account's own word, given off
# chain. The keystore refuses one under any policy, with or without the time. Wallet 0 has
# no policy here, so any other recipient is signed: the refusal is the NEP-641 rule's own,
# not a refusal of every recipient.
log "E10 sign-message refuses a NEP-641 recipient, with and without its time"
e10_sign() { api_wk "$KEY0" POST /wallet/v1/sign-message "$(jq -nc --arg r "$1" '{message:"e10", recipient:$r}')" >/dev/null; }
for R in "testnet: $OWNER @ $(date -u +%Y-%m-%dT%H:%M:%SZ)" "testnet: $OWNER" "testnet: $OWNER -> $ACCOUNT0"; do
  e10_sign "$R"
  if [[ "$HTTP" == 403 ]] && grep -qF "NEP-641 offchain authorization" <<<"$BODY"; then pass "E10 refused, as a NEP-641 authorization: \"$R\""
  else fail "E10 \"$R\": $HTTP $(why)"; fi
done
e10_sign "app.example.testnet"
if [[ "$HTTP" == 200 && "$(jq -r '.signature // ""' <<<"$BODY")" == ed25519:* && "$(jq -r '.account_id // ""' <<<"$BODY")" == "$ACCOUNT0" ]]; then
  pass "E10 an ordinary recipient is signed by wallet 0, which has no policy: the NEP-641 rule refuses only its own form"
else fail "E10 an ordinary recipient: $HTTP $(why)"; fi

# ── B1–B2: a wallet that can leave acts only on its owner's account ──────────
# The wallet's NEAR key is the executor of any account it is bound to, and it leaves with
# the owner's master. So the coordinator binds it to the owner's own account alone, and
# never in the leased mode; the keystore signs no w_execute_extension on another account.
log "B1 the owner's wallet is bound only to the owner's own account"
B_WORDS="is bound only to the account they leave to"
b1_put() { api_wk "$KEY0" PUT /wallet/v1/binding "$1" >/dev/null; }
b1_refused() { # b1_refused <name> <words> <body>
  b1_put "$3"
  if [[ "$HTTP" == 400 ]] && grep -qF "$B_WORDS" <<<"$BODY" && grep -qF "$2" <<<"$BODY"; then pass "$1: 400, $2"
  else fail "$1: $HTTP $(why)"; fi
}
b1_refused "B1 personal_account to another account" "'$PARENT' is not that account" \
  "$(jq -nc --arg a "$PARENT" '{asset_account_id:$a, kind:"personal_account"}')"
# impl_version 6 is a version the coordinator's own migration seeds: a refusal that names
# impl_version is the version check, not this rule, and fails the row.
b1_refused "B1 hos_lease to another account" "kind=hos_lease" \
  "$(jq -nc --arg a "$PARENT" '{asset_account_id:$a, owner_account_id:$a, impl_version:6, kind:"hos_lease"}')"
b1_refused "B1 hos_lease to the owner's own account" "kind=hos_lease" \
  "$(jq -nc --arg a "$OWNER" '{asset_account_id:$a, owner_account_id:$a, impl_version:6, kind:"hos_lease"}')"
# The owner's own account in the personal mode is taken: a pending record, nothing on
# chain until the owner installs the wallet contract — which this run does not. Deleted
# at once.
b1_put "$(jq -nc --arg a "$OWNER" '{asset_account_id:$a, kind:"personal_account"}')"
if [[ "$HTTP" == 200 && "$(jq -r '[.kind, .asset_account_id, .binding_status] | @json' <<<"$BODY")" == "[\"personal_account\",\"$OWNER\",\"pending\"]" ]]; then
  pass "B1 personal_account to the owner's own account: taken, pending"
  api_wk "$KEY0" DELETE /wallet/v1/binding >/dev/null
  [[ "$HTTP" == 200 && "$(jq -r .binding_status <<<"$BODY")" == revoked ]] && pass "B1 and deleted" \
    || fail "B1 the binding to the owner's account could not be deleted: $HTTP $(why)"
else fail "B1 personal_account to the owner's own account: $HTTP $(why)"; fi

log "B2 the keystore signs no w_execute_extension on another account"
# An unbound account, so nothing in the coordinator stands in the way: the refusal is the
# keystore's, before its version gate, the decoder and the policy. A keystore without the
# rule refuses the call at that gate instead (no binding names a decoder), in other words,
# and the row fails on the words; nothing is signed either way.
B2_ARGS=$(jq -nc --arg a "$PARENT" '{request:{external:[{receiver_id:$a, actions:[{action:"transfer", payload:{amount:"1"}}]}]}}')
api_wk "$KEY0" POST /wallet/v1/call "$(jq -nc --arg r "$PARENT" --argjson a "$B2_ARGS" '{receiver_id:$r, method_name:"w_execute_extension", args:$a, deposit:"1"}')" >/dev/null
if [[ "$HTTP" =~ ^4 ]] && grep -qF "acts through w_execute_extension only on the account they leave to" <<<"$BODY" \
   && grep -qF "'$PARENT' is not that account" <<<"$BODY"; then pass "B2 refused ($HTTP), in the keystore's words"
else fail "B2 a w_execute_extension on $PARENT: $HTTP $(why)"; fi

# ── E5: a key deleted from the owner's account ───────────────────────────────
log "E5 a key deleted from the owner's account stops opening the owner's wallets"
E5_KP=$(node "$HOS_LIB_DIR/ed25519_keypair.mjs")
E5_CREDS="$WORK/second-key.json"
( umask 077; jq -c --arg a "$OWNER" '. + {account_id:$a}' <<<"$E5_KP" > "$E5_CREDS" ); unset E5_KP
E5_PK=$(jq -r .public_key "$E5_CREDS")
if near --quiet account add-key "$OWNER" grant-full-access use-manually-provided-public-key "$E5_PK" \
     network-config "$NETWORK" sign-with-keychain send >/dev/null 2>&1; then
  bearer_owner 0 GET '/wallet/v1/address?chain=near' "$E5_CREDS"
  if [[ "$HTTP" == 200 ]]; then pass "E5 a second full-access key of the owner opens the owner's wallet"
  else fail "E5 the second key's Bearer near answered $HTTP before it was deleted"; fi
  if near --quiet account delete-keys "$OWNER" public-keys "$E5_PK" network-config "$NETWORK" sign-with-keychain send >/dev/null 2>&1; then
    E5_T0=$(date +%s); E5_AFTER=""
    for _ in $(seq 1 36); do
      bearer_owner 0 GET '/wallet/v1/address?chain=near' "$E5_CREDS"
      [[ "$HTTP" == 401 ]] && { E5_AFTER=$(( $(date +%s) - E5_T0 )); break; }
      sleep 10
    done
    if [[ -n "$E5_AFTER" ]]; then pass "E5 the deleted key is refused (401) ${E5_AFTER}s after its deletion"
    else fail "E5 the deleted key still opens the owner's wallet 6 minutes after its deletion (last answer $HTTP)"; fi
  else fail "E5 the second key could not be deleted"; fi
else fail "E5 a second key could not be added to the owner"; fi

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
# The lowering D3 left pending takes effect one raised window after it was asked for; the
# rows since then may or may not have taken that long. Whichever window is in force when
# the exit starts is the one it must wait.
LOWERED_AT=$(rec '(.pending_exit_window.effective_at // 0) / 1e9 | floor')
T0=$(date +%s)
if (( LOWERED_AT > T0 + 5 )); then IN_FORCE=$RAISED_W; WHICH="the raised window (the lowering is still pending)"
elif (( LOWERED_AT == 0 || LOWERED_AT < T0 - 5 )); then IN_FORCE=$MIN_W; WHICH="the lowered window (the lowering took effect)"
else IN_FORCE=""; fi
if OUT=$(exit_tool initiate); then pass "X1 the exit is started"; else fail "X1 initiate: $(near_why "$OUT")"; fi
LEFT=$(( $(finalize_after) - T0 ))
if [[ -z "$IN_FORCE" ]]; then skip "X1 the exit started within 5 s of the lowering taking effect: which window applies is not judged"
elif (( LEFT > 0 && LEFT >= IN_FORCE - 10 && LEFT <= IN_FORCE + 30 )); then pass "X1 the exit waits $WHICH: ${LEFT}s"
else fail "X1 the exit waits ${LEFT}s; $WHICH is ${IN_FORCE}s"; fi
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

# A copy of the claim file for the check that needs time (H5 in the test plan: does the RPC
# still answer for the claim a day and a week later). Kept only when asked for, owner-only.
if [[ -n "${KEEP_CLAIM_DIR:-}" ]]; then
  ( umask 077; mkdir -p "$KEEP_CLAIM_DIR" && cp "$CLAIM" "$KEEP_CLAIM_DIR/$OWNER.$(date -u +%Y%m%dT%H%M%SZ).json" ) \
    && note "claim file kept in KEEP_CLAIM_DIR for a later 'owner-exit open'"
fi

log "E6 a claim never writes over a claim file"
E6_BEFORE=$(shasum -a 256 "$CLAIM" | cut -d' ' -f1)
claim "$CLAIM"
if [[ $RC -ne 0 && -z "$MASTER" && "$(shasum -a 256 "$CLAIM" | cut -d' ' -f1)" == "$E6_BEFORE" ]]; then
  pass "E6 a claim onto an existing file is refused, and the file is untouched"
else fail "E6 a claim onto an existing file: rc=$RC, file $( [[ "$(shasum -a 256 "$CLAIM" | cut -d' ' -f1)" == "$E6_BEFORE" ]] && echo untouched || echo CHANGED)"; fi
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
  elif ! near --quiet tokens "$IMPLICIT" send-near "$PARENT" '0.1 NEAR' network-config "$NETWORK" sign-with-keychain send >/dev/null 2>&1; then
    fail "X3 the transfer signed with the derived key was refused"
  else
    AFTER=$(account_field "$IMPLICIT" amount)
    if [[ "$AFTER" =~ ^[0-9]+$ ]] && python3 -I -c 'import sys; sys.exit(0 if int(sys.argv[2]) <= int(sys.argv[1]) - 10**23 else 1)' "$BEFORE" "$AFTER"; then
      pass "X3 a transfer signed with the derived key landed"
    else fail "X3 the derived key's transfer did not land (balance before ${#BEFORE} digits, after: ${AFTER:-unreadable})"; fi
  fi
else fail "X3 the derived key is not the wallet's"; fi

log "E4 the sub-wallet after the exit"
if [[ -z "$SUB_WALLET" ]]; then fail "E4 no sub-wallet to find after the exit"
else
  SUB_ID=$("$RECOVERY_BIN" compute-wallet-id --account-id "$WALLET0" --seed sub1 --vault-id "owner:$OWNER:1" 2>/dev/null | tail -1 | tr -d '[:space:]')
  [[ "$SUB_ID" == "$SUB_WALLET" ]] && pass "E4 compute-wallet-id gives the id the coordinator gave it" \
    || fail "E4 compute-wallet-id gives ${SUB_ID:-nothing}, the coordinator gave $SUB_WALLET"
  SUB_DERIVED=$(CUSTOMER_RECOVERY_MASTER="$MASTER1" "$RECOVERY_BIN" derive-wallet-key --wallet-id "$SUB_WALLET" 2>/dev/null | jq -r '.near_address // empty')
  if [[ -z "$SUB_ACCOUNT" ]]; then fail "E4 the coordinator named no account for the sub-wallet: nothing to compare the derived key with"
  elif [[ ! "$SUB_DERIVED" =~ ^[0-9a-f]{64}$ ]]; then fail "E4 the recovery tool gave no implicit account for the sub-wallet"
  elif [[ "$SUB_DERIVED" == "$SUB_ACCOUNT" ]]; then pass "E4 the master gives the sub-wallet's key"
  else fail "E4 the key derived for the sub-wallet is not its address"; fi
fi
unset DERIVED

log "X5 every key of wallet 0 derived from the master is the one OutLayer served"
# The private keys are dropped as the tool's output is read: X5 holds addresses and public
# keys only.
X5=$(CUSTOMER_RECOVERY_MASTER="$MASTER1" "$RECOVERY_BIN" derive-wallet-key --wallet-id "$WALLET0" \
  --chain all --sub-path "$A1_SUB_PATH" 2>/dev/null | jq -c '[.keys[] | {chain, sub_path, address, public_key}]' 2>/dev/null)
# derived <chain> <sub_path or ""> <field>
derived() { jq -r --arg c "$1" --arg p "$2" --arg f "$3" \
  'first(.[] | select(.chain == $c and (.sub_path // "") == $p)) | .[$f] // empty' <<<"${X5:-[]}" 2>/dev/null; }
if [[ -z "$X5" ]]; then fail "X5 derive-wallet-key --chain all --sub-path gave no keys"
else
  X5_NEAR=$(derived near "" address)
  [[ -n "$SERVED_NEAR" && "$X5_NEAR" == "$SERVED_NEAR" ]] && pass "X5 near: the master's key is at $X5_NEAR" \
    || fail "X5 near: derived ${X5_NEAR:-nothing}, served ${SERVED_NEAR:-nothing}"
  X5_EVM=$(derived evm "" address)
  [[ -n "$SERVED_EVM" && "$X5_EVM" == "$SERVED_EVM" && "$(derived evm "" public_key)" == "$SERVED_EVM_PK" ]] \
    && pass "X5 evm: the master's key is at $X5_EVM, with the public key served" \
    || fail "X5 evm: derived ${X5_EVM:-nothing} ($(derived evm "" public_key)), served ${SERVED_EVM:-nothing} ($SERVED_EVM_PK)"
  X5_SOL=$(derived solana "" address)
  [[ -n "$SERVED_SOL" && "$X5_SOL" == "$SERVED_SOL" && "$(derived solana "" public_key)" == "$SERVED_SOL_PK" ]] \
    && pass "X5 solana: the master's key is at $X5_SOL" \
    || fail "X5 solana: derived ${X5_SOL:-nothing}, served ${SERVED_SOL:-nothing}"
  X5_SUB=$(derived evm "$A1_SUB_PATH" address)
  [[ -n "$SERVED_SUB" && "$X5_SUB" == "$SERVED_SUB" && "$(derived evm "$A1_SUB_PATH" public_key)" == "$SERVED_SUB_PK" ]] \
    && pass "X5 evm sub-key $A1_SUB_PATH: the master's key is at $X5_SUB, with the public key served" \
    || fail "X5 evm sub-key $A1_SUB_PATH: derived ${X5_SUB:-nothing}, served ${SERVED_SUB:-nothing}"
fi
unset X5

log "X4 OutLayer no longer serves the generation that left"
signs "$KEY0"
# The exit's own refusal: a 403 for another reason — a freeze, a blocked scope — is not it.
if [[ "$HTTP" == 403 ]] && grep -qF "($OWNER) has exited generation 1" <<<"$BODY"; then pass "X4 the wallet's key is refused: 403, naming the owner's exit"
else fail "X4 auth-sign after the exit answered $HTTP $(why)"; fi
signs "$KEY1"
if [[ "$HTTP" == 403 ]] && grep -qF "($OWNER) has exited generation 1" <<<"$BODY"; then pass "X4 and the second wallet's"
else fail "X4 auth-sign for seed 1 after the exit answered $HTTP"; fi

log "X6 no payment key of the wallet that left spends; its funded key still closes"
# The coordinator's own refusal: a 403 for another reason is not it.
spend_refused() { [[ "$HTTP" == 403 && "$(jq -r '.reason // ""' <<<"$BODY")" == wallet_exited && "$(jq -r '.terminal' <<<"$BODY")" == true ]]; }
if [[ -z "$E9_KEPT" ]]; then skip "X6 E9 got no trial key: its spending after the exit is not judged"
else
  pk_call "$E9_KEPT"
  if spend_refused && grep -qF "owner's exit" <<<"$BODY"; then pass "X6 the trial key spends nothing: 403 wallet_exited"
  else fail "X6 a call on the trial key after the exit: $HTTP $(why)"; fi
fi
if [[ -z "$E11_PK" || -z "$E11_NONCE" ]]; then fail "X6 no funded key from E11 to spend after the exit"
else
  pk_call "$E11_PK"
  if spend_refused && grep -qF "outlayer keys close $E11_NONCE" <<<"$BODY"; then
    pass "X6 the funded key spends nothing: 403 wallet_exited, naming \`outlayer keys close $E11_NONCE\`"
  else fail "X6 a call on the funded key after the exit: $HTTP $(why)"; fi
  if [[ -z "$IMPLICIT" ]]; then fail "X6 the funded key is not closed: X3 derived no key for the wallet's account"
  elif OUT=$(near contract call-function as-transaction "$CONTRACT_ID" close_payment_key \
      json-args "$(jq -nc --argjson n "$E11_NONCE" '{nonce:$n}')" prepaid-gas '100 Tgas' attached-deposit '1 yoctoNEAR' \
      sign-as "$IMPLICIT" network-config "$NETWORK" sign-with-keychain send 2>&1); then
    # The close answers once executed; the ledger is read at a final block.
    X6_SINCE=""
    for _ in $(seq 1 10); do
      X6_SINCE=$(near_view "$CONTRACT_ID" get_payment_key_refund_ledger \
        "$(jq -nc --arg o "$IMPLICIT" --argjson n "$E11_NONCE" '{owner:$o, nonce:$n}')" | jq -r '.closing_since // empty' 2>/dev/null)
      [[ "$X6_SINCE" =~ ^[0-9]+$ ]] && break; sleep 2
    done
    if [[ "$X6_SINCE" =~ ^[0-9]+$ ]]; then pass "X6 close_payment_key by the wallet's account is taken: the key is closing, its refund claimable in 24 h"
    else fail "X6 close_payment_key went through, but the ledger shows no close"; fi
    pk_call "$E11_PK"
    if [[ "$HTTP" == 401 && "$(jq -r '.reason // ""' <<<"$BODY")" == invalid_key ]]; then pass "X6 the closed key is unknown to the coordinator: 401 invalid_key"
    else fail "X6 a call on the closed key: $HTTP $(why)"; fi
  else fail "X6 close_payment_key by the wallet's account: $(near_why "$OUT")"; fi
fi
E9_KEPT=""; E11_PK=""

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
G2_ADDR=$(api_wk "$KEY2" GET '/wallet/v1/address?chain=near' >/dev/null; jq -r '.address // empty' <<<"$BODY")
bearer_owner 0 GET '/wallet/v1/address?chain=near'
[[ "$HTTP" == 200 && -n "$G2_ADDR" && "$(jq -r .address <<<"$BODY")" == "$G2_ADDR" && "$G2_ADDR" != "$ACCOUNT0" ]] \
  && pass "E3 after the exit the owner's signature acts on generation 2's wallet" \
  || fail "E3 Bearer near (owner, seed 0) after the exit: $HTTP, not generation 2's wallet"

# ── C1–C2: a claim that cannot finish leaves nothing standing ────────────────
# The claim marks the generation as leaving before it asks MPC; a claim that does not reach
# MPC, or that MPC refuses, must leave no mark (the mark refuses the owner's wallets for up
# to an hour) and must not move the generation.
log "C1 a claim MPC refuses; C2 a claim with too little gas"
if OUT=$(exit_tool initiate); then
  wait_for_window
  # The DAO takes the key as text; MPC refuses a string that is no G1 point.
  OUT=$(near contract call-function as-transaction "$DAO" claim_escrow_key '{"app_public_key":"bls12381g1:notapoint"}' \
    prepaid-gas '300 Tgas' attached-deposit '1 yoctoNEAR' sign-as "$OWNER" network-config "$NETWORK" sign-with-keychain send 2>&1)
  C1_RC=$?
  if [[ "$(rec '[.generation, .claim_in_flight, (.pending != null)] | @json')" == "[2,false,true]" ]]; then
    pass "C1 a claim MPC refused (rc=$C1_RC): no claim in flight, generation 2, the exit still pending"
  else fail "C1 after a refused claim the record is $(rec '{generation, claim_in_flight, pending: (.pending != null)}' | tr -d '\n')"; fi
  grep -qF "exit_claim_failed $OWNER" <<<"$OUT" && pass "C1 the DAO logged exit_claim_failed" \
    || note "C1 no exit_claim_failed log in near-cli's output (it may not print callback logs)"
  signs "$KEY2"
  [[ "$HTTP" == 200 ]] && pass "C1 the owner's wallet still signs after the refused claim" || fail "C1 auth-sign after a refused claim: $HTTP"
  # 100 TGas cannot hold the 130 TGas the claim reserves for MPC and its callback.
  OUT=$(near contract call-function as-transaction "$DAO" claim_escrow_key '{"app_public_key":"bls12381g1:notapoint"}' \
    prepaid-gas '100 Tgas' attached-deposit '1 yoctoNEAR' sign-as "$OWNER" network-config "$NETWORK" sign-with-keychain send 2>&1)
  if [[ $? -ne 0 && "$(rec '[.generation, .claim_in_flight] | @json')" == "[2,false]" ]]; then
    pass "C2 a claim with too little gas fails whole: no claim in flight, generation 2"
  else fail "C2 a claim with too little gas: record $(rec '{generation, claim_in_flight}' | tr -d '\n')"; fi
  if OUT=$(exit_tool cancel) && [[ "$(rec .pending)" == null ]]; then pass "C2 the exit is cancelled again"
  else fail "C2 cancel after the failed claims: $(near_why "$OUT")"; fi
else fail "C1 initiate: $(near_why "$OUT")"; fi

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
