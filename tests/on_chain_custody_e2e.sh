#!/usr/bin/env bash
#
# Agent On-chain custody on testnet: an owner sets up a wallet contract for their agent, the
# agent moves its funds under two signatures, and the owner's policy decides what is signed.
# The agent's side is tests/lib/custody_agent.mjs (custody-core's byte formats, held to its
# vectors before anything runs); the owner's page is played by near-cli and the recovery tool.
#
#   P   the keystore DAO lists the build; the agent's side matches custody-core's vectors and
#       the keystore's statement vector
#   F   an owner registers the exit and gets a wallet (generation 1, seed 0) from an agent link
#   S1  the setup: the agent opens it; the owner reads it, checks the keystore's statement over
#       the TEE key (its signature, then is_keystore_approved on the DAO), signs the agent key's message,
#       creates `agent.<owner>`, installs the published build with `(A, E)` and removes every
#       key; seals the owner's signature and its key; the agent collects it as the SDK does
#       (the NEP-413 signature, its key a full-access key of the owner on chain, the key it
#       derives, the keystore's statement, the pair on chain) and has the same key; a seal of a
#       signature by a key that is not the owner's is refused at the agent
#   S2  on chain: the account runs the approved build, answers `w_public_key` with the pair
#       the coordinator recorded, and has no access key
#   S3  the setup token is spent; a setup naming an account outside the owner's is refused;
#       the agent cannot name an account whose TEE key is another wallet's, or one with no
#       wallet contract
#   S4  a second wallet (seed 1) set up on the owner's own account: the owner's keys stay
#   N   no policy on chain: nothing is prepared
#   M1  a transfer within the policy: asked, the request checked and the TEE's half verified
#       by the agent, signed last, relayed by the working account; the recipient is paid once
#   R   refusals: a relay with a random half, with an HTTPS-request signature as the half,
#       with the TEE's half in the agent's place; on chain: the TEE's half alone, the two
#       swapped, and M1's proof sent again — none moves the balance. Then the agent's half:
#       the operation goes through
#   H   the HTTPS door: a request taken twice (409), a stale timestamp, a `wk_` on the
#       operation routes, an agent's signature on a `wk_` route, another key's signature;
#       an internal operation of the wallet contract (add_extension) cannot be asked for
#   P1  over `per_transaction`: refused, nothing to sign
#   A   the agent: the same id with another body is refused; the open operations list shows
#       an operation waiting for the agent's half; asking again continues it
#   P2  above `auto_up_to`: the operation waits; listed as pending; the approver votes; the
#       agent's repeat under the same id is prepared and goes through
#   D   the build list: the DAO revokes the build; an operation is not prepared, and one
#       prepared before is not relayed; the DAO approves it again and the agent goes on
#   T   a request past its ten minutes is not executed, and the balance does not move
#   I1  use_bound_identity: a program run with the flag runs as the wallet contract's account
#       (needs a trial key for the wallet; steps aside loudly without one)
#   S5  a new account with no key: the owner funds a one-time key with an ordinary transfer,
#       the key creates the wallet contract at its 0s address (NEP-616) by StateInit and
#       deletes its own account; the account has no key and no balance, runs the approved
#       build and holds the pair; the setup takes it; the spent token answers 409; a move
#   Z   STORAGE_MOVES calls (default 0) with no deposit from that zero-balance contract
#       (then, with STORAGE_REST seconds, a rest and one more call):
#       its storage against the zero-balance limit of 770 bytes
#   NM  an agent on a new machine: the owner's own signature (Bearer near:) stores a policy
#       naming a new key, which runs the wallet while the old one stops; a setup again shows
#       the wallet contract on record and hands the same agent key over for the same account
#   L   a locked policy on a wallet with a wallet contract (wallet 0; APPROVER and APPROVER2,
#       2 of 2). The keystore signs the lock only when the owner's exit needs the same quorum
#       in the DAO, and never with an approver pinned to a key; with the set named, the owner
#       alone stores the first locked policy
#   LF  under the lock the owner alone freezes: nothing is prepared; and unfreezes
#   LB  an operation inside the limits needs no approver: prepared, the TEE's half verified,
#       the agent's half last, executed
#   LC  a change of the policy by the owner alone is held: nothing signed, the chain and the
#       limit in force unchanged, a delete refused on chain; one vote of two keeps it held;
#       the second signs it, the owner stores it (still locked) and the new limit applies
#   LE  the exit under the lock: the owner alone cannot drop the exit approvers (one reject
#       ends the change); an exit past its window is not claimed without a vote, a vote from
#       outside the set is refused, and one reject ends the exit
#   LU  the unlock is a change like any other: held, then signed by the quorum and stored
#   X   the owner's exit: with exit approvers in force (L) one vote of two does not open the
#       claim and the second does; after the claim the agent's operations are refused; the
#       owner, with the recovery tool and no OutLayer service, moves funds out of the wallet
#       contract
#
# D takes two DAO votes on testnet (members' keys in the local keychain); between them every
# wallet contract on testnet is refused, and the cleanup approves the build again if the run
# stops there. T waits out the ten minutes. Not here: an extension added to a wallet contract
# by hand (it takes both keys, so it is the owner's after the exit, when the keystore no
# longer serves that generation anyway: keystore unit tests hold the rule), and the NEAR
# Intents kinds (mainnet only).
#
# Run:
#   PARENT=outlayer-alice.testnet ./tests/on_chain_custody_e2e.sh --apply
# APPROVER (default outlayer-carol) votes; APPROVER2 (default RECIPIENT) is the lock's second
# approver; RECIPIENT (default outlayer-daniel) is paid; STRANGER (default outlayer-bob) sends
# the on-chain refusals. About 4.5 NEAR of PARENT's, most of it left on the run's accounts. The
# working account relays: nearcore reserves 300 Tgas at its pessimistic gas price before a relay
# runs (0.3 NEAR on testnet), so it is funded with 1 NEAR. L is the owner's: three policy writes
# (0.1 NEAR attached to each), one more exit fee (0.01 NEAR) and one more exit window (60 s);
# the approvers pay the gas of their exit votes.

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/hos_common.sh"
source "$HOS_LIB_DIR/near_sign.sh"

[[ "${1:-}" == "--apply" ]] || { sed -n '3,81p' "$0" >&2; warn "Dry run. Pass --apply."; exit 0; }
[[ "$NETWORK" == testnet ]] || { echo "✗ this suite runs on testnet" >&2; exit 1; }

DAO="${DAO:-dao.outlayer.testnet}"
CONTRACT_ID="${CONTRACT_ID:-outlayer.testnet}"
BUILD="${BUILD:-651XC7DH8J4Xczf8JKXH9pyveBY8ZuNCfy5HZ3SvuSiL}"
APPROVER="${APPROVER:-outlayer-carol.testnet}"
RECIPIENT="${RECIPIENT:-outlayer-daniel.testnet}"
APPROVER2="${APPROVER2:-$RECIPIENT}"
STRANGER="${STRANGER:-outlayer-bob.testnet}"
DAO_MEMBER="${DAO_MEMBER:-zavodil.testnet}"
MPC_CONTRACT="${MPC_CONTRACT:-v1.signer-prod.testnet}"
VECTORS="${VECTORS:-$REPO_ROOT/../shared-tee-helpers/custody-core/vectors}"
AGENT_JS="$HOS_LIB_DIR/custody_agent.mjs"
hos_require
for a in "$APPROVER" "$APPROVER2" "$RECIPIENT" "$STRANGER"; do
  [[ -f "$CREDS_DIR/$a.json" ]] || { echo "✗ creds missing for $a" >&2; exit 1; }
done

OWNER="oc$(date +%s).$PARENT"
OWNER_CREDS="$CREDS_DIR/$OWNER.json"
AGENT_ACC="agent.$OWNER"
AGENT_CREDS="$CREDS_DIR/$AGENT_ACC.json"
WORK=$(mktemp -d -t on_chain_custody.XXXXXX) || exit 1
chmod 700 "$WORK"
TS=$(date +%s)

REVOKED=""
approve_build() { # the DAO's vote for the build, driven to execution
  local i
  for i in 1 2 3 4 5; do
    (NETWORK=testnet; source "$REPO_ROOT/scripts/lib/dao_gov.sh"; dao_drive "$DAO" "$DAO_MEMBER" "$(jq -nc --arg h "$BUILD" '{ApproveWalletContract:{code_hash:$h}}')") >/dev/null 2>&1 && return 0
    sleep 65
  done
  return 1
}
cleanup() {
  if [[ -n "$REVOKED" ]]; then
    warn "the run stopped with the build revoked: approving it again"
    approve_build || warn "the build is NOT approved again: run the ApproveWalletContract vote by hand"
  fi
  # The agent's account has no key by design: what it holds stays there.
  rm -f -- "${AGENT_CREDS:?}"
  if [[ -f "$OWNER_CREDS" ]]; then
    near account delete-account "$OWNER" beneficiary "$PARENT" \
      network-config "$NETWORK" sign-with-keychain send >/dev/null 2>&1 || true
    rm -f -- "${OWNER_CREDS:?}"
  fi
  [[ -d "$WORK" ]] && rm -rf -- "${WORK:?}"
}
trap cleanup EXIT

why() { jq -r '"\(.error // "no error code"): \(.message // "" | .[0:200])"' <<<"$BODY" 2>/dev/null || echo "an answer that is not JSON"; }
rpc_post() { printf 'url = "%s"\n' "$RPC_URL" | curl -sS --max-time 30 -K - -H 'Content-Type: application/json' --data-binary "$1"; }
view_account() { rpc_post "$(jq -nc --arg a "$1" '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"view_account",finality:"final",account_id:$a}}')"; }
balance() { view_account "$1" | jq -r '.result.amount // "0"'; }
access_keys() { rpc_post "$(jq -nc --arg a "$1" '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"view_access_key_list",finality:"final",account_id:$a}}')" | jq -c '[.result.keys[]?.public_key]'; }
sub() { python3 -I -c 'import sys; print(int(sys.argv[1]) - int(sys.argv[2]))' "$1" "$2"; }
OUT=""
sent_tx() { grep -oE 'Transaction ID: [1-9A-HJ-NP-Za-km-z]{43,44}' <<<"$OUT" | tail -1 | cut -d' ' -f3; }

# agent <METHOD> <path> [body] — a request signed by the agent's key (AGENT_SEED_FILE), with
# the wallet contract named in ACCOUNT_OF_AGENT. AGENT_NONCE / AGENT_TIMESTAMP override the
# signed nonce and time; EXTRA_HEADER adds one header line. Sets HTTP and BODY.
agent() {
  local method=$1 path=$2 body=${3:-} out bodyf headers
  throttle
  out=$(mktemp "$WORK/out.XXXXXX"); bodyf=$(mktemp "$WORK/body.XXXXXX")
  printf '%s' "$body" > "$bodyf"
  headers=$(node "$AGENT_JS" headers "$ACCOUNT_OF_AGENT" "$method" "$path" "$bodyf") || { HTTP=000; BODY='{"error":"the agent could not sign"}'; return; }
  [[ -n "${EXTRA_HEADER:-}" ]] && headers+=$'\n'"$EXTRA_HEADER"
  local -a args=(-sS -o "$out" -w '%{http_code}' -X "$method" "$COORDINATOR_URL$path" --max-time 120 -H @-)
  [[ "$method" == POST ]] && args+=(-H 'Content-Type: application/json' --data-binary @"$bodyf")
  HTTP=$(curl "${args[@]}" <<<"$headers" 2>/dev/null)
  BODY=$(tr -d '\n' < "$out"); rm -f "$out" "$bodyf"
}
OPS=/wallet/contract/v1/operations
ask() { agent POST "$OPS" "$(jq -nc --arg id "$1" --argjson op "$2" '{id:$id, op:$op}')"; }
op_state() { agent GET "$OPS/$1"; }
# Save what an operation waiting for the agent holds: the request and the TEE's half.
keep_prepared() { # keep_prepared <name>
  jq -c '.message' <<<"$BODY" > "$WORK/$1.msg"; jq -r '.tee_half' <<<"$BODY" > "$WORK/$1.tee"
}
# check_prepared <name> <op-json> [account] [tee-key] — the agent's own checks before it
# signs: the request is this wallet contract's (the agent's account and wallet 0's TEE key
# unless named), is the operation asked for, and carries a valid TEE half.
check_prepared() {
  local name=$1 op=$2 signer=${3:-$ACCOUNT_OF_AGENT} tee=${4:-$TEE_PUB} msg; msg=$(cat "$WORK/$name.msg")
  local kind; kind=$(jq -r .kind <<<"$op")
  local want
  case "$kind" in
    transfer) want=$(jq -nc --arg s "$signer" --argjson op "$op" '[$s, $op.to, "transfer", $op.amount]')
              [[ "$(jq -c '[.signer_id, .promise.receiver_id, .promise.action.action, .promise.action.amount]' <<<"$msg")" == "$want" ]] || return 1 ;;
    *) return 1 ;;
  esac
  [[ "$(jq -r .chain_id <<<"$msg")" == testnet ]] || return 1
  node "$AGENT_JS" verify-tee "$WORK/$name.msg" "$(cat "$WORK/$name.tee")" "$tee"
}
relay_with() { agent POST "$OPS/$1/relay" "$(jq -nc --arg h "$2" '{agent_half:$h}')"; }
# settle <id> — poll the operation until the chain answered; STATUS is where it ended.
STATUS=""
settle() {
  local i
  for i in $(seq 1 30); do
    STATUS=$(jq -r '.status // ""' <<<"$BODY")
    [[ "$STATUS" == success || "$STATUS" == failed || "$STATUS" == closed ]] && return 0
    sleep 3; op_state "$1"
  done
  return 1
}
# Raw execute_signed on chain from STRANGER: <name> <proof-hex>. 0 when the transaction went
# through; the CLI's output stays in OUT.
execute_signed_raw() {
  local args; args=$(node "$AGENT_JS" execute-args "$WORK/$1.msg" "$2")
  OUT=$(near contract call-function as-transaction "$AGENT_ACC" w_execute_signed json-args "$args" \
    prepaid-gas '300 Tgas' attached-deposit '0 NEAR' sign-as "$STRANGER" \
    network-config "$NETWORK" sign-with-keychain send 2>&1)
}
near_refusal() { grep -oiE '(Smart contract panicked|FunctionCallError|ExecutionError)[^"]{0,160}' <<<"$OUT" | head -1; }

# ── P ────────────────────────────────────────────────────────────────────────
log "P  the build and the agent's side"
APPROVED=$(near_view "$DAO" get_approved_wallet_contracts '{}')
if jq -e --arg b "$BUILD" 'index($b) != null' <<<"$APPROVED" >/dev/null 2>&1; then pass "P  $DAO lists the build $BUILD"
else echo "✗ $DAO does not list $BUILD: $APPROVED" >&2; exit 1; fi
if [[ -d "$VECTORS" ]] && node "$AGENT_JS" selftest "$VECTORS" >/dev/null; then pass "P  the agent's side matches custody-core's vectors"
else echo "✗ custody_agent.mjs does not match the vectors in $VECTORS" >&2; exit 1; fi

# ── F ────────────────────────────────────────────────────────────────────────
log "F  the owner $OWNER and its wallet"
EXIT_CFG=$(near_view "$DAO" get_config | jq -c '.exit // empty' 2>/dev/null)
[[ -n "$EXIT_CFG" ]] || { echo "✗ $DAO offers no exit" >&2; exit 1; }
REG_FEE=$(jq -r .registration_fee <<<"$EXIT_CFG"); MIN_W=$(jq -r .min_window_secs <<<"$EXIT_CFG")
KP=$(node "$HOS_LIB_DIR/ed25519_keypair.mjs")
( umask 077; jq -c --arg a "$OWNER" '. + {account_id:$a}' <<<"$KP" > "$OWNER_CREDS" )
unset KP
OWNER_PUB=$(jq -r .public_key "$OWNER_CREDS")
# create_account <account> <amount> <public key> <signer> — once more after a failure: another
# process signing as the same account can take the nonce.
create_account() {
  local try
  for try in 1 2; do
    OUT=$(near account create-account fund-myself "$1" "$2" use-manually-provided-public-key "$3" \
      sign-as "$4" network-config "$NETWORK" sign-with-keychain send 2>&1)
    for _ in 1 2 3 4 5 6 7 8; do account_exists "$1" && return 0; sleep 2; done
    warn "creating $1 (attempt $try): $(near_why "$OUT")"
  done
  return 1
}
create_account "$OWNER" '3 NEAR' "$OWNER_PUB" "$PARENT" || { echo "✗ $OWNER was not created" >&2; exit 1; }
FEE="$REG_FEE yoctoNEAR"
OUT=$(near contract call-function as-transaction "$DAO" register_exit_owner json-args "$(jq -nc --argjson w "$MIN_W" '{exit_window_sec:$w}')" \
  prepaid-gas '100 Tgas' attached-deposit "$FEE" sign-as "$OWNER" network-config "$NETWORK" sign-with-keychain send 2>&1) \
  || { echo "✗ register_exit_owner: $(near_why "$OUT")" >&2; exit 1; }

# new_wallet <seed> → WID, WK, WACC: an agent link, and the owner's NEP-413 proof for it.
new_wallet() {
  api - POST /wallet/v1/exit-link "$(jq -nc --arg s "$1" '{seed:$s}')" >/dev/null
  local link; link=$(jq -r '.link // ""' <<<"$BODY"); WK=$(jq -r '.api_key // ""' <<<"$BODY")
  [[ "$HTTP" == 200 && -n "$link" && "$WK" == wk_* ]] || return 1
  api - POST /wallet/v1/owner-wallet/prepare "$(jq -nc --arg l "$link" --arg a "$OWNER" '{link:$l, account_id:$a}')" >/dev/null
  local msg nonce sig; msg=$(jq -r '.message // ""' <<<"$BODY"); [[ -n "$msg" ]] || return 1
  nonce=$(head -c 32 /dev/urandom | base64 | tr -d '\n')
  sig=$(CUSTOMER_RECOVERY_PRIVATE_KEY="$(jq -r .private_key "$OWNER_CREDS")" "$RECOVERY_BIN" sign-nep413 \
    --message "$msg" --recipient outlayer:owner-wallet --nonce-base64 "$nonce" | jq -r .signature)
  api - POST /wallet/v1/owner-wallet "$(jq -nc --arg l "$link" --arg a "$OWNER" --arg pk "$OWNER_PUB" \
    --arg s "$sig" --arg n "$nonce" '{link:$l, account_id:$a, public_key:$pk, signature:$s, nonce:$n}')" >/dev/null
  # The first wallet writes the escrow; the keystore may read its own write back too early.
  if [[ "$HTTP" != 200 && "$(jq -r '.message // ""' <<<"$BODY")" == *"is not on chain after its write"* ]]; then
    sleep 10
    api - POST /wallet/v1/owner-wallet "$(jq -nc --arg l "$link" --arg a "$OWNER" --arg pk "$OWNER_PUB" \
      --arg s "$sig" --arg n "$nonce" '{link:$l, account_id:$a, public_key:$pk, signature:$s, nonce:$n}')" >/dev/null
  fi
  [[ "$HTTP" == 200 ]] || return 1
  WID=$(jq -r .wallet_id <<<"$BODY"); WACC=$(jq -r .near_account_id <<<"$BODY")
}
if new_wallet 0; then WID0=$WID WK0=$WK WACC0=$WACC; pass "F  the owner's wallet: $WID0 (working account $WACC0)"
else echo "✗ the owner's wallet was not created: $HTTP $(why)" >&2; exit 1; fi
# The working account pays the gas of each relay.
if fund_account "$WACC0" 1; then pass "F  the working account funded with 1 NEAR"
else fail "F  the working account could not be funded"; fi

# ── S1 ───────────────────────────────────────────────────────────────────────
log "S1 the setup"
api_wk "$WK0" GET /wallet/v1/contract/key >/dev/null
TEE_PUB=$(jq -r '.tee_public_key // ""' <<<"$BODY")
[[ "$HTTP" == 200 && "$TEE_PUB" =~ ^[0-9a-f]{64}$ ]] && pass "S1 the wallet's TEE key" || fail "S1 /wallet/v1/contract/key: $HTTP $(why)"
RPUB=$(node "$AGENT_JS" x25519-new "$WORK/setup.x")
api_wk "$WK0" POST /wallet/v1/contract/setup "$(jq -nc --arg r "$RPUB" '{recipient_public_key:$r}')" >/dev/null
SETUP_TOKEN=$(jq -r '.token // ""' <<<"$BODY")
[[ "$HTTP" == 200 && -n "$SETUP_TOKEN" ]] && pass "S1 the agent opened a setup" || { fail "S1 open: $HTTP $(why)"; verdict on_chain_custody; exit 1; }
api_wk "$WK0" GET /wallet/v1/contract/setup >/dev/null
[[ "$HTTP" == 200 && "$(jq -r .done <<<"$BODY")" == false ]] && pass "S1 the agent sees it not done" || fail "S1 not done: $HTTP $(why)"

# The owner's page: what the setup token shows.
owner_page() { # owner_page <METHOD> [body]
  local out bodyf; out=$(mktemp "$WORK/out.XXXXXX"); throttle
  local -a args=(-sS -o "$out" -w '%{http_code}' -X "$1" "$COORDINATOR_URL/wallet/v1/contract/setup/owner" --max-time 60 -H @-)
  if [[ -n "${2:-}" ]]; then bodyf=$(mktemp "$WORK/body.XXXXXX"); printf '%s' "$2" > "$bodyf"; args+=(-H 'Content-Type: application/json' --data-binary @"$bodyf"); fi
  HTTP=$(curl "${args[@]}" <<<"Authorization: Bearer $SETUP_TOKEN" 2>/dev/null)
  BODY=$(tr -d '\n' < "$out"); rm -f "$out" ${bodyf:+"$bodyf"}
}
# The agent's collect, as the SDK's collectSetup: the setup answer in BODY, the TEE key's
# statement read here; agent_collect <wk> <x-file> <out> [setup-json]. Prints the account.
agent_collect() {
  local setup=${4:-$BODY}
  api_wk "$1" GET /wallet/v1/contract/key >/dev/null
  jq -nc --argjson s "$setup" --argjson k "$BODY" '{setup:$s, key:$k}' \
    | RPC_URL="$RPC_URL" node "$AGENT_JS" collect "$2" "$OWNER" "$DAO" "$3"
}
owner_page GET
if [[ "$HTTP" == 200 && "$(jq -c '[.wallet_id, .owner, .tee_public_key, .recipient_public_key, .agent_key_request.recipient]' <<<"$BODY")" == "$(jq -nc --arg w "$WID0" --arg o "$OWNER" --arg t "$TEE_PUB" --arg r "$RPUB" '[$w,$o,$t,$r,"outlayer-agent-key"]')" ]]; then
  pass "S1 the owner's page shows the wallet, the owner, the TEE key and the agent's one-time key"
else fail "S1 the owner's page: $HTTP $(why)"; fi
# The page uses the TEE key only once the keystore's statement over it checks out.
if STATED=$(RPC_URL="$RPC_URL" node "$AGENT_JS" tee-statement "$DAO" "$OWNER" "$WID0" <<<"$BODY" 2>&1) && [[ "$STATED" == "$TEE_PUB" ]]; then
  pass "S1 the TEE key comes with the keystore's statement: signed by a key $DAO approves, for this owner and wallet"
else fail "S1 the keystore's statement over the TEE key: $STATED"; fi
AK_MSG=$(jq -r '.agent_key_request.message' <<<"$BODY"); AK_NONCE=$(jq -r '.agent_key_request.nonce_base64' <<<"$BODY")
AK_SIG=$(CUSTOMER_RECOVERY_PRIVATE_KEY="$(jq -r .private_key "$OWNER_CREDS")" "$RECOVERY_BIN" sign-nep413 \
  --message "$AK_MSG" --recipient outlayer-agent-key --nonce-base64 "$AK_NONCE" | jq -r .signature)
AGENT_KEY_SIGNATURE="$AK_SIG" node "$AGENT_JS" seed "$OWNER" "$WID0" "$WORK/owner_side.seed"
AK_SIG2=$(CUSTOMER_RECOVERY_PRIVATE_KEY="$(jq -r .private_key "$OWNER_CREDS")" "$RECOVERY_BIN" sign-nep413 \
  --message "$AK_MSG" --recipient outlayer-agent-key --nonce-base64 "$AK_NONCE" | jq -r .signature)
[[ "$AK_SIG" == "$AK_SIG2" ]] && pass "S1 the owner's signature repeats: the agent's key needs no backup" || fail "S1 the owner's signature differs on a second signing"
( umask 077; printf '%s' "$AK_SIG" > "$WORK/ak.sig" )
unset AK_SIG AK_SIG2
AGENT_PUB=$(AGENT_SEED_FILE="$WORK/owner_side.seed" node "$AGENT_JS" pub)

# The account: created with the owner's key, the build installed with (A, E), every key removed.
( umask 077; jq -c --arg a "$AGENT_ACC" '. + {account_id:$a}' "$OWNER_CREDS" > "$AGENT_CREDS" )
create_account "$AGENT_ACC" '0.5 NEAR' "$OWNER_PUB" "$OWNER" || fail "S1 $AGENT_ACC was not created"
OUT=$(near contract deploy "$AGENT_ACC" use-global-hash "$BUILD" with-init-call w_init \
  json-args "$(jq -nc --arg p "$AGENT_PUB$TEE_PUB" '{public_key:$p}')" prepaid-gas '10 Tgas' attached-deposit '1 yoctoNEAR' \
  network-config "$NETWORK" sign-with-keychain send 2>&1) && pass "S1 $AGENT_ACC created and the build installed with the pair" \
  || fail "S1 the install: $(near_why "$OUT")"
OUT=$(near account delete-keys "$AGENT_ACC" public-keys "$OWNER_PUB" network-config "$NETWORK" sign-with-keychain send 2>&1) \
  || fail "S1 the owner's key was not removed: $(near_why "$OUT")"
SEALED=$(AGENT_KEY_SIGNATURE="$(cat "$WORK/ak.sig")" node "$AGENT_JS" seal "$RPUB" "$OWNER" "$WID0" "$OWNER_PUB")
owner_page POST "$(jq -nc --arg a "$OWNER.evil.testnet" --arg s "$SEALED" '{account_id:$a, sealed_agent_key:$s}')"
[[ "$HTTP" == 400 ]] && pass "S3 a setup naming an account outside the owner's: 400" || fail "S3 an outside account answered $HTTP $(why)"
owner_page POST "$(jq -nc --arg a "$AGENT_ACC" --arg s "$SEALED" '{account_id:$a, sealed_agent_key:$s}')"
if [[ "$HTTP" == 200 && "$(jq -c '[.account_id, .agent_public_key]' <<<"$BODY")" == "$(jq -nc --arg a "$AGENT_ACC" --arg k "$AGENT_PUB" '[$a,$k]')" ]]; then
  pass "S1 the owner finished the setup: the coordinator read the pair from the chain"
else fail "S1 the owner's finish: $HTTP $(why)"; fi
owner_page GET
[[ "$HTTP" == 409 ]] && grep -q "\`$AGENT_ACC\`" <<<"$BODY" && pass "S3 the spent token says the setup was finished, with its account (409)" \
  || fail "S3 the spent token answered $HTTP $(why)"

# The agent collects its key.
api_wk "$WK0" GET /wallet/v1/contract/setup >/dev/null
if [[ "$HTTP" == 200 && "$(jq -c '[.done, .account_id, .agent_public_key]' <<<"$BODY")" == "$(jq -nc --arg a "$AGENT_ACC" --arg k "$AGENT_PUB" '[true,$a,$k]')" ]]; then
  SETUP_DONE=$BODY
  if COLLECTED=$(agent_collect "$WK0" "$WORK/setup.x" "$WORK/agent.seed" 2>&1) && [[ "$COLLECTED" == "$AGENT_ACC" ]] \
     && [[ "$(AGENT_SEED_FILE="$WORK/agent.seed" node "$AGENT_JS" pub)" == "$AGENT_PUB" ]]; then
    pass "S1 the agent's collect verified the owner's NEP-413 signature, its key as a full-access key of $OWNER on chain, and the pair on $AGENT_ACC: the contract's agent key"
  else fail "S1 the agent's collect: $COLLECTED"; fi
  # Anyone who knows the one-time key can seal to it: a signature of the owner's message by a
  # key of its own, with the account it would name, is refused by the chain's access keys.
  KP=$(node "$HOS_LIB_DIR/ed25519_keypair.mjs")
  FORGED_SIG=$(CUSTOMER_RECOVERY_PRIVATE_KEY="$(jq -r .private_key <<<"$KP")" "$RECOVERY_BIN" sign-nep413 \
    --message "$AK_MSG" --recipient outlayer-agent-key --nonce-base64 "$AK_NONCE" | jq -r .signature)
  FORGED=$(AGENT_KEY_SIGNATURE="$FORGED_SIG" node "$AGENT_JS" seal "$RPUB" "$OWNER" "$WID0" "$(jq -r .public_key <<<"$KP")")
  unset KP FORGED_SIG
  if OUT=$(agent_collect "$WK0" "$WORK/setup.x" "$WORK/forged.seed" "$(jq -c --arg s "$FORGED" '.sealed_agent_key = $s' <<<"$SETUP_DONE")" 2>&1); then
    fail "S1 a seal of a signature by a key that is not the owner's was taken: $OUT"
  elif grep -q "is not a full-access key of $OWNER" <<<"$OUT"; then
    pass "S1 a seal of a signature by a key that is not the owner's is refused at the agent (view_access_key on chain)"
  else fail "S1 the forged seal was refused for another reason: $OUT"; fi
  rm -f "$WORK/forged.seed"
else fail "S1 the agent's collect: $HTTP $(why)"; fi
skip "S1 a link without \`to\`: the suite finishes the setup with the token and opens no link; the page's setupLink refuses one (dashboard test/wallet-contract.test.mjs)"
rm -f "$WORK/owner_side.seed"
export AGENT_SEED_FILE="$WORK/agent.seed" ACCOUNT_OF_AGENT="$AGENT_ACC"

# ── S2 ───────────────────────────────────────────────────────────────────────
log "S2 the wallet contract on chain"
GCH=$(view_account "$AGENT_ACC" | jq -r '.result.global_contract_hash // ""')
[[ "$GCH" == "$BUILD" ]] && pass "S2 $AGENT_ACC runs the approved build" || fail "S2 the account runs '$GCH'"
ON_CHAIN_PAIR=$(near_view "$AGENT_ACC" w_public_key '{}' | tr -d '"')
[[ "$ON_CHAIN_PAIR" == "$AGENT_PUB$TEE_PUB" ]] && pass "S2 w_public_key is the pair registered" || fail "S2 w_public_key is '$ON_CHAIN_PAIR'"
KEYS=$(access_keys "$AGENT_ACC")
[[ "$KEYS" == "[]" ]] && pass "S2 the account has no access key" || fail "S2 access keys left: $KEYS"
api_wk "$WK0" GET /wallet/v1/contract >/dev/null
[[ "$HTTP" == 200 && "$(jq -r .account_id <<<"$BODY")" == "$AGENT_ACC" ]] && pass "S2 GET /wallet/v1/contract names it" || fail "S2 /wallet/v1/contract: $HTTP $(why)"

# ── S4 + S3 ──────────────────────────────────────────────────────────────────
log "S4 a second wallet, on the owner's own account"
if new_wallet 1; then
  WID1=$WID WK1=$WK
  api_wk "$WK1" GET /wallet/v1/contract/key >/dev/null; TEE1=$(jq -r '.tee_public_key // ""' <<<"$BODY")
  [[ "$TEE1" != "$TEE_PUB" && "$TEE1" =~ ^[0-9a-f]{64}$ ]] && pass "S4 each wallet has its own TEE key" || fail "S4 TEE key of wallet 1: '$TEE1'"
  # Another agent key for it, from the owner's signature for that wallet.
  api_wk "$WK1" POST /wallet/v1/contract/setup "$(jq -nc --arg r "$RPUB" '{recipient_public_key:$r}')" >/dev/null
  SETUP_TOKEN=$(jq -r '.token // ""' <<<"$BODY")
  owner_page GET
  S4_SIG=$(CUSTOMER_RECOVERY_PRIVATE_KEY="$(jq -r .private_key "$OWNER_CREDS")" "$RECOVERY_BIN" sign-nep413 \
    --message "$(jq -r '.agent_key_request.message' <<<"$BODY")" --recipient outlayer-agent-key \
    --nonce-base64 "$(jq -r '.agent_key_request.nonce_base64' <<<"$BODY")" | jq -r .signature)
  AGENT_KEY_SIGNATURE="$S4_SIG" node "$AGENT_JS" seed "$OWNER" "$WID1" "$WORK/s4.seed"
  ( umask 077; printf '%s' "$S4_SIG" > "$WORK/s4.sig" ); unset S4_SIG
  A1=$(AGENT_SEED_FILE="$WORK/s4.seed" node "$AGENT_JS" pub)
  [[ "$A1" != "$AGENT_PUB" ]] && pass "S4 each wallet has its own agent key" || fail "S4 the same agent key for two wallets"
  OUT=$(near contract deploy "$OWNER" use-global-hash "$BUILD" with-init-call w_init \
    json-args "$(jq -nc --arg p "$A1$TEE1" '{public_key:$p}')" prepaid-gas '10 Tgas' attached-deposit '1 yoctoNEAR' \
    network-config "$NETWORK" sign-with-keychain send 2>&1) || fail "S4 the install on $OWNER: $(near_why "$OUT")"
  owner_page POST "$(jq -nc --arg a "$OWNER" --arg s "$(AGENT_KEY_SIGNATURE="$(cat "$WORK/s4.sig")" node "$AGENT_JS" seal "$RPUB" "$OWNER" "$WID1" "$OWNER_PUB")" '{account_id:$a, sealed_agent_key:$s}')"
  [[ "$HTTP" == 200 && "$(jq -r .account_id <<<"$BODY")" == "$OWNER" ]] && pass "S4 the owner's own account is the second wallet's contract" || fail "S4 finish: $HTTP $(why)"
  [[ "$(access_keys "$OWNER")" == "[\"$OWNER_PUB\"]" ]] && pass "S4 the owner's key stays on it" || fail "S4 keys on $OWNER: $(access_keys "$OWNER")"
  api_wk "$WK1" GET /wallet/v1/contract/setup >/dev/null
  if [[ "$HTTP" == 200 && "$(jq -c '[.done, .account_id, .agent_public_key]' <<<"$BODY")" == "$(jq -nc --arg a "$OWNER" --arg k "$A1" '[true,$a,$k]')" ]]; then
    if COLLECTED=$(agent_collect "$WK1" "$WORK/setup.x" "$WORK/s4.collected" 2>&1) && [[ "$COLLECTED" == "$OWNER" ]] \
       && [[ "$(AGENT_SEED_FILE="$WORK/s4.collected" node "$AGENT_JS" pub)" == "$A1" ]]; then
      pass "S4 the agent collected its key for the owner's own account: the owner's signature, its key on chain and the pair on $OWNER checked"
    else fail "S4 the agent's collect: $COLLECTED"; fi
  else fail "S4 the agent's collect: $HTTP $(why)"; fi
  api_wk "$WK1" PUT /wallet/v1/contract "$(jq -nc --arg a "$AGENT_ACC" '{account_id:$a}')" >/dev/null
  [[ "$HTTP" == 400 ]] && grep -q 'was not set up for this wallet' <<<"$BODY" && pass "S3 the agent cannot name another wallet's contract: 400" \
    || fail "S3 another wallet's contract answered $HTTP $(why)"
  api_wk "$WK1" PUT /wallet/v1/contract "$(jq -nc --arg a "$PARENT" '{account_id:$a}')" >/dev/null
  [[ "$HTTP" == 400 ]] && grep -q 'does not answer `w_public_key`' <<<"$BODY" && pass "S3 an account with no wallet contract: 400" \
    || fail "S3 an account with no contract answered $HTTP $(why)"
  rm -f "$WORK/s4.seed" "$WORK/s4.sig" "$WORK/s4.collected"
else fail "S4 the second wallet: $HTTP $(why)"; fi

# ── N ────────────────────────────────────────────────────────────────────────
log "N  no policy on chain"
TRANSFER_SMALL=$(jq -nc --arg to "$RECIPIENT" '{kind:"transfer", to:$to, amount:"10000000000000000000000"}')   # 0.01 NEAR
ask "n-$TS" "$TRANSFER_SMALL"
[[ "$HTTP" == 403 && "$(jq -r .error <<<"$BODY")" == policy_denied ]] && pass "N  nothing is prepared without a policy (403 policy_denied)" \
  || fail "N  without a policy: $HTTP $(why)"

# ── the owner's policy ───────────────────────────────────────────────────────
log "the owner stores a policy: 0.05 NEAR a transfer, 0.02 a day without the approver"
APPROVER_PUB=$(jq -r .public_key "$CREDS_DIR/$APPROVER.json")
POLICY=$(jq -nc --arg w "$WID0" --arg a "$APPROVER" --arg k "$APPROVER_PUB" '{wallet_id:$w,
  rules:{transaction_types:["transfer"], limits:{per_transaction:{native:"50000000000000000000000"}}},
  approval:{threshold:{required:1}, approvers:[{id:$a, pubkey:$k}], auto_up_to:{daily:{native:"20000000000000000000000"}}}}')
api_wk "$WK0" POST /wallet/v1/encrypt-policy "$POLICY" >/dev/null
PENC=$(jq -r '.encrypted_base64 // ""' <<<"$BODY")
api_wk "$WK0" POST /wallet/v1/sign-policy "$(jq -nc --arg ed "$PENC" --arg c "$OWNER" '{encrypted_data:$ed, caller:$c}')" >/dev/null
if [[ "$HTTP" == 200 ]]; then
  WPUB0="ed25519:$(jq -r .public_key_hex <<<"$BODY")"
  ARGS=$(jq -c --arg ed "$PENC" '{wallet_pubkey:("ed25519:" + .public_key_hex), encrypted_data:$ed, wallet_signature:.signature_hex, version, locked, valid_until}' <<<"$BODY")
  OUT=$(near contract call-function as-transaction "$CONTRACT_ID" store_wallet_policy json-args "$ARGS" \
    prepaid-gas '100 Tgas' attached-deposit '0.1 NEAR' sign-as "$OWNER" network-config "$NETWORK" sign-with-keychain send 2>&1) \
    && pass "policy stored by the owner" || fail "store_wallet_policy: $(near_why "$OUT")"
  unset ARGS
  sleep 5
else fail "sign-policy: $HTTP $(why)"; fi

# ── M1 ───────────────────────────────────────────────────────────────────────
log "M1 a transfer within the policy"
R_BEFORE=$(balance "$RECIPIENT"); C_BEFORE=$(balance "$AGENT_ACC")
ask "m1-$TS" "$TRANSFER_SMALL"
if [[ "$HTTP" == 200 && "$(jq -r .status <<<"$BODY")" == awaiting_signature ]]; then
  keep_prepared m1
  pass "M1 prepared: awaiting the agent's half"
  check_prepared m1 "$TRANSFER_SMALL" && pass "M1 the request is the transfer asked for, and the TEE's half is valid" \
    || fail "M1 the prepared request is not the operation asked for: $(cat "$WORK/m1.msg")"
  M1_HALF=$(node "$AGENT_JS" half "$WORK/m1.msg")
  relay_with "m1-$TS" "$M1_HALF"
  if [[ "$HTTP" == 200 ]] && settle "m1-$TS" && [[ "$STATUS" == success ]]; then
    pass "M1 relayed and executed (tx $(jq -r '.tx_hash // "?"' <<<"$BODY"))"; M1_DONE=1
    sleep 3
    GOT=$(sub "$(balance "$RECIPIENT")" "$R_BEFORE")
    [[ "$GOT" == 10000000000000000000000 ]] && pass "M1 the recipient got 0.01 NEAR, once" || fail "M1 the recipient's balance moved by $GOT"
  else fail "M1 relay: $HTTP status=$STATUS $(why)"; fi
  relay_with "m1-$TS" "$M1_HALF"
  [[ "$(jq -r '.status // ""' <<<"$BODY")" == success ]] && pass "M1 relaying a settled operation again answers where it stands" \
    || fail "M1 a second relay answered $HTTP $(why)"
else fail "M1 ask: $HTTP $(why)"; fi

# ── R ────────────────────────────────────────────────────────────────────────
log "R  refusals"
TRANSFER_TINY=$(jq -nc --arg to "$RECIPIENT" '{kind:"transfer", to:$to, amount:"1000000000000000000000"}')   # 0.001 NEAR
ask "r-$TS" "$TRANSFER_TINY"
if [[ "$HTTP" == 200 && "$(jq -r .status <<<"$BODY")" == awaiting_signature ]]; then
  keep_prepared r
  TEE_HALF=$(cat "$WORK/r.tee")
  relay_with "r-$TS" "$(openssl rand -hex 64)"
  [[ "$HTTP" == 401 ]] && pass "R  a random half: 401" || fail "R  a random half answered $HTTP $(why)"
  bf=$(mktemp "$WORK/body.XXXXXX"); printf '{}' > "$bf"
  relay_with "r-$TS" "$(node "$AGENT_JS" https-half "$AGENT_ACC" POST "$OPS/r-$TS/relay" "$bf")"; rm -f "$bf"
  [[ "$HTTP" == 401 ]] && pass "R  an HTTPS-request signature as the half: 401" || fail "R  an HTTPS signature as the half answered $HTTP $(why)"
  relay_with "r-$TS" "$TEE_HALF"
  [[ "$HTTP" == 401 ]] && pass "R  the TEE's half in the agent's place: 401" || fail "R  the TEE's half as the agent's answered $HTTP $(why)"
  # On chain, past the coordinator.
  C0=$(balance "$AGENT_ACC")
  R_HALF=$(node "$AGENT_JS" half "$WORK/r.msg")
  if execute_signed_raw r "$(printf '0%.0s' $(seq 1 128))$TEE_HALF"; then fail "R  the chain took the TEE's half alone"
  else pass "R  the chain refuses the TEE's half alone ($(near_refusal))"; fi
  if execute_signed_raw r "$TEE_HALF$R_HALF"; then fail "R  the chain took the two halves swapped"
  else pass "R  the chain refuses the two halves swapped ($(near_refusal))"; fi
  if [[ -n "${M1_DONE:-}" ]]; then
    if execute_signed_raw m1 "$M1_HALF$(cat "$WORK/m1.tee")"; then fail "R  the chain took M1's proof a second time"
    else pass "R  the chain refuses M1's request again ($(near_refusal))"; fi
  fi
  sleep 3
  [[ "$(balance "$AGENT_ACC")" == "$C0" ]] && pass "R  the wallet contract's balance did not move" || fail "R  the balance moved: $C0 → $(balance "$AGENT_ACC")"
  relay_with "r-$TS" "$R_HALF"
  if [[ "$HTTP" == 200 ]] && settle "r-$TS" && [[ "$STATUS" == success ]]; then pass "R  after the refusals, the agent's half: executed"
  else fail "R  the operation after the refusals: $HTTP status=$STATUS $(why)"; fi
else fail "R  ask: $HTTP $(why)"; fi

# ── H ────────────────────────────────────────────────────────────────────────
log "H  the HTTPS door"
NONCE=$(openssl rand -hex 16)
AGENT_NONCE=$NONCE agent GET "$OPS"
[[ "$HTTP" == 200 ]] && pass "H  a signed request: 200" || fail "H  a signed list: $HTTP $(why)"
AGENT_NONCE=$NONCE agent GET "$OPS"
[[ "$HTTP" == 409 ]] && pass "H  the same request again: 409" || fail "H  a request taken twice answered $HTTP $(why)"
AGENT_TIMESTAMP=$(( $(date +%s) - 3600 )) agent GET "$OPS"
[[ "$HTTP" =~ ^4 && "$HTTP" != 409 ]] && pass "H  a timestamp an hour old: $HTTP" || fail "H  a stale timestamp answered $HTTP $(why)"
api_wk "$WK0" GET "$OPS" >/dev/null
[[ "$HTTP" =~ ^4 ]] && pass "H  a wk_ key on the operation routes: $HTTP" || fail "H  a wk_ key answered $HTTP"
H_HEADERS=$(node "$AGENT_JS" headers "$AGENT_ACC" GET /wallet/v1/balance "")
HTTP=$(curl -sS -o /dev/null -w '%{http_code}' "$COORDINATOR_URL/wallet/v1/balance?chain=near" -H @- <<<"$H_HEADERS" 2>/dev/null)
[[ "$HTTP" == 401 ]] && pass "H  an agent's signature on a wk_ route: 401" || fail "H  an agent's signature on a wk_ route answered $HTTP"
ask "h-ext-$TS" "$(jq -nc --arg a "$STRANGER" '{kind:"add_extension", account_id:$a}')"
[[ "$HTTP" == 400 && -z "$(jq -r '.tee_half // ""' <<<"$BODY")" ]] \
  && pass "H  an internal operation of the wallet contract (add_extension) cannot be asked for: 400" \
  || fail "H  add_extension answered $HTTP $(why)"
openssl rand -hex 32 > "$WORK/other.seed"
AGENT_SEED_FILE="$WORK/other.seed" agent GET "$OPS"
[[ "$HTTP" == 401 ]] && pass "H  another key's signature in the wallet contract's name: 401" || fail "H  another key answered $HTTP $(why)"
rm -f "$WORK/other.seed"

# ── P1 ───────────────────────────────────────────────────────────────────────
log "P1 over per_transaction"
ask "p1-$TS" "$(jq -nc --arg to "$RECIPIENT" '{kind:"transfer", to:$to, amount:"100000000000000000000000"}')"   # 0.1 NEAR
[[ "$HTTP" == 403 && -z "$(jq -r '.message // empty | select(type=="object")' <<<"$BODY")" && "$(jq -r '.tee_half // ""' <<<"$BODY")" == "" ]] \
  && pass "P1 refused with nothing to sign (403): $(jq -r '.message' <<<"$BODY" | head -c 120)" || fail "P1 over the limit answered $HTTP $(why)"

# ── A ────────────────────────────────────────────────────────────────────────
log "A  the agent"
ask "m1-$TS" "$TRANSFER_TINY"
[[ "$HTTP" == 409 ]] && pass "A  the same id with another body: 409" || fail "A  the same id, another body answered $HTTP $(why)"
ask "a-$TS" "$TRANSFER_TINY"
if [[ "$(jq -r .status <<<"$BODY")" == awaiting_signature ]]; then
  HASH_A=$(jq -r .request_hash <<<"$BODY"); keep_prepared a
  agent GET "$OPS"
  [[ "$(jq -r --arg id "a-$TS" '[.operations[]? | select(.id == $id) | .status][0] // ""' <<<"$BODY")" == awaiting_signature ]] \
    && pass "A  the open operations list it, waiting for the agent's half" || fail "A  the list: $HTTP $(why)"
  ask "a-$TS" "$TRANSFER_TINY"
  [[ "$(jq -r '[.status, .request_hash] | @json' <<<"$BODY")" == "[\"awaiting_signature\",\"$HASH_A\"]" ]] \
    && pass "A  a restarted agent asks again under the same id: the same operation" || fail "A  the repeat: $HTTP $(why)"
  relay_with "a-$TS" "$(node "$AGENT_JS" half "$WORK/a.msg")"
  if [[ "$HTTP" == 200 ]] && settle "a-$TS" && [[ "$STATUS" == success ]]; then pass "A  and continues to the end"
  else fail "A  relay: $HTTP status=$STATUS $(why)"; fi
  agent GET "$OPS"
  [[ "$(jq -r --arg id "a-$TS" '[.operations[]? | select(.id == $id)] | length' <<<"$BODY")" == 0 ]] && pass "A  a settled operation is no longer open" \
    || fail "A  the settled operation is still listed"
else fail "A  ask: $HTTP $(why)"; fi

# ── D + T ────────────────────────────────────────────────────────────────────
log "D  the build list"
in_list() { near_view "$DAO" get_approved_wallet_contracts '{}' | jq -e --arg b "$BUILD" 'index($b) != null' >/dev/null 2>&1; }
ask "t-$TS" "$TRANSFER_TINY"
if [[ "$(jq -r .status <<<"$BODY")" == awaiting_signature ]]; then
  keep_prepared t; T_HALF=$(node "$AGENT_JS" half "$WORK/t.msg")
  T_DEADLINE=$(( $(jq -r .created_at_ns "$WORK/t.msg" | cut -c1-10) + 600 ))
  pass "T  prepared, and kept unsigned until its ten minutes end"
else fail "T  ask: $HTTP $(why)"; fi
REVOKED=1
for i in 1 2 3 4 5; do
  (NETWORK=testnet; source "$REPO_ROOT/scripts/lib/dao_gov.sh"; dao_drive "$DAO" "$DAO_MEMBER" "$(jq -nc --arg h "$BUILD" '{RevokeWalletContract:{code_hash:$h}}')") >/dev/null 2>&1 && break
  sleep 65
done
if ! in_list; then
  pass "D  the DAO revoked the build"
  ask "d-$TS" "$TRANSFER_TINY"
  [[ "$HTTP" == 403 && "$(jq -r .error <<<"$BODY")" == wallet_contract_refused ]] \
    && pass "D  an operation is not prepared for a build off the list (403 wallet_contract_refused)" \
    || fail "D  with the build revoked: $HTTP $(why)"
  if [[ -n "${T_HALF:-}" ]]; then
    relay_with "t-$TS" "$T_HALF"
    [[ "$HTTP" =~ ^4 ]] && pass "D  a request prepared before is not relayed either ($HTTP $(jq -r .error <<<"$BODY"))" \
      || fail "D  a prepared request was relayed with the build revoked: $HTTP $(why)"
    op_state "t-$TS"
    [[ "$(jq -r .status <<<"$BODY")" == awaiting_signature ]] && pass "D  and it still waits for its half" || fail "D  the refused relay left it $(jq -r .status <<<"$BODY")"
  fi
else fail "D  the revoke vote did not execute"; fi
if approve_build && in_list; then
  REVOKED=""
  pass "D  the DAO approved the build again"
  ask "d-$TS" "$TRANSFER_TINY"
  if [[ "$(jq -r .status <<<"$BODY")" == awaiting_signature ]]; then
    keep_prepared d
    relay_with "d-$TS" "$(node "$AGENT_JS" half "$WORK/d.msg")"
    if [[ "$HTTP" == 200 ]] && settle "d-$TS" && [[ "$STATUS" == success ]]; then pass "D  the agent goes on under the same id"
    else fail "D  relay after the approval: $HTTP status=$STATUS $(why)"; fi
  else fail "D  after the approval: $HTTP $(why)"; fi
else fail "D  the build is not approved again"; fi

log "T  a request past its time"
if [[ -n "${T_HALF:-}" ]]; then
  WAIT=$(( T_DEADLINE + 15 - $(date +%s) ))
  (( WAIT > 0 )) && { note "waiting ${WAIT}s for the request's ten minutes to end"; sleep "$WAIT"; }
  C0=$(balance "$AGENT_ACC")
  relay_with "t-$TS" "$T_HALF"
  [[ "$HTTP" == 200 ]] && settle "t-$TS"
  T_STATUS=$(jq -r '.status // ""' <<<"$BODY")
  if [[ "$T_STATUS" != success ]]; then pass "T  not executed: $HTTP ${T_STATUS:-} $(jq -r '(.reason // .message // "") | .[0:120]' <<<"$BODY")"
  else fail "T  a request past its ten minutes was executed"; fi
  sleep 3
  [[ "$(balance "$AGENT_ACC")" == "$C0" ]] && pass "T  the balance did not move" || fail "T  the balance moved"
fi

# ── P2 ───────────────────────────────────────────────────────────────────────
log "P2 above auto_up_to: the approver"
TRANSFER_MID=$(jq -nc --arg to "$RECIPIENT" '{kind:"transfer", to:$to, amount:"30000000000000000000000"}')   # 0.03 NEAR
ask "p2-$TS" "$TRANSFER_MID"
APPROVAL_ID=$(jq -r '.approval_id // ""' <<<"$BODY")
if [[ "$HTTP" == 200 && "$(jq -r .status <<<"$BODY")" == pending_approval && -n "$APPROVAL_ID" ]]; then
  pass "P2 the operation waits for the approver"
  ask "p2-$TS" "$TRANSFER_MID"
  [[ "$(jq -r .status <<<"$BODY")" == pending_approval ]] && pass "P2 asked again before the vote: still waiting" || fail "P2 a repeat before the vote: $HTTP $(why)"
  api_wk "$WK0" GET /wallet/v1/pending_approvals >/dev/null
  [[ "$(jq -r --arg id "$APPROVAL_ID" '[.approvals[]? | select(.approval_id == $id) | .type][0] // ""' <<<"$BODY")" == wallet_contract ]] \
    && pass "P2 the wallet's pending approvals list it as wallet_contract" || fail "P2 pending_approvals: $HTTP $(why)"
  DETAILS=$(curl -sS "$COORDINATOR_URL/wallet/v1/approval/$APPROVAL_ID")
  APPROVE_MSG="approve:$APPROVAL_ID:$(jq -r .wallet_pubkey <<<"$DETAILS"):$(jq -r .request_hash <<<"$DETAILS")"
  NONCE_B64=$(head -c 32 /dev/urandom | base64 | tr -d '\n')
  VOTE=$(CUSTOMER_RECOVERY_PRIVATE_KEY="$(jq -r .private_key "$CREDS_DIR/$APPROVER.json")" "$RECOVERY_BIN" sign-nep413 \
    --message "$APPROVE_MSG" --recipient "$CONTRACT_ID" --nonce-base64 "$NONCE_B64" | jq -r .signature)
  api - POST "/wallet/v1/approve/$APPROVAL_ID" "$(jq -nc --arg s "$VOTE" --arg pk "$APPROVER_PUB" --arg a "$APPROVER" --arg n "$NONCE_B64" \
    '{signature:$s, public_key:$pk, account_id:$a, nonce:$n}')" >/dev/null
  [[ "$HTTP" == 200 ]] && pass "P2 the approver voted" || fail "P2 the vote: $HTTP $(why)"
  ask "p2-$TS" "$TRANSFER_MID"
  if [[ "$HTTP" == 200 && "$(jq -r .status <<<"$BODY")" == awaiting_signature ]]; then
    keep_prepared p2
    check_prepared p2 "$TRANSFER_MID" && pass "P2 after the vote the repeat is prepared, and is the transfer approved" || fail "P2 the prepared request is not the one approved"
    relay_with "p2-$TS" "$(node "$AGENT_JS" half "$WORK/p2.msg")"
    if [[ "$HTTP" == 200 ]] && settle "p2-$TS" && [[ "$STATUS" == success ]]; then pass "P2 executed"
    else fail "P2 relay: $HTTP status=$STATUS $(why)"; fi
  else fail "P2 the repeat after the vote: $HTTP $(why)"; fi
else fail "P2 ask: $HTTP $(why)"; fi

# ── I1 ───────────────────────────────────────────────────────────────────────
log "I1 use_bound_identity"
CLAIM=$(curl -sS -m 60 -X POST "$COORDINATOR_URL/trial-key" -H @<(printf '%s\n' "Authorization: Bearer $WK0") \
  -H 'Content-Type: application/json' -d '{}' 2>/dev/null)
PK=$(jq -r '.payment_key // empty' <<<"$CLAIM")
if [[ -z "$PK" ]]; then
  skip "I1 no trial key for the wallet ($(jq -r '.error // "no answer"' <<<"$CLAIM")): the identity row needs one"
else
  out=$(mktemp "$WORK/out.XXXXXX")
  HTTP=$(curl -sS -o "$out" -w '%{http_code}' -m 300 -X POST "$COORDINATOR_URL/call/connectors.outlayer.testnet/connector-probe" \
    -H @<(printf '%s\n' "X-Payment-Key: $PK") -H 'Content-Type: application/json' \
    -d '{"input":{"operation":"whoami"},"use_bound_identity":true}' 2>/dev/null)
  BODY=$(tr -d '\n' < "$out"); rm -f "$out"
  SENDER=$(jq -r '.output // .result // "{}"' <<<"$BODY" 2>/dev/null | jq -r '.sender_id // ""' 2>/dev/null)
  [[ "$HTTP" == 200 && "$SENDER" == "$AGENT_ACC" ]] && pass "I1 the program runs as the wallet contract's account ($SENDER)" \
    || fail "I1 use_bound_identity: $HTTP sender='$SENDER' $(why)"
  unset PK
fi

# ── S5 + Z ───────────────────────────────────────────────────────────────────
log "S5 a new account with no key: the 0s wallet contract (NEP-616)"
if new_wallet 2; then
  WID2=$WID WK2=$WK WACC2=$WACC
  # 1 NEAR, and 1 more per 1000 storage calls: each relay spends about 0.0004
  fund_account "$WACC2" $(( 1 + ${STORAGE_MOVES:-0} / 1000 )) || fail "S5 the working account could not be funded"
  api_wk "$WK2" GET /wallet/v1/contract/key >/dev/null; TEE2=$(jq -r '.tee_public_key // ""' <<<"$BODY")
  RPUB2=$(node "$AGENT_JS" x25519-new "$WORK/s5.x")
  api_wk "$WK2" POST /wallet/v1/contract/setup "$(jq -nc --arg r "$RPUB2" '{recipient_public_key:$r}')" >/dev/null
  SETUP_TOKEN=$(jq -r '.token // ""' <<<"$BODY")
  owner_page GET
  S5_SIG=$(CUSTOMER_RECOVERY_PRIVATE_KEY="$(jq -r .private_key "$OWNER_CREDS")" "$RECOVERY_BIN" sign-nep413 \
    --message "$(jq -r '.agent_key_request.message' <<<"$BODY")" --recipient outlayer-agent-key \
    --nonce-base64 "$(jq -r '.agent_key_request.nonce_base64' <<<"$BODY")" | jq -r .signature)
  AGENT_KEY_SIGNATURE="$S5_SIG" node "$AGENT_JS" seed "$OWNER" "$WID2" "$WORK/s5.seed"
  ( umask 077; printf '%s' "$S5_SIG" > "$WORK/s5.sig" ); unset S5_SIG
  A2=$(AGENT_SEED_FILE="$WORK/s5.seed" node "$AGENT_JS" pub)
  PAIR2="$A2$TEE2"; EXPECTED_0S=$(node "$AGENT_JS" deterministic "$PAIR2")
  # the one-time key: funded by the owner with an ordinary transfer, nothing else
  KP=$(node "$HOS_LIB_DIR/ed25519_keypair.mjs")
  ( umask 077; jq -r .private_key <<<"$KP" > "$WORK/page.key" )
  K_ACC=$(node -e 'const B="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";let n=0n;for(const c of process.argv[1].slice(8))n=n*58n+BigInt(B.indexOf(c));console.log(n.toString(16).padStart(64,"0"))' "$(jq -r .public_key <<<"$KP")")
  unset KP
  O0=$(balance "$OWNER")
  OUT=$(near --quiet tokens "$OWNER" send-near "$K_ACC" '0.02 NEAR' network-config "$NETWORK" sign-with-keychain send 2>&1) \
    || fail "S5 the owner's transfer to the one-time key: $(near_why "$OUT")"
  sleep 4
  ACC0S=$(RPC_URL="$RPC_URL" PAGE_KEY_FILE="$WORK/page.key" node "$AGENT_JS" create-0s "$OWNER" "$PAIR2" 2>&1 | tail -1)
  rm -f "$WORK/page.key"
  SEALED2=$(AGENT_KEY_SIGNATURE="$(cat "$WORK/s5.sig")" node "$AGENT_JS" seal "$RPUB2" "$OWNER" "$WID2" "$OWNER_PUB")
  rm -f "$WORK/s5.sig"
  if [[ "$ACC0S" == "$EXPECTED_0S" ]]; then
    pass "S5 the one-time key created the wallet contract by StateInit at its address ($ACC0S)"
    sleep 3
    V=$(view_account "$ACC0S")
    [[ "$(jq -r '[.result.amount, .result.global_contract_hash] | @json' <<<"$V")" == "[\"0\",\"$BUILD\"]" ]] \
      && pass "S5 the account runs the approved build with no balance ($(jq -r .result.storage_usage <<<"$V") bytes)" \
      || fail "S5 the account: $(jq -c '.result | {amount, global_contract_hash, storage_usage}' <<<"$V")"
    [[ "$(access_keys "$ACC0S")" == "[]" ]] && pass "S5 no access key on it" || fail "S5 keys: $(access_keys "$ACC0S")"
    [[ "$(near_view "$ACC0S" w_public_key '{}' | tr -d '"')" == "$PAIR2" ]] && pass "S5 w_public_key is the pair" || fail "S5 w_public_key differs"
    [[ "$(view_account "$K_ACC" | jq -r '.error.cause.name // "exists"')" == UNKNOWN_ACCOUNT ]] \
      && pass "S5 the one-time key's account is deleted" || fail "S5 the one-time key's account is still there"
    SPENT=$(python3 -I -c 'import sys; print((int(sys.argv[1]) - int(sys.argv[2])) / 1e24)' "$O0" "$(balance "$OWNER")")
    note "S5 the owner spent $SPENT NEAR in all (the transfer's gas, the StateInit, the rest returned)"
    owner_page POST "$(jq -nc --arg a "$ACC0S" --arg s "$SEALED2" '{account_id:$a, sealed_agent_key:$s}')"
    [[ "$HTTP" == 200 && "$(jq -r .account_id <<<"$BODY")" == "$ACC0S" ]] && pass "S5 the setup takes the 0s account" || fail "S5 finish: $HTTP $(why)"
    owner_page GET
    [[ "$HTTP" == 409 ]] && grep -q 'finished already' <<<"$BODY" && pass "S5 the spent token says the setup was finished (409)" \
      || fail "S5 the spent token answered $HTTP $(why)"
    api_wk "$WK2" GET /wallet/v1/contract/setup >/dev/null
    if COLLECTED=$(agent_collect "$WK2" "$WORK/s5.x" "$WORK/s5.collected" 2>&1) && [[ "$COLLECTED" == "$ACC0S" ]] \
       && [[ "$(AGENT_SEED_FILE="$WORK/s5.collected" node "$AGENT_JS" pub)" == "$A2" ]]; then
      pass "S5 the agent collected its key: the owner's signature, the pair on chain and the 0s address checked"
    else fail "S5 the agent's collect: $COLLECTED"; fi

    # the owner's policy for this wallet: transfers and calls
    POLICY2=$(jq -nc --arg w "$WID2" '{wallet_id:$w, rules:{transaction_types:["transfer","call"], limits:{per_transaction:{native:"50000000000000000000000"}}}}')
    api_wk "$WK2" POST /wallet/v1/encrypt-policy "$POLICY2" >/dev/null; PENC=$(jq -r '.encrypted_base64 // ""' <<<"$BODY")
    api_wk "$WK2" POST /wallet/v1/sign-policy "$(jq -nc --arg ed "$PENC" --arg c "$OWNER" '{encrypted_data:$ed, caller:$c}')" >/dev/null
    ARGS=$(jq -c --arg ed "$PENC" '{wallet_pubkey:("ed25519:" + .public_key_hex), encrypted_data:$ed, wallet_signature:.signature_hex, version, locked, valid_until}' <<<"$BODY")
    OUT=$(near contract call-function as-transaction "$CONTRACT_ID" store_wallet_policy json-args "$ARGS" \
      prepaid-gas '100 Tgas' attached-deposit '0.1 NEAR' sign-as "$OWNER" network-config "$NETWORK" sign-with-keychain send 2>&1) \
      || fail "S5 store_wallet_policy: $(near_why "$OUT")"
    unset ARGS; sleep 5
    SAVED_ACCOUNT=$ACCOUNT_OF_AGENT SAVED_SEED=$AGENT_SEED_FILE
    export ACCOUNT_OF_AGENT="$ACC0S" AGENT_SEED_FILE="$WORK/s5.seed"

    log "Z  storage of a zero-balance 0s contract: ${STORAGE_MOVES:-0} calls with no deposit"
    CALL0=$(jq -nc '{kind:"call", to:"wrap.testnet", method:"ft_metadata", args_base64:"e30=", gas:"5000000000000", deposit:"0"}')
    Z0=$(view_account "$ACC0S" | jq -r .result.storage_usage); ZOK=0; ZFAIL=""
    for i in $(seq 1 "${STORAGE_MOVES:-0}"); do
      ask "z$i-$TS" "$CALL0"
      if [[ "$(jq -r .status <<<"$BODY")" == awaiting_signature ]]; then
        keep_prepared z
        relay_with "z$i-$TS" "$(node "$AGENT_JS" half "$WORK/z.msg")"
        if [[ "$HTTP" == 200 ]] && settle "z$i-$TS" && [[ "$STATUS" == success ]]; then ZOK=$((ZOK + 1))
        else ZFAIL="call $i: $HTTP status=$STATUS $(why)"; break; fi
      else ZFAIL="call $i asked: $HTTP $(why)"; break; fi
      (( i % 25 == 0 )) && note "Z  $(date -u +%T) after $i calls: $(view_account "$ACC0S" | jq -r .result.storage_usage) bytes, last nonce $(jq -r .nonce "$WORK/z.msg")"
    done
    if (( ${STORAGE_MOVES:-0} > 0 )); then
      Z1=$(view_account "$ACC0S" | jq -r .result.storage_usage)
      if [[ -z "$ZFAIL" ]]; then pass "Z  $ZOK calls from a zero-balance 0s contract: storage $Z0 → $Z1 bytes (zero-balance limit 770)"
      else finding "Z  after $ZOK calls the next one failed at $Z1 bytes (from $Z0): $ZFAIL"; fi
      # STORAGE_REST seconds with no call, then one: past two timeouts the contract drops
      # every nonce it keeps on that call
      if (( ${STORAGE_REST:-0} > 0 )); then
        note "Z  $(date -u +%T) resting ${STORAGE_REST}s"
        sleep "$STORAGE_REST"
        ask "zr-$TS" "$CALL0"
        if [[ "$(jq -r .status <<<"$BODY")" == awaiting_signature ]]; then
          keep_prepared z
          relay_with "zr-$TS" "$(node "$AGENT_JS" half "$WORK/z.msg")"
          if [[ "$HTTP" == 200 ]] && settle "zr-$TS" && [[ "$STATUS" == success ]]; then
            pass "Z  after the rest the call executes: storage $(view_account "$ACC0S" | jq -r .result.storage_usage) bytes (was $Z1)"
          else finding "Z  after the rest the call failed: $HTTP status=$STATUS $(why)"; fi
        else finding "Z  after the rest the call was not prepared: $HTTP $(why)"; fi
      fi
    fi

    log "S5 a move out of the 0s contract"
    near --quiet tokens "$PARENT" send-near "$ACC0S" '0.05 NEAR' network-config "$NETWORK" sign-with-keychain send >/dev/null 2>&1
    sleep 3
    ask "s5m-$TS" "$TRANSFER_SMALL"
    if [[ "$(jq -r .status <<<"$BODY")" == awaiting_signature ]]; then
      keep_prepared s5m
      check_prepared s5m "$TRANSFER_SMALL" "$ACC0S" "$TEE2" && pass "S5 the move is prepared, and is the transfer asked for" || fail "S5 the prepared request differs"
      relay_with "s5m-$TS" "$(node "$AGENT_JS" half "$WORK/s5m.msg")"
      [[ "$HTTP" == 200 ]] && settle "s5m-$TS" && [[ "$STATUS" == success ]] && pass "S5 a move out of the 0s contract executed" \
        || fail "S5 the move: $HTTP status=$STATUS $(why)"
    else fail "S5 ask: $HTTP $(why)"; fi
    export ACCOUNT_OF_AGENT="$SAVED_ACCOUNT" AGENT_SEED_FILE="$SAVED_SEED"
  else fail "S5 create-0s: $ACC0S"; fi
else fail "S5 the third wallet: $HTTP $(why)"; fi

# ── NM ───────────────────────────────────────────────────────────────────────
log "NM an agent on a new machine: a new key through the owner's own signature, the same agent key again"
# The owner's request under `Bearer near:` in the owner's scope, signed with the owner's key file
# (tests/lib/owner_token.mjs, the code the skill gives the owner). Sets HTTP and BODY.
owner_api() {
  local method=$1 path=$2 body=${3:-} out bodyf
  throttle
  out=$(mktemp "$WORK/out.XXXXXX")
  local -a args=(-sS -o "$out" -w '%{http_code}' -X "$method" "$COORDINATOR_URL$path" --max-time 60 -H @-)
  if [[ -n "$body" ]]; then bodyf=$(mktemp "$WORK/body.XXXXXX"); printf '%s' "$body" > "$bodyf"; args+=(-H 'Content-Type: application/json' --data-binary @"$bodyf"); fi
  HTTP=$(curl "${args[@]}" <<<"Authorization: Bearer near:$(OWNER_KEY_FILE="$OWNER_CREDS" node "$HOS_LIB_DIR/owner_token.mjs" "$OWNER" 0)" 2>/dev/null)
  BODY=$(tr -d '\n' < "$out"); rm -f "$out" ${bodyf:+"$bodyf"}
}
# owner_policy <jq filter over GET /wallet/v1/policy> — the owner stores the policy the filter makes.
owner_policy() {
  owner_api GET /wallet/v1/policy; local current=$BODY
  owner_api POST /wallet/v1/encrypt-policy "$(jq -c "$1" <<<"$current")"
  local enc; enc=$(jq -r '.encrypted_base64 // ""' <<<"$BODY"); [[ -n "$enc" ]] || return 1
  owner_api POST /wallet/v1/sign-policy "$(jq -nc --arg e "$enc" --arg c "$OWNER" '{encrypted_data:$e, caller:$c}')"
  [[ "$HTTP" == 200 ]] || return 1
  local args; args=$(jq -c --arg e "$enc" '{wallet_pubkey:("ed25519:"+.public_key_hex), encrypted_data:$e, wallet_signature:.signature_hex, version, locked, valid_until}' <<<"$BODY")
  near contract call-function as-transaction "$CONTRACT_ID" store_wallet_policy json-args "$args" \
    prepaid-gas '100 Tgas' attached-deposit '0.1 NEAR' sign-as "$OWNER" network-config "$NETWORK" sign-with-keychain send >/dev/null 2>&1
}
key_works() { # key_works <wk_> — the key answers within a minute
  local i; for i in $(seq 1 20); do api_wk "$1" GET '/wallet/v1/address?chain=near' >/dev/null; [[ "$HTTP" == 200 ]] && return 0; sleep 3; done; return 1
}
owner_api GET /wallet/v1/contract
[[ "$HTTP" == 200 && "$(jq -r .account_id <<<"$BODY")" == "$AGENT_ACC" ]] \
  && pass "NM the owner reaches the wallet by its own signature: seed 0 holds $AGENT_ACC" || fail "NM the owner's token: $HTTP $(why)"
( umask 077; printf 'wk_%s' "$(openssl rand -hex 32)" > "$WORK/new.wk" )
NEW_HASH=$(printf '%s' "$(cat "$WORK/new.wk")" | shasum -a 256 | cut -d' ' -f1)
api_wk "$(cat "$WORK/new.wk")" GET '/wallet/v1/address?chain=near' >/dev/null
[[ "$HTTP" == 401 ]] || fail "NM the new key answered $HTTP before any policy named it"
if owner_policy "$(printf '{wallet_id, rules, approval, capabilities, refund_addresses, authorized_key_hashes: ["%s"]} | with_entries(select(.value != null))' "$NEW_HASH")" \
   && key_works "$(cat "$WORK/new.wk")"; then
  pass "NM the owner's policy names the new key, and it runs the wallet"
  api_wk "$WK0" GET '/wallet/v1/address?chain=near' >/dev/null
  [[ "$HTTP" == 401 ]] && pass "NM the key of the old machine stops with the same write" || fail "NM the old key answered $HTTP"
else fail "NM the new key: the policy store or its sync failed"; fi

# A setup again from the new machine: the same owner key, the same agent key, the same account.
RPUB3=$(node "$AGENT_JS" x25519-new "$WORK/new.x")
api_wk "$(cat "$WORK/new.wk")" POST /wallet/v1/contract/setup "$(jq -nc --arg r "$RPUB3" '{recipient_public_key:$r}')" >/dev/null
SETUP_TOKEN=$(jq -r '.token // ""' <<<"$BODY")
owner_page GET
if [[ "$HTTP" == 200 && "$(jq -c '[.current_contract.account_id, .current_contract.agent_public_key]' <<<"$BODY")" == "$(jq -nc --arg a "$AGENT_ACC" --arg k "$AGENT_PUB" '[$a,$k]')" ]]; then
  pass "NM the owner's page names the wallet contract the wallet has, and its agent key"
else fail "NM current_contract: $HTTP $(jq -c '.current_contract // "absent"' <<<"$BODY" 2>/dev/null | cut -c1-160)"; fi
AGENT_KEY_SIGNATURE="$(cat "$WORK/ak.sig")" node "$AGENT_JS" seed "$OWNER" "$WID0" "$WORK/again.seed"
[[ "$(AGENT_SEED_FILE="$WORK/again.seed" node "$AGENT_JS" pub)" == "$AGENT_PUB" ]] \
  && pass "NM the owner's key makes the agent key on record again" || fail "NM the signature made another agent key"
owner_page POST "$(jq -nc --arg a "$AGENT_ACC" --arg s "$(AGENT_KEY_SIGNATURE="$(cat "$WORK/ak.sig")" node "$AGENT_JS" seal "$RPUB3" "$OWNER" "$WID0" "$OWNER_PUB")" '{account_id:$a, sealed_agent_key:$s}')"
[[ "$HTTP" == 200 && "$(jq -r .account_id <<<"$BODY")" == "$AGENT_ACC" ]] && pass "NM the setup again hands the key over for the same account" \
  || fail "NM the hand-over: $HTTP $(why)"
api_wk "$(cat "$WORK/new.wk")" GET /wallet/v1/contract/setup >/dev/null
if [[ "$(jq -r .done <<<"$BODY")" == true ]] \
   && [[ "$(agent_collect "$(cat "$WORK/new.wk")" "$WORK/new.x" "$WORK/new.seed")" == "$AGENT_ACC" ]] \
   && [[ "$(AGENT_SEED_FILE="$WORK/new.seed" node "$AGENT_JS" pub)" == "$AGENT_PUB" ]]; then
  pass "NM the agent on the new machine holds the same agent key, for $AGENT_ACC"
else fail "NM the new machine's agent key: $(jq -c '{done, error}' <<<"$BODY" 2>/dev/null)"; fi
rm -f "$WORK/again.seed" "$WORK/new.seed" "$WORK/new.x"

# Back as it was: a policy that names no key brings the creation key back.
if owner_policy '{wallet_id, rules, approval, capabilities, refund_addresses} | with_entries(select(.value != null))' && key_works "$WK0"; then
  pass "NM a policy naming no key brings the creation key back"
else fail "NM the creation key did not come back"; fi
rm -f "$WORK/new.wk"

# ── L ────────────────────────────────────────────────────────────────────────
# The owner's side of the DAO's exit, for L and X.
MPC_PK=$(near_view "$MPC_CONTRACT" public_key '{"domain_id":2}' | tr -d '"')
exit_tool() {
  local cmd=$1; shift
  RPC_URL="$RPC_URL" OWNER_PRIVATE_KEY="$(jq -r .private_key "$OWNER_CREDS")" MPC_PUBLIC_KEY="$MPC_PK" \
    "$RECOVERY_BIN" owner-exit "$cmd" --owner "$OWNER" --dao "$DAO" "$@" 2>&1
}
exit_record() { near_view "$DAO" get_exit_owner "$(jq -nc --arg a "$OWNER" '{account:$a}')"; }
# exit_set — the exit approvers in force, sorted, and their threshold.
exit_set() { exit_record | jq -c '[(.approvers | sort), .threshold]' 2>/dev/null; }
# tx <signer> <contract> <method> <args-json> <deposit> — a transaction; its output in OUT.
# One refused for its nonce was never applied (near-cli read the key's nonce from a node a
# block behind) and is sent again.
tx() {
  local attempt rc
  for attempt in 1 2 3; do
    OUT=$(near --quiet contract call-function as-transaction "$2" "$3" json-args "$4" \
      prepaid-gas '100 Tgas' attached-deposit "$5" sign-as "$1" network-config "$NETWORK" \
      sign-with-keychain send 2>&1); rc=$?
    sleep 3
    grep -q 'Transaction nonce .* must be account\[access_key\].nonce' <<<"$OUT" || return $rc
  done
  return $rc
}
# exit_vote <approve|reject> <approver> <nonce> — an approver's vote on the owner's pending action.
exit_vote() { tx "$2" "$DAO" "${1}_exit" "$(jq -nc --arg o "$OWNER" --argjson n "$3" '{owner:$o, nonce:$n}')" '1 yoctoNEAR'; }
# The policy record of wallet 0 on chain as version/locked/frozen; chain_shows waits for it.
policy_chain() { near_view "$CONTRACT_ID" get_wallet_policy "$(jq -nc --arg k "${WPUB0:-}" '{wallet_pubkey:$k}')" | jq -r '"\(.version)/\(.locked)/\(.frozen)"' 2>/dev/null; }
chain_shows() { # chain_shows <row and what> <version/locked/frozen>
  local i got=""
  for i in 1 2 3 4 5 6; do got=$(policy_chain); [[ "$got" == "$2" ]] && break; sleep 3; done
  [[ "$got" == "$2" ]] && pass "$1: the chain shows version/locked/frozen $got" || fail "$1: the chain shows $got, expected $2"
}
# policy_ask <policy-json> — wallet 0's key asks the keystore to sign a policy for the owner.
# 0: signed, BODY is the signature and L_ENC the ciphertext. 2: held for the approvers
# (L_AID, L_RID, L_HASH). 1: refused, HTTP and BODY say why.
policy_ask() {
  L_ENC=""; L_AID=""; L_RID=""; L_HASH=""
  api_wk "$WK0" POST /wallet/v1/encrypt-policy "$1" >/dev/null
  L_ENC=$(jq -r '.encrypted_base64 // ""' <<<"$BODY" 2>/dev/null); [[ -n "$L_ENC" ]] || return 1
  api_wk "$WK0" POST /wallet/v1/sign-policy "$(jq -nc --arg ed "$L_ENC" --arg c "$OWNER" '{encrypted_data:$ed, caller:$c}')" >/dev/null
  if [[ "$(jq -r '.status // ""' <<<"$BODY" 2>/dev/null)" == pending_approval ]]; then
    L_AID=$(jq -r .approval_id <<<"$BODY"); L_RID=$(jq -r .request_id <<<"$BODY"); L_HASH=$(jq -r .request_hash <<<"$BODY")
    return 2
  fi
  [[ "$HTTP" == 200 && -n "$(jq -r '.signature_hex // ""' <<<"$BODY" 2>/dev/null)" ]]
}
# policy_store <store_wallet_policy args> — the owner's transaction.
policy_store() { tx "$OWNER" "$CONTRACT_ID" store_wallet_policy "$1" '0.1 NEAR'; }
# policy_vote <approver> <approval id> <request hash> — a NEP-413 approve by the approver's own
# key. HTTP and BODY are the coordinator's answer.
policy_vote() {
  local who=$1 aid=$2 hash=$3 wpk nonce sig
  api - GET "/wallet/v1/approval/$aid" >/dev/null; wpk=$(jq -r '.wallet_pubkey // ""' <<<"$BODY")
  nonce=$(head -c 32 /dev/urandom | base64 | tr -d '\n')
  sig=$(CUSTOMER_RECOVERY_PRIVATE_KEY="$(jq -r .private_key "$CREDS_DIR/$who.json")" "$RECOVERY_BIN" sign-nep413 \
    --message "approve:$aid:$wpk:$hash" --recipient "$CONTRACT_ID" --nonce-base64 "$nonce" | jq -r .signature)
  api - POST "/wallet/v1/approve/$aid" "$(jq -nc --arg s "$sig" --arg pk "$(jq -r .public_key "$CREDS_DIR/$who.json")" \
    --arg a "$who" --arg n "$nonce" '{signature:$s, public_key:$pk, account_id:$a, nonce:$n}')" >/dev/null
}
# policy_request <request id> — the held write's request, waited for; R_ST is where it ended
# and BODY the request.
R_ST=""
policy_request() {
  local i; R_ST=""
  for i in $(seq 1 20); do
    sleep 3
    api_wk "$WK0" GET "/wallet/v1/requests/$1" >/dev/null
    R_ST=$(jq -r '.status // ""' <<<"$BODY" 2>/dev/null)
    [[ "$R_ST" == success || "$R_ST" == failed || "$R_ST" == rejected ]] && return 0
  done
  return 1
}
# ask_until <id prefix> <op> <status|error> — the agent asks, under a new id each time, until
# the answer's status or error code is the one named (a write on chain reaches the
# coordinator within a minute). ASKED is the id of the last ask.
ASKED=""
ask_until() {
  local i
  for i in $(seq 1 20); do
    ASKED="$1$i-$TS"; ask "$ASKED" "$2"
    [[ "$(jq -r '.status // .error // ""' <<<"$BODY" 2>/dev/null)" == "$3" ]] && return 0
    sleep 3
  done
  return 1
}
# run_prepared <row> <name> <op> — the operation in BODY is waiting for the agent: checked,
# signed last, relayed, settled.
run_prepared() {
  keep_prepared "$2"
  check_prepared "$2" "$3" && pass "$1 prepared: the request is the transfer asked for, and the TEE's half is valid" \
    || fail "$1 the prepared request is not the operation asked for"
  relay_with "$ASKED" "$(node "$AGENT_JS" half "$WORK/$2.msg")"
  if [[ "$HTTP" == 200 ]] && settle "$ASKED" && [[ "$STATUS" == success ]]; then pass "$1 the agent's half last: executed"
  else fail "$1 relay: $HTTP status=$STATUS $(why)"; fi
}

log "L  a locked policy on a wallet with a wallet contract: approvers $APPROVER + $APPROVER2 (2 of 2)"
# 0.05 NEAR a transfer, 0.2 a day without the approvers; LC raises the first to 0.1.
lock_policy() { # lock_policy <per_transaction> <locked true|false> [approvers-json]
  jq -nc --arg w "$WID0" --arg a "$APPROVER" --arg b "$APPROVER2" --arg per "$1" --argjson locked "$2" --argjson approvers "${3:-null}" \
    '{wallet_id:$w, rules:{transaction_types:["transfer"], limits:{per_transaction:{native:$per}}},
      approval:({threshold:{required:2}, approvers:($approvers // [{id:$a},{id:$b}]), auto_up_to:{daily:{native:"200000000000000000000000"}}}
                + (if $locked then {locked:true} else {} end))}'
}
PER_OLD=50000000000000000000000; PER_NEW=100000000000000000000000; L_PER=$PER_OLD
TRANSFER_OVER=$(jq -nc --arg to "$RECIPIENT" '{kind:"transfer", to:$to, amount:"60000000000000000000000"}')   # 0.06 NEAR
WANT_SET=$(jq -nc --arg a "$APPROVER" --arg b "$APPROVER2" '[([$a,$b] | sort), 2]')
L_LOCKED=""; L_V=""
if [[ -z "${WPUB0:-}" || "$(policy_chain | cut -d/ -f2)" != false ]]; then
  fail "L  wallet 0 has no unlocked policy on chain to lock ($(policy_chain))"
else
  L_V=$(policy_chain | cut -d/ -f1)
  policy_ask "$(lock_policy "$PER_OLD" true)"; RC=$?
  [[ $RC -eq 1 && "$HTTP" =~ ^4 ]] && grep -q 'set_exit_approvers' <<<"$BODY" \
    && pass "L  with no exit approvers in the DAO the keystore does not sign a locked policy ($HTTP, names set_exit_approvers)" \
    || fail "L  a lock with no exit approvers: rc=$RC $HTTP $(why)"
  tx "$OWNER" "$DAO" set_exit_approvers "$(jq -nc --arg a "$APPROVER" --arg b "$APPROVER2" '{approvers:[$a,$b], threshold:2}')" '1 yoctoNEAR'
  [[ "$(exit_set)" == "$WANT_SET" ]] && pass "L  the owner names the exit approvers in the DAO: the first set is in force at once" \
    || fail "L  set_exit_approvers: $(near_why "$OUT"); the DAO shows $(exit_set)"
  policy_ask "$(lock_policy "$PER_OLD" true "$(jq -nc --arg a "$APPROVER" --arg k "$APPROVER_PUB" --arg b "$APPROVER2" '[{id:$a, pubkey:$k},{id:$b}]')")"; RC=$?
  [[ $RC -eq 1 && "$HTTP" =~ ^4 ]] && grep -q 'pinned to a key' <<<"$BODY" \
    && pass "L  a lock with an approver pinned to a key is not signed ($HTTP)" \
    || fail "L  a lock with a pinned approver: rc=$RC $HTTP $(why)"
  policy_ask "$(lock_policy "$PER_OLD" true)"; RC=$?
  if [[ $RC -eq 0 && "$(jq -c '[.version, .locked]' <<<"$BODY")" == "[$((L_V + 1)),true]" ]]; then
    pass "L  the keystore signs the lock for the owner alone: version $((L_V + 1)), locked"
    policy_store "$(jq -c --arg ed "$L_ENC" '{wallet_pubkey:("ed25519:" + .public_key_hex), encrypted_data:$ed, wallet_signature:.signature_hex, version, locked, valid_until}' <<<"$BODY")" \
      && pass "L  the owner alone stores the first locked policy" || fail "L  store_wallet_policy: $(near_why "$OUT")"
    L_V=$((L_V + 1))
    chain_shows "L  after the owner's write" "$L_V/true/false"
    [[ "$(policy_chain)" == "$L_V/true/false" ]] && L_LOCKED=1
  else fail "L  the first lock: rc=$RC $HTTP $(why)"; fi
fi

if [[ -z "$L_LOCKED" ]]; then
  skip "LF LB LC LE LU: the locked policy is not on chain, so nothing under it is judged"
else
  # ── LF ─────────────────────────────────────────────────────────────────────
  log "LF under the lock the owner alone freezes and unfreezes"
  tx "$OWNER" "$CONTRACT_ID" freeze_wallet "$(jq -nc --arg k "$WPUB0" '{wallet_pubkey:$k}')" '0 NEAR' \
    && pass "LF freeze_wallet by the owner alone went through" || fail "LF freeze_wallet: $(near_why "$OUT")"
  chain_shows "LF frozen" "$L_V/true/true"
  ask_until lf "$TRANSFER_TINY" wallet_frozen && [[ "$HTTP" == 403 ]] \
    && pass "LF nothing is prepared for a frozen wallet (403 wallet_frozen)" || fail "LF an operation of a frozen wallet: $HTTP $(why)"
  tx "$OWNER" "$CONTRACT_ID" unfreeze_wallet "$(jq -nc --arg k "$WPUB0" '{wallet_pubkey:$k}')" '0 NEAR' \
    && pass "LF unfreeze_wallet by the owner alone went through" || fail "LF unfreeze_wallet: $(near_why "$OUT")"
  chain_shows "LF unfrozen" "$L_V/true/false"

  # ── LB ─────────────────────────────────────────────────────────────────────
  log "LB an operation inside the limits, under the lock"
  if ask_until lb "$TRANSFER_TINY" awaiting_signature; then
    pass "LB 0.001 NEAR under the locked policy waits for no approver"
    run_prepared LB lb "$TRANSFER_TINY"
  else fail "LB ask: $HTTP $(why)"; fi

  # ── LC ─────────────────────────────────────────────────────────────────────
  log "LC a change of the policy under the lock: 0.05 → 0.1 NEAR a transfer"
  ask "lc0-$TS" "$TRANSFER_OVER"
  [[ "$HTTP" == 403 && "$(jq -r .error <<<"$BODY")" == policy_denied ]] && pass "LC 0.06 NEAR is over the limit in force (403 policy_denied)" \
    || fail "LC 0.06 NEAR before the change: $HTTP $(why)"
  policy_ask "$(lock_policy "$PER_NEW" true)"; RC=$?
  if [[ $RC -eq 2 ]]; then
    C_AID=$L_AID C_RID=$L_RID C_HASH=$L_HASH
    [[ -z "$(jq -r '.signature_hex // ""' <<<"$BODY")" ]] && pass "LC the owner alone gets no signature: the write is held for the approvers" \
      || fail "LC a held write carries a signature"
    api - GET "/wallet/v1/approval/$C_AID" >/dev/null
    [[ "$(jq -c '[.request_type, .required_approvals, .request_data.version, .request_data.locked]' <<<"$BODY")" == "[\"policy_update\",2,$((L_V + 1)),true]" ]] \
      && pass "LC the approvers see a policy_update to version $((L_V + 1)), still locked, needing 2 votes" \
      || fail "LC the approval: $(jq -c '[.request_type, .required_approvals, .request_data.version, .request_data.locked]' <<<"$BODY" 2>/dev/null)"
    tx "$OWNER" "$CONTRACT_ID" delete_wallet_policy "$(jq -nc --arg k "$WPUB0" '{wallet_pubkey:$k}')" '0 NEAR'
    RC=$?; WHY=$(near_why "$OUT")
    [[ $RC -ne 0 ]] && grep -q 'policy is locked' <<<"$WHY" && pass "LC the owner cannot delete the policy instead: refused on chain (policy is locked)" \
      || fail "LC delete_wallet_policy under the lock: rc=$RC $WHY"
    policy_vote "$APPROVER" "$C_AID" "$C_HASH"
    [[ "$HTTP" == 200 && "$(jq -r .status <<<"$BODY")" == pending ]] && pass "LC one vote of two: still held" || fail "LC the first vote: $HTTP $(why)"
    chain_shows "LC with one vote" "$L_V/true/false"
    ask "lc1-$TS" "$TRANSFER_OVER"
    [[ "$HTTP" == 403 && "$(jq -r .error <<<"$BODY")" == policy_denied ]] && pass "LC the limit in force is still the old one (403 policy_denied)" \
      || fail "LC 0.06 NEAR with one vote: $HTTP $(why)"
    policy_vote "$APPROVER2" "$C_AID" "$C_HASH"
    [[ "$HTTP" == 200 ]] || fail "LC the second vote: $HTTP $(why)"
    policy_request "$C_RID"
    if [[ "$R_ST" == success && "$(jq -c '[.result.version, .result.locked]' <<<"$BODY")" == "[$((L_V + 1)),true]" ]]; then
      pass "LC with the quorum the keystore signed the write: version $((L_V + 1)), locked"
      policy_store "$(jq -c '.result | {wallet_pubkey, encrypted_data, wallet_signature, version, locked, valid_until}' <<<"$BODY")" \
        && pass "LC the owner stores the approved policy" || fail "LC store_wallet_policy: $(near_why "$OUT")"
      L_V=$((L_V + 1)); L_PER=$PER_NEW
      chain_shows "LC after the quorum" "$L_V/true/false"
      if ask_until lc "$TRANSFER_OVER" awaiting_signature; then
        pass "LC the new limit applies: 0.06 NEAR is prepared"
        run_prepared LC lc "$TRANSFER_OVER"
      else fail "LC 0.06 NEAR after the change: $HTTP $(why)"; fi
    else fail "LC the held write ended '$R_ST': $(jq -c '.result' <<<"$BODY" 2>/dev/null | head -c 200)"; fi
  else fail "LC a change under the lock was not held: rc=$RC $HTTP $(why)"; fi

  # ── LE ─────────────────────────────────────────────────────────────────────
  log "LE the exit under the lock"
  tx "$OWNER" "$DAO" set_exit_approvers '{"approvers":[], "threshold":0}' '1 yoctoNEAR'
  E_REC=$(exit_record); E_NONCE=$(jq -r '.pending.nonce // ""' <<<"$E_REC")
  if [[ -n "$E_NONCE" && "$(jq -c '.pending.kind | keys' <<<"$E_REC")" == '["SetApprovers"]' && "$(exit_set)" == "$WANT_SET" ]]; then
    pass "LE the owner alone cannot drop the exit approvers: the change is pending, the set stays in force"
    exit_vote reject "$APPROVER" "$E_NONCE"
    [[ "$(exit_record | jq -c '.pending')" == null && "$(exit_set)" == "$WANT_SET" ]] && pass "LE one reject ends the change: the set is as it was" \
      || fail "LE reject_exit on the change: $(near_why "$OUT"); the DAO shows $(exit_set)"
  else fail "LE set_exit_approvers to none: $(near_why "$OUT"); pending $(jq -c '.pending.kind // null' <<<"$E_REC" 2>/dev/null)"; fi
  if [[ "$MPC_PK" == bls12381g2:* ]] && OUT=$(exit_tool initiate); then
    E_REC=$(exit_record); E_NONCE=$(jq -r '.pending.nonce // ""' <<<"$E_REC"); E_GEN=$(jq -r .generation <<<"$E_REC")
    pass "LE the owner started an exit (nonce $E_NONCE)"
    exit_vote approve "$STRANGER" "$E_NONCE"
    RC=$?; WHY=$(near_why "$OUT")
    [[ $RC -ne 0 ]] && grep -q 'not an approver of this owner' <<<"$WHY" && pass "LE a vote from outside the set is refused on chain" \
      || fail "LE approve_exit by $STRANGER: rc=$RC $WHY"
    AFTER=$(jq -r '(.pending.kind.Exit.finalize_after // 0) / 1e9 | floor' <<<"$E_REC")
    WAIT=$(( AFTER + 6 - $(date +%s) )); (( WAIT > 0 )) && { note "waiting ${WAIT}s for the exit window"; sleep "$WAIT"; }
    OUT=$(exit_tool claim --claim-file "$WORK/claim-novote.json"); OUT=$(grep -v '^master_hex=' <<<"$OUT")
    E_REC=$(exit_record)
    if grep -q '0 of 2 approvals' <<<"$OUT" && [[ "$(jq -c '[.generation, .claim_in_flight, (.pending.nonce | tostring)]' <<<"$E_REC")" == "[$E_GEN,false,\"$E_NONCE\"]" ]]; then
      pass "LE past the window the claim is refused without the approvers (0 of 2 approvals); the generation stays $E_GEN"
    else fail "LE a claim with no vote: $(grep -oE '[0-9]+ of [0-9]+ approvals|the exit window has not elapsed|no exit is pending' <<<"$OUT" | head -1); the DAO shows $(jq -c '{generation, claim_in_flight}' <<<"$E_REC" 2>/dev/null)"; fi
    exit_vote reject "$APPROVER2" "$E_NONCE"
    [[ "$(exit_record | jq -c '[.pending, .generation]')" == "[null,$E_GEN]" ]] && pass "LE one reject by an approver ends the exit" \
      || fail "LE reject_exit: $(near_why "$OUT"); pending $(exit_record | jq -c '.pending.kind // null' 2>/dev/null)"
    ask_until le "$TRANSFER_TINY" awaiting_signature && pass "LE the wallet goes on after the rejected exit: an operation is prepared" \
      || fail "LE an operation after the rejected exit: $HTTP $(why)"
  else fail "LE the exit did not start: $(near_why "$OUT")"; fi

  # ── LU ─────────────────────────────────────────────────────────────────────
  log "LU the unlock"
  policy_ask "$(lock_policy "$L_PER" false)"; RC=$?
  if [[ $RC -eq 2 ]]; then
    pass "LU the owner alone does not unlock: the write is held for the approvers"
    U_AID=$L_AID U_RID=$L_RID U_HASH=$L_HASH
    policy_vote "$APPROVER" "$U_AID" "$U_HASH"
    [[ "$HTTP" == 200 && "$(jq -r .status <<<"$BODY")" == pending ]] && pass "LU one vote of two: still held" || fail "LU the first vote: $HTTP $(why)"
    chain_shows "LU with one vote" "$L_V/true/false"
    policy_vote "$APPROVER2" "$U_AID" "$U_HASH"
    [[ "$HTTP" == 200 ]] || fail "LU the second vote: $HTTP $(why)"
    policy_request "$U_RID"
    if [[ "$R_ST" == success && "$(jq -c '[.result.version, .result.locked]' <<<"$BODY")" == "[$((L_V + 1)),false]" ]]; then
      policy_store "$(jq -c '.result | {wallet_pubkey, encrypted_data, wallet_signature, version, locked, valid_until}' <<<"$BODY")" \
        && pass "LU with the quorum the unlock is signed, and the owner stores it" || fail "LU store_wallet_policy: $(near_why "$OUT")"
      L_V=$((L_V + 1))
      chain_shows "LU after the quorum" "$L_V/false/false"
    else fail "LU the held unlock ended '$R_ST': $(jq -c '.result' <<<"$BODY" 2>/dev/null | head -c 200)"; fi
  else fail "LU an unlock was not held: rc=$RC $HTTP $(why)"; fi
fi

# ── X ────────────────────────────────────────────────────────────────────────
log "X  the owner's exit"
MASTER=""
if [[ "$MPC_PK" == bls12381g2:* ]] && OUT=$(exit_tool initiate); then
  pass "X  the owner started the exit"
  X_REC=$(exit_record); X_NONCE=$(jq -r '.pending.nonce // ""' <<<"$X_REC"); X_GEN=$(jq -r .generation <<<"$X_REC")
  AFTER=$(jq -r '(.pending.kind.Exit.finalize_after // 0) / 1e9 | floor' <<<"$X_REC")
  WAIT=$(( AFTER + 6 - $(date +%s) )); (( WAIT > 0 )) && { note "waiting ${WAIT}s for the exit window"; sleep "$WAIT"; }
  # With exit approvers in force (L) the claim takes their quorum as well as the window.
  if [[ "$(jq -r '.approvers | length' <<<"$X_REC")" != 0 ]]; then
    exit_vote approve "$APPROVER" "$X_NONCE" && pass "X  $APPROVER approves the exit on chain" || fail "X  approve_exit by $APPROVER: $(near_why "$OUT")"
    OUT=$(exit_tool claim --claim-file "$WORK/claim-onevote.json"); OUT=$(grep -v '^master_hex=' <<<"$OUT")
    grep -q '1 of 2 approvals' <<<"$OUT" && [[ "$(exit_record | jq -r .generation)" == "$X_GEN" ]] \
      && pass "X  one vote of two does not open the claim (1 of 2 approvals)" \
      || fail "X  a claim with one vote of two: $(grep -oE '[0-9]+ of [0-9]+ approvals|the exit window has not elapsed|no exit is pending' <<<"$OUT" | head -1)"
    exit_vote approve "$APPROVER2" "$X_NONCE" && pass "X  $APPROVER2 approves: the quorum" || fail "X  approve_exit by $APPROVER2: $(near_why "$OUT")"
  fi
  OUT=$(exit_tool claim --claim-file "$WORK/claim.json")
  MASTER=$(grep -oE '^master_hex=[0-9a-f]{64}$' <<<"$OUT" | cut -d= -f2); OUT=$(grep -v '^master_hex=' <<<"$OUT")
  [[ -n "$MASTER" ]] && pass "X  the claim gave the owner the master" || fail "X  claim: $(near_why "$OUT")"
else fail "X  the exit did not start: $(near_why "$OUT")"; fi
if [[ -n "$MASTER" ]]; then
  ask "x-$TS" "$TRANSFER_TINY"
  [[ "$HTTP" =~ ^4 ]] && pass "X  after the claim the agent's operation is refused ($HTTP $(why))" \
    || fail "X  after the claim: $HTTP $(why)"
  KEYS_OUT=$(CUSTOMER_RECOVERY_MASTER="$MASTER" AGENT_KEY_SIGNATURE="$(cat "$WORK/ak.sig")" "$RECOVERY_BIN" wallet-contract keys --owner "$OWNER" --wallet-id "$WID0" 2>/dev/null)
  [[ "$(jq -r .public_key <<<"$KEYS_OUT")" == "$AGENT_PUB$TEE_PUB" ]] && pass "X  the tool derives both keys of the pair from the master and the signature" \
    || fail "X  the tool's pair is not the contract's"
  R0=$(balance "$RECIPIENT")
  MADE=$(CUSTOMER_RECOVERY_MASTER="$MASTER" AGENT_KEY_SIGNATURE="$(cat "$WORK/ak.sig")" "$RECOVERY_BIN" wallet-contract request \
    --owner "$OWNER" --wallet-id "$WID0" --contract "$AGENT_ACC" --network testnet \
    --transfer-to "$RECIPIENT" --amount 50000000000000000000000 2>/dev/null)
  OUT=$(near contract call-function as-transaction "$AGENT_ACC" w_execute_signed json-args "$(jq -c .args <<<"$MADE")" \
    prepaid-gas '300 Tgas' attached-deposit '0 NEAR' sign-as "$STRANGER" network-config "$NETWORK" sign-with-keychain send 2>&1) \
    || fail "X  the owner's request: $(near_why "$OUT")"
  sleep 3
  [[ "$(sub "$(balance "$RECIPIENT")" "$R0")" == 50000000000000000000000 ]] \
    && pass "X  the owner moved 0.05 NEAR out of the wallet contract with no OutLayer service" \
    || fail "X  the owner's move did not arrive"
  unset MASTER MADE KEYS_OUT
fi

verdict on_chain_custody
