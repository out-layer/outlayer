#!/usr/bin/env bash
#
# Agent On-chain custody on testnet: an owner sets up a wallet contract for their agent, the
# agent moves its funds under two signatures, and the owner's policy decides what is signed.
# The agent's side is tests/lib/custody_agent.mjs (custody-core's byte formats, held to its
# vectors before anything runs); the owner's page is played by near-cli and the recovery tool.
#
#   P   the keystore DAO lists the build; the agent's side matches custody-core's vectors
#   F   an owner registers the exit and gets a wallet (generation 1, seed 0) from an agent link
#   S1  the setup: the agent opens it; the owner reads it, signs the agent key's message,
#       creates `agent.<owner>`, installs the published build with `(A, E)` and removes every
#       key; seals the agent's key; the agent collects it and opens the same key
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
#       operation routes, an agent's signature on a `wk_` route, another key's signature
#   P1  over `per_transaction`: refused, nothing to sign
#   A   the agent: the same id with another body is refused; the open operations list shows
#       an operation waiting for the agent's half; asking again continues it
#   P2  above `auto_up_to`: the operation waits; listed as pending; the approver votes; the
#       agent's repeat under the same id is prepared and goes through
#   I1  use_bound_identity: a program run with the flag runs as the wallet contract's account
#       (needs a trial key for the wallet; steps aside loudly without one)
#
# Not here: the DAO revoking the build (two DAO votes, and every wallet on testnet refused between them), an
# extension added to a wallet contract by hand, the owner's exit (owner_exit_e2e.sh), and
# the NEAR Intents kinds (mainnet only).
#
# Run:
#   PARENT=outlayer-alice.testnet ./tests/on_chain_custody_e2e.sh --apply
# APPROVER (default outlayer-carol) votes; RECIPIENT (default outlayer-daniel) is paid;
# STRANGER (default outlayer-bob) sends the on-chain refusals. About 4.5 NEAR of PARENT's, most of
# it left on the run's accounts. The working account relays: nearcore reserves 300 Tgas at its
# pessimistic gas price before a relay runs (0.3 NEAR on testnet), so it is funded with 1 NEAR.

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/hos_common.sh"
source "$HOS_LIB_DIR/near_sign.sh"

[[ "${1:-}" == "--apply" ]] || { sed -n '3,45p' "$0" >&2; warn "Dry run. Pass --apply."; exit 0; }
[[ "$NETWORK" == testnet ]] || { echo "✗ this suite runs on testnet" >&2; exit 1; }

DAO="${DAO:-dao.outlayer.testnet}"
CONTRACT_ID="${CONTRACT_ID:-outlayer.testnet}"
BUILD="${BUILD:-651XC7DH8J4Xczf8JKXH9pyveBY8ZuNCfy5HZ3SvuSiL}"
APPROVER="${APPROVER:-outlayer-carol.testnet}"
RECIPIENT="${RECIPIENT:-outlayer-daniel.testnet}"
STRANGER="${STRANGER:-outlayer-bob.testnet}"
VECTORS="${VECTORS:-$REPO_ROOT/../shared-tee-helpers/custody-core/vectors}"
AGENT_JS="$HOS_LIB_DIR/custody_agent.mjs"
hos_require
for a in "$APPROVER" "$RECIPIENT" "$STRANGER"; do
  [[ -f "$CREDS_DIR/$a.json" ]] || { echo "✗ creds missing for $a" >&2; exit 1; }
done

OWNER="oc$(date +%s).$PARENT"
OWNER_CREDS="$CREDS_DIR/$OWNER.json"
AGENT_ACC="agent.$OWNER"
AGENT_CREDS="$CREDS_DIR/$AGENT_ACC.json"
WORK=$(mktemp -d -t on_chain_custody.XXXXXX) || exit 1
chmod 700 "$WORK"
TS=$(date +%s)

cleanup() {
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
# check_prepared <name> <op-json> — the agent's own checks before it signs: the request is
# this wallet contract's, is the operation asked for, and carries a valid TEE half.
check_prepared() {
  local name=$1 op=$2 msg; msg=$(cat "$WORK/$name.msg")
  local kind; kind=$(jq -r .kind <<<"$op")
  local want
  case "$kind" in
    transfer) want=$(jq -nc --arg s "$ACCOUNT_OF_AGENT" --argjson op "$op" '[$s, $op.to, "transfer", $op.amount]')
              [[ "$(jq -c '[.signer_id, .promise.receiver_id, .promise.action.action, .promise.action.amount]' <<<"$msg")" == "$want" ]] || return 1 ;;
    *) return 1 ;;
  esac
  [[ "$(jq -r .chain_id <<<"$msg")" == testnet ]] || return 1
  node "$AGENT_JS" verify-tee "$WORK/$name.msg" "$(cat "$WORK/$name.tee")" "$TEE_PUB"
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
owner_page GET
if [[ "$HTTP" == 200 && "$(jq -c '[.wallet_id, .owner, .tee_public_key, .recipient_public_key, .agent_key_request.recipient]' <<<"$BODY")" == "$(jq -nc --arg w "$WID0" --arg o "$OWNER" --arg t "$TEE_PUB" --arg r "$RPUB" '[$w,$o,$t,$r,"outlayer-agent-key"]')" ]]; then
  pass "S1 the owner's page shows the wallet, the owner, the TEE key and the agent's one-time key"
else fail "S1 the owner's page: $HTTP $(why)"; fi
AK_MSG=$(jq -r '.agent_key_request.message' <<<"$BODY"); AK_NONCE=$(jq -r '.agent_key_request.nonce_base64' <<<"$BODY")
AK_SIG=$(CUSTOMER_RECOVERY_PRIVATE_KEY="$(jq -r .private_key "$OWNER_CREDS")" "$RECOVERY_BIN" sign-nep413 \
  --message "$AK_MSG" --recipient outlayer-agent-key --nonce-base64 "$AK_NONCE" | jq -r .signature)
node "$AGENT_JS" seed "$OWNER" "$WID0" "$AK_SIG" "$WORK/owner_side.seed"
AK_SIG2=$(CUSTOMER_RECOVERY_PRIVATE_KEY="$(jq -r .private_key "$OWNER_CREDS")" "$RECOVERY_BIN" sign-nep413 \
  --message "$AK_MSG" --recipient outlayer-agent-key --nonce-base64 "$AK_NONCE" | jq -r .signature)
[[ "$AK_SIG" == "$AK_SIG2" ]] && pass "S1 the owner's signature repeats: the agent's key needs no backup" || fail "S1 the owner's signature differs on a second signing"
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
SEALED=$(AGENT_SEED_FILE="$WORK/owner_side.seed" node "$AGENT_JS" seal "$RPUB" "$WID0")
owner_page POST "$(jq -nc --arg a "$OWNER.evil.testnet" --arg s "$SEALED" '{account_id:$a, sealed_agent_key:$s}')"
[[ "$HTTP" == 400 ]] && pass "S3 a setup naming an account outside the owner's: 400" || fail "S3 an outside account answered $HTTP $(why)"
owner_page POST "$(jq -nc --arg a "$AGENT_ACC" --arg s "$SEALED" '{account_id:$a, sealed_agent_key:$s}')"
if [[ "$HTTP" == 200 && "$(jq -c '[.account_id, .agent_public_key]' <<<"$BODY")" == "$(jq -nc --arg a "$AGENT_ACC" --arg k "$AGENT_PUB" '[$a,$k]')" ]]; then
  pass "S1 the owner finished the setup: the coordinator read the pair from the chain"
else fail "S1 the owner's finish: $HTTP $(why)"; fi
owner_page GET
[[ "$HTTP" == 404 ]] && pass "S3 the setup token is spent" || fail "S3 the spent token answered $HTTP"

# The agent collects its key.
api_wk "$WK0" GET /wallet/v1/contract/setup >/dev/null
if [[ "$HTTP" == 200 && "$(jq -c '[.done, .account_id, .agent_public_key]' <<<"$BODY")" == "$(jq -nc --arg a "$AGENT_ACC" --arg k "$AGENT_PUB" '[true,$a,$k]')" ]]; then
  node "$AGENT_JS" open "$WORK/setup.x" "$WID0" "$(jq -r .sealed_agent_key <<<"$BODY")" "$WORK/agent.seed"
  [[ "$(AGENT_SEED_FILE="$WORK/agent.seed" node "$AGENT_JS" pub)" == "$AGENT_PUB" ]] \
    && pass "S1 the agent collected and opened its key: the contract's agent key" || fail "S1 the key the agent opened is not the contract's"
else fail "S1 the agent's collect: $HTTP $(why)"; fi
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
  node "$AGENT_JS" seed "$OWNER" "$WID1" "$S4_SIG" "$WORK/s4.seed"; unset S4_SIG
  A1=$(AGENT_SEED_FILE="$WORK/s4.seed" node "$AGENT_JS" pub)
  [[ "$A1" != "$AGENT_PUB" ]] && pass "S4 each wallet has its own agent key" || fail "S4 the same agent key for two wallets"
  OUT=$(near contract deploy "$OWNER" use-global-hash "$BUILD" with-init-call w_init \
    json-args "$(jq -nc --arg p "$A1$TEE1" '{public_key:$p}')" prepaid-gas '10 Tgas' attached-deposit '1 yoctoNEAR' \
    network-config "$NETWORK" sign-with-keychain send 2>&1) || fail "S4 the install on $OWNER: $(near_why "$OUT")"
  owner_page POST "$(jq -nc --arg a "$OWNER" --arg s "$(AGENT_SEED_FILE="$WORK/s4.seed" node "$AGENT_JS" seal "$RPUB" "$WID1")" '{account_id:$a, sealed_agent_key:$s}')"
  [[ "$HTTP" == 200 && "$(jq -r .account_id <<<"$BODY")" == "$OWNER" ]] && pass "S4 the owner's own account is the second wallet's contract" || fail "S4 finish: $HTTP $(why)"
  [[ "$(access_keys "$OWNER")" == "[\"$OWNER_PUB\"]" ]] && pass "S4 the owner's key stays on it" || fail "S4 keys on $OWNER: $(access_keys "$OWNER")"
  api_wk "$WK1" PUT /wallet/v1/contract "$(jq -nc --arg a "$AGENT_ACC" '{account_id:$a}')" >/dev/null
  [[ "$HTTP" == 400 ]] && grep -q 'was not set up for this wallet' <<<"$BODY" && pass "S3 the agent cannot name another wallet's contract: 400" \
    || fail "S3 another wallet's contract answered $HTTP $(why)"
  api_wk "$WK1" PUT /wallet/v1/contract "$(jq -nc --arg a "$PARENT" '{account_id:$a}')" >/dev/null
  if [[ "$HTTP" == 400 ]] && grep -q 'does not answer `w_public_key`' <<<"$BODY"; then pass "S3 an account with no wallet contract: 400"
  elif [[ "$HTTP" =~ ^4 ]]; then finding "S3 an account with no contract is refused ($HTTP), but with the RPC's words, not the setup's: $(why)"
  else fail "S3 an account with no contract answered $HTTP $(why)"; fi
  rm -f "$WORK/s4.seed"
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

verdict on_chain_custody
