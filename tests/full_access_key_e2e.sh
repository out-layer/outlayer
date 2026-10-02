#!/usr/bin/env bash
#
# An owner's signature counts only from a FULL-ACCESS key of the account
# (`shared_tee_helpers::signer_key`). A function-call key is held by whatever
# application the owner once logged into, and speaks for nobody.
#
#   F1  Bearer near: signed by a function-call key of PARENT → 401
#   F2  Bearer near: signed by PARENT's full-access key → 200 (control)
#   F3  POST /register with a NEAR proof by the function-call key → 400
#   F4  PUT /wallet/v1/api-key claimed with the function-call key → 400
#   F5  a secrets update signed by the function-call key → 403 "may only call functions"
#   F6  the same update signed by PARENT's full-access key is not refused for its key (control)
#   F7  a secrets update in PARENT's name signed by STRANGER's key → 403 "does not belong"
#   F8  Bearer near: for an implicit account not created yet, signed by its own key → 200
#   F9  a full-access key added a moment ago is the owner's at once: a secrets
#       update and a Bearer near: signed by it are not refused for the key
#       (both read the optimistic block)
#
# Votes are in approval_votes_e2e.sh (V1, V9). The suite adds a function-call
# key and, for F9, a full-access key to PARENT, and removes both on exit.
#
# Run:
#   PARENT=outlayer-alice.testnet STRANGER=outlayer-carol.testnet ./tests/full_access_key_e2e.sh --apply

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/hos_common.sh"

[[ "${1:-}" == "--apply" ]] || { warn "Dry run. Pass --apply."; exit 0; }

STRANGER="${STRANGER:-outlayer-carol.testnet}"
hos_require
command -v node >/dev/null || { echo "✗ missing node" >&2; exit 1; }
[[ -f "$HOME/.near-credentials/$NETWORK/$STRANGER.json" ]] || { echo "✗ creds missing for $STRANGER" >&2; exit 1; }
STRANGER_SK=$(jq -r .private_key "$HOME/.near-credentials/$NETWORK/$STRANGER.json")
STRANGER_PK=$(jq -r .public_key "$HOME/.near-credentials/$NETWORK/$STRANGER.json")
PARENT_PK=$(jq -r .public_key "$CREDS_DIR/$PARENT.json")

# raw <method> <path> <body> [header] — an unauthenticated call, or one with a header.
raw() {
  local out; out=$(mktemp -t fak.XXXXXX); throttle
  local -a args=(-sS -o "$out" -w '%{http_code}' -X "$1" "$COORDINATOR_URL$2" --max-time 60)
  [[ -n "${3:-}" ]] && args+=(-H 'Content-Type: application/json' --data-binary "$3")
  [[ -n "${4:-}" ]] && args+=(-H "$4")
  HTTP=$(curl "${args[@]}" 2>/dev/null); BODY=$(tr -d '\n' < "$out"); rm -f "$out"
}
bearer_with() { # bearer_with <private-key> <account> <seed>
  echo "Authorization: Bearer near:$(CUSTOMER_RECOVERY_PRIVATE_KEY="$1" "$RECOVERY_BIN" sign-bearer-near --account-id "$2" --seed "$3")"
}
# secrets_update <private-key> <public-key> — an append of FA_PROBE under PARENT/fa-probe.
secrets_update() {
  local msg nonce sig
  msg=$(printf 'Update Outlayer secrets for %s:default\nkeys:FA_PROBE' "$PARENT")
  nonce=$(head -c 32 /dev/urandom | base64 | tr -d '\n')
  sig=$(CUSTOMER_RECOVERY_PRIVATE_KEY="$1" "$RECOVERY_BIN" sign-nep413 --message "$msg" \
    --recipient "$CONTRACT_ID" --nonce-base64 "$nonce" | jq -r '.signature')
  raw POST /secrets/update_user_secrets "$(jq -nc --arg o "$PARENT" --arg m "$msg" --arg s "$sig" --arg pk "$2" \
    --arg n "$nonce" --arg r "$CONTRACT_ID" --arg p "$PARENT/fa-probe" \
    '{accessor:{type:"Project", project_id:$p}, profile:"default", owner:$o, mode:"append",
      secrets:{FA_PROBE:"x"}, generate_protected:[], signed_message:$m, signature:$s,
      public_key:$pk, nonce:$n, recipient:$r}')"
}
key_refusal() { grep -qiE "may only call functions|not a full-access key|does not belong|not a key of" <<<"$BODY"; }

# ── a function-call key on PARENT ───────────────────────────────────────────
FC=$(node "$HOS_LIB_DIR/ed25519_keypair.mjs"); FC_PK=$(jq -r .public_key <<<"$FC"); FC_SK=$(jq -r .private_key <<<"$FC")
FA_PK=""
drop_fc_key() {
  near --quiet account delete-keys "$PARENT" public-keys "$FC_PK" network-config "$NETWORK" \
    sign-with-keychain send >/dev/null 2>&1 || warn "could not remove the function-call key $FC_PK from $PARENT"
  if [[ -n "$FA_PK" ]]; then
    near --quiet account delete-keys "$PARENT" public-keys "$FA_PK" network-config "$NETWORK" \
      sign-with-keychain send >/dev/null 2>&1 || warn "could not remove the full-access key $FA_PK from $PARENT — remove it by hand"
  fi
}
log "setup: a function-call key on $PARENT"
near --quiet account add-key "$PARENT" grant-function-call-access --allowance '0.01 NEAR' \
  --contract-account-id "$CONTRACT_ID" --function-names '' use-manually-provided-public-key "$FC_PK" \
  network-config "$NETWORK" sign-with-keychain send >/dev/null 2>&1 \
  || { echo "✗ could not add a function-call key to $PARENT" >&2; exit 1; }
trap drop_fc_key EXIT
sleep 4
SEED="fak-$(date +%s)-$$"

log "F1 Bearer near: by the function-call key"
raw GET "/wallet/v1/address?chain=near" "" "$(bearer_with "$FC_SK" "$PARENT" "$SEED")"
assert_status "F1 refused" 401 && assert_msg "F1 names the full-access rule" "not a full-access key"

log "F2 Bearer near: by the full-access key"
raw GET "/wallet/v1/address?chain=near" "" "$(bearer_with "$PARENT_PRIVKEY" "$PARENT" "$SEED")"
assert_status "F2 accepted" 200

log "F3 POST /register with a proof by the function-call key"
TS=$(date +%s); MSG="register:$SEED-r:$TS"
SIG=$(CUSTOMER_RECOVERY_PRIVATE_KEY="$FC_SK" node "$HOS_LIB_DIR/ed25519_sign.mjs" "$MSG")
raw POST /register "$(jq -nc --arg a "$PARENT" --arg s "$SEED-r" --arg pk "$FC_PK" --arg m "$MSG" --arg g "$SIG" \
  '{account_id:$a, seed:$s, pubkey:$pk, message:$m, signature:$g}')"
assert_status "F3 refused" 400 && assert_msg "F3 names the full-access rule" "not a full-access key"

log "F4 PUT /wallet/v1/api-key claimed with the function-call key"
SUB_KEY="wk_$(head -c 32 /dev/urandom | xxd -p -c 64)"
CLAIM=$(CUSTOMER_RECOVERY_PRIVATE_KEY="$FC_SK" "$RECOVERY_BIN" sign-api-key-claim --account-id "$PARENT" --seed "$SEED-k" --sub-key "$SUB_KEY")
raw PUT /wallet/v1/api-key "$CLAIM"
assert_status "F4 refused" 400 && assert_msg "F4 names the full-access rule" "not a full-access key"

log "F5 a secrets update signed by the function-call key"
secrets_update "$FC_SK" "$FC_PK"
assert_status "F5 refused" 403 && assert_msg "F5 says the key may only call functions" "may only call functions"

log "F6 the same update signed by the full-access key"
secrets_update "$PARENT_PRIVKEY" "$PARENT_PK"
if key_refusal; then fail "F6 the owner's full-access key was refused: HTTP $HTTP $(msg_of)"
else pass "F6 not refused for its key (HTTP $HTTP)"; fi

log "F7 a secrets update in $PARENT's name signed by $STRANGER's key"
secrets_update "$STRANGER_SK" "$STRANGER_PK"
assert_status "F7 refused" 403 && assert_msg "F7 says the key is not the owner's" "does not belong"

log "F8 Bearer near: for an implicit account not created yet"
IMP=$(node "$HOS_LIB_DIR/ed25519_keypair.mjs"); IMP_SK=$(jq -r .private_key <<<"$IMP"); IMP_PK=$(jq -r .public_key <<<"$IMP")
IMP_ACCOUNT=$(node -e '
const B58="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";let n=0n;
for (const c of process.argv[1].slice(8)) n=n*58n+BigInt(B58.indexOf(c));
process.stdout.write(n.toString(16).padStart(64,"0"));' "$IMP_PK")
raw GET "/wallet/v1/address?chain=near" "" "$(bearer_with "$IMP_SK" "$IMP_ACCOUNT" "$SEED-i")"
assert_status "F8 the key of an implicit account not made yet speaks for it" 200

log "F9 a full-access key added a moment ago"
FA=$(node "$HOS_LIB_DIR/ed25519_keypair.mjs"); FA_SK=$(jq -r .private_key <<<"$FA")
if near --quiet account add-key "$PARENT" grant-full-access use-manually-provided-public-key "$(jq -r .public_key <<<"$FA")" \
     network-config "$NETWORK" sign-with-keychain send >/dev/null 2>&1; then
  FA_PK=$(jq -r .public_key <<<"$FA")
  secrets_update "$FA_SK" "$FA_PK"
  if key_refusal; then fail "F9 the new full-access key was refused for the secrets update: HTTP $HTTP $(msg_of)"
  else pass "F9 the new full-access key signs a secrets update at once (HTTP $HTTP)"; fi
  raw GET "/wallet/v1/address?chain=near" "" "$(bearer_with "$FA_SK" "$PARENT" "$SEED-f")"
  assert_status "F9 the new full-access key signs Bearer near: at once" 200
else
  fail "F9 could not add a full-access key to $PARENT"
fi

verdict "full-access keys"
