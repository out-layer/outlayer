#!/usr/bin/env bash
# The intents signing rules, live on TESTNET, against the deployed keystore called
# directly. NEAR Intents are mainnet-only, and the coordinator answers 503 on every
# intents route of testnet before anything is built — but every decision the
# KEYSTORE makes about what it signs needs no intents.near, so it is judged here on
# the build actually running in the TEE.
#
#   A  Trusted artifacts — a swap of 100 units, no policy (the keystore's stand-in):
#      A0 the swap's own transfer → signed (control)
#      A1 an add_public_key intent → 403 trusted op artifact refused
#      A2 a key beside the transfer → 403
#      A3 101 units → 403 (more than the op)
#      A4 another signer → 403
#      A5 `intents` twice, the harmless copy last → 403
#      A6 another token → 403
#      A7 a NEP-413 recipient that is not an intents verifier → 403
#   B  The other doors to the wallet's intents account:
#      B1 raw signing with the NEAR key, no policy → 403
#      B2 raw signing on solana → signed (control)
#      B3 a cross-chain withdraw of native NEAR, its transfer in wNEAR → signed
#      B4 an Op::Call to intents.near (add_public_key) → 403 intents_call — the
#         keystore's own fence, not the coordinator's
#      B5 the gate-only cross_chain_deposit call → 403, never signed
#   C  The storage deposit paid from intents wNEAR (the keystore reads the token):
#      C1 the minimum for a fresh account → the storage_deposit intent, signed
#      C2 below the minimum / C3 above the 0.00125 NEAR ceiling / C4 an account
#         already registered / C5 zero → refused
#   D  A Trusted op on a multisig wallet — a policy on chain (threshold 1, approver
#      outlayer-bob, payment_check allowed), one payment check of 1000 units:
#      D1 no votes → 403   D2 the approver's vote → signed
#      D3 a non-approver's vote → 403   D4 a vote over another op → 403
#      D5 the approver's vote with an add_public_key artifact → 403
#
# Not here: the jwt challenge (the keystore reads intents.near.current_salt(),
# which testnet has not), and everything the COORDINATOR decides — those are unit
# and database tests, live on mainnet only.
#
# Secrets: the keystore URL and token come from scripts/.env
# (SMOKE_KEYSTORE_URL_TESTNET, SMOKE_KEYSTORE_TOKEN_TESTNET) or the environment,
# and neither is printed — only whether each is set. The URL moves with every
# keystore redeploy: take `KEYSTORE_BASE_URLS` from the API node's
# coordinator.env (see .idea/TESTING-WITH-ADMIN.md §7a). The token reaches curl
# through stdin; the approver's key reaches customer-recovery through the
# environment. Signatures made here are by testnet wallets and are worthless on
# mainnet; nothing is submitted anywhere.
#
# Spends one policy store (0.1 NEAR) from PARENT for D.
#
#   PARENT=outlayer-alice.testnet ./tests/intents_keystore_e2e.sh --apply
set -uo pipefail
source "$(dirname "$0")/lib/hos_common.sh"
[[ "${1:-}" == "--apply" ]] || { sed -n 2,48p "$0"; exit 0; }
hos_require
[[ -f "$REPO_ROOT/scripts/.env" ]] && { set -a; source "$REPO_ROOT/scripts/.env"; set +a; }
KEYSTORE_URL="${KEYSTORE_URL:-${SMOKE_KEYSTORE_URL_TESTNET:-}}"
KEYSTORE_TOKEN="${KEYSTORE_TOKEN:-${SMOKE_KEYSTORE_TOKEN_TESTNET:-}}"
note "keystore URL: $([[ -n "$KEYSTORE_URL" ]] && echo set || echo MISSING), token: $([[ -n "$KEYSTORE_TOKEN" ]] && echo "set (${#KEYSTORE_TOKEN} chars)" || echo MISSING)"
[[ -n "$KEYSTORE_URL" && -n "$KEYSTORE_TOKEN" ]] || { echo "✗ set SMOKE_KEYSTORE_URL_TESTNET and SMOKE_KEYSTORE_TOKEN_TESTNET in scripts/.env" >&2; exit 1; }

# ks <path> <json> → HTTP, BODY. The token through stdin, never argv; curl's
# own errors are dropped, since they quote the URL.
ks() {
  local out
  throttle
  out=$(printf 'Authorization: Bearer %s\n' "$KEYSTORE_TOKEN" | curl -s -m 30 -w '\n%{http_code}' \
    -X POST "$KEYSTORE_URL$1" -H @- -H 'Content-Type: application/json' -d "$2" 2>/dev/null)
  HTTP=$(tail -n1 <<<"$out"); BODY=$(sed '$d' <<<"$out")
}
refused() { # <desc> [text the refusal must carry]
  if [[ "$HTTP" =~ ^4 && ( -z "${2:-}" || "$BODY" == *"$2"* ) ]]; then
    pass "$1 — $HTTP: $(jq -r '.error // .message // .' <<<"$BODY" 2>/dev/null | head -c 100)"
  else
    fail "$1 — expected a refusal${2:+ naming '$2'}, got HTTP $HTTP: $(head -c 200 <<<"$BODY")"
  fi
}
signed() { # <desc> <field the signature is in>
  [[ "$HTTP" == 200 && -n "$(jq -r ".${2} // empty" <<<"$BODY")" ]] && pass "$1" \
    || fail "$1 — expected a signature, got HTTP $HTTP: $(head -c 200 <<<"$BODY")"
}
nonce() { head -c 32 /dev/urandom | base64 | tr -d '\n'; }
DEADLINE=$(date -u -v+5M +%Y-%m-%dT%H:%M:%S.000Z 2>/dev/null || date -u -d '+5 min' +%Y-%m-%dT%H:%M:%S.000Z)
message() { jq -nc --arg s "$2" --arg d "$DEADLINE" --argjson i "$1" '{signer_id:$s, deadline:$d, intents:$i}'; }
transfer() { jq -nc --arg r "$2" --arg t "$3" --arg a "$1" '{intent:"transfer", receiver_id:$r, tokens:{($t):$a}}'; }
ADDKEY='{"intent":"add_public_key","public_key":"ed25519:DcA2MzgpJbrUATQLLceocVckhhAqrkingax4oJ9kZ847"}'

# ── preflight: the keystore answers, and takes this token ────────────────────
W="$(uuidgen | tr 'A-Z' 'a-z')"
ks /wallet/derive-address "$(jq -nc --arg w "$W" '{wallet_id:$w, chain:"near"}')"
case "$HTTP" in
  200) SIGNER=$(jq -r '.address // empty' <<<"$BODY") ;;
  000) echo "✗ the keystore does not answer at SMOKE_KEYSTORE_URL_TESTNET — it moves with every redeploy; take KEYSTORE_BASE_URLS from the API node's coordinator.env" >&2; exit 1 ;;
  401|403) echo "✗ the keystore refused the token (HTTP $HTTP) — its hash must be in the keystore's allowed_coordinator_token_hashes" >&2; exit 1 ;;
  *) echo "✗ derive-address answered HTTP $HTTP: $(head -c 200 <<<"$BODY")" >&2; exit 1 ;;
esac
[[ -n "${SIGNER:-}" ]] || { echo "✗ derive-address named no address" >&2; exit 1; }
note "throwaway wallet ${SIGNER:0:12}…"

# ── A: Trusted artifacts ─────────────────────────────────────────────────────
TOKEN="nep141:usdc.fakes.testnet"
SWAP=$(jq -nc --arg t "$TOKEN" '{kind:"swap", token_in:$t, amount_in:"100", token_out:"nep141:wrap.testnet", min_out:"1"}')
trusted() { # trusted <op> <message> [recipient]
  ks /wallet/sign "$(jq -nc --arg w "$W" --argjson op "$1" --arg m "$2" --arg r "${3:-intents.near}" --arg n "$(nonce)" \
    '{wallet_id:$w, op:$op, artifact:{message:$m, nonce_base64:$n, recipient:$r}}')"
}
OWN=$(transfer 100 dep.testnet "$TOKEN")
log "A Trusted artifacts"
trusted "$SWAP" "$(message "[$OWN]" "$SIGNER")";                            signed "A0 the swap's own transfer is signed" signature_base58
trusted "$SWAP" "$(message "[$ADDKEY]" "$SIGNER")";                         refused "A1 an added key is never signed" "trusted op artifact refused"
trusted "$SWAP" "$(message "[$OWN,$ADDKEY]" "$SIGNER")";                    refused "A2 a key beside the transfer" "trusted op artifact refused"
trusted "$SWAP" "$(message "[$(transfer 101 dep.testnet "$TOKEN")]" "$SIGNER")"; refused "A3 more than the op" "trusted op artifact refused"
trusted "$SWAP" "$(message "[$OWN]" someone-else.testnet)";                 refused "A4 another signer" "trusted op artifact refused"
trusted "$SWAP" "{\"signer_id\":\"$SIGNER\",\"deadline\":\"$DEADLINE\",\"intents\":[$ADDKEY],\"intents\":[$OWN]}"
refused "A5 a key twice in the message" "trusted op artifact refused"
trusted "$SWAP" "$(message "[$(transfer 100 dep.testnet nep141:btc.fakes.testnet)]" "$SIGNER")"; refused "A6 another token" "trusted op artifact refused"
trusted "$SWAP" "$(message "[$OWN]" "$SIGNER")" attacker.testnet;          refused "A7 the NEP-413 recipient is pinned" "not an intents verifier"

# ── B: the other doors ───────────────────────────────────────────────────────
log "B the other doors to the intents account"
raw() {
  local bytes hash
  bytes=$(nonce); hash=$(printf '%s' "$bytes" | base64 -d | shasum -a 256 | cut -d' ' -f1)
  ks /wallet/sign "$(jq -nc --arg w "$W" --arg c "$1" --arg h "$hash" --arg b "$bytes" \
    '{wallet_id:$w, op:{kind:"raw", chain:$c, payload_hash:$h}, artifact:{bytes_base64:$b}}')"
}
raw near;   refused "B1 no raw signature by the NEAR key without near listed" "raw_sign.chains"
raw solana; signed "B2 a raw solana signature (control)" signature_base64
CC=$(jq -nc '{kind:"cross_chain_withdraw", to:"0x0000000000000000000000000000000000000001", amount:"5", token:"native", chain:"eth"}')
trusted "$CC" "$(message "[$(transfer 5 dep.testnet nep141:wrap.near)]" "$SIGNER")"; signed "B3 native NEAR leaves as wNEAR" signature_base58
call_op() { jq -nc --arg m "$1" '{kind:"call", to:"intents.near", method:$m, args_base64:"e30=", gas:"30000000000000", deposit:"1"}'; }
ks /wallet/sign "$(jq -nc --arg w "$W" --argjson op "$(call_op add_public_key)" '{wallet_id:$w, op:$op}')"
refused "B4 the keystore fences a call to intents.near itself" "intents_call"
ks /wallet/sign "$(jq -nc --arg w "$W" --argjson op "$(call_op cross_chain_deposit)" '{wallet_id:$w, op:$op}')"
refused "B5 a gate-only call is never signed" "policy question, never a transaction"

# ── C: the storage deposit from intents ──────────────────────────────────────
log "C the storage deposit paid from intents wNEAR"
SD_TOKEN=usdc.fakes.testnet; MIN=1250000000000000000000; REGISTERED=outlayer-alice.testnet
sd() { ks /wallet/sign "$(jq -nc --arg w "$W" --arg c "$SD_TOKEN" --arg a "$1" --arg m "$2" \
  '{wallet_id:$w, op:{kind:"intents_storage_deposit", contract_id:$c, account_id:$a, amount:$m}}')"; }
FRESH=$(openssl rand -hex 32)
sd "$FRESH" "$MIN"
I=$(jq -r '.message // empty' <<<"$BODY" | jq -c '.intents[0] // empty' 2>/dev/null)
if [[ "$HTTP" == 200 && "$(jq -r .intent <<<"$I")" == storage_deposit && "$(jq -r .deposit_for_account_id <<<"$I")" == "$FRESH" \
      && "$(jq -r .amount <<<"$I")" == "$MIN" && "$(jq -r .contract_id <<<"$I")" == "$SD_TOKEN" ]]; then
  pass "C1 the minimum for a fresh account: the storage_deposit intent, signed"
else
  fail "C1 expected the storage_deposit intent signed, got HTTP $HTTP: $(head -c 200 <<<"$BODY")"
fi
sd "$FRESH" 1249999999999999999999; refused "C2 below the minimum" "is $MIN yoctoNEAR"
sd "$FRESH" 1250000000000000000001; refused "C3 above the ceiling" "above the"
sd "$REGISTERED" "$MIN";            refused "C4 an account already registered" "already registered"
sd "$FRESH" 0;                      refused "C5 zero" "pays nothing"

# ── D: a Trusted op on a multisig wallet ─────────────────────────────────────
log "D a payment check on a multisig wallet"
APPROVER=outlayer-bob.testnet; NOT_APPROVER=outlayer-carol.testnet
SEED_D="ikeys-$(date +%s)-$$"
read -r WID ADDR < <(wallet_address "$SEED_D")
if [[ -z "${WID:-}" ]] || ! store_policy "$SEED_D" "$WID" "$(jq -nc --arg a "$APPROVER" \
     '{rules:{}, approval:{threshold:{required:1}, approvers:[{id:$a}]}, capabilities:{payment_check:{allowed:true}}}')"; then
  fail "D the multisig wallet could not be set up; D1–D5 are unjudged"
else
  CHECK=$(jq -nc --arg t "nep141:usdc.near" '{kind:"payment_check", amount:"1000", token:$t}')
  OTHER=$(jq -nc --arg t "nep141:usdc.near" '{kind:"payment_check", amount:"999", token:$t}')
  hash_of() { jq -S -c . <<<"$1" | tr -d '\n' | shasum -a 256 | cut -d' ' -f1; }
  vote() { # vote <voter> <request_hash> → one ApproverSig
    local n sj; n=$(nonce)
    sj=$(CUSTOMER_RECOVERY_PRIVATE_KEY="$(jq -r .private_key "$HOME/.near-credentials/$NETWORK/$1.json")" "$RECOVERY_BIN" sign-nep413 \
      --message "approve:ikeys-probe:ed25519:$ADDR:$2" --recipient "$CONTRACT_ID" --nonce-base64 "$n")
    jq -nc --arg v "$1" --arg p "$(jq -r .public_key <<<"$sj")" --arg s "$(jq -r .signature <<<"$sj")" --arg n "$n" \
      '{approver_id:$v, public_key:$p, signature:$s, nonce:$n}'
  }
  check() { # check <intents-json> [vote]
    local info=null
    [[ -n "${2:-}" ]] && info=$(jq -nc --arg r "$CONTRACT_ID" --argjson a "$2" '{approval_id:"ikeys-probe", recipient:$r, approvals:[$a], rejections:[]}')
    ks /wallet/sign "$(jq -nc --arg w "$WID" --argjson op "$CHECK" --arg m "$(message "$1" "$ADDR")" --arg n "$(nonce)" --argjson ai "$info" \
      '{wallet_id:$w, op:$op, artifact:{message:$m, nonce_base64:$n, recipient:"intents.near"}} + (if $ai == null then {} else {approval_info:$ai} end)')"
  }
  FUND="[$(transfer 1000 check-key.testnet nep141:usdc.near)]"
  check "$FUND";                                                   refused "D1 no votes: the threshold is not met"
  check "$FUND" "$(vote "$APPROVER" "$(hash_of "$CHECK")")";       signed "D2 the approver's vote: signed" signature_base58
  check "$FUND" "$(vote "$NOT_APPROVER" "$(hash_of "$CHECK")")";   refused "D3 a non-approver's vote does not count"
  check "$FUND" "$(vote "$APPROVER" "$(hash_of "$OTHER")")";       refused "D4 a vote binds the request hash"
  check "[$ADDKEY]" "$(vote "$APPROVER" "$(hash_of "$CHECK")")";   refused "D5 an approval does not open an account-control artifact" "trusted op artifact refused"
fi

verdict "intents keystore"
