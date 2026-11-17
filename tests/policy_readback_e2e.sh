#!/usr/bin/env bash
# GET /wallet/v1/policy answers the policy the chain holds NOW, live.
#
# The coordinator keeps a decrypted copy of each wallet's policy
# (wallet_accounts.policy_json) beside the sha256 of the ciphertext it was
# decrypted from (policy_ciphertext_sha256). A read holds the copy against the
# chain's record and has the keystore decrypt again when the copy is not of it.
# Each probe below puts the copy out of step with the chain — the state a chain
# event that never reached the coordinator leaves behind — and judges the read:
#
#   F1  a policy stored twice in a row reads back as the second one, with its
#       version
#   F2  a copy of an earlier policy is replaced by the read, in the answer and
#       in the row
#   F3  `frozen` is the chain's, whatever the coordinator's column says
#   F4  a policy deleted on chain reads as `policy: none` although a copy is
#       still stored, and the read clears the copy
#   F5  a policy stored again after the delete reads back with version 1 and
#       its own rules — a version alone never names the rules
#   F6  a read that decrypts and the read after it, served from the copy,
#       answer the same TEXT: the keys of a freshly decrypted policy are in the
#       order the stored copy has (clients compare readback byte for byte)
#
# F2–F4 write the out-of-step state into the coordinator's row themselves, so
# they do not depend on how fast the worker relays an event.
#
# Required env:
#   PARENT     NEAR account that owns the wallet's policy (key in the legacy keychain)
#   PSQL_CMD   the coordinator's testnet DB, one statement
#
# Run:
#   PARENT=outlayer-alice.testnet PSQL_CMD=… ./tests/policy_readback_e2e.sh --apply

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/hos_common.sh"
source "$HOS_LIB_DIR/near_sign.sh"   # near_why

[[ "${1:-}" == "--apply" ]] || { warn "Dry-run. Pass --apply: stores, freezes and deletes one wallet policy on $NETWORK."; exit 0; }
hos_require
sql_alive || { echo "✗ PSQL_CMD required and answering: the probes put the coordinator's copy out of step" >&2; exit 1; }

SEED="readback-$(date +%s)-$$"
read -r WID _ADDR < <(wallet_address "$SEED") || true
[[ -n "${WID:-}" ]] || { echo "✗ no wallet for seed $SEED" >&2; exit 1; }
note "wallet $WID (seed $SEED), owner $PARENT"

types_of() { jq -c '.rules.transaction_types // "absent"' <<<"${1:-$BODY}" 2>/dev/null; }
copy_types() { sql "SELECT COALESCE((policy_json->'rules'->'transaction_types')::text, 'NULL') FROM wallet_accounts WHERE wallet_id = '$WID'" | tr -d ' '; }
copy_digest() { sql "SELECT COALESCE(policy_ciphertext_sha256, 'NULL') FROM wallet_accounts WHERE wallet_id = '$WID'"; }
# chain_digest — sha256 of the ciphertext a final block holds for this wallet;
# empty when the chain did not say. A copy is OF the chain's policy when its
# digest is this, not merely when it looks like a digest.
chain_digest() {
  local enc
  enc=$(near_view "$CONTRACT_ID" get_wallet_policy "$(jq -nc --arg k "$WALLET_PUBKEY" '{wallet_pubkey:$k}')" | jq -r '.encrypted_data // empty' 2>/dev/null)
  [[ -n "$enc" ]] && printf '%s' "$enc" | shasum -a 256 | cut -d' ' -f1
}
frozen_col() { sql "SELECT frozen::text FROM wallet_accounts WHERE wallet_id = '$WID'"; }
chain_call() { # chain_call <method> — a controller call keyed on the wallet's pubkey
  local out
  out=$(near_tty "near contract call-function as-transaction $CONTRACT_ID $1 \
    json-args '$(jq -nc --arg k "$WALLET_PUBKEY" '{wallet_pubkey:$k}')' prepaid-gas '30.0 Tgas' attached-deposit '0 NEAR' \
    sign-as $PARENT network-config $NETWORK sign-with-keychain send" 2>&1) || { warn "$1 failed: $(near_why "$out")"; return 1; }
}
# wait_copy <expected transaction_types json> — the worker's sync of the last
# chain write has landed in the coordinator's row.
wait_copy() {
  local i
  for i in $(seq 1 30); do [[ "$(copy_types)" == "$1" ]] && return 0; sleep 4; done
  return 1
}

# ── F1 ───────────────────────────────────────────────────────────────────────
log "F1  two policy writes in a row read back as the second"
store_policy "$SEED" "$WID" '{"rules":{"transaction_types":["transfer"]}}' || { fail "F1 fixture: policy v1 not stored"; verdict policy_readback; exit 1; }
api "$SEED" GET /wallet/v1/policy >/dev/null
if [[ "$HTTP" == 200 && "$(types_of)" == '["transfer"]' && "$(jq -r '.version' <<<"$BODY")" == 1 ]]; then
  pass "F1a the first policy reads back at once: transfer, version 1"
else fail "F1a first readback: HTTP $HTTP types=$(types_of) version=$(jq -r '.version' <<<"$BODY")"; fi
store_policy "$SEED" "$WID" '{"rules":{"transaction_types":["call"]}}' || { fail "F1 fixture: policy v2 not stored"; verdict policy_readback; exit 1; }
api "$SEED" GET /wallet/v1/policy >/dev/null
if [[ "$HTTP" == 200 && "$(types_of)" == '["call"]' && "$(jq -r '.version' <<<"$BODY")" == 2 ]]; then
  pass "F1b the edit reads back at once: call, version 2"
else fail "F1b readback after the edit: HTTP $HTTP types=$(types_of) version=$(jq -r '.version' <<<"$BODY") — rules and version are not of one record"; fi

# ── F2 ───────────────────────────────────────────────────────────────────────
log "F2  a copy of an earlier policy is replaced by the read"
# The worker's sync of v2 may still be on its way: F1b's own read has already
# put v2 in the row, so the row cannot say whether the event has landed. An
# event lands once, so the probe runs twice — a late event can restore the row
# under one round only, and the other judges the read alone.
for round in 1 2; do
  sql "UPDATE wallet_accounts SET policy_json = jsonb_set(policy_json, '{rules,transaction_types}', '[\"stale\"]') WHERE wallet_id = '$WID'" >/dev/null
  sql "UPDATE wallet_accounts SET policy_ciphertext_sha256 = 'an-earlier-ciphertext' WHERE wallet_id = '$WID'" >/dev/null
  if [[ "$(copy_types)" != '["stale"]' || "$(copy_digest)" != an-earlier-ciphertext ]]; then
    fail "F2 round $round fixture: the row was not put out of step (types=$(copy_types))"
    continue
  fi
  api "$SEED" GET /wallet/v1/policy >/dev/null
  if [[ "$HTTP" == 200 && "$(types_of)" == '["call"]' && "$(jq -r '.version' <<<"$BODY")" == 2 ]]; then
    pass "F2a round $round: the read answers the chain's policy over a copy of an earlier one"
  else fail "F2a round $round: HTTP $HTTP types=$(types_of): the read answered the out-of-step copy"; fi
  CD=$(chain_digest)
  if [[ "$(copy_types)" == '["call"]' && -n "$CD" && "$(copy_digest)" == "$CD" ]]; then
    pass "F2b round $round: the row holds the chain's policy and the digest of its ciphertext"
  else fail "F2b round $round: the row after the read: types=$(copy_types) digest=$(copy_digest | head -c 16)… chain=$(head -c 16 <<<"$CD")…"; fi
done

# ── F3 ───────────────────────────────────────────────────────────────────────
log "F3  frozen is the chain's"
if chain_call freeze_wallet; then
  sleep 4
  for _ in $(seq 1 20); do [[ "$(sql "SELECT frozen::text FROM wallet_accounts WHERE wallet_id = '$WID'")" == true ]] && break; sleep 4; done
  sql "UPDATE wallet_accounts SET frozen = FALSE WHERE wallet_id = '$WID'" >/dev/null
  [[ "$(frozen_col)" == false ]] || fail "F3a fixture: the column was not set to false"
  api "$SEED" GET /wallet/v1/policy >/dev/null
  [[ "$HTTP" == 200 && "$(bool_of frozen)" == true ]] \
    && pass "F3a a frozen wallet reads frozen although the coordinator's column says otherwise" \
    || fail "F3a HTTP $HTTP frozen=$(bool_of frozen) on a wallet frozen on chain"
  if chain_call unfreeze_wallet; then
    sleep 4
    for _ in $(seq 1 20); do [[ "$(sql "SELECT frozen::text FROM wallet_accounts WHERE wallet_id = '$WID'")" == false ]] && break; sleep 4; done
    sql "UPDATE wallet_accounts SET frozen = TRUE WHERE wallet_id = '$WID'" >/dev/null
    [[ "$(frozen_col)" == true ]] || fail "F3b fixture: the column was not set to true"
    api "$SEED" GET /wallet/v1/policy >/dev/null
    [[ "$HTTP" == 200 && "$(bool_of frozen)" == false ]] \
      && pass "F3b a thawed wallet reads thawed although the coordinator's column says otherwise" \
      || fail "F3b HTTP $HTTP frozen=$(bool_of frozen) on a wallet thawed on chain"
    sql "UPDATE wallet_accounts SET frozen = FALSE WHERE wallet_id = '$WID'" >/dev/null
  else fail "F3 fixture: unfreeze_wallet failed — the wallet is left frozen, F4 cannot delete"; fi
else skip "F3: freeze_wallet did not go through"; fi

# ── F4 ───────────────────────────────────────────────────────────────────────
log "F4  a policy deleted on chain reads as none"
if chain_call delete_wallet_policy; then
  sleep 4
  wait_copy NULL || warn "the worker's sync of the delete was not seen in the row; F4 judges the read alone"
  sql "UPDATE wallet_accounts SET policy_json = '{\"rules\":{\"transaction_types\":[\"ghost\"]}}'::jsonb WHERE wallet_id = '$WID'" >/dev/null
  sql "UPDATE wallet_accounts SET policy_ciphertext_sha256 = 'a-deleted-ciphertext' WHERE wallet_id = '$WID'" >/dev/null
  [[ "$(copy_types)" == '["ghost"]' && "$(copy_digest)" == a-deleted-ciphertext ]] || fail "F4 fixture: the copy of the deleted policy was not put in the row"
  api "$SEED" GET /wallet/v1/policy >/dev/null
  if [[ "$HTTP" == 200 && "$(jq -r '.policy // "absent"' <<<"$BODY")" == none && "$(types_of)" == '"absent"' ]]; then
    pass "F4a no policy on chain reads as none over a copy still stored"
  else fail "F4a HTTP $HTTP policy=$(jq -r '.policy // "absent"' <<<"$BODY") types=$(types_of): a policy the chain no longer holds was answered"; fi
  [[ "$(copy_types)" == NULL && "$(copy_digest)" == NULL ]] \
    && pass "F4b the read cleared the copy and its digest" \
    || fail "F4b the row after the read: types=$(copy_types) digest=$(copy_digest | head -c 24)"
else skip "F4: delete_wallet_policy did not go through"; fi

# ── F5 ───────────────────────────────────────────────────────────────────────
# Its keys are written in an order a `jsonb` copy does not keep (shorter keys
# first there): F6 sees the difference if a read answers them as written.
RECREATED=$(jq -nc --arg p "$PARENT" '{rules:{transaction_types:["transfer","delete"], limits:{per_transaction:{native:"1000000000000000000000000"}, daily:{native:"2000000000000000000000000"}}, addresses:{mode:"whitelist", list:[$p]}}}')
log "F5  a policy stored again after the delete"
if store_policy "$SEED" "$WID" "$RECREATED"; then
  api "$SEED" GET /wallet/v1/policy >/dev/null
  if [[ "$HTTP" == 200 && "$(jq -r '.version' <<<"$BODY")" == 1 \
        && "$(jq -S -c '.rules' <<<"$BODY")" == "$(jq -S -c '.rules' <<<"$RECREATED")" ]]; then
    pass "F5 version 1 again, with the new rules"
  else fail "F5 HTTP $HTTP version=$(jq -r '.version' <<<"$BODY") rules=$(jq -S -c '.rules' <<<"$BODY" | head -c 200)"; fi

  # ── F6 ─────────────────────────────────────────────────────────────────────
  log "F6  a decrypting read and a read from the copy answer the same text"
  wait_copy '["transfer","delete"]' || warn "the worker's sync of the new policy was not seen in the row"
  sql "UPDATE wallet_accounts SET policy_ciphertext_sha256 = 'an-earlier-ciphertext' WHERE wallet_id = '$WID'" >/dev/null
  if [[ "$(copy_digest)" != an-earlier-ciphertext ]]; then
    fail "F6 fixture: the copy's digest was not put out of step"
  else
    api "$SEED" GET /wallet/v1/policy >/dev/null; FIRST=$(jq -c '{rules, approval, capabilities}' <<<"$BODY"); H1=$HTTP
    CD=$(chain_digest)
    [[ -n "$CD" && "$(copy_digest)" == "$CD" ]] && pass "F6a the first read decrypted and stored the copy, under the chain's digest" \
      || fail "F6a the first read did not store the copy of the chain's ciphertext (digest $(copy_digest | head -c 16)… chain $(head -c 16 <<<"$CD")…)"
    api "$SEED" GET /wallet/v1/policy >/dev/null; SECOND=$(jq -c '{rules, approval, capabilities}' <<<"$BODY")
    if [[ "$H1" == 200 && "$HTTP" == 200 && "$FIRST" == "$SECOND" ]]; then
      pass "F6b both reads answer the same text: $(head -c 120 <<<"$FIRST")"
    else fail "F6b the texts differ (HTTP $H1/$HTTP): first=$(head -c 160 <<<"$FIRST") second=$(head -c 160 <<<"$SECOND")"; fi
  fi
else fail "F5 fixture: the policy was not stored again"; fi

verdict policy_readback
