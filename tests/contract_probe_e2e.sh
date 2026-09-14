#!/usr/bin/env bash
#
# Probes the DEPLOYED contract for the class of bug where one logical value has
# more than one spelling — and for the refusals that are supposed to hold.
#
# Written after `freeze_wallet` / `unfreeze_wallet` turned out to look their
# entry up by the RAW key while everything is stored under the canonical one, so
# the same wallet key in upper case answered "Wallet policy not found". That is
# not a thing a unit test would have caught by itself: the contract accepted
# both spellings happily, and only the pair of them together is wrong.
#
# Every probe states what it expects BEFORE it runs, and reports the answer it
# got rather than a verdict computed from a second assumption. A probe that
# cannot arrange its precondition says SKIPPED, never passes by absence.
#
# Run (spends testnet NEAR — storage deposits, refunded by the cleanups):
#   CALLER=zavodil.testnet OTHER=zavodil2.testnet ./tests/contract_probe_e2e.sh --apply
#
# Read-only by default: prints the plan and exits.

set -uo pipefail

APPLY=false
[[ "${1:-}" == "--apply" ]] && APPLY=true

NETWORK="${NETWORK:-testnet}"
CONTRACT_ID="${CONTRACT_ID:-outlayer.testnet}"
CALLER="${CALLER:-}"
OTHER="${OTHER:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -z "${RPC_URL:-}" && -f "$SCRIPT_DIR/../.env" ]]; then
  RPC_URL=$(grep -E "^$(echo "$NETWORK" | tr '[:lower:]' '[:upper:]')_NEAR_RPC_URL=" "$SCRIPT_DIR/../.env" | cut -d= -f2-)
fi
# Otherwise lib/rpc.sh builds a keyed URL from FASTNEAR_API_KEY or near-cli's
# config, or warns and uses the unkeyed host.
source "$SCRIPT_DIR/lib/rpc.sh"

PASS=0; FAILED=0; FAILED_NAMES=()
log()  { printf '\n\033[36m▶ %s\033[0m\n' "$*" >&2; }
note() { printf '\033[35m• %s\033[0m\n' "$*" >&2; }
pass() { printf '\033[32m✓ %s\033[0m\n' "$*" >&2; PASS=$((PASS+1)); }
fail() { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; FAILED=$((FAILED+1)); FAILED_NAMES+=("$*"); }

# A view call. Answers the raw JSON the contract returned, or `null`.
view() {
  curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg c "$CONTRACT_ID" --arg m "$1" --arg a "$(printf '%s' "$2" | base64 | tr -d '\n')" \
      '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"call_function",finality:"final",account_id:$c,method_name:$m,args_base64:$a}}')" \
    | jq -r '.result.result | implode' 2>/dev/null || echo 'null'
}

# A change call. Keeps the WHOLE output in $OUT — a suppressed answer is how
# this suite has repeatedly blamed the product for a call that never happened.
OUT=""
call() { # call <signer> <method> <json-args> <deposit> [gas]
  OUT=$(near contract call-function as-transaction "$CONTRACT_ID" "$2" \
          json-args "$3" prepaid-gas "${5:-100.0 Tgas}" attached-deposit "$4" \
          sign-as "$1" network-config "$NETWORK" sign-with-keychain send 2>&1)
  grep -q "succeeded" <<<"$OUT"
}

# Did the last call fail FOR THE STATED REASON? A refusal that happens for
# another reason is not the refusal being tested.
refused_with() { grep -qi "$1" <<<"$OUT"; }

if [[ "$APPLY" != true ]]; then
  cat >&2 <<'PLAN'
  (dry-run) probes, in order:
    P1  a WASM hash in UPPER case is a different secret from the same hash in lower
    P2  a payment key at profile "01" is a second key for nonce 1
    P3  freeze/unfreeze follow the key's spelling rather than the key
    P4  a stranger cannot pause the contract
    P5  a stranger cannot delete somebody else's secret
    P6  a secret cannot be stored against a project that does not exist
  Pass --apply to run. Storage deposits are refunded by the cleanups.
PLAN
  exit 0
fi

[[ -n "$CALLER" ]] || { echo "CALLER=<account> is required" >&2; exit 1; }
[[ -n "$OTHER"  ]] || { echo "OTHER=<second account> is required" >&2; exit 1; }

# ── P1: one WASM hash, two spellings ─────────────────────────────────────────
#
# The contract checks a wasm hash is 64 hex characters and never says WHICH
# case. The worker computes it with `hex::encode`, which is lower — so a secret
# filed under an upper-case hash is one nothing will ever ask for.
log "P1 a WASM hash in UPPER case"

HASH_LOWER=$(printf 'probe-%s' "$(openssl rand -hex 6)" | shasum -a 256 | cut -d' ' -f1)
HASH_UPPER=$(printf '%s' "$HASH_LOWER" | tr 'a-f' 'A-F')

acc_upper=$(jq -nc --arg h "$HASH_UPPER" '{WasmHash:{hash:$h}}')
acc_lower=$(jq -nc --arg h "$HASH_LOWER" '{WasmHash:{hash:$h}}')

if call "$CALLER" store_secrets \
      "$(jq -nc --argjson a "$acc_upper" '{accessor:$a, profile:"probe", encrypted_secrets_base64:"cHJvYmU=", access:"AllowAll", vault_id:null}')" \
      '0.1 NEAR'; then
  pass "P1 the contract accepted an UPPER-case wasm hash"

  GOT_UPPER=$(view get_secrets "$(jq -nc --argjson a "$acc_upper" --arg o "$CALLER" '{accessor:$a, profile:"probe", owner:$o}')")
  GOT_LOWER=$(view get_secrets "$(jq -nc --argjson a "$acc_lower" --arg o "$CALLER" '{accessor:$a, profile:"probe", owner:$o}')")

  [[ "$GOT_UPPER" != "null" && -n "$GOT_UPPER" ]] \
    && pass "P1 it reads back under the SAME spelling" \
    || fail "P1 the secret is not readable under the spelling it was stored with"

  if [[ "$GOT_LOWER" == "null" || -z "$GOT_LOWER" ]]; then
    fail "P1 the same hash in lower case finds NOTHING — the worker computes it lower, so this secret is unreachable by the code it was left for"
  else
    pass "P1 the same hash in lower case finds the same secret — the accessor is canonical"
  fi

  call "$CALLER" delete_secrets \
    "$(jq -nc --argjson a "$acc_upper" '{accessor:$a, profile:"probe"}')" '0 NEAR' \
    && note "P1 cleaned up (deposit refunded)" \
    || note "P1 cleanup FAILED, 0.1 NEAR left staked: $(tail -c 200 <<<"$OUT")"
else
  note "P1 SKIPPED — the store was refused: $(tail -c 200 <<<"$OUT")"
fi

# ── P2: a payment key's profile IS its nonce, in one spelling ────────────────
#
# `delete_payment_key` looks the key up at `nonce.to_string()`, and the
# coordinator holds one row per (owner, nonce). The bug class is a key filed at
# "01" becoming a SECOND on-chain key for nonce 1 that neither of them can see.
# The contract's answer is `canonical_profile`: the padded spelling is rendered
# from the parsed number, so "01" and "1" are ONE slot. This probe asserts
# exactly that — and because the store now lands ON the canonical slot, it must
# know what sits there BEFORE it writes: the first guard here read the slot
# after the write and could only ever see its own bytes.
log "P2 a payment key at profile \"01\""

acc_pk='{"System":"PaymentKey"}'

PRE_ONE=$(view get_secrets "$(jq -nc --argjson a "$acc_pk" --arg o "$OTHER" '{accessor:$a, profile:"1", owner:$o}')")
if [[ "$PRE_ONE" != "null" && -n "$PRE_ONE" ]]; then
  note "P2 SKIPPED — $OTHER holds a real key at nonce 1, and a canonicalised store would overwrite it"
else
  NEXT_BEFORE=$(view get_next_payment_key_nonce "$(jq -nc --arg a "$OTHER" '{account_id:$a}')")

  if call "$OTHER" store_secrets \
        "$(jq -nc --argjson a "$acc_pk" '{accessor:$a, profile:"01", encrypted_secrets_base64:"cHJvYmU=", access:"AllowAll", vault_id:null}')" \
        '0.1 NEAR'; then
    GOT_ONE=$(view get_secrets "$(jq -nc --argjson a "$acc_pk" --arg o "$OTHER" '{accessor:$a, profile:"1", owner:$o}')")
    GOT_PAD=$(view get_secrets "$(jq -nc --argjson a "$acc_pk" --arg o "$OTHER" '{accessor:$a, profile:"01", owner:$o}')")
    NEXT_AFTER=$(view get_next_payment_key_nonce "$(jq -nc --arg a "$OTHER" '{account_id:$a}')")

    if [[ "$GOT_ONE" != "null" && -n "$GOT_ONE" && "$GOT_ONE" == "$GOT_PAD" ]]; then
      pass "P2 the padded spelling lands in the canonical slot — one nonce, one slot, both spellings read it"
    else
      fail "P2 two slots for one nonce: \"1\" → $(head -c 24 <<<"$GOT_ONE") vs \"01\" → $(head -c 24 <<<"$GOT_PAD")"
    fi
    note "P2 get_next_payment_key_nonce: $NEXT_BEFORE → $NEXT_AFTER"

    # The canonical door must be able to remove what a padded store created —
    # this is the half that failed live before `canonical_profile` existed.
    if call "$OTHER" delete_payment_key "$(jq -nc '{nonce:1}')" '1 yoctoNEAR'; then
      pass "P2 delete_payment_key(1) reaches what the padded store created (deposit refunded)"
    else
      fail "P2 delete_payment_key(1) cannot see the padded key: $(tail -c 160 <<<"$OUT")"
      call "$OTHER" delete_secrets \
        "$(jq -nc --argjson a "$acc_pk" '{accessor:$a, profile:"01"}')" '0 NEAR' \
        && note "P2 cleaned up through delete_secrets (deposit refunded)" \
        || note "P2 cleanup FAILED, 0.1 NEAR left staked: $(tail -c 200 <<<"$OUT")"
    fi
  else
    if refused_with "nonce"; then
      pass "P2 a zero-padded nonce is refused outright: $(grep -o 'Payment key[^"]*' <<<"$OUT" | head -1)"
    else
      note "P2 INCONCLUSIVE — refused for another reason: $(tail -c 200 <<<"$OUT")"
    fi
  fi
fi

# ── P3: freeze and unfreeze, by spelling ─────────────────────────────────────
#
# Needs a policy entry, and storing one needs a wallet signature — which only
# the keystore can make. So this probe READS an existing policy rather than
# arranging one: pass POLICY_PUBKEY for a wallet whose policy CALLER controls.
log "P3 freeze/unfreeze and the key's spelling"

POLICY_PUBKEY="${POLICY_PUBKEY:-}"
if [[ -z "$POLICY_PUBKEY" ]]; then
  note "P3 SKIPPED — set POLICY_PUBKEY to a wallet key whose policy $CALLER controls"
else
  SHOUTED="ed25519:$(printf '%s' "${POLICY_PUBKEY#ed25519:}" | tr 'a-f' 'A-F')"
  HAS=$(view has_wallet_policy "$(jq -nc --arg k "$POLICY_PUBKEY" '{wallet_pubkey:$k}')")
  if [[ "$HAS" != "true" ]]; then
    note "P3 SKIPPED — $CONTRACT_ID holds no policy for $POLICY_PUBKEY"
  else
    if call "$CALLER" freeze_wallet "$(jq -nc --arg k "$SHOUTED" '{wallet_pubkey:$k}')" '0 NEAR'; then
      pass "P3 the shouted key froze the same wallet — freeze follows the KEY"
      call "$CALLER" unfreeze_wallet "$(jq -nc --arg k "$SHOUTED" '{wallet_pubkey:$k}')" '0 NEAR' \
        && pass "P3 …and thawed it again" \
        || fail "P3 froze but could NOT thaw with the same spelling: $(tail -c 200 <<<"$OUT")"
    elif refused_with "Wallet policy not found"; then
      fail "P3 the same key in UPPER case answers 'Wallet policy not found' — an emergency freeze, and the way out of one, lost to capitalisation"
    else
      note "P3 INCONCLUSIVE — refused for another reason: $(tail -c 200 <<<"$OUT")"
    fi
  fi
fi

# ── P4…P6: the refusals that must hold ───────────────────────────────────────
log "P4 a stranger cannot pause the contract"
if call "$OTHER" set_paused "$(jq -nc '{paused:true}')" '0 NEAR'; then
  fail "P4 $OTHER PAUSED THE CONTRACT — set_paused is owner-only"
  call "$OTHER" set_paused "$(jq -nc '{paused:false}')" '0 NEAR' && note "P4 unpaused again"
else
  refused_with "owner" \
    && pass "P4 refused, and the message names the owner" \
    || note "P4 refused for another reason: $(tail -c 160 <<<"$OUT")"
fi

log "P5 a stranger cannot delete somebody else's secret"
# Deletion is keyed by (accessor, profile, OWNER=caller), so a stranger asking
# for the same accessor and profile addresses THEIR OWN slot and finds nothing.
if call "$OTHER" delete_secrets \
      "$(jq -nc --argjson a "$acc_lower" '{accessor:$a, profile:"probe"}')" '0 NEAR'; then
  fail "P5 $OTHER deleted a secret addressed by $CALLER's accessor and profile"
else
  refused_with "not found" \
    && pass "P5 refused — a delete addresses the caller's own secrets and nobody else's" \
    || note "P5 refused for another reason: $(tail -c 160 <<<"$OUT")"
fi

log "P6 a secret cannot be stored against a project that does not exist"
GHOST="$OTHER/project-that-does-not-exist-$(openssl rand -hex 3)"
if call "$OTHER" store_secrets \
      "$(jq -nc --arg p "$GHOST" '{accessor:{Project:{project_id:$p}}, profile:"probe", encrypted_secrets_base64:"cHJvYmU=", access:"AllowAll", vault_id:null}')" \
      '0.1 NEAR'; then
  fail "P6 a secret was stored against '$GHOST', which does not exist"
  call "$OTHER" delete_secrets "$(jq -nc --arg p "$GHOST" '{accessor:{Project:{project_id:$p}}, profile:"probe"}')" '0 NEAR' >/dev/null
else
  refused_with "does not exist" \
    && pass "P6 refused, naming the project" \
    || note "P6 refused for another reason: $(tail -c 160 <<<"$OUT")"
fi

echo
log "SUMMARY"
pass "passed: $PASS"
if [[ $FAILED -gt 0 ]]; then
  for n in "${FAILED_NAMES[@]}"; do printf '\033[31m  ✗ %s\033[0m\n' "$n" >&2; done
  echo "FAILED: $FAILED" >&2
  exit 1
fi
