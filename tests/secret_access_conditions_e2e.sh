#!/usr/bin/env bash
#
# AccessCondition, end to end — the two gates that decide whether a WASI run
# gets to see somebody's secrets.
#
# The keystore decides this INSIDE the enclave, at decryption time, against the
# account that requested the execution. Two conditions are checked here:
#
#   `AccountPattern` — a regex over the caller's account id. It is compiled to
#   `\A(?:…)\z`, and the anchoring is the security boundary: an unanchored
#   `is_match` succeeds on any SUBSTRING, so the exact-looking pattern
#   `pat\.you\.testnet` would also admit `xpat.you.testnet` and
#   `sub.pat.you.testnet`. That is one account's secrets handed to another.
#
#   `NftOwned` — a condition the keystore can only answer by asking the chain.
#   Its interesting case is not the answer but the absence of one: a contract
#   that does not exist cannot say who owns token 1, and a condition that
#   cannot be evaluated must never read as satisfied.
#
# WHY THIS EXISTS BESIDE THE UNIT VECTORS. `keystore-worker/src/types.rs`
# carries vectors for the regex, and they are good ones — six of them fail the
# moment the anchoring is removed. What they cannot show is that the caller the
# enclave measures is the account that signed the transaction, that a denial
# actually stops the run rather than handing the module an empty environment,
# and that the refusal reaches the chain where the caller can read it. Those are
# three joins between four processes, and they are what this drives.
#
# WHAT IT JUDGES BY. The `execution_completed` event in the transaction's own
# logs. Not the yielded return value: a refused run answers `null`, which is
# also what a timeout looks like, and judging by it would call a correct refusal
# indistinguishable from a stalled worker. The event carries `success` and the
# reason, and it is on chain — which is also the point of A5.
#
# THE POSITIVE CONTROL IS NOT OPTIONAL. A1 proves the matching caller reads the
# canary VALUE back out of the enclave. Without it every denial below is
# satisfied by a secret nobody can ever read, and a broken keystore passes.
#
# Money: five runs at 0.1 NEAR attached (0.001 charged, the rest refunded),
# three sub-accounts at 1 NEAR each on the first run only, and three secret
# profiles at ~0.004 NEAR of storage. Re-runs reuse the accounts.
#
# Run:
#   PARENT=you.testnet ./tests/secret_access_conditions_e2e.sh --apply
#   PARENT=you.testnet ./tests/secret_access_conditions_e2e.sh --destroy
#
# Needs a deployed project that reports which secrets it can see. The default is
# `$PARENT/test-secrets`, which is `wasi-examples/test-secrets-example`:
#   cd wasi-examples/test-secrets-example && ./build.sh && outlayer deploy test-secrets
# That artefact carries a manifest naming the AUTHOR's profile `author`, which
# must be stored under Project($PARENT/test-secrets) with access allow-all (see
# the example's README) — while it is absent, EVERY run of the project is
# refused and each case below reads as a denial. `03_project_model.sh` in the
# example's tests stores it as part of its fixture.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/hos_common.sh"

PARENT="${PARENT:-}"
NETWORK="${NETWORK:-testnet}"
CONTRACT_ID="${CONTRACT_ID:-outlayer.testnet}"
PROJECT="${SECRETS_PROJECT:-}"
DEPOSIT='0.1 NEAR'

MODE="${1:-}"
[[ "$MODE" == "--apply" || "$MODE" == "--destroy" ]] || {
  sed -n '3,45p' "$0" >&2; echo "  Pass --apply to run, --destroy to remove the accounts." >&2; exit 0; }
hos_require
PROJECT="${PROJECT:-$PARENT/test-secrets}"

# The three callers, and why these names. `pat` is the one the pattern names.
# `xpat` puts a character BEFORE it and `sub.pat` puts a label before it with a
# dot — between them they cover both ends of the substring hole, and both are
# real accounts rather than strings in an assertion, because the property under
# test is what the enclave measures and not what a regex does in isolation.
MATCHER="pat.$PARENT"
PREFIX_TRAP="xpat.$PARENT"
SUFFIX_TRAP="sub.pat.$PARENT"
# The pattern as an owner would write it: an exact account, dots escaped.
PATTERN="pat\\.$(sed 's/\./\\./g' <<<"$PARENT")"

# A contract that does not exist, so the chain cannot answer the condition. The
# suffix keeps it from ever being registered by someone else on testnet.
ABSENT_NFT="no-such-nft-$(openssl rand -hex 4).testnet"
# One that does, and that the caller does not own token 1 of, so the condition
# is answerable and false.
PRESENT_NFT="${PRESENT_NFT:-nft.examples.testnet}"

# ── teardown ─────────────────────────────────────────────────────────────────
if [[ "$MODE" == "--destroy" ]]; then
  log "Removing the probe accounts"
  for a in "$SUFFIX_TRAP" "$PREFIX_TRAP" "$MATCHER"; do
    near --quiet account delete-account "$a" beneficiary "$PARENT" \
      network-config "$NETWORK" sign-with-legacy-keychain send >/dev/null 2>&1 \
      && note "deleted $a" || note "$a was not there"
  done
  exit 0
fi

# ── fixture ──────────────────────────────────────────────────────────────────

# view_account, as a yes/no. A missing account and a present one are told apart
# by the RPC's own error, so this asks the node rather than a local file: the
# credentials outlive a `--destroy`, and a leftover json would otherwise report
# an account that no longer exists.
account_is_on_chain() {
  local out
  out=$(curl -sS "$RPC_URL" -H 'content-type: application/json' -d "$(jq -nc --arg a "$1" \
        '{jsonrpc:"2.0",id:1,method:"query",
          params:{request_type:"view_account",finality:"final",account_id:$a}}')" 2>/dev/null)
  [[ -n "$(jq -r '.result.amount // empty' <<<"$out")" ]]
}

make_account() { # make_account <name> <parent> <amount>
  if account_is_on_chain "$1"; then note "$1 is already there"; return 0; fi
  local signer=with-keychain
  [[ "$2" != "$PARENT" ]] && signer=with-legacy-keychain
  near --quiet account create-account fund-myself "$1" "$3" \
    autogenerate-new-keypair save-to-legacy-keychain \
    sign-as "$2" network-config "$NETWORK" "sign-$signer" send >/dev/null 2>&1
  account_is_on_chain "$1" || { echo "✗ could not create $1" >&2; exit 1; }
  note "created $1 with $3"
}

log "Fixture: the project, the callers, the secret"
PROJECT_VIEW=$(near_view "$CONTRACT_ID" get_project "$(jq -nc --arg p "$PROJECT" '{project_id:$p}')")
if [[ -z "$PROJECT_VIEW" || "$PROJECT_VIEW" == "null" || "$PROJECT_VIEW" == "ERR" ]]; then
  skip "$PROJECT is not deployed — deploy wasi-examples/test-secrets-example as \`test-secrets\` first"
  verdict "secret access conditions"; exit $?
fi
note "project: $PROJECT"

make_account "$MATCHER"     "$PARENT"  '1 NEAR'
make_account "$PREFIX_TRAP" "$PARENT"  '1 NEAR'
make_account "$SUFFIX_TRAP" "$MATCHER" '1 NEAR'

# The canary. A denial that returned an EMPTY secret would satisfy every probe
# below, so what A1 reads back has to be a value this run chose.
CANARY="canary-$(openssl rand -hex 6)"

# The blob is encrypted by the CLI under a seed built from the ACCESSOR, not
# from the access rule — so a profile can be stored once and then re-stored with
# a different gate, and the ciphertext stays valid. That is what lets this suite
# set conditions the CLI has no flag for.
store_profile() { # store_profile <profile> <access-json>
  local profile=$1 access=$2 blob view_args before after record
  view_args=$(jq -nc --arg p "$PROJECT" --arg pr "$profile" --arg o "$PARENT" \
    '{accessor:{Project:{project_id:$p}}, profile:$pr, owner:$o}')
  # `updated_at` of whatever is on chain now (0 when the profile does not exist yet), so the
  # wait below can tell THIS run's write from the previous run's record.
  before=$(near_view "$CONTRACT_ID" get_secrets "$view_args" | jq -r '.updated_at // 0')
  OUTLAYER_NETWORK="$NETWORK" outlayer secrets set --project "$PROJECT" --profile "$profile" \
    "$(jq -nc --arg c "$CANARY" '{SECRET:$c}')" >/dev/null 2>&1 \
    || { echo "✗ could not store profile $profile" >&2; exit 1; }
  # `secrets set` returns once the transaction is EXECUTED (optimistic); `near_view` reads with
  # finality "final". Read too early and the view still shows the PREVIOUS run's blob, and the
  # re-store below would carry that old ciphertext under the new gate — the module then reads a
  # canary from a run that is not this one. So wait for the write to become final.
  after=$before
  for _ in $(seq 1 15); do
    record=$(near_view "$CONTRACT_ID" get_secrets "$view_args")
    after=$(jq -r '.updated_at // 0' <<<"$record")
    [[ "$after" != "$before" ]] && break
    sleep 2
  done
  [[ "$after" != "$before" ]] \
    || { echo "✗ $profile: the stored secret never became final (updated_at still $before)" >&2; exit 1; }
  blob=$(jq -r '.encrypted_secrets // empty' <<<"$record")
  [[ -n "$blob" ]] || { echo "✗ $profile stored nothing readable" >&2; exit 1; }
  near --quiet contract call-function as-transaction "$CONTRACT_ID" store_secrets \
    json-args "$(jq -nc --arg p "$PROJECT" --arg pr "$profile" --arg b "$blob" --argjson a "$access" \
      '{accessor:{Project:{project_id:$p}}, profile:$pr, encrypted_secrets_base64:$b,
        access:$a, vault_id:null}')" \
    prepaid-gas '100.0 Tgas' attached-deposit '0.02 NEAR' \
    sign-as "$PARENT" network-config "$NETWORK" sign-with-keychain send >/dev/null 2>&1 \
    || { echo "✗ could not re-gate $profile" >&2; exit 1; }
  note "profile '$profile' gated by $(jq -c 'keys[0]' <<<"$access")"
}

store_profile patternprobe "$(jq -nc --arg p "$PATTERN" '{AccountPattern:{pattern:$p}}')"
store_profile chainabsent  "$(jq -nc --arg c "$ABSENT_NFT" '{NftOwned:{contract:$c, token_id:"1"}}')"
store_profile chainfalse   "$(jq -nc --arg c "$PRESENT_NFT" '{NftOwned:{contract:$c, token_id:"1"}}')"

# ── the probe ────────────────────────────────────────────────────────────────
#
# Sets RUN_OK / RUN_ERR / RUN_SECRET from the transaction's own logs.
RUN_OK=""; RUN_ERR=""; RUN_SECRET=""
run_as() { # run_as <signer> <profile>
  local signer=$1 profile=$2 out ev signer_flag=with-legacy-keychain
  [[ "$signer" == "$PARENT" ]] && signer_flag=with-keychain
  out=$(near contract call-function as-transaction "$CONTRACT_ID" request_execution \
    json-args "$(jq -nc --arg p "$PROJECT" --arg pr "$profile" --arg o "$PARENT" \
      '{source:{Project:{project_id:$p}},
        input_data:"{\"message\":\"probe\"}",
        secrets_ref:{profile:$pr, account_id:$o},
        resource_limits:{max_instructions:1000000000,max_memory_mb:128,max_execution_seconds:30}}')" \
    prepaid-gas '300.0 Tgas' attached-deposit "$DEPOSIT" \
    sign-as "$signer" network-config "$NETWORK" "sign-$signer_flag" send 2>&1)
  # The completion event, which is the only place the chain states an outcome.
  ev=$(grep -o 'EVENT_JSON:.*execution_completed.*' <<<"$out" | sed 's/^EVENT_JSON://' | head -1)
  # NOT `.success // empty`: jq's `//` treats FALSE exactly like null, so every
  # refusal — the outcome this suite is about — would read as "the event said
  # nothing" and each assertion below would fail with the wrong sentence.
  RUN_OK=$(jq -r '.data[0] | if has("success") then (.success|tostring) else "absent" end' <<<"$ev" 2>/dev/null)
  RUN_ERR=$(jq -r '.data[0].error_message // ""' <<<"$ev" 2>/dev/null)
  # The module's own answer, when it ran at all.
  RUN_SECRET=$(awk '/Function execution return value/{getline; print}' <<<"$out" \
    | jq -r 'select(. != null) | fromjson | .secrets[]? | select(.key=="SECRET") | .value // ""' 2>/dev/null)
}

# ── A1 the caller the pattern names ──────────────────────────────────────────
log "A1 the account the pattern names"
run_as "$MATCHER" patternprobe
[[ "$RUN_OK" == "true" ]] \
  && pass "A1 the run completed for $MATCHER" \
  || fail "A1 the matching caller was refused ('$RUN_ERR') — every denial below is now meaningless"
[[ "$RUN_SECRET" == "$CANARY" ]] \
  && pass "A1 and the module read the canary out of the enclave — the gate opens on a real secret" \
  || fail "A1 the module saw '$RUN_SECRET', expected the canary this run stored"
# A1 is the positive control for everything below. While the author profile is
# missing this project refuses EVERY run, and each denial row would then pass on
# a refusal that has nothing to do with the condition it names.
[[ "$RUN_OK" == "true" && "$RUN_SECRET" == "$CANARY" ]] || {
  fail "A1 failed, so every refusal below would pass for the wrong reason — stopping here"
  verdict "secret access conditions"; exit 1
}

# ── A2/A3 the two ends of the substring hole ─────────────────────────────────
log "A2 a character BEFORE the pattern"
run_as "$PREFIX_TRAP" patternprobe
[[ "$RUN_OK" == "false" ]] \
  && pass "A2 $PREFIX_TRAP was refused — the pattern is anchored at the start" \
  || fail "A2 $PREFIX_TRAP RAN: an unanchored pattern is handing this account another's secrets"
[[ -z "$RUN_SECRET" ]] \
  && pass "A2 and it saw no secret at all" \
  || fail "A2 the refused caller still read '$RUN_SECRET'"

log "A3 a label BEFORE the pattern"
run_as "$SUFFIX_TRAP" patternprobe
[[ "$RUN_OK" == "false" ]] \
  && pass "A3 $SUFFIX_TRAP was refused — a sub-account does not inherit its parent's gate" \
  || fail "A3 $SUFFIX_TRAP RAN: the pattern matched a substring of a longer account"
[[ -z "$RUN_SECRET" ]] \
  && pass "A3 and it saw no secret at all" \
  || fail "A3 the refused caller still read '$RUN_SECRET'"

# ── A4 the owner is not exempt ───────────────────────────────────────────────
#
# The account that STORED the secret does not match the pattern it wrote, and a
# condition that quietly exempted the owner would be a rule nobody could rely on
# when the owner is a shared or a deployer account.
log "A4 the secret's own owner, who does not match"
run_as "$PARENT" patternprobe
[[ "$RUN_OK" == "false" ]] \
  && pass "A4 $PARENT was refused by its own rule — a pattern is a gate, not a courtesy" \
  || fail "A4 the owner ran anyway: the condition is not applied to whoever stored the secret"

# ── A5 the refusal is legible where the caller is ────────────────────────────
log "A5 what the chain says about a refusal"
[[ -n "$RUN_ERR" ]] \
  && pass "A5 the completion event carries a reason: '$(head -c 60 <<<"$RUN_ERR")…'" \
  || fail "A5 the refusal reached the chain with no reason — the caller cannot tell it from a crash"

# ── S1 a condition the chain cannot answer ───────────────────────────────────
log "S1 NftOwned against a contract that does not exist"
run_as "$MATCHER" chainabsent
S1_ERR="$RUN_ERR"
[[ "$RUN_OK" == "false" ]] \
  && pass "S1 refused — a condition that cannot be evaluated is not satisfied" \
  || fail "S1 an unanswerable condition GRANTED the secret: the check fails open"
[[ -z "$RUN_SECRET" ]] \
  && pass "S1 and nothing was decrypted" \
  || fail "S1 the module read '$RUN_SECRET' through a condition nobody could answer"

# ── S2 the control: answerable, and false ────────────────────────────────────
#
# Without this, S1 is satisfied by an `NftOwned` that refuses everybody — which
# is fail-closed by accident rather than by rule, and would keep passing after
# the condition stopped working at all.
log "S2 NftOwned against a real contract the caller does not own from"
run_as "$MATCHER" chainfalse
[[ "$RUN_OK" == "false" ]] \
  && pass "S2 refused as well — so S1's refusal is about the missing answer, not a dead condition" \
  || fail "S2 the caller was granted a token it does not own"
[[ "$RUN_ERR" != "$S1_ERR" ]] \
  && pass "S2 and the two refusals do not read alike — an operator can tell a wrong rule from an unreachable one" \
  || finding "an unanswerable condition and a false one give the caller the SAME sentence ('$(head -c 60 <<<"$RUN_ERR")…'), so a typo in a contract name reads as a denial that is working"

verdict "secret access conditions"
exit $?
