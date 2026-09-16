#!/usr/bin/env bash
#
# A secret judged on the account that CALLED the contract: the `Predecessor`
# access condition, live.
#
# Every other leaf is judged against the transaction's SIGNER. A contract the
# owner signs one transaction to is the predecessor when it relays
# `request_execution` naming the owner's row — the signer is still the owner,
# and `Whitelist[owner]` admits (X1 in secrets_security_e2e.sh). `Predecessor
# { condition }` re-judges its condition on that calling account instead, so
# the owner can say who may stand in between: nobody, one DAO, a pattern.
#
# Two relay contracts (tests/deputy-stub) stand in for "a contract the owner
# signed to": deputy.$PARENT and deputy2.$PARENT, the same artefact on two
# accounts, so a rule that names ONE of them is shown to refuse the other.
#
# What each row pins — and every ADMIT checks that the canary VALUE reached
# the guest, every REFUSE that `success` is false, that no canary came back,
# and which calling account the refusal states; a run that never answered is
# a failure, never a refusal:
#   P0  control: Whitelist[owner] — the deputy's relay is ADMITTED and the
#       canary comes back through it. Proves the relay hole is real on this
#       deployment, so every refusal below is the leaf's doing and not the
#       relay's. A direct call is admitted too
#   P1  And[Whitelist[owner], Predecessor{Whitelist[owner]}] — the owner's
#       "direct calls only": direct admitted; through the deputy refused, the
#       refusal stating the deputy as the account the call came from
#   P2  the ciphertext is byte-identical across the access edits: naming a
#       calling account is not re-storing the secret
#   P3  And[Whitelist[owner], Predecessor{Whitelist[deputy]}] — composability
#       through ONE relay: through the deputy admitted; through deputy2
#       refused stating deputy2; direct refused stating the owner
#   P4  And[Whitelist[owner], Not{Predecessor{Whitelist[deputy]}}] — "not
#       through this one": direct admitted; through the deputy refused,
#       stating the deputy; through deputy2 admitted
#   P5  a PATTERN inside the wrapper, `deputy2?\.<owner>` — through either
#       deputy admitted, direct refused. Pins that patterns nested in the
#       wrapper are compiled: an uncompiled one is an error that refuses all
#   P6  a STRANGER calling P1's row directly — refused, and the refusal
#       states the facts (signer, called from) without blaming any leaf: a
#       refusal never attributes, it reports
#   P7  Or[Whitelist[nobody], Predecessor{Whitelist[deputy]}] — the wrapper
#       ALONE admits: through the deputy the owner is admitted though no
#       branch names them; direct refused
#   P8  a CHAIN-READ leaf inside, Predecessor{DaoMember{dao, council}} where
#       the council names the owner: direct admitted (the owner is the calling
#       account and IS a member); through the deputy refused (the deputy is
#       not). Pins that leaves asking the chain are asked about the
#       predecessor
#   P9  Predecessor{Predecessor{Whitelist[deputy]}} — stored, and judged as
#       the single wrapper (the calling account has no predecessor of its own)
#   H1  over HTTPS on the owner's payment key: P1's row admits, P3's row
#       refuses stating the owner as the calling account — the HTTPS door
#       reports the payer, because nothing relays an HTTPS call
#
# A refusal's wording is FACTS — "signer X, called from Y" — never a guess at
# which leaf refused. Rows that check wording check that the right calling
# account was reported, which is what proves the worker sent it.
#
# NOT covered here, and deliberately: a function-call access key on the
# owner's own account. A dapp holding one signs directly — predecessor ==
# signer == owner — and no condition on the calling account can see it.
#
# Needs: PARENT (owns the row, signs, owns the deputies), the deputy artefact
# (cd tests/deputy-stub && cargo near build non-reproducible-wasm), and the
# project $PARENT/test-secrets published from wasi-examples/test-secrets-example.
# PAYMENT_KEY (a funded key owned by PARENT) enables H1. DAO_CONTRACT /
# DAO_ROLE (default: the A4 fixture, olseca4.sputnikv2.testnet council) for P8.
#
# Money: ~20 on-chain runs at 0.1 NEAR attached (0.001 charged, the rest
# refunded), two HTTPS calls, one storage row, and on the FIRST run only:
# deputy2.$PARENT and xpat.$PARENT as sub-accounts (3 + 1 NEAR, kept as
# fixtures).
#
# Run:
#   PARENT=you.testnet ./tests/secret_predecessor_e2e.sh                    # the plan
#   PARENT=you.testnet PAYMENT_KEY=… ./tests/secret_predecessor_e2e.sh --apply
#   ONLY=P1,P3 … --apply                                                    # a subset

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/hos_common.sh"

PARENT="${PARENT:-}"
PROJECT="${SECRETS_PROJECT:-${PARENT:-}/test-secrets}"
PAYMENT_KEY="${PAYMENT_KEY:-}"
PROFILE="${PROFILE:-viacheck}"
DEPUTY_WASM="${DEPUTY_WASM:-$SCRIPT_DIR/deputy-stub/target/near/deputy_stub.wasm}"
DAO_CONTRACT="${DAO_CONTRACT:-olseca4.sputnikv2.testnet}"
DAO_ROLE="${DAO_ROLE:-council}"
DEPOSIT='0.1 NEAR'
CANARY="via-canary-$(openssl rand -hex 6)"

[[ "${1:-}" == "--apply" ]] || { sed -n '3,75p' "$0" >&2; echo "  Pass --apply to run." >&2; exit 0; }
[[ -n "$PARENT" ]] || { echo "✗ set PARENT" >&2; exit 1; }
[[ -f "$DEPUTY_WASM" ]] || { echo "✗ no deputy artefact at $DEPUTY_WASM — build it: (cd tests/deputy-stub && cargo near build non-reproducible-wasm)" >&2; exit 1; }
hos_require
source "$SCRIPT_DIR/lib/secrets_common.sh"

DEPUTY="deputy.$PARENT"
DEPUTY2="deputy2.$PARENT"
STRANGER="xpat.$PARENT"
note "project: $PROJECT   profile: $PROFILE   deputies: $DEPUTY, $DEPUTY2"

want() { [[ -z "${ONLY:-}" ]] || [[ ",$ONLY," == *",$1,"* ]]; }

# ── condition builders ───────────────────────────────────────────────────────
via()      { jq -nc --argjson c "$1" '{Predecessor:{condition:$c}}'; }
and_of()   { jq -nc --argjson a "$1" --argjson b "$2" '{Logic:{operator:"And",conditions:[$a,$b]}}'; }
or_of()    { jq -nc --argjson a "$1" --argjson b "$2" '{Logic:{operator:"Or",conditions:[$a,$b]}}'; }
not_of()   { jq -nc --argjson c "$1" '{Not:{condition:$c}}'; }
pattern()  { jq -nc --arg p "$1" '{AccountPattern:{pattern:$p}}'; }
dao_leaf() { jq -nc --arg d "$1" --arg r "$2" '{DaoMember:{dao_contract:$d, role:$r}}'; }

# ── the deployment gate ──────────────────────────────────────────────────────
#
# Asked of the deployed contract, not of the checkout, and fail-closed: only a
# numeric price — the contract pricing a Predecessor condition it understands —
# opens the gate (see secret_build_lock_e2e.sh for why not `near_view`).
gate() {
  local args raw price why
  args=$(jq -nc --argjson a "$(accessor_json "$PROJECT")" --arg o "$PARENT" \
          --argjson x "$(via "$(whitelist "$PARENT")")" \
          '{accessor:$a, profile:"probe", owner:$o, encrypted_secrets_base64:"", access:$x, vault_id:null}')
  raw=$(curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' --max-time 30 \
    -d "$(jq -nc --arg a "$CONTRACT_ID" --arg g "$(printf '%s' "$args" | base64 | tr -d '\n')" \
      '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"call_function",finality:"final",
        account_id:$a,method_name:"estimate_storage_cost",args_base64:$g}}')" 2>&1)
  price=$(jq -r 'if .result.result then (.result.result | implode) else empty end' <<<"$raw" 2>/dev/null | tr -d '"')
  if [[ "$price" =~ ^[0-9]+$ ]]; then
    note "the deployed contract prices a Predecessor condition ($price yoctoNEAR) — it knows the variant"
    return 0
  fi
  why=$(jq -r '.result.error // .error.data // .error.message // empty' <<<"$raw" 2>/dev/null | head -c 300)
  if grep -q "unknown variant" <<<"$why"; then
    skip "the deployed contract does not know the Predecessor condition — deploy contract, keystore, then workers, then re-run"
  else
    skip "the contract would not price a Predecessor condition, and not because the variant is unknown — nothing below can be trusted until this is understood"
  fi
  note "the contract answered: ${why:-$(head -c 200 <<<"$raw")}"
  verdict "secret predecessor"; exit $?
}
gate

# ── the fixtures: two deputies and a stranger ────────────────────────────────

# The artefact's code hash as the chain reports it (base58 of sha256).
deputy_wasm_hash() {
  python3 - "$DEPUTY_WASM" <<'PY'
import hashlib, sys
d = hashlib.sha256(open(sys.argv[1], 'rb').read()).digest()
A = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
n = int.from_bytes(d, 'big'); s = ''
while n:
    n, r = divmod(n, 58); s = A[r] + s
print('1' * (len(d) - len(d.lstrip(b'\0'))) + s)
PY
}
WANT_HASH=$(deputy_wasm_hash)
[[ "$WANT_HASH" =~ ^[1-9A-HJ-NP-Za-km-z]{43,44}$ ]] || { echo "✗ could not hash the deputy artefact (python3? $DEPUTY_WASM?) — got '$WANT_HASH'" >&2; exit 1; }

# ensure_deputy <account> — created, and (re)deployed whenever the code on it
# is not this artefact or its owner is not $PARENT. `new` takes the owner by
# name and accepts only the deploy transaction, signed by the deputy's key.
ensure_deputy() {
  local acc=$1 out
  if ! account_exists "$acc"; then
    create_subaccount "$acc" 3 || { echo "✗ could not create $acc" >&2; exit 1; }
    note "created $acc with 3 NEAR"
  fi
  if [[ "$(account_field "$acc" code_hash)" != "$WANT_HASH" ]] \
     || [[ "$(near_view "$acc" owner '{}' | tr -d '"')" != "$PARENT" ]]; then
    out=$(near --quiet contract deploy "$acc" use-file "$DEPUTY_WASM" \
      with-init-call new json-args "$(jq -nc --arg o "$PARENT" '{owner:$o}')" prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR' \
      network-config "$NETWORK" sign-with-keychain send 2>&1) \
      || { echo "✗ the deputy did not deploy to $acc: $(grep -viE '^\s*$' <<<"$out" | tail -3 | tr '\n' ' ' | head -c 240)" >&2; exit 1; }
    sleep 3
  fi
  note "$acc holds code $(account_field "$acc" code_hash | head -c 12)… owned by $PARENT"
}
ensure_deputy "$DEPUTY"
ensure_deputy "$DEPUTY2"
make_account "$STRANGER" "$PARENT" '1 NEAR'

# ── one run, relayed through a deputy ────────────────────────────────────────
#
# The OWNER signs a transaction to the deputy; the deputy is the predecessor
# and the payer when it forwards `request_execution`. The yield resolves in a
# receipt of the same transaction, so the tree is polled for the completion
# event rather than the send judged. Sets RUN_OK / RUN_ERR / RUN_SENDER, and
# RUN_OUT from the transaction's RETURN VALUE — the module's answer, which the
# deputy's caller sees. That is where a relayed run's canary would surface.
RUN_SENDER=""
# Whether a relayed run's canary surfaces in the return value at all — learned
# from the control run, so a relay whose return value does not propagate is
# judged on the event alone rather than failing every admission.
RELAY_RETURNS_CANARY=1
LAST_RUN_RELAYED=0
relay_via() { # relay_via <deputy>
  local deputy=$1 args out tx logs ev ret i
  RUN_OK=absent; RUN_ERR=""; RUN_OUT=""; RUN_SENDER=""; LAST_RUN_RELAYED=1
  args=$(jq -nc --arg c "$CONTRACT_ID" --arg p "$PROJECT" --arg o "$PARENT" --arg pr "$PROFILE" \
    '{outlayer:$c, source:{Project:{project_id:$p}}, secrets_ref:{account_id:$o, profile:$pr},
      deposit:"100000000000000000000000"}')
  out=$(near contract call-function as-transaction "$deputy" relay json-args "$args" \
    prepaid-gas '300.0 Tgas' attached-deposit '0 NEAR' \
    sign-as "$PARENT" network-config "$NETWORK" sign-with-keychain send 2>&1)
  tx=$(grep -oE 'Transaction ID: *[1-9A-HJ-NP-Za-km-z]{40,50}' <<<"$out" | grep -oE '[1-9A-HJ-NP-Za-km-z]{40,50}' | head -1)
  logs="$out"
  if [[ -z "$tx" ]]; then
    note "the relay through $deputy never landed: $(grep -A3 -iE 'error|panick|fail' <<<"$out" | grep -viE '^\s*$' | head -3 | tr '\n' ' ' | head -c 300)"
    return 0
  fi
  local raw=""
  for i in $(seq 1 20); do
    raw=$(curl -sS --max-time 45 "$RPC_URL" -X POST -H 'Content-Type: application/json' \
      -d "$(jq -nc --arg t "$tx" --arg s "$PARENT" \
        '{jsonrpc:"2.0",id:1,method:"tx",params:{tx_hash:$t,sender_account_id:$s,wait_until:"FINAL"}}')")
    logs=$(jq -r '[.result.receipts_outcome[]?.outcome.logs[]?] | join("\n")' <<<"$raw" 2>/dev/null)
    grep -q "execution_completed" <<<"$logs" && break
    sleep 6
  done
  ev=$(grep -o 'EVENT_JSON:.*execution_completed.*' <<<"$logs" | sed 's/^EVENT_JSON://' | head -1)
  if [[ -z "$ev" ]]; then
    note "no completion event in $tx after two minutes — the relayed run did not finish"
    return 0
  fi
  RUN_OK=$(jq -r '.data[0] | if has("success") then (.success|tostring) else "absent" end' <<<"$ev" 2>/dev/null)
  RUN_ERR=$(jq -r '.data[0].error_message // ""' <<<"$ev" 2>/dev/null)
  RUN_SENDER=$(jq -r '.data[0].sender_id // ""' <<<"$ev" 2>/dev/null)
  ret=$(jq -r '.result.status.SuccessValue // empty' <<<"$raw" | base64 --decode 2>/dev/null \
    | jq -c 'if type=="string" then fromjson else . end' 2>/dev/null)
  RUN_OUT="$ret"
}

direct() { LAST_RUN_RELAYED=0; run_as "$PARENT" "$PARENT/$PROFILE"; }
direct_as() { LAST_RUN_RELAYED=0; run_as "$1" "$PARENT/$PROFILE"; }

secret_arrived() { [[ "$(secret_value USER_SECRET)" == "$CANARY" ]]; }
# For an ADMISSION: the canary reached the guest — or, on a relay whose return
# value the control run showed does not carry it, the completion event's own
# success. A refusal is never judged this way: a missing canary is its point.
admitted_evidence() {
  secret_arrived && return 0
  [[ "$LAST_RUN_RELAYED" == 1 && "$RELAY_RETURNS_CANARY" == 0 && "$RUN_OK" == "true" ]]
}
ciphertext_of()  { jq -r '.encrypted_secrets // empty' <<<"$(row_of "$PROJECT" "$PROFILE")"; }

# The three ways a row is judged. Each names the row (P-id), how the run was
# made (for the message), and what it asserts.
#
# expect_admitted <row> <how> — the run completed and the canary reached the
# guest. A run that completed WITHOUT the canary is a failure too: the secret
# was withheld from a run the condition should have admitted.
expect_admitted() {
  local row=$1 how=$2
  if [[ "$RUN_OK" == "true" ]] && admitted_evidence; then
    pass "$row $how: admitted$(secret_arrived && echo ', and the canary reached the guest')"
  elif [[ "$RUN_OK" == "absent" ]]; then
    fail "$row $how: nothing answered — a run that never finished is not an admission"
  elif [[ "$RUN_OK" == "true" ]]; then
    fail "$row $how: the run completed but the canary did not reach the guest: $(head -c 200 <<<"$RUN_OUT")"
  else
    fail "$row $how: REFUSED where it should have been admitted: $(head -c 300 <<<"$RUN_ERR")"
  fi
}

# expect_refused <row> <how> <must-say-regex> [must-not-say-regex] [strict]
#
# A refusal is a VERDICT the keystore reached — never an error it could not
# judge past: "Access validation failed … reports none" is an old worker, "parse
# access condition" an old keystore, and a suite that counted those as
# refusals would go green on a deployment without the feature. With `strict`
# the wording is the row's subject and a miss is a failure; otherwise a
# finding.
expect_refused() {
  local row=$1 how=$2 must=$3 mustnot=${4:-} strict=${5:-}
  if secret_arrived; then
    fail "$row $how: the canary came back — the condition did NOT hold"
  elif [[ "$RUN_OK" == "absent" ]]; then
    fail "$row $how: nothing answered — a timeout is not a refusal"
  elif [[ "$RUN_OK" == "true" ]]; then
    fail "$row $how: the run completed without the secret instead of being refused: $(head -c 200 <<<"$RUN_OUT")"
  elif grep -qiE "validation failed|reports none|no calling account|parse access condition|unknown variant" <<<"$RUN_ERR"; then
    fail "$row $how: the keystore could not JUDGE the row — a deployment error, not a refusal: $(head -c 300 <<<"$RUN_ERR")"
  elif ! grep -qiE "denied|access" <<<"$RUN_ERR"; then
    fail "$row $how: failed, but not as an access refusal: $(head -c 300 <<<"$RUN_ERR")"
  elif [[ -n "$mustnot" ]] && grep -qE "$mustnot" <<<"$RUN_ERR"; then
    fail "$row $how: refused, but the message blames the wrong thing ('$mustnot'): $(head -c 300 <<<"$RUN_ERR")"
  elif ! grep -qE "$must" <<<"$RUN_ERR"; then
    if [[ "$strict" == strict ]]; then
      fail "$row $how: refused, but the reason does not say '$must': $(head -c 300 <<<"$RUN_ERR")"
    else
      finding "$row $how: refused, but the reason does not say '$must': $(head -c 300 <<<"$RUN_ERR")"
    fi
  else
    pass "$row $how: refused — $(grep -oE 'Access denied by access condition.*' <<<"$RUN_ERR" | head -c 160)"
  fi
}

# ── P0 the control: the relay hole is real here ──────────────────────────────
log "P0 control — Whitelist[owner]: the deputy's relay is admitted, so every refusal below is the leaf's"
store "$PROJECT" "$PROFILE" "$(jq -nc --arg v "$CANARY" '{USER_SECRET:$v}')" "whitelist:$PARENT"
CIPHER_BEFORE="$(ciphertext_of)"
direct
if ! { [[ "$RUN_OK" == "true" ]] && secret_arrived; }; then
  fail "P0 the row does not read even for the owner's direct call, so nothing below would mean anything — success=$RUN_OK err='$(head -c 300 <<<"$RUN_ERR")'"
  verdict "secret predecessor"; exit $?
fi
pass "P0 direct: admitted, canary in the guest's answer"
relay_via "$DEPUTY"
if [[ "$RUN_OK" == "true" ]] && secret_arrived; then
  pass "P0 through $DEPUTY: admitted with sender_id=$RUN_SENDER, and the canary came back through the relay — the hole this condition closes"
elif [[ "$RUN_OK" == "true" ]]; then
  RELAY_RETURNS_CANARY=0
  finding "P0 through $DEPUTY: admitted (sender_id=$RUN_SENDER) but the canary did not propagate as the relay's return value — relayed admissions below are judged on the event, refusals on success=false"
else
  fail "P0 through $DEPUTY: the relay was NOT admitted on a plain whitelist (success=$RUN_OK, '$(head -c 200 <<<"$RUN_ERR")') — the door no longer judges the signer alone, and the rows below cannot attribute their refusals"
  verdict "secret predecessor"; exit $?
fi

# ── P1 direct calls only ─────────────────────────────────────────────────────
if want P1; then
  log "P1 And[Whitelist[owner], Predecessor{Whitelist[owner]}] — only the owner, calling directly"
  set_access "$PROJECT" "$PROFILE" "$(and_of "$(whitelist "$PARENT")" "$(via "$(whitelist "$PARENT")")")"
  direct
  # The one place an OLD keystore or worker shows: the owner's own direct call
  # is refused for a reason that is about the deployment, not the condition.
  if [[ "$RUN_OK" == "false" ]] && grep -qiE "reports none|no calling account|parse access condition|unknown variant" <<<"$RUN_ERR"; then
    fail "P1 the owner's direct call was refused for the DEPLOYMENT, not the rule: '$(head -c 240 <<<"$RUN_ERR")' — keystore and worker must both carry the Predecessor code"
    delete_row "$PROJECT" "$PROFILE"
    verdict "secret predecessor"; exit $?
  fi
  expect_admitted P1 "direct"
  relay_via "$DEPUTY"
  expect_refused P1 "through $DEPUTY" "called from $DEPUTY" "" strict
fi

# ── P2 no re-encryption ──────────────────────────────────────────────────────
if want P2; then
  log "P2 the ciphertext is untouched by naming a calling account"
  # Its own edit, so the row stands on its own under ONLY=P2.
  set_access "$PROJECT" "$PROFILE" "$(and_of "$(whitelist "$PARENT")" "$(via "$(whitelist "$PARENT" "$DEPUTY")")")"
  if [[ -n "$CIPHER_BEFORE" && "$(ciphertext_of)" == "$CIPHER_BEFORE" ]]; then
    pass "P2 the stored ciphertext is byte-identical across the edit"
  else
    fail "P2 the ciphertext changed when the condition did"
  fi
fi

# ── P3 through one relay only ────────────────────────────────────────────────
if want P3; then
  log "P3 And[Whitelist[owner], Predecessor{Whitelist[$DEPUTY]}] — composable through this relay and no other"
  set_access "$PROJECT" "$PROFILE" "$(and_of "$(whitelist "$PARENT")" "$(via "$(whitelist "$DEPUTY")")")"
  relay_via "$DEPUTY"
  expect_admitted P3 "through $DEPUTY"
  relay_via "$DEPUTY2"
  expect_refused P3 "through $DEPUTY2" "called from $DEPUTY2" "" strict
  direct
  expect_refused P3 "direct" "called from $PARENT" "" strict
fi

# ── P4 not through this one ──────────────────────────────────────────────────
if want P4; then
  log "P4 And[Whitelist[owner], Not{Predecessor{Whitelist[$DEPUTY]}}] — anything but this relay"
  set_access "$PROJECT" "$PROFILE" "$(and_of "$(whitelist "$PARENT")" "$(not_of "$(via "$(whitelist "$DEPUTY")")")")"
  direct
  expect_admitted P4 "direct"
  relay_via "$DEPUTY"
  expect_refused P4 "through $DEPUTY" "called from $DEPUTY" "" strict
  relay_via "$DEPUTY2"
  expect_admitted P4 "through $DEPUTY2"
fi

# ── P5 a pattern inside the wrapper ──────────────────────────────────────────
if want P5; then
  PARENT_RE=$(sed 's/\./\\./g' <<<"$PARENT")
  log "P5 Predecessor{AccountPattern{deputy2?\\.$PARENT_RE}} — a pattern nested in the wrapper is compiled and judged on the caller's contract"
  set_access "$PROJECT" "$PROFILE" "$(and_of "$(whitelist "$PARENT")" "$(via "$(pattern "deputy2?\\.$PARENT_RE")")")"
  relay_via "$DEPUTY"
  expect_admitted P5 "through $DEPUTY"
  relay_via "$DEPUTY2"
  expect_admitted P5 "through $DEPUTY2"
  direct
  expect_refused P5 "direct" "called from $PARENT"
fi

# ── P6 a stranger, and what the refusal must not say ─────────────────────────
if want P6; then
  log "P6 a stranger calls P1's row directly — refused, the facts stated, nothing blamed"
  set_access "$PROJECT" "$PROFILE" "$(and_of "$(whitelist "$PARENT")" "$(via "$(whitelist "$PARENT")")")"
  direct_as "$STRANGER"
  expect_refused P6 "$STRANGER direct" "signer $STRANGER, called from $STRANGER" "admits|directly" strict
fi

# ── P7 the wrapper alone admits ──────────────────────────────────────────────
if want P7; then
  log "P7 Or[Whitelist[nobody], Predecessor{Whitelist[$DEPUTY]}] — the calling account admits when nothing names the signer"
  set_access "$PROJECT" "$PROFILE" "$(or_of "$(whitelist "nobody-$$.testnet")" "$(via "$(whitelist "$DEPUTY")")")"
  relay_via "$DEPUTY"
  expect_admitted P7 "through $DEPUTY (the signer is named nowhere)"
  direct
  expect_refused P7 "direct" "called from $PARENT"
fi

# ── P8 a chain-read leaf inside ──────────────────────────────────────────────
if ! want P8; then
  :
elif [[ -z "$DAO_CONTRACT" ]]; then
  skip "P8 needs DAO_CONTRACT (a sputnik DAO whose $DAO_ROLE names $PARENT)"
elif ! jq -e --arg p "$PARENT" --arg r "$DAO_ROLE" '.roles[]? | select(.name==$r) | .kind.Group // [] | index($p)' \
       <<<"$(near_view "$DAO_CONTRACT" get_policy '{}' 2>/dev/null)" >/dev/null 2>&1; then
  # The row proves nothing unless $PARENT really is in that role: read the
  # policy the keystore reads, and step aside loudly if the fixture drifted.
  skip "P8 $PARENT is not in $DAO_CONTRACT/$DAO_ROLE (Group) — point DAO_CONTRACT at a DAO whose $DAO_ROLE names $PARENT"
else
  log "P8 Predecessor{DaoMember{$DAO_CONTRACT, $DAO_ROLE}} — membership is asked about the CALLING account"
  set_access "$PROJECT" "$PROFILE" "$(and_of "$(whitelist "$PARENT")" "$(via "$(dao_leaf "$DAO_CONTRACT" "$DAO_ROLE")")")"
  direct
  if [[ "$RUN_OK" == "false" ]] && grep -qiE "validation failed|no NEAR client|cannot be evaluated" <<<"$RUN_ERR"; then
    fail "P8 the keystore could not ask the chain: '$(head -c 200 <<<"$RUN_ERR")'"
  else
    expect_admitted P8 "direct (the owner is in the $DAO_ROLE)"
    relay_via "$DEPUTY"
    expect_refused P8 "through $DEPUTY (not a member)" "called from $DEPUTY"
  fi
fi

# ── P9 nested wrappers ───────────────────────────────────────────────────────
if want P9; then
  log "P9 Predecessor{Predecessor{Whitelist[$DEPUTY]}} — stored, and judged as one wrapper"
  set_access "$PROJECT" "$PROFILE" "$(and_of "$(whitelist "$PARENT")" "$(via "$(via "$(whitelist "$DEPUTY")")")")"
  relay_via "$DEPUTY"
  expect_admitted P9 "through $DEPUTY"
  direct
  expect_refused P9 "direct" "called from $PARENT" "" strict
fi

# ── H1 the HTTPS door ────────────────────────────────────────────────────────
if ! want H1; then
  :
elif [[ -z "$PAYMENT_KEY" ]]; then
  skip "H1 needs PAYMENT_KEY (a key owned by $PARENT) — the HTTPS door reports the payer as the calling account"
else
  log "H1 over HTTPS the payer is the calling account: P1's row admits, P3's refuses as a direct call"
  https_run() { LAST_RUN_RELAYED=0; https_post "$PAYMENT_KEY" "$PROJECT" "$(jq -nc --arg o "$PARENT" --arg pr "$PROFILE" \
    '{input:{message:"via-https"}, secrets_ref:{profile:$pr, account_id:$o}}')"; }
  set_access "$PROJECT" "$PROFILE" "$(and_of "$(whitelist "$PARENT")" "$(via "$(whitelist "$PARENT")")")"
  https_run
  expect_admitted H1 "HTTPS on $PARENT's key, Predecessor{Whitelist[owner]}"
  set_access "$PROJECT" "$PROFILE" "$(and_of "$(whitelist "$PARENT")" "$(via "$(whitelist "$DEPUTY")")")"
  https_run
  expect_refused H1 "HTTPS on $PARENT's key, Predecessor{Whitelist[$DEPUTY]}" "called from $PARENT" "called from $DEPUTY" strict
fi

# ── cleanup ──────────────────────────────────────────────────────────────────
log "cleanup"
delete_row "$PROJECT" "$PROFILE"

verdict "secret predecessor"
