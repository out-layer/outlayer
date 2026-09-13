#!/usr/bin/env bash
#
# The adversarial rows of the secrets catalogue: what a hostile or careless
# caller can do to the one secret model, against a PUBLISHED test-secrets
# project. `03_project_model.sh` in the example's tests is the happy path and
# the delegation rows; this is everything that should be REFUSED, and how.
#
# Every refusal here is judged on three things at once: the verdict, the
# STATUS (a 4xx, or a finished call — never a 5xx) and the TIME (an answer, not
# a hang). A refusal that hangs is the row-11 defect of the audit (the worker
# never settled the HTTPS call); such a case is reported as a FINDING with the
# call id rather than as a pass.
#
#   N1  a condition nested 200 deep never sits on chain: the contract refuses it
#   N2  a condition nested 60 deep is stored, evaluated within the call's own
#       timeout, and still decides correctly (owner in, stranger out)
#   M1–M8  a hostile secrets_ref over HTTPS — an account that does not exist,
#       an empty one, 300 characters, unicode, a colon; a profile with a slash,
#       whitespace, 10 KB — is answered, never with a 5xx, never with the secret
#   B1–B4  a malformed secrets_ref SHAPE — no profile, a number for the
#       account, extra fields, a megabyte — is refused at the door, never a 5xx
#   R1  a non-owner's update_access changes nothing: the contract refuses and
#       the row is byte-identical
#   R2  the owner's own empty whitelist refuses the owner's own run; the
#       author's row is untouched, so the project still runs for a caller who
#       names nothing
#   Y1  async:true with a secrets_ref sees the same environment as sync, read
#       back through /calls/{id}
#   S1  a wallet the row does not name is refused, with and without
#       use_bound_identity — a binding moves the name a guest acts as, not
#       access
#   P1  header AND body on a connector: the body's row wins [AGENT_SECRET_MODE;
#       RUN_CONNECTOR_BODY=0 skips it on a coordinator too old to honour a body
#       secrets_ref on the connector path]
#   D3  a wallet with an ACTIVE personal binding names the owner's row and sets
#       use_bound_identity → the secret arrives, `sender` becomes the BOUND
#       account, and `payer` stays the wallet. The third is the point: a binding
#       moves the name a guest acts as, never whose money or whose access
#   D2  the same grant on the ON-CHAIN door: the wallet signs
#       `request_execution` itself and the secret arrives, judged by the
#       transaction's own receipt tree rather than by the send being accepted
#   D9  a wallet with an ACTIVE binding, asking for a row that does not name
#       it, is refused — even though the name it wears is a subaccount of the
#       owner's own account. The control call runs first, so the refusal is
#       known to come from the condition and not from a dead binding
#   C6  the first call after a new version is activated, carrying a secrets_ref
#       → the re-queue path still passes the reference through
#   C8  two agents firing at once, each naming its OWN row: neither ever sees the
#       other's secret. The one thing a single-threaded test cannot show
#   C9  a connector call naming secrets but NO operation → refused for the
#       operation, not for the secrets: nothing is decrypted for a call that
#       will not run
#   D7  the binding is revoked and the grant stands: the wallet keeps reading
#       the secret until the OWNER edits the row. Destructive — it ends the
#       binding D3 and D9 need, so it runs last and only with
#       D7_DESTROY_BINDING=1
#   W1  a custody wallet stores a row of its OWN through /wallet/v1/call,
#       owns it as its implicit account and reads it back; a second wallet
#       is refused by that row's condition. The prerequisite for retiring
#       the agent-secret path: without it a wallet with no named account
#       behind it could keep no secret at all
#   U5  the caller names the AUTHOR's row directly. UNREACHABLE as the plan
#       words it: this project's manifest already declares that profile, so
#       naming it again makes the SAME key arrive twice and the collision rule
#       refuses — which is correct, and is what A7 pins. The row asserts the
#       refusal instead of pretending to compare environments
#   U4  a row stored for project A, named from a call to project B → not found,
#       and B runs without it
#   U11 a profile shaped like an implicit account (64 hex) on a human's row →
#       the CONTRACT refuses the store, naming the owner and saying what to do.
#       The plan (and this suite, at first) expected the keystore's
#       `enforce_agent_secret` to be the gate; it is only the second line
#   D11 a secret named after a system variable → refused AT THE DOOR, before
#       anything is encrypted or stored, with the offending keys named. Three
#       guesses were wrong before this one: the plan expected the contract to
#       refuse, this suite first expected nothing to refuse and the worker to
#       strip at run time. The worker's strip is real but is the SECOND line
#   A4  a DaoMember condition against a real sputnik DAO → a non-member is
#       refused. The admit half needs membership this account does not have
#   U9  a whitelist of 2 000 accounts: it is STORED, it still decides inside the
#       call's own timeout (the 2 000th account is admitted, a stranger refused),
#       and the row's storage_deposit is read before and after — because
#       `update_access` charges NO deposit while it can grow the condition by
#       tens of kilobytes. Whether that is paid for is measured, not assumed
#   K4  the same row overwritten afterwards still works, and the deposit returns
#       to what it was — accounting that closes rather than drifts
#   T1  a grant whose ValidUntil has passed refuses, and the message names the
#       instant (the naming needs a worker carrying access_denied_message; the
#       rows skip themselves on a contract or keystore without ValidUntil)
#   T2  the same grant moved to the future admits
#   T3  until_ns "abc" is refused by the contract; "0" is stored, and the
#       owner's own Or-branch still admits the owner
#   T4  the whole cycle on one row: granted until a future instant and admitted,
#       the instant moved into the past and refused, a later instant and admitted
#       again — with the stored instant read back to the nanosecond and the
#       ciphertext never moving
#
# Needs:
#   PARENT               the project owner, key in the keychain; the outlayer
#                        CLI's credentials must be this account
#   $PARENT/test-secrets published from wasi-examples/test-secrets-example
#                        with ./build.sh (the manifest build); the `author`
#                        profile is stored here if it is missing
#   OWNER_PAYMENT_KEY    (M*, B*, Y1) a payment key owned by PARENT:
#                        `outlayer keys create`, then `outlayer keys show <nonce>`
#   AGENT_PAYMENT_KEY / AGENT_ACCOUNT   (S1, P1) a custody wallet's key and
#                        implicit account — a wallet the rows here never name
#   AGENT_WK             (P1) that wallet's wk_, for `secrets set-for-agent`
#   AGENT2_PAYMENT_KEY / AGENT2_ACCOUNT   (C8) a SECOND custody wallet
#   RUN_CONNECTOR_BODY=0 (P1) skip it against an older coordinator; default 1
#   AGENT_SECRET_MODE    run|skip (tests/lib/agent_secret_mode.sh); P1 is the
#                        one case here that uses the agent-secret mode
#
# Money: ~10 on-chain runs at 0.1 NEAR attached (0.001 charged, the rest
# refunded), a handful of HTTPS calls on the keys above, two storage rows, one
# throwaway sub-account at 1 NEAR on the first run only.
#
# Run:
#   PARENT=you.testnet ./tests/secrets_security_e2e.sh            # dry run: the plan
#   PARENT=you.testnet OWNER_PAYMENT_KEY=… ./tests/secrets_security_e2e.sh --apply
#   ONLY=N1,B4 … --apply                                          # a subset
#
# Two of the plan's rows are UNREACHABLE by construction and are asserted
# nowhere, on purpose: D12 (an HTTPS caller claiming another `context.sender_id`)
# because `HttpsCallRequest` has no such field at all — the guest-visible sender
# is computed server-side as `bound_sender.unwrap_or(sender_id)`; and the
# unknown-sender refusal, for the same kind of reason (every door fills it).
# Writing a live row for either would test the test, not the product.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/hos_common.sh"
source "$SCRIPT_DIR/lib/agent_secret_mode.sh"

PARENT="${PARENT:-}"
PROJECT="${SECRETS_PROJECT:-}"
CONNECTOR_PROJECT="${CONNECTOR_PROJECT:-connectors.outlayer.testnet/connector-probe}"
OWNER_PAYMENT_KEY="${OWNER_PAYMENT_KEY:-}"
AGENT_PAYMENT_KEY="${AGENT_PAYMENT_KEY:-}"
AGENT_ACCOUNT="${AGENT_ACCOUNT:-}"
AGENT_WK="${AGENT_WK:-}"
AGENT2_PAYMENT_KEY="${AGENT2_PAYMENT_KEY:-}"
AGENT2_ACCOUNT="${AGENT2_ACCOUNT:-}"
# D3: the account the agent's wallet is bound to (its binding must be ACTIVE).
BOUND_ASSET="${BOUND_ASSET:-}"
# C6: a published version of $PROJECT to activate, other than the active one.
SWITCH_TO="${SWITCH_TO:-}"
# A real sputnik DAO, for A4. Its `council` must NOT contain $PARENT, which is
# what makes the refusal meaningful.
DAO_CONTRACT="${DAO_CONTRACT:-genesis.sputnikv2.testnet}"
DAO_ROLE="${DAO_ROLE:-council}"
OTHER_PROJECT="${OTHER_PROJECT:-$PARENT/test-storage}"
OUTLAYER_BIN="${OUTLAYER_BIN:-outlayer}"
RUN_CONNECTOR_BODY="${RUN_CONNECTOR_BODY:-1}"
DEPOSIT='0.1 NEAR'

MODE="${1:-}"
if [[ "$MODE" != "--apply" ]]; then
  sed -n '3,112p' "$0" >&2
  echo "  Pass --apply to run." >&2
  exit 0
fi
hos_require
command -v "$OUTLAYER_BIN" >/dev/null || { echo "✗ the outlayer CLI is not on PATH (OUTLAYER_BIN)" >&2; exit 1; }
PROJECT="${PROJECT:-$PARENT/test-secrets}"
source "$SCRIPT_DIR/lib/secrets_common.sh"

STRANGER="xpat.$PARENT"
ROW=sec

# `ONLY=N1,B4` runs a subset (the fixture always runs; every row restores what
# it changed, so any subset leaves the rows as it found them).
want() { [[ -z "${ONLY:-}" ]] || [[ ",$ONLY," == *",$1,"* ]]; }

# `update_access` signed by anyone, reported rather than fatal: the refusals
# here are the point. Waits for finality when the transaction lands.
TRY_OUT=""
try_update_access() { # try_update_access <signer> <project> <profile> <access-json>
  local signer=$1 project=$2 profile=$3 access=$4 flag=with-legacy-keychain before rc
  [[ "$signer" == "$PARENT" ]] && flag=with-keychain
  before=$(jq -r '.updated_at // 0' <<<"$(row_of "$project" "$profile")")
  # The arguments are CONCATENATED and sent as base64: a tree nested past what
  # jq or near-cli will parse (N1 is one) must still reach the contract, whose
  # own parser is the one under test. Profiles here are plain words.
  local args
  args=$(printf '{"accessor":%s,"profile":"%s","new_access":%s}' "$(accessor_json "$project")" "$profile" "$access" | base64 | tr -d '\n')

  # The status is captured into `rc` the instant the call returns. Reading `$?`
  # after an `if … fi` reads the status of the IF, not of the call — which is
  # how a contract's refusal came back from here as acceptance, and made R1
  # report a hole that the chain shows does not exist.
  send() { # send <deposit>
    TRY_OUT=$(near --quiet contract call-function as-transaction "$CONTRACT_ID" update_access \
      base64-args "$args" \
      prepaid-gas '30.0 Tgas' attached-deposit "$1" \
      sign-as "$signer" network-config "$NETWORK" "sign-$flag" send 2>&1)
    return $?
  }

  # `update_access` is payable, and the conditions this helper sends are
  # deliberately hostile — nested past any parser, or malformed — so pricing
  # them through `estimate_storage_cost` is not possible. A flat NEAR keeps
  # every refusal here about the CONDITION rather than about the deposit.
  send '1 NEAR'; rc=$?

  if (( rc != 0 )) && grep -qiE "expired|Tx not found|timed out" <<<"$TRY_OUT"; then
    note "the send expired before the RPC took it, retrying once"
    sleep 5
    send '1 NEAR'; rc=$?
  fi

  if (( rc != 0 )) && grep -qi "accept deposit\|not payable" <<<"$TRY_OUT"; then
    note "the deployed contract predates the update_access deposit: retrying without one"
    send '0 NEAR'; rc=$?
  fi

  (( rc == 0 )) || return 1

  # Only a call that LANDED waits for the row: waiting on a refused one would
  # spend thirty seconds discovering what the refusal already said.
  [[ "$signer" == "$PARENT" ]] && wait_row_after "$project" "$profile" "$before"
  return 0
}

# What a hang MEANS, per section. A reference the contract could never match is
# the coordinator door's to refuse (`well_formed_secrets_ref` → 400
# `invalid_secrets_ref`); a reference it could match, refused by the row's own
# condition, is the worker's to settle (`report_refusal` → `complete_https_call`,
# audit row 11). Both live in the working tree: against a coordinator or a worker
# without them, such a call waits for the timeout sweeper instead of answering.
HANG_FIX="the worker must settle the refused call (audit row 11: report_refusal \
answers complete_https_call) — deploy the worker"

# Whose key may read the call a row made. `/calls/{id}` is authenticated: it
# admits the payment key that owns the call, or the wallet's own credential.
# Polling it without one answers an error rather than a status, which would read
# as a call nobody settled.
POLL_KEY=""

# A refusal's status and time, judged together with its verdict. `answered
# <label>` passes when the door answered at all — 4xx, or a finished call — and
# fails on a 5xx or on silence. A call that came back `pending` is followed for
# a minute; one still pending then is the row-11 hang, reported as a finding.
answered() {
  local label=$1 cid status i
  case "$HTTP_CODE" in
    000) fail "$label: nothing answered within 90 s — $HANG_FIX"; return ;;
    5*)  fail "$label: HTTP $HTTP_CODE — $(head -c 200 <<<"$ANS")"; return ;;
  esac
  status=$(jq -r '.status // ""' <<<"$ANS" 2>/dev/null)
  cid=$(jq -r '.call_id // ""' <<<"$ANS" 2>/dev/null)
  if [[ "$HTTP_CODE" == 2* && -n "$cid" && "$status" != "completed" && "$status" != "failed" ]]; then
    local polled poll_http
    for i in $(seq 1 20); do
      sleep 3
      polled=$(curl -sS --max-time 20 -w '\nHTTP:%{http_code}' "$COORDINATOR_URL/calls/$cid" \
        ${POLL_KEY:+-H "X-Payment-Key: $POLL_KEY"} 2>/dev/null)
      poll_http=${polled##*HTTP:}
      if [[ "$poll_http" != 2* ]]; then
        skip "$label: the call's status could not be read (HTTP $poll_http) — this row measures settlement, and that needs the key owning the call"
        return
      fi
      status=$(jq -r '.status // ""' <<<"${polled%$'\n'HTTP:*}" 2>/dev/null)
      [[ "$status" == "completed" || "$status" == "failed" ]] && break
    done
    if [[ "$status" != "completed" && "$status" != "failed" ]]; then
      finding "$label: call $cid is still '$status' a minute later — a refused run nobody settled (audit row 11; the worker redeploy)"
      return
    fi
  fi
  pass "$label: answered HTTP $HTTP_CODE${status:+, status $status}${RUN_ERR:+ — $(head -c 120 <<<"$RUN_ERR")}"
}

deep() { # deep <n> — the owner's whitelist under n NOTs (even n: the same verdict)
  jq -nc --arg p "$PARENT" --argjson n "$1" \
    'reduce range($n) as $i ({Whitelist:{accounts:[$p]}}; {Not:{condition:.}})'
}

# ── fixture ──────────────────────────────────────────────────────────────────
log "Fixture: the project, the stranger, the rows"
PROJECT_VIEW=$(near_view "$CONTRACT_ID" get_project "$(jq -nc --arg p "$PROJECT" '{project_id:$p}')")
if [[ -z "$PROJECT_VIEW" || "$PROJECT_VIEW" == "null" || "$PROJECT_VIEW" == "ERR" ]]; then
  skip "$PROJECT is not deployed — ./build.sh, outlayer upload, outlayer deploy test-secrets (see the example's README)"
  verdict "secrets security"; exit $?
fi
note "project: $PROJECT"
make_account "$STRANGER" "$PARENT" '1 NEAR'

if [[ -z "$(jq -r '.encrypted_secrets // empty' <<<"$(row_of "$PROJECT" author)")" ]]; then
  store "$PROJECT" author "$(jq -nc --arg v "author-$(openssl rand -hex 6)" '{AUTHOR_SECRET:$v}')" allow-all
else
  note "the author profile is stored; left as it is"
fi
USER_CANARY="user-$(openssl rand -hex 6)"
store "$PROJECT" "$ROW" "$(jq -nc --arg v "$USER_CANARY" '{USER_SECRET:$v}')" "whitelist:$PARENT"
restore_row() { set_access "$PROJECT" "$ROW" "$(whitelist "$PARENT")"; }
trap 'restore_row >/dev/null 2>&1 || true' EXIT

# ── N nesting ────────────────────────────────────────────────────────────────
if want N1; then
log "N1 a condition nested 200 deep"
BEFORE=$(row_of "$PROJECT" "$ROW")
if try_update_access "$PARENT" "$PROJECT" "$ROW" "$(deep 200)"; then
  finding "N1 the contract STORED a 200-deep condition: $(head -c 100 <<<"$TRY_OUT")"
  run_as "$PARENT" "$PARENT/$ROW"
  [[ "$RUN_OK" != "absent" ]] \
    && pass "N1 and the keystore still answered (success=$RUN_OK): no hang" \
    || fail "N1 the run never completed"
  restore_row
else
  pass "N1 the contract refused to store it: $(grep -o 'Smart contract panicked[^"]\{0,90\}\|[Rr]ecursion[^"]\{0,60\}\|Error:[^"]\{0,80\}' <<<"$TRY_OUT" | head -1)"
  [[ "$(row_of "$PROJECT" "$ROW")" == "$BEFORE" ]] \
    && pass "N1 and the row is byte-identical" \
    || fail "N1 the row changed under a refused update"
fi

fi

if want N2; then
log "N2 a condition nested 60 deep still decides, in time"
set_access "$PROJECT" "$ROW" "$(deep 60)"
run_as "$PARENT" "$PARENT/$ROW"
[[ "$RUN_OK" == "true" && "$(field .user)" == "true" && "$(secret_value USER_SECRET)" == "$USER_CANARY" ]] \
  && pass "N2 the owner is admitted through 60 NOTs and reads the canary" \
  || fail "N2 owner: success=$RUN_OK user=$(field .user) err='$RUN_ERR'"
run_as "$STRANGER" "$PARENT/$ROW"
[[ "$RUN_OK" == "false" ]] \
  && pass "N2 the stranger is refused through the same tree: $(head -c 100 <<<"$RUN_ERR")" \
  || fail "N2 stranger: success=$RUN_OK user=$(field .user)"
restore_row

fi

# ── M/B hostile references over HTTPS ────────────────────────────────────────
if ! want M && ! want B && ! want Y1; then
  :
elif [[ -z "$OWNER_PAYMENT_KEY" ]]; then
  skip "M1–M8, B1–B4, Y1 need OWNER_PAYMENT_KEY (a payment key owned by $PARENT)"
else
  # M and B name rows the contract could never hold. EITHER deploy clears them:
  # the coordinator's door check stops such a reference before a job exists, and
  # the worker's refusal path settles the call if one is already running.
  HANG_FIX="either deploy clears this: the coordinator refuses the reference at the door \
(invalid_secrets_ref, 400), or the worker settles the refused call (audit row 11)"
  POLL_KEY="$OWNER_PAYMENT_KEY"
  if want M; then
  log "M a hostile secrets_ref is answered, never with a 5xx, never with the secret"
  m_row() { # m_row <id> <account_id> <profile> <what>
    https_post "$OWNER_PAYMENT_KEY" "$PROJECT" \
      "$(jq -nc --arg a "$2" --arg pr "$3" '{input:{message:"probe"}, secrets_ref:{account_id:$a, profile:$pr}}')"
    answered "$1 $4"
    [[ -z "$(secret_value USER_SECRET)" ]] \
      && pass "$1 and no secret reached the guest" \
      || fail "$1 USER_SECRET reached the guest through '$2'/'$3'"
  }
  m_row M1 "nobody-$(openssl rand -hex 4).testnet" "$ROW" "an account that does not exist"
  m_row M2 "" "$ROW" "an empty account"
  m_row M3 "$(head -c 300 /dev/zero | tr '\0' a).testnet" "$ROW" "a 300-character account"
  m_row M4 "ünïcödé.testnet" "$ROW" "a unicode account"
  m_row M5 "$PARENT:$ROW" "$ROW" "an account with a colon"
  m_row M6 "$PARENT" "$ROW/../author" "a profile with slashes"
  m_row M7 "$PARENT" "   " "a whitespace profile"
  m_row M8 "$PARENT" "$(head -c 10240 /dev/zero | tr '\0' p)" "a 10 KB profile"

  fi
  if want B; then
  log "B a malformed secrets_ref shape is refused at the door"
  b_row() { # b_row <id> <raw-body> <what>
    https_post "$OWNER_PAYMENT_KEY" "$PROJECT" "$2"
    case "$HTTP_CODE" in
      4*) pass "$1 $3 → HTTP $HTTP_CODE: $(head -c 100 <<<"$RUN_ERR")" ;;
      5*|000) fail "$1 $3 → HTTP $HTTP_CODE — $HANG_FIX" ;;
      *) note "$1 $3 was ACCEPTED (HTTP $HTTP_CODE) — the field was ignored rather than refused"; answered "$1 $3" ;;
    esac
  }
  b_row B1 '{"input":{"message":"probe"},"secrets_ref":{"account_id":"nobody.testnet"}}' "no profile"
  b_row B2 '{"input":{"message":"probe"},"secrets_ref":{"account_id":42,"profile":"p"}}' "a number for the account"
  b_row B3 "$(jq -nc --arg p "$PARENT" '{input:{message:"probe"}, secrets_ref:{account_id:$p, profile:"nope", extra:1}}')" "an extra field"
  # A megabyte does not fit in an argument (ARG_MAX), so the body goes through
  # a file — `@path`, which curl reads and https_post passes on as it is.
  BIG=$(mktemp -t secsec_big.XXXXXX)
  { printf '{"input":{"message":"probe"},"secrets_ref":{"account_id":"%s","profile":"' "$PARENT"; head -c 1048576 /dev/zero | tr '\0' q; printf '"}}'; } > "$BIG"
  b_row B4 "@$BIG" "a one-megabyte profile (a size the contract's 64 characters cannot hold)"
  rm -f "$BIG"

  fi
  if want Y1; then
  log "Y1 async: the same environment, read back through /calls/{id}"
  https_post "$OWNER_PAYMENT_KEY" "$PROJECT" \
    "$(jq -nc --arg a "$PARENT" --arg pr "$ROW" '{input:{message:"probe"}, secrets_ref:{account_id:$a, profile:$pr}, async:true}')"
  CID=$(jq -r '.call_id // ""' <<<"$ANS" 2>/dev/null)
  if [[ "$HTTP_CODE" != 2* || -z "$CID" ]]; then
    fail "Y1 the async call was not accepted (HTTP $HTTP_CODE): $(head -c 160 <<<"$ANS")"
  else
    STATUS=""; POLLED=""
    for i in $(seq 1 30); do
      sleep 3
      POLLED=$(curl -sS --max-time 20 "$COORDINATOR_URL/calls/$CID" -H "X-Payment-Key: $OWNER_PAYMENT_KEY" 2>/dev/null)
      STATUS=$(jq -r '.status // ""' <<<"$POLLED" 2>/dev/null)
      [[ "$STATUS" == "completed" || "$STATUS" == "failed" ]] && break
    done
    RUN_OUT=$(jq -c '.output | if type=="string" then fromjson else . end' <<<"$POLLED" 2>/dev/null)
    [[ "$STATUS" == "completed" && "$(field .user)" == "true" && "$(secret_value USER_SECRET)" == "$USER_CANARY" ]] \
      && pass "Y1 completed through the poll with the owner's canary in the environment" \
      || fail "Y1 status=$STATUS user=$(field .user) err='$(jq -r '.error // ""' <<<"$POLLED" 2>/dev/null)'"
  fi
  fi
fi

# ── R update_access ──────────────────────────────────────────────────────────
if want R1; then
log "R1 a non-owner's update_access"
BEFORE=$(row_of "$PROJECT" "$ROW")
if try_update_access "$STRANGER" "$PROJECT" "$ROW" "$(whitelist "$STRANGER")"; then
  fail "R1 $STRANGER's update_access on $PARENT's row was ACCEPTED"
else
  pass "R1 refused by the contract: $(grep -o 'Secrets not found\|Smart contract panicked[^"]\{0,60\}' <<<"$TRY_OUT" | head -1)"
fi
sleep 3
[[ "$(row_of "$PROJECT" "$ROW")" == "$BEFORE" ]] \
  && pass "R1 the row is byte-identical" \
  || fail "R1 the row changed under a stranger's update_access"

fi

if want R2; then
log "R2 the owner's empty whitelist"
set_access "$PROJECT" "$ROW" '{"Whitelist":{"accounts":[]}}'
run_as "$PARENT" "$PARENT/$ROW"
[[ "$RUN_OK" == "false" ]] && grep -qi "denied" <<<"$RUN_ERR" \
  && pass "R2 the owner's own run is refused: $(head -c 100 <<<"$RUN_ERR")" \
  || fail "R2 owner: success=$RUN_OK user=$(field .user) err='$RUN_ERR'"
run_as "$PARENT"
[[ "$RUN_OK" == "true" && "$(field .author)" == "true" ]] \
  && pass "R2 and a run naming nothing still gets the author's row — one row's condition touches one row" \
  || fail "R2 the author's row stopped admitting: success=$RUN_OK author=$(field .author) err='$RUN_ERR'"
restore_row

fi

# ── S a wallet the row does not name ─────────────────────────────────────────
if ! want S1; then
  :
elif [[ -z "$AGENT_PAYMENT_KEY" ]]; then
  skip "S1 needs AGENT_PAYMENT_KEY (a custody wallet's key that the row does not name)"
else
  HANG_FIX="the worker must settle the refused call (audit row 11: report_refusal \
answers complete_https_call) — deploy the worker"
  POLL_KEY="$AGENT_PAYMENT_KEY"
  log "S1 a wallet the row does not name, with and without use_bound_identity"
  https_post "$AGENT_PAYMENT_KEY" "$PROJECT" \
    "$(jq -nc --arg a "$PARENT" --arg pr "$ROW" '{input:{message:"probe"}, secrets_ref:{account_id:$a, profile:$pr}}')"
  if [[ "$RUN_OK" == "true" && "$(field .user)" == "true" ]]; then
    fail "S1 an unnamed wallet read the owner's row"
  else
    answered "S1 unnamed wallet"
  fi
  https_post "$AGENT_PAYMENT_KEY" "$PROJECT" \
    "$(jq -nc --arg a "$PARENT" --arg pr "$ROW" '{input:{message:"probe"}, secrets_ref:{account_id:$a, profile:$pr}, use_bound_identity:true}')"
  if [[ "$RUN_OK" == "true" && "$(field .user)" == "true" ]]; then
    fail "S1 use_bound_identity admitted a wallet the row does not name"
  else
    answered "S1 with use_bound_identity"
  fi
fi

# ── P header and body together on a connector ────────────────────────────────
if ! want P1 || ! agent_secret_mode P1; then
  :
elif [[ "$RUN_CONNECTOR_BODY" != "1" ]]; then
  skip "P1 (RUN_CONNECTOR_BODY=0): needs the coordinator that honours a body secrets_ref on the connector path"
elif [[ -z "$AGENT_WK" || -z "$AGENT_PAYMENT_KEY" || -z "$AGENT_ACCOUNT" ]]; then
  skip "P1 needs AGENT_WK, AGENT_PAYMENT_KEY and AGENT_ACCOUNT"
elif ! "$OUTLAYER_BIN" secrets set-for-agent --help >/dev/null 2>&1; then
  skip "P1 '$OUTLAYER_BIN secrets set-for-agent' is not available"
else
  log "P1 header AND body on $CONNECTOR_PROJECT: the body's row wins"
  HDR_TOKEN="from-header-$(openssl rand -hex 4)"
  BODY_TOKEN="from-body-$(openssl rand -hex 4)"
  if ! OUTLAYER_WALLET_KEY="$AGENT_WK" OUTLAYER_NETWORK="$NETWORK" "$OUTLAYER_BIN" secrets set-for-agent \
       "$(jq -nc --arg t "$HDR_TOKEN" '{PROBE_TOKEN:$t}')" --project "$CONNECTOR_PROJECT" >/dev/null 2>&1; then
    fail "P1 could not store the agent's own row with set-for-agent"
  else
    store "$CONNECTOR_PROJECT" both "$(jq -nc --arg t "$BODY_TOKEN" '{PROBE_TOKEN:$t}')" "whitelist:$PARENT,$AGENT_ACCOUNT"
    call_https "$AGENT_PAYMENT_KEY" "$CONNECTOR_PROJECT" "$PARENT/both" '{"operation":"secret"}' -H 'X-Use-Owner-Secret: 1'
    GOT=$(jq -r '.secrets[]? | select(.key=="PROBE_TOKEN") | .sha256_prefix // empty' <<<"$RUN_OUT" 2>/dev/null)
    WANT=$(printf '%s' "$BODY_TOKEN" | shasum -a 256 | cut -c1-8)
    OTHER=$(printf '%s' "$HDR_TOKEN" | shasum -a 256 | cut -c1-8)
    if [[ "$RUN_OK" == "true" && "$GOT" == "$WANT" ]]; then
      pass "P1 the guest saw the BODY's token, not the header's"
    elif [[ "$GOT" == "$OTHER" ]]; then
      fail "P1 the header's row overrode the body's — the coordinator dropped what the body named"
    else
      fail "P1 success=$RUN_OK token=$GOT err='$RUN_ERR'"
    fi
    set_access "$CONNECTOR_PROJECT" both "$(whitelist "$PARENT")"
  fi
fi

# ── U5 naming the author's row directly ──────────────────────────────────────
#
# The author's row is an ordinary row: a caller may name it in `secrets_ref`.
# Doing so must give exactly what the manifest path gives and nothing more — if
# naming it widened anything, the manifest would not be the only way in.
if want U5; then
  log "U5 the caller names the author's own profile"
  run_as "$PARENT" "$PARENT/author"
  # The manifest names `author` too, so the key arrives from both sides and the
  # merge refuses. Asserting "the same environment, nothing more" would be
  # asserting something the collision rule forbids.
  if [[ "$RUN_OK" == "false" ]] && grep -q "both define" <<<"$RUN_ERR"; then
    pass "U5 refused as a collision, because the manifest declares that profile too: $(head -c 110 <<<"$RUN_ERR")"
  elif [[ "$RUN_OK" == "true" ]]; then
    fail "U5 the same profile arrived from the manifest AND the call, and the run proceeded — the collision rule did not fire"
  else
    fail "U5 refused for something other than the collision: $(head -c 160 <<<"$RUN_ERR")"
  fi
  note "U5 as the plan words it (naming the author's row for an identical environment) is unreachable on a project whose manifest declares that profile"
fi

# ── U4 a row belonging to another project ────────────────────────────────────
#
# Rows are keyed by accessor. A row stored for project A must be invisible to a
# call to project B even when B's caller names it, and B must still RUN — a
# missing row is not a refusal.
if ! want U4; then
  :
elif [[ -z "$(jq -r '.encrypted_secrets // empty' <<<"$(row_of "$OTHER_PROJECT" u4)" 2>/dev/null)" ]]; then
  store "$OTHER_PROJECT" u4 "$(jq -nc --arg v "other-project-$(openssl rand -hex 4)" '{USER_SECRET:$v}')" allow-all
  U4_READY=1
else
  U4_READY=1
fi
if want U4 && [[ "${U4_READY:-}" == "1" ]]; then
  log "U4 a row stored for $OTHER_PROJECT, named from a call to $PROJECT"
  run_as "$PARENT" "$PARENT/u4"
  if [[ "$RUN_OK" == "true" ]]; then
    [[ -z "$(secret_value USER_SECRET)" && "$(field .user)" == "false" ]] \
      && pass "U4 the other project's row was not found, and this project ran anyway" \
      || fail "U4 a row stored for $OTHER_PROJECT reached a run of $PROJECT: user=$(field .user) value='$(secret_value USER_SECRET)'"
  else
    # A refusal is also wrong here: not-found must not stop the run.
    fail "U4 the run was REFUSED rather than continuing without the missing row: $(head -c 140 <<<"$RUN_ERR")"
  fi
fi

# ── U11 a profile shaped like an implicit account ─────────────────────────────
#
# `enforce_agent_secret` fires on any 64-hex PROFILE and then demands
# profile == caller AND profile == owner. A named account can satisfy neither, so
# such a row is readable by nobody — including the owner who stored it. That is
# the trap the interfaces are supposed to warn about at store time.
if want U11; then
  log "U11 a 64-hex profile on a human's row is refused at the contract"
  U11_PROFILE=$(openssl rand -hex 32)
  # Deliberately NOT the `store` helper: that one exits on failure, and a
  # refusal is the expected result here.
  U11_OUT=$(OUTLAYER_NETWORK="$NETWORK" "$OUTLAYER_BIN" secrets set \
    "$(jq -nc --arg v "u11-$(openssl rand -hex 4)" '{USER_SECRET:$v}')" \
    --project "$PROJECT" --profile "$U11_PROFILE" --access allow-all 2>&1)
  if grep -q "names an AGENT" <<<"$U11_OUT"; then
    pass "U11 the contract refused the store and named the owner: $(grep -o 'A profile of 64 hex[^"]*' <<<"$U11_OUT" | head -c 150)"
  elif grep -qiE "error|panick" <<<"$U11_OUT"; then
    fail "U11 refused, but not by the profile rule: $(tail -2 <<<"$U11_OUT" | head -c 200)"
  else
    fail "U11 a 64-hex profile was STORED under $PARENT — an agent-shaped row now exists for a named account"
    delete_row "$PROJECT" "$U11_PROFILE"
  fi
  [[ -z "$(jq -r '.encrypted_secrets // empty' <<<"$(row_of "$PROJECT" "$U11_PROFILE")")" ]] \
    && pass "U11 and nothing was left on chain" \
    || fail "U11 a row exists on chain for the refused profile"
fi

# ── D11 a secret named after a system variable ────────────────────────────────
#
# The plan expected `store_secrets` to refuse these. It does not — there is no
# such check in the contract. The defence is the WORKER stripping every
# SYSTEM_ENV_VARS name from the merged map before writing its own, so the row
# stores and is then neutralised. Asserting the plan's version would have
# encoded an expectation the system does not make.
if want D11; then
  log "D11 a secret named NEAR_SENDER_ID and NEAR_USER_ACCOUNT_ID"
  # NOT the `store` helper: it exits on failure, and a refusal is the result.
  D11_OUT=$(OUTLAYER_NETWORK="$NETWORK" "$OUTLAYER_BIN" secrets set \
    '{"NEAR_SENDER_ID":"forged-sender","NEAR_USER_ACCOUNT_ID":"forged-payer"}' \
    --project "$PROJECT" --profile d11 --access allow-all 2>&1)
  if grep -qi "reserved system keyword" <<<"$D11_OUT"; then
    pass "D11 refused before anything was encrypted: $(grep -o 'Cannot use reserved system keywords[^"]*' <<<"$D11_OUT" | head -c 140)"
    grep -q "NEAR_SENDER_ID" <<<"$D11_OUT" && grep -q "NEAR_USER_ACCOUNT_ID" <<<"$D11_OUT" \
      && pass "D11 and it names BOTH offending keys, so the owner knows what to rename" \
      || fail "D11 the refusal does not name both keys: $(head -c 200 <<<"$D11_OUT")"
  elif grep -qiE "error|panick" <<<"$D11_OUT"; then
    fail "D11 refused, but not by the reserved-name rule: $(tail -2 <<<"$D11_OUT" | head -c 220)"
  else
    fail "D11 a secret named after system variables was STORED"
  fi
  [[ -z "$(jq -r '.encrypted_secrets // empty' <<<"$(row_of "$PROJECT" d11)")" ]] \
    && pass "D11 and nothing was left on chain" \
    || fail "D11 a row exists on chain for the refused profile"
  note "D11 the worker's strip of SYSTEM_ENV_VARS is the second line, unit-covered by no_secret_can_occupy_a_system_variable_on_either_path; reaching it live would need ciphertext stored by a route that skips this door — uncovered"
fi

# ── A4 a DaoMember condition ──────────────────────────────────────────────────
#
# The keystore answers this by calling `get_policy` on the DAO and looking for
# the caller in the named role. Only the REFUSAL half is asserted: the councils
# of the public testnet DAOs do not contain this account, and membership is not
# something it can grant itself. The admit half stays uncovered, and the
# catalogue says so.
if want A4; then
  log "A4 a DaoMember condition against $DAO_CONTRACT role $DAO_ROLE"
  set_access "$PROJECT" "$ROW" "$(jq -nc --arg d "$DAO_CONTRACT" --arg r "$DAO_ROLE" '{DaoMember:{dao_contract:$d, role:$r}}')"
  run_as "$PARENT" "$PARENT/$ROW"
  if [[ "$RUN_OK" == "false" ]] && grep -qi "denied" <<<"$RUN_ERR"; then
    pass "A4 a non-member of $DAO_ROLE is refused: $(head -c 120 <<<"$RUN_ERR")"
  elif [[ "$RUN_OK" == "true" ]]; then
    fail "A4 $PARENT was ADMITTED by a DaoMember condition naming a council it is not in"
  else
    fail "A4 refused for something other than the condition: $(head -c 160 <<<"$RUN_ERR")"
  fi
  note "A4 the admit half needs membership in $DAO_CONTRACT/$DAO_ROLE — uncovered"
  restore_row
fi

# ── D3 a bound wallet reading the owner's row ────────────────────────────────
#
# The whole grant model rests on one separation: a binding moves the NAME a guest
# acts as and nothing else. So this asserts three things at once, and the third
# carries it — if `payer` followed the binding, every grant and every quota would
# be attributed to an account that paid nothing.
if ! want D3; then
  :
elif [[ -z "$AGENT_PAYMENT_KEY" || -z "$AGENT_ACCOUNT" || -z "$BOUND_ASSET" ]]; then
  skip "D3 needs AGENT_PAYMENT_KEY, AGENT_ACCOUNT and BOUND_ASSET (the account that wallet is bound to, binding ACTIVE)"
else
  log "D3 the agent names the owner's row while acting as $BOUND_ASSET"
  set_access "$PROJECT" "$ROW" "$(whitelist "$PARENT" "$AGENT_ACCOUNT")"
  https_post "$AGENT_PAYMENT_KEY" "$PROJECT" \
    "$(jq -nc --arg a "$PARENT" --arg pr "$ROW" '{input:{message:"d3"}, secrets_ref:{account_id:$a, profile:$pr}, use_bound_identity:true}')"
  if [[ "$RUN_OK" != "true" ]]; then
    fail "D3 the bound run did not complete: HTTP $HTTP_CODE $(head -c 160 <<<"$RUN_ERR")"
  else
    [[ "$(secret_value USER_SECRET)" == "$USER_CANARY" ]] \
      && pass "D3 the grant still admits the wallet while it acts as another name" \
      || fail "D3 the canary did not arrive: got '$(secret_value USER_SECRET)'"
    [[ "$(field .sender)" == "$BOUND_ASSET" ]] \
      && pass "D3 sender became the BOUND account ($BOUND_ASSET)" \
      || fail "D3 sender is '$(field .sender)', expected $BOUND_ASSET"
    [[ "$(field .payer)" == "$AGENT_ACCOUNT" ]] \
      && pass "D3 and the PAYER did not move — access and money follow the wallet, not the name" \
      || fail "D3 payer is '$(field .payer)', expected $AGENT_ACCOUNT — billing followed a binding"
  fi
  restore_row
fi

# ── D2 the same grant, on the ON-CHAIN door ──────────────────────────────────
#
# D1 (in the example's `03`) grants a wallet and lets it read the owner's row
# over HTTPS. This is that same grant through the other door: the wallet signs
# `request_execution` itself, through `POST /wallet/v1/call`, because the
# executor's key lives inside the enclave and cannot be signed with locally.
#
# WHAT IT JUDGES BY, and why that matters here more than anywhere else.
# `request_execution` yields: the send returns a transaction hash long before
# anything runs, so a row that stopped at "the call was accepted" would be green
# whether or not the secret ever arrived. The subject is the transaction's own
# receipt tree — the `execution_completed` event for success and the sender, and
# the module's logged answer for the canary. A run that never completes is
# reported as such, never as a pass.
if ! want D2; then
  :
elif [[ -z "$AGENT_WK" || -z "$AGENT_ACCOUNT" ]]; then
  skip "D2 needs AGENT_WK and AGENT_ACCOUNT (the wallet signs this one itself)"
else
  log "D2 the wallet sends request_execution naming the owner's row"
  set_access "$PROJECT" "$ROW" "$(whitelist "$PARENT" "$AGENT_ACCOUNT")"

  D2_ARGS=$(jq -nc --arg p "$PROJECT" --arg o "$PARENT" --arg pr "$ROW" \
    '{source:{Project:{project_id:$p}}, input_data:"{\"message\":\"d2\"}",
      secrets_ref:{profile:$pr, account_id:$o},
      resource_limits:{max_instructions:1000000000,max_memory_mb:128,max_execution_seconds:30}}')
  D2_ANS=$(curl -sS --max-time 180 -X POST "$COORDINATOR_URL/wallet/v1/call" \
    -H "Authorization: Bearer $AGENT_WK" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg c "$CONTRACT_ID" --argjson a "$D2_ARGS" \
      '{receiver_id:$c, method_name:"request_execution", args:$a,
        gas:"300000000000000", deposit:"100000000000000000000000"}')" 2>&1)
  D2_TX=$(jq -r '.tx_hash // empty' <<<"$D2_ANS" 2>/dev/null)

  if [[ -z "$D2_TX" ]]; then
    fail "D2 the wallet could not send request_execution: $(head -c 220 <<<"$D2_ANS")"
  else
    note "D2 transaction $D2_TX"
    # The run finishes in a receipt of this same transaction, but not at once.
    # Polling the tree is the only way to judge the RUN rather than the send.
    D2_LOGS=""
    for _ in $(seq 1 20); do
      D2_LOGS=$(curl -sS --max-time 45 "$RPC_URL" -X POST -H 'Content-Type: application/json' \
        -d "$(jq -nc --arg t "$D2_TX" --arg s "$AGENT_ACCOUNT" \
          '{jsonrpc:"2.0",id:1,method:"tx",params:{tx_hash:$t,sender_account_id:$s,wait_until:"FINAL"}}')" \
        | jq -r '[.result.receipts_outcome[]?.outcome.logs[]?] | join("\n")' 2>/dev/null)
      grep -q "execution_completed" <<<"$D2_LOGS" && break
      sleep 6
    done

    if ! grep -q "execution_completed" <<<"$D2_LOGS"; then
      fail "D2 no completion event in $D2_TX after two minutes — the run did not finish, so nothing here is a verdict about secrets"
    else
      D2_EV=$(grep -o 'EVENT_JSON:.*execution_completed.*' <<<"$D2_LOGS" | sed 's/^EVENT_JSON://' | head -1)
      D2_OK=$(jq -r '.data[0].success // "absent"' <<<"$D2_EV" 2>/dev/null)
      D2_SENDER=$(jq -r '.data[0].sender_id // ""' <<<"$D2_EV" 2>/dev/null)
      [[ "$D2_OK" == "true" ]] \
        && pass "D2 the on-chain run completed" \
        || fail "D2 the on-chain run failed: $(jq -r '.data[0].error_message // ""' <<<"$D2_EV" | head -c 200)"
      [[ "$D2_SENDER" == "$AGENT_ACCOUNT" ]] \
        && pass "D2 the sender on chain is the wallet itself ($AGENT_ACCOUNT)" \
        || fail "D2 the event names sender '$D2_SENDER', expected $AGENT_ACCOUNT"
      # The module's answer is the transaction's RETURN VALUE, not its logs: the
      # contract logs a preview truncated at 100 characters, which cuts off
      # before the interesting keys and would report a secret that arrived as
      # missing.
      D2_OUT=$(curl -sS --max-time 45 "$RPC_URL" -X POST -H 'Content-Type: application/json' \
        -d "$(jq -nc --arg t "$D2_TX" --arg s "$AGENT_ACCOUNT" \
          '{jsonrpc:"2.0",id:1,method:"tx",params:{tx_hash:$t,sender_account_id:$s,wait_until:"FINAL"}}')" \
        | jq -r '.result.status.SuccessValue // empty' | base64 --decode 2>/dev/null \
        | jq -r 'if type=="string" then fromjson else . end' 2>/dev/null)
      D2_VALUE=$(jq -r '.secrets[]? | select(.key=="USER_SECRET") | .value // empty' <<<"$D2_OUT" 2>/dev/null)
      if [[ "$D2_VALUE" == "$USER_CANARY" ]]; then
        pass "D2 the owner's secret reached the guest through the on-chain door"
      else
        fail "D2 the run completed but USER_SECRET came back as '$D2_VALUE', expected the canary — the grant did not carry across the doors"
      fi
      [[ "$(jq -r '.payer // ""' <<<"$D2_OUT")" == "$AGENT_ACCOUNT" ]] \
        && pass "D2 and the payer in the module's own answer is the wallet" \
        || fail "D2 the module saw payer '$(jq -r '.payer // ""' <<<"$D2_OUT")', expected $AGENT_ACCOUNT"
    fi
  fi
  restore_row
fi

# ── D9 a BOUND wallet the row does not name ──────────────────────────────────
#
# The catalogue words this as a stranger's wallet bound to the stranger's own
# account. This runs it in a sharper form: the wallet is bound to a subaccount
# of the OWNER's own name, so the bound identity is as close to the owner as a
# binding can put it, and it still buys nothing. Access is judged on the payer.
#
# Two calls, in this order, because the second means nothing without the first.
# A refusal proves the condition gated the run only if the very same call was
# admitted a moment earlier — otherwise a suspended binding, an expired key or
# a typo in the profile would read exactly like a working access rule.
if ! want D9; then
  :
elif [[ -z "$AGENT_PAYMENT_KEY" || -z "$AGENT_ACCOUNT" || -z "$BOUND_ASSET" ]]; then
  skip "D9 needs AGENT_PAYMENT_KEY, AGENT_ACCOUNT and BOUND_ASSET (that wallet's binding ACTIVE)"
else
  log "D9 the same bound call, once named by the row and once not"
  D9_BODY=$(jq -nc --arg a "$PARENT" --arg pr "$ROW" \
    '{input:{message:"d9"}, secrets_ref:{account_id:$a, profile:$pr}, use_bound_identity:true}')

  set_access "$PROJECT" "$ROW" "$(whitelist "$PARENT" "$AGENT_ACCOUNT")"
  POLL_KEY="$AGENT_PAYMENT_KEY"
  https_post "$AGENT_PAYMENT_KEY" "$PROJECT" "$D9_BODY"
  if [[ "$RUN_OK" == "true" && "$(field .sender)" == "$BOUND_ASSET" ]]; then
    pass "D9 the binding is live: the guest acts as $BOUND_ASSET and the grant admits it"
  else
    fail "D9 the control call did not run bound — success=$RUN_OK sender='$(field .sender)' err='$(head -c 140 <<<"$RUN_ERR")'. Nothing below would mean anything, so the refusal half is not judged"
    D9_SKIP=1
  fi

  if [[ "${D9_SKIP:-0}" != "1" ]]; then
    set_access "$PROJECT" "$ROW" "$(whitelist "$PARENT")"
    https_post "$AGENT_PAYMENT_KEY" "$PROJECT" "$D9_BODY"
    if [[ "$(secret_value USER_SECRET)" == "$USER_CANARY" ]]; then
      fail "D9 the secret arrived at a wallet the row does not name — a binding widened access"
    elif [[ "$RUN_OK" == "false" ]] && grep -qi "denied\|permission" <<<"$RUN_ERR"; then
      pass "D9 refused once the row stopped naming the wallet, though the name it wears is the owner's own subaccount"
    else
      fail "D9 neither admitted nor clearly refused: success=$RUN_OK err='$(head -c 160 <<<"$RUN_ERR")'"
    fi
  fi
  unset D9_SKIP
  restore_row
fi

# ── C6 the first call after a version switch ──────────────────────────────────
#
# Activating a version means the next call finds no compiled wasm cached, so the
# coordinator compiles and RE-QUEUES the execute task. A reference dropped on
# that path would strand exactly the first caller after every publish.
if ! want C6; then
  :
elif [[ -z "$OWNER_PAYMENT_KEY" || -z "$SWITCH_TO" ]]; then
  skip "C6 needs OWNER_PAYMENT_KEY and SWITCH_TO (a published version of $PROJECT to activate)"
else
  log "C6 activating $SWITCH_TO, then the first call with a secrets_ref"
  WAS_ACTIVE=$(near_view "$CONTRACT_ID" get_project "$(jq -nc --arg p "$PROJECT" '{project_id:$p}')" | jq -r '.active_version // empty')
  [[ -n "$WAS_ACTIVE" ]] || { fail "C6 could not read the current active version"; WAS_ACTIVE=""; }
  activate() { # activate <version_key>
    near --quiet contract call-function as-transaction "$CONTRACT_ID" set_active_version \
      json-args "$(jq -nc --arg n "${PROJECT#*/}" --arg v "$1" '{project_name:$n, version_key:$v}')" \
      prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR' \
      sign-as "$PARENT" network-config "$NETWORK" sign-with-keychain send >/dev/null 2>&1
  }
  if [[ -n "$WAS_ACTIVE" ]] && activate "$SWITCH_TO"; then
    https_post "$OWNER_PAYMENT_KEY" "$PROJECT" \
      "$(jq -nc --arg a "$PARENT" --arg pr "$ROW" '{input:{message:"c6"}, secrets_ref:{account_id:$a, profile:$pr}}')"
    if [[ "$RUN_OK" == "true" && "$(secret_value USER_SECRET)" == "$USER_CANARY" ]]; then
      pass "C6 the first call after the switch carried its reference through the re-queue"
    else
      fail "C6 first call after the switch: success=$RUN_OK user=$(field .user) value='$(secret_value USER_SECRET)' err='$(head -c 140 <<<"$RUN_ERR")'"
    fi
    activate "$WAS_ACTIVE" && note "C6 active version restored to ${WAS_ACTIVE:0:16}…" \
      || fail "C6 COULD NOT RESTORE the active version — it is still $SWITCH_TO, put it back by hand"
  else
    fail "C6 could not activate $SWITCH_TO"
  fi
fi

# ── C8 two agents at once, no cross-talk ─────────────────────────────────────
#
# Each agent names ITS OWN row, and the rows hold different canaries. Fired one
# at a time this proves nothing: the interesting failure is a guest that reads
# the secret decrypted for a call running beside it, and that only appears under
# load. Judged on the VALUES, not on "a secret arrived".
if ! want C8; then
  :
elif [[ -z "$AGENT_PAYMENT_KEY" || -z "$AGENT_ACCOUNT" || -z "$AGENT2_PAYMENT_KEY" || -z "$AGENT2_ACCOUNT" ]]; then
  skip "C8 needs two custody wallets: AGENT_PAYMENT_KEY/AGENT_ACCOUNT and AGENT2_PAYMENT_KEY/AGENT2_ACCOUNT"
else
  log "C8 two agents firing at once, each naming its own row"
  C8_A=$(openssl rand -hex 6); C8_B=$(openssl rand -hex 6)
  store "$PROJECT" c8a "$(jq -nc --arg v "canary-a-$C8_A" '{USER_SECRET:$v}')" "whitelist:$PARENT,$AGENT_ACCOUNT"
  store "$PROJECT" c8b "$(jq -nc --arg v "canary-b-$C8_B" '{USER_SECRET:$v}')" "whitelist:$PARENT,$AGENT2_ACCOUNT"
  C8_DIR=$(mktemp -d)
  C8_N="${C8_N:-8}"
  for i in $(seq 1 "$C8_N"); do
    curl -sS --max-time 90 -X POST "$COORDINATOR_URL/call/$PROJECT" \
      -H "X-Payment-Key: $AGENT_PAYMENT_KEY" -H 'Content-Type: application/json' \
      -d "$(jq -nc --arg o "$PARENT" '{input:{message:"c8"}, secrets_ref:{profile:"c8a", account_id:$o}}')" \
      > "$C8_DIR/a.$i" 2>&1 &
    curl -sS --max-time 90 -X POST "$COORDINATOR_URL/call/$PROJECT" \
      -H "X-Payment-Key: $AGENT2_PAYMENT_KEY" -H 'Content-Type: application/json' \
      -d "$(jq -nc --arg o "$PARENT" '{input:{message:"c8"}, secrets_ref:{profile:"c8b", account_id:$o}}')" \
      > "$C8_DIR/b.$i" 2>&1 &
  done
  wait
  value_of() { jq -r '.output | if type=="string" then fromjson else . end | .secrets[]? | select(.key=="USER_SECRET") | .value // empty' < "$1" 2>/dev/null | head -1; }
  A_OWN=0; A_FOREIGN=0; B_OWN=0; B_FOREIGN=0; UNREAD=0
  for i in $(seq 1 "$C8_N"); do
    va=$(value_of "$C8_DIR/a.$i"); vb=$(value_of "$C8_DIR/b.$i")
    case "$va" in "canary-a-$C8_A") A_OWN=$((A_OWN+1)) ;; "canary-b-$C8_B") A_FOREIGN=$((A_FOREIGN+1)) ;; "") UNREAD=$((UNREAD+1)) ;; esac
    case "$vb" in "canary-b-$C8_B") B_OWN=$((B_OWN+1)) ;; "canary-a-$C8_A") B_FOREIGN=$((B_FOREIGN+1)) ;; "") UNREAD=$((UNREAD+1)) ;; esac
  done
  echo "        agent1 own=$A_OWN foreign=$A_FOREIGN | agent2 own=$B_OWN foreign=$B_FOREIGN | no value=$UNREAD" >&2
  [[ "$A_FOREIGN" -eq 0 && "$B_FOREIGN" -eq 0 ]] \
    && pass "C8 no guest saw the other agent's canary in $((C8_N*2)) calls at once" \
    || fail "C8 CROSS-TALK: agent1 saw the other's secret $A_FOREIGN time(s), agent2 $B_FOREIGN"
  # A run of refusals would make the line above vacuous, so the positive half is
  # asserted too: both agents really did read their own secret.
  [[ "$A_OWN" -ge 1 && "$B_OWN" -ge 1 ]] \
    && pass "C8 and both agents did read their own ($A_OWN and $B_OWN)" \
    || fail "C8 nothing was read at all (own: $A_OWN and $B_OWN) — the no-cross-talk result above means nothing"
  rm -rf "$C8_DIR"
  set_access "$PROJECT" c8a "$(whitelist "$PARENT")"
  set_access "$PROJECT" c8b "$(whitelist "$PARENT")"
fi

# ── C9 a connector call that names secrets but no operation ───────────────────
#
# Such a call must die for the OPERATION, with nothing decrypted for it. From
# outside, the evidence is which refusal comes back: a secrets message would
# mean the lookup happened first. Uses the owner's key, because a custody
# wallet's connector quota would answer before either check.
if ! want C9; then
  :
elif [[ -z "$OWNER_PAYMENT_KEY" ]]; then
  skip "C9 needs OWNER_PAYMENT_KEY (a named account's key has no connector quota ceiling)"
else
  log "C9 a connector call naming a secret but no operation"
  https_post "$OWNER_PAYMENT_KEY" "$CONNECTOR_PROJECT" \
    "$(jq -nc --arg o "$PARENT" '{input:{}, secrets_ref:{profile:"sec", account_id:$o}}')"
  if [[ "$RUN_OK" == "true" ]]; then
    fail "C9 a connector call with no operation RAN"
  elif grep -qiE "operation" <<<"$RUN_ERR"; then
    pass "C9 refused for the operation, not for the secrets: $(head -c 120 <<<"$RUN_ERR")"
  elif grep -qiE "secret|denied|decrypt" <<<"$RUN_ERR"; then
    fail "C9 refused over the SECRETS ('$(head -c 120 <<<"$RUN_ERR")') — the lookup ran for a call that was never going to"
  else
    fail "C9 refused for something else: HTTP $HTTP_CODE '$(head -c 160 <<<"$RUN_ERR")'"
  fi
fi

# ── U9 / K4 a whitelist of two thousand accounts ─────────────────────────────
#
# Two questions at this size, and they are different. Does the condition still
# DECIDE — a tree the keystore cannot evaluate inside the call's timeout would
# fail open or hang, and neither is acceptable. And is the storage PAID for —
# a condition grown by tens of kilobytes is tens of kilobytes somebody has to
# fund, and `update_access` prices the row exactly as a store prices it. The
# deposit must MOVE with the size; a row that grew for free is storage funded
# by every other account on the contract.
if ! want U9; then
  :
else
  log "U9 a whitelist of ${U9_SIZE:-2000} accounts on $PROJECT/$ROW"
  U9_SIZE="${U9_SIZE:-2000}"
  DEPOSIT_BEFORE=$(jq -r '.storage_deposit // "0"' <<<"$(row_of "$PROJECT" "$ROW")")
  # The real account goes LAST, so admitting it means the whole list was walked.
  U9_COND=$(jq -nc --arg me "$PARENT" --argjson n "$U9_SIZE" \
    '{Whitelist:{accounts:([range($n-1) | "filler-\(.).u9.testnet"] + [$me])}}')
  echo "        condition is $(printf '%s' "$U9_COND" | wc -c | tr -d ' ') bytes" >&2
  if set_access "$PROJECT" "$ROW" "$U9_COND" 2>/dev/null; then
    pass "U9 the contract stored a ${U9_SIZE}-account whitelist"
    DEPOSIT_AFTER=$(jq -r '.storage_deposit // "0"' <<<"$(row_of "$PROJECT" "$ROW")")
    echo "        storage_deposit before=$DEPOSIT_BEFORE after=$DEPOSIT_AFTER" >&2
    if [[ "$DEPOSIT_AFTER" == "$DEPOSIT_BEFORE" ]]; then
      fail "U9 the row grew by tens of kilobytes and storage_deposit did not move ($DEPOSIT_AFTER) — storage funded by nobody. If the note above said the deployed contract predates the update_access deposit, deploy it and run this row again"
    elif [[ "$DEPOSIT_AFTER" -gt "$DEPOSIT_BEFORE" ]] 2>/dev/null || [[ ${#DEPOSIT_AFTER} -gt ${#DEPOSIT_BEFORE} ]]; then
      pass "U9 and the deposit grew with the condition ($DEPOSIT_BEFORE → $DEPOSIT_AFTER)"
    else
      fail "U9 the condition grew but the deposit SHRANK ($DEPOSIT_BEFORE → $DEPOSIT_AFTER)"
    fi
    # Does it still decide, and inside the call's own timeout?
    run_as "$PARENT" "$PARENT/$ROW"
    [[ "$RUN_OK" == "true" && "$(secret_value USER_SECRET)" == "$USER_CANARY" ]] \
      && pass "U9 the ${U9_SIZE}th account is admitted — the whole list was walked in time" \
      || fail "U9 the owner was not admitted: success=$RUN_OK err='$(head -c 150 <<<"$RUN_ERR")'"
    run_as "$STRANGER" "$PARENT/$ROW"
    [[ "$RUN_OK" == "false" ]] \
      && pass "U9 and an account absent from all ${U9_SIZE} is refused" \
      || fail "U9 a stranger was admitted by a ${U9_SIZE}-account whitelist it is not in"

    # K4: the row still overwrites, and the deposit comes back.
    log "K4 overwrite the same row, then check the deposit closes"
    restore_row
    DEPOSIT_RESTORED=$(jq -r '.storage_deposit // "0"' <<<"$(row_of "$PROJECT" "$ROW")")
    echo "        storage_deposit restored=$DEPOSIT_RESTORED (was $DEPOSIT_BEFORE)" >&2
    [[ "$DEPOSIT_RESTORED" == "$DEPOSIT_BEFORE" ]] \
      && pass "K4 shrinking the condition returned the deposit to where it started" \
      || finding "K4 storage_deposit did not return: started $DEPOSIT_BEFORE, ended $DEPOSIT_RESTORED"
    run_as "$PARENT" "$PARENT/$ROW"
    [[ "$RUN_OK" == "true" && "$(secret_value USER_SECRET)" == "$USER_CANARY" ]] \
      && pass "K4 and the row still decrypts after being rewritten twice" \
      || fail "K4 the row stopped working after the overwrite: success=$RUN_OK err='$(head -c 150 <<<"$RUN_ERR")'"
  else
    # A refusal is a legitimate outcome — the contract may cap the size. Say so.
    pass "U9 the contract REFUSED a ${U9_SIZE}-account whitelist, which is a defensible cap"
    note "U9 nothing was changed; the row keeps the condition it had"
  fi
fi

# ── T time limits ────────────────────────────────────────────────────────────
NOW_NS=$(( $(date +%s) * 1000000000 ))
grant_until() { # grant_until <until_ns> — the owner always; the stranger until the instant
  jq -nc --arg p "$PARENT" --arg s "$STRANGER" --arg u "$1" \
    '{Logic:{operator:"Or",conditions:[{Whitelist:{accounts:[$p]}},
      {Logic:{operator:"And",conditions:[{Whitelist:{accounts:[$s]}},{ValidUntil:{until_ns:$u}}]}}]}}'
}
if want T; then
log "T1 a grant whose time limit has passed"
if ! try_update_access "$PARENT" "$PROJECT" "$ROW" "$(grant_until 1)"; then
  skip "T1–T3: the contract refuses ValidUntil ($(grep -o 'unknown variant[^"]\{0,60\}\|Smart contract panicked[^"]\{0,60\}' <<<"$TRY_OUT" | head -1)) — deploy the contract that carries it"
else
  run_as "$STRANGER" "$PARENT/$ROW"
  if [[ "$RUN_OK" == "false" ]] && grep -qi "unknown variant\|ValidUntil\|parse" <<<"$RUN_ERR"; then
    skip "T1–T3: the keystore does not know ValidUntil yet ($(head -c 100 <<<"$RUN_ERR")) — deploy the keystore that carries it"
    restore_row
    verdict "secrets security"; exit $?
  elif [[ "$RUN_OK" == "false" ]] && grep -qi "denied" <<<"$RUN_ERR"; then
    # The VERDICT and the REASON are two claims, and only the first is the
    # product's behaviour. A lapsed grant must refuse; naming the instant it
    # lapsed at is the worker passing the keystore's own sentence through
    # (`access_denied_message`), which a worker built before that fix replaces
    # with a fixed string.
    pass "T1 the lapsed grant refuses the stranger: $(head -c 100 <<<"$RUN_ERR")"
    if grep -q "time limit passed at 1970-01-01T00:00:00Z" <<<"$RUN_ERR"; then
      pass "T1 and the message names the instant it lapsed at"
    else
      finding "T1 the refusal does not name the instant — this worker replaces the keystore's sentence with a fixed string; needs the access_denied_message fix deployed"
    fi
  else
    fail "T1 stranger: success=$RUN_OK user=$(field .user) err='$RUN_ERR' (expected a refusal)"
  fi
  run_as "$PARENT" "$PARENT/$ROW"
  [[ "$RUN_OK" == "true" && "$(field .user)" == "true" ]] \
    && pass "T1 the owner's own branch has no limit and still admits" \
    || fail "T1 owner: success=$RUN_OK user=$(field .user) err='$RUN_ERR'"

  log "T2 the same grant, one hour into the future"
  set_access "$PROJECT" "$ROW" "$(grant_until $(( NOW_NS + 3600 * 1000000000 )))"
  run_as "$STRANGER" "$PARENT/$ROW"
  [[ "$RUN_OK" == "true" && "$(field .user)" == "true" && "$(secret_value USER_SECRET)" == "$USER_CANARY" ]] \
    && pass "T2 admitted before the instant, and reads the canary" \
    || fail "T2 stranger: success=$RUN_OK user=$(field .user) err='$RUN_ERR'"

  log "T3 raw until_ns values"
  if try_update_access "$PARENT" "$PROJECT" "$ROW" "$(grant_until abc)"; then
    fail "T3 the contract stored until_ns \"abc\""
  else
    pass "T3 until_ns \"abc\" is refused by the contract"
  fi
  set_access "$PROJECT" "$ROW" "$(grant_until 0)"
  run_as "$PARENT" "$PARENT/$ROW"
  [[ "$RUN_OK" == "true" && "$(field .user)" == "true" ]] \
    && pass "T3 until_ns \"0\" is stored and the owner's branch admits the owner" \
    || fail "T3 owner under until_ns 0: success=$RUN_OK user=$(field .user) err='$RUN_ERR'"
  run_as "$STRANGER" "$PARENT/$ROW"
  [[ "$RUN_OK" == "false" ]] \
    && pass "T3 and the stranger's lapsed branch refuses" \
    || fail "T3 stranger under until_ns 0 was admitted"

  # ── T4 the whole cycle, on one row, with the value never re-stored ──────────
  #
  # What an owner actually does: grant until a date, watch it lapse, grant
  # again. Nobody waits an hour for the lapse — moving the instant into the past
  # is the same thing to the keystore, and it is the same `update_access` the
  # owner would use to shorten a grant.
  log "T4 granted, lapsed, granted again"
  BLOB_T4=$(jq -r '.encrypted_secrets' <<<"$(row_of "$PROJECT" "$ROW")")
  FUTURE=$(( NOW_NS + 3600 * 1000000000 ))
  set_access "$PROJECT" "$ROW" "$(grant_until "$FUTURE")"
  # Stored is stored: the instant must come back as it went in, to the
  # nanosecond. A `U64` that lost precision or a string that became a number
  # would still look like a date here and admit at the wrong moment.
  STORED_UNTIL=$(jq -r '.. | objects | select(has("ValidUntil")) | .ValidUntil.until_ns' \
    <<<"$(row_of "$PROJECT" "$ROW")" 2>/dev/null | head -1)
  [[ "$STORED_UNTIL" == "$FUTURE" ]] \
    && pass "T4 the chain stored the exact instant it was given ($FUTURE)" \
    || fail "T4 the chain stored until_ns '$STORED_UNTIL', expected '$FUTURE'"
  run_as "$STRANGER" "$PARENT/$ROW"
  [[ "$RUN_OK" == "true" && "$(field .user)" == "true" ]] \
    && pass "T4 granted until an hour from now: the stranger reads it" \
    || fail "T4 granted: success=$RUN_OK user=$(field .user) err='$RUN_ERR'"

  set_access "$PROJECT" "$ROW" "$(grant_until 1)"
  run_as "$STRANGER" "$PARENT/$ROW"
  [[ "$RUN_OK" == "false" ]] && grep -qi "denied" <<<"$RUN_ERR" \
    && pass "T4 the instant moved into the past: the same caller is refused" \
    || fail "T4 lapsed: success=$RUN_OK user=$(field .user) err='$RUN_ERR'"

  set_access "$PROJECT" "$ROW" "$(grant_until "$FUTURE")"
  run_as "$STRANGER" "$PARENT/$ROW"
  [[ "$RUN_OK" == "true" && "$(field .user)" == "true" && "$(secret_value USER_SECRET)" == "$USER_CANARY" ]] \
    && pass "T4 a later instant brings it back, and the canary is the same secret" \
    || fail "T4 re-dated: success=$RUN_OK user=$(field .user) err='$RUN_ERR'"
  [[ -n "$BLOB_T4" && "$(jq -r '.encrypted_secrets' <<<"$(row_of "$PROJECT" "$ROW")")" == "$BLOB_T4" ]] \
    && pass "T4 and the ciphertext never moved: only the date was ever edited" \
    || fail "T4 the ciphertext changed while only the date was edited"
  restore_row
fi
fi

# ── W1: the wallet lane — a wallet keeps a secret of its own ─────────────────
#
# The Phase 5 prerequisite. If the agent-secret machinery is to be retired, a
# custody wallet with no human-held named account must still be able to keep a
# secret: it signs `store_secrets` through `/wallet/v1/call`, owns the row as
# its own implicit account, and names `{implicit, profile}` like any caller.
#
# The refusal half is not decoration. A row whose condition is `Whitelist[self]`
# read back BY self proves nothing alone — an ungated row answers identically.
# A second wallet has to be refused for the first read to carry any weight.
if want W1; then
if [[ -z "$AGENT_WK" || -z "$AGENT_PAYMENT_KEY" || -z "$AGENT_ACCOUNT" ]]; then
  skip "W1 needs AGENT_WK, AGENT_PAYMENT_KEY and AGENT_ACCOUNT (one custody wallet's own credentials)"
elif [[ -z "$AGENT2_PAYMENT_KEY" ]]; then
  skip "W1 needs AGENT2_PAYMENT_KEY — without a second wallet the refusal half cannot run, and a self-whitelist read by self would prove nothing"
elif [[ ! -x "$SCRIPT_DIR/lib/store_row_for_owner.py" ]]; then
  skip "W1 needs tests/lib/store_row_for_owner.py — it seals an envelope for an owner the CLI cannot sign as"
else
  log "W1 a custody wallet stores its OWN row through /wallet/v1/call and reads it back"
  W1_PROFILE="wallet-own"
  W1_CANARY="w1-$(openssl rand -hex 6)"
  W1_BEFORE=$(jq -r '.updated_at // 0' <<<"$(row_of_owner "$PROJECT" "$W1_PROFILE" "$AGENT_ACCOUNT")")
  W1_BLOB=$("$SCRIPT_DIR/lib/store_row_for_owner.py" "$PROJECT" "$W1_PROFILE" "$AGENT_ACCOUNT" \
      "$(jq -nc --arg v "$W1_CANARY" '{USER_SECRET:$v}')" 2>/dev/null \
    | grep -o '"encrypted_secrets_base64": "[^"]*"' | head -1 | cut -d'"' -f4)
  if [[ -z "$W1_BLOB" ]]; then
    fail "W1 no envelope could be sealed for owner=$AGENT_ACCOUNT — the keystore's pubkey for that owner is what the row needs"
  else
    W1_ANS=$(curl -sS --max-time 120 -X POST "$COORDINATOR_URL/wallet/v1/call" \
      -H "Authorization: Bearer $AGENT_WK" -H 'Content-Type: application/json' \
      -d "$(jq -nc --arg c "$CONTRACT_ID" --arg pj "$PROJECT" --arg pr "$W1_PROFILE" \
               --arg b "$W1_BLOB" --arg a "$AGENT_ACCOUNT" \
        '{receiver_id:$c, method_name:"store_secrets",
          args:{accessor:{Project:{project_id:$pj}}, profile:$pr,
                encrypted_secrets_base64:$b, access:{Whitelist:{accounts:[$a]}}},
          gas:"100000000000000", deposit:"100000000000000000000000"}')" 2>&1)
    W1_TX=$(jq -r '.tx_hash // empty' <<<"$W1_ANS" 2>/dev/null)
    if [[ -z "$W1_TX" ]]; then
      fail "W1 the wallet could not store its own row: $(head -c 220 <<<"$W1_ANS")"
    else
      pass "W1 the wallet signed its own store_secrets (tx $W1_TX)"
      # `/wallet/v1/call` answers once the transaction is IN; a FINAL view read
      # can still miss the row for a second or two. Polling here rather than
      # asserting at once is the difference between reading the chain and
      # reading the clock — an eager read reports a row that exists as absent.
      wait_row_after "$PROJECT" "$W1_PROFILE" "$W1_BEFORE" "$AGENT_ACCOUNT" \
        || note "W1 the row did not appear within 30 s of the store"
      W1_ACCESS=$(jq -c '.access // empty' <<<"$(row_of_owner "$PROJECT" "$W1_PROFILE" "$AGENT_ACCOUNT")" 2>/dev/null)
      [[ "$W1_ACCESS" == *"$AGENT_ACCOUNT"* ]] \
        && pass "W1 the row sits on chain owned by the wallet, whitelisting only itself" \
        || fail "W1 the stored condition is '$W1_ACCESS', expected a whitelist naming $AGENT_ACCOUNT"

      POLL_KEY="$AGENT_PAYMENT_KEY"
      call_https "$AGENT_PAYMENT_KEY" "$PROJECT" "$AGENT_ACCOUNT/$W1_PROFILE"
      [[ "$RUN_OK" == "true" && "$(secret_value USER_SECRET)" == "$W1_CANARY" ]] \
        && pass "W1 the wallet read its own secret back, payer=$(field .payer)" \
        || fail "W1 the wallet could not read its own row: success=$RUN_OK value='$(secret_value USER_SECRET)' err='$RUN_ERR'"

      POLL_KEY="$AGENT2_PAYMENT_KEY"
      call_https "$AGENT2_PAYMENT_KEY" "$PROJECT" "$AGENT_ACCOUNT/$W1_PROFILE"
      if [[ "$(secret_value USER_SECRET)" == "$W1_CANARY" ]]; then
        fail "W1 a second wallet READ the row — the wallet's own whitelist did not gate it"
      elif [[ "$RUN_OK" == "false" ]] && grep -qi "denied\|permission" <<<"$RUN_ERR"; then
        pass "W1 a second wallet is refused by that condition: $(head -c 90 <<<"$RUN_ERR")"
      else
        fail "W1 the second wallet neither read the secret nor was clearly refused: success=$RUN_OK err='$RUN_ERR'"
      fi

      curl -sS --max-time 120 -X POST "$COORDINATOR_URL/wallet/v1/call" \
        -H "Authorization: Bearer $AGENT_WK" -H 'Content-Type: application/json' \
        -d "$(jq -nc --arg c "$CONTRACT_ID" --arg pj "$PROJECT" --arg pr "$W1_PROFILE" \
          '{receiver_id:$c, method_name:"delete_secrets",
            args:{accessor:{Project:{project_id:$pj}}, profile:$pr},
            gas:"100000000000000", deposit:"0"}')" >/dev/null 2>&1
      note "W1 the wallet's row was deleted again, so a re-run starts from nothing"
    fi
  fi
fi
fi

# ── D7 a grant outlives the binding it was made for ──────────────────────────
#
# RUN THIS LAST. It revokes the binding, which is the fixture D3 and D9 need,
# and nothing here puts it back: re-binding needs the asset account and the
# setup kit again.
#
# The trade-off the plan states out loud. A whitelist names an executor, not a
# binding, so tearing the binding down leaves the grant standing — the agent
# keeps reading the secret until somebody edits the condition. That is the cost
# of explicit grants, and the reason the dashboard lists grants per account and
# `ValidUntil` exists. The row proves both halves: still admitted after the
# revocation, refused the moment the owner edits the row.
if ! want D7; then
  :
elif [[ -z "$AGENT_PAYMENT_KEY" || -z "$AGENT_ACCOUNT" || -z "$AGENT_WK" ]]; then
  skip "D7 needs AGENT_PAYMENT_KEY, AGENT_ACCOUNT and AGENT_WK (the wallet whose binding is torn down)"
elif [[ "${D7_DESTROY_BINDING:-0}" != "1" ]]; then
  skip "D7 revokes this wallet's binding and cannot restore it — pass D7_DESTROY_BINDING=1 to allow that"
else
  log "D7 the binding goes away; the grant does not"
  set_access "$PROJECT" "$ROW" "$(whitelist "$PARENT" "$AGENT_ACCOUNT")"
  POLL_KEY="$AGENT_PAYMENT_KEY"

  D7_BEFORE=$(curl -sS --max-time 60 "$COORDINATOR_URL/wallet/v1/binding" \
    -H "Authorization: Bearer $AGENT_WK" 2>/dev/null | jq -r '.binding_status // "none"')
  [[ "$D7_BEFORE" == "active" ]] \
    && pass "D7 the wallet starts with an ACTIVE binding" \
    || note "D7 the binding is '$D7_BEFORE', not active — the revocation half proves less than it should"

  curl -sS --max-time 60 -X DELETE "$COORDINATOR_URL/wallet/v1/binding" \
    -H "Authorization: Bearer $AGENT_WK" >/dev/null 2>&1
  D7_AFTER=$(curl -sS --max-time 60 "$COORDINATOR_URL/wallet/v1/binding" \
    -H "Authorization: Bearer $AGENT_WK" 2>/dev/null | jq -r '.binding_status // .error // "?"')
  [[ "$D7_AFTER" != "active" ]] \
    && pass "D7 the binding is gone ($D7_AFTER) — the extension has been removed" \
    || fail "D7 the binding is STILL active after DELETE; the rest of this row would prove nothing"

  https_post "$AGENT_PAYMENT_KEY" "$PROJECT" \
    "$(jq -nc --arg a "$PARENT" --arg pr "$ROW" '{input:{message:"d7"}, secrets_ref:{account_id:$a, profile:$pr}}')"
  [[ "$RUN_OK" == "true" && "$(secret_value USER_SECRET)" == "$USER_CANARY" ]] \
    && pass "D7 the grant still admits the wallet with no binding at all — grants outlive bindings" \
    || fail "D7 the wallet lost the secret when the binding went: success=$RUN_OK err='$(head -c 140 <<<"$RUN_ERR")'"

  set_access "$PROJECT" "$ROW" "$(whitelist "$PARENT")"
  https_post "$AGENT_PAYMENT_KEY" "$PROJECT" \
    "$(jq -nc --arg a "$PARENT" --arg pr "$ROW" '{input:{message:"d7b"}, secrets_ref:{account_id:$a, profile:$pr}}')"
  if [[ "$(secret_value USER_SECRET)" == "$USER_CANARY" ]]; then
    fail "D7 the secret still arrived after the owner removed the account from the row"
  elif [[ "$RUN_OK" == "false" ]] && grep -qi "denied\|permission" <<<"$RUN_ERR"; then
    pass "D7 editing the condition is what ends the grant — and it ends it at once"
  else
    fail "D7 after the revocation the call neither ran nor was clearly refused: success=$RUN_OK err='$(head -c 160 <<<"$RUN_ERR")'"
  fi
  restore_row
fi

verdict "secrets security"
