#!/usr/bin/env bash
#
# §5 of the HoS test plan — identity and attribution over the HTTPS door.
#
# The whole point of Agent Connect is that ONE of a wallet's two identities
# moves and the other does not: the guest ACTS AS the bound account
# (`NEAR_SENDER_ID`) while the money is still the executor's
# (`NEAR_USER_ACCOUNT_ID`). If both moved, usage would be attributed to an
# account that paid nothing; if neither did, the binding would buy the partner
# nothing at all. So each probe below reads BOTH values out of the guest and
# asks which one changed.
#
# Judged inside the guest, not from the answer envelope: `connector-probe`'s
# `whoami` reports the variables the WORKER injected, none of which a caller
# can set in the request body. That is the only place the question can be
# answered honestly.
#
# The on-chain half (`bound_identity_onchain_e2e.sh` B0–B5) reads the
# coordinator's own rows and needs database access from the coordinator host;
# it is not repeated here.
#
#   PARENT=you.testnet ./tests/hos_identity_e2e.sh --apply
#
# Optional: NONWALLET_PAYMENT_KEY=<a funded key owned by a NAMED account> adds
# I1c, the arm where the credential names no wallet at all.
#
# Optional: PSQL_CMD=<one-statement SQL command> adds §I6/§I7 — who the call is
# BILLED to, and whether one operation can be followed from the id a client
# holds down to the enclave's own evidence (R8). Everything above them judges
# the guest, which cannot answer either question. See .idea/TESTING-WITH-ADMIN.md.

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/hos_common.sh"

[[ "${1:-}" == "--apply" ]] || { sed -n '3,31p' "$0" >&2; echo "  Pass --apply to run." >&2; exit 0; }
hos_require

PROJECT="${PROJECT:-connectors.outlayer.testnet/connector-probe}"

# Set by I2 when the bound call goes through, and read by §I6/§I7. Declared here
# because this harness runs under `set -u`: an I2 that failed would otherwise
# take the whole script down at the first mention of them, turning one failed
# assertion into a suite that reports nothing at all.
CALL_BOUND=""; ATT_URL=""; BODY_I2=""

# probe <payment-key> <flag> <operation> — one HTTPS call into the guest.
probe() {
  local pk=$1 flag=$2 op=${3:-whoami} out
  throttle
  out=$(mktemp -t hos_ident.XXXXXX)
  HTTP=$(curl -sS -o "$out" -w '%{http_code}' -m 300 -X POST "$COORDINATOR_URL/call/$PROJECT" \
    -H "X-Payment-Key: $pk" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg o "$op" --argjson f "$flag" '{input:{operation:$o}, use_bound_identity:$f}')" 2>/dev/null)
  BODY="$(tr -d '\n' < "$out")"; rm -f "$out"
  # The handle the API gives a client, and the only one it gives: §I7 walks the
  # coordinator's rows starting from this and nothing else, because nothing else
  # is what a caller holds.
  CALL_ID=$(jq -r '.call_id // ""' <<<"$BODY" 2>/dev/null)
}
guest() { jq -r "$1 // \"\"" <<<"$(jq -r '.output // .result // "{}"' <<<"$BODY" 2>/dev/null)" 2>/dev/null; }

# ── a wallet the coordinator minted, so the payer and the bound wallet are one ─
log "Minting a wallet and claiming its trial key"
WK=$(curl -sS -m 60 -X POST "$COORDINATOR_URL/register" -H 'Content-Type: application/json' -d '{}' 2>/dev/null | jq -r '.api_key // empty')
[[ -n "$WK" ]] || { echo "✗ /register gave no key" >&2; exit 1; }
api_wk "$WK" GET "/wallet/v1/address?chain=near" >/dev/null
WID=$(jq -r '.wallet_id // empty' <<<"$BODY"); EXEC=$(jq -r '.address // empty' <<<"$BODY")
[[ -n "$WID" ]] || { echo "✗ /address failed: $BODY" >&2; exit 1; }
note "wallet $WID / executor $EXEC"

CLAIM=$(curl -sS -m 60 -X POST "$COORDINATOR_URL/trial-key" -H "Authorization: Bearer $WK" \
  -H 'Content-Type: application/json' -d '{}' 2>/dev/null)
PK=$(jq -r '.payment_key // empty' <<<"$CLAIM")

# A trial is not always on offer (`trial_unavailable`), and that is not
# resettable from outside — so it would cost this suite the whole HTTPS half of
# `use_bound_identity` — silently, on a run that then reports nothing wrong. A
# wallet can buy its own key instead. The key it gets is owned by the same
# implicit account the trial key would have been, which is what makes I1 land on
# the binding lookup rather than on "this key names no wallet".
if [[ -z "$PK" ]]; then
  note "no trial key ($(jq -r '.error // .' <<<"$CLAIM" | head -c 90)) — buying one with stablecoin instead"
  buy_payment_key "$WK" "$EXEC" && PK="$PAID_KEY"
fi

if [[ -z "$PK" ]]; then
  skip "§5 — this wallet has no key to pay with: no trial is on offer to this run and the stablecoin route did not go through either (see the warning above for which step)"
  # Exit 3, not 0: without a key this suite judges nothing, and §5 is where the
  # HTTPS half of `use_bound_identity` is judged at all. A zero here reads in
  # the runner's table as a suite that passed.
  verdict "§5 identity"; exit 3
fi
note "paying with ${PK:0:8}… ($(jq -r 'if .calls then "a trial of \(.calls) calls" else "bought with stablecoin" end' <<<"$CLAIM" 2>/dev/null || echo "bought with stablecoin"))"

ACC="hos-ident-$(openssl rand -hex 3).$PARENT"
cleanup() {
  local rc=$?
  api_wk "$WK" DELETE /wallet/v1/binding >/dev/null 2>&1 || true
  account_exists "$ACC" && { note "cleaning up $ACC"; delete_account "$ACC"; }
  return $rc
}
trap cleanup EXIT

# ── I0 the flag OFF, with no binding: the guest is the caller ──────────────
log "I0 use_bound_identity=false, before any binding exists"
probe "$PK" false
if [[ "$HTTP" == "200" ]]; then
  S0=$(guest '.sender_id'); P0=$(guest '.user_account_id')
  note "sender=$S0 payer=$P0"
  if [[ -n "$S0" && "$S0" == "$P0" ]]; then
    pass "I0 the guest acts as its caller and pays as its caller — one identity, as before Agent Connect"
  else
    fail "I0 sender='$S0' payer='$P0' — with no binding the two must be the same account"
  fi
else
  fail "I0 the probe call failed (HTTP $HTTP): $(head -c 220 <<<"$BODY")"
  verdict "§5 identity"; exit 1
fi

# ── I1 the flag ON with NO binding is refused, not silently ignored ────────
log "I1 use_bound_identity=true while the wallet is unbound"
probe "$PK" true
S1=$(guest '.sender_id')
if [[ "$HTTP" == "200" && "$S1" == "$S0" ]]; then
  fail "I1 the flag was silently ignored: the job RAN under the caller's own name '$S1' with no binding in existence. The ON-CHAIN door refuses this exact case (handlers/tasks.rs sets the sender to an empty string so the worker rejects the job, with the comment 'NOT a silent fallback to the caller's own name'); the HTTPS door's own comment says the same and then falls through to None (handlers/call.rs, the bound_sender match: fetch_optional yields None for an absent or inactive binding and only a DB ERROR refuses). A connector that turns NEAR_SENDER_ID into something real — near-email into the mailbox it sends from — sends successfully from the wrong account, with nothing in the record to explain it"
elif [[ "$HTTP" == "200" ]]; then
  fail "I1 the job ran and the guest saw sender='$S1' with no binding in existence"
else
  # What this alone proves: the job did NOT go ahead under the caller's own
  # name — deliberately no more. The wider claim, that asking to be somebody the
  # wallet is not is an error, belongs to the three assertions below; making it
  # here as well turns one wrong-reason refusal into a pass and three failures
  # about a single observation.
  pass "I1 refused rather than run (HTTP $HTTP) — nothing executed under the wrong identity"
  note "  $(jq -r '.message // .error // .' <<<"$BODY" | head -c 160)"
  # WHICH refusal, not just any. A wallet that ran out of money, a project that
  # moved, a key past its scope — each is a 4xx too, and any of them would let
  # this probe pass while the flag went on being ignored.
  [[ "$HTTP" == "409" ]] \
    && pass "I1 409 — the wallet's state has no such name, which is a conflict rather than a fault of ours" \
    || fail "I1 refused with HTTP $HTTP, expected 409: a refusal for some other reason passes this probe while the flag is still ignored"
  [[ "$(jq -r '.reason // ""' <<<"$BODY")" == "no_bound_identity" ]] \
    && pass "I1 and names itself no_bound_identity — the field clients branch on" \
    || fail "I1 reason is '$(jq -r '.reason // "none"' <<<"$BODY")', not no_bound_identity"
  [[ "$(bool_of terminal)" == "false" ]] \
    && pass "I1 terminal:false — binding an account later makes this very call work" \
    || fail "I1 terminal is '$(bool_of terminal)'; marking this terminal sends an agent away for good over a state its owner can change"
fi

# ── I1c a key that names no wallet cannot borrow a name either ─────────────
#
# The OTHER silent arm. `use_bound_identity` resolves the wallet from the
# credential when no `X-Wallet-Id` is sent, and a payment key owned by a NAMED
# account resolves to nothing at all — a different absence from "this wallet has
# no binding", and one that no amount of binding will ever fix. It has its own
# terminal flag for that reason, and the flag is the part a client acts on.
#
# Needs a key this machine cannot mint: `outlayer keys create` signs
# `store_secrets` as the account itself. Supplied, or skipped loudly.
log "I1c use_bound_identity=true from a key owned by a named account"
if [[ -z "${NONWALLET_PAYMENT_KEY:-}" ]]; then
  skip "I1c — set NONWALLET_PAYMENT_KEY to a funded key owned by a NAMED account (outlayer keys create + keys topup) to judge the second silent arm"
else
  probe "$NONWALLET_PAYMENT_KEY" true
  if [[ "$HTTP" == "200" ]]; then
    fail "I1c the flag was ignored for a key that names no wallet: the job ran as '$(guest '.sender_id')'"
  else
    pass "I1c refused (HTTP $HTTP) — a credential that names no wallet has no binding to run under"
    [[ "$(bool_of terminal)" == "true" ]] \
      && pass "I1c terminal:true — no owner action turns a named account's key into a wallet's key, so retrying is pointless" \
      || fail "I1c terminal is '$(bool_of terminal)'; this arm never becomes true, and a client told to retry will retry forever"
  fi
fi

# ── the binding ────────────────────────────────────────────────────────────
log "Binding the wallet to $ACC"
create_subaccount "$ACC" 0.7 || { echo "✗ $ACC never appeared" >&2; exit 1; }
api_wk "$WK" PUT /wallet/v1/binding "$(jq -nc --arg a "$ACC" '{asset_account_id:$a, kind:"personal_account"}')" >/dev/null
[[ "$HTTP" == "200" ]] || { echo "✗ PUT failed $HTTP: $BODY" >&2; exit 1; }

# ── I1b the binding exists and is PENDING, which authorizes nothing ────────
#
# The window between the PUT and the owner's transaction landing is a real
# state, not a contrivance: it is where every binding starts. The SQL filters on
# `status = 'active'`, so this ought to fall out for free — which is exactly the
# kind of claim that is worth a probe rather than a reading of the query.
log "I1b use_bound_identity=true while the binding is still pending"
api_wk "$WK" GET /wallet/v1/binding >/dev/null
PEND=$(jq -r '.binding_status // ""' <<<"$BODY")
if [[ "$PEND" != "pending" ]]; then
  skip "I1b the binding was '$PEND', not pending, by the time the probe ran — nothing to judge"
else
  probe "$PK" true
  if [[ "$HTTP" == "200" ]]; then
    fail "I1b a PENDING binding was honoured: the guest ran as '$(guest '.sender_id')' on the strength of a binding the owner has not confirmed on chain"
  else
    pass "I1b refused (HTTP $HTTP) — a binding nobody has confirmed authorizes nothing"
    [[ "$(jq -r '.reason // ""' <<<"$BODY")" == "no_bound_identity" ]] \
      && pass "I1b and for the right reason — the same refusal as no binding at all" \
      || fail "I1b refused as '$(jq -r '.reason // .error // "?"' <<<"$BODY")', which is not the binding rule speaking"
  fi
fi

install_wallet "$ACC" "$EXEC" || { echo "✗ the setup transaction did not land" >&2; exit 1; }
ST=""
for _ in 1 2 3 4 5 6 7 8; do
  api_wk "$WK" GET /wallet/v1/binding >/dev/null
  ST=$(jq -r '.binding_status // ""' <<<"$BODY"); [[ "$ST" == "active" ]] && break; sleep 3
done
[[ "$ST" == "active" ]] && pass "the binding is ACTIVE" || { fail "the binding never went active ('$ST')"; verdict "§5 identity"; exit 1; }

# ── I2 the flag ON with an active binding ─────────────────────────────────
log "I2 use_bound_identity=true with the binding live"
probe "$PK" true
if [[ "$HTTP" == "200" ]]; then
  S2=$(guest '.sender_id'); P2=$(guest '.user_account_id')
  # Kept for §I6/§I7, which judge THIS call's record rather than making another:
  # a second call would leave a second set of rows, and "the row I found" is not
  # the same claim as "the row for the answer I hold".
  CALL_BOUND="$CALL_ID"; BODY_I2="$BODY"
  ATT_URL=$(jq -r '.attestation_url // ""' <<<"$BODY")
  note "sender=$S2 payer=$P2 call=$CALL_BOUND"
  [[ "$S2" == "$ACC" ]] \
    && pass "I2 the guest acts as the BOUND account ($S2) — verified in the worker against the chain, not taken from the request" \
    || fail "I2 the guest saw sender='$S2', expected the bound account '$ACC'"
  [[ "$P2" == "$P0" ]] \
    && pass "I2 the PAYER did not move ($P2) — billing follows the money, never the name" \
    || fail "I2 the payer changed from '$P0' to '$P2' — usage would be attributed to an account that paid nothing"
else
  fail "I2 the call failed (HTTP $HTTP): $(head -c 220 <<<"$BODY")"
fi

# ── I3 the flag OFF with a live binding: nothing changes for old clients ──
log "I3 use_bound_identity=false with the binding still live"
probe "$PK" false
if [[ "$HTTP" == "200" ]]; then
  S3=$(guest '.sender_id')
  [[ "$S3" == "$S0" ]] \
    && pass "I3 an unflagged call is unaffected by the binding ($S3) — the flag is opt-in, not a mode" \
    || fail "I3 an unflagged call saw sender='$S3', not the caller's own '$S0' — the binding changed clients that never asked"
else
  fail "I3 the call failed (HTTP $HTTP)"
fi

# ── I4 the guest cannot forge either identity through its own inputs ───────
log "I4 the reserved system variables, as the guest sees them"
probe "$PK" true env
if [[ "$HTTP" == "200" ]]; then
  DUMP=$(jq -r '.output // .result // "{}"' <<<"$BODY")
  if grep -q "NEAR_SENDER_ID" <<<"$DUMP"; then
    pass "I4 the environment report is available and names the injected variables"
  else
    note "  env report: $(head -c 220 <<<"$DUMP")"
    skip "I4 — the env report did not name NEAR_SENDER_ID; nothing to compare"
  fi
else
  skip "I4 — the env operation answered HTTP $HTTP"
fi

# ── I5 VRF: the randomness follows the PAYER on this door ─────────────────
log "I5 VRF with and without the flag"
probe "$PK" false vrf; V_OFF=$(guest '.detail')
probe "$PK" true  vrf; V_ON=$(guest '.detail')
if [[ -n "$V_OFF$V_ON" ]]; then
  note "vrf(flag off): $(head -c 150 <<<"$V_OFF")"
  note "vrf(flag on):  $(head -c 150 <<<"$V_ON")"
  pass "I5 both doors answered — the alpha inputs are recorded above for the comparison the plan asks for"
else
  skip "I5 — the probe's vrf operation returned nothing to compare"
fi

# ── §I6/§I7 the record: who is billed, and can one call be followed ────────
#
# Everything above judged the guest — the right subject for "who am I", and the
# wrong one for "who pays" and "what is on file". Those two live in the
# coordinator's own rows, and the rows are what an operator, an invoice and a
# support request are all built from. R8 of the acceptance list asks for one
# operation to be followable from the answer a client holds all the way to the
# receipts; §I6 and §I7 are that walk over the HTTPS door.
#
# NOT reachable from a laptop without a command that reads the coordinator's
# database: it listens on its host only. Skipped loudly rather than quietly
# reduced to what the answer envelope alone can show.
log "§I6/§I7 the coordinator's rows for the bound call"
if [[ -z "$CALL_BOUND" ]]; then
  skip "§I6/§I7 — I2 produced no call_id, so there is no call to follow"
elif ! sql_alive; then
  skip "§I6/§I7 — set PSQL_CMD to a command that runs one statement of SQL against the coordinator's database (see .idea/TESTING-WITH-ADMIN.md). Without it the money and the audit trail are judged by nothing but the answer that was already read above"
else
  # ── I6 the two identities as the REQUEST records them ────────────────────
  ROW=$(sql_row "SELECT request_id || '|' || COALESCE(context_sender_id,'') || '|' \
                     || COALESCE(user_account_id,'') || '|' || COALESCE(payment_key_owner,'') || '|' \
                     || COALESCE(binding_kind,'') || '|' || is_https_call
                   FROM execution_requests WHERE call_id = '$CALL_BOUND'")
  if [[ -z "$ROW" ]]; then
    fail "I6 no execution_requests row for call $CALL_BOUND — the call the client was told about left no record"
  else
    IFS='|' read -r R_REQ R_SENDER R_USER R_PKO R_KIND R_HTTPS <<<"$ROW"
    note "request $R_REQ: sender=$R_SENDER payer=$R_USER key-owner=$R_PKO kind=$R_KIND"
    [[ "$R_SENDER" == "$ACC" ]] \
      && pass "I6 the request records the BORROWED name ($R_SENDER) — the guest's answer and the file agree" \
      || fail "I6 the request records sender '$R_SENDER', expected the bound account '$ACC'"
    # The half nobody would notice breaking: the guest goes on answering
    # correctly while the money moves to a name in the record.
    [[ "$R_USER" == "$P0" ]] \
      && pass "I6 and the PAYER is unchanged ($R_USER) — the borrowed name never reaches the column billing reads" \
      || fail "I6 the payer column holds '$R_USER', expected the key's own account '$P0' — usage would be attributed to an account that paid nothing"
    [[ "$R_PKO" == "$P0" ]] \
      && pass "I6 the payment key's owner is recorded as itself ($R_PKO)" \
      || fail "I6 payment_key_owner is '$R_PKO', expected '$P0'"
    [[ "$R_KIND" == "personal_account" ]] \
      && pass "I6 the row says WHICH kind of binding was used ($R_KIND) — without it a bound call is indistinguishable afterwards from an ordinary one" \
      || fail "I6 binding_kind is '$R_KIND', expected personal_account"
    # Which DOOR. The two are billed by different code down different tables,
    # and a request filed under the wrong one is earned on twice or not at all.
    # `true`, not `t`: psql's one-letter rendering of a boolean is how it DISPLAYS
    # a column of its own, and this one arrives inside a concatenation, where it
    # has already been cast to text by Postgres itself.
    [[ "$R_HTTPS" == "true" ]] \
      && pass "I6 and the row knows this came in over HTTPS, which is what decides where the money is accounted" \
      || fail "I6 is_https_call is '$R_HTTPS' for a call made over HTTPS"
  fi

  # ── I6b the LEDGER, which is a different table and a different rule ──────
  #
  # An earnings row appears only when somebody is OWED something, and the probes
  # above owe nobody: `whoami` is priced at a fee whose author share is zero, so
  # the call costs money and credits no developer. The `secret` operation of the
  # same connector carries a 70% author share, which is what makes a row exist —
  # and the row is where attribution either holds or silently does not.
  #
  # Deliberately NOT done with `X-Attached-Deposit`, the other route to a
  # developer's earnings: the connector path refuses it (`call.rs` says so and a
  # unit test names the three places), so a deposit here buys a completed call
  # and no row at all — which reads exactly like the defect this probe is for.
  log "I6b a bound call that actually owes somebody money"
  probe "$PK" true secret
  DEP_CALL="$CALL_ID"
  if [[ "$HTTP" != "200" || -z "$DEP_CALL" ]]; then
    skip "I6b — the priced operation answered HTTP $HTTP ($(msg_of | head -c 140)); with no call there is nothing to attribute"
  elif [[ "$(sql "SELECT allowance_covered::text FROM https_calls WHERE call_id = '$DEP_CALL'")" == "true" ]]; then
    # A trial or a subscription pays a connector's author nothing — the caller
    # paid us nothing for it — so there is correctly no row to read.
    skip "I6b — this key's call was covered by an allowance, which owes the connector's author nothing and so writes no earnings row"
  else
    ROWS=$(sql_row "SELECT string_agg(project_owner || '~' || COALESCE(caller,'NULL') || '~' \
                        || COALESCE(payment_key_owner,'NULL') || '~' || amount, ' ') \
                      FROM earnings_history WHERE call_id = '$DEP_CALL'")
    if [[ -z "$ROWS" ]]; then
      fail "I6b a call that owed a connector's author their share left no earnings_history row (call $DEP_CALL) — money changed hands and the ledger does not say between whom"
    else
      note "earnings: $ROWS"
      BAD=0; SEEN=0
      for r in $ROWS; do
        SEEN=$((SEEN+1)); ROW_OK=true
        E_CALLER=$(cut -d'~' -f2 <<<"$r"); E_PKO=$(cut -d'~' -f3 <<<"$r")
        # The whole point, stated over every identity column at once rather than
        # over the one that happens to be filled today: a schema that starts
        # populating `caller` for HTTPS rows must not populate it with the name
        # the guest borrowed.
        [[ "$E_CALLER" == "$ACC" || "$E_PKO" == "$ACC" ]] && { ROW_OK=false; note "  row names the BORROWED account"; }
        [[ "$E_PKO" == "$P0" ]] || { ROW_OK=false; note "  row credits '$E_PKO', not the payer '$P0'"; }
        # Counted per ROW, not per broken assertion: two complaints about one
        # row otherwise report "2 of 1 rows", and a count that cannot be read is
        # a count nobody checks.
        $ROW_OK || BAD=$((BAD+1))
      done
      (( SEEN > 0 && BAD == 0 )) \
        && pass "I6b every earnings row for this call names the PAYER ($P0) and none names the borrowed account ($ACC) — $SEEN row(s)" \
        || fail "I6b $BAD of $SEEN earnings rows attribute this call to the wrong account: $ROWS"
    fi
  fi

  # ── I7 the ladder: from the handle a client holds down to the receipts ───
  #
  # A client is given `call_id` and nothing else — no request id, no job id, no
  # worker. So the walk starts there, and each rung has to be reachable from the
  # one above it. A break anywhere is a call that cannot be answered questions
  # about after the fact, which is the whole of R8.
  log "I7 following one call from its id to the run that produced it"
  [[ "$ATT_URL" == "/attestations/by-call/$CALL_BOUND" ]] \
    && pass "I7 rung 1 the answer carries the attestation's address, derived from the call id ($ATT_URL)" \
    || fail "I7 rung 1 attestation_url is '$ATT_URL', expected '/attestations/by-call/$CALL_BOUND' — a client cannot reach the quote from what it was given"

  CROW=$(sql_row "SELECT status || '|' || COALESCE(instructions::text,'') || '|' \
                      || COALESCE(time_ms::text,'') || '|' || COALESCE(compute_cost::text,'') \
                    FROM https_calls WHERE call_id = '$CALL_BOUND'")
  if [[ -z "$CROW" ]]; then
    fail "I7 rung 2 no https_calls row for $CALL_BOUND — the call the client holds an id for is not on file"
  else
    IFS='|' read -r C_ST C_INS C_MS C_COST <<<"$CROW"
    [[ "$C_ST" == "completed" ]] \
      && pass "I7 rung 2 the call is on file as completed" \
      || fail "I7 rung 2 the row says status '$C_ST' for a call the client was answered 200 on"
    # The numbers a caller is billed on. If the answer and the row disagree,
    # every invoice dispute is unresolvable — and neither side is obviously
    # wrong, which is the worst shape this can take.
    A_INS=$(jq -r '.instructions // ""' <<<"$BODY_I2"); A_COST=$(jq -r '.compute_cost // ""' <<<"$BODY_I2")
    if [[ -n "$A_INS" ]]; then
      [[ "$A_INS" == "$C_INS" ]] \
        && pass "I7 rung 2 the instruction count the client was told matches the row ($C_INS)" \
        || fail "I7 rung 2 the client was told $A_INS instructions and the row records $C_INS"
    else
      note "  the answer carried no instruction count to compare"
    fi
    if [[ -n "$A_COST" ]]; then
      [[ "$A_COST" == "$C_COST" ]] \
        && pass "I7 rung 2 and so does the cost ($C_COST)" \
        || fail "I7 rung 2 the client was told cost $A_COST and the row records $C_COST"
    fi
    A_MS=$(jq -r '.time_ms // ""' <<<"$BODY_I2")
    if [[ -n "$A_MS" ]]; then
      [[ "$A_MS" == "$C_MS" ]] \
        && pass "I7 rung 2 and so does the time it took ($C_MS ms)" \
        || fail "I7 rung 2 the client was told $A_MS ms and the row records $C_MS"
    fi
  fi

  if [[ -z "${R_REQ:-}" ]]; then
    fail "I7 rung 3 the call id reaches no execution request, so the walk stops here — the rungs below it cannot be judged either"
  else
    pass "I7 rung 3 the call id reaches the execution request ($R_REQ)"
    JROW=$(sql_row "SELECT job_id || '|' || COALESCE(worker_id,'') || '|' || status \
                      FROM jobs WHERE request_id = $R_REQ ORDER BY created_at DESC LIMIT 1")
    if [[ -z "$JROW" ]]; then
      fail "I7 rung 4 no job for request $R_REQ — the request that ran cannot be tied to the run"
    else
      IFS='|' read -r J_ID J_WORKER J_ST <<<"$JROW"
      note "job $J_ID on worker '${J_WORKER:-none}' — $J_ST"
      [[ -n "$J_WORKER" ]] \
        && pass "I7 rung 4 the run names the WORKER that did it ($J_WORKER) — the last link before the attestation, and the one that says whose enclave to ask" \
        || fail "I7 rung 4 the job records no worker; an execution nobody can be named for cannot be attested to afterwards"
      [[ "$J_ST" == "completed" ]] \
        && pass "I7 rung 4 and the job agrees the run finished" \
        || fail "I7 rung 4 the job is '$J_ST' for a call answered 200"
    fi
  fi

  # Rung 5 — the receipts. Deterministic from the call id, so the address is
  # answerable at once; the QUOTE behind it is uploaded by the worker after the
  # answer went out, which is why this waits rather than reads once.
  ATT_CODE=""
  for _ in 1 2 3 4 5 6; do
    throttle
    ATT_CODE=$(curl -sS -o /dev/null -w '%{http_code}' -m 30 "$COORDINATOR_URL$ATT_URL" 2>/dev/null)
    [[ "$ATT_CODE" == "200" ]] && break; sleep 5
  done
  if [[ "$ATT_CODE" == "200" ]]; then
    pass "I7 rung 5 the TEE attestation for this very call is reachable from the id the client holds — the walk closes"
  elif [[ "$ATT_CODE" == "404" ]]; then
    finding "I7 rung 5 the attestation for call $CALL_BOUND was still 404 half a minute after the answer. The address is right and the run is on file; what a client sees is a verification that is not yet there and nothing telling it when to look again"
  else
    fail "I7 rung 5 the attestation address answered HTTP $ATT_CODE"
  fi
fi

verdict "§5 identity"
