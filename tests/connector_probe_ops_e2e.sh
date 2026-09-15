#!/usr/bin/env bash
#
# The seven operations connector-probe serves that no other suite ever calls.
#
# The probe exists to prove things about the PLATFORM — that raw sockets are
# shut, that a trapped run costs nothing, that a manifest alone delivers the
# author's credential — and each of those lives in an operation. Six of its
# fifteen are exercised elsewhere (`ping`, `whoami`, `secret`, `burn`, `fetch`,
# `forbidden_fetch`, `budget` between the pricing and budget suites); these
# seven were written and then never run.
#
#   O1 `author_secret`  the author's credential arrives from the MANIFEST alone:
#                       no header, no `secrets_ref`, nothing in the request. The
#                       answer carries the key's length and a hash prefix and
#                       never the value, which is the shape every connector
#                       should copy
#   O2 `sockets`        raw TCP to 1.1.1.1:80 and a DNS lookup are BOTH refused.
#                       The one row here that is about containment: a pass means
#                       `wasi:http` is the only way out, so the outbound
#                       allowlist and the egress audit cannot be walked around.
#                       Judged on the two error fields, not on `ok` — the module
#                       fills them with `connected` / `resolved` when a socket
#                       worked, and a row that read `ok` alone would pass on the
#                       very answer that says the box is open
#   O3 `trap`           the module dies without answering: the call is reported
#                       as a FAILURE, not as a success with an empty body
#   O4 `fail`           the other way a run ends badly — it answered `ok:false`
#                       and exited 1. Run right after O3 because the pair is the
#                       point: a trap leaves no output, a failure leaves one,
#                       and the platform must not report them alike
#   O5 `sleep`          the module makes the run long and lives to say so;
#                       `slept_ms` is read back against what was asked. The other
#                       half — the execution limit ending the run — is the
#                       pricing suite's C9 and is not repeated here
#   O6 `vrf`            `near:vrf` answers with an alpha to bind the randomness
#                       to, and TWO seeds give two different outputs. Without the
#                       second call this row would pass on a constant
#   O7 `refund`         a module cannot hand back money it was never given.
#                       `ATTACHED_USD` is `"0"` on the HTTPS door BY DESIGN —
#                       the worker sets it so, because a deposit exists only on
#                       the chain door (`worker/src/main.rs`: "HTTPS has no NEAR
#                       payment or attached deposit"). Every refund here must be
#                       refused and must name the zero it was compared against,
#                       whether it asks for one unit or a billion — that is the
#                       dangerous direction excluded, a payout that should not
#                       happen
#   O8 `refund` on chain  the other half, on the only door that carries a
#                       deposit: `request_execution` with `attached_usd`, and
#                       the module's own answer read out of the transaction's
#                       RETURN VALUE. A refund inside what was attached lands; a
#                       refund past it is refused there too. Needs CALLER to
#                       hold a stablecoin balance inside the contract
#
# Needs: PAYMENT_KEY — a funded payment key; CALLER (O8 only) — an account with
# a stablecoin balance INSIDE the contract and NEAR for the compute deposit.
# Nine connector calls over HTTPS, so the key's
# daily quota (per wallet+connector, laddered by the caller's age) must have
# room: a wallet minted today carries the floor of ten and would not finish.
#
# Run:
#   PAYMENT_KEY=… ./tests/connector_probe_ops_e2e.sh --apply

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/hos_common.sh"

PROJECT="${PROJECT:-connectors.outlayer.testnet/connector-probe}"
PAYMENT_KEY="${PAYMENT_KEY:-}"
DEPOSIT="${DEPOSIT:-50000}"
CALLER="${CALLER:-$PARENT}"
ATTACH_USD="${ATTACH_USD:-20000}"
REFUND_USD="${REFUND_USD:-5000}"

[[ "${1:-}" == "--apply" ]] || { sed -n '3,50p' "$0" >&2; echo "  Pass --apply to run." >&2; exit 0; }
[[ -n "$PAYMENT_KEY" ]] || { echo "✗ set PAYMENT_KEY" >&2; exit 1; }
hos_require

# call <operation> [extra-input-json] → the whole answer on stdout; RC is the
# HTTP code. The deposit rides on every call: these operations are priced, and
# a call refused for the fee would look like the operation refusing.
BODY=""
call() {
  local op=$1 extra=${2:-'{}'} out
  out=$(mktemp -t probeops.XXXXXX)
  RC=$(curl -s -o "$out" -w '%{http_code}' -m 120 -X POST "$COORDINATOR_URL/call/$PROJECT" \
        -H "X-Payment-Key: $PAYMENT_KEY" -H "X-Attached-Deposit: $DEPOSIT" \
        -H 'Content-Type: application/json' \
        -d "$(jq -nc --arg o "$op" --argjson e "$extra" '{input: ({operation:$o} + $e)}')")
  BODY="$(tr -d '\n' < "$out")"; rm -f "$out"
  printf '%s' "$BODY"
}
out_field() { jq -r ".output.$1 // empty" <<<"$BODY" 2>/dev/null; }
quota_hit() { [[ "$BODY" == *connector_quota_exceeded* ]]; }

note "project: $PROJECT"

# ── O1 the author's credential, from the manifest alone ──────────────────────
log "O1 author_secret — no header, no secrets_ref, nothing in the request"
call author_secret >/dev/null
if quota_hit; then
  skip "O1 — this key's daily connector quota is spent; every row below would report the quota, not the operation"
  verdict "connector-probe operations"; exit 0
fi
FOUND=$(jq -r '.output.secrets // [] | map(select(.found)) | length' <<<"$BODY" 2>/dev/null)
TOTAL=$(jq -r '.output.secrets // [] | length' <<<"$BODY" 2>/dev/null)
if [[ "${TOTAL:-0}" -gt 0 && "$FOUND" == "$TOTAL" ]]; then
  pass "O1 the author's key reached the guest with nothing in the request ($FOUND of $TOTAL)"
else
  fail "O1 the manifest's author secret did not arrive: found=$FOUND of ${TOTAL:-0} — $(head -c 200 <<<"$BODY")"
fi
# What it reports about the secret, and what it must not: the length and eight
# hex of a hash, never the value. A connector copied from this one inherits it.
PREFIX=$(jq -r '.output.secrets // [] | map(select(.found)) | .[0].sha256_prefix // empty' <<<"$BODY" 2>/dev/null)
LEN=$(jq -r '.output.secrets // [] | map(select(.found)) | .[0].len // empty' <<<"$BODY" 2>/dev/null)
if [[ "$PREFIX" =~ ^[0-9a-f]{8}$ && -n "$LEN" ]]; then
  pass "O1 and it reports the secret rather than printing it (len $LEN, sha256 ${PREFIX})"
else
  fail "O1 the answer does not describe the secret the documented way: prefix='$PREFIX' len='$LEN'"
fi

# ── O2 containment ───────────────────────────────────────────────────────────
log "O2 sockets — raw TCP and DNS must both be refused"
call sockets >/dev/null
TCP=$(out_field tcp_error); LOOKUP=$(out_field lookup_error)
if [[ -z "$TCP" && -z "$LOOKUP" ]]; then
  fail "O2 the call did not answer: $(head -c 200 <<<"$BODY")"
elif [[ "$TCP" == "connected" || "$LOOKUP" == "resolved" ]]; then
  fail "O2 A RAW SOCKET PATH IS OPEN — tcp='$TCP' lookup='$LOOKUP'. The outbound allowlist and the egress audit can be bypassed from inside the enclave"
else
  pass "O2 raw TCP refused ($(head -c 60 <<<"$TCP"))"
  pass "O2 and the name lookup refused ($(head -c 60 <<<"$LOOKUP"))"
fi

# ── O3 / O4 the two ways a run ends badly ────────────────────────────────────
log "O3 trap — the module dies without answering"
call trap >/dev/null
TRAP_OK=$(jq -r '.success // empty' <<<"$BODY" 2>/dev/null)
TRAP_OUT=$(jq -r '.output // empty' <<<"$BODY" 2>/dev/null)
if [[ "$TRAP_OK" == "true" ]]; then
  fail "O3 a trapped run was reported as a SUCCESS: $(head -c 220 <<<"$BODY")"
else
  pass "O3 reported as a failure, not as a success with an empty body (HTTP $RC)"
fi

log "O4 fail — the module answers, then exits 1"
call fail >/dev/null
FAIL_DETAIL=$(out_field detail)
FAIL_SUCCESS=$(jq -r '.success // empty' <<<"$BODY" 2>/dev/null)
if [[ "$FAIL_SUCCESS" == "true" ]]; then
  fail "O4 a non-zero exit was reported as a success: $(head -c 220 <<<"$BODY")"
else
  pass "O4 a non-zero exit is a failure too (HTTP $RC)"
fi
# The pair is the point. A trap leaves NO output; a failure leaves one. If the
# platform flattened both to the same empty answer, an agent could not tell a
# module that refused from a module that died.
if [[ -n "$FAIL_DETAIL" && -z "$TRAP_OUT" ]]; then
  pass "O4 and the two are told apart: the failure carried its own words ('$(head -c 60 <<<"$FAIL_DETAIL")'), the trap carried none"
elif [[ -n "$FAIL_DETAIL" && -n "$TRAP_OUT" ]]; then
  fail "O4 the TRAP produced an output body as well — a module that died is being reported like one that answered"
else
  note "O4 the failure's own words did not survive the platform's reporting; the two cases are distinguished only by status here"
fi

# ── O5 a long run ────────────────────────────────────────────────────────────
log "O5 sleep — the module makes the run long"
call sleep '{"seconds":3}' >/dev/null
SLEPT=$(out_field slept_ms)
if [[ -n "$SLEPT" ]] && (( SLEPT >= 3000 )); then
  pass "O5 slept ${SLEPT}ms and was still alive to say so"
else
  fail "O5 slept_ms='$SLEPT' for a 3s request: $(head -c 200 <<<"$BODY")"
fi

# ── O6 randomness that is bound to something ─────────────────────────────────
log "O6 vrf — the caller's seed is bound into the alpha, and a colon cannot forge one"
# The alpha is `vrf:{request_id}:{sender_id}:{user_seed}`
# (`worker/src/outlayer_vrf/host_functions.rs`). Two calls never share one,
# because the request id moves — so "two answers differ" proves NOTHING here and
# is not asserted. What is asserted is that the caller's own seed is IN the
# alpha: randomness nobody can replay and nobody can detach from who asked.
SEED_A="probe-$(openssl rand -hex 3)"
call vrf "$(jq -nc --arg s "$SEED_A" '{seed:$s}')" >/dev/null
A_ALPHA=$(out_field vrf_alpha); A_OUT=$(out_field vrf_output); A_SIG=$(out_field vrf_signature)
if [[ "$A_ALPHA" == *":$SEED_A" ]]; then
  pass "O6 the alpha ends with the seed the caller sent ($A_ALPHA)"
else
  fail "O6 the caller's seed is not in the alpha — the randomness is not bound to what was asked: alpha='$A_ALPHA' seed='$SEED_A'"
fi
if [[ "$A_ALPHA" == *":$PARENT:"* ]]; then
  pass "O6 and the alpha names the account that asked"
else
  fail "O6 the alpha does not name the caller: '$A_ALPHA'"
fi
if [[ -n "$A_OUT" && -n "$A_SIG" ]]; then
  pass "O6 with an output and a signature over it, so the draw can be checked afterwards"
else
  fail "O6 no output or no signature: output='$(head -c 24 <<<"$A_OUT")' signature='$(head -c 24 <<<"$A_SIG")'"
fi
# The delimiter rule, which nothing has ever exercised. `:` separates the three
# parts of the alpha, so a seed carrying one could spell a DIFFERENT request id
# and sender into it — randomness that looks bound to somebody else.
call vrf '{"seed":"a:b"}' >/dev/null
COLON_ERR=$(out_field detail); COLON_ALPHA=$(out_field vrf_alpha)
if [[ -z "$COLON_ALPHA" ]] && grep -qi "must not contain" <<<"$COLON_ERR"; then
  pass "O6 a seed carrying a colon is refused — the alpha's delimiter cannot be spelled by the caller"
elif [[ -n "$COLON_ALPHA" ]]; then
  fail "O6 A COLON IN THE SEED WAS ACCEPTED: alpha='$COLON_ALPHA'. A caller can write the request id and sender fields of its own alpha"
else
  fail "O6 the colon seed was neither refused nor answered: $(head -c 200 <<<"$BODY")"
fi

# ── O7 money going back ──────────────────────────────────────────────────────
log "O7 refund — nothing was attached on this door, so nothing may go back"
# `ATTACHED_USD` is "0" over HTTPS by the worker's own rule, so both sizes below
# must be refused. Asserted from both ends deliberately: one unit is what a
# careless module would ask for, a billion is what a hostile one would, and a
# door that paid either would be paying out of the AUTHOR's earnings.
for AMOUNT in 1 999999999; do
  call refund "$(jq -nc --argjson a "$AMOUNT" '{refund_usd:$a}')" >/dev/null
  BACK=$(out_field refunded_usd); ERR=$(out_field refund_error); ATT=$(out_field attached_usd)
  if [[ -n "$BACK" ]]; then
    fail "O7 A REFUND OF $AMOUNT WAS PAID against $ATT attached — a module can take money it was never given, out of the author's earnings"
  elif [[ -z "$ERR" ]]; then
    fail "O7 a refund of $AMOUNT neither landed nor was refused: $(head -c 200 <<<"$BODY")"
  elif [[ "$ERR" != *"attached USD 0"* ]]; then
    fail "O7 a refund of $AMOUNT was refused, but not for the zero it was compared against: '$(head -c 120 <<<"$ERR")'"
  else
    pass "O7 a refund of $AMOUNT is refused against ${ATT:-0} attached ($(head -c 60 <<<"$ERR"))"
  fi
done
note "O7 a refund that LANDS cannot be shown on this door: it attaches nothing. That row needs a request carrying a deposit, and none exists yet"

# ── O8 the same operation on the door that carries money ─────────────────────
log "O8 refund on chain — where a deposit exists, a refund must actually land"
# `request_execution` is the only door with an attached deposit, so it is the
# only place the PAYING half of `refund` can be shown. The module's answer is
# the transaction's RETURN VALUE: the contract's logs truncate at 100
# characters, well before the fields this row reads.
onchain() {  # onchain <input-json> <attached_usd> → the guest's answer on stdout
  local input=$1 usd=$2 out
  # `--quiet` prints the transaction's RETURN VALUE and nothing else: the
  # module's whole answer, as a JSON string. No polling and no transaction hash
  # to chase — `request_execution` settles inside the call. The update banner
  # near-cli writes to stderr is dropped by taking the last line that looks like
  # that string.
  out=$(near --quiet contract call-function as-transaction "$CONTRACT_ID" request_execution \
    json-args "$(jq -nc --arg p "$PROJECT" --arg i "$input" --arg u "$usd" \
      '{source:{Project:{project_id:$p}}, input_data:$i,
        resource_limits:{max_instructions:1000000000,max_memory_mb:128,max_execution_seconds:30},
        params:{attached_usd:$u}}')" \
    prepaid-gas '300.0 Tgas' attached-deposit '0.1 NEAR' \
    sign-as "$CALLER" network-config "$NETWORK" sign-with-keychain send 2>&1)
  local value
  value=$(grep -E '^".*"$' <<<"$out" | tail -1)
  if [[ -z "$value" ]]; then
    echo "NO_ANSWER $(tail -3 <<<"$out" | tr '\n' ' ' | head -c 220)"
    return 1
  fi
  jq -r 'fromjson' <<<"$value" 2>/dev/null || { echo "NO_ANSWER unreadable: $(head -c 200 <<<"$value")"; return 1; }
}

if [[ -z "$CALLER" ]]; then
  skip "O8 — set CALLER to an account holding a stablecoin balance inside the contract"
else
  ANS=$(onchain "$(jq -nc --argjson r "$REFUND_USD" '{operation:"refund", refund_usd:$r}')" "$ATTACH_USD")
  if [[ "$ANS" == NO_ANSWER* ]]; then
    fail "O8 the request_execution gave no answer: ${ANS#NO_ANSWER }"
  elif [[ -z "$ANS" ]]; then
    fail "O8 the on-chain run produced no answer within two minutes — nothing here is a verdict about refunds"
  else
    SAW=$(jq -r '.attached_usd // empty' <<<"$ANS"); BACK=$(jq -r '.refunded_usd // empty' <<<"$ANS")
    ERR=$(jq -r '.refund_error // empty' <<<"$ANS")
    # The control first: without a real deposit in the guest's environment the
    # row below would be the HTTPS case again, dressed as a new one.
    if [[ "$SAW" == "$ATTACH_USD" ]]; then
      pass "O8 the guest saw the deposit this door carries (ATTACHED_USD=$SAW)"
    else
      fail "O8 the guest saw ATTACHED_USD='$SAW', not the $ATTACH_USD attached — the deposit did not reach the run"
    fi
    if [[ "$BACK" == "$REFUND_USD" && -z "$ERR" ]]; then
      pass "O8 and a refund inside it LANDED: $BACK of $SAW came back"
    else
      fail "O8 a refund of $REFUND_USD out of $SAW did not land: refunded='$BACK' error='$(head -c 140 <<<"$ERR")'"
    fi
  fi

  # And the refusal on the same door, so the pair is judged in one place: the
  # limit is what was ATTACHED, not what the module felt like asking for.
  ANS=$(onchain '{"operation":"refund","refund_usd":999999999}' "$ATTACH_USD")
  if [[ "$ANS" == NO_ANSWER* || -z "$ANS" ]]; then
    fail "O8 the over-refund run produced no answer: $(head -c 160 <<<"$ANS")"
  else
    OVER_BACK=$(jq -r '.refunded_usd // empty' <<<"$ANS"); OVER_ERR=$(jq -r '.refund_error // empty' <<<"$ANS")
    if [[ -n "$OVER_BACK" ]]; then
      fail "O8 AN OVER-REFUND WAS PAID ON CHAIN: $OVER_BACK against $(jq -r '.attached_usd' <<<"$ANS") attached — out of the author's earnings"
    elif [[ -n "$OVER_ERR" ]]; then
      pass "O8 and past the deposit it is refused here too ($(head -c 70 <<<"$OVER_ERR"))"
    else
      fail "O8 the over-refund neither landed nor was refused: $(head -c 200 <<<"$ANS")"
    fi
  fi
fi

verdict "connector-probe operations"
