#!/bin/bash
# A daily budget under parallel calls, end to end.
#
# A connector that keeps a cap in project storage — the owner's messages a day,
# an agent's trading volume — must not let two calls at once both fit under it.
# The connectors reserve their share with the SDK's atomic `storage::increment`
# before doing the work and give it back when the work did not happen. The unit
# tests show the reservation logic is right on top of an atomic counter; this
# shows the counter IS atomic on the real worker and coordinator, which is the
# half no unit test can reach.
#
#   B1 a fresh budget reads zero
#   B2 N calls at once against a cap of CAP: no more than CAP get through, and
#      the counter afterwards equals exactly how many did
#   B3 a call past a full budget is refused and takes nothing
#   B4 a reservation the work did not use is given back
#   G1 (optional) the Gmail connector itself: N sends at once against the owner's
#      `max_per_day`, and `status` agrees with how many went
#
# B* use the testnet connector-probe's `budget` operation. It needs the probe
# version that has it, and the operation priced (`scripts/set_connector_prices_testnet.sh`).
#
# What this needs, and what SKIPS without it:
#   PAYMENT_KEY        a payment key funded with MONEY, with no subscription on
#                      it. A key paying from an allowance runs one call at a time
#                      by design, so it could never race; money runs them at once.
#   GMAIL_PAYMENT_KEY  for G1: a key the Gmail-connected wallet owns
#   GMAIL_WALLET_ID    for G1: that wallet's id
#   GMAIL_TEST_TO      for G1: an address the owner's policy allows — it WILL
#                      receive up to `max_per_day` real messages
#
# About `N + CAP + 6` connector calls at the defaults, roughly nineteen. A funded
# key has no call limit; a TRIAL key is ten calls in all and cannot finish — B2
# says so rather than blaming the counter.
#
# Run (dry-run prints the plan; --apply spends a little compute):
#   PAYMENT_KEY=… ./tests/connector_budget_parallel_e2e.sh --apply

set -uo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/agent_secret_mode.sh"

APPLY=false
[[ "${1:-}" == "--apply" ]] && APPLY=true

COORDINATOR_URL="${COORDINATOR_URL:-https://testnet-api.outlayer.ai}"
PROBE="${PROBE:-connectors.outlayer.testnet/connector-probe}"
GMAIL="${GMAIL:-connectors.outlayer.testnet/gmail}"
PAYMENT_KEY="${PAYMENT_KEY:-}"
N="${N:-12}"
CAP="${CAP:-5}"
GMAIL_PAYMENT_KEY="${GMAIL_PAYMENT_KEY:-}"
GMAIL_WALLET_ID="${GMAIL_WALLET_ID:-}"
GMAIL_TEST_TO="${GMAIL_TEST_TO:-}"

RUN="t$(date +%s)-$$"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0; FAIL=0; SKIP=0
pass() { echo "  PASS  $*"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL  $*"; FAIL=$((FAIL + 1)); }
skip() { echo "  SKIP  $*"; SKIP=$((SKIP + 1)); }

# One call to the probe's `budget` operation; prints the guest's output JSON.
probe() {
  local input="$1"
  curl -s --max-time 90 "$COORDINATOR_URL/call/$PROBE" \
    -H "X-Payment-Key: $PAYMENT_KEY" -H "Content-Type: application/json" \
    -d "{\"input\": $input}"
}

field() {  # field <json> <python expression over `o` = the guest output>
  python3 -c '
import json, sys
try:
    body = json.loads(sys.argv[1])
except Exception:
    print("<not json>"); sys.exit()
o = body.get("output", body)
if isinstance(o, str):
    try: o = json.loads(o)
    except Exception: pass
try:
    print(eval(sys.argv[2], {}, {"o": o}))
except Exception:
    print("<missing>")
' "$1" "$2"
}

# The counter, read with a retry. A read has no side effect — the counter is
# durable state and nobody else is touching this run id — so re-reading is safe
# in a way re-reserving would not be. One call straight after a burst of twelve
# parallel ones is not a measurement: a single transient refusal would read as a
# wrong count and accuse the connector of losing a reservation. On giving up it
# says what actually came back, because a bare "<not json>" teaches nothing.
counter() {  # counter <run-id>  → the count on stdout, diagnostics on stderr
  local run=$1 out value i
  for i in 1 2 3; do
    out="$(probe "{\"operation\":\"budget\",\"mode\":\"read\",\"run\":\"$run\"}")"
    value="$(field "$out" 'o["count"]')"
    case "$value" in
      ''|'<not json>'|'<missing>')
        # A retry is for a TRANSIENT refusal. A spent trial is not one: it
        # refuses every attempt for good.
        if [[ "$out" == *trial_exhausted* || "$out" == *trial_expired* ]]; then
          printf '%s' "unread"
          echo "        the counter cannot be read: this TRIAL key has made its calls — use a funded key — $(sed -n 's/.*"error":"\([^"]*\)".*/\1/p' <<<"$out" | head -c 120)" >&2
          return 0
        fi
        sleep 3 ;;
      *) printf '%s' "$value"; return 0 ;;
    esac
  done
  printf '%s' "unread"
  echo "        the counter could not be read in 3 tries; last answer: ${out:0:200}" >&2
}

echo "Budget under parallel calls — run id $RUN, N=$N, CAP=$CAP"
echo "  coordinator: $COORDINATOR_URL"
echo "  probe:       $PROBE"
if ! $APPLY; then
  echo
  echo "Dry run. Would: read a fresh budget, fire $N reservations at once against a cap of $CAP,"
  echo "check that at most $CAP were admitted and the counter equals the admitted number,"
  echo "then check a refusal past the cap and a released reservation. Add --apply to run."
  exit 0
fi

if [[ -z "$PAYMENT_KEY" ]]; then
  skip "B1–B4: no PAYMENT_KEY"
else
  echo; echo "B1 a fresh budget reads zero"
  count="$(counter "$RUN")"
  [[ "$count" == "0" ]] && pass "count=0" || fail "count=$count"

  echo; echo "B2 $N reservations at once against a cap of $CAP"
  for i in $(seq 1 "$N"); do
    probe "{\"operation\":\"budget\",\"mode\":\"reserve\",\"cap\":$CAP,\"run\":\"$RUN\"}" > "$WORK/b2.$i" &
  done
  wait
  admitted=0; refused=0; contended=0; broken=0; quota=0
  for i in $(seq 1 "$N"); do
    body="$(cat "$WORK/b2.$i")"
    case "$(field "$body" 'o["admitted"]')" in
      True) admitted=$((admitted + 1)) ;;
      False)
        if [[ "$(field "$body" '"could not be updated" in o.get("detail","")')" == "True" ]]; then
          contended=$((contended + 1))
        else
          refused=$((refused + 1))
        fi ;;
      # A SPENT TRIAL answers before the module runs, so its refusal is the
      # coordinator's JSON and not the module's — it has no `admitted` field and
      # would otherwise be counted as an unreadable answer, failing the run with
      # a message about the wrong thing. It is its own case because it means
      # this run cannot be judged at all: the calls that were refused never
      # reached the counter under test.
      *) if [[ "$body" == *trial_exhausted* || "$body" == *trial_expired* ]]; then
           quota=$((quota + 1))
         else
           broken=$((broken + 1)); echo "        unreadable answer: ${body:0:200}"
         fi ;;
    esac
  done
  echo "        admitted=$admitted refused-by-cap=$refused refused-by-contention=$contended quota=$quota unreadable=$broken"
  if [[ "$quota" -gt 0 ]]; then
    fail "$quota of $N calls were refused because the key is a SPENT TRIAL, not by the cap — the counter under test never saw them. Use a funded key, which has no call limit."
  fi
  [[ "$broken" -eq 0 ]] && pass "every call answered" || fail "$broken calls gave no readable answer"
  [[ "$admitted" -le "$CAP" ]] && pass "no more than the cap got through ($admitted ≤ $CAP)" \
                                 || fail "THE CAP WAS PASSED: $admitted admitted against $CAP"
  [[ "$admitted" -ge 1 ]] && pass "at least one got through" || fail "nothing was admitted"
  if [[ "$contended" -gt 0 ]]; then
    echo "        note: $contended calls lost the compare-and-swap five times and were refused —"
    echo "        the safe direction; it means fewer than the cap may have been admitted"
  fi
  count="$(counter "$RUN")"
  [[ "$count" == "$admitted" ]] && pass "the counter equals the admitted calls ($count)" \
                                  || fail "counter=$count but $admitted were admitted — a reservation leaked or was lost"

  echo; echo "B3 a call past a full budget"
  fill=$(( CAP - admitted ))
  for _ in $(seq 1 "$fill"); do
    probe "{\"operation\":\"budget\",\"mode\":\"reserve\",\"cap\":$CAP,\"run\":\"$RUN\"}" > /dev/null
  done
  out="$(probe "{\"operation\":\"budget\",\"mode\":\"reserve\",\"cap\":$CAP,\"run\":\"$RUN\"}")"
  [[ "$(field "$out" 'o["admitted"]')" == "False" ]] && pass "refused" || fail "admitted past a full budget — $out"
  count="$(counter "$RUN")"
  [[ "$count" == "$CAP" ]] && pass "the refusal took nothing (count=$count)" || fail "count=$count, expected $CAP"

  echo; echo "B4 a reservation the work did not use is given back"
  RUN2="${RUN}-release"
  out="$(probe "{\"operation\":\"budget\",\"mode\":\"release\",\"cap\":$CAP,\"run\":\"$RUN2\"}")"
  [[ "$(field "$out" 'o["admitted"]')" == "True" ]] && pass "the reservation was taken" || fail "not taken — $out"
  count="$(counter "$RUN2")"
  [[ "$count" == "0" ]] && pass "and given back (count=0)" || fail "count=$count after a release"
fi

echo; echo "G1 the Gmail connector's own budget"
if ! agent_secret_mode G1; then
  :
elif [[ -z "$GMAIL_PAYMENT_KEY" || -z "$GMAIL_WALLET_ID" || -z "$GMAIL_TEST_TO" ]]; then
  skip "G1: needs GMAIL_PAYMENT_KEY, GMAIL_WALLET_ID and GMAIL_TEST_TO"
else
  gmail() {
    curl -s --max-time 90 "$COORDINATOR_URL/call/$GMAIL" \
      -H "X-Payment-Key: $GMAIL_PAYMENT_KEY" -H "X-Wallet-Id: $GMAIL_WALLET_ID" \
      -H "X-Use-Owner-Secret: 1" -H "Content-Type: application/json" -d "{\"input\": $1}"
  }
  # The connector answers an envelope {success, operation, error, output,
  # logs}; the fields are under `output`, a cap refusal is success:false with
  # error "policy_denied: N of the owner's M messages a day are used; …".
  status="$(gmail '{"operation":"status"}')"
  max="$(field "$status" 'o["output"]["policy"]["max_per_day"]')"
  before="$(field "$status" 'o["output"]["sent_today"]')"
  if ! [[ "$max" =~ ^[0-9]+$ && "$before" =~ ^[0-9]+$ ]]; then
    fail "status did not report max_per_day and sent_today — $status"
  else
    room=$(( max - before ))
    echo "        max_per_day=$max sent_today=$before room=$room; firing $N sends"
    for i in $(seq 1 "$N"); do
      gmail "{\"operation\":\"send\",\"to\":\"$GMAIL_TEST_TO\",\"subject\":\"budget check $RUN #$i\",\"body\":\"parallel budget check\"}" > "$WORK/g1.$i" &
    done
    wait
    sent=0
    for i in $(seq 1 "$N"); do
      [[ "$(field "$(cat "$WORK/g1.$i")" 'bool(o.get("success")) and "message_id" in (o.get("output") or {})')" == "True" ]] && sent=$((sent + 1))
    done
    # Nothing sent means the cap was never approached, and both asserts below
    # would pass on an empty run: 0 ≤ room, and after == before + 0. The one
    # honest exception is a cap already reached today (room 0): then every
    # send must be refused, and that refusal IS the cap working.
    if (( room == 0 )); then
      # Refused BY THE CAP — the sentence the cap writes — not merely "no
      # message_id": a dead credential or a rejected recipient also sends
      # nothing, and would pass a row that only counted silence.
      refused=0
      for i in $(seq 1 "$N"); do
        [[ "$(field "$(cat "$WORK/g1.$i")" '(not o.get("success")) and "messages a day are used" in str(o.get("error") or "")')" == "True" ]] && refused=$((refused + 1))
      done
      [[ "$refused" == "$N" ]] && pass "the cap was already reached today and every send was refused by the cap ($N/$N)" \
                               || fail "THE OWNER'S CAP WAS PASSED, or a send failed for another reason: room 0, yet only $refused of $N were refused by the cap"
    else
      [[ "$sent" -ge 1 ]] || fail "G1 nothing was sent with room for $room — the cap was never exercised, so the two checks below say nothing"
    fi
    [[ "$sent" -le "$room" ]] && pass "no more than the room was sent ($sent ≤ $room)" \
                              || fail "THE OWNER'S CAP WAS PASSED: $sent sent with room for $room"
    after="$(field "$(gmail '{"operation":"status"}')" 'o["output"]["sent_today"]')"
    [[ "$after" == "$(( before + sent ))" ]] && pass "status agrees ($after)" \
                                             || fail "status says $after, expected $(( before + sent ))"
  fi
fi

echo
echo "passed $PASS, failed $FAIL, skipped $SKIP"
[[ "$FAIL" -eq 0 ]]
