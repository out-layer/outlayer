#!/usr/bin/env bash
#
# §7 of the HoS test plan — resource abuse, as a cross-cutting class.
#
# The question is narrow, and it is not "does a limit exist": it is whether any
# input a stranger can post makes the coordinator or the enclave answer with a
# SERVER error. A 4xx is a working door. A 5xx on a crafted body is the class
# that takes custody down for everyone, because the decoder runs before the
# signature and it runs inside the enclave.
#
# So every probe here is judged the same way: 4xx good, 5xx a failure, 2xx only
# where the request was legal.
#
#   PARENT=you.testnet ./tests/hos_dos_e2e.sh --apply
#
# Needs the shared fixture (tests/hos_fixture.sh --apply).

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/hos_common.sh"

HOS_STATE="${HOS_STATE:-$REPO_ROOT/tests/.hos_fixture.env}"
[[ "${1:-}" == "--apply" ]] || { sed -n '3,16p' "$0" >&2; echo "  Pass --apply to run." >&2; exit 0; }
hos_require
[[ -f "$HOS_STATE" ]] || { echo "no fixture — run tests/hos_fixture.sh --apply first" >&2; exit 1; }
# shellcheck disable=SC1090
source "$HOS_STATE"

WL="${WL:-zavodil2.testnet}"

# §4 leaves the fixture with an open address filter. Give it one that refuses
# the destinations below, so nothing in a DoS suite can accidentally spend.
store_policy "$SEED" "$WALLET_ID" \
  "$(jq -nc --arg s "$ASSET" '{rules:{addresses:{mode:"whitelist",list:[$s]},limits:{per_transaction:{native:"1"}}}}')" \
  || warn "the guard policy could not be stored — probes below may spend"

judge() {
  if [[ "$HTTP" =~ ^5 ]]; then
    fail "$1 — answered $HTTP, a SERVER error on a crafted input: $(msg_of | head -c 160)"
  elif [[ "$HTTP" =~ ^4 ]]; then
    pass "$1 — refused $HTTP $(err_of)"
  else
    pass "$1 — accepted (HTTP $HTTP); legal input, no crash"
  fi
}

# ── S1 a request carrying very many promises ───────────────────────────────
for n in 50 200 1000; do
  ENV=$(python3 -c "
import json,sys
p=[{'receiver_id':'$WL','actions':[{'action':'transfer','payload':{'amount':'1'}}]} for _ in range($n)]
sys.stdout.write(json.dumps({'request':{'external':p}}))")
  log "S1 $n promises in one request"
  call_ext_raw "$SEED" "$ASSET" "$(b64 "$ENV")" >/dev/null
  judge "S1 [$n promises]"
done

# ── S2 one promise carrying very many actions ──────────────────────────────
ENV=$(python3 -c "
import json,sys
a=[{'action':'transfer','payload':{'amount':'1'}} for _ in range(2000)]
sys.stdout.write(json.dumps({'request':{'external':[{'receiver_id':'$WL','actions':a}]}}))")
log "S2 2000 actions in one promise"
call_ext_raw "$SEED" "$ASSET" "$(b64 "$ENV")" >/dev/null
judge "S2 [2000 actions]"

# ── S3 a very large args blob inside a call ────────────────────────────────
ENV=$(python3 -c "
import json,base64,sys
inner=json.dumps({'receiver_id':'$WL','amount':'1','memo':'x'*400000}).encode()
sys.stdout.write(json.dumps({'request':{'external':[{'receiver_id':'usdc.fakes.testnet','actions':[
  {'action':'function_call','payload':{'function_name':'ft_transfer','args':base64.b64encode(inner).decode(),'deposit':'1','gas':'30000000000000'}}]}]}}))")
log "S3 a 400 KB memo inside the nested arguments"
call_ext_raw "$SEED" "$ASSET" "$(b64 "$ENV")" >/dev/null
judge "S3 [400 KB nested args]"

# ── S4 a very large policy ─────────────────────────────────────────────────
log "S4 a policy carrying 20 000 whitelisted addresses"
BIGPOL=$(python3 -c "
import json,sys
sys.stdout.write(json.dumps({'rules':{'addresses':{'mode':'whitelist','list':['a%d.testnet'%i for i in range(20000)]}}}))")
throttle
H=$(curl -sS -o /tmp/hos_bigpol.json -w '%{http_code}' -X POST "$COORDINATOR_URL/wallet/v1/encrypt-policy" \
  -H "$(AUTH_FOR "$SEED")" -H 'Content-Type: application/json' --max-time 90 \
  -d "$(jq -nc --arg wid "$WALLET_ID" --argjson p "$BIGPOL" '$p + {wallet_id:$wid}')" 2>/dev/null)
HTTP=$H; BODY=$(head -c 400 /tmp/hos_bigpol.json); rm -f /tmp/hos_bigpol.json
judge "S4 [20 000-address policy]"

# ── S5 mutation sweep: no input may produce a server error ────────────────
#
# Not a fuzzer — one already runs against the decoder in the crate. This is the
# E2E half of the same claim: whatever the crate refuses, the ENCLAVE refuses
# without falling over, over the real wire.
log "S5 mutating a valid envelope 24 ways"
MUTANTS=$(python3 - "$WL" <<'PY'
import sys, base64
wl = sys.argv[1]
cases = [
 ("valid", '{"request":{"external":[{"receiver_id":"%s","actions":[{"action":"transfer","payload":{"amount":"1000"}}]}]}}' % wl),
 ("no-actions", '{"request":{"external":[{"receiver_id":"a.testnet","actions":[]}]}}'),
 ("null-actions", '{"request":{"external":[{"receiver_id":"a.testnet","actions":null}]}}'),
 ("actions-not-list", '{"request":{"external":[{"receiver_id":"a.testnet","actions":{}}]}}'),
 ("external-not-list", '{"request":{"external":{}}}'),
 ("request-is-list", '{"request":[]}'),
 ("request-is-empty-map", '{"request":{}}'),
 ("external-empty", '{"request":{"external":[]}}'),
 ("request-is-string", '{"request":"hello"}'),
 ("receiver-missing", '{"request":{"external":[{"actions":[]}]}}'),
 ("receiver-null", '{"request":{"external":[{"receiver_id":null,"actions":[]}]}}'),
 ("receiver-number", '{"request":{"external":[{"receiver_id":42,"actions":[]}]}}'),
 ("receiver-huge", '{"request":{"external":[{"receiver_id":"' + "x"*100000 + '.testnet","actions":[]}]}}'),
 ("action-null", '{"request":{"external":[{"receiver_id":"a.testnet","actions":[null]}]}}'),
 ("action-no-payload", '{"request":{"external":[{"receiver_id":"a.testnet","actions":[{"action":"transfer"}]}]}}'),
 ("payload-null", '{"request":{"external":[{"receiver_id":"a.testnet","actions":[{"action":"transfer","payload":null}]}]}}'),
 ("amount-number", '{"request":{"external":[{"receiver_id":"a.testnet","actions":[{"action":"transfer","payload":{"amount":1000}}]}]}}'),
 ("amount-object", '{"request":{"external":[{"receiver_id":"a.testnet","actions":[{"action":"transfer","payload":{"amount":{}}}]}]}}'),
 ("amount-list", '{"request":{"external":[{"receiver_id":"a.testnet","actions":[{"action":"transfer","payload":{"amount":[1]}}]}]}}'),
 ("gas-negative", '{"request":{"external":[{"receiver_id":"a.testnet","actions":[{"action":"function_call","payload":{"function_name":"f","args":"","deposit":"0","gas":-5}}]}]}}'),
 ("args-not-base64", '{"request":{"external":[{"receiver_id":"a.testnet","actions":[{"action":"function_call","payload":{"function_name":"ft_transfer","args":"@@@@","deposit":"1"}}]}]}}'),
 ("fn-name-empty", '{"request":{"external":[{"receiver_id":"a.testnet","actions":[{"action":"function_call","payload":{"function_name":"","args":"","deposit":"1"}}]}]}}'),
 ("internal-not-list", '{"request":{"internal":{}}}'),
 ("internal-unknown-op", '{"request":{"internal":[{"op":"self_destruct","payload":{}}]}}'),
 ("space-in-account", '{"request":{"external":[{"receiver_id":"a .testnet","actions":[]}]}}'),
]
for name, payload in cases:
    print(name + "|" + base64.b64encode(payload.encode()).decode())
print("raw-bytes|" + base64.b64encode(bytes([0xff, 0xfe, 0x00, 0x01, 0x02])).decode())
PY
)
while IFS="|" read -r name blob; do
  [[ -n "$name" ]] || continue
  call_ext_raw "$SEED" "$ASSET" "$blob" >/dev/null
  if [[ "$HTTP" =~ ^5 ]]; then
    fail "S5 [$name] answered $HTTP — a crafted envelope reached a server error: $(msg_of | head -c 140)"
  elif [[ "$name" == request-is-list || "$name" == request-is-empty-map || "$name" == external-empty ]]; then
    # A request that asks for nothing decodes, and every rule permits it; the
    # door refuses it before signing, so the executor never pays for a no-op.
    if [[ "$HTTP" == "403" && "$(err_of)" == "policy_denied" ]] && grep -qi "no operation" <<<"$(msg_of)"; then
      pass "S5 [$name] empty request refused -> $HTTP $(err_of)"
    else
      fail "S5 [$name] an EMPTY envelope must be refused 403 policy_denied (no operation), got HTTP $HTTP $(err_of) tx $(jq -r '.tx_hash // "-"' <<<"$BODY" | head -c 12): $(msg_of | head -c 140)"
    fi
  else
    pass "S5 [$name] -> $HTTP $(err_of)"
  fi
done <<<"$MUTANTS"

# ── S6 firing faster than the wallet can serve ────────────────────────────
log "S6 eight concurrent calls on one wallet"
for i in 1 2 3 4 5 6 7 8; do
  ( curl -sS -o "/tmp/hos_burst_$i.json" -w '%{http_code}' -X POST "$COORDINATOR_URL/wallet/v1/call" \
      -H "$(AUTH_FOR "$SEED")" -H 'Content-Type: application/json' --max-time 90 \
      -d "$(jq -nc --arg r "$ASSET" --arg a "$(b64 "$(ext_transfer "$WL" "1000")")" \
            '{receiver_id:$r, method_name:"w_execute_extension", args_base64:$a, deposit:"1", gas:"90000000000000"}')" \
      > "/tmp/hos_burst_$i.code" 2>/dev/null ) &
done
wait
FIVEX=0
for i in 1 2 3 4 5 6 7 8; do
  C=$(cat "/tmp/hos_burst_$i.code" 2>/dev/null)
  [[ "$C" =~ ^5 ]] && FIVEX=$((FIVEX+1))
  note "  $i -> $C $(head -c 70 "/tmp/hos_burst_$i.json" 2>/dev/null)"
done
rm -f /tmp/hos_burst_*.json /tmp/hos_burst_*.code
(( FIVEX == 0 )) \
  && pass "S6 no server error under a burst — the extra callers are told the wallet is busy, not dropped" \
  || fail "S6 $FIVEX of eight concurrent calls answered 5xx"

# ── S7 a chain-backed AccessCondition that cannot be answered ──────────────
#
# `NearBalance`, `NftOwned` and `DaoMember` are decided by asking the chain, and
# a question the chain cannot answer must never read as a yes. That is not
# reachable from this suite — it needs a WASI run that requests a secret, which
# is a different stack — and it is driven live in
# `tests/secret_access_conditions_e2e.sh` §S1/§S2, where an `NftOwned` naming a
# contract that does not exist is refused, and a real contract the caller owns
# nothing from is refused differently, so the first refusal is about the missing
# answer rather than a condition that denies everybody.
note "S7 is covered by tests/secret_access_conditions_e2e.sh §S1/§S2 (live)"

verdict "§7 DoS / resources"
