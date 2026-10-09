#!/usr/bin/env bash
#
# A project moves only onto an acceptance (`accept_project_transfer`) that the
# receiving account gave for exactly that project and that owner; names are
# ASCII. Against the DEPLOYED contract.
#
#   T0  the contract is on storage version 11 (otherwise every probe SKIPs)
#   T1  alice creates `alice/<name>`
#   T2  alice transfers it to bob with no acceptance → "has not accepted project"
#   T3  bob accepts `alice/<name>`, paying what estimate_transfer_acceptance_cost
#       quotes; the excess over the record comes back to bob in the same tx
#   T4  alice transfers → `bob/<name>` exists with the same uuid, `alice/<name>`
#       is gone, and the record's deposit returns to bob in the transfer's receipts
#   T5  an acceptance is for ONE owner: bob accepts `carol/<name>-2`; alice's
#       transfer of `alice/<name>-2` is still refused
#   T6  bob revokes that acceptance → its deposit comes back; a second revoke
#       → "has no acceptance"
#   T7  a name with a Cyrillic а is refused by create_project and by
#       accept_project_transfer
#   T8  a priced project does not move — needs the contract owner's key; SKIP
#       here, covered by the unit test `a_priced_project_does_not_move`
#   cleanup: bob deletes `bob/<name>`, alice deletes `alice/<name>-2`
#
# Run (spends testnet NEAR for storage deposits, refunded by the cleanups):
#   ./tests/project_transfer_e2e.sh --apply
#   OWNER=… TAKER=… OTHER=… override the accounts (defaults below).

set -uo pipefail

APPLY=false
[[ "${1:-}" == "--apply" ]] && APPLY=true

NETWORK="${NETWORK:-testnet}"
CONTRACT_ID="${CONTRACT_ID:-outlayer.testnet}"
OWNER="${OWNER:-outlayer-alice.testnet}"
TAKER="${TAKER:-outlayer-bob.testnet}"
OTHER="${OTHER:-outlayer-carol.testnet}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/rpc.sh"
source "$SCRIPT_DIR/lib/near_sign.sh"

PASS=0; FAILED=0; SKIPPED=0; FAILED_NAMES=()
log()  { printf '\n\033[36m▶ %s\033[0m\n' "$*" >&2; }
note() { printf '\033[35m• %s\033[0m\n' "$*" >&2; }
pass() { printf '\033[32m✓ %s\033[0m\n' "$*" >&2; PASS=$((PASS+1)); }
fail() { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; FAILED=$((FAILED+1)); FAILED_NAMES+=("$*"); }
skip() { printf '\033[33m∅ SKIP: %s\033[0m\n' "$*" >&2; SKIPPED=$((SKIPPED+1)); }

# view <method> <json-args> — the raw JSON the contract returned, or `null`.
view() {
  curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' --max-time 30 \
    -d "$(jq -nc --arg c "$CONTRACT_ID" --arg m "$1" --arg a "$(printf '%s' "$2" | base64 | tr -d '\n')" \
      '{jsonrpc:"2.0",id:1,method:"query",params:{request_type:"call_function",finality:"final",account_id:$c,method_name:$m,args_base64:$a}}')" \
    | jq -r '.result.result | implode' 2>/dev/null || echo 'null'
}

# tx <signer> <method> <json-args> <deposit> — sets OUT, RC, TXH, WHY. The
# whole CLI output stays in OUT; WHY is the contract's or the CLI's reason,
# never the raw output (which can carry the keyed RPC URL).
tx() {
  OUT=$(near contract call-function as-transaction "$CONTRACT_ID" "$2" json-args "$3" \
    prepaid-gas '100.0 Tgas' attached-deposit "$4" sign-as "$1" network-config "$NETWORK" \
    sign-with-keychain send 2>&1); RC=$?
  grep -q "succeeded" <<<"$OUT" || RC=1
  TXH=$(grep -aoE 'Transaction ID: [1-9A-HJ-NP-Za-km-z]{43,44}' <<<"$OUT" | head -1 | awk '{print $3}')
  WHY=$(near_why "$OUT")
}

# refunds <tx-hash> <sender> — "receiver amount" for every transfer the
# contract made inside that transaction.
refunds() {
  curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' --max-time 60 \
    -d "$(jq -nc --arg h "$1" --arg s "$2" '{jsonrpc:"2.0",id:1,method:"EXPERIMENTAL_tx_status",params:{tx_hash:$h,sender_account_id:$s,wait_until:"FINAL"}}')" \
  | jq -r --arg c "$CONTRACT_ID" '.result.receipts[]? | select(.predecessor_id == $c)
      | .receiver_id as $r | .receipt.Action.actions[]? | select(.Transfer) | "\($r) \(.Transfer.deposit)"'
}

refused() { # refused <label> <pattern>
  if [[ $RC -ne 0 ]] && grep -qi "$2" <<<"$WHY"; then pass "$1 refused: $(head -c 140 <<<"$WHY")"
  else fail "$1 expected a refusal naming /$2/, got rc=$RC: $WHY"; fi
}
succeeded() { if [[ $RC -eq 0 ]]; then pass "$1"; else fail "$1: $WHY"; fi; }

project() { view get_project "$(jq -nc --arg id "$1" '{project_id:$id}')"; }
sub() { python3 -c 'import sys; print(int(sys.argv[1]) - int(sys.argv[2]))' "$1" "$2"; }
yocto_of_near() { python3 -c 'import decimal,sys; print(int(decimal.Decimal(sys.argv[1]) * 10**24))' "$1"; }

SOURCE='{"WasmUrl":{"url":"https://example.invalid/transfer-probe.wasm","hash":"cbf80ed0080dd62f2041745cdc958ec0fbd192f33aeaa756f7873d742204b2f8","build_target":null}}'
NAME="xfer-$(date +%s)"
NAME2="$NAME-2"

if [[ "$APPLY" != true ]]; then
  cat >&2 <<PLAN
  (dry-run) contract $CONTRACT_ID on $NETWORK, RPC $(rpc_url_public)
  owner $OWNER, taker $TAKER, other $OTHER, project name $NAME
  Pass --apply to run T0–T8 and the cleanups.
PLAN
  exit 0
fi

note "RPC: $(rpc_url_public)"
for tool in near jq curl python3; do command -v "$tool" >/dev/null || { echo "✗ missing $tool" >&2; exit 1; }; done

log "T0 storage version"
VERSION=$(view get_storage_version '{}')
if [[ "$VERSION" != '"11"' ]]; then
  skip "contract is on storage version $VERSION, not 11 — the acceptance deploy is pending; nothing to probe"
  echo "PASS=$PASS FAILED=$FAILED SKIPPED=$SKIPPED" >&2
  exit 0
fi
pass "storage version 11"

log "T1 $OWNER creates $OWNER/$NAME"
tx "$OWNER" create_project "$(jq -nc --arg n "$NAME" --argjson s "$SOURCE" '{name:$n, source:$s}')" '0.05 NEAR'
succeeded "create_project $NAME"
UUID=$(project "$OWNER/$NAME" | jq -r '.uuid // empty')
[[ -n "$UUID" ]] && pass "project exists, uuid $UUID" || fail "get_project($OWNER/$NAME) answered nothing"

log "T2 transfer with no acceptance"
tx "$OWNER" transfer_project "$(jq -nc --arg n "$NAME" --arg o "$TAKER" '{project_name:$n, new_owner:$o}')" '0 NEAR'
refused "T2 unaccepted transfer" "has not accepted project"
[[ -n "$(project "$OWNER/$NAME" | jq -r '.uuid // empty')" ]] && pass "the project stayed with $OWNER" || fail "the project moved without an acceptance"

log "T3 $TAKER accepts $OWNER/$NAME"
QUOTE=$(view estimate_transfer_acceptance_cost "$(jq -nc --arg t "$TAKER" --arg f "$OWNER" --arg n "$NAME" '{new_owner:$t, from:$f, name:$n}')" | tr -d '"')
note "quoted $QUOTE yoctoNEAR for the record"
ATTACH=$(yocto_of_near 0.01)
tx "$TAKER" accept_project_transfer "$(jq -nc --arg f "$OWNER" --arg n "$NAME" '{from:$f, name:$n}')" '0.01 NEAR'
succeeded "accept_project_transfer"
EXCESS=$(refunds "$TXH" "$TAKER" | awk -v t="$TAKER" '$1==t {print $2}' | head -1)
if [[ -n "$EXCESS" ]]; then
  CHARGED=$(sub "$ATTACH" "$EXCESS")
  note "charged $CHARGED yoctoNEAR"
  if python3 -c 'import sys; q,c=int(sys.argv[1]),int(sys.argv[2]); sys.exit(0 if q>=c and q-c<=8*10**19 else 1)' "$QUOTE" "$CHARGED"; then
    pass "the quote covers the charge within a few bytes (quote $QUOTE, charge $CHARGED)"
  else fail "quote $QUOTE vs charge $CHARGED: the estimate must be at least the charge and close to it"; fi
else
  fail "no refund of the excess to $TAKER in $TXH"; CHARGED=""
fi

HELD=$(view get_project_transfer_acceptance "$(jq -nc --arg t "$TAKER" --arg f "$OWNER" --arg n "$NAME" '{new_owner:$t, from:$f, name:$n}')" | tr -d '"')
[[ -n "$CHARGED" && "$HELD" == "$CHARGED" ]] && pass "get_project_transfer_acceptance answers the deposit held ($HELD)" || fail "view answered '$HELD', charge was '$CHARGED'"

log "T4 $OWNER transfers; the record's deposit returns to $TAKER"
tx "$OWNER" transfer_project "$(jq -nc --arg n "$NAME" --arg o "$TAKER" '{project_name:$n, new_owner:$o}')" '0 NEAR'
succeeded "transfer_project"
NEW_UUID=$(project "$TAKER/$NAME" | jq -r '.uuid // empty')
[[ "$NEW_UUID" == "$UUID" ]] && pass "$TAKER/$NAME has the same uuid" || fail "$TAKER/$NAME uuid '$NEW_UUID', expected '$UUID'"
[[ "$(project "$OWNER/$NAME")" == "null" ]] && pass "$OWNER/$NAME is gone" || fail "$OWNER/$NAME still answers"
BACK=$(refunds "$TXH" "$OWNER" | awk -v t="$TAKER" '$1==t {print $2}' | head -1)
if [[ -n "$CHARGED" && "$BACK" == "$CHARGED" ]]; then pass "the acceptance deposit ($CHARGED) came back to $TAKER"
else fail "expected a transfer of $CHARGED to $TAKER in $TXH, saw '${BACK:-nothing}'"; fi
OWNER_LIST=$(view list_user_projects "$(jq -nc --arg a "$OWNER" '{account_id:$a}')" | jq -r --arg id "$OWNER/$NAME" '[.[]? | select(.project_id==$id)] | length')
TAKER_LIST=$(view list_user_projects "$(jq -nc --arg a "$TAKER" '{account_id:$a}')" | jq -r --arg id "$TAKER/$NAME" '[.[]? | select(.project_id==$id)] | length')
[[ "$OWNER_LIST" == 0 && "$TAKER_LIST" == 1 ]] && pass "the owner indices moved with it" || fail "indices: owner has $OWNER_LIST, taker has $TAKER_LIST"

[[ "$(view get_project_transfer_acceptance "$(jq -nc --arg t "$TAKER" --arg f "$OWNER" --arg n "$NAME" '{new_owner:$t, from:$f, name:$n}')")" == "null" ]] \
  && pass "the acceptance is consumed" || fail "the acceptance survived the transfer"

log "T5 an acceptance names the owner it is from"
tx "$OWNER" create_project "$(jq -nc --arg n "$NAME2" --argjson s "$SOURCE" '{name:$n, source:$s}')" '0.05 NEAR'
succeeded "create_project $NAME2"
tx "$TAKER" accept_project_transfer "$(jq -nc --arg f "$OTHER" --arg n "$NAME2" '{from:$f, name:$n}')" '0.01 NEAR'
succeeded "accept $OTHER/$NAME2"
ACCEPT2_TX="$TXH"
tx "$OWNER" transfer_project "$(jq -nc --arg n "$NAME2" --arg o "$TAKER" '{project_name:$n, new_owner:$o}')" '0 NEAR'
refused "T5 transfer from a different owner" "has not accepted project"

log "T6 revoke"
EXCESS2=$(refunds "$ACCEPT2_TX" "$TAKER" | awk -v t="$TAKER" '$1==t {print $2}' | head -1)
CHARGED2=$(sub "$ATTACH" "${EXCESS2:-0}")
tx "$TAKER" revoke_project_transfer "$(jq -nc --arg f "$OTHER" --arg n "$NAME2" '{from:$f, name:$n}')" '0 NEAR'
succeeded "revoke_project_transfer"
BACK2=$(refunds "$TXH" "$TAKER" | awk -v t="$TAKER" '$1==t {print $2}' | head -1)
[[ "$BACK2" == "$CHARGED2" ]] && pass "the revoked record's deposit ($CHARGED2) came back" || fail "expected $CHARGED2 back on revoke, saw '${BACK2:-nothing}'"
tx "$TAKER" revoke_project_transfer "$(jq -nc --arg f "$OTHER" --arg n "$NAME2" '{from:$f, name:$n}')" '0 NEAR'
refused "T6 second revoke" "has no acceptance for project"

log "T7 names are ASCII"
HOMOGLYPH="polym$(printf '\xd0\xb0')rket-$NAME"
tx "$OWNER" create_project "$(jq -nc --arg n "$HOMOGLYPH" --argjson s "$SOURCE" '{name:$n, source:$s}')" '0.05 NEAR'
refused "T7 create_project with a Cyrillic а" "ASCII letters, digits, dash, or underscore"
tx "$TAKER" accept_project_transfer "$(jq -nc --arg f "$OWNER" --arg n "$HOMOGLYPH" '{from:$f, name:$n}')" '0.01 NEAR'
refused "T7 accept_project_transfer with a Cyrillic а" "ASCII letters, digits, dash, or underscore"

log "T8 a priced project does not move"
skip "set_project_pricing is the contract owner's; covered by the unit test a_priced_project_does_not_move"

log "cleanup"
tx "$TAKER" delete_project "$(jq -nc --arg n "$NAME" '{project_name:$n}')" '0 NEAR'
succeeded "$TAKER deletes $TAKER/$NAME"
tx "$OWNER" delete_project "$(jq -nc --arg n "$NAME2" '{project_name:$n}')" '0 NEAR'
succeeded "$OWNER deletes $OWNER/$NAME2"

echo >&2
echo "PASS=$PASS FAILED=$FAILED SKIPPED=$SKIPPED" >&2
for n in "${FAILED_NAMES[@]:-}"; do [[ -n "$n" ]] && echo "  ✗ $n" >&2; done
[[ $FAILED -eq 0 ]]
