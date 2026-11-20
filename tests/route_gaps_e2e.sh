#!/usr/bin/env bash
#
# Withdraw and swap routes on MAINNET, dry and quoted only — nothing is signed,
# nothing moves. The wallet is the test agent's (`.env.test-agent`), which
# holds a little ZEC on intents (`nep141:zec.omft.near`) and nothing else.
#
#   M1  public dry withdraw of ZEC to chains the catalog lists: aptos and
#       starknet list ZEC, so the route is assessed — would_succeed, or 1Click's
#       own refusal (upstream_rejected / no_liquidity); ton and xrp list no ZEC,
#       so only the chain's recognition is checked (unsupported_token expected).
#       Never unsupported_chain
#   M2  confidential dry withdraw to the same chains: never unsupported_chain;
#       200, or a typed refusal (on ton/xrp unsupported_token, as in M1)
#   M3  confidential dry withdraw of a HOT `nep245:` asset to its chain: the
#       chain is recognized
#   M4  swap quotes with a `1cs_v1:` destination (ZEC sol / near / starknet,
#       CFI base): 200 with an amount_out
#   M5  swap quote with a `1cs_v1:sol:…` SOURCE: 400 unsupported_token naming
#       intents.near
#   M6  swap quote with the NEAR-side `1cs_v1:near:nep141:zec.omft.near` source: 200
#   M7  public dry withdraw of that id on chain near: a real reason, no mangled id
#   M8  dry withdraw to `nosuchchain`: 400 unsupported_chain naming the catalog
#   M9  confidential swap quote wNEAR → NPRO (HoS item 7): no_liquidity
#   M10 public dry withdraw of 1 unit of ZEC to Zcash: upstream_rejected or
#       no_liquidity, with 1Click's words
#   M11 confidential dry withdraw of BSC USDT (`nep141:bnb-….omdep.near`) to
#       bsc: the chain is the catalog's `bsc`, not the id's `bnb` — 200 or
#       1Click's own refusal, never unsupported_chain
#   M12 confidential dry withdraw to near of an asset from another chain: it
#       arrives as NEAR's listing of its symbol — ZEC, BSC USDT, Polygon USDC
#       and strkBTC (listed on near) are quoted with an amount_out
#   M13 confidential dry withdraw of native BNB to near: NEAR lists no BNB —
#       400 unsupported_token
#
# The confidential dry-run quotes without reading the balance, so M11–M13 name
# assets the wallet does not hold.
#
# Public dry-runs count against the wallet's daily custody ceiling (M1 ×4, M7,
# M10), confidential ones too (M2 ×4, M3, M11, M12 ×4, M13); quotes do not.
#
# Run:
#   ./tests/route_gaps_e2e.sh --apply
#   ENV_FILE=connectors/polymarket-connector/.env.test-agent   (WK, NEAR_ACCOUNT_ID)

NETWORK=mainnet
COORDINATOR_URL="${COORDINATOR_URL:-https://api.outlayer.ai}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/hos_common.sh"

[[ "${1:-}" == "--apply" ]] || { warn "Dry run. Pass --apply."; exit 0; }
note "RPC: $(rpc_url_public)"
ENV_FILE="${ENV_FILE:-$REPO_ROOT/connectors/polymarket-connector/.env.test-agent}"
[[ -f "$ENV_FILE" ]] || { echo "✗ no $ENV_FILE" >&2; exit 1; }
set -a; source "$ENV_FILE"; set +a
: "${WK:?WK (the wallet wk_) is not in $ENV_FILE}"
: "${NEAR_ACCOUNT_ID:?NEAR_ACCOUNT_ID is not in $ENV_FILE}"
note "wallet key present (${#WK} chars), account $NEAR_ACCOUNT_ID"

ZEC="nep141:zec.omft.near"
ZEC_NEAR_1CS="1cs_v1:near:nep141:zec.omft.near"
ZEC_SOL_1CS="1cs_v1:sol:spl:A7bdiYdS5GjqGFtxf17ppRHtDKPkkRqbKtR27dxvQXaS"
ZEC_STARKNET_1CS="1cs_v1:starknet:erc20:0x05ce53b9b68fb8e9ecab9283a96d97948914733fd6ed8d9a53a276a419497841"
CFI_BASE_1CS="1cs_v1:base:erc20:0x0382e3fee4a420bd446367d468a6f00225853420"
HOT_POL="nep245:v2_1.omni.hot.tg:137_2jwTGwKRX3AEe7tyzDrxtDjEFgSt"
WNEAR="nep141:wrap.near"
NPRO="nep141:npro.nearmobile.near"
EVM_TO="0x000000000000000000000000000000000000dEaD"
# 1Click refuses the burn address as a BSC recipient; a fresh one per run.
EVM_LIVE_TO="0x$(openssl rand -hex 20)"
BSC_USDT="nep141:bnb-0x55d398326f99059ff775485246999027b3197955.omdep.near"
BNB="nep141:bnb.omdep.near"
POL_USDC="nep141:pol-0x3c499c542cef5e3811e1192ce70d8cc03d5c3359.omdep.near"
STRK_BTC="nep141:strk-0xe646ef2a705bf5147ceffc8dfbcc7bee4946b8f7.omdep.near"
# A Move / Starknet address: 0x + 64 hex.
HEX64_TO="0x$(printf '1%.0s' $(seq 1 64))"
TYPED='^(no_liquidity|upstream_rejected|unsupported_token|insufficient_balance|storage_not_registered|recipient_not_found|policy_denied|invalid_request)$'

# The ZEC the wallet holds on intents, in minimal units (8 decimals).
api_wk "$WK" GET "/wallet/v1/balance?source=intents&token=$ZEC" >/dev/null
HELD=$(jq -r '.balance // "0"' <<<"$BODY")
[[ "$HELD" =~ ^[0-9]+$ && "$HELD" -gt 1 ]] || { echo "✗ the wallet holds no ZEC on intents (balance '$HELD'); fund it first" >&2; exit 1; }
AMOUNT=$(( HELD / 2 )); (( AMOUNT >= 1 )) || AMOUNT=1
note "ZEC held: $HELD, amount under test: $AMOUNT"

dry() {    api_wk "$WK" POST /wallet/v1/intents/withdraw/dry-run "$1" >/dev/null; }
cdry() {   api_wk "$WK" POST /wallet/v1/confidential/withdraw/dry-run "$1" >/dev/null; }
quote() {  api_wk "$WK" POST /wallet/v1/intents/swap/quote "$1" >/dev/null; }
cquote() { api_wk "$WK" POST /wallet/v1/confidential/swap/quote "$1" >/dev/null; }
reason() { jq -r '.reason // ""' <<<"$BODY"; }
wd_body() { jq -nc --arg c "$1" --arg t "$2" --arg a "$3" --arg to "$4" '{chain:$c, token:$t, amount:$a, to:$to}'; }

# ZEC is listed on aptos and starknet (catalog of 2026-10-14): there the route
# is assessed by 1Click. On ton and xrp it is not listed: the chain must be
# recognized, and the refusal is unsupported_token — the route itself was not
# assessed, and the output says so.
for chain in aptos starknet; do
  log "M1 public dry withdraw of ZEC to $chain"
  dry "$(wd_body "$chain" "$ZEC" "$AMOUNT" "$HEX64_TO")"
  if [[ "$HTTP" == 200 ]]; then
    if [[ "$(jq -r .would_succeed <<<"$BODY")" == true ]]; then pass "M1 $chain would_succeed: $(msg_of | head -c 120)"
    elif [[ "$(reason)" =~ ^(upstream_rejected|no_liquidity)$ ]]; then pass "M1 $chain assessed by 1Click: $(reason) — $(msg_of | head -c 120)"
    elif [[ "$(reason)" == unsupported_token ]]; then fail "M1 $chain the destination asset was not found: $(msg_of)"
    else fail "M1 $chain reason '$(reason)': $(msg_of)"; fi
  elif [[ "$HTTP" == 503 ]]; then skip "M1 $chain route not assessed: $(err_of) — $(msg_of | head -c 120)"
  else fail "M1 $chain HTTP $HTTP $(err_of): $(msg_of)"; fi
done
for chain in ton xrp; do
  log "M1 public dry withdraw of ZEC to $chain (recognition only: ZEC is not listed there)"
  dry "$(wd_body "$chain" "$ZEC" "$AMOUNT" "$EVM_TO")"
  if [[ "$HTTP" == 200 && "$(reason)" == unsupported_token ]]; then pass "M1 $chain recognized; route not assessed (unsupported_token, as expected)"
  elif [[ "$(err_of)" == unsupported_chain ]]; then fail "M1 $chain unsupported_chain: $(msg_of)"
  elif [[ "$HTTP" == 503 ]]; then skip "M1 $chain not assessed: $(err_of)"
  else fail "M1 $chain HTTP $HTTP reason '$(reason)' $(err_of): $(msg_of)"; fi
done

for chain in aptos starknet ton xrp; do
  log "M2 confidential dry withdraw of ZEC to $chain"
  to=$EVM_TO; [[ $chain == aptos || $chain == starknet ]] && to=$HEX64_TO
  cdry "$(wd_body "$chain" "$ZEC" "$AMOUNT" "$to")"
  if [[ "$HTTP" == 200 ]]; then pass "M2 $chain quoted"
  elif [[ "$(err_of)" == unsupported_chain ]]; then fail "M2 $chain unsupported_chain: $(msg_of)"
  elif [[ "$(err_of)" == unsupported_token && ( $chain == ton || $chain == xrp ) ]]; then pass "M2 $chain recognized; route not assessed (unsupported_token, as expected)"
  elif [[ "$(err_of)" =~ ^(no_liquidity|upstream_rejected)$ ]]; then pass "M2 $chain assessed by 1Click: $(err_of) — $(msg_of | head -c 120)"
  elif [[ "$HTTP" == 503 ]]; then skip "M2 $chain not assessed: $(err_of)"
  else fail "M2 $chain HTTP $HTTP $(err_of): $(msg_of)"; fi
done

log "M3 confidential dry withdraw of a HOT asset to polygon"
cdry "$(wd_body polygon "$HOT_POL" 1000000 "$EVM_TO")"
if [[ "$(err_of)" == unsupported_chain ]] || grep -qi 'not NEP-141\|Unsupported source_asset' <<<"$BODY"; then
  fail "M3 the HOT asset's chain was not recognized: $(msg_of)"
elif [[ "$HTTP" == 200 || "$(err_of)" =~ ^(no_liquidity|upstream_rejected|unsupported_token)$ ]]; then
  pass "M3 chain recognized (HTTP $HTTP $(err_of))"
elif [[ "$HTTP" == 503 ]]; then skip "M3 not assessed: $(err_of)"
else fail "M3 HTTP $HTTP $(err_of): $(msg_of)"; fi

for out in "$ZEC_SOL_1CS" "$ZEC_NEAR_1CS" "$ZEC_STARKNET_1CS" "$CFI_BASE_1CS"; do
  log "M4 swap quote wNEAR → $out"
  quote "$(jq -nc --arg i "$WNEAR" --arg o "$out" '{token_in:$i, token_out:$o, amount_in:"50000000000000000000000"}')"
  if assert_status "M4 quoted" 200; then
    [[ "$(jq -r '.amount_out // ""' <<<"$BODY")" =~ ^[0-9]+$ ]] && pass "M4 amount_out $(jq -r .amount_out <<<"$BODY")" || fail "M4 no amount_out: $BODY"
  fi
done

log "M5 swap quote with a 1cs_v1 source on another chain"
quote "$(jq -nc --arg i "$ZEC_SOL_1CS" --arg o "$WNEAR" '{token_in:$i, token_out:$o, amount_in:"1000000"}')"
assert_status "M5 refused" 400 && assert_denied "M5 unsupported_token" unsupported_token && assert_msg "M5 names the id on intents.near" "intents.near"

log "M6 swap quote with the NEAR-side 1cs_v1 source"
quote "$(jq -nc --arg i "$ZEC_NEAR_1CS" --arg o "$WNEAR" --arg a "$AMOUNT" '{token_in:$i, token_out:$o, amount_in:$a}')"
if [[ "$HTTP" == 200 ]]; then pass "M6 quoted"
elif [[ "$(err_of)" == no_liquidity ]]; then pass "M6 the source id was accepted; 1Click: $(msg_of)"
else fail "M6 HTTP $HTTP $(err_of): $(msg_of)"; fi

log "M7 public dry withdraw of the NEAR-side 1cs_v1 id on near"
dry "$(wd_body near "$ZEC_NEAR_1CS" "$AMOUNT" "$NEAR_ACCOUNT_ID")"
if assert_status "M7 answered" 200; then
  if grep -q '1cs_v1' <<<"$BODY"; then fail "M7 the id was not translated: $(msg_of)"
  elif [[ "$(jq -r .would_succeed <<<"$BODY")" == true || "$(reason)" =~ $TYPED ]]; then pass "M7 $(jq -r .would_succeed <<<"$BODY") $(reason)"
  else fail "M7 reason '$(reason)': $(msg_of)"; fi
fi

log "M8 dry withdraw to a chain that does not exist"
dry "$(wd_body nosuchchain "$ZEC" "$AMOUNT" "$EVM_TO")"
assert_status "M8 refused" 400 && assert_denied "M8 unsupported_chain" unsupported_chain && assert_msg "M8 names the catalog" "catalog lists"

log "M9 confidential swap quote wNEAR → NPRO (HoS item 7)"
cquote "$(jq -nc --arg i "$WNEAR" --arg o "$NPRO" '{token_in:$i, token_out:$o, amount_in:"50000000000000000000000"}')"
if [[ "$(err_of)" == no_liquidity ]]; then pass "M9 no_liquidity: $(msg_of)"
elif [[ "$HTTP" == 200 ]]; then pass "M9 quoted — the shard has liquidity today"
else fail "M9 HTTP $HTTP $(err_of): $(msg_of)"; fi

log "M10 public dry withdraw of 1 unit of ZEC to Zcash"
dry "$(wd_body zcash "$ZEC" 1 "${ZEC_TO:-t1KqzqoByrbAPWDAJgZvDxdqAPHJeLG8sHH}")"
if assert_status "M10 answered" 200; then
  [[ "$(reason)" =~ ^(upstream_rejected|no_liquidity)$ ]] && pass "M10 $(reason): $(msg_of | head -c 120)" || fail "M10 reason '$(reason)': $(msg_of)"
fi

log "M11 confidential dry withdraw of BSC USDT to bsc"
cdry "$(wd_body bsc "$BSC_USDT" 5000000000000000000 "$EVM_LIVE_TO")"
if [[ "$HTTP" == 200 ]]; then pass "M11 quoted, amount_out $(jq -r '.amount_out // "none"' <<<"$BODY")"
elif [[ "$(err_of)" == unsupported_chain ]]; then fail "M11 the asset's chain was read from its id: $(msg_of)"
elif [[ "$(err_of)" =~ ^(no_liquidity|upstream_rejected)$ ]]; then pass "M11 assessed by 1Click: $(err_of) — $(msg_of | head -c 120)"
elif [[ "$HTTP" == 503 ]]; then skip "M11 not assessed: $(err_of)"
else fail "M11 HTTP $HTTP $(err_of): $(msg_of)"; fi

# asset|amount|what it arrives as on near
for row in "$ZEC|$AMOUNT|ZEC" "$BSC_USDT|5000000000000000000|NEAR USDT" "$POL_USDC|5000000|NEAR USDC" "$STRK_BTC|10000|strkBTC"; do
  IFS='|' read -r asset amount as <<<"$row"
  log "M12 confidential dry withdraw of $asset to near (arrives as $as)"
  cdry "$(wd_body near "$asset" "$amount" "$NEAR_ACCOUNT_ID")"
  if [[ "$HTTP" == 200 ]]; then
    [[ "$(jq -r '.amount_out // ""' <<<"$BODY")" =~ ^[0-9]+$ ]] && pass "M12 $as quoted, amount_out $(jq -r .amount_out <<<"$BODY")" || fail "M12 $as no amount_out: $BODY"
  elif [[ "$(err_of)" == no_liquidity ]]; then skip "M12 $as route not assessed: no_liquidity — $(msg_of | head -c 120)"
  elif [[ "$HTTP" == 503 ]]; then skip "M12 $as not assessed: $(err_of)"
  else fail "M12 $as HTTP $HTTP $(err_of): $(msg_of)"; fi
done

log "M13 confidential dry withdraw of native BNB to near"
cdry "$(wd_body near "$BNB" 50000000000000000 "$NEAR_ACCOUNT_ID")"
assert_status "M13 refused" 400 && assert_denied "M13 unsupported_token" unsupported_token

verdict "route gaps (mainnet, dry)"
