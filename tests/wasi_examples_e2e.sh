#!/usr/bin/env bash
# The playground's examples, run end to end on testnet and judged by what they answer.
#
# Every example the dashboard's playground offers on testnet (`app/playground/page.tsx` in the
# dashboard repo), called exactly as the playground calls it: `request_execution` on the
# contract with the same source, input, limits, secrets profile and response format, or the
# proxy contract's `flip_coin`. The answer is read from the chain and checked for content —
# a number in range, the city asked for, every storage call passing — not only for a
# transaction that went through. Run it after any change to how the worker runs WASM: the
# engine, the host functions, the linker.
#
#   X1  random (WASI P1)            a random_number within [1, 100]
#   X2  AI completions (P2, secrets) a text whose sentences start with "O" (the secret prompt)
#   X3  echo (P1)                   the caller and the input, with a block height
#   X4  weather (P2, secrets)       London, a numeric temperature
#   X5  multi-source oracle (P2)    a NEAR price > 0 aggregated from at least four exchanges
#   X6  Ethereum API (P2, secrets)  a hex value from the provider
#   X7  project storage test (P2)   the project's own storage self-test: every check passed
#   X8  Ethereum state proof (P2)   a Chainlink ETH/USD answer proven against Ethereum state, with its age
#   X9  coin flip (proxy contract)  a Heads/Tails verdict from coin-toss.testnet
#   X10 VRF coin flip (proxy)       a verdict whose VRF proof the contract verified on chain
#
#   tests/wasi_examples_e2e.sh --apply
#   ONLY=X3,X9 tests/wasi_examples_e2e.sh --apply
#
# CALLER (default outlayer-elena.testnet) signs every call and pays ~0.1 NEAR per direct
# example (the unused part is refunded) and 0.01 / 0.05 NEAR per coin flip. The secrets
# profiles belong to zavodil2.testnet, as in the playground.
set -uo pipefail
[[ "${1:-}" == "--apply" ]] || { sed -n 2,28p "$0"; exit 0; }
cd "$(dirname "$0")/.."
source tests/lib/rpc.sh

NETWORK="${NETWORK:-testnet}"
CONTRACT_ID="${CONTRACT_ID:-outlayer.testnet}"
CALLER="${CALLER:-outlayer-elena.testnet}"
SECRETS_OWNER="${SECRETS_OWNER:-zavodil2.testnet}"
ONLY="${ONLY:-}"

PASS=0; FAIL=0
pass() { echo "✓ $*"; PASS=$((PASS + 1)); }
fail() { echo "✗ $*"; FAIL=$((FAIL + 1)); }
want() { [[ -z "$ONLY" ]] || [[ ",$ONLY," == *",$1,"* ]]; }

echo "• RPC: $(rpc_url_public)"
echo "• caller $CALLER, contract $CONTRACT_ID"

FASTFS=https://wasmhub.testnet.fastfs.io/fastfs.testnet
LIMITS='{"max_instructions":10000000000,"max_memory_mb":128,"max_execution_seconds":60}'

# The request_execution arguments of one WasmUrl example.
wasm_args() { # hash build_target input secrets_profile response_format [url_hash | https://url]
  local secrets=null url="$FASTFS/${6:-$1}.wasm"
  [[ "$6" == https://* ]] && url=$6
  [[ -n "$4" ]] && secrets=$(jq -nc --arg p "$4" --arg a "$SECRETS_OWNER" '{profile:$p, account_id:$a}')
  jq -nc --arg url "$url" --arg h "$1" --arg t "$2" --arg i "$3" --argjson s "$secrets" \
    --arg f "$5" --argjson l "$LIMITS" \
    '{source:{WasmUrl:{url:$url, hash:$h, build_target:$t}}, resource_limits:$l, input_data:$i, secrets_ref:$s, response_format:$f}'
}

# Send one call and print what the chain says it returned: the decoded SuccessValue, or
# `FAILED <reason>`.
call() { # receiver method args deposit
  local out tx try
  # A transaction refused before it reached a block (another signer of CALLER took the nonce,
  # or the block it was signed against left the window) changed nothing: sent again.
  for try in 1 2 3; do
    out=$(near contract call-function as-transaction "$1" "$2" json-args "$3" prepaid-gas '300 Tgas' \
      attached-deposit "$4" sign-as "$CALLER" network-config "$NETWORK" sign-with-legacy-keychain send 2>&1 </dev/null)
    grep -aqE 'must be account\[access_key\]\.nonce|Transaction has expired' <<<"$out" || break
    sleep 3
  done
  tx=$(grep -aoE 'Transaction ID: [A-Za-z0-9]+' <<<"$out" | head -1 | cut -d' ' -f3)
  [[ -n "$tx" ]] || { echo "FAILED no transaction: $(grep -aE 'Error|error' <<<"$out" | head -2 | tr '\n' ' ' | cut -c1-200)"; return; }
  echo "• tx $tx" >&2
  curl -sS --max-time 90 "$RPC_URL" -H 'content-type: application/json' \
    -d "$(jq -nc --arg t "$tx" --arg s "$CALLER" '{jsonrpc:"2.0",id:1,method:"EXPERIMENTAL_tx_status",params:{tx_hash:$t,sender_account_id:$s,wait_until:"FINAL"}}')" \
    | jq -r 'if .result.status.SuccessValue then .result.status.SuccessValue
             else "FAILED " + ((.result.status.Failure // .error) | tostring) end' \
    | { read -r v; if [[ "$v" == FAILED* ]]; then echo "$v"; else base64 -d <<<"$v"; fi; }
}

# Judge an answer with a jq expression that must be true; print the answer either way.
judge() { # id description answer jq-expr
  local shown; shown=$(head -c 300 <<<"$3" | tr '\n' ' ')
  if [[ "$3" != FAILED* ]] && jq -e "$4" <<<"$3" >/dev/null 2>&1; then
    pass "$1 $2 — $shown"
  else
    fail "$1 $2 — got: $shown"
  fi
}

if want X1; then
  echo "▶ X1 random (WASI P1)"
  A=$(call "$CONTRACT_ID" request_execution \
    "$(wasm_args 0bb0668611f0fa9abeabbfaabf48436a46c94aa65ae1a0d106db7212f2d5f88a wasm32-wasip1 '{"min":1,"max":100}' '' Json)" '0.1 NEAR')
  judge X1 "a random number within [1, 100]" "$A" '.random_number | type == "number" and . >= 1 and . <= 100'
fi

if want X2; then
  echo "▶ X2 AI completions (WASI P2, a secret system prompt)"
  INPUT='{"prompt":"What could the NEAR OutLayer project do?","history":[{"role":"user","content":"Tell me about NEAR"},{"role":"assistant","content":"NEAR is the most scalable Layer 1 blockchain."}],"model_name":"accounts/fireworks/models/gpt-oss-120b","max_tokens":16384}'
  A=$(call "$CONTRACT_ID" request_execution \
    "$(wasm_args 142b02e8f18360900065b9397a385d1b374958405802fdb020fb301250c742ce wasm32-wasip2 "$INPUT" secret-system-prompt Text https://test.fastfs.io/outlayer-alice.testnet/outlayer.testnet/142b02e8f18360900065b9397a385d1b374958405802fdb020fb301250c742ce.wasm)" '0.1 NEAR')
  # The secret prompt makes every sentence start with "O": the answer proves the secret reached the run.
  judge X2 "an answer shaped by the secret prompt (starts with \"O\")" "$A" 'type == "string" and length > 40 and startswith("O")'
fi

if want X3; then
  echo "▶ X3 echo (WASI P1)"
  A=$(call "$CONTRACT_ID" request_execution \
    "$(wasm_args a42ad9cac53669204ab431a52ba1d7314ca8909301106f7cbe64f91e4bf8da1e wasm32-wasip1 'Hello, NEARverse!' '' Text)" '0.1 NEAR')
  [[ "$A" == *"$CALLER said \\\"Hello, NEARverse!\\\" at block "* ]] \
    && pass "X3 the echo names $CALLER and the input" || fail "X3 the echo reads: $(head -c 200 <<<"$A")"
fi

if want X4; then
  echo "▶ X4 weather (WASI P2, secrets)"
  A=$(call "$CONTRACT_ID" request_execution \
    "$(wasm_args 3c5c3435d040a183cd94e6a121e058171a66d4f1fd7f16784520ca0dcaed2239 wasm32-wasip2 '{"city":"London","units":"metric"}' default Json)" '0.1 NEAR')
  judge X4 "London, with a numeric temperature" "$A" '.city == "London" and (.temperature | type == "number")'
fi

if want X5; then
  echo "▶ X5 multi-source oracle (WASI P2)"
  INPUT='{"requests":[{"id":"eur_usd_rate","sources":[{"name":"custom","custom":{"url":"https://open.er-api.com/v6/latest/EUR","json_path":"rates.USD","value_type":"number","method":"GET","headers":[]}}]},{"id":"near_price","sources":[{"name":"coingecko","id":"near"},{"name":"binance","id":"NEARUSDT"},{"name":"huobi","id":"nearusdt"},{"name":"cryptocom","id":"NEAR_USDT"},{"name":"kucoin","id":"NEAR-USDT"},{"name":"gate","id":"near_usdt"},{"name":"pyth","id":"0xc415de8d2eba7db216527dff4b60e8f3a5311c740dadb233e13e12547e226750"}],"aggregation_method":"median","min_sources_num":4},{"id":"near_last_block_validator","sources":[{"name":"custom","custom":{"url":"https://api.nearblocks.io/v1/blocks/latest?limit=1","json_path":"blocks.0.author_account_id","value_type":"string","method":"GET","headers":[]}}]},{"id":"elden_ring_price_cents","sources":[{"name":"custom","custom":{"url":"https://store.steampowered.com/api/appdetails/?appids=1245620&cc=us","json_path":"1245620.data.price_overview.final","value_type":"number","method":"GET","headers":[]}}]}],"max_price_deviation_percent":10.0}'
  A=$(call "$CONTRACT_ID" request_execution \
    "$(wasm_args feca3d1651885d39bde0e4e65fd4c2429a1a5dfbf50dc17e3685f84383bc8e1b wasm32-wasip2 "$INPUT" default Json)" '0.1 NEAR')
  judge X5 "a NEAR price > 0 from at least four exchanges" "$A" \
    '[.results[] | select(.id == "near_price")][0].data | (.value | type == "number" and . > 0) and (.sources | length >= 4)'
fi

if want X6; then
  echo "▶ X6 Ethereum API (WASI P2, secrets)"
  INPUT='{"requests":[{"id":"alchemy","sources":[{"name":"custom","custom":{"url":"https://eth-mainnet.g.alchemy.com/v2","method":"POST","body":{"method":"eth_getBalance","params":["0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045","latest"],"id":1,"jsonrpc":"2.0"},"json_path":"result","value_type":"string"}}]}],"max_price_deviation_percent":10.0}'
  A=$(call "$CONTRACT_ID" request_execution \
    "$(wasm_args 34907feceac091ba89f167a5cd408ebf6a6758b6ed1bde63020071788f722a35 wasm32-wasip2 "$INPUT" alchemy Json)" '0.1 NEAR')
  judge X6 "a hex value from the provider" "$A" '.results[0].data.value | type == "string" and startswith("0x")'
fi

if want X7; then
  echo "▶ X7 project storage test (WASI P2, near:storage)"
  ARGS=$(jq -nc --argjson l "$LIMITS" '{source:{Project:{project_id:"zavodil2.testnet/test-storage", version_key:null}}, resource_limits:$l, input_data:"{\"command\":\"test_all\"}", response_format:"Text"}')
  A=$(call "$CONTRACT_ID" request_execution "$ARGS" '0.1 NEAR')
  # Text format: the answer is a JSON string holding the project's own JSON report.
  judge X7 "every storage check passed" "$A" 'fromjson | .success == true and .tests.failed == 0 and .tests.passed > 0'
fi

if want X8; then
  echo "▶ X8 Ethereum state proof (WASI P2)"
  INPUT='{"proxy":"0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419","pair":"ETH/USD"}'
  A=$(call "$CONTRACT_ID" request_execution \
    "$(wasm_args cf9ef7e1e3c217d187e2d1c2727c52675ee68de49cb7ce9791fe03ac7db340cc wasm32-wasip2 "$INPUT" '' Json)" '0.1 NEAR')
  judge X8 "a proof answer with its age" "$A" '.age_secs | type == "number"'
fi

if want X9; then
  echo "▶ X9 coin flip (proxy contract)"
  A=$(call coin-toss.testnet flip_coin '{"choice":"Heads"}' '0.01 NEAR')
  judge X9 "a Heads/Tails verdict" "$A" 'type == "string" and test("Result: (Heads|Tails)")'
fi

if want X10; then
  echo "▶ X10 VRF coin flip (proxy contract)"
  A=$(call coin-flip-vrf.testnet flip_coin '{"choice":"Heads"}' '0.05 NEAR')
  judge X10 "a verdict whose VRF proof the contract verified" "$A" 'type == "string" and test("VRF proof verified on-chain")'
fi

echo
echo "▶ wasi examples — $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
