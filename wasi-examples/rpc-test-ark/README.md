# RPC Test Ark

Test WASM component for OutLayer RPC host functions.

## Overview

This WASI P2 component calls the `near:rpc/api@0.1.0` host functions the
OutLayer worker provides (`worker/wit/world.wit`; `wit/world.wit` here is the
same interface) and reports each call as passed or failed. It runs one fixed
suite against **testnet** accounts and transactions written into the code; it
reads no input.

| Group | Calls |
|---|---|
| Query | `view-account` (final and optimistic), `view` (`wrap.testnet.ft_metadata`), `view-access-key`, `view-access-key-list`, `view-code`, `view-state` |
| Block | `block` (final and optimistic), `gas-price`, `chunk`, `changes` |
| Network | `status`, `network-info`, `validators` |
| Transaction | `tx-status`, `receipt`, `send-tx` (a fixed, already-signed testnet transaction) |
| Signed by the module | `call` (`deposit_and_stake` of 0.00001 NEAR to `aurora.pool.f863973.m0`) and `transfer` (1 yoctoNEAR to `outlayer.testnet`) — only when `NEAR_SENDER_PRIVATE_KEY` is set |
| Low-level | `raw("status")` |

`call` and `transfer` sign as `NEAR_SENDER_ID` with the key in the
`NEAR_SENDER_PRIVATE_KEY` secret: the worker never signs with a key of its own.
On OutLayer, `NEAR_SENDER_ID` is the caller's account (a system variable a
secret cannot set), so the key must be a full-access key of the caller's own
account, and these two tests move real testnet funds.

## Building

```bash
# Make sure wasm32-wasip2 target is installed
rustup target add wasm32-wasip2

# Build the component
cargo build --target wasm32-wasip2 --release
```

## Running

### On OutLayer

Run it on **testnet**, with `response_format` `Text`: stdout carries a
human-readable report before the JSON (below), so it is not one JSON value. The
worker links `near:rpc` only when its RPC proxy is on
(`NEAR_RPC_PROXY_ENABLED`, default `true`), and allows at most
`NEAR_RPC_PROXY_MAX_CALLS` calls per run (default 100).

### With wasi-test-runner (Standalone)

```bash
cd ../wasi-test-runner
cargo build --release
./target/release/wasi-test \
  --wasm ../rpc-test-ark/target/wasm32-wasip2/release/rpc-test-ark.wasm \
  --input '{}' \
  --rpc \
  --rpc-url "https://rpc.testnet.fastnear.com" \
  --max-instructions 50000000000
```

The runner warns that the output is not JSON; that is the report text.

## Output Format

stdout is the report, then `JSON output:` and one line of JSON:

```
=== NEAR RPC Test Suite (API 0.1.0) ===

Signer: alice.testnet (credentials: no)

--- Query Methods ---
[PASS] view_account(outlayer.testnet, final)
...
=== Results: 19/19 passed (0 failed) ===

JSON output:
{"success":true,"total":19,"passed":19,"failed":0,"results":[{"name":"view_account(outlayer.testnet, final)","success":true,"result":{...}}, ...]}
```

`success` is true when no test failed. Each result carries `name`, `success`,
and `result` or `error`.

## How It Works

1. The component imports `near:rpc/api@0.1.0` via `wit_bindgen::generate!` (world `rpc-test`)
2. It calls the host functions (e.g. `near::rpc::api::view_account`)
3. The worker's `outlayer_rpc` module sends the request to its NEAR RPC endpoint (`NEAR_RPC_PROXY_URL`, else `NEAR_RPC_URL`); the endpoint's API key never reaches the module
4. The response is returned to the module as `(result, error)`

## WIT Interface

Every function returns `tuple<string, string>`: `(result, error)` — if `error`
is non-empty, the call failed. `finality-or-block` takes `"final"`,
`"optimistic"`, a block height or a block hash; empty means `"final"`. The
signatures this component calls:

```wit
package near:rpc@0.1.0;

interface api {
    view: func(contract-id: string, method-name: string, args-json: string, finality-or-block: string) -> tuple<string, string>;
    view-account: func(account-id: string, finality-or-block: string) -> tuple<string, string>;
    view-access-key: func(account-id: string, public-key: string, finality-or-block: string) -> tuple<string, string>;
    view-access-key-list: func(account-id: string, finality-or-block: string) -> tuple<string, string>;
    view-code: func(account-id: string, finality-or-block: string) -> tuple<string, string>;
    view-state: func(account-id: string, prefix-base64: string, finality-or-block: string) -> tuple<string, string>;

    block: func(finality-or-block: string) -> tuple<string, string>;
    chunk: func(chunk-id-or-block-shard: string) -> tuple<string, string>;
    changes: func(finality-or-block: string) -> tuple<string, string>;

    send-tx: func(signed-tx-base64: string, wait-until: string) -> tuple<string, string>;
    tx-status: func(tx-hash: string, sender-account-id: string, wait-until: string) -> tuple<string, string>;
    receipt: func(receipt-id: string) -> tuple<string, string>;

    /// The module provides the signer: the worker NEVER signs with its own key.
    /// signer-key: NEAR format (ed25519:base58...). wait-until empty = "FINAL".
    call: func(signer-id: string, signer-key: string, receiver-id: string, method-name: string, args-json: string, deposit-yocto: string, gas: string, wait-until: string) -> tuple<string, string>;
    transfer: func(signer-id: string, signer-key: string, receiver-id: string, amount-yocto: string, wait-until: string) -> tuple<string, string>;

    gas-price: func(block-id: string) -> tuple<string, string>;
    status: func() -> tuple<string, string>;
    network-info: func() -> tuple<string, string>;
    validators: func(epoch-id: string) -> tuple<string, string>;

    raw: func(method: string, params-json: string) -> tuple<string, string>;
}
```

## See Also

- [WASI_TUTORIAL.md](../WASI_TUTORIAL.md) - WASI development guide
- [worker/.env.example](../../worker/.env.example) - RPC proxy configuration (`NEAR_RPC_PROXY_*`)
