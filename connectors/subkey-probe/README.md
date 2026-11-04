# subkey-probe

A connector whose only job is exercising **EVM sub-keys** through the
`outlayer:wallet` host functions — the path from a guest's `label` to a key the
keystore derives under `connector.{connector_id}.{label}`.

It exists apart from `connector-probe`, which does not import the wallet
interface (most probe calls carry no wallet), and from
`wasi-examples/wallet-probe`, which is not a connector (no `connector_id`, so
no sub-keys). This module is both: a connector with a manifest, importing
`outlayer:wallet`, with `network: []` — the wallet functions are host calls,
not HTTP, and it reaches nothing else. Testnet only: the coordinator's
registry lists it there and nowhere else.

## Operations

| `operation` | price | shows |
|---|---|---|
| `address` | free | `get-sub-key-address` for `default`, `trading` and `bridge` on `base` are three different addresses, none of them the wallet's own (`get-address`); the empty label is `default`; `trading` on `hyperevm` is the same address as on `base` |
| `sign` | $0.01 | `evm-sign-message("subkey-probe", utf8)` under `trading`; the module recovers the signer from the EIP-191 digest in-guest (k256) and compares it with the `trading` address. Then the same with the empty label: it must sign, and recover to the `default` sub-key — never to the wallet's own address (`get-address`) |
| `foreign_label` | free | `hl.trading`, `near-email:send`, `Trading`, `a b`, `connector.mercury.trading` (all `invalid_label`) and `trading` on `near`/`solana` (refused by the coordinator) — every one must be a refusal |

`ok` is the verdict; `detail` says why. `address` carries the addresses,
`sign` the signature and both signers, `foreign_label` every refusal it got and
any request that was accepted but must not have been.

## Calling it

Every call needs a wallet, because the module imports `outlayer:wallet`:

```bash
curl -s https://testnet-api.outlayer.ai/call/connectors.outlayer.testnet/subkey-probe \
  -H "X-Payment-Key: $SUB_PAYMENT_KEY" \
  -H "X-Wallet-Id: $WALLET_ID" \
  -H 'Content-Type: application/json' \
  -d '{"input":{"operation":"address"}}'
```

`X-Payment-Key` is a key the custody wallet itself owns; `X-Wallet-Id` is that
wallet's id (what `GET /wallet/v1/address` returns as `wallet_id`), and it may
only confirm the wallet the key identifies, never choose another. Without a
wallet the module still runs, and every wallet function answers `no_wallet`.

`sign` is gated by the wallet's `evm_sign` capability: a wallet with no policy
is unrestricted; one with a policy needs `evm_sign.allowed: true`, or the
operation answers `policy_denied`.

## Building and publishing

```bash
./build.sh          # checks wit/wallet.wit against the worker's, builds, prints the hash
```

Publish under the connectors namespace (`connectors.outlayer.testnet/subkey-probe`)
and price it with `scripts/set_connector_prices_testnet.sh`.
