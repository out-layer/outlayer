# Testnet USDC: getting the stablecoin OutLayer's testnet takes

OutLayer on testnet is paid in one NEP-141 token, `usdc.fakes.testnet`
("Bridged USDC", symbol `USDC.e`, 6 decimals: `1000000` = $1). It is the
token `outlayer.testnet` returns from `get_payment_token_contract()` and the
only one its `ft_on_transfer` accepts. The token has no value and no faucet
gate: its `mint` method is open, so any account mints as much as it needs.

Mainnet takes real USDC; nothing here applies there.

## 1. Mint

`mint` credits an account that is **registered** on the token. An account that
never held `usdc.fakes.testnet` is not registered, and `mint` panics with
`The account <id> is not registered`. Register once with `storage_deposit`
(0.00125 NEAR, the token's `storage_balance_bounds`), then mint.

With [near-cli](https://github.com/near/near-cli-rs):

```bash
# once per account
near contract call-function as-transaction usdc.fakes.testnet storage_deposit \
  json-args '{"account_id": "<you>.testnet"}' \
  prepaid-gas '30.0 Tgas' attached-deposit '0.00125 NEAR' \
  sign-as <you>.testnet network-config testnet sign-with-keychain send

# $20 — the amount is in minimal units; mint takes no deposit
near contract call-function as-transaction usdc.fakes.testnet mint \
  json-args '{"account_id": "<you>.testnet", "amount": "20000000"}' \
  prepaid-gas '30.0 Tgas' attached-deposit '0 NEAR' \
  sign-as <you>.testnet network-config testnet sign-with-keychain send

near contract call-function as-read-only usdc.fakes.testnet ft_balance_of \
  json-args '{"account_id": "<you>.testnet"}' network-config testnet now
```

In a browser: open
[the contract's methods on NEARBlocks](https://testnet.nearblocks.io/address/usdc.fakes.testnet/contract/methods),
connect a testnet wallet, run `storage_deposit` with `account_id` and
0.00125 NEAR attached, then `mint` with `account_id` and `amount`.

Any account may mint for any other: `account_id` need not be the signer.

## 2. Spend it on OutLayer

### Top up a payment key (HTTPS API)

- **Dashboard**: [app.outlayer.ai](https://app.outlayer.ai), Settings →
  Network → Testnet, then Payment Keys → the key's top-up. The wallet signs
  one `ft_transfer_call` of the token.
- **CLI**: `OUTLAYER_NETWORK=testnet outlayer keys topup <nonce> --usd 5`
  (see [CLI.md](CLI.md)).
- **Raw**: `ft_transfer_call` on `usdc.fakes.testnet` with
  `receiver_id: "outlayer.testnet"`, 1 yoctoNEAR attached, and
  `msg: {"action":"top_up_payment_key","nonce":N,"owner":"<optional>"}`.
  `owner` defaults to the sender, so one account can top up another's key.

The minimum is `10000` ($0.01); less refuses the whole transfer, and a
top-up that cannot land (no such key, a closing key) comes back to the sender.
Then call `https://testnet-api.outlayer.ai` with the key.

### Pay a project from a NEAR contract or transaction (`attached_usd`)

`request_execution` debits `attached_usd` from the caller's balance held in
`outlayer.testnet`, not from the wallet. Fund that balance first:

- **Dashboard**: Deposit USDC on the home page (Settings → Network → Testnet first).
- **Raw**: `ft_transfer_call` on `usdc.fakes.testnet` with
  `receiver_id: "outlayer.testnet"`, 1 yoctoNEAR attached, and
  `msg: {"action":"deposit_balance"}`. Minimum `10000` ($0.01).

Check it with `get_user_stablecoin_balance(account_id)` on `outlayer.testnet`;
`withdraw_balance(amount)` (1 yoctoNEAR) takes it back. The contract's
messages are specified in [contract/README.md](../contract/README.md),
"Stablecoin: deposits and earnings".
