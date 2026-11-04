# Wallet Tests

The full custody / intents run order and fund-safety model is in
[TESTING.md](TESTING.md). This page covers the smaller wallet suites and the
unit tests behind them.

## Unit tests (no infrastructure)

```bash
# coordinator (separate repository: outlayer-coordinator)
cd ~/projects/outlayer-coordinator && SQLX_OFFLINE=true cargo test wallet
#   modules: wallet::auth, wallet::types, wallet::policy, wallet::nonce,
#            wallet::webhooks, wallet::handlers, wallet::cross_chain, …

# keystore (this repository)
cd keystore-worker && cargo test

# worker wallet host functions
cd worker && cargo test wallet --lib

# policy evaluation shared by coordinator and keystore
cd ~/projects/shared-tee-helpers && cargo test wallet_policy
```

## Integration suites (running coordinator + keystore)

Each suite takes `COORDINATOR_URL`; the default is shown per suite. Point it
at `https://testnet-api.outlayer.ai` for testnet, a local `http://localhost:8080`
for a local stack. A suite that reads the chain itself goes through
`tests/lib/rpc.sh` and needs a keyed FastNEAR RPC (`FASTNEAR_API_KEY` or
near-cli's config); do not run past its `⚠ no FastNEAR API key` warning.

### Mode 1 — agent without a policy (`wallet_mode1_agent.sh`, default `localhost:8080`)

Registers via `POST /register` and exercises the wallet methods with the
`wk_` key.

### Mode 2 — wallet with a policy (`wallet_mode2_policy.sh`, default `localhost:8080`)

Registers a wallet and an approver, encrypts a policy (limits, whitelist,
approval threshold) and tests enforcement and the multisig approval flow.
Cases that need the policy stored on chain report SKIP when it is not: a
wallet with no policy has no limits.

### Intents withdraw (`wallet_intents_e2e.sh`, mainnet, manual funding)

register → fund → wrap → intents withdraw; asserts `result.delivered` is the
canonical asset id ([issue #25](https://github.com/out-layer/outlayer/issues/25)).
Default `COORDINATOR_URL` is `localhost:8080`; intents exist on mainnet only.

```bash
./tests/wallet_intents_e2e.sh setup
# fund the printed address with NEAR, then:
./tests/wallet_intents_e2e.sh call
./tests/wallet_intents_e2e.sh withdraw
```

### Withdraw dry-run fidelity (`wallet_dry_run_e2e.sh`, read-only, no funds)

Asserts that `POST /wallet/v1/intents/withdraw/dry-run` and the real
`POST /wallet/v1/intents/withdraw` agree
([issue #28](https://github.com/out-layer/outlayer/issues/28)): the dry-run
asks the bridge for its minimum, checks the balance, mirrors the input
validation and evaluates the `cross_chain_withdraw` policy op for a cross-chain
exit.

Runs on a fresh **unfunded** wallet. The `amount: "0"` cases clear the balance
gate (`0 >= 0`) and are refused deeper in the pipeline, which is how the
bridge / storage / recipient checks are reached without money. The real
withdraw is called **only** for cases the dry-run predicts will fail — a 2xx
from one of those is the bug.

Needs a mainnet coordinator (intents are mainnet-only); against testnet it
detects the 503 and skips itself.

```bash
COORDINATOR_URL=https://api.outlayer.ai ./tests/wallet_dry_run_e2e.sh
SKIP_PARITY=1 ./tests/wallet_dry_run_e2e.sh   # dry-run assertions only
```

Not covered (needs an on-chain policy, i.e. a funded wallet; SKIPped):
`policy_denied` / `wallet_frozen` verdicts and the cross-chain op-type gate.
Unit-tested instead in shared-tee-helpers
(`wallet_policy.rs::cross_chain_withdraw_is_default_deny_own_type`) and the
coordinator (`wallet::cross_chain::tests::withdraw_dry_quote_differs_from_real_only_in_dry_flag`).

### Deposit-intent chain matrix (`legacy/wallet_deposit_intent_chains_e2e.sh`, read-only)

`/wallet/v1/deposit-intent` returns a chain-appropriate deposit address for
each source chain (default `CHAINS=near,ethereum,base,arbitrum,solana,bitcoin`,
default `COORDINATOR_URL=https://api.outlayer.ai`). Its coverage is also in
`unified_op_e2e_intents.sh` T15.

```bash
COORDINATOR_URL=http://localhost:8080 CHAINS=ethereum,base,solana \
  ./tests/legacy/wallet_deposit_intent_chains_e2e.sh
```

### EVM signing (`wallet_evm_sign_e2e.sh`, read-only, default `localhost:8080`)

`GET /wallet/v1/address` returns one shared secp256k1 `0x` address for every
EVM chain (ethereum, polygon, base, arbitrum, optimism, bsc, avalanche, hood
and their aliases). Sign endpoints: `POST /wallet/v1/evm/sign-typed-data`
(EIP-712 v4), `/wallet/v1/evm/sign-message` (EIP-191 `personal_sign`) and
`/wallet/v1/evm/sign-transaction` (the **client** serializes the unsigned tx,
the keystore keccak256s and signs it; no assembly, nonce, gas or broadcast).
Signatures are 65-byte `0x` `r‖s‖v`, `v ∈ {27, 28}`, low-s.

The suite asserts address stability (`ethereum` == `polygon` == `base`) and
the signature shape of all three endpoints. Capability gating is SKIPped
(needs a funded wallet for an on-chain policy) and unit-tested by
`evm_sign_capability_defaults_and_raw_tx_subflag` (shared-tee-helpers):
default-deny under a policy, `allowed: true` permits, no policy = unrestricted.

> `requires_approval` is not supported for EVM signing. An EIP-712 signature
> is itself fund-moving (EIP-3009 ≈ transfer, EIP-2612 ≈ approve), so
> `evm_sign` grants full authority over whatever is bridged to the EVM
> address. The keystore and coordinator never build or broadcast an EVM tx.

### Solana signing (`wallet_solana_sign_e2e.sh`, read-only)

The client builds and broadcasts; the keystore only ed25519-signs the raw
bytes. `GET /wallet/v1/address?chain=solana` returns the base58 address
(`sol` is an alias), `POST /wallet/v1/solana/sign-message` signs raw message
bytes (`encoding: utf8|hex|base64`) and `/wallet/v1/solana/sign-transaction`
signs a client-serialized message (base64, ≤1232 bytes). Signatures are
64-byte base58.

Its default `COORDINATOR_URL` is mainnet (`https://api.outlayer.ai`); set
`COORDINATOR_URL=https://testnet-api.outlayer.ai` to run it on testnet.

The suite asserts address shape and alias, signature shape and the canonical
`"solana"` echo, rejection of an unknown `encoding`, and the
message/transaction guard: a legacy tx message sent to sign-message is
rejected (400) and the same bytes sign through sign-transaction (pinned in
`keystore-worker/src/solana.rs::guard_catches_minimal_handbuilt_tx`). Gating
is unit-tested by `solana_sign_capability_defaults_and_raw_tx_subflag`;
byte-exact equivalence with `@solana/web3.js` / nacl by
`solana.rs::signatures_match_solana_tooling_byte_for_byte`.

> Same caveat as EVM: `solana_sign` + `raw_tx` grants full authority over the
> Solana address; `requires_approval` is not supported (fails closed).

## Run everything

```bash
./tests/run_all.sh
```

`run_all.sh` includes `wallet_mode1_agent.sh`, `wallet_evm_sign_e2e.sh`,
`wallet_solana_sign_e2e.sh`, `wallet_dry_run_e2e.sh` and `wallet_mode2_policy.sh`.
