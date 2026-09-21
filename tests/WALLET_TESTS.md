# Wallet Tests

## Unit Tests (no infrastructure needed)

```bash
# All wallet unit tests at once
cd coordinator && SQLX_OFFLINE=true cargo test wallet
cd keystore-worker && cargo test test_policy
cd worker && cargo test wallet --lib

# Individual modules
cd coordinator && SQLX_OFFLINE=true cargo test wallet::auth
cd coordinator && SQLX_OFFLINE=true cargo test wallet::types
cd coordinator && SQLX_OFFLINE=true cargo test wallet::policy
cd coordinator && SQLX_OFFLINE=true cargo test wallet::nonce
cd coordinator && SQLX_OFFLINE=true cargo test wallet::webhooks
cd coordinator && SQLX_OFFLINE=true cargo test wallet::handlers
```

## Integration Tests (require running services)

### Prerequisites

Coordinator, keystore, PostgreSQL, and Redis must be running.

### Mode 1 — Simple Agent (no policy)

Agent registers via POST /register and tests all wallet methods with API key auth.

```bash
./tests/wallet_mode1_agent.sh
```

### Mode 2 — User with Policy

Registers wallet + approver, encrypts a policy (limits, whitelist, approval threshold), then tests enforcement and multisig approval flow.

```bash
./tests/wallet_mode2_policy.sh
```

**Note:** Some Mode 2 tests require the encrypted policy to be stored on-chain. Without that, the policy engine returns "no policy" and allows everything. Tests that depend on active policy will show as SKIP.

### Wallet intents withdraw (mainnet, manual funding)

Full flow: register → fund → wrap → intents withdraw. Asserts the
`result.delivered` field matches the canonical asset id (regression net
for [issue #25](https://github.com/out-layer/outlayer/issues/25) where
`delivered: "wnear"` was emitted for every NEP-141, including USDC).

```bash
./tests/wallet_intents_e2e.sh setup
# fund the printed address with NEAR, then:
./tests/wallet_intents_e2e.sh call
./tests/wallet_intents_e2e.sh withdraw
```

### Withdraw dry-run fidelity (read-only, no funds)

Asserts that `POST /wallet/v1/intents/withdraw/dry-run` and the real
`POST /wallet/v1/intents/withdraw` agree. Regression net for
[issue #28](https://github.com/out-layer/outlayer/issues/28), where the
dry-run answered `would_succeed: true` for a cross-chain amount the withdraw
then refused with `1Click: Amount is too low for bridge, try at least 303064` —
it never asked the bridge, never checked the balance, never mirrored the input
validation, and evaluated an `Op::Withdraw` policy op for a cross-chain exit
that the real call gates on `cross_chain_withdraw`.

Runs on a fresh **unfunded** wallet, so it is safe on every deploy. The
`amount: "0"` cases clear the balance gate (`0 >= 0`) and get refused deeper in
the pipeline, which is how the bridge / storage / recipient checks are reached
without money. The real withdraw is called **only** for cases the dry-run
predicts will fail — if one of those ever returns 2xx, that is the bug.

Needs a **mainnet-configured** coordinator (intents are mainnet-only); against a
testnet coordinator it detects the 503 and skips itself.

```bash
./tests/wallet_dry_run_e2e.sh
COORDINATOR_URL=https://api.outlayer.ai ./tests/wallet_dry_run_e2e.sh
SKIP_PARITY=1 ./tests/wallet_dry_run_e2e.sh   # dry-run assertions only
```

Not covered (needs an on-chain policy ⇒ a funded wallet, SKIPped by the script):
`policy_denied` / `wallet_frozen` verdicts and the cross-chain op-type gate. The
op-type logic is unit-tested in shared-tee-helpers
(`wallet_policy.rs::cross_chain_withdraw_is_default_deny_own_type`); the dry-run
and real quote sharing one builder is unit-tested in the coordinator
(`wallet::cross_chain::tests::withdraw_dry_quote_differs_from_real_only_in_dry_flag`).

### Deposit-intent chain matrix (read-only)

Verifies that `/wallet/v1/deposit-intent` returns chain-appropriate deposit
addresses for every supported source chain. No funding needed. Regression
net for [issue #25 Bug A](https://github.com/out-layer/outlayer/issues/25)
(the wrapper used to return Solana base58 addresses for any source chain).

```bash
./tests/wallet_deposit_intent_chains_e2e.sh
# Or against a custom coordinator / subset of chains:
COORDINATOR_URL=http://localhost:8080 \
  CHAINS=ethereum,base,solana \
  ./tests/wallet_deposit_intent_chains_e2e.sh
```

### EVM signing

EVM signing v1 is shipped: `GET /wallet/v1/address` serves all supported EVM
chains (ethereum, polygon, base, arbitrum, optimism, bsc, avalanche, hood, plus
aliases) returning one shared secp256k1 `0x` address, and three sign endpoints
are live — `POST /wallet/v1/evm/sign-typed-data` (EIP-712 v4),
`/wallet/v1/evm/sign-message` (EIP-191 `personal_sign`), and
`/wallet/v1/evm/sign-transaction` (raw tx: the **client** serializes the
unsigned tx, the keystore keccak256s + signs it; no assembly, nonce, gas, or
broadcast). Signatures are 65-byte `0x` `r‖s‖v`, `v ∈ {27, 28}`, low-s.

`tests/wallet_evm_sign_e2e.sh` (read-only, no funds; needs only coordinator +
keystore, so it runs on testnet; wired into `run_all.sh`) asserts:

- **address stability** — `/wallet/v1/address` returns the same `0x` address for
  `ethereum` == `polygon` == `base`.
- **signature shape** — all three EVM endpoints return a 65-byte `0x` `r‖s‖v`
  signature with `v ∈ {27, 28}`.
- **capability gating** is SKIPped here (it needs a funded wallet to store an
  on-chain policy); the gating logic is covered by the unit test
  `evm_sign_capability_defaults_and_raw_tx_subflag` (default-DENY under a policy;
  `allowed:true` permits; omit/`false` blocks; no-policy = unrestricted) and
  `ecrecover == address` by the `crypto.rs` recover tests.

> `requires_approval` is NOT supported for it. An EIP-712 signature is itself
> fund-moving (EIP-3009 ≈ transfer, EIP-2612 ≈ approve), so `evm_sign` grants
> full authority over whatever float is bridged to the EVM address — the
> NEAR-intents balance is never exposed. The keystore/coordinator never build
> or broadcast an EVM tx; gas, nonce, and broadcast are the client's job.

### Solana signing

Solana signing v1 is shipped (same model as EVM: the client builds and
broadcasts, the keystore only ed25519-signs the raw bytes — Solana has no
digest step): `GET /wallet/v1/address?chain=solana` returns the base58 ed25519
address, `POST /wallet/v1/solana/sign-message` signs raw message bytes
(`encoding: utf8|hex|base64`), and `/wallet/v1/solana/sign-transaction` signs a
client-serialized transaction message (base64, ≤1232 bytes). Signatures are
64-byte base58. The `sol` alias is accepted and canonicalized to `solana`.

`tests/wallet_solana_sign_e2e.sh` (read-only, no funds; needs only coordinator +
keystore, so it runs on testnet; wired into `run_all.sh`) asserts:

- **address shape + alias** — `/wallet/v1/address` returns a 32-byte base58
  pubkey, identical for `solana` and `sol`.
- **signature shape + canonical echo** — sign-message (utf8 and hex) returns a
  64-byte base58 signature; a `chain: "sol"` request is echoed back as
  `"solana"`; an unknown `encoding` is rejected (400), never sniffed.
- **the message/transaction guard** — a valid hand-built legacy tx message sent
  to sign-message is rejected (400), then the SAME bytes sign fine via
  sign-transaction (no-policy wallet ⇒ raw-tx unrestricted). This is the
  `raw_tx`-bypass protection; the same bytes are pinned in the keystore unit
  test `solana.rs::guard_catches_minimal_handbuilt_tx`.
- **capability gating** is SKIPped here (needs a funded wallet to store an
  on-chain policy); the gating logic is covered by the unit test
  `solana_sign_capability_defaults_and_raw_tx_subflag`, and byte-exact
  signature equivalence with `@solana/web3.js`/nacl by
  `solana.rs::signatures_match_solana_tooling_byte_for_byte` (pinned vectors,
  public no-funds test key).

> Same caveats as EVM: a signed Solana transaction message is itself
> fund-moving, so `solana_sign` + `raw_tx` grants full authority over the
> Solana address's float; `requires_approval` is NOT supported (fails closed).
> The keystore/coordinator never build or broadcast a Solana tx; blockhash,
> fees, assembly, and broadcast are the client's job.

### Run everything

```bash
./tests/run_all.sh
```

## Test Counts

| Layer | Location | Tests |
|-------|----------|-------|
| Unit | `keystore-worker/src/api.rs` (evaluate_policy) | 21 |
| Unit | `keystore-worker/src/crypto.rs` (secp256k1 recover + pinned fixture) | 2 |
| Unit | `keystore-worker/src/eip712.rs` (viem reference vectors) | 2 |
| Unit | `keystore-worker/src/api.rs` (evm_chains_share_one_canonical_seed) | 1 |
| Unit | `shared-tee-helpers/src/wallet_policy.rs` (evm_sign_capability_defaults_and_raw_tx_subflag) | 1 |
| Unit | `coordinator/src/wallet/auth.rs` | 18 |
| Unit | `coordinator/src/wallet/types.rs` | 5 |
| Unit | `coordinator/src/wallet/policy.rs` | 4 |
| Unit | `coordinator/src/wallet/nonce.rs` | 3 |
| Unit | `coordinator/src/wallet/webhooks.rs` | 4 |
| Unit | `coordinator/src/wallet/handlers.rs` | 15 |
| Unit | `coordinator/src/wallet/handlers.rs` (test_validate_chain_*) | 3 |
| Unit | `worker/src/outlayer_wallet/host_functions.rs` | 3 |
| Integration | `tests/wallet_mode1_agent.sh` | 21 |
| Integration | `tests/wallet_mode2_policy.sh` | 17 |
| E2E | `tests/wallet_intents_e2e.sh` | 1 (asserts `delivered`) |
| E2E | `tests/wallet_deposit_intent_chains_e2e.sh` | 6 chains |
| E2E | `tests/wallet_evm_sign_e2e.sh` | 4 (address-stability + 3 sig-shape; gating SKIP) — see [EVM signing](#evm-signing) |
| **Total** | | **126** |
