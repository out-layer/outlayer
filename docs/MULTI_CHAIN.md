# Multi-Chain Support for Agent Custody Wallets

Agent Custody lets AI agents hold and manage funds through TEE-held wallets with owner-set spending policies. **NEAR, EVM chains and Solana are signed for directly.** The keystore derives a secp256k1 key for EVM chains and an ed25519 key for Solana next to the wallet's NEAR key. Other chains (Bitcoin, TON, XRP and the rest of the 1Click catalog) are reached through NEAR Intents deposits and withdrawals; the wallet holds no key on them. The custody reference is https://app.outlayer.ai/docs/agent-custody.

## Overview

| Component | NEAR | EVM (ethereum/polygon/base/arbitrum/optimism/bsc/avalanche/hyperevm/hood) | Solana |
|-----------|------|---------------------|--------|
| Key (keystore) | ed25519 | secp256k1 (one shared address across all EVM chains) | ed25519 (base58 address) |
| Signing (keystore) | ed25519 | ECDSA secp256k1 (keccak256 + sign; EIP-712 / EIP-191 / raw-tx hash) | ed25519 over the raw serialized message (no digest step) |
| Derivation seed | `wallet:{id}:near` | `wallet:{id}:evm` (shared by every EVM chain); a sub-key is `subkey:{id}:evm:{sub_path}` | `wallet:{id}:solana` (the `sol` alias canonicalizes to it) |
| API | transfer, call, delete, storage-deposit, intents deposit / withdraw / transfer / swap, payment checks, confidential intents, limit orders | `evm/sign-typed-data`, `evm/sign-message`, `evm/sign-transaction` (signing only — no build/broadcast) | `solana/sign-message`, `solana/sign-transaction` (signing only — no build/broadcast) |
| Policy (keystore) | all rules | `evm_sign` capability (default-DENY under a policy) + `raw_tx` sub-flag (default-OFF) | `solana_sign` capability — same model as `evm_sign` |

Each seed is HMAC-SHA256'd with the wallet's master secret inside the keystore enclave. Nothing is stored: every address is derived on request from the `wallet_id`.

## One policy per wallet

The policy is **one per `wallet_id`**, stored on chain under the wallet's NEAR public key (`wallet_pubkey`), and it governs every chain. What it can check differs by chain:

- **NEAR and intents operations** carry a token, an amount and a recipient, so every rule applies: capabilities, transaction types, per-transaction and cumulative limits, whitelists, time windows, rate limit, approvals, freeze.
- **EVM and Solana signing** carries no amount, token or recipient the keystore can read. Only `frozen`, `time_restrictions` and the `evm_sign` / `solana_sign` capability apply. Limits, whitelists and the rate limit do not, and `requires_approval` on these capabilities is refused rather than ignored.

## EVM Signing

The model is deliberately narrow: **the client builds and broadcasts; the keystore only hashes (keccak256) and signs.** Neither the keystore nor the coordinator assembles an EVM transaction, picks a nonce or gas, or broadcasts. Cross-chain value movement uses `POST /wallet/v1/intents/deposit/cross-chain` (alias `/wallet/v1/deposit-intent`) and `POST /wallet/v1/intents/withdraw`, through 1Click with NEAR signatures, not a native EVM transaction.

### Supported chains

`ethereum`, `polygon`, `base`, `arbitrum`, `optimism`, `bsc`, `avalanche`, `hyperevm`, `hood` — plus the aliases `eth`, `pol`, `matic`, `arb`, `op`, `avax`. **All EVM chains share ONE derived secp256k1 address** (a single EOA, seed `wallet:{id}:evm`). `GET /wallet/v1/address?chain=<chain>` serves any of these and returns that one `0x` address. `hyperevm` is Hyperliquid's EVM (chain id 999): signable like the rest. `hood` is Robinhood Chain, an Arbitrum L2. `hypercore` (Hyperliquid's L1) is not signable through `/wallet/v1/evm/*`: it is a 1Click deposit and withdraw chain whose accounts are that same `0x` address, and a HyperCore action is signed as EIP-712 typed data by whoever trades there (the Hyperliquid connector does). Account deletion is NEAR-only.

### Sub-keys

`GET /wallet/v1/address` and the three `evm/*` endpoints take an optional
`sub_path` (`[a-z0-9][a-z0-9._-]{0,63}`, EVM only). It names a distinct
secp256k1 key of the same wallet — seed `subkey:{id}:evm:{sub_path}`, under its
own root so that no key-exporting endpoint of the keystore can spell it. It is
a separate **address** under the wallet's one authority, not a separate
authority: whoever holds the wallet's API key can sign for any path, and the
owner's policy governs every path alike, through the same `evm_sign`
capability. What a path buys is separation of balances — a connector's trading
key and its bridge key are different addresses, and neither is the wallet's;
which path an integration may use is decided by whoever forwards it. The empty
path is the wallet's own key — from the HTTPS API; a WASI guest never reaches
it, because the worker maps every label it is given, the empty one included,
to a `connector.{connector_id}.{label}` path. The coordinator and the keystore
validate the path with one shared rule (`shared_tee_helpers::is_valid_sub_path`)
and both refuse it on non-EVM chains; the coordinator echoes it in the
response. Nothing about a sub-key is stored — its address is derived on
request.

### Endpoints

| Endpoint | Standard | What the keystore does |
|----------|----------|------------------------|
| `POST /wallet/v1/evm/sign-typed-data` | EIP-712 v4 | Computes the digest from the full `eth_signTypedData_v4` object (`typed_data`), then signs |
| `POST /wallet/v1/evm/sign-message` | EIP-191 `personal_sign` | Computes `keccak256("\x19Ethereum Signed Message:\n" + len + msg)`, then signs. `encoding`: `utf8` (default) or `hex` |
| `POST /wallet/v1/evm/sign-transaction` | raw tx | The **client** serializes the unsigned tx (`unsigned_tx`, `0x`-hex); the keystore keccak256-hashes and signs it. For an EIP-1559 (type-2) tx the `yParity` needed to assemble the final tx is `v - 27`. |

Every request names `chain`. All three return a 65-byte `0x` signature `r‖s‖v`, with `v ∈ {27, 28}` and low-s (EIP-2) normalization. The EIP-712 encoder is hand-rolled (no `alloy`/`ethers`) so it adds no dependency to the enclave's attestation surface; it is pinned against viem-generated reference vectors (`keystore-worker/src/eip712_vectors.json`).

### Policy capability: `evm_sign`

`evm_sign` is **default-DENY under a policy**: a policy must set `capabilities.evm_sign.allowed = true` to permit EIP-712 / EIP-191 signing (a wallet with **no policy** is unrestricted). `sign_message` is the only default-allow capability. A `raw_tx` sub-flag is **default-OFF** and separately gates the raw-transaction endpoint. `requires_approval` is **not supported** for `evm_sign`: a policy that sets it is refused rather than silently ignored.

**Caveat — `evm_sign` is fund-moving authority, not a read-only grant.** An EIP-712 signature can itself move funds: EIP-3009 `transferWithAuthorization` ≈ a transfer, EIP-2612 `Permit` ≈ an approve. So `evm_sign` grants full authority over whatever sits on the wallet's EVM address. The `raw_tx` flag is a kill-switch for arbitrary raw transactions, **not** a containment boundary for typed-data drains. No EVM signing path can move the wallet's NEAR Intents balance.

### Not provided

- The dashboard shows the wallet's NEAR address only; EVM addresses come from `GET /wallet/v1/address`, and there is no signing UI. The dashboard's policy form sets `evm_sign` / `solana_sign`.

## Solana Signing

Solana signing follows the EVM model: **the client builds and broadcasts; the keystore only signs.** There is no digest step on Solana — the ed25519 signature covers the raw serialized message bytes — so the keystore signs the supplied bytes as-is. It never assembles a transaction, never picks a blockhash, and never broadcasts. The chain identifier is `solana` (alias `sol`); both spellings canonicalize to the one key on seed `wallet:{id}:solana`. `GET /wallet/v1/address?chain=solana` returns the base58 ed25519 public key, which is the Solana address. Solana has no sub-keys: a request carrying `sub_path` is refused.

### Endpoints

| Endpoint | What the keystore does |
|----------|------------------------|
| `POST /wallet/v1/solana/sign-message` | Signs the decoded `message` bytes (`encoding`: `utf8` default / `hex` / `base64`, no content sniffing) — verifiable with `nacl.sign.detached.verify`; Sign-in-with-Solana flows work unchanged. **Rejects bytes that parse as a valid transaction message** (see guard below). Max 64 KiB. |
| `POST /wallet/v1/solana/sign-transaction` | The **client** serializes the unsigned transaction **message** (`unsigned_tx`, base64 — what the signature covers: web3.js `tx.serializeMessage()` / `versionedTx.message.serialize()`); the keystore signs the bytes as-is. Max 1232 bytes (the Solana packet limit). The client assembles the signed tx (`compact-u16 sig count ‖ signatures ‖ message`) and broadcasts. |

Both return a 64-byte ed25519 signature, **base58** (Solana convention).

### The message/transaction guard

Solana has no EIP-191-style prefix separating messages from transactions: a "message" whose bytes are a valid serialized transaction message would, once signed, be broadcastable — bypassing the `raw_tx` sub-flag. Wallets (Phantom, Solflare) close this by refusing to `signMessage` bytes that parse as a transaction message; `keystore-worker/src/solana.rs::parses_as_transaction_message` implements the same **reject-only** check (legacy + versioned v0 wire format, strict full-byte consumption, `sanitize()`-level header/index checks). It never interprets the payload beyond "could a node accept this as a transaction" — blind signing stays blind. The parser is hand-rolled (no `solana-sdk` in the enclave, same rationale as the EIP-712 encoder) and pinned against `@solana/web3.js`-generated reference vectors (`keystore-worker/src/solana_vectors.json`, generator: `keystore-worker/scripts/gen_solana_vectors.mjs`), including a byte-exact cross-signing test: the keystore's signature over the vector transactions is asserted identical to web3.js/nacl output, and splicing it into the wire format reproduces the web3.js-signed transaction exactly.

### Policy capability: `solana_sign`

Same model as `evm_sign`, evaluated by `solana_sign_decision` in `shared-tee-helpers` (one implementation with the EVM gate, so the chains cannot drift): **default-DENY under a policy** (`capabilities.solana_sign.allowed = true` to opt in; no policy → unrestricted), the `frozen` and `time_restrictions` gates apply, `requires_approval` is refused, and the `raw_tx` sub-flag (**default-OFF**) separately gates `sign-transaction`.

**Caveat:** a signed Solana transaction message is itself fund-moving, so `solana_sign` + `raw_tx` grants full authority over whatever sits on the wallet's Solana address. No Solana signing path can move the wallet's NEAR Intents balance.

**`raw_sign`:** the keystore also accepts a hash-pinned `raw` operation that blind-signs bytes with the wallet's NEAR or Solana ed25519 key (EVM is refused; `sol` canonicalizes to `solana`), gated by the separate default-DENY `raw_sign` capability with an optional per-chain list. The public API exposes no route that builds it.

## Checklist: Adding another chain

1. Add a chain predicate in `shared-tee-helpers/src/lib.rs` (single source of truth for keystore + coordinator) and a capability + decision fn in `wallet_policy.rs` (reuse `chain_sign_decision`).
2. Add keystore signing handler(s) in `keystore-worker/src/api.rs` mirroring `evm_sign_digest` / `solana_sign_bytes`; canonicalize aliases in `wallet_seed()`.
3. **Every chain uses a distinct derivation seed** (`wallet:{id}:near` vs `wallet:{id}:evm` vs `wallet:{id}:solana`) — the cross-curve/cross-chain domain-separation invariant: a blind signature on one chain's key can never forge another chain's transaction or a NEAR auth message.
4. Follow the blind-signing model: the **client** builds and broadcasts; the keystore only signs. Do not build or broadcast in the coordinator.
5. If the chain signs raw bytes (no digest), decide how messages are separated from transactions (prefix or reject-guard) BEFORE shipping the message endpoint.
6. Admit the chain in the coordinator's `validate_chain()`, add `/wallet/v1/<chain>/*` routes, update the api-spec + reference vectors.

## Key Files

| File | What it does |
|------|----------------|
| coordinator (private repo) `src/wallet/handlers.rs` | `validate_chain()` admits near + EVM + Solana; `evm_sign_*` / `solana_sign_*` handlers forward to the keystore via `keystore_chain_sign` (no build/broadcast) |
| `keystore-worker/src/crypto.rs` | `derive_keypair()` (ed25519), `derive_secp256k1_keypair()`, `derive_eth_address()`, `sign()` (ed25519 over raw bytes — the Solana primitive), `sign_secp256k1_prehash()` |
| `keystore-worker/src/eip712.rs` | Hand-rolled EIP-712 v4 + EIP-191 digest computation; pinned to `eip712_vectors.json` |
| `keystore-worker/src/solana.rs` | Hand-rolled reject-only Solana tx-message guard + size caps; pinned to `solana_vectors.json` |
| `keystore-worker/src/api.rs` | `/wallet/evm/*` + `/wallet/solana/*` handlers; `wallet_seed()` canonicalization; capability gating via `shared_tee_helpers::wallet_policy::{evm_sign_decision, solana_sign_decision}` |
| `shared-tee-helpers/src/wallet_policy.rs` | The policy engine: ops, capabilities, `chain_sign_decision` |
| `contract/src/wallet.rs` | Wallet policies, keyed by `wallet_pubkey` (the NEAR key) |
