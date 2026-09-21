# Multi-Chain Support for Agent Custody Wallets

Agent Custody allows AI agents to hold and manage funds via TEE-secured wallets with configurable spending policies. **NEAR, all EVM chains, and Solana are supported.** The keystore generates keys for EVM chains (secp256k1) and Solana (ed25519). This document describes the shipped EVM and Solana signing models.

## Current Status

| Component | NEAR | EVM (eth/polygon/base/arbitrum/optimism/bsc/avalanche/hyperevm/hood) | Solana |
|-----------|------|---------------------|--------|
| Key generation (keystore) | ed25519 | secp256k1 (one shared address across all EVM chains) | ed25519 (base58 address) |
| Transaction signing (keystore) | ed25519 | ECDSA secp256k1 (keccak256 + sign; off-chain EIP-712 / EIP-191 / raw-tx hash) | ed25519 over the raw serialized message (no digest step) |
| Derivation seed | `wallet:{id}:near` | `wallet:{id}:evm` (shared by every EVM chain); a sub-key is `subkey:{id}:evm:{sub_path}` | `wallet:{id}:solana` (the `sol` alias canonicalizes to it) |
| Coordinator handlers | withdraw, call, transfer, swap, deposit | `evm/sign-typed-data`, `evm/sign-message`, `evm/sign-transaction` (signing only — no build/broadcast) | `solana/sign-message`, `solana/sign-transaction` (signing only — no build/broadcast) |
| Dashboard UI | full support | address display | not implemented |
| Policy evaluation (keystore) | all rules | `evm_sign` capability (default-DENY under a policy; set `allowed:true`) + `raw_tx` sub-flag (default-OFF); shared policy | `solana_sign` capability — same model as `evm_sign` (`allowed` + `raw_tx`); shared policy |

## Architecture: Shared Policy

Policy is **one per `wallet_id`**, shared across all chains. Spending limits, rate limits, time restrictions, and approval thresholds apply to all operations regardless of chain. Address restrictions (`addresses.list`) can contain addresses of any format.

Policy is stored on-chain keyed by `wallet_pubkey` (the NEAR ed25519 key). This key serves as the wallet's "anchor". Other chain keys are linked through the same `wallet_id` in the coordinator database.

## EVM Signing (shipped)

EVM signing is **live**. The model is deliberately narrow: **the client builds and broadcasts; the keystore only hashes (keccak256) and signs.** The keystore and coordinator never assemble an EVM transaction, never pick a nonce or gas, and never broadcast. Cross-chain value movement still rides `/wallet/v1/deposit-intent` + `/wallet/v1/intents/withdraw` (1Click + NEAR signatures, no native EVM tx).

### Supported chains

`ethereum`, `polygon`, `base`, `arbitrum`, `optimism`, `bsc`, `avalanche`, `hyperevm`, `hood` — plus the 1Click-style aliases `eth`, `pol`, `matic`, `arb`, `op`, `avax`. **All EVM chains share ONE derived secp256k1 address** (a single EOA, seed `wallet:{id}:evm`). `GET /wallet/v1/address` serves any of these and returns that one `0x` address. `hyperevm` is Hyperliquid's EVM (chain id 999): signable like the rest, not a 1Click deposit or withdraw chain. `hood` is Robinhood Chain, an Arbitrum L2: signable, and a 1Click deposit and withdraw chain like `base` or `arbitrum`. Account delete stays NEAR-only.

### Sub-keys

`GET /wallet/v1/address` and the three `evm/*` endpoints take an optional
`sub_path` (`[a-z0-9][a-z0-9._-]{0,63}`, EVM only). It names a distinct
secp256k1 key of the same wallet — seed `subkey:{id}:evm:{sub_path}`, under its
own root so that no key-exporting endpoint of the keystore can spell it. It is
a separate **address** under the wallet's one authority, not a separate
authority: whoever holds the wallet's API key can sign for any path, and the
owner's policy governs every path alike. What a path buys is separation of
balances — a connector's trading key and its bridge key are different
addresses, and neither is the wallet's; which path an integration may use is
decided by whoever forwards it. The empty path is the wallet's own key — from
the HTTPS API; a WASI guest never reaches it, because the worker maps every
label it is given, the empty one included, to a `connector.…` path. The
coordinator and the keystore validate the path with one shared rule
(`shared_tee_helpers::is_valid_sub_path`) and both refuse it on non-EVM
chains; the coordinator echoes it in the response. Nothing about a sub-key is
stored — its address is derived on request. The same `evm_sign` capability
governs every sub-key: a sub-key is the same wallet's authority over a
separate balance, not a separate authority.

### Endpoints

| Endpoint | Standard | What the keystore does |
|----------|----------|------------------------|
| `POST /wallet/v1/evm/sign-typed-data` | EIP-712 v4 | Computes the digest from the full `eth_signTypedData_v4` object server-side, then signs |
| `POST /wallet/v1/evm/sign-message` | EIP-191 `personal_sign` | Computes `keccak256("\x19Ethereum Signed Message:\n" + len + msg)`, then signs |
| `POST /wallet/v1/evm/sign-transaction` | raw tx | The **client** serializes the unsigned tx; the keystore keccak256-hashes and signs it. No assembly, nonce/gas selection, or broadcast. For an EIP-1559 (type-2) tx the `yParity` needed to assemble the final tx is `v - 27`. |

All three return a 65-byte `0x` signature `r‖s‖v`, with `v ∈ {27, 28}` and low-s (EIP-2) normalization. The EIP-712 encoder is **hand-rolled** (no `alloy`/`ethers`) so it adds no dependency to the enclave's attestation surface; it is pinned against viem-generated reference vectors (`keystore-worker/src/eip712_vectors.json`).

### Policy capability: `evm_sign`

`evm_sign` is **default-DENY under a policy** — like every other fund-moving capability, a policy must explicitly set `capabilities.evm_sign.allowed = true` to permit EIP-712 / EIP-191 signing (a wallet with **no policy** is unrestricted). `sign_message` is the only default-allow capability. A `raw_tx` sub-flag is **default-OFF** and separately gates the raw-transaction endpoint. `requires_approval` is **not supported** for `evm_sign` (a policy that sets it fails closed rather than silently ignoring the owner's intent).

**Caveat — `evm_sign` is fund-moving authority, not a read-only grant.** An EIP-712 signature can itself move funds: EIP-3009 `transferWithAuthorization` ≈ a transfer, EIP-2612 `Permit` ≈ an approve. So `evm_sign` grants full authority over whatever float sits on the wallet's EVM address — bounded to what has been bridged there. The `raw_tx` flag is a kill-switch for arbitrary raw transactions, **not** a containment boundary for typed-data drains. The NEAR-intents balance is never exposed by any EVM signing path.

### Remaining EVM work

- **Dashboard chain selector for signing flows** — address display exists; per-chain signing UX is not built.
- **Persisting derived EVM addresses** (`wallet_chain_addresses`) is optional — the address is deterministic from the seed and the shared EOA is identical across chains, so the table is only a convenience cache.

## Solana Signing (shipped)

Solana signing follows the EVM model exactly: **the client builds and broadcasts; the keystore only signs.** There is no digest step on Solana — the ed25519 signature covers the raw serialized message bytes — so the keystore signs the supplied bytes as-is. It never assembles a transaction, never picks a blockhash, and never broadcasts. The chain identifier is `solana` (alias `sol`); both spellings canonicalize to the ONE derived key on seed `wallet:{id}:solana`. `GET /wallet/v1/address?chain=solana` returns the base58 ed25519 public key (which IS the Solana address).

### Endpoints

| Endpoint | What the keystore does |
|----------|------------------------|
| `POST /wallet/v1/solana/sign-message` | Signs the raw decoded bytes (`encoding`: `utf8` default / `hex` / `base64`, no content sniffing) — verifiable with `nacl.sign.detached.verify`; Sign-in-with-Solana flows work unchanged. **Rejects bytes that parse as a valid transaction message** (see guard below). Max 64 KiB. |
| `POST /wallet/v1/solana/sign-transaction` | The **client** serializes the unsigned transaction **message** (base64 — what the signature covers: web3.js `tx.serializeMessage()` / `versionedTx.message.serialize()`); the keystore signs the bytes as-is. Max 1232 bytes (the Solana packet limit). The client assembles the signed tx (`compact-u16 sig count ‖ signatures ‖ message`) and broadcasts. |

Both return a 64-byte ed25519 signature, **base58** (Solana convention).

### The message/transaction guard

Unlike EVM, Solana has no EIP-191-style prefix cryptographically separating messages from transactions: a "message" whose bytes are a valid serialized transaction message would, once signed, be broadcastable — silently bypassing the `raw_tx` sub-flag. Wallets (Phantom, Solflare) close this by refusing to `signMessage` bytes that parse as a transaction message; `keystore-worker/src/solana.rs::parses_as_transaction_message` implements the same **reject-only** check (legacy + versioned v0 wire format, strict full-byte consumption, `sanitize()`-level header/index checks). It never interprets the payload beyond "could a node accept this as a transaction" — blind signing stays blind. The parser is hand-rolled (no `solana-sdk` in the enclave, same rationale as the EIP-712 encoder) and pinned against `@solana/web3.js`-generated reference vectors (`keystore-worker/src/solana_vectors.json`, generator: `keystore-worker/scripts/gen_solana_vectors.mjs`), including a **byte-exact cross-signing test**: the keystore's signature over the vector transactions is asserted identical to web3.js/nacl output, and splicing it into the wire format reproduces the web3.js-signed transaction exactly.

### Policy capability: `solana_sign`

Same model as `evm_sign`, evaluated by the shared `solana_sign_decision` in `shared-tee-helpers` (one implementation with the EVM gate — the chains cannot drift): **default-DENY under a policy** (`capabilities.solana_sign.allowed = true` to opt in; no policy → unrestricted), `frozen` + `time_restrictions` global gates apply, `requires_approval` fails closed, and the `raw_tx` sub-flag (**default-OFF**) separately gates `sign-transaction`.

**Caveat:** a signed Solana transaction message is itself fund-moving, so `solana_sign` + `raw_tx` grants full authority over the wallet's Solana float — bounded to what has been sent there. The NEAR-intents balance is never exposed by any Solana signing path.

**Overlap with `raw_sign`:** the unified `/wallet/sign` endpoint's `Op::Raw { chain: "solana" }` also blind-signs bytes with the same key, gated by the separate default-DENY `raw_sign` capability (optionally restricted per-chain via `raw_sign.chains`). `raw_sign` is an independent, blunter blind-sign gate with no message/transaction distinction — a policy author locking down Solana must leave BOTH `solana_sign` and `raw_sign` disabled (both are default-DENY under a policy, so the default is safe). ⚠️ Alias caveat: `Op::Raw` treats `chain` as a **literal seed namespace** (`wallet:{id}:{chain}`, no alias canonicalization — a pre-existing property of that endpoint), so `Op::Raw { chain: "sol" }` derives a *different* key than the `/wallet/v1/solana/*` endpoints (which canonicalize `sol` → `solana`). Always use `"solana"` in `Op::Raw`.

### Remaining Solana work

- **Dashboard**: Solana address display + signing UX (matches EVM, where signing UX is also TODO).
- **SDK**: thin `solanaSignMessage` / `solanaSignTransaction` methods after an api-spec sync.

## Checklist: Adding another chain

1. Add a chain predicate in `shared-tee-helpers/src/lib.rs` (single source of truth for keystore + coordinator) and a capability + decision fn in `wallet_policy.rs` (reuse `chain_sign_decision`).
2. Add keystore signing handler(s) in `keystore-worker/src/api.rs` mirroring `evm_sign_digest` / `solana_sign_bytes`; canonicalize aliases in `wallet_seed()`.
3. **Every chain uses a distinct derivation seed** (`wallet:{id}:near` vs `wallet:{id}:evm` vs `wallet:{id}:solana`) — this is the cross-curve/cross-chain domain-separation invariant: a blind signature on one chain's key can never forge another chain's transaction or a NEAR auth message.
4. Follow the blind-signing model: the **client** builds and broadcasts; the keystore only signs. Do not build/broadcast in the coordinator.
5. If the chain signs raw bytes (no digest), decide how messages are separated from transactions (prefix or reject-guard) BEFORE shipping the message endpoint.
6. Un-gate the chain in the coordinator's `validate_chain()`, add `/wallet/v1/<chain>/*` routes, update the api-spec + reference vectors.

## Key Files

| File | What it does |
|------|----------------|
| `coordinator/src/wallet/handlers.rs` | `validate_chain()` admits near + EVM + Solana; `evm_sign_*` / `solana_sign_*` handlers forward to the keystore via `keystore_chain_sign` (no build/broadcast) |
| `keystore-worker/src/crypto.rs` | `derive_keypair()` (ed25519), `derive_secp256k1_keypair()`, `derive_eth_address()`, `sign()` (ed25519 over raw bytes — the Solana primitive), `sign_secp256k1_prehash()` |
| `keystore-worker/src/eip712.rs` | Hand-rolled EIP-712 v4 + EIP-191 digest computation; pinned to `eip712_vectors.json` |
| `keystore-worker/src/solana.rs` | Hand-rolled reject-only Solana tx-message guard + size caps; pinned to `solana_vectors.json` (generator: `scripts/gen_solana_vectors.mjs`) |
| `keystore-worker/src/api.rs` | `/wallet/evm/*` + `/wallet/solana/*` handlers; `wallet_seed()` canonicalization; capability gating via `shared_tee_helpers::wallet_policy::{evm_sign_decision, solana_sign_decision}` |
| `dashboard/app/wallet/manage/page.tsx` | Multi-chain address display (per-chain signing UX still TODO) |
| `contract/src/wallet.rs` | No changes needed — policy is keyed by `wallet_pubkey` (NEAR key) |
