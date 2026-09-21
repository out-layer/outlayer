# Agent Custody — Developer Reference

Institutional-grade custody wallets for AI agents. An agent gets an API key to operate a NEAR-native wallet whose cross-chain value is custodied on `intents.near`. Private keys live exclusively inside a TEE (Intel TDX). The wallet owner sets policy (spending limits, whitelists, multisig, freeze) — all enforced inside the TEE. Cross-chain deposits/withdrawals via NEAR Intents + the 1Click solver (gasless), like a CEX: deposit, operate, withdraw to an external address. The wallet now signs EVM payloads itself — EIP-712 typed data, EIP-191 `personal_sign`, and raw EVM transactions (the client builds/serializes the unsigned tx and broadcasts; the keystore only keccak256-hashes and signs). Solana signing follows the same model — off-chain messages and serialized transaction messages, ed25519, base58 signature; the client assembles and broadcasts.

> **⚠️ Only send whitelisted Intents assets — anything else is lost permanently.**
> Deposits/withdrawals only work for assets in the NEAR Intents / 1Click token
> catalog (`GET /wallet/v1/tokens`), on the exact chain a deposit address was
> issued for. Sending an unsupported token, the wrong token, a token on the
> wrong chain, an NFT, or an unlisted native gas coin to a deposit address is
> **unrecoverable**. Deposit addresses from
> `/wallet/v1/intents/deposit/cross-chain` (legacy alias `/wallet/v1/deposit-intent`)
> are per-request and expire (30 min) — never reuse one or send after expiry.

---

## Integrating

For most use cases, use the **TypeScript SDK** instead of calling the HTTP API directly:

```bash
npm install @outlayer/sdk
```

```ts
import { OutlayerClient } from '@outlayer/sdk';

// 1. Register a wallet (anonymous, returns API key once)
const { apiKey, walletId, handoffUrl } = await OutlayerClient.register();

// 2. Use it
const client = new OutlayerClient({ apiKey });
const result = await client.withdraw({
  chain: 'ethereum',
  to: '0x742d35Cc6634C0532925a3b844Bc9e7595f8b4f5',
  amount: '1000000',
  token: 'nep141:usdt.tether-token.near',
});
```

- **SDK source**: [out-layer/sdk-js](https://github.com/out-layer/sdk-js) (MIT)
- **SDK on npm**: [`@outlayer/sdk`](https://www.npmjs.com/package/@outlayer/sdk)
- **OpenAPI spec**: [out-layer/api-spec](https://github.com/out-layer/api-spec)
- **Interactive API docs**: https://api.outlayer.ai/docs (Scalar UI)

The SDK auto-generates types from the OpenAPI spec, adds typed error classes (`PolicyDeniedError`, `WalletFrozenError`, etc.), automatic idempotency keys, and retry with backoff on 5xx + network errors. SDK feature parity with the raw HTTP API; the rest of this document is the reference for both.

For other languages, generate a client from the OpenAPI spec:

```bash
# Python
openapi-python-client generate --url https://api.outlayer.ai/openapi.json
# Go
oapi-codegen -generate types https://api.outlayer.ai/openapi.json > types.go
```

---

## Architecture

```
                ┌──────────────┐               ┌───────────────┐
                │   AI Agent   │               │ Wallet Owner  │
                │ (API key)    │               │ (NEAR wallet) │
                └──────┬───────┘               └───────┬───────┘
                       │ withdraw, call, address        │ set policy, freeze
                       ▼                                ▼
              ┌─────────────────────────────────────────────────┐
              │            Coordinator (stateless proxy)         │
              │  auth API key → forward to keystore → track DB  │
              └──────────────────────┬──────────────────────────┘
                                     │
                                     ▼
              ┌─────────────────────────────────────────────────┐
              │               TEE (Intel TDX)                   │
              │                                                 │
              │  ┌────────────┐ ┌───────────┐ ┌─────────────┐  │
              │  │ Key Derivat│ │ Tx Signing│ │ Policy Eval │  │
              │  │ HMAC-SHA256│ │ Ed25519 / │ │ Decrypt from│  │
              │  │ from MPC   │ │ secp256k1 │ │ chain, check│  │
              │  │ master key │ │           │ │ all rules   │  │
              │  └────────────┘ └───────────┘ └─────────────┘  │
              └──────────────────────┬──────────────────────────┘
                                     │ submit signed tx / read policy
                                     ▼
              ┌──────────────────┐   ┌─────────────────────────┐
              │  NEAR Blockchain │   │     NEAR Intents         │
              │  policy storage  │   │  gasless cross-chain     │
              │  freeze/unfreeze │   │  NEAR, ETH, BTC, SOL    │
              └──────────────────┘   └─────────────────────────┘
```

**Coordinator is a stateless proxy.** It authenticates API keys, forwards requests to the keystore TEE, and tracks operational data in PostgreSQL. All security-critical work (key derivation, signing, policy evaluation) happens inside the TEE.

---

## Components & Key Files

### Coordinator — `coordinator/src/wallet/`

HTTP API server. Handles auth, routing, usage tracking, webhooks.

| File | Lines | Description |
|------|-------|-------------|
| [mod.rs](coordinator/src/wallet/mod.rs) | 124 | Router setup, `WalletState` struct, negative policy cache |
| [handlers.rs](coordinator/src/wallet/handlers.rs) | 3,425 | All HTTP endpoint handlers |
| [auth.rs](coordinator/src/wallet/auth.rs) | 819 | API key authentication (SHA-256 hash lookup) |
| [types.rs](coordinator/src/wallet/types.rs) | 659 | Request/response structs, error types |
| [policy.rs](coordinator/src/wallet/policy.rs) | 460 | Policy caching, NEAR RPC `has_wallet_policy()` calls |
| [backend/mod.rs](coordinator/src/wallet/backend/mod.rs) | — | `WalletBackend` trait + 1Click API types |
| [backend/intents.rs](coordinator/src/wallet/backend/intents.rs) | — | 1Click REST API (swap quotes, status polling), token list |
| [audit.rs](coordinator/src/wallet/audit.rs) | 76 | Audit log recording |
| [webhooks.rs](coordinator/src/wallet/webhooks.rs) | 278 | Webhook delivery with retry + HMAC-SHA256 |
| [idempotency.rs](coordinator/src/wallet/idempotency.rs) | 38 | Idempotency key check/store |
| [nonce.rs](coordinator/src/wallet/nonce.rs) | 74 | Per-wallet nonce mutex for concurrent withdrawals |

#### Key handler functions (handlers.rs)

| Function | Line | Description |
|----------|------|-------------|
| `register()` | 36 | Generate UUID wallet_id + API key → call keystore TEE to derive NEAR address |
| `withdraw()` | — | Build `Op::Withdraw` → check-policy → keystore `/wallet/sign` (gasless `native_withdraw`/`ft_withdraw` intent) → publish to solver relay → record usage after success |
| `withdraw_dry_run()` | 755 | Simulate withdraw: policy + balance check without execution |
| `call()` | 2186 | Native NEAR function call: policy check → keystore sign → broadcast |
| `transfer()` | 2621 | Chain-agnostic transfer (chain param, currently near only): policy → keystore sign → broadcast |
| `get_balance()` | 2983 | Chain-agnostic balance query (chain param, currently near only) via RPC |
| `intents_deposit()` | — | Deposit FT into intents.near via `ft_transfer_call` (intents.near auto-registers callers via its own `ft_on_transfer` hook — no NEP-145 `storage_deposit` issued) |
| `swap()` | — | Swap via 1Click: quote → ft_transfer_call to intents.near → mt_transfer → poll |
| `deposit()` | 857 | Cross-chain deposit via Intents quote |
| `get_address()` | 345 | Derive wallet address. Serves **`near` + all EVM chains + `solana`** (EVM chains share **one secp256k1 `0x` address**; `solana`/`sol` returns the base58 ed25519 pubkey). `bitcoin` stays gated (no signing path yet; that cross-chain value uses Intents). |
| `encrypt_policy()` | 1155 | Send policy JSON to keystore for encryption |
| `sign_policy()` | 1199 | Keystore signs encrypted policy SHA256 for on-chain verification |
| `approve()` | 1447 | Submit multisig approval (NEP-413 signature verification) |
| `reject()` | 1714 | Reject pending approval |
| `get_policy()` | 1284 | Fetch decrypted policy from keystore |
| `record_usage()` | 263 | Write spending to `wallet_usage` (daily/hourly/monthly periods) |
| `get_current_usage()` | 298 | Read current usage for velocity limit checks |
| `internal_wallet_check()` | 2623 | Worker-only: check policy for WASI execution |
| `internal_activate_policy()` | 2873 | Worker-only: activate policy after on-chain signing |
| `internal_wallet_frozen_change()` | 3106 | Sync freeze status from contract events |

### Keystore TEE — `keystore-worker/src/`

Runs inside Intel TDX. Holds master secret from NEAR MPC. All crypto happens here.

| File | Key area | Description |
|------|----------|-------------|
| [api.rs](keystore-worker/src/api.rs) | Wallet routes | Router for `/wallet/*` (coordinator-token-only) endpoints |
| [api.rs](keystore-worker/src/api.rs) | `wallet_derive_address_handler` | Derive pubkey from seed `"wallet:{wallet_id}:{chain}"` |
| [api.rs](keystore-worker/src/api.rs) | `wallet_sign_handler` | **Single** signing entry point. Takes a canonical `op` (+ optional `approval_info`, `artifact` carrying `bytes_base64`/`message`/`nonce_base64`/`recipient`, and `usage`); derives `request_hash = sha256(canonical_json(op))`, evaluates the on-chain policy, verifies approver signatures when required, then produces the artifact per the op's bind mode (Built / Hash-pinned / Trusted). Replaces the old per-flow sign endpoints (transaction / nep413 / near-call / near-transfer). |
| [api.rs](keystore-worker/src/api.rs) | `wallet_sign_policy_handler` | Sign an encrypted policy blob: decrypt-validates the ciphertext, then signs `sha256(encrypted_data)` (rejects a caller-supplied raw hash — not a signing oracle) |
| [api.rs](keystore-worker/src/api.rs) | `wallet_check_policy_handler` | Pre-flight: decrypt policy from chain → `evaluate(policy, op, usage, now)` → return `{allowed, frozen, requires_approval, required_approvals, reason, request_hash}` (the decrypted policy never leaves the TEE) |
| [crypto.rs](keystore-worker/src/crypto.rs) | `derive_keypair()` | `HMAC-SHA256(master_secret, seed)` → Ed25519 keypair |

The keystore exposes exactly one signing endpoint, `POST /wallet/sign`. The OLD five separate
sign endpoints (`/wallet/sign-transaction`, `/wallet/sign-nep413`, `/wallet/sign-near-call`,
`/wallet/sign-near-transfer`, and the policy-hash signer used as a raw oracle) are **removed**.
OutLayer's own Bearer/register/api-key authentication (previously `sign-message` with
`format:"raw"`) is now a dedicated coordinator endpoint, `POST /wallet/v1/auth-sign`, which maps
to an `Op::Auth` the keystore constructs and signs raw ed25519.

#### Canonical `op` model

Every signable operation is a canonical `op` with `request_hash = sha256(canonical_json(op))`
(a recursive-key-sorted, compact JSON; amounts are decimal strings, never JSON numbers — so the
hash reproduces even for `call.args`). The kind fixes the **bind mode** — how the keystore is
allowed to produce the artifact it signs:

| Bind mode | Kinds | Keystore behavior |
|-----------|-------|-------------------|
| **Built** | `transfer`, `call`, `delete`, `withdraw` (+ `auth`) | Constructs the NEAR tx / NEP-413 intent / auth string FROM the op fields → artifact == approved op |
| **Hash-pinned** | `raw`, `sign_message` | Op carries `payload_hash`/`message_hash`; signs the supplied bytes iff `sha256(bytes) == hash` |
| **Trusted** | `swap`, `confidential`, `cross_chain_withdraw`, `limit_order`, `payment_check` | Artifact (e.g. the 1Click quote / deposit address) can't exist at approval time; the keystore checks capability + policy + multisig on the op fields and pins the recipient, then signs the supplied artifact, **trusting the coordinator to have built it from the approved op**. The keystore does NOT itself re-verify the artifact's token/amount against the op — those are bound only by that coordinator-trust, the same trust as the coordinator-supplied off-chain deposit address (documented tradeoff) |

The deposit family (`intents/deposit`, `storage-deposit`, cross-chain deposit) is all
`Op::Call` — there is no finer deposit policy type. `auth` is non-fund (a domain-separated
`auth:`/`register:`/`api-key:` string, never a 32-byte tx hash), so it is always allowed on a
non-frozen wallet — no capability, no multisig.

#### Key derivation

```
master_secret (from NEAR MPC network, never leaves TEE)
    │
    ├── seed: "wallet:{wallet_id}:near"      → Ed25519 → NEAR implicit account
    ├── seed: "wallet:{wallet_id}:evm"        → secp256k1 → ETH address (shared by all EVM chains)
    ├── seed: "wallet:{wallet_id}:solana"     → Ed25519 → Solana address
    └── seed: "wallet:{wallet_id}:bitcoin"    → secp256k1 → BTC address
```

Same wallet_id always produces same addresses across chains. Deterministic, stateless.

> The keystore *can* derive and sign for all of the above (secp256k1 for EVM,
> Ed25519 for NEAR/Solana). The public `GET /wallet/v1/address` endpoint now
> serves **NEAR + all EVM chains + Solana** — every EVM chain returns the same
> shared secp256k1 `0x` address; Solana returns the base58 ed25519 public key.
> The keystore signs EVM payloads (EIP-712 / EIP-191 / raw tx) and Solana
> payloads (off-chain messages / serialized tx messages, ed25519); the
> **client** assembles and broadcasts the transaction (the coordinator/keystore
> never build, fund, or broadcast one). Cross-chain value movement also still
> works through NEAR Intents + the 1Click solver. See
> [coordinator `docs/MULTI_CHAIN.md`](https://github.com/out-layer/coordinator/blob/main/docs/MULTI_CHAIN.md).

#### Policy evaluation flow (inside TEE)

One engine (`shared_tee_helpers::wallet_policy::evaluate`) is shared by check-policy and
`/wallet/sign`. **The keystore is the sole evaluator** — only it can decrypt the on-chain policy,
so the plaintext policy never leaves the TEE. The coordinator only *supplies* `usage` (it owns the
stateful spend counters).

1. Coordinator sends `POST /wallet/check-policy { wallet_id, op, usage? }` (the same call shape
   `/wallet/sign` takes; `usage` is the coordinator's `current_usage` JSON, optional)
2. Keystore calls `get_wallet_policy(wallet_pubkey)` view method on NEAR (O(1) lookup)
3. Keystore decrypts `encrypted_data` with the derived key
4. `evaluate(policy, op, usage, now)` checks, in order: frozen → `transaction_types` → `allowed_tokens`
   → whitelist/blacklist → per-tx limit → **velocity limits (only when `usage` is supplied)** →
   time restrictions → capabilities → generic multisig trigger
5. Returns `Decision`: `Allow`, `Deny { reason }`, `RequiresApproval { threshold }`, `Frozen`

**Stateless vs stateful.** The stateless clauses (frozen, transaction_types, allowed_tokens,
whitelist, per-transaction, time, capabilities, the multisig trigger) are enforced *exactly* on
every signature, with or without `usage`. The cumulative clauses (`daily`/`hourly`/`monthly` spend
and the hourly tx-count / `rate_limit`) are stateful: they run only when the coordinator supplies
`usage`, and a token's spend is recorded (+1) only after a successful operation. Under concurrency
they are therefore **best-effort** — simultaneous requests can read the same pre-spend counter and
all pass, so a burst can overshoot a cumulative cap. For hard stops, rely on the per-transaction
limit, multisig, or freeze.

### Contract — `contract/src/wallet.rs`

On-chain storage for encrypted policies and freeze flags.

| Function | Line | Description |
|----------|------|-------------|
| `store_wallet_policy()` | 164 | Store encrypted policy + verify wallet signature on-chain |
| `freeze_wallet()` | 280 | Controller-only emergency freeze (no wallet sig needed) |
| `unfreeze_wallet()` | 313 | Controller-only unfreeze |
| `delete_wallet_policy()` | 344 | Delete policy, refund storage deposit |
| `has_wallet_policy()` | 387 | View: check existence (for negative cache) |
| `get_wallet_policy()` | 394 | View: return `{ owner, encrypted_data, frozen, updated_at }` |

```rust
pub struct WalletPolicyEntry {
    pub owner: AccountId,           // Controller NEAR account
    pub encrypted_data: String,     // Encrypted by keystore TEE
    pub frozen: bool,               // Emergency freeze (separate from encrypted_data)
    pub updated_at: u64,            // Block timestamp
    pub storage_deposit: Balance,   // Refundable
}
```

**Ownership**: First `store_wallet_policy()` call sets `owner = caller`. Subsequent updates only from same owner. Wallet signature required — over `store_wallet_policy:v1:{wallet_pubkey}:{len}:{encrypted_data}:{caller}`, so it proves key ownership AND is usable only by the account named in it.

**Freezing survives an edit**: a policy update keeps whatever `frozen` the entry held; a new entry starts unfrozen. Thawing is `unfreeze_wallet()`, controller-only — the same authority, said out loud. A freeze is an answer to a compromised agent key, and the controller's next act is usually to tighten the policy; resetting the flag there would reopen the wallet while the key is still in someone else's hands.

**On-chain signature verification**: Ed25519 → `env::ed25519_verify()` (~26 Tgas), secp256k1 → `env::ecrecover()` (~35 Tgas).

### Worker WASI host functions — `worker/src/outlayer_wallet/`

WASI containers can call wallet functions via WIT interface.

| File | Description |
|------|-------------|
| [host_functions.rs](worker/src/outlayer_wallet/host_functions.rs) | WIT interface implementation (9,316 lines) |
| [mod.rs](worker/src/outlayer_wallet/mod.rs) | Module setup & linker bindings |
| [wallet.wit](worker/wit/deps/wallet.wit) | WIT interface definition |

**WIT interface** (`outlayer:wallet/api@0.1.0`):

```wit
get-id() → (string, string)
get-address(chain) → (string, string)                         # near, solana, any EVM chain
get-sub-key-address(chain, label) → (string, string)          # a connector's EVM sub-key (empty label = `default`; never the wallet's own key)
evm-sign-typed-data(chain, typed-data, label) → (string, string)   # EIP-712 v4; evm_sign capability
evm-sign-message(chain, message, encoding, label) → (string, string) # EIP-191; encoding utf8|hex
evm-sign-transaction(chain, unsigned-tx, label) → (string, string) # keccak of the serialized tx; evm_sign.raw_tx
withdraw(chain, to, amount, token) → (string, string)         # cross-chain via Intents (whitelisted assets only)
withdraw-dry-run(chain, to, amount, token) → (string, string)
get-request-status(request-id) → (string, string)
list-tokens() → (string, string)
transfer(chain, to, amount) → (string, string)                # chain-specific (currently: near)
get-balance(chain, token) → (string, string)                  # chain-specific (currently: near)
get-intents-balance(token) → (string, string)                 # the wallet's balance INSIDE intents.near, per asset
deposit-intent(chain, token, amount) → (string, string)       # 1Click deposit address to bring funds from another chain into intents
get-confidential-balance(token) → (string, string)            # the wallet's CONFIDENTIAL (shielded) intents balance; empty token = all
confidential-withdraw(chain, to, amount, token) → (string, string)   # shielded balance → an address on another chain; policy-gated like withdraw
confidential-deposit-intent(chain, token, amount) → (string, string) # 1Click deposit address landing in the shielded balance
intents-deposit(token, amount) → (string, string)             # deposit FT to intents.near
swap(token-in, token-out, amount-in, min-amount-out) → (string, string)  # swap via Intents
```

Available only when `WALLET_ID` env var is set (coordinator passes it when `X-Wallet-Id` header is valid). Rate limited to 200 calls per execution. Sub-keys (`label`) exist only for a connector in the connectors namespace whose manifest `connector_id` equals its project name, and they are the only EVM keys a guest can sign with — the wallet's own EVM key is signable through the HTTPS API alone; see `docs/CONNECTORS.md` §4.5.

### Dashboard — `dashboard/app/wallet/`

| Page | File | Description |
|------|------|-------------|
| Handoff/setup | [page.tsx](dashboard/app/wallet/page.tsx) | Receive API key, connect NEAR wallet, set initial policy |
| Policy management | [manage/page.tsx](dashboard/app/wallet/manage/page.tsx) | Edit policy, manage approvers, freeze/unfreeze |
| Approvals list | [approvals/page.tsx](dashboard/app/wallet/approvals/page.tsx) | List pending multisig approvals |
| Approval detail | [approvals/[id]/page.tsx](dashboard/app/wallet/approvals/[id]/page.tsx) | View & sign specific approval |
| Audit log | [audit/page.tsx](dashboard/app/wallet/audit/page.tsx) | Full transaction and event history |
| Fund request | [fund/page.tsx](dashboard/app/wallet/fund/page.tsx) | User funds agent via link (?to, ?amount, ?token) |

### Documentation page

| File | Description |
|------|-------------|
| [docs/agent-custody/page.tsx](dashboard/app/docs/agent-custody/page.tsx) | User-facing docs page |

---

## Database Schema

Migrations: `coordinator/migrations/20260220000001_wallet.sql`, `20260220000002_wallet_policy_columns.sql`

| Table | Purpose |
|-------|---------|
| `wallet_accounts` | wallet_id, near_pubkey, policy_json (synced), frozen flag |
| `wallet_api_keys` | SHA-256 hash of API key → wallet_id mapping |
| `wallet_requests` | Async operation tracking (withdraw, deposit, call) |
| `wallet_pending_approvals` | Multisig approval state machine |
| `wallet_approval_signatures` | Individual approver signatures |
| `wallet_usage` | Per-token per-period spending (hourly/daily/monthly) |
| `wallet_audit_log` | Complete event history |
| `wallet_webhook_deliveries` | Webhook retry queue |

**Note**: `wallet_usage` is in the coordinator DB, not on-chain. If DB is compromised, velocity limits could be reset. Mitigation: per-tx limits and whitelists are checked in keystore TEE (not bypassable), and audit log records all operations.

---

## Flows

### Registration

```
Agent → POST /register → Coordinator
    Coordinator:
        1. Generate UUID wallet_id
        2. Generate random API key (wk_...)
        3. Store SHA-256(api_key) → wallet_id in DB
        4. Call keystore POST /wallet/derive-address { wallet_id, chain: "near" }
    Keystore TEE:
        5. HMAC-SHA256(master_secret, "wallet:{wallet_id}:near") → Ed25519 keypair
        6. Return { address, public_key }
    Coordinator:
        7. Return { api_key, near_account_id, handoff_url }
```

No blockchain transaction. Instant. API key shown once.

### Withdraw (with policy)

Withdraws tokens from the wallet's intents.near balance to a receiver as a **gasless** NEP-413
`withdraw` intent published to the solver relay (`native_withdraw` for native NEAR, `ft_withdraw`
for NEP-141). The wallet pays no NEAR gas. (The old direct on-chain `/intents/ft-withdraw`
endpoint — which gated as a `call` and lost the amount/token limits — is **removed**; all
same-chain FT withdrawals go through this path.)

```
Agent → POST /wallet/v1/intents/withdraw { to, amount, chain, token }
    with Authorization: Bearer wk_...

    Coordinator:
        1. Lookup wallet_id from SHA-256(api_key)
        2. Check idempotency key
        3. Build canonical op: Op::Withdraw { to, amount, token }
        4. Get current_usage from wallet_usage table
        5. Call keystore POST /wallet/check-policy { wallet_id, op, usage }
    Keystore TEE:
        6. get_wallet_policy(wallet_pubkey) via NEAR RPC
        7. Decrypt policy → evaluate(policy, op, usage, now)
        8. Return decision: Allow / Deny / RequiresApproval / Frozen
    Coordinator (if Allow):
        9. Call keystore POST /wallet/sign { wallet_id, op, usage }
    Keystore TEE:
        10. Re-derive request_hash, re-run policy, then BUILD the NEP-413
            native_withdraw / ft_withdraw intent from the op and sign it
    Coordinator:
        11. publish_intent to the solver relay (gasless)
        12. record_usage() → wallet_usage table (only AFTER a successful sign+submit)
        13. Create wallet_requests entry → return { request_id, status } (with result_data: { intent_hash, delivered })
        14. Record audit log
        15. Enqueue webhook if configured
```

**Usage is recorded post-settle, never on create-pending.** Nothing is reserved when a request is
accepted and nothing is released when it fails — `record_usage()` is the only writer of these
counters and it runs after the outcome is known. This keeps the velocity counters honest while
still bounding each op by the exact (stateless) per-transaction limit, whitelist, and capability
checks inside the TEE.

What that means for each outcome, because the spend windows and the transaction count answer
differently:

| outcome | `daily`/`hourly`/`monthly` spend | `rate_limit.max_per_hour` |
|---------|----------------------------------|---------------------------|
| refused before it was sent — by this policy, or by a pre-flight check | nothing | nothing |
| reached the chain and reverted | nothing — no money moved | **one** |
| settled | the amount that moved | one per (token, amount) pair |

A reverted request costing nothing against the spend windows but still consuming one of the hourly
allowance is deliberate: a limiter a caller can walk past by failing its own calls is not a
limiter. By the same rule, one request moving both NEAR and a token counts twice.

**What a call spends is the deposit it ATTACHED, not what it turned out to cost.** Most contracts
refund the change, and the refund is *not* credited back — attach what you mean to spend. The same
holds for a call that panics: the protocol returns the deposit, the counter keeps it. This errs the
safe way, and it is the rule rather than an omission — a limit that under-counts stops being a
limit. The 1-yoctoNEAR marker a payable method demands (`assert_one_yocto`) is protocol overhead,
deducted before anything is counted.

**Token options for `chain=near`** — the `token` field selects what the recipient receives:

| `token` | Recipient receives | Notes |
|---------|--------------------|-------|
| omitted / `"near"` / `"native"` | **native NEAR** (default) | intents.near unwraps the wallet's wNEAR and sends native NEAR via the `native_withdraw` intent. Gasless; recipient needs **no** `wrap.near` storage. The recipient account must already exist (or be a 64-char implicit account) — a `native_withdraw` to a non-existent named account burns the wNEAR and is rejected up front. |
| `"nep141:wrap.near"` (or `"wrap.near"`) | **wNEAR** (NEP-141) | Explicit opt-in. Recipient must be storage-registered on `wrap.near` (`POST /wallet/v1/storage-deposit`). |
| other `nep141:<token>` | that NEP-141 | Recipient must be storage-registered on that token. |

This solves the "wallet holds only wNEAR, 0 native NEAR" case: it can withdraw native NEAR for gas/staking without first unwrapping. For cross-chain (`chain=ethereum`, etc.) the `token` is the source Intents asset and 1Click delivers the destination chain's native asset.

### Policy Setup

```
Dashboard → POST /wallet/v1/encrypt-policy { rules, approval, ... }
    Coordinator → Keystore: encrypt policy JSON
    Keystore → Return encrypted_base64

Dashboard → POST /wallet/v1/sign-policy { encrypted_data, caller }
    Coordinator → Keystore: sign the message the contract rebuilds,
        store_wallet_policy:v1:{wallet_pubkey}:{len}:{encrypted_data}:{caller}
    Keystore → Return { signature, wallet_pubkey }

    `caller` is the account that will send the transaction below, and it is
    SIGNED — the signature is good for that account and no other.

Dashboard → NEAR tx: store_wallet_policy(wallet_pubkey, encrypted_base64, signature)
    Contract: verify signature on-chain → store WalletPolicyEntry

Dashboard → POST /wallet/v1/invalidate-cache { wallet_id }
    Coordinator: clear negative policy cache
```

### Freeze (Emergency)

```
Wallet Owner → NEAR tx: freeze_wallet(wallet_pubkey)
    Contract: check caller == entry.owner → set frozen = true

Any subsequent wallet operation:
    Keystore reads fresh policy → sees frozen == true → rejects
```

No API gateway involvement needed. Owner can freeze directly on-chain. Latency: 2-5 seconds (blockchain confirmation).

**What a freeze is.** It closes the agent's access to everything the policy gates: no new transfer,
withdrawal, swap, signature or order. It does NOT unwind what the wallet already left on a venue — a
**limit order resting on 1Click** was authorised once, under the policy of that moment, and keeps
filling and paying out with no further signature; positions opened through a connector are the same.
A freeze cannot promise otherwise: the number of open orders is unbounded, and closing them is the
venue's own asynchronous business.

So cleaning up is a separate step, and the methods for it are **never frozen and never
policy-gated**. A freeze does not revoke the agent's API key — it refuses what the policy gates — so
the SAME key keeps working for everything that only winds down: reading orders,
`POST /wallet/v1/limit-orders/cancel-all`, cancelling order by order. After a freeze the agent (or the
owner, with that key) goes through the venues and cancels what it left there. Cancelling only brings
funds home. It is asynchronous,
and 1Click may fill a last slice before a cancel lands. See [Limit Orders](#limit-orders).

### Multisig Approval

```
Agent → POST /wallet/v1/intents/withdraw { amount > threshold }
    Policy check → RequiresApproval(2 of 3)
    Create wallet_pending_approvals entry
    Return { status: "pending_approval", approval_id, required: 2 }

Approver 1 → POST /wallet/v1/approve/{approval_id}
    with NEP-413 wallet signature
    Store in wallet_approval_signatures → approved: 1/2

Approver 2 → POST /wallet/v1/approve/{approval_id}
    Store signature → threshold met
    Auto-execute: sign tx → submit via intents → update request status
    Enqueue webhook: request_completed
```

Approvers sign `approve:{approval_id}:{wallet_pubkey}:{request_hash}` (NEP-413, recipient == the wallet contract,
wallet-bound); a `reject:` vote from a real approver vetoes. The keystore re-derives `request_hash`
from the stored canonical op and verifies the signatures itself — the coordinator transports them
but cannot forge or rebind them.

**Multisig covers Trusted ops too.** On a wallet with an approval threshold, the Trusted kinds —
`swap`, `confidential`, `cross_chain_withdraw`, `limit_order` — also create a pending approval and execute only
after the approvers confirm. What the approval actually binds is narrow: it binds *whether* the op
runs (the keystore verifies the approver signatures over the canonical op, and pins the recipient).
It does **not** bind the token/amount through the keystore — at execution the coordinator fetches
the 1Click artifact (quote → deposit address) and the keystore signs it **without re-verifying** the
artifact's `token_in`/`amount_in` against the approved op. The artifact matching the op is enforced
only by trusting the coordinator to have built it from that op — the **same coordinator-trust** as
the off-chain deposit address (generated at execution, coordinator-supplied, and not independently
verifiable by the keystore — the 1Click quote signature does not cover it). So: a compromised
coordinator could substitute the artifact's token/amount/routing post-approval; the on-chain
guarantees are the recipient pin + the approver signatures, not the value terms — a documented
tradeoff. `payment_check` is the **exception**: it is NOT wired into the generic multisig trigger —
its creation is gated by the default-DENY `payment_check` capability + the per-transaction amount
cap (cap-gated, not approval-gated, even on a multisig wallet).

---

### What an approver signs — and why the request's origin does not matter

*"When I sign a confirmation of my agent's action, I want to be sure the request came from the TEE."*
The direct answer: a request never comes FROM the TEE. It comes from the agent, through the coordinator,
and no signature could say otherwise — anyone able to submit an operation would receive the same
"genuine" stamp. What the TEE guarantees is the part that matters: **nothing executes unless the policy
allows it and the policy's approvers signed this exact operation.** So an approver does not need to
trust where a request came from — only to read the operation in front of them. Four things make that true:

1. **The vote is bound to the operation itself.** It signs
   `approve:{approval_id}:{wallet_pubkey}:{request_hash}`, and `request_hash` is
   `sha256(canonical_json(op))` — recipient, token, amount, and for an order its output terms and
   recipient type. It cannot be replayed for another wallet or stretched to another operation.
2. **The approver's browser checks that before signing.** Both approval endpoints
   (`GET /wallet/v1/pending_approvals_by_pubkey`, `GET /wallet/v1/approval/{id}`) return `op_canonical` —
   the exact string the hash is of. The dashboard hashes it itself, shows the parse of that same string,
   and disables Approve on a mismatch or a missing string. What is on screen is what the signature covers.
3. **The TEE decides again at execution.** The keystore, inside Intel TDX, decrypts the policy (encrypted
   on chain; nothing else reads it), runs `evaluate` on the op once more — a forbidden op is refused
   however many approvals it carries — and `verify_approvals` checks that enough signatures from the
   approvers THE POLICY names cover THIS hash. Only then does it sign.
4. **The keystore is itself verifiable**: its TDX measurements are approved on chain by the keystore DAO,
   and the master secret is released only to an approved measurement.

So a request somebody invented has exactly the power of a genuine one: none beyond what the policy allows
and the approver knowingly signed. That is also why the keystore does not sign approval requests as
"genuine": whoever can create a request — a holder of the agent's key through the API, or the coordinator
calling `check-policy` — would be handed that signature too, so it would tell an approver nothing.

Not covered: the agent chose the operation, and approving is a judgement of it — of the operation shown,
never of text the agent attached. For Trusted operations the off-chain routing is built at execution
(see the tradeoff above).

Checking by hand:

```bash
A=https://api.outlayer.ai/wallet/v1/approval/$APPROVAL_ID
curl -s $A | jq -j .op_canonical | shasum -a 256   # the hash of the operation
curl -s $A | jq -r .request_hash                   # the hash the vote signs — must be equal
```

## Policy Format

Stored encrypted on NEAR blockchain. Only keystore TEE can decrypt.

```json
{
  "version": 1,
  "frozen": false,
  "rules": {
    "transaction_types": ["transfer", "call", "withdraw", "swap", "delete"],
    "allowed_tokens": ["*"],
    "addresses": { "mode": "whitelist", "list": ["bob.near", "dex.near"] },
    "limits": {
      "per_transaction": { "native": "10000000000000000000000000", "nep141:usdt.tether-token.near": "1000000000" },
      "daily": { "*": "100000000000000000000000000" },
      "hourly": { "*": "50000000000000000000000000" },
      "monthly": { "*": "500000000000000000000000000" }
    },
    "time_restrictions": { "timezone": "UTC", "allowed_hours": [9, 17], "allowed_days": [1, 2, 3, 4, 5] },
    "rate_limit": { "max_per_hour": 60 }
  },
  "approval": {
    "threshold": { "required": 2 },
    "approvers": [
      { "id": "alice.near", "role": "admin",  "pubkey": "ed25519:<base58>" },
      { "id": "bob.near",   "role": "signer", "pubkey": "ed25519:<base58>" },
      { "id": "carol.near", "role": "signer", "pubkey": "ed25519:<base58>" }
    ],
    "excluded_types": []
  },
  "capabilities": {
    "raw_sign":     { "allowed": false, "chains": ["ethereum", "solana"], "requires_approval": true },
    "evm_sign":     { "allowed": true,  "raw_tx": false },
    "solana_sign":  { "allowed": false, "raw_tx": false },
    "confidential": { "allowed": false, "requires_approval": false },
    "sign_message": { "allowed": true,  "requires_approval": false, "allowed_recipients": [] },
    "swap":         { "allowed": false, "requires_approval": false },
    "cross_chain_withdraw": { "allowed": false, "requires_approval": false },
    "payment_check": { "allowed": false, "requires_approval": false }
  },
  "webhook_url": "https://myapp.com/webhook/wallet"
}
```

### `transaction_types` — the keystore op kinds

`transfer`, `call`, `delete`, `withdraw` (same-chain intents withdrawal), `swap`,
`cross_chain_withdraw`, `limit_order`, `raw`, `sign_message`. The deposit family (`intents/deposit`,
`storage-deposit`, cross-chain deposit) all gate as **`call`** — there is no separate deposit type.
Legacy deposit names (`intents_deposit`/`storage_deposit`/`cross_chain_deposit`) in a deployed
policy are normalized to `call` so old policies keep matching. Note `cross_chain_withdraw` is its
**own** type (NOT folded into `withdraw`) — a policy must list it explicitly to permit bridging out.
`limit_order` is likewise its own type: permitting swaps, or cross-chain exits, does not permit
resting an order that pays out unattended.

### `addresses` — how a destination is matched

An entry matches a destination when the two strings are equal, with one exception: an EVM address
(`0x` + 40 hex digits) matches in any letter case, because its case is only the EIP-55 checksum — the
same twenty bytes either way. Matched exactly, a `blacklist` holding `0xabc…` would let the agent
reach that very account by writing `0xABC…`. Nothing else is folded: base58 (Solana, Bitcoin) and
bech32 are case-sensitive by nature, and a NEAR account id is lower case only, so another spelling
of one is not that account.

### Bound wallets: the fund lane faces the rules twice

A `w_execute_extension` call — the lane a bound wallet spends through — is judged first by its
DECODED effects (every receiver, token move, refund destination and storage beneficiary inside
`args_base64`), and then, on the way out, by the ordinary scalar rules applied to the OUTER call.
Both layers are deliberate. What the outer call looks like to the second layer:

| field | value on the fund lane |
|---|---|
| type | `call` — a `w_execute_extension` is a call, whatever the payment inside it is |
| destination | the wallet's **bound account** — the door the call goes through, not a payee |
| token | `native` — a call is denominated in NEAR, whatever token its effects move |

So a policy governing a bound wallet must **also**:

- list `call` in `transaction_types`, or the lane is refused with `Transaction type 'call' is not
  allowed by policy` — a policy of `["transfer"]` describes exactly what the owner wants and
  refuses the only route that does it;
- list the **bound account itself** in `addresses.list` (or use `mode: "none"`), or every call
  through the lane is refused with `Address '<bound account>' is not in whitelist` — naming an
  account the owner never listed as a destination;
- include `native` (or `"*"`) in `allowed_tokens`, or every native transfer through the lane is
  refused with `Token 'native' is not allowed by policy`, even when what actually moves is a token
  the list does allow.

Each of those three refusals names which of them it is, and says that the account or word it
quotes belongs to the door rather than to the payment.

The outer deposit is **not** exempt from the native limits: the caller chooses it, and whatever is
attached is metered as native spend (less the 1-yoctoNEAR `assert_one_yocto` marker, which proves
key ownership rather than paying anyone). A lane call that attaches real NEAR is measured for it,
on top of the decoded effects inside.

Narrowing `allowed_tokens` to a single fungible token therefore switches off native spending on the
lane. That is the rule working as written, not a defect — but it is not what the policy looks like
it says.

### Roles

| Role | Approve transactions | Modify policy | Freeze wallet |
|------|---------------------|---------------|---------------|
| admin | Yes | Yes (quorum) | Yes |
| signer | Yes | No | No |

### Limits — `"*"` = wildcard for all tokens

- `per_transaction` — max amount per single tx (STATELESS, enforced in the TEE on every signature)
- `hourly` / `daily` / `monthly` — velocity limits (STATEFUL — checked against the coordinator-supplied `usage`; best-effort under concurrency)
- `rate_limit.max_per_hour` — max number of transactions per hour (STATEFUL)

### Capabilities — default-DENY opt-ins for the non-Built primitives

All capabilities default to **DENY** under a policy except `sign_message` (default-allow).
Under a policy a wallet must explicitly enable each of the rest (a wallet with **no policy** is
unrestricted):

- `raw_sign` — sign arbitrary raw bytes. `chains` is an optional allowlist (absent = all chains
  **including `near`**, which can sign a NEAR tx/intent outside the structured policy — by design;
  warn before enabling). With no on-chain policy at all, raw is permitted (permissionless start).
- `evm_sign` — sign EVM payloads (EIP-712 typed data, EIP-191 `personal_sign`, raw EVM tx).
  **DEFAULT-DENY** under a policy, like the other fund-moving capabilities — set
  `evm_sign.allowed: true` to permit (the dashboard writes this when its EVM-signing box is
  checked). Carries a `raw_tx` sub-flag that is **DEFAULT-OFF**: with `allowed:true`, typed-data
  and message signing work, but signing a raw EVM transaction additionally requires `raw_tx: true`.
  `requires_approval` is **NOT supported** for `evm_sign`. CAVEAT (why it's opt-in): an EIP-712
  signature is itself fund-moving (EIP-3009 ≈ transfer, EIP-2612 ≈ approve), so `evm_sign` grants
  full authority over the EVM address's float — bounded to what is bridged onto that address; the
  NEAR-intents balance is never exposed through it.
- `solana_sign` — sign Solana payloads (off-chain messages, serialized transaction messages). Same
  model as `evm_sign`: **DEFAULT-DENY** under a policy, `raw_tx` sub-flag **DEFAULT-OFF** gating
  transaction signing, `requires_approval` NOT supported. The message endpoint signs raw bytes
  (nacl/SIWS-verifiable) but **rejects** bytes that parse as a valid Solana transaction message —
  Solana has no EIP-191-style prefix, so without this guard a "message" could be a broadcastable
  transaction bypassing `raw_tx` (same protection Phantom/Solflare apply). A signed transaction
  message is fund-moving: `solana_sign` + `raw_tx` grants full authority over the Solana address's
  float; the NEAR-intents balance is never exposed through it.
- `confidential` — the confidential-intents flows (Trusted).
- `sign_message` — generic non-fund NEP-413 (e.g. dApp login). `allowed_recipients` is a
  default-DENY allowlist of verifier recipients (NOT a blocklist); `intents.near`/`intents.far`
  are always excluded. This is NOT OutLayer auth (that is `/wallet/v1/auth-sign`).
- `swap` — 1Click swap (Trusted). Default-DENY even when `transaction_types` is absent.
- `cross_chain_withdraw` — 1Click swap+bridge exit (Trusted, irreversible). Default-DENY; pairs
  with the `cross_chain_withdraw` type + the `to` whitelist + amount limit.
- `limit_order` — a swap rested on 1Click at the owner's price (Trusted). Default-DENY; pairs with
  the `limit_order` type + the `to` whitelist + amount limit, exactly like `cross_chain_withdraw`,
  because an order priced through the market fills at once and is then simply an exit to its `recipient`.
  The op binds `token_out` + `min_amount_out`, so multisig approvers sign the order's terms.
- `payment_check` — claimable-link escrow (Trusted, whitelist-BYPASS: funds reach an arbitrary
  holder via the link). Default-DENY; gated by this capability + the per-transaction amount cap.

Each capability also honors `requires_approval` (opt-in multisig for that primitive specifically).
`approval.threshold` is either a bare number or `{ "required": N }`; `approval.approvers[].id` is a
NEAR account id (with the on-chain `pubkey` pinned); `approval.excluded_types` lists op types exempt
from the generic approval trigger.

---

## API Endpoints

Base: `https://api.outlayer.ai` (mainnet) · `https://testnet-api.outlayer.ai` (testnet)

> **NEAR Intents are mainnet-only.** There are no testnet Intents solvers, so on testnet the
> coordinator returns **HTTP 503** for every intents-dependent endpoint — the whole
> `/wallet/v1/intents/*` family (deposit, withdraw, swap, cross-chain deposit, payment-check) **and**
> all `/wallet/v1/confidential/*` routes. The non-intents surface (address, balance, `transfer`,
> `call`, `sign-message`, `auth-sign`, the `/wallet/v1/evm/*` signers — pure crypto, no intents —
> policy, approvals, delete) works on both networks.

### Public

| Method | Path | Description |
|--------|------|-------------|
| POST | `/register` | Create wallet, returns API key (one-time) |

### Authenticated (Bearer API key)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/wallet/v1/address?chain={chain}` | Derive address — `near` + all EVM chains (one shared secp256k1 `0x` address) + `solana` (base58 ed25519); `bitcoin` gated |
| POST | `/wallet/v1/intents/withdraw` | Withdraw / cross-chain transfer |
| POST | `/wallet/v1/intents/withdraw/dry-run` | Simulate withdrawal (policy + balance check) |
| POST | `/wallet/v1/call` | Native NEAR contract call |
| POST | `/wallet/v1/transfer` | Chain-agnostic transfer (`chain` param, currently near) |
| GET | `/wallet/v1/balance?chain={chain}&token={token}` | Chain-agnostic balance (defaults to near) |
| POST | `/wallet/v1/intents/deposit` | Deposit FT into intents.near (for manual intents operations) |
| POST | `/wallet/v1/intents/swap` | Swap via 1Click: quote → deposit to intents.near → mt_transfer → poll |
| POST | `/wallet/v1/intents/deposit/cross-chain` | Cross-chain deposit (via 1Click / NEAR Intents; `source_asset` or `chain`+`token` shape). Legacy alias `/wallet/v1/deposit-intent`, still works |
| GET | `/wallet/v1/intents/deposit/cross-chain/status?id={intent_id}` | Poll a cross-chain deposit's status. Legacy alias `/wallet/v1/deposit-status`, still works |
| GET | `/wallet/v1/intents/deposit/cross-chain/list` | List this wallet's cross-chain deposits. Legacy alias `/wallet/v1/deposits`, still works |
| POST | `/wallet/v1/confidential/shield` | SHIELD: public intents → confidential shard (503 if not enabled). Legacy alias `/wallet/v1/confidential/deposit`, still works |
| POST | `/wallet/v1/confidential/unshield` | Confidential → public intents |
| POST | `/wallet/v1/confidential/withdraw` | Confidential → external chain (or `chain="near"` for **native NEAR** delivery via `intents.near native_withdraw`) |
| POST | `/wallet/v1/confidential/withdraw/dry-run` | Quote a confidential withdraw |
| POST | `/wallet/v1/confidential/transfer` | Private confidential → confidential transfer |
| POST | `/wallet/v1/confidential/swap` | Confidential swap (distinct assets) |
| POST | `/wallet/v1/confidential/swap/quote` | Quote a confidential swap |
| POST | `/wallet/v1/confidential/deposit/cross-chain` | Cross-chain deposit into confidential (via 1Click / NEAR Intents). Legacy alias `/wallet/v1/confidential/deposit-intent`, still works |
| GET | `/wallet/v1/confidential/balance` | Read confidential balances (private shard `intents.far`, no public RPC) |
| GET | `/wallet/v1/requests/{id}` | Poll async operation status |
| GET | `/wallet/v1/requests` | List operations (filter: type, status, limit) |
| GET | `/wallet/v1/tokens` | List available tokens (Intents proxy) |
| POST | `/wallet/v1/sign-message` | Generic NEP-413 message signing (recipient default-DENY allowlist; `intents.*` excluded). `format:"raw"` is **gone** — use `/auth-sign` |
| POST | `/wallet/v1/evm/sign-typed-data` | Sign EIP-712 typed data (v4). 65-byte `0x r‖s‖v` sig, `v∈{27,28}`, low-s. Gated by `evm_sign` capability |
| POST | `/wallet/v1/evm/sign-message` | Sign EIP-191 `personal_sign` (this is **different** from the NEP-413 `/wallet/v1/sign-message` above). Gated by `evm_sign` |
| POST | `/wallet/v1/evm/sign-transaction` | Sign a raw EVM tx — **client serializes the unsigned tx**, keystore keccak256-hashes + signs (no assembly/nonce/gas/broadcast; `yParity = v − 27` for EIP-1559). Gated by `evm_sign` + the `raw_tx` sub-flag |
| POST | `/wallet/v1/solana/sign-message` | Sign raw Solana message bytes (ed25519, base58 sig; `encoding: utf8\|hex\|base64`). Rejects bytes that parse as a valid tx message. Gated by `solana_sign` capability |
| POST | `/wallet/v1/solana/sign-transaction` | Sign a Solana tx **message** — **client serializes** (web3.js `tx.serializeMessage()`, base64, ≤1232 bytes), keystore ed25519-signs the bytes as-is (no assembly/blockhash/broadcast). Gated by `solana_sign` + the `raw_tx` sub-flag |
| POST | `/wallet/v1/auth-sign` | OutLayer NEAR-key auth signature (`{purpose: bearer\|register\|api-key, seed, vault_id?}` → `{auth_message, auth_timestamp, signature, public_key}`). Replaces the old `sign-message format:"raw"` |
| GET | `/wallet/v1/policy` | View current policy (decrypted via keystore). `policy: none` — no policy stored, every operation allowed; `policy: stored` — the returned sections are the policy as written |
| POST | `/wallet/v1/encrypt-policy` | Encrypt policy for on-chain storage |
| POST | `/wallet/v1/sign-policy` | Keystore signs the policy message (domain + blob + `caller`) for `store_wallet_policy` |
| POST | `/wallet/v1/invalidate-cache` | Clear negative policy cache |
| GET | `/wallet/v1/pending_approvals` | List pending multisig approvals |
| POST | `/wallet/v1/approve/{id}` | Submit multisig approval signature |
| POST | `/wallet/v1/reject/{id}` | Reject pending approval |
| GET | `/wallet/v1/audit` | Full event history |

### Internal (worker network only)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/internal/wallet-check` | Policy check for WASI execution |
| POST | `/internal/wallet-audit` | Record audit event from WASI |

---

## Limit Orders

A swap rested on 1Click (`/v0/orders`) at a price the owner sets, funded from the wallet's intents
balance. It waits until it fills — partially or fully — is cancelled, or reaches its deadline
(7 days unless set). Mainnet only. Full design: `docs/LIMIT_ORDERS.md` in the coordinator repo.

| Method | Path | Description |
|--------|------|-------------|
| POST | `/wallet/v1/limit-orders` | Rest an order (`base_asset`, `quote_asset`, `side`, `quantity`, `price`, optional `recipient` / `recipient_type` (`intents` · `confidential_intents` · `destination_chain`) / `deadline` — 1Click's own parameters) |
| GET | `/wallet/v1/limit-orders` | The wallet's orders as last recorded, newest first (`?open=true` → not recorded as finished; `limit` 1..100, default 50 — more is refused, not trimmed; `offset`). Never asks 1Click; the live state is the per-order read |
| GET | `/wallet/v1/limit-orders/{order_id}` | One order — 1Click's order in snake_case with lower-case values, nothing renamed; 404 for another wallet's |
| POST | `/wallet/v1/limit-orders/{order_id}/cancel` | Cancel one. Never policy-gated; works on a frozen wallet |
| POST | `/wallet/v1/limit-orders/cancel-all` | Ask 1Click to cancel every unfinished limit order of THIS wallet (only those placed here; other venues are untouched). Filled output is still paid out, the remainder refunded to the intents balance. At most 50 orders per call, oldest first (`?offset=n` steps over a batch that keeps failing; `?limit=1..50` — after about a minute of a slow 1Click the call answers 503 with what was accepted, and the caller lowers it). Answers `{known, cancelled, failed, remaining, complete}`; `complete: false` → some are still resting, call again. Asynchronous. Never policy-gated; works on a frozen wallet with the same key |

**The property that shapes it.** Every other exit is signed at the moment it moves money. A
resting order is authorised ONCE and pays out later — possibly days later — with no further
signature. So it is gated as the exit it can become (`Op::LimitOrder`: default-DENY capability,
its own transaction type, the whitelist on `recipient`, the amount limit), and a freeze does not reach
it: the owner cancels what is resting (see [Freeze](#freeze-emergency)). The whitelist covers the default recipient too: an
order paying out to the wallet's own intents account needs that account on the list. The op carries the
recipient type (`to_type`), which approvers sign over; `confidential_intents` additionally needs the
`confidential` capability. An intents balance short of the order's input answers `insufficient_balance`
before anything is created at 1Click.

**Create, in order.** (1) The terms — what the wallet sends at most, what it must receive at
least — are computed by the coordinator from the request and the assets' catalog decimals.
(2) The keystore decides on those terms; a multisig wallet parks here until approvers sign them.
(3) The order is created at 1Click, unfunded — this moves nothing. (4) 1Click's own figures are
held to the authorised terms: it may ask for less and promise more, never the reverse; otherwise
the order is cancelled and nothing is funded. (5) The wallet funds the order with the same
keystore-signed intents transfer a cross-chain withdraw uses, for 1Click's amount.

**Ownership.** 1Click's order list is scoped to our partner key and cannot be filtered by account,
so the coordinator's `limit_orders` table is the only index from a wallet to its orders. The cancel
sweep also pages 1Click's working orders and adopts any whose **refund account** is this wallet's —
the refund side, because the output may be paid to an external address while the remainder always
comes home to whoever funded the order.

**The answer is 1Click's order, whole.** Every attribute of its `LimitOrderAttributes`
(`https://1click.chaindefuser.com/docs/v0/openapi.yaml`) in snake_case with lower-case enumerated
values — `fill_status`, `payout_status`, `is_payout_status_final`, `payouts`, `partial_fills` (the
fills so far on a `partially_filled` order), `deposited_amount`, `swap_view`, `app_fees`,
`estimated_withdraw_fee` / `estimated_refund_fee`, `order_type`, `deposit_mode`, `deposit_type`,
`confidentiality`, `time_in_force`, … — plus the two fields that are ours: `transfer_intent_hash` and,
on create, `request_id`. `payouts`, `partial_fills` and `app_fees` are passed through verbatim.

**HTTP only, on purpose.** No `wallet.wit` host function and no CLI command, the same as payment
checks: every surface that can rest an order is attack surface, and they are added when a user asks.

**Not ours to set.** 1Click applies its own app fee to the input (reported back as `app_fees`, basis
points) and a 0.1 USD minimum order value. `is_payout_status_final` is the only terminal signal: a
`fill_status` of `canceled` or `filled` alone is not, and `pending_cancel` may still fill a last slice.

---

## Confidential Intents

> **Building an agent?** See the integration guide
> [`CONFIDENTIAL_INTENTS.md`](https://github.com/out-layer/coordinator/blob/main/docs/CONFIDENTIAL_INTENTS.md)
> in the coordinator repo — it covers the mental model (private on-chain shard,
> same-wallet identity, what privacy you actually get) + all methods, written
> for agent developers. This section is the operator/architecture summary.

The `/wallet/v1/confidential/*` routes mirror `/wallet/v1/intents/*` but operate
on the Defuse **confidential** shard — a separate PRIVATE shard (the
`intents.far` contract), distinct from public `intents.near`. Disabled by default —
gated by `ENABLE_CONFIDENTIAL_INTENTS` plus a **separate** Defuse partner
agreement (`ONECLICK_CONFIDENTIAL_BASE_URL` + `ONECLICK_CONFIDENTIAL_JWT`, which
**must differ** from the public `ONECLICK_JWT`). When unconfigured, every
confidential route returns **HTTP 503** `service_unavailable`.

Pipeline per op: NEP-413 challenge → per-account JWT (cached in Redis
`wallet:{id}:cfjwt`, 14 min) → 1Click quote → generate-intent → sign via
keystore → submit-intent. Ops are async; status is refreshed on read of
`GET /wallet/v1/requests/{id}` until terminal.

**Privacy** (must be disclosed to users):

- Confidential balances are **real on-chain state** on the private `intents.far`
  shard — not off-chain, not a solver database. The privacy is that this shard
  has **no public RPC**: you cannot read it (verified — `intents.far` resolves to
  `UNKNOWN_ACCOUNT` on public mainnet RPC). It is an auditable smart contract:
  the operator/Defuse, auditors, or law enforcement with a warrant CAN read it.
- Internal moves (confidential transfer/swap) leave **no public-chain trace** —
  they settle on the private shard. Only the edges touch the public chain.
- **SHIELD/UNSHIELD link the wallet on-chain** (entry/exit reveal); cross-chain
  DEPOSIT/WITHDRAW only expose the external-chain sender/receiver (public on that
  chain), not the confidential shard's internal moves.
- **Not hidden, ever**: the Defuse/1Click solver layer (sees plaintext intents),
  the `partner_id` mapping, and the source-chain identity.
- **Cross-chain DEPOSIT/WITHDRAW are still correlatable by timing and amount**:
  the source-chain deposit (at T) and destination-chain delivery (at T+N, e.g.
  0.5 in / 0.44 out after the 1Click solver fee) are both visible on their public
  chains and join trivially. True unlinkability needs jitter delays + amount
  splitting.

Each wallet has a single confidential identity (the custody wallet itself);
there is no separate or unlinkable confidential identity.

---

## Negative Policy Cache

Coordinator caches `wallet_id → NoPolicy` in-memory (HashMap, TTL 5 min). If no policy exists, subsequent requests skip the keystore call entirely (no limits to check). Cache cleared on:
- `POST /wallet/v1/invalidate-cache` (dashboard calls after on-chain tx)
- TTL expiry (5 min)

If policy exists → keystore always reads fresh from chain (never cached).

---

## Error Codes

| Error | Meaning |
|-------|---------|
| `missing_auth` | No Authorization header |
| `invalid_api_key` | Key not found or revoked |
| `policy_denied` | Operation blocked by policy rules |
| `wallet_frozen` | Wallet frozen by controller |
| `insufficient_balance` | Not enough funds |
| `pending_approval` | Needs multisig (not an error — returns approval_id) |
| `rate_limited` | Too many requests |
| `invalid_address` | Bad destination address |
| `unsupported_token` | Token not supported |

### Which HTTP status a failure gets

The status is a decision about **what the caller should do next**, not about how
sorry we are. Three questions, in order:

1. **Did anything happen?**
   * Nothing happened and the same request would work later — a view call that
     could not reach the node, a database read that failed, a keystore that is
     not ready, an event that has not been delivered yet — is **503** with
     `Retry-After`. Codes: `chain_unavailable`, `keystore_error`,
     `confidential_jwt_expired` on `/wallet/v1/*`, and `upstream_unavailable`
     on `/call`.
   * A feature this deployment does not offer — confidential intents with the
     flag off, binding events with no webhook secret, intents on a network with
     no solvers — is **503** WITHOUT `Retry-After`, code `service_unavailable`.
     Same status, opposite instruction: there is no interval after which an
     unset environment variable becomes set, and telling a client to come back
     in five seconds is telling it to poll forever. The two shared one code
     once, and the header could then only ever be right for one of them.

     For the same reason `/call`'s transient answer is `upstream_unavailable`
     rather than `service_unavailable`: a client's retry rule is written once
     and applied to every door, so one code may carry only one instruction.
   * Something MAY have happened and we cannot tell — a broadcast that timed
     out, a write whose outcome we never read — is **500**, and the message must
     say the outcome is unknown and what a retry would DO. This is the one place
     an RPC failure keeps a 500, and it is enforced: `classify_rpc_error` is the
     only site allowed to answer `internal_error` for a NEAR RPC error, and a
     test reads the source to keep it that way. Every READ — a balance, a code
     hash, an access key, a nonce — is `chain_unavailable` instead. `broadcast_tx_commit`
     answering `TIMEOUT_ERROR` is the common case: it accepted the transaction
     and ran out of its own polling window, so the transaction is usually on
     chain. Calling that 503 invites the retry that spends twice.
   * It happened and it failed on chain is **422** with the tx hash, never a 5xx.
2. **Is it the caller's to fix?** Then 4xx, naming the field or the rule. A
   refusal the caller cannot act on is worse than no explanation.
3. **Is it OUR deployment being wrong** — a contract that is not there, a method
   the deployed contract does not have, a variable that should have been set for
   the path the caller legitimately reached? **500.** Not 400: telling a customer
   to fix their request when they cannot is a wall with no door. Not 503 either:
   "come back later" is false, because nothing improves without an operator, and
   the client cannot tell a broken deployment from a busy one. 500 is what routes
   to ops alerts.

   The line between this and the `service_unavailable` above is whether the
   absence is a CHOICE. A deployment that deliberately does not offer
   confidential intents is answering correctly and says so; a deployment missing
   `KEYSTORE_DAO_ACCOUNT_ID` while a customer uses vault scope is broken, and the
   customer must not be told to come back for it.

**Never 502 or 504.** Cloudflare replaces origin 502/504 with its own HTML page
and the JSON body — the code the client branches on — never arrives. 503 passes
through, and so does every 4xx.

The distinction that keeps being re-derived: a **read** that failed changed
nothing (503), a **write** that failed may have landed (500 + a sentence). Which
is why "every database error is transient" is wrong in a codebase with more
writes than reads.

---

## Per-customer Vaults (sovereignty option)

By default, every wallet's keys are derived from the **OutLayer
default master** (HMAC-SHA256 chain rooted in the keystore-worker's
TEE secret). Convenient and recovery-free, but if OutLayer ceases,
the derived keys are gone with it.

A **per-customer vault** replaces that shared master with a
per-customer master derived via NEAR's MPC network from a
sub-account the customer controls. The wallet's API key is bound
to the vault at registration time; subsequent wallet operations
forward `X-Customer-Vault: <vault_id>` to the keystore, which
routes derivations through the per-vault master.

### Wallet creation flow with vault scope

```
Customer → outlayer vault init  (or dashboard /vault page)
    Atomic NEAR tx (5 actions, all-or-nothing):
        CreateAccount(vault.<customer.near>)
        Transfer(0.1 NEAR)               // storage stake + MPC-call gas reserve
        UseGlobalContract(approved_code_hash)
        FunctionCall("new", {parent, keystore_dao, mpc_contract, exit_window})
        AddKey(tee_pubkey, FCAK on vault.request_master)
    POST /customer/sign-verification → keystore re-verifies + signs
                                       mark_vault_verified on chain
    POST /customer/register {vault_id, webhook_url?}
    Coordinator:
        1. View-call keystore_dao.is_vault_verified(vault_id) — must be true
        2. INSERT wallet_accounts (wallet_id, vault_id, vault_webhook_url)
        3. INSERT wallet_api_keys (key_hash, customer_account_id=vault_id)
        4. POST /wallet/derive-address  (with X-Customer-Vault header)
    Keystore TEE:
        5. Lazy-load: ensure_customer_loaded(vault_id) drives MPC CKD
           with derivation_path = HMAC(default_master, "vault-master:{vault_id}")
        6. Cache per-vault master in masters: HashMap<AccountId, [u8;32]>
        7. HMAC(per_vault_master, "wallet:{wallet_id}:near") → keypair
        8. Return { address, public_key }
    Coordinator:
        9. Save derived public_key on the wallet row
       10. Commit transaction; return API key + fire vault_registered webhook
```

The customer's API key is now permanently bound to the vault. Every
wallet operation uses the per-vault master; on cessation or
unilateral exit, the customer recovers control of the vault account
and the per-vault master remains derivable by any post-recovery
DAO-approved TEE worker (deterministic — same `(default_master,
vault_id)` → same `secret_path` → same MPC-derived master).

### Recovery flow (cessation path)

```
DAO members → keystore_dao.declare_cessation()      [is_ceased() = true]

Anyone      → vault.initiate_recovery()
                  → cross-contract is_ceased() check
                  → recovery = {trigger: Cessation,
                                finalize_after: now+7d,
                                finalize_before: now+14d}

(7-day delay)

Anyone      → vault.finalize_recovery()
                  → cross-contract is_ceased() check (still true?)
                  → unlocked = true
                  → recovery = None

Parent      → vault.unlocked_add_key(parent_pubkey, full_access: true)
              [parent now controls the sub-account; can withdraw funds
               and migrate to a new custody provider]
```

### Recovery flow (unilateral path)

```
Parent → vault.set_exit_window(86400)            [optional, 24h-30d range]
Parent → vault.unilateral_initiate_recovery()
            → recovery = {trigger: Unilateral,
                          finalize_after: now + window_secs}

(configured delay — default 24h)

Anyone → vault.finalize_recovery()                [no DAO check]
            → unlocked = true

Parent → vault.unlocked_add_key(...)
```

For the architectural reference (two-layer key derivation, race-attack
mitigation, governance fixes), see [VAULTS.md](VAULTS.md). For the
customer-facing how-to, see `dashboard/app/docs/vaults/page.tsx`.

---

## Security Model

1. **MPC master secret** — obtained from NEAR Protocol MPC network via DAO-governed process. Lives only inside TEE. Individual wallet keys derived deterministically via HMAC-SHA256.

2. **TEE isolation** — Intel TDX enclaves. Key derivation, signing, policy evaluation all inside TEE. Even infrastructure operator cannot extract keys or bypass policy.

3. **Policy on-chain** — encrypted, stored in NEAR contract `LookupMap`. Only TEE can decrypt. Controller can freeze wallet directly on-chain without going through API.

4. **API key security** — only SHA-256 hash stored in DB. Plaintext shown once at registration. Key prefix `wk_` for identification.

5. **Velocity limits** — tracked in coordinator DB (`wallet_usage` table). Usage recorded BEFORE execution (prevents bypass via intentional failures). Per-tx limits checked in TEE (not bypassable even if DB is compromised).

6. **Agent compromise recovery** — freeze wallet (instant, on-chain) → revoke API key → create new key. Private key never exposed — nothing to rotate.
