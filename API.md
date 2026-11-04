# OutLayer API

The OutLayer HTTP API is served by the **coordinator** — the task queue and
gateway that fronts the TEE workers, contracts, and keystore. It exposes the
Agent Custody wallet and the verifiable compute layer — connectors and arbitrary
WASI modules — over plain HTTPS.

## Base URLs (Networks)

| Network | Base URL | Contract |
|---------|----------|----------|
| Mainnet | `https://api.outlayer.ai` | `outlayer.near` |
| Testnet | `https://testnet-api.outlayer.ai` | `outlayer.testnet` |

The paths below are identical on both networks — only the host differs. Pick the
base URL that matches the network your project / wallet is deployed on. The
dashboard host `app.outlayer.ai` serves no API.

> **NEAR Intents is mainnet-only.** Testnet does not run the Intents solver
> network, so the intents-dependent Agent Custody endpoints are **not available
> on testnet**: every `/wallet/v1/intents/*` route, cross-chain gasless
> withdrawals, and all `/wallet/v1/confidential/*` routes. Test those against
> the **mainnet** API only. The rest of the wallet API (address, balance,
> transfer, `call`, `sign-message`, policy, approval) works on both networks.

- **Interactive reference (Scalar UI)**: `https://api.outlayer.ai/docs`
- **OpenAPI 3.1 spec**: `https://api.outlayer.ai/openapi.json` — source of truth at [out-layer/api-spec](https://github.com/out-layer/api-spec); request and response schemas live there
- **TypeScript SDK**: [`@outlayer/sdk`](https://www.npmjs.com/package/@outlayer/sdk) ([source](https://github.com/out-layer/sdk-js))

## Authentication

| Header | Used by | Meaning |
|--------|---------|---------|
| `X-Payment-Key: owner:nonce:secret` | `/call`, `/calls/{id}`, `/payment-keys/balance`, `/subscription/*` | A payment key: a funded key, a subscription, or the wallet's trial key |
| `Authorization: Bearer wk_...` or `Bearer near:...` | All wallet endpoints, `POST /trial-key`, `GET /calls/{id}` | Wallet API key, or a deterministic wallet's NEAR signature. It runs the wallet and does not pay: on `/call` alone it is refused as `401 wk_is_not_a_payer` |
| `X-Wallet-Id` | `/call` to a connector that acts on the wallet | The paying key's own wallet (`wallet_id` from `GET /wallet/v1/address`); without it the run has no wallet |
| _(none)_ | `/register`, public read endpoints | No auth |

> Only `X-Payment-Key` or `Authorization: Bearer wk_...` / `near:...` are
> accepted for authenticated calls. There is no `X-API-Key` header.

## Execution API

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/call/{owner}/{project}` | `X-Payment-Key` | Execute a project's WASI module. Body: `{"input": …, "secrets_ref"?, "secrets_refs"?, "async"?, "version_key"?, "resource_limits"?}`. `secrets_refs` names several secret rows in order (at most 5; not with `secrets_ref`; the project's manifest must say `"secrets_refs": true`): each opens for the caller as one does, their variables join (a name set differently by two rows refuses the run), and a task may be opened for the owner of any of them; refused on a connector that reads the wallet owner's policy row (Polymarket, Hyperliquid), which no other row joins. Sync by default; `"async": true` returns a `call_id` |
| GET | `/calls/{call_id}` | `X-Payment-Key` of the calling key, or `Bearer wk_` of the wallet that owns it | Poll a `pending` call: an async one, or a sync one the API restarted during |
| GET | `/payment-keys/balance` | `X-Payment-Key` | The key's balance |
| GET | `/subscription/status` | `X-Payment-Key` | What a key has left — for a trial key, `trial.calls_left` |
| POST | `/subscription/purchase` | `X-Payment-Key` | Turn balance already on the key into subscription allowance |
| PUT | `/subscription/notifications` | `X-Payment-Key` | Where to warn the owner about allowance and expiry |
| POST | `/trial-key` | `Bearer wk_...` / `near:...` | Claim the wallet's trial key: an allowance for connector calls only, with an expiry; the key is derived and can be read again below |
| GET | `/wallet/v1/payment-key` | `Bearer wk_...` / `near:...` | The wallet's nonce-0 key (trial or sponsored), derived again; only the credential that claimed it reads it |
| POST | `/wallet/v1/sponsorship` | `Bearer wk_...` / `near:...` | Redeem a sponsor code (`spn_…`): a subscription, paid by the sponsor, on the nonce-0 key |

Optional execution headers: `X-Compute-Limit` (max compute budget in
stablecoin minimal units), `X-Attached-Deposit` (payment forwarded to the
project author, read by the WASM via the `USD_PAYMENT` env var; never honoured
for a trial or other granted key).

## Agent Custody Wallet API

Per-agent wallets whose keys are derived inside the keystore TEE from a master
secret issued by the NEAR MPC network. All endpoints except `/register` require
`Authorization: Bearer wk_...` (or `Bearer near:...`).

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/register` | Register a wallet, get API key and the trial offer (no auth) |
| GET | `/wallet/v1/balance` | Balance (NEAR or FT), per chain |
| GET | `/wallet/v1/address` | Address for any supported chain |
| GET | `/wallet/v1/tokens` | List supported tokens |
| POST | `/wallet/v1/transfer` | Transfer NEAR / FT |
| POST | `/wallet/v1/call` | Call a NEAR smart contract |
| POST | `/wallet/v1/sign-message` | NEP-413 message signing |
| POST | `/wallet/v1/auth-sign` | OutLayer NEAR-key auth signature (`{purpose, seed, vault_id?}`) |
| POST | `/wallet/v1/evm/sign-message` · `/evm/sign-transaction` · `/evm/sign-typed-data` | EVM signing |
| POST | `/wallet/v1/solana/sign-message` · `/solana/sign-transaction` | Solana signing |
| POST | `/wallet/v1/intents/deposit` | Deposit FT into Intents balance · **mainnet only** |
| POST | `/wallet/v1/intents/withdraw` | Withdrawal — same-chain (native NEAR / NEP-141) or cross-chain (gasless); `/dry-run` available · **mainnet only** |
| POST | `/wallet/v1/intents/transfer` | Transfer inside Intents · **mainnet only** |
| POST | `/wallet/v1/intents/swap` | Swap tokens via Intents; `/swap/quote` for a quote · **mainnet only** |
| POST | `/wallet/v1/intents/deposit/cross-chain` | Cross-chain deposit via 1Click (alias `/wallet/v1/deposit-intent`); `/cross-chain/status` + `/cross-chain/list` available · **mainnet only** |
| POST/GET | `/wallet/v1/limit-orders` | Create / list limit orders (via 1Click); `/{id}`, `/{id}/cancel`, `/cancel-all` |
| POST | `/wallet/v1/create-payment-key` | A key with money on it — no call limit (USDC or NEAR deposit) |
| GET | `/wallet/v1/policy` | The wallet's policy |
| POST | `/wallet/v1/sign-policy` · `/encrypt-policy` | Prepare a policy for storing on chain (spend limits, allowlists) |
| GET/POST | `/wallet/v1/approval/{id}` · `/approve/{id}` · `/reject/{id}` · `/pending_approvals` | Multisig approval flow |
| PUT/DELETE | `/wallet/v1/api-key` · `/api-key/{key_hash}` | Register a delegate `wk_` key (for a sub-agent wallet by seed, or for a deterministic wallet by NEAR signature) / revoke one |
| GET | `/wallet/v1/requests` · `/requests/{id}` | Request list / status |
| GET | `/wallet/v1/audit` | Audit log |
| POST | `/wallet/v1/delete` | Delete wallet |

### Confidential Intents (private balances)

**Mainnet only** — built on NEAR Intents, so unavailable on the testnet API.

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/wallet/v1/confidential/shield` | Shield funds into the private shard (alias `/wallet/v1/confidential/deposit`) |
| GET | `/wallet/v1/confidential/balance` | Private balance |
| POST | `/wallet/v1/confidential/transfer` | Private transfer |
| POST | `/wallet/v1/confidential/swap` | Private swap; `/swap/quote` for a quote |
| POST | `/wallet/v1/confidential/withdraw` | Withdraw (incl. native NEAR); `/dry-run` available |
| POST | `/wallet/v1/confidential/unshield` | Move back to public balance |
| POST | `/wallet/v1/confidential/deposit/cross-chain` | Cross-chain deposit into the confidential shard, quote-only: returns a deposit address (alias `/wallet/v1/confidential/deposit-intent`) |

### Payment Checks (gasless agent-to-agent payments)

`/wallet/v1/payment-check/{create,batch-create,claim,reclaim,peek,status,list}`
— see [docs/PAYMENT_CHECKS.md](docs/PAYMENT_CHECKS.md).

## Public (read-only, no auth)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/public/pricing` | Current pricing |
| GET | `/public/stats` · `/public/workers` | Network stats / live workers |
| GET | `/public/connectors` · `/public/connectors/{id}/describe` | Connector catalogue / one connector's operations |
| GET / POST | `/public/storage/get` · `/public/storage/batch` | Read public (unencrypted) project storage |
| GET | `/public/payment-keys/{owner}/{nonce}/balance` · `/usage` | Payment key balance / usage |
| GET | `/public/project-earnings/{owner}` · `/public/users/{account}/earnings` | Earnings (read) |
| GET | `/attestations/by-call/{call_id}` · `/by-tx/{tx_hash}` · `/by-request/{request_id}` | Attestation record of one execution |
| GET | `/public/collateral` | Intel TDX collateral for verifying an attestation |
| GET | `/vrf/pubkey` | VRF public key (for on-chain verification) |

## Source availability and trust

**The coordinator (this API) is closed source.** It is the task queue, WASM
cache, payment accounting and HTTPS gateway. It cannot read TEE memory, forge
an attestation, or produce an execution result that passes attestation without
a registered worker having computed it.

It is **not** a stateless proxy, and for agent custody it is a trusted
component:

- it authenticates wallet API keys (it stores only SHA-256 hashes of `wk_` keys);
- it keeps usage counters, pending approvals and a readable copy of wallet
  policies in PostgreSQL — cumulative (daily/hourly/monthly) limits are counted
  here, outside the enclave;
- for swaps, cross-chain withdrawals, confidential transfers, limit orders and
  payment checks it supplies the intents message the enclave signs.

The keystore TEE reads the wallet's policy from the chain before signing, and
enforces per-transaction limits, multisig and freeze inside the enclave. The
exact split, and the governance keys OutLayer holds at this stage, are in
[docs/NON_CUSTODIAL.md](docs/NON_CUSTODIAL.md).

**The components that run in or govern the TEE are open source:**

- **Workers** — execute WASI modules inside Intel TDX TEEs ([worker/](worker/))
- **Contracts** — `outlayer.near` and friends ([contract/](contract/),
  [register-contract/](register-contract/),
  [keystore-dao-contract/](keystore-dao-contract/), [vault-contract/](vault-contract/))
- **Keystore worker** — key derivation, signing and secrets decryption inside the TEE ([keystore-worker/](keystore-worker/))
- **Libraries / SDKs** — [sdk/outlayer/](sdk/outlayer/) (Rust, on crates.io as
  [`outlayer`](https://crates.io/crates/outlayer)),
  [`@outlayer/sdk`](https://github.com/out-layer/sdk-js) (TypeScript),
  [shared-tee-helpers](https://github.com/out-layer/shared-tee-helpers)
  (TEE challenge-response auth)

See [README.md](README.md#security-model) and
[WORKER_ATTESTATION.md](WORKER_ATTESTATION.md).
