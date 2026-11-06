# Payment Checks

Gasless agent-to-agent payments through ephemeral NEAR Intents accounts. Agent A locks tokens from its intents balance into a check and sends a single key to Agent B, who claims the funds into its own wallet — no gas, no on-chain account, no exchange of wallet keys. Supports partial claims, expiry, and reclaim.

Payment checks run on NEAR Intents, which is mainnet only: on testnet every endpoint answers 503. The website reference is https://app.outlayer.ai/docs/payment-checks.

## Why Payment Checks

| Problem | Payment Checks Solution |
|---------|------------------------|
| Direct transfers require NEAR for gas | Create, claim and reclaim are gasless — solver relay with off-chain NEP-413 signatures |
| Receiver needs an on-chain account with gas | Receiver needs only an OutLayer wallet credential |
| Direct transfers are irreversible | Sender can reclaim unclaimed funds at any time |
| No native partial payment support | Built-in partial claim and partial reclaim |
| Escrow requires smart contract development | A check acts as lightweight escrow — one API call |

## How It Works

```
Agent A (Sender)              Agent B (Receiver)
     |                              |
     |  1. POST /create             |
     |  ────────────────►           |
     |  ← check_key                 |
     |                              |
     |  2. Send check_key           |
     |  ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─►|
     |     (any channel)            |
     |                              |
     |                 3. POST /peek |
     |                 (verify)      |
     |                              |
     |                4. POST /claim |
     |                ◄─────────────|
     |                 funds move    |
     |                              |
     |  5. POST /reclaim (optional) |
     |  (get unclaimed funds back)  |
```

### Step-by-step

1. **Create** — Agent A calls `POST /wallet/v1/payment-check/create`. The tokens must already be in A's intents balance (`POST /wallet/v1/intents/deposit` or a cross-chain deposit). The keystore derives a unique ephemeral key, the wallet signs a transfer of the tokens from its intents balance to the ephemeral account, the coordinator publishes it to the solver relay, and the response carries the `check_key`.

2. **Share** — Agent A sends the `check_key` to Agent B over any channel (HTTP, message, QR code). The key is a 64-char hex string.

3. **Peek** (optional) — Agent B calls `POST /wallet/v1/payment-check/peek` with the key to read the check's balance, memo, status and expiry before claiming.

4. **Claim** — Agent B calls `POST /wallet/v1/payment-check/claim` with the key. The coordinator signs, with the `check_key`, a transfer intent from the ephemeral account to Agent B's intents balance and publishes it. Supports partial claims.

5. **Reclaim** (optional) — Agent A can reclaim unclaimed funds via `POST /wallet/v1/payment-check/reclaim`. The keystore derives the ephemeral key again, so A does not need to store it.

## Transfer Mechanism

Every leg is a NEAR Intents `transfer` intent: the coordinator gets a NEP-413 signature and submits it to the solver relay, which executes it on `intents.near`. Nothing pays gas.

| Operation | From → To | Who Signs | Gas |
|-----------|-----------|-----------|-----|
| Create | Sender's intents balance → ephemeral account | Sender's wallet key (keystore TEE) | None |
| Claim | Ephemeral account → claimer's intents balance | The `check_key`, used by the coordinator | None |
| Reclaim | Ephemeral account → sender's intents balance | The ephemeral key, derived again by the keystore and used by the coordinator | None |

### Ephemeral Accounts

Each check gets its own account on `intents.near`, derived from the wallet's master secret and a per-wallet counter. This gives each check an isolated balance that can be moved by whoever holds the `check_key`, or by the sender through a reclaim.

```
Key derivation (HMAC-SHA256 with the wallet's master, inside the keystore):
  wallet:{id}:near                        ← main wallet key (never exported)
  wallet:{id}:near:check:{counter}        ← ephemeral key per check

The check_key IS the raw ed25519 private key of the ephemeral account.
The ephemeral account ID = hex(public_key) on intents.near.
```

A wallet bound to a per-customer vault derives its check keys from the vault's master.

## Policy

Under a stored policy, creating a check needs `capabilities.payment_check.allowed = true` (default-DENY), and the check's token and amount are held to the policy's per-transaction limit. A check routes funds to whoever holds its key, so a recipient whitelist cannot gate it; the capability is the gate. A wallet with no policy can create checks freely.

A check moves money, so it is held to the wallet's approval rules like a transfer or a swap: `approval.threshold` applies, `approval.excluded_types: ["payment_check"]` lifts it, and `capabilities.payment_check.requires_approval` demands it on its own. On a wallet that requires approval the create reserves the check `pending_approval`, hands over its key (the account is fixed by the check's counter and holds nothing yet), and opens an approval over the check's token and amount; once the threshold is met the coordinator derives the key again, checks the account is the one reserved, and funds the check with the approvers' votes forwarded to the keystore, which verifies them before signing. A veto, an approval that expires unmet (24 hours), or the check's own `expires_at` passing while it waits, ends the check `failed` — an expired check is never funded. A claim or reclaim of a check still `pending_approval` is refused. `batch-create` on such a wallet is refused whole (`403 policy_denied`): one check, one approval.

Each create counts as one `custody:payment_check` operation against the wallet's ceiling (`429 operation_limit_reached`, nothing reserved); a claim or a reclaim is signed by the check's own key, goes through no policy, and is not counted.

The create message is supplied by the coordinator, not built by the enclave: see [Limits we state plainly](https://github.com/out-layer/outlayer/blob/main/docs/NON_CUSTODIAL.md#11-limits-we-state-plainly).

## API Reference

Base URL: `https://api.outlayer.ai/wallet/v1/payment-check`

Every endpoint takes a wallet credential: `Authorization: Bearer wk_...` or `Authorization: Bearer near:...`.

### Retries and timeouts

Send `X-Idempotency-Key` on create, batch-create, claim and reclaim, and `X-Answer-Within: <seconds>` below your own timeout. A call whose transfer is not confirmed in time answers with an in-flight status and a `poll_url`; poll it rather than repeating the call. A repeated call with the same idempotency key answers `duplicate_idempotency_key` naming the earlier request; for a create it carries `checks: [{check_id, check_key, status}]` with the key derived again (`check_key: null` when asked under a different vault scope than the create's).

### POST /create

Create a new payment check.

**Request:**
```json
{
  "token": "17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1",
  "amount": "1000000",
  "memo": "Payment for data analysis",
  "expires_in": 3600
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `token` | string | yes | Token contract ID (e.g., the USDC contract) |
| `amount` | string | yes | Amount in smallest units (e.g., "1000000" = 1 USDC), greater than 0 |
| `memo` | string | no | Optional memo (max 256 chars), visible to the receiver |
| `expires_in` | number | no | Expiry in seconds from now, at most ten years |

**Response:**
```json
{
  "check_id": "a1b2c3d4-...",
  "check_key": "7f3a9b2c...64 hex chars...",
  "status": "unclaimed",
  "token": "17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1",
  "amount": "1000000",
  "memo": "Payment for data analysis",
  "created_at": "2026-03-13T10:00:00Z",
  "expires_at": "2026-03-13T11:00:00Z"
}
```

`status` is `unclaimed` once the funding transfer has executed, or `creating` with a `poll_url` while it is unconfirmed. The `check_key` is in both answers: keep it, and do not create the check again. A `creating` check ends `unclaimed`, or `failed` if the funding never executed (nothing moved).

On a wallet whose policy requires approval, `status` is `pending_approval` with `approval_id`, `required`, `approved`, `request_hash` and a `poll_url`; the `check_key` is in that answer too. The check is funded once the approvers meet the threshold and then reads `unclaimed`; a veto or an unmet approval ends it `failed`.

### POST /batch-create

Create up to 10 checks in one call, each with its own key and ephemeral account.

**Request:**
```json
{
  "checks": [
    {"token": "170...a1", "amount": "1000000", "memo": "Task 1"},
    {"token": "170...a1", "amount": "2000000", "memo": "Task 2"}
  ]
}
```

**Response:**
```json
{
  "checks": [
    {"check_id": "...", "check_key": "...", "status": "unclaimed", "token": "...", "amount": "1000000", ...},
    {"check_id": "...", "check_key": "...", "status": "unclaimed", "token": "...", "amount": "2000000", ...}
  ]
}
```

If the batch stops before its last check, the response carries `error`: the checks listed were created, the rest were not. Each check is decided by the policy, and counted, before any is reserved; a wallet whose policy requires approval gets no batch (`403 policy_denied`).

### POST /claim

Claim funds from a check into the caller's wallet. Supports partial claims.

**Request:**
```json
{
  "check_key": "7f3a9b2c...64 hex chars...",
  "amount": "500000"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `check_key` | string | yes | The 64-char hex key from the sender |
| `amount` | string | no | Partial claim amount (omit to claim the whole balance) |

**Response:**
```json
{
  "request_id": "5e6f7a8b-...",
  "status": "partially_claimed",
  "token": "17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1",
  "amount_claimed": "500000",
  "remaining": "500000",
  "memo": "Payment for data analysis",
  "claimed_at": "2026-03-13T10:05:00Z",
  "intent_hash": "Bx7k..."
}
```

`status` is `claimed` / `partially_claimed`, or `processing` with a `poll_url` (and no `remaining` / `claimed_at`) while the transfer is unconfirmed. A claim is refused after the check's expiry, while the check is still awaiting its owner's approval or being funded, while another leg is in flight, and once it is fully claimed or reclaimed. Only checks created through OutLayer can be claimed.

### POST /reclaim

Reclaim unclaimed funds to the sender's wallet. Only the wallet that created the check can reclaim; expiry does not prevent it.

**Request:**
```json
{
  "check_id": "a1b2c3d4-...",
  "amount": "500000"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `check_id` | string | yes | The check ID from the create response |
| `amount` | string | no | Partial reclaim amount (omit to reclaim the whole balance) |

**Response:**
```json
{
  "request_id": "9c0d1e2f-...",
  "status": "reclaimed",
  "token": "17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1",
  "amount_reclaimed": "500000",
  "remaining": "0",
  "reclaimed_at": "2026-03-13T10:10:00Z",
  "intent_hash": "Cx9m..."
}
```

`status` is `reclaimed` / `partially_reclaimed`, or `processing` with a `poll_url`.

### GET /status?check_id=...

Current state of a check. Only the creating wallet can query it.

**Response:**
```json
{
  "check_id": "a1b2c3d4-...",
  "token": "17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1",
  "amount": "1000000",
  "claimed_amount": "500000",
  "reclaimed_amount": "500000",
  "status": "reclaimed",
  "memo": "Payment for data analysis",
  "created_at": "2026-03-13T10:00:00Z",
  "expires_at": "2026-03-13T11:00:00Z",
  "claimed_at": "2026-03-13T10:05:00Z",
  "claimed_by": "a2b3b5b5c72c..."
}
```

### GET /list?status=...&limit=50&offset=0

List the checks created by the authenticated wallet.

| Param | Required | Description |
|-------|----------|-------------|
| `status` | no | Filter: `pending_approval`, `creating`, `unclaimed`, `claiming`, `partially_claimed`, `claimed`, `reclaiming`, `partially_reclaimed`, `reclaimed`, `failed`, `expired` |
| `limit` | no | Max results (default 50, max 100) |
| `offset` | no | Pagination offset (default 0) |

### POST /peek

Read a check's balance using its `check_key`, to verify it before claiming. Any wallet credential can peek.

**Request:**
```json
{
  "check_key": "7f3a9b2c...64 hex chars..."
}
```

**Response:**
```json
{
  "token": "17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1",
  "balance": "1000000",
  "memo": "Payment for data analysis",
  "status": "unclaimed",
  "expires_at": "2026-03-13T11:00:00Z"
}
```

`balance` is read from `intents.near`.

## Check Lifecycle

```
                    create
                      |
         (approval    v
          threshold) [pending_approval] ---- vetoed / approval expired ---> [failed]
                      |  threshold met
                      v
                  [creating] ---- funding never executed ---> [failed]
                      |
                      v
                  [unclaimed]
                   /      \
          claim   /        \  reclaim
                 v          v
       [partially_claimed] [partially_reclaimed]
              |       \         /       |
       claim  |        \       /        | reclaim
              v         v     v         v
          [claimed]   (mixed)    [reclaimed]
```

**Statuses:**
- `pending_approval` — the wallet's approvers have not met the threshold; the account is empty
- `creating` — funding transfer not confirmed yet
- `unclaimed` — funds locked, waiting to be claimed
- `claiming` / `reclaiming` — a claim or reclaim is in flight; another waits for it
- `partially_claimed` — some funds claimed, rest available
- `partially_reclaimed` — some funds reclaimed by the sender
- `claimed` — the balance reached zero through a claim
- `reclaimed` — the balance reached zero through a reclaim
- `failed` — the funding never executed, was vetoed, or its approval expired unmet; nothing moved
- `expired` — reported for an `unclaimed` check past its expiry

**Expiry:** if `expires_in` is set, the check cannot be claimed after expiry. The funds stay in the ephemeral account until the sender reclaims them; expiry does not return them by itself.

## Security

| Threat | Mitigation |
|--------|------------|
| check_key intercepted in transit | Use encrypted channels (HTTPS, E2E messaging). A leaked key lets anyone with an OutLayer wallet claim the funds. |
| Sender's API key compromised | The API key can be revoked. Under a policy, checks need the `payment_check` capability, stay within the per-transaction limit, and on a wallet with an approval threshold wait for the approvers. |
| Replay of claim/reclaim | Each intent has a random nonce and a 5-minute deadline; `intents.near` rejects a reused nonce. Amounts are tracked under a row lock. |
| Ephemeral key collision | Per-wallet counter, incremented atomically in the database; a counter value is never reused. |
| Funds stuck in ephemeral account | The sender can always reclaim — the keystore derives the ephemeral key again from the same path. |

**Who sees the `check_key`:** it never goes on chain. It is returned by the keystore through the coordinator on create, and on claim the receiver sends it to the coordinator, which signs the claim with it outside the TEE. Because the keystore can derive any check's key for the coordinator, the coordinator is trusted with every open check's balance; see [NON_CUSTODIAL.md](https://github.com/out-layer/outlayer/blob/main/docs/NON_CUSTODIAL.md).

## Comparison

|  | Payment Checks | Direct Transfer | Smart Contract Escrow |
|--|----------------|-----------------|----------------------|
| Gas required | None (funds must be in the intents balance) | Sender pays | Both parties pay |
| Receiver needs account | Only an OutLayer wallet credential | On-chain account + gas | On-chain account + gas |
| Partial payment | Built-in | N/A | Custom logic |
| Reclaim | Built-in, gasless | N/A (irreversible) | Custom logic + gas |
| On-chain footprint | Intents executed by the solver relay | 1 transaction | Contract deployment + calls |
| Setup complexity | One API call | One API call | Contract dev + deployment |

## Use Cases

- **Agent-to-agent payments** — Agent A creates a check and sends the key with its API request. Agent B verifies it (peek), does the work, claims payment. If B does not deliver, A reclaims.
- **Bounties & task rewards** — Create a check with an expiry and share the key with the task completer. Partial claims allow splitting among contributors.
- **Escrow-style payments** — Lock funds in a check and share the key only when conditions are met.
- **Batch payouts** — `batch-create` makes up to 10 checks in one call, each with its own key.
