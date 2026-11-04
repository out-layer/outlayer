# Deterministic Wallets via NEAR Signature Auth

## Why this matters

OutLayer wallet keys are derived on demand inside an Intel TDX enclave (the keystore) from a master secret issued by the NEAR MPC network; they are never stored, and no endpoint exports them. At this stage OutLayer still holds governance keys that bear on that guarantee — see [Governance at this stage](https://github.com/out-layer/outlayer/blob/main/docs/NON_CUSTODIAL.md#governance-at-this-stage).

Deterministic wallets let one NEAR account own any number of wallets for its users without storing a credential per user. The wallet is identified by `(account_id, seed)`, and every request is authenticated by a fresh signature from that account's key.

## Problem

`POST /register` without a body creates a wallet with a random `wk_` API key. A client serving many users must store one `wk_` per user; a leak of that store is a leak of every wallet.

## Solution

Authenticate with a NEAR signature on every request. The coordinator stores no auth secret for these wallets: it checks the signature and that the signing key is a full-access key of the account. The client derives wallet access from its NEAR key + a seed — nothing to store per user.

Key revocation = remove the key from the NEAR account. It takes effect within 60 seconds (the coordinator's access-key cache).

## Use cases

**Web app with OAuth login.** The server holds one NEAR key. A user logs in via Google/GitHub; the server sets `seed = hex(SHA256(provider + ":" + user_id))` and the user has a wallet. No per-user key storage.

**Telegram/Discord bot.** The bot holds one NEAR key in env. For each user, `seed = hex(SHA256(telegram_user_id))`. No per-user DB.

**AI agent spawning sub-agents.** The parent derives a `wk_` key from (its key, seed, index), registers its hash via `PUT /wallet/v1/api-key`, and hands the key string to the sub-agent. The sub-agent uses a plain `Bearer wk_...` — no crypto, works with any HTTP client or LLM framework. The parent can re-derive the key at any time without storage.

All three share one pattern: **one NEAR account, many wallets, no stored per-user secrets, access control through NEAR keys.**

## What every wallet gets

A deterministic wallet is a wallet like any other; every `/wallet/v1/*` endpoint works the same way:

- **Addresses** — the NEAR implicit account, one `0x` address for every EVM chain, and a Solana address, all derived from the wallet (`GET /wallet/v1/address`). Other chains are reached through NEAR Intents.
- **Swaps** — `/wallet/v1/intents/swap` through 1Click, gasless from the intents balance.
- **Cross-chain deposits and withdrawals** — `/wallet/v1/intents/deposit/cross-chain` and `/wallet/v1/intents/withdraw` through 1Click.
- **On-chain calls** — NEAR contract calls (`/wallet/v1/call`).
- **Token transfers** — native NEAR (`/wallet/v1/transfer`) and intents balances (`/wallet/v1/intents/transfer`).
- **Policy engine** — capabilities, limits, whitelists, time windows, rate limit, multisig approval, freeze.
- **Webhooks** — the policy's `webhook_url` receives wallet events.
- **Trial** — a wallet can claim a trial key (`POST /trial-key`) within its first days; the `trial` block of the `POST /register` response states the calls and days.

Intents operations are mainnet only.

## Architecture

```
Client (bot)                    Coordinator                  Keystore (TEE)
   |                                |                            |
   |-- Bearer near:<signed JSON> -->|                            |
   |                                |-- verify ed25519 sig       |
   |                                |-- RPC: full-access key?    |
   |                                |-- derive wallet_id         |
   |                                |-- create row if new        |
   |                                |-- operation -------------->|
   |                                |<-- signature / address ----|
   |<-- result ---------------------|                            |
```

- **Auth** = ed25519 signature verification in the coordinator + a full-access-key check over RPC, cached 60 s.
- **Wallet keys** = derived and used by the keystore, as for every wallet.
- **Coordinator DB** = a `wallet_accounts` row; no auth secret for `Bearer near:`.

## Auth: Bearer token format

One `Authorization` header for every wallet type, told apart by prefix:

```
# Random wallets and delegate keys
Authorization: Bearer wk_a1b2c3d4...

# Deterministic wallets
Authorization: Bearer near:<base64url>
```

The base64url payload (padding optional) is a JSON object:

```json
{
  "account_id": "my-tg-bot.near",
  "seed": "a1b2c3...",
  "pubkey": "ed25519:<base58>",
  "timestamp": 1712000000,
  "signature": "<base58>"
}
```

| Field | Description |
|-------|-------------|
| `account_id` | The client's NEAR account |
| `seed` | Which wallet: 1–256 characters of `[a-zA-Z0-9._-]` (no `:`) |
| `pubkey` | A **full-access** key of `account_id`, `ed25519:<base58>` (or the key of an implicit account that does not exist on chain yet). A function-call key is refused |
| `timestamp` | Unix seconds, within ±30 s of the coordinator's clock |
| `signature` | Raw ed25519 signature (not NEP-413), base58, of `auth:<seed>:<timestamp>` |
| `vault_id` | Optional. Scopes the wallet to a per-customer vault; the signed message is then `auth:<seed>:<timestamp>:<vault_id>`, and `account_id` must be the vault's parent on chain |

The wallet is created on the first authenticated request; `POST /register` is optional for a `Bearer near:` client.

### Verification

1. base64url-decode → parse JSON; validate `seed`.
2. Rebuild `auth:<seed>:<timestamp>` (`:<vault_id>` appended when present), check the timestamp (±30 s), verify the raw ed25519 signature against `pubkey`.
3. Check that `pubkey` is a full-access key of `account_id`: cached result, otherwise one NEAR RPC call. Both answers are cached for 60 s.
4. With `vault_id`: check the vault is verified on the DAO contract and that `account_id` is its parent.
5. `wallet_id = UUID(SHA256("outlayer:deterministic-wallet-id:" + account_id + ":" + seed [+ "\0vault:" + vault_id])[..16])`.
6. Create the `wallet_accounts` row if it does not exist.

Two timestamp windows:
- ±30 s for `Bearer near:` (every request).
- ±300 s for `POST /register` and `PUT /wallet/v1/api-key` with a NEAR signature in the body (setup steps).

The order the coordinator tries credentials: the worker's internal credential (`X-Internal-Wallet-Auth` + `X-Wallet-Id`, for WASI host functions), then `Bearer near:`, then `Bearer wk_` (looked up by SHA-256 hash).

## POST /register — deterministic path

### Request

```json
{
  "account_id": "my-tg-bot.near",
  "seed": "a1b2c3...",
  "pubkey": "ed25519:<base58>",
  "message": "register:<seed>:<timestamp_sec>",
  "signature": "<base58>"
}
```

Any of these five fields present = deterministic path, and then all five are required. None present = random wallet with a `wk_` key. The deterministic path does not take `vault_id` (400); a vault-scoped deterministic wallet is reached with `Bearer near:` carrying `vault_id`.

### Validation

1. `seed` is 1–256 characters of `[a-zA-Z0-9._-]`.
2. `message` is `register:<seed>:<timestamp>` with the same seed.
3. Timestamp within ±300 s.
4. Raw ed25519 signature (not NEP-413) of `message` verifies against `pubkey`.
5. For a wallet that does not exist yet: `pubkey` is a full-access key of `account_id` (cached 60 s).

`POST /register` is rate-limited per IP.

### Response

```json
{
  "wallet_id": "uuid-string",
  "near_account_id": "hex64-implicit-account",
  "trial": { "available": true, "calls": 50, "days": 7, "claim_url": "POST /trial-key", "scope": "connectors.outlayer.near/*" }
}
```

No `api_key` and no `handoff_url`. Repeating the call returns the same wallet, without `trial`.

## Key rotation

No endpoint needed.

```bash
# 1. Add the new key
near add-key my-tg-bot.near ed25519:NEW_KEY

# 2. Sign with the new key — accepted at once

# 3. Remove the old key
near delete-key my-tg-bot.near ed25519:OLD_KEY

# 4. Within 60 s the cached answer for the old key expires → 401
```

The wallet is `(account_id, seed)`; keys rotate freely.

## What the keystore does

- Derives the wallet's keys (`wallet:{wallet_id}:near`, `:evm`, `:solana`) from the master on demand.
- Evaluates the wallet's policy and signs.

No auth credential for `Bearer near:` is stored anywhere.

## PUT /wallet/v1/api-key — delegate key for sub-agents

Registers the SHA-256 hash (64 hex characters) of a client-derived `wk_` key, creating the wallet it opens if needed. Idempotent. Two auth modes.

### Mode 1: Bearer header (an existing wallet creates a sub-wallet)

An authenticated wallet (`Bearer wk_...` or `Bearer near:...`) creates a sub-wallet. No NEAR signature in the body.

```json
{
  "seed": "sub-task-42",
  "key_hash": "sha256hex64chars..."
}
```

Sub-wallet `wallet_id = deterministic(parent_wallet_id, seed, parent's vault)`. A vault-bound parent's sub-wallets derive from the same vault. No RPC check.

**Ambiguity guard:** a Bearer header together with any of `account_id`, `pubkey`, `message`, `signature` or `vault_id` in the body → 400.

### Mode 2: NEAR signature in the body (a NEAR account, no Bearer header)

```json
{
  "account_id": "parent-agent.near",
  "seed": "sub-task-42",
  "key_hash": "sha256hex64chars...",
  "pubkey": "ed25519:<base58>",
  "message": "api-key:sub-task-42:<timestamp>",
  "signature": "<base58>"
}
```

Timestamp within ±300 s, raw ed25519 signature, and `pubkey` must be a full-access key of `account_id` on every call. Optional `vault_id`: `account_id` must be the vault's parent. The wallet is `deterministic(account_id, seed, vault)` — the same wallet `Bearer near:` reaches for that account, seed and vault.

### Response (both modes)

```json
{
  "wallet_id": "uuid-string",
  "near_account_id": "hex64-implicit-account",
  "vault_id": "vault.example.near"
}
```

`vault_id` is present only for a vault-scoped wallet.

## DELETE /wallet/v1/api-key/:key_hash — revoke a key

Revokes one `wk_` key of the authenticated wallet. Auth: any credential of that wallet (`Bearer near:...` or `Bearer wk_...`). The key stops working at once. Response: `{"revoked": true}`.

**The last active key cannot be revoked** (409 Conflict), so a wallet reachable only through `wk_` keys cannot lock itself out. The rule counts `wk_` keys only: a deterministic wallet with a single delegate key cannot revoke it, even though its account can still sign `Bearer near:` requests.

### Sub-agent usage

```python
# Parent: derive the key (no storage needed, re-derive any time)
api_key = "wk_" + hmac.new(NEAR_SECRET, f"{seed}:0".encode(), hashlib.sha256).hexdigest()

# Parent: register its hash (idempotent)
requests.put(f"{API_BASE}/wallet/v1/api-key", json={
    "account_id": ACCOUNT_ID, "seed": "sub-task-42",
    "key_hash": hashlib.sha256(api_key.encode()).hexdigest(),
    "pubkey": NEAR_PUBKEY, "message": message, "signature": sig,
})

# Sub-agent: plain Bearer token
requests.get(f"{API_BASE}/wallet/v1/balance",
    headers={"Authorization": f"Bearer {api_key}"})
```

## Summary of endpoints

| Endpoint | Auth | Creates wallet? | Returns api_key? | Use case |
|----------|------|----------------|-----------------|----------|
| `POST /register` (no body) | None | Yes (random) | Yes (`wk_`) | Quick start, testing |
| `POST /register` (with signature) | NEAR sig in body | Yes (deterministic) | No | Server/bot that then uses `Bearer near:...` |
| any `/wallet/v1/*` with `Bearer near:` | NEAR sig in header | Yes, on first use | No | Every request of a deterministic client |
| `PUT /wallet/v1/api-key` | Bearer header OR NEAR sig in body | Yes if needed | No (caller knows it) | Register a delegate key for a sub-agent |
| `DELETE /wallet/v1/api-key/:key_hash` | `Bearer near:...` or `Bearer wk_...` | No | — | Revoke a key (last key protected) |

## Auth signatures from the wallet's own key — POST /wallet/v1/auth-sign

To produce OutLayer's `Bearer near:` / register / api-key auth signature **with the wallet's TEE key** (rather than a NEAR key you hold), call `POST /wallet/v1/auth-sign`.

Request body: `{ "purpose": "bearer" | "register" | "api-key", "seed": "...", "vault_id": "..." }` (`vault_id` only for `bearer`). The keystore builds the exact domain-separated string with a fresh server timestamp and signs it raw ed25519. It moves no funds, so it is allowed on any wallet that is not frozen. Response:

```json
{
  "auth_message": "auth:<seed>:<timestamp>",
  "auth_timestamp": 1712000000,
  "signature": "<base58, no ed25519: prefix>",
  "public_key": "ed25519:<base58>"
}
```

Send `auth_message` verbatim. `POST /wallet/v1/sign-message` produces NEP-413 signatures only and does not sign raw bytes. It never signs for an intents verifier (`intents.near`, `intents.far`), and under a policy only for the recipients listed in `capabilities.sign_message.allowed_recipients`.

## Flow examples

All Python examples share the helpers defined in Flow 2: `_sign_message()`, `_make_bearer()`, `NEAR_SECRET`, `NEAR_PUBKEY`, `ACCOUNT_ID`, `API_BASE`. Flows 6 and 7 also use:

```python
def wallet_request_by_seed(seed: str, method: str, path: str, **kwargs):
    """Wallet API call using Bearer near:... for a specific seed."""
    return requests.request(method, f"{API_BASE}{path}",
        headers={"Authorization": f"Bearer {_make_bearer(seed)}"},
        **kwargs,
    )
```

### Flow 1: Quick start (random wallet)

No NEAR account needed.

```python
# 1. Register — one call, no auth
resp = requests.post("https://api.outlayer.ai/register")
api_key = resp.json()["api_key"]          # "wk_a1b2c3..."
account = resp.json()["near_account_id"]  # "hex64..."

# 2. Use the wallet — plain Bearer token
requests.get("https://api.outlayer.ai/wallet/v1/balance",
    headers={"Authorization": f"Bearer {api_key}"})
```

The developer stores `api_key`. The coordinator keeps only its SHA-256 hash; a lost key cannot be recovered.

---

### Flow 2: Telegram bot (deterministic, NEAR signature auth)

The bot holds one full-access NEAR key in env and creates wallets for any number of users, storing nothing per user.

```python
import hashlib, hmac, json, time, base64, requests
from nacl.signing import SigningKey
import base58

# ── Setup (once, in env) ──────────────────────────────────────────────
NEAR_SECRET = load_near_secret_bytes()          # 32-byte ed25519 seed of a full-access key
NEAR_KEY = SigningKey(NEAR_SECRET)
NEAR_PUBKEY = f"ed25519:{base58.b58encode(NEAR_KEY.verify_key.encode()).decode()}"
ACCOUNT_ID = "my-tg-bot.near"
API_BASE = "https://api.outlayer.ai"

# ── Helpers ───────────────────────────────────────────────────────────
def _sign_message(message: str) -> str:
    """Sign a message with the bot's NEAR key, return base58 signature."""
    return base58.b58encode(NEAR_KEY.sign(message.encode()).signature).decode()

def _seed_for_user(telegram_user_id: int) -> str:
    """Deterministic seed from user ID. Same user → same seed → same wallet."""
    return hashlib.sha256(str(telegram_user_id).encode()).hexdigest()

def _make_bearer(seed: str) -> str:
    """Build the Bearer near:... token for one wallet API call."""
    timestamp = int(time.time())
    message = f"auth:{seed}:{timestamp}"
    payload = json.dumps({
        "account_id": ACCOUNT_ID,
        "seed": seed,
        "pubkey": NEAR_PUBKEY,
        "timestamp": timestamp,
        "signature": _sign_message(message),
    }, separators=(",", ":"))
    token = base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")
    return f"near:{token}"

# ── Registration (idempotent — safe on every /start) ──────────────────
def ensure_wallet_with_seed(seed: str) -> dict:
    timestamp = int(time.time())
    message = f"register:{seed}:{timestamp}"
    resp = requests.post(f"{API_BASE}/register", json={
        "account_id": ACCOUNT_ID,
        "seed": seed,
        "pubkey": NEAR_PUBKEY,
        "message": message,
        "signature": _sign_message(message),
    })
    return resp.json()
    # First call:  creates the wallet, returns { wallet_id, near_account_id, trial }
    # Repeat call: returns the same wallet

def ensure_wallet(telegram_user_id: int) -> dict:
    return ensure_wallet_with_seed(_seed_for_user(telegram_user_id))

# ── Wallet operations (Bearer near:... on every request) ─────────────
def wallet_request(telegram_user_id: int, method: str, path: str, **kwargs):
    seed = _seed_for_user(telegram_user_id)
    return requests.request(method, f"{API_BASE}{path}",
        headers={"Authorization": f"Bearer {_make_bearer(seed)}"},
        **kwargs,
    )

# ── Bot handlers ──────────────────────────────────────────────────────
def on_start(user_id: int):
    wallet = ensure_wallet(user_id)
    send_message(user_id, f"Your wallet: {wallet['near_account_id']}")

def on_balance(user_id: int):
    resp = wallet_request(user_id, "GET", "/wallet/v1/balance")
    send_message(user_id, f"Balance: {resp.json()}")

def on_swap(user_id: int, token_in: str, token_out: str, amount_in: str):
    resp = wallet_request(user_id, "POST", "/wallet/v1/intents/swap", json={
        "token_in": token_in,      # e.g. "nep141:wrap.near"
        "token_out": token_out,    # e.g. "nep141:usdt.tether-token.near"
        "amount_in": amount_in,    # smallest units
    })
    send_message(user_id, f"Swap: {resp.json()}")

def on_send(user_id: int, receiver: str, amount_yocto: str):
    resp = wallet_request(user_id, "POST", "/wallet/v1/transfer", json={
        "to": receiver,
        "amount": amount_yocto,
    })
    send_message(user_id, f"Sent: {resp.json()}")
```

The bot stores no per-user keys. Restart, redeploy, move servers — everything keeps working. The NEAR key in env is the only secret, and it is a full-access key of the bot's account: keep the account for this purpose only.

---

### Flow 3: Web app with Google login (deterministic, NEAR signature auth)

Same as the bot, with the seed derived from the OAuth provider and user ID.

```python
def on_google_login(google_user_id: str) -> dict:
    seed = hashlib.sha256(f"google:{google_user_id}".encode()).hexdigest()
    return ensure_wallet_with_seed(seed)

def on_github_login(github_user_id: str) -> dict:
    seed = hashlib.sha256(f"github:{github_user_id}".encode()).hexdigest()
    return ensure_wallet_with_seed(seed)

# Different provider + same person = different wallets (by design)
# Same provider + same person = always the same wallet
```

The seed is a hex digest, so it satisfies the seed alphabet whatever the provider's IDs contain.

---

### Flow 4a: Custody wallet creating sub-agents (Bearer auth, no NEAR key)

The parent has a `wk_` API key and no NEAR key.

```python
import hashlib, requests

API = "https://api.outlayer.ai"
PARENT_KEY = "wk_..."
HEADERS = {"Authorization": f"Bearer {PARENT_KEY}", "Content-Type": "application/json"}

def create_sub_agent_wallet(task_id: str) -> tuple[str, str]:
    seed = f"sub-agent-{task_id}"
    sub_key = f"wk_{hashlib.sha256(f'{seed}:0:{PARENT_KEY}'.encode()).hexdigest()}"
    key_hash = hashlib.sha256(sub_key.encode()).hexdigest()

    resp = requests.put(f"{API}/wallet/v1/api-key",
        headers=HEADERS,
        json={"seed": seed, "key_hash": key_hash},
    ).json()
    return resp["near_account_id"], sub_key

account, key = create_sub_agent_wallet("task-42")
# Sub-agent uses: Authorization: Bearer wk_...
```

A parent registered with `vault_id` passes its vault to every sub-wallet.

---

### Flow 4b: NEAR account creating sub-agents (NEAR signature)

The parent holds a NEAR key; sub-agents get plain Bearer tokens.

```python
def create_sub_agent_wallet(task_id: str, key_index: int = 0) -> tuple[str, str]:
    """Create the wallet + derive a wk_ key for a sub-agent.
    Returns (near_account_id, api_key). Call again to re-derive."""

    seed = f"sub-agent-{task_id}"

    # 1. Derive the wk_ key deterministically
    key_material = hmac.new(
        NEAR_SECRET, f"{seed}:{key_index}".encode(), hashlib.sha256
    ).hexdigest()
    api_key = f"wk_{key_material}"
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()

    # 2. Register its hash (idempotent)
    timestamp = int(time.time())
    message = f"api-key:{seed}:{timestamp}"
    resp = requests.put(f"{API_BASE}/wallet/v1/api-key", json={
        "account_id": ACCOUNT_ID,
        "seed": seed,
        "key_hash": key_hash,
        "pubkey": NEAR_PUBKEY,
        "message": message,
        "signature": _sign_message(message),
    })
    return resp.json()["near_account_id"], api_key

account, key = create_sub_agent_wallet("task-42")
sub_agent = spawn_agent(task="Buy 10 USDT on NEAR", wallet_key=key)

# ── Sub-agent (no crypto, any language) ───────────────────────────────
def sub_agent_main(wallet_key: str):
    headers = {"Authorization": f"Bearer {wallet_key}"}
    balance = requests.get(f"{API_BASE}/wallet/v1/balance", headers=headers).json()
    swap = requests.post(f"{API_BASE}/wallet/v1/intents/swap", headers=headers, json={
        "token_in": "nep141:wrap.near",
        "token_out": "nep141:usdt.tether-token.near",
        "amount_in": "10000000000000000000000000",   # 10 wNEAR
    }).json()

# ── Later: the parent re-derives the key without any storage ─────────
_, same_key = create_sub_agent_wallet("task-42")  # same key as before
```

The sub-agent's wallet here is the wallet `Bearer near:` reaches for `(ACCOUNT_ID, "sub-agent-task-42")`, so the parent can operate it directly too.

---

### Flow 5: NEAR key rotation

The bot's NEAR key was exposed. Rotate without affecting wallets.

```bash
near generate-key --outputDir ./new-key
near add-key my-tg-bot.near ed25519:NEW_PUBLIC_KEY      # full access
# Update the bot's env with the new key, restart the bot
near delete-key my-tg-bot.near ed25519:OLD_PUBLIC_KEY
# Within 60 s, Bearer near: tokens signed by the old key → 401
```

Wallets are not affected — `wallet_id` depends on `(account_id, seed)`, not on the key.

**For Flow 4b:** existing `wk_` keys keep working after a rotation (they are stored by hash, independent of the NEAR key), but the parent derived them with the old key and can no longer re-derive them. Sub-agents created afterwards use keys derived from the new key. Old sub-agent keys stay valid until revoked.

---

### Flow 6: Key revocation (compromised key)

```bash
near delete-key my-tg-bot.near ed25519:COMPROMISED_KEY
# - Bearer near: signed by the compromised key → 401 within 60 s
# - wk_ keys derived from it → still work (stored by hash)
```

To revoke the `wk_` delegate keys derived from the compromised key:

```python
for seed, index in compromised_sub_agents:
    old_key = "wk_" + hmac.new(OLD_NEAR_SECRET, f"{seed}:{index}".encode(), hashlib.sha256).hexdigest()
    old_hash = hashlib.sha256(old_key.encode()).hexdigest()
    # Authenticated with the new NEAR key
    wallet_request_by_seed(seed, "DELETE", f"/wallet/v1/api-key/{old_hash}")
```

Register the replacement key first: the last active `wk_` key of a wallet cannot be revoked (409).

---

### Flow 7: Sub-agent with a policy (spending limits)

The parent creates a wallet for the sub-agent that may only swap wNEAR, at most 5 wNEAR per swap. Setting a policy is three steps: encrypt it, have the wallet sign it for the account that will store it, store it on chain.

```python
# ── Parent agent ──────────────────────────────────────────────────────

# 1. Create the wallet + wk_ key for the sub-agent (Flow 4b)
account, sub_key = create_sub_agent_wallet("task-42")
seed = "sub-agent-task-42"
wallet_id = wallet_request_by_seed(seed, "GET", "/wallet/v1/address?chain=near").json()["wallet_id"]

# 2. Encrypt the policy in the keystore
encrypted = wallet_request_by_seed(seed, "POST", "/wallet/v1/encrypt-policy", json={
    "wallet_id": wallet_id,
    "rules": {
        "transaction_types": ["swap"],
        "limits": {"per_transaction": {"nep141:wrap.near": "5000000000000000000000000"}},
    },
    "capabilities": {"swap": {"allowed": True}},
}).json()                                # { encrypted_base64, wallet_pubkey }

# 3. Have the wallet sign it for the account that will store it.
#    `caller` is part of what is signed: the answer works for that account only.
signed = wallet_request_by_seed(seed, "POST", "/wallet/v1/sign-policy", json={
    "encrypted_data": encrypted["encrypted_base64"],
    "caller": "you.near",
}).json()                                # { signature_hex, public_key_hex }

# 4. you.near calls store_wallet_policy on outlayer.near with a storage deposit
#    (estimate_wallet_policy_cost gives the amount):
#      { "wallet_pubkey": encrypted["wallet_pubkey"],
#        "encrypted_data": encrypted["encrypted_base64"],
#        "wallet_signature": signed["signature_hex"] }
#    you.near becomes the policy's controller: only it can update, freeze or delete it.

# 5. Hand the wk_ key to the sub-agent
sub_agent = spawn_agent(task="Buy USDT", wallet_key=sub_key)

# ── Sub-agent ─────────────────────────────────────────────────────────
headers = {"Authorization": f"Bearer {sub_key}"}

requests.get(f"{API_BASE}/wallet/v1/balance", headers=headers)          # reads are not policy-gated

requests.post(f"{API_BASE}/wallet/v1/intents/swap", headers=headers, json={
    "token_in": "nep141:wrap.near", "token_out": "nep141:usdt.tether-token.near",
    "amount_in": "3000000000000000000000000",                          # 3 wNEAR: allowed
})

requests.post(f"{API_BASE}/wallet/v1/intents/swap", headers=headers, json={
    "token_in": "nep141:wrap.near", "token_out": "nep141:usdt.tether-token.near",
    "amount_in": "10000000000000000000000000",                         # 10 wNEAR
})  # → 403 policy_denied (per-transaction limit)

requests.post(f"{API_BASE}/wallet/v1/transfer", headers=headers, json={
    "to": "attacker.near", "amount": "100",
})  # → 403 policy_denied (transfer is not an allowed transaction type)
```

The keystore evaluates the policy inside the TEE before it signs; the sub-agent's key cannot bypass it. The cumulative limits (daily, hourly, monthly, rate limit) are counted by the coordinator. The controller account changes the policy, or freezes the wallet, with a transaction of its own. The policy format is documented at https://app.outlayer.ai/docs/agent-custody.
