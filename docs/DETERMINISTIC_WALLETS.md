# Deterministic Wallets via NEAR Signature Auth

## Why this matters

OutLayer wallets run inside TEE (Intel TDX) — keys never leave the enclave. Combined with NEAR MPC network for cross-chain signing, this gives integrators **verifiable custody**: any wallet operation can be audited on-chain, and the TEE attestation proves the key was never extracted.

Deterministic wallets make this accessible to any developer: one NEAR account → unlimited wallets for your users, with TEE-backed security and cross-chain capabilities out of the box. No key management, no per-user storage, no infrastructure to maintain.

## Problem

POST /register creates wallets with random API keys. Clients (bots, servers) must store per-user api_key in their DB. DB leak = all wallets compromised.

## Solution

Deterministic wallets authenticated by NEAR signature on every request. Coordinator stores zero auth secrets. Client derives wallet access from its NEAR key + seed — nothing to store per-user.

Key revocation = remove key from NEAR account. Effect within 60 seconds (cache TTL).

## Use cases

**Web app with OAuth login.** Server has one NEAR key. User logs in via Google/GitHub/etc. Server derives `seed = SHA256(provider + ":" + user_id)`, calls /register, user gets a wallet instantly. Zero per-user key storage. DB stores only user profiles, not wallet credentials.

**Telegram/Discord bot.** Bot has one NEAR key in env. For each user: `seed = SHA256(telegram_user_id)`. Bot re-derives wallet on every request from BOT_SECRET. No per-user DB.

**AI agent spawning sub-agents.** Parent agent derives a `wk_` key from (near_key, seed, index), registers its hash via `PUT /wallet/v1/api-key`, hands the key string to sub-agent. Sub-agent uses simple `Bearer wk_...` — zero crypto, works with any HTTP client or LLM framework. Parent can re-derive the key anytime without storage.

All three share the same pattern: **one NEAR account, many wallets, zero stored secrets. Access control via NEAR keys.**

## What integrators get out of the box

Every deterministic wallet has the same capabilities as a regular wallet — all existing features work via the same API:

- **Multi-chain addresses** — NEAR, Ethereum, Base, Arbitrum, Solana, Bitcoin derived from one wallet via NEAR MPC network
- **Gasless swaps** — `/intents/swap` via solver relay, no gas needed on wallet
- **Cross-chain deposits** — any source chain (Solana, Ethereum, Bitcoin, EVM L2s) → NEAR via the 1Click bridge (`/deposit-intent`)
- **On-chain calls** — arbitrary NEAR contract calls (`/call`)
- **Token transfers** — NEAR native + any NEP-141 token
- **Policy engine** — spending limits, allowed actions, freeze thresholds, multisig approval
- **Webhooks** — notifications on wallet events
- **TEE attestation** — all wallet keys derived inside Intel TDX, verifiable on-chain
- **Trial** — a wallet made by `POST /register` can claim fifty connector calls in its first week (`POST /trial-key`), no payment setup needed

## Architecture

```
Client (bot)                    Coordinator                  Keystore (TEE)
   |                                |                            |
   |-- Bearer near:<signed JSON> -->|                            |
   |                                |-- verify ed25519 sig       |
   |                                |-- RPC: pubkey in account?  |
   |                                |-- derive wallet_id         |
   |                                |-- keystore_derive_address->|
   |                                |<-- near implicit account --|
   |<-- { wallet_id, account_id } --|                            |
```

- **Auth** = NEAR signature verification (ed25519, in-process) + access key check (RPC, cached 60s)
- **Wallet keys** = keystore derives & signs (existing path, unchanged)
- **Coordinator DB** = wallet_accounts row only, no auth secrets

## Auth: Bearer token format

Single `Authorization` header for both wallet types. Middleware detects format by prefix:

```
# Random wallets (existing)
Authorization: Bearer wk_a1b2c3d4...

# Deterministic wallets (new)
Authorization: Bearer near:<base64url>
```

The base64url payload is a JSON object:

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
| `account_id` | NEAR account_id of the client |
| `seed` | Arbitrary string — determines which wallet |
| `pubkey` | NEAR public key (ed25519:base58) |
| `timestamp` | Unix timestamp (seconds) |
| `signature` | ed25519 signature of `"auth:<seed>:<timestamp>"` |

## Auth middleware flow

```
1. Try X-Internal-Wallet-Auth (trusted worker, no DB query)
2. Try Bearer near:... → NEAR signature auth:
   a. base64url-decode → parse JSON
   b. Verify timestamp ±30 sec (MAX_TIMESTAMP_SKEW = 30)
   c. Parse pubkey "ed25519:<base58>" → raw 32 bytes
   d. Verify raw ed25519 signature of "auth:<seed>:<timestamp>" against pubkey
   e. Access key cache check: "account_id\0pubkey" → valid?
      - Cache hit → use cached result
      - Cache miss → NEAR RPC view_access_key (single call, no retry)
      - Cache result for 60s (both positive and negative)
   f. Derive wallet_id = deterministic(account_id, seed)
   g. Verify wallet_id exists in wallet_accounts
   h. Return WalletAuth { wallet_id, ... }
3. Try Bearer wk_... → existing api_key auth (unchanged)
4. No auth → Err(MissingAuth)
```

**Two timestamp windows:**
- `MAX_TIMESTAMP_SKEW = 30` sec — Bearer near: auth (every request, tight)
- `MAX_REGISTRATION_SKEW = 300` sec (5 min) — POST /register, PUT /api-key with NEAR sig in body (setup steps)

All wallet/v1/* endpoints receive `WalletAuth` — they don't know or care how it was obtained.

### Access key cache

```rust
struct AccessKeyCache {
    // "account_id\0pubkey" → (valid, cached_at)
    // NUL-separated composite key avoids tuple allocation on lookup
    entries: Arc<RwLock<HashMap<String, (bool, Instant)>>>,
}
```

- TTL: 60 seconds
- Max entries: 10K (lazy cleanup on write, same pattern as ApiKeyCache)
- Negative caching: invalid keys cached for 60s to prevent RPC spam
- Security tradeoff: 60s window after key deletion before access revoked

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

All 5 fields present = deterministic path. All absent = current behavior (random key).

### Validation

1. All 5 fields must be present together, else 400
2. `seed` must not be empty
3. Parse `message` via `rsplit_once(':')` — extract seed and timestamp, verify seed matches `seed` field. Seeds may contain `:`.
4. Timestamp ±5 min (`MAX_REGISTRATION_SKEW = 300` — longer window for setup operations)
5. Parse `pubkey` "ed25519:\<base58\>" → raw 32 bytes
6. Verify **raw ed25519** signature (NOT NEP-413) of `message` against `pubkey`
7. NEAR RPC: `check_access_key_exists(rpc_url, account_id, pubkey)` — **only for new wallets** (cached 60s)

### Wallet creation

```
wallet_id = UUID(SHA256("outlayer:deterministic-wallet-id:" + account_id + ":" + seed))
```

Deterministic. Same (account_id, seed) = same wallet_id = same NEAR implicit account.

```sql
INSERT INTO wallet_accounts (wallet_id) VALUES ($1) ON CONFLICT DO NOTHING
-- rows_affected > 0 → new wallet, derive address via keystore
-- rows_affected = 0 → existing wallet, skip inserts, derive address (idempotent)
```

RPC access key check: only when creating (rows_affected > 0). Idempotent return skips RPC.

### Response

```json
{
  "wallet_id": "uuid-string",
  "near_account_id": "hex64-implicit-account",
  "trial": { "available": true, "calls": 50, "days": 7, "claim_url": "POST /trial-key", "scope": "connectors.outlayer.near/*" }
}
```

No `api_key`. No `handoff_url`. Client doesn't need them.

## Key rotation

**No endpoint needed.**

```bash
# 1. Bot adds new NEAR key
near add-key my-tg-bot.near ed25519:NEW_KEY

# 2. Bot starts signing with new key — works immediately (RPC sees new key)

# 3. Bot removes old key
near delete-key my-tg-bot.near ed25519:OLD_KEY

# 4. Within 60s, old key expires from cache → 401 for anyone using it
```

Wallet identity = (account_id, seed). Keys rotate freely. No coordinator action needed.

## Key revocation (compromised key)

```bash
# Remove compromised key from NEAR account
near delete-key my-tg-bot.near ed25519:COMPROMISED

# Within 60 seconds: cache expires, attacker gets 401
# No coordinator action. No DB update. Automatic.
```

## What uses keystore (unchanged)

Keystore (TEE) still:
- Derives wallet's ed25519 keypair from `"wallet:{wallet_id}:near"`
- Signs NEAR transactions on behalf of the wallet
- Wallet's implicit NEAR account is custodial (keystore holds private key)

What's NOT stored anywhere: auth credentials. Coordinator DB has zero secrets for deterministic wallets.

## What to reuse from existing code

| Component | Location | Usage |
|-----------|----------|-------|
| `verify_ed25519()` | `wallet/auth.rs:293` | Signature verification |
| `check_access_key_exists()` | `near_client.rs:276` | RPC access key check |
| `MAX_TIMESTAMP_SKEW = 30` | `wallet/auth.rs:25` | Timestamp validation |
| `state.near_rpc_url` | `wallet/mod.rs:46` | RPC URL |
| `ed25519-dalek`, `bs58` | `Cargo.toml` | Already in deps |
| `keystore_derive_address()` | `wallet/handlers.rs` | Wallet address derivation |
| `build_trial_info()` | `wallet/handlers.rs` | The trial offer in the response |
| `INSERT ON CONFLICT` pattern | current diff | Race condition safe |
| `Bytes` body parsing | current diff | Backward compat |
| `ApiKeyCache` pattern | `wallet/auth.rs` | Same DashMap + TTL pattern for AccessKeyCache |

## PUT /wallet/v1/api-key — delegate key for sub-agents

Registers a client-derived `wk_` key hash. Creates sub-wallet if not exists. Idempotent.

**Two auth modes:**

### Mode 1: Bearer header (custody wallets)

Custody wallet (`Bearer wk_...`) or deterministic wallet (`Bearer near:...`) creates a sub-wallet. No NEAR signatures needed — parent is already authenticated.

Sends `Authorization: Bearer wk_...` header + minimal body:
```json
{
  "seed": "sub-task-42",
  "key_hash": "sha256hex64chars..."
}
```

Sub-wallet_id = `deterministic(parent_wallet_id, seed)`. No RPC check.

**Ambiguity guard:** If both Bearer header AND signature fields (account_id, pubkey, message, signature) are present in body → 400 error. Prevents silent fallthrough bugs.

### Mode 2: NEAR signature in body (external NEAR accounts)

No Bearer header. All 6 fields required:
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

Timestamp window: ±5 min. Raw ed25519 signature. RPC check for new wallets.

### Response (both modes)

```json
{
  "wallet_id": "uuid-string",
  "near_account_id": "hex64-implicit-account"
}
```

### Flow (Mode 1 — Bearer)

1. Authenticate via Bearer header (existing `authenticate()`)
2. Reject if signature fields also present (ambiguous auth)
3. Derive wallet_id = `deterministic(parent_wallet_id, seed)`
4. Create wallet if not exists (no RPC check — parent is authenticated)
5. Store key_hash in wallet_api_keys (INSERT ON CONFLICT DO NOTHING — idempotent)
6. Return wallet info

### Flow (Mode 2 — NEAR sig)

1. Validate signature + timestamp (±5 min)
2. NEAR RPC: check pubkey is on account (cached 60s, skip if wallet already exists)
3. Derive wallet_id = `deterministic(account_id, seed)`
4. Create wallet if not exists (INSERT ON CONFLICT DO NOTHING)
5. Store key_hash in wallet_api_keys (INSERT ON CONFLICT DO NOTHING — idempotent)
6. Return wallet info

## DELETE /wallet/v1/api-key/:key_hash — revoke delegate key

Revokes a `wk_` key for a deterministic wallet. **Auth: `Bearer near:...` header** (unlike PUT, wallet must already exist here, so normal auth middleware works).

Sets `revoked_at = NOW()` in wallet_api_keys. The `wk_` key stops working after auth cache expires (60s).

Coordinator verifies the caller owns the wallet (derives wallet_id from Bearer's account_id + seed, checks key_hash belongs to that wallet_id).

**Cannot revoke the last key.** If wallet has only one active `wk_` key, DELETE returns 409 Conflict. This prevents locking out wallets that are only accessible via `wk_` keys (Flow 1 random wallets). Deterministic wallet owners can always access via `Bearer near:...` regardless, but the guard applies uniformly.

### Sub-agent usage

```python
# Parent: derive key (no storage needed, re-derive anytime)
api_key = f"wk_{hmac_sha256(near_private_key, f'{seed}:0').hex()}"

# Parent: register key hash (idempotent, call once or many times)
requests.put(".../wallet/v1/api-key", json={
    "account_id": ACCOUNT_ID, "seed": "sub-task-42",
    "key_hash": sha256(api_key.encode()).hexdigest(),
    "pubkey": NEAR_PUBKEY, "message": message, "signature": sig,
})

# Parent hands string to sub-agent
sub_agent.set_bearer_token(api_key)

# Sub-agent: zero crypto, zero dependencies
requests.get(".../wallet/v1/balance",
    headers={"Authorization": f"Bearer {api_key}"})

# Later, on another machine, without any DB:
api_key = f"wk_{hmac_sha256(near_private_key, f'{seed}:0').hex()}"
# Same key, re-derived from (near_key, seed, index)
```

## Summary of endpoints

| Endpoint | Auth | Creates wallet? | Returns api_key? | Use case |
|----------|------|----------------|-----------------|----------|
| `POST /register` (no body) | None | Yes (random) | Yes (`wk_`) | Quick start, testing |
| `POST /register` (with signature) | NEAR sig in body | Yes (deterministic) | No | Server/bot, uses `Bearer near:...` |
| `PUT /wallet/v1/api-key` | Bearer header OR NEAR sig in body | Yes if needed | No (caller knows it) | Register delegate key for sub-agent |
| `DELETE /wallet/v1/api-key/:key_hash` | `Bearer near:...` or `Bearer wk_...` | No | — | Revoke delegate key (last key protected) |

## OutLayer auth signatures from the wallet key — POST /wallet/v1/auth-sign

To produce OutLayer's own Bearer / register / api-key auth token **from the wallet's TEE key**
(not from a locally-held NEAR key), use the dedicated `POST /wallet/v1/auth-sign` endpoint.

> The old `POST /wallet/v1/sign-message` `"format": "raw"` parameter is **removed** — calling
> `/sign-message` with `format:"raw"` now returns an error pointing here. `/sign-message` only
> produces NEP-413 signatures (and enforces a default-DENY recipient allowlist); it is no longer a
> raw byte signer.

Request body: `{ "purpose": "bearer" | "register" | "api-key", "seed": "...", "vault_id": "..." }`
(`vault_id` is only valid for `bearer`). The keystore **constructs** the exact domain-separated auth
string with a fresh server timestamp and signs it raw ed25519 (an `Op::Auth` — non-fund, always
allowed on a non-frozen wallet, never a 32-byte tx hash). Response:

```json
{
  "auth_message": "auth:<seed>:<timestamp>",   // send verbatim
  "auth_timestamp": 1712000000,
  "signature": "<base58, no ed25519: prefix>",
  "public_key": "ed25519:<base58>"
}
```

For an arbitrary plain ed25519 signature over your own bytes (custom auth protocols, off-chain
proofs on a chain the structured policy doesn't cover), use the `raw` op via `/wallet/sign` — gated
by the default-DENY `raw_sign` capability (with an optional per-chain allowlist).

## What to write new

1. **`parse_near_pubkey(s: &str) -> Result<[u8; 32]>`** — parse `"ed25519:<base58>"` → raw bytes
2. **`AccessKeyCache`** — in-memory cache for NEAR RPC results, 60s TTL
3. **`extract_near_bearer_auth()`** — parse `Bearer near:<base64>`, verify sig, check access key, derive wallet_id
4. **`register_deterministic()`** — handler for deterministic path in register
5. **`register_api_key()`** — handler for PUT /wallet/v1/api-key (register client-derived key hash)
6. **`revoke_api_key()`** — handler for DELETE /wallet/v1/api-key/:key_hash (revoke delegate key, NEAR sig auth)
7. **`RegisterRequest`** — extended with 5 new optional fields
8. **Update `authenticate()`** — check Bearer prefix: `wk_` → existing path, `near:` → new path

## What does NOT change

- POST /register without body — current behavior, random key
- Bearer wk_... auth — unchanged, works for random wallets
- Worker — unchanged (stateless proxy)
- Keystore-worker — unchanged
- All wallet/v1/* endpoint handlers — unchanged (only auth layer adds new path)
- DB migrations — no new tables (wallet_accounts, wallet_api_keys reused)
  - wallet_api_keys used for random wallets (Flow 1) and delegate `wk_` keys (Flow 4), not for `Bearer near:...` auth

## Flow examples

All Python examples share these helpers (defined in Flow 2): `_sign_message()`, `_make_bearer()`, `NEAR_SECRET`, `NEAR_PUBKEY`, `ACCOUNT_ID`, `API_BASE`.

Flows 4, 6, 7 also use:

```python
def wallet_request_by_seed(seed: str, method: str, path: str, **kwargs):
    """Wallet API call using Bearer near:... for a specific seed."""
    return requests.request(method, f"{API_BASE}{path}",
        headers={"Authorization": f"Bearer {_make_bearer(seed)}"},
        **kwargs,
    )
```

### Flow 1: Quick start (existing behavior, no changes)

A developer wants to try the API. No NEAR account needed.

```python
# 1. Register — one call, no auth
resp = requests.post("https://api.outlayer.ai/register")
api_key = resp.json()["api_key"]          # "wk_a1b2c3..."
account = resp.json()["near_account_id"]  # "hex64..."

# 2. Use wallet — simple Bearer token
requests.get("https://api.outlayer.ai/wallet/v1/balance",
    headers={"Authorization": f"Bearer {api_key}"})

# Same with curl:
# curl -H "Authorization: Bearer wk_a1b2c3..." .../wallet/v1/balance
```

Developer stores `api_key`. If lost — wallet is lost (no recovery).

---

### Flow 2: Telegram bot (deterministic, NEAR signature auth)

Bot has one NEAR key in env. Creates wallets for thousands of users. Stores nothing per-user.

```python
import hashlib, hmac, json, time, base64, requests
from nacl.signing import SigningKey
import base58

# ── Setup (once, in env) ──────────────────────────────────────────────
NEAR_SECRET = load_near_secret_bytes()          # 32 bytes from env
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
    """Build Bearer near:... token for wallet API calls."""
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

# ── Registration (idempotent — safe to call on every bot /start) ──────
def ensure_wallet(telegram_user_id: int) -> dict:
    seed = _seed_for_user(telegram_user_id)
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
    # First call:  creates wallet, returns { wallet_id, near_account_id, trial }
    # Repeat call: returns same wallet, skips creation

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

def on_swap(user_id: int, token_in: str, token_out: str, amount: str):
    resp = wallet_request(user_id, "POST", "/wallet/v1/intents/swap", json={
        "token_in": token_in,
        "token_out": token_out,
        "amount": amount,
    })
    send_message(user_id, f"Swap: {resp.json()}")

def on_send(user_id: int, receiver: str, amount: str):
    resp = wallet_request(user_id, "POST", "/wallet/v1/transfer", json={
        "to": receiver,
        "amount": amount,
    })
    send_message(user_id, f"Sent: {resp.json()}")
```

Bot stores zero per-user keys. Restart bot, redeploy, move to another server — everything works. NEAR key in env is the only secret.

---

### Flow 3: Web app with Google login (deterministic, NEAR signature auth)

Same as Telegram bot, but seed derived from OAuth provider + user ID.

```python
# User logs in via Google OAuth → server gets google_user_id
def on_google_login(google_user_id: str) -> dict:
    seed = hashlib.sha256(f"google:{google_user_id}".encode()).hexdigest()
    # ... same ensure_wallet() / wallet_request() as above
    return ensure_wallet_with_seed(seed)

# User logs in via GitHub
def on_github_login(github_user_id: str) -> dict:
    seed = hashlib.sha256(f"github:{github_user_id}".encode()).hexdigest()
    return ensure_wallet_with_seed(seed)

# Different provider + same person = different wallets (by design)
# Same provider + same person = always the same wallet
```

---

### Flow 4a: Custody wallet creating sub-agents (Bearer auth, no crypto)

Parent agent has a `wk_` API key (custody wallet). No NEAR key needed.

```python
import hashlib, requests

API = "https://api.outlayer.ai"
PARENT_KEY = "wk_..."
HEADERS = {"Authorization": f"Bearer {PARENT_KEY}", "Content-Type": "application/json"}

def create_sub_agent_wallet(task_id: str) -> tuple[str, str]:
    seed = f"sub-agent:{task_id}"
    sub_key = f"wk_{hashlib.sha256(f'{seed}:0:{PARENT_KEY}'.encode()).hexdigest()}"
    key_hash = hashlib.sha256(sub_key.encode()).hexdigest()

    resp = requests.put(f"{API}/wallet/v1/api-key",
        headers=HEADERS,
        json={"seed": seed, "key_hash": key_hash},
    ).json()
    return resp["near_account_id"], sub_key

# Create and hand key to sub-agent
account, key = create_sub_agent_wallet("task-42")
# Sub-agent uses: Authorization: Bearer wk_...
```

---

### Flow 4b: External NEAR account creating sub-agents (NEAR signature)

Parent agent has a NEAR key. Creates wallets for sub-agents. Sub-agents use simple Bearer tokens — no crypto libraries needed.

```python
# ── Parent agent ──────────────────────────────────────────────────────

def create_sub_agent_wallet(task_id: str, key_index: int = 0) -> tuple[str, str]:
    """Create wallet + derive a wk_ key for a sub-agent.
    Returns (near_account_id, api_key). Can be called again to re-derive."""

    seed = f"sub-agent:{task_id}"

    # 1. Derive wk_ key deterministically (parent can re-derive anytime)
    key_material = hmac.new(
        NEAR_SECRET, f"{seed}:{key_index}".encode(), hashlib.sha256
    ).hexdigest()
    api_key = f"wk_{key_material}"
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()

    # 2. Register key hash in coordinator (idempotent)
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
    near_account_id = resp.json()["near_account_id"]

    return near_account_id, api_key

# 3. Parent creates sub-agent, hands it the key
account, key = create_sub_agent_wallet("task-42")
sub_agent = spawn_agent(
    task="Buy 10 USDT on NEAR",
    wallet_key=key,  # simple string
)

# ── Sub-agent (zero crypto, any language, any LLM framework) ─────────

def sub_agent_main(wallet_key: str):
    headers = {"Authorization": f"Bearer {wallet_key}"}

    # Check balance
    balance = requests.get(f"{API_BASE}/wallet/v1/balance", headers=headers).json()
    print(f"Balance: {balance}")

    # Execute swap
    swap = requests.post(f"{API_BASE}/wallet/v1/intents/swap", headers=headers, json={
        "token_in": "wrap.near",
        "token_out": "usdt.tether-token.near",
        "amount": "10.0",
    }).json()
    print(f"Swap result: {swap}")

# ── Later: parent re-derives the key without any storage ─────────────
# Parent's server restarts, DB is empty, doesn't matter:
_, same_key = create_sub_agent_wallet("task-42")  # same key as before
```

---

### Flow 5: NEAR key rotation

Bot's NEAR key was exposed. Rotate without affecting wallets.

```bash
# 1. Generate new key
near generate-key --outputDir ./new-key

# 2. Add new key to the NEAR account (on-chain tx, signed by old key)
near add-key my-tg-bot.near ed25519:NEW_PUBLIC_KEY

# 3. Update bot's env with new key, restart bot
# Bot now signs with new key → works immediately (RPC sees new key)

# 4. Remove old key
near delete-key my-tg-bot.near ed25519:OLD_PUBLIC_KEY

# 5. Within 60 seconds: anyone using old key → cache expires → 401
```

Wallets are NOT affected — wallet_id depends on (account_id, seed), not on which key signs.

**Note for Flow 4 (sub-agents):** if parent rotates NEAR key, existing `wk_` keys keep working (they're in wallet_api_keys, independent of NEAR key). But `hmac(near_private_key, ...)` changes, so parent can no longer re-derive old `wk_` keys. For sub-agents created after rotation, parent uses new key. Old sub-agent keys remain valid until revoked.

---

### Flow 6: Key revocation (compromised key)

```bash
# Remove compromised key from NEAR account
near delete-key my-tg-bot.near ed25519:COMPROMISED_KEY

# Result:
# - Bearer near:... signed by compromised key → 401 within 60s (cache expires)
# - Bearer wk_... keys derived from compromised key → still work (stored by hash)
```

To also revoke `wk_` delegate keys derived from the compromised NEAR key:

```python
# Parent re-derives the key_hash of each compromised wk_ key (knows seed + index)
for seed, index in compromised_sub_agents:
    old_key = f"wk_{hmac_sha256(OLD_NEAR_SECRET, f'{seed}:{index}').hex()}"
    old_hash = hashlib.sha256(old_key.encode()).hexdigest()

    # Revoke via DELETE (authenticated with new NEAR key)
    wallet_request_by_seed(seed, "DELETE", f"/wallet/v1/api-key/{old_hash}")
```

---

### Flow 7: Sub-agent with policy (spending limits)

Parent creates a wallet for sub-agent with restrictions: max $5 per swap, no transfers.
Uses existing policy system — no new endpoints needed.

```python
# ── Parent agent ──────────────────────────────────────────────────────

# 1. Create wallet + wk_ key for sub-agent (same as Flow 4)
account, sub_key = create_sub_agent_wallet("task-42")

# 2. Set policy on the wallet (parent signs with Bearer near:...)
seed = "sub-agent:task-42"

# 2a. Encrypt policy rules via keystore TEE
policy_resp = wallet_request_by_seed(seed, "POST", "/wallet/v1/encrypt-policy", json={
    "rules": [
        {"action": "swap", "max_amount_usd": "5.00"},
        {"action": "balance", "allow": True},
        {"action": "transfer", "deny": True},
        {"action": "delete", "deny": True},
    ],
    "freeze_threshold_usd": "20.00",  # freeze wallet if balance drops below $20
})
encrypted_policy = policy_resp.json()

# 2b. Sign encrypted policy with wallet's key (coordinator asks keystore).
# `caller` is the NEAR account that will send store_wallet_policy — it is part
# of what gets signed, so the answer works for that account and no other.
wallet_request_by_seed(seed, "POST", "/wallet/v1/sign-policy", json={
    **encrypted_policy,
    "caller": "you.near",
})
# Send store_wallet_policy from that account → enforced on every operation

# 3. Hand wk_ key to sub-agent
sub_agent = spawn_agent(task="Buy USDT", wallet_key=sub_key)

# ── Sub-agent tries to use the wallet ────────────────────────────────

headers = {"Authorization": f"Bearer {sub_key}"}

# ✅ Check balance — allowed
requests.get(f"{API_BASE}/wallet/v1/balance", headers=headers)

# ✅ Swap $3 of NEAR → USDT — allowed (under $5 limit)
requests.post(f"{API_BASE}/wallet/v1/intents/swap", headers=headers, json={
    "token_in": "wrap.near",
    "token_out": "usdt.tether-token.near",
    "amount_usd": "3.00",
})

# ❌ Swap $10 — denied by policy
requests.post(f"{API_BASE}/wallet/v1/intents/swap", headers=headers, json={
    "token_in": "wrap.near",
    "token_out": "usdt.tether-token.near",
    "amount_usd": "10.00",
})
# → 403 {"error": "Policy denied: max_amount_usd exceeded"}

# ❌ Transfer to external address — denied by policy
requests.post(f"{API_BASE}/wallet/v1/transfer", headers=headers, json={
    "to": "attacker.near",
    "amount": "100",
})
# → 403 {"error": "Policy denied: transfer not allowed"}
```

Policy is enforced at coordinator level, inside TEE. Sub-agent cannot bypass it — policy is checked before keystore signs any transaction. Parent can update policy anytime via `Bearer near:...`.
