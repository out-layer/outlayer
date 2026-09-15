# Keystore Worker - TEE Secret Management for NEAR OutLayer

The **Keystore Worker** is a secure service that runs in a Trusted Execution Environment (TEE) to manage encryption/decryption of user secrets for the NEAR OutLayer platform.

## Overview

When users want to execute code that requires secrets (API keys, credentials, etc.), they encrypt those secrets with the keystore's public key. The keystore worker then decrypts these secrets ONLY for verified executor workers running in TEE environments.

**Security Model:**
- Private key **NEVER** leaves TEE memory
- Only verified workers can request decryption: the handshake checks that the worker's key is an
  access key on the operator account (`OPERATOR_ACCOUNT_ID`) — where `register_worker_key` puts
  it after verifying a TDX quote — and every later request carries the resulting session
- Token-based authentication for API access
- Public key is published on-chain in the NEAR contract

## Architecture

```
┌─────────────────────────────────────┐
│  User / Contract                    │
│  - Gets pubkey from contract        │
│  - Encrypts secrets with pubkey     │
└────────┬────────────────────────────┘
         │
         ↓ (encrypted secrets in request_execution)
┌─────────────────────────────────────┐
│  NEAR Contract                      │
│  - Stores keystore pubkey           │
│  - Validates requests               │
└─────────────────────────────────────┘
         ↓
┌─────────────────────────────────────┐
│  Executor Worker (in TEE)           │
│  - Receives task with encrypted     │
│  - Opens a TEE session              │
│  - Requests decryption              │
└────────┬────────────────────────────┘
         │
         ↓ POST /decrypt (X-TEE-Session)
┌─────────────────────────────────────┐
│  Keystore Worker (in TEE)           │
│  ✓ Verify the TEE session           │
│  ✓ Decrypt with private key         │
│  ✓ Return plaintext (over TLS)      │
│  - Private key stays in TEE         │
└─────────────────────────────────────┘
```

## Features

- **TEE-Ready:** Designed for Intel SGX, AMD SEV-SNP, or simulated TEE
- **High Performance:** Async/await with Tokio for parallel request handling
- **Secure:** Workers authenticate with a bearer token plus a challenge-response TEE session; a
  request without a live session is refused
- **Simple API:** RESTful HTTP endpoints
- **Contract Integration:** Publishes public key to NEAR contract
- **Token Auth:** SHA256 bearer tokens for additional security layer
- **CKD Support:** Confidential Key Derivation via NEAR MPC Network for deterministic secrets

## API Endpoints

### `GET /health`

In TEE mode (`USE_TEE_REGISTRATION=true`) the HTTP port is bound only after the instance is ready
(DAO approval + MPC-derived master); until then connections are refused. This is what lets the
dstack gateway balance one hostname across several instances of a version: an instance that is
still waiting for its vote is simply not connectable.
Liveness only, no auth. Deliberately carries nothing about fleet state — see
`/admin/loaded-vaults` for that.

**Response:**
```json
{
  "status": "ok",
  "tee_mode": "OutlayerTee"
}
```

### `POST /pubkey`
Get keystore public key. Public for `vault_id = null`; a vault-scoped request requires a
coordinator or worker token, because it can trigger an on-chain CKD derivation paid by that
vault.

**Response:**
```json
{
  "public_key_hex": "a1b2c3d4...",
  "public_key_base58": "Ed25519:..."
}
```

### `POST /decrypt`
Decrypt secrets for verified TEE worker (requires auth)

**Headers:**
```
Authorization: Bearer <worker-token>
X-TEE-Session: <session-id>
```

**Request:**
```json
{
  "encrypted_secrets": "base64-encoded-ciphertext",
  "task_id": "optional-task-id"
}
```

**Response:**
```json
{
  "plaintext_secrets": "base64-encoded-plaintext"
}
```

**Error Response:**
```json
{
  "error": "TEE session not found"
}
```

## Configuration

Create a `.env` file (see `.env.example`):

```bash
# Server
SERVER_HOST=0.0.0.0
SERVER_PORT=8081

# NEAR Configuration
NEAR_NETWORK=testnet
NEAR_RPC_URL=https://rpc.testnet.fastnear.com/?apiKey=<your-fastnear-key>
OFFCHAINVM_CONTRACT_ID=outlayer.testnet

# Keystore account (must be authorized in contract)
KEYSTORE_ACCOUNT_ID=keystore.testnet
KEYSTORE_PRIVATE_KEY=ed25519:...

# NEAR RPC Client (for reading secrets from contract)
# Both are REQUIRED for repo-based secrets to work:
NEAR_CONTRACT_ID=outlayer.testnet

# Master Secret for Key Derivation
# Generate: openssl rand -hex 32
KEYSTORE_MASTER_SECRET=your_master_secret_hex_64_chars
# optional, non-TEE only: where a generated master is written instead of stderr
KEYSTORE_MASTER_SECRET_OUT_PATH_NON_TEE=/path/to/master.env

# Worker authentication (SHA256 hashes of bearer tokens)
ALLOWED_WORKER_TOKEN_HASHES=hash1,hash2,hash3

# TEE mode (sgx|sev|simulated|none)
TEE_MODE=none

# Logging
RUST_LOG=info,keystore_worker=debug
```

## Setup

### 1. Generate Keystore Account and Key

```bash
# Create a new NEAR account for keystore
near create-account keystore.testnet --useFaucet

# Generate a new keypair (this will be stored in ~/.near-credentials)
# Or use an existing key from the credentials file
```

### 2. Generate Worker Auth Tokens

```bash
# Generate a secure random token
TOKEN=$(openssl rand -hex 32)
echo "Worker token: $TOKEN"

# Hash it with SHA256
TOKEN_HASH=$(echo -n "$TOKEN" | sha256sum | cut -d' ' -f1)
echo "Token hash (add to .env): $TOKEN_HASH"
```

Add the hash to `ALLOWED_WORKER_TOKEN_HASHES` in `.env`:
```
ALLOWED_WORKER_TOKEN_HASHES=cbd8f6f0e3e8ec29d3d1f58a2c8c6d6e8d7f5a4b3c2d1e0f1a2b3c4d5e6f7a8b
```

Workers will use the original token (not the hash) in their requests:
```
Authorization: Bearer <original-token>
```

### 3. Configure Contract

The keystore worker will verify that its public key matches the contract's stored key on startup. You need to set the public key in the contract first:

```bash
# Get the public key from keystore worker startup logs or /pubkey endpoint
# Then call contract method:
near contract call-function as-transaction outlayer.testnet set_keystore_pubkey json-args '{"pubkey_hex":"a1b2c3d4..."}' prepaid-gas '30.0 Tgas' attached-deposit '0 NEAR' sign-as keystore.testnet network-config testnet sign-with-keychain send
```

### 4. Run Keystore Worker

```bash
cd keystore-worker

# Install dependencies
cargo build --release

# Run
cargo run --release

# Or run directly
./target/release/keystore-worker
```

You should see:
```
INFO  Starting NEAR OutLayer Keystore Worker
INFO  Keystore initialized, public_key=a1b2c3d4...
INFO  ✓ Public key verified - matches contract
INFO  Keystore worker API server started, addr=0.0.0.0:8081
INFO  Ready to serve decryption requests from executor workers
```

## Deploying

**Keystore first, then the workers for it.** A worker has its keystore instances baked in
(`KEYSTORE_BASE_URLS`, all of one version), so it only ever talks to keystores it was deployed
for — the new worker needs those keystores to already exist. The same pinning is why the two can
change their shared request shape in a single release with no deprecation window: a worker never
meets a keystore of a different version. With several instances listed the worker holds a TEE
session on the one serving it and moves to the next only when that one becomes unreachable.

Restarting the keystore mints a fresh ephemeral registration key and needs a DAO vote within
~30 minutes, so schedule the release when a voter is on hand. Retire the previous version's
keys afterwards: paste the `export KEEP_DAL=…` / `export KEEP_AMS=…` lines that
`outlayer keystore-keys <net>` prints on the nodes, then run `scripts/revoke_old_keystore_keys.sh <network>`.

## Testing

### Test Health Endpoint

```bash
curl http://localhost:8081/health
```

### Managing Secrets

Use the **Dashboard UI** at http://localhost:3000/secrets to:
- Create/edit/delete secrets with JSON format
- Configure access control (AllowAll, Whitelist, NEAR/FT/NFT balance)
- Client-side ChaCha20-Poly1305 encryption

Secrets are encrypted in browser and stored on contract.

## TEE Integration

### Current Status
- ✅ Production TEE via Intel TDX (Phala Network)
- ✅ Worker TEE sessions (challenge-response over a key held on the operator account)
- ✅ Worker registration with on-chain verification
- ✅ Masters never persisted: the default master is CKD-derived at boot, per-vault masters on
  first touch, and the registration keypair lives only in memory

### Alternative TEE Deployment Options

**Intel SGX:**
1. Add dependency: `sgx_tstd`, `sgx_types`
2. Implement sealed storage in `initialize_keystore()`
3. Integrate Intel Attestation Service (IAS) or DCAP
4. Build with `cargo build --target x86_64-fortanix-unknown-sgx`

**AMD SEV-SNP:**
1. Add dependency: `sev` crate
2. Implement SEV attestation verification
3. Use SNP guest tools for attestation generation
4. Build with appropriate target

**Key Changes for TEE:**
- Implement sealed storage for private key persistence
- Add remote attestation with hardware root of trust

(AEAD encryption and X25519 ECDH were previously listed here as pending; both are
implemented — see `src/crypto.rs`.)

## Confidential Key Derivation (CKD)

### Overview

The keystore integrates with NEAR's **Confidential Key Derivation (CKD)** - an advanced cryptographic primitive that leverages the NEAR MPC Network to provide deterministic secrets for TEE applications. Unlike traditional key derivation, CKD uses distributed computation where multiple MPC nodes collaborate to generate secrets without any single node knowing the final value.

### How It Works with MPC Network

```
TEE App → Developer Contract → MPC Contract → MPC Network
    ↑                                               ↓
    └─── Encrypted Secret (Y, C) ←─────────────────┘

No single MPC node knows the final secret!
```

The CKD protocol flow:
1. TEE app generates fresh ElGamal key pair (a, A) and includes A in attestation
2. Developer contract validates TEE attestation and calls MPC contract
3. Each MPC node computes partial BLS signature using its secret share
4. Coordinator aggregates encrypted shares into (Y, C)
5. Only the TEE app can decrypt using private key a to get final secret

### Security Properties

1. **Deterministic** - Same app_id always produces the same secret
2. **Private** - Secret known only to the requesting TEE app
3. **Distributed** - No single MPC node has the complete secret
4. **TEE-protected** - Secrets computed and used only inside secure enclaves
5. **Threshold security** - Requires t-of-n MPC nodes to cooperate

### Cryptographic Foundation

- **BLS signatures** on pairing-friendly BLS12-381 curves
- **ElGamal encryption** for secure transport
- **HKDF** for final key derivation
- **Threshold cryptography** ensuring no single point of failure

### Use Case: Persistent Secrets

When a user stores secrets for their repository:
1. Keystore derives a unique child key for that repo
2. Secrets are encrypted with the child key
3. After keystore restart, the same child key can be regenerated
4. Secrets remain accessible without storing any keys on disk

### Implementation

The CKD is implemented using HMAC-SHA256 with domain separation:

```rust
// Derive child key for a specific repository
let child_key = hmac_sha256(
    master_key,
    format!("keystore-ckd:{}:{}", repo_url, owner)
);
```

This ensures:
- **No key reuse** across different repositories
- **Consistent keys** for the same repository
- **Cryptographic isolation** between users and repos

### Benefits

1. **No key management overhead** - Only derivation key needs protection
2. **Automatic key rotation** - Change derivation key to rotate all derived keys
3. **Audit trail** - Can track which repos had keys derived
4. **Compliance** - Keys are never persisted, only derived when needed

## Security Considerations

### Current Implementation

Production-ready security features:

1. **TEE:** Intel TDX via Phala Network with hardware attestation
2. **Attestation:** On-chain verification via worker registration contract
3. **Key Storage:** TEE sealed storage with hardware binding
4. **Encryption:** ECIES — ephemeral X25519 ECDH + HKDF-SHA256 + ChaCha20-Poly1305
   AEAD. Wire format: `[0x01 | ephemeral_pubkey(32) | nonce(12) | ciphertext | tag(16)]`.
   Only the TEE holds the private key; the key published by `/pubkey` can encrypt but
   not decrypt.

### Security Best Practices

- Keystore runs exclusively in TEE environment
- Worker registration verified on-chain before execution
- Access control validated for each secret request
- Rate limiting at coordinator level
- Audit logging for all decrypt operations
- Monitoring and alerting via coordinator

### Adding a key family

Every key this keystore holds is `HMAC-SHA256(master, seed)` over a seed
STRING, and the two curves — ed25519 (`derive_keypair`) and secp256k1
(`derive_secp256k1_keypair`) — feed the seed into the HMAC without a curve tag.
So two seeds that are the same string are the same key, whatever curve or
endpoint asked for it. The seed namespace is flat, and what keeps families of
keys apart is only the shape of their strings. Three consequences for anyone
adding a family:

1. **Know which endpoints hand out private material.** Today exactly one does:
   `/wallet/derive-ephemeral-key` (payment checks). It builds
   `wallet:{id}:{chain}:{sub_path}` from two request strings and returns the
   private key. Any signing key whose seed that endpoint could spell is a
   signing key it can export. The families it cannot reach are: two-segment
   seeds under `wallet:` (it always appends a non-empty third segment), and
   anything under a different root.

2. **Give a new signing family its own root, not a level under `wallet:`.**
   EVM sub-keys are `subkey:{id}:evm:{sub_path}` for this reason alone — under
   `wallet:{id}:evm:{sub_path}` they would be reachable through the exporter
   with `chain=evm`. A root is separation by construction; a validation rule on
   the exporter is separation by a check somebody has to remember. Prefer the
   root. (Separating at the HMAC level with a domain tag, as `secret-path:` and
   `ecies:` do, is stronger still, but rotates every existing key of the family
   it is applied to — fine for a new family, never for an old one.)

3. **Keep `:` out of caller-supplied path segments.** `:` is the segment
   separator of every seed; a path that may contain it can spell a deeper level
   (`validate_sub_path` refuses it). Validate the shape, do not normalise it: two
   spellings that derive one key, or one that derives a different key than the
   caller wrote, are both silent.

`no_exportable_seed_can_name_a_signing_key` in `api.rs` encodes the invariant:
add the new family's seed to that test before adding the family.

## Troubleshooting

### "Public key mismatch" error on startup

**Cause:** The keystore's private key doesn't match the public key stored in the contract.

**Fix:**
1. Check `KEYSTORE_PRIVATE_KEY` is correct
2. Check `OFFCHAINVM_CONTRACT_ID` points to the right contract
3. Call `set_keystore_pubkey` on contract with correct public key
4. Or generate a new keystore and update contract

### "TEE session not found" / "session expired"

**Cause:** The keystore has no live session for this worker — it restarted (sessions live in
memory only), or the worker never completed the challenge-response handshake.

**Fix:**
1. The worker re-registers automatically on this error for `/decrypt`, `/encrypt` and
   `/decrypt-raw`; check its logs for a failed re-handshake and its cause
2. Verify the worker's key is still an access key on the operator account (removed keys, e.g.
   by `remove_worker_keys`, invalidate the handshake)
3. Jobs that were mid-execution when the keystore restarted fail by design — retry them

### "Unauthorized" error

**Cause:** Worker token is invalid or not in allowed list.

**Fix:**
1. Check worker has correct `KEYSTORE_AUTH_TOKEN` in its `.env`
2. Verify token hash is in keystore's `ALLOWED_WORKER_TOKEN_HASHES`
3. Token must match exactly (including whitespace)

## Performance

**Expected throughput:**
- ~1000 decrypt operations/second (single worker, no TEE overhead)
- ~100-500 ops/sec with SGX attestation verification
- Linear scaling with CPU cores (tokio async runtime)

**Latency:**
- < 1ms for decryption operation (X25519 ECDH + ChaCha20-Poly1305)
- ~10-50ms with SGX remote attestation
- Network latency depends on deployment topology

## Development

### Run tests
```bash
cargo test
```

### Run with debug logging
```bash
RUST_LOG=debug cargo run
```

### Build for production
```bash
cargo build --release
```

## License

MIT (same as parent project)
