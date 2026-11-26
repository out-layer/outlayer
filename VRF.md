# OutLayer VRF — Verifiable Random Function

Cryptographically provable randomness for NEAR smart contracts.
Anyone can verify the proof on-chain: the output was produced by OutLayer's VRF key for exactly this alpha, and cannot have been re-rolled. That the output was unpredictable rests on the VRF key staying inside attested enclaves — see [Unpredictable without the key](#2-unpredictable-without-the-key).

## How it works

```
WASI Module                    Worker (TEE)                  Keystore (TEE)
    |                              |                              |
    |  vrf::random("coin-flip")    |                              |
    |----------------------------->|                              |
    |                              |  alpha = "vrf:42:alice.near:coin-flip"
    |                              |  POST /vrf/generate {alpha}  |
    |                              |----------------------------->|
    |                              |                              |  signature = Ed25519_sign(vrf_sk, alpha)
    |                              |                              |  output    = SHA256(signature)
    |                              |  {output_hex, signature_hex} |
    |                              |<-----------------------------|
    |  VrfOutput {                 |
    |    output_hex,               |
    |    signature_hex,            |
    |    alpha                     |
    |  }                           |
    |<-----------------------------|

On-chain verification:
    env::ed25519_verify(signature, alpha.as_bytes(), vrf_pubkey)  // native NEAR host function
```

### Alpha format

```
vrf:{request_id}:{sender_id}:{user_seed}
```

- **request_id** — the contract's request id (on-chain request) or the numeric request id the coordinator assigns to an HTTPS call. Auto-injected by worker, WASM cannot set it.
- **sender_id** — the paying account: the transaction's sender (blockchain) or the payment key owner (HTTPS). It is not the bound name a `use_bound_identity` run uses. Auto-injected by worker.
- **user_seed** — arbitrary string from developer's WASM module. Must not contain `:`.

Example: `vrf:98321:alice.near:coin-flip`

### Cryptographic primitives

| Primitive | Usage |
|-----------|-------|
| HMAC-SHA256 | Key derivation: `HMAC-SHA256(master_secret, "vrf-key")` → 32 bytes → Ed25519 keypair |
| Ed25519 (RFC 8032) | Deterministic signature: `sign(vrf_sk, alpha)` → 64-byte signature |
| SHA-256 | Output derivation: `SHA256(signature)` → 32-byte random output |

## Security properties

### 1. Deterministic — no re-rolling

Ed25519 signatures are deterministic per RFC 8032. Same key + same alpha = same signature = same output. The worker cannot retry to get a different result.

### 2. Unpredictable without the key

The VRF private key is derived inside the keystore TEE (Intel TDX) from the keystore's shared master secret via `HMAC-SHA256(master_secret, "vrf-key")` — always the default OutLayer master, never a customer vault's. The master secret is issued by the NEAR MPC network (chain-key derivation), where no single node holds it.

Stage caveat: `dao.outlayer.near` currently also carries a full-access key that can obtain the shared master outside an enclave, and measurement approval is owner-only (see [docs/NON_CUSTODIAL.md](docs/NON_CUSTODIAL.md#governance-at-this-stage)). Whoever holds the master can compute the VRF output for any alpha in advance. Verification proves the output was not re-rolled; it does not prove nobody could predict it.

### 3. Non-manipulable alpha

The WASM module only provides `user_seed`. The worker auto-prepends `request_id` and `sender_id`. The WASM guest cannot change these values. On an on-chain request `request_id` comes from the contract's event; on an HTTPS call it is assigned by the coordinator.

This means:
- Same seed by different users → different output (sender_id differs)
- Same seed in different requests → different output (request_id differs)
- A WASM module cannot forge an alpha to replay a previous result

### 4. Publicly verifiable

Anyone can verify the VRF output — no trust in the TEE required:

```
ed25519_verify(vrf_pubkey, alpha, signature) == true
SHA256(signature) == output
```

The VRF public key is available at `GET /vrf/pubkey` and can be hardcoded in smart contracts.

### 5. Consistent across keystore instances

All keystore instances derive the VRF keypair from the same master secret with the fixed seed `"vrf-key"`. This means:
- All instances produce the same VRF public key
- Any instance can generate the same output for the same alpha
- Keystore restarts don't change the key (the key changes only if the master secret does)

### 6. Rate-limited

Max 10 VRF calls per WASM execution. Prevents abuse of the signing endpoint.

## Developer guide

### SDK usage (Rust WASI module)

Add `outlayer` to your `Cargo.toml`:

```toml
[dependencies]
outlayer = "0.2"
```

Generate random output:

```rust
use outlayer::vrf;

// Get verifiable random output
let result = vrf::random("my-seed")?;
println!("Random: {}", result.output_hex);       // SHA256(signature), 32 bytes hex
println!("Proof:  {}", result.signature_hex);     // Ed25519 signature, 64 bytes hex
println!("Alpha:  {}", result.alpha);             // "vrf:{request_id}:{sender_id}:my-seed"

// Or get raw bytes
let (bytes, signature_hex, alpha) = vrf::random_bytes("my-seed")?;
// bytes: [u8; 32] — use for random number generation

// Get VRF public key (for including in output)
let pubkey = vrf::public_key()?;
```

Map to a range (e.g. 0..=99):

```rust
let result = vrf::random("roll")?;
let first_4_bytes = u32::from_be_bytes(hex_to_bytes(&result.output_hex[..8]));
let roll = (first_4_bytes as u64 * 100 / (u32::MAX as u64 + 1)) as u32; // 0..=99
```

Multiple independent random values — use unique sub-seeds:

```rust
for i in 0..5 {
    let result = vrf::random(&format!("card:{}", i))?;
    // Each call gets a unique alpha → unique output
}
```

### Constraints

- `user_seed` must not contain `:` (used as alpha delimiter)
- Max 10 VRF calls per execution
- VRF requires the keystore — the module must run on OutLayer workers (a component that imports `near:vrf/api` fails to start where VRF is unavailable)

### On-chain verification (NEAR smart contract)

```rust
use near_sdk::env;

fn verify_vrf(
    vrf_pubkey: &[u8; 32],   // from GET /vrf/pubkey or hardcoded
    alpha: &str,              // from VRF output
    signature: &[u8; 64],    // from VRF output (signature_hex decoded)
) -> bool {
    // NEAR native ed25519_verify
    env::ed25519_verify(signature, alpha.as_bytes(), vrf_pubkey)
}
```

Full contract example — see [wasi-examples/vrf-example/vrf-contract/](https://github.com/out-layer/vrf-example/tree/main/vrf-contract/).

### Deploying a contract with VRF

**Step 1.** Get the VRF public key:

```bash
# Mainnet
curl -s https://api.outlayer.ai/vrf/pubkey | jq -r .vrf_public_key_hex

# Testnet
curl -s https://testnet-api.outlayer.ai/vrf/pubkey | jq -r .vrf_public_key_hex
```

**Step 2.** Initialize contract with the pubkey:

```bash
near call my-vrf.near new '{
  "outlayer_contract_id": "outlayer.near",
  "project_id": "alice.near/vrf-ark",
  "vrf_pubkey_hex": "a1b2c3d4..."
}' --accountId my-vrf.near
```

**Step 3.** Verify it was stored:

```bash
near view my-vrf.near get_vrf_pubkey
# "a1b2c3d4..."
```

If the keystore rotates the VRF key (rare), update via `set_vrf_pubkey` (contract owner only):

```bash
near call my-vrf.near set_vrf_pubkey '{"vrf_pubkey_hex": "new_key_hex..."}' --accountId my-vrf.near
```

### Complete example: coin flip with on-chain verification

**WASI module** — generates VRF random number:
```rust
use outlayer::vrf;

let result = vrf::random("coin-flip")?;
// Map to 0 (Heads) or 1 (Tails)
let bytes = u32::from_be_bytes(/* first 4 bytes of output_hex */);
let side = (bytes as u64 * 2 / (u32::MAX as u64 + 1)) as u32;
```

**NEAR contract** — requests execution and verifies:
```rust
// 1. Request execution
ext_outlayer::ext(outlayer_contract_id)
    .with_attached_deposit(NearToken::from_millinear(10))
    .request_execution(
        json!({"Project": {"project_id": "alice.near/vrf-ark"}}),
        Some(resource_limits),
        Some(r#"{"seed":"coin-flip","max":1}"#.to_string()),
        None,
        Some("Json".to_string()),
        Some(player.clone()),
    )
    .then(ext_self::ext(current_account_id()).on_vrf_result(player, choice));

// 2. In callback — verify proof
let entry = &vrf_response.results[0];
let sig_bytes: [u8; 64] = hex::decode(&entry.signature_hex).try_into().unwrap();
let valid = env::ed25519_verify(&sig_bytes, entry.alpha.as_bytes(), &self.vrf_pubkey);
assert!(valid, "VRF proof verification failed");
```

## User verification guide

### 1. Get the VRF public key

```bash
curl https://api.outlayer.ai/vrf/pubkey
# {"vrf_public_key_hex":"a1b2c3d4..."}  (64 hex chars = 32 bytes)
```

### 2. Verify Ed25519 signature

Given a VRF result:
```json
{
  "value": 0,
  "signature_hex": "abcd...1234",
  "alpha": "vrf:98321:alice.near:coin-flip"
}
```

**Python (PyNaCl):**
```python
from nacl.signing import VerifyKey
import hashlib

vrf_pubkey_hex = "..."   # from /vrf/pubkey
signature_hex = "..."     # from result
alpha = "vrf:98321:alice.near:coin-flip"

vrf_pubkey = bytes.fromhex(vrf_pubkey_hex)
signature = bytes.fromhex(signature_hex)

# Verify: Ed25519 signature over alpha
verify_key = VerifyKey(vrf_pubkey)
verify_key.verify(alpha.encode(), signature)  # raises if invalid
print("Signature VALID")

# Verify: output = SHA256(signature)
output = hashlib.sha256(signature).hexdigest()
print(f"Output: {output}")

# If mapped to range: first 4 bytes → u32 → scale
first_4 = int(output[:8], 16)
mapped = first_4 * (max_value + 1) // (2**32)
print(f"Mapped value: {mapped}")
```

**JavaScript (tweetnacl):**
```javascript
import nacl from 'tweetnacl';
import { createHash } from 'crypto';

const vrfPubkey = Buffer.from(vrfPubkeyHex, 'hex');
const signature = Buffer.from(signatureHex, 'hex');
const alpha = Buffer.from('vrf:98321:alice.near:coin-flip');

// Verify signature
const valid = nacl.sign.detached.verify(alpha, signature, vrfPubkey);
console.log('Valid:', valid);

// Verify output
const output = createHash('sha256').update(signature).digest('hex');
console.log('Output:', output);
```

**NEAR contract (on-chain):**
```rust
let valid = env::ed25519_verify(&signature_bytes, alpha.as_bytes(), &vrf_pubkey_bytes);
```

### 3. Verify alpha integrity

The alpha `vrf:{request_id}:{sender_id}:{user_seed}` contains:
- **request_id** — visible in the `execution_requested` event of the `request_execution` call (on-chain requests; for an HTTPS call it is the coordinator's id and cannot be checked against the chain)
- **sender_id** — the account that paid for the request
- **user_seed** — the seed from the WASM input

Reconstruct and compare:
```python
expected_alpha = f"vrf:{request_id}:{sender_id}:{user_seed}"
assert alpha == expected_alpha, "Alpha mismatch — possible tampering"
```

### Verification checklist

1. `ed25519_verify(vrf_pubkey, alpha, signature)` — signature is valid
2. `SHA256(signature) == output_hex` — output matches signature
3. Alpha contains correct `request_id` from the blockchain event (on-chain requests)
4. Alpha contains correct `sender_id` (the caller)
5. VRF public key matches `GET /vrf/pubkey`

If all 5 checks pass, the output is the one OutLayer's VRF key gives for this alpha: it was not re-rolled or swapped after the fact. Unpredictability depends on the key's custody (see above).

## API reference

| Endpoint | Method | Auth | Response |
|----------|--------|------|----------|
| `/vrf/pubkey` | GET | Public | `{"vrf_public_key_hex": "..."}` |

SDK functions:

| Function | Returns | Description |
|----------|---------|-------------|
| `vrf::random(seed)` | `Result<VrfOutput>` | Random output + proof |
| `vrf::random_bytes(seed)` | `Result<([u8; 32], String, String)>` | Raw bytes + signature + alpha |
| `vrf::public_key()` | `Result<String>` | VRF public key hex |

## Source code

- Crypto: [keystore-worker/src/crypto.rs](keystore-worker/src/crypto.rs) — `vrf_generate`, `vrf_public_key_hex`
- Host functions: [worker/src/outlayer_vrf/host_functions.rs](worker/src/outlayer_vrf/host_functions.rs)
- SDK: [sdk/outlayer/src/vrf.rs](sdk/outlayer/src/vrf.rs)
- WIT interface: [sdk/outlayer/wit/deps/vrf.wit](sdk/outlayer/wit/deps/vrf.wit)
- Example WASI: [wasi-examples/vrf-example/](https://github.com/out-layer/vrf-example/)
- Example contract: [wasi-examples/vrf-example/vrf-contract/](https://github.com/out-layer/vrf-example/tree/main/vrf-contract/)
