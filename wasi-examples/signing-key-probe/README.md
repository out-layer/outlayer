# signing-key-probe

A WASI module whose only job is exercising the `outlayer:signing-keys` host
functions: `public-key(path, vault)` and `sign(path, vault, message)`. It
imports that interface and WASI, nothing else.

The rules it exercises — `signing_keys` in the manifest, `bind`, `caller`,
`vault`, how a key is issued — are in
[`CONNECTOR_MANIFEST.md`](../CONNECTOR_MANIFEST.md), section `signing_keys`.

## Why it is not part of `wallet-probe`

A module that imports `outlayer:wallet` is refused at startup when the request
names no wallet (see [`wallet-probe/README.md`](../wallet-probe/README.md)). A
signing key needs no wallet: it works from an on-chain `request_execution` as
well as over HTTPS with an ordinary payment key. Putting the import here next
to the wallet one would have tied every run of this probe to a wallet it does
not use.

## The builds

One manifest per build, picked by a cargo feature (`manifests/`):

| Build (`target/variants/`) | Feature | Keys | Run it as |
|---|---|---|---|
| `signing-key-probe-project.wasm` | `project` (default) | `alpha`, `beta` — `bind: "project"` | a project version (WasmUrl) |
| `signing-key-probe-project-v2.wasm` | `project,v2` | the same | a second version of that project |
| `signing-key-probe-wasm.wasm` | `wasm` | `code` — `bind: "wasm"` | a direct run of its wasm URL |
| `signing-key-probe-wasm-v2.wasm` | `wasm,v2` | the same | a direct run — another build, another key |
| `signing-key-probe-project-vault.wasm` | `project-vault` | `alpha`, and `treasury` with vault `vault.alice.near` | the worker's component tests |

`v2` changes one constant, so the same manifest has a second sha256.

```bash
./build.sh
```

builds all five and checks each: the `outlayer.manifest` section is in the
artefact and is that build's; the module imports `outlayer:signing-keys/api`
and nothing of ours besides WASI; the two builds of one manifest are two hashes;
`wit/signing-keys.wit` has not drifted from the worker's
`worker/wit/deps/signing-keys.wit`. It also reports whether the manifest
survives `wasm-tools strip`, the step the platform applies to a GitHub build of
a `wasm32-wasip2` component.

## Not a connector

No `connector_id`: an ordinary project. `"network": []` is declared, so the
probe reaches no network, and the signing is done by host functions.

Deploy it under an ordinary account (`you.testnet/signing-key-probe`), not the
connectors namespace — for the reason given in `wallet-probe/README.md`.

## Calling it

A `bind: "project"` build runs through its project, on chain or over HTTPS:

```bash
curl -s -X POST "https://testnet-api.outlayer.ai/call/you.testnet/signing-key-probe" \
  -H "X-Payment-Key: $PAYMENT_KEY" -H 'Content-Type: application/json' \
  -d '{"input":{"operation":"all_public_keys"}}'
```

A `bind: "wasm"` build runs directly from its wasm URL, on chain
(`request_execution` with a `WasmUrl` source, or `outlayer run --wasm <url>`).
Run the other way round, either build is refused before it starts; so is any
build of this code from a GitHub repository.

Every key these builds declare is a `caller: "signer"` key (the default): bound
to the transaction's signer on chain, the payment key's owner over HTTPS. A
`caller: "predecessor"` key would bind to the account that called the contract
instead — a DAO, a wallet contract — and refuse a run that carries none; no
build here declares one.

The `sign` operation signs whatever `message_hex` it is handed. That is what a
probe is for; a module in production signs only messages it composes itself,
never caller-supplied bytes — the key's public key is a real NEAR implicit
account.

## Operations

Input is one JSON object with `operation`. Every answer carries `status`
(`ok`, `err`, or `n/a`), `message`, `operation` and `build`. A refusal from the
host is an `err` answer, never a failed run.

| `operation` | Fields | Answers |
|---|---|---|
| `public_key` | `path`, `vault?` | `public_key` (hex) |
| `sign` | `path`, `vault?`, `message_hex` | `signature`, `public_key` (hex) |
| `sign_and_verify` | `path`, `vault?`, `message_hex` | as `sign`, plus `verified` and `tampered_rejected`, checked inside the guest |
| `sign_nep413` | `path`, `vault?`, `message`, `recipient`, `nonce_hex` (32 bytes), `callback_url?` | `accountId`, `publicKey`, `signature` — the shape of a wallet's `signMessage` |
| `all_public_keys` | — | `keys: {path: {vault, public_key}}` for every declared key |
| `what_i_can_see` | `scan_masked_hex?` | every environment variable and its value, the arguments, stdin as it arrived, the working directory, the filesystem listing, the size of linear memory — and, for each needle (hex of the bytes XOR `0x5a`), how many times it occurs in the module's own memory. Every declared key is used first, in the same run |
| `attack` | `name` | one of the attacks below |
| `attacks` | — | all of them, `results: [{name, status, message}]` |

`vault` is the key's declared vault: omit it for a key declared without one.

### Attacks

| `name` | Expected |
|---|---|
| `undeclared_path` | `err` |
| `empty_path` | `err` |
| `colon_path` — `<first path>:x` | `err` |
| `traversal_path` — `../<first path>` | `err` |
| `huge_path` — 1 MiB | `err`, and the reason does not echo it |
| `oversized_message` — 65537 bytes | `err` |
| `message_at_cap` — 65536 bytes | `ok`, and the signature verifies |
| `vault_when_none_declared` | `err` |
| `vault_missing_when_declared` | `err` (`n/a` in a build with no vaulted key) |
| `vault_wrong_when_declared` | `err` (`n/a` in a build with no vaulted key) |
| `determinism` — two calls, one answer | `ok` |

## `sign_nep413`: a NEP-413 signature from a signing key

The part meant to be copied. A NEP-413 (`signMessage`) signature is ed25519
over `sha256(borsh(2^31 + 413) ++ borsh(payload))`; `sign` signs raw bytes, so
the guest builds the payload, hashes it, and signs the hash. The result has the
shape a NEAR wallet's `signMessage` answers, so anything that verifies a
wallet's NEP-413 signature verifies this one:

```toml
[dependencies]
borsh = { version = "1", features = ["derive"] }
sha2 = "0.10"
bs58 = "0.5"
base64 = "0.22"
hex = "0.4"
serde = { version = "1.0", features = ["derive"] }
```

```rust
// `signing_keys` is the generated `outlayer:signing-keys` binding (src/main.rs).

/// NEP-413's prefix, borsh-serialized as a little-endian u32 in front of the
/// payload, so the signed bytes can never be a valid NEAR transaction.
const NEP413_TAG: u32 = (1 << 31) + 413;

/// The payload in the specification's field order: borsh encodes fields in
/// declaration order, so the order is part of the format.
#[derive(borsh::BorshSerialize)]
struct Nep413Payload {
    message: String,
    nonce: [u8; 32],
    recipient: String,
    callback_url: Option<String>,
}

/// What a wallet's `signMessage` answers.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct Nep413Signed {
    account_id: String, // the implicit account: the public key, lowercase hex
    public_key: String, // "ed25519:" + base58
    signature: String,  // base64 of the 64 bytes
}

fn nep413_hash(payload: &Nep413Payload) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut bytes = borsh::to_vec(&NEP413_TAG).expect("a u32 serializes");
    bytes.extend(borsh::to_vec(payload).expect("the payload serializes"));
    Sha256::digest(&bytes).into()
}

fn sign_nep413(path: &str, vault: Option<&str>, payload: &Nep413Payload) -> Result<Nep413Signed, String> {
    use base64::Engine;
    let signature = signing_keys::sign(path, vault, &nep413_hash(payload))?;
    let public_key = signing_keys::public_key(path, vault)?;
    Ok(Nep413Signed {
        account_id: hex::encode(&public_key),
        public_key: format!("ed25519:{}", bs58::encode(&public_key).into_string()),
        signature: base64::engine::general_purpose::STANDARD.encode(signature),
    })
}
```

Called:

```json
{"input": {"operation": "sign_nep413", "path": "alpha",
           "message": "Login to example.com", "recipient": "example.com",
           "nonce_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"}}
```

Verified anywhere, without the probe (Python: `struct` for borsh, PyNaCl):

```python
import base64, hashlib, struct
from nacl.signing import VerifyKey

def borsh_string(s): return struct.pack('<I', len(s)) + s
def nep413_hash(message, nonce, recipient, callback_url=None):
    payload = borsh_string(message.encode()) + nonce + borsh_string(recipient.encode())
    payload += b'\x00' if callback_url is None else b'\x01' + borsh_string(callback_url.encode())
    return hashlib.sha256(struct.pack('<I', 2**31 + 413) + payload).digest()

h = nep413_hash("Login to example.com", bytes(range(32)), "example.com")
VerifyKey(bytes.fromhex(answer["accountId"])).verify(h, base64.b64decode(answer["signature"]))  # raises on a bad signature
```

`accountId` is the key's NEAR implicit account. The `nonce` is the verifier's:
it chooses it, and refuses one it has seen before.

## What checks it

* `cargo test` here — the NEP-413 hash against a vector computed independently
  in Python, and the borsh bytes spelled out.
* `worker/tests/signing_key_probe.rs` — every build through the executor with
  injected keys: every operation, the pinned public key and signatures, an
  independent ed25519 and NEP-413 verification, every attack and vault
  mismatch, no seed byte in the environment, stdin or linear memory, and a
  module that declares keys and is handed none refused before it runs.
* `tests/signing_keys_e2e.sh` — the same against a deployed worker and
  keystore, on testnet.
