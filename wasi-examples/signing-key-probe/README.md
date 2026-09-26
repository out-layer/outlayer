# signing-key-probe

A WASI module whose only job is exercising the `outlayer:signing-keys` host
functions — `public-key(path, vault)`, `sign(path, vault, message)` and
`sign-nep413(path, vault, message, recipient, nonce, callback-url)` — and,
in its encryption builds, the `outlayer:encryption-keys` host functions —
`encrypt`, `decrypt` and `mac` — and, in its two `encryption-storage` builds, raw
storage (`near:storage`'s `-raw` functions) and records sealed with an
encryption key and stored raw. It imports those interfaces and WASI, nothing
else.

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
| `signing-key-probe-project-pred.wasm` | `project-pred` | `alpha` — `caller: "predecessor"`, `bind: "project"` | a version of the same project |
| `signing-key-probe-wasm.wasm` | `wasm` | `code` — `bind: "wasm"` | a direct run of its wasm URL |
| `signing-key-probe-wasm-v2.wasm` | `wasm,v2` | the same | a direct run — another build, another key |
| `signing-key-probe-project-vault.wasm` | `project-vault` | `alpha`, and `treasury` with vault `vault.alice.near` | the worker's component tests |
| `signing-key-probe-project-secp.wasm` | `project-secp` | `evm` (`secp256k1`) and `alpha` (`ed25519`) — `bind: "project"` | a project version (WasmUrl) |
| `signing-key-probe-wasm-secp.wasm` | `wasm-secp` | `code-evm` (`secp256k1`) — `bind: "wasm"` | a direct run of its wasm URL |
| `signing-key-probe-encryption.wasm` | `encryption` | signing `alpha`; encryption `alpha`, `beta` — `bind: "project"` | a project version (WasmUrl) |
| `signing-key-probe-encryption-v2.wasm` | `encryption,v2` | the same | a second version of that project |
| `signing-key-probe-encryption-storage.wasm` | `encryption-storage` | the `encryption` build's keys, and `near:storage` | a version of the same project |
| `signing-key-probe-encryption-storage-pred.wasm` | `encryption-storage-pred` | the same, with `storage_account: "predecessor"` | a version of the same project |
| `signing-key-probe-encryption-wasm.wasm` | `encryption-wasm` | encryption `code` — `bind: "wasm"` | a direct run of its wasm URL |
| `signing-key-probe-encryption-wasm-v2.wasm` | `encryption-wasm,v2` | the same | a direct run — another build, another key |
| `signing-key-probe-encryption-vault.wasm` | `encryption-vault` | encryption `alpha`, and `treasury` with vault `vault.alice.near` | a project version whose owner has that vault |
| `signing-key-probe-encryption-pred.wasm` | `encryption-pred` | encryption `alpha` — `caller: "predecessor"`, `bind: "project"` | a project version |
| `signing-key-probe-encryption-typed.wasm` | `encryption-typed` | encryption `alpha` with a `type` member | refused before it runs, however it is run |

`v2` changes one constant, so the same manifest has a second sha256. Only the
encryption builds import `outlayer:encryption-keys`; the `encryption` build
declares `alpha` in both families, which are two unrelated keys.

Only the two `encryption-storage` builds import `near:storage`. Storage exists only on a run
through a project, and the worker refuses a module that imports it on any other
run — so no build meant for a direct run may import it — and a module that
imports it does not start in the worker's executor tests without a storage
client. Its keys are declared exactly as the `encryption` build's, so as a
version of the same project it holds the same keys: what one seals, the other
opens.

An encryption key is declared with `path` and, as for a signing key, `bind`,
`caller` and `vault` — and no `type`: an encryption key has none, and a `type`
member is refused as an unknown field. The algorithm is the platform's choice,
named by the first byte of every ciphertext (`0x01`: XChaCha20-Poly1305 with a
random 24-byte nonce); a later format would get another marker over the same
key.

```bash
./build.sh
```

builds all seventeen and checks each: the `outlayer.manifest` section is in the
artefact and is that build's; the module imports `outlayer:signing-keys/api` —
`outlayer:encryption-keys/api` exactly in the encryption builds, and
`near:storage/api` exactly in the two `encryption-storage` builds — and nothing of ours
besides WASI; the two builds of one manifest are two hashes;
`wit/signing-keys.wit`, `wit-encryption/encryption-keys.wit` and
`wit-storage/storage.wit` have not drifted from the worker's
`worker/wit/deps/`; exactly the two `-secp` builds declare a `secp256k1` key;
exactly `encryption-typed` names a `type` on an encryption key, exactly
`encryption-pred` declares a predecessor encryption key, exactly `project-pred`
a predecessor signing key, and exactly
`encryption-storage-pred` declares `storage_account: "predecessor"`. It also reports whether the manifest
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
to the transaction's signer on chain, the payment key's owner over HTTPS —
except `project-pred`'s and `encryption-pred`'s. A `caller: "predecessor"` key binds to the account
that called the contract instead — a DAO, a wallet contract — and refuses a run
that carries none. The caller kind is part of the derivation: on a direct call,
where the predecessor is the signer, the predecessor key at `alpha` is still
another key than the signer key at `alpha`.

Storage has an owner too: every record a run reads or writes sits in one
account's cell of the project, and the manifest's `storage_account` names which
account of the job it is. `encryption-storage` leaves it at the default,
`signer` — the transaction's signer on chain, the payment key's owner over
HTTPS. `encryption-storage-pred` declares `"predecessor"`: its records sit in
the cell of the account that called the contract (a relaying contract, not the
user who signed), which on a direct call and over HTTPS is the same account as
the signer's; a run that carries no predecessor is refused before it starts.
The two builds hold the same keys, so as versions of one project a record one
seals opens in the other only when both runs resolve to the same cell. The
guest never names the account.

The `sign` operation signs whatever `message_hex` it is handed — for a
`secp256k1` key, whatever 32-byte digest. That is what a probe is for; a module
in production signs only messages it composes itself and hashes itself, never
caller-supplied bytes or digests — an ed25519 key's public key is a real NEAR
implicit account, a secp256k1 key's an EVM address, and a caller-chosen digest
can be the hash of any EVM transaction.

## Key types

| `type` | `public_key` | `sign` |
|---|---|---|
| `ed25519` | 32 bytes | RFC 8032 over the raw message, at most 65536 bytes; 64 bytes out |
| `secp256k1` | 64 bytes `x ‖ y` (uncompressed SEC1 without `0x04`, NEAR's `secp256k1:` key) | a 32-byte prehash only, signed as it is (RFC 6979); 65 bytes `r ‖ s ‖ v`, low-s, `v` 0 or 1 (EVM: `v + 27`) |

The EVM address of a `secp256k1` key is `0x` and the last 20 bytes of
keccak256 of its 64-byte public key (`evm_address`).

## Operations

Input is one JSON object with `operation`. Every answer carries `status`
(`ok`, `err`, or `n/a`), `message`, `operation` and `build`. A refusal from the
host is an `err` answer, never a failed run.

| `operation` | Fields | Answers |
|---|---|---|
| `public_key` | `path`, `vault?` | `public_key` (hex) |
| `sign` | `path`, `vault?`, `message_hex` | `signature`, `public_key` (hex) |
| `sign_and_verify` | `path`, `vault?`, `message_hex` | as `sign`, plus `verified` and `tampered_rejected`, checked inside the guest; for a `secp256k1` key (with k256) also `recovered` (the signature and its `v` recover to the key), `low_s`, `v` and `evm_address` |
| `sign_nep413` | `path`, `vault?`, `message`, `recipient`, `nonce_hex` (32 bytes), `callback_url?` | `accountId`, `publicKey`, `signature` — the shape of a wallet's `signMessage`, built in the guest; `err` for a key that is not ed25519 |
| `host_nep413` | as `sign_nep413` (the nonce goes to the host as given) | the same three fields from the host's `sign-nep413`, which builds the NEP-413 bytes itself — byte for byte the `sign_nep413` answer |
| `evm_address` | `path`, `vault?` | `public_key` and `evm_address` of a `secp256k1` key; `err` for an ed25519 key |
| `all_public_keys` | — | `keys: {path: {vault, public_key}}` for every declared key |
| `what_i_can_see` | `scan_masked_hex?` | every environment variable and its value, the arguments, stdin as it arrived, the working directory, the filesystem listing, the size of linear memory — and, for each needle (hex of the bytes XOR `0x5a`), how many times it occurs in the module's own memory. Every declared key is used first, in the same run |
| `attack` | `name` | one of the attacks below |
| `attacks` | — | all of them, `results: [{name, status, message}]` |

`vault` is the key's declared vault: omit it for a key declared without one.

The encryption builds add:

| `operation` | Fields | Answers |
|---|---|---|
| `encrypt` | `path`, `vault?`, `plaintext_hex`, `aad_hex?` | `ciphertext` (hex: `01 ‖ nonce ‖ ciphertext ‖ tag`) |
| `decrypt` | `path`, `vault?`, `ciphertext_hex`, `aad_hex?` | `plaintext` (hex), or `err` `decryption failed` |
| `mac` | `path`, `vault?`, `plaintext_hex` (the data) | `mac` (hex, 32 bytes) |
| `encrypt_and_decrypt` | `path`, `vault?`, `plaintext_hex`, `aad_hex?` | `round_trip`, `fresh_nonce`, `other_aad_refused`, `length`, `format` (the first byte is the `0x01` format marker), checked inside the guest |
| `all_encryption_keys` | — | `keys: {path: {vault, mac}}`: the mac of a fixed string under every declared encryption key |
| `enc_attack` | `name` | one of the encryption attacks below |
| `enc_attacks` | — | all of them |

`decrypt` hands back whatever it opens to whoever called: that is what a probe
is for. A module in production decides from what it has checked who may read
what it opens.

The `encryption-storage` builds add, on the run's own project storage (one
account's records; every name below is the storage key):

| `operation` | Fields | Answers |
|---|---|---|
| `raw_set` | `key`, `value_hex` | stored as given (`set-raw`) |
| `raw_get` | `key` | `found`, `value_hex` (`get-raw`) |
| `raw_set_if_absent` | `key`, `value_hex` | `inserted` (`set-if-absent-raw`) |
| `raw_set_if_equals` | `key`, `expected_hex`, `new_hex` | `updated`, `current_hex` — the stored bytes when not replaced (`set-if-equals-raw`) |
| `enc_set`, `enc_get` | `key`, `value_hex` / `key` | the encrypted mode (`set`, `get`), to meet the other mode |
| `storage_has`, `storage_delete` | `key` | `exists`, `deleted` |
| `storage_list` | `prefix?` | `keys`: the names, raw ones as written |
| `sealed_put` | `path`, `vault?`, `key` (the record's name), `value` (text) | sealed with the encryption key at `path` under `aad` = the storage key, stored raw under the storage key: the hex of `mac(path, vault, name)`. Answers `storage_key`, `stored_len` |
| `sealed_get` | `path`, `vault?`, `key` | `found`, `value`, `value_hex`, `storage_key` |
| `raw_attack` | `name`, `key?` (a prefix, default `raw-attacks`) | one of the storage attacks below |
| `raw_attacks` | `key?` | all of them |

A record keeps the mode it was written in. The documented errors:

| Call | On a record written | Error |
|---|---|---|
| `get-raw` | encrypted | `the record at this key was written encrypted; read it with get` |
| `get` | raw | `the record at this key was written raw; read it with get-raw` |
| `set-raw` | encrypted | `the record at this key was written encrypted; set-raw does not convert it — write it with set, or delete it first` |
| `set` | raw | `the record at this key was written raw; set does not convert it — write it with set-raw, or delete it first` |
| `set-if-equals-raw` | encrypted | `the record at this key was written encrypted; compare it with set-if-equals` |
| `set-if-equals` | raw | `the record at this key was written raw; compare it with set-if-equals-raw` |

`sealed_put` is the pattern the platform's own documentation recommends: the
operator of the storage sees a mac, never the name, and ciphertext, never the
value; the ciphertext is bound to the key it is stored under, so moved under
another name it does not open.

### Attacks

| `name` | Expected |
|---|---|
| `undeclared_path` | `err` |
| `empty_path` | `err` |
| `colon_path` — `<first path>:x` | `err` |
| `traversal_path` — `../<first path>` | `err` |
| `huge_path` — 1 MiB | `err`, and the reason does not echo it |
| `oversized_message` — 65537 bytes, to the first ed25519 key | `err` (`n/a` with no ed25519 key) |
| `message_at_cap` — 65536 bytes, to the first ed25519 key | `ok`, and the signature verifies (`n/a` with no ed25519 key) |
| `vault_when_none_declared` | `err` |
| `vault_missing_when_declared` | `err` (`n/a` in a build with no vaulted key) |
| `vault_wrong_when_declared` | `err` (`n/a` in a build with no vaulted key) |
| `determinism` — two calls, one answer | `ok` |
| `secp_message_not_32` — 31, 33 and 13 bytes to the first secp256k1 key | `err` (`n/a` with no secp256k1 key) |
| `nep413_wrong_type` — `sign-nep413` with a secp256k1 key | `err` (`n/a` with no secp256k1 key) |
| `nep413_bad_nonce` — `sign-nep413` with a 31-, 33- and 0-byte nonce | `err` (`n/a` with no ed25519 key) |

Encryption attacks (`enc_attacks`), each against a ciphertext the run seals
first:

| `name` | Expected |
|---|---|
| `undeclared_path`, `empty_path`, `colon_path` | `err` |
| `wrong_aad`, `tampered_tag`, `tampered_body`, `tampered_nonce`, `bad_format_marker`, `truncated`, `shorter_than_overhead`, `empty_ciphertext`, `cross_path` | `err`, exactly `decryption failed` (`cross_path` is `n/a` with one key) |
| `oversized_plaintext`, `oversized_aad`, `oversized_data` — 262145 bytes; `oversized_ciphertext` | `err` |
| `plaintext_at_cap` — 262144 bytes | `ok`, and it opens |
| `vault_when_none_declared` | `err` |
| `vault_missing_when_declared`, `vault_wrong_when_declared` | `err` (`n/a` with no vaulted key) |
| `mac_determinism` — one name one tag, another name another | `ok` |
| `mac_separation` — a tag does not open as a ciphertext | `ok` |
| `encryption_path_is_not_a_signing_path` | `err` from `sign` |
| `signing_path_is_not_an_encryption_path` | `err` from `mac` (`n/a` when every signing path is also an encryption path) |

Storage attacks (`raw_attacks`, `encryption-storage`), each on records it
writes under `<prefix>/<name>` and deletes afterwards. `unchanged: true`, where
present, says the record written before the attack is still what is stored;
`setup_failed` says that record could not be written:

| `name` | Expected |
|---|---|
| `get_raw_on_encrypted`, `get_on_raw`, `set_raw_over_encrypted`, `set_over_raw`, `cas_raw_on_encrypted`, `cas_on_raw` | `err`, the documented error above; `unchanged` |
| `increment_on_raw` | `err` (`written raw`); `unchanged` |
| `set_if_absent_raw_on_encrypted`, `set_if_absent_on_raw`, `set_if_absent_raw_on_raw` | `err` `not inserted`; `unchanged` |
| `cas_raw_lose` — stale expected bytes | `err` `not replaced`; `current_is_stored`, `unchanged` |
| `cas_raw_absent` — no record | `err` `not replaced: no record at the key`; `current_empty` |
| `cas_raw_win`, `delete_raw`, `list_shows_raw_name` | `ok` |

## `sign_nep413`: a NEP-413 signature from a signing key

The host function `sign-nep413` does all of this in one call and answers the
same three fields (`host_nep413` here). What follows is the same signature
built in the guest from `sign` — the part meant to be copied where the payload
needs to be seen. A NEP-413 (`signMessage`) signature is ed25519
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
    let public_key = signing_keys::public_key(path, vault)?;
    if public_key.len() != 32 {
        return Err(format!("NEP-413 is signed with an ed25519 key; the key at {path:?} is not one"));
    }
    let signature = signing_keys::sign(path, vault, &nep413_hash(payload))?;
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
  in Python, the borsh bytes spelled out, the EVM address and the in-guest
  secp256k1 check against Python's (`coincurve`, keccak256) key and signature,
  and the build's manifest: no `type` on an encryption key outside
  `encryption-typed`, a predecessor key only in `encryption-pred`, `ed25519` on
  every signing key outside the `-secp` builds.
* `worker/tests/signing_key_probe.rs` — every build through the executor with
  injected keys: every operation, the pinned public keys and signatures
  (ed25519 from PyNaCl, secp256k1 and EVM addresses from `coincurve`), an
  independent ed25519, secp256k1 and NEP-413 verification, `host_nep413` byte
  for byte the guest-built signature, every attack and vault
  mismatch, no seed byte in the environment, stdin or linear memory, and a
  module that declares keys and is handed none refused before it runs.
* `worker/tests/encryption_key_probe.rs` — the encryption builds the same
  way: a round trip across runs, a ciphertext sealed by libsodium opening in
  the guest, the pinned `mac`, every attack and vault mismatch, the two
  families apart at one path, no key or `mac` subkey byte in the environment,
  stdin, output or linear memory, a module that declares encryption keys
  and is handed none refused before it runs, the typed build's manifest
  refused — and `encryption-storage` against an in-process coordinator and
  keystore that keep the coordinator's mode rule: raw round trips with no
  keystore call, the mode errors both ways, every storage attack, and a sealed
  record opened with an independent XChaCha20-Poly1305. The storage tests run
  in a release build only (`cargo test --release --test
  encryption_key_probe`): reqwest's blocking client, which the storage client
  is, asserts in a debug build that it is not inside a tokio runtime.
* `tests/signing_keys_e2e.sh` — the signing builds against a deployed worker
  and keystore, on testnet.
* `tests/encryption_keys_e2e.sh` — the encryption and storage builds against
  a deployed worker, keystore and coordinator, on testnet.
